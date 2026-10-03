//! Self-extracting archive (SFX) carver.
//!
//! Droppers commonly ship as an ordinary PE or ELF executable stub with a real
//! archive appended after the program image (or embedded within it). The stub
//! unpacks itself at runtime; a scanner must find and unpack that archive
//! statically. We scan the executable for the first embedded archive magic past
//! the stub and emit the slice from that magic to EOF as a single member, so the
//! engine re-dispatches it to the matching extractor (7z, RAR, ZIP, CAB, ARJ).
//! This complements exav's existing embedded-PE carving.
//!
//! Detection is intentionally conservative (see [`looks_like_sfx`]): we only
//! claim an SFX when the input *starts* with an executable magic (`MZ`/`ELF`)
//! **and** an archive magic appears well past the header. A bare archive
//! (archive magic at offset 0) is left to normal format detection.
//!
//! The scan is a bounded substring search; the carve is a single `[off..]`
//! slice, so hostile input can neither panic nor blow the budget.

use crate::*;
use std::io::{Read, Seek};

/// Archive magics we look for embedded in an executable stub, each paired with a
/// short label for diagnostics. The 2-byte ARJ magic is the loosest and can
/// false-positive inside a stub, so we always take the *earliest* match across
/// all signatures and emit only that one (bounded work, one member).
const SIGS: &[(&[u8], &str)] = &[
    (b"7z\xBC\xAF\x27\x1C", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"PK\x03\x04", "zip"),
    (b"MSCF", "cab"),
    (&[0x60, 0xEA], "arj"),
];

/// Minimum offset an embedded archive magic must sit at for the input to be
/// treated as an SFX. Anything within the first 64 bytes is far more likely a
/// coincidental byte pattern in the executable header than a real payload.
const MIN_SFX_OFFSET: usize = 64;

/// True when `data` begins with a PE (`MZ`) or ELF (`\x7fELF`) executable magic.
fn starts_with_exe(data: &[u8]) -> bool {
    data.starts_with(b"MZ") || data.starts_with(b"\x7fELF")
}

/// Locate the *earliest* embedded archive magic strictly past offset 0. Returns
/// `(offset, label)` or `None`. Searching from offset 1 skips the container's
/// own magic so a bare archive isn't reported as its own SFX payload.
/// Does a plausible ARJ main header start here?
///
/// `60 EA` is two bytes, so across a megabyte of executable it turns up by
/// chance roughly once, and a false hit is not harmless: the carve hands the
/// ARJ extractor a fragment of the stub, extraction fails, and an ordinary file
/// is reported `UNSCANNABLE`. A .NET assembly did exactly that.
///
/// The three fields after the magic settle it. The basic header size is bounded
/// by the format at 2600 bytes, the first header is at least the 30 bytes of
/// fixed fields and cannot exceed the header holding it, and the host OS is one
/// of a dozen defined values.
fn plausible_arj_header(data: &[u8], off: usize) -> bool {
    let Some(h) = data.get(off..off + 11) else {
        return false;
    };
    let basic_size = u16::from_le_bytes([h[2], h[3]]) as usize;
    let first_size = h[4] as usize;
    let host_os = h[8];
    (30..=2600).contains(&basic_size)
        && first_size >= 30
        && first_size <= basic_size
        && host_os <= 11
}

/// Does a 7z start header begin here? Its CRC-32 over the 20 bytes after it
/// must match: 7-Zip checks it, and the six-byte magic also turns up in the
/// code of tools that handle 7z, where a carve reads a header that is not one.
fn plausible_7z_header(data: &[u8], off: usize) -> bool {
    let Some(h) = data.get(off..off + 32) else {
        return false;
    };
    crc32fast::hash(&h[12..32]) == u32::from_le_bytes([h[8], h[9], h[10], h[11]])
}

fn find_embedded_archive(data: &[u8]) -> Option<(usize, &'static str)> {
    find_archive_from(data, 1)
}

/// [`find_embedded_archive`] over the offsets from `from` on.
fn find_archive_from(data: &[u8], from: usize) -> Option<(usize, &'static str)> {
    let hay = data.get(from..)?;
    let mut best: Option<(usize, &'static str)> = None;
    for &(sig, name) in SIGS {
        // ARJ's and 7z's matches are walked until one carries a header that
        // checks out: ARJ's magic is weak enough that the first hit is often
        // noise, and 7z's is in the code of tools that handle the format. The
        // other signatures are taken as they come.
        let plausible: fn(&[u8], usize) -> bool = match name {
            "arj" => plausible_arj_header,
            "7z" => plausible_7z_header,
            _ => |_, _| true,
        };
        let found = memchr::memmem::find_iter(hay, sig)
            .map(|rel| rel + from)
            .find(|&off| plausible(data, off));
        if let Some(off) = found {
            if best.is_none_or(|(b, _)| off < b) {
                best = Some((off, name));
            }
        }
    }
    best
}

/// True when `data` looks like a self-extracting archive: an executable stub
/// with an archive magic embedded past [`MIN_SFX_OFFSET`] (used by `detect`).
pub(crate) fn looks_like_sfx(p: &crate::Probe) -> bool {
    if !starts_with_exe(p.head) {
        return false;
    }
    let off = match p.source() {
        None => find_embedded_archive(p.head).map(|(off, _)| off),
        Some(_) => p.sfx_payload(),
    };
    matches!(off, Some(off) if off > MIN_SFX_OFFSET)
}

/// The search [`payload_offset`] makes, fed a window at a time by a pass
/// that reads the object for other searches too.
pub(crate) struct PayloadSearch {
    found: Option<Option<usize>>,
}

impl PayloadSearch {
    /// Bytes each window must run into the next: the 7z start header, the
    /// longest a candidate's check reads, so a match across the seam is seen
    /// whole.
    pub(crate) const OVERLAP: usize = 32;

    pub(crate) fn new() -> Self {
        PayloadSearch { found: None }
    }

    /// Search window `w`, at `base` in the object, the object's last or not.
    pub(crate) fn feed(&mut self, base: usize, w: &[u8], last: bool) {
        if self.found.is_some() {
            return;
        }
        // Offset 0 is the executable's own magic, never its payload.
        let from = if base == 0 { 1 } else { 0 };
        if let Some((off, _)) = find_archive_from(w, from) {
            // Near the end of a window a match may be cut short, and an ARJ or
            // 7z candidate before it wrongly passed over; the next window sees
            // both whole.
            if last || off + Self::OVERLAP <= w.len() {
                self.found = Some(Some(base + off));
                return;
            }
        }
        if last {
            self.found = Some(None);
        }
    }

    /// Whether the search has its answer.
    pub(crate) fn done(&self) -> bool {
        self.found.is_some()
    }

    /// Where the first embedded archive starts, if any.
    pub(crate) fn offset(&self) -> Option<usize> {
        self.found.flatten()
    }
}

/// Offset of the archive [`find_embedded_archive`] finds in the first `limit`
/// bytes of `source`, read a window at a time rather than held whole.
pub(crate) fn payload_offset<R: Read + Seek>(
    source: &mut R,
    limit: u64,
) -> Result<Option<u64>, LimitHit> {
    /// Bytes read per window.
    const WINDOW: usize = 1 << 20;
    /// Kept from one window into the next, as [`PayloadSearch::OVERLAP`].
    const OVERLAP: usize = PayloadSearch::OVERLAP;
    source
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|e| LimitHit::corrupt(format!("sfx: {e}")))?;
    let mut buf: Vec<u8> = Vec::new();
    // Offset of `buf[0]` in the source.
    let mut base = 0u64;
    let mut left = limit;
    loop {
        let want = (WINDOW as u64).min(left) as usize;
        let kept = buf.len();
        buf.resize(kept + want, 0);
        let n = crate::read_full(source, &mut buf[kept..])?;
        buf.truncate(kept + n);
        left -= n as u64;
        let last = n < want || left == 0;
        // Offset 0 is the executable's own magic, never its payload.
        let from = if base == 0 { 1 } else { 0 };
        if let Some((off, _)) = find_archive_from(&buf, from) {
            // Near the end of a window a match may be cut short, and an ARJ or
            // 7z candidate before it wrongly passed over; the next window sees
            // both whole.
            if last || off + OVERLAP <= buf.len() {
                return Ok(Some(base + off as u64));
            }
        }
        if last {
            return Ok(None);
        }
        let drop = buf.len() - OVERLAP.min(buf.len());
        buf.drain(..drop);
        base += drop as u64;
    }
}

/// Walk a self-extractor: its appended archive, streamed from where it lies.
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let mut source = crate::source::Reader::new(src);
    let members = stream_offsets(&mut source)?;
    crate::stream::stream_stored(&mut source, budget, visit, members)
}

/// Find the appended archive's offset, searching as far as detection does (a
/// window at a time), then stream the payload `[off, EOF)` via seek+take, so a
/// self-extracting installer with a multi-gigabyte payload is scanned without
/// buffering it. A shorter search than detection's would type a file as an SFX
/// and then find nothing in it.
pub(crate) fn stream_offsets<R: Read + Seek>(
    source: &mut R,
) -> Result<Vec<(String, u64, u64)>, LimitHit> {
    let len = source
        .seek(std::io::SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("sfx: {e}")))?;
    let Some(off) = payload_offset(source, len)? else {
        return Ok(Vec::new());
    };
    if off >= len {
        return Ok(Vec::new());
    }
    Ok(vec![("sfx-payload".to_string(), off, len - off)])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn looks_like_sfx(data: &[u8]) -> bool {
        super::looks_like_sfx(&crate::Probe::whole(data))
    }

    /// An `MZ` stub of zero filler up to `payload_at`, then `payload`.
    fn mz_stub(payload: &[u8], payload_at: usize) -> Vec<u8> {
        let mut out = vec![b'M', b'Z'];
        out.resize(payload_at, 0);
        out.extend_from_slice(payload);
        out
    }

    /// The payload is found as far into the file as detection looks, whatever
    /// the buffer limit: the search holds a window at a time.
    #[test]
    fn a_payload_past_the_buffer_limit_is_found() {
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend_from_slice(b"local-header::MALWARETEST::body");
        let blob = mz_stub(&zip, 64 * 1024);
        assert!(looks_like_sfx(&blob));
        let limits = Limits {
            max_buffer_bytes: 16 * 1024,
            ..Limits::default()
        };
        let entries = extract(Format::Sfx, &blob, &mut Budget::new(limits)).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].data.starts_with(b"PK\x03\x04"));
    }

    #[test]
    fn carves_appended_zip_payload() {
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend_from_slice(b"local-header::MALWARETEST::body");
        let blob = mz_stub(&zip, 200);
        assert!(looks_like_sfx(&blob));

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Sfx, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "sfx-payload");
        // The member starts exactly at the archive magic and carries the payload.
        assert!(entries[0].data.starts_with(b"PK\x03\x04"));
        assert!(entries[0].data.windows(11).any(|w| w == b"MALWARETEST"));
    }

    /// A 7z signature header with a start-header CRC that checks out.
    fn sevenz_header() -> Vec<u8> {
        let mut h = b"7z\xBC\xAF\x27\x1C\x00\x04".to_vec();
        let next = [19u64.to_le_bytes(), 0u64.to_le_bytes()].concat();
        let start = [&next[..], &0u32.to_le_bytes()].concat();
        h.extend_from_slice(&crc32fast::hash(&start).to_le_bytes());
        h.extend_from_slice(&start);
        h
    }

    #[test]
    fn carves_appended_7z_payload() {
        let mut seven = sevenz_header();
        seven.extend_from_slice(b"----MALWARETEST----");
        let blob = mz_stub(&seven, 512);
        assert!(looks_like_sfx(&blob));

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Sfx, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].data.starts_with(b"7z\xBC\xAF\x27\x1C"));
        assert!(entries[0].data.windows(11).any(|w| w == b"MALWARETEST"));
    }

    /// From a live installer: a tool that handles 7z holds the six-byte magic
    /// in its own data. Carved as a payload, it read as a broken 7z archive and
    /// made the executable `UNSCANNABLE`.
    #[test]
    fn a_7z_magic_without_its_start_header_is_passed_over() {
        let mut junk = b"7z\xBC\xAF\x27\x1C".to_vec();
        junk.extend_from_slice(&[0x5a; 40]);
        assert!(!looks_like_sfx(&mz_stub(&junk, 512)));

        let mut blob = mz_stub(&junk, 512);
        blob.extend_from_slice(&sevenz_header());
        assert_eq!(find_embedded_archive(&blob), Some((512 + junk.len(), "7z")));
    }

    /// The windowed search must answer what the whole-buffer one does, wherever
    /// the archive sits relative to a window seam.
    #[test]
    fn the_windowed_search_agrees_with_the_whole_buffer() {
        const W: usize = 1 << 20;
        let search = |blob: &[u8], limit: u64| {
            payload_offset(&mut std::io::Cursor::new(blob), limit).unwrap()
        };
        let whole = |blob: &[u8]| find_embedded_archive(blob).map(|(o, _)| o as u64);
        // An ARJ main header that passes `plausible_arj_header`.
        let arj = [0x60, 0xEA, 40, 0, 30, 0, 0, 0, 1, 0, 0];
        // The same header with a ZIP magic inside it. Cut by the seam, the ARJ
        // candidate fails its check while the ZIP fits, and a search taking
        // that answer would miss the earlier archive.
        let mut arj_zip = arj;
        arj_zip[6..10].copy_from_slice(b"PK\x03\x04");
        let seven = sevenz_header();
        for at in (W - 40..W + 24).chain([100, 2 * W - 3]) {
            for magic in [&b"PK\x03\x04"[..], &arj[..], &arj_zip[..], &seven[..]] {
                let blob = mz_stub(magic, at);
                assert_eq!(search(&blob, blob.len() as u64), whole(&blob), "{at}");
            }
            // A bare `60 EA` cut by the seam, then a real archive after it.
            let mut blob = mz_stub(&[0x60, 0xEA], at);
            blob.resize(at + 7, 0);
            blob.extend_from_slice(b"PK\x03\x04");
            assert_eq!(search(&blob, blob.len() as u64), whole(&blob), "{at}");
        }
        // The limit ends the search as the end of the prefix did.
        let blob = mz_stub(b"PK\x03\x04", 1000);
        assert_eq!(search(&blob, 1002), None);
        assert_eq!(search(&blob, 1004), Some(1000));
    }

    #[test]
    fn bare_archive_at_offset_zero_is_not_sfx() {
        // A zip that begins at offset 0 must go through normal detection, not
        // the SFX carver.
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend_from_slice(&[0u8; 100]);
        assert!(!looks_like_sfx(&zip));
    }

    #[test]
    fn executable_without_payload_is_not_sfx() {
        let mut blob = vec![b'M', b'Z'];
        blob.extend_from_slice(&[0u8; 500]);
        assert!(!looks_like_sfx(&blob));
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Sfx, &blob, &mut budget).unwrap().is_empty());
    }

    #[test]
    fn truncated_and_garbage_do_not_panic() {
        let mut budget = Budget::new(Limits::default());
        for input in [b"".as_slice(), b"M", b"MZ", &[0x60], b"PK\x03\x04"] {
            let _ = extract(Format::Sfx, &input, &mut budget).unwrap();
        }
    }
}
