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
fn find_embedded_archive(data: &[u8]) -> Option<(usize, &'static str)> {
    if data.len() < 2 {
        return None;
    }
    let hay = &data[1..]; // past offset 0
    let mut best: Option<(usize, &'static str)> = None;
    for &(sig, name) in SIGS {
        if let Some(rel) = memchr::memmem::find(hay, sig) {
            let off = rel + 1; // re-base onto the full buffer
            if best.is_none_or(|(b, _)| off < b) {
                best = Some((off, name));
            }
        }
    }
    best
}

/// True when `data` looks like a self-extracting archive: an executable stub
/// with an archive magic embedded past [`MIN_SFX_OFFSET`] (used by `detect`).
pub(crate) fn looks_like_sfx(data: &[u8]) -> bool {
    if !starts_with_exe(data) {
        return false;
    }
    matches!(find_embedded_archive(data), Some((off, _)) if off > MIN_SFX_OFFSET)
}

/// Reader-based streaming: find the appended archive's offset by scanning a
/// bounded prefix (the stub is small), then stream the payload `[off, EOF)` via
/// seek+take — so a self-extracting installer with a multi-gigabyte payload is
/// scanned without buffering it. Matches [`extract_sfx`]'s single `sfx-payload`
/// member.
pub(crate) fn stream_offsets<R: std::io::Read + std::io::Seek>(
    source: &mut R,
    max_buffer: u64,
) -> Result<Vec<(String, u64, u64)>, LimitHit> {
    use std::io::SeekFrom;
    let len = source
        .seek(SeekFrom::End(0))
        .map_err(|e| LimitHit::corrupt(format!("sfx: {e}")))?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|e| LimitHit::corrupt(format!("sfx: {e}")))?;
    let scan = max_buffer.min(len) as usize;
    let mut prefix = vec![0u8; scan];
    let mut n = 0;
    while n < prefix.len() {
        match source.read(&mut prefix[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => break,
        }
    }
    prefix.truncate(n);
    let Some((off, _)) = find_embedded_archive(&prefix) else {
        return Ok(Vec::new());
    };
    if off as u64 >= len {
        return Ok(Vec::new());
    }
    Ok(vec![(
        "sfx-payload".to_string(),
        off as u64,
        len - off as u64,
    )])
}

pub(crate) fn extract_sfx<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // First embedded archive past the stub, or nothing to carve.
    let Some((off, _label)) = find_embedded_archive(data) else {
        return Ok(None);
    };
    let start = off.min(data.len());
    let slice = &data[start..];

    budget.count_entry()?;
    let cap = budget.reserve()?;
    if slice.len() as u64 > cap {
        return Err(LimitHit::new("sfx payload exceeds budget".to_string()));
    }
    let bytes = slice.to_vec();
    budget.commit(bytes.len() as u64);
    if let Some(r) = visit(Entry::new("sfx-payload".to_string(), bytes), budget) {
        return Ok(Some(r));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `MZ` stub of zero filler up to `payload_at`, then `payload`.
    fn mz_stub(payload: &[u8], payload_at: usize) -> Vec<u8> {
        let mut out = vec![b'M', b'Z'];
        out.resize(payload_at, 0);
        out.extend_from_slice(payload);
        out
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

    #[test]
    fn carves_appended_7z_payload() {
        let mut seven = b"7z\xBC\xAF\x27\x1C".to_vec();
        seven.extend_from_slice(b"----MALWARETEST----");
        let blob = mz_stub(&seven, 512);
        assert!(looks_like_sfx(&blob));

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Sfx, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].data.starts_with(b"7z\xBC\xAF\x27\x1C"));
        assert!(entries[0].data.windows(11).any(|w| w == b"MALWARETEST"));
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
            let _ = extract(Format::Sfx, input, &mut budget).unwrap();
        }
    }
}
