//! CHM (Microsoft Compiled HTML Help, `.chm`) extractor.
//!
//! A CHM file is the ITSS ("InfoTech Storage System") container Windows Help
//! uses to ship a whole website — HTML topics, scripts, images and embedded
//! objects — in one file. Malware routinely abuses it: a `.chm` can auto-run
//! script/`.hhc` content or carry a dropper, so we enumerate the internal files
//! and hand their bytes to the engine to scan.
//!
//! Layout (all integers little-endian), from the public ITSS/ITSF container
//! format (the LZX-compressed sections are decoded by the `lzxd` crate):
//!
//! ```text
//! ITSF header @0        magic "ITSF", version, then a header-section table:
//!   +0x38 i64 OffsetHS0  -> header section 0 (has the total file length)
//!   +0x48 i64 OffsetHS1  -> header section 1 == the ITSP directory
//!   +0x58 i64 OffsetCS0  -> content section 0 base (v3+; v1/2 computed)
//! ITSP directory (HS1)  magic "ITSP":
//!   +0x10 u32 chunk_size, +0x2c u32 num_chunks; entries live in PMGL chunks
//!   that start at HS1+0x54. Each PMGL chunk:
//!     +0x14.. entries, last u16 of the chunk = entry count.
//!     entry = ENCINT name_len, name[name_len], ENCINT section, offset, length.
//! ```
//!
//! Every named entry belongs to one of two content sections:
//! - section 0 — stored uncompressed at `sec0_offset + offset`.
//! - section 1 — the single LZX stream in
//!   `::DataSpace/Storage/MSCompressed/Content`; a file's `offset`/`length`
//!   index into the *decompressed* stream. LZX parameters come from
//!   `.../ControlData` (window size, reset interval) and the per-frame reset
//!   offsets from `.../Transform/{GUID}/InstanceData/ResetTable`. LZX is decoded
//!   with the shared `lzxd` crate (same dependency the CAB extractor uses).
//!
//! Robustness: this is attacker-controlled input, so every offset/length is
//! bounds-checked and clamped; a structurally invalid header returns `Ok(None)`,
//! a file we can't decompress becomes an `Entry::unsupported` (never a panic and
//! never a failed scan). If the LZX stream can't be decoded we still emit each
//! uncompressed (section 0) file and mark the compressed ones unsupported.

use crate::*;
use lzxd::{Lzxd, WindowSize};

/// One LZX output frame is always 32 KiB (`LZX_FRAME_SIZE`).
const LZX_FRAME_SIZE: usize = 0x8000;

/// System-file names we need for LZX decompression.
const CONTENT_NAME: &str = "::DataSpace/Storage/MSCompressed/Content";
const CONTROL_NAME: &str = "::DataSpace/Storage/MSCompressed/ControlData";
const SPANINFO_NAME: &str = "::DataSpace/Storage/MSCompressed/SpanInfo";
const RTABLE_NAME: &str = "::DataSpace/Storage/MSCompressed/Transform/\
{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable";

// ---- little-endian readers, all bounds-checked (return None past EOF) --------

fn u16at(d: &[u8], p: usize) -> Option<u16> {
    d.get(p..p + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn u32at(d: &[u8], p: usize) -> Option<u32> {
    d.get(p..p + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64at(d: &[u8], p: usize) -> Option<u64> {
    d.get(p..p + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Read an ENCINT (big-endian base-128, high bit = continuation) from `d` at
/// `*pos`, advancing `*pos`. Bounded to `end` and to 8 bytes (63 bits) so hostile
/// data can neither run off the buffer nor spin. Returns `None` on truncation.
fn read_encint(d: &[u8], pos: &mut usize, end: usize) -> Option<u64> {
    let mut result: u64 = 0;
    for _ in 0..9 {
        if *pos >= end {
            return None;
        }
        let c = d[*pos];
        *pos += 1;
        result = (result << 7) | u64::from(c & 0x7f);
        if c & 0x80 == 0 {
            return Some(result);
        }
    }
    None
}

/// A named entry in the CHM directory.
struct DirEntry {
    name: String,
    section: u64,
    offset: u64,
    length: u64,
}

/// The parsed CHM directory: where content section 0 begins and every entry.
struct ChmDir {
    sec0_offset: usize,
    entries: Vec<DirEntry>,
}

/// Parse the ITSF header + ITSP directory. Returns `None` if this isn't a
/// structurally valid CHM (so `detect` mis-fires or the file is too truncated).
fn parse_chm(d: &[u8]) -> Option<ChmDir> {
    if !d.starts_with(b"ITSF") {
        return None;
    }
    // Header-section table follows the 0x38-byte ITSF header.
    let off_hs1 = u64at(d, 0x38 + 0x10)? as usize; // ITSP directory
                                                   // The directory offset must land inside the file. Bounding it here also keeps
                                                   // every `off_hs1 + <small const>` read below from overflowing `usize` on a
                                                   // crafted 64-bit offset (a `d.len() <= isize::MAX` invariant makes the adds
                                                   // safe once `off_hs1 < d.len()`).
    if off_hs1 >= d.len() {
        return None;
    }
    // OffsetCS0 (content section 0 base). Present in v3; for v1/2 we recompute
    // it below from the directory geometry.
    let version = u32at(d, 0x04)?;
    let mut sec0_offset = u64at(d, 0x38 + 0x20).unwrap_or(0) as usize;

    // ITSP directory header.
    if d.get(off_hs1..off_hs1 + 4)? != b"ITSP" {
        return None;
    }
    let chunk_size = u32at(d, off_hs1 + 0x10)? as usize;
    let num_chunks = u32at(d, off_hs1 + 0x2c)? as usize;
    // Sanity bounds (arbitrary caps against memory blow-ups).
    if !(8..=0x40000).contains(&chunk_size) || num_chunks == 0 || num_chunks > 100_000 {
        return None;
    }
    let dir_start = off_hs1.checked_add(0x54)?;
    // Directory must fit in the file.
    let dir_bytes = chunk_size.checked_mul(num_chunks)?;
    if dir_start.checked_add(dir_bytes)? > d.len() {
        return None;
    }
    if version < 3 {
        sec0_offset = dir_start + dir_bytes;
    }
    if sec0_offset > d.len() {
        return None;
    }

    let mut entries = Vec::new();
    for cn in 0..num_chunks {
        let cs = dir_start + cn * chunk_size;
        let chunk = &d[cs..cs + chunk_size];
        // Only PMGL (listing) chunks hold file entries; skip PMGI index chunks.
        if &chunk[0..4] != b"PMGL" {
            continue;
        }
        // The entry region runs from +0x14 up to the quickref area; the very last
        // u16 of the chunk is the entry count. Read encints bounded by `end`.
        let end = chunk_size - 2;
        let num_entries = u16at(chunk, end)? as usize;
        let mut p = 0x14usize;
        for _ in 0..num_entries {
            let name_len = read_encint(chunk, &mut p, end)? as usize;
            if name_len > end.saturating_sub(p) {
                break; // truncated / hostile name length
            }
            let name = String::from_utf8_lossy(&chunk[p..p + name_len]).into_owned();
            p += name_len;
            let section = read_encint(chunk, &mut p, end)?;
            let offset = read_encint(chunk, &mut p, end)?;
            let length = read_encint(chunk, &mut p, end)?;
            entries.push(DirEntry {
                name,
                section,
                offset,
                length,
            });
        }
    }

    Some(ChmDir {
        sec0_offset,
        entries,
    })
}

/// Read a section-0 (uncompressed) system file's bytes, bounds-checked against
/// the whole CHM buffer.
fn read_sec0<'a>(d: &'a [u8], sec0_offset: usize, e: &DirEntry) -> Option<&'a [u8]> {
    let start = sec0_offset.checked_add(usize::try_from(e.offset).ok()?)?;
    let len = usize::try_from(e.length).ok()?;
    d.get(start..start.checked_add(len)?)
}

/// LZX parameters carried by `ControlData`.
struct LzxParams {
    window: WindowSize,
    reset_interval_frames: usize,
}

fn parse_control(blob: &[u8]) -> Option<LzxParams> {
    // struct: u32 len, u32 "LZXC", u32 version, u32 reset_interval, u32 window,...
    if u32at(blob, 0x04)? != 0x4358_5A4C {
        return None; // not "LZXC"
    }
    let (mut reset_interval, window_size) = match u32at(blob, 0x08)? {
        1 => (u32at(blob, 0x0c)? as u64, u32at(blob, 0x10)? as u64),
        2 => (
            (u32at(blob, 0x0c)? as u64) * LZX_FRAME_SIZE as u64,
            (u32at(blob, 0x10)? as u64) * LZX_FRAME_SIZE as u64,
        ),
        _ => return None,
    };
    // Guard against a zero/oversized window before the match below.
    if window_size == 0 {
        return None;
    }
    let window = match window_size {
        0x0_8000 => WindowSize::KB32,
        0x1_0000 => WindowSize::KB64,
        0x2_0000 => WindowSize::KB128,
        0x4_0000 => WindowSize::KB256,
        0x8_0000 => WindowSize::KB512,
        0x10_0000 => WindowSize::MB1,
        0x20_0000 => WindowSize::MB2,
        _ => return None,
    };
    // reset_interval must be a whole number of frames, at least one.
    if reset_interval == 0 || reset_interval % LZX_FRAME_SIZE as u64 != 0 {
        // Fall back to a single reset interval spanning everything.
        reset_interval = LZX_FRAME_SIZE as u64;
    }
    Some(LzxParams {
        window,
        reset_interval_frames: (reset_interval / LZX_FRAME_SIZE as u64).max(1) as usize,
    })
}

/// Parsed reset table: uncompressed stream length + per-entry compressed byte
/// offsets. `per_frame` tells whether the offsets are indexed per 32 KiB frame
/// (`num_entries >= total_frames`) or per reset interval.
struct ResetTable {
    uncomp_len: u64,
    offsets: Vec<u64>,
}

fn parse_reset_table(blob: &[u8]) -> Option<ResetTable> {
    let num_entries = u32at(blob, 0x04)? as usize;
    let entry_size = u32at(blob, 0x08)? as usize;
    let table_off = u32at(blob, 0x0c)? as usize;
    let uncomp_len = u64at(blob, 0x10)?;
    if !(entry_size == 4 || entry_size == 8) || num_entries > 1_000_000 {
        return None;
    }
    let mut offsets = Vec::with_capacity(num_entries.min(4096));
    for i in 0..num_entries {
        let eo = table_off.checked_add(i.checked_mul(entry_size)?)?;
        let v = if entry_size == 8 {
            u64at(blob, eo)?
        } else {
            u32at(blob, eo)? as u64
        };
        offsets.push(v);
    }
    Some(ResetTable {
        uncomp_len,
        offsets,
    })
}

/// Decompress the section-1 LZX `content` stream into a single buffer (bounded
/// to `cap` bytes). Returns the decoded buffer plus whether at least one frame
/// decoded successfully.
///
/// LZX in CHM is framed: the stream is padded up to a whole number of 32 KiB
/// frames (padded to the reset interval), so every frame decodes to exactly
/// `LZX_FRAME_SIZE` bytes — we must always ask the decoder for a full frame, not
/// the reset table's "honest" (unpadded) length, or the last block ends mid-way
/// and the decoder reports EOF.
///
/// Best-effort: only frames that start at an LZX reset boundary are decoded
/// (each with a fresh decoder). This is exact for single-frame streams and for
/// streams whose reset interval is one frame — the common cases. Frames inside a
/// multi-frame reset interval can't be started independently with this crate, so
/// they're left zero-filled rather than decoded to garbage. Never panics.
fn decompress_content(
    content: &[u8],
    params: &LzxParams,
    rt: &ResetTable,
    cap: usize,
) -> (Vec<u8>, bool) {
    let real_len = rt.uncomp_len as usize;
    if real_len == 0 || cap == 0 {
        return (Vec::new(), false);
    }
    // Frames covering the real (unpadded) length — files never index past it.
    let frames_needed = real_len.div_ceil(LZX_FRAME_SIZE);
    // Hold whole frames only (never a partial frame — see doc comment), bounded
    // by the caller's byte budget (always room for at least one frame if cap>0).
    let max_frames = (cap / LZX_FRAME_SIZE).max(1).min(frames_needed);
    let buf_len = max_frames * LZX_FRAME_SIZE;
    let mut out = vec![0u8; buf_len];

    let rif = params.reset_interval_frames.max(1);
    let per_frame = rt.offsets.len() >= frames_needed;

    let mut any = false;
    let mut r = 0usize;
    loop {
        let frame = match r.checked_mul(rif) {
            Some(f) if f < max_frames => f,
            _ => break,
        };
        // Compressed byte offset at which this reset-aligned frame begins.
        let byte_off = if r == 0 && rt.offsets.is_empty() {
            0
        } else if per_frame {
            match rt.offsets.get(frame) {
                Some(&o) => o as usize,
                None => break,
            }
        } else {
            match rt.offsets.get(r) {
                Some(&o) => o as usize,
                None => break,
            }
        };
        if byte_off > content.len() {
            break;
        }
        let chunk = &content[byte_off..];
        let out_pos = frame * LZX_FRAME_SIZE;
        // Fresh decoder per reset point (each reset boundary re-initialises the
        // LZX state); the crate then handles the E8 header and block structure.
        let mut lzxd = Lzxd::new(params.window);
        if let Ok(bytes) = lzxd.decompress_next(chunk, LZX_FRAME_SIZE) {
            let n = bytes.len().min(out.len() - out_pos);
            out[out_pos..out_pos + n].copy_from_slice(&bytes[..n]);
            any = true;
        }
        r += 1;
    }
    (out, any)
}

pub(crate) fn extract_chm<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let dir = match parse_chm(data) {
        Some(d) => d,
        None => return Ok(None),
    };

    // Locate the system files needed for LZX decompression.
    let mut content = None;
    let mut control = None;
    let mut rtable = None;
    let mut spaninfo = None;
    for e in &dir.entries {
        match e.name.as_str() {
            CONTENT_NAME => content = Some(e),
            CONTROL_NAME => control = Some(e),
            RTABLE_NAME => rtable = Some(e),
            SPANINFO_NAME => spaninfo = Some(e),
            _ => {}
        }
    }

    // Decode the compressed content section once (shared by all section-1 files).
    // Bounded to what the budget still allows so a huge declared length can't OOM.
    let mut decompressed: Vec<u8> = Vec::new();
    let mut lzx_ok = false;
    if let Some(content_e) = content {
        if let Some(content_bytes) = read_sec0(data, dir.sec0_offset, content_e) {
            let params = control
                .and_then(|c| read_sec0(data, dir.sec0_offset, c))
                .and_then(parse_control);
            // Reset table gives the frame offsets + true uncompressed length;
            // fall back to SpanInfo (length only) or the content length itself.
            let rt = rtable
                .and_then(|r| read_sec0(data, dir.sec0_offset, r))
                .and_then(parse_reset_table)
                .or_else(|| {
                    spaninfo
                        .and_then(|s| read_sec0(data, dir.sec0_offset, s))
                        .and_then(|b| u64at(b, 0))
                        .map(|uncomp_len| ResetTable {
                            uncomp_len,
                            offsets: Vec::new(),
                        })
                });
            if let (Some(params), Some(rt)) = (params, rt) {
                let cap = budget.reserve().unwrap_or(0) as usize;
                if cap > 0 {
                    let (buf, ok) = decompress_content(content_bytes, &params, &rt, cap);
                    decompressed = buf;
                    lzx_ok = ok;
                }
            }
        }
    }

    // Emit every named file. System files (":: …") and directory placeholders are
    // skipped; their bytes are the container plumbing, not user content.
    for e in &dir.entries {
        if e.length == 0 || e.name.starts_with("::") {
            continue;
        }
        budget.count_entry()?;
        let cap = budget.reserve()?;

        let (entry, committed) = if e.section == 0 {
            // Uncompressed: slice straight out of the file.
            match read_sec0(data, dir.sec0_offset, e) {
                // Cutting the entry down to the cap and handing it over as the
                // file is a silent truncation: the rest of the bytes are in the
                // container, and a signature past the cut would never fire on a
                // member that looks complete.
                Some(bytes) if bytes.len() as u64 > cap => (
                    Entry::unsupported(
                        e.name.clone(),
                        e.length,
                        false,
                        "CHM entry exceeds the per-member size budget",
                    ),
                    0,
                ),
                Some(bytes) => {
                    let buf = bytes.to_vec();
                    let n = buf.len() as u64;
                    (Entry::new(e.name.clone(), buf), n)
                }
                None => (
                    Entry::unsupported(e.name.clone(), e.length, false, "CHM entry out of bounds"),
                    0,
                ),
            }
        } else if e.section == 1 {
            // Compressed: slice out of the decompressed LZX stream.
            let start = usize::try_from(e.offset).ok();
            let len = usize::try_from(e.length).ok();
            match (lzx_ok, start, len) {
                // Same again for the compressed section: report rather than
                // deliver a prefix dressed up as the whole entry.
                (true, Some(_), Some(l)) if l as u64 > cap => (
                    Entry::unsupported(
                        e.name.clone(),
                        e.length,
                        false,
                        "CHM entry exceeds the per-member size budget",
                    ),
                    0,
                ),
                (true, Some(s), Some(l))
                    if s.checked_add(l)
                        .is_some_and(|end| end <= decompressed.len()) =>
                {
                    let buf = decompressed[s..s + l].to_vec();
                    let n = buf.len() as u64;
                    (Entry::new(e.name.clone(), buf), n)
                }
                _ => (
                    Entry::unsupported(e.name.clone(), e.length, false, "CHM LZX decode failed"),
                    0,
                ),
            }
        } else {
            // Unknown section number.
            (
                Entry::unsupported(e.name.clone(), e.length, false, "CHM unknown section"),
                0,
            )
        };

        budget.commit(committed);
        if let Some(r) = visit(entry, budget) {
            return Ok(Some(r));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_chm_input_yields_nothing() {
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Chm, b"not a chm file at all", &mut budget).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn truncated_itsf_does_not_panic() {
        // Just the magic, nothing else — every downstream read must bail cleanly.
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Chm, b"ITSF", &mut budget).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn random_bytes_after_magic_do_not_panic() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"ITSF");
        // Fill with a pseudo-random-ish but deterministic pattern.
        for i in 0..4096u32 {
            blob.push((i.wrapping_mul(2654435761) >> 13) as u8);
        }
        let mut budget = Budget::new(Limits::default());
        // Must not panic; result is "not a valid CHM" (empty) or some entries.
        let _ = extract(Format::Chm, &blob, &mut budget).unwrap();
    }

    #[test]
    fn read_encint_roundtrips_and_is_bounded() {
        // 0x1234 -> 0xA4,0x34 (big-endian base-128 with continuation bit).
        let buf = [0xA4u8, 0x34];
        let mut p = 0;
        assert_eq!(read_encint(&buf, &mut p, buf.len()), Some(0x1234));
        assert_eq!(p, 2);
        // All-continuation bytes must terminate (never spin / overrun).
        let bad = [0x80u8; 16];
        let mut p = 0;
        assert_eq!(read_encint(&bad, &mut p, bad.len()), None);
    }

    // Real-malware CHM fixtures live under tests/fixtures/chm and are exercised by
    // the integration test in tests/chm.rs (kept out of unit tests so the crate
    // still builds without the fixtures present).

    /// A crafted ITSF whose HS1 (ITSP) offset is `u64::MAX` must bail via the
    /// `off_hs1 >= d.len()` guard rather than overflow any `off_hs1 + const` read.
    #[test]
    fn hostile_hs1_offset_no_panic() {
        let mut d = vec![0u8; 0x200];
        d[0..4].copy_from_slice(b"ITSF");
        d[0x04..0x08].copy_from_slice(&3u32.to_le_bytes());
        d[0x48..0x50].copy_from_slice(&u64::MAX.to_le_bytes()); // OffsetHS1
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Chm, &d, &mut budget).unwrap().is_empty());
    }

    /// Valid ITSF+ITSP magic but hostile directory geometry (`chunk_size` and
    /// `num_chunks` both `u32::MAX`) must be rejected without overflow / OOB in
    /// `chunk_size * num_chunks` or `dir_start + cn * chunk_size`.
    #[test]
    fn hostile_itsp_geometry_no_panic() {
        let hs1 = 0x60usize;
        let mut d = vec![0u8; 0x200];
        d[0..4].copy_from_slice(b"ITSF");
        d[0x04..0x08].copy_from_slice(&3u32.to_le_bytes());
        d[0x48..0x50].copy_from_slice(&(hs1 as u64).to_le_bytes());
        d[hs1..hs1 + 4].copy_from_slice(b"ITSP");
        d[hs1 + 0x10..hs1 + 0x14].copy_from_slice(&u32::MAX.to_le_bytes()); // chunk_size
        d[hs1 + 0x2c..hs1 + 0x30].copy_from_slice(&u32::MAX.to_le_bytes()); // num_chunks
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Chm, &d, &mut budget).unwrap().is_empty());

        // Also a well-formed geometry whose extent overruns the file: rejected by
        // the `dir_start + dir_bytes > d.len()` guard, not by a panic.
        d[hs1 + 0x10..hs1 + 0x14].copy_from_slice(&0x1000u32.to_le_bytes());
        d[hs1 + 0x2c..hs1 + 0x30].copy_from_slice(&50u32.to_le_bytes());
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Chm, &d, &mut budget).unwrap().is_empty());
    }

    /// A valid PMGL chunk whose first entry declares a hostile ENCINT name length
    /// (larger than the chunk) must `break` cleanly — never slice out of bounds.
    #[test]
    fn hostile_entry_name_len_no_panic() {
        let chunk_size = 0x40usize;
        let hs1 = 0x60usize;
        let dir_start = hs1 + 0x54;
        let total = dir_start + chunk_size + 0x100;
        let mut d = vec![0u8; total];
        d[0..4].copy_from_slice(b"ITSF");
        d[0x04..0x08].copy_from_slice(&3u32.to_le_bytes());
        d[0x48..0x50].copy_from_slice(&(hs1 as u64).to_le_bytes());
        d[0x58..0x60].copy_from_slice(&(total as u64).to_le_bytes()); // sec0 base
        d[hs1..hs1 + 4].copy_from_slice(b"ITSP");
        d[hs1 + 0x10..hs1 + 0x14].copy_from_slice(&(chunk_size as u32).to_le_bytes());
        d[hs1 + 0x2c..hs1 + 0x30].copy_from_slice(&1u32.to_le_bytes());
        // PMGL chunk with entry count 1 and a hostile name_len encint (0x81 0x00 = 128).
        d[dir_start..dir_start + 4].copy_from_slice(b"PMGL");
        let end = dir_start + chunk_size - 2;
        d[end..end + 2].copy_from_slice(&1u16.to_le_bytes());
        d[dir_start + 0x14] = 0x81;
        d[dir_start + 0x15] = 0x00;
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Chm, &d, &mut budget).unwrap().is_empty());
    }
}
