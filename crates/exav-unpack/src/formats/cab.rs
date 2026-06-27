#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

pub(crate) fn extract_cab<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Malformed/truncated cabinets are a common evasion: the CFHEADER's
    // `cbCabinet` (total size, bytes 8..12) is set larger than the actual file
    // (often `0xFFFFFFFF`) so strict parsers bail, while the member data is
    // still recoverable. Clamp the field to the real length so extraction can
    // proceed, mirroring lenient extractors. Only rewrite when it overstates.
    let patched = repair_cab_size(data);
    let src: &[u8] = patched.as_deref().unwrap_or(data);
    let mut cabinet =
        cab::Cabinet::new(Cursor::new(src)).map_err(|e| LimitHit::new(format!("cab: {e}")))?;
    // Collect names first so the immutable folder/file iteration doesn't borrow
    // the cabinet while we read (read_file needs &mut).
    let names: Vec<String> = cabinet
        .folder_entries()
        .flat_map(|f| f.file_entries().map(|e| e.name().to_string()))
        .collect();
    for name in names {
        budget.count_entry()?;
        let cap = budget.reserve()?;
        let reader = match cabinet.read_file(&name) {
            Ok(r) => r,
            Err(_) => {
                // The folder decompressor couldn't even start (corrupt/truncated
                // MSZIP) — record the member as unscannable and keep going rather
                // than aborting the whole cabinet (a truncated cabinet is a known
                // evasion: a strict parser bails and misses the other members).
                if let Some(r) =
                    visit(Entry::unsupported(name, 0, false, "corrupt CAB member"), budget)
                {
                    return Ok(Some(r));
                }
                continue;
            }
        };
        // Tolerant read: keep the bytes decoded from intact MSZIP blocks even if
        // a later block is truncated or corrupt, so an embedded payload in the
        // recovered prefix is still scanned (rather than the whole member, and
        // cabinet, being thrown away on the first bad block).
        let buf = tolerant_read(reader, cap);
        budget.commit(buf.len() as u64);
        if let Some(r) = visit(Entry::new(name, buf), budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// Read up to `cap` bytes, returning whatever was decoded so far if the
/// underlying decompressor errors part-way (a truncated/corrupt MSZIP stream).
/// Unlike [`bounded_read`], a mid-stream error is not fatal — the recovered
/// prefix is still handed to the scanner.
fn tolerant_read<R: Read>(mut r: R, cap: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    while (buf.len() as u64) < cap {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let room = (cap - buf.len() as u64) as usize;
                buf.extend_from_slice(&chunk[..n.min(room)]);
            }
            Err(_) => break, // truncated/corrupt block — keep what decoded cleanly
        }
    }
    buf
}

/// If the CFHEADER `cbCabinet` field (total cabinet size, little-endian at
/// offset 8) claims a size larger than the buffer, return a copy with that
/// field clamped to the actual length; otherwise `None` (no copy needed). This
/// recovers cabinets whose total-size header is deliberately corrupted to defeat
/// strict parsers, without altering well-formed cabinets.
fn repair_cab_size(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 || &data[0..4] != b"MSCF" {
        return None;
    }
    let declared = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as u64;
    if declared <= data.len() as u64 {
        return None;
    }
    let mut out = data.to_vec();
    out[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
    Some(out)
}
