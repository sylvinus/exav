#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

const XZ_MAGIC: &[u8] = &[0xFD, b'7', b'z', b'X', b'Z', 0x00];

pub(crate) fn extract_xz<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let (out, truncated) = decode_xz_streams(data, cap)?;
    if truncated {
        return Err(LimitHit::new("xz member exceeds budget".to_string()));
    }
    ratio_guard(data.len() as u64, out.len() as u64, budget)?;
    budget.commit(out.len() as u64);
    Ok(visit(Entry::new("xz-content".to_string(), out), budget))
}

/// Decode every concatenated `.xz` stream (`pixz`/parallel-xz produce
/// multi-stream files, and `lzma_rs::xz_decompress` errors outright on the
/// trailing streams). Split on the 6-byte xz stream magic, decode each stream
/// (trimming the inter-stream zero padding), and concatenate. Single-stream
/// files take the fast path; a spurious magic inside compressed data (≈1 in
/// 2^48) makes a slice fail to decode and we fall back to a plain decode.
fn decode_xz_streams(data: &[u8], cap: u64) -> Result<(Vec<u8>, bool), LimitHit> {
    let starts: Vec<usize> = memchr::memmem::find_iter(data, XZ_MAGIC).collect();
    if starts.len() <= 1 {
        return decode_one_xz(data, cap);
    }
    let mut out = Vec::new();
    for i in 0..starts.len() {
        let s = starts[i];
        let e = starts.get(i + 1).copied().unwrap_or(data.len());
        // Trim trailing zero padding (xz "Stream Padding") so the slice is exactly
        // one stream — lzma_rs rejects trailing bytes.
        let mut slice = &data[s..e];
        while slice.last() == Some(&0) {
            slice = &slice[..slice.len() - 1];
        }
        let remaining = cap - out.len() as u64;
        match decode_one_xz(slice, remaining) {
            Ok((bytes, truncated)) => {
                out.extend_from_slice(&bytes);
                if truncated {
                    return Ok((out, true));
                }
            }
            Err(_) => return decode_one_xz(data, cap),
        }
    }
    Ok((out, false))
}

/// Decode a single `.xz` stream into a budget-capped buffer.
fn decode_one_xz(data: &[u8], cap: u64) -> Result<(Vec<u8>, bool), LimitHit> {
    // lzma-rs is writer-based; cap the writer so a bomb can't allocate past the
    // budget (it stops and reports the overflow rather than decoding it all).
    let mut sink = CapWriter::new(cap);
    let mut input = std::io::BufReader::new(Cursor::new(data));
    match lzma_rs::xz_decompress(&mut input, &mut sink) {
        Ok(()) => {}
        Err(_) if sink.over => return Ok((sink.buf, true)),
        Err(e) => return Err(LimitHit::new(format!("xz: {e}"))),
    }
    Ok((sink.buf, false))
}
