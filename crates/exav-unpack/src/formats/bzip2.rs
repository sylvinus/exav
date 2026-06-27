#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

pub(crate) fn extract_bzip2<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let (out, truncated) = decode_bzip2_streams(data, cap)?;
    if truncated {
        return Err(LimitHit::new("bzip2 member exceeds budget".to_string()));
    }
    ratio_guard(data.len() as u64, out.len() as u64, budget)?;
    budget.commit(out.len() as u64);
    Ok(visit(Entry::new("bzip2-content".to_string(), out), budget))
}

/// Decode every concatenated bzip2 stream (a bzip2 file may be several — `pbzip2`
/// produces multi-stream output, and the payload can live in a later one).
/// `DecoderReader` decodes only the first stream.
///
/// bzip2's decoder buffers a full block ahead, so the exact stream boundary
/// can't be recovered from the decoder. Instead split on the `BZh[1-9]` stream
/// magic and decode each slice independently. This is a no-op for the common
/// single-stream file, and if a `BZh[1-9]` happens to occur *inside* compressed
/// data (≈1 in 2^32 per position) a slice fails to decode and we fall back to a
/// plain single-stream decode — so the result is never worse than before.
fn decode_bzip2_streams(data: &[u8], cap: u64) -> Result<(Vec<u8>, bool), LimitHit> {
    let starts = bzip2_stream_starts(data);
    if starts.len() <= 1 {
        return decode_one_bzip2(data, cap);
    }
    let mut out = Vec::new();
    for i in 0..starts.len() {
        let s = starts[i];
        let e = starts.get(i + 1).copied().unwrap_or(data.len());
        let remaining = cap - out.len() as u64;
        match decode_one_bzip2(&data[s..e], remaining) {
            Ok((bytes, truncated)) => {
                out.extend_from_slice(&bytes);
                if truncated {
                    return Ok((out, true));
                }
            }
            // A split landed inside a stream (spurious magic): the multi-stream
            // assumption is wrong — decode the whole input as one stream.
            Err(_) => return decode_one_bzip2(data, cap),
        }
    }
    Ok((out, false))
}

/// Offsets of bzip2 stream headers (`BZh` followed by a `1`-`9` block-size).
fn bzip2_stream_starts(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    for off in memchr::memmem::find_iter(data, b"BZh") {
        if matches!(data.get(off + 3), Some(b'1'..=b'9')) {
            out.push(off);
        }
    }
    out
}

/// Decode a single bzip2 stream, capped at `cap` output bytes.
fn decode_one_bzip2(data: &[u8], cap: u64) -> Result<(Vec<u8>, bool), LimitHit> {
    bounded_read(bzip2_rs::DecoderReader::new(Cursor::new(data)), cap)
        .map_err(|e| LimitHit::new(format!("bzip2: {e}")))
}
