//! NSIS (Nullsoft Scriptable Install System) installer extractor.
//!
//! Implemented from NSIS's own **zlib-licensed** format headers
//! (`Source/exehead/fileform.h`) and public reverse-engineering. An NSIS
//! installer is a PE stub (`MZ…`) followed by a *firstheader* and a compressed
//! data block:
//!
//! ```text
//! firstheader (0x1c bytes):
//!   0x00 u32     flags
//!   0x04 u8[16]  signature = LE 0xDEADBEEF + "NullsoftInst"
//!   0x14 u32     header_size
//!   0x18 u32     archive_size   // total bytes of the data block that follows
//!   0x1c ...     data block
//! ```
//!
//! The data block is either **solid** (one compressed stream over the whole
//! region) or **non-solid** (a sequence of `[u32 size][data]` blocks; the top bit
//! of `size` marks a block compressed). Compression is raw DEFLATE, LZMA, or
//! NSIS's modified bzip2, chosen from a block's leading bytes.
//!
//! Safe/partial: try a solid decode first, else walk the block sequence; a block
//! whose codec can't be decoded is surfaced as `unsupported`. All sizes are
//! attacker-controlled, so arithmetic saturates, slices are clamped, block count
//! is capped, and each decode is bounded by the [`Budget`].

use crate::*;
use std::io::Cursor;

/// 16-byte firstheader signature: LE `0xDEADBEEF` then ASCII `"NullsoftInst"`.
const NSIS_SIG: [u8; 16] = [
    0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's', b't',
];

const FIRSTHEADER_LEN: usize = 0x1c;
const MAX_BLOCKS: usize = 10_000;
const SOLID_MIN_OUTPUT: usize = 64;

#[inline]
fn u32le(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

/// The firstheader offset (its `flags` field, 4 bytes before the signature).
fn find_firstheader(data: &[u8]) -> Option<usize> {
    memchr::memmem::find(data, &NSIS_SIG)?.checked_sub(4)
}

/// True if `data` is a PE stub carrying the NSIS firstheader signature.
pub(crate) fn is_nsis(data: &[u8]) -> bool {
    data.starts_with(b"MZ") && find_firstheader(data).is_some()
}

pub(crate) fn extract_nsis<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let Some(fh) = find_firstheader(data) else {
        return Ok(None);
    };
    let data_start = fh.saturating_add(FIRSTHEADER_LEN);
    if data_start > data.len() {
        return Ok(None);
    }
    let archive_size = u32le(data, fh + 0x18) as usize;
    let arch_end = data_start.saturating_add(archive_size).min(data.len());
    if arch_end <= data_start {
        return Ok(None);
    }

    // Solid attempt: the whole region as one compressed stream.
    let cap = budget.reserve()?;
    if let Some(bytes) = decode_stream(&data[data_start..arch_end], cap) {
        if bytes.len() >= SOLID_MIN_OUTPUT {
            budget.count_entry()?;
            budget.commit(bytes.len() as u64);
            return Ok(visit(Entry::new("nsis-solid".to_string(), bytes), budget));
        }
    }

    // Non-solid: a `[u32 size][data]` block sequence.
    let mut pos = data_start;
    let mut n = 0usize;
    while pos + 4 <= arch_end && n < MAX_BLOCKS {
        let word = u32le(data, pos);
        pos += 4;
        let compressed = word & 0x8000_0000 != 0;
        let size = (word & 0x7fff_ffff) as usize;
        if size == 0 {
            n += 1;
            continue;
        }
        let clamped = size.min(arch_end - pos);
        let block = &data[pos..pos + clamped];
        pos += clamped;
        n += 1;

        budget.count_entry()?;
        let cap = budget.reserve()?;
        let decoded = if compressed {
            decode_stream(block, cap)
        } else {
            Some(block[..clamped.min(cap as usize)].to_vec())
        };
        let stop = match decoded {
            Some(bytes) => {
                budget.commit(bytes.len() as u64);
                visit(Entry::new(format!("nsis-{n}"), bytes), budget)
            }
            None => visit(
                Entry::unsupported(
                    format!("nsis-{n}"),
                    clamped as u64,
                    false,
                    "NSIS block codec",
                ),
                budget,
            ),
        };
        if let Some(r) = stop {
            return Ok(Some(r));
        }
        if clamped < size {
            break;
        }
    }
    Ok(None)
}

/// Decode one NSIS compressed stream, selecting the codec from the leading byte:
/// `'1'` ⇒ NSIS bzip2, `0x5d` ⇒ LZMA props, else raw DEFLATE — with a fallback.
fn decode_stream(block: &[u8], cap: u64) -> Option<Vec<u8>> {
    match block.first().copied()? {
        b'1' => decode_bzip2(block, cap).or_else(|| decode_deflate(block, cap)),
        0x5d => decode_lzma(block, cap).or_else(|| decode_deflate(block, cap)),
        _ => decode_deflate(block, cap).or_else(|| decode_lzma(block, cap)),
    }
}

fn nonempty(r: Result<(Vec<u8>, bool), std::io::Error>) -> Option<Vec<u8>> {
    match r {
        Ok((out, _)) if !out.is_empty() => Some(out),
        _ => None,
    }
}

/// Raw DEFLATE (NSIS "zlib", no zlib wrapper).
fn decode_deflate(block: &[u8], cap: u64) -> Option<Vec<u8>> {
    nonempty(bounded_read(flate2::read::DeflateDecoder::new(block), cap))
}

/// NSIS LZMA: 1 props byte + u32 dictionary size, then the stream (size unknown,
/// decoded to the end marker).
fn decode_lzma(block: &[u8], cap: u64) -> Option<Vec<u8>> {
    if block.len() < 5 {
        return None;
    }
    let reader = lzma_rust2::LzmaReader::new_with_props(
        Cursor::new(&block[5..]),
        u64::MAX,
        block[0],
        u32le(block, 1),
        None,
    )
    .ok()?;
    nonempty(bounded_read(reader, cap))
}

/// NSIS's modified bzip2 (header stripped); the stock decoder usually rejects it,
/// in which case the block is reported unsupported.
fn decode_bzip2(block: &[u8], cap: u64) -> Option<Vec<u8>> {
    nonempty(bounded_read(
        bzip2_rs::DecoderReader::new(Cursor::new(block)),
        cap,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::DeflateEncoder, Compression};
    use std::io::Write;

    fn synthetic_nsis(deflate_block: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"MZ");
        out.extend_from_slice(&[0u8; 62]);
        let fh = out.len();
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        out.extend_from_slice(&NSIS_SIG);
        out.extend_from_slice(&0u32.to_le_bytes()); // header_size
        let asz = 4 + deflate_block.len();
        out.extend_from_slice(&(asz as u32).to_le_bytes()); // archive_size
        debug_assert_eq!(out.len(), fh + FIRSTHEADER_LEN);
        out.extend_from_slice(&((deflate_block.len() as u32) | 0x8000_0000).to_le_bytes());
        out.extend_from_slice(deflate_block);
        out
    }

    fn raw_deflate(payload: &[u8]) -> Vec<u8> {
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
        enc.write_all(payload).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn detects_and_extracts() {
        let blob = synthetic_nsis(&raw_deflate(b"MALWARETEST inside an NSIS deflate block"));
        assert!(is_nsis(&blob));
        assert_eq!(detect(&blob), Some(Format::Nsis));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Nsis, &blob, &mut budget).unwrap();
        assert!(entries
            .iter()
            .any(|e| e.data.windows(11).any(|w| w == b"MALWARETEST")));
    }

    #[test]
    fn non_nsis_pe_yields_nothing() {
        let mut blob = b"MZ".to_vec();
        blob.extend_from_slice(&[0u8; 512]);
        assert!(!is_nsis(&blob));
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Nsis, &blob, &mut budget)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn truncated_firstheader_no_panic() {
        let mut blob = b"MZ".to_vec();
        blob.extend_from_slice(&[0u8; 8]);
        blob.extend_from_slice(&NSIS_SIG);
        let mut budget = Budget::new(Limits::default());
        assert!(extract(Format::Nsis, &blob, &mut budget)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn garbage_block_unsupported_no_panic() {
        let mut junk = vec![0x02u8];
        junk.extend_from_slice(&[0xffu8; 40]);
        let blob = synthetic_nsis(&junk);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Nsis, &blob, &mut budget).unwrap();
        assert!(entries
            .iter()
            .all(|e| e.unsupported.is_some() || !e.data.is_empty()));
    }

    #[test]
    fn absurd_archive_size_clamped() {
        let mut blob = synthetic_nsis(&raw_deflate(b"payload"));
        let sig = memchr::memmem::find(&blob, &NSIS_SIG).unwrap();
        let asz_off = sig + 16;
        blob[asz_off..asz_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut budget = Budget::new(Limits::default());
        let _ = extract(Format::Nsis, &blob, &mut budget).unwrap();
    }
}
