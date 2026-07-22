//! LZ4 — the frame format (`.lz4`).
//!
//! 7-Zip ZS, PeaZip and every Unix box with `lz4(1)` open these, and the codec
//! turns up inside other containers often enough that a standalone frame is an
//! ordinary thing to be handed. The payload is compressed, so a raw pattern scan
//! sees nothing.
//!
//! Implemented from the public LZ4 frame and block specifications. All fields
//! are **little-endian**.
//!
//! ```text
//! magic (4) | FLG | BD | [content size 8] | [dict id 4] | HC
//! block: u32 size  (top bit set => stored verbatim) | data | [block checksum 4]
//! ...
//! end mark: u32 0  | [content checksum 4]
//! ```
//!
//! Blocks may be **linked**: with `B.Indep` clear a match can reach back into
//! the previous block, so every block decodes into one continuous buffer rather
//! than being decompressed on its own.

use crate::{Budget, Entry, Format, LimitHit, Sink};

fn is_lz4(d: &[u8]) -> bool {
    super::sniff::is(d, Format::Lz4)
}

/// Skippable frames are `0x184D2A50`..`0x184D2A5F`: a length and payload a
/// reader steps over. Needed here to find the next frame when several are
/// concatenated, not just to recognise the first.
const SKIPPABLE_MASK: [u8; 3] = [0x2A, 0x4D, 0x18];

/// `0x184D2204`, little-endian on disk. Also used to find the next frame when
/// several are concatenated, which is why it stays here as well as in `sniff`.
const MAGIC: [u8; 4] = [0x04, 0x22, 0x4D, 0x18];
/// The pre-1.5 "legacy" frame, still written by `lz4 -l` and some embedders.
const LEGACY_MAGIC: [u8; 4] = [0x02, 0x21, 0x4C, 0x18];

/// FLG bits.
const FLG_VERSION_MASK: u8 = 0b1100_0000;
const FLG_VERSION: u8 = 0b0100_0000;
const FLG_BLOCK_CHECKSUM: u8 = 1 << 4;
const FLG_CONTENT_SIZE: u8 = 1 << 3;
const FLG_CONTENT_CHECKSUM: u8 = 1 << 2;
const FLG_DICT_ID: u8 = 1 << 0;

/// A block whose top size bit is set is stored, not compressed.
const BLOCK_UNCOMPRESSED: u32 = 0x8000_0000;

/// Legacy frames use a fixed 8 MiB block size.
const LEGACY_BLOCK: usize = 8 * 1024 * 1024;

fn le_u32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Decompress one LZ4 block, appending to `out`. Matches may reach back before
/// `block_start` when blocks are linked, which is why the whole output buffer is
/// passed rather than a per-block one.
fn block(src: &[u8], out: &mut Vec<u8>, cap: usize) -> Result<(), &'static str> {
    let mut i = 0usize;
    while i < src.len() {
        let token = src[i];
        i += 1;
        // Literal length: the high nibble, extended by 255-terminated bytes.
        let mut lit = (token >> 4) as usize;
        if lit == 15 {
            loop {
                let b = *src.get(i).ok_or("LZ4 literal length runs past the block")?;
                i += 1;
                lit += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        let end = i.checked_add(lit).ok_or("LZ4 literal length overflows")?;
        let lits = src.get(i..end).ok_or("LZ4 literals run past the block")?;
        if out.len() + lits.len() > cap {
            return Err("LZ4 frame exceeds the size budget");
        }
        out.extend_from_slice(lits);
        i = end;

        // The last sequence in a block is literals only, with no match after it.
        if i >= src.len() {
            break;
        }
        let offset = u16::from_le_bytes([
            *src.get(i).ok_or("LZ4 match offset is truncated")?,
            *src.get(i + 1).ok_or("LZ4 match offset is truncated")?,
        ]) as usize;
        i += 2;
        if offset == 0 || offset > out.len() {
            return Err("LZ4 match points before the start of the stream");
        }
        let mut len = (token & 0x0F) as usize;
        if len == 15 {
            loop {
                let b = *src.get(i).ok_or("LZ4 match length runs past the block")?;
                i += 1;
                len += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        // The minimum match is 4 bytes, so the stored length is biased by it.
        len += 4;
        if out.len() + len > cap {
            return Err("LZ4 frame exceeds the size budget");
        }
        // Overlapping matches are legal and common — a run of one byte is
        // encoded as offset 1 — so this copies byte by byte on purpose.
        let start = out.len() - offset;
        for k in 0..len {
            let b = out[start + k];
            out.push(b);
        }
    }
    Ok(())
}

/// Read the frame header, returning where the block data starts and whether each
/// block carries a trailing checksum.
fn header(data: &[u8]) -> Result<(usize, bool, bool), &'static str> {
    let flg = *data.get(4).ok_or("LZ4 frame header is truncated")?;
    if flg & FLG_VERSION_MASK != FLG_VERSION {
        return Err("LZ4 frame version is not one exav reads");
    }
    let mut off = 6; // magic(4) + FLG + BD
    if flg & FLG_CONTENT_SIZE != 0 {
        off += 8;
    }
    if flg & FLG_DICT_ID != 0 {
        // A dictionary lives outside the file, so anything compressed against
        // one cannot be reconstructed from this file alone.
        return Err("LZ4 frame uses an external dictionary");
    }
    off += 1; // header checksum
    if off > data.len() {
        return Err("LZ4 frame header is truncated");
    }
    Ok((
        off,
        flg & FLG_BLOCK_CHECKSUM != 0,
        flg & FLG_CONTENT_CHECKSUM != 0,
    ))
}

pub(crate) fn extract_lz4<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !is_lz4(data) {
        return Ok(None);
    }
    budget.count_entry()?;
    let cap = budget.reserve()? as usize;

    let mut out: Vec<u8> = Vec::new();
    let mut decoded_any = false;
    let mut pos = 0usize;

    // Frames concatenate: `lz4 -dc` on a file holding several emits all of them,
    // one after another. Stopping at the first end mark would leave everything
    // behind it unscanned, which is a one-command way to hide a payload.
    while pos + 8 <= data.len() {
        let legacy = data[pos..].starts_with(&LEGACY_MAGIC);
        let (mut p, block_checksum, content_checksum) = if legacy {
            (pos + 4, false, false)
        } else if data[pos..].starts_with(&MAGIC) {
            match header(&data[pos..]) {
                Ok((off, bc, cc)) => (pos + off, bc, cc),
                Err(reason) => {
                    return finish(out, decoded_any, reason, data.len() as u64, budget, visit)
                }
            }
        } else if data[pos] & 0xF0 == 0x50 && data[pos + 1..pos + 4] == SKIPPABLE_MASK {
            // A skippable frame carries no compressed data of its own; step over
            // it and carry on with whatever follows.
            let len = le_u32(data, pos + 4).unwrap_or(0) as usize;
            pos = pos.saturating_add(8).saturating_add(len);
            continue;
        } else {
            // Trailing bytes that are not a frame. If nothing decoded at all the
            // file was never really LZ4; otherwise this is junk after the data.
            break;
        };

        while let Some(size) = le_u32(data, p) {
            p += 4;
            if !legacy && size == 0 {
                // End mark, then the optional whole-frame checksum.
                if content_checksum {
                    p += 4;
                }
                break;
            }
            let stored = !legacy && size & BLOCK_UNCOMPRESSED != 0;
            let n = (size & !BLOCK_UNCOMPRESSED) as usize;
            // A block extending past the end means the file is truncated: those
            // bytes are absent rather than hidden, and what came before is kept.
            let Some(body) = data.get(p..p + n) else {
                p = data.len();
                break;
            };
            p += n;
            let block_cap = if legacy {
                cap.min(out.len() + LEGACY_BLOCK)
            } else {
                cap
            };
            if stored {
                if out.len() + body.len() > block_cap {
                    return finish(
                        out,
                        decoded_any,
                        "LZ4 frame exceeds the size budget",
                        data.len() as u64,
                        budget,
                        visit,
                    );
                }
                out.extend_from_slice(body);
            } else if let Err(reason) = block(body, &mut out, block_cap) {
                return finish(out, decoded_any, reason, data.len() as u64, budget, visit);
            }
            decoded_any = true;
            if block_checksum {
                p += 4;
            }
            if p >= data.len() {
                break;
            }
            // A legacy frame has no end mark: it ends where the next frame's
            // magic begins, or at the end of the file.
            if legacy && (data[p..].starts_with(&LEGACY_MAGIC) || data[p..].starts_with(&MAGIC)) {
                break;
            }
        }
        if p <= pos {
            break; // no progress — malformed
        }
        pos = p;
    }

    if !decoded_any {
        return report(
            "LZ4 frame holds no readable block",
            data.len() as u64,
            budget,
            visit,
        );
    }
    budget.commit(out.len() as u64);
    Ok(visit(Entry::new("lz4-content".to_string(), out), budget))
}

/// A frame that failed partway has still produced real bytes. Emitting them and
/// reporting the failure beats discarding content that was successfully decoded.
fn finish<R>(
    out: Vec<u8>,
    decoded_any: bool,
    reason: &'static str,
    size: u64,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if !decoded_any {
        return report(reason, size, budget, visit);
    }
    budget.count_entry()?;
    if let Some(r) = visit(
        Entry::unsupported("lz4-content".to_string(), size, false, reason),
        budget,
    ) {
        return Ok(Some(r));
    }
    budget.commit(out.len() as u64);
    Ok(visit(Entry::new("lz4-content".to_string(), out), budget))
}

fn report<R>(
    reason: &'static str,
    size: u64,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    Ok(visit(
        Entry::unsupported("lz4-content".to_string(), size, false, reason),
        budget,
    ))
}
