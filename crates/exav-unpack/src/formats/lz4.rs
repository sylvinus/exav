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

use crate::source::ByteSource;

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
    crate::bytes::at(d, off, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
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

/// Output kept for matches to reach back into: an offset is 16 bits.
const HISTORY: usize = 64 * 1024;

/// The largest block the reader takes in. A frame block is at most 4 MiB and
/// a legacy one at most 8 MiB compressed plus its worst-case growth.
const MAX_BLOCK_READ: usize = 16 * 1024 * 1024;

/// Walk an `.lz4` file: one member, decoded as it is read. The decoder holds
/// one block and the 64 KiB a match can reach back into.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut crate::Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, crate::LimitHit> {
    use crate::stream::{emit_stream, single_meta};
    budget.count_entry()?;
    match content_reader(src) {
        Ok(mut dec) => emit_stream(
            &single_meta("lz4-content", src, None),
            &mut dec,
            budget,
            visit,
        ),
        Err(reason) => Ok(visit(
            &single_meta("lz4-content", src, Some(reason)),
            None,
            budget,
        )),
    }
}

/// The content of every frame in `src`, concatenated, as a `Read` decoding a
/// block at a time. Frames concatenate: `lz4 -dc` on a file holding several
/// emits all of them, and stopping at the first end mark would leave a payload
/// behind it unscanned. `Err` when not one block decodes, with the reason.
pub(crate) fn content_reader(src: &dyn ByteSource) -> Result<Lz4Reader<'_>, &'static str> {
    let mut r = Lz4Reader {
        src,
        pos: 0,
        blocks: None,
        history: Vec::new(),
        handed: 0,
        done: false,
        failed: None,
    };
    if r.next_block()? {
        Ok(r)
    } else {
        Err("LZ4 frame holds no readable block")
    }
}

pub(crate) struct Lz4Reader<'a> {
    src: &'a dyn ByteSource,
    /// Where the frame being read starts, or the next one.
    pos: usize,
    /// Inside a frame: where its next block is, and how its blocks are laid
    /// out.
    blocks: Option<Blocks>,
    /// Decoded bytes: the last [`HISTORY`] handed out, then those not yet.
    history: Vec<u8>,
    handed: usize,
    done: bool,
    failed: Option<&'static str>,
}

#[derive(Clone, Copy)]
struct Blocks {
    p: usize,
    legacy: bool,
    block_checksum: bool,
    content_checksum: bool,
}

impl<'a> Lz4Reader<'a> {
    /// Up to `n` bytes at `at`, as many as the input holds there. `Err` when
    /// the source fails to give them.
    fn window(&self, at: usize, n: usize) -> Result<std::borrow::Cow<'a, [u8]>, &'static str> {
        let w = self.src.window(at, n);
        if w.len() < n.min(self.src.len().saturating_sub(at)) {
            return Err("LZ4 input could not be read");
        }
        Ok(w)
    }

    /// Leave the frame, the next one starting at `p`. `false` when that makes
    /// no progress.
    fn end_frame(&mut self, p: usize) -> bool {
        self.blocks = None;
        if p <= self.pos {
            return false;
        }
        self.pos = p;
        true
    }

    /// Decode the next block onto `history`. `Ok(false)` when no block is
    /// left, `Err` with the reason when one fails.
    fn next_block(&mut self) -> Result<bool, &'static str> {
        let len = self.src.len();
        loop {
            let Some(mut b) = self.blocks else {
                // Frames concatenate: `lz4 -dc` on a file holding several emits
                // all of them, one after another.
                let pos = self.pos;
                if pos.saturating_add(8) > len {
                    return Ok(false);
                }
                let head = self.window(pos, 32)?;
                let blocks = if head.starts_with(&LEGACY_MAGIC) {
                    Blocks {
                        p: pos + 4,
                        legacy: true,
                        block_checksum: false,
                        content_checksum: false,
                    }
                } else if head.starts_with(&MAGIC) {
                    let (off, block_checksum, content_checksum) = header(&head)?;
                    Blocks {
                        p: pos + off,
                        legacy: false,
                        block_checksum,
                        content_checksum,
                    }
                } else if head.len() >= 8 && head[0] & 0xF0 == 0x50 && head[1..4] == SKIPPABLE_MASK
                {
                    // A skippable frame carries no compressed data of its own.
                    let skip = le_u32(&head, 4).unwrap_or(0) as usize;
                    self.pos = pos.saturating_add(8).saturating_add(skip);
                    continue;
                } else {
                    // Trailing bytes that are not a frame.
                    return Ok(false);
                };
                self.blocks = Some(blocks);
                continue;
            };
            let Some(size) = le_u32(&self.window(b.p, 4)?, 0) else {
                if !self.end_frame(b.p) {
                    return Ok(false);
                }
                continue;
            };
            b.p += 4;
            if !b.legacy && size == 0 {
                // End mark, then the optional whole-frame checksum.
                if b.content_checksum {
                    b.p += 4;
                }
                if !self.end_frame(b.p) {
                    return Ok(false);
                }
                continue;
            }
            let stored = !b.legacy && size & BLOCK_UNCOMPRESSED != 0;
            let n = (size & !BLOCK_UNCOMPRESSED) as usize;
            if b.p.saturating_add(n) > len {
                // Truncated: those bytes are absent rather than hidden.
                if !self.end_frame(len) {
                    return Ok(false);
                }
                continue;
            }
            if n > MAX_BLOCK_READ {
                return Err("LZ4 block is larger than the format allows");
            }
            let body = self.window(b.p, n)?;
            b.p += n;
            // A frame block is held to the legacy size too, which is twice the
            // largest the format allows, so that one block cannot fill memory.
            let block_cap = self.history.len() + LEGACY_BLOCK;
            if stored {
                if self.history.len() + body.len() > block_cap {
                    return Err("LZ4 frame exceeds the size budget");
                }
                self.history.extend_from_slice(&body);
            } else {
                block(&body, &mut self.history, block_cap)?;
            }
            if b.block_checksum {
                b.p += 4;
            }
            self.blocks = Some(b);
            // A legacy frame has no end mark: it ends where the next frame's
            // magic begins, or at the end of the file.
            let next = self.window(b.p, 4)?;
            if b.p >= len
                || (b.legacy && (next.starts_with(&LEGACY_MAGIC) || next.starts_with(&MAGIC)))
            {
                self.end_frame(b.p);
            }
            return Ok(true);
        }
    }
}

impl std::io::Read for Lz4Reader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.handed < self.history.len() {
                let n = (self.history.len() - self.handed).min(out.len());
                out[..n].copy_from_slice(&self.history[self.handed..self.handed + n]);
                self.handed += n;
                return Ok(n);
            }
            if let Some(reason) = self.failed.take() {
                self.done = true;
                return Err(std::io::Error::other(reason));
            }
            if self.done {
                return Ok(0);
            }
            // Keep only what a match can still reach.
            let drop = self.handed.saturating_sub(HISTORY);
            self.history.drain(..drop);
            self.handed -= drop;
            match self.next_block() {
                Ok(true) => {}
                Ok(false) => self.done = true,
                Err(reason) => self.failed = Some(reason),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// Input the source fails to deliver is a read error, not the frame's end.
    #[test]
    fn a_source_that_fails_is_not_taken_for_the_end() {
        let blob = crate::read_fixture(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/lz4/one.lz4"
        ))
        .unwrap();
        assert!(super::content_reader(&blob).is_ok());
        let src = crate::source::short_source(&blob[..100], blob.len() as u64);
        assert_eq!(
            super::content_reader(&src).err(),
            Some("LZ4 input could not be read")
        );
    }
}
