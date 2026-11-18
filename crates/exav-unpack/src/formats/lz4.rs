//! LZ4: the frame format (`.lz4`).
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
pub(crate) fn block(src: &[u8], out: &mut Vec<u8>, cap: usize) -> Result<(), &'static str> {
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
        // Overlapping matches are legal and common (a run of one byte is
        // encoded as offset 1), so this copies byte by byte on purpose.
        let start = out.len() - offset;
        for k in 0..len {
            let b = out[start + k];
            out.push(b);
        }
    }
    Ok(())
}

/// Where [`BlockReader`] is in a block.
enum Seq {
    /// At the token of a sequence.
    Token,
    /// In the literals of a sequence: how many are left, and the token whose
    /// low nibble is the length of the match that follows them, unless they
    /// are the block's last.
    Literals(usize, u8),
    /// In a match: how many bytes are left to copy, and from how far back.
    Match(usize, usize),
    Done,
}

/// One LZ4 block (no frame) read as it is decoded, for a block whose output
/// is too long to hold: what is held is the block's input, the last 64 KiB of
/// output, which a match can reach, and what the caller has not read yet. The
/// block ends after `want` bytes, as a partial decode of a block does, and the
/// rest of its input is left unread. Its bytes and its errors are those of
/// [`block`]: a bad offset is `InvalidData`, input that ends before `want`
/// bytes were made is `UnexpectedEof`, and the bytes before an error are read
/// before it.
#[cfg_attr(not(feature = "erofs"), allow(dead_code))]
pub(crate) struct BlockReader {
    src: Vec<u8>,
    at: usize,
    /// The output kept: the last [`HISTORY`] bytes, then those not yet read.
    out: Vec<u8>,
    read: usize,
    /// How many bytes of output were dropped from `out`.
    dropped: u64,
    /// How many more bytes the block gives.
    left: u64,
    seq: Seq,
    /// The error that ends the block, to come after the bytes before it.
    failed: Option<std::io::Error>,
}

#[cfg_attr(not(feature = "erofs"), allow(dead_code))]
impl BlockReader {
    pub(crate) fn new(src: Vec<u8>, want: u64) -> Self {
        BlockReader {
            src,
            at: 0,
            out: Vec::new(),
            read: 0,
            dropped: 0,
            left: want,
            seq: if want == 0 { Seq::Done } else { Seq::Token },
            failed: None,
        }
    }

    /// A length: `n`, and the bytes of an extension where it is 15.
    fn length(&mut self, n: usize) -> Result<usize, std::io::Error> {
        let mut len = n;
        if n == 15 {
            loop {
                let b = *self.src.get(self.at).ok_or_else(truncated)?;
                self.at += 1;
                len = len.saturating_add(b as usize);
                if b != 255 {
                    break;
                }
            }
        }
        Ok(len)
    }

    /// Decode a piece of the block onto `out`: at most `room` bytes of
    /// literals or of a match.
    fn step(&mut self, room: usize) -> Result<(), std::io::Error> {
        let left = usize::try_from(self.left).unwrap_or(usize::MAX);
        match self.seq {
            Seq::Done => {}
            Seq::Token => {
                let token = *self.src.get(self.at).ok_or_else(truncated)?;
                self.at += 1;
                let lit = self.length((token >> 4) as usize)?;
                if self.at.checked_add(lit).is_none_or(|e| e > self.src.len()) {
                    return Err(invalid("LZ4 literals run past the block"));
                }
                self.seq = Seq::Literals(lit, token);
            }
            Seq::Literals(n, token) => {
                let take = n.min(room).min(left);
                self.out
                    .extend_from_slice(&self.src[self.at..self.at + take]);
                self.at += take;
                self.left -= take as u64;
                let n = n - take;
                if self.left == 0 {
                    self.seq = Seq::Done;
                } else if n > 0 {
                    self.seq = Seq::Literals(n, token);
                } else if self.at >= self.src.len() {
                    // The block's last sequence is literals only, and the
                    // block is short of what was wanted.
                    return Err(truncated());
                } else {
                    let bytes = self.src.get(self.at..self.at + 2).ok_or_else(truncated)?;
                    let offset = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
                    self.at += 2;
                    let made = self.dropped + self.out.len() as u64;
                    if offset == 0 || offset as u64 > made {
                        return Err(invalid("LZ4 match points before the start of the block"));
                    }
                    // The minimum match is 4 bytes, so the length is biased by it.
                    let len = self.length((token & 0x0F) as usize)?.saturating_add(4);
                    self.seq = Seq::Match(len, offset);
                }
            }
            Seq::Match(n, offset) => {
                let take = n.min(room).min(left);
                // The copy may overlap what it writes. The last 64 KiB are
                // kept, so `offset` is in `out`.
                let start = self.out.len() - offset;
                if offset >= take {
                    self.out.extend_from_within(start..start + take);
                } else {
                    for k in 0..take {
                        let b = self.out[start + k];
                        self.out.push(b);
                    }
                }
                self.left -= take as u64;
                let n = n - take;
                self.seq = if self.left == 0 {
                    Seq::Done
                } else if n > 0 {
                    Seq::Match(n, offset)
                } else {
                    Seq::Token
                };
            }
        }
        Ok(())
    }
}

fn truncated() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "LZ4 block ends before its output does",
    )
}

fn invalid(why: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, why)
}

impl std::io::Read for BlockReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.out.len() - self.read < buf.len()
            && self.failed.is_none()
            && !matches!(self.seq, Seq::Done)
        {
            let want = buf.len() - (self.out.len() - self.read);
            if let Err(e) = self.step(want.max(4096)) {
                self.failed = Some(e);
            }
        }
        let n = buf.len().min(self.out.len() - self.read);
        if n == 0 {
            return self.failed.take().map_or(Ok(0), Err);
        }
        buf[..n].copy_from_slice(&self.out[self.read..self.read + n]);
        self.read += n;
        // Keep only what a match can still reach.
        if self.read > 2 * HISTORY {
            let drop = self.read - HISTORY;
            self.out.drain(..drop);
            self.read -= drop;
            self.dropped += drop as u64;
        }
        Ok(n)
    }
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
pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut crate::Budget,
    visit: crate::stream::Visit<()>,
) -> Result<Option<()>, crate::LimitHit> {
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

    use super::{BlockReader, HISTORY, block};
    use std::io::Read;

    /// An LZ4 block of `data`, by a greedy match finder: the kinds of sequence
    /// a real encoder makes (long literals, long matches, overlapping ones).
    fn encode(data: &[u8]) -> Vec<u8> {
        fn sequence(out: &mut Vec<u8>, lits: &[u8], m: Option<(usize, usize)>) {
            let ext = |out: &mut Vec<u8>, mut n: usize| {
                while n >= 255 {
                    out.push(255);
                    n -= 255;
                }
                out.push(n as u8);
            };
            let mlen = m.map_or(0, |(_, l)| l - 4);
            out.push((lits.len().min(15) as u8) << 4 | mlen.min(15) as u8);
            if lits.len() >= 15 {
                ext(out, lits.len() - 15);
            }
            out.extend_from_slice(lits);
            if let Some((offset, _)) = m {
                out.extend_from_slice(&(offset as u16).to_le_bytes());
                if mlen >= 15 {
                    ext(out, mlen - 15);
                }
            }
        }
        let mut out = Vec::new();
        let mut table = std::collections::HashMap::new();
        let (mut i, mut anchor) = (0, 0);
        while i + 9 <= data.len() {
            let key = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            let prev = table.insert(key, i);
            match prev.filter(|&p| i - p <= 65535 && data[p..p + 4] == data[i..i + 4]) {
                Some(p) => {
                    let mut len = 4;
                    while i + len < data.len() - 5 && data[p + len] == data[i + len] {
                        len += 1;
                    }
                    sequence(&mut out, &data[anchor..i], Some((i - p, len)));
                    i += len;
                    anchor = i;
                }
                None => i += 1,
            }
        }
        sequence(&mut out, &data[anchor..], None);
        out
    }

    /// Text with phrases that come back near and far, and runs.
    fn sample(n: usize) -> Vec<u8> {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut out: Vec<u8> = Vec::new();
        while out.len() < n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            match (x % 5, out.len()) {
                (0, len) if len > 100 => {
                    let back = 1 + (x >> 8) as usize % len.min(65535);
                    for _ in 0..(4 + (x >> 40) as usize % 400) {
                        out.push(out[out.len() - back]);
                    }
                }
                (1, _) => out.extend(std::iter::repeat_n(
                    (x >> 20) as u8,
                    1 + (x >> 30) as usize % 700,
                )),
                (2, _) => out.push((x >> 24) as u8),
                _ => out.extend_from_slice(b"the quick brown fox jumps "),
            }
        }
        out.truncate(n);
        out
    }

    fn read_all(mut r: impl Read, chunk: usize) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let mut buf = vec![0u8; chunk];
        loop {
            match r.read(&mut buf) {
                Ok(0) => return (out, true),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(_) => return (out, false),
            }
        }
    }

    /// Read as it goes, a block gives what [`block`] gives, whatever the size
    /// of the reads, and a block cut at `want` gives that many bytes.
    #[test]
    fn a_block_read_as_it_goes_is_the_block_decoded() {
        for n in [1000, 70_000, 400_000] {
            let data = sample(n);
            let enc = encode(&data);
            let mut whole = Vec::new();
            block(&enc, &mut whole, usize::MAX).unwrap();
            assert!(whole == data, "{n}: the encoder");
            for chunk in [1, 7, 4096, 100_000] {
                let (got, ok) = read_all(BlockReader::new(enc.clone(), n as u64), chunk);
                assert!(ok && got == data, "{n} bytes, reads of {chunk}");
            }
            for want in [1, n / 3, n - 1] {
                let (got, ok) = read_all(BlockReader::new(enc.clone(), want as u64), 999);
                assert!(ok && got == data[..want], "{n} bytes, cut at {want}");
            }
        }
    }

    /// A damaged block gives the bytes [`block`] had made when it failed, and
    /// then fails, and one that ends early is the error and not a short block.
    #[test]
    fn a_damaged_block_gives_what_came_before_the_damage() {
        let data = sample(50_000);
        let enc = encode(&data);
        let mut x = 12345u32;
        let mut next = || {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            (x >> 8) as usize
        };
        for round in 0..400 {
            let mut bad = enc.clone();
            match round % 3 {
                0 => bad.truncate(next() % bad.len()),
                1 => {
                    for _ in 0..1 + next() % 3 {
                        let at = next() % bad.len();
                        bad[at] ^= 1 << (next() % 8);
                    }
                }
                _ => {
                    let at = next() % bad.len();
                    bad[at..].fill(0xFF);
                }
            }
            let mut want = Vec::new();
            let whole = block(&bad, &mut want, usize::MAX);
            // Asked for more than the block makes, the reader makes the same
            // bytes and fails, unless the block was well formed.
            let (got, ok) = read_all(BlockReader::new(bad.clone(), want.len() as u64 + 1), 333);
            assert!(got == want, "round {round}: the bytes before the end");
            assert!(
                !ok,
                "round {round}: asked for a byte more than the block has"
            );
            if whole.is_ok() {
                let (got, ok) = read_all(BlockReader::new(bad, want.len() as u64), 333);
                assert!(ok && got == want, "round {round}: a block that decodes");
            }
        }
    }

    /// What is held is the input, the 64 KiB a match reaches, and what has not
    /// been read: a block that is 16 MiB of one byte is read through a
    /// window.
    #[test]
    fn a_long_block_is_read_through_a_window() {
        let n = 16 << 20;
        let mut data = vec![7u8; n];
        data[..9].copy_from_slice(b"beginning");
        data[n - 3..].copy_from_slice(b"end");
        let enc = encode(&data);
        assert!(enc.len() < 100_000, "{}", enc.len());
        let mut r = BlockReader::new(enc, n as u64);
        let mut buf = vec![0u8; 4096];
        let (mut total, mut most) = (0usize, 0usize);
        let mut tail = Vec::new();
        loop {
            let got = r.read(&mut buf).unwrap();
            if got == 0 {
                break;
            }
            total += got;
            most = most.max(r.out.capacity());
            tail.extend_from_slice(&buf[..got]);
            tail.drain(..tail.len().saturating_sub(3));
        }
        assert_eq!(total, n);
        assert_eq!(tail, b"end");
        // The window and what is read at once, with the slack of a growing
        // vector, and not the 16 MiB of the block.
        assert!(most <= 6 * HISTORY, "the window held {most} bytes");
    }
}
