//! Unix `compress` (`.Z`) — LZW as specified by the original `compress(1)`.
//!
//! Every Unix reads `.Z`: libarchive/`bsdtar`, macOS, `gzip -d`, 7-Zip. It is
//! also old enough that a lot of tooling treats it as inert, which is exactly
//! what makes it usable as a wrapper.
//!
//! Format (public, and unchanged since 1985):
//!
//! ```text
//! 1F 9D  magic
//! xx     flags: bit 7 = block mode, bits 0-4 = max code width (9..=16)
//! ...    LZW codes, LSB-first, width growing from 9 bits as the table fills
//! ```
//!
//! Two details differ from the GIF/TIFF LZW that general-purpose crates
//! implement, which is why this is written out rather than delegated:
//!
//! * **The code stream is written in groups of eight codes.** Whenever the code
//!   width changes — on a table reset *and* on every width increase — the writer
//!   pads to the next multiple of `width * 8` bits before continuing. A decoder
//!   that skips the padding only on reset stays in step until the first width
//!   change and then reads garbage. Verified against `compress -b16`/`-b12`
//!   output from ncompress 5.0, which is where this was originally got wrong.
//! * **Block mode** reserves code 256 as a table reset.
//! * The width increases once the table reaches `1 << width` entries.
//!
//! The group boundary is measured from a base that MOVES to each padding point
//! — the reference restarts its input buffer there — and from the start of the
//! code stream, after the 3-byte header. Getting either of those wrong decodes
//! the first few hundred bytes correctly and then silently produces garbage,
//! which is why this is checked against real `compress` output rather than a
//! round-trip against a matching encoder.

use std::io::{self, Read};

use crate::source::{ByteSource, Bytes, Stepper};

const INIT_WIDTH: u32 = 9;
const MAX_WIDTH_LIMIT: u32 = 16;
const CLEAR: u16 = 256;
const FIRST_FREE: u16 = 257;

/// A decoder over a whole `.Z` file, header included, one code at a time.
struct Lzw<B> {
    data: B,
    max_width: u32,
    block_mode: bool,
    /// `prefix`/`suffix` are the classic parallel arrays: entry `c` extends
    /// entry `prefix[c]` by the byte `suffix[c]`.
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    next: u16,
    width: u32,
    prev: Option<u16>,
    stack: Vec<u8>,
    /// Bit cursor over the code stream (after the 3-byte header).
    bitpos: u64,
    total_bits: u64,
    /// Codes are written in groups of eight, and on any width change the
    /// writer pads to the next group boundary at the OLD width. The boundary is
    /// measured from a base that MOVES to each padding point, not from the
    /// start of the file: the reference restarts its input buffer there, so a
    /// decoder that aligns absolutely drifts after the first width change.
    base: u64,
}

impl<B: Bytes> Lzw<B> {
    /// `None` when the header is unusable.
    fn new(mut data: B) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }
        let flags = data.at(2);
        let max_width = (flags & 0x1f) as u32;
        let block_mode = flags & 0x80 != 0;
        if !(INIT_WIDTH..=MAX_WIDTH_LIMIT).contains(&max_width) {
            return None;
        }
        let table_cap = 1usize << max_width;
        let total_bits = (data.len() as u64 - 3) * 8;
        Some(Lzw {
            data,
            max_width,
            block_mode,
            prefix: vec![0u16; table_cap],
            suffix: vec![0u8; table_cap],
            next: if block_mode { FIRST_FREE } else { CLEAR },
            width: INIT_WIDTH,
            prev: None,
            stack: Vec::new(),
            bitpos: 0,
            total_bits,
            base: 0,
        })
    }

    fn align_to_group(&mut self) {
        let group = (self.width as u64) * 8;
        self.bitpos = self.base + (self.bitpos - self.base).div_ceil(group) * group;
        self.base = self.bitpos;
    }

    fn read_code(&mut self) -> Option<u16> {
        if self.bitpos + self.width as u64 > self.total_bits {
            return None;
        }
        let mut v: u32 = 0;
        for i in 0..self.width {
            let b = self.bitpos + i as u64;
            let byte = self.data.at(3 + (b / 8) as usize);
            let bit = (byte >> (b % 8)) & 1;
            v |= (bit as u32) << i; // LSB-first
        }
        self.bitpos += self.width as u64;
        Some(v as u16)
    }

    /// Append the string the next code expands to. `Some(false)` at the end of
    /// the input (a stream that ends mid-code is truncated, not corrupt),
    /// `None` for a code the table cannot expand.
    fn step(&mut self, out: &mut Vec<u8>) -> Option<bool> {
        let table_cap = self.prefix.len();
        loop {
            // Widen before reading, mirroring the writer: it grows the code
            // width as soon as the table reaches `(1 << width) - 1` entries,
            // and pads to the next group boundary at the old width as it does
            // so.
            if self.width < self.max_width && self.next as u32 >= (1u32 << self.width) {
                self.align_to_group();
                self.width += 1;
            }
            let Some(code) = self.read_code() else {
                return Some(false);
            };

            if self.block_mode && code == CLEAR {
                // A reset is also a width change: pad at the width in force,
                // then start over at the initial width.
                self.align_to_group();
                self.next = FIRST_FREE;
                self.width = INIT_WIDTH;
                self.prev = None;
                continue;
            }

            // Rebuild the string for `code` by walking the prefix chain.
            self.stack.clear();
            let mut cur = code;
            if cur >= self.next {
                // KwKwK: the code refers to the entry being defined right now.
                let p = self.prev?;
                self.stack.push(first_byte(&self.prefix, &self.suffix, p));
                cur = p;
            }
            let mut guard = 0usize;
            while cur >= 256 {
                if cur as usize >= table_cap || guard > table_cap {
                    return None; // cyclic or out-of-range chain
                }
                self.stack.push(self.suffix[cur as usize]);
                cur = self.prefix[cur as usize];
                guard += 1;
            }
            self.stack.push(cur as u8);
            out.extend(self.stack.iter().rev());

            // Define the next table entry from the previous code plus this
            // string's first byte.
            if let Some(p) = self.prev {
                if (self.next as usize) < table_cap {
                    self.prefix[self.next as usize] = p;
                    self.suffix[self.next as usize] = *self.stack.last().unwrap_or(&0);
                    self.next += 1;
                }
            }
            self.prev = Some(code);
            return Some(true);
        }
    }
}

/// Walk a `.Z` file: one member, decoded as it is read.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut crate::Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, crate::LimitHit> {
    use crate::stream::{emit_stream, single_meta};
    budget.count_entry()?;
    match content_reader(src) {
        Some(mut dec) => emit_stream(
            &single_meta("lzw-content", src, None),
            &mut dec,
            budget,
            visit,
        ),
        None => {
            let meta = single_meta(
                "lzw-content",
                src,
                Some("malformed Unix compress (.Z) stream"),
            );
            Ok(visit(&meta, None, budget))
        }
    }
}

/// The content of a `.Z` file as a `Read`, decoded as it is read, for the
/// streaming walk. `None` when the header is unusable.
pub(crate) fn content_reader(data: &dyn ByteSource) -> Option<LzwReader<'_>> {
    Some(LzwReader {
        src: data,
        lzw: Lzw::new(Stepper::new(data))?,
        staged: Vec::new(),
        taken: 0,
        done: false,
    })
}

pub(crate) struct LzwReader<'a> {
    src: &'a dyn ByteSource,
    lzw: Lzw<Stepper<'a>>,
    /// Decoded bytes not yet handed out.
    staged: Vec<u8>,
    taken: usize,
    done: bool,
}

impl Read for LzwReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.taken == self.staged.len() && !self.done {
            self.staged.clear();
            self.taken = 0;
            while self.staged.len() < 4096 {
                match self.lzw.step(&mut self.staged) {
                    Some(true) => {}
                    Some(false) => {
                        self.done = true;
                        break;
                    }
                    None => {
                        return Err(io::Error::other(self.src.read_error().unwrap_or_else(
                            || "malformed Unix compress (.Z) stream".to_string(),
                        )));
                    }
                }
            }
            // A source that failed reads as zeros: what came from them is not
            // the content.
            if let Some(e) = self.src.read_error() {
                self.done = true;
                self.staged.clear();
                return Err(io::Error::other(e));
            }
        }
        let n = (self.staged.len() - self.taken).min(out.len());
        out[..n].copy_from_slice(&self.staged[self.taken..self.taken + n]);
        self.taken += n;
        Ok(n)
    }
}

/// First byte of the string a code expands to.
fn first_byte(prefix: &[u16], suffix: &[u8], mut c: u16) -> u8 {
    let mut guard = 0usize;
    while c >= 256 {
        if c as usize >= prefix.len() || guard > prefix.len() {
            return 0;
        }
        c = prefix[c as usize];
        guard += 1;
        let _ = suffix;
    }
    c as u8
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    /// Input the source fails to deliver is a read error, not the end of the
    /// stream.
    #[test]
    fn a_source_that_fails_is_not_taken_for_the_end() {
        let blob = crate::read_fixture(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/lzw/bigreset.b16.Z"
        ))
        .unwrap();
        let mut all = Vec::new();
        super::content_reader(&blob)
            .unwrap()
            .read_to_end(&mut all)
            .unwrap();
        let src = crate::source::short_source(&blob[..1000], blob.len() as u64);
        let mut part = Vec::new();
        let read = super::content_reader(&src).unwrap().read_to_end(&mut part);
        assert!(read.is_err());
        assert!(part.len() < all.len() && all.starts_with(&part));
    }
}
