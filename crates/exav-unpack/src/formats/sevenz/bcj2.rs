//! BCJ2: 7-Zip's x86 branch converter, the four-input one.
//!
//! 7-Zip selects BCJ2 automatically for executables at high compression
//! settings, so "a 7z of an .exe at `-mx=9`" is an entirely ordinary thing for
//! an attacker to produce. Unlike every other 7z coder it takes **four** input
//! streams rather than one, which is why it needs the folder's bind-pair graph
//! rather than the linear chain the other codecs use:
//!
//! * **main**: the instruction bytes, with converted addresses removed
//! * **call**: 4-byte big-endian absolute targets for `E8` (CALL)
//! * **jump**: the same for `E9` (JMP)
//! * **rc**: a range-coded bit per candidate opcode, saying whether it was
//!   actually converted
//!
//! The filter rewrites absolute branch targets back to the relative form the
//! instruction encoding uses. The range coder is the standard LZMA one (11-bit
//! probabilities, 5 move bits), which is why the probability update below looks
//! like the LZMA decoder's.
//!
//! Implemented from the public BCJ2 description; validated in
//! `tests/sevenz_bcj2.rs` against archives produced by official 7-Zip 25.01,
//! not against any encoder of our own.

use std::io::{BufRead, Read};

const NUM_MODEL_BITS: u32 = 11;
const BIT_MODEL_TOTAL: u32 = 1 << NUM_MODEL_BITS;
const NUM_MOVE_BITS: u32 = 5;
const TOP_VALUE: u32 = 1 << 24;

/// `probs[0]` covers the `0F 8x` (Jcc near) case, `probs[1]` covers `E9`, and
/// `probs[2 + prev]` covers `E8` keyed on the preceding byte.
const NUM_PROBS: usize = 2 + 256;

/// Is `b1` the second byte of a branch instruction whose target BCJ2 may have
/// converted? `b0` is the byte before it.
fn is_branch(b0: u8, b1: u8) -> bool {
    (b1 & 0xFE) == 0xE8 || (b0 == 0x0F && (b1 & 0xF0) == 0x80)
}

/// One byte of `r`, `None` at its end.
fn byte(r: &mut dyn std::io::BufRead) -> std::io::Result<Option<u8>> {
    let b = r.fill_buf()?.first().copied();
    if b.is_some() {
        r.consume(1);
    }
    Ok(b)
}

/// The folder's output, `out_size` bytes at most, reassembled from the four
/// streams, each read as it is needed. The folder is decoded as it is read, so
/// `out_size`, a header var-int, reserves nothing.
pub(super) struct Reader<'a> {
    main: std::io::BufReader<Box<dyn std::io::Read + 'a>>,
    call: std::io::BufReader<Box<dyn std::io::Read + 'a>>,
    jump: std::io::BufReader<Box<dyn std::io::Read + 'a>>,
    rc: std::io::BufReader<Box<dyn std::io::Read + 'a>>,
    range: u32,
    code: u32,
    probs: [u16; NUM_PROBS],
    out: u64,
    out_size: u64,
    prev: u8,
    /// A converted target not yet given, and how much of it was.
    target: [u8; 4],
    given: usize,
    /// The error that ended a call whose bytes were given first.
    failed: Option<std::io::Error>,
    done: bool,
}

impl<'a> Reader<'a> {
    pub(super) fn new(
        [main, call, jump, rc]: [Box<dyn std::io::Read + 'a>; 4],
        out_size: u64,
    ) -> std::io::Result<Self> {
        let buf = |r| std::io::BufReader::with_capacity(64 * 1024, r);
        let mut r = Reader {
            main: buf(main),
            call: buf(call),
            jump: buf(jump),
            rc: buf(rc),
            range: 0xFFFF_FFFF,
            code: 0,
            probs: [(BIT_MODEL_TOTAL / 2) as u16; NUM_PROBS],
            out: 0,
            out_size,
            prev: 0,
            target: [0; 4],
            given: 4,
            failed: None,
            done: false,
        };
        // The first byte is padding; the next four are the initial code.
        r.rc_byte()?;
        for _ in 0..4 {
            r.code = (r.code << 8) | u32::from(r.rc_byte()?);
        }
        Ok(r)
    }

    /// The range coder's next byte, zero past its end.
    fn rc_byte(&mut self) -> std::io::Result<u8> {
        Ok(byte(&mut self.rc)?.unwrap_or(0))
    }

    fn decode_bit(&mut self, idx: usize) -> std::io::Result<u32> {
        let prob = &mut self.probs[idx];
        let bound = (self.range >> NUM_MODEL_BITS) * u32::from(*prob);
        let bit = if self.code < bound {
            self.range = bound;
            *prob += ((BIT_MODEL_TOTAL - u32::from(*prob)) >> NUM_MOVE_BITS) as u16;
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob -= (u32::from(*prob) >> NUM_MOVE_BITS) as u16;
            1
        };
        if self.range < TOP_VALUE {
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(self.rc_byte()?);
        }
        Ok(bit)
    }
}

impl Reader<'_> {
    /// Fill `buf` from the start, `n` counting the bytes put in it. On an
    /// error `n` is what was put in before it.
    fn fill(&mut self, buf: &mut [u8], n: &mut usize) -> std::io::Result<()> {
        while *n < buf.len() && self.out < self.out_size {
            if self.given < 4 {
                buf[*n] = self.target[self.given];
                self.given += 1;
                *n += 1;
                self.out += 1;
                continue;
            }
            // Bytes up to the next candidate branch are copied as they are.
            let room = (buf.len() - *n)
                .min(usize::try_from(self.out_size - self.out).unwrap_or(usize::MAX));
            let chunk = self.main.fill_buf()?;
            if chunk.is_empty() {
                // The main stream ran out before the folder's declared size:
                // the archive is truncated, and what exists has been decoded.
                break;
            }
            let mut k = 0;
            let mut prev = self.prev;
            let mut branch = false;
            while k < chunk.len().min(room) {
                let b = chunk[k];
                k += 1;
                if is_branch(prev, b) {
                    branch = true;
                    break;
                }
                prev = b;
            }
            buf[*n..*n + k].copy_from_slice(&chunk[..k]);
            let b = chunk[k - 1];
            self.main.consume(k);
            *n += k;
            self.out += k as u64;
            if !branch {
                self.prev = prev;
                continue;
            }
            let idx = if b == 0xE8 {
                2 + prev as usize
            } else if b == 0xE9 {
                1
            } else {
                0
            };
            if self.decode_bit(idx)? == 0 {
                self.prev = b;
                continue;
            }
            let src = if b == 0xE8 {
                &mut self.call
            } else {
                &mut self.jump
            };
            let mut raw = [0u8; 4];
            src.read_exact(&mut raw)
                .map_err(|_| std::io::Error::other("7z BCJ2: call/jump stream exhausted"))?;
            let absolute = u32::from_be_bytes(raw);
            // Relative to the end of the instruction, four bytes past here.
            let relative = absolute.wrapping_sub((self.out as u32).wrapping_add(4));
            self.target = relative.to_le_bytes();
            self.given = 0;
            self.prev = (relative >> 24) as u8;
        }
        Ok(())
    }
}

impl std::io::Read for Reader<'_> {
    /// An error met after some bytes were put in `buf` is returned by the next
    /// call, so that those bytes, which a damaged stream is scanned up to, are
    /// not lost with it. After an error the reader is at its end.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(e) = self.failed.take() {
            self.done = true;
            return Err(e);
        }
        if self.done {
            return Ok(0);
        }
        let mut n = 0;
        match self.fill(buf, &mut n) {
            Ok(()) => Ok(n),
            Err(e) if n > 0 => {
                self.failed = Some(e);
                Ok(n)
            }
            Err(e) => {
                self.done = true;
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    /// `data`, then an error.
    struct Fails(Cursor<Vec<u8>>);

    impl Read for Fails {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.read(buf)? {
                0 => Err(std::io::Error::other("damaged")),
                n => Ok(n),
            }
        }
    }

    /// A reader of `out_size` bytes over `main`, with empty call and jump
    /// streams, and range coder bytes (padding, then a code no probability can
    /// be below) that convert every candidate branch.
    fn sized<'a>(main: impl Read + 'a, out_size: u64) -> super::Reader<'a> {
        super::Reader::new(
            [
                Box::new(main),
                Box::new(&b""[..]),
                Box::new(&b""[..]),
                Box::new(&[0u8, 0xFF, 0xFF, 0xFF, 0xFF][..]),
            ],
            out_size,
        )
        .unwrap()
    }

    fn reader<'a>(main: impl Read + 'a) -> super::Reader<'a> {
        sized(main, 1000)
    }

    /// A stream that fails part way: the bytes decoded before the failure are
    /// given first, in whatever size the caller reads, and the failure comes
    /// with the next read. The reader is at its end after it.
    #[test]
    fn the_bytes_before_a_failed_stream_are_given_before_its_error() {
        type Make = fn() -> super::Reader<'static>;
        let cases: [(&str, Make, &[u8]); 2] = [
            (
                "the main stream fails",
                || reader(Fails(Cursor::new(b"hello world".to_vec()))),
                b"hello world",
            ),
            (
                "the call stream is short",
                || reader(&b"hello\xE8 world"[..]),
                b"hello\xE8",
            ),
        ];
        for (what, make, before) in cases {
            for size in [1, 4, 64, 4096] {
                let mut r = make();
                let mut got = Vec::new();
                let mut buf = vec![0u8; size];
                loop {
                    match r.read(&mut buf) {
                        Ok(0) => panic!("{what}, reads of {size}: ended without its error"),
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                        Err(_) => break,
                    }
                }
                assert_eq!(got, before, "{what}, reads of {size}");
                assert_eq!(r.read(&mut buf).unwrap(), 0, "{what}, reads of {size}");
            }
        }
    }

    /// The declared output size is a header var-int. Reserving it directly asks
    /// the allocator for whatever the archive says, and an allocation that large
    /// does not return an error: it aborts the process, which no `catch_unwind`
    /// boundary can turn back into a verdict.
    ///
    /// If this regresses the test does not fail, it kills the test binary. That
    /// is the same thing a scan does.
    #[test]
    fn a_huge_declared_output_does_not_get_reserved() {
        let mut r = sized(&b"abc"[..], u64::MAX / 2);
        let mut out = Vec::new();
        r.read_to_end(&mut out).expect("read");
        assert_eq!(out, b"abc", "the bytes of the main stream, no more");
    }
}
