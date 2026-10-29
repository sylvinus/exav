//! LZO1X decompression, the codec of the squashfs images of routers and set-top
//! boxes. Safe on any input: every read and every copy is bounds-checked, and
//! the output has a ceiling.
//!
//! The stream is a run of instructions, each a literal run or a match, the low
//! two bits of the last byte of a match saying how many literals (0 to 3) follow
//! it. A match's distance and length are in its opcode and the bytes after, in
//! one of four layouts by the opcode's size, and the stream ends with the match
//! of the longest distance and no distance at all (`11 00 00`).

// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]

/// What the decoder does next, the places the format's instructions lead to.
#[derive(Clone, Copy)]
enum Next {
    /// An instruction that is a literal run, or a match.
    Instruction,
    /// The instruction after a literal run: a match, or one that is the short
    /// match of a run of four literals or more.
    AfterRun,
    /// A match, its opcode being `t`.
    Match,
}

/// The decoder: the input and where it is, the output and its ceiling.
struct Lzo<'a> {
    src: &'a [u8],
    at: usize,
    out: Vec<u8>,
    max: usize,
}

impl Lzo<'_> {
    fn byte(&mut self) -> Result<usize, &'static str> {
        let b = *self
            .src
            .get(self.at)
            .ok_or("LZO input ends inside an instruction")?;
        self.at = self.at.saturating_add(1);
        Ok(usize::from(b))
    }

    /// A length that goes on in bytes of 255 while they are zero: the zeros,
    /// then the last byte, and `base` besides.
    fn extended(&mut self, base: usize) -> Result<usize, &'static str> {
        let mut n = base;
        loop {
            let b = self.byte()?;
            if b != 0 {
                return Ok(n.saturating_add(b));
            }
            n = n.saturating_add(255);
        }
    }

    fn literals(&mut self, n: usize) -> Result<(), &'static str> {
        let end = self.at.checked_add(n).ok_or("LZO literal run overflows")?;
        let lits = self
            .src
            .get(self.at..end)
            .ok_or("LZO literal run goes past the input")?;
        if self.out.len().saturating_add(n) > self.max {
            return Err("LZO output exceeds the size budget");
        }
        self.out.extend_from_slice(lits);
        self.at = end;
        Ok(())
    }

    /// `len` bytes from `dist` back, which may overlap what is being written.
    fn copy(&mut self, dist: usize, len: usize) -> Result<(), &'static str> {
        if dist == 0 || dist > self.out.len() {
            return Err("LZO match points before the start of the output");
        }
        if self.out.len().saturating_add(len) > self.max {
            return Err("LZO output exceeds the size budget");
        }
        let start = self.out.len().saturating_sub(dist);
        for k in 0..len {
            let b = self.out[start.saturating_add(k)];
            self.out.push(b);
        }
        Ok(())
    }
}

/// Decompress an LZO1X stream of at most `max` bytes of output.
pub fn decompress(src: &[u8], max: usize) -> Result<Vec<u8>, &'static str> {
    let mut d = Lzo {
        src,
        at: 0,
        out: Vec::new(),
        max,
    };
    let mut next = Next::Instruction;
    let mut t = 0usize;
    // A first byte above 17 is a literal run of that many less 17.
    if let Some(&first) = src.first().filter(|&&b| b > 17) {
        d.at = 1;
        t = usize::from(first).saturating_sub(17);
        d.literals(t)?;
        if t < 4 {
            // The literals of a match that has not been read: its instruction is next.
            t = d.byte()?;
            next = Next::Match;
        } else {
            next = Next::AfterRun;
        }
    }
    loop {
        // How many literals follow the match just read.
        let trail: usize;
        match next {
            Next::Instruction => {
                if d.at >= src.len() {
                    return Ok(d.out);
                }
                t = d.byte()?;
                if t >= 16 {
                    next = Next::Match;
                    continue;
                }
                if t == 0 {
                    t = d.extended(15)?;
                }
                d.literals(t.saturating_add(3))?;
                next = Next::AfterRun;
                continue;
            }
            Next::AfterRun => {
                t = d.byte()?;
                if t >= 16 {
                    next = Next::Match;
                    continue;
                }
                // A match of three bytes, far back, that follows a run of literals.
                let dist = 1usize
                    .saturating_add(0x0800)
                    .saturating_add(t >> 2)
                    .saturating_add(d.byte()?.saturating_mul(4));
                d.copy(dist, 3)?;
                trail = t & 3;
            }
            Next::Match => {
                if t >= 64 {
                    let dist = 1usize
                        .saturating_add((t >> 2) & 7)
                        .saturating_add(d.byte()?.saturating_mul(8));
                    d.copy(dist, (t >> 5).saturating_add(1))?;
                    trail = t & 3;
                } else if t >= 32 {
                    let mut len = t & 31;
                    if len == 0 {
                        len = d.extended(31)?;
                    }
                    let (a, b) = (d.byte()?, d.byte()?);
                    let dist = 1usize
                        .saturating_add(a >> 2)
                        .saturating_add(b.saturating_mul(64));
                    d.copy(dist, len.saturating_add(2))?;
                    trail = a & 3;
                } else if t >= 16 {
                    let mut len = t & 7;
                    if len == 0 {
                        len = d.extended(7)?;
                    }
                    let (a, b) = (d.byte()?, d.byte()?);
                    let far = (t & 8).saturating_mul(2048);
                    let dist = far
                        .saturating_add(a >> 2)
                        .saturating_add(b.saturating_mul(64));
                    // The longest distance, no distance: the end.
                    if dist == 0 {
                        return Ok(d.out);
                    }
                    d.copy(dist.saturating_add(0x4000), len.saturating_add(2))?;
                    trail = a & 3;
                } else {
                    // Two bytes, near, after literals of one to three.
                    let dist = 1usize
                        .saturating_add(t >> 2)
                        .saturating_add(d.byte()?.saturating_mul(4));
                    d.copy(dist, 2)?;
                    trail = t & 3;
                }
            }
        }
        if trail == 0 {
            next = Next::Instruction;
        } else {
            d.literals(trail)?;
            t = d.byte()?;
            next = Next::Match;
        }
    }
}

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn a_stream_of_literals_alone_ends_at_its_marker() {
        // 17 + 5: five literals, then the end marker.
        let mut s = vec![22];
        s.extend_from_slice(b"hello");
        s.extend_from_slice(&[0x11, 0, 0]);
        assert_eq!(decompress(&s, 100).unwrap(), b"hello");
    }

    #[test]
    fn a_long_run_of_literals_and_a_match_over_itself() {
        // Literals "abc", then an M3 match: 001 00110 (length 6 + 2), and
        // distance 1 (0 << 2, 0) with no literals after; then the end.
        let mut s = vec![17 + 3];
        s.extend_from_slice(b"abc");
        s.extend_from_slice(&[0x20 | 6, 0, 0]);
        s.extend_from_slice(&[0x11, 0, 0]);
        assert_eq!(decompress(&s, 100).unwrap(), b"abccccccccc");
    }

    #[test]
    fn the_output_has_a_ceiling_and_the_input_is_not_trusted() {
        let mut s = vec![17 + 5];
        s.extend_from_slice(b"hello");
        s.extend_from_slice(&[0x11, 0, 0]);
        assert!(decompress(&s, 4).is_err());
        // Ends inside a literal run, a match, and with no marker.
        assert!(decompress(&[22, b'h', b'e'], 100).is_err());
        assert!(decompress(&[22, b'h', b'e', b'l', b'l', b'o', 0x20], 100).is_err());
        // A match before the start.
        assert!(decompress(&[17 + 4, b'a', b'b', b'c', b'd', 0x20 | 3, 0xFC, 0xFF], 100).is_err());
        assert!(decompress(&[], 100).unwrap().is_empty());
    }

    /// The first block `lzop` makes of a text, at its levels 1 (LZO1X-1) and 9
    /// (LZO1X-999): the instructions of both encoders, near and far matches and
    /// long runs of literals, put to one decoder (`fuzz/seeds/lzo/make.py`).
    #[test]
    fn the_blocks_lzop_makes_are_decoded_to_the_text() {
        let mut text = Vec::new();
        for _ in 0..4 {
            text.extend_from_slice(&b"the quick brown fox jumps over the lazy dog. ".repeat(40));
            for _ in 0..3 {
                text.extend((0..=255u8).collect::<Vec<_>>());
            }
        }
        for level in [1, 9] {
            let p = format!(
                "{}/tests/fixtures/fs/lzo_text_{level}.bin",
                env!("CARGO_MANIFEST_DIR")
            );
            let block = crate::read_fixture(&p).unwrap();
            assert_eq!(
                decompress(&block, text.len()).unwrap(),
                text,
                "level {level}"
            );
            // One byte of room less than the text.
            assert!(decompress(&block, text.len() - 1).is_err(), "level {level}");
        }
    }
}
