//! Decoder for the bytecode signature format's textual number/data encoding.
//!
//! The encoding packs integers as nibbles in printable bytes: a byte `0x6N`
//! carries nibble value `N` (so `` ` `` = 0 … `o` = 15). A "number" is a count
//! byte `0x60 + k` followed by `k` nibble bytes, little-endian. A "fixed
//! number" is just `width` nibble bytes with no count prefix. "Data" is a `|`
//! marker, a number length `n`, then `2n` nibble bytes (two nibbles per byte,
//! low nibble first).

/// An instruction operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    /// A value/register index (a prior result, argument, or local).
    Reg(u32),
    /// An inline immediate constant.
    Const(u64),
    /// A reference to global `id` (e.g. the file size / match data).
    Global(u32),
}

/// A cursor over one logical bytecode line.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// A malformed-encoding error with the byte offset where it occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub at: usize,
    pub msg: &'static str,
}

type R<T> = Result<T, DecodeError>;

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn err(&self, msg: &'static str) -> DecodeError {
        DecodeError { at: self.pos, msg }
    }

    /// Next raw byte without consuming.
    pub fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Byte `n` ahead without consuming.
    pub fn peek_at(&self, n: usize) -> Option<u8> {
        self.buf.get(self.pos + n).copied()
    }

    /// Consume and return the next raw byte.
    pub fn byte(&mut self) -> R<u8> {
        let b = *self.buf.get(self.pos).ok_or(self.err("unexpected end"))?;
        self.pos += 1;
        Ok(b)
    }

    /// Consume an expected literal byte.
    pub fn expect(&mut self, want: u8) -> R<()> {
        if self.byte()? != want {
            return Err(self.err("expected marker byte"));
        }
        Ok(())
    }

    /// One nibble byte (`0x6N`) → its value `N`.
    fn nibble(&mut self) -> R<u8> {
        let b = self.byte()?;
        if b & 0xf0 != 0x60 {
            return Err(self.err("byte is not a nibble (0x6N)"));
        }
        Ok(b & 0x0f)
    }

    /// A length-prefixed little-endian number: count byte then that many
    /// nibbles. The count is bounded to 16 nibbles (a 64-bit value).
    pub fn number(&mut self) -> R<u64> {
        let lead = self.byte()?;
        let count = lead.checked_sub(0x60).ok_or(self.err("bad number lead"))?;
        if count > 16 {
            return Err(self.err("number too long"));
        }
        let mut n = 0u64;
        for i in 0..count {
            n |= u64::from(self.nibble()?) << (4 * i as u32);
        }
        Ok(n)
    }

    /// `number()` narrowed to `u32`, rejecting overflow.
    pub fn number_u32(&mut self) -> R<u32> {
        let n = self.number()?;
        u32::try_from(n).map_err(|_| self.err("number exceeds u32"))
    }

    /// A fixed-width little-endian number of exactly `width` nibbles.
    pub fn fixed(&mut self, width: usize) -> R<u64> {
        if width > 16 {
            return Err(self.err("fixed width too long"));
        }
        let mut n = 0u64;
        for i in 0..width {
            n |= u64::from(self.nibble()?) << (4 * i as u32);
        }
        Ok(n)
    }

    /// `|`-marked byte data: marker, length, then 2 nibbles per byte
    /// (low nibble first). `max` bounds the declared length.
    pub fn data(&mut self, max: usize) -> R<Vec<u8>> {
        self.expect(b'|')?;
        let len = self.number()? as usize;
        if len > max {
            return Err(self.err("data length exceeds limit"));
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            let lo = self.nibble()?;
            let hi = self.nibble()?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }

    /// An instruction operand: either an inline constant (lead byte `0x4N`/
    /// `0x50` → count, value nibbles, 1-nibble type) or a plain value index.
    pub fn operand(&mut self) -> R<Operand> {
        let lead = self.peek().ok_or(self.err("operand at end"))?;
        if lead & 0xf0 == 0x40 || lead == 0x50 {
            self.pos += 1; // consume the marked lead
                           // The format ORs the lead with 0x20 then reads it as a count byte,
                           // so `0x4N` → count N and `0x50` → count 16 (a full 64-bit value).
            let count = ((lead | 0x20).wrapping_sub(0x60)) as usize;
            if count > 16 {
                return Err(self.err("operand constant too long"));
            }
            let mut v = 0u64;
            for i in 0..count {
                v |= u64::from(self.nibble()?) << (4 * i as u32);
            }
            // The type nibble encodes the operand's byte width. A width of 0
            // is special: the operand is not an inline constant but a reference
            // to global `v` (the file size, match data, and similar).
            let ty = self.nibble()?;
            if ty == 0 {
                Ok(Operand::Global(v as u32))
            } else {
                Ok(Operand::Const(v))
            }
        } else {
            Ok(Operand::Reg(self.number_u32()?))
        }
    }

    /// A `data()` blob interpreted as a string (trailing NUL dropped).
    pub fn string(&mut self, max: usize) -> R<String> {
        let mut bytes = self.data(max)?;
        if bytes.last() == Some(&0) {
            bytes.pop();
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_zero_and_small() {
        // "`" => count 0 => value 0
        assert_eq!(Reader::new(b"`").number().unwrap(), 0);
        // "af" => count 1, nibble f(6) => 6
        assert_eq!(Reader::new(b"af").number().unwrap(), 6);
        // "ba`" => count 2, nibbles a(1),`(0) => 1 (little-endian)
        assert_eq!(Reader::new(b"ba`").number().unwrap(), 1);
        // "b`a" => count 2, nibbles `(0),a(1) => 1<<4 = 16
        assert_eq!(Reader::new(b"b`a").number().unwrap(), 16);
    }

    #[test]
    fn rejects_non_nibble() {
        // count says 1 nibble, but 'z' (0x7a) is not 0x6N
        assert!(Reader::new(b"az").number().is_err());
        // bad lead byte (< 0x60)
        assert!(Reader::new(b"!").number().is_err());
    }

    #[test]
    fn fixed_width() {
        // two nibbles a(1),b(2) => 1 | 2<<4 = 0x21
        assert_eq!(Reader::new(b"ab").fixed(2).unwrap(), 0x21);
    }

    #[test]
    fn data_roundtrip() {
        // '|' then length number "ab" (count 1, nibble b=2 => len 2),
        // then 2 bytes as nibble pairs (low nibble first):
        //   b(2),c(3) -> (3<<4)|2 = 0x32 ; d(4),e(5) -> (5<<4)|4 = 0x54
        let mut r = Reader::new(b"|abbcde");
        assert_eq!(r.data(16).unwrap(), vec![0x32, 0x54]);
    }

    #[test]
    fn number_does_not_overrun() {
        // count says 3 nibbles but only 1 present
        assert!(Reader::new(b"da").number().is_err());
    }
}
