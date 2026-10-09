//! The bit codes of ODA spec chapter 2: a DWG object is a stream of bits,
//! most values prefixed by a short code that says how many follow.

use super::Version;

/// Why a value could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitError {
    /// The value runs past the end of its stream.
    End,
    /// A code the specification leaves unused (BL or BD `11`), a negative
    /// length, or a handle of more than 8 bytes.
    Invalid,
}

impl std::fmt::Display for BitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BitError::End => "a value runs past the end of its stream",
            BitError::Invalid => "a value uses a code the format does not define",
        })
    }
}

impl std::error::Error for BitError {}

pub type BitResult<T> = Result<T, BitError>;

/// A handle reference (spec 2.13): a code, and a handle or an offset from
/// the referring object's handle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HandleRef {
    pub code: u8,
    pub value: u64,
}

impl HandleRef {
    /// The handle referred to, from an object whose handle is `base`: codes
    /// 6, 8, 0xA and 0xC are relative to it (spec 2.13), the others absolute.
    pub fn absolute(self, base: u64) -> u64 {
        match self.code {
            6 => base.wrapping_add(1),
            8 => base.wrapping_sub(1),
            0xA => base.wrapping_add(self.value),
            0xC => base.wrapping_sub(self.value),
            _ => self.value,
        }
    }
}

/// A reader over a window of bits, most significant bit of each byte first.
#[derive(Clone, Debug)]
pub struct Bits<'a> {
    data: &'a [u8],
    pos: u64,
    end: u64,
}

impl<'a> Bits<'a> {
    pub fn new(data: &'a [u8]) -> Bits<'a> {
        Bits {
            data,
            pos: 0,
            end: (data.len() as u64).saturating_mul(8),
        }
    }

    /// The bits of `data` from `start` to `end`, both cut to its length.
    pub fn window(data: &'a [u8], start: u64, end: u64) -> Bits<'a> {
        let total = (data.len() as u64).saturating_mul(8);
        let end = end.min(total);
        Bits {
            data,
            pos: start.min(end),
            end,
        }
    }

    /// The bit position, from the start of the data.
    pub fn position(&self) -> u64 {
        self.pos
    }

    pub fn end(&self) -> u64 {
        self.end
    }

    pub fn remaining(&self) -> u64 {
        self.end - self.pos
    }

    /// Move to a bit position, kept within the window.
    pub fn seek(&mut self, bit: u64) {
        self.pos = bit.min(self.end);
    }

    /// Stop the window at `bit`, which must be past the current position.
    pub fn set_end(&mut self, bit: u64) {
        self.end = bit.clamp(self.pos, self.end);
    }

    pub fn skip(&mut self, bits: u64) -> BitResult<()> {
        if bits > self.remaining() {
            return Err(BitError::End);
        }
        self.pos += bits;
        Ok(())
    }

    /// Up to 64 bits as an unsigned number, first bit most significant.
    pub fn read(&mut self, n: u32) -> BitResult<u64> {
        if u64::from(n) > self.remaining() || n > 64 {
            return Err(BitError::End);
        }
        let mut v = 0u64;
        let mut left = n;
        while left > 0 {
            let byte = *self
                .data
                .get((self.pos >> 3) as usize)
                .ok_or(BitError::End)?;
            let avail = 8 - (self.pos & 7) as u32;
            let k = avail.min(left);
            let bits = (u64::from(byte) >> (avail - k)) & ((1u64 << k) - 1);
            v = (v << k) | bits;
            self.pos += u64::from(k);
            left -= k;
        }
        Ok(v)
    }

    /// B
    pub fn b(&mut self) -> BitResult<bool> {
        Ok(self.read(1)? == 1)
    }

    /// BB
    pub fn bb(&mut self) -> BitResult<u8> {
        Ok(self.read(2)? as u8)
    }

    /// 3B (spec 2.1): one to three bits, until a zero.
    pub fn b3(&mut self) -> BitResult<u8> {
        let mut v = 0u8;
        for _ in 0..3 {
            let bit = self.read(1)? as u8;
            v = (v << 1) | bit;
            if bit == 0 {
                break;
            }
        }
        Ok(v)
    }

    /// RC
    pub fn rc(&mut self) -> BitResult<u8> {
        Ok(self.read(8)? as u8)
    }

    fn raw<const N: usize>(&mut self) -> BitResult<[u8; N]> {
        if (N as u64) * 8 > self.remaining() {
            return Err(BitError::End);
        }
        let mut out = [0u8; N];
        for b in &mut out {
            *b = self.rc()?;
        }
        Ok(out)
    }

    /// RS
    pub fn rs(&mut self) -> BitResult<i16> {
        Ok(i16::from_le_bytes(self.raw()?))
    }

    /// RL
    pub fn rl(&mut self) -> BitResult<i32> {
        Ok(i32::from_le_bytes(self.raw()?))
    }

    /// RD
    pub fn rd(&mut self) -> BitResult<f64> {
        Ok(f64::from_le_bytes(self.raw()?))
    }

    /// BS (spec 2.2)
    pub fn bs(&mut self) -> BitResult<i16> {
        match self.bb()? {
            0 => self.rs(),
            1 => Ok(i16::from(self.rc()?)),
            2 => Ok(0),
            _ => Ok(256),
        }
    }

    /// BL (spec 2.3)
    pub fn bl(&mut self) -> BitResult<i32> {
        match self.bb()? {
            0 => self.rl(),
            1 => Ok(i32::from(self.rc()?)),
            2 => Ok(0),
            _ => Err(BitError::Invalid),
        }
    }

    /// BLL (spec 2.4): a byte count, then the bytes, least significant
    /// first. The spec reads the count as a 3B (one to three bits); files
    /// give it three bits always: an R2013 header's data is its R2010
    /// conversion's shifted by three bits, REQUIREDVERSIONS (a BLL of 0)
    /// between them.
    pub fn bll(&mut self) -> BitResult<u64> {
        let n = self.read(3)? as u8;
        let mut v = 0u64;
        for i in 0..n {
            v |= u64::from(self.rc()?) << (8 * u32::from(i));
        }
        Ok(v)
    }

    /// BD (spec 2.5)
    pub fn bd(&mut self) -> BitResult<f64> {
        match self.bb()? {
            0 => self.rd(),
            1 => Ok(1.0),
            2 => Ok(0.0),
            _ => Err(BitError::Invalid),
        }
    }

    /// DD (spec 2.9): bytes of `default` replaced by those that follow.
    pub fn dd(&mut self, default: f64) -> BitResult<f64> {
        let mut bytes = default.to_le_bytes();
        match self.bb()? {
            0 => {}
            1 => {
                let new: [u8; 4] = self.raw()?;
                bytes[..4].copy_from_slice(&new);
            }
            2 => {
                let new: [u8; 6] = self.raw()?;
                bytes[4..6].copy_from_slice(&new[..2]);
                bytes[..4].copy_from_slice(&new[2..]);
            }
            _ => return self.rd(),
        }
        Ok(f64::from_le_bytes(bytes))
    }

    /// 2RD
    pub fn rd2(&mut self) -> BitResult<[f64; 2]> {
        Ok([self.rd()?, self.rd()?])
    }

    /// 2BD
    pub fn bd2(&mut self) -> BitResult<[f64; 2]> {
        Ok([self.bd()?, self.bd()?])
    }

    /// 3BD
    pub fn bd3(&mut self) -> BitResult<[f64; 3]> {
        Ok([self.bd()?, self.bd()?, self.bd()?])
    }

    /// 3RD
    pub fn rd3(&mut self) -> BitResult<[f64; 3]> {
        Ok([self.rd()?, self.rd()?, self.rd()?])
    }

    /// BE (spec 2.8): from R2000, one bit for the default (0, 0, 1).
    pub fn be(&mut self, version: Version) -> BitResult<[f64; 3]> {
        if version >= Version::R2000 && self.b()? {
            return Ok([0.0, 0.0, 1.0]);
        }
        self.bd3()
    }

    /// BT (spec 2.10): from R2000, one bit for the default 0.
    pub fn bt(&mut self, version: Version) -> BitResult<f64> {
        if version >= Version::R2000 && self.b()? {
            return Ok(0.0);
        }
        self.bd()
    }

    /// H (spec 2.13): a code and counter nibble, then the counter's bytes,
    /// most significant first.
    pub fn h(&mut self) -> BitResult<HandleRef> {
        let code = self.read(4)? as u8;
        let n = self.read(4)? as u32;
        if n > 8 {
            return Err(BitError::Invalid);
        }
        let value = self.read(n * 8)?;
        Ok(HandleRef { code, value })
    }

    /// `n` bytes.
    pub fn bytes(&mut self, n: usize) -> BitResult<Vec<u8>> {
        if (n as u64).saturating_mul(8) > self.remaining() {
            return Err(BitError::End);
        }
        if self.pos & 7 == 0 {
            let at = (self.pos >> 3) as usize;
            let out = crate::bytes::at(self.data, at, n)
                .ok_or(BitError::End)?
                .to_vec();
            self.pos += n as u64 * 8;
            return Ok(out);
        }
        (0..n).map(|_| self.rc()).collect()
    }

    /// T (R13 to 2004): a BS byte count, then the bytes in the drawing's
    /// code page. Writers often count a terminating zero.
    pub fn t(&mut self) -> BitResult<Vec<u8>> {
        let n = self.bs()?;
        let n = usize::try_from(n).map_err(|_| BitError::Invalid)?;
        self.bytes(n)
    }

    /// TU (2007 on): a BS character count, then UTF-16LE code units.
    pub fn tu(&mut self) -> BitResult<String> {
        let n = self.bs()?;
        let n = usize::try_from(n).map_err(|_| BitError::Invalid)?;
        if (n as u64).saturating_mul(16) > self.remaining() {
            return Err(BitError::End);
        }
        let mut units = Vec::with_capacity(n);
        for _ in 0..n {
            units.push(u16::from_le_bytes(self.raw()?));
        }
        while units.last() == Some(&0) {
            units.pop();
        }
        Ok(String::from_utf16_lossy(&units))
    }

    /// MC (spec 2.6), signed: the last byte's 0x40 bit negates. Bits past
    /// the 64th are dropped; a tenth continued byte is invalid.
    pub fn mc(&mut self) -> BitResult<i64> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.rc()?;
            if shift > 63 {
                return Err(BitError::Invalid);
            }
            if b & 0x80 != 0 {
                v |= u64::from(b & 0x7F) << shift;
                shift += 7;
                continue;
            }
            v |= u64::from(b & 0x3F) << shift;
            let v = v as i64;
            return Ok(if b & 0x40 != 0 { v.wrapping_neg() } else { v });
        }
    }

    /// MC, unsigned (the object map's handle offsets): handles of 8 bytes
    /// take ten.
    pub fn umc(&mut self) -> BitResult<u64> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.rc()?;
            if shift > 63 {
                return Err(BitError::Invalid);
            }
            v |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
        }
    }

    /// MS (spec 2.7): 15-bit little-endian modules, the high bit of each
    /// saying another follows.
    pub fn ms(&mut self) -> BitResult<u64> {
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let w = u16::from_le_bytes(self.raw()?);
            if shift > 45 {
                return Err(BitError::Invalid);
            }
            v |= u64::from(w & 0x7FFF) << shift;
            if w & 0x8000 == 0 {
                return Ok(v);
            }
            shift += 15;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_bits(s: &str) -> Vec<u8> {
        let bits: Vec<u8> = s.bytes().filter(|c| *c == b'0' || *c == b'1').collect();
        bits.chunks(8)
            .map(|c| {
                let mut b = 0u8;
                for (i, bit) in c.iter().enumerate() {
                    b |= (bit - b'0') << (7 - i);
                }
                b
            })
            .collect()
    }

    /// The streams of spec 2.2 and 2.3, read as the spec reads them.
    #[test]
    fn bitshorts_and_bitlongs_read_as_the_spec_examples() {
        let data = from_bits("0000000001000000011011010000111110");
        let mut b = Bits::new(&data);
        let shorts: Vec<i16> = (0..5).map(|_| b.bs().unwrap()).collect();
        assert_eq!(shorts, [257, 0, 256, 15, 0]);

        let data = from_bits("000000000100000001000000000000000010010000111110");
        let mut b = Bits::new(&data);
        let longs: Vec<i32> = (0..4).map(|_| b.bl().unwrap()).collect();
        assert_eq!(longs, [257, 0, 15, 0]);
    }

    /// Spec 2.6 and 2.7's examples.
    #[test]
    fn modular_numbers_read_as_the_spec_examples() {
        assert_eq!(Bits::new(&[0b1000_0010, 0b0010_0100]).mc(), Ok(4610));
        assert_eq!(
            Bits::new(&[0b1110_1001, 0b1001_0111, 0b1110_0110, 0b0011_0101]).mc(),
            Ok(112_823_273)
        );
        assert_eq!(Bits::new(&[0b1000_0101, 0b0100_1011]).mc(), Ok(-1413));
        // An 8-byte handle offset: ten bytes.
        let mut big = vec![0xFF; 9];
        big.push(0x01);
        assert_eq!(Bits::new(&big).umc(), Ok(u64::MAX));
        assert_eq!(Bits::new(&[0xFF; 11]).umc(), Err(BitError::Invalid));
        assert_eq!(
            Bits::new(&[0b0011_0001, 0b1111_0100, 0b1000_1101, 0b0000_0000]).ms(),
            Ok(4_650_033)
        );
    }

    #[test]
    fn handles_are_big_endian_and_relative_codes_apply_to_the_base() {
        // 5.2.05.E7: a hard pointer to 5E7.
        let mut b = Bits::new(&[0x52, 0x05, 0xE7]);
        let h = b.h().unwrap();
        assert_eq!(
            h,
            HandleRef {
                code: 5,
                value: 0x5E7
            }
        );
        assert_eq!(HandleRef { code: 6, value: 0 }.absolute(0x10), 0x11);
        assert_eq!(HandleRef { code: 8, value: 0 }.absolute(0x10), 0xF);
        assert_eq!(
            HandleRef {
                code: 0xA,
                value: 3
            }
            .absolute(0x10),
            0x13
        );
        assert_eq!(
            HandleRef {
                code: 0xC,
                value: 3
            }
            .absolute(0x10),
            0xD
        );
    }

    #[test]
    fn a_bitdouble_with_default_patches_the_default() {
        // 01: four bytes replace the low four of 1.0.
        let patch = [0x11u8, 0x22, 0x33, 0x44];
        let mut bits = String::from("01");
        for b in patch {
            bits.push_str(&format!("{b:08b}"));
        }
        let data = from_bits(&bits);
        let mut want = 1.0f64.to_le_bytes();
        want[..4].copy_from_slice(&patch);
        assert_eq!(
            Bits::new(&data).dd(1.0).unwrap().to_bits(),
            f64::from_le_bytes(want).to_bits()
        );
        assert_eq!(Bits::new(&from_bits("00")).dd(2.5), Ok(2.5));
    }

    #[test]
    fn reading_past_the_end_fails_without_moving() {
        let mut b = Bits::new(&[0xFF]);
        assert_eq!(b.rs(), Err(BitError::End));
        assert_eq!(b.position(), 0);
        let mut b = Bits::new(&[0b1111_1111]);
        assert_eq!(b.h(), Err(BitError::Invalid));
        // A T whose BS length is a raw -1.
        let mut b = Bits::new(&[0b0011_1111, 0xFF, 0b1100_0000]);
        assert_eq!(b.t(), Err(BitError::Invalid));
        // One of 255 bytes, in a stream of one.
        let mut b = Bits::new(&[0b0111_1111, 0b1100_0000]);
        assert_eq!(b.t(), Err(BitError::End));
    }
}
