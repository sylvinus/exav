//! Low-level 7z parsing primitives: variable-length integers, bitsets,
//! NID constants, and a cursor-based reader.

use crate::LimitHit;

// ─── NID (Next Header ID) constants ────────────────────────────────────────

pub(super) const NID_END: u8 = 0x00;
pub(super) const NID_HEADER: u8 = 0x01;
pub(super) const NID_ARCHIVE_PROPERTIES: u8 = 0x02;
pub(super) const NID_ADDITIONAL_STREAMS_INFO: u8 = 0x03;
pub(super) const NID_MAIN_STREAMS_INFO: u8 = 0x04;
pub(super) const NID_FILES_INFO: u8 = 0x05;
pub(super) const NID_PACK_INFO: u8 = 0x06;
pub(super) const NID_UNPACK_INFO: u8 = 0x07;
pub(super) const NID_SUB_STREAMS_INFO: u8 = 0x08;
pub(super) const NID_SIZE: u8 = 0x09;
pub(super) const NID_CRC: u8 = 0x0A;
pub(super) const NID_FOLDER: u8 = 0x0B;
pub(super) const NID_CODERS_UNPACK_SIZE: u8 = 0x0C;
pub(super) const NID_NUM_UNPACK_STREAM: u8 = 0x0D;
pub(super) const NID_EMPTY_STREAM: u8 = 0x0E;
pub(super) const NID_EMPTY_FILE: u8 = 0x0F;
pub(super) const NID_ANTI: u8 = 0x10;
pub(super) const NID_NAME: u8 = 0x11;
pub(super) const NID_C_TIME: u8 = 0x12;
pub(super) const NID_A_TIME: u8 = 0x13;
pub(super) const NID_M_TIME: u8 = 0x14;
pub(super) const NID_WIN_ATTRIBUTES: u8 = 0x15;
pub(super) const NID_ENCODED_HEADER: u8 = 0x17;

// ─── Signature header ──────────────────────────────────────────────────────

pub(super) const SIGNATURE_HEADER_SIZE: u64 = 32;
pub(super) const SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

// ─── Encoder method IDs ────────────────────────────────────────────────────

pub(super) const ID_COPY: [u8; 1] = [0x00];
pub(super) const ID_LZMA: [u8; 3] = [0x03, 0x01, 0x01];
pub(super) const ID_LZMA2: [u8; 1] = [0x21];
pub(super) const ID_PPMD: [u8; 3] = [0x03, 0x04, 0x01];
pub(super) const ID_BZIP2: [u8; 3] = [0x04, 0x02, 0x02];
pub(super) const ID_DEFLATE: [u8; 3] = [0x04, 0x01, 0x08];
pub(super) const ID_BCJ_X86: [u8; 4] = [0x03, 0x03, 0x01, 0x03];
pub(super) const ID_BCJ_ARM: [u8; 4] = [0x03, 0x03, 0x05, 0x01];
pub(super) const ID_BCJ_ARM64: [u8; 1] = [0x0A];
pub(super) const ID_DELTA: [u8; 1] = [0x03];

// ─── Cursor-based reader ───────────────────────────────────────────────────

pub(super) struct SevenZReader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> SevenZReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn read_byte(&mut self) -> Result<u8, LimitHit> {
        if self.pos >= self.data.len() {
            return Err(LimitHit::corrupt("7z: unexpected end of data".into()));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], LimitHit> {
        if self.pos + n > self.data.len() {
            return Err(LimitHit::corrupt("7z: unexpected end of data".into()));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub fn read_u32(&mut self) -> Result<u32, LimitHit> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, LimitHit> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn read_nid(&mut self) -> Result<u8, LimitHit> {
        self.read_byte()
    }
}

// ─── Variable-length integer (7z encoding) ─────────────────────────────────

pub(super) fn read_var_u64(r: &mut SevenZReader) -> Result<u64, LimitHit> {
    let first = r.read_byte()? as u64;
    let mut mask: u64 = 0x80;
    let mut value: u64 = 0;
    for i in 0..8u32 {
        if (first & mask) == 0 {
            return Ok(value | ((first & (mask - 1)) << (8 * i)));
        }
        let b = r.read_byte()? as u64;
        value |= b << (8 * i);
        mask >>= 1;
    }
    Ok(value)
}

pub(super) fn read_var_usize(r: &mut SevenZReader) -> Result<usize, LimitHit> {
    read_var_u64(r).map(|v| v as usize)
}

// ─── Bitset ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub(super) struct BitSet {
    bits: Vec<u64>,
    len: usize,
}

impl BitSet {
    pub fn new(len: usize) -> Self {
        let words = len.div_ceil(64);
        Self {
            bits: vec![0u64; words],
            len,
        }
    }

    pub fn get(&self, i: usize) -> bool {
        if i >= self.len {
            return false;
        }
        let word = i / 64;
        let bit = i % 64;
        (self.bits[word] >> bit) & 1 == 1
    }

    pub fn set(&mut self, i: usize, val: bool) {
        if i >= self.len {
            return;
        }
        let word = i / 64;
        let bit = i % 64;
        if val {
            self.bits[word] |= 1 << bit;
        } else {
            self.bits[word] &= !(1 << bit);
        }
    }

    pub(super) fn read_all_or_bits(
        r: &mut SevenZReader,
        num_bits: usize,
    ) -> Result<Self, LimitHit> {
        let all_defined = r.read_byte()?;
        let mut bs = BitSet::new(num_bits);
        if all_defined != 0 {
            bs.bits.iter_mut().for_each(|w| *w = u64::MAX);
            return Ok(bs);
        }
        Self::read_bits(r, num_bits, bs)
    }

    /// Read a raw BitSet (no all_defined byte), MSB-first within each byte.
    pub(super) fn read_bits(
        r: &mut SevenZReader,
        num_bits: usize,
        mut bs: BitSet,
    ) -> Result<Self, LimitHit> {
        let mut i = 0;
        while i < num_bits {
            let b = r.read_byte()?;
            for bit_idx in 0..8 {
                if i >= num_bits {
                    break;
                }
                bs.set(i, b & (0x80 >> bit_idx) != 0);
                i += 1;
            }
        }
        Ok(bs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_basic() {
        let data = [0x00];
        let mut r = SevenZReader::new(&data);
        assert_eq!(read_var_u64(&mut r).unwrap(), 0);

        let data = [0x7F];
        let mut r = SevenZReader::new(&data);
        assert_eq!(read_var_u64(&mut r).unwrap(), 127);

        let data = [0x80, 0x01];
        let mut r = SevenZReader::new(&data);
        assert_eq!(read_var_u64(&mut r).unwrap(), 1);
    }

    #[test]
    fn bitset_basic() {
        let mut bs = BitSet::new(10);
        assert!(!bs.get(0));
        bs.set(3, true);
        assert!(bs.get(3));
        assert!(!bs.get(4));
    }
}
