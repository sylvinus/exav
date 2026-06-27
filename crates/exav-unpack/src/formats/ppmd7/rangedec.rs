//! Range decoders for PPMd7.
//!
//! Two coders share the var.H model:
//!
//! * [`SevenZRangeDecoder`] — the 7-Zip range coder, vendored from `ppmd-rust`
//!   1.4.0 (CC0-1.0 OR MIT-0). Used to validate the vendored model against
//!   real `.7z` PPMd streams produced by the `7z` CLI.
//! * [`RarRangeDecoder`] — RAR's Subbotin carry-less range coder. Its
//!   arithmetic (`Low`/`Code`/`Range`/`Bottom`, the `(Low ^ (Low+Range))`
//!   normalisation, the no-leading-byte init) is reproduced from libarchive's
//!   BSD-2-Clause `archive_ppmd7.c` `PpmdRAR_RangeDec_*` functions — **not from
//!   UnRAR**.
//!
//! Both pull bytes from an in-memory cursor (a `&[u8]` + position) so the model
//! stays allocation-free w.r.t. the input. `out_of_data` records truncation:
//! once the source is exhausted, reads yield 0 and the flag is set, letting the
//! framing layer stop cleanly instead of looping.

use super::RangeDec;

const K_TOP_VALUE: u32 = 1 << 24;
/// Binary-context probability scale (PPMD_BIN_SCALE = 1 << 14).
const PPMD_BIN_SCALE: u32 = 1 << 14;

/// A byte source over an in-memory slice that yields 0 past the end and records
/// that it ran out (so the model can detect truncation). Only the test-only
/// `SevenZRangeDecoder` uses it; `RarRangeDecoder` owns its buffer directly.
#[cfg(test)]
struct ByteIn<'a> {
    data: &'a [u8],
    pos: usize,
    out_of_data: bool,
}

#[cfg(test)]
impl<'a> ByteIn<'a> {
    fn new(data: &'a [u8]) -> Self {
        ByteIn {
            data,
            pos: 0,
            out_of_data: false,
        }
    }

    #[inline]
    fn read(&mut self) -> u32 {
        match self.data.get(self.pos) {
            Some(&b) => {
                self.pos += 1;
                b as u32
            }
            None => {
                self.out_of_data = true;
                0
            }
        }
    }
}

// -------------------------------------------------------------------------
// 7z range coder (vendored from ppmd-rust)
// -------------------------------------------------------------------------

#[cfg(test)]
pub(crate) struct SevenZRangeDecoder<'a> {
    range: u32,
    code: u32,
    inp: ByteIn<'a>,
    init_ok: bool,
}

#[cfg(test)]
impl<'a> SevenZRangeDecoder<'a> {
    /// 7z init: a leading byte (must be 0) then four code bytes; `code` must be
    /// `< 0xFFFFFFFF`. `init_ok` is false if the framing byte is non-zero.
    pub(crate) fn new(data: &'a [u8]) -> Self {
        let mut inp = ByteIn::new(data);
        let lead = inp.read();
        let mut code = 0u32;
        for _ in 0..4 {
            code = (code << 8) | inp.read();
        }
        SevenZRangeDecoder {
            range: 0xFFFF_FFFF,
            code,
            inp,
            init_ok: lead == 0 && code != 0xFFFF_FFFF,
        }
    }

    pub(crate) fn init_ok(&self) -> bool {
        self.init_ok
    }

    #[inline(always)]
    fn normalize(&mut self) {
        if self.range < K_TOP_VALUE {
            self.code = (self.code << 8) | self.inp.read();
            self.range <<= 8;
            if self.range < K_TOP_VALUE {
                self.code = (self.code << 8) | self.inp.read();
                self.range <<= 8;
            }
        }
    }
}

#[cfg(test)]
impl<'a> RangeDec for SevenZRangeDecoder<'a> {
    #[inline(always)]
    fn get_threshold(&mut self, total: u32) -> u32 {
        self.range /= total;
        self.code / self.range
    }

    #[inline(always)]
    fn decode(&mut self, start: u32, size: u32) {
        self.code = self.code.wrapping_sub(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize();
    }

    #[inline(always)]
    fn decode_bit(&mut self, size0: u32) -> u32 {
        // 7z bin decode: newBound = (range >> 14) * size0
        let new_bound = (self.range >> 14).wrapping_mul(size0);
        let bit;
        if self.code < new_bound {
            bit = 0;
            self.range = new_bound;
        } else {
            bit = 1;
            self.code = self.code.wrapping_sub(new_bound);
            self.range = self.range.wrapping_sub(new_bound);
        }
        self.normalize();
        bit
    }

    #[inline(always)]
    fn out_of_data(&self) -> bool {
        self.inp.out_of_data
    }

    #[inline(always)]
    fn bytes_consumed(&self) -> usize {
        self.inp.pos
    }
}

// -------------------------------------------------------------------------
// RAR range coder (Subbotin carry-less; from libarchive archive_ppmd7.c)
// -------------------------------------------------------------------------

pub(crate) struct RarRangeDecoder {
    low: u32,
    code: u32,
    range: u32,
    bottom: u32,
    data: Vec<u8>,
    pos: usize,
    out_of_data: bool,
    init_ok: bool,
}

impl RarRangeDecoder {
    /// RAR init (`PpmdRAR_RangeDec_Init`): `Low = 0`, `Range = 0xFFFFFFFF`, read
    /// four bytes into `Code` (no leading framing byte), require
    /// `Code != 0xFFFFFFFF`, then `Bottom = 0x8000`. Owns its byte buffer (the
    /// RAR3 framing layer reconstructs the remaining member bytes into a `Vec`).
    pub(crate) fn new(data: Vec<u8>) -> Self {
        let mut dec = RarRangeDecoder {
            low: 0,
            code: 0,
            range: 0xFFFF_FFFF,
            bottom: 0x8000,
            data,
            pos: 0,
            out_of_data: false,
            init_ok: false,
        };
        let mut code = 0u32;
        for _ in 0..4 {
            code = (code << 8) | dec.read_byte();
        }
        dec.code = code;
        dec.init_ok = !dec.out_of_data && code != 0xFFFF_FFFF;
        dec
    }

    pub(crate) fn init_ok(&self) -> bool {
        self.init_ok
    }

    #[inline]
    fn read_byte(&mut self) -> u32 {
        match self.data.get(self.pos) {
            Some(&b) => {
                self.pos += 1;
                b as u32
            }
            None => {
                self.out_of_data = true;
                0
            }
        }
    }

    #[inline(always)]
    fn normalize(&mut self) {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= K_TOP_VALUE {
                if self.range >= self.bottom {
                    break;
                }
                // Underflow: clamp range to keep precision (Subbotin trick).
                self.range = (0u32.wrapping_sub(self.low)) & (self.bottom - 1);
            }
            let b = self.read_byte();
            self.code = (self.code << 8) | b;
            self.range <<= 8;
            self.low <<= 8;
        }
    }
}

impl RangeDec for RarRangeDecoder {
    #[inline(always)]
    fn get_threshold(&mut self, total: u32) -> u32 {
        self.range /= total;
        (self.code.wrapping_sub(self.low)) / self.range
    }

    #[inline(always)]
    fn decode(&mut self, start: u32, size: u32) {
        self.low = self.low.wrapping_add(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize();
    }

    #[inline(always)]
    fn decode_bit(&mut self, size0: u32) -> u32 {
        // RAR bin decode (Range_DecodeBit_RAR): threshold against BIN_SCALE.
        let value = self.get_threshold(PPMD_BIN_SCALE);
        if value < size0 {
            self.decode(0, size0);
            0
        } else {
            self.decode(size0, PPMD_BIN_SCALE - size0);
            1
        }
    }

    #[inline(always)]
    fn out_of_data(&self) -> bool {
        self.out_of_data
    }

    #[inline(always)]
    fn bytes_consumed(&self) -> usize {
        self.pos
    }
}
