// Copyright (c) the JPEG XL Project Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use std::fmt::Debug;

use crate::{error::Error, util::tracing_wrappers::*};
use byteorder::{ByteOrder, LittleEndian};

/// Reads bits from a sequence of bytes.
#[derive(Clone)]
pub struct BitReader<'a> {
    data: &'a [u8],
    bit_buf: u64,
    bits_in_buf: usize,
    total_bits_read: usize,
    initial_bits: usize,
}

impl Debug for BitReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BitReader{{ data: [{} bytes], bit_buf: {:0width$b}, total_bits_read: {} }}",
            self.data.len(),
            self.bit_buf,
            self.total_bits_read,
            width = self.bits_in_buf
        )
    }
}

pub const MAX_BITS_PER_CALL: usize = 56;

impl<'a> BitReader<'a> {
    /// Constructs a BitReader for a given range of data.
    pub fn new(data: &[u8]) -> BitReader<'_> {
        BitReader {
            data,
            bit_buf: 0,
            bits_in_buf: 0,
            total_bits_read: 0,
            initial_bits: data.len() * 8,
        }
    }

    /// Constructs a BitReader for padded data where `real_len` bytes are valid
    /// content and the remaining bytes are zero padding.
    ///
    /// The padding ensures `refill()` can always take the fast 8-byte read path
    /// instead of falling back to byte-by-byte `refill_slow()`. The caller must
    /// ensure `data.len() >= real_len + 8` (8 bytes of zero padding).
    ///
    /// `initial_bits` is set from `real_len`, so `check_for_error()` and
    /// `total_bits_available()` report the correct content length.
    pub fn new_padded(data: &[u8], real_len: usize) -> Result<BitReader<'_>, Error> {
        if real_len > 0 && data.len() < real_len.saturating_add(8) {
            return Err(Error::SectionTooShort);
        }
        Ok(BitReader {
            data,
            bit_buf: 0,
            bits_in_buf: 0,
            total_bits_read: 0,
            initial_bits: real_len * 8,
        })
    }

    /// Reads `num` bits from the buffer without consuming them.
    ///
    /// `num` must satisfy `num <= MAX_BITS_PER_CALL` (56). Values >= 64 would
    /// cause `1u64 << num` to be undefined-output-in-release; values
    /// `MAX_BITS_PER_CALL < num < 64` would silently read past `refill()`'s
    /// fast path. Saturate to 0 in release as a defense-in-depth check — any
    /// caller passing an out-of-range value is a bug we want surfaced via the
    /// debug_assert *and* prevented from corrupting state in release.
    #[inline(always)]
    pub fn peek(&mut self, num: usize) -> u64 {
        // Out-of-range early-return must precede the debug_assert! so the
        // saturation contract is testable under `cargo test` (which builds
        // with debug_assertions=on). Any caller actually exercising this
        // path is a bug, but in release we must not corrupt state.
        if num > MAX_BITS_PER_CALL {
            return 0;
        }
        debug_assert!(num <= MAX_BITS_PER_CALL);
        if self.bits_in_buf < num {
            self.refill();
        }
        // SAFETY-NOTE: `num <= 56` is enforced above, so the shift is well-defined.
        self.bit_buf & ((1u64 << num) - 1)
    }

    /// Advances by `num` bits. Similar to `skip_bits`, but bits must be in the buffer.
    pub fn consume(&mut self, num: usize) -> Result<(), Error> {
        if self.bits_in_buf < num {
            return Err(Error::OutOfBounds((num - self.bits_in_buf).div_ceil(8)));
        }
        self.bit_buf >>= num;
        self.bits_in_buf -= num;
        self.total_bits_read = self.total_bits_read.wrapping_add(num);
        Ok(())
    }

    #[inline(always)]
    pub fn consume_optimistic(&mut self, num: usize) {
        self.bit_buf >>= num;
        self.bits_in_buf = self.bits_in_buf.saturating_sub(num);
        self.total_bits_read = self.total_bits_read.wrapping_add(num);
    }

    /// Reads `num` bits from the buffer.
    /// ```ignore
    /// # use crate::bit_reader::BitReader;
    /// let mut br = BitReader::new(&[0, 1]);
    /// assert_eq!(br.read(8)?, 0);
    /// assert_eq!(br.read(4)?, 1);
    /// assert_eq!(br.read(4)?, 0);
    /// assert_eq!(br.total_bits_read(), 16);
    /// assert!(br.read(1).is_err());
    /// # Ok::<(), zenjxl_decoder::api::Error>(())
    /// ```
    #[inline]
    pub fn read(&mut self, num: usize) -> Result<u64, Error> {
        let ret = self.peek(num);
        self.consume(num)?;
        Ok(ret)
    }

    /// inline(never) wrapper around read, for cold code paths.
    #[inline(never)]
    pub fn read_noinline(&mut self, num: usize) -> Result<u64, Error> {
        self.read(num)
    }

    #[inline(always)]
    pub fn read_optimistic(&mut self, num: usize) -> u64 {
        let ret = self.peek(num);
        self.consume_optimistic(num);
        ret
    }

    pub fn check_for_error(&self) -> Result<(), Error> {
        if self.total_bits_read > self.initial_bits {
            Err(Error::OutOfBounds(self.total_bits_read - self.initial_bits))
        } else {
            Ok(())
        }
    }

    /// Returns the total number of bits that have been read or skipped.
    pub fn total_bits_read(&self) -> usize {
        self.total_bits_read
    }

    /// Returns the total number of bits that can still be read or skipped.
    pub fn total_bits_available(&self) -> usize {
        self.data.len() * 8 + self.bits_in_buf
    }

    /// Skips `num` bits.
    /// ```ignore
    /// # use crate::bit_reader::BitReader;
    /// let mut br = BitReader::new(&[0, 1]);
    /// assert_eq!(br.read(8)?, 0);
    /// br.skip_bits(4)?;
    /// assert_eq!(br.total_bits_read(), 12);
    /// # Ok::<(), zenjxl_decoder::api::Error>(())
    /// ```
    #[inline(never)]
    pub fn skip_bits(&mut self, mut n: usize) -> Result<(), Error> {
        // Check if we can skip within the current buffer
        if let Some(next_remaining_bits) = self.bits_in_buf.checked_sub(n) {
            self.total_bits_read += n;
            self.bits_in_buf = next_remaining_bits;
            self.bit_buf >>= n;
            return Ok(());
        }

        // Adjust the number of bits to skip and reset the buffer
        n -= self.bits_in_buf;
        self.total_bits_read += self.bits_in_buf;
        self.bit_buf = 0;
        self.bits_in_buf = 0;

        // Check if the remaining bits to skip exceed the total bits in `data`
        let bits_available = self.data.len() * 8;
        if n > bits_available {
            self.total_bits_read += bits_available;
            return Err(Error::OutOfBounds(n - bits_available));
        }

        // Skip bytes directly in `data`, then handle leftover bits
        self.total_bits_read += n / 8 * 8;
        self.data = &self.data[n / 8..];
        n %= 8;

        // Refill the buffer and adjust for any remaining bits
        self.refill();
        let to_consume = self.bits_in_buf.min(n);
        // The bits loaded by refill() haven't been counted in total_bits_read yet,
        // so we add (not subtract) the bits we're consuming. The original code
        // incorrectly subtracted here, causing underflow when skip_bits was called
        // on a fresh BitReader.
        self.total_bits_read += to_consume;
        n -= to_consume;
        self.bit_buf >>= to_consume;
        self.bits_in_buf -= to_consume;
        if n > 0 {
            Err(Error::OutOfBounds(n))
        } else {
            Ok(())
        }
    }

    /// Return the number of bits
    pub fn bits_to_next_byte(&self) -> usize {
        let byte_boundary = self.total_bits_read.div_ceil(8) * 8;
        byte_boundary - self.total_bits_read
    }

    /// Jumps to the next byte boundary. The skipped bytes have to be 0.
    /// ```ignore
    /// # use crate::bit_reader::BitReader;
    /// let mut br = BitReader::new(&[0, 1]);
    /// assert_eq!(br.read(8)?, 0);
    /// br.skip_bits(4)?;
    /// br.jump_to_byte_boundary()?;
    /// assert_eq!(br.total_bits_read(), 16);
    /// # Ok::<(), zenjxl_decoder::api::Error>(())
    /// ```
    #[inline(never)]
    pub fn jump_to_byte_boundary(&mut self) -> Result<(), Error> {
        if self.read(self.bits_to_next_byte())? != 0 {
            return Err(Error::NonZeroPadding);
        }
        Ok(())
    }

    #[inline(always)]
    fn refill(&mut self) {
        // See Refill() in C++ code.
        if self.data.len() >= 8 {
            let bits = LittleEndian::read_u64(self.data);
            self.bit_buf |= bits << self.bits_in_buf;
            let read_bytes = (63 - self.bits_in_buf) >> 3;
            self.bits_in_buf |= 56;
            self.data = &self.data[read_bytes..];
            debug_assert!(56 <= self.bits_in_buf && self.bits_in_buf < 64);
        } else {
            self.refill_slow()
        }
    }

    #[inline(never)]
    fn refill_slow(&mut self) {
        while self.bits_in_buf < 56 {
            if self.data.is_empty() {
                return;
            }
            self.bit_buf |= (self.data[0] as u64) << self.bits_in_buf;
            self.bits_in_buf += 8;
            self.data = &self.data[1..];
        }
    }

    /// Splits off a separate BitReader to handle the next `n` *full* bytes.
    /// If `self` is not aligned to a byte boundary, it skips to the next byte boundary.
    /// `self` is automatically advanced by `n` bytes.
    #[allow(dead_code)] // Used by Frame::sections (TOC-based section splitting)
    pub fn split_at(&mut self, n: usize) -> Result<BitReader<'a>, Error> {
        self.jump_to_byte_boundary()?;
        let mut ret = Self { ..*self };
        self.skip_bits(n * 8)?;
        let bytes_in_buf = ret.bits_in_buf / 8;
        if n > bytes_in_buf {
            // Prevent the returned bitreader from over-reading.
            ret.data = &ret.data[..n - bytes_in_buf];
        } else {
            // `n * 8` must be < 64 here. `bytes_in_buf <= bits_in_buf / 8 <= 8`,
            // so `n <= 8` => `n * 8 <= 64`. Guard the `n == 8` case to avoid the
            // undefined `1u64 << 64` shift; for `n == 8` the mask is the full
            // u64 (no masking needed since the buffer is already exactly 64 bits).
            let shift = n * 8;
            ret.bits_in_buf = shift;
            if shift < 64 {
                ret.bit_buf &= (1u64 << shift) - 1;
            }
            ret.data = &[];
        }
        debug!(?n, ret=?ret);
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peek_out_of_range_does_not_panic() {
        // num > MAX_BITS_PER_CALL (56) used to be only a `debug_assert!`, so a
        // release build would compute `1u64 << num` and silently corrupt state
        // for `num >= 64` (UB-shaped behavior masked at u64). The hardened
        // `peek` now early-returns 0 — this test pins that contract.
        let data = [0xff_u8; 16];
        let mut br = BitReader::new(&data);
        assert_eq!(br.peek(64), 0);
        assert_eq!(br.peek(70), 0);
        assert_eq!(br.peek(usize::MAX), 0);
        // The bit buffer state must not have been corrupted by the bad calls —
        // legitimate reads still work.
        assert_eq!(br.read(8).unwrap(), 0xff);
    }

    #[test]
    fn test_split_at_eight_bytes_no_undefined_shift() {
        // split_at(8) computes `1u64 << 64` in the masking branch when the
        // buffer holds exactly 8 bytes. The hardened path skips the mask in
        // that case (full-u64 mask is identity).
        let data = [0xab_u8; 32];
        let mut br = BitReader::new(&data);
        // Force `bits_in_buf == 64` by issuing a refill via peek().
        let _ = br.peek(56);
        let split = br.split_at(8).unwrap();
        // Both halves remain consistent; reads against the split still succeed.
        let mut split = split;
        assert_eq!(split.read(8).unwrap(), 0xab);
    }

    #[test]
    fn test_skip_bits_on_fresh_reader() {
        // This test checks if skip_bits works correctly on a fresh BitReader
        let data = [0x12, 0x34, 0x56, 0x78];
        let mut br = BitReader::new(&data);

        // Try to skip 1 bit on a fresh reader - this should work
        br.skip_bits(1)
            .expect("skip_bits should work on fresh reader");
        assert_eq!(br.total_bits_read(), 1);

        // Read the next 7 bits to complete the byte
        let val = br.read(7).expect("read should work");
        assert_eq!(val, 0x12 >> 1); // Should get the lower 7 bits of 0x12
    }
}
