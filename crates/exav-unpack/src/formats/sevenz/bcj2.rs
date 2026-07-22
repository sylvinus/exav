//! BCJ2 — 7-Zip's x86 branch converter, the four-input one.
//!
//! 7-Zip selects BCJ2 automatically for executables at high compression
//! settings, so "a 7z of an .exe at `-mx=9`" is an entirely ordinary thing for
//! an attacker to produce. Unlike every other 7z coder it takes **four** input
//! streams rather than one, which is why it needs the folder's bind-pair graph
//! rather than the linear chain the other codecs use:
//!
//! * **main** — the instruction bytes, with converted addresses removed
//! * **call** — 4-byte big-endian absolute targets for `E8` (CALL)
//! * **jump** — the same for `E9` (JMP)
//! * **rc** — a range-coded bit per candidate opcode, saying whether it was
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

use crate::LimitHit;

const NUM_MODEL_BITS: u32 = 11;
const BIT_MODEL_TOTAL: u32 = 1 << NUM_MODEL_BITS;
const NUM_MOVE_BITS: u32 = 5;
const TOP_VALUE: u32 = 1 << 24;

/// `probs[0]` covers the `0F 8x` (Jcc near) case, `probs[1]` covers `E9`, and
/// `probs[2 + prev]` covers `E8` keyed on the preceding byte.
const NUM_PROBS: usize = 2 + 256;

struct RangeDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(buf: &'a [u8]) -> Self {
        let mut rd = RangeDecoder {
            buf,
            pos: 0,
            range: 0xFFFF_FFFF,
            code: 0,
        };
        // The first byte is padding; the next four are the initial code.
        rd.pos = 1;
        for _ in 0..4 {
            rd.code = (rd.code << 8) | rd.next_byte() as u32;
        }
        rd
    }

    fn next_byte(&mut self) -> u8 {
        let b = self.buf.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }

    fn normalize(&mut self) {
        if self.range < TOP_VALUE {
            self.range <<= 8;
            self.code = (self.code << 8) | self.next_byte() as u32;
        }
    }

    fn decode_bit(&mut self, prob: &mut u16) -> u32 {
        let bound = (self.range >> NUM_MODEL_BITS) * (*prob as u32);
        let bit = if self.code < bound {
            self.range = bound;
            *prob += ((BIT_MODEL_TOTAL - *prob as u32) >> NUM_MOVE_BITS) as u16;
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob -= (*prob as u32 >> NUM_MOVE_BITS) as u16;
            1
        };
        self.normalize();
        bit
    }
}

/// Is `b1` the second byte of a branch instruction whose target BCJ2 may have
/// converted? `b0` is the byte before it.
fn is_branch(b0: u8, b1: u8) -> bool {
    (b1 & 0xFE) == 0xE8 || (b0 == 0x0F && (b1 & 0xF0) == 0x80)
}

/// Reassemble `out_size` bytes from the four BCJ2 streams.
pub(super) fn decode(
    main: &[u8],
    call: &[u8],
    jump: &[u8],
    rc: &[u8],
    out_size: usize,
) -> Result<Vec<u8>, LimitHit> {
    let mut probs = [(BIT_MODEL_TOTAL / 2) as u16; NUM_PROBS];
    let mut rd = RangeDecoder::new(rc);

    // Reserve against the cap, not against the declaration: `out_size` is an
    // attacker-written header field, and the loop below grows `out` as it goes,
    // so a short reservation costs a few reallocations and nothing else.
    let mut out = Vec::with_capacity(crate::cap_prealloc(out_size));
    let (mut main_pos, mut call_pos, mut jump_pos) = (0usize, 0usize, 0usize);
    let mut prev: u8 = 0;

    while out.len() < out_size {
        let Some(&b) = main.get(main_pos) else {
            // The main stream ran out before the folder's declared size: the
            // archive is truncated, so what exists has been decoded.
            break;
        };
        main_pos += 1;
        out.push(b);

        if !is_branch(prev, b) {
            prev = b;
            continue;
        }
        // A candidate branch: the range coder says whether its target was
        // converted to absolute form and moved into the call/jump stream.
        let idx = if b == 0xE8 {
            2 + prev as usize
        } else if b == 0xE9 {
            1
        } else {
            0
        };
        if rd.decode_bit(&mut probs[idx]) == 0 {
            prev = b;
            continue;
        }
        let (src_buf, src_pos) = if b == 0xE8 {
            (call, &mut call_pos)
        } else {
            (jump, &mut jump_pos)
        };
        let Some(raw) = src_buf.get(*src_pos..*src_pos + 4) else {
            return Err(LimitHit::corrupt(
                "7z BCJ2: call/jump stream exhausted".to_string(),
            ));
        };
        *src_pos += 4;
        let absolute = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        // x86 branch displacements are relative to the END of the instruction,
        // which is four bytes past where the target is about to be written.
        let relative = absolute.wrapping_sub(out.len() as u32 + 4);
        out.extend_from_slice(&relative.to_le_bytes());
        prev = (relative >> 24) as u8;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    /// The declared output size is a header var-int. Reserving it directly asks
    /// the allocator for whatever the archive says, and an allocation that large
    /// does not return an error — it aborts the process, which no `catch_unwind`
    /// boundary can turn back into a verdict.
    ///
    /// If this regresses the test does not fail, it kills the test binary. That
    /// is the same thing a scan does.
    #[test]
    fn a_huge_declared_output_does_not_get_reserved() {
        let out = super::decode(&[], &[], &[], &[], usize::MAX / 2).expect("decode");
        assert!(
            out.is_empty(),
            "no main-stream bytes, so there is nothing to decode"
        );
    }
}
