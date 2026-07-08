//! aPLib decompression (clean-room, from the published on-disk format).
//!
//! aPLib is a byte-aligned LZ77 variant with an interleaved MSB-first tag-bit
//! stream and gamma-2 coded offsets/lengths. It is the compression codec used
//! by several PE runtime packers — Petite 2.x, FSG 2.0 and NsPack all wrap an
//! aPLib stream around the original image — so decoding it lets the engine scan
//! the *original* bytes rather than only the packed stub.
//!
//! The two stream primitives (`getbit`, `getgamma`) are reproduced verbatim from
//! the reference `depack.c` (public-domain aPLib by Jørgen Ibsen); the decision
//! tree, the `R0`/`LWM` ("last-was-match") state and the offset-dependent length
//! bias (`< 128`, `>= 1280`, `>= 32000`) follow the same reference. The decoder
//! is fully bounds-checked (`#![forbid(unsafe_code)]` at the crate root): any
//! out-of-range back-reference, truncated stream, or output exceeding `max_out`
//! yields `None` rather than a panic, so hostile input can never crash the
//! scanner or read out of bounds.
//!
//! Verified in-tree by byte-exact round-trip against [`tests::pack`], an
//! independent aPLib encoder written to the same published format (literals +
//! general gamma matches + end marker), over random and highly-repetitive
//! inputs across the offset-bias boundaries.

/// MSB-first tag-bit reader over an aPLib stream. Tag bytes are pulled lazily
/// from the same cursor that yields literal/offset data bytes, exactly as the
/// reference decoder does, so the two interleave correctly.
struct BitIn<'a> {
    src: &'a [u8],
    pos: usize,
    tag: u8,
    nbits: u8,
}

impl<'a> BitIn<'a> {
    fn new(src: &'a [u8]) -> Self {
        BitIn {
            src,
            pos: 0,
            tag: 0,
            nbits: 0,
        }
    }

    /// Read the next data byte from the stream (literal or offset low byte).
    fn byte(&mut self) -> Option<u8> {
        let b = *self.src.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// `aP_getbit`: reload a fresh tag byte when the current one is exhausted,
    /// then shift out the top bit (MSB first).
    fn bit(&mut self) -> Option<u32> {
        if self.nbits == 0 {
            self.tag = self.byte()?;
            self.nbits = 8;
        }
        let bit = (self.tag >> 7) & 1;
        self.tag <<= 1;
        self.nbits -= 1;
        Some(bit as u32)
    }

    /// `aP_getgamma`: gamma-2 code — `result` starts at 1, then repeatedly
    /// `result = (result << 1) + bit` while the following continuation bit is 1.
    /// The smallest value it can encode is 2.
    fn gamma(&mut self) -> Option<u32> {
        let mut result: u32 = 1;
        loop {
            result = result.checked_mul(2)?.checked_add(self.bit()?)?;
            if self.bit()? == 0 {
                return Some(result);
            }
            // Bound the code length: a legitimate gamma value fits in 32 bits.
            if result > (1 << 30) {
                return None;
            }
        }
    }
}

/// Decompress an aPLib stream. Returns the decompressed bytes, or `None` if the
/// stream is malformed, references out of bounds, or would exceed `max_out`.
pub(crate) fn depack(src: &[u8], max_out: usize) -> Option<Vec<u8>> {
    if src.is_empty() {
        return None;
    }
    let mut bi = BitIn::new(src);
    let mut out: Vec<u8> = Vec::new();

    // First byte is emitted verbatim.
    out.push(bi.byte()?);

    let mut r0: usize = usize::MAX; // last match offset ("R0"); sentinel = unset
    let mut lwm = 0u32; // "last was match"

    loop {
        if out.len() > max_out {
            return None;
        }
        if bi.bit()? == 0 {
            // 0 -> literal byte.
            let b = bi.byte()?;
            out.push(b);
            lwm = 0;
            continue;
        }
        if bi.bit()? == 0 {
            // 10 -> gamma-coded match (the general LZ case).
            let mut offs = bi.gamma()? as usize;
            let len;
            if lwm == 0 && offs == 2 {
                // Reuse the previous offset (R0).
                offs = r0;
                len = bi.gamma()? as usize;
            } else {
                offs = if lwm == 0 {
                    offs.checked_sub(3)?
                } else {
                    offs.checked_sub(2)?
                };
                offs = offs.checked_mul(256)?.checked_add(bi.byte()? as usize)?;
                let mut l = bi.gamma()? as usize;
                if offs >= 32000 {
                    l += 1;
                }
                if offs >= 1280 {
                    l += 1;
                } else if offs < 128 {
                    l += 2;
                }
                len = l;
                r0 = offs;
            }
            copy_match(&mut out, offs, len, max_out)?;
            lwm = 1;
            continue;
        }
        if bi.bit()? == 0 {
            // 100.. wait: consumed "11", next bit 0 -> "110": 7-bit offset, len 2/3.
            let b = bi.byte()? as usize;
            let len = 2 + (b & 1);
            let offs = b >> 1;
            if offs == 0 {
                // End-of-stream marker.
                return Some(out);
            }
            copy_match(&mut out, offs, len, max_out)?;
            r0 = offs;
            lwm = 1;
            continue;
        }
        // 111 -> 4-bit short offset, single byte. offs == 0 emits a literal NUL.
        let mut offs = 0usize;
        for _ in 0..4 {
            offs = (offs << 1) + bi.bit()? as usize;
        }
        if offs == 0 {
            out.push(0);
        } else {
            copy_match(&mut out, offs, 1, max_out)?;
        }
        lwm = 0;
    }
}

/// Copy `len` bytes from `offs` behind the current output tail, one byte at a
/// time (aPLib matches may overlap, e.g. RLE runs). Fully bounds-checked.
#[inline]
fn copy_match(out: &mut Vec<u8>, offs: usize, len: usize, max_out: usize) -> Option<()> {
    if offs == 0 || offs > out.len() {
        return None;
    }
    if out.len() + len > max_out {
        return None;
    }
    // Byte-at-a-time so overlapping matches (offs < len, e.g. RLE runs) copy the
    // bytes produced earlier in this same run. `start + i` indexes into the
    // growing buffer, so it reaches those freshly-pushed bytes.
    let start = out.len() - offs;
    for i in 0..len {
        let b = out[start + i];
        out.push(b);
    }
    Some(())
}

/// MSB-first tag-bit writer mirroring [`BitIn`]: a tag byte is reserved in the
/// output the moment its first bit is written and filled in place, so data bytes
/// appended in between land after it — exactly the interleaving the decoder
/// expects. Test-only: the independent encoder used to build round-trip and
/// end-to-end fixtures; not part of the scanning path.
#[cfg(test)]
pub(crate) mod encoder {
    struct BitOut {
        out: Vec<u8>,
        tag_pos: usize,
        filled: u8,
    }

    impl BitOut {
        fn new() -> Self {
            BitOut {
                out: Vec::new(),
                tag_pos: usize::MAX,
                filled: 8,
            }
        }
        fn bit(&mut self, b: u32) {
            if self.filled == 8 {
                self.tag_pos = self.out.len();
                self.out.push(0);
                self.filled = 0;
            }
            if b & 1 != 0 {
                self.out[self.tag_pos] |= 0x80 >> self.filled;
            }
            self.filled += 1;
        }
        fn byte(&mut self, b: u8) {
            self.out.push(b);
        }
        /// Inverse of `getgamma`: emit `v` (>= 2) as a gamma-2 code.
        fn gamma(&mut self, v: u32) {
            assert!(v >= 2);
            let hb = 31 - v.leading_zeros(); // index of the leading 1
            let mut i = hb; // emit bits below the leading 1, MSB..LSB
            while i > 0 {
                i -= 1;
                self.bit((v >> i) & 1);
                self.bit(if i > 0 { 1 } else { 0 });
            }
        }
    }

    /// Independent aPLib encoder (literals + general gamma matches + end marker).
    /// Greedy longest-match search; only emits a match when its length is
    /// achievable through the "10" path for that offset's length bias, so the
    /// output is always a well-formed aPLib stream the reference decoder accepts.
    pub(crate) fn pack(input: &[u8]) -> Vec<u8> {
        let mut bo = BitOut::new();
        if input.is_empty() {
            // Degenerate: nothing sensible to emit; callers don't use this.
            bo.byte(0);
        } else {
            bo.byte(input[0]);
        }
        let mut lwm = 0u32;
        let mut i = 1usize;
        while i < input.len() {
            // Greedy longest match in the already-emitted history.
            let (mut best_len, mut best_off) = (0usize, 0usize);
            let max_off = i; // whole history
            let search_start = i.saturating_sub(0xFF_FFFF);
            for start in search_start..i {
                let off = i - start;
                let _ = max_off;
                let mut l = 0usize;
                while i + l < input.len() && input[start + l] == input[i + l] {
                    l += 1;
                    if l >= 4096 {
                        break;
                    }
                }
                if l > best_len {
                    best_len = l;
                    best_off = off;
                }
            }
            // The "10" path can encode length >= 4 for every offset bias (the
            // smallest gamma is 2, plus a bias of at most 2), so a 4-byte
            // minimum keeps every emitted match well-formed for the decoder.
            if best_len >= 4 {
                // Emit "10" general match.
                bo.bit(1);
                bo.bit(0);
                let high = (best_off >> 8) as u32;
                let g = if lwm == 0 { high + 3 } else { high + 2 };
                bo.gamma(g);
                bo.byte((best_off & 0xFF) as u8);
                // Reverse the decoder's length bias to get the gamma length.
                let mut bias = 0usize;
                if best_off >= 32000 {
                    bias += 1;
                }
                if best_off >= 1280 {
                    bias += 1;
                } else if best_off < 128 {
                    bias += 2;
                }
                bo.gamma((best_len - bias) as u32);
                lwm = 1;
                i += best_len;
            } else {
                // Emit literal.
                bo.bit(0);
                bo.byte(input[i]);
                lwm = 0;
                i += 1;
            }
        }
        // End marker: "110" then a byte whose offset field (>>1) is 0.
        bo.bit(1);
        bo.bit(1);
        bo.bit(0);
        bo.byte(0);
        bo.out
    }
}

#[cfg(test)]
mod tests {
    use super::depack;
    use super::encoder::pack;

    fn roundtrip(input: &[u8]) {
        let packed = pack(input);
        let out = depack(&packed, input.len() + 16).expect("depack");
        assert_eq!(out, input, "round-trip mismatch (len {})", input.len());
    }

    #[test]
    fn roundtrip_literals_only() {
        roundtrip(b"hello, world");
        roundtrip(b"A");
        roundtrip(&[0u8, 1, 2, 3, 255, 254, 0, 0]);
    }

    #[test]
    fn roundtrip_repetitive_forces_matches() {
        // Long RLE run (overlapping match) and repeated phrases exercise the
        // "10" gamma path and overlapping copies.
        roundtrip(&vec![0x41u8; 1000]);
        let mut v = Vec::new();
        for _ in 0..200 {
            v.extend_from_slice(b"the quick brown fox ");
        }
        roundtrip(&v);
    }

    #[test]
    fn roundtrip_offset_bias_boundaries() {
        // Build inputs whose best match offsets straddle the 128 / 1280 / 32000
        // length-bias boundaries so the decoder's bias arithmetic is covered.
        for &gap in &[100usize, 200, 1300, 33000] {
            let mut v: Vec<u8> = (0..gap as u32)
                .map(|x| (x.wrapping_mul(2654435761u32) >> 24) as u8)
                .collect();
            let tail: Vec<u8> = v[..gap.min(64)].to_vec();
            v.extend_from_slice(&tail); // a match at distance ~gap
            v.extend_from_slice(&tail);
            roundtrip(&v);
        }
    }

    #[test]
    fn roundtrip_pseudorandom_sizes() {
        // Deterministic LCG data at several sizes; mixes literals and short
        // incidental matches.
        for &n in &[1usize, 2, 3, 7, 33, 129, 1000, 5000] {
            let mut state = 0x12345678u32;
            let data: Vec<u8> = (0..n)
                .map(|_| {
                    state = state.wrapping_mul(1103515245).wrapping_add(12345);
                    (state >> 16) as u8
                })
                .collect();
            roundtrip(&data);
        }
    }

    #[test]
    fn malformed_streams_return_none_not_panic() {
        assert!(depack(b"", 1024).is_none());
        // Truncated after the verbatim byte with a dangling literal tag.
        assert!(depack(&[0x41, 0x00], 1024).is_none());
        // A stream that decodes past the cap must be refused.
        let packed = pack(&vec![0x55u8; 500]);
        assert!(depack(&packed, 16).is_none());
        // Fuzz-ish: assorted junk must never panic.
        for seed in 0u32..64 {
            let mut s = seed.wrapping_mul(2654435761).wrapping_add(1);
            let junk: Vec<u8> = (0..40)
                .map(|_| {
                    s = s.wrapping_mul(1103515245).wrapping_add(12345);
                    (s >> 20) as u8
                })
                .collect();
            let _ = depack(&junk, 1 << 16);
        }
    }
}
