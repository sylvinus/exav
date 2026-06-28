//! PPMd variant H (PPMd7) model, vendored and adapted from `ppmd-rust` 1.4.0
//! (Copyright the `ppmd-rust` authors, dual-licensed **CC0-1.0 OR MIT-0** — a
//! public-domain-equivalent licence). `ppmd-rust` is itself a Rust
//! port of Igor Pavlov's 7-Zip PPMd7, which in turn implements Dmitry Shkarin's
//! public-domain PPMd var.H (2001). **None of this derives from UnRAR/RARLAB.**
//!
//! The upstream `ppmd-rust` exposes only a 7z byte-stream decoder
//! (`Ppmd7Decoder`) whose range coder is `pub(crate)`. RAR's PPMd uses the same
//! var.H *model* but a different (Subbotin carry-less) range coder and its own
//! framing. So the model is vendored here and generalised over a [`RangeDec`]
//! trait that exposes the three operations PPMd needs from a range decoder
//! (`get_threshold`, `decode`, `decode_bit`); concrete decoders for the 7z and
//! RAR range coders are provided in [`rangedec`]. The RAR framing (escape
//! symbol, order/memory bits, LZSS interplay) lives in `rar3_unpack.rs` and is
//! derived from libarchive's BSD-2-Clause `archive_read_support_format_rar.c`
//! (the same upstream this crate already ports for RAR3/RAR5 LZ), not UnRAR.
//!
//! Everything is bounds/over-subscription checked at the framing layer; the
//! model uses an internal raw-pointer arena (as the C original does) but never
//! escapes its own pre-allocated allocation, and decode errors are surfaced as
//! `SYM_ERROR`/`SYM_END` rather than panicking.

mod model;
mod rangedec;
mod tagged_offset;

pub(crate) use model::Ppmd7;
pub(crate) use rangedec::RarRangeDecoder;
pub(crate) use rangedec::SevenZRangeDecoder;

/// A range decoder symbol decode returned this end-of-stream marker.
pub(crate) const SYM_END: i32 = -1;
/// A range decoder symbol decode hit a model/range inconsistency.
pub(crate) const SYM_ERROR: i32 = -2;

pub(crate) const PPMD7_MIN_ORDER: u32 = 2;
pub(crate) const PPMD7_MAX_ORDER: u32 = 64;
pub(crate) const PPMD7_MIN_MEM_SIZE: u32 = 2048;
pub(crate) const PPMD7_MAX_MEM_SIZE: u32 = u32::MAX - 12 * 3;

/// Decode a complete 7z-framed PPMd7 stream of exactly `out_len` bytes. Used by
/// the model-validation test against a reference `ppmd-rust` encoder. Returns
/// `None` if init fails or the stream is truncated/inconsistent before producing
/// `out_len` bytes.
#[cfg(test)]
pub(crate) fn decode_7z(data: &[u8], order: u32, mem_size: u32, out_len: usize) -> Option<Vec<u8>> {
    let rc = SevenZRangeDecoder::new(data);
    if !rc.init_ok() {
        return None;
    }
    let mut model = Ppmd7::new(rc, order, mem_size)?;
    let mut out = Vec::with_capacity(out_len);
    while out.len() < out_len {
        let sym = model.decode_symbol();
        if sym < 0 {
            return None;
        }
        out.push(sym as u8);
    }
    Some(out)
}

/// The three operations PPMd7's symbol decoder needs from a range decoder.
///
/// Each operation leaves the decoder in a normalised state (so the model never
/// has to call a separate `normalize`). For the 7z coder normalisation is
/// idempotent when the range is already large enough, so always-normalising is
/// behaviourally identical to the upstream `decode` + later `normalize_remote`.
pub(crate) trait RangeDec {
    /// `get_threshold(total)`: scale the range by `total` and return the count.
    fn get_threshold(&mut self, total: u32) -> u32;
    /// Consume the sub-range `[start, start+size)` and renormalise.
    fn decode(&mut self, start: u32, size: u32);
    /// Decode one binary-context bit with probability `size0`. Returns 0/1.
    fn decode_bit(&mut self, size0: u32) -> u32;
    /// True once the underlying byte source has been exhausted (truncation).
    fn out_of_data(&self) -> bool;
    /// Number of input bytes consumed so far (for resuming a shared cursor after
    /// a RAR3 PPMd→LZSS conversion).
    fn bytes_consumed(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ppmd_rust::Ppmd7Encoder;
    use std::io::Write;

    /// Round-trip the vendored model against the reference `ppmd-rust` 7z
    /// encoder: encode known data with the reference encoder, decode with our
    /// vendored `Ppmd7<SevenZRangeDecoder>`, and assert byte-exact equality.
    /// This validates the var.H model + the 7z range decoder.
    fn roundtrip(data: &[u8], order: u32, mem: u32) {
        let mut packed = Vec::new();
        {
            let mut enc = Ppmd7Encoder::new(&mut packed, order, mem).unwrap();
            enc.write_all(data).unwrap();
            // No end marker: decoder is bounded by the known output length.
            enc.finish(false).unwrap();
        }
        let decoded = decode_7z(&packed, order, mem, data.len())
            .expect("vendored model failed to decode reference 7z PPMd stream");
        assert_eq!(decoded, data, "byte mismatch (order={order}, mem={mem})");
    }

    #[test]
    fn model_matches_reference_text() {
        let text = b"the quick brown fox jumps over the lazy dog. \
                     the quick brown fox jumps over the lazy dog. \
                     PPMd var.H round-trip validation, repeated text repeated text."
            .repeat(40);
        roundtrip(&text, 6, 1 << 18);
        roundtrip(&text, 16, 1 << 20);
    }

    #[test]
    fn model_matches_reference_binary() {
        // Pseudo-random but deterministic bytes exercise the escape/SEE paths.
        let mut data = Vec::with_capacity(8192);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..8192 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            data.push((x >> 16) as u8);
        }
        roundtrip(&data, 4, 1 << 16);
        roundtrip(&data, 8, 1 << 19);
    }

    #[test]
    fn model_matches_reference_small() {
        roundtrip(b"a", 2, 2048);
        roundtrip(b"abcabcabcabc", 3, 4096);
        roundtrip(&[0u8; 1000], 6, 1 << 16);
    }
}
