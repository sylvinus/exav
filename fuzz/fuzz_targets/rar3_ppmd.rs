#![no_main]
//! Feed arbitrary bytes through the RAR3 PPMd unpacker.  The fuzzer supplies
//! both the (possibly malformed) packed data and the metadata; the decoder
//! must never panic regardless of input.
use exav_unpack::{Budget, Limits, unpack29};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Interpret the first 16 bytes as little-endian metadata, rest as packed
    // payload.  This lets the fuzzer explore the full decoder state space
    // without us needing a real RAR4 header parser.
    if data.len() < 16 {
        return;
    }
    let unp = u64::from_le_bytes(data[..8].try_into().unwrap());
    let win_bits = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let unp = unp.min(64 * 1024);
    // win_bits must be in 10..=24 for the PPMd allocator.
    let win_bits = 10 + (win_bits % 15);
    let packed = &data[16..];

    let mut limits = Limits::default();
    // A member decodes to its stream's end, past the size it declares: the
    // budget is what keeps a run short.
    limits.max_extracted_bytes = 64 * 1024;
    limits.max_buffer_bytes = 4 * 1024 * 1024;
    limits.max_compression_ratio = u64::MAX;
    limits.max_members = 100;
    let mut budget = Budget::new(limits);
    let _ = unpack29(packed, unp, win_bits, &mut budget);
});
