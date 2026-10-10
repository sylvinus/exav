#![no_main]
//! Full-pipeline target: arbitrary bytes through the whole scanner with
//! heuristics on (pattern + hash, recursive unpack, PE/ML/fuzzy). Must
//! never panic, hang, or exhaust memory regardless of input.
use libfuzzer_sys::fuzz_target;
use exav_core::{analyze, Scanner, ScanOptions};

#[path = "../extreme.rs"]
mod extreme;

// A quarter of the mutations set one header field to the top of its range, where
// unchecked sums overflow (see `extreme.rs`).
libfuzzer_sys::fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    if extreme::set_extreme_field(data, size, seed) {
        size
    } else {
        libfuzzer_sys::fuzzer_mutate(data, size, max_size)
    }
});

fuzz_target!(|data: &[u8]| {
    let db = Scanner::builtin();
    let mut opts = ScanOptions::default();
    opts.heuristics = true;
    let _ = analyze(&db, data, &opts);
});
