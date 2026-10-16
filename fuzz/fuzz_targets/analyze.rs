#![no_main]
//! Full-pipeline target: arbitrary bytes through the whole scanner, against the
//! signature files of `fuzz/db/` (every signature kind, the YARA rules and a
//! bytecode program included), under options the input's last two bytes choose
//! (`options::scan_options`): the heuristics and alerts, bounds tight or
//! production's, an object read in memory or through the block cache. Must
//! never panic, hang, or exhaust memory regardless of input.
//!
//! The last two bytes are the selector and are not scanned, so a fixture seed
//! of any length works unchanged, under whichever options its tail happens to
//! select.
use exav_core::analyze;
use exav_fuzz_support::{extreme, frame};
use libfuzzer_sys::fuzz_target;

#[path = "../db.rs"]
mod db;
#[path = "../options.rs"]
mod options;

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
    exav_fuzz_support::panics::tolerate_inside(exav_fuzz_support::panics::CONTAINED);
    let (body, bits) = frame::trailer(data);
    let _ = analyze(db::scanner(), body, &options::scan_options(bits));
});
