#![no_main]
//! Full-pipeline target: arbitrary bytes through the whole scanner with
//! heuristics on (pattern + hash, recursive unpack, PE/ML/fuzzy). Must
//! never panic, hang, or exhaust memory regardless of input.
use libfuzzer_sys::fuzz_target;
use exav_core::{analyze, Database, ScanOptions};

fuzz_target!(|data: &[u8]| {
    let db = Database::builtin();
    let opts = ScanOptions { heuristics: true, ..Default::default() };
    let _ = analyze(&db, data, &opts);
});
