#![no_main]
//! PE structural analysis (goblin parse + section entropy + imphash) on
//! hostile bytes.
use exav_core::pe;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pe::analyze(data);
});
