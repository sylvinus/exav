#![no_main]
//! PE structural analysis (goblin parse + section entropy + imphash) on
//! hostile bytes.
use libfuzzer_sys::fuzz_target;
use exav_core::pe;

fuzz_target!(|data: &[u8]| {
    let _ = pe::analyze(data);
});
