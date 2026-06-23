#![no_main]
//! CVD/CLD container parsing (header + gzip + tar) on hostile bytes.
use libfuzzer_sys::fuzz_target;
use exav_core::cvd;

fuzz_target!(|data: &[u8]| {
    let _ = cvd::read(data);
});
