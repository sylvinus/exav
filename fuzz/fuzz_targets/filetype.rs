#![no_main]
//! Content-based file-type identification on hostile bytes.
use exav_core::filetype;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = filetype::identify(data);
});
