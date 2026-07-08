#![no_main]
//! Content-based file-type identification on hostile bytes.
use libfuzzer_sys::fuzz_target;
use exav_core::filetype;

fuzz_target!(|data: &[u8]| {
    let _ = filetype::identify(data);
});
