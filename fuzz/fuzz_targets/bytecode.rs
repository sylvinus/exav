#![no_main]
//! The `.cbc` bytecode parser (number/data decoder + header/trigger/API
//! parsing) and the bounded VM decoder on arbitrary input. Must never panic.
use exav_core::bytecode;
use exav_core::bytecode::decode::Reader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The number/data decoder over raw bytes.
    let mut r = Reader::new(data);
    let _ = r.number();
    let _ = r.data(1 << 16);
    let mut r2 = Reader::new(data);
    let _ = r2.fixed(8);

    // The full program parser over arbitrary text.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = bytecode::parse(text);
    }
});
