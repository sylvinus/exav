#![no_main]
//! Archive extraction on hostile bytes, tried as EVERY supported format.
//! The fuzzer doesn't need to "luck into" valid headers — each input is
//! attempted as all formats, so even random bytes exercise every parser's
//! error paths. Tight budgets prevent DoS from decompression bombs.
//!
//! A short list of candidate passwords is supplied so the decryption paths
//! (ZipCrypto/WinZip-AES, 7z AES, PDF/DMG crypto) are reachable when the mutator
//! produces a plausible encrypted container.
//!
//! Seeds: `scripts/fuzz-seeds.sh` (the `containers` directory, every test
//! fixture of at most 64 KiB), so the mutator starts inside each parser instead
//! of rediscovering magic bytes.
use libfuzzer_sys::fuzz_target;
use exav_unpack::{extract, Budget, Format, Limits};

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

fn tight_limits() -> Limits {
    let mut l = Limits::default();
    l.max_extracted_bytes = 256 * 1024;
    l.max_members = 5;
    l.max_compression_ratio = 50;
    l.max_buffer_bytes = 128 * 1024;
    l.max_scanned_bytes = 256 * 1024;
    l.max_recursion = 2;
    // Every format stays reachable. Narrowing the set here would take whole
    // parsers out of the fuzzer's reach, which is the opposite of what this
    // target is for.
    l.allowed_formats = None;
    l
}

fuzz_target!(|data: &[u8]| {
    // `Format::ALL`, not a list of our own: a hand-kept copy here fell behind
    // the enum and left 26 formats unfuzzed. Each parser's error paths are
    // reached directly, without the mutator synthesising valid magic bytes.
    for &fmt in Format::ALL {
        // Candidate passwords exercise the decryption paths (7z AES, ZipCrypto,
        // WinZip-AES, PDF/DMG); harmless for every other format.
        let mut budget = Budget::with_passwords(
            tight_limits(),
            vec!["infected".to_string(), "hunter2".to_string()],
        );
        let _ = extract(fmt, &data, &mut budget);
    }
});
