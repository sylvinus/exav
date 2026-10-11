#![no_main]
//! The PCRE subsignatures of a logical signature: ClamAV's PCRE2 syntax
//! rewritten for two Rust engines (`exav_core::engine`'s `pcre.rs`), the
//! backtracking one vendored from fancy-regex and the linear `regex`.
//!
//! The input is `[flags: u8] [pattern_len: u16 LE] [pattern] [haystack]`; the
//! flags are bits for `i s m x E U`. A pattern comes from a signature database
//! and the haystack from a scanned file, so both are hostile.
//!
//! Checked: the rewrite and both engines neither panic nor hang, and when the
//! translation is in the linear engine's subset the two engines answer the same
//! (the module's contract: "a subset both engines read as PCRE does"), when the
//! backtracking engine answers at all. Its step budget makes a pathological
//! pattern a refusal, not a hang.
use exav_core::engine::compare_engines;
use libfuzzer_sys::fuzz_target;

/// A longer pattern is cut: a regex that large is a compile benchmark.
const MAX_PATTERN: usize = 512;

fuzz_target!(|input: &[u8]| {
    let [flags, lo, hi, rest @ ..] = input else {
        return;
    };
    let len = (u16::from_le_bytes([*lo, *hi]) as usize).min(rest.len()).min(MAX_PATTERN);
    let (pattern, hay) = rest.split_at(len);
    let Ok(pattern) = std::str::from_utf8(pattern) else {
        return;
    };
    let letters: String = ["i", "s", "m", "x", "E", "U"]
        .iter()
        .enumerate()
        .filter(|(n, _)| flags & (1 << n) != 0)
        .map(|(_, l)| *l)
        .collect();
    let Some(got) = compare_engines(pattern, &letters, hay) else {
        return;
    };
    // A refusal by the backtracking engine (a pattern it will not build, or a
    // step budget spent) is no answer: the scan takes the linear engine's when
    // the translation is in its subset, and the backtracking one only for what
    // the linear one cannot run.
    if let (Some(linear), Some(backtracking)) = (got.linear, got.backtracking) {
        assert_eq!(
            backtracking, linear,
            "/{pattern}/{letters} as {}: the backtracking engine says {backtracking}, the linear {linear}",
            got.translated
        );
    }
});
