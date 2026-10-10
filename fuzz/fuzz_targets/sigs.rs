#![no_main]
//! Signature-text parsers (simple Name=HEX, hash db, fuzzy db) on arbitrary
//! UTF-8. `.ndb` text is fuzzed through the engine by `ndb_compile`.
use libfuzzer_sys::fuzz_target;
use exav_core::fuzzy::FuzzyDb;
use exav_core::hashes::HashDb;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = exav_core::patterns::parse_simple(text);
        let mut h = HashDb::new();
        h.extend_from_text(text);
        let mut f = FuzzyDb::new();
        f.extend_from_text(text);
    }
});
