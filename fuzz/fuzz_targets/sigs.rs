#![no_main]
//! Signature-text parsers (.ndb, simple Name=HEX, hash db, fuzzy db) on
//! arbitrary UTF-8.
use libfuzzer_sys::fuzz_target;
use exav_core::fuzzy::FuzzyDb;
use exav_core::hashes::HashDb;
use exav_core::patterns::PatternSet;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = PatternSet::parse_ndb(text);
        let _ = PatternSet::parse_simple(text);
        let mut h = HashDb::new();
        h.extend_from_text(text);
        let mut f = FuzzyDb::new();
        f.extend_from_text(text);
    }
});
