#![no_main]
//! Fuzz the NDB/LDB signature compiler: parse arbitrary signature text through
//! `EngineBuilder::add_ndb()` / `add_ldb()`, then build the engine.  Catches
//! panics in `parse_elems`, `compile_body`, `pick_anchor`, `parse_gap`,
//! `parse_alt`, AC automaton construction, and all the hex-wildcard parsing
//! codepaths that no other fuzz target reaches.
use libfuzzer_sys::fuzz_target;
use exav_core::engine::EngineBuilder;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let mut b = EngineBuilder::new();
        // Feed arbitrary text as NDB lines.
        b.add_ndb(text, false);
        // Feed the same text as LDB lines (different parser, different panics).
        b.add_ldb(text, false);
        // Build the engine — exercises AC construction from whatever compiled.
        let _ = b.build();
    }
});
