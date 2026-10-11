#![no_main]
//! exav's native YARA engine: rule text through the compiler, then the compiled
//! rules over fuzzed data.
//!
//! The input is `[rule_len: u16 LE] [rule text] [data]`. A seed is a rule file
//! behind its length, with a short sample after it (`scripts/fuzz-seeds.sh`
//! writes them from `fuzz/seeds/yara/`). The compiler is reached by anything
//! the loader hands it from a `.yar` file; the evaluator runs the conditions
//! on bytes the rule's author never saw: the `pe`, `elf`, `dotnet`, `math`,
//! `hash` and `string` modules, which parse the scanned file, and the pattern
//! matcher's hex, regular-expression, `xor` and `base64` forms.
//!
//! Checked: neither compiling nor scanning panics or overruns its budget; a
//! scan twice gives the same rules; and every match a scan reports lies inside
//! the data (`PatternMatch::data` slices it, so one that does not is a panic
//! here).
use exav_core::yara;
use libfuzzer_sys::fuzz_target;

/// Longer rule text is cut: compiling a long rule file is not what is under
/// test, and its time is not the fuzzer's to spend.
const MAX_RULES: usize = 4096;

fuzz_target!(|input: &[u8]| {
    let [lo, hi, rest @ ..] = input else {
        return;
    };
    let len = (u16::from_le_bytes([*lo, *hi]) as usize).min(rest.len()).min(MAX_RULES);
    let (text, data) = rest.split_at(len);
    let Ok(text) = std::str::from_utf8(text) else {
        return;
    };
    let Ok(rules) = yara::compile(text) else {
        return;
    };

    let run = |filename: Option<&str>| {
        let mut scanner = yara::Scanner::new(&rules);
        if let Some(f) = filename {
            scanner.set_global("filename", f);
            scanner.set_global("filepath", f);
            scanner.set_global("extension", ".js");
        }
        let results = scanner.scan(data).expect("scanning does not fail");
        let mut matched = Vec::new();
        for rule in results.matching_rules() {
            for pattern in rule.patterns() {
                for m in pattern.matches() {
                    assert_eq!(m.data().len(), m.length());
                }
            }
            matched.push(rule.identifier().to_string());
        }
        (matched, results.budget_exhausted())
    };
    let first = run(None);
    assert_eq!(first, run(None), "a scan twice gave two answers");
    let _ = run(Some("sample.js"));
});
