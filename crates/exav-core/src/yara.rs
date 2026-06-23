//! YARA rule support via the pure-Rust `yara-x` engine (VirusTotal).
//!
//! Traditional engines support only a restricted YARA subset (no modules, ≤64 strings/rule,
//! etc.). `yara-x` targets ~full YARA compatibility, so loading real-world
//! `.yar`/`.yara` rule sets gives detection coverage those engines can't.
//!
//! Rules execute on wasmtime's **Pulley interpreter** (the `pulley` feature on
//! the yara-x dependency), so there is no native JIT / runtime codegen — the
//! malware bytes are parsed by yara-x's safe-Rust modules + regex, and the
//! compiled rule condition runs interpreted. Rule *source* is what we keep and
//! serialize (into the on-disk cache); the compiled `Rules` are built lazily on
//! first scan and not serialized.

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Default, Serialize, Deserialize)]
pub struct YaraDb {
    /// Accumulated rule sources (one per loaded `.yar`/`.yara` file).
    sources: Vec<String>,
    /// Compiled rules, built once from `sources` on first use. `None` if no
    /// sources, or if compilation failed.
    #[serde(skip)]
    compiled: OnceLock<Option<yara_x::Rules>>,
}

impl YaraDb {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.sources.len()
    }
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
    /// Add one rule file's source text.
    pub fn extend_from_text(&mut self, text: &str) {
        self.sources.push(text.to_string());
    }

    fn rules(&self) -> Option<&yara_x::Rules> {
        self.compiled
            .get_or_init(|| {
                if self.sources.is_empty() {
                    return None;
                }
                let mut c = yara_x::Compiler::new();
                for src in &self.sources {
                    // A bad rule file is skipped, not fatal to the DB load.
                    let _ = c.add_source(src.as_str());
                }
                Some(c.build())
            })
            .as_ref()
    }

    /// Scan `data`; return the identifier of the first matching rule.
    pub fn scan(&self, data: &[u8]) -> Option<String> {
        let rules = self.rules()?;
        let mut scanner = yara_x::Scanner::new(rules);
        let results = scanner.scan(data).ok()?;
        results
            .matching_rules()
            .next()
            .map(|r| r.identifier().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_a_simple_rule() {
        let mut db = YaraDb::new();
        db.extend_from_text(
            r#"
            rule evil_marker {
                strings:
                    $a = "UNIQUE_EXAV_YARA_MARKER"
                condition:
                    $a
            }
            "#,
        );
        assert_eq!(db.len(), 1);
        assert_eq!(
            db.scan(b"....UNIQUE_EXAV_YARA_MARKER....").as_deref(),
            Some("evil_marker")
        );
        assert!(db.scan(b"nothing to see here").is_none());
    }

    #[test]
    fn hex_and_condition_rule() {
        let mut db = YaraDb::new();
        db.extend_from_text(
            r#"
            rule pe_with_two {
                strings:
                    $mz = { 4D 5A }
                    $s = "evilfn"
                condition:
                    $mz at 0 and $s
            }
            "#,
        );
        assert_eq!(
            db.scan(b"MZ\x90\x00 ... evilfn ...").as_deref(),
            Some("pe_with_two")
        );
        assert!(db.scan(b"xxMZ evilfn").is_none());
    }
}
