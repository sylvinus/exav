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

/// The data fields are always present (so the on-disk cache format is identical
/// whether or not the `yara` feature is built), but the actual yara-x
/// compilation/matching is gated on the feature. Without it, rule sources are
/// still stored (a cache built with yara can be loaded without it and vice
/// versa) — they're simply never matched.
#[derive(Default, Serialize, Deserialize)]
pub struct YaraDb {
    /// Accumulated rule sources (one per loaded `.yar`/`.yara` file).
    sources: Vec<String>,
    /// Whether any loaded rule file came from an unofficial database. ClamAV
    /// suffixes such detections with `.UNOFFICIAL`. YARA rules are essentially
    /// always unofficial (official `.cvd`s ship none).
    #[serde(default)]
    unofficial: bool,
    /// Serialized compiled rules (`yara_x::Rules::serialize`), produced once at
    /// cache-build time by [`Self::finalize`]. yara-x compilation of a large
    /// ruleset is slow (seconds for a few thousand rules); caching the compiled
    /// form means loading a prebuilt cache deserializes them instead of
    /// recompiling on the first scan. Empty until finalized.
    #[serde(default)]
    compiled_bytes: Option<Vec<u8>>,
    /// In-memory compiled rules, restored once from `compiled_bytes` (fast) or,
    /// failing that, compiled from `sources`. `None` if there are no rules or
    /// compilation failed.
    #[cfg(feature = "yara")]
    #[serde(skip)]
    compiled: std::sync::OnceLock<Option<yara_x::Rules>>,
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
    /// Add one rule file's source text. `unofficial` marks rules loaded from a
    /// non-`.cvd` database (the usual case), so matches carry `.UNOFFICIAL`.
    pub fn extend_from_text(&mut self, text: &str, unofficial: bool) {
        self.sources.push(text.to_string());
        self.unofficial |= unofficial;
    }

    /// Compile the accumulated rule sources once and keep the serialized result,
    /// so a cache built from this database loads without recompiling. Called at
    /// build time. Idempotent; a compile failure leaves `sources` as the
    /// fallback.
    pub fn finalize(&mut self) {
        #[cfg(feature = "yara")]
        {
            if self.compiled_bytes.is_some() || self.sources.is_empty() {
                return;
            }
            let mut c = yara_x::Compiler::new();
            for src in &self.sources {
                let _ = c.add_source(src.as_str());
            }
            if let Ok(bytes) = c.build().serialize() {
                self.compiled_bytes = Some(bytes);
            }
        }
    }

    #[cfg(feature = "yara")]
    fn rules(&self) -> Option<&yara_x::Rules> {
        self.compiled
            .get_or_init(|| {
                // Prefer the precompiled form (fast); fall back to compiling the
                // sources (e.g. a cache built before this field existed).
                if let Some(bytes) = &self.compiled_bytes {
                    return yara_x::Rules::deserialize(bytes).ok();
                }
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

    /// Scan `data`; return the name of the first matching rule, formatted as
    /// ClamAV reports YARA detections: a `YARA.` prefix and, for rules from an
    /// unofficial database, a `.UNOFFICIAL` suffix.
    #[cfg(feature = "yara")]
    pub fn scan(&self, data: &[u8]) -> Option<String> {
        let rules = self.rules()?;
        let mut scanner = yara_x::Scanner::new(rules);
        let results = scanner.scan(data).ok()?;
        let id = results.matching_rules().next()?.identifier().to_string();
        let suffix = if self.unofficial { ".UNOFFICIAL" } else { "" };
        Some(format!("YARA.{id}{suffix}"))
    }

    /// Built without the `yara` feature: rules are stored but never matched.
    #[cfg(not(feature = "yara"))]
    pub fn scan(&self, _data: &[u8]) -> Option<String> {
        None
    }
}

#[cfg(all(test, feature = "yara"))]
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
            true, // unofficial -> YARA.<id>.UNOFFICIAL
        );
        assert_eq!(db.len(), 1);
        assert_eq!(
            db.scan(b"....UNIQUE_EXAV_YARA_MARKER....").as_deref(),
            Some("YARA.evil_marker.UNOFFICIAL")
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
            false, // official -> YARA. prefix only, no .UNOFFICIAL
        );
        assert_eq!(
            db.scan(b"MZ\x90\x00 ... evilfn ...").as_deref(),
            Some("YARA.pe_with_two")
        );
        assert!(db.scan(b"xxMZ evilfn").is_none());
    }
}
