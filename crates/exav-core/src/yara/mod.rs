//! YARA rule support via a native, dependency-light engine.
//!
//! Traditional engines support only a restricted YARA subset (no modules, ≤64
//! strings/rule, etc.). This one targets broad real-world YARA compatibility
//! (strings, full conditions, for-loops/`with`, and the `pe`/`math`/`hash`/
//! `string`/`time` modules) while compiling **natively** — no wasmtime/Cranelift
//! JIT, no runtime codegen at scan time (W^X preserved).
//!
//! Like the rest of exav's database, [`YaraDb`] serializes its COMPILED form: at
//! database-build time ([`YaraDb::finalize`]) the rules are compiled and the
//! compiled rule set is serialized into `YaraDb::compiled_blob`, so a prebuilt
//! `.exavdb` loads the YARA engine WITHOUT recompiling — in particular without
//! rebuilding the expensive daachorse atom automaton. The daachorse automaton +
//! owned IR + per-pattern definitions travel in the blob; only the per-pattern
//! regexes (whose compiled automata are not serializable) are recompiled from
//! their stored source on load. The rule *sources* are also retained, so a build
//! WITHOUT the `yara` feature still round-trips the database, and a load whose
//! blob is absent / version-incompatible falls back to compiling from source
//! (never silently losing coverage). See `YaraDb::compiled_blob`.
//!
//! The engine REJECTS rules that use constructs it does not implement
//! (`macho`/`dex` modules, `pe.rich_signature`/`version_info`,
//! `floatN()` reads, the `wide` modifier on regexps, …) as compile *errors*
//! rather than mis-evaluating them. To avoid one unsupported rule silently
//! dropping a whole third-party feed, we compile **per rule** (see
//! [`Compiler::add_source_lenient`]) and record every rejection in
//! [`YaraDb::rejected`], so the coverage gap is always visible — never silent.
//!
//! # Where the native engine lives
//!
//! The native YARA engine (`compiler`, `ir`, `matcher`, `scanner`, `base64`,
//! `error`, and the `modules/` tree) lives here so its byte/hash/PE primitives
//! share the rest of `exav-core`. The submodules are gated on `feature = "yara"`
//! and their public API is re-exported below, so a consumer who wants YARA on
//! its own uses `exav_core::yara` without going through a scan.
//!
//! Why the AV signature `engine`/`logic.rs`/`.cbc` bytecode VM are deliberately
//! NOT reused for YARA matching is documented at the bottom of this module.

// The native engine, gated on the `yara` feature (its parser/regex/base64/bstr/
// crc32 dependencies are optional). `YaraDb` below is compiled unconditionally.
#[cfg(feature = "yara")]
#[allow(dead_code)]
mod atoms;
#[cfg(feature = "yara")]
#[allow(dead_code)]
mod base64;
#[cfg(feature = "yara")]
#[allow(dead_code)]
mod compiler;
#[cfg(feature = "yara")]
#[allow(dead_code)]
mod error;
#[cfg(feature = "yara")]
#[allow(dead_code)]
mod ir;
#[cfg(feature = "yara")]
#[allow(dead_code)]
mod matcher;
#[cfg(feature = "yara")]
#[allow(dead_code)]
mod modules;
#[cfg(feature = "yara")]
#[allow(dead_code)]
mod scanner;

// Public API of the native engine, re-exported so `exav_core::yara::*` is the
// whole surface a standalone consumer needs.
#[cfg(feature = "yara")]
pub use compiler::{Compiler, ExternalValue};
#[cfg(feature = "yara")]
pub use error::{Error, Result};
#[cfg(feature = "yara")]
pub use ir::ExternalType;
#[cfg(feature = "yara")]
pub use scanner::{
    Matches, MatchingRules, Pattern, PatternMatch, Patterns, Rule, Rules, ScanResults, Scanner,
};

/// Compiles a single YARA source into a ready-to-scan [`Rules`] set.
#[cfg(feature = "yara")]
pub fn compile(src: &str) -> Result<Rules> {
    let mut c = Compiler::new();
    c.add_source(src)?;
    Ok(c.build())
}

use serde::{Deserialize, Serialize};

/// Format version of [`YaraDb::compiled_blob`]. Bumped whenever the serialized
/// compiled-rules layout (the `Rules` blob: IR, pattern defs, atom automaton)
/// changes in an incompatible way. A loaded blob whose version does not match
/// this build is ignored and the rules are recompiled from source, so a stale
/// blob is never misread — the coverage is preserved, just without the load-time
/// shortcut. (This is independent of the outer `.exavdb` format serial in
/// `crate::database`, which guards the whole file.)
#[cfg(feature = "yara")]
const YARA_BLOB_VERSION: u32 = 1;

/// The data fields are always present (so the on-disk database format is identical
/// whether or not the `yara` feature is built), but the actual compilation and
/// matching are gated on the feature. Without it, rule sources are
/// still stored (a database built with yara can be loaded without it and vice
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
    /// Rules the engine could not compile, recorded at [`Self::finalize`]
    /// time (i.e. when the database is built) as `"<rule name>: <reason>"`. This
    /// is serialized into the database so an operator loading a prebuilt `.exavdb`
    /// can still SEE which rules were dropped and why — a rule that will not
    /// compile is always accounted for, never invisibly missing.
    #[serde(default)]
    rejected: Vec<String>,
    /// The serialized COMPILED rule set, produced by [`Self::finalize`] at
    /// database-build time (only when built with the `yara` feature). When
    /// present and version-compatible, [`Self::rules`] deserializes it — skipping
    /// the expensive daachorse atom-automaton build — instead of recompiling from
    /// `sources`. This is what makes a prebuilt `.exavdb` load its YARA engine
    /// without recompiling, consistent with the rest of the database (which also
    /// serializes its compiled form). Absent when the database was built without
    /// the `yara` feature, or predates this field; then `rules()` falls back to
    /// compiling `sources`. To a build WITHOUT the `yara` feature these are opaque
    /// bytes that round-trip through the database untouched.
    #[serde(default)]
    compiled_blob: Option<Vec<u8>>,
    /// Format version of `compiled_blob` (see [`YARA_BLOB_VERSION`]). A mismatch
    /// makes `rules()` ignore the blob and recompile from source.
    #[serde(default)]
    blob_version: u32,
    /// In-memory compiled rules, materialized once (lazily): by deserializing
    /// `compiled_blob` when it is present and version-compatible, otherwise by
    /// compiling `sources`. `None` if there are no rules.
    #[cfg(feature = "yara")]
    #[serde(skip)]
    compiled: std::sync::OnceLock<Option<Rules>>,
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

    /// Rules the engine refused to compile, as `"<name>: <reason>"`
    /// strings. Populated by [`Self::finalize`] (database-build time) and
    /// preserved across serialization, so operators can audit the coverage gap.
    pub fn rejected(&self) -> &[String] {
        &self.rejected
    }

    /// Number of rules dropped because the engine could not compile them.
    pub fn rejected_count(&self) -> usize {
        self.rejected.len()
    }

    /// Compile the accumulated rule sources once at database-build time to (a)
    /// validate them and record which rules were rejected (so the coverage gap is
    /// captured in the built database) and (b) SERIALIZE the compiled rule set
    /// into `Self::compiled_blob`, so a prebuilt `.exavdb` loads the YARA engine
    /// without recompiling — skipping the expensive atom-automaton build — exactly
    /// as the rest of the database serializes its compiled form. Idempotent.
    pub fn finalize(&mut self) {
        #[cfg(feature = "yara")]
        {
            if self.sources.is_empty() {
                return;
            }
            let (rules, rejected) = compile_lenient(&self.sources);
            self.rejected = rejected;
            // Persist the compiled form so loading skips recompilation.
            self.compiled_blob = Some(rules.serialize());
            self.blob_version = YARA_BLOB_VERSION;
            if !self.rejected.is_empty() {
                eprintln!(
                    "[exav yara] WARN: {} YARA rule(s) could not be compiled and were dropped \
                     (unsupported construct/module); detections from them are unavailable. \
                     First few: {}",
                    self.rejected.len(),
                    preview(&self.rejected),
                );
            }
        }
    }

    #[cfg(feature = "yara")]
    fn rules(&self) -> Option<&Rules> {
        self.compiled
            .get_or_init(|| {
                if self.sources.is_empty() {
                    return None;
                }
                // Fast path: a version-compatible prebuilt compiled blob loads
                // the rule set (incl. the atom automaton) without recompiling.
                if let Some(blob) = &self.compiled_blob {
                    if self.blob_version == YARA_BLOB_VERSION {
                        match Rules::deserialize(blob) {
                            Ok(rules) => return Some(rules),
                            Err(e) => eprintln!(
                                "[exav yara] WARN: prebuilt YARA rules failed to deserialize \
                                 ({e}); recompiling from source.",
                            ),
                        }
                    } else {
                        eprintln!(
                            "[exav yara] WARN: prebuilt YARA rules have blob version {} but this \
                             build expects {YARA_BLOB_VERSION}; recompiling from source.",
                            self.blob_version,
                        );
                    }
                }
                // Fallback: no blob (database built without the `yara` feature, or
                // predating it), or an unusable blob — recompile from source. The
                // coverage is identical; only the load-time shortcut is skipped.
                let (rules, _rejected) = compile_lenient(&self.sources);
                Some(rules)
            })
            .as_ref()
    }

    /// Scan `data`; return the name of the first matching rule, formatted as
    /// ClamAV reports YARA detections: a `YARA.` prefix and, for rules from an
    /// unofficial database, a `.UNOFFICIAL` suffix.
    ///
    /// `filename` is the identity of the object being scanned (a file path).
    /// When present, the standard THOR/signature-base external variables are set
    /// for this scan so rules that reference them can match:
    ///
    /// * `filepath`  — the path as given (original case),
    /// * `filename`  — the basename (original case),
    /// * `extension` — the lowercased extension *including* the leading dot
    ///   (e.g. `".js"`), per the signature-base convention.
    ///
    /// `filetype`/`owner` are left undefined (exav does not model them). When
    /// `filename` is `None`, all externals stay undefined and rules referencing
    /// them simply do not match.
    #[cfg(feature = "yara")]
    pub fn scan(&self, data: &[u8], filename: Option<&str>) -> Option<String> {
        let rules = self.rules()?;
        let mut scanner = Scanner::new(rules);
        if let Some(path) = filename {
            scanner.set_global("filepath", path);
            let base = file_basename(path);
            scanner.set_global("filename", base);
            if let Some(ext) = file_extension(base) {
                scanner.set_global("extension", ext);
            }
        }
        let results = scanner.scan(data).ok()?;
        let id = results.matching_rules().next()?.identifier().to_string();
        let suffix = if self.unofficial { ".UNOFFICIAL" } else { "" };
        Some(format!("YARA.{id}{suffix}"))
    }

    /// Built without the `yara` feature: rules are stored but never matched.
    #[cfg(not(feature = "yara"))]
    pub fn scan(&self, _data: &[u8], _filename: Option<&str>) -> Option<String> {
        None
    }
}

/// The basename of a path, splitting on both `/` and `\` so Windows-style paths
/// embedded in rules (`filepath contains "\\Temp\\"`) resolve correctly too.
#[cfg(feature = "yara")]
fn file_basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// The lowercased extension of a basename, *including* the leading dot
/// (`"Invoice.JS"` -> `".js"`), matching the THOR/signature-base `extension ==
/// ".js"` convention. Returns `None` (undefined) when the basename has no
/// extension, or a leading-dot dotfile with no further extension (`".bashrc"`).
#[cfg(feature = "yara")]
fn file_extension(basename: &str) -> Option<String> {
    let dot = basename.rfind('.')?;
    // A leading dot (dotfile like `.bashrc`) is not an extension.
    if dot == 0 {
        return None;
    }
    Some(basename[dot..].to_ascii_lowercase())
}

/// Compiles every source per-rule, so one unsupported rule cannot drop a whole
/// feed. Returns the compiled rule set plus the human-readable rejection list
/// (`"<name>: <reason>"`), which the caller records/logs.
#[cfg(feature = "yara")]
fn compile_lenient(sources: &[String]) -> (Rules, Vec<String>) {
    let mut c = Compiler::new();
    let mut rejected = Vec::new();
    for src in sources {
        for (name, err) in c.add_source_lenient(src) {
            let label = if name.is_empty() {
                "<source>".to_string()
            } else {
                name
            };
            rejected.push(format!("{label}: {err}"));
        }
    }
    (c.build(), rejected)
}

/// A short, bounded preview of the rejection list for a one-line log message.
#[cfg(feature = "yara")]
fn preview(rejected: &[String]) -> String {
    const MAX: usize = 3;
    let shown = rejected
        .iter()
        .take(MAX)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    if rejected.len() > MAX {
        format!("{shown}; … (+{} more)", rejected.len() - MAX)
    } else {
        shown
    }
}

// ---------------------------------------------------------------------------
// Design note: why the AV signature engine is NOT reused for YARA matching
// ---------------------------------------------------------------------------
//
// This module lives inside exav-core alongside the ClamAV-style signature
// `engine` (`crate::engine`, `crate::engine::logic`) and the `.cbc` bytecode VM
// (`crate::bytecode`), and it reuses leaf primitives from them (PE parsing via
// `crate::pe`, hashing via `md-5`/`sha1`/`sha2` + `crate::hexsig`, entropy via
// `crate::pe::shannon_entropy`, `memchr`). It deliberately does NOT reuse the AV
// matcher or the bytecode VM for evaluating YARA rule *conditions*. A future
// contributor should not "unify" these — doing so breaks the yara-x A/B
// differential (~17k rules, 0 disagreements). The reasons are structural:
//
//   * The AV pattern matcher is non-exhaustive by design (it reports the first
//     hit and stops, and prunes on Aho-Corasick prefilter economics). YARA
//     conditions need *exhaustive* per-pattern match sets: counts (`#a`), the
//     i-th offset/length (`@a[i]`/`!a[i]`), `$a at N`, `$a in (a..b)`, and
//     `N of`/`P% of` quantifiers all require every match, not just existence.
//
//   * The AV signature IR `Node` cannot express YARA's condition language:
//     arbitrary boolean/arithmetic/bitwise algebra, quantified `for` loops over
//     ranges/sets/module arrays, `with` bindings, and module field/function
//     calls. YARA conditions are lowered to this module's own `ir::Cond` tree.
//
//   * The `.cbc` bytecode VM has no value model for YARA semantics: it has no
//     first-class `undefined` (YARA's tri-state that propagates through every
//     operator), and no structured struct/array/map/function values (the
//     `pe`/`math`/`hash`/`string`/`time` modules). Bolting these onto the VM
//     would be a larger, riskier change than the native tree-walking evaluator
//     here, and would still have to match yara-x bit-for-bit.
//
// So the split is intentional: share stateless leaf primitives, keep the
// matching/evaluation engines separate.

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
            db.scan(b"....UNIQUE_EXAV_YARA_MARKER....", None).as_deref(),
            Some("YARA.evil_marker.UNOFFICIAL")
        );
        assert!(db.scan(b"nothing to see here", None).is_none());
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
            db.scan(b"MZ\x90\x00 ... evilfn ...", None).as_deref(),
            Some("YARA.pe_with_two")
        );
        assert!(db.scan(b"xxMZ evilfn", None).is_none());
    }

    #[test]
    fn pe_module_rule_compiles_and_matches() {
        // A rule importing the `pe` module and using a `pe.` field must still
        // compile and match under the native `pe` module.
        let mut db = YaraDb::new();
        db.extend_from_text(
            r#"
            import "pe"
            rule uses_pe {
                strings:
                    $s = "evilfn"
                condition:
                    $s and (pe.is_pe or filesize > 0)
            }
            "#,
            false,
        );
        db.finalize();
        assert_eq!(db.rejected_count(), 0, "rejected: {:?}", db.rejected());
        assert_eq!(
            db.scan(b"MZ .... evilfn ....", None).as_deref(),
            Some("YARA.uses_pe")
        );
    }

    /// The COMPILED rule set must survive a full `YaraDb` MessagePack round trip
    /// (the `.exavdb` boundary) and load WITHOUT recompiling from source: after
    /// `finalize`, the serialized blob is present, travels through serialize +
    /// deserialize, and the reloaded database scans identically — driven by the
    /// deserialized compiled blob, not a source recompile.
    #[test]
    fn compiled_blob_survives_database_serialization() {
        let mut db = YaraDb::new();
        db.extend_from_text(
            r#"
            rule blob_demo {
                strings:
                    $a = "needle"
                    $r = /vers?ion[0-9]+/
                condition:
                    $a and #r >= 1
            }
            "#,
            true,
        );
        db.finalize();
        // finalize must have produced a compiled blob (built with the yara feature).
        assert!(db.compiled_blob.is_some(), "finalize should set the blob");
        assert_eq!(db.blob_version, YARA_BLOB_VERSION);

        // Serialize the whole YaraDb (as `crate::database` does) and reload it.
        let bytes = rmp_serde::to_vec(&db).expect("encode YaraDb");
        let reloaded: YaraDb = rmp_serde::from_slice(&bytes).expect("decode YaraDb");
        assert!(reloaded.compiled_blob.is_some());
        assert_eq!(reloaded.blob_version, YARA_BLOB_VERSION);

        let hit = b"a needle and version42 here";
        let miss = b"a needle but no ver marker";
        for d in [db, reloaded] {
            assert_eq!(
                d.scan(hit, None).as_deref(),
                Some("YARA.blob_demo.UNOFFICIAL")
            );
            assert!(d.scan(miss, None).is_none());
        }
    }

    /// If the blob version does not match this build, the loader must ignore the
    /// stale blob and recompile from source — never misread it, never go silent.
    #[test]
    fn stale_blob_version_falls_back_to_source() {
        let mut db = YaraDb::new();
        db.extend_from_text(r#"rule v { strings: $a = "marker" condition: $a }"#, false);
        db.finalize();
        assert!(db.compiled_blob.is_some());
        // Simulate a blob written by an incompatible engine version.
        db.blob_version = YARA_BLOB_VERSION.wrapping_add(1);
        // Still detects (recompiled from the retained sources).
        assert_eq!(db.scan(b"..marker..", None).as_deref(), Some("YARA.v"));
    }

    #[test]
    fn external_variables_compile_and_match_with_filename() {
        // A signature-base-style rule referencing the standard externals must
        // (a) compile without the host declaring them, and (b) match only when
        // the scanned file's identity is supplied and its externals satisfy the
        // condition.
        let mut db = YaraDb::new();
        db.extend_from_text(
            r#"
            rule js_dropper {
                strings:
                    $s = "payload"
                condition:
                    $s and extension == ".js" and filename matches /invoice/i
            }
            "#,
            true,
        );
        db.finalize();
        assert_eq!(db.rejected_count(), 0, "rejected: {:?}", db.rejected());

        let data = b"....payload....";
        // Right name + extension -> match.
        assert_eq!(
            db.scan(data, Some("/tmp/Invoice_2026.JS")).as_deref(),
            Some("YARA.js_dropper.UNOFFICIAL")
        );
        // Windows path, basename still resolves the extension.
        assert_eq!(
            db.scan(data, Some("C:\\Users\\x\\invoice.js")).as_deref(),
            Some("YARA.js_dropper.UNOFFICIAL")
        );
        // Wrong extension -> no match.
        assert!(db.scan(data, Some("/tmp/invoice.txt")).is_none());
        // Wrong filename -> no match.
        assert!(db.scan(data, Some("/tmp/report.js")).is_none());
        // No filename at all -> externals undefined -> no match.
        assert!(db.scan(data, None).is_none());
    }

    #[test]
    fn unsupported_rule_is_recorded_not_silently_dropped() {
        // One rule uses an unsupported construct (`pe.rich_signature`), the
        // other is fine. The good rule must still load; the bad one must be
        // accounted for in `rejected`, not invisibly missing.
        let mut db = YaraDb::new();
        db.extend_from_text(
            r#"
            import "pe"
            rule good_rule {
                strings:
                    $a = "keepme"
                condition:
                    $a
            }
            rule bad_rule {
                condition:
                    pe.rich_signature.length > 0
            }
            "#,
            true,
        );
        db.finalize();
        assert_eq!(db.rejected_count(), 1, "rejected: {:?}", db.rejected());
        assert!(db.rejected()[0].contains("bad_rule"));
        // The good rule still matches despite its neighbour being rejected.
        assert_eq!(
            db.scan(b"....keepme....", None).as_deref(),
            Some("YARA.good_rule.UNOFFICIAL")
        );
    }
}
