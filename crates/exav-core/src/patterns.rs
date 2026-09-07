//! Literal byte-pattern matching via a single streaming Aho-Corasick
//! automaton (all patterns matched in one pass, any file size).

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};
use serde::{Deserialize, Serialize};

use crate::hexsig::{parse_ndb_body, NdbPattern};

/// A named literal byte pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub name: String,
    pub bytes: Vec<u8>,
    /// Whether this pattern came from an unofficial (non-`.cvd`) database. The
    /// clean name is stored; the `.UNOFFICIAL` suffix is applied at report time
    /// (compat mode). Defaults to `false` so older databases load as official.
    #[serde(default)]
    pub unofficial: bool,
}

impl Pattern {
    /// A new official (non-suffixed) pattern.
    pub fn new(name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            bytes: bytes.into(),
            unofficial: false,
        }
    }

    /// A new pattern carrying explicit `unofficial` provenance.
    pub fn with_prov(name: impl Into<String>, bytes: impl Into<Vec<u8>>, unofficial: bool) -> Self {
        Self {
            name: name.into(),
            bytes: bytes.into(),
            unofficial,
        }
    }
}

/// Whether an `.ndb` signature's `Target`/`Offset` columns make it safe to add
/// to the streaming literal set — i.e. it is valid at any offset in any file
/// type. Only `Target:0` (any type) combined with `Offset:*` (any offset)
/// qualifies; anything else carries a constraint the constraint-free streaming
/// matcher cannot honor. Blank columns (malformed line) are treated as
/// constrained (excluded) so uncertainty never widens the match.
fn stream_safe(target: &str, offset: &str) -> bool {
    target.trim() == "0" && offset.trim() == "*"
}

/// A set of literal patterns for the streaming path. The Aho-Corasick
/// automaton is built lazily on first use: in-memory (file) scans go through
/// the full engine, which already covers these literals, so only stdin/pipe
/// scans pay the (one-time) construction — keeping cold start cheap.
pub struct PatternSet {
    ac: OnceLock<AhoCorasick>,
    /// The source patterns; the automaton is (re)built from these on demand.
    pub(crate) src: Vec<Pattern>,
    /// Number of source signatures skipped, e.g. wildcard `.ndb` bodies.
    /// How many `.ndb` lines the STREAMING set could not carry. Most are
    /// wildcard bodies, which the full buffered engine loads and matches
    /// perfectly well — so this is streaming-set bookkeeping, **not** a
    /// coverage gap, and must not be reported to users as skipped signatures.
    /// See `Db::unsupported_count`.
    pub unsupported: usize,
}

/// The EICAR anti-virus test string, assembled at runtime.
///
/// Re-exported rather than redefined so the sequence has exactly one home in the
/// workspace — see [`exav_unpack::eicar`] for why it is never stored as a
/// literal.
pub use exav_unpack::eicar;

impl PatternSet {
    /// Build from literal patterns. `unsupported` records how many source
    /// signatures could not be represented (e.g. wildcard `.ndb` sigs). The
    /// automaton itself is constructed lazily (see `PatternSet::ac`).
    pub fn build(patterns: &[Pattern], unsupported: usize) -> Result<Self, String> {
        Ok(Self {
            ac: OnceLock::new(),
            src: patterns.to_vec(),
            unsupported,
        })
    }

    /// The streaming automaton, built on first use (Standard match kind is
    /// required for streaming search; detection only needs presence).
    pub(crate) fn ac(&self) -> &AhoCorasick {
        self.ac.get_or_init(|| {
            let raw: Vec<&[u8]> = self.src.iter().map(|p| p.bytes.as_slice()).collect();
            AhoCorasick::builder()
                .match_kind(MatchKind::Standard)
                .build(&raw)
                .expect("streaming pattern automaton builds")
        })
    }

    /// `(clean_name, unofficial)` for a pattern index — the report layer applies
    /// the `.UNOFFICIAL` suffix in compat mode.
    pub(crate) fn name_prov(&self, i: usize) -> (&str, bool) {
        (&self.src[i].name, self.src[i].unofficial)
    }

    /// A set containing only the EICAR test signature.
    pub fn builtin() -> Self {
        Self::build(&[Pattern::new("Eicar-Test-Signature", eicar().to_vec())], 0)
            .expect("builtin pattern set builds")
    }

    /// Parse `.ndb` lines (`Name:Type:Offset:HexSig[:MinFL[:MaxFL]]`) into
    /// literal patterns, returning the patterns and the number of bodies
    /// skipped because they use wildcards.
    pub fn parse_ndb(text: &str) -> (Vec<Pattern>, usize) {
        Self::parse_ndb_prov(text, false)
    }

    /// As [`PatternSet::parse_ndb`], tagging each parsed literal with `unofficial`
    /// provenance (set for `.ndb` files from a non-`.cvd` database).
    pub fn parse_ndb_prov(text: &str, unofficial: bool) -> (Vec<Pattern>, usize) {
        let mut patterns = Vec::new();
        let mut unsupported = 0usize;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(4, ':');
            let name = parts.next().unwrap_or("");
            let target = parts.next().unwrap_or("");
            let offset = parts.next().unwrap_or("");
            let body = match parts.next() {
                Some(b) => b,
                None => {
                    unsupported += 1;
                    continue;
                }
            };
            // The streaming literal set matches over raw, unbuffered bytes where
            // no PE layout and no per-buffer file type exist, so it may only
            // carry signatures that are valid *anywhere, in any file type*:
            // `Target:0` (any) with `Offset:*` (any). A type- or offset-
            // constrained signature — e.g. a short pattern pinned to a PE entry
            // point (`1:EP+0,64:5746c3`) — would false-positive if matched
            // unanchored here, since the constraint can't be checked. Such sigs
            // are still loaded and correctly enforced by the full (buffered)
            // engine, so they are simply excluded from the streaming set rather
            // than counted unsupported.
            if !stream_safe(target, offset) {
                continue;
            }
            match parse_ndb_body(body) {
                NdbPattern::Literal(bytes) if !bytes.is_empty() => {
                    patterns.push(Pattern::with_prov(name, bytes, unofficial));
                }
                _ => unsupported += 1,
            }
        }
        (patterns, unsupported)
    }

    /// Parse a minimal `Name=HEX` database (exav's own simple format).
    pub fn parse_simple(text: &str) -> Result<Vec<Pattern>, String> {
        let mut patterns = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, hex) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: expected Name=HEX", i + 1))?;
            let bytes =
                crate::hexsig::decode_hex(hex).map_err(|e| format!("line {}: {e}", i + 1))?;
            patterns.push(Pattern::new(name.trim(), bytes));
        }
        Ok(patterns)
    }

    /// Convenience: build a set directly from `.ndb` text.
    pub fn from_ndb(text: &str) -> Result<Self, String> {
        let (patterns, unsupported) = Self::parse_ndb(text);
        if patterns.is_empty() {
            return Err(format!(
                "no literal .ndb patterns (skipped {unsupported} unsupported)"
            ));
        }
        Self::build(&patterns, unsupported)
    }

    /// Convenience: build a set directly from `Name=HEX` text.
    pub fn from_simple_db(text: &str) -> Result<Self, String> {
        let patterns = Self::parse_simple(text)?;
        if patterns.is_empty() {
            return Err("no patterns".into());
        }
        Self::build(&patterns, 0)
    }

    pub fn len(&self) -> usize {
        self.src.len()
    }

    pub fn is_empty(&self) -> bool {
        self.src.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndb_loads_literals_and_counts_wildcards() {
        let db = "Sig.A:0:*:deadbeef\nSig.B:0:*:dead*beef\nSig.C:0:*:cafe\n";
        let set = PatternSet::from_ndb(db).unwrap();
        assert_eq!(set.len(), 2); // A and C literal; B wildcard skipped
        assert_eq!(set.unsupported, 1);
    }

    #[test]
    fn stream_set_excludes_constrained_sigs() {
        // Regression: the streaming literal set matches over raw bytes with no
        // file-type/offset context, so a `Target`- or `Offset`-constrained sig
        // (e.g. the real `Win.Spyware.Zbot-1290:1:EP+0,64:5746c3` — a 3-byte
        // pattern pinned to a PE entry point) must NOT enter it, or it
        // false-positives unanchored on any file that happens to contain those
        // bytes. Only `Target:0` + `Offset:*` (valid anywhere) qualifies.
        let db = concat!(
            "Generic.Any:0:*:deadbeef\n",       // kept: any type, any offset
            "Pe.Ep.Short:1:EP+0,64:5746c3\n",   // dropped: PE-only, entry-point
            "Any.AtOffset:0:512:cafebabe\n",    // dropped: absolute offset
            "Elf.Anywhere:6:*:0badf00d\n",      // dropped: ELF target only
        );
        let (patterns, _unsupported) = PatternSet::parse_ndb(db);
        let names: Vec<&str> = patterns.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["Generic.Any"], "only the unconstrained sig is stream-safe");
    }

    #[test]
    fn stream_safe_predicate() {
        assert!(stream_safe("0", "*"));
        assert!(!stream_safe("1", "*")); // PE target
        assert!(!stream_safe("0", "EP+0")); // entry-point anchored
        assert!(!stream_safe("0", "0")); // absolute offset 0
        assert!(!stream_safe("", "")); // malformed → treated as constrained
    }
}

