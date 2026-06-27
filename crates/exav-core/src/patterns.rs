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
    /// (compat mode). Defaults to `false` so older caches load as official.
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

/// A set of literal patterns for the streaming path. The Aho-Corasick
/// automaton is built lazily on first use: in-memory (file) scans go through
/// the full engine, which already covers these literals, so only stdin/pipe
/// scans pay the (one-time) construction — keeping cold start cheap.
pub struct PatternSet {
    ac: OnceLock<AhoCorasick>,
    /// The source patterns; the automaton is (re)built from these on demand.
    pub(crate) src: Vec<Pattern>,
    /// Number of source signatures skipped, e.g. wildcard `.ndb` bodies.
    pub unsupported: usize,
}

/// EICAR anti-virus test string.
pub const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

impl PatternSet {
    /// Build from literal patterns. `unsupported` records how many source
    /// signatures could not be represented (e.g. wildcard `.ndb` sigs). The
    /// automaton itself is constructed lazily (see [`PatternSet::ac`]).
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
        Self::build(&[Pattern::new("Eicar-Test-Signature", EICAR)], 0)
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
            let _type = parts.next();
            let _offset = parts.next();
            let body = match parts.next() {
                Some(b) => b,
                None => {
                    unsupported += 1;
                    continue;
                }
            };
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
}
