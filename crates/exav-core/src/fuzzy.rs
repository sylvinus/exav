//! Fuzzy / similarity hashing for variant detection:
//!  * **imphash** — exact md5 of the PE import table; clusters samples that
//!    share imports. Matched by exact lookup.
//!  * **TLSH** — locality-sensitive whole-file hash; matched by distance,
//!    so near-variants of a known-bad sample are caught.

use std::collections::HashMap;
use std::str::FromStr;

use tlsh2::{Tlsh, TlshDefaultBuilder};

/// The concrete Tlsh type produced by [`TlshDefaultBuilder`] (128/1).
type DefaultTlsh = Tlsh<1, 72, 32>;

/// Serializable form of a [`FuzzyDb`] (TLSH digests as hex strings).
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct FuzzyCache {
    imphash: HashMap<String, String>,
    imp_sized: Vec<(String, u64, String)>,
    tlsh: Vec<(String, String, i32)>,
}

/// A database of fuzzy signatures.
#[derive(Default)]
pub struct FuzzyDb {
    /// imphash hex -> signature name, size-agnostic (the `*` size / our own
    /// `imphash:HEX:Name` format).
    imphash: HashMap<String, String>,
    /// `(imphash hex, import count) -> name` for `.imp` signatures,
    /// which constrain the match to an exact import count.
    imp_sized: HashMap<(String, u64), String>,
    /// (parsed TLSH, name, max distance) for distance matching.
    tlsh: Vec<(DefaultTlsh, String, i32)>,
}

impl FuzzyDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.imphash.len() + self.imp_sized.len() + self.tlsh.len()
    }

    /// Parse `.imp` PE import-table-hash signatures:
    /// `PEImportTableHash:PEImportTableSize:MalwareName` (size is the import
    /// count, or `*` for any). Format is otherwise HDB-like.
    pub fn extend_imp(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut p = line.split(':');
            if let (Some(h), Some(sz), Some(name)) = (p.next(), p.next(), p.next()) {
                let h = h.trim().to_ascii_lowercase();
                let sz = sz.trim();
                if sz == "*" {
                    self.imphash.insert(h, name.to_string());
                } else if let Ok(n) = sz.parse::<u64>() {
                    self.imp_sized.insert((h, n), name.to_string());
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Parse a fuzzy-signature file. One entry per line:
    ///   `imphash:HEX:Name`
    ///   `tlsh:HASH:Name[:MaxDistance]`   (default distance 100)
    /// `#` comments and blank lines ignored.
    pub fn extend_from_text(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split(':');
            match parts.next() {
                Some("imphash") => {
                    if let (Some(h), Some(name)) = (parts.next(), parts.next()) {
                        self.imphash
                            .insert(h.trim().to_ascii_lowercase(), name.to_string());
                    }
                }
                Some("tlsh") => {
                    if let (Some(h), Some(name)) = (parts.next(), parts.next()) {
                        let dist = parts.next().and_then(|d| d.parse().ok()).unwrap_or(100);
                        if let Ok(t) = DefaultTlsh::from_str(h.trim()) {
                            self.tlsh.push((t, name.to_string(), dist));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Decompose into serializable parts for the on-disk cache. TLSH digests
    /// are stored by their hex string (the parsed form isn't serializable) and
    /// re-parsed on load.
    pub(crate) fn to_cache(&self) -> FuzzyCache {
        FuzzyCache {
            imphash: self.imphash.clone(),
            imp_sized: self
                .imp_sized
                .iter()
                .map(|((h, n), name)| (h.clone(), *n, name.clone()))
                .collect(),
            tlsh: self
                .tlsh
                .iter()
                .map(|(t, n, d)| {
                    (
                        String::from_utf8_lossy(&t.hash()).into_owned(),
                        n.clone(),
                        *d,
                    )
                })
                .collect(),
        }
    }

    /// Rebuild from cached parts.
    pub(crate) fn from_cache(c: FuzzyCache) -> Self {
        let mut tlsh = Vec::with_capacity(c.tlsh.len());
        for (hex, name, dist) in c.tlsh {
            if let Ok(t) = DefaultTlsh::from_str(&hex) {
                tlsh.push((t, name, dist));
            }
        }
        Self {
            imphash: c.imphash,
            imp_sized: c
                .imp_sized
                .into_iter()
                .map(|(h, n, name)| ((h, n), name))
                .collect(),
            tlsh,
        }
    }

    /// imphash lookup: an exact `(hash, import_count)` `.imp` match first, then
    /// a size-agnostic match.
    pub fn match_imphash(&self, imphash: &str, import_count: u64) -> Option<String> {
        if imphash.is_empty() {
            return None;
        }
        if let Some(n) = self.imp_sized.get(&(imphash.to_string(), import_count)) {
            return Some(n.clone());
        }
        self.imphash.get(imphash).cloned()
    }

    /// Distance-based TLSH match; returns the closest signature within its
    /// configured threshold.
    pub fn match_tlsh(&self, data: &[u8]) -> Option<String> {
        if self.tlsh.is_empty() {
            return None;
        }
        let sample = tlsh_of(data)?;
        let mut best: Option<(i32, &str)> = None;
        for (t, name, max) in &self.tlsh {
            let d = sample.diff(t, true);
            if d <= *max && best.map(|(bd, _)| d < bd).unwrap_or(true) {
                best = Some((d, name));
            }
        }
        best.map(|(_, n)| n.to_string())
    }
}

/// Compute a TLSH for a buffer. Returns `None` if the input is too small
/// or too uniform for TLSH to produce a digest (it needs ~50+ bytes).
pub fn tlsh_of(data: &[u8]) -> Option<DefaultTlsh> {
    let mut b = TlshDefaultBuilder::new();
    b.update(data);
    b.build()
}

/// TLSH digest as a hex string (for storing in a fuzzy DB), or `None`.
pub fn tlsh_string(data: &[u8]) -> Option<String> {
    tlsh_of(data).map(|t| String::from_utf8_lossy(&t.hash()).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seed: u8) -> Vec<u8> {
        // Deterministic pseudo-random-ish content large enough for TLSH.
        (0..2048u32)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn imphash_exact_match() {
        let mut db = FuzzyDb::new();
        db.extend_from_text("imphash:abc123:Family.A\n");
        assert_eq!(db.match_imphash("abc123", 0).as_deref(), Some("Family.A"));
        assert!(db.match_imphash("def456", 0).is_none());
        assert!(db.match_imphash("", 0).is_none());
    }

    #[test]
    fn imp_size_constrained() {
        // `.imp`: HASH:IMPORT_COUNT:Name — count must match.
        let mut db = FuzzyDb::new();
        db.extend_imp("98c88d882f01a3f6ac1e5f7dfd761624:39:Win.Trojan.X\n");
        db.extend_imp("aabbcc:*:Win.AnyCount\n");
        assert_eq!(
            db.match_imphash("98c88d882f01a3f6ac1e5f7dfd761624", 39)
                .as_deref(),
            Some("Win.Trojan.X")
        );
        // Same hash, wrong import count -> no sized match.
        assert!(db
            .match_imphash("98c88d882f01a3f6ac1e5f7dfd761624", 40)
            .is_none());
        // `*` size matches any count.
        assert_eq!(
            db.match_imphash("aabbcc", 7).as_deref(),
            Some("Win.AnyCount")
        );
    }

    #[test]
    fn tlsh_self_distance_is_zero() {
        let data = sample(0);
        let h = tlsh_string(&data).expect("tlsh for 2KB buffer");
        let mut db = FuzzyDb::new();
        db.extend_from_text(&format!("tlsh:{h}:Family.B:10\n"));
        // identical content -> distance 0 -> matches
        assert_eq!(db.match_tlsh(&data).as_deref(), Some("Family.B"));
    }
}
