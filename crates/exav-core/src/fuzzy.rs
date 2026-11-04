//! Fuzzy / similarity hashing for variant detection:
//!  * **imp**: exact md5 of the PE import table, made as clamscan makes it,
//!    for `.imp` signatures.
//!  * **imphash**: exact md5 of the PE import table, made as `pe.imphash()`
//!    makes it (the usual import hash, pefile's, VirusTotal's), for the
//!    `imphash:` lines of a `.fdb` file. It is not the hash `.imp` signatures
//!    carry: the two differ for C++ names, a library such as `lua5.1.dll`, and
//!    others.
//!  * **TLSH**: locality-sensitive whole-file hash; matched by distance,
//!    so near-variants of a known-bad sample are caught.

use std::collections::HashMap;
use std::str::FromStr;

use tlsh2::{Tlsh, TlshDefaultBuilder};

/// The concrete Tlsh type produced by [`TlshDefaultBuilder`] (128/1).
type DefaultTlsh = Tlsh<1, 72, 32>;

/// Serializable form of a [`FuzzyDb`] (TLSH digests as hex strings).
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct FuzzyCache {
    imp_any: HashMap<String, String>,
    imp_sized: Vec<(String, u64, String)>,
    tlsh: Vec<(String, String, i32)>,
    imphash: HashMap<String, String>,
}

/// A database of fuzzy signatures.
#[derive(Default)]
pub struct FuzzyDb {
    /// clamscan import hash hex -> signature name, for `.imp` signatures of
    /// any size (`*`).
    imp_any: HashMap<String, String>,
    /// `(clamscan import hash hex, length of the hashed string) -> name` for
    /// `.imp` signatures, which constrain the match to that length.
    imp_sized: HashMap<(String, u64), String>,
    /// `pe.imphash()` hex -> signature name, for the `imphash:HEX:Name` lines
    /// of a `.fdb` file.
    imphash: HashMap<String, String>,
    /// (parsed TLSH, name, max distance) for distance matching.
    tlsh: Vec<(DefaultTlsh, String, i32)>,
}

impl FuzzyDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.imp_any.len() + self.imp_sized.len() + self.imphash.len() + self.tlsh.len()
    }

    /// Parse `.imp` PE import-table-hash signatures:
    /// `PEImportTableHash:PEImportTableSize:MalwareName`. The size is the
    /// length in bytes of the string the hash is of, which `clamscan --debug`
    /// prints with the hash (`IMP: <hash>:<size>`), or `*` for any. Format is
    /// otherwise HDB-like.
    /// Returns how many lines did not parse.
    pub fn extend_imp(&mut self, text: &str) -> usize {
        let mut skipped = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut p = line.split(':');
            let (Some(h), Some(sz), Some(name)) = (p.next(), p.next(), p.next()) else {
                skipped += 1;
                continue;
            };
            let h = h.trim().to_ascii_lowercase();
            let sz = sz.trim();
            if sz == "*" {
                self.imp_any.insert(h, name.to_string());
            } else if let Ok(n) = sz.parse::<u64>() {
                self.imp_sized.insert((h, n), name.to_string());
            } else {
                skipped += 1;
            }
        }
        skipped
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether any `.imp` signature is loaded.
    pub(crate) fn has_imp(&self) -> bool {
        !self.imp_any.is_empty() || !self.imp_sized.is_empty()
    }

    /// Whether any `imphash:` line is loaded.
    pub(crate) fn has_pe_imphash(&self) -> bool {
        !self.imphash.is_empty()
    }

    /// Parse a fuzzy-signature file. One entry per line:
    ///   `imphash:HEX:Name`
    ///   `tlsh:HASH:Name[:MaxDistance]`   (default distance 100)
    /// `#` comments and blank lines ignored. Returns how many other lines
    /// did not parse.
    pub fn extend_from_text(&mut self, text: &str) -> usize {
        let mut skipped = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split(':');
            let added = match parts.next() {
                Some("imphash") => match (parts.next(), parts.next()) {
                    (Some(h), Some(name)) => {
                        self.imphash
                            .insert(h.trim().to_ascii_lowercase(), name.to_string());
                        true
                    }
                    _ => false,
                },
                Some("tlsh") => match (parts.next(), parts.next()) {
                    (Some(h), Some(name)) => {
                        let dist = parts.next().and_then(|d| d.parse().ok()).unwrap_or(100);
                        DefaultTlsh::from_str(h.trim())
                            .map(|t| self.tlsh.push((t, name.to_string(), dist)))
                            .is_ok()
                    }
                    _ => false,
                },
                _ => false,
            };
            skipped += usize::from(!added);
        }
        skipped
    }

    /// Decompose into serializable parts for the on-disk database. TLSH digests
    /// are stored by their hex string (the parsed form isn't serializable) and
    /// re-parsed on load.
    pub(crate) fn to_cache(&self) -> FuzzyCache {
        FuzzyCache {
            imp_any: self.imp_any.clone(),
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

    /// Rebuild from the stored parts.
    pub(crate) fn from_cache(c: FuzzyCache) -> Self {
        let mut tlsh = Vec::with_capacity(c.tlsh.len());
        for (hex, name, dist) in c.tlsh {
            if let Ok(t) = DefaultTlsh::from_str(&hex) {
                tlsh.push((t, name, dist));
            }
        }
        Self {
            imp_any: c.imp_any,
            imphash: c.imphash,
            imp_sized: c
                .imp_sized
                .into_iter()
                .map(|(h, n, name)| ((h, n), name))
                .collect(),
            tlsh,
        }
    }

    /// `.imp` lookup: an exact `(hash, hashed_len)` match first, then a
    /// size-agnostic match. `imp` is the import hash as clamscan makes it, and
    /// `hashed_len` the length in bytes of the string it is the MD5 of.
    pub fn match_imp(&self, imp: &str, hashed_len: u64) -> Option<String> {
        if imp.is_empty() {
            return None;
        }
        if let Some(n) = self.imp_sized.get(&(imp.to_string(), hashed_len)) {
            return Some(n.clone());
        }
        self.imp_any.get(imp).cloned()
    }

    /// `imphash:` lookup of the import hash `pe.imphash()` gives.
    pub fn match_pe_imphash(&self, imphash: &str) -> Option<String> {
        if imphash.is_empty() {
            return None;
        }
        self.imphash.get(imphash).cloned()
    }

    /// Distance-based TLSH match; returns the closest signature within its
    /// configured threshold.
    pub fn match_tlsh(&self, data: &[u8]) -> Option<String> {
        self.match_tlsh_source(&data)
    }

    /// As [`Self::match_tlsh`], over an object that need not be held in memory.
    pub(crate) fn match_tlsh_source(&self, data: &dyn crate::byte_source::ByteSource) -> Option<String> {
        if self.tlsh.is_empty() {
            return None;
        }
        let mut b = TlshDefaultBuilder::new();
        data.chunks(0, data.len(), &mut |_, piece| {
            b.update(piece);
            true
        });
        let sample = b.build()?;
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
        assert_eq!(db.match_pe_imphash("abc123").as_deref(), Some("Family.A"));
        assert!(db.match_pe_imphash("def456").is_none());
        assert!(db.match_pe_imphash("").is_none());
    }

    #[test]
    fn imp_size_constrained() {
        // `.imp`: HASH:SIZE:Name, SIZE the length of the string the hash is of.
        let mut db = FuzzyDb::new();
        db.extend_imp("98c88d882f01a3f6ac1e5f7dfd761624:2020:Win.Trojan.X\n");
        db.extend_imp("aabbcc:*:Win.AnySize\n");
        assert_eq!(
            db.match_imp("98c88d882f01a3f6ac1e5f7dfd761624", 2020)
                .as_deref(),
            Some("Win.Trojan.X")
        );
        // Same hash, another length -> no sized match.
        assert!(db
            .match_imp("98c88d882f01a3f6ac1e5f7dfd761624", 2021)
            .is_none());
        // `*` size matches any length.
        assert_eq!(db.match_imp("aabbcc", 7).as_deref(), Some("Win.AnySize"));
    }

    /// A line of an `.imp` file whose size is not a number is skipped, and the
    /// lines around it load, as a line of a hash database (`.hdb`) with the
    /// same fault is: the two share their line shape and, with it, how a
    /// malformed line is treated. clamscan refuses the whole file for it.
    #[test]
    fn a_malformed_imp_line_is_skipped_as_a_malformed_hash_line_is() {
        let hash = "a".repeat(32);
        for (size, loads) in [
            ("78", true),
            ("0", true),
            ("+78", true),
            (" 78 ", true),
            ("*", true),
            ("4294967374", true),
            ("-1", false),
            ("abc", false),
            ("", false),
            ("0x4e", false),
            ("7 8", false),
        ] {
            let text = format!("{hash}:{size}:Name\n");
            let mut imp = FuzzyDb::new();
            imp.extend_imp(&format!("{}:1:Before\n{text}{}:2:After\n", "b".repeat(32), "c".repeat(32)));
            let mut hdb = crate::hashes::HashDb::new();
            hdb.extend_from_text(&format!("{}:1:Before\n{text}{}:2:After\n", "b".repeat(32), "c".repeat(32)));
            let expect = 2 + usize::from(loads);
            assert_eq!(imp.len(), expect, "size {size:?} in an .imp file");
            assert_eq!(hdb.len(), expect, "size {size:?} in an .hdb file");
        }
        // A line with no name is skipped (an `.hdb` line is named `Unnamed`).
        let mut imp = FuzzyDb::new();
        imp.extend_imp(&format!("{hash}\n{hash}:5\n"));
        assert_eq!(imp.len(), 0);
    }

    /// The two kinds of import hash are matched apart: an `imphash:` line does
    /// not match the hash clamscan makes, and an `.imp` signature does not
    /// match the usual one. They survive the database file.
    #[test]
    fn imp_signatures_and_imphash_lines_are_matched_apart() {
        let mut db = FuzzyDb::new();
        db.extend_imp("aaaa:*:FromImp\nbbbb:7:SizedImp\n");
        db.extend_from_text("imphash:cccc:FromFdb\n");
        assert!(db.has_imp() && db.has_pe_imphash());
        assert_eq!(db.len(), 3);
        for db in [&db, &FuzzyDb::from_cache(db.to_cache())] {
            assert_eq!(db.match_imp("aaaa", 1).as_deref(), Some("FromImp"));
            assert_eq!(db.match_imp("bbbb", 7).as_deref(), Some("SizedImp"));
            assert!(db.match_imp("cccc", 1).is_none());
            assert_eq!(db.match_pe_imphash("cccc").as_deref(), Some("FromFdb"));
            assert!(db.match_pe_imphash("aaaa").is_none());
            assert!(db.match_pe_imphash("bbbb").is_none());
        }
        let mut only_imp = FuzzyDb::new();
        only_imp.extend_imp("aaaa:*:FromImp\n");
        assert!(only_imp.has_imp() && !only_imp.has_pe_imphash());
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

    #[test]
    fn a_digest_fed_in_chunks_is_the_one_made_whole() {
        use crate::byte_source::{BlockCache, CHUNK};
        let data: Vec<u8> = (0..5 * CHUNK + 77).map(|i| ((i * 31 % 251) ^ (i / 97)) as u8).collect();
        let h = tlsh_string(&data).expect("tlsh");
        let mut db = FuzzyDb::new();
        db.extend_from_text(&format!("tlsh:{h}:Family.C:0\n"));
        let cache = BlockCache::with_sizes(std::io::Cursor::new(data), 509, 4096).unwrap();
        // Distance 0 only: the chunked digest must be exactly the whole one.
        assert_eq!(db.match_tlsh_source(&cache).as_deref(), Some("Family.C"));
    }
}
