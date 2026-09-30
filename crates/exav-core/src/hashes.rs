//! Hash signatures (`.hdb`/`.hsb`-style) and the MD5/SHA1/SHA256 digests they
//! are matched against, computed in one pass over an object of any size.

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::hexsig::{decode_hex, encode_hex};

/// Decode a hex digest into a fixed-size array, or `None` on bad length/hex.
fn hex_array<const N: usize>(hex: &str) -> Option<[u8; N]> {
    decode_hex(hex).ok()?.try_into().ok()
}

/// A sorted table mapping fixed-comparable keys to signature names.
///
/// Entries are accumulated into `pending` during parsing, then [`finalize`]d
/// into a sorted key array plus a single concatenated `names` buffer (one
/// allocation for all names, not one `String` per entry). Lookups binary-search
/// the keys. Compared to a `HashMap<K, Box<str>>` over millions of entries this
/// cuts both memory (no per-bucket/per-name overhead) and load time (a database
/// deserializes into packed `Vec`s, not millions of hash inserts and string
/// allocations).
///
/// [`finalize`]: SortedTable::finalize
#[derive(serde::Serialize, serde::Deserialize)]
struct SortedTable<K> {
    keys: Vec<K>,
    /// (offset, len) into `names`, parallel to `keys`.
    spans: Vec<(u32, u32)>,
    names: String,
    /// Per-entry provenance (parallel to `keys`): whether the signature came from
    /// an unofficial (non-`.cvd`) database. The clean name is stored in `names`;
    /// the `.UNOFFICIAL` suffix is applied by the report layer (compat mode).
    #[serde(default)]
    unofficial: Vec<bool>,
    #[serde(skip)]
    pending: Vec<(K, String, bool)>,
}

impl<K> Default for SortedTable<K> {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            spans: Vec::new(),
            names: String::new(),
            unofficial: Vec::new(),
            pending: Vec::new(),
        }
    }
}

impl<K: Ord + Clone> SortedTable<K> {
    fn insert(&mut self, key: K, name: &str, unofficial: bool) {
        self.pending.push((key, name.to_string(), unofficial));
    }

    fn len(&self) -> usize {
        self.keys.len() + self.pending.len()
    }

    /// Sort accumulated entries and intern their names. On a duplicate key the
    /// last inserted wins (matching the previous `HashMap` overwrite semantics).
    fn finalize(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let mut p = std::mem::take(&mut self.pending);
        // Stable sort so equal keys keep insertion order; the last then wins.
        p.sort_by(|a, b| a.0.cmp(&b.0));
        self.keys = Vec::with_capacity(p.len());
        self.spans = Vec::with_capacity(p.len());
        self.unofficial = Vec::with_capacity(p.len());
        self.names = String::new();
        let mut i = 0;
        while i < p.len() {
            let mut j = i;
            while j + 1 < p.len() && p[j + 1].0 == p[i].0 {
                j += 1;
            }
            let off = self.names.len() as u32;
            self.names.push_str(&p[j].1);
            self.spans.push((off, p[j].1.len() as u32));
            self.unofficial.push(p[j].2);
            self.keys.push(p[j].0.clone());
            i = j + 1;
        }
    }

    /// Return `(clean_name, unofficial)` for `key`.
    fn get(&self, key: &K) -> Option<(&str, bool)> {
        let i = self.keys.binary_search(key).ok()?;
        let (off, len) = self.spans[i];
        // `unofficial` may be empty when loading an older database (serde default);
        // treat a missing entry as official.
        let unofficial = self.unofficial.get(i).copied().unwrap_or(false);
        Some((&self.names[off as usize..(off + len) as usize], unofficial))
    }
}

/// One digest algorithm's signatures, split into a size-constrained table
/// (keyed by `(file_or_section_size, digest)`) and an any-size table (the
/// `*` wildcard). The `.hdb`/`.hsb`/`.mdb`/`.msb` formats all carry a `SIZE`
/// field: a numeric size constrains the match to exactly that length, `*`
/// matches any length. Dropping the size (matching on digest alone) would
/// diverge. One concrete type per digest length (16/20/32) keeps
/// the fixed-size-array keys (no per-entry heap allocation over millions of
/// signatures); serde and `Default` don't support const-generic array fields,
/// hence the macro rather than a `DigestTable<const N>`.
macro_rules! digest_table {
    ($name:ident, $n:literal) => {
        #[derive(Default, Serialize, Deserialize)]
        struct $name {
            any: SortedTable<[u8; $n]>,
            sized: SortedTable<(u64, [u8; $n])>,
        }
        impl $name {
            fn len(&self) -> usize {
                self.any.len() + self.sized.len()
            }
            fn finalize(&mut self) {
                self.any.finalize();
                self.sized.finalize();
            }
            /// `size == None` means the `*` wildcard.
            fn insert(&mut self, key: [u8; $n], size: Option<u64>, name: &str, unofficial: bool) {
                match size {
                    Some(s) => self.sized.insert((s, key), name, unofficial),
                    None => self.any.insert(key, name, unofficial),
                }
            }
            fn get(&self, key: &[u8; $n], size: u64) -> Option<(&str, bool)> {
                self.sized.get(&(size, *key)).or_else(|| self.any.get(key))
            }
            /// Whether a signature could match an object of `size` bytes: one
            /// of any size, or one of exactly that size.
            fn wants(&self, size: u64) -> bool {
                let keys = &self.sized.keys;
                let i = keys.partition_point(|k| k.0 < size);
                !self.any.keys.is_empty() || keys.get(i).is_some_and(|k| k.0 == size)
            }
        }
    };
}

/// Which digests a lookup can use for an object of one size.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Want {
    pub(crate) md5: bool,
    pub(crate) sha1: bool,
    pub(crate) sha256: bool,
}

impl Want {
    pub(crate) fn union(self, o: Want) -> Want {
        Want {
            md5: self.md5 || o.md5,
            sha1: self.sha1 || o.sha1,
            sha256: self.sha256 || o.sha256,
        }
    }
}
digest_table!(Md5Table, 16);
digest_table!(Sha1Table, 20);
digest_table!(Sha256Table, 32);

/// Parse a `HASH:SIZE[:NAME]` line into `(hash_hex, size_or_wildcard, name)`.
/// `size` is `None` for the `*` wildcard, `Some(n)` for a numeric size, and
/// the whole line is rejected (`None` return) for a malformed/missing size.
fn parse_hash_line(line: &str) -> Option<(&str, Option<u64>, &str)> {
    let mut parts = line.split(':');
    let hash = parts.next()?.trim();
    let size = parts.next()?.trim();
    let name = parts.next().map(|s| s.trim()).unwrap_or("Unnamed");
    let size = if size == "*" {
        None
    } else {
        Some(size.parse::<u64>().ok()?)
    };
    Some((hash, size, name))
}

/// A database of whole-file hash signatures, keyed by raw digest bytes and
/// constrained by the signature's size field.
#[derive(Default, Serialize, Deserialize)]
pub struct HashDb {
    md5: Md5Table,
    sha1: Sha1Table,
    sha256: Sha256Table,
}

impl HashDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.md5.len() + self.sha1.len() + self.sha256.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sort and intern accumulated entries; call once after all `extend_*`.
    pub fn finalize(&mut self) {
        self.md5.finalize();
        self.sha1.finalize();
        self.sha256.finalize();
    }

    /// Parse hash signatures. Both `.hdb` (`md5:size:name`) and
    /// `.hsb` (`sha:size:name`) share a `HASH:SIZE:NAME` layout; the hash
    /// algorithm is inferred from the hex digest length
    /// (32=MD5, 40=SHA1, 64=SHA256). `SIZE` may be `*` (any) or a byte count
    /// that the file length must match. Call [`HashDb::finalize`] when done.
    pub fn extend_from_text(&mut self, text: &str) {
        self.extend_from_text_prov(text, false);
    }

    /// As [`HashDb::extend_from_text`], tagging every parsed entry with `unofficial`
    /// provenance (set for signatures from a non-`.cvd` database). The clean name
    /// is stored; `.UNOFFICIAL` is applied at report time in compat mode.
    pub fn extend_from_text_prov(&mut self, text: &str, unofficial: bool) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((hash, size, name)) = parse_hash_line(line) else {
                continue;
            };
            match hash.len() {
                32 => {
                    if let Some(k) = hex_array::<16>(hash) {
                        self.md5.insert(k, size, name, unofficial);
                    }
                }
                40 => {
                    if let Some(k) = hex_array::<20>(hash) {
                        self.sha1.insert(k, size, name, unofficial);
                    }
                }
                64 => {
                    if let Some(k) = hex_array::<32>(hash) {
                        self.sha256.insert(k, size, name, unofficial);
                    }
                }
                _ => {}
            }
        }
    }

    /// The digests [`Self::lookup`] can match for an object of `size` bytes:
    /// only those of an algorithm with a signature of any size, or of that
    /// size. Most objects need none of the SHA ones, and some none at all.
    pub(crate) fn wants(&self, size: u64) -> Want {
        Want {
            md5: self.md5.wants(size),
            sha1: self.sha1.wants(size),
            sha256: self.sha256.wants(size),
        }
    }

    /// Look up computed digests for a file of `size` bytes; returns the matching
    /// signature's `(clean_name, unofficial)`. A sized signature matches only at
    /// that exact length; a `*` signature matches any length.
    pub fn lookup(&self, digests: &Digests, size: u64) -> Option<(String, bool)> {
        if let Some(k) = hex_array::<16>(&digests.md5) {
            if let Some((n, u)) = self.md5.get(&k, size) {
                return Some((n.to_string(), u));
            }
        }
        if let Some(k) = hex_array::<20>(&digests.sha1) {
            if let Some((n, u)) = self.sha1.get(&k, size) {
                return Some((n.to_string(), u));
            }
        }
        if let Some(k) = hex_array::<32>(&digests.sha256) {
            if let Some((n, u)) = self.sha256.get(&k, size) {
                return Some((n.to_string(), u));
            }
        }
        None
    }
}

/// PE-section hash signatures: `.mdb`/`.mdu` (MD5) and `.msb` (SHA1/
/// SHA256), all `SectionSize:HASH:Name` (size may be `*`). The algorithm is
/// inferred from the hash hex length, mirroring [`HashDb`].
#[derive(Default, Serialize, Deserialize)]
pub struct SectionHashDb {
    md5: Md5Table,
    sha1: Sha1Table,
    sha256: Sha256Table,
}

impl SectionHashDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.md5.len() + self.sha1.len() + self.sha256.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sort and intern accumulated entries; call once after all `extend_*`.
    pub fn finalize(&mut self) {
        self.md5.finalize();
        self.sha1.finalize();
        self.sha256.finalize();
    }

    /// True if any SHA (not just MD5) section signatures are loaded, so the
    /// caller knows whether computing per-section SHA digests is worthwhile.
    pub fn wants_sha(&self) -> bool {
        self.sha1.len() > 0 || self.sha256.len() > 0
    }

    /// Parse `.mdb`/`.mdu`/`.msb` lines (`SectionSize:HASH:Name`). The first
    /// field is the size, the second the hash: the opposite field order from
    /// `.hdb`, so this does not reuse `parse_hash_line`.
    pub fn extend_from_text(&mut self, text: &str) {
        self.extend_from_text_prov(text, false);
    }

    /// As [`SectionHashDb::extend_from_text`], tagging each entry's `unofficial`
    /// provenance.
    pub fn extend_from_text_prov(&mut self, text: &str, unofficial: bool) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split(':');
            let size = match parts.next() {
                Some(s) => s.trim(),
                None => continue,
            };
            let hash = match parts.next() {
                Some(h) => h.trim(),
                None => continue,
            };
            let name = parts.next().map(|s| s.trim()).unwrap_or("Unnamed");
            let size = if size == "*" {
                None
            } else {
                match size.parse::<u64>() {
                    Ok(s) => Some(s),
                    Err(_) => continue,
                }
            };
            match hash.len() {
                32 => {
                    if let Some(k) = hex_array::<16>(hash) {
                        self.md5.insert(k, size, name, unofficial);
                    }
                }
                40 => {
                    if let Some(k) = hex_array::<20>(hash) {
                        self.sha1.insert(k, size, name, unofficial);
                    }
                }
                64 => {
                    if let Some(k) = hex_array::<32>(hash) {
                        self.sha256.insert(k, size, name, unofficial);
                    }
                }
                _ => {}
            }
        }
    }

    /// Look up a section by its raw size and computed digests; returns the
    /// matching signature's `(clean_name, unofficial)`.
    pub fn lookup(&self, size: u64, digests: &Digests) -> Option<(String, bool)> {
        if let Some(k) = hex_array::<16>(&digests.md5) {
            if let Some((n, u)) = self.md5.get(&k, size) {
                return Some((n.to_string(), u));
            }
        }
        if let Some(k) = hex_array::<20>(&digests.sha1) {
            if let Some((n, u)) = self.sha1.get(&k, size) {
                return Some((n.to_string(), u));
            }
        }
        if let Some(k) = hex_array::<32>(&digests.sha256) {
            if let Some((n, u)) = self.sha256.get(&k, size) {
                return Some((n.to_string(), u));
            }
        }
        None
    }
}

/// Hex digests computed over a file.
#[derive(Debug, Clone)]
pub struct Digests {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// Digests for section-hash matching: always MD5; SHA1/SHA256 only when
/// `want_sha` (i.e. `.msb` signatures are loaded), since they are otherwise
/// unused. Skipped fields are left empty and their lookups simply miss.
pub fn section_digests(data: &[u8], want_sha: bool) -> Digests {
    if want_sha {
        digests_of(data)
    } else {
        Digests {
            md5: encode_hex(&Md5::digest(data)),
            sha1: String::new(),
            sha256: String::new(),
        }
    }
}

/// Compute digests over a byte slice (used for already-buffered content
/// such as extracted archive entries).
pub fn digests_of(data: &[u8]) -> Digests {
    digests_of_source(&data)
}

/// [`digests_of`] an object that need not be held in memory.
pub(crate) fn digests_of_source(data: &dyn crate::byte_source::ByteSource) -> Digests {
    let all = Want {
        md5: true,
        sha1: true,
        sha256: true,
    };
    digests_wanted(data, all)
}

/// The digests of `data` that `want` asks for; the others are left empty, and
/// a lookup of them misses. Wanting none reads nothing.
pub(crate) fn digests_wanted(data: &dyn crate::byte_source::ByteSource, want: Want) -> Digests {
    let mut h = Hashing::new(want);
    if want != Want::default() {
        data.chunks(0, data.len(), &mut |_, piece| {
            h.update(piece);
            true
        });
    }
    h.finish()
}

/// The digests [`digests_wanted`] computes, fed an object's bytes in order by
/// a read that serves other searches too.
pub(crate) struct Hashing {
    md5: Option<Md5>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
}

impl Hashing {
    pub(crate) fn new(want: Want) -> Self {
        Hashing {
            md5: want.md5.then(Md5::new),
            sha1: want.sha1.then(Sha1::new),
            sha256: want.sha256.then(Sha256::new),
        }
    }

    pub(crate) fn update(&mut self, piece: &[u8]) {
        // Every hasher over a 16 KiB slice before the next, which stays in
        // L1/L2 across them.
        for chunk in piece.chunks(16 * 1024) {
            self.md5.iter_mut().for_each(|h| h.update(chunk));
            self.sha1.iter_mut().for_each(|h| h.update(chunk));
            self.sha256.iter_mut().for_each(|h| h.update(chunk));
        }
    }

    pub(crate) fn finish(self) -> Digests {
        Digests {
            md5: self.md5.map_or_else(String::new, |h| encode_hex(&h.finalize())),
            sha1: self.sha1.map_or_else(String::new, |h| encode_hex(&h.finalize())),
            sha256: self.sha256.map_or_else(String::new, |h| encode_hex(&h.finalize())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_md5() {
        // md5("") = d41d8cd98f00b204e9800998ecf8427e
        let d = digests_of(b"");
        assert_eq!(d.md5, "d41d8cd98f00b204e9800998ecf8427e");
        // sha256("") = e3b0c442...
        assert!(d.sha256.starts_with("e3b0c44298fc1c14"));
    }

    #[test]
    fn hashdb_lookup() {
        let mut db = HashDb::new();
        let d = digests_of(b"malware");
        let n = "malware".len() as u64;
        db.extend_from_text(&format!("{}:*:Test.Malware\n", d.md5));
        db.finalize();
        assert_eq!(
            db.lookup(&d, n).map(|(n, _)| n).as_deref(),
            Some("Test.Malware")
        );
        assert!(db.lookup(&digests_of(b"clean"), 5).is_none());
    }

    #[test]
    fn hashdb_size_constraint() {
        // A sized signature matches only at that exact file length.
        let mut db = HashDb::new();
        let d = digests_of(b"malware");
        db.extend_from_text(&format!("{}:7:Test.Sized\n", d.md5));
        db.finalize();
        assert_eq!(
            db.lookup(&d, 7).map(|(n, _)| n).as_deref(),
            Some("Test.Sized")
        ); // size matches
        assert!(db.lookup(&d, 8).is_none()); // same hash, wrong size -> miss
    }

    #[test]
    fn hashdb_sha_whole_file() {
        let mut db = HashDb::new();
        let d = digests_of(b"payload");
        db.extend_from_text(&format!("{}:*:Test.BySha256\n", d.sha256));
        db.finalize();
        assert_eq!(
            db.lookup(&d, 7).map(|(n, _)| n).as_deref(),
            Some("Test.BySha256")
        );
    }

    #[test]
    fn section_hash_db() {
        let dig = |b: &[u8]| digests_of(b);
        let s = dig(b"section-bytes");
        let other = dig(b"other");
        let mut db = SectionHashDb::new();
        // .mdb (MD5) sized + wildcard, plus an .msb (SHA256) wildcard entry.
        db.extend_from_text(&format!(
            "4096:{}:Sig.Sized\n*:{}:Sig.AnySize\n*:{}:Sig.BySha\n",
            s.md5, other.md5, other.sha256
        ));
        db.finalize();
        assert!(db.wants_sha());
        // exact size+md5
        assert_eq!(
            db.lookup(4096, &s).map(|(n, _)| n).as_deref(),
            Some("Sig.Sized")
        );
        // wrong size, not a wildcard entry -> miss
        assert!(db.lookup(512, &s).is_none());
        // wildcard size matches any size (md5 and sha both registered for `other`)
        assert!(matches!(
            db.lookup(12345, &other).map(|(n, _)| n).as_deref(),
            Some("Sig.AnySize") | Some("Sig.BySha")
        ));
        // unrelated content -> miss
        assert!(db.lookup(4096, &dig(b"nope")).is_none());
    }
}
