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
///
/// Stored as a few blobs rather than millions of entries decoded one element
/// at a time: the keys as fixed-width records, the spans as words, the names
/// as one string and the provenance as bits.
struct SortedTable<K> {
    keys: Vec<K>,
    /// (offset, len) into `names`, parallel to `keys`.
    spans: Vec<(u32, u32)>,
    names: String,
    /// Per-entry provenance (parallel to `keys`): whether the signature came from
    /// an unofficial (non-`.cvd`) database. The clean name is stored in `names`;
    /// the `.UNOFFICIAL` suffix is applied by the report layer (compat mode).
    unofficial: Vec<bool>,
    pending: Vec<(K, String, bool)>,
}

/// A key a [`SortedTable`] stores as a fixed-width record.
trait Record: Sized {
    const WIDTH: usize;
    fn put(&self, out: &mut Vec<u8>);
    fn get(b: &[u8]) -> Self;
}

impl<const N: usize> Record for [u8; N] {
    const WIDTH: usize = N;
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
    fn get(b: &[u8]) -> Self {
        b.try_into().expect("a record of its width")
    }
}

impl<const N: usize> Record for (u64, [u8; N]) {
    const WIDTH: usize = 8 + N;
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
        out.extend_from_slice(&self.1);
    }
    fn get(b: &[u8]) -> Self {
        (
            u64::from_le_bytes(b[..8].try_into().expect("eight bytes")),
            b[8..].try_into().expect("a record of its width"),
        )
    }
}

impl<K: Record> Serialize for SortedTable<K> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use crate::database::Blob;
        let mut keys = Vec::with_capacity(self.keys.len() * K::WIDTH);
        for k in &self.keys {
            k.put(&mut keys);
        }
        let spans: Vec<u8> = self.spans.iter().flat_map(|&(o, l)| [o.to_le_bytes(), l.to_le_bytes()]).flatten().collect();
        let mut bits = vec![0u8; self.unofficial.len().div_ceil(8)];
        for (i, _) in self.unofficial.iter().enumerate().filter(|(_, &u)| u) {
            bits[i / 8] |= 1 << (i % 8);
        }
        (Blob(&keys), Blob(&spans), &self.names, Blob(&bits)).serialize(s)
    }
}

impl<'de, K: Record + Ord> Deserialize<'de> for SortedTable<K> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use crate::database::BlobBuf;
        use serde::de::Error;
        let (keys, spans, names, bits): (BlobBuf, BlobBuf, String, BlobBuf) = Deserialize::deserialize(d)?;
        let (keys, spans, bits) = (keys.0, spans.0, bits.0);
        let n = keys.len() / K::WIDTH;
        if keys.len() % K::WIDTH != 0 || spans.len() != n * 8 || bits.len() != n.div_ceil(8) {
            return Err(D::Error::custom("hash table blobs of unequal lengths"));
        }
        // `as_chunks` cannot take a generic's associated const as its width.
        #[allow(clippy::chunks_exact_to_as_chunks)]
        let keys: Vec<K> = keys.chunks_exact(K::WIDTH).map(K::get).collect();
        let spans: Vec<(u32, u32)> = spans
            .as_chunks::<8>()
            .0
            .iter()
            .map(|w| {
                let (o, l) = w.split_at(4);
                (u32::from_le_bytes(o.try_into().unwrap()), u32::from_le_bytes(l.try_into().unwrap()))
            })
            .collect();
        // In u64, so a corrupt span cannot overflow a 32-bit `usize`.
        let in_names = |&(o, l): &(u32, u32)| {
            let e = o as u64 + l as u64;
            e <= names.len() as u64 && names.is_char_boundary(o as usize) && names.is_char_boundary(e as usize)
        };
        if !keys.is_sorted() || !spans.iter().all(in_names) {
            return Err(D::Error::custom("hash table out of order or out of bounds"));
        }
        let unofficial = (0..n).map(|i| bits[i / 8] >> (i % 8) & 1 != 0).collect();
        Ok(SortedTable {
            keys,
            spans,
            names,
            unofficial,
            pending: Vec::new(),
        })
    }
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
        let (off, len) = (self.spans[i].0 as usize, self.spans[i].1 as usize);
        Some((&self.names[off..off + len], self.unofficial[i]))
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
        lookup_in(&self.md5, &self.sha1, &self.sha256, digests, size)
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

    /// The digests [`Self::lookup`] can match for a section of `size` bytes:
    /// most sections' sizes are no signature's, and need none.
    pub(crate) fn wants(&self, size: u64) -> Want {
        Want {
            md5: self.md5.wants(size),
            sha1: self.sha1.wants(size),
            sha256: self.sha256.wants(size),
        }
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
        lookup_in(&self.md5, &self.sha1, &self.sha256, digests, size)
    }
}

/// The first signature of the three tables matching `digests` at `size`.
fn lookup_in(
    md5: &Md5Table,
    sha1: &Sha1Table,
    sha256: &Sha256Table,
    d: &Digests,
    size: u64,
) -> Option<(String, bool)> {
    d.md5
        .and_then(|k| md5.get(&k, size))
        .or_else(|| d.sha1.and_then(|k| sha1.get(&k, size)))
        .or_else(|| d.sha256.and_then(|k| sha256.get(&k, size)))
        .map(|(n, u)| (n.to_string(), u))
}

/// Digests computed over a file, those asked for.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Digests {
    pub md5: Option<[u8; 16]>,
    pub sha1: Option<[u8; 20]>,
    pub sha256: Option<[u8; 32]>,
}

impl Digests {
    /// The MD5, in hex; empty when it was not computed.
    pub fn md5_hex(&self) -> String {
        self.md5.map(|d| encode_hex(&d)).unwrap_or_default()
    }

    /// The SHA-1, in hex; empty when it was not computed.
    pub fn sha1_hex(&self) -> String {
        self.sha1.map(|d| encode_hex(&d)).unwrap_or_default()
    }

    /// The SHA-256, in hex; empty when it was not computed.
    pub fn sha256_hex(&self) -> String {
        self.sha256.map(|d| encode_hex(&d)).unwrap_or_default()
    }
}

/// The digests of section `data`, of `size` bytes, that section signatures of
/// that size could match; none, without reading it, for most sections.
pub(crate) fn section_digests(db: &SectionHashDb, size: u64, data: &[u8]) -> Digests {
    digests_wanted(&data, db.wants(size))
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
            md5: self.md5.map(|h| h.finalize().into()),
            sha1: self.sha1.map(|h| h.finalize().into()),
            sha256: self.sha256.map(|h| h.finalize().into()),
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
        assert_eq!(d.md5_hex(), "d41d8cd98f00b204e9800998ecf8427e");
        // sha256("") = e3b0c442...
        assert!(d.sha256_hex().starts_with("e3b0c44298fc1c14"));
    }

    /// A table stored and read back answers every lookup as before, and one
    /// whose span runs out of its names is refused rather than read.
    #[test]
    fn hash_tables_round_trip_as_blobs() {
        let (a, b, c) = (digests_of(b"one"), digests_of(b"two"), digests_of(b"three"));
        let mut db = HashDb::new();
        db.extend_from_text(&format!("{}:3:Sized.Md5\n{}:*:Any.Sha1\n", a.md5_hex(), b.sha1_hex()));
        db.extend_from_text_prov(&format!("{}:5:Sized.Sha256.é\n", c.sha256_hex()), true);
        db.finalize();
        let blob = rmp_serde::to_vec(&db).unwrap();
        let back: HashDb = rmp_serde::from_slice(&blob).unwrap();
        for (d, size) in [(&a, 3), (&b, 99), (&c, 5), (&a, 4), (&c, 6)] {
            assert_eq!(back.lookup(d, size), db.lookup(d, size), "{size}");
        }
        assert_eq!(back.lookup(&c, 5), Some(("Sized.Sha256.é".to_string(), true)));
        assert_eq!(back.lookup(&b, 99), Some(("Any.Sha1".to_string(), false)));
        // Break the last span so it runs past the names: refused.
        let mut t = SortedTable::<[u8; 4]>::default();
        t.insert(*b"abcd", "Name", false);
        t.finalize();
        t.spans[0].1 = 99;
        let blob = rmp_serde::to_vec(&t).unwrap();
        assert!(rmp_serde::from_slice::<SortedTable<[u8; 4]>>(&blob).is_err());
    }

    #[test]
    fn hashdb_lookup() {
        let mut db = HashDb::new();
        let d = digests_of(b"malware");
        let n = "malware".len() as u64;
        db.extend_from_text(&format!("{}:*:Test.Malware\n", d.md5_hex()));
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
        db.extend_from_text(&format!("{}:7:Test.Sized\n", d.md5_hex()));
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
        db.extend_from_text(&format!("{}:*:Test.BySha256\n", d.sha256_hex()));
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
            s.md5_hex(),
            other.md5_hex(),
            other.sha256_hex()
        ));
        db.finalize();
        // Only what a signature of the size could match.
        assert_eq!(db.wants(4096), Want { md5: true, sha1: false, sha256: true });
        assert_eq!(db.wants(512), Want { md5: true, sha1: false, sha256: true });
        let mut sized = SectionHashDb::new();
        sized.extend_from_text(&format!("4096:{}:Sig.Sized\n", s.md5_hex()));
        sized.finalize();
        assert_eq!(sized.wants(512), Want::default());
        assert_eq!(section_digests(&sized, 512, b"section-bytes"), Digests::default());
        assert_eq!(section_digests(&sized, 4096, b"section-bytes").md5, s.md5);
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
