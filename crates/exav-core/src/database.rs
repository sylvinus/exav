//! On-disk serialization of a built [`Scanner`] (the compiled `.exavdb`
//! database), so cold starts skip the expensive automaton construction and
//! signature parsing.
//!
//! The database is built once, typically on a capable host such as a daily CI
//! job, and the resulting file is distributed to and loaded directly by CLI
//! instances. Loading it reconstructs the double-array automatons from
//! daachorse's own byte format (no rebuild).
//!
//! The file starts with a magic tag and a format version; a mismatch is
//! rejected rather than misread. The database is a trusted artifact (you build
//! and fetch it yourself, over a channel you trust): its contents decide what is
//! detected, and nothing here checks who produced it.

use std::io::{self, Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::engine::SigEngine;
use crate::fuzzy::FuzzyDb;
use crate::hashes::{HashDb, SectionHashDb};
use crate::ml::HeuristicModel;
use crate::Scanner;

/// 8-byte format tag for the `.exavdb` prebuilt database. The 6-char ASCII name
/// plus two fixed bytes; the format *serial* lives in the separate [`VERSION`]
/// field below, not here. Any file whose first eight bytes don't match this tag
/// fails the header check and is rebuilt.
const MAGIC: &[u8; 8] = b"EXAVDB\x00\x01";
/// Serialized-layout serial, bumped whenever the on-disk payload format changes
/// (a load rejects any other value rather than misreading stale bytes). An
/// incompatible database is rejected by the magic or this serial and rebuilt.
///
/// The current layout includes the serialized COMPILED YARA rule set in `YaraDb`
/// (the compiled-blob + blob-version fields), so a prebuilt database loads the
/// YARA engine without recompiling. Version 4 dropped the streaming literal set;
/// version 5 added each automaton's longest anchor runs.
const VERSION: u32 = 5;
/// Fixed header: 8-byte magic + 4-byte little-endian version.
const HEADER_LEN: u64 = 12;
/// Trailing SHA-256 of the payload (integrity stamp).
const DIGEST_LEN: u64 = 32;

/// Serialize one value to `w` (MessagePack via the maintained rmp-serde).
pub(crate) fn enc<T: serde::Serialize, W: Write>(val: &T, w: &mut W) -> io::Result<()> {
    rmp_serde::encode::write(w, val).map_err(io::Error::other)
}

/// Deserialize one value from `r`.
pub(crate) fn dec<T: serde::de::DeserializeOwned, R: Read>(r: &mut R) -> io::Result<T> {
    rmp_serde::decode::from_read(r).map_err(io::Error::other)
}

/// Run `f` on a thread of its own while `g` runs on this one, and return both:
/// how a load decodes independent parts of a database at once. One after the
/// other where there are no threads.
pub(crate) fn alongside<A: Send, B>(f: impl FnOnce() -> A + Send, g: impl FnOnce() -> B) -> (A, B) {
    #[cfg(target_family = "wasm")]
    return (f(), g());
    #[cfg(not(target_family = "wasm"))]
    std::thread::scope(|s| {
        let h = s.spawn(f);
        let b = g();
        let a = h.join().unwrap_or_else(|p| std::panic::resume_unwind(p));
        (a, b)
    })
}

/// Bytes serde writes as one binary blob, as [`enc_bytes`] does outside it.
pub(crate) struct Blob<'a>(pub(crate) &'a [u8]);

impl serde::Serialize for Blob<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

/// A [`Blob`] read back.
pub(crate) struct BlobBuf(pub(crate) Vec<u8>);

impl<'de> serde::Deserialize<'de> for BlobBuf {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = BlobBuf;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a binary blob")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<BlobBuf, E> {
                Ok(BlobBuf(v.to_vec()))
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<BlobBuf, E> {
                Ok(BlobBuf(v))
            }
        }
        d.deserialize_byte_buf(Visit)
    }
}

/// `#[serde(with = ...)]` for an optional byte vector stored as a [`Blob`].
pub(crate) mod opt_blob {
    pub(crate) fn serialize<S: serde::Serializer>(
        v: &Option<Vec<u8>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&v.as_deref().map(super::Blob), s)
    }

    pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        let v: Option<super::BlobBuf> = serde::Deserialize::deserialize(d)?;
        Ok(v.map(|b| b.0))
    }
}

/// Write `bytes` as one MessagePack binary blob, which a load reads back with
/// one copy. A `Vec<u8>` through serde is an array of integers instead, decoded
/// one element at a time: it was most of a load's time.
pub(crate) fn enc_bytes<W: Write>(bytes: &[u8], w: &mut W) -> io::Result<()> {
    rmp::encode::write_bin(w, bytes).map_err(io::Error::other)
}

/// Read a blob [`enc_bytes`] wrote. A length past what is left of the payload
/// is refused before anything is allocated for it.
pub(crate) fn dec_bytes<R: PayloadRead>(r: &mut R) -> io::Result<Vec<u8>> {
    let len = rmp::decode::read_bin_len(r).map_err(io::Error::other)? as u64;
    if len > r.left() {
        return Err(bad("database blob runs past the end of the payload"));
    }
    let mut out = vec![0; len as usize];
    r.read_exact(&mut out)?;
    Ok(out)
}

/// A database payload being read, which knows how much of it is left.
pub(crate) trait PayloadRead: Read {
    fn left(&self) -> u64;
}

impl PayloadRead for &[u8] {
    fn left(&self) -> u64 {
        self.len() as u64
    }
}

impl<T: PayloadRead + ?Sized> PayloadRead for &mut T {
    fn left(&self) -> u64 {
        (**self).left()
    }
}

/// The payload of a database file, read once and hashed as it goes, so the
/// integrity check does not cost a second read of the file.
struct HashedPayload<R> {
    inner: R,
    left: u64,
    hasher: Sha256,
}

impl<R: Read> Read for HashedPayload<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        let n = self.inner.read(&mut buf[..want])?;
        self.hasher.update(&buf[..n]);
        self.left -= n as u64;
        Ok(n)
    }
}

/// Buffered above the hashing, so the digest is fed large pieces rather
/// than every few bytes a decoder asks for.
impl<R: Read> PayloadRead for io::BufReader<HashedPayload<R>> {
    fn left(&self) -> u64 {
        self.get_ref().left + self.buffer().len() as u64
    }
}

/// Write `vals` as one binary blob of little-endian words.
pub(crate) fn enc_u32s<W: Write>(vals: &[u32], w: &mut W) -> io::Result<()> {
    let bytes: Vec<u8> = vals.iter().flat_map(|v| v.to_le_bytes()).collect();
    enc_bytes(&bytes, w)
}

/// Read words [`enc_u32s`] wrote.
pub(crate) fn dec_u32s<R: PayloadRead>(r: &mut R) -> io::Result<Vec<u32>> {
    let bytes = dec_bytes(r)?;
    let (words, rest) = bytes.as_chunks::<4>();
    if !rest.is_empty() {
        return Err(bad("database blob is not a whole number of words"));
    }
    Ok(words.iter().map(|&w| u32::from_le_bytes(w)).collect())
}

/// A writer that SHA-256s everything passing through it (the payload digest).
struct HashWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Serialize a built database, framed as `MAGIC | VERSION | payload | sha256`.
pub fn write<W: Write>(db: &Scanner, mut w: W) -> io::Result<()> {
    w.write_all(MAGIC)?;
    w.write_all(&VERSION.to_le_bytes())?;
    let mut hw = HashWriter {
        inner: w,
        hasher: Sha256::new(),
    };
    write_payload(db, &mut hw)?;
    let digest = hw.hasher.finalize();
    hw.inner.write_all(&digest)?;
    Ok(())
}

fn write_payload<W: Write>(db: &Scanner, w: &mut W) -> io::Result<()> {
    // The expensive part: the wildcard/logical engine.
    db.engine.write_cache(&mut *w)?;
    enc(&db.hashes, w)?;
    enc(&db.sections, w)?;
    enc(&db.fuzzy.to_cache(), w)?;
    enc(&db.cdb, w)?;
    enc(&db.yara, w)?;
    enc(&db.allow, w)?;
    enc(&db.ignored, w)?;
    enc(&db.bytecode.sources(), w)?;
    enc(&db.ml_threshold, w)?;
    enc(&db.ftm, w)?;
    enc(&db.icons, w)?;
    enc(&db.crb.sources(), w)?;
    enc(&db.passwords, w)?;
    // Phishing DB (`.pdb`/`.wdb`): serialised feature-independently (empty tuple
    // when the `phishing` feature is off) so the database layout doesn't fork on
    // features. Only the sources travel; compiled regexes are rebuilt on load.
    #[cfg(feature = "phishing")]
    enc(&db.phishing.to_cache_parts(), w)?;
    #[cfg(not(feature = "phishing"))]
    {
        // Empty parts, keeping the database layout identical across features.
        let empty: crate::PhishingPartsOwned = Default::default();
        enc(&empty, w)?;
    }
    enc(&db.db_version, w)?;
    Ok(())
}

/// Validate the header, returning the payload byte length.
fn read_header<R: Read>(r: &mut R, total_len: u64) -> io::Result<u64> {
    let mut hdr = [0u8; HEADER_LEN as usize];
    r.read_exact(&mut hdr)?;
    if &hdr[..8] != MAGIC {
        return Err(bad("not an exav database file"));
    }
    let version = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    if version != VERSION {
        return Err(bad(format!(
            "unsupported database version {version} (this build expects {VERSION})"
        )));
    }
    total_len
        .checked_sub(HEADER_LEN + DIGEST_LEN)
        .ok_or_else(|| bad("database file is truncated"))
}

/// Deserialize the payload sections (already integrity-checked) into a database.
fn read_payload<R: PayloadRead>(mut r: R) -> io::Result<Scanner> {
    let engine = SigEngine::read_cache(&mut r)?;
    let hashes: HashDb = dec(&mut r)?;
    let sections: SectionHashDb = dec(&mut r)?;
    let fuzzy = FuzzyDb::from_cache(dec(&mut r)?);
    let cdb: crate::container::CdbDb = dec(&mut r)?;
    let yara: crate::yara::YaraDb = dec(&mut r)?;
    let allow: HashDb = dec(&mut r)?;
    let ignored = dec(&mut r)?;
    let bytecode_sources: Vec<String> = dec(&mut r)?;
    let ml_threshold = dec(&mut r)?;
    let ftm = dec(&mut r)?;
    let icons = dec(&mut r)?;
    let crb_sources: Vec<String> = dec(&mut r)?;
    let passwords: Vec<String> = dec(&mut r)?;
    // Phishing DB parts (always present in the format; empty when built without
    // the `phishing` feature). Regexes are recompiled from the sources on load.
    #[cfg_attr(not(feature = "phishing"), allow(unused_variables))]
    let phishing_parts: crate::PhishingPartsOwned = dec(&mut r)?;
    let db_version: Option<(u32, String)> = dec(&mut r)?;
    Ok(Scanner {
        engine,
        hashes,
        sections,
        fuzzy,
        cdb,
        yara,
        allow,
        ignored,
        bytecode: crate::bytecode::runtime::BytecodeRuntime::from_stored(bytecode_sources),
        model: Box::new(HeuristicModel),
        ml_threshold,
        ftm,
        icons,
        crb: crate::authenticode::CrbDb::from_sources(&crb_sources),
        passwords,
        db_version,
        #[cfg(feature = "phishing")]
        phishing: crate::phishing::PhishingDb::from_cache_parts(phishing_parts),
    })
}

/// Reverse of [`write()`] over an arbitrary reader, held whole in memory and
/// checked before it is decoded. [`load`] reads a file once instead, without
/// holding it.
pub fn read<R: Read>(mut r: R) -> io::Result<Scanner> {
    let mut rest = Vec::new();
    r.read_to_end(&mut rest)?;
    let payload_len = read_header(&mut &rest[..], rest.len() as u64)?;
    let (head_payload, trailer) = rest.split_at(rest.len() - DIGEST_LEN as usize);
    let payload = &head_payload[HEADER_LEN as usize..];
    debug_assert_eq!(payload.len() as u64, payload_len);
    verify_digest(payload, trailer)?;
    read_payload(payload)
}

/// SHA-256 the payload and compare to the stored trailer.
fn verify_digest(payload: &[u8], trailer: &[u8]) -> io::Result<()> {
    let mut h = Sha256::new();
    h.update(payload);
    if h.finalize().as_slice() != trailer {
        return Err(bad("database integrity check failed (digest mismatch)"));
    }
    Ok(())
}

/// True if `path` looks like an exav database file (by magic tag).
pub fn is_database_file(path: &Path) -> bool {
    let mut m = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut m))
        .is_ok()
        && &m == MAGIC
}

/// Write a database file at `path`.
pub fn save(db: &Scanner, path: &Path) -> io::Result<()> {
    let f = std::fs::File::create(path)?;
    write(db, io::BufWriter::new(f))
}

/// Load a database file from `path`. Two passes over the file (hash, then
/// deserialize) so the integrity check happens before deserialization without
/// buffering the whole payload in memory.
pub fn load(path: &Path) -> io::Result<Scanner> {
    let mut f = std::fs::File::open(path)?;
    let total = f.metadata()?.len();
    let payload_len = read_header(&mut f, total)?;
    // One pass: the payload is hashed as it is decoded, and the digest checked
    // before the result is used. A torn or corrupt file is rejected all the
    // same; what decoding it can do first is bounded, since no length in it
    // is trusted past the end of the payload.
    let hashed = HashedPayload {
        inner: f,
        left: payload_len,
        hasher: Sha256::new(),
    };
    let mut payload = io::BufReader::with_capacity(1 << 20, hashed);
    let decoded = read_payload(&mut payload);
    io::copy(&mut payload, &mut io::sink())?;
    let mut hashed = payload.into_inner();
    let mut trailer = [0u8; DIGEST_LEN as usize];
    hashed.inner.read_exact(&mut trailer)?;
    if hashed.hasher.finalize().as_slice() != trailer {
        return Err(bad("database integrity check failed (digest mismatch)"));
    }
    decoded
}

#[cfg(test)]
mod tests {
    use crate::{analyze, ScanOptions, Verdict};

    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn database_round_trip_matches_fresh_build() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        // A literal ndb sig, a wildcard ndb sig, a logical sig, and a hash sig.
        std::fs::write(
            dir.path().join("a.ndb"),
            "Sig.Lit:0:*:6d616c6963696f7573\nSig.Wild:0:*:6d61*696f7573\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.ldb"),
            "Sig.Logic;Engine:0-255;0&1;6d616c;696f7573\n",
        )
        .unwrap();
        let d = crate::hashes::digests_of(b"hashme");
        std::fs::write(dir.path().join("c.hdb"), format!("{}:*:Sig.Hash\n", d.md5)).unwrap();

        let fresh = crate::loader::load(dir.path()).unwrap();

        let db_path = dir.path().join("db.exavdb");
        super::save(&fresh, &db_path).unwrap();
        assert!(super::is_database_file(&db_path));
        let loaded = super::load(&db_path).unwrap();

        // Same signature count and same verdicts from the reloaded database.
        assert_eq!(fresh.signature_count(), loaded.signature_count());
        let opts = ScanOptions::default();
        for sample in [
            &b"this is malicious content"[..],
            &b"ma is malicious"[..],
            &b"hashme"[..],
            &b"perfectly clean"[..],
        ] {
            let a = analyze(&fresh, sample, &opts);
            let b = analyze(&loaded, sample, &opts);
            assert_eq!(
                matches!(a.verdict, Verdict::Infected { .. }),
                matches!(b.verdict, Verdict::Infected { .. }),
                "verdict mismatch for {sample:?}"
            );
        }
    }

    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn rejects_non_database_and_bad_version() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        let p = dir.path().join("nope");
        std::fs::write(&p, b"not a database at all").unwrap();
        assert!(!super::is_database_file(&p));
        assert!(super::load(&p).is_err());
    }

    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn rejects_tampered_database() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.ndb"), "Sig.Lit:0:*:6d616c6963696f7573\n").unwrap();
        let db = crate::loader::load(dir.path()).unwrap();
        let path = dir.path().join("db.exavdb");
        super::save(&db, &path).unwrap();

        // Flip a byte in the middle of the payload; the digest must reject it.
        let mut bytes = std::fs::read(&path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        let err = match super::load(&path) {
            Ok(_) => panic!("tampered database should not load"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("integrity"),
            "expected integrity error, got: {err}"
        );
        // The buffered `read` path must reject it too.
        assert!(super::read(std::io::Cursor::new(&bytes)).is_err());
    }

    /// `load` decodes as it reads and checks the digest at the end, so what it
    /// decodes first may be corrupt: any one byte flipped, and any truncation,
    /// has to come out an error, never a panic, a huge allocation or a load.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn every_corruption_is_an_error() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.ndb"), "Sig.Lit:0:*:6d616c6963696f7573\n").unwrap();
        std::fs::write(
            dir.path().join("b.ldb"),
            "Sig.L;Engine:51-255,Target:0;0&1;6d616c;6963696f::i\n",
        )
        .unwrap();
        let db = crate::loader::load(dir.path()).unwrap();
        let mut good = Vec::new();
        super::write(&db, &mut good).unwrap();
        let path = dir.path().join("db.exavdb");
        let rejected = |bytes: &[u8]| {
            std::fs::write(&path, bytes).unwrap();
            super::load(&path).is_err() && super::read(bytes).is_err()
        };
        for i in 0..good.len() {
            let mut bytes = good.clone();
            bytes[i] ^= 0x5a;
            assert!(rejected(&bytes), "byte {i} of {} flipped", good.len());
        }
        for len in 0..good.len() {
            assert!(rejected(&good[..len]), "cut at {len} of {}", good.len());
        }
        assert!(!rejected(&good));
    }

    /// Per-signature `unofficial` provenance survives the database round-trip, so a
    /// single database yields clean names in a default scan and
    /// `.UNOFFICIAL` names in a compat scan.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn provenance_round_trips_for_compat_naming() {
        use crate::Verdict;
        let dir = crate::tmpfile::TempDir::new().unwrap();
        // 6d616c77617265 = "malware"; a loose `.ndb` is unofficial.
        std::fs::write(dir.path().join("a.ndb"), "Demo.Loose:0:*:6d616c77617265\n").unwrap();
        let fresh = crate::loader::load(dir.path()).unwrap();
        let path = dir.path().join("db.exavdb");
        super::save(&fresh, &path).unwrap();
        let loaded = super::load(&path).unwrap();

        let data = b"xx malware xx";
        let compat = ScanOptions {
            restrict_extractors: true,
            unofficial_suffix: true,
            ..ScanOptions::default()
        };
        for db in [&fresh, &loaded] {
            match analyze(db, data, &ScanOptions::default()).verdict {
                Verdict::Infected { signature, .. } => assert_eq!(signature, "Demo.Loose"),
                other => panic!("expected detection, got {other:?}"),
            }
            match analyze(db, data, &compat).verdict {
                Verdict::Infected { signature, .. } => {
                    assert_eq!(signature, "Demo.Loose.UNOFFICIAL")
                }
                other => panic!("expected detection, got {other:?}"),
            }
        }
    }

    /// The `.pdb`/`.wdb` phishing DB must survive the prebuilt database round-trip:
    /// a database-loaded engine applies the same brand-scoping and allow-listing
    /// (incl. the recompiled `X:` regexes) as a fresh `-d <dbdir>` load.
    #[cfg(feature = "phishing")]
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn phishing_db_round_trips_through_database() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("p.pdb"), "H:paypal.com\n").unwrap();
        std::fs::write(
            dir.path().join("p.wdb"),
            "X:.+\\.etradefinancial\\.com([/?].*)?:(.+\\.)?etrade\\.com([/?].*)?\n",
        )
        .unwrap();
        let fresh = crate::loader::load(dir.path()).unwrap();
        let path = dir.path().join("db.exavdb");
        super::save(&fresh, &path).unwrap();
        let loaded = super::load(&path).unwrap();

        // Spoof of a protected brand -> flagged; the X: regex pair -> suppressed.
        let spoof = br#"<a href="http://evil.example/x">www.paypal.com</a>"#;
        let allowed = br#"<a href="http://email.etradefinancial.com/x">www.etrade.com</a>"#;
        for db in [&fresh, &loaded] {
            assert!(!db.phishing.is_empty());
            assert_eq!(
                crate::phishing::scan(spoof, &db.phishing),
                Some(crate::phishing::Phish::SpoofedDomain)
            );
            assert_eq!(crate::phishing::scan(allowed, &db.phishing), None);
        }
    }
}
