//! On-disk serialization of a built [`Database`] so cold starts skip the
//! expensive automaton construction and signature parsing.
//!
//! The cache is built once — typically on a capable host such as a daily CI
//! job — and the resulting file is distributed to and loaded directly by CLI
//! instances. Loading it reconstructs the double-array automatons from
//! daachorse's own byte format (no rebuild) and re-parses only the small
//! streaming literal set.
//!
//! The file starts with a magic tag and a format version; a mismatch is
//! rejected rather than misread. The cache is a trusted artifact (you build
//! and fetch it yourself, over a channel you trust) — it is not a safe target
//! for arbitrary untrusted bytes, since the automaton bytes are deserialized
//! without full validation.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::engine::SigEngine;
use crate::fuzzy::FuzzyDb;
use crate::hashes::{HashDb, SectionHashDb};
use crate::ml::HeuristicModel;
use crate::patterns::{Pattern, PatternSet};
use crate::Database;

const MAGIC: &[u8; 8] = b"EXAVCAC\x01";
/// Bumped whenever the serialized layout changes (not live yet, so stale
/// on-disk caches are simply deleted rather than version-bumped).
///
/// v8: per-signature `unofficial` provenance added to the engine bodies/logical
/// sigs, the hash/section tables, `.cdb` sigs and the streaming literal patterns,
/// so the `.UNOFFICIAL` suffix is applied at report time (compat mode) instead of
/// being baked into names at load — one cache now serves both compat and
/// non-compat scans.
///
/// v9: `.pwdb` password pool serialized into the payload (decryption candidates
/// for encrypted archive members).
const VERSION: u32 = 9;
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
pub fn write<W: Write>(db: &Database, mut w: W) -> io::Result<()> {
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

fn write_payload<W: Write>(db: &Database, w: &mut W) -> io::Result<()> {
    // Streaming literal patterns; the automaton is rebuilt on load (cheap).
    enc(&db.patterns.src, w)?;
    enc(&db.patterns.unsupported, w)?;
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
    enc(&db.passwords, w)?;
    Ok(())
}

/// Validate the header, returning the payload byte length.
fn read_header<R: Read>(r: &mut R, total_len: u64) -> io::Result<u64> {
    let mut hdr = [0u8; HEADER_LEN as usize];
    r.read_exact(&mut hdr)?;
    if &hdr[..8] != MAGIC {
        return Err(bad("not an exav cache file"));
    }
    let version = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    if version != VERSION {
        return Err(bad(format!(
            "unsupported cache version {version} (this build expects {VERSION})"
        )));
    }
    total_len
        .checked_sub(HEADER_LEN + DIGEST_LEN)
        .ok_or_else(|| bad("cache file is truncated"))
}

/// Deserialize the payload sections (already integrity-checked) into a database.
fn read_payload<R: Read>(mut r: R) -> io::Result<Database> {
    let src: Vec<Pattern> = dec(&mut r)?;
    let unsupported: usize = dec(&mut r)?;
    let patterns = PatternSet::build(&src, unsupported).map_err(io::Error::other)?;
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
    let passwords: Vec<String> = dec(&mut r)?;
    Ok(Database {
        patterns,
        engine,
        hashes,
        sections,
        fuzzy,
        cdb,
        yara,
        allow,
        ignored,
        bytecode: crate::bytecode::runtime::BytecodeRuntime::from_sources(bytecode_sources),
        model: Box::new(HeuristicModel),
        ml_threshold,
        ftm,
        icons,
        passwords,
    })
}

/// Reverse of [`write`] over an arbitrary reader. Buffers the payload to verify
/// its SHA-256 *before* deserializing (so the unchecked automaton decode never
/// runs on tampered bytes). [`load`] is more memory-frugal for files.
pub fn read<R: Read>(mut r: R) -> io::Result<Database> {
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
        return Err(bad("cache integrity check failed (digest mismatch)"));
    }
    Ok(())
}

/// True if `path` looks like an exav cache file (by magic tag).
pub fn is_cache_file(path: &Path) -> bool {
    let mut m = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut m))
        .is_ok()
        && &m == MAGIC
}

/// Write a cache file at `path`.
pub fn save(db: &Database, path: &Path) -> io::Result<()> {
    let f = std::fs::File::create(path)?;
    write(db, io::BufWriter::new(f))
}

/// Load a cache file from `path`. Two passes over the file (hash, then
/// deserialize) so the integrity check happens before deserialization without
/// buffering the whole payload in memory.
pub fn load(path: &Path) -> io::Result<Database> {
    let mut f = std::fs::File::open(path)?;
    let total = f.metadata()?.len();
    let payload_len = read_header(&mut f, total)?;

    // Pass 1: hash the payload and compare to the trailer.
    let mut hasher = Sha256::new();
    let mut remaining = payload_len;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        f.read_exact(&mut buf[..want])?;
        hasher.update(&buf[..want]);
        remaining -= want as u64;
    }
    let mut trailer = [0u8; DIGEST_LEN as usize];
    f.read_exact(&mut trailer)?;
    if hasher.finalize().as_slice() != trailer {
        return Err(bad("cache integrity check failed (digest mismatch)"));
    }

    // Pass 2: deserialize from the verified payload region.
    f.seek(SeekFrom::Start(HEADER_LEN))?;
    let payload = io::BufReader::new(f.take(payload_len));
    read_payload(payload)
}

#[cfg(test)]
mod tests {
    use crate::{analyze, ScanOptions, Verdict};

    #[test]
    fn cache_round_trip_matches_fresh_build() {
        let dir = tempfile::tempdir().unwrap();
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

        let fresh = crate::db::load(dir.path()).unwrap();

        let cache_path = dir.path().join("db.exavcache");
        super::save(&fresh, &cache_path).unwrap();
        assert!(super::is_cache_file(&cache_path));
        let loaded = super::load(&cache_path).unwrap();

        // Same signature count and same verdicts from the reloaded cache.
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
    fn rejects_non_cache_and_bad_version() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope");
        std::fs::write(&p, b"not a cache at all").unwrap();
        assert!(!super::is_cache_file(&p));
        assert!(super::load(&p).is_err());
    }

    #[test]
    fn rejects_tampered_cache() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.ndb"), "Sig.Lit:0:*:6d616c6963696f7573\n").unwrap();
        let db = crate::db::load(dir.path()).unwrap();
        let path = dir.path().join("db.exavcache");
        super::save(&db, &path).unwrap();

        // Flip a byte in the middle of the payload; the digest must reject it.
        let mut bytes = std::fs::read(&path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        let err = match super::load(&path) {
            Ok(_) => panic!("tampered cache should not load"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("integrity"),
            "expected integrity error, got: {err}"
        );
        // The buffered `read` path must reject it too.
        assert!(super::read(std::io::Cursor::new(&bytes)).is_err());
    }

    /// Per-signature `unofficial` provenance survives the cache round-trip, so a
    /// single cached database yields clean names in a default scan and
    /// `.UNOFFICIAL` names in a compat scan.
    #[test]
    fn provenance_round_trips_for_compat_naming() {
        use crate::Verdict;
        let dir = tempfile::tempdir().unwrap();
        // 6d616c77617265 = "malware"; a loose `.ndb` is unofficial.
        std::fs::write(dir.path().join("a.ndb"), "Demo.Loose:0:*:6d616c77617265\n").unwrap();
        let fresh = crate::db::load(dir.path()).unwrap();
        let path = dir.path().join("db.exavcache");
        super::save(&fresh, &path).unwrap();
        let loaded = super::load(&path).unwrap();

        let data = b"xx malware xx";
        let mut compat = ScanOptions::default();
        compat.compat = true;
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
}
