//! On-disk serialization of a built [`Scanner`] (the compiled `.exavdb`
//! database), so cold starts skip signature parsing and the index build.
//!
//! The database is built once, typically on a capable host such as a daily CI
//! job, and the resulting file is distributed to and loaded directly by CLI
//! instances. Loading it reads the signature index back as the build laid it
//! out (no rebuild).
//!
//! The file starts with a magic tag and a format version; a mismatch is
//! rejected rather than misread. The database is a trusted artifact (you build
//! and fetch it yourself, over a channel you trust): its contents decide what is
//! detected, and nothing here checks who produced it.

use std::io::{self, Read, Write};
use std::path::Path;

use crc32fast::Hasher as Crc32;

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
/// YARA engine without recompiling. Version 3 is exav 0.0.1's; version 4
/// replaced the signature automatons with the anchor index and the pinned
/// bodies, and the trailing SHA-256 with a CRC-32. Bumped once per release
/// at most.
///
/// Enum variants are stored by index ([`to_vec_indexed`]), so reordering the
/// variants of a stored enum, or inserting one before others, changes the
/// format as much as a new field does: bump this then, and exav-update's
/// `EXAV_DB_VERSION` with it.
const VERSION: u32 = 4;
/// Fixed header: 8-byte magic + 4-byte little-endian version.
const HEADER_LEN: u64 = 12;
/// Trailing CRC-32 of the payload, little-endian. The file is trusted (see the
/// module docs), so this guards against a torn download or a damaged disk, not
/// against tampering: what a checksum is for, at a fraction of a hash's cost.
const DIGEST_LEN: u64 = 4;

/// Serialize one value to `w`, as [`to_vec_indexed`] encodes it.
pub(crate) fn enc<T: serde::Serialize, W: Write>(val: &T, w: &mut W) -> io::Result<()> {
    w.write_all(&to_vec_indexed(val)?)
}

/// Deserialize one value from `r`.
pub(crate) fn dec<T: serde::de::DeserializeOwned, R: Read>(r: &mut R) -> io::Result<T> {
    rmp_serde::decode::from_read(r).map_err(io::Error::other)
}

/// Encode `val` as MessagePack the way rmp-serde lays it out (structs as
/// arrays), except that an enum variant is written as its index rather than
/// its name: rmp-serde reads either, and an index is decoded without a string
/// compared per variant, which was a tenth of a load's time. Unlike rmp-serde,
/// it refuses a sequence or map of unknown length and 128-bit integers; no
/// stored type has either.
pub(crate) fn to_vec_indexed<T: serde::Serialize + ?Sized>(val: &T) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    val.serialize(Indexed(&mut out)).map_err(io::Error::other)?;
    Ok(out)
}

/// The serializer behind [`to_vec_indexed`].
struct Indexed<'a>(&'a mut Vec<u8>);

/// An error of [`Indexed`]: a length MessagePack cannot hold, or one serde
/// did not give.
#[derive(Debug)]
struct IndexedError(String);

impl std::fmt::Display for IndexedError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IndexedError {}

impl serde::ser::Error for IndexedError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        IndexedError(msg.to_string())
    }
}

impl From<rmp::encode::ValueWriteError> for IndexedError {
    fn from(e: rmp::encode::ValueWriteError) -> Self {
        IndexedError(e.to_string())
    }
}

impl From<std::io::Error> for IndexedError {
    fn from(e: std::io::Error) -> Self {
        IndexedError(e.to_string())
    }
}

fn len32(len: Option<usize>) -> Result<u32, IndexedError> {
    len.and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| IndexedError("a length unknown or past 2^32".into()))
}

impl<'a> serde::Serializer for Indexed<'a> {
    type Ok = ();
    type Error = IndexedError;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<(), IndexedError> {
        Ok(rmp::encode::write_bool(self.0, v)?)
    }
    fn serialize_i8(self, v: i8) -> Result<(), IndexedError> {
        self.serialize_i64(v as i64)
    }
    fn serialize_i16(self, v: i16) -> Result<(), IndexedError> {
        self.serialize_i64(v as i64)
    }
    fn serialize_i32(self, v: i32) -> Result<(), IndexedError> {
        self.serialize_i64(v as i64)
    }
    fn serialize_i64(self, v: i64) -> Result<(), IndexedError> {
        rmp::encode::write_sint(self.0, v)?;
        Ok(())
    }
    fn serialize_u8(self, v: u8) -> Result<(), IndexedError> {
        self.serialize_u64(v as u64)
    }
    fn serialize_u16(self, v: u16) -> Result<(), IndexedError> {
        self.serialize_u64(v as u64)
    }
    fn serialize_u32(self, v: u32) -> Result<(), IndexedError> {
        self.serialize_u64(v as u64)
    }
    fn serialize_u64(self, v: u64) -> Result<(), IndexedError> {
        rmp::encode::write_uint(self.0, v)?;
        Ok(())
    }
    fn serialize_f32(self, v: f32) -> Result<(), IndexedError> {
        Ok(rmp::encode::write_f32(self.0, v)?)
    }
    fn serialize_f64(self, v: f64) -> Result<(), IndexedError> {
        Ok(rmp::encode::write_f64(self.0, v)?)
    }
    fn serialize_char(self, v: char) -> Result<(), IndexedError> {
        self.serialize_str(v.encode_utf8(&mut [0; 4]))
    }
    fn serialize_str(self, v: &str) -> Result<(), IndexedError> {
        Ok(rmp::encode::write_str(self.0, v)?)
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<(), IndexedError> {
        Ok(rmp::encode::write_bin(self.0, v)?)
    }
    fn serialize_none(self) -> Result<(), IndexedError> {
        self.serialize_unit()
    }
    fn serialize_some<T: serde::Serialize + ?Sized>(self, v: &T) -> Result<(), IndexedError> {
        v.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), IndexedError> {
        Ok(rmp::encode::write_nil(self.0)?)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), IndexedError> {
        rmp::encode::write_array_len(self.0, 0)?;
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        index: u32,
        _: &'static str,
    ) -> Result<(), IndexedError> {
        self.serialize_u32(index)
    }
    fn serialize_newtype_struct<T: serde::Serialize + ?Sized>(
        self,
        _: &'static str,
        v: &T,
    ) -> Result<(), IndexedError> {
        v.serialize(self)
    }
    fn serialize_newtype_variant<T: serde::Serialize + ?Sized>(
        self,
        _: &'static str,
        index: u32,
        _: &'static str,
        v: &T,
    ) -> Result<(), IndexedError> {
        rmp::encode::write_map_len(self.0, 1)?;
        rmp::encode::write_uint(self.0, index as u64)?;
        v.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self, IndexedError> {
        rmp::encode::write_array_len(self.0, len32(len)?)?;
        Ok(self)
    }
    fn serialize_tuple(self, len: usize) -> Result<Self, IndexedError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(self, _: &'static str, len: usize) -> Result<Self, IndexedError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        index: u32,
        _: &'static str,
        len: usize,
    ) -> Result<Self, IndexedError> {
        rmp::encode::write_map_len(self.0, 1)?;
        rmp::encode::write_uint(self.0, index as u64)?;
        self.serialize_seq(Some(len))
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self, IndexedError> {
        rmp::encode::write_map_len(self.0, len32(len)?)?;
        Ok(self)
    }
    fn serialize_struct(self, _: &'static str, len: usize) -> Result<Self, IndexedError> {
        self.serialize_seq(Some(len))
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        index: u32,
        _: &'static str,
        len: usize,
    ) -> Result<Self, IndexedError> {
        self.serialize_tuple_variant("", index, "", len)
    }
    fn is_human_readable(&self) -> bool {
        false
    }
}

impl serde::ser::SerializeSeq for Indexed<'_> {
    type Ok = ();
    type Error = IndexedError;
    fn serialize_element<T: serde::Serialize + ?Sized>(
        &mut self,
        v: &T,
    ) -> Result<(), IndexedError> {
        v.serialize(Indexed(self.0))
    }
    fn end(self) -> Result<(), IndexedError> {
        Ok(())
    }
}

impl serde::ser::SerializeTuple for Indexed<'_> {
    type Ok = ();
    type Error = IndexedError;
    fn serialize_element<T: serde::Serialize + ?Sized>(
        &mut self,
        v: &T,
    ) -> Result<(), IndexedError> {
        v.serialize(Indexed(self.0))
    }
    fn end(self) -> Result<(), IndexedError> {
        Ok(())
    }
}

impl serde::ser::SerializeTupleStruct for Indexed<'_> {
    type Ok = ();
    type Error = IndexedError;
    fn serialize_field<T: serde::Serialize + ?Sized>(&mut self, v: &T) -> Result<(), IndexedError> {
        v.serialize(Indexed(self.0))
    }
    fn end(self) -> Result<(), IndexedError> {
        Ok(())
    }
}

impl serde::ser::SerializeTupleVariant for Indexed<'_> {
    type Ok = ();
    type Error = IndexedError;
    fn serialize_field<T: serde::Serialize + ?Sized>(&mut self, v: &T) -> Result<(), IndexedError> {
        v.serialize(Indexed(self.0))
    }
    fn end(self) -> Result<(), IndexedError> {
        Ok(())
    }
}

impl serde::ser::SerializeMap for Indexed<'_> {
    type Ok = ();
    type Error = IndexedError;
    fn serialize_key<T: serde::Serialize + ?Sized>(&mut self, k: &T) -> Result<(), IndexedError> {
        k.serialize(Indexed(self.0))
    }
    fn serialize_value<T: serde::Serialize + ?Sized>(&mut self, v: &T) -> Result<(), IndexedError> {
        v.serialize(Indexed(self.0))
    }
    fn end(self) -> Result<(), IndexedError> {
        Ok(())
    }
}

impl serde::ser::SerializeStruct for Indexed<'_> {
    type Ok = ();
    type Error = IndexedError;
    fn serialize_field<T: serde::Serialize + ?Sized>(
        &mut self,
        _: &'static str,
        v: &T,
    ) -> Result<(), IndexedError> {
        v.serialize(Indexed(self.0))
    }
    fn end(self) -> Result<(), IndexedError> {
        Ok(())
    }
}

impl serde::ser::SerializeStructVariant for Indexed<'_> {
    type Ok = ();
    type Error = IndexedError;
    fn serialize_field<T: serde::Serialize + ?Sized>(
        &mut self,
        _: &'static str,
        v: &T,
    ) -> Result<(), IndexedError> {
        v.serialize(Indexed(self.0))
    }
    fn end(self) -> Result<(), IndexedError> {
        Ok(())
    }
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

/// The payload of a database file, read once and checksummed as it goes, so
/// the integrity check does not cost a second read of the file.
struct HashedPayload<R> {
    inner: R,
    left: u64,
    hasher: Crc32,
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

/// Buffered above the checksum, so it is fed large pieces rather than every
/// few bytes a decoder asks for.
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

/// A writer that checksums everything passing through it (the payload).
struct HashWriter<W> {
    inner: W,
    hasher: Crc32,
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

/// Serialize a built database, framed as `MAGIC | VERSION | payload | crc32`.
pub fn write<W: Write>(db: &Scanner, mut w: W) -> io::Result<()> {
    w.write_all(MAGIC)?;
    w.write_all(&VERSION.to_le_bytes())?;
    let mut hw = HashWriter {
        inner: w,
        hasher: Crc32::new(),
    };
    write_payload(db, &mut hw)?;
    let digest = hw.hasher.finalize();
    hw.inner.write_all(&digest.to_le_bytes())?;
    // A buffered writer's last bytes go out here, where an error is seen,
    // not when it is dropped, where it is lost.
    hw.inner.flush()
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

/// Checksum the payload and compare to the stored trailer.
fn verify_digest(payload: &[u8], trailer: &[u8]) -> io::Result<()> {
    if crc32fast::hash(payload).to_le_bytes() != trailer {
        return Err(bad("database integrity check failed (checksum mismatch)"));
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

/// Load a database file from `path`, in one pass: the payload is checksummed
/// as it is decoded, and the checksum checked before the result is used,
/// without holding the file in memory.
pub fn load(path: &Path) -> io::Result<Scanner> {
    let mut f = std::fs::File::open(path)?;
    let total = f.metadata()?.len();
    let payload_len = read_header(&mut f, total)?;
    // A torn or corrupt file is rejected all the same; what decoding it can
    // do first is bounded, since no length in it is trusted past the end of
    // the payload.
    let hashed = HashedPayload {
        inner: f,
        left: payload_len,
        hasher: Crc32::new(),
    };
    let mut payload = io::BufReader::with_capacity(1 << 20, hashed);
    let decoded = read_payload(&mut payload);
    io::copy(&mut payload, &mut io::sink())?;
    let mut hashed = payload.into_inner();
    let mut trailer = [0u8; DIGEST_LEN as usize];
    hashed.inner.read_exact(&mut trailer)?;
    if hashed.hasher.finalize().to_le_bytes() != trailer {
        return Err(bad("database integrity check failed (checksum mismatch)"));
    }
    decoded
}

#[cfg(test)]
mod tests {
    use crate::{analyze, ScanOptions, Verdict};

    /// What the indexed encoder writes, rmp-serde reads back as the same
    /// value, every shape serde has; and no variant goes by its name.
    #[test]
    fn indexed_variants_read_back_as_written() {
        // The shared suffix is what the check below looks for in the bytes.
        #[allow(clippy::enum_variant_names)]
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        enum Shape {
            UnitVariantName,
            NewtypeVariantName(u32),
            TupleVariantName(i8, String),
            StructVariantName { a: Option<u64>, b: Vec<Shape> },
        }
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Unit;
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct All {
            shapes: Vec<Shape>,
            map: std::collections::BTreeMap<u16, (bool, char)>,
            none: Option<Shape>,
            unit: Unit,
            float: f64,
            neg: i64,
            #[serde(with = "super::opt_blob")]
            blob: Option<Vec<u8>>,
        }
        let v = All {
            shapes: vec![
                Shape::UnitVariantName,
                Shape::NewtypeVariantName(u32::MAX),
                Shape::TupleVariantName(-3, "é".into()),
                Shape::StructVariantName {
                    a: Some(1 << 40),
                    b: vec![
                        Shape::UnitVariantName,
                        Shape::StructVariantName { a: None, b: vec![] },
                    ],
                },
            ],
            map: [(7, (true, 'x')), (300, (false, '€'))].into(),
            none: None,
            unit: Unit,
            float: -2.5,
            neg: i64::MIN,
            blob: Some(vec![0, 255, 7]),
        };
        let bytes = super::to_vec_indexed(&v).unwrap();
        assert_eq!(rmp_serde::from_slice::<All>(&bytes).unwrap(), v);
        assert!(
            !bytes.windows(7).any(|w| w == b"Variant"),
            "a variant written by its name"
        );
        assert!(bytes.len() < rmp_serde::to_vec(&v).unwrap().len());
    }

    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn database_round_trip_matches_fresh_build() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        // A literal ndb sig, a wildcard ndb sig, a logical sig, and a hash sig;
        // and signatures their offset pins, checked where it puts them.
        std::fs::write(
            dir.path().join("a.ndb"),
            "Sig.Lit:0:*:6d616c6963696f7573\nSig.Wild:0:*:6d61*696f7573\n\
             Sig.Pin:0:0:4d5a9000ff\nSig.Wide:0:4,100:70696e6e6564\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.ldb"),
            "Sig.Logic;Engine:0-255;0&1;6d616c;696f7573\n\
             Sig.PinCI;Engine:51-255,Target:0;0;EOF-6:7a6f6d626965::i\n",
        )
        .unwrap();
        let d = crate::hashes::digests_of(b"hashme");
        std::fs::write(
            dir.path().join("c.hdb"),
            format!("{}:*:Sig.Hash\n", d.md5_hex()),
        )
        .unwrap();

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
        for (sample, want) in [
            (&b"MZ\x90\x00\xff then the rest"[..], Some("Sig.Pin")),
            (&b"abcdefpinned"[..], Some("Sig.Wide")),
            (&b"pinned too early"[..], None),
            (&b"its last word: ZoMbIe"[..], Some("Sig.PinCI")),
            (&b"zombie, but not last"[..], None),
        ] {
            for db in [&fresh, &loaded] {
                let v = analyze(db, sample, &opts).verdict;
                assert_eq!(
                    matches!(v, Verdict::Infected { .. }),
                    want.is_some(),
                    "{sample:?}: {v:?}"
                );
                if want.is_some() {
                    assert_eq!(v.detail(), want, "{sample:?}");
                }
            }
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

        // Flip a byte in the middle of the payload; the checksum must reject it.
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

    /// `load` decodes as it reads and checks the checksum at the end, so what it
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
        let d = crate::hashes::digests_of(b"hashme");
        std::fs::write(
            dir.path().join("c.hdb"),
            format!("{}:6:Sig.Md5\n", d.md5_hex()),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("d.hsb"),
            format!("{}:*:Sig.Sha\n", d.sha256_hex()),
        )
        .unwrap();
        let db = crate::loader::load(dir.path()).unwrap();
        let v = analyze(&db, b"hashme", &ScanOptions::default()).verdict;
        assert!(matches!(v, Verdict::Infected { .. }), "{v:?}");
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
