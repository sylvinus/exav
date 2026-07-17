#![allow(unused_imports)]
#![cfg_attr(
    not(feature = "decrypt"),
    allow(dead_code, unused_mut, unreachable_code)
)]
#[cfg(feature = "decrypt")]
use super::zip_crypto;
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// The encryption scheme + real (post-decrypt) compression method of an
/// encrypted ZIP member, plus the raw stored bytes.
pub struct EncryptedMember {
    pub raw: Vec<u8>,
    /// `None` = legacy PKWARE ZipCrypto; `Some(strength)` = WinZip AES
    /// (strength 1=AES-128, 2=AES-192, 3=AES-256).
    pub aes_strength: Option<u8>,
    /// Real compression method of the *decrypted* payload (0 = Store, 8 = Deflate).
    pub method: u16,
    /// High byte of the member's DOS mod-time, the ZipCrypto password-check byte
    /// for streaming (data-descriptor) archives — Info-ZIP `zip`'s default. `None`
    /// if the header carried no timestamp. Ignored for AES.
    pub dos_time_hi: Option<u8>,
}

/// Read the raw stored bytes of an encrypted member and classify its encryption
/// scheme + underlying compression method. For WinZip AES the member's
/// `compression()` is the `AesCrypto` wrapper, so the *real* method comes from
/// the 0x9901 AES extra field (parsed from the member's local extra data).
pub fn read_encrypted_member(
    file: &mut ::zip::read::ZipFile<'_, impl Read>,
    max_buffer: u64,
) -> Result<EncryptedMember, std::io::Error> {
    // The `zip` crate models a WinZip-AES member's `compression()` as a special
    // `Aes` method and stores the real method in the 0x9901 extra field.
    let (aes_strength, method) = parse_aes_extra(file.extra_data())
        .map(|(s, m)| (Some(s), m))
        .unwrap_or((None, compression_to_u16(file.compression())));
    // High byte of the 16-bit DOS mod-time — the ZipCrypto check byte for
    // data-descriptor archives (captured before the body is consumed).
    let dos_time_hi = file.last_modified().map(|dt| (dt.timepart() >> 8) as u8);
    // Bound the whole-member ciphertext read by the global peak-buffer limit;
    // the declared member size is attacker-controlled.
    let mut raw = Vec::new();
    (&mut *file)
        .take(max_buffer.saturating_add(1))
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > max_buffer {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted ZIP member exceeds max-buffer",
        ));
    }
    Ok(EncryptedMember {
        raw,
        aes_strength,
        method,
        dos_time_hi,
    })
}

/// Map the crate's `CompressionMethod` to the ZIP numeric method code we need
/// for post-decrypt decompression. Only Store/Deflate are decoded; anything else
/// is reported as Store (the bytes are passed through and scanned raw).
pub fn compression_to_u16(m: ::zip::CompressionMethod) -> u16 {
    match m {
        ::zip::CompressionMethod::Stored => 0,
        ::zip::CompressionMethod::Deflated => 8,
        _ => 0xffff,
    }
}

/// The ZIP numeric method code for a `CompressionMethod`, preserving the codec
/// identity (LZMA/BZIP2/ZSTD/XZ/PPMd) so [`decode_zip_raw`] can pick the right
/// decoder (APPNOTE 4.4.5).
// `CompressionMethod::Unsupported` is deprecated in the `zip` crate, but it is
// the only way to recover the raw method number for a codec the crate can't
// decode — which is exactly what we need to route to our own decoders.
#[allow(deprecated)]
fn zip_method_code(m: &::zip::CompressionMethod) -> u16 {
    use ::zip::CompressionMethod as C;
    // With only the `deflate-flate2` feature the crate collapses every codec it
    // can't handle (LZMA 14, BZIP2 12, ZSTD 93, XZ 95, PPMd 98, …) into
    // `Unsupported(code)`, so the real method number comes through there.
    match m {
        C::Stored => 0,
        C::Deflated => 8,
        C::Unsupported(n) => *n,
        _ => 0xffff,
    }
}

/// Decode a ZIP member the `zip` crate itself can't (LZMA/BZIP2/ZSTD/XZ) from its
/// RAW compressed bytes, using exav's own decoders — so a payload hidden behind a
/// codec the crate lacks is still extracted and scanned. `usz` is the header's
/// declared uncompressed size (LZMA needs it as the decode target; memory is
/// still bounded by `cap`). Returns `None` when the method isn't decodable in this
/// build; the caller then emits an `unsupported` member — never a silent clean.
#[allow(unused_variables)]
fn decode_zip_raw(method: u16, raw: &[u8], usz: u64, cap: u64) -> Option<(Vec<u8>, bool)> {
    match method {
        // APPNOTE 5.8.8: 2-byte version, 2-byte props-size (=5), then the 5-byte
        // LZMA properties (1 lc/lp/pb byte + 4-byte dict size), then the stream.
        #[cfg(feature = "lzip")]
        14 => {
            if raw.len() < 9 {
                return None;
            }
            let props = raw[4];
            let dict = u32::from_le_bytes([raw[5], raw[6], raw[7], raw[8]]);
            let reader = lzma_rust2::LzmaReader::new_with_props(
                Cursor::new(&raw[9..]),
                usz,
                props,
                dict,
                None,
            )
            .ok()?;
            bounded_read(reader, cap).ok()
        }
        #[cfg(feature = "bzip2")]
        12 => bounded_read(bzip2_rs::DecoderReader::new(Cursor::new(raw)), cap).ok(),
        #[cfg(feature = "zstd")]
        93 => {
            let d = ruzstd::decoding::StreamingDecoder::new(Cursor::new(raw)).ok()?;
            bounded_read(d, cap).ok()
        }
        // Method 95 = XZ: the raw member bytes are a complete .xz stream.
        #[cfg(feature = "xz")]
        95 => super::xz::decode_xz(raw, cap).ok(),
        _ => None,
    }
}

/// Parse the WinZip-AES 0x9901 extra field: `len(2)=7, ver(2), "AE"(2),
/// strength(1), method(2)`. Returns `(strength, real_method)`.
pub(crate) fn parse_aes_extra(extra: Option<&[u8]>) -> Option<(u8, u16)> {
    let mut data = extra?;
    while data.len() >= 4 {
        let id = u16::from_le_bytes([data[0], data[1]]);
        let len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let body = data.get(4..4 + len)?;
        if id == 0x9901 && body.len() >= 7 {
            let strength = body[4];
            let method = u16::from_le_bytes([body[5], body[6]]);
            return Some((strength, method));
        }
        data = &data[4 + len..];
    }
    None
}

/// Passwords exav tries automatically on an encrypted ZIP after the caller/DB
/// pool: the well-known malware-distribution conventions. A password-protected
/// dropper is a classic scanner-evasion trick, so cracking these zero-config
/// matters (mirrors the Office `VelvetSweatshop` default).
#[cfg(feature = "decrypt")]
const DEFAULT_ZIP_PASSWORDS: &[&str] = &["infected", "virus", "malware", "password", "123456"];

/// Try each pool password against the encrypted member; on the first that
/// decrypts (verifier/MAC for AES, CRC check byte for ZipCrypto), decompress per
/// the real method and return the plaintext. `None` if no password worked.
#[cfg(feature = "decrypt")]
pub fn decrypt_zip_member(
    enc: &EncryptedMember,
    crc: u32,
    budget: &mut Budget,
) -> Result<Option<Vec<u8>>, LimitHit> {
    // ZipCrypto's one-byte password check compares against the CRC-32 high byte,
    // or — for streaming (data-descriptor) archives, where the CRC wasn't known
    // at encryption time — the DOS mod-time high byte. We don't know which the
    // writer used, so accept either candidate; the full-payload CRC check below
    // is the real gate for the common Store/Deflate members.
    let mut check_bytes = [(crc >> 24) as u8; 2];
    let check_bytes: &[u8] = match enc.dos_time_hi {
        Some(t) => {
            check_bytes[1] = t;
            &check_bytes
        }
        None => &check_bytes[..1],
    };
    // Candidate passwords: the caller/DB pool first, then exav's built-in list of
    // passwords commonly used by malware-distribution ZIPs (the AV-sharing
    // convention "infected", etc.) so a password-protected dropper is cracked with
    // no configuration — mirroring the Office `VelvetSweatshop` default. Built into
    // an owned list so it doesn't borrow `budget` across the mutable `reserve()`.
    let mut candidates: Vec<Vec<u8>> = budget
        .passwords
        .iter()
        .map(|p| p.as_bytes().to_vec())
        .collect();
    candidates.extend(DEFAULT_ZIP_PASSWORDS.iter().map(|p| p.as_bytes().to_vec()));
    for pw in &candidates {
        let decrypted = match enc.aes_strength {
            Some(s) => zip_crypto::decrypt_aes(&enc.raw, s, pw),
            None => zip_crypto::decrypt_zipcrypto(&enc.raw, pw, check_bytes),
        };
        let Some(decrypted) = decrypted else { continue };
        // Decompress the decrypted payload per its real method, bounded.
        let cap = budget.reserve()?;
        let out = match enc.method {
            0 => {
                let take = (decrypted.len() as u64).min(cap) as usize;
                if decrypted.len() as u64 > cap {
                    return Err(LimitHit::new("decrypted zip member exceeds budget".into()));
                }
                decrypted[..take].to_vec()
            }
            8 => {
                let (buf, truncated) = bounded_read(
                    flate2::read::DeflateDecoder::new(Cursor::new(&decrypted[..])),
                    cap,
                )
                .map_err(|e| LimitHit::new(format!("zip inflate (decrypted): {e}")))?;
                if truncated {
                    return Err(LimitHit::new("decrypted zip member exceeds budget".into()));
                }
                buf
            }
            // A method we don't decode: hand back the decrypted (still-compressed)
            // bytes so name/size sigs and any embedded plaintext still match.
            _ => {
                if decrypted.len() as u64 > cap {
                    return Err(LimitHit::new("decrypted zip member exceeds budget".into()));
                }
                decrypted
            }
        };
        // Legacy ZipCrypto accepts on a single CRC byte (1/256 false-accept).
        // Validate the decompressed plaintext against the central-directory
        // CRC-32; on mismatch the password was wrong (or the member is corrupt),
        // so keep trying other passwords rather than handing back garbage that
        // would then be scanned as if it were the real cleartext. AES is already
        // authenticated by its verifier + HMAC, so this guards ZipCrypto only;
        // methods we don't decompress here can't be CRC-checked and fall through.
        if enc.aes_strength.is_none()
            && matches!(enc.method, 0 | 8)
            && zip_crypto::crc32_ieee(&out) != crc
        {
            continue;
        }
        return Ok(Some(out));
    }
    Ok(None)
}

pub(crate) fn extract_zip<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Normal pass: everything the central directory references. If the central
    // directory itself is unparseable (corrupt / forged / truncated — a `corrupt`
    // stop), don't give up: fall through to the raw local-header scan below, which
    // needs no central directory and salvages whatever members are still present.
    // Genuine budget stops from a member we already began extracting propagate.
    match extract_zip_from(Cursor::new(data), budget, &mut *visit) {
        Ok(Some(r)) => return Ok(Some(r)),
        Ok(None) => {}
        Err(e) if !e.corrupt => return Err(e),
        Err(_) => {}
    }
    // Dual indexing: a forged ZIP can hide a member by leaving it OUT of the
    // central directory (which the `zip` crate reads) while its Local File Header
    // + data still sit in the file — the OS/target still extracts it. Scan the raw
    // bytes for local headers the central directory doesn't cover and extract
    // those too, so a member hidden this way is still scanned. This is also the
    // salvage path when the central directory is unparseable.
    scan_orphan_locals(data, budget, visit)
}

/// Extract ZIP members present as Local File Headers but NOT listed in the
/// central directory (a central/local mismatch used to hide payloads). See
/// APPNOTE 4.3.7 for the local header layout.
fn scan_orphan_locals<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Local-header offsets the central directory already covered.
    let mut known = std::collections::HashSet::new();
    if let Ok(mut zip) = ::zip::ZipArchive::new(Cursor::new(data)) {
        for i in 0..zip.len() {
            if let Ok(f) = zip.by_index_raw(i) {
                known.insert(f.header_start() as usize);
            }
        }
    }
    const MAX_ORPHANS: usize = 256;
    let mut found = 0usize;
    let mut pos = 0usize;
    while pos + 30 <= data.len() && found < MAX_ORPHANS {
        let Some(rel) = memfind(&data[pos..], b"PK\x03\x04") else {
            break;
        };
        let off = pos + rel;
        pos = off + 4;
        if known.contains(&off) {
            continue;
        }
        match parse_local_member(data, off, budget)? {
            Some(entry) => {
                found += 1;
                if let Some(r) = visit(entry, budget) {
                    return Ok(Some(r));
                }
            }
            None => continue,
        }
    }
    Ok(None)
}

/// Find the first occurrence of `needle` in `hay`.
fn memfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse one Local File Header at `off` and extract+decompress its member.
/// Returns `None` (skip) for a header with no in-line size (streaming data
/// descriptor), an out-of-range extent, or a codec we can't decode here.
fn parse_local_member(
    data: &[u8],
    off: usize,
    budget: &mut Budget,
) -> Result<Option<Entry>, LimitHit> {
    let h = match data.get(off..off + 30) {
        Some(h) => h,
        None => return Ok(None),
    };
    let flags = u16::from_le_bytes([h[6], h[7]]);
    let method = u16::from_le_bytes([h[8], h[9]]);
    let comp = u32::from_le_bytes([h[18], h[19], h[20], h[21]]) as usize;
    let usz = u32::from_le_bytes([h[22], h[23], h[24], h[25]]) as u64;
    let name_len = u16::from_le_bytes([h[26], h[27]]) as usize;
    let extra_len = u16::from_le_bytes([h[28], h[29]]) as usize;
    // Streaming members (data-descriptor flag, sizes deferred) or a directory
    // entry give us no reliable length to carve — skip.
    if flags & 0x08 != 0 || comp == 0 {
        return Ok(None);
    }
    let data_start = off + 30 + name_len + extra_len;
    let raw = match data.get(data_start..data_start + comp) {
        Some(r) => r,
        None => return Ok(None),
    };
    let name = String::from_utf8_lossy(data.get(off + 30..off + 30 + name_len).unwrap_or(&[]))
        .into_owned();
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let out = match method {
        0 => raw
            .get(..(comp as u64).min(cap) as usize)
            .unwrap_or(raw)
            .to_vec(),
        8 => {
            // Salvage the bytes decoded before any corruption rather than
            // dropping the whole member: this is a best-effort recovery of a
            // malformed archive, and the payload a signature matches may sit in
            // the valid prefix (matching clamd, which scans partial inflate).
            let (o, truncated) = bounded_read_salvage(
                flate2::read::DeflateDecoder::new(Cursor::new(raw)),
                cap,
                true,
            )
            .map_err(|e| LimitHit::corrupt(format!("orphan zip inflate: {e}")))?;
            if truncated {
                return Ok(None);
            }
            o
        }
        _ => match decode_zip_raw(method, raw, usz, cap) {
            Some((o, false)) => o,
            _ => return Ok(None),
        },
    };
    ratio_guard(comp as u64, out.len() as u64, budget)?;
    budget.commit(out.len() as u64);
    Ok(Some(Entry {
        comp_size: comp as u64,
        encrypted: false,
        unsupported: None,
        name,
        data: out,
    }))
}

/// Stream a ZIP from any seekable reader, invoking `visit` per file member. With
/// a range-backed reader (e.g. HTTP) this reads only the central directory and
/// the members it actually decompresses, rather than the whole archive.
pub fn extract_zip_from<Rd: Read + Seek, R>(
    reader: Rd,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // A failure to open the archive means the central directory is unparseable
    // (corrupt/forged/truncated), NOT a resource limit — mark it `corrupt` so the
    // caller salvages via the local-header scan and the verdict is `Unscannable`,
    // never `LimitsExceeded`.
    let mut zip =
        ::zip::ZipArchive::new(reader).map_err(|e| LimitHit::corrupt(format!("zip: {e}")))?;
    for i in 0..zip.len() {
        // Count every central-directory entry, including directories, so a
        // directory-only archive cannot iterate past the file-count budget.
        budget.count_entry()?;
        // Peek the member with the RAW reader first: it never invokes the crate's
        // decryptor, so it succeeds for encrypted members too (which `by_index`
        // would reject — we build `zip` WITHOUT `aes-crypto`, the feature that
        // pulls `getrandom`). For an encrypted member we decrypt the raw bytes
        // ourselves; for a cleartext one we re-open with the decompressing reader.
        let mut file = zip
            .by_index_raw(i)
            .map_err(|e| LimitHit::new(format!("zip entry {i}: {e}")))?;
        if !file.is_file() {
            continue;
        }
        let name = file.name().to_string();
        let comp = file.compressed_size();
        // Codec + declared uncompressed size, captured from the raw header so we
        // can decode methods the `zip` crate lacks (LZMA/BZIP2/ZSTD) ourselves.
        let method = zip_method_code(&file.compression());
        let usz = file.size();

        // Encrypted member: try the password pool, decrypt+decompress on success,
        // else emit a metadata-only `PasswordProtected` signal.
        if file.encrypted() {
            // Without the `decrypt` feature there is no cipher stack compiled in,
            // so an encrypted member is reported as unsupported (never decrypted,
            // never silently clean) — the same as an encrypted member with no
            // password supplied.
            #[cfg(not(feature = "decrypt"))]
            {
                drop(file);
                let e = Entry::unsupported(name, comp, true, "encrypted ZIP member");
                if let Some(r) = visit(e, budget) {
                    return Ok(Some(r));
                }
                continue;
            }
            #[cfg(feature = "decrypt")]
            {
                let crc = file.crc32();
                let enc = match read_encrypted_member(&mut file, budget.limits.max_buffer_bytes()) {
                    Ok(e) => e,
                    Err(_) => {
                        drop(file);
                        let e = Entry::unsupported(name, comp, true, "encrypted ZIP member");
                        if let Some(r) = visit(e, budget) {
                            return Ok(Some(r));
                        }
                        continue;
                    }
                };
                drop(file);
                match decrypt_zip_member(&enc, crc, budget)? {
                    Some(plain) => {
                        budget.commit(plain.len() as u64);
                        let entry = Entry {
                            comp_size: comp,
                            encrypted: false,
                            unsupported: None,
                            name,
                            data: plain,
                        };
                        if let Some(r) = visit(entry, budget) {
                            return Ok(Some(r));
                        }
                    }
                    None => {
                        let e = Entry::unsupported(name, comp, true, "encrypted ZIP member");
                        if let Some(r) = visit(e, budget) {
                            return Ok(Some(r));
                        }
                    }
                }
            }
            continue;
        }
        // A member too large to decompress within budget would otherwise abort
        // the whole archive — and ClamAV reads `.cdb` member metadata
        // (name/size/encryption) from the header WITHOUT decompressing, so
        // aborting here is a false-negative on name/size-based container sigs
        // (e.g. a fake `…pdf.exe` dropper). Instead yield a metadata-only member
        // (flagged Unscannable, empty data) so `.cdb` still matches and the rest
        // of the archive is still scanned.
        let mut oversized = |budget: &mut Budget, reason: &'static str| -> Option<R> {
            visit(
                Entry::unsupported(name.clone(), comp, false, reason),
                budget,
            )
        };
        let cap = match budget.reserve() {
            Ok(c) => c,
            Err(_) => {
                drop(file);
                if let Some(r) = oversized(budget, "archive member exceeds size budget") {
                    return Ok(Some(r));
                }
                continue;
            }
        };

        // Codec the `zip` crate can't decode (LZMA/BZIP2/ZSTD/…): decode the raw
        // bytes with exav's own decoders so the payload isn't hidden behind an
        // unsupported method. A decode we can't do (or an unknown codec) yields a
        // metadata-only unsupported member and the archive keeps going — one bad
        // member never aborts the whole ZIP.
        let (buf, truncated) = if method != 0 && method != 8 {
            let (raw, _) = bounded_read(&mut file, budget.limits.max_buffer_bytes())
                .map_err(|e| LimitHit::new(format!("zip raw read: {e}")))?;
            drop(file);
            match decode_zip_raw(method, &raw, usz, cap) {
                Some(out) => out,
                None => {
                    if let Some(r) = oversized(budget, "archive member: unsupported ZIP codec") {
                        return Ok(Some(r));
                    }
                    continue;
                }
            }
        } else {
            // Store/Deflate: re-open with the decompressing reader (the raw reader
            // returns still-compressed bytes).
            drop(file);
            let mut file = match zip.by_index(i) {
                Ok(f) => f,
                Err(_) => {
                    if let Some(r) = oversized(budget, "archive member: ZIP decode failed") {
                        return Ok(Some(r));
                    }
                    continue;
                }
            };
            let r = bounded_read_salvage(&mut file, cap, !budget.should_verify_checksums())
                .map_err(|e| LimitHit::new(format!("zip read: {e}")))?;
            drop(file);
            r
        };
        if truncated {
            if let Some(r) = oversized(budget, "archive member exceeds size budget") {
                return Ok(Some(r));
            }
            continue;
        }
        // `comp` is attacker-controlled; the absolute caps above are the real
        // bound. The ratio check is only a fast reject when comp is plausible.
        ratio_guard(comp, buf.len() as u64, budget)?;
        budget.commit(buf.len() as u64);
        // Compressed size is meaningful for `.cdb` `FileSizeInContainer`.
        let entry = Entry {
            comp_size: comp,
            encrypted: false,
            unsupported: None,
            name,
            data: buf,
        };
        if let Some(r) = visit(entry, budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// Lazy, seekable ZIP reader: yields one [`Entry`] at a time so a range-backed
/// reader (e.g. an HTTP range request over a remote ZIP) only fetches the
/// member currently being read, and the caller can stop early — e.g. on the
/// first detection — without touching later members. This is the seekable
/// counterpart to [`extract`], which buffers everything.
pub struct ZipMembers<R: Read + Seek> {
    zip: ::zip::ZipArchive<R>,
    next: usize,
}

impl<R: Read + Seek> ZipMembers<R> {
    /// Open a seekable ZIP (reads only the central directory up front).
    pub fn open(reader: R) -> Result<Self, LimitHit> {
        let zip = ::zip::ZipArchive::new(reader).map_err(|e| LimitHit::new(format!("zip: {e}")))?;
        Ok(Self { zip, next: 0 })
    }

    /// Number of central-directory entries (files and directories).
    pub fn len(&self) -> usize {
        self.zip.len()
    }
    pub fn is_empty(&self) -> bool {
        self.zip.is_empty()
    }

    /// Pre-parsed member metadata from the central directory. Directories are
    /// included (with `uncompressed_size` 0). No member data is decompressed.
    pub fn list_entries(&mut self) -> Vec<crate::MemberInfo> {
        let mut out = Vec::with_capacity(self.zip.len());
        for i in 0..self.zip.len() {
            if let Ok(file) = self.zip.by_index_raw(i) {
                out.push(crate::MemberInfo {
                    name: file.name().to_string(),
                    index: i,
                    compressed_size: file.compressed_size(),
                    uncompressed_size: file.size(),
                    encrypted: file.encrypted(),
                });
            }
        }
        out
    }

    /// Read and decompress the next *file* member under `budget`; `None` when
    /// the archive is exhausted. Directories are skipped (but still counted
    /// toward the file-count budget).
    pub fn next_member(&mut self, budget: &mut Budget) -> Option<Result<Entry, LimitHit>> {
        while self.next < self.zip.len() {
            let i = self.next;
            self.next += 1;
            if let Err(h) = budget.count_entry() {
                return Some(Err(h));
            }
            match self.extract_entry(i, budget) {
                Ok(Some(e)) => return Some(Ok(e)),
                Ok(None) => continue,
                Err(h) => return Some(Err(h)),
            }
        }
        None
    }

    /// Extract a specific member by index. Returns `Ok(None)` for directories.
    pub(crate) fn extract_entry(
        &mut self,
        i: usize,
        budget: &mut Budget,
    ) -> Result<Option<Entry>, LimitHit> {
        // Peek with the RAW reader: it never invokes the crate decryptor,
        // so it succeeds for encrypted members too (we build `zip` WITHOUT
        // `aes-crypto`). Cleartext members are re-opened decompressing below.
        let mut file = self
            .zip
            .by_index_raw(i)
            .map_err(|e| LimitHit::new(format!("zip entry {i}: {e}")))?;
        if !file.is_file() {
            return Ok(None);
        }
        let name = file.name().to_string();
        let comp = file.compressed_size();
        // Encrypted member: try the password pool; on success yield the
        // decrypted+decompressed bytes, else a metadata-only encrypted
        // member so the caller surfaces PasswordProtected (never a panic
        // or an abort that would mask later members).
        if file.encrypted() {
            #[cfg(not(feature = "decrypt"))]
            {
                drop(file);
                return Ok(Some(Entry::unsupported(
                    name,
                    comp,
                    true,
                    "encrypted ZIP member",
                )));
            }
            #[cfg(feature = "decrypt")]
            {
                let crc = file.crc32();
                let enc = match read_encrypted_member(&mut file, budget.limits.max_buffer_bytes()) {
                    Ok(e) => e,
                    Err(_) => {
                        return Ok(Some(Entry::unsupported(
                            name,
                            comp,
                            true,
                            "encrypted ZIP member",
                        )))
                    }
                };
                drop(file);
                return match decrypt_zip_member(&enc, crc, budget)? {
                    Some(plain) => {
                        budget.commit(plain.len() as u64);
                        Ok(Some(Entry {
                            comp_size: comp,
                            encrypted: false,
                            unsupported: None,
                            name,
                            data: plain,
                        }))
                    }
                    None => Ok(Some(Entry::unsupported(
                        name,
                        comp,
                        true,
                        "encrypted ZIP member",
                    ))),
                };
            }
        }
        // Cleartext member: re-open decompressing so `bounded_read` yields
        // the *decompressed* content.
        drop(file);
        let mut file = self
            .zip
            .by_index(i)
            .map_err(|e| LimitHit::new(format!("zip entry {i}: {e}")))?;
        // A member too large for the budget yields a metadata-only member
        // (Unscannable, empty data) rather than aborting the archive walk,
        // so name/size `.cdb` sigs still match and later members are scanned.
        let cap = match budget.reserve() {
            Ok(c) => c,
            Err(_) => {
                return Ok(Some(Entry::unsupported(
                    name,
                    comp,
                    false,
                    "archive member exceeds size budget",
                )))
            }
        };
        let (buf, truncated) =
            bounded_read_salvage(&mut file, cap, !budget.should_verify_checksums())
                .map_err(|e| LimitHit::new(format!("zip read: {e}")))?;
        if truncated {
            return Ok(Some(Entry::unsupported(
                name,
                comp,
                false,
                "archive member exceeds size budget",
            )));
        }
        ratio_guard(comp, buf.len() as u64, budget)?;
        budget.commit(buf.len() as u64);
        Ok(Some(Entry {
            comp_size: comp,
            encrypted: false,
            unsupported: None,
            name,
            data: buf,
        }))
    }
}
