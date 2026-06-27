#![allow(unused_imports)]
use crate::*;
use super::zip_crypto;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// The encryption scheme + real (post-decrypt) compression method of an
/// encrypted ZIP member, plus the raw stored bytes.
struct EncryptedMember {
    raw: Vec<u8>,
    /// `None` = legacy PKWARE ZipCrypto; `Some(strength)` = WinZip AES
    /// (strength 1=AES-128, 2=AES-192, 3=AES-256).
    aes_strength: Option<u8>,
    /// Real compression method of the *decrypted* payload (0 = Store, 8 = Deflate).
    method: u16,
}

/// Read the raw stored bytes of an encrypted member and classify its encryption
/// scheme + underlying compression method. For WinZip AES the member's
/// `compression()` is the `AesCrypto` wrapper, so the *real* method comes from
/// the 0x9901 AES extra field (parsed from the member's local extra data).
fn read_encrypted_member(
    file: &mut zip::read::ZipFile<'_>,
) -> Result<EncryptedMember, std::io::Error> {
    // The `zip` crate models a WinZip-AES member's `compression()` as a special
    // `Aes` method and stores the real method in the 0x9901 extra field.
    let (aes_strength, method) = parse_aes_extra(file.extra_data())
        .map(|(s, m)| (Some(s), m))
        .unwrap_or((None, compression_to_u16(file.compression())));
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    Ok(EncryptedMember {
        raw,
        aes_strength,
        method,
    })
}

/// Map the crate's `CompressionMethod` to the ZIP numeric method code we need
/// for post-decrypt decompression. Only Store/Deflate are decoded; anything else
/// is reported as Store (the bytes are passed through and scanned raw).
fn compression_to_u16(m: zip::CompressionMethod) -> u16 {
    match m {
        zip::CompressionMethod::Stored => 0,
        #[allow(deprecated)]
        zip::CompressionMethod::Deflated => 8,
        _ => 0xffff,
    }
}

/// Parse the WinZip-AES 0x9901 extra field: `len(2)=7, ver(2), "AE"(2),
/// strength(1), method(2)`. Returns `(strength, real_method)`.
fn parse_aes_extra(extra: Option<&[u8]>) -> Option<(u8, u16)> {
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

/// Try each pool password against the encrypted member; on the first that
/// decrypts (verifier/MAC for AES, CRC check byte for ZipCrypto), decompress per
/// the real method and return the plaintext. `None` if no password worked.
fn decrypt_zip_member(
    enc: &EncryptedMember,
    crc: u32,
    budget: &mut Budget,
) -> Result<Option<Vec<u8>>, LimitHit> {
    let check_byte = (crc >> 24) as u8;
    // Try each password by index so the immutable `passwords` slice isn't borrowed
    // across the mutable `budget.reserve()` below.
    for idx in 0..budget.passwords.len() {
        let decrypted = {
            let pw = budget.passwords[idx].as_bytes();
            match enc.aes_strength {
                Some(s) => zip_crypto::decrypt_aes(&enc.raw, s, pw),
                None => zip_crypto::decrypt_zipcrypto(&enc.raw, pw, check_byte),
            }
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
    extract_zip_from(Cursor::new(data), budget, visit)
}

/// Stream a ZIP from any seekable reader, invoking `visit` per file member. With
/// a range-backed reader (e.g. HTTP) this reads only the central directory and
/// the members it actually decompresses, rather than the whole archive.
pub fn extract_zip_from<Rd: Read + Seek, R>(
    reader: Rd,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| LimitHit::new(format!("zip: {e}")))?;
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

        // Encrypted member: try the password pool, decrypt+decompress on success,
        // else emit a metadata-only `PasswordProtected` signal.
        if file.encrypted() {
            let crc = file.crc32();
            let enc = match read_encrypted_member(&mut file) {
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
            continue;
        }
        // Cleartext member: re-open with the decompressing reader so `bounded_read`
        // below yields the *decompressed* content (the raw reader returns the
        // still-compressed bytes).
        drop(file);
        let mut file = zip
            .by_index(i)
            .map_err(|e| LimitHit::new(format!("zip entry {i}: {e}")))?;
        // A member too large to decompress within budget would otherwise abort
        // the whole archive — and ClamAV reads `.cdb` member metadata
        // (name/size/encryption) from the header WITHOUT decompressing, so
        // aborting here is a false-negative on name/size-based container sigs
        // (e.g. a fake `…pdf.exe` dropper). Instead yield a metadata-only member
        // (flagged Unscannable, empty data) so `.cdb` still matches and the rest
        // of the archive is still scanned.
        let mut oversized = |budget: &mut Budget| -> Option<R> {
            visit(
                Entry::unsupported(name.clone(), comp, false, "archive member exceeds size budget"),
                budget,
            )
        };
        let cap = match budget.reserve() {
            Ok(c) => c,
            Err(_) => {
                drop(file);
                if let Some(r) = oversized(budget) {
                    return Ok(Some(r));
                }
                continue;
            }
        };
        let (buf, truncated) =
            bounded_read(&mut file, cap).map_err(|e| LimitHit::new(format!("zip read: {e}")))?;
        if truncated {
            drop(file);
            if let Some(r) = oversized(budget) {
                return Ok(Some(r));
            }
            continue;
        }
        // `comp` is attacker-controlled; the absolute caps above are the real
        // bound. The ratio check is only a fast reject when comp is plausible.
        ratio_guard(comp, buf.len() as u64, budget)?;
        budget.commit(buf.len() as u64);
        drop(file); // release the &mut zip borrow before the visitor runs
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
    zip: zip::ZipArchive<R>,
    next: usize,
}

impl<R: Read + Seek> ZipMembers<R> {
    /// Open a seekable ZIP (reads only the central directory up front).
    pub fn open(reader: R) -> Result<Self, LimitHit> {
        let zip = zip::ZipArchive::new(reader).map_err(|e| LimitHit::new(format!("zip: {e}")))?;
        Ok(Self { zip, next: 0 })
    }

    /// Number of central-directory entries (files and directories).
    pub fn len(&self) -> usize {
        self.zip.len()
    }
    pub fn is_empty(&self) -> bool {
        self.zip.is_empty()
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
            let res = (|| -> Result<Option<Entry>, LimitHit> {
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
                    let crc = file.crc32();
                    let enc = match read_encrypted_member(&mut file) {
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
                let (buf, truncated) = bounded_read(&mut file, cap)
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
            })();
            match res {
                Ok(Some(e)) => return Some(Ok(e)),
                Ok(None) => continue,
                Err(h) => return Some(Err(h)),
            }
        }
        None
    }
}
