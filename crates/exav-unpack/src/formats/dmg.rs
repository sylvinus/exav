#![cfg_attr(
    not(feature = "decrypt"),
    allow(dead_code, unused_mut, unused_imports, unreachable_code)
)]
// Every sum and product on a header's number is checked or saturating here; a
// plain one fails the build, so the next edit cannot add the unchecked kind.
#![deny(clippy::arithmetic_side_effects)]
use crate::source::{ByteSource, Reader};
use crate::*;
use std::io::{Cursor, Read, Seek, SeekFrom};

/// "koly": the UDIF trailer signature (last 512 bytes of the file).
const KOLY_SIG: &[u8; 4] = b"koly";

/// Whether `trailer`, the first 12 bytes of an object's last 512, is a UDIF
/// `koly` trailer: its signature, version 4, and its own size, 512.
pub(crate) fn is_koly(trailer: &[u8]) -> bool {
    trailer.len() >= 12
        && trailer[..4] == KOLY_SIG[..]
        && trailer[4..8] == 4u32.to_be_bytes()
        && trailer[8..12] == 512u32.to_be_bytes()
}

/// "encrcdsa": encrypted DMG header signature.
const ENCRCDSA_SIG: &[u8; 8] = b"encrcdsa";

/// HFS+ volume header signature (big-endian 0x482B).
const HFS_PLUS_SIG: [u8; 2] = [0x48, 0x2B];

/// APFS container superblock signature "NXSB".
const APFS_SIG: &[u8; 4] = b"NXSB";

// ─── Detection ───────────────────────────────────────────────────────────────

pub(crate) fn is_dmg(p: &Probe) -> bool {
    let data = p.head;
    if p.len == 0 {
        return false;
    }
    if p.len >= 512 && p.window(p.len.saturating_sub(512), 4)[..] == KOLY_SIG[..] {
        return true;
    }
    if data.len() >= 8 && &data[0..8] == ENCRCDSA_SIG {
        return true;
    }
    // Both signatures are checked through the same validators the extractor
    // uses, so `detect` cannot claim a file the extractor will then refuse.
    find_hfs_offset(data).is_some() || find_apfs_offset(data).is_some()
}

/// HFSX, the case-sensitive variant, uses a different signature and version.
const HFSX_SIG: [u8; 2] = [0x48, 0x58];

/// Does a plausible HFS+/HFSX volume header start at `off`?
///
/// The signature alone is **two bytes**. Scanning 64 KiB at 16-byte steps gives
/// about four thousand chances for it to appear by accident, so on arbitrary
/// data (a compressed archive, say) it hits perhaps one time in twenty. That
/// is not a theoretical worry: it costs the file its real format, because
/// whatever it actually was is never tried once `detect` has answered `Dmg`.
///
/// So the signature has to be corroborated. The two fields right after it are
/// enough: the version is 4 (HFS+) or 5 (HFSX), and the allocation block size is
/// a power of two of at least 512. Together they take the false-positive rate to
/// somewhere around one in a billion.
fn plausible_hfs_header(data: &[u8], off: usize) -> bool {
    let Some(h) = crate::bytes::at(data, off, 44) else {
        return false;
    };
    let sig = [h[0], h[1]];
    let version = u16::from_be_bytes([h[2], h[3]]);
    let ok_sig = (sig == HFS_PLUS_SIG && version == 4) || (sig == HFSX_SIG && version == 5);
    if !ok_sig {
        return false;
    }
    // `blockSize` sits at offset 40 of the volume header.
    let block_size = u32::from_be_bytes([h[40], h[41], h[42], h[43]]);
    block_size >= 512 && block_size.is_power_of_two()
}

fn find_hfs_offset(data: &[u8]) -> Option<usize> {
    let limit = data.len().min(64 * 1024);
    (0..limit)
        .step_by(16)
        .find(|&off| plausible_hfs_header(data, off))
}

/// The APFS container superblock's `nx_block_size`, which corroborates the
/// four-byte signature the same way the HFS+ check does. Four bytes is a much
/// stronger start than two, but the object header before it is free to check.
/// `off` is where `NXSB` itself sits, which is 32 bytes into the superblock:
/// the object header (checksum, oid, xid, type, subtype) comes first.
/// `nx_block_size` is the field immediately after the magic.
fn plausible_apfs_header(data: &[u8], off: usize) -> bool {
    let Some(h) = crate::bytes::at(data, off, 8) else {
        return false;
    };
    if &h[0..4] != APFS_SIG {
        return false;
    }
    let block_size = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
    block_size >= 512 && block_size.is_power_of_two()
}

fn find_apfs_offset(data: &[u8]) -> Option<usize> {
    let limit = data.len().min(64 * 1024);
    (0..limit)
        .step_by(16)
        .find(|&off| plausible_apfs_header(data, off))
}

// ─── Encrypted DMG header parsing ────────────────────────────────────────────

/// The fields exav uses of an Apple encrypted DMG (`encrcdsa`, version 2)
/// header: 264 bytes, big-endian, laid out as dmgwiz's `EncryptedDmgHeader`.
#[cfg(feature = "decrypt")]
struct EncryptedDmgHeader {
    version: u32,
    data_enc_key_bits: u32,
    hmac_key_bits: u32,
    blocksize: u32,
    datasize: u64,
    dataoffset: u64,
    kdf_iteration_count: u32,
    kdf_salt_len: u32,
    kdf_salt: [u8; 32],
    blob_enc_iv_size: u32,
    blob_enc_iv: [u8; 32],
    encrypted_keyblob_size: u32,
    encrypted_keyblob1: [u8; 32],
    encrypted_keyblob2: [u8; 32],
}

#[cfg(feature = "decrypt")]
fn parse_encrypted_header(data: &[u8]) -> Result<EncryptedDmgHeader, LimitHit> {
    let h = data
        .get(..264)
        .ok_or_else(|| LimitHit::corrupt("encrypted DMG header truncated".into()))?;
    if &h[..8] != b"encrcdsa" {
        return Err(LimitHit::corrupt("missing encrcdsa signature".into()));
    }
    let u32_at = |o: usize| u32::from_be_bytes(h[o..o.saturating_add(4)].try_into().unwrap());
    let u64_at = |o: usize| u64::from_be_bytes(h[o..o.saturating_add(8)].try_into().unwrap());
    let bytes_at = |o: usize| -> [u8; 32] { h[o..o.saturating_add(32)].try_into().unwrap() };
    let header = EncryptedDmgHeader {
        version: u32_at(8),
        data_enc_key_bits: u32_at(24),
        hmac_key_bits: u32_at(32),
        blocksize: u32_at(52),
        datasize: u64_at(56),
        dataoffset: u64_at(64),
        kdf_iteration_count: u32_at(104),
        kdf_salt_len: u32_at(108),
        kdf_salt: bytes_at(112),
        blob_enc_iv_size: u32_at(144),
        blob_enc_iv: bytes_at(148),
        encrypted_keyblob_size: u32_at(196),
        encrypted_keyblob1: bytes_at(200),
        encrypted_keyblob2: bytes_at(232),
    };
    // Both index fixed-size arrays further on.
    if header.kdf_salt_len > 32 || header.encrypted_keyblob_size > 64 {
        return Err(LimitHit::corrupt(
            "encrypted DMG header sizes out of range".into(),
        ));
    }
    Ok(header)
}

// ─── Decryption ──────────────────────────────────────────────────────────────

/// Derive a 24-byte key from password using PBKDF2-HMAC-SHA1.
#[cfg(feature = "decrypt")]
fn derive_key_dmg(password: &[u8], salt: &[u8; 32], salt_len: u32, iterations: u32) -> [u8; 24] {
    let iter =
        std::num::NonZeroU32::new(iterations).unwrap_or(std::num::NonZeroU32::new(1000).unwrap());
    let mut key = [0u8; 24];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, &salt[..salt_len as usize], iter.get(), &mut key);
    key
}

/// Decrypt the keyblob using 3DES-CBC.
#[cfg(feature = "decrypt")]
fn decrypt_keyblob(
    header: &EncryptedDmgHeader,
    derived_key: &[u8; 24],
) -> Result<Vec<u8>, LimitHit> {
    use cbc::cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};

    let iv_len = header.blob_enc_iv_size as usize;
    let mut iv = [0u8; 8];
    iv[..iv_len.min(8)].copy_from_slice(&header.blob_enc_iv[..iv_len.min(8)]);

    let mut keyblob = [0u8; 64];
    let kb_len = header.encrypted_keyblob_size as usize;
    let part1 = header.encrypted_keyblob1;
    let part2 = header.encrypted_keyblob2;
    keyblob[..32].copy_from_slice(&part1);
    keyblob[32..32 + 32].copy_from_slice(&part2);
    let ciphertext = &keyblob[..kb_len];

    // 3DES-CBC decrypt with NoPadding, then truncate to plaintext length.
    type TdesCbc = cbc::Decryptor<des::TdesEde3>;
    let mut buf = ciphertext.to_vec();
    // Pad to multiple of 8.
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
    let decryptor = TdesCbc::new_from_slices(derived_key, &iv)
        .map_err(|_| LimitHit::corrupt("invalid 3DES key/iv length".into()))?;
    let plaintext = decryptor
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|_| {
            LimitHit::corrupt("3DES keyblob decryption failed (wrong password?)".into())
        })?;
    Ok(plaintext.to_vec())
}

/// Compute per-chunk IV using HMAC-SHA1(hmac_key, chunk_no_be32)[0..16].
#[cfg(feature = "decrypt")]
fn compute_chunk_iv(hmac_key: &[u8], chunk_no: u32) -> [u8; 16] {
    use hmac::{Hmac, KeyInit, Mac};
    type HmacSha1 = Hmac<sha1::Sha1>;

    let mut mac = HmacSha1::new_from_slice(hmac_key).expect("HMAC accepts any key size");
    mac.update(&chunk_no.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&result[..16]);
    iv
}

/// Decrypt the encrypted DMG data using the given password.
/// Returns the decrypted raw disk image, or None if the password is wrong.
#[cfg(feature = "decrypt")]
fn try_decrypt_dmg(data: &[u8], password: &str) -> Result<Vec<u8>, LimitHit> {
    let header = parse_encrypted_header(data)?;

    if header.version != 2 {
        return Err(LimitHit::corrupt(format!(
            "unsupported encrypted DMG version {}",
            header.version
        )));
    }

    // Only support AES-128-CBC and AES-256-CBC.
    let aes_key_bytes = header.data_enc_key_bits as usize / 8;
    if aes_key_bytes != 16 && aes_key_bytes != 32 {
        return Err(LimitHit::corrupt(format!(
            "unsupported AES key size {} bits",
            header.data_enc_key_bits
        )));
    }

    let hmac_key_bytes = header.hmac_key_bits as usize / 8;

    // Derive key from password.
    let derived_key = derive_key_dmg(
        password.as_bytes(),
        &header.kdf_salt,
        header.kdf_salt_len,
        header.kdf_iteration_count,
    );

    // Decrypt keyblob to get AES key + HMAC key.
    let keyblob = decrypt_keyblob(&header, &derived_key)?;
    let keys_end = aes_key_bytes.saturating_add(hmac_key_bytes);
    if keyblob.len() < keys_end {
        return Err(LimitHit::corrupt(
            "keyblob too short after decryption".into(),
        ));
    }
    let aes_key = &keyblob[..aes_key_bytes];
    let hmac_key = &keyblob[aes_key_bytes..keys_end];

    // Decrypt all chunks. `blocksize` is an attacker-controlled u32; bound the
    // single chunk allocation by the (default) global peak-buffer limit and
    // reject a zero block size (which would divide-by-zero below).
    let chunk_size = header.blocksize as usize;
    if chunk_size == 0 || chunk_size as u64 > crate::Limits::default().max_buffer_bytes {
        return Err(LimitHit::new(
            "DMG block size invalid or exceeds max-buffer".into(),
        ));
    }
    let data_size = crate::bytes::to_usize(header.datasize);
    let data_start = crate::bytes::to_usize(header.dataoffset);
    let num_chunks = data_size.div_ceil(chunk_size);

    let mut plaintext = Vec::with_capacity(crate::cap_prealloc(data_size));
    let mut chunk_buf = vec![0u8; chunk_size];

    for chunk_no in 0..num_chunks {
        let src_start = chunk_no
            .checked_mul(chunk_size)
            .and_then(|n| n.checked_add(data_start))
            .filter(|&s| s < data.len());
        let Some(src_start) = src_start else {
            break;
        };
        let src_end = src_start.saturating_add(chunk_size).min(data.len());
        let src_len = src_end.saturating_sub(src_start);
        chunk_buf[..src_len].copy_from_slice(&data[src_start..src_end]);
        if src_len < chunk_size {
            // Last chunk may be short; pad with zeros for decryption.
            chunk_buf[src_len..chunk_size].fill(0);
        }

        let iv = compute_chunk_iv(hmac_key, chunk_no as u32);

        // AES-CBC decrypt.
        use cbc::cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};
        type Aes128Cbc = cbc::Decryptor<aes::Aes128>;
        type Aes256Cbc = cbc::Decryptor<aes::Aes256>;

        let remain = data_size.saturating_sub(plaintext.len());
        let to_write = remain.min(chunk_size);

        if aes_key_bytes == 16 {
            let decryptor = Aes128Cbc::new_from_slices(aes_key, &iv)
                .map_err(|_| LimitHit::corrupt("invalid AES-128 key/iv".into()))?;
            let mut buf = chunk_buf[..chunk_size].to_vec();
            match decryptor.decrypt_padded::<NoPadding>(&mut buf) {
                Ok(pt) => plaintext.extend_from_slice(&pt[..to_write]),
                Err(_) => {
                    return Err(LimitHit::corrupt(
                        "AES-128 decryption failed (wrong password?)".into(),
                    ))
                }
            }
        } else {
            let decryptor = Aes256Cbc::new_from_slices(aes_key, &iv)
                .map_err(|_| LimitHit::corrupt("invalid AES-256 key/iv".into()))?;
            let mut buf = chunk_buf[..chunk_size].to_vec();
            match decryptor.decrypt_padded::<NoPadding>(&mut buf) {
                Ok(pt) => plaintext.extend_from_slice(&pt[..to_write]),
                Err(_) => {
                    return Err(LimitHit::corrupt(
                        "AES-256 decryption failed (wrong password?)".into(),
                    ))
                }
            }
        }
    }

    Ok(plaintext)
}

// ─── Extraction ──────────────────────────────────────────────────────────────

/// Walk a DMG off its source, each file handed to `visit`. The disk image is
/// decompressed a run at a time as the filesystem reaches it, never whole.
pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    budget.count_entry()?;
    let mut emit =
        |entry: Entry, budget: &mut Budget| crate::stream::emit_entry(entry, budget, &mut *visit);
    if src.window(0, 8)[..] != ENCRCDSA_SIG[..] {
        return walk_disk(Reader::new(src), budget, &mut emit);
    }
    match decrypt_image(src, budget)? {
        Ok(disk) => walk_disk(Cursor::new(disk), budget, &mut emit),
        Err(reason) => emit(
            Entry::unsupported("encrypted.dmg".to_string(), src.len() as u64, true, reason),
            budget,
        ),
    }
}

type Emit<'a, T> = &'a mut dyn FnMut(Entry, &mut Budget) -> Result<Option<T>, LimitHit>;

/// The decrypted image of an encrypted DMG, or why it was not decrypted.
/// Decryption takes the whole image.
fn decrypt_image(
    src: &dyn ByteSource,
    budget: &Budget,
) -> Result<Result<Vec<u8>, &'static str>, LimitHit> {
    #[cfg(not(feature = "decrypt"))]
    {
        let _ = (src, budget);
        Ok(Err("encrypted DMG (decrypt feature disabled)"))
    }
    #[cfg(feature = "decrypt")]
    {
        if budget.passwords.is_empty() {
            return Ok(Err("encrypted DMG (no password provided)"));
        }
        let data = crate::stream::read_whole(Format::Dmg, src, budget)?;
        for pw in &budget.passwords {
            let Ok(decrypted) = try_decrypt_dmg(&data, pw) else {
                continue;
            };
            // A right password gives a koly trailer or a filesystem.
            let has_koly = decrypted.len() >= 512
                && crate::bytes::at(&decrypted, decrypted.len().saturating_sub(512), 4)
                    == Some(KOLY_SIG.as_slice());
            let has_fs =
                find_hfs_offset(&decrypted).is_some() || find_apfs_offset(&decrypted).is_some();
            if has_koly || has_fs {
                return Ok(Ok(decrypted));
            }
        }
        // The reason is `&'static str`, one of a fixed set rather than a
        // formatted string: leaking a fresh allocation per attempt would let
        // anyone grow a long-running daemon without bound by resubmitting
        // encrypted images. Which decryption step objected does not change what
        // the operator does about it: supply the password.
        Ok(Err("encrypted DMG (wrong password, decryption failed)"))
    }
}

/// Walk the filesystem on a (possibly UDIF-compressed) disk image. A run
/// that failed to decode part way leaves the walk reading what decoded
/// before the failure, and bytes past it that may not be the disk's
/// (decoders can run on past damage before they notice it), so it is
/// reported once the walk is done.
fn walk_disk<D: Read + Seek, T>(
    disk: D,
    budget: &mut Budget,
    emit: Emit<T>,
) -> Result<Option<T>, LimitHit> {
    let disk = super::udif::disk(disk)?;
    let damaged = disk.damage();
    let found = walk_fs(disk, budget, emit)?;
    if found.is_some() || !damaged.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(found);
    }
    budget.count_entry()?;
    emit(
        Entry::unsupported(
            "dmg-disk".to_string(),
            0,
            false,
            "DMG run failed to decode part way; the bytes before the failure were scanned",
        ),
        budget,
    )
}

/// Walk the HFS+ or APFS filesystem on `disk`.
fn walk_fs<D: Read + Seek, T>(
    mut disk: super::udif::Disk<D>,
    budget: &mut Budget,
    emit: Emit<T>,
) -> Result<Option<T>, LimitHit> {
    // Both filesystems are looked for in the first 64 KiB, as `is_dmg` does.
    let mut head = Vec::new();
    disk.seek(SeekFrom::Start(0))
        .and_then(|_| (&mut disk).take(64 * 1024 + 44).read_to_end(&mut head))
        .map_err(|e| LimitHit::corrupt(format!("UDIF decompress: {e}")))?;

    if let Some(nxsb_off) = find_apfs_offset(&head) {
        let part = Part::new(disk, nxsb_off.saturating_sub(32) as u64)?;
        let mut vol = apfs::ApfsVolume::open(part)
            .map_err(|e| LimitHit::corrupt(format!("apfs open: {e}")))?;
        let walk = vol
            .walk()
            .map_err(|e| LimitHit::corrupt(format!("apfs walk: {e}")))?;
        for we in walk {
            if we.entry.kind != apfs::EntryKind::File {
                continue;
            }
            let hit = read_file(we.path, budget, emit, |path, out| {
                vol.read_file_to(path, out).map(|_| ())
            })?;
            if hit.is_some() {
                return Ok(hit);
            }
        }
        return Ok(None);
    }

    if let Some(hfs_off) = find_hfs_offset(&head) {
        let part = Part::new(disk, hfs_off.saturating_sub(1024) as u64)?;
        let mut vol = hfsplus::HfsVolume::open(part)
            .map_err(|e| LimitHit::corrupt(format!("hfs+ open: {e}")))?;
        let walk = vol
            .walk()
            .map_err(|e| LimitHit::corrupt(format!("hfs+ walk: {e}")))?;
        for we in walk {
            if we.entry.kind != hfsplus::EntryKind::File {
                continue;
            }
            // Only the data fork is read. A resource fork is content too, and
            // where macOS compressed a file (decmpfs) it holds the file's
            // bytes while the data fork is empty: reported, not scanned as
            // empty.
            if vol.stat(&we.path).is_ok_and(|s| s.resource_fork_size > 0) {
                budget.count_entry()?;
                let e = Entry::unsupported(we.path, 0, false, "HFS+ resource fork not read");
                if let Some(t) = emit(e, budget)? {
                    return Ok(Some(t));
                }
                continue;
            }
            let hit = read_file(we.path, budget, emit, |path, out| {
                vol.read_file_to(path, out).map(|_| ())
            })?;
            if hit.is_some() {
                return Ok(hit);
            }
        }
        return Ok(None);
    }

    Err(LimitHit::corrupt(
        "no HFS+ or APFS filesystem found in DMG".into(),
    ))
}

/// Read one file, bounded by the peak-buffer limit, and emit it. The
/// filesystem crates hand a file over whole.
fn read_file<T, E>(
    path: String,
    budget: &mut Budget,
    emit: Emit<T>,
    read: impl FnOnce(&str, &mut Capped) -> Result<(), E>,
) -> Result<Option<T>, LimitHit> {
    budget.count_entry()?;
    let mut out = Capped {
        data: Vec::new(),
        cap: budget.reserve()?,
        over: false,
    };
    let read = read(&path, &mut out);
    if out.over {
        return Err(LimitHit::new(format!("DMG file '{path}' exceeds budget")));
    }
    if read.is_err() {
        // Its bytes are in the image and were not all read: reported, not
        // dropped, and those read before the failure scanned.
        budget.commit(out.data.len() as u64);
        return emit(
            Entry {
                unsupported: Some("DMG file could not be read"),
                ..Entry::new(path, out.data)
            },
            budget,
        );
    }
    budget.commit(out.data.len() as u64);
    emit(Entry::new(path, out.data), budget)
}

/// A `Write` that refuses to grow past `cap`.
struct Capped {
    data: Vec<u8>,
    cap: u64,
    over: bool,
}

impl std::io::Write for Capped {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if (self.data.len() as u64).saturating_add(b.len() as u64) > self.cap {
            self.over = true;
            return Err(std::io::Error::other("over the buffer limit"));
        }
        self.data.extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The disk from `start` on, where a filesystem begins.
struct Part<D> {
    disk: D,
    start: u64,
}

impl<D: Read + Seek> Part<D> {
    fn new(mut disk: D, start: u64) -> Result<Self, LimitHit> {
        disk.seek(SeekFrom::Start(start))
            .map_err(|e| LimitHit::corrupt(format!("DMG: {e}")))?;
        Ok(Part { disk, start })
    }
}

impl<D: Read> Read for Part<D> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.disk.read(buf)
    }
}

impl<D: Seek> Seek for Part<D> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let to = match to {
            SeekFrom::Start(p) => SeekFrom::Start(self.start.saturating_add(p)),
            other => other,
        };
        let at = self.disk.seek(to)?;
        at.checked_sub(self.start).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before the start of the filesystem",
            )
        })
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

// The tests lay out their inputs by index arithmetic on small constants.
#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn is_dmg(data: &[u8]) -> bool {
        super::is_dmg(&Probe::whole(data))
    }

    #[test]
    fn detect_koly_trailer() {
        let mut buf = vec![0u8; 1024];
        buf[512..516].copy_from_slice(b"koly");
        assert!(is_dmg(&buf));
    }

    #[test]
    fn detect_encrcdsa() {
        let mut buf = vec![0u8; 1024];
        buf[0..8].copy_from_slice(b"encrcdsa");
        assert!(is_dmg(&buf));
    }

    /// Every field of an `encrcdsa` header is read from its big-endian place.
    #[cfg(feature = "decrypt")]
    #[test]
    fn encrypted_header_fields() {
        let mut h = b"encrcdsa".to_vec();
        // version .. hmac_key_bits: seven u32s, each its own index.
        for i in 0..7u32 {
            h.extend_from_slice(&(0x0101_0000 + i).to_be_bytes());
        }
        h.extend_from_slice(&[0xaa; 16]); // uuid
        h.extend_from_slice(&4096u32.to_be_bytes()); // blocksize
        h.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes()); // datasize
        h.extend_from_slice(&0x1112_1314_1516_1718u64.to_be_bytes()); // dataoffset
        h.extend_from_slice(&[0xbb; 24]);
        h.extend_from_slice(&1u32.to_be_bytes()); // kdf_algorithm
        h.extend_from_slice(&2u32.to_be_bytes()); // kdf_prng_algorithm
        h.extend_from_slice(&1000u32.to_be_bytes()); // kdf_iteration_count
        h.extend_from_slice(&20u32.to_be_bytes()); // kdf_salt_len
        h.extend((0..32).map(|i| i as u8)); // kdf_salt
        h.extend_from_slice(&8u32.to_be_bytes()); // blob_enc_iv_size
        h.extend((0..32).map(|i| 0x40 + i as u8)); // blob_enc_iv
        for v in [192u32, 17, 7, 6] {
            h.extend_from_slice(&v.to_be_bytes());
        }
        h.extend_from_slice(&48u32.to_be_bytes()); // encrypted_keyblob_size
        h.extend((0..64).map(|i| 0x80 + i as u8)); // encrypted_keyblob1, 2
        assert_eq!(h.len(), 264);
        h.extend_from_slice(b"trailing data");
        let p = parse_encrypted_header(&h).unwrap();
        assert_eq!(p.version, 0x0101_0000);
        assert_eq!(p.data_enc_key_bits, 0x0101_0004);
        assert_eq!(p.hmac_key_bits, 0x0101_0006);
        assert_eq!(p.blocksize, 4096);
        assert_eq!(p.datasize, 0x0102_0304_0506_0708);
        assert_eq!(p.dataoffset, 0x1112_1314_1516_1718);
        assert_eq!(p.kdf_iteration_count, 1000);
        assert_eq!(p.kdf_salt_len, 20);
        assert_eq!(p.kdf_salt[31], 31);
        assert_eq!(p.blob_enc_iv_size, 8);
        assert_eq!(p.blob_enc_iv[0], 0x40);
        assert_eq!(p.encrypted_keyblob_size, 48);
        assert_eq!(p.encrypted_keyblob1[0], 0x80);
        assert_eq!(p.encrypted_keyblob2[31], 0xbf);
        assert!(parse_encrypted_header(&h[..263]).is_err(), "short");
        let mut bad = h.clone();
        bad[..8].copy_from_slice(b"encrcdsb");
        assert!(parse_encrypted_header(&bad).is_err(), "signature");
        for (at, v) in [(108, 33u32), (196, 65)] {
            let mut bad = h.clone();
            bad[at..at + 4].copy_from_slice(&v.to_be_bytes());
            assert!(parse_encrypted_header(&bad).is_err(), "size at {at}");
        }
    }

    /// A data offset at the top of the range ends the chunk loop; it used to
    /// overflow the chunk position, whatever the password (the keyblob is
    /// decrypted without padding, so a wrong one still reaches the loop).
    #[cfg(feature = "decrypt")]
    #[test]
    fn a_data_offset_at_the_top_of_the_range_ends_the_decryption() {
        let mut h = vec![0u8; 264];
        h[..8].copy_from_slice(b"encrcdsa");
        let put32 =
            |h: &mut Vec<u8>, at: usize, v: u32| h[at..at + 4].copy_from_slice(&v.to_be_bytes());
        put32(&mut h, 8, 2); // version
        put32(&mut h, 24, 128); // AES key bits
        put32(&mut h, 32, 160); // HMAC key bits
        put32(&mut h, 52, 4096); // blocksize
        h[56..64].copy_from_slice(&8192u64.to_be_bytes()); // datasize
        h[64..72].copy_from_slice(&0xFFFF_FFFF_FFFF_F000u64.to_be_bytes()); // dataoffset
        put32(&mut h, 104, 1); // kdf iterations
        put32(&mut h, 196, 64); // keyblob size
        h.resize(8192, 0);
        let out = try_decrypt_dmg(&h, "any").expect("the walk ends with nothing decrypted");
        assert!(out.is_empty());
    }

    /// Write a well-formed HFS+ volume header at `off`.
    fn put_hfs(buf: &mut [u8], off: usize) {
        buf[off] = 0x48;
        buf[off + 1] = 0x2B;
        buf[off + 2..off + 4].copy_from_slice(&4u16.to_be_bytes()); // version
        buf[off + 40..off + 44].copy_from_slice(&4096u32.to_be_bytes()); // blockSize
    }

    /// Write a well-formed APFS container superblock at `off`.
    fn put_apfs(buf: &mut [u8], off: usize) {
        buf[off..off + 4].copy_from_slice(b"NXSB");
        buf[off + 4..off + 8].copy_from_slice(&4096u32.to_le_bytes()); // nx_block_size
    }

    #[test]
    fn detect_raw_hfs() {
        let mut buf = vec![0u8; 2048];
        put_hfs(&mut buf, 1024);
        assert!(is_dmg(&buf));
    }

    #[test]
    fn detect_raw_apfs() {
        let mut buf = vec![0u8; 2048];
        put_apfs(&mut buf, 1024);
        assert!(is_dmg(&buf));
    }

    #[test]
    fn detect_apfs_unaligned() {
        let mut buf = vec![0u8; 0x6000];
        put_apfs(&mut buf, 0x5020);
        assert!(is_dmg(&buf));
    }

    #[test]
    fn a_bare_signature_without_a_plausible_header_is_not_a_dmg() {
        // `H+` is two bytes. Across 64 KiB scanned at 16-byte steps it turns up
        // by chance in roughly one arbitrary buffer in twenty, and a false hit
        // is not a wasted check, it is a stolen file: `detect` answers `Dmg`, so
        // whatever the buffer really was never gets tried.
        //
        // Found by fuzzing chains of nested formats, where a compressed member
        // hit it and the whole branch came back UNSCANNABLE.
        let mut buf = vec![0u8; 4096];
        buf[1024] = 0x48;
        buf[1025] = 0x2B;
        assert!(
            !is_dmg(&buf),
            "the signature alone must not be enough; the version and block size \
             fields have to agree"
        );

        // Right signature, wrong version.
        let mut buf = vec![0u8; 4096];
        put_hfs(&mut buf, 1024);
        buf[1026..1028].copy_from_slice(&9u16.to_be_bytes());
        assert!(!is_dmg(&buf));

        // Right signature and version, implausible block size.
        let mut buf = vec![0u8; 4096];
        put_hfs(&mut buf, 1024);
        buf[1064..1068].copy_from_slice(&3000u32.to_be_bytes());
        assert!(!is_dmg(&buf));
    }

    #[test]
    fn no_false_positive_random_data() {
        let buf = vec![0xAA; 4096];
        assert!(!is_dmg(&buf));
    }

    #[test]
    fn no_false_positive_too_short() {
        assert!(!is_dmg(&[0u8; 4]));
    }

    /// The disk is read as the filesystem needs it, so one larger than the
    /// buffer limit still gives up its files.
    #[test]
    fn a_disk_over_the_buffer_limit_is_walked() {
        for name in ["hfs_plus_udzo.dmg", "apfs_udrw.dmg"] {
            let path = format!("{}/tests/fixtures/dmg/{name}", env!("CARGO_MANIFEST_DIR"));
            let blob = std::fs::read(path).unwrap();
            let mut budget = Budget::new(Limits {
                max_buffer_bytes: 64 * 1024,
                ..Limits::default()
            });
            let files: Vec<(String, Vec<u8>)> = crate::extract(Format::Dmg, &blob, &mut budget)
                .unwrap_or_else(|e| panic!("{name}: {e:?}"))
                .into_iter()
                .map(|e| (e.name, e.data))
                .collect();
            assert_eq!(files, [("/test.txt".to_string(), b"hello hfs+\n".to_vec())]);
        }
    }
}
