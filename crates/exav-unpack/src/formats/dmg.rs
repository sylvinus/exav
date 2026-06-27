use crate::*;
use std::io::Cursor;

/// "koly" — the UDIF trailer signature (last 512 bytes of the file).
const KOLY_SIG: &[u8; 4] = b"koly";

/// "encrcdsa" — encrypted DMG header signature.
const ENCRCDSA_SIG: &[u8; 8] = b"encrcdsa";

/// HFS+ volume header signature (big-endian 0x482B).
const HFS_PLUS_SIG: [u8; 2] = [0x48, 0x2B];

/// APFS container superblock signature "NXSB".
const APFS_SIG: &[u8; 4] = b"NXSB";

// ─── Detection ───────────────────────────────────────────────────────────────

pub(crate) fn is_dmg(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    if data.len() >= 512 && &data[data.len() - 512..data.len() - 508] == KOLY_SIG {
        return true;
    }
    if data.len() >= 8 && &data[0..8] == ENCRCDSA_SIG {
        return true;
    }
    let limit = data.len().min(64 * 1024);
    for off in (0..limit).step_by(16) {
        if data.len() >= off + 2 && data[off..off + 2] == HFS_PLUS_SIG {
            return true;
        }
        if data.len() >= off + 4 && &data[off..off + 4] == APFS_SIG {
            return true;
        }
    }
    false
}

fn find_hfs_offset(data: &[u8]) -> Option<usize> {
    let limit = data.len().min(64 * 1024);
    for off in (0..limit).step_by(16) {
        if data.len() >= off + 2 && data[off..off + 2] == HFS_PLUS_SIG {
            return Some(off);
        }
    }
    None
}

fn find_apfs_offset(data: &[u8]) -> Option<usize> {
    let limit = data.len().min(64 * 1024);
    for off in (0..limit).step_by(16) {
        if data.len() >= off + 4 && &data[off..off + 4] == APFS_SIG {
            return Some(off);
        }
    }
    None
}

fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= 8 && &data[0..8] == ENCRCDSA_SIG
}

// ─── Encrypted DMG header parsing ────────────────────────────────────────────

/// Apple encrypted DMG header, matching dmgwiz's `EncryptedDmgHeader`.
/// Deserialized via bincode (big-endian, fixint encoding).
#[derive(serde::Deserialize)]
struct EncryptedDmgHeader {
    #[allow(dead_code)]
    signature: [char; 8],
    #[allow(dead_code)]
    version: u32,
    #[allow(dead_code)]
    enc_iv_size: u32,
    #[allow(dead_code)]
    unk1: u32,
    #[allow(dead_code)]
    unk2: u32,
    data_enc_key_bits: u32,
    #[allow(dead_code)]
    unk4: u32,
    hmac_key_bits: u32,
    #[allow(dead_code)]
    uuid: [u8; 16],
    blocksize: u32,
    datasize: u64,
    dataoffset: u64,
    #[allow(dead_code)]
    unk6: [u8; 24],
    #[allow(dead_code)]
    kdf_algorithm: u32,
    #[allow(dead_code)]
    kdf_prng_algorithm: u32,
    kdf_iteration_count: u32,
    kdf_salt_len: u32,
    kdf_salt: [u8; 32],
    #[allow(dead_code)]
    blob_enc_iv_size: u32,
    blob_enc_iv: [u8; 32],
    #[allow(dead_code)]
    blob_enc_key_bits: u32,
    #[allow(dead_code)]
    blob_enc_algorithm: u32,
    #[allow(dead_code)]
    blob_enc_padding: u32,
    #[allow(dead_code)]
    blob_enc_mode: u32,
    encrypted_keyblob_size: u32,
    encrypted_keyblob1: [u8; 32],
    encrypted_keyblob2: [u8; 32],
}

/// Parse the encrcdsa header from raw bytes using bincode (matching dmgwiz).
fn parse_encrypted_header(data: &[u8]) -> Result<EncryptedDmgHeader, LimitHit> {
    use bincode::Options;

    let mut cursor = Cursor::new(data);
    let header: EncryptedDmgHeader = bincode::DefaultOptions::new()
        .with_big_endian()
        .with_fixint_encoding()
        .deserialize_from(&mut cursor)
        .map_err(|e| LimitHit::corrupt(format!("encrypted DMG header parse: {e}")))?;

    let sig: String = header.signature.iter().collect();
    if sig != "encrcdsa" {
        return Err(LimitHit::corrupt("missing encrcdsa signature".into()));
    }

    Ok(header)
}

// ─── Decryption ──────────────────────────────────────────────────────────────

/// Derive a 24-byte key from password using PBKDF2-HMAC-SHA1.
fn derive_key_dmg(password: &[u8], salt: &[u8; 32], salt_len: u32, iterations: u32) -> [u8; 24] {
    let iter = std::num::NonZeroU32::new(iterations).unwrap_or(std::num::NonZeroU32::new(1000).unwrap());
    let mut key = [0u8; 24];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, &salt[..salt_len as usize], iter.get(), &mut key);
    key
}

/// Decrypt the keyblob using 3DES-CBC.
fn decrypt_keyblob(
    header: &EncryptedDmgHeader,
    derived_key: &[u8; 24],
) -> Result<Vec<u8>, LimitHit> {
    use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};

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
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| LimitHit::corrupt("3DES keyblob decryption failed (wrong password?)".into()))?;
    Ok(plaintext.to_vec())
}

/// Compute per-chunk IV using HMAC-SHA1(hmac_key, chunk_no_be32)[0..16].
fn compute_chunk_iv(hmac_key: &[u8], chunk_no: u32) -> [u8; 16] {
    use hmac::{Hmac, Mac};
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
    if keyblob.len() < aes_key_bytes + hmac_key_bytes {
        return Err(LimitHit::corrupt("keyblob too short after decryption".into()));
    }
    let aes_key = &keyblob[..aes_key_bytes];
    let hmac_key = &keyblob[aes_key_bytes..aes_key_bytes + hmac_key_bytes];

    // Decrypt all chunks.
    let chunk_size = header.blocksize as usize;
    let data_size = header.datasize as usize;
    let data_start = header.dataoffset as usize;
    let num_chunks = data_size.div_ceil(chunk_size);

    let mut plaintext = Vec::with_capacity(data_size);
    let mut chunk_buf = vec![0u8; chunk_size];

    for chunk_no in 0..num_chunks {
        let src_start = data_start + chunk_no * chunk_size;
        let src_end = (src_start + chunk_size).min(data.len());
        if src_start >= data.len() {
            break;
        }
        let src_len = src_end - src_start;
        chunk_buf[..src_len].copy_from_slice(&data[src_start..src_end]);
        if src_len < chunk_size {
            // Last chunk may be short — pad with zeros for decryption.
            chunk_buf[src_len..chunk_size].fill(0);
        }

        let iv = compute_chunk_iv(hmac_key, chunk_no as u32);

        // AES-CBC decrypt.
        use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
        type Aes128Cbc = cbc::Decryptor<aes::Aes128>;
        type Aes256Cbc = cbc::Decryptor<aes::Aes256>;

        let remain = data_size - plaintext.len();
        let to_write = remain.min(chunk_size);

        if aes_key_bytes == 16 {
            let decryptor = Aes128Cbc::new_from_slices(aes_key, &iv)
                .map_err(|_| LimitHit::corrupt("invalid AES-128 key/iv".into()))?;
            let mut buf = chunk_buf[..chunk_size].to_vec();
            match decryptor.decrypt_padded_mut::<NoPadding>(&mut buf) {
                Ok(pt) => plaintext.extend_from_slice(&pt[..to_write]),
                Err(_) => return Err(LimitHit::corrupt("AES-128 decryption failed (wrong password?)".into())),
            }
        } else {
            let decryptor = Aes256Cbc::new_from_slices(aes_key, &iv)
                .map_err(|_| LimitHit::corrupt("invalid AES-256 key/iv".into()))?;
            let mut buf = chunk_buf[..chunk_size].to_vec();
            match decryptor.decrypt_padded_mut::<NoPadding>(&mut buf) {
                Ok(pt) => plaintext.extend_from_slice(&pt[..to_write]),
                Err(_) => return Err(LimitHit::corrupt("AES-256 decryption failed (wrong password?)".into())),
            }
        }
    }

    Ok(plaintext)
}

// ─── Extraction ──────────────────────────────────────────────────────────────

pub(crate) fn extract_dmg<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;

    // Encrypted DMG — try each password from the budget.
    if is_encrypted(data) {
        if budget.passwords.is_empty() {
            let entry = Entry::unsupported(
                "encrypted.dmg".to_string(),
                data.len() as u64,
                true,
                "encrypted DMG (no password provided)",
            );
            if let Some(r) = visit(entry, budget) {
                return Ok(Some(r));
            }
            return Ok(None);
        }

        let mut last_err = None;
        for pw in &budget.passwords {
            match try_decrypt_dmg(data, pw) {
                Ok(decrypted) => {
                    // Validate: decrypted payload must contain a koly trailer or filesystem.
                    let has_koly = decrypted.len() >= 512
                        && &decrypted[decrypted.len() - 512..decrypted.len() - 508] == KOLY_SIG;
                    let has_fs = find_hfs_offset(&decrypted).is_some()
                        || find_apfs_offset(&decrypted).is_some();
                    if !has_koly && !has_fs {
                        last_err = Some(LimitHit::corrupt(
                            "wrong password (no koly/filesystem in decrypted data)".into(),
                        ));
                        continue;
                    }
                    let raw = decompress_udif(&decrypted)?;
                    return extract_from_raw(&raw, budget, visit);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        // All passwords failed.
        let reason = if let Some(e) = last_err {
            format!("encrypted DMG (wrong password): {e}")
        } else {
            "encrypted DMG (wrong password)".into()
        };
        let entry = Entry::unsupported(
            "encrypted.dmg".to_string(),
            data.len() as u64,
            true,
            Box::leak(reason.into_boxed_str()),
        );
        if let Some(r) = visit(entry, budget) {
            return Ok(Some(r));
        }
        return Ok(None);
    }

    let raw = decompress_udif(data)?;
    extract_from_raw(&raw, budget, visit)
}

/// Extract filesystem from a raw (already decrypted/decompressed) disk image.
fn extract_from_raw<R>(
    raw: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    if let Some(nxsb_off) = find_apfs_offset(raw) {
        let partition_start = nxsb_off.saturating_sub(32);
        return extract_apfs(raw, partition_start, budget, visit);
    }

    if let Some(hfs_off) = find_hfs_offset(raw) {
        let partition_start = hfs_off.saturating_sub(1024);
        return extract_hfs_with_crate(raw, partition_start, budget, visit);
    }

    Err(LimitHit::corrupt(
        "no HFS+ or APFS filesystem found in DMG".into(),
    ))
}

fn decompress_udif(data: &[u8]) -> Result<Vec<u8>, LimitHit> {
    super::udif::decompress_udif(data)
}

fn extract_hfs_with_crate<R>(
    data: &[u8],
    partition_start: usize,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let reader = &data[partition_start..];
    let mut vol = hfsplus::HfsVolume::open(Cursor::new(reader))
        .map_err(|e| LimitHit::corrupt(format!("hfs+ open: {e}")))?;

    let walk = vol
        .walk()
        .map_err(|e| LimitHit::corrupt(format!("hfs+ walk: {e}")))?;

    for we in walk {
        if we.entry.kind != hfsplus::EntryKind::File {
            continue;
        }
        match vol.read_file(&we.path) {
            Ok(file_data) => {
                budget.count_entry()?;
                let entry = Entry::new(we.path, file_data);
                if let Some(r) = visit(entry, budget) {
                    return Ok(Some(r));
                }
            }
            Err(_) => {}
        }
    }
    Ok(None)
}

fn extract_apfs<R>(
    data: &[u8],
    partition_start: usize,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let reader = &data[partition_start..];
    let mut vol = apfs::ApfsVolume::open(Cursor::new(reader))
        .map_err(|e| LimitHit::corrupt(format!("apfs open: {e}")))?;

    let walk = vol
        .walk()
        .map_err(|e| LimitHit::corrupt(format!("apfs walk: {e}")))?;

    for we in walk {
        if we.entry.kind != apfs::EntryKind::File {
            continue;
        }
        match vol.read_file(&we.path) {
            Ok(file_data) => {
                budget.count_entry()?;
                let entry = Entry::new(we.path, file_data);
                if let Some(r) = visit(entry, budget) {
                    return Ok(Some(r));
                }
            }
            Err(_) => {}
        }
    }
    Ok(None)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn detect_raw_hfs() {
        let mut buf = vec![0u8; 2048];
        buf[1024] = 0x48;
        buf[1025] = 0x2B;
        assert!(is_dmg(&buf));
    }

    #[test]
    fn detect_raw_apfs() {
        let mut buf = vec![0u8; 2048];
        buf[1024..1028].copy_from_slice(b"NXSB");
        assert!(is_dmg(&buf));
    }

    #[test]
    fn detect_apfs_unaligned() {
        let mut buf = vec![0u8; 0x6000];
        buf[0x5020..0x5024].copy_from_slice(b"NXSB");
        assert!(is_dmg(&buf));
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
}
