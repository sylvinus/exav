//! Decryption of password-protected legacy Office documents (BIFF8 `.xls`) using
//! the **RC4 (basic)** and **RC4-CryptoAPI** schemes, per the public
//! **[MS-OFFCRYPTO] §2.3.6 / §2.3.5** key derivations and the **[MS-XLS] §2.4.117**
//! `FilePass` record. Implemented clean-room from those specifications.
//!
//! The headline case is the well-known default password **`VelvetSweatshop`**:
//! Excel encrypts with it by default so the file opens with no prompt, which
//! malware abuses to hide macros/objects from scanners that stop at "encrypted"
//! while still opening zero-click for the victim. exav tries it (and the empty
//! password) automatically so the real content is scanned.
//!
//! Only the `Workbook`/`Book` stream is encrypted; other storages (e.g. the VBA
//! project) are not.
//!
//! This module also implements the legacy **XOR obfuscation** scheme
//! (`wEncryptionType == 0`, [MS-OFFCRYPTO] §2.3.7) and both OOXML schemes:
//! **standard** (AES-ECB, SHA-1 spun 50000×) and **agile** (AES-CBC with a
//! per-blob KDF), §2.3.4. `ole.rs` routes an `EncryptionInfo` +
//! `EncryptedPackage` compound file here and scans the recovered `.zip`; a
//! document that still won't open is reported password-protected, never clean.

use sha1::{Digest, Sha1};

use super::offcrypto::DEFAULT_PASSWORDS as DEFAULT_OFFICE_PASSWORDS;

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// An encrypted BIFF `Workbook`/`Book` stream decrypted with the caller's
/// password pool plus the default passwords ([`DEFAULT_OFFICE_PASSWORDS`]), by
/// [`offcrypto`](super::offcrypto): `None` if the scheme is not handled or no
/// password matched (the caller then reports password-protected, never a silent
/// clean).
pub(crate) fn try_decrypt_workbook(stream: &[u8], passwords: &[String]) -> Option<Vec<u8>> {
    let candidates: Vec<&str> = passwords
        .iter()
        .map(String::as_str)
        .chain(DEFAULT_OFFICE_PASSWORDS.iter().copied())
        .collect();
    super::offcrypto::decrypt_workbook(stream, &candidates).ok()
}

// ─────────────────────────── OOXML (.docx/.xlsx) AES ───────────────────────────

use aes::cipher::{BlockCipherDecrypt, KeyInit};

/// AES-ECB decrypt `data` in place-copy (used by OOXML STANDARD encryption, which
/// is ECB with no IV). Trailing partial block is left as-is.
fn aes_ecb_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    macro_rules! run {
        ($ty:ty) => {{
            if let Ok(c) = <$ty>::new_from_slice(key) {
                for chunk in out.chunks_mut(16) {
                    if chunk.len() == 16 {
                        let mut b = aes::Block::try_from(&*chunk).expect("a whole block");
                        c.decrypt_block(&mut b);
                        chunk.copy_from_slice(&b);
                    }
                }
            }
        }};
    }
    match key.len() {
        16 => run!(aes::Aes128),
        24 => run!(aes::Aes192),
        32 => run!(aes::Aes256),
        _ => {}
    }
    out
}

/// OOXML STANDARD-encryption key derivation ([MS-OFFCRYPTO] §2.3.4.7): SHA-1 over
/// `salt ‖ UTF16LE(pw)`, 50000 spin iterations, a final block-key hash, then the
/// 0x36/0x5c derivation to `key_bytes`.
fn ooxml_standard_key(salt: &[u8], pw: &str, key_bytes: usize) -> Vec<u8> {
    let mut h = sha1(&[salt, &utf16le(pw)].concat());
    for i in 0u32..50000 {
        let mut m = i.to_le_bytes().to_vec();
        m.extend_from_slice(&h);
        h = sha1(&m);
    }
    let mut m = h.to_vec();
    m.extend_from_slice(&0u32.to_le_bytes()); // block key 0
    let hfinal = sha1(&m);
    let mut buf1 = [0x36u8; 64];
    let mut buf2 = [0x5cu8; 64];
    for i in 0..20 {
        buf1[i] ^= hfinal[i];
        buf2[i] ^= hfinal[i];
    }
    let mut key = sha1(&buf1).to_vec();
    key.extend_from_slice(&sha1(&buf2));
    key.truncate(key_bytes);
    key
}

/// Parsed OOXML STANDARD `EncryptionInfo`.
struct OoxmlStandard {
    key_bytes: usize,
    salt: Vec<u8>,
    enc_verifier: Vec<u8>,
    enc_verifier_hash: Vec<u8>,
}

/// Parse a STANDARD-encryption `EncryptionInfo` stream (version minor 2). Agile
/// (4.4) and extensible are not handled here.
fn parse_ooxml_standard(info: &[u8]) -> Option<OoxmlStandard> {
    if info.len() < 8 {
        return None;
    }
    let minor = u16::from_le_bytes([info[2], info[3]]);
    if minor != 2 {
        return None; // not standard encryption
    }
    let header_size = u32::from_le_bytes(info.get(8..12)?.try_into().ok()?) as usize;
    // EncryptionHeader starts at offset 12; KeySize is its 5th u32 (offset +16).
    let hdr = crate::bytes::at(info, 12, header_size)?;
    let key_bits = u32::from_le_bytes(hdr.get(16..20)?.try_into().ok()?);
    let key_bytes = if key_bits == 0 {
        16
    } else {
        (key_bits / 8) as usize
    };
    // EncryptionVerifier follows the header.
    let v = info.get(12usize.checked_add(header_size)?..)?;
    let salt_size = u32::from_le_bytes(v.get(0..4)?.try_into().ok()?) as usize;
    let salt = crate::bytes::at(v, 4, salt_size)?.to_vec();
    let ev_off = 4usize.checked_add(salt_size)?;
    let enc_verifier = crate::bytes::at(v, ev_off, 16)?.to_vec();
    let vh_off = ev_off.checked_add(16)?;
    let vhash_size = u32::from_le_bytes(crate::bytes::at(v, vh_off, 4)?.try_into().ok()?) as usize;
    // The stored hash is padded up to the cipher block; read the padded field.
    let padded = vhash_size.checked_next_multiple_of(16)?;
    let enc_verifier_hash = crate::bytes::at(v, vh_off.checked_add(4)?, padded)?.to_vec();
    Some(OoxmlStandard {
        key_bytes,
        salt,
        enc_verifier,
        enc_verifier_hash,
    })
}

/// Try to decrypt an OOXML-encrypted package (`EncryptionInfo` + `EncryptedPackage`
/// streams). Dispatches on the scheme: the STANDARD (ECB) scheme first, then the
/// AGILE (AES-CBC, `EncryptionInfo` 4.4) scheme. Returns the inner OOXML `.zip` on
/// a password that verifies (`VelvetSweatshop`, empty, and the caller pool), or
/// `None` if neither scheme applies or no password matched.
pub(crate) fn try_decrypt_ooxml(
    info: &[u8],
    package: &[u8],
    passwords: &[String],
) -> Option<Vec<u8>> {
    try_decrypt_ooxml_standard(info, package, passwords)
        .or_else(|| try_decrypt_ooxml_agile(info, package, passwords))
}

/// STANDARD (ECB) OOXML decryption. `info` is the `EncryptionInfo` stream,
/// `package` the `EncryptedPackage` stream (an 8-byte LE plaintext-length prefix
/// followed by the AES-ECB ciphertext).
fn try_decrypt_ooxml_standard(
    info: &[u8],
    package: &[u8],
    passwords: &[String],
) -> Option<Vec<u8>> {
    let s = parse_ooxml_standard(info)?;
    if package.len() < 8 {
        return None;
    }
    let candidates = passwords
        .iter()
        .map(String::as_str)
        .chain(DEFAULT_OFFICE_PASSWORDS.iter().copied());
    for pw in candidates {
        let key = ooxml_standard_key(&s.salt, pw, s.key_bytes);
        // Verify: AES-ECB decrypt verifier + its hash; SHA1(verifier) must match.
        let verifier = aes_ecb_decrypt(&key, &s.enc_verifier);
        let vhash = aes_ecb_decrypt(&key, &s.enc_verifier_hash);
        if verifier.len() < 16 || vhash.len() < 20 {
            continue;
        }
        if sha1(&verifier[..16])[..] != vhash[..20] {
            continue;
        }
        // Decrypt the package; first 8 bytes are the LE64 plaintext length.
        let plain_len = u64::from_le_bytes(package[..8].try_into().ok()?) as usize;
        let mut out = aes_ecb_decrypt(&key, &package[8..]);
        out.truncate(plain_len.min(out.len()));
        return Some(out);
    }
    None
}

// ───────────────────── OOXML AGILE (AES-CBC) encryption ─────────────────────
//
// Agile encryption ([MS-OFFCRYPTO] §2.3.4.10–15): the `EncryptionInfo` stream is
// a small header (version 4.4) followed by an XML descriptor. A password-derived
// key unwraps a random secret key, which decrypts the `EncryptedPackage` in
// 4096-byte segments each with its own IV. Clean-room from the public spec,
// cross-checked against the MIT-licensed msoffcrypto reference.

use sha2::{Sha256, Sha384, Sha512};

/// Block keys ([MS-OFFCRYPTO] §2.3.4.10) that select which derived key each step
/// uses: verifier-hash input, verifier-hash value, and the wrapped key value.
const AGILE_BLK_VERIFIER_INPUT: &[u8] = &[0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79];
const AGILE_BLK_VERIFIER_VALUE: &[u8] = &[0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E];
const AGILE_BLK_KEY_VALUE: &[u8] = &[0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6];

/// The hash algorithm named in an agile `EncryptionInfo` descriptor.
#[derive(Clone, Copy, PartialEq)]
enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Some(HashAlg::Sha1),
            "SHA256" => Some(HashAlg::Sha256),
            "SHA384" => Some(HashAlg::Sha384),
            "SHA512" => Some(HashAlg::Sha512),
            _ => None,
        }
    }
    fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha1 => sha1(data).to_vec(),
            HashAlg::Sha256 => {
                let mut h = Sha256::new();
                h.update(data);
                h.finalize().to_vec()
            }
            HashAlg::Sha384 => {
                let mut h = Sha384::new();
                h.update(data);
                h.finalize().to_vec()
            }
            HashAlg::Sha512 => {
                let mut h = Sha512::new();
                h.update(data);
                h.finalize().to_vec()
            }
        }
    }
}

/// AES-CBC decrypt (NoPadding): decrypt the block-aligned prefix and leave any
/// trailing partial block untouched. All AES key lengths (128/192/256) supported.
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    use aes::cipher::block_padding::NoPadding;
    use aes::cipher::{BlockModeDecrypt, KeyIvInit};
    let mut out = data.to_vec();
    let n = out.len() - out.len() % 16;
    if iv.len() < 16 || n == 0 {
        return out;
    }
    macro_rules! run {
        ($ty:ty) => {{
            if let Ok(c) = <cbc::Decryptor<$ty>>::new_from_slices(key, &iv[..16]) {
                let _ = c.decrypt_padded::<NoPadding>(&mut out[..n]);
            }
        }};
    }
    match key.len() {
        16 => run!(aes::Aes128),
        24 => run!(aes::Aes192),
        32 => run!(aes::Aes256),
        _ => {}
    }
    out
}

/// Minimal standard base64 decoder (whitespace-tolerant, stops at padding). The
/// agile descriptor stores all binary fields base64-encoded.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        buf = (buf << 6) | val(c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Return the opening tag `<…>` of an XML element identified by a `marker`
/// substring unique to it (e.g. `"<keyData"`, or `"spinCount="` for the
/// namespaced `<p:encryptedKey>`).
fn xml_element<'a>(xml: &'a str, marker: &str) -> Option<&'a str> {
    let pos = xml.find(marker)?;
    let lt = xml[..pos].rfind('<')?;
    let gt = xml[pos..].find('>')? + pos;
    Some(&xml[lt..=gt])
}

/// Extract the value of attribute `name` from a single element's opening tag.
fn xml_attr<'a>(elem: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}=\"");
    let start = elem.find(&key)? + key.len();
    let rest = &elem[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Parsed agile `EncryptionInfo`: the key-data (package) cipher params plus the
/// password key-encryptor params and the three encrypted blobs.
struct OoxmlAgile {
    kd_hash: HashAlg,
    kd_salt: Vec<u8>,
    kd_block_size: usize,
    ek_hash: HashAlg,
    ek_salt: Vec<u8>,
    ek_key_bytes: usize,
    spin_count: u32,
    enc_verifier_input: Vec<u8>,
    enc_verifier_value: Vec<u8>,
    enc_key_value: Vec<u8>,
}

/// Parse an agile `EncryptionInfo` stream (version 4.4): a 4-byte version, 4-byte
/// reserved flags, then a UTF-8 XML descriptor.
fn parse_ooxml_agile(info: &[u8]) -> Option<OoxmlAgile> {
    if info.len() < 8 {
        return None;
    }
    let major = u16::from_le_bytes([info[0], info[1]]);
    let minor = u16::from_le_bytes([info[2], info[3]]);
    if major < 4 || minor != 4 {
        return None; // not agile
    }
    let xml = std::str::from_utf8(&info[8..]).ok()?;
    let kd = xml_element(xml, "<keyData")?;
    let ek = xml_element(xml, "spinCount=")?;

    let dec = |b: &str| -> Option<usize> { b.parse::<usize>().ok() };
    Some(OoxmlAgile {
        kd_hash: HashAlg::parse(xml_attr(kd, "hashAlgorithm")?)?,
        kd_salt: b64_decode(xml_attr(kd, "saltValue")?)?,
        kd_block_size: dec(xml_attr(kd, "blockSize")?).unwrap_or(16).clamp(16, 64),
        ek_hash: HashAlg::parse(xml_attr(ek, "hashAlgorithm")?)?,
        ek_salt: b64_decode(xml_attr(ek, "saltValue")?)?,
        ek_key_bytes: dec(xml_attr(ek, "keyBits")?)?.checked_div(8)?,
        spin_count: xml_attr(ek, "spinCount")?.parse::<u32>().ok()?,
        enc_verifier_input: b64_decode(xml_attr(ek, "encryptedVerifierHashInput")?)?,
        enc_verifier_value: b64_decode(xml_attr(ek, "encryptedVerifierHashValue")?)?,
        enc_key_value: b64_decode(xml_attr(ek, "encryptedKeyValue")?)?,
    })
}

/// The most hash rounds taken from an `EncryptionInfo`'s `spinCount`.
const MAX_AGILE_SPIN: u32 = 1_000_000;

/// Agile password hash ([MS-OFFCRYPTO] §2.3.4.11): `H0 = Hash(salt ‖ UTF16LE(pw))`,
/// then `spin` iterations of `Hi = Hash(LE32(i) ‖ H(i-1))`. Excludes the block key.
fn agile_iterated_hash(salt: &[u8], pw: &str, alg: HashAlg, spin: u32) -> Vec<u8> {
    let mut h = alg.digest(&[salt, &utf16le(pw)].concat());
    // Office writes 100,000. The count is the file's, and each password tried
    // costs this many hashes: 4 billion would be an hour of one.
    for i in 0..spin.min(MAX_AGILE_SPIN) {
        let mut m = i.to_le_bytes().to_vec();
        m.extend_from_slice(&h);
        h = alg.digest(&m);
    }
    h
}

/// Finish an agile key derivation: `Hash(h ‖ blockKey)` truncated/padded to
/// `key_bytes` (padding with 0x36 per the spec normalization).
fn agile_derive_key(h: &[u8], block_key: &[u8], alg: HashAlg, key_bytes: usize) -> Vec<u8> {
    let mut m = h.to_vec();
    m.extend_from_slice(block_key);
    let mut k = alg.digest(&m);
    if k.len() < key_bytes {
        k.resize(key_bytes, 0x36);
    }
    k.truncate(key_bytes);
    k
}

/// Try to decrypt an AGILE-encrypted OOXML package. Returns the inner `.zip` on a
/// verifying password, or `None` if the scheme isn't agile or no password matched.
fn try_decrypt_ooxml_agile(info: &[u8], package: &[u8], passwords: &[String]) -> Option<Vec<u8>> {
    let a = parse_ooxml_agile(info)?;
    if a.ek_key_bytes == 0 || a.ek_key_bytes > 32 || a.ek_salt.len() < 16 || package.len() < 8 {
        return None;
    }
    let candidates = passwords
        .iter()
        .map(String::as_str)
        .chain(DEFAULT_OFFICE_PASSWORDS.iter().copied());
    for pw in candidates {
        let h = agile_iterated_hash(&a.ek_salt, pw, a.ek_hash, a.spin_count);
        let key1 = agile_derive_key(&h, AGILE_BLK_VERIFIER_INPUT, a.ek_hash, a.ek_key_bytes);
        let key2 = agile_derive_key(&h, AGILE_BLK_VERIFIER_VALUE, a.ek_hash, a.ek_key_bytes);
        // Verify: Hash(decrypt(verifierInput)) must equal decrypt(verifierValue).
        let dec_input = aes_cbc_decrypt(&key1, &a.ek_salt, &a.enc_verifier_input);
        let dec_value = aes_cbc_decrypt(&key2, &a.ek_salt, &a.enc_verifier_value);
        let calc = a.ek_hash.digest(&dec_input);
        if calc.len() > dec_value.len() || calc[..] != dec_value[..calc.len()] {
            continue;
        }
        // Unwrap the random secret key, then decrypt the package segments.
        let key3 = agile_derive_key(&h, AGILE_BLK_KEY_VALUE, a.ek_hash, a.ek_key_bytes);
        let secret = aes_cbc_decrypt(&key3, &a.ek_salt, &a.enc_key_value);
        if secret.len() < a.ek_key_bytes {
            continue;
        }
        return Some(decrypt_agile_package(
            package,
            &secret[..a.ek_key_bytes],
            &a,
        ));
    }
    None
}

/// Decrypt an agile `EncryptedPackage`: an 8-byte LE plaintext length, then the
/// ciphertext in 4096-byte segments, each AES-CBC with `IV = Hash(kdSalt ‖ LE32(i))`.
fn decrypt_agile_package(package: &[u8], secret: &[u8], a: &OoxmlAgile) -> Vec<u8> {
    let total = u64::from_le_bytes(package[..8].try_into().unwrap()) as usize;
    let ct = &package[8..];
    let want = total.min(ct.len());
    let mut out = Vec::with_capacity(want);
    for (i, seg) in ct.chunks(4096).enumerate() {
        let mut m = a.kd_salt.clone();
        m.extend_from_slice(&(i as u32).to_le_bytes());
        let mut iv = a.kd_hash.digest(&m);
        iv.truncate(a.kd_block_size.max(16));
        out.extend_from_slice(&aes_cbc_decrypt(secret, &iv, seg));
        if out.len() >= want {
            break;
        }
    }
    out.truncate(want);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The password and the EncryptionInfo come from the user and the file: no
    /// length of either may panic the derivation.
    #[test]
    fn a_spin_count_of_billions_is_cut_to_a_million_rounds() {
        let start = std::time::Instant::now();
        let h = agile_iterated_hash(&[0u8; 16], "pw", HashAlg::Sha1, u32::MAX);
        assert_eq!(h.len(), 20);
        assert!(start.elapsed() < std::time::Duration::from_secs(20));
        // The same as asking for the cut itself.
        assert_eq!(
            h,
            agile_iterated_hash(&[0u8; 16], "pw", HashAlg::Sha1, MAX_AGILE_SPIN)
        );
    }

    #[test]
    fn a_short_standard_encryption_info_is_not_parsed_not_a_panic() {
        for len in 0..=11 {
            let mut info = vec![0u8; len];
            if len > 3 {
                info[2] = 2; // minor
            }
            assert!(parse_ooxml_standard(&info).is_none(), "length {len}");
        }
        let mut huge = vec![0u8; 16];
        huge[2] = 2;
        huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_ooxml_standard(&huge).is_none());
    }

    fn eicar() -> &'static [u8] {
        crate::eicar()
    }

    fn push_rec(v: &mut Vec<u8>, id: u16, data: &[u8]) {
        v.extend_from_slice(&id.to_le_bytes());
        v.extend_from_slice(&(data.len() as u16).to_le_bytes());
        v.extend_from_slice(data);
    }

    /// A `Workbook` stream (BOF, `FilePass`, an EICAR record, EOF) encrypted
    /// with the default password by `method`.
    fn encrypted_workbook(method: &str) -> Vec<u8> {
        use super::super::offcrypto::encrypt::{encrypt_stream, filepass};
        let mut wb = Vec::new();
        // BOF of BIFF8.
        push_rec(
            &mut wb,
            0x0809,
            &[0x00, 0x06, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        let at = wb.len();
        push_rec(&mut wb, 0x002f, &filepass(method, true)); // FilePass
        push_rec(&mut wb, 0x00ff, eicar()); // non-exempt → encrypted
        push_rec(&mut wb, 0x000a, &[]); // EOF
        encrypt_stream(method, &mut wb, at);
        assert!(
            !wb.windows(eicar().len()).any(|w| w == eicar()),
            "EICAR encrypted"
        );
        wb
    }

    /// End-to-end: the default password recovers the cleartext EICAR of a
    /// workbook with no caller password, whichever the scheme.
    #[test]
    fn velvetsweatshop_recovers_eicar() {
        for method in ["rc4", "cryptoapi40", "cryptoapi128", "xor"] {
            let ct = encrypted_workbook(method);
            let recovered = try_decrypt_workbook(&ct, &[])
                .unwrap_or_else(|| panic!("{method}: VelvetSweatshop must decrypt"));
            assert!(
                recovered.windows(eicar().len()).any(|w| w == eicar()),
                "{method}"
            );
        }
    }

    /// A workbook embedded in another, as Excel stores an inserted workbook
    /// object, is decrypted too: only the first workbook stream was checked,
    /// and a plain one at the top hid an encrypted one below it. Excel names
    /// the storage `MBD` and eight hex digits, which the walk visits after
    /// `/Workbook`; a shorter name is visited before it.
    #[test]
    fn an_embedded_encrypted_workbook_is_decrypted() {
        use std::io::Write;
        let ct = encrypted_workbook("rc4");

        for storage in ["/MBD0001", "/MBD0012AB34"] {
            let mut cf = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
            let plain = [0x09, 0x08, 0, 0, 0x0a, 0x00, 0, 0];
            cf.create_stream("/Workbook")
                .unwrap()
                .write_all(&plain)
                .unwrap();
            cf.create_storage(storage).unwrap();
            let inner_path = format!("{storage}/Workbook");
            cf.create_stream(&inner_path)
                .unwrap()
                .write_all(&ct)
                .unwrap();
            let blob = cf.into_inner().into_inner();
            let entries = crate::formats::ole::extract_ole(
                &blob,
                &mut crate::Budget::new(crate::Limits::default()),
            )
            .unwrap();
            let inner = entries.iter().find(|e| e.name == inner_path).unwrap();
            assert!(inner.encrypted && inner.unsupported.is_none(), "{storage}");
            assert!(
                inner.data.windows(eicar().len()).any(|w| w == eicar()),
                "{storage}"
            );
        }
    }

    fn aes_ecb_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        let cipher = aes::Aes128::new_from_slice(key).unwrap();
        let mut out = data.to_vec();
        for chunk in out.chunks_mut(16) {
            let mut b = aes::Block::try_from(&*chunk).unwrap();
            cipher.encrypt_block(&mut b);
            chunk.copy_from_slice(&b);
        }
        out
    }

    /// End-to-end OOXML STANDARD encryption: build an `EncryptionInfo` +
    /// `EncryptedPackage` with the empty password and confirm the default-password
    /// path recovers the plaintext EICAR.
    #[test]
    fn ooxml_standard_empty_password_recovers_eicar() {
        let salt = [0x11u8; 16];
        let key = ooxml_standard_key(&salt, "", 16); // empty password, AES-128
        let verifier = [0x22u8; 16];
        let enc_verifier = aes_ecb_encrypt(&key, &verifier);
        let mut vhash_padded = sha1(&verifier).to_vec();
        vhash_padded.resize(32, 0);
        let enc_vhash = aes_ecb_encrypt(&key, &vhash_padded);

        // EncryptionInfo (standard, version 3.2).
        let mut info = Vec::new();
        info.extend_from_slice(&3u16.to_le_bytes());
        info.extend_from_slice(&2u16.to_le_bytes());
        info.extend_from_slice(&0u32.to_le_bytes());
        let mut hdr = vec![0u8; 32];
        hdr[16..20].copy_from_slice(&128u32.to_le_bytes()); // KeySize
        info.extend_from_slice(&(hdr.len() as u32).to_le_bytes());
        info.extend_from_slice(&hdr);
        info.extend_from_slice(&16u32.to_le_bytes());
        info.extend_from_slice(&salt);
        info.extend_from_slice(&enc_verifier);
        info.extend_from_slice(&20u32.to_le_bytes());
        info.extend_from_slice(&enc_vhash);

        // EncryptedPackage: 8-byte LE length prefix + AES-ECB(padded plaintext).
        let eicar = eicar();
        let mut plain = eicar.to_vec();
        while !plain.len().is_multiple_of(16) {
            plain.push(0);
        }
        let mut package = (eicar.len() as u64).to_le_bytes().to_vec();
        package.extend_from_slice(&aes_ecb_encrypt(&key, &plain));

        let out = try_decrypt_ooxml(&info, &package, &[]).expect("standard OOXML must decrypt");
        assert!(
            out.windows(eicar.len()).any(|w| w == eicar),
            "EICAR must be recovered from the decrypted OOXML package"
        );
    }

    /// End-to-end wiring: a real OLE2/CFB container holding `EncryptionInfo` +
    /// `EncryptedPackage` must be routed through the decryptor by the OLE
    /// extractor, not merely reported password-protected. The crypto is covered
    /// above; this pins the plumbing between `ole.rs` and this module.
    #[test]
    fn encrypted_ooxml_in_a_cfb_container_is_decrypted_by_the_extractor() {
        use crate::{Budget, Limits};
        use std::io::{Cursor, Write};

        // Same standard-scheme (AES-128-ECB, empty password) construction as the
        // test above, kept local so the two can't drift into sharing a bug.
        let salt = [0x42u8; 16];
        let key = ooxml_standard_key(&salt, "", 16);
        let verifier = [0x24u8; 16];
        let enc_verifier = aes_ecb_encrypt(&key, &verifier);
        let vhash = sha1(&verifier);
        let mut vhash_padded = vhash.to_vec();
        while !vhash_padded.len().is_multiple_of(16) {
            vhash_padded.push(0);
        }
        let enc_vhash = aes_ecb_encrypt(&key, &vhash_padded);

        let mut info = Vec::new();
        info.extend_from_slice(&3u16.to_le_bytes());
        info.extend_from_slice(&2u16.to_le_bytes());
        info.extend_from_slice(&0u32.to_le_bytes());
        let mut hdr = vec![0u8; 32];
        hdr[16..20].copy_from_slice(&128u32.to_le_bytes());
        info.extend_from_slice(&(hdr.len() as u32).to_le_bytes());
        info.extend_from_slice(&hdr);
        info.extend_from_slice(&16u32.to_le_bytes());
        info.extend_from_slice(&salt);
        info.extend_from_slice(&enc_verifier);
        info.extend_from_slice(&20u32.to_le_bytes());
        info.extend_from_slice(&enc_vhash);

        let mut plain = eicar().to_vec();
        while !plain.len().is_multiple_of(16) {
            plain.push(0);
        }
        let mut package = (eicar().len() as u64).to_le_bytes().to_vec();
        package.extend_from_slice(&aes_ecb_encrypt(&key, &plain));

        // Wrap both streams in a genuine compound file.
        let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).expect("create cfb");
        cf.create_stream("/EncryptionInfo")
            .expect("EncryptionInfo")
            .write_all(&info)
            .expect("write info");
        cf.create_stream("/EncryptedPackage")
            .expect("EncryptedPackage")
            .write_all(&package)
            .expect("write package");
        cf.flush().expect("flush cfb");
        let blob = cf.into_inner().into_inner();

        let mut budget = Budget::new(Limits::default());
        let entries = crate::formats::ole::extract_ole(&blob, &mut budget).expect("extract ole");
        assert!(
            entries.iter().all(|e| e.unsupported.is_none()),
            "the container must be decrypted, not reported password-protected: {:?}",
            entries.iter().map(|e| e.unsupported).collect::<Vec<_>>()
        );
        assert!(
            entries
                .iter()
                .any(|e| e.data.windows(eicar().len()).any(|w| w == eicar())),
            "EICAR must be recovered through the full container path"
        );
    }

    fn aes256_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
        use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
        let mut out = data.to_vec();
        let n = out.len();
        let enc = <cbc::Encryptor<aes::Aes256>>::new_from_slices(key, &iv[..16]).unwrap();
        enc.encrypt_padded::<NoPadding>(&mut out, n)
            .unwrap()
            .to_vec()
    }

    fn b64_encode(data: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            out.push(T[(b[0] >> 2) as usize] as char);
            out.push(T[(((b[0] & 3) << 4) | (b[1] >> 4)) as usize] as char);
            out.push(if chunk.len() > 1 {
                T[(((b[1] & 15) << 2) | (b[2] >> 6)) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                T[(b[2] & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn b64_roundtrip() {
        for v in [
            &b""[..],
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            &[0u8, 255, 16, 200, 3],
        ] {
            assert_eq!(b64_decode(&b64_encode(v)).unwrap(), v.to_vec());
        }
    }

    /// End-to-end OOXML AGILE encryption (AES-256/SHA-512): build a valid
    /// `EncryptionInfo` 4.4 descriptor + `EncryptedPackage` for the empty password
    /// and confirm the default-password path recovers the plaintext EICAR.
    #[test]
    fn ooxml_agile_empty_password_recovers_eicar() {
        let ek_salt = [0x11u8; 16];
        let kd_salt = [0x33u8; 16];
        let spin: u32 = 1000;
        let alg = HashAlg::Sha512;
        let key_bytes = 32;

        // Password key derivation (empty password).
        let h = agile_iterated_hash(&ek_salt, "", alg, spin);
        let key1 = agile_derive_key(&h, AGILE_BLK_VERIFIER_INPUT, alg, key_bytes);
        let key2 = agile_derive_key(&h, AGILE_BLK_VERIFIER_VALUE, alg, key_bytes);
        let key3 = agile_derive_key(&h, AGILE_BLK_KEY_VALUE, alg, key_bytes);

        let verifier_input = [0x22u8; 16];
        let enc_verifier_input = aes256_cbc_encrypt(&key1, &ek_salt, &verifier_input);
        let hashed = alg.digest(&verifier_input); // 64 bytes = 4 blocks
        let enc_verifier_value = aes256_cbc_encrypt(&key2, &ek_salt, &hashed);

        let secret = [0x5au8; 32];
        let enc_key_value = aes256_cbc_encrypt(&key3, &ek_salt, &secret);

        // EncryptedPackage: LE64 length + one 4096-segment AES-CBC(EICAR).
        let mut plain = eicar().to_vec();
        while !plain.len().is_multiple_of(16) {
            plain.push(0);
        }
        let mut seg_iv = alg.digest(&[&kd_salt[..], &0u32.to_le_bytes()].concat());
        seg_iv.truncate(16);
        let seg = aes256_cbc_encrypt(&secret, &seg_iv, &plain);
        let mut package = (eicar().len() as u64).to_le_bytes().to_vec();
        package.extend_from_slice(&seg);

        // Agile EncryptionInfo: version 4.4, reserved flags, then the XML.
        let xml = format!(
            "<?xml version=\"1.0\"?>\
<encryption>\
<keyData saltSize=\"16\" blockSize=\"16\" keyBits=\"256\" hashSize=\"64\" \
cipherAlgorithm=\"AES\" cipherChaining=\"ChainingModeCBC\" hashAlgorithm=\"SHA512\" saltValue=\"{}\"/>\
<keyEncryptors><keyEncryptor uri=\"http://schemas.microsoft.com/office/2006/keyEncryptor/password\">\
<p:encryptedKey spinCount=\"{}\" saltSize=\"16\" blockSize=\"16\" keyBits=\"256\" hashSize=\"64\" \
cipherAlgorithm=\"AES\" cipherChaining=\"ChainingModeCBC\" hashAlgorithm=\"SHA512\" saltValue=\"{}\" \
encryptedVerifierHashInput=\"{}\" encryptedVerifierHashValue=\"{}\" encryptedKeyValue=\"{}\"/>\
</keyEncryptor></keyEncryptors></encryption>",
            b64_encode(&kd_salt),
            spin,
            b64_encode(&ek_salt),
            b64_encode(&enc_verifier_input),
            b64_encode(&enc_verifier_value),
            b64_encode(&enc_key_value),
        );
        let mut info = Vec::new();
        info.extend_from_slice(&4u16.to_le_bytes());
        info.extend_from_slice(&4u16.to_le_bytes());
        info.extend_from_slice(&0x40u32.to_le_bytes());
        info.extend_from_slice(xml.as_bytes());

        let out = try_decrypt_ooxml(&info, &package, &[]).expect("agile OOXML must decrypt");
        assert!(
            out.windows(eicar().len()).any(|w| w == eicar()),
            "EICAR must be recovered from the decrypted agile package"
        );
    }

    fn hexv(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// Authoritative vector from the msoffcrypto `makekey_from_password` doctest
    /// (extracted from a real agile-encrypted Office file): our derivation must
    /// unwrap the exact secret key. Proves byte-exact agreement with real Office
    /// AES-256/SHA-512 agile encryption.
    #[test]
    fn agile_makekey_matches_real_office_vector() {
        let salt = hexv("4c725d45dc610f939412a04da7910466");
        let ekv = hexv("a16cd5165a7ab9d271113ed386a78cf49692e8e527b0c5fc0055ed080b7cb94b");
        let expected = hexv("40206609d9faadf24b076aebf2c435b74292c8b8a7aa81bc679be89711b02ac2");
        let h = agile_iterated_hash(&salt, "Password1234_", HashAlg::Sha512, 100000);
        let key3 = agile_derive_key(&h, AGILE_BLK_KEY_VALUE, HashAlg::Sha512, 32);
        let secret = aes_cbc_decrypt(&key3, &salt, &ekv);
        assert_eq!(
            secret, expected,
            "agile secret-key derivation must match Office"
        );
    }

    /// Authoritative vector from the msoffcrypto `verify_password` doctest (real
    /// agile file): the correct password verifies and a wrong one does not.
    #[test]
    fn agile_verify_password_matches_real_office_vector() {
        let salt = hexv("cbca1c999343fbad92075634150034b0");
        let enc_in = hexv("39eea54e26e514798c284bc7714d38ac");
        let enc_val = hexv(
            "14376d6d817334e6b0ff4fd8221a7c678e5d8a784e8f999f4c188930c36a4b29\
             c5b333605b5cd403b05003adcf18cca8cbab8debe373c65604a0becfae5c0ad0",
        );
        let check = |pw: &str| -> bool {
            let h = agile_iterated_hash(&salt, pw, HashAlg::Sha512, 100000);
            let key1 = agile_derive_key(&h, AGILE_BLK_VERIFIER_INPUT, HashAlg::Sha512, 32);
            let key2 = agile_derive_key(&h, AGILE_BLK_VERIFIER_VALUE, HashAlg::Sha512, 32);
            let dec_in = aes_cbc_decrypt(&key1, &salt, &enc_in);
            let calc = HashAlg::Sha512.digest(&dec_in);
            let dec_val = aes_cbc_decrypt(&key2, &salt, &enc_val);
            calc.len() <= dec_val.len() && calc[..] == dec_val[..calc.len()]
        };
        assert!(check("Password1234_"), "correct password must verify");
        assert!(!check("wrong-password"), "wrong password must not verify");
    }
}
