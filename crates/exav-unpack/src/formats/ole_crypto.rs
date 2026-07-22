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
//! (`wEncryptionType == 0`, [MS-OFFCRYPTO] §2.3.7) and both OOXML schemes —
//! **standard** (AES-ECB, SHA-1 spun 50000×) and **agile** (AES-CBC with a
//! per-blob KDF), §2.3.4. `ole.rs` routes an `EncryptionInfo` +
//! `EncryptedPackage` compound file here and scans the recovered `.zip`; a
//! document that still won't open is reported password-protected, never clean.

use md5::{Digest, Md5};
use sha1::Sha1;

/// Passwords exav tries automatically on an encrypted Office document before
/// giving up and reporting it password-protected: the Excel default (opens with
/// no prompt — the common malware trick) and the empty password.
pub(crate) const DEFAULT_OFFICE_PASSWORDS: &[&str] = &["VelvetSweatshop", ""];

fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// RC4 stream cipher (symmetric: the same routine decrypts and encrypts).
fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        i = (i + 1) & 0xff;
        j = (j + s[i] as usize) & 0xff;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) & 0xff];
        out.push(b ^ k);
    }
    out
}

/// The RC4 key schedule for a password, in one of the two legacy schemes.
enum KeyDeriver {
    /// RC4 basic ([MS-OFFCRYPTO] §2.3.6.2): MD5-based, 5-byte intermediate.
    Basic([u8; 5]),
    /// RC4-CryptoAPI ([MS-OFFCRYPTO] §2.3.5.2): SHA-1-based, `key_bytes`-long key.
    CryptoApi { h0: [u8; 20], key_bytes: usize },
}

impl KeyDeriver {
    fn basic(salt: &[u8], pw: &str) -> Self {
        let h0 = md5(&utf16le(pw));
        let mut buf = Vec::with_capacity(21 * 16);
        for _ in 0..16 {
            buf.extend_from_slice(&h0[..5]);
            buf.extend_from_slice(salt);
        }
        let h1 = md5(&buf);
        let mut inter = [0u8; 5];
        inter.copy_from_slice(&h1[..5]);
        KeyDeriver::Basic(inter)
    }

    fn cryptoapi(salt: &[u8], pw: &str, key_bits: u32) -> Self {
        let mut m = Vec::with_capacity(salt.len() + pw.len() * 2);
        m.extend_from_slice(salt);
        m.extend_from_slice(&utf16le(pw));
        // A zero KeySize means the 40-bit default.
        let key_bytes = if key_bits == 0 {
            5
        } else {
            (key_bits / 8) as usize
        };
        KeyDeriver::CryptoApi {
            h0: sha1(&m),
            key_bytes,
        }
    }

    /// Per-block RC4 key; the stream is re-keyed every 1024 bytes.
    fn block_key(&self, block: u32) -> Vec<u8> {
        match self {
            KeyDeriver::Basic(inter) => {
                let mut kd = [0u8; 9];
                kd[..5].copy_from_slice(inter);
                kd[5..].copy_from_slice(&block.to_le_bytes());
                md5(&kd).to_vec()
            }
            KeyDeriver::CryptoApi { h0, key_bytes } => {
                let mut kd = Vec::with_capacity(24);
                kd.extend_from_slice(h0);
                kd.extend_from_slice(&block.to_le_bytes());
                let hf = sha1(&kd);
                if *key_bytes <= 5 {
                    // 40-bit: 5 real key bytes zero-padded to a 16-byte RC4 key.
                    let mut k = vec![0u8; 16];
                    k[..5].copy_from_slice(&hf[..5]);
                    k
                } else {
                    hf[..*key_bytes].to_vec()
                }
            }
        }
    }

    /// The verifier hash: MD5 for basic, SHA-1 for CryptoAPI.
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            KeyDeriver::Basic(_) => md5(data).to_vec(),
            KeyDeriver::CryptoApi { .. } => sha1(data).to_vec(),
        }
    }
}

/// The parameters parsed from a `FilePass` record.
struct FilePass {
    salt: Vec<u8>,
    enc_verifier: Vec<u8>,
    enc_vhash: Vec<u8>,
    /// `None` = RC4 basic; `Some(key_bits)` = RC4-CryptoAPI.
    cryptoapi_key_bits: Option<u32>,
}

impl FilePass {
    fn deriver(&self, pw: &str) -> KeyDeriver {
        match self.cryptoapi_key_bits {
            None => KeyDeriver::basic(&self.salt, pw),
            Some(bits) => KeyDeriver::cryptoapi(&self.salt, pw, bits),
        }
    }

    /// [MS-OFFCRYPTO] §2.3.6.3 / §2.3.5.6: the block-0 keystream decrypts the
    /// 16-byte verifier followed continuously by its hash; the password is
    /// correct when `H(verifier) == verifierHash`.
    fn password_ok(&self, pw: &str) -> bool {
        if self.enc_verifier.len() != 16 || self.enc_vhash.is_empty() {
            return false;
        }
        let d = self.deriver(pw);
        let mut blob = Vec::with_capacity(self.enc_verifier.len() + self.enc_vhash.len());
        blob.extend_from_slice(&self.enc_verifier);
        blob.extend_from_slice(&self.enc_vhash);
        let dec = rc4(&d.block_key(0), &blob);
        d.hash(&dec[..16]) == dec[16..]
    }
}

/// Parse the `FilePass` record (BIFF record `0x2F`) that must follow `BOF` at the
/// start of an encrypted `Workbook`/`Book` stream. Handles RC4 basic (version
/// major 1) and RC4-CryptoAPI (major ≥ 2); XOR obfuscation (`wEncryptionType 0`)
/// is left for the detect-only path.
fn parse_filepass(stream: &[u8]) -> Option<FilePass> {
    if stream.len() < 4 {
        return None;
    }
    let bof_size = u16::from_le_bytes([stream[2], stream[3]]) as usize;
    let fp = 4 + bof_size;
    let body = fp + 4;
    if body > stream.len() || u16::from_le_bytes([stream[fp], stream[fp + 1]]) != 0x2f {
        return None;
    }
    let size = u16::from_le_bytes([stream[fp + 2], stream[fp + 3]]) as usize;
    let rec = stream.get(body..body + size)?;
    if rec.len() < 6 || u16::from_le_bytes([rec[0], rec[1]]) != 1 {
        return None; // XOR obfuscation or none
    }
    let major = u16::from_le_bytes([rec[2], rec[3]]);
    if major == 1 {
        // RC4 basic: salt(16) ‖ encVerifier(16) ‖ encVerifierHash(16).
        let v = rec.get(6..54)?;
        Some(FilePass {
            salt: v[0..16].to_vec(),
            enc_verifier: v[16..32].to_vec(),
            enc_vhash: v[32..48].to_vec(),
            cryptoapi_key_bits: None,
        })
    } else {
        // RC4-CryptoAPI: Flags(4) HeaderSize(4) EncryptionHeader{…KeySize@16…}
        // then EncryptionVerifier{SaltSize(4) Salt EncVerifier(16) HashSize(4) Hash}.
        let hdr_meta = rec.get(6..14)?;
        let header_size = u32::from_le_bytes(hdr_meta[4..8].try_into().ok()?) as usize;
        let header = rec.get(14..14 + header_size)?;
        let key_bits = u32::from_le_bytes(header.get(16..20)?.try_into().ok()?);
        let v = rec.get(14 + header_size..)?;
        let salt_size = u32::from_le_bytes(v.get(0..4)?.try_into().ok()?) as usize;
        let salt = v.get(4..4 + salt_size)?.to_vec();
        let enc_verifier = v.get(4 + salt_size..4 + salt_size + 16)?.to_vec();
        let vh = 4 + salt_size + 16;
        let vhash_size = u32::from_le_bytes(v.get(vh..vh + 4)?.try_into().ok()?) as usize;
        let enc_vhash = v.get(vh + 4..vh + 4 + vhash_size)?.to_vec();
        Some(FilePass {
            salt,
            enc_verifier,
            enc_vhash,
            cryptoapi_key_bits: Some(key_bits),
        })
    }
}

// Record IDs whose *data* stays in cleartext ([MS-OFFCRYPTO] §2.3.6.1): BOF,
// FilePass, UsrExcl, FileLock, InterfaceHdr, RRDInfo, RRDHead.
const EXEMPT: &[u16] = &[0x0809, 0x002f, 0x0194, 0x0195, 0x00e1, 0x0196, 0x0138];
// BoundSheet8: its 4-byte `lbPlyPos` (right after the header) also stays cleartext.
const BOUNDSHEET8: u16 = 0x0085;
const BLOCK: usize = 1024;

/// Decrypt a whole `Workbook`/`Book` stream in place following the BIFF record
/// structure: record headers stay cleartext, exempt records' data stays
/// cleartext, and every other record's data is RC4-decrypted — while the cipher
/// position advances continuously over the cleartext regions (re-keyed each
/// 1024-byte block). See [MS-OFFCRYPTO] §2.3.6.1.
fn decrypt_workbook(stream: &[u8], deriver: &KeyDeriver) -> Vec<u8> {
    // `cipher_in` is the same length as the stream: cleartext positions are zero
    // (so the cipher still advances over them) and encrypted positions carry the
    // real bytes. `plain[pos] = Some(byte)` overlays the cleartext afterwards.
    let mut cipher_in = vec![0u8; stream.len()];
    let mut plain: Vec<Option<u8>> = vec![None; stream.len()];
    let mut p = 0usize;
    while p + 4 <= stream.len() {
        let num = u16::from_le_bytes([stream[p], stream[p + 1]]);
        let size = u16::from_le_bytes([stream[p + 2], stream[p + 3]]) as usize;
        let dstart = p + 4;
        let dend = (dstart + size).min(stream.len());
        // Record header is always cleartext.
        for k in 0..4.min(stream.len() - p) {
            plain[p + k] = Some(stream[p + k]);
        }
        if num == 0x2f {
            // FilePass: neutralise the type to 0 but keep the size field; zero data.
            plain[p] = Some(0);
            plain[p + 1] = Some(0);
            for pos in plain.iter_mut().take(dend).skip(dstart) {
                *pos = Some(0);
            }
        } else if EXEMPT.contains(&num) {
            for k in dstart..dend {
                plain[k] = Some(stream[k]);
            }
        } else if num == BOUNDSHEET8 {
            for k in dstart..(dstart + 4).min(dend) {
                plain[k] = Some(stream[k]); // lbPlyPos stays cleartext
            }
            let s = (dstart + 4).min(dend);
            cipher_in[s..dend].copy_from_slice(&stream[s..dend]);
        } else {
            cipher_in[dstart..dend].copy_from_slice(&stream[dstart..dend]);
        }
        p = dend;
    }
    // RC4 the buffer, re-keying every 1024 bytes.
    let mut out = Vec::with_capacity(stream.len());
    for (b, chunk) in cipher_in.chunks(BLOCK).enumerate() {
        out.extend_from_slice(&rc4(&deriver.block_key(b as u32), chunk));
    }
    // Overlay the cleartext skeleton.
    for (pos, &pb) in plain.iter().enumerate() {
        if let Some(byte) = pb {
            out[pos] = byte;
        }
    }
    out
}

/// Try to decrypt an encrypted BIFF8 `Workbook`/`Book` stream with the caller's
/// password pool plus exav's [`DEFAULT_OFFICE_PASSWORDS`]. Handles the RC4 schemes
/// (basic / CryptoAPI) and the legacy XOR obfuscation (`wEncryptionType == 0`).
/// Returns the decrypted stream on the first password that verifies, or `None`
/// if the scheme is unhandled or no password matched (the caller then reports
/// password-protected — never a silent clean).
pub(crate) fn try_decrypt_workbook(stream: &[u8], passwords: &[String]) -> Option<Vec<u8>> {
    let candidates: Vec<&str> = passwords
        .iter()
        .map(String::as_str)
        .chain(DEFAULT_OFFICE_PASSWORDS.iter().copied())
        .collect();
    // RC4 basic / CryptoAPI (wEncryptionType == 1).
    if let Some(fp) = parse_filepass(stream) {
        for pw in &candidates {
            if fp.password_ok(pw) {
                return Some(decrypt_workbook(stream, &fp.deriver(pw)));
            }
        }
        return None;
    }
    // Legacy XOR obfuscation (wEncryptionType == 0).
    if let Some(verifier) = parse_filepass_xor(stream) {
        for pw in &candidates {
            if xor_verify_password(pw, verifier) {
                return Some(decrypt_workbook_xor(stream, pw));
            }
        }
    }
    None
}

// ─────────────────── BIFF XOR obfuscation ([MS-OFFCRYPTO] §2.3.7) ───────────────
//
// The legacy `wEncryptionType == 0` scheme obfuscates each record's data with a
// 16-byte array derived from the password (`ROR(byte ^ pad, 5)` per byte), with
// the same cleartext-exempt records as the RC4 path. Clean-room from the public
// [MS-OFFCRYPTO] §2.3.7 tables/algorithms, cross-checked against the MIT
// msoffcrypto reference vectors.

#[rustfmt::skip]
const XOR_PAD: [u8; 15] = [
    0xBB, 0xFF, 0xFF, 0xBA, 0xFF, 0xFF, 0xB9, 0x80,
    0x00, 0xBE, 0x0F, 0x00, 0xBF, 0x0F, 0x00,
];
#[rustfmt::skip]
const XOR_INITIAL: [u16; 15] = [
    0xE1F0, 0x1D0F, 0xCC9C, 0x84C0, 0x110C, 0x0E10, 0xF1CE, 0x313E,
    0x1872, 0xE139, 0xD40F, 0x84F9, 0x280C, 0xA96A, 0x4EC3,
];
#[rustfmt::skip]
const XOR_MATRIX: [u16; 105] = [
    0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09, 0x7B61, 0xF6C2, 0xFDA5,
    0xEB6B, 0xC6F7, 0x9DCF, 0x2BBF, 0x4563, 0x8AC6, 0x05AD, 0x0B5A, 0x16B4, 0x2D68,
    0x5AD0, 0x0375, 0x06EA, 0x0DD4, 0x1BA8, 0x3750, 0x6EA0, 0xDD40, 0xD849, 0xA0B3,
    0x5147, 0xA28E, 0x553D, 0xAA7A, 0x44D5, 0x6F45, 0xDE8A, 0xAD35, 0x4A4B, 0x9496,
    0x390D, 0x721A, 0xEB23, 0xC667, 0x9CEF, 0x29FF, 0x53FE, 0xA7FC, 0x5FD9, 0x47D3,
    0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68, 0xF6D0, 0xB861, 0x60E3, 0xC1C6, 0x93AD,
    0x377B, 0x6EF6, 0xDDEC, 0x45A0, 0x8B40, 0x06A1, 0x0D42, 0x1A84, 0x3508, 0x6A10,
    0xAA51, 0x4483, 0x8906, 0x022D, 0x045A, 0x08B4, 0x1168, 0x76B4, 0xED68, 0xCAF1,
    0x85C3, 0x1BA7, 0x374E, 0x6E9C, 0x3730, 0x6E60, 0xDCC0, 0xA9A1, 0x4363, 0x86C6,
    0x1DAD, 0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373, 0x06E6, 0x0DCC, 0x1021, 0x2042,
    0x4084, 0x8108, 0x1231, 0x2462, 0x48C4,
];

/// `ROR(b1 ^ b2, 1)` over 8 bits — the per-element mixing of the XOR array.
fn xor_ror(b1: u8, b2: u8) -> u8 {
    (b1 ^ b2).rotate_right(1)
}

/// [MS-OFFCRYPTO] §2.3.7.1 password verifier derivation. `true` if `pw` matches
/// the stored `verification_bytes`.
fn xor_verify_password(pw: &str, verification_bytes: u16) -> bool {
    let bytes = pw.as_bytes();
    if bytes.is_empty() || bytes.len() > 15 {
        return false;
    }
    let mut arr: Vec<u16> = Vec::with_capacity(bytes.len() + 1);
    arr.push(bytes.len() as u16);
    arr.extend(bytes.iter().map(|&b| b as u16));
    arr.reverse();
    let mut verifier: u16 = 0;
    for b in arr {
        let i1 = if verifier & 0x4000 == 0 { 0 } else { 1 };
        let i2 = verifier.wrapping_mul(2) & 0x7FFF;
        verifier = (i1 ^ i2) ^ b;
    }
    (verifier ^ 0xCE4B) == verification_bytes
}

/// [MS-OFFCRYPTO] §2.3.7.2 `CreateXorKey_Method1`.
fn xor_create_key(pw: &[u8]) -> u16 {
    let mut xor_key = XOR_INITIAL[pw.len() - 1];
    let mut current_element: i32 = 0x68;
    for &ch in pw.iter().rev() {
        let mut c = ch;
        for _ in 0..7 {
            if c & 0x40 != 0 {
                xor_key ^= XOR_MATRIX[current_element as usize];
            }
            c <<= 1;
            current_element -= 1;
        }
    }
    xor_key
}

/// [MS-OFFCRYPTO] §2.3.7.2 `CreateXorArray_Method1`: the 16-byte obfuscation
/// array. `None` if the password length isn't 1..=15 (the scheme's range).
fn xor_create_array(pw: &str) -> Option<[u8; 16]> {
    let pw = pw.as_bytes();
    if pw.is_empty() || pw.len() > 15 {
        return None;
    }
    let xor_key = xor_create_key(pw);
    let hi = (xor_key >> 8) as u8;
    let lo = (xor_key & 0xFF) as u8;
    let mut obf = [0u8; 16];
    let mut index = pw.len();

    if index % 2 == 1 {
        obf[index] = xor_ror(XOR_PAD[0], hi);
        index -= 1;
        obf[index] = xor_ror(pw[pw.len() - 1], lo);
    }
    while index > 0 {
        index -= 1;
        obf[index] = xor_ror(pw[index], hi);
        index -= 1;
        obf[index] = xor_ror(pw[index], lo);
    }

    let mut index = 15usize;
    let mut pad_index = 15 - pw.len();
    while pad_index > 0 {
        obf[index] = xor_ror(XOR_PAD[pad_index], hi);
        index -= 1;
        pad_index -= 1;
        obf[index] = xor_ror(XOR_PAD[pad_index], lo);
        index -= 1;
        pad_index -= 1;
    }
    Some(obf)
}

/// Locate the `FilePass` record and, if it is the XOR scheme
/// (`wEncryptionType == 0`), return its 16-bit `verificationBytes`.
fn parse_filepass_xor(stream: &[u8]) -> Option<u16> {
    if stream.len() < 4 {
        return None;
    }
    let bof_size = u16::from_le_bytes([stream[2], stream[3]]) as usize;
    let fp = 4 + bof_size;
    let body = fp + 4;
    if body > stream.len() || u16::from_le_bytes([stream[fp], stream[fp + 1]]) != 0x2f {
        return None;
    }
    let size = u16::from_le_bytes([stream[fp + 2], stream[fp + 3]]) as usize;
    let rec = stream.get(body..body + size)?;
    // XORObfuscation: wEncryptionType(2)=0, Key(2), VerificationBytes(2).
    if rec.len() < 6 || u16::from_le_bytes([rec[0], rec[1]]) != 0 {
        return None;
    }
    Some(u16::from_le_bytes([rec[4], rec[5]]))
}

/// Decrypt a BIFF `Workbook`/`Book` stream obfuscated with the XOR scheme
/// ([MS-OFFCRYPTO] §2.3.7.3 `DecryptData_Method1`). Record headers and the
/// cleartext-exempt records (BOF/FilePass/… and BoundSheet8's `lbPlyPos`) stay
/// verbatim; every other record's data is de-obfuscated `ROR(byte ^ pad, 5)`,
/// with the array index seeded from the record's end offset in the stream.
fn decrypt_workbook_xor(stream: &[u8], password: &str) -> Vec<u8> {
    let Some(arr) = xor_create_array(password) else {
        return stream.to_vec();
    };
    let mut out = stream.to_vec();
    // De-obfuscate one encrypted run: `idx0` seeds the array position.
    let deobf = |out: &mut [u8], start: usize, end: usize, idx0: usize| {
        let mut idx = idx0 % 16;
        for k in start..end {
            out[k] = (stream[k] ^ arr[idx]).rotate_right(5);
            idx = (idx + 1) % 16;
        }
    };
    let mut p = 0usize;
    while p + 4 <= stream.len() {
        let num = u16::from_le_bytes([stream[p], stream[p + 1]]);
        let size = u16::from_le_bytes([stream[p + 2], stream[p + 3]]) as usize;
        let dstart = p + 4;
        let dend = (dstart + size).min(stream.len());
        if EXEMPT.contains(&num) {
            // header + data stay cleartext (already copied)
        } else if num == BOUNDSHEET8 {
            // lbPlyPos (first 4 data bytes) stays cleartext; the rest is a run
            // whose seed carries the +4 offset the spec applies to it.
            let run = (dstart + 4).min(dend);
            deobf(&mut out, run, dend, dend + 4);
        } else {
            deobf(&mut out, dstart, dend, dend);
        }
        p = dend;
    }
    out
}

// ─────────────────────────── OOXML (.docx/.xlsx) AES ───────────────────────────

use aes::cipher::{BlockDecrypt, KeyInit};

/// AES-ECB decrypt `data` in place-copy (used by OOXML STANDARD encryption, which
/// is ECB with no IV). Trailing partial block is left as-is.
fn aes_ecb_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    macro_rules! run {
        ($ty:ty) => {{
            if let Ok(c) = <$ty>::new_from_slice(key) {
                for chunk in out.chunks_mut(16) {
                    if chunk.len() == 16 {
                        let mut b =
                            aes::cipher::generic_array::GenericArray::clone_from_slice(chunk);
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
    let header_size = u32::from_le_bytes([info[8], info[9], info[10], info[11]]) as usize;
    // EncryptionHeader starts at offset 12; KeySize is its 5th u32 (offset +16).
    let hdr = info.get(12..12 + header_size)?;
    let key_bits = u32::from_le_bytes(hdr.get(16..20)?.try_into().ok()?);
    let key_bytes = if key_bits == 0 {
        16
    } else {
        (key_bits / 8) as usize
    };
    // EncryptionVerifier follows the header.
    let v = info.get(12 + header_size..)?;
    let salt_size = u32::from_le_bytes(v.get(0..4)?.try_into().ok()?) as usize;
    let salt = v.get(4..4 + salt_size)?.to_vec();
    let enc_verifier = v.get(4 + salt_size..4 + salt_size + 16)?.to_vec();
    let vh_off = 4 + salt_size + 16;
    let vhash_size = u32::from_le_bytes(v.get(vh_off..vh_off + 4)?.try_into().ok()?) as usize;
    // The stored hash is padded up to the cipher block; read the padded field.
    let padded = vhash_size.div_ceil(16) * 16;
    let enc_verifier_hash = v.get(vh_off + 4..vh_off + 4 + padded)?.to_vec();
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
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    let mut out = data.to_vec();
    let n = out.len() - out.len() % 16;
    if iv.len() < 16 || n == 0 {
        return out;
    }
    macro_rules! run {
        ($ty:ty) => {{
            if let Ok(c) = <cbc::Decryptor<$ty>>::new_from_slices(key, &iv[..16]) {
                let _ = c.decrypt_padded_mut::<NoPadding>(&mut out[..n]);
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

/// Agile password hash ([MS-OFFCRYPTO] §2.3.4.11): `H0 = Hash(salt ‖ UTF16LE(pw))`,
/// then `spin` iterations of `Hi = Hash(LE32(i) ‖ H(i-1))`. Excludes the block key.
fn agile_iterated_hash(salt: &[u8], pw: &str, alg: HashAlg, spin: u32) -> Vec<u8> {
    let mut h = alg.digest(&[salt, &utf16le(pw)].concat());
    for i in 0..spin {
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

    const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

    fn push_rec(v: &mut Vec<u8>, id: u16, data: &[u8]) {
        v.extend_from_slice(&id.to_le_bytes());
        v.extend_from_slice(&(data.len() as u16).to_le_bytes());
        v.extend_from_slice(data);
    }

    /// Build a `Workbook` stream (BOF, `FilePass`, an EICAR record, EOF) and
    /// encrypt the EICAR record's data with the block-0 keystream (the whole
    /// stream fits one 1024-byte block).
    fn encrypted_workbook(d: &KeyDeriver, filepass_body: &[u8]) -> Vec<u8> {
        let mut wb = Vec::new();
        push_rec(&mut wb, 0x0809, &[0u8; 16]); // BOF
        push_rec(&mut wb, 0x002f, filepass_body); // FilePass
        let off = wb.len() + 4;
        push_rec(&mut wb, 0x00ff, EICAR); // non-exempt → encrypted
        push_rec(&mut wb, 0x000a, &[]); // EOF
        let ks = rc4(&d.block_key(0), &vec![0u8; wb.len()]);
        for i in 0..EICAR.len() {
            wb[off + i] ^= ks[off + i];
        }
        assert!(
            !wb.windows(EICAR.len()).any(|w| w == EICAR),
            "EICAR encrypted"
        );
        wb
    }

    /// Encrypted verifier pair for a password/scheme: `verifier ‖ H(verifier)`
    /// under the block-0 keystream.
    fn verifier_pair(d: &KeyDeriver, verifier: &[u8]) -> Vec<u8> {
        let mut vblob = verifier.to_vec();
        vblob.extend_from_slice(&d.hash(verifier));
        rc4(&d.block_key(0), &vblob)
    }

    // Independently-generated vector (salt 00..0f, password "Secret1").
    #[test]
    fn rc4_basic_verifier_and_key() {
        let salt = (0u8..16).collect::<Vec<_>>();
        let fp = FilePass {
            salt: salt.clone(),
            enc_verifier: hex("d11cfb57cde29a6eaf45018e01931b31").to_vec(),
            enc_vhash: hex("9687999033ca45aaade5f45386030a07").to_vec(),
            cryptoapi_key_bits: None,
        };
        assert!(fp.password_ok("Secret1"));
        assert!(!fp.password_ok("wrong"));
        assert!(!fp.password_ok("VelvetSweatshop"));
        match KeyDeriver::basic(&salt, "Secret1") {
            KeyDeriver::Basic(inter) => assert_eq!(inter, hex5("cabe9bb94c")),
            _ => panic!(),
        }
    }

    // Independently-generated vector, cross-checked against the msoffcrypto
    // reference `verifypw` (salt 10..1f, password "VelvetSweatshop", 128-bit).
    #[test]
    fn rc4_cryptoapi_verifier_vector() {
        let salt = (16u8..32).collect::<Vec<_>>();
        let fp = FilePass {
            salt,
            enc_verifier: hex("66871900f3075fc3fa7e1d9b934d6b22").to_vec(),
            enc_vhash: hex20("13146eb6c265735c52ea6eb1cc48739e80561620").to_vec(),
            cryptoapi_key_bits: Some(128),
        };
        assert!(fp.password_ok("VelvetSweatshop"));
        assert!(!fp.password_ok("nope"));
    }

    #[test]
    fn rc4_is_symmetric() {
        let k = b"key1234567890abc";
        let pt = b"eicar-ish plaintext content";
        assert_eq!(rc4(k, &rc4(k, pt)), pt);
    }

    /// End-to-end (RC4 basic): VelvetSweatshop default recovers cleartext EICAR
    /// with no caller password.
    #[test]
    fn velvetsweatshop_basic_recovers_eicar() {
        let salt = [0x5au8; 16];
        let d = KeyDeriver::basic(&salt, "VelvetSweatshop");
        let enc = verifier_pair(&d, &[0x24u8; 16]);
        let mut fp = vec![1u8, 0, 1, 0, 1, 0]; // encType=1, ver 1.1
        fp.extend_from_slice(&salt);
        fp.extend_from_slice(&enc[..32]);
        let ct = encrypted_workbook(&d, &fp);
        let recovered = try_decrypt_workbook(&ct, &[]).expect("VelvetSweatshop must decrypt");
        assert!(recovered.windows(EICAR.len()).any(|w| w == EICAR));
    }

    /// End-to-end (RC4-CryptoAPI, 128-bit): VelvetSweatshop default recovers EICAR.
    #[test]
    fn velvetsweatshop_cryptoapi_recovers_eicar() {
        let salt = [0x3cu8; 16];
        let d = KeyDeriver::cryptoapi(&salt, "VelvetSweatshop", 128);
        let enc = verifier_pair(&d, &[0x24u8; 16]); // 16 + 20 = 36 bytes
                                                    // FilePass: encType(1) vMaj(3) vMin(3) Flags(4) HeaderSize(4) Header Verifier
        let mut header = vec![0u8; 32];
        header[16..20].copy_from_slice(&128u32.to_le_bytes()); // KeySize
        let mut vblk = Vec::new();
        vblk.extend_from_slice(&16u32.to_le_bytes());
        vblk.extend_from_slice(&salt);
        vblk.extend_from_slice(&enc[..16]);
        vblk.extend_from_slice(&20u32.to_le_bytes());
        vblk.extend_from_slice(&enc[16..36]);
        let mut fp = Vec::new();
        fp.extend_from_slice(&1u16.to_le_bytes());
        fp.extend_from_slice(&3u16.to_le_bytes());
        fp.extend_from_slice(&3u16.to_le_bytes());
        fp.extend_from_slice(&0x24u32.to_le_bytes());
        fp.extend_from_slice(&(header.len() as u32).to_le_bytes());
        fp.extend_from_slice(&header);
        fp.extend_from_slice(&vblk);
        let ct = encrypted_workbook(&d, &fp);
        let recovered = try_decrypt_workbook(&ct, &[]).expect("CryptoAPI VelvetSweatshop decrypt");
        assert!(recovered.windows(EICAR.len()).any(|w| w == EICAR));
    }

    fn aes_ecb_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
        use aes::cipher::{BlockEncrypt, KeyInit};
        let cipher = aes::Aes128::new_from_slice(key).unwrap();
        let mut out = data.to_vec();
        for chunk in out.chunks_mut(16) {
            let mut b = aes::cipher::generic_array::GenericArray::clone_from_slice(chunk);
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
        let eicar = EICAR;
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

        let mut plain = EICAR.to_vec();
        while !plain.len().is_multiple_of(16) {
            plain.push(0);
        }
        let mut package = (EICAR.len() as u64).to_le_bytes().to_vec();
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
                .any(|e| e.data.windows(EICAR.len()).any(|w| w == EICAR)),
            "EICAR must be recovered through the full container path"
        );
    }

    fn aes256_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
        use aes::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
        let mut out = data.to_vec();
        let n = out.len();
        let enc = <cbc::Encryptor<aes::Aes256>>::new_from_slices(key, &iv[..16]).unwrap();
        enc.encrypt_padded_mut::<NoPadding>(&mut out, n)
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
        let mut plain = EICAR.to_vec();
        while !plain.len().is_multiple_of(16) {
            plain.push(0);
        }
        let mut seg_iv = alg.digest(&[&kd_salt[..], &0u32.to_le_bytes()].concat());
        seg_iv.truncate(16);
        let seg = aes256_cbc_encrypt(&secret, &seg_iv, &plain);
        let mut package = (EICAR.len() as u64).to_le_bytes().to_vec();
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
            out.windows(EICAR.len()).any(|w| w == EICAR),
            "EICAR must be recovered from the decrypted agile package"
        );
    }

    /// Password verifier matches the MS-OFFCRYPTO reference vector (the
    /// `VelvetSweatshop` default stores `0x9a0a`).
    #[test]
    fn xor_verifier_matches_reference() {
        assert!(xor_verify_password("VelvetSweatshop", 0x9a0a));
        assert!(xor_verify_password("password1", 0xe1ae));
        assert!(xor_verify_password("Secret1", 0xc266));
        assert!(!xor_verify_password("VelvetSweatshop", 0x0000));
        assert!(!xor_verify_password("wrong", 0x9a0a));
    }

    /// The 16-byte obfuscation array matches the MIT msoffcrypto reference for
    /// several passwords (validates the tables + key derivation byte-for-byte).
    #[test]
    fn xor_array_matches_reference_vectors() {
        for (pw, hex) in [
            ("VelvetSweatshop", "876b9ae21ee305621e699660986e9404"),
            ("password1", "dbb75abe58b0da357bda1cf8bef81cdb"),
            ("abc", "95999475da577857da7465a87a2f2577"),
            ("Secret1", "7b3863b360b04a572d758f752d56928a"),
        ] {
            assert_eq!(
                xor_create_array(pw).unwrap().to_vec(),
                hexv(hex),
                "xor array mismatch for {pw:?}"
            );
        }
    }

    /// End-to-end: obfuscate a BIFF `Workbook` (BOF, XOR `FilePass`, an EICAR
    /// record, EOF) with the XOR scheme, then confirm the default-password path
    /// recovers the cleartext EICAR — exercising the per-record index math.
    #[test]
    fn xor_obfuscation_recovers_eicar() {
        let pw = "VelvetSweatshop";
        let arr = xor_create_array(pw).unwrap();

        let mut wb = Vec::new();
        push_rec(&mut wb, 0x0809, &[0u8; 16]); // BOF (exempt)
                                               // FilePass XOR: wEncryptionType=0, key, verifier(0x9a0a)
        let mut fp = Vec::new();
        fp.extend_from_slice(&0u16.to_le_bytes());
        fp.extend_from_slice(&0x1234u16.to_le_bytes()); // key (unused for verify)
        fp.extend_from_slice(&0x9a0au16.to_le_bytes()); // verificationBytes
        push_rec(&mut wb, 0x002f, &fp);
        let rec_off = wb.len(); // stream offset of the EICAR record header
        push_rec(&mut wb, 0x00ff, EICAR); // non-exempt → obfuscated
        push_rec(&mut wb, 0x000a, &[]); // EOF

        // Obfuscate the EICAR record's data in place: cipher = ROL(plain,5) ^ pad,
        // with the same end-offset seed the decryptor uses.
        let dstart = rec_off + 4;
        let dend = dstart + EICAR.len();
        let idx0 = dend % 16;
        for (j, k) in (dstart..dend).enumerate() {
            wb[k] = wb[k].rotate_left(5) ^ arr[(idx0 + j) % 16];
        }
        assert!(
            !wb.windows(EICAR.len()).any(|w| w == EICAR),
            "EICAR must be obfuscated in the input"
        );

        let recovered = try_decrypt_workbook(&wb, &[]).expect("XOR VelvetSweatshop must decrypt");
        assert!(
            recovered.windows(EICAR.len()).any(|w| w == EICAR),
            "EICAR must be recovered from the de-obfuscated workbook"
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

    fn hex(s: &str) -> [u8; 16] {
        let mut o = [0u8; 16];
        for (i, b) in o.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        o
    }
    fn hex20(s: &str) -> [u8; 20] {
        let mut o = [0u8; 20];
        for (i, b) in o.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        o
    }
    fn hex5(s: &str) -> [u8; 5] {
        let mut o = [0u8; 5];
        for (i, b) in o.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        o
    }
}
