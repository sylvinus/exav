use crate::formats::pdf_parse::types::Primitive;
use std::collections::HashMap;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use digest::Digest;
use md5::Md5;

const PADDING: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum CryptMethod {
    None,
    V2,
    AESV2,
    AESV3,
}

pub(crate) struct CryptDict {
    pub o: Vec<u8>,
    pub u: Vec<u8>,
    pub r: u32,
    pub v: i32,
    pub bits: u32,
    pub p: i32,
    pub encrypt_metadata: bool,
    pub crypt_filters: HashMap<String, CryptFilter>,
    pub default_stream_filter: Option<String>,
    pub oe: Option<Vec<u8>>,
    pub ue: Option<Vec<u8>>,
}

impl CryptDict {
    pub(crate) fn from_primitive(dict: &HashMap<String, Primitive>) -> Option<Self> {
        let o = dict.get("O")?.as_str()?.to_vec();
        let u = dict.get("U")?.as_str()?.to_vec();
        let r = dict.get("R")?.as_u32()?;
        let v = dict.get("V")?.as_i64()? as i32;
        let p = dict.get("P")?.as_i64()? as i32;

        let bits = match v {
            1 => 40,
            2 | 4 => dict.get("Length").and_then(|l| l.as_u32()).unwrap_or(128),
            5 | 6 => 256,
            _ => 128,
        };

        let encrypt_metadata = if p & (1 << 11) != 0 {
            false
        } else {
            match dict.get("EncryptMetadata") {
                Some(Primitive::Boolean(b)) => *b,
                _ => true,
            }
        };

        let mut crypt_filters = HashMap::new();
        let mut default_stream_filter = None;

        if let Some(Primitive::Dictionary(cf_dict)) = dict.get("CF") {
            for (name, val) in cf_dict {
                if let Primitive::Dictionary(cf_entries) = val {
                    let method = match cf_entries.get("CFM") {
                        Some(Primitive::Name(n)) => match n.as_str() {
                            "V2" => CryptMethod::V2,
                            "AESV2" => CryptMethod::AESV2,
                            "AESV3" => CryptMethod::AESV3,
                            _ => CryptMethod::None,
                        },
                        _ => CryptMethod::None,
                    };
                    let length = cf_entries.get("Length").and_then(|l| l.as_u32());
                    crypt_filters.insert(name.clone(), CryptFilter { method, length });
                }
            }
        }

        if let Some(Primitive::Name(n)) = dict.get("StmF") {
            default_stream_filter = Some(n.clone());
        } else if let Some(Primitive::Name(n)) = dict.get("Filter") {
            default_stream_filter = Some(n.clone());
        }

        let oe = dict.get("OE").and_then(|s| s.as_str()).map(|s| s.to_vec());
        let ue = dict.get("UE").and_then(|s| s.as_str()).map(|s| s.to_vec());

        Some(CryptDict {
            o,
            u,
            r,
            v,
            bits,
            p,
            encrypt_metadata,
            crypt_filters,
            default_stream_filter,
            oe,
            ue,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CryptFilter {
    pub method: CryptMethod,
    pub length: Option<u32>,
}

pub(crate) struct Decoder {
    pub key: Vec<u8>,
    pub key_size: usize,
    pub method: CryptMethod,
}

impl Decoder {
    pub(crate) fn from_password(
        dict: &CryptDict,
        id: &[u8],
        pass: &[u8],
    ) -> Result<Self, PdfCryptError> {
        let (key_bits, method) = resolve_crypt_method(dict)?;
        let level = dict.r;

        if (2..=4).contains(&level) {
            let key_size = key_bits as usize / 8;
            let key = key_derivation_user_password_rc4(level, key_size, dict, id, pass);

            if check_password_rc4(level, &dict.u, id, &key[..key_size.min(16)]) {
                return Ok(Decoder {
                    key,
                    key_size,
                    method,
                });
            }

            let password_wrap_key = key_derivation_owner_password_rc4(level, key_size, pass)?;
            let mut data = dict.o.clone();
            let rounds = if level == 2 { 1u8 } else { 20u8 };
            for round in 0..rounds {
                let mut round_key = password_wrap_key.clone();
                for byte in round_key.iter_mut() {
                    *byte ^= round;
                }
                rc4_apply(&round_key, &mut data);
            }

            let key = key_derivation_user_password_rc4(level, key_size, dict, id, &data);
            if check_password_rc4(level, &dict.u, id, &key[..key_size]) {
                return Ok(Decoder {
                    key,
                    key_size,
                    method,
                });
            }
            return Err(PdfCryptError::InvalidPassword);
        }

        if level == 5 || level == 6 {
            return derive_key_v5_v6(dict, id, pass, method);
        }

        Err(PdfCryptError::UnsupportedRevision(level))
    }

    pub(crate) fn decrypt_stream(&self, obj_id: u32, data: &mut [u8]) {
        if data.is_empty() || self.method == CryptMethod::None {
            return;
        }
        match self.method {
            CryptMethod::V2 => {
                let key = self.per_object_key(obj_id, None);
                rc4_apply(&key, data);
            }
            CryptMethod::AESV2 => {
                if data.len() < 16 {
                    return;
                }
                let (iv, ciphertext) = data.split_at_mut(16);
                let iv = iv.to_vec();
                let key = self.per_object_key(obj_id, Some(b"sAlT"));
                aes_128_cbc_decrypt(&key, &iv, ciphertext);
            }
            CryptMethod::AESV3 => {
                if data.len() < 16 {
                    return;
                }
                let (iv, ciphertext) = data.split_at_mut(16);
                let iv = iv.to_vec();
                let key = self.key[..32.min(self.key.len())].to_vec();
                aes_256_cbc_decrypt(&key, &iv, ciphertext);
            }
            CryptMethod::None => {}
        }
    }

    fn per_object_key(&self, obj_id: u32, salt: Option<&[u8]>) -> Vec<u8> {
        let n = self.key_size.min(16);
        let mut data = Vec::with_capacity(n + 5 + 4);
        data.extend_from_slice(&self.key[..n]);
        data.extend_from_slice(&obj_id.to_le_bytes()[..3]);
        data.extend_from_slice(&0u16.to_le_bytes());
        if let Some(s) = salt {
            data.extend_from_slice(s);
        }
        let hash = md5_compute(&data);
        hash[..n.min(16)].to_vec()
    }
}

#[derive(Debug)]
pub(crate) enum PdfCryptError {
    InvalidPassword,
    UnsupportedRevision(u32),
    MissingEntry(String),
    InvalidData(String),
}

impl std::fmt::Display for PdfCryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPassword => write!(f, "invalid password"),
            Self::UnsupportedRevision(r) => write!(f, "unsupported revision {r}"),
            Self::MissingEntry(s) => write!(f, "missing entry: {s}"),
            Self::InvalidData(s) => write!(f, "invalid data: {s}"),
        }
    }
}

fn resolve_crypt_method(dict: &CryptDict) -> Result<(u32, CryptMethod), PdfCryptError> {
    match dict.v {
        1 => Ok((40, CryptMethod::V2)),
        2 => {
            if dict.bits % 8 != 0 {
                Err(PdfCryptError::InvalidData(format!(
                    "invalid key length {}",
                    dict.bits
                )))
            } else {
                Ok((dict.bits, CryptMethod::V2))
            }
        }
        4..=6 => {
            let filter_name = dict
                .default_stream_filter
                .as_ref()
                .ok_or_else(|| PdfCryptError::MissingEntry("StmF".into()))?;
            let cf = dict
                .crypt_filters
                .get(filter_name)
                .ok_or_else(|| PdfCryptError::MissingEntry(format!("CF/{filter_name}")))?;
            match cf.method {
                CryptMethod::V2 | CryptMethod::AESV2 => {
                    Ok((cf.length.map(|n| 8 * n).unwrap_or(dict.bits), cf.method))
                }
                CryptMethod::AESV3 if dict.v == 5 => {
                    Ok((cf.length.map(|n| 8 * n).unwrap_or(dict.bits), cf.method))
                }
                CryptMethod::AESV3 if dict.v == 6 => Ok((256, CryptMethod::AESV3)),
                m => Err(PdfCryptError::InvalidData(format!(
                    "unsupported crypt method {m:?}"
                ))),
            }
        }
        v => Err(PdfCryptError::InvalidData(format!(
            "unsupported V value {v}"
        ))),
    }
}

// ---- RC4 (RFC 6229) — kept as hand-rolled because the `rc4` crate requires
// compile-time typenum key sizes, while PDF uses variable-length keys (40-2048
// bits). This is a well-understood 17-line cipher with no unsafe code.

fn rc4_apply(key: &[u8], data: &mut [u8]) {
    if key.is_empty() {
        return;
    }
    let mut s = [0u8; 256];
    for (i, x) in s.iter_mut().enumerate() {
        *x = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    for b in data.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        *b ^= s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
    }
}

// ---- MD5 (md-5 crate: Md5 + Digest trait) ----

fn md5_compute(data: &[u8]) -> [u8; 16] {
    let digest = Md5::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

fn md5_streaming(data_parts: &[&[u8]]) -> [u8; 16] {
    let mut ctx = Md5::new();
    for part in data_parts {
        ctx.update(part);
    }
    let digest = ctx.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

// ---- SHA-256/384/512 (sha2 crate, digest 0.10) ----

fn sha256_compute(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn sha384_compute(data: &[u8]) -> [u8; 48] {
    let mut hasher = sha2::Sha384::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 48];
    out.copy_from_slice(&result);
    out
}

fn sha512_compute(data: &[u8]) -> [u8; 64] {
    let mut hasher = sha2::Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

struct Sha256Stream(sha2::Sha256);

impl Sha256Stream {
    fn new() -> Self {
        Sha256Stream(sha2::Sha256::new())
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> [u8; 32] {
        let result = self.0.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

// ---- Password derivation (V1-V4, RC4) ----

fn key_derivation_user_password_rc4(
    revision: u32,
    key_size: usize,
    dict: &CryptDict,
    id: &[u8],
    pass: &[u8],
) -> Vec<u8> {
    let o = &dict.o;
    let p = dict.p;
    let padded_pass = if pass.len() < 32 {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(pass);
        buf.extend_from_slice(&PADDING[..32 - pass.len()]);
        buf
    } else {
        pass[..32].to_vec()
    };

    let p_bytes = p.to_le_bytes();
    let mut data_parts: Vec<&[u8]> = vec![&padded_pass, o, &p_bytes, id];
    if revision >= 4 && !dict.encrypt_metadata {
        data_parts.push(&[0xff, 0xff, 0xff, 0xff]);
    }
    let mut data = md5_streaming(&data_parts);

    if revision >= 3 {
        for _ in 0..50 {
            data = md5_compute(&data[..key_size.min(16)]);
        }
    }
    let mut key = vec![0u8; key_size.max(16)];
    key[..16].copy_from_slice(&data);
    key
}

fn key_derivation_owner_password_rc4(
    revision: u32,
    key_size: usize,
    pass: &[u8],
) -> Result<Vec<u8>, PdfCryptError> {
    let mut ctx = Md5::new();
    if pass.len() < 32 {
        ctx.update(pass);
        ctx.update(&PADDING[..32 - pass.len()]);
    } else {
        ctx.update(&pass[..32]);
    }
    if revision >= 3 {
        for _ in 0..50 {
            let digest = ctx.finalize();
            ctx = Md5::new();
            ctx.update(digest);
        }
    }
    let digest = ctx.finalize();
    Ok(digest[..key_size].to_vec())
}

fn check_password_rc4(revision: u32, document_u: &[u8], id: &[u8], key: &[u8]) -> bool {
    match revision {
        2 => {
            let mut data = PADDING.to_vec();
            rc4_apply(key, &mut data);
            data == document_u
        }
        3..=4 => {
            let u_hash = compute_u_rev_3_4(id, key);
            document_u.starts_with(&u_hash)
        }
        _ => false,
    }
}

fn compute_u_rev_3_4(id: &[u8], key: &[u8]) -> [u8; 16] {
    let mut data = md5_streaming(&[&PADDING, id]);
    rc4_apply(key, &mut data);
    for i in 1u8..=19 {
        let mut round_key = key.to_vec();
        for b in round_key.iter_mut() {
            *b ^= i;
        }
        rc4_apply(&round_key, &mut data);
    }
    data
}

// ---- V5/V6 key derivation ----

fn derive_key_v5_v6(
    dict: &CryptDict,
    _id: &[u8],
    pass: &[u8],
    method: CryptMethod,
) -> Result<Decoder, PdfCryptError> {
    let u = &dict.u;
    let o = &dict.o;
    if u.len() != 48 || o.len() != 48 {
        return Err(PdfCryptError::InvalidData(
            "U/O must be 48 bytes for V5/V6".into(),
        ));
    }

    let user_hash = &u[..32];
    let user_validation_salt = &u[32..40];
    let user_key_salt = &u[40..48];
    let owner_hash = &o[..32];
    let owner_validation_salt = &o[32..40];
    let owner_key_salt = &o[40..48];

    let password_prepped = stringprep::saslprep(
        std::str::from_utf8(pass).map_err(|_| PdfCryptError::InvalidPassword)?,
    )
    .map_err(|_| PdfCryptError::InvalidPassword)?
    .as_bytes()
    .to_vec();

    let (intermediate_key, wrapped_key) = if dict.r == 6 {
        let user_hash_computed = revision_6_kdf(&password_prepped, user_validation_salt, b"");
        if user_hash_computed == *user_hash {
            (
                revision_6_kdf(&password_prepped, user_key_salt, b"").to_vec(),
                dict.ue.clone().unwrap_or_default(),
            )
        } else {
            let owner_hash_computed = revision_6_kdf(&password_prepped, owner_validation_salt, u);
            if owner_hash_computed == *owner_hash {
                (
                    revision_6_kdf(&password_prepped, owner_key_salt, u).to_vec(),
                    dict.oe.clone().unwrap_or_default(),
                )
            } else {
                return Err(PdfCryptError::InvalidPassword);
            }
        }
    } else {
        let computed = Sha256Stream::new().finalize_with(&password_prepped, user_validation_salt);
        if computed[..] == *user_hash {
            let kdf = Sha256Stream::new().finalize_with(&password_prepped, user_key_salt);
            (kdf.to_vec(), dict.ue.clone().unwrap_or_default())
        } else {
            let computed2 =
                Sha256Stream::new().finalize_with_3(&password_prepped, owner_validation_salt, u);
            if computed2[..] == *owner_hash {
                let kdf = Sha256Stream::new().finalize_with_3(&password_prepped, owner_key_salt, u);
                (kdf.to_vec(), dict.oe.clone().unwrap_or_default())
            } else {
                return Err(PdfCryptError::InvalidPassword);
            }
        }
    };

    let zero_iv = [0u8; 16];
    let mut key_data = wrapped_key.clone();
    aes_256_cbc_decrypt(
        &intermediate_key[..32.min(intermediate_key.len())],
        &zero_iv,
        &mut key_data,
    );
    key_data.truncate(32);

    Ok(Decoder {
        key: key_data,
        key_size: 32,
        method,
    })
}

impl Sha256Stream {
    fn finalize_with(mut self, a: &[u8], b: &[u8]) -> [u8; 32] {
        self.update(a);
        self.update(b);
        self.finalize()
    }
    fn finalize_with_3(mut self, a: &[u8], b: &[u8], c: &[u8]) -> [u8; 32] {
        self.update(a);
        self.update(b);
        self.update(c);
        self.finalize()
    }
}

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

fn revision_6_kdf(password: &[u8], salt: &[u8], u: &[u8]) -> [u8; 32] {
    let mut block_size: usize = 32;
    let mut block = [0u8; 64];

    let h = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        hasher.update(u);
        let r = hasher.finalize();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&r);
        buf
    };

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&h[..16]);
    iv.copy_from_slice(&h[16..32]);
    block[..32].copy_from_slice(&h[..32]);

    let mut i = 0u32;
    let mut data_buf = vec![0u8; (password.len() + 64 + u.len()) * 64];
    loop {
        let data_repeat_len = password.len() + block_size + u.len();
        data_buf[..password.len()].copy_from_slice(password);
        data_buf[password.len()..password.len() + block_size].copy_from_slice(&block[..block_size]);
        data_buf[password.len() + block_size..data_repeat_len].copy_from_slice(u);
        let total = data_repeat_len * 64;
        for j in 1..64 {
            data_buf.copy_within(..data_repeat_len, j * data_repeat_len);
        }

        let encryptor = Aes128CbcEnc::new(&key.into(), &iv.into());
        let mut block_data = data_buf[..total].to_vec();
        while block_data.len() % 16 != 0 {
            block_data.push(0);
        }
        let padded_len = block_data.len();
        let _ = encryptor.encrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(
            &mut block_data,
            padded_len,
        );
        let encrypted = &block_data[..total];

        let sum: usize = encrypted[..16].iter().map(|&b| b as usize).sum();
        block_size = sum % 3 * 16 + 32;

        match block_size {
            32 => {
                let hash = sha256_compute(encrypted);
                block[..32].copy_from_slice(&hash);
            }
            48 => {
                let hash = sha384_compute(encrypted);
                block[..48].copy_from_slice(&hash);
            }
            64 => {
                let hash = sha512_compute(encrypted);
                block[..64].copy_from_slice(&hash);
            }
            _ => {}
        }

        key.copy_from_slice(&block[..16]);
        iv.copy_from_slice(&block[16..32]);

        i += 1;
        if i >= 64 {
            break;
        }
        if i >= 32 && block[63] as u32 >= 32 {
            break;
        }
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&block[..32]);
    result
}

// ---- AES wrappers (aes + cbc crates) ----

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

fn aes_128_cbc_decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) {
    if key.len() < 16 || iv.len() < 16 || data.is_empty() {
        return;
    }
    let cipher = Aes128CbcDec::new_from_slices(&key[..16], &iv[..16]);
    if let Ok(cipher) = cipher {
        let _ = cipher.decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(data);
    }
}

fn aes_256_cbc_decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) {
    if key.len() < 32 || iv.len() < 16 || data.is_empty() {
        return;
    }
    let cipher = Aes256CbcDec::new_from_slices(&key[..32], &iv[..16]);
    if let Ok(cipher) = cipher {
        let _ = cipher.decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(data);
    }
}
