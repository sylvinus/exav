//! RAR5 encryption: AES-256-CBC under a PBKDF2-HMAC-SHA256 key, as RARLAB's
//! format technote lays out the records.
//!
//! One PBKDF2 block over the password and the record's salt gives three values,
//! read at 2^count, 2^count + 16 and 2^count + 32 iterations: the AES key, the
//! key that tweaks the member's checksum, and the password check, the last
//! folded to 8 bytes by XOR.

use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// The largest KDF count RAR writes: 2^24 iterations. A larger one costs more
/// than any archive is worth and is refused.
const MAX_KDF_COUNT: u8 = 24;

/// What the password and salt derive.
#[derive(Clone)]
pub(crate) struct Keys {
    pub key: [u8; 32],
    pub hash_key: [u8; 32],
    check: [u8; 8],
}

/// The fields of a file encryption record (type 0x01) or an archive
/// encryption header after its common fields.
#[derive(Clone)]
pub(crate) struct CryptRecord {
    pub kdf_count: u8,
    pub salt: [u8; 16],
    /// Absent in the archive encryption header, whose headers carry their own.
    pub iv: [u8; 16],
    /// The password check and its SHA-256 checksum, when the flag says so.
    pub check: Option<[u8; 12]>,
    /// Flag 0x0002: the stored checksum is keyed to the password.
    pub tweaked: bool,
}

impl CryptRecord {
    /// Parse the record body after its type: version, flags, KDF count, salt,
    /// then the IV when `with_iv`, then the check value if flagged.
    pub(crate) fn parse(b: &[u8], with_iv: bool) -> Option<Self> {
        let (version, n) = super::rar::vint(b, 0)?;
        let (flags, m) = super::rar::vint(b, n)?;
        if version != 0 {
            return None;
        }
        let mut p = n + m;
        let kdf_count = *b.get(p)?;
        p += 1;
        let salt: [u8; 16] = b.get(p..p + 16)?.try_into().ok()?;
        p += 16;
        let mut iv = [0u8; 16];
        if with_iv {
            iv = b.get(p..p + 16)?.try_into().ok()?;
            p += 16;
        }
        let check = if flags & 0x01 != 0 {
            Some(b.get(p..p + 12)?.try_into().ok()?)
        } else {
            None
        };
        Some(CryptRecord {
            kdf_count,
            salt,
            iv,
            check,
            tweaked: flags & 0x02 != 0,
        })
    }

    /// Whether `keys` pass the record's password check. A check value whose
    /// own checksum is wrong says nothing, and passes.
    pub(crate) fn accepts(&self, keys: &Keys) -> bool {
        let Some(c) = self.check else {
            return true;
        };
        if Sha256::digest(&c[..8])[..4] != c[8..] {
            return true;
        }
        c[..8] == keys.check
    }
}

/// Derive the keys for `password` over `salt` at 2^`kdf_count` iterations.
pub(crate) fn derive(password: &[u8], salt: &[u8; 16], kdf_count: u8) -> Option<Keys> {
    if kdf_count > MAX_KDF_COUNT {
        return None;
    }
    let mac = HmacSha256::new_from_slice(password).ok()?;
    let rounds = 1u32 << kdf_count;
    let mut m = mac.clone();
    m.update(salt);
    m.update(&1u32.to_be_bytes());
    let mut u: [u8; 32] = m.finalize().into_bytes().into();
    let mut f = u;
    let mut got = [[0u8; 32]; 3];
    for i in 1..=rounds + 32 {
        if i > 1 {
            let mut m = mac.clone();
            m.update(&u);
            u = m.finalize().into_bytes().into();
            for (a, b) in f.iter_mut().zip(u) {
                *a ^= b;
            }
        }
        if i == rounds {
            got[0] = f;
        } else if i == rounds + 16 {
            got[1] = f;
        } else if i == rounds + 32 {
            got[2] = f;
        }
    }
    let mut check = [0u8; 8];
    for (i, b) in got[2].iter().enumerate() {
        check[i % 8] ^= b;
    }
    Some(Keys {
        key: got[0],
        hash_key: got[1],
        check,
    })
}

/// The keys of the first candidate password `record` accepts: the caller's,
/// then those tried on an encrypted ZIP. `cache` keeps what each salt derived, since
/// every member of an archive usually shares one and each derivation costs
/// tens of thousands of HMACs.
pub(crate) fn find_keys(
    record: &CryptRecord,
    passwords: &[String],
    cache: &mut Vec<([u8; 16], u8, Vec<u8>, Keys)>,
) -> Option<Keys> {
    find_keys_within(record, passwords, cache, MAX_KDF_ROUNDS)
}

/// The PBKDF2 iterations all the derivations of one archive may add up to:
/// every member may carry a salt of its own, and every password is tried over
/// each. About half a minute of HMACs.
const MAX_KDF_ROUNDS: u64 = 1 << 25;

fn find_keys_within(
    record: &CryptRecord,
    passwords: &[String],
    cache: &mut Vec<([u8; 16], u8, Vec<u8>, Keys)>,
    max_rounds: u64,
) -> Option<Keys> {
    let candidates = passwords
        .iter()
        .map(String::as_str)
        .chain(super::DEFAULT_ARCHIVE_PASSWORDS.iter().copied());
    let rounds_of = |count: u8| 1u64 << count.min(MAX_KDF_COUNT);
    let mut spent: u64 = cache.iter().map(|(_, c, ..)| rounds_of(*c)).sum();
    for pw in candidates {
        let pw = pw.as_bytes();
        let cached = cache
            .iter()
            .find(|(s, c, p, _)| *s == record.salt && *c == record.kdf_count && p == pw)
            .map(|(.., k)| k.clone());
        let keys = match cached {
            Some(k) => k,
            None => {
                spent = spent.saturating_add(rounds_of(record.kdf_count));
                if spent > max_rounds {
                    return None;
                }
                let k = derive(pw, &record.salt, record.kdf_count)?;
                cache.push((record.salt, record.kdf_count, pw.to_vec(), k.clone()));
                k
            }
        };
        // With no check value the first candidate is taken, and the member's
        // checksum decides.
        if record.accepts(&keys) {
            return Some(keys);
        }
    }
    None
}

/// Decrypt `data` in place under `key` and `iv`, the tail short of a block
/// dropped.
pub(crate) fn decrypt(key: &[u8; 32], iv: &[u8; 16], data: &mut Vec<u8>) {
    use aes::cipher::block_padding::NoPadding;
    data.truncate(data.len() - data.len() % 16);
    let ok = Aes256CbcDec::new_from_slices(key, iv)
        .map(|c| c.decrypt_padded::<NoPadding>(data).is_ok())
        .unwrap_or(false);
    if !ok {
        data.clear();
    }
}

/// A CRC-32 as a member under a tweaked checksum stores it: HMAC-SHA256 of its
/// bytes under the hash key, folded to 32 bits.
pub(crate) fn tweak_crc(hash_key: &[u8; 32], crc: u32) -> u32 {
    let Ok(mut m) = HmacSha256::new_from_slice(hash_key) else {
        return crc;
    };
    m.update(&crc.to_le_bytes());
    m.finalize()
        .into_bytes()
        .iter()
        .enumerate()
        .fold(0u32, |r, (i, &b)| r ^ (u32::from(b) << ((i & 3) * 8)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record whose password check no candidate passes.
    fn record(salt: u8, kdf_count: u8) -> CryptRecord {
        let value = [7u8; 8];
        let mut check = [0u8; 12];
        check[..8].copy_from_slice(&value);
        check[8..].copy_from_slice(&Sha256::digest(value)[..4]);
        CryptRecord {
            kdf_count,
            salt: [salt; 16],
            iv: [0; 16],
            check: Some(check),
            tweaked: false,
        }
    }

    /// Salts of a member each, and a password list: the derivations stop at
    /// the archive's total, not at the end of the members.
    #[test]
    fn key_derivations_over_many_salts_stop_at_the_total() {
        let passwords: Vec<String> = (0..50).map(|i| format!("password {i}")).collect();
        let mut cache = Vec::new();
        // 2^10 iterations a derivation, 2^13 allowed in all: eight of them.
        for salt in 0..40 {
            assert!(find_keys_within(&record(salt, 10), &passwords, &mut cache, 1 << 13).is_none());
        }
        assert_eq!(cache.len(), 8);
    }
}
