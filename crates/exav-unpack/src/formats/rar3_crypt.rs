//! RAR 2.9 / 3.x / 4.x encryption: AES-128-CBC under a key and IV derived
//! from the password with SHA-1.
//!
//! The password in UTF-16LE and an 8-byte salt are hashed 2^18 times, each
//! round followed by the round number as 3 little-endian bytes. Every 2^14
//! rounds the last byte of the digest so far is one byte of the IV; the key is
//! the final digest's first 16 bytes, each 32-bit word in little-endian order.
//! The format has no password check: a wrong password is found out by the
//! member's checksum.

use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};
use sha1::{Digest, Sha1};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const ROUNDS: u32 = 1 << 18;

/// What a password and salt derive.
#[derive(Clone)]
pub(crate) struct Keys {
    key: [u8; 16],
    iv: [u8; 16],
}

/// Derive the key and IV of `password` over `salt`.
pub(crate) fn derive(password: &str, salt: &[u8; 8]) -> Keys {
    let mut seed: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    seed.extend_from_slice(salt);
    let mut sha = Sha1::new();
    let mut iv = [0u8; 16];
    for i in 0..ROUNDS {
        sha.update(&seed);
        sha.update(&i.to_le_bytes()[..3]);
        if i % (ROUNDS / 16) == 0 {
            iv[(i / (ROUNDS / 16)) as usize] = sha.clone().finalize()[19];
        }
    }
    let d = sha.finalize();
    let mut key = [0u8; 16];
    for (w, k) in d[..16].chunks(4).zip(key.chunks_mut(4)) {
        k.copy_from_slice(&[w[3], w[2], w[1], w[0]]);
    }
    Keys { key, iv }
}

/// Decrypt `data` under `keys`, the tail short of a block dropped.
pub(crate) fn decrypt(keys: &Keys, data: &mut Vec<u8>) {
    data.truncate(data.len() - data.len() % 16);
    let ok = Aes128CbcDec::new_from_slices(&keys.key, &keys.iv)
        .map(|c| c.decrypt_padded::<NoPadding>(data).is_ok())
        .unwrap_or(false);
    if !ok {
        data.clear();
    }
}

/// What each password derived over each salt, kept for the whole archive:
/// every derivation is 2^18 SHA-1 rounds.
#[derive(Default)]
pub(crate) struct KeyCache(Vec<([u8; 8], String, Keys)>);

impl KeyCache {
    pub(crate) fn get(&mut self, password: &str, salt: &[u8; 8]) -> Keys {
        if let Some((.., k)) = self.0.iter().find(|(s, p, _)| s == salt && p == password) {
            return k.clone();
        }
        let k = derive(password, salt);
        self.0.push((*salt, password.to_string(), k.clone()));
        k
    }
}

/// The passwords to try: the caller's, then the defaults.
pub(crate) fn candidates(passwords: &[String]) -> Vec<String> {
    passwords
        .iter()
        .cloned()
        .chain(
            super::DEFAULT_ARCHIVE_PASSWORDS
                .iter()
                .map(|p| p.to_string()),
        )
        .collect()
}
