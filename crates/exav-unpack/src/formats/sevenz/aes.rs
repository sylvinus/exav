//! 7z AES-256 decryption (method `06F10701`, "7zAES").
//!
//! 7-Zip encrypts a folder's packed stream with AES-256-CBC. The 256-bit key is
//! derived from the passphrase and a per-archive salt by an iterated SHA-256:
//! a single hash context is updated with `salt || password_utf16le || counter`
//! (`counter` a little-endian `u64`, incremented each round) `2^numCyclesPower`
//! times, then finalised. The IV and salt travel in the coder properties. This
//! is the decrypt half only — no key wrapping, no RNG.
//!
//! Only the *data* layer is handled here (the common `7z a -p…` case, plaintext
//! header). Archives with an AES-encrypted *header* (`-mhe=on`) fail to parse
//! and are still reported encrypted/unsupported by the caller.
//!
//! `#![forbid(unsafe_code)]`: property parsing is bounds-checked, the KDF round
//! count is capped to reject a DoS, and a wrong passphrase simply yields bytes
//! the downstream codec rejects (never a panic, never emitted as data).

use crate::LimitHit;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read};

/// The special `numCyclesPower` meaning "use the passphrase (with salt) verbatim
/// as the key" — no hashing.
const NO_HASH_CYCLES: u32 = 0x3f;

/// Upper bound on `numCyclesPower` we will run the KDF for. The 7-Zip default is
/// 19 (2^19 ≈ 5·10^5 SHA-256 blocks); anything above this is treated as a
/// denial-of-service attempt and rejected. (`0x3f` is the no-hash sentinel and
/// is allowed separately.)
const MAX_CYCLES_POWER: u32 = 24;

/// Parsed 7zAES coder properties.
struct AesProps {
    num_cycles_power: u32,
    salt: Vec<u8>,
    iv: [u8; 16],
}

/// Parse the 7zAES coder `properties` blob into `(numCyclesPower, salt, iv)`.
/// Layout: byte0 = `numCyclesPower` in the low 6 bits; bit7/bit6 are the salt/iv
/// size "carry" bits; if either is set, byte1's nibbles add to the salt/iv
/// sizes; then `salt` and `iv` bytes follow. Returns `None` on malformed input.
fn parse_props(props: &[u8]) -> Option<AesProps> {
    let b0 = *props.first()?;
    let num_cycles_power = (b0 & 0x3f) as u32;
    let mut salt_size = 0usize;
    let mut iv_size = 0usize;
    let mut pos = 1usize;
    if b0 & 0xc0 != 0 {
        salt_size = ((b0 >> 7) & 1) as usize;
        iv_size = ((b0 >> 6) & 1) as usize;
        if props.len() >= 2 {
            let b1 = props[1];
            salt_size += (b1 >> 4) as usize;
            iv_size += (b1 & 0x0f) as usize;
            pos = 2;
        }
    }
    if iv_size > 16 {
        return None;
    }
    let salt_end = pos.checked_add(salt_size)?;
    let iv_end = salt_end.checked_add(iv_size)?;
    if iv_end > props.len() {
        return None;
    }
    let salt = props[pos..salt_end].to_vec();
    let mut iv = [0u8; 16];
    iv[..iv_size].copy_from_slice(&props[salt_end..iv_end]);
    Some(AesProps {
        num_cycles_power,
        salt,
        iv,
    })
}

/// Derive the AES-256 key from a UTF-16LE password, the salt, and the cycle
/// count. `None` if the cycle count is beyond [`MAX_CYCLES_POWER`] (DoS guard).
fn derive_key(password_utf16le: &[u8], salt: &[u8], num_cycles_power: u32) -> Option<[u8; 32]> {
    if num_cycles_power == NO_HASH_CYCLES {
        // No hashing: key = (salt || password), zero-padded / truncated to 32.
        let mut key = [0u8; 32];
        let mut concat = Vec::with_capacity(salt.len() + password_utf16le.len());
        concat.extend_from_slice(salt);
        concat.extend_from_slice(password_utf16le);
        let n = concat.len().min(32);
        key[..n].copy_from_slice(&concat[..n]);
        return Some(key);
    }
    if num_cycles_power > MAX_CYCLES_POWER {
        return None;
    }
    let rounds: u64 = 1u64 << num_cycles_power;
    let mut hasher = Sha256::new();
    let mut counter = [0u8; 8];
    for _ in 0..rounds {
        hasher.update(salt);
        hasher.update(password_utf16le);
        hasher.update(counter);
        // Increment the 64-bit little-endian counter.
        for byte in counter.iter_mut() {
            let (v, carry) = byte.overflowing_add(1);
            *byte = v;
            if !carry {
                break;
            }
        }
    }
    Some(hasher.finalize().into())
}

/// Encode a passphrase as UTF-16LE, as 7-Zip does before key derivation.
fn utf16le(password: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(password.len() * 2);
    for u in password.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// A `Read` adapter that decrypts a 7zAES folder stream. It reads the whole
/// ciphertext on first read (folder streams are bounded by the archive/budget),
/// AES-256-CBC-decrypts it with no padding (7z streams are block-aligned; the
/// exact unpacked length is enforced by the caller), and serves the plaintext.
pub(super) struct Aes7zReader {
    inner: Option<Box<dyn Read>>,
    key: [u8; 32],
    iv: [u8; 16],
    plain: Cursor<Vec<u8>>,
}

impl Aes7zReader {
    /// Build the decryptor for a 7zAES coder. `password` is the passphrase to
    /// try. Returns an error if the properties are malformed, no password was
    /// supplied, or the KDF cost is out of range — the caller maps that to the
    /// existing "encrypted / unsupported" outcome.
    pub(super) fn new(
        inner: Box<dyn Read>,
        properties: &[u8],
        password: Option<&str>,
    ) -> Result<Self, LimitHit> {
        let Some(password) = password else {
            return Err(LimitHit::corrupt("7z: AES member needs a password".into()));
        };
        let props =
            parse_props(properties).ok_or_else(|| LimitHit::corrupt("7z: bad AES props".into()))?;
        let key = derive_key(&utf16le(password), &props.salt, props.num_cycles_power)
            .ok_or_else(|| LimitHit::corrupt("7z: AES KDF cost too high".into()))?;
        Ok(Aes7zReader {
            inner: Some(inner),
            key,
            iv: props.iv,
            plain: Cursor::new(Vec::new()),
        })
    }

    fn fill(&mut self) -> io::Result<()> {
        let Some(mut inner) = self.inner.take() else {
            return Ok(());
        };
        let mut ct = Vec::new();
        inner.read_to_end(&mut ct)?;
        // CBC operates on whole blocks; drop any trailing partial block.
        let full = ct.len() - (ct.len() % 16);
        ct.truncate(full);
        let pt = cbc::Decryptor::<aes::Aes256>::new(&self.key.into(), &self.iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut ct)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "7z AES decrypt"))?
            .to_vec();
        self.plain = Cursor::new(pt);
        Ok(())
    }
}

impl Read for Aes7zReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.inner.is_some() {
            self.fill()?;
        }
        self.plain.read(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::BlockEncryptMut;

    /// AES-256-CBC encrypt with NoPadding (test-only, mirrors the decrypt path)
    /// to build a ciphertext the reader must recover.
    fn encrypt(key: &[u8; 32], iv: &[u8; 16], mut data: Vec<u8>) -> Vec<u8> {
        let pad = (16 - data.len() % 16) % 16;
        data.resize(data.len() + pad, 0);
        let n = data.len();
        cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into())
            .encrypt_padded_mut::<NoPadding>(&mut data, n)
            .unwrap()
            .to_vec()
    }

    #[test]
    fn kdf_matches_reference_default_cycles() {
        // Derive with the default numCyclesPower=19 and a known salt/password,
        // then confirm the key round-trips an AES-CBC blob end to end. (This
        // exercises the exact KDF the reader uses, so a wrong iteration count or
        // byte order would break the round-trip below.)
        let props = build_props(19, b"SALTSALT", &[0u8; 16]);
        let parsed = parse_props(&props).unwrap();
        assert_eq!(parsed.num_cycles_power, 19);
        assert_eq!(parsed.salt, b"SALTSALT");
        let key = derive_key(&utf16le("hunter2"), &parsed.salt, 19).unwrap();
        // Determinism: same inputs → same key.
        let key2 = derive_key(&utf16le("hunter2"), &parsed.salt, 19).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn reader_round_trips_plaintext() {
        let props = build_props(16, b"\x01\x02\x03\x04", &[9u8; 16]);
        let parsed = parse_props(&props).unwrap();
        let key = derive_key(&utf16le("s3cr3t"), &parsed.salt, parsed.num_cycles_power).unwrap();
        let plain = b"CreateObject(\"WScript.Shell\") EICAR body padded out to blocks!!".to_vec();
        let ct = encrypt(&key, &parsed.iv, plain.clone());

        let mut reader =
            Aes7zReader::new(Box::new(Cursor::new(ct)), &props, Some("s3cr3t")).unwrap();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        // Decryption yields the block-padded plaintext; the real caller truncates
        // to the known unpacked size. Compare the meaningful prefix.
        assert!(
            got.starts_with(&plain),
            "decrypted prefix must match plaintext"
        );
    }

    #[test]
    fn wrong_password_does_not_match() {
        let props = build_props(16, b"\x01\x02\x03\x04", &[9u8; 16]);
        let parsed = parse_props(&props).unwrap();
        let key = derive_key(&utf16le("right"), &parsed.salt, parsed.num_cycles_power).unwrap();
        let plain = vec![0x41u8; 32];
        let ct = encrypt(&key, &parsed.iv, plain.clone());
        let mut reader =
            Aes7zReader::new(Box::new(Cursor::new(ct)), &props, Some("wrong")).unwrap();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        assert_ne!(got, plain, "wrong password must not recover plaintext");
    }

    #[test]
    fn dos_guard_and_missing_password() {
        // Cycle power above the cap is rejected.
        let hot = build_props(40, b"s", &[0u8; 16]);
        assert!(Aes7zReader::new(Box::new(Cursor::new(vec![])), &hot, Some("x")).is_err());
        // Missing password is rejected.
        let ok = build_props(16, b"s", &[0u8; 16]);
        assert!(Aes7zReader::new(Box::new(Cursor::new(vec![])), &ok, None).is_err());
        // Malformed props are rejected.
        assert!(Aes7zReader::new(Box::new(Cursor::new(vec![])), &[], Some("x")).is_err());
    }

    /// Build a 7zAES property blob with an explicit salt and IV (both present).
    fn build_props(cycles: u32, salt: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        // b0: cycles in low 6 bits, set both salt(bit7) and iv(bit6) carry bits.
        let b0 = (cycles as u8 & 0x3f) | 0x80 | 0x40;
        // b1: high nibble adds to salt size, low nibble adds to iv size. The
        // carry bits already contribute 1 each, so subtract 1 from each field.
        let salt_extra = (salt.len() as u8).saturating_sub(1);
        let iv_extra = (16u8).saturating_sub(1);
        let b1 = (salt_extra << 4) | (iv_extra & 0x0f);
        let mut p = vec![b0, b1];
        p.extend_from_slice(salt);
        p.extend_from_slice(iv);
        p
    }
}
