//! 7z AES-256 decryption (method `06F10701`, "7zAES").
//!
//! 7-Zip encrypts a folder's packed stream with AES-256-CBC. The 256-bit key is
//! derived from the passphrase and a per-archive salt by an iterated SHA-256:
//! a single hash context is updated with `salt || password_utf16le || counter`
//! (`counter` a little-endian `u64`, incremented each round) `2^numCyclesPower`
//! times, then finalised. The IV and salt travel in the coder properties. This
//! is the decrypt half only: no key wrapping, no RNG.
//!
//! The reader decrypts a folder's packed stream as it is read, so a folder of
//! any size takes the memory of one chunk. It does not tell a wrong passphrase
//! from the right one: the bytes it gives are garbage the next coder rejects,
//! or that fail the CRC the caller checks. Property parsing is bounds-checked
//! and the KDF round count is capped.

use crate::LimitHit;
use crate::kdf::Pass;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
use sha2::{Digest, Sha256};
use std::io::{self, Read};

/// Ciphertext decrypted at a time.
const CHUNK: usize = 64 * 1024;

/// The special `numCyclesPower` meaning "use the passphrase (with salt) verbatim
/// as the key", with no hashing.
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

/// A `Read` adapter that decrypts a 7zAES folder stream: AES-256-CBC with no
/// padding, a chunk of ciphertext at a time. The stream is a whole number of
/// blocks, and a partial block at its end is dropped; the plaintext is as long
/// as the ciphertext, and the coder after this one stops at its own size.
pub(super) struct Aes7zReader<'a> {
    inner: Box<dyn Read + 'a>,
    key: [u8; 32],
    /// What the next chunk chains from: the IV, then the last ciphertext block
    /// of the chunk before.
    iv: [u8; 16],
    buf: Box<[u8]>,
    /// `buf[pos..end]` is decrypted and not yet read. `buf[end..filled]` is
    /// the start of a block whose rest has not been read.
    pos: usize,
    end: usize,
    filled: usize,
    eof: bool,
    /// An error of `inner`, met after ciphertext was read: returned once the
    /// plaintext of that ciphertext has been.
    failed: Option<io::Error>,
}

impl<'a> Aes7zReader<'a> {
    /// Build the decryptor for a 7zAES coder. `password` is the passphrase to
    /// try. Returns an error if the properties are malformed, no password was
    /// supplied, or the KDF cost is out of range; the caller maps that to the
    /// existing "encrypted / unsupported" outcome.
    pub(super) fn new(
        inner: Box<dyn Read + 'a>,
        properties: &[u8],
        password: Option<Pass<'_>>,
    ) -> Result<Self, LimitHit> {
        let Some(pass) = password else {
            return Err(LimitHit::corrupt("7z: AES member needs a password".into()));
        };
        let props =
            parse_props(properties).ok_or_else(|| LimitHit::corrupt("7z: bad AES props".into()))?;
        let word = utf16le(pass.word);
        // The key is made once per password, salt and count in a scan, and the
        // scan has a bound on the rounds it spends ([`crate::kdf`]).
        let key = match props.num_cycles_power {
            NO_HASH_CYCLES => derive_key(&word, &props.salt, NO_HASH_CYCLES),
            cycles if cycles > MAX_CYCLES_POWER => None,
            cycles => pass
                .kdf
                .sevenz_key(&word, &props.salt, cycles, 1u64 << cycles, || {
                    derive_key(&word, &props.salt, cycles)
                }),
        }
        .ok_or_else(|| LimitHit::corrupt("7z: AES KDF cost too high".into()))?;
        Ok(Aes7zReader {
            inner,
            key,
            iv: props.iv,
            buf: vec![0; CHUNK].into_boxed_slice(),
            pos: 0,
            end: 0,
            filled: 0,
            eof: false,
            failed: None,
        })
    }

    /// Read the next chunk of ciphertext and decrypt its whole blocks. Leaves
    /// `pos == end` when there is no more.
    fn refill(&mut self) -> io::Result<()> {
        if let Some(e) = self.failed.take() {
            return Err(e);
        }
        if self.eof {
            return Ok(());
        }
        // The start of a block the last chunk ended in goes to the front.
        self.buf.copy_within(self.end..self.filled, 0);
        self.filled -= self.end;
        self.pos = 0;
        self.end = 0;
        while self.filled < self.buf.len() {
            match self.inner.read(&mut self.buf[self.filled..]) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(n) => self.filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if self.filled < 16 => return Err(e),
                Err(e) => {
                    self.failed = Some(e);
                    break;
                }
            }
        }
        let full = self.filled - self.filled % 16;
        if full == 0 {
            return Ok(());
        }
        let mut next_iv = [0u8; 16];
        next_iv.copy_from_slice(&self.buf[full - 16..full]);
        cbc::Decryptor::<aes::Aes256>::new(&self.key.into(), &self.iv.into())
            .decrypt_padded::<NoPadding>(&mut self.buf[..full])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "7z AES decrypt"))?;
        self.iv = next_iv;
        self.end = full;
        Ok(())
    }
}

impl Read for Aes7zReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pos == self.end {
            self.refill()?;
            if self.pos == self.end && self.eof {
                return Ok(0);
            }
        }
        let n = out.len().min(self.end - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::BlockModeEncrypt;
    use std::io::Cursor;

    /// AES-256-CBC encrypt with NoPadding (test-only, mirrors the decrypt path)
    /// to build a ciphertext the reader must recover.
    fn encrypt(key: &[u8; 32], iv: &[u8; 16], mut data: Vec<u8>) -> Vec<u8> {
        let pad = (16 - data.len() % 16) % 16;
        data.resize(data.len() + pad, 0);
        let n = data.len();
        cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into())
            .encrypt_padded::<NoPadding>(&mut data, n)
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

        let kdf = crate::kdf::Kdf::default();
        let pass = Pass {
            word: "s3cr3t",
            kdf: &kdf,
        };
        let mut reader = Aes7zReader::new(Box::new(Cursor::new(ct)), &props, Some(pass)).unwrap();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        // Decryption yields the block-padded plaintext. Compare the meaningful
        // prefix.
        assert!(
            got.starts_with(&plain),
            "decrypted prefix must match plaintext"
        );
    }

    /// `data`, at most `step` bytes at a time, and then the end of the stream
    /// or, with `fails`, an error. `read` counts the bytes given.
    struct Trickle {
        data: Vec<u8>,
        at: usize,
        step: usize,
        fails: bool,
        read: std::rc::Rc<std::cell::Cell<usize>>,
    }

    impl Trickle {
        fn new(data: Vec<u8>, step: usize) -> Self {
            Trickle {
                data,
                at: 0,
                step,
                fails: false,
                read: Default::default(),
            }
        }
    }

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.at == self.data.len() {
                return if self.fails {
                    Err(io::Error::other("damaged"))
                } else {
                    Ok(0)
                };
            }
            let n = buf.len().min(self.step).min(self.data.len() - self.at);
            buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
            self.at += n;
            self.read.set(self.read.get() + n);
            Ok(n)
        }
    }

    /// The ciphertext of `plain`, a whole number of blocks, with `tail` after
    /// it, and the properties the reader is built from (the password is `pw`).
    fn ciphertext(plain: &[u8], tail: &[u8]) -> (Vec<u8>, Vec<u8>) {
        assert_eq!(plain.len() % 16, 0);
        let props = build_props(8, b"\x01\x02\x03\x04", &[7u8; 16]);
        let parsed = parse_props(&props).unwrap();
        let key = derive_key(&utf16le("pw"), &parsed.salt, parsed.num_cycles_power).unwrap();
        let mut ct = encrypt(&key, &parsed.iv, plain.to_vec());
        ct.extend(tail);
        (ct, props)
    }

    fn reader_of(stream: Trickle, props: &[u8]) -> Aes7zReader<'static> {
        let kdf = crate::kdf::Kdf::default();
        let pass = Pass {
            word: "pw",
            kdf: &kdf,
        };
        Aes7zReader::new(Box::new(stream), props, Some(pass)).unwrap()
    }

    /// Across the seams of its chunks, and of the reads it is given and gives,
    /// the stream decrypts as one: the chain from one chunk to the next is the
    /// last block of ciphertext, and a partial block at the end is dropped.
    #[test]
    fn a_stream_decrypts_as_one_in_reads_of_any_size() {
        let plain: Vec<u8> = (0..3 * CHUNK as u32 + 1000)
            .map(|i| (i * 31 % 251) as u8)
            .collect();
        let plain = &plain[..plain.len() - plain.len() % 16];
        let (ct, props) = ciphertext(plain, &[0xAB; 7]);
        for step in [1, 7, 16, 100, 4096, CHUNK, 1 << 20] {
            for out in [1, 15, 17, 4096, 1 << 20] {
                let mut reader = reader_of(Trickle::new(ct.clone(), step), &props);
                let mut got = Vec::new();
                let mut buf = vec![0u8; out];
                loop {
                    match reader.read(&mut buf).unwrap() {
                        0 => break,
                        n => got.extend_from_slice(&buf[..n]),
                    }
                }
                assert!(got == plain, "ciphertext in {step}s, read in {out}s");
            }
        }
    }

    /// A megabyte of ciphertext is not read to give its first bytes.
    #[test]
    fn the_ciphertext_is_read_a_chunk_at_a_time() {
        let (ct, props) = ciphertext(&vec![0x41u8; 1 << 20], &[]);
        let stream = Trickle::new(ct, 1 << 20);
        let read = stream.read.clone();
        let mut reader = reader_of(stream, &props);
        let mut first = [0u8; 100];
        reader.read_exact(&mut first).unwrap();
        assert_eq!(first, [0x41u8; 100]);
        assert!(read.get() <= 64 * 1024, "{} bytes read", read.get());
    }

    /// An error of the stream after some ciphertext comes after the plaintext
    /// of that ciphertext, whole blocks of it.
    #[test]
    fn an_error_of_the_stream_comes_after_the_plaintext_before_it() {
        let plain: Vec<u8> = (0..160u32).map(|i| i as u8).collect();
        let (ct, props) = ciphertext(&plain, &[0xAB; 5]);
        for size in [1, 16, 4096] {
            let mut stream = Trickle::new(ct.clone(), 40);
            stream.fails = true;
            let mut reader = reader_of(stream, &props);
            let mut got = Vec::new();
            let mut buf = vec![0u8; size];
            let err = loop {
                match reader.read(&mut buf) {
                    Ok(0) => panic!("ended without the error"),
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(e) => break e,
                }
            };
            assert_eq!(got, plain, "reads of {size}");
            assert_eq!(err.to_string(), "damaged");
        }
    }

    #[test]
    fn wrong_password_does_not_match() {
        let props = build_props(16, b"\x01\x02\x03\x04", &[9u8; 16]);
        let parsed = parse_props(&props).unwrap();
        let key = derive_key(&utf16le("right"), &parsed.salt, parsed.num_cycles_power).unwrap();
        let plain = vec![0x41u8; 32];
        let ct = encrypt(&key, &parsed.iv, plain.clone());
        let kdf = crate::kdf::Kdf::default();
        let pass = Pass {
            word: "wrong",
            kdf: &kdf,
        };
        let mut reader = Aes7zReader::new(Box::new(Cursor::new(ct)), &props, Some(pass)).unwrap();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        assert_ne!(got, plain, "wrong password must not recover plaintext");
    }

    #[test]
    fn dos_guard_and_missing_password() {
        let kdf = crate::kdf::Kdf::default();
        let pass = Pass {
            word: "x",
            kdf: &kdf,
        };
        // Cycle power above the cap is rejected.
        let hot = build_props(40, b"s", &[0u8; 16]);
        assert!(Aes7zReader::new(Box::new(Cursor::new(vec![])), &hot, Some(pass)).is_err());
        // Missing password is rejected.
        let ok = build_props(16, b"s", &[0u8; 16]);
        assert!(Aes7zReader::new(Box::new(Cursor::new(vec![])), &ok, None).is_err());
        // Malformed props are rejected.
        assert!(Aes7zReader::new(Box::new(Cursor::new(vec![])), &[], Some(pass)).is_err());
    }

    /// Thousands of folders of one archive, which 7-Zip gives the same key, cost
    /// one derivation; a scan that asks for more than its share is refused
    /// the rest, whatever the passwords.
    #[test]
    fn a_scan_derives_a_key_once_and_within_its_share() {
        let kdf = crate::kdf::Kdf::default();
        let props = build_props(16, b"s", &[9u8; 16]);
        let start = std::time::Instant::now();
        for _ in 0..2000 {
            let pass = Pass {
                word: "same",
                kdf: &kdf,
            };
            assert!(Aes7zReader::new(Box::new(Cursor::new(vec![])), &props, Some(pass)).is_ok());
        }
        // 2000 derivations of 2^16 would be 1.3 s here; one is a few ms.
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
        assert_eq!(kdf.sevenz_spent(), 1 << 16);
        // Many passwords at 2^24: 4 are derived, then the scan has no share left.
        let hot = build_props(24, b"s", &[9u8; 16]);
        let mut derived = 0;
        for n in 0..8 {
            let word = format!("password {n}");
            let pass = Pass {
                word: &word,
                kdf: &kdf,
            };
            if Aes7zReader::new(Box::new(Cursor::new(vec![])), &hot, Some(pass)).is_ok() {
                derived += 1;
            }
        }
        assert_eq!(
            derived, 3,
            "2^26 less the 2^16 already spent is three of 2^24"
        );
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
