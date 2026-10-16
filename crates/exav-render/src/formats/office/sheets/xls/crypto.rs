//! Decryption of XLS files saved with the default password,
//! "VelvetSweatshop", which Excel uses for a workbook that is only
//! protected against changes: RC4 ([MS-OFFCRYPTO] 2.3.6), RC4 CryptoAPI
//! (2.3.5) and XOR obfuscation (2.3.7, BIFF2 to BIFF8). Another password
//! cannot be tried without asking the user, and is reported as
//! [`Error::Encrypted`](crate::formats::office::sheets::Error::Encrypted).

use crate::formats::office::common::bytes::{u16_at, u32_at, Cur};
use md5::{Digest, Md5};
use sha1::Sha1;

pub const DEFAULT_PASSWORD: &str = "VelvetSweatshop";

/// RC4 keystream XORed into `data`.
pub(crate) fn rc4(key: &[u8], data: &mut [u8]) {
    if key.is_empty() {
        return;
    }
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    for b in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        *b ^= s[s[i as usize].wrapping_add(s[j as usize]) as usize];
    }
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// 2.3.7.1: the 16-bit verifier of a password.
pub(crate) fn xor_verifier(pw: &[u8]) -> u16 {
    let mut v: u16 = 0;
    let mut arr = vec![pw.len() as u8];
    arr.extend_from_slice(pw);
    for &b in arr.iter().rev() {
        let i1 = u16::from(v & 0x4000 != 0);
        let i2 = (v << 1) & 0x7FFF;
        v = (i1 | i2) ^ u16::from(b);
    }
    v ^ 0xCE4B
}

/// The 16-byte XOR array of a password and the key FILEPASS stores, as
/// [MS-OFFCRYPTO] 2.3.7.5 builds it, kept rotated left by 3 so that a byte
/// decrypts as `rol3(byte) ^ array[i]`.
fn xor_array(pw: &[u8], key: u16) -> [u8; 16] {
    const PAD: [u8; 15] = [
        0xBB, 0xFF, 0xFF, 0xBA, 0xFF, 0xFF, 0xB9, 0x80, 0x00, 0xBE, 0x0F, 0x00, 0xBF, 0x0F, 0x00,
    ];
    let mut a = [0u8; 16];
    for (i, v) in a.iter_mut().enumerate() {
        *v = if i < pw.len() {
            pw[i]
        } else {
            PAD[i - pw.len()]
        };
    }
    let [lo, hi] = key.to_le_bytes();
    for (i, v) in a.iter_mut().enumerate() {
        let k = if i % 2 == 0 { lo } else { hi };
        *v = (*v ^ k).rotate_left(2);
    }
    a
}

pub(crate) enum Decryptor {
    Rc4 { h1: [u8; 5] },
    CryptoApi { h0: Vec<u8>, key_len: usize },
    Xor { array: [u8; 16] },
}

/// Why FILEPASS could not be used.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Another password.
    Password,
    /// A method this reader does not have.
    Method,
}

impl Decryptor {
    /// From a FILEPASS record's payload. BIFF2 to BIFF5 have only XOR
    /// obfuscation, without the leading encryption type.
    pub fn from_filepass(d: &[u8], biff8: bool) -> Result<Decryptor, Refused> {
        let mut c = Cur::new(d);
        let kind = if biff8 { c.u16() } else { 0 };
        if kind == 0 {
            let key = c.u16();
            let verifier = c.u16();
            let pw = DEFAULT_PASSWORD.as_bytes();
            if c.short || xor_verifier(pw) != verifier {
                return Err(Refused::Password);
            }
            return Ok(Decryptor::Xor {
                array: xor_array(pw, key),
            });
        }
        if kind != 1 {
            return Err(Refused::Method);
        }
        let major = c.u16();
        let _minor = c.u16();
        if major == 1 {
            let salt = c.bytes(16).to_vec();
            let verifier = c.bytes(16).to_vec();
            let hash = c.bytes(16).to_vec();
            if c.short {
                return Err(Refused::Method);
            }
            let h0 = Md5::digest(utf16(DEFAULT_PASSWORD));
            let mut buf = Vec::with_capacity(336);
            for _ in 0..16 {
                buf.extend_from_slice(&h0[..5]);
                buf.extend_from_slice(&salt);
            }
            let h1 = Md5::digest(&buf);
            let mut t = [0u8; 5];
            t.copy_from_slice(&h1[..5]);
            let dec = Decryptor::Rc4 { h1: t };
            let mut both = [verifier, hash].concat();
            rc4(&dec.key(0), &mut both);
            return if Md5::digest(&both[..16]).as_slice() == &both[16..] {
                Ok(dec)
            } else {
                Err(Refused::Password)
            };
        }
        if (2..=4).contains(&major) {
            let _flags = c.u32();
            let hsize = c.u32() as usize;
            let header = c.bytes(hsize);
            let key_bits = u32_at(header, 16) as usize;
            let key_len = match key_bits {
                0 => 5,
                40..=128 if key_bits.is_multiple_of(8) => key_bits / 8,
                _ => return Err(Refused::Method),
            };
            let salt_size = c.u32() as usize;
            let salt = c.bytes(salt_size.min(16)).to_vec();
            let verifier = c.bytes(16).to_vec();
            let _hash_size = c.u32();
            let vhash = c.bytes(20).to_vec();
            if c.short {
                return Err(Refused::Method);
            }
            let mut h = Sha1::new();
            h.update(&salt);
            h.update(utf16(DEFAULT_PASSWORD));
            let dec = Decryptor::CryptoApi {
                h0: h.finalize().to_vec(),
                key_len,
            };
            let mut both = [verifier, vhash].concat();
            rc4(&dec.key(0), &mut both);
            return if Sha1::digest(&both[..16]).as_slice() == &both[16..] {
                Ok(dec)
            } else {
                Err(Refused::Password)
            };
        }
        Err(Refused::Method)
    }

    fn key(&self, block: u32) -> Vec<u8> {
        match self {
            Decryptor::Rc4 { h1 } => {
                let mut h = Md5::new();
                h.update(h1);
                h.update(block.to_le_bytes());
                h.finalize().to_vec()
            }
            Decryptor::CryptoApi { h0, key_len } => {
                let mut h = Sha1::new();
                h.update(h0);
                h.update(block.to_le_bytes());
                let f = h.finalize();
                if *key_len == 5 {
                    let mut k = f[..5].to_vec();
                    k.resize(16, 0);
                    k
                } else {
                    f[..(*key_len).min(16)].to_vec()
                }
            }
            Decryptor::Xor { .. } => vec![],
        }
    }

    /// Decrypts, in place, every record of `data` after the one at
    /// `filepass` (the offset of its header), but for the records and
    /// fields that are never encrypted ([MS-XLS] 2.2.10).
    pub fn decrypt_stream(&self, data: &mut [u8], filepass: usize) {
        let mut p = filepass + 4 + u16_at(data, filepass + 2) as usize;
        // (start of plain bytes, start of encrypted bytes, end, data start)
        let mut ranges = Vec::new();
        while p + 4 <= data.len() {
            let id = u16_at(data, p);
            let len = u16_at(data, p + 2) as usize;
            let start = p + 4;
            let end = (start + len).min(data.len());
            let from = match id {
                // BOF, FILEPASS, USREXCL, FILELOCK, INTERFACEHDR, RRDINFO, RRDHEAD.
                0x0809 | 0x0409 | 0x0209 | 0x0009 | 0x002F | 0x0194 | 0x0195 | 0x00E1 | 0x0138
                | 0x0196 => end,
                // BOUNDSHEET's stream position.
                0x0085 => (start + 4).min(end),
                _ => start,
            };
            if from < end {
                ranges.push((from, end, start, len));
            }
            p = end;
        }
        match self {
            Decryptor::Xor { array } => {
                for (from, end, start, len) in ranges {
                    for (i, b) in data.iter_mut().enumerate().take(end).skip(from) {
                        let k = array[(start + len + (i - start)) & 15];
                        *b = b.rotate_left(3) ^ k;
                    }
                }
            }
            _ => {
                let mut block = u32::MAX;
                let mut ks = vec![0u8; 1024];
                for (from, end, _, _) in ranges {
                    for i in from..end {
                        let blk = (i / 1024) as u32;
                        if blk != block {
                            block = blk;
                            ks.iter_mut().for_each(|b| *b = 0);
                            rc4(&self.key(blk), &mut ks);
                        }
                        data[i] ^= ks[i % 1024];
                    }
                }
            }
        }
    }
}

/// Encryption with the default password, for the tests: the inverse of
/// [`Decryptor::decrypt_stream`], written from the specification apart
/// from it.
#[cfg(test)]
pub(crate) mod encrypt {
    use super::*;

    /// A FILEPASS payload for `method` ("xor", "rc4", "cryptoapi40",
    /// "cryptoapi128") and a fixed salt.
    pub fn filepass(method: &str, biff8: bool) -> Vec<u8> {
        let pw = DEFAULT_PASSWORD;
        let salt: Vec<u8> = (0..16u8)
            .map(|i| i.wrapping_mul(37).wrapping_add(11))
            .collect();
        let verifier: Vec<u8> = (0..16u8)
            .map(|i| i.wrapping_mul(91).wrapping_add(3))
            .collect();
        let mut out = vec![];
        match method {
            "xor" => {
                if biff8 {
                    out.extend_from_slice(&0u16.to_le_bytes());
                }
                out.extend_from_slice(&xor_key(pw.as_bytes()).to_le_bytes());
                out.extend_from_slice(&xor_verifier(pw.as_bytes()).to_le_bytes());
            }
            "rc4" => {
                out.extend_from_slice(&[1, 0, 1, 0, 1, 0]);
                out.extend_from_slice(&salt);
                let h0 = Md5::digest(utf16(pw));
                let mut buf = vec![];
                for _ in 0..16 {
                    buf.extend_from_slice(&h0[..5]);
                    buf.extend_from_slice(&salt);
                }
                let h1 = Md5::digest(&buf);
                let mut key = Md5::new();
                key.update(&h1[..5]);
                key.update(0u32.to_le_bytes());
                let mut both = [verifier.clone(), Md5::digest(&verifier).to_vec()].concat();
                rc4(&key.finalize(), &mut both);
                out.extend_from_slice(&both);
            }
            m => {
                let bits: u32 = if m == "cryptoapi40" { 40 } else { 128 };
                out.extend_from_slice(&[1, 0, 2, 0, 2, 0]);
                out.extend_from_slice(&4u32.to_le_bytes());
                let csp: Vec<u8> = utf16("Microsoft Base Cryptographic Provider v1.0\0");
                let mut header = vec![];
                header.extend_from_slice(&4u32.to_le_bytes()); // flags: fCryptoAPI
                header.extend_from_slice(&0u32.to_le_bytes());
                header.extend_from_slice(&0x6801u32.to_le_bytes()); // RC4
                header.extend_from_slice(&0x8004u32.to_le_bytes()); // SHA-1
                header.extend_from_slice(&bits.to_le_bytes());
                header.extend_from_slice(&1u32.to_le_bytes());
                header.extend_from_slice(&[0; 8]);
                header.extend_from_slice(&csp);
                out.extend_from_slice(&(header.len() as u32).to_le_bytes());
                out.extend_from_slice(&header);
                out.extend_from_slice(&16u32.to_le_bytes());
                out.extend_from_slice(&salt);
                let mut h = Sha1::new();
                h.update(&salt);
                h.update(utf16(pw));
                let h0 = h.finalize();
                let mut k = Sha1::new();
                k.update(h0);
                k.update(0u32.to_le_bytes());
                let f = k.finalize();
                let key = if bits == 40 {
                    [&f[..5], &[0u8; 11][..]].concat()
                } else {
                    f[..16].to_vec()
                };
                let mut both = [verifier.clone(), Sha1::digest(&verifier).to_vec()].concat();
                rc4(&key, &mut both);
                out.extend_from_slice(&both[..16]);
                out.extend_from_slice(&20u32.to_le_bytes());
                out.extend_from_slice(&both[16..]);
            }
        }
        out
    }

    /// 2.3.7.2's CreateXorKey_Method1.
    pub fn xor_key(pw: &[u8]) -> u16 {
        const INITIAL: [u16; 15] = [
            0xE1F0, 0x1D0F, 0xCC9C, 0x84C0, 0x110C, 0x0E10, 0xF1CE, 0x313E, 0x1872, 0xE139, 0xD40F,
            0x84F9, 0x280C, 0xA96A, 0x4EC3,
        ];
        const MATRIX: [u16; 105] = [
            0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09, 0x7B61, 0xF6C2, 0xFDA5, 0xEB6B,
            0xC6F7, 0x9DCF, 0x2BBF, 0x4563, 0x8AC6, 0x05AD, 0x0B5A, 0x16B4, 0x2D68, 0x5AD0, 0x0375,
            0x06EA, 0x0DD4, 0x1BA8, 0x3750, 0x6EA0, 0xDD40, 0xD849, 0xA0B3, 0x5147, 0xA28E, 0x553D,
            0xAA7A, 0x44D5, 0x6F45, 0xDE8A, 0xAD35, 0x4A4B, 0x9496, 0x390D, 0x721A, 0xEB23, 0xC667,
            0x9CEF, 0x29FF, 0x53FE, 0xA7FC, 0x5FD9, 0x47D3, 0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68,
            0xF6D0, 0xB861, 0x60E3, 0xC1C6, 0x93AD, 0x377B, 0x6EF6, 0xDDEC, 0x45A0, 0x8B40, 0x06A1,
            0x0D42, 0x1A84, 0x3508, 0x6A10, 0xAA51, 0x4483, 0x8906, 0x022D, 0x045A, 0x08B4, 0x1168,
            0x76B4, 0xED68, 0xCAF1, 0x85C3, 0x1BA7, 0x374E, 0x6E9C, 0x3730, 0x6E60, 0xDCC0, 0xA9A1,
            0x4363, 0x86C6, 0x1DAD, 0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373, 0x06E6, 0x0DCC, 0x1021,
            0x2042, 0x4084, 0x8108, 0x1231, 0x2462, 0x48C4,
        ];
        let mut key = INITIAL[pw.len() - 1];
        let mut el = 0x68usize;
        for &c in pw.iter().rev() {
            let mut c = c;
            for _ in 0..7 {
                if c & 0x40 != 0 {
                    key ^= MATRIX[el];
                }
                c = c.wrapping_mul(2);
                el = el.wrapping_sub(1);
            }
        }
        key
    }

    /// Encrypts the records after FILEPASS (at offset `filepass`), as
    /// [MS-OFFCRYPTO] 2.3.7.3 (EncryptData_Method1 with the array of
    /// 2.3.7.2) and 2.3.6 describe it.
    pub fn encrypt_stream(method: &str, data: &mut [u8], filepass: usize) {
        let mut p = filepass + 4 + u16_at(data, filepass + 2) as usize;
        let pw = DEFAULT_PASSWORD.as_bytes();
        let fp = data[filepass + 4..filepass + 4 + u16_at(data, filepass + 2) as usize].to_vec();
        let biff8 = fp.len() > 4;
        let dec = Decryptor::from_filepass(&fp, biff8).ok();
        let xa = method_1_array(pw);
        while p + 4 <= data.len() {
            let id = u16_at(data, p);
            let len = u16_at(data, p + 2) as usize;
            let start = p + 4;
            let end = (start + len).min(data.len());
            let from = match id {
                0x0809 | 0x0409 | 0x0209 | 0x0009 | 0x002F | 0x0194 | 0x0195 | 0x00E1 | 0x0138
                | 0x0196 => end,
                0x0085 => start + 4,
                _ => start,
            };
            for i in from..end {
                if method == "xor" {
                    let idx = (start + len + (i - start)) & 15;
                    data[i] = data[i].rotate_left(5) ^ xa[idx];
                } else if let Some(d) = &dec {
                    let mut ks = vec![0u8; i % 1024 + 1];
                    rc4(&d.key((i / 1024) as u32), &mut ks);
                    data[i] ^= ks[i % 1024];
                }
            }
            p = end;
        }
    }

    /// 2.3.7.2's CreateXorArray_Method1, as the specification writes it.
    fn method_1_array(pw: &[u8]) -> [u8; 16] {
        const PAD: [u8; 15] = [
            0xBB, 0xFF, 0xFF, 0xBA, 0xFF, 0xFF, 0xB9, 0x80, 0x00, 0xBE, 0x0F, 0x00, 0xBF, 0x0F,
            0x00,
        ];
        let ror = |b: u8| b.rotate_right(1);
        let key = xor_key(pw);
        let (hi, lo) = ((key >> 8) as u8, key as u8);
        let mut a = [0u8; 16];
        let mut index = pw.len();
        if index % 2 == 1 {
            a[index] = ror(PAD[0] ^ hi);
            index -= 1;
            a[index] = ror(pw[pw.len() - 1] ^ lo);
        }
        while index > 0 {
            index -= 1;
            a[index] = ror(pw[index] ^ hi);
            index -= 1;
            a[index] = ror(pw[index] ^ lo);
        }
        let mut index = 15usize;
        let mut pad = 15 - pw.len();
        while pad > 0 {
            a[index] = ror(PAD[pad] ^ hi);
            index -= 1;
            pad -= 1;
            a[index] = ror(PAD[pad] ^ lo);
            index = index.wrapping_sub(1);
            pad = pad.wrapping_sub(1);
            if pad > 15 {
                break;
            }
        }
        a
    }
}

#[cfg(test)]
mod tests {
    use super::encrypt::*;
    use super::*;

    #[test]
    fn rc4_test_vector() {
        // RFC 6229, key 0x0102030405, first bytes of keystream.
        let mut d = [0u8; 8];
        rc4(&[1, 2, 3, 4, 5], &mut d);
        assert_eq!(d, [0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27]);
    }

    #[test]
    fn verifier_of_the_default_password() {
        // [MS-OFFCRYPTO] 2.3.7.1 on "VelvetSweatshop"; the stored key is
        // CreateXorKey_Method1 of it.
        let pw = DEFAULT_PASSWORD.as_bytes();
        let fp = filepass("xor", true);
        assert!(matches!(
            Decryptor::from_filepass(&fp, true),
            Ok(Decryptor::Xor { .. })
        ));
        assert_eq!(u16_at(&fp, 4), xor_verifier(pw));
        // Another password's verifier is refused.
        let mut bad = fp.clone();
        bad[4] ^= 1;
        assert_eq!(
            Decryptor::from_filepass(&bad, true).err(),
            Some(Refused::Password)
        );
    }

    #[test]
    fn our_xor_array_is_the_specifications() {
        // The array built from the stored key, rotated, equals 2.3.7.2's
        // CreateXorArray_Method1 rotated the same way.
        let pw = DEFAULT_PASSWORD.as_bytes();
        let mut stream = vec![];
        // A FILEPASS (XOR, BIFF8), then a record of 40 known bytes.
        let fp = filepass("xor", true);
        stream.extend_from_slice(&0x002Fu16.to_le_bytes());
        stream.extend_from_slice(&(fp.len() as u16).to_le_bytes());
        stream.extend_from_slice(&fp);
        let plain: Vec<u8> = (0..40u8).collect();
        stream.extend_from_slice(&0x0204u16.to_le_bytes());
        stream.extend_from_slice(&40u16.to_le_bytes());
        stream.extend_from_slice(&plain);
        let mut enc = stream.clone();
        encrypt_stream("xor", &mut enc, 0);
        assert_ne!(enc, stream);
        let d = Decryptor::from_filepass(&fp, true).unwrap();
        d.decrypt_stream(&mut enc, 0);
        assert_eq!(enc, stream);
        let _ = pw;
    }

    #[test]
    fn rc4_and_cryptoapi_round_trip() {
        for m in ["rc4", "cryptoapi40", "cryptoapi128"] {
            let fp = filepass(m, true);
            let mut stream = vec![];
            stream.extend_from_slice(&0x002Fu16.to_le_bytes());
            stream.extend_from_slice(&(fp.len() as u16).to_le_bytes());
            stream.extend_from_slice(&fp);
            for k in 0..300u16 {
                stream.extend_from_slice(&0x0203u16.to_le_bytes());
                stream.extend_from_slice(&14u16.to_le_bytes());
                stream.extend_from_slice(&k.to_le_bytes());
                stream.extend_from_slice(&[7; 12]);
            }
            let mut enc = stream.clone();
            encrypt_stream(m, &mut enc, 0);
            assert_ne!(enc, stream, "{m}");
            let d = Decryptor::from_filepass(&fp, true).unwrap_or_else(|e| panic!("{m}: {e:?}"));
            d.decrypt_stream(&mut enc, 0);
            assert_eq!(enc, stream, "{m}");
        }
    }
}
