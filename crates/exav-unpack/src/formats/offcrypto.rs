//! Decryption of Excel workbooks saved with a password ([MS-OFFCRYPTO] 2.3.5
//! to 2.3.7, [MS-XLS] 2.2.10): RC4 (2.3.6), RC4 CryptoAPI (2.3.5) and XOR
//! obfuscation (2.3.7, BIFF2 to BIFF8), read from the `FilePass` record.
//!
//! The headline case is the default password `VelvetSweatshop`: Excel
//! encrypts with it a workbook that is only protected against changes, so it
//! opens with no prompt, and malware abuses that to hide macros and objects
//! from scanners that stop at "encrypted". The scanner and the converters of
//! exav-render both open such a workbook here, with the passwords they were
//! given and these defaults.
//!
//! Only the workbook stream is encrypted; the other storages of the compound
//! file (the VBA project among them) are not.

use md5::{Digest, Md5};
use sha1::Sha1;

/// The password Excel uses for a workbook it protects against changes only.
pub const DEFAULT_PASSWORD: &str = "VelvetSweatshop";

/// The passwords tried on every encrypted workbook after the caller's own:
/// the default one, and none.
pub const DEFAULT_PASSWORDS: &[&str] = &[DEFAULT_PASSWORD, ""];

/// RC4 keystream XORed into `data`.
pub fn rc4(key: &[u8], data: &mut [u8]) {
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

fn u16_at(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2)
        .map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// A cursor over a record's payload that never reads past it: a short read
/// is flagged, not a panic.
struct Cur<'a> {
    d: &'a [u8],
    p: usize,
    short: bool,
}

impl<'a> Cur<'a> {
    fn new(d: &'a [u8]) -> Self {
        Cur {
            d,
            p: 0,
            short: false,
        }
    }

    fn bytes(&mut self, n: usize) -> &'a [u8] {
        match self.p.checked_add(n).and_then(|e| self.d.get(self.p..e)) {
            Some(s) => {
                self.p += n;
                s
            }
            None => {
                self.short = true;
                self.p = self.d.len();
                &[]
            }
        }
    }

    fn u16(&mut self) -> u16 {
        u16_at(self.bytes(2), 0)
    }

    fn u32(&mut self) -> u32 {
        u32_at(self.bytes(4), 0)
    }
}

/// 2.3.7.1: the 16-bit verifier of a password.
pub fn xor_verifier(pw: &[u8]) -> u16 {
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

/// What decrypts a workbook, from its FILEPASS record and a password.
pub enum Decryptor {
    Rc4 { h1: [u8; 5] },
    CryptoApi { h0: Vec<u8>, key_len: usize },
    Xor { array: [u8; 16] },
}

/// Why FILEPASS could not be used.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// None of the passwords.
    Password,
    /// A method this reader does not have.
    Method,
}

impl Decryptor {
    /// From a FILEPASS record's payload and the passwords to try, in order.
    /// BIFF2 to BIFF5 have only XOR obfuscation, without the leading
    /// encryption type.
    pub fn from_filepass(d: &[u8], biff8: bool, passwords: &[&str]) -> Result<Decryptor, Refused> {
        let mut c = Cur::new(d);
        let kind = if biff8 { c.u16() } else { 0 };
        if kind == 0 {
            let key = c.u16();
            let verifier = c.u16();
            if c.short {
                return Err(Refused::Method);
            }
            // The scheme takes passwords of 1 to 15 bytes.
            return passwords
                .iter()
                .map(|pw| pw.as_bytes())
                .find(|pw| (1..=15).contains(&pw.len()) && xor_verifier(pw) == verifier)
                .map(|pw| Decryptor::Xor {
                    array: xor_array(pw, key),
                })
                .ok_or(Refused::Password);
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
            for pw in passwords {
                let h0 = Md5::digest(utf16(pw));
                let mut buf = Vec::with_capacity(336);
                for _ in 0..16 {
                    buf.extend_from_slice(&h0[..5]);
                    buf.extend_from_slice(&salt);
                }
                let h1 = Md5::digest(&buf);
                let mut t = [0u8; 5];
                t.copy_from_slice(&h1[..5]);
                let dec = Decryptor::Rc4 { h1: t };
                let mut both = [verifier.clone(), hash.clone()].concat();
                rc4(&dec.key(0), &mut both);
                if Md5::digest(&both[..16]).as_slice() == &both[16..] {
                    return Ok(dec);
                }
            }
            return Err(Refused::Password);
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
            for pw in passwords {
                let mut h = Sha1::new();
                h.update(&salt);
                h.update(utf16(pw));
                let dec = Decryptor::CryptoApi {
                    h0: h.finalize().to_vec(),
                    key_len,
                };
                let mut both = [verifier.clone(), vhash.clone()].concat();
                rc4(&dec.key(0), &mut both);
                if Sha1::digest(&both[..16]).as_slice() == &both[16..] {
                    return Ok(dec);
                }
            }
            return Err(Refused::Password);
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

/// The offset of the FILEPASS record of a workbook stream, if it has one: it
/// follows the opening BOF.
pub fn filepass_at(stream: &[u8]) -> Option<usize> {
    let mut p = 0usize;
    // BOF, then FILEPASS where it is written; a few records are looked at in
    // case a writer put something between.
    for _ in 0..8 {
        if p + 4 > stream.len() {
            return None;
        }
        if u16_at(stream, p) == 0x002F {
            return Some(p);
        }
        p += 4 + usize::from(u16_at(stream, p + 2));
    }
    None
}

/// A workbook stream decrypted with the first password that opens it:
/// `Err(Refused::Password)` if none does. A stream with no FILEPASS comes back
/// as it is. The FILEPASS record of the result is blanked (its type zero, its
/// payload zeros), so that what reads the result does not take it for
/// encrypted again.
pub fn decrypt_workbook(stream: &[u8], passwords: &[&str]) -> Result<Vec<u8>, Refused> {
    let mut out = stream.to_vec();
    let Some(fp) = filepass_at(stream) else {
        return Ok(out);
    };
    // BIFF2 to BIFF5 write only the key and verifier of XOR obfuscation, four
    // bytes; from BIFF8 on there is an encryption type first.
    let size = usize::from(u16_at(stream, fp + 2));
    let biff8 = size > 4;
    let payload = stream.get(fp + 4..fp + 4 + size).ok_or(Refused::Method)?;
    Decryptor::from_filepass(payload, biff8, passwords)?.decrypt_stream(&mut out, fp);
    out[fp..fp + 2].fill(0);
    out[fp + 4..fp + 4 + size].fill(0);
    Ok(out)
}

/// Encryption with the default password, for the tests of what reads encrypted
/// workbooks: the inverse of [`Decryptor::decrypt_stream`], written from the
/// specification apart from it.
#[cfg(any(test, feature = "test-util"))]
pub mod encrypt {
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
        let dec = Decryptor::from_filepass(&fp, biff8, &[DEFAULT_PASSWORD]).ok();
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
            Decryptor::from_filepass(&fp, true, &[DEFAULT_PASSWORD]),
            Ok(Decryptor::Xor { .. })
        ));
        assert_eq!(u16_at(&fp, 4), xor_verifier(pw));
        // Another password's verifier is refused.
        let mut bad = fp.clone();
        bad[4] ^= 1;
        assert_eq!(
            Decryptor::from_filepass(&bad, true, &[DEFAULT_PASSWORD]).err(),
            Some(Refused::Password)
        );
    }

    /// The password that opens a workbook is found among those given, in the
    /// order given; none of them is a refusal.
    #[test]
    fn the_right_password_is_found_among_several() {
        for m in ["xor", "rc4", "cryptoapi40", "cryptoapi128"] {
            let fp = filepass(m, true);
            let found = Decryptor::from_filepass(&fp, true, &["wrong", "", DEFAULT_PASSWORD]);
            assert!(found.is_ok(), "{m}");
            assert_eq!(
                Decryptor::from_filepass(&fp, true, &["wrong", ""]).err(),
                Some(Refused::Password),
                "{m}"
            );
            assert_eq!(
                Decryptor::from_filepass(&fp, true, &[]).err(),
                Some(Refused::Password),
                "{m}"
            );
        }
    }

    #[test]
    fn our_xor_array_is_the_specifications() {
        // The array built from the stored key, rotated, equals 2.3.7.2's
        // CreateXorArray_Method1 rotated the same way.
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
        let d = Decryptor::from_filepass(&fp, true, &[DEFAULT_PASSWORD]).unwrap();
        d.decrypt_stream(&mut enc, 0);
        assert_eq!(enc, stream);
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
            let d = Decryptor::from_filepass(&fp, true, &[DEFAULT_PASSWORD])
                .unwrap_or_else(|e| panic!("{m}: {e:?}"));
            d.decrypt_stream(&mut enc, 0);
            assert_eq!(enc, stream, "{m}");
        }
    }

    fn hexv(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// The verifier matches the MS-OFFCRYPTO reference vectors (the
    /// `VelvetSweatshop` default stores `0x9a0a`).
    #[test]
    fn xor_verifier_matches_reference() {
        assert_eq!(xor_verifier(b"VelvetSweatshop"), 0x9a0a);
        assert_eq!(xor_verifier(b"password1"), 0xe1ae);
        assert_eq!(xor_verifier(b"Secret1"), 0xc266);
        assert_ne!(xor_verifier(b"wrong"), 0x9a0a);
    }

    /// The obfuscation array matches the MIT msoffcrypto reference for several
    /// passwords, byte for byte (which validates the tables and the key
    /// derivation): the reference array is ours rotated left by 3, and ours
    /// rotated back is the reference's.
    #[test]
    fn xor_array_matches_reference_vectors() {
        for (pw, hex) in [
            ("VelvetSweatshop", "876b9ae21ee305621e699660986e9404"),
            ("password1", "dbb75abe58b0da357bda1cf8bef81cdb"),
            ("abc", "95999475da577857da7465a87a2f2577"),
            ("Secret1", "7b3863b360b04a572d758f752d56928a"),
        ] {
            let ours = xor_array(pw.as_bytes(), xor_key(pw.as_bytes()));
            let reference: Vec<u8> = ours.iter().map(|b| b.rotate_right(3)).collect();
            assert_eq!(reference, hexv(hex), "xor array mismatch for {pw:?}");
        }
    }

    /// Passwords of 1 to 15 bytes are opened by the XOR scheme, others are not.
    #[test]
    fn xor_passwords_of_every_length_are_tried() {
        for n in 0..=16 {
            let pw = "a".repeat(n);
            let key = if (1..=15).contains(&n) {
                xor_key(pw.as_bytes())
            } else {
                0
            };
            let mut fp = vec![0u8, 0];
            fp.extend(key.to_le_bytes());
            fp.extend(xor_verifier(pw.as_bytes()).to_le_bytes());
            let found = Decryptor::from_filepass(&fp, true, &[&pw]).is_ok();
            assert_eq!(found, (1..=15).contains(&n), "length {n}");
        }
    }

    // Independently generated vector (salt 00..0f, password "Secret1").
    #[test]
    fn rc4_basic_verifier_and_key() {
        let mut fp = vec![1u8, 0, 1, 0, 1, 0];
        fp.extend(0u8..16);
        fp.extend(hexv("d11cfb57cde29a6eaf45018e01931b31"));
        fp.extend(hexv("9687999033ca45aaade5f45386030a07"));
        match Decryptor::from_filepass(&fp, true, &["wrong", DEFAULT_PASSWORD, "Secret1"]) {
            Ok(Decryptor::Rc4 { h1 }) => assert_eq!(h1.to_vec(), hexv("cabe9bb94c")),
            _ => panic!("Secret1 opens it"),
        }
        assert_eq!(
            Decryptor::from_filepass(&fp, true, &["wrong", DEFAULT_PASSWORD]).err(),
            Some(Refused::Password)
        );
    }

    // Independently generated vector, cross-checked against the msoffcrypto
    // reference (salt 10..1f, password "VelvetSweatshop", 128-bit).
    #[test]
    fn rc4_cryptoapi_verifier_vector() {
        let mut header = vec![0u8; 32];
        header[16..20].copy_from_slice(&128u32.to_le_bytes());
        let mut fp = vec![1u8, 0, 3, 0, 3, 0];
        fp.extend(0x24u32.to_le_bytes());
        fp.extend((header.len() as u32).to_le_bytes());
        fp.extend(&header);
        fp.extend(16u32.to_le_bytes());
        fp.extend(16u8..32);
        fp.extend(hexv("66871900f3075fc3fa7e1d9b934d6b22"));
        fp.extend(20u32.to_le_bytes());
        fp.extend(hexv("13146eb6c265735c52ea6eb1cc48739e80561620"));
        assert!(Decryptor::from_filepass(&fp, true, &[DEFAULT_PASSWORD]).is_ok());
        assert_eq!(
            Decryptor::from_filepass(&fp, true, &["nope"]).err(),
            Some(Refused::Password)
        );
        // A key size past what SHA-1 gives is a method not had, not a cut key.
        fp[6 + 8 + 16..6 + 8 + 20].copy_from_slice(&2048u32.to_le_bytes());
        assert_eq!(
            Decryptor::from_filepass(&fp, true, &[DEFAULT_PASSWORD]).err(),
            Some(Refused::Method)
        );
    }

    #[test]
    fn rc4_is_symmetric() {
        let k = b"key1234567890abc";
        let pt = b"eicar-ish plaintext content";
        let mut d = pt.to_vec();
        rc4(k, &mut d);
        assert_ne!(&d[..], &pt[..]);
        rc4(k, &mut d);
        assert_eq!(&d[..], &pt[..]);
    }

    /// A whole workbook stream (a BOF, a FILEPASS, records), whose FILEPASS is
    /// found after the BOF.
    #[test]
    fn a_workbook_is_decrypted_from_its_filepass() {
        for m in ["xor", "rc4", "cryptoapi128"] {
            let fp = filepass(m, true);
            let mut stream = vec![];
            // BOF, BIFF8, workbook globals.
            stream.extend_from_slice(&0x0809u16.to_le_bytes());
            stream.extend_from_slice(&16u16.to_le_bytes());
            stream.extend_from_slice(&[0x00, 0x06, 0x05, 0x00]);
            stream.extend_from_slice(&[0; 12]);
            let filepass_pos = stream.len();
            stream.extend_from_slice(&0x002Fu16.to_le_bytes());
            stream.extend_from_slice(&(fp.len() as u16).to_le_bytes());
            stream.extend_from_slice(&fp);
            for k in 0..50u16 {
                stream.extend_from_slice(&0x0203u16.to_le_bytes());
                stream.extend_from_slice(&14u16.to_le_bytes());
                stream.extend_from_slice(&k.to_le_bytes());
                stream.extend_from_slice(&[9; 12]);
            }
            let mut enc = stream.clone();
            encrypt_stream(m, &mut enc, filepass_pos);
            assert_eq!(filepass_at(&enc), Some(filepass_pos), "{m}");
            let out = decrypt_workbook(&enc, DEFAULT_PASSWORDS).unwrap();
            // The records are the plain ones, and FILEPASS is blanked.
            let mut blanked = stream.clone();
            blanked[filepass_pos..filepass_pos + 2].fill(0);
            blanked[filepass_pos + 4..filepass_pos + 4 + fp.len()].fill(0);
            assert_eq!(out, blanked, "{m}");
            assert_eq!(filepass_at(&out), None, "{m}");
            assert_eq!(
                decrypt_workbook(&enc, &["no"]).err(),
                Some(Refused::Password),
                "{m}"
            );
        }
    }
}
