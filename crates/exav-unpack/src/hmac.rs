//! HMAC (RFC 2104) and PBKDF2 (RFC 8018, section 5.2) over the hashes that
//! implement the `digest` traits (SHA-1 and SHA-256 here), and a comparison
//! that does not stop at the first differing byte.

use digest::common::BlockSizeUser;
use digest::{Digest, Output};

/// An HMAC keyed once: the hash state after the inner pad and after the
/// outer pad. Cloning it gives a fresh MAC under the same key.
#[derive(Clone)]
pub(crate) struct Hmac<D> {
    inner: D,
    outer: D,
}

impl<D: Digest + BlockSizeUser + Clone> Hmac<D> {
    /// Any key length is allowed; one longer than the hash's block is hashed
    /// first.
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut block = vec![0u8; D::block_size()];
        if key.len() > block.len() {
            let hashed = D::digest(key);
            block[..hashed.len()].copy_from_slice(&hashed);
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        for b in &mut block {
            *b ^= 0x36;
        }
        let mut inner = D::new();
        inner.update(&block);
        for b in &mut block {
            *b ^= 0x36 ^ 0x5c;
        }
        let mut outer = D::new();
        outer.update(&block);
        Hmac { inner, outer }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub(crate) fn finalize(self) -> Output<D> {
        let mut outer = self.outer;
        outer.update(self.inner.finalize());
        outer.finalize()
    }
}

/// Block `index` (1 based) of PBKDF2 after `rounds` (at least 1) iterations.
/// `seen(i, t)` is called with the running value after each iteration `i`,
/// counted from 1, so a caller can read it at several counts.
pub(crate) fn pbkdf2_block<D: Digest + BlockSizeUser + Clone>(
    mac: &Hmac<D>,
    salt: &[u8],
    index: u32,
    rounds: u32,
    mut seen: impl FnMut(u32, &Output<D>),
) -> Output<D> {
    let mut m = mac.clone();
    m.update(salt);
    m.update(&index.to_be_bytes());
    let mut u = m.finalize();
    let mut t = u.clone();
    seen(1, &t);
    for i in 2..=rounds {
        let mut m = mac.clone();
        m.update(&u);
        u = m.finalize();
        for (a, b) in t.iter_mut().zip(&u) {
            *a ^= b;
        }
        seen(i, &t);
    }
    t
}

/// PBKDF2 with HMAC over `D`, filling `out` (at most 2^32 - 1 blocks of the
/// hash's size). `rounds` is at least 1; 0 does the same as 1.
pub(crate) fn pbkdf2<D: Digest + BlockSizeUser + Clone>(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    out: &mut [u8],
) {
    let mac = Hmac::<D>::new(password);
    for (index, chunk) in (1..=u32::MAX).zip(out.chunks_mut(<D as Digest>::output_size())) {
        let t = pbkdf2_block(&mac, salt, index, rounds, |_, _| {});
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

/// Whether `a` and `b` are equal, in a time that depends on their lengths
/// and not on where they differ.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::Sha1;
    use sha2::Sha256;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn mac<D: Digest + BlockSizeUser + Clone>(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = Hmac::<D>::new(key);
        m.update(data);
        m.finalize().to_vec()
    }

    /// RFC 2202, section 3 (HMAC-SHA-1), cases 1 to 7.
    #[test]
    fn hmac_sha1_matches_rfc_2202() {
        let long = [0xaa; 80];
        let cases: [(&[u8], &[u8], &str); 7] = [
            (
                &[0x0b; 20],
                b"Hi There",
                "b617318655057264e28bc0b6fb378c8ef146be00",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            ),
            (
                &[0xaa; 20],
                &[0xdd; 50],
                "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
            ),
            (
                &hex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                &[0xcd; 50],
                "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
            ),
            (
                &[0x0c; 20],
                b"Test With Truncation",
                "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
            ),
            (
                &long,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "aa4ae5e15272d00e95705637ce8a3b55ed402112",
            ),
            (
                &long,
                b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
                "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
            ),
        ];
        for (n, (key, data, want)) in cases.iter().enumerate() {
            assert_eq!(mac::<Sha1>(key, data), hex(want), "case {}", n + 1);
        }
    }

    /// RFC 4231, section 4 (HMAC-SHA-256), cases 1 to 4, 6 and 7. Case 5 is a
    /// truncated output and is not run. Cases 6 and 7 have a 131-byte key,
    /// longer than the 64-byte block.
    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        let long = [0xaa; 131];
        let cases: [(&[u8], &[u8], &str); 6] = [
            (
                &[0x0b; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                &[0xaa; 20],
                &[0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                &hex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                &[0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                &long,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                &long,
                b"This is a test using a larger than block-size key and a larger than \
                  block-size data. The key needs to be hashed before being used by the \
                  HMAC algorithm.",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (n, (key, data, want)) in cases.iter().enumerate() {
            assert_eq!(mac::<Sha256>(key, data), hex(want), "case {n}");
        }
    }

    /// RFC 6070 (PBKDF2-HMAC-SHA-1). The 16,777,216-iteration vector is left
    /// out.
    #[test]
    fn pbkdf2_sha1_matches_rfc_6070() {
        let cases: [(&[u8], &[u8], u32, &str); 5] = [
            (
                b"password",
                b"salt",
                1,
                "0c60c80f961f0e71f3a9b524af6012062fe037a6",
            ),
            (
                b"password",
                b"salt",
                2,
                "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
            ),
            (
                b"password",
                b"salt",
                4096,
                "4b007901b765489abead49d926f721d065a429c1",
            ),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
            ),
            (
                b"pass\0word",
                b"sa\0lt",
                4096,
                "56fa6aa75548099dcc37d7f03425e0c3",
            ),
        ];
        for (n, (pw, salt, rounds, want)) in cases.iter().enumerate() {
            let want = hex(want);
            let mut out = vec![0; want.len()];
            pbkdf2::<Sha1>(pw, salt, *rounds, &mut out);
            assert_eq!(out, want, "case {n}");
        }
    }

    /// RFC 7914, section 11 (PBKDF2-HMAC-SHA-256); both ask for two blocks.
    #[test]
    fn pbkdf2_sha256_matches_rfc_7914() {
        let cases: [(&[u8], &[u8], u32, &str); 2] = [
            (
                b"passwd",
                b"salt",
                1,
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc
                 49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            ),
            (
                b"Password",
                b"NaCl",
                80000,
                "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56
                 a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
            ),
        ];
        for (n, (pw, salt, rounds, want)) in cases.iter().enumerate() {
            let want = hex(want);
            let mut out = vec![0; want.len()];
            pbkdf2::<Sha256>(pw, salt, *rounds, &mut out);
            assert_eq!(out, want, "case {n}");
        }
    }

    #[test]
    fn a_block_can_be_read_at_several_counts() {
        let mac = Hmac::<Sha256>::new(b"password");
        let mut at = Vec::new();
        let last = pbkdf2_block(&mac, b"salt", 1, 5, |i, t| at.push((i, t.to_vec())));
        assert_eq!(at.len(), 5);
        assert_eq!(at[4].1, last.to_vec());
        for (i, t) in &at {
            let mut out = [0u8; 32];
            pbkdf2::<Sha256>(b"password", b"salt", *i, &mut out);
            assert_eq!(&out[..], &t[..]);
        }
    }

    #[test]
    fn ct_eq_compares_every_byte_and_the_length() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"xbc"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"ab", b"abc"));
    }
}
