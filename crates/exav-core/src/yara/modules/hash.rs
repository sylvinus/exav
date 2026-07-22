//! The `hash` module.
//!
//! Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X. Hash
//! primitives come from the RustCrypto crates (`md-5`/`sha1`/`sha2`) and
//! `crc32fast`, matching yara-x's choices.

use std::collections::HashMap;
use std::rc::Rc;

use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

use super::FuncId;
use crate::yara::ir::Value;

/// The `hash` module exposes only functions, so its root is an empty struct.
pub(crate) fn root() -> Value {
    Value::Struct(Rc::new(HashMap::new()))
}

pub(crate) fn call(func: FuncId, data: &[u8], args: &[Value]) -> Option<Value> {
    use FuncId::*;
    match func {
        HashMd5Data => hex_over_range::<Md5>(data, args).map(Value::Str),
        HashMd5Str => Some(Value::Str(hex::<Md5>(args[0].as_bytes()?))),
        HashSha1Data => hex_over_range::<Sha1>(data, args).map(Value::Str),
        HashSha1Str => Some(Value::Str(hex::<Sha1>(args[0].as_bytes()?))),
        HashSha256Data => hex_over_range::<Sha256>(data, args).map(Value::Str),
        HashSha256Str => Some(Value::Str(hex::<Sha256>(args[0].as_bytes()?))),
        HashCrc32Data => {
            let s = range(data, args)?;
            Some(Value::Int(crc32fast::hash(s) as i64))
        }
        HashCrc32Str => Some(Value::Int(crc32fast::hash(args[0].as_bytes()?) as i64)),
        HashChecksum32Data => {
            let s = range(data, args)?;
            Some(Value::Int(checksum32(s) as i64))
        }
        HashChecksum32Str => Some(Value::Int(checksum32(args[0].as_bytes()?) as i64)),
        _ => unreachable!("non-hash FuncId dispatched to hash::call"),
    }
}

/// Resolves `(offset, size)` args to a byte slice, matching yara-x: the range
/// is `offset..(offset+size)`, and any out-of-bounds/negative bound yields
/// undefined (`None`).
fn range<'d>(data: &'d [u8], args: &[Value]) -> Option<&'d [u8]> {
    let offset = args[0].to_i64()?;
    let size = args[1].to_i64()?;
    let start: usize = offset.try_into().ok()?;
    let end: usize = offset.checked_add(size)?.try_into().ok()?;
    data.get(start..end)
}

fn hex_over_range<D: Digest>(data: &[u8], args: &[Value]) -> Option<Vec<u8>> {
    let s = range(data, args)?;
    Some(hex::<D>(s))
}

/// One-shot digest of `data` with `D`, lowercase-hex-encoded (as YARA returns
/// hashes). The digest uses the same RustCrypto crates the rest of exav-core
/// uses, and the hex encoding reuses exav-core's `hexsig::encode_hex` (identical
/// `0123456789abcdef` lowercase output the bespoke encoder produced here before).
fn hex<D: Digest>(data: &[u8]) -> Vec<u8> {
    crate::hexsig::encode_hex(&D::digest(data)).into_bytes()
}

/// yara-x's `checksum32`: sum of all bytes modulo 2^32 (with a SWAR fast path;
/// the naive sum is equivalent).
fn checksum32(data: &[u8]) -> u32 {
    let mut checksum: u32 = 0;
    for &byte in data {
        checksum = checksum.wrapping_add(byte as u32);
    }
    checksum
}

#[cfg(test)]
mod tests {
    // Ported from yara-x's `hash` module tests (BSD-3-Clause), see
    // LICENSE-YARA-X.
    fn t(src: &str, data: &[u8]) -> bool {
        let rules = crate::yara::compile(src).expect("compile");
        rules.scan(data).matching_rules().len() == 1
    }

    #[test]
    fn md5() {
        assert!(t(
            r#"import "hash" rule r {
              condition:
                hash.md5(0, filesize) == "6df23dc03f9b54cc38a0fc1483df6e21" and
                hash.md5(3, 3) == "37b51d194a7513e45b56f6524f2d51f2" and
                hash.md5(0, filesize) == hash.md5("foobarbaz") and
                hash.md5(3, 3) == hash.md5("bar")
            }"#,
            b"foobarbaz"
        ));
    }

    #[test]
    fn sha1() {
        assert!(t(
            r#"import "hash" rule r {
              condition:
                hash.sha1(0, filesize) == "5f5513f8822fdbe5145af33b64d8d970dcf95c6e" and
                hash.sha1(3, 3) == "62cdb7020ff920e5aa642c3d4066950dd1f01f4d" and
                hash.sha1(0, filesize) == hash.sha1("foobarbaz") and
                hash.sha1(3, 3) == hash.sha1("bar")
            }"#,
            b"foobarbaz"
        ));
    }

    #[test]
    fn sha256() {
        assert!(t(
            r#"import "hash" rule r {
              condition:
                hash.sha256(0, filesize) == "97df3588b5a3f24babc3851b372f0ba71a9dcdded43b14b9d06961bfc1707d9d" and
                hash.sha256(3, 3) == "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9" and
                hash.sha256(0, filesize) == hash.sha256("foobarbaz") and
                hash.sha256(3, 3) == hash.sha256("bar")
            }"#,
            b"foobarbaz"
        ));
    }

    #[test]
    fn crc32() {
        assert!(t(
            r#"import "hash" rule r {
              condition:
                hash.crc32(0, filesize) == 0x1a7827aa and
                hash.crc32(3, 3) == 0x76ff8caa and
                hash.crc32(0, filesize) == hash.crc32("foobarbaz") and
                hash.crc32(3, 3) == hash.crc32("bar")
            }"#,
            b"foobarbaz"
        ));
    }

    #[test]
    fn checksum32() {
        assert!(t(
            r#"import "hash" rule r { condition: hash.checksum32("TEST STRING") == 0x337 }"#,
            b"foobarbaz"
        ));
        assert!(t(
            r#"import "hash" rule r { condition: hash.checksum32(0, filesize) == 0x337 }"#,
            b"TEST STRING"
        ));
    }

    #[test]
    fn out_of_bounds_is_undefined() {
        assert!(t(
            r#"import "hash" rule r { condition: not defined hash.md5(0, 100) }"#,
            b"foobarbaz"
        ));
    }
}
