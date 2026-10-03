//! Encrypted RAR5 archives, and hard links, made by official RAR 7.23 from
//! `a.txt` and `b.txt`:
//!
//! ```sh
//! rar a -m3 -pinfected enc_data.rar a.txt b.txt
//! rar a -m3 -hpinfected enc_headers.rar a.txt b.txt
//! rar a -m3 -hpsecret enc_headers_unknown.rar a.txt
//! rar a -m0 -psecret enc_stored_unknown.rar a.txt
//! rar a -m3 -oh hardlink.rar a.txt a_link.txt   # a_link.txt a hard link to a.txt
//! ```
//!
//! `infected` is among the passwords exav tries on its own; `secret` is not.

use super::extract_each;
use exav_unpack::{Budget, Entry, Format, Limits};

const A: &str = "2673a5a4fd9870c942d8e1b56cf883e472b4b428ce2c4c7b87032049373768a5";
const B: &str = "ee730c5a2e41032d0c296b26b958ff26c81e710e7c30271184a4f5019aca4eff";

fn members(name: &str, passwords: &[&str]) -> Vec<Entry> {
    let p = format!("{}/tests/fixtures/rar5/{name}", env!("CARGO_MANIFEST_DIR"));
    let blob = std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let mut b = Budget::with_passwords(
        Limits::default(),
        passwords.iter().map(|s| s.to_string()).collect(),
    );
    let mut out = Vec::new();
    let _ = extract_each(
        Format::Rar,
        &blob,
        &mut b,
        &mut |e: Entry, _: &mut Budget| {
            out.push(e);
            None::<()>
        },
    );
    out
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Every member decrypted, decoded and checked against its checksum, which
/// under a password is keyed to it: name, digest, and still flagged encrypted.
fn decrypted(name: &str, passwords: &[&str]) -> Vec<(String, String, bool)> {
    let mut got: Vec<_> = members(name, passwords)
        .into_iter()
        .map(|e| {
            assert!(
                e.unsupported.is_none(),
                "{name} {}: {:?}",
                e.name,
                e.unsupported
            );
            (e.name, sha256_hex(&e.data), e.encrypted)
        })
        .collect();
    got.sort();
    got
}

#[test]
fn encrypted_data_opens_with_a_default_password() {
    assert_eq!(
        decrypted("enc_data.rar", &[]),
        [
            ("a.txt".into(), A.into(), true),
            ("b.txt".into(), B.into(), true)
        ]
    );
}

/// `-hp` encrypts every header after the archive encryption header. Those
/// were never read, and the archive came out as one with no members: clean.
#[test]
fn encrypted_headers_open_with_a_default_password() {
    assert_eq!(
        decrypted("enc_headers.rar", &[]),
        [
            ("a.txt".into(), A.into(), true),
            ("b.txt".into(), B.into(), true)
        ]
    );
}

#[test]
fn encrypted_headers_without_the_password_are_reported() {
    let e = members("enc_headers_unknown.rar", &[]);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(e[0].encrypted && e[0].unsupported.is_some());
    assert_eq!(
        decrypted("enc_headers_unknown.rar", &["secret"]),
        [("a.txt".into(), A.into(), true)]
    );
}

/// A stored member under a password exav does not have was handed over as
/// its ciphertext, unflagged, as though it were the file.
#[test]
fn an_encrypted_stored_member_is_not_its_ciphertext() {
    let e = members("enc_stored_unknown.rar", &[]);
    assert_eq!(e.len(), 1, "{e:?}");
    assert!(e[0].encrypted && e[0].unsupported.is_some() && e[0].data.is_empty());
    assert_eq!(
        decrypted("enc_stored_unknown.rar", &["secret"]),
        [("a.txt".into(), A.into(), true)]
    );
}

/// A hard link has no data of its own: it is the member it names.
#[test]
fn a_hard_link_is_the_member_it_names() {
    assert_eq!(
        decrypted("hardlink.rar", &[]),
        [
            ("a.txt".into(), A.into(), false),
            ("a_link.txt".into(), A.into(), false)
        ]
    );
}
