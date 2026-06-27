//! Password-supplied decryption of encrypted ZIP members (WinZip AES + legacy
//! PKWARE ZipCrypto), validated byte-exact against `7z`-created fixtures.
//!
//! Fixtures (under `tests/fixtures/encrypted/`) each store a single member,
//! `eicar.txt` (the EICAR test string + padding), encrypted with password
//! `secret`:
//!
//! * `zip_aes256_store.zip`   — AES-256, Store
//! * `zip_aes256_deflate.zip` — AES-256, Deflate
//! * `zip_zipcrypto_store.zip`   — PKWARE ZipCrypto, Store
//! * `zip_zipcrypto_deflate.zip` — PKWARE ZipCrypto, Deflate
//!
//! With the right password the EICAR marker is recovered; with no password the
//! member must surface as `unsupported(encrypted=true)` (→ `PasswordProtected`),
//! never silently clean.

use exav_unpack::{extract, Budget, Format, Limits};

const EICAR_PREFIX: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/encrypted/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn has_eicar(data: &[u8]) -> bool {
    data.windows(EICAR_PREFIX.len()).any(|w| w == EICAR_PREFIX)
}

/// With the correct password each scheme decrypts and the EICAR marker is found.
#[test]
fn decrypts_with_password() {
    for name in [
        "zip_aes256_store.zip",
        "zip_aes256_deflate.zip",
        "zip_zipcrypto_store.zip",
        "zip_zipcrypto_deflate.zip",
    ] {
        let blob = fixture(name);
        let mut budget =
            Budget::with_passwords(Limits::default(), vec!["secret".to_string()]);
        let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1, "{name}: one member");
        let e = &entries[0];
        assert!(
            e.unsupported.is_none(),
            "{name}: should have decrypted, got unsupported={:?}",
            e.unsupported
        );
        assert!(!e.encrypted, "{name}: decrypted member is not flagged encrypted");
        assert!(has_eicar(&e.data), "{name}: EICAR not recovered from decrypted bytes");
    }
}

/// A decoy password before the real one still finds it (pool is tried in order).
#[test]
fn decrypts_with_pool_second_password() {
    let blob = fixture("zip_aes256_deflate.zip");
    let mut budget = Budget::with_passwords(
        Limits::default(),
        vec!["wrong".to_string(), "secret".to_string()],
    );
    let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
    assert!(has_eicar(&entries[0].data));
}

/// Without a password (empty pool), every scheme yields a metadata-only,
/// encrypted member — never silently clean.
#[test]
fn no_password_reports_encrypted() {
    for name in [
        "zip_aes256_store.zip",
        "zip_aes256_deflate.zip",
        "zip_zipcrypto_store.zip",
        "zip_zipcrypto_deflate.zip",
    ] {
        let blob = fixture(name);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1, "{name}");
        let e = &entries[0];
        assert!(e.encrypted, "{name}: member must be flagged encrypted");
        assert!(e.unsupported.is_some(), "{name}: must be unsupported (no password)");
        assert!(e.data.is_empty(), "{name}: undecrypted member has no data");
        assert!(!has_eicar(&e.data));
    }
}

/// A wrong password also reports encrypted (no false 'decrypted' on bad creds).
#[test]
fn wrong_password_reports_encrypted() {
    for name in ["zip_aes256_store.zip", "zip_zipcrypto_store.zip"] {
        let blob = fixture(name);
        let mut budget =
            Budget::with_passwords(Limits::default(), vec!["nope".to_string()]);
        let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
        let e = &entries[0];
        assert!(e.encrypted, "{name}: wrong password must still report encrypted");
        assert!(e.unsupported.is_some(), "{name}");
    }
}

/// 7z: AES-256 header-encrypted archive is DETECTED as encrypted (not decrypted
/// — the `aes256` feature is off to keep `getrandom` out). It must surface as an
/// encrypted member, never silently clean.
#[test]
fn sevenz_encrypted_detected() {
    let p = format!(
        "{}/tests/fixtures/encrypted/aes256_hdr.7z",
        env!("CARGO_MANIFEST_DIR")
    );
    let blob = std::fs::read(&p).unwrap();
    assert_eq!(exav_unpack::detect(&blob), Some(Format::SevenZip));
    // Even with a password supplied we currently only DETECT (no 7z decrypt yet).
    let mut budget = Budget::with_passwords(Limits::default(), vec!["password".to_string()]);
    let entries = extract(Format::SevenZip, &blob, &mut budget).unwrap();
    assert!(!entries.is_empty(), "must emit an encrypted signal");
    assert!(
        entries.iter().any(|e| e.encrypted && e.unsupported.is_some()),
        "7z AES must be reported encrypted, got {:?}",
        entries.iter().map(|e| (&e.name, e.encrypted, e.unsupported)).collect::<Vec<_>>()
    );
}
