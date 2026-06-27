//! End-to-end: password-supplied scanning of encrypted archives through the
//! full exav-core `analyze` path.
//!
//! Fixtures each hold a single member, `eicar.txt` (the exact EICAR test
//! string), encrypted with password `secret` (ZIP) / `password` (7z):
//!
//! * `zip_aes256_store.zip`      — WinZip AES-256
//! * `zip_zipcrypto_store.zip`   — legacy PKWARE ZipCrypto
//! * `aes256_hdr.7z`             — header-encrypted 7z (detect-only)
//!
//! With the password the inner EICAR is FOUND (`Infected`); without it the scan
//! is `PasswordProtected` — never `Clean`, never `Infected`.

use exav_core::{analyze, db, ScanOptions, Verdict};

fn builtin_db() -> exav_core::Database {
    // The built-in DB carries the EICAR signature, which is all we need.
    exav_core::Database::builtin()
}

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn with_pw(pw: &str) -> ScanOptions {
    ScanOptions {
        passwords: vec![pw.to_string()],
        ..ScanOptions::default()
    }
}

#[test]
fn zip_aes_decrypts_and_finds_eicar() {
    let db = builtin_db();
    let blob = fixture("zip_aes256_store.zip");
    // With the password: the EICAR inside is decrypted and detected.
    match analyze(&db, &blob, &with_pw("secret")).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.contains("EICAR") || signature.contains("Eicar"),
            "unexpected signature {signature}"
        ),
        other => panic!("expected Infected with password, got {other:?}"),
    }
    // Without the password: PasswordProtected, never Clean/Infected.
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::PasswordProtected { .. } => {}
        other => panic!("expected PasswordProtected w/o password, got {other:?}"),
    }
    // A wrong password is still PasswordProtected.
    match analyze(&db, &blob, &with_pw("wrong")).verdict {
        Verdict::PasswordProtected { .. } => {}
        other => panic!("expected PasswordProtected w/ wrong password, got {other:?}"),
    }
}

#[test]
fn zip_zipcrypto_decrypts_and_finds_eicar() {
    let db = builtin_db();
    let blob = fixture("zip_zipcrypto_store.zip");
    match analyze(&db, &blob, &with_pw("secret")).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("expected Infected, got {other:?}"),
    }
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::PasswordProtected { .. } => {}
        other => panic!("expected PasswordProtected, got {other:?}"),
    }
}

#[test]
fn sevenz_encrypted_is_password_protected() {
    let db = builtin_db();
    let blob = fixture("aes256_hdr.7z");
    // 7z AES is detect-only (no decrypt to keep getrandom out), so even with the
    // password the verdict is PasswordProtected — but crucially never Clean.
    for opts in [ScanOptions::default(), with_pw("password")] {
        match analyze(&db, &blob, &opts).verdict {
            Verdict::PasswordProtected { .. } => {}
            other => panic!("expected PasswordProtected for encrypted 7z, got {other:?}"),
        }
    }
}

/// The `.pwdb` pool (loaded into the database) also supplies decryption
/// passwords, unioned with `ScanOptions::passwords`.
#[test]
fn pwdb_pool_supplies_decryption_password() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("p.pwdb"),
        "Sig;Engine:81-255,Target:0;0;secret\n",
    )
    .unwrap();
    // Built-in EICAR isn't loaded from a dir, so add a throwaway ndb to build a DB
    // that still carries the default EICAR pattern.
    std::fs::write(dir.path().join("a.ndb"), "Demo.X:0:*:6e6f7065\n").unwrap();
    let db = db::load(dir.path()).unwrap();
    assert_eq!(db.passwords, vec!["secret".to_string()]);

    let blob = fixture("zip_aes256_store.zip");
    // No runtime password — only the `.pwdb` pool — still decrypts + detects.
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("expected Infected from .pwdb pool, got {other:?}"),
    }
}
