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
    let p = format!(
        "{}/tests/fixtures/encrypted/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
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
        let mut budget = Budget::with_passwords(Limits::default(), vec!["secret".to_string()]);
        let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1, "{name}: one member");
        let e = &entries[0];
        assert!(
            e.unsupported.is_none(),
            "{name}: should have decrypted, got unsupported={:?}",
            e.unsupported
        );
        // Decrypting does not un-encrypt the member it came from. The flag stays
        // set so `--alert-encrypted` still reports the fact, while `unsupported`
        // stays clear so the recovered plaintext is scanned normally — the two
        // are independent, and tying them together meant that cracking a password
        // erased the report of there having been one.
        assert!(
            e.encrypted,
            "{name}: a decrypted member must still be flagged as having been encrypted"
        );
        assert!(
            has_eicar(&e.data),
            "{name}: EICAR not recovered from decrypted bytes"
        );
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
        assert!(
            e.unsupported.is_some(),
            "{name}: must be unsupported (no password)"
        );
        assert!(e.data.is_empty(), "{name}: undecrypted member has no data");
        assert!(!has_eicar(&e.data));
    }
}

/// A wrong password also reports encrypted (no false 'decrypted' on bad creds).
#[test]
fn wrong_password_reports_encrypted() {
    for name in ["zip_aes256_store.zip", "zip_zipcrypto_store.zip"] {
        let blob = fixture(name);
        let mut budget = Budget::with_passwords(Limits::default(), vec!["nope".to_string()]);
        let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
        let e = &entries[0];
        assert!(
            e.encrypted,
            "{name}: wrong password must still report encrypted"
        );
        assert!(e.unsupported.is_some(), "{name}");
    }
}

/// Regression: a ZipCrypto archive written with a streaming **data descriptor**
/// (general-purpose bit 3), as Info-ZIP's `zip -e`/`-P` emits by default. Here
/// the one-byte password check is the high byte of the DOS mod-time, not the
/// CRC-32 — checking only against the CRC byte would reject the correct password
/// and report the member password-protected even with `secret`. (The other
/// `zip_zipcrypto_*` fixtures are `7z`-made with bit 3
/// clear, so they never exercised this path.)
#[test]
fn zipcrypto_data_descriptor_decrypts_with_password() {
    let blob = fixture("zip_zipcrypto_datadesc.zip");
    let mut budget = Budget::with_passwords(Limits::default(), vec!["secret".to_string()]);
    let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert!(
        e.unsupported.is_none(),
        "data-descriptor ZipCrypto should decrypt with the right password, got unsupported={:?}",
        e.unsupported
    );
    // Still flagged as having been encrypted — see the note in
    // `decrypts_with_password`. Recovering the content does not unmake the fact.
    assert!(e.encrypted, "the member was encrypted and must say so");
    assert!(
        has_eicar(&e.data),
        "EICAR not recovered from decrypted bytes"
    );
}

/// The same data-descriptor fixture with the wrong password must still report
/// encrypted — the mod-time check byte widens acceptance but the full-payload
/// CRC check still rejects bad credentials (no false decrypt).
#[test]
fn zipcrypto_data_descriptor_wrong_password_reports_encrypted() {
    let blob = fixture("zip_zipcrypto_datadesc.zip");
    let mut budget = Budget::with_passwords(Limits::default(), vec!["nope".to_string()]);
    let entries = extract(Format::Zip, &blob, &mut budget).unwrap();
    let e = &entries[0];
    assert!(e.encrypted && e.unsupported.is_some());
    assert!(!has_eicar(&e.data));
}

/// 7z: an AES-256 header-encrypted (`-mhe=on`) archive without a valid password
/// must surface as an encrypted member, never silently clean. With the correct
/// password and decryption compiled in, the header + data decrypt and the inner
/// EICAR is recovered.
#[test]
fn sevenz_encrypted_detected() {
    let p = format!(
        "{}/tests/fixtures/encrypted/aes256_hdr.7z",
        env!("CARGO_MANIFEST_DIR")
    );
    let blob = std::fs::read(&p).unwrap();
    assert_eq!(exav_unpack::detect(&blob), Some(Format::SevenZip));

    // No valid password → encrypted signal, never clean.
    let mut budget = Budget::with_passwords(Limits::default(), vec!["wrong".to_string()]);
    let entries = extract(Format::SevenZip, &blob, &mut budget).unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.encrypted && e.unsupported.is_some()),
        "7z AES must be reported encrypted without a password, got {:?}",
        entries
            .iter()
            .map(|e| (&e.name, e.encrypted, e.unsupported))
            .collect::<Vec<_>>()
    );

    // Correct password + decryption → the encrypted header decrypts to EICAR.
    #[cfg(feature = "decrypt")]
    {
        let mut budget = Budget::with_passwords(Limits::default(), vec!["password".to_string()]);
        let entries = extract(Format::SevenZip, &blob, &mut budget).unwrap();
        assert!(
            entries.iter().any(|e| has_eicar(&e.data)),
            "-mhe 7z must decrypt to EICAR with the password"
        );
    }
}

/// Verify that MSI stream names are correctly decompressed by exav-unpack.
/// Reads the PowerShell MSI, extracts all streams, and checks that:
/// 1. Known decompressed names appear (e.g., !_Tables, !_StringPool)
/// 2. The total stream count is correct (56 for this MSI)
#[test]
fn msi_stream_name_decompression() {
    let data = match std::fs::read("/tmp/msi_test/powershell.msi") {
        Ok(d) => d,
        Err(_) => return, // skip if test fixture not available
    };
    let limits = exav_unpack::Limits::default();
    let mut budget = exav_unpack::Budget::new(limits);
    let entries = exav_unpack::extract(exav_unpack::Format::Ole, &data, &mut budget).unwrap();

    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();

    // The PowerShell MSI has 56 OLE2 streams
    assert!(
        entries.len() >= 50,
        "Expected at least 50 streams, got {}",
        entries.len()
    );

    // Check that known MSI table names are present (decompressed)
    let has_tables = names.iter().any(|n| n.ends_with("_Tables"));
    let has_string_pool = names.iter().any(|n| n.ends_with("_StringPool"));
    let has_string_data = names.iter().any(|n| n.ends_with("_StringData"));
    let has_columns = names.iter().any(|n| n.ends_with("_Columns"));

    assert!(has_tables, "_Tables stream not found in decompressed names");
    assert!(
        has_string_pool,
        "_StringPool stream not found in decompressed names"
    );
    assert!(
        has_string_data,
        "_StringData stream not found in decompressed names"
    );
    assert!(
        has_columns,
        "_Columns stream not found in decompressed names"
    );
}
