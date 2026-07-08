//! End-to-end tests for the opt-in ClamAV `--alert-*` heuristic alerts.
//!
//! These correspond to ClamAV's `CL_SCAN_HEURISTIC_*` flags, which are **off by
//! default**: with the flag clear the existing verdict is unchanged; only when
//! the caller opts in does the heuristic upgrade to an `Infected` detection.
//!
//! * `alert_encrypted` — a password-protected member becomes
//!   `Heuristics.Encrypted.*` (was [`Verdict::PasswordProtected`]).
//! * `alert_macros` — an OLE2 document carrying a VBA project becomes
//!   `Heuristics.OLE2.ContainsMacros`.

use std::io::Write;

use exav_core::{analyze, Database, Method, ScanOptions, Verdict};

fn builtin_db() -> Database {
    // The built-in DB carries only the EICAR signature; the heuristics under
    // test are structural, not signature-driven.
    Database::builtin()
}

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

// --- alert-encrypted -------------------------------------------------------

#[test]
fn encrypted_zip_default_is_password_protected() {
    // Regression guard for the "additive only" constraint: with the flag OFF the
    // encrypted ZIP still yields the existing PasswordProtected verdict.
    let db = builtin_db();
    let blob = fixture("zip_aes256_store.zip");
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::PasswordProtected { .. } => {}
        other => panic!("expected PasswordProtected with flag off, got {other:?}"),
    }
}

#[test]
fn alert_encrypted_upgrades_to_heuristic_detection() {
    let db = builtin_db();
    let blob = fixture("zip_aes256_store.zip");
    let opts = ScanOptions {
        alert_encrypted: true,
        ..ScanOptions::default()
    };
    match analyze(&db, &blob, &opts).verdict {
        Verdict::Infected {
            signature, method, ..
        } => {
            assert_eq!(signature, "Heuristics.Encrypted.Zip");
            assert_eq!(method, Method::Heuristic);
        }
        other => panic!("expected Heuristics.Encrypted.Zip Infected, got {other:?}"),
    }
}

#[test]
fn alert_encrypted_with_password_still_finds_payload() {
    // A real detection beats the heuristic: with the correct password the inner
    // EICAR is decrypted and FOUND, not reported as merely "encrypted".
    let db = builtin_db();
    let blob = fixture("zip_aes256_store.zip");
    let opts = ScanOptions {
        alert_encrypted: true,
        passwords: vec!["secret".to_string()],
        ..ScanOptions::default()
    };
    match analyze(&db, &blob, &opts).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.contains("EICAR") || signature.contains("Eicar"),
            "expected EICAR detection, got {signature}"
        ),
        other => panic!("expected EICAR Infected, got {other:?}"),
    }
}

// --- alert-macros ----------------------------------------------------------

/// Build a minimal, valid OLE2 (Compound File Binary) document carrying a VBA
/// project: a `VBA/dir` stream holding an (uncompressed) MS-OVBA compressed
/// container with a single `MODULENAME` record. exav's OLE extractor decompresses
/// this, finds one module, and emits the `vba_project` text artifact — the signal
/// the `--alert-macros` heuristic keys on.
fn macro_ole2() -> Vec<u8> {
    // A single MS-OVBA `dir` record: MODULENAME (id 0x0019), size 6, "Macros".
    let mut dir_records: Vec<u8> = Vec::new();
    dir_records.extend_from_slice(&0x0019u16.to_le_bytes()); // record id
    dir_records.extend_from_slice(&6u32.to_le_bytes()); // record size
    dir_records.extend_from_slice(b"Macros"); // module name (6 bytes)

    // Wrap in an MS-OVBA CompressedContainer with one *raw* (uncompressed) chunk:
    //   [0x01] signature byte, then a chunk header u16 with
    //   compressed=0, chunk-signature=0b011 (bits 12..15), size=len-1 (bits 0..12).
    let mut dir_stream: Vec<u8> = vec![0x01];
    let header: u16 = (0b011 << 12) | ((dir_records.len() as u16) - 1);
    dir_stream.extend_from_slice(&header.to_le_bytes());
    dir_stream.extend_from_slice(&dir_records);

    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut cf = cfb::CompoundFile::create(cursor).expect("create cfb");
    cf.create_storage("/VBA").expect("create /VBA storage");
    {
        let mut s = cf.create_stream("/VBA/dir").expect("create /VBA/dir");
        s.write_all(&dir_stream).expect("write dir stream");
        s.flush().expect("flush dir stream");
    }
    cf.flush().expect("flush cfb");
    cf.into_inner().into_inner()
}

#[test]
fn macro_ole2_fixture_is_recognised_as_ole() {
    // Sanity: the constructed blob is a real OLE2 container.
    let db = builtin_db();
    assert_eq!(
        db.identify(&macro_ole2()),
        exav_core::filetype::FileType::Ole
    );
}

#[test]
fn macro_ole2_default_not_flagged() {
    // Additive-only guard: with the flag off a macro-bearing OLE2 is not flagged
    // on that basis (the built-in DB has no macro signature, so it is Clean).
    let db = builtin_db();
    let blob = macro_ole2();
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Clean => {}
        other => panic!("expected Clean with flag off, got {other:?}"),
    }
}

#[test]
fn alert_macros_flags_vba_project() {
    let db = builtin_db();
    let blob = macro_ole2();
    let opts = ScanOptions {
        alert_macros: true,
        ..ScanOptions::default()
    };
    match analyze(&db, &blob, &opts).verdict {
        Verdict::Infected {
            signature, method, ..
        } => {
            assert_eq!(signature, "Heuristics.OLE2.ContainsMacros");
            assert_eq!(method, Method::Heuristic);
        }
        other => panic!("expected Heuristics.OLE2.ContainsMacros, got {other:?}"),
    }
}
