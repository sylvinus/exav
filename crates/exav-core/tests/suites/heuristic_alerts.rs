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
//!
//! It also covers the `clamav_heuristics` / `heuristics` split: the
//! ClamAV-default `Heuristics.PDF.ObfuscatedNameObject` heuristic is **on by
//! default** (FP-safe parity with clamscan), can be turned off by clearing
//! `clamav_heuristics`, and is also enabled by the broader `heuristics` flag.

use std::io::Write;

use exav_core::{analyze, Method, ScanOptions, Scanner, Verdict};

fn builtin_db() -> Scanner {
    // The built-in DB carries only the EICAR signature; the heuristics under
    // test are structural, not signature-driven.
    Scanner::builtin()
}

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
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
    let mut opts = ScanOptions::default();
    opts.alert_encrypted = true;
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

/// One stored ZIP member with the encryption bit set over cleartext, as APK
/// packers write every member (Android ignores the bit).
fn falsely_encrypted_zip(body: &[u8]) -> Vec<u8> {
    flagged_zip(body, 1, 1)
}

/// One stored cleartext member, its central and local headers carrying the
/// general-purpose flags given.
fn flagged_zip(body: &[u8], central_flags: u16, local_flags: u16) -> Vec<u8> {
    let name = b"classes.dex";
    let crc = crc32fast::hash(body);
    let mut z = Vec::new();
    let header = |sig: &[u8], central: bool| {
        let mut h = sig.to_vec();
        if central {
            h.extend_from_slice(&20u16.to_le_bytes()); // made by
        }
        h.extend_from_slice(&20u16.to_le_bytes()); // needed
        let flags = if central { central_flags } else { local_flags };
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes()); // stored
        h.extend_from_slice(&[0; 4]); // time, date
        h.extend_from_slice(&crc.to_le_bytes());
        h.extend_from_slice(&(body.len() as u32).to_le_bytes());
        h.extend_from_slice(&(body.len() as u32).to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes()); // extra
        if central {
            h.extend_from_slice(&[0; 6]); // comment length, disk, internal attributes
            h.extend_from_slice(&0u32.to_le_bytes()); // external attributes
            h.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        }
        h.extend_from_slice(name);
        h
    };
    z.extend(header(b"PK\x03\x04", false));
    z.extend_from_slice(body);
    let cd = z.len();
    z.extend(header(b"PK\x01\x02", true));
    let cd_len = z.len() - cd;
    z.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    z.extend_from_slice(&(cd_len as u32).to_le_bytes());
    z.extend_from_slice(&(cd as u32).to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z
}

/// A member whose encryption bit lies is read anyway, and still reported as
/// encrypted when the alert is on, as ClamAV reports it: after the walk, so a
/// signature in its content wins.
#[test]
fn a_falsely_encrypted_member_is_read_and_still_alerted() {
    let db = builtin_db();
    let mut opts = ScanOptions::default();
    let benign = falsely_encrypted_zip(b"dex\n035\0 nothing to see here");
    assert!(matches!(
        analyze(&db, &benign, &opts).verdict,
        Verdict::Clean
    ));
    opts.alert_encrypted = true;
    match analyze(&db, &benign, &opts).verdict {
        Verdict::Infected { signature, .. } => assert_eq!(signature, "Heuristics.Encrypted.Zip"),
        other => panic!("expected Heuristics.Encrypted.Zip, got {other:?}"),
    }
    let infected = falsely_encrypted_zip(exav_core::unpack::eicar());
    match analyze(&db, &infected, &opts).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "{signature}"
        ),
        other => panic!("expected EICAR, got {other:?}"),
    }
}

/// ClamAV alerts on a ZIP member's local header, bit 0 set and bit 13 (headers
/// masked) clear, whatever the central directory says. APKs from the corpus
/// set the bit in the central directory only, or with bit 13, and ClamAV said
/// nothing of them.
#[test]
fn the_encryption_alert_follows_the_local_header() {
    let db = builtin_db();
    let mut opts = ScanOptions::default();
    opts.alert_encrypted = true;
    for (central, local, alerts) in [
        (0x0001, 0x0000, false),
        (0x0000, 0x0001, true),
        (0x0001, 0x0001, true),
        (0x0001, 0x2001, false),
        (0x2001, 0x0001, true),
        (0xff49, 0xff49, false),
    ] {
        let zip = flagged_zip(b"dex\n035\0 nothing to see here", central, local);
        let verdict = analyze(&db, &zip, &opts).verdict;
        let alerted = matches!(&verdict, Verdict::Infected { signature, .. }
            if signature == "Heuristics.Encrypted.Zip");
        assert_eq!(
            alerted, alerts,
            "central {central:#06x}, local {local:#06x}: {verdict:?}"
        );
    }
}

/// A `.cdb` signature's encryption field matches either of a ZIP member's
/// headers, as ClamAV matches each.
#[test]
fn a_cdb_encryption_field_matches_either_header() {
    let mut l = exav_core::loader::Builder::new();
    l.add_named_bytes(
        "t.cdb",
        b"Test.Cdb.Enc:CL_TYPE_ZIP:*:classes\\.dex:*:*:1:*:*:*\n\
          Test.Cdb.Plain:CL_TYPE_ZIP:*:classes\\.dex:*:*:0:*:*:*\n",
        true,
    );
    let db = l.build().unwrap();
    let opts = ScanOptions::default();
    for (central, local, want) in [
        (0x0000, 0x0000, &["Test.Cdb.Plain"][..]),
        (0x0001, 0x0001, &["Test.Cdb.Enc"]),
        (0x0001, 0x0000, &["Test.Cdb.Enc", "Test.Cdb.Plain"]),
        (0x0000, 0x0001, &["Test.Cdb.Enc", "Test.Cdb.Plain"]),
    ] {
        let zip = flagged_zip(b"dex\n035\0 nothing to see here", central, local);
        let mut got: Vec<String> = exav_core::analyze_all(&db, &zip, &opts)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        got.sort();
        assert_eq!(got, want, "central {central:#06x}, local {local:#06x}");
    }
}

#[test]
fn alert_encrypted_with_password_still_finds_payload() {
    // A real detection beats the heuristic: with the correct password the inner
    // EICAR is decrypted and FOUND, not reported as merely "encrypted".
    let db = builtin_db();
    let blob = fixture("zip_aes256_store.zip");
    let mut opts = ScanOptions::default();
    opts.alert_encrypted = true;
    opts.passwords = vec!["secret".to_string()];
    match analyze(&db, &blob, &opts).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.contains("EICAR") || signature.contains("Eicar"),
            "expected EICAR detection, got {signature}"
        ),
        other => panic!("expected EICAR Infected, got {other:?}"),
    }
}

#[test]
fn a_decrypted_7z_member_is_still_reported_as_encrypted() {
    // Decrypting with a pool password must not erase the fact that the member
    // was encrypted: under all-match both the payload and the heuristic are
    // reported, as they are for ZIP.
    let db = builtin_db();
    let blob = fixture("aes256_hdr.7z");
    let mut opts = ScanOptions::default();
    opts.alert_encrypted = true;
    opts.passwords = vec!["password".to_string()];
    let names: Vec<String> = exav_core::analyze_all(&db, &blob, &opts)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert!(
        names
            .iter()
            .any(|n| n.to_ascii_uppercase().contains("EICAR")),
        "{names:?}"
    );
    assert!(
        names.iter().any(|n| n == "Heuristics.Encrypted.7Zip"),
        "{names:?}"
    );
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
    let mut opts = ScanOptions::default();
    opts.alert_macros = true;
    match analyze(&db, &blob, &opts).verdict {
        Verdict::Infected {
            signature, method, ..
        } => {
            // ClamAV suffixes the macro dialect; the bare name matches no filter.
            assert_eq!(signature, "Heuristics.OLE2.ContainsMacros.VBA");
            assert_eq!(method, Method::Heuristic);
        }
        other => panic!("expected Heuristics.OLE2.ContainsMacros.VBA, got {other:?}"),
    }
}

// --- clamav-default heuristics: PDF ObfuscatedNameObject --------------------

/// A minimal PDF whose `/JavaScript` name object hex-escapes an alphanumeric
/// (`#61` = 'a') to hide the keyword — the exact trick ClamAV flags by default.
fn obfuscated_pdf() -> Vec<u8> {
    b"%PDF-1.5\n1 0 obj<</Type/Catalog/Open#41ction<</J#61vaScript(x)>>>>endobj\n%%EOF".to_vec()
}

#[test]
fn pdf_obfuscated_name_fires_by_default() {
    // On by default: this ClamAV-default heuristic is FP-safe, so exav out of the
    // box detects it (matching stock clamscan's default behavior).
    let db = builtin_db();
    let blob = obfuscated_pdf();
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.PDF.ObfuscatedNameObject");
        }
        other => panic!("expected Heuristics.PDF.ObfuscatedNameObject by default, got {other:?}"),
    }
}

#[test]
fn pdf_obfuscated_name_can_be_disabled() {
    // The parity subset is a distinct switch: clearing `clamav_heuristics` (with
    // the exclusive `heuristics` also off) turns the heuristic off for a raw scan.
    let db = builtin_db();
    let blob = obfuscated_pdf();
    let mut opts = ScanOptions::default();
    opts.clamav_heuristics = false;
    match analyze(&db, &blob, &opts).verdict {
        Verdict::Clean => {}
        other => panic!("expected Clean with clamav_heuristics off, got {other:?}"),
    }
}

#[test]
fn pdf_obfuscated_name_fires_under_clamav_heuristics() {
    // What `--clamav-compat` sets: the ClamAV-default heuristics on, exclusive
    // TLSH/ML off. The PDF obfuscation heuristic must fire to match stock clamscan.
    let db = builtin_db();
    let blob = obfuscated_pdf();
    let mut opts = ScanOptions::default();
    opts.clamav_heuristics = true;
    match analyze(&db, &blob, &opts).verdict {
        Verdict::Infected {
            signature, method, ..
        } => {
            assert_eq!(signature, "Heuristics.PDF.ObfuscatedNameObject");
            assert_eq!(method, Method::Heuristic);
        }
        other => panic!("expected Heuristics.PDF.ObfuscatedNameObject, got {other:?}"),
    }
}

#[test]
fn pdf_obfuscated_name_fires_under_full_heuristics() {
    // `--detect exav-heuristics` is the superset, so it includes the ClamAV-default subset.
    let db = builtin_db();
    let blob = obfuscated_pdf();
    let mut opts = ScanOptions::default();
    opts.heuristics = true;
    opts.clamav_heuristics = true;
    match analyze(&db, &blob, &opts).verdict {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.PDF.ObfuscatedNameObject");
        }
        other => panic!("expected Heuristics.PDF.ObfuscatedNameObject, got {other:?}"),
    }
}
