//! End-to-end: password-supplied scanning of encrypted archives through the
//! full exav-core `analyze` path.
//!
//! Fixtures each hold a single member, `eicar.txt` (the exact EICAR test
//! string), encrypted with password `secret` (ZIP) / `password` (7z):
//!
//! * `zip_aes256_store.zip`: WinZip AES-256
//! * `zip_zipcrypto_store.zip`: legacy PKWARE ZipCrypto
//! * `aes256_hdr.7z`: header-encrypted 7z (`-mhe=on`)
//!
//! With the password the inner EICAR is FOUND (`Infected`); without it the scan
//! is `PasswordProtected`, never `Clean`, never `Infected`.

use exav_core::{ScanOptions, Verdict, analyze, loader};
use exav_unpack::zip_write::{FileOptions, Method, ZipWriter};

fn builtin_db() -> exav_core::Scanner {
    // The built-in DB carries the EICAR signature, which is all we need.
    exav_core::Scanner::builtin()
}

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn with_pw(pw: &str) -> ScanOptions {
    let mut o = ScanOptions::default();
    o.passwords = vec![pw.to_string()];
    o
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
fn sevenz_encrypted_header_decrypts_and_finds_eicar() {
    let db = builtin_db();
    let blob = fixture("aes256_hdr.7z");
    // With the password, the AES-encrypted header (`-mhe=on`) and the data are
    // decrypted, so the inner EICAR is found.
    match analyze(&db, &blob, &with_pw("password")).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("expected Infected with password, got {other:?}"),
    }
    // Without the password: PasswordProtected, never Clean, never Infected.
    for opts in [ScanOptions::default(), with_pw("wrong")] {
        match analyze(&db, &blob, &opts).verdict {
            Verdict::PasswordProtected { .. } => {}
            other => panic!("expected PasswordProtected without password, got {other:?}"),
        }
    }
}

/// `aes_copy_eicar.7z` (exav-unpack's fixtures; password `hunter2`; three
/// folders of one file each, AES and then Copy, one of them the EICAR string),
/// with the CRCs of its files taken out of the header, which is not
/// compressed, and the checksums of the headers made right again.
fn sevenz_without_crcs() -> Vec<u8> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-unpack/tests/fixtures/7z/aes_copy_eicar.7z"
    );
    let blob = exav_core::unpack::read_fixture(p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let crc = |d: &[u8]| {
        let mut c = flate2::Crc::new();
        c.update(d);
        c.sum()
    };
    let u64_at = |at: usize| u64::from_le_bytes(blob[at..at + 8].try_into().unwrap()) as usize;
    let (header_at, size) = (32 + u64_at(12), u64_at(20));
    let header = &blob[header_at..header_at + size];
    // The digests of the substreams: property 0x0A, all defined, one CRC for
    // each of the three folders.
    let at = header
        .windows(2)
        .rposition(|w| w == [0x0A, 0x01])
        .expect("the digests are in the header");
    assert_eq!(header[at + 2 + 12..at + 2 + 14], [0, 0], "three CRCs");
    let mut new = header[..at].to_vec();
    new.extend_from_slice(&[0x0A, 0x00, 0x00]);
    new.extend_from_slice(&header[at + 2 + 12..]);
    let mut out = blob[..header_at].to_vec();
    out[20..28].copy_from_slice(&(new.len() as u64).to_le_bytes());
    out[28..32].copy_from_slice(&crc(&new).to_le_bytes());
    let start = crc(&out[12..32]);
    out[8..12].copy_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&new);
    out
}

/// With no CRC in the header nothing confirms the password, and with a stored
/// coder under the cipher a wrong one decodes as well as the right one: what
/// it gives is garbage. The folders are read with the first password that
/// decodes them and the archive is PasswordProtected, unless something is
/// found in what they decode to.
#[test]
fn a_7z_without_crcs_is_password_protected_unless_something_is_found() {
    let db = builtin_db();
    let eicar = |blob: &[u8], opts: &ScanOptions| {
        matches!(&analyze(&db, blob, opts).verdict, Verdict::Infected { signature, .. }
            if signature.to_ascii_uppercase().contains("EICAR"))
    };
    let password_protected = |blob: &[u8], opts: &ScanOptions| {
        matches!(
            analyze(&db, blob, opts).verdict,
            Verdict::PasswordProtected { .. }
        )
    };
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-unpack/tests/fixtures/7z/aes_copy_eicar.7z"
    );
    let with_crcs = exav_core::unpack::read_fixture(p).unwrap();
    // As 7-Zip wrote it, the CRCs tell the password: found with the right
    // one, refused with a wrong one.
    assert!(eicar(&with_crcs, &with_pw("hunter2")));
    assert!(password_protected(&with_crcs, &with_pw("nope")));

    let blob = sevenz_without_crcs();
    // The right password still finds what is there.
    assert!(eicar(&blob, &with_pw("hunter2")));
    // A wrong one decodes to garbage, in which nothing is found.
    assert!(password_protected(&blob, &with_pw("nope")));
    assert!(password_protected(&blob, &ScanOptions::default()));
}

/// The `.pwdb` pool (loaded into the database) also supplies decryption
/// passwords, unioned with `ScanOptions::passwords`.
#[test]
fn pwdb_pool_supplies_decryption_password() {
    let dir = crate::tmpfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("p.pwdb"),
        "Sig;Engine:81-255,Target:0;0;secret\n",
    )
    .unwrap();
    // Built-in EICAR isn't loaded from a dir, so add a throwaway ndb to build a DB
    // that still carries the default EICAR pattern.
    std::fs::write(dir.path().join("a.ndb"), "Demo.X:0:*:6e6f7065\n").unwrap();
    let db = loader::load(dir.path()).unwrap();
    assert_eq!(db.passwords(), &["secret".to_string()][..]);

    let blob = fixture("zip_aes256_store.zip");
    // No runtime password, only the `.pwdb` pool: it still decrypts and detects.
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("expected Infected from .pwdb pool, got {other:?}"),
    }
}

/// An encrypted archive among the members of another is reported as
/// password-protected once the other members are scanned, whatever their
/// order; the password reaches it.
#[test]
fn an_encrypted_archive_inside_an_archive_is_password_protected() {
    use std::io::Write;

    let db = builtin_db();
    let inner = fixture("zip_aes256_store.zip");
    for encrypted_first in [true, false] {
        let mut z = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let stored = FileOptions::default().method(Method::Stored);
        let mut members: Vec<(&str, &[u8])> =
            vec![("inner.zip", &inner[..]), ("note.txt", b"nothing to see")];
        if !encrypted_first {
            members.reverse();
        }
        for (name, data) in members {
            z.start_file(name, stored).unwrap();
            z.write_all(data).unwrap();
        }
        let outer = z.finish().unwrap().into_inner();
        match analyze(&db, &outer, &ScanOptions::default()).verdict {
            Verdict::PasswordProtected { .. } => {}
            other => panic!("first {encrypted_first}: expected PasswordProtected, got {other:?}"),
        }
        match analyze(&db, &outer, &with_pw("secret")).verdict {
            Verdict::Infected { .. } => {}
            other => panic!("first {encrypted_first}: expected Infected, got {other:?}"),
        }
    }
}

/// A picture with an encrypted ZIP appended opens as that ZIP in the usual
/// archive tools, so it is reported like the ZIP would be.
#[test]
fn an_encrypted_zip_appended_to_a_picture_is_reported() {
    let db = builtin_db();
    let zip = fixture("zip_aes256_store.zip");
    let mut jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00".to_vec();
    jpeg.resize(4096, 0x42);
    jpeg.extend_from_slice(b"\xff\xd9");
    let polyglot = [&jpeg[..], &zip[..]].concat();

    match analyze(&db, &polyglot, &ScanOptions::default()).verdict {
        Verdict::PasswordProtected { .. } => {}
        other => panic!("expected PasswordProtected, got {other:?}"),
    }
    match analyze(&db, &polyglot, &with_pw("secret")).verdict {
        Verdict::Infected { .. } => {}
        other => panic!("expected Infected with the password, got {other:?}"),
    }

    // Without its central directory the local header alone does not prove an
    // archive is there: a chance `PK\x03\x04` looks the same.
    let cd = zip.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
    let headless = [&jpeg[..], &zip[..cd]].concat();
    assert_eq!(
        analyze(&db, &headless, &ScanOptions::default()).verdict,
        Verdict::Clean
    );
}

/// A walk that stops at a limit after an encrypted member still reports it:
/// password protection over a limit, as a container's reasons fold.
#[test]
fn an_encrypted_member_before_a_limit_is_password_protected() {
    use std::io::Write;
    let stored = FileOptions::default().method(Method::Stored);
    let mut z = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file("locked.zip", stored).unwrap();
    z.write_all(&fixture("zip_aes256_store.zip")).unwrap();
    for i in 0..40 {
        z.start_file(&format!("f{i}.txt"), stored).unwrap();
        z.write_all(b"padding\n").unwrap();
    }
    let blob = z.finish().unwrap().into_inner();
    let mut opts = ScanOptions::default();
    opts.limits.max_members = 4;
    match analyze(&builtin_db(), &blob, &opts).verdict {
        Verdict::PasswordProtected { .. } => {}
        other => panic!("expected PasswordProtected, got {other:?}"),
    }
    // Under `--alert-exceeds-max` the limit is a detection, which wins.
    opts.alert_exceeds_max = true;
    match analyze(&builtin_db(), &blob, &opts).verdict {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.Limits.Exceeded.MaxFiles")
        }
        other => panic!("expected the MaxFiles alert, got {other:?}"),
    }
}

/// A RAR archive of a member whose dictionary is over the object limit and a
/// member encrypted after it: the reader notes the limit on the first and goes
/// on, so the walk completes. The limit is a detection when reported as found, and wins over
/// password protection as a detection does, in the default scan and in
/// `--all-matches`.
#[test]
fn a_limit_noted_on_a_member_beats_an_encrypted_one_when_reported_as_found() {
    let blob = fixture("rar_locked_and_over_limit.rar");
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 4096;
    match analyze(&builtin_db(), &blob, &opts).verdict {
        Verdict::PasswordProtected { .. } => {}
        other => panic!("expected PasswordProtected, got {other:?}"),
    }
    opts.alert_exceeds_max = true;
    match analyze(&builtin_db(), &blob, &opts).verdict {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.Limits.Exceeded.MaxFileSize")
        }
        other => panic!("expected the MaxFileSize alert, got {other:?}"),
    }
    let (names, outcome) = exav_core::analyze_all_with_outcome(&builtin_db(), &blob, &opts);
    assert_eq!(
        names.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
        ["Heuristics.Limits.Exceeded.MaxFileSize"],
        "{outcome:?}"
    );
}

/// The same limit noted on a first member, and the walk stopped by a header
/// that does not parse after it (made with `rar` 7.23, then the second file
/// header's CRC changed): reported as found, the limit is a detection and wins
/// over the damage, as a signature found before it would.
#[test]
fn a_limit_noted_on_a_member_beats_a_later_stop_at_damage_when_reported_as_found() {
    let blob = fixture("rar_over_limit_then_damaged.rar");
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 4096;
    match analyze(&builtin_db(), &blob, &opts).verdict {
        Verdict::Unscannable { .. } => {}
        other => panic!("expected Unscannable, got {other:?}"),
    }
    opts.alert_exceeds_max = true;
    match analyze(&builtin_db(), &blob, &opts).verdict {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.Limits.Exceeded.MaxFileSize")
        }
        other => panic!("expected the MaxFileSize alert, got {other:?}"),
    }
}
