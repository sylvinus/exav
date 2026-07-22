//! Heuristic alert names must match ClamAV's **exactly**.
//!
//! A heuristic reaches a client as an ordinary `FOUND` whose *name* carries all
//! the information — there is no separate channel. Gateways that treat
//! heuristics differently (tag rather than block, lower score) do it by matching
//! the string. So a name that is one suffix off is not cosmetic: it is a policy
//! rule that silently stops firing after a migration.
//!
//! Two names were wrong and are pinned here:
//!
//! * `Heuristics.OLE2.ContainsMacros` — ClamAV suffixes the macro dialect,
//!   `.VBA` or `.XLM`. exav emitted the bare name, matching neither.
//! * `Heuristics.Phishing.Email.Cloaked.IP` — ClamAV calls it
//!   `Cloaked.NumericIP`.
//!
//! Both were found by enumerating ClamAV's emitted names rather than by reading
//! exav, which is the only way this class of bug shows up.

use exav_core::{analyze, loader, ScanOptions, Scanner, Verdict};
use std::io::Write;

fn empty_db() -> Scanner {
    let mut l = loader::Builder::new();
    // A signature that cannot match, so any detection is the heuristic's.
    l.add_named_bytes("t.ndb", b"Zzz.Never:0:*:deadbeefdeadbeef\n", true);
    l.build().expect("build database")
}

fn detection(db: &Scanner, blob: &[u8], opts: &ScanOptions) -> Option<String> {
    match analyze(db, blob, opts).verdict {
        Verdict::Infected { signature, .. } => Some(signature),
        _ => None,
    }
}

/// A minimal valid OLE2 document carrying a VBA project — the same construction
/// `heuristic_alerts.rs` uses, so the fixture is known to reach the extractor.
/// A hand-rolled OLE2 with a plain-text module stream does NOT: exav's extractor
/// needs a real MS-OVBA compressed container, and a fixture that silently fails
/// to fire turns every assertion after it into a no-op.
fn ole_with_vba() -> Vec<u8> {
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
fn macro_alert_carries_the_dialect_suffix() {
    let db = empty_db();
    let doc = ole_with_vba();

    let opts = ScanOptions {
        alert_macros: true,
        ..ScanOptions::default()
    };
    // The fixture MUST fire, or the assertions below are vacuous — which is the
    // failure mode this whole file exists to prevent.
    let name = detection(&db, &doc, &opts)
        .expect("fixture did not trigger the macro heuristic; the test would prove nothing");
    assert!(
        name == "Heuristics.OLE2.ContainsMacros.VBA"
            || name == "Heuristics.OLE2.ContainsMacros.XLM",
        "macro alert must carry ClamAV's dialect suffix (.VBA/.XLM); got {name}"
    );
}

#[test]
fn macro_alert_is_off_unless_asked() {
    // Every ClamAV heuristic in this family is opt-in. Firing by default would
    // flag every macro-bearing office document in an organisation.
    let db = empty_db();
    let doc = ole_with_vba();
    let got = detection(&db, &doc, &ScanOptions::default());
    assert!(
        !got.as_deref().unwrap_or("").contains("ContainsMacros"),
        "macro alert must not fire without --alert-macros; got {got:?}"
    );
}

#[test]
#[cfg(feature = "phishing")]
fn cloaked_ip_uses_clamavs_numericip_name() {
    let db = empty_db();
    // Visible text names a brand; the href points at a bare IP literal.
    let page = b"<html><body>\
        <a href=\"http://192.0.2.44/login\">https://www.example-bank.com/login</a>\
        </body></html>";

    let opts = ScanOptions {
        alert_phishing: true,
        ..ScanOptions::default()
    };
    let name = detection(&db, page, &opts)
        .expect("fixture did not trigger the phishing heuristic; the test would prove nothing");
    assert!(
        name.starts_with("Heuristics.Phishing.Email."),
        "unexpected phishing name {name}"
    );
    assert!(
        !name.ends_with("Cloaked.IP"),
        "ClamAV's name is `Cloaked.NumericIP`; `Cloaked.IP` matches no gateway filter"
    );
}

/// The names exav emits that ClamAV does not. These are *additions*, not
/// mismatches — they cannot cause a missed detection, only an extra one — but
/// they must stay deliberate rather than drift in unnoticed.
#[test]
fn exav_only_names_are_the_ones_we_expect() {
    // `Heuristics.Encrypted.Doc` was on this list and did not belong: it is a
    // MISMATCH, not an addition. For an encrypted OLE2 document ClamAV emits
    // `Heuristics.Encrypted.OLE2` — observed 468 times against 0 for `.Doc`
    // across a corpus run — so exav's name matched no gateway filter while
    // looking, on this list, like a deliberate extra. The trap is that ClamAV's
    // config option IS called `AlertEncryptedDoc`; the option name and the
    // signature name differ, and only the signature name is on the wire.
    //
    // A name belongs here only when ClamAV emits NOTHING for that condition.
    // When both engines report the same finding, the strings have to match.
    const EXAV_ONLY: &[&str] = &[
        "Heuristics.Encrypted.Archive",
        "Heuristics.Authenticode.HashMismatch",
        "Heuristics.PE.PackedWithInjectionImports",
        "Heuristics.Static.Suspect",
    ];
    // Pinned as documentation: if a name is added here, it belongs in the
    // comparison page's heuristics table too.
    assert_eq!(EXAV_ONLY.len(), 4);
}

/// An encrypted Office document must be reported under ClamAV's own name.
///
/// The document below is an OLE2 container carrying the MS-OFFCRYPTO stream pair
/// (`EncryptionInfo` and `EncryptedPackage`) with content that cannot be
/// decrypted, which is what a real password-protected `.docx`/`.xlsx` looks like
/// without the password. The extractor surfaces it as an encrypted, undecodable
/// member, and `--alert-encrypted` turns that into a detection.
///
/// The name has to be exact: a gateway filtering on ClamAV's string matches on
/// that string and nothing else. Verified against the oracle — over one corpus
/// run clamd emitted `Heuristics.Encrypted.OLE2` 468 times and
/// `Heuristics.Encrypted.Doc` never.
#[test]
fn an_encrypted_office_document_uses_clamavs_signature_name() {
    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let mut cf = cfb::CompoundFile::create(cursor).expect("create OLE2");
    {
        // Version 4 agile header, then bytes that are not a valid descriptor —
        // enough to be recognised as MS-OFFCRYPTO, not enough to decrypt.
        let mut s = cf.create_stream("/EncryptionInfo").expect("EncryptionInfo");
        s.write_all(&[0x04, 0x00, 0x04, 0x00]).unwrap();
        s.write_all(&[0x40, 0x00, 0x00, 0x00]).unwrap();
        s.write_all(&[0xab; 64]).unwrap();
        s.flush().unwrap();
    }
    {
        let mut s = cf
            .create_stream("/EncryptedPackage")
            .expect("EncryptedPackage");
        s.write_all(&(4096u64).to_le_bytes()).unwrap();
        s.write_all(&[0xcd; 4096]).unwrap();
        s.flush().unwrap();
    }
    cf.flush().expect("flush");
    let doc = cf.into_inner().into_inner();

    let db = empty_db();
    let opts = ScanOptions {
        alert_encrypted: true,
        ..ScanOptions::default()
    };
    let name = detection(&db, &doc, &opts).expect(
        "the encrypted-Office fixture did not trigger the heuristic at all; \
         the assertion below would prove nothing",
    );
    assert_eq!(
        name, "Heuristics.Encrypted.OLE2",
        "ClamAV emits `Heuristics.Encrypted.OLE2` for an encrypted OLE2 document. \
         Note its CONFIG OPTION is `AlertEncryptedDoc` — the option name and the \
         signature name differ, and only the signature name reaches a gateway."
    );
}

/// The one phishing shape where the domains agree and only the transport lies:
/// the visible text promises `https://`, the `href` is plain `http://`.
#[test]
#[cfg(feature = "phishing")]
fn ssl_spoof_uses_clamavs_hyphenated_name() {
    let db = empty_db();
    let page = b"<html><body>\
        <a href=\"http://www.example-bank.com/login\">https://www.example-bank.com/login</a>\
        </body></html>";
    let opts = ScanOptions {
        alert_phishing: true,
        ..ScanOptions::default()
    };
    let name =
        detection(&db, page, &opts).expect("an https display over an http href must be reported");
    assert_eq!(
        name, "Heuristics.Phishing.Email.SSL-Spoof",
        "ClamAV hyphenates this one; `SSLSpoof` or `Ssl.Spoof` match no filter"
    );
}

/// The same link with matching schemes is ordinary and must stay silent.
#[test]
#[cfg(feature = "phishing")]
fn matching_schemes_are_not_a_spoof() {
    let db = empty_db();
    for page in [
        &b"<a href=\"https://www.example-bank.com/x\">https://www.example-bank.com/x</a>"[..],
        &b"<a href=\"http://www.example-bank.com/x\">http://www.example-bank.com/x</a>"[..],
    ] {
        let opts = ScanOptions {
            alert_phishing: true,
            ..ScanOptions::default()
        };
        assert_eq!(
            detection(&db, page, &opts),
            None,
            "a link whose display and href agree is not a spoof"
        );
    }
}

// ------------------------------------------------------- Broken.Executable

/// A file carrying an executable magic whose headers do not hold together. The
/// signal is the *contradiction* — which is why an arbitrary binary blob must
/// never qualify.
#[test]
fn broken_executable_needs_a_broken_executable() {
    let db = empty_db();
    let opts = ScanOptions {
        alert_broken: true,
        ..ScanOptions::default()
    };

    // Claims a PE header at 0x3c, but there is nothing parseable there.
    let mut broken = b"MZ".to_vec();
    broken.resize(0x3c, 0);
    broken.extend_from_slice(&0x80u32.to_le_bytes());
    broken.resize(0x80, 0);
    broken.extend_from_slice(b"PE\0\0");
    broken.extend_from_slice(&[0xff; 32]); // garbage COFF header
    assert_eq!(
        detection(&db, &broken, &opts).as_deref(),
        Some("Heuristics.Broken.Executable"),
        "a PE whose headers do not parse must be reported under --alert-broken"
    );

    // Same file, flag off.
    assert_eq!(
        detection(&db, &broken, &ScanOptions::default()),
        None,
        "the alert is opt-in, like ClamAV's"
    );
}

#[test]
fn ordinary_files_are_not_broken_executables() {
    let db = empty_db();
    let opts = ScanOptions {
        alert_broken: true,
        ..ScanOptions::default()
    };
    for (what, blob) in [
        ("plain text", &b"hello, this is an ordinary text file\n"[..]),
        ("random binary", &[0x00, 0x01, 0x02, 0x03, 0xff, 0xfe][..]),
        // A bare DOS stub with no PE header is old, not broken.
        (
            "MZ with no PE header",
            &b"MZ\x90\x00\x03\x00\x00\x00 dos stub only"[..],
        ),
    ] {
        assert_eq!(
            detection(&db, blob, &opts),
            None,
            "{what} must not be reported as a broken executable"
        );
    }
}

/// A JPEG whose APPn segments are ordered the way Office and Adobe write them
/// must not be reported as broken media.
///
/// JPEG permits APPn markers in any order. Requiring Exif at segment index <= 2
/// flagged every `docProps/thumbnail.jpeg` and every Photoshop export, because
/// both interleave an ICC profile or a Photoshop resource block first. clamd,
/// which has the same machinery, emits these names zero times over 8,978 samples
/// while emitting other Broken.Media names 29 times.
#[test]
fn office_and_adobe_jpeg_marker_order_is_not_broken_media() {
    fn seg(marker: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, marker];
        v.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(body);
        v
    }
    // APP0 JFIF -> APP2 ICC_PROFILE -> APP1 Exif: Exif at index 3, as Word writes it.
    let mut jpg = vec![0xFF, 0xD8];
    jpg.extend(seg(0xE0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0"));
    jpg.extend(seg(0xE2, b"ICC_PROFILE\0\x01\x01padding-padding"));
    jpg.extend(seg(0xE1, b"Exif\0\0MM\0\x2a\0\0\0\x08\0\0"));
    jpg.extend(seg(0xC0, &[0x08, 0, 16, 0, 16, 1, 1, 0x11, 0]));
    jpg.extend_from_slice(&[0xFF, 0xD9]);

    let opts = ScanOptions {
        alert_broken_media: true,
        ..ScanOptions::default()
    };
    assert_eq!(
        detection(&empty_db(), &jpg, &opts),
        None,
        "a marker order the format allows is not evidence of tampering"
    );
}

// --- subsignature modifiers -------------------------------------------------

/// `::f` (fullword) must bound the match with non-alphanumeric bytes.
///
/// Dropping the modifier is not a milder version of honouring it: the
/// subsignature then matches as a plain substring, so the signature fires on
/// strictly more than its author asked for. 44 signatures in daily.ldb use `::f`,
/// which made this a systematic false-positive source rather than one bad match.
#[test]
fn a_fullword_subsignature_does_not_match_inside_a_longer_word() {
    fn db_with(sig: &str) -> Scanner {
        let mut l = loader::Builder::new();
        l.add_named_bytes("t.ldb", sig.as_bytes(), true);
        l.build().expect("build database")
    }
    // Target 0 (any), one subsig, expression "0".
    let db = db_with("Test.Fullword;Engine:51-255,Target:0;0;6d61726b6572776f7264::f\n");
    let opts = ScanOptions::default();

    assert_eq!(
        detection(&db, b"xxxmarkerwordyyy", &opts),
        None,
        "glued to letters on both sides, so not a whole word"
    );
    assert_eq!(
        detection(&db, b"xxxmarkerword", &opts),
        None,
        "a word boundary is needed on BOTH sides, not just the trailing one"
    );
    assert_eq!(
        detection(&db, b"markerword9", &opts),
        None,
        "digits are word bytes too"
    );
    assert_eq!(
        detection(&db, b"the markerword here", &opts).as_deref(),
        Some("Test.Fullword"),
        "bounded by spaces: this is exactly what the signature asks for"
    );
    assert_eq!(
        detection(&db, b"markerword", &opts).as_deref(),
        Some("Test.Fullword"),
        "the edges of the buffer are boundaries"
    );
}

/// A stripped ELF section-header table is reported in BOTH modes; only the name
/// changes.
///
/// exav does not consider these broken — section headers are optional for
/// execution and the binaries run — but no toolchain zeroes the entry size, so
/// the fact is worth reporting under a name that says what it is. ClamAV files it
/// under `Heuristics.Broken.Executable`, and a gateway filtering on that exact
/// string has to keep matching under `--clamav-compat`.
///
/// The point of the pair below: compat changes VOCABULARY, never coverage.
#[test]
fn a_stripped_elf_section_table_is_reported_in_both_modes() {
    // Minimal 64-bit little-endian ELF header with e_shentsize (offset 58) zeroed.
    let mut elf = vec![0u8; 64];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // 64-bit
    elf[5] = 1; // little-endian
    elf[6] = 1; // version
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = EXEC
    elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes()); // x86-64
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf[58..60].copy_from_slice(&0u16.to_le_bytes()); // e_shentsize: STRIPPED

    let base = ScanOptions {
        alert_broken: true,
        ..ScanOptions::default()
    };
    assert_eq!(
        detection(&empty_db(), &elf, &base).as_deref(),
        Some("Heuristics.ELF.StrippedSectionHeaders"),
        "exav names what it actually found"
    );

    let compat = ScanOptions {
        alert_broken: true,
        clamav_compat: true,
        ..ScanOptions::default()
    };
    assert_eq!(
        detection(&empty_db(), &elf, &compat).as_deref(),
        Some("Heuristics.Broken.Executable"),
        "under compat the same finding carries ClamAV's name"
    );

    // A canonical entry size is ordinary and must stay silent in both modes.
    let mut ok = elf.clone();
    ok[58..60].copy_from_slice(&64u16.to_le_bytes());
    assert_eq!(detection(&empty_db(), &ok, &base), None);
    assert_eq!(detection(&empty_db(), &ok, &compat), None);
}

/// `::f` must survive a database round-trip.
///
/// The daemon and any production deployment load a PREBUILT `.exavdb`, not the
/// raw signature text. A modifier that is honoured when parsing but lost when
/// serialised would work in every unit test and silently stop working in the
/// only configuration that ships.
#[test]
fn fullword_survives_the_prebuilt_database() {
    let sig = "Test.FullwordRt;Engine:51-255,Target:0;0;6d61726b6572776f7264::f\n";
    let mut l = loader::Builder::new();
    l.add_named_bytes("t.ldb", sig.as_bytes(), true);
    let db = l.build().expect("build database");

    let dir = crate::tmpfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("rt.exavdb");
    exav_core::database::save(&db, &path).expect("write prebuilt database");
    let loaded = exav_core::database::load(&path).expect("load prebuilt database");

    let opts = ScanOptions::default();
    assert_eq!(
        detection(&loaded, b"xxxmarkerwordyyy", &opts),
        None,
        "fullword was lost in the database round-trip: the substring matched"
    );
    assert_eq!(
        detection(&loaded, b"the markerword here", &opts).as_deref(),
        Some("Test.FullwordRt"),
        "the genuine whole-word match must still fire after a round-trip"
    );
}
