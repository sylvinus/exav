//! ZIP dual indexing, at the verdict level.
//!
//! A ZIP carries two indexes: the central directory at the end, and a local file
//! header in front of every member. Readers use the central directory, so a
//! member left out of it is invisible to them while the extractor on the target
//! machine still unpacks it. exav therefore scans the raw bytes for local headers
//! the central directory doesn't cover.
//!
//! The verdict is the point. Finding the orphan and scanning it must yield
//! `Infected`; failing to *decode* one must yield `Unscannable`, never `Clean` —
//! a member exav could not read is content it did not examine, and reporting the
//! containing file clean on that basis is exactly the silent-clean bug.

use exav_core::{analyze, ScanOptions, Scanner, Verdict};

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

/// A bare local file header plus payload — no central directory, so every member
/// is reached through the orphan scan.
fn lfh(name: &str, method: u16, flags: u16, payload: &[u8], declared_comp: Option<u32>) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"PK\x03\x04");
    v.extend_from_slice(&20u16.to_le_bytes());
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&method.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&declared_comp.unwrap_or(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(&(name.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(payload);
    v
}

#[test]
fn orphan_member_carrying_eicar_is_found() {
    let db = Scanner::builtin();
    let blob = lfh("hidden.txt", 0, 0, eicar(), None);
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("EICAR hidden in an orphan local header must be FOUND, got {other:?}"),
    }
}

#[test]
fn undecodable_orphan_member_is_not_clean() {
    // Method 9 (Deflate64) is a real ZIP method exav has no decoder for. The
    // member is present and the target would extract it; exav cannot read it, so
    // the honest answer is "not fully scanned".
    let db = Scanner::builtin();
    let blob = lfh(
        "packed.bin",
        9,
        0,
        b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8",
        None,
    );
    assert!(
        !matches!(
            analyze(&db, &blob, &ScanOptions::default()).verdict,
            Verdict::Clean
        ),
        "an orphan member exav could not decode must never be reported Clean"
    );
}

#[test]
fn encrypted_orphan_member_is_not_clean() {
    let db = Scanner::builtin();
    let blob = lfh(
        "secret.bin",
        0,
        0x0001,
        b"\x11\x22\x33\x44opaque-bytes",
        None,
    );
    assert!(
        !matches!(
            analyze(&db, &blob, &ScanOptions::default()).verdict,
            Verdict::Clean
        ),
        "an encrypted orphan member must never be reported Clean"
    );
}

#[test]
fn a_truncated_archive_is_clean_not_flagged() {
    // The header declares far more data than the file holds. Those bytes are
    // ABSENT from the file, not hidden in it — the victim's extractor gets
    // nothing either, so there is no evasion to catch, and every byte that does
    // exist was scanned. exav scans for malware, it is not a file-integrity
    // validator (docs/QUIRKS.md).
    let db = Scanner::builtin();
    let blob = lfh("cut.bin", 0, 0, b"only-a-few-bytes", Some(50_000));
    assert!(
        matches!(
            analyze(&db, &blob, &ScanOptions::default()).verdict,
            Verdict::Clean
        ),
        "a merely truncated archive should be Clean"
    );
}

#[test]
fn ordinary_file_with_chance_pk34_stays_clean() {
    // The counterweight: `PK\x03\x04` occurs by chance in ordinary binaries, and
    // treating a chance hit as an unreadable member would make clean files
    // spuriously not-clean. Only structurally credible headers count.
    let db = Scanner::builtin();
    let mut blob: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    blob[100..104].copy_from_slice(b"PK\x03\x04");
    blob[106..108].copy_from_slice(&0x0080u16.to_le_bytes()); // reserved flag bit set
    blob[108..110].copy_from_slice(&0x5555u16.to_le_bytes()); // not a real method
    blob[2000..2004].copy_from_slice(b"PK\x03\x04");
    blob[2026..2028].copy_from_slice(&0u16.to_le_bytes()); // zero-length name
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Clean => {}
        other => panic!("chance PK\\x03\\x04 bytes must not affect the verdict, got {other:?}"),
    }
}

#[test]
fn damaged_jar_with_hundreds_of_orphans_is_fully_scanned() {
    // The shape this was found on: a real JAR whose End Of Central Directory
    // record is gone, so no reader can enumerate it — 400+ members reachable
    // only as local headers. A few hundred members is ordinary for a JAR, so
    // capping the orphan scan below that would silently leave most of the
    // archive unscanned. EICAR sits in the 300th member, past any small cap.
    let db = Scanner::builtin();
    let mut blob = Vec::new();
    for i in 0..400 {
        let payload: &[u8] = if i == 300 {
            eicar()
        } else {
            b"harmless filler"
        };
        blob.extend_from_slice(&lfh(&format!("pkg/cls{i}.class"), 0, 0, payload, None));
    }
    // No central directory and no EOCD at all, exactly as observed.
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("EICAR in the 300th orphan member must be FOUND, got {other:?}"),
    }
}
