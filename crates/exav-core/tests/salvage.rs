//! A truncated / corrupt compressed member must still have its RECOVERABLE
//! prefix scanned — malware in the part that did decode is caught, never hidden
//! by the decode error on the missing tail. (Regression: exav previously marked
//! the whole member Unscannable and discarded the salvageable bytes, so EICAR in
//! a truncated gzip went undetected while `zcat` recovered it fine.)

use std::io::Write;

use exav_core::{analyze, Database, ScanOptions, Verdict};

const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

fn gzip(payload: &[u8], level: flate2::Compression) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), level);
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

#[test]
fn truncated_gzip_still_scans_recoverable_content() {
    let db = Database::builtin();
    // EICAR up front, then a large filler tail. Stored (uncompressed) DEFLATE so
    // compressed offsets track payload offsets — cutting the tail predictably
    // removes only filler, leaving EICAR before the cut and recoverable.
    let mut payload = EICAR.to_vec();
    payload.extend(vec![b'B'; 16384]);
    let full = gzip(&payload, flate2::Compression::none());
    // Drop the trailer + a chunk of the tail: an "unexpected end of file" decode
    // error, but EICAR is far before the cut and still decodes.
    let truncated = &full[..full.len() - 2048];

    match analyze(&db, truncated, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("EICAR in a truncated gzip must still be FOUND, got {other:?}"),
    }
}

#[test]
fn truncated_gzip_without_malware_is_clean_not_flagged() {
    // exav scans for malware, it is not a file-integrity validator: a truncated
    // stream we fully recovered and found nothing in is CLEAN, not "not fully
    // scanned". The missing tail is absent, not hidden.
    let db = Database::builtin();
    let mut payload = b"nothing malicious here, just filler ".to_vec();
    payload.extend(vec![b'B'; 16384]);
    let full = gzip(&payload, flate2::Compression::none());
    let truncated = &full[..full.len() - 2048];
    match analyze(&db, truncated, &ScanOptions::default()).verdict {
        Verdict::Clean { .. } => {}
        other => panic!("truncated-but-clean gzip should be Clean, got {other:?}"),
    }
}

#[test]
fn intact_gzip_still_works() {
    // Sanity: the salvage path doesn't regress the normal (untruncated) case.
    let db = Database::builtin();
    let mut payload = vec![b'x'; 100];
    payload.extend_from_slice(EICAR);
    let blob = gzip(&payload, flate2::Compression::default());
    matches!(
        analyze(&db, &blob, &ScanOptions::default()).verdict,
        Verdict::Infected { .. }
    )
    .then_some(())
    .expect("intact gzip with EICAR must be Infected");
}
