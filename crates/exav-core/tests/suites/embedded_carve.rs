//! A container (ZIP here) appended to a carrier — a PE overlay / SFX stub /
//! dropper — must be carved and scanned. The normal scan only types offset 0, so
//! without embedded-archive carving the payload in the overlay is invisible.

use exav_core::{analyze, ScanOptions, Scanner, Verdict};

#[test]
fn appended_overlay_zip_is_carved_and_scanned() {
    let db = Scanner::builtin();
    let blob = exav_core::unpack::read_fixture(&format!(
        "{}/tests/fixtures/pe_overlay_zip.bin",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("EICAR in an appended-overlay ZIP must be found, got {other:?}"),
    }
}
