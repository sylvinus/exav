//! Regression: `.cdb` container-metadata signatures that match on a member's
//! FILENAME (e.g. ClamAV's `Archive.Filetype.DualExtJS`, which flags a
//! double-extension `*.pdf.js` inside a ZIP) must fire on the STREAMED container
//! path — the path ZIP/OOXML actually take via the daemon and CLI. This path had
//! no CDB matching, so these detections were silently missed. It also exercises
//! the 1-based `FilePos` semantics (ClamAV counts members from 1).

use exav_core::{loader, scan_seekable, ScanOptions, Verdict};
use std::io::Cursor;

fn db_with_dualext() -> exav_core::Scanner {
    // The real daily.cvd sig (double-extension JS inside a ZIP, FilePos:1).
    let cdb = r"Archive.Filetype.DualExtJS-6168221-2:CL_TYPE_ZIP:*:^[^/\\]+\.(doc|xls|ppt|pdf|png|gif|jpeg)\.js$:*:*:*:1:*:";
    let mut loader = loader::Builder::new();
    loader.add_named_bytes("t.cdb", cdb.as_bytes(), true);
    loader.build().expect("build db")
}

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/tests/fixtures/cdb/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

#[test]
fn dual_extension_js_detected_on_streamed_zip() {
    let db = db_with_dualext();
    let zip = fixture("dualext.zip"); // member: PurchaseOrder_20260605.pdf.js
    match scan_seekable(
        &db,
        Cursor::new(&zip),
        zip.len() as u64,
        &ScanOptions::default(),
    )
    .unwrap()
    .verdict
    {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Archive.Filetype.DualExtJS-6168221-2")
        }
        other => panic!("expected DualExtJS detection, got {other:?}"),
    }
}

#[test]
fn single_extension_not_flagged() {
    let db = db_with_dualext();
    let zip = fixture("benign.zip"); // member: report.pdf
    assert!(
        !matches!(
            scan_seekable(
                &db,
                Cursor::new(&zip),
                zip.len() as u64,
                &ScanOptions::default()
            )
            .unwrap()
            .verdict,
            Verdict::Infected { .. }
        ),
        "a benign single-extension member must not be flagged"
    );
}
