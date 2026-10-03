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

/// An executable in an OLE2 file is also carved from the file's own bytes and
/// scanned to the end of the file, as ClamAV carves it: a PE-only signature on
/// bytes of a later stream matches, which carving inside the executable's own
/// stream cannot see.
#[test]
fn an_ole2_file_is_carved_from_its_own_bytes() {
    use std::io::Write;
    let pe = include_bytes!("../testdata/tiny_pe32.exe");
    let marker = b"OLE2-CARVE-MARKER-AFTER-THE-STREAM";
    let mut doc = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
    // Over 4 KiB each, so both live in regular sectors, written in order.
    let mut first = vec![0u8; 1000];
    first.extend_from_slice(pe);
    first.resize(8192, 0x22);
    doc.create_stream("/WordDocument")
        .unwrap()
        .write_all(&first)
        .unwrap();
    let mut second = vec![0x33u8; 2000];
    second.extend_from_slice(marker);
    second.resize(8192, 0x44);
    doc.create_stream("/1Table")
        .unwrap()
        .write_all(&second)
        .unwrap();
    let file = doc.into_inner().into_inner();

    let hex: String = marker.iter().map(|b| format!("{b:02x}")).collect();
    let mut l = exav_core::loader::Builder::new();
    let sig = format!("Test.Ole2.Carved;Engine:51-255,Target:1;0;{hex}\n");
    l.add_named_bytes("t.ldb", sig.as_bytes(), true);
    let db = l.build().unwrap();
    match analyze(&db, &file, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert_eq!(signature, "Test.Ole2.Carved"),
        other => panic!("expected the carved executable to match, got {other:?}"),
    }
}
