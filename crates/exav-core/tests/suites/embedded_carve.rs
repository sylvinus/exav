//! A container (ZIP here) appended to a carrier — a PE overlay / SFX stub /
//! dropper — must be carved and scanned. The normal scan only types offset 0, so
//! without embedded-archive carving the payload in the overlay is invisible.

use exav_core::{analyze, ScanOptions, Scanner, Verdict};
use std::io::Write;

/// A text carrier holding `n` copies of `item`, each after some filler, so no
/// copy runs into the next.
fn carrier(item: &[u8], n: usize) -> Vec<u8> {
    let mut out = b"a carrier with things stapled inside it\n".to_vec();
    for _ in 0..n {
        out.extend_from_slice(&[b'.'; 100]);
        out.extend_from_slice(item);
    }
    out.extend_from_slice(&[b'.'; 100]);
    out
}

fn tiny_pe() -> &'static [u8] {
    include_bytes!("../testdata/tiny_pe32.exe")
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(data).unwrap();
    gz.finish().unwrap()
}

fn verdict(data: &[u8]) -> Verdict {
    analyze(&Scanner::builtin(), data, &ScanOptions::default()).verdict
}

/// Carving scans at most 16 executables of a kind in one object. A 17th was
/// left out silently, so 16 decoys in front of a dropper hid it from every
/// signature that needs it carved: the object is not fully scanned, and says so.
#[test]
fn executables_past_the_carving_cap_are_not_a_clean_scan() {
    assert_eq!(verdict(&carrier(tiny_pe(), 16)), Verdict::Clean);
    match verdict(&carrier(tiny_pe(), 17)) {
        Verdict::LimitsExceeded { reason } => assert!(reason.contains("carving"), "{reason}"),
        other => panic!("17 embedded executables must not scan clean, got {other:?}"),
    }
}

/// The same for archives, at 32.
#[test]
fn archives_past_the_carving_cap_are_not_a_clean_scan() {
    let gz = gzip(b"nothing to see in this member");
    assert_eq!(verdict(&carrier(&gz, 32)), Verdict::Clean);
    match verdict(&carrier(&gz, 33)) {
        Verdict::LimitsExceeded { reason } => assert!(reason.contains("carving"), "{reason}"),
        other => panic!("33 embedded archives must not scan clean, got {other:?}"),
    }
}

/// Reaching the cap in one member does not stop the walk: a detection in a
/// later member of the same container is still found.
#[test]
fn a_member_at_the_carving_cap_does_not_hide_its_siblings() {
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut alone = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    alone.start_file("decoys.bin", stored).unwrap();
    alone.write_all(&carrier(tiny_pe(), 17)).unwrap();
    let alone = alone.finish().unwrap().into_inner();
    assert!(
        matches!(verdict(&alone), Verdict::LimitsExceeded { .. }),
        "the capped member alone makes the archive not fully scanned"
    );

    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file("decoys.bin", stored).unwrap();
    zip.write_all(&carrier(tiny_pe(), 17)).unwrap();
    // Deflated, so EICAR is not in the ZIP's own bytes: only the member has it.
    let deflated = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("payload.txt", deflated).unwrap();
    let eicar = exav_core::unpack::eicar();
    // Long and repetitive, so the compressor codes it rather than storing it.
    zip.write_all(&[eicar, b"\n"].concat().repeat(64)).unwrap();
    let zip = zip.finish().unwrap().into_inner();
    assert!(
        !zip.windows(eicar.len()).any(|w| w == eicar),
        "EICAR must be only in the member"
    );
    match verdict(&zip) {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!("EICAR after a capped member must be found, got {other:?}"),
    }
}

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
