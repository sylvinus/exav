//! A container (ZIP here) appended to a carrier — a PE overlay / SFX stub /
//! dropper — must be carved and scanned. The normal scan only types offset 0, so
//! without embedded-archive carving the payload in the overlay is invisible.

use exav_core::{ScanOptions, Scanner, Verdict, analyze};
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

/// A zip of a few hundred entries stapled into a document is one archive, not
/// one per entry: it is scanned once and does not trip the carving cap.
#[test]
fn a_zip_of_many_entries_stapled_into_a_document_is_clean() {
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for k in 0..300 {
        z.start_file(format!("entry{k}.txt"), stored).unwrap();
        z.write_all(b"nothing to see here").unwrap();
    }
    let z = z.finish().unwrap().into_inner();
    let mut doc = b"a document with a zip stapled inside it\n".to_vec();
    doc.extend_from_slice(&z);
    doc.extend_from_slice(&[b'.'; 100]);
    assert_eq!(verdict(&doc), Verdict::Clean);
}

/// A zip whose first header names a size that lands on a second archive does
/// not hide that archive: the first one's walk reaches every local header
/// after its own, whether the second sits inside the first one's span (before
/// its central directory) or after its end.
#[test]
fn a_second_zip_at_the_offset_the_first_one_names_is_still_found() {
    let eicar = exav_core::unpack::eicar();
    let deflated = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut x = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    x.start_file("p.txt", deflated).unwrap();
    x.write_all(&[eicar, b"\n"].concat().repeat(64)).unwrap();
    let x = x.finish().unwrap().into_inner();
    assert!(!x.windows(eicar.len()).any(|w| w == eicar));

    // A: one stored entry "a.txt", then `middle`, then its directory.
    let a = |middle: &[u8]| {
        let data = b"hello";
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let mut out = b"PK\x03\x04\x14\0\0\0\0\0\0\0\x21\0".to_vec();
        out.extend_from_slice(&crc.sum().to_le_bytes());
        out.extend_from_slice(&[5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0]);
        out.extend_from_slice(b"a.txt");
        out.extend_from_slice(data);
        let cd_at = out.len() + middle.len();
        out.extend_from_slice(middle);
        let cd = out.len();
        out.extend_from_slice(b"PK\x01\x02\x14\0\x14\0\0\0\0\0\0\0\x21\0");
        out.extend_from_slice(&crc.sum().to_le_bytes());
        // Sizes, name length 5, then the extra, comment, disk, attribute and
        // local header offset fields, all zero.
        out.extend_from_slice(&[5, 0, 0, 0, 5, 0, 0, 0, 5, 0]);
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(b"a.txt");
        let size = (out.len() - cd) as u32;
        out.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(cd_at as u32).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    };
    for (what, zip) in [("inside", a(&x)), ("after", [a(b""), x.clone()].concat())] {
        let mut doc = b"a document with two zips stapled inside it\n".to_vec();
        doc.extend_from_slice(&zip);
        doc.extend_from_slice(&[b'.'; 100]);
        match verdict(&doc) {
            Verdict::Infected { signature, .. } => assert!(
                signature.to_ascii_uppercase().contains("EICAR"),
                "{what}: unexpected signature {signature}"
            ),
            other => panic!("{what}: EICAR in the second zip must be found, got {other:?}"),
        }
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
