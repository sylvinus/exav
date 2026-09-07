//! A truncated / corrupt compressed member must still have its RECOVERABLE
//! prefix scanned — malware in the part that did decode is caught, never hidden
//! by the decode error on the missing tail. (Regression guard: marking the whole
//! member Unscannable and discarding the salvageable bytes would hide EICAR in a
//! truncated gzip that `zcat` recovers fine.)

use std::io::Write;

use exav_core::{analyze, ScanOptions, Scanner, Verdict};

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

fn gzip(payload: &[u8], level: flate2::Compression) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), level);
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

#[test]
fn truncated_gzip_still_scans_recoverable_content() {
    let db = Scanner::builtin();
    // EICAR up front, then a large filler tail. Stored (uncompressed) DEFLATE so
    // compressed offsets track payload offsets — cutting the tail predictably
    // removes only filler, leaving EICAR before the cut and recoverable.
    let mut payload = eicar().to_vec();
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
    let db = Scanner::builtin();
    let mut payload = b"nothing malicious here, just filler ".to_vec();
    payload.extend(vec![b'B'; 16384]);
    let full = gzip(&payload, flate2::Compression::none());
    let truncated = &full[..full.len() - 2048];
    match analyze(&db, truncated, &ScanOptions::default()).verdict {
        Verdict::Clean => {}
        other => panic!("truncated-but-clean gzip should be Clean, got {other:?}"),
    }
}

/// A ZIP that OPENS but whose first member cannot be read: the central directory
/// is intact, so the archive parses, and the failure only arrives when the member
/// itself is reached. Word documents carrying an embedded ZIP land here routinely
/// — the embedded copy's central directory records offsets relative to the whole
/// document, so they point outside the carved slice.
fn zip_with_an_unreadable_first_member() -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file(
        "payload.bin",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .unwrap();
    z.write_all(&[b'P'; 2048]).unwrap();
    let mut blob = z.finish().unwrap().into_inner();
    // Lie about where the central directory starts. A reader reconciles the
    // claim against where the directory actually is and carries the difference
    // over to every local-header offset, so the directory still parses and the
    // members it points at do not. Bytes 16..20 of the EOCD are that offset.
    let eocd = blob
        .windows(4)
        .rposition(|w| w == b"PK\x05\x06")
        .expect("end-of-central-directory record");
    blob[eocd + 16..eocd + 20].copy_from_slice(&0u32.to_le_bytes());
    blob
}

/// A carrier holding a normal ZIP with EICAR in it, deflated so the bytes appear
/// nowhere verbatim and only extraction can reach them.
fn carrier_with_an_eicar_zip(prefix: Vec<u8>) -> Vec<u8> {
    let mut blob = prefix;
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file(
        "eicar.txt",
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated),
    )
    .unwrap();
    z.write_all(eicar()).unwrap();
    blob.extend_from_slice(&z.finish().unwrap().into_inner());
    blob
}

#[test]
fn one_unreadable_member_does_not_take_the_rest_of_the_archive_with_it() {
    // A WELL-FORMED archive with a single bad member — the ordinary case, not an
    // exotic one. Every recorded offset is correct and members 2 and 3 are
    // perfectly readable; only the first member's local header signature is
    // destroyed.
    //
    // Two mechanisms can combine here into a silent clean, which is why this is
    // asserted rather than assumed. The central-directory walk gives up on the
    // whole archive at the first member it cannot read, and the local-header
    // salvage pass then skips the survivors because their directory records
    // parsed and put them in its "already covered" set. Covered by the pass that
    // abandoned them, skipped by the pass that would have rescued them.
    //
    // Deflated, so the payload appears nowhere verbatim: the container's raw scan
    // cannot find it, and only actually reaching the third member can.
    let db = Scanner::builtin();
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, body) in [
        ("first.bin", &b"aaaaaaaaaaaaaaaaaaaaaaaa"[..]),
        ("second.bin", &b"bbbbbbbbbbbbbbbbbbbbbbbb"[..]),
        ("third.bin", eicar()),
    ] {
        z.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
        z.write_all(body).unwrap();
    }
    let mut blob = z.finish().unwrap().into_inner();

    // Break ONLY the first directory record's pointer to its local header (byte 42
    // of the CDFH), aiming it one byte into the file so the signature there cannot
    // match. The archive still opens, members 2 and 3 keep correct pointers, and
    // the file still begins with a ZIP magic.
    //
    // That last part is not cosmetic. Corrupting the magic at offset 0 instead
    // makes the file stop being detected as a ZIP at all, so it reaches the
    // embedded-carve path and the payload is found for an unrelated reason — a
    // version of this test written that way passed against the unfixed engine and
    // proved nothing.
    let cd = blob
        .windows(4)
        .position(|w| w == b"PK\x01\x02")
        .expect("central directory");
    blob[cd + 42..cd + 46].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        &blob[..4],
        b"PK\x03\x04",
        "the file must still be recognisable as a ZIP, or this tests the carve path"
    );

    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!(
            "EICAR in the third member must be found even though the first is \
             unreadable, got {other:?}"
        ),
    }
}

#[test]
fn an_archive_that_wont_open_is_unscannable_not_over_a_limit() {
    // The two verdicts are not interchangeable wording. `Unscannable` is a member
    // exav could not read, and the walk goes on to everything else in the file;
    // `LimitsExceeded` is a budget stop, which aborts the walk and takes the
    // containing scan with it. Nothing here is near a limit — the archive simply
    // does not parse — so calling it one costs every later member.
    //
    // What that cost looks like: a Word document whose `1Table` stream carried an
    // embedded ZIP of this shape came back `LimitsExceeded`, because the abort
    // unwound out of the ZIP and out of the OLE walk before the document's macro
    // artifacts were built. Its live VBA project went unreported and every
    // `Target:2` `Doc.*` signature was skipped on it.
    let db = Scanner::builtin();
    let blob = zip_with_an_unreadable_first_member();
    match analyze(&db, &blob, &ScanOptions::default()).verdict {
        Verdict::Unscannable { .. } => {}
        other => panic!("a ZIP that will not open must be Unscannable, got {other:?}"),
    }
}

#[test]
fn a_malformed_archive_does_not_hide_a_detection_beside_it() {
    // Sanity first: on its own, the carve finds EICAR in an appended ZIP. Without
    // this the assertion below could pass on a scan that found nothing anywhere.
    let db = Scanner::builtin();
    assert!(
        matches!(
            analyze(
                &db,
                &carrier_with_an_eicar_zip(vec![b'H'; 512]),
                &ScanOptions::default()
            )
            .verdict,
            Verdict::Infected { .. }
        ),
        "the carve path must find EICAR in an appended ZIP"
    );

    // Now with a ZIP that won't open sitting in front of it. One unreadable
    // archive must cost only itself.
    let mut prefix = vec![b'H'; 512];
    prefix.extend_from_slice(&zip_with_an_unreadable_first_member());
    prefix.extend(vec![b'T'; 512]);
    match analyze(
        &db,
        &carrier_with_an_eicar_zip(prefix),
        &ScanOptions::default(),
    )
    .verdict
    {
        Verdict::Infected { signature, .. } => assert!(
            signature.to_ascii_uppercase().contains("EICAR"),
            "unexpected signature {signature}"
        ),
        other => panic!(
            "a malformed carved archive must not suppress a detection elsewhere \
             in the same file, got {other:?}"
        ),
    }
}

#[test]
fn intact_gzip_still_works() {
    // Sanity: the salvage path doesn't regress the normal (untruncated) case.
    let db = Scanner::builtin();
    let mut payload = vec![b'x'; 100];
    payload.extend_from_slice(eicar());
    let blob = gzip(&payload, flate2::Compression::default());
    matches!(
        analyze(&db, &blob, &ScanOptions::default()).verdict,
        Verdict::Infected { .. }
    )
    .then_some(())
    .expect("intact gzip with EICAR must be Infected");
}
