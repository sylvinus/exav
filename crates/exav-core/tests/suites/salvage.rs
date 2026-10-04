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

/// A bzip2, Zstandard, xz or lzip file cut short, as a download that stopped:
/// what decodes before the cut is scanned, EICAR in it is found, and a prefix
/// without it is clean, not partial. The streams are the members of exav-unpack's
/// `cut_<codec>.zip` fixtures (written by 7-Zip 25.01; zstd 1.5.7 for Zstandard)
/// and `cut_lzip.lz` (lzip 1.25, `lzip -9`), each text with EICAR in the middle.
/// Python 3.13's `bz2` and `lzma`, `zstd -dc` and `lzip -dc` give a prefix
/// without EICAR from each cut 25% in, and one with it from each cut 90% in.
#[cfg(feature = "all-formats")]
#[test]
fn a_compressed_file_cut_short_is_scanned_as_far_as_it_goes() {
    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/../exav-unpack/tests/fixtures");
    let read = |p: &str| {
        exav_core::unpack::read_fixture(&format!("{fixtures}/{p}"))
            .unwrap_or_else(|e| panic!("{p}: {e}"))
    };
    let member = |zip: Vec<u8>| {
        let u16_at = |o: usize| usize::from(u16::from_le_bytes([zip[o], zip[o + 1]]));
        let comp = u32::from_le_bytes(zip[18..22].try_into().unwrap()) as usize;
        let start = 30 + u16_at(26) + u16_at(28);
        zip[start..start + comp].to_vec()
    };
    let files = [
        ("bzip2", member(read("zip/cut_bzip2.zip"))),
        ("zstd", member(read("zip/cut_zstd.zip"))),
        ("xz", member(read("zip/cut_xz.zip"))),
        ("lzip", read("cut_lzip.lz")),
    ];
    let db = Scanner::builtin();
    let mut wrong = Vec::new();
    for (codec, file) in &files {
        for (pct, found) in [(25, false), (90, true)] {
            let v = analyze(
                &db,
                &file[..file.len() * pct / 100],
                &ScanOptions::default(),
            )
            .verdict;
            let ok = match &v {
                Verdict::Infected { signature, .. } => {
                    found && signature.to_ascii_uppercase().contains("EICAR")
                }
                Verdict::Clean => !found,
                _ => false,
            };
            if !ok {
                wrong.push(format!("{codec}, cut at {pct}%: {v:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
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
    // Point the member's directory entry at a local header that is not there.
    // The directory still parses and the member it points at does not. Bytes
    // 42..46 of a central directory header are that offset.
    let cd = blob
        .windows(4)
        .rposition(|w| w == b"PK\x01\x02")
        .expect("central directory header");
    blob[cd + 42..cd + 46].copy_from_slice(&7u32.to_le_bytes());
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

/// Damage part way through a compressed stream, in each format that decodes
/// one. Needs those formats compiled in.
#[cfg(feature = "all-formats")]
mod damaged {
    use super::*;

    /// Deflate data that decodes `prefix`, then hits a block of the reserved type
    /// with `rest` behind it: content present in the file that no decoder reaches.
    fn deflate_broken_after(prefix: &[u8], rest: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(prefix).unwrap();
        // A sync flush ends on a byte boundary with no final block.
        e.flush().unwrap();
        let mut raw = e.get_ref().clone();
        // BFINAL 0, BTYPE 11.
        raw.push(0x06);
        raw.extend_from_slice(rest);
        raw
    }

    /// Long enough that a decoder hands some of it over before it reaches the
    /// damage, which is the case a salvage exists for.
    fn clean_prefix() -> Vec<u8> {
        (0..4000u32)
            .flat_map(|i| format!("line {i} of a clean prefix\n").into_bytes())
            .collect()
    }

    const UNREACHED: &[u8] = &[0x5a; 4096];

    fn gzip_header() -> Vec<u8> {
        vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff]
    }

    fn gzip_broken() -> Vec<u8> {
        let mut g = gzip_header();
        g.extend(deflate_broken_after(&clean_prefix(), UNREACHED));
        g
    }

    /// A gzip that decodes in full and then fails its CRC-32.
    fn gzip_bad_crc() -> Vec<u8> {
        let mut g = gzip(&clean_prefix(), flate2::Compression::default());
        let n = g.len();
        g[n - 8] ^= 0xff;
        g
    }

    fn zip_one(name: &str, body: &[u8]) -> Vec<u8> {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        z.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
        z.write_all(body).unwrap();
        z.finish().unwrap().into_inner()
    }

    /// A ZIP whose deflated member breaks part way.
    fn zip_broken() -> Vec<u8> {
        zip_broken_after(&clean_prefix())
    }

    /// A ZIP whose deflated member breaks right after `prefix`.
    fn zip_broken_after(prefix: &[u8]) -> Vec<u8> {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        z.start_file(
            "m.bin",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        z.write_all(&deflate_broken_after(prefix, UNREACHED))
            .unwrap();
        let mut blob = z.finish().unwrap().into_inner();
        // Relabel the stored member as deflated, in its local header and its
        // directory record.
        blob[8..10].copy_from_slice(&8u16.to_le_bytes());
        let cd = blob.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        blob[cd + 10..cd + 12].copy_from_slice(&8u16.to_le_bytes());
        blob
    }

    /// A ZIP whose member decodes in full and then fails its CRC-32.
    fn zip_bad_crc() -> Vec<u8> {
        let mut blob = zip_one("m.bin", &clean_prefix());
        blob[14] ^= 0xff;
        let cd = blob.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        blob[cd + 16] ^= 0xff;
        blob
    }

    fn in_zip(name: &str, data: &[u8]) -> Vec<u8> {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        z.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        z.write_all(data).unwrap();
        z.finish().unwrap().into_inner()
    }

    fn in_tar(name: &str, data: &[u8]) -> Vec<u8> {
        let mut ar = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        ar.append_data(&mut h, name, data).unwrap();
        ar.into_inner().unwrap()
    }

    /// A PDF with one FlateDecode stream.
    fn pdf_with_stream(zlib: &[u8]) -> Vec<u8> {
        let mut p = format!(
            "%PDF-1.4\n1 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
            zlib.len()
        )
        .into_bytes();
        p.extend_from_slice(zlib);
        p.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
        p
    }

    fn zlib(payload: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(payload).unwrap();
        e.finish().unwrap()
    }

    fn verdict(blob: &[u8]) -> Verdict {
        analyze(&Scanner::builtin(), blob, &ScanOptions::default()).verdict
    }

    /// An MSZIP cabinet holding one member, `body`, whose third 32 KiB block
    /// is replaced by a deflate block of the reserved type: the first two
    /// decode, nothing after them does.
    fn cab_broken_in_block_three(body: &[u8]) -> Vec<u8> {
        let mut builder = cab::CabinetBuilder::new();
        builder
            .add_folder(cab::CompressionType::MsZip)
            .add_file("m.bin");
        let mut blob = Vec::new();
        let mut w = builder.build(std::io::Cursor::new(&mut blob)).unwrap();
        while let Some(mut f) = w.next_file().unwrap() {
            f.write_all(body).unwrap();
        }
        w.finish().unwrap();
        // CFFOLDER follows the 36-byte CFHEADER: the first CFDATA's offset.
        let mut at = u32::from_le_bytes(blob[36..40].try_into().unwrap()) as usize;
        for _ in 0..2 {
            let cb = u16::from_le_bytes([blob[at + 4], blob[at + 5]]) as usize;
            at += 8 + cb;
        }
        // Past the block's checksum, size fields and `CK`: BFINAL 1, BTYPE 11.
        assert_eq!(&blob[at + 8..at + 10], b"CK");
        blob[at + 10] = 0x07;
        blob
    }

    /// Filler that does not compress, so the member spans several blocks.
    fn noise(n: usize) -> Vec<u8> {
        let mut x: u32 = 0x9e37_79b9;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    /// The bytes a damaged CAB member decoded before the damage are scanned,
    /// and with nothing found the damage keeps the file from passing as clean.
    #[test]
    fn a_damaged_cab_member_is_scanned_up_to_the_damage() {
        let mut infected = eicar().to_vec();
        infected.extend(noise(160 * 1024));
        match verdict(&cab_broken_in_block_three(&infected)) {
            Verdict::Infected { .. } => {}
            other => panic!("EICAR before the damage: expected Infected, got {other:?}"),
        }
        match verdict(&cab_broken_in_block_three(&noise(160 * 1024))) {
            Verdict::Unscannable { .. } => {}
            other => panic!("nothing before the damage: expected Unscannable, got {other:?}"),
        }
    }

    /// A ZOO member that fails its CRC still has every byte it holds scanned.
    /// `store.zoo` holds one stored member; putting EICAR at its start is what
    /// breaks the CRC.
    #[test]
    fn a_zoo_member_failing_its_crc_is_scanned() {
        let mut zoo = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../exav-unpack/tests/fixtures/zoo/store.zoo"
        ))
        .unwrap();
        // The archive header's first directory entry, whose `offset` field
        // locates the member's data.
        let entry = u32::from_le_bytes(zoo[24..28].try_into().unwrap()) as usize;
        let data = u32::from_le_bytes(zoo[entry + 10..entry + 14].try_into().unwrap()) as usize;
        assert!(
            matches!(verdict(&zoo), Verdict::Clean),
            "the fixture itself: {:?}",
            verdict(&zoo)
        );
        zoo[data..data + eicar().len()].copy_from_slice(eicar());
        match verdict(&zoo) {
            Verdict::Infected { .. } => {}
            other => panic!("expected Infected, got {other:?}"),
        }
    }

    /// Corruption part way through a compressed stream leaves content in the
    /// file that was never decoded, so a clean prefix is not a clean file. The
    /// same answer whether the stream is the file or sits inside another one.
    #[test]
    fn content_left_undecoded_is_not_clean() {
        let mut pdf_broken = vec![0x78, 0x9c];
        pdf_broken.extend(deflate_broken_after(&clean_prefix(), UNREACHED));
        for (what, blob) in [
            ("gzip", gzip_broken()),
            ("gzip in tar", in_tar("x.gz", &gzip_broken())),
            ("gzip in zip", in_zip("x.gz", &gzip_broken())),
            ("zip", zip_broken()),
            ("zip in tar", in_tar("x.zip", &zip_broken())),
            ("zip in zip", in_zip("x.zip", &zip_broken())),
            ("pdf", pdf_with_stream(&pdf_broken)),
        ] {
            match verdict(&blob) {
                Verdict::Unscannable { .. } => {}
                other => panic!("{what}: expected Unscannable, got {other:?}"),
            }
        }
    }

    /// A stream that decoded in full and then failed its checksum hides nothing:
    /// every byte it holds was scanned. exav is not an integrity checker.
    #[test]
    fn a_bad_checksum_after_a_full_decode_is_clean() {
        let mut pdf_adler = zlib(&clean_prefix());
        let n = pdf_adler.len();
        pdf_adler[n - 1] ^= 0xff;
        for (what, blob) in [
            ("gzip", gzip_bad_crc()),
            ("gzip in tar", in_tar("x.gz", &gzip_bad_crc())),
            ("gzip in zip", in_zip("x.gz", &gzip_bad_crc())),
            ("zip", zip_bad_crc()),
            ("zip in tar", in_tar("x.zip", &zip_bad_crc())),
            ("zip in zip", in_zip("x.zip", &zip_bad_crc())),
            ("pdf", pdf_with_stream(&pdf_adler)),
        ] {
            match verdict(&blob) {
                Verdict::Clean => {}
                other => panic!("{what}: expected Clean, got {other:?}"),
            }
        }
    }

    /// The counterweight: each broken stream still has its prefix scanned, and a
    /// detection there wins over the damage after it. EICAR sits right before the
    /// damage, in the output of the very read that fails.
    #[test]
    fn a_detection_before_the_damage_is_still_found() {
        let mut prefix = clean_prefix();
        prefix.extend_from_slice(eicar());
        let mut gz = gzip_header();
        gz.extend(deflate_broken_after(&prefix, UNREACHED));
        let mut pdf = vec![0x78, 0x9c];
        pdf.extend(deflate_broken_after(&prefix, UNREACHED));
        let zip = zip_broken_after(&prefix);
        for (what, blob) in [
            ("gzip", gz.clone()),
            ("gzip in tar", in_tar("x.gz", &gz)),
            ("gzip in zip", in_zip("x.gz", &gz)),
            ("zip", zip.clone()),
            ("zip in tar", in_tar("x.zip", &zip)),
            ("pdf", pdf_with_stream(&pdf)),
        ] {
            match verdict(&blob) {
                Verdict::Infected { .. } => {}
                other => panic!("{what}: expected Infected, got {other:?}"),
            }
        }
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
