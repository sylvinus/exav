//! Structural validation of images — ClamAV's `Heuristics.Broken.Media.*`.
//!
//! The premise is that a decoder is forgiving and a parser is not: every viewer
//! that renders a truncated GIF is being generous, and the generosity is what
//! exploit writers aim at. So these checks are strict about the container and
//! say nothing about pixels.
//!
//! Both directions are pinned for every format. A validator that fires on
//! ordinary images is worse than no validator at all — images are the most
//! common file type on earth, and this alert is opt-in precisely because a false
//! positive is expensive.

use exav_unpack::broken_media_alert;

// ------------------------------------------------------------ valid fixtures

/// The smallest well-formed GIF89a: header, screen descriptor, a 2-entry global
/// colour table, one 1×1 image, and the trailer.
fn valid_gif() -> Vec<u8> {
    let mut v = b"GIF89a".to_vec();
    v.extend_from_slice(&1u16.to_le_bytes()); // width
    v.extend_from_slice(&1u16.to_le_bytes()); // height
    v.push(0x80); // global colour table, 2 entries
    v.push(0); // background index
    v.push(0); // aspect ratio
    v.extend_from_slice(&[0, 0, 0, 0xff, 0xff, 0xff]); // colour table
    v.push(0x2C); // image descriptor
    v.extend_from_slice(&[0, 0, 0, 0]); // left, top
    v.extend_from_slice(&1u16.to_le_bytes()); // width
    v.extend_from_slice(&1u16.to_le_bytes()); // height
    v.push(0); // no local colour table
    v.push(2); // LZW minimum code size
    v.push(2); // sub-block length
    v.extend_from_slice(&[0x44, 0x01]); // LZW data
    v.push(0); // sub-block terminator
    v.push(0x3B); // trailer
    v
}

/// A well-formed PNG: signature, IHDR, IDAT, IEND, each with a CRC slot.
fn valid_png() -> Vec<u8> {
    fn chunk(ty: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut c = (body.len() as u32).to_be_bytes().to_vec();
        c.extend_from_slice(ty);
        c.extend_from_slice(body);
        c.extend_from_slice(&[0, 0, 0, 0]); // CRC slot; not verified here
        c
    }
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    v.extend_from_slice(&chunk(b"IHDR", &ihdr));
    v.extend_from_slice(&chunk(b"IDAT", &[0x78, 0x9c, 0x63, 0x00, 0x00]));
    v.extend_from_slice(&chunk(b"IEND", &[]));
    v
}

/// A well-formed little-endian TIFF with one IFD holding one SHORT field.
fn valid_tiff() -> Vec<u8> {
    let mut v = b"II\x2a\x00".to_vec();
    v.extend_from_slice(&8u32.to_le_bytes()); // first IFD at offset 8
    v.extend_from_slice(&1u16.to_le_bytes()); // one entry
    v.extend_from_slice(&0x0100u16.to_le_bytes()); // tag: ImageWidth
    v.extend_from_slice(&3u16.to_le_bytes()); // type: SHORT
    v.extend_from_slice(&1u32.to_le_bytes()); // count
    v.extend_from_slice(&1u32.to_le_bytes()); // inline value
    v.extend_from_slice(&0u32.to_le_bytes()); // next IFD: none
    v
}

/// A well-formed JPEG: SOI, a JFIF APP0, a SOF0, then SOS.
fn valid_jpeg() -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8];
    // APP0 / JFIF, 16 bytes of payload
    v.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
    v.extend_from_slice(b"JFIF\0");
    v.extend_from_slice(&[0x01, 0x01, 0x00, 0, 1, 0, 1, 0, 0]);
    // SOF0: length 0x0B covers its own 2 bytes plus 9 of payload — precision,
    // height, width, component count, then 3 bytes for the single component.
    v.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0, 1, 0, 1, 0x01, 0x01, 0x11, 0x00,
    ]);
    // SOS — entropy data follows and is not validated
    v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
    v.extend_from_slice(&[0x00; 8]);
    v
}

#[test]
fn well_formed_images_are_not_flagged() {
    for (what, blob) in [
        ("GIF", valid_gif()),
        ("PNG", valid_png()),
        ("TIFF", valid_tiff()),
        ("JPEG", valid_jpeg()),
    ] {
        assert_eq!(
            broken_media_alert(&blob),
            None,
            "{what}: a well-formed image must not be flagged — this alert exists \
             to catch containers that do not hold together, not ordinary files"
        );
    }
}

#[test]
fn non_images_report_nothing() {
    for blob in [
        &b""[..],
        &b"just some text\n"[..],
        &b"PK\x03\x04 a zip, not an image"[..],
        &b"MZ\x90\x00 an executable"[..],
    ] {
        assert_eq!(broken_media_alert(blob), None);
    }
}

// ---------------------------------------------------------------- truncation

#[test]
fn a_truncated_gif_names_where_it_broke() {
    let g = valid_gif();
    // Cut inside the screen descriptor.
    assert_eq!(
        broken_media_alert(&g[..10]),
        Some("Heuristics.Broken.Media.GIF.TruncatedScreenDescriptor")
    );
    // Cut inside the global colour table.
    assert_eq!(
        broken_media_alert(&g[..15]),
        Some("Heuristics.Broken.Media.GIF.TruncatedGlobalColorTable")
    );
}

/// An extension whose sub-block runs past the end of the file is flagged,
/// not taken for a well-formed image.
#[test]
fn a_gif_extension_sub_block_past_eof_is_flagged() {
    let mut g = valid_gif();
    let pos = g.iter().position(|&b| b == 0x2C).expect("descriptor");
    g.truncate(pos);
    // A comment extension declaring a 100-byte sub-block, 3 bytes of it there.
    g.extend_from_slice(&[0x21, 0xFE, 100, b'a', b'b', b'c']);
    assert_eq!(
        broken_media_alert(&g),
        Some("Heuristics.Broken.Media.GIF.TruncatedExtensionSubBlock")
    );
}

#[test]
fn a_gif_with_an_unknown_block_label_is_flagged() {
    let mut g = valid_gif();
    // Replace the image-descriptor introducer with a label no spec defines.
    let pos = g.iter().position(|&b| b == 0x2C).expect("descriptor");
    g[pos] = 0x5A;
    assert_eq!(
        broken_media_alert(&g),
        Some("Heuristics.Broken.Media.GIF.UnknownBlockLabel")
    );
}

#[test]
fn a_png_chunk_running_past_eof_is_flagged() {
    let mut p = valid_png();
    // Inflate the IDAT length so the chunk claims more than the file holds.
    let idat = p
        .windows(4)
        .position(|w| w == b"IDAT")
        .expect("IDAT present");
    p[idat - 4..idat].copy_from_slice(&0x0000_7000u32.to_be_bytes());
    assert_eq!(
        broken_media_alert(&p),
        Some("Heuristics.Broken.Media.PNG.EOFReadingChunk")
    );
}

#[test]
fn a_png_chunk_length_above_the_spec_cap_is_flagged() {
    let mut p = valid_png();
    let idat = p.windows(4).position(|w| w == b"IDAT").expect("IDAT");
    p[idat - 4..idat].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
    assert_eq!(
        broken_media_alert(&p),
        Some("Heuristics.Broken.Media.PNG.InvalidChunkLength")
    );
}

#[test]
fn a_png_without_iend_is_flagged() {
    let p = valid_png();
    let iend = p.windows(4).position(|w| w == b"IEND").expect("IEND");
    assert!(broken_media_alert(&p[..iend - 4]).is_some());
}

#[test]
fn a_tiff_ifd_pointing_outside_the_file_is_flagged() {
    let mut t = valid_tiff();
    t[4..8].copy_from_slice(&0x0010_0000u32.to_le_bytes());
    assert_eq!(
        broken_media_alert(&t),
        Some("Heuristics.Broken.Media.TIFF.InvalidIFDOffset")
    );
}

#[test]
fn a_tiff_ifd_chain_that_loops_backwards_is_flagged() {
    // A next-IFD offset pointing at or before the current one is how a parser is
    // made to loop forever.
    let mut t = valid_tiff();
    let next_off = t.len() - 4;
    t[next_off..].copy_from_slice(&8u32.to_le_bytes());
    assert_eq!(
        broken_media_alert(&t),
        Some("Heuristics.Broken.Media.TIFF.OutOfOrderIFDOffset")
    );
}

#[test]
fn a_jpeg_segment_running_past_eof_is_flagged() {
    let mut j = valid_jpeg();
    // Enlarge the APP0 length beyond the file. The length lives at 4..6 — 2..4
    // is the marker itself.
    j[4] = 0xF0;
    assert_eq!(
        broken_media_alert(&j),
        Some("Heuristics.Broken.Media.JPEG.SegmentDataOutOfFile")
    );
}

#[test]
fn a_jpeg_segment_length_below_two_is_impossible() {
    let mut j = valid_jpeg();
    j[4] = 0x00;
    j[5] = 0x01; // length includes its own two bytes, so 1 cannot occur
    assert_eq!(
        broken_media_alert(&j),
        Some("Heuristics.Broken.Media.JPEG.InvalidSegmentSize")
    );
}

#[test]
fn a_duplicate_jfif_marker_is_flagged() {
    let mut j = vec![0xFF, 0xD8];
    let app0 = {
        let mut a = vec![0xFF, 0xE0, 0x00, 0x10];
        a.extend_from_slice(b"JFIF\0");
        a.extend_from_slice(&[0x01, 0x01, 0x00, 0, 1, 0, 1, 0, 0]);
        a
    };
    j.extend_from_slice(&app0);
    j.extend_from_slice(&app0); // the duplicate
    j.extend_from_slice(&[0xFF, 0xD9]);
    assert_eq!(
        broken_media_alert(&j),
        Some("Heuristics.Broken.Media.JPEG.JFIFdupAppMarker")
    );
}

/// Junk before a marker is skipped when the marker is within 16 bytes, as
/// clamscan skips it, and reported when it is not.
#[test]
fn stray_bytes_between_jpeg_segments_are_flagged_past_fifteen() {
    let after_app0 = 2 + 18;
    for (junk, want) in [
        (14, None),
        (
            15,
            Some("Heuristics.Broken.Media.JPEG.SpuriousBytesBeforeSegment"),
        ),
    ] {
        let mut j = valid_jpeg();
        j.splice(after_app0..after_app0, std::iter::repeat_n(0x41, junk));
        assert_eq!(broken_media_alert(&j), want, "{junk} bytes");
    }
}

/// What clamscan names, from crafted inputs: it takes a file for a JPEG only
/// from 6 bytes and `FF D8 FF`, reads a length after every marker before the
/// scan (EOI and the restart markers too), and wants JFIF first, after
/// nothing but comments and APP1 segments.
#[test]
fn jpeg_names_follow_clamscan() {
    let seg = |m: u8, body: &[u8]| {
        let mut s = vec![0xFF, m];
        s.extend_from_slice(&(body.len() as u16 + 2).to_be_bytes());
        s.extend_from_slice(body);
        s
    };
    let jfif = seg(0xE0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
    let exif = seg(0xE1, b"Exif\0\0\0\0\0\0\0\0\0\0\0\0");
    let icc = seg(0xE2, b"ICC_PROFILE\0\0\0\0\0");
    let spiff = seg(0xE8, b"SPIFF\0\0\0\0\0\0\0\0\0\0\0");
    let jfxx = seg(0xE0, b"JFXX\0\x10\0\0\0\0\0\0\0\0\0");
    let scan = valid_jpeg()[2 + 18..].to_vec();
    let jpeg = |parts: &[&[u8]]| {
        let mut j = vec![0xFF, 0xD8];
        for p in parts {
            j.extend_from_slice(p);
        }
        j
    };
    for (what, j, want) in [
        ("junk after SOI", jpeg(&[b"ABC", &jfif, &scan]), None),
        ("SOI then EOI", jpeg(&[&[0xFF, 0xD9]]), None),
        (
            "EOI before the scan",
            jpeg(&[&jfif, &[0xFF, 0xD9]]),
            Some("CantReadSegmentSize"),
        ),
        (
            "RST before the scan",
            jpeg(&[&jfif, &[0xFF, 0xD0], &scan]),
            Some("SegmentDataOutOfFile"),
        ),
        ("Exif then JFIF", jpeg(&[&exif, &jfif, &scan]), None),
        (
            "ICC then JFIF",
            jpeg(&[&icc, &jfif, &scan]),
            Some("JFIFmarkerBadPosition"),
        ),
        ("JFIF then JFXX", jpeg(&[&jfif, &jfxx, &scan]), None),
        (
            "JFIF then SPIFF",
            jpeg(&[&jfif, &spiff, &scan]),
            Some("SPIFFdupAppMarker"),
        ),
        (
            "SPIFF then Exif",
            jpeg(&[&spiff, &exif, &scan]),
            Some("ExifDupAppMarker"),
        ),
        (
            "ICC then SPIFF",
            jpeg(&[&icc, &spiff, &scan]),
            Some("SPIFFmarkerBadPosition"),
        ),
        // The start of scan's own header is checked too (from go-fuzz's JPEG
        // corpus): a length past the end, or one short of itself.
        (
            "SOS past the end",
            jpeg(&[&jfif, &[0xFF, 0xDA, 0x00, 0x0E]]),
            Some("SegmentDataOutOfFile"),
        ),
        (
            "SOS length 1",
            jpeg(&[&jfif, &[0xFF, 0xDA, 0x00, 0x01, 0, 0]]),
            Some("InvalidSegmentSize"),
        ),
        (
            "SOS cut in its length",
            jpeg(&[&jfif, &[0xFF, 0xDA, 0x00]]),
            Some("CantReadSegmentSize"),
        ),
    ] {
        let want = want.map(|n| format!("Heuristics.Broken.Media.JPEG.{n}"));
        assert_eq!(broken_media_alert(&j).map(str::to_string), want, "{what}");
    }
}

#[test]
fn hostile_input_never_panics() {
    // Every validator walks attacker-controlled lengths and offsets; the crate
    // is `#![forbid(unsafe_code)]`, so the requirement is simply that nothing
    // indexes out of bounds.
    let magics: [&[u8]; 4] = [b"GIF89a", b"\x89PNG\r\n\x1a\n", b"II\x2a\x00", b"\xff\xd8"];
    for magic in magics {
        for len in 0..64usize {
            let mut v = magic.to_vec();
            v.extend(std::iter::repeat_n(0xFFu8, len));
            let _ = broken_media_alert(&v);
            let mut w = magic.to_vec();
            w.extend((0..len).map(|i| (i * 37) as u8));
            let _ = broken_media_alert(&w);
        }
    }
}
