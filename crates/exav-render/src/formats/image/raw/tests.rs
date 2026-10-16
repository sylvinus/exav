use super::*;

/// A JPEG stream's headers: SOI, a frame of `sof` marker, a scan, `scan`
/// entropy bytes, EOI.
fn stream(sof: u8, precision: u8, w: u16, h: u16, components: u8, scan: &[u8]) -> Vec<u8> {
    let mut d = vec![0xFF, 0xD8, 0xFF, sof];
    d.extend_from_slice(&(8 + 3 * u16::from(components)).to_be_bytes());
    d.push(precision);
    d.extend_from_slice(&h.to_be_bytes());
    d.extend_from_slice(&w.to_be_bytes());
    d.push(components);
    for c in 0..components {
        d.extend_from_slice(&[c + 1, 0x11, 0]);
    }
    d.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 1, 1, 0, 0, 0, 0]);
    d.extend_from_slice(scan);
    d.extend_from_slice(&[0xFF, 0xD9]);
    d
}

fn baseline(w: u16, h: u16) -> Vec<u8> {
    stream(0xC0, 8, w, h, 3, &[1, 2, 3])
}

#[test]
fn a_jpeg_stream_gives_its_frame_and_its_end() {
    let mut d = baseline(640, 480);
    let len = d.len();
    d.extend_from_slice(&[9, 9, 9]);
    let info = jpeg::parse(&d).unwrap();
    assert_eq!(
        info,
        jpeg::Info {
            width: 640,
            height: 480,
            components: 3,
            len,
            orientation: None
        }
    );
}

#[test]
fn what_the_decoder_does_not_read_is_not_a_stream() {
    // Lossless, hierarchical, arithmetic: other frame types than 0 to 2.
    for sof in [0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCF] {
        assert_eq!(
            jpeg::parse(&stream(sof, 8, 8, 8, 3, &[])),
            None,
            "SOF {sof:#x}"
        );
    }
    // 12-bit samples, an empty frame, two components, a frame that lies about
    // its components.
    assert_eq!(jpeg::parse(&stream(0xC0, 12, 8, 8, 3, &[])), None);
    assert_eq!(jpeg::parse(&stream(0xC0, 8, 0, 8, 3, &[])), None);
    assert_eq!(jpeg::parse(&stream(0xC0, 8, 8, 0, 3, &[])), None);
    assert_eq!(jpeg::parse(&stream(0xC0, 8, 8, 8, 2, &[])), None);
    let mut d = baseline(8, 8);
    // SOI, marker, length, precision, height, width, then the count.
    d[11] = 4;
    assert_eq!(jpeg::parse(&d), None);
    // A scan before any frame, and a second start marker or an end marker
    // before the scan.
    let scan_first = [
        0xFF, 0xD8, 0xFF, 0xDA, 0, 8, 1, 1, 0, 0, 0, 0, 1, 2, 0xFF, 0xD9,
    ];
    assert_eq!(jpeg::parse(&scan_first), None);
    assert_eq!(jpeg::parse(&[0xFF, 0xD8, 0xFF, 0xD8, 0xFF, 0xD9]), None);
    assert_eq!(jpeg::parse(&[0xFF, 0xD8, 0xFF, 0xD9]), None);
    // Not even a start marker, or one with nothing after it.
    assert_eq!(jpeg::parse(&[0xFF, 0xD8]), None);
    assert_eq!(jpeg::parse(b""), None);
}

#[test]
fn a_segment_longer_than_the_data_is_not_a_stream() {
    let d = baseline(8, 8);
    // Up to the end of the scan header (past it the stream is cut short, not
    // refused).
    let header = d.windows(2).position(|w| w == [0xFF, 0xDA]).unwrap() + 2 + 8;
    for cut in 0..header {
        assert_eq!(jpeg::parse(&d[..cut]), None, "cut at {cut}");
    }
    assert_eq!(jpeg::parse(&d[..header]).unwrap().len, header);
    // A comment segment that claims more than there is.
    let mut d = vec![0xFF, 0xD8, 0xFF, 0xFE, 0xFF, 0xFF, 1, 2, 3];
    assert_eq!(jpeg::parse(&d), None);
    // A segment length under two.
    d = vec![0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x01, 0xFF, 0xDA];
    assert_eq!(jpeg::parse(&d), None);
}

#[test]
fn fill_bytes_before_a_marker_are_skipped() {
    let mut d = baseline(8, 8);
    d.splice(2..2, [0xFF, 0xFF, 0xFF]);
    assert_eq!(jpeg::parse(&d).unwrap().width, 8);
}

#[test]
fn the_end_marker_is_not_taken_from_stuffed_bytes_or_restarts() {
    // 0xFF 0x00 is a data byte, 0xFF 0xD0 to 0xD7 a restart: neither ends it.
    let d = stream(
        0xC0,
        8,
        8,
        8,
        3,
        &[0xFF, 0x00, 0xFF, 0xD3, 0x12, 0xFF, 0x00],
    );
    let info = jpeg::parse(&d).unwrap();
    assert_eq!(info.len, d.len());
    // A stream with no end marker runs to the end of the data.
    let mut cut = d.clone();
    cut.truncate(cut.len() - 2);
    assert_eq!(jpeg::parse(&cut).unwrap().len, cut.len());
    // A progressive stream's markers between scans are skipped by length: the
    // table marker holds an end-of-image look-alike that is not one.
    let mut p = stream(0xC2, 8, 8, 8, 3, &[1]);
    let at = p.len() - 2;
    p.splice(
        at..at,
        [
            0xFF, 0xC4, 0x00, 0x06, 0xFF, 0xD9, 1, 2, 0xFF, 0xDA, 0, 8, 1, 1, 0, 0, 0, 0, 7,
        ],
    );
    assert_eq!(jpeg::parse(&p).unwrap().len, p.len());
}

#[test]
fn the_start_markers_in_a_file_are_found_in_order_and_not_inside_each_other() {
    let a = baseline(10, 20);
    let b = baseline(30, 40);
    let lossless = stream(0xC3, 8, 99, 99, 1, &[5, 5]);
    let mut d = vec![0u8; 5];
    d.extend_from_slice(&a);
    d.extend_from_slice(&[0xFF, 0xD8, 0xFF, 7, 7]);
    d.extend_from_slice(&lossless);
    d.extend_from_slice(&b);
    let found = jpeg::find(&d);
    let got: Vec<(usize, u32, u32)> = found
        .iter()
        .map(|(at, i)| (*at, i.width, i.height))
        .collect();
    let b_at = 5 + a.len() + 5 + lossless.len();
    assert_eq!(got, vec![(5, 10, 20), (b_at, 30, 40)]);
    // A stream inside a comment segment (a thumbnail in an APP1 segment is
    // found by itself, but the outer stream is walked past it, once).
    let inner = baseline(4, 4);
    let mut outer = vec![0xFF, 0xD8, 0xFF, 0xE1];
    outer.extend_from_slice(&((inner.len() + 2) as u16).to_be_bytes());
    outer.extend_from_slice(&inner);
    outer.extend_from_slice(&baseline(50, 50)[2..]);
    let found = jpeg::find(&outer);
    assert_eq!(found.len(), 1);
    assert_eq!((found[0].0, found[0].1.width), (0, 50));
}

#[test]
fn the_orientation_of_a_streams_exif_is_read() {
    // APP1: "Exif", a little-endian TIFF with one SHORT entry, tag 0x112.
    let mut exif = b"Exif\0\0II*\0\x08\0\0\0\x01\0\x12\x01\x03\0\x01\0\0\0".to_vec();
    exif.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
    let mut d = vec![0xFF, 0xD8, 0xFF, 0xE1];
    d.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
    d.extend_from_slice(&exif);
    d.extend_from_slice(&baseline(8, 8)[2..]);
    assert_eq!(jpeg::parse(&d).unwrap().orientation, Some(6));
    // A value outside 1 to 8 is none.
    let at = d.windows(2).position(|w| w == [6, 0]).unwrap();
    d[at] = 9;
    assert_eq!(jpeg::parse(&d).unwrap().orientation, None);
    // A segment that is not Exif says nothing.
    let mut other = d.clone();
    other[6] = b'X';
    d[at] = 6;
    other[at] = 6;
    assert_eq!(jpeg::parse(&other).unwrap().orientation, None);
}

#[test]
fn the_first_exif_segment_gives_the_orientation() {
    let app1 = |o: u8| {
        let mut exif = b"Exif\0\0II*\0\x08\0\0\0\x01\0\x12\x01\x03\0\x01\0\0\0".to_vec();
        exif.extend_from_slice(&[o, 0, 0, 0, 0, 0, 0, 0]);
        let mut seg = vec![0xFF, 0xE1];
        seg.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
        seg.extend_from_slice(&exif);
        seg
    };
    // An XMP segment first says nothing; of two Exif segments, the first wins.
    let mut d = vec![
        0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x08, b'h', b't', b't', b'p', 0, 0,
    ];
    d.extend_from_slice(&app1(6));
    d.extend_from_slice(&app1(3));
    d.extend_from_slice(&baseline(8, 8)[2..]);
    assert_eq!(jpeg::parse(&d).unwrap().orientation, Some(6));
}

#[test]
fn a_tiffs_orientation_needs_its_magic_and_a_value_from_1_to_8() {
    let tiff = |magic: u16, value: u16| {
        let mut d = b"II".to_vec();
        d.extend_from_slice(&magic.to_le_bytes());
        d.extend_from_slice(&[8, 0, 0, 0, 1, 0, 0x12, 1, 3, 0, 1, 0, 0, 0]);
        d.extend_from_slice(&value.to_le_bytes());
        d.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        d
    };
    assert_eq!(tiff::orientation(&tiff(42, 8)), Some(8));
    assert_eq!(tiff::orientation(&tiff(42, 0)), None);
    assert_eq!(tiff::orientation(&tiff(42, 9)), None);
    assert_eq!(tiff::orientation(&tiff(43, 8)), None);
    assert_eq!(tiff::orientation(b"II*\0"), None);
}

#[test]
fn a_directory_is_read_once_and_the_total_is_capped() {
    // Each of 200 directories points at the next, and at itself.
    let mut d = b"II*\0\x08\0\0\0".to_vec();
    for k in 0..200u32 {
        let at = 8 + k * 18;
        d.extend_from_slice(&1u16.to_le_bytes());
        // One entry: SubIFDs (LONG, 1) pointing at this directory.
        d.extend_from_slice(&0x14Au16.to_le_bytes());
        d.extend_from_slice(&4u16.to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&at.to_le_bytes());
        d.extend_from_slice(&(at + 18).to_le_bytes());
    }
    let scan = tiff::scan(&d, tiff::header(&d).unwrap());
    assert_eq!(scan.ifds.len(), 64);
}

#[test]
fn nesting_of_sub_directories_is_capped() {
    // A chain where each directory's only link is a SubIFD to the next.
    let mut d = b"II*\0\x08\0\0\0".to_vec();
    for k in 0..20u32 {
        let at = 8 + k * 18;
        d.extend_from_slice(&1u16.to_le_bytes());
        d.extend_from_slice(&0x14Au16.to_le_bytes());
        d.extend_from_slice(&4u16.to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes());
        d.extend_from_slice(&(at + 18).to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
    }
    let scan = tiff::scan(&d, tiff::header(&d).unwrap());
    // The first directory and three levels under it.
    assert_eq!(scan.ifds.len(), 4);
}

/// A 3 by 2 picture, a pixel per number, as 2-channel pixels.
fn picture() -> Pixels {
    Pixels {
        width: 3,
        height: 2,
        channels: Channels::LumaAlpha,
        samples: Samples::U8(vec![1, 11, 2, 12, 3, 13, 4, 14, 5, 15, 6, 16]),
    }
}

fn luma(p: &Pixels) -> Vec<u8> {
    let Samples::U8(v) = &p.samples else {
        panic!("8-bit")
    };
    v.chunks(2).map(|c| c[0]).collect()
}

/// Exif's eight orientations of
///
///     1 2 3
///     4 5 6
///
/// written out by hand.
#[test]
fn orientation_turns_pixels_as_exif_defines_it() {
    let cases: [(u8, (u32, u32), [u8; 6]); 8] = [
        (1, (3, 2), [1, 2, 3, 4, 5, 6]),
        (2, (3, 2), [3, 2, 1, 6, 5, 4]),
        (3, (3, 2), [6, 5, 4, 3, 2, 1]),
        (4, (3, 2), [4, 5, 6, 1, 2, 3]),
        (5, (2, 3), [1, 4, 2, 5, 3, 6]),
        (6, (2, 3), [4, 1, 5, 2, 6, 3]),
        (7, (2, 3), [6, 3, 5, 2, 4, 1]),
        (8, (2, 3), [3, 6, 2, 5, 1, 4]),
    ];
    for (o, size, want) in cases {
        let p = orient(picture(), o);
        assert_eq!((p.width, p.height), size, "orientation {o}");
        assert_eq!(luma(&p), want, "orientation {o}");
        // The second channel travels with its pixel.
        let Samples::U8(v) = &p.samples else { panic!() };
        assert!(v.chunks(2).all(|c| c[1] == c[0] + 10), "orientation {o}");
    }
}

#[test]
fn orientation_leaves_other_values_and_other_depths_alone() {
    for o in [0, 9, 200] {
        assert_eq!(orient(picture(), o), picture());
    }
    let wide = Pixels {
        width: 2,
        height: 1,
        channels: Channels::Luma,
        samples: Samples::U16(vec![1, 2]),
    };
    assert_eq!(orient(wide.clone(), 3), wide);
}

/// One 64 by 48 JPEG of the fixtures (tests/fixtures/raw/make.py).
fn good_jpeg() -> Vec<u8> {
    let raf: &[u8] = include_bytes!("../../../../tests/fixtures/raw/fujifilm-o1.raf");
    let at = 160;
    let info = jpeg::parse(&raf[at..]).unwrap();
    raf[at..at + info.len].to_vec()
}

/// A Fujifilm-signed file of `broken` larger streams that parse and do not
/// decode (no tables), then a good smaller one.
fn file_with_broken_streams(broken: usize) -> Vec<u8> {
    let mut d = b"FUJIFILMCCD-RAW ".to_vec();
    for _ in 0..broken {
        d.extend_from_slice(&stream(0xC0, 8, 100, 100, 3, &[1, 2, 3, 4]));
        d.extend_from_slice(&[0; 8]);
    }
    d.extend_from_slice(&good_jpeg());
    d
}

#[test]
fn a_few_previews_are_tried_before_giving_up() {
    // Seven that fail, then the good one: the eighth try.
    let (p, info) = preview(&file_with_broken_streams(MAX_TRIES - 1), DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height, info.found), (64, 48, MAX_TRIES));
    // The ninth is not tried.
    assert_eq!(
        preview(&file_with_broken_streams(MAX_TRIES), DECODE_MAX).err(),
        Some(Error::Undecodable)
    );
}

/// A preview over the budget is not a try: the ones under it still are.
#[test]
fn previews_over_the_budget_do_not_count_as_tries() {
    let (p, _) = preview(&file_with_broken_streams(MAX_TRIES + 3), 64 * 48 * 4).unwrap();
    assert_eq!((p.width, p.height), (64, 48));
}

/// A little-endian TIFF of one directory of `entries` (tag, type, count,
/// value), all inline, whose next directory is `next`.
fn one_directory(entries: &[(u16, u16, u32, u32)], next: u32) -> Vec<u8> {
    let mut d = b"II*\0\x08\0\0\0".to_vec();
    d.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for &(tag, typ, count, value) in entries {
        d.extend_from_slice(&tag.to_le_bytes());
        d.extend_from_slice(&typ.to_le_bytes());
        d.extend_from_slice(&count.to_le_bytes());
        d.extend_from_slice(&value.to_le_bytes());
    }
    d.extend_from_slice(&next.to_le_bytes());
    d
}

fn scan(d: &[u8]) -> tiff::Scan {
    tiff::scan(d, tiff::header(d).unwrap())
}

#[test]
fn a_directory_that_points_at_itself_is_one_directory() {
    // SubIFDs and the next directory both name the directory itself.
    let d = one_directory(&[(0x14A, 4, 1, 8)], 8);
    assert_eq!(scan(&d).ifds.len(), 1);
    // The Exif pointer too.
    let d = one_directory(&[(0x8769, 4, 1, 8)], 0);
    assert_eq!(scan(&d).ifds.len(), 1);
}

#[test]
fn a_directory_of_more_entries_than_the_cap_is_not_read() {
    let entry = (0x9999, 3, 1, 0);
    assert_eq!(scan(&one_directory(&[entry; 1024], 0)).ifds.len(), 1);
    assert_eq!(scan(&one_directory(&[entry; 1025], 0)).ifds.len(), 0);
}

#[test]
fn a_sub_ifd_tag_of_too_many_pointers_is_not_followed() {
    // `n` pointers, out of line after the directory, each to an empty
    // directory of its own.
    let build = |n: u32| {
        let list = 8 + 2 + 12 + 4;
        let mut d = one_directory(&[(0x14A, 4, n, list)], 0);
        for k in 0..n {
            d.extend_from_slice(&(list + 4 * n + 6 * k).to_le_bytes());
        }
        for _ in 0..n {
            d.extend_from_slice(&[0; 6]);
        }
        d
    };
    assert_eq!(scan(&build(16)).ifds.len(), 17);
    assert_eq!(scan(&build(17)).ifds.len(), 1);
}

#[test]
fn a_list_of_strips_over_the_cap_is_lost_and_one_at_it_is_kept() {
    // StripOffsets and StripByteCounts of `n` LONGs each, out of line after the
    // directory.
    let build = |n: u32| {
        let first = 8 + 2 + 2 * 12 + 4;
        let mut d = one_directory(
            &[
                (0x111, 4, n, first as u32),
                (0x117, 4, n, first as u32 + 4 * n),
            ],
            0,
        );
        d.extend(std::iter::repeat_n(7u8, 8 * n as usize));
        d
    };
    let at_cap = scan(&build(1 << 16));
    assert!(!at_cap.ifds[0].chunks_lost);
    assert_eq!(at_cap.ifds[0].chunks.len(), 1 << 16);
    let over = scan(&build((1 << 16) + 1));
    assert!(over.ifds[0].chunks_lost);
    assert!(over.ifds[0].chunks.is_empty());
}

#[test]
fn only_so_many_streams_are_kept() {
    let mut d = Vec::new();
    for _ in 0..70 {
        d.extend_from_slice(&baseline(8, 8));
    }
    assert_eq!(jpeg::find(&d).len(), 64);
}

#[test]
fn a_header_of_too_many_segments_is_not_read() {
    let with_comments = |n: usize| {
        let mut d = vec![0xFF, 0xD8];
        for _ in 0..n {
            d.extend_from_slice(&[0xFF, 0xFE, 0, 2]);
        }
        d.extend_from_slice(&baseline(8, 8)[2..]);
        d
    };
    // The frame and the scan are two of the 256 segments.
    assert!(jpeg::parse(&with_comments(254)).is_some());
    assert!(jpeg::parse(&with_comments(255)).is_none());
}

/// A 2 by 1 uncompressed RGB DNG whose one strip has, or lacks, its byte count.
fn rgb_dng(with_count: bool) -> Vec<u8> {
    rgb_dng_edited(with_count, |_| {})
}

/// [`rgb_dng`] with its entries changed by `edit` before they are written.
fn rgb_dng_edited(with_count: bool, edit: impl Fn(&mut [(u16, u16, u32, u32)])) -> Vec<u8> {
    let n: u16 = if with_count { 9 } else { 8 };
    let bits_at = 8 + 2 + u32::from(n) * 12 + 4;
    let data_at = bits_at + 6;
    let mut entries: Vec<(u16, u16, u32, u32)> = vec![
        (0x100, 4, 1, 2),
        (0x101, 4, 1, 1),
        (0x102, 3, 3, bits_at),
        (0x103, 3, 1, 1),
        (0x106, 3, 1, 2),
        (0x111, 4, 1, data_at),
        (0x115, 3, 1, 3),
        (0xC612, 1, 4, 0x0000_0401),
    ];
    if with_count {
        entries.push((0x117, 4, 1, 6));
    }
    edit(&mut entries);
    let mut d = one_directory(&entries, 0);
    d.extend_from_slice(&[8, 0, 8, 0, 8, 0]);
    d.extend_from_slice(&[10, 20, 30, 40, 50, 60]);
    d
}

/// The conditions an uncompressed preview is read under: each, left out, gives
/// the picture; broken, there is none.
#[test]
fn an_uncompressed_preview_is_read_only_as_chunky_untiled_uncompressed_strips() {
    assert!(preview(&rgb_dng(true), DECODE_MAX).is_ok());
    let none = |d: Vec<u8>, what: &str| {
        assert_eq!(
            preview(&d, DECODE_MAX).err(),
            Some(Error::NoPreview),
            "{what}"
        );
    };
    // Tiles, not strips.
    none(
        rgb_dng_edited(true, |e| {
            for x in e.iter_mut() {
                match x.0 {
                    0x111 => x.0 = 0x144,
                    0x117 => x.0 = 0x145,
                    _ => {}
                }
            }
        }),
        "tiled",
    );
    // A byte count of a type that is not read: the strip is not trusted.
    none(
        rgb_dng_edited(true, |e| {
            for x in e.iter_mut().filter(|x| x.0 == 0x117) {
                x.1 = 5;
            }
        }),
        "byte count of a rational",
    );
    // LZW, not bytes.
    none(
        rgb_dng_edited(true, |e| {
            for x in e.iter_mut().filter(|x| x.0 == 0x103) {
                x.3 = 5;
            }
        }),
        "compressed",
    );
}

#[test]
fn a_single_strip_may_leave_out_its_byte_count() {
    for with_count in [true, false] {
        let (p, info) = preview(&rgb_dng(with_count), DECODE_MAX).unwrap();
        assert_eq!(
            (p.width, p.height, info.jpeg),
            (2, 1, false),
            "{with_count}"
        );
        assert_eq!(p.samples, Samples::U8(vec![10, 20, 30, 40, 50, 60]));
    }
}

/// The boxes of an ISO base media file: `size`, `kind`, `body`.
fn bmff_box(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut d = ((8 + body.len()) as u32).to_be_bytes().to_vec();
    d.extend_from_slice(kind);
    d.extend_from_slice(body);
    d
}

fn orientation_tiff(o: u16) -> Vec<u8> {
    one_directory(&[(0x112, 3, 1, u32::from(o))], 0)
}

/// A `uuid` box: 16 bytes naming its type, then `children`.
fn bmff_uuid(children: &[u8]) -> Vec<u8> {
    let mut body = vec![0xAB; 16];
    body.extend_from_slice(children);
    bmff_box(b"uuid", &body)
}

/// A box laid out as a CR3 lays out its Exif: moov > uuid > CMT1.
fn cr3_moov(orientation: u16) -> Vec<u8> {
    let cmt1 = bmff_box(b"CMT1", &orientation_tiff(orientation));
    bmff_box(b"moov", &bmff_uuid(&cmt1))
}

#[test]
fn an_orientation_is_the_cmt1_box_of_a_uuid_box_of_moov() {
    assert_eq!(bmff::orientation(&cr3_moov(6)), Some(6));
    // After the boxes that come first in a file, and before the ones that
    // follow it.
    let mut d = bmff_box(b"ftyp", b"crx \0\0\0\x01");
    d.extend_from_slice(&bmff_box(b"free", &[0; 9]));
    d.extend_from_slice(&bmff_uuid(&bmff_box(b"CMT1", &orientation_tiff(3))));
    d.extend_from_slice(&cr3_moov(8));
    d.extend_from_slice(&bmff_box(b"mdat", &[0; 20]));
    assert_eq!(bmff::orientation(&d), Some(8));
    // The other boxes of `moov` and of the `uuid` box are passed over.
    let cmt1 = bmff_box(b"CMT1", &orientation_tiff(5));
    let mut inner = bmff_box(b"CNCV", b"Canon");
    inner.extend_from_slice(&bmff_box(b"CMT0", &orientation_tiff(2)));
    inner.extend_from_slice(&cmt1);
    let mut moov = bmff_box(b"trak", &bmff_box(b"CMT1", &orientation_tiff(2)));
    moov.extend_from_slice(&bmff_uuid(&inner));
    assert_eq!(bmff::orientation(&bmff_box(b"moov", &moov)), Some(5));
}

#[test]
fn an_orientation_is_nowhere_else() {
    let tiff = orientation_tiff(6);
    let cmt1 = bmff_box(b"CMT1", &tiff);
    // At the top, a TIFF box that is not in a `uuid` box of `moov`.
    assert_eq!(bmff::orientation(&cmt1), None);
    assert_eq!(bmff::orientation(&bmff_uuid(&cmt1)), None);
    assert_eq!(bmff::orientation(&bmff_box(b"moov", &cmt1)), None);
    // In a box of `moov` that is not a `uuid` box.
    let other = bmff_box(b"trak", &cmt1);
    assert_eq!(bmff::orientation(&bmff_box(b"moov", &other)), None);
    let other = bmff_box(b"trak", &bmff_uuid(&cmt1));
    assert_eq!(bmff::orientation(&bmff_box(b"moov", &other)), None);
    // Not either with 16 bytes before the boxes, as a `uuid` box has.
    let other = bmff_box(b"trak", &[&[0xAB; 16][..], &cmt1].concat());
    assert_eq!(bmff::orientation(&bmff_box(b"moov", &other)), None);
    // A `moov` box inside another box is not looked for.
    assert_eq!(bmff::orientation(&bmff_box(b"free", &cr3_moov(6))), None);
    // Another `uuid` box in between is one level too many.
    let deeper = bmff_box(b"moov", &bmff_uuid(&bmff_uuid(&cmt1)));
    assert_eq!(bmff::orientation(&deeper), None);
    // A TIFF box of another name.
    let moov = |b: &[u8]| bmff_box(b"moov", &bmff_uuid(b));
    assert_eq!(bmff::orientation(&moov(&bmff_box(b"CMT2", &tiff))), None);
    // A CMT1 box that holds no orientation, one out of range, or no TIFF.
    let plain = bmff_box(b"CMT1", &one_directory(&[(0x10F, 3, 1, 1)], 0));
    assert_eq!(bmff::orientation(&moov(&plain)), None);
    assert_eq!(bmff::orientation(&cr3_moov(9)), None);
    assert_eq!(bmff::orientation(&moov(&bmff_box(b"CMT1", b"II*\0"))), None);
}

#[test]
fn the_first_cmt1_box_found_is_the_one() {
    let with = |o| bmff_uuid(&bmff_box(b"CMT1", &orientation_tiff(o)));
    // A `uuid` box with no CMT1 box, and one too short to hold its type, are
    // passed over; a second CMT1 is not read.
    let mut moov = bmff_uuid(&bmff_box(b"free", &[]));
    moov.extend_from_slice(&bmff_box(b"uuid", &[0xAB; 15]));
    moov.extend_from_slice(&with(7));
    moov.extend_from_slice(&with(2));
    assert_eq!(bmff::orientation(&bmff_box(b"moov", &moov)), Some(7));
    // Even if the first has none.
    let mut moov = with(0);
    moov.extend_from_slice(&with(2));
    assert_eq!(bmff::orientation(&bmff_box(b"moov", &moov)), None);
    // The first `moov` is the one.
    let mut d = bmff_box(b"moov", &[]);
    d.extend_from_slice(&cr3_moov(4));
    assert_eq!(bmff::orientation(&d), None);
}

#[test]
fn a_boxs_size_may_be_64_bits_or_run_to_the_end_but_never_past_it() {
    let tiff = orientation_tiff(3);
    let wrap = |cmt1: &[u8]| bmff_box(b"moov", &bmff_uuid(cmt1));
    // A CMT1 box with the size field given, whatever it is.
    let cmt1 = |size: u32, extra: &[u8]| {
        let mut b = size.to_be_bytes().to_vec();
        b.extend_from_slice(b"CMT1");
        b.extend_from_slice(extra);
        b.extend_from_slice(&tiff);
        b
    };
    // Size 1: a 64-bit size follows the type.
    let big = cmt1(1, &(16 + tiff.len() as u64).to_be_bytes());
    assert_eq!(bmff::orientation(&wrap(&big)), Some(3));
    // Size 0: to the end of the enclosing box.
    assert_eq!(bmff::orientation(&wrap(&cmt1(0, &[]))), Some(3));
    // A size past the end of the enclosing box, or under the header's own.
    let past = cmt1(8 + tiff.len() as u32 + 1, &[]);
    assert_eq!(bmff::orientation(&wrap(&past)), None);
    for size in [2, 7] {
        assert_eq!(bmff::orientation(&wrap(&cmt1(size, &[]))), None, "{size}");
    }
    // A 64-bit size under its header's, past the end, or not all there.
    for size in [0u64, 15, 16 + tiff.len() as u64 + 1, u64::MAX] {
        let b = cmt1(1, &size.to_be_bytes());
        assert_eq!(bmff::orientation(&wrap(&b)), None, "{size}");
    }
    let mut cut = cmt1(1, &[]);
    cut.truncate(12);
    assert_eq!(bmff::orientation(&wrap(&cut)), None);
    // The same sizes on the `moov` box itself.
    let moov = cr3_moov(6);
    let mut open = 0u32.to_be_bytes().to_vec();
    open.extend_from_slice(&moov[4..]);
    assert_eq!(bmff::orientation(&open), Some(6));
    let mut big = 1u32.to_be_bytes().to_vec();
    big.extend_from_slice(b"moov");
    big.extend_from_slice(&(moov.len() as u64 + 8).to_be_bytes());
    big.extend_from_slice(&moov[8..]);
    assert_eq!(bmff::orientation(&big), Some(6));
    let mut short = moov.clone();
    short[3] -= 1;
    assert_eq!(bmff::orientation(&short), None);
    short[3] += 2;
    assert_eq!(bmff::orientation(&short), None);
}

#[test]
fn a_file_cut_or_flipped_anywhere_is_read_without_a_panic() {
    let mut d = bmff_box(b"ftyp", b"crx \0\0\0\x01");
    let moov_at = d.len();
    d.extend_from_slice(&cr3_moov(6));
    let end = d.len();
    // `moov` has to be all there.
    for n in 0..=end {
        let want = (n == end).then_some(6);
        assert_eq!(bmff::orientation(&d[..n]), want, "cut at {n}");
        let _ = bmff::is_cr3(&d[..n]);
    }
    for at in 0..end {
        for v in [0x00, 0x01, 0x7F, 0x80, 0xFF] {
            let mut f = d.clone();
            f[at] = v;
            let r = bmff::orientation(&f);
            // The brand and the version of `ftyp` are not read here.
            if (8..moov_at).contains(&at) {
                assert_eq!(r, Some(6), "byte {at} = {v:#x}");
            }
        }
    }
}

#[test]
fn only_so_many_boxes_are_looked_at() {
    let free = bmff_box(b"free", &[]);
    // Each of the boxes before `moov`, `moov`, its `uuid` box and CMT1.
    let after = |before: usize| {
        let mut d = free.repeat(before);
        d.extend_from_slice(&cr3_moov(6));
        bmff::orientation(&d)
    };
    assert_eq!(after(bmff::MAX_BOXES - 3), Some(6));
    assert_eq!(after(bmff::MAX_BOXES - 2), None);
    assert_eq!(after(bmff::MAX_BOXES * 40), None);
    // The budget is one for all the levels: neither level is over it alone.
    let half = bmff::MAX_BOXES / 2 + 2;
    let cmt1 = bmff_box(b"CMT1", &orientation_tiff(6));
    let mut inner = free.repeat(half);
    inner.extend_from_slice(&cmt1);
    let mut moov = free.repeat(half);
    moov.extend_from_slice(&bmff_uuid(&inner));
    let mut d = free.repeat(half);
    d.extend_from_slice(&bmff_box(b"moov", &moov));
    assert_eq!(bmff::orientation(&d), None);
    // The same with room to spare.
    let mut inner = free.repeat(half / 4);
    inner.extend_from_slice(&cmt1);
    let mut moov = free.repeat(half / 4);
    moov.extend_from_slice(&bmff_uuid(&inner));
    let mut d = free.repeat(half / 4);
    d.extend_from_slice(&bmff_box(b"moov", &moov));
    assert_eq!(bmff::orientation(&d), Some(6));
}

#[test]
fn a_crw_needs_its_heap_signature() {
    let mut d = b"II\x1a\0\0\0HEAPCCDR".to_vec();
    d.extend_from_slice(&[0; 32]);
    assert_eq!(detect(&d), Some(Kind::Crw));
    d[6..14].copy_from_slice(b"HEAPXXXX");
    assert_eq!(detect(&d), None);
}

#[test]
fn a_cr3_is_an_iso_file_whose_major_brand_is_crx() {
    assert!(bmff::is_cr3(&bmff_box(b"ftyp", b"crx \0\0\0\x01")));
    // With compatible brands, or as a prefix of a file.
    assert!(bmff::is_cr3(&bmff_box(b"ftyp", b"crx \0\0\0\x01crx isom")));
    assert!(bmff::is_cr3(b"\0\0\0\x18ftypcrx \0\0\0\x01"));
    // Another major brand, the brand only compatible, another box first.
    assert!(!bmff::is_cr3(&bmff_box(b"ftyp", b"isom\0\0\0\x01")));
    assert!(!bmff::is_cr3(&bmff_box(b"ftyp", b"heic\0\0\0\x01crx ")));
    assert!(!bmff::is_cr3(&bmff_box(b"moov", b"crx \0\0\0\x01")));
    assert!(!bmff::is_cr3(&bmff_box(b"ftyp", b"CRX \0\0\0\x01")));
    // Too short to be the box it says.
    assert!(!bmff::is_cr3(b"\0\0\0\x18ftypcrx"));
    assert!(!bmff::is_cr3(b""));
    for size in [0u32, 1, 8, 15] {
        let mut d = bmff_box(b"ftyp", b"crx \0\0\0\x01");
        d[..4].copy_from_slice(&size.to_be_bytes());
        assert!(!bmff::is_cr3(&d), "size {size}");
    }
    let mut d = bmff_box(b"ftyp", b"crx \0\0\0\x01");
    d[..4].copy_from_slice(&16u32.to_be_bytes());
    assert!(bmff::is_cr3(&d));
}
