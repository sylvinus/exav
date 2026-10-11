//! DWG, R13 to R2018: the file structure, and the preview images and
//! OLE2FRAME objects as the container's members.
//!
//! The drawings in `fixtures/dwg/` are exav-render's
//! `tests/fixtures/cad/src/cp1251.dxf` (ezdxf) as the ODA File Converter
//! saved it as DWG of each version (`make.py --convert-dwg` there); their
//! preview holds no image. Those in `fixtures/dwg/preview/` have a bitmap
//! as their preview, those in `fixtures/dwg/ole/` an OLE2FRAME (`make.py`
//! in each). The other previews here are built as the ODA specification
//! lays them out (14.2, and 4.1 for the R2004 file header).

#![cfg(feature = "dwg")]

use std::io::Read;

use exav_unpack::dwg::{looks_like_dwg, Dwg, PreviewKind, Version};
use exav_unpack::{detect, extract, Budget, Entry, Format, Limits};

/// Every version the converter writes, as the fixture directories name them.
const VERSIONS: [&str; 8] = [
    "R13", "R14", "R2000", "R2004", "R2007", "R2010", "R2013", "R2018",
];

fn gunzip(gz: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut out)
        .expect("a gzip fixture");
    out
}

fn fixtures() -> [(Vec<u8>, Version); 8] {
    [
        (
            gunzip(include_bytes!("../fixtures/dwg/R13.dwg.gz")),
            Version::R13,
        ),
        (
            gunzip(include_bytes!("../fixtures/dwg/R14.dwg.gz")),
            Version::R14,
        ),
        (
            gunzip(include_bytes!("../fixtures/dwg/R2000.dwg.gz")),
            Version::R2000,
        ),
        (
            gunzip(include_bytes!("../fixtures/dwg/R2004.dwg.gz")),
            Version::R2004,
        ),
        (
            gunzip(include_bytes!("../fixtures/dwg/R2007.dwg.gz")),
            Version::R2007,
        ),
        (
            gunzip(include_bytes!("../fixtures/dwg/R2010.dwg.gz")),
            Version::R2010,
        ),
        (
            gunzip(include_bytes!("../fixtures/dwg/R2013.dwg.gz")),
            Version::R2013,
        ),
        (
            gunzip(include_bytes!("../fixtures/dwg/R2018.dwg.gz")),
            Version::R2018,
        ),
    ]
}

fn members(data: &[u8]) -> Vec<Entry> {
    let mut budget = Budget::new(Limits::default());
    extract(Format::Dwg, &data, &mut budget).expect("extracts")
}

const PREVIEW_START: [u8; 16] = [
    0x1F, 0x25, 0x6D, 0x07, 0xD4, 0x36, 0x28, 0x28, 0x9D, 0x57, 0xCA, 0x3F, 0x9D, 0x44, 0x10, 0x2B,
];
const PREVIEW_END: [u8; 16] = [
    0xE0, 0xDA, 0x92, 0xF8, 0x2B, 0xC9, 0xD7, 0xD7, 0x62, 0xA8, 0x35, 0xC0, 0x62, 0xBB, 0xEF, 0xD4,
];

/// An R2000 file header (spec 3.2) with three section locators pointing
/// nowhere, and a preview (spec 14.2) of the given images, `(code, data)`.
fn with_preview(images: &[(u8, &[u8])]) -> Vec<u8> {
    let mut f = b"AC1015".to_vec();
    f.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&[0; 4]); // 0x0D: the preview's address, below
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&30u16.to_le_bytes()); // ANSI_1252
    f.extend_from_slice(&3u32.to_le_bytes());
    for n in 0..3u8 {
        f.push(n);
        f.extend_from_slice(&[0; 8]);
    }
    f.extend_from_slice(&[0, 0]); // CRC
    f.extend_from_slice(&[
        0x95, 0xA0, 0x4E, 0x28, 0x99, 0x82, 0x1A, 0xE5, 0x5E, 0x41, 0xE0, 0x5F, 0x9D, 0x3A, 0x4D,
        0x00,
    ]);
    let start = f.len();
    f[0x0D..0x11].copy_from_slice(&(start as u32).to_le_bytes());
    f.extend_from_slice(&PREVIEW_START);
    let overall = f.len();
    f.extend_from_slice(&[0; 4]);
    f.push(images.len() as u8);
    let mut at = start + 16 + 4 + 1 + 9 * images.len();
    for (code, data) in images {
        f.push(*code);
        f.extend_from_slice(&(at as u32).to_le_bytes());
        f.extend_from_slice(&(data.len() as u32).to_le_bytes());
        at += data.len();
    }
    for (_, data) in images {
        f.extend_from_slice(data);
    }
    let size = (f.len() - overall - 4) as u32;
    f[overall..overall + 4].copy_from_slice(&size.to_le_bytes());
    f.extend_from_slice(&PREVIEW_END);
    f
}

/// An R2004 file header (spec 4.1): the version, the preview's address at
/// 0x0D, and at 0x80 the 0x6C bytes of the file ID string and zeros XORed
/// with the sequence spec 4.1 generates. Then the preview of `images` at
/// 0x100. No page map: the drawing does not open.
fn r2004_with_preview(images: &[(u8, &[u8])]) -> Vec<u8> {
    let mut f = vec![0u8; 0x100];
    f[..6].copy_from_slice(b"AC1018");
    let mut plain = [0u8; 0x6C];
    plain[..12].copy_from_slice(b"AcFssFcAJMB\0");
    let mut seed: u32 = 1;
    for (i, b) in plain.iter().enumerate() {
        seed = seed.wrapping_mul(0x343FD).wrapping_add(0x269EC3);
        f[0x80 + i] = b ^ (seed >> 16) as u8;
    }
    // `with_preview`'s preview, moved to 0x100: its addresses shift.
    let r2000 = with_preview(images);
    let start = u32::from_le_bytes(r2000[0x0D..0x11].try_into().unwrap()) as usize;
    let shift = 0x100 - start;
    let mut preview = r2000[start..].to_vec();
    for k in 0..images.len() {
        let p = 16 + 4 + 1 + 9 * k + 1;
        let v = u32::from_le_bytes(preview[p..p + 4].try_into().unwrap()) as usize + shift;
        preview[p..p + 4].copy_from_slice(&(v as u32).to_le_bytes());
    }
    f[0x0D..0x11].copy_from_slice(&0x100u32.to_le_bytes());
    f.extend_from_slice(&preview);
    f
}

/// A 2x2 8-bit bitmap: BITMAPINFOHEADER, a 256-colour palette, two rows of
/// four bytes.
fn dib() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&40u32.to_le_bytes());
    d.extend_from_slice(&2i32.to_le_bytes());
    d.extend_from_slice(&2i32.to_le_bytes());
    d.extend_from_slice(&1u16.to_le_bytes());
    d.extend_from_slice(&8u16.to_le_bytes());
    d.extend_from_slice(&[0; 24]);
    d.extend((0..256u32).flat_map(|i| [i as u8, i as u8, i as u8, 0]));
    d.extend_from_slice(&[1, 2, 0, 0, 3, 4, 0, 0]);
    d
}

#[test]
fn the_converters_files_are_dwg_and_every_object_reads() {
    for (data, version) in fixtures() {
        assert_eq!(detect(&data), Some(Format::Dwg), "{version:?}");
        let dwg = Dwg::open(&data).expect("opens");
        assert_eq!(dwg.version(), version);
        assert!(dwg.problems().is_empty(), "{:?}", dwg.problems());
        // The source's $DWGCODEPAGE.
        assert_eq!(
            exav_unpack::dwg::code_page_name(dwg.code_page()),
            Some("ANSI_1251"),
            "{version:?}"
        );
        let map = dwg.object_map();
        assert!(map.len() > 100, "{version:?}: {} objects", map.len());
        // Each object the map points at says it is the object of that
        // handle, and is of a type the file knows.
        for &(handle, _) in map {
            let o = dwg
                .object(handle)
                .expect("mapped")
                .unwrap_or_else(|e| panic!("{version:?} {handle:X}: {e}"));
            assert_eq!(o.handle, handle);
            assert!(
                dwg.type_name(o.type_code).is_some(),
                "{version:?} {handle:X}: type {}",
                o.type_code
            );
        }
        // The preview section is there, with no image.
        assert!(dwg.preview().is_empty());
        assert!(members(&data).is_empty());
    }
}

/// The drawings of `fixtures/dwg/ole/` (make.py there: one OLE2FRAME,
/// handle 2F, embedding a compound file whose stream is a ZIP of the EICAR
/// test file), every version: the compound file is a member, from its
/// signature on, as the `cfb` and `zip` crates read it back.
#[test]
fn an_ole2frame_yields_its_compound_file() {
    use std::io::Cursor;
    for v in VERSIONS {
        let path = format!(
            "{}/tests/fixtures/dwg/ole/{v}.dwg.gz",
            env!("CARGO_MANIFEST_DIR")
        );
        let data = gunzip(&exav_unpack::read_fixture(&path).expect("fixture"));
        assert_eq!(detect(&data), Some(Format::Dwg), "{v}");
        let m = members(&data);
        let names: Vec<&str> = m.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["ole2frame-2F.ole"], "{v}");
        let mut doc = cfb::CompoundFile::open(Cursor::new(&m[0].data)).expect("a compound file");
        let mut zipped = Vec::new();
        doc.open_stream("/CONTENTS")
            .expect("its stream")
            .read_to_end(&mut zipped)
            .expect("read");
        let mut zip = zip::ZipArchive::new(Cursor::new(zipped)).expect("a ZIP");
        let mut file = Vec::new();
        zip.by_name("eicar.com")
            .expect("the file")
            .read_to_end(&mut file)
            .expect("read");
        assert_eq!(file, exav_unpack::eicar(), "{v}");
    }
}

/// The C4 fixtures (`fixtures/dwg/c4/`, make.py there): an OLE2FRAME
/// holding an Office document with a macro (`macros`), and one holding a
/// Packager that wraps a file (`packager`), each drawing also carrying an
/// xref block. Every version: the OLE member is there, and the
/// `dwg-metadata` member names the xref path (the application names come
/// from a drawing's proxy classes, none here). The embedded EICAR is
/// reached end to end by the exav-core test; here the carriers are checked.
#[test]
fn the_c4_fixtures_yield_their_ole_object_and_metadata() {
    for case in ["macros", "packager"] {
        for v in VERSIONS {
            let path = format!(
                "{}/tests/fixtures/dwg/c4/{case}/{v}.dwg.gz",
                env!("CARGO_MANIFEST_DIR")
            );
            let data = gunzip(&exav_unpack::read_fixture(&path).expect("fixture"));
            assert_eq!(detect(&data), Some(Format::Dwg), "{case} {v}");
            let m = members(&data);
            assert!(
                m.iter()
                    .any(|e| e.name.starts_with("ole2frame-") && e.name.ends_with(".ole")),
                "{case} {v}: the OLE2FRAME member, got {:?}",
                m.iter().map(|e| &e.name).collect::<Vec<_>>()
            );
            let meta = m
                .iter()
                .find(|e| e.name == "dwg-metadata")
                .unwrap_or_else(|| panic!("{case} {v}: no dwg-metadata member"));
            let text = String::from_utf8_lossy(&meta.data);
            assert!(
                text.contains("xref: secret-site.dwg"),
                "{case} {v}: the xref path, got {text:?}"
            );
        }
    }
}

/// The drawings of `fixtures/dwg/preview/` (make.py there: a DXF whose
/// THUMBNAILIMAGE section is the bitmap of `DIB.hex`), every version: the
/// converter made the bitmap the DWG's preview, which the opened drawing
/// lists and the container gives as `thumbnail.bmp`, the bitmap behind a
/// BMP file header.
#[test]
fn the_converters_preview_is_the_bitmap_it_was_given() {
    let hex = std::fs::read_to_string(format!(
        "{}/tests/fixtures/dwg/preview/DIB.hex",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("DIB.hex");
    let hex = hex.trim();
    let bitmap: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    for v in VERSIONS {
        let path = format!(
            "{}/tests/fixtures/dwg/preview/{v}.dwg.gz",
            env!("CARGO_MANIFEST_DIR")
        );
        let data = gunzip(&exav_unpack::read_fixture(&path).expect("fixture"));
        assert_eq!(detect(&data), Some(Format::Dwg), "{v}");
        let dwg = Dwg::open(&data).expect("opens");
        let images: Vec<(PreviewKind, &[u8])> =
            dwg.preview().iter().map(|p| (p.kind, p.data)).collect();
        assert_eq!(images, [(PreviewKind::Bmp, &bitmap[..])], "{v}");
        let m = members(&data);
        assert_eq!(m[0].name, "thumbnail.bmp", "{v}");
        assert_eq!(&m[0].data[..2], b"BM", "{v}");
        assert_eq!(&m[0].data[14..], &bitmap[..], "{v}");
    }
}

/// R2007 keeps copies of its file header and maps (spec 5.2 and 5.3): the
/// file header's block repeats in its page at 0x80 and the page is again
/// the file's last 0x400 bytes; the page map's data repeats within its page
/// (at 0x480 in the fixture, 9 times), whose second copy is at 0x880. A
/// damaged copy is passed over for one whose CRCs match.
#[test]
fn a_damaged_r2007_header_or_map_is_read_from_a_copy() {
    let (data, _) = fixtures()
        .into_iter()
        .find(|(_, v)| *v == Version::R2007)
        .expect("R2007");
    let reads = |d: &[u8], what: &str| {
        assert!(looks_like_dwg(d), "{what}");
        let dwg = Dwg::open(d).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert!(dwg.problems().is_empty(), "{what}: {:?}", dwg.problems());
        assert_eq!(
            dwg.object_map().len(),
            Dwg::open(&data).unwrap().object_map().len()
        );
    };
    let tail = data.len() - 0x400;
    // The first compressed byte of the header block's first copy, byte 0x20
    // of the first of three interleaved codewords, in both pages: the
    // block's second copy.
    let mut d = data.clone();
    d[0x80 + 3 * 0x20] ^= 0xFF;
    d[tail + 3 * 0x20] ^= 0xFF;
    reads(&d, "header copy");
    // The whole page at 0x80: the page at the end.
    let mut d = data.clone();
    d[0x80..0x480].fill(0);
    reads(&d, "header page");
    // The first byte of the page map's first copy, in both pages: the
    // data's second copy.
    let mut d = data.clone();
    d[0x480] ^= 0xFF;
    d[0x880] ^= 0xFF;
    reads(&d, "page map copy");
    // Every copy of the page map's page: the map's second page.
    let mut d = data.clone();
    d[0x480..0x880].fill(0);
    reads(&d, "page map page");
    // Without its copies the file header is not one.
    let mut d = data.clone();
    d[0x80..0x480].fill(0);
    let len = d.len();
    d[len - 0x400..].fill(0);
    assert!(!looks_like_dwg(&d));
    assert!(Dwg::open(&d).is_err());
}

#[test]
fn a_preview_yields_its_images() {
    let bitmap = dib();
    let wmf = b"\xD7\xCD\xC6\x9Aa metafile".to_vec();
    let png = b"\x89PNG\r\n\x1a\nnot really".to_vec();
    let data = with_preview(&[(1, &[0u8; 80]), (2, &bitmap), (3, &wmf), (6, &png)]);
    assert!(looks_like_dwg(&data));
    assert_eq!(detect(&data), Some(Format::Dwg));
    let m = members(&data);
    let names: Vec<&str> = m.iter().map(|e| e.name.as_str()).collect();
    // The objects, which the locators do not locate, are reported.
    assert_eq!(
        names,
        [
            "thumbnail.bmp",
            "thumbnail.wmf",
            "thumbnail.png",
            "dwg-objects"
        ]
    );
    assert!(m[3].unsupported.is_some());
    // The bitmap as a BMP file: its 14-byte header (BMP file format: `BM`,
    // file size, two reserved words, offset of the pixels), then the bitmap.
    let bmp = &m[0].data;
    assert_eq!(&bmp[..2], b"BM");
    assert_eq!(&bmp[2..6], &((14 + bitmap.len()) as u32).to_le_bytes());
    assert_eq!(&bmp[6..10], &[0; 4]);
    assert_eq!(&bmp[10..14], &(14 + 40 + 1024u32).to_le_bytes());
    assert_eq!(&bmp[14..], &bitmap[..]);
    assert_eq!(m[1].data, wmf);
    assert_eq!(m[2].data, png);
    // The locators point nowhere: the drawing does not open, its preview is
    // found all the same.
    assert!(Dwg::open(&data).is_err());
}

/// R2004 on, the preview is found the same way, from the encrypted file
/// header; a version ID alone, or R2007's over an R2004 header, is not a
/// DWG this reads.
#[test]
fn an_r2004_preview_yields_its_images() {
    let bitmap = dib();
    let png = b"\x89PNG\r\n\x1a\nnot really".to_vec();
    let data = r2004_with_preview(&[(2, &bitmap), (6, &png)]);
    assert!(looks_like_dwg(&data));
    assert_eq!(detect(&data), Some(Format::Dwg));
    let m = members(&data);
    let names: Vec<&str> = m.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["thumbnail.bmp", "thumbnail.png", "dwg-objects"]);
    assert!(m[2].unsupported.is_some());
    assert_eq!(&m[0].data[14..], &bitmap[..]);
    assert_eq!(m[1].data, png);
    assert!(Dwg::open(&data).is_err());
    // The ID string must decrypt.
    let mut bad = data.clone();
    bad[0x80] ^= 1;
    assert!(!looks_like_dwg(&bad));
    let mut r2007 = data.clone();
    r2007[..6].copy_from_slice(b"AC1021");
    assert!(!looks_like_dwg(&r2007));
    assert_ne!(detect(&r2007), Some(Format::Dwg));
}

/// The first 0x1C bytes of a DWG of a release before R13 as AutoCAD's files
/// of the local corpus have them: the version ID, zeros, a byte (1; 0 in
/// R2.10 files), `03 00 05 00`, a 16-bit number and two offsets, each the
/// values of a file of that release.
fn pre_r13_header(id: &[u8; 6], one: u8, count: u16, start: u32, end: u32) -> Vec<u8> {
    let mut h = id.to_vec();
    h.extend_from_slice(&[0; 6]);
    h.extend_from_slice(&[one, 3, 0, 5, 0]);
    h.extend_from_slice(&count.to_le_bytes());
    h.push(0);
    h.extend_from_slice(&start.to_le_bytes());
    h.extend_from_slice(&end.to_le_bytes());
    h.resize(0x200, 0);
    h
}

/// A DWG of R12 or older is a drawing exav does not read, not something
/// else: detected as DWG, refused by version, and reported to the scanner
/// as one unsupported entry rather than nothing (which scans clean).
/// `fixtures/dwg/pre-r13/R12.dwg.gz` is the ODA File Converter's R12 DWG of
/// an ezdxf drawing; the older releases are headers built as files of
/// those releases lay them out (the converter's ACAD9 and ACAD10 outputs
/// never finish).
#[test]
fn a_drawing_older_than_r13_is_reported_unsupported() {
    let r12 = gunzip(include_bytes!("../fixtures/dwg/pre-r13/R12.dwg.gz"));
    let older = [
        (pre_r13_header(b"AC1004", 1, 129, 1007, 6607), "AC1004"),
        (pre_r13_header(b"AC1003", 1, 122, 981, 81_679), "AC1003"),
        (pre_r13_header(b"AC1002", 1, 114, 929, 1107), "AC1002"),
        (pre_r13_header(b"AC2.10", 0, 83, 741, 935), "AC2.10"),
    ];
    let files = std::iter::once((r12, "AC1009")).chain(older);
    for (data, id) in files {
        assert_eq!(exav_unpack::dwg::pre_r13_version(&data), Some(id));
        assert!(!looks_like_dwg(&data), "{id}");
        assert_eq!(detect(&data), Some(Format::Dwg), "{id}");
        match Dwg::open(&data) {
            Err(exav_unpack::dwg::Error::UnsupportedVersion(v)) => assert_eq!(v, id),
            Err(e) => panic!("{id}: {e}"),
            Ok(_) => panic!("{id}: opened"),
        }
        let m = members(&data);
        assert_eq!(m.len(), 1, "{id}");
        assert_eq!(m[0].name, format!("dwg-{id}"));
        assert!(m[0].unsupported.is_some_and(|r| r.contains("before R13")));
        assert!(m[0].data.is_empty());
    }
    // A version ID alone, or entity offsets out of order, is not one.
    assert_eq!(
        exav_unpack::dwg::pre_r13_version(b"AC1009 is the version of an R12 drawing"),
        None
    );
    let swapped = pre_r13_header(b"AC1009", 1, 205, 1743, 1742);
    assert_eq!(exav_unpack::dwg::pre_r13_version(&swapped), None);
    let r13 = pre_r13_header(b"AC1012", 1, 205, 1743, 1800);
    assert_eq!(exav_unpack::dwg::pre_r13_version(&r13), None);
}

#[test]
fn the_preview_of_an_opened_drawing_lists_every_entry() {
    let (mut data, _) = fixtures()
        .into_iter()
        .find(|(_, v)| *v == Version::R2000)
        .expect("R2000");
    // Replace the converter's empty preview by one at the end of the file,
    // and point the file header at it.
    let preview = with_preview(&[(1, &[0u8; 80]), (2, &dib())]);
    // Where `with_preview` puts it: after three locators, their CRC and the
    // sentinel.
    let start = 0x19 + 9 * 3 + 2 + 16;
    let tail = &preview[start..];
    let at = data.len();
    data.extend_from_slice(tail);
    // Entry addresses are absolute: shift them to where the tail now is.
    let shift = at - start;
    for k in 0..2 {
        let p = at + 16 + 4 + 1 + 9 * k + 1;
        let v = u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize + shift;
        data[p..p + 4].copy_from_slice(&(v as u32).to_le_bytes());
    }
    data[0x0D..0x11].copy_from_slice(&(at as u32).to_le_bytes());
    let dwg = Dwg::open(&data).expect("opens");
    let kinds: Vec<PreviewKind> = dwg.preview().iter().map(|p| p.kind).collect();
    assert_eq!(kinds, [PreviewKind::Header, PreviewKind::Bmp]);
    // The patched address breaks the file header's CRC, which is said.
    assert_eq!(dwg.problems(), ["the file header's CRC does not match"]);
    let names: Vec<String> = members(&data).into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["thumbnail.bmp"]);
}

#[test]
fn a_preview_entry_past_the_end_is_left_out() {
    let mut data = with_preview(&[(2, &dib())]);
    data.truncate(data.len() - 100);
    let names: Vec<String> = members(&data).into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["dwg-objects"]);
}

/// Cut short or with bits flipped, a file is opened, walked and extracted
/// without a panic.
#[test]
fn damaged_files_do_not_panic() {
    let walk = |data: &[u8]| {
        let _ = detect(&data);
        let mut budget = Budget::new(Limits::default());
        let _ = extract(Format::Dwg, &data, &mut budget);
        if let Ok(dwg) = Dwg::open(data) {
            for &(h, _) in dwg.object_map() {
                if let Some(Ok(mut o)) = dwg.object(h) {
                    while o.handle_ref().is_ok() {}
                    let _ = o.tv();
                }
            }
        }
    };
    let ole = ["R13", "R2000", "R2004", "R2007", "R2018"].map(|v| {
        let path = format!(
            "{}/tests/fixtures/dwg/ole/{v}.dwg.gz",
            env!("CARGO_MANIFEST_DIR")
        );
        gunzip(&exav_unpack::read_fixture(&path).expect("fixture"))
    });
    for data in fixtures().into_iter().map(|(d, _)| d).chain(ole) {
        for cut in (0..data.len()).step_by(97) {
            walk(&data[..cut]);
        }
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..500 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let mut b = data.clone();
            let at = (seed as usize) % b.len();
            b[at] ^= 1 << (seed >> 61);
            walk(&b);
        }
    }
}
