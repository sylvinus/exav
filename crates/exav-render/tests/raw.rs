//! Camera RAW files, shown by their embedded previews: synthetic containers of
//! each family (tests/fixtures/raw/make.py), whose previews are four colour
//! quadrants, so that what was chosen and how it was turned shows in the
//! pixels. Hostile files are those fixtures with a field patched.
#![cfg(feature = "raw")]

use std::cell::Cell;
use std::sync::Once;
use std::time::{Duration, Instant};

use exav_render::image::raw::{self, Kind};
use exav_render::image::{decode, decode_any, Error, Format, Pixels, Samples, DECODE_MAX};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/raw/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

thread_local!(static PANICKED: Cell<bool> = const { Cell::new(false) });

/// Records a panic on this thread, which the readers would otherwise turn
/// into `Undecodable` without a trace.
fn watch_panics() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            PANICKED.with(|p| p.set(true));
            previous(info);
        }));
    });
    PANICKED.with(|p| p.set(false));
}

fn panicked() -> bool {
    PANICKED.with(|p| p.get())
}

fn rgb(p: &Pixels) -> &[u8] {
    assert_eq!(p.channels.count(), 3, "RGB pixels expected");
    match &p.samples {
        Samples::U8(v) => v,
        other => panic!("8-bit samples expected, got {other:?}"),
    }
}

/// The pixel at the middle of quadrant (`qx`, `qy`), each 0 or 1.
fn quadrant(p: &Pixels, qx: usize, qy: usize) -> [u8; 3] {
    let (w, h) = (p.width as usize, p.height as usize);
    let (x, y) = (w / 4 + qx * w / 2, h / 4 + qy * h / 2);
    let at = (y * w + x) * 3;
    rgb(p)[at..at + 3].try_into().unwrap()
}

const RED: [u8; 3] = [255, 0, 0];
const GREEN: [u8; 3] = [0, 255, 0];
const BLUE: [u8; 3] = [0, 0, 255];
const YELLOW: [u8; 3] = [255, 255, 0];

/// Within JPEG's loss of the four colours.
fn is_colour(got: [u8; 3], want: [u8; 3]) -> bool {
    got.iter().zip(want).all(|(&g, w)| g.abs_diff(w) < 40)
}

/// The quadrants as seen, top left, top right, bottom left, bottom right.
fn quadrants(p: &Pixels) -> [[u8; 3]; 4] {
    [
        quadrant(p, 0, 0),
        quadrant(p, 1, 0),
        quadrant(p, 0, 1),
        quadrant(p, 1, 1),
    ]
}

fn assert_quadrants(p: &Pixels, want: [[u8; 3]; 4], what: &str) {
    let got = quadrants(p);
    for (g, w) in got.iter().zip(want) {
        assert!(is_colour(*g, w), "{what}: got {got:?}, want {want:?}");
    }
}

const AS_STORED: [[u8; 3]; 4] = [RED, GREEN, BLUE, YELLOW];

fn open(name: &str) -> (Pixels, raw::Info) {
    raw::preview(&fixture(name), DECODE_MAX).unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn every_family_is_detected_by_its_bytes() {
    let cases = [
        ("preview-jpeg.dng", Kind::Dng),
        ("preview-rgb.dng", Kind::Dng),
        ("no-preview.dng", Kind::Dng),
        ("canon.cr2", Kind::Cr2),
        ("canon-o1.cr3", Kind::Cr3),
        ("canon-heif.cr3", Kind::Cr3),
        ("canon.crw", Kind::Crw),
        ("nikon.nef", Kind::TiffEp),
        ("sony.arw", Kind::TiffEp),
        ("pentax.pef", Kind::TiffEp),
        ("samsung.srw", Kind::TiffEp),
        ("hasselblad.3fr", Kind::TiffEp),
        ("sony-thumbnail.srf", Kind::TiffEp),
        ("kodak16-be.dcr", Kind::TiffEp),
        ("olympus.orf", Kind::Orf),
        ("olympus-rs.orf", Kind::Orf),
        ("olympus-be.orf", Kind::Orf),
        ("panasonic.rw2", Kind::Rw2),
        ("panasonic-no-preview.rw2", Kind::Rw2),
        ("phaseone.iiq", Kind::Iiq),
        ("fujifilm-o1.raf", Kind::Raf),
        ("sigma.x3f", Kind::X3f),
        ("minolta.mrw", Kind::Mrw),
    ];
    for (file, kind) in cases {
        assert_eq!(raw::detect(&fixture(file)), Some(kind), "{file}");
    }
}

/// What no maker's name goes with, TIFF-structured, is RAW by its sensor data
/// alone: each compression the makers number, a colour filter array by its
/// photometric or its tags, and the DNGPrivateData tag.
#[test]
fn sensor_data_alone_makes_a_tiff_a_raw_file() {
    let files = [
        "compression-99.tif",
        "compression-32767.tif",
        "compression-32769.tif",
        "compression-32772.tif",
        "compression-34713.tif",
        "compression-65000.tif",
        "compression-65535.tif",
        "photometric-cfa-only.tif",
        "cfa-tags-only.tif",
        "private-data-only.tif",
    ];
    for file in files {
        let data = fixture(file);
        assert_eq!(raw::detect(&data), Some(Kind::TiffEp), "{file}");
        let (p, info) = open(file);
        assert_eq!((p.width, p.height, info.jpeg), (16, 12, false), "{file}");
    }
    // The same file without its sensor data is the TIFF it looks like.
    assert_eq!(raw::detect(&fixture("plain.tif")), None);
}

/// A camera maker's name next to a camera's structure is enough, whatever the
/// case it is written in, for each maker; another name is not.
#[test]
fn a_camera_makers_name_beside_a_subifd_makes_a_tiff_a_raw_file() {
    let base = fixture("hasselblad.3fr");
    let ifd0 = first_ifd(&base);
    let make = entry(&base, ifd0, 0x10F);
    let at = u32_at(&base, make + 8, true);
    let makes = [
        "CANON",
        "Nikon",
        "SONY",
        "olympus",
        "PANASONIC",
        "Leica",
        "FUJIFILM",
        "PENTAX",
        "RICOH",
        "SAMSUNG",
        "KODAK",
        "EPSON",
        "MINOLTA",
        "MAMIYA",
        "LEAF",
        "PHASE ONE",
        "HASSELBLAD",
        "CASIO",
        "SIGMA",
    ];
    for name in makes {
        let mut d = base.clone();
        d[at..at + 11].fill(0);
        d[at..at + name.len()].copy_from_slice(name.as_bytes());
        assert_eq!(raw::detect(&d), Some(Kind::TiffEp), "{name}");
    }
    for name in ["ACME", "Adobe", "GIMP", ""] {
        let mut d = base.clone();
        d[at..at + 11].fill(0);
        d[at..at + name.len()].copy_from_slice(name.as_bytes());
        assert_eq!(raw::detect(&d), None, "{name}");
    }
}

/// Only a few JPEG start markers are tried, so that a file of nothing but
/// those costs a bounded time: a preview the directories name is found
/// whatever comes before it.
#[test]
fn a_preview_the_directories_name_is_found_past_a_crowd_of_start_markers() {
    let (p, info) = open("many-markers.dng");
    assert_eq!((p.width, p.height, info.found), (64, 48, 1));
}

/// The file name's extension says nothing: only the bytes are read.
#[test]
fn detection_ignores_the_name_and_the_tail() {
    // A prefix is all a signature needs, and a cut-off file still says what
    // it is.
    assert_eq!(
        raw::detect(&fixture("fujifilm-o1.raf")[..40]),
        Some(Kind::Raf)
    );
    assert_eq!(raw::detect(&fixture("canon-o1.cr3")[..40]), Some(Kind::Cr3));
    assert_eq!(raw::detect(b""), None);
    assert_eq!(raw::detect(b"II*\0"), None);
}

/// A TIFF stays a TIFF: the TIFF decoder reads it, `raw` does not claim it,
/// even with a camera maker's name in it.
#[test]
fn a_plain_tiff_is_not_a_raw_file() {
    for file in ["plain.tif", "plain-with-make.tif"] {
        let tiff = fixture(file);
        assert_eq!(raw::detect(&tiff), None, "{file}");
        assert_eq!(Format::detect(&tiff), Some(Format::Tiff), "{file}");
        let via_any = decode_any(&tiff, DECODE_MAX).unwrap();
        let direct = decode(&tiff, Format::Tiff, DECODE_MAX).unwrap();
        assert_eq!(via_any, direct, "{file}");
        assert_eq!((via_any.width, via_any.height), (16, 12), "{file}");
        assert_quadrants(&via_any, AS_STORED, file);
    }
}

/// A camera's structure and no preview, with nothing else to say it is RAW:
/// `raw` leaves it to the TIFF decoder, which is what the file may be.
#[test]
fn a_tiff_with_a_camera_structure_and_no_preview_is_left_to_the_tiff_decoder() {
    let tiff = fixture("camera-structure-no-preview.tif");
    assert_eq!(raw::detect(&tiff), Some(Kind::TiffEp));
    assert_eq!(raw::decode(&tiff, DECODE_MAX), Err(Error::Unsupported));
    assert_eq!(
        decode_any(&tiff, DECODE_MAX),
        decode(&tiff, Format::Tiff, DECODE_MAX)
    );
    assert_ne!(decode_any(&tiff, DECODE_MAX), Err(Error::NoPreview));
}

#[test]
fn a_dng_shows_its_largest_preview() {
    // A 16 by 12 uncompressed thumbnail in the first directory, a 64 by 48
    // JPEG in a SubIFD, sensor data (lossless JPEG) in another.
    let (p, info) = open("preview-jpeg.dng");
    assert_eq!((p.width, p.height), (64, 48));
    assert_eq!(
        info,
        raw::Info {
            kind: Kind::Dng,
            width: 64,
            height: 48,
            orientation: 1,
            jpeg: true,
            found: 2,
        }
    );
    assert_quadrants(&p, AS_STORED, "preview-jpeg.dng");
}

#[test]
fn decode_any_shows_a_tiff_structured_raw_by_its_preview() {
    // `Format::detect` reads the first bytes as TIFF, as `exav-imagehash`
    // must; `decode_any` is the one that knows the file is a RAW.
    for (file, size) in [
        ("preview-jpeg.dng", (64, 48)),
        ("nikon.nef", (80, 48)),
        ("sony.arw", (72, 48)),
        ("canon.cr2", (96, 64)),
        ("pentax.pef", (88, 56)),
    ] {
        let data = fixture(file);
        assert_eq!(Format::detect(&data), Some(Format::Tiff), "{file}");
        let p = decode_any(&data, DECODE_MAX).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!((p.width, p.height), size, "{file}");
        assert_quadrants(&p, AS_STORED, file);
    }
    // The formats no TIFF decoder reads (`detect` knows none of them).
    for (file, size) in [
        ("olympus.orf", (104, 72)),
        ("panasonic.rw2", (112, 64)),
        ("fujifilm-o1.raf", (64, 48)),
        ("canon-o1.cr3", (128, 96)),
        ("sigma.x3f", (80, 56)),
        ("canon.crw", (72, 48)),
    ] {
        let data = fixture(file);
        assert_eq!(Format::detect(&data), None, "{file}");
        let p = decode_any(&data, DECODE_MAX).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!((p.width, p.height), size, "{file}");
        assert_quadrants(&p, AS_STORED, file);
    }
}

/// The families keep their previews in different places: a SubIFD, the first
/// directory, a maker note, a tag nothing documents, a box, a section.
#[test]
fn each_family_gives_the_preview_where_it_keeps_it() {
    let cases = [
        ("canon.cr2", 96, 64, true),
        ("nikon.nef", 80, 48, true),
        ("sony.arw", 72, 48, true),
        ("pentax.pef", 88, 56, true),
        ("samsung.srw", 56, 40, true),
        ("olympus.orf", 104, 72, true),
        ("olympus-rs.orf", 104, 72, true),
        ("olympus-be.orf", 104, 72, true),
        ("panasonic.rw2", 112, 64, true),
        ("fujifilm-o1.raf", 64, 48, true),
        ("canon-o1.cr3", 128, 96, true),
        ("sigma.x3f", 80, 56, true),
        ("canon.crw", 72, 48, true),
        ("hasselblad.3fr", 32, 24, false),
        ("phaseone.iiq", 24, 16, false),
    ];
    for (file, w, h, jpeg) in cases {
        let (p, info) = open(file);
        assert_eq!((info.width, info.height, info.jpeg), (w, h, jpeg), "{file}");
        assert_eq!((p.width, p.height), (w, h), "{file}");
        assert_quadrants(&p, AS_STORED, file);
    }
}

#[test]
fn a_progressive_preview_decodes() {
    let (p, _) = open("progressive.dng");
    assert_eq!((p.width, p.height), (48, 32));
    assert_quadrants(&p, AS_STORED, "progressive.dng");
}

#[test]
fn uncompressed_previews_are_read_whatever_their_depth_and_byte_order() {
    let (p, info) = open("preview-grey.dng");
    assert_eq!((p.width, p.height, p.channels.count()), (16, 12, 1));
    assert!(!info.jpeg);
    for file in ["kodak16-be.dcr", "kodak16-le.dcr"] {
        let (p, info) = open(file);
        assert_eq!((p.width, p.height), (16, 12), "{file}");
        assert!(!info.jpeg, "{file}");
        assert_quadrants(&p, AS_STORED, file);
        // The high byte of each 16-bit sample.
        assert!(matches!(&p.samples, Samples::U8(_)), "{file}");
    }
}

/// Lossy DNG compresses its sensor data as baseline JPEG, which is no
/// preview, here larger than the real one.
#[test]
fn sensor_data_is_not_taken_for_a_preview_even_as_a_baseline_jpeg() {
    let (p, info) = open("lossy-linear.dng");
    assert_eq!((p.width, p.height), (48, 32));
    assert_eq!(info.found, 1);
}

/// Where the preview is turned by the orientation of the file: the first
/// directory's, or the JPEG's own Exif when it has one.
#[test]
fn the_orientation_is_applied_from_where_it_is_written() {
    // IFD0 says 6 (a rotation a quarter turn clockwise) for a RGB preview.
    let (p, info) = open("preview-rgb.dng");
    assert_eq!((info.width, info.height, info.orientation), (32, 24, 6));
    assert_eq!((p.width, p.height), (24, 32));
    assert_quadrants(&p, [BLUE, RED, YELLOW, GREEN], "preview-rgb.dng");
    // The JPEG's own Exif says 6 and IFD0 says 3: the JPEG's is the one.
    let (p, info) = open("orientation-own.dng");
    assert_eq!(info.orientation, 6);
    assert_quadrants(&p, [BLUE, RED, YELLOW, GREEN], "orientation-own.dng");
    // A CR3 keeps it in the CMT1 box of `moov`, not in its JPEGs.
    let (p, info) = open("canon-o8.cr3");
    assert_eq!(info.orientation, 8);
    assert_eq!((p.width, p.height), (96, 128));
    assert_quadrants(&p, [GREEN, YELLOW, RED, BLUE], "canon-o8.cr3");
    assert_eq!(open("canon-o1.cr3").1.orientation, 1);
}

/// All eight, from the JPEG's own Exif, against what the Exif specification
/// says each value is.
#[test]
fn all_eight_orientations_turn_the_picture_as_exif_defines_them() {
    let [tl, tr, bl, br] = AS_STORED;
    // The quadrants as seen after each value, row by row.
    let want = [
        [tl, tr, bl, br],
        [tr, tl, br, bl],
        [br, bl, tr, tl],
        [bl, br, tl, tr],
        [tl, bl, tr, br],
        [bl, tl, br, tr],
        [br, tr, bl, tl],
        [tr, br, tl, bl],
    ];
    for (i, want) in want.into_iter().enumerate() {
        let o = i + 1;
        let (p, info) = open(&format!("fujifilm-o{o}.raf"));
        assert_eq!(info.orientation as usize, o);
        let swapped = o >= 5;
        let size = if swapped { (48, 64) } else { (64, 48) };
        assert_eq!((p.width, p.height), size, "orientation {o}");
        assert_quadrants(&p, want, &format!("orientation {o}"));
    }
}

/// A CR3 holds a thumbnail (THMB), a preview (PRVW) and the full-size JPEG
/// at the start of `mdat`, whose box has a 64-bit size.
#[test]
fn a_cr3_gives_the_full_size_jpeg_when_the_budget_allows_it() {
    let data = fixture("canon-o1.cr3");
    let (p, info) = raw::preview(&data, DECODE_MAX).unwrap();
    assert_eq!((info.kind, info.found, info.jpeg), (Kind::Cr3, 3, true));
    assert_eq!((p.width, p.height), (128, 96));
    // 4 bytes a pixel: 96 by 64 fits, 128 by 96 does not.
    let (p, info) = raw::preview(&data, 96 * 64 * 4).unwrap();
    assert_eq!((info.found, p.width, p.height), (3, 96, 64));
    let (p, _) = raw::preview(&data, 16 * 12 * 4).unwrap();
    assert_eq!((p.width, p.height), (16, 12));
}

#[test]
fn a_file_with_no_preview_says_so() {
    for file in [
        "no-preview.dng",
        "panasonic-no-preview.rw2",
        "minolta.mrw",
        "canon-heif.cr3",
    ] {
        let data = fixture(file);
        assert!(raw::detect(&data).is_some(), "{file}");
        assert_eq!(
            raw::decode(&data, DECODE_MAX),
            Err(Error::NoPreview),
            "{file}"
        );
        assert_eq!(
            decode_any(&data, DECODE_MAX),
            Err(Error::NoPreview),
            "{file}"
        );
    }
    assert_eq!(
        Error::NoPreview.to_string(),
        "camera RAW file with no preview to show"
    );
}

#[test]
fn what_is_not_a_raw_file_is_unsupported() {
    assert_eq!(raw::decode(b"", DECODE_MAX), Err(Error::Unsupported));
    assert_eq!(
        raw::decode(b"just some text, not a camera file", DECODE_MAX),
        Err(Error::Unsupported)
    );
    // A JPEG is an image, not a RAW file with a preview.
    assert_eq!(
        raw::decode(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 2], DECODE_MAX),
        Err(Error::Unsupported)
    );
}

/// The budget is on what the page holds, as RGBA (four bytes a pixel, six when
/// the picture must be turned): a preview over it is passed by for a smaller
/// one, and the error says it is the size when there is none.
#[test]
fn a_preview_over_the_budget_gives_way_to_a_smaller_one() {
    let data = fixture("preview-jpeg.dng");
    // 64 by 48 is 12,288 bytes; 16 by 12 is 768.
    let (p, _) = raw::preview(&data, 12_288).unwrap();
    assert_eq!((p.width, p.height), (64, 48));
    let (p, info) = raw::preview(&data, 12_287).unwrap();
    assert_eq!((p.width, p.height), (16, 12));
    assert!(!info.jpeg);
    assert_eq!(raw::decode(&data, 767), Err(Error::TooLarge));
    assert_eq!(decode_any(&data, 767), Err(Error::TooLarge));
    // Turned, the same preview needs six bytes a pixel.
    let turned = fixture("preview-rgb.dng");
    assert_eq!(raw::preview(&turned, 32 * 24 * 6).unwrap().1.width, 32);
    assert_eq!(raw::preview(&turned, 32 * 24 * 6 - 1).unwrap().1.width, 16);
    // A limit over the decoder's own is the decoder's.
    assert!(raw::decode(&data, u64::MAX).is_ok());
}

fn u16_at(d: &[u8], at: usize, le: bool) -> usize {
    let b = [d[at], d[at + 1]];
    usize::from(if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    })
}

fn u32_at(d: &[u8], at: usize, le: bool) -> usize {
    let b = [d[at], d[at + 1], d[at + 2], d[at + 3]];
    (if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    }) as usize
}

fn put_u32(d: &mut [u8], at: usize, v: u32, le: bool) {
    d[at..at + 4].copy_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
}

/// Offsets of the entries (tag, offset of the entry) of the directory at `ifd`.
fn entries(d: &[u8], ifd: usize) -> Vec<(u16, usize)> {
    let le = d[0] == b'I';
    (0..u16_at(d, ifd, le))
        .map(|k| {
            let at = ifd + 2 + k * 12;
            (u16_at(d, at, le) as u16, at)
        })
        .collect()
}

fn first_ifd(d: &[u8]) -> usize {
    u32_at(d, 4, d[0] == b'I')
}

fn entry(d: &[u8], ifd: usize, tag: u16) -> usize {
    entries(d, ifd)
        .into_iter()
        .find(|e| e.0 == tag)
        .unwrap_or_else(|| panic!("no tag {tag:#x}"))
        .1
}

/// No hostile input may hang or panic: each of these has some preview or
/// none, and answers in a bounded time.
fn assert_survives(data: &[u8], what: &str) -> Result<(Pixels, raw::Info), Error> {
    watch_panics();
    let started = Instant::now();
    let r = raw::preview(data, 64 << 20);
    assert!(!panicked(), "{what}: panicked");
    assert!(started.elapsed() < Duration::from_secs(2), "{what}: slow");
    r
}

#[test]
fn a_chain_of_directories_that_loops_is_read_once() {
    // IFD0 of the CR2 chained to itself.
    let mut d = fixture("canon.cr2");
    let ifd0 = first_ifd(&d);
    let le = true;
    let next = ifd0 + 2 + u16_at(&d, ifd0, le) * 12;
    put_u32(&mut d, next, ifd0 as u32, le);
    let (p, info) = assert_survives(&d, "chain loop").unwrap();
    assert_eq!((p.width, p.height), (96, 64));
    // The JPEG of the directory, once, and the thumbnail found by its marker.
    assert_eq!(info.found, 2);
    // And the SubIFD list of a DNG pointing back at its first directory.
    let mut d = fixture("preview-jpeg.dng");
    let ifd0 = first_ifd(&d);
    let sub = entry(&d, ifd0, 0x14A);
    let list = u32_at(&d, sub + 8, true);
    put_u32(&mut d, list, ifd0 as u32, true);
    let (p, info) = assert_survives(&d, "subifd loop").unwrap();
    assert_eq!((p.width, p.height), (64, 48));
    // The first directory's thumbnail, once, and the JPEG.
    assert_eq!(info.found, 2);
}

#[test]
fn offsets_and_counts_past_the_data_are_refused_not_followed() {
    // A strip that starts past the end: the other preview is used.
    let mut d = fixture("preview-rgb.dng");
    let ifd0 = first_ifd(&d);
    let strips = entry(&d, ifd0, 0x111);
    put_u32(&mut d, strips + 8, u32::MAX - 3, false);
    let (p, info) = assert_survives(&d, "strip offset").unwrap();
    assert_eq!(info.width, 32);
    assert_eq!(p.width, 24);
    // A strip whose length runs past the end of the data.
    let mut d = fixture("preview-rgb.dng");
    let counts = entry(&d, ifd0, 0x117);
    put_u32(&mut d, counts + 8, u32::MAX, false);
    let (_, info) = assert_survives(&d, "strip length").unwrap();
    assert_eq!(info.width, 32);
    // A count of values that does not fit: the entry is not read.
    let mut d = fixture("preview-rgb.dng");
    let bits = entry(&d, ifd0, 0x102);
    put_u32(&mut d, bits + 4, u32::MAX, false);
    let _ = assert_survives(&d, "count");
    // Every preview's strips gone: there is none, which is no crash.
    let mut d = fixture("preview-rgb.dng");
    for ifd in [ifd0] {
        for tag in [0x111, 0x117] {
            let e = entry(&d, ifd, tag);
            put_u32(&mut d, e + 8, u32::MAX - 3, false);
        }
    }
    let sub_list = u32_at(&d, entry(&d, ifd0, 0x14A) + 8, false);
    for k in 0..2 {
        let sub = u32_at(&d, sub_list + 4 * k, false);
        for tag in [0x111, 0x117] {
            if let Some(e) = entries(&d, sub).into_iter().find(|e| e.0 == tag) {
                put_u32(&mut d, e.1 + 8, u32::MAX - 3, false);
            }
        }
    }
    assert_eq!(
        assert_survives(&d, "no strips").err(),
        Some(Error::NoPreview)
    );
}

#[test]
fn a_directory_with_more_entries_than_the_file_holds_is_skipped() {
    let mut d = fixture("canon.cr2");
    let ifd0 = first_ifd(&d);
    d[ifd0..ifd0 + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    // The first directory cannot be read: the JPEG streams are still found
    // where they lie.
    let (p, _) = assert_survives(&d, "entry count").unwrap();
    assert_eq!((p.width, p.height), (96, 64));
}

#[test]
fn a_preview_declared_enormous_is_not_allocated() {
    // The uncompressed preview claims 65,000 by 65,000 and has a few bytes.
    let mut d = fixture("preview-rgb.dng");
    let ifd0 = first_ifd(&d);
    for tag in [0x100, 0x101] {
        let e = entry(&d, ifd0, tag);
        put_u32(&mut d, e + 8, 65_000, false);
    }
    let (_, info) = assert_survives(&d, "declared size").unwrap();
    assert_eq!(info.width, 32);
    // JPEG streams too: a frame header that says 65,535 by 65,535.
    let mut d = fixture("fujifilm-o1.raf");
    let sof = d.windows(2).position(|w| w == [0xFF, 0xC0]).unwrap();
    d[sof + 5..sof + 9].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    // Past a limit that is the caller's, it is a size; past the decoder's own,
    // the image is undecodable.
    assert_eq!(
        assert_survives(&d, "frame size").err(),
        Some(Error::TooLarge)
    );
    assert_eq!(raw::decode(&d, DECODE_MAX).err(), Some(Error::Undecodable));
}

/// An uncompressed preview is read when it is stored as TIFF stores it,
/// chunky: a planar one is not taken for one.
#[test]
fn a_planar_uncompressed_preview_is_not_read() {
    let mut d = fixture("preview-rgb.dng");
    let ifd0 = first_ifd(&d);
    let sub_list = u32_at(&d, entry(&d, ifd0, 0x14A) + 8, false);
    let sub = u32_at(&d, sub_list + 4, false);
    let planar = entry(&d, sub, 0x11C);
    d[planar + 8..planar + 10].copy_from_slice(&2u16.to_be_bytes());
    let (_, info) = raw::preview(&d, DECODE_MAX).unwrap();
    assert_eq!((info.width, info.found), (16, 1));
}

#[test]
fn a_file_made_of_start_markers_costs_a_bounded_time() {
    // A start marker every eight bytes, each followed by comment segments
    // that run through every start marker after it and never reach a frame:
    // read in full, each costs a walk of the rest of the file.
    let mut d = b"FUJIFILMCCD-RAW ".to_vec();
    d.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x06, 0, 0].repeat(8 << 20));
    let r = assert_survives(&d, "start markers");
    assert_eq!(r.err(), Some(Error::NoPreview));
}

#[test]
fn every_truncation_of_every_fixture_is_answered() {
    watch_panics();
    let dir = format!("{}/tests/fixtures/raw", env!("CARGO_MANIFEST_DIR"));
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "py") {
            continue;
        }
        let data = std::fs::read(&path).unwrap();
        for cut in (0..data.len()).step_by(7) {
            let _ = raw::preview(&data[..cut], 64 << 20);
            let _ = decode_any(&data[..cut], 64 << 20);
            assert!(!panicked(), "{} cut at {cut}", path.display());
        }
    }
}

#[test]
fn bytes_flipped_in_a_fixture_never_panic() {
    watch_panics();
    for file in [
        "canon.cr2",
        "nikon.nef",
        "preview-jpeg.dng",
        "canon-o8.cr3",
        "olympus.orf",
    ] {
        let data = fixture(file);
        for at in 0..data.len().min(400) {
            for v in [0x00, 0xFF, 0x7F, 0x80] {
                let mut d = data.clone();
                d[at] = v;
                let _ = raw::preview(&d, 64 << 20);
                assert!(!panicked(), "{file} byte {at} = {v:#x}");
            }
        }
    }
}
