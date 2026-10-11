//! JPEG 2000, JBIG2 and CCITT fax, decoded and compared with the pictures
//! independent encoders were given (tests/fixtures/images/make.py).
#![cfg(all(
    feature = "image",
    feature = "jp2",
    feature = "jbig2",
    feature = "ccitt"
))]

use std::cell::Cell;
use std::sync::Once;

use exav_render::image::{
    decode, decode_any, Channels, Error, Format, Pixels, Samples, DECODE_MAX,
};
use exav_render::pdf_image::{decode_ccitt, decode_jbig2, decode_jpx, CcittParams, JpxParams};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/images/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn source(name: &str) -> Pixels {
    decode_any(&fixture(name), DECODE_MAX).expect("the source PNG")
}

fn bytes(p: &Pixels) -> &[u8] {
    match &p.samples {
        Samples::U8(v) => v,
        other => panic!("8-bit samples expected, got {other:?}"),
    }
}

thread_local!(static PANICKED: Cell<bool> = const { Cell::new(false) });

/// Records a panic on this thread, which `decode` would otherwise turn into
/// `Undecodable` without a trace.
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

#[test]
fn lossless_jpeg_2000_gives_back_the_encoded_pixels() {
    for (file, png, channels) in [
        ("rgb.jp2", "rgb.png", Channels::Rgb),
        ("rgb.j2k", "rgb.png", Channels::Rgb),
        ("grey.j2k", "grey.png", Channels::Luma),
        ("rgba.jp2", "rgba.png", Channels::Rgba),
    ] {
        let want = source(png);
        assert_eq!(want.channels, channels, "{png}");
        let got = decode_any(&fixture(file), DECODE_MAX).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(
            (got.width, got.height, got.channels),
            (want.width, want.height, channels),
            "{file}"
        );
        assert_eq!(bytes(&got), bytes(&want), "{file}");
    }
}

/// The bilevel source as 8-bit grey: 0 black, 255 white.
fn bilevel() -> Pixels {
    let p = source("bilevel.png");
    assert_eq!(p.channels, Channels::Luma);
    p
}

#[test]
fn jbig2_files_of_both_organisations_give_back_the_encoded_page() {
    let want = bilevel();
    for file in ["generic.jb2", "generic-random.jb2"] {
        let got = decode_any(&fixture(file), DECODE_MAX).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(
            (got.width, got.height, got.channels),
            (want.width, want.height, Channels::Luma),
            "{file}"
        );
        assert_eq!(bytes(&got), bytes(&want), "{file}");
    }
}

/// jbig2enc's symbol coder places some symbols a row above where they were
/// (pdf.js's PDFium decoder draws this file the same way): the page has the
/// source's black pixels, a few of them moved.
#[test]
fn a_symbol_coded_jbig2_file_draws_the_symbols_of_the_page() {
    let want = bilevel();
    let got = decode_any(&fixture("symbol.jb2"), DECODE_MAX).unwrap();
    assert_eq!((got.width, got.height), (want.width, want.height));
    let black = |p: &Pixels| bytes(p).iter().filter(|&&v| v == 0).count();
    assert_eq!(black(&got), black(&want));
    let differ = bytes(&got)
        .iter()
        .zip(bytes(&want))
        .filter(|(a, b)| a != b)
        .count();
    assert!(differ * 8 < bytes(&want).len(), "{differ} pixels differ");
    // The same stream, as a PDF embeds it, gives the same page.
    let embedded = decode_jbig2(
        &fixture("symbol.jb2")[13..],
        want.width,
        want.height,
        None,
        1 << 30,
    )
    .unwrap();
    assert_eq!(embedded, packed(&got));
}

#[test]
fn each_format_is_known_by_its_first_bytes() {
    for (file, format) in [
        ("rgb.jp2", Format::Jpeg2000),
        ("rgb.j2k", Format::Jpeg2000),
        ("generic.jb2", Format::Jbig2),
        ("generic-random.jb2", Format::Jbig2),
    ] {
        assert_eq!(Format::detect(&fixture(file)), Some(format), "{file}");
    }
    assert_eq!(Format::Jpeg2000.name(), "jpeg2000");
    assert_eq!(Format::Jbig2.name(), "jbig2");
    assert!(Format::ALL.contains(&Format::Jpeg2000) && Format::ALL.contains(&Format::Jbig2));
    // A JBIG2 stream without the file header (as embedded in a PDF) is not a
    // file.
    assert_eq!(Format::detect(&fixture("generic.jb2")[13..]), None);
}

#[test]
fn a_file_of_several_jbig2_pages_is_refused_rather_than_drawn_merged() {
    let mut file = fixture("generic.jb2");
    // The header's page count, after the ID and the flags.
    file[9..13].copy_from_slice(&2u32.to_be_bytes());
    assert_eq!(
        decode_any(&file, DECODE_MAX).unwrap_err(),
        Error::Undecodable
    );
}

/// Every prefix, and every byte inverted in turn: an error or a picture,
/// never a panic.
#[test]
fn damaged_files_are_errors_not_panics() {
    watch_panics();
    for file in [
        "rgb.jp2",
        "rgb.j2k",
        "grey.j2k",
        "rgba.jp2",
        "generic.jb2",
        "generic-random.jb2",
        "symbol.jb2",
    ] {
        let data = fixture(file);
        for cut in 0..data.len() {
            let _ = decode_any(&data[..cut], DECODE_MAX);
            assert!(!panicked(), "{file} cut at {cut}");
        }
        for at in 0..data.len() {
            let mut d = data.clone();
            d[at] ^= 0xFF;
            let _ = decode_any(&d, 16 << 20);
            assert!(!panicked(), "{file} with byte {at} inverted");
        }
        assert_eq!(
            decode_any(&data[..data.len() / 2], DECODE_MAX).map(|_| ()),
            Err(Error::Undecodable),
            "{file} cut in half"
        );
    }
}

/// The same for pdf.js's decoders, which do not catch panics: in the
/// viewer's WebAssembly a panic traps the module.
#[test]
fn damaged_pdf_streams_are_errors_not_panics() {
    let mangled = |data: &[u8]| {
        let mut all: Vec<Vec<u8>> = (0..data.len()).map(|cut| data[..cut].to_vec()).collect();
        all.extend((0..data.len()).map(|at| {
            let mut d = data.to_vec();
            d[at] ^= 0xFF;
            d
        }));
        all
    };
    for file in ["rgb.jp2", "rgb.j2k", "rgba.jp2"] {
        for d in mangled(&fixture(file)) {
            for num_components in [0, 1, 3, 4] {
                let p = JpxParams {
                    num_components,
                    indexed: num_components == 1,
                    smask_in_data: num_components == 0,
                    reduce_power: 0,
                };
                let _ = decode_jpx(&d, p, 16 << 20);
            }
        }
    }
    for file in ["generic.jb2", "symbol.jb2"] {
        for d in mangled(&fixture(file)[13..]) {
            let _ = decode_jbig2(&d, 83, 37, None, 16 << 20);
        }
    }
    for (file, k) in [
        ("bilevel.g4", -1),
        ("bilevel.g3-1d", 0),
        ("bilevel.g3-2d", 1),
        ("bilevel.g3-fill", 0),
        ("bilevel.rle", 0),
    ] {
        for d in mangled(&fixture(file)) {
            for align in [false, true] {
                let p = CcittParams {
                    width: 83,
                    height: 37,
                    k,
                    end_of_line: k >= 0,
                    encoded_byte_align: align,
                    black_is_1: false,
                    columns: 83,
                    rows: 0,
                };
                let _ = decode_ccitt(&d, p, 16 << 20);
            }
        }
    }
}

/// A codestream whose size and single tile are 60000 by 60000.
fn huge_codestream() -> Vec<u8> {
    let mut cs = fixture("rgb.j2k");
    // SOC, then SIZ: marker, Lsiz, Rsiz, Xsiz, Ysiz, XOsiz, YOsiz, XTsiz, YTsiz.
    for at in [8, 12, 24, 28] {
        cs[at..at + 4].copy_from_slice(&60_000u32.to_be_bytes());
    }
    cs
}

/// A JBIG2 file whose page is 65535 by 65535.
fn huge_page() -> Vec<u8> {
    let mut file = fixture("generic.jb2");
    // The file header, then the page information segment's header.
    assert_eq!(file[13 + 4] & 0x3F, 48, "page information first");
    file[24..28].copy_from_slice(&65_535u32.to_be_bytes());
    file[28..32].copy_from_slice(&65_535u32.to_be_bytes());
    file
}

/// Decoding either would take gigabytes: refused from the declared size,
/// before anything is allocated for the pixels.
#[test]
fn a_huge_declared_size_is_refused_before_decoding() {
    for (what, data, format) in [
        ("jpeg 2000", huge_codestream(), Format::Jpeg2000),
        ("jbig2", huge_page(), Format::Jbig2),
    ] {
        assert_eq!(
            decode(&data, format, 64 << 20).unwrap_err(),
            Error::TooLarge,
            "{what}"
        );
        assert_eq!(
            decode(&data, format, DECODE_MAX).unwrap_err(),
            Error::Undecodable,
            "{what}"
        );
    }
    let params = JpxParams::default();
    assert_eq!(
        decode_jpx(&huge_codestream(), params, 64 << 20)
            .unwrap_err()
            .message(),
        "Image too large"
    );
    assert_eq!(
        decode_jbig2(
            &fixture("generic.jb2")[13..],
            100_000,
            100_000,
            None,
            64 << 20
        )
        .unwrap_err()
        .message(),
        "Image too large"
    );
    let fax = CcittParams {
        width: 100_000,
        height: 100_000,
        k: -1,
        end_of_line: false,
        encoded_byte_align: false,
        black_is_1: false,
        columns: 100_000,
        rows: 0,
    };
    assert_eq!(
        decode_ccitt(&fixture("bilevel.g4"), fax, 64 << 20)
            .unwrap_err()
            .message(),
        "Image too large"
    );
}

/// Fuzz finding (2026-10-10, `imagehash`: a timeout): 227 bytes of segments
/// whose generic region declares hundreds of millions of pixels. The memory
/// check charged a region at one bit a pixel, so a 64 MiB budget let through
/// a decode of ~5 s in a release build (the viewer's 1 GiB budget allows 16 times as much). A
/// region's pixels are work, charged at a byte each like the page's.
#[test]
fn a_region_declaring_more_pixels_than_the_budget_is_refused() {
    let segments = fixture("jbig2_region_bomb.seg");
    let started = std::time::Instant::now();
    let embedded = decode_jbig2(&segments, 97, 61, None, 64 << 20);
    assert_eq!(embedded.unwrap_err().message(), "Image too large");
    // A file whose region is 2048 by 2048 (512 KiB as bits): over a 1 MiB
    // budget as work, though not as memory.
    let embedded: Vec<u8> = page_with_a_region(2048)
        .iter()
        .flat_map(|(h, d)| [&h[..], &d[..]].concat())
        .collect();
    let mut file = b"\x97JB2\r\n\x1a\n".to_vec();
    file.extend_from_slice(&[1, 0, 0, 0, 1]);
    file.extend_from_slice(&embedded);
    assert_eq!(
        decode(&file, Format::Jbig2, 1 << 20).unwrap_err(),
        Error::TooLarge
    );
    assert_eq!(
        decode_jbig2(&embedded, 120, 64, None, 1 << 20)
            .unwrap_err()
            .message(),
        "Image too large"
    );
    assert!(started.elapsed().as_secs() < 2, "refused from the headers");
}

// pdf.js's layouts (exav-render's `pdf_image`), against the same sources.

fn interleave_with(p: &Pixels, alpha: Option<u8>) -> Vec<u8> {
    let n = p.channels.count();
    bytes(p)
        .chunks(n)
        .flat_map(|px| px.iter().copied().chain(alpha))
        .collect()
}

#[test]
fn jpx_gives_the_layout_pdfjs_asks_for() {
    let rgb = source("rgb.png");
    let jp2 = fixture("rgb.jp2");
    let run = |num_components, smask_in_data, reduce_power, data: &[u8]| {
        decode_jpx(
            data,
            JpxParams {
                num_components,
                indexed: false,
                smask_in_data,
                reduce_power,
            },
            1 << 30,
        )
        .unwrap()
        .expect("pixels")
    };
    // No colour space in the PDF: RGBA.
    let img = run(0, false, 0, &jp2);
    assert_eq!((img.width, img.height, img.components), (37, 23, 4));
    assert_eq!(img.data, interleave_with(&rgb, Some(255)));
    // The colour space's components.
    assert_eq!(run(3, false, 0, &jp2).data, bytes(&rgb));
    let red: Vec<u8> = bytes(&rgb).iter().step_by(3).copied().collect();
    assert_eq!(run(1, false, 0, &jp2).data, red);
    // The alpha of /SMaskInData.
    let rgba = source("rgba.png");
    assert_eq!(run(0, true, 0, &fixture("rgba.jp2")).data, bytes(&rgba));
    // Reduced: each side halved, rounded up.
    let half = run(0, false, 1, &jp2);
    assert_eq!(
        (half.width, half.height, half.data.len()),
        (19, 12, 19 * 12 * 4)
    );
    // Errors carry pdf.js's messages.
    assert_eq!(
        decode_jpx(b"not an image", JpxParams::default(), 1 << 30)
            .unwrap_err()
            .message(),
        "Unknown format"
    );
    assert!(decode_jpx(&jp2[..jp2.len() / 2], JpxParams::default(), 1 << 30).is_err());
}

/// Found by the `imagehash` fuzz target: hayro-jpeg2000 0.4.1 places a
/// reduced decode's samples with full-resolution coordinates, and panics on
/// an image area offset, on a subsampled component in more than one tile and
/// on a column of tiles one sample wide. Such a reduced decode fails; the
/// same files decode at full size, and other tiled ones reduced.
#[test]
fn a_reduced_jpx_decode_the_decoder_cannot_place_fails_cleanly() {
    let decode = |data: &[u8], num_components, reduce_power| {
        let p = JpxParams {
            num_components,
            reduce_power,
            ..JpxParams::default()
        };
        decode_jpx(data, p, 1 << 30)
    };
    let offset = fixture("rgb-offset.j2k");
    let subsampled = fixture("grey-subsampled-tiles.j2k");
    let narrow = fixture("rgb38-narrow-tile.j2k");
    // opj_compress does not give back the one-sample column (OpenJPEG's
    // decoder reads it as hayro-jpeg2000 does), so only its size is compared.
    for (data, n, png, lossless) in [
        (&offset, 3, "rgb.png", true),
        (&subsampled, 1, "grey.png", true),
        (&narrow, 3, "rgb38.png", false),
    ] {
        let full = decode(data, n, 0).unwrap().expect("pixels");
        let png = source(png);
        assert_eq!((full.width, full.height), (png.width, png.height));
        if lossless {
            assert_eq!(full.data, bytes(&png));
        }
        for reduce_power in [1, 2] {
            watch_panics();
            let r = std::panic::catch_unwind(|| decode(data, n, reduce_power));
            assert!(!panicked(), "reduce_power {reduce_power} panicked");
            assert!(r.unwrap().is_err());
        }
    }
    // Tiles of 16 by 16, each at least a sample at a quarter of the size:
    // reduced as OpenJPEG reduces them.
    let tiles = fixture("rgb38-tiles.j2k");
    let half = decode(&tiles, 3, 1).unwrap().expect("pixels");
    assert_eq!(half.data, bytes(&source("rgb38-tiles-r1.png")));
    let quarter = decode(&tiles, 3, 2).unwrap().expect("pixels");
    assert_eq!((quarter.width, quarter.height), (10, 6));
}

/// The source as rows of bits, 1 for white, each row padded with 1s.
fn packed(p: &Pixels) -> Vec<u8> {
    let stride = p.width.div_ceil(8) as usize;
    let mut out = vec![0xFF; stride * p.height as usize];
    for (i, &v) in bytes(p).iter().enumerate() {
        let (x, y) = (i % p.width as usize, i / p.width as usize);
        if v == 0 {
            out[y * stride + x / 8] &= !(0x80 >> (x % 8));
        }
    }
    out
}

#[test]
fn an_embedded_jbig2_stream_gives_the_page_as_rows_of_bits() {
    let want = bilevel();
    // A sequential file is its 13-byte header, then the segments a PDF embeds.
    let stream = &fixture("generic.jb2")[13..];
    assert_eq!(
        decode_jbig2(stream, want.width, want.height, None, 1 << 30).unwrap(),
        packed(&want)
    );
    // Another size is the page cut, or padded with white.
    let cut = decode_jbig2(stream, 16, 2, None, 1 << 30).unwrap();
    let full = packed(&want);
    let stride = want.width.div_ceil(8) as usize;
    assert_eq!(cut, [&full[..2], &full[stride..stride + 2]].concat());
    let padded = decode_jbig2(stream, want.width, want.height + 3, None, 1 << 30).unwrap();
    assert_eq!(&padded[..full.len()], &full[..]);
    assert!(padded[full.len()..].iter().all(|&b| b == 0xFF));
    assert!(decode_jbig2(b"", 8, 8, None, 1 << 30).is_err());
}

/// JBIG2 segments (T.88 7.2) of a 120 by 64 page holding an immediate
/// generic region of `side` by `side`, page association on one byte: the
/// headers and the data parts, in order.
fn page_with_a_region(side: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
    let segment = |number: u32, kind: u8, data: Vec<u8>| {
        let mut h = number.to_be_bytes().to_vec();
        h.extend_from_slice(&[kind, 0, 1]);
        h.extend_from_slice(&(data.len() as u32).to_be_bytes());
        (h, data)
    };
    let mut page = [120u32, 64, 0, 0].map(u32::to_be_bytes).concat();
    page.extend_from_slice(&[0, 0, 0]);
    // Region information (size, position, combination), then the generic
    // region's flags (template 0, arithmetic), its four AT pixels, and
    // coded data the decoder reads past the end of.
    let mut region = [side, side, 0, 0].map(u32::to_be_bytes).concat();
    region.extend_from_slice(&[0, 0, 3, 0xFF, 0xFD, 0xFF, 2, 0xFE, 0xFE, 0xFE]);
    region.extend_from_slice(&[0x5A; 16]);
    vec![
        segment(0, 48, page),
        segment(1, 38, region),
        segment(2, 49, Vec::new()),
    ]
}

/// Found by the `imagehash` fuzz target: a stream of a few hundred bytes
/// declaring a region of a billion pixels on a small page, which
/// hayro-jbig2 decodes at its declared size. A region's bitmap counts
/// against the decode budget as the page's does; a file whose regions are
/// its page fits the same budget.
#[test]
fn a_jbig2_region_larger_than_the_budget_is_refused() {
    let budget = 256 << 10;
    let segments = page_with_a_region(2048);
    let embedded: Vec<u8> = segments
        .iter()
        .flat_map(|(h, d)| [&h[..], &d[..]].concat())
        .collect();
    assert_eq!(
        decode_jbig2(&embedded, 120, 64, None, budget).map_err(|e| e.message()),
        Err("Image too large")
    );
    assert!(decode_jbig2(&embedded, 120, 64, None, 1 << 30).is_ok());
    // As files: sequential (each header followed by its data) and random
    // access (every header, an end of file, then every data part).
    let id = b"\x97JB2\r\n\x1a\n";
    let mut sequential = [&id[..], &[1, 0, 0, 0, 1]].concat();
    sequential.extend_from_slice(&embedded);
    let mut random = [&id[..], &[0, 0, 0, 0, 1]].concat();
    for (h, _) in &segments {
        random.extend_from_slice(h);
    }
    random.extend_from_slice(&[0, 0, 0, 3, 51, 0, 0, 0, 0, 0, 0]);
    for (_, d) in &segments {
        random.extend_from_slice(d);
    }
    for file in [&sequential, &random] {
        assert_eq!(Format::detect(file), Some(Format::Jbig2));
        assert_eq!(decode(file, Format::Jbig2, budget), Err(Error::TooLarge));
        assert!(decode(file, Format::Jbig2, DECODE_MAX).is_ok());
    }
    let want = bilevel();
    for file in ["generic.jb2", "generic-random.jb2"] {
        assert_eq!(
            bytes(&decode_any(&fixture(file), budget).unwrap()),
            bytes(&want)
        );
    }
    let stream = &fixture("generic.jb2")[13..];
    assert_eq!(
        decode_jbig2(stream, want.width, want.height, None, budget).unwrap(),
        packed(&want)
    );
}

#[test]
fn every_ccitt_mode_gives_back_the_encoded_picture() {
    let want = bilevel();
    let rows = packed(&want);
    for (file, k, end_of_line, encoded_byte_align) in [
        ("bilevel.g4", -1, false, false),
        ("bilevel.g3-1d", 0, true, false),
        ("bilevel.g3-2d", 1, true, false),
        ("bilevel.g3-fill", 0, true, true),
        ("bilevel.rle", 0, false, true),
    ] {
        let p = CcittParams {
            width: want.width,
            height: want.height,
            k,
            end_of_line,
            encoded_byte_align,
            black_is_1: false,
            columns: want.width,
            rows: want.height,
        };
        let data = fixture(file);
        assert_eq!(decode_ccitt(&data, p, 1 << 30).unwrap(), rows, "{file}");
        // /BlackIs1 flips every pixel, and the padding with them.
        let flipped: Vec<u8> = rows.iter().map(|b| !b).collect();
        assert_eq!(
            decode_ccitt(
                &data,
                CcittParams {
                    black_is_1: true,
                    ..p
                },
                1 << 30
            )
            .unwrap(),
            flipped,
            "{file} /BlackIs1"
        );
    }
}

#[test]
fn rows_a_ccitt_stream_does_not_reach_are_zero() {
    let want = bilevel();
    let p = CcittParams {
        width: want.width,
        height: want.height,
        k: -1,
        end_of_line: false,
        encoded_byte_align: false,
        black_is_1: false,
        columns: want.width,
        rows: 0,
    };
    let out = decode_ccitt(&[], p, 1 << 30).unwrap();
    assert!(out.iter().all(|&b| b == 0));
}
