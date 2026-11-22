//! QR codes (`qr`, `ScanOptions::qr_codes`): the payload of a code in an
//! image is matched as a text view, and a link in it is judged by the phishing
//! check; off unless asked for, never under `--clamav-compat`, and a reading
//! a limit stopped is not reported clean.

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};
use exav_unpack::zip_write::{FileOptions, ZipWriter};
use image::{DynamicImage, GrayImage, ImageFormat};

/// A code for `payload`, four pixels to a module, with its quiet zone; drawn
/// by an encoder of its own.
fn qr_grey(payload: &str) -> GrayImage {
    let code = qrcode::QrCode::new(payload.as_bytes()).unwrap();
    let n = code.width() as u32;
    let colors = code.to_colors();
    let side = (n + 8) * 4;
    GrayImage::from_fn(side, side, |x, y| {
        let (mx, my) = (x / 4, y / 4);
        let dark = (4..n + 4).contains(&mx)
            && (4..n + 4).contains(&my)
            && colors[((my - 4) * n + (mx - 4)) as usize] == qrcode::Color::Dark;
        image::Luma([if dark { 0 } else { 255 }])
    })
}

fn png(img: GrayImage) -> Vec<u8> {
    let mut out = std::io::Cursor::new(Vec::new());
    DynamicImage::ImageLuma8(img)
        .write_to(&mut out, ImageFormat::Png)
        .unwrap();
    out.into_inner()
}

/// A PNG of a code for `payload`.
fn qr_png(payload: &str) -> Vec<u8> {
    png(qr_grey(payload))
}

fn scanner(body: &str) -> Scanner {
    let hex: String = body.bytes().map(|b| format!("{b:02x}")).collect();
    let mut l = loader::Builder::new();
    l.add_named_bytes("t.ndb", format!("Test.Qr:7:*:{hex}\n").as_bytes(), true);
    l.build().unwrap()
}

fn verdict(db: &Scanner, file: &[u8], set: impl FnOnce(&mut ScanOptions)) -> Verdict {
    let mut o = ScanOptions::default();
    set(&mut o);
    analyze(db, file, &o).verdict
}

const URL: &str = "https://evil.example/pay?id=7";

#[test]
fn a_codes_payload_is_matched_only_when_asked_for() {
    let png = qr_png(URL);
    let db = scanner("evil.example/pay");
    assert!(matches!(
        verdict(&db, &png, |o| o.qr_codes = true),
        Verdict::Infected { .. }
    ));
    assert!(matches!(verdict(&db, &png, |_| {}), Verdict::Clean));
    assert!(matches!(
        verdict(&db, &png, |o| {
            o.qr_codes = true;
            o.clamav_compat = true;
        }),
        Verdict::Clean
    ));
}

#[test]
fn a_code_in_an_image_inside_an_archive_is_read() {
    use std::io::Write;
    let mut w = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file("scan-me.png", FileOptions::default()).unwrap();
    w.write_all(&qr_png(URL)).unwrap();
    let zip = w.finish().unwrap().into_inner();
    assert!(matches!(
        verdict(&scanner("evil.example/pay"), &zip, |o| o.qr_codes = true),
        Verdict::Infected { .. }
    ));
}

#[test]
fn a_link_in_a_code_is_judged_by_the_phishing_check() {
    let png = qr_png("https://www.paypal.com@evil.example/login");
    match verdict(&scanner("never present"), &png, |o| {
        o.qr_codes = true;
        o.alert_phishing = true;
    }) {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.Phishing.Email.Cloaked.Username")
        }
        v => panic!("{v:?}"),
    }
}

#[test]
fn an_image_past_the_pixel_limit_is_not_reported_clean() {
    let png = qr_png(URL);
    let v = verdict(&scanner("never present"), &png, |o| {
        o.qr_codes = true;
        o.max_qr_pixels = Some(100);
    });
    assert!(!matches!(v, Verdict::Clean), "{v:?}");
    // No limit: read, and clean.
    let v = verdict(&scanner("never present"), &png, |o| {
        o.qr_codes = true;
        o.max_qr_pixels = None;
        o.max_qr_millis = None;
    });
    assert!(matches!(v, Verdict::Clean), "{v:?}");
}

#[test]
fn an_image_with_more_codes_than_the_limit_is_not_reported_clean() {
    let (a, b) = (qr_grey("https://a.example/"), qr_grey("https://b.example/"));
    let mut both = GrayImage::from_pixel(a.width() + b.width(), a.height(), image::Luma([255]));
    image::imageops::overlay(&mut both, &a, 0, 0);
    image::imageops::overlay(&mut both, &b, i64::from(a.width()), 0);
    let both = png(both);
    let db = scanner("never present");
    let v = verdict(&db, &both, |o| {
        o.qr_codes = true;
        o.max_qr_codes = Some(1);
    });
    assert!(!matches!(v, Verdict::Clean), "{v:?}");
    // The default and `None` read both.
    for max in [Some(exav_core::DEFAULT_MAX_QR_CODES), None] {
        let v = verdict(&db, &both, |o| {
            o.qr_codes = true;
            o.max_qr_codes = max;
        });
        assert!(matches!(v, Verdict::Clean), "{max:?}: {v:?}");
    }
}

#[test]
fn a_link_in_a_code_is_judged_when_the_database_has_only_hash_signatures() {
    // Nothing for a text view to be matched against but the EICAR signature
    // every database holds.
    let mut l = loader::Builder::new();
    l.add_named_bytes(
        "t.hdb",
        b"00112233445566778899aabbccddeeff:1234:Test.Hash\n",
        true,
    );
    let db = l.build().unwrap();
    let png = qr_png("https://www.paypal.com@evil.example/login");
    match verdict(&db, &png, |o| {
        o.qr_codes = true;
        o.alert_phishing = true;
    }) {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.Phishing.Email.Cloaked.Username")
        }
        v => panic!("{v:?}"),
    }
    let v = verdict(&db, &png, |o| o.qr_codes = true);
    assert!(matches!(v, Verdict::Clean), "{v:?}");
}

/// A PDF whose one object is a square image XObject of `side` pixels, with
/// `dict` for the rest of its entries, holding `samples` Flate-coded.
fn pdf_with_image(side: u32, dict: &str, samples: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(samples).unwrap();
    let z = z.finish().unwrap();
    let mut pdf = format!(
        "%PDF-1.4\n1 0 obj\n<< /Type /XObject /Subtype /Image /Width {side} /Height {side} \
         {dict} /Filter /FlateDecode /Length {} >>\nstream\n",
        z.len()
    )
    .into_bytes();
    pdf.extend_from_slice(&z);
    pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
    pdf
}

#[test]
fn a_code_in_a_raw_image_of_a_pdf_is_read() {
    let img = qr_grey(URL);
    let side = img.width();
    let white = |x: u32, y: u32| img.get_pixel(x, y).0[0] > 127;
    // One bit a pixel, rows padded to a byte: set for a white pixel under
    // DeviceGray, for a dark one under the palette below.
    let bits = |set_when_white: bool| {
        let mut out = Vec::new();
        for y in 0..side {
            let mut row = vec![0u8; side.div_ceil(8) as usize];
            for x in 0..side {
                if white(x, y) == set_when_white {
                    row[(x / 8) as usize] |= 0x80 >> (x % 8);
                }
            }
            out.extend(row);
        }
        out
    };
    // Eight bits a pixel, each row stored as its difference to the one above
    // (PNG predictor 15, filter 2).
    let mut up = Vec::new();
    let mut above = vec![0u8; side as usize];
    for y in 0..side {
        up.push(2);
        let row: Vec<u8> = (0..side).map(|x| img.get_pixel(x, y).0[0]).collect();
        up.extend(row.iter().zip(&above).map(|(a, b)| a.wrapping_sub(*b)));
        above = row;
    }
    let pdfs = [
        (
            "1 bit",
            pdf_with_image(
                side,
                "/BitsPerComponent 1 /ColorSpace /DeviceGray",
                &bits(true),
            ),
        ),
        (
            "8 bits, predictor",
            pdf_with_image(
                side,
                &format!(
                    "/BitsPerComponent 8 /ColorSpace /DeviceGray \
                     /DecodeParms << /Predictor 15 /Colors 1 /Columns {side} >>"
                ),
                &up,
            ),
        ),
        (
            "indexed",
            pdf_with_image(
                side,
                "/BitsPerComponent 1 /ColorSpace [/Indexed /DeviceRGB 1 <ffffff000000>]",
                &bits(false),
            ),
        ),
    ];
    let db = scanner("evil.example/pay");
    for (what, pdf) in &pdfs {
        let v = verdict(&db, pdf, |o| o.qr_codes = true);
        assert!(matches!(v, Verdict::Infected { .. }), "{what}: {v:?}");
        let v = verdict(&db, pdf, |_| {});
        assert!(matches!(v, Verdict::Clean), "{what}: {v:?}");
    }
}

/// The PDFs' only object is a 132 by 132 image of a code for `URL`, in a
/// CCITT Group 4 stream (`tiffcp -c g4`) and in a JBIG2 stream (`jbig2 -p`,
/// jbig2enc's embedded form, no globals), both drawn by qrencode. A third has
/// the stream of `jbig2 -s -p` (symbol mode) and its symbol dictionary in the
/// `/JBIG2Globals` object.
#[test]
fn a_code_in_a_ccitt_or_jbig2_image_of_a_pdf_is_read() {
    let pdfs = [
        ("ccitt", &include_bytes!("../testdata/qr_ccitt_g4.pdf")[..]),
        ("jbig2", &include_bytes!("../testdata/qr_jbig2.pdf")[..]),
        (
            "jbig2 symbols",
            &include_bytes!("../testdata/qr_jbig2_symbols.pdf")[..],
        ),
    ];
    let db = scanner("evil.example/pay");
    for (what, pdf) in pdfs {
        let v = verdict(&db, pdf, |o| o.qr_codes = true);
        assert!(matches!(v, Verdict::Infected { .. }), "{what}: {v:?}");
        let v = verdict(&db, pdf, |_| {});
        assert!(matches!(v, Verdict::Clean), "{what}: {v:?}");
    }
}

/// An image that is recognised and not read ends unscannable under
/// `qr_codes` with its reason, and is as it was without it: a PNG cut short, a
/// raster in a color space that is not read, a JBIG2 stream that does not
/// decode.
#[test]
fn an_image_that_is_not_read_is_not_reported_clean() {
    let png = qr_png(URL);
    let lab = pdf_with_image(
        2,
        "/BitsPerComponent 8 /ColorSpace [/Lab << /WhitePoint [0.95 1 1.09] >>]",
        &[0; 12],
    );
    // A page information segment cut short.
    let mut jbig2 = b"%PDF-1.4\n1 0 obj\n<< /Type /XObject /Subtype /Image /Width 8 /Height 8 \
        /BitsPerComponent 1 /ColorSpace /DeviceGray /Filter /JBIG2Decode /Length 20 >>\n\
        stream\n"
        .to_vec();
    jbig2.extend_from_slice(&[
        0, 0, 0, 0, 0x30, 0, 1, 0, 0, 0, 0x13, 0, 0, 0, 0x84, 0, 0, 0, 0x84, 0,
    ]);
    jbig2.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
    let db = scanner("never present");
    for (what, file, why) in [
        ("cut png", &png[..60], "does not decode"),
        ("lab", &lab[..], "a PDF image whose dictionary"),
        ("jbig2", &jbig2[..], "does not decode"),
    ] {
        let v = verdict(&db, file, |o| o.qr_codes = true);
        let Verdict::Unscannable { reason } = &v else {
            panic!("{what}: {v:?}");
        };
        assert!(
            reason.contains("QR codes") && reason.contains(why),
            "{what}: {reason}"
        );
        let v = verdict(&db, file, |_| {});
        assert!(matches!(v, Verdict::Clean), "{what}: {v:?}");
    }
}

/// The signatures of BMP and PNM are two bytes: a file that starts with them
/// and has no header of the format is not an image, so it is clean, and a BMP
/// with its header and its pixels cut short is an image that does not decode.
#[test]
fn a_file_that_only_starts_like_an_image_is_not_reported_unreadable() {
    let mut cut_bmp = b"BM".to_vec();
    cut_bmp.extend_from_slice(&102u32.to_le_bytes());
    cut_bmp.extend_from_slice(&0u32.to_le_bytes());
    cut_bmp.extend_from_slice(&54u32.to_le_bytes());
    cut_bmp.extend_from_slice(&40u32.to_le_bytes());
    cut_bmp.extend_from_slice(&4u32.to_le_bytes());
    cut_bmp.extend_from_slice(&4u32.to_le_bytes());
    cut_bmp.extend_from_slice(&[1, 0, 24, 0]);
    cut_bmp.extend_from_slice(&[0; 24]);
    cut_bmp.extend_from_slice(&[0xFF; 10]);
    let db = scanner("never present");
    for (what, file) in [
        (
            "text BM",
            &b"BMW parts list: engines, gearboxes, seats\n"[..],
        ),
        (
            "text P1",
            &b"P1 is the name of the plain bitmap format\n"[..],
        ),
        (
            "binary BM",
            &b"BMSWIM\0\0\0hAsun#supported 7z \0\x80decqs"[..],
        ),
    ] {
        let v = verdict(&db, file, |o| o.qr_codes = true);
        assert!(matches!(v, Verdict::Clean), "{what}: {v:?}");
    }
    let v = verdict(&db, &cut_bmp, |o| o.qr_codes = true);
    let Verdict::Unscannable { reason } = &v else {
        panic!("cut bmp: {v:?}");
    };
    assert!(reason.contains("QR codes"), "{reason}");
    let v = verdict(&db, &cut_bmp, |_| {});
    assert!(matches!(v, Verdict::Clean), "cut bmp: {v:?}");
}

/// A PDF whose one object is an image with `dict` for its entries and `data`,
/// unfiltered, for its stream.
fn pdf_with_plain_image(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut pdf = format!(
        "%PDF-1.4\n1 0 obj\n<< /Type /XObject /Subtype /Image {dict} /Length {} >>\nstream\n",
        data.len()
    )
    .into_bytes();
    pdf.extend_from_slice(data);
    pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
    pdf
}

/// An image whose dictionary lacks the size, the depth or the color space is
/// one no reader can build: said, not silent.
#[test]
fn a_pdf_image_whose_dictionary_does_not_describe_it_is_not_reported_clean() {
    let db = scanner("never present");
    for (what, dict) in [
        (
            "width",
            "/Height 2 /BitsPerComponent 8 /ColorSpace /DeviceGray",
        ),
        (
            "height",
            "/Width 2 /BitsPerComponent 8 /ColorSpace /DeviceGray",
        ),
        ("depth", "/Width 2 /Height 2 /ColorSpace /DeviceGray"),
        ("color space", "/Width 2 /Height 2 /BitsPerComponent 8"),
    ] {
        let pdf = pdf_with_plain_image(dict, &[0; 16]);
        let v = verdict(&db, &pdf, |o| o.qr_codes = true);
        let Verdict::Unscannable { reason } = &v else {
            panic!("{what}: {v:?}");
        };
        assert!(reason.contains("whose dictionary"), "{what}: {reason}");
        let v = verdict(&db, &pdf, |_| {});
        assert!(matches!(v, Verdict::Clean), "{what}: {v:?}");
    }
    // The same image with all of it is read, and clean.
    let pdf = pdf_with_plain_image(
        "/Width 2 /Height 2 /BitsPerComponent 8 /ColorSpace /DeviceGray",
        &[0; 16],
    );
    let v = verdict(&db, &pdf, |o| o.qr_codes = true);
    assert!(matches!(v, Verdict::Clean), "{v:?}");
}

/// The pixel limit bounds the regions a JBIG2 stream declares as well as the
/// size of the image: the stream of `qr_jbig2.pdf` has a 132 by 132 region,
/// and its dictionary is changed here to say 8 by 8.
#[test]
fn the_regions_of_a_jbig2_image_are_held_to_the_pixel_limit() {
    let mut pdf = include_bytes!("../testdata/qr_jbig2.pdf").to_vec();
    let (from, to) = (
        &b"/Width 132 /Height 132"[..],
        &b"/Width 8   /Height 8  "[..],
    );
    let at = pdf.windows(from.len()).position(|w| w == from).unwrap();
    pdf[at..at + to.len()].copy_from_slice(to);
    let db = scanner("never present");
    let v = verdict(&db, &pdf, |o| {
        o.qr_codes = true;
        o.max_qr_pixels = Some(1000);
    });
    let Verdict::LimitsExceeded { reason } = &v else {
        panic!("{v:?}");
    };
    assert!(reason.contains("1000-pixel limit"), "{reason}");
    // A limit that holds the regions: read, and clean.
    let v = verdict(&db, &pdf, |o| {
        o.qr_codes = true;
        o.max_qr_pixels = Some(20_000);
    });
    assert!(matches!(v, Verdict::Clean), "{v:?}");
}

/// The page a JBIG2 stream declares in its page information segment is held
/// to the pixel limit too, whatever size the image dictionary gives: the
/// stream here is that segment alone, for a page of 1000 by 1000, in an image
/// the dictionary says is 8 by 8.
#[test]
fn the_page_of_a_jbig2_stream_is_held_to_the_pixel_limit() {
    let mut pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /XObject /Subtype /Image /Width 8 /Height 8 \
        /BitsPerComponent 1 /ColorSpace /DeviceGray /Filter /JBIG2Decode /Length 30 >>\n\
        stream\n"
        .to_vec();
    // Segment 0, type 48, page 1, 19 bytes of data.
    pdf.extend_from_slice(&[0, 0, 0, 0, 0x30, 0, 1, 0, 0, 0, 19]);
    pdf.extend_from_slice(&1000u32.to_be_bytes());
    pdf.extend_from_slice(&1000u32.to_be_bytes());
    pdf.extend_from_slice(&[0; 11]);
    pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
    let db = scanner("never present");
    let v = verdict(&db, &pdf, |o| {
        o.qr_codes = true;
        o.max_qr_pixels = Some(100_000);
    });
    let Verdict::LimitsExceeded { reason } = &v else {
        panic!("{v:?}");
    };
    assert!(reason.contains("100000-pixel limit"), "{reason}");
    let v = verdict(&db, &pdf, |o| {
        o.qr_codes = true;
        o.max_qr_pixels = Some(2_000_000);
    });
    assert!(matches!(v, Verdict::Clean), "{v:?}");
}
