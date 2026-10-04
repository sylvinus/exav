use super::*;
use image::ImageFormat;

fn solid_png(w: u32, h: u32, rgb: [u8; 3]) -> Vec<u8> {
    let img = image::RgbImage::from_pixel(w, h, image::Rgb(rgb));
    let mut out = std::io::Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(img)
        .write_to(&mut out, ImageFormat::Png)
        .unwrap();
    out.into_inner()
}

fn clamav(data: &[u8]) -> Result<String, Error> {
    Hasher::new(Preset::ClamAv)
        .hash(data)
        .map(|h| h.to_string())
}

#[test]
fn solid_nonblack_is_dc_only() {
    // A flat non-black field: only the DC coefficient is positive, the median
    // is 0, so only the first bit is set.
    for color in [
        [255, 255, 255],
        [128, 128, 128],
        [200, 30, 30],
        [10, 10, 200],
    ] {
        let png = solid_png(64, 64, color);
        for preset in [Preset::ClamAv, Preset::ImagehashPhash] {
            let h = Hasher::new(preset).hash(&png).unwrap();
            assert_eq!(h.to_string(), "8000000000000000", "{preset:?} {color:?}");
        }
    }
}

#[test]
fn solid_black_is_all_zero() {
    assert_eq!(
        clamav(&solid_png(64, 64, [0, 0, 0])).unwrap(),
        "0000000000000000"
    );
}

/// `sigtool --fuzzy-img` from ClamAV 1.5.4 prints `fed581d5812a853b` for
/// this JPEG; image 0.24's decoder gave `fed581d5812b852b`.
#[test]
fn a_jpeg_hashes_as_clamav_decodes_it() {
    let jpeg = include_bytes!("../tests/fixtures/decoder_sensitive.jpg");
    assert_eq!(clamav(jpeg).unwrap(), "fed581d5812a853b");
}

/// `sigtool --fuzzy-img` reads neither JPEG 2000 nor JBIG2, but the hash is
/// one of pixels: these files hash as the PNGs they were losslessly encoded
/// from do (exav-render's fixtures, see make.py there). The hashes are what
/// sigtool (ClamAV 1.4.3) prints for those PNGs. They are not among
/// clamscan's graphics.
#[test]
#[cfg(all(feature = "jp2", feature = "jbig2"))]
fn jpeg_2000_and_jbig2_hash_as_the_same_pixels_in_a_png() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../exav-render/tests/fixtures/images"
    );
    let read = |name: &str| std::fs::read(format!("{dir}/{name}")).unwrap();
    for (file, f, png, sigtool) in [
        ("rgb.jp2", Format::Jpeg2000, "rgb.png", "f0a50fd80dda4b1e"),
        ("rgb.j2k", Format::Jpeg2000, "rgb.png", "f0a50fd80dda4b1e"),
        (
            "generic.jb2",
            Format::Jbig2,
            "bilevel.png",
            "d656ab50a9e9c82d",
        ),
        (
            "generic-random.jb2",
            Format::Jbig2,
            "bilevel.png",
            "d656ab50a9e9c82d",
        ),
    ] {
        let data = read(file);
        assert_eq!(Format::detect(&data), Some(f), "{file}");
        assert_eq!(clamav(&read(png)).unwrap(), sigtool, "{png}");
        assert_eq!(clamav(&data).unwrap(), sigtool, "{file}");
        assert!(
            Formats::ALL.contains(f) && Formats::NONE.with(f).contains(f),
            "{file}"
        );
        assert!(!Formats::CLAMAV_GRAPHICS.contains(f), "{file}");
        let graphics = Hasher::with_params(Params {
            formats: Formats::CLAMAV_GRAPHICS,
            ..Params::CLAMAV
        })
        .unwrap();
        assert_eq!(
            graphics.hash(&data).map(|h| h.to_string()),
            Err(Error::Unsupported),
            "{file}"
        );
    }
}

#[test]
fn a_non_image_is_unsupported() {
    assert_eq!(
        clamav(b"not an image at all, just text bytes"),
        Err(Error::Unsupported)
    );
    assert_eq!(
        clamav(b"\x89PNG\r\n\x1a\n truncated"),
        Err(Error::Undecodable)
    );
}

/// `sigtool --fuzzy-img` hashes a WebP; clamscan, scanning, does not take
/// one for graphics.
#[cfg(feature = "webp")]
#[test]
fn a_webp_is_hashed_but_not_clamav_graphics() {
    let img = image::RgbImage::from_pixel(16, 16, image::Rgb([90, 160, 20]));
    let mut out = std::io::Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(img)
        .write_to(&mut out, ImageFormat::WebP)
        .unwrap();
    let webp = out.into_inner();
    assert_eq!(Format::detect(&webp), Some(Format::Webp));
    assert_eq!(clamav(&webp).unwrap(), "8000000000000000");
    let scan = Hasher::with_params(Params {
        formats: Formats::CLAMAV_GRAPHICS,
        ..Params::CLAMAV
    })
    .unwrap();
    assert_eq!(scan.hash(&webp), Err(Error::Unsupported));
}

/// A gradient with every channel varying, `h` rows tall so that its
/// conversion takes several strips.
fn gradient(w: u32, h: u32) -> DynamicImage {
    DynamicImage::ImageRgba16(image::ImageBuffer::from_fn(w, h, |x, y| {
        image::Rgba([
            (x * 1031 + y * 7) as u16,
            ((y * 523) ^ (x * 97)) as u16,
            (x * y * 13) as u16,
            (65535 - y * 11) as u16,
        ])
    }))
}

/// [`gray_bt601`] by converting the whole image to RGB8 at once.
fn gray_whole(img: &DynamicImage) -> GrayImage {
    let rgb = img.to_rgb8();
    let mut gray = GrayImage::new(rgb.width(), rgb.height());
    for (src, dst) in rgb.pixels().zip(gray.pixels_mut()) {
        dst.0[0] = luma_bt601(src[0], src[1], src[2]);
    }
    gray
}

/// Every pixel type turns grey strip by strip as it does whole, in any
/// colour space, and an RGB8 image in place as through a copy.
#[test]
fn grey_is_the_same_strip_by_strip() {
    let src = gradient(1024, 3000);
    let mut p3 = src.clone();
    p3.set_color_space(image::metadata::Cicp::DISPLAY_P3)
        .unwrap();
    for img in [
        src.clone(),
        p3,
        DynamicImage::ImageRgb8(src.to_rgb8()),
        DynamicImage::ImageRgba8(src.to_rgba8()),
        DynamicImage::ImageLuma8(src.to_luma8()),
        DynamicImage::ImageLumaA8(src.to_luma_alpha8()),
        DynamicImage::ImageRgb16(src.to_rgb16()),
        DynamicImage::ImageLuma16(src.to_luma16()),
        DynamicImage::ImageLumaA16(src.to_luma_alpha16()),
        DynamicImage::ImageRgb32F(src.to_rgb32f()),
        DynamicImage::ImageRgba32F(src.to_rgba32f()),
    ] {
        let what = format!("{:?} {:?}", img.color(), img.color_space());
        let row = 1024 * usize::from(img.color().bytes_per_pixel());
        assert!(STRIP_BYTES / row < 3000, "{what}: fits one strip");
        assert!(gray_bt601(img.clone()) == gray_whole(&img), "{what}");
    }
}

/// Decoding past the caller's allowance is a limit, not an undecodable file.
#[test]
fn an_image_past_the_allowance_is_too_large() {
    let png = solid_png(64, 64, [9, 99, 199]);
    let at = |max| {
        Hasher::with_params(Params {
            max_decode_bytes: max,
            ..Params::CLAMAV
        })
        .unwrap()
        .hash(&png)
    };
    assert_eq!(at(64 * 64), Err(Error::TooLarge));
    assert!(at(64 * 64 * 3).is_ok());
}

/// An image past what ClamAV decodes has no hash there either, so it is
/// not reported as a limit.
#[test]
fn an_image_past_what_clamav_decodes_is_undecodable() {
    let chunk = |kind: &[u8], body: &[u8]| {
        let mut c = (body.len() as u32).to_be_bytes().to_vec();
        c.extend_from_slice(kind);
        c.extend_from_slice(body);
        let crc = crc32fast::hash(&c[4..]);
        c.extend_from_slice(&crc.to_be_bytes());
        c
    };
    let mut ihdr = 40_000u32.to_be_bytes().to_vec();
    ihdr.extend_from_slice(&40_000u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend(chunk(b"IHDR", &ihdr));
    png.extend(chunk(b"IDAT", b"\x78\x9c"));
    png.extend(chunk(b"IEND", b""));
    assert_eq!(clamav(&png), Err(Error::Undecodable));
    let small = Hasher::with_params(Params {
        max_decode_bytes: 1 << 20,
        ..Params::CLAMAV
    })
    .unwrap();
    assert_eq!(small.hash(&png), Err(Error::TooLarge));
}

/// The pixel entry points hash as decoding the same pixels does.
#[test]
fn pixels_hash_as_the_file_does() {
    let img = gradient(97, 61).to_rgb8();
    let mut png = std::io::Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(img.clone())
        .write_to(&mut png, ImageFormat::Png)
        .unwrap();
    for preset in [Preset::ClamAv, Preset::ImagehashPhash] {
        let h = Hasher::new(preset);
        let file = h.hash(png.get_ref()).unwrap();
        assert_eq!(
            h.hash_rgb8(97, 61, img.as_raw()).unwrap(),
            file,
            "{preset:?}"
        );
        let rgba = DynamicImage::ImageRgb8(img.clone()).to_rgba8();
        assert_eq!(
            h.hash_rgba8(97, 61, rgba.as_raw()).unwrap(),
            file,
            "{preset:?}"
        );
    }
    assert!(Hasher::new(Preset::ClamAv)
        .hash_rgb8(97, 61, &[0; 5])
        .is_err());
}

#[test]
fn sizes_and_hex() {
    let png = {
        let img = gradient(200, 150).to_rgb8();
        let mut c = std::io::Cursor::new(Vec::new());
        DynamicImage::ImageRgb8(img)
            .write_to(&mut c, ImageFormat::Png)
            .unwrap();
        c.into_inner()
    };
    for (size, digits) in [(5, 7), (8, 16), (16, 64)] {
        let p = Params {
            hash_size: size,
            ..Params::IMAGEHASH_PHASH
        };
        let h = Hasher::with_params(p).unwrap().hash(&png).unwrap();
        assert_eq!(h.bits().len(), (size * size) as usize);
        let s = h.to_string();
        assert_eq!(s.len(), digits, "{size}");
        // Back from hex, with the leading padding bits.
        let back: ImageHash = s.parse().unwrap();
        assert_eq!(back.bits()[back.bits().len() - h.bits().len()..], *h.bits());
    }
    let a: ImageHash = "ff00".parse().unwrap();
    let b: ImageHash = "0f01".parse().unwrap();
    assert_eq!(a.distance(&b), Some(5));
    assert_eq!(a.distance(&"ff".parse().unwrap()), None);
    assert_eq!(a.to_bytes(), vec![0xff, 0]);
}

#[test]
fn bad_params_are_refused() {
    for p in [
        Params {
            hash_size: 1,
            ..Params::CLAMAV
        },
        Params {
            highfreq_factor: 0,
            ..Params::CLAMAV
        },
        Params {
            hash_size: 4096,
            ..Params::CLAMAV
        },
        Params {
            keep_dc: false,
            highfreq_factor: 1,
            ..Params::CLAMAV
        },
    ] {
        assert!(
            matches!(Hasher::with_params(p), Err(Error::InvalidParams(_))),
            "{p:?}"
        );
    }
    assert!(Hasher::with_params(Params {
        keep_dc: false,
        ..Params::CLAMAV
    })
    .is_ok());
}
