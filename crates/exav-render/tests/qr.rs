//! `qr`: the payloads of the QR codes in an image, in any format the image
//! decoders read, within the limits asked for. The codes are drawn here by an
//! encoder of their own (`qrcode`).

use exav_render::qr::{Found, Limits, Settings, find, find_in_grey, search};
use image::{DynamicImage, GrayImage, ImageFormat, Rgba, RgbaImage};

/// The modules of a code for `payload`, `scale` pixels each, with the quiet
/// zone of four modules around it; dark is `true`.
fn modules(payload: &str, scale: u32) -> (u32, Vec<bool>) {
    let code = qrcode::QrCode::new(payload.as_bytes()).unwrap();
    let n = code.width() as u32;
    let side = (n + 8) * scale;
    let colors = code.to_colors();
    let mut dark = vec![false; (side * side) as usize];
    for y in 0..side {
        for x in 0..side {
            let (mx, my) = (x / scale, y / scale);
            if (4..n + 4).contains(&mx) && (4..n + 4).contains(&my) {
                let c = colors[((my - 4) * n + (mx - 4)) as usize];
                dark[(y * side + x) as usize] = c == qrcode::Color::Dark;
            }
        }
    }
    (side, dark)
}

fn grey(payload: &str) -> GrayImage {
    let (side, dark) = modules(payload, 4);
    GrayImage::from_fn(side, side, |x, y| {
        image::Luma([if dark[(y * side + x) as usize] {
            0
        } else {
            255
        }])
    })
}

fn encoded(img: DynamicImage, format: ImageFormat) -> Vec<u8> {
    // The GIF and BMP encoders take colour.
    let img = match format {
        ImageFormat::Gif => DynamicImage::ImageRgba8(img.to_rgba8()),
        ImageFormat::Bmp => DynamicImage::ImageRgb8(img.to_rgb8()),
        _ => img,
    };
    let mut out = std::io::Cursor::new(Vec::new());
    img.write_to(&mut out, format).unwrap();
    out.into_inner()
}

fn read(data: &[u8]) -> Found {
    find(data, 1 << 28, &Limits::default()).unwrap()
}

const URL: &str = "https://login.evil.example/session?id=42";

#[test]
fn a_codes_payload_is_read_in_every_format_drawn() {
    for format in [ImageFormat::Png, ImageFormat::Gif, ImageFormat::Bmp] {
        let data = encoded(DynamicImage::ImageLuma8(grey(URL)), format);
        let f = read(&data);
        assert_eq!(f.payloads, [URL], "{format:?}");
        assert_eq!(f.cut, None, "{format:?}");
    }
}

#[test]
fn a_code_drawn_on_a_transparent_background_is_read() {
    let (side, dark) = modules(URL, 4);
    let img = RgbaImage::from_fn(side, side, |x, y| {
        if dark[(y * side + x) as usize] {
            Rgba([0, 0, 0, 255])
        } else {
            Rgba([0, 0, 0, 0])
        }
    });
    let f = read(&encoded(DynamicImage::ImageRgba8(img), ImageFormat::Png));
    assert_eq!(f.payloads, [URL]);
}

#[test]
fn each_code_of_an_image_is_read_up_to_the_limit() {
    let a = grey("https://a.example/");
    let b = grey("https://b.example/");
    let mut both = GrayImage::from_pixel(
        a.width() + b.width(),
        a.height().max(b.height()),
        image::Luma([255]),
    );
    image::imageops::overlay(&mut both, &a, 0, 0);
    image::imageops::overlay(&mut both, &b, i64::from(a.width()), 0);
    let png = encoded(DynamicImage::ImageLuma8(both), ImageFormat::Png);
    let mut f = read(&png);
    f.payloads.sort();
    assert_eq!(f.payloads, ["https://a.example/", "https://b.example/"]);
    let one = Limits {
        max_codes: Some(1),
        ..Limits::default()
    };
    let f = find(&png, 1 << 28, &one).unwrap();
    assert_eq!(f.payloads.len(), 1);
    assert!(f.cut.unwrap().contains("more than 1"));
    // `None` reads them all.
    let all = Limits {
        max_codes: None,
        ..Limits::default()
    };
    let f = find(&png, 1 << 28, &all).unwrap();
    assert_eq!(f.payloads.len(), 2);
    assert_eq!(f.cut, None);
}

/// A grey image tiled with finder patterns (the square a code has in three
/// corners), `scale` pixels to a module, one every `pitch` pixels. Nothing in
/// it is a code, but every pair of patterns is a candidate group for the
/// reader.
fn tiled_finders(x: usize, y: usize, scale: usize, pitch: usize) -> u8 {
    let (mx, my) = ((x % pitch) / scale, (y % pitch) / scale);
    let dark = mx < 7
        && my < 7
        && (matches!(mx, 0 | 6)
            || matches!(my, 0 | 6)
            || ((2..=4).contains(&mx) && (2..=4).contains(&my)));
    if dark { 0 } else { 255 }
}

#[test]
fn a_search_that_runs_past_its_time_is_stopped_whatever_the_reader_is_doing() {
    // Thousands of finder patterns: the reader copies the whole image for each
    // pair it tries, which would take hours.
    let (side, scale, pitch) = (2000, 2, 24);
    let limits = Limits {
        max_time: Some(std::time::Duration::from_millis(100)),
        max_finders: None,
        max_grids: None,
        ..Limits::default()
    };
    let start = std::time::Instant::now();
    let f = find_in_grey(
        side,
        side,
        |x, y| tiled_finders(x, y, scale, pitch),
        1 << 30,
        &limits,
    );
    assert!(f.payloads.is_empty());
    assert!(f.cut.unwrap().contains("took over 100 ms"));
    // Far from the hours it takes unbounded; a loaded machine has room.
    assert!(start.elapsed() < std::time::Duration::from_secs(30));
}

#[test]
fn an_image_over_the_pixel_limit_is_not_searched() {
    let png = encoded(DynamicImage::ImageLuma8(grey(URL)), ImageFormat::Png);
    let small = Limits {
        max_pixels: Some(100),
        ..Limits::default()
    };
    let f = find(&png, 1 << 28, &small).unwrap();
    assert!(f.payloads.is_empty());
    assert!(f.cut.is_some());
    // `None` is no limit.
    let any = Limits {
        max_pixels: None,
        max_time: None,
        ..Limits::default()
    };
    assert_eq!(find(&png, 1 << 28, &any).unwrap().payloads, [URL]);
}

#[test]
fn an_image_without_a_code_and_what_is_not_an_image() {
    let blank = GrayImage::from_pixel(64, 64, image::Luma([255]));
    assert_eq!(
        read(&encoded(DynamicImage::ImageLuma8(blank), ImageFormat::Png)),
        Found::default()
    );
    assert!(find(b"not an image", 1 << 28, &Limits::default()).is_err());
}

#[test]
fn a_search_under_a_callers_settings_says_why_it_was_cut() {
    let png = encoded(DynamicImage::ImageLuma8(grey(URL)), ImageFormat::Png);
    let open = Settings {
        max_pixels: None,
        max_millis: None,
        max_codes: None,
        max_finders: None,
        max_grids: None,
        max_buffer_bytes: u64::MAX,
    };
    assert_eq!(search(&png, None, &open).unwrap().payloads, [URL]);
    assert_eq!(search(b"not an image", None, &open), None);
    // An image that does not decode within the buffer limit has no payloads
    // and a reason, not an error.
    let tight = Settings {
        max_buffer_bytes: 64,
        ..open
    };
    let f = search(&png, None, &tight).unwrap();
    assert!(f.payloads.is_empty());
    assert!(f.cut.unwrap().contains("64-byte decode limit"));
    // The time limit given in milliseconds reaches the search.
    let blank = GrayImage::from_pixel(256, 256, image::Luma([255]));
    let blank = encoded(DynamicImage::ImageLuma8(blank), ImageFormat::Png);
    let late = Settings {
        max_millis: Some(0),
        ..open
    };
    assert!(
        search(&blank, None, &late)
            .unwrap()
            .cut
            .unwrap()
            .contains("took over 0 ms")
    );
}

/// A CCITT image is refused on the size its dictionary declares, before the
/// codec runs over its stream or anything is allocated for it.
#[test]
fn a_codec_image_over_the_pixel_limit_is_refused_before_it_is_decoded() {
    use exav_unpack::{Raster, RasterCodec};
    let raster = Raster {
        width: 60_000,
        height: 60_000,
        bits: 1,
        codec: Some(RasterCodec::Ccitt {
            k: -1,
            end_of_line: false,
            encoded_byte_align: false,
            black_is_1: false,
            columns: 60_000,
            rows: 0,
        }),
        ..Raster::default()
    };
    let settings = Settings {
        max_pixels: Some(50_000_000),
        max_millis: None,
        max_codes: None,
        max_finders: None,
        max_grids: None,
        max_buffer_bytes: 1 << 40,
    };
    let f = search(&[0xff; 8], Some(&raster), &settings).unwrap();
    assert!(f.payloads.is_empty() && f.unread.is_none());
    assert!(f.cut.unwrap().contains("50000000-pixel limit"));
    // Without the pixel limit it is the decode ceiling that refuses it.
    let open = Settings {
        max_pixels: None,
        ..settings
    };
    let f = search(&[0xff; 8], Some(&raster), &open).unwrap();
    assert!(f.cut.is_none() && f.unread.is_some());
}
