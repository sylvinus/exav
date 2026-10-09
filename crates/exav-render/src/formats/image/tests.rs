use super::*;

/// A PNG written by the `png` crate itself, not through `image`.
fn png(
    width: u32,
    height: u32,
    color: png::ColorType,
    depth: png::BitDepth,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = png::Encoder::new(&mut out, width, height);
    e.set_color(color);
    e.set_depth(depth);
    e.write_header().unwrap().write_image_data(data).unwrap();
    out
}

/// 16-bit samples come back as written, unconverted: a caller that converts
/// them its own way (exav-imagehash's Pillow grey) sees what the file holds.
#[test]
fn sixteen_bit_samples_are_given_as_the_file_holds_them() {
    let values: [u16; 6] = [0, 1, 0x1234, 0x8000, 0xfffe, 0xffff];
    let be: Vec<u8> = values.iter().flat_map(|v| v.to_be_bytes()).collect();
    let file = png(2, 1, png::ColorType::Rgb, png::BitDepth::Sixteen, &be);
    let p = decode_any(&file, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height, p.channels), (2, 1, Channels::Rgb));
    assert_eq!(p.samples, Samples::U16(values.to_vec()));
}

/// RGBA8 for display is what `image` itself converts to, for every layout.
#[test]
fn rgba8_is_the_image_crates_conversion_for_every_layout() {
    let grey = [7u8, 200];
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (
            png(2, 1, png::ColorType::Grayscale, png::BitDepth::Eight, &grey),
            "luma8",
        ),
        (
            png(
                1,
                1,
                png::ColorType::GrayscaleAlpha,
                png::BitDepth::Eight,
                &[9, 128],
            ),
            "la8",
        ),
        (
            png(1, 1, png::ColorType::Rgb, png::BitDepth::Eight, &[1, 2, 3]),
            "rgb8",
        ),
        (
            png(
                1,
                1,
                png::ColorType::Rgba,
                png::BitDepth::Eight,
                &[1, 2, 3, 4],
            ),
            "rgba8",
        ),
        (
            png(
                1,
                1,
                png::ColorType::Grayscale,
                png::BitDepth::Sixteen,
                &[0xab, 0xcd],
            ),
            "luma16",
        ),
        (
            png(
                1,
                1,
                png::ColorType::Rgba,
                png::BitDepth::Sixteen,
                &[1, 2, 3, 4, 5, 6, 0xff, 0],
            ),
            "rgba16",
        ),
    ];
    for (file, what) in cases {
        let ours = decode_any(&file, DECODE_MAX).unwrap().to_rgba8();
        let theirs = image::load_from_memory(&file)
            .unwrap()
            .to_rgba8()
            .into_raw();
        assert_eq!(ours, theirs, "{what}");
    }
}

/// Float images (HDR decodes to them) convert as `image` converts them.
#[test]
fn float_pixels_convert_as_the_image_crate_does() {
    let img = DynamicImage::ImageRgb32F(
        ImageBuffer::from_raw(2, 1, vec![0.0, 0.5, 1.5, -1.0, 0.25, 1.0]).unwrap(),
    );
    let p = Pixels::from_dynamic(img.clone());
    assert_eq!(
        p.samples,
        Samples::F32(vec![0.0, 0.5, 1.5, -1.0, 0.25, 1.0])
    );
    assert_eq!(p.to_rgba8(), img.to_rgba8().into_raw());
}

/// A limit under the default is a size limit; over it, or on a damaged file,
/// the image is undecodable; an unknown format is unsupported.
#[test]
fn what_cannot_be_decoded_says_why() {
    let big = png(
        1000,
        1000,
        png::ColorType::Grayscale,
        png::BitDepth::Eight,
        &vec![0; 1_000_000],
    );
    assert_eq!(decode_any(&big, 4096), Err(Error::TooLarge));
    assert!(decode_any(&big, DECODE_MAX).is_ok());
    assert_eq!(
        decode_any(&big[..big.len() / 2], DECODE_MAX),
        Err(Error::Undecodable)
    );
    assert_eq!(
        decode_any(b"not an image at all", DECODE_MAX),
        Err(Error::Unsupported)
    );
}

/// The JPEG path is the vendored decoder: its size is the one the frame
/// header declares, read here from the bytes.
#[test]
fn a_jpeg_decodes_to_the_size_its_frame_header_declares() {
    let jpeg: &[u8] =
        include_bytes!("../../../../exav-imagehash/tests/fixtures/decoder_sensitive.jpg");
    let sof = (0..jpeg.len() - 9)
        .find(|&i| jpeg[i] == 0xff && matches!(jpeg[i + 1], 0xc0..=0xc2))
        .expect("a frame header");
    let height = u32::from(u16::from_be_bytes([jpeg[sof + 5], jpeg[sof + 6]]));
    let width = u32::from(u16::from_be_bytes([jpeg[sof + 7], jpeg[sof + 8]]));
    let p = decode(jpeg, Format::Jpeg, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height), (width, height));
    assert_eq!(p.to_rgba8().len(), width as usize * height as usize * 4);
}

/// Found by the `imagehash` fuzz target: weezl 0.1.10 asserted, in debug
/// builds, that a TIFF LZW table never holds 4,095 codes, which a stream
/// without a clear code reaches. One clear code, then a literal per pixel,
/// each adding a code to the table, 12-bit codes from the 1,790th on, as the
/// decoder widens them one code early (TIFF 6.0, section 13).
#[test]
fn a_tiff_lzw_strip_filling_its_table_without_a_clear_code_decodes() {
    let (width, height) = (64u16, 61u16);
    let pixels: Vec<u8> = (0..usize::from(width) * usize::from(height))
        .map(|i| (i * 7 + i / 64) as u8)
        .collect();
    let mut codes = vec![(256u16, 9u32)];
    for (i, &p) in pixels.iter().enumerate() {
        let bits = match i {
            0..254 => 9,
            254..766 => 10,
            766..1790 => 11,
            _ => 12,
        };
        codes.push((u16::from(p), bits));
    }
    codes.push((257, 12));
    let (mut strip, mut acc, mut n) = (Vec::new(), 0u64, 0u32);
    for (code, bits) in codes {
        acc = acc << bits | u64::from(code);
        n += bits;
        while n >= 8 {
            n -= 8;
            strip.push((acc >> n) as u8);
        }
    }
    if n > 0 {
        strip.push((acc << (8 - n)) as u8);
    }
    // Little-endian TIFF, the strip at 8, then the directory.
    let ifd = 8 + strip.len() as u32;
    let mut tiff = b"II*\0".to_vec();
    tiff.extend_from_slice(&ifd.to_le_bytes());
    tiff.extend_from_slice(&strip);
    let entries: [(u16, u16, u32); 9] = [
        (256, 3, width.into()),
        (257, 3, height.into()),
        (258, 3, 8),
        (259, 3, 5),
        (262, 3, 1),
        (273, 4, 8),
        (277, 3, 1),
        (278, 3, height.into()),
        (279, 4, strip.len() as u32),
    ];
    tiff.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for (tag, kind, value) in entries {
        tiff.extend_from_slice(&tag.to_le_bytes());
        tiff.extend_from_slice(&kind.to_le_bytes());
        tiff.extend_from_slice(&1u32.to_le_bytes());
        tiff.extend_from_slice(&value.to_le_bytes());
    }
    tiff.extend_from_slice(&0u32.to_le_bytes());
    let p = decode(&tiff, Format::Tiff, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height, p.channels), (64, 61, Channels::Luma));
    assert_eq!(p.samples, Samples::U8(pixels));
}

thread_local!(static PANICKED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) });

/// Records a panic on this thread, which `decode` would otherwise turn into
/// `Undecodable` without a trace.
fn watch_panics() {
    static HOOK: std::sync::Once = std::sync::Once::new();
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

/// A little-endian TIFF with one directory of `(tag, type, count, value)`
/// entries (values inline) and 8 bytes of strip data.
fn tiff_with(entries: &[(u16, u16, u32, u32)]) -> Vec<u8> {
    let mut tiff = b"II*\0".to_vec();
    tiff.extend_from_slice(&16u32.to_le_bytes());
    tiff.extend_from_slice(&[0; 8]);
    tiff.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for &(tag, kind, count, value) in entries {
        tiff.extend_from_slice(&tag.to_le_bytes());
        tiff.extend_from_slice(&kind.to_le_bytes());
        tiff.extend_from_slice(&count.to_le_bytes());
        tiff.extend_from_slice(&value.to_le_bytes());
    }
    tiff.extend_from_slice(&0u32.to_le_bytes());
    tiff
}

/// A TIFF's own numbers decide its sizes: counts and products of them that do
/// not fit are errors, not panics (each of these panicked a build with
/// overflow checks, or wrapped to a size that passed the consistency check).
#[test]
fn tiff_tags_at_the_ends_of_their_ranges_are_errors_not_panics() {
    let base = |extra: &[(u16, u16, u32, u32)]| {
        let mut e = vec![
            (256, 3, 1, 1),
            (257, 4, 1, 70_000),
            (258, 3, 1, 8),
            (259, 3, 1, 1),
            (262, 3, 1, 1),
            (273, 4, 1, 8),
            (277, 3, 1, 1),
            (278, 3, 1, 1),
            (279, 4, 1, 1),
        ];
        for x in extra {
            e.retain(|y| y.0 != x.0);
            e.push(*x);
        }
        e.sort_by_key(|x| x.0);
        tiff_with(&e)
    };
    // The same file at one row decodes: the builder is sound.
    assert!(decode(&base(&[(257, 4, 1, 1)]), Format::Tiff, DECODE_MAX).is_ok());
    // SampleFormat with no values.
    let empty_format = base(&[(339, 3, 0, 0)]);
    // 70,000 one-row strips of 65,535 planes.
    let many_planes = base(&[(277, 3, 1, 65_535), (284, 3, 1, 2)]);
    // 1x1 tiles over a 4,294,967,295 square image, planar.
    let many_tiles = tiff_with(&[
        (256, 4, 1, u32::MAX),
        (257, 4, 1, u32::MAX),
        (258, 3, 1, 8),
        (259, 3, 1, 1),
        (262, 3, 1, 1),
        (277, 3, 1, 65_535),
        (284, 3, 1, 2),
        (322, 4, 1, 1),
        (323, 4, 1, 1),
        (324, 4, 1, 8),
        (325, 4, 1, 1),
    ]);
    for (what, file) in [
        ("an empty SampleFormat", empty_format),
        ("planes times strips", many_planes),
        ("tiles across times down", many_tiles),
    ] {
        watch_panics();
        let _ = decode(&file, Format::Tiff, DECODE_MAX);
        assert!(!panicked(), "{what} panicked the decoder");
    }
}
