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

/// Palette indices with an alpha sample beside each (SamplesPerPixel 2): the
/// hash is of nothing, as ClamAV's decoder refuses it; the viewer draws RGBA.
#[test]
fn a_palette_tiff_with_an_alpha_sample_is_shown() {
    let mut map = vec![0u16; 768];
    map[1] = 65535; // index 1: red
    map[256 + 2] = 65535; // index 2: green
    let map: Vec<u8> = map.iter().flat_map(|v| v.to_le_bytes()).collect();
    let file = tiff_strip(
        2,
        1,
        &[1, 200, 2, 100],
        &[
            (258, 3, [8, 0].repeat(2)),
            (262, 3, short(3)),
            (277, 3, short(2)),
            (320, 3, map),
            (338, 3, short(2)),
        ],
    );
    assert_eq!(
        decode(&file, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&file, DECODE_MAX).unwrap();
    assert_eq!(p.channels, Channels::Rgba);
    assert_eq!(p.samples, Samples::U8(vec![255, 0, 0, 200, 0, 255, 0, 100]));
}

/// A raster of three bands that are not colours (photometric 1) shows its
/// first band, chunky or planar.
#[test]
fn a_multiband_tiff_shows_its_first_band() {
    let grey = |file: &[u8]| {
        let p = decode_any(file, DECODE_MAX).unwrap();
        assert_eq!(p.channels, Channels::Luma);
        p.samples
    };
    let entries = |planar: u16| {
        vec![
            (258, 3, [8, 0].repeat(3)),
            (262, 3, short(1)),
            (277, 3, short(3)),
            (284, 3, short(planar)),
            (338, 3, [0, 0].repeat(2)),
        ]
    };
    let chunky = tiff_strip(2, 1, &[10, 20, 30, 40, 50, 60], &entries(1));
    assert_eq!(grey(&chunky), Samples::U8(vec![10, 40]));
    let planar = tiff_strips(2, 1, &[&[10, 40], &[20, 50], &[30, 60]], &entries(2));
    assert_eq!(grey(&planar), Samples::U8(vec![10, 40]));
}

/// Old-style LZW (TIFF 5.0: least significant bit first, a code late, as in
/// GIF) starts 0x00 and an odd byte; libtiff reads it (`quad-lzw-compat.tiff`).
/// The hashing decoder reads it as the new style and fails.
#[test]
fn an_old_style_lzw_tiff_is_shown() {
    let pixels: Vec<u8> = (0..64).map(|i| (i * 7 % 256) as u8).collect();
    let strip = weezl::encode::Encoder::new(weezl::BitOrder::Lsb, 8)
        .encode(&pixels)
        .unwrap();
    assert_eq!(strip[0], 0);
    assert_eq!(strip[1] & 1, 1);
    let tiff = tiff_strip(
        8,
        8,
        &strip,
        &[
            (258, 3, [8, 0].to_vec()),
            (259, 3, short(5)),
            (262, 3, short(1)),
            (277, 3, short(1)),
        ],
    );
    assert_eq!(
        decode(&tiff, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&tiff, DECODE_MAX).unwrap();
    assert_eq!(p.samples, Samples::U8(pixels));
}

/// YCbCr stored with the chroma sampled 2 by 2 and no JPEG (libtiff's
/// `ycbcr-cat.tif`, LZW): units of four luma values, Cb and Cr, which the
/// decoder took for pixels of three samples and failed on.
#[test]
fn a_ycbcr_tiff_with_subsampled_chroma_and_no_jpeg_is_shown() {
    // Two units across, one down: the first all Y 100, Cb 128, Cr 200 (a red,
    // as in the test above), the second grey 50, 60 over 70, 80.
    let units = [100, 100, 100, 100, 128, 200, 50, 60, 70, 80, 128, 128];
    let tiff = tiff_strip(
        4,
        2,
        &units,
        &[
            (258, 3, [8, 0].repeat(3)),
            (262, 3, short(6)),
            (277, 3, short(3)),
            (530, 3, [2, 0, 2, 0].to_vec()),
        ],
    );
    assert_eq!(
        decode(&tiff, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&tiff, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height), (4, 2));
    let rgba = p.to_rgba8();
    let px = |x: usize, y: usize| rgba[(y * 4 + x) * 4..(y * 4 + x) * 4 + 3].to_vec();
    for (x, y) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
        assert_eq!(px(x, y), [200, 49, 100], "{x},{y}");
    }
    assert_eq!(px(2, 0), [50, 50, 50]);
    assert_eq!(px(3, 0), [60, 60, 60]);
    assert_eq!(px(2, 1), [70, 70, 70]);
    assert_eq!(px(3, 1), [80, 80, 80]);
}

/// A Deflate strip whose Adler-32 is wrong is read by libtiff and drawn by
/// Pillow (OpenCV's `multipage.tif`); the hashing decoder refuses it.
#[test]
fn a_deflate_tiff_with_a_wrong_checksum_is_shown() {
    use std::io::Write;
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(&[1, 2, 3, 4]).unwrap();
    let mut strip = z.finish().unwrap();
    let last = strip.len() - 1;
    strip[last] ^= 0xff;
    let tiff = tiff_strip(
        2,
        2,
        &strip,
        &[
            (258, 3, [8, 0].to_vec()),
            (259, 3, short(8)),
            (262, 3, short(1)),
            (277, 3, short(1)),
        ],
    );
    assert_eq!(
        decode(&tiff, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&tiff, DECODE_MAX).unwrap();
    assert_eq!(p.samples, Samples::U8(vec![1, 2, 3, 4]));
}

/// A directory whose next link points at itself ends the chain in libtiff,
/// which draws the image (`test_ifd_loop_to_self.tif`); the hashing decoder
/// calls it a cycle.
#[test]
fn a_tiff_whose_directory_links_to_itself_is_shown() {
    let mut tiff = tiff_with(&[
        (256, 3, 1, 2),
        (257, 3, 1, 1),
        (258, 3, 1, 8),
        (262, 3, 1, 1),
        (273, 4, 1, 8),
        (279, 4, 1, 2),
    ]);
    let end = tiff.len();
    tiff[end - 4..].copy_from_slice(&16u32.to_le_bytes());
    assert_eq!(
        decode(&tiff, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&tiff, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height), (2, 1));
}

/// A strip with no StripByteCounts (and no RowsPerStrip) runs to the end of the
/// file in libtiff, which reads it (a test scan, `tdf115863.tif`).
#[test]
fn a_tiff_strip_with_no_byte_count_is_shown() {
    let mut tiff = tiff_with(&[
        (256, 3, 1, 2),
        (257, 3, 1, 1),
        (258, 3, 1, 8),
        (262, 3, 1, 1),
        (273, 4, 1, 8),
        (277, 3, 1, 1),
    ]);
    tiff[8..10].copy_from_slice(&[7, 9]);
    assert_eq!(
        decode(&tiff, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&tiff, DECODE_MAX).unwrap();
    assert_eq!(p.samples, Samples::U8(vec![7, 9]));
}

/// CIELab (photometric 8): L* of 255 is white, a* and b* are signed.
#[test]
fn a_cielab_tiff_is_shown_in_rgb() {
    let tiff = tiff_strip(
        4,
        1,
        &[255, 0, 0, 0, 0, 0, 128, 127, 0, 128, 129, 0],
        &[
            (258, 3, [8, 0].repeat(3)),
            (262, 3, short(8)),
            (277, 3, short(3)),
        ],
    );
    assert_eq!(
        decode(&tiff, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&tiff, DECODE_MAX).unwrap();
    assert_eq!(p.channels, Channels::Rgb);
    let Samples::U8(v) = p.samples else { panic!() };
    assert!(v[..3].iter().all(|&c| c >= 254), "{v:?}");
    assert_eq!(v[3..6], [0, 0, 0]);
    // a* of +127 is red, of -127 (129 as a byte) green.
    assert!(v[6] > v[7] + 100, "{v:?}");
    assert!(v[10] > v[9] + 50, "{v:?}");
}

/// A JPEG in a TIFF with an Adobe marker, three components and the ids R, G, B
/// (an RGB JPEG: ImageSharp's `rgb_jpegcompressed_nojpegtable.tiff`).
/// zune-jpeg 0.4 takes it for CMYK, and the strip is refused.
#[test]
fn an_rgb_jpeg_in_a_tiff_is_shown() {
    const JPEG: &str = "ffd8ffee000e41646f626500640000000000ffdb0043001b12141714111b1716171e1c1b2028422b28252528513a3d3042605565645f555d5b6a7899816a7190735b5d85b586909ea3abadab6780bcc9baa6c799a8aba4ffdb0043011c1e1e2823284e2b2b4ea46e5d6ea4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4ffc00011080008000803521100471101421101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03520047114211003f00a75ce7ae7fffd9";
    let jpeg: Vec<u8> = (0..JPEG.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&JPEG[i..i + 2], 16).unwrap())
        .collect();
    let tiff = tiff_strip(
        8,
        8,
        &jpeg,
        &[
            (258, 3, [8, 0].repeat(3)),
            (259, 3, short(7)),
            (262, 3, short(2)),
            (277, 3, short(3)),
        ],
    );
    let p = decode_any(&tiff, DECODE_MAX).unwrap();
    assert_eq!(p.channels, Channels::Rgb);
    let Samples::U8(v) = p.samples else { panic!() };
    // The samples as the JPEG stores them, read as RGB.
    for (got, want) in v[..3].iter().zip([88u8, 100, 209]) {
        assert!(got.abs_diff(want) <= 2, "{:?}", &v[..3]);
    }
}

/// libtiff keeps the offsets of tiles and of strips in one field: a tiled file
/// may name its tiles with StripOffsets and StripByteCounts (ImageSharp's
/// `quad-tile.tiff`).
#[test]
fn a_tiled_tiff_with_strip_offsets_is_shown() {
    // Two tiles of one column each, the first holding 10 and 30.
    let tiled = tiff_strips(
        2,
        2,
        &[&[10, 30], &[20, 40]],
        &[
            (258, 3, [8, 0].to_vec()),
            (262, 3, short(1)),
            (277, 3, short(1)),
            (322, 3, short(1)),
            (323, 3, short(2)),
        ],
    );
    let p = decode_any(&tiled, DECODE_MAX).unwrap();
    assert_eq!(p.samples, Samples::U8(vec![10, 20, 30, 40]));
    assert_eq!(
        decode(&tiled, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
}

/// The Orientation tag of a TIFF says how the stored rows are turned for the
/// eye; `decode`, which is what is hashed, leaves them as stored.
#[test]
fn a_tiff_is_turned_as_its_orientation_says() {
    // 3x2, stored as 1 2 3 / 4 5 6.
    for (orientation, w, h, shown) in [
        (1u16, 3, 2, [1, 2, 3, 4, 5, 6]),
        (2, 3, 2, [3, 2, 1, 6, 5, 4]),
        (3, 3, 2, [6, 5, 4, 3, 2, 1]),
        (4, 3, 2, [4, 5, 6, 1, 2, 3]),
        (5, 2, 3, [1, 4, 2, 5, 3, 6]),
        (6, 2, 3, [4, 1, 5, 2, 6, 3]),
        (7, 2, 3, [6, 3, 5, 2, 4, 1]),
        (8, 2, 3, [3, 6, 2, 5, 1, 4]),
        (9, 3, 2, [1, 2, 3, 4, 5, 6]),
    ] {
        let file = tiff_strip(
            3,
            2,
            &[1, 2, 3, 4, 5, 6],
            &[
                (258, 3, short(8)),
                (262, 3, short(1)),
                (274, 3, short(orientation)),
                (277, 3, short(1)),
            ],
        );
        let hashed = decode(&file, Format::Tiff, DECODE_MAX).unwrap();
        assert_eq!(hashed.samples, Samples::U8(vec![1, 2, 3, 4, 5, 6]));
        let p = decode_any(&file, DECODE_MAX).unwrap();
        assert_eq!((p.width, p.height), (w, h), "orientation {orientation}");
        assert_eq!(
            p.samples,
            Samples::U8(shown.to_vec()),
            "orientation {orientation}"
        );
    }
}

/// Colours stored premultiplied by their alpha (an extra sample of kind 1)
/// are drawn as they are, and look dark at a soft edge; the viewer divides
/// them, the hash is of the samples.
#[test]
fn a_tiff_with_associated_alpha_is_shown_divided_by_it() {
    let rgba8 = (258, 3, [8, 0].repeat(4));
    let extra = (338, 3, short(1));
    let file = tiff_strip(
        2,
        1,
        &[10, 20, 30, 128, 90, 90, 90, 0],
        &[rgba8, (262, 3, short(2)), (277, 3, short(4)), extra],
    );
    let Samples::U8(hashed) = decode(&file, Format::Tiff, DECODE_MAX).unwrap().samples else {
        panic!()
    };
    assert_eq!(hashed, [10, 20, 30, 128, 90, 90, 90, 0]);
    let p = decode_any(&file, DECODE_MAX).unwrap();
    assert_eq!(p.channels, Channels::Rgba);
    assert_eq!(p.samples, Samples::U8(vec![20, 40, 60, 128, 0, 0, 0, 0]));
    // Grey and alpha, the same.
    let file = tiff_strip(
        1,
        1,
        &[10, 128],
        &[
            (258, 3, [8, 0].repeat(2)),
            (262, 3, short(1)),
            (277, 3, short(2)),
            (338, 3, short(1)),
        ],
    );
    let p = decode_any(&file, DECODE_MAX).unwrap();
    assert_eq!(p.samples, Samples::U8(vec![20, 128]));
}

/// An extra sample of no stated use (ExtraSamples 0) is not a transparency: a
/// 16-bit picture with such a fourth band came out nearly invisible.
#[test]
fn an_extra_sample_of_no_stated_use_is_not_an_alpha() {
    let sixteen = |n: usize| (258, 3, [16, 0].repeat(n));
    let value = |v: u16| v.to_le_bytes();
    let rgba16 = [value(0x1000), value(0x2000), value(0x3000), value(0x0100)].concat();
    let file = tiff_strip(
        1,
        1,
        &rgba16,
        &[
            sixteen(4),
            (262, 3, short(2)),
            (277, 3, short(4)),
            (338, 3, short(0)),
        ],
    );
    let p = decode_any(&file, DECODE_MAX).unwrap();
    assert_eq!(p.channels, Channels::Rgba);
    assert_eq!(p.samples, Samples::U8(vec![0x10, 0x20, 0x30, 255]));
    // The same with the extra sample declared an unassociated alpha: kept.
    let file = tiff_strip(
        1,
        1,
        &rgba16,
        &[
            sixteen(4),
            (262, 3, short(2)),
            (277, 3, short(4)),
            (338, 3, short(2)),
        ],
    );
    let p = decode_any(&file, DECODE_MAX).unwrap();
    assert_eq!(
        p.samples,
        Samples::U16(vec![0x1000, 0x2000, 0x3000, 0x0100])
    );
}

/// Zstandard strips (compression 50000) are the viewer's to read; the hash is
/// of what ClamAV's decoder reads, which has none.
#[test]
fn a_zstandard_tiff_is_shown_and_not_hashed() {
    let pixels: Vec<u8> = (0..32).map(|i| (i * 8) as u8).collect();
    let strip =
        ruzstd::encoding::compress_to_vec(&pixels[..], ruzstd::encoding::CompressionLevel::Fastest);
    let file = tiff_strip(
        8,
        4,
        &strip,
        &[
            (258, 3, short(8)),
            (259, 3, short(50000)),
            (262, 3, short(1)),
            (277, 3, short(1)),
        ],
    );
    assert_eq!(
        decode(&file, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&file, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height, p.channels), (8, 4, Channels::Luma));
    assert_eq!(p.samples, Samples::U8(pixels));
    // The viewer's codecs are off again for what is hashed.
    assert_eq!(
        decode(&file, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
}

/// Old-style JPEG (compression 6) in the three layouts files have it in (made
/// by `tests/fixtures/ojpeg/make.py`, and read by libtiff and Pillow too): a
/// whole JPEG as the strip, a scan with its tables in tags, a JPEG stream the
/// file points to that the strip lies in, and one that stops short of the scan
/// header, which starts the strip. The hash path has none.
#[test]
fn old_style_jpeg_tiffs_are_shown() {
    for name in ["whole", "tables", "interchange", "scanheader"] {
        let path = format!(
            "{}/tests/fixtures/ojpeg/{name}.tif",
            env!("CARGO_MANIFEST_DIR")
        );
        let file = std::fs::read(path).unwrap();
        assert_eq!(
            decode(&file, Format::Tiff, DECODE_MAX),
            Err(Error::Undecodable),
            "{name}"
        );
        let p = decode_any(&file, DECODE_MAX).unwrap();
        assert_eq!(
            (p.width, p.height, p.channels),
            (16, 16, Channels::Rgb),
            "{name}"
        );
        let rgba = p.to_rgba8();
        let near = |x: usize, y: usize, want: [u8; 3]| {
            let got = &rgba[(y * 16 + x) * 4..][..3];
            assert!(
                got.iter().zip(want).all(|(&g, w)| g.abs_diff(w) < 30),
                "{name} at {x},{y}: {got:?} for {want:?}"
            );
        };
        near(2, 3, [200, 30, 30]);
        near(13, 12, [30, 30, 200]);
    }
}

/// Grey of 12 bits, the values one after another and each row to a byte
/// (libtiff cannot show them; Pillow reads them as 16-bit): shown stretched,
/// and reversed when white is zero. The hash path refuses them.
#[test]
fn a_twelve_bit_grey_tiff_is_shown() {
    // 3 values to a row of 5 bytes (36 bits and 4 of padding).
    let values = [[0u16, 1000, 2000], [3000, 4000, 4095]];
    let strip: Vec<u8> = values
        .iter()
        .flat_map(|row| {
            let bits = row.iter().fold(0u64, |acc, v| acc << 12 | u64::from(*v)) << 4;
            bits.to_be_bytes()[3..].to_vec()
        })
        .collect();
    for (photometric, reversed) in [(1, false), (0, true)] {
        let file = tiff_strip(
            3,
            2,
            &strip,
            &[
                (258, 3, short(12)),
                (262, 3, short(photometric)),
                (277, 3, short(1)),
            ],
        );
        assert_eq!(
            decode(&file, Format::Tiff, DECODE_MAX),
            Err(Error::Undecodable)
        );
        let p = decode_any(&file, DECODE_MAX).unwrap();
        assert_eq!((p.width, p.height, p.channels), (3, 2, Channels::Luma));
        let Samples::U8(mut v) = p.samples else {
            panic!()
        };
        if reversed {
            v.reverse();
        }
        assert_eq!(v[0], 0);
        assert_eq!(v[5], 255);
        // The two brightest share the top of the stretch.
        assert!(
            v.array_windows().all(|[a, b]| a <= b) && v[0] < v[1] && v[1] < v[2],
            "{v:?}"
        );
    }
}

/// Packed samples have no byte order: a big-endian file's 12-bit values are
/// read as a little-endian file's are.
#[test]
fn a_twelve_bit_tiff_of_the_other_byte_order_is_read_the_same() {
    let entry = |tag: u16, kind: u16, value: u32| {
        let mut e = tag.to_be_bytes().to_vec();
        e.extend_from_slice(&kind.to_be_bytes());
        e.extend_from_slice(&1u32.to_be_bytes());
        if kind == 3 {
            e.extend_from_slice(&(value as u16).to_be_bytes());
            e.extend_from_slice(&[0, 0]);
        } else {
            e.extend_from_slice(&value.to_be_bytes());
        }
        e
    };
    // The values 0x123, 0xABC, 0x456 and 0xFFF, behind the header.
    let mut file = b"MM\0*\0\0\0\x0e\x12\x3a\xbc\x45\x6f\xff".to_vec();
    let entries = [
        entry(256, 3, 4),
        entry(257, 3, 1),
        entry(258, 3, 12),
        entry(259, 3, 1),
        entry(262, 3, 1),
        entry(273, 4, 8),
        entry(277, 3, 1),
        entry(278, 3, 1),
        entry(279, 4, 6),
    ];
    file.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for e in entries {
        file.extend_from_slice(&e);
    }
    file.extend_from_slice(&[0; 4]);
    let p = decode_any(&file, DECODE_MAX).unwrap();
    let Samples::U8(v) = p.samples else { panic!() };
    // In the order of the values: 0x123 < 0x456 < 0xABC <= 0xFFF (the top of
    // the stretch is shared).
    assert!(v[0] < v[2] && v[2] < v[1] && v[1] <= v[3], "{v:?}");
}

/// libtiff takes the first entries of a BitsPerSample with more than the
/// samples a pixel has, and a file with no photometric interpretation is grey
/// (or RGB with three samples) to GIS programs.
#[test]
fn a_tiff_with_extra_bit_counts_or_no_photometric_is_shown() {
    let extra = tiff_strip(
        2,
        1,
        &[10, 20, 30, 40, 50, 60],
        &[
            (
                258,
                3,
                [8u16, 8, 8, 1]
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect(),
            ),
            (262, 3, short(2)),
            (277, 3, short(3)),
        ],
    );
    let none = tiff_strip(
        2,
        1,
        &[10, 20, 30, 40, 50, 60],
        &[(258, 3, vec![8, 0, 8, 0, 8, 0]), (277, 3, short(3))],
    );
    for file in [extra, none] {
        assert_eq!(
            decode(&file, Format::Tiff, DECODE_MAX),
            Err(Error::Undecodable)
        );
        let p = decode_any(&file, DECODE_MAX).unwrap();
        assert_eq!(p.channels, Channels::Rgb);
        assert_eq!(p.samples, Samples::U8(vec![10, 20, 30, 40, 50, 60]));
    }
    let grey = tiff_strip(2, 1, &[7, 9], &[(258, 3, short(8)), (277, 3, short(1))]);
    assert_eq!(
        decode(&grey, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    assert_eq!(
        decode_any(&grey, DECODE_MAX).unwrap().samples,
        Samples::U8(vec![7, 9])
    );
}

/// LZMA strips (compression 34925) are an xz stream with one LZMA2 block, as
/// libtiff writes them, behind a delta filter when it predicts; made with
/// Python's `lzma`. The viewer reads them, the hash path does not.
#[test]
fn an_lzma_tiff_is_shown_and_not_hashed() {
    let pixels: Vec<u8> = (0..32).map(|i| (i * 8) as u8).collect();
    for strip in [
        "fd377a585a000000ff12d9410200210100000000372797d601001f0008101820283038404850586068\
         707880889098a0a8b0b8c0c8d0d8e0e8f0f8000001302010a3aec406729e7a010000000000595a",
        "fd377a585a000000ff12d94102010301002101002895101ae0001f00075d0000029169554000000000\
         011b20795edeb206729e7a010000000000595a",
    ] {
        let file = tiff_strip(
            8,
            4,
            &hex(strip),
            &[
                (258, 3, short(8)),
                (259, 3, short(34925)),
                (262, 3, short(1)),
                (277, 3, short(1)),
            ],
        );
        assert_eq!(
            decode(&file, Format::Tiff, DECODE_MAX),
            Err(Error::Undecodable)
        );
        let p = decode_any(&file, DECODE_MAX).unwrap();
        assert_eq!((p.width, p.height, p.channels), (8, 4, Channels::Luma));
        assert_eq!(p.samples, Samples::U8(pixels.clone()));
    }
}

/// ThunderScan (compression 32809) codes 4-bit pixels as runs of the last
/// one, 2-bit and 3-bit steps from it, and raw values; a row at a time.
#[test]
fn a_thunderscan_tiff_is_shown() {
    let strip = [
        // 3 raw, 3 more of it, steps +1 -1 (2 skips), steps +2 -1.
        0xC3,
        0x03,
        0x40 | 1 << 4 | 3 << 2 | 2,
        0x80 | 2 << 3 | 7,
        // Eight raw values.
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC4,
        0xC5,
        0xC6,
        0xC7,
        // Eight of the last pixel, which starts a row as 0.
        0x08,
        // Raw 15, seven of it.
        0xCF,
        0x07,
    ];
    let file = tiff_strip(
        8,
        4,
        &strip,
        &[
            (258, 3, short(4)),
            (259, 3, short(32809)),
            (262, 3, short(1)),
            (277, 3, short(1)),
        ],
    );
    assert_eq!(
        decode(&file, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&file, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height, p.channels), (8, 4, Channels::Luma));
    let want: Vec<u8> = [
        3, 3, 3, 3, 4, 3, 5, 4, 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
    .into_iter()
    .chain([15; 8])
    .map(|v| v * 17)
    .collect();
    assert_eq!(p.samples, Samples::U8(want));
}

/// A 2x16 grey image in one LZW tile of 16x16. The decoder reads a row's two
/// bytes, then its 14 of padding, and with this data `weezl` (0.1.10 as well
/// as 0.1.12) gives 226 of the 256 bytes and stops: the hash is of what
/// ClamAV's reading gives, none; the viewer's block-wise reading is whole.
#[test]
fn an_lzw_tile_that_weezl_ends_short_is_read_whole_for_the_viewer() {
    let mut x = 27u32.wrapping_mul(2654435761).wrapping_add(12345);
    let mut tile = Vec::new();
    let mut pixels = Vec::new();
    for _ in 0..16 {
        for column in 0..16 {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            let value = if column < 2 {
                (x >> 16) as u8 & 0x3f
            } else {
                0
            };
            tile.push(value);
            if column < 2 {
                pixels.push(value);
            }
        }
    }
    let strip = weezl::encode::Encoder::with_tiff_size_switch(weezl::BitOrder::Msb, 8)
        .encode(&tile)
        .unwrap();
    // The one tile, at 8; then the directory.
    let mut file = b"II*\0".to_vec();
    file.extend_from_slice(&(8 + strip.len() as u32).to_le_bytes());
    file.extend_from_slice(&strip);
    let entries: [(u16, u16, u32); 10] = [
        (256, 3, 2),
        (257, 3, 16),
        (258, 3, 8),
        (259, 3, 5),
        (262, 3, 1),
        (277, 3, 1),
        (322, 3, 16),
        (323, 3, 16),
        (324, 4, 8),
        (325, 4, strip.len() as u32),
    ];
    file.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for (tag, kind, value) in entries {
        file.extend_from_slice(&tag.to_le_bytes());
        file.extend_from_slice(&kind.to_le_bytes());
        file.extend_from_slice(&1u32.to_le_bytes());
        file.extend_from_slice(&value.to_le_bytes());
    }
    file.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        decode(&file, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&file, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height), (2, 16));
    assert_eq!(p.samples, Samples::U8(pixels));
}

/// A 20x20 grey image in LZW tiles of 16x16, four of them, the last three
/// partly outside the image: the decoder reads the data of a row of such a
/// tile and skips the padding, and at the end of a stream asked for more than
/// the decoder had taken the end code of, `weezl` said `NoProgress` with two
/// bytes of output, which the reader asserted against.
#[test]
fn lzw_tiles_that_overhang_the_image_decode_whole() {
    watch_panics();
    let pixel = |x: usize, y: usize| ((x * 37) ^ (y * 91)).wrapping_add(x * y) as u8;
    let mut tiles = Vec::new();
    for (tx, ty) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
        let mut data = Vec::new();
        for y in 0..16 {
            for x in 0..16 {
                let (px, py) = (tx * 16 + x, ty * 16 + y);
                data.push(if px < 20 && py < 20 { pixel(px, py) } else { 0 });
            }
        }
        tiles.push(
            weezl::encode::Encoder::with_tiff_size_switch(weezl::BitOrder::Msb, 8)
                .encode(&data)
                .unwrap(),
        );
    }
    let mut file = b"II*\0\0\0\0\0".to_vec();
    let (mut offsets, mut counts) = (Vec::new(), Vec::new());
    for t in &tiles {
        offsets.extend_from_slice(&(file.len() as u32).to_le_bytes());
        counts.extend_from_slice(&(t.len() as u32).to_le_bytes());
        file.extend_from_slice(t);
        file.resize(file.len().next_multiple_of(2), 0);
    }
    let (offsets_at, counts_at) = (file.len() as u32, file.len() as u32 + 16);
    file.extend_from_slice(&offsets);
    file.extend_from_slice(&counts);
    let ifd = file.len() as u32;
    file[4..8].copy_from_slice(&ifd.to_le_bytes());
    let entries: [(u16, u16, u32, u32); 10] = [
        (256, 3, 1, 20),
        (257, 3, 1, 20),
        (258, 3, 1, 8),
        (259, 3, 1, 5),
        (262, 3, 1, 1),
        (277, 3, 1, 1),
        (322, 3, 1, 16),
        (323, 3, 1, 16),
        (324, 4, 4, offsets_at),
        (325, 4, 4, counts_at),
    ];
    file.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for (tag, kind, count, value) in entries {
        file.extend_from_slice(&tag.to_le_bytes());
        file.extend_from_slice(&kind.to_le_bytes());
        file.extend_from_slice(&count.to_le_bytes());
        file.extend_from_slice(&value.to_le_bytes());
    }
    file.extend_from_slice(&0u32.to_le_bytes());
    let p = decode(&file, Format::Tiff, DECODE_MAX).unwrap();
    let want: Vec<u8> = (0..20)
        .flat_map(|y| (0..20).map(move |x| pixel(x, y)))
        .collect();
    assert_eq!(p.samples, Samples::U8(want));
    assert!(!panicked());
}

/// A tile 4,294,967,295 wide on an image one pixel wide, floating point, with
/// the floating point predictor: the decoder sets a buffer aside for one row of
/// the tile, 51 GB, before it reads anything. It is over the limit asked for,
/// and said so, not an allocation.
#[test]
fn a_tile_row_over_the_limit_is_too_large_before_it_is_allocated() {
    let file = tiff_with(&[
        (256, 4, 1, 1),
        (257, 4, 1, 1),
        (258, 3, 1, 32),
        (259, 3, 1, 1),
        (262, 3, 1, 2),
        (277, 3, 1, 3),
        (317, 3, 1, 3),
        (322, 4, 1, u32::MAX),
        (323, 4, 1, 1),
        (324, 4, 1, 8),
        (325, 4, 1, 1),
        (339, 3, 1, 3),
    ]);
    assert_eq!(
        decode(&file, Format::Tiff, 16 << 20).err(),
        Some(Error::TooLarge)
    );
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

/// A TIFF of one uncompressed strip: `entries` are `(tag, type, values)` with
/// the values written out of line after the strip.
fn tiff_strip(width: u32, height: u32, strip: &[u8], entries: &[(u16, u16, Vec<u8>)]) -> Vec<u8> {
    tiff_strips(width, height, &[strip], entries)
}

/// [`tiff_strip`] of several strips of `height` rows each (a planar image has
/// one per band).
fn tiff_strips(
    width: u32,
    height: u32,
    strips: &[&[u8]],
    entries: &[(u16, u16, Vec<u8>)],
) -> Vec<u8> {
    let long = |v: Vec<u32>| v.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>();
    let mut at = 8u32;
    let mut offsets = Vec::new();
    for s in strips {
        offsets.push(at);
        at += s.len() as u32;
    }
    let mut all: Vec<(u16, u16, Vec<u8>)> = vec![
        (256, 4, width.to_le_bytes().to_vec()),
        (257, 4, height.to_le_bytes().to_vec()),
        (259, 3, 1u16.to_le_bytes().to_vec()),
        (273, 4, long(offsets)),
        (278, 4, height.to_le_bytes().to_vec()),
        (
            279,
            4,
            long(strips.iter().map(|s| s.len() as u32).collect()),
        ),
    ];
    // An entry given replaces the default of its tag.
    all.retain(|e| !entries.iter().any(|g| g.0 == e.0));
    all.extend(entries.iter().cloned());
    all.sort_by_key(|e| e.0);
    let mut out = b"II*\0".to_vec();
    out.extend_from_slice(&0u32.to_le_bytes());
    for s in strips {
        out.extend_from_slice(s);
    }
    let mut blobs = Vec::new();
    let mut table = Vec::new();
    let blob_base = at as usize;
    let entry_count = all.len() as u16;
    for (tag, kind, bytes) in &all {
        let size = match kind {
            3 => 2,
            4 => 4,
            _ => 1,
        };
        let count = (bytes.len() / size) as u32;
        table.extend_from_slice(&tag.to_le_bytes());
        table.extend_from_slice(&kind.to_le_bytes());
        table.extend_from_slice(&count.to_le_bytes());
        if bytes.len() <= 4 {
            let mut v = bytes.clone();
            v.resize(4, 0);
            table.extend_from_slice(&v);
        } else {
            table.extend_from_slice(&((blob_base + blobs.len()) as u32).to_le_bytes());
            blobs.extend_from_slice(bytes);
            if blobs.len() % 2 == 1 {
                blobs.push(0);
            }
        }
    }
    out.extend_from_slice(&blobs);
    let ifd_at = out.len() as u32;
    out[4..8].copy_from_slice(&ifd_at.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    // The entries must be in tag order.
    let mut rows: Vec<&[u8]> = table.chunks(12).collect();
    rows.sort_by_key(|r| u16::from_le_bytes([r[0], r[1]]));
    for r in rows {
        out.extend_from_slice(r);
    }
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

fn short(v: u16) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

/// What the hashing decoder refuses, `decode_any` draws for the eye.
#[test]
fn tiffs_of_floats_signed_values_and_palettes_are_shown() {
    // 32-bit floats: the 99.5th percentile and up is white.
    let strip: Vec<u8> = [0.0f32, 100.0, 200.0, 300.0]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    let file = tiff_strip(
        4,
        1,
        &strip,
        &[
            (258, 3, short(32)),
            (262, 3, short(1)),
            (277, 3, short(1)),
            (339, 3, short(3)),
        ],
    );
    assert_eq!(
        decode(&file, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&file, DECODE_MAX).unwrap();
    assert_eq!(p.channels, Channels::Luma);
    let Samples::U8(v) = p.samples else { panic!() };
    assert_eq!((v[0], v[2], v[3]), (0, 255, 255));
    assert!(v[1] > 100 && v[1] < 150, "{v:?}");

    // Signed 16-bit with a nodata value, which is neither the lowest nor
    // counted in the range.
    let strip: Vec<u8> = [-9999i16, 10, 20, 30, 40]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    let file = tiff_strip(
        5,
        1,
        &strip,
        &[
            (258, 3, short(16)),
            (262, 3, short(1)),
            (277, 3, short(1)),
            (339, 3, short(2)),
            (42113, 2, b"-9999\0".to_vec()),
        ],
    );
    let Samples::U8(v) = decode_any(&file, DECODE_MAX).unwrap().samples else {
        panic!()
    };
    assert_eq!(v, [0, 0, 128, 255, 255]);

    // A palette of 8 bits, and one of 4 bits, packed.
    let map = |n: usize| -> Vec<u8> {
        let mut m = Vec::new();
        for channel in 0..3usize {
            for i in 0..n {
                m.extend(((i * (channel + 1) * 257) as u16).to_le_bytes());
            }
        }
        m
    };
    let eight = tiff_strip(
        3,
        1,
        &[0, 1, 2],
        &[
            (258, 3, short(8)),
            (262, 3, short(3)),
            (277, 3, short(1)),
            (320, 3, map(256)),
        ],
    );
    let four = tiff_strip(
        3,
        1,
        &[0x01, 0x20],
        &[
            (258, 3, short(4)),
            (262, 3, short(3)),
            (277, 3, short(1)),
            (320, 3, map(16)),
        ],
    );
    for file in [eight, four] {
        assert_eq!(
            decode(&file, Format::Tiff, DECODE_MAX),
            Err(Error::Undecodable)
        );
        let p = decode_any(&file, DECODE_MAX).unwrap();
        assert_eq!(p.channels, Channels::Rgb);
        let Samples::U8(v) = p.samples else { panic!() };
        // Entry i is (i, 2i, 3i) in the high bytes of the 16-bit map.
        assert_eq!(v, [0, 0, 0, 1, 2, 3, 2, 4, 6]);
    }

    // One plane of a planar file.
    let file = tiff_strip(
        2,
        2,
        &[1, 2, 3, 4],
        &[
            (258, 3, short(8)),
            (262, 3, short(1)),
            (277, 3, short(1)),
            (284, 3, short(2)),
        ],
    );
    assert_eq!(
        decode(&file, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let Samples::U8(v) = decode_any(&file, DECODE_MAX).unwrap().samples else {
        panic!()
    };
    assert_eq!(v, [1, 2, 3, 4]);

    // Grey of 4 bits and of 2 bits, black or white first.
    for (bits, packed, want) in [
        (4u16, [0x0F, 0x48], [0, 255, 68, 136]),
        (2, [0b0011_0110, 0], [0, 255, 85, 170]),
    ] {
        let file = tiff_strip(
            4,
            1,
            &packed,
            &[
                (258, 3, short(bits)),
                (262, 3, short(1)),
                (277, 3, short(1)),
            ],
        );
        let Samples::U8(v) = decode_any(&file, DECODE_MAX).unwrap().samples else {
            panic!()
        };
        assert_eq!(v, want, "{bits} bits");
        let inverted = tiff_strip(
            4,
            1,
            &packed,
            &[
                (258, 3, short(bits)),
                (262, 3, short(0)),
                (277, 3, short(1)),
            ],
        );
        let Samples::U8(v) = decode_any(&inverted, DECODE_MAX).unwrap().samples else {
            panic!()
        };
        assert_eq!(v, want.map(|w| 255 - w), "{bits} bits, white first");
    }

    // Damage is still damage.
    assert!(decode_any(&file[..file.len() / 2], DECODE_MAX).is_err());
}

/// A DDS header (and the DX10 one when `dxgi` is given) before `body`.
#[cfg(feature = "dds")]
fn dds(width: u32, height: u32, pixel_format: [u32; 8], dxgi: Option<u32>, body: &[u8]) -> Vec<u8> {
    let mut out = b"DDS ".to_vec();
    let mut header = [0u32; 31];
    header[0] = 124;
    header[1] = 0x1007;
    header[2] = height;
    header[3] = width;
    header[18..26].copy_from_slice(&pixel_format);
    header[26] = 0x1000;
    for v in header {
        out.extend_from_slice(&v.to_le_bytes());
    }
    if let Some(f) = dxgi {
        for v in [f, 3, 0, 1, 0] {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
    out.extend_from_slice(body);
    out
}

#[cfg(feature = "dds")]
fn four_cc(c: &[u8; 4]) -> [u32; 8] {
    [32, 4, u32::from_le_bytes(*c), 0, 0, 0, 0, 0]
}

/// What `image` does not read of DDS, `decode_any` draws.
#[cfg(feature = "dds")]
#[test]
fn dds_of_other_blocks_sizes_and_layouts_is_shown() {
    let u8s = |p: Pixels| match p.samples {
        Samples::U8(v) => v,
        _ => panic!("not bytes"),
    };
    // BC1 of a size that is not a multiple of 4: a red block, cropped to 5x3.
    let red = [0x00, 0xf8, 0x00, 0xf8, 0, 0, 0, 0];
    let file = dds(5, 3, four_cc(b"DXT1"), None, &[red, red, red, red].concat());
    assert_eq!(
        decode(&file, Format::Dds, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&file, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height), (5, 3));
    let v = u8s(p);
    assert_eq!(v.len(), 5 * 3 * 4);
    assert!(v.chunks(4).all(|px| px == [255, 0, 0, 255]), "{v:?}");

    // BC4: 200 as a grey, through the DX10 header (80, BC4_UNORM).
    let bc4 = [200, 200, 0, 0, 0, 0, 0, 0];
    let v = u8s(decode_any(&dds(4, 4, four_cc(b"DX10"), Some(80), &bc4), DECODE_MAX).unwrap());
    assert!(v.chunks(4).all(|px| px == [200, 200, 200, 255]), "{v:?}");

    // A normal map in BC5: x and y as stored, z worked out (flat is 128, 128, 255).
    let bc5 = [128, 128, 0, 0, 0, 0, 0, 0, 128, 128, 0, 0, 0, 0, 0, 0];
    let v = u8s(decode_any(&dds(4, 4, four_cc(b"ATI2"), None, &bc5), DECODE_MAX).unwrap());
    assert_eq!(&v[..4], [128, 128, 255, 255]);

    // 16-bit 5:6:5, by its masks.
    let masks = [32, 0x40, 0, 16, 0xf800, 0x7e0, 0x1f, 0];
    let body: Vec<u8> = [0xf800u16, 0x07e0, 0x001f, 0xffff]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    let v = u8s(decode_any(&dds(2, 2, masks, None, &body), DECODE_MAX).unwrap());
    assert_eq!(
        v,
        [
            255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255
        ]
    );

    // A luminance of 8 bits.
    let lum = [32, 0x2_0000, 0, 8, 0xff, 0, 0, 0];
    let v = u8s(decode_any(&dds(2, 1, lum, None, &[10, 250]), DECODE_MAX).unwrap());
    assert_eq!(v, [10, 10, 10, 255, 250, 250, 250, 255]);

    // Half floats, four to a pixel (DXGI 10).
    let one = 0x3c00u16.to_le_bytes();
    let body = [one, [0, 0], [0, 0], one].concat();
    let p = decode_any(&dds(1, 1, four_cc(b"DX10"), Some(10), &body), DECODE_MAX).unwrap();
    assert_eq!(p.samples, Samples::F32(vec![1.0, 0.0, 0.0, 1.0]));

    // A typeless BC1 (DXGI 70) is read as BC1.
    let typeless = dds(
        5,
        3,
        four_cc(b"DX10"),
        Some(70),
        &[red, red, red, red].concat(),
    );
    let v = u8s(decode_any(&typeless, DECODE_MAX).unwrap());
    assert!(v.chunks(4).all(|px| px == [255, 0, 0, 255]), "{v:?}");

    // An 8-bit palette of RGBA entries.
    let mut body = vec![0u8; 1024];
    body[4..8].copy_from_slice(&[9, 8, 7, 255]);
    body[8..12].copy_from_slice(&[1, 2, 3, 128]);
    body.extend_from_slice(&[1, 2]);
    let v = u8s(decode_any(
        &dds(2, 1, [32, 0x20, 0, 8, 0, 0, 0, 0], None, &body),
        DECODE_MAX,
    )
    .unwrap());
    assert_eq!(v, [9, 8, 7, 255, 1, 2, 3, 128]);

    // Too short a body is damage, and the hash path still refuses the same files.
    assert!(decode_any(&file[..file.len() - 20], DECODE_MAX).is_err());
}

/// BC1 keeps one index of a block for "no colour" when its first colour is not
/// above its second: `image` draws it black and opaque (leaves of a tree
/// cut out of the picture), `decode_any` leaves it transparent.
#[cfg(feature = "dds")]
#[test]
fn a_dxt1_texture_with_transparent_texels_is_shown_with_them() {
    let block = [0x00, 0x00, 0x00, 0xf8, 0x57, 0x55, 0x55, 0x55];
    let file = dds(4, 4, four_cc(b"DXT1"), None, &block);
    let hashed = decode(&file, Format::Dds, DECODE_MAX).unwrap().to_rgba8();
    assert_eq!(hashed[3], 255);
    let shown = decode_any(&file, DECODE_MAX).unwrap().to_rgba8();
    assert_eq!(shown[..4], [0, 0, 0, 0]);
    assert_eq!(shown[4..8], [255, 0, 0, 255]);
}

/// A PNG that is not 32-bit inside an ICO is what `image` refuses; the
/// viewer takes the PNG as it is.
#[cfg(feature = "ico")]
#[test]
fn an_ico_with_a_png_that_is_not_32_bit_is_shown() {
    let inner = png(
        2,
        2,
        png::ColorType::Grayscale,
        png::BitDepth::Eight,
        &[0, 80, 160, 255],
    );
    let mut file = vec![0, 0, 1, 0, 1, 0, 2, 2, 0, 0, 1, 0, 32, 0];
    file.extend_from_slice(&(inner.len() as u32).to_le_bytes());
    file.extend_from_slice(&22u32.to_le_bytes());
    file.extend_from_slice(&inner);
    assert_eq!(
        decode(&file, Format::Ico, DECODE_MAX),
        Err(Error::Undecodable)
    );
    let p = decode_any(&file, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height), (2, 2));
    assert_eq!(p.to_rgba8()[4..8], [80, 80, 80, 255]);
}

/// Photoshop writes CMYK with spot or alpha channels after the four inks.
#[test]
fn a_cmyk_tiff_with_extra_channels_is_shown_by_its_inks() {
    let eight = |n: usize| (258, 3, [8, 0].repeat(n));
    let rgb = |file: &[u8]| {
        let p = decode_any(file, DECODE_MAX).unwrap();
        assert_eq!(p.channels, Channels::Rgb);
        let Samples::U8(v) = p.samples else { panic!() };
        v
    };
    let entries = |planar: bool| {
        vec![
            eight(6),
            (262, 3, short(5)),
            (277, 3, short(6)),
            (284, 3, short(if planar { 2 } else { 1 })),
        ]
    };
    let chunky = tiff_strip(
        2,
        1,
        &[0, 0, 0, 0, 7, 9, 100, 0, 0, 50, 7, 9],
        &entries(false),
    );
    assert_eq!(rgb(&chunky), [255, 255, 255, 124, 205, 205]);
    let planar = tiff_strips(
        2,
        1,
        &[&[0, 100], &[0, 0], &[0, 0], &[0, 50], &[7, 7], &[9, 9]],
        &entries(true),
    );
    assert_eq!(rgb(&planar), [255, 255, 255, 124, 205, 205]);
}

/// Planar colour, CMYK and YCbCr, which the hashing decoder refuses or
/// leaves unconverted.
#[test]
fn tiffs_of_planar_cmyk_and_ycbcr_are_shown() {
    let eight = |n: usize| (258, 3, [8, 0].repeat(n));
    let rgb = |file: &[u8]| {
        let p = decode_any(file, DECODE_MAX).unwrap();
        assert_eq!(p.channels, Channels::Rgb);
        let Samples::U8(v) = p.samples else { panic!() };
        v
    };

    // Planar RGB: a strip for each band.
    let planar = tiff_strips(
        2,
        1,
        &[&[10, 20], &[30, 40], &[50, 60]],
        &[
            eight(3),
            (262, 3, short(2)),
            (277, 3, short(3)),
            (284, 3, short(2)),
        ],
    );
    assert_eq!(
        decode(&planar, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    assert_eq!(rgb(&planar), [10, 30, 50, 20, 40, 60]);

    // Planar CMYK: no ink is white.
    let cmyk = tiff_strips(
        2,
        1,
        &[&[0, 100], &[0, 0], &[0, 0], &[0, 50]],
        &[
            eight(4),
            (262, 3, short(5)),
            (277, 3, short(4)),
            (284, 3, short(2)),
        ],
    );
    assert_eq!(rgb(&cmyk), [255, 255, 255, 124, 205, 205]);

    // YCbCr with no subsampling: Y 100, Cb 128, Cr 200 is (200, 49, 100).
    let ycc = tiff_strip(
        1,
        1,
        &[100, 128, 200],
        &[
            eight(3),
            (262, 3, short(6)),
            (277, 3, short(3)),
            (
                530,
                3,
                [1u16, 1].iter().flat_map(|v| v.to_le_bytes()).collect(),
            ),
        ],
    );
    assert_eq!(rgb(&ycc), [200, 49, 100]);
}

/// A `#` line after the maximum value, or among a plain file's samples, is
/// what `image` refuses.
#[cfg(feature = "pnm")]
#[test]
fn pnm_with_comments_in_odd_places_is_shown() {
    let rgba = |file: &[u8]| decode_any(file, DECODE_MAX).unwrap().to_rgba8();
    for (name, file) in [
        (
            "after the maximum value",
            &b"P3\n1 1\n255\n# c\n1 2 3\n"[..],
        ),
        ("among the samples", b"P3\n1 1\n255\n1 2 # c\n3\n"),
    ] {
        assert_eq!(
            decode(file, Format::Pnm, DECODE_MAX),
            Err(Error::Undecodable),
            "{name}"
        );
        assert_eq!(rgba(file), [1, 2, 3, 255], "{name}");
    }
    // A raw file keeps its bytes, '#' or not: the header ends at one blank.
    let raw = b"P6\n1 1\n# c\n255\n#\x02\x03";
    assert_eq!(rgba(raw), [b'#', 2, 3, 255]);
}

/// Bytes from a string of 0 and 1, the last byte padded with 0.
#[cfg(feature = "ccitt")]
fn bits(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |v, b| v << 1 | (b - b'0')) << (8 - c.len()))
        .collect()
}

/// CCITT fax: Group 3 one-dimensional (compression 2) and Group 4 with a fill
/// order of 2, which the hashing decoder does not read.
#[cfg(feature = "ccitt")]
#[test]
fn tiffs_of_ccitt_fax_are_shown() {
    let grey = |file: &[u8]| {
        let Samples::U8(v) = decode_any(file, DECODE_MAX).unwrap().samples else {
            panic!()
        };
        v
    };
    let fax = |compression: u16, photometric: u16, fill_order: u16, data: &[u8]| {
        tiff_strip(
            8,
            1,
            data,
            &[
                (258, 3, short(1)),
                (259, 3, short(compression)),
                (262, 3, short(photometric)),
                (266, 3, short(fill_order)),
                (277, 3, short(1)),
            ],
        )
    };
    // A row of 4 white pixels, then 4 black: runs of 4 are 1011 and 011.
    let half = [255, 255, 255, 255, 0, 0, 0, 0];
    let rle = fax(2, 0, 1, &bits("1011011"));
    assert_eq!(
        decode(&rle, Format::Tiff, DECODE_MAX),
        Err(Error::Undecodable)
    );
    assert_eq!(grey(&rle), half);
    // A white run is a 0 bit: with 1 as black, the picture is the other way.
    assert_eq!(
        grey(&fax(2, 1, 1, &bits("1011011"))),
        [0, 0, 0, 0, 255, 255, 255, 255]
    );
    // Group 4: horizontal mode (001) with the same two runs, then the end of
    // the block; each byte written with its bits reversed for a fill order of 2.
    let g4: Vec<u8> = bits("0011011011000000000001000000000001")
        .iter()
        .map(|b| b.reverse_bits())
        .collect();
    let file = fax(4, 0, 2, &g4);
    // The hashing decoder reads the bytes as they are, and gets a white row.
    let Samples::U8(hashed) = decode(&file, Format::Tiff, DECODE_MAX).unwrap().samples else {
        panic!()
    };
    assert_ne!(hashed, half);
    assert_eq!(grey(&file), half);
}

/// A fill order of 2 has the bits of each byte in reverse order (libtiff
/// reads it so); the hashing decoder ignores it.
#[test]
fn tiffs_of_samples_low_bit_first_are_shown_in_order() {
    let grey = |p: Pixels| {
        let Samples::U8(v) = p.samples else { panic!() };
        v
    };
    // 1 bit: the first of 8 pixels is white, written as bit 0.
    let one = tiff_strip(
        8,
        1,
        &[0x01],
        &[
            (258, 3, short(1)),
            (262, 3, short(1)),
            (266, 3, short(2)),
            (277, 3, short(1)),
        ],
    );
    let hashed = grey(decode(&one, Format::Tiff, DECODE_MAX).unwrap());
    assert_eq!(hashed[7], 255);
    assert_eq!(
        grey(decode_any(&one, DECODE_MAX).unwrap()),
        [255, 0, 0, 0, 0, 0, 0, 0]
    );
    // 2 bits: 0, 1, 2, 3 as 0b00_01_10_11 with the bits of the byte reversed.
    let two = tiff_strip(
        4,
        1,
        &[0b1101_1000],
        &[
            (258, 3, short(2)),
            (262, 3, short(1)),
            (266, 3, short(2)),
            (277, 3, short(1)),
        ],
    );
    assert_eq!(
        grey(decode_any(&two, DECODE_MAX).unwrap()),
        [0, 85, 170, 255]
    );
}

/// A BMP of 2x2 pixels, 24-bit, with a header of `header` bytes, `planes`
/// planes and this height.
fn bmp_of_two_by_two(header: u32, planes: u16, height: i32) -> Vec<u8> {
    let mut f = b"BM".to_vec();
    f.extend_from_slice(&(14 + header + 16).to_le_bytes());
    f.extend_from_slice(&[0; 4]);
    f.extend_from_slice(&(14 + header).to_le_bytes());
    f.extend_from_slice(&header.to_le_bytes());
    f.extend_from_slice(&2u32.to_le_bytes());
    f.extend_from_slice(&height.to_le_bytes());
    f.extend_from_slice(&planes.to_le_bytes());
    f.extend_from_slice(&24u16.to_le_bytes());
    f.resize(14 + header as usize, 0);
    // Rows as they come: pixels B, G, R, padded to 8 bytes.
    f.extend_from_slice(&[1, 2, 3, 4, 5, 6, 0, 0, 7, 8, 9, 10, 11, 12, 0, 0]);
    f
}

/// What `image` refuses of BMP: the header of OS/2 2.x, a plane count that is
/// not 1.
#[test]
fn bmps_with_an_os2_header_or_other_planes_are_shown() {
    let rgb = |file: &[u8]| {
        let rgba = decode_any(file, DECODE_MAX).unwrap().to_rgba8();
        rgba.chunks(4)
            .flat_map(|p| p[..3].to_vec())
            .collect::<Vec<_>>()
    };
    // Bottom row first: (3, 2, 1), (6, 5, 4); then (9, 8, 7), (12, 11, 10).
    let rows = [9, 8, 7, 12, 11, 10, 3, 2, 1, 6, 5, 4];
    assert_eq!(rgb(&bmp_of_two_by_two(40, 1, 2)), rows);
    for (name, file) in [
        ("an OS/2 header", bmp_of_two_by_two(64, 1, 2)),
        ("planes", bmp_of_two_by_two(40, 0, 2)),
    ] {
        assert_eq!(
            decode(&file, Format::Bmp, DECODE_MAX),
            Err(Error::Undecodable),
            "{name}"
        );
        assert_eq!(rgb(&file), rows, "{name}");
    }
}

/// RLE rows stored top-down (a negative height, which the format does not
/// allow with compression) are what `image` refuses.
#[test]
fn a_top_down_rle_bmp_is_shown_the_right_way_up() {
    let rle: &[u8] = &[2, 0, 0, 0, 2, 1, 0, 0, 0, 1];
    let mut f = b"BM".to_vec();
    f.extend_from_slice(&(14 + 40 + 8 + rle.len() as u32).to_le_bytes());
    f.extend_from_slice(&[0; 4]);
    f.extend_from_slice(&(14u32 + 40 + 8).to_le_bytes());
    f.extend_from_slice(&40u32.to_le_bytes());
    f.extend_from_slice(&2u32.to_le_bytes());
    f.extend_from_slice(&(-2i32).to_le_bytes());
    f.extend_from_slice(&[1, 0, 8, 0]);
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&(rle.len() as u32).to_le_bytes());
    f.extend_from_slice(&[0; 8]);
    f.extend_from_slice(&2u32.to_le_bytes());
    f.extend_from_slice(&2u32.to_le_bytes());
    // Black and white.
    f.extend_from_slice(&[0, 0, 0, 0, 255, 255, 255, 0]);
    f.extend_from_slice(rle);
    assert_eq!(decode(&f, Format::Bmp, DECODE_MAX), Err(Error::Undecodable));
    let rgba = decode_any(&f, DECODE_MAX).unwrap().to_rgba8();
    // The first row of the file is the top one: black, then white.
    assert_eq!(rgba[..3], [0, 0, 0]);
    assert_eq!(rgba[8..11], [255, 255, 255]);
}

/// An RLE8 stream that ends with a delta past the last row, which `image` calls
/// corrupt and Windows and Pillow draw (Mozilla's `rle4-delta-320x240.bmp`
/// ends so).
#[test]
fn an_rle_bmp_with_a_delta_past_the_end_is_shown() {
    // One pixel of colour 1, a move of 2 right and 1 up, one of colour 2, and
    // a move up again.
    let rle: &[u8] = &[1, 1, 0, 2, 2, 1, 1, 2, 0, 2, 0, 1, 0, 1];
    let mut f = b"BM".to_vec();
    f.extend_from_slice(&(14 + 40 + 12 + rle.len() as u32).to_le_bytes());
    f.extend_from_slice(&[0; 4]);
    f.extend_from_slice(&(14u32 + 40 + 12).to_le_bytes());
    f.extend_from_slice(&40u32.to_le_bytes());
    f.extend_from_slice(&4u32.to_le_bytes());
    f.extend_from_slice(&2u32.to_le_bytes());
    f.extend_from_slice(&[1, 0, 8, 0]);
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&(rle.len() as u32).to_le_bytes());
    f.extend_from_slice(&[0; 8]);
    f.extend_from_slice(&3u32.to_le_bytes());
    f.extend_from_slice(&3u32.to_le_bytes());
    // Black, white, red (blue first).
    f.extend_from_slice(&[0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 255, 0]);
    f.extend_from_slice(rle);
    assert_eq!(decode(&f, Format::Bmp, DECODE_MAX), Err(Error::Undecodable));
    let p = decode_any(&f, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height), (4, 2));
    let rgba = p.to_rgba8();
    let px = |x: usize, y: usize| rgba[(y * 4 + x) * 4..(y * 4 + x) * 4 + 3].to_vec();
    // The first row of the picture is the last of the file.
    assert_eq!(px(3, 0), [255, 0, 0]);
    assert_eq!(px(0, 0), [0, 0, 0]);
    assert_eq!(px(0, 1), [255, 255, 255]);
}

/// A 2x2 32-bit icon image (a DIB with its AND mask), `mask` bytes of it
/// kept, in a directory of one entry of the given type, entry size and
/// length.
#[cfg(feature = "ico")]
fn icon_of_two_by_two(kind: u8, entry_side: u8, length: Option<u32>, mask: usize) -> Vec<u8> {
    let mut dib = Vec::new();
    for v in [40u32, 2, 4] {
        dib.extend_from_slice(&v.to_le_bytes());
    }
    dib.extend_from_slice(&[1, 0, 32, 0]);
    dib.extend_from_slice(&[0; 24]);
    for p in 0..4u8 {
        dib.extend_from_slice(&[10 * p, 20 * p, 30 * p, 255]);
    }
    dib.extend_from_slice(&[0; 8][..mask]);
    let length = length.unwrap_or(dib.len() as u32);
    let mut file = vec![
        0, 0, kind, 0, 1, 0, entry_side, entry_side, 0, 0, 1, 0, 32, 0,
    ];
    file.extend_from_slice(&length.to_le_bytes());
    file.extend_from_slice(&22u32.to_le_bytes());
    file.extend_from_slice(&dib);
    file
}

/// A 32-bit icon of 2x2 pixels in the file's order (the bottom row first)
/// with these alphas, and the first bytes of the two rows of its AND mask.
#[cfg(feature = "ico")]
fn icon_of_alphas(alphas: [u8; 4], mask: [u8; 2]) -> Vec<u8> {
    let mut dib = Vec::new();
    for v in [40u32, 2, 4] {
        dib.extend_from_slice(&v.to_le_bytes());
    }
    dib.extend_from_slice(&[1, 0, 32, 0]);
    dib.extend_from_slice(&[0; 24]);
    for a in alphas {
        dib.extend_from_slice(&[10, 20, 30, a]);
    }
    dib.extend_from_slice(&[mask[0], 0, 0, 0, mask[1], 0, 0, 0]);
    let mut file = vec![0, 0, 1, 0, 1, 0, 2, 2, 0, 0, 1, 0, 32, 0];
    file.extend_from_slice(&(dib.len() as u32).to_le_bytes());
    file.extend_from_slice(&22u32.to_le_bytes());
    file.extend_from_slice(&dib);
    file
}

/// An icon image whose header gives no bits to a pixel and a huge width and
/// height is not given a mask buffer the size those say.
#[cfg(feature = "ico")]
#[test]
fn an_icon_header_with_huge_sizes_and_no_bits_is_refused_cheaply() {
    let mut dib = Vec::new();
    for v in [40u32, 0x7FFF_FFFF, 0x7FFF_FFFE] {
        dib.extend_from_slice(&v.to_le_bytes());
    }
    dib.extend_from_slice(&[1, 0, 0, 0]);
    dib.resize(40 + 16, 0);
    let mut file = vec![0, 0, 1, 0, 1, 0, 2, 2, 0, 0, 1, 0, 0, 0];
    file.extend_from_slice(&(dib.len() as u32).to_le_bytes());
    file.extend_from_slice(&22u32.to_le_bytes());
    file.extend_from_slice(&dib);
    assert!(decode_any(&file, DECODE_MAX).is_err());
}

/// Windows draws a 32-bit icon by its alpha and leaves its AND mask out, unless
/// there is no alpha; `image` applies the mask over the alpha.
#[cfg(feature = "ico")]
#[test]
fn a_32_bit_icon_is_drawn_by_its_alpha_or_else_by_its_mask() {
    let alphas = |file: &[u8]| {
        let rgba = decode_any(file, DECODE_MAX).unwrap().to_rgba8();
        rgba.chunks(4).map(|p| p[3]).collect::<Vec<_>>()
    };
    // The mask covers the bottom row; its alpha stays, the soft pixel too.
    assert_eq!(
        alphas(&icon_of_alphas([255, 255, 128, 255], [0b1100_0000, 0])),
        [128, 255, 255, 255]
    );
    // A count of colours in the header of a 32-bit image puts nothing before
    // its pixels.
    let mut junk = icon_of_alphas([255, 255, 128, 255], [0b1100_0000, 0]);
    junk[22 + 32..22 + 36].copy_from_slice(&12345u32.to_le_bytes());
    assert_eq!(alphas(&junk), [128, 255, 255, 255]);
    // No alpha at all: the mask hides the second pixel of the bottom row.
    assert_eq!(
        alphas(&icon_of_alphas([0; 4], [0b0100_0000, 0])),
        [255, 255, 255, 0]
    );
}

/// A colour profile after the pixels of a V5 header is not the AND mask.
#[cfg(feature = "ico")]
#[test]
fn the_colour_profile_of_a_v5_icon_image_is_not_read_as_its_mask() {
    let mut dib = Vec::new();
    for v in [124u32, 2, 4] {
        dib.extend_from_slice(&v.to_le_bytes());
    }
    dib.extend_from_slice(&[1, 0, 24, 0]);
    dib.extend_from_slice(&[0; 24]);
    dib.resize(112, 0);
    // The profile starts where the 16 bytes of 2x2 24-bit pixels end, and
    // holds 16 bytes that would hide every pixel as a mask.
    dib.extend_from_slice(&140u32.to_le_bytes());
    dib.extend_from_slice(&16u32.to_le_bytes());
    dib.resize(124, 0);
    dib.extend_from_slice(&[10, 20, 30, 40, 50, 60, 0, 0, 10, 20, 30, 40, 50, 60, 0, 0]);
    dib.extend_from_slice(&[0xFF; 16]);
    let mut file = vec![0, 0, 1, 0, 1, 0, 2, 2, 0, 0, 1, 0, 24, 0];
    file.extend_from_slice(&(dib.len() as u32).to_le_bytes());
    file.extend_from_slice(&22u32.to_le_bytes());
    file.extend_from_slice(&dib);
    let rgba = decode_any(&file, DECODE_MAX).unwrap().to_rgba8();
    assert_eq!(rgba.chunks(4).map(|p| p[3]).collect::<Vec<_>>(), [255; 4]);
}

/// Of the images of one size in an icon file, the one with most colour is
/// shown, in whatever order the file lists them.
#[cfg(feature = "ico")]
#[test]
fn the_icon_image_with_most_colour_is_shown() {
    // A 2x2 DIB of one colour (B, G, R, A), then its AND mask.
    let dib = |bgra: [u8; 4]| {
        let mut d = Vec::new();
        for v in [40u32, 2, 4] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d.extend_from_slice(&[1, 0, 32, 0]);
        d.extend_from_slice(&[0; 24]);
        d.extend(bgra.repeat(4));
        d.extend_from_slice(&[0; 8]);
        d
    };
    let few = (8u8, dib([0, 0, 255, 255]));
    let many = (32u8, dib([255, 0, 0, 255]));
    for order in [[&few, &many], [&many, &few]] {
        let mut file = vec![0, 0, 1, 0, 2, 0];
        let mut at = 6 + 2 * 16;
        for (bits, image) in order {
            file.extend_from_slice(&[2, 2, 0, 0, 1, 0, *bits, 0]);
            file.extend_from_slice(&(image.len() as u32).to_le_bytes());
            file.extend_from_slice(&(at as u32).to_le_bytes());
            at += image.len();
        }
        for (_, image) in order {
            file.extend_from_slice(image);
        }
        assert_eq!(
            decode_any(&file, DECODE_MAX).unwrap().to_rgba8()[..4],
            [0, 0, 255, 255]
        );
    }
}

/// Cursors, and icons with a length too short, a size that is not the
/// image's or a cut AND mask, are what `image` refuses.
#[cfg(feature = "ico")]
#[test]
fn damaged_icons_and_cursors_are_shown() {
    let whole = icon_of_two_by_two(1, 2, None, 8);
    let p = decode_any(&whole, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height), (2, 2));
    // The first pixel of the bottom row of the file is the top row's.
    let first = p.to_rgba8()[..4].to_vec();
    for (name, file) in [
        ("a cursor", icon_of_two_by_two(2, 2, None, 8)),
        ("a length too short", icon_of_two_by_two(1, 2, Some(10), 8)),
        ("another size", icon_of_two_by_two(1, 4, None, 8)),
        ("a cut mask", icon_of_two_by_two(1, 2, None, 4)),
    ] {
        let p = decode_any(&file, DECODE_MAX).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!((p.width, p.height), (2, 2), "{name}");
        assert_eq!(p.to_rgba8()[..4], first[..], "{name}");
    }
}

/// A bare JPEG 2000 codestream of 4x4 pixels, written by opj_compress from
/// Y = 100, Cb = 128, Cr = 200 with the chroma subsampled 2x2: it has no
/// colour box, and is YCbCr.
#[cfg(feature = "jp2")]
#[test]
fn a_codestream_with_subsampled_chroma_is_ycbcr() {
    let file = hex(
        "ff4fff51002f000000000004000000040000000000000000000000040000000400000000000000000003\
         070101070202070202ff52000c00000001000004040001ff5c00044040ff640025000143726561746564\
         206279204f70656e4a5045472076657273696f6e20322e352e33ff90000a0000000000200001ff93c3e7\
         0e1150548842e11f80cfb41001d78943ffd9",
    );
    let p = decode(&file, Format::Jpeg2000, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height), (4, 4));
    assert_eq!(p.to_rgba8()[..4], [200, 49, 100, 255]);
}

/// Four 8-bit components under a greyscale colour box (what GDAL writes for a
/// multi-band raster), made with opj_compress: not CMYK, the first is shown.
#[cfg(feature = "jp2")]
#[test]
fn four_bands_under_a_greyscale_colour_box_show_the_first() {
    let file = hex(
        "0000000c6a5020200d0a870a00000014667479706a703220000000006a7032200000002d6a70326800\
         0000166968647200000004000000040004070700000000000f636f6c720100000000001100\
         0000c06a703263ff4fff510032000000000004000000040000000000000000000000040000000400\
         000000000000000004070101070101070101070101ff52000c00000001000004040001ff5c000440\
         40ff640025000143726561746564206279204f70656e4a5045472076657273696f6e20322e352e33\
         ff90000a0000000000450001ff93cfb44010dbb0c37aa1c444397f4784cb71b77fcfb42414005\
         15c0841816a08c3e70e1150548842e11fcfb42c1150495c084241e53e0c1fffd9",
    );
    let p = decode(&file, Format::Jpeg2000, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height, p.channels), (4, 4, Channels::Luma));
    let Samples::U8(v) = p.samples else { panic!() };
    assert_eq!(v[..4], [5, 15, 25, 35]);
}

/// The 18 bytes that start a Targa file: colour map type, image type, first
/// map entry, map length and entry bits, size, depth and descriptor.
#[allow(clippy::too_many_arguments)]
fn tga(
    map: u8,
    kind: u8,
    first: u16,
    map_len: u16,
    map_bits: u8,
    size: (u16, u16),
    depth: u8,
    descriptor: u8,
) -> Vec<u8> {
    let mut f = vec![0, map, kind];
    f.extend_from_slice(&first.to_le_bytes());
    f.extend_from_slice(&map_len.to_le_bytes());
    f.push(map_bits);
    f.extend_from_slice(&[0; 4]);
    f.extend_from_slice(&size.0.to_le_bytes());
    f.extend_from_slice(&size.1.to_le_bytes());
    f.extend_from_slice(&[depth, descriptor]);
    f
}

/// A Targa file has no magic number, so `Format::detect` does not know it and
/// the hash path never sees it; the viewer takes a file whose pixels fill it.
/// This one starts as a cursor file does (00 00 02 00), which must not take it.
#[test]
fn a_targa_file_is_shown_though_it_has_no_magic_number() {
    let mut f = tga(0, 2, 0, 0, 0, (2, 2), 24, 0);
    // Bottom row first: red, green (blue first in a pixel); then blue, white.
    f.extend_from_slice(&[0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255]);
    assert_eq!(Format::detect(&f), None);
    let p = decode_any(&f, DECODE_MAX).unwrap();
    assert_eq!((p.width, p.height, p.channels), (2, 2, Channels::Rgb));
    let rgba = p.to_rgba8();
    assert_eq!(
        rgba.chunks(4).map(|c| c[..3].to_vec()).collect::<Vec<_>>(),
        [[0, 0, 255], [255, 255, 255], [255, 0, 0], [0, 255, 0]]
    );
    // Not a Targa file: the pixels are short, or something follows them.
    assert_eq!(
        decode_any(&f[..f.len() - 1], DECODE_MAX),
        Err(Error::Unsupported)
    );
    f.push(0);
    assert_eq!(decode_any(&f, DECODE_MAX), Err(Error::Unsupported));
}

/// Run-length packets, a top-left origin, and a version 2 footer, which lets
/// the file be longer than its pixels; some writers leave the footer's NUL off.
#[test]
fn a_run_length_targa_with_a_footer_is_shown() {
    for nul in [true, false] {
        let mut f = tga(0, 11, 0, 0, 0, (4, 1), 8, 0x20);
        // A run of three 7s, then one raw pixel.
        f.extend_from_slice(&[0x82, 7, 0x00, 200]);
        f.extend_from_slice(&[0; 8]);
        f.extend_from_slice(b"TRUEVISION-XFILE.");
        if nul {
            f.push(0);
        }
        let p = decode_any(&f, DECODE_MAX).unwrap();
        assert_eq!((p.width, p.height, p.channels), (4, 1, Channels::Luma));
        assert_eq!(p.samples, Samples::U8(vec![7, 7, 7, 200]));
    }
}

/// Indices into a colour map that does not start at entry 0, with its alpha.
#[test]
fn a_colour_mapped_targa_is_read_through_its_map() {
    // Entries 1 and 2 of the map, 32 bits: dark red, half-clear green.
    let mut f = tga(1, 1, 1, 2, 32, (2, 1), 8, 0x28);
    f.extend_from_slice(&[0, 0, 128, 255, 0, 255, 0, 128]);
    f.extend_from_slice(&[2, 1]);
    let p = decode_any(&f, DECODE_MAX).unwrap();
    assert_eq!(p.channels, Channels::Rgba);
    assert_eq!(p.to_rgba8(), [0, 255, 0, 128, 128, 0, 0, 255]);
}

/// A 32-bit pixel's alpha is shown, unless nothing set it.
#[test]
fn the_alpha_of_a_32_bit_targa_is_shown_unless_it_is_all_zero() {
    let pixels = |alpha: [u8; 2]| {
        let mut f = tga(0, 2, 0, 0, 0, (2, 1), 32, 0x28);
        f.extend_from_slice(&[10, 20, 30, alpha[0], 40, 50, 60, alpha[1]]);
        f
    };
    let p = decode_any(&pixels([255, 100]), DECODE_MAX).unwrap();
    assert_eq!(p.channels, Channels::Rgba);
    assert_eq!(p.to_rgba8(), [30, 20, 10, 255, 60, 50, 40, 100]);
    let p = decode_any(&pixels([0, 0]), DECODE_MAX).unwrap();
    assert_eq!(p.channels, Channels::Rgb);
    assert_eq!(p.to_rgba8(), [30, 20, 10, 255, 60, 50, 40, 255]);
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
