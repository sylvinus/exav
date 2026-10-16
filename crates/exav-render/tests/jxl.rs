//! JPEG XL, through zenjxl-decoder.
//!
//! The oracles are not the decoder's own output. The lossless files were made
//! by libjxl's `cjxl` from pixels this file computes (`source`), so a correct
//! decode gives those pixels back exactly. The lossy ones carry the pixels
//! libjxl's own `djxl` decodes them to, which a second implementation must match
//! to within the rounding of its arithmetic.
//!
//! Regenerate with `cjxl` and `djxl` 0.11 from the PPM, PAM and PGM that
//! `source` describes: `cjxl x.ppm rgb-lossless.jxl -d 0 -e 7`, `-d 1 -e 5`
//! for `rgb-lossy`, `-d 2 -e 3` for `rgb-lossy-e3`, `--container=1` for
//! `rgb-container`, `djxl x.jxl x.ref.ppm` for the references.

use std::cell::Cell;
use std::sync::Once;

use exav_render::image::{
    decode, decode_any, Channels, Error, Format, Pixels, Samples, DECODE_MAX,
};

const W: usize = 64;
const H: usize = 48;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/images/jxl/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The pixel the files were made from.
fn source(x: usize, y: usize) -> [u8; 3] {
    let (r, g, b) = ((x * 4) % 256, (y * 5) % 256, ((x * y) / 3) % 256);
    let [r, g, b] = [r as u8, g as u8, b as u8];
    if (x / 8 + y / 8).is_multiple_of(2) {
        [255 - r, 255 - g, 255 - b]
    } else {
        [r, g, b]
    }
}

fn u8s(p: &Pixels) -> &[u8] {
    match &p.samples {
        Samples::U8(v) => v,
        other => panic!("8-bit samples expected, got {other:?}"),
    }
}

/// The samples of a binary PPM (P6), after its header.
fn ppm(name: &str) -> Vec<u8> {
    let data = fixture(name);
    let mut fields = 0;
    let mut at = 0;
    while fields < 4 {
        while data[at].is_ascii_whitespace() {
            at += 1;
        }
        while !data[at].is_ascii_whitespace() {
            at += 1;
        }
        fields += 1;
    }
    data[at + 1..].to_vec()
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
fn a_codestream_and_a_container_are_known_by_their_first_bytes() {
    assert_eq!(
        Format::detect(&fixture("rgb-lossless.jxl")),
        Some(Format::Jxl)
    );
    assert_eq!(
        Format::detect(&fixture("rgb-container.jxl")),
        Some(Format::Jxl)
    );
    assert!(Format::ALL.contains(&Format::Jxl));
    assert_eq!(Format::Jxl.name(), "jxl");
    assert_eq!(Format::detect(b"\xFF\xD8\xFF\xE0"), Some(Format::Jpeg));
    assert_eq!(Format::detect(b"\xFF\x0B"), None);
}

#[test]
fn lossless_files_decode_to_the_pixels_they_were_made_from() {
    for file in ["rgb-lossless.jxl", "rgb-container.jxl"] {
        let p = decode_any(&fixture(file), DECODE_MAX).unwrap();
        assert_eq!(
            (p.width as usize, p.height as usize, p.channels),
            (W, H, Channels::Rgba),
            "{file}"
        );
        let samples = u8s(&p);
        for y in 0..H {
            for x in 0..W {
                let at = (y * W + x) * 4;
                let [r, g, b] = source(x, y);
                assert_eq!(samples[at..at + 4], [r, g, b, 255], "{file} at {x},{y}");
            }
        }
    }
}

#[test]
fn an_alpha_channel_comes_through_as_straight_alpha() {
    let p = decode_any(&fixture("rgba-lossless.jxl"), DECODE_MAX).unwrap();
    assert_eq!(
        (p.width as usize, p.height as usize, p.channels),
        (W, H, Channels::Rgba)
    );
    let samples = u8s(&p);
    for y in 0..H {
        for x in 0..W {
            let at = (y * W + x) * 4;
            let alpha = ((x * 255) / (W - 1)) as u8;
            assert_eq!(samples[at + 3], alpha, "alpha at {x},{y}");
            // Under an alpha of 0 an encoder may keep or clear the colour.
            if alpha > 0 {
                assert_eq!(samples[at..at + 3], source(x, y), "colour at {x},{y}");
            }
        }
    }
}

#[test]
fn a_grey_image_is_grey_with_alpha() {
    let p = decode_any(&fixture("grey-lossless.jxl"), DECODE_MAX).unwrap();
    assert_eq!(
        (p.width as usize, p.height as usize, p.channels),
        (W, H, Channels::LumaAlpha)
    );
    let samples = u8s(&p);
    for y in 0..H {
        for x in 0..W {
            let [r, g, b] = source(x, y);
            let grey =
                ((u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114) / 1000) as u8;
            let at = (y * W + x) * 2;
            assert_eq!(samples[at..at + 2], [grey, 255], "at {x},{y}");
        }
    }
    // What a page draws: grey in all three colour channels.
    let rgba = p.to_rgba8();
    assert_eq!(rgba[..4], [u8s(&p)[0], u8s(&p)[0], u8s(&p)[0], 255]);
}

/// The PNGs of the JPEG 2000 and JBIG2 tests, encoded losslessly by `cjxl`
/// (`cjxl x.png x.jxl -d 0 -e 7`): the PNG is the oracle.
#[test]
fn a_lossless_file_gives_back_the_png_it_was_encoded_from() {
    let images = |name: &str| {
        std::fs::read(format!(
            "{}/tests/fixtures/images/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    for (jxl, png) in [("rgb.jxl", "rgb.png"), ("rgba.jxl", "rgba.png")] {
        let got = decode_any(&images(jxl), DECODE_MAX).unwrap();
        let want = decode_any(&images(png), DECODE_MAX).unwrap().to_rgba8();
        assert_eq!(got.channels, Channels::Rgba, "{jxl}");
        let got = u8s(&got);
        assert_eq!(got.len(), want.len(), "{jxl}");
        for (i, (g, w)) in got
            .as_chunks::<4>()
            .0
            .iter()
            .zip(want.as_chunks::<4>().0)
            .enumerate()
        {
            // Under an alpha of 0 the colour is not kept.
            let same = if w[3] == 0 { g[3] == 0 } else { g == w };
            assert!(same, "{jxl}: pixel {i} is {g:?}, the PNG's is {w:?}");
        }
    }
}

/// A lossy file is decoded by two implementations to the same picture, give
/// or take the rounding of their arithmetic: libjxl's `djxl` made the
/// reference.
#[test]
fn lossy_files_decode_as_libjxl_decodes_them() {
    for (file, reference) in [
        ("rgb-lossy.jxl", "rgb-lossy.ref.ppm"),
        ("rgb-lossy-e3.jxl", "rgb-lossy-e3.ref.ppm"),
    ] {
        let p = decode_any(&fixture(file), DECODE_MAX).unwrap();
        let want = ppm(reference);
        let got = u8s(&p);
        assert_eq!(got.len() / 4 * 3, want.len(), "{file}");
        let mut worst = 0u8;
        let mut off = 0usize;
        for (i, px) in got.as_chunks::<4>().0.iter().enumerate() {
            assert_eq!(px[3], 255);
            for c in 0..3 {
                let d = px[c].abs_diff(want[i * 3 + c]);
                worst = worst.max(d);
                off += usize::from(d > 0);
            }
        }
        assert!(
            worst <= 2,
            "{file}: a sample is {worst} levels from libjxl's ({off} differ)"
        );
    }
}

/// The limit is the caller's: a file declaring 121 million pixels is refused
/// from its header, before anything is allocated for them.
#[test]
fn an_image_over_the_budget_is_refused_from_its_header() {
    let data = fixture("big-flat.jxl");
    let start = std::time::Instant::now();
    assert_eq!(
        decode(&data, Format::Jxl, 64 << 20).map(|_| ()),
        Err(Error::TooLarge)
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "{:?}",
        start.elapsed()
    );
    // At the budget of every decoder here, the file is still not decoded to
    // gigabytes of floats.
    let result = decode(&data, Format::Jxl, DECODE_MAX);
    assert!(result.is_err() || result.is_ok_and(|p| u8s(&p).len() <= 4 * 121_000_000));
}

/// 9 million pixels, under every limit the decoder has of its own: only the
/// caller's budget refuses it, from the size its header declares.
#[test]
fn the_callers_budget_is_the_decoders_limit() {
    let data = fixture("mid-grey.jxl");
    // Four bytes a pixel as RGBA: 36 MB.
    assert_eq!(
        decode(&data, Format::Jxl, 16 << 20).map(|_| ()),
        Err(Error::TooLarge)
    );
    let p = decode(&data, Format::Jxl, 256 << 20).unwrap();
    assert_eq!(
        (p.width, p.height, p.channels),
        (3000, 3000, Channels::LumaAlpha)
    );
    for (x, y) in [(0usize, 0usize), (1, 0), (0, 1), (2999, 2999), (1234, 2345)] {
        assert_eq!(
            u8s(&p)[(y * 3000 + x) * 2],
            ((x * 7 + y * 3) % 256) as u8,
            "at {x},{y}"
        );
    }
}

/// A decoder this size on hostile bytes: cut short and damaged at many places,
/// every file ends in a pixel result or an error, with no panic (which
/// `decode` would report as `Undecodable`, so the hook watches for one).
#[test]
fn damaged_files_are_errors_not_panics() {
    watch_panics();
    for file in [
        "rgb-lossless.jxl",
        "rgb-lossy.jxl",
        "rgb-lossy-e3.jxl",
        "rgba-lossless.jxl",
        "grey-lossless.jxl",
        "rgb-container.jxl",
    ] {
        let data = fixture(file);
        for cut in (0..data.len()).step_by(7) {
            let _ = decode_any(&data[..cut], 64 << 20);
            assert!(!panicked(), "{file} cut at {cut}");
        }
        for at in (0..data.len()).step_by(3) {
            for flip in [0x01u8, 0x80, 0xFF] {
                let mut d = data.clone();
                d[at] ^= flip;
                let _ = decode_any(&d, 64 << 20);
                assert!(!panicked(), "{file}: byte {at} xor {flip:#x}");
            }
        }
    }
}
