//! Outside `--clamav-compat`, every image format exav decodes is graphics
//! (`Target:5`) and hashed for `fuzzy_img#`; under it, only clamscan's five
//! (PNG, GIF, JPEG, TIFF, BMP) are. The hash is one of pixels, so a signature
//! `sigtool --fuzzy-img` made from a PNG finds the same picture stored as
//! JPEG 2000 or JBIG2, two formats sigtool does not read.
//!
//! The files are exav-render's fixtures (tests/fixtures/images/make.py there):
//! `rgb.jp2` and `rgb.j2k` are `rgb.png` encoded losslessly by opj_compress,
//! `generic.jb2` is `bilevel.png` encoded by jbig2enc, `generic-random.jb2`
//! the same segments reordered. The hashes are what `sigtool --fuzzy-img`
//! (ClamAV 1.4.3) prints for the two PNGs.

use exav_core::{analyze, loader, ScanOptions, Scanner, Verdict};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../exav-render/tests/fixtures/images/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn scanner(line: &str) -> Scanner {
    let mut b = loader::Builder::new();
    b.add_named_bytes("t.ldb", format!("{line}\n").as_bytes(), true);
    b.build().expect("a one-signature database")
}

fn found(db: &Scanner, data: &[u8], opts: &ScanOptions) -> Option<String> {
    match analyze(db, data, opts).verdict {
        Verdict::Infected { signature, .. } => Some(signature),
        _ => None,
    }
}

fn modes() -> [(&'static str, ScanOptions); 2] {
    [
        ("default", ScanOptions::default()),
        ("clamav-compat", ScanOptions::clamav_compat()),
    ]
}

#[test]
fn a_signature_made_from_a_png_finds_the_same_picture_in_jpeg_2000_and_jbig2() {
    for (png, other, sigtool) in [
        ("rgb.png", "rgb.jp2", "f0a50fd80dda4b1e"),
        ("rgb.png", "rgb.j2k", "f0a50fd80dda4b1e"),
        ("bilevel.png", "generic.jb2", "d656ab50a9e9c82d"),
        ("bilevel.png", "generic-random.jb2", "d656ab50a9e9c82d"),
    ] {
        let db = scanner(&format!(
            "Test.Fuzzy;Engine:150-255,Target:0;0;fuzzy_img#{sigtool}"
        ));
        let (png_data, other_data) = (fixture(png), fixture(other));
        for (mode, opts) in modes() {
            // The control: exav hashes the PNG as sigtool does.
            assert_eq!(
                found(&db, &png_data, &opts).as_deref(),
                Some("Test.Fuzzy"),
                "{png} {mode}"
            );
            let want = (mode == "default").then_some("Test.Fuzzy");
            assert_eq!(
                found(&db, &other_data, &opts).as_deref(),
                want,
                "{other} {mode}"
            );
        }
    }
}

#[test]
fn jpeg_2000_and_jbig2_are_graphics_outside_clamav_compat() {
    for (file, magic) in [
        ("rgb.jp2", "0000000c6a502020"),
        ("rgb.j2k", "ff4fff51"),
        ("generic.jb2", "974a42320d0a1a0a"),
    ] {
        let data = fixture(file);
        let graphics = scanner(&format!("Test.Graphics;Engine:51-255,Target:5;0;{magic}"));
        let any = scanner(&format!("Test.Any;Engine:51-255,Target:0;0;{magic}"));
        for (mode, opts) in modes() {
            let want = (mode == "default").then_some("Test.Graphics");
            assert_eq!(
                found(&graphics, &data, &opts).as_deref(),
                want,
                "{file} {mode}"
            );
            // The control: the same bytes, for any file, match in both.
            assert_eq!(
                found(&any, &data, &opts).as_deref(),
                Some("Test.Any"),
                "{file} {mode}"
            );
        }
    }
}
