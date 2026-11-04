//! `--qr` through the command line: the payload of a QR code in an
//! image is matched and its link judged by `--detect phishing` (feature `qr`),
//! and a build without the feature refuses the flag rather than scan as if.
//! `fixtures/qr/login.png` is a code for
//! `https://www.paypal.com@evil.example/login`, drawn by the `qrcode` crate.

use std::path::Path;
use std::process::Command;

#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

const PNG: &[u8] = include_bytes!("fixtures/qr/login.png");

fn sigs(words: &str) -> TempDir {
    let d = TempDir::new().unwrap();
    let hex: String = words.bytes().map(|b| format!("{b:02x}")).collect();
    std::fs::write(d.path().join("t.ndb"), format!("Test.Qr:7:*:{hex}\n")).unwrap();
    d
}

fn scan(db: &Path, file: &Path, extra: &[&str]) -> (i32, String) {
    scan_env(db, file, extra, &[])
}

fn scan_env(db: &Path, file: &Path, extra: &[&str], vars: &[(&str, &str)]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_exav"))
        .arg("-d")
        .arg(db)
        .args(extra)
        .arg(file)
        .env_remove("EXAV_QR")
        .envs(vars.iter().copied())
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn image() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("scan-me.png");
    std::fs::write(&p, PNG).unwrap();
    (dir, p)
}

#[cfg(feature = "qr")]
#[test]
fn a_codes_payload_is_found_and_its_link_judged_only_with_the_flag() {
    let (_dir, file) = image();
    let db = sigs("evil.example/login");
    let (code, out) = scan(db.path(), &file, &["--qr"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("Test.Qr FOUND"), "{out}");
    let (code, out) = scan(db.path(), &file, &[]);
    assert_eq!(code, 0, "{out}");
    let none = sigs("never present");
    let (code, out) = scan(none.path(), &file, &["--qr", "--detect", "phishing"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("Heuristics.Phishing.Email.Cloaked.Username FOUND"),
        "{out}"
    );
    // An image past the pixel limit is not reported clean.
    let (code, out) = scan(none.path(), &file, &["--qr", "--max-qr-pixels", "100"]);
    assert_eq!(code, 3, "{out}");
    let (code, out) = scan(none.path(), &file, &["--qr", "--max-qr-pixels", "off"]);
    assert_eq!(code, 0, "{out}");
}

/// A greyscale image (PGM) of codes for `payloads` side by side, four pixels
/// to a module, each with its quiet zone.
#[cfg(feature = "qr")]
fn pgm(payloads: &[&str]) -> Vec<u8> {
    let codes: Vec<_> = payloads
        .iter()
        .map(|p| qrcode::QrCode::new(p.as_bytes()).unwrap())
        .collect();
    let colors: Vec<_> = codes.iter().map(|c| c.to_colors()).collect();
    let sides: Vec<usize> = codes.iter().map(|c| (c.width() + 8) * 4).collect();
    let (width, height) = (sides.iter().sum::<usize>(), *sides.iter().max().unwrap());
    let mut out = format!("P5\n{width} {height}\n255\n").into_bytes();
    for y in 0..height {
        for ((code, colors), side) in codes.iter().zip(&colors).zip(&sides) {
            let n = code.width();
            for x in 0..*side {
                let (mx, my) = (x / 4, y / 4);
                let dark = (4..n + 4).contains(&mx)
                    && (4..n + 4).contains(&my)
                    && colors[(my - 4) * n + (mx - 4)] == qrcode::Color::Dark;
                out.push(if dark { 0 } else { 255 });
            }
        }
    }
    out
}

#[cfg(feature = "qr")]
#[test]
fn the_codes_read_in_an_image_are_a_setting() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("sheet.pgm");
    std::fs::write(&file, pgm(&["https://a.example/", "https://b.example/"])).unwrap();
    let db = sigs("never present");
    let (code, out) = scan(db.path(), &file, &["--qr"]);
    assert_eq!(code, 0, "{out}");
    let (code, out) = scan(db.path(), &file, &["--qr", "--max-qr-codes", "1"]);
    assert_eq!(code, 3, "{out}");
    for all in ["off", "0"] {
        let (code, out) = scan(db.path(), &file, &["--qr", "--max-qr-codes", all]);
        assert_eq!(code, 0, "{all}: {out}");
    }
    let (code, out) = scan(db.path(), &file, &["--qr", "--max-qr-codes", "many"]);
    assert_eq!(code, 2, "{out}");
}

/// The sheet of two codes has 6 finder patterns and 2 candidate grids.
#[cfg(feature = "qr")]
#[test]
fn the_finder_patterns_and_candidate_grids_of_an_image_are_settings() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("sheet.pgm");
    std::fs::write(&file, pgm(&["https://a.example/", "https://b.example/"])).unwrap();
    let db = sigs("never present");
    for (flag, var, short, enough) in [
        ("--max-qr-finders", "EXAV_MAX_QR_FINDERS", "5", "6"),
        ("--max-qr-grids", "EXAV_MAX_QR_GRIDS", "1", "2"),
    ] {
        let (code, out) = scan(db.path(), &file, &["--qr", flag, short]);
        assert_eq!(code, 3, "{flag}: {out}");
        let (code, out) = scan(db.path(), &file, &["--qr", flag, enough]);
        assert_eq!(code, 0, "{flag}: {out}");
        for all in ["off", "0"] {
            let (code, out) = scan(db.path(), &file, &["--qr", flag, all]);
            assert_eq!(code, 0, "{flag} {all}: {out}");
        }
        let (code, out) = scan(db.path(), &file, &["--qr", flag, "many"]);
        assert_eq!(code, 2, "{flag}: {out}");
        // The variable sets it, and the flag wins over it.
        let (code, out) = scan_env(db.path(), &file, &["--qr"], &[(var, short)]);
        assert_eq!(code, 3, "{var}: {out}");
        let (code, out) = scan_env(db.path(), &file, &["--qr", flag, enough], &[(var, short)]);
        assert_eq!(code, 0, "{var} and {flag}: {out}");
    }
}

#[cfg(not(feature = "qr"))]
#[test]
fn a_build_without_qr_refuses_the_flag() {
    let (_dir, file) = image();
    let db = sigs("never present");
    let (code, out) = scan(db.path(), &file, &["--qr"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("--features qr"), "{out}");
}
