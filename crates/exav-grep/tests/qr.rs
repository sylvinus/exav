//! `--qr`: the payloads of the QR codes in an image are searched, under
//! `image.png!qr`, in a file and inside an archive; and the `exav-qr` command,
//! which prints them. The fixture is exav's own, a code for
//! `https://www.paypal.com@evil.example/login`.

#![cfg(feature = "qr")]

use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_exav-grep");
const QR: &str = env!("CARGO_BIN_EXE_exav-qr");
const PNG: &[u8] = include_bytes!("../../exav/tests/fixtures/qr/login.png");

fn scratch(tag: &str, name: &str, bytes: &[u8]) -> PathBuf {
    let d = std::env::temp_dir().join(format!("exav-grep-qr-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

fn run(args: &[&str], file: &PathBuf) -> Output {
    Command::new(BIN).args(args).arg(file).output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn a_codes_payload_is_searched_with_qr_only() {
    let file = scratch("file", "scan.png", PNG);
    let o = run(&["--qr", "evil.example"], &file);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let out = stdout(&o);
    assert!(out.contains("scan.png!qr:"), "{out}");
    assert!(
        out.contains("https://www.paypal.com@evil.example/login"),
        "{out}"
    );
    let o = run(&["evil.example"], &file);
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    // Past the pixel limit: said, not a quiet "no match".
    let o = run(&["--qr", "--max-qr-pixels", "100", "evil.example"], &file);
    assert_ne!(o.status.code(), Some(0), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("pixel"),
        "{o:?}"
    );
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

/// A greyscale image (PGM) of codes for `payloads` side by side, four pixels
/// to a module, each with its quiet zone.
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

#[test]
fn no_limit_is_off_or_zero_in_any_case() {
    let file = scratch("nolimit", "scan.png", PNG);
    for (flag, off) in [
        ("--max-qr-pixels", "0"),
        ("--max-qr-pixels", "OFF"),
        ("--max-qr-millis", "0"),
        ("--max-qr-millis", "off"),
        ("--max-qr-codes", "0"),
        ("--max-qr-codes", "off"),
    ] {
        let o = run(&["--qr", flag, off, "evil.example"], &file);
        assert_eq!(o.status.code(), Some(0), "{flag} {off}: {o:?}");
    }
    let o = run(&["--qr", "--max-qr-codes", "many", "evil.example"], &file);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

#[test]
fn the_codes_read_in_an_image_are_a_setting() {
    let file = scratch(
        "codes",
        "sheet.pgm",
        &pgm(&["https://a.example/", "https://b.example/"]),
    );
    let o = run(&["--qr", "example"], &file);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(stdout(&o).contains("https://a.example/") && stdout(&o).contains("https://b.example/"));
    // Past the limit: said, not a quiet "no match".
    let o = run(&["--qr", "--max-qr-codes", "1", "no such payload"], &file);
    assert_ne!(o.status.code(), Some(0), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("more than 1"),
        "{o:?}"
    );
    for all in ["off", "0"] {
        let o = run(&["--qr", "--max-qr-codes", all, "example"], &file);
        assert_eq!(o.status.code(), Some(0), "{all}: {o:?}");
    }
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

/// Each limit of a QR search has a flag and a variable. The sheet of two
/// codes has 6 finder patterns and 2 candidate grids. A time limit cannot be
/// provoked on an image this small: its variable is seen through a value that
/// is refused.
#[test]
fn each_limit_of_a_qr_search_has_a_flag_and_a_variable() {
    let file = scratch(
        "limits",
        "sheet.pgm",
        &pgm(&["https://a.example/", "https://b.example/"]),
    );
    let env_run = |args: &[&str], var: &str, value: &str| {
        Command::new(BIN)
            .args(args)
            .arg(&file)
            .env(var, value)
            .output()
            .unwrap()
    };
    // (flag, variable, a value that cuts the search, a value that does not,
    // what the cut says)
    for (flag, var, cut) in [
        (
            "--max-qr-pixels",
            "EXAV_MAX_QR_PIXELS",
            Some(("1", "1000000", "over the 1-pixel limit")),
        ),
        ("--max-qr-millis", "EXAV_MAX_QR_MILLIS", None),
        (
            "--max-qr-codes",
            "EXAV_MAX_QR_CODES",
            Some(("1", "2", "more than 1 in an image")),
        ),
        (
            "--max-qr-finders",
            "EXAV_MAX_QR_FINDERS",
            Some(("5", "6", "more than 5 finder patterns")),
        ),
        (
            "--max-qr-grids",
            "EXAV_MAX_QR_GRIDS",
            Some(("1", "2", "more than 1 candidate grids")),
        ),
    ] {
        for within in ["off", "0", "OFF"] {
            let o = run(&["--qr", flag, within, "example"], &file);
            assert_eq!(o.status.code(), Some(0), "{flag} {within}: {o:?}");
        }
        let o = run(&["--qr", flag, "many", "example"], &file);
        assert_eq!(o.status.code(), Some(2), "{flag}: {o:?}");
        // A value of the variable is read as the flag's, and the flag wins.
        let o = env_run(&["--qr", "example"], var, "many");
        assert_eq!(o.status.code(), Some(2), "{var}: {o:?}");
        assert!(String::from_utf8_lossy(&o.stderr).contains(flag), "{o:?}");
        let o = env_run(&["--qr", flag, "off", "example"], var, "many");
        assert_eq!(o.status.code(), Some(0), "{var} and {flag}: {o:?}");
        let Some((short, enough, said)) = cut else {
            continue;
        };
        // Past the limit: said, not a quiet "no match".
        let o = run(&["--qr", flag, short, "no such payload"], &file);
        assert_ne!(o.status.code(), Some(0), "{flag}: {o:?}");
        assert!(String::from_utf8_lossy(&o.stderr).contains(said), "{o:?}");
        let o = run(&["--qr", flag, enough, "example"], &file);
        assert_eq!(o.status.code(), Some(0), "{flag} {enough}: {o:?}");
        let o = env_run(&["--qr", "no such payload"], var, short);
        assert!(
            String::from_utf8_lossy(&o.stderr).contains(said),
            "{var}: {o:?}"
        );
        let o = env_run(&["--qr", flag, enough, "example"], var, short);
        assert_eq!(o.status.code(), Some(0), "{var} and {flag}: {o:?}");
    }
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

/// A ZIP of one member, with its central directory.
fn zip_member(name: &str, method: u16, crc: u32, packed: &[u8], size: usize) -> Vec<u8> {
    let mut zip = b"PK\x03\x04".to_vec();
    let tail = |zip: &mut Vec<u8>| {
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(size as u32).to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
    };
    for n in [20u16, 0, method, 0, 0] {
        zip.extend_from_slice(&n.to_le_bytes());
    }
    tail(&mut zip);
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(name.as_bytes());
    zip.extend_from_slice(packed);
    let directory = zip.len();
    zip.extend_from_slice(b"PK\x01\x02");
    for n in [20u16, 20, 0, method, 0, 0] {
        zip.extend_from_slice(&n.to_le_bytes());
    }
    tail(&mut zip);
    // No extra field, comment or file attributes, and the header at 0.
    zip.extend_from_slice(&[0; 16]);
    zip.extend_from_slice(name.as_bytes());
    let size_of_directory = zip.len() - directory;
    zip.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    zip.extend_from_slice(&(size_of_directory as u32).to_le_bytes());
    zip.extend_from_slice(&(directory as u32).to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip
}

/// A ZIP of one stored member.
fn zip_of(name: &str, body: &[u8]) -> Vec<u8> {
    zip_member(name, 0, 0, body, body.len())
}

#[test]
fn a_code_in_an_archive_member_is_searched() {
    let zip = zip_of("inner/scan.png", PNG);
    let file = scratch("zip", "a.zip", &zip);
    let o = run(&["--qr", "evil.example/login"], &file);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(
        stdout(&o).contains("a.zip!inner/scan.png!qr:"),
        "{}",
        stdout(&o)
    );
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

/// A PDF whose one image XObject holds the pixels of a code for `payload`,
/// eight bits a pixel and no filter: no file header to tell it is an image.
fn pdf_with_raw_code(payload: &str) -> Vec<u8> {
    let pgm = pgm(&[payload]);
    // The pixels follow the three header lines.
    let pixels = pgm
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'\n')
        .nth(2)
        .unwrap()
        .0
        + 1;
    let samples = &pgm[pixels..];
    let side = samples.len().isqrt();
    let mut pdf = format!(
        "%PDF-1.4\n1 0 obj\n<< /Type /XObject /Subtype /Image /Width {side} /Height {side} \
         /BitsPerComponent 8 /ColorSpace /DeviceGray /Length {} >>\nstream\n",
        samples.len()
    )
    .into_bytes();
    pdf.extend_from_slice(samples);
    pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
    pdf
}

#[test]
fn a_code_in_a_raw_image_of_a_pdf_is_searched() {
    let pdf = pdf_with_raw_code("https://www.paypal.com@evil.example/login");
    let file = scratch("pdf", "scan.pdf", &pdf);
    let o = run(&["--qr", "evil.example/login"], &file);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(
        stdout(&o).contains("scan.pdf!pdf-obj-1-0!qr:"),
        "{}",
        stdout(&o)
    );
    let o = run(&["evil.example/login"], &file);
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

/// An image that is recognised and not read (it does not decode, or it is a
/// PDF image in a color space that is not read) is reported unreadable under
/// `--qr`, as an image that could not be read is, and is quiet without it.
#[test]
fn an_image_that_is_not_read_is_reported_under_qr() {
    let lab = b"%PDF-1.4\n1 0 obj\n<< /Type /XObject /Subtype /Image /Width 2 /Height 2 \
        /BitsPerComponent 8 /ColorSpace [/Lab << /WhitePoint [0.95 1 1.09] >>] \
        /Length 12 >>\nstream\nabcdefghijkl\nendstream\nendobj\n\
        trailer\n<< /Root 1 0 R >>\n%%EOF\n";
    for (name, bytes, why) in [
        ("cut.png", &PNG[..60], "does not decode"),
        ("lab.pdf", &lab[..], "not read"),
    ] {
        let file = scratch("unread", name, bytes);
        let o = run(&["--qr", "evil.example"], &file);
        assert_eq!(o.status.code(), Some(3), "{name}: {o:?}");
        let err = String::from_utf8_lossy(&o.stderr).into_owned();
        assert!(err.contains(name) && err.contains(why), "{name}: {err}");
        let o = run(&["evil.example"], &file);
        assert_eq!(o.status.code(), Some(1), "{name}: {o:?}");
        assert!(o.stderr.is_empty(), "{name}: {o:?}");
        std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
    }
}

const PAYLOAD: &str = "https://www.paypal.com@evil.example/login";

fn exav_qr(args: &[&str], path: &PathBuf) -> Output {
    Command::new(QR).args(args).arg(path).output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A greyscale image with no code in it.
fn blank_pgm() -> Vec<u8> {
    let mut v = b"P5\n64 64\n255\n".to_vec();
    v.extend(std::iter::repeat_n(255u8, 64 * 64));
    v
}

#[test]
fn exav_qr_prints_the_code_of_an_image_in_an_archive_with_its_location() {
    let file = scratch("qr-zip", "a.zip", &zip_of("inner/scan.png", PNG));
    let o = exav_qr(&[], &file);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let want = format!("{}!inner/scan.png:1:{PAYLOAD}\n", file.display());
    assert_eq!(stdout(&o), want);
    assert!(o.stderr.is_empty(), "{o:?}");
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

#[test]
fn exav_qr_prints_the_code_of_a_raw_image_of_a_pdf() {
    let file = scratch("qr-pdf", "scan.pdf", &pdf_with_raw_code(PAYLOAD));
    let o = exav_qr(&[], &file);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let want = format!("{}!pdf-obj-1-0:1:{PAYLOAD}\n", file.display());
    assert_eq!(stdout(&o), want);
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

#[test]
fn exav_qr_reads_a_directory_only_with_r() {
    let dir = std::env::temp_dir().join(format!("exav-grep-qr-{}-tree", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("a.png"), PNG).unwrap();
    std::fs::write(dir.join("sub/b.pgm"), pgm(&["https://b.example/"])).unwrap();
    // Neither a text nor a container without members has anything to print.
    std::fs::write(dir.join("notes.txt"), b"nothing to see").unwrap();
    std::fs::write(
        dir.join("empty.zip"),
        b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    )
    .unwrap();
    let o = exav_qr(&[], &dir);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(stderr(&o).contains("is a directory (use -r)"), "{o:?}");
    assert!(o.stdout.is_empty(), "{o:?}");
    let o = exav_qr(&["-r"], &dir);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let mut lines: Vec<String> = stdout(&o).lines().map(str::to_string).collect();
    lines.sort();
    let d = dir.display();
    assert_eq!(
        lines,
        [
            format!("{d}/a.png:1:{PAYLOAD}"),
            format!("{d}/sub/b.pgm:1:https://b.example/")
        ]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn exav_qr_exits_1_when_no_code_was_found_and_nothing_was_left_unread() {
    let file = scratch("qr-none", "blank.pgm", &blank_pgm());
    let o = exav_qr(&[], &file);
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert!(o.stdout.is_empty() && o.stderr.is_empty(), "{o:?}");
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

#[test]
fn exav_qr_exits_2_for_a_path_it_cannot_open() {
    let missing = PathBuf::from("/nonexistent/exav-qr/scan.png");
    let o = exav_qr(&[], &missing);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(stderr(&o).contains("scan.png"), "{o:?}");
}

#[test]
fn exav_qr_says_an_image_that_does_not_decode_and_exits_3() {
    let file = scratch("qr-broken", "cut.png", &PNG[..60]);
    let o = exav_qr(&[], &file);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(o.stdout.is_empty(), "{o:?}");
    let err = stderr(&o);
    assert!(
        err.contains("exav-qr:") && err.contains("cut.png") && err.contains("does not decode"),
        "{err}"
    );
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

#[test]
fn exav_qr_says_a_pdf_image_it_does_not_read_and_exits_3() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /XObject /Subtype /Image /Width 2 /Height 2 \
        /BitsPerComponent 8 /ColorSpace [/Lab << /WhitePoint [0.95 1 1.09] >>] \
        /Length 12 >>\nstream\nabcdefghijkl\nendstream\nendobj\n\
        trailer\n<< /Root 1 0 R >>\n%%EOF\n";
    let file = scratch("qr-lab", "scan.pdf", pdf);
    let o = exav_qr(&[], &file);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(o.stdout.is_empty(), "{o:?}");
    let err = stderr(&o);
    assert!(
        err.contains("exav-qr:") && err.contains("scan.pdf") && err.contains("not read"),
        "{err}"
    );
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

#[test]
fn exav_qr_limits_are_flags_with_variables_and_a_limit_reached_is_said() {
    let file = scratch("qr-limit", "scan.png", PNG);
    let env_run = |args: &[&str], value: &str| {
        Command::new(QR)
            .args(args)
            .arg(&file)
            .env("EXAV_MAX_QR_PIXELS", value)
            .output()
            .unwrap()
    };
    let o = exav_qr(&["--max-qr-pixels", "100"], &file);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(stderr(&o).contains("100-pixel"), "{o:?}");
    let o = env_run(&[], "100");
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(stderr(&o).contains("100-pixel"), "{o:?}");
    // The flag wins over the variable, and `off` is no limit.
    let o = env_run(&["--max-qr-pixels", "off"], "100");
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let o = exav_qr(&["--max-qr-pixels", "many"], &file);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

/// A PGM of `side` by `side` white pixels as a deflate stream a few kilobytes
/// long (one block with fixed Huffman codes: the header as literals, a white
/// pixel, then matches of 258 bytes at distance 1), the size of the file and
/// its CRC-32.
fn deflated_white_pgm(side: usize) -> (Vec<u8>, usize, u32) {
    struct Bits {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }
    impl Bits {
        fn put(&mut self, value: u32, len: u32) {
            self.acc |= u64::from(value) << self.n;
            self.n += len;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }
        /// A Huffman code, which is packed from its first bit.
        fn code(&mut self, code: u32, len: u32) {
            self.put(code.reverse_bits() >> (32 - len), len);
        }
    }
    let head = format!("P5\n{side} {side}\n255\n").into_bytes();
    let mut bits = Bits {
        out: Vec::new(),
        acc: 0,
        n: 0,
    };
    bits.put(1, 1); // the last block
    bits.put(1, 2); // with fixed codes
    for &b in &head {
        bits.code(0x30 + u32::from(b), 8); // a literal below 144
    }
    let white = |bits: &mut Bits| bits.code(0x190 + (255 - 144), 9);
    white(&mut bits);
    let mut left = side * side - 1;
    while left >= 258 {
        bits.code(0xc5, 8); // length 258
        bits.code(0, 5); // distance 1
        left -= 258;
    }
    for _ in 0..left {
        white(&mut bits);
    }
    bits.code(0, 7); // end of block
    bits.put(0, 7); // pad to a byte
    let mut crc = u32::MAX;
    for byte in head
        .iter()
        .copied()
        .chain(std::iter::repeat_n(255, side * side))
    {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    (bits.out, head.len() + side * side, !crc)
}

#[test]
fn exav_qr_says_an_image_too_long_to_hold_and_prints_nothing_of_it() {
    // A member decoded as it is read is held whole up to 4 MiB, whatever the
    // limit: this one is longer.
    let (packed, size, crc) = deflated_white_pgm(2200);
    let zip = zip_member("white.pgm", 8, crc, &packed, size);
    let file = scratch("qr-long", "a.zip", &zip);
    let o = exav_qr(&["--max-object-bytes", "1M"], &file);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(o.stdout.is_empty(), "{o:?}");
    let err = stderr(&o);
    assert!(
        err.contains("white.pgm") && err.contains("over the 1048576-byte limit"),
        "{err}"
    );
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

#[test]
fn exav_qr_shows_the_control_characters_of_a_payload_as_escapes() {
    let file = scratch("qr-escape", "sheet.pgm", &pgm(&["a\nb\u{1b}[2Jc\u{202e}d"]));
    let o = exav_qr(&[], &file);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let want = format!("{}:1:a\\nb\\u{{1b}}[2Jc\\u{{202e}}d\n", file.display());
    assert_eq!(stdout(&o), want);
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}

/// A backslash is written doubled, so that `\n` in the output is always an
/// escape and a payload of the two characters `\` and `n` is told from a newline.
#[test]
fn exav_qr_doubles_the_backslash_of_a_payload() {
    let file = scratch("qr-backslash", "sheet.pgm", &pgm(&["C:\\new\\table\nx"]));
    let o = exav_qr(&[], &file);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let want = format!("{}:1:C:\\\\new\\\\table\\nx\n", file.display());
    assert_eq!(stdout(&o), want);
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}
