//! Four bytes that a search of a whole object finds (the Script Encoder
//! marker) do not decide what the object is: an installer, an RTF document
//! with an object, a ZIP behind a picture, a PDF behind a prefix and a
//! message are still opened, and a signature on what is inside is found.

use std::io::Write;

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};

const MARK: &[u8] = b"#@~^";
const PAYLOAD: &[u8] = b"MEMBERPAYLOAD of the detect order suite";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A database of one signature: `PAYLOAD` at offset 0 of any object, so that
/// it is found in a member that is the payload and in nothing that holds it
/// compressed or encoded.
fn scanner() -> Scanner {
    let mut b = loader::Builder::new();
    let line = format!("Exav.Test.Member:0:0:{}\n", hex(PAYLOAD));
    b.add_named_bytes("member.ndb", line.as_bytes(), false);
    b.build().unwrap()
}

fn found(file: &[u8], opts: &ScanOptions) -> Option<String> {
    match analyze(&scanner(), file, opts).verdict {
        Verdict::Infected { signature, .. } => Some(signature),
        _ => None,
    }
}

/// `file` with the marker over its bytes from `at`.
fn over(file: &[u8], at: usize) -> Vec<u8> {
    let mut v = file.to_vec();
    v[at..at + MARK.len()].copy_from_slice(MARK);
    v
}

/// The signature is found in `plain`, and in `marked`, which holds the marker.
fn found_in_both(what: &str, plain: &[u8], marked: &[u8]) {
    let opts = ScanOptions::default();
    assert_eq!(
        found(plain, &opts).as_deref(),
        Some("Exav.Test.Member"),
        "{what}: without the marker"
    );
    assert_eq!(
        found(marked, &opts).as_deref(),
        Some("Exav.Test.Member"),
        "{what}: with the marker"
    );
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn zip_of(member: &[u8]) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    z.start_file("payload.txt", opts).unwrap();
    z.write_all(member).unwrap();
    z.finish().unwrap().into_inner()
}

/// An NSIS installer with one deflated block.
fn nsis() -> Vec<u8> {
    let sig: [u8; 16] = [
        0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's',
        b't',
    ];
    let block = deflate(PAYLOAD);
    let mut blob = b"MZ".to_vec();
    blob.extend_from_slice(&[0u8; 62]);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&sig);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&((0x1c + 4 + block.len() + 4) as u32).to_le_bytes());
    blob.extend_from_slice(&((block.len() as u32) | 0x8000_0000).to_le_bytes());
    blob.extend_from_slice(&block);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob
}

/// The installer is opened by default and under `--clamav-compat`.
#[test]
fn an_nsis_installer_holding_the_marker_is_opened() {
    let exe = nsis();
    let opts = [ScanOptions::default(), ScanOptions::clamav_compat()];
    for (mode, opts) in opts.iter().enumerate() {
        for marked in [over(&exe, 8), [&exe[..], MARK].concat()] {
            for file in [&exe, &marked] {
                let hit = found(file, opts);
                assert_eq!(
                    hit.as_deref().map(|s| s.trim_end_matches(".UNOFFICIAL")),
                    Some("Exav.Test.Member"),
                    "mode {mode}"
                );
            }
        }
    }
}

#[test]
fn an_rtf_document_holding_the_marker_has_its_object_scanned() {
    let rtf = format!(
        "{{\\rtf1\\ansi ABCD {{\\object\\objemb{{\\objdata {}}}}}}}",
        hex(PAYLOAD)
    );
    found_in_both("rtf", rtf.as_bytes(), &over(rtf.as_bytes(), 14));
}

/// A ZIP behind a picture or a script line is opened, as the readers of ZIP do.
#[test]
fn a_zip_behind_other_bytes_holding_the_marker_is_scanned() {
    let zip = zip_of(PAYLOAD);
    let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89";
    for prefix in [
        [&png[..], &[0u8; 100][..]].concat(),
        b"#!/usr/bin/env python3\n".to_vec(),
    ] {
        let file = [&prefix[..], &zip[..]].concat();
        found_in_both("zip", &file, &over(&file, prefix.len() - 8));
    }
}

#[test]
fn a_zip_self_extractor_holding_the_marker_is_scanned() {
    let mut exe = b"MZ".to_vec();
    exe.resize(400, 0x90);
    exe.extend_from_slice(&zip_of(PAYLOAD));
    found_in_both("sfx", &exe, &over(&exe, 200));
}

#[test]
fn a_pdf_behind_a_short_prefix_holding_the_marker_is_scanned() {
    let pdf = format!(
        "junk\n%PDF-1.4\n% a comment line\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
3 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n\
trailer\n<< /Root 1 0 R >>\n%%EOF\n",
        PAYLOAD.len(),
        String::from_utf8_lossy(PAYLOAD)
    );
    found_in_both("pdf", pdf.as_bytes(), &over(pdf.as_bytes(), 5 + 9 + 4));
}

/// Two bytes at 1080 and the three of an LHA method at 2 to 6 are not an ext
/// volume or an LHA archive: a PDF behind a short prefix that holds them is
/// still read, not refused as a volume or an archive that does not open.
#[test]
fn a_pdf_holding_the_bytes_of_ext_or_lha_is_still_a_pdf() {
    let body = format!(
        "%PDF-1.4\n% {}\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
3 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n\
trailer\n<< /Root 1 0 R >>\n%%EOF\n",
        "x".repeat(1200),
        PAYLOAD.len(),
        String::from_utf8_lossy(PAYLOAD)
    );
    let opts = ScanOptions::default();
    for prefix in ["junk\n", "ab-lh5-"] {
        let pdf = format!("{prefix}{body}").into_bytes();
        assert_eq!(
            found(&pdf, &opts).as_deref(),
            Some("Exav.Test.Member"),
            "{prefix:?}"
        );
    }
    let mut ext = format!("junk\n{body}").into_bytes();
    ext[1080..1082].copy_from_slice(&[0x53, 0xEF]);
    assert_eq!(
        found(&ext, &opts).as_deref(),
        Some("Exav.Test.Member"),
        "ext bytes"
    );
    // Under the compat mode as well.
    let compat = ScanOptions::clamav_compat();
    assert_eq!(
        found(&ext, &compat).as_deref(),
        Some("Exav.Test.Member.UNOFFICIAL"),
        "ext bytes, compat"
    );
}

/// The tables and the string pool of an installer database are streams of
/// small numbers, with a header that a stream of LZMA Utils can have. They are
/// not read as one: an ordinary database ends clean, not unscannable.
#[test]
fn the_streams_of_an_installer_database_are_not_read_as_lzma() {
    let mut pool = vec![0u8; 4];
    let mut x = 12345u32;
    for i in 0..100 {
        let (len, uses) = match i {
            0 => (4u16, 1u16),
            1 | 2 => (0, 0),
            _ => {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                ((x >> 24) as u16 % 40 + 1, (x >> 16) as u16 % 7 + 1)
            }
        };
        pool.extend_from_slice(&len.to_le_bytes());
        pool.extend_from_slice(&uses.to_le_bytes());
    }
    let upgrade: [u8; 32] = [
        0x20, 0x00, 0x20, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x00, 0x80, 0x02, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00,
        0x2b, 0x00,
    ];
    let mut cf = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
    // An installer database names a table's stream with U+4840 for its `!`.
    for (name, data) in [
        ("/\u{4840}_StringPool", &pool[..]),
        ("/\u{4840}Upgrade", &upgrade[..]),
    ] {
        cf.create_stream(name).unwrap().write_all(data).unwrap();
    }
    cf.flush().unwrap();
    let msi = cf.into_inner().into_inner();
    for opts in [ScanOptions::default(), ScanOptions::clamav_compat()] {
        let verdict = analyze(&scanner(), &msi, &opts).verdict;
        assert_eq!(verdict, Verdict::Clean, "{verdict:?}");
    }
}

/// A cabinet found by its magic inside a file, whose directory cannot be read
/// (the bytes after the first sectors of a cabinet in a compound file are not
/// the cabinet's), is a magic met by chance: the file is clean, as the scan of
/// its own bytes found, not "limits exceeded".
#[test]
fn a_cabinet_with_an_unreadable_directory_inside_a_file_is_not_a_limit() {
    let mut builder = cab::CabinetBuilder::new();
    builder
        .add_folder(cab::CompressionType::MsZip)
        .add_file("data.bin");
    let mut w = builder.build(std::io::Cursor::new(Vec::new())).unwrap();
    while let Some(mut f) = w.next_file().unwrap() {
        let text: String = (0..2000)
            .map(|i| format!("line {i} of the file\n"))
            .collect();
        f.write_all(text.as_bytes()).unwrap();
    }
    let mut damaged = w.finish().unwrap().into_inner();
    let name_at = u32::from_le_bytes(damaged[16..20].try_into().unwrap()) as usize + 16;
    damaged[name_at..name_at + 300].fill(b'x');
    let mut carrier = b"a carrier with a cabinet stapled behind it\n".repeat(20);
    carrier.extend_from_slice(&damaged);
    for opts in [ScanOptions::default(), ScanOptions::clamav_compat()] {
        let verdict = analyze(&scanner(), &carrier, &opts).verdict;
        assert_eq!(verdict, Verdict::Clean, "{verdict:?}");
    }
}

/// The data of an executable holds `MSCF` and four zeros, as the names of the
/// C++ types of a cabinet tool do: that is no cabinet stapled to it.
#[test]
fn a_cabinet_magic_in_the_data_of_an_executable_is_not_a_payload() {
    let mut exe = include_bytes!("../testdata/tiny_pe32.exe").to_vec();
    exe.extend_from_slice(
        b"MSCF\0\0\0\0\xc4\x1f\x40\0\0\0\0\0\x2e\x3f\x41\x56CNode@@\0\x65\x40\x40\0",
    );
    exe.extend_from_slice(&[0x5a; 200]);
    for opts in [ScanOptions::default(), ScanOptions::clamav_compat()] {
        let verdict = analyze(&scanner(), &exe, &opts).verdict;
        assert_eq!(verdict, Verdict::Clean, "{verdict:?}");
    }
}

/// A compound file holds an executable and a cabinet, whose sectors another
/// stream's are mixed with. The executable is also scanned from its header to
/// the end of the file, as clamscan carves it, and the cabinet that follows
/// it there is not the cabinet of the file: its bytes are in the order of the
/// sectors, not of the stream. That is no payload of an executable, and the
/// cabinet in its own stream is read.
#[test]
fn a_cabinet_in_the_sectors_of_a_compound_file_is_not_an_executables_payload() {
    let mut builder = cab::CabinetBuilder::new();
    let folder = builder.add_folder(cab::CompressionType::MsZip);
    for i in 0..150 {
        folder.add_file(format!("directory/with/a/long/name/for/file-{i:04}.dat"));
    }
    let mut w = builder.build(std::io::Cursor::new(Vec::new())).unwrap();
    let mut x = 0x9E37_79B9u32;
    while let Some(mut f) = w.next_file().unwrap() {
        let noise: Vec<u8> = (0..300)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        f.write_all(&noise).unwrap();
    }
    let cabinet = w.finish().unwrap().into_inner();
    assert!(cabinet.len() > 4096);
    let pe = include_bytes!("../testdata/tiny_pe32.exe");
    let mut cf = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).unwrap();
    cf.create_stream("/Binary.Program")
        .unwrap()
        .write_all(pe)
        .unwrap();
    // Two streams written in turn, a sector at a time.
    let mut a = cf.create_stream("/MergeModule.CABinet").unwrap();
    let mut b = cf.create_stream("/Filler").unwrap();
    for (x, y) in cabinet
        .chunks(512)
        .zip(b"f".repeat(cabinet.len()).chunks(512))
    {
        a.write_all(x).unwrap();
        a.flush().unwrap();
        b.write_all(y).unwrap();
        b.flush().unwrap();
    }
    drop((a, b));
    cf.flush().unwrap();
    let file = cf.into_inner().into_inner();
    // A stream under 4 KiB is not in sectors of its own: the file table of
    // the cabinet runs past that.
    let table_end = u32::from_le_bytes(cabinet[36..40].try_into().unwrap()) as usize;
    assert!(table_end > 4096 + 1024, "{table_end}");
    assert!(
        file.windows(table_end).all(|w| w != &cabinet[..table_end]),
        "the cabinet is whole in the file: the sectors were not mixed"
    );
    for opts in [ScanOptions::default(), ScanOptions::clamav_compat()] {
        let verdict = analyze(&scanner(), &file, &opts).verdict;
        assert_eq!(verdict, Verdict::Clean, "{verdict:?}");
    }
}

/// A message that holds the marker in its text is still a message: its
/// attachment is decoded and scanned.
#[test]
fn a_message_holding_the_marker_has_its_attachment_scanned() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(PAYLOAD);
    for start in ["From: a@example.com", "Received: from x by y"] {
        let mail = format!(
            "{start}\r\nTo: b@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BB\"\r\n\r\n--BB\r\nContent-Type: text/plain\r\n\r\n\
a line of text\r\n--BB\r\nContent-Type: application/octet-stream\r\n\
Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"a.bin\"\r\n\r\n\
{b64}\r\n--BB--\r\n"
        );
        let at = mail.find("a line of text").unwrap();
        found_in_both("mail", mail.as_bytes(), &over(mail.as_bytes(), at + 2));
    }
}
