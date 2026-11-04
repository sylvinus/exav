//! The type `detect` gives an object does not depend on four bytes that a
//! search of the whole object finds: a format told by its structure, or by a
//! longer magic, is typed first, and the searches for a short marker come
//! after every rule that reads a header.

use exav_unpack::{Budget, Entry, Format, Limits, detect, extract, read_fixture};

/// The marker a search of the whole object looks for.
const MARK: &[u8] = b"#@~^";

/// The script GUID and the marker of a compiled AutoIt script, as they are in
/// the resource or the data appended to an executable.
fn autoit_tag(marker: &[u8; 8]) -> Vec<u8> {
    let mut v = vec![
        0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 0x48,
        0x7D,
    ];
    v.extend_from_slice(marker);
    v
}

/// The superblock of a 1 KiB-block ext2 volume of 2048 blocks and 64 inodes
/// in one group, as `mke2fs` writes the fields the check looks at, in a buffer
/// of `len` bytes. `edit` changes the 1024 bytes of the superblock.
fn ext_image(len: usize, edit: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut img = vec![0u8; len];
    let sb = &mut img[1024..2048];
    let put32 = |sb: &mut [u8], at: usize, v: u32| sb[at..at + 4].copy_from_slice(&v.to_le_bytes());
    put32(sb, 0, 64); // inodes
    put32(sb, 4, 2048); // blocks
    put32(sb, 20, 1); // first data block
    put32(sb, 24, 0); // log block size (1 KiB)
    put32(sb, 28, 0); // log cluster size
    put32(sb, 32, 8192); // blocks per group
    put32(sb, 36, 8192);
    put32(sb, 40, 64); // inodes per group
    sb[56..58].copy_from_slice(&[0x53, 0xEF]);
    put32(sb, 76, 1); // revision
    put32(sb, 84, 11); // first inode
    sb[88..90].copy_from_slice(&128u16.to_le_bytes());
    edit(sb);
    img
}

/// An LHA header of level `level` for a file named `name`, with its data.
fn lha_header(level: u8, name: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    let base = |h: &mut Vec<u8>, level: u8| {
        h.extend_from_slice(b"-lh5-");
        h.extend_from_slice(&5u32.to_le_bytes()); // packed
        h.extend_from_slice(&5u32.to_le_bytes()); // original
        h.extend_from_slice(&[0, 0, 0, 0]); // time
        h.push(0x20);
        h.push(level);
    };
    match level {
        0 | 1 => {
            base(&mut h, level);
            h.push(name.len() as u8);
            h.extend_from_slice(name);
            h.extend_from_slice(&[0x12, 0x34]); // crc
            if level == 1 {
                h.push(b'U');
                h.extend_from_slice(&[0, 0]); // no extended header
            }
            let sum = h.iter().fold(0u8, |a, &x| a.wrapping_add(x));
            [&[h.len() as u8, sum][..], &h].concat()
        }
        2 => {
            base(&mut h, 2);
            h.extend_from_slice(&[0x12, 0x34, b'U']);
            // One extended header: a type, two bytes, the size of the next (0).
            h.extend_from_slice(&5u16.to_le_bytes());
            h.extend_from_slice(&[0x01, b'a', b'b', 0, 0]);
            [&((h.len() + 2) as u16).to_le_bytes()[..], &h].concat()
        }
        _ => {
            base(&mut h, 3);
            h.extend_from_slice(&[0x12, 0x34, b'U']);
            h.extend_from_slice(&39u32.to_le_bytes()); // total
            h.extend_from_slice(&7u32.to_le_bytes()); // first extended header
            h.extend_from_slice(&[0x01, b'a', b'b', 0, 0, 0, 0]);
            [&[4u8, 0][..], &h].concat()
        }
    }
}

fn fixture(rel: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{rel}", env!("CARGO_MANIFEST_DIR"));
    read_fixture(&path).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[cfg(any(feature = "dxf", feature = "dwg", feature = "ext"))]
fn gunzip(gz: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut out)
        .expect("a gzip fixture");
    out
}

/// `file` with the marker written over its bytes from `at`.
fn over(file: &[u8], at: usize) -> Vec<u8> {
    let mut v = file.to_vec();
    v[at..at + MARK.len()].copy_from_slice(MARK);
    v
}

/// `file` and the marker after it.
fn then_mark(file: &[u8]) -> Vec<u8> {
    [file, MARK].concat()
}

fn members(fmt: Format, data: &[u8]) -> Vec<Entry> {
    let mut budget = Budget::new(Limits::default());
    extract(fmt, &data, &mut budget).expect("extracts")
}

fn contains(entries: &[Entry], needle: &[u8]) -> bool {
    entries
        .iter()
        .any(|e| e.data.windows(needle.len()).any(|w| w == needle))
}

/// The format of `plain` and of `marked`, which holds the marker, and the
/// members its reader gives for both.
fn same_type_and_members(plain: &[u8], marked: &[u8], want: Format) {
    assert_eq!(detect(&plain), Some(want), "without the marker");
    assert_eq!(detect(&marked), Some(want), "with the marker");
    let (a, b) = (members(want, plain), members(want, marked));
    assert!(!a.is_empty(), "the reader gives no member");
    let names = |v: &[Entry]| v.iter().map(|e| e.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(&a), names(&b));
}

#[cfg(feature = "onenote")]
#[test]
fn a_onenote_section_with_the_marker_is_one() {
    let guid = [
        0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96,
        0xD3,
    ];
    let store = [
        0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45, 0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E,
        0xAC,
    ];
    let payload = b"PAYLOAD-OF-A-ONENOTE-FILE";
    let mut one = guid.to_vec();
    one.extend_from_slice(b"....filler between the header and the object....");
    one.extend_from_slice(&store);
    one.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    one.extend_from_slice(&[0; 12]);
    one.extend_from_slice(payload);
    same_type_and_members(&one, &over(&one, 20), Format::OneNote);
    assert!(contains(
        &members(Format::OneNote, &over(&one, 20)),
        payload
    ));
}

#[cfg(feature = "rtf")]
#[test]
fn an_rtf_document_with_the_marker_and_an_object_is_one() {
    let payload = b"PAYLOAD-OF-AN-RTF-OBJECT";
    let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
    let rtf = format!("{{\\rtf1\\ansi ABCD {{\\object\\objemb{{\\objdata {hex}}}}}}}");
    let rtf = rtf.as_bytes();
    same_type_and_members(rtf, &over(rtf, 14), Format::Rtf);
    assert!(contains(&members(Format::Rtf, &over(rtf, 14)), payload));
}

#[cfg(feature = "dxf")]
#[test]
fn a_dxf_drawing_with_the_marker_is_one() {
    let dxf = b"0\nSECTION\n2\nHEADER\n9\n$ACADVER\n1\nAC1015\n0\nENDSEC\n0\nSECTION\n2\nENTITIES\n0\nENDSEC\n0\nEOF\n";
    assert_eq!(detect(&&dxf[..]), Some(Format::Dxf));
    assert_eq!(detect(&then_mark(dxf)), Some(Format::Dxf));
    let gz = include_bytes!("../fixtures/dxf/ascii-R2018.dxf.gz");
    let real = gunzip(gz);
    assert_eq!(detect(&real), Some(Format::Dxf));
    assert_eq!(detect(&then_mark(&real)), Some(Format::Dxf));
}

#[cfg(feature = "dwg")]
#[test]
fn a_dwg_drawing_with_the_marker_is_one() {
    for gz in [
        &include_bytes!("../fixtures/dwg/R2000.dwg.gz")[..],
        &include_bytes!("../fixtures/dwg/R2018.dwg.gz")[..],
    ] {
        let dwg = gunzip(gz);
        assert_eq!(detect(&dwg), Some(Format::Dwg));
        assert_eq!(detect(&then_mark(&dwg)), Some(Format::Dwg));
        assert_eq!(detect(&over(&dwg, dwg.len() / 2)), Some(Format::Dwg));
    }
}

#[cfg(feature = "lnk")]
#[test]
fn a_shell_link_with_the_marker_is_one() {
    let lnk = fixture("lnk/eicar.lnk");
    assert_eq!(detect(&lnk), Some(Format::Lnk));
    assert_eq!(detect(&then_mark(&lnk)), Some(Format::Lnk));
}

#[cfg(feature = "binhex")]
#[test]
fn a_binhex_file_with_the_marker_is_one() {
    let hqx = fixture("binhex/eicar.hqx");
    same_type_and_members(&hqx, &then_mark(&hqx), Format::Binhex);
}

#[cfg(feature = "pyc")]
#[test]
fn a_pyc_with_the_marker_is_one() {
    let pyc = fixture("pyc/eicar.pyc");
    same_type_and_members(&pyc, &then_mark(&pyc), Format::Pyc);
    assert_eq!(detect(&over(&pyc, pyc.len() / 2)), Some(Format::Pyc));
    // A PDF header among its constants does not make it a PDF.
    let mut with_pdf = pyc.clone();
    with_pdf[40..46].copy_from_slice(b"%PDF-1");
    assert_eq!(detect(&with_pdf), Some(Format::Pyc));
}

/// The two bytes at offset 2 of a pyc are weak: a text whose first line is
/// two characters long, and a header with a number no Python wrote, are not one.
#[cfg(feature = "pyc")]
#[test]
fn a_text_with_a_two_character_first_line_is_not_a_pyc() {
    for first in [&b"{}"[..], b"--", b"//", b"%%", b"ab", b"#!"] {
        let text = [
            first,
            b"\r\nthe second line of a text file\r\nand a third\r\n",
        ]
        .concat();
        assert_ne!(detect(&text), Some(Format::Pyc), "{first:?}");
        assert_ne!(detect(&then_mark(&text)), Some(Format::Pyc), "{first:?}");
    }
    let header = |magic: u16| {
        let mut v = magic.to_le_bytes().to_vec();
        v.extend_from_slice(b"\r\n");
        v.extend_from_slice(&[0; 12]);
        v.extend_from_slice(b"c\0\0\0body of the code object");
        v
    };
    // The numbers CPython has written: 1.5, 1.6, 2.0, 2.1, 2.2, 2.3 to 2.7,
    // 3.0 and the releases since (3.15 is at 3666).
    for magic in [
        20121, 50428, 50823, 60202, 60717, 62011, 62131, 62211, 3000, 3131, 3180, 3320, 3379, 3394,
        3413, 3425, 3439, 3495, 3531, 3571, 3627, 3666,
    ] {
        assert_eq!(detect(&header(magic)), Some(Format::Pyc), "{magic}");
    }
    for magic in [0, 2999, 4000, 8224, 25185, 31355, 50000, 65535] {
        assert_ne!(detect(&header(magic)), Some(Format::Pyc), "{magic}");
    }
}

/// A script that opens with a short first line, then names a PDF header.
#[cfg(feature = "pyc")]
#[test]
fn a_script_with_a_pdf_header_in_its_first_line_is_not_a_pyc() {
    let script = b"ab\r\n%PDF-1.4 is what this prints\r\n".to_vec();
    assert_ne!(detect(&script), Some(Format::Pyc));
}

#[cfg(feature = "nsis")]
fn nsis() -> Vec<u8> {
    use flate2::{Compression, write::DeflateEncoder};
    use std::io::Write;
    let sig: [u8; 16] = [
        0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's',
        b't',
    ];
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
    enc.write_all(b"MALWARETEST hidden in an NSIS deflate block")
        .unwrap();
    let deflate = enc.finish().unwrap();
    let mut blob = b"MZ".to_vec();
    blob.extend_from_slice(&[0u8; 62]);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&sig);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&((0x1c + 4 + deflate.len() + 4) as u32).to_le_bytes());
    blob.extend_from_slice(&((deflate.len() as u32) | 0x8000_0000).to_le_bytes());
    blob.extend_from_slice(&deflate);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob
}

#[cfg(feature = "nsis")]
#[test]
fn an_nsis_installer_with_the_marker_is_one() {
    let exe = nsis();
    assert_eq!(detect(&exe), Some(Format::Nsis));
    // In the stub, and after the data.
    for marked in [over(&exe, 8), then_mark(&exe)] {
        same_type_and_members(&exe, &marked, Format::Nsis);
        assert!(contains(
            &members(Format::Nsis, &marked),
            b"MALWARETEST hidden"
        ));
    }
}

#[cfg(feature = "autoit")]
#[test]
fn an_autoit_executable_with_the_marker_is_one() {
    for tag in [b"AU3!EA05", b"AU3!EA06"] {
        let mut exe = b"MZ".to_vec();
        exe.resize(300, 0);
        exe.extend_from_slice(&autoit_tag(tag));
        exe.extend_from_slice(&[0; 64]);
        assert_eq!(detect(&exe), Some(Format::Autoit));
        assert_eq!(detect(&over(&exe, 100)), Some(Format::Autoit));
        assert_eq!(detect(&then_mark(&exe)), Some(Format::Autoit));
    }
}

#[cfg(feature = "sfx")]
#[test]
fn a_zip_self_extractor_with_the_marker_is_one() {
    let zip = fixture("zip/dd_python_stored.zip");
    let mut exe = b"MZ".to_vec();
    exe.resize(400, 0x90);
    exe.extend_from_slice(&zip);
    let marked = over(&exe, 200);
    assert_eq!(detect(&exe), Some(Format::Sfx));
    assert_eq!(detect(&marked), Some(Format::Sfx));
    assert!(!members(Format::Sfx, &marked).is_empty());
}

/// A ZIP read by its end record, behind a picture, a script line or padding.
#[cfg(feature = "zip")]
#[test]
fn a_zip_behind_other_bytes_with_the_marker_is_a_zip() {
    let zip = fixture("zip/dd_python_stored.zip");
    let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89";
    for prefix in [
        [&png[..], &[0u8; 100][..]].concat(),
        b"#!/usr/bin/env python3\n".to_vec(),
        vec![b' '; 300],
        b"<xdp:xdp>\n<chunk>\n".to_vec(),
        b"(This file must be converted with BinHex 4.0)\n".to_vec(),
    ] {
        let file = [&prefix[..], &zip[..]].concat();
        assert_eq!(detect(&file), Some(Format::Zip), "{}", prefix.len());
        // The marker in the prefix, and in the picture's data.
        for at in [prefix.len() - 8, 4] {
            let marked = over(&file, at);
            assert_eq!(detect(&marked), Some(Format::Zip), "{at}");
        }
        let marked = over(&file, prefix.len() - 8);
        assert!(!members(Format::Zip, &marked).is_empty());
    }
}

#[cfg(feature = "pdf")]
#[test]
fn a_pdf_behind_a_short_prefix_with_the_marker_is_a_pdf() {
    let pdf = b"%PDF-1.4\n% a comment line\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
3 0 obj\n<< /Length 25 >>\nstream\nPAYLOAD-OF-A-PDF-STREAM\nendstream\nendobj\n\
trailer\n<< /Root 1 0 R >>\n%%EOF\n";
    let file = [&b"junk\n"[..], &pdf[..]].concat();
    // In the comment line.
    let marked = over(&file, 5 + 9 + 4);
    same_type_and_members(&file, &marked, Format::Pdf);
    assert!(contains(
        &members(Format::Pdf, &marked),
        b"PAYLOAD-OF-A-PDF"
    ));
}

#[cfg(feature = "partition")]
#[test]
fn a_disk_image_with_the_marker_is_a_partitioned_one() {
    let mut mbr = vec![0u8; 8192];
    mbr[510..512].copy_from_slice(&[0x55, 0xAA]);
    mbr[446] = 0x80;
    mbr[450] = 0x0C;
    mbr[454..458].copy_from_slice(&2u32.to_le_bytes());
    mbr[458..462].copy_from_slice(&6u32.to_le_bytes());
    assert_eq!(detect(&mbr), Some(Format::Partition));
    assert_eq!(detect(&over(&mbr, 3000)), Some(Format::Partition));
    // With the other markers a search looks for, in its first sectors.
    let mut full = mbr.clone();
    full[1024..1048].copy_from_slice(&autoit_tag(b"AU3!EA06"));
    full[1100..1106].copy_from_slice(b"%PDF-1");
    full[1200..1204].copy_from_slice(b"<xdp");
    full[1300..1344].copy_from_slice(b"(This file must be converted with BinHex 4.0");
    assert_eq!(detect(&over(&full, 3000)), Some(Format::Partition));
}

/// An ext volume is told by two bytes at 1080: a file system image that holds
/// an executable, a document or a script is the volume, whatever it holds.
#[cfg(feature = "ext")]
#[test]
fn an_ext_image_is_a_volume_whatever_it_holds() {
    let mut img = ext_image(16384, |_| {});
    assert_eq!(detect(&img), Some(Format::Ext));
    img[2048..2072].copy_from_slice(&autoit_tag(b"AU3!EA06"));
    img[2100..2106].copy_from_slice(b"%PDF-1");
    img[2200..2204].copy_from_slice(b"<xdp");
    img[2300..2344].copy_from_slice(b"(This file must be converted with BinHex 4.0");
    assert_eq!(detect(&img), Some(Format::Ext));
    assert_eq!(detect(&over(&img, 5000)), Some(Format::Ext));
    // A zip as its last bytes: found by its end record, if nothing else is.
    let zip = fixture("zip/dd_python_stored.zip");
    let mut with_zip = img.clone();
    with_zip.extend_from_slice(&zip);
    assert_eq!(detect(&with_zip), Some(Format::Ext));
}

/// A format told by structure or by a magic of its own stays what it is, when
/// two bytes of the weak kind turn up in it by chance.
#[test]
fn two_weak_bytes_do_not_retype_a_format_with_a_header() {
    #[allow(unused_mut)]
    let mut cases: Vec<(Vec<u8>, Format)> = Vec::new();
    #[cfg(feature = "rtf")]
    {
        let mut rtf = b"{\\rtf1\\ansi ".to_vec();
        rtf.resize(2000, b'.');
        cases.push((rtf, Format::Rtf));
    }
    #[cfg(feature = "javaclass")]
    {
        let mut class = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52];
        class.resize(2000, 0xAB);
        cases.push((class, Format::JavaClass));
    }
    #[cfg(feature = "onenote")]
    {
        let mut one = vec![
            0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29,
            0x96, 0xD3,
        ];
        one.resize(2000, 0);
        cases.push((one, Format::OneNote));
    }
    #[cfg(feature = "nsis")]
    {
        let mut exe = nsis();
        exe.resize(2000, 0);
        cases.push((exe, Format::Nsis));
    }
    #[cfg(feature = "autoit")]
    {
        let mut exe = b"MZ".to_vec();
        exe.resize(300, 0);
        exe.extend_from_slice(&autoit_tag(b"AU3!EA06"));
        exe.resize(2000, 0);
        cases.push((exe, Format::Autoit));
    }
    for (data, want) in cases {
        let mut chance = data.clone();
        // The bytes of an ext superblock.
        chance[1080..1082].copy_from_slice(&[0x53, 0xEF]);
        assert_eq!(detect(&chance), Some(want), "{want:?} with ext bytes");
        // The bytes after the two of an executable that an LHA header has its
        // method in.
        if data.starts_with(b"MZ") {
            let mut lha = data.clone();
            lha[2..7].copy_from_slice(b"-lh5-");
            assert_eq!(detect(&lha), Some(want), "{want:?} with an LHA method");
        }
    }
}

/// The header of an LHA archive is told by its method, `-lh5-` and the like.
#[cfg(feature = "lha")]
#[test]
fn an_lha_header_is_still_one_with_the_marker() {
    let mut lha = lha_header(0, b"a.txt");
    lha.resize(200, 0);
    assert_eq!(detect(&lha), Some(Format::Lha));
    assert_eq!(detect(&then_mark(&lha)), Some(Format::Lha));
    assert_eq!(detect(&over(&lha, 100)), Some(Format::Lha));
}

/// Nothing is typed from the marker but an encoded script.
#[cfg(feature = "screnc")]
#[test]
fn the_marker_alone_still_makes_a_script_encoder_file() {
    let mut text = b"<html><script language=\"VBScript.Encode\">".to_vec();
    text.extend_from_slice(MARK);
    text.extend_from_slice(b"AAAAAA==xxxxxxxxxxxxxxxx^#~@</script></html>");
    assert_eq!(detect(&text), Some(Format::Screnc));
    let plain = b"just some text, with no marker in it\n";
    assert_eq!(detect(&&plain[..]), None);
}

/// A compiled AutoIt script has its marker after the script GUID, in the
/// resource of an executable and in the data appended to one, or it is a
/// file of its own that starts with the marker. The marker alone anywhere
/// else, such as in the strings of a program, is not one.
#[cfg(feature = "autoit")]
#[test]
fn a_compiled_autoit_script_is_told_by_its_guid() {
    for tag in [b"AU3!EA05", b"AU3!EA06"] {
        let anchored = autoit_tag(tag);
        let mut text = b"some text before\n".to_vec();
        text.extend_from_slice(&anchored);
        text.extend_from_slice(b"\nand after\n");
        assert_eq!(detect(&text), Some(Format::Autoit), "{tag:?} in a text");
        let mut at_start = tag.to_vec();
        at_start.resize(200, 0);
        assert_eq!(detect(&at_start), Some(Format::Autoit), "{tag:?} first");
        for stub in [&b"MZ"[..], b"\x7fELF", b"plain text\n", b""] {
            let mut bare = stub.to_vec();
            bare.resize(300, 0);
            bare.extend_from_slice(tag);
            bare.resize(600, 0);
            assert_ne!(detect(&bare), Some(Format::Autoit), "{stub:?} {tag:?} bare");
            // The GUID not directly before the marker.
            let mut apart = stub.to_vec();
            apart.resize(300, 0);
            apart.extend_from_slice(&anchored[..16]);
            apart.push(b' ');
            apart.extend_from_slice(tag);
            apart.resize(600, 0);
            assert_ne!(
                detect(&apart),
                Some(Format::Autoit),
                "{stub:?} {tag:?} apart"
            );
        }
    }
}

/// For a format `detect` finds by a string, whether the start of the object
/// is the format's own header.
#[test]
fn the_header_of_a_format_found_by_a_string_is_told_from_the_string() {
    use exav_unpack::{is_found_by_string, string_is_header};
    for f in [
        Format::Screnc,
        Format::Xdp,
        Format::Binhex,
        Format::Autoit,
        Format::Pdf,
    ] {
        assert!(is_found_by_string(f), "{f:?}");
    }
    for f in [
        Format::Zip,
        Format::Ole,
        Format::Email,
        Format::Lha,
        Format::Ext,
    ] {
        assert!(!is_found_by_string(f), "{f:?}");
        assert!(!string_is_header(f, b"PK\x03\x04"), "{f:?}");
    }
    #[cfg(feature = "screnc")]
    {
        assert!(string_is_header(Format::Screnc, b"#@~^AAAAAA=="));
        assert!(!string_is_header(Format::Screnc, b"x #@~^AAAAAA=="));
    }
    #[cfg(feature = "binhex")]
    {
        let line = b"(This file must be converted with BinHex 4.0)\r";
        assert!(string_is_header(Format::Binhex, line));
        assert!(!string_is_header(
            Format::Binhex,
            &[b"\n", &line[..]].concat()
        ));
    }
    #[cfg(feature = "xdp")]
    {
        let root = b"<?xml version=\"1.0\"?>\n<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\">";
        assert!(string_is_header(Format::Xdp, root));
        assert!(!string_is_header(Format::Xdp, b"<xdp><pdf><chunk>"));
    }
    #[cfg(feature = "autoit")]
    {
        assert!(string_is_header(Format::Autoit, &autoit_tag(b"AU3!EA06")));
        assert!(!string_is_header(Format::Autoit, b"AU3!EA06 and the rest"));
    }
    assert!(string_is_header(Format::Pdf, b"%PDF-1.4\n"));
    assert!(!string_is_header(Format::Pdf, b"\n%PDF-1.4\n"));
}

/// Two bytes at 1080 are not an ext volume: the fields of the superblock
/// around them are. A volume is typed, whichever field is the one in the
/// image, and each field that is wrong turns it down.
#[test]
fn the_fields_of_an_ext_superblock_are_checked() {
    let put32 = |sb: &mut [u8], at: usize, v: u32| sb[at..at + 4].copy_from_slice(&v.to_le_bytes());
    assert_eq!(detect(&ext_image(8192, |_| {})), Some(Format::Ext));
    // A 4 KiB block, no first data block, revision 0, a cut image.
    let four = ext_image(8192, |sb| {
        put32(sb, 20, 0);
        put32(sb, 24, 2);
        put32(sb, 28, 2);
        put32(sb, 32, 32768);
        put32(sb, 36, 32768);
        put32(sb, 4, 4096);
        put32(sb, 76, 0);
    });
    assert_eq!(detect(&four), Some(Format::Ext));
    // Bigalloc: clusters of 16 blocks, a first data block of 0 on 1 KiB blocks.
    let big = ext_image(8192, |sb| {
        put32(sb, 100, 0x200);
        put32(sb, 20, 0);
        put32(sb, 28, 4);
    });
    assert_eq!(detect(&big), Some(Format::Ext));
    type Edit = (&'static str, Box<dyn Fn(&mut [u8])>);
    let wrong: [Edit; 13] = [
        ("block size 128 KiB", Box::new(move |sb| put32(sb, 24, 7))),
        ("revision 2", Box::new(move |sb| put32(sb, 76, 2))),
        ("first data block 2", Box::new(move |sb| put32(sb, 20, 2))),
        (
            "first data block 1 on 4 KiB blocks",
            Box::new(move |sb| {
                put32(sb, 24, 2);
                put32(sb, 28, 2);
            }),
        ),
        (
            "cluster size without bigalloc",
            Box::new(move |sb| put32(sb, 28, 1)),
        ),
        ("inode count", Box::new(move |sb| put32(sb, 0, 65))),
        ("no inodes per group", Box::new(move |sb| put32(sb, 40, 0))),
        ("no blocks per group", Box::new(move |sb| put32(sb, 32, 0))),
        (
            "blocks per group over a bitmap",
            Box::new(move |sb| put32(sb, 32, 8193)),
        ),
        ("no blocks", Box::new(move |sb| put32(sb, 4, 1))),
        (
            "inode size not a power of 2",
            Box::new(|sb| sb[88..90].copy_from_slice(&100u16.to_le_bytes())),
        ),
        ("no magic", Box::new(|sb| sb[56..58].fill(0))),
        ("a journal device", Box::new(move |sb| put32(sb, 96, 8))),
    ];
    for (what, edit) in wrong {
        assert_ne!(detect(&ext_image(8192, edit)), Some(Format::Ext), "{what}");
    }
    // Only the magic, among zeros, or in the comment of a PDF.
    let mut zeros = vec![0u8; 8192];
    zeros[1080..1082].copy_from_slice(&[0x53, 0xEF]);
    assert_eq!(detect(&zeros), None);
    let mut pdf = b"junk\n%PDF-1.4\n%".to_vec();
    pdf.resize(3000, b'x');
    pdf[1080..1082].copy_from_slice(&[0x53, 0xEF]);
    assert_eq!(detect(&pdf), Some(Format::Pdf));
}

/// The volume in the repository's fixture is typed, with the fields it has.
#[cfg(feature = "ext")]
#[test]
fn a_real_ext_volume_is_typed() {
    let img = gunzip(&fixture("ext/fragmented.img.gz"));
    assert_eq!(detect(&img), Some(Format::Ext));
}

/// An executable is not an ext volume nor an LHA archive, whatever bytes it
/// holds where those are looked for: an ELF file or a PE with a superblock in
/// its first sectors, and an LHA header after `MZ`.
#[test]
fn an_executable_is_neither_a_volume_nor_an_lha_archive() {
    for magic in [&b"\x7fELF"[..], b"MZ"] {
        let img = ext_image(8192, |_| {});
        assert_eq!(detect(&img), Some(Format::Ext));
        let mut exe = img;
        exe[..magic.len()].copy_from_slice(magic);
        assert_ne!(detect(&exe), Some(Format::Ext), "{magic:?}");
    }
    // `MZ` is a header size of 77 and a checksum of 0x5A: a level 0 header with
    // a name of 55 bytes, and a CRC chosen to make the sum right.
    let mut lha = lha_header(0, &[b'n'; 55]);
    assert_eq!(&lha[..2], &[77, lha[1]][..]);
    let sum = lha[2..].iter().fold(0u8, |a, &x| a.wrapping_add(x));
    // The two bytes after the name are the CRC.
    lha[22 + 55] = lha[22 + 55].wrapping_add(0x5A_u8.wrapping_sub(sum));
    lha[1] = b'Z';
    lha[0] = b'M';
    assert_eq!(&lha[..7], b"MZ-lh5-");
    lha.resize(300, 0);
    assert_ne!(detect(&lha), Some(Format::Lha));
    // The same header after bytes that are not an executable's: the archive.
    let mut plain = lha_header(0, &[b'n'; 55]);
    plain.resize(300, 0);
    assert_eq!(detect(&plain), Some(Format::Lha));
}

/// An LHA header is told by its method and the fields of its level; the
/// bytes of a method between dashes, in a text or a document, are not one.
#[test]
fn the_fields_of_an_lha_header_are_checked() {
    for level in 0..=3 {
        let mut lha = lha_header(level, b"file.txt");
        lha.resize(300, 0);
        assert_eq!(detect(&lha), Some(Format::Lha), "level {level}");
    }
    let broken: Vec<(&str, Vec<u8>)> = {
        let mut v = Vec::new();
        let mut edit = |what: &'static str, level: u8, f: &dyn Fn(&mut Vec<u8>)| {
            let mut h = lha_header(level, b"file.txt");
            f(&mut h);
            h.resize(300, 0);
            v.push((what, h));
        };
        edit("level 0 checksum", 0, &|h| h[1] ^= 1);
        edit("level 0 size", 0, &|h| h[0] += 1);
        edit("level 0 name length", 0, &|h| h[21] += 1);
        edit("level 1 checksum", 1, &|h| h[1] ^= 1);
        edit("level 1 size", 1, &|h| h[0] -= 1);
        edit("level 2 total", 2, &|h| h[0] += 3);
        edit("level 2 chain", 2, &|h| h[24] = 200);
        edit("level 2 chain one byte", 2, &|h| h[24] = 1);
        edit("level 3 word", 3, &|h| h[0] = 5);
        edit("level 3 total", 3, &|h| h[24] += 1);
        edit("level 3 chain", 3, &|h| h[28] = 2);
        edit("level 4", 0, &|h| h[20] = 4);
        // The checksum is made right again, so that the method is what is wrong.
        edit("method", 0, &|h| {
            h[3] = b'x';
            h[1] = h[1].wrapping_add(b'x' - b'l');
        });
        edit("method characters", 0, &|h| {
            h[4] = 0;
            h[1] = h[1].wrapping_sub(b'h');
        });
        v
    };
    for (what, data) in broken {
        assert_ne!(detect(&data), Some(Format::Lha), "{what}");
    }
    // A method between dashes at 2, in a text, or ahead of a PDF.
    let mut text = b"ab-lh5-".to_vec();
    text.resize(300, b' ');
    assert_ne!(detect(&text), Some(Format::Lha));
    let mut pdf = b"ab-lh5-\n%PDF-1.4\n".to_vec();
    pdf.resize(3000, b'x');
    assert_eq!(detect(&pdf), Some(Format::Pdf));
}
