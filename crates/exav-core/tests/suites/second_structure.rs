//! A file can be two archives, and a reader opens the one it goes by.
//!
//! The magic at the start types a file as one format. `unzip` goes by the record
//! at the end of the file instead, and a disk image keeps the start of its first
//! sectors for boot code, so a PDF, a tar or a gzip with a ZIP behind it, or an
//! ISO that begins with an archive's magic, is a second archive for the reader
//! that opens it as that. Each payload here is deflated EICAR, so the string is
//! not in the bytes of the file.

use exav_core::{ScanOptions, Scanner, Verdict, analyze};
use std::io::Write;

fn payload() -> Vec<u8> {
    [exav_core::unpack::eicar(), b"\n"].concat().repeat(40)
}

fn verdict(data: &[u8]) -> Verdict {
    let eicar = exav_core::unpack::eicar();
    assert!(
        !data.windows(eicar.len()).any(|w| w == eicar),
        "the string must not be in the file's bytes"
    );
    analyze(&Scanner::builtin(), data, &ScanOptions::default()).verdict
}

fn zip_with_payload() -> Vec<u8> {
    let deflated = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file("e.com", deflated).unwrap();
    z.write_all(&payload()).unwrap();
    z.finish().unwrap().into_inner()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(data).unwrap();
    gz.finish().unwrap()
}

fn is_infected(v: &Verdict) -> bool {
    matches!(v, Verdict::Infected { .. })
}

#[test]
fn the_zip_alone_is_infected() {
    assert!(is_infected(&verdict(&zip_with_payload())));
}

#[test]
fn a_zip_behind_a_pdf_is_found() {
    let mut f =
        b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
            .to_vec();
    assert!(!is_infected(&verdict(&f)), "the PDF alone is clean");
    f.extend_from_slice(&zip_with_payload());
    assert!(is_infected(&verdict(&f)), "{:?}", verdict(&f));
}

#[test]
fn a_zip_behind_a_tar_is_found() {
    let mut tar = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(5);
    h.set_mode(0o644);
    h.set_cksum();
    tar.append_data(&mut h, "note.txt", &b"hello"[..]).unwrap();
    let mut f = tar.into_inner().unwrap();
    assert!(!is_infected(&verdict(&f)));
    f.extend_from_slice(&zip_with_payload());
    assert!(is_infected(&verdict(&f)), "{:?}", verdict(&f));
}

#[test]
fn a_zip_behind_a_gzip_is_found() {
    let mut f = gzip(b"nothing to see here\n");
    assert!(!is_infected(&verdict(&f)));
    f.extend_from_slice(&zip_with_payload());
    assert!(is_infected(&verdict(&f)), "{:?}", verdict(&f));
}

const SECTOR: usize = 2048;

fn dir_record(lba: u32, size: u32, is_dir: bool, name: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; 33 + name.len()];
    r[2..6].copy_from_slice(&lba.to_le_bytes());
    r[10..14].copy_from_slice(&size.to_le_bytes());
    r[25] = if is_dir { 2 } else { 0 };
    r[32] = name.len() as u8;
    r[33..].copy_from_slice(name);
    r[0] = r.len() as u8;
    r
}

/// An ISO 9660 image with one file in its primary tree: sector 16 the volume
/// descriptor, 17 its terminator, 18 the root directory, 19 the file. The
/// first bytes are left to `system_area`, as the format allows.
fn iso_with(system_area: &[u8], file: &[u8]) -> Vec<u8> {
    let mut img = vec![0u8; 20 * SECTOR];
    img[..system_area.len()].copy_from_slice(system_area);
    let mut put = |sector: usize, off: usize, bytes: &[u8]| {
        let a = sector * SECTOR + off;
        img[a..a + bytes.len()].copy_from_slice(bytes);
    };
    put(16, 0, &[1]);
    put(16, 1, b"CD001");
    put(16, 156, &dir_record(18, SECTOR as u32, true, &[0]));
    put(17, 0, &[255]);
    put(17, 1, b"CD001");
    let mut root = dir_record(18, SECTOR as u32, true, &[0]);
    root.extend(dir_record(18, SECTOR as u32, true, &[1]));
    root.extend(dir_record(19, file.len() as u32, false, b"E.GZ;1"));
    put(18, 0, &root);
    put(19, 0, file);
    img
}

#[test]
fn an_iso_that_begins_with_an_archive_magic_is_walked_as_the_iso_it_is() {
    let file = gzip(&payload());
    // A plain ISO: the control.
    assert!(is_infected(&verdict(&iso_with(&[], &file))));
    // The same image under a ZIP's local header magic, in the system area.
    let img = iso_with(b"PK\x03\x04", &file);
    assert!(is_infected(&verdict(&img)), "{:?}", verdict(&img));
}
