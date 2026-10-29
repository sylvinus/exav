//! `ar` and `cpio` archives that are a little irregular are read as far as the
//! tools that unpack them read them.
//!
//! `ar` and `dpkg-deb` take a size field that has a stray byte after its digits;
//! GNU `cpio` skips bytes that are not a header and goes on at the next one; the
//! Linux kernel unpacks the archives of an initramfs one after the other. A
//! reader that stops at the first of these shows the rest of the file to no
//! scan.

use exav_unpack::{Budget, Entry, Format, Limits, extract};

fn entries(format: Format, blob: &[u8]) -> Vec<Entry> {
    let mut budget = Budget::new(Limits::default());
    extract(format, &blob, &mut budget).unwrap()
}

fn names(es: &[Entry]) -> Vec<&str> {
    es.iter().map(|e| e.name.as_str()).collect()
}

// ---- ar --------------------------------------------------------------------

fn ar_member(name: &str, data: &[u8], size_field: Option<&[u8; 10]>) -> Vec<u8> {
    let mut size = [b' '; 10];
    let digits = data.len().to_string();
    size[..digits.len()].copy_from_slice(digits.as_bytes());
    let mut h = format!(
        "{:<16}{:<12}{:<6}{:<6}{:<8}",
        format!("{name}/"),
        0,
        0,
        0,
        100644
    )
    .into_bytes();
    h.extend_from_slice(size_field.unwrap_or(&size));
    h.extend_from_slice(b"`\n");
    assert_eq!(h.len(), 60);
    h.extend_from_slice(data);
    if data.len() % 2 == 1 {
        h.push(b'\n');
    }
    h
}

#[test]
fn an_ar_size_field_with_a_stray_byte_after_its_digits_is_read() {
    let mut size = [b' '; 10];
    size[..2].copy_from_slice(b"11");
    size[9] = 0;
    let mut ar = b"!<arch>\n".to_vec();
    ar.extend(ar_member("first.txt", b"hello world", Some(&size)));
    ar.extend(ar_member("second.bin", b"the payload!", None));
    let es = entries(Format::Ar, &ar);
    assert_eq!(names(&es), ["first.txt", "second.bin"], "{es:?}");
    assert_eq!(es[1].data, b"the payload!");
}

#[test]
fn bytes_after_an_ar_member_that_are_not_a_header_are_scanned() {
    let mut ar = b"!<arch>\n".to_vec();
    ar.extend(ar_member("first.txt", b"hello world", None));
    let at = ar.len();
    ar.extend_from_slice(b"this is not a header at all, but it is in the file");
    let es = entries(Format::Ar, &ar);
    let rest = es
        .iter()
        .find(|e| e.name == format!("<ar-from-{at}>"))
        .expect("the rest, as a member");
    assert!(rest.data.starts_with(b"this is not a header"));
}

#[test]
fn padding_after_the_last_ar_member_is_not_a_member() {
    let mut ar = b"!<arch>\n".to_vec();
    ar.extend(ar_member("first.txt", b"hello world", None));
    ar.extend_from_slice(b"\n\n");
    let es = entries(Format::Ar, &ar);
    assert_eq!(names(&es), ["first.txt"]);
}

// ---- cpio ------------------------------------------------------------------

fn newc(name: &str, data: &[u8]) -> Vec<u8> {
    let name_z = format!("{name}\0");
    let fields = [0, 0, 0, 0, 1, 0, data.len(), 0, 0, 0, 0, name_z.len(), 0];
    let mut out = b"070701".to_vec();
    for f in fields {
        out.extend_from_slice(format!("{f:08x}").as_bytes());
    }
    out.extend_from_slice(name_z.as_bytes());
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out
}

fn archive(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v: Vec<u8> = members.iter().flat_map(|(n, d)| newc(n, d)).collect();
    v.extend(newc("TRAILER!!!", b""));
    v
}

#[test]
fn a_cpio_header_with_a_bad_digit_is_skipped_and_the_next_one_read() {
    let mut cpio = archive(&[("benign.txt", b"hello"), ("payload.bin", b"the payload!")]);
    // The first header's file size field.
    cpio[54] = b'g';
    let es = entries(Format::Cpio, &cpio);
    assert!(
        es.iter()
            .any(|e| e.name == "payload.bin" && e.data == b"the payload!"),
        "{:?}",
        names(&es)
    );
    // And what was skipped was scanned.
    assert!(
        es.iter().any(|e| e.name.starts_with("<cpio-from-0")),
        "{:?}",
        names(&es)
    );
}

#[test]
fn the_archives_of_an_initramfs_are_all_read() {
    let mut cpio = archive(&[("early.txt", b"microcode")]);
    cpio.extend(archive(&[("payload.bin", b"the payload!")]));
    let es = entries(Format::Cpio, &cpio);
    assert!(
        es.iter().any(|e| e.name == "payload.bin"),
        "{:?}",
        names(&es)
    );
    // With zeros of padding between them.
    let mut padded = archive(&[("early.txt", b"microcode")]);
    padded.extend_from_slice(&[0; 512]);
    padded.extend(archive(&[("payload.bin", b"the payload!")]));
    let es = entries(Format::Cpio, &padded);
    assert!(
        es.iter().any(|e| e.name == "payload.bin"),
        "{:?}",
        names(&es)
    );
}

#[test]
fn what_follows_a_cpio_trailer_that_is_not_a_header_is_scanned() {
    // A compressed second part of an initramfs, as bootloaders concatenate them.
    let mut cpio = archive(&[("early.txt", b"microcode")]);
    let at = cpio.len();
    cpio.extend_from_slice(b"\x1f\x8b\x08\x00 the rest of the image, compressed");
    let es = entries(Format::Cpio, &cpio);
    let rest = es
        .iter()
        .find(|e| e.name == format!("<cpio-from-{at}>"))
        .expect("the rest");
    assert!(rest.data.starts_with(b"\x1f\x8b\x08"));
}

#[test]
fn a_plain_cpio_with_zero_padding_is_unchanged() {
    let mut cpio = archive(&[("a.txt", b"one"), ("b.txt", b"two")]);
    cpio.extend_from_slice(&[0; 1024]);
    let es = entries(Format::Cpio, &cpio);
    assert_eq!(names(&es), ["a.txt", "b.txt"]);
}
