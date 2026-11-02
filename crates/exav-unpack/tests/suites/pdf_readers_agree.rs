//! A PDF that a reader opens is a PDF whose streams exav reads.
//!
//! Each file here is one that qpdf, pdfium or Acrobat open and show the stream
//! of, with one thing different from the plain layout: bytes before the header,
//! a form feed where a space goes, a filter named by a reference or behind a
//! `/Crypt`, an earlier object that does not end. The stream holds deflated
//! EICAR, so the string is nowhere in the file.

use exav_unpack::{Budget, Format, Limits, detect, extract};
use std::io::Write;

fn payload() -> Vec<u8> {
    [exav_unpack::eicar(), b"\n"].concat().repeat(40)
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// `1 0 obj`'s dictionary text up to `/Length`, then the stream.
fn stream_object(id: u32, dict_extra: &str, raw: &[u8]) -> Vec<u8> {
    let mut o = format!(
        "{id} 0 obj\n<< /Length {} {dict_extra} >>\nstream\n",
        raw.len()
    )
    .into_bytes();
    o.extend_from_slice(raw);
    o.extend_from_slice(b"\nendstream\nendobj\n");
    o
}

fn pdf(lead: &[u8], objects: &[Vec<u8>]) -> Vec<u8> {
    let mut v = lead.to_vec();
    v.extend_from_slice(b"%PDF-1.5\n");
    for o in objects {
        v.extend_from_slice(o);
    }
    v.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    v
}

fn entries(blob: &[u8]) -> Vec<exav_unpack::Entry> {
    let mut budget = Budget::new(Limits::default());
    extract(Format::Pdf, &blob, &mut budget).unwrap()
}

fn finds_the_payload(blob: &[u8]) -> bool {
    let eicar = exav_unpack::eicar();
    assert!(
        !blob.windows(eicar.len()).any(|w| w == eicar),
        "the string must not be in the file's bytes"
    );
    entries(blob)
        .iter()
        .any(|e| e.data.windows(eicar.len()).any(|w| w == eicar))
}

#[test]
fn the_plain_layout_is_read() {
    let p = pdf(
        b"",
        &[stream_object(5, "/Filter /FlateDecode", &zlib(&payload()))],
    );
    assert_eq!(detect(&p), Some(Format::Pdf));
    assert!(finds_the_payload(&p));
}

#[test]
fn bytes_before_the_header_do_not_make_it_another_file() {
    let body = stream_object(5, "/Filter /FlateDecode", &zlib(&payload()));
    for lead in [
        b"\n".to_vec(),
        b"\xEF\xBB\xBF".to_vec(),
        b"Content-Type: application/pdf\r\n\r\n".to_vec(),
        vec![b'x'; 1000],
    ] {
        let p = pdf(&lead, std::slice::from_ref(&body));
        assert_eq!(detect(&p), Some(Format::Pdf), "{} bytes before", lead.len());
        assert!(finds_the_payload(&p), "{} bytes before", lead.len());
    }
}

#[test]
fn a_header_far_in_or_without_a_version_is_not_a_pdf() {
    let body = stream_object(5, "/Filter /FlateDecode", &zlib(&payload()));
    // Past the first kilobyte, no reader takes it for one.
    let far = pdf(&vec![b'x'; 1100], std::slice::from_ref(&body));
    assert_eq!(detect(&far), None);
    // A text that merely mentions the magic.
    assert_eq!(detect(b"the header of a PDF is %PDF- and a version"), None);
}

/// A tar whose first member is a PDF has the magic at byte 512, inside the
/// first kilobyte, and is a tar.
#[cfg(feature = "tar")]
#[test]
fn a_tar_holding_a_pdf_first_is_a_tar() {
    let body = stream_object(5, "/Filter /FlateDecode", &zlib(&payload()));
    let file = pdf(b"", &[body]);
    let mut tar = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(file.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    tar.append_data(&mut h, "report.pdf", &file[..]).unwrap();
    assert_eq!(detect(&tar.into_inner().unwrap()), Some(Format::Tar));
}

#[test]
fn a_form_feed_is_white_space() {
    let z = zlib(&payload());
    let filter = stream_object(5, "/Filter\x0c/FlateDecode", &z);
    assert!(finds_the_payload(&pdf(b"", &[filter])));
    let mut keyword = stream_object(5, "/Filter /FlateDecode", &z);
    keyword.splice(..8, b"5\x0c0\x0cobj\n".iter().copied());
    assert!(finds_the_payload(&pdf(b"", &[keyword])));
}

#[test]
fn a_filter_given_by_reference_is_applied() {
    let z = zlib(&payload());
    let name = b"7 0 obj\n/FlateDecode\nendobj\n".to_vec();
    let list = b"8 0 obj\n[ /FlateDecode ]\nendobj\n".to_vec();
    assert!(finds_the_payload(&pdf(
        b"",
        &[name.clone(), stream_object(5, "/Filter 7 0 R", &z)]
    )));
    assert!(finds_the_payload(&pdf(
        b"",
        &[list, stream_object(5, "/Filter 8 0 R", &z)]
    )));
    // The name inside an array, by reference.
    assert!(finds_the_payload(&pdf(
        b"",
        &[name, stream_object(5, "/Filter [ 7 0 R ]", &z)]
    )));
}

#[test]
fn a_filter_given_by_a_reference_to_nothing_is_reported() {
    let z = zlib(&payload());
    let es = entries(&pdf(b"", &[stream_object(5, "/Filter 99 0 R", &z)]));
    assert!(
        es.iter().any(|e| e.unsupported.is_some()),
        "a stream whose filter cannot be found must say so: {es:?}"
    );
}

#[test]
fn the_identity_crypt_filter_is_passed_over() {
    let z = zlib(&payload());
    let p = pdf(
        b"",
        &[stream_object(5, "/Filter [ /Crypt /FlateDecode ]", &z)],
    );
    assert!(finds_the_payload(&p));
}

#[test]
fn a_filter_nothing_decodes_is_reported() {
    let z = zlib(&payload());
    let es = entries(&pdf(
        b"",
        &[stream_object(
            5,
            "/Filter [ /NoSuchDecode /FlateDecode ]",
            &z,
        )],
    ));
    assert!(es.iter().any(|e| e.unsupported.is_some()), "{es:?}");
    // An image codec ends a chain without a word: nothing follows it to hide.
    let es = entries(&pdf(b"", &[stream_object(5, "/Filter /DCTDecode", &z)]));
    assert!(es.iter().all(|e| e.unsupported.is_none()), "{es:?}");
}

#[test]
fn an_object_that_does_not_end_does_not_hide_the_ones_after_it() {
    let z = zlib(&payload());
    let broken = b"3 0 obj\n<< /Note (this string is never closed >>\nendobj\n".to_vec();
    let p = pdf(b"", &[broken, stream_object(5, "/Filter /FlateDecode", &z)]);
    assert!(finds_the_payload(&p));
}

#[test]
fn a_comment_mark_before_an_object_on_the_same_line_does_not_hide_it() {
    let z = zlib(&payload());
    let mut p = pdf(b"", &[stream_object(4, "", b"plain")]);
    // After the first object's `endobj`, on the line the next one starts on.
    let after = b"endobj\n";
    let at = p.windows(after.len()).position(|w| w == after).unwrap() + after.len();
    let next = stream_object(5, "/Filter /FlateDecode", &z);
    p.splice(at..at, [b"% a note ".as_slice(), &next].concat());
    assert!(finds_the_payload(&p));
}

/// Reading on after an object that does not end costs the bytes read twice. A
/// file of thousands of objects that each leave a string open would cost the
/// square of its size, so the re-reading is bounded, and the file says so when
/// the bound is reached.
#[test]
fn many_objects_that_do_not_end_are_bounded_and_reported() {
    let mut p = b"%PDF-1.5\n".to_vec();
    for i in 0..6000 {
        p.extend_from_slice(
            format!("{} 0 obj\n<< /A (never closed >>\nendobj\n", i + 1).as_bytes(),
        );
    }
    let started = std::time::Instant::now();
    let es = entries(&p);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "took {:?}",
        started.elapsed()
    );
    assert!(
        es.iter()
            .any(|e| e.name == "pdf-overlapping-objects" && e.unsupported.is_some()),
        "{:?}",
        es.iter()
            .map(|e| (&e.name, e.unsupported))
            .collect::<Vec<_>>()
    );
}
