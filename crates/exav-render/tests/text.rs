//! `text::visible_text`: one entry for the text of every kind of document that
//! has some, chosen by the bytes where they say and by the name where not.

#[path = "cad_common/mod.rs"]
mod common;

use exav_render::text::{visible_text, wants};
use exav_unpack::Limits;

fn text(name: &str, data: &[u8]) -> Option<String> {
    visible_text(name, data, 1 << 20, &Limits::default()).map(|v| v.text)
}

#[test]
fn markdown_html_and_package_parts_by_what_they_are() {
    assert_eq!(
        text("a.md", b"Please *read* it").unwrap(),
        "Please read it\n"
    );
    assert_eq!(
        text(
            "page.bin",
            b"<html><body><p>one</p><a href=\"http://x.example/\">two</a></body></html>"
        )
        .unwrap(),
        "one\ntwo (http://x.example/)\n"
    );
    assert_eq!(
        text(
            "word/document.xml",
            b"<w:document><w:p><w:r><w:t>in a docx</w:t></w:r></w:p></w:document>"
        )
        .unwrap(),
        "in a docx\n"
    );
}

/// Found by the `visible_text` fuzz target: the reader took a binary file with
/// a SpreadsheetML marker among its first bytes for that document, where
/// `wants`, which the scanner asks first, wants text to begin with.
#[test]
fn a_binary_file_with_a_spreadsheet_marker_among_its_bytes_is_not_that_document() {
    let mut data = b"AC1012\0\0\0\0\0\0\x01X\0\0\0\0\0\x1e\0\x05\0\0\0\x12".to_vec();
    data.extend_from_slice(
        b"<?xml version=\"1.0\"?><Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\">\
          <Worksheet/></Workbook>",
    );
    // And a flat OpenDocument file's root element.
    let mut flat = b"{\\rinrtf2\0\x05\xb2\0\0\0\x01X\0\0\0\0\0\x1e\0\x05".to_vec();
    flat.extend_from_slice(
        b"<office:document office:mimetype=\"application/vnd.oasis.opendocument.text\"/>",
    );
    for data in [&data, &flat] {
        for name in ["a.dwg", "a.xml", "member"] {
            assert_eq!(text(name, data), None, "{name}");
            assert!(!wants(name, &data[..data.len().min(1024)]), "{name}");
        }
    }
    // The same document as text is read, and wanted.
    let doc = &data[data.len() - 107..];
    assert!(wants("a.xml", doc));
    assert!(text("a.xml", doc).is_some());
}

#[test]
fn what_has_no_text_gives_none() {
    assert_eq!(text("notes.txt", b"just some words"), None);
    assert_eq!(text("a.bin", &[0u8; 64]), None);
    assert_eq!(text("a.dwg", b"AC1032 not really"), None);
    assert_eq!(text("a", b""), None);
}

#[test]
fn a_drawing_is_its_texts_attributes_and_names_in_dxf_and_in_dwg_alike() {
    let dxf = common::fixture("ascii/R2018/all.dxf").expect("fixture");
    let dwg = common::fixture("dwg/R2018/all.dwg").expect("fixture");
    for (name, data) in [("all.dxf", &dxf), ("all.dwg", &dwg)] {
        let t = text(name, data).unwrap_or_else(|| panic!("{name}: no text"));
        // TEXT, a layer name, and MTEXT without its formatting codes.
        assert!(t.contains("Left text"), "{name}: {t}");
        assert!(t.contains("WALLS"), "{name}: {t}");
        assert!(!t.contains("\\P") && !t.contains("\\f"), "{name}: {t}");
    }
    // The same drawing says the same in both.
    let a: std::collections::BTreeSet<_> = text("a.dxf", &dxf)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let b: std::collections::BTreeSet<_> = text("a.dwg", &dwg)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert!(a.contains("Left text") && b.contains("Left text"));
    let common: Vec<_> = a.intersection(&b).collect();
    assert!(
        common.len() * 2 > a.len(),
        "{} of {} lines agree",
        common.len(),
        a.len()
    );
}

#[test]
fn the_text_of_a_drawing_is_cut_at_the_cap() {
    let dxf = common::fixture("ascii/R2018/all.dxf").expect("fixture");
    let v = visible_text("all.dxf", &dxf, 64, &Limits::default()).unwrap();
    assert!(v.truncated);
    assert!(v.text.len() <= 64);
}

#[test]
fn a_drawing_is_read_within_the_memory_the_caller_allows() {
    let mut dxf = String::from("  0\nSECTION\n  2\nENTITIES\n");
    for _ in 0..1000 {
        dxf.push_str("  0\nLINE\n 10\n0\n 20\n0\n 11\n1\n 21\n1\n");
    }
    dxf.push_str("  0\nTEXT\n  1\nafter the lines\n 10\n0\n 20\n0\n  0\nENDSEC\n  0\nEOF\n");
    let mut limits = Limits::default();
    let v = visible_text("a.dxf", dxf.as_bytes(), 1 << 20, &limits).unwrap();
    assert!(v.text.contains("after the lines") && !v.truncated);
    // Room for fewer entities than the drawing has: the text found is kept,
    // and the scan is told it is not all there.
    limits.max_buffer_bytes = 100 * exav_render::cad::ENTITY_BYTES;
    let v = visible_text("a.dxf", dxf.as_bytes(), 1 << 20, &limits).unwrap();
    assert!(!v.text.contains("after the lines") && v.truncated);

    // A DWG whose sections expand past it is unreadable, not empty.
    let dwg = common::fixture("dwg/R2018/all.dwg").expect("fixture");
    limits.max_buffer_bytes = 1 << 10;
    let v = visible_text("a.dwg", &dwg, 1 << 20, &limits).unwrap();
    assert!(v.text.is_empty());
    assert!(v.unreadable.is_some_and(|w| w.starts_with("too-large")));
}

#[test]
fn damaged_drawings_and_documents_do_not_panic() {
    let dxf = common::fixture("ascii/R2018/all.dxf").expect("fixture");
    let dwg = common::fixture("dwg/R2018/all.dwg").expect("fixture");
    for data in [&dxf, &dwg] {
        for cut in [0, 7, 100, data.len() / 3, data.len() - 1] {
            let _ = text("x", &data[..cut]);
            let mut flipped = data[..cut].to_vec();
            for i in (0..flipped.len()).step_by(97) {
                flipped[i] ^= 0xa5;
            }
            let _ = text("x", &flipped);
        }
    }
}
