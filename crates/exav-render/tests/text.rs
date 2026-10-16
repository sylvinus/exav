//! `text::visible_text`: one entry for the text of every kind of document that
//! has some, chosen by the bytes where they say and by the name where not.

#[path = "cad_common/mod.rs"]
mod common;

use exav_render::text::visible_text;
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
