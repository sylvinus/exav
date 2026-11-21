//! `text::visible_text`: one entry for the text of every kind of document that
//! has some, chosen by the bytes where they say and by the name where not.

#[path = "cad_common/mod.rs"]
mod common;

use exav_render::text::visible_text;
use exav_unpack::Limits;

/// `text::wants` for a file known by its start alone.
fn wants(name: &str, head: &[u8]) -> bool {
    exav_render::text::wants(name, &head)
}

fn text(name: &str, data: &[u8]) -> Option<String> {
    visible_text(name, data, 1 << 20, &Limits::default()).map(|v| v.text)
}

/// One byte that is not UTF-8 makes the whole file windows-1252, as
/// exav-unpack reads text.
#[test]
fn a_markdown_file_that_is_not_utf8_is_read_as_windows_1252() {
    assert_eq!(
        text("a.md", b"caf\xe9 *au* lait").unwrap(),
        "caf\u{e9} au lait\n"
    );
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

/// A SpreadsheetML file whose `<Table>` is in its first kilobyte is read as
/// the workbook it says it is, not as a page of HTML.
#[cfg(feature = "text-office")]
#[test]
fn a_spreadsheet_with_a_table_near_its_start_is_a_spreadsheet() {
    let xml: &[u8] = b"<?xml version=\"1.0\"?>\
        <Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\" \
        xmlns:ss=\"urn:schemas-microsoft-com:office:spreadsheet\">\
        <Worksheet ss:Name=\"Prices\"><Table><Row><Cell><Data ss:Type=\"String\">tea</Data></Cell>\
        </Row></Table></Worksheet></Workbook>";
    let v = visible_text("book.xml", xml, 1 << 20, &Limits::default()).unwrap();
    assert_eq!(v.text, "Prices\ntea\n");
    assert_eq!(v.sections.len(), 1, "{:?}", v.sections);
}

/// Found by the `visible_text` fuzz target: the reader took a binary file with
/// a SpreadsheetML marker among its first bytes for that document, where
/// `wants`, which the scanner asks first, wants text to begin with.
#[test]
fn a_binary_file_with_a_spreadsheet_marker_among_its_bytes_is_not_that_document() {
    let xml: &[u8] =
        b"<?xml version=\"1.0\"?><Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\">\
                       <Worksheet/></Workbook>";
    let mut data = b"AC1012\0\0\0\0\0\0\x01X\0\0\0\0\0\x1e\0\x05\0\0\0\x12".to_vec();
    data.extend_from_slice(xml);
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
    // The same document as text is read, and wanted, where the office formats are.
    #[cfg(feature = "text-office")]
    {
        assert!(wants("a.xml", xml));
        assert!(text("a.xml", xml).is_some());
    }
}

/// The streams of `a` and `b`, two compound files, in one.
#[cfg(feature = "text-office")]
fn merged(a: &[u8], b: &[u8]) -> Vec<u8> {
    use exav_unpack::cfb::{Compound, build};
    let mut streams: Vec<(String, Vec<u8>)> = Vec::new();
    for data in [a, b] {
        let c = Compound::open(data).expect("a compound file");
        for s in c.streams() {
            if !streams.iter().any(|(n, _)| n == s.name) {
                streams.push((
                    s.name.to_string(),
                    c.read(s.index, u64::MAX).data.into_owned(),
                ));
            }
        }
    }
    let refs: Vec<(&str, &[u8])> = streams
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    build(&refs)
}

#[cfg(feature = "text-office")]
fn office_fixture(path: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/office/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

#[cfg(feature = "text-office")]
#[test]
fn a_compound_file_holding_several_documents_gives_the_text_of_each() {
    let both = merged(
        &office_fixture("docs/sample.doc"),
        &office_fixture("slides/sample.ppt"),
    );
    let doc_alone = text("a.doc", &office_fixture("docs/sample.doc")).unwrap();
    for name in ["a.ppt", "a.doc"] {
        let t = text(name, &both).unwrap();
        assert!(t.contains("Second slide text"), "{name}: {t}");
        assert!(t.starts_with(&doc_alone), "{name}: {t}");
    }
}

#[test]
fn an_ooxml_packages_links_join_their_labels_to_their_targets() {
    use exav_unpack::zip_write::{FileOptions, ZipWriter};
    use std::io::Write;
    let mut w = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in [
        (
            "word/document.xml",
            r#"<w:document xmlns:w="w" xmlns:r="r"><w:hyperlink r:id="rId1"><w:r><w:t>www.bank.example</w:t></w:r></w:hyperlink></w:document>"#,
        ),
        (
            "word/_rels/document.xml.rels",
            r#"<Relationships><Relationship Id="rId1" Type="x/hyperlink" Target="http://evil.example/" TargetMode="External"/></Relationships>"#,
        ),
    ] {
        w.start_file(name, FileOptions::default()).unwrap();
        w.write_all(data.as_bytes()).unwrap();
    }
    let docx = w.finish().unwrap().into_inner();
    let v = visible_text("a.docx", &docx, 1 << 20, &Limits::default()).unwrap();
    assert_eq!(v.text, "www.bank.example (http://evil.example/)\n");
    assert_eq!(
        v.links,
        [(
            "www.bank.example".to_string(),
            "http://evil.example/".to_string()
        )]
    );
    assert!(wants("a.docx", &docx[..64]));
}

#[test]
fn an_email_is_its_headers_and_a_body_that_is_html() {
    let msg = b"From: =?UTF-8?Q?Caf=C3=A9?= <a@b.example>\r\nSubject: hi\r\n\r\n<p>body</p>";
    assert!(wants("x", msg));
    assert_eq!(
        text("x", msg).unwrap(),
        "From: Caf\u{e9} <a@b.example>\nSubject: hi\nbody\n"
    );
    // A body of another kind is a member of the message, not read here.
    let plain = b"From: a@b.example\r\nSubject: hi\r\n\r\njust words";
    assert_eq!(
        text("x", plain).unwrap(),
        "From: a@b.example\nSubject: hi\n"
    );
}

#[test]
fn an_ifc_model_is_the_strings_of_its_instances() {
    let ifc = b"ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('IFC4'));\nENDSEC;\nDATA;\n\
                #1=IFCPROJECT('0YvctVUKr0kugbFTf53O9L',$,'Tower',$,$,$,$,$,$);\n\
                #2=IFCCARTESIANPOINT((0.,0.,0.));\n\
                #3=IFCPROPERTYSINGLEVALUE('Fire rating',$,IFCLABEL('R\\X2\\00E9\\X0\\sistant'),$);\n\
                ENDSEC;\nEND-ISO-10303-21;\n";
    assert!(wants("m.ifc", ifc));
    assert_eq!(
        text("m.ifc", ifc).unwrap(),
        "Tower\nFire rating R\u{e9}sistant\n"
    );
    // Cut at the cap, and said.
    let v = visible_text("m.ifc", ifc, 8, &Limits::default()).unwrap();
    assert!(v.truncated);
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

/// The drawing of exav-unpack's `fixtures/dwg/links/` (`make.py` there), in
/// each version the converter writes: seven entities, six of which carry the
/// hyperlink of AutoCAD's HYPERLINK command (the same one twice, a link to a
/// view, three with a plain target, one described by its own address) and
/// one the extended data of another application, which looks like a link.
fn links_dwg(version: &str) -> Vec<u8> {
    let path = format!(
        "{}/../exav-unpack/tests/fixtures/dwg/links/{version}.dwg.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    common::gunzip(&exav_unpack::read_fixture(&path).expect("fixture"))
}

const DWG_VERSIONS: [&str; 8] = [
    "R13", "R14", "R2000", "R2004", "R2007", "R2010", "R2013", "R2018",
];

#[test]
fn a_dwgs_hyperlinks_are_its_text_and_its_links() {
    for v in DWG_VERSIONS {
        let dwg = links_dwg(v);
        let got = visible_text("plan.dwg", &dwg, 1 << 20, &Limits::default())
            .unwrap_or_else(|| panic!("{v}: no text"));
        let lines: Vec<&str> = got.text.lines().collect();
        // The first lines are the links: a target, then its texts.
        assert_eq!(
            lines[..10],
            [
                "https://evil.example/steal",
                "https://www.paypal.com/login",
                "Detail text display",
                "Detail 1",
                "https://example.org/docs/a%20b",
                "Docs",
                "https://example.org/caf\u{e9}",
                "Caf\u{e9}",
                "https://example.org/same",
                "https://example.org/same",
            ][..],
            "{v}"
        );
        // And the drawing's own text after them.
        assert!(lines[10..].contains(&"hello"), "{v}: {}", got.text);
        assert!(!got.text.contains("other.example"), "{v}: {}", got.text);
        // A description that is not its target is a link to be judged, the
        // view's (no target) is not.
        assert_eq!(
            got.links,
            [
                (
                    "https://www.paypal.com/login".to_string(),
                    "https://evil.example/steal".to_string()
                ),
                (
                    "Docs".to_string(),
                    "https://example.org/docs/a%20b".to_string()
                ),
                (
                    "Caf\u{e9}".to_string(),
                    "https://example.org/caf\u{e9}".to_string()
                ),
            ],
            "{v}"
        );
        assert!(!got.truncated, "{v}");
    }
}

/// The scanner asks `wants` with a kilobyte, which holds the file header of
/// every version but R2007's (it ends at 0x480).
#[test]
fn a_dwg_of_every_version_is_wanted_from_its_first_kilobyte() {
    for v in DWG_VERSIONS {
        let dwg = links_dwg(v);
        assert!(wants("plan.dwg", &dwg[..1024]), "{v}");
        assert!(wants("plan", &dwg[..1024]), "{v}");
    }
    // Wanted is not read: the whole file has to be a drawing.
    let shaped = b"AC1021\0\0\0\0\0\x19\x03 and nothing else";
    assert!(wants("a.dwg", shaped));
    assert_eq!(text("a.dwg", shaped), None);
    assert!(!wants("a.dwg", b"AC1021 not really"));
}

/// The links come before the rest, so a text cut at the cap keeps the first.
#[test]
fn the_hyperlinks_of_a_dwg_are_cut_with_the_text() {
    let dwg = links_dwg("R2018");
    // 26 + 1 and 28 + 1 bytes: the spoofed link fits, "Detail text display"
    // does not.
    let got = visible_text("plan.dwg", &dwg, 60, &Limits::default()).unwrap();
    assert!(got.truncated);
    assert_eq!(
        got.text,
        "https://evil.example/steal\nhttps://www.paypal.com/login\n"
    );
    assert_eq!(got.links.len(), 1);
}

/// Hyperlinks are charged to the drawing's entity limit: past it the rest
/// are dropped and a warning says so (which a scan reads as a text cut).
#[test]
fn a_dwg_with_more_hyperlinks_than_the_limit_says_so() {
    let dwg = links_dwg("R2018");
    let limits = exav_render::cad::Limits {
        max_entities: 3,
        ..exav_render::cad::Limits::default()
    };
    let d = exav_render::cad::read_dwg_with(&dwg, &limits).unwrap();
    assert_eq!(d.hyperlinks.len(), 3);
    assert!(
        d.warnings
            .iter()
            .any(|w| w.kind == exav_render::cad::WarningKind::LimitReached
                && w.message == "hyperlinks past the first 3 were dropped"),
        "{:?}",
        d.warnings
    );
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
