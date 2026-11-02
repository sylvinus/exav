//! The other formats, converted: the fixtures, and short documents written
//! for what each case needs.

#[path = "office_common/mod.rs"]
mod common;

use common::*;
use exav_render::docs::{Error, Format, Limits, convert};
use exav_render::formats::office::test_util::{PackageWriter, W, literal_block};

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/office/docs/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn run(input: &[u8], f: Format) -> Vec<u8> {
    convert(input, f, &Limits::default()).unwrap().docx
}

fn body(docx: &[u8]) -> String {
    part(docx, "word/document.xml")
}

/// The run (from its `<w:r>`) that holds `text`.
fn run_of<'a>(d: &'a str, text: &str) -> &'a str {
    let at = d
        .find(text)
        .unwrap_or_else(|| panic!("{text} is not in the document"));
    let start = d[..at].rfind("<w:r>").unwrap_or(0);
    &d[start..at]
}

#[test]
fn every_fixture_has_the_same_content() {
    for (name, f) in [
        ("sample.doc", Format::Doc),
        ("sample.odt", Format::Odt),
        ("sample.fodt", Format::Fodt),
        ("sample.rtf", Format::Rtf),
    ] {
        let docx = run(&fixture(name), f);
        // ODF bolds the complex script too.
        let d = body(&docx).replace("<w:bCs/>", "");
        assert!(d.contains("Quarterly summary"), "{name}");
        assert!(d.contains("twelve percent"), "{name}");
        assert!(
            d.contains("<w:tbl>") && d.matches("<w:tr>").count() == 2,
            "{name}: {d}"
        );
        // The bold run is "twelve percent" and nothing around it.
        assert!(
            run_of(&d, "twelve percent").contains("<w:b/>"),
            "{name}: {d}"
        );
        assert!(
            !run_of(&d, "Revenue grew by").contains("<w:b/>"),
            "{name}: {d}"
        );
        assert!(
            !run_of(&d, "over the quarter").contains("<w:b/>"),
            "{name}: {d}"
        );
        assert!(d.contains("Second item"), "{name}");
    }
}

/// A flat ODT around `content`, with `extra` in the styles.
fn fodt(styles: &str, content: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0"?><office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" office:mimetype="application/vnd.oasis.opendocument.text">{styles}<office:body><office:text>{content}</office:text></office:body></office:document>"#
    )
    .into_bytes()
}

#[test]
fn odt_collapses_white_space_as_the_format_says() {
    let d = body(&run(
        &fodt(
            "",
            r#"<text:p>  a   b <text:s text:c="2"/>c<text:line-break/> d<text:tab/>e</text:p>"#,
        ),
        Format::Fodt,
    ));
    // Leading white space goes, runs collapse, text:s counts, a space after a
    // break goes.
    assert!(d.contains(">a b   c<"), "{d}");
    assert!(
        d.contains(
            "<w:br/><w:t xml:space=\"preserve\">d</w:t><w:tab/><w:t xml:space=\"preserve\">e</w:t>"
        ),
        "{d}"
    );
}

#[test]
fn odt_master_pages_become_sections_with_headers() {
    let styles = r#"<office:automatic-styles>
<style:page-layout style:name="L1"><style:page-layout-properties fo:page-width="20cm" fo:page-height="30cm" fo:margin-top="1cm" fo:margin-bottom="1cm" fo:margin-left="2cm" fo:margin-right="2cm"/><style:header-style><style:header-footer-properties fo:min-height="0.5cm" fo:margin-bottom="0.2cm"/></style:header-style></style:page-layout>
<style:page-layout style:name="L2"><style:page-layout-properties fo:page-width="29.7cm" fo:page-height="21cm" style:print-orientation="landscape" fo:margin-top="1cm" fo:margin-bottom="1cm" fo:margin-left="1cm" fo:margin-right="1cm"/></style:page-layout>
<style:style style:name="Wide" style:family="paragraph" style:master-page-name="Landscape"/>
</office:automatic-styles>
<office:master-styles><style:master-page style:name="Standard" style:page-layout-name="L1"><style:header><text:p>Top of page</text:p></style:header></style:master-page><style:master-page style:name="Landscape" style:page-layout-name="L2"/></office:master-styles>"#;
    let d = run(
        &fodt(
            styles,
            r#"<text:p>one</text:p><text:p text:style-name="Wide">two</text:p>"#,
        ),
        Format::Fodt,
    );
    let b = body(&d);
    assert_eq!(b.matches("<w:sectPr>").count(), 2, "{b}");
    assert!(b.contains("<w:pgSz w:w=\"11339\" w:h=\"17008\"/>"), "{b}");
    assert!(b.contains("w:orient=\"landscape\""), "{b}");
    assert!(b.contains("<w:headerReference w:type=\"default\""), "{b}");
    assert!(part(&d, "word/header1.xml").contains("Top of page"));
    // The body starts below the header: 1 cm + 0.5 cm + 0.2 cm.
    assert!(
        b.contains("w:top=\"963\"") && b.contains("w:header=\"567\""),
        "{b}"
    );
}

#[test]
fn odt_tables_keep_their_spans() {
    let c = r#"<table:table><table:table-column table:number-columns-repeated="3"/>
<table:table-row><table:table-cell table:number-columns-spanned="2" table:number-rows-spanned="2"><text:p>A</text:p></table:table-cell><table:covered-table-cell/><table:table-cell><text:p>B</text:p></table:table-cell></table:table-row>
<table:table-row><table:covered-table-cell/><table:covered-table-cell/><table:table-cell><text:p>C</text:p></table:table-cell></table:table-row></table:table>"#;
    let b = body(&run(&fodt("", c), Format::Fodt));
    assert!(
        b.contains("<w:gridSpan w:val=\"2\"/><w:vMerge w:val=\"restart\"/>"),
        "{b}"
    );
    // The second row's first cell continues the merge, spanning two columns.
    assert!(b.contains("<w:gridSpan w:val=\"2\"/><w:vMerge/>"), "{b}");
    assert_eq!(b.matches("<w:tc>").count(), 4, "{b}");
}

#[test]
fn odt_notes_comments_links_and_lists() {
    let styles = r#"<office:styles><text:list-style style:name="N"><text:list-level-style-number text:level="1" style:num-format="1" style:num-suffix="."/></text:list-style></office:styles>"#;
    let c = r##"<text:p>See<text:note text:note-class="footnote"><text:note-citation>1</text:note-citation><text:note-body><text:p>The note</text:p></text:note-body></text:note> <text:a xlink:href="https://example.org/">site</text:a> <text:a xlink:href="javascript:alert(1)">bad</text:a> <text:a xlink:href="#mark">inner</text:a><office:annotation><dc:creator xmlns:dc="http://purl.org/dc/elements/1.1/">Ann Lee</dc:creator><text:p>Remark</text:p></office:annotation></text:p>
<text:list text:style-name="N"><text:list-item><text:p>x</text:p></text:list-item></text:list>
<text:list text:style-name="N"><text:list-item><text:p>y</text:p></text:list-item></text:list>
<text:list text:style-name="N" text:continue-numbering="true"><text:list-item><text:p>z</text:p></text:list-item></text:list>"##;
    let d = run(&fodt(styles, c), Format::Fodt);
    let b = body(&d);
    assert!(b.contains("<w:footnoteReference w:id=\"1\"/>"), "{b}");
    assert!(part(&d, "word/footnotes.xml").contains("The note"));
    assert!(b.contains("<w:hyperlink r:id=\"rId"), "{b}");
    assert!(part(&d, "word/_rels/document.xml.rels").contains("https://example.org/"));
    assert!(!part(&d, "word/_rels/document.xml.rels").contains("javascript"));
    assert!(b.contains("w:anchor=\"mark\""), "{b}");
    assert!(b.contains("<w:commentReference w:id=\"0\"/>"), "{b}");
    assert!(part(&d, "word/comments.xml").contains("Ann Lee"));
    // The second list starts over, the third continues the second.
    let n = part(&d, "word/numbering.xml");
    assert_eq!(n.matches("<w:num ").count(), 2, "{n}");
    assert!(n.contains("<w:startOverride w:val=\"1\"/>"), "{n}");
    assert_eq!(b.matches("<w:numId w:val=\"2\"/>").count(), 2, "{b}");
}

#[test]
fn odt_pictures_come_from_the_package_and_the_flat_form() {
    let png = [
        0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, b'I', b'H', b'D', b'R', 0, 0,
        0, 2, 0, 0, 0, 3, 8, 2, 0, 0, 0,
    ];
    let frame = |inner: &str| {
        format!(
            r#"<text:p><draw:frame xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" text:anchor-type="as-char" svg:width="2cm" svg:height="3cm">{inner}</draw:frame></text:p>"#
        )
    };
    // Flat: base64 data.
    let b64 = "iVBORw0KGgoAAAANSUhEUgAAAAIAAAADCAIAAAA=";
    let d = run(
        &fodt(
            "",
            &frame(&format!(
                "<draw:image><office:binary-data>{b64}</office:binary-data></draw:image>"
            )),
        ),
        Format::Fodt,
    );
    assert!(has_part(&d, "word/media/image1.png"));
    assert!(
        body(&d).contains("<wp:extent cx=\"720000\" cy=\"1080000\"/>"),
        "{}",
        body(&d)
    );
    // Package: a member named by xlink:href.
    let content = format!(
        r#"<?xml version="1.0"?><office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:xlink="http://www.w3.org/1999/xlink"><office:body><office:text>{}</office:text></office:body></office:document-content>"#,
        frame(r#"<draw:image xlink:href="Pictures/a.png"/>"#)
    );
    let mut z = PackageWriter::new(1 << 20);
    z.put(
        "mimetype",
        b"application/vnd.oasis.opendocument.text",
        false,
    )
    .unwrap();
    z.put("content.xml", content.as_bytes(), true).unwrap();
    z.put("Pictures/a.png", &png, true).unwrap();
    let d = run(&z.finish().unwrap(), Format::Odt);
    assert!(has_part(&d, "word/media/image1.png"));
}

#[test]
fn odt_refuses_what_is_not_text_and_what_is_encrypted() {
    let mut z = PackageWriter::new(1 << 20);
    z.put(
        "mimetype",
        b"application/vnd.oasis.opendocument.spreadsheet",
        false,
    )
    .unwrap();
    // A spreadsheet's mimetype over a content part that reads as a text.
    z.put(
        "content.xml",
        br#"<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:body><office:text><text:p>x</text:p></office:text></office:body></office:document-content>"#,
        true,
    )
    .unwrap();
    let e = convert(&z.finish().unwrap(), Format::Odt, &Limits::default()).unwrap_err();
    assert_eq!(e.kind(), "not-format");
    let mut z = PackageWriter::new(1 << 20);
    z.put(
        "mimetype",
        b"application/vnd.oasis.opendocument.text",
        false,
    )
    .unwrap();
    z.put("content.xml", b"<a/>", true).unwrap();
    z.put(
        "META-INF/manifest.xml",
        b"<m><manifest:encryption-data xmlns:manifest=\"x\"/></m>",
        true,
    )
    .unwrap();
    assert_eq!(
        convert(&z.finish().unwrap(), Format::Odt, &Limits::default()).unwrap_err(),
        Error::Encrypted
    );
    assert_eq!(
        convert(b"not a zip", Format::Odt, &Limits::default())
            .unwrap_err()
            .kind(),
        "not-format"
    );
    assert_eq!(
        convert(b"<a/>", Format::Fodt, &Limits::default())
            .unwrap_err()
            .kind(),
        "not-format"
    );
}

#[test]
fn odt_is_bounded() {
    let paras: String = (0..50).map(|_| "<text:p>x</text:p>").collect();
    let e = convert(
        &fodt("", &paras),
        Format::Fodt,
        &Limits::default().with_max_paragraphs(10),
    )
    .unwrap_err();
    assert_eq!(e, Error::TooLarge("paragraphs"));
    // Deeply nested lists end, whatever they hold.
    let mut s = String::new();
    for _ in 0..200 {
        s.push_str("<text:list><text:list-item>");
    }
    s.push_str("<text:p>deep</text:p>");
    for _ in 0..200 {
        s.push_str("</text:list-item></text:list>");
    }
    let _ = convert(&fodt("", &s), Format::Fodt, &Limits::default());
}

fn rtf(s: &str) -> String {
    body(&run(s.as_bytes(), Format::Rtf))
}

#[test]
fn rtf_text_has_the_formatting_in_effect_when_it_was_written() {
    // The text before a control word has the formatting before it.
    let d = rtf(
        r"{\rtf1\ansi\deff0{\fonttbl{\f0 Times New Roman;}{\f1 Arial;}}{\colortbl;\red255\green0\blue0;}\pard a \b bold\b0  b {\i italic} c {\cf1 red} d {\f1\fs40 big}\par}",
    );
    assert!(d.contains("<w:r><w:t xml:space=\"preserve\">a </w:t></w:r><w:r><w:rPr><w:b/></w:rPr><w:t xml:space=\"preserve\">bold</w:t></w:r>"), "{d}");
    // \b0 stays in force: the groups that follow are not bold either.
    assert!(
        d.contains(
            "<w:rPr><w:b w:val=\"0\"/><w:i/></w:rPr><w:t xml:space=\"preserve\">italic</w:t>"
        ),
        "{d}"
    );
    assert!(d.contains("<w:rPr><w:b w:val=\"0\"/><w:color w:val=\"FF0000\"/></w:rPr><w:t xml:space=\"preserve\">red</w:t>"), "{d}");
    assert!(d.contains("<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\" w:eastAsia=\"Arial\" w:cs=\"Arial\"/><w:b w:val=\"0\"/><w:sz w:val=\"40\"/><w:szCs w:val=\"40\"/></w:rPr><w:t xml:space=\"preserve\">big</w:t>"), "{d}");
}

#[test]
fn rtf_groups_closed_more_than_they_were_opened_are_ignored() {
    // Found by fuzzing: a footnote that ends the document's only group, and a
    // second closing brace.
    let d = convert(
        b"{\\rtf1\\ansi text.\xfb\\footnote footnote}}\n",
        Format::Rtf,
        &Limits::default(),
    );
    assert!(d.is_ok() || d.is_err());
    let d = convert(b"{\\rtf1 a}}}} b\\par}", Format::Rtf, &Limits::default());
    assert!(d.is_ok() || d.is_err());
}

#[test]
fn rtf_positioned_paragraphs_are_frames() {
    let d = rtf(
        r"{\rtf1\ansi\pard\pvpg\phpg\posx1143\posy4743\absw9615\absh-2922\dfrmtxtx72\dfrmtxty36\nowrap Hello\par\pard\phmrg\posxc\pvpara\posyb\absh300 More\par}",
    );
    assert!(
        d.contains("<w:framePr w:w=\"9615\" w:h=\"2922\" w:hRule=\"exact\" w:hSpace=\"72\" w:vSpace=\"36\" w:wrap=\"notBeside\" w:hAnchor=\"page\" w:vAnchor=\"page\" w:x=\"1143\" w:y=\"4743\"/>"),
        "{d}"
    );
    assert!(
        d.contains("<w:framePr w:h=\"300\" w:hRule=\"atLeast\" w:hAnchor=\"margin\" w:vAnchor=\"text\" w:xAlign=\"center\" w:yAlign=\"bottom\"/>"),
        "{d}"
    );
}

#[test]
fn rtf_characters_in_every_encoding() {
    // \'e9 in the code page, \u with its fallback skipped, Cyrillic by font charset.
    let d = rtf(
        "{\\rtf1\\ansi\\ansicpg1252\\deff0{\\fonttbl{\\f0 A;}{\\f1\\fcharset204 B;}}caf\\'e9 \\u8364?x \\uc0\\u233 y {\\f1\\'cf\\'f0\\'e8}\\par}",
    );
    assert!(d.contains("café €x éy"), "{d}");
    assert!(d.contains("При"), "{d}");
}

#[test]
fn rtf_tables_lists_sections_and_notes() {
    let d = run(
        b"{\\rtf1\\ansi{\\*\\listtable{\\list\\listid1{\\listlevel\\levelnfc23\\levelstartat1{\\leveltext\\'01\\u8226 ?;}{\\levelnumbers;}\\fi-360\\li720}}}{\\*\\listoverridetable{\\listoverride\\listid1\\ls1}}\n\\paperw11906\\paperh16838\\margl1000\\margr1000\\margt1000\\margb1000\n\\pard\\ls1\\ilvl0 item\\par\n\\trowd\\trgaph108\\cellx2000\\cellx5000\\pard\\intbl a\\cell b\\cell\\row\n\\trowd\\trgaph108\\cellx2000\\cellx5000\\pard\\intbl c\\cell d\\cell\\row\n\\pard after\\chftn{\\footnote\\pard\\chftn  text of note}\\par\n{\\header\\pard head\\par}\\sect\\sectd\\landscape\\pgwsxn16838\\pghsxn11906 second\\par}",
        Format::Rtf,
    );
    let b = body(&d);
    assert!(b.contains("<w:numId w:val=\"1\"/>"), "{b}");
    assert!(part(&d, "word/numbering.xml").contains("<w:numFmt w:val=\"bullet\"/>"));
    assert_eq!(b.matches("<w:tr>").count(), 2, "{b}");
    assert!(
        b.contains("<w:gridCol w:w=\"2000\"/><w:gridCol w:w=\"3000\"/>"),
        "{b}"
    );
    assert!(b.contains("<w:footnoteReference w:id=\"1\"/>"), "{b}");
    assert!(part(&d, "word/footnotes.xml").contains("text of note"));
    assert_eq!(b.matches("<w:sectPr>").count(), 2, "{b}");
    assert!(b.contains("<w:pgSz w:w=\"11906\" w:h=\"16838\"/>"), "{b}");
    // The second section's own size, landscape.
    assert!(
        b.contains("<w:pgSz w:w=\"16838\" w:h=\"11906\" w:orient=\"landscape\"/>"),
        "{b}"
    );
    assert!(part(&d, "word/header1.xml").contains("head"));
    // The mark in the note is the note's own.
    assert!(
        part(&d, "word/footnotes.xml").contains("<w:footnoteRef/>"),
        "{}",
        part(&d, "word/footnotes.xml")
    );
}

#[test]
fn rtf_pictures_and_links() {
    let d = run(
        br#"{\rtf1 {\pict\pngblip\picwgoal1440\pichgoal720 89504e470d0a1a0a0000000d49484452000000020000000308020000000000}
{\field{\*\fldinst HYPERLINK "https://example.org/"}{\fldrslt link}} {\field{\*\fldinst HYPERLINK "javascript:x"}{\fldrslt bad}}\par}"#,
        Format::Rtf,
    );
    assert!(has_part(&d, "word/media/image1.png"));
    let b = body(&d);
    assert!(
        b.contains("<wp:extent cx=\"914400\" cy=\"457200\"/>"),
        "{b}"
    );
    assert!(b.contains("<w:hyperlink r:id="), "{b}");
    assert!(!part(&d, "word/_rels/document.xml.rels").contains("javascript"));
}

#[test]
fn rtf_is_refused_when_it_is_not_and_bounded_when_it_is() {
    assert_eq!(
        convert(b"plain text", Format::Rtf, &Limits::default())
            .unwrap_err()
            .kind(),
        "not-format"
    );
    // Groups nested past the bound.
    let deep = format!("{{\\rtf1 {}x{}}}", "{".repeat(500), "}".repeat(500));
    assert_eq!(
        convert(deep.as_bytes(), Format::Rtf, &Limits::default())
            .unwrap_err()
            .kind(),
        "malformed"
    );
    // Huge parameters do not overflow.
    let _ = convert(
        b"{\\rtf1 \\fs-2147483648 \\li2147483647 \\expnd99999999999 x\\par}",
        Format::Rtf,
        &Limits::default(),
    );
    let many: String = (0..100).map(|_| "x\\par ").collect();
    let e = convert(
        format!("{{\\rtf1 {many}}}").as_bytes(),
        Format::Rtf,
        &Limits::default().with_max_paragraphs(5),
    )
    .unwrap_err();
    assert_eq!(e, Error::TooLarge("paragraphs"));
}

#[test]
fn word_2003_xml() {
    let x = String::from_utf8(fixture("sample-2003.xml")).unwrap();
    let d = run(x.as_bytes(), Format::Wml2003);
    let b = body(&d);
    assert!(
        b.contains("<w:pStyle w:val=\"H1\"/><w:jc w:val=\"center\"/>"),
        "{b}"
    );
    assert!(b.contains("<w:i/><w:color w:val=\"0000FF\"/>"), "{b}");
    assert!(b.contains("<w:hyperlink r:id="), "{b}");
    assert!(
        b.contains("<w:gridCol w:w=\"2500\"/>") && b.contains(">c2<"),
        "{b}"
    );
    // The last section's properties are the document's.
    assert!(
        b.contains("<w:pgSz w:w=\"11906\" w:h=\"16838\"/>") && b.contains("w:left=\"1200\""),
        "{b}"
    );
    assert_eq!(b.matches("<w:sectPr>").count(), 1, "{b}");
    assert!(part(&d, "word/styles.xml").contains("w:styleId=\"H1\""));
    // UTF-16 text works as well.
    let mut u16: Vec<u8> = vec![0xFF, 0xFE];
    u16.extend(x.encode_utf16().flat_map(|c| c.to_le_bytes()));
    assert!(body(&run(&u16, Format::Wml2003)).contains(">Title<"));
    assert_eq!(
        convert(b"<a/>", Format::Wml2003, &Limits::default())
            .unwrap_err()
            .kind(),
        "not-format"
    );
}

/// An IWA stream of objects: (id, type, message).
fn iwa(objects: &[(u64, u32, W)]) -> Vec<u8> {
    let mut raw = vec![];
    for (id, ty, m) in objects {
        let info = W::default().uint(1, *id).msg(
            2,
            W::default()
                .uint(1, u64::from(*ty))
                .uint(3, m.0.len() as u64),
        );
        raw.extend(W::varint_len(info.0.len() as u64));
        raw.extend(&info.0);
        raw.extend(&m.0);
    }
    let block = literal_block(&raw);
    let mut out = vec![
        0,
        block.len() as u8,
        (block.len() >> 8) as u8,
        (block.len() >> 16) as u8,
    ];
    out.extend(block);
    out
}

#[test]
fn pages_text_with_its_styles_and_page() {
    let table = |entries: &[(u64, Option<u64>)]| {
        let mut t = W::default();
        for (i, o) in entries {
            let mut e = W::default().uint(1, *i);
            if let Some(o) = o {
                e = e.reference(2, *o);
            }
            t = t.msg(1, e);
        }
        t
    };
    let text = "Title\nBody words here";
    let storage = W::default()
        .bytes(3, text.as_bytes())
        .msg(5, table(&[(0, Some(3)), (6, Some(4))]))
        .msg(8, table(&[(0, Some(6)), (11, Some(5)), (16, Some(6))]));
    // A bold 20 pt centered paragraph style, a plain one, an italic character
    // style and an empty one.
    let pstyle = |bold: bool, size: f32, align: u64| {
        let mut chars = W::default();
        if bold {
            chars = chars.uint(1, 1);
        }
        chars = chars.float(3, size);
        W::default()
            .msg(11, chars)
            .msg(12, W::default().uint(1, align))
    };
    let doc = W::default()
        .reference(4, 2)
        .float(30, 595.0)
        .float(31, 842.0)
        .float(32, 72.0)
        .float(33, 36.0)
        .float(34, 72.0)
        .float(35, 36.0);
    let objects = [
        (1, 10000, doc),
        (2, 2001, storage),
        (3, 2022, pstyle(true, 20.0, 2)),
        (4, 2022, pstyle(false, 12.0, 0)),
        (5, 2021, W::default().msg(11, W::default().uint(2, 1))),
        (6, 2021, W::default().msg(11, W::default())),
    ];
    let mut z = PackageWriter::new(1 << 20);
    z.put("Index/Document.iwa", &iwa(&objects), true).unwrap();
    let d = run(&z.finish().unwrap(), Format::Pages);
    let b = body(&d);
    assert!(b.contains("<w:jc w:val=\"center\"/>"), "{b}");
    assert!(b.contains("<w:b/><w:sz w:val=\"40\"/><w:szCs w:val=\"40\"/></w:rPr><w:t xml:space=\"preserve\">Title</w:t>"), "{b}");
    assert!(b.contains("<w:i/><w:sz w:val=\"24\"/><w:szCs w:val=\"24\"/></w:rPr><w:t xml:space=\"preserve\">words</w:t>"), "{b}");
    assert!(b.contains("<w:pgSz w:w=\"11900\" w:h=\"16840\"/>"), "{b}");
    assert!(
        b.contains("w:top=\"1440\"") && b.contains("w:left=\"720\""),
        "{b}"
    );
    // No archives at all: not a Pages document; XML Pages are told apart.
    let mut z = PackageWriter::new(1 << 20);
    z.put("index.xml", b"<a/>", true).unwrap();
    assert_eq!(
        convert(&z.finish().unwrap(), Format::Pages, &Limits::default())
            .unwrap_err()
            .kind(),
        "unsupported"
    );
    let mut z = PackageWriter::new(1 << 20);
    z.put("other", b"x", true).unwrap();
    assert_eq!(
        convert(&z.finish().unwrap(), Format::Pages, &Limits::default())
            .unwrap_err()
            .kind(),
        "not-format"
    );
}

/// The memory bound counts what the model takes, which is a few kilobytes
/// for a table cell and for a paragraph: 20,000 cells, or 100,000 paragraphs,
/// hold some 100 and 270 MB.
#[test]
fn rtf_cells_and_paragraphs_are_counted_at_what_they_take() {
    let cells = format!(
        "{{\\rtf1 {}}}",
        "\\trowd\\cellx100\\cell\\row".repeat(20_000)
    );
    let paras = format!("{{\\rtf1 {}}}", "x\\par ".repeat(100_000));
    for rtf in [cells, paras] {
        let within = |mib: u64| {
            let limits = Limits::default().with_max_memory(mib << 20);
            convert(rtf.as_bytes(), Format::Rtf, &limits)
        };
        assert_eq!(within(64).unwrap_err(), Error::TooLarge("memory"));
        assert!(within(512).is_ok());
    }
}

#[test]
fn a_tree_of_elements_nothing_reads_is_charged_for() {
    let x = format!(
        "<w:wordDocument xmlns:w=\"http://schemas.microsoft.com/office/word/2003/wordml\"><w:body>{}</w:body></w:wordDocument>",
        "<w:x/>".repeat(100_000)
    );
    let small = Limits::default().with_max_memory(8 << 20);
    assert_eq!(
        convert(x.as_bytes(), Format::Wml2003, &small).unwrap_err(),
        Error::TooLarge("memory")
    );
    assert!(convert(x.as_bytes(), Format::Wml2003, &Limits::default()).is_ok());
}
