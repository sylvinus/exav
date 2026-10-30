//! HTML pages read as documents: Word's "Save as Web Page" (a `.doc` that is
//! HTML), alone or in its MIME message, and other pages.

#[path = "office_common/mod.rs"]
mod common;

use common::*;
use exav_render::docs::{Error, Format, Limits, convert, text};

fn run(html: &str) -> Vec<u8> {
    convert(html.as_bytes(), Format::Html, &Limits::default())
        .unwrap()
        .docx
}

fn body(docx: &[u8]) -> String {
    part(docx, "word/document.xml")
}

/// What Word writes: Office namespaces, an `xml` block and conditional
/// comments in the head, a style sheet of `Mso` classes with a page, and
/// paragraphs of `o:p`.
const WORD: &str = r##"<html xmlns:o="urn:schemas-microsoft-com:office:office"
xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40">
<head><meta http-equiv=Content-Type content="text/html; charset=windows-1252">
<title>The title is not text of the page</title>
<!--[if gte mso 9]><xml><w:WordDocument><w:View>Print</w:View></w:WordDocument></xml><![endif]-->
<style><!--
p.MsoNormal {margin:0cm; font-size:11.0pt; font-family:"Calibri"}
span.red {color:#FF0000}
@page WordSection1 {size:595.3pt 841.9pt; margin:72.0pt 54.0pt 72.0pt 54.0pt}
div.WordSection1 {page:WordSection1}
--></style><script>var hidden = "script text";</script></head>
<body lang=EN-US><div class=WordSection1>
<h1>Quarterly <i>summary</i></h1>
<p class=MsoNormal>Revenue grew by <b>twelve percent</b>&nbsp;in <span class=red>May</span> &amp; June.<o:p></o:p></p>
<p class=MsoNormal style='text-align:center'>Centered
and  <u>underlined</u></p>
<p><a href="https://example.org/a">a web link</a>, <a href="javascript:alert(1)">a script link</a>,
<a href="file:///C:/secret.txt">a file link</a>, <a href="#top">a place</a> and <a name=top>an anchor</a>.</p>
<ul><li>first<li>second<ol><li>nested one</ol></ul>
<table border=1 cellpadding=2><tr><th>Head</th><td colspan=2>wide</td></tr>
<tr><td rowspan=2>tall</td><td>b</td><td>c</td></tr><tr><td>d</td><td>e</td></tr></table>
<p style="display:none">not shown</p>
<pre>line one
  line two</pre>
</div></body></html>"##;

#[test]
fn a_word_page_is_read() {
    let docx = run(WORD);
    let d = body(&docx);
    for shown in [
        "Quarterly",
        "twelve percent",
        "May",
        "&amp; June",
        "a web link",
        "nested one",
    ] {
        assert!(d.contains(shown), "{shown}: {d}");
    }
    for hidden in [
        "not shown",
        "script text",
        "title is not text",
        "WordDocument",
    ] {
        assert!(!d.contains(hidden), "{hidden}");
    }
    // The bold run is the bold words; the page's style gave the colour.
    let at = d.find("twelve percent").unwrap();
    assert!(
        d[..at]
            .rfind("<w:r>")
            .map(|s| d[s..at].contains("<w:b/>"))
            .unwrap_or(false),
        "{d}"
    );
    let at = d.find(">May<").unwrap();
    assert!(
        d[..at]
            .rfind("<w:r>")
            .map(|s| d[s..at].contains("w:val=\"FF0000\""))
            .unwrap_or(false),
        "{d}"
    );
    // The heading, the centred paragraph, the page of the style sheet.
    assert!(d.contains("<w:outlineLvl w:val=\"0\"/>"), "{d}");
    assert!(d.contains("<w:jc w:val=\"center\"/>"), "{d}");
    assert!(d.contains("<w:pgSz w:w=\"11906\" w:h=\"16838\"/>"), "{d}");
    assert!(
        d.contains("w:left=\"1080\"") && d.contains("w:top=\"1440\""),
        "{d}"
    );
    // A table with its spans, and a line break of `pre` that stays.
    assert!(
        d.contains("<w:tbl>")
            && d.contains("w:gridSpan w:val=\"2\"")
            && d.contains("<w:vMerge w:val=\"restart\"/>"),
        "{d}"
    );
    assert!(
        d.matches("<w:vMerge/>").count() + d.matches("<w:vMerge w:val=\"continue\"/>").count() >= 1,
        "{d}"
    );
    assert!(d.contains("<w:br/>") && d.contains("  line two"), "{d}");
    // The list marks, in a paragraph of the item's own.
    let t = text(WORD.as_bytes(), Format::Html, &Limits::default(), 1 << 20)
        .unwrap()
        .text;
    assert!(
        t.contains("\u{2022} first\n\u{2022} second\n1. nested one\n"),
        "{t}"
    );
    // No paragraph for the white space between blocks.
    assert!(!d.contains("<w:t xml:space=\"preserve\"></w:t>"), "{d}");
}

/// A link goes to a web, mail, phone or FTP address or to a place in the page,
/// and nowhere else: a script, a file on the author's computer or a data
/// address is text.
#[test]
fn only_safe_links_are_kept() {
    let docx = run(WORD);
    let d = body(&docx);
    assert_eq!(d.matches("<w:hyperlink ").count(), 2, "{d}");
    let rels = part(&docx, "word/_rels/document.xml.rels");
    assert!(rels.contains("https://example.org/a"), "{rels}");
    for refused in ["javascript", "secret.txt"] {
        assert!(
            !rels.contains(refused) && !d.contains(&format!("w:anchor=\"{refused}")),
            "{refused}"
        );
    }
    assert!(
        d.contains("a script link") && d.contains("a file link"),
        "{d}"
    );
    let more = run(
        r#"<p><a href="data:text/html;base64,PHNjcmlwdD4=">d</a> <a href="MAILTO:a@b.c">m</a>
        <a href="vbscript:x">v</a> <a href="relative.html">r</a> <a href="tel:+123">t</a></p>"#,
    );
    let m = body(&more);
    assert_eq!(m.matches("<w:hyperlink ").count(), 2, "{m}");
}

/// The page, its pictures and its encodings in one MIME message (Word's
/// "Single File Web Page", often named `.doc`).
#[test]
fn a_mime_wrapped_page_is_read_with_its_picture() {
    // A 1x1 PNG.
    let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==";
    let message = format!(
        "MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=\"----=_NextPart_01\"; type=\"text/html\"\r\n\r\n\
         This is a multi-part message in MIME format.\r\n\r\n------=_NextPart_01\r\n\
         Content-Type: text/html; charset=\"utf-8\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\
         Content-Location: file:///C:/Temp/page.html\r\n\r\n\
         <html xmlns:w=3D\"urn:schemas-microsoft-com:office:word\"><body><p>Caf=C3=A9 =\r\nau lait</p>\
         <p><img src=3D\"page_files/image001.png\" width=3D32 height=3D16 alt=3D\"logo\"></p>\
         <p><img src=3D\"missing.png\" alt=3D\"gone\"></p></body></html>\r\n\
         ------=_NextPart_01\r\nContent-Location: file:///C:/Temp/page_files/image001.png\r\n\
         Content-Transfer-Encoding: base64\r\nContent-Type: image/png\r\n\r\n{png}\r\n\
         ------=_NextPart_01--\r\n"
    );
    let docx = convert(message.as_bytes(), Format::Html, &Limits::default())
        .unwrap()
        .docx;
    let d = body(&docx);
    assert!(d.contains("Café au lait"), "{d}");
    assert!(
        d.contains("<w:drawing>") && d.contains("cx=\"304800\" cy=\"152400\""),
        "{d}"
    );
    assert!(
        d.contains("[gone]"),
        "the picture that is not there is told by its text: {d}"
    );
    assert!(
        !d.contains("MIME-Version") && !d.contains("NextPart"),
        "{d}"
    );
    assert!(has_part(&docx, "word/media/image1.png"));
    let t = text(
        message.as_bytes(),
        Format::Html,
        &Limits::default(),
        1 << 20,
    )
    .unwrap();
    assert!(t.text.contains("Café au lait"), "{}", t.text);
}

#[test]
fn a_picture_in_a_data_address_is_embedded() {
    let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==";
    let d = body(&run(&format!(
        r#"<p>x<img src="data:image/png;base64,{png}" width=10 height=10></p>"#
    )));
    assert!(d.contains("<w:drawing>"), "{d}");
}

#[test]
fn what_is_not_html_is_refused_and_hostile_pages_are_bounded() {
    let e = convert(b"just some text", Format::Html, &Limits::default()).unwrap_err();
    assert_eq!(e.kind(), "not-format");
    // Many paragraphs.
    let many = "<p>x".repeat(200);
    let e = convert(
        many.as_bytes(),
        Format::Html,
        &Limits::default().with_max_paragraphs(5),
    )
    .unwrap_err();
    assert_eq!(e, Error::TooLarge("paragraphs"));
    // Elements nested far past what is kept, and tables in tables.
    let deep = format!(
        "<html><body>{}text{}</body></html>",
        "<div>".repeat(50_000),
        "</div>".repeat(50_000)
    );
    assert!(body(&run(&deep)).contains("text"));
    let tables = format!(
        "<html><body>{}cell{}</body></html>",
        "<table><tr><td>".repeat(5_000),
        "</td></tr></table>".repeat(5_000)
    );
    assert!(convert(tables.as_bytes(), Format::Html, &Limits::default()).is_ok());
    // Cells past the bound.
    let cells = format!("<table><tr>{}</tr></table>", "<td>c".repeat(100));
    let e = convert(
        cells.as_bytes(),
        Format::Html,
        &Limits::default().with_max_cells(10),
    )
    .unwrap_err();
    assert_eq!(e, Error::TooLarge("table cells"));
}

/// The text a scanner or a search reads: what the page shows.
#[test]
fn the_text_of_a_page_is_what_it_shows() {
    let t = text(WORD.as_bytes(), Format::Html, &Limits::default(), 1 << 20).unwrap();
    assert!(t.text.contains("Quarterly summary"), "{}", t.text);
    assert!(
        t.text
            .contains("Revenue grew by twelve percent\u{a0}in May & June."),
        "{}",
        t.text
    );
    assert!(!t.text.contains("script text") && !t.text.contains("not shown"));
}

/// Tables left open and nested a hundred thousand deep are read to the
/// depth elements nest to; the model they make is not as deep as the page.
#[test]
fn tables_nested_without_end_do_not_exhaust_the_stack() {
    let page = format!("<body>{}cell</body>", "<table><tr><td>".repeat(100_000));
    let docx = convert(page.as_bytes(), Format::Html, &Limits::default())
        .unwrap()
        .docx;
    assert!(body(&docx).contains("cell"));
}

/// The cells a row span continues into are cells of the model, and are
/// counted: 5,000 rows each spanning 1,000 rows made some 5 million of them.
#[test]
fn the_cells_a_row_span_continues_into_are_counted() {
    let page = format!(
        "<body><table>{}</table></body>",
        "<tr><td rowspan=1000>x".repeat(5_000)
    );
    let limits = Limits::default().with_max_memory(256 << 20);
    let e = convert(page.as_bytes(), Format::Html, &limits).unwrap_err();
    assert!(matches!(e, Error::TooLarge(_)), "{e:?}");
}

/// Raw text elements are found by their end tag without a copy of the rest of
/// the page for each: 200,000 of them are a page of a few MB, not a minute.
#[test]
fn many_raw_text_elements_are_linear() {
    let page = format!(
        "<body>{}</body>",
        "<script></script><style></style>".repeat(100_000)
    );
    let start = std::time::Instant::now();
    assert!(convert(page.as_bytes(), Format::Html, &Limits::default()).is_ok());
    assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
}

/// A link opened inside a link ends the first, as in HTML: links left open
/// by the thousand do not nest into a model as deep.
#[test]
fn links_left_open_do_not_nest() {
    let page = format!("<body>{}end</body>", "<a href='http://x/'>l".repeat(50_000));
    let docx = convert(page.as_bytes(), Format::Html, &Limits::default())
        .unwrap()
        .docx;
    assert!(body(&docx).contains("end"));
    // Every link is a link of its own, none within another.
    let d = body(&docx);
    assert!(d.matches("<w:hyperlink").count() >= 40_000);
}
