//! The text a reader sees in HTML, in the XML parts of Office and OpenDocument
//! files, and in PDF.

use exav_unpack::Limits;
use exav_unpack::text::{Kind, XmlPart, extract, kind};

fn html(src: &str) -> String {
    extract(Kind::Html, src.as_bytes(), 1 << 20, &Limits::default()).text
}

fn xml(part: XmlPart, src: &str) -> String {
    extract(Kind::Xml(part), src.as_bytes(), 1 << 20, &Limits::default()).text
}

// ── HTML ─────────────────────────────────────────────────────────────────────

#[test]
fn tags_between_the_letters_of_a_word_do_not_split_it() {
    assert_eq!(html("cl<b>ick</b> <i>here</i>"), "click here\n");
}

#[test]
fn blocks_are_lines_and_a_table_row_is_a_line_with_tabs() {
    assert_eq!(
        html("<p>one</p><p>two</p><div>three</div>"),
        "one\ntwo\nthree\n"
    );
    assert_eq!(
        html("<table><tr><td>a</td><td>b</td></tr><tr><td>c</td></tr></table>"),
        "a\tb\nc\n"
    );
    assert_eq!(html("a<br>b<br/>c"), "a\nb\nc\n");
}

#[test]
fn scripts_styles_comments_and_templates_are_not_text() {
    assert_eq!(
        html(
            "a<script>var x = \"<b>no</b>\"; </script><style>p { } </style><!-- hid -->b<template><p>t</p></template>c"
        ),
        "abc\n"
    );
    // A raw-text element ends at its own end tag only.
    assert_eq!(html("<style>x</script>y</style>z"), "z\n");
    assert_eq!(html("<SCRIPT>no</SCRIPT>yes"), "yes\n");
    // A script that opens a comment and another script ends at the second end tag.
    assert_eq!(html("<script><!--<script>x</script>y</script>z"), "z\n");
}

#[test]
fn entities_are_decoded_whatever_their_name() {
    assert_eq!(
        html(
            "&amp; &lt;b&gt; &hearts; &#65; &#x42; &nbsp;x &zzzz; &CounterClockwiseContourIntegral;"
        ),
        "& <b> \u{2665} A B x &zzzz; \u{2233}\n"
    );
    // The specification's legacy names need no semicolon.
    assert_eq!(html("&notit"), "\u{ac}it\n");
}

#[test]
fn a_link_is_its_label_and_where_it_leads() {
    assert_eq!(
        html("<a href=\"https://evil.example/x?a=1&amp;b=2\">Click <b>here</b></a> now"),
        "Click here (https://evil.example/x?a=1&b=2) now\n"
    );
    // The label that is the target says it once; a fragment leads nowhere.
    assert_eq!(
        html("<a href=\"https://a.example/\">https://a.example/</a> <a href=\"#top\">top</a>"),
        "https://a.example/ top\n"
    );
    // Whatever the target is.
    assert_eq!(
        html("<a href='javascript:alert(1)'>run</a>"),
        "run (javascript:alert(1))\n"
    );
    // A label naming one site over a target on another is all there to see.
    let t = html("<a href=\"https://evil.example/steal\">https://www.paypal.com/login</a>");
    assert!(
        t.contains("paypal.com/login") && t.contains("(https://evil.example/steal)"),
        "{t}"
    );
    // An unclosed link ends with the document.
    assert_eq!(html("<a href=x>y"), "y (x)\n");
}

#[test]
fn an_image_is_its_alt_text() {
    assert_eq!(html("a<img src=x alt=\"a diagram\">b"), "a a diagram b\n");
}

#[test]
fn title_and_textarea_are_text_as_written() {
    assert_eq!(
        html("<title>T &amp; U</title><textarea><b>x</b></textarea>"),
        "T & U\n<b>x</b>\n"
    );
}

#[test]
fn a_greater_than_in_a_quoted_attribute_does_not_end_the_tag() {
    assert_eq!(html("<a title=\"a > b\" href=\"u\">t</a>"), "t (u)\n");
}

#[test]
fn bytes_that_are_not_utf8_are_read_as_windows_1252() {
    let t = extract(
        Kind::Html,
        b"<p>caf\xe9 \x80</p>",
        1 << 20,
        &Limits::default(),
    )
    .text;
    assert_eq!(t, "caf\u{e9} \u{20ac}\n");
    let utf16: Vec<u8> = [0xff, 0xfe]
        .into_iter()
        .chain("<p>hi</p>".encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    assert_eq!(
        extract(Kind::Html, &utf16, 1 << 20, &Limits::default()).text,
        "hi\n"
    );
}

#[test]
fn the_text_is_cut_at_the_cap_and_says_so() {
    let e = extract(
        Kind::Html,
        "<p>word </p>".repeat(1000).as_bytes(),
        100,
        &Limits::default(),
    );
    assert!(e.truncated);
    assert!(e.text.len() <= 101, "{}", e.text.len());
    assert!(!extract(Kind::Html, b"<p>a</p>", 100, &Limits::default()).truncated);
}

#[test]
fn hostile_html_is_bounded_in_time_and_stack() {
    let inputs = [
        "<a href=\"".repeat(100_000),
        "<".repeat(500_000),
        "<div>".repeat(300_000),
        "<!--".repeat(100_000),
        "&".repeat(500_000),
        "<a ".repeat(200_000),
        "<script>".repeat(100_000),
        "<p a=b ".repeat(100_000),
    ];
    for src in inputs {
        let started = std::time::Instant::now();
        let src = src.clone();
        std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(move || {
                extract(Kind::Html, src.as_bytes(), 1 << 22, &Limits::default())
                    .text
                    .len()
            })
            .unwrap()
            .join()
            .expect("no panic, no stack overflow");
        assert!(started.elapsed().as_secs() < 20, "{:?}", started.elapsed());
    }
}

// ── XML parts ────────────────────────────────────────────────────────────────

#[test]
fn a_word_document_is_its_paragraphs_without_field_codes_and_deleted_text() {
    let doc = r#"<w:document xmlns:w="x"><w:body>
        <w:p><w:r><w:t>Hello</w:t></w:r><w:r><w:t xml:space="preserve"> world</w:t></w:r></w:p>
        <w:p><w:r><w:instrText>HYPERLINK "http://x.example"</w:instrText></w:r>
            <w:del><w:r><w:delText>gone</w:delText></w:r></w:del><w:r><w:t>Second</w:t><w:tab/><w:t>tabbed &amp; &#65;</w:t></w:r></w:p>
        </w:body></w:document>"#;
    assert_eq!(xml(XmlPart::Word, doc), "Hello world\nSecond tabbed & A\n");
}

#[test]
fn slides_shared_strings_and_sheets_have_their_own_places_for_text() {
    assert_eq!(
        xml(
            XmlPart::Slide,
            "<p:sld><a:p><a:r><a:t>Title</a:t></a:r></a:p><a:p><a:r><a:t>Body</a:t></a:r><a:br/><a:r><a:t>next</a:t></a:r></a:p></p:sld>"
        ),
        "Title\nBody\nnext\n"
    );
    assert_eq!(
        xml(
            XmlPart::SharedStrings,
            "<sst><si><t>one</t></si><si><r><t>tw</t></r><r><t>o</t></r></si></sst>"
        ),
        "one\ntwo\n"
    );
    assert_eq!(
        xml(
            XmlPart::Sheet,
            "<worksheet><sheetData><row><c t=\"s\"><v>5</v></c><c><f>HYPERLINK(\"http://x\",\"y\")</f><v>0</v></c></row><row><c t=\"inlineStr\"><is><t>z</t></is></c></row></sheetData></worksheet>"
        ),
        "HYPERLINK(\"http://x\",\"y\")\nz\n"
    );
}

#[test]
fn opendocument_text_is_read_wherever_it_is() {
    assert_eq!(
        xml(
            XmlPart::Odf,
            "<office:text><text:h>Head</text:h><text:p>a <text:span>b</text:span><text:s/>c<text:line-break/>d</text:p><table:table-row><table:table-cell><text:p>x</text:p></table:table-cell><table:table-cell><text:p>y</text:p></table:table-cell></table:table-row></office:text>"
        ),
        "Head\na b c\nd\nx\ty\n"
    );
}

#[test]
fn a_custom_entity_is_never_expanded_and_damage_ends_the_reading_not_the_scan() {
    let bomb = "<!DOCTYPE d [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]><w:document><w:p><w:t>&b;ok</w:t></w:p></w:document>";
    let t = xml(XmlPart::Word, bomb);
    assert!(t.len() < 100, "{t}");
    assert_eq!(
        xml(XmlPart::Word, "<w:p><w:t>before</w:t></w:p><w:p><w:t>cut"),
        "before\ncut\n"
    );
    assert_eq!(xml(XmlPart::Word, "<<<>>>&&& <w:t"), "");
}

// ── what a document is ───────────────────────────────────────────────────────

#[test]
fn a_document_is_known_by_its_bytes_or_its_path() {
    assert_eq!(
        kind("x", b"%PDF-1.7\n"),
        cfg!(feature = "text-pdf").then_some(Kind::Pdf)
    );
    assert_eq!(kind("x", b"\n\n<!DOCTYPE html><html>"), Some(Kind::Html));
    assert_eq!(kind("a.htm", b"plain"), Some(Kind::Html));
    assert_eq!(kind("x", b"<HTML><BODY>"), Some(Kind::Html));
    assert_eq!(
        kind("word/document.xml", b"<?xml"),
        Some(Kind::Xml(XmlPart::Word))
    );
    assert_eq!(
        kind("xl/worksheets/sheet3.xml", b"<?xml"),
        Some(Kind::Xml(XmlPart::Sheet))
    );
    // A fragment, as an email's body is.
    assert_eq!(kind("x", b"Hi <a href='u'>there</a>"), Some(Kind::Html));
    // Markup is text: a binary file by any of these names is not.
    assert_eq!(kind("a.html", b"PK\x03\x04\0\0\0"), None);
    assert_eq!(kind("word/document.xml", b"\x89PNG\r\n\x1a\n\0\0"), None);
    assert_eq!(kind("notes.txt", b"just words"), None);
    assert_eq!(kind("x", b""), None);
}

// ── PDF ──────────────────────────────────────────────────────────────────────

#[cfg(feature = "text-pdf")]
mod pdf {
    use super::*;

    /// A PDF of one page with the text drawn by `content`, in the font
    /// dictionary `font` (not embedded: a standard font).
    fn pdf(content: &str, font: &str) -> Vec<u8> {
        pdf_objects(content, font, "")
    }

    fn pdf_objects(content: &str, font: &str, extra: &str) -> Vec<u8> {
        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        let mut put = |out: &mut Vec<u8>, body: &str| {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", offsets.len()).as_bytes());
        };
        put(&mut out, "<</Type/Catalog/Pages 2 0 R>>");
        put(&mut out, "<</Type/Pages/Kids[3 0 R]/Count 1>>");
        put(
            &mut out,
            "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>",
        );
        put(
            &mut out,
            &format!(
                "<</Length {}>>\nstream\n{content}\nendstream",
                content.len()
            ),
        );
        put(&mut out, font);
        if !extra.is_empty() {
            put(&mut out, extra);
        }
        let xref = out.len();
        out.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1).as_bytes(),
        );
        for o in &offsets {
            out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<</Size {}/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n",
                offsets.len() + 1
            )
            .as_bytes(),
        );
        out
    }

    const HELVETICA: &str =
        "<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>";

    fn text(pdf: &[u8]) -> String {
        extract(Kind::Pdf, pdf, 1 << 20, &Limits::default()).text
    }

    #[test]
    fn the_lines_and_words_of_a_page() {
        let p = pdf(
            "BT /F1 12 Tf 72 700 Td (Hello World) Tj 0 -20 Td (Second ) Tj (line) Tj ET",
            HELVETICA,
        );
        assert_eq!(text(&p), "Hello World\nSecond line\n");
    }

    #[test]
    fn a_kerned_word_stays_whole_and_a_gap_is_a_space() {
        let p = pdf(
            "BT /F1 12 Tf 72 700 Td [(W) 80 (ord) -600 (next)] TJ ET",
            HELVETICA,
        );
        assert_eq!(text(&p), "Word next\n");
    }

    #[test]
    fn the_fonts_to_unicode_map_decides_what_the_codes_are() {
        // Code 0x41 is shown as "Z" by the font's own map.
        let cmap = "/CIDInit /ProcSet findresource begin 12 dict begin begincmap 1 begincodespacerange <00> <FF> endcodespacerange 1 beginbfchar <41> <005A> endbfchar endcmap";
        let font = "<</Type/Font/Subtype/Type1/BaseFont/Helvetica/ToUnicode 6 0 R>>";
        let extra = format!("<</Length {}>>\nstream\n{cmap}\nendstream", cmap.len());
        let p = pdf_objects("BT /F1 12 Tf 72 700 Td (AAB) Tj ET", font, &extra);
        assert_eq!(text(&p), "ZZB\n");
    }

    #[test]
    fn a_flate_stream_is_read_and_a_bomb_is_cut_not_read() {
        use std::io::Write;
        let content = "BT /F1 12 Tf 72 700 Td (compressed text) Tj ET";
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(content.as_bytes()).unwrap();
        let z = z.finish().unwrap();
        // A page, its content stream deflated.
        let mut out = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>endobj\n".to_vec();
        out.extend_from_slice(
            format!(
                "4 0 obj<</Length {}/Filter/FlateDecode>>\nstream\n",
                z.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(&z);
        out.extend_from_slice(
            format!(
                "\nendstream\nendobj\n5 0 obj{HELVETICA}endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
            )
            .as_bytes(),
        );
        assert_eq!(text(&out), "compressed text\n");

        // 64 MiB of spaces in a 64 KiB stream, against a 1 MiB limit.
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        let chunk = vec![b' '; 1 << 20];
        for _ in 0..64 {
            z.write_all(&chunk).unwrap();
        }
        let z = z.finish().unwrap();
        let mut bomb = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 9 9]/Contents 4 0 R>>endobj\n".to_vec();
        bomb.extend_from_slice(
            format!(
                "4 0 obj<</Length {}/Filter/FlateDecode>>\nstream\n",
                z.len()
            )
            .as_bytes(),
        );
        bomb.extend_from_slice(&z);
        bomb.extend_from_slice(b"\nendstream\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF\n");
        let mut limits = Limits::default();
        limits.max_buffer_bytes = 1 << 20;
        let e = extract(Kind::Pdf, &bomb, 1 << 20, &limits);
        assert!(e.truncated, "a stream past the limit is cut");
        assert!(e.text.is_empty());
    }

    #[test]
    fn an_image_that_declares_a_size_hayro_would_allocate_is_not_read() {
        // hayro sizes its buffers by the dictionary: a 100000 by 100000 JBIG2
        // image in a 123 KB file took it 8.9 GB.
        let image = |w: u32, h: u32| {
            let content = "BT /F1 12 Tf 72 700 Td (visible words) Tj ET /Im0 Do";
            format!(
                "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n\
                 3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>/XObject<</Im0 6 0 R>>>>/Contents 4 0 R>>endobj\n\
                 4 0 obj<</Length {}>>\nstream\n{content}\nendstream\nendobj\n\
                 5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>endobj\n\
                 6 0 obj<</Type/XObject/Subtype/Image/Width {w}/Height {h}/ColorSpace/DeviceGray/BitsPerComponent 8/Length 4>>\nstream\nabcd\nendstream\nendobj\n\
                 trailer<</Root 1 0 R>>\n%%EOF\n",
                content.len()
            )
            .into_bytes()
        };
        let big = extract(
            Kind::Pdf,
            &image(100_000, 100_000),
            1 << 20,
            &Limits::default(),
        );
        assert!(big.truncated && big.text.is_empty(), "{big:?}");
        // An ordinary image is no reason to refuse the page.
        let small = extract(Kind::Pdf, &image(640, 480), 1 << 20, &Limits::default());
        assert!(!small.truncated);
        assert_eq!(small.text, "visible words\n");
    }

    /// A PDF whose page content is `stream`, with `filter`.
    fn pdf_with_stream(filter: &str, stream: &[u8]) -> Vec<u8> {
        let mut v = format!(
            "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n\
             3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 9 9]/Contents 4 0 R>>endobj\n\
             4 0 obj<</Length {}/Filter/{filter}>>\nstream\n",
            stream.len()
        )
        .into_bytes();
        v.extend_from_slice(stream);
        v.extend_from_slice(b"\nendstream\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF\n");
        v
    }

    #[test]
    fn image_data_whose_header_declares_a_huge_page_is_not_read() {
        // A JBIG2 page information segment for 100000 by 100000 pixels: the
        // shape of the 123 KB file that took hayro 8.9 GB.
        let mut jbig2 = vec![0, 0, 0, 0, 0x30, 0x00, 0x01, 0, 0, 0, 19];
        jbig2.extend_from_slice(&100_000u32.to_be_bytes());
        jbig2.extend_from_slice(&100_000u32.to_be_bytes());
        jbig2.extend_from_slice(&[0; 11]);
        let bomb = extract(
            Kind::Pdf,
            &pdf_with_stream("JBIG2Decode", &jbig2),
            1 << 20,
            &Limits::default(),
        );
        assert!(bomb.truncated, "{bomb:?}");
        // The same page at a size a scan has.
        let mut small = jbig2.clone();
        small[11..15].copy_from_slice(&2000u32.to_be_bytes());
        small[15..19].copy_from_slice(&3000u32.to_be_bytes());
        let ok = extract(
            Kind::Pdf,
            &pdf_with_stream("JBIG2Decode", &small),
            1 << 20,
            &Limits::default(),
        );
        assert!(!ok.truncated, "{ok:?}");

        // A JPEG of 65535 by 65535, and one of 640 by 480.
        let jpeg = |w: u16, h: u16| {
            let mut j = vec![0xff, 0xd8, 0xff, 0xc0, 0, 17, 8];
            j.extend_from_slice(&h.to_be_bytes());
            j.extend_from_slice(&w.to_be_bytes());
            j.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1, 0xff, 0xd9]);
            j
        };
        assert!(
            extract(
                Kind::Pdf,
                &pdf_with_stream("DCTDecode", &jpeg(65535, 65535)),
                1 << 20,
                &Limits::default()
            )
            .truncated
        );
        assert!(
            !extract(
                Kind::Pdf,
                &pdf_with_stream("DCTDecode", &jpeg(640, 480)),
                1 << 20,
                &Limits::default()
            )
            .truncated
        );

        // A JPEG 2000 codestream whose SIZ says 100000 by 100000.
        let mut jpx = vec![0xff, 0x4f, 0xff, 0x51, 0, 41, 0, 0];
        jpx.extend_from_slice(&100_000u32.to_be_bytes());
        jpx.extend_from_slice(&100_000u32.to_be_bytes());
        jpx.extend_from_slice(&[0; 8]);
        assert!(
            extract(
                Kind::Pdf,
                &pdf_with_stream("JPXDecode", &jpx),
                1 << 20,
                &Limits::default()
            )
            .truncated
        );
        // Image data whose header cannot be read is refused too.
        assert!(
            extract(
                Kind::Pdf,
                &pdf_with_stream("JBIG2Decode", b"nonsense"),
                1 << 20,
                &Limits::default()
            )
            .truncated
        );
    }

    #[test]
    fn what_is_not_a_pdf_has_no_text_and_does_not_panic() {
        for data in [
            &b""[..],
            b"%PDF-",
            b"%PDF-1.4\n1 0 obj<<>>endobj",
            b"%PDF-1.4 garbage \xff\xfe\x00",
        ] {
            let e = extract(Kind::Pdf, data, 1 << 20, &Limits::default());
            assert!(e.text.is_empty());
        }
    }
}
