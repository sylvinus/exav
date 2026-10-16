//! The text of presentations and drawings, taken from the model the readers
//! fill and not from a PPTX written and read back.

use exav_render::slides::{convert, text, Error, Format, Limits};
use std::io::Read;

fn fixture(dir: &str, name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/office/{dir}/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn words(format: Format, dir: &str, name: &str) -> exav_render::formats::office::text::Text {
    text(&fixture(dir, name), format, &Limits::default(), 1 << 20).unwrap()
}

const NS: &str = r#"xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0" xmlns:xlink="http://www.w3.org/1999/xlink""#;

/// A flat presentation holding `pages` (draw:page elements).
fn fodp(pages: &str) -> Vec<u8> {
    format!(
        r#"<office:document {NS} office:mimetype="application/vnd.oasis.opendocument.presentation"><office:body><office:presentation>{pages}</office:presentation></office:body></office:document>"#
    )
    .into_bytes()
}

fn rect(body: &str) -> String {
    format!(
        r#"<draw:rect svg:x="1cm" svg:y="1cm" svg:width="5cm" svg:height="2cm">{body}</draw:rect>"#
    )
}

fn of(doc: &[u8]) -> exav_render::formats::office::text::Text {
    text(doc, Format::Fodp, &Limits::default(), 1 << 20).unwrap()
}

#[test]
fn every_format_gives_the_words_of_its_slides_one_section_to_a_slide() {
    for (name, format) in [
        ("sample.ppt", Format::Ppt),
        ("sample.odp", Format::Odp),
        ("sample.fodp", Format::Fodp),
    ] {
        let t = words(format, "slides", name);
        assert_eq!(
            t.text,
            "Quarterly budget\nRevenue up 12%\nCosts flat\nPlan\nNotes\nSecond slide text\n",
            "{name}"
        );
        let labels: Vec<_> = t.sections.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(labels, ["slide 1", "slide 2"], "{name}");
        assert_eq!(
            &t.text[t.sections[1].range.clone()],
            "Notes\nSecond slide text\n"
        );
        assert!(!t.truncated);
    }
    let key = words(Format::Keynote, "slides", "sample.key");
    assert_eq!(key.text, "Example Presentation\nThis is a subtitle.\n");
}

#[test]
fn a_drawing_gives_its_pages_by_name() {
    for (name, format) in [("sample.odg", Format::Odg), ("sample.fodg", Format::Fodg)] {
        let t = words(format, "draw", name);
        let labels: Vec<_> = t.sections.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(labels, ["slide 1 \"Plan\"", "slide 2 \"Detail\""], "{name}");
        assert!(
            t.text.contains("Red box") && t.text.contains("Detail"),
            "{name}"
        );
        // A shape on a layer that is not displayed is not read.
        assert!(!t.text.contains("Hidden note"), "{name}");
    }
}

#[test]
fn chart_text_is_text() {
    let t = words(Format::Odp, "slides", "chart.odp");
    for w in ["Quarterly sales", "Sales", "Q1", "Q2", "Q3"] {
        assert!(t.text.lines().any(|l| l == w), "{w}");
    }
}

#[test]
fn a_hyperlink_is_its_label_then_its_target() {
    let page = format!(
        r#"<draw:page>{}</draw:page>"#,
        rect(
            r#"<text:p>go <text:a xlink:href="https://evil.test/login">paypal.com</text:a> now</text:p><text:p><text:a xlink:href="https://same.test/">https://same.test/</text:a></text:p>"#
        )
    );
    let t = of(&fodp(&page));
    assert_eq!(
        t.text,
        "go paypal.com (https://evil.test/login) now\nhttps://same.test/\n"
    );
    // Only a link whose label is not its target is a pair.
    assert_eq!(
        t.links,
        [(
            "paypal.com".to_string(),
            "https://evil.test/login".to_string()
        )]
    );
}

#[test]
fn the_slide_number_is_not_text() {
    let page = format!(
        "<draw:page>{}</draw:page>",
        rect("<text:p>Page <text:page-number>7</text:page-number> end</text:p>")
    );
    let t = of(&fodp(&page));
    assert!(
        t.text.contains("Page") && t.text.contains("end"),
        "{}",
        t.text
    );
    // The reader writes the slide's own number (1) as the field's text.
    assert!(!t.text.contains('1') && !t.text.contains('7'), "{}", t.text);
}

#[test]
fn a_table_is_a_line_to_a_row_with_a_tab_between_cells() {
    let page = r#"<draw:page><draw:frame svg:x="0cm" svg:y="0cm" svg:width="8cm" svg:height="3cm"><table:table><table:table-column table:number-columns-repeated="2"/><table:table-row><table:table-cell><text:p>a1</text:p></table:table-cell><table:table-cell><text:p>b1</text:p></table:table-cell></table:table-row><table:table-row><table:table-cell><text:p>a2</text:p></table:table-cell><table:table-cell><text:p>b2</text:p></table:table-cell></table:table-row></table:table></draw:frame></draw:page>"#;
    let t = of(&fodp(page));
    assert_eq!(t.text, "a1\tb1\na2\tb2\n");
}

#[test]
fn a_hidden_slide_is_read_and_says_it_is_hidden() {
    let pages = format!(
        r#"<draw:page presentation:visibility="hidden">{}</draw:page><draw:page>{}</draw:page>"#,
        rect("<text:p>secret</text:p>"),
        rect("<text:p>shown</text:p>")
    );
    let t = of(&fodp(&pages));
    let labels: Vec<_> = t.sections.iter().map(|s| s.label.as_str()).collect();
    assert_eq!(labels, ["hidden slide 1", "slide 2"]);
    assert_eq!(t.text, "secret\nshown\n");
}

#[test]
fn text_a_master_draws_on_every_slide_is_read_apart_from_the_placeholders() {
    let doc = format!(
        r#"<office:document {NS} office:mimetype="application/vnd.oasis.opendocument.presentation"><office:master-styles><style:master-page style:name="M" style:display-name="Corporate">{}{}</style:master-page></office:master-styles><office:body><office:presentation><draw:page draw:master-page-name="M">{}</draw:page></office:presentation></office:body></office:document>"#,
        r#"<draw:rect svg:x="0cm" svg:y="0cm" svg:width="4cm" svg:height="1cm"><text:p>Confidential notice</text:p></draw:rect>"#,
        r#"<draw:frame presentation:class="title" svg:x="0cm" svg:y="0cm" svg:width="4cm" svg:height="1cm"><draw:text-box><text:p>Click to edit the title</text:p></draw:text-box></draw:frame>"#,
        rect("<text:p>slide words</text:p>")
    );
    let t = of(doc.as_bytes());
    let labels: Vec<_> = t.sections.iter().map(|s| s.label.as_str()).collect();
    assert_eq!(labels, ["slide 1", "master \"Corporate\""]);
    assert!(t.text.contains("Confidential notice"));
    assert!(!t.text.contains("Click to edit"));
}

#[test]
fn the_cap_cuts_the_text_and_says_so() {
    let pages = format!(
        "<draw:page>{}</draw:page>",
        rect("<text:p>aaaaaaaaaa</text:p><text:p>bbbbbbbbbb</text:p>")
    );
    let t = text(&fodp(&pages), Format::Fodp, &Limits::default(), 15).unwrap();
    assert!(t.truncated);
    assert!(t.text.len() <= 15);
    assert!(t.text.starts_with("slide") || t.text.starts_with('a'));
}

#[test]
fn it_refuses_what_the_converter_refuses() {
    // Not that format.
    assert!(matches!(
        text(
            &fixture("slides", "sample.ppt"),
            Format::Odp,
            &Limits::default(),
            1 << 20
        ),
        Err(Error::NotFormat(_))
    ));
    // Damaged: an error, no panic.
    let mut damaged = fixture("slides", "sample.ppt");
    for b in damaged.iter_mut().skip(512).take(4096) {
        *b = 0xFF;
    }
    assert!(text(&damaged, Format::Ppt, &Limits::default(), 1 << 20).is_err());
    // Past a limit.
    let mut small = Limits::default();
    small.max_input = 100;
    assert!(matches!(
        text(
            &fixture("slides", "sample.ppt"),
            Format::Ppt,
            &small,
            1 << 20
        ),
        Err(Error::TooLarge(_))
    ));
}

/// The words of the PPTX the converter writes for a fixture, in order.
fn pptx_words(pptx: &[u8]) -> Vec<String> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(pptx)).unwrap();
    let mut names: Vec<String> = z
        .file_names()
        .filter_map(|n| n.ok().map(|n| n.to_string()))
        .filter(|n| n.starts_with("ppt/slides/slide") && n.ends_with(".xml"))
        .collect();
    names.sort_by_key(|n| {
        n.trim_start_matches("ppt/slides/slide")
            .trim_end_matches(".xml")
            .parse::<u32>()
            .unwrap_or(0)
    });
    let mut out = vec![];
    for n in names {
        let mut xml = String::new();
        z.by_name(&n).unwrap().read_to_string(&mut xml).unwrap();
        let mut rest = xml.as_str();
        while let Some(i) = rest.find("<a:t>") {
            let from = i + 5;
            let j = rest[from..].find("</a:t>").unwrap();
            out.push(rest[from..from + j].to_string());
            rest = &rest[from + j..];
        }
    }
    out
}

#[test]
fn the_words_are_those_of_the_pptx_the_converter_writes() {
    for (dir, name, format) in [
        ("slides", "sample.ppt", Format::Ppt),
        ("slides", "sample.odp", Format::Odp),
        ("slides", "sample.key", Format::Keynote),
        ("draw", "sample.odg", Format::Odg),
    ] {
        let bytes = fixture(dir, name);
        let c = convert(&bytes, format, &Limits::default()).unwrap();
        let t = text(&bytes, format, &Limits::default(), 1 << 20).unwrap();
        let mine: Vec<&str> = t.text.split_whitespace().collect();
        let theirs: Vec<String> = pptx_words(&c.pptx)
            .iter()
            .flat_map(|w| w.split_whitespace().map(String::from).collect::<Vec<_>>())
            .collect();
        for w in &theirs {
            assert!(mine.contains(&w.as_str()), "{name}: {w} missing");
        }
    }
}
