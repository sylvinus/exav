//! The text of every format, taken from what its reader makes: the fixtures,
//! and short documents with one of each thing a reader sees (a table, a
//! header, a footnote, a comment, links, hidden text).

#[path = "office_common/mod.rs"]
mod common;

use common::*;
use exav_render::docs::{Error, Format, Limits, convert, text};
use exav_render::formats::office::test_util::{PackageWriter, W, Zip, build_cfb, literal_block};
use exav_render::formats::office::text::Text;

const CAP: usize = 1 << 20;

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/office/docs/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn extract(input: &[u8], f: Format) -> Text {
    text(input, f, &Limits::default(), CAP).unwrap_or_else(|e| panic!("{f:?}: {e}"))
}

/// The text of the section called `label`.
fn section<'a>(t: &'a Text, label: &str) -> &'a str {
    let s = t
        .sections
        .iter()
        .find(|s| s.label == label)
        .unwrap_or_else(|| panic!("no section {label} in {:?}", t.sections));
    &t.text[s.range.clone()]
}

/// The labels of the sections, in order.
fn labels(t: &Text) -> Vec<&str> {
    t.sections.iter().map(|s| s.label.as_str()).collect()
}

// ---- the words of a DOCX, to compare with ----

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let end = rest.find(';').expect("an entity ends");
        let e = &rest[1..end];
        match e {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                let n = match e.strip_prefix("#x") {
                    Some(h) => u32::from_str_radix(h, 16),
                    None => e.trim_start_matches('#').parse(),
                };
                out.push(char::from_u32(n.expect("a character reference")).expect("a character"));
            }
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

/// The `w:t` text of a part: runs, but not hidden ones, not field
/// instructions and not the result of a page number field. A tab or a break
/// is a space, a paragraph and a cell end with one.
fn docx_text(xml: &str) -> String {
    struct Field {
        instr: String,
        result: bool,
        skip: bool,
    }
    let mut out = String::new();
    // The runs open, with whether each is hidden: a text box holds runs
    // inside a run.
    let mut runs: Vec<(String, bool)> = vec![];
    let mut fields: Vec<Field> = vec![];
    let mut rest = xml;
    while let Some(lt) = rest.find('<') {
        rest = &rest[lt + 1..];
        let gt = rest.find('>').expect("a tag ends");
        let tag = &rest[..gt];
        rest = &rest[gt + 1..];
        let closing = tag.starts_with('/');
        let name = tag
            .trim_start_matches('/')
            .split(|c: char| c.is_whitespace() || c == '/')
            .next()
            .unwrap_or("");
        match (name, closing) {
            ("w:r", false) => runs.push((String::new(), false)),
            ("w:r", true) => {
                let (run, hidden) = runs.pop().expect("a run is open");
                if !hidden {
                    out.push_str(&run);
                }
            }
            ("w:vanish", false) => {
                if let Some(r) = runs.last_mut() {
                    r.1 = !tag.contains("w:val=\"0\"");
                }
            }
            ("w:t", false) if !tag.ends_with('/') => {
                let end = rest.find("</w:t>").expect("w:t ends");
                // Not an instruction's, nor a page number's.
                if fields.iter().all(|f| f.result && !f.skip)
                    && let Some(r) = runs.last_mut()
                {
                    r.0.push_str(&unescape(&rest[..end]));
                }
                rest = &rest[end..];
            }
            ("w:instrText", false) => {
                let end = rest.find("</w:instrText>").expect("w:instrText ends");
                if let Some(f) = fields.last_mut() {
                    f.instr.push_str(&unescape(&rest[..end]));
                }
                rest = &rest[end..];
            }
            ("w:fldChar", false) => {
                if tag.contains("\"begin\"") {
                    fields.push(Field {
                        instr: String::new(),
                        result: false,
                        skip: false,
                    });
                } else if tag.contains("\"separate\"") {
                    if let Some(f) = fields.last_mut() {
                        f.result = true;
                        let word = f.instr.split_whitespace().next().unwrap_or("");
                        f.skip = word.eq_ignore_ascii_case("PAGE")
                            || word.eq_ignore_ascii_case("NUMPAGES");
                    }
                } else {
                    fields.pop();
                }
            }
            ("w:tab" | "w:br" | "w:cr", false) => {
                if let Some(r) = runs.last_mut() {
                    r.0.push(' ');
                }
            }
            ("w:noBreakHyphen", false) => {
                if let Some(r) = runs.last_mut() {
                    r.0.push('-');
                }
            }
            ("w:p" | "w:tc", true) => out.push(' '),
            _ => {}
        }
    }
    out
}

/// The words of every text part of a DOCX, sorted.
fn docx_words(docx: &[u8]) -> Vec<String> {
    let names = Zip::open(docx).expect("a ZIP package").names();
    let mut all = String::new();
    for n in names {
        let text_part = [
            "document",
            "header",
            "footer",
            "footnotes",
            "endnotes",
            "comments",
        ]
        .iter()
        .any(|p| n.starts_with(&format!("word/{p}")) && n.ends_with(".xml"));
        if text_part {
            all.push(' ');
            all.push_str(&docx_text(&part(docx, &n)));
        }
    }
    let mut w: Vec<String> = all.split_whitespace().map(str::to_string).collect();
    w.sort();
    w
}

/// The words of a text, sorted, without the targets written after links.
fn text_words(t: &Text) -> Vec<String> {
    let mut s = t.text.clone();
    for (_, target) in &t.links {
        s = s.replace(&format!(" ({target})"), "");
    }
    let mut w: Vec<String> = s.split_whitespace().map(str::to_string).collect();
    w.sort();
    w
}

/// The text and the DOCX the converter writes have the same words.
fn same_words_as_the_converter(name: &str, input: &[u8], f: Format) {
    let t = extract(input, f);
    let c = convert(input, f, &Limits::default()).unwrap_or_else(|e| panic!("{name}: {e}"));
    let (a, b) = (text_words(&t), docx_words(&c.docx));
    assert!(!a.is_empty(), "{name}: no words");
    assert_eq!(a, b, "{name}");
}

// ---- documents of each format with the same things in them ----

const ODF_NS: &str = r#"xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:dc="http://purl.org/dc/elements/1.1/""#;

const ODF_AUTOMATIC: &str = r#"<office:automatic-styles>
<style:page-layout style:name="L1"><style:page-layout-properties fo:page-width="21cm" fo:page-height="29.7cm"/></style:page-layout>
<style:style style:name="Hid" style:family="text"><style:text-properties text:display="none"/></style:style>
<style:style style:name="Strike" style:family="text"><style:text-properties style:text-line-through-style="solid"/></style:style>
</office:automatic-styles>"#;

const ODF_MASTER: &str = r#"<office:master-styles><style:master-page style:name="Standard" style:page-layout-name="L1"><style:header><text:p>HEADTEXT</text:p></style:header><style:footer><text:p>FOOTTEXT</text:p></style:footer></style:master-page></office:master-styles>"#;

const ODF_BODY: &str = r#"<text:p>Alpha beta gamma</text:p>
<text:p>Visit <text:a xlink:href="https://example.org/x">the site</text:a> today <text:a xlink:href="https://example.org/">https://example.org/</text:a></text:p>
<text:p>before <text:span text:style-name="Hid">SECRET</text:span>after</text:p>
<text:p><text:span text:style-name="Strike">struck</text:span> kept</text:p>
<text:p>Page <text:page-number>7</text:page-number></text:p>
<text:p>note<text:note text:note-class="footnote"><text:note-citation>1</text:note-citation><text:note-body><text:p>NOTETEXT</text:p></text:note-body></text:note></text:p>
<text:p>end<text:note text:note-class="endnote"><text:note-citation>i</text:note-citation><text:note-body><text:p>ENDTEXT</text:p></text:note-body></text:note></text:p>
<text:p>word<office:annotation><dc:creator>Ann Lee</dc:creator><text:p>COMMENTTEXT</text:p></office:annotation></text:p>
<table:table><table:table-column table:number-columns-repeated="2"/>
<table:table-row><table:table-cell><text:p>r1c1</text:p></table:table-cell><table:table-cell><text:p>r1c2</text:p></table:table-cell></table:table-row>
<table:table-row><table:table-cell><text:p>r2c1</text:p></table:table-cell><table:table-cell><text:p>r2c2</text:p></table:table-cell></table:table-row>
</table:table>
<text:p>Boxed <draw:frame text:anchor-type="as-char" svg:width="2cm" svg:height="1cm"><draw:text-box><text:p>BOXTEXT</text:p></draw:text-box></draw:frame> text</text:p>
<text:p>Last</text:p>"#;

fn fodt() -> Vec<u8> {
    format!(
        r#"<?xml version="1.0"?><office:document {ODF_NS} office:mimetype="application/vnd.oasis.opendocument.text">{ODF_AUTOMATIC}{ODF_MASTER}<office:body><office:text>{ODF_BODY}</office:text></office:body></office:document>"#
    )
    .into_bytes()
}

fn odt_with(content: &str, styles: &str, manifest: Option<&str>) -> Vec<u8> {
    let mut z = PackageWriter::new(1 << 22);
    z.put(
        "mimetype",
        b"application/vnd.oasis.opendocument.text",
        false,
    )
    .unwrap();
    z.put("content.xml", content.as_bytes(), true).unwrap();
    z.put("styles.xml", styles.as_bytes(), true).unwrap();
    if let Some(m) = manifest {
        z.put("META-INF/manifest.xml", m.as_bytes(), true).unwrap();
    }
    z.finish().unwrap()
}

fn odt() -> Vec<u8> {
    odt_with(
        &format!(
            r#"<?xml version="1.0"?><office:document-content {ODF_NS}>{ODF_AUTOMATIC}<office:body><office:text>{ODF_BODY}</office:text></office:body></office:document-content>"#
        ),
        &format!(
            r#"<?xml version="1.0"?><office:document-styles {ODF_NS}>{ODF_AUTOMATIC}{ODF_MASTER}</office:document-styles>"#
        ),
        None,
    )
}

fn rtf() -> Vec<u8> {
    br#"{\rtf1\ansi\deff0{\fonttbl{\f0 Arial;}}
{\header\pard HEADTEXT\par}{\footer\pard FOOTTEXT\par}
\pard Alpha beta gamma\par
Visit {\field{\*\fldinst HYPERLINK "https://example.org/x"}{\fldrslt the site}} today {\field{\*\fldinst HYPERLINK "https://example.org/"}{\fldrslt https://example.org/}}\par
before {\v SECRET}after\par
{\strike struck} kept\par
Page {\field{\*\fldinst PAGE}{\fldrslt 7}}\par
note{\super\chftn{\footnote\pard\plain\chftn  NOTETEXT}}\par
\trowd\trgaph108\cellx2000\cellx4000
\pard\intbl r1c1\cell r1c2\cell\row
\trowd\trgaph108\cellx2000\cellx4000
\pard\intbl r2c1\cell r2c2\cell\row
\pard Last\par}
"#
    .to_vec()
}

const WML_NS: &str = r#"xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml" xmlns:wx="http://schemas.microsoft.com/office/word/2003/auxHint" xmlns:aml="http://schemas.microsoft.com/aml/2001/core" xmlns:v="urn:schemas-microsoft-com:vml""#;

fn wml() -> Vec<u8> {
    format!(
        r#"<?xml version="1.0"?><w:wordDocument {WML_NS}><w:body><wx:sect><wx:sub-section>
<w:p><w:r><w:t>Alpha beta gamma</w:t></w:r></w:p>
<w:p><w:r><w:t>Visit </w:t></w:r><w:hlink w:dest="https://example.org/x"><w:r><w:t>the site</w:t></w:r></w:hlink><w:r><w:t> today </w:t></w:r><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText> HYPERLINK "https://example.org/" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>https://example.org/</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>
<w:p><w:r><w:t>before </w:t></w:r><w:r><w:rPr><w:vanish/></w:rPr><w:t>SECRET</w:t></w:r><w:r><w:t>after</w:t></w:r></w:p>
<w:p><w:r><w:rPr><w:strike/></w:rPr><w:t>struck</w:t></w:r><w:r><w:t> kept</w:t></w:r></w:p>
<w:p><w:r><w:t>Page </w:t></w:r><w:fldSimple w:instr=" PAGE "><w:r><w:t>7</w:t></w:r></w:fldSimple></w:p>
<w:p><w:r><w:t>note</w:t></w:r><w:r><w:footnote><w:p><w:r><w:footnoteRef/><w:t> NOTETEXT</w:t></w:r></w:p></w:footnote></w:r></w:p>
<w:p><w:r><w:t>word</w:t></w:r><aml:annotation aml:id="0" w:type="Word.Comment" aml:author="Ann Lee"><aml:content><w:p><w:r><w:t>COMMENTTEXT</w:t></w:r></w:p></aml:content></aml:annotation></w:p>
<w:tbl><w:tblGrid><w:gridCol w:w="2000"/><w:gridCol w:w="2000"/></w:tblGrid>
<w:tr><w:tc><w:p><w:r><w:t>r1c1</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>r1c2</w:t></w:r></w:p></w:tc></w:tr>
<w:tr><w:tc><w:p><w:r><w:t>r2c1</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>r2c2</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
<w:p><w:r><w:t>Last</w:t></w:r></w:p>
<w:sectPr><w:hdr w:type="odd"><w:p><w:r><w:t>HEADTEXT</w:t></w:r></w:p></w:hdr><w:ftr w:type="odd"><w:p><w:r><w:t>FOOTTEXT</w:t></w:r></w:p></w:ftr></w:sectPr>
</wx:sub-section></wx:sect></w:body></w:wordDocument>"#
    )
    .into_bytes()
}

fn para(t: &str, runs: Vec<(usize, usize, Vec<u8>)>, grpprl: Vec<u8>) -> Para {
    Para {
        text: t.as_bytes().to_vec(),
        runs,
        grpprl,
    }
}

/// A Word 97 document with the same things in it, as the file a writer would
/// make.
fn doc97() -> Vec<u8> {
    let spec = vec![0x55, 0x08, 1];
    let cell = vec![0x16, 0x24, 1];
    let mut row = vec![0x16, 0x24, 1, 0x17, 0x24, 1];
    // sprmTDefTable: two cells, edges 0, 2000, 4000, then a TC80 each.
    let mut v = vec![2u8];
    for e in [0i16, 2000, 4000] {
        v.extend(e.to_le_bytes());
    }
    v.extend([0u8; 40]);
    row.extend([0x08, 0xD6]);
    row.extend((v.len() as u16 + 1).to_le_bytes());
    row.extend(v);
    let paras = vec![
        para("Alpha beta gamma\r", vec![], vec![]),
        para(
            "Visit \x13 HYPERLINK \"https://example.org/x\" \x14the site\x15 today \x13 HYPERLINK \"https://example.org/\" \x14https://example.org/\x15\r",
            vec![],
            vec![],
        ),
        // sprmCFVanish on "SECRET".
        para(
            "before SECRETafter\r",
            vec![(7, 13, vec![0x3C, 0x08, 1])],
            vec![],
        ),
        // sprmCFStrike on "struck".
        para("struck kept\r", vec![(0, 6, vec![0x37, 0x08, 1])], vec![]),
        para("Page \x13 PAGE \x147\x15\r", vec![], vec![]),
        para("note\x02\r", vec![(4, 5, spec.clone())], vec![]),
        para("word\x05\r", vec![(4, 5, spec)], vec![]),
        para("r1c1\x07", vec![], cell.clone()),
        para("r1c2\x07", vec![], cell.clone()),
        para("\x07", vec![], row.clone()),
        para("r2c1\x07", vec![], cell.clone()),
        para("r2c2\x07", vec![], cell),
        para("\x07", vec![], row),
        para("Last\r", vec![], vec![]),
    ];
    let mark_at = |mark: u8| {
        let mut cp = 0u32;
        for p in &paras {
            if let Some(i) = p.text.iter().position(|c| *c == mark) {
                return cp + i as u32;
            }
            cp += p.text.len() as u32;
        }
        panic!("no mark");
    };
    let head = b"HEADTEXT\r\r".to_vec();
    let foot = b"FOOTTEXT\r\r".to_vec();
    let (h, f) = (head.len() as u32, foot.len() as u32);
    doc(
        &paras,
        &Options {
            // The default header of the first section is the story 7, the
            // default footer the story 9.
            hdd: [vec![0; 8], vec![h, h, h + f, h + f, h + f, h + f]].concat(),
            header: [head, foot].concat(),
            footnotes: vec![b"\x02 NOTETEXT\r".to_vec()],
            footnote_refs: vec![mark_at(2)],
            comments: vec![b"COMMENTTEXT\r".to_vec()],
            comment_refs: vec![mark_at(5)],
            ..Options::default()
        },
    )
}

fn six(p: &[Para], header: Option<&[u8]>) -> Vec<u8> {
    doc6(
        p,
        &Six {
            header: header.map(<[u8]>::to_vec),
            ..Six::default()
        },
    )
}

/// A Word 6 document: words, a tab, a break, hidden and struck text, a header.
fn doc6_sample() -> Vec<u8> {
    six(
        &[
            para("Plain bold words\r", vec![(6, 10, vec![85, 1])], vec![]),
            para("Second\ttab and\x0Bbreak\r", vec![], vec![]),
            // sprmCFVanish, sprmCFStrike.
            para(
                "before SECRETafter\rstruck kept\r",
                vec![(7, 13, vec![92, 1]), (19, 25, vec![87, 1])],
                vec![],
            ),
        ],
        Some(b"HEADTEXT\r\r"),
    )
}

fn table(entries: &[(u64, Option<u64>)]) -> W {
    let mut t = W::default();
    for (i, o) in entries {
        let mut e = W::default().uint(1, *i);
        if let Some(o) = o {
            e = e.reference(2, *o);
        }
        t = t.msg(1, e);
    }
    t
}

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

/// A Pages document of the paragraphs `body` (joined by line feeds).
fn pages_of(body: &str) -> Vec<u8> {
    let storage = W::default()
        .bytes(3, body.as_bytes())
        .msg(5, table(&[(0, Some(3))]))
        .msg(8, table(&[(0, Some(4))]));
    let objects = [
        (1, 10000, W::default().reference(4, 2)),
        (2, 2001, storage),
        (3, 2022, W::default().msg(11, W::default().float(3, 12.0))),
        (4, 2021, W::default().msg(11, W::default())),
    ];
    let mut z = PackageWriter::new(1 << 20);
    z.put("Index/Document.iwa", &iwa(&objects), true).unwrap();
    z.finish().unwrap()
}

fn every_document() -> Vec<(&'static str, Vec<u8>, Format)> {
    vec![
        ("sample.doc", fixture("sample.doc"), Format::Doc),
        ("sample.odt", fixture("sample.odt"), Format::Odt),
        ("sample.fodt", fixture("sample.fodt"), Format::Fodt),
        ("sample.rtf", fixture("sample.rtf"), Format::Rtf),
        (
            "sample-2003.xml",
            fixture("sample-2003.xml"),
            Format::Wml2003,
        ),
        ("doc97", doc97(), Format::Doc),
        ("doc6", doc6_sample(), Format::Doc),
        ("fodt", fodt(), Format::Fodt),
        ("odt", odt(), Format::Odt),
        ("rtf", rtf(), Format::Rtf),
        ("wml", wml(), Format::Wml2003),
        (
            "pages",
            pages_of("Title\nBody words here\nA third paragraph"),
            Format::Pages,
        ),
    ]
}

/// The text is `body`, then the sections, each with its label and text.
fn assert_text(t: &Text, body: &str, sections: &[(&str, &str)]) {
    let all: String = std::iter::once(body)
        .chain(sections.iter().map(|s| s.1))
        .collect();
    assert_eq!(t.text, all);
    assert_eq!(labels(t), sections.iter().map(|s| s.0).collect::<Vec<_>>());
    for (label, s) in sections {
        assert_eq!(section(t, label), *s);
    }
    assert_eq!(
        body.len(),
        t.text.len() - sections.iter().map(|s| s.1.len()).sum::<usize>()
    );
    assert!(!t.truncated);
}

/// The link whose label is not its target; the other one, whose label is its
/// target, is written once and has no pair.
fn assert_links(t: &Text) {
    assert_eq!(
        t.links,
        [("the site".to_string(), "https://example.org/x".to_string())]
    );
}

const START: &str = "Alpha beta gamma\nVisit the site (https://example.org/x) today https://example.org/\nbefore after\nstruck kept\nPage\nnote\n";

const TABLE: &str = "r1c1\tr1c2\nr2c1\tr2c2\n";

#[test]
fn the_fixtures_have_their_words() {
    let plain = "Quarterly summary\nRevenue grew by twelve percent over the quarter, while costs stayed flat.\nFirst item\nSecond item\nRegion\tSales\nNorth\t120\nEnd of the summary.\n";
    for (name, f) in [
        ("sample.doc", Format::Doc),
        ("sample.odt", Format::Odt),
        ("sample.fodt", Format::Fodt),
    ] {
        let t = extract(&fixture(name), f);
        assert_text(&t, plain, &[]);
        assert!(t.links.is_empty(), "{name}");
    }
    // The RTF fixture writes its bullets as text.
    let t = extract(&fixture("sample.rtf"), Format::Rtf);
    assert_text(
        &t,
        &plain
            .replace("First", "\u{2022}\tFirst")
            .replace("Second", "\u{2022}\tSecond"),
        &[],
    );
    // A link whose label is not its target.
    let t = extract(&fixture("sample-2003.xml"), Format::Wml2003);
    assert_text(
        &t,
        "Title\nblue italic link (https://example.org/)\nc1\tc2\n",
        &[],
    );
    assert_eq!(
        t.links,
        [("link".to_string(), "https://example.org/".to_string())]
    );
}

#[test]
fn every_document_has_the_words_of_the_docx_the_converter_writes() {
    for (name, input, f) in every_document() {
        same_words_as_the_converter(name, &input, f);
    }
}

#[test]
fn a_word_97_document_has_everything_a_reader_sees() {
    let t = extract(&doc97(), Format::Doc);
    assert_text(
        &t,
        &format!("{START}word\n{TABLE}Last\n"),
        &[
            ("headers and footers", "HEADTEXT\nFOOTTEXT\n"),
            ("footnotes", "NOTETEXT\n"),
            ("comments", "COMMENTTEXT\n"),
        ],
    );
    assert_links(&t);
}

#[test]
fn a_word_6_document_has_its_words_and_its_header() {
    let t = extract(&doc6_sample(), Format::Doc);
    assert_text(
        &t,
        "Plain bold words\nSecond\ttab and\nbreak\nbefore after\nstruck kept\n",
        &[("headers and footers", "HEADTEXT\n")],
    );
}

#[test]
fn tracked_changes_are_text() {
    let p = Para {
        text: b"gone new kept\r".to_vec(),
        // sprmCFRMarkDel on "gone", sprmCFRMark (inserted) on "new".
        runs: vec![(0, 4, vec![0x00, 0x08, 1]), (5, 8, vec![0x01, 0x08, 1])],
        grpprl: vec![],
    };
    let t = extract(&doc(&[p], &Options::default()), Format::Doc);
    assert_text(&t, "gone new kept\n", &[]);
}

#[test]
fn an_open_document_text_has_everything_a_reader_sees() {
    let all = |t: &Text| {
        assert_text(
            t,
            &format!("{START}end\nword\n{TABLE}Boxed text\nBOXTEXT\nLast\n"),
            &[
                ("headers and footers", "HEADTEXT\nFOOTTEXT\n"),
                ("footnotes", "NOTETEXT\n"),
                ("endnotes", "ENDTEXT\n"),
                ("comments", "COMMENTTEXT\n"),
            ],
        );
        assert_links(t);
    };
    all(&extract(&fodt(), Format::Fodt));
    all(&extract(&odt(), Format::Odt));
}

#[test]
fn an_rtf_has_everything_a_reader_sees_but_comments() {
    let t = extract(&rtf(), Format::Rtf);
    assert_text(
        &t,
        &format!("{START}{TABLE}Last\n"),
        &[
            ("headers and footers", "HEADTEXT\nFOOTTEXT\n"),
            ("footnotes", "NOTETEXT\n"),
        ],
    );
    assert_links(&t);
}

/// A `}` too many closes the document's group; what follows is still the
/// document (html2rtf writes such files, and unrtf reads them whole).
#[test]
fn an_rtf_with_a_brace_too_many_goes_on() {
    let t = extract(
        br"{\rtf1\ansi{\b First}\par}} Second\par Third\par}",
        Format::Rtf,
    );
    let words: Vec<&str> = t.text.split_whitespace().collect();
    assert_eq!(words, ["First", "Second", "Third"], "{:?}", t.text);
}

/// A note in a list four levels deep is still a note (a bibliography's
/// endnote in a nested bullet list lost its text), and notes in notes stop
/// after a few levels.
#[test]
fn a_note_in_a_deeply_nested_list_keeps_its_text() {
    let note = |body: &str| {
        format!(
            r#"<text:note text:note-class="endnote"><text:note-citation>1</text:note-citation><text:note-body>{body}</text:note-body></text:note>"#
        )
    };
    let mut body = format!("<text:p>item{}</text:p>", note("<text:p>NOTETEXT</text:p>"));
    for _ in 0..4 {
        body = format!("<text:list><text:list-item>{body}</text:list-item></text:list>");
    }
    let fodt = format!(
        r#"<?xml version="1.0"?><office:document {ODF_NS} office:mimetype="application/vnd.oasis.opendocument.text"><office:body><office:text>{body}</office:text></office:body></office:document>"#
    );
    let t = extract(fodt.as_bytes(), Format::Fodt);
    assert_eq!(section(&t, "endnotes"), "NOTETEXT\n");

    // Notes inside notes: the first levels are read, a long chain is cut.
    let mut chain = "<text:p>LEAF</text:p>".to_string();
    for level in (1..=6).rev() {
        chain = format!("<text:p>L{level}{}</text:p>", note(&chain));
    }
    let fodt = format!(
        r#"<?xml version="1.0"?><office:document {ODF_NS} office:mimetype="application/vnd.oasis.opendocument.text"><office:body><office:text>{chain}</office:text></office:body></office:document>"#
    );
    let t = extract(fodt.as_bytes(), Format::Fodt);
    let notes = section(&t, "endnotes");
    assert!(notes.contains("L2") && !notes.contains("LEAF"), "{notes:?}");
}

#[test]
fn a_word_2003_xml_has_everything_a_reader_sees() {
    let t = extract(&wml(), Format::Wml2003);
    assert_text(
        &t,
        &format!("{START}word\n{TABLE}Last\n"),
        &[
            ("headers and footers", "HEADTEXT\nFOOTTEXT\n"),
            ("footnotes", "NOTETEXT\n"),
            ("comments", "COMMENTTEXT\n"),
        ],
    );
    assert_links(&t);
}

#[test]
fn a_header_the_sections_share_is_read_once() {
    let sect = |footer: &str| {
        format!(
            r#"<w:sectPr><w:hdr w:type="odd"><w:p><w:r><w:t>SAME</w:t></w:r></w:p></w:hdr><w:ftr w:type="odd"><w:p><w:r><w:t>{footer}</w:t></w:r></w:p></w:ftr></w:sectPr>"#
        )
    };
    let x = format!(
        r#"<?xml version="1.0"?><w:wordDocument {WML_NS}><w:body><wx:sect><wx:sub-section><w:p><w:r><w:t>one</w:t></w:r></w:p>{}</wx:sub-section><wx:sub-section><w:p><w:r><w:t>two</w:t></w:r></w:p>{}</wx:sub-section></wx:sect></w:body></w:wordDocument>"#,
        sect("F1"),
        sect("F2")
    );
    let t = extract(x.as_bytes(), Format::Wml2003);
    assert_text(
        &t,
        "one\ntwo\n",
        &[("headers and footers", "SAME\nF1\nF2\n")],
    );
    // The converter writes a header part for each of the two sections.
    let c = convert(x.as_bytes(), Format::Wml2003, &Limits::default()).unwrap();
    assert_eq!(
        docx_words(&c.docx).iter().filter(|w| *w == "SAME").count(),
        2
    );
}

#[test]
fn word_2003_xml_fields_make_links_and_page_numbers_are_left_out() {
    let x = format!(
        r#"<?xml version="1.0"?><w:wordDocument {WML_NS}><w:body>
<w:p><w:fldSimple w:instr=" HYPERLINK &quot;https://example.org/simple&quot; "><w:r><w:t>simple link</w:t></w:r></w:fldSimple><w:r><w:t> and </w:t></w:r><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText> HYPERLINK "https://example.org/complex" \o "tip" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>complex link</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>
<w:p><w:r><w:t>page </w:t></w:r><w:fldSimple w:instr=" PAGE \* MERGEFORMAT "><w:r><w:t>3</w:t></w:r></w:fldSimple><w:r><w:t> of </w:t></w:r><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText> NUMPAGES </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>9</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r><w:r><w:t> date </w:t></w:r><w:fldSimple w:instr=" DATE "><w:r><w:t>today</w:t></w:r></w:fldSimple></w:p>
</w:body></w:wordDocument>"#
    );
    let t = extract(x.as_bytes(), Format::Wml2003);
    assert_text(
        &t,
        "simple link (https://example.org/simple) and complex link (https://example.org/complex)\npage  of  date today\n",
        &[],
    );
    assert_eq!(
        t.links,
        [
            (
                "simple link".to_string(),
                "https://example.org/simple".to_string()
            ),
            (
                "complex link".to_string(),
                "https://example.org/complex".to_string()
            )
        ]
    );
    same_words_as_the_converter("fields", x.as_bytes(), Format::Wml2003);
}

#[test]
fn a_pages_document_has_its_paragraphs() {
    let t = extract(&pages_of("Title\nBody words here"), Format::Pages);
    assert_text(&t, "Title\nBody words here\n", &[]);
}

#[test]
fn hidden_text_is_left_out_of_every_format_and_struck_text_is_not() {
    for (name, input, f) in every_document() {
        let t = extract(&input, f);
        assert!(!t.text.contains("SECRET"), "{name}");
        assert!(
            !t.text.contains("PAGE") && !t.text.contains("HYPERLINK"),
            "{name}: a field instruction"
        );
        if ["doc97", "fodt", "odt", "rtf", "wml"].contains(&name) {
            assert!(t.text.contains("struck kept"), "{name}");
            assert!(t.text.contains("before after"), "{name}");
            // The page number field is left out, its label is not.
            assert!(!t.text.contains('7') && t.text.contains("Page\n"), "{name}");
        }
    }
}

#[test]
fn a_style_can_hide_a_paragraph() {
    let styles = r#"<office:automatic-styles><style:style style:name="HidP" style:family="paragraph"><style:text-properties text:display="none"/></style:style><style:style style:name="HidC" style:family="text"><style:text-properties text:display="none"/></style:style></office:automatic-styles>"#;
    let body = r#"<text:p>one</text:p><text:p text:style-name="HidP">HIDDENPARA</text:p><text:p>two <text:span text:style-name="HidC">HIDDENSPAN</text:span>three</text:p>"#;
    let flat = format!(
        r#"<office:document {ODF_NS}>{styles}<office:body><office:text>{body}</office:text></office:body></office:document>"#
    );
    let t = extract(flat.as_bytes(), Format::Fodt);
    assert_text(&t, "one\ntwo three\n", &[]);
    // And through a style of a Word 2003 XML document.
    let x = format!(
        r#"<?xml version="1.0"?><w:wordDocument {WML_NS}><w:styles><w:style w:type="paragraph" w:styleId="Hid"><w:name w:val="Hid"/><w:rPr><w:vanish/></w:rPr></w:style><w:style w:type="character" w:styleId="HidC"><w:name w:val="HidC"/><w:rPr><w:vanish/></w:rPr></w:style></w:styles><w:body><w:p><w:r><w:t>one</w:t></w:r></w:p><w:p><w:pPr><w:pStyle w:val="Hid"/></w:pPr><w:r><w:t>HIDDENPARA</w:t></w:r></w:p><w:p><w:r><w:t>two </w:t></w:r><w:r><w:rPr><w:rStyle w:val="HidC"/></w:rPr><w:t>HIDDENSPAN</w:t></w:r><w:r><w:t>three</w:t></w:r></w:p></w:body></w:wordDocument>"#
    );
    let t = extract(x.as_bytes(), Format::Wml2003);
    assert_text(&t, "one\ntwo three\n", &[]);
}

#[test]
fn a_picture_has_its_alt_text_and_a_text_box_its_text() {
    let b64 = "iVBORw0KGgoAAAANSUhEUgAAAAIAAAADCAIAAAA=";
    let body = format!(
        r#"<text:p>Look <draw:frame text:anchor-type="as-char" svg:width="2cm" svg:height="3cm"><draw:image><office:binary-data>{b64}</office:binary-data></draw:image><svg:desc>A red kite</svg:desc></draw:frame>here</text:p><text:p>Next</text:p>"#
    );
    let flat = format!(
        r#"<office:document {ODF_NS}><office:body><office:text>{body}</office:text></office:body></office:document>"#
    );
    let t = extract(flat.as_bytes(), Format::Fodt);
    assert_text(&t, "Look here\nA red kite\nNext\n", &[]);
}

#[test]
fn the_text_of_shapes_in_a_group_is_kept() {
    let body = r#"<text:p>before <draw:g text:anchor-type="paragraph"><draw:frame svg:width="5cm" svg:height="2cm"><draw:text-box><text:p>BOXTEXT</text:p></draw:text-box></draw:frame><draw:g><draw:rect svg:width="3cm" svg:height="1cm"><text:p>RECTTEXT</text:p></draw:rect></draw:g></draw:g> after</text:p>"#;
    let flat = format!(
        r#"<office:document {ODF_NS}><office:body><office:text>{body}</office:text></office:body></office:document>"#
    );
    let c = convert(flat.as_bytes(), Format::Fodt, &Limits::default()).unwrap();
    let words = docx_words(&c.docx);
    for w in ["BOXTEXT", "RECTTEXT", "before", "after"] {
        assert!(words.iter().any(|x| x == w), "{w}: {words:?}");
    }
    same_words_as_the_converter("group", flat.as_bytes(), Format::Fodt);
}

#[test]
fn spanned_empty_and_nested_cells_keep_a_row_on_a_line() {
    let c = r#"<table:table><table:table-column table:number-columns-repeated="3"/>
<table:table-row><table:table-cell table:number-columns-spanned="2"><text:p>A</text:p></table:table-cell><table:covered-table-cell/><table:table-cell><text:p>B</text:p></table:table-cell></table:table-row>
<table:table-row><table:table-cell><text:p>x</text:p><text:p>y</text:p></table:table-cell><table:table-cell/><table:table-cell><text:p>C</text:p></table:table-cell></table:table-row>
<table:table-row><table:table-cell><table:table><table:table-column table:number-columns-repeated="2"/><table:table-row><table:table-cell><text:p>n1</text:p></table:table-cell><table:table-cell><text:p>n2</text:p></table:table-cell></table:table-row></table:table></table:table-cell><table:table-cell><text:p>D</text:p></table:table-cell><table:table-cell/></table:table-row>
</table:table><text:p>after</text:p>"#;
    let flat = format!(
        r#"<office:document {ODF_NS}><office:body><office:text>{c}</office:text></office:body></office:document>"#
    );
    let t = extract(flat.as_bytes(), Format::Fodt);
    assert_text(&t, "A\tB\nx y\t\tC\nn1\tn2\n\tD\nafter\n", &[]);
    same_words_as_the_converter("spans", flat.as_bytes(), Format::Fodt);

    let x = format!(
        r#"<?xml version="1.0"?><w:wordDocument {WML_NS}><w:body><w:tbl><w:tr><w:tc><w:p><w:r><w:t>one</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>in1</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>in2</w:t></w:r></w:p></w:tc></w:tr></w:tbl><w:p><w:r><w:t>two</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>side</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:wordDocument>"#
    );
    let t = extract(x.as_bytes(), Format::Wml2003);
    assert_text(&t, "one\nin1\tin2\ntwo\tside\n", &[]);
    same_words_as_the_converter("nested", x.as_bytes(), Format::Wml2003);
}

#[test]
fn the_cap_cuts_the_text_of_every_format() {
    for (name, input, f) in every_document() {
        let full = extract(&input, f);
        assert!(!full.truncated, "{name}");
        // A cap that holds all of it, and one byte less.
        let t = text(&input, f, &Limits::default(), full.text.len()).unwrap();
        assert_eq!((&t.text, t.truncated), (&full.text, false), "{name}");
        let t = text(&input, f, &Limits::default(), full.text.len() - 1).unwrap();
        assert!(t.truncated, "{name}");
        assert!(full.text.starts_with(&t.text), "{name}");
        // Cut in the middle, and at nothing.
        for cap in [0, 1, 7, 20, full.text.len() / 2] {
            let t = text(&input, f, &Limits::default(), cap).unwrap();
            assert!(t.truncated, "{name} at {cap}");
            assert!(t.text.len() <= cap, "{name} at {cap}");
            assert!(full.text.starts_with(&t.text), "{name} at {cap}");
            for s in &t.sections {
                assert!(s.range.end <= t.text.len(), "{name} at {cap}");
            }
        }
    }
}

#[test]
fn the_cap_leaves_the_later_sections_out() {
    let t = text(&doc97(), Format::Doc, &Limits::default(), 40).unwrap();
    assert!(t.truncated);
    assert!(t.sections.is_empty());
    assert!(!t.text.contains("HEADTEXT"));
    // Room for the body and part of the footnotes.
    let full = extract(&doc97(), Format::Doc);
    let at = full.sections[1].range.start + 3;
    let t = text(&doc97(), Format::Doc, &Limits::default(), at).unwrap();
    assert!(t.truncated);
    assert_eq!(labels(&t), ["headers and footers", "footnotes"]);
    assert_eq!(section(&t, "footnotes"), "NOT");
}

// ---- refusals ----

/// Documents that are encrypted.
fn encrypted() -> Vec<(&'static str, Vec<u8>, Format)> {
    let p = || para("x\r", vec![], vec![]);
    let manifest = "<m><manifest:encryption-data xmlns:manifest=\"x\"/></m>";
    let storage = W::default().bytes(3, b"text").msg(5, table(&[(0, None)]));
    let mut z = PackageWriter::new(1 << 20);
    z.put("Index/Document.iwa", &iwa(&[(2, 2001, storage)]), true)
        .unwrap();
    vec![
        (
            "doc97",
            doc(
                &[p()],
                &Options {
                    encrypted: true,
                    ..Options::default()
                },
            ),
            Format::Doc,
        ),
        (
            "doc6",
            doc6(
                &[p()],
                &Six {
                    flags: 0x0100,
                    ..Six::default()
                },
            ),
            Format::Doc,
        ),
        ("odt", odt_with("<a/>", "<a/>", Some(manifest)), Format::Odt),
        ("pages", z.finish().unwrap(), Format::Pages),
    ]
}

#[test]
fn an_encrypted_document_is_refused_like_the_converter_refuses_it() {
    for (name, input, f) in encrypted() {
        assert_eq!(
            text(&input, f, &Limits::default(), CAP).unwrap_err(),
            Error::Encrypted,
            "{name}"
        );
        assert_eq!(
            convert(&input, f, &Limits::default()).unwrap_err(),
            Error::Encrypted,
            "{name}"
        );
    }
}

/// Documents that are of the format and damaged, and what is said.
fn damaged() -> Vec<(&'static str, Vec<u8>, Format)> {
    let wd = vec![0u8; 100];
    let deep = format!("{{\\rtf1 {}x{}}}", "{".repeat(500), "}".repeat(500));
    vec![
        (
            "doc: the WordDocument stream ends too soon",
            build_cfb(&[("WordDocument", &wd)]),
            Format::Doc,
        ),
        (
            "odt: the content is cut",
            odt_with(
                "<office:document-content><office:body><office:text><text:p",
                "<a/>",
                None,
            ),
            Format::Odt,
        ),
        (
            "fodt: the document is cut",
            fodt()[..200].to_vec(),
            Format::Fodt,
        ),
        (
            "rtf: groups nested past the bound",
            deep.into_bytes(),
            Format::Rtf,
        ),
        (
            "wml: the document is cut",
            wml()[..300].to_vec(),
            Format::Wml2003,
        ),
    ]
}

#[test]
fn a_damaged_document_is_malformed_and_never_a_panic() {
    for (name, input, f) in damaged() {
        let e = text(&input, f, &Limits::default(), CAP).unwrap_err();
        assert_eq!(e.kind(), "malformed", "{name}: {e}");
        assert_eq!(
            convert(&input, f, &Limits::default()).unwrap_err(),
            e,
            "{name}"
        );
    }
}

#[test]
fn what_is_not_of_the_format_is_refused_as_such() {
    for f in [
        Format::Doc,
        Format::Odt,
        Format::Fodt,
        Format::Rtf,
        Format::Wml2003,
        Format::Pages,
    ] {
        for input in [
            &b""[..],
            b"plain text, no markup",
            b"<a/>",
            b"\x00\x01\x02\x03",
        ] {
            let e = text(input, f, &Limits::default(), CAP).unwrap_err();
            assert_eq!(
                convert(input, f, &Limits::default()).unwrap_err(),
                e,
                "{f:?} {input:?}"
            );
        }
    }
    let e = text(b"plain text", Format::Rtf, &Limits::default(), CAP).unwrap_err();
    assert_eq!(e.kind(), "not-format");
    // A Word 95 file is a document of the format this reader does not take.
    let old = doc(
        &[para("x\r", vec![], vec![])],
        &Options {
            fib_version: 0x0065,
            ..Options::default()
        },
    );
    let e = text(&old, Format::Doc, &Limits::default(), CAP).unwrap_err();
    assert_eq!(e.kind(), "unsupported");
}

#[test]
fn cut_and_flipped_documents_are_refused_as_the_converter_refuses_them() {
    let limits = Limits::default().with_max_memory(64 << 20);
    let (mut ok, mut refused) = (0, 0);
    for (name, input, f) in every_document() {
        let mut check = |d: &[u8]| match text(d, f, &limits, CAP) {
            Ok(_) => ok += 1,
            Err(e) => {
                refused += 1;
                assert_eq!(convert(d, f, &limits).unwrap_err(), e, "{name}");
            }
        };
        let step = (input.len() / 60).max(1);
        for cut in (0..input.len()).step_by(step) {
            check(&input[..cut]);
        }
        let mut m = input.clone();
        let step = (input.len() / 200).max(1);
        for i in (0..m.len()).step_by(step) {
            m[i] ^= 0xFF;
            check(&m);
            m[i] ^= 0xFF;
        }
    }
    assert!(ok > 100 && refused > 100, "{ok} read, {refused} refused");
}

#[test]
fn the_limits_bound_the_text_as_they_bound_the_conversion() {
    let multi: Vec<_> = every_document()
        .into_iter()
        .filter(|d| d.0 != "sample-2003.xml")
        .collect();
    for (name, input, f) in &multi {
        let tight = [
            (Limits::default().with_max_paragraphs(1), "paragraphs"),
            (Limits::default().with_max_memory(100), "memory"),
        ];
        for (limits, what) in tight {
            let e = text(input, *f, &limits, CAP).unwrap_err();
            assert_eq!(e.kind(), "too-large", "{name}: {e}");
            assert_eq!(
                convert(input, *f, &limits).unwrap_err(),
                e,
                "{name}: {what}"
            );
        }
        let mut small = Limits::default();
        small.max_input = 10;
        assert_eq!(
            text(input, *f, &small, CAP).unwrap_err(),
            Error::TooLarge("input"),
            "{name}"
        );
        // The same document within the limits.
        text(input, *f, &Limits::default(), CAP).unwrap();
    }
    // Table cells.
    for name in ["doc97", "fodt", "odt", "rtf", "wml"] {
        let (_, input, f) = every_document().into_iter().find(|d| d.0 == name).unwrap();
        let limits = Limits::default().with_max_cells(1);
        assert_eq!(
            text(&input, f, &limits, CAP).unwrap_err(),
            Error::TooLarge("table cells"),
            "{name}"
        );
    }
}
