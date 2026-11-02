//! Documents nested as deep as their parsers allow, and deeper.
//!
//! The converters walk a tree with a call per level. The XML parser stops a
//! tree at `MAX_DEPTH` levels, and RTF and HTML have limits of their own, so
//! the walk is as deep as that and no deeper: the question is whether each
//! converter's frames, times that depth, fit the stack of the thread it runs
//! on (a viewer's worker, a WebAssembly host's one megabyte). Each format is
//! converted here on a stack of a quarter of that, with the elements that nest
//! in it repeated to well past the limit and, for a flat file, to a depth the
//! parser would let through if it let anything. The tests run at the test
//! profile's `opt-level = 1`; `make stack-frames` reads the frames of release
//! builds.
//!
//! `EXAV_DEBUG_NESTING=<part of a case name>` runs the cases with it in their
//! name and says which; `EXAV_DEBUG_NESTING_DEPTHS=40,80` and
//! `EXAV_DEBUG_NESTING_STACK_KB=128` take other depths and stacks: how deep a
//! case can go on how small a stack is a bisection with them.

#![cfg(all(
    feature = "office-docs",
    feature = "office-slides",
    feature = "office-sheets"
))]

use std::io::Write;
use std::time::{Duration, Instant};

/// A quarter of the stack of a WebAssembly host's only thread, the smallest the
/// converters run on.
const STACK: usize = 256 * 1024;
const MEMORY: u64 = 64 << 20;

/// A kind of nesting: its name, and the body nested to a depth.
type Case = (&'static str, Box<dyn Fn(usize) -> String>);

/// What a conversion came to, under `EXAV_DEBUG_NESTING`.
fn said(r: Result<(), String>) {
    if std::env::var_os("EXAV_DEBUG_NESTING").is_some() {
        eprintln!("  {r:?}");
    }
}

fn docs(f: exav_render::docs::Format) -> impl Fn(&[u8]) + Send + Clone + 'static {
    move |d| {
        let l = exav_render::docs::Limits::default().with_max_memory(MEMORY);
        let r = exav_render::docs::convert(d, f, &l);
        said(r.map(|_| ()).map_err(|e| e.to_string()));
    }
}

fn sheets(f: exav_render::sheets::Format) -> impl Fn(&[u8]) + Send + Clone + 'static {
    move |d| {
        let l = exav_render::sheets::Limits::default().with_max_memory(MEMORY);
        let r = exav_render::sheets::convert(d, f, &l);
        said(r.map(|_| ()).map_err(|e| e.to_string()));
    }
}

fn slides(f: exav_render::slides::Format) -> impl Fn(&[u8]) + Send + Clone + 'static {
    move |d| {
        let l = exav_render::slides::Limits::default().with_max_memory(MEMORY);
        let r = exav_render::slides::convert(d, f, &l);
        said(r.map(|_| ()).map_err(|e| e.to_string()));
    }
}

fn on_small_stack(
    name: String,
    convert: impl Fn(&[u8]) + Send + 'static,
    data: Vec<u8>,
) -> Option<String> {
    // `EXAV_DEBUG_NESTING=<part of a case name>` runs the cases whose name has
    // it, and says which, since a stack overflow aborts the process.
    if let Ok(only) = std::env::var("EXAV_DEBUG_NESTING") {
        if !name.contains(&only) {
            return None;
        }
        eprintln!("{name}");
    }
    let stack = std::env::var("EXAV_DEBUG_NESTING_STACK_KB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(STACK, |kb| kb << 10);
    let started = Instant::now();
    let r = std::thread::Builder::new()
        .stack_size(stack)
        .spawn(move || convert(&data))
        .unwrap()
        .join();
    match r {
        Err(_) => Some(format!("{name}: overflowed its stack or panicked")),
        Ok(()) if started.elapsed() > Duration::from_secs(20) => Some(format!(
            "{name}: took {:.1} s",
            started.elapsed().as_secs_f64()
        )),
        Ok(()) => None,
    }
}

fn assert_all(findings: Vec<Option<String>>) {
    let findings: Vec<String> = findings.into_iter().flatten().collect();
    assert!(findings.is_empty(), "\n{}", findings.join("\n"));
}

const ODF_NS: &str = "xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" \
    xmlns:text=\"urn:oasis:names:tc:opendocument:xmlns:text:1.0\" \
    xmlns:table=\"urn:oasis:names:tc:opendocument:xmlns:table:1.0\" \
    xmlns:draw=\"urn:oasis:names:tc:opendocument:xmlns:drawing:1.0\" \
    xmlns:svg=\"urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0\" \
    xmlns:style=\"urn:oasis:names:tc:opendocument:xmlns:style:1.0\" \
    xmlns:fo=\"urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0\" \
    xmlns:xlink=\"http://www.w3.org/1999/xlink\" \
    xmlns:presentation=\"urn:oasis:names:tc:opendocument:xmlns:presentation:1.0\" \
    xmlns:chart=\"urn:oasis:names:tc:opendocument:xmlns:chart:1.0\" \
    xmlns:dc=\"http://purl.org/dc/elements/1.1/\" office:version=\"1.2\"";

/// `open` repeated `depth` times, then `inner`, then the matching `close`.
fn nest(open: &str, close: &str, inner: &str, depth: usize) -> String {
    format!("{}{inner}{}", open.repeat(depth), close.repeat(depth))
}

/// A zipped ODF package of one `content.xml`.
fn odf_zip(mime: &str, content: &str) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    z.start_file("mimetype", stored).unwrap();
    z.write_all(mime.as_bytes()).unwrap();
    z.start_file("content.xml", zip::write::SimpleFileOptions::default())
        .unwrap();
    z.write_all(content.as_bytes()).unwrap();
    z.finish().unwrap().into_inner()
}

/// The documents of an ODF body kind (`text`, `spreadsheet`, `presentation`,
/// `drawing`) with `body_of(depth)` as the body, as flat and as packaged.
fn odf(kind: &str, body: String) -> (String, String) {
    let flat = format!(
        "<?xml version=\"1.0\"?><office:document {ODF_NS} office:mimetype=\"application/vnd.oasis.opendocument.{kind}\">\
         <office:body><office:{kind}>{body}</office:{kind}></office:body></office:document>"
    );
    let content = format!(
        "<?xml version=\"1.0\"?><office:document-content {ODF_NS}>\
         <office:body><office:{kind}>{body}</office:{kind}></office:body></office:document-content>"
    );
    (flat, content)
}

/// The depths tried: inside the limit, at it, and past it.
/// `EXAV_DEBUG_NESTING_DEPTHS=40,80` takes others.
fn depths() -> Vec<usize> {
    match std::env::var("EXAV_DEBUG_NESTING_DEPTHS") {
        Ok(v) => v.split(',').filter_map(|d| d.parse().ok()).collect(),
        Err(_) => vec![120, 250, 5_000],
    }
}

#[test]
fn odf_text() {
    let shapes: Vec<Case> = vec![
        (
            "lists",
            Box::new(|d| {
                nest(
                    "<text:list><text:list-item>",
                    "</text:list-item></text:list>",
                    "<text:p>x</text:p>",
                    d,
                )
            }),
        ),
        (
            "tables",
            Box::new(|d| {
                nest(
                    "<table:table><table:table-row><table:table-cell>",
                    "</table:table-cell></table:table-row></table:table>",
                    "<text:p>x</text:p>",
                    d,
                )
            }),
        ),
        (
            "spans",
            Box::new(|d| {
                format!(
                    "<text:p>{}</text:p>",
                    nest("<text:span>", "</text:span>", "x", d)
                )
            }),
        ),
        (
            "links",
            Box::new(|d| {
                format!(
                    "<text:p>{}</text:p>",
                    nest("<text:a xlink:href=\"http://a\">", "</text:a>", "x", d)
                )
            }),
        ),
        (
            "sections",
            Box::new(|d| nest("<text:section>", "</text:section>", "<text:p>x</text:p>", d)),
        ),
        (
            "text boxes",
            Box::new(|d| {
                format!(
                    "<text:p>{}</text:p>",
                    nest(
                        "<draw:frame><draw:text-box>",
                        "</draw:text-box></draw:frame>",
                        "<text:p>x</text:p>",
                        d
                    )
                )
            }),
        ),
        (
            "notes",
            Box::new(|d| {
                format!(
                    "<text:p>{}</text:p>",
                    nest(
                        "<text:note><text:note-body><text:p>",
                        "</text:p></text:note-body></text:note>",
                        "x",
                        d
                    )
                )
            }),
        ),
        (
            "groups",
            Box::new(|d| {
                format!(
                    "<text:p>{}</text:p>",
                    nest(
                        "<draw:g>",
                        "</draw:g>",
                        "<draw:rect svg:width=\"1cm\" svg:height=\"1cm\"/>",
                        d
                    )
                )
            }),
        ),
        (
            "tracked changes",
            Box::new(|d| {
                nest(
                    "<text:tracked-changes><text:changed-region>",
                    "</text:changed-region></text:tracked-changes>",
                    "",
                    d,
                )
            }),
        ),
        (
            "headings",
            Box::new(|d| nest("<text:h>", "</text:h>", "x", d)),
        ),
    ];
    let mut findings = vec![];
    for (name, body) in &shapes {
        for depth in depths() {
            let (flat, content) = odf("text", body(depth));
            let label = |k: &str| format!("{k} {name} x{depth}");
            findings.push(on_small_stack(
                label("fodt"),
                docs(exav_render::docs::Format::Fodt),
                flat.into_bytes(),
            ));
            findings.push(on_small_stack(
                label("odt"),
                docs(exav_render::docs::Format::Odt),
                odf_zip("application/vnd.oasis.opendocument.text", &content),
            ));
        }
    }
    assert_all(findings);
}

#[test]
fn odf_spreadsheets() {
    let cell = |inner: &str| {
        format!("<table:table-row><table:table-cell>{inner}</table:table-cell></table:table-row>")
    };
    let shapes: Vec<Case> = vec![
        (
            "tables",
            Box::new(move |d| {
                format!(
                    "<table:table>{}</table:table>",
                    nest(
                        "<table:table-row><table:table-cell><table:table>",
                        "</table:table></table:table-cell></table:table-row>",
                        "",
                        d
                    )
                )
            }),
        ),
        (
            "groups",
            Box::new(move |d| {
                format!(
                    "<table:table>{}</table:table>",
                    cell(&nest(
                        "<draw:g>",
                        "</draw:g>",
                        "<draw:rect svg:width=\"1cm\" svg:height=\"1cm\"/>",
                        d
                    ))
                )
            }),
        ),
        (
            "frames",
            Box::new(move |d| {
                format!(
                    "<table:table>{}</table:table>",
                    cell(&nest(
                        "<draw:frame><draw:text-box>",
                        "</draw:text-box></draw:frame>",
                        "<text:p>x</text:p>",
                        d
                    ))
                )
            }),
        ),
        (
            "row groups",
            Box::new(|d| {
                format!(
                    "<table:table>{}</table:table>",
                    nest(
                        "<table:table-row-group>",
                        "</table:table-row-group>",
                        "<table:table-row><table:table-cell/></table:table-row>",
                        d
                    )
                )
            }),
        ),
        (
            "column groups",
            Box::new(|d| {
                format!(
                    "<table:table>{}</table:table>",
                    nest(
                        "<table:table-header-columns>",
                        "</table:table-header-columns>",
                        "<table:table-column/>",
                        d
                    )
                )
            }),
        ),
        (
            "spans",
            Box::new(move |d| {
                format!(
                    "<table:table>{}</table:table>",
                    cell(&format!(
                        "<text:p>{}</text:p>",
                        nest("<text:span>", "</text:span>", "x", d)
                    ))
                )
            }),
        ),
        (
            "sub-tables",
            Box::new(|d| {
                nest(
                    "<table:table><table:sub-table>",
                    "</table:sub-table></table:table>",
                    "",
                    d,
                )
            }),
        ),
    ];
    let mut findings = vec![];
    for (name, body) in &shapes {
        for depth in depths() {
            let (flat, content) = odf("spreadsheet", body(depth));
            let label = |k: &str| format!("{k} {name} x{depth}");
            findings.push(on_small_stack(
                label("fods"),
                sheets(exav_render::sheets::Format::Fods),
                flat.into_bytes(),
            ));
            findings.push(on_small_stack(
                label("ods"),
                sheets(exav_render::sheets::Format::Ods),
                odf_zip("application/vnd.oasis.opendocument.spreadsheet", &content),
            ));
        }
    }
    assert_all(findings);
}

#[test]
fn odf_drawings_and_presentations() {
    let page = |inner: &str| format!("<draw:page draw:name=\"p\">{inner}</draw:page>");
    let shapes: Vec<Case> = vec![
        (
            "groups",
            Box::new(move |d| {
                page(&nest(
                    "<draw:g>",
                    "</draw:g>",
                    "<draw:rect svg:width=\"1cm\" svg:height=\"1cm\"/>",
                    d,
                ))
            }),
        ),
        (
            "frames",
            Box::new(move |d| {
                page(&nest(
                    "<draw:frame svg:width=\"1cm\" svg:height=\"1cm\"><draw:text-box>",
                    "</draw:text-box></draw:frame>",
                    "<text:p>x</text:p>",
                    d,
                ))
            }),
        ),
        (
            "lists",
            Box::new(move |d| {
                page(&format!(
                    "<draw:frame svg:width=\"1cm\" svg:height=\"1cm\"><draw:text-box>{}</draw:text-box></draw:frame>",
                    nest(
                        "<text:list><text:list-item>",
                        "</text:list-item></text:list>",
                        "<text:p>x</text:p>",
                        d
                    )
                ))
            }),
        ),
        (
            "spans",
            Box::new(move |d| {
                page(&format!(
                    "<draw:frame svg:width=\"1cm\" svg:height=\"1cm\"><draw:text-box><text:p>{}</text:p></draw:text-box></draw:frame>",
                    nest("<text:span>", "</text:span>", "x", d)
                ))
            }),
        ),
        (
            "connectors",
            Box::new(move |d| {
                page(&nest(
                    "<draw:connector svg:x1=\"0\" svg:y1=\"0\" svg:x2=\"1cm\" svg:y2=\"1cm\">",
                    "</draw:connector>",
                    "",
                    d,
                ))
            }),
        ),
        (
            "custom shapes",
            Box::new(move |d| {
                page(&nest(
                    "<draw:custom-shape>",
                    "</draw:custom-shape>",
                    "<draw:enhanced-geometry draw:enhanced-path=\"M 0 0 L 1 1 N\"/>",
                    d,
                ))
            }),
        ),
        (
            "a formula",
            Box::new(move |d| {
                page(&format!(
                    "<draw:custom-shape><draw:enhanced-geometry draw:enhanced-path=\"M 0 0 L $0 1 N\" draw:equations=\"\"><draw:equation draw:name=\"f0\" draw:formula=\"{}1{}\"/></draw:enhanced-geometry></draw:custom-shape>",
                    "(".repeat(d),
                    ")".repeat(d)
                ))
            }),
        ),
        (
            "a unary formula",
            Box::new(move |d| {
                page(&format!(
                    "<draw:custom-shape><draw:enhanced-geometry draw:enhanced-path=\"M 0 0 L $0 1 N\"><draw:equation draw:name=\"f0\" draw:formula=\"{}1\"/></draw:enhanced-geometry></draw:custom-shape>",
                    "-".repeat(d)
                ))
            }),
        ),
        (
            "pages",
            Box::new(move |d| nest("<draw:page draw:name=\"p\">", "</draw:page>", "", d)),
        ),
    ];
    let mut findings = vec![];
    for (name, body) in &shapes {
        for depth in depths() {
            for (kind, flat_f, zip_f) in [
                (
                    "presentation",
                    exav_render::slides::Format::Fodp,
                    exav_render::slides::Format::Odp,
                ),
                (
                    "drawing",
                    exav_render::slides::Format::Fodg,
                    exav_render::slides::Format::Odg,
                ),
            ] {
                let (flat, content) = odf(kind, body(depth));
                let label = |k: &str| format!("{k} {kind} {name} x{depth}");
                findings.push(on_small_stack(
                    label("flat"),
                    slides(flat_f),
                    flat.into_bytes(),
                ));
                findings.push(on_small_stack(
                    label("zip"),
                    slides(zip_f),
                    odf_zip(
                        &format!("application/vnd.oasis.opendocument.{kind}"),
                        &content,
                    ),
                ));
            }
        }
    }
    assert_all(findings);
}

#[test]
fn word_2003_xml() {
    let head = "<?xml version=\"1.0\"?><w:wordDocument xmlns:w=\"http://schemas.microsoft.com/office/word/2003/wordml\" \
        xmlns:wx=\"http://schemas.microsoft.com/office/word/2003/auxHint\" xmlns:v=\"urn:schemas-microsoft-com:vml\">";
    let shapes: Vec<Case> = vec![
        (
            "sections",
            Box::new(|d| {
                nest(
                    "<wx:sect>",
                    "</wx:sect>",
                    "<w:p><w:r><w:t>x</w:t></w:r></w:p>",
                    d,
                )
            }),
        ),
        (
            "tables",
            Box::new(|d| nest("<w:tbl><w:tr><w:tc>", "</w:tc></w:tr></w:tbl>", "<w:p/>", d)),
        ),
        (
            "hyperlinks",
            Box::new(|d| {
                format!(
                    "<w:p>{}</w:p>",
                    nest(
                        "<w:hlink w:dest=\"http://a\">",
                        "</w:hlink>",
                        "<w:r><w:t>x</w:t></w:r>",
                        d
                    )
                )
            }),
        ),
        (
            "runs",
            Box::new(|d| format!("<w:p>{}</w:p>", nest("<w:r>", "</w:r>", "<w:t>x</w:t>", d))),
        ),
        (
            "sub-documents",
            Box::new(|d| nest("<wx:sub-section>", "</wx:sub-section>", "<w:p/>", d)),
        ),
        (
            "text boxes",
            Box::new(|d| {
                format!(
                    "<w:p><w:r>{}</w:r></w:p>",
                    nest(
                        "<w:pict><v:shape><v:textbox><w:txbxContent>",
                        "</w:txbxContent></v:textbox></v:shape></w:pict>",
                        "<w:p/>",
                        d
                    )
                )
            }),
        ),
        (
            "insertions",
            Box::new(|d| {
                format!(
                    "<w:p>{}</w:p>",
                    nest(
                        "<aml:annotation xmlns:aml=\"http://schemas.microsoft.com/aml/2001/core\">",
                        "</aml:annotation>",
                        "",
                        d
                    )
                )
            }),
        ),
    ];
    let mut findings = vec![];
    for (name, body) in &shapes {
        for depth in depths() {
            let xml = format!("{head}<w:body>{}</w:body></w:wordDocument>", body(depth));
            findings.push(on_small_stack(
                format!("wml2003 {name} x{depth}"),
                docs(exav_render::docs::Format::Wml2003),
                xml.into_bytes(),
            ));
        }
    }
    assert_all(findings);
}

#[test]
fn spreadsheetml_2003() {
    let head = "<?xml version=\"1.0\"?><Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\" \
        xmlns:ss=\"urn:schemas-microsoft-com:office:spreadsheet\" xmlns:html=\"http://www.w3.org/TR/REC-html40\">";
    let shapes: Vec<Case> = vec![
        (
            "rich text",
            Box::new(|d| {
                format!(
                    "<Worksheet><Table><Row><Cell><ss:Data ss:Type=\"String\">{}</ss:Data></Cell></Row></Table></Worksheet>",
                    nest("<html:B>", "</html:B>", "x", d)
                )
            }),
        ),
        (
            "worksheets",
            Box::new(|d| {
                nest(
                    "<Worksheet><Table><Row><Cell>",
                    "</Cell></Row></Table></Worksheet>",
                    "",
                    d,
                )
            }),
        ),
        (
            "names",
            Box::new(|d| {
                format!(
                    "<Names>{}</Names>",
                    nest("<NamedRange>", "</NamedRange>", "", d)
                )
            }),
        ),
        (
            "comments",
            Box::new(|d| {
                format!(
                    "<Worksheet><Table><Row><Cell><Comment>{}</Comment></Cell></Row></Table></Worksheet>",
                    nest("<ss:Data>", "</ss:Data>", "x", d)
                )
            }),
        ),
        (
            "styles",
            Box::new(|d| format!("<Styles>{}</Styles>", nest("<Style>", "</Style>", "", d))),
        ),
    ];
    let mut findings = vec![];
    for (name, body) in &shapes {
        for depth in depths() {
            let xml = format!("{head}{}</Workbook>", body(depth));
            findings.push(on_small_stack(
                format!("xmlss {name} x{depth}"),
                sheets(exav_render::sheets::Format::SpreadsheetMl),
                xml.into_bytes(),
            ));
        }
    }
    assert_all(findings);
}

#[test]
fn html_and_rtf_and_sylk() {
    let n = 100_000;
    let docs_html = docs(exav_render::docs::Format::Html);
    let sheets_html = sheets(exav_render::sheets::Format::Html);
    let rtf = docs(exav_render::docs::Format::Rtf);
    let sylk = sheets(exav_render::sheets::Format::Sylk);
    let mut findings = vec![];
    let html_shapes = [
        ("tables", "<table><tr><td>"),
        ("lists", "<ul><li>"),
        ("divs", "<div>"),
        ("spans", "<span><b><i>"),
        ("frames", "<frameset><frame>"),
        ("blockquotes", "<blockquote>"),
        ("fonts", "<font>"),
        ("anchors", "<a href=\"http://a\">"),
        ("unclosed tags", "<"),
        ("entities", "&amp;&#x41;&"),
    ];
    for (name, open) in html_shapes {
        let doc = format!("<html><body>{}x</body></html>", open.repeat(n));
        findings.push(on_small_stack(
            format!("docs html {name}"),
            docs_html.clone(),
            doc.clone().into_bytes(),
        ));
        findings.push(on_small_stack(
            format!("sheets html {name}"),
            sheets_html.clone(),
            doc.into_bytes(),
        ));
    }
    let rtf_shapes = [
        ("groups", "{"),
        ("destinations", "{\\*\\x "),
        ("tables", "\\trowd{\\intbl "),
        ("fields", "{\\field{\\*\\fldinst "),
        ("pictures", "{\\pict "),
        ("shapes", "{\\shp{\\*\\shpinst "),
        ("fonts", "{\\fonttbl{\\f0 "),
        ("lists", "{\\listtable{\\list "),
        ("footnotes", "{\\footnote "),
    ];
    for (name, open) in rtf_shapes {
        let doc = format!("{{\\rtf1\\ansi {}x}}", open.repeat(n));
        findings.push(on_small_stack(
            format!("rtf {name}"),
            rtf.clone(),
            doc.into_bytes(),
        ));
    }
    let sylk_doc = format!("ID;P\n{}E\n", "C;X1;Y1;K\"x\";E".repeat(n) + "\n");
    findings.push(on_small_stack(
        "sylk cells".into(),
        sylk.clone(),
        sylk_doc.into_bytes(),
    ));
    let sylk_formula = format!("ID;P\nC;X1;Y1;E{}1\nE\n", "-(".repeat(n));
    findings.push(on_small_stack(
        "sylk formula".into(),
        sylk,
        sylk_formula.into_bytes(),
    ));
    assert_all(findings);
}

#[test]
fn visio_pages() {
    let ns = "xmlns=\"http://schemas.microsoft.com/office/visio/2012/main\" \
        xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"";
    let shapes: Vec<Case> = vec![
        (
            "sub-shapes",
            Box::new(|d| {
                format!(
                    "<Shapes>{}</Shapes>",
                    nest(
                        "<Shape ID=\"1\" Type=\"Group\"><Shapes>",
                        "</Shapes></Shape>",
                        "<Shape ID=\"2\"><Text>x</Text></Shape>",
                        d
                    )
                )
            }),
        ),
        (
            "a master chain",
            Box::new(|d| {
                format!(
                    "<Shapes><Shape ID=\"1\" Master=\"1\">{}</Shape></Shapes>",
                    nest("<Section N=\"Geometry\"><Row>", "</Row></Section>", "", d)
                )
            }),
        ),
        (
            "a formula",
            Box::new(|d| {
                format!(
                    "<Shapes><Shape ID=\"1\"><Cell N=\"PinX\" F=\"{}1{}\"/></Shape></Shapes>",
                    "(".repeat(d),
                    ")".repeat(d)
                )
            }),
        ),
        (
            "a unary formula",
            Box::new(|d| {
                format!(
                    "<Shapes><Shape ID=\"1\"><Cell N=\"PinX\" F=\"{}1\"/></Shape></Shapes>",
                    "-".repeat(d)
                )
            }),
        ),
        (
            "a binary formula",
            Box::new(|d| {
                format!(
                    "<Shapes><Shape ID=\"1\"><Cell N=\"PinX\" F=\"{}1\"/></Shape></Shapes>",
                    "1+".repeat(d)
                )
            }),
        ),
        (
            "a reference chain",
            Box::new(|d| {
                format!(
                    "<Shapes><Shape ID=\"1\"><Cell N=\"PinX\" V=\"1\" F=\"Sheet.1!PinX\"/></Shape>{}</Shapes>",
                    (2..d)
                        .map(|i| format!(
                            "<Shape ID=\"{i}\"><Cell N=\"PinX\" F=\"Sheet.{}!PinX\"/></Shape>",
                            i - 1
                        ))
                        .collect::<String>()
                )
            }),
        ),
    ];
    let mut findings = vec![];
    for (name, body) in &shapes {
        for depth in depths() {
            let page = format!(
                "<?xml version=\"1.0\"?><PageContents {ns}>{}</PageContents>",
                body(depth)
            );
            let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            let o = zip::write::SimpleFileOptions::default();
            z.start_file("[Content_Types].xml", o).unwrap();
            z.write_all(b"<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Override PartName=\"/visio/document.xml\" ContentType=\"application/vnd.ms-visio.drawing.main+xml\"/></Types>").unwrap();
            z.start_file("_rels/.rels", o).unwrap();
            z.write_all(b"<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/visio/2010/relationships/document\" Target=\"visio/document.xml\"/></Relationships>").unwrap();
            z.start_file("visio/document.xml", o).unwrap();
            z.write_all(format!("<?xml version=\"1.0\"?><VisioDocument {ns}/>").as_bytes())
                .unwrap();
            z.start_file("visio/_rels/document.xml.rels", o).unwrap();
            z.write_all(b"<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/visio/2010/relationships/pages\" Target=\"pages/pages.xml\"/></Relationships>").unwrap();
            z.start_file("visio/pages/pages.xml", o).unwrap();
            z.write_all(format!("<?xml version=\"1.0\"?><Pages {ns}><Page ID=\"0\" Name=\"p\"><Rel r:id=\"rId1\"/></Page></Pages>").as_bytes()).unwrap();
            z.start_file("visio/pages/_rels/pages.xml.rels", o).unwrap();
            z.write_all(b"<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.microsoft.com/visio/2010/relationships/page\" Target=\"page1.xml\"/></Relationships>").unwrap();
            z.start_file("visio/pages/page1.xml", o).unwrap();
            z.write_all(page.as_bytes()).unwrap();
            let data = z.finish().unwrap().into_inner();
            findings.push(on_small_stack(
                format!("vsdx {name} x{depth}"),
                slides(exav_render::slides::Format::Vsdx),
                data,
            ));
        }
    }
    assert_all(findings);
}
