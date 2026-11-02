//! The text of spreadsheets, taken from what the readers parse.

use exav_render::formats::office::text::Text;
use exav_render::sheets::{Error, Format, Limits, convert, text};
use std::io::{Read, Write};

const ALL: [(&str, Format); 8] = [
    ("sample.xls", Format::Xls),
    ("sample.ods", Format::Ods),
    ("sample.fods", Format::Fods),
    ("sample.numbers", Format::Numbers),
    ("numbers09.numbers", Format::Numbers),
    ("sample-2003.xml", Format::SpreadsheetMl),
    ("sample.html", Format::Html),
    ("sample.slk", Format::Sylk),
];

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/office/sheets/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

const CAP: usize = 1 << 20;

fn of(data: &[u8], format: Format) -> Text {
    text(data, format, &Limits::default(), CAP).unwrap()
}

fn labels(t: &Text) -> Vec<&str> {
    t.sections.iter().map(|s| s.label.as_str()).collect()
}

fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(vec![]));
    for (name, data) in files {
        z.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        z.write_all(data).unwrap();
    }
    z.finish().unwrap().into_inner()
}

// Fixtures.

const BUDGET: &str = "Budget\nItem\tAmount\tDate\nRent\t1200\t45296\nFood\t345.5\t45303\n\
Travel\t89.99\t45323\nTotal\t1635.49\nMerged note across three columns\n";

#[test]
fn the_cells_of_the_fixtures() {
    // The workbooks keep the date as a serial and the number without its
    // format: the model holds no displayed text.
    let want = format!("{BUDGET}Notes\nSecond sheet\t1\n");
    for name in [("sample.xls", Format::Xls), ("sample.ods", Format::Ods)] {
        let t = of(&fixture(name.0), name.1);
        assert_eq!(t.text, want, "{}", name.0);
        assert_eq!(labels(&t), ["sheet \"Budget\"", "sheet \"Notes\""]);
        assert!(!t.truncated && t.links.is_empty());
    }
    let t = of(&fixture("sample.fods"), Format::Fods);
    assert_eq!(t.text, format!("{BUDGET}Notes\nSecond sheet\tTRUE\n"));
    // The text formats: the same table, one day later, and no date or
    // amount where the table has none.
    let t = of(&fixture("sample-2003.xml"), Format::SpreadsheetMl);
    assert_eq!(
        t.text,
        "Budget\nItem\tAmount\tDate\nRent\t1200\t45297\nFood\t345.5\nTravel\t89.99\n\
         Total\t1635.49\nMerged note across three columns\nNotes\nSecond sheet\tTRUE\n"
    );
    assert_eq!(labels(&t), ["sheet \"Budget\"", "sheet \"Notes\""]);
    for (name, format) in [("sample.html", Format::Html), ("sample.slk", Format::Sylk)] {
        let t = of(&fixture(name), format);
        assert!(
            t.text.contains(
                "Item\tAmount\tDate\nRent\t1200\t45297\nFood\t345.5\nTravel\t89.99\n\
                 Total\t1635.49\nMerged note across three columns\n"
            ),
            "{name}: {}",
            t.text
        );
        assert_eq!(t.sections.len(), 1);
    }
}

#[test]
fn numbers_documents() {
    let t = of(&fixture("sample.numbers"), Format::Numbers);
    assert_eq!(labels(&t), ["sheet \"Sheet 1\""]);
    assert!(
        t.text.starts_with("Sheet 1\nSheetJS\tB1\tC1\tD1\tE1\n"),
        "{}",
        t.text
    );
    assert!(t.text.contains("A3\tB3:D3\n"), "{}", t.text);
    let t = of(&fixture("numbers09.numbers"), Format::Numbers);
    assert_eq!(
        labels(&t),
        [
            "sheet \"Checking - Account Categories\"",
            "sheet \"Checking - Transactions\"",
            "sheet \"Second sheet\""
        ]
    );
    for s in [
        "Category\tAmount\nHome\t-872.4\n",
        "Total\t-2575.9\n",
        "Beginning Balance\t4650\n",
        // A formula's cached value.
        "101\t40087\tRent\tHome\t-775\t3875\n",
        "Debit Card\t40102\tFill up SUV for camping trip\tGas\t-75\t3702.6\n",
        "Second sheet\nTest\n0.5\t0.1\n0.6\n",
    ] {
        assert!(t.text.contains(s), "{s:?} in {}", t.text);
    }
}

// The XLSX the converter writes says the same.

/// The unescaped text of an XML fragment's `<t>` elements, joined.
fn t_elements(xml: &str) -> String {
    let mut out = String::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<t") {
        rest = &rest[i + 2..];
        let Some(close) = rest.find('>') else { break };
        if !(rest.starts_with('>') || rest.starts_with(' ')) || rest[..close].ends_with('/') {
            continue;
        }
        let body = &rest[close + 1..];
        let end = body.find("</t>").unwrap();
        out.push_str(&unescape(&body[..end]));
        rest = &body[end..];
    }
    out
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The blocks `<tag>...</tag>` of an XML part.
fn blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = vec![];
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let body = &rest[i + open.len()..];
        let end = body.find(&close).unwrap();
        out.push(&body[..end]);
        rest = &body[end + close.len()..];
    }
    out
}

/// The strings of an XLSX's shared string table and inline strings, and its
/// sheets' names.
fn xlsx_strings(xlsx: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(xlsx)).unwrap();
    let names: Vec<String> = z
        .file_names()
        .filter_map(|n| n.ok().map(|n| n.to_string()))
        .collect();
    let mut strings = vec![];
    let mut sheets = vec![];
    for n in names {
        let mut xml = String::new();
        z.by_name(&n).unwrap().read_to_string(&mut xml).unwrap();
        if n == "xl/sharedStrings.xml" {
            strings.extend(blocks(&xml, "si").into_iter().map(t_elements));
        } else if n.starts_with("xl/worksheets/") && n.ends_with(".xml") {
            strings.extend(blocks(&xml, "is").into_iter().map(t_elements));
        } else if n == "xl/workbook.xml" {
            for part in xml.split("<sheet ").skip(1) {
                let name = part.split("name=\"").nth(1).unwrap();
                sheets.push(unescape(name.split('"').next().unwrap()));
            }
        }
    }
    (strings, sheets)
}

#[test]
fn the_text_has_the_cell_texts_of_the_xlsx() {
    for (name, format) in ALL {
        let data = fixture(name);
        let t = of(&data, format);
        let xlsx = convert(&data, format, &Limits::default()).unwrap().xlsx;
        let (strings, sheets) = xlsx_strings(&xlsx);
        assert!(!strings.is_empty() && !sheets.is_empty(), "{name}");
        let lines: Vec<&str> = t.text.lines().collect();
        // Every string of the XLSX is in the text, line by line.
        for s in &strings {
            for line in s.lines().map(str::trim).filter(|l| !l.is_empty()) {
                assert!(
                    lines
                        .iter()
                        .any(|l| l.split('\t').any(|c| c.trim() == line)),
                    "{name}: {line:?} of the XLSX is not in {}",
                    t.text
                );
            }
        }
        // And every word of the text is a number, a sheet name or one of them.
        for line in &lines {
            for cell in line.split('\t').map(str::trim).filter(|c| !c.is_empty()) {
                let known = cell.parse::<f64>().is_ok()
                    || cell == "TRUE"
                    || cell == "FALSE"
                    || sheets.iter().any(|s| s == cell)
                    || strings.iter().any(|s| s.lines().any(|l| l.trim() == cell));
                assert!(known, "{name}: {cell:?} of the text is not in the XLSX");
            }
        }
        for s in &sheets {
            assert!(t.text.contains(s.as_str()), "{name}: sheet {s}");
        }
    }
}

// A flat ODF spreadsheet with a hidden sheet, a comment, links, a formula,
// a boolean, an error, a validation and a shape.

const ODF_NS: &str = r#"xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:number="urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0" xmlns:calcext="urn:org:documentfoundation:names:experimental:calc:xmlns:calcext:1.0""#;

/// Styles, automatic then body, as `office:document` and
/// `office:document-content` both hold them.
const ODF_BODY: &str = r##"
 <office:automatic-styles>
  <number:number-style style:name="N2"><number:number number:decimal-places="2" number:grouping="true"/></number:number-style>
  <style:style style:name="money" style:family="table-cell" style:data-style-name="N2"/>
  <style:style style:name="ta-hidden" style:family="table"><style:table-properties table:display="false"/></style:style>
 </office:automatic-styles>
 <office:body><office:spreadsheet>
  <table:content-validations>
   <table:content-validation table:name="v1" table:condition="of:cell-content-is-whole-number() and cell-content-is-between(1,10)" table:allow-empty-cell="true">
    <table:help-message table:title="Pick" table:display="true"><text:p>Enter a whole number</text:p></table:help-message>
    <table:error-message table:message-type="stop" table:display="true" table:title="Oops"><text:p>Not a number</text:p></table:error-message>
   </table:content-validation>
  </table:content-validations>
  <table:table table:name="Open">
   <table:table-row>
    <table:table-cell office:value-type="string"><office:annotation><dc:creator>Eve</dc:creator><text:p>Note one</text:p><text:p>Note two</text:p></office:annotation><text:p>Plain</text:p></table:table-cell>
    <table:table-cell office:value-type="string"><text:p><text:a xlink:href="https://example.com/x">Site</text:a></text:p></table:table-cell>
    <table:table-cell office:value-type="string"><text:p><text:a xlink:href="https://example.com/">https://example.com/</text:a></text:p></table:table-cell>
   </table:table-row>
   <table:table-row>
    <table:table-cell table:formula="of:=1+2" office:value-type="float" office:value="3"><text:p>3,00</text:p></table:table-cell>
    <table:table-cell office:value-type="boolean" office:boolean-value="true"><text:p>TRUE</text:p></table:table-cell>
    <table:table-cell table:formula="of:=1/0" office:value-type="string" office:string-value="" calcext:value-type="error"><text:p>#DIV/0!</text:p></table:table-cell>
   </table:table-row>
   <table:table-row>
    <table:table-cell table:style-name="money" office:value-type="float" office:value="1200"><text:p>1,200.00</text:p></table:table-cell>
    <table:table-cell table:content-validation-name="v1" office:value-type="float" office:value="5"><text:p>5</text:p></table:table-cell>
   </table:table-row>
   <table:shapes>
    <draw:custom-shape svg:x="1cm" svg:y="1cm" svg:width="3cm" svg:height="2cm"><text:p>Words in a shape</text:p><draw:enhanced-geometry draw:type="rectangle"/></draw:custom-shape>
   </table:shapes>
  </table:table>
  <table:table table:name="Stash" table:style-name="ta-hidden">
   <table:table-row>
    <table:table-cell office:value-type="string"><text:p>hidden words</text:p></table:table-cell>
   </table:table-row>
  </table:table>
 </office:spreadsheet></office:body>"##;

fn fods() -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document {ODF_NS} office:version="1.3" office:mimetype="application/vnd.oasis.opendocument.spreadsheet">{ODF_BODY}
</office:document>"#
    )
    .into_bytes()
}

fn ods(manifest: Option<&str>) -> Vec<u8> {
    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-content {ODF_NS} office:version="1.3">{ODF_BODY}
</office:document-content>"#
    );
    let mut files = vec![
        (
            "mimetype",
            &b"application/vnd.oasis.opendocument.spreadsheet"[..],
        ),
        ("content.xml", content.as_bytes()),
    ];
    if let Some(m) = manifest {
        files.push(("META-INF/manifest.xml", m.as_bytes()));
    }
    zip(&files)
}

/// What both forms of the ODF document read as.
fn check_odf(t: &Text) {
    assert_eq!(
        &t.text[t.sections[0].range.clone()],
        "Open\nPlain\tSite (https://example.com/x)\thttps://example.com/\n\
         3\tTRUE\t#DIV/0!\n1200\t5\n"
    );
    assert_eq!(
        labels(t),
        [
            "sheet \"Open\"",
            "sheet \"Open\" comments",
            "sheet \"Open\" drawings",
            "hidden sheet \"Stash\""
        ],
        "{}",
        t.text
    );
    let comments = &t.text[t.sections[1].range.clone()];
    assert_eq!(
        comments,
        "Note one\nNote two\nPick\nEnter a whole number\nOops\nNot a number\n"
    );
    let drawings = &t.text[t.sections[2].range.clone()];
    assert_eq!(drawings, "Words in a shape\n");
    assert_eq!(
        &t.text[t.sections[3].range.clone()],
        "Stash\nhidden words\n"
    );
    assert_eq!(
        t.links,
        [("Site".to_string(), "https://example.com/x".to_string())]
    );
}

#[test]
fn flat_odf_features() {
    check_odf(&of(&fods(), Format::Fods));
}

#[test]
fn odf_package_features() {
    check_odf(&of(&ods(None), Format::Ods));
}

#[test]
fn an_encrypted_ods_is_refused() {
    let manifest = r#"<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"><manifest:encryption-data manifest:checksum-type="SHA1/1K"/></manifest:file-entry></manifest:manifest>"#;
    let e = text(&ods(Some(manifest)), Format::Ods, &Limits::default(), CAP).unwrap_err();
    assert_eq!(e, Error::Encrypted);
}

#[test]
fn an_encrypted_numbers_document_is_refused() {
    let enc = zip(&[("Index/Document.iwa", b"x"), (".iwpv2", b"x")]);
    let e = text(&enc, Format::Numbers, &Limits::default(), CAP).unwrap_err();
    assert_eq!(e, Error::Encrypted);
}

// XML Spreadsheet 2003.

const XMLSS: &str = r##"<?xml version="1.0"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:x="urn:schemas-microsoft-com:office:excel"
 xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">
 <Styles><Style ss:ID="money"><NumberFormat ss:Format="#,##0.00"/></Style></Styles>
 <Worksheet ss:Name="Shown">
  <Table>
   <Row>
    <Cell ss:HRef="https://example.com/x"><Data ss:Type="String">Site</Data></Cell>
    <Cell ss:HRef="mailto:a@b.test"><Data ss:Type="String">a@b.test</Data></Cell>
    <Cell ss:HRef="#Other!A1"><Data ss:Type="String">Jump</Data></Cell>
   </Row>
   <Row>
    <Cell ss:Formula="=SUM(R[-1]C:R[-1]C)+1000"><Data ss:Type="Number">1005</Data></Cell>
    <Cell><Data ss:Type="Boolean">0</Data></Cell>
    <Cell><Data ss:Type="Error">#N/A</Data></Cell>
    <Cell ss:StyleID="money"><Data ss:Type="Number">1200</Data></Cell>
   </Row>
   <Row>
    <Cell><Data ss:Type="String">Commented</Data><Comment ss:Author="Eve"><Data>Be careful here</Data></Comment></Cell>
   </Row>
  </Table>
 </Worksheet>
 <Worksheet ss:Name="Tucked away">
  <Table><Row><Cell><Data ss:Type="String">hidden words</Data></Cell></Row></Table>
  <WorksheetOptions xmlns="urn:schemas-microsoft-com:office:excel"><Visible>SheetHidden</Visible></WorksheetOptions>
 </Worksheet>
 <Worksheet ss:Name="Deeper">
  <Table><Row><Cell><Data ss:Type="String">very hidden words</Data></Cell></Row></Table>
  <WorksheetOptions xmlns="urn:schemas-microsoft-com:office:excel"><Visible>SheetVeryHidden</Visible></WorksheetOptions>
 </Worksheet>
</Workbook>"##;

#[test]
fn xml_spreadsheet_features() {
    let t = of(XMLSS.as_bytes(), Format::SpreadsheetMl);
    assert_eq!(
        t.text,
        "Shown\nSite (https://example.com/x)\ta@b.test\tJump (#Other!A1)\n\
         1005\tFALSE\t#N/A\t1200\nCommented\n\
         Be careful here\n\
         Tucked away\nhidden words\nDeeper\nvery hidden words\n"
    );
    assert_eq!(
        labels(&t),
        [
            "sheet \"Shown\"",
            "sheet \"Shown\" comments",
            "hidden sheet \"Tucked away\"",
            "hidden sheet \"Deeper\""
        ]
    );
    // The formula's source is not text.
    assert!(!t.text.contains("SUM") && !t.text.contains("1000"));
    // A mailto link whose label is its address is not a pair.
    assert_eq!(
        t.links,
        [
            ("Site".to_string(), "https://example.com/x".to_string()),
            ("Jump".to_string(), "#Other!A1".to_string()),
        ]
    );
}

// HTML and SYLK.

#[test]
fn html_links() {
    let html = br#"<html><body><table>
<tr><td><a href="https://example.com/x">Site</a></td><td><a href="https://example.com/">https://example.com/</a></td></tr>
<tr><td>plain</td><td><a href="javascript:alert(1)">trap</a></td></tr>
</table></body></html>"#;
    let t = of(html, Format::Html);
    assert!(
        t.text
            .contains("Site (https://example.com/x)\thttps://example.com/\nplain\ttrap\n"),
        "{}",
        t.text
    );
    assert_eq!(
        t.links,
        [("Site".to_string(), "https://example.com/x".to_string())]
    );
}

#[test]
fn sylk_values() {
    let slk = "ID;PWXL;N;E\r\nC;Y1;X1;K\"Text\"\r\nC;X2;KTRUE;Anote\r\nC;X3;K#N/A\r\n\
C;Y2;X1;K3;E1+2\r\nC;X2;K0.5\r\nE\r\n";
    let t = of(slk.as_bytes(), Format::Sylk);
    assert_eq!(
        labels(&t),
        ["sheet \"Sheet1\"", "sheet \"Sheet1\" comments"]
    );
    assert_eq!(t.text, "Sheet1\nText\tTRUE\t#N/A\n3\t0.5\nnote\n");
}

// Excel 2 to 2003 workbooks, built record by record.

fn rec(id: u16, body: &[u8]) -> Vec<u8> {
    let mut r = id.to_le_bytes().to_vec();
    r.extend((body.len() as u16).to_le_bytes());
    r.extend(body);
    r
}

fn bof(biff8: bool, dt: u16) -> Vec<u8> {
    let v = if biff8 { 0x0600u16 } else { 0x0500 };
    let mut b = v.to_le_bytes().to_vec();
    b.extend(dt.to_le_bytes());
    b.extend([0u8; 4]);
    if biff8 {
        b.extend([0u8; 8]);
    }
    rec(0x0809, &b)
}

fn label(biff8: bool, row: u16, col: u16, s: &str) -> Vec<u8> {
    let mut b = [
        row.to_le_bytes(),
        col.to_le_bytes(),
        0x000Fu16.to_le_bytes(),
    ]
    .concat();
    b.extend((s.len() as u16).to_le_bytes());
    if biff8 {
        b.push(0);
    }
    b.extend(s.as_bytes());
    rec(0x0204, &b)
}

fn number(row: u16, col: u16, v: f64) -> Vec<u8> {
    let mut b = [
        row.to_le_bytes(),
        col.to_le_bytes(),
        0x000Fu16.to_le_bytes(),
    ]
    .concat();
    b.extend(v.to_le_bytes());
    rec(0x0203, &b)
}

fn bool_err(row: u16, col: u16, v: u8, is_err: bool) -> Vec<u8> {
    let mut b = [
        row.to_le_bytes(),
        col.to_le_bytes(),
        0x000Fu16.to_le_bytes(),
    ]
    .concat();
    b.extend([v, is_err as u8]);
    rec(0x0205, &b)
}

/// A formula with a string result: the FORMULA record, then its STRING.
fn formula_string(biff8: bool, row: u16, col: u16, source: &str, cached: &str) -> Vec<u8> {
    let mut rgce = vec![0x17, source.len() as u8];
    if biff8 {
        rgce.push(0);
    }
    rgce.extend(source.as_bytes());
    let mut b = [
        row.to_le_bytes(),
        col.to_le_bytes(),
        0x000Fu16.to_le_bytes(),
    ]
    .concat();
    b.extend([0, 0, 0, 0, 0, 0, 0xFF, 0xFF]);
    b.extend([0u8; 6]);
    b.extend((rgce.len() as u16).to_le_bytes());
    b.extend(rgce);
    let mut out = rec(0x0006, &b);
    let mut s = (cached.len() as u16).to_le_bytes().to_vec();
    if biff8 {
        s.push(0);
    }
    s.extend(cached.as_bytes());
    out.extend(rec(0x0207, &s));
    out
}

/// A BIFF5 note: the text is in the record.
fn note(row: u16, col: u16, s: &str) -> Vec<u8> {
    let mut b = [row.to_le_bytes(), col.to_le_bytes()].concat();
    b.extend((s.len() as u16).to_le_bytes());
    b.extend(s.as_bytes());
    rec(0x001C, &b)
}

fn utf16z(s: &str) -> Vec<u8> {
    let mut b = (s.chars().count() as u32 + 1).to_le_bytes().to_vec();
    for u in s.encode_utf16().chain([0]) {
        b.extend(u.to_le_bytes());
    }
    b
}

/// A BIFF8 hyperlink to a URL, with a display text.
fn hlink(row: u16, col: u16, display: &str, url: &str) -> Vec<u8> {
    let mut b = [row, row, col, col]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<u8>>();
    b.extend([
        0xD0, 0xC9, 0xEA, 0x79, 0xF9, 0xBA, 0xCE, 0x11, 0x8C, 0x82, 0x00, 0xAA, 0x00, 0x4B, 0xA9,
        0x0B,
    ]);
    b.extend(2u32.to_le_bytes());
    // Has a moniker, absolute, has a display text.
    b.extend(0x13u32.to_le_bytes());
    b.extend(utf16z(display));
    b.extend([
        0xE0, 0xC9, 0xEA, 0x79, 0xF9, 0xBA, 0xCE, 0x11, 0x8C, 0x82, 0x00, 0xAA, 0x00, 0x4B, 0xA9,
        0x0B,
    ]);
    let u = utf16z(url);
    b.extend((u.len() as u32 - 4).to_le_bytes());
    b.extend(&u[4..]);
    rec(0x01B8, &b)
}

/// A workbook of `sheets`: name, state (0 visible, 1 hidden, 2 very hidden)
/// and the records of the sheet.
fn workbook(biff8: bool, sheets: &[(&str, u8, Vec<u8>)]) -> Vec<u8> {
    let eof = rec(0x000A, &[]);
    let boundsheet = |pos: u32, state: u8, name: &str| {
        let mut b = pos.to_le_bytes().to_vec();
        b.extend([state, 0, name.len() as u8]);
        if biff8 {
            b.push(0);
        }
        b.extend(name.as_bytes());
        rec(0x0085, &b)
    };
    let subs: Vec<Vec<u8>> = sheets
        .iter()
        .map(|(_, _, body)| {
            let mut s = bof(biff8, 0x10);
            s.extend(body);
            s.extend(&eof);
            s
        })
        .collect();
    let codepage = rec(0x0042, &1252u16.to_le_bytes());
    let head_len = bof(biff8, 5).len()
        + codepage.len()
        + sheets
            .iter()
            .map(|s| boundsheet(0, 0, s.0).len())
            .sum::<usize>()
        + eof.len();
    let mut g = bof(biff8, 5);
    g.extend(codepage);
    let mut pos = head_len;
    for (i, (name, state, _)) in sheets.iter().enumerate() {
        g.extend(boundsheet(pos as u32, *state, name));
        pos += subs[i].len();
    }
    g.extend(&eof);
    assert_eq!(g.len(), head_len);
    for s in subs {
        g.extend(s);
    }
    g
}

#[test]
fn biff5_features() {
    let mut open = vec![];
    open.extend(label(false, 0, 0, "Hello"));
    open.extend(number(0, 1, 2.5));
    open.extend(bool_err(1, 0, 1, false));
    open.extend(bool_err(1, 1, 0x07, true));
    open.extend(formula_string(false, 2, 0, "source words", "cached words"));
    open.extend(note(0, 0, "check me"));
    let mut stash = vec![];
    stash.extend(label(false, 0, 0, "hidden words"));
    let wb = workbook(false, &[("Open", 0, open), ("Stash", 1, stash)]);
    let t = of(&wb, Format::Xls);
    assert_eq!(
        t.text,
        "Open\nHello\t2.5\nTRUE\t#DIV/0!\ncached words\ncheck me\nStash\nhidden words\n"
    );
    assert_eq!(
        labels(&t),
        [
            "sheet \"Open\"",
            "sheet \"Open\" comments",
            "hidden sheet \"Stash\""
        ]
    );
    assert!(!t.text.contains("source words"));
}

#[test]
fn biff8_features() {
    let mut open = vec![];
    open.extend(label(true, 0, 0, "Docs"));
    open.extend(hlink(0, 0, "Docs", "https://example.com/docs"));
    open.extend(label(true, 1, 0, "https://example.com/"));
    open.extend(hlink(1, 0, "https://example.com/", "https://example.com/"));
    open.extend(formula_string(true, 2, 0, "source words", "cached words"));
    let mut deeper = vec![];
    deeper.extend(label(true, 0, 0, "very hidden words"));
    let wb = workbook(true, &[("Open", 0, open), ("Deeper", 2, deeper)]);
    let t = of(&wb, Format::Xls);
    assert_eq!(
        t.text,
        "Open\nDocs (https://example.com/docs)\nhttps://example.com/\ncached words\n\
         Deeper\nvery hidden words\n"
    );
    assert_eq!(labels(&t), ["sheet \"Open\"", "hidden sheet \"Deeper\""]);
    assert_eq!(
        t.links,
        [("Docs".to_string(), "https://example.com/docs".to_string())]
    );
}

#[test]
fn an_encrypted_workbook_is_refused() {
    for filepass in [
        // RC4 with a verifier of another password.
        [&1u16.to_le_bytes()[..], &[1, 0, 1, 0], &[0x5Au8; 48]].concat(),
        // XOR with another key.
        [&0u16.to_le_bytes()[..], &[0x34, 0x12, 0x78, 0x56]].concat(),
    ] {
        let mut s = bof(true, 5);
        s.extend(rec(0x002F, &filepass));
        s.extend(rec(0x000A, &[]));
        let e = text(&s, Format::Xls, &Limits::default(), CAP).unwrap_err();
        assert_eq!(e, Error::Encrypted);
    }
}

// Refusals and limits.

#[test]
fn the_wrong_format_is_refused() {
    let l = Limits::default();
    let xls = fixture("sample.xls");
    assert!(matches!(
        text(&xls, Format::Ods, &l, CAP),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        text(&xls, Format::Numbers, &l, CAP),
        Err(Error::NotFormat(_))
    ));
    let ods = fixture("sample.ods");
    assert!(matches!(
        text(&ods, Format::Xls, &l, CAP),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        text(b"", Format::Fods, &l, CAP),
        Err(Error::NotFormat(_) | Error::Malformed(_))
    ));
}

#[test]
fn damaged_documents_are_refused() {
    let l = Limits::default();
    // The compound file's signature, then nothing.
    let mut cfb = fixture("sample.xls")[..8].to_vec();
    cfb.extend([0u8; 600]);
    assert!(matches!(
        text(&cfb, Format::Xls, &l, CAP),
        Err(Error::Malformed(_) | Error::Unsupported(_))
    ));
    // A workbook cut inside its directory, and one with its sectors erased.
    let xls = fixture("sample.xls");
    let mut erased = xls.clone();
    erased[512..1024].fill(0xFF);
    for d in [&xls[..600], &erased[..]] {
        let r = text(d, Format::Xls, &l, CAP);
        assert!(matches!(r, Err(Error::Malformed(_))), "{r:?}");
    }
    // XML cut short.
    let truncated = text(&fods()[..400], Format::Fods, &l, CAP);
    assert!(
        matches!(truncated, Err(Error::Malformed(_))),
        "{truncated:?}"
    );
    let xml = br#"<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"><Worksheet"#;
    let r = text(xml, Format::SpreadsheetMl, &l, CAP);
    assert!(matches!(r, Err(Error::Malformed(_))), "{r:?}");
    let junk = zip(&[
        (
            "mimetype",
            b"application/vnd.oasis.opendocument.spreadsheet",
        ),
        ("content.xml", b"<office:document-content><oops"),
    ]);
    let r = text(&junk, Format::Ods, &l, CAP);
    assert!(matches!(r, Err(Error::Malformed(_))), "{r:?}");
}

#[test]
fn every_truncation_is_read_or_refused() {
    for (name, format) in ALL {
        let data = fixture(name);
        let step = (data.len() / 200).max(1);
        for n in (0..data.len()).step_by(step) {
            let _ = text(&data[..n], format, &Limits::default(), CAP);
        }
    }
}

#[test]
fn limits_are_kept() {
    for (name, format) in ALL {
        let data = fixture(name);
        let cap = CAP;
        let r = |l: Limits| text(&data, format, &l, cap).unwrap_err();
        assert_eq!(
            r(Limits::default().with_max_cells(5)),
            Error::TooLarge("cells"),
            "{name}"
        );
        assert_eq!(
            r(Limits::default().with_max_memory(2000)),
            Error::TooLarge("memory"),
            "{name}"
        );
        let mut small = Limits::default();
        small.max_input = 100;
        assert_eq!(r(small), Error::TooLarge("input"), "{name}");
        // The converter refuses the same.
        assert_eq!(
            convert(&data, format, &Limits::default().with_max_cells(5)).unwrap_err(),
            Error::TooLarge("cells")
        );
    }
}

// The cap.

#[test]
fn the_cap_cuts_the_text() {
    for (name, format) in ALL {
        let data = fixture(name);
        let full = of(&data, format);
        assert!(!full.truncated, "{name}");
        let short = [0, 1, 7, 20, 64, 150, full.text.len() - 1];
        for cap in short.into_iter().filter(|&c| c < full.text.len()) {
            let t = text(&data, format, &Limits::default(), cap).unwrap();
            assert!(t.text.len() <= cap, "{name} at {cap}: {}", t.text.len());
            assert!(t.truncated, "{name} at {cap}");
            assert!(full.text.starts_with(&t.text), "{name} at {cap}");
        }
        for cap in [full.text.len(), full.text.len() + 1] {
            let t = text(&data, format, &Limits::default(), cap).unwrap();
            assert_eq!(t.text, full.text, "{name} at {cap}");
            assert!(!t.truncated, "{name} at {cap}");
        }
    }
}
