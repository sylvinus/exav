//! Documents written here in the shape the samples have.

use super::*;
use crate::formats::office::sheets::limits::Limits;

const T1: &str = "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A";
const T2: &str = "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B";

/// A document: the stylesheet's styles, then the workspaces' XML.
fn doc(styles: &str, workspaces: &str) -> String {
    format!(
        r#"<?xml version="1.0"?>
<ls:document xmlns:ls="http://developer.apple.com/namespaces/ls" xmlns:sf="http://developer.apple.com/namespaces/sf" xmlns:sfa="http://developer.apple.com/namespaces/sfa" ls:version="92008102400">
<ls:stylesheet sfa:ID="ss-0"><sf:styles>{styles}</sf:styles></ls:stylesheet>
<ls:workspace-array>{workspaces}</ls:workspace-array>
<ls:tabular-prototypes><sf:tabular-info><sf:tabular-model sf:name="Unnamed Table" sf:id="FFFF"><sf:grid sf:numcols="1" sf:numrows="1"><sf:datasource><sf:t><sf:ct sfa:s="prototype"/></sf:t></sf:datasource></sf:grid></sf:tabular-model></sf:tabular-info>
<sf:paragraphstyle sfa:ID="proto-para" sf:ident="para-body"><sf:property-map><sf:fontName><sf:string sfa:string="Zapfino"/></sf:fontName></sf:property-map></sf:paragraphstyle>
</ls:tabular-prototypes>
</ls:document>"#
    )
}

fn workspace(name: &str, tables: &str) -> String {
    format!(
        r#"<ls:workspace ls:workspace-name="{name}"><ls:page-info><sf:layers><sf:layer><sf:drawables>{tables}</sf:drawables></sf:layer></sf:layers></ls:page-info></ls:workspace>"#
    )
}

/// A table: `attrs` on the model, `grid` the grid's children.
fn table(attrs: &str, rows: u32, cols: u32, grid: &str) -> String {
    format!(
        r#"<sf:tabular-info><sf:tabular-model {attrs}><sf:grid sf:numcols="{cols}" sf:numrows="{rows}">{grid}</sf:grid></sf:tabular-model></sf:tabular-info>"#
    )
}

fn read_str(xml: &str) -> Workbook {
    read(xml.as_bytes(), &mut Budget::new(Limits::default())).unwrap()
}

fn value(s: &Sheet, r: u32, c: u32) -> &Value {
    s.cells.get(&(r, c)).map_or(&Value::Empty, |c| &c.value)
}

fn style<'a>(wb: &'a Workbook, s: &Sheet, r: u32, c: u32) -> &'a Style {
    wb.styles.get(s.cells[&(r, c)].style)
}

const NUMBER_STYLES: &str = r##"
<sf:cell-style sfa:ID="cur"><sf:property-map>
  <sf:SFTCellStylePropertyFormatType><sf:number sfa:number="257" sfa:type="i"/></sf:SFTCellStylePropertyFormatType>
  <sf:SFTCellStylePropertyNumberFormat><sf:number-format sf:format-type="1" sf:format-string="&#xA4;#,##0.00;(&#xA4;#,##0.00)" sf:format-decimal-places="2" sf:format-currency-code="EUR" sf:format-negative-style="0" sf:format-show-thousands-separator="true" sf:format-fraction-accuracy="-1" sf:format-use-accounting-style="true"/></sf:SFTCellStylePropertyNumberFormat>
</sf:property-map></sf:cell-style>
<sf:cell-style sfa:ID="auto"><sf:property-map>
  <sf:SFTCellStylePropertyFormatType><sf:number sfa:number="255" sfa:type="i"/></sf:SFTCellStylePropertyFormatType>
  <sf:SFTCellStylePropertyNumberFormat><sf:number-format sf:format-type="0" sf:format-string="#,##0.###;-#,##0.###" sf:format-decimal-places="0" sf:format-show-thousands-separator="true"/></sf:SFTCellStylePropertyNumberFormat>
  <sf:SFTCellStylePropertyDateTimeFormat><sf:date-format sfa:ID="df" sf:fmt="M/d/yy"/></sf:SFTCellStylePropertyDateTimeFormat>
</sf:property-map></sf:cell-style>"##;

/// Sheet 1, table T1 (5 rows, 3 columns, a header row and a footer row),
/// and T2, one cell.
fn budget_doc() -> String {
    let t1 = table(
        &format!(
            r#"sf:name="T1" sf:id="{T1}" sf:num-header-rows="1" sf:num-header-columns="0" sf:num-footer-rows="1" sf:header-rows-frozen="true" sf:header-columns-frozen="false""#
        ),
        5,
        3,
        r#"<sf:columns><sf:grid-column sf:width="72"/><sf:grid-column sf:width="144"/><sf:grid-column sf:width="0"/></sf:columns>
<sf:rows><sf:grid-row sf:height="20"/><sf:grid-row sf:height="30"/></sf:rows>
<sf:datasource>
<sf:t sf:ct="0" sf:col-span="2"><sf:ct sfa:s="Head"/></sf:t>
<sf:s sf:ho="1"/>
<sf:g/>
<sf:n sf:ct="254" sf:s="cur" sf:v="1.5"/>
<sf:d sf:s="auto" sf:cell-date="276048000"/>
<sf:cb sf:f="0"/>
<sf:pm sf:ct="254"><sf:menu-choices><sf:t sfa:ID="ch1"><sf:ct sfa:s="Home"/></sf:t><sf:n sfa:ID="ch2" sf:v="7"/></sf:menu-choices><sf:proxied-cell-ref sfa:IDREF="ch2"/></sf:pm>
<sf:n sf:s="auto" sf:v="1234.5"/>
<sf:n sf:ct="255" sf:s="auto" sf:v="0.5"><sf:cf sf:implicit-format-type="256"><sf:number-format sf:format-type="0" sf:format-decimal-places="1" sf:format-show-thousands-separator="false"/></sf:cf></sf:n>
<sf:f sf:ct="256"><sf:fo sf:fs="=SUM(A)" sf:ht="0A" sf:hc="1024"/><sf:r><sf:rn sf:v="5"/></sf:r></sf:f>
<sf:f><sf:fo sf:fs="=A2×2≠3"/><sf:r><sf:rn sf:v="1"/></sf:r></sf:f>
<sf:f><sf:fo sf:fs="=__CHART(A1)"/><sf:r><sf:rs><sf:ct sfa:s="kept"/></sf:rs></sf:r></sf:f>
</sf:datasource>"#,
    );
    let t2 = table(
        &format!(r#"sf:name="T2" sf:id="{T2}""#),
        1,
        2,
        &format!(
            r#"<sf:datasource><sf:f><sf:fo sf:fs="=SUM(SFTGlobalID_{T1} :: B)+SFTGlobalID_{T1}::$A$2"/><sf:r><sf:rn sf:v="9"/></sf:r></sf:f><sf:f><sf:fo sf:fs="=ifs(B1,1)"/><sf:r><sf:rn sf:v="1"/></sf:r></sf:f></sf:datasource>"#
        ),
    );
    doc(
        NUMBER_STYLES,
        &(workspace("Budget", &(t1 + &t2))
            + &workspace("Notes", &table(r#"sf:name="Table 1" sf:id="0C""#, 1, 1, ""))),
    )
}

#[test]
fn tables_become_sheets() {
    let wb = read_str(&budget_doc());
    let names: Vec<&str> = wb.sheets.iter().map(|s| s.name.as_str()).collect();
    // A sheet's only table takes the sheet's name; prototypes are left out.
    assert_eq!(names, ["Budget - T1", "Budget - T2", "Notes"]);
}

#[test]
fn cells_and_positions() {
    let wb = read_str(&budget_doc());
    let s = &wb.sheets[0];
    assert_eq!(value(s, 0, 0), &Value::text("Head"));
    assert_eq!(value(s, 1, 0), &Value::Number(1.5));
    // 2009-10-01.
    assert_eq!(value(s, 1, 1), &Value::Number(40087.0));
    assert_eq!(value(s, 1, 2), &Value::Bool(false));
    // The pop-up menu's chosen item.
    assert_eq!(value(s, 2, 0), &Value::Number(7.0));
    assert_eq!(value(s, 2, 1), &Value::Number(1234.5));
    assert_eq!(value(s, 3, 0), &Value::Number(0.5));
    assert_eq!(value(s, 4, 0), &Value::Number(5.0));
    assert_eq!(value(s, 4, 2), &Value::text("kept"));
    assert_eq!(
        s.merges,
        [Range {
            r1: 0,
            c1: 0,
            r2: 0,
            c2: 1
        }]
    );
}

#[test]
fn number_formats() {
    let wb = read_str(&budget_doc());
    let s = &wb.sheets[0];
    assert_eq!(
        style(&wb, s, 1, 0).numfmt,
        "\"€\"* #,##0.00;\"€\"* (#,##0.00)"
    );
    assert_eq!(style(&wb, s, 1, 1).numfmt, "m/d/yy");
    // Automatic: General, whatever number format the style keeps.
    assert_eq!(style(&wb, s, 2, 1).numfmt, Style::default().numfmt);
    // The format Numbers chose for an automatic cell.
    assert_eq!(style(&wb, s, 3, 0).numfmt, "0.0");
}

#[test]
fn formulas() {
    let wb = read_str(&budget_doc());
    let f = |s: usize, r, c| {
        wb.sheets[s].cells[&(r, c)]
            .formula
            .as_deref()
            .map(str::to_string)
    };
    // A whole column is its body rows.
    assert_eq!(f(0, 4, 0).as_deref(), Some("SUM(A$2:A$4)"));
    assert_eq!(f(0, 4, 1).as_deref(), Some("A2*2<>3"));
    // A chart's formula has no Excel form: its value stays.
    assert_eq!(f(0, 4, 2), None);
    assert_eq!(
        f(1, 0, 0).as_deref(),
        Some("SUM('Budget - T1'!B$2:B$4)+'Budget - T1'!$A$2")
    );
    assert_eq!(f(1, 0, 1).as_deref(), Some("_xlfn.IFS(B1,1)"));
    assert!(wb.warnings.iter().any(|w| w.starts_with("1 formulas")));
}

#[test]
fn sizes_and_panes() {
    let wb = read_str(&budget_doc());
    let s = &wb.sheets[0];
    assert_eq!(
        s.col_info(1).and_then(|c| c.width),
        Some(width_chars(144.0))
    );
    assert!(s.col_info(2).unwrap().hidden);
    assert_eq!(s.rows[&1].height, Some(30.0));
    assert_eq!(s.freeze, Some((1, 0)));
    assert_eq!(wb.sheets[1].freeze, None);
}

/// A table of one row of `cells` (each `<sf:t sf:s=...>`) in a document of
/// `styles`, with `extra` in the model.
fn styled(styles: &str, extra: &str, rows: u32, cols: u32, cells: &str) -> Workbook {
    let t = format!(
        r#"<sf:tabular-info><sf:tabular-model sf:name="T" sf:id="0D" sf:num-header-rows="1">{extra}<sf:grid sf:numcols="{cols}" sf:numrows="{rows}"><sf:datasource>{cells}</sf:datasource></sf:grid></sf:tabular-model></sf:tabular-info>"#
    );
    read_str(&doc(styles, &workspace("S", &t)))
}

const CELL_STYLES: &str = r#"
<sf:paragraphstyle sfa:ID="p-body" sf:ident="para-body"><sf:property-map>
  <sf:fontName><sf:string sfa:string="Cochin-Bold"/></sf:fontName>
  <sf:fontSize><sf:number sfa:number="11" sfa:type="i"/></sf:fontSize>
  <sf:alignment><sf:number sfa:number="2" sfa:type="i"/></sf:alignment>
</sf:property-map></sf:paragraphstyle>
<sf:cell-style sfa:ID="c-base" sf:ident="cell-body"><sf:property-map>
  <sf:fill><sf:color xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="sfa:calibrated-rgb-color-type" sfa:r="1" sfa:g="0" sfa:b="0" sfa:a="0.5"/></sf:fill>
  <sf:SFTCellTextWrapProperty><sf:number sfa:number="0" sfa:type="c"/></sf:SFTCellTextWrapProperty>
  <sf:SFTCellStylePropertyParagraphStyle><sf:paragraphstyle-ref sfa:IDREF="p-body"/></sf:SFTCellStylePropertyParagraphStyle>
</sf:property-map></sf:cell-style>
<sf:cell-style sfa:ID="c-none" sf:parent-ident="cell-body"><sf:property-map><sf:fill><sf:null/></sf:fill></sf:property-map></sf:cell-style>
<sf:cell-style sfa:ID="c-inherit" sf:parent-ident="cell-body"><sf:property-map><sf:fill/>
  <sf:SFTCellStylePropertyParagraphStyle><sf:paragraphstyle sf:parent-ident="para-body"><sf:property-map><sf:bold><sf:number sfa:number="1" sfa:type="i"/></sf:bold><sf:fontColor><sf:color sfa:w="0.5" sfa:a="1"/></sf:fontColor></sf:property-map></sf:paragraphstyle></sf:SFTCellStylePropertyParagraphStyle>
</sf:property-map></sf:cell-style>"#;

#[test]
fn cell_styles() {
    let wb = styled(
        CELL_STYLES,
        "",
        1,
        3,
        r#"<sf:t sf:s="c-base"><sf:ct sfa:s="a"/></sf:t><sf:t sf:s="c-none"><sf:ct sfa:s="b"/></sf:t><sf:t sf:s="c-inherit"><sf:ct sfa:s="c"/></sf:t>"#,
    );
    let s = &wb.sheets[0];
    let base = style(&wb, s, 0, 0);
    // Half-transparent red over white.
    assert_eq!(base.fill, Fill::solid(0xFF8080));
    assert!(!base.align.wrap);
    assert_eq!(base.align.horizontal, Some("center"));
    // The face the name says, the weight `sf:bold` says; the document's
    // style, not the prototype's of the same ident.
    assert_eq!(
        (
            base.font.name.as_str(),
            base.font.bold,
            base.font.size_centipt
        ),
        ("Cochin", false, 1100)
    );
    // An explicit null clears the fill; an empty property inherits it.
    assert_eq!(style(&wb, s, 0, 1).fill, Fill::default());
    let inherit = style(&wb, s, 0, 2);
    assert_eq!(inherit.fill, Fill::solid(0xFF8080));
    assert!(inherit.font.bold);
    assert_eq!(inherit.font.name, "Cochin");
    assert_eq!(inherit.font.color, Some(0x808080));
}

const TABLE_STYLE: &str = r#"
<sf:vector-style sfa:ID="thin-grey" sf:ident="v-body"><sf:property-map><sf:SFTStrokeProperty><sf:stroke sf:width="1"><sf:pattern sf:type="solid"/><sf:color sfa:r="0.8" sfa:g="0.8" sfa:b="0.8" sfa:a="1"/></sf:stroke></sf:SFTStrokeProperty></sf:property-map></sf:vector-style>
<sf:vector-style sfa:ID="thick-red"><sf:property-map><sf:SFTStrokeProperty><sf:stroke sf:width="3"><sf:pattern sf:type="solid"/><sf:color sfa:r="1" sfa:g="0" sfa:b="0" sfa:a="1"/></sf:stroke></sf:SFTStrokeProperty></sf:property-map></sf:vector-style>
<sf:vector-style sfa:ID="none"><sf:property-map><sf:SFTStrokeProperty><sf:stroke sf:width="1"><sf:pattern sf:type="empty"/><sf:color sfa:r="0" sfa:g="0" sfa:b="0" sfa:a="1"/></sf:stroke></sf:SFTStrokeProperty></sf:property-map></sf:vector-style>
<sf:tabular-style sfa:ID="ts"><sf:property-map>
  <sf:SFTTableBandedRowsProperty><sf:number sfa:number="1" sfa:type="c"/></sf:SFTTableBandedRowsProperty>
  <sf:SFTTableBandedCellFillProperty><sf:color sfa:r="0" sfa:g="0" sfa:b="1" sfa:a="1"/></sf:SFTTableBandedCellFillProperty>
  <sf:SFTDefaultBodyVectorStyleProperty><sf:vector-style-ref sfa:IDREF="thin-grey"/></sf:SFTDefaultBodyVectorStyleProperty>
  <sf:SFTDefaultBorderVectorStyleProperty><sf:vector-style-ref sfa:IDREF="thick-red"/></sf:SFTDefaultBorderVectorStyleProperty>
  <sf:SFTDefaultHeaderRowCellStyleProperty><sf:cell-style><sf:property-map><sf:fill><sf:color sfa:r="0" sfa:g="1" sfa:b="0" sfa:a="1"/></sf:fill></sf:property-map></sf:cell-style></sf:SFTDefaultHeaderRowCellStyleProperty>
</sf:property-map></sf:tabular-style>"#;

#[test]
fn table_style_lines_bands_and_regions() {
    // 4 rows (a header row), 2 columns; the data source lists one cell.
    let wb = styled(
        TABLE_STYLE,
        r#"<sf:tabular-style-ref sfa:IDREF="ts"/>"#,
        4,
        2,
        r#"<sf:n sf:ct="257" sf:v="1"/>"#,
    );
    let s = &wb.sheets[0];
    let grey = Edge {
        style: Some("thin"),
        color: Some(0xCCCCCC),
    };
    let red = Edge {
        style: Some("thick"),
        color: Some(0xFF0000),
    };
    // (1, 1): body; the border on its right, body lines elsewhere.
    let b = &style(&wb, s, 1, 1).border;
    assert_eq!(
        (&b.top, &b.right, &b.bottom, &b.left),
        (&grey, &red, &grey, &grey)
    );
    // Cells the data source leaves out take their region's style.
    assert_eq!(style(&wb, s, 0, 0).fill, Fill::solid(0x00FF00));
    assert_eq!(style(&wb, s, 0, 0).border.top, red);
    // Bands: the second body row and every second after it.
    assert_eq!(style(&wb, s, 1, 1).fill, Fill::default());
    assert_eq!(style(&wb, s, 2, 0).fill, Fill::solid(0x0000FF));
    assert_eq!(style(&wb, s, 3, 0).fill, Fill::default());
}

#[test]
fn gridline_runs_override_the_table_style() {
    // A thick red line left of column 1 on row 0 only, and an empty line
    // above row 1 over both columns.
    let grid = r#"<sf:vertical-gridline-styles><sf:style-run sf:gridline-index="1"><sf:vector-style-ref sfa:IDREF="thick-red" sf:start-index="0" sf:stop-index="1"/></sf:style-run></sf:vertical-gridline-styles>
<sf:horizontal-gridline-styles><sf:style-run sf:gridline-index="1"><sf:vector-style-ref sfa:IDREF="none" sf:start-index="0" sf:stop-index="2"/></sf:style-run></sf:horizontal-gridline-styles>"#;
    let t = format!(
        r#"<sf:tabular-info><sf:tabular-model sf:name="T" sf:id="0D"><sf:tabular-style-ref sfa:IDREF="ts"/><sf:grid sf:numcols="2" sf:numrows="2">{grid}<sf:datasource><sf:n sf:v="1"/><sf:n sf:v="2"/><sf:n sf:ct="255" sf:v="3"/><sf:n sf:v="4"/></sf:datasource></sf:grid></sf:tabular-model></sf:tabular-info>"#
    );
    let wb = read_str(&doc(TABLE_STYLE, &workspace("S", &t)));
    let s = &wb.sheets[0];
    let red = Edge {
        style: Some("thick"),
        color: Some(0xFF0000),
    };
    assert_eq!(style(&wb, s, 0, 0).border.right, red);
    assert_eq!(style(&wb, s, 0, 1).border.left, red);
    assert_eq!(style(&wb, s, 1, 0).border.right, Edge::default());
    assert_eq!(style(&wb, s, 0, 0).border.bottom, Edge::default());
    // No table style line where runs are given.
    assert_eq!(style(&wb, s, 0, 0).border.top, Edge::default());
}

#[test]
fn packages() {
    use std::io::Write;
    let xml = budget_doc();
    let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::fast());
    gz.write_all(xml.as_bytes()).unwrap();
    let gz = gz.finish().unwrap();
    let zip = |files: &[(&str, &[u8])]| {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(vec![]));
        for (n, d) in files {
            z.start_file(*n, zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(d).unwrap();
        }
        z.finish().unwrap().into_inner()
    };
    let b = || Budget::new(Limits::default());
    for z in [
        zip(&[("index.xml", xml.as_bytes())]),
        zip(&[
            ("Doc.numbers/Contents/index.xml", b"<x/>"),
            ("Doc.numbers/index.xml.gz", &gz),
        ]),
    ] {
        assert_eq!(super::super::read(&z, &mut b()).unwrap().sheets.len(), 3);
    }
    let dir: &[(&str, &[u8])] = &[("QuickLook/Thumbnail.jpg", b"x"), ("index.xml.gz", &gz)];
    assert_eq!(
        super::super::read_package(dir, &mut b())
            .unwrap()
            .sheets
            .len(),
        3
    );
    // Gzip that inflates past the part limit.
    let small = Limits {
        max_part: (gz.len() + xml.len()) as u64 / 2,
        ..Limits::default()
    };
    assert_eq!(
        super::super::read(&zip(&[("index.xml.gz", &gz)]), &mut Budget::new(small)).unwrap_err(),
        Error::TooLarge("a package part")
    );
}

#[test]
fn refusals_and_limits() {
    let b = || Budget::new(Limits::default());
    assert!(matches!(
        read(b"<plist/>", &mut b()),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        read(doc("", "").as_bytes(), &mut b()),
        Err(Error::Unsupported(_))
    ));
    let few = Limits::default().with_max_cells(5);
    assert_eq!(
        read(budget_doc().as_bytes(), &mut Budget::new(few)).unwrap_err(),
        Error::TooLarge("cells")
    );
}

#[test]
fn damaged_documents_do_not_panic() {
    let xml = budget_doc();
    let b = xml.as_bytes();
    for cut in (0..b.len()).step_by(97) {
        let _ = read(&b[..cut], &mut Budget::new(Limits::default()));
    }
    // Hostile numbers and references.
    for cells in [
        r#"<sf:n sf:ct="-5" sf:v="1"/>"#,
        r#"<sf:n sf:ct="99999999999999999999" sf:v="1"/>"#,
        r#"<sf:t sf:col-span="4294967295" sf:row-span="4294967295"><sf:ct sfa:s="x"/></sf:t>"#,
        r#"<sf:f><sf:fo sf:fs="=SFTGlobalID_DEAD :: A1+ZZZZ9999999999+&quot;"/></sf:f>"#,
        r#"<sf:pm><sf:proxied-cell-ref sfa:IDREF="nowhere"/></sf:pm>"#,
        r#"<sf:d sf:cell-date="1e308"/><sf:n sf:v="NaN"/>"#,
    ] {
        let t = table(
            r#"sf:name="T" sf:id="0D""#,
            3,
            3,
            &format!("<sf:datasource>{cells}</sf:datasource>"),
        );
        let _ = read(
            doc("", &workspace("S", &t)).as_bytes(),
            &mut Budget::new(Limits::default()),
        );
    }
    // A style that is its own parent.
    let loop_styles = r#"<sf:cell-style sfa:ID="l" sf:ident="l" sf:parent-ident="l"><sf:property-map><sf:fill/></sf:property-map></sf:cell-style>"#;
    let wb = styled(
        loop_styles,
        "",
        1,
        1,
        r#"<sf:t sf:s="l"><sf:ct sfa:s="x"/></sf:t>"#,
    );
    assert_eq!(wb.sheets[0].cells.len(), 1);
}
