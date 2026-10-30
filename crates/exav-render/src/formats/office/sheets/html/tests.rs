use super::*;
use crate::formats::office::sheets::limits::Limits;

fn read_str(s: &str) -> Workbook {
    read(s.as_bytes(), &mut Budget::new(Limits::default())).unwrap()
}

fn value(s: &crate::formats::office::sheets::model::Sheet, r: u32, c: u32) -> &Value {
    s.cells.get(&(r, c)).map_or(&Value::Empty, |c| &c.value)
}

fn style<'a>(
    wb: &'a Workbook,
    s: &crate::formats::office::sheets::model::Sheet,
    r: u32,
    c: u32,
) -> &'a Style {
    wb.styles.get(s.cells[&(r, c)].style)
}

/// A worksheet as Excel saves it as a web page, cut down.
const EXCEL: &str = r##"<html xmlns:o="urn:schemas-microsoft-com:office:office"
xmlns:x="urn:schemas-microsoft-com:office:excel"
xmlns="http://www.w3.org/TR/REC-html40">
<head>
<meta http-equiv=Content-Type content="text/html; charset=windows-1252">
<meta name=ProgId content=Excel.Sheet>
<style>
<!--table
	{mso-displayed-decimal-separator:"\.";
	mso-displayed-thousand-separator:"\,";}
.style0
	{mso-number-format:General;
	text-align:general;
	vertical-align:bottom;
	white-space:nowrap;
	color:windowtext;
	font-size:10.0pt;
	font-weight:400;
	font-family:Arial;
	border:none;}
td
	{mso-style-parent:style0;
	padding-top:1px;
	color:windowtext;
	font-size:10.0pt;
	font-family:Arial;
	mso-number-format:General;
	white-space:nowrap;}
.xl24
	{mso-style-parent:style0;
	font-weight:700;
	text-align:center;
	border-top:none;
	border-right:none;
	border-bottom:.5pt solid windowtext;
	border-left:none;
	background:yellow;
	mso-pattern:auto none;}
.xl25
	{mso-style-parent:style0;
	mso-number-format:"\0022$\0022\#\,\#\#0\.00";}
.xl26
	{mso-style-parent:style0;
	mso-number-format:"Short Date";}
.xl27
	{mso-style-parent:style0;
	mso-number-format:"\@";
	white-space:normal;}
-->
</style>
<!--[if gte mso 9]><xml>
 <x:ExcelWorkbook>
  <x:ExcelWorksheets>
   <x:ExcelWorksheet>
    <x:Name>Budget &amp; Plan</x:Name>
    <x:WorksheetOptions>
     <x:FreezePanes/>
     <x:SplitHorizontal>1</x:SplitHorizontal>
     <x:DoNotDisplayGridlines/>
    </x:WorksheetOptions>
   </x:ExcelWorksheet>
  </x:ExcelWorksheets>
 </x:ExcelWorkbook>
</xml><![endif]-->
</head>
<body link=blue vlink=purple>
<table x:str border=0 cellpadding=0 cellspacing=0 width=355 style='border-collapse:collapse;table-layout:fixed;width:267pt'>
 <col width=98 style='mso-width-source:userset;width:74pt'>
 <col width=64 span=2 style='width:48pt'>
 <col width=0 style='display:none'>
 <tr height=34 style='height:25.5pt'>
  <td height=34 class=xl24 width=98 style='height:25.5pt;width:74pt'>Item</td>
  <td class=xl24 colspan=2 style='border-left:none'>Amount</td>
  <td colspan=2 style='mso-ignore:colspan'>overflowing text</td>
 </tr>
 <tr height=17 style='height:12.75pt'>
  <td height=17>Rent</td>
  <td class=xl25 align=right x:num="1234.5">$1,234.50</td>
  <td class=xl26 align=right x:num="40087">10/1/2009</td>
  <td class=xl27 x:str="0042">0042</td>
 </tr>
 <tr height=17 style='height:12.75pt'>
  <td rowspan=2 height=34>Total</td>
  <td align=right x:num x:fmla="=SUM(B2:B2)">1234.5</td>
  <td x:bool="TRUE">TRUE</td>
  <td x:err="#DIV/0!" x:fmla="=1/0">#DIV/0!</td>
 </tr>
 <tr height=17 style='height:12.75pt;display:none'>
  <td x:num>1,000</td>
  <td><a href="https://example.com/">a link</a></td>
  <td>line<br style='mso-data-placement:same-cell'>two</td>
 </tr>
</table>
</body>
</html>
"##;

#[test]
fn excel_values() {
    let wb = read_str(EXCEL);
    let s = &wb.sheets[0];
    assert_eq!(s.name, "Budget & Plan");
    assert_eq!(value(s, 0, 0), &Value::text("Item"));
    assert_eq!(value(s, 0, 1), &Value::text("Amount"));
    // After a two-column cell, the next is in the fourth column.
    assert_eq!(value(s, 0, 3), &Value::text("overflowing text"));
    assert_eq!(value(s, 1, 1), &Value::Number(1234.5));
    assert_eq!(value(s, 1, 2), &Value::Number(40087.0));
    // x:str on the table: text, here a number's digits kept.
    assert_eq!(value(s, 1, 3), &Value::text("0042"));
    assert_eq!(value(s, 2, 2), &Value::Bool(true));
    assert_eq!(value(s, 2, 3), &Value::Error(CellError::Div0));
    // The row span pushes the next row's cells right.
    assert_eq!(value(s, 3, 1), &Value::Number(1000.0));
    assert_eq!(value(s, 3, 2), &Value::text("a link"));
    assert_eq!(value(s, 3, 3), &Value::text("line\ntwo"));
    let f = |r, c| s.cells[&(r, c)].formula.as_deref().map(str::to_string);
    assert_eq!(f(2, 1).as_deref(), Some("SUM(B2:B2)"));
    assert_eq!(f(2, 3).as_deref(), Some("1/0"));
    assert_eq!(s.hyperlinks[0].url.as_deref(), Some("https://example.com/"));
}

#[test]
fn excel_merges_sizes_options() {
    let wb = read_str(EXCEL);
    let s = &wb.sheets[0];
    // A column span merges; one Excel marks mso-ignore:colspan does not.
    assert_eq!(
        s.merges,
        [
            Range {
                r1: 0,
                c1: 1,
                r2: 0,
                c2: 2
            },
            Range {
                r1: 2,
                c1: 0,
                r2: 3,
                c2: 0
            }
        ]
    );
    // 98 pixels: 13.29 characters of 7 pixels after 5 of padding, stored
    // with the padding.
    assert_eq!(s.col_info(0).and_then(|c| c.width), Some(3585.0 / 256.0));
    assert_eq!(s.col_info(2).and_then(|c| c.width), Some(9.140625));
    assert!(s.col_info(3).unwrap().hidden);
    assert_eq!(s.rows[&0].height, Some(25.5));
    assert!(s.rows[&3].hidden);
    assert_eq!(s.freeze, Some((1, 0)));
    assert!(!s.show_grid);
}

#[test]
fn excel_styles() {
    let wb = read_str(EXCEL);
    let s = &wb.sheets[0];
    assert_eq!(
        (
            wb.styles.get(0).font.name.as_str(),
            wb.styles.get(0).font.size_centipt
        ),
        ("Arial", 1000)
    );
    let head = style(&wb, s, 0, 0);
    assert!(head.font.bold);
    assert_eq!(head.align.horizontal, Some("center"));
    assert_eq!(head.fill, Fill::solid(0xFFFF00));
    assert_eq!(head.border.bottom.style, Some("thin"));
    assert_eq!(head.border.top.style, None);
    // CSS escapes resolved: Excel's format code.
    assert_eq!(style(&wb, s, 1, 1).numfmt, "\"$\"#,##0.00");
    assert_eq!(style(&wb, s, 1, 2).numfmt, "m/d/yyyy");
    assert_eq!(style(&wb, s, 1, 3).numfmt, "@");
    assert!(style(&wb, s, 1, 3).align.wrap);
    assert!(style(&wb, s, 3, 3).align.wrap);
}

/// What later Excel versions write (no `x:num`, numbers in the text with
/// the separators the table names), and Excel's other habits.
#[test]
fn excel_details() {
    let page = r##"<html xmlns:x="urn:schemas-microsoft-com:office:excel">
<head><style>
table {mso-displayed-decimal-separator:"\,"; mso-displayed-thousand-separator:"\.";}
.xl70 {mso-style-parent:style0; border:.5pt solid windowtext; background:#DEEBF7; mso-pattern:#CCFFFF none;}
</style>
<!--[if gte mso 9]><xml><x:ExcelWorkbook><x:1904Date/></x:ExcelWorkbook></xml><![endif]-->
</head><body>
<table border=0 cellpadding=0 cellspacing=0>
 <col width=98 style='mso-width-source:userset;mso-width-alt:3584;width:74pt'>
 <tr height=17><td x:str="'Aug-01">Aug-01</td><td>1.234,5</td><td>12,5%</td></tr>
 <tr height=38 style='height:28.0pt;mso-xlrowspan:2'><td colspan=3 style='mso-ignore:colspan'></td></tr>
 <tr><td colspan=3 class=xl70 style='mso-ignore:colspan'>&nbsp;</td></tr>
 <![if supportMisalignedColumns]><tr height=0 style='display:none'><td width=98>phantom</td></tr><![endif]>
</table>
<div style='mso-element:comment-list'><div style='mso-element:comment'><p>a comment</p></div></div>
</body></html>"##;
    let wb = read_str(page);
    let s = &wb.sheets[0];
    assert!(wb.date1904);
    assert_eq!(value(s, 0, 0), &Value::text("Aug-01"));
    assert_eq!(value(s, 0, 1), &Value::Number(1234.5));
    assert_eq!(value(s, 0, 2), &Value::Number(0.125));
    // One row standing for two empty ones, their height shared.
    assert_eq!(s.rows[&1].height, Some(14.0));
    assert_eq!(s.rows[&2].height, Some(14.0));
    // An unmerged run of formatted cells: each formatted, none merged.
    assert!(s.merges.is_empty());
    for c in 0..3 {
        assert_eq!(style(&wb, s, 3, c).fill, Fill::solid(0xDEEBF7));
        assert_eq!(style(&wb, s, 3, c).border.left.style, Some("thin"));
    }
    // Excel's own width unit, the phantom row and the comments left out.
    assert_eq!(s.col_info(0).and_then(|c| c.width), Some(14.0));
    assert_eq!(s.cells.keys().map(|k| k.0).max(), Some(3));
    assert!(
        !s.cells
            .values()
            .any(|c| c.value == Value::text("a comment"))
    );
}

#[test]
fn several_tables_and_plain_html() {
    let page = "<!DOCTYPE html><html><head><title>Report</title><style>td.n { text-align: right } .hot { background-color: #f00 }</style></head><body>
<h1>Heading</h1>
<table><thead><tr><th>Name<th>Score</thead>
<tbody><tr><td>Ann<td class=n>12%<tr><td class=hot>Bob<td>(1,234.50)</tbody></table>
<p>between</p>
<table><tr><td><b>bold</b> and <i>italic</i></td><td>caf&eacute; &amp; t&#233;a&nbsp;!</td></tr>
<tr><td><table><tr><td>inner</td><td>cells</td></tr></table></td></tr></table>
<script>document.write('<table><tr><td>no</td></tr></table>')</script>
</body></html>";
    let wb = read_str(page);
    let s = &wb.sheets[0];
    assert_eq!(s.name, "Sheet1");
    // Text around tables, a row each in the first column.
    assert_eq!(value(s, 0, 0), &Value::text("Heading"));
    assert!(style(&wb, s, 0, 0).font.bold);
    assert_eq!(value(s, 1, 0), &Value::text("Name"));
    let th = style(&wb, s, 1, 0);
    assert!(th.font.bold && th.align.horizontal == Some("center"));
    assert_eq!(value(s, 2, 1), &Value::Number(0.12));
    assert_eq!(style(&wb, s, 2, 1).numfmt, "0%");
    assert_eq!(style(&wb, s, 2, 1).align.horizontal, Some("right"));
    assert_eq!(value(s, 3, 1), &Value::Number(-1234.5));
    assert_eq!(style(&wb, s, 3, 1).numfmt, "#,##0.00");
    assert_eq!(style(&wb, s, 3, 0).fill, Fill::solid(0xFF0000));
    assert_eq!(value(s, 4, 0), &Value::text("between"));
    let Value::Rich(runs) = value(s, 5, 0) else {
        panic!("{:?}", value(s, 5, 0))
    };
    let parts: Vec<(&str, bool, bool)> = runs
        .iter()
        .map(|r| {
            (
                r.text.as_str(),
                r.font.as_ref().unwrap().bold,
                r.font.as_ref().unwrap().italic,
            )
        })
        .collect();
    assert_eq!(
        parts,
        [
            ("bold", true, false),
            (" and ", false, false),
            ("italic", false, true)
        ]
    );
    assert_eq!(value(s, 5, 1), &Value::text("café & téa !"));
    // A table in a cell: its text.
    assert_eq!(value(s, 6, 0), &Value::text("inner cells"));
    // Nothing from the script.
    assert!(!s.cells.values().any(|c| c.value == Value::text("no")));
    assert_eq!(wb.styles.get(0).font.name, "Times New Roman");
}

#[test]
fn captions_rules_and_breaks() {
    // No style sheet: a line break starts a cell a row down.
    let page = "<table border=1><caption>Facts</caption><tr><td rowspan=2>one<br>two</td><td>x</td></tr><tr><td>y</td></tr></table>";
    let wb = read_str(page);
    let s = &wb.sheets[0];
    assert_eq!(value(s, 0, 0), &Value::text("Facts"));
    assert_eq!(value(s, 1, 0), &Value::text("one"));
    assert_eq!(value(s, 2, 0), &Value::text("two"));
    assert_eq!(value(s, 2, 1), &Value::text("y"));
    assert_eq!(style(&wb, s, 1, 1).border.left.style, Some("thin"));
    // Excel's style sheet keeps it in the cell.
    let wb = read_str(
        "<style>br {mso-data-placement:same-cell;}</style><table><tr><td>one<br>two</td></tr></table>",
    );
    assert_eq!(value(&wb.sheets[0], 0, 0), &Value::text("one\ntwo"));
}

#[test]
fn encodings() {
    let page = b"<html><meta charset=windows-1251><table><tr><td>\xcf\xf0\xe8\xe2\xe5\xf2</td></tr></table></html>";
    let wb = read(page, &mut Budget::new(Limits::default())).unwrap();
    assert_eq!(value(&wb.sheets[0], 0, 0), &Value::text("Привет"));
    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(
            "<table><tr><td>é</td></tr></table>"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        )
        .collect();
    let wb = read(&utf16, &mut Budget::new(Limits::default())).unwrap();
    assert_eq!(value(&wb.sheets[0], 0, 0), &Value::text("é"));
}

#[test]
fn refusals_and_limits() {
    let b = || Budget::new(Limits::default());
    assert!(matches!(
        read(b"just text, a < b", &mut b()),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        read(b"<html><body><p>no table</p></body></html>", &mut b()),
        Err(Error::NotFormat(_))
    ));
    // A workbook's frameset: its sheets are other files, not read.
    let frames = b"<html><head><meta name=\"Excel Workbook Frameset\"><!--[if gte mso 9]><xml><x:ExcelWorkbook><x:ExcelWorksheets><x:ExcelWorksheet><x:Name>S</x:Name><x:WorksheetSource HRef=\"Book_files/sheet001.htm\"/></x:ExcelWorksheet></x:ExcelWorksheets></x:ExcelWorkbook></xml><![endif]--></head><frameset rows=\"*,39\"><frame src=\"Book_files/sheet001.htm\"></frameset></html>";
    assert!(matches!(read(frames, &mut b()), Err(Error::Unsupported(_))));
    let few = Limits::default().with_max_cells(5);
    assert_eq!(
        read(EXCEL.as_bytes(), &mut Budget::new(few)).unwrap_err(),
        Error::TooLarge("cells")
    );
}

#[test]
fn hostile_pages() {
    let b = EXCEL.as_bytes();
    for cut in (0..b.len()).step_by(37) {
        let _ = read(&b[..cut], &mut Budget::new(Limits::default()));
    }
    let deep = "<table><tr><td>".repeat(300);
    assert!(read(deep.as_bytes(), &mut Budget::new(Limits::default())).is_err());
    for page in [
        "<table><tr><td rowspan=65534 colspan=65534>x</td></tr></table>",
        "<table><col span=99999999 width=1e999><tr><td colspan=-5 rowspan=0>&#0;&#x110000;&#xD800;&bogus;&</td></tr></table>",
        "<table x:str><tr><td x:num=\"NaN\" x:fmla=\"=\" x:bool x:err>1e999</td><td x:num>1,2,3</td></tr></table>",
        "<table><tr><td style='mso-number-format:\"\\'; border:99999pt solid'><b><b><b>x</table></td></b>",
        "<table><style>td{</style><tr><td class=\"a b c\">x<script>",
        "<<<table <tr <td>>>x</table",
        // A multi-byte character before a conditional's `>` (found by
        // fuzzing).
        "<table><tr><td>a<![if é>b<![endif]></td></tr></table>",
    ] {
        let _ = read(page.as_bytes(), &mut Budget::new(Limits::default()));
    }
}

/// What Excel writes for browsers between `<![if !vml]>` and `<![endif]>` is
/// not what Excel reads: the cell it holds is not a cell.
#[test]
fn downlevel_conditionals_hide_what_excel_writes_for_browsers() {
    let wb = read_str(
        "<table><tr><td>a</td><![if !vml]><td>b</td><![endif]><![if gte x]><td>c</td><![endif]></tr></table>",
    );
    let s = &wb.sheets[0];
    assert_eq!(value(s, 0, 0), &Value::text("a"));
    assert_eq!(value(s, 0, 1), &Value::text("c"));
    assert_eq!(value(s, 0, 2), &Value::Empty);
}
