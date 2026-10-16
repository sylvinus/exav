use super::*;
use crate::formats::office::sheets::limits::Limits;

fn book(styles: &str, sheets: &str) -> String {
    format!(
        r#"<?xml version="1.0"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet" xmlns:html="http://www.w3.org/TR/REC-html40">
<Styles>{styles}</Styles>
{sheets}
</Workbook>"#
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

const STYLES: &str = r##"
<Style ss:ID="Default" ss:Name="Normal"><Alignment ss:Vertical="Bottom"/><Font ss:FontName="Calibri" ss:Size="11" ss:Color="#000000"/></Style>
<Style ss:ID="bold"><Font ss:Bold="1"/><Borders><Border ss:Position="Bottom" ss:LineStyle="Continuous" ss:Weight="2" ss:Color="#FF0000"/><Border ss:Position="Left" ss:LineStyle="Dash" ss:Weight="1"/></Borders></Style>
<Style ss:ID="pct" ss:Parent="bold"><Interior ss:Color="#FFFF00" ss:Pattern="Solid"/><NumberFormat ss:Format="Percent"/><Alignment ss:Horizontal="Center" ss:WrapText="1" ss:Rotate="-45"/></Style>
<Style ss:ID="date"><NumberFormat ss:Format="yyyy\-mm\-dd"/></Style>
<Style ss:ID="unbold" ss:Parent="pct"><Font ss:Bold="0" ss:Italic="1" ss:Underline="Double"/></Style>"##;

fn sample() -> String {
    book(
        STYLES,
        r##"<Worksheet ss:Name="Data">
<Names><NamedRange ss:Name="Print_Area" ss:RefersTo="=Data!R1C1:R4C3"/></Names>
<Table ss:DefaultColumnWidth="60" ss:DefaultRowHeight="15">
 <Column ss:Width="48"/>
 <Column ss:Index="3" ss:Width="96" ss:Span="1"/>
 <Column ss:Hidden="1"/>
 <Row ss:Height="30">
  <Cell ss:StyleID="bold" ss:MergeAcross="1"><Data ss:Type="String">Head</Data></Cell>
  <Cell><Data ss:Type="Number">2.5</Data></Cell>
  <Cell ss:Index="5" ss:StyleID="pct"><Data ss:Type="Number">0.25</Data></Cell>
 </Row>
 <Row ss:Index="3">
  <Cell ss:StyleID="date"><Data ss:Type="DateTime">2009-10-01T00:00:00.000</Data></Cell>
  <Cell><Data ss:Type="DateTime">1899-12-31T12:00:00.000</Data></Cell>
  <Cell><Data ss:Type="Boolean">1</Data></Cell>
  <Cell ss:Formula="=1/0"><Data ss:Type="Error">#DIV/0!</Data></Cell>
  <Cell ss:StyleID="unbold"><Data ss:Type="String" x:Ticked="1">007</Data></Cell>
 </Row>
 <Row>
  <Cell ss:Formula="=SUM(R[-3]C[1]:R[-1]C[1])+RC[2]"><Data ss:Type="Number">2.5</Data></Cell>
  <Cell ss:MergeDown="1" ss:HRef="https://example.com/" x:HRefScreenTip="tip"><Data ss:Type="String">link</Data><Comment ss:Author="Ann"><ss:Data>a <B>note</B></ss:Data></Comment></Cell>
  <Cell><ss:Data ss:Type="String" xmlns="http://www.w3.org/TR/REC-html40">plain <B>bold <I>both</I></B><Font html:Color="#FF0000">red</Font></ss:Data></Cell>
 </Row>
 <Row ss:Index="10" ss:Span="2" ss:Height="5" ss:Hidden="1"/>
 <Row ss:Index="13"><Cell ss:ArrayRange="RC:R[1]C" ss:Formula="={1;2}"><Data ss:Type="Number">1</Data></Cell></Row>
</Table>
<WorksheetOptions xmlns="urn:schemas-microsoft-com:office:excel">
 <FreezePanes/><FrozenNoSplit/><SplitHorizontal>1</SplitHorizontal><TopRowBottomPane>1</TopRowBottomPane>
 <DoNotDisplayGridlines/><Zoom>85</Zoom>
</WorksheetOptions>
<AutoFilter x:Range="R1C1:R4C3" xmlns="urn:schemas-microsoft-com:office:excel"/>
</Worksheet>
<Worksheet ss:Name="Hidden">
 <Table><Row><Cell><Data ss:Type="String">x</Data></Cell></Row></Table>
 <WorksheetOptions xmlns="urn:schemas-microsoft-com:office:excel"><Visible>SheetHidden</Visible><Selected/></WorksheetOptions>
</Worksheet>"##,
    )
}

#[test]
fn cells_indexes_and_types() {
    let wb = read_str(&sample());
    let s = &wb.sheets[0];
    assert_eq!(value(s, 0, 0), &Value::text("Head"));
    // After a merge across two cells, the next cell is the third.
    assert_eq!(value(s, 0, 2), &Value::Number(2.5));
    assert_eq!(value(s, 0, 4), &Value::Number(0.25));
    assert_eq!(value(s, 2, 0), &Value::Number(40087.0));
    // A time alone sits on day 0.
    assert_eq!(value(s, 2, 1), &Value::Number(0.5));
    assert_eq!(value(s, 2, 2), &Value::Bool(true));
    assert_eq!(value(s, 2, 3), &Value::Error(CellError::Div0));
    assert_eq!(value(s, 2, 4), &Value::text("'007"));
    assert_eq!(
        s.merges,
        [
            Range {
                r1: 0,
                c1: 0,
                r2: 0,
                c2: 1
            },
            Range {
                r1: 3,
                c1: 1,
                r2: 4,
                c2: 1
            }
        ]
    );
    let Value::Rich(runs) = value(s, 3, 2) else {
        panic!("{:?}", value(s, 3, 2))
    };
    let plain: Vec<(&str, bool, bool, Option<Rgb>)> = runs
        .iter()
        .map(|r| {
            (
                r.text.as_str(),
                r.font.as_ref().unwrap().bold,
                r.font.as_ref().unwrap().italic,
                r.font.as_ref().unwrap().color,
            )
        })
        .collect();
    assert_eq!(
        plain,
        [
            ("plain ", false, false, None),
            ("bold ", true, false, None),
            ("both", true, true, None),
            ("red", false, false, Some(0xFF0000))
        ]
    );
}

#[test]
fn formulas_names_links_notes() {
    let wb = read_str(&sample());
    let s = &wb.sheets[0];
    let f = |r, c| s.cells[&(r, c)].formula.as_deref().map(str::to_string);
    assert_eq!(f(3, 0).as_deref(), Some("SUM(B1:B3)+C4"));
    assert_eq!(f(2, 3).as_deref(), Some("1/0"));
    assert_eq!(f(12, 0).as_deref(), Some("{1;2}"));
    assert_eq!(
        s.arrays.get(&(12, 0)),
        Some(&Range {
            r1: 12,
            c1: 0,
            r2: 13,
            c2: 0
        })
    );
    assert_eq!(wb.names.len(), 1);
    assert_eq!(
        (
            wb.names[0].name.as_str(),
            wb.names[0].sheet,
            wb.names[0].formula.as_str()
        ),
        ("_xlnm.Print_Area", Some(0), "Data!$A$1:$C$4")
    );
    assert_eq!(s.hyperlinks[0].url.as_deref(), Some("https://example.com/"));
    assert_eq!(s.hyperlinks[0].tooltip.as_deref(), Some("tip"));
    assert_eq!(
        (s.comments[0].author.as_str(), s.comments[0].text.as_str()),
        ("Ann", "a note")
    );
    assert_eq!(
        s.autofilter,
        Some(Range {
            r1: 0,
            c1: 0,
            r2: 3,
            c2: 2
        })
    );
}

#[test]
fn styles_and_parents() {
    let wb = read_str(&sample());
    let s = &wb.sheets[0];
    assert_eq!(wb.styles.get(0).font.name, "Calibri");
    let bold = style(&wb, s, 0, 0);
    assert!(bold.font.bold);
    assert_eq!(
        bold.border.bottom,
        Edge {
            style: Some("medium"),
            color: Some(0xFF0000)
        }
    );
    assert_eq!(bold.border.left.style, Some("dashed"));
    let pct = style(&wb, s, 0, 4);
    // Its parent's bold and borders, its own fill, format and alignment.
    assert!(pct.font.bold && pct.border.bottom.style == Some("medium"));
    assert_eq!(pct.fill, Fill::solid(0xFFFF00));
    assert_eq!(pct.numfmt, "0.00%");
    assert_eq!(
        (pct.align.horizontal, pct.align.wrap, pct.align.rotation),
        (Some("center"), true, 135)
    );
    let unbold = style(&wb, s, 2, 4);
    assert!(!unbold.font.bold && unbold.font.italic && unbold.font.underline == Some("double"));
    assert_eq!(unbold.fill, Fill::solid(0xFFFF00));
    assert_eq!(style(&wb, s, 2, 0).numfmt, "yyyy\\-mm\\-dd");
    // Unstyled cells take the default style.
    assert_eq!(s.cells[&(0, 2)].style, 0);
}

#[test]
fn sizes_and_options() {
    let wb = read_str(&sample());
    let s = &wb.sheets[0];
    // 48pt is 64 pixels: 8.43 characters of a 7-pixel digit, stored with
    // the padding as 9.140625, as Excel stores its default width.
    assert_eq!(s.col_info(0).and_then(|c| c.width), Some(9.140625));
    assert_eq!(s.col_info(1).and_then(|c| c.width), None);
    assert_eq!(s.col_info(3).and_then(|c| c.width), Some(18.28125));
    assert!(s.col_info(4).unwrap().hidden);
    assert_eq!(s.default_col_width, Some(11.421875));
    assert_eq!(s.default_row_height, 15.0);
    assert_eq!(s.rows[&0].height, Some(30.0));
    assert!((9..=11).all(|r| s.rows[&r].hidden));
    assert!(!s.rows.contains_key(&12) || !s.rows[&12].hidden);
    assert_eq!(s.freeze, Some((1, 0)));
    assert!(!s.show_grid);
    assert_eq!(s.zoom, 85);
    assert_eq!(wb.sheets[1].state, SheetState::Hidden);
    assert_eq!(wb.active, 1);
}

#[test]
fn encodings() {
    let xml = book(
        "",
        r#"<Worksheet ss:Name="Лист"><Table><Row><Cell><Data ss:Type="String">Привет</Data></Cell></Row></Table></Worksheet>"#,
    );
    let declared = xml.replacen(
        "<?xml version=\"1.0\"?>",
        "<?xml version=\"1.0\" encoding=\"windows-1251\"?>",
        1,
    );
    let (cp, _, _) = encoding_rs::WINDOWS_1251.encode(&declared);
    let wb = read(&cp, &mut Budget::new(Limits::default())).unwrap();
    assert_eq!(wb.sheets[0].name, "Лист");
    assert_eq!(value(&wb.sheets[0], 0, 0), &Value::text("Привет"));
}

#[test]
fn refusals_and_limits() {
    let b = || Budget::new(Limits::default());
    assert!(matches!(
        read(b"<html/>", &mut b()),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        read(book("", "").as_bytes(), &mut b()),
        Err(Error::Unsupported(_))
    ));
    let few = Limits::default().with_max_cells(5);
    assert_eq!(
        read(sample().as_bytes(), &mut Budget::new(few)).unwrap_err(),
        Error::TooLarge("cells")
    );
}

#[test]
fn hostile_documents() {
    let xml = sample();
    for cut in (0..xml.len()).step_by(61) {
        let _ = read(&xml.as_bytes()[..cut], &mut Budget::new(Limits::default()));
    }
    for table in [
        r#"<Row ss:Index="1048576"><Cell ss:Index="16384" ss:MergeAcross="99" ss:MergeDown="4000000000"><Data ss:Type="Number">1</Data></Cell><Cell><Data ss:Type="Number">2</Data></Cell></Row><Row><Cell/></Row>"#,
        r#"<Row ss:Span="4294967295" ss:Height="1e308"/><Column ss:Span="4294967295" ss:Width="-1"/>"#,
        r#"<Row><Cell ss:Formula="=R[-99999999999]C+&quot;" ss:ArrayRange="R0C0"><Data ss:Type="DateTime">-0001-99-99</Data></Cell></Row>"#,
    ] {
        let doc = book(
            r#"<Style ss:ID="a" ss:Parent="b"/><Style ss:ID="b" ss:Parent="a"><Font ss:Size="-1"/></Style>"#,
            &format!(r#"<Worksheet ss:Name="S"><Table ss:StyleID="a">{table}</Table></Worksheet>"#),
        );
        let _ = read(doc.as_bytes(), &mut Budget::new(Limits::default()));
    }
}
