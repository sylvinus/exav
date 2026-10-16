//! The fixtures converted through the public API, the XLSX read back.

use exav_render::sheets::{convert, Error, Format, Limits};
use std::io::Read;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/office/sheets/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// The XLSX's parts as text.
struct Xlsx(zip::ZipArchive<std::io::Cursor<Vec<u8>>>);

impl Xlsx {
    fn of(name: &str, format: Format) -> Xlsx {
        let c = convert(&fixture(name), format, &Limits::default()).unwrap();
        Xlsx(zip::ZipArchive::new(std::io::Cursor::new(c.xlsx)).unwrap())
    }

    fn part(&mut self, name: &str) -> String {
        let mut s = String::new();
        self.0
            .by_name(name)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        s
    }
}

/// What every conversion of sample.fods shows, whatever it went through.
fn budget(x: &mut Xlsx) {
    let wb = x.part("xl/workbook.xml");
    assert!(
        wb.contains(r#"<sheet name="Budget""#) && wb.contains(r#"<sheet name="Notes""#),
        "{wb}"
    );
    let sst = x.part("xl/sharedStrings.xml");
    for s in [
        "Item",
        "Rent",
        "Travel",
        "Merged note across three columns",
        "Second sheet",
    ] {
        assert!(sst.contains(s), "{s} in {sst}");
    }
    let s1 = x.part("xl/worksheets/sheet1.xml");
    assert!(s1.contains("<f>SUM(B2:B4)</f><v>1635.49</v>"), "{s1}");
    assert!(s1.contains(r#"<mergeCell ref="A6:C6"/>"#), "{s1}");
    // The amount, a number; the date, a serial.
    assert!(
        s1.contains("<v>345.5</v>") && s1.contains("<v>45296</v>"),
        "{s1}"
    );
    let st = x.part("xl/styles.xml");
    assert!(st.contains("FF4472C4"), "the header's fill: {st}");
    // #,##0.00, Excel's built-in format 4.
    assert!(
        st.contains(r#"<xf numFmtId="4""#),
        "the amounts' format: {st}"
    );
    // TRUE, which the source's producer saved again as the number 1 (no boolean
    // format in the source).
    let s2 = x.part("xl/worksheets/sheet2.xml");
    assert!(s2.contains("<v>1</v>"), "{s2}");
}

#[test]
fn ods() {
    budget(&mut Xlsx::of("sample.ods", Format::Ods));
}

#[test]
fn fods() {
    let mut x = Xlsx::of("sample.fods", Format::Fods);
    budget(&mut x);
    assert!(x
        .part("xl/worksheets/sheet2.xml")
        .contains(r#"t="b"><v>1</v>"#));
}

#[test]
fn xls() {
    budget(&mut Xlsx::of("sample.xls", Format::Xls));
}

#[test]
fn numbers() {
    let mut x = Xlsx::of("sample.numbers", Format::Numbers);
    assert!(x
        .part("xl/workbook.xml")
        .contains(r#"<sheet name="Sheet 1""#));
    let sst = x.part("xl/sharedStrings.xml");
    assert!(sst.contains("SheetJS") && sst.contains("B3:D3"), "{sst}");
    let s1 = x.part("xl/worksheets/sheet1.xml");
    assert!(s1.contains(r#"<mergeCell ref="B3:D3"/>"#), "{s1}");
    assert!(s1.contains(r#"showGridLines="0""#), "{s1}");
}

#[test]
fn numbers_09() {
    let mut x = Xlsx::of("numbers09.numbers", Format::Numbers);
    let wb = x.part("xl/workbook.xml");
    for name in [
        "Checking - Account Categories",
        "Checking - Transactions",
        "Second sheet",
    ] {
        assert!(wb.contains(&format!(r#"<sheet name="{name}""#)), "{wb}");
    }
    let sst = x.part("xl/sharedStrings.xml");
    assert!(
        sst.contains("Beginning Balance") && sst.contains("Fill up SUV for camping trip"),
        "{sst}"
    );
    // A formula on another table, its whole columns as their body rows.
    let s1 = x.part("xl/worksheets/sheet1.xml");
    assert!(
        s1.contains("<f>SUMIF('Checking - Transactions'!$D$3:$D$14,A2,'Checking - Transactions'!E$3:E$14)</f>"),
        "{s1}"
    );
    let s2 = x.part("xl/worksheets/sheet2.xml");
    assert!(s2.contains(r#"<mergeCell ref="A1:B1"/>"#), "{s2}");
    assert!(s2.contains(r#"ySplit="2""#), "the frozen header rows: {s2}");
    // 2009-10-01.
    assert!(s2.contains("<v>40087</v>"), "{s2}");
    let st = x.part("xl/styles.xml");
    assert!(
        st.contains(r#"formatCode="&quot;€&quot;* #,##0.00;&quot;€&quot;* (#,##0.00)""#),
        "the accounting format: {st}"
    );
    assert!(st.contains(r#"<name val="Cochin"/>"#), "{st}");
}

/// What each conversion of the text formats' budget table shows.
fn text_budget(x: &mut Xlsx, merged: bool) {
    let sst = x.part("xl/sharedStrings.xml");
    for s in ["Item", "Rent", "Travel", "Merged note across three columns"] {
        assert!(sst.contains(s), "{s} in {sst}");
    }
    let s1 = x.part("xl/worksheets/sheet1.xml");
    assert!(s1.contains("<f>SUM(B2:B4)</f><v>1635.49</v>"), "{s1}");
    assert!(
        s1.contains("<v>345.5</v>") && s1.contains("<v>45297</v>"),
        "{s1}"
    );
    assert_eq!(s1.contains(r#"<mergeCell ref="A7:C7"/>"#), merged, "{s1}");
    let st = x.part("xl/styles.xml");
    assert!(
        st.contains(r#"<xf numFmtId="4""#),
        "the amounts' format: {st}"
    );
    assert!(
        st.contains(r#"formatCode="yyyy\-mm\-dd""#),
        "the date's format: {st}"
    );
}

#[test]
fn xml_spreadsheet() {
    let mut x = Xlsx::of("sample-2003.xml", Format::SpreadsheetMl);
    let wb = x.part("xl/workbook.xml");
    assert!(
        wb.contains(r#"<sheet name="Budget""#) && wb.contains(r#"<sheet name="Notes""#),
        "{wb}"
    );
    text_budget(&mut x, true);
    assert!(x.part("xl/styles.xml").contains("FF4472C4"));
    assert!(x.part("xl/worksheets/sheet1.xml").contains(r#"ySplit="1""#));
    assert!(x
        .part("xl/worksheets/sheet2.xml")
        .contains(r#"t="b"><v>1</v>"#));
}

#[test]
fn html_table() {
    let mut x = Xlsx::of("sample.html", Format::Html);
    assert!(x
        .part("xl/workbook.xml")
        .contains(r#"<sheet name="Budget""#));
    text_budget(&mut x, true);
    assert!(x.part("xl/styles.xml").contains("FF4472C4"));
    assert!(x.part("xl/worksheets/sheet1.xml").contains(r#"ySplit="1""#));
}

#[test]
fn sylk() {
    let mut x = Xlsx::of("sample.slk", Format::Sylk);
    text_budget(&mut x, false);
}

#[test]
fn the_wrong_format_is_refused() {
    let xls = fixture("sample.xls");
    assert!(matches!(
        convert(&xls, Format::Ods, &Limits::default()),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        convert(&xls, Format::Numbers, &Limits::default()),
        Err(Error::NotFormat(_))
    ));
    let ods = fixture("sample.ods");
    assert!(matches!(
        convert(&ods, Format::Xls, &Limits::default()),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        convert(&ods, Format::Numbers, &Limits::default()),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        convert(b"", Format::Fods, &Limits::default()),
        Err(Error::NotFormat(_) | Error::Malformed(_))
    ));
}

#[test]
fn limits_are_kept() {
    for (name, format) in [
        ("sample.xls", Format::Xls),
        ("sample.ods", Format::Ods),
        ("sample.numbers", Format::Numbers),
        ("numbers09.numbers", Format::Numbers),
        ("sample-2003.xml", Format::SpreadsheetMl),
        ("sample.html", Format::Html),
        ("sample.slk", Format::Sylk),
    ] {
        let data = fixture(name);
        assert_eq!(
            convert(&data, format, &Limits::default().with_max_cells(5)).unwrap_err(),
            Error::TooLarge("cells"),
            "{name}"
        );
        assert_eq!(
            convert(&data, format, &Limits::default().with_max_memory(2000)).unwrap_err(),
            Error::TooLarge("memory"),
            "{name}"
        );
        let mut small = Limits::default();
        small.max_input = 100;
        assert_eq!(
            convert(&data, format, &small).unwrap_err(),
            Error::TooLarge("input"),
            "{name}"
        );
    }
}

/// Every truncation of each fixture is refused or converted, never a panic.
#[test]
fn truncated_files() {
    for (name, format) in [
        ("sample.xls", Format::Xls),
        ("sample.ods", Format::Ods),
        ("sample.fods", Format::Fods),
        ("sample.numbers", Format::Numbers),
        ("numbers09.numbers", Format::Numbers),
        ("sample-2003.xml", Format::SpreadsheetMl),
        ("sample.html", Format::Html),
        ("sample.slk", Format::Sylk),
    ] {
        let data = fixture(name);
        let step = (data.len() / 200).max(1);
        for n in (0..data.len()).step_by(step) {
            let _ = convert(&data[..n], format, &Limits::default());
        }
    }
}
