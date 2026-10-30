use super::*;
use crate::formats::office::sheets::limits::Limits;

fn read_bytes(b: &[u8]) -> Workbook {
    read(b, &mut Budget::new(Limits::default())).unwrap()
}

fn value(s: &Sheet, r: u32, c: u32) -> &Value {
    s.cells.get(&(r, c)).map_or(&Value::Empty, |c| &c.value)
}

/// What Excel writes, cut down: the format and font tables, the default
/// format, bounds, options, widths, then cells and their formats.
const SAMPLE: &str = "ID;PWXL;N;E\r
P;PGeneral\r
P;P0.00\r
P;P#,##0;;[Red]\\-#,##0\r
P;Pdd/mm/yyyy\r
P;FCalibri;M220;L9\r
P;ECalibri;M220;SB;L9\r
P;ECourier New;M200;SI\r
F;P0;DG0G8;M300\r
B;Y5;X4;D0 0 4 3\r
O;L;D;V0;K47;G100 0.001\r
F;W1 1 17\r
F;W2 16384 9\r
F;W4 4 0\r
F;R2;SDM1;M400\r
NN;NTotal;ER3C2\r
C;Y1;X1;K\"Month;;s\"\r
F;Y1;X1;FG0C;SDTB\r
C;X2;K\"Units\"\r
C;Y2;X1;K40087\r
F;P3;Y2;X1\r
C;X2;K118\r
C;Y3;X2;K236;ESUM(R[-1]C:R[-1]C)\r
F;X2;Y3;F$2R\r
C;Y4;X2;K1;ER[-2]C/R[-2]C;D\r
C;Y5;X2;K1;S;R4;C2\r
C;Y4;X3;KTRUE;AA note\x1b :second line\r
C;X4;K#N/A\r
F;Y5;X3;P2;SM2\r
C;Y5;X1;K\"Caf\x1bNBe \x1bN#5\"\r
E\r
C;Y9;X9;K\"after the end\"\r
";

#[test]
fn values_and_positions() {
    let wb = read_bytes(SAMPLE.as_bytes());
    let s = &wb.sheets[0];
    assert_eq!(value(s, 0, 0), &Value::text("Month;s"));
    // X stays when only Y moves, and the other way round.
    assert_eq!(value(s, 0, 1), &Value::text("Units"));
    assert_eq!(value(s, 1, 0), &Value::Number(40087.0));
    assert_eq!(value(s, 1, 1), &Value::Number(118.0));
    assert_eq!(value(s, 3, 2), &Value::Bool(true));
    assert_eq!(value(s, 3, 3), &Value::Error(CellError::NA));
    assert_eq!(value(s, 4, 0), &Value::text("Café £5"));
    assert!(!s.cells.contains_key(&(8, 8)));
    assert_eq!(s.comments[0].text, "A note\nsecond line");
}

#[test]
fn formulas_and_names() {
    let wb = read_bytes(SAMPLE.as_bytes());
    let s = &wb.sheets[0];
    let f = |r, c| s.cells[&(r, c)].formula.as_deref().map(str::to_string);
    assert_eq!(f(2, 1).as_deref(), Some("SUM(B2:B2)"));
    assert_eq!(f(3, 1).as_deref(), Some("B2/B2"));
    // A shared expression, from the cell that uses it.
    assert_eq!(f(4, 1).as_deref(), Some("B3/B3"));
    assert_eq!(value(s, 2, 1), &Value::Number(236.0));
    assert_eq!(
        (wb.names[0].name.as_str(), wb.names[0].formula.as_str()),
        ("Total", "$B$3")
    );
}

#[test]
fn formats_widths_heights() {
    let wb = read_bytes(SAMPLE.as_bytes());
    let s = &wb.sheets[0];
    let st = |r, c| wb.styles.get(s.cells[&(r, c)].style);
    // The first font is the default.
    assert_eq!(
        (
            wb.styles.get(0).font.name.as_str(),
            wb.styles.get(0).font.size_centipt
        ),
        ("Calibri", 1100)
    );
    let head = st(0, 0);
    assert_eq!(head.align.horizontal, Some("center"));
    assert!(head.font.bold);
    assert_eq!(
        (
            head.border.top.style,
            head.border.bottom.style,
            head.border.left.style
        ),
        (Some("thin"), Some("thin"), None)
    );
    assert_eq!(st(1, 0).numfmt, "dd/mm/yyyy");
    assert_eq!(st(2, 1).numfmt, "\"$\"#,##0.00_);\\(\"$\"#,##0.00\\)");
    assert_eq!(st(2, 1).align.horizontal, Some("right"));
    let p = st(4, 2);
    assert_eq!(p.numfmt, "#,##0;[Red]\\-#,##0");
    assert_eq!(
        (p.font.name.as_str(), p.font.italic, p.font.size_centipt),
        ("Courier New", true, 1000)
    );
    // Row 2's format: bold, its font.
    assert!(st(1, 1).font.bold);
    assert_eq!(s.rows[&1].height, Some(20.0));
    assert_eq!(s.default_row_height, 15.0);
    // 17 and 9 characters of Calibri 11's 7-pixel digit, padding in.
    assert_eq!(s.col_info(0).and_then(|c| c.width), Some(17.7109375));
    assert_eq!(s.col_info(5).and_then(|c| c.width), Some(9.7109375));
    assert!(s.col_info(3).unwrap().hidden);
}

#[test]
fn line_endings_and_encodings() {
    // Carriage returns alone, Windows-1252 text.
    let wb = read_bytes(b"ID;PWXL\rC;Y1;X1;K\"Caf\xe9\"\rC;X2;K2\r");
    assert_eq!(value(&wb.sheets[0], 0, 0), &Value::text("Café"));
    assert_eq!(value(&wb.sheets[0], 0, 1), &Value::Number(2.0));
    // Excel for the Macintosh: Mac Roman.
    let wb = read_bytes(b"ID;PXL;N;E\rC;Y1;X1;K\"\xd1 Caf\x8e\"\r");
    assert_eq!(value(&wb.sheets[0], 0, 0), &Value::text("— Café"));
    // A semicolon left alone in a quoted value.
    let wb = read_bytes(b"ID;PWXL\nC;Y1;X1;K\"a;b\";ER1C2\n");
    assert_eq!(value(&wb.sheets[0], 0, 0), &Value::text("a;b"));
    assert_eq!(wb.sheets[0].cells[&(0, 0)].formula.as_deref(), Some("$B$1"));
    // UTF-8 when it is.
    let wb = read_bytes("ID;P\nC;Y1;X1;K\"Café\"\n".as_bytes());
    assert_eq!(value(&wb.sheets[0], 0, 0), &Value::text("Café"));
    // The 1904 date system.
    assert!(read_bytes(b"ID;P\nO;V4\n").date1904);
}

#[test]
fn refusals_and_limits() {
    assert!(matches!(
        read(b"id;P", &mut Budget::new(Limits::default())),
        Err(Error::NotFormat(_))
    ));
    assert!(matches!(
        read(b"<html>", &mut Budget::new(Limits::default())),
        Err(Error::NotFormat(_))
    ));
    let few = Limits::default().with_max_cells(5);
    assert_eq!(
        read(SAMPLE.as_bytes(), &mut Budget::new(few)).unwrap_err(),
        Error::TooLarge("cells")
    );
}

#[test]
fn hostile_files() {
    let b = SAMPLE.as_bytes();
    for cut in 0..b.len() {
        let _ = read(&b[..cut], &mut Budget::new(Limits::default()));
    }
    for s in [
        "ID\nC;Y99999999999;X0;K1\nC;Y1048576;X16384;K\"x\";ER[-9999999]C[99999]\nF;W0 99999 999\nF;W5 2 1\nF;R0;M-5\nF;SM99999999999999999999\n",
        "ID\nC;Y2;X2;S;R2;C2\nC;Y3;X3;M;R1;C1\nC;Y1;X1;S;R9;C9\n\x1bN\x1b\x1b \x1bNH",
        "ID\nP;P\nP;F\nF;P99\nNN;N\nNN;E\nC;K\"\n",
    ] {
        let _ = read(s.as_bytes(), &mut Budget::new(Limits::default()));
    }
}
