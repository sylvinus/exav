//! Whole workbooks: the fixture as Excel 97 saved it, encrypted here with
//! the default password; and BIFF2 to BIFF5 files built record by record.

use crate::formats::office::sheets::error::Error;
use crate::formats::office::sheets::limits::{Budget, Limits};
use crate::formats::office::sheets::model::*;
use exav_unpack::cfb::Compound;
use exav_unpack::offcrypto::encrypt;

const SAMPLE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/office/sheets/sample.xls"
));

fn read(bytes: &[u8]) -> Result<Workbook, Error> {
    super::read(bytes, &mut Budget::new(Limits::default()))
}

fn rec(id: u16, body: &[u8]) -> Vec<u8> {
    let mut r = id.to_le_bytes().to_vec();
    r.extend((body.len() as u16).to_le_bytes());
    r.extend(body);
    r
}

fn text(v: &Value) -> String {
    v.display()
}

/// The fixture's Workbook stream.
fn workbook_stream() -> Vec<u8> {
    Compound::open(SAMPLE)
        .unwrap()
        .stream(&["Workbook"])
        .unwrap()
}

/// `stream` with a FILEPASS for `method` after its BOF, the sheet positions
/// moved accordingly, then encrypted.
fn encrypted(method: &str) -> Vec<u8> {
    let s = workbook_stream();
    let bof_len = 4 + u16::from_le_bytes([s[2], s[3]]) as usize;
    let fp = rec(0x002F, &encrypt::filepass(method, true));
    let mut out = s[..bof_len].to_vec();
    out.extend(&fp);
    out.extend(&s[bof_len..]);
    // BOUNDSHEET: the substream's position, now further.
    let mut p = 0;
    while p + 4 <= out.len() {
        let id = u16::from_le_bytes([out[p], out[p + 1]]);
        let len = u16::from_le_bytes([out[p + 2], out[p + 3]]) as usize;
        if id == 0x0085 {
            let pos = u32::from_le_bytes(out[p + 4..p + 8].try_into().unwrap()) + fp.len() as u32;
            out[p + 4..p + 8].copy_from_slice(&pos.to_le_bytes());
        }
        p += 4 + len;
    }
    encrypt::encrypt_stream(method, &mut out, bof_len);
    out
}

/// What the fixture holds, read from any of its forms.
fn sample_content(wb: &Workbook) {
    let names: Vec<&str> = wb.sheets.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["Budget", "Notes"]);
    let s = &wb.sheets[0];
    assert_eq!(text(&s.cells[&(1, 0)].value), "Rent");
    assert_eq!(s.cells[&(2, 1)].value, Value::Number(345.5));
    assert_eq!(s.cells[&(4, 1)].formula.as_deref(), Some("SUM(B2:B4)"));
    assert_eq!(
        s.merges,
        [Range {
            r1: 5,
            c1: 0,
            r2: 5,
            c2: 2
        }]
    );
    let head = wb.styles.get(s.cells[&(0, 0)].style);
    assert!(head.font.bold);
    assert_eq!(head.fill.fg, Some(0x4472C4));
    assert_eq!(
        wb.styles.get(s.cells[&(1, 2)].style).numfmt,
        "yyyy\\-mm\\-dd"
    );
}

#[test]
fn the_fixture() {
    sample_content(&read(SAMPLE).unwrap());
    // The bare Workbook stream reads the same.
    sample_content(&read(&workbook_stream()).unwrap());
}

#[test]
fn encrypted_with_the_default_password() {
    for method in ["xor", "rc4", "cryptoapi40", "cryptoapi128"] {
        let data = encrypted(method);
        // Encrypted: the plain text is gone.
        assert!(!data.windows(4).any(|w| w == b"Rent"), "{method}");
        sample_content(&read(&data).unwrap_or_else(|e| panic!("{method}: {e}")));
    }
}

#[test]
fn another_password_is_refused() {
    let mut data = encrypted("rc4");
    // The verifier's hash, damaged: the password does not match.
    let fp = 4 + u16::from_le_bytes([data[2], data[3]]) as usize;
    data[fp + 4 + 6 + 16 + 3] ^= 0x55;
    assert_eq!(read(&data).unwrap_err(), Error::Encrypted);
}

/// A BIFF5 workbook: globals with two BOUNDSHEETs (8-bit names), then the
/// sheets' substreams.
fn biff5() -> Vec<u8> {
    let bof = |dt: u16| rec(0x0809, &[0x00, 0x05, dt as u8, (dt >> 8) as u8, 0, 0, 0, 0]);
    let eof = rec(0x000A, &[]);
    let sheet_a = {
        let mut s = bof(0x10);
        // LABEL A1 "Hello" (byte string), NUMBER B1 2.5, RK A2 10, FORMULA B2 = A2*B1.
        let mut label = vec![0, 0, 0, 0, 0x0F, 0, 5, 0];
        label.extend(b"Hello");
        s.extend(rec(0x0204, &label));
        let mut num = vec![0, 0, 1, 0, 0x0F, 0];
        num.extend(2.5f64.to_le_bytes());
        s.extend(rec(0x0203, &num));
        // RK 10: an integer, shifted left 2, flag 2.
        let mut rk = vec![1, 0, 0, 0, 0x0F, 0];
        rk.extend(((10u32 << 2) | 2).to_le_bytes());
        s.extend(rec(0x027E, &rk));
        // ptgRef A2 (BIFF5: row word with relative flags, column byte),
        // ptgRef B1, ptgMul.
        let rgce = [0x24, 0x01, 0xC0, 0x00, 0x24, 0x00, 0xC0, 0x01, 0x05];
        let mut f = vec![1, 0, 1, 0, 0x0F, 0];
        f.extend(25.0f64.to_le_bytes());
        f.extend([0, 0, 0, 0, 0, 0]);
        f.extend((rgce.len() as u16).to_le_bytes());
        f.extend(rgce);
        s.extend(rec(0x0006, &f));
        s.extend(&eof);
        s
    };
    let sheet_b = {
        let mut s = bof(0x10);
        let mut label = vec![0, 0, 0, 0, 0x0F, 0, 3, 0];
        label.extend(b"\xe9t\xe9");
        s.extend(rec(0x0204, &label));
        s.extend(&eof);
        s
    };
    let boundsheet = |pos: u32, name: &[u8]| {
        let mut b = pos.to_le_bytes().to_vec();
        b.extend([0, 0, name.len() as u8]);
        b.extend(name);
        rec(0x0085, &b)
    };
    // Code page 1252, then the BOUNDSHEETs at their final positions.
    let head_len = bof(5).len()
        + rec(0x0042, &[0, 0]).len()
        + boundsheet(0, b"First").len()
        + boundsheet(0, b"Second").len()
        + eof.len();
    let mut g = bof(5);
    g.extend(rec(0x0042, &1252u16.to_le_bytes()));
    g.extend(boundsheet(head_len as u32, b"First"));
    g.extend(boundsheet((head_len + sheet_a.len()) as u32, b"Second"));
    g.extend(&eof);
    assert_eq!(g.len(), head_len);
    g.extend(sheet_a);
    g.extend(sheet_b);
    g
}

#[test]
fn biff5_workbook() {
    let wb = read(&biff5()).unwrap();
    assert_eq!(
        wb.sheets
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>(),
        ["First", "Second"]
    );
    let s = &wb.sheets[0];
    assert_eq!(s.cells[&(0, 0)].value, Value::text("Hello"));
    assert_eq!(s.cells[&(0, 1)].value, Value::Number(2.5));
    assert_eq!(s.cells[&(1, 0)].value, Value::Number(10.0));
    assert_eq!(s.cells[&(1, 1)].formula.as_deref(), Some("A2*B1"));
    assert_eq!(s.cells[&(1, 1)].value, Value::Number(25.0));
    // Windows-1252 text.
    assert_eq!(wb.sheets[1].cells[&(0, 0)].value, Value::text("été"));
}

#[test]
fn biff2_to_biff4_worksheets() {
    // BIFF2: LABEL with 3 attribute bytes and an 8-bit length, INTEGER,
    // NUMBER; BIFF3 and BIFF4: LABEL and NUMBER with an XF index.
    let mut b2 = rec(0x0009, &[2, 0, 0x10, 0]);
    let mut label = vec![0, 0, 0, 0, 0, 0, 0, 2];
    label.extend(b"Hi");
    b2.extend(rec(0x0004, &label));
    b2.extend(rec(0x0002, &[1, 0, 0, 0, 0, 0, 0, 42, 0]));
    let mut num = vec![2, 0, 0, 0, 0, 0, 0];
    num.extend(0.5f64.to_le_bytes());
    b2.extend(rec(0x0003, &num));
    b2.extend(rec(0x000A, &[]));
    let wb = read(&b2).unwrap();
    let s = &wb.sheets[0];
    assert_eq!(s.cells[&(0, 0)].value, Value::text("Hi"));
    assert_eq!(s.cells[&(1, 0)].value, Value::Number(42.0));
    assert_eq!(s.cells[&(2, 0)].value, Value::Number(0.5));
    for bof in [0x0209u16, 0x0409] {
        let mut b = rec(bof, &[0, 3, 0x10, 0, 0, 0]);
        let mut label = vec![0, 0, 1, 0, 0, 0, 3, 0];
        label.extend(b"abc");
        b.extend(rec(0x0204, &label));
        let mut num = vec![1, 0, 1, 0, 0, 0];
        num.extend(7.25f64.to_le_bytes());
        b.extend(rec(0x0203, &num));
        b.extend(rec(0x000A, &[]));
        let wb = read(&b).unwrap();
        assert_eq!(
            wb.sheets[0].cells[&(0, 1)].value,
            Value::text("abc"),
            "{bof:x}"
        );
        assert_eq!(
            wb.sheets[0].cells[&(1, 1)].value,
            Value::Number(7.25),
            "{bof:x}"
        );
    }
}

#[test]
fn damaged_compound_files_are_read_leniently() {
    // The fixture cut short of its last sector, and with garbage where the
    // header's mini stream cutoff is: still read.
    let mut d = SAMPLE.to_vec();
    d[56..60].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    sample_content(&read(&d).unwrap());
    let short = &SAMPLE[..SAMPLE.len() - 100];
    let _ = read(short);
    // Bytes flipped one at a time across the file: never a panic.
    for i in (0..SAMPLE.len()).step_by(13) {
        let mut d = SAMPLE.to_vec();
        d[i] ^= 0xFF;
        let _ = read(&d);
    }
}

/// A shared string whose header ends with its record: the CONTINUE that holds
/// the characters starts with the width flag, which may differ from the
/// header's. Strings after it were read as 8-bit when they were 16-bit.
#[test]
fn a_string_whose_header_ends_its_record_takes_the_width_of_the_next() {
    use super::SplitReader;
    // 3 characters, flags 0 (8-bit) in the first record; the second says 16-bit.
    let mut d = vec![3, 0, 0];
    d.extend([1, b'x', 0, b'y', 0, b'z', 0]);
    let mut r = SplitReader {
        d: &d,
        breaks: &[3],
        p: 0,
    };
    assert_eq!(r.rich().0, "xyz");
    // The same string with the flag byte first in the record when 8-bit stays so.
    let mut d = vec![3, 0, 0];
    d.extend([0, b'a', b'b', b'c']);
    let mut r = SplitReader {
        d: &d,
        breaks: &[3],
        p: 0,
    };
    assert_eq!(r.rich().0, "abc");
}
