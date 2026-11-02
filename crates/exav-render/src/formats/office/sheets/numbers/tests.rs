//! Documents built here, object by object, with the protobuf writer and
//! literal-only Snappy blocks.

use super::proto::write::W;
use crate::formats::office::common::iwa::snappy::literal_block;
use crate::formats::office::sheets::error::Error;
use crate::formats::office::sheets::limits::{Budget, Limits};
use crate::formats::office::sheets::model::*;
use std::io::Write;

/// One IWA stream holding `objects` (identifier, message type, payload).
fn iwa(objects: &[(u64, u32, W)]) -> Vec<u8> {
    let mut raw = vec![];
    for (id, kind, m) in objects {
        let info = W::default().uint(1, *id).msg(
            2,
            W::default()
                .uint(1, u64::from(*kind))
                .uint(3, m.0.len() as u64),
        );
        raw.extend(W::varint_len(info.0.len() as u64));
        raw.extend(&info.0);
        raw.extend(&m.0);
    }
    let block = literal_block(&raw);
    let mut out = vec![
        0u8,
        block.len() as u8,
        (block.len() >> 8) as u8,
        (block.len() >> 16) as u8,
    ];
    out.extend(block);
    out
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

/// A v5 cell record: `kind`, then the fields of `flags` from `fields`.
fn cell(kind: u8, flags: u32, fields: &[u8]) -> Vec<u8> {
    let mut b = vec![5, kind, 0, 0, 0, 0, 0, 0];
    b.extend(flags.to_le_bytes());
    b.extend(fields);
    b
}

fn decimal(m: u64) -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b[..8].copy_from_slice(&m.to_le_bytes());
    let e = 6176u32;
    b[14] |= ((e & 0x7F) << 1) as u8;
    b[15] |= (e >> 7) as u8;
    b
}

/// A tile row: records for columns 0.., wide offsets.
fn row(index: u64, cells: &[Option<Vec<u8>>]) -> W {
    let mut storage = vec![];
    let mut offsets = vec![];
    for c in cells {
        match c {
            Some(rec) => {
                offsets.extend(((storage.len() / 4) as i16).to_le_bytes());
                storage.extend(rec);
                while storage.len() % 4 != 0 {
                    storage.push(0);
                }
            }
            None => offsets.extend((-1i16).to_le_bytes()),
        }
    }
    W::default()
        .uint(1, index)
        .uint(2, cells.iter().flatten().count() as u64)
        .bytes(6, &storage)
        .bytes(7, &offsets)
        .uint(8, 1)
}

fn entry(key: u64) -> W {
    W::default().uint(1, key).uint(2, 1)
}

/// A document with two tables on one sheet: T1 (3 rows, 2 columns, one
/// header row) and T2, which a formula of T1 refers to.
fn document() -> Vec<u8> {
    let num = |v: u64| cell(2, 0x1, &decimal(v));
    let text = |k: u32| cell(3, 0x8, &k.to_le_bytes());
    // B3 = A3 + T2::A1, as postfix: A3, T2::A1, +.
    let rel = |r: i64, c: i64| {
        W::default()
            .uint(1, 36)
            .msg(27, W::default().sint(1, r))
            .msg(26, W::default().sint(1, c))
    };
    let t2_uuid = W::default()
        .uint(2, 0x11)
        .uint(3, 0x22)
        .uint(4, 0x33)
        .uint(5, 0x44);
    let cross = W::default()
        .uint(1, 36)
        .msg(27, W::default().sint(1, 0).uint(2, 1))
        .msg(26, W::default().sint(1, 0).uint(2, 1))
        .msg(28, W::default().msg(1, t2_uuid));
    let ast = W::default()
        .msg(1, rel(0, -1))
        .msg(1, cross)
        .msg(1, W::default().uint(1, 1));
    let formula_cell = {
        let mut f = decimal(15);
        f.extend(1u32.to_le_bytes());
        cell(2, 0x1 | 0x200, &f)
    };
    let tile = W::default()
        .msg(5, row(0, &[Some(text(1)), Some(text(2))]))
        .msg(5, row(1, &[Some(num(4)), Some(num(5))]))
        .msg(5, row(2, &[Some(num(6)), Some(formula_cell)]))
        .uint(7, 1);
    let strings = W::default()
        .uint(1, 1)
        .msg(3, entry(1).bytes(3, b"Name"))
        .msg(3, entry(2).bytes(3, b"Value"));
    let formulas = W::default()
        .uint(1, 3)
        .msg(3, entry(1).msg(5, W::default().msg(1, ast)));
    let cols = W::default().uint(1, 1).msg(
        2,
        W::default()
            .uint(1, 1)
            .float(2, 140.0)
            .uint(3, 0)
            .uint(4, 3),
    );
    let merge = W::default().msg(
        1,
        W::default()
            .msg(1, W::default().fixed32(1, 0))
            .msg(2, W::default().fixed32(1, (2 << 16) | 1)),
    );
    let store = W::default()
        .msg(1, W::default().uint(1, 1))
        .reference(2, 31)
        .msg(
            3,
            W::default()
                .msg(1, W::default().uint(1, 0).reference(2, 20))
                .uint(2, 256),
        )
        .reference(4, 21)
        .reference(6, 22)
        .reference(13, 23);
    let t1 = W::default()
        .bytes(1, b"t1")
        .msg(4, store)
        .uint(6, 3)
        .uint(7, 2)
        .bytes(8, b"T1")
        .uint(9, 1)
        .uint(10, 0)
        .uint(12, 1)
        .double(16, 18.0)
        .double(17, 98.0)
        .msg(84, W::default().msg(1, W::default().uint(1, 7).uint(2, 0)));
    let t2_tile = W::default().msg(5, row(0, &[Some(num(10))])).uint(7, 1);
    let t2 = W::default()
        .bytes(1, b"t2")
        .msg(
            4,
            W::default().msg(
                3,
                W::default()
                    .msg(1, W::default().uint(1, 0).reference(2, 40))
                    .uint(2, 256),
            ),
        )
        .uint(6, 1)
        .uint(7, 1)
        .bytes(8, b"T2")
        .double(16, 20.0)
        .double(17, 98.0)
        .msg(84, W::default().msg(1, W::default().uint(1, 8).uint(2, 0)));
    // T2's haunted owner (owner_uid 8) maps to the base UUID references use.
    let base = W::default()
        .uint(1, 0x22 << 32 | 0x11)
        .uint(2, 0x44 << 32 | 0x33);
    let owner = W::default()
        .msg(1, W::default().uint(1, 8).uint(2, 0))
        .uint(2, 1)
        .uint(3, 35)
        .msg(12, base);
    let objects = vec![
        (1, 1, W::default().reference(1, 2)),
        (
            2,
            2,
            W::default()
                .bytes(1, b"Sheet 1")
                .reference(2, 3)
                .reference(2, 4),
        ),
        (3, 6000, W::default().reference(2, 10)),
        (4, 6000, W::default().reference(2, 11)),
        (10, 6001, t1),
        (11, 6001, t2),
        (20, 6002, tile),
        (21, 6005, strings),
        (22, 6005, formulas),
        (23, 6144, merge),
        (31, 6006, cols),
        (40, 6002, t2_tile),
        (50, 4008, owner),
    ];
    let doc = iwa(&objects);
    zip(&[("Index/Document.iwa", &doc)])
}

fn read(bytes: &[u8]) -> Result<Workbook, Error> {
    super::read(bytes, &mut Budget::new(Limits::default()))
}

#[test]
fn tables_become_sheets() {
    let wb = read(&document()).unwrap();
    let names: Vec<&str> = wb.sheets.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["Sheet 1 - T1", "Sheet 1 - T2"]);
    let s = &wb.sheets[0];
    assert_eq!(s.cells[&(0, 0)].value, Value::text("Name"));
    assert_eq!(s.cells[&(1, 1)].value, Value::Number(5.0));
    // The formula, with the reference to the other table by its sheet.
    let f = &s.cells[&(2, 1)];
    assert_eq!(f.formula.as_deref(), Some("A3+'Sheet 1 - T2'!$A$1"));
    assert_eq!(f.value, Value::Number(15.0));
    // Header row frozen, the merge, the column width, the row height.
    assert_eq!(s.freeze, Some((1, 0)));
    assert_eq!(
        s.merges,
        [Range {
            r1: 0,
            c1: 0,
            r2: 0,
            c2: 1
        }]
    );
    assert_eq!(
        s.col_info(1).and_then(|c| c.width),
        Some((140.0f64 * 96.0 / 72.0 / 7.0 * 256.0).round() / 256.0)
    );
    assert_eq!(s.default_row_height, 18.0);
    assert!(!s.show_grid);
}

#[test]
fn the_text_of_the_tables() {
    let wb = read(&document()).unwrap();
    let t = crate::formats::office::sheets::text::of(&wb, 1000);
    // The formula's cached value, not its source.
    assert_eq!(
        t.text,
        "Sheet 1 - T1\nName\tValue\n4\t5\n6\t15\nSheet 1 - T2\n10\n"
    );
    assert!(!t.truncated);
}

#[test]
fn refusals() {
    let enc = zip(&[("Index/Document.iwa", b"x"), (".iwpv2", b"x")]);
    assert_eq!(read(&enc).unwrap_err(), Error::Encrypted);
    // Numbers '09: its XML is read, here not XML at all.
    let old = zip(&[("index.xml.gz", b"x")]);
    assert!(matches!(read(&old), Err(Error::NotFormat(_))));
    let empty = zip(&[("Index/Document.iwa", &iwa(&[(9, 2, W::default())]))]);
    assert!(matches!(read(&empty), Err(Error::NotFormat(_))));
    assert!(matches!(read(b"not a zip"), Err(Error::NotFormat(_))));
}

#[test]
fn nested_index_zip() {
    let doc = document();
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(&doc[..])).unwrap();
    let mut iwa = vec![];
    std::io::Read::read_to_end(&mut z.by_name("Index/Document.iwa").unwrap(), &mut iwa).unwrap();
    let inner = zip(&[("Index/Document.iwa", &iwa)]);
    let outer = zip(&[("Doc.numbers/Index.zip", &inner)]);
    assert_eq!(read(&outer).unwrap().sheets.len(), 2);
}

#[test]
fn damaged_documents_do_not_panic() {
    let doc = document();
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(&doc[..])).unwrap();
    let mut iwa = vec![];
    std::io::Read::read_to_end(&mut z.by_name("Index/Document.iwa").unwrap(), &mut iwa).unwrap();
    // Every truncation, and bytes flipped one at a time.
    for n in (0..iwa.len()).step_by(7) {
        let _ = read(&zip(&[("Index/Document.iwa", &iwa[..n])]));
    }
    for i in (4..iwa.len()).step_by(3) {
        let mut d = iwa.clone();
        d[i] ^= 0xA5;
        let _ = read(&zip(&[("Index/Document.iwa", &d)]));
    }
}

#[test]
fn cells_are_counted() {
    let r = super::read(
        &document(),
        &mut Budget::new(Limits::default().with_max_cells(3)),
    );
    assert_eq!(r.unwrap_err(), Error::TooLarge("cells"));
}
