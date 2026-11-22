//! CSV and TSV, read into a workbook of one sheet whose cells are all text.
//!
//! The encoding is chosen by exav-unpack's rule for text files. The separator
//! is the comma, semicolon or tab that cuts every one of the first rows into
//! the same number of fields, found with the reader that then reads the whole
//! file. Fields follow RFC 4180 (a quote opens a quoted field only at its
//! start, `""` inside one is a quote), with `\n`, `\r\n` and a lone `\r` as
//! line ends and no row for a blank line.

use crate::formats::office::sheets::error::{Error, Result};
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use exav_unpack::text::Encoding;
use std::iter::Peekable;
use std::str::Chars;

/// Rows weighed to find the separator.
const SNIFF_ROWS: usize = 20;

/// What a separator can be. A file that reads as a table under several is
/// read with the first of them that gives it the most fields.
const DELIMITERS: [char; 3] = [',', ';', '\t'];

/// Characters XML 1.0 cannot hold, and the two it forbids as non-characters.
/// A field loses them (a DOS text ends with Ctrl-Z).
fn dropped(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' | '\u{fffe}' | '\u{ffff}')
}

struct Scanner<'a> {
    chars: Peekable<Chars<'a>>,
    delimiter: char,
    buf: String,
}

impl<'a> Scanner<'a> {
    fn new(text: &'a str, delimiter: char) -> Self {
        Scanner {
            chars: text.chars().peekable(),
            delimiter,
            buf: String::new(),
        }
    }

    /// Reads the next row, giving each of its fields to `field` (a `dyn`, so
    /// that the reader is compiled once for the sniff and the read). `false`
    /// at the end of the text; a blank line is no row.
    fn row(&mut self, field: &mut dyn FnMut(&str) -> Result<()>) -> Result<bool> {
        let mut quoted = false;
        // Whether the row has any text, and whether a field of it has ended.
        let mut started = false;
        let mut ended = false;
        // Whether no character of the current field has been read yet.
        let mut fresh = true;
        self.buf.clear();
        loop {
            let Some(c) = self.chars.next() else {
                if started || ended {
                    field(&self.buf)?;
                    return Ok(true);
                }
                return Ok(false);
            };
            if quoted {
                if c == '"' {
                    if self.chars.next_if_eq(&'"').is_some() {
                        self.buf.push('"');
                    } else {
                        quoted = false;
                    }
                } else if !dropped(c) {
                    self.buf.push(c);
                }
            } else if c == '"' && fresh {
                quoted = true;
                started = true;
                fresh = false;
            } else if c == self.delimiter {
                field(&self.buf)?;
                self.buf.clear();
                ended = true;
                started = true;
                fresh = true;
            } else if c == '\n' || c == '\r' {
                if c == '\r' {
                    self.chars.next_if_eq(&'\n');
                }
                if started || ended {
                    field(&self.buf)?;
                    return Ok(true);
                }
            } else {
                started = true;
                fresh = false;
                if !dropped(c) {
                    self.buf.push(c);
                }
            }
        }
    }
}

/// The separator of `text`: the one that gives the first rows the same number
/// of fields, and the most of them. Counting occurrences instead would read
/// a free-text column with punctuation in it as the separator. Nothing fits
/// (one column, or ragged rows) and it is the comma.
fn sniff(text: &str) -> char {
    let mut best = DELIMITERS[0];
    let mut widest = 1;
    for delimiter in DELIMITERS {
        let mut scanner = Scanner::new(text, delimiter);
        let mut first = None;
        let mut ragged = false;
        for _ in 0..SNIFF_ROWS {
            let mut width = 0usize;
            let more = scanner.row(&mut |_| {
                width += 1;
                Ok(())
            });
            if !matches!(more, Ok(true)) {
                break;
            }
            if *first.get_or_insert(width) != width {
                ragged = true;
                break;
            }
        }
        if let Some(width) = first.filter(|&w| !ragged && w > widest) {
            best = delimiter;
            widest = width;
        }
    }
    best
}

/// windows-1252 for the bytes 0x80 to 0x9f, as the WHATWG Encoding Standard
/// has it (the five that Microsoft leaves undefined stay C1 controls).
const WINDOWS_1252: [char; 32] = [
    '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8d}', 'Ž', '\u{8f}',
    '\u{90}', '‘', '’', '“', '”', '•', '–', '\u{2014}', '˜', '™', 'š', '›', 'œ', '\u{9d}', 'ž',
    'Ÿ',
];

/// `body` as text in `encoding`, a bad sequence a U+FFFD. The choice of
/// encoding is exav-unpack's; the four are decoded here, without the tables
/// of a general decoder, which would add much to the size of the wasm module.
fn decode(body: &[u8], encoding: Encoding) -> String {
    match encoding {
        Encoding::Utf8 => String::from_utf8_lossy(body).into_owned(),
        Encoding::Utf16Le | Encoding::Utf16Be => {
            let (pairs, rest) = body.as_chunks::<2>();
            let units = pairs.iter().map(|&p| {
                if encoding == Encoding::Utf16Be {
                    u16::from_be_bytes(p)
                } else {
                    u16::from_le_bytes(p)
                }
            });
            let mut out: String = char::decode_utf16(units)
                .map(|c| c.unwrap_or('\u{fffd}'))
                .collect();
            if !rest.is_empty() {
                out.push('\u{fffd}');
            }
            out
        }
        Encoding::Windows1252 => body
            .iter()
            .map(|&b| match b {
                0x80..=0x9f => WINDOWS_1252[usize::from(b - 0x80)],
                _ => char::from(b),
            })
            .collect(),
    }
}

/// Reads `bytes` into a workbook of one sheet: a text cell for each field
/// that is not empty, every field counted against the cell limit.
pub(crate) fn read(bytes: &[u8], budget: &mut Budget) -> Result<Workbook> {
    let reading = exav_unpack::text::file_reading(bytes, false)
        .ok_or_else(|| Error::NotFormat("not a text file".into()))?;
    let text = decode(&bytes[reading.start..reading.end], reading.encoding);
    budget.alloc(text.len() as u64)?;
    let mut scanner = Scanner::new(&text, sniff(&text));

    // Calibri 11 and the sizes Excel gives its sheets.
    let mut style = Style::default();
    style.font.name = "Calibri".into();
    style.font.size_centipt = 1100;
    let mut wb = Workbook::new(style);
    let mut sheet = Sheet::new("Sheet1".into());
    sheet.default_row_height = 15.0;
    sheet.default_col_width = Some(8.43);

    let mut row = 0u32;
    loop {
        let mut col = 0u32;
        let more = scanner.row(&mut |field| {
            if row > MAX_ROW {
                return Err(Error::TooLarge("rows"));
            }
            if col > MAX_COL {
                return Err(Error::TooLarge("columns"));
            }
            budget.cell(field.len())?;
            if !field.is_empty() {
                sheet.cells.insert(
                    (row, col),
                    Cell {
                        value: Value::text(field),
                        formula: None,
                        style: 0,
                    },
                );
            }
            col += 1;
            Ok(())
        })?;
        if !more {
            break;
        }
        row += 1;
    }
    wb.sheets.push(sheet);
    Ok(wb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::sheets::{Limits, convert_csv};

    /// The cells of the sheet `bytes` is read into, row by row.
    fn rows(bytes: &[u8]) -> Vec<Vec<String>> {
        let wb = read(bytes, &mut Budget::new(Limits::default())).unwrap();
        let cells = &wb.sheets[0].cells;
        let last = cells.keys().map(|&(r, _)| r).max().map_or(0, |r| r + 1);
        (0..last)
            .map(|r| {
                let width = cells.keys().filter(|k| k.0 == r).map(|k| k.1 + 1).max();
                (0..width.unwrap_or(0))
                    .map(|c| {
                        cells
                            .get(&(r, c))
                            .map_or(String::new(), |c| c.value.display())
                    })
                    .collect()
            })
            .collect()
    }

    fn strings(rows: &[&[&str]]) -> Vec<Vec<String>> {
        rows.iter()
            .map(|r| r.iter().map(|s| s.to_string()).collect())
            .collect()
    }

    fn utf16(text: &str, big: bool) -> Vec<u8> {
        let mut out = if big {
            vec![0xfe, 0xff]
        } else {
            vec![0xff, 0xfe]
        };
        for u in text.encode_utf16() {
            out.extend(if big {
                u.to_be_bytes()
            } else {
                u.to_le_bytes()
            });
        }
        out
    }

    #[test]
    fn quotes_hold_separators_quotes_and_line_ends() {
        let doc = "a;\"b;c\";\"say \"\"hi\"\"\";\"x\ny\"\n5\" pipe;z;w;v\n";
        assert_eq!(
            rows(doc.as_bytes()),
            strings(&[
                &["a", "b;c", "say \"hi\"", "x\ny"],
                &["5\" pipe", "z", "w", "v"]
            ])
        );
    }

    #[test]
    fn a_separator_in_a_quoted_field_does_not_count() {
        let doc = "lot,observation\n03,\"reprise; enduit; joints\"\n";
        assert_eq!(
            rows(doc.as_bytes()),
            strings(&[&["lot", "observation"], &["03", "reprise; enduit; joints"]])
        );
    }

    /// Quotes in the middle of a field are text. The earlier reader toggled
    /// "quoted" on each of them when it looked for the separator, so an odd
    /// number of them in the first rows left a comma to win.
    #[test]
    fn stray_quotes_do_not_hide_the_separator() {
        let doc = "5\" pipe;x\n6\" pipe;y\n7\" pipe;z\n";
        assert_eq!(
            rows(doc.as_bytes()),
            strings(&[&["5\" pipe", "x"], &["6\" pipe", "y"], &["7\" pipe", "z"]])
        );
    }

    /// Every kind of line end ends a row when the separator is looked for, as
    /// when the rows are read. The earlier reader weighed a file with lone
    /// carriage returns as one row and could pick the wrong separator.
    #[test]
    fn line_ends_are_crlf_cr_and_lf_and_blank_lines_are_no_rows() {
        let doc = "a;b\r\nc;d\re;f\ng;h\n\n\"p\r\nq\";r\r\n\r\n";
        assert_eq!(
            rows(doc.as_bytes()),
            strings(&[
                &["a", "b"],
                &["c", "d"],
                &["e", "f"],
                &["g", "h"],
                &["p\r\nq", "r"]
            ])
        );
        assert_eq!(
            rows(b"x,y\rp;q;r;s,t\r"),
            strings(&[&["x", "y"], &["p;q;r;s", "t"]])
        );
    }

    #[test]
    fn a_byte_order_mark_is_not_text() {
        let utf8 = b"\xef\xbb\xbf\"a\";b\n1;2\n";
        let want = strings(&[&["a", "b"], &["1", "2"]]);
        assert_eq!(rows(utf8), want);
        let text = "\"a\";b\n1;2\n";
        assert_eq!(rows(&utf16(text, false)), want);
        assert_eq!(rows(&utf16(text, true)), want);
    }

    /// The encoding is the one of the whole file, not of its first 64 KiB, as
    /// exav-unpack reads a text file. A windows-1252 file whose first accent
    /// is late was read as UTF-8 with a replacement character; a UTF-8 file
    /// with one stray byte is now read as windows-1252 throughout.
    #[test]
    fn the_encoding_is_that_of_the_whole_file() {
        assert_eq!(
            rows(b"libell\xe9;qt\xe9\n1;2\n"),
            strings(&[&["libellé", "qté"], &["1", "2"]])
        );
        // The bytes 0x80 to 0x9f are the euro sign, quotes and the like.
        assert_eq!(rows(b"prix\x80;it\x92s\n"), strings(&[&["prix€", "it’s"]]));
        let mut late = "a;b\n".repeat(20_000).into_bytes();
        late.extend(b"libell\xe9;x\n");
        assert_eq!(rows(&late).last().unwrap(), &["libellé", "x"]);
        let mut stray = "libellé;b\n".repeat(20_000).into_bytes();
        stray.extend(b"\xe9;x\n");
        let read = rows(&stray);
        assert_eq!(read[0], ["libellÃ©", "b"]);
        assert_eq!(read.last().unwrap(), &["é", "x"]);
    }

    /// UTF-16 without a byte-order mark and UTF-32 are not read: the earlier
    /// reader took them for windows-1252 or UTF-16 and dropped the NULs.
    #[test]
    fn what_is_not_text_is_refused() {
        let utf16_plain: Vec<u8> = "a;b\n1;2\n".bytes().flat_map(|b| [b, 0]).collect();
        let utf32 = b"\xff\xfe\0\0a\0\0\0;\0\0\0b\0\0\0".to_vec();
        for doc in [utf16_plain, utf32] {
            let err = read(&doc, &mut Budget::new(Limits::default())).unwrap_err();
            assert_eq!(err.kind(), "not-format");
        }
    }

    /// Cells of the XLSX: every field is text, an empty one is no cell, the
    /// characters XML cannot hold are dropped, the spaces around a field are
    /// kept, and a text that looks like an escape is escaped so that it reads
    /// back as written (the earlier writer left it, and a reader took it for
    /// the character it names).
    #[test]
    fn the_xlsx_holds_the_cells_as_text() {
        let doc = "id;note\n1;_x0041_\n2;  padded  \n3;b\u{1}c\u{1a}\n4;\n";
        let xlsx = convert_csv(doc.as_bytes(), &Limits::default())
            .unwrap()
            .xlsx;
        let mut zip = crate::formats::office::common::package::Zip::open(&xlsx).unwrap();
        let mut part =
            |name: &str| String::from_utf8(zip.read(name, 1 << 20).unwrap().unwrap()).unwrap();
        let sheet = part("xl/worksheets/sheet1.xml");
        for cell in ["A1", "B1", "A5", "B4"] {
            assert!(sheet.contains(&format!("r=\"{cell}\"")), "{cell}");
        }
        assert!(!sheet.contains("r=\"B5\""));
        let strings = part("xl/sharedStrings.xml");
        for text in ["_x005F_x0041_", "  padded  ", ">bc<"] {
            assert!(strings.contains(text), "{text}");
        }
        assert!(!strings.contains("_x0001_"));
    }

    /// Past the sheet an XLSX can hold, a table is refused: the earlier
    /// writer named cells that do not exist.
    #[test]
    fn a_table_past_the_sheet_is_refused() {
        let limits = Limits::default();
        let wide = format!("{}a\n", "a,".repeat(usize::try_from(MAX_COL).unwrap() + 1));
        assert_eq!(
            convert_csv(wide.as_bytes(), &limits).unwrap_err(),
            Error::TooLarge("columns")
        );
        let edge = format!("{}a\n", "a,".repeat(usize::try_from(MAX_COL).unwrap()));
        assert!(convert_csv(edge.as_bytes(), &limits).is_ok());
        let tall = "a\n".repeat(usize::try_from(MAX_ROW).unwrap() + 2);
        assert_eq!(
            convert_csv(tall.as_bytes(), &limits).unwrap_err(),
            Error::TooLarge("rows")
        );
    }

    #[test]
    fn the_cell_limit_counts_empty_fields() {
        let doc = b"a,b\n,\n";
        assert!(convert_csv(doc, &Limits::default().with_max_cells(4)).is_ok());
        assert_eq!(
            convert_csv(doc, &Limits::default().with_max_cells(3)).unwrap_err(),
            Error::TooLarge("cells")
        );
    }
}
