//! What a BIFF workbook's global records say that formulas need: the code
//! page, the sheets, the defined names and the external references their
//! tokens point at.

use super::formula::{Ctx, read_chars};
use super::record::Rec;
use crate::bytes::Cur;
use crate::formats::charset;

/// A BOUNDSHEET record.
pub struct BoundSheet {
    /// Offset of the sheet's BOF in the stream.
    pub pos: usize,
    pub name: String,
    pub state: u8,
    /// 0 worksheet, 1 Excel 4.0 macro sheet, 2 chart, 6 Visual Basic module.
    pub kind: u8,
}

/// A NAME record.
pub struct Name {
    pub name: String,
    /// 1-based sheet of a local name.
    pub sheet: u16,
    pub hidden: bool,
    pub rgce: Vec<u8>,
    /// What follows `rgce`: the data its array constants keep.
    pub extra: Vec<u8>,
}

/// A BIFF8 SUPBOOK record.
#[derive(Default, Clone, Debug)]
pub struct Supbook {
    pub internal: bool,
    pub addin: bool,
    /// An external workbook's number among them, from 1.
    pub ext_index: usize,
    pub sheets: Vec<String>,
    pub names: Vec<String>,
}

/// A BIFF5 EXTERNSHEET entry.
#[derive(Clone, Debug)]
pub enum ExtSheet5 {
    /// A sheet of this workbook (by name), or the workbook itself.
    Own,
    /// An external document's sheet: its number among external documents.
    External { doc: usize, sheet: String },
    /// Add-in functions: the names that follow.
    Names(Vec<String>),
}

/// The workbook-wide tables, filled by [`Book::record`] from the records of
/// the globals substream (all of a BIFF2 to BIFF4 stream's records).
pub struct Book {
    /// 2, 3, 4, 5 or 8.
    pub ver: u8,
    pub codepage: u16,
    pub sheets: Vec<BoundSheet>,
    pub names: Vec<Name>,
    /// BIFF8 EXTERNSHEET entries: (supbook, first sheet, last sheet).
    pub xti: Vec<(u16, i16, i16)>,
    pub supbooks: Vec<Supbook>,
    /// BIFF5 globals' EXTERNSHEET entries (for names).
    pub ext5: Vec<ExtSheet5>,
    /// The names of `sheets`, which formulas refer to; set by [`Book::finish`]
    /// or by a reader that knows better.
    pub sheet_names: Vec<String>,
    /// The names of `names`; set by [`Book::finish`].
    pub name_texts: Vec<String>,
    /// External documents, numbered from 1 by their place here.
    ext_docs: Vec<String>,
}

impl Book {
    pub fn new(ver: u8) -> Book {
        Book {
            ver,
            codepage: if ver >= 8 { 1200 } else { 1252 },
            sheets: vec![],
            names: vec![],
            xti: vec![],
            supbooks: vec![],
            ext5: vec![],
            sheet_names: vec![],
            name_texts: vec![],
            ext_docs: vec![],
        }
    }

    /// Takes the record if it is one of the tables'. Returns whether it was.
    pub fn record(&mut self, r: &Rec) -> bool {
        let ver = self.ver;
        let mut c = Cur::new(&r.data);
        match r.id {
            0x0042 => {
                self.codepage = c.u16();
                if ver >= 8 {
                    self.codepage = 1200;
                }
            }
            0x0085 => {
                let pos = c.u32() as usize;
                let state = c.u8();
                let kind = c.u8();
                let name = self.string(&mut c, 1);
                self.sheets.push(BoundSheet {
                    pos,
                    name,
                    state,
                    kind,
                });
            }
            0x0018 | 0x0218 => {
                let n = self.name(r);
                self.names.push(n);
            }
            0x0017 if ver >= 8 => {
                let n = c.u16() as usize;
                for _ in 0..n {
                    let sb = c.u16();
                    let a = c.i16();
                    let b = c.i16();
                    if c.short {
                        break;
                    }
                    self.xti.push((sb, a, b));
                }
            }
            0x0017 => {
                let e = self.ext_sheet5(&r.data);
                self.ext5.push(e);
            }
            0x01AE => {
                let ctab = c.u16();
                let cch = c.u16();
                let mut sb = Supbook::default();
                if cch == 0x0401 {
                    sb.internal = true;
                } else if cch == 0x3A01 {
                    sb.addin = true;
                } else {
                    let mut c2 = Cur::at(&r.data, 2);
                    let url = self.string(&mut c2, 2);
                    for _ in 0..ctab.min(4096) {
                        if c2.left() == 0 {
                            break;
                        }
                        sb.sheets.push(self.string(&mut c2, 2));
                    }
                    sb.ext_index = self.ext_doc(&url);
                }
                self.supbooks.push(sb);
            }
            0x0023 => {
                if ver >= 8 {
                    let _flags = c.u16();
                    c.u32();
                    let name = self.string(&mut c, 1);
                    if let Some(sb) = self.supbooks.last_mut() {
                        sb.names.push(name);
                    }
                } else if ver == 5 {
                    c.skip(6);
                    let n = c.u8() as usize;
                    let name = charset::decode(c.bytes(n), self.codepage);
                    if let Some(ExtSheet5::Names(v)) = self.ext5.last_mut() {
                        v.push(name);
                    }
                }
            }
            _ => return false,
        }
        true
    }

    /// Fills `sheet_names` and `name_texts` from the records read.
    pub fn finish(&mut self) {
        self.sheet_names = self.sheets.iter().map(|s| s.name.clone()).collect();
        self.name_texts = self.names.iter().map(|n| n.name.clone()).collect();
    }

    /// What a formula needs to name what it refers to. `ext5` is the
    /// EXTERNSHEET entries in scope (a BIFF5 sheet's, or the globals').
    pub fn ctx<'a>(&'a self, ext5: &'a [ExtSheet5]) -> Ctx<'a> {
        Ctx {
            ver: self.ver,
            sheets: &self.sheet_names,
            names: &self.name_texts,
            xti: &self.xti,
            supbooks: &self.supbooks,
            ext5,
            codepage: self.codepage,
        }
    }

    /// A string in the BIFF5-and-older code page, or BIFF8's Unicode, with
    /// a length of `len_bytes` (1 or 2) before it.
    pub fn string(&self, c: &mut Cur, len_bytes: u8) -> String {
        let n = if len_bytes == 1 {
            c.u8() as usize
        } else {
            c.u16() as usize
        };
        if self.ver >= 8 {
            let f = c.u8();
            read_chars(c, n, f & 1 != 0)
        } else {
            charset::decode(c.bytes(n), self.codepage)
        }
    }

    /// The number of an external document among those the workbook names.
    pub fn ext_doc(&mut self, doc: &str) -> usize {
        match self.ext_docs.iter().position(|d| d == doc) {
            Some(i) => i + 1,
            None => {
                self.ext_docs.push(doc.to_string());
                self.ext_docs.len()
            }
        }
    }

    /// A BIFF5 EXTERNSHEET record's entry.
    pub fn ext_sheet5(&mut self, d: &[u8]) -> ExtSheet5 {
        let n = d.first().copied().unwrap_or(0) as usize;
        let body = d.get(1..).unwrap_or(&[]);
        match body.first() {
            Some(0x02..=0x04) | None => ExtSheet5::Own,
            Some(&0x3A) if n == 1 => ExtSheet5::Names(vec![]),
            Some(_) => {
                let s = charset::decode(&body[..n.min(body.len())], self.codepage);
                let s = s.strip_prefix('\u{1}').unwrap_or(&s).to_string();
                let (doc, sheet) = match s.rfind(']') {
                    Some(i) => (s[..i].replace('[', ""), s[i + 1..].to_string()),
                    None => (s.clone(), String::new()),
                };
                let doc: String = doc.chars().filter(|c| (*c as u32) >= 0x20).collect();
                ExtSheet5::External {
                    doc: self.ext_doc(&doc),
                    sheet,
                }
            }
        }
    }

    fn name(&self, r: &Rec) -> Name {
        let ver = self.ver;
        let mut c = Cur::new(&r.data);
        let (flags, cch, cce, sheet, name);
        if ver == 2 {
            flags = u16::from(c.u8()) & 0xFFFE;
            c.skip(2);
            cch = c.u8() as usize;
            cce = c.u8() as usize;
            sheet = 0;
            name = charset::decode(c.bytes(cch), self.codepage);
        } else {
            flags = c.u16();
            c.u8();
            cch = c.u8() as usize;
            cce = c.u16() as usize;
            if ver >= 5 {
                c.u16();
                sheet = c.u16();
                c.skip(4);
            } else {
                sheet = 0;
            }
            name = if ver >= 8 {
                let f = c.u8();
                read_chars(&mut c, cch, f & 1 != 0)
            } else {
                charset::decode(c.bytes(cch), self.codepage)
            };
        }
        let builtin = flags & 0x20 != 0;
        let name = if builtin {
            let b = match name.chars().next().map_or(0xFF, |c| c as u32) {
                0 => "Consolidate_Area",
                1 => "Auto_Open",
                2 => "Auto_Close",
                3 => "Extract",
                4 => "Database",
                5 => "Criteria",
                6 => "Print_Area",
                7 => "Print_Titles",
                8 => "Recorder",
                9 => "Data_Form",
                10 => "Auto_Activate",
                11 => "Auto_Deactivate",
                12 => "Sheet_Title",
                13 => "_FilterDatabase",
                _ => "Unknown",
            };
            format!("_xlnm.{b}")
        } else if name == "_FilterDatabase" {
            "_xlnm._FilterDatabase".into()
        } else {
            name
        };
        let rgce = c.bytes(cce).to_vec();
        let extra = r.data[c.p.min(r.data.len())..].to_vec();
        Name {
            name,
            sheet,
            hidden: flags & 1 != 0,
            rgce,
            extra,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn rec(id: u16, data: Vec<u8>) -> Rec<'static> {
        Rec {
            id,
            pos: 0,
            data: Cow::Owned(data),
            breaks: vec![],
        }
    }

    #[test]
    fn sheets_and_a_builtin_name_are_read() {
        let mut b = Book::new(8);
        // BOUNDSHEET: a macro sheet "Macro1" at 0x100.
        let mut d = 0x100u32.to_le_bytes().to_vec();
        d.extend([0, 1, 6, 0]);
        d.extend(b"Macro1");
        assert!(b.record(&rec(0x0085, d)));
        // NAME: the built-in Auto_Open (code 1) with no formula.
        let d = vec![0x20, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(b.record(&rec(0x0018, d)));
        assert!(!b.record(&rec(0x0203, vec![0; 14])));
        b.finish();
        assert_eq!((b.sheets[0].kind, b.sheets[0].pos), (1, 0x100));
        assert_eq!(b.sheet_names, ["Macro1"]);
        assert_eq!(b.name_texts, ["_xlnm.Auto_Open"]);
    }
}
