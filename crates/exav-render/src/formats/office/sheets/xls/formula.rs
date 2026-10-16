//! BIFF formula tokens ([MS-XLS] 2.5.198 Rgce; BIFF2 to BIFF5 as
//! OpenOffice.org's Excel format documentation, chapter 3, describes them)
//! to Excel A1 formula text.

use super::ftab::FTAB;
use crate::formats::office::common::bytes::Cur;
use crate::formats::office::sheets::model::{col_name, CellError};
use crate::formats::office::sheets::numtext;

/// Formula text past this many characters is refused: Excel's own limit is
/// 8192, and joining operands would otherwise be quadratic.
const MAX_TEXT: usize = 16_384;

/// A BIFF8 SUPBOOK record.
#[derive(Default, Clone, Debug)]
pub(crate) struct Supbook {
    pub internal: bool,
    pub addin: bool,
    /// An external workbook's number among them, from 1.
    pub ext_index: usize,
    pub sheets: Vec<String>,
    pub names: Vec<String>,
}

/// A BIFF5 EXTERNSHEET entry.
#[derive(Clone, Debug)]
pub(crate) enum ExtSheet5 {
    /// A sheet of this workbook (by name), or the workbook itself.
    Own,
    /// An external document's sheet: its number among external documents.
    External { doc: usize, sheet: String },
    /// Add-in functions: the names that follow.
    Names(Vec<String>),
}

/// What a formula needs from the workbook to name what it refers to.
pub(crate) struct Ctx<'a> {
    pub ver: u8,
    pub sheets: &'a [String],
    /// Defined names, 1-based in tokens.
    pub names: &'a [String],
    /// BIFF8 EXTERNSHEET entries: (supbook, first sheet, last sheet).
    pub xti: &'a [(u16, i16, i16)],
    pub supbooks: &'a [Supbook],
    /// BIFF5: the EXTERNSHEET entries in scope (a sheet's, or the globals').
    pub ext5: &'a [ExtSheet5],
    pub codepage: u16,
}

pub(crate) fn error_name(code: u8) -> &'static str {
    CellError::from_biff(code).unwrap_or(CellError::NA).name()
}

/// Functions Excel 2007 added, stored in XLS as `_xlfn.` add-in calls: in
/// XLSX they are native, written without the prefix.
const XL2007: &[&str] = &[
    "AVERAGEIF",
    "AVERAGEIFS",
    "COUNTIFS",
    "IFERROR",
    "SUMIFS",
    "CUBEKPIMEMBER",
    "CUBEMEMBER",
    "CUBEMEMBERPROPERTY",
    "CUBERANKEDMEMBER",
    "CUBESET",
    "CUBESETCOUNT",
    "CUBEVALUE",
];

/// A sheet name as a formula writes it, quoted when it must be.
pub(crate) fn quote_sheet(name: &str) -> String {
    let plain = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        && !name.starts_with(|c: char| c.is_ascii_digit() || c == '.')
        && !looks_like_ref(name);
    if plain {
        name.to_string()
    } else {
        format!("'{}'", name.replace('\'', "''"))
    }
}

/// A sheet of external workbook `n`: `[1]Sheet1`, quoted when the sheet's
/// name must be.
pub(crate) fn quote_external(n: usize, sheet: &str) -> String {
    if quote_sheet(sheet) == sheet {
        format!("[{n}]{sheet}")
    } else {
        format!("'[{n}]{}'", sheet.replace('\'', "''"))
    }
}

fn looks_like_ref(s: &str) -> bool {
    let up = s.to_ascii_uppercase();
    let letters = up.chars().take_while(char::is_ascii_alphabetic).count();
    let rest = &up[letters..];
    ((1..=3).contains(&letters) && !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
        || up == "TRUE"
        || up == "FALSE"
        || (up.starts_with('R')
            && up[1..].contains('C')
            && up[1..].chars().all(|c| c.is_ascii_digit() || c == 'C'))
}

pub(crate) struct Decoded {
    pub text: String,
    /// The formula is a reference to a shared or array formula: its cell.
    pub exp: Option<(u32, u32)>,
    /// A data table's cell.
    pub table: bool,
}

/// Fixed argument counts of functions whose count changed after BIFF2
/// (FIXED after BIFF3): a PtgFunc in an older file carries them.
fn old_fixed(i: u16, ver: u8) -> Option<usize> {
    match (i, ver) {
        (14, 2..=3) => Some(2),
        (70, 2) | (197, 2) => Some(1),
        (101, 2) | (102, 2) => Some(3),
        (220, 2) => Some(2),
        _ => None,
    }
}

fn ftab(i: u16) -> Option<(&'static str, i8)> {
    FTAB.binary_search_by_key(&i, |e| e.0)
        .ok()
        .map(|k| (FTAB[k].1, FTAB[k].2))
}

fn push(st: &mut Vec<String>, s: String) -> Result<(), String> {
    if s.len() > MAX_TEXT {
        return Err("formula too long".into());
    }
    st.push(s);
    Ok(())
}

fn pop(st: &mut Vec<String>) -> Result<String, String> {
    st.pop().ok_or_else(|| "stack underflow".to_string())
}

/// Decodes `rgce` (and `extra`, the data its array constants keep after
/// it). `row` and `col` are the formula's cell, which relative references
/// in shared formulas, conditional formats and validations are offsets
/// from.
pub(crate) fn decode(
    ctx: &Ctx,
    rgce: &[u8],
    extra: &[u8],
    row: u32,
    col: u32,
) -> Result<Decoded, String> {
    decode_with(ctx, rgce, extra, row, col, false)
}

/// A conditional format's or a validation's formula: its references are
/// offsets from (`row`, `col`), the top left of its ranges (the "method B"
/// of OpenOffice.org's documentation, 3.9), whether written as RefN and
/// AreaN tokens or as Ref, Area, Ref3d and Area3d ones with the relative
/// flags set.
pub(crate) fn decode_relative(
    ctx: &Ctx,
    rgce: &[u8],
    row: u32,
    col: u32,
) -> Result<Decoded, String> {
    decode_with(ctx, rgce, &[], row, col, true)
}

fn decode_with(
    ctx: &Ctx,
    rgce: &[u8],
    extra: &[u8],
    row: u32,
    col: u32,
    relative: bool,
) -> Result<Decoded, String> {
    let ver = ctx.ver;
    let mut c = Cur::new(rgce);
    let mut ex = Cur::new(extra);
    let mut st: Vec<String> = Vec::new();
    let w2 = if ver >= 3 { 2 } else { 1 };
    while c.left() > 0 {
        let ptg = c.u8();
        let base = if ptg >= 0x20 {
            (ptg & 0x1F) | 0x20
        } else {
            ptg
        };
        match base {
            0x01 => {
                let r = c.u16() as u32;
                let cc = if ver >= 3 {
                    c.u16() as u32
                } else {
                    c.u8() as u32
                };
                return Ok(Decoded {
                    text: String::new(),
                    exp: Some((r, cc)),
                    table: false,
                });
            }
            0x02 => {
                return Ok(Decoded {
                    text: String::new(),
                    exp: None,
                    table: true,
                })
            }
            0x03..=0x11 => {
                let b = pop(&mut st)?;
                let a = pop(&mut st)?;
                let op = match base {
                    0x03 => "+",
                    0x04 => "-",
                    0x05 => "*",
                    0x06 => "/",
                    0x07 => "^",
                    0x08 => "&",
                    0x09 => "<",
                    0x0A => "<=",
                    0x0B => "=",
                    0x0C => ">=",
                    0x0D => ">",
                    0x0E => "<>",
                    0x0F => " ",
                    0x10 => ",",
                    _ => ":",
                };
                push(&mut st, format!("{a}{op}{b}"))?;
            }
            0x12 => {
                let a = pop(&mut st)?;
                push(&mut st, format!("+{a}"))?;
            }
            0x13 => {
                let a = pop(&mut st)?;
                push(&mut st, format!("-{a}"))?;
            }
            0x14 => {
                let a = pop(&mut st)?;
                push(&mut st, format!("{a}%"))?;
            }
            0x15 => {
                let a = pop(&mut st)?;
                push(&mut st, format!("({a})"))?;
            }
            0x16 => st.push(String::new()),
            0x17 => {
                let s = if ver >= 8 {
                    read_short_unicode(&mut c)
                } else {
                    read_byte_string(&mut c, ctx.codepage)
                };
                push(&mut st, format!("\"{}\"", s.replace('"', "\"\"")))?;
            }
            0x18 => return Err("extended token".into()),
            0x19 => {
                let grbit = c.u8();
                if grbit & 0x04 != 0 {
                    // attrChoose: a jump table of its argument count plus one.
                    let n = if ver >= 3 {
                        c.u16() as usize
                    } else {
                        c.u8() as usize
                    };
                    c.skip((n + 1) * w2);
                } else if grbit & 0x10 != 0 {
                    c.skip(w2);
                    let a = pop(&mut st)?;
                    push(&mut st, format!("SUM({a})"))?;
                } else {
                    c.skip(w2);
                }
            }
            0x1C => {
                let e = error_name(c.u8());
                st.push(e.to_string());
            }
            0x1D => st.push(if c.u8() != 0 {
                "TRUE".into()
            } else {
                "FALSE".into()
            }),
            0x1E => st.push(c.u16().to_string()),
            0x1F => st.push(numtext::shortest(c.f64())),
            0x20 => {
                c.skip(if ver >= 5 { 7 } else { 6 });
                push(&mut st, read_array(&mut ex, ver, ctx.codepage))?;
            }
            0x21 => {
                let i = if ver >= 4 { c.u16() } else { u16::from(c.u8()) };
                let (name, n) = ftab(i).ok_or_else(|| format!("unknown function {i}"))?;
                let n = match (n, old_fixed(i, ver)) {
                    (_, Some(k)) => k,
                    (n, None) if n >= 0 => n as usize,
                    _ => return Err(format!("variable function {name} in PtgFunc")),
                };
                if st.len() < n {
                    return Err("stack underflow".into());
                }
                let args = st.split_off(st.len() - n);
                push(&mut st, format!("{name}({})", args.join(",")))?;
            }
            0x22 => {
                let argc = (c.u8() & 0x7F) as usize;
                let i = if ver >= 4 { c.u16() } else { u16::from(c.u8()) };
                let ce = i & 0x8000 != 0;
                let i = i & 0x7FFF;
                if st.len() < argc {
                    return Err("stack underflow".into());
                }
                let mut args = st.split_off(st.len() - argc);
                let name = if ce {
                    format!("CMD{i}")
                } else if i == 255 {
                    // An add-in or newer function: its name is the first operand.
                    if args.is_empty() {
                        return Err("add-in call without a name".into());
                    }
                    let n = args.remove(0);
                    let bare = n.strip_prefix("_xlfn.").unwrap_or(&n).to_string();
                    if XL2007.contains(&bare.to_ascii_uppercase().as_str()) {
                        bare
                    } else {
                        n
                    }
                } else {
                    ftab(i)
                        .map(|f| f.0.to_string())
                        .ok_or_else(|| format!("unknown function {i}"))?
                };
                push(&mut st, format!("{name}({})", args.join(",")))?;
            }
            0x23 => {
                let idx = if ver >= 8 {
                    c.u32() as usize
                } else if ver == 5 {
                    let i = c.u16();
                    c.skip(12);
                    i as usize
                } else {
                    let i = c.u16();
                    c.skip(if ver == 4 { 10 } else { 5 });
                    i as usize
                };
                st.push(
                    ctx.names
                        .get(idx.wrapping_sub(1))
                        .cloned()
                        .unwrap_or_else(|| "#NAME?".into()),
                );
            }
            0x24 | 0x2C => {
                let l = loc(&mut c, ver, row, col, relative || base == 0x2C);
                st.push(a1(l));
            }
            0x25 | 0x2D => {
                let a = area(&mut c, ver, row, col, relative || base == 0x2D);
                push(&mut st, a)?;
            }
            0x26..=0x28 => c.skip(if ver >= 5 { 6 } else { 5 }),
            0x29 => c.skip(w2),
            0x2A => {
                c.skip(if ver >= 8 { 4 } else { 3 });
                st.push("#REF!".into());
            }
            0x2B => {
                c.skip(if ver >= 8 { 8 } else { 6 });
                st.push("#REF!".into());
            }
            0x39 => {
                let text = if ver >= 8 {
                    let ixti = c.u16() as usize;
                    let ni = c.u32() as usize;
                    name_x(ctx, ixti, ni)
                } else {
                    let ixals = c.i16();
                    c.skip(8);
                    let ni = c.u16() as usize;
                    c.skip(12);
                    if ixals < 0 {
                        ctx.names
                            .get(ni.wrapping_sub(1))
                            .cloned()
                            .unwrap_or_else(|| "#NAME?".into())
                    } else {
                        match ctx.ext5.get((ixals as usize).wrapping_sub(1)) {
                            Some(ExtSheet5::Names(n)) => n
                                .get(ni.wrapping_sub(1))
                                .cloned()
                                .unwrap_or_else(|| "#NAME?".into()),
                            _ => "#NAME?".into(),
                        }
                    }
                };
                st.push(text);
            }
            0x3A..=0x3D => {
                let prefix = sheet_prefix(ctx, &mut c);
                let text = match base {
                    0x3A => format!("{prefix}{}", a1(loc(&mut c, ver, row, col, relative))),
                    0x3B => format!("{prefix}{}", area(&mut c, ver, row, col, relative)),
                    0x3C => {
                        c.skip(if ver >= 8 { 4 } else { 3 });
                        "#REF!".into()
                    }
                    _ => {
                        c.skip(if ver >= 8 { 8 } else { 6 });
                        "#REF!".into()
                    }
                };
                push(&mut st, text)?;
            }
            _ => return Err(format!("unknown token {ptg:#x}")),
        }
        if c.short {
            return Err("truncated formula".into());
        }
    }
    let t = st.pop().ok_or("empty formula")?;
    if !st.is_empty() {
        return Err("operands left over".into());
    }
    Ok(Decoded {
        text: t,
        exp: None,
        table: false,
    })
}

fn name_x(ctx: &Ctx, ixti: usize, ni: usize) -> String {
    let Some(&(sb, _, _)) = ctx.xti.get(ixti) else {
        return "#NAME?".into();
    };
    let Some(book) = ctx.supbooks.get(sb as usize) else {
        return "#NAME?".into();
    };
    if book.internal {
        return ctx
            .names
            .get(ni.wrapping_sub(1))
            .cloned()
            .unwrap_or_else(|| "#NAME?".into());
    }
    let n = book
        .names
        .get(ni.wrapping_sub(1))
        .cloned()
        .unwrap_or_else(|| "#NAME?".into());
    if book.addin {
        n
    } else {
        format!("[{}]!{n}", book.ext_index)
    }
}

fn sheet_prefix(ctx: &Ctx, c: &mut Cur) -> String {
    let range = |names: &[String], first: i64, last: i64, ext: Option<usize>| -> String {
        let get =
            |i: i64| -> Option<&String> { usize::try_from(i).ok().and_then(|i| names.get(i)) };
        let prefix = ext.map(|n| format!("[{n}]")).unwrap_or_default();
        match (get(first), get(last)) {
            (Some(a), Some(_)) if first == last => match ext {
                Some(n) => format!("{}!", quote_external(n, a)),
                None => format!("{}!", quote_sheet(a)),
            },
            (Some(a), Some(b)) if quote_sheet(a) == *a && quote_sheet(b) == *b => {
                format!("{prefix}{a}:{b}!")
            }
            (Some(a), Some(b)) => format!(
                "'{prefix}{}:{}'!",
                a.replace('\'', "''"),
                b.replace('\'', "''")
            ),
            _ => "#REF!".into(),
        }
    };
    if ctx.ver >= 8 {
        let ixti = c.u16() as usize;
        let Some(&(sb, first, last)) = ctx.xti.get(ixti) else {
            return "#REF!".into();
        };
        match ctx.supbooks.get(sb as usize) {
            Some(b) if !b.internal => {
                range(&b.sheets, first.into(), last.into(), Some(b.ext_index))
            }
            _ => range(ctx.sheets, first.into(), last.into(), None),
        }
    } else {
        let ixals = c.i16();
        c.skip(8);
        let first = c.i16();
        let last = c.i16();
        if ixals < 0 {
            range(ctx.sheets, first.into(), last.into(), None)
        } else {
            match ctx.ext5.get((ixals as usize).wrapping_sub(1)) {
                Some(ExtSheet5::External { doc, sheet }) => {
                    format!("{}!", quote_external(*doc, sheet))
                }
                _ => "#REF!".into(),
            }
        }
    }
}

/// A cell location with its relative flags.
#[derive(Clone, Copy)]
struct Loc {
    r: u32,
    c: u32,
    rrel: bool,
    crel: bool,
}

fn maxrow(ver: u8) -> i64 {
    if ver >= 8 {
        0x10000
    } else {
        0x4000
    }
}

impl Loc {
    /// BIFF8: a row, and a column word with the relative flags.
    fn biff8(r: u32, cw: u16) -> Loc {
        Loc {
            r,
            c: (cw & 0x3FFF) as u32,
            rrel: cw & 0x8000 != 0,
            crel: cw & 0x4000 != 0,
        }
    }

    /// BIFF2 to BIFF7: a row word with the relative flags, and a column.
    fn biff5(rw: u16, c: u32) -> Loc {
        Loc {
            r: (rw & 0x3FFF) as u32,
            c,
            rrel: rw & 0x8000 != 0,
            crel: rw & 0x4000 != 0,
        }
    }
}

/// `offsets`: relative parts are offsets from (row, col), as in RefN.
fn resolve(l: Loc, row: u32, col: u32, offsets: bool, ver: u8) -> Loc {
    let mut out = l;
    if offsets {
        if l.rrel {
            let off = if ver >= 8 {
                i64::from(l.r as u16 as i16)
            } else {
                (i64::from(l.r) << 50) >> 50
            };
            out.r = (i64::from(row) + off).rem_euclid(maxrow(ver)) as u32;
        }
        if l.crel {
            let off = i64::from(l.c as u8 as i8);
            out.c = (i64::from(col) + off).rem_euclid(256) as u32;
        }
    }
    out
}

fn loc(c: &mut Cur, ver: u8, row: u32, col: u32, offsets: bool) -> Loc {
    let l = if ver >= 8 {
        let r = c.u16() as u32;
        Loc::biff8(r, c.u16())
    } else {
        let rw = c.u16();
        Loc::biff5(rw, c.u8() as u32)
    };
    resolve(l, row, col, offsets, ver)
}

fn a1(l: Loc) -> String {
    format!(
        "{}{}{}{}",
        if l.crel { "" } else { "$" },
        col_name(l.c),
        if l.rrel { "" } else { "$" },
        u64::from(l.r) + 1
    )
}

fn area(c: &mut Cur, ver: u8, row: u32, col: u32, offsets: bool) -> String {
    let (a, b) = if ver >= 8 {
        let r1 = c.u16() as u32;
        let r2 = c.u16() as u32;
        let c1 = c.u16();
        let c2 = c.u16();
        (
            resolve(Loc::biff8(r1, c1), row, col, offsets, ver),
            resolve(Loc::biff8(r2, c2), row, col, offsets, ver),
        )
    } else {
        let r1 = c.u16();
        let r2 = c.u16();
        let c1 = c.u8() as u32;
        let c2 = c.u8() as u32;
        (
            resolve(Loc::biff5(r1, c1), row, col, offsets, ver),
            resolve(Loc::biff5(r2, c2), row, col, offsets, ver),
        )
    };
    let lastrow = if ver >= 8 { 0xFFFF } else { 0x3FFF };
    // Whole columns and rows, as Excel writes them.
    if a.r == 0 && b.r == lastrow && !a.rrel && !b.rrel {
        return format!(
            "{}{}:{}{}",
            if a.crel { "" } else { "$" },
            col_name(a.c),
            if b.crel { "" } else { "$" },
            col_name(b.c)
        );
    }
    if a.c == 0 && b.c == 0xFF && !a.crel && !b.crel {
        return format!(
            "{}{}:{}{}",
            if a.rrel { "" } else { "$" },
            u64::from(a.r) + 1,
            if b.rrel { "" } else { "$" },
            u64::from(b.r) + 1
        );
    }
    format!("{}:{}", a1(a), a1(b))
}

fn read_short_unicode(c: &mut Cur) -> String {
    let n = c.u8() as usize;
    let flags = c.u8();
    read_chars(c, n, flags & 1 != 0)
}

/// `n` characters, two bytes each or one byte each (Latin-1).
pub(crate) fn read_chars(c: &mut Cur, n: usize, wide: bool) -> String {
    if wide {
        let b = c.bytes(n.saturating_mul(2));
        let u: Vec<u16> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|x| u16::from_le_bytes(*x))
            .collect();
        String::from_utf16_lossy(&u)
    } else {
        c.bytes(n).iter().map(|&b| b as char).collect()
    }
}

fn read_byte_string(c: &mut Cur, cp: u16) -> String {
    let n = c.u8() as usize;
    crate::formats::office::common::codepage::decode(c.bytes(n), cp)
}

/// Columns less one, then rows less one, in every version; strings differ.
fn read_array(ex: &mut Cur, ver: u8, cp: u16) -> String {
    let (cols, rows) = (ex.u8() as usize + 1, ex.u16() as usize + 1);
    let mut out = String::from("{");
    'rows: for r in 0..rows {
        if r > 0 {
            out.push(';');
        }
        for k in 0..cols {
            if k > 0 {
                out.push(',');
            }
            match ex.u8() {
                0x01 => out.push_str(&numtext::shortest(ex.f64())),
                0x02 => {
                    let s = if ver >= 8 {
                        let n = ex.u16() as usize;
                        let f = ex.u8();
                        read_chars(ex, n, f & 1 != 0)
                    } else {
                        let n = ex.u8() as usize;
                        crate::formats::office::common::codepage::decode(ex.bytes(n), cp)
                    };
                    out.push('"');
                    out.push_str(&s.replace('"', "\"\""));
                    out.push('"');
                }
                0x04 => {
                    let b = ex.u8();
                    ex.skip(7);
                    out.push_str(if b != 0 { "TRUE" } else { "FALSE" });
                }
                0x10 => {
                    let e = ex.u8();
                    ex.skip(7);
                    out.push_str(error_name(e));
                }
                _ => ex.skip(8),
            }
            if ex.short || out.len() > MAX_TEXT {
                break 'rows;
            }
        }
    }
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Ctx<'static> {
        Ctx {
            ver: 8,
            sheets: &[],
            names: &[],
            xti: &[],
            supbooks: &[],
            ext5: &[],
            codepage: 1252,
        }
    }

    #[test]
    fn decodes_operators_functions_and_constants() {
        // =SUM(A1:B2)*2 with an attrSum, then <> TRUE, as Excel stores it.
        let mut r = vec![0x25, 0, 0, 1, 0, 0, 0xC0, 1, 0xC0];
        r.extend_from_slice(&[0x19, 0x10, 0, 0]);
        r.extend_from_slice(&[0x1E, 2, 0, 0x05]);
        r.extend_from_slice(&[0x1D, 1, 0x0E]);
        let d = decode(&ctx(), &r, &[], 0, 0).unwrap();
        assert_eq!(d.text, "SUM(A1:B2)*2<>TRUE");
        // #N/A stays an error constant.
        assert_eq!(
            decode(&ctx(), &[0x1C, 0x2A], &[], 0, 0).unwrap().text,
            "#N/A"
        );
        // ROUND(1.5,0): a fixed-argument function.
        let mut r = vec![0x1F];
        r.extend_from_slice(&1.5f64.to_le_bytes());
        r.extend_from_slice(&[0x1E, 0, 0, 0x21, 27, 0]);
        assert_eq!(decode(&ctx(), &r, &[], 0, 0).unwrap().text, "ROUND(1.5,0)");
    }

    #[test]
    fn relative_offsets_wrap() {
        // RefN one row up and one column left of B2.
        let r = [0x2C, 0xFF, 0xFF, 0xFF, 0xC0];
        assert_eq!(decode(&ctx(), &r, &[], 1, 1).unwrap().text, "A1");
    }

    #[test]
    fn conditional_formats_count_from_their_range() {
        // An Area, relative, rows -1 to +1 and column +3 from B2: E1:E3.
        // Read as a cell formula, the same token names rows 65536 and 2.
        let r = [0x25, 0xFF, 0xFF, 1, 0, 3, 0xC0, 3, 0xC0];
        assert_eq!(decode_relative(&ctx(), &r, 1, 1).unwrap().text, "E1:E3");
        assert_eq!(decode(&ctx(), &r, &[], 1, 1).unwrap().text, "D65536:D2");
        // Absolute parts stay where they are.
        let r = [0x24, 4, 0, 2, 0x00];
        assert_eq!(decode_relative(&ctx(), &r, 1, 1).unwrap().text, "$C$5");
    }

    #[test]
    fn hostile_formulas_are_refused_not_panicking() {
        assert!(decode(&ctx(), &[0x03], &[], 0, 0).is_err());
        assert!(decode(&ctx(), &[0x22, 0x7F, 0xFF, 0x00], &[], 0, 0).is_err());
        // A long chain of concatenations stops at the text limit.
        let mut r = vec![0x17, 200, 0];
        r.extend(std::iter::repeat_n(b'x', 200));
        for _ in 0..200 {
            r.extend_from_slice(&[0x17, 200, 0]);
            r.extend(std::iter::repeat_n(b'x', 200));
            r.push(0x08);
        }
        assert_eq!(
            decode(&ctx(), &r, &[], 0, 0).err().as_deref(),
            Some("formula too long")
        );
        assert!(decode(
            &ctx(),
            &[0x20, 0, 0, 0, 0, 0, 0, 0],
            &[0xFF, 0xFF, 0xFF],
            0,
            0
        )
        .is_ok());
    }

    #[test]
    fn biff2_fixed_counts() {
        let c = Ctx { ver: 2, ..ctx() };
        // FIXED(1,2) with a BIFF2 PtgFunc.
        let r = [0x1E, 1, 0, 0x1E, 2, 0, 0x21, 14];
        assert_eq!(decode(&c, &r, &[], 0, 0).unwrap().text, "FIXED(1,2)");
    }
}
