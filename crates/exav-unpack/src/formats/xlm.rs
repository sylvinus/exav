//! Excel 4.0 (XLM) macro surfacing from an OLE2 `Workbook`/`Book` BIFF stream.
//!
//! XLM macros predate VBA: the macro lives in cells of a dedicated *macro sheet*
//! rather than a VBA project, so they slip past VBA-only macro detection. A
//! `BOUNDSHEET` record (`0x0085`) with sheet-type `1` marks an Excel 4.0 macro
//! sheet; the macro formulas live in `FORMULA` records whose string constants
//! (URLs, `EXEC`/`CALL` arguments, alert text) are stored as `ptgStr` tokens.
//!
//! We walk the BIFF record stream, detect any macro sheet, and — when present —
//! surface a synthetic `xlm_macro` artifact carrying the macro-sheet names, the
//! recovered string constants, and each macro formula's tokens decoded from the
//! `ptg` stream, including the **built-in function names** (`EXEC`/`CALL`/
//! `ALERT`/…) which are stored as numeric ids and so are *invisible to a raw
//! byte scan*. So the engine's `Target:2`/`Doc.*` signatures match the real
//! function calls and `--alert-macros` fires for XLM the same way it does for
//! VBA. Every read is bounds-checked; a malformed stream yields `None`, never a
//! panic.
//!
//! The formula tokens are emitted in postfix (RPN) order — full infix
//! reconstruction with operator precedence and cell-reference formatting is a
//! follow-up, but every IOC-bearing token (function name, string, number) is
//! recovered, and the raw `Workbook` stream is scanned regardless.

/// BIFF record types we care about.
const R_BOF: u16 = 0x0809;
const R_BOUNDSHEET: u16 = 0x0085;
const R_FORMULA: u16 = 0x0006;
const R_LABEL: u16 = 0x0204;
const R_NAME: u16 = 0x0018;
const R_ARRAY: u16 = 0x0221;

/// Sheet-type (`dt`) byte in a `BOUNDSHEET` record marking an Excel 4.0 macro sheet.
const DT_EXCEL4_MACRO: u8 = 1;

/// Total surfaced-string budget (defensive; the artifact only needs the IOCs).
const MAX_XLM_ARTIFACT: usize = 512 * 1024;

#[inline]
fn u16le(d: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(p)?, *d.get(p + 1)?]))
}

/// Read a `ShortXLUnicodeString` (`cch:u8`, `grbit:u8`, chars) → `String`.
/// `grbit` bit 0 (`fHighByte`) selects 16-bit UTF-16 vs 8-bit compressed chars.
fn read_short_string(d: &[u8]) -> Option<String> {
    let cch = *d.first()? as usize;
    let grbit = *d.get(1)?;
    let chars = d.get(2..)?;
    if grbit & 1 == 0 {
        // 8-bit compressed: each byte is the low half of a UTF-16 unit.
        let n = cch.min(chars.len());
        Some(chars[..n].iter().map(|&b| b as char).collect())
    } else {
        let n = cch.min(chars.len() / 2);
        let units: Vec<u16> = (0..n)
            .map(|i| u16::from_le_bytes([chars[i * 2], chars[i * 2 + 1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }
}

/// True if `s` is worth surfacing: non-trivial length and mostly printable.
fn is_useful(s: &str) -> bool {
    let t = s.trim();
    t.len() >= 3 && t.chars().filter(|c| !c.is_control()).count() * 4 >= t.chars().count() * 3
}

/// Look up a BIFF/XLM built-in function name by its `ptgFunc`/`ptgFuncVar` id.
fn func_name(id: u16) -> Option<&'static str> {
    let t = &super::xlm_functions::XLM_FUNCTIONS;
    t.binary_search_by_key(&id, |&(k, _)| k)
        .ok()
        .map(|i| t[i].1)
        .or_else(|| {
            // Command-equivalent (macro) functions carry the 0x8000 bit; try both.
            t.binary_search_by_key(&(id ^ 0x8000), |&(k, _)| k)
                .ok()
                .map(|i| t[i].1)
        })
}

/// Read a `ptgStr` string (`cch:u8`, `grbit:u8`, chars) at `rgce[i+1..]`,
/// returning `(text, bytes_consumed_after_the_token_byte)`.
fn read_ptgstr(rgce: &[u8], i: usize) -> Option<(String, usize)> {
    let cch = *rgce.get(i)? as usize;
    let high = rgce.get(i + 1)? & 1 == 1;
    let nbytes = if high { cch * 2 } else { cch };
    let chars = rgce.get(i + 2..i + 2 + nbytes)?;
    let s = if high {
        let units: Vec<u16> = chars
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_le_bytes)
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        chars.iter().map(|&b| b as char).collect()
    };
    Some((s, 2 + nbytes))
}

/// Walk a `FORMULA`/`ARRAY` `rgce` token array, emitting the IOC-bearing tokens
/// — built-in **function names** (`EXEC`/`CALL`/`ALERT`/…, invisible to a raw
/// byte scan because they're stored as numeric ids), **string constants**, and
/// numeric literals — as a single reconstructed formula line. Fully
/// bounds-checked; an unknown/complex token (`ptgArray`, `ptgMemArea`, …) ends
/// the walk cleanly (partial line kept). `ptg` class bits (value/ref/array,
/// `0x20`/`0x40`/`0x60`) are normalised to the base type.
fn parse_formula(rgce: &[u8], out: &mut Vec<String>) {
    let mut items: Vec<String> = Vec::new();
    let mut i = 0usize;
    let mut guard = 0usize;
    while i < rgce.len() {
        guard += 1;
        if guard > 100_000 || items.len() > 4096 {
            break;
        }
        let tok = rgce[i];
        let base = if tok >= 0x20 {
            0x20 | (tok & 0x1f)
        } else {
            tok
        };
        i += 1;
        // Operand byte-lengths for the tokens we walk through; `None` = special.
        let fixed: Option<usize> = match base {
            0x01 | 0x02 => Some(4),        // ptgExp / ptgTbl
            0x03..=0x16 => Some(0),        // binary/unary operators, paren, missarg
            0x1c | 0x1d => Some(1),        // ptgErr / ptgBool
            0x1e => Some(2),               // ptgInt
            0x1f => Some(8),               // ptgNum
            0x23 => Some(4),               // ptgName (BIFF8)
            0x24 | 0x2a | 0x2c => Some(4), // ptgRef / ptgRefErr / ptgRefN
            0x25 | 0x2b | 0x2d => Some(8), // ptgArea / ptgAreaErr / ptgAreaN
            0x39 | 0x3a | 0x3c => Some(6), // ptgNameX / ptgRef3d / ptgRefErr3d
            0x3b | 0x3d => Some(10),       // ptgArea3d / ptgAreaErr3d
            _ => None,
        };
        if let Some(n) = fixed {
            if base == 0x1e {
                if let Some(b) = rgce.get(i..i + 2) {
                    items.push(u16::from_le_bytes([b[0], b[1]]).to_string());
                }
            }
            i += n;
            continue;
        }
        match base {
            0x17 => match read_ptgstr(rgce, i) {
                Some((s, consumed)) => {
                    items.push(format!("\"{}\"", s.replace('"', "\"\"")));
                    i += consumed;
                }
                None => break,
            },
            0x19 => {
                // ptgAttr: grbit + 2 bytes; a `bAttrChoose` jump table is complex.
                match rgce.get(i) {
                    Some(&g) if g & 0x04 == 0 => i += 3,
                    _ => break,
                }
            }
            0x21 => {
                // ptgFunc: 2-byte function id.
                match rgce.get(i..i + 2) {
                    Some(b) => {
                        let id = u16::from_le_bytes([b[0], b[1]]);
                        items.push(func_name(id).unwrap_or("FUNC").to_string());
                        i += 2;
                    }
                    None => break,
                }
            }
            0x22 => {
                // ptgFuncVar: 1-byte arg count + 2-byte function id.
                match rgce.get(i + 1..i + 3) {
                    Some(b) => {
                        let id = u16::from_le_bytes([b[0], b[1]]);
                        items.push(func_name(id).unwrap_or("FUNC").to_string());
                        i += 3;
                    }
                    None => break,
                }
            }
            _ => break, // unknown / complex token — stop cleanly
        }
    }
    if !items.is_empty() {
        let line = items.join(" ");
        if is_useful(&line) {
            out.push(line);
        }
    }
}

/// Compute the `rgce` token slice of a `FORMULA` (0x0006) record body: a 20-byte
/// header, then `cce:u16`, then the tokens.
fn formula_rgce(body: &[u8]) -> Option<&[u8]> {
    let cce = u16le(body, 20)? as usize;
    body.get(22..22 + cce)
}

/// Parse the OLE2 streams; if a `Workbook`/`Book` stream contains at least one
/// Excel 4.0 macro sheet, return a surfaced `xlm_macro` artifact (macro-sheet
/// names + recovered string constants). Returns `None` when no XLM macro sheet
/// is present or the stream can't be parsed.
pub(crate) fn xlm_macro_artifact(streams: &[(String, &[u8])]) -> Option<Vec<u8>> {
    // OLE stream names carry a path prefix (e.g. `/Workbook`); match the basename.
    let (_, data) = streams.iter().find(|(n, _)| {
        let base = n.rsplit(['/', '\\']).next().unwrap_or(n);
        base.eq_ignore_ascii_case("Workbook") || base.eq_ignore_ascii_case("Book")
    })?;
    if u16le(data, 0)? != R_BOF {
        return None;
    }

    let mut macro_sheets: Vec<String> = Vec::new();
    let mut strings: Vec<String> = Vec::new();
    let mut total = 0usize;
    let mut pos = 0usize;
    // Bound the number of records walked (defensive against a crafted stream).
    let mut guard = 0usize;

    while pos + 4 <= data.len() {
        guard += 1;
        if guard > 1_000_000 || total > MAX_XLM_ARTIFACT {
            break;
        }
        let typ = u16le(data, pos)?;
        let len = u16le(data, pos + 2)? as usize;
        pos += 4;
        let end = (pos + len).min(data.len());
        let body = &data[pos..end];
        pos = end;

        match typ {
            R_BOUNDSHEET => {
                // [lbPlyPos:u32][hsState:u8][dt:u8][name: ShortXLUnicodeString]
                if body.get(5).copied() == Some(DT_EXCEL4_MACRO) {
                    let name = body
                        .get(6..)
                        .and_then(read_short_string)
                        .unwrap_or_default();
                    total += name.len();
                    macro_sheets.push(name);
                }
            }
            R_LABEL => {
                // [rw:u16][col:u16][ixfe:u16][XLUnicodeString: cch:u16 ...]
                if let Some(s) = body.get(6..).and_then(|b| {
                    let cch = u16le(b, 0)? as usize;
                    read_short_string_wide(b.get(2..)?, cch)
                }) {
                    if is_useful(&s) {
                        total += s.len();
                        strings.push(s);
                    }
                }
            }
            R_NAME => {
                // Defined names (e.g. built-in `Auto_Open`). Name text is a
                // ShortXLUnicodeString at a fixed offset in the record.
                if let Some(s) = body.get(15..).and_then(read_short_string) {
                    if is_useful(&s) {
                        total += s.len();
                        strings.push(s);
                    }
                }
            }
            R_FORMULA => {
                if let Some(rgce) = formula_rgce(body) {
                    parse_formula(rgce, &mut strings);
                }
            }
            R_ARRAY => {
                // ARRAY body: 12-byte header, then cce:u16, then rgce.
                if let Some(cce) = u16le(body, 12) {
                    if let Some(rgce) = body.get(14..14 + cce as usize) {
                        parse_formula(rgce, &mut strings);
                    }
                }
            }
            _ => {}
        }
    }

    if macro_sheets.is_empty() {
        return None;
    }

    let mut out = String::from("Excel 4.0 macro (XLM)\n");
    for m in &macro_sheets {
        out.push_str("macro-sheet: ");
        out.push_str(m);
        out.push('\n');
    }
    // Dedup adjacent duplicates (SST/shared strings can repeat) cheaply.
    strings.dedup();
    for s in &strings {
        if out.len() + s.len() + 1 > MAX_XLM_ARTIFACT {
            break;
        }
        out.push_str(s);
        out.push('\n');
    }
    Some(out.into_bytes())
}

/// Read a wide (`cch:u16`-counted) `XLUnicodeString` body: `grbit:u8`, chars.
fn read_short_string_wide(d: &[u8], cch: usize) -> Option<String> {
    let grbit = *d.first()?;
    let chars = d.get(1..)?;
    if grbit & 1 == 0 {
        let n = cch.min(chars.len());
        Some(chars[..n].iter().map(|&b| b as char).collect())
    } else {
        let n = cch.min(chars.len() / 2);
        let units: Vec<u16> = (0..n)
            .map(|i| u16::from_le_bytes([chars[i * 2], chars[i * 2 + 1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }
}

#[cfg(test)]
mod tests {
    use crate::{extract, Budget, Format, Limits};

    /// End-to-end against a real Excel 4.0 macro `.xls` (from the `oletools` test
    /// corpus, cross-checked with `olevba`): the OLE path must surface an
    /// `xlm_macro` member that flags the macro sheet and recovers the macro's
    /// string constant (`olevba`: `ALERT("This is a sample Excel 4 macro")`).
    #[test]
    fn real_excel4_macro_is_surfaced() {
        let data = include_bytes!("../../tests/fixtures/xlm_excel4_sample.xls");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Ole, data, &mut budget).unwrap();
        let xlm = entries
            .iter()
            .find(|e| e.name == "xlm_macro")
            .expect("an xlm_macro artifact must be surfaced");
        let text = String::from_utf8_lossy(&xlm.data);
        assert!(text.contains("Excel 4.0 macro (XLM)"), "text: {text}");
        // The plain string constant carrying the payload.
        assert!(
            text.contains("This is a sample Excel 4 macro"),
            "recovered XLM text was: {text}"
        );
        // The Ptg-decoded function names (invisible to a raw byte scan — stored
        // as numeric ids). olevba: ALERT("This is a sample Excel 4 macro"), HALT().
        assert!(text.contains("ALERT"), "expected ALERT in: {text}");
        assert!(text.contains("HALT"), "expected HALT in: {text}");
    }

    /// A benign OLE document with no macro sheet must NOT surface an xlm_macro.
    #[test]
    fn no_macro_sheet_no_artifact() {
        // Minimal OLE with a Workbook stream that has a BOF but no BOUNDSHEET
        // macro-sheet: build via the parser directly on a tiny BIFF stream.
        let biff = [0x09u8, 0x08, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]; // BOF only
        let streams: Vec<(String, &[u8])> = vec![("Workbook".to_string(), &biff[..])];
        assert!(super::xlm_macro_artifact(&streams).is_none());
    }
}
