//! Excel 4.0 (XLM) macro surfacing from an OLE2 `Workbook`/`Book` BIFF stream.
//!
//! XLM macros predate VBA: the macro lives in cells of a dedicated *macro
//! sheet* rather than a VBA project, so they slip past VBA-only macro
//! detection. A `BOUNDSHEET` record with sheet type `1` marks an Excel 4.0
//! macro sheet; the macro formulas live in `FORMULA` and `ARRAY` records as
//! `ptg` tokens, where the built-in functions (`EXEC`, `CALL`, `ALERT`, ...)
//! are numbers, invisible to a scan of the file's bytes.
//!
//! We read the stream with the BIFF reader exav-render converts workbooks
//! with, and when a macro sheet is present surface a synthetic `xlm_macro`
//! artifact: the macro-sheet names, the defined names with what they refer to,
//! the text cells, and each formula as Excel shows it (`=EXEC("calc.exe")`),
//! so the engine's `Target:2` and `Doc.*` signatures match the function calls
//! and `--alert-macros` fires for XLM as it does for VBA. A formula the reader
//! refuses still gives the calls and constants it read before the token it
//! could not. Every read is bounds-checked; a malformed stream yields `None`,
//! never a panic.

use super::biff::{self, Book, formula};
use crate::bytes::{Cur, u16_at};

const R_FORMULA: u16 = 0x0006;
const R_LABEL: u16 = 0x0204;
const R_ARRAY: u16 = 0x0221;
const R_EOF: u16 = 0x000A;

/// Sheet-type (`dt`) byte in a `BOUNDSHEET` record marking an Excel 4.0 macro sheet.
const DT_EXCEL4_MACRO: u8 = 1;

/// Total surfaced-string budget (defensive; the artifact only needs the IOCs).
const MAX_XLM_ARTIFACT: usize = 512 * 1024;

/// True if `s` is worth surfacing: non-trivial length and mostly printable.
fn is_useful(s: &str) -> bool {
    let t = s.trim();
    t.len() >= 3 && t.chars().filter(|c| !c.is_control()).count() * 4 >= t.chars().count() * 3
}

/// Parse the OLE2 streams; if a `Workbook`/`Book` stream contains at least one
/// Excel 4.0 macro sheet, return a surfaced `xlm_macro` artifact. Returns
/// `None` when no XLM macro sheet is present or the stream can't be parsed.
pub(crate) fn xlm_macro_artifact(streams: &[(String, &[u8])]) -> Option<Vec<u8>> {
    // OLE stream names carry a path prefix (e.g. `/Workbook`); match the basename.
    let (_, data) = streams.iter().find(|(n, _)| {
        let base = n.rsplit(['/', '\\']).next().unwrap_or(n);
        base.eq_ignore_ascii_case("Workbook") || base.eq_ignore_ascii_case("Book")
    })?;
    let mut recs = biff::records(data);
    let first = recs.next()?;
    // BIFF8 and BIFF5; the older kinds are not in compound files.
    if first.id != 0x0809 {
        return None;
    }
    let mut book = Book::new(biff::bof_version(&first));
    for r in recs.by_ref().take_while(|r| r.id != R_EOF) {
        book.record(&r);
    }
    book.finish();
    if !book.sheets.iter().any(|s| s.kind == DT_EXCEL4_MACRO) {
        return None;
    }

    let mut lines: Vec<String> = Vec::new();
    let mut total = 0usize;
    let ctx = book.ctx(&book.ext5);
    for n in &book.names {
        let text = match formula::decode_partial(&ctx, &n.rgce, &n.extra, 0, 0) {
            p if p.text.is_empty() => n.name.clone(),
            p => format!("{}={}", n.name, p.text),
        };
        if is_useful(&text) {
            total += text.len();
            lines.push(text);
        }
    }
    for r in biff::records(data) {
        if total > MAX_XLM_ARTIFACT {
            break;
        }
        let body: &[u8] = &r.data;
        let text = match r.id {
            R_FORMULA => {
                // 20 bytes of cell, value and flags, then cce:u16 and the tokens.
                let cce = u16_at(body, 20) as usize;
                crate::bytes::at(body, 22, cce)
                    .map(|rgce| macro_formula(&ctx, rgce, u16_at(body, 0), u16_at(body, 2)))
            }
            R_ARRAY => {
                // 12 bytes of range and flags, then cce:u16 and the tokens.
                let cce = u16_at(body, 12) as usize;
                crate::bytes::at(body, 14, cce)
                    .map(|rgce| macro_formula(&ctx, rgce, u16_at(body, 0), u16::from(body[4])))
            }
            R_LABEL => {
                // [rw:u16][col:u16][ixfe:u16][string: cch:u16 ...]
                let mut c = Cur::at(body, 6);
                let s = book.string(&mut c, 2);
                (!c.short && is_useful(&s)).then_some(s)
            }
            _ => None,
        };
        if let Some(t) = text.filter(|t| !t.is_empty()) {
            total += t.len();
            lines.push(t);
        }
    }

    let mut out = String::from("Excel 4.0 macro (XLM)\n");
    for s in book.sheets.iter().filter(|s| s.kind == DT_EXCEL4_MACRO) {
        out.push_str("macro-sheet: ");
        out.push_str(&s.name);
        out.push('\n');
    }
    // Adjacent duplicates (a fill-down repeats a formula) say nothing new.
    lines.dedup();
    for s in &lines {
        if out.len() + s.len() + 1 > MAX_XLM_ARTIFACT {
            break;
        }
        out.push_str(s);
        out.push('\n');
    }
    Some(out.into_bytes())
}

/// A macro formula as a line: `=` and the formula, as the cell shows it.
fn macro_formula(ctx: &formula::Ctx, rgce: &[u8], row: u16, col: u16) -> String {
    let p = formula::decode_partial(ctx, rgce, &[], u32::from(row), u32::from(col));
    if p.text.is_empty() {
        String::new()
    } else {
        format!("={}", p.text)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Budget, Format, Limits, extract};

    /// End-to-end against a real Excel 4.0 macro `.xls` (from the `oletools` test
    /// corpus, cross-checked with `olevba`): the OLE path must surface an
    /// `xlm_macro` member that flags the macro sheet and writes the macro as
    /// `olevba` does: `ALERT("This is a sample Excel 4 macro")`.
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
        // Function names are numbers in the file; the formulas read as in Excel.
        assert!(
            text.lines()
                .any(|l| l == "=ALERT(\"This is a sample Excel 4 macro\")"),
            "recovered XLM text was: {text}"
        );
        assert!(text.lines().any(|l| l == "=HALT()"), "text: {text}");
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

    /// A formula with a token the reader refuses keeps the calls and strings
    /// before it, so a writer cannot hide a function behind an odd token.
    #[test]
    fn a_formula_the_reader_refuses_still_gives_what_came_before() {
        let mut stream = Vec::new();
        let mut rec = |id: u16, body: &[u8]| {
            stream.extend(id.to_le_bytes());
            stream.extend((body.len() as u16).to_le_bytes());
            stream.extend_from_slice(body);
        };
        rec(0x0809, &[0, 6, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut sheet = vec![0u8; 4];
        sheet.extend([0, 1, 6, 0]);
        sheet.extend(b"Macro1");
        rec(0x0085, &sheet);
        rec(0x000A, &[]);
        // =EXEC("calc") followed by a token that is not one (0x7F).
        let mut rgce = vec![0x17, 4, 0, b'c', b'a', b'l', b'c'];
        rgce.extend([0x42, 1, 110, 0, 0x7F]);
        let mut f = vec![0u8; 20];
        f.extend((rgce.len() as u16).to_le_bytes());
        f.extend(rgce);
        rec(0x0006, &f);
        let streams: Vec<(String, &[u8])> = vec![("Workbook".to_string(), &stream[..])];
        let out = super::xlm_macro_artifact(&streams).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.lines().any(|l| l == "=EXEC(\"calc\")"), "text: {text}");
    }
}
