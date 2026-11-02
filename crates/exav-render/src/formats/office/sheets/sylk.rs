//! SYLK (Symbolic Link), Multiplan's and Excel's text interchange format,
//! after Microsoft's "SYLK summary" (sylksum.doc, 1986) and knowledge base
//! article Q64338: one record a line, fields after `;` (`;;` a literal
//! semicolon), a current cell that `X` and `Y` fields move. `C` records
//! hold values and R1C1 expressions, `F` records formats, column widths
//! and row heights, `P` records the number format and font tables, `NN`
//! names. Text is in the writer's ANSI code page, with `ESC N` sequences
//! (ISO 6937) for accented letters.

use crate::formats::office::sheets::error::{Error, Result};
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use crate::formats::office::sheets::r1c1;
use std::collections::{BTreeMap, HashMap};

const ESC: u8 = 0x1B;
/// Fields read in a record, and characters in a field.
const MAX_FIELDS: usize = 256;

/// ISO 6937's non-spacing accents (`ESC N` 0x41 to 0x4F), as the
/// combining mark each stands for and the letters it composes with.
fn accent(designator: u8, base: char) -> Option<char> {
    let (from, to, spacing): (&str, &str, char) = match designator {
        0x41 => ("AEIOUaeiou", "ÀÈÌÒÙàèìòù", '`'),
        0x42 => ("AEIOUYaeiouyCcNnSsZz", "ÁÉÍÓÚÝáéíóúýĆćŃńŚśŹź", '´'),
        0x43 => ("AEIOUaeiou", "ÂÊÎÔÛâêîôû", '^'),
        0x44 => ("ANOano", "ÃÑÕãñõ", '~'),
        0x45 => ("AEIOUaeiou", "ĀĒĪŌŪāēīōū", '¯'),
        0x46 => ("AGUagu", "ĂĞŬăğŭ", '˘'),
        0x47 => ("CEGIZcegz", "ĊĖĠİŻċėġż", '˙'),
        0x48 => ("AEIOUaeiouy", "ÄËÏÖÜäëïöüÿ", '¨'),
        0x4A => ("AUau", "ÅŮåů", '˚'),
        0x4B => ("CGKLNRSTcklnrst", "ÇĢĶĻŅŖŞŢçķļņŗşţ", '¸'),
        0x4D => ("OUou", "ŐŰőű", '˝'),
        0x4E => ("AEIUaeiu", "ĄĘĮŲąęįų", '˛'),
        0x4F => ("CDENRSTZcdenrstz", "ČĎĚŇŘŠŤŽčďěňřšťž", 'ˇ'),
        _ => return None,
    };
    if base == ' ' {
        return Some(spacing);
    }
    from.chars()
        .position(|c| c == base)
        .and_then(|i| to.chars().nth(i))
        .or(Some(base))
}

/// ISO 6937's other characters (`ESC N` and one byte).
fn special(b: u8) -> Option<char> {
    const LOW: &str = "¡¢£$¥#§¤‘“«←↑→↓°±²³×µ¶·÷’”»¼½¾¿";
    const HIGH: &str = "―¹®©™♪¬¦\u{0}\u{0}\u{0}\u{0}⅛⅜⅝⅞ΩÆĐªĦ\u{0}ĲĿŁØŒºÞŦŊŉĸæđðħıĳŀłøœßþŧŋ";
    let c = match b {
        0x21..=0x3F => LOW.chars().nth(usize::from(b - 0x21)),
        0x50..=0x7E => HIGH.chars().nth(usize::from(b - 0x50)),
        _ => None,
    }?;
    (c != '\0').then_some(c)
}

/// A line's text: escape sequences resolved, the rest decoded as `cp`.
fn decode(line: &[u8], cp: &'static encoding_rs::Encoding) -> String {
    let mut out = String::new();
    let mut raw: Vec<u8> = vec![];
    let flush = |raw: &mut Vec<u8>, out: &mut String| {
        if !raw.is_empty() {
            out.push_str(&cp.decode_without_bom_handling(raw).0);
            raw.clear();
        }
    };
    let mut i = 0;
    while i < line.len() {
        let b = line[i];
        if b != ESC {
            raw.push(b);
            i += 1;
            continue;
        }
        match (line.get(i + 1).copied(), line.get(i + 2).copied()) {
            (Some(b'N'), Some(d @ 0x41..=0x4F)) => {
                let base = line.get(i + 3).map_or(' ', |&c| char::from(c));
                if let Some(c) = accent(d, base) {
                    flush(&mut raw, &mut out);
                    out.push(c);
                    i += 4;
                    continue;
                }
                i += 3;
            }
            (Some(b'N'), Some(s)) => {
                flush(&mut raw, &mut out);
                if let Some(c) = special(s) {
                    out.push(c);
                }
                i += 3;
            }
            (Some(c1 @ 0x20..=0x2F), Some(c2 @ 0x30..=0x3F)) => {
                raw.push(((c1 - 0x20) << 4) | (c2 - 0x30));
                i += 3;
            }
            _ => i += 1,
        }
    }
    flush(&mut raw, &mut out);
    out
}

/// A record's fields after its type: `;;` is a semicolon within one. A
/// quoted value (`K"..."`) also keeps the single semicolons some writers
/// leave in it.
fn fields(rest: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let last_quote = rest.rfind('"').unwrap_or(0);
    let mut chars = rest.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == ';' {
            if chars.peek().map(|p| p.1) == Some(';') {
                chars.next();
                cur.push(';');
                continue;
            }
            let quoted =
                cur.starts_with("K\"") && (cur.len() == 2 || !cur.ends_with('"')) && i < last_quote;
            if quoted {
                cur.push(';');
                continue;
            }
            out.push(std::mem::take(&mut cur));
            if out.len() >= MAX_FIELDS {
                return out;
            }
        } else {
            cur.push(c);
        }
    }
    out.push(cur);
    out
}

/// One of the formats an `F` record gives a cell, row or column.
#[derive(Clone, Default, PartialEq)]
struct Fmt {
    numfmt: Option<String>,
    align: Option<&'static str>,
    bold: bool,
    italic: bool,
    shade: bool,
    borders: [bool; 4],
    font: Option<usize>,
}

impl Fmt {
    fn is_empty(&self) -> bool {
        *self == Fmt::default()
    }

    /// Over `under`: what this one leaves unset, `under` gives.
    fn over(&self, under: &Fmt) -> Fmt {
        Fmt {
            numfmt: self.numfmt.clone().or_else(|| under.numfmt.clone()),
            align: self.align.or(under.align),
            bold: self.bold || under.bold,
            italic: self.italic || under.italic,
            shade: self.shade || under.shade,
            borders: std::array::from_fn(|i| self.borders[i] || under.borders[i]),
            font: self.font.or(under.font),
        }
    }
}

/// `F<type><digits><align>`: General (G, D, C), fixed (F), exponential
/// (E), dollar ($), percent (%), bar graph (*, left General).
fn simple(s: &str) -> (Option<String>, Option<&'static str>) {
    let b: Vec<char> = s.chars().collect();
    let Some(&kind) = b.first() else {
        return (None, None);
    };
    let digits: String = b
        .iter()
        .skip(1)
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let d: usize = digits.parse::<usize>().unwrap_or(0).min(30);
    let align = match b.get(1 + digits.len()) {
        Some('L') => Some("left"),
        Some('C') => Some("center"),
        Some('R') => Some("right"),
        Some('X') => Some("fill"),
        _ => None,
    };
    let dec = if d > 0 {
        format!(".{}", "0".repeat(d))
    } else {
        String::new()
    };
    let numfmt = match kind {
        'F' => Some(format!("0{dec}")),
        'E' => Some(format!("0{dec}E+00")),
        '$' => Some(format!("\"$\"#,##0{dec}_);\\(\"$\"#,##0{dec}\\)")),
        '%' => Some(format!("0{dec}%")),
        'I' => Some("0".into()),
        _ => None,
    };
    (numfmt, align)
}

/// A `K` value: a quoted string, TRUE or FALSE, an error, or a number.
fn value(k: &str) -> Value {
    let k = k.trim_end();
    if let Some(s) = k.strip_prefix('"') {
        return Value::text(s.strip_suffix('"').unwrap_or(s));
    }
    match k {
        "TRUE" => return Value::Bool(true),
        "FALSE" => return Value::Bool(false),
        _ => {}
    }
    if k.starts_with('#')
        && let Some(e) = CellError::parse(k)
    {
        return Value::Error(e);
    }
    match k.trim().parse::<f64>() {
        Ok(v) if v.is_finite() => Value::Number(v),
        _ if k.is_empty() => Value::Empty,
        _ => Value::text(k),
    }
}

struct Font {
    name: String,
    size: f64,
    bold: bool,
    italic: bool,
    underline: bool,
    strike: bool,
}

struct CellData {
    value: Value,
    expr: Option<String>,
    /// The cell whose expression or value this one shares.
    shared: Option<(u32, u32)>,
    array: Option<(u32, u32)>,
    note: Option<String>,
}

impl Default for CellData {
    fn default() -> Self {
        CellData {
            value: Value::Empty,
            expr: None,
            shared: None,
            array: None,
            note: None,
        }
    }
}

pub(crate) fn read(bytes: &[u8], budget: &mut Budget) -> Result<Workbook> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    if !bytes.starts_with(b"ID") {
        return Err(Error::NotFormat("not a SYLK file (no ID record)".into()));
    }
    budget.alloc(bytes.len() as u64 * 2)?;
    // UTF-8 when the file is; else the writer's ANSI code page: Mac Roman
    // for "XL" (Excel for the Macintosh, sylksum's producer list; Windows
    // Excel writes "WXL"), Windows-1252 otherwise.
    let id = bytes
        .split(|&b| b == b'\n' || b == b'\r')
        .next()
        .unwrap_or_default();
    let cp = if std::str::from_utf8(bytes).is_ok() {
        encoding_rs::UTF_8
    } else if id.split(|&b| b == b';').any(|f| f == b"PXL") {
        encoding_rs::MACINTOSH
    } else {
        encoding_rs::WINDOWS_1252
    };

    let mut numfmts: Vec<String> = vec![];
    let mut fonts: Vec<Font> = vec![];
    let mut cells: BTreeMap<(u32, u32), CellData> = BTreeMap::new();
    let mut cell_fmts: HashMap<(u32, u32), Fmt> = HashMap::new();
    let mut row_fmts: HashMap<u32, Fmt> = HashMap::new();
    let mut col_fmts: HashMap<u32, Fmt> = HashMap::new();
    let mut default_fmt = Fmt::default();
    let mut widths: Vec<(u32, u32, f64)> = vec![];
    let mut heights: BTreeMap<u32, f64> = BTreeMap::new();
    let mut default_height = None;
    let mut default_width = None;
    let mut names: Vec<(String, String)> = vec![];
    let mut date1904 = false;
    let mut show_grid = true;
    let mut show_headers = true;
    let (mut x, mut y) = (0u32, 0u32);
    let coord = |v: &str, max: u32| {
        v.trim()
            .parse::<u64>()
            .ok()
            .filter(|&n| n >= 1 && n - 1 <= u64::from(max))
            .map(|n| (n - 1) as u32)
    };

    for raw in bytes
        .split(|&b| b == b'\n' || b == b'\r')
        .filter(|l| !l.is_empty())
    {
        let line = decode(raw, cp);
        let (kind, rest) = line.split_once(';').unwrap_or((&line, ""));
        let f = fields(rest);
        match kind {
            "C" => {
                let mut data = CellData::default();
                let (mut sr, mut sc) = (None, None);
                let mut share = false;
                for fl in &f {
                    let (k, v) = fl.split_at(fl.chars().next().map_or(0, char::len_utf8));
                    match k {
                        "X" => x = coord(v, MAX_COL).unwrap_or(x),
                        "Y" => y = coord(v, MAX_ROW).unwrap_or(y),
                        "K" => data.value = value(v),
                        "E" => data.expr = Some(v.to_string()),
                        "M" => data.expr = Some(v.to_string()),
                        "S" => share = true,
                        "R" => sr = coord(v, MAX_ROW),
                        "C" => sc = coord(v, MAX_COL),
                        "A" => data.note = Some(v.to_string()),
                        _ => {}
                    }
                }
                if let (Some(r), Some(c)) = (sr, sc) {
                    if share {
                        data.shared = Some((r, c));
                    } else if f.iter().any(|fl| fl.starts_with('M')) {
                        data.array = Some((r, c));
                    }
                }
                if !cells.contains_key(&(y, x)) {
                    budget
                        .cell(data.value.text_len() + data.expr.as_ref().map_or(0, String::len))?;
                }
                cells.insert((y, x), data);
            }
            "F" => {
                let mut fmt = Fmt::default();
                let (mut row, mut col) = (None, None);
                let mut is_default = false;
                for fl in &f {
                    let (k, v) = fl.split_at(fl.chars().next().map_or(0, char::len_utf8));
                    match k {
                        "X" => x = coord(v, MAX_COL).unwrap_or(x),
                        "Y" => y = coord(v, MAX_ROW).unwrap_or(y),
                        "F" => {
                            let (n, a) = simple(v);
                            fmt.numfmt = fmt.numfmt.or(n);
                            fmt.align = a;
                        }
                        "D" => {
                            is_default = true;
                            let (n, a) = simple(v);
                            fmt.numfmt = fmt.numfmt.or(n);
                            fmt.align = a;
                            // The default column width follows the format.
                            let w: String = v
                                .chars()
                                .skip(1)
                                .skip_while(char::is_ascii_digit)
                                .skip(1)
                                .collect();
                            default_width = w
                                .trim()
                                .parse::<f64>()
                                .ok()
                                .filter(|w| (0.0..=255.0).contains(w))
                                .or(default_width);
                        }
                        "P" => {
                            if let Some(n) =
                                v.trim().parse::<usize>().ok().and_then(|i| numfmts.get(i))
                            {
                                fmt.numfmt = Some(n.clone());
                            }
                        }
                        "S" => {
                            let mut chars = v.chars().peekable();
                            while let Some(c) = chars.next() {
                                match c {
                                    'D' => fmt.bold = true,
                                    'I' => fmt.italic = true,
                                    'S' => fmt.shade = true,
                                    'T' => fmt.borders[0] = true,
                                    'R' => fmt.borders[1] = true,
                                    'B' => fmt.borders[2] = true,
                                    'L' => fmt.borders[3] = true,
                                    'M' => {
                                        let mut n = String::new();
                                        while let Some(d) = chars.next_if(char::is_ascii_digit) {
                                            n.push(d);
                                        }
                                        fmt.font = n.parse().ok();
                                    }
                                    _ => {}
                                }
                            }
                        }
                        "W" => {
                            let p: Vec<f64> = v
                                .split_whitespace()
                                .filter_map(|n| n.parse().ok())
                                .collect();
                            if let [a, b, w] = p[..]
                                && a >= 1.0
                                && b >= a
                                && (0.0..=255.0).contains(&w)
                                && widths.len() < 4096
                            {
                                widths.push((
                                    (a - 1.0).min(f64::from(MAX_COL)) as u32,
                                    (b - 1.0).min(f64::from(MAX_COL)) as u32,
                                    w,
                                ));
                            }
                        }
                        "R" => row = coord(v, MAX_ROW),
                        "C" => col = coord(v, MAX_COL),
                        "M" => {
                            if let Ok(t) = v.trim().parse::<f64>() {
                                let h = (t / 20.0).clamp(0.0, 409.0);
                                match row {
                                    Some(r) => {
                                        heights.insert(r, h);
                                    }
                                    None => default_height = Some(h),
                                }
                            }
                        }
                        "G" => show_grid = false,
                        "H" => show_headers = false,
                        _ => {}
                    }
                }
                if is_default {
                    default_fmt = fmt.over(&default_fmt);
                } else if let Some(r) = row {
                    if !fmt.is_empty() {
                        budget.alloc(96)?;
                        row_fmts.insert(r, fmt);
                    }
                } else if let Some(c) = col {
                    if !fmt.is_empty() && col_fmts.len() < 4096 {
                        col_fmts.insert(c, fmt);
                    }
                } else if !fmt.is_empty() {
                    // The cell it names, or else the current one.
                    if !cell_fmts.contains_key(&(y, x)) {
                        budget.alloc(96)?;
                    }
                    cell_fmts.insert((y, x), fmt);
                }
            }
            "P" => {
                for fl in &f {
                    let (k, v) = fl.split_at(fl.chars().next().map_or(0, char::len_utf8));
                    match k {
                        "P" if numfmts.len() < 4096 => numfmts.push(v.chars().take(255).collect()),
                        "F" | "E" if fonts.len() < 4096 => {
                            let mut font = Font {
                                name: v.chars().take(64).collect(),
                                size: 10.0,
                                bold: false,
                                italic: false,
                                underline: false,
                                strike: false,
                            };
                            for g in &f {
                                if let Some(s) = g.strip_prefix('M') {
                                    font.size = s
                                        .trim()
                                        .parse::<f64>()
                                        .map_or(10.0, |t| (t / 20.0).clamp(1.0, 409.0));
                                } else if let Some(s) = g.strip_prefix('S') {
                                    font.bold = s.contains('B');
                                    font.italic = s.contains('I');
                                    font.underline = s.contains('U');
                                    font.strike = s.contains('S');
                                }
                            }
                            fonts.push(font);
                            break;
                        }
                        _ => {}
                    }
                }
            }
            "O" => {
                for fl in &f {
                    if let Some(v) = fl.strip_prefix('V') {
                        date1904 = v.trim().parse::<u32>().is_ok_and(|v| v != 0);
                    }
                }
            }
            "NN" if names.len() < 1 << 14 => {
                let name = f.iter().find_map(|fl| fl.strip_prefix('N'));
                let expr = f.iter().find_map(|fl| fl.strip_prefix('E'));
                if let (Some(n), Some(e)) = (name, expr) {
                    names.push((n.to_string(), e.to_string()));
                }
            }
            "E" => break,
            _ => {}
        }
    }

    // The workbook.
    let font_of = |i: Option<usize>| -> crate::formats::office::sheets::model::Font {
        match i.and_then(|i| fonts.get(i)).or(fonts.first()) {
            Some(f) => crate::formats::office::sheets::model::Font {
                name: if f.name.is_empty() {
                    "Arial".into()
                } else {
                    f.name.clone()
                },
                size_centipt: (f.size * 100.0).round() as u32,
                bold: f.bold,
                italic: f.italic,
                underline: f.underline.then_some("single"),
                strike: f.strike,
                ..crate::formats::office::sheets::model::Font::default()
            },
            None => crate::formats::office::sheets::model::Font {
                name: "Arial".into(),
                size_centipt: 1000,
                ..crate::formats::office::sheets::model::Font::default()
            },
        }
    };
    let style_of = |fmt: &Fmt| -> Style {
        let mut st = Style {
            font: font_of(fmt.font),
            ..Style::default()
        };
        if let Some(n) = &fmt.numfmt {
            st.numfmt.clone_from(n);
        }
        st.align.horizontal = fmt.align;
        st.font.bold |= fmt.bold;
        st.font.italic |= fmt.italic;
        if fmt.shade {
            st.fill = Fill {
                pattern: "gray125",
                fg: None,
                bg: None,
            };
        }
        let thin = Edge {
            style: Some("thin"),
            color: None,
        };
        let [t, r, b, l] = fmt.borders;
        st.border = Border {
            top: if t { thin.clone() } else { Edge::default() },
            right: if r { thin.clone() } else { Edge::default() },
            bottom: if b { thin.clone() } else { Edge::default() },
            left: if l { thin.clone() } else { Edge::default() },
            ..Border::default()
        };
        st
    };
    let mut wb = Workbook::new(style_of(&default_fmt));
    wb.date1904 = date1904;
    let mut sheet = Sheet::new("Sheet1".into());
    sheet.show_grid = show_grid;
    sheet.show_headers = show_headers;
    if let Some(h) = default_height {
        sheet.default_row_height = h;
        sheet.default_row_custom = true;
    }
    if let Some(w) = default_width {
        sheet.base_col_width = Some(w.round() as u32);
    }
    // Columns: later records win where they overlap earlier ones.
    let mut cols: Vec<ColInfo> = vec![];
    // Widths count characters of the default font's digit; XLSX adds the
    // 5 pixels of padding (ECMA-376 part 1, 18.3.1.13).
    let f0 = font_of(None);
    let digit = (crate::formats::office::sheets::fonts::digit_twips(&f0.name, f0.size_pt()) / 15.0)
        .round()
        .max(1.0);
    for (first, last, w) in widths {
        let width = ((w * digit + 5.0) / digit * 256.0).trunc() / 256.0;
        set_cols(&mut cols, first, last, |ci| {
            ci.width = (w > 0.0).then_some(width.min(255.0));
            ci.hidden = w == 0.0;
        });
    }
    let mut cache: Vec<(Fmt, u32)> = vec![];
    let mut style_id = |wb: &mut Workbook, fmt: &Fmt| -> u32 {
        if fmt.is_empty() {
            return 0;
        }
        if let Some((_, s)) = cache.iter().find(|(f, _)| f == fmt) {
            return *s;
        }
        let s = wb.styles.add(style_of(&fmt.over(&default_fmt)));
        if cache.len() < 4096 {
            cache.push((fmt.clone(), s));
        }
        s
    };
    for (r, h) in heights {
        sheet.rows.insert(
            r,
            RowInfo {
                height: Some(h),
                custom_height: true,
                hidden: h == 0.0,
                style: None,
                outline: 0,
            },
        );
    }
    for (&r, fmt) in &row_fmts {
        let s = style_id(&mut wb, fmt);
        sheet.rows.entry(r).or_default().style = Some(s);
    }
    for (&c, fmt) in &col_fmts {
        let s = style_id(&mut wb, fmt);
        set_cols(&mut cols, c, c, |ci| ci.style = Some(s));
    }
    sheet.cols = cols;
    let mut bad_formulas = 0usize;
    let keys: Vec<(u32, u32)> = cells
        .keys()
        .copied()
        .chain(cell_fmts.keys().copied())
        .collect();
    for (r, c) in keys {
        if sheet.cells.contains_key(&(r, c)) {
            continue;
        }
        let data = cells.get(&(r, c));
        let fmt = cell_fmts.get(&(r, c)).cloned().unwrap_or_default();
        let fmt = fmt.over(
            row_fmts
                .get(&r)
                .or_else(|| col_fmts.get(&c))
                .unwrap_or(&Fmt::default()),
        );
        let style = style_id(&mut wb, &fmt);
        let Some(d) = data else {
            budget.cell(0)?;
            sheet.cells.insert((r, c), Cell::styled(style));
            continue;
        };
        // A shared expression or value: the base cell's, from here.
        let base = d.shared.and_then(|at| cells.get(&at));
        let expr = d
            .expr
            .as_deref()
            .or_else(|| base.and_then(|b| b.expr.as_deref()));
        let value = match (&d.value, base) {
            (Value::Empty, Some(b)) if b.expr.is_none() => b.value.clone(),
            (v, _) => v.clone(),
        };
        let mut formula = None;
        if let Some(e) = expr {
            match r1c1::to_a1(e, (r, c)) {
                Some(a1) => formula = Some(a1.into_boxed_str()),
                None => bad_formulas += 1,
            }
        }
        if let (Some((r2, c2)), true) = (d.array, formula.is_some()) {
            sheet.arrays.insert(
                (r, c),
                Range {
                    r1: r,
                    c1: c,
                    r2: r2.max(r),
                    c2: c2.max(c),
                },
            );
        }
        if let Some(n) = &d.note {
            sheet.comments.push(Comment {
                row: r,
                col: c,
                author: String::new(),
                text: n.chars().take(32_767).collect(),
                visible: false,
            });
        }
        sheet.cells.insert(
            (r, c),
            Cell {
                value,
                formula,
                style,
            },
        );
    }
    for (name, expr) in names {
        if let Some(formula) = r1c1::to_a1(&expr, (0, 0)) {
            wb.names.push(DefinedName {
                name,
                sheet: None,
                formula,
                hidden: false,
            });
        }
    }
    if bad_formulas > 0 {
        wb.warn(format!(
            "{bad_formulas} formulas could not be read and were left as their values"
        ));
    }
    if sheet.cells.is_empty() && cells.is_empty() && widths_empty(&sheet) {
        wb.warn("the SYLK file holds no cells");
    }
    wb.sheets.push(sheet);
    Ok(wb)
}

fn widths_empty(s: &Sheet) -> bool {
    s.cols.is_empty()
}

/// Applies `f` to columns `first..=last` of `cols`, a sorted list of
/// ranges that do not overlap, splitting the ranges it cuts.
fn set_cols(cols: &mut Vec<ColInfo>, first: u32, last: u32, f: impl Fn(&mut ColInfo)) {
    let mut out = Vec::with_capacity(cols.len() + 2);
    let mut covered = first;
    for ci in cols.drain(..) {
        if ci.last < first || ci.first > last {
            out.push(ci);
            continue;
        }
        if ci.first < first {
            out.push(ColInfo {
                last: first - 1,
                ..ci.clone()
            });
        }
        // The gap before this range, then the part inside.
        let (a, b) = (ci.first.max(first), ci.last.min(last));
        if covered < a {
            let mut gap = ColInfo {
                first: covered,
                last: a - 1,
                width: None,
                hidden: false,
                style: None,
                outline: 0,
            };
            f(&mut gap);
            out.push(gap);
        }
        let mut mid = ColInfo {
            first: a,
            last: b,
            ..ci.clone()
        };
        f(&mut mid);
        out.push(mid);
        covered = b.saturating_add(1);
        if ci.last > last {
            out.push(ColInfo {
                first: last + 1,
                ..ci
            });
        }
    }
    if covered <= last {
        let mut rest = ColInfo {
            first: covered,
            last,
            width: None,
            hidden: false,
            style: None,
            outline: 0,
        };
        f(&mut rest);
        out.push(rest);
    }
    out.sort_by_key(|c| c.first);
    *cols = out;
}

#[cfg(test)]
mod tests;
