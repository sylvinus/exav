//! Numbers '08 and '09 documents: one XML file, `index.xml` (gzipped in
//! packages), in Apple's "sf", "sfa" and "ls" namespaces. No description
//! of the format was published; what is read here was learnt from sample
//! files, the converter's output on them checked against another
//! application's.
//!
//! What the samples show:
//! - `ls:workspace` elements are the sheets (`ls:workspace-name`); their
//!   `sf:tabular-model` elements the tables (`sf:name`, `sf:id`,
//!   `sf:num-header-rows`, `sf:num-header-columns`, `sf:num-footer-rows`,
//!   `sf:header-rows-frozen`, `sf:header-columns-frozen`). Tables under
//!   `ls:tabular-prototypes` are templates, not content.
//! - `sf:grid` gives `sf:numrows` and `sf:numcols`, then `sf:columns`
//!   (`sf:grid-column sf:width`, points), `sf:rows` (`sf:grid-row
//!   sf:height`), the gridline styles and `sf:datasource`.
//! - The data source lists cells in order. A cell's position is its row
//!   times 256 plus its column; `sf:ct` is its distance from the previous
//!   cell's (the first
//!   cell's position), 1 when absent. Cells: `g` empty, `t` text (an
//!   `sf:ct` child's `sfa:s`), `n` number (`sf:v`), `d` date
//!   (`sf:cell-date`, seconds since 2001-01-01), `cb` check box, `f`
//!   formula (`sf:fo sf:fs`, its result in `sf:r`), `pm` pop-up menu (the
//!   choice `sf:proxied-cell-ref` names), `s` a cell a merge covers.
//!   `sf:col-span` and `sf:row-span` merge; `sf:s` names the cell style.
//! - Styles reference each other by `sfa:ID` / `sfa:IDREF`, and inherit by
//!   `sf:parent-ident` / `sf:ident`; a property is set when its element in
//!   `sf:property-map` has content (`sf:null` sets it empty).
//! - Formulas are text, with tables named `SFTGlobalID_<sf:id> ::`.

use super::format;
use super::formula::TableDims;
use super::proto::Msg;
use super::style::TextProps;
use super::table::{push_merge, region, serial, width_chars};
use crate::formats::office::sheets::error::{Error, Result};
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use crate::formats::office::sheets::ods::dom::{self, Node};
use std::collections::HashMap;

const MAX_CHAIN: usize = 32;
/// Columns a row holds: positions count 256 to a row.
const ROW_STRIDE: i64 = 256;
const MAX_FORMULA: usize = 16_384;

struct Doc<'a> {
    ids: HashMap<&'a str, &'a Node>,
    idents: HashMap<&'a str, &'a Node>,
}

impl<'a> Doc<'a> {
    /// Style idents repeat: each table prototype and the printing
    /// stylesheet carry their own copies. The document's are taken first.
    fn index(root: &'a Node) -> Doc<'a> {
        let mut doc = Doc {
            ids: HashMap::new(),
            idents: HashMap::new(),
        };
        for all in [false, true] {
            let mut stack = vec![root];
            while let Some(n) = stack.pop() {
                if !all && matches!(n.name.as_str(), "ls:tabular-prototypes" | "ls:printingss") {
                    continue;
                }
                if let Some(id) = n.attr("sfa:ID") {
                    doc.ids.entry(id).or_insert(n);
                }
                if let Some(id) = n.attr("sf:ident") {
                    doc.idents.entry(id).or_insert(n);
                }
                stack.extend(n.nodes());
            }
        }
        doc
    }

    /// `n`, or what its `sfa:IDREF` names.
    fn deref(&self, n: &'a Node) -> &'a Node {
        match n.attr("sfa:IDREF").and_then(|r| self.ids.get(r)) {
            Some(t) => t,
            None => n,
        }
    }

    /// The first child of `n` that is not `sf:null`, dereferenced.
    fn value_of(&self, n: &'a Node) -> Option<&'a Node> {
        let v = n.nodes().next()?;
        (v.name != "sf:null").then(|| self.deref(v))
    }

    /// Property `name` of `style` or of the first style up its chain that
    /// sets it: the property element, `None` when no style sets it.
    fn prop(&self, style: &'a Node, name: &str) -> Option<&'a Node> {
        let mut cur = Some(style);
        for _ in 0..MAX_CHAIN {
            let s = cur?;
            if let Some(p) = s.child("sf:property-map").and_then(|m| m.child(name)) {
                if p.nodes().next().is_some() {
                    return Some(p);
                }
            }
            cur = s
                .attr("sf:parent-ident")
                .and_then(|i| self.idents.get(i))
                .copied();
        }
        None
    }

    fn number(&self, style: &'a Node, name: &str) -> Option<f64> {
        self.value_of(self.prop(style, name)?)?
            .attr("sfa:number")?
            .parse()
            .ok()
    }
}

fn num(n: &Node, a: &str) -> Option<f64> {
    n.attr(a)
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite())
}

/// An `sf:color`: RGB or grey, `None` when transparent.
fn color(c: &Node) -> Option<Rgb> {
    rgba(c, false)
}

/// A colour as RGB, `None` when transparent; `on_white`: a translucent
/// colour as it shows over white.
fn rgba(c: &Node, on_white: bool) -> Option<Rgb> {
    let a = num(c, "sfa:a").unwrap_or(1.0).clamp(0.0, 1.0);
    if a < 0.01 {
        return None;
    }
    let f = |n| num(c, n).unwrap_or(0.0).clamp(0.0, 1.0);
    let (r, g, b) = match c.attr("sfa:w") {
        Some(_) => (f("sfa:w"), f("sfa:w"), f("sfa:w")),
        None => (f("sfa:r"), f("sfa:g"), f("sfa:b")),
    };
    let q = |v: f64| {
        let v = if on_white { v * a + (1.0 - a) } else { v };
        (v * 255.0).round() as u32
    };
    Some(q(r) << 16 | q(g) << 8 | q(b))
}

/// The colour a fill shows over the white page: its colour, or a
/// gradient's first stop. Table styles fill with translucent colours.
fn fill_color(n: &Node) -> Option<Rgb> {
    if n.name == "sf:color" {
        return rgba(n, true);
    }
    rgba(n.find("sf:color")?, true)
}

/// A protobuf TSK.FormatStructArchive of the fields `format::code` reads.
struct FormatFields {
    kind: u32,
    decimals: Option<u64>,
    currency: Option<String>,
    negative: Option<u64>,
    thousands: Option<bool>,
    accounting: Option<bool>,
    fraction: Option<u64>,
    date: Option<String>,
}

impl FormatFields {
    fn encode(&self) -> Vec<u8> {
        fn varint(out: &mut Vec<u8>, mut v: u64) {
            loop {
                let b = (v & 0x7F) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(b);
                    return;
                }
                out.push(b | 0x80);
            }
        }
        let mut out = vec![];
        let mut field = |n: u32, v: u64| {
            varint(&mut out, u64::from(n) << 3);
            varint(&mut out, v);
        };
        field(1, u64::from(self.kind));
        if let Some(d) = self.decimals {
            field(2, d);
        }
        if let Some(n) = self.negative {
            field(4, n);
        }
        if let Some(t) = self.thousands {
            field(5, u64::from(t));
        }
        if let Some(a) = self.accounting {
            field(6, u64::from(a));
        }
        if let Some(f) = self.fraction {
            field(11, f);
        }
        for (n, s) in [(3u32, &self.currency), (14, &self.date)] {
            if let Some(s) = s {
                varint(&mut out, u64::from(n) << 3 | 2);
                varint(&mut out, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
        }
        out
    }
}

/// A cell's format code: its own computed format (`sf:cf`), else its
/// style's; `None` for General.
fn format_code(
    doc: &Doc,
    cell: &Node,
    style: Option<&Node>,
    value: Option<f64>,
    is_date: bool,
) -> Option<String> {
    let cf = cell
        .nodes()
        .find(|n| n.name == "sf:cf" || n.name == "sf:cf-ref")
        .map(|n| doc.deref(n));
    let number_format = cf.and_then(|c| c.child("sf:number-format")).or_else(|| {
        style
            .and_then(|s| doc.prop(s, "sf:SFTCellStylePropertyNumberFormat"))
            .and_then(|p| doc.value_of(p))
    });
    let date_format = cf
        .and_then(|c| {
            c.nodes()
                .find(|n| n.name == "sf:date-format" || n.name == "sf:date-format-ref")
        })
        .map(|n| doc.deref(n))
        .or_else(|| {
            style
                .and_then(|s| doc.prop(s, "sf:SFTCellStylePropertyDateTimeFormat"))
                .and_then(|p| doc.value_of(p))
        });
    let declared = style
        .and_then(|s| doc.number(s, "sf:SFTCellStylePropertyFormatType"))
        .map(|v| v as u32)
        .filter(|&t| t != 255);
    let implicit = cf
        .and_then(|c| num(c, "sf:implicit-format-type"))
        .map(|v| v as u32)
        .or_else(|| {
            style
                .and_then(|s| doc.number(s, "sf:SFTCellStylePropertyImplicitFormatType"))
                .map(|v| v as u32)
        })
        .filter(|&t| t != 255);
    // Automatic (255) shows numbers as General does; an implicit type is
    // the format Numbers chose for an automatic cell, its decimals those
    // the value was typed with.
    let kind = if is_date {
        format::DATE
    } else {
        declared.or(implicit)?
    };
    let fields = match kind {
        format::DATE => FormatFields {
            kind,
            decimals: None,
            currency: None,
            negative: None,
            thousands: None,
            accounting: None,
            fraction: None,
            date: date_format
                .and_then(|d| d.attr("sf:fmt"))
                .map(str::to_string),
        },
        format::DECIMAL
        | format::CURRENCY
        | format::PERCENT
        | format::SCIENTIFIC
        | format::FRACTION => {
            let n = number_format?;
            // 65534 in the samples: as many as the value needs, which the
            // format code reads as 253.
            let decimals = num(n, "sf:format-decimal-places").map(|d| d.clamp(0.0, 253.0) as u64);
            FormatFields {
                kind,
                decimals,
                currency: n.attr("sf:format-currency-code").map(str::to_string),
                negative: num(n, "sf:format-negative-style").map(|v| v.max(0.0) as u64),
                thousands: n
                    .attr("sf:format-show-thousands-separator")
                    .map(|v| v == "true"),
                accounting: n
                    .attr("sf:format-use-accounting-style")
                    .map(|v| v == "true"),
                fraction: num(n, "sf:format-fraction-accuracy")
                    .map(|v| (v as i64 as i32) as u32 as u64),
                date: None,
            }
        }
        format::TEXT => return Some("@".into()),
        _ => return None,
    };
    let bytes = fields.encode();
    format::code(Msg(&bytes), None, value)
}

/// The paragraph style a cell style draws its text with.
fn paragraph_style<'a>(doc: &Doc<'a>, style: &'a Node) -> Option<&'a Node> {
    if let Some(p) = doc
        .prop(style, "sf:SFTCellStylePropertyParagraphStyle")
        .and_then(|p| doc.value_of(p))
    {
        return Some(p);
    }
    let layout = doc
        .prop(style, "sf:SFTCellStylePropertyLayoutStyle")
        .and_then(|p| doc.value_of(p))?;
    doc.prop(layout, "sf:layoutParagraphStyle")
        .and_then(|p| doc.value_of(p))
}

/// A paragraph style's character properties. Weight and slant are those
/// `sf:bold` and `sf:italic` set, whatever face `sf:fontName` names: a
/// sample's body cells in "Cochin-Bold" without `sf:bold` show regular.
fn text_props(doc: &Doc, para: &Node) -> TextProps {
    let n = |name: &str| doc.number(para, name);
    TextProps {
        bold: Some(n("sf:bold").is_some_and(|v| v != 0.0)),
        italic: Some(n("sf:italic").is_some_and(|v| v != 0.0)),
        size: n("sf:fontSize").map(|v| v as f32).filter(|v| *v > 0.0),
        font: doc
            .prop(para, "sf:fontName")
            .and_then(|p| doc.value_of(p))
            .and_then(|s| s.attr("sfa:string"))
            .map(str::to_string),
        color: doc
            .prop(para, "sf:fontColor")
            .map(|p| doc.value_of(p).and_then(color)),
        underline: n("sf:underline").map(|v| v as u64),
        strike: n("sf:strikethru").map(|v| v as u64),
        align: n("sf:alignment").map(|v| v as u64),
    }
}

/// A stroke as an edge: no line when its pattern is empty.
fn stroke_edge(doc: &Doc, vector_style: &Node) -> Option<Edge> {
    let p = doc.prop(vector_style, "sf:SFTStrokeProperty")?;
    let s = doc.value_of(p)?;
    let pattern = s.child("sf:pattern").map(|p| doc.deref(p));
    let kind = pattern.and_then(|p| p.attr("sf:type")).unwrap_or("solid");
    let width = num(s, "sf:width").unwrap_or(1.0);
    let rgb = s.child("sf:color").and_then(color);
    if matches!(kind, "empty" | "none") || width <= 0.0 || rgb.is_none() {
        return Some(Edge::default());
    }
    let style = match (kind, width) {
        ("pattern", _) => "dashed",
        (_, w) if w >= 2.5 => "thick",
        (_, w) if w >= 1.5 => "medium",
        _ => "thin",
    };
    Some(Edge {
        style: Some(style),
        color: rgb.filter(|&c| c != 0),
    })
}

/// Formula text of Numbers '09 to Excel syntax; `None` for what Excel
/// cannot say.
fn convert_formula(
    fs: &str,
    host: usize,
    tables: &[TableDims],
    by_id: &HashMap<String, usize>,
) -> Option<String> {
    let src: Vec<char> = fs.trim().trim_start_matches('=').chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut table: Option<usize> = None;
    while i < src.len() {
        let c = src[i];
        if c == '"' {
            let start = i;
            i += 1;
            while i < src.len() {
                if src[i] == '"' {
                    if src.get(i + 1) == Some(&'"') {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i += 1;
            }
            i = (i + 1).min(src.len());
            out.extend(&src[start..i]);
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' || c == '$' {
            let start = i;
            while i < src.len()
                && (src[i].is_ascii_alphanumeric() || matches!(src[i], '_' | '$' | '.'))
            {
                i += 1;
            }
            let word: String = src[start..i].iter().collect();
            let mut j = i;
            while j < src.len() && src[j] == ' ' {
                j += 1;
            }
            if let Some(id) = word.strip_prefix("SFTGlobalID_") {
                // A table: what follows "::" is in it.
                if src.get(j) == Some(&':') && src.get(j + 1) == Some(&':') {
                    table = Some(*by_id.get(&id.to_ascii_uppercase())?);
                    i = j + 2;
                    while i < src.len() && src[i] == ' ' {
                        i += 1;
                    }
                    continue;
                }
                return None;
            }
            if src.get(j) == Some(&'(') {
                if word.starts_with("__") {
                    return None;
                }
                let up = word.to_ascii_uppercase();
                if crate::formats::office::sheets::ods::formula::XLFN.contains(&up.as_str()) {
                    out.push_str("_xlfn.");
                }
                out.push_str(&up);
                continue;
            }
            // A reference, alone or the start of a range.
            let first = parse_ref(&word);
            let mut second = None;
            if first.is_some() && src.get(i) == Some(&':') {
                let s = i + 1;
                let mut e = s;
                while e < src.len() && (src[e].is_ascii_alphanumeric() || src[e] == '$') {
                    e += 1;
                }
                let w: String = src[s..e].iter().collect();
                if let Some(r) = parse_ref(&w) {
                    second = Some(r);
                    i = e;
                }
            }
            match first {
                Some(a) => {
                    let t = table.take().unwrap_or(host);
                    out.push_str(&ref_text(a, second.unwrap_or(a), t, host, tables)?);
                }
                None => {
                    if table.is_some() {
                        return None;
                    }
                    out.push_str(&word);
                }
            }
            continue;
        }
        match c {
            '×' => out.push('*'),
            '÷' => out.push('/'),
            '≠' => out.push_str("<>"),
            '≤' => out.push_str("<="),
            '≥' => out.push_str(">="),
            _ => out.push(c),
        }
        i += 1;
        if out.len() > MAX_FORMULA {
            return None;
        }
    }
    (!out.contains("::") && !out.trim().is_empty() && table.is_none()).then_some(out)
}

/// A reference token: (column, column absolute, row, row absolute), the
/// row `None` for a whole column.
type Ref = (u32, bool, Option<u32>, bool);

fn parse_ref(w: &str) -> Option<Ref> {
    let b = w.as_bytes();
    let mut i = 0;
    let col_abs = b.first() == Some(&b'$');
    if col_abs {
        i += 1;
    }
    let cs = i;
    while i < b.len() && b[i].is_ascii_uppercase() {
        i += 1;
    }
    if i == cs || i - cs > 3 {
        return None;
    }
    let col = b[cs..i]
        .iter()
        .fold(0u32, |a, &x| a * 26 + u32::from(x - b'A' + 1))
        - 1;
    if i == b.len() {
        if matches!(w, "TRUE" | "FALSE") {
            return None;
        }
        return (col <= MAX_COL).then_some((col, col_abs, None, false));
    }
    let row_abs = b[i] == b'$';
    if row_abs {
        i += 1;
    }
    let row: u32 = std::str::from_utf8(&b[i..]).ok()?.parse().ok()?;
    (row >= 1 && row - 1 <= MAX_ROW && col <= MAX_COL).then_some((
        col,
        col_abs,
        Some(row - 1),
        row_abs,
    ))
}

fn ref_text(a: Ref, b: Ref, t: usize, host: usize, tables: &[TableDims]) -> Option<String> {
    let d = tables.get(t)?;
    let cell = |c: u32, ca: bool, r: u32, ra: bool| {
        format!(
            "{}{}{}{}",
            if ca { "$" } else { "" },
            col_name(c),
            if ra { "$" } else { "" },
            r + 1
        )
    };
    let text = match (a.2, b.2) {
        (Some(r1), Some(r2)) if (a.0, r1) == (b.0, r2) => cell(a.0, a.1, r1, a.3),
        (Some(r1), Some(r2)) => format!("{}:{}", cell(a.0, a.1, r1, a.3), cell(b.0, b.1, r2, b.3)),
        _ => {
            // A whole column: its body rows, as in Numbers.
            let first = d.header_rows;
            let last = d.rows.saturating_sub(d.footer_rows).saturating_sub(1);
            let (first, last) = if first <= last {
                (first, last)
            } else {
                (0, d.rows.saturating_sub(1))
            };
            format!(
                "{}:{}",
                cell(a.0, a.1, first, true),
                cell(b.0, b.1, last, true)
            )
        }
    };
    Some(if t == host {
        text
    } else {
        format!(
            "{}!{text}",
            crate::formats::office::sheets::xls::formula::quote_sheet(&d.name)
        )
    })
}

struct TableRef<'a> {
    model: &'a Node,
    sheet: usize,
}

/// The tables of a sheet, in document order, prototypes left out.
fn tables_in<'a>(n: &'a Node, out: &mut Vec<&'a Node>, depth: u32) {
    for c in n.nodes() {
        if c.name == "sf:tabular-model" {
            out.push(c);
        } else if depth < 32 && c.name != "ls:tabular-prototypes" {
            tables_in(c, out, depth + 1);
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct StyleKey {
    style: Option<String>,
    numfmt: Option<String>,
    border: [Option<Edge>; 4],
    band: Option<Rgb>,
}

pub(crate) fn read(xml: &[u8], budget: &mut Budget) -> Result<Workbook> {
    budget.alloc(xml.len() as u64 * 4)?;
    let root = dom::parse(xml, dom::MAX_ELEMENTS)?;
    if root.name != "ls:document" {
        return Err(Error::NotFormat("not a Numbers '08 or '09 document".into()));
    }
    let doc = Doc::index(&root);
    let mut wb = Workbook::new(Style {
        font: Font {
            name: "Helvetica".into(),
            ..Font::default()
        },
        align: Align {
            vertical: Some("top"),
            wrap: true,
            ..Align::default()
        },
        ..Style::default()
    });

    let mut sheets: Vec<String> = vec![];
    let mut refs: Vec<TableRef> = vec![];
    for (k, ws) in root
        .child("ls:workspace-array")
        .into_iter()
        .flat_map(|a| a.all("ls:workspace"))
        .take(4096)
        .enumerate()
    {
        sheets.push(
            ws.attr("ls:workspace-name")
                .map_or_else(|| format!("Sheet {}", k + 1), str::to_string),
        );
        let mut found = vec![];
        tables_in(ws, &mut found, 0);
        refs.extend(found.into_iter().map(|model| TableRef { model, sheet: k }));
    }
    if refs.is_empty() {
        return Err(Error::Unsupported(
            "a Numbers document without tables".into(),
        ));
    }
    if refs.len() > budget.limits.max_sheets as usize {
        return Err(Error::TooLarge("sheets"));
    }
    let raw: Vec<String> = refs
        .iter()
        .map(|t| {
            let name = t.model.attr("sf:name").unwrap_or("Table");
            if refs.iter().filter(|x| x.sheet == t.sheet).count() == 1 {
                sheets[t.sheet].clone()
            } else {
                format!("{} - {name}", sheets[t.sheet])
            }
        })
        .collect();
    let names = crate::formats::office::sheets::xlsx::sheet_names(raw.iter().map(String::as_str));
    let count = |m: &Node, a: &str, max: u32| {
        m.attr(a)
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0)
            .min(max)
    };
    let dims: Vec<TableDims> = refs
        .iter()
        .zip(&names)
        .map(|(t, n)| {
            let grid = t.model.child("sf:grid");
            let rows = grid.map_or(0, |g| count(g, "sf:numrows", MAX_ROW + 1));
            let cols = grid.map_or(0, |g| count(g, "sf:numcols", 256));
            TableDims {
                name: n.clone(),
                rows,
                cols,
                header_rows: count(t.model, "sf:num-header-rows", rows),
                header_cols: count(t.model, "sf:num-header-columns", cols),
                footer_rows: count(t.model, "sf:num-footer-rows", rows),
            }
        })
        .collect();
    let by_id: HashMap<String, usize> = refs
        .iter()
        .enumerate()
        .filter_map(|(i, t)| Some((t.model.attr("sf:id")?.to_ascii_uppercase(), i)))
        .collect();

    let mut bad_formulas = 0usize;
    for (i, t) in refs.iter().enumerate() {
        let mut sheet = Sheet::new(dims[i].name.clone());
        sheet.show_grid = false;
        read_table(
            &doc,
            t.model,
            i,
            &dims,
            &by_id,
            &mut sheet,
            &mut wb,
            budget,
            &mut bad_formulas,
        )?;
        wb.sheets.push(sheet);
    }
    if bad_formulas > 0 {
        wb.warn(format!(
            "{bad_formulas} formulas Excel cannot express were left as their values"
        ));
    }
    if root.find("sf:chart-info").is_some() {
        wb.warn("charts are not converted");
    }
    Ok(wb)
}

#[allow(clippy::too_many_arguments)]
fn read_table(
    doc: &Doc,
    model: &Node,
    idx: usize,
    dims: &[TableDims],
    by_id: &HashMap<String, usize>,
    sheet: &mut Sheet,
    wb: &mut Workbook,
    budget: &mut Budget,
    bad_formulas: &mut usize,
) -> Result<()> {
    let d = &dims[idx];
    let Some(grid) = model.child("sf:grid") else {
        return Ok(());
    };

    // Sizes.
    sheet.default_row_height = 18.0;
    sheet.default_row_custom = true;
    sheet.default_col_width = Some(width_chars(72.0));
    for (c, col) in grid
        .child("sf:columns")
        .into_iter()
        .flat_map(|n| n.all("sf:grid-column"))
        .take(d.cols as usize)
        .enumerate()
    {
        if let Some(w) = num(col, "sf:width").filter(|w| *w >= 0.0) {
            sheet.cols.push(ColInfo {
                first: c as u32,
                last: c as u32,
                width: Some(width_chars(w)),
                hidden: w == 0.0,
                style: None,
                outline: 0,
            });
        }
    }
    for (r, row) in grid
        .child("sf:rows")
        .into_iter()
        .flat_map(|n| n.all("sf:grid-row"))
        .take(d.rows as usize)
        .enumerate()
    {
        if let Some(h) = num(row, "sf:height").filter(|h| *h >= 0.0) {
            sheet.rows.insert(
                r as u32,
                RowInfo {
                    height: Some(h.min(409.0)),
                    custom_height: true,
                    hidden: h == 0.0,
                    style: None,
                    outline: 0,
                },
            );
        }
    }

    // Borders: the gridlines' style runs, else the table style's.
    let borders = gridlines(doc, model, grid, d, budget)?;

    // Region styles, for cells the data source leaves out.
    let table_style = model.child("sf:tabular-style-ref").map(|n| doc.deref(n));
    let region_style = |reg: usize| -> Option<&Node> {
        let name = [
            "sf:SFTDefaultBodyCellStyleProperty",
            "sf:SFTDefaultHeaderRowCellStyleProperty",
            "sf:SFTDefaultHeaderColumnCellStyleProperty",
            "sf:SFTDefaultFooterRowCellStyleProperty",
        ][reg];
        table_style
            .and_then(|t| doc.prop(t, name))
            .and_then(|p| doc.value_of(p))
    };

    // Banded rows: every second body row, from the second, takes the band
    // fill where its cells have none.
    let band_fill = table_style
        .filter(|t| {
            doc.number(t, "sf:SFTTableBandedRowsProperty")
                .is_some_and(|v| v != 0.0)
        })
        .and_then(|t| doc.prop(t, "sf:SFTTableBandedCellFillProperty"))
        .and_then(|p| doc.value_of(p))
        .and_then(fill_color);
    let band =
        |r: u32, c: u32| band_fill.filter(|_| region(d, r, c) == 0 && (r - d.header_rows) % 2 == 1);

    let mut cache: HashMap<StyleKey, u32> = HashMap::new();
    let mut style_of = |wb: &mut Workbook,
                        style: Option<&Node>,
                        numfmt: Option<String>,
                        border: [Option<Edge>; 4],
                        band: Option<Rgb>|
     -> u32 {
        let key = StyleKey {
            style: style.and_then(|s| s.attr("sfa:ID")).map(str::to_string),
            numfmt,
            border,
            band,
        };
        if let Some(&s) = cache.get(&key) {
            return s;
        }
        let mut st = Style::default();
        let mut tp = TextProps::default();
        if let Some(s) = style {
            if let Some(p) = paragraph_style(doc, s) {
                tp = text_props(doc, p);
            }
            if let Some(f) = doc.prop(s, "sf:fill") {
                if let Some(c) = doc.value_of(f).and_then(fill_color) {
                    st.fill = Fill::solid(c);
                }
            }
            st.align.wrap = doc
                .number(s, "sf:SFTCellTextWrapProperty")
                .is_none_or(|v| v != 0.0);
            let valign = doc.number(s, "sf:verticalAlignment").or_else(|| {
                let layout = doc
                    .prop(s, "sf:SFTCellStylePropertyLayoutStyle")
                    .and_then(|p| doc.value_of(p))?;
                doc.number(layout, "sf:verticalAlignment")
            });
            st.align.vertical = match valign.map(|v| v as u32) {
                Some(1) => Some("center"),
                Some(2) => None,
                _ => Some("top"),
            };
        } else {
            st.align.vertical = Some("top");
            st.align.wrap = true;
        }
        if let (Some(c), "none") = (key.band, st.fill.pattern) {
            st.fill = Fill::solid(c);
        }
        if tp.font.is_none() {
            tp.font = Some("Helvetica".into());
        }
        st.font = tp.font();
        st.align.horizontal = match tp.align {
            Some(0) => Some("left"),
            Some(1) => Some("right"),
            Some(2) => Some("center"),
            Some(3) => Some("justify"),
            _ => None,
        };
        if let Some(f) = &key.numfmt {
            st.numfmt.clone_from(f);
        }
        let [top, right, bottom, left] = key.border.clone();
        st.border = Border {
            top: top.unwrap_or_default(),
            right: right.unwrap_or_default(),
            bottom: bottom.unwrap_or_default(),
            left: left.unwrap_or_default(),
            ..Border::default()
        };
        let id = wb.styles.add(st);
        cache.insert(key, id);
        id
    };

    // Cells.
    let mut pos: i64 = 0;
    let mut first = true;
    let source = grid.child("sf:datasource");
    for cell in source.into_iter().flat_map(|s| s.nodes()) {
        let step = cell
            .attr("sf:ct")
            .and_then(|v| v.trim().parse::<i64>().ok());
        pos = if first {
            step.unwrap_or(0)
        } else {
            pos.saturating_add(step.unwrap_or(1))
        };
        first = false;
        if pos < 0 {
            break;
        }
        let (r, c) = ((pos / ROW_STRIDE) as u64, (pos % ROW_STRIDE) as u32);
        if r >= u64::from(d.rows) {
            break;
        }
        let r = r as u32;
        if c >= d.cols {
            continue;
        }
        let style = cell.attr("sf:s").and_then(|s| doc.ids.get(s)).copied();
        let mut formula = None;
        let (value, fmt) = match cell.name.as_str() {
            "sf:t" => (
                text_of(cell).map_or(Value::Empty, Value::text),
                format_code(doc, cell, style, None, false).filter(|f| f == "@"),
            ),
            "sf:n" => {
                let v = num(cell, "sf:v");
                (
                    v.map_or(Value::Empty, Value::Number),
                    format_code(doc, cell, style, v, false),
                )
            }
            "sf:d" => {
                let v = num(cell, "sf:cell-date").map(serial);
                (
                    v.map_or(Value::Empty, Value::Number),
                    format_code(doc, cell, style, v, true)
                        .or_else(|| Some(format::DEFAULT_DATE.into())),
                )
            }
            "sf:cb" => (
                Value::Bool(num(cell, "sf:v").is_some_and(|v| v != 0.0)),
                None,
            ),
            "sf:pm" => {
                let choice = cell.find("sf:proxied-cell-ref").map(|n| doc.deref(n));
                let v = match choice {
                    Some(ch) if ch.name == "sf:n" => {
                        num(ch, "sf:v").map_or(Value::Empty, Value::Number)
                    }
                    Some(ch) => text_of(ch).map_or(Value::Empty, Value::text),
                    None => Value::Empty,
                };
                (v, None)
            }
            "sf:f" => {
                if let Some(fs) = cell
                    .child("sf:fo")
                    .map(|n| doc.deref(n))
                    .and_then(|f| f.attr("sf:fs"))
                {
                    match convert_formula(fs, idx, dims, by_id) {
                        Some(f) => formula = Some(f.into_boxed_str()),
                        None => *bad_formulas += 1,
                    }
                }
                let result = cell.child("sf:r").and_then(|r| r.nodes().next());
                match result {
                    Some(res) if res.name == "sf:rn" => {
                        let v = num(res, "sf:v").unwrap_or(0.0);
                        (
                            Value::Number(v),
                            format_code(doc, res, style, Some(v), false),
                        )
                    }
                    Some(res) if res.name == "sf:rd" => {
                        let v = num(res, "sf:cell-date").map(serial);
                        (
                            v.map_or(Value::Empty, Value::Number),
                            Some(format::DEFAULT_DATE.into()),
                        )
                    }
                    Some(res) if res.name == "sf:rb" => (
                        Value::Bool(num(res, "sf:v").is_some_and(|v| v != 0.0)),
                        None,
                    ),
                    Some(res) => (text_of(res).map_or(Value::Empty, Value::text), None),
                    None => (Value::Empty, None),
                }
            }
            _ => (Value::Empty, None),
        };
        // Merges.
        let span = |a: &str| {
            cell.attr(a)
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|&n| n > 1)
        };
        let (cs, rs) = (span("sf:col-span"), span("sf:row-span"));
        if cs.is_some() || rs.is_some() {
            let last = |at: u32, n: Option<u32>| at.saturating_add(n.unwrap_or(1) - 1);
            push_merge(sheet, d, r, c, last(r, rs), last(c, cs));
        }
        let border = borders.get(&(r, c)).cloned().unwrap_or_default();
        let sid = style_of(wb, style, fmt, border, band(r, c));
        let extra = value.text_len() + formula.as_ref().map_or(0, |f| f.len());
        budget.cell(extra)?;
        sheet.cells.insert(
            (r, c),
            Cell {
                value,
                formula,
                style: sid,
            },
        );
    }

    // Cells the data source leaves out that show a fill or a border.
    let area = u64::from(d.rows) * u64::from(d.cols);
    if area <= 1 << 20 && budget.room_for_cells(area) {
        for r in 0..d.rows {
            for c in 0..d.cols {
                if sheet.cells.contains_key(&(r, c)) {
                    continue;
                }
                let border = borders.get(&(r, c)).cloned().unwrap_or_default();
                let sid = style_of(wb, region_style(region(d, r, c)), None, border, band(r, c));
                let st = wb.styles.get(sid);
                if st.fill.pattern != "none" || st.border != Border::default() {
                    budget.cell(0)?;
                    sheet.cells.insert((r, c), Cell::styled(sid));
                }
            }
        }
    }

    let fr = if model.attr("sf:header-rows-frozen") == Some("true") {
        d.header_rows
    } else {
        0
    };
    let fc = if model.attr("sf:header-columns-frozen") == Some("true") {
        d.header_cols
    } else {
        0
    };
    if fr > 0 || fc > 0 {
        sheet.freeze = Some((fr, fc));
    }
    Ok(())
}

/// A text cell's text: its `sf:ct` child's, else the paragraphs it holds.
fn text_of(n: &Node) -> Option<String> {
    if let Some(s) = n.child("sf:ct").and_then(|c| c.attr("sfa:s")) {
        return Some(s.to_string());
    }
    let mut out = vec![];
    let mut stack = vec![n];
    while let Some(x) = stack.pop() {
        if x.name == "sf:p" {
            out.push(x.own_text());
            continue;
        }
        let mut kids: Vec<&Node> = x.nodes().collect();
        kids.reverse();
        stack.extend(kids);
        if out.len() > 4096 {
            break;
        }
    }
    (!out.is_empty()).then(|| out.join("\n"))
}

/// Each cell's top, right, bottom and left edges.
type Borders = HashMap<(u32, u32), [Option<Edge>; 4]>;

/// The table's lines: `sf:vertical-gridline-styles` (line `i` left of
/// column `i`, its runs over rows) and `sf:horizontal-gridline-styles`
/// (line `i` above row `i`, its runs over columns), each run an
/// `sf:vector-style-ref` from `sf:start-index` to `sf:stop-index`. With
/// none, the table style's: body lines inside, the border around, the
/// header and footer separators.
fn gridlines(
    doc: &Doc,
    model: &Node,
    grid: &Node,
    d: &TableDims,
    budget: &mut Budget,
) -> Result<Borders> {
    let mut out: Borders = HashMap::new();
    if u64::from(d.rows) * u64::from(d.cols) > 1 << 20 {
        return Ok(out);
    }
    // (vertical, line, from, to, edge).
    let mut lines: Vec<(bool, u32, u32, u32, Edge)> = vec![];
    for (vertical, name) in [
        (true, "sf:vertical-gridline-styles"),
        (false, "sf:horizontal-gridline-styles"),
    ] {
        for run in grid
            .child(name)
            .into_iter()
            .flat_map(|g| g.all("sf:style-run"))
            .take(1 << 16)
        {
            let Some(line) = num(run, "sf:gridline-index").map(|v| v.max(0.0) as u32) else {
                continue;
            };
            for vs in run.all("sf:vector-style-ref").take(1 << 16) {
                let from = num(vs, "sf:start-index").unwrap_or(0.0).max(0.0) as u32;
                let to = num(vs, "sf:stop-index").unwrap_or(0.0).max(0.0) as u32;
                if let Some(e) = stroke_edge(doc, doc.deref(vs)) {
                    lines.push((vertical, line, from, to, e));
                }
            }
        }
    }
    if lines.is_empty() {
        let table_style = model.child("sf:tabular-style-ref").map(|n| doc.deref(n));
        let edge = |name: &str| -> Option<Edge> {
            let vs = table_style
                .and_then(|t| doc.prop(t, name))
                .and_then(|p| doc.value_of(p))?;
            stroke_edge(doc, vs).filter(|e| e.style.is_some())
        };
        let body = edge("sf:SFTDefaultBodyVectorStyleProperty");
        let border = edge("sf:SFTDefaultBorderVectorStyleProperty");
        let header_sep = edge("sf:SFTDefaultHeaderSeparatorVectorStyleProperty").or(body.clone());
        let footer_sep = edge("sf:SFTDefaultFooterSeparatorVectorStyleProperty").or(body.clone());
        let fr_start = d.rows.saturating_sub(d.footer_rows);
        for y in 0..=d.rows {
            let e = if y == 0 || y == d.rows {
                border.clone()
            } else if d.header_rows > 0 && y == d.header_rows {
                header_sep.clone()
            } else if d.footer_rows > 0 && y == fr_start {
                footer_sep.clone()
            } else {
                body.clone()
            };
            if let Some(e) = e {
                lines.push((false, y, 0, d.cols, e));
            }
        }
        for x in 0..=d.cols {
            let e = if x == 0 || x == d.cols {
                border.clone()
            } else if d.header_cols > 0 && x == d.header_cols {
                header_sep.clone()
            } else {
                body.clone()
            };
            if let Some(e) = e {
                lines.push((true, x, 0, d.rows, e));
            }
        }
    }
    // Runs may repeat: past a few passes over the table, the rest is
    // dropped.
    let mut work = 4 * (u64::from(d.rows) + 1) * (u64::from(d.cols) + 1);
    for (vertical, line, from, to, e) in lines {
        let to = to.min(if vertical { d.rows } else { d.cols });
        let Some(left) = work.checked_sub(u64::from(to.saturating_sub(from))) else {
            break;
        };
        work = left;
        for k in from..to {
            // The cell after the line and the one before it.
            let (after, before, sa, sb) = if vertical {
                ((k, line), line.checked_sub(1).map(|c| (k, c)), 3, 1)
            } else {
                ((line, k), line.checked_sub(1).map(|r| (r, k)), 0, 2)
            };
            for (cell, side) in [(Some(after), sa), (before, sb)] {
                let Some((r, c)) = cell else { continue };
                if r >= d.rows || c >= d.cols {
                    continue;
                }
                if !out.contains_key(&(r, c)) {
                    budget.alloc(64)?;
                }
                out.entry((r, c)).or_default()[side] = e.style.is_some().then(|| e.clone());
            }
        }
    }
    out.retain(|_, v| v.iter().any(Option::is_some));
    Ok(out)
}

#[cfg(test)]
mod tests;
