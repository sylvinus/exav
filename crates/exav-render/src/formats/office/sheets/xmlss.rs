//! Excel 2002 and 2003 XML Spreadsheet ("SpreadsheetML", namespace
//! `urn:schemas-microsoft-com:office:spreadsheet`), after Microsoft's XML
//! Spreadsheet Reference (Office XP, 2001): worksheets, their tables,
//! columns, rows and cells (`ss:Index` gaps, `ss:Span`), typed values and
//! rich text, R1C1 formulas, styles and their parents, merges, sizes,
//! names, links, comments, filters and the Excel worksheet options.

use crate::formats::office::common::xml::{self as dom, Node};
use crate::formats::office::sheets::css;
use crate::formats::office::sheets::error::{Error, Result};
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use crate::formats::office::sheets::r1c1;
use std::collections::HashMap;

const MAX_CHAIN: usize = 32;

/// An attribute in the SpreadsheetML namespace, or without one: other
/// writers than Excel leave the prefix out.
fn attr<'a>(n: &'a Node, name: &str) -> Option<&'a str> {
    n.attrs
        .iter()
        .find(|(k, _)| {
            k.strip_prefix("ss:")
                .or_else(|| k.strip_prefix("x:"))
                .unwrap_or(k)
                == name
        })
        .map(|(_, v)| v.as_str())
}

fn flag(n: &Node, name: &str) -> Option<bool> {
    attr(n, name).map(|v| matches!(v.trim(), "1" | "true" | "True" | "TRUE"))
}

fn num(n: &Node, name: &str) -> Option<f64> {
    attr(n, name)
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite())
}

/// A 1-based index attribute as 0-based, within `max`.
fn index(n: &Node, name: &str, max: u32) -> Option<u32> {
    attr(n, name)
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&v| v >= 1 && v - 1 <= u64::from(max))
        .map(|v| (v - 1) as u32)
}

fn count(n: &Node, name: &str) -> u32 {
    attr(n, name)
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// An element, by its local name, in the SpreadsheetML or Excel
/// namespace or none.
fn is(n: &Node, local: &str) -> bool {
    n.name
        .strip_prefix("ss:")
        .or_else(|| n.name.strip_prefix("x:"))
        .unwrap_or(&n.name)
        == local
}

fn children<'a>(n: &'a Node, local: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
    n.nodes().filter(move |c| is(c, local))
}

fn child<'a>(n: &'a Node, local: &str) -> Option<&'a Node> {
    n.nodes().find(|c| is(c, local))
}

/// The named number formats of the reference ("the same as the HTML
/// number formats").
pub(crate) fn named_format(f: &str) -> Option<&'static str> {
    Some(match f.trim().to_ascii_lowercase().as_str() {
        "general" | "general number" => "General",
        "general date" => "m/d/yyyy h:mm",
        "long date" => "dddd, mmmm dd, yyyy",
        "medium date" => "dd-mmm-yy",
        "short date" => "m/d/yyyy",
        "long time" => "h:mm:ss AM/PM",
        "medium time" => "h:mm AM/PM",
        "short time" => "h:mm",
        "currency" => "\"$\"#,##0.00_);[Red]\\(\"$\"#,##0.00\\)",
        "euro currency" => "[$€-2]\\ #,##0.00_);[Red]\\([$€-2]\\ #,##0.00\\)",
        "fixed" => "0.00",
        "standard" => "#,##0.00",
        "percent" => "0.00%",
        "scientific" => "0.00E+00",
        "yes/no" => "\"Yes\";\"Yes\";\"No\"",
        "true/false" => "\"True\";\"True\";\"False\"",
        "on/off" => "\"On\";\"On\";\"Off\"",
        _ => return None,
    })
}

/// `ss:LineStyle` and `ss:Weight` (0 hairline, 1 thin, 2 medium, 3 thick)
/// as an XLSX border style.
fn line(style: &str, weight: f64) -> Option<&'static str> {
    let w = weight.round() as i64;
    Some(match style {
        "Continuous" => match w {
            i64::MIN..=0 => "hair",
            1 => "thin",
            2 => "medium",
            _ => "thick",
        },
        "Dash" if w >= 2 => "mediumDashed",
        "Dash" => "dashed",
        "Dot" => "dotted",
        "DashDot" if w >= 2 => "mediumDashDot",
        "DashDot" => "dashDot",
        "DashDotDot" if w >= 2 => "mediumDashDotDot",
        "DashDotDot" => "dashDotDot",
        "SlantDashDot" => "slantDashDot",
        "Double" => "double",
        _ => return None,
    })
}

fn rgb(s: Option<&str>) -> Option<Option<Rgb>> {
    css::color(s?)
}

/// `ss:Pattern` as an XLSX patternType.
fn pattern(p: &str) -> Option<&'static str> {
    Some(match p {
        "Solid" => "solid",
        "Gray75" => "darkGray",
        "Gray50" => "mediumGray",
        "Gray25" => "lightGray",
        "Gray125" => "gray125",
        "Gray0625" => "gray0625",
        "HorzStripe" => "darkHorizontal",
        "VertStripe" => "darkVertical",
        "ReverseDiagStripe" => "darkUp",
        "DiagStripe" => "darkDown",
        "DiagCross" => "darkGrid",
        "ThickDiagCross" => "darkTrellis",
        "ThinHorzStripe" => "lightHorizontal",
        "ThinVertStripe" => "lightVertical",
        "ThinReverseDiagStripe" => "lightUp",
        "ThinDiagStripe" => "lightDown",
        "ThinHorzCross" => "lightGrid",
        "ThinDiagCross" => "lightTrellis",
        _ => return None,
    })
}

/// A style's properties applied over `st`: each attribute given overrides.
fn apply(st: &mut Style, s: &Node) {
    for p in s.nodes() {
        let name = p.name.strip_prefix("ss:").unwrap_or(&p.name);
        match name {
            "Alignment" => {
                if let Some(h) = attr(p, "Horizontal") {
                    st.align.horizontal = match h {
                        "Left" => Some("left"),
                        "Center" => Some("center"),
                        "Right" => Some("right"),
                        "Fill" => Some("fill"),
                        "Justify" => Some("justify"),
                        "CenterAcrossSelection" => Some("centerContinuous"),
                        "Distributed" | "JustifyDistributed" => Some("distributed"),
                        _ => None,
                    };
                }
                if let Some(v) = attr(p, "Vertical") {
                    st.align.vertical = match v {
                        "Top" => Some("top"),
                        "Center" => Some("center"),
                        "Justify" => Some("justify"),
                        "Distributed" | "JustifyDistributed" => Some("distributed"),
                        _ => None,
                    };
                }
                if let Some(w) = flag(p, "WrapText") {
                    st.align.wrap = w;
                }
                if let Some(s) = flag(p, "ShrinkToFit") {
                    st.align.shrink = s;
                }
                if let Some(i) = num(p, "Indent") {
                    st.align.indent = i.clamp(0.0, 250.0) as u8;
                }
                if let Some(r) = num(p, "Rotate") {
                    let r = r.round().clamp(-90.0, 90.0) as i32;
                    st.align.rotation = if r < 0 { (90 - r) as u8 } else { r as u8 };
                }
                if flag(p, "VerticalText") == Some(true) {
                    st.align.rotation = 255;
                }
                if let Some(o) = attr(p, "ReadingOrder") {
                    st.align.reading_order = match o {
                        "LeftToRight" => 1,
                        "RightToLeft" => 2,
                        _ => 0,
                    };
                }
            }
            "Borders" => {
                for b in children(p, "Border") {
                    let style = line(
                        attr(b, "LineStyle").unwrap_or("None"),
                        num(b, "Weight").unwrap_or(0.0),
                    );
                    let edge = Edge {
                        style,
                        color: style
                            .and(rgb(attr(b, "Color")).flatten())
                            .filter(|&c| c != 0),
                    };
                    match attr(b, "Position") {
                        Some("Left") => st.border.left = edge,
                        Some("Right") => st.border.right = edge,
                        Some("Top") => st.border.top = edge,
                        Some("Bottom") => st.border.bottom = edge,
                        Some("DiagonalLeft") => {
                            st.border.diag_down = edge.style.is_some();
                            st.border.diagonal = edge;
                        }
                        Some("DiagonalRight") => {
                            st.border.diag_up = edge.style.is_some();
                            st.border.diagonal = edge;
                        }
                        _ => {}
                    }
                }
            }
            "Font" => {
                let f = &mut st.font;
                if let Some(n) = attr(p, "FontName").filter(|n| !n.trim().is_empty()) {
                    f.name = n.trim().chars().take(64).collect();
                }
                if let Some(s) = num(p, "Size").filter(|s| *s > 0.0) {
                    f.size_centipt = (s * 100.0).round().clamp(100.0, 40_000.0) as u32;
                }
                if let Some(b) = flag(p, "Bold") {
                    f.bold = b;
                }
                if let Some(i) = flag(p, "Italic") {
                    f.italic = i;
                }
                if let Some(s) = flag(p, "StrikeThrough") {
                    f.strike = s;
                }
                if let Some(o) = flag(p, "Outline") {
                    f.outline = o;
                }
                if let Some(s) = flag(p, "Shadow") {
                    f.shadow = s;
                }
                if let Some(u) = attr(p, "Underline") {
                    f.underline = match u {
                        "Single" => Some("single"),
                        "Double" => Some("double"),
                        "SingleAccounting" => Some("singleAccounting"),
                        "DoubleAccounting" => Some("doubleAccounting"),
                        _ => None,
                    };
                }
                if let Some(v) = attr(p, "VerticalAlign") {
                    f.vert_align = match v {
                        "Superscript" => Some("superscript"),
                        "Subscript" => Some("subscript"),
                        _ => None,
                    };
                }
                if let Some(c) = rgb(attr(p, "Color")) {
                    f.color = c.filter(|&c| c != 0);
                }
            }
            "Interior" => {
                let color = rgb(attr(p, "Color")).flatten();
                let kind = attr(p, "Pattern").map(pattern);
                match kind {
                    Some(Some("solid")) => st.fill = color.map_or(Fill::NONE, Fill::solid),
                    Some(Some(k)) => {
                        st.fill = Fill {
                            pattern: k,
                            fg: rgb(attr(p, "PatternColor")).flatten().or(Some(0)),
                            bg: color,
                        };
                    }
                    Some(None) => st.fill = Fill::NONE,
                    // A colour without a pattern: Excel reads a solid fill.
                    None if let Some(c) = color => st.fill = Fill::solid(c),
                    None => {}
                }
            }
            "NumberFormat" => {
                if let Some(f) = attr(p, "Format") {
                    st.numfmt = named_format(f)
                        .map_or_else(|| f.chars().take(255).collect(), str::to_string);
                }
            }
            "Protection" => {
                if let Some(l) = flag(p, "Protected") {
                    st.locked = l;
                }
                if let Some(h) = flag(p, "HideFormula") {
                    st.hidden = h;
                }
            }
            _ => {}
        }
    }
}

/// The workbook's styles, resolved through their parents (`Default` when
/// none is named).
fn styles(root: &Node, base: &Style) -> HashMap<String, Style> {
    let defs: HashMap<&str, &Node> = child(root, "Styles")
        .into_iter()
        .flat_map(|s| children(s, "Style"))
        .filter_map(|s| Some((attr(s, "ID")?, s)))
        .take(1 << 16)
        .collect();
    let mut out: HashMap<String, Style> = HashMap::new();
    for &id in defs.keys() {
        // The chain from the style up, then applied from the top down.
        let mut chain = vec![];
        let mut cur = Some(id);
        while let Some(c) = cur {
            let Some(n) = defs.get(c) else { break };
            if chain.len() >= MAX_CHAIN || chain.contains(&c) {
                break;
            }
            chain.push(c);
            cur = attr(n, "Parent").or((c != "Default").then_some("Default"));
        }
        let mut st = base.clone();
        for c in chain.iter().rev() {
            apply(&mut st, defs[c]);
        }
        out.insert(id.to_string(), st);
    }
    out
}

/// An xsd:dateTime as a 1900 date system serial: Excel's times sit on
/// 1899-12-31, day 0, and its serials count a 29 February 1900.
fn serial(s: &str) -> Option<f64> {
    let v = crate::formats::office::sheets::ods::parse_date(s.trim(), (1899, 12, 30))?;
    Some(if v < 61.0 { v - 1.0 } else { v })
}

/// A cell's rich text: the HTML formatting tags Excel writes in `ss:Data`.
fn rich(data: &Node, base: &Font) -> Option<Value> {
    data.nodes().next()?;
    fn walk(n: &Node, font: &Font, out: &mut Vec<Run>, depth: u32) {
        for c in &n.children {
            match c {
                dom::Child::Text(t) => {
                    // The indentation of a pretty-printed document between
                    // the tags is not text.
                    let lead = t.len() - t.trim_start().len();
                    let t = if t[..lead].contains('\n') {
                        &t[lead..]
                    } else {
                        t.as_str()
                    };
                    let end = t.trim_end().len();
                    let t = if t[end..].contains('\n') {
                        &t[..end]
                    } else {
                        t
                    };
                    if t.is_empty() {
                        continue;
                    }
                    match out.last_mut() {
                        Some(last) if last.font.as_ref() == Some(font) => last.text.push_str(t),
                        _ => out.push(Run {
                            text: t.to_string(),
                            font: Some(font.clone()),
                        }),
                    }
                }
                dom::Child::Node(x) if depth < 32 => {
                    let mut f = font.clone();
                    match x.name.rsplit(':').next().unwrap_or("") {
                        "B" => f.bold = true,
                        "I" => f.italic = true,
                        "U" => {
                            f.underline =
                                Some(if attr(x, "Style").is_some_and(|s| s.contains("double")) {
                                    "double"
                                } else {
                                    "single"
                                })
                        }
                        "S" => f.strike = true,
                        "Sub" => f.vert_align = Some("subscript"),
                        "Sup" => f.vert_align = Some("superscript"),
                        "Font" => {
                            for (k, v) in &x.attrs {
                                match k.rsplit(':').next().unwrap_or("") {
                                    "Color" => {
                                        if let Some(c) = css::color(v) {
                                            f.color = c.filter(|&c| c != 0);
                                        }
                                    }
                                    "Face" => f.name = v.chars().take(64).collect(),
                                    "Size" => {
                                        if let Ok(s) = v.trim().parse::<f64>()
                                            && s.is_finite()
                                            && s > 0.0
                                        {
                                            f.size_centipt =
                                                (s * 100.0).round().clamp(100.0, 40_000.0) as u32;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                    walk(x, &f, out, depth + 1);
                }
                dom::Child::Node(_) => {}
            }
            if out.len() > 4096 {
                return;
            }
        }
    }
    let mut out = vec![];
    walk(data, base, &mut out, 0);
    out.retain(|r| !r.text.is_empty());
    Some(if out.len() <= 1 {
        Value::text(out.into_iter().map(|r| r.text).collect::<String>())
    } else {
        Value::Rich(out.into())
    })
}

/// Text of a node and its descendants.
fn text(n: &Node) -> String {
    fn all(n: &Node, out: &mut String, depth: u32) {
        for c in &n.children {
            match c {
                dom::Child::Text(t) => out.push_str(t),
                dom::Child::Node(x) if depth < 32 => all(x, out, depth + 1),
                dom::Child::Node(_) => {}
            }
            if out.len() > 1 << 20 {
                return;
            }
        }
    }
    let mut s = String::new();
    all(n, &mut s, 0);
    s
}

/// A width in points, at 96 dpi, as the XLSX width of a column whose font
/// has digits `digit` pixels wide (ECMA-376 part 1, 18.3.1.13): the
/// characters Excel shows, 5 pixels of padding off and to the hundredth,
/// then the stored width, padding back in and to 1/256.
pub(crate) fn width_chars(pt: f64, digit: f64) -> f64 {
    let px = (pt * 96.0 / 72.0).round();
    if px <= 0.0 {
        return 0.0;
    }
    let chars = (((px - 5.0) / digit * 100.0 + 0.5).trunc() / 100.0).max(0.0);
    (((chars * digit + 5.0) / digit * 256.0).trunc() / 256.0).clamp(0.0, 255.0)
}

/// An R1C1 range (`R1C1:R10C3`, `R2`, `C1:C3`) as a range, relative to A1.
fn range_r1c1(s: &str) -> Option<Range> {
    let a1 = r1c1::to_a1(s, (0, 0))?;
    let a1 = a1.rsplit('!').next()?.replace('$', "");
    let (a, b) = a1.split_once(':').unwrap_or((&a1, &a1));
    let (r1, c1) = parse_cell(a)?;
    let (r2, c2) = parse_cell(b)?;
    Some(Range {
        r1: r1.min(r2),
        c1: c1.min(c2),
        r2: r1.max(r2),
        c2: c1.max(c2),
    })
}

pub(crate) fn read(bytes: &[u8], budget: &mut Budget) -> Result<Workbook> {
    let xml = crate::formats::office::sheets::textenc::xml_utf8(bytes);
    let root = dom::parse(&xml, &mut budget.tree())?;
    if root.name != "ss:Workbook" {
        return Err(Error::NotFormat(format!(
            "not an XML Spreadsheet: {}",
            root.name
        )));
    }
    let base = Style {
        font: Font {
            name: "Arial".into(),
            size_centipt: 1000,
            ..Font::default()
        },
        ..Style::default()
    };
    let styles = styles(&root, &base);
    let default = styles.get("Default").cloned().unwrap_or(base);
    let digit = (crate::formats::office::sheets::fonts::digit_twips(
        &default.font.name,
        default.font.size_pt(),
    ) / 15.0)
        .round()
        .max(1.0);
    let mut wb = Workbook::new(default.clone());
    let mut ids: HashMap<String, u32> = HashMap::new();
    let mut style_id = |wb: &mut Workbook, id: Option<&str>| -> Option<u32> {
        let id = id?;
        if let Some(&s) = ids.get(id) {
            return Some(s);
        }
        let s = wb.styles.add(styles.get(id)?.clone());
        ids.insert(id.to_string(), s);
        Some(s)
    };

    let sheets: Vec<&Node> = children(&root, "Worksheet").collect();
    if sheets.is_empty() {
        return Err(Error::Unsupported(
            "an XML Spreadsheet without worksheets".into(),
        ));
    }
    if sheets.len() > budget.limits.max_sheets as usize {
        return Err(Error::TooLarge("sheets"));
    }
    let names = crate::formats::office::sheets::xlsx::sheet_names(
        sheets
            .iter()
            .enumerate()
            .map(|(i, s)| attr(s, "Name").unwrap_or(if i == 0 { "Sheet1" } else { "Sheet" })),
    );
    let mut bad_formulas = 0usize;
    let mut skipped: Vec<&str> = vec![];
    for (k, ws) in sheets.iter().enumerate() {
        let mut sheet = Sheet::new(names[k].clone());
        if flag(ws, "RightToLeft") == Some(true) {
            sheet.rtl = true;
        }
        if let Some(t) = child(ws, "Table") {
            read_table(
                t,
                &mut sheet,
                &mut wb,
                &mut style_id,
                digit,
                budget,
                &mut bad_formulas,
            )?;
        }
        if let Some(o) = child(ws, "WorksheetOptions")
            .filter(|o| o.name.starts_with("x:") || !o.name.contains(':'))
        {
            options(o, &mut sheet, &mut wb, k);
        }
        if let Some(f) = child(ws, "AutoFilter")
            .and_then(|f| attr(f, "Range"))
            .and_then(range_r1c1)
        {
            sheet.autofilter = Some(f);
        }
        for (what, el) in [
            ("conditional formats", "ConditionalFormatting"),
            ("validations", "DataValidation"),
            ("pivot tables", "PivotTable"),
        ] {
            if child(ws, el).is_some() && !skipped.contains(&what) {
                skipped.push(what);
            }
        }
        wb.sheets.push(sheet);
    }
    // Names, the workbook's then each sheet's.
    let scopes = std::iter::once((None, child(&root, "Names"))).chain(
        sheets
            .iter()
            .enumerate()
            .map(|(i, s)| (Some(i), child(s, "Names"))),
    );
    for (scope, names) in scopes {
        for n in names
            .into_iter()
            .flat_map(|n| children(n, "NamedRange"))
            .take(1 << 14)
        {
            let (Some(name), Some(refers)) = (attr(n, "Name"), attr(n, "RefersTo")) else {
                continue;
            };
            let name = match name {
                "_FilterDatabase" => continue,
                "Print_Area" | "Print_Titles" | "Criteria" | "Extract" | "Consolidate_Area"
                | "Sheet_Title" => format!("_xlnm.{name}"),
                n => n.to_string(),
            };
            let Some(formula) = r1c1::to_a1(refers, (0, 0)) else {
                continue;
            };
            // A print area or titles of a sheet name its cells with the sheet in
            // XLSX; some writers leave the sheet out (`=R1`), which readers refuse.
            let formula = match scope.and_then(|i| wb.sheets.get(i)) {
                Some(sheet) if name.starts_with("_xlnm.") && !formula.contains('!') => {
                    format!(
                        "{}!{formula}",
                        super::xls::formula::quote_sheet(&sheet.name)
                    )
                }
                _ => formula,
            };
            wb.names.push(DefinedName {
                name,
                sheet: scope,
                formula,
                hidden: flag(n, "Hidden") == Some(true),
            });
        }
    }
    if bad_formulas > 0 {
        wb.warn(format!(
            "{bad_formulas} formulas could not be read and were left as their values"
        ));
    }
    for s in skipped {
        wb.warn(format!("{s} are not converted"));
    }
    Ok(wb)
}

fn read_table(
    t: &Node,
    sheet: &mut Sheet,
    wb: &mut Workbook,
    style_id: &mut impl FnMut(&mut Workbook, Option<&str>) -> Option<u32>,
    digit: f64,
    budget: &mut Budget,
    bad_formulas: &mut usize,
) -> Result<()> {
    if let Some(w) = num(t, "DefaultColumnWidth").filter(|w| *w >= 0.0) {
        sheet.default_col_width = Some(width_chars(w, digit));
    }
    if let Some(h) = num(t, "DefaultRowHeight").filter(|h| *h >= 0.0) {
        sheet.default_row_height = h.min(409.0);
    }
    let table_style = style_id(wb, attr(t, "StyleID"));
    // Columns.
    let mut next = 0u32;
    let mut col_styles: Vec<(u32, u32, u32)> = vec![];
    for c in children(t, "Column").take(MAX_COL as usize + 1) {
        let first = index(c, "Index", MAX_COL).unwrap_or(next);
        let last = first.saturating_add(count(c, "Span")).min(MAX_COL);
        next = last.saturating_add(1);
        let style = style_id(wb, attr(c, "StyleID"));
        let width = num(c, "Width")
            .filter(|w| *w >= 0.0)
            .map(|w| width_chars(w, digit));
        let hidden = flag(c, "Hidden") == Some(true);
        if width.is_some() || hidden || style.is_some() {
            sheet.cols.push(ColInfo {
                first,
                last,
                width,
                hidden,
                style,
                outline: 0,
            });
        }
        if let Some(s) = style {
            col_styles.push((first, last, s));
        }
        if next > MAX_COL {
            break;
        }
    }
    // Rows and cells.
    let mut r_next = 0u32;
    for row in children(t, "Row") {
        let Some(r) = index(row, "Index", MAX_ROW).or((r_next <= MAX_ROW).then_some(r_next)) else {
            break;
        };
        let span = count(row, "Span");
        r_next = r.saturating_add(span).saturating_add(1);
        let row_style = style_id(wb, attr(row, "StyleID"));
        let height = num(row, "Height")
            .filter(|h| *h >= 0.0)
            .map(|h| h.min(409.0));
        let hidden = flag(row, "Hidden") == Some(true);
        if height.is_some() || hidden || row_style.is_some() {
            let last = r.saturating_add(span).min(MAX_ROW).min(r + 65_536);
            budget.alloc(64 * u64::from(last - r + 1))?;
            for rr in r..=last {
                sheet.rows.insert(
                    rr,
                    RowInfo {
                        height,
                        custom_height: height.is_some(),
                        hidden,
                        style: row_style,
                        outline: 0,
                    },
                );
            }
        }
        let mut c_next = 0u32;
        for cell in children(row, "Cell") {
            let Some(c) = index(cell, "Index", MAX_COL).or((c_next <= MAX_COL).then_some(c_next))
            else {
                break;
            };
            let across = count(cell, "MergeAcross").min(MAX_COL - c);
            let down = count(cell, "MergeDown").min(MAX_ROW - r);
            c_next = c.saturating_add(across).saturating_add(1);
            if across > 0 || down > 0 {
                sheet.merges.push(Range {
                    r1: r,
                    c1: c,
                    r2: r + down,
                    c2: c + across,
                });
            }
            let style = style_id(wb, attr(cell, "StyleID"))
                .or(row_style)
                .or_else(|| {
                    col_styles
                        .iter()
                        .find(|s| s.0 <= c && c <= s.1)
                        .map(|s| s.2)
                })
                .or(table_style)
                .unwrap_or(0);
            let font = wb.styles.get(style).font.clone();
            let data = child(cell, "Data");
            let value = match data {
                Some(d) => match attr(d, "Type").unwrap_or("String") {
                    "Number" => text(d)
                        .trim()
                        .parse::<f64>()
                        .ok()
                        .filter(|v| v.is_finite())
                        .map_or(Value::Empty, Value::Number),
                    "DateTime" => {
                        serial(&text(d)).map_or_else(|| Value::text(text(d)), Value::Number)
                    }
                    "Boolean" => {
                        Value::Bool(matches!(text(d).trim(), "1" | "TRUE" | "True" | "true"))
                    }
                    "Error" => CellError::parse(&text(d))
                        .map_or(Value::Error(CellError::Value), Value::Error),
                    _ => {
                        let v = rich(d, &font).unwrap_or_else(|| Value::text(text(d)));
                        match v {
                            Value::Text(t) if t.is_empty() => Value::Empty,
                            Value::Text(t) if flag(d, "Ticked") == Some(true) => {
                                Value::text(format!("'{t}"))
                            }
                            v => v,
                        }
                    }
                },
                None => Value::Empty,
            };
            let mut formula = None;
            if let Some(f) = attr(cell, "Formula") {
                match r1c1::to_a1(f, (r, c)) {
                    Some(a1) => formula = Some(a1.into_boxed_str()),
                    None => *bad_formulas += 1,
                }
            }
            if let (Some(a), true) = (attr(cell, "ArrayRange"), formula.is_some())
                && let Some(a1) = r1c1::to_a1(a, (r, c))
            {
                let a1 = a1.replace('$', "");
                let (x, y) = a1.split_once(':').unwrap_or((&a1, &a1));
                if let (Some((r1, c1)), Some((r2, c2))) = (parse_cell(x), parse_cell(y)) {
                    sheet.arrays.insert(
                        (r, c),
                        Range {
                            r1: r1.min(r2),
                            c1: c1.min(c2),
                            r2: r1.max(r2),
                            c2: c1.max(c2),
                        },
                    );
                }
            }
            if let Some(href) = attr(cell, "HRef") {
                let link = Hyperlink {
                    range: Range::cell(r, c),
                    url: (!href.starts_with('#') && safe_url(href)).then(|| href.to_string()),
                    location: href.strip_prefix('#').map(str::to_string),
                    tooltip: attr(cell, "HRefScreenTip").map(str::to_string),
                    display: None,
                };
                if link.url.is_some() || link.location.is_some() {
                    sheet.hyperlinks.push(link);
                }
            }
            if let Some(note) = child(cell, "Comment") {
                let body = child(note, "Data").map(text).unwrap_or_default();
                sheet.comments.push(Comment {
                    row: r,
                    col: c,
                    author: attr(note, "Author").unwrap_or("").to_string(),
                    text: body.chars().take(32_767).collect(),
                    visible: flag(note, "ShowAlways") == Some(true),
                });
            }
            if matches!(value, Value::Empty) && formula.is_none() && style == 0 {
                continue;
            }
            budget.cell(value.text_len() + formula.as_ref().map_or(0, |f| f.len()))?;
            sheet.cells.insert(
                (r, c),
                Cell {
                    value,
                    formula,
                    style,
                },
            );
            if c_next > MAX_COL {
                break;
            }
        }
        if r_next > MAX_ROW {
            break;
        }
    }
    Ok(())
}

/// Excel's worksheet options: panes, grid lines, visibility, zoom.
fn options(o: &Node, sheet: &mut Sheet, wb: &mut Workbook, k: usize) {
    let int = |name: &str| child(o, name).and_then(|n| n.own_text().trim().parse::<u32>().ok());
    if child(o, "FreezePanes").is_some() {
        let rows = int("SplitHorizontal").unwrap_or(0).min(MAX_ROW);
        let cols = int("SplitVertical").unwrap_or(0).min(MAX_COL);
        if rows > 0 || cols > 0 {
            sheet.freeze = Some((rows, cols));
        }
    }
    if child(o, "DoNotDisplayGridlines").is_some() {
        sheet.show_grid = false;
    }
    if child(o, "DoNotDisplayZeros").is_some() {
        sheet.show_zeros = false;
    }
    if child(o, "DoNotDisplayHeadings").is_some() {
        sheet.show_headers = false;
    }
    if child(o, "DisplayRightToLeft").is_some() {
        sheet.rtl = true;
    }
    match child(o, "Visible").map(|v| v.own_text()) {
        Some(v) if v.trim() == "SheetHidden" => sheet.state = SheetState::Hidden,
        Some(v) if v.trim() == "SheetVeryHidden" => sheet.state = SheetState::VeryHidden,
        _ => {}
    }
    if let Some(z) = int("Zoom").filter(|z| (10..=400).contains(z)) {
        sheet.zoom = z;
    }
    if child(o, "Selected").is_some() {
        wb.active = k;
    }
}

#[cfg(test)]
mod tests;
