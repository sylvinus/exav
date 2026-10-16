//! A table:table to a sheet: columns, rows, cells, merges, notes, links,
//! validation, conditional formats and drawings.

use super::dom::{Child, Node};
use super::styles::Props;
use super::{cf, draw, paragraphs, parse_date, parse_duration, parse_range_addr, text_of, Doc};
use crate::formats::office::sheets::error::Result;
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use std::collections::HashMap;

/// Empty rows repeated more than this are not read one by one.
const BIG_BLOCK: u32 = 1024;

fn repeat(n: &Node, k: &str) -> u32 {
    n.attr(k)
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(1)
        .max(1)
}

/// Column width in points to XLSX characters of the default font's digit.
pub(crate) fn width_chars(pt: f64, digit_twips: f64) -> f64 {
    ((pt * 20.0).round() / digit_twips * 256.0).round() / 256.0
}

fn gather<'a>(n: &'a Node, leaf: &str, groups: &[&str], out: &mut Vec<&'a Node>, depth: u32) {
    for c in n.nodes() {
        if c.name == leaf {
            out.push(c);
        } else if depth < 32 && groups.contains(&c.name.as_str()) {
            gather(c, leaf, groups, out, depth + 1);
        }
    }
}

fn row_has_content(row: &Node) -> bool {
    row.nodes().any(|c| {
        c.attr("office:value-type").is_some()
            || c.attr("table:formula").is_some()
            || c.attr("table:number-columns-spanned").is_some()
            || c.attr("table:number-rows-spanned").is_some()
            || c.attr("table:content-validation-name").is_some()
            || c.nodes().any(|x| {
                x.name == "office:annotation"
                    || x.name.starts_with("draw:")
                    || (x.name == "text:p" && !x.children.is_empty())
            })
    })
}

/// Empty cells of a run that extends to the end of the sheet, styled.
struct Tail {
    c1: u32,
    c2: u32,
    style: Option<String>,
    from_row: u32,
}

pub(crate) fn read_table(
    t: &Node,
    doc: &mut Doc,
    wb: &mut Workbook,
    budget: &mut Budget,
    sheet: &mut Sheet,
    charts_out: &mut Vec<super::PendingChart>,
) -> Result<()> {
    // Columns: widths, styles and visibility.
    let f0 = wb.styles.get(0).font.clone();
    let digit = crate::formats::office::sheets::fonts::digit_twips(&f0.name, f0.size_pt());
    // A column without a style is 0.889 inch wide.
    sheet.default_col_width = Some(width_chars(64.0, digit));
    let mut cols: Vec<&Node> = vec![];
    gather(
        t,
        "table:table-column",
        &[
            "table:table-column-group",
            "table:table-header-columns",
            "table:table-columns",
        ],
        &mut cols,
        0,
    );
    let mut col = 0u32;
    let mut col_style: Vec<(u32, u32, Option<String>)> = vec![];
    for c in cols {
        let n = repeat(c, "table:number-columns-repeated");
        let first = col;
        col = col.saturating_add(n);
        if first > MAX_COL {
            break;
        }
        let last = col.saturating_sub(1).min(MAX_COL);
        let mut info = ColInfo {
            first,
            last,
            ..Default::default()
        };
        if let Some(w) = c
            .attr("table:style-name")
            .and_then(|sn| doc.st.other("table-column", sn))
            .and_then(|cs| cs.child("style:table-column-properties"))
            .and_then(|p| p.attr("style:column-width"))
            .and_then(super::styles::parse_len_pt)
        {
            info.width = Some(width_chars(w.clamp(0.0, 4000.0), digit));
        }
        info.hidden = matches!(c.attr("table:visibility"), Some("collapse" | "filter"));
        let ds = c.attr("table:default-cell-style-name").map(str::to_string);
        if let Some(d) = ds.as_deref().filter(|d| *d != "Default") {
            info.style = Some(doc.sid(wb, Some(d)));
        }
        col_style.push((first, last, ds));
        sheet.cols.push(info);
    }
    let col_style_name = |c: u32| -> Option<&str> { style_at(&col_style, c) };

    let mut rows: Vec<&Node> = vec![];
    gather(
        t,
        "table:table-row",
        &[
            "table:table-row-group",
            "table:table-header-rows",
            "table:table-rows",
        ],
        &mut rows,
        0,
    );

    // Row heights: the most common one is the default.
    let row_info = |doc: &Doc, row: &Node| -> RowInfo {
        let mut info = RowInfo::default();
        if let Some(p) = row
            .attr("table:style-name")
            .and_then(|sn| doc.st.other("table-row", sn))
            .and_then(|rs| rs.child("style:table-row-properties"))
        {
            if let Some(h) = p
                .attr("style:row-height")
                .and_then(super::styles::parse_len_pt)
            {
                // Heights are whole twips.
                info.height = Some(((h * 20.0).round() / 20.0).clamp(0.0, 409.5));
            }
            info.custom_height = p.attr("style:use-optimal-row-height") != Some("true");
        }
        info.hidden = matches!(row.attr("table:visibility"), Some("collapse" | "filter"));
        info
    };
    let mut heights: HashMap<u64, u64> = HashMap::new();
    {
        let mut r = 0u64;
        for row in &rows {
            let n = u64::from(repeat(row, "table:number-rows-repeated"));
            let rep = n.min(u64::from(MAX_ROW) + 1 - r.min(u64::from(MAX_ROW) + 1));
            if let Some(h) = row_info(doc, row).height {
                *heights.entry((h * 100.0).round() as u64).or_default() += rep;
            }
            r = r.saturating_add(n);
        }
    }
    if let Some((h, _)) = heights
        .iter()
        .max_by_key(|e| (*e.1, std::cmp::Reverse(*e.0)))
    {
        sheet.default_row_height = *h as f64 / 100.0;
    }
    let default_h = sheet.default_row_height;

    // The rows after the last one with content, when they reach the end of
    // the sheet: their look becomes the sheet's or the columns' default
    // instead of being written row by row.
    let tail_start = rows
        .iter()
        .rposition(|r| row_has_content(r))
        .map_or(0, |i| i + 1);
    let tail_rows: u64 = rows[tail_start..]
        .iter()
        .map(|r| u64::from(repeat(r, "table:number-rows-repeated")))
        .sum();
    let head_rows: u64 = rows[..tail_start]
        .iter()
        .map(|r| u64::from(repeat(r, "table:number-rows-repeated")))
        .sum();
    let has_tail = tail_rows > u64::from(BIG_BLOCK)
        && head_rows + tail_rows + 4 * u64::from(BIG_BLOCK) > u64::from(MAX_ROW);
    let last_big = (tail_start..rows.len())
        .rev()
        .find(|&i| repeat(rows[i], "table:number-rows-repeated") > BIG_BLOCK);
    // Rows hidden or resized to the end: the longest run of empty rows at
    // the end that are all alike.
    let mut row_tail_start = rows.len();
    if let Some(last) = rows.last().map(|r| row_info(doc, r)) {
        while row_tail_start > tail_start && row_info(doc, rows[row_tail_start - 1]) == last {
            row_tail_start -= 1;
        }
    }
    let row_tail_rows: u64 = rows[row_tail_start..]
        .iter()
        .map(|r| u64::from(repeat(r, "table:number-rows-repeated")))
        .sum();
    let all_rows = head_rows + tail_rows;
    // The rows the document does not list after it, when there are few,
    // are written as rows of the old default.
    let after_tail = (u64::from(MAX_ROW) + 1).saturating_sub(all_rows);
    // The rows above it are then written one by one: worth it while they
    // are fewer than those it saves.
    let rows_above = all_rows.saturating_sub(row_tail_rows);
    let uniform_tail = row_tail_rows > u64::from(BIG_BLOCK)
        && after_tail <= 4 * u64::from(BIG_BLOCK)
        && rows_above < row_tail_rows.min(65_536);
    // What an empty cell shows: its fill and borders.
    let visible = |doc: &mut Doc, wb: &mut Workbook, name: Option<&str>| -> (Fill, Border) {
        let id = doc.sid(wb, name);
        let s = wb.styles.get(id);
        (s.fill.clone(), s.border.clone())
    };
    let mut r = 0u32;
    let mut anchored: Vec<(u32, u32, &Node)> = vec![];
    let mut tails: Vec<Tail> = vec![];
    let mut row_tail: Option<(u32, RowInfo)> = None;
    let mut skipped_format = false;
    for (idx, row) in rows.iter().enumerate() {
        if r > MAX_ROW {
            break;
        }
        let n = repeat(row, "table:number-rows-repeated");
        let rep = n.min(MAX_ROW - r + 1);
        let content = row_has_content(row);
        let big_empty = !content && rep > BIG_BLOCK;
        // Only the last large block becomes the columns' default; the rows
        // around it are read as rows.
        let trailing = has_tail && Some(idx) == last_big;
        let info = row_info(doc, row);
        let notable = info.hidden || info.height.is_some_and(|h| (h - default_h).abs() > 1e-9);
        if notable {
            if uniform_tail && idx >= row_tail_start {
                if row_tail.is_none() {
                    row_tail = Some((r, info.clone()));
                }
            } else if big_empty && !budget.room_for_cells(u64::from(rep)) {
                skipped_format = true;
            } else {
                budget.alloc(u64::from(rep) * 48)?;
                for k in 0..rep {
                    sheet.rows.insert(r + k, info.clone());
                }
            }
        }
        let row_default = row.attr("table:default-cell-style-name");
        let mut c = 0u32;
        for cell in row.nodes() {
            let is_cell = cell.name == "table:table-cell";
            if !is_cell && cell.name != "table:covered-table-cell" {
                continue;
            }
            let cn = repeat(cell, "table:number-columns-repeated");
            if c > MAX_COL {
                break;
            }
            let crep = cn.min(MAX_COL - c + 1);
            let own_style = cell.attr("table:style-name").or(row_default);
            let style_name = own_style.or_else(|| col_style_name(c));
            let parsed = if is_cell {
                parse_cell(cell, doc, style_name, budget)?
            } else {
                None
            };
            if let Some((value, formula)) = parsed {
                let s = doc.sid(wb, style_name);
                let extra = value.text_len() + formula.as_ref().map_or(0, |f| f.len());
                for k in 0..rep {
                    for j in 0..crep {
                        // Each column may have its own default style.
                        let (s, name) = if own_style.is_none() && j > 0 {
                            (doc.sid(wb, col_style_name(c + j)), col_style_name(c + j))
                        } else {
                            (s, style_name)
                        };
                        doc.note_maps(name, r + k, c + j);
                        sheet.cells.insert(
                            (r + k, c + j),
                            Cell {
                                value: value.clone(),
                                formula: formula.clone(),
                                style: s,
                            },
                        );
                        budget.cell(extra)?;
                    }
                }
            } else if let Some(name) = own_style {
                // An empty styled run: a cell where it shows otherwise than
                // its column would; to the last column, the row's style.
                let to_end = c.saturating_add(cn) > MAX_COL && c > 0;
                let look = visible(doc, wb, Some(name));
                if trailing {
                    if look != visible(doc, wb, col_style_name(c))
                        || look != visible(doc, wb, col_style_name(c + crep - 1))
                    {
                        tails.push(Tail {
                            c1: c,
                            c2: c + crep - 1,
                            style: Some(name.to_string()),
                            from_row: r,
                        });
                    }
                } else if to_end {
                    if look == (Fill::NONE, Border::default()) {
                        // Shows nothing.
                    } else if big_empty && !budget.room_for_cells(u64::from(rep)) {
                        skipped_format = true;
                    } else {
                        let id = doc.sid(wb, Some(name));
                        budget.alloc(u64::from(rep) * 48)?;
                        for k in 0..rep {
                            sheet
                                .rows
                                .entry(r + k)
                                .or_insert_with(|| RowInfo {
                                    height: info.height,
                                    custom_height: info.custom_height,
                                    ..Default::default()
                                })
                                .style = Some(id);
                        }
                    }
                } else {
                    let differ: Vec<u32> = (0..crep)
                        .filter(|&j| {
                            col_style_name(c + j) != Some(name)
                                && visible(doc, wb, col_style_name(c + j)) != look
                        })
                        .collect();
                    let need = differ.len() as u64 * u64::from(rep);
                    if need > 0 && big_empty && !budget.room_for_cells(need) {
                        skipped_format = true;
                    } else if need > 0 {
                        let s = doc.sid(wb, Some(name));
                        for k in 0..rep {
                            for &j in &differ {
                                sheet.cells.insert((r + k, c + j), Cell::styled(s));
                                doc.note_maps(Some(name), r + k, c + j);
                                budget.cell(0)?;
                            }
                        }
                    }
                }
            }
            if is_cell {
                first_copy(cell, doc, sheet, (r, c), rep, crep, &mut anchored);
            }
            c = c.saturating_add(cn);
        }
        r = r.saturating_add(n);
    }
    if skipped_format {
        wb.warn(format!(
            "{}: the formatting of large unused areas was left out",
            sheet.name
        ));
    }
    promote_tails(doc, wb, budget, sheet, tails, &col_style)?;
    if let Some((from, info)) = row_tail {
        // Rows from here to the end are hidden or of another height: the
        // sheet's default, and every row above keeps its own.
        budget.alloc((u64::from(from) + after_tail) * 48)?;
        // Written as rows of their own height, the default changing.
        let own = RowInfo {
            height: Some(default_h),
            custom_height: true,
            ..Default::default()
        };
        for k in (0..from).chain((all_rows.min(u64::from(MAX_ROW) + 1) as u32)..=MAX_ROW) {
            sheet.rows.entry(k).or_insert_with(|| own.clone());
        }
        if info.hidden {
            sheet.default_row_hidden = true;
        }
        if let Some(h) = info.height {
            sheet.default_row_height = h;
            sheet.default_row_custom = info.custom_height;
        }
    }
    // Every cell of a merged range has its first cell's style: the
    // application draws the range with that cell's attributes.
    for m in sheet.merges.clone() {
        if m.area() > 100_000 {
            continue;
        }
        // The first cell's style, written or its column's.
        let s = sheet
            .cells
            .get(&(m.r1, m.c1))
            .map(|c| c.style)
            .or_else(|| sheet.col_info(m.c1).and_then(|c| c.style))
            .unwrap_or(0);
        for rr in m.r1..=m.r2 {
            for cc in m.c1..=m.c2 {
                if let std::collections::btree_map::Entry::Vacant(e) = sheet.cells.entry((rr, cc)) {
                    e.insert(Cell::styled(s));
                    budget.cell(0)?;
                } else if let Some(x) = sheet.cells.get_mut(&(rr, cc)) {
                    x.style = s;
                }
            }
        }
    }
    cf::read_table_cfs(t, doc, wb, sheet);
    draw::read_drawings(t, doc, wb, budget, sheet, &anchored, charts_out)?;
    Ok(())
}

/// Columns whose empty cells keep a style to the end of the sheet take it
/// as their column style; the rows above keep what they showed.
/// The default cell style of column `c`.
fn style_at(cols: &[(u32, u32, Option<String>)], c: u32) -> Option<&str> {
    let i = cols.partition_point(|x| x.0 <= c);
    cols.get(i.wrapping_sub(1))
        .filter(|x| c <= x.1)
        .and_then(|x| x.2.as_deref())
}

fn promote_tails(
    doc: &mut Doc,
    wb: &mut Workbook,
    budget: &mut Budget,
    sheet: &mut Sheet,
    tails: Vec<Tail>,
    cols: &[(u32, u32, Option<String>)],
) -> Result<()> {
    let col_style_name = |c: u32| style_at(cols, c);
    for tail in tails {
        let ncols = u64::from(tail.c2 - tail.c1 + 1);
        let above = u64::from(tail.from_row);
        let used_cols: Vec<u32> = (tail.c1..=tail.c2)
            .filter(|&c| col_style_name(c) != tail.style.as_deref())
            .collect();
        if used_cols.is_empty() {
            continue;
        }
        let new = doc.sid(wb, tail.style.as_deref());
        // A run to the last column covers what no row reaches: columns past
        // the used ones keep their cells only where rows have some.
        let last_used = sheet.cells.keys().map(|k| k.1).max().unwrap_or(0).max(
            sheet
                .cols
                .iter()
                .map(|c| c.last)
                .filter(|&l| l < MAX_COL)
                .max()
                .unwrap_or(0),
        );
        let cols_needing_cells = used_cols
            .iter()
            .filter(|&&c| c <= last_used.saturating_add(1))
            .count() as u64;
        if !budget.room_for_cells(above * cols_needing_cells.min(ncols)) {
            wb.warn(format!(
                "{}: the formatting of large unused areas was left out",
                sheet.name
            ));
            continue;
        }
        for &c in &used_cols {
            let old = doc.sid(wb, col_style_name(c));
            if c <= last_used.saturating_add(1) {
                for r in 0..tail.from_row {
                    if let std::collections::btree_map::Entry::Vacant(e) = sheet.cells.entry((r, c))
                    {
                        e.insert(Cell::styled(old));
                        budget.cell(0)?;
                    }
                }
            }
        }
        set_col_style(sheet, &used_cols, new);
    }
    Ok(())
}

/// Sets the style of columns, splitting the column records they are in.
fn set_col_style(sheet: &mut Sheet, cols: &[u32], style: u32) {
    // Runs of consecutive columns.
    let mut runs: Vec<(u32, u32)> = vec![];
    for &c in cols {
        match runs.last_mut() {
            Some(l) if l.1 + 1 == c => l.1 = c,
            _ => runs.push((c, c)),
        }
    }
    for (a, b) in runs {
        let mut out: Vec<ColInfo> = vec![];
        let mut covered: Vec<(u32, u32)> = vec![];
        for ci in sheet.cols.drain(..) {
            if ci.last < a || ci.first > b {
                out.push(ci);
                continue;
            }
            if ci.first < a {
                out.push(ColInfo {
                    last: a - 1,
                    ..ci.clone()
                });
            }
            if ci.last > b {
                out.push(ColInfo {
                    first: b + 1,
                    ..ci.clone()
                });
            }
            let (f, l) = (ci.first.max(a), ci.last.min(b));
            covered.push((f, l));
            out.push(ColInfo {
                first: f,
                last: l,
                style: Some(style).filter(|&s| s != 0),
                ..ci
            });
        }
        // Columns no record described.
        covered.sort_unstable();
        let mut next = a;
        for (f, l) in covered {
            if f > next {
                out.push(ColInfo {
                    first: next,
                    last: f - 1,
                    style: Some(style).filter(|&s| s != 0),
                    ..Default::default()
                });
            }
            next = l.saturating_add(1);
        }
        if next <= b {
            out.push(ColInfo {
                first: next,
                last: b,
                style: Some(style).filter(|&s| s != 0),
                ..Default::default()
            });
        }
        out.sort_by_key(|c| c.first);
        sheet.cols = out;
    }
}

/// Merges, array ranges, notes, links, validation and drawings of a cell:
/// on its first copy only.
fn first_copy<'a>(
    cell: &'a Node,
    doc: &mut Doc,
    sheet: &mut Sheet,
    (r, c): (u32, u32),
    rep: u32,
    crep: u32,
    anchored: &mut Vec<(u32, u32, &'a Node)>,
) {
    let cs = repeat(cell, "table:number-columns-spanned");
    let rs = repeat(cell, "table:number-rows-spanned");
    if (cs > 1 || rs > 1) && sheet.merges.len() < 1 << 20 {
        if let Some(m) = (Range {
            r1: r,
            c1: c,
            r2: r.saturating_add(rs - 1),
            c2: c.saturating_add(cs - 1),
        })
        .clipped()
        {
            sheet.merges.push(m);
        }
    }
    let mc = cell
        .attr("table:number-matrix-columns-spanned")
        .and_then(|v| v.parse::<u32>().ok());
    let mr = cell
        .attr("table:number-matrix-rows-spanned")
        .and_then(|v| v.parse::<u32>().ok());
    if let (Some(mc), Some(mr)) = (mc, mr) {
        if mc > 0
            && mr > 0
            && sheet
                .cells
                .get(&(r, c))
                .is_some_and(|x| x.formula.is_some())
        {
            if let Some(a) = (Range {
                r1: r,
                c1: c,
                r2: r.saturating_add(mr - 1),
                c2: c.saturating_add(mc - 1),
            })
            .clipped()
            {
                sheet.arrays.insert((r, c), a);
            }
        }
    }
    if let Some(a) = cell.child("office:annotation") {
        let mut text = String::new();
        for (k, p) in a.all("text:p").enumerate() {
            if k > 0 {
                text.push('\n');
            }
            text_of(p, &mut text);
        }
        let author = a.child("dc:creator").map(|n| {
            let mut s = String::new();
            text_of(n, &mut s);
            s
        });
        if sheet.comments.len() < 1 << 16 {
            sheet.comments.push(Comment {
                row: r,
                col: c,
                author: author.unwrap_or_default(),
                text,
                visible: a.attr("office:display") == Some("true"),
            });
        }
    }
    if let Some(link) = find_link(cell, 0) {
        let (url, location) = match link.strip_prefix('#') {
            Some(l) => (None, Some(location_to_excel(l))),
            None => (Some(link.clone()).filter(|u| safe_url(u)), None),
        };
        if (url.is_some() || location.is_some()) && sheet.hyperlinks.len() < 1 << 16 {
            sheet.hyperlinks.push(Hyperlink {
                range: Range::cell(r, c),
                url,
                location,
                tooltip: None,
                display: None,
            });
        }
    }
    if let Some(vn) = cell.attr("table:content-validation-name") {
        if let Some(v) = doc.validations.get(vn) {
            let rng = Range {
                r1: r,
                c1: c,
                r2: r + rep - 1,
                c2: c + crep - 1,
            };
            match sheet.validations.iter_mut().find(|x| {
                x.prompt == v.prompt
                    && x.formula1 == v.formula1
                    && x.kind == v.kind
                    && x.operator == v.operator
                    && x.formula2 == v.formula2
                    && x.error == v.error
            }) {
                Some(existing) => {
                    if existing.ranges.len() < 1024 {
                        existing.ranges.push(rng);
                    }
                }
                None => {
                    if sheet.validations.len() < 1 << 12 {
                        let mut v = v.clone();
                        v.ranges = vec![rng];
                        sheet.validations.push(v);
                    }
                }
            }
        }
    }
    for f in cell.nodes() {
        if f.name.starts_with("draw:") && anchored.len() < 1 << 16 {
            anchored.push((r, c, f));
        }
    }
}

fn find_link(n: &Node, depth: u32) -> Option<String> {
    if depth > 16 {
        return None;
    }
    for c in n.nodes() {
        if c.name == "text:a" {
            return c.attr("xlink:href").map(str::to_string);
        }
        if c.name != "office:annotation" && !c.name.starts_with("draw:") {
            if let Some(x) = find_link(c, depth + 1) {
                return Some(x);
            }
        }
    }
    None
}

fn location_to_excel(l: &str) -> String {
    match parse_range_addr(l) {
        Some((sheet, r)) => format!(
            "{}!{}",
            crate::formats::office::sheets::xls::formula::quote_sheet(&sheet),
            range_ref(&r)
        ),
        None => l.to_string(),
    }
}

/// A cell's value and formula, `None` when it has neither.
fn parse_cell(
    cell: &Node,
    doc: &mut Doc,
    style_name: Option<&str>,
    budget: &mut Budget,
) -> Result<Option<(Value, Option<Box<str>>)>> {
    let vt = cell
        .attr("office:value-type")
        .or(cell.attr("calcext:value-type"));
    let formula = cell.attr("table:formula").and_then(|f| doc.fc.convert(f));
    let num = |k: &str| {
        cell.attr(k)
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
    };
    let error_text = |cell: &Node| -> Value {
        let t = paragraphs(cell);
        // The application's own codes have no XLSX error: #VALUE!.
        Value::Error(CellError::parse(&t).unwrap_or(CellError::Value))
    };
    let mut value = match vt {
        _ if cell.attr("calcext:value-type") == Some("error") => error_text(cell),
        Some("float" | "percentage" | "currency") => {
            Value::Number(num("office:value").unwrap_or(0.0))
        }
        Some("date") => cell
            .attr("office:date-value")
            .and_then(|v| parse_date(v, doc.null))
            .map_or(Value::Empty, Value::Number),
        Some("time") => cell
            .attr("office:time-value")
            .and_then(parse_duration)
            .map_or(Value::Empty, Value::Number),
        Some("boolean") => Value::Bool(matches!(
            cell.attr("office:boolean-value").map(str::trim),
            Some("true" | "1")
        )),
        Some("string") => {
            let base = doc.st.resolve(style_name.unwrap_or("Default"));
            match cell_runs(cell, &base, &doc.text_styles) {
                Some(runs) => rich(runs, doc),
                None => Value::text(
                    cell.attr("office:string-value")
                        .map(str::to_string)
                        .unwrap_or_else(|| paragraphs(cell)),
                ),
            }
        }
        _ if cell.child("text:p").is_some() && formula.is_none() => Value::text(paragraphs(cell)),
        _ => Value::Empty,
    };
    // A formula whose result is an error, in documents that do not type it.
    if value == Value::Empty && formula.is_some() {
        let t = paragraphs(cell);
        if t.starts_with('#') || t.starts_with("Err:") {
            value = Value::Error(CellError::parse(&t).unwrap_or(CellError::Value));
        }
    }
    if value == Value::Empty && formula.is_none() {
        return Ok(None);
    }
    budget.alloc(value.text_len() as u64)?;
    Ok(Some((value, formula.map(String::into_boxed_str))))
}

/// The runs of a cell's text where spans change the font, or `None` when
/// none does.
fn cell_runs(
    cell: &Node,
    base: &Props,
    text_styles: &HashMap<String, Props>,
) -> Option<Vec<(String, Props)>> {
    fn walk(
        n: &Node,
        cur: &Props,
        ts: &HashMap<String, Props>,
        runs: &mut Vec<(String, Props)>,
        any: &mut bool,
        depth: u32,
    ) {
        if depth > 32 || runs.len() > 4096 {
            return;
        }
        for c in &n.children {
            match c {
                Child::Text(t) => runs.push((t.clone(), cur.clone())),
                Child::Node(x) => match x.name.as_str() {
                    "text:span" => {
                        let mut p = cur.clone();
                        if let Some(sp) = x.attr("text:style-name").and_then(|sn| ts.get(sn)) {
                            p.overlay(sp);
                            *any = true;
                        }
                        walk(x, &p, ts, runs, any, depth + 1);
                    }
                    "text:s" => {
                        let k = x
                            .attr("text:c")
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(1)
                            .min(1000);
                        runs.push((" ".repeat(k), cur.clone()));
                    }
                    "text:tab" => runs.push(("\t".into(), cur.clone())),
                    "text:line-break" => runs.push(("\n".into(), cur.clone())),
                    "office:annotation" => {}
                    _ => walk(x, cur, ts, runs, any, depth + 1),
                },
            }
        }
    }
    let mut runs: Vec<(String, Props)> = vec![];
    let mut any = false;
    let mut first = true;
    for p in cell.nodes().filter(|p| p.name == "text:p") {
        if !first {
            let last = runs.last().map_or_else(|| base.clone(), |r| r.1.clone());
            runs.push(("\n".into(), last));
        }
        first = false;
        walk(p, base, text_styles, &mut runs, &mut any, 0);
    }
    any.then_some(runs)
}

fn rich(runs: Vec<(String, Props)>, doc: &Doc) -> Value {
    let mut out: Vec<Run> = vec![];
    for (text, p) in runs {
        let font = doc.st.to_style(&p).font;
        if let Some(last) = out.last_mut() {
            if last.font.as_ref() == Some(&font) {
                last.text.push_str(&text);
                continue;
            }
        }
        out.push(Run {
            text,
            font: Some(font),
        });
    }
    out.retain(|r| !r.text.is_empty());
    if out.len() <= 1 {
        Value::text(out.into_iter().map(|r| r.text).collect::<String>())
    } else {
        Value::Rich(out.into())
    }
}
