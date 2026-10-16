//! One table (TST.TableModelArchive) to one sheet.
//!
//! TableModelArchive fields: table_style 3, base_data_store 4,
//! number_of_rows 6, number_of_columns 7, table_name 8, header rows 9,
//! header columns 10, footer rows 11, header_rows_frozen 12,
//! header_columns_frozen 13, default_row_height 16, default_column_width
//! 17, region cell styles 18 (body), 19 (header row), 20 (header column),
//! 21 (footer), region text styles 24 to 27 in the same order,
//! merge_owner 47 (formula_store 2: formulas 3, each formula 2),
//! stroke_sidecar 49, haunted_owner 84 (owner_uid 1).
//!
//! DataStore fields: rowHeaders 1 (buckets 2), columnHeaders 2 (a bucket),
//! tiles 3 (tiles 1: tileid 1, tile 2; tile_size 2), stringTable 4,
//! styleTable 5, formula_table 6, format_table_pre_bnc 11,
//! formulaErrorTable 12, merge_region_map 13, rich_text_table 17,
//! commentStorageTable 19, format_table 22. A data list (TST.TableDataList)
//! holds entries 3 (key 1, string 3, reference 4, formula 5, format 6,
//! rich_text_payload 9, comment_storage 10) and segments 4 holding more.

use super::cells::{self, Raw};
use super::format;
use super::formula::{self, Refs, TableDims};
use super::iwa::Store;
use super::proto::Msg;
use super::style::{self, CellProps, TextProps};
use crate::formats::office::sheets::error::Result;
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use std::collections::HashMap;
use std::rc::Rc;

/// Days from 1899-12-30, the 1900 date system's day 0, to 2001-01-01.
const EPOCH_DAYS: f64 = 36_892.0;

/// What tables share: the object store, the tables as references see
/// them, custom formats and resolved styles.
pub struct Cx<'a> {
    pub store: &'a Store,
    pub tables: Vec<TableDims>,
    pub by_uuid: HashMap<u128, usize>,
    /// Custom format UUIDs to their CustomFormatArchive.
    pub custom_formats: HashMap<u128, Msg<'a>>,
    /// Merged ranges the calculation engine records, by table: (first
    /// row, first column, last row, last column).
    pub merges: HashMap<usize, Vec<(u32, u32, u32, u32)>>,
    pub cell_props: HashMap<u64, CellProps>,
    pub text_props: HashMap<u64, TextProps>,
}

impl Cx<'_> {
    fn cell_props(&mut self, id: Option<u64>) -> CellProps {
        let Some(id) = id else {
            return CellProps::default();
        };
        if let Some(p) = self.cell_props.get(&id) {
            return p.clone();
        }
        let p = style::cell_props(self.store, id);
        self.cell_props.insert(id, p.clone());
        p
    }

    fn text_props(&mut self, id: Option<u64>) -> TextProps {
        let Some(id) = id else {
            return TextProps::default();
        };
        if let Some(p) = self.text_props.get(&id) {
            return p.clone();
        }
        let p = style::text_props(self.store, id);
        self.text_props.insert(id, p.clone());
        p
    }
}

/// A data list's entries by key.
fn data_list<'a>(store: &'a Store, id: Option<u64>) -> HashMap<u32, Msg<'a>> {
    let mut out = HashMap::new();
    let Some((_, m)) = id.and_then(|i| store.get(i)) else {
        return out;
    };
    let mut add = |list: Msg<'a>| {
        for e in list.msgs(3) {
            if let Some(k) = e.uint(1) {
                out.insert(k as u32, e);
            }
        }
    };
    add(m);
    for seg in m.references(4).take(1 << 16) {
        if let Some((_, s)) = store.get(seg) {
            add(s);
        }
    }
    out
}

/// Row or column headers: index to (size, hidden, cell style, text style).
type Headers = HashMap<u32, (f32, bool, Option<u64>, Option<u64>)>;

fn headers(store: &Store, buckets: impl Iterator<Item = u64>, max: u32) -> Headers {
    let mut out = HashMap::new();
    for b in buckets.take(4096) {
        let Some((_, m)) = store.get(b) else { continue };
        for h in m.msgs(2) {
            let Some(i) = h.uint(1).map(|i| i as u32).filter(|&i| i < max) else {
                continue;
            };
            let size = h
                .float(2)
                .filter(|s| s.is_finite() && *s > 0.0)
                .unwrap_or(0.0);
            out.insert(
                i,
                (
                    size,
                    h.uint(3).unwrap_or(0) != 0,
                    h.reference(5),
                    h.reference(6),
                ),
            );
        }
    }
    out
}

/// Which part of the table a cell is in: 0 body, 1 header row, 2 header
/// column, 3 footer. Header rows take their corner with header columns,
/// header columns theirs with footer rows.
pub(super) fn region(d: &TableDims, r: u32, c: u32) -> usize {
    if r < d.header_rows {
        1
    } else if c < d.header_cols {
        2
    } else if d.footer_rows > 0 && r >= d.rows.saturating_sub(d.footer_rows) {
        3
    } else {
        0
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct StyleKey {
    region: usize,
    cell: [Option<u64>; 3],
    text: [Option<u64>; 3],
    numfmt: Option<String>,
    border: [Option<Edge>; 4],
}

pub fn read_table(
    cx: &mut Cx,
    idx: usize,
    model: Msg,
    sheet: &mut Sheet,
    wb: &mut Workbook,
    budget: &mut Budget,
) -> Result<()> {
    let store = cx.store;
    let d = cx.tables[idx].clone();
    let ds = model.msg(4).unwrap_or_default();
    let strings = data_list(store, ds.reference(4));
    let styles = data_list(store, ds.reference(5));
    let formulas = data_list(store, ds.reference(6));
    let formats = data_list(store, ds.reference(22).or_else(|| ds.reference(11)));
    let rich = data_list(store, ds.reference(17));
    let comments = data_list(store, ds.reference(19));
    let style_ref = |k: Option<u32>| k.and_then(|k| styles.get(&k)).and_then(|e| e.reference(4));

    // Sizes.
    let def_h = model
        .double(16)
        .filter(|h| h.is_finite() && *h > 0.0)
        .unwrap_or(20.0);
    sheet.default_row_height = def_h.min(409.0);
    sheet.default_row_custom = true;
    let def_w = model
        .double(17)
        .filter(|w| w.is_finite() && *w > 0.0)
        .unwrap_or(98.0);
    sheet.default_col_width = Some(width_chars(def_w));
    let rows_h = headers(store, ds.msg(1).unwrap_or_default().references(2), d.rows);
    let cols_h = headers(store, ds.reference(2).into_iter(), d.cols);
    let mut col_keys: Vec<&u32> = cols_h.keys().collect();
    col_keys.sort_unstable();
    for &c in col_keys {
        let (size, hidden, _, _) = cols_h[&c];
        if c > MAX_COL || (size <= 0.0 && !hidden) {
            continue;
        }
        let width = (size > 0.0).then(|| width_chars(f64::from(size)));
        sheet.cols.push(ColInfo {
            first: c,
            last: c,
            width,
            hidden,
            style: None,
            outline: 0,
        });
    }
    for (&r, &(size, hidden, _, _)) in &rows_h {
        if r > MAX_ROW || (size <= 0.0 && !hidden) {
            continue;
        }
        let height = (size > 0.0).then(|| f64::from(size).min(409.0));
        sheet.rows.insert(
            r,
            RowInfo {
                height,
                custom_height: height.is_some(),
                hidden,
                style: None,
                outline: 0,
            },
        );
    }

    // Merges: from the merge owner's formulas, else the calculation
    // engine's, else the region map.
    for pair in model
        .msg(47)
        .and_then(|m| m.msg(2))
        .into_iter()
        .flat_map(|s| s.msgs(3))
        .take(1 << 16)
    {
        let Some(node) = pair
            .msg(2)
            .and_then(|f| f.msg(1))
            .and_then(|a| a.msgs(1).next())
        else {
            continue;
        };
        if node.uint(1) != Some(67) {
            continue;
        }
        let Some(t) = node.msg(40) else { continue };
        let span = |m: Option<Msg>| {
            m.and_then(|m| Some((m.uint(1)? as u32, m.uint(2).or(m.uint(1))? as u32)))
        };
        if let (Some((r1, r2)), Some((c1, c2))) = (span(t.msgs(4).next()), span(t.msgs(3).next())) {
            push_merge(sheet, &d, r1, c1, r2, c2);
        }
    }
    if sheet.merges.is_empty() {
        for &(r1, c1, r2, c2) in cx.merges.get(&idx).into_iter().flatten() {
            push_merge(sheet, &d, r1, c1, r2, c2);
        }
    }
    if sheet.merges.is_empty() {
        if let Some((_, m)) = ds.reference(13).and_then(|i| store.get(i)) {
            for cr in m.msgs(1).take(1 << 16) {
                let packed = |f: u32| cr.msg(f).and_then(|x| x.uint(1)).map(|v| v as u32);
                let (Some(o), Some(s)) = (packed(1), packed(2)) else {
                    continue;
                };
                let (c1, r1) = (o >> 16, o & 0xFFFF);
                let (nc, nr) = (s >> 16, s & 0xFFFF);
                if nc > 0 && nr > 0 {
                    push_merge(sheet, &d, r1, c1, r1 + nr - 1, c1 + nc - 1);
                }
            }
        }
    }

    // Borders.
    let borders = strokes(store, model, &d, budget)?;

    // Cells.
    let region_cell = [18, 19, 20, 21].map(|f| model.reference(f));
    let region_text = [24, 25, 26, 27].map(|f| model.reference(f));
    let mut style_cache: HashMap<StyleKey, u32> = HashMap::new();
    let refs_tables = std::mem::take(&mut cx.tables);
    let refs_uuid = std::mem::take(&mut cx.by_uuid);
    let mut bad_formulas = 0usize;
    let tiles = ds.msg(3).unwrap_or_default();
    let tile_size = tiles.uint(2).filter(|&s| s > 0).unwrap_or(256);
    let mut result = Ok(());
    'tiles: for t in tiles.msgs(1).take(1 << 16) {
        let (Some(tid), Some((_, tile))) = (t.uint(1), t.reference(2).and_then(|r| store.get(r)))
        else {
            continue;
        };
        let bnc = tile.boolean(7).unwrap_or(false);
        for ri in tile.msgs(5) {
            let Some(row) = tid
                .checked_mul(tile_size)
                .and_then(|b| b.checked_add(ri.uint(1).unwrap_or(0)))
            else {
                continue;
            };
            if row >= u64::from(d.rows) || row > u64::from(MAX_ROW) {
                continue;
            }
            let row = row as u32;
            let wide = ri.boolean(8).unwrap_or(false);
            // The current storage when there is one: writers set the "saved
            // in BNC" flag of the tile inconsistently.
            let (storage, offsets) = match (ri.bytes(6), ri.bytes(7)) {
                (Some(s), Some(o)) if bnc || !o.is_empty() => (s, o),
                _ => (
                    ri.bytes(3).unwrap_or_default(),
                    ri.bytes(4).unwrap_or_default(),
                ),
            };
            for (col, rec) in cells::row_cells(storage, offsets, wide) {
                if col >= d.cols || col > MAX_COL {
                    continue;
                }
                let Some(raw) = cells::decode(rec) else {
                    continue;
                };
                let rh = rows_h.get(&row);
                let ch = cols_h.get(&col);
                let reg = region(&d, row, col);
                let numfmt = cell_format(cx, &formats, &raw);
                let key = StyleKey {
                    region: reg,
                    cell: [
                        style_ref(raw.cell_style),
                        rh.and_then(|h| h.2),
                        ch.and_then(|h| h.2),
                    ],
                    text: [
                        style_ref(raw.text_style),
                        rh.and_then(|h| h.3),
                        ch.and_then(|h| h.3),
                    ],
                    numfmt,
                    border: borders.get(&(row, col)).cloned().unwrap_or_default(),
                };
                let sid = style_for(
                    cx,
                    wb,
                    &mut style_cache,
                    key,
                    region_cell[reg],
                    region_text[reg],
                );
                let (value, link) =
                    cell_value(store, &strings, &rich, &raw, wb, &mut cx.text_props);
                let mut cell = Cell {
                    value,
                    formula: None,
                    style: sid,
                };
                if let Some(f) = raw
                    .formula
                    .and_then(|k| formulas.get(&k))
                    .and_then(|e| e.msg(5))
                    .and_then(|f| f.msg(1))
                {
                    let refs = Refs {
                        tables: &refs_tables,
                        by_uuid: &refs_uuid,
                        host: idx,
                    };
                    match formula::convert(f, &refs, row, col) {
                        Some(text) => cell.formula = Some(text.into()),
                        None => bad_formulas += 1,
                    }
                }
                if let Some(url) = link.filter(|u| safe_url(u)) {
                    sheet.hyperlinks.push(Hyperlink {
                        range: Range::cell(row, col),
                        url: Some(url),
                        location: None,
                        tooltip: None,
                        display: None,
                    });
                }
                if let Some((_, c)) = raw
                    .comment
                    .and_then(|k| comments.get(&k))
                    .and_then(|e| e.reference(10))
                    .and_then(|r| store.get(r))
                {
                    // TSD.CommentStorageArchive: text 1, author 3
                    // (TSK.AnnotationAuthorArchive: name 1), replies 4.
                    let author_of = |m: Msg| {
                        m.reference(3)
                            .and_then(|a| store.get(a))
                            .and_then(|a| a.1.string(1))
                            .unwrap_or_default()
                    };
                    let mut text = c.string(1).unwrap_or_default();
                    for r in c.references(4).take(256).filter_map(|r| store.get(r)) {
                        let t = r.1.string(1).unwrap_or_default();
                        if !t.is_empty() {
                            text.push_str(&format!("\n{}: {t}", author_of(r.1)));
                        }
                    }
                    if !text.is_empty() {
                        sheet.comments.push(Comment {
                            row,
                            col,
                            author: author_of(c),
                            text,
                            visible: false,
                        });
                    }
                }
                let extra = cell.value.text_len() + cell.formula.as_ref().map_or(0, |f| f.len());
                if let Err(e) = budget.cell(extra) {
                    result = Err(e);
                    break 'tiles;
                }
                sheet.cells.insert((row, col), cell);
            }
        }
    }
    cx.tables = refs_tables;
    cx.by_uuid = refs_uuid;
    result?;
    if bad_formulas > 0 {
        wb.warn(format!(
            "{}: {bad_formulas} formulas Excel cannot express were left as their values",
            sheet.name
        ));
    }

    // Empty cells that show a fill or a border.
    let area = u64::from(d.rows) * u64::from(d.cols);
    let all = area <= 1 << 20 && budget.room_for_cells(area);
    if !all {
        wb.warn(format!(
            "{}: fills of empty cells left out, the table is too large",
            sheet.name
        ));
    }
    let mut todo: Vec<(u32, u32)> = vec![];
    if all {
        for r in 0..d.rows.min(MAX_ROW + 1) {
            for c in 0..d.cols.min(MAX_COL + 1) {
                if !sheet.cells.contains_key(&(r, c)) {
                    todo.push((r, c));
                }
            }
        }
    } else {
        todo.extend(borders.keys().filter(|k| !sheet.cells.contains_key(k)));
        todo.sort_unstable();
    }
    for (r, c) in todo {
        let rh = rows_h.get(&r);
        let ch = cols_h.get(&c);
        let reg = region(&d, r, c);
        let key = StyleKey {
            region: reg,
            cell: [None, rh.and_then(|h| h.2), ch.and_then(|h| h.2)],
            text: [None, rh.and_then(|h| h.3), ch.and_then(|h| h.3)],
            numfmt: None,
            border: borders.get(&(r, c)).cloned().unwrap_or_default(),
        };
        let sid = style_for(
            cx,
            wb,
            &mut style_cache,
            key,
            region_cell[reg],
            region_text[reg],
        );
        let st = wb.styles.get(sid);
        if st.fill.pattern == "none" && st.border == Border::default() {
            continue;
        }
        budget.cell(0)?;
        sheet.cells.insert((r, c), Cell::styled(sid));
    }

    // Frozen headers.
    let fr = if model.boolean(12).unwrap_or(false) {
        d.header_rows
    } else {
        0
    };
    let fc = if model.boolean(13).unwrap_or(false) {
        d.header_cols
    } else {
        0
    };
    if fr > 0 || fc > 0 {
        sheet.freeze = Some((fr.min(d.rows), fc.min(d.cols)));
    }
    Ok(())
}

/// A width in points as an XLSX column width: pixels at 96 dpi over the
/// 7-pixel maximum digit width of the default font (10-point Helvetica
/// Neue, or the sans-serif face that stands in for it).
pub(super) fn width_chars(pt: f64) -> f64 {
    ((pt * 96.0 / 72.0 / 7.0 * 256.0).round() / 256.0).min(255.0)
}

pub(super) fn push_merge(sheet: &mut Sheet, d: &TableDims, r1: u32, c1: u32, r2: u32, c2: u32) {
    if r1 > r2 || c1 > c2 || r2 >= d.rows || c2 >= d.cols || (r1 == r2 && c1 == c2) {
        return;
    }
    let m = Range { r1, c1, r2, c2 };
    if !sheet
        .merges
        .iter()
        .any(|x| x.r1 <= m.r2 && m.r1 <= x.r2 && x.c1 <= m.c2 && m.c1 <= x.c2)
    {
        sheet.merges.push(m);
    }
}

/// The XLSX code of a cell's format, `None` for General.
fn cell_format(cx: &Cx, formats: &HashMap<u32, Msg>, raw: &Raw) -> Option<String> {
    let f = raw
        .format()
        .and_then(|k| formats.get(&k))
        .and_then(|e| e.msg(6));
    let value = match raw.kind {
        cells::DURATION => raw.number().map(|s| s / 86_400.0),
        _ => raw.number(),
    };
    let Some(f) = f else {
        return match raw.kind {
            cells::DATE => Some(if raw.seconds.unwrap_or(0.0).rem_euclid(86_400.0) == 0.0 {
                "yyyy-mm-dd".into()
            } else {
                format::DEFAULT_DATE.into()
            }),
            cells::DURATION => Some("[h]:mm:ss".into()),
            _ => None,
        };
    };
    let custom = f
        .msg(41)
        .and_then(formula::uuid)
        .and_then(|u| cx.custom_formats.get(&u))
        .and_then(|c| c.msg(3));
    format::code(f, custom, value)
}

fn style_for(
    cx: &mut Cx,
    wb: &mut Workbook,
    cache: &mut HashMap<StyleKey, u32>,
    key: StyleKey,
    reg_cell: Option<u64>,
    reg_text: Option<u64>,
) -> u32 {
    if let Some(&s) = cache.get(&key) {
        return s;
    }
    let mut cp = CellProps::default();
    for id in key.cell.iter().copied().chain([reg_cell]) {
        cp.under(&cx.cell_props(id));
    }
    let mut tp = TextProps::default();
    for id in key.text.iter().copied().chain([reg_text]) {
        tp.under(&cx.text_props(id));
    }
    let mut st = Style {
        font: tp.font(),
        ..Style::default()
    };
    if let Some(Some(c)) = cp.fill {
        st.fill = Fill::solid(c);
    }
    st.align.wrap = cp.wrap.unwrap_or(true);
    st.align.vertical = match cp.valign.unwrap_or(0) {
        1 => Some("center"),
        2 => None,
        _ => Some("top"),
    };
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
}

/// Seconds since 2001-01-01 as a 1900 date system serial, which counts a
/// 29 February 1900 that was not: days of 1900 before March are one less.
/// Earlier dates, which the system cannot show, are left as they count.
pub(super) fn serial(secs: f64) -> f64 {
    let v = EPOCH_DAYS + secs / 86_400.0;
    if (2.0..61.0).contains(&v) {
        v - 1.0
    } else {
        v
    }
}

/// A cell's value, and the link of a rich text cell that holds one.
fn cell_value(
    store: &Store,
    strings: &HashMap<u32, Msg>,
    rich: &HashMap<u32, Msg>,
    raw: &Raw,
    wb: &Workbook,
    text_props: &mut HashMap<u64, TextProps>,
) -> (Value, Option<String>) {
    let v = match raw.kind {
        cells::NUMBER | cells::CURRENCY => raw
            .number()
            .filter(|v| v.is_finite())
            .map_or(Value::Empty, Value::Number),
        // An empty string is kept only as a formula's result.
        cells::TEXT => raw
            .string
            .and_then(|k| strings.get(&k))
            .and_then(|e| e.string(3))
            .filter(|s| !s.is_empty() || raw.formula.is_some())
            .map_or(Value::Empty, Value::text),
        cells::DATE => raw
            .seconds
            .filter(|s| s.is_finite())
            .map_or(Value::Empty, |s| Value::Number(serial(s))),
        cells::DURATION => raw
            .double
            .filter(|s| s.is_finite())
            .map_or(Value::Empty, |s| Value::Number(s / 86_400.0)),
        cells::BOOL => Value::Bool(raw.double.unwrap_or(0.0) > 0.0),
        cells::ERROR => Value::Error(CellError::Value),
        cells::RICH => {
            let storage = raw
                .rich
                .and_then(|k| rich.get(&k))
                .and_then(|e| e.reference(9))
                .and_then(|p| store.get(p))
                .and_then(|p| p.1.reference(1))
                .and_then(|s| store.get(s));
            return match storage {
                Some((_, s)) => rich_text(store, s, wb, text_props),
                None => (Value::Empty, None),
            };
        }
        _ => Value::Empty,
    };
    (v, None)
}

/// A TSWP.StorageArchive: text 3, table_char_style 8 and table_smartfield
/// 11 (entries 1: character_index 1, object 2). Character indexes count
/// UTF-16 units.
fn rich_text(
    store: &Store,
    s: Msg,
    wb: &Workbook,
    text_props: &mut HashMap<u64, TextProps>,
) -> (Value, Option<String>) {
    let text: String = s
        .all(3)
        .filter_map(|v| {
            if let super::proto::Val::Bytes(b) = v {
                Some(String::from_utf8_lossy(b).into_owned())
            } else {
                None
            }
        })
        .collect();
    let mut link = None;
    for e in s.msg(11).into_iter().flat_map(|t| t.msgs(1)) {
        if let Some((_, h)) = e.reference(2).and_then(|o| store.get(o)) {
            if let Some(u) = h.string(2).filter(|u| !u.is_empty()) {
                link.get_or_insert(u);
            }
        }
    }
    let runs: Vec<(usize, Option<u64>)> = s
        .msg(8)
        .into_iter()
        .flat_map(|t| t.msgs(1))
        .filter_map(|e| Some((e.uint(1)? as usize, e.reference(2))))
        .take(4096)
        .collect();
    if runs.iter().all(|r| r.1.is_none()) {
        return (Value::text(text), link);
    }
    let units: Vec<u16> = text.encode_utf16().collect();
    let base = wb.styles.get(0).font.clone();
    let mut out: Vec<Run> = vec![];
    for (i, &(start, sty)) in runs.iter().enumerate() {
        let end = runs
            .get(i + 1)
            .map_or(units.len(), |r| r.0)
            .min(units.len());
        let start = start.min(end);
        if start == end {
            continue;
        }
        let t = String::from_utf16_lossy(&units[start..end]);
        let font = sty.map(|id| {
            let p = text_props
                .entry(id)
                .or_insert_with(|| style::text_props(store, id))
                .clone();
            let mut f = p.font();
            if p.font.is_none() {
                f.name.clone_from(&base.name);
            }
            f
        });
        out.push(Run { text: t, font });
    }
    if let Some(first) = runs.first().filter(|r| r.0 > 0) {
        let head = String::from_utf16_lossy(&units[..first.0.min(units.len())]);
        out.insert(
            0,
            Run {
                text: head,
                font: None,
            },
        );
    }
    if out.is_empty() {
        return (Value::text(text), link);
    }
    (Value::Rich(Rc::from(out)), link)
}

/// The borders strokes draw: TST.StrokeSidecarArchive (left 4, right 5,
/// top 6 and bottom 7 column or row stroke layers), each layer a
/// TST.StrokeLayerArchive (row_column_index 1, stroke_runs 2: origin 1,
/// length 2, stroke 3, order 4), over the table style's lines. A run of a
/// higher order draws over a lower one. Each line is set on both cells it
/// separates.
fn strokes(store: &Store, model: Msg, d: &TableDims, budget: &mut Budget) -> Result<Borders> {
    let mut out: Borders = HashMap::new();
    // (order, side, line index, from, to, edge); side 0 top, 1 right,
    // 2 bottom, 3 left. The table style's lines come first, under all.
    let mut runs = if u64::from(d.rows) * u64::from(d.cols) <= 1 << 20 {
        style_lines(store, model, d)
    } else {
        vec![]
    };
    let sidecar = model
        .reference(49)
        .and_then(|r| store.get(r))
        .map(|o| o.1)
        .unwrap_or_default();
    for (field, side) in [(6u32, 0usize), (5, 1), (7, 2), (4, 3)] {
        for layer in sidecar.references(field).take(1 << 16) {
            let Some((_, l)) = store.get(layer) else {
                continue;
            };
            let idx = l.uint(1).unwrap_or(0) as u32;
            for run in l.msgs(2) {
                let origin = run.int(1).unwrap_or(0).max(0) as u32;
                let len = run.uint(2).unwrap_or(0) as u32;
                let Some(s) = run.msg(3) else { continue };
                runs.push((
                    run.uint(4).unwrap_or(0) as i64,
                    side,
                    idx,
                    origin,
                    origin.saturating_add(len),
                    style::stroke_edge(s),
                ));
            }
        }
    }
    runs.sort_by_key(|r| r.0);
    let horizontal = |side: usize| side == 0 || side == 2;
    let mut set = |r: u32, c: u32, side: usize, e: &Edge, out: &mut Borders| -> Result<()> {
        if r >= d.rows || c >= d.cols {
            return Ok(());
        }
        let slot = match out.get_mut(&(r, c)) {
            Some(s) => s,
            None => {
                budget.alloc(64)?;
                out.entry((r, c)).or_default()
            }
        };
        slot[side] = Some(e.clone());
        Ok(())
    };
    for (_, side, idx, from, to, edge) in runs {
        let (from, to) = if horizontal(side) {
            (from, to.min(d.cols))
        } else {
            (from, to.min(d.rows))
        };
        for k in from..to {
            let (r, c) = if horizontal(side) { (idx, k) } else { (k, idx) };
            set(r, c, side, &edge, &mut out)?;
            // The neighbour across the line.
            match side {
                0 if r > 0 => set(r - 1, c, 2, &edge, &mut out)?,
                2 => set(r + 1, c, 0, &edge, &mut out)?,
                3 if c > 0 => set(r, c - 1, 1, &edge, &mut out)?,
                1 => set(r, c + 1, 3, &edge, &mut out)?,
                _ => {}
            }
        }
    }
    // A cleared edge is no edge.
    for v in out.values_mut() {
        for e in v.iter_mut() {
            if e.as_ref().is_some_and(|e| e.style.is_none()) {
                *e = None;
            }
        }
    }
    out.retain(|_, v| v.iter().any(Option::is_some));
    Ok(out)
}

/// (order, side, line index, from, to, edge).
type Line = (i64, usize, u32, u32, u32, Edge);

/// Each cell's top, right, bottom and left edges.
type Borders = HashMap<(u32, u32), [Option<Edge>; 4]>;

/// The lines a table style draws (TST.TableStyleArchive: table_properties
/// 11, the style's parent in field 1). TableStylePropertiesArchive: which
/// lines show, v_strokes_visible 33, h_strokes_visible 34,
/// hr_separator_visible 35, hc_separator_visible 36,
/// footer_separator_visible 37, table_border_visible 38; and the strokes:
/// header rows 46 (separator), 47 (border), 48 (horizontal), 49
/// (vertical); header columns 50 (border), 51 (separator), 52, 53;
/// footer rows 54 (separator), 55 (border), 56, 57; body 58 (horizontal
/// border), 59 (vertical border), 60 (horizontal), 61 (vertical).
fn style_lines(store: &Store, model: Msg, d: &TableDims) -> Vec<Line> {
    let mut chain = vec![];
    let mut cur = model.reference(3);
    for _ in 0..16 {
        let Some((_, m)) = cur.and_then(|i| store.get(i)) else {
            break;
        };
        if let Some(p) = m.msg(11) {
            chain.push(p);
        }
        cur = m.msg(1).and_then(|s| s.reference(3));
    }
    if chain.is_empty() {
        return vec![];
    }
    let flag = |n: u32| chain.iter().find_map(|p| p.boolean(n)).unwrap_or(false);
    let stroke = |n: u32, shown: bool| -> Option<Edge> {
        if !shown {
            return None;
        }
        let e = style::stroke_edge(chain.iter().find_map(|p| p.msg(n))?);
        e.style.is_some().then_some(e)
    };
    let (v_in, h_in, hr_sep, hc_sep, ft_sep, border) =
        (flag(33), flag(34), flag(35), flag(36), flag(37), flag(38));
    let (rows, cols, hr, hc) = (d.rows, d.cols, d.header_rows, d.header_cols);
    let fr_start = rows.saturating_sub(d.footer_rows).max(hr);
    let mut runs: Vec<Line> = vec![];
    let mut push = |side: usize, idx: u32, from: u32, to: u32, e: Option<Edge>| {
        if let Some(e) = e.filter(|_| from < to) {
            runs.push((-1, side, idx, from, to, e));
        }
    };
    // Horizontal lines: line y is above row y.
    for y in 0..=rows {
        let footer = d.footer_rows > 0 && y >= fr_start;
        for (from, to, in_hc) in [(0, hc.min(cols), true), (hc.min(cols), cols, false)] {
            let e = if y == 0 || y == rows {
                let edge_row = if y == 0 { 0 } else { rows - 1 };
                if edge_row < hr {
                    stroke(47, border)
                } else if d.footer_rows > 0 && edge_row >= fr_start {
                    stroke(55, border)
                } else if in_hc {
                    stroke(50, border)
                } else {
                    stroke(58, border)
                }
            } else if hr > 0 && y == hr {
                stroke(46, hr_sep)
            } else if d.footer_rows > 0 && y == fr_start {
                stroke(54, ft_sep)
            } else if y < hr {
                stroke(48, h_in)
            } else if footer {
                stroke(56, h_in)
            } else if in_hc {
                stroke(52, h_in)
            } else {
                stroke(60, h_in)
            };
            let (side, idx) = if y < rows {
                (0, y)
            } else {
                (2, rows.saturating_sub(1))
            };
            push(side, idx, from, to, e);
        }
    }
    // Vertical lines: line x is left of column x.
    for x in 0..=cols {
        for (from, to, part) in [
            (0, hr.min(rows), 1),
            (hr.min(rows), fr_start.min(rows), 0),
            (fr_start.min(rows), rows, 3),
        ] {
            let e = if x == 0 || x == cols {
                match part {
                    1 => stroke(47, border),
                    3 => stroke(55, border),
                    _ if x == 0 && hc > 0 => stroke(50, border),
                    _ => stroke(59, border),
                }
            } else if hc > 0 && x == hc && part == 0 {
                stroke(51, hc_sep)
            } else {
                match part {
                    1 => stroke(49, v_in),
                    3 => stroke(57, v_in),
                    _ if x < hc => stroke(53, v_in),
                    _ => stroke(61, v_in),
                }
            };
            let (side, idx) = if x < cols {
                (3, x)
            } else {
                (1, cols.saturating_sub(1))
            };
            push(side, idx, from, to, e);
        }
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::serial;

    #[test]
    fn serials_count_the_leap_day_1900_had_not() {
        let day = 86_400.0;
        // 1900-01-01 is serial 1, 1900-03-01 serial 61, 2001-01-01 36892.
        assert_eq!(serial(-36_890.0 * day), 1.0);
        assert_eq!(serial(-36_831.0 * day), 61.0);
        assert_eq!(serial(0.0), 36_892.0);
        // 1899-12-31 has no serial: left as it counts.
        assert_eq!(serial(-36_891.0 * day), 1.0);
    }
}
