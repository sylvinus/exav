//! Keynote tables (TST.TableInfoArchive) to the model's tables: sizes,
//! cell text, region and cell fills, borders and merged cells. Messages are
//! read by field number, as the sheets reader does for Numbers (the layout
//! is the table model both applications share); the numbers are those of
//! the message definitions keynote-parser (MIT, Peter Sobot) extracted from
//! the application, and of numbers-parser (MIT, Jon Connell) for the cell
//! records.
//!
//! TST.TableInfoArchive: drawable 1, table_model 2. TST.TableModelArchive:
//! table_style 3, base_data_store 4, number_of_rows 6, number_of_columns 7,
//! header rows 9, header columns 10, footer rows 11, default_row_height 16,
//! default_column_width 17, region cell styles 18 (body), 19 (header row),
//! 20 (header column), 21 (footer), region text styles 24 to 27, merge_owner
//! 47, stroke_sidecar 49. TST.DataStore: rowHeaders 1 (buckets 2),
//! columnHeaders 2, tiles 3 (tiles 1: tileid 1, tile 2; tile_size 2),
//! stringTable 4, styleTable 5, rich_text_table 17. A data list holds
//! entries 3 (key 1, string 3, reference 4, rich_text_payload 9) and
//! segments 4.

use super::{Reader, text, ty};
use crate::formats::office::common::iwa::Store;
use crate::formats::office::common::iwa::proto::Msg;
use crate::formats::office::slides::error::Result;
use crate::formats::office::slides::limits::Budget;
use crate::formats::office::slides::model::*;
use std::collections::HashMap;

const PT: f64 = 12700.0;
const MAX_CHAIN: usize = 32;
/// Rows and columns a table may have.
const MAX_ROWS: u32 = 10_000;
const MAX_COLS: u32 = 1_000;

/// A TSP.Color as RGB; `None` when transparent.
fn color(c: Msg) -> Option<Color> {
    let col = super::shapes::color(c);
    (col.alpha != Some(0)).then_some(col)
}

/// A fill's colour: its colour, or its gradient's first stop.
fn fill_color(f: Msg) -> Option<Color> {
    if let Some(c) = f.msg(1) {
        return color(c);
    }
    color(f.msg(2)?.msgs(2).next()?.msg(1)?)
}

/// A data list's entries by key.
fn data_list<'a>(store: &'a Store, id: Option<u64>) -> HashMap<u32, Msg<'a>> {
    let mut out = HashMap::new();
    let Some((_, m)) = id.and_then(|i| store.get(i)) else {
        return out;
    };
    let mut add = |list: Msg<'a>| {
        for e in list.msgs(3).take(1 << 20) {
            if let Some(k) = e.uint(1) {
                out.insert(k as u32, e);
            }
        }
    };
    add(m);
    for seg in m.references(4).take(1 << 12) {
        if let Some((_, s)) = store.get(seg) {
            add(s);
        }
    }
    out
}

/// Row or column headers: index to size and cell style.
type Headers = HashMap<u32, (f32, Option<u64>)>;

fn headers(store: &Store, buckets: impl Iterator<Item = u64>, max: u32) -> Headers {
    let mut out = HashMap::new();
    for b in buckets.take(4096) {
        let Some((_, m)) = store.get(b) else { continue };
        for h in m.msgs(2).take(1 << 16) {
            let Some(i) = h.uint(1).map(|i| i as u32).filter(|&i| i < max) else {
                continue;
            };
            let size = h
                .float(2)
                .filter(|s| s.is_finite() && *s > 0.0)
                .unwrap_or(0.0);
            out.insert(i, (size, h.reference(5)));
        }
    }
    out
}

/// What a cell record holds: its type byte (2 number, 3 text, 5 date, 6
/// boolean, 7 duration, 8 error, 9 rich text, 10 currency), its value and
/// the keys into the data lists.
#[derive(Default)]
struct Raw {
    kind: u8,
    decimal: Option<f64>,
    double: Option<f64>,
    seconds: Option<f64>,
    string: Option<u32>,
    rich: Option<u32>,
    cell_style: Option<u32>,
    text_style: Option<u32>,
}

fn u32_at(b: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(p..p + 4)?.try_into().ok()?))
}

fn f64_at(b: &[u8], p: usize) -> Option<f64> {
    Some(f64::from_le_bytes(b.get(p..p + 8)?.try_into().ok()?))
}

/// An IEEE 754 decimal128 in the binary integer encoding: a 14-bit
/// exponent biased by 6176 and a 113-bit coefficient.
fn decimal128(b: &[u8]) -> f64 {
    if b.len() < 16 {
        return 0.0;
    }
    let exp = ((i32::from(b[15] & 0x7F) << 7) | i32::from(b[14] >> 1)) - 6176;
    let mut m: u128 = u128::from(b[14] & 1);
    for &x in b[..14].iter().rev() {
        m = (m << 8) | u128::from(x);
    }
    let sign = if b[15] & 0x80 != 0 { "-" } else { "" };
    format!("{sign}{m}e{exp}").parse().unwrap_or(0.0)
}

/// A cell record: version 5 has a type byte, a field mask at byte 8 and
/// the fields the mask names in mask order; versions 1 to 4 differ.
fn decode(b: &[u8]) -> Option<Raw> {
    match *b.first()? {
        5 => {
            let flags = u32_at(b, 8)?;
            let mut p = 12usize;
            let mut c = Raw {
                kind: *b.get(1)?,
                ..Raw::default()
            };
            if flags & 0x1 != 0 {
                c.decimal = Some(decimal128(b.get(p..p + 16)?));
                p += 16;
            }
            if flags & 0x2 != 0 {
                c.double = Some(f64_at(b, p)?);
                p += 8;
            }
            if flags & 0x4 != 0 {
                c.seconds = Some(f64_at(b, p)?);
                p += 8;
            }
            // The 4-byte keys, in mask order; those not read are skipped.
            for bit in [
                0x8u32, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000,
                0x8000, 0x10000, 0x20000, 0x40000, 0x80000,
            ] {
                if flags & bit == 0 {
                    continue;
                }
                let v = u32_at(b, p)?;
                p += 4;
                match bit {
                    0x8 => c.string = Some(v),
                    0x10 => c.rich = Some(v),
                    0x20 => c.cell_style = Some(v),
                    0x40 => c.text_style = Some(v),
                    _ => {}
                }
            }
            Some(c)
        }
        v @ 1..=4 => {
            let flags = u32_at(b, 4)?;
            let mut p = if v > 1 { 12 } else { 8 };
            let mut c = Raw {
                kind: *b.get(if v >= 4 { 1 } else { 2 })?,
                ..Raw::default()
            };
            if flags & 0x2 != 0 {
                p += 4;
            }
            p += (flags & if v > 1 { 0xD8C } else { 0x18C }).count_ones() as usize * 4;
            if flags & 0x200 != 0 {
                c.rich = Some(u32_at(b, p)?);
                p += 4;
            }
            p += (flags & if v > 1 { 0x3000 } else { 0x1000 }).count_ones() as usize * 4;
            if flags & 0x10 != 0 {
                c.string = Some(u32_at(b, p)?);
                p += 4;
            }
            if flags & 0x20 != 0 {
                c.double = Some(f64_at(b, p)?);
                p += 8;
            }
            if flags & 0x40 != 0 {
                c.seconds = Some(f64_at(b, p)?);
            }
            if c.kind == 2 {
                c.decimal = c.double;
            }
            Some(c)
        }
        _ => None,
    }
}

/// The column records of one tile row: `offsets` are 16-bit, in units of 4
/// bytes when `wide`, negative for an empty column.
fn row_cells<'a>(storage: &'a [u8], offsets: &[u8], wide: bool) -> Vec<(u32, &'a [u8])> {
    let starts: Vec<Option<usize>> = offsets
        .as_chunks::<2>()
        .0
        .iter()
        .map(|o| {
            let v = i16::from_le_bytes(*o);
            (v >= 0).then(|| v as usize * if wide { 4 } else { 1 })
        })
        .collect();
    let mut out = vec![];
    for (col, s) in starts.iter().enumerate() {
        let Some(s) = *s else { continue };
        let end = starts[col + 1..]
            .iter()
            .flatten()
            .next()
            .copied()
            .unwrap_or(storage.len())
            .min(storage.len());
        if let Some(rec) = storage.get(s..end.max(s)) {
            out.push((col as u32, rec));
        }
    }
    out
}

/// The number as the cell shows it without a format: no trailing zeros.
fn plain_number(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        return format!("{}", v as i64);
    }
    let s = format!("{v:.10}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// A date as ISO text, from seconds since 2001-01-01.
fn date_text(seconds: f64) -> String {
    let days = (seconds / 86_400.0).floor();
    // Days from 1970-01-01 to 2001-01-01 are 11323; civil from days.
    let z = days as i64 + 11_323 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// A style's cell properties (TST.CellStyleArchive: cell_properties 11,
/// cell_fill 1), through its parents.
fn cell_fill(store: &Store, id: Option<u64>) -> Option<Option<Color>> {
    let mut cur = id;
    for _ in 0..MAX_CHAIN {
        let (_, m) = store.get(cur?)?;
        if let Some(f) = m.msg(11).and_then(|cp| cp.msg(1)) {
            return Some(fill_color(f));
        }
        cur = m.msg(1).and_then(|s| s.reference(3));
    }
    None
}

/// A TSD.StrokeArchive as a line; `None` when it draws nothing.
fn edge(s: Msg) -> Option<Line> {
    let l = super::shapes::stroke(s, None);
    (l.fill != Fill::None && l.width > 0).then_some(l)
}

/// Each cell's left, right, top and bottom edges.
type Borders = HashMap<(u32, u32), [Option<Line>; 4]>;

struct Dims {
    rows: u32,
    cols: u32,
    header_rows: u32,
    header_cols: u32,
    footer_rows: u32,
}

/// The lines a table style draws (TST.TableStyleArchive: table_properties
/// 11, parent in field 1). TableStylePropertiesArchive: v_strokes_visible
/// 33, h_strokes_visible 34, hr_separator_visible 35, hc_separator_visible
/// 36, footer_separator_visible 37, table_border_visible 38; strokes: header
/// rows 46 (separator), 47 (border), 48 (horizontal), 49 (vertical); header
/// columns 50 (border), 51 (separator), 52, 53; footer rows 54 (separator),
/// 55 (border), 56, 57; body 58 (horizontal border), 59 (vertical border),
/// 60 (horizontal), 61 (vertical).
fn style_borders(store: &Store, model: Msg, d: &Dims, out: &mut Borders) {
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
        return;
    }
    let flag = |n: u32| chain.iter().find_map(|p| p.boolean(n)).unwrap_or(false);
    let stroke = |n: u32, shown: bool| -> Option<Line> {
        if !shown {
            return None;
        }
        edge(chain.iter().find_map(|p| p.msg(n))?)
    };
    let (v_in, h_in, hr_sep, hc_sep, ft_sep, border) =
        (flag(33), flag(34), flag(35), flag(36), flag(37), flag(38));
    let (rows, cols, hr, hc) = (d.rows, d.cols, d.header_rows, d.header_cols);
    let fr_start = rows.saturating_sub(d.footer_rows).max(hr);
    let mut put = |r: u32, c: u32, side: usize, e: &Line| {
        if r < rows && c < cols {
            out.entry((r, c)).or_default()[side] = Some(e.clone());
        }
    };
    // Horizontal lines: line y is above row y, below the last row at `rows`.
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
            let Some(e) = e else { continue };
            for c in from..to {
                if y < rows {
                    put(y, c, 2, &e);
                }
                if y > 0 {
                    put(y - 1, c, 3, &e);
                }
            }
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
            let Some(e) = e else { continue };
            for r in from..to {
                if x < cols {
                    put(r, x, 0, &e);
                }
                if x > 0 {
                    put(r, x - 1, 1, &e);
                }
            }
        }
    }
}

/// The fill of every second body row, when the table style bands rows
/// (TableStylePropertiesArchive: banded_rows 1, banded_fill 2).
fn banding(store: &Store, model: Msg) -> Option<Color> {
    let mut cur = model.reference(3);
    let mut banded = None;
    let mut fill = None;
    for _ in 0..16 {
        let Some((_, m)) = cur.and_then(|i| store.get(i)) else {
            break;
        };
        if let Some(p) = m.msg(11) {
            banded = banded.or_else(|| p.boolean(1));
            fill = fill.or_else(|| p.msg(2));
        }
        cur = m.msg(1).and_then(|s| s.reference(3));
    }
    banded.filter(|&b| b).and(fill).and_then(fill_color)
}

/// The borders strokes draw over the style's: TST.StrokeSidecarArchive
/// (left 4, right 5, top 6 and bottom 7 column or row stroke layers), each a
/// TST.StrokeLayerArchive (row_column_index 1, stroke_runs 2: origin 1,
/// length 2, stroke 3, order 4). A run of a higher order draws over a lower
/// one.
fn sidecar_borders(store: &Store, model: Msg, d: &Dims, out: &mut Borders) {
    let Some((_, side)) = model.reference(49).and_then(|r| store.get(r)) else {
        return;
    };
    // (order, side 0 left 1 right 2 top 3 bottom, line index, from, to, edge)
    let mut runs: Vec<(i64, usize, u32, u32, u32, Option<Line>)> = vec![];
    for (field, s) in [(4u32, 0usize), (5, 1), (6, 2), (7, 3)] {
        for layer in side.references(field).take(1 << 14) {
            let Some((_, l)) = store.get(layer) else {
                continue;
            };
            let idx = l.uint(1).unwrap_or(0) as u32;
            for run in l.msgs(2).take(1 << 14) {
                let origin = run.int(1).unwrap_or(0).max(0) as u32;
                let len = run.uint(2).unwrap_or(0) as u32;
                let Some(st) = run.msg(3) else { continue };
                runs.push((
                    run.int(4).unwrap_or(0),
                    s,
                    idx,
                    origin,
                    origin.saturating_add(len),
                    edge(st),
                ));
            }
        }
    }
    runs.sort_by_key(|r| r.0);
    for (_, s, idx, from, to, e) in runs {
        let horizontal = s >= 2;
        let to = if horizontal {
            to.min(d.cols)
        } else {
            to.min(d.rows)
        };
        for k in from..to {
            let (r, c) = if horizontal { (idx, k) } else { (k, idx) };
            if r >= d.rows || c >= d.cols {
                continue;
            }
            out.entry((r, c)).or_default()[s] = e.clone();
            // The cell across the line.
            let (nr, nc, ns) = match s {
                0 => (r, c.wrapping_sub(1), 1),
                1 => (r, c + 1, 0),
                2 => (r.wrapping_sub(1), c, 3),
                _ => (r + 1, c, 2),
            };
            if nr < d.rows && nc < d.cols {
                out.entry((nr, nc)).or_default()[ns] = e.clone();
            }
        }
    }
}

/// Merged ranges (first row, first column, last row, last column), from the
/// merge owner's formulas: a node of type 67 holding the row and column
/// spans in its field 40 (rows 4, columns 3, each from 1 and to 2).
fn merges(model: Msg) -> Vec<(u32, u32, u32, u32)> {
    let mut out = vec![];
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
            out.push((r1, c1, r2, c2));
        }
    }
    out
}

/// The text of a TSWP storage as a text body, in the table's text style.
fn storage_text(
    r: &mut Reader,
    store: &Store,
    storage: u64,
    number: usize,
    budget: &mut Budget,
) -> Result<Option<TextBody>> {
    match store.get(storage) {
        Some((ty::STORAGE | ty::STORAGE_2, st)) => text::body(r, st, None, number, budget),
        _ => Ok(None),
    }
}

/// A table as a shape, `None` when it has no cells or is too large.
pub fn table(
    r: &mut Reader,
    info: Msg,
    number: usize,
    budget: &mut Budget,
) -> Result<Option<Shape>> {
    let store = r.store;
    let Some(model) = info.reference(2).and_then(|i| store.typed(i, 6001)) else {
        return Ok(None);
    };
    let d = Dims {
        rows: model.uint(6).unwrap_or(0).min(u64::from(u32::MAX)) as u32,
        cols: model.uint(7).unwrap_or(0).min(u64::from(u32::MAX)) as u32,
        header_rows: model.uint(9).unwrap_or(0) as u32,
        header_cols: model.uint(10).unwrap_or(0) as u32,
        footer_rows: model.uint(11).unwrap_or(0) as u32,
    };
    if d.rows == 0 || d.cols == 0 {
        return Ok(None);
    }
    if d.rows > MAX_ROWS || d.cols > MAX_COLS || u64::from(d.rows) * u64::from(d.cols) > 1 << 18 {
        r.p.warn("tables too large to convert");
        return Ok(None);
    }
    let Some(drawable) = info.msg(1) else {
        return Ok(None);
    };
    let (xf, _, _) = super::shapes::xfrm(drawable);
    budget.shape(0)?;
    let ds = model.msg(4).unwrap_or_default();
    let strings = data_list(store, ds.reference(4));
    let styles = data_list(store, ds.reference(5));
    let rich = data_list(store, ds.reference(17));
    let style_ref = |k: Option<u32>| k.and_then(|k| styles.get(&k)).and_then(|e| e.reference(4));
    let def_h = model
        .double(16)
        .filter(|h| h.is_finite() && *h > 0.0)
        .unwrap_or(20.0);
    let def_w = model
        .double(17)
        .filter(|w| w.is_finite() && *w > 0.0)
        .unwrap_or(98.0);
    let rows_h = headers(store, ds.msg(1).unwrap_or_default().references(2), d.rows);
    let cols_h = headers(store, ds.reference(2).into_iter(), d.cols);
    let to_emu = |v: f64| (v.clamp(1.0, 20_000.0) * PT).round() as Emu;
    let mut table = Table {
        cols: (0..d.cols)
            .map(|c| {
                to_emu(
                    cols_h
                        .get(&c)
                        .map_or(def_w, |h| if h.0 > 0.0 { f64::from(h.0) } else { def_w }),
                )
            })
            .collect(),
        rows: (0..d.rows)
            .map(|rw| Row {
                h: to_emu(
                    rows_h
                        .get(&rw)
                        .map_or(def_h, |h| if h.0 > 0.0 { f64::from(h.0) } else { def_h }),
                ),
                cells: vec![Cell::default(); d.cols as usize],
            })
            .collect(),
    };
    budget.alloc(u64::from(d.rows) * u64::from(d.cols) * 256)?;
    let region = |row: u32, col: u32| {
        if row < d.header_rows {
            1
        } else if col < d.header_cols {
            2
        } else if d.footer_rows > 0 && row >= d.rows.saturating_sub(d.footer_rows) {
            3
        } else {
            0
        }
    };
    let region_cell = [18u32, 19, 20, 21].map(|f| model.reference(f));
    let region_text = [24u32, 25, 26, 27].map(|f| model.reference(f));

    let band = banding(store, model);

    // Borders.
    let mut borders: Borders = HashMap::new();
    style_borders(store, model, &d, &mut borders);
    sidecar_borders(store, model, &d, &mut borders);

    // Cells.
    let mut raws: HashMap<(u32, u32), Raw> = HashMap::new();
    let tiles = ds.msg(3).unwrap_or_default();
    let tile_size = tiles.uint(2).filter(|&s| s > 0).unwrap_or(256);
    for t in tiles.msgs(1).take(1 << 16) {
        let (Some(tid), Some((_, tile))) = (t.uint(1), t.reference(2).and_then(|x| store.get(x)))
        else {
            continue;
        };
        let bnc = tile.boolean(7).unwrap_or(false);
        for ri in tile.msgs(5).take(1 << 16) {
            let Some(row) = tid
                .checked_mul(tile_size)
                .and_then(|b| b.checked_add(ri.uint(1).unwrap_or(0)))
                .filter(|&x| x < u64::from(d.rows))
            else {
                continue;
            };
            let wide = ri.boolean(8).unwrap_or(false);
            let (storage, offsets) = match (ri.bytes(6), ri.bytes(7)) {
                (Some(s), Some(o)) if bnc || !o.is_empty() => (s, o),
                _ => (
                    ri.bytes(3).unwrap_or_default(),
                    ri.bytes(4).unwrap_or_default(),
                ),
            };
            for (col, rec) in row_cells(storage, offsets, wide) {
                if col >= d.cols {
                    continue;
                }
                if let Some(raw) = decode(rec) {
                    raws.insert((row as u32, col), raw);
                }
            }
        }
    }
    for rw in 0..d.rows {
        for col in 0..d.cols {
            let raw = raws.get(&(rw, col));
            let reg = region(rw, col);
            let cell = &mut table.rows[rw as usize].cells[col as usize];
            // Fill: the cell's style, its row's or column's, the region's.
            let fill = [
                style_ref(raw.and_then(|c| c.cell_style)),
                rows_h.get(&rw).and_then(|h| h.1),
                cols_h.get(&col).and_then(|h| h.1),
                region_cell[reg],
            ]
            .into_iter()
            .find_map(|s| cell_fill(store, s));
            if let Some(Some(c)) = fill {
                cell.fill = Fill::Solid(c);
            }
            // Every second body row, from the second, over cells that set
            // no fill of their own.
            let own = raw.is_some_and(|c| c.cell_style.is_some());
            if let Some(band) = band.filter(|_| reg == 0 && !own)
                && (rw - d.header_rows) % 2 == 1
            {
                cell.fill = Fill::Solid(band);
            }
            if let Some(b) = borders.get(&(rw, col)) {
                cell.borders = [
                    b[0].clone().unwrap_or_default(),
                    b[1].clone().unwrap_or_default(),
                    b[2].clone().unwrap_or_default(),
                    b[3].clone().unwrap_or_default(),
                ];
            }
            let Some(raw) = raw else { continue };
            let text_style = style_ref(raw.text_style).or(region_text[reg]);
            let plain = match raw.kind {
                2 | 10 => raw
                    .decimal
                    .or(raw.double)
                    .filter(|v| v.is_finite())
                    .map(plain_number),
                3 => raw
                    .string
                    .and_then(|k| strings.get(&k))
                    .and_then(|e| e.string(3)),
                5 => raw.seconds.filter(|s| s.is_finite()).map(date_text),
                6 => raw
                    .double
                    .map(|v| if v > 0.0 { "TRUE" } else { "FALSE" }.to_string()),
                7 => raw.double.filter(|v| v.is_finite()).map(plain_number),
                8 => Some("#ERROR".to_string()),
                _ => None,
            };
            if let Some(t) = plain.filter(|t| !t.is_empty()) {
                budget.alloc(t.len() as u64 * 16)?;
                let rp = text::run_props(r, text_style, None);
                let mut pp = text::para_props(r, text_style, 0, None, rp.color);
                // Numbers are at the right, as Keynote shows them.
                if pp.align.is_none() && matches!(raw.kind, 2 | 5 | 7 | 10) {
                    pp.align = Some("r");
                }
                cell.text = TextBody {
                    body: BodyProps {
                        insets: [91_440, 45_720, 91_440, 45_720],
                        anchor: "ctr",
                        ..BodyProps::default()
                    },
                    paras: vec![Paragraph {
                        props: pp,
                        runs: vec![Run {
                            kind: RunKind::Text(t),
                            props: rp.clone(),
                        }],
                        end: rp,
                    }],
                    levels: ListStyle::default(),
                };
            } else if raw.kind == 9 {
                let storage = raw
                    .rich
                    .and_then(|k| rich.get(&k))
                    .and_then(|e| e.reference(9))
                    .and_then(|p| store.get(p))
                    .and_then(|p| p.1.reference(1));
                if let Some(mut t) = match storage {
                    Some(s) => storage_text(r, store, s, number, budget)?,
                    None => None,
                } {
                    t.body.insets = [91_440, 45_720, 91_440, 45_720];
                    t.body.anchor = "ctr";
                    cell.text = t;
                }
            }
        }
    }
    // Merged cells: the first cell spans, the others are covered.
    for (r1, c1, r2, c2) in merges(model).into_iter().take(1 << 14) {
        if r1 > r2 || c1 > c2 || r2 >= d.rows || c2 >= d.cols {
            continue;
        }
        for rw in r1..=r2 {
            for col in c1..=c2 {
                let cell = &mut table.rows[rw as usize].cells[col as usize];
                if rw == r1 && col == c1 {
                    cell.grid_span = c2 - c1 + 1;
                    cell.row_span = r2 - r1 + 1;
                } else {
                    cell.h_merge = col > c1;
                    cell.v_merge = rw > r1;
                }
            }
        }
    }
    Ok(Some(Shape::new(ShapeKind::Table(Box::new(table)), xf)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_count_from_2001() {
        assert_eq!(date_text(0.0), "2001-01-01");
        assert_eq!(date_text(86_400.0 * 365.0), "2002-01-01");
        // 2004 is a leap year: 2004-03-01 is 1155 days after 2001-01-01.
        assert_eq!(date_text(86_400.0 * 1155.0), "2004-03-01");
    }

    #[test]
    fn numbers_without_a_format() {
        assert_eq!(plain_number(42.0), "42");
        assert_eq!(plain_number(0.1), "0.1");
        assert_eq!(plain_number(-1234.5678), "-1234.5678");
    }

    #[test]
    fn offsets_of_a_row() {
        let storage = b"aaaabbbbbbbbcccc";
        // Columns 0, 2 and 3; column 1 empty.
        let offs: Vec<u8> = [0i16, -1, 1, 3]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let cells = row_cells(storage, &offs, true);
        assert_eq!(
            cells,
            vec![
                (0, &storage[0..4]),
                (2, &storage[4..12]),
                (3, &storage[12..16])
            ]
        );
    }
}
