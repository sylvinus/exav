//! A worksheet substream's records to a sheet of the model.

use super::formula::{self, ExtSheet5};
use super::stream::{self, Rec};
use super::{cf, chart, escher, rich_value, Globals, SplitReader};
use crate::formats::office::common::bytes::{u16_at, Cur};
use crate::formats::office::sheets::error::Result;
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use std::collections::HashMap;

/// A shared, array or table formula, by the cell its range starts at.
struct Shared {
    range: Range,
    rgce: Vec<u8>,
    extra: Vec<u8>,
    array: bool,
}

/// A drawing object (OBJ record) and what follows it.
pub(crate) struct Obj {
    pub id: u16,
    pub kind: u16,
    /// A text box's or note's text (TXO).
    pub text: Option<String>,
    /// An embedded chart's substream, as indexes into the records.
    pub chart: Option<(usize, usize)>,
    /// BIFF5 keeps the anchor in the OBJ record.
    pub anchor: Option<Anchor>,
}

/// BIFF2 to BIFF5 OBJ anchor: columns with 1/1024 and rows with 1/256
/// offsets.
pub(crate) fn biff_anchor(v: [u16; 8]) -> Anchor {
    let fx = |d: u16| i64::from(d.min(1024)) * 1_000_000 / 1024;
    let fy = |d: u16| i64::from(d.min(256)) * 1_000_000 / 256;
    let mut to = (u32::from(v[4]), u32::from(v[6]), fx(v[5]), fy(v[7]));
    // An end at the top of a row is the bottom of the row above.
    if to.3 == 0 && to.1 > 0 {
        to.1 -= 1;
        to.3 = 1_000_000;
    }
    Anchor {
        from: (u32::from(v[0]), u32::from(v[2]), fx(v[1]), fy(v[3])),
        to,
    }
}

fn put(sheet: &mut Sheet, budget: &mut Budget, row: u32, col: u32, cell: Cell) -> Result<()> {
    if row > MAX_ROW || col > MAX_COL {
        return Ok(());
    }
    let extra = cell.value.text_len() + cell.formula.as_ref().map_or(0, |f| f.len());
    if sheet.cells.insert((row, col), cell).is_none() {
        budget.cell(extra)?;
    } else {
        budget.alloc(extra as u64)?;
    }
    Ok(())
}

/// An RK number ([MS-XLS] 2.5.217).
pub(crate) fn rk(v: u32) -> f64 {
    let x = if v & 2 != 0 {
        f64::from((v as i32) >> 2)
    } else {
        f64::from_bits(u64::from(v & 0xFFFF_FFFC) << 32)
    };
    if v & 1 != 0 {
        x / 100.0
    } else {
        x
    }
}

/// Reads the sheet; returns whether it has filter buttons (AUTOFILTERINFO),
/// which the _FilterDatabase name alone does not draw.
pub(crate) fn read_sheet(
    g: &mut Globals,
    wb: &mut Workbook,
    budget: &mut Budget,
    recs: &[Rec],
    sheet: &mut Sheet,
) -> Result<bool> {
    let ver = g.ver;
    // Shared and array formulas first: a cell's PtgExp may come before.
    let mut shared: HashMap<(u32, u32), Shared> = HashMap::new();
    let mut ext5: Vec<ExtSheet5> = vec![];
    let mut depth = 0;
    for r in recs {
        match r.id {
            id if stream::BOF_IDS.contains(&id) => depth += 1,
            0x000A => depth -= 1,
            0x04BC | 0x0221 | 0x0021 if depth == 1 => {
                let mut c = Cur::new(&r.data);
                let r1 = c.u16() as u32;
                let r2 = c.u16() as u32;
                let c1 = c.u8() as u32;
                let c2 = c.u8() as u32;
                let array = r.id != 0x04BC;
                if array {
                    c.skip(match ver {
                        5.. => 6,
                        3 | 4 => 2,
                        _ => 1,
                    });
                } else {
                    c.u16();
                }
                let cce = if ver >= 3 {
                    c.u16() as usize
                } else {
                    c.u8() as usize
                };
                let rgce = c.bytes(cce).to_vec();
                let extra = r.data[c.p.min(r.data.len())..].to_vec();
                if shared.len() < 1 << 20 {
                    shared.insert(
                        (r1, c1),
                        Shared {
                            range: Range { r1, c1, r2, c2 },
                            rgce,
                            extra,
                            array,
                        },
                    );
                }
            }
            0x0017 if depth == 1 && ver <= 5 => {
                let e = g.ext_sheet5(&r.data);
                ext5.push(e);
            }
            0x0023 if depth == 1 && ver <= 5 => {
                let mut c = Cur::at(&r.data, 6);
                let n = c.u8() as usize;
                let name = crate::formats::office::common::codepage::decode(c.bytes(n), g.codepage);
                if let Some(ExtSheet5::Names(v)) = ext5.last_mut() {
                    v.push(name);
                }
            }
            _ => {}
        }
    }
    // Shared ranges by their first row, to find the one holding a cell:
    // (first row, last row, first column, last column, key in `shared`).
    let mut by_row: Vec<(u32, u32, u32, u32, _)> = shared
        .iter()
        .map(|(k, s)| (s.range.r1, s.range.r2, s.range.c1, s.range.c2, *k))
        .collect();
    by_row.sort_unstable();

    let mut pending_string: Option<(u32, u32)> = None;
    let mut ixfe: Option<u16> = None;
    let mut objs: Vec<Obj> = vec![];
    let mut notes: Vec<(u32, u32, Option<u16>, String, bool)> = vec![];
    let mut cfs: Vec<cf::Pending> = vec![];
    let mut drawing: Vec<u8> = vec![];
    let mut defcolwidth: Option<u16> = None;
    let mut stdwidth: Option<u16> = None;
    let mut window_seen = false;
    let mut depth = 0;
    let mut has_autofilter = false;
    let mut i = 0;
    while i < recs.len() {
        let r = &recs[i];
        i += 1;
        if stream::BOF_IDS.contains(&r.id) {
            depth += 1;
            if depth == 2 {
                // An embedded chart: its substream belongs to the last object.
                let end = super::substream_end(recs, i - 1);
                if let Some(o) = objs.last_mut().filter(|o| o.chart.is_none()) {
                    o.chart = Some((i - 1, end));
                }
                i = end;
                depth = 1;
            }
            continue;
        }
        if r.id == 0x000A {
            depth -= 1;
            continue;
        }
        if depth != 1 {
            continue;
        }
        let mut c = Cur::new(&r.data);
        // A cell's style: BIFF2's 3 attribute bytes (XF 63: IXFE before),
        // a 2-byte XF index from BIFF3 on.
        macro_rules! cell_style {
            () => {
                if ver == 2 {
                    let a = c.bytes(3);
                    let attrs = [
                        a.first().copied().unwrap_or(0),
                        a.get(1).copied().unwrap_or(0),
                        a.get(2).copied().unwrap_or(0),
                    ];
                    let x = u16::from(attrs[0] & 0x3F);
                    let x = if x == 63 { ixfe.take().unwrap_or(0) } else { x };
                    g.style_of_attrs(wb, attrs, x)
                } else {
                    let x = c.u16();
                    g.style_id(wb, x)
                }
            };
        }
        match r.id {
            0x0044 => ixfe = Some(c.u16()),
            0x0201 | 0x0001 => {
                let row = c.u16() as u32;
                let col = c.u16() as u32;
                let s = cell_style!();
                put(sheet, budget, row, col, Cell::styled(s))?;
            }
            0x00BE => {
                let row = c.u16() as u32;
                let first = c.u16() as u32;
                let n = r.data.len().saturating_sub(6) / 2;
                for k in 0..n as u32 {
                    let x = c.u16();
                    let s = g.style_id(wb, x);
                    put(sheet, budget, row, first + k, Cell::styled(s))?;
                }
            }
            0x0203 | 0x0003 | 0x0002 | 0x027E | 0x007E => {
                let row = c.u16() as u32;
                let col = c.u16() as u32;
                let s = cell_style!();
                let v = match r.id {
                    0x0002 => f64::from(c.u16()),
                    0x027E | 0x007E => rk(c.u32()),
                    _ => c.f64(),
                };
                put(
                    sheet,
                    budget,
                    row,
                    col,
                    Cell {
                        value: Value::Number(v),
                        formula: None,
                        style: s,
                    },
                )?;
            }
            0x00BD => {
                let row = c.u16() as u32;
                let first = c.u16() as u32;
                let n = r.data.len().saturating_sub(6) / 6;
                for k in 0..n as u32 {
                    let x = c.u16();
                    let v = rk(c.u32());
                    let s = g.style_id(wb, x);
                    put(
                        sheet,
                        budget,
                        row,
                        first + k,
                        Cell {
                            value: Value::Number(v),
                            formula: None,
                            style: s,
                        },
                    )?;
                }
            }
            0x0204 | 0x0004 | 0x00D6 => {
                let row = c.u16() as u32;
                let col = c.u16() as u32;
                let s = cell_style!();
                let text = if ver == 2 {
                    g.string(&mut c, 1)
                } else if ver >= 8 {
                    let mut sr = SplitReader {
                        d: &r.data,
                        breaks: &r.breaks,
                        p: c.p,
                    };
                    let n = sr.u16() as usize;
                    let f = sr.u8();
                    let t = sr.chars(n, f & 1 != 0);
                    c.p = sr.p;
                    t
                } else {
                    g.string(&mut c, 2)
                };
                let value = if r.id == 0x00D6 {
                    let n = if ver >= 8 {
                        c.u16() as usize
                    } else {
                        c.u8() as usize
                    };
                    let mut runs = vec![];
                    for _ in 0..n {
                        if c.left() == 0 {
                            break;
                        }
                        runs.push(if ver >= 8 {
                            (c.u16(), c.u16())
                        } else {
                            (u16::from(c.u8()), u16::from(c.u8()))
                        });
                    }
                    rich_value(g, text, &runs)
                } else {
                    Value::text(text)
                };
                put(
                    sheet,
                    budget,
                    row,
                    col,
                    Cell {
                        value,
                        formula: None,
                        style: s,
                    },
                )?;
            }
            0x00FD => {
                let row = c.u16() as u32;
                let col = c.u16() as u32;
                let x = c.u16();
                let i = c.u32() as usize;
                let value = g.sst.get(i).cloned().unwrap_or(Value::Empty);
                let s = g.style_id(wb, x);
                put(
                    sheet,
                    budget,
                    row,
                    col,
                    Cell {
                        value,
                        formula: None,
                        style: s,
                    },
                )?;
            }
            0x0205 | 0x0005 => {
                let row = c.u16() as u32;
                let col = c.u16() as u32;
                let s = cell_style!();
                let v = c.u8();
                let e = c.u8();
                let value = if e != 0 {
                    Value::Error(CellError::from_biff(v).unwrap_or(CellError::NA))
                } else {
                    Value::Bool(v != 0)
                };
                put(
                    sheet,
                    budget,
                    row,
                    col,
                    Cell {
                        value,
                        formula: None,
                        style: s,
                    },
                )?;
            }
            0x0006 | 0x0206 | 0x0406 => {
                let row = c.u16() as u32;
                let col = c.u16() as u32;
                let s = cell_style!();
                let res = c.bytes(8).to_vec();
                let cce = if ver == 2 {
                    c.u8();
                    c.u8() as usize
                } else {
                    c.u16();
                    if ver >= 5 {
                        c.u32();
                    }
                    c.u16() as usize
                };
                let rgce = c.bytes(cce).to_vec();
                let extra = r.data[c.p.min(r.data.len())..].to_vec();
                let value = if res.len() < 8 {
                    Value::Empty
                } else if res[6] == 0xFF && res[7] == 0xFF {
                    match res[0] {
                        0 => {
                            pending_string = Some((row, col));
                            Value::Empty
                        }
                        1 => Value::Bool(res[2] != 0),
                        2 => Value::Error(CellError::from_biff(res[2]).unwrap_or(CellError::NA)),
                        // An empty string.
                        3 => Value::text(""),
                        _ => Value::Empty,
                    }
                } else {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&res);
                    Value::Number(f64::from_le_bytes(b))
                };
                let ctx = g.ctx(&ext5);
                let mut f = None;
                match formula::decode(&ctx, &rgce, &extra, row, col) {
                    Ok(d) if d.exp.is_some() => {
                        let (ar, ac) = d.exp.unwrap_or_default();
                        // The record at the cell the token names, else one whose
                        // range holds the cell (some writers start it elsewhere).
                        let found = shared.get(&(ar, ac)).or_else(|| {
                            let end = by_row.partition_point(|e| e.0 <= row);
                            by_row[..end]
                                .iter()
                                .rev()
                                .take(64)
                                .find(|e| e.1 >= row && e.2 <= col && e.3 >= col)
                                .and_then(|e| shared.get(&e.4))
                        });
                        if let Some(sh) = found {
                            if sh.array {
                                if (row, col) == (sh.range.r1, sh.range.c1) {
                                    if let Ok(dd) =
                                        formula::decode(&ctx, &sh.rgce, &sh.extra, row, col)
                                    {
                                        f = Some(dd.text);
                                        sheet.arrays.insert((row, col), sh.range);
                                    }
                                }
                            } else if let Ok(dd) =
                                formula::decode(&ctx, &sh.rgce, &sh.extra, row, col)
                            {
                                f = Some(dd.text);
                            }
                        }
                    }
                    Ok(d) if d.table => {}
                    Ok(d) => f = Some(d.text),
                    Err(e) => wb.warn(format!("formula at {}: {e}", cell_ref(row, col))),
                }
                put(
                    sheet,
                    budget,
                    row,
                    col,
                    Cell {
                        value,
                        formula: f.map(String::into_boxed_str),
                        style: s,
                    },
                )?;
            }
            0x0207 | 0x0007 => {
                if let Some(at) = pending_string.take() {
                    let s = if ver == 2 {
                        g.string(&mut c, 1)
                    } else if ver >= 8 {
                        let mut sr = SplitReader {
                            d: &r.data,
                            breaks: &r.breaks,
                            p: 0,
                        };
                        let n = sr.u16() as usize;
                        let f = sr.u8();
                        sr.chars(n, f & 1 != 0)
                    } else {
                        g.string(&mut c, 2)
                    };
                    budget.alloc(s.len() as u64)?;
                    if let Some(cell) = sheet.cells.get_mut(&at) {
                        cell.value = Value::text(s);
                    }
                }
            }
            0x0208 | 0x0008 => {
                let row = c.u16() as u32;
                c.skip(4);
                let h = c.u16();
                let mut info = RowInfo {
                    height: Some(f64::from(h & 0x7FFF) / 20.0),
                    ..Default::default()
                };
                if ver == 2 {
                    info.custom_height = h & 0x8000 == 0;
                    c.skip(2);
                    if c.u8() == 1 {
                        c.skip(5);
                        let x = c.u16();
                        info.style = Some(g.style_id(wb, x)).filter(|&s| s != 0);
                    }
                } else {
                    c.skip(4);
                    let flags = c.u16();
                    let x = c.u16();
                    info.outline = (flags & 7) as u8;
                    info.hidden = flags & 0x20 != 0;
                    info.custom_height = flags & 0x40 != 0;
                    if flags & 0x80 != 0 {
                        let x = if ver >= 8 { x & 0xFFF } else { x };
                        info.style = Some(g.style_id(wb, x));
                    }
                }
                if row <= MAX_ROW {
                    budget.alloc(48)?;
                    sheet.rows.insert(row, info);
                }
            }
            0x007D => {
                let first = c.u16() as u32;
                let last = c.u16() as u32;
                let w = c.u16();
                let x = c.u16();
                let flags = c.u16();
                let st = g.style_id(wb, x);
                if first <= MAX_COL && sheet.cols.len() < 1 << 16 {
                    sheet.cols.push(ColInfo {
                        first,
                        last: last.clamp(first, MAX_COL),
                        width: Some(f64::from(w) / 256.0),
                        hidden: flags & 1 != 0,
                        style: Some(st).filter(|&s| s != 0),
                        outline: ((flags >> 8) & 7) as u8,
                    });
                }
            }
            0x0024 => {
                let first = c.u8() as u32;
                let last = c.u8() as u32;
                let w = c.u16();
                sheet.cols.push(ColInfo {
                    first,
                    last: last.max(first),
                    width: Some(f64::from(w) / 256.0),
                    ..Default::default()
                });
            }
            0x0020 => {
                // BIFF2 COLUMNDEFAULT: a style per column.
                let first = c.u16() as u32;
                let last = c.u16() as u32;
                for col in first..last.min(first + 256) {
                    let a = c.bytes(3);
                    if a.len() < 3 {
                        break;
                    }
                    let attrs = [a[0], a[1], a[2]];
                    let s = g.style_of_attrs(wb, attrs, u16::from(a[0] & 0x3F));
                    if s != 0 {
                        match sheet
                            .cols
                            .iter_mut()
                            .find(|x| x.first == col && x.last == col)
                        {
                            Some(ci) => ci.style = Some(s),
                            None => sheet.cols.push(ColInfo {
                                first: col,
                                last: col,
                                style: Some(s),
                                ..Default::default()
                            }),
                        }
                    }
                }
            }
            0x0055 => defcolwidth = Some(c.u16()),
            0x0099 => stdwidth = Some(c.u16()),
            0x0225 => {
                let flags = c.u16();
                let h = c.u16();
                sheet.default_row_height = f64::from(h) / 20.0;
                sheet.default_row_custom = flags & 1 != 0;
                sheet.default_row_hidden = flags & 2 != 0;
            }
            0x0025 => {
                let h = c.u16();
                sheet.default_row_height = f64::from(h & 0x7FFF) / 20.0;
            }
            0x00E5 => {
                let n = c.u16() as usize;
                for _ in 0..n {
                    let r1 = c.u16() as u32;
                    let r2 = c.u16() as u32;
                    let c1 = c.u16() as u32;
                    let c2 = c.u16() as u32;
                    if c.short {
                        break;
                    }
                    if r2 >= r1 && c2 >= c1 && (r2 > r1 || c2 > c1) && sheet.merges.len() < 1 << 20
                    {
                        sheet.merges.push(Range { r1, c1, r2, c2 });
                    }
                }
            }
            0x023E if !window_seen => {
                window_seen = true;
                let f = c.u16();
                let top = c.u16() as u32;
                let left = c.u16() as u32;
                sheet.show_grid = f & 2 != 0;
                sheet.show_headers = f & 4 != 0;
                sheet.show_zeros = f & 0x10 != 0;
                sheet.rtl = f & 0x40 != 0;
                if f & 8 != 0 {
                    sheet.freeze = Some((0, 0));
                }
                if top > 0 || left > 0 {
                    sheet.top_left = Some((top, left));
                }
                if ver >= 8 && r.data.len() >= 14 {
                    let normal = u16_at(&r.data, 12);
                    if normal != 0 {
                        sheet.zoom = u32::from(normal);
                    }
                }
            }
            0x003E if !window_seen => {
                window_seen = true;
                c.u8();
                sheet.show_grid = c.u8() != 0;
                sheet.show_headers = c.u8() != 0;
                let frozen = c.u8() != 0;
                sheet.show_zeros = c.u8() != 0;
                if frozen {
                    sheet.freeze = Some((0, 0));
                }
            }
            0x0041 => {
                let x = c.u16() as u32;
                let y = c.u16() as u32;
                if sheet.freeze.is_some() {
                    sheet.freeze = Some((y, x));
                }
            }
            0x00A0 => {
                let num = c.u16() as u32;
                let den = c.u16() as u32;
                if let Some(z) = (num * 100).checked_div(den) {
                    sheet.zoom = z;
                }
            }
            0x0081 => {
                let f = c.u16();
                sheet.outline_below = f & 0x40 != 0;
                sheet.outline_right = f & 0x80 != 0;
            }
            0x0862 if ver >= 8 => {
                // SHEETEXT: the tab colour.
                c.skip(12);
                let cb = c.u32();
                let icv = c.u32() & 0x7F;
                if cb >= 20 || icv != 0x7F {
                    sheet.tab_color = g.color(icv as u16);
                }
            }
            0x0012 => sheet.protected = c.u16() != 0,
            0x009D => has_autofilter = true,
            0x01B8 => {
                if let Some(h) = read_hlink(&r.data) {
                    if sheet.hyperlinks.len() < 1 << 16 {
                        sheet.hyperlinks.push(h);
                    }
                }
            }
            0x0800 => {
                c.skip(2);
                let r1 = c.u16() as u32;
                c.u16();
                let c1 = c.u16() as u32;
                c.u16();
                let n = r.data.len().saturating_sub(10) / 2;
                let t = formula::read_chars(&mut c, n, true);
                if let Some(h) = sheet
                    .hyperlinks
                    .iter_mut()
                    .rev()
                    .find(|h| h.range.r1 == r1 && h.range.c1 == c1)
                {
                    h.tooltip = Some(t.trim_end_matches('\0').to_string());
                }
            }
            0x00EC => {
                budget.alloc(r.data.len() as u64)?;
                drawing.extend_from_slice(&r.data);
            }
            0x005D => {
                if objs.len() >= 1 << 16 {
                    continue;
                }
                if ver >= 8 {
                    // The first subrecord, ftCmo, has the type and id.
                    c.skip(4);
                    let kind = c.u16();
                    let id = c.u16();
                    objs.push(Obj {
                        id,
                        kind,
                        text: None,
                        chart: None,
                        anchor: None,
                    });
                } else {
                    c.u32();
                    let kind = c.u16();
                    let id = c.u16();
                    c.u16();
                    let mut v = [0u16; 8];
                    for x in &mut v {
                        *x = c.u16();
                    }
                    let anchor = (!c.short).then(|| biff_anchor(v));
                    objs.push(Obj {
                        id,
                        kind,
                        text: None,
                        chart: None,
                        anchor,
                    });
                }
            }
            0x01B6 => {
                if let Some(o) = objs.last_mut() {
                    o.text = Some(read_txo(&r.data, &r.breaks));
                }
            }
            0x001C => {
                let row = c.u16() as u32;
                let col = c.u16() as u32;
                if ver >= 8 {
                    let flags = c.u16();
                    let id = c.u16();
                    let author = g.string(&mut c, 2);
                    notes.push((row, col, Some(id), author, flags & 2 != 0));
                } else {
                    let n = c.u16() as usize;
                    let text = crate::formats::office::common::codepage::decode(
                        c.bytes(n.min(2048)),
                        g.codepage,
                    );
                    if row == 0xFFFF {
                        if let Some(last) = notes.last_mut() {
                            if last.3.len() < 1 << 20 {
                                last.3.push_str(&text);
                            }
                        }
                    } else if notes.len() < 1 << 16 {
                        notes.push((row, col, None, text, false));
                    }
                }
            }
            0x01B0 | 0x0879 => {
                if let Some(p) = cf::header(&r.data, r.id == 0x0879) {
                    cfs.push(p);
                }
            }
            0x01B1 | 0x087A | 0x087B => {
                let ctx = g.ctx(&ext5);
                cf::rule(g, &ctx, r, &mut cfs);
            }
            0x01BE => {
                let ctx = g.ctx(&ext5);
                if let Some(v) = cf::validation(&ctx, &r.data, &r.breaks) {
                    if sheet.validations.len() < 1 << 16 {
                        sheet.validations.push(v);
                    }
                }
            }
            _ => {}
        }
    }
    sheet.cond_formats = cf::finish(cfs);
    for (row, col, id, text_or_author, visible) in notes {
        let (author, text) = match id {
            None => (String::new(), text_or_author),
            Some(id) => (
                text_or_author,
                objs.iter()
                    .find(|o| o.id == id)
                    .and_then(|o| o.text.clone())
                    .unwrap_or_default(),
            ),
        };
        sheet.comments.push(Comment {
            row,
            col,
            author,
            text,
            visible,
        });
    }
    default_widths(sheet, wb, stdwidth, defcolwidth);
    row_styles(sheet, budget)?;
    for cell in sheet.cells.values_mut() {
        // A first run without a font has the cell's.
        if let Value::Rich(runs) = &cell.value {
            if runs.first().is_some_and(|r| r.font.is_none()) {
                let mut v: Vec<Run> = runs.to_vec();
                v[0].font = Some(wb.styles.get(cell.style).font.clone());
                cell.value = Value::Rich(v.into());
            }
        }
    }
    let shapes = if drawing.is_empty() {
        vec![]
    } else {
        escher::shapes(&drawing)
    };
    escher::place(g, wb, sheet, budget, &shapes, &objs, recs)?;
    for o in &objs {
        // BIFF5 charts, anchored by their OBJ record.
        if ver < 8 && o.kind == 5 {
            if let (Some((a, b)), Some(anchor)) = (o.chart, o.anchor) {
                if let Some(ch) = chart::read_chart(g, &recs[a..b], Some(anchor), wb) {
                    sheet.charts.push(ch);
                }
            }
        }
    }
    Ok(has_autofilter)
}

/// A row's default format shows in its cells that have no record. XLSX
/// readers that draw only cells and column formats would leave them
/// blank, so they are written as cells, over the 256 columns of an XLS
/// sheet, or up to the last used column when that would be too many.
fn row_styles(sheet: &mut Sheet, budget: &mut Budget) -> Result<()> {
    let styled: Vec<(u32, u32)> = sheet
        .rows
        .iter()
        .filter_map(|(&r, i)| i.style.map(|s| (r, s)))
        .collect();
    if styled.is_empty() {
        return Ok(());
    }
    let mut ncols = 256u32;
    if styled.len() as u64 * 256 > 1_000_000 || !budget.room_for_cells(styled.len() as u64 * 256) {
        ncols = sheet
            .cells
            .keys()
            .map(|k| k.1 + 1)
            .max()
            .unwrap_or(0)
            .min(256);
    }
    for (r, s) in styled {
        for c in 0..ncols {
            if let std::collections::btree_map::Entry::Vacant(e) = sheet.cells.entry((r, c)) {
                if !budget.room_for_cells(1) {
                    return Ok(());
                }
                e.insert(Cell::styled(s));
                budget.cell(0)?;
            }
        }
    }
    Ok(())
}

/// The default column width: STANDARDWIDTH, else DEFCOLWIDTH characters
/// and the padding a column has around its text.
fn default_widths(
    sheet: &mut Sheet,
    wb: &Workbook,
    stdwidth: Option<u16>,
    defcolwidth: Option<u16>,
) {
    let font_pt = wb.styles.get(0).font.size_pt();
    match stdwidth {
        Some(w) => sheet.default_col_width = Some(f64::from(w) / 256.0),
        None => {
            let base = f64::from(defcolwidth.unwrap_or(8));
            sheet.default_col_width = Some(base + 10.546875 / font_pt.max(1.0));
        }
    }
    if let Some(w) = defcolwidth {
        sheet.base_col_width = Some(u32::from(w));
    }
}

fn read_txo(d: &[u8], breaks: &[usize]) -> String {
    let cch = u16_at(d, 10) as usize;
    let Some(&start) = breaks.first() else {
        return String::new();
    };
    let mut sr = SplitReader {
        d,
        breaks,
        p: start,
    };
    let wide = sr.u8() & 1 != 0;
    sr.chars(cch, wide)
}

fn hl_string(c: &mut Cur) -> String {
    let n = c.u32() as usize;
    let m = n.min(c.left() / 2);
    formula::read_chars(c, m, true)
        .trim_end_matches('\0')
        .to_string()
}

fn read_hlink(d: &[u8]) -> Option<Hyperlink> {
    let mut c = Cur::new(d);
    let r1 = c.u16() as u32;
    let r2 = c.u16() as u32;
    let c1 = c.u16() as u32;
    let c2 = c.u16() as u32;
    c.skip(16);
    c.u32();
    let flags = c.u32();
    let mut h = Hyperlink {
        range: Range { r1, c1, r2, c2 },
        url: None,
        location: None,
        tooltip: None,
        display: None,
    };
    if flags & 0x14 != 0 {
        h.display = Some(hl_string(&mut c));
    }
    if flags & 0x80 != 0 {
        hl_string(&mut c);
    }
    if flags & 0x1 != 0 {
        if flags & 0x100 != 0 {
            h.url = Some(hl_string(&mut c));
        } else {
            let clsid = c.bytes(16).to_vec();
            const URL: [u8; 16] = [
                0xE0, 0xC9, 0xEA, 0x79, 0xF9, 0xBA, 0xCE, 0x11, 0x8C, 0x82, 0x00, 0xAA, 0x00, 0x4B,
                0xA9, 0x0B,
            ];
            const FILE: [u8; 16] = [0x03, 0x03, 0, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
            if clsid == URL {
                let n = c.u32() as usize;
                let m = (n / 2).min(c.left() / 2);
                let s = formula::read_chars(&mut c, m, true);
                h.url = Some(s.split('\0').next().unwrap_or("").to_string());
            } else if clsid == FILE {
                let up = c.u16();
                let n = c.u32() as usize;
                let ansi = c.bytes(n);
                let mut path: String = ansi
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as char)
                    .collect();
                c.skip(24);
                if c.u32() > 0 {
                    let nb = c.u32() as usize;
                    c.u16();
                    path = formula::read_chars(&mut c, nb / 2, true);
                }
                h.url = Some(format!("{}{path}", "../".repeat(usize::from(up.min(64)))));
            } else {
                return None;
            }
        }
    }
    if flags & 0x8 != 0 {
        h.location = Some(hl_string(&mut c));
    }
    if h.url.as_deref().is_some_and(|u| !safe_url(u)) {
        h.url = None;
    }
    if h.url.is_none() && h.location.is_none() {
        return None;
    }
    Some(h)
}
