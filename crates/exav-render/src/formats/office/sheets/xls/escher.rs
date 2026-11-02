//! Office Drawing ([MS-ODRAW]) in XLS: the workbook's picture store
//! (MSODRAWINGGROUP) and each sheet's shapes (MSODRAWING), matched with the
//! OBJ records that follow them, as pictures, charts and shapes.

use super::sheet::{Obj, biff_anchor};
use super::stream::Rec;
use super::{Globals, chart};
use crate::formats::office::common::bytes::Cur;
use crate::formats::office::sheets::error::Result;
use crate::formats::office::sheets::geom::Grid;
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;
use std::io::Read;

pub(crate) struct Blip {
    pub ext: &'static str,
    pub data: Vec<u8>,
}

struct Rh {
    inst: u16,
    typ: u16,
    len: usize,
}

fn header(c: &mut Cur) -> Option<Rh> {
    if c.left() < 8 {
        return None;
    }
    let vi = c.u16();
    let typ = c.u16();
    let len = c.u32() as usize;
    Some(Rh {
        inst: vi >> 4,
        typ,
        len,
    })
}

/// The records directly in `d`: header and body.
fn children(d: &[u8]) -> Vec<(Rh, &[u8])> {
    let mut out = vec![];
    let mut c = Cur::new(d);
    while let Some(rh) = header(&mut c) {
        let end = c.p.saturating_add(rh.len).min(d.len());
        out.push((rh, &d[c.p..end]));
        c.p = end;
        if out.len() > 1 << 16 {
            break;
        }
    }
    out
}

/// Pictures of the store, in order (a shape's `pib` is 1-based in it).
pub(crate) fn blips(d: &[u8]) -> Vec<Blip> {
    let mut out = Vec::new();
    // DggContainer > BStoreContainer > BSE records.
    for (rh, body) in children(d) {
        if rh.typ != 0xF000 {
            continue;
        }
        for (rh, body) in children(body) {
            if rh.typ != 0xF001 {
                continue;
            }
            for (rh, bse) in children(body) {
                if rh.typ != 0xF007 {
                    continue;
                }
                let name_len = bse.get(33).copied().unwrap_or(0) as usize;
                let rest = bse.get(36 + name_len..).unwrap_or(&[]);
                let blip = children(rest)
                    .into_iter()
                    .next()
                    .and_then(|(bh, data)| blip(&bh, data));
                out.push(blip.unwrap_or(Blip {
                    ext: "bin",
                    data: vec![],
                }));
                if out.len() >= 1 << 16 {
                    return out;
                }
            }
        }
    }
    out
}

/// Metafiles past this size inflated are dropped.
const MAX_METAFILE: u64 = 64 << 20;

fn blip(h: &Rh, d: &[u8]) -> Option<Blip> {
    // An instance with its low bit set has a second 16-byte id.
    let two = |base: u16| if h.inst == base + 1 { 32 } else { 16 };
    let (ext, skip, meta) = match h.typ {
        0xF01A => ("emf", two(0x3D4), true),
        0xF01B => ("wmf", two(0x216), true),
        0xF01C => ("pict", two(0x542), true),
        0xF01D | 0xF02A => (
            "jpeg",
            if h.inst == 0x46B || h.inst == 0x6E3 {
                33
            } else {
                17
            },
            false,
        ),
        0xF01E => ("png", two(0x6E0) + 1, false),
        0xF01F => ("dib", two(0x7A8) + 1, false),
        0xF029 => ("tiff", two(0x6E4) + 1, false),
        _ => return None,
    };
    if !meta {
        let data = d.get(skip..)?.to_vec();
        if ext == "dib" {
            return Some(Blip {
                ext: "bmp",
                data: dib_to_bmp(&data),
            });
        }
        return Some(Blip { ext, data });
    }
    let hdr = d.get(skip..skip + 34)?;
    let body = d.get(skip + 34..)?;
    let data = if hdr[32] == 0 {
        let mut out = Vec::new();
        flate2::read::ZlibDecoder::new(body)
            .take(MAX_METAFILE)
            .read_to_end(&mut out)
            .ok()?;
        out
    } else {
        body.to_vec()
    };
    let data = if ext == "wmf" && !data.starts_with(&[0xD7, 0xCD, 0xC6, 0x9A]) {
        placeable_wmf(&data, hdr)
    } else {
        data
    };
    Some(Blip { ext, data })
}

/// A WMF without its placeable header gets one, from the blip's bounds.
fn placeable_wmf(data: &[u8], hdr: &[u8]) -> Vec<u8> {
    let mut c = Cur::at(hdr, 4);
    let mut h = vec![0xD7, 0xCD, 0xC6, 0x9A, 0, 0];
    for _ in 0..4 {
        h.extend_from_slice(&(c.i32() as i16).to_le_bytes());
    }
    h.extend_from_slice(&1440u16.to_le_bytes());
    h.extend_from_slice(&[0, 0, 0, 0]);
    let mut sum = 0u16;
    for k in 0..10 {
        sum ^= u16::from_le_bytes([h[2 * k], h[2 * k + 1]]);
    }
    h.extend_from_slice(&sum.to_le_bytes());
    h.extend_from_slice(data);
    h
}

fn dib_to_bmp(dib: &[u8]) -> Vec<u8> {
    let hsize = Cur::at(dib, 0).u32() as usize;
    let bits = Cur::at(dib, 14).u16() as u32;
    let used = Cur::at(dib, 32).u32();
    let colors = if bits <= 8 && bits > 0 {
        if used > 0 { used.min(256) } else { 1 << bits }
    } else {
        used.min(256)
    };
    let off = 14 + hsize.min(1 << 16) + colors as usize * 4;
    let mut out = Vec::with_capacity(dib.len() + 14);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&((dib.len() + 14) as u32).to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&(off as u32).to_le_bytes());
    out.extend_from_slice(dib);
    out
}

/// One shape of a sheet's drawing.
pub(crate) struct EShape {
    spt: u16,
    flags: u32,
    /// Has client data: an OBJ record follows it.
    client: bool,
    anchor: Option<[u16; 8]>,
    /// In its group's coordinates.
    child: Option<[i32; 4]>,
    /// A group's own coordinate system.
    group_rect: Option<[i32; 4]>,
    props: Vec<(u16, u32)>,
    /// The group shape this one belongs to.
    parent: Option<usize>,
}

impl EShape {
    fn prop(&self, id: u16) -> Option<u32> {
        self.props.iter().find(|p| p.0 & 0x3FFF == id).map(|p| p.1)
    }

    fn bool_prop(&self, id: u16, bit: u32) -> Option<bool> {
        let v = self.prop(id)?;
        (v & (1 << (bit + 16)) != 0).then_some(v & (1 << bit) != 0)
    }
}

fn shape(body: &[u8], parent: Option<usize>) -> EShape {
    let mut s = EShape {
        spt: 0,
        flags: 0,
        client: false,
        anchor: None,
        child: None,
        group_rect: None,
        props: vec![],
        parent,
    };
    for (rh, b) in children(body) {
        let mut c = Cur::new(b);
        match rh.typ {
            0xF00A => {
                s.spt = rh.inst;
                c.u32();
                s.flags = c.u32();
            }
            0xF009 => s.group_rect = Some([c.i32(), c.i32(), c.i32(), c.i32()]),
            0xF00F => s.child = Some([c.i32(), c.i32(), c.i32(), c.i32()]),
            0xF010 => {
                c.u16();
                let mut v = [0u16; 8];
                for x in &mut v {
                    *x = c.u16();
                }
                if !c.short {
                    s.anchor = Some(v);
                }
            }
            0xF011 => s.client = true,
            0xF00B | 0xF122 => {
                for _ in 0..rh.inst.min(512) {
                    let id = c.u16();
                    let v = c.u32();
                    if c.short {
                        break;
                    }
                    s.props.push((id, v));
                }
            }
            _ => {}
        }
    }
    s
}

fn walk_group(d: &[u8], parent: Option<usize>, out: &mut Vec<EShape>, depth: u32) {
    let mut me = parent;
    let mut first = true;
    for (rh, body) in children(d) {
        if out.len() >= 1 << 16 {
            return;
        }
        match rh.typ {
            0xF004 => {
                out.push(shape(body, if first { parent } else { me }));
                if first {
                    // A group's first shape is the group itself.
                    me = Some(out.len() - 1);
                }
                first = false;
            }
            0xF003 if depth < 32 => {
                walk_group(body, me, out, depth + 1);
                first = false;
            }
            _ => {}
        }
    }
}

/// The shapes of a sheet's drawing, in order.
pub(crate) fn shapes(d: &[u8]) -> Vec<EShape> {
    let mut out = vec![];
    for (rh, body) in children(d) {
        if rh.typ == 0xF002 {
            for (rh, b) in children(body) {
                if rh.typ == 0xF003 {
                    walk_group(b, None, &mut out, 0);
                }
            }
        } else if rh.typ == 0xF003 {
            walk_group(body, None, &mut out, 0);
        } else if rh.typ == 0xF004 {
            out.push(shape(body, None));
        }
    }
    out
}

/// An OfficeArtCOLORREF: RGB, or an index into the workbook's palette.
fn colorref(g: &Globals, v: u32) -> Option<Rgb> {
    let flags = (v >> 24) as u8;
    if flags & 0x08 != 0 {
        return g.color((v & 0xFF) as u16);
    }
    if flags & 0x10 != 0 {
        return None;
    }
    Some((v & 0xFF) << 16 | (v & 0xFF00) | (v >> 16) & 0xFF)
}

fn preset(spt: u16, obj: u16) -> Option<&'static str> {
    Some(match spt {
        1 | 202 | 75 | 109 => "rect",
        2 => "roundRect",
        3 => "ellipse",
        4 | 110 => "diamond",
        5 => "triangle",
        6 => "rtTriangle",
        7 => "parallelogram",
        8 => "trapezoid",
        9 => "hexagon",
        10 => "octagon",
        11 => "plus",
        12 => "star5",
        13 => "rightArrow",
        15 => "homePlate",
        16 => "cube",
        19 => "arc",
        20 => "line",
        22 => "can",
        23 => "donut",
        32 => "straightConnector1",
        56 => "flowChartTerminator",
        66 => "leftArrow",
        67 => "downArrow",
        68 => "upArrow",
        96 => "smileyFace",
        _ => match obj {
            1 => "line",
            2 | 6 => "rect",
            3 => "ellipse",
            4 => "arc",
            _ => "rect",
        },
    })
}

/// Pictures, charts and shapes of a sheet, from its drawing's shapes and
/// the OBJ records matched to them in order.
pub(crate) fn place(
    g: &mut Globals,
    wb: &mut Workbook,
    sheet: &mut Sheet,
    budget: &mut Budget,
    shapes: &[EShape],
    objs: &[Obj],
    recs: &[Rec],
) -> Result<()> {
    if g.book.ver < 8 {
        // BIFF5: no drawing; the objects carry their anchors.
        for o in objs {
            let Some(a) = o.anchor else { continue };
            if matches!(o.kind, 1..=4 | 6) {
                let mut s = Shape::new(a, preset(0, o.kind).unwrap_or("rect"));
                s.fill = (o.kind != 1).then_some(0xFFFFFF);
                s.line = Some(0);
                s.text.text = o.text.clone().unwrap_or_default();
                s.name = format!("Shape {}", o.id);
                sheet.shapes.push(s);
            }
        }
        return Ok(());
    }
    let client: Vec<usize> = (0..shapes.len()).filter(|&i| shapes[i].client).collect();
    // Group shapes in pixels, for their children.
    let grid = Grid::for_anchors(
        sheet,
        shapes.iter().filter_map(|s| s.anchor.map(biff_anchor)),
    );
    let anchors: Vec<Option<Anchor>> = client
        .iter()
        .map(|&si| match (shapes[si].anchor, shapes[si].parent) {
            (Some(a), _) => Some(biff_anchor(a)),
            (None, Some(_)) => rect(sheet, &grid, shapes, si, 0)
                .map(|(x0, y0, x1, y1)| grid.anchor(sheet, x0, y0, x1, y1)),
            _ => None,
        })
        .collect();
    for (k, &si) in client.iter().enumerate() {
        let Some(o) = objs.get(k) else { break };
        let s = &shapes[si];
        let Some(anchor) = anchors[k] else { continue };
        match o.kind {
            8 => {
                let Some(pib) = s.prop(0x0104) else { continue };
                let Some(b) = g.blips.get((pib as usize).wrapping_sub(1)) else {
                    continue;
                };
                if b.data.is_empty() {
                    continue;
                }
                budget.alloc(b.data.len() as u64)?;
                sheet.images.push(Image {
                    anchor,
                    ext: b.ext,
                    data: b.data.clone(),
                    name: format!("Picture {}", sheet.images.len() + 1),
                });
            }
            5 => {
                if let Some((a, b)) = o.chart
                    && let Some(ch) = chart::read_chart(g, &recs[a..b], Some(anchor), wb)
                {
                    sheet.charts.push(ch);
                }
            }
            1 | 2 | 3 | 4 | 6 | 9 | 30 => {
                if s.flags & 0x08 != 0 {
                    continue;
                }
                let geom = preset(s.spt, o.kind).unwrap_or("rect");
                let mut shp = Shape::new(anchor, geom);
                let filled = s.bool_prop(0x01BF, 4).unwrap_or(true);
                let lined = s.bool_prop(0x01FF, 3).unwrap_or(true);
                if filled && geom != "line" {
                    shp.fill = Some(
                        s.prop(0x0181)
                            .map_or(Some(0xFFFFFF), |v| colorref(g, v))
                            .unwrap_or(0xFFFFFF),
                    );
                }
                if lined {
                    shp.line = Some(
                        s.prop(0x01C0)
                            .map_or(Some(0), |v| colorref(g, v))
                            .unwrap_or(0),
                    );
                    shp.line_width = s.prop(0x01CB).map(i64::from);
                }
                shp.line_dash = match s.prop(0x01CE) {
                    Some(1) => Some("dash"),
                    Some(2) => Some("dot"),
                    Some(3) => Some("dashDot"),
                    Some(4) => Some("lgDashDotDot"),
                    Some(5..=10) => Some("sysDash"),
                    _ => None,
                };
                shp.head_arrow = s.prop(0x01D0).is_some_and(|v| v != 0);
                shp.tail_arrow = s.prop(0x01D1).is_some_and(|v| v != 0);
                shp.rotation = s
                    .prop(0x0004)
                    .map_or(0.0, |v| f64::from(v as i32) / 65536.0);
                shp.flip_h = s.flags & 0x40 != 0;
                shp.flip_v = s.flags & 0x80 != 0;
                shp.text.text = o.text.clone().unwrap_or_default();
                shp.name = format!("Shape {}", o.id);
                sheet.shapes.push(shp);
            }
            _ => {}
        }
    }
    Ok(())
}

/// A shape's rectangle in pixels: its anchor, or its place in its group.
fn rect(
    sheet: &Sheet,
    grid: &Grid,
    shapes: &[EShape],
    i: usize,
    depth: u32,
) -> Option<(f64, f64, f64, f64)> {
    let s = shapes.get(i)?;
    if let Some(a) = s.anchor {
        let a = biff_anchor(a);
        return Some((
            grid.x(sheet, a.from.0, a.from.2),
            grid.y(sheet, a.from.1, a.from.3),
            grid.x(sheet, a.to.0, a.to.2),
            grid.y(sheet, a.to.1, a.to.3),
        ));
    }
    if depth > 32 {
        return None;
    }
    let p = s.parent?;
    let (gx0, gy0, gx1, gy1) = rect(sheet, grid, shapes, p, depth + 1)?;
    let g = shapes[p].group_rect?;
    let c = s.child?;
    let (w, h) = (
        f64::from(g[2]) - f64::from(g[0]),
        f64::from(g[3]) - f64::from(g[1]),
    );
    if w <= 0.0 || h <= 0.0 {
        return None;
    }
    let fx = |v: i32| gx0 + (f64::from(v) - f64::from(g[0])) / w * (gx1 - gx0);
    let fy = |v: i32| gy0 + (f64::from(v) - f64::from(g[1])) / h * (gy1 - gy0);
    Some((fx(c[0]), fy(c[1]), fx(c[2]), fy(c[3])))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(ver: u16, inst: u16, typ: u16, body: &[u8]) -> Vec<u8> {
        let mut v = ((inst << 4) | ver).to_le_bytes().to_vec();
        v.extend_from_slice(&typ.to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn grouped_shapes_have_parents_and_child_anchors() {
        let mut grp = rec(
            1,
            0,
            0xF009,
            &[0, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, 100, 0, 0, 0],
        );
        grp.extend(rec(2, 0, 0xF00A, &[1, 4, 0, 0, 1, 0, 0, 0]));
        grp.extend(rec(0, 0, 0xF010, &[0; 18]));
        grp.extend(rec(0, 0, 0xF011, &[]));
        let mut child = rec(2, 3, 0xF00A, &[2, 4, 0, 0, 2, 0, 0, 0]);
        child.extend(rec(
            0,
            0,
            0xF00F,
            &[10, 0, 0, 0, 10, 0, 0, 0, 50, 0, 0, 0, 50, 0, 0, 0],
        ));
        child.extend(rec(0, 0, 0xF011, &[]));
        let mut group = rec(15, 0, 0xF004, &grp);
        group.extend(rec(15, 0, 0xF004, &child));
        let d = rec(15, 0, 0xF003, &group);
        let s = shapes(&d);
        assert_eq!(s.len(), 2);
        assert_eq!(s[1].parent, Some(0));
        assert_eq!(s[1].spt, 3);
        assert_eq!(s[1].child, Some([10, 10, 50, 50]));
        assert!(s[0].group_rect.is_some() && s[0].client && s[1].client);
    }

    #[test]
    fn hostile_drawings_do_not_panic() {
        let mut d = rec(15, 0, 0xF003, &[]);
        d.extend_from_slice(&[0xFF; 40]);
        let _ = shapes(&d);
        let _ = blips(&[0x0F, 0, 0, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(dib_to_bmp(&[]).len(), 14);
    }
}
