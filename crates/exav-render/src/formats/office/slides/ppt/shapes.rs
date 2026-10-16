//! OfficeArt shapes to the model: anchors, geometry (preset and custom
//! paths), fills, lines, shadows and pictures ([MS-ODRAW] 2.3).

use super::escher::{array, OShape, Props, F_CONNECTOR, F_FLIP_H, F_FLIP_V};
use super::presets;
use crate::formats::office::common::bytes::Cur;
use crate::formats::office::slides::model::*;

/// What converting a slide's shapes needs.
pub struct Ctx<'a> {
    pub scheme: &'a [Rgb; 8],
    /// A picture store entry (1-based `pib`) to the model's media index.
    pub blips: &'a [Option<usize>],
}

/// A 16.16 fixed-point value.
fn fixed(v: u32) -> f64 {
    f64::from(v as i32) / 65536.0
}

fn alpha(v: Option<u32>) -> Option<u32> {
    v.map(|o| ((f64::from(o.min(65536)) / 65536.0) * 100_000.0).round() as u32)
        .filter(|&a| a < 100_000)
}

/// Applies a procedural colour change ([MS-ODRAW] 2.2.2) to `c`.
fn modify(c: Rgb, op: u32, p: u32) -> Rgb {
    let ch = |c: Rgb, s: u32| (c >> s) & 0xFF;
    let mut v = [ch(c, 16), ch(c, 8), ch(c, 0)];
    if op & 0x8000 != 0 {
        let g = (v[0] * 77 + v[1] * 151 + v[2] * 28) >> 8;
        v = [g, g, g];
    }
    for x in &mut v {
        *x = match op & 0x0F00 {
            0x0100 => *x * p / 255,
            0x0200 => 255 - (255 - *x) * p / 255,
            0x0300 => (*x + p).min(255),
            0x0400 => x.saturating_sub(p),
            0x0500 => p.saturating_sub(*x),
            0x0600 => {
                if *x < p {
                    0
                } else {
                    255
                }
            }
            _ => *x,
        };
        if op & 0x2000 != 0 {
            *x = 255 - *x;
        }
        if op & 0x4000 != 0 {
            *x ^= 0x80;
        }
    }
    v[0] << 16 | v[1] << 8 | v[2]
}

/// The colours a system index can refer to.
#[derive(Clone, Copy, Default)]
pub struct Refs {
    pub fill: Rgb,
    pub line: Rgb,
    pub fill_back: Rgb,
    pub line_back: Rgb,
    pub shadow: Rgb,
}

/// An OfficeArtCOLORREF as RGB.
pub fn color(v: u32, scheme: &[Rgb; 8], refs: &Refs) -> Rgb {
    let flags = v >> 24;
    if flags & 0x08 != 0 {
        return scheme[(v & 7) as usize];
    }
    if flags & 0x10 != 0 {
        let idx = v & 0xFFFF;
        let base = match idx & 0xFF {
            0xF0 => refs.fill,
            0xF1 => refs.line,
            0xF2 => refs.line,
            0xF3 => refs.shadow,
            0xF5 => refs.fill_back,
            0xF6 => refs.line_back,
            0xF7 => refs.fill,
            // Windows system colours: window text black, window white...
            5 => 0xFFFFFF,
            _ => 0x000000,
        };
        return modify(base, idx & 0xFF00, (v >> 16) & 0xFF);
    }
    (v & 0xFF) << 16 | (v & 0xFF00) | (v >> 16) & 0xFF
}

/// The shape's colours, resolved in the order they depend on each other.
pub fn refs(p: &Props, scheme: &[Rgb; 8]) -> Refs {
    let mut r = Refs {
        fill: 0xFFFFFF,
        line: 0x000000,
        fill_back: 0xFFFFFF,
        line_back: 0xFFFFFF,
        shadow: 0x808080,
    };
    r.fill = color(p.get(0x0181).unwrap_or(0xFFFFFF), scheme, &r);
    r.line = color(p.get(0x01C0).unwrap_or(0), scheme, &r);
    r.fill_back = color(p.get(0x0183).unwrap_or(0xFFFFFF), scheme, &r);
    r.line_back = color(p.get(0x01C2).unwrap_or(0xFFFFFF), scheme, &r);
    r.shadow = color(p.get(0x0201).unwrap_or(0x808080), scheme, &r);
    r
}

pub fn fill(p: &Props, ctx: &Ctx, refs: &Refs) -> Fill {
    if p.flag(0x01BF, 4) == Some(false) {
        return Fill::None;
    }
    let a = alpha(p.get(0x0182));
    let back_a = alpha(p.get(0x0184));
    let fg = Color {
        rgb: refs.fill,
        alpha: a,
    };
    let bg = Color {
        rgb: refs.fill_back,
        alpha: back_a,
    };
    match p.get(0x0180).unwrap_or(0) {
        1 => {
            // A two-colour pattern bitmap: its colours blended.
            let mix = |s: u32| (((refs.fill >> s) & 0xFF) + ((refs.fill_back >> s) & 0xFF)) / 2;
            Fill::Solid(Color {
                rgb: mix(16) << 16 | mix(8) << 8 | mix(0),
                alpha: a,
            })
        }
        k @ (2 | 3) => match picture(p.get(0x0186), ctx) {
            Some(media) => Fill::Picture {
                media,
                tile: k == 2,
            },
            None => Fill::Solid(fg),
        },
        k @ 4..=8 => gradient(p, k, fg, bg, ctx, refs),
        9 => Fill::None,
        _ => Fill::Solid(fg),
    }
}

fn picture(pib: Option<u32>, ctx: &Ctx) -> Option<usize> {
    let i = pib? as usize;
    ctx.blips.get(i.checked_sub(1)?).copied().flatten()
}

fn gradient(p: &Props, kind: u32, fg: Color, bg: Color, ctx: &Ctx, refs: &Refs) -> Fill {
    let mut stops: Vec<(u32, Color)> = vec![];
    if let Some(d) = p.complex(0x0197) {
        for e in array(d) {
            let mut c = Cur::new(e);
            let col = c.u32();
            let pos = fixed(c.u32()).clamp(0.0, 1.0);
            stops.push((
                (pos * 100_000.0).round() as u32,
                Color {
                    rgb: color(col, ctx.scheme, refs),
                    alpha: fg.alpha,
                },
            ));
        }
    }
    let focus = p.int(0x018C).unwrap_or(0).clamp(-100, 100);
    if stops.len() < 2 {
        // fillColor is the first colour, fillBackColor the last; focus
        // places the last: 100 at the end, 0 at the start, 50 in the middle
        // with the first at both ends. Negative values mirror it.
        stops = match focus.abs() {
            0 => vec![(0, bg), (100_000, fg)],
            100 => vec![(0, fg), (100_000, bg)],
            f => vec![(0, fg), (f as u32 * 1000, bg), (100_000, fg)],
        };
        if focus < 0 && focus > -100 {
            stops = vec![(0, bg), ((100 + focus) as u32 * 1000, fg), (100_000, bg)];
        }
    } else if focus != 0 && focus.abs() != 100 {
        // The colours run to the focus and back.
        let f = focus.unsigned_abs() * 1000;
        let mut v: Vec<(u32, Color)> = stops
            .iter()
            .map(|(pos, c)| ((*pos as u64 * f as u64 / 100_000) as u32, *c))
            .collect();
        v.extend(stops.iter().rev().map(|(pos, c)| {
            (
                f + ((100_000 - *pos) as u64 * (100_000 - f) as u64 / 100_000) as u32,
                *c,
            )
        }));
        stops = v;
    } else if focus == 0 {
        stops = stops
            .iter()
            .rev()
            .map(|(pos, c)| (100_000 - pos, *c))
            .collect();
    }
    let kind = match kind {
        4 | 7 => {
            // Zero degrees runs from the bottom up; DrawingML's from the left.
            let a = fixed(p.get(0x018B).unwrap_or(0));
            GradientKind::Linear((270.0 - a).rem_euclid(360.0))
        }
        5 | 8 => {
            let r = |id: u16| {
                (fixed(p.get(id).unwrap_or(0)).clamp(0.0, 1.0) * 100_000.0).round() as i32
            };
            let (l, t, rr, b) = (r(0x018D), r(0x018E), r(0x018F), r(0x0190));
            stops = stops
                .iter()
                .rev()
                .map(|(pos, c)| (100_000 - pos, *c))
                .collect();
            GradientKind::Path("rect", [l, t, 100_000 - rr, 100_000 - b])
        }
        _ => {
            stops = stops
                .iter()
                .rev()
                .map(|(pos, c)| (100_000 - pos, *c))
                .collect();
            GradientKind::Path("shape", [50_000, 50_000, 50_000, 50_000])
        }
    };
    stops.sort_by_key(|s| s.0);
    Fill::Gradient(Gradient { stops, kind })
}

fn arrow(kind: Option<u32>, w: Option<u32>, l: Option<u32>) -> Option<Arrow> {
    let kind = match kind? {
        1 => "triangle",
        2 => "stealth",
        3 => "diamond",
        4 => "oval",
        5..=7 => "arrow",
        _ => return None,
    };
    let size = |v: Option<u32>| match v.unwrap_or(1) {
        0 => "sm",
        2 => "lg",
        _ => "med",
    };
    Some(Arrow {
        kind,
        w: size(w),
        len: size(l),
    })
}

pub fn line(p: &Props, refs: &Refs) -> Line {
    if p.flag(0x01FF, 3) == Some(false) {
        return Line::default();
    }
    let width = p
        .get(0x01CB)
        .map(|w| i64::from(w as i32))
        .unwrap_or(9525)
        .max(0);
    Line {
        fill: Fill::Solid(Color {
            rgb: refs.line,
            alpha: alpha(p.get(0x01C1)),
        }),
        width,
        dash: match p.get(0x01CE).unwrap_or(0) {
            1 | 6 => Some("dash"),
            2 => Some("sysDot"),
            3 | 8 => Some("dashDot"),
            4 => Some("sysDashDotDot"),
            5 => Some("dot"),
            7 => Some("lgDash"),
            9 => Some("lgDashDot"),
            10 => Some("lgDashDotDot"),
            _ => None,
        },
        cap: match p.get(0x01D7) {
            Some(0) => Some("rnd"),
            Some(1) => Some("sq"),
            Some(2) => Some("flat"),
            _ => None,
        },
        join: match p.get(0x01D6) {
            Some(0) => Some("bevel"),
            Some(1) => Some("miter"),
            Some(2) => Some("round"),
            _ => None,
        },
        compound: match p.get(0x01CD).unwrap_or(0) {
            1 => Some("dbl"),
            2 => Some("thickThin"),
            3 => Some("thinThick"),
            4 => Some("tri"),
            _ => None,
        },
        head: arrow(p.get(0x01D0), p.get(0x01D2), p.get(0x01D3)),
        tail: arrow(p.get(0x01D1), p.get(0x01D4), p.get(0x01D5)),
    }
}

pub fn shadow(p: &Props, refs: &Refs) -> Option<Shadow> {
    if p.flag(0x023F, 1) != Some(true) {
        return None;
    }
    let dx = p.int(0x0205).unwrap_or(25400) as f64;
    let dy = p.int(0x0206).unwrap_or(25400) as f64;
    Some(Shadow {
        color: Color {
            rgb: refs.shadow,
            alpha: alpha(p.get(0x0204)),
        },
        blur: 0,
        dist: dx.hypot(dy).round() as Emu,
        dir: dy.atan2(dx).to_degrees(),
    })
}

/// Points along an elliptical arc as cubic Béziers: centre, radii, start
/// angle and sweep in radians.
fn arc_cubics(cx: f64, cy: f64, rx: f64, ry: f64, start: f64, sweep: f64, out: &mut Vec<PathCmd>) {
    let n = (sweep.abs() / std::f64::consts::FRAC_PI_2)
        .ceil()
        .clamp(1.0, 16.0) as usize;
    let step = sweep / n as f64;
    let k = 4.0 / 3.0 * (step / 4.0).tan();
    let mut a = start;
    for _ in 0..n {
        let b = a + step;
        let (ca, sa, cb, sb) = (a.cos(), a.sin(), b.cos(), b.sin());
        let p1 = (cx + rx * (ca - k * sa), cy + ry * (sa + k * ca));
        let p2 = (cx + rx * (cb + k * sb), cy + ry * (sb - k * cb));
        let p3 = (cx + rx * cb, cy + ry * sb);
        out.push(PathCmd::Cubic(
            p1.0.round() as i64,
            p1.1.round() as i64,
            p2.0.round() as i64,
            p2.1.round() as i64,
            p3.0.round() as i64,
            p3.1.round() as i64,
        ));
        a = b;
    }
}

/// A custom geometry from pVertices and pSegmentInfo, or `None`.
pub fn custom(p: &Props) -> Option<Geometry> {
    let verts = array(p.complex(0x0145)?);
    if verts.is_empty() {
        return None;
    }
    let pts: Vec<(i64, i64)> = verts
        .iter()
        .map(|e| {
            let mut c = Cur::new(e);
            if e.len() >= 8 {
                (c.i32().into(), c.i32().into())
            } else {
                (c.i16().into(), c.i16().into())
            }
        })
        .collect();
    let left = i64::from(p.int(0x0140).unwrap_or(0));
    let top = i64::from(p.int(0x0141).unwrap_or(0));
    let right = i64::from(p.int(0x0142).unwrap_or(21600));
    let bottom = i64::from(p.int(0x0143).unwrap_or(21600));
    let fill_ok = p.flag(0x017F, 0) != Some(false);
    let line_ok = p.flag(0x017F, 3) != Some(false);
    let mut path = Path {
        w: (right - left).max(1),
        h: (bottom - top).max(1),
        fill: fill_ok,
        stroke: line_ok,
        cmds: vec![],
    };
    let at = |i: usize| pts.get(i).map(|&(x, y)| (x - left, y - top));
    let mut k = 0usize;
    let segs: Vec<u16> = p
        .complex(0x0146)
        .map(|d| array(d).iter().map(|e| Cur::new(e).u16()).collect())
        .unwrap_or_default();
    if segs.is_empty() {
        let mut first = true;
        for i in 0..pts.len() {
            let (x, y) = at(i)?;
            path.cmds.push(if first {
                PathCmd::Move(x, y)
            } else {
                PathCmd::Line(x, y)
            });
            first = false;
        }
        return Some(Geometry::Custom(vec![path]));
    }
    let mut started = false;
    for s in segs.iter().take(1 << 16) {
        let typ = s >> 13;
        let n = usize::from(s & 0x1FFF);
        match typ {
            0 => {
                for _ in 0..n.max(1) {
                    let Some((x, y)) = at(k) else { break };
                    k += 1;
                    path.cmds.push(if started {
                        PathCmd::Line(x, y)
                    } else {
                        PathCmd::Move(x, y)
                    });
                    started = true;
                }
            }
            1 => {
                for _ in 0..n.max(1) {
                    let (Some(a), Some(b), Some(c)) = (at(k), at(k + 1), at(k + 2)) else {
                        break;
                    };
                    k += 3;
                    if !started {
                        path.cmds.push(PathCmd::Move(a.0, a.1));
                        started = true;
                    }
                    path.cmds.push(PathCmd::Cubic(a.0, a.1, b.0, b.1, c.0, c.1));
                }
            }
            2 => {
                if let Some((x, y)) = at(k) {
                    path.cmds.push(PathCmd::Move(x, y));
                    started = true;
                }
                k += 1;
            }
            3 => path.cmds.push(PathCmd::Close),
            4 => started = false,
            5 | 6 => {
                let esc = (s >> 8) & 0x1F;
                let n = usize::from(s & 0xFF);
                match esc {
                    // Arcs: bounding box corners, then the start and end radial points.
                    3..=6 => {
                        for _ in 0..(n / 4).max(1) {
                            let (Some(a), Some(b), Some(st), Some(en)) =
                                (at(k), at(k + 1), at(k + 2), at(k + 3))
                            else {
                                break;
                            };
                            k += 4;
                            let (cx, cy) = ((a.0 + b.0) as f64 / 2.0, (a.1 + b.1) as f64 / 2.0);
                            let (rx, ry) = (
                                ((b.0 - a.0) as f64 / 2.0).abs(),
                                ((b.1 - a.1) as f64 / 2.0).abs(),
                            );
                            if rx < 1.0 || ry < 1.0 {
                                continue;
                            }
                            let ang = |p: (i64, i64)| {
                                ((p.1 as f64 - cy) / ry).atan2((p.0 as f64 - cx) / rx)
                            };
                            let (a0, a1) = (ang(st), ang(en));
                            let clockwise = esc == 5 || esc == 6;
                            let mut sweep = a1 - a0;
                            let tau = std::f64::consts::TAU;
                            if clockwise {
                                if sweep <= 0.0 {
                                    sweep += tau;
                                }
                            } else if sweep >= 0.0 {
                                sweep -= tau;
                            }
                            let sx = cx + rx * a0.cos();
                            let sy = cy + ry * a0.sin();
                            let (sx, sy) = (sx.round() as i64, sy.round() as i64);
                            if started && (esc == 3 || esc == 5) {
                                path.cmds.push(PathCmd::Line(sx, sy));
                            } else {
                                path.cmds.push(PathCmd::Move(sx, sy));
                            }
                            started = true;
                            arc_cubics(cx, cy, rx, ry, a0, sweep, &mut path.cmds);
                        }
                    }
                    // Quadrants: an elliptical quarter to the next point.
                    7 | 8 => {
                        for i in 0..n.max(1) {
                            let Some(end) = at(k) else { break };
                            k += 1;
                            let cur = last_point(&path.cmds).unwrap_or(end);
                            let x_first = (esc == 7) == (i % 2 == 0);
                            let ctrl = if x_first {
                                (end.0, cur.1)
                            } else {
                                (cur.0, end.1)
                            };
                            let kk = 0.5523;
                            let c1 = (
                                cur.0 + ((ctrl.0 - cur.0) as f64 * kk) as i64,
                                cur.1 + ((ctrl.1 - cur.1) as f64 * kk) as i64,
                            );
                            let c2 = (
                                end.0 + ((ctrl.0 - end.0) as f64 * kk) as i64,
                                end.1 + ((ctrl.1 - end.1) as f64 * kk) as i64,
                            );
                            if !started {
                                path.cmds.push(PathCmd::Move(cur.0, cur.1));
                                started = true;
                            }
                            path.cmds
                                .push(PathCmd::Cubic(c1.0, c1.1, c2.0, c2.1, end.0, end.1));
                        }
                    }
                    // No fill, no line.
                    0xA => path.fill = false,
                    0xB => path.stroke = false,
                    // Angle ellipses: centre, radii, then start angle and
                    // sweep (16.16 degrees, counterclockwise).
                    1 | 2 => {
                        for _ in 0..(n / 3).max(1) {
                            let (Some(c), Some(r), Some(a)) =
                                (at(k), pts.get(k + 1).copied(), pts.get(k + 2).copied())
                            else {
                                break;
                            };
                            k += 3;
                            let (cx, cy) = (c.0 as f64, c.1 as f64);
                            let (rx, ry) = (r.0 as f64, r.1 as f64);
                            let st = -(a.0 as f64 / 65536.0).to_radians();
                            let sw = -(a.1 as f64 / 65536.0).to_radians();
                            let sx = (cx + rx * st.cos()).round() as i64;
                            let sy = (cy + ry * st.sin()).round() as i64;
                            if esc == 1 && started {
                                path.cmds.push(PathCmd::Line(sx, sy));
                            } else {
                                path.cmds.push(PathCmd::Move(sx, sy));
                            }
                            started = true;
                            arc_cubics(cx, cy, rx.abs(), ry.abs(), st, sw, &mut path.cmds);
                        }
                    }
                    _ => k += n,
                }
            }
            _ => {}
        }
    }
    if path.cmds.is_empty() {
        return None;
    }
    Some(Geometry::Custom(vec![path]))
}

fn last_point(cmds: &[PathCmd]) -> Option<(i64, i64)> {
    cmds.iter().rev().find_map(|c| match *c {
        PathCmd::Move(x, y) | PathCmd::Line(x, y) => Some((x, y)),
        PathCmd::Cubic(_, _, _, _, x, y) => Some((x, y)),
        PathCmd::Quad(_, _, x, y) => Some((x, y)),
        _ => None,
    })
}

/// The shape's position: from its client anchor (master units) or, in a
/// group, its child anchor (the group's units). A shape turned by 45 to 135
/// degrees (or 225 to 315) stores the box it covers turned: its own box is
/// that one with width and height swapped about the centre.
pub fn xfrm(s: &OShape, in_group: bool) -> Option<Xfrm> {
    let (r, scale): ([i32; 4], f64) = if in_group {
        (s.child.or(s.anchor)?, 1.0)
    } else {
        (s.anchor.or(s.child)?, 1587.5)
    };
    let mut x = (f64::from(r[0]) * scale).round() as Emu;
    let mut y = (f64::from(r[1]) * scale).round() as Emu;
    let mut w = (f64::from(r[2].saturating_sub(r[0])) * scale).round() as Emu;
    let mut h = (f64::from(r[3].saturating_sub(r[1])) * scale).round() as Emu;
    let rot = s.props.get(0x0004).map(fixed).unwrap_or(0.0);
    let norm = rot.rem_euclid(360.0);
    if (45.0..135.0).contains(&norm) || (225.0..315.0).contains(&norm) {
        let (cx, cy) = (x + w / 2, y + h / 2);
        std::mem::swap(&mut w, &mut h);
        x = cx - w / 2;
        y = cy - h / 2;
    }
    Some(Xfrm {
        x,
        y,
        w: w.max(0),
        h: h.max(0),
        rot,
        flip_h: s.flags & F_FLIP_H != 0,
        flip_v: s.flags & F_FLIP_V != 0,
    })
}

/// Geometry of a non-group shape: its own path when it has one (vertices
/// and segments, or vertices alone without a known type), whatever its
/// type says, else its type's preset.
pub fn geometry(s: &OShape, w: Emu, h: Emu) -> Geometry {
    let own = s.props.complex(0x0146).is_some() || presets::name(s.spt).is_none();
    if let Some(g) = custom(&s.props).filter(|_| own) {
        return g;
    }
    presets::geometry(s.spt, &s.props, w, h).unwrap_or_default()
}

/// Text insets, anchor and wrap of a shape's text body.
pub fn body_props(p: &Props) -> BodyProps {
    let ins = |id: u16, d: i32| Emu::from(p.int(id).unwrap_or(d).max(0));
    let (anchor, ctr) = match p.get(0x0087).unwrap_or(0) {
        1 | 4 => ("ctr", false),
        2 | 5 | 7 | 9 => ("b", false),
        _ => ("t", false),
    };
    let ctr = ctr || matches!(p.get(0x0087), Some(3 | 4 | 5 | 8 | 9));
    BodyProps {
        insets: [
            ins(0x0081, 91440),
            ins(0x0082, 45720),
            ins(0x0083, 91440),
            ins(0x0084, 45720),
        ],
        anchor,
        anchor_ctr: ctr,
        wrap: p.get(0x0085).unwrap_or(0) != 2,
        vert: match p.get(0x0088).unwrap_or(0) {
            1 | 5 => Some("vert"),
            2 => Some("vert270"),
            3 => Some("eaVert"),
            _ => None,
        },
        autofit: if p.flag(0x00BF, 1) == Some(true) {
            Autofit::Shape
        } else {
            Autofit::None
        },
        rot: 0.0,
        columns: 1,
    }
}

/// A WordArt shape's text: one centred paragraph per line, in the shape's
/// fill colour, its font size the given one or the shape's height.
pub fn word_art(p: &Props, text: &str, refs: &Refs, ctx: &Ctx, h: Emu) -> TextBody {
    let color = match fill(p, ctx, refs) {
        Fill::Solid(c) => c,
        Fill::Gradient(g) => g.stops.first().map(|s| s.1).unwrap_or(Color::rgb(0)),
        _ => Color::rgb(refs.fill),
    };
    let lines: Vec<&str> = text.split(['\n', '\r']).filter(|l| !l.is_empty()).collect();
    let n = lines.len().max(1) as f64;
    let fit = (h as f64 / 12700.0 / n * 0.75).clamp(1.0, 400.0);
    let size = p
        .get(0x00C3)
        .map(fixed)
        .filter(|&s| s > 0.0 && p.flag(0x00FF, 8) != Some(true))
        .unwrap_or(fit);
    let props = RunProps {
        size: Some((size.min(fit.max(1.0)) * 100.0).round() as u32),
        bold: p.flag(0x00FF, 5),
        italic: p.flag(0x00FF, 4),
        color: Some(color),
        font: p.complex(0x00C5).map(utf16).filter(|f| !f.is_empty()),
        ..RunProps::default()
    };
    TextBody {
        body: BodyProps {
            insets: [0; 4],
            anchor: "ctr",
            wrap: false,
            ..BodyProps::default()
        },
        paras: lines
            .iter()
            .map(|l| Paragraph {
                props: ParaProps {
                    align: Some("ctr"),
                    bullet: Some(Bullet::None),
                    ..ParaProps::default()
                },
                runs: vec![Run {
                    kind: RunKind::Text(l.to_string()),
                    props: props.clone(),
                }],
                end: props.clone(),
            })
            .collect(),
        levels: ListStyle::default(),
    }
}

fn utf16(d: &[u8]) -> String {
    let u: Vec<u16> = d
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .take(1 << 16)
        .collect();
    let end = u.iter().position(|&c| c == 0).unwrap_or(u.len());
    String::from_utf16_lossy(&u[..end])
}

/// A picture's crop, in 1/100000 of each side.
pub fn crop(p: &Props) -> [i32; 4] {
    let f = |id: u16| {
        (fixed(p.get(id).unwrap_or(0)) * 100_000.0)
            .round()
            .clamp(-1e7, 1e7) as i32
    };
    [f(0x0102), f(0x0100), f(0x0103), f(0x0101)]
}

pub fn is_connector(s: &OShape) -> bool {
    s.flags & F_CONNECTOR != 0 || matches!(s.spt, 20 | 32..=40)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::slides::ppt::escher::Prop;

    #[test]
    fn colours_scheme_rgb_and_system() {
        let scheme = [0x111111, 0x222222, 0, 0, 0x555555, 0, 0, 0];
        let refs = Refs {
            fill: 0x808080,
            ..Refs::default()
        };
        assert_eq!(color(0x0033_2211, &scheme, &refs), 0x112233);
        assert_eq!(color(0x0800_0004, &scheme, &refs), 0x555555);
        // The fill colour darkened to half.
        assert_eq!(color(0x1080_01F0, &scheme, &refs), 0x404040);
    }

    #[test]
    fn rotated_anchor_is_swapped() {
        let s = OShape {
            anchor: Some([0, 0, 576, 288]),
            props: Props(vec![Prop {
                id: 4,
                value: 90 << 16,
                complex: None,
            }]),
            ..OShape::default()
        };
        let x = xfrm(&s, false).unwrap();
        assert_eq!((x.w, x.h), (457_200, 914_400));
        assert_eq!((x.x, x.y), (228_600, -228_600));
        assert_eq!(x.rot, 90.0);
    }

    #[test]
    fn freeform_path_from_vertices_and_segments() {
        // Three points, moveTo, lineTo 2, close, end.
        let mut v = vec![3, 0, 3, 0, 4, 0];
        for (x, y) in [(0i16, 0i16), (100, 0), (100, 50)] {
            v.extend(x.to_le_bytes());
            v.extend(y.to_le_bytes());
        }
        let mut s = vec![4, 0, 4, 0, 2, 0];
        for seg in [0x4000u16, 0x0002, 0x6001, 0x8000] {
            s.extend(seg.to_le_bytes());
        }
        let p = Props(vec![
            Prop {
                id: 0x0145,
                value: 0,
                complex: Some(&v),
            },
            Prop {
                id: 0x0146,
                value: 0,
                complex: Some(&s),
            },
        ]);
        let Some(Geometry::Custom(paths)) = custom(&p) else {
            panic!("no path")
        };
        let cmds: Vec<String> = paths[0].cmds.iter().map(|c| format!("{c:?}")).collect();
        assert_eq!(
            cmds,
            vec!["Move(0, 0)", "Line(100, 0)", "Line(100, 50)", "Close"]
        );
    }
}
