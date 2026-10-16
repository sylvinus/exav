//! Keynote drawables to the model: shapes and their path sources, text
//! boxes, pictures and groups, with fills, strokes and shadows from their
//! styles.
//!
//! TSD.DrawableArchive: geometry 1 (position 1, size 2, angle 4).
//! TSD.ShapeArchive: super 1, style 2, pathsource 3, head_line_end 4,
//! tail_line_end 5. TSWP.ShapeInfoArchive: super 1, deprecated_storage 2,
//! owned_storage 4. TSD.ImageArchive: super 1, style 3, data 11,
//! originalData 13. TSD.GroupArchive: super 1, children 2.

use super::{text, ty, Props, Reader};
use crate::formats::office::common::iwa::proto::Msg;
use crate::formats::office::slides::error::Result;
use crate::formats::office::slides::limits::Budget;
use crate::formats::office::slides::model::*;

const PT: f64 = 12700.0;

/// A TSP.Color (r 3, g 4, b 5, a 6 in 0 to 1) as a colour.
pub fn color(c: Msg) -> Color {
    let ch = |n: u32| (f64::from(c.float(n).unwrap_or(0.0)).clamp(0.0, 1.0) * 255.0).round() as u32;
    let a = f64::from(c.float(6).unwrap_or(1.0)).clamp(0.0, 1.0);
    Color {
        rgb: ch(3) << 16 | ch(4) << 8 | ch(5),
        alpha: (a < 1.0).then(|| (a * 100_000.0).round() as u32),
    }
}

fn with_opacity(mut c: Color, o: Option<f64>) -> Color {
    if let Some(o) = o.filter(|&o| o < 1.0) {
        let a = f64::from(c.alpha.unwrap_or(100_000)) * o.clamp(0.0, 1.0);
        c.alpha = Some(a.round() as u32);
    }
    c
}

/// A TSD.FillArchive: color 1, gradient 2 (type 1, stops 2 (color 1,
/// fraction 2), anglegradient 5 (gradientangle 2)), image 3 (technique 2,
/// imagedata 6).
pub fn fill(r: &mut Reader, f: Msg) -> Fill {
    if let Some(c) = f.msg(1) {
        return Fill::Solid(color(c));
    }
    if let Some(g) = f.msg(2) {
        let stops: Vec<(u32, Color)> = g
            .msgs(2)
            .take(64)
            .map(|s| {
                let pos = (f64::from(s.float(2).unwrap_or(0.0)).clamp(0.0, 1.0) * 100_000.0).round()
                    as u32;
                (pos, s.msg(1).map(color).unwrap_or(Color::rgb(0)))
            })
            .collect();
        if stops.is_empty() {
            return Fill::None;
        }
        let kind = if g.uint(1) == Some(1) {
            GradientKind::Path("circle", [50_000; 4])
        } else {
            // Counterclockwise degrees from left to right.
            let a = g
                .msg(5)
                .and_then(|a| a.float(2))
                .map(f64::from)
                .unwrap_or(0.0);
            GradientKind::Linear((-a).rem_euclid(360.0))
        };
        return Fill::Gradient(Gradient { stops, kind });
    }
    if let Some(i) = f.msg(3) {
        let id = i.msg(6).or_else(|| i.msg(7)).and_then(|d| d.uint(1));
        if let Some(media) = id.and_then(|id| r.image(id)) {
            return Fill::Picture {
                media,
                tile: i.uint(2) == Some(2),
            };
        }
    }
    Fill::None
}

/// A TSD.StrokeArchive: color 1, width 2, cap 3, join 4, pattern 6 (type
/// 1: 0 dashed, 1 solid, 2 none; pattern 4).
pub fn stroke(s: Msg, opacity: Option<f64>) -> Line {
    let kind = s.msg(6).and_then(|p| p.uint(1)).unwrap_or(1);
    if kind == 2 {
        return Line::default();
    }
    let width = f64::from(s.float(2).unwrap_or(1.0)).max(0.0);
    let dash = (kind == 0).then(|| {
        let p: Vec<f32> = s
            .msg(6)
            .map(|p| {
                p.all(4)
                    .filter_map(|v| match v {
                        crate::formats::office::common::iwa::proto::Val::Fixed32(x) => {
                            Some(f32::from_bits(x))
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        match p.first() {
            Some(&d) if d <= 1.5 => "sysDot",
            Some(&d) if d >= 4.0 => "lgDash",
            _ => "dash",
        }
    });
    Line {
        fill: Fill::Solid(with_opacity(
            s.msg(1).map(color).unwrap_or(Color::rgb(0)),
            opacity,
        )),
        width: (width * PT).round() as Emu,
        dash,
        cap: match s.uint(3) {
            Some(1) => Some("rnd"),
            Some(2) => Some("sq"),
            _ => None,
        },
        join: match s.uint(4) {
            Some(1) => Some("round"),
            Some(2) => Some("bevel"),
            Some(0) => Some("miter"),
            _ => None,
        },
        ..Line::default()
    }
}

/// A TSD.ShadowArchive: color 1, angle 2, offset 3, radius 4, opacity 5,
/// is_enabled 6.
pub fn shadow(s: Msg) -> Option<Shadow> {
    if s.boolean(6) == Some(false) {
        return None;
    }
    let mut c = s.msg(1).map(color).unwrap_or(Color::rgb(0));
    c = with_opacity(c, s.float(5).map(f64::from));
    Some(Shadow {
        color: c,
        blur: (f64::from(s.int(4).unwrap_or(0).clamp(0, 1000) as i32) * PT).round() as Emu,
        dist: (f64::from(s.float(3).unwrap_or(0.0)).abs() * PT).round() as Emu,
        // Counterclockwise from the right, to DrawingML's clockwise.
        dir: (-f64::from(s.float(2).unwrap_or(315.0))).rem_euclid(360.0),
    })
}

fn arrow(end: Option<Msg>) -> Option<Arrow> {
    let id = end?.string(5)?.to_ascii_lowercase();
    let kind = if id.contains("circle") {
        "oval"
    } else if id.contains("diamond") || id.contains("square") {
        "diamond"
    } else if id.contains("open") || id.contains("simple") || id == "line" {
        "arrow"
    } else if id.contains("arrow") {
        "triangle"
    } else {
        return None;
    };
    Some(Arrow {
        kind,
        w: "med",
        len: "med",
    })
}

/// Points of a TSP.Path (elements 1: type 1, points 2) in a box of
/// `natural` size, as a path.
fn path(p: Msg, natural: (f64, f64)) -> Option<Geometry> {
    // Path units: points times 100.
    let s = 100.0;
    let pt = |m: Msg| {
        (
            (f64::from(m.float(1).unwrap_or(0.0)) * s).round() as i64,
            (f64::from(m.float(2).unwrap_or(0.0)) * s).round() as i64,
        )
    };
    let mut out = Path {
        w: (natural.0 * s).round().max(1.0) as i64,
        h: (natural.1 * s).round().max(1.0) as i64,
        fill: true,
        stroke: true,
        cmds: vec![],
    };
    let mut started = false;
    for e in p.msgs(1).take(1 << 16) {
        let pts: Vec<(i64, i64)> = e.msgs(2).map(pt).collect();
        match (e.uint(1).unwrap_or(0), pts.as_slice()) {
            (1, [a, ..]) => {
                out.cmds.push(PathCmd::Move(a.0, a.1));
                started = true;
            }
            (2, [a, ..]) if started => out.cmds.push(PathCmd::Line(a.0, a.1)),
            (3, [a, b, ..]) if started => out.cmds.push(PathCmd::Quad(a.0, a.1, b.0, b.1)),
            (4, [a, b, c, ..]) if started => {
                out.cmds.push(PathCmd::Cubic(a.0, a.1, b.0, b.1, c.0, c.1))
            }
            (5, _) if started => out.cmds.push(PathCmd::Close),
            _ => {}
        }
    }
    // A trailing lone move draws nothing.
    if matches!(out.cmds.last(), Some(PathCmd::Move(..))) {
        out.cmds.pop();
    }
    (!out.cmds.is_empty()).then(|| Geometry::Custom(vec![out]))
}

fn size_of(m: Option<Msg>, w: f64, h: f64) -> (f64, f64) {
    m.map(|s| {
        (
            f64::from(s.float(1).unwrap_or(w as f32)),
            f64::from(s.float(2).unwrap_or(h as f32)),
        )
    })
    .filter(|s| s.0 > 0.0 && s.1 > 0.0)
    .unwrap_or((w.max(1.0), h.max(1.0)))
}

/// A TSD.PathSourceArchive (horizontalFlip 1, verticalFlip 2, point 3,
/// scalar 4, bezier 5, callout 6, connection line 7, editable bezier 8).
fn geometry(ps: Msg, w: f64, h: f64) -> Geometry {
    if let Some(s) = ps.msg(4) {
        // Scalar: rounded rectangle 0 (radius), regular polygon 1 (sides),
        // chevron 2.
        let (nw, nh) = size_of(s.msg(3), w, h);
        let v = f64::from(s.float(2).unwrap_or(0.0));
        return match s.uint(1).unwrap_or(0) {
            0 if v > 0.0 => Geometry::Preset {
                name: "roundRect",
                adj: vec![(
                    "adj",
                    ((v / nw.min(nh)) * 100_000.0).round().clamp(0.0, 50_000.0) as i64,
                )],
            },
            0 => Geometry::default(),
            1 => {
                let n = (v.round() as usize).clamp(3, 64);
                let mut p = Path {
                    w: 100_000,
                    h: 100_000,
                    fill: true,
                    stroke: true,
                    cmds: vec![],
                };
                for i in 0..n {
                    let a =
                        -std::f64::consts::FRAC_PI_2 + i as f64 * std::f64::consts::TAU / n as f64;
                    let (x, y) = (
                        (50_000.0 + 50_000.0 * a.cos()) as i64,
                        (50_000.0 + 50_000.0 * a.sin()) as i64,
                    );
                    p.cmds.push(if i == 0 {
                        PathCmd::Move(x, y)
                    } else {
                        PathCmd::Line(x, y)
                    });
                }
                p.cmds.push(PathCmd::Close);
                Geometry::Custom(vec![p])
            }
            _ => Geometry::preset("chevron"),
        };
    }
    if let Some(p) = ps.msg(3) {
        return Geometry::preset(match p.uint(1).unwrap_or(1) {
            0 => "leftArrow",
            10 => "leftRightArrow",
            100 => match p
                .msg(2)
                .and_then(|pt| pt.float(1))
                .map(|v| v.round() as i32)
            {
                Some(4) => "star4",
                Some(6) => "star6",
                Some(7) => "star7",
                Some(8) => "star8",
                Some(10) => "star10",
                Some(12) => "star12",
                _ => "star5",
            },
            200 => "plus",
            _ => "rightArrow",
        });
    }
    let bezier = ps.msg(5).or_else(|| ps.msg(7).and_then(|c| c.msg(1)));
    if let Some(b) = bezier {
        let natural = size_of(b.msg(2), w, h);
        if let Some(g) = b.msg(3).and_then(|p| path(p, natural)) {
            return g;
        }
    }
    if let Some(e) = ps.msg(8) {
        let natural = size_of(e.msg(2), w, h);
        let s = 100.0;
        let pt = |m: Option<Msg>| {
            m.map(|m| {
                (
                    (f64::from(m.float(1).unwrap_or(0.0)) * s).round() as i64,
                    (f64::from(m.float(2).unwrap_or(0.0)) * s).round() as i64,
                )
            })
            .unwrap_or((0, 0))
        };
        let mut out = Path {
            w: (natural.0 * s).round().max(1.0) as i64,
            h: (natural.1 * s).round().max(1.0) as i64,
            fill: true,
            stroke: true,
            cmds: vec![],
        };
        for sub in e.msgs(1).take(4096) {
            let nodes: Vec<Msg> = sub.msgs(1).take(1 << 16).collect();
            let Some(first) = nodes.first() else { continue };
            let p0 = pt(first.msg(2));
            out.cmds.push(PathCmd::Move(p0.0, p0.1));
            let closed = sub.boolean(2).unwrap_or(false);
            let mut segs: Vec<(Msg, Msg)> = nodes.windows(2).map(|w| (w[0], w[1])).collect();
            if closed && nodes.len() > 1 {
                segs.push((nodes[nodes.len() - 1], nodes[0]));
            }
            for (a, b) in segs {
                let (c1, c2, p) = (pt(a.msg(3)), pt(b.msg(1)), pt(b.msg(2)));
                out.cmds
                    .push(PathCmd::Cubic(c1.0, c1.1, c2.0, c2.1, p.0, p.1));
            }
            if closed {
                out.cmds.push(PathCmd::Close);
            }
        }
        if !out.cmds.is_empty() {
            return Geometry::Custom(vec![out]);
        }
    }
    if ps.msg(6).is_some() {
        return Geometry::preset("wedgeRoundRectCallout");
    }
    Geometry::default()
}

/// The box of a drawable (DrawableArchive geometry 1), in EMU.
pub(super) fn xfrm(d: Msg) -> (Xfrm, f64, f64) {
    let g = d.msg(1);
    let pos = g.and_then(|g| g.msg(1));
    let size = g.and_then(|g| g.msg(2));
    let f = |m: Option<Msg>, n: u32| f64::from(m.and_then(|m| m.float(n)).unwrap_or(0.0));
    let (w, h) = (f(size, 1).max(0.0), f(size, 2).max(0.0));
    let angle = f64::from(g.and_then(|g| g.float(4)).unwrap_or(0.0));
    (
        Xfrm {
            x: (f(pos, 1) * PT).round() as Emu,
            y: (f(pos, 2) * PT).round() as Emu,
            w: (w * PT).round() as Emu,
            h: (h * PT).round() as Emu,
            // Counterclockwise degrees, to clockwise.
            rot: (-angle).rem_euclid(360.0),
            ..Xfrm::default()
        },
        w,
        h,
    )
}

/// A drawable by identifier, or `None` when it is not one this converts.
pub fn drawable(
    r: &mut Reader,
    id: u64,
    number: usize,
    budget: &mut Budget,
    depth: u32,
) -> Result<Option<Shape>> {
    if depth > 32 {
        return Ok(None);
    }
    let Some((kind, m)) = r.store.get(id) else {
        return Ok(None);
    };
    match kind {
        ty::PLACEHOLDER => {
            let Some(info) = m.msg(1) else {
                return Ok(None);
            };
            let mut s = shape_info(r, info, number, budget)?;
            if let Some(s) = &mut s {
                s.placeholder = match m.uint(2) {
                    Some(2) => Some(Placeholder {
                        kind: "title",
                        idx: None,
                    }),
                    Some(3) => Some(Placeholder {
                        kind: "body",
                        idx: Some(1),
                    }),
                    Some(1) => Some(Placeholder {
                        kind: "sldNum",
                        idx: Some(12),
                    }),
                    _ => None,
                };
            }
            Ok(s)
        }
        ty::SHAPE_INFO => shape_info(r, m, number, budget),
        ty::SHAPE | ty::CONNECTION_LINE => {
            let shape = if kind == ty::CONNECTION_LINE {
                m.msg(1)
            } else {
                Some(m)
            };
            match shape {
                Some(sh) => {
                    budget.shape(0)?;
                    Ok(Some(plain(r, sh, None)))
                }
                None => Ok(None),
            }
        }
        ty::IMAGE => {
            budget.shape(0)?;
            let Some(d) = m.msg(1) else { return Ok(None) };
            let data = m.msg(11).or_else(|| m.msg(13)).and_then(|d| d.uint(1));
            let Some(media) = data.and_then(|id| r.image(id)) else {
                r.p.warn("pictures whose data is missing");
                return Ok(None);
            };
            budget.alloc(r.p.media[media].data.len() as u64)?;
            let style = m.reference(3);
            let opacity = r.find(style, Props::Media, |p| p.float(2)).map(f64::from);
            let line = r
                .find(style, Props::Media, |p| p.msg(1))
                .map(|s| stroke(s, opacity))
                .unwrap_or_default();
            let shadow = r.find(style, Props::Media, |p| p.msg(3)).and_then(shadow);
            let (xf, _, _) = xfrm(d);
            let mut s = Shape::new(
                ShapeKind::Pic(Box::new(Pic {
                    media,
                    crop: [0; 4],
                    geom: Geometry::default(),
                    line,
                    shadow,
                    alpha: opacity
                        .filter(|&o| o < 1.0)
                        .map(|o| (o * 100_000.0).round() as u32),
                })),
                xf,
            );
            s.descr = d.string(8).unwrap_or_default();
            Ok(Some(s))
        }
        ty::GROUP => {
            let Some(d) = m.msg(1) else { return Ok(None) };
            let (xf, w, h) = xfrm(d);
            let mut kids = vec![];
            for c in m.references(2).take(10_000) {
                if let Some(s) = drawable(r, c, number, budget, depth + 1)? {
                    kids.push(s);
                }
            }
            if kids.is_empty() {
                return Ok(None);
            }
            // Children are placed in the group's own space.
            let child = Xfrm {
                x: 0,
                y: 0,
                w: ((w * PT).round() as Emu).max(1),
                h: ((h * PT).round() as Emu).max(1),
                ..Xfrm::default()
            };
            Ok(Some(Shape::new(
                ShapeKind::Group(Box::new(Group {
                    child,
                    shapes: kids,
                })),
                xf,
            )))
        }
        ty::TABLE_INFO => super::table::table(r, m, number, budget),
        ty::CHART => super::chart::chart(r, m, budget),
        ty::MOVIE => {
            budget.shape(0)?;
            let Some(d) = m.msg(1) else { return Ok(None) };
            Ok(Some(movie(r, m, d, budget)?))
        }
        _ => Ok(None),
    }
}

/// A TSD.MovieArchive (poster image 15, audio only image 16, style 19):
/// its poster frame, else a dark box with a play triangle, as a movie
/// cannot play in the PPTX.
fn movie(r: &mut Reader, m: Msg, d: Msg, budget: &mut Budget) -> Result<Shape> {
    let (xf, _, _) = xfrm(d);
    let poster = m
        .msg(15)
        .or_else(|| m.msg(16))
        .and_then(|p| p.uint(1))
        .and_then(|id| r.image(id));
    if let Some(media) = poster {
        budget.alloc(r.p.media[media].data.len() as u64)?;
        let style = m.reference(19);
        let opacity = r.find(style, Props::Media, |p| p.float(2)).map(f64::from);
        let line = r
            .find(style, Props::Media, |p| p.msg(1))
            .map(|s| stroke(s, opacity))
            .unwrap_or_default();
        let shadow = r.find(style, Props::Media, |p| p.msg(3)).and_then(shadow);
        return Ok(Shape::new(
            ShapeKind::Pic(Box::new(Pic {
                media,
                crop: [0; 4],
                geom: Geometry::default(),
                line,
                shadow,
                alpha: None,
            })),
            xf,
        ));
    }
    r.p.warn("movies without a poster frame, drawn as a box");
    let kind = ShapeKind::media_placeholder(xf.w, xf.h, m.boolean(9) != Some(true));
    Ok(Shape::new(kind, xf))
}

/// A TSD.ShapeArchive (no text) with its style.
fn plain(r: &mut Reader, sh: Msg, text: Option<TextBody>) -> Shape {
    let d = sh.msg(1);
    let (mut xf, w, h) = d.map(xfrm).unwrap_or_default();
    let style = sh.reference(2);
    let opacity = r.find(style, Props::Shape, |p| p.float(3)).map(f64::from);
    let fill = match r.find(style, Props::Shape, |p| p.msg(1)) {
        Some(f) => match fill(r, f) {
            Fill::Solid(c) => Fill::Solid(with_opacity(c, opacity)),
            f => f,
        },
        None => Fill::None,
    };
    let mut line = r
        .find(style, Props::Shape, |p| p.msg(2))
        .map(|s| stroke(s, opacity))
        .unwrap_or_default();
    if line.fill != Fill::None {
        line.head = arrow(
            sh.msg(4)
                .or_else(|| r.find(style, Props::Shape, |p| p.msg(6))),
        );
        line.tail = arrow(
            sh.msg(5)
                .or_else(|| r.find(style, Props::Shape, |p| p.msg(7))),
        );
    }
    let shadow = r.find(style, Props::Shape, |p| p.msg(4)).and_then(shadow);
    let geom = match sh.msg(3) {
        Some(ps) => {
            xf.flip_h = ps.boolean(1).unwrap_or(false);
            xf.flip_v = ps.boolean(2).unwrap_or(false);
            geometry(ps, w, h)
        }
        None => Geometry::default(),
    };
    let mut s = Shape::new(
        ShapeKind::Sp(Box::new(Sp {
            geom,
            fill,
            line,
            shadow,
            text,
            ..Sp::default()
        })),
        xf,
    );
    if let Some(url) = d.and_then(|d| d.string(4)).and_then(|u| Link::url(&u)) {
        s.link = Some(url);
    }
    s.descr = d.and_then(|d| d.string(8)).unwrap_or_default();
    s
}

/// A TSWP.ShapeInfoArchive: a shape with text.
fn shape_info(
    r: &mut Reader,
    info: Msg,
    number: usize,
    budget: &mut Budget,
) -> Result<Option<Shape>> {
    let Some(sh) = info.msg(1) else {
        return Ok(None);
    };
    budget.shape(0)?;
    let style = sh.reference(2);
    let storage = info.reference(4).or_else(|| info.reference(2));
    let text = match storage.and_then(|id| r.store.get(id)) {
        Some((ty::STORAGE | ty::STORAGE_2, st)) => text::body(r, st, style, number, budget)?,
        _ => None,
    };
    Ok(Some(plain(r, sh, text)))
}
