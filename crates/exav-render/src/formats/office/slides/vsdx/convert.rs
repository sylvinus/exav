//! The shapes of a page as model shapes. A shape's transform is the one of
//! [MS-VSDX] 2.2.3.2.1: subtract the local pin, mirror, turn
//! counterclockwise, add the pin; the page and its groups have the Y axis
//! pointing up and a PPTX has it pointing down.

use super::format;
use super::geom::{self, GPath, Seg};
use super::resolve::Tree;
use super::text;
use crate::formats::office::common::image;
use crate::formats::office::slides::error::{Error, Result};
use crate::formats::office::slides::limits::{Budget, text_bytes};
use crate::formats::office::slides::model::*;
use crate::formats::office::slides::package::Zip;
use std::collections::HashMap;

const EMU_PER_INCH: f64 = 914_400.0;

/// Path segments of one shape.
const MAX_SEGS: usize = 200_000;
/// The most a picture part may be.
const MAX_PICTURE: u64 = 64 << 20;

/// A length in inches, scaled by `k`, in EMU.
fn emu(v: f64, k: f64) -> Emu {
    if v.is_finite() {
        (v * k * EMU_PER_INCH).clamp(-1e13, 1e13).round() as Emu
    } else {
        0
    }
}

/// The box a shape's coordinates are in: the page, or a group's local box.
/// Its lower left corner is (`x0`, `y0`) and it is `h` high, in inches of
/// the drawing; `k` is the paper inches to each, where the drawing is
/// scaled ([MS-VSDX] 2.2.2.3).
#[derive(Clone, Copy)]
pub struct Frame {
    pub x0: f64,
    pub y0: f64,
    pub h: f64,
    pub k: f64,
}

impl Frame {
    fn x(&self, x: f64) -> f64 {
        (x - self.x0) * EMU_PER_INCH * self.k
    }

    fn y(&self, y: f64) -> f64 {
        (self.y0 + self.h - y) * EMU_PER_INCH * self.k
    }

    fn pt(&self, x: f64, y: f64) -> (i64, i64) {
        let c = |v: f64| {
            if v.is_finite() {
                v.clamp(-1e13, 1e13).round() as i64
            } else {
                0
            }
        };
        (c(self.x(x)), c(self.y(y)))
    }
}

/// A shape's own transform.
struct Xf {
    w: f64,
    h: f64,
    pin: (f64, f64),
    loc: (f64, f64),
    angle: f64,
    flip: (bool, bool),
}

impl Xf {
    /// A vector from the local pin, mirrored and turned.
    fn turn(&self, v: (f64, f64)) -> (f64, f64) {
        let (x, y) = (
            if self.flip.0 { -v.0 } else { v.0 },
            if self.flip.1 { -v.1 } else { v.1 },
        );
        let (s, c) = self.angle.sin_cos();
        (x * c - y * s, x * s + y * c)
    }

    /// A point of the shape in its parent's coordinates.
    fn to_parent(&self, p: (f64, f64)) -> (f64, f64) {
        let v = self.turn((p.0 - self.loc.0, p.1 - self.loc.1));
        (self.pin.0 + v.0, self.pin.1 + v.1)
    }

    /// The box of the shape in its parent's frame: the unturned box, its
    /// turn and its mirrors.
    fn xfrm(&self, f: Frame, ws: f64, hs: f64) -> Xfrm {
        let (cx, cy) = self.to_parent((self.w / 2.0, self.h / 2.0));
        Xfrm {
            x: (f.x(cx) - ws * f.k * EMU_PER_INCH / 2.0).round() as Emu,
            y: (f.y(cy) - hs * f.k * EMU_PER_INCH / 2.0).round() as Emu,
            w: emu(ws, f.k),
            h: emu(hs, f.k),
            rot: (-self.angle.to_degrees()).rem_euclid(360.0),
            flip_h: self.flip.0,
            flip_v: self.flip.1,
        }
    }
}

pub struct Conv<'c, 'a, 'z> {
    pub t: &'c Tree<'a>,
    pub p: &'c mut Presentation,
    pub budget: &'c mut Budget,
    pub zip: &'c mut Zip<'z>,
    pub media: &'c mut HashMap<String, Option<usize>>,
    /// The layers of the page and whether they show, by index.
    pub layers: &'c [(u32, bool)],
    /// The names of the slides, for links to pages.
    pub slide_names: &'c [String],
    /// A picture past its limit, raised when the page is done.
    pub failed: Option<Error>,
}

impl Conv<'_, '_, '_> {
    /// The top-level shapes of a page `h` inches high, `k` inches of paper
    /// to each of the drawing.
    pub fn page(&mut self, h: f64, k: f64) -> Result<Vec<Shape>> {
        let f = Frame {
            x0: 0.0,
            y0: 0.0,
            h,
            k,
        };
        let mut out = vec![];
        for &r in &self.t.roots {
            out.extend(self.shape(r, f)?);
        }
        if let Some(e) = self.failed.take() {
            return Err(e);
        }
        Ok(out)
    }

    fn hidden_by_layer(&self, n: usize) -> bool {
        let members: Vec<i64> = match self.t.val(n, "LayerMember") {
            Some(super::formula::Val::Num(x)) => vec![x as i64],
            Some(super::formula::Val::Str(s)) => {
                s.split(';').filter_map(|m| m.trim().parse().ok()).collect()
            }
            _ => vec![],
        };
        members.iter().any(|m| {
            self.layers
                .iter()
                .any(|(ix, shown)| i64::from(*ix) == *m && !shown)
        })
    }

    fn picture(&mut self, path: &str) -> Option<usize> {
        if let Some(m) = self.media.get(path) {
            return *m;
        }
        let m = match self.zip.read(path, MAX_PICTURE) {
            Ok(Some(d)) => match image::ext(&d) {
                Some(ext) => {
                    if let Err(e) = self.budget.alloc(d.len() as u64) {
                        self.failed.get_or_insert(e);
                        None
                    } else {
                        Some(self.p.add_media(ext, d))
                    }
                }
                None => None,
            },
            Ok(None) => None,
            Err(e) => {
                self.failed.get_or_insert(e);
                None
            }
        };
        self.media.insert(path.to_string(), m);
        m
    }

    fn link(&self, n: usize) -> (Option<Link>, String) {
        for (key, _) in self.t.rows(n, "Hyperlink", None) {
            let s = |c: &str| match self.t.row_val(n, "Hyperlink", None, &key, c) {
                Some(super::formula::Val::Str(s)) => s,
                _ => String::new(),
            };
            let (address, sub, descr) = (s("Address"), s("SubAddress"), s("Description"));
            if let Some(l) = Link::url(&address) {
                return (Some(l), descr);
            }
            // A page of this drawing, by its name (a shape of it after "!").
            let page = sub.split('!').next().unwrap_or("");
            if address.is_empty()
                && !page.is_empty()
                && let Some(i) = self.slide_names.iter().position(|n| n == page)
            {
                return (Some(Link::Slide(i)), descr);
            }
        }
        (None, String::new())
    }

    fn shape(&mut self, n: usize, f: Frame) -> Result<Vec<Shape>> {
        let t = self.t;
        let kind = t.kind(n);
        if t.deleted(n) || kind == "Guide" || self.hidden_by_layer(n) {
            return Ok(vec![]);
        }
        let g = |name: &str| {
            t.num(n, name)
                .filter(|v| v.is_finite())
                .map_or(0.0, |v| v.clamp(-1e6, 1e6))
        };
        let xf = Xf {
            w: g("Width"),
            h: g("Height"),
            pin: (g("PinX"), g("PinY")),
            loc: (g("LocPinX"), g("LocPinY")),
            angle: g("Angle"),
            flip: (g("FlipX") != 0.0, g("FlipY") != 0.0),
        };
        let (ws, hs) = (xf.w.abs(), xf.h.abs());
        let own = Frame {
            x0: xf.w.min(0.0),
            y0: xf.h.min(0.0),
            h: hs,
            k: f.k,
        };
        let xfrm = xf.xfrm(f, ws, hs);
        let (link, descr) = self.link(n);
        let name = t.name(n).to_string();
        let mut out: Vec<Shape> = vec![];
        let finish = |mut s: Shape, link: &Option<Link>| {
            s.name = name.clone();
            s.descr = descr.clone();
            s.link = link.clone();
            s
        };

        // A picture.
        if kind == "Foreign"
            && let Some(fd) = t.foreign(n)
        {
            match fd.target.as_deref().and_then(|p| self.picture(p)) {
                Some(media) => {
                    let (iw, ih) = (g("ImgWidth"), g("ImgHeight"));
                    let crop = if iw > 0.0 && ih > 0.0 {
                        let (ox, oy) = (g("ImgOffsetX"), g("ImgOffsetY"));
                        let c = |v: f64| (v * 100_000.0).clamp(-1e6, 1e6).round() as i32;
                        [
                            c(-ox / iw),
                            c((oy + ih - xf.h) / ih),
                            c(1.0 - (xf.w - ox) / iw),
                            c(-oy / ih),
                        ]
                    } else {
                        [0; 4]
                    };
                    let tr = g("Transparency").clamp(0.0, 1.0);
                    let pic = Pic {
                        media,
                        crop,
                        geom: Geometry::default(),
                        line: Line::default(),
                        shadow: None,
                        alpha: (tr > 0.0).then(|| ((1.0 - tr) * 100_000.0).round() as u32),
                    };
                    out.push(finish(
                        Shape::new(ShapeKind::Pic(Box::new(pic)), xfrm.clone()),
                        &link,
                    ));
                    return Ok(out);
                }
                None => self
                    .p
                    .warn("embedded objects without a picture it can draw"),
            }
        }

        if format::has_effects(t, n) {
            self.p
                .warn("shadows, glows, bevels, reflections and soft edges are not drawn");
        }
        let paths = geom::paths(t, n, xf.w, xf.h, MAX_SEGS)?;
        let body = text::build(t, n, f.k);
        let children: Vec<usize> = t.nodes[n].children.clone();

        // The shape's own geometry and text.
        if !paths.is_empty() || body.is_some() {
            let mut sp = Sp::default();
            let mut separate: Option<(Xfrm, TextBody)> = None;
            if !paths.is_empty() {
                let cmds: usize = paths.iter().map(|p| p.segs.len()).sum();
                self.budget.alloc(cmds as u64 * 32)?;
                sp.geom = Geometry::Custom(model_paths(&paths, own, ws, hs));
                sp.fill = format::fill(t, n);
                sp.line = format::line(t, n);
            }
            if let Some(mut b) = body {
                self.budget.alloc(text_bytes(&b))?;
                match text_block(t, n, &xf, own, ws, hs) {
                    Block::Whole => sp.text = Some(b),
                    Block::Inside(r) => {
                        sp.text_rect = Some(r);
                        sp.text = Some(b);
                    }
                    Block::Free {
                        cx,
                        cy,
                        w,
                        h,
                        angle,
                    } => {
                        if w * f.k < 0.05 {
                            b.body.wrap = false;
                            b.body.anchor_ctr = true;
                        }
                        // Its centre is where the shape's transform moves the
                        // block's centre to.
                        let tx = Xf {
                            w,
                            h,
                            pin: xf.to_parent((cx, cy)),
                            loc: (w / 2.0, h / 2.0),
                            angle: xf.angle + angle,
                            flip: (false, false),
                        };
                        separate = Some((tx.xfrm(f, w.max(0.01 / f.k), h.max(0.2 / f.k)), b));
                    }
                }
            }
            if !paths.is_empty() || sp.text.is_some() {
                if paths.is_empty() {
                    sp.fill = Fill::None;
                    sp.line = Line::default();
                }
                out.push(finish(
                    Shape::new(ShapeKind::Sp(Box::new(sp)), xfrm.clone()),
                    &link,
                ));
            }
            if let Some((tx, b)) = separate {
                let sp = Sp {
                    text: Some(b),
                    ..Sp::default()
                };
                out.push(Shape::new(ShapeKind::Sp(Box::new(sp)), tx));
            }
        }

        // Its subshapes, in a group with the shape's box.
        if !children.is_empty() {
            let mut kids = vec![];
            for c in children {
                kids.extend(self.shape(c, own)?);
            }
            if !kids.is_empty() {
                let g = Group {
                    child: Xfrm {
                        x: 0,
                        y: 0,
                        w: emu(ws, f.k),
                        h: emu(hs, f.k),
                        ..Xfrm::default()
                    },
                    shapes: kids,
                };
                out.push(finish(
                    Shape::new(ShapeKind::Group(Box::new(g)), xfrm.clone()),
                    &None,
                ));
            }
        }
        Ok(out)
    }
}

fn model_paths(paths: &[GPath], f: Frame, ws: f64, hs: f64) -> Vec<Path> {
    let (pw, ph) = (emu(ws, f.k).max(1), emu(hs, f.k).max(1));
    paths
        .iter()
        .map(|g| {
            let mut cmds = Vec::with_capacity(g.segs.len());
            for s in &g.segs {
                cmds.push(match *s {
                    Seg::Move(x, y) => {
                        let p = f.pt(x, y);
                        PathCmd::Move(p.0, p.1)
                    }
                    Seg::Line(x, y) => {
                        let p = f.pt(x, y);
                        PathCmd::Line(p.0, p.1)
                    }
                    Seg::Cubic(c) => {
                        let (a, b, e) = (f.pt(c[0], c[1]), f.pt(c[2], c[3]), f.pt(c[4], c[5]));
                        PathCmd::Cubic(a.0, a.1, b.0, b.1, e.0, e.1)
                    }
                    Seg::Close => PathCmd::Close,
                });
            }
            Path {
                w: pw,
                h: ph,
                fill: g.fill,
                stroke: g.stroke,
                cmds,
            }
        })
        .collect()
}

/// Where the text block of a shape is.
enum Block {
    /// The box of the shape.
    Whole,
    /// A part of the box, as fractions (left, top, right, bottom).
    Inside([f64; 4]),
    /// Elsewhere: its centre in the shape's coordinates, its size and its
    /// turn relative to the shape.
    Free {
        cx: f64,
        cy: f64,
        w: f64,
        h: f64,
        angle: f64,
    },
}

/// The text block of a shape ([MS-VSDX] 2.2.8.5.1): its own pin, size and
/// angle, in the shape's coordinates.
fn text_block(t: &Tree, n: usize, xf: &Xf, own: Frame, ws: f64, hs: f64) -> Block {
    let g = |name: &str| {
        t.num(n, name)
            .filter(|v| v.is_finite())
            .map_or(0.0, |v| v.clamp(-1e6, 1e6))
    };
    if t.val(n, "TxtWidth").is_none() && t.val(n, "TxtHeight").is_none() {
        return Block::Whole;
    }
    let (tw, th) = (g("TxtWidth").abs(), g("TxtHeight").abs());
    let angle = g("TxtAngle");
    let bx = Xf {
        w: tw,
        h: th,
        pin: (g("TxtPinX"), g("TxtPinY")),
        loc: (g("TxtLocPinX"), g("TxtLocPinY")),
        angle,
        flip: xf.flip,
    };
    let (cx, cy) = bx.to_parent((tw / 2.0, th / 2.0));
    let turned = angle.rem_euclid(std::f64::consts::TAU);
    let upright = turned < 1e-3 || std::f64::consts::TAU - turned < 1e-3;
    if upright && ws > 1e-6 && hs > 1e-6 {
        let r = [
            (cx - tw / 2.0 - own.x0) / ws,
            (own.y0 + hs - (cy + th / 2.0)) / hs,
            (cx + tw / 2.0 - own.x0) / ws,
            (own.y0 + hs - (cy - th / 2.0)) / hs,
        ];
        let tol = 1e-3;
        if r.iter().all(|v| (-tol..=1.0 + tol).contains(v)) {
            let whole = r[0].abs() < tol
                && r[1].abs() < tol
                && (r[2] - 1.0).abs() < tol
                && (r[3] - 1.0).abs() < tol;
            return if whole {
                Block::Whole
            } else {
                Block::Inside([
                    r[0].clamp(0.0, 1.0),
                    r[1].clamp(0.0, 1.0),
                    r[2].clamp(0.0, 1.0),
                    r[3].clamp(0.0, 1.0),
                ])
            };
        }
    }
    Block::Free {
        cx,
        cy,
        w: tw,
        h: th,
        angle,
    }
}

/// The layers of a page sheet: the index of each and whether it shows.
pub fn layers(page_sheet: &super::sheet::Sheet) -> Vec<(u32, bool)> {
    let mut out = vec![];
    for s in page_sheet.sections.iter().filter(|s| s.name == "Layer") {
        for (i, r) in s.rows.iter().enumerate() {
            let ix = r.ix.unwrap_or(i as u32);
            let shown = r
                .cells
                .get("Visible")
                .and_then(|c| c.v.as_deref())
                .and_then(super::formula::parse_number)
                .is_none_or(|v| v != 0.0);
            out.push((ix, shown));
        }
    }
    out
}
