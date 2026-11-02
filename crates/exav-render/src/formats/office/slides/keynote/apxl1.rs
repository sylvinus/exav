//! Keynote 1 documents (2003): one XML file, `presentation.apxl`, whose
//! schema Apple published in technical notes TN2067 and TN2073 (the APXL
//! schema), with the pictures beside it. Read here: the theme's slide size
//! and prototype objects (the defaults of shapes, lines, pictures and text
//! boxes), the master slides (placeholders, objects, background, bullet
//! prototypes) and the slides (objects, bullets, background).
//!
//! Colours are "r g b" (0 to 1), "r g b a", or "g" followed by a grey
//! level. Transformations are "m11 m12 m21 m22 tx ty". Objects are drawn
//! bottom to top in document order. The first bullet of a slide, at level
//! 0, is its title; the others fill the body, one paragraph each.

use super::apxl::Pkg;
use super::text::ps_font;
use crate::formats::office::common::xml::Node;
use crate::formats::office::slides::error::{Error, Result};
use crate::formats::office::slides::limits::Budget;
use crate::formats::office::slides::model::*;
use std::collections::HashMap;

const PT: f64 = 12700.0;

struct Reader<'a> {
    pkg: Pkg<'a>,
    media: HashMap<String, Option<usize>>,
    failed: Option<Error>,
    pending: u64,
    p: Presentation,
    /// The theme's prototype object of each kind.
    protos: HashMap<&'static str, &'a Node>,
}

pub(crate) fn read<'a>(root: &'a Node, pkg: Pkg<'a>, budget: &mut Budget) -> Result<Presentation> {
    if root.name != "presentation" {
        return Err(Error::NotFormat("not a Keynote document".into()));
    }
    let Some(theme) = root.child("theme") else {
        return Err(Error::NotFormat("no theme".into()));
    };
    let mut r = Reader {
        pkg,
        media: HashMap::new(),
        failed: None,
        pending: 0,
        p: Presentation::default(),
        protos: HashMap::new(),
    };
    let size = theme.attr("slide-size").map(nums).unwrap_or_default();
    let (w, h) = (
        size.first().copied().unwrap_or(1024.0),
        size.get(1).copied().unwrap_or(768.0),
    );
    r.p.width = (w.clamp(16.0, 20_000.0) * PT).round() as Emu;
    r.p.height = (h.clamp(16.0, 20_000.0) * PT).round() as Emu;
    if let Some(d) = theme.child("prototype-drawables") {
        for n in d.nodes() {
            let kind = match n.name.as_str() {
                "shape" => "shape",
                "line" => "line",
                "image" => "image",
                "textbox" => "textbox",
                _ => continue,
            };
            r.protos.entry(kind).or_insert(n);
        }
    }
    let mut masters: HashMap<&str, (usize, &Node)> = HashMap::new();
    if let Some(list) = theme.child("master-slides") {
        for m in list.all("master-slide").take(4096) {
            let id = m.attr("id").unwrap_or("");
            let mi = r.master(m, budget)?;
            masters.entry(id).or_insert((mi, m));
        }
    }
    let Some(list) = root.child("slide-list") else {
        return Err(Error::NotFormat("no slides".into()));
    };
    let mut n = 0usize;
    for s in list.all("slide") {
        budget.slide(n)?;
        n += 1;
        r.p.total_slides = n;
        if !budget.wants(n - 1) {
            continue;
        }
        let (mi, master) = s
            .attr("master-slide-id")
            .and_then(|id| masters.get(id).copied())
            .unwrap_or((0, s));
        let slide = r.slide(s, mi, master, budget)?;
        r.p.slides.push(slide);
        if let Some(e) = r.failed.take() {
            return Err(e);
        }
    }
    if r.p.masters.is_empty() {
        r.p.masters.push(Master::default());
    }
    Ok(r.p)
}

fn nums(s: &str) -> Vec<f64> {
    s.split(|c: char| c.is_whitespace() || c == ',')
        .filter_map(|t| t.parse::<f64>().ok())
        .filter(|v| v.is_finite())
        .collect()
}

fn channel(v: f64) -> u32 {
    (v.clamp(0.0, 1.0) * 255.0).round() as u32
}

/// A colour attribute.
fn color(s: &str) -> Option<Color> {
    let s = s.trim();
    if let Some(g) = s.strip_prefix('g') {
        let v = channel(g.trim().parse::<f64>().ok()?);
        return Some(Color::rgb(v << 16 | v << 8 | v));
    }
    let v = nums(s);
    match v.as_slice() {
        [r, g, b, rest @ ..] => {
            let a = rest.first().copied().unwrap_or(1.0).clamp(0.0, 1.0);
            Some(Color {
                rgb: channel(*r) << 16 | channel(*g) << 8 | channel(*b),
                alpha: (a < 1.0).then(|| (a * 100_000.0).round() as u32),
            })
        }
        [g] => {
            let v = channel(*g);
            Some(Color::rgb(v << 16 | v << 8 | v))
        }
        _ => None,
    }
}

fn with_opacity(mut c: Color, o: Option<f64>) -> Color {
    if let Some(o) = o.filter(|&o| o < 1.0) {
        let a = f64::from(c.alpha.unwrap_or(100_000)) * o.clamp(0.0, 1.0);
        c.alpha = Some(a.round() as u32);
    }
    c
}

/// The attribute of `n`, else of its prototype.
fn attr<'n>(n: &'n Node, proto: Option<&'n Node>, a: &str) -> Option<&'n str> {
    n.attr(a).or_else(|| proto.and_then(|p| p.attr(a)))
}

/// The style element `name` of `n`, else of its prototype.
fn style<'n>(n: &'n Node, proto: Option<&'n Node>, name: &str) -> Option<&'n Node> {
    n.child("styles")
        .and_then(|s| s.child(name))
        .or_else(|| proto?.child("styles")?.child(name))
}

/// Path commands `M`, `L`, `C`, `Z` as absolute commands.
enum Seg {
    Move(f64, f64),
    Line(f64, f64),
    Cubic([f64; 6]),
    Close,
}

fn parse_path(d: &str) -> Option<Vec<Seg>> {
    let toks: Vec<&str> = d.split_ascii_whitespace().take(1 << 16).collect();
    let mut out = vec![];
    let mut i = 0;
    let take = |i: usize, n: usize| -> Option<Vec<f64>> {
        toks.get(i + 1..i + 1 + n)?
            .iter()
            .map(|t| t.parse::<f64>().ok().filter(|v| v.is_finite()))
            .collect()
    };
    while i < toks.len() {
        match toks[i] {
            "M" => {
                let v = take(i, 2)?;
                out.push(Seg::Move(v[0], v[1]));
                i += 3;
            }
            "L" => {
                let v = take(i, 2)?;
                out.push(Seg::Line(v[0], v[1]));
                i += 3;
            }
            "C" => {
                let v = take(i, 6)?;
                out.push(Seg::Cubic([v[0], v[1], v[2], v[3], v[4], v[5]]));
                i += 7;
            }
            "Z" => {
                out.push(Seg::Close);
                i += 1;
            }
            _ => return None,
        }
    }
    Some(out)
}

/// The bounds of a path, curves included: (min x, min y, max x, max y).
fn bounds(segs: &[Seg]) -> Option<(f64, f64, f64, f64)> {
    let mut b: Option<(f64, f64, f64, f64)> = None;
    let mut add = |x: f64, y: f64| {
        b = Some(match b {
            None => (x, y, x, y),
            Some((a, c, d, e)) => (a.min(x), c.min(y), d.max(x), e.max(y)),
        });
    };
    let mut cur = (0.0, 0.0);
    for s in segs {
        match s {
            Seg::Move(x, y) | Seg::Line(x, y) => {
                add(*x, *y);
                cur = (*x, *y);
            }
            Seg::Cubic(c) => {
                add(c[4], c[5]);
                // The extremes between the end points: roots of the derivative.
                for axis in 0..2 {
                    let p0 = if axis == 0 { cur.0 } else { cur.1 };
                    let (p1, p2, p3) = (c[axis], c[2 + axis], c[4 + axis]);
                    let a = -p0 + 3.0 * p1 - 3.0 * p2 + p3;
                    let bq = 2.0 * (p0 - 2.0 * p1 + p2);
                    let cq = p1 - p0;
                    let mut ts = vec![];
                    if a.abs() < 1e-9 {
                        if bq.abs() > 1e-9 {
                            ts.push(-cq / bq);
                        }
                    } else {
                        let disc = bq * bq - 4.0 * a * cq;
                        if disc >= 0.0 {
                            let sq = disc.sqrt();
                            ts.push((-bq + sq) / (2.0 * a));
                            ts.push((-bq - sq) / (2.0 * a));
                        }
                    }
                    for t in ts.into_iter().filter(|t| *t > 0.0 && *t < 1.0) {
                        let u = 1.0 - t;
                        let v = u * u * u * p0
                            + 3.0 * u * u * t * p1
                            + 3.0 * u * t * t * p2
                            + t * t * t * p3;
                        if axis == 0 {
                            add(v, cur.1);
                        } else {
                            add(cur.0, v);
                        }
                    }
                }
                cur = (c[4], c[5]);
            }
            Seg::Close => {}
        }
    }
    b
}

/// The box of an object whose local box is (x0, y0, w, h) under the
/// transformation `m`, as a position, size and rotation.
fn place(m: &[f64], x0: f64, y0: f64, w: f64, h: f64) -> Xfrm {
    let m = if m.len() == 6 {
        m
    } else {
        &[1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
    };
    let (cx, cy) = (x0 + w / 2.0, y0 + h / 2.0);
    let center = (m[0] * cx + m[2] * cy + m[4], m[1] * cx + m[3] * cy + m[5]);
    let sx = m[0].hypot(m[1]);
    let sy = m[2].hypot(m[3]);
    let (bw, bh) = (w * sx, h * sy);
    let clamp = |v: f64| v.clamp(-1e6, 1e6);
    Xfrm {
        x: (clamp(center.0 - bw / 2.0) * PT).round() as Emu,
        y: (clamp(center.1 - bh / 2.0) * PT).round() as Emu,
        w: (clamp(bw) * PT).round() as Emu,
        h: (clamp(bh) * PT).round() as Emu,
        rot: m[1].atan2(m[0]).to_degrees().rem_euclid(360.0),
        flip_h: m[0] * m[3] - m[1] * m[2] < 0.0,
        flip_v: false,
    }
}

impl<'a> Reader<'a> {
    fn image(&mut self, name: &str) -> Option<usize> {
        if let Some(&m) = self.media.get(name) {
            return m;
        }
        let bytes = match self.pkg.get(name) {
            Ok(b) => b,
            Err(e) => {
                self.failed.get_or_insert(e);
                None
            }
        };
        let m = bytes.and_then(|d| {
            let ext = crate::formats::office::slides::package::image_ext(&d)?;
            self.pending += d.len() as u64;
            Some(self.p.add_media(ext, d))
        });
        self.media.insert(name.to_string(), m);
        m
    }

    /// A `fill-style` or `background-fill-style`.
    fn fill(&mut self, f: &Node) -> Fill {
        match f.attr("fill-type") {
            Some("color") => f
                .attr("fill-color")
                .and_then(color)
                .map_or(Fill::None, Fill::Solid),
            Some("gradient") => {
                let g = f.child("gradient");
                let c = |a: &str| g.and_then(|g| g.attr(a)).and_then(color);
                let (Some(s), Some(e)) = (c("start-color"), c("end-color")) else {
                    return Fill::None;
                };
                let angle = g
                    .and_then(|g| g.attr("gradient-angle"))
                    .and_then(|a| a.trim().parse::<f64>().ok())
                    .unwrap_or(270.0);
                Fill::Gradient(Gradient {
                    stops: vec![(0, s), (100_000, e)],
                    kind: GradientKind::Linear((-angle).rem_euclid(360.0)),
                })
            }
            Some("image") => {
                let tile = f.attr("image-scale") == Some("tile");
                match f.attr("image-data").and_then(|n| self.image(n)) {
                    Some(media) => Fill::Picture { media, tile },
                    None => Fill::None,
                }
            }
            _ => Fill::None,
        }
    }

    fn master(&mut self, m: &'a Node, budget: &mut Budget) -> Result<usize> {
        let mut out = Master {
            name: m.attr("name").unwrap_or("Master").to_string(),
            layouts: vec![Layout {
                name: "Blank".into(),
                kind: "blank",
                show_master_shapes: true,
                ..Layout::default()
            }],
            ..Master::default()
        };
        out.background = Some(
            m.child("background-fill-style")
                .map(|f| self.fill(f))
                .filter(|f| *f != Fill::None)
                .unwrap_or(Fill::Solid(Color::rgb(0xFFFFFF))),
        );
        if let Some(d) = m.child("drawables") {
            self.drawables(d, None, None, &mut out.shapes, budget)?;
        }
        budget.alloc(std::mem::take(&mut self.pending))?;
        let i = self.p.masters.len();
        self.p.masters.push(out);
        Ok(i)
    }

    fn slide(
        &mut self,
        s: &'a Node,
        mi: usize,
        master: &'a Node,
        budget: &mut Budget,
    ) -> Result<Slide> {
        let background = s
            .child("background-fill-style")
            .map(|f| self.fill(f))
            .filter(|f| *f != Fill::None);
        let mut shapes = vec![];
        if let Some(d) = s.child("drawables") {
            self.drawables(d, Some(s), Some(master), &mut shapes, budget)?;
        }
        budget.alloc(std::mem::take(&mut self.pending))?;
        Ok(Slide {
            name: None,
            master: mi,
            layout: 0,
            background,
            shapes,
            hidden: s.attr("hidden") == Some("true"),
            show_master_shapes: true,
        })
    }

    /// The objects of a `drawables` list. In a slide, the title and body
    /// placeholders get the text of the slide's bullets, placed as the
    /// master's placeholders are.
    fn drawables(
        &mut self,
        list: &'a Node,
        slide: Option<&'a Node>,
        master: Option<&'a Node>,
        out: &mut Vec<Shape>,
        budget: &mut Budget,
    ) -> Result<()> {
        for n in list.nodes().take(10_000) {
            let shape = match n.name.as_str() {
                "title" | "body" => match slide {
                    Some(s) => self.placeholder(n, s, master, budget)?,
                    None => None,
                },
                "shape" => {
                    budget.shape(0)?;
                    self.shape(n)
                }
                "line" => {
                    budget.shape(0)?;
                    self.line(n)
                }
                "image" => {
                    budget.shape(0)?;
                    self.picture(n)
                }
                "textbox" => {
                    budget.shape(0)?;
                    self.textbox(n, budget)?
                }
                "plugin" => {
                    self.p.warn("tables and charts");
                    None
                }
                _ => None,
            };
            out.extend(shape);
            budget.alloc(std::mem::take(&mut self.pending))?;
        }
        Ok(())
    }

    /// Fill, line and shadow of an object, with its prototype's defaults.
    fn sp_props(&mut self, n: &'a Node, proto: Option<&'a Node>) -> Sp {
        let opacity = attr(n, proto, "opacity").and_then(|o| o.trim().parse::<f64>().ok());
        let fill = match style(n, proto, "fill-style") {
            Some(f) => match self.fill(f) {
                Fill::Solid(c) => Fill::Solid(with_opacity(c, opacity)),
                f => f,
            },
            None => Fill::None,
        };
        let dash = style(n, proto, "dash-style").and_then(|d| d.attr("pattern"));
        let line = match (dash, attr(n, proto, "stroke-color").and_then(color)) {
            (Some("none"), _) | (None, None) | (_, None) => Line::default(),
            (dash, Some(c)) => Line {
                fill: Fill::Solid(with_opacity(c, opacity)),
                width: (attr(n, proto, "stroke-width")
                    .and_then(|w| w.trim().parse::<f64>().ok())
                    .unwrap_or(1.0)
                    .clamp(0.0, 1000.0)
                    * PT)
                    .round() as Emu,
                dash: dash.filter(|d| *d != "solid").map(|_| "dash"),
                ..Line::default()
            },
        };
        let shadow = style(n, proto, "shadow-style").and_then(|s| {
            let o = s
                .attr("opacity")
                .and_then(|o| o.trim().parse::<f64>().ok())
                .unwrap_or(0.0);
            if o <= 0.0 {
                return None;
            }
            let f = |a: &str, d: f64| {
                s.attr(a)
                    .and_then(|v| v.trim().parse::<f64>().ok())
                    .unwrap_or(d)
            };
            let c = s.attr("color").and_then(color).unwrap_or(Color::rgb(0));
            Some(Shadow {
                color: with_opacity(c, Some(o)),
                blur: (f("radius", 0.0).clamp(0.0, 1000.0) * PT).round() as Emu,
                dist: (f("offset", 0.0).abs().min(1000.0) * PT).round() as Emu,
                // Counterclockwise degrees, to DrawingML's clockwise.
                dir: (-f("angle", 315.0)).rem_euclid(360.0),
            })
        });
        Sp {
            fill,
            line,
            shadow,
            ..Sp::default()
        }
    }

    fn shape(&mut self, n: &'a Node) -> Option<Shape> {
        let proto = self.protos.get("shape").copied();
        let segs = parse_path(n.attr("path")?)?;
        let (x0, y0, x1, y1) = bounds(&segs)?;
        let (w, h) = ((x1 - x0).max(0.01), (y1 - y0).max(0.01));
        let m = nums(n.attr("transformation").unwrap_or(""));
        let xf = place(&m, x0, y0, w, h);
        let s = 100.0;
        let p = |x: f64, y: f64| (((x - x0) * s).round() as i64, ((y - y0) * s).round() as i64);
        let mut path = Path {
            w: (w * s).round().max(1.0) as i64,
            h: (h * s).round().max(1.0) as i64,
            fill: true,
            stroke: true,
            cmds: vec![],
        };
        for seg in &segs {
            path.cmds.push(match seg {
                Seg::Move(x, y) => {
                    let q = p(*x, *y);
                    PathCmd::Move(q.0, q.1)
                }
                Seg::Line(x, y) => {
                    let q = p(*x, *y);
                    PathCmd::Line(q.0, q.1)
                }
                Seg::Cubic(c) => {
                    let (a, b, d) = (p(c[0], c[1]), p(c[2], c[3]), p(c[4], c[5]));
                    PathCmd::Cubic(a.0, a.1, b.0, b.1, d.0, d.1)
                }
                Seg::Close => PathCmd::Close,
            });
        }
        if matches!(path.cmds.last(), Some(PathCmd::Move(..))) {
            path.cmds.pop();
        }
        let mut sp = self.sp_props(n, proto);
        sp.geom = Geometry::Custom(vec![path]);
        Some(Shape::new(ShapeKind::Sp(Box::new(sp)), xf))
    }

    fn line(&mut self, n: &'a Node) -> Option<Shape> {
        let proto = self.protos.get("line").copied();
        let t = nums(n.attr("tail")?);
        let h = nums(n.attr("head")?);
        let (tx, ty, hx, hy) = (*t.first()?, *t.get(1)?, *h.first()?, *h.get(1)?);
        let (x0, y0) = (tx.min(hx), ty.min(hy));
        let (w, hh) = ((tx - hx).abs(), (ty - hy).abs());
        let s = 100.0;
        let p = |x: f64, y: f64| (((x - x0) * s).round() as i64, ((y - y0) * s).round() as i64);
        let (a, b) = (p(tx, ty), p(hx, hy));
        let path = Path {
            w: (w * s).round().max(1.0) as i64,
            h: (hh * s).round().max(1.0) as i64,
            fill: false,
            stroke: true,
            cmds: vec![PathCmd::Move(a.0, a.1), PathCmd::Line(b.0, b.1)],
        };
        let xf = place(&[1.0, 0.0, 0.0, 1.0, 0.0, 0.0], x0, y0, w, hh);
        let mut sp = self.sp_props(n, proto);
        sp.fill = Fill::None;
        sp.geom = Geometry::Custom(vec![path]);
        Some(Shape::new(ShapeKind::Sp(Box::new(sp)), xf))
    }

    fn picture(&mut self, n: &'a Node) -> Option<Shape> {
        let proto = self.protos.get("image").copied();
        let media = self.image(n.attr("image-data")?)?;
        let size = nums(n.attr("natural-size")?);
        let (w, h) = (*size.first()?, *size.get(1)?);
        let m = nums(attr(n, proto, "transformation").unwrap_or(""));
        let xf = place(&m, 0.0, 0.0, w.max(1.0), h.max(1.0));
        let sp = self.sp_props(n, proto);
        Some(Shape::new(
            ShapeKind::Pic(Box::new(Pic {
                media,
                crop: [0; 4],
                geom: Geometry::default(),
                line: sp.line,
                shadow: sp.shadow,
                alpha: None,
            })),
            xf,
        ))
    }

    fn textbox(&mut self, n: &'a Node, budget: &mut Budget) -> Result<Option<Shape>> {
        let proto = self.protos.get("textbox").copied();
        let Some(content) = n.child("content") else {
            return Ok(None);
        };
        let size = nums(n.attr("size").unwrap_or(""));
        let m = nums(attr(n, proto, "transformation").unwrap_or(""));
        let w = size.first().copied().unwrap_or(200.0).max(1.0);
        let h = size.get(1).copied().unwrap_or(50.0).max(1.0);
        let xf = place(&m, 0.0, 0.0, w, h);
        let defaults = proto.and_then(|p| p.child("content"));
        let Some(text) = self.text(&[(content, 0)], defaults, Marker::default(), budget)? else {
            return Ok(None);
        };
        let mut sp = self.sp_props(n, proto);
        sp.text = Some(text);
        Ok(Some(Shape::new(ShapeKind::Sp(Box::new(sp)), xf)))
    }

    /// A title or body placeholder with the slide's bullets as its text.
    fn placeholder(
        &mut self,
        ph: &'a Node,
        slide: &'a Node,
        master: Option<&'a Node>,
        budget: &mut Budget,
    ) -> Result<Option<Shape>> {
        let title = ph.name == "title";
        if ph.attr("visibility") == Some("hidden") {
            return Ok(None);
        }
        // The master's placeholder places it unless the slide's does.
        let from_master = master
            .and_then(|m| m.child("drawables"))
            .and_then(|d| d.child(&ph.name));
        let geo = |a: &str| ph.attr(a).or_else(|| from_master.and_then(|m| m.attr(a)));
        let (Some(size), Some(loc)) = (geo("size").map(nums), geo("location").map(nums)) else {
            return Ok(None);
        };
        let (Some(&w), Some(&h), Some(&x), Some(&y)) =
            (size.first(), size.get(1), loc.first(), loc.get(1))
        else {
            return Ok(None);
        };
        let Some(bullets) = slide.child("bullets") else {
            return Ok(None);
        };
        let protos = master.and_then(|m| m.child("prototype-bullets"));
        let indents = geo("bullet-indentation").map(nums).unwrap_or_default();
        let mut frames: Vec<(&Node, u32, &Node)> = vec![];
        for b in bullets.all("bullet").take(1 << 16) {
            let level = b
                .attr("level")
                .and_then(|l| l.trim().parse::<u32>().ok())
                .unwrap_or(0);
            if (level == 0) != title {
                continue;
            }
            if let Some(c) = b.child("content") {
                frames.push((c, level, b));
            }
        }
        if frames.is_empty() {
            return Ok(None);
        }
        let mut valign = geo("vertical-alignment").unwrap_or("top");
        if valign == "tracks-master" {
            valign = from_master
                .and_then(|m| m.attr("vertical-alignment"))
                .unwrap_or("top");
        }
        let mut body = None;
        for &(frame, level, own) in &frames {
            let proto = protos.and_then(|p| {
                p.all("bullet").find(|p| {
                    p.attr("level").and_then(|l| l.trim().parse::<u32>().ok()) == Some(level)
                })
            });
            let one = self.text(
                &[(frame, level)],
                proto.and_then(|p| p.child("content")),
                Marker {
                    own: Some(own),
                    proto,
                    indent: indents.get(level as usize).copied(),
                },
                budget,
            )?;
            match (&mut body, one) {
                (None, one) => body = one,
                (Some(TextBody { paras, .. }), Some(more)) => paras.extend(more.paras),
                _ => {}
            }
        }
        let Some(mut text) = body else {
            return Ok(None);
        };
        text.body.anchor = match valign {
            "middle" => "ctr",
            "bottom" => "b",
            _ => "t",
        };
        let xf = place(&[1.0, 0.0, 0.0, 1.0, 0.0, 0.0], x, y, w, h);
        let sp = Sp {
            text: Some(text),
            ..Sp::default()
        };
        let mut s = Shape::new(ShapeKind::Sp(Box::new(sp)), xf);
        s.placeholder = Some(if title {
            Placeholder {
                kind: "title",
                idx: None,
            }
        } else {
            Placeholder {
                kind: "body",
                idx: Some(1),
            }
        });
        Ok(Some(s))
    }

    /// The `content` elements as a text body, one paragraph per line;
    /// `defaults` gives the attributes a content does not set, `bullet` the
    /// prototype bullet of its level.
    fn text(
        &mut self,
        frames: &[(&'a Node, u32)],
        defaults: Option<&'a Node>,
        marker: Marker<'a>,
        budget: &mut Budget,
    ) -> Result<Option<TextBody>> {
        use crate::formats::office::common::xml::Child;
        let mut paras = vec![];
        for &(c, level) in frames {
            let chain: Vec<&Node> = [Some(c), defaults].into_iter().flatten().collect();
            let bp = self.para_props(&chain, &marker, level);
            let base = self.run_props(&chain);
            let mut cur = Paragraph {
                props: bp.clone(),
                runs: vec![],
                end: base.clone(),
            };
            // Text, and spans that change the character attributes; a new
            // line starts a paragraph.
            let mut pieces: Vec<(String, RunProps)> = vec![];
            for k in &c.children {
                match k {
                    Child::Text(t) => pieces.push((t.clone(), base.clone())),
                    Child::Node(n) if n.name == "span" => {
                        let mut sc = vec![n];
                        sc.extend(&chain);
                        pieces.push((flat_text(n), self.run_props(&sc)));
                    }
                    _ => {}
                }
            }
            budget.alloc(pieces.iter().map(|p| p.0.len() as u64).sum::<u64>() * 16)?;
            for (text, rp) in pieces {
                let mut lines = text.split('\n');
                if let Some(first) = lines.next() {
                    push_text(&mut cur.runs, first, &rp);
                }
                for line in lines {
                    paras.push(std::mem::replace(
                        &mut cur,
                        Paragraph {
                            props: bp.clone(),
                            runs: vec![],
                            end: base.clone(),
                        },
                    ));
                    push_text(&mut cur.runs, line, &rp);
                }
            }
            paras.push(cur);
        }
        if paras.iter().all(|p| p.runs.is_empty()) {
            return Ok(None);
        }
        Ok(Some(TextBody {
            body: BodyProps::default(),
            paras,
            levels: ListStyle::default(),
        }))
    }

    /// Run properties from attributes: the first node of `chain` that has
    /// one gives it.
    fn run_props(&self, chain: &[&Node]) -> RunProps {
        let a = |n: &str| chain.iter().find_map(|c| c.attr(n));
        let mut rp = RunProps::default();
        if let Some(name) = a("font-name") {
            let (fam, b, i) = ps_font(name);
            rp.font = Some(fam);
            if b {
                rp.bold = Some(true);
            }
            if i {
                rp.italic = Some(true);
            }
        }
        let size = a("font-size")
            .and_then(|s| s.trim().parse::<f64>().ok())
            .unwrap_or(24.0)
            .clamp(1.0, 4000.0);
        rp.size = Some((size * 100.0).round() as u32);
        rp.color = Some(a("font-color").and_then(color).unwrap_or(Color::rgb(0)));
        rp
    }

    fn para_props(&self, chain: &[&Node], marker: &Marker, level: u32) -> ParaProps {
        let a = |n: &str| chain.iter().find_map(|c| c.attr(n));
        let pts = |v: f64| (v.clamp(-10_000.0, 10_000.0) * PT).round() as Emu;
        let f = |n: &str| a(n).and_then(|v| v.trim().parse::<f64>().ok());
        let mut pp = ParaProps {
            level: level.min(8) as u8,
            align: a("paragraph-alignment").map(|v| match v {
                "right" => "r",
                "center" => "ctr",
                "justify" | "justified" => "just",
                _ => "l",
            }),
            margin: f("paragraph-head-indent").map(pts),
            indent: f("paragraph-first-line-indent")
                .map(|fl| pts(fl - f("paragraph-head-indent").unwrap_or(0.0))),
            bullet: Some(Bullet::None),
            ..ParaProps::default()
        };
        if level == 0 {
            return pp;
        }
        // The slide's bullet says how it is marked, "inherited" meaning as
        // the master's prototype for its level.
        let kind = match marker.own.and_then(|b| b.attr("marker-type")) {
            Some(k) if k != "inherited" => Some(k),
            _ => marker.proto.and_then(|b| b.attr("marker-type")),
        };
        let spec = marker
            .own
            .and_then(|b| b.child("character-bullet-style"))
            .or_else(|| marker.proto.and_then(|b| b.child("character-bullet-style")));
        let glyph = spec.and_then(|s| s.child("bullet-characters"));
        let ch = glyph
            .map(|c| c.own_text())
            .and_then(|t| t.trim().chars().next())
            .unwrap_or('\u{2022}');
        // The bullet's size is relative to the text's.
        let size = spec
            .and_then(|s| s.attr("size"))
            .and_then(|s| s.trim().parse::<f64>().ok())
            .zip(
                glyph
                    .and_then(|g| g.attr("font-size"))
                    .and_then(|s| s.trim().parse::<f64>().ok()),
            )
            .zip(f("font-size"))
            .map(|((rel, bs), fs)| {
                ((rel * bs / fs.max(1.0)) * 100_000.0).clamp(25_000.0, 400_000.0) as u32
            });
        let color = glyph
            .and_then(|g| g.attr("font-color"))
            .and_then(color)
            .or_else(|| a("font-color").and_then(color));
        pp.space_before = marker
            .own
            .and_then(|b| b.attr("spacing"))
            .or_else(|| marker.proto.and_then(|b| b.attr("spacing")))
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|s| *s > 0.0)
            .map(|s| Spacing::Pts((s.min(1000.0) * 100.0).round() as i32));
        pp.bullet = match kind {
            Some("character" | "image") => Some(Bullet::Char {
                ch,
                font: None,
                color,
                size,
            }),
            Some("sequence") => Some(Bullet::AutoNum {
                scheme: "arabicPeriod",
                start: 1,
                font: None,
                color,
                size,
            }),
            _ => Some(Bullet::None),
        };
        if pp.bullet != Some(Bullet::None) {
            // The bullet is at the level's indentation plus the first line
            // indent; the text follows it.
            let at = marker.indent.unwrap_or(0.0) + f("paragraph-first-line-indent").unwrap_or(0.0);
            pp.margin = Some(pts(at + 25.0));
            pp.indent = Some(pts(-25.0));
        }
        pp
    }
}

/// How a bullet is marked: the slide's own bullet, the master's prototype
/// for its level and the level's indentation in the placeholder.
#[derive(Default)]
struct Marker<'a> {
    own: Option<&'a Node>,
    proto: Option<&'a Node>,
    indent: Option<f64>,
}

fn push_text(runs: &mut Vec<Run>, text: &str, props: &RunProps) {
    if text.is_empty() {
        return;
    }
    match runs.last_mut() {
        Some(Run {
            kind: RunKind::Text(prev),
            props: p,
        }) if p == props => prev.push_str(text),
        _ => runs.push(Run {
            kind: RunKind::Text(text.to_string()),
            props: props.clone(),
        }),
    }
}

/// The text of a `span`.
fn flat_text(c: &Node) -> String {
    use crate::formats::office::common::xml::Child;
    let mut out = String::new();
    for k in &c.children {
        match k {
            Child::Text(t) => out.push_str(t),
            Child::Node(n) if n.name == "span" => out.push_str(&flat_text(n)),
            _ => {}
        }
    }
    out
}
