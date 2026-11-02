//! PowerPoint 95 (version 7) presentations: a compound file whose
//! "PowerPoint Document" stream is one tree of records with a 16-byte
//! header (type, 0xFFFF for a container, length, an identifier), and
//! pictures and text in the same stream. Microsoft published no
//! specification of it; what is read here was learnt from sample documents
//! and from another application's output on them, used as a black box.
//!
//! What the samples show:
//! - The document (3, then 0x03E8) holds the document atom (0x03E9: slide
//!   size in master units, 1/576 inch), the environment (0x03F2, with the
//!   font entities 0x0FB7: a name at byte 28), and the slides (0x03EE) and
//!   masters (0x03F8) in containers 0x07D0. A slide's colour scheme is
//!   0x03F4 / 0x07EF: a count, then red, green, blue, 0 for each colour.
//! - A slide's own 0x0BC0 is its background; its objects are the children of
//!   0x0BB8 (a group, 0x0BB9, holds another). Coordinates have their origin
//!   at the slide's centre. Objects: 0x0BC0 a shape, 0x0BC2 a placeholder
//!   with text (0x0BC3: its type), 0x0BC6 a line (0x0BC7: x1 y1 x2 y2, 0x0BBF:
//!   head and tail arrow styles), 0x0BC8 a freeform, 0x0BCA an arc.
//! - 0x0BC1 (40 bytes) is a shape's bounds: its geometry code (-3 rectangle,
//!   -2 rounded rectangle with its adjustment next, -1 ellipse, 3 burst, 4
//!   parallelogram, 5 hexagon, 9 right arrow, 14 trapezoid; 0x4000 and 0x2000
//!   flip it), the adjustment, flags, then left, top, right, bottom and the
//!   rotation (see `rotation`).
//! - 0x0BBD (56 bytes) is its look. Byte 0: 0xFF for no line, else the line's
//!   dash (byte 1) and width (byte 3, an index into `WIDTHS`); 4 to 7 the line
//!   colour; byte 12 0xFF for no fill; byte 13 the kind of fill (1 solid, 2
//!   the background, 3 half transparent, 4 and 6 a pattern, 5 a gradient, 7 a
//!   picture), 20 to 23 the fill colour and 24 to 27 the second colour. A
//!   colour is red, green, blue and an index: 0xFE for the RGB, else a
//!   scheme colour.
//! - Text (0x0FA1 / 0x0FA2 / 0x0FE0): the characters, in Windows 1252, in a
//!   0x07EE atom (identifier 53); character runs (0x0FE2) and paragraph runs
//!   (0x0FE3) in 0x07EC containers, each run a count of characters, its type,
//!   a size and a pointer, then its properties. Character properties: font
//!   (2 bytes), size in points (at 4), flags at 8 (1 bold, 2 italic, 4
//!   underline, 0x400 superscript, 0x800 subscript), colour at 10, the
//!   position in percent at 16. Paragraph properties: bullet flags (at 0, 1
//!   for a bullet), bullet colour (2), character (6), font (8), size in
//!   percent (12), alignment (28: 0 left, 1 centre, 2 right, 3 justified),
//!   line spacing (32), space before (36) and after (40): positive is a
//!   percent of the text, negative is points.

use crate::formats::office::common::bytes::Cur;
use crate::formats::office::slides::error::{Error, Result};
use crate::formats::office::slides::limits::Budget;
use crate::formats::office::slides::model::*;

/// Whether `stream` is a PowerPoint 95 document stream.
pub(crate) fn is95(stream: &[u8]) -> bool {
    stream.len() >= 16 && Cur::new(stream).u32() == 3 && Cur::at(stream, 4).u32() == 0xFFFF
}

const MASTER_UNIT: f64 = 1587.5;

/// Line widths in points, by the width index.
const WIDTHS: [f64; 10] = [1.0, 2.0, 3.0, 6.0, 8.0, 10.0, 3.0, 4.0, 4.0, 6.0];

const DEFAULT_SCHEME: [Rgb; 8] = [
    0xFFFFFF, 0x000000, 0x808080, 0x000000, 0x00CC99, 0x3333CC, 0xCCCCFF, 0xB2B2B2,
];

#[derive(Clone, Copy)]
struct Rec<'a> {
    typ: u32,
    flag: u32,
    /// The header's fourth field: for a text atom, what it holds.
    id: u32,
    data: &'a [u8],
}

struct Recs<'a> {
    d: &'a [u8],
    p: usize,
    n: usize,
}

fn recs(d: &[u8]) -> Recs<'_> {
    Recs { d, p: 0, n: 0 }
}

impl<'a> Iterator for Recs<'a> {
    type Item = Rec<'a>;

    fn next(&mut self) -> Option<Rec<'a>> {
        if self.p + 16 > self.d.len() || self.n >= 1 << 20 {
            return None;
        }
        let mut c = Cur::at(self.d, self.p);
        let typ = c.u32();
        let flag = c.u32();
        let len = c.u32() as usize;
        let id = c.u32();
        let start = self.p + 16;
        let end = start.saturating_add(len).min(self.d.len());
        self.p = end;
        self.n += 1;
        Some(Rec {
            typ,
            flag,
            id,
            data: &self.d[start..end],
        })
    }
}

impl<'a> Rec<'a> {
    fn kids(&self) -> Recs<'a> {
        recs(self.data)
    }

    fn child(&self, typ: u32) -> Option<Rec<'a>> {
        self.kids().find(|r| r.typ == typ)
    }

    fn container(&self) -> bool {
        self.flag == 0xFFFF
    }
}

/// Records of type `typ` anywhere under `r`, in order.
fn find_all<'a>(r: &Rec<'a>, typ: u32, depth: u32, out: &mut Vec<Rec<'a>>) {
    for k in r.kids() {
        if k.typ == typ {
            out.push(k);
        }
        // A string is a record with the container flag but holds text.
        if k.container() && k.typ != 0x0FBA && depth < 16 && out.len() < 4096 {
            find_all(&k, typ, depth + 1, out);
        }
    }
}

struct Reader<'a> {
    fonts: Vec<String>,
    width: i64,
    height: i64,
    p: Presentation,
    _marker: std::marker::PhantomData<&'a ()>,
}

pub(crate) fn read(stream: &[u8], budget: &mut Budget) -> Result<Presentation> {
    let root = recs(stream)
        .next()
        .filter(|r| r.typ == 3)
        .ok_or_else(|| Error::Malformed("no file record".into()))?;
    let doc = root
        .child(0x03E8)
        .ok_or_else(|| Error::Malformed("no document record".into()))?;
    let (w, h) = doc
        .child(0x03E9)
        .map(|a| (Cur::new(a.data).i32(), Cur::at(a.data, 4).i32()))
        .unwrap_or((5760, 4320));
    let (w, h) = (
        i64::from(w.clamp(576, 100_000)),
        i64::from(h.clamp(576, 100_000)),
    );
    let mut r = Reader {
        fonts: vec![],
        width: w,
        height: h,
        p: Presentation::default(),
        _marker: std::marker::PhantomData,
    };
    r.p.width = (w as f64 * MASTER_UNIT).round() as Emu;
    r.p.height = (h as f64 * MASTER_UNIT).round() as Emu;
    // The fonts, in the order the runs name them.
    let mut ents = vec![];
    find_all(&doc, 0x0FB7, 0, &mut ents);
    for e in ents.iter().take(4096) {
        let name = e.data.get(28..60).unwrap_or(&[]);
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        r.fonts
            .push(crate::formats::office::slides::package::latin1(
                &name[..end],
            ));
    }
    let mut slides: Vec<Rec> = vec![];
    let mut masters: Vec<Rec> = vec![];
    for k in doc.kids().filter(|k| k.typ == 0x07D0) {
        for s in k.kids() {
            match s.typ {
                0x03EE => slides.push(s),
                0x03F8 => masters.push(s),
                _ => {}
            }
        }
    }
    // One master; a slide's own scheme and shapes come over it.
    let mut master = Master {
        name: "Master".into(),
        layouts: vec![Layout {
            name: "Blank".into(),
            kind: "blank",
            show_master_shapes: true,
            ..Layout::default()
        }],
        background: Some(Fill::Solid(Color::rgb(0xFFFFFF))),
        ..Master::default()
    };
    if let Some(m) = masters.first() {
        let scheme = scheme_of(m);
        if let Some(bg) = m.child(0x0BC0).and_then(|b| r.background(&b, &scheme)) {
            master.background = Some(bg);
        }
        if let Some(list) = m.child(0x0BB8) {
            r.shapes(&list, &scheme, true, &mut master.shapes, budget, 0)?;
        }
    }
    r.p.masters.push(master);
    let mut n = 0usize;
    for s in slides {
        budget.slide(n)?;
        n += 1;
        r.p.total_slides = n;
        if !budget.wants(n - 1) {
            continue;
        }
        let scheme = scheme_of(&s);
        let background = s.child(0x0BC0).and_then(|b| r.background(&b, &scheme));
        let mut shapes = vec![];
        if let Some(list) = s.child(0x0BB8) {
            r.shapes(&list, &scheme, false, &mut shapes, budget, 0)?;
        }
        r.p.slides.push(Slide {
            name: None,
            master: 0,
            layout: 0,
            background,
            shapes,
            hidden: false,
            show_master_shapes: true,
        });
    }
    Ok(r.p)
}

/// A slide's or master's colour scheme.
fn scheme_of(r: &Rec) -> [Rgb; 8] {
    let Some(a) = r.child(0x03F4).and_then(|s| s.child(0x07EF)) else {
        return DEFAULT_SCHEME;
    };
    let mut out = DEFAULT_SCHEME;
    let mut c = Cur::at(a.data, 4);
    for slot in &mut out {
        let (rr, g, b, _) = (c.u8(), c.u8(), c.u8(), c.u8());
        if c.short {
            return DEFAULT_SCHEME;
        }
        *slot = u32::from(rr) << 16 | u32::from(g) << 8 | u32::from(b);
    }
    out
}

/// A colour: red, green, blue and an index (0xFE: the RGB; 0 to 7: the
/// scheme's).
fn color_at(d: &[u8], at: usize, scheme: &[Rgb; 8]) -> Option<Rgb> {
    let b = d.get(at..at + 4)?;
    match b[3] {
        0xFE => Some(u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2])),
        i if i < 8 => Some(scheme[usize::from(i)]),
        _ => None,
    }
}

impl Reader<'_> {
    fn emu_x(&self, x: i32) -> Emu {
        ((f64::from(x) + self.width as f64 / 2.0) * MASTER_UNIT).round() as Emu
    }

    fn emu_y(&self, y: i32) -> Emu {
        ((f64::from(y) + self.height as f64 / 2.0) * MASTER_UNIT).round() as Emu
    }

    /// A slide's background from its own shape: a solid fill.
    fn background(&self, b: &Rec, scheme: &[Rgb; 8]) -> Option<Fill> {
        let look = b.child(0x0BBD)?;
        match fill_of(look.data, scheme) {
            f @ Fill::Solid(_) => Some(f),
            _ => None,
        }
    }

    /// The objects of a 0x0BB8 list.
    fn shapes(
        &mut self,
        list: &Rec,
        scheme: &[Rgb; 8],
        master: bool,
        out: &mut Vec<Shape>,
        budget: &mut Budget,
        depth: u32,
    ) -> Result<()> {
        for k in list.kids().take(1 << 16) {
            match k.typ {
                0x0BB9 if depth < 16 => {
                    if let Some(inner) = k.child(0x0BB8) {
                        self.shapes(&inner, scheme, master, out, budget, depth + 1)?;
                    }
                }
                0x0BC0 | 0x0BC2 | 0x0BC4 => {
                    budget.shape(0)?;
                    out.extend(self.boxed(&k, scheme, master, budget)?);
                }
                0x0BC6 => {
                    budget.shape(0)?;
                    out.extend(self.line(&k, scheme));
                }
                0x0BC8 | 0x0BCA => self.p.warn("freeform shapes and arcs"),
                _ => {}
            }
        }
        Ok(())
    }

    /// A shape with a geometry code, and its text.
    fn boxed(
        &mut self,
        k: &Rec,
        scheme: &[Rgb; 8],
        master: bool,
        budget: &mut Budget,
    ) -> Result<Option<Shape>> {
        let (Some(b), Some(look)) = (k.child(0x0BC1), k.child(0x0BBD)) else {
            return Ok(None);
        };
        let mut c = Cur::new(b.data);
        let code = c.i32();
        let adj = c.i32();
        c.skip(4);
        let (l, t, r, bt) = (c.i32(), c.i32(), c.i32(), c.i32());
        let rot = c.i32();
        if c.short {
            return Ok(None);
        }
        let xf = Xfrm {
            x: self.emu_x(l.min(r)),
            y: self.emu_y(t.min(bt)),
            w: ((f64::from(r) - f64::from(l)).abs() * MASTER_UNIT).round() as Emu,
            h: ((f64::from(bt) - f64::from(t)).abs() * MASTER_UNIT).round() as Emu,
            rot: rotation(rot),
            flip_h: code & 0x4000 != 0 && code > 0,
            flip_v: code & 0x2000 != 0 && code > 0,
        };
        let kind = if code > 0 { code & 0x1FFF } else { code };
        let geom = geometry(kind, adj);
        let fill = fill_of(look.data, scheme);
        let line = line_of(look.data, scheme);
        let ph = k
            .child(0x0BC3)
            .map(|p| Cur::new(p.data).u32() & 0xFF)
            .filter(|_| k.typ == 0x0BC2);
        let text = match k.child(0x0FA1) {
            Some(t) => self.text(&t, scheme, ph, budget)?,
            None => None,
        };
        // A placeholder shows only its own text and look; a master's shows
        // its prompt on the master and nothing on the slides.
        if (master && ph.is_some())
            || (ph.is_some() && text.is_none() && fill == Fill::None && line.fill == Fill::None)
        {
            return Ok(None);
        }
        if text.is_none() && fill == Fill::None && line.fill == Fill::None {
            return Ok(None);
        }
        let mut s = Shape::new(
            ShapeKind::Sp(Box::new(Sp {
                geom,
                fill,
                line,
                text,
                ..Sp::default()
            })),
            xf,
        );
        s.placeholder = ph.map(|id| match id {
            0x0D => Placeholder {
                kind: "title",
                idx: None,
            },
            0x0F => Placeholder {
                kind: "ctrTitle",
                idx: None,
            },
            0x10 => Placeholder {
                kind: "subTitle",
                idx: Some(1),
            },
            _ => Placeholder {
                kind: "body",
                idx: Some(1),
            },
        });
        Ok(Some(s))
    }

    fn line(&mut self, k: &Rec, scheme: &[Rgb; 8]) -> Option<Shape> {
        let (pts, look) = (k.child(0x0BC7)?, k.child(0x0BBD)?);
        let mut c = Cur::new(pts.data);
        let (x1, y1, x2, y2) = (c.i32(), c.i32(), c.i32(), c.i32());
        if c.short {
            return None;
        }
        let xf = Xfrm {
            x: self.emu_x(x1.min(x2)),
            y: self.emu_y(y1.min(y2)),
            w: ((f64::from(x1) - f64::from(x2)).abs() * MASTER_UNIT).round() as Emu,
            h: ((f64::from(y1) - f64::from(y2)).abs() * MASTER_UNIT).round() as Emu,
            ..Xfrm::default()
        };
        let (a, b) = (
            (
                (x1 - x1.min(x2)) as i64 * 100,
                (y1 - y1.min(y2)) as i64 * 100,
            ),
            (
                (x2 - x1.min(x2)) as i64 * 100,
                (y2 - y1.min(y2)) as i64 * 100,
            ),
        );
        let path = Path {
            w: (i64::from((x1 - x2).abs()) * 100).max(1),
            h: (i64::from((y1 - y2).abs()) * 100).max(1),
            fill: false,
            stroke: true,
            cmds: vec![PathCmd::Move(a.0, a.1), PathCmd::Line(b.0, b.1)],
        };
        let mut line = line_of(look.data, scheme);
        if let Some(arrows) = k.child(0x0BBF) {
            // The head grows with the line's width: a thick line's is small.
            let size = if line.width >= 38_100 { "sm" } else { "med" };
            let tri = Arrow {
                kind: "triangle",
                w: size,
                len: size,
            };
            if arrows.data.first().is_some_and(|&v| v != 0) {
                line.head = Some(tri.clone());
            }
            if arrows.data.get(1).is_some_and(|&v| v != 0) {
                line.tail = Some(tri);
            }
        }
        if line.fill == Fill::None {
            return None;
        }
        Some(Shape::new(
            ShapeKind::Sp(Box::new(Sp {
                geom: Geometry::Custom(vec![path]),
                fill: Fill::None,
                line,
                ..Sp::default()
            })),
            xf,
        ))
    }

    /// A text object's paragraphs, with the formatting of its runs.
    fn text(
        &mut self,
        t: &Rec,
        scheme: &[Rgb; 8],
        ph: Option<u32>,
        budget: &mut Budget,
    ) -> Result<Option<TextBody>> {
        let Some(body) = t.child(0x0FA2).and_then(|b| b.child(0x0FE0)) else {
            return Ok(None);
        };
        let Some(chars) = body
            .kids()
            .find(|k| k.typ == 0x07EE && k.id == 53)
            .map(|k| k.data)
        else {
            return Ok(None);
        };
        let mut char_runs: Vec<(usize, &[u8])> = vec![];
        let mut para_runs: Vec<(usize, &[u8])> = vec![];
        for rc in body.kids().filter(|k| k.typ == 0x07EC) {
            for atom in rc.kids().filter(|a| a.typ == 0x07EE) {
                let d = atom.data;
                let mut p = 0usize;
                // A count of characters, the run's type, 4 bytes, the
                // properties' size, a pointer, the properties.
                while p + 20 <= d.len() && char_runs.len() + para_runs.len() < 1 << 16 {
                    let mut c = Cur::at(d, p);
                    let count = c.u32() as usize;
                    let typ = c.u32();
                    c.skip(4);
                    let size = c.u32() as usize;
                    let Some(props) = d.get(p + 20..p + 20 + size) else {
                        break;
                    };
                    match typ {
                        0x0FE2 => char_runs.push((count, props)),
                        0x0FE3 => para_runs.push((count, props)),
                        _ => {}
                    }
                    p += 20 + size;
                }
            }
        }
        budget.alloc(chars.len() as u64 * 16)?;
        let text: Vec<u8> = chars.iter().take(1 << 20).copied().collect();
        if text.iter().all(|&b| b == b'\r' || b == 0) {
            return Ok(None);
        }
        let mut paras = vec![];
        let mut start = 0usize;
        loop {
            let end = text[start..]
                .iter()
                .position(|&b| b == b'\r')
                .map_or(text.len(), |i| start + i);
            let pp = run_at(&para_runs, start);
            let first = run_at(&char_runs, start).map(|p| self.run_props(p, scheme));
            let size = first.as_ref().and_then(|r| r.size).unwrap_or(1800);
            let props = self.para_props(pp, size, scheme);
            let mut runs: Vec<Run> = vec![];
            let mut i = start;
            while i < end {
                let (n, cp) = run_span(&char_runs, i);
                let stop = (i + n.max(1)).min(end);
                let rp = cp.map(|p| self.run_props(p, scheme)).unwrap_or_default();
                let s = crate::formats::office::slides::package::latin1(&text[i..stop]);
                match runs.last_mut() {
                    Some(Run {
                        kind: RunKind::Text(prev),
                        props,
                    }) if *props == rp => prev.push_str(&s),
                    _ => runs.push(Run {
                        kind: RunKind::Text(s),
                        props: rp,
                    }),
                }
                i = stop;
            }
            paras.push(Paragraph {
                props,
                runs,
                end: first.unwrap_or_default(),
            });
            if end >= text.len() || paras.len() >= 1 << 16 {
                break;
            }
            start = end + 1;
        }
        Ok(Some(TextBody {
            body: BodyProps {
                anchor: if matches!(ph, Some(0x0D | 0x0F)) {
                    "ctr"
                } else {
                    "t"
                },
                // A text box fits its text: one line is not wrapped.
                wrap: ph.is_some() || paras.len() > 1,
                ..BodyProps::default()
            },
            paras,
            levels: ListStyle::default(),
        }))
    }

    /// Character properties: font at 0, size at 4, flags at 8, colour at
    /// 10, position at 16.
    fn run_props(&self, p: &[u8], scheme: &[Rgb; 8]) -> RunProps {
        let mut c = Cur::new(p);
        let font = usize::from(c.u16());
        c.skip(2);
        let size = c.u16();
        c.skip(2);
        let flags = c.u16();
        let color = color_at(p, 10, scheme).unwrap_or(0);
        let pos = Cur::at(p, 16).i32();
        RunProps {
            size: Some(u32::from(size.clamp(1, 4000)) * 100),
            bold: Some(flags & 1 != 0),
            italic: Some(flags & 2 != 0),
            underline: (flags & 4 != 0).then_some("sng"),
            color: Some(Color::rgb(color)),
            font: self.fonts.get(font).filter(|f| !f.is_empty()).cloned(),
            baseline: if flags & 0x400 != 0 {
                Some(pos.clamp(-100, 100) * 1000)
            } else if flags & 0x800 != 0 {
                Some(-pos.abs().clamp(0, 100) * 1000)
            } else {
                None
            },
            ..RunProps::default()
        }
    }

    /// Paragraph properties: bullet flags at 0, bullet colour at 2,
    /// character at 6, font at 8, size at 12, alignment at 28, line
    /// spacing at 32, space before at 36 and after at 40.
    fn para_props(&self, p: Option<&[u8]>, size: u32, scheme: &[Rgb; 8]) -> ParaProps {
        let Some(p) = p else {
            return ParaProps {
                bullet: Some(Bullet::None),
                ..ParaProps::default()
            };
        };
        let mut c = Cur::new(p);
        let bullet_flags = c.u16();
        let font = Cur::at(p, 8).u16();
        let ch = Cur::at(p, 6).u16();
        let bsize = Cur::at(p, 12).u32();
        let align = Cur::at(p, 28).u32();
        let line = Cur::at(p, 32).i32();
        let before = Cur::at(p, 36).i32();
        let after = Cur::at(p, 40).i32();
        // Positive spacing is a percent of the text's size; negative, points.
        let space = |v: i32| -> Option<Spacing> {
            match v {
                0 => None,
                v if v > 0 => Some(Spacing::Pts(
                    (f64::from(size) * f64::from(v.min(1000)) / 100.0).round() as i32,
                )),
                v => Some(Spacing::Pts(v.saturating_abs().min(1584) * 100)),
            }
        };
        let bullet = if bullet_flags & 1 != 0 {
            let name = self.fonts.get(usize::from(font)).map(String::as_str);
            let symbol = name.is_some_and(|n| {
                let l = n.to_ascii_lowercase();
                l.contains("sorts") || l.contains("wingdings") || l.contains("symbol")
            });
            let c = if symbol {
                '\u{2022}'
            } else {
                char::from_u32(
                    crate::formats::office::slides::package::latin1(&[ch as u8])
                        .chars()
                        .next()
                        .map_or(0x2022, |c| c as u32),
                )
                .filter(|c| !c.is_control())
                .unwrap_or('\u{2022}')
            };
            Bullet::Char {
                ch: c,
                font: None,
                color: color_at(p, 2, scheme).map(Color::rgb),
                size: Some(bsize)
                    .filter(|s| (25..=400).contains(s))
                    .map(|s| s * 1000),
            }
        } else {
            Bullet::None
        };
        let bulleted = bullet != Bullet::None;
        ParaProps {
            align: match align {
                1 => Some("ctr"),
                2 => Some("r"),
                3 => Some("just"),
                _ => None,
            },
            line_spacing: match line {
                0 => None,
                v if v > 0 => Some(Spacing::Pct(v.min(1000) * 1000)),
                v => Some(Spacing::Pts(v.saturating_abs().min(1584) * 100)),
            },
            space_before: space(before),
            space_after: space(after),
            margin: bulleted.then_some(228_600),
            indent: bulleted.then_some(-228_600),
            bullet: Some(bullet),
            ..ParaProps::default()
        }
    }
}

/// The run of `runs` (counts of characters) covering character `at`.
fn run_at<'a>(runs: &[(usize, &'a [u8])], at: usize) -> Option<&'a [u8]> {
    let mut start = 0usize;
    for (n, p) in runs {
        if at < start.saturating_add(*n) {
            return Some(p);
        }
        start = start.saturating_add(*n);
    }
    runs.last().map(|r| r.1)
}

/// The characters left in the run covering `at`, and its properties.
fn run_span<'a>(runs: &[(usize, &'a [u8])], at: usize) -> (usize, Option<&'a [u8]>) {
    let mut start = 0usize;
    for (n, p) in runs {
        if at < start.saturating_add(*n) {
            return (start + n - at, Some(p));
        }
        start = start.saturating_add(*n);
    }
    (usize::MAX / 2, runs.last().map(|r| r.1))
}

/// A shape's geometry from its code.
fn geometry(code: i32, adj: i32) -> Geometry {
    match code {
        -2 | 13 => Geometry::Preset {
            name: "roundRect",
            adj: vec![("adj", (f64::from(adj.clamp(0, 8100)) * 6.17).round() as i64)],
        },
        -1 => Geometry::preset("ellipse"),
        3 => Geometry::preset("irregularSeal1"),
        4 => Geometry::preset("parallelogram"),
        5 => Geometry::preset("hexagon"),
        9 => Geometry::preset("rightArrow"),
        14 => Geometry::preset("trapezoid"),
        _ => Geometry::default(),
    }
}

/// A shape's rotation in degrees: its value is in 1/14.93 of a degree.
fn rotation(v: i32) -> f64 {
    (f64::from(v) * 360.0 / 5376.0).rem_euclid(360.0)
}

/// A shape's line: bytes 0 (0xFF for none), 1 (dash), 3 (width index) and
/// the colour at 4.
fn line_of(d: &[u8], scheme: &[Rgb; 8]) -> Line {
    if d.first().is_none_or(|&b| b == 0xFF) {
        return Line::default();
    }
    let dash = match d.get(1) {
        Some(1) => Some("sysDot"),
        Some(2) => Some("dash"),
        Some(3) => Some("lgDash"),
        Some(4) => Some("dashDot"),
        _ => None,
    };
    let width = WIDTHS[usize::from(d.get(3).copied().unwrap_or(0)).min(WIDTHS.len() - 1)];
    Line {
        fill: Fill::Solid(Color::rgb(color_at(d, 4, scheme).unwrap_or(0))),
        width: (width * 12_700.0).round() as Emu,
        dash,
        ..Line::default()
    }
}

/// A shape's fill: byte 12 (0xFF for none), byte 13 (the kind), the
/// colours at 20 and 24.
fn fill_of(d: &[u8], scheme: &[Rgb; 8]) -> Fill {
    if d.get(12).is_none_or(|&b| b == 0xFF) {
        return Fill::None;
    }
    let fg = color_at(d, 20, scheme).unwrap_or(0xCBCBCB);
    let bg = color_at(d, 24, scheme).unwrap_or(0xFFFFFF);
    match d.get(13) {
        Some(1) => Fill::Solid(Color::rgb(fg)),
        Some(2) => Fill::Solid(Color::rgb(scheme[0])),
        Some(3) => Fill::Solid(Color {
            rgb: fg,
            alpha: Some(50_000),
        }),
        Some(4 | 6) => Fill::Pattern {
            preset: "pct50",
            fg: Color::rgb(fg),
            bg: Color::rgb(bg),
        },
        Some(5) => Fill::Gradient(Gradient {
            stops: vec![(0, Color::rgb(fg)), (100_000, Color::rgb(bg))],
            kind: GradientKind::Linear(if d.get(16) == Some(&1) { 0.0 } else { 90.0 }),
        }),
        // A picture: not read.
        _ => Fill::None,
    }
}
