//! Shapes, fills, lines and geometry as PresentationML and DrawingML.

use super::text::write_text_body;
use super::xml::{esc, hex};
use crate::formats::office::slides::model::*;
use std::fmt::Write as _;

pub const REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

/// A part's relationships: (type, target, external), deduplicated.
#[derive(Default)]
pub struct Rels(pub Vec<(&'static str, String, bool)>);

impl Rels {
    pub fn add(&mut self, kind: &'static str, target: String, external: bool) -> String {
        if let Some(i) = self
            .0
            .iter()
            .position(|r| r.0 == kind && r.1 == target && r.2 == external)
        {
            return format!("rId{}", i + 1);
        }
        self.0.push((kind, target, external));
        format!("rId{}", self.0.len())
    }

    pub fn xml(&self) -> String {
        let mut r = format!(
            "{}<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">",
            super::xml::XML_HEAD
        );
        for (i, (kind, target, ext)) in self.0.iter().enumerate() {
            // A full type, or one of the office document's.
            let ty = if kind.starts_with("http") {
                kind.to_string()
            } else {
                format!("{REL}/{kind}")
            };
            let _ = write!(
                r,
                "<Relationship Id=\"rId{}\" Type=\"{ty}\" Target=\"{}\"",
                i + 1,
                esc(target)
            );
            if *ext {
                r.push_str(" TargetMode=\"External\"");
            }
            r.push_str("/>");
        }
        r.push_str("</Relationships>");
        r
    }
}

/// What a part's shapes refer to.
pub struct Ctx<'a> {
    pub rels: Rels,
    pub next_id: u32,
    /// Each picture's name in ppt/media.
    pub media: &'a [String],
    /// Each picture's tile scale, 100000 being 100%: its size at its own
    /// resolution over its size at 96 dpi, which a renderer takes.
    pub scales: &'a [(u32, u32)],
    /// Each slide's part name, in ppt/slides.
    pub slides: &'a [String],
    /// The pictures this part uses.
    pub used: Vec<usize>,
    /// The number of the last chart part, and the charts this part adds.
    pub chart_no: usize,
    pub charts: Vec<(usize, String)>,
    /// The most bytes of XML the part may reach, and whether it did: the
    /// shapes after that are not written.
    pub limit: usize,
    pub over: bool,
}

impl<'a> Ctx<'a> {
    pub fn new(
        media: &'a [String],
        scales: &'a [(u32, u32)],
        slides: &'a [String],
        chart_no: usize,
    ) -> Ctx<'a> {
        Ctx {
            rels: Rels::default(),
            next_id: 2,
            media,
            scales,
            slides,
            used: vec![],
            chart_no,
            charts: vec![],
            limit: usize::MAX,
            over: false,
        }
    }

    pub fn image(&mut self, media: usize) -> Option<String> {
        let name = self.media.get(media)?;
        if !self.used.contains(&media) {
            self.used.push(media);
        }
        Some(self.rels.add("image", format!("../media/{name}"), false))
    }

    fn id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// The attributes and relationship of a hyperlink: ` r:id=".." action=".."`.
    pub fn link_attrs(&mut self, link: &Link) -> Option<String> {
        let jump = |j: &str| format!(" r:id=\"\" action=\"ppaction://hlinkshowjump?jump={j}\"");
        Some(match link {
            Link::Url(u) => {
                let id = self.rels.add("hyperlink", u.clone(), true);
                format!(" r:id=\"{id}\"")
            }
            Link::Slide(i) => {
                let name = self.slides.get(*i)?;
                let id = self.rels.add("slide", name.clone(), false);
                format!(" r:id=\"{id}\" action=\"ppaction://hlinksldjump\"")
            }
            Link::NextSlide => jump("nextslide"),
            Link::PrevSlide => jump("previousslide"),
            Link::FirstSlide => jump("firstslide"),
            Link::LastSlide => jump("lastslide"),
        })
    }
}

fn emu(v: Emu) -> Emu {
    v.clamp(-27_273_042_316_900, 27_273_042_316_900)
}

fn size(v: Emu) -> Emu {
    v.clamp(0, 27_273_042_316_900)
}

/// Degrees to 1/60000 degree in [0, 360).
pub fn angle(deg: f64) -> i64 {
    if !deg.is_finite() {
        return 0;
    }
    ((deg.rem_euclid(360.0)) * 60000.0).round() as i64 % 21_600_000
}

pub fn color(o: &mut String, c: &Color) {
    match c.alpha {
        Some(a) if a < 100_000 => {
            let _ = write!(
                o,
                "<a:srgbClr val=\"{}\"><a:alpha val=\"{}\"/></a:srgbClr>",
                hex(c.rgb),
                a
            );
        }
        _ => {
            let _ = write!(o, "<a:srgbClr val=\"{}\"/>", hex(c.rgb));
        }
    }
}

pub fn solid(o: &mut String, c: &Color) {
    o.push_str("<a:solidFill>");
    color(o, c);
    o.push_str("</a:solidFill>");
}

pub fn fill(o: &mut String, f: &Fill, ctx: &mut Ctx) {
    match f {
        Fill::None => o.push_str("<a:noFill/>"),
        Fill::Solid(c) => solid(o, c),
        Fill::Gradient(g) => gradient(o, g),
        Fill::Picture { media, tile } => match ctx.image(*media) {
            Some(id) => {
                let _ = write!(
                    o,
                    "<a:blipFill rotWithShape=\"1\"><a:blip r:embed=\"{id}\"/>"
                );
                if *tile {
                    let (sx, sy) = ctx
                        .scales
                        .get(*media)
                        .copied()
                        .unwrap_or((100_000, 100_000));
                    let _ = write!(
                        o,
                        "<a:tile tx=\"0\" ty=\"0\" sx=\"{sx}\" sy=\"{sy}\" flip=\"none\" algn=\"tl\"/>"
                    );
                } else {
                    o.push_str("<a:stretch><a:fillRect/></a:stretch>");
                }
                o.push_str("</a:blipFill>");
            }
            None => o.push_str("<a:noFill/>"),
        },
        Fill::Pattern { preset, fg, bg } => {
            let _ = write!(o, "<a:pattFill prst=\"{preset}\"><a:fgClr>");
            color(o, fg);
            o.push_str("</a:fgClr><a:bgClr>");
            color(o, bg);
            o.push_str("</a:bgClr></a:pattFill>");
        }
    }
}

fn gradient(o: &mut String, g: &Gradient) {
    o.push_str("<a:gradFill rotWithShape=\"1\"><a:gsLst>");
    let mut stops = g.stops.clone();
    if stops.is_empty() {
        stops.push((0, Color::rgb(0xFFFFFF)));
    }
    if stops.len() == 1 {
        stops.push((100_000, stops[0].1));
    }
    for (pos, c) in &stops {
        let _ = write!(o, "<a:gs pos=\"{}\">", (*pos).min(100_000));
        color(o, c);
        o.push_str("</a:gs>");
    }
    o.push_str("</a:gsLst>");
    match &g.kind {
        GradientKind::Linear(a) => {
            let _ = write!(o, "<a:lin ang=\"{}\" scaled=\"0\"/>", angle(*a));
        }
        GradientKind::Path(path, r) => {
            let _ = write!(
                o,
                "<a:path path=\"{path}\"><a:fillToRect l=\"{}\" t=\"{}\" r=\"{}\" b=\"{}\"/></a:path>",
                r[0], r[1], r[2], r[3]
            );
        }
    }
    o.push_str("</a:gradFill>");
}

pub fn line(o: &mut String, l: &Line, ctx: &mut Ctx) {
    line_as(o, "a:ln", l, ctx)
}

/// A line under `tag`: `a:ln`, or a table cell's `a:lnL`...
fn line_as(o: &mut String, tag: &str, l: &Line, ctx: &mut Ctx) {
    if l.fill == Fill::None {
        let _ = write!(o, "<{tag}><a:noFill/></{tag}>");
        return;
    }
    let _ = write!(o, "<{tag} w=\"{}\"", size(l.width).min(20_116_800));
    if let Some(c) = l.cap {
        let _ = write!(o, " cap=\"{c}\"");
    }
    if let Some(c) = l.compound {
        let _ = write!(o, " cmpd=\"{c}\"");
    }
    o.push('>');
    fill(o, &l.fill, ctx);
    if let Some(d) = l.dash {
        let _ = write!(o, "<a:prstDash val=\"{d}\"/>");
    }
    match l.join {
        Some("round") => o.push_str("<a:round/>"),
        Some("bevel") => o.push_str("<a:bevel/>"),
        Some("miter") => o.push_str("<a:miter lim=\"800000\"/>"),
        _ => {}
    }
    for (tag, a) in [("headEnd", &l.head), ("tailEnd", &l.tail)] {
        if let Some(a) = a {
            let _ = write!(
                o,
                "<a:{tag} type=\"{}\" w=\"{}\" len=\"{}\"/>",
                a.kind, a.w, a.len
            );
        }
    }
    let _ = write!(o, "</{tag}>");
}

pub fn shadow(o: &mut String, s: &Option<Shadow>) {
    match s {
        Some(s) => {
            let _ = write!(
                o,
                "<a:effectLst><a:outerShdw blurRad=\"{}\" dist=\"{}\" dir=\"{}\" algn=\"ctr\" rotWithShape=\"0\">",
                size(s.blur).min(20_116_800),
                size(s.dist).min(20_116_800),
                angle(s.dir)
            );
            color(o, &s.color);
            o.push_str("</a:outerShdw></a:effectLst>");
        }
        None => o.push_str("<a:effectLst/>"),
    }
}

pub fn geometry(o: &mut String, g: &Geometry) {
    match g {
        Geometry::Preset { name, adj } => {
            let _ = write!(o, "<a:prstGeom prst=\"{name}\"><a:avLst>");
            for (n, v) in adj {
                let _ = write!(o, "<a:gd name=\"{n}\" fmla=\"val {v}\"/>");
            }
            o.push_str("</a:avLst></a:prstGeom>");
        }
        Geometry::Custom(paths) => {
            o.push_str("<a:custGeom><a:avLst/><a:gdLst/><a:ahLst/><a:cxnLst/><a:rect l=\"0\" t=\"0\" r=\"r\" b=\"b\"/><a:pathLst>");
            for p in paths {
                let _ = write!(o, "<a:path w=\"{}\" h=\"{}\"", p.w.max(0), p.h.max(0));
                if !p.fill {
                    o.push_str(" fill=\"none\"");
                }
                if !p.stroke {
                    o.push_str(" stroke=\"0\"");
                }
                o.push('>');
                let pt = |o: &mut String, x: i64, y: i64| {
                    let _ = write!(o, "<a:pt x=\"{x}\" y=\"{y}\"/>");
                };
                for c in &p.cmds {
                    match *c {
                        PathCmd::Move(x, y) => {
                            o.push_str("<a:moveTo>");
                            pt(o, x, y);
                            o.push_str("</a:moveTo>");
                        }
                        PathCmd::Line(x, y) => {
                            o.push_str("<a:lnTo>");
                            pt(o, x, y);
                            o.push_str("</a:lnTo>");
                        }
                        PathCmd::Cubic(a, b, c, d, e, f) => {
                            o.push_str("<a:cubicBezTo>");
                            pt(o, a, b);
                            pt(o, c, d);
                            pt(o, e, f);
                            o.push_str("</a:cubicBezTo>");
                        }
                        PathCmd::Quad(a, b, c, d) => {
                            o.push_str("<a:quadBezTo>");
                            pt(o, a, b);
                            pt(o, c, d);
                            o.push_str("</a:quadBezTo>");
                        }
                        PathCmd::Close => o.push_str("<a:close/>"),
                    }
                }
                o.push_str("</a:path>");
            }
            o.push_str("</a:pathLst></a:custGeom>");
        }
    }
}

fn xfrm(o: &mut String, tag: &str, x: &Xfrm, child: Option<&Xfrm>) {
    let _ = write!(o, "<{tag}");
    let rot = angle(x.rot);
    if rot != 0 {
        let _ = write!(o, " rot=\"{rot}\"");
    }
    if x.flip_h {
        o.push_str(" flipH=\"1\"");
    }
    if x.flip_v {
        o.push_str(" flipV=\"1\"");
    }
    let _ = write!(
        o,
        "><a:off x=\"{}\" y=\"{}\"/><a:ext cx=\"{}\" cy=\"{}\"/>",
        emu(x.x),
        emu(x.y),
        size(x.w),
        size(x.h)
    );
    if let Some(c) = child {
        let _ = write!(
            o,
            "<a:chOff x=\"{}\" y=\"{}\"/><a:chExt cx=\"{}\" cy=\"{}\"/>",
            emu(c.x),
            emu(c.y),
            size(c.w),
            size(c.h)
        );
    }
    let _ = write!(o, "</{tag}>");
}

/// `<p:cNvPr .../>` with the shape's id, name, description and link.
fn cnvpr(o: &mut String, s: &Shape, ctx: &mut Ctx, default: &str) {
    let id = ctx.id();
    let name = if s.name.is_empty() {
        format!("{default} {}", id - 1)
    } else {
        s.name.clone()
    };
    let _ = write!(o, "<p:cNvPr id=\"{id}\" name=\"{}\"", esc(&name));
    if !s.descr.is_empty() {
        let _ = write!(o, " descr=\"{}\"", esc(&s.descr));
    }
    if s.hidden {
        o.push_str(" hidden=\"1\"");
    }
    let link = s.link.as_ref().and_then(|l| ctx.link_attrs(l));
    match link {
        Some(attrs) => {
            let _ = write!(o, "><a:hlinkClick{attrs}/></p:cNvPr>");
        }
        None => o.push_str("/>"),
    }
}

fn nvpr(o: &mut String, s: &Shape) {
    match &s.placeholder {
        Some(ph) => {
            o.push_str("<p:nvPr><p:ph");
            if ph.kind != "obj" {
                let _ = write!(o, " type=\"{}\"", ph.kind);
            }
            if let Some(i) = ph.idx {
                let _ = write!(o, " idx=\"{i}\"");
            }
            o.push_str("/></p:nvPr>");
        }
        None => o.push_str("<p:nvPr/>"),
    }
}

/// The shapes of a tree, in order.
pub fn shapes(o: &mut String, list: &[Shape], ctx: &mut Ctx) {
    for s in list {
        if o.len() > ctx.limit {
            ctx.over = true;
            return;
        }
        shape(o, s, ctx);
    }
}

pub fn shape(o: &mut String, s: &Shape, ctx: &mut Ctx) {
    if let ShapeKind::Sp(sp) = &s.kind {
        // Paths that are only filled or only stroked: PowerPoint honours
        // each path's flags, the renderers this is written for do not, so
        // one shape is written for each kind of path.
        if let Geometry::Custom(paths) = &sp.geom {
            let kind = |p: &Path| (p.fill, p.stroke);
            let mixed = paths.iter().any(|p| kind(p) != kind(&paths[0]));
            if mixed && !sp.connector {
                let mut kinds: Vec<(bool, bool)> = vec![];
                for p in paths {
                    if !kinds.contains(&kind(p)) {
                        kinds.push(kind(p));
                    }
                }
                for (i, &(f, st)) in kinds.iter().enumerate() {
                    let mut part = s.clone();
                    if i > 0 {
                        part.placeholder = None;
                    }
                    if let ShapeKind::Sp(sub) = &mut part.kind {
                        sub.geom = Geometry::Custom(
                            paths
                                .iter()
                                .filter(|p| kind(p) == (f, st))
                                .cloned()
                                .map(|mut p| {
                                    p.fill = true;
                                    p.stroke = true;
                                    p
                                })
                                .collect(),
                        );
                        if !f {
                            sub.fill = Fill::None;
                        }
                        if !st {
                            sub.line = Line::default();
                        }
                        if i > 0 {
                            sub.text = None;
                            sub.shadow = None;
                        }
                    }
                    shape(o, &part, ctx);
                }
                return;
            }
        }
    }
    match &s.kind {
        ShapeKind::Sp(sp) if sp.connector => {
            o.push_str("<p:cxnSp><p:nvCxnSpPr>");
            cnvpr(o, s, ctx, "Connector");
            o.push_str("<p:cNvCxnSpPr/>");
            nvpr(o, s);
            o.push_str("</p:nvCxnSpPr><p:spPr>");
            xfrm(o, "a:xfrm", &s.xfrm, None);
            geometry(o, &sp.geom);
            fill(o, &sp.fill, ctx);
            line(o, &sp.line, ctx);
            shadow(o, &sp.shadow);
            o.push_str("</p:spPr></p:cxnSp>");
        }
        ShapeKind::Sp(sp) => {
            o.push_str("<p:sp><p:nvSpPr>");
            cnvpr(o, s, ctx, "Shape");
            if sp.text.is_some()
                && s.placeholder.is_none()
                && sp.fill == Fill::None
                && sp.line.fill == Fill::None
            {
                o.push_str("<p:cNvSpPr txBox=\"1\"/>");
            } else {
                o.push_str("<p:cNvSpPr/>");
            }
            nvpr(o, s);
            o.push_str("</p:nvSpPr><p:spPr>");
            xfrm(o, "a:xfrm", &s.xfrm, None);
            geometry(o, &sp.geom);
            fill(o, &sp.fill, ctx);
            line(o, &sp.line, ctx);
            shadow(o, &sp.shadow);
            o.push_str("</p:spPr>");
            match &sp.text {
                // The text area is the insets: a renderer need not honour
                // a custom geometry's own text rectangle.
                Some(t) if let Some(a) = sp.text_rect => {
                    let mut t = t.clone();
                    let (w, h) = (s.xfrm.w.max(0) as f64, s.xfrm.h.max(0) as f64);
                    let [l, tp, r, b] = &mut t.body.insets;
                    *l += (a[0] * w).round() as Emu;
                    *tp += (a[1] * h).round() as Emu;
                    *r += ((1.0 - a[2]) * w).round() as Emu;
                    *b += ((1.0 - a[3]) * h).round() as Emu;
                    write_text_body(o, "p:txBody", &t, ctx)
                }
                Some(t) => write_text_body(o, "p:txBody", t, ctx),
                None if s.placeholder.is_some() => {
                    write_text_body(o, "p:txBody", &TextBody::default(), ctx)
                }
                None => {}
            }
            o.push_str("</p:sp>");
        }
        ShapeKind::Pic(p) => {
            let Some(rid) = ctx.image(p.media) else {
                return;
            };
            o.push_str("<p:pic><p:nvPicPr>");
            cnvpr(o, s, ctx, "Picture");
            o.push_str("<p:cNvPicPr><a:picLocks noChangeAspect=\"1\"/></p:cNvPicPr>");
            nvpr(o, s);
            let _ = write!(o, "</p:nvPicPr><p:blipFill><a:blip r:embed=\"{rid}\"");
            match p.alpha {
                Some(a) if a < 100_000 => {
                    let _ = write!(o, "><a:alphaModFix amt=\"{a}\"/></a:blip>");
                }
                _ => o.push_str("/>"),
            }
            if p.crop.iter().any(|&c| c != 0) {
                let _ = write!(
                    o,
                    "<a:srcRect l=\"{}\" t=\"{}\" r=\"{}\" b=\"{}\"/>",
                    p.crop[0], p.crop[1], p.crop[2], p.crop[3]
                );
            }
            o.push_str("<a:stretch><a:fillRect/></a:stretch></p:blipFill><p:spPr>");
            xfrm(o, "a:xfrm", &s.xfrm, None);
            geometry(o, &p.geom);
            o.push_str("<a:noFill/>");
            line(o, &p.line, ctx);
            shadow(o, &p.shadow);
            o.push_str("</p:spPr></p:pic>");
        }
        ShapeKind::Group(g) => {
            o.push_str("<p:grpSp><p:nvGrpSpPr>");
            cnvpr(o, s, ctx, "Group");
            o.push_str("<p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr>");
            xfrm(o, "a:xfrm", &s.xfrm, Some(&g.child));
            o.push_str("</p:grpSpPr>");
            shapes(o, &g.shapes, ctx);
            o.push_str("</p:grpSp>");
        }
        ShapeKind::Table(t) => table(o, s, t, ctx),
        ShapeKind::Chart(xml) => {
            ctx.chart_no += 1;
            let n = ctx.chart_no;
            ctx.charts.push((n, xml.clone()));
            let rid = ctx
                .rels
                .add("chart", format!("../charts/chart{n}.xml"), false);
            o.push_str("<p:graphicFrame><p:nvGraphicFramePr>");
            cnvpr(o, s, ctx, "Chart");
            o.push_str("<p:cNvGraphicFramePr/>");
            nvpr(o, s);
            o.push_str("</p:nvGraphicFramePr>");
            xfrm(o, "p:xfrm", &s.xfrm, None);
            let _ = write!(
                o,
                "<a:graphic><a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/chart\"><c:chart xmlns:c=\"http://schemas.openxmlformats.org/drawingml/2006/chart\" r:id=\"{rid}\"/></a:graphicData></a:graphic></p:graphicFrame>"
            );
        }
    }
}

/// Charts in a shape list, groups included.
pub fn count_charts(list: &[Shape]) -> usize {
    list.iter()
        .map(|s| match &s.kind {
            ShapeKind::Chart(_) => 1,
            ShapeKind::Group(g) => count_charts(&g.shapes),
            _ => 0,
        })
        .sum()
}

fn table(o: &mut String, s: &Shape, t: &Table, ctx: &mut Ctx) {
    if t.cols.is_empty() || t.rows.is_empty() {
        return;
    }
    o.push_str("<p:graphicFrame><p:nvGraphicFramePr>");
    cnvpr(o, s, ctx, "Table");
    o.push_str("<p:cNvGraphicFramePr><a:graphicFrameLocks noGrp=\"1\"/></p:cNvGraphicFramePr>");
    nvpr(o, s);
    o.push_str("</p:nvGraphicFramePr>");
    xfrm(o, "p:xfrm", &s.xfrm, None);
    o.push_str("<a:graphic><a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/table\"><a:tbl><a:tblPr/><a:tblGrid>");
    for w in &t.cols {
        let _ = write!(o, "<a:gridCol w=\"{}\"/>", size(*w));
    }
    o.push_str("</a:tblGrid>");
    let ncols = t.cols.len();
    for row in &t.rows {
        let _ = write!(o, "<a:tr h=\"{}\">", size(row.h));
        for k in 0..ncols {
            let empty = Cell::default();
            let c = row.cells.get(k).unwrap_or(&empty);
            o.push_str("<a:tc");
            if c.grid_span > 1 {
                let _ = write!(o, " gridSpan=\"{}\"", c.grid_span);
            }
            if c.row_span > 1 {
                let _ = write!(o, " rowSpan=\"{}\"", c.row_span);
            }
            if c.h_merge {
                o.push_str(" hMerge=\"1\"");
            }
            if c.v_merge {
                o.push_str(" vMerge=\"1\"");
            }
            o.push('>');
            write_text_body(o, "a:txBody", &c.text, ctx);
            let b = &c.text.body;
            let _ = write!(
                o,
                "<a:tcPr marL=\"{}\" marR=\"{}\" marT=\"{}\" marB=\"{}\" anchor=\"{}\">",
                size(b.insets[0]),
                size(b.insets[2]),
                size(b.insets[1]),
                size(b.insets[3]),
                b.anchor
            );
            for (tag, l) in ["a:lnL", "a:lnR", "a:lnT", "a:lnB"].iter().zip(&c.borders) {
                line_as(o, tag, l, ctx);
            }
            fill(o, &c.fill, ctx);
            o.push_str("</a:tcPr></a:tc>");
        }
        o.push_str("</a:tr>");
    }
    o.push_str("</a:tbl></a:graphicData></a:graphic></p:graphicFrame>");
}

/// `<p:bg>` for a background fill.
pub fn background(o: &mut String, f: &Option<Fill>, ctx: &mut Ctx) {
    if let Some(f) = f {
        o.push_str("<p:bg><p:bgPr>");
        fill(o, f, ctx);
        o.push_str("<a:effectLst/></p:bgPr></p:bg>");
    }
}

/// The group properties every shape tree starts with.
pub const TREE_HEAD: &str = "<p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"0\" cy=\"0\"/><a:chOff x=\"0\" y=\"0\"/><a:chExt cx=\"0\" cy=\"0\"/></a:xfrm></p:grpSpPr>";

pub fn tree(o: &mut String, list: &[Shape], ctx: &mut Ctx) {
    o.push_str("<p:spTree>");
    o.push_str(TREE_HEAD);
    shapes(o, list, ctx);
    o.push_str("</p:spTree>");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn angles_wrap_into_a_turn() {
        assert_eq!(angle(90.0), 5_400_000);
        assert_eq!(angle(-90.0), 16_200_000);
        assert_eq!(angle(360.0), 0);
        assert_eq!(angle(f64::NAN), 0);
    }

    #[test]
    fn relationships_are_shared() {
        let mut r = Rels::default();
        let a = r.add("image", "../media/image1.png".into(), false);
        let b = r.add("image", "../media/image1.png".into(), false);
        let c = r.add("hyperlink", "https://example.org/".into(), true);
        assert_eq!(
            (a.as_str(), b.as_str(), c.as_str()),
            ("rId1", "rId1", "rId2")
        );
        assert!(r.xml().contains("TargetMode=\"External\""));
    }
}
