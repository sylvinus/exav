//! Keynote 2 to 5 (2003 to 2012) documents: one XML file, `index.apxl`
//! (gzipped in some packages), in Apple's "key", "sf" and "sfa" namespaces,
//! with the pictures beside it. No description of this format was
//! published (Apple published only the Keynote 1 schema, see `apxl1`); what
//! is read here was learnt from sample documents.
//!
//! What the samples show:
//! - `key:size` is the slide size in points. `key:slide-list` holds the
//!   `key:slide` elements in order, each naming its master (`key:master-ref`)
//!   and slide style (`key:style-ref`, whose `sf:fill` is the background).
//! - A slide's `key:page` has `sf:layers`: a background layer, a proxy of
//!   the master's layer (the master's `BGMasterSlideLayer`, whose drawables
//!   show on every slide; its prototype layer does not), and a foreground
//!   layer. A layer's `sf:drawables` holds the objects, inline or as `-ref`
//!   elements naming an object by `sfa:ID`.
//! - Styles live in a `key:stylesheet` of the theme, of each master and of
//!   each slide, each naming its parent (`sf:parent-ref`). A style names its
//!   parent by `sf:parent-ident`, looked up in the stylesheet it is in and
//!   then in its parents, never as itself. Its `sf:property-map` sets a
//!   property when the element has content; `sf:null` sets it to nothing.
//! - A placeholder's position and size are those of its placeholder style
//!   (`sf:geometry` property); its own `sf:geometry` is a stub.
//! - Text is `sf:text-storage` / `sf:text-body` / `sf:p` (`sf:style`, and
//!   `sf:list-level` from 1 for bullets), `sf:span` for character styles and
//!   `sf:br` at the end of a paragraph. Colours are `sfa:r`, `sfa:g`, `sfa:b`
//!   or `sfa:w` with `sfa:a`; font names are PostScript names.
//! - A list style's `listLabelTypes` has an entry per level from 0, the
//!   label indents and text indents likewise.
//! - Keynote 2 and 3 keep a slide's text in `key:bullets`, a `key:headline`
//!   for each paragraph (`key:depth`, 0 for the title) when the
//!   placeholders have none.

use super::text::ps_font;
use crate::formats::office::common::xml::{Child, Node};
use crate::formats::office::slides::error::{Error, Result};
use crate::formats::office::slides::limits::Budget;
use crate::formats::office::slides::model::*;
use crate::formats::office::slides::package::Zip;
use std::collections::HashMap;

const PT: f64 = 12700.0;
/// No stylesheet.
const NONE: usize = usize::MAX;
/// Hops up a chain of styles or stylesheets.
const MAX_CHAIN: usize = 32;

/// Where pictures are read from: the package's members, paths relative to
/// the directory holding the XML (`base`, empty or ending in "/"), else to
/// the package's root.
pub(crate) enum Pkg<'a> {
    None,
    Zip(Zip<'a>, String),
    Files(&'a [(&'a str, &'a [u8])], String),
}

impl Pkg<'_> {
    pub(super) fn get(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        let path = path.trim_start_matches("./");
        match self {
            Pkg::None => Ok(None),
            Pkg::Zip(z, base) => {
                if !base.is_empty()
                    && let Some(d) = z.read(&format!("{base}{path}"), 64 << 20)?
                {
                    return Ok(Some(d));
                }
                z.read(path, 64 << 20)
            }
            Pkg::Files(f, base) => {
                let find = |p: &str| f.iter().find(|x| x.0 == p).map(|x| x.1.to_vec());
                Ok(find(&format!("{base}{path}")).or_else(|| find(path)))
            }
        }
    }
}

struct Sheet<'a> {
    node: &'a Node,
    parent: Option<usize>,
    idents: HashMap<&'a str, &'a Node>,
}

/// A style and the stylesheet it is in.
#[derive(Clone, Copy)]
struct Sty<'a> {
    node: &'a Node,
    sheet: usize,
}

struct Reader<'a> {
    ids: HashMap<&'a str, (&'a Node, usize)>,
    sheets: Vec<Sheet<'a>>,
    sheet_ids: HashMap<&'a str, usize>,
    pkg: Pkg<'a>,
    /// Pictures by path: their media index.
    media: HashMap<String, Option<usize>>,
    /// A picture the package could not give within the limits, raised
    /// after the slide that wanted it.
    failed: Option<Error>,
    /// Bytes of pictures read and not yet charged to the budget.
    pending: u64,
    masters: HashMap<&'a str, usize>,
    p: Presentation,
}

pub(crate) fn read<'a>(root: &'a Node, pkg: Pkg<'a>, budget: &mut Budget) -> Result<Presentation> {
    if root.name != "key:presentation" {
        return Err(Error::NotFormat("not a Keynote document".into()));
    }
    let mut r = Reader {
        ids: HashMap::new(),
        sheets: vec![],
        sheet_ids: HashMap::new(),
        pkg,
        media: HashMap::new(),
        failed: None,
        pending: 0,
        masters: HashMap::new(),
        p: Presentation::default(),
    };
    r.index(root, NONE, 0);
    // Parents, once every stylesheet is known.
    for i in 0..r.sheets.len() {
        let parent = r.sheets[i]
            .node
            .child("sf:parent-ref")
            .and_then(|p| p.attr("sfa:IDREF"))
            .and_then(|id| r.sheet_ids.get(id))
            .copied()
            .filter(|&p| p != i);
        r.sheets[i].parent = parent;
    }
    r.convert(root, budget)?;
    Ok(r.p)
}

impl<'a> Reader<'a> {
    /// Records the identifiers and style names under `n`, in stylesheet
    /// `sheet`.
    fn index(&mut self, n: &'a Node, sheet: usize, depth: u32) {
        if depth > 250 {
            return;
        }
        let mut sheet = sheet;
        // The objects of a theme, a master or a slide use its stylesheet.
        let own = match n.name.as_str() {
            "key:stylesheet" => Some(n),
            "key:theme" | "key:master-slide" | "key:slide" => n.child("key:stylesheet"),
            _ => None,
        };
        if let Some(ss) = own {
            sheet = match ss.attr("sfa:ID").and_then(|id| self.sheet_ids.get(id)) {
                Some(&i) => i,
                None => {
                    let i = self.sheets.len();
                    self.sheets.push(Sheet {
                        node: ss,
                        parent: None,
                        idents: HashMap::new(),
                    });
                    if let Some(id) = ss.attr("sfa:ID") {
                        self.sheet_ids.insert(id, i);
                    }
                    i
                }
            };
        }
        if let Some(id) = n.attr("sfa:ID") {
            self.ids.entry(id).or_insert((n, sheet));
        }
        if sheet != NONE
            && let Some(ident) = n.attr("sf:ident")
        {
            self.sheets[sheet].idents.entry(ident).or_insert(n);
        }
        for c in n.nodes() {
            self.index(c, sheet, depth + 1);
        }
    }

    /// `n`, or what its `sfa:IDREF` names.
    fn deref(&self, n: &'a Node, sheet: usize) -> (&'a Node, usize) {
        match n.attr("sfa:IDREF").and_then(|r| self.ids.get(r)) {
            Some(&(t, s)) => (t, s),
            None => (n, sheet),
        }
    }

    fn by_ident(&self, ident: &str, sheet: usize, not: Option<&Node>) -> Option<Sty<'a>> {
        let mut cur = sheet;
        for _ in 0..MAX_CHAIN {
            if cur == NONE {
                return None;
            }
            let s = &self.sheets[cur];
            if let Some(&node) = s.idents.get(ident)
                && not.is_none_or(|x| !std::ptr::eq(x, node))
            {
                return Some(Sty { node, sheet: cur });
            }
            cur = s.parent.unwrap_or(NONE);
        }
        None
    }

    /// A style by identifier or by name, as a reference in `sheet` gives it.
    fn style(&self, name: &str, sheet: usize) -> Option<Sty<'a>> {
        if let Some(&(node, s)) = self.ids.get(name) {
            return Some(Sty { node, sheet: s });
        }
        self.by_ident(name, sheet, None)
    }

    fn parent(&self, s: Sty<'a>) -> Option<Sty<'a>> {
        self.by_ident(s.node.attr("sf:parent-ident")?, s.sheet, Some(s.node))
    }

    /// The value of property `name` in `style` or its nearest parent that
    /// sets it, and the stylesheet it is in. `sf:null` is no value.
    fn prop(&self, style: Option<Sty<'a>>, name: &str) -> Option<(&'a Node, usize)> {
        let mut cur = style;
        for _ in 0..MAX_CHAIN {
            let s = cur?;
            if let Some(p) = s.node.child("sf:property-map").and_then(|m| m.child(name))
                && let Some(v) = p.nodes().next()
            {
                if v.name == "sf:null" {
                    return None;
                }
                return Some(self.deref(v, s.sheet));
            }
            cur = self.parent(s);
        }
        None
    }

    fn prop_num(&self, style: Option<Sty<'a>>, name: &str) -> Option<f64> {
        self.prop(style, name).and_then(|(v, _)| num(v))
    }

    fn prop_style(&self, style: Option<Sty<'a>>, name: &str) -> Option<Sty<'a>> {
        self.prop(style, name)
            .map(|(node, sheet)| Sty { node, sheet })
    }

    /// A style referenced by an element's `sfa:IDREF`, as a child of `n`.
    fn style_child(&self, n: &'a Node, name: &str, sheet: usize) -> Option<Sty<'a>> {
        let c = n.child(name)?.nodes().next()?;
        let (node, sheet) = self.deref(c, sheet);
        Some(Sty { node, sheet })
    }

    fn convert(&mut self, root: &'a Node, budget: &mut Budget) -> Result<()> {
        let size = root
            .child("key:size")
            .or_else(|| root.child("key:theme-list")?.find("key:size"));
        let (w, h) = size.map_or((1024.0, 768.0), |s| {
            (
                attr_f(s, "sfa:w").unwrap_or(1024.0),
                attr_f(s, "sfa:h").unwrap_or(768.0),
            )
        });
        self.p.width = (w.clamp(16.0, 20_000.0) * PT).round() as Emu;
        self.p.height = (h.clamp(16.0, 20_000.0) * PT).round() as Emu;
        let Some(list) = root.child("key:slide-list") else {
            return Err(Error::NotFormat("no slides".into()));
        };
        let mut n = 0usize;
        for s in list.all("key:slide") {
            budget.slide(n)?;
            n += 1;
            self.p.total_slides = n;
            if !budget.wants(n - 1) {
                continue;
            }
            let slide = self.slide(s, budget)?;
            self.p.slides.push(slide);
            if let Some(e) = self.failed.take() {
                return Err(e);
            }
        }
        if self.p.masters.is_empty() {
            self.p.masters.push(Master::default());
        }
        Ok(())
    }

    /// A slide or master's background from its slide style.
    fn background(&mut self, style: Option<Sty<'a>>) -> Option<Fill> {
        let (v, sheet) = self.prop(style, "sf:fill")?;
        Some(self.fill(v, sheet))
    }

    fn master(&mut self, m: &'a Node, budget: &mut Budget) -> Result<usize> {
        let key = m.attr("sfa:ID").unwrap_or("");
        if let Some(&i) = self.masters.get(key) {
            return Ok(i);
        }
        let sheet = m
            .child("key:stylesheet")
            .and_then(|s| s.attr("sfa:ID"))
            .and_then(|id| self.sheet_ids.get(id))
            .copied()
            .unwrap_or(NONE);
        let style = self.style_ref(m, "key:style-ref", sheet);
        let mut out = Master {
            name: m.attr("key:name").unwrap_or("Master").to_string(),
            layouts: vec![Layout {
                name: "Blank".into(),
                kind: "blank",
                show_master_shapes: true,
                ..Layout::default()
            }],
            ..Master::default()
        };
        out.background = self
            .background(style)
            .or(Some(Fill::Solid(Color::rgb(0xFFFFFF))));
        if let Some(layers) = m.child("key:page").and_then(|p| p.child("sf:layers")) {
            for layer in layers.all("sf:layer") {
                // The prototype layer holds objects to copy, not to show.
                if layer_name(layer) == Some("BGMasterSlidePrototypeLayer") {
                    continue;
                }
                if let Some(d) = layer.child("sf:drawables") {
                    self.drawables(d, sheet, 0, &mut out.shapes, None, budget, 0)?;
                }
            }
        }
        let i = self.p.masters.len();
        self.p.masters.push(out);
        self.masters.insert(key, i);
        Ok(i)
    }

    fn slide(&mut self, s: &'a Node, budget: &mut Budget) -> Result<Slide> {
        let sheet = s
            .child("key:stylesheet")
            .and_then(|s| s.attr("sfa:ID"))
            .and_then(|id| self.sheet_ids.get(id))
            .copied()
            .unwrap_or(NONE);
        let mi = match s
            .child("key:master-ref")
            .map(|r| self.deref(r, sheet).0)
            .filter(|m| m.name == "key:master-slide")
        {
            Some(m) => self.master(m, budget)?,
            None => {
                if self.p.masters.is_empty() {
                    self.p.masters.push(Master::default());
                }
                0
            }
        };
        let style = self.style_ref(s, "key:style-ref", sheet);
        let background = self.background(style);
        let number = self.p.slides.len() + 1;
        let mut shapes = vec![];
        let headlines = Headlines::of(s);
        if let Some(layers) = s.child("key:page").and_then(|p| p.child("sf:layers")) {
            for layer in layers.all("sf:layer") {
                if let Some(d) = layer.child("sf:drawables") {
                    self.drawables(d, sheet, number, &mut shapes, Some(&headlines), budget, 0)?;
                }
            }
        }
        Ok(Slide {
            name: None,
            master: mi,
            layout: 0,
            background,
            shapes,
            hidden: false,
            show_master_shapes: true,
        })
    }

    /// The style a reference element child of `n` (`key:style-ref`) names.
    fn style_ref(&self, n: &'a Node, name: &str, sheet: usize) -> Option<Sty<'a>> {
        let c = n.child(name)?;
        c.attr("sfa:IDREF")?;
        let (node, sheet) = self.deref(c, sheet);
        Some(Sty { node, sheet })
    }

    /// The objects of a layer, in drawing order. `slide` is the text kept
    /// in the headlines of a slide's bullets; `None` in a master, where
    /// placeholders are not shown.
    #[allow(clippy::too_many_arguments)]
    fn drawables(
        &mut self,
        list: &'a Node,
        sheet: usize,
        number: usize,
        out: &mut Vec<Shape>,
        slide: Option<&Headlines<'a>>,
        budget: &mut Budget,
        depth: u32,
    ) -> Result<()> {
        if depth > 16 {
            return Ok(());
        }
        for c in list.nodes().take(10_000) {
            let (n, ns) = self.deref(c, sheet);
            let local = n.name.split_once(':').map_or(n.name.as_str(), |x| x.1);
            let shape = match local {
                "title-placeholder" | "body-placeholder" | "slide-number-placeholder" => {
                    match slide {
                        Some(h) => self.placeholder(n, local, ns, number, h, budget)?,
                        None => None,
                    }
                }
                "shape" | "line" | "connection-line" => {
                    budget.shape(0)?;
                    self.shape(n, ns, number, budget)?
                }
                "media" => {
                    budget.shape(0)?;
                    self.media_shape(n, ns)?
                }
                "group" => self.group(n, ns, number, slide, budget, depth)?,
                "tabular-info" | "table-info" => {
                    self.p.warn("tables");
                    None
                }
                "chart-info" | "chart" => {
                    self.p.warn("charts");
                    None
                }
                "movie-media" => {
                    self.p.warn("movies and sounds");
                    None
                }
                _ => None,
            };
            out.extend(shape);
            budget.alloc(std::mem::take(&mut self.pending))?;
        }
        Ok(())
    }

    fn group(
        &mut self,
        n: &'a Node,
        sheet: usize,
        number: usize,
        slide: Option<&Headlines<'a>>,
        budget: &mut Budget,
        depth: u32,
    ) -> Result<Option<Shape>> {
        let Some((xf, _, _)) = geometry(n.child("sf:geometry")) else {
            return Ok(None);
        };
        let mut kids = vec![];
        if let Some(d) = n.child("sf:drawables") {
            self.drawables(d, sheet, number, &mut kids, slide, budget, depth + 1)?;
        }
        if kids.is_empty() {
            return Ok(None);
        }
        let child = Xfrm {
            x: 0,
            y: 0,
            w: xf.w.max(1),
            h: xf.h.max(1),
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

    /// A title or body placeholder with its text.
    fn placeholder(
        &mut self,
        n: &'a Node,
        local: &str,
        sheet: usize,
        number: usize,
        headlines: &Headlines<'a>,
        budget: &mut Budget,
    ) -> Result<Option<Shape>> {
        let own = n.child("key:text").or_else(|| n.child("sf:text"));
        let frames: Vec<(&Node, u32)> = match (own, local) {
            (Some(f), _) => vec![(f, 0)],
            (None, "title-placeholder") => headlines.title.clone(),
            (None, "body-placeholder") => headlines.body.clone(),
            _ => vec![],
        };
        if frames.is_empty() {
            return Ok(None);
        }
        let style = self.style_child(n, "sf:style", sheet);
        // The placeholder's own geometry is a stub: its style gives the box.
        let geom = self
            .prop(style, "sf:geometry")
            .and_then(|(g, _)| geometry(g.child("sf:geometry").or(Some(g))))
            .or_else(|| geometry(n.child("sf:geometry")));
        let Some((xf, _, _)) = geom else {
            return Ok(None);
        };
        let Some(text) = self.text(&frames, style, sheet, number, budget)? else {
            return Ok(None);
        };
        budget.shape(0)?;
        let mut sp = self.sp_props(style);
        sp.text = Some(text);
        let mut s = Shape::new(ShapeKind::Sp(Box::new(sp)), xf);
        s.placeholder = match local {
            "title-placeholder" => Some(Placeholder {
                kind: "title",
                idx: None,
            }),
            "body-placeholder" => Some(Placeholder {
                kind: "body",
                idx: Some(1),
            }),
            _ => None,
        };
        Ok(Some(s))
    }

    /// Fill, line and shadow of a style.
    fn sp_props(&mut self, style: Option<Sty<'a>>) -> Sp {
        let opacity = self.prop_num(style, "sf:opacity");
        let fill = match self.prop(style, "sf:fill") {
            Some((v, sheet)) => match self.fill(v, sheet) {
                Fill::Solid(c) => Fill::Solid(with_opacity(c, opacity)),
                f => f,
            },
            None => Fill::None,
        };
        let line = self
            .prop(style, "sf:stroke")
            .and_then(|(s, _)| stroke(s, opacity))
            .unwrap_or_default();
        let shadow = self.prop(style, "sf:shadow").and_then(|(s, _)| shadow(s));
        Sp {
            fill,
            line,
            shadow,
            ..Sp::default()
        }
    }

    fn shape(
        &mut self,
        n: &'a Node,
        sheet: usize,
        number: usize,
        budget: &mut Budget,
    ) -> Result<Option<Shape>> {
        let Some((xf, w, h)) = geometry(n.child("sf:geometry")) else {
            return Ok(None);
        };
        let natural = n
            .child("sf:geometry")
            .and_then(|g| g.child("sf:naturalSize"))
            .map(|s| {
                (
                    attr_f(s, "sfa:w").unwrap_or(w),
                    attr_f(s, "sfa:h").unwrap_or(h),
                )
            })
            .filter(|s| s.0 > 0.0 && s.1 > 0.0)
            .unwrap_or((w.max(1.0), h.max(1.0)));
        let style = n
            .child("sf:style")
            .and_then(|s| s.nodes().next())
            .map(|c| self.deref(c, sheet))
            .map(|(node, sheet)| Sty { node, sheet });
        let mut sp = self.sp_props(style);
        sp.geom = n
            .child("sf:path")
            .and_then(|p| path_of(p, natural))
            .unwrap_or_default();
        if let Some(frame) = n.child("sf:text") {
            sp.text = self.text(&[(frame, 0)], style, sheet, number, budget)?;
        }
        Ok(Some(Shape::new(ShapeKind::Sp(Box::new(sp)), xf)))
    }

    /// A picture: the image frame, cropped to the crop frame.
    fn media_shape(&mut self, n: &'a Node, sheet: usize) -> Result<Option<Shape>> {
        // A placeholder for a picture the user did not add.
        if n.attr("sf:placeholder") == Some("true") {
            return Ok(None);
        }
        let Some((frame, ..)) = geometry(n.child("sf:geometry")) else {
            return Ok(None);
        };
        let Some(content) = n.child("sf:content") else {
            return Ok(None);
        };
        let Some(data) = content.nodes().find_map(|m| self.image_data(m)) else {
            if content.find("sf:movie-media").is_some() || content.find("sf:movie").is_some() {
                self.p.warn("videos and sounds, drawn as boxes");
                let sp = ShapeKind::media_placeholder(frame.w, frame.h, true);
                return Ok(Some(Shape::new(sp, frame)));
            }
            return Ok(None);
        };
        let Some(media) = self.image(&data) else {
            self.p.warn("pictures whose data is missing");
            return Ok(None);
        };
        let style = n
            .child("sf:style")
            .and_then(|s| s.nodes().next())
            .map(|c| self.deref(c, sheet))
            .map(|(node, sheet)| Sty { node, sheet });
        let opacity = self.prop_num(style, "sf:opacity");
        let line = self
            .prop(style, "sf:stroke")
            .and_then(|(s, _)| stroke(s, opacity))
            .unwrap_or_default();
        let shadow = self.prop(style, "sf:shadow").and_then(|(s, _)| shadow(s));
        // The visible window, in the same space as the image frame.
        let (xf, crop) = match geometry(n.child("sf:crop-geometry")) {
            Some((win, ..)) if frame.w > 0 && frame.h > 0 => {
                let f = |v: Emu, total: Emu| ((v as f64 / total as f64) * 100_000.0).round() as i32;
                let crop = [
                    f(win.x - frame.x, frame.w).clamp(0, 99_000),
                    f(win.y - frame.y, frame.h).clamp(0, 99_000),
                    f(frame.x + frame.w - (win.x + win.w), frame.w).clamp(0, 99_000),
                    f(frame.y + frame.h - (win.y + win.h), frame.h).clamp(0, 99_000),
                ];
                (win, crop)
            }
            _ => (frame, [0; 4]),
        };
        Ok(Some(Shape::new(
            ShapeKind::Pic(Box::new(Pic {
                media,
                crop,
                geom: Geometry::default(),
                line,
                shadow,
                alpha: opacity
                    .filter(|&o| o < 1.0)
                    .map(|o| (o.clamp(0.0, 1.0) * 100_000.0).round() as u32),
            })),
            xf,
        )))
    }

    /// The package paths of the picture `n` (a media content or a textured
    /// fill) holds: the filtered image if it has one, else the original.
    fn image_data(&self, n: &'a Node) -> Option<Vec<String>> {
        let fi = n.child("sf:filtered-image")?;
        let mut out = vec![];
        for part in ["sf:filtered", "sf:unfiltered"] {
            let Some(p) = fi.child(part) else { continue };
            let (p, _) = self.deref(p, NONE);
            if let Some(d) = p.child("sf:data") {
                let (d, _) = self.deref(d, NONE);
                out.extend(
                    ["sf:path", "sf:displayname"]
                        .iter()
                        .filter_map(|a| d.attr(a))
                        .map(str::to_string),
                );
            }
        }
        (!out.is_empty()).then_some(out)
    }

    /// A picture's media index, trying each path in turn. Its bytes are
    /// charged to the budget by the caller (`pending`).
    fn image(&mut self, paths: &[String]) -> Option<usize> {
        for path in paths {
            if let Some(&m) = self.media.get(path) {
                if m.is_some() {
                    return m;
                }
                continue;
            }
            let bytes = match self.pkg.get(path) {
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
            self.media.insert(path.clone(), m);
            if m.is_some() {
                return m;
            }
        }
        None
    }

    fn fill(&mut self, v: &'a Node, sheet: usize) -> Fill {
        let (v, _) = self.deref(v, sheet);
        match v.name.as_str() {
            "sf:color" => color(v).map_or(Fill::None, Fill::Solid),
            "sf:angle-gradient" | "sf:gradient" => gradient(v).unwrap_or(Fill::None),
            "sf:textured-fill" => {
                let tile = v.attr("sf:technique") == Some("tile");
                match self.image_data(v).and_then(|paths| self.image(&paths)) {
                    Some(media) => Fill::Picture { media, tile },
                    None => Fill::None,
                }
            }
            _ => Fill::None,
        }
    }
}

/// The text of a slide that keeps it in `key:bullets` (Keynote 2 and 3): a
/// `key:headline` for each paragraph, at its depth, 0 for the title.
#[derive(Default)]
struct Headlines<'a> {
    title: Vec<(&'a Node, u32)>,
    body: Vec<(&'a Node, u32)>,
}

impl<'a> Headlines<'a> {
    fn of(slide: &'a Node) -> Self {
        let mut h = Headlines::default();
        let Some(bullets) = slide.child("key:bullets") else {
            return h;
        };
        for headline in bullets.all("key:headline").take(1 << 16) {
            let Some(frame) = headline.child("key:text") else {
                continue;
            };
            let depth = headline
                .attr("key:depth")
                .and_then(|d| d.trim().parse::<u32>().ok())
                .unwrap_or(0);
            if depth == 0 {
                h.title.push((frame, 0));
            } else {
                h.body.push((frame, depth));
            }
        }
        h
    }
}

fn layer_name(layer: &Node) -> Option<&str> {
    layer
        .child("sf:type")?
        .child("sf:string")?
        .attr("sfa:string")
}

fn attr_f(n: &Node, a: &str) -> Option<f64> {
    n.attr(a)
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite())
}

/// The value of an `sf:number` or `sf:decimal-number`.
fn num(v: &Node) -> Option<f64> {
    attr_f(v, "sfa:number")
}

/// A frame (`sf:geometry`, `sf:crop-geometry`): the box in EMU, and its
/// width and height in points.
fn geometry(g: Option<&Node>) -> Option<(Xfrm, f64, f64)> {
    let g = g?;
    let size = g.child("sf:size")?;
    let pos = g.child("sf:position");
    let f = |n: Option<&Node>, a: &str| n.and_then(|n| attr_f(n, a)).unwrap_or(0.0);
    let (w, h) = (
        f(Some(size), "sfa:w").max(0.0),
        f(Some(size), "sfa:h").max(0.0),
    );
    let clamp = |v: f64| v.clamp(-1e6, 1e6);
    Some((
        Xfrm {
            x: (clamp(f(pos, "sfa:x")) * PT).round() as Emu,
            y: (clamp(f(pos, "sfa:y")) * PT).round() as Emu,
            w: (clamp(w) * PT).round() as Emu,
            h: (clamp(h) * PT).round() as Emu,
            ..Xfrm::default()
        },
        w,
        h,
    ))
}

fn channel(v: f64) -> u32 {
    (v.clamp(0.0, 1.0) * 255.0).round() as u32
}

/// An `sf:color`: RGB, grey or CMYK with alpha.
fn color(c: &Node) -> Option<Color> {
    let a = attr_f(c, "sfa:a").unwrap_or(1.0).clamp(0.0, 1.0);
    let f = |n: &str| attr_f(c, n);
    let rgb = if let Some(w) = f("sfa:w") {
        let g = channel(w);
        g << 16 | g << 8 | g
    } else if let Some(cy) = f("sfa:c") {
        let (m, y, k) = (
            f("sfa:m").unwrap_or(0.0),
            f("sfa:y").unwrap_or(0.0),
            f("sfa:k").unwrap_or(0.0),
        );
        let ch = |v: f64| channel((1.0 - v.clamp(0.0, 1.0)) * (1.0 - k.clamp(0.0, 1.0)));
        ch(cy) << 16 | ch(m) << 8 | ch(y)
    } else {
        channel(f("sfa:r").unwrap_or(0.0)) << 16
            | channel(f("sfa:g").unwrap_or(0.0)) << 8
            | channel(f("sfa:b").unwrap_or(0.0))
    };
    Some(Color {
        rgb,
        alpha: (a < 1.0).then(|| (a * 100_000.0).round() as u32),
    })
}

fn with_opacity(mut c: Color, o: Option<f64>) -> Color {
    if let Some(o) = o.filter(|&o| o < 1.0) {
        let a = f64::from(c.alpha.unwrap_or(100_000)) * o.clamp(0.0, 1.0);
        c.alpha = Some(a.round() as u32);
    }
    c
}

/// An `sf:angle-gradient`: stops with fractions and colours; the angle in
/// radians, counterclockwise.
fn gradient(g: &Node) -> Option<Fill> {
    let stops: Vec<(u32, Color)> = g
        .child("sf:stops")?
        .all("sf:gradient-stop")
        .take(64)
        .filter_map(|s| {
            let c = color(s.child("sf:color")?)?;
            let pos = attr_f(s, "sf:fraction").unwrap_or(0.0).clamp(0.0, 1.0);
            Some(((pos * 100_000.0).round() as u32, c))
        })
        .collect();
    if stops.is_empty() {
        return None;
    }
    let kind = if g.attr("sf:type") == Some("radial") {
        GradientKind::Path("circle", [50_000; 4])
    } else {
        let a = attr_f(g, "sf:angle").unwrap_or(0.0).to_degrees();
        GradientKind::Linear((-a).rem_euclid(360.0))
    };
    Some(Fill::Gradient(Gradient { stops, kind }))
}

/// An `sf:stroke`; `None` when it draws nothing.
fn stroke(s: &Node, opacity: Option<f64>) -> Option<Line> {
    let kind = s.child("sf:pattern").and_then(|p| p.attr("sf:type"));
    if matches!(kind, Some("none" | "empty")) {
        return None;
    }
    let width = attr_f(s, "sf:width").unwrap_or(1.0).clamp(0.0, 1000.0);
    let c = s.child("sf:color").and_then(color)?;
    Some(Line {
        fill: Fill::Solid(with_opacity(c, opacity)),
        width: (width * PT).round() as Emu,
        dash: kind.filter(|k| *k != "solid").map(|_| "dash"),
        cap: match s.attr("sf:cap") {
            Some("round") => Some("rnd"),
            Some("square") => Some("sq"),
            _ => None,
        },
        join: match s.attr("sf:join") {
            Some("round") => Some("round"),
            Some("bevel") => Some("bevel"),
            Some("miter") => Some("miter"),
            _ => None,
        },
        ..Line::default()
    })
}

/// An `sf:shadow`: angle in degrees clockwise, offset and radius in
/// points.
fn shadow(s: &Node) -> Option<Shadow> {
    if s.attr("sf:is-null") == Some("true") {
        return None;
    }
    let c = s.child("sf:color").and_then(color).unwrap_or(Color::rgb(0));
    let c = with_opacity(c, attr_f(s, "sf:opacity"));
    let offset = attr_f(s, "sf:offset").unwrap_or(0.0).abs();
    if offset == 0.0 && c.alpha == Some(0) {
        return None;
    }
    Some(Shadow {
        color: c,
        blur: (attr_f(s, "sf:radius").unwrap_or(0.0).clamp(0.0, 1000.0) * PT).round() as Emu,
        dist: (offset.min(1000.0) * PT).round() as Emu,
        dir: attr_f(s, "sf:angle").unwrap_or(0.0).rem_euclid(360.0),
    })
}

/// A shape's path: `sf:bezier` elements holding SVG-like commands in the
/// shape's natural size.
fn path_of(p: &Node, natural: (f64, f64)) -> Option<Geometry> {
    let b = p
        .child("sf:bezier-path")
        .and_then(|b| b.child("sf:bezier"))
        .or_else(|| p.child("sf:bezier"))?;
    path(b.attr("sfa:path")?, natural)
}

/// Commands `M x y`, `L x y`, `C x1 y1 x2 y2 x y`, `Z`.
fn path(d: &str, natural: (f64, f64)) -> Option<Geometry> {
    let s = 100.0;
    let mut out = Path {
        w: (natural.0 * s).round().max(1.0) as i64,
        h: (natural.1 * s).round().max(1.0) as i64,
        fill: true,
        stroke: true,
        cmds: vec![],
    };
    let toks: Vec<&str> = d.split_ascii_whitespace().take(1 << 16).collect();
    let mut i = 0;
    let mut started = false;
    let pts = |i: &mut usize, n: usize| -> Option<Vec<i64>> {
        let v: Vec<i64> = toks
            .get(*i + 1..*i + 1 + n)?
            .iter()
            .map(|t| t.parse::<f64>().ok().map(|v| (v * s).round() as i64))
            .collect::<Option<_>>()?;
        *i += 1 + n;
        Some(v)
    };
    while i < toks.len() {
        match toks[i] {
            "M" => {
                let v = pts(&mut i, 2)?;
                out.cmds.push(PathCmd::Move(v[0], v[1]));
                started = true;
            }
            "L" if started => {
                let v = pts(&mut i, 2)?;
                out.cmds.push(PathCmd::Line(v[0], v[1]));
            }
            "C" if started => {
                let v = pts(&mut i, 6)?;
                out.cmds
                    .push(PathCmd::Cubic(v[0], v[1], v[2], v[3], v[4], v[5]));
            }
            "Z" => {
                out.cmds.push(PathCmd::Close);
                i += 1;
            }
            _ => return None,
        }
    }
    // A trailing lone move draws nothing.
    if matches!(out.cmds.last(), Some(PathCmd::Move(..))) {
        out.cmds.pop();
    }
    (!out.cmds.is_empty()).then(|| Geometry::Custom(vec![out]))
}

// Text.

impl<'a> Reader<'a> {
    /// The text frames (`key:text`, `sf:text`) of a shape in `shape_style`,
    /// each with the list level its paragraphs are given when they name
    /// none, as a text body; `None` when they hold no text.
    fn text(
        &mut self,
        frames: &[(&'a Node, u32)],
        shape_style: Option<Sty<'a>>,
        sheet: usize,
        number: usize,
        budget: &mut Budget,
    ) -> Result<Option<TextBody>> {
        let mut paras = vec![];
        let mut layout = None;
        for &(frame, forced) in frames {
            let Some(storage) = frame.child("sf:text-storage") else {
                continue;
            };
            let sheet = storage
                .child("sf:stylesheet-ref")
                .and_then(|r| r.attr("sfa:IDREF"))
                .and_then(|id| self.sheet_ids.get(id))
                .copied()
                .unwrap_or(sheet);
            let Some(body) = storage.child("sf:text-body") else {
                continue;
            };
            let frame_layout = frame
                .attr("sf:layoutstyle")
                .and_then(|l| self.style(l, sheet))
                .or_else(|| self.prop_style(shape_style, "sf:layoutStyle"));
            layout = layout.or(frame_layout);
            let default_para = self
                .prop_style(frame_layout, "sf:layoutParagraphStyle")
                .or_else(|| self.prop_style(shape_style, "sf:layoutParagraphStyle"));
            let mut stack: Vec<&Node> = body.nodes().collect();
            stack.reverse();
            // Paragraphs may sit in `sf:layout` elements.
            while let Some(n) = stack.pop() {
                match n.name.as_str() {
                    "sf:p" => {
                        if paras.len() >= 1 << 16 {
                            break;
                        }
                        paras.push(self.paragraph(
                            n,
                            default_para,
                            forced,
                            sheet,
                            number,
                            budget,
                        )?);
                    }
                    "sf:layout" => {
                        let mut kids: Vec<&Node> = n.nodes().collect();
                        kids.reverse();
                        stack.extend(kids);
                    }
                    _ => {}
                }
            }
        }
        if paras.iter().all(|p| {
            p.runs
                .iter()
                .all(|r| matches!(&r.kind, RunKind::Text(t) if t.is_empty()))
        }) {
            return Ok(None);
        }
        let pad = self.prop(layout, "sf:padding").map(|(p, _)| p);
        let ins = |a: &str| {
            pad.and_then(|p| attr_f(p, a))
                .map(|v| (v.clamp(0.0, 1000.0) * PT).round() as Emu)
                .unwrap_or(0)
        };
        let valign = self.prop_num(layout, "sf:verticalAlignment").unwrap_or(0.0);
        let shrink = self
            .prop_num(layout, "sf:shrinkTextToFit")
            .is_some_and(|v| v != 0.0);
        let cols = self
            .prop(layout, "sf:columns")
            .and_then(|(c, _)| attr_f(c, "sf:count"))
            .map_or(1, |c| c.clamp(1.0, 16.0) as u32);
        Ok(Some(TextBody {
            body: BodyProps {
                insets: [
                    ins("sf:left"),
                    ins("sf:top"),
                    ins("sf:right"),
                    ins("sf:bottom"),
                ],
                anchor: match valign as i32 {
                    1 => "ctr",
                    2 => "b",
                    _ => "t",
                },
                autofit: if shrink {
                    Autofit::Normal(100_000, 0)
                } else {
                    Autofit::None
                },
                columns: cols,
                ..BodyProps::default()
            },
            paras,
            levels: ListStyle::default(),
        }))
    }

    /// A paragraph. A paragraph that names no list level takes `forced`.
    fn paragraph(
        &mut self,
        p: &'a Node,
        default_para: Option<Sty<'a>>,
        forced: u32,
        sheet: usize,
        number: usize,
        budget: &mut Budget,
    ) -> Result<Paragraph> {
        let pstyle = p
            .attr("sf:style")
            .and_then(|s| self.style(s, sheet))
            .or(default_para);
        let level = p
            .attr("sf:list-level")
            .and_then(|l| l.trim().parse::<u32>().ok())
            .unwrap_or(forced)
            .min(8);
        let base = self.run_props(pstyle, None);
        let props = self.para_props(pstyle, level, base.color);
        let mut runs: Vec<Run> = vec![];
        let last = p.nodes().count();
        let mut seen = 0;
        for c in &p.children {
            budget.alloc(64)?;
            let (kind, rp) = match c {
                Child::Text(t) => (RunKind::Text(self.cased(t, pstyle, None)), base.clone()),
                Child::Node(n) => {
                    seen += 1;
                    match n.name.as_str() {
                        "sf:span" | "sf:link" => {
                            let cstyle = n.attr("sf:style").and_then(|s| self.style(s, sheet));
                            let mut rp = self.run_props(pstyle, cstyle);
                            if n.name == "sf:link" {
                                rp.link = n.attr("href").and_then(Link::url);
                            }
                            (RunKind::Text(self.cased(&n.own_text(), pstyle, cstyle)), rp)
                        }
                        // The last one ends the paragraph; any other breaks the line.
                        "sf:br" if seen == last => continue,
                        "sf:br" | "sf:lnbr" => (RunKind::Break, base.clone()),
                        "sf:tab" => (RunKind::Text("\t".into()), base.clone()),
                        "sf:page-number" | "sf:slide-number" => {
                            (RunKind::Field("slidenum", number.to_string()), base.clone())
                        }
                        _ => continue,
                    }
                }
            };
            match (&kind, runs.last_mut()) {
                (RunKind::Text(t), _) if t.is_empty() => {}
                (
                    RunKind::Text(t),
                    Some(Run {
                        kind: RunKind::Text(prev),
                        props,
                    }),
                ) if *props == rp => prev.push_str(t),
                _ => runs.push(Run { kind, props: rp }),
            }
        }
        Ok(Paragraph {
            props,
            runs,
            end: base,
        })
    }

    /// `text` with the capitalization of its styles (3 is each word's first
    /// letter in capitals; all caps and small caps are the renderer's).
    fn cased(&self, text: &str, para: Option<Sty<'a>>, chr: Option<Sty<'a>>) -> String {
        let cap = self
            .prop_num(chr, "sf:capitalization")
            .or_else(|| self.prop_num(para, "sf:capitalization"));
        if cap == Some(3.0) {
            title_case(text)
        } else {
            text.to_string()
        }
    }

    fn run_props(&self, para: Option<Sty<'a>>, chr: Option<Sty<'a>>) -> RunProps {
        let get = |name: &str| {
            self.prop(chr, name)
                .or_else(|| self.prop(para, name))
                .map(|(v, _)| v)
        };
        let mut rp = RunProps::default();
        if let Some(name) = get("sf:fontName").and_then(|v| v.attr("sfa:string")) {
            let (fam, b, i) = ps_font(name);
            rp.font = Some(fam);
            if b {
                rp.bold = Some(true);
            }
            if i {
                rp.italic = Some(true);
            }
        }
        if let Some(b) = get("sf:bold").and_then(num) {
            rp.bold = Some(b != 0.0 || rp.bold == Some(true));
        }
        if let Some(i) = get("sf:italic").and_then(num) {
            rp.italic = Some(i != 0.0 || rp.italic == Some(true));
        }
        let size = get("sf:fontSize")
            .and_then(num)
            .unwrap_or(24.0)
            .clamp(1.0, 4000.0);
        rp.size = Some((size * 100.0).round() as u32);
        rp.color = Some(
            get("sf:fontColor")
                .filter(|v| v.name == "sf:color")
                .and_then(color)
                .unwrap_or(Color::rgb(0)),
        );
        rp.baseline = match get("sf:superscript").and_then(num) {
            Some(1.0) => Some(30_000),
            Some(2.0) => Some(-25_000),
            _ => None,
        };
        rp.underline = get("sf:underline").and_then(num).map(|u| {
            if u == 0.0 {
                "none"
            } else if u == 2.0 {
                "dbl"
            } else {
                "sng"
            }
        });
        rp.strike = get("sf:strikethru")
            .and_then(num)
            .map(|u| if u == 0.0 { "noStrike" } else { "sngStrike" });
        rp.caps = match get("sf:capitalization").and_then(num) {
            Some(1.0) => Some("all"),
            Some(2.0) => Some("small"),
            _ => None,
        };
        rp.shadow = get("sf:textShadow").and_then(shadow);
        rp
    }

    fn para_props(&self, para: Option<Sty<'a>>, level: u32, color: Option<Color>) -> ParaProps {
        let n = |name: &str| self.prop_num(para, name);
        let pts = |v: f64| (v.clamp(-10_000.0, 10_000.0) * PT).round() as Emu;
        let mut pp = ParaProps {
            level: level.min(8) as u8,
            align: n("sf:alignment").map(|a| match a as i32 {
                1 => "r",
                2 => "ctr",
                3 => "just",
                _ => "l",
            }),
            margin: n("sf:leftIndent").map(pts),
            indent: n("sf:firstLineIndent").map(pts),
            space_after: n("sf:spaceAfter").map(|v| Spacing::Pts((v * 100.0).round() as i32)),
            space_before: n("sf:spaceBefore").map(|v| Spacing::Pts((v * 100.0).round() as i32)),
            default_tab: n("sf:defaultTabStops").filter(|&v| v > 0.0).map(pts),
            bullet: Some(Bullet::None),
            ..ParaProps::default()
        };
        let list = self.prop_style(para, "sf:listStyle");
        if level > 0 {
            let lv = level as usize;
            let entry = |name: &str| -> Option<&'a Node> {
                let (arr, _) = self.prop(list, name)?;
                arr.nodes().nth(lv).map(|e| self.deref(e, NONE).0)
            };
            let bullet = entry("sf:listLabelTypes").and_then(|t| label(t, color));
            if let Some(b) = bullet {
                let label_at = entry("sf:listLabelIndents").and_then(num).unwrap_or(0.0);
                let text_at = entry("sf:listTextIndents").and_then(num).unwrap_or(20.0);
                pp.bullet = Some(b);
                pp.margin = Some(pts(label_at + text_at) + pp.margin.unwrap_or(0));
                pp.indent = Some(pts(-text_at));
            }
        }
        pp
    }
}

/// A list label type (`sf:list-label-typeinfo`) as a bullet.
fn label(t: &Node, color: Option<Color>) -> Option<Bullet> {
    if t.attr("sf:type") != Some("text") {
        return None;
    }
    let l = t.child("sf:text-label")?;
    let format = l.attr("sf:format").unwrap_or("\u{2022}");
    match l.attr("sf:type") {
        Some("bullet") | None => Some(Bullet::Char {
            ch: format.chars().next().unwrap_or('\u{2022}'),
            font: None,
            color,
            size: None,
        }),
        Some(kind) => {
            let scheme = match kind {
                "upper-roman" | "roman-upper" => "romanUcPeriod",
                "lower-roman" | "roman-lower" => "romanLcPeriod",
                "upper-alpha" | "alpha-upper" => "alphaUcPeriod",
                "lower-alpha" | "alpha-lower" => "alphaLcPeriod",
                _ => "arabicPeriod",
            };
            Some(Bullet::AutoNum {
                scheme,
                start: 1,
                font: None,
                color,
                size: None,
            })
        }
    }
}

fn title_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut start = true;
    for c in s.chars() {
        if start && c.is_alphabetic() {
            out.extend(c.to_uppercase());
        } else {
            out.push(c);
        }
        start = !c.is_alphanumeric() && c != '\'';
    }
    out
}
