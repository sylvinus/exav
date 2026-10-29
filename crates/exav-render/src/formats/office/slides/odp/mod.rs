//! OpenDocument presentations ([ODF 1.2] part 1, 9 and 10): ODP and OTP
//! packages and flat FODP documents. Each master page becomes a slide
//! master with its background and drawings; each draw:page a slide, its
//! shapes and text resolved through their styles into explicit properties.

mod geom;
mod styles;
mod text;

use crate::formats::office::common::base64;
use crate::formats::office::common::xml::{self, Node};
use crate::formats::office::slides::error::{Error, Result};
use crate::formats::office::slides::limits::Budget;
use crate::formats::office::slides::model::*;
use crate::formats::office::slides::package::{Zip, image_ext};
use std::collections::HashMap;
use styles::{Props, Styles, color, len, percent};

/// What a document holds: slides, or the pages of a drawing, each of which
/// becomes a slide of its own size.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Kind {
    Presentation,
    Drawing,
}

impl Kind {
    /// Whether a media type is this kind's: OpenDocument says "graphics" for
    /// a drawing, OpenOffice 1.x said "drawing".
    fn is_type(self, media_type: &str) -> bool {
        match self {
            Kind::Presentation => media_type.contains("presentation"),
            Kind::Drawing => media_type.contains("graphics") || media_type.contains("drawing"),
        }
    }

    fn body(self) -> &'static str {
        match self {
            Kind::Presentation => "office:presentation",
            Kind::Drawing => "office:drawing",
        }
    }
}

pub(crate) fn read_odp(z: Zip, budget: &mut Budget) -> Result<Presentation> {
    read_package(z, budget, Kind::Presentation)
}

pub(crate) fn read_odg(z: Zip, budget: &mut Budget) -> Result<Presentation> {
    read_package(z, budget, Kind::Drawing)
}

fn read_package(mut z: Zip, budget: &mut Budget, kind: Kind) -> Result<Presentation> {
    let max = budget.limits.max_part;
    if let Some(m) = z.get("mimetype", 256, budget)? {
        let m = String::from_utf8_lossy(&m);
        if !kind.is_type(&m) {
            return Err(Error::NotFormat(format!(
                "an OpenDocument file of type {}",
                m.trim()
            )));
        }
    }
    if let Some(m) = z.get("META-INF/manifest.xml", 16 << 20, budget)? {
        let m = String::from_utf8_lossy(&m);
        if let Some(i) = m.find("manifest:full-path=\"content.xml\"") {
            let e = &m[i..];
            let end = e
                .find("</manifest:file-entry>")
                .or_else(|| e.find("/>"))
                .unwrap_or(e.len());
            if e[..end].contains("encryption-data") {
                return Err(Error::Encrypted);
            }
        }
    }
    let content = z
        .get("content.xml", max, budget)?
        .ok_or_else(|| Error::NotFormat("no content.xml".into()))?;
    let styles_xml = z.get("styles.xml", max, budget)?;
    let content = xml::parse(&content, &mut budget.tree())?;
    let styles_doc = match styles_xml {
        Some(s) => xml::parse(&s, &mut budget.tree()).ok(),
        None => None,
    };
    // Pictures and objects are read when a slide uses them.
    let r = Reader::new(&content, styles_doc.as_ref(), Some(z), kind);
    r.read(budget)
}

pub(crate) fn read_fodp(bytes: &[u8], budget: &mut Budget) -> Result<Presentation> {
    read_flat(bytes, budget, Kind::Presentation)
}

pub(crate) fn read_fodg(bytes: &[u8], budget: &mut Budget) -> Result<Presentation> {
    read_flat(bytes, budget, Kind::Drawing)
}

fn read_flat(bytes: &[u8], budget: &mut Budget, kind: Kind) -> Result<Presentation> {
    let doc = xml::parse(bytes, &mut budget.tree())?;
    if doc.name != "office:document" {
        return Err(Error::NotFormat(format!(
            "not a flat ODF document: {}",
            doc.name
        )));
    }
    if let Some(m) = doc.attr("office:mimetype")
        && !kind.is_type(m)
    {
        return Err(Error::NotFormat(format!(
            "a flat OpenDocument file of type {m}"
        )));
    }
    let r = Reader::new(&doc, None, None, kind);
    r.read(budget)
}

/// The most an inline picture may decode to, as for a picture in the package.
const INLINE_PICTURE_MAX: usize = 64 << 20;

/// A position and size, and the transform of an ODF shape.
fn transform(n: &Node) -> Xfrm {
    let g = |k: &str| n.attr(k).and_then(len).unwrap_or(0);
    let (x, y, w, h) = (
        g("svg:x"),
        g("svg:y"),
        g("svg:width").max(0),
        g("svg:height").max(0),
    );
    let mut xf = Xfrm {
        x,
        y,
        w,
        h,
        ..Xfrm::default()
    };
    let Some(t) = n.attr("draw:transform") else {
        return xf;
    };
    // rotate(a) then translate(x y), applied to the box at the origin.
    let mut rot = 0.0f64;
    let mut tx = 0.0f64;
    let mut ty = 0.0f64;
    let mut translated = false;
    let mut rest = t;
    while let Some(open) = rest.find('(') {
        let name = rest[..open].trim().trim_start_matches(',').trim();
        let Some(close) = rest[open..].find(')') else {
            break;
        };
        let args: Vec<&str> = rest[open + 1..open + close]
            .split([' ', ','])
            .filter(|s| !s.is_empty())
            .collect();
        match name {
            "rotate" => {
                rot += args
                    .first()
                    .and_then(|a| a.parse::<f64>().ok())
                    .unwrap_or(0.0)
            }
            "translate" => {
                tx += args.first().and_then(|a| len(a)).unwrap_or(0) as f64;
                ty += args.get(1).and_then(|a| len(a)).unwrap_or(0) as f64;
                translated = true;
            }
            _ => {}
        }
        rest = &rest[open + close + 1..];
    }
    if !translated {
        tx = x as f64;
        ty = y as f64;
    }
    let (hw, hh) = (w as f64 / 2.0, h as f64 / 2.0);
    // Counterclockwise on screen, about the origin.
    let cx = hw * rot.cos() + hh * rot.sin() + tx;
    let cy = -hw * rot.sin() + hh * rot.cos() + ty;
    xf.x = (cx - hw).round() as Emu;
    xf.y = (cy - hh).round() as Emu;
    xf.rot = (-rot.to_degrees()).rem_euclid(360.0);
    xf
}

/// Which styles a shape's attributes name, in which scope.
#[derive(Clone, Copy, PartialEq)]
enum Scope {
    Content,
    Master,
}

struct Reader<'d> {
    kind: Kind,
    /// The layers of a drawing that are not displayed.
    hidden_layers: Vec<String>,
    content: &'d Node,
    styles_doc: Option<&'d Node>,
    master: Styles,
    body: Styles,
    /// The package, for the pictures and objects slides use.
    zip: Option<Zip<'d>>,
    /// A part the package could not give within the limits, raised after
    /// the slide that wanted it.
    failed: Option<Error>,
    media: HashMap<String, Option<usize>>,
    media_bytes: u64,
    /// The text area of the custom shape `geometry` last read.
    text_area: std::cell::Cell<Option<[f64; 4]>>,
    p: Presentation,
}

/// Per page context for fields.
struct PageCtx {
    number: usize,
    footer: String,
    date: String,
    header: String,
    auto_color: Rgb,
}

/// The automatic font colour on a background: white on a dark one.
fn auto_color(bg: Option<&Fill>) -> Rgb {
    let c = match bg {
        Some(Fill::Solid(c)) => c.rgb,
        Some(Fill::Gradient(g)) => g.stops.first().map(|s| s.1.rgb).unwrap_or(0xFFFFFF),
        _ => 0xFFFFFF,
    };
    let l = ((c >> 16) & 0xFF) * 299 + ((c >> 8) & 0xFF) * 587 + (c & 0xFF) * 114;
    if l < 128_000 { 0xFFFFFF } else { 0x000000 }
}

impl<'d> Reader<'d> {
    fn new(
        content: &'d Node,
        styles_doc: Option<&'d Node>,
        zip: Option<Zip<'d>>,
        kind: Kind,
    ) -> Reader<'d> {
        let sources: Vec<&Node> = styles_doc
            .into_iter()
            .chain(std::iter::once(content))
            .collect();
        let mut master = Styles::default();
        let mut body = Styles::default();
        for s in [&mut master, &mut body] {
            for d in &sources {
                for k in ["office:font-face-decls", "office:styles"] {
                    if let Some(n) = d.child(k) {
                        s.add(n);
                    }
                }
            }
        }
        // A flat document has one set of automatic styles for both.
        if let Some(sd) = styles_doc {
            if let Some(a) = sd.child("office:automatic-styles") {
                master.add(a);
            }
        } else if let Some(a) = content.child("office:automatic-styles") {
            master.add(a);
        }
        if let Some(a) = content.child("office:automatic-styles") {
            body.add(a);
        }
        Reader {
            kind,
            hidden_layers: vec![],
            content,
            styles_doc,
            master,
            body,
            zip,
            failed: None,
            media: HashMap::new(),
            media_bytes: 0,
            text_area: std::cell::Cell::new(None),
            p: Presentation::default(),
        }
    }

    fn styles(&self, s: Scope) -> &Styles {
        match s {
            Scope::Content => &self.body,
            Scope::Master => &self.master,
        }
    }

    fn masters_node(&self) -> Option<&'d Node> {
        self.styles_doc
            .and_then(|s| s.child("office:master-styles"))
            .or_else(|| self.content.child("office:master-styles"))
    }

    fn read(mut self, budget: &mut Budget) -> Result<Presentation> {
        let pres = self
            .content
            .child("office:body")
            .and_then(|b| b.child(self.kind.body()))
            .ok_or_else(|| Error::NotFormat(format!("no {} body", self.kind.body())))?;
        let masters: Vec<&Node> = self
            .masters_node()
            .map(|m| m.all("style:master-page").take(1024).collect())
            .unwrap_or_default();
        let pages: Vec<&Node> = pres.all("draw:page").collect();
        let (w, h) = match self.kind {
            // Slide size from the first master's page layout; without one,
            // the 28 by 15.75 cm of a new presentation.
            Kind::Presentation => {
                let new = (10_080_000, 5_670_000);
                self.page_size(masters.first().copied(), new).unwrap_or(new)
            }
            // A PPTX has one size: the largest of the pages', each page
            // drawn from its top left corner. Without any, A4 landscape.
            Kind::Drawing => {
                let a4 = (10_692_000, 7_560_000);
                pages
                    .iter()
                    .filter_map(|p| {
                        let name = p.attr("draw:master-page-name")?;
                        let m = masters.iter().find(|m| m.attr("style:name") == Some(name));
                        self.page_size(m.copied(), a4)
                    })
                    .reduce(|a, b| (a.0.max(b.0), a.1.max(b.1)))
                    .or_else(|| self.page_size(masters.first().copied(), a4))
                    .unwrap_or(a4)
            }
        };
        self.p.width = w;
        self.p.height = h;
        if self.kind == Kind::Drawing {
            self.hidden_layers = self
                .masters_node()
                .into_iter()
                .flat_map(|m| m.all("draw:layer-set"))
                .flat_map(|s| s.all("draw:layer"))
                .filter(|l| l.attr("draw:display") == Some("none"))
                .filter_map(|l| l.attr("draw:name").map(str::to_string))
                .collect();
        }

        let mut master_index: HashMap<String, usize> = HashMap::new();
        for m in &masters {
            let name = m.attr("style:name").unwrap_or("").to_string();
            let master = self.master(m, budget)?;
            master_index.insert(name, self.p.masters.len());
            self.p.masters.push(master);
        }
        if self.p.masters.is_empty() {
            self.p.masters.push(Master::default());
        }
        let decls = self.decls(pres);
        self.p.total_slides = pages.len();
        for (i, page) in pages.iter().enumerate() {
            if let Some(e) = self.failed.take() {
                return Err(e);
            }
            budget.slide(i)?;
            if !budget.wants(i) {
                continue;
            }
            let mname = page.attr("draw:master-page-name").unwrap_or("");
            let mi = master_index.get(mname).copied().unwrap_or(0);
            let mnode = masters
                .iter()
                .find(|m| m.attr("style:name") == Some(mname))
                .copied()
                .or(masters.first().copied());
            let slide = self.slide(page, i + 1, mi, mnode, &decls, budget)?;
            self.p.slides.push(slide);
            budget.alloc(std::mem::take(&mut self.media_bytes))?;
        }
        if let Some(e) = self.failed.take() {
            return Err(e);
        }
        budget.alloc(self.media_bytes)?;
        Ok(self.p)
    }

    /// The size of the page a master page's layout gives, a side it leaves
    /// out taken from `default`; `None` without a layout.
    fn page_size(&self, master: Option<&Node>, default: (Emu, Emu)) -> Option<(Emu, Emu)> {
        let pl = self
            .master
            .page_layouts
            .get(master?.attr("style:page-layout-name")?)?;
        Some((
            pl.len("fo:page-width").unwrap_or(default.0),
            pl.len("fo:page-height").unwrap_or(default.1),
        ))
    }

    /// Footer and date declarations of the presentation, by name.
    fn decls(&self, pres: &Node) -> HashMap<(String, String), String> {
        let mut out = HashMap::new();
        for (tag, kind) in [
            ("presentation:footer-decl", "footer"),
            ("presentation:header-decl", "header"),
            ("presentation:date-time-decl", "date"),
        ] {
            for d in pres.all(tag) {
                if let Some(n) = d.attr("presentation:name") {
                    let fixed = d.attr("presentation:source") != Some("current-date");
                    let t = if fixed {
                        styles::text_of(d)
                    } else {
                        String::new()
                    };
                    out.insert((kind.to_string(), n.to_string()), t);
                }
            }
        }
        out
    }

    fn page_fill(&mut self, props: &Props, scope: Scope) -> Option<Fill> {
        match props.get("draw:fill") {
            None | Some("none") => None,
            _ => Some(self.fill(props, scope)),
        }
    }

    fn master(&mut self, m: &Node, budget: &mut Budget) -> Result<Master> {
        let dp = self
            .master
            .resolve("drawing-page", m.attr("draw:style-name"));
        let bg = self
            .page_fill(&dp, Scope::Master)
            .or(Some(Fill::Solid(Color::rgb(0xFFFFFF))));
        let ctx = PageCtx {
            number: 1,
            footer: String::new(),
            date: String::new(),
            header: String::new(),
            auto_color: auto_color(bg.as_ref()),
        };
        let mut shapes = vec![];
        for n in m.nodes() {
            if n.attr("presentation:class").is_some() {
                continue;
            }
            if let Some(s) = self.shape(n, Scope::Master, &ctx, None, budget, 0)? {
                shapes.push(s);
            }
        }
        Ok(Master {
            name: m
                .attr("style:display-name")
                .or(m.attr("style:name"))
                .unwrap_or("")
                .to_string(),
            background: bg,
            shapes,
            layouts: vec![Layout {
                name: "Blank".into(),
                kind: "blank",
                show_master_shapes: true,
                ..Layout::default()
            }],
            ..Master::default()
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn slide(
        &mut self,
        page: &Node,
        number: usize,
        mi: usize,
        master: Option<&Node>,
        decls: &HashMap<(String, String), String>,
        budget: &mut Budget,
    ) -> Result<Slide> {
        let dp = self
            .body
            .resolve("drawing-page", page.attr("draw:style-name"));
        let background = if dp.is("presentation:background-visible", "false") {
            Some(Fill::Solid(Color::rgb(0xFFFFFF)))
        } else {
            self.page_fill(&dp, Scope::Content)
        };
        let decl = |kind: &str, attr: &str| {
            page.attr(attr)
                .and_then(|n| decls.get(&(kind.to_string(), n.to_string())))
                .cloned()
                .unwrap_or_default()
        };
        let shown_bg =
            background
                .as_ref()
                .or(self.p.masters.get(mi).and_then(|m| m.background.as_ref()));
        let ctx = PageCtx {
            number,
            footer: decl("footer", "presentation:use-footer-name"),
            date: decl("date", "presentation:use-date-time-name"),
            header: decl("header", "presentation:use-header-name"),
            auto_color: auto_color(shown_bg),
        };
        let mut shapes = vec![];
        for n in page.nodes() {
            if n.attr("draw:layer")
                .is_some_and(|l| self.hidden_layers.iter().any(|h| h == l))
            {
                continue;
            }
            if let Some(s) = self.shape(n, Scope::Content, &ctx, None, budget, 0)? {
                shapes.push(s);
            }
        }
        // The master's footer, slide number and date, as the page shows them.
        if let Some(m) = master {
            let show = |k: &str, default: bool| dp.get(k).map(|v| v == "true").unwrap_or(default);
            for n in m.nodes() {
                let wanted = match n.attr("presentation:class") {
                    Some("footer") => {
                        show("presentation:display-footer", true) && !ctx.footer.is_empty()
                    }
                    Some("page-number") => show("presentation:display-page-number", false),
                    Some("date-time") => {
                        show("presentation:display-date-time", true) && !ctx.date.is_empty()
                    }
                    _ => false,
                };
                if wanted && let Some(s) = self.shape(n, Scope::Master, &ctx, None, budget, 0)? {
                    shapes.push(s);
                }
            }
        }
        let name = match self.kind {
            Kind::Drawing => page.attr("draw:name").map(str::to_string),
            Kind::Presentation => None,
        };
        Ok(Slide {
            name,
            master: mi,
            layout: 0,
            background,
            shapes,
            hidden: dp.is("presentation:visibility", "hidden")
                || page.attr("presentation:visibility") == Some("hidden"),
            show_master_shapes: !dp.is("presentation:background-objects-visible", "false"),
        })
    }

    /// The bytes of a picture by its href, once, as a media index. Their
    /// memory is charged when the reading ends.
    /// A picture by its package path, or "data:" and its base64 text (a
    /// flat file's inline picture).
    fn image(&mut self, href: &str) -> Option<usize> {
        if let Some(b64) = href.strip_prefix("data:") {
            let d = base64::decode(b64, INLINE_PICTURE_MAX)?;
            let ext = image_ext(&d)?;
            self.media_bytes += d.len() as u64;
            return Some(self.p.add_media(ext, d));
        }
        let key = href.trim_start_matches("./").to_string();
        if let Some(&m) = self.media.get(&key) {
            return m;
        }
        let m = self.part(&key).and_then(|d| Some((image_ext(&d)?, d)));
        let m = m.map(|(ext, d)| {
            self.media_bytes += d.len() as u64;
            self.p.add_media(ext, d)
        });
        self.media.insert(key, m);
        m
    }

    /// A member of the package by its path (with or without "./"), at most
    /// 64 MiB; a larger one fails the conversion after the slide.
    fn part(&mut self, path: &str) -> Option<Vec<u8>> {
        let zip = self.zip.as_mut()?;
        let path = path.trim_start_matches("./");
        let found = match zip.read(path, 64 << 20) {
            Ok(None) => zip.read(&format!("./{path}"), 64 << 20),
            r => r,
        };
        found.unwrap_or_else(|e| {
            self.failed.get_or_insert(e);
            None
        })
    }

    fn inline_image(&mut self, n: &Node) -> Option<usize> {
        if let Some(h) = n.attr("xlink:href") {
            return self.image(h);
        }
        let d = base64::decode(
            &n.child("office:binary-data")?.own_text(),
            INLINE_PICTURE_MAX,
        )?;
        let ext = image_ext(&d)?;
        self.media_bytes += d.len() as u64;
        Some(self.p.add_media(ext, d))
    }

    fn fill(&mut self, p: &Props, scope: Scope) -> Fill {
        let alpha = p
            .get("draw:opacity")
            .and_then(percent)
            .map(|f| (f * 100_000.0).round().clamp(0.0, 100_000.0) as u32)
            .filter(|&a| a < 100_000);
        let c = |rgb: Rgb| Color { rgb, alpha };
        // Unstyled shapes are filled, as their usual writer's default
        // style is (pages say otherwise in `page_fill`).
        match p.get("draw:fill").unwrap_or("solid") {
            "solid" => Fill::Solid(c(p.color("draw:fill-color").unwrap_or(0x729FCF))),
            "gradient" => {
                let st = self.styles(scope);
                let g = p
                    .get("draw:fill-gradient-name")
                    .and_then(|n| st.object("draw:gradient", n))
                    .cloned();
                match g {
                    Some(g) => gradient(&g, alpha),
                    None => Fill::Solid(c(p.color("draw:fill-color").unwrap_or(0x729FCF))),
                }
            }
            "bitmap" => {
                let href = p
                    .get("draw:fill-image-name")
                    .and_then(|n| self.styles(scope).object("draw:fill-image", n))
                    .and_then(|o| o.get("xlink:href"))
                    .map(str::to_string);
                // ODF's default is to repeat.
                // A tile as large as the shape is the shape stretched.
                let whole = |k: &str| p.get(k).and_then(percent).is_some_and(|f| f >= 0.99);
                let tile = !matches!(p.get("style:repeat"), Some("stretch" | "no-repeat"))
                    && !(whole("draw:fill-image-width") && whole("draw:fill-image-height"));
                match href.and_then(|h| self.image(&h)) {
                    Some(media) => Fill::Picture { media, tile },
                    None => Fill::Solid(c(p.color("draw:fill-color").unwrap_or(0xCCCCCC))),
                }
            }
            "hatch" => {
                let h = p
                    .get("draw:fill-hatch-name")
                    .and_then(|n| self.styles(scope).object("draw:hatch", n));
                let fg = h.and_then(|h| h.color("draw:color")).unwrap_or(0);
                let rot = h
                    .and_then(|h| h.get("draw:rotation"))
                    .map(angle_tenths)
                    .unwrap_or(0.0)
                    .rem_euclid(180.0);
                let double = h.is_some_and(|h| h.get("draw:style") != Some("single"));
                let preset = match (double, rot) {
                    (true, r) if (r - 45.0).abs() < 22.5 || (r - 135.0).abs() < 22.5 => "diagCross",
                    (true, _) => "cross",
                    (false, r) if (r - 90.0).abs() < 22.5 => "vert",
                    (false, r) if (r - 45.0).abs() < 22.5 => "upDiag",
                    (false, r) if (r - 135.0).abs() < 22.5 => "dnDiag",
                    _ => "horz",
                };
                let bg = if p.is("draw:fill-hatch-solid", "true") {
                    c(p.color("draw:fill-color").unwrap_or(0xFFFFFF))
                } else {
                    Color {
                        rgb: 0xFFFFFF,
                        alpha: Some(0),
                    }
                };
                Fill::Pattern {
                    preset,
                    fg: c(fg),
                    bg,
                }
            }
            _ => Fill::None,
        }
    }

    fn line(&self, p: &Props, scope: Scope) -> Line {
        let stroke = p.get("draw:stroke").unwrap_or("solid");
        if stroke == "none" {
            return Line::default();
        }
        let alpha = p
            .get("svg:stroke-opacity")
            .and_then(|v| percent(v).or_else(|| v.parse::<f64>().ok()))
            .map(|f| (f * 100_000.0).round().clamp(0.0, 100_000.0) as u32)
            .filter(|&a| a < 100_000);
        // A width with no unit is in hundredths of a millimetre, as a drawing
        // counts them.
        let width = p
            .get("svg:stroke-width")
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
            .map(|v| (v * 360.0).clamp(-1e13, 1e13).round() as Emu)
            .or_else(|| p.len("svg:stroke-width"))
            .unwrap_or(0)
            .max(0);
        let dash = if stroke == "dash" {
            let d = p
                .get("draw:stroke-dash")
                .and_then(|n| self.styles(scope).object("draw:stroke-dash", n));
            Some(dash_preset(d))
        } else {
            None
        };
        let marker = |which: &str| -> Option<Arrow> {
            let name = p.get(&format!("draw:marker-{which}"))?;
            if name.is_empty() {
                return None;
            }
            let lname = name.to_ascii_lowercase();
            let kind = if lname.contains("circle") {
                "oval"
            } else if lname.contains("square") || lname.contains("diamond") {
                "diamond"
            } else if lname.contains("line") || lname.contains("concave") {
                "stealth"
            } else {
                "triangle"
            };
            let mw = p
                .len(&format!("draw:marker-{which}-width"))
                .unwrap_or(width * 3);
            let ratio = if width > 0 {
                mw as f64 / width as f64
            } else {
                mw as f64 / 12_700.0
            };
            let size = if ratio < 2.5 {
                "sm"
            } else if ratio < 5.0 {
                "med"
            } else {
                "lg"
            };
            Some(Arrow {
                kind,
                w: size,
                len: size,
            })
        };
        Line {
            fill: Fill::Solid(Color {
                rgb: p.color("svg:stroke-color").unwrap_or(0x3465A4),
                alpha,
            }),
            width: if width == 0 { 9525 } else { width },
            dash,
            cap: match p.get("svg:stroke-linecap") {
                Some("round") => Some("rnd"),
                Some("square") => Some("sq"),
                _ => None,
            },
            join: match p.get("draw:stroke-linejoin") {
                Some("round") => Some("round"),
                Some("bevel") => Some("bevel"),
                Some("miter") => Some("miter"),
                _ => None,
            },
            compound: None,
            head: marker("start"),
            tail: marker("end"),
        }
    }

    fn shadow(&self, p: &Props) -> Option<Shadow> {
        if !p.is("draw:shadow", "visible") {
            return None;
        }
        let dx = p.len("draw:shadow-offset-x").unwrap_or(0) as f64;
        let dy = p.len("draw:shadow-offset-y").unwrap_or(0) as f64;
        let alpha = p
            .get("draw:shadow-opacity")
            .and_then(percent)
            .map(|f| (f * 100_000.0).round().clamp(0.0, 100_000.0) as u32);
        Some(Shadow {
            color: Color {
                rgb: p.color("draw:shadow-color").unwrap_or(0x808080),
                alpha,
            },
            blur: p.len("loext:shadow-blur").unwrap_or(0).max(0),
            dist: dx.hypot(dy).round() as Emu,
            dir: dy.atan2(dx).to_degrees(),
        })
    }

    fn style_of(&self, n: &Node, scope: Scope) -> (Props, Option<String>) {
        let st = self.styles(scope);
        if let Some(ps) = n.attr("presentation:style-name") {
            let mut p = st.resolve("presentation", Some(ps));
            if let Some(gs) = n.attr("draw:style-name") {
                p.overlay(&st.chain("graphic", Some(gs)).0);
            }
            return (p, Some(ps.to_string()));
        }
        (st.resolve("graphic", n.attr("draw:style-name")), None)
    }

    fn body_props(&self, p: &Props, frame: bool) -> BodyProps {
        let pad = |k: &str, d: Emu| p.len(k).or_else(|| p.len("fo:padding")).unwrap_or(d).max(0);
        // Unsaid, a drawing shape's text sits in its middle, a frame's at
        // its top.
        let anchor = match p.get("draw:textarea-vertical-align") {
            Some("middle") => "ctr",
            Some("bottom") => "b",
            Some(_) => "t",
            None if frame => "t",
            None => "ctr",
        };
        let wrap = if frame {
            !p.is("draw:auto-grow-width", "true")
        } else {
            !p.is("fo:wrap-option", "no-wrap")
        };
        let autofit = if p.is("draw:fit-to-size", "true")
            || p.is("draw:fit-to-size", "shrink-to-fit")
            || p.is("style:shrink-to-fit", "true")
        {
            Autofit::Normal(100_000, 0)
        } else if p.is("draw:auto-grow-height", "true") && frame {
            Autofit::Shape
        } else {
            Autofit::None
        };
        BodyProps {
            insets: [
                pad("fo:padding-left", 0),
                pad("fo:padding-top", 0),
                pad("fo:padding-right", 0),
                pad("fo:padding-bottom", 0),
            ],
            anchor,
            anchor_ctr: !wrap && p.is("draw:textarea-horizontal-align", "center"),
            wrap,
            vert: match p.get("style:writing-mode") {
                Some("tb-rl") | Some("tb") => Some("eaVert"),
                Some("tb-rl90") => Some("vert"),
                Some("bt-lr") => Some("vert270"),
                _ => None,
            },
            autofit,
            rot: 0.0,
            columns: p
                .get("fo:column-count")
                .and_then(|v| v.parse().ok())
                .unwrap_or(1)
                .clamp(1, 16),
        }
    }

    /// Text of `n` (a text box or a shape) with `props` as the shape's
    /// style.
    #[allow(clippy::too_many_arguments)]
    fn text(
        &mut self,
        n: &Node,
        props: &Props,
        pres_style: Option<&str>,
        scope: Scope,
        ctx: &PageCtx,
        frame: bool,
        budget: &mut Budget,
    ) -> Result<Option<TextBody>> {
        let has = n
            .nodes()
            .any(|c| matches!(c.name.as_str(), "text:p" | "text:list" | "text:h"));
        if !has {
            return Ok(None);
        }
        // Outline levels: the presentation style's "-outline1" ancestor
        // names the others.
        let st = self.styles(scope);
        let mut outline_base: Option<String> = None;
        let mut cur = pres_style.map(str::to_string);
        let mut guard = 0;
        while let Some(s) = cur.take() {
            guard += 1;
            if guard > 32 {
                break;
            }
            if let Some(b) = s.strip_suffix("-outline1") {
                outline_base = Some(b.to_string());
                break;
            }
            cur = st.get("presentation", &s).and_then(|d| d.parent.clone());
        }
        let list = pres_style
            .and_then(|s| st.list_of("presentation", Some(s)))
            .or_else(|| st.list_of("graphic", n.attr("draw:style-name")))
            .cloned();
        let levels = |lv: usize| -> Option<Props> {
            let b = outline_base.as_ref()?;
            (lv > 1).then(|| st.chain("presentation", Some(&format!("{b}-outline{lv}"))))
        };
        let mut tctx = text::TextCtx {
            styles: st,
            base: props,
            levels: &levels,
            list: list.as_ref(),
            slide_number: ctx.number,
            footer: &ctx.footer,
            date: &ctx.date,
            header: &ctx.header,
            // Over the shape's own solid fill, else over the page.
            auto_color: match (props.get("draw:fill"), props.color("draw:fill-color")) {
                (Some("solid"), Some(c)) => auto_color(Some(&Fill::Solid(Color::rgb(c)))),
                _ => ctx.auto_color,
            },
            pictures: vec![],
        };
        let mut paras = text::paragraphs(n, &mut tctx);
        let pictures = std::mem::take(&mut tctx.pictures);
        if !pictures.is_empty() {
            // Picture bullets name their picture by its place in the list;
            // one that cannot be read is a round bullet.
            let media: Vec<Option<usize>> = pictures.iter().map(|href| self.image(href)).collect();
            for p in &mut paras {
                if let Some(Bullet::Picture { media: i, size }) = p.props.bullet.clone() {
                    p.props.bullet = Some(match media.get(i).copied().flatten() {
                        Some(media) => Bullet::Picture { media, size },
                        None => Bullet::Char {
                            ch: '\u{2022}',
                            font: None,
                            color: None,
                            size,
                        },
                    });
                }
            }
        }
        // A drawing shape's text block is centred unless said otherwise.
        if !frame
            && props
                .get("draw:textarea-horizontal-align")
                .is_none_or(|a| a == "center")
        {
            for p in &mut paras {
                p.props.align.get_or_insert("ctr");
            }
        }
        let chars: usize = paras.iter().map(|p| p.runs.len() * 32).sum();
        budget.alloc(chars as u64)?;
        Ok(Some(TextBody {
            body: self.body_props(props, frame),
            paras,
            levels: ListStyle::default(),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn shape(
        &mut self,
        n: &Node,
        scope: Scope,
        ctx: &PageCtx,
        _parent: Option<&Xfrm>,
        budget: &mut Budget,
        depth: u32,
    ) -> Result<Option<Shape>> {
        if depth > 32 {
            return Ok(None);
        }
        let kind = n.name.as_str();
        if !matches!(
            kind,
            "draw:frame"
                | "draw:rect"
                | "draw:ellipse"
                | "draw:circle"
                | "draw:line"
                | "draw:polyline"
                | "draw:polygon"
                | "draw:path"
                | "draw:custom-shape"
                | "draw:connector"
                | "draw:g"
                | "draw:measure"
                | "draw:caption"
                | "draw:regular-polygon"
        ) {
            return Ok(None);
        }
        budget.shape(0)?;
        let class = n.attr("presentation:class");
        if matches!(class, Some("notes" | "handout" | "page")) {
            return Ok(None);
        }
        let (props, pres_style) = self.style_of(n, scope);
        let mut xf = transform(n);
        let fill = self.fill(&props, scope);
        let line = self.line(&props, scope);
        // An empty placeholder shows only while editing, but for the fill
        // and line it has.
        if n.attr("presentation:placeholder") == Some("true")
            && fill == Fill::None
            && line.fill == Fill::None
        {
            return Ok(None);
        }
        let shadow = self.shadow(&props);
        let mut shape_kind: Option<ShapeKind> = None;
        match kind {
            "draw:frame" => {
                // A picture, a table, an object's replacement or a text box.
                if let Some(t) = n.child("table:table") {
                    shape_kind = self
                        .table(t, &xf, scope, ctx, budget)?
                        .map(|t| ShapeKind::Table(Box::new(t)));
                }
                // A chart object, as a chart.
                if let Some(obj) = n.child("draw:object") {
                    // In a package, a part named by a link; in a flat file,
                    // the object's document inside it.
                    let content = match (obj.attr("xlink:href"), obj.child("office:document")) {
                        (_, Some(doc)) => {
                            let x = doc.to_xml();
                            budget.alloc(x.len() as u64)?;
                            Some(x.into_bytes())
                        }
                        (Some(href), None) => self.part(&format!(
                            "{}/content.xml",
                            href.trim_start_matches("./").trim_end_matches('/')
                        )),
                        _ => None,
                    };
                    if let Some(xml) =
                        content.and_then(|c| crate::formats::office::sheets::odf_chart_part(&c))
                    {
                        budget.alloc(xml.len() as u64)?;
                        shape_kind = Some(ShapeKind::Chart(xml));
                    }
                }
                if shape_kind.is_none() {
                    // A raster picture or metafile first, an SVG last (a
                    // frame may hold both).
                    let mut pic = None;
                    let mut svg = None;
                    for img in n.all("draw:image") {
                        if let Some(m) = self.inline_image(img) {
                            if self.p.media[m].ext == "svg" {
                                svg.get_or_insert(m);
                            } else {
                                pic = Some(m);
                                break;
                            }
                        }
                    }
                    let pic = pic.or(svg);
                    if pic.is_none()
                        && (n.child("draw:object").is_some()
                            || n.child("draw:object-ole").is_some())
                    {
                        self.p
                            .warn("embedded objects without a replacement picture it can draw");
                    }
                    if let Some(media) = pic {
                        shape_kind = Some(ShapeKind::Pic(Box::new(Pic {
                            media,
                            crop: [0; 4],
                            geom: Geometry::default(),
                            line: line.clone(),
                            shadow: shadow.clone(),
                            alpha: props
                                .get("draw:image-opacity")
                                .and_then(percent)
                                .map(|f| (f * 100_000.0).round() as u32),
                        })));
                    }
                }
                // A video or sound that cannot play: a box in its place.
                if let (None, Some(plugin)) = (&shape_kind, n.child("draw:plugin")) {
                    let href = plugin.attr("xlink:href").unwrap_or("").to_ascii_lowercase();
                    let audio = [
                        ".mp3", ".wav", ".ogg", ".oga", ".m4a", ".aac", ".flac", ".wma",
                    ]
                    .iter()
                    .any(|e| href.ends_with(e));
                    self.p.warn("videos and sounds, drawn as boxes");
                    shape_kind = Some(ShapeKind::media_placeholder(xf.w, xf.h, !audio));
                }
                if shape_kind.is_none() {
                    let tb = n.child("draw:text-box");
                    let text = match tb {
                        Some(tb) => {
                            self.text(tb, &props, pres_style.as_deref(), scope, ctx, true, budget)?
                        }
                        None => None,
                    };
                    if text.is_none() && tb.is_none() {
                        return Ok(None);
                    }
                    shape_kind = Some(ShapeKind::Sp(Box::new(Sp {
                        geom: Geometry::default(),
                        fill: fill.clone(),
                        line: line.clone(),
                        shadow: shadow.clone(),
                        text,
                        ..Sp::default()
                    })));
                }
            }
            "draw:g" => {
                let mut kids = vec![];
                for c in n.nodes() {
                    if let Some(s) = self.shape(c, scope, ctx, None, budget, depth + 1)? {
                        kids.push(s);
                    }
                }
                if kids.is_empty() {
                    return Ok(None);
                }
                let bbox = bounds(&kids);
                let mut s = Shape::new(
                    ShapeKind::Group(Box::new(Group {
                        child: bbox.clone(),
                        shapes: kids,
                    })),
                    bbox,
                );
                s.name = n.attr("draw:name").unwrap_or("").to_string();
                return Ok(Some(s));
            }
            _ => {
                let eg = n.child("draw:enhanced-geometry");
                let fontwork = eg.is_some_and(|e| {
                    e.attr("draw:text-path") == Some("true")
                        || e.attr("draw:type")
                            .is_some_and(|t| t.starts_with("fontwork"))
                });
                if fontwork {
                    // Fontwork: its text in its fill, filling the shape.
                    let mut text =
                        self.text(n, &props, pres_style.as_deref(), scope, ctx, false, budget)?;
                    if let Some(t) = &mut text {
                        let lines = t.paras.len().max(1) as f64;
                        let size = ((xf.h as f64 / 12_700.0 / lines * 0.75).clamp(1.0, 400.0)
                            * 100.0) as u32;
                        let color = match &fill {
                            Fill::Solid(c) => Some(*c),
                            Fill::Gradient(g) => g.stops.first().map(|s| s.1),
                            _ => None,
                        };
                        for p in &mut t.paras {
                            p.props.align = Some("ctr");
                            for r in &mut p.runs {
                                r.props.size = Some(size);
                                if color.is_some() {
                                    r.props.color = color;
                                }
                            }
                        }
                        t.body.anchor = "ctr";
                        t.body.wrap = false;
                        t.body.insets = [0; 4];
                    }
                    let sp = Sp {
                        geom: Geometry::default(),
                        fill: Fill::None,
                        line: Line::default(),
                        shadow,
                        text,
                        ..Sp::default()
                    };
                    let mut s = Shape::new(ShapeKind::Sp(Box::new(sp)), xf);
                    s.name = n.attr("draw:name").unwrap_or("").to_string();
                    return Ok(Some(s));
                }
                self.text_area.set(None);
                let (geom, connector) = self.geometry(n, &mut xf);
                let text_rect = self.text_area.take();
                let Some(geom) = geom else {
                    return Ok(None);
                };
                let text =
                    self.text(n, &props, pres_style.as_deref(), scope, ctx, false, budget)?;
                let open = matches!(
                    kind,
                    "draw:line" | "draw:polyline" | "draw:connector" | "draw:measure"
                );
                shape_kind = Some(ShapeKind::Sp(Box::new(Sp {
                    geom,
                    fill: if open { Fill::None } else { fill },
                    line,
                    shadow,
                    text,
                    connector: connector && n.child("text:p").is_none(),
                    text_rect,
                })));
            }
        }
        let Some(k) = shape_kind else { return Ok(None) };
        let mut s = Shape::new(k, xf);
        s.name = n.attr("draw:name").unwrap_or("").to_string();
        s.descr = n
            .child("svg:desc")
            .or_else(|| n.child("svg:title"))
            .map(styles::text_of)
            .unwrap_or_default();
        s.placeholder = class.and_then(|c| {
            Some(Placeholder {
                kind: match c {
                    "title" => "title",
                    "outline" => "body",
                    "subtitle" => "subTitle",
                    "footer" => "ftr",
                    "page-number" => "sldNum",
                    "date-time" => "dt",
                    "header" => return None,
                    _ => "obj",
                },
                idx: match c {
                    "title" => None,
                    "outline" => Some(1),
                    "subtitle" => Some(1),
                    "footer" => Some(11),
                    "page-number" => Some(12),
                    "date-time" => Some(10),
                    _ => Some(2),
                },
            })
        });
        Ok(Some(s))
    }

    /// Geometry of a drawing shape, and whether it is a line.
    fn geometry(&self, n: &Node, xf: &mut Xfrm) -> (Option<Geometry>, bool) {
        let vb = |n: &Node| geom::view_box(n.attr("svg:viewBox"));
        match n.name.as_str() {
            "draw:rect" | "draw:caption" => {
                let r = n.attr("draw:corner-radius").and_then(len).unwrap_or(0);
                let ss = xf.w.min(xf.h).max(1);
                if r > 0 {
                    let adj = ((r as f64 / ss as f64) * 100_000.0)
                        .round()
                        .clamp(0.0, 50_000.0) as i64;
                    (
                        Some(Geometry::Preset {
                            name: "roundRect",
                            adj: vec![("adj", adj)],
                        }),
                        false,
                    )
                } else {
                    (Some(Geometry::default()), false)
                }
            }
            "draw:ellipse" | "draw:circle" => {
                let kind = n.attr("draw:kind").unwrap_or("full");
                if kind == "full" {
                    return (Some(Geometry::preset("ellipse")), false);
                }
                let st = n.attr("draw:start-angle").map(angle_deg).unwrap_or(0.0);
                let en = n.attr("draw:end-angle").map(angle_deg).unwrap_or(360.0);
                // Counterclockwise degrees to DrawingML's clockwise ones.
                let a = |d: f64| ((360.0 - d).rem_euclid(360.0) * 60000.0).round() as i64;
                let name = match kind {
                    "arc" => "arc",
                    "cut" => "chord",
                    _ => "pie",
                };
                // The swept part runs counterclockwise from start to end:
                // clockwise from end to start.
                (
                    Some(Geometry::Preset {
                        name,
                        adj: vec![("adj1", a(en)), ("adj2", a(st))],
                    }),
                    false,
                )
            }
            "draw:line" | "draw:measure" | "draw:connector" => {
                let g = |k: &str| n.attr(k).and_then(len).unwrap_or(0);
                let (x1, y1, x2, y2) = (g("svg:x1"), g("svg:y1"), g("svg:x2"), g("svg:y2"));
                if n.name == "draw:connector"
                    && let (Some(d), Some(v)) = (n.attr("svg:d"), vb(n))
                {
                    // The path's box is the view box, in 1/100 mm.
                    let bx = (v[0] * 360.0).round() as Emu;
                    let by = (v[1] * 360.0).round() as Emu;
                    let bw = (v[2] * 360.0).round() as Emu;
                    let bh = (v[3] * 360.0).round() as Emu;
                    *xf = Xfrm {
                        x: bx,
                        y: by,
                        w: bw.max(1),
                        h: bh.max(1),
                        ..Xfrm::default()
                    };
                    return (geom::svg_path(d, v, false), true);
                }
                *xf = Xfrm {
                    x: x1.min(x2),
                    y: y1.min(y2),
                    w: (x2 - x1).abs(),
                    h: (y2 - y1).abs(),
                    flip_h: x2 < x1,
                    flip_v: y2 < y1,
                    ..Xfrm::default()
                };
                (Some(Geometry::preset("line")), true)
            }
            "draw:polyline" | "draw:polygon" => {
                let v = vb(n).unwrap_or([0.0, 0.0, xf.w.max(1) as f64, xf.h.max(1) as f64]);
                (
                    n.attr("draw:points")
                        .and_then(|p| geom::points(p, v, n.name == "draw:polygon")),
                    n.name == "draw:polyline",
                )
            }
            "draw:path" => {
                let v = vb(n).unwrap_or([0.0, 0.0, xf.w.max(1) as f64, xf.h.max(1) as f64]);
                (
                    n.attr("svg:d").and_then(|d| geom::svg_path(d, v, true)),
                    false,
                )
            }
            "draw:regular-polygon" => {
                let k = n
                    .attr("draw:corners")
                    .and_then(|c| c.parse::<usize>().ok())
                    .unwrap_or(5)
                    .clamp(3, 64);
                let concave = n.attr("draw:concave") == Some("true");
                let sharp = n.attr("draw:sharpness").and_then(percent).unwrap_or(0.5);
                let mut pts = String::new();
                let total = if concave { k * 2 } else { k };
                for i in 0..total {
                    let a = -std::f64::consts::FRAC_PI_2
                        + i as f64 * std::f64::consts::TAU / total as f64;
                    let r = if concave && i % 2 == 1 {
                        1.0 - sharp
                    } else {
                        1.0
                    };
                    pts.push_str(&format!(
                        "{},{} ",
                        500.0 + 500.0 * r * a.cos(),
                        500.0 + 500.0 * r * a.sin()
                    ));
                }
                (geom::points(&pts, [0.0, 0.0, 1000.0, 1000.0], true), false)
            }
            "draw:custom-shape" => {
                let Some(eg) = n.child("draw:enhanced-geometry") else {
                    return (Some(Geometry::default()), false);
                };
                if let Some((g, mh, mv, area)) = geom::enhanced(eg, xf.w, xf.h) {
                    self.text_area.set(area);
                    if mh {
                        xf.flip_h = !xf.flip_h;
                    }
                    if mv {
                        xf.flip_v = !xf.flip_v;
                    }
                    return (Some(g), false);
                }
                let preset = match eg.attr("draw:type").unwrap_or("rectangle") {
                    "ellipse" => "ellipse",
                    "round-rectangle" => "roundRect",
                    "isosceles-triangle" => "triangle",
                    "right-triangle" => "rtTriangle",
                    "diamond" => "diamond",
                    "parallelogram" => "parallelogram",
                    "trapezoid" => "trapezoid",
                    "hexagon" => "hexagon",
                    "octagon" => "octagon",
                    "pentagon" => "pentagon",
                    "cross" => "plus",
                    "star5" => "star5",
                    "right-arrow" => "rightArrow",
                    "left-arrow" => "leftArrow",
                    "up-arrow" => "upArrow",
                    "down-arrow" => "downArrow",
                    "heart" => "heart",
                    "smiley" => "smileyFace",
                    "can" => "can",
                    "cube" => "cube",
                    t if t.starts_with("ooxml-") => {
                        // The preset itself; unknown names fall back to a rectangle.
                        return (Some(Geometry::preset(ooxml_preset(&t[6..]))), false);
                    }
                    _ => "rect",
                };
                (Some(Geometry::preset(preset)), false)
            }
            _ => (None, false),
        }
    }

    fn table(
        &mut self,
        t: &Node,
        xf: &Xfrm,
        scope: Scope,
        ctx: &PageCtx,
        budget: &mut Budget,
    ) -> Result<Option<Table>> {
        let st = self.styles(scope);
        let mut cols: Vec<Emu> = vec![];
        for c in t.all("table:table-column").take(1000) {
            let w = st
                .resolve("table-column", c.attr("table:style-name"))
                .len("style:column-width")
                .unwrap_or(0);
            let rep = c
                .attr("table:number-columns-repeated")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1)
                .min(1000);
            for _ in 0..rep {
                cols.push(w);
            }
        }
        let rows_nodes: Vec<&Node> = t
            .nodes()
            .flat_map(|n| {
                if n.name == "table:table-row" {
                    vec![n]
                } else if n.name.starts_with("table:table-header-rows")
                    || n.name == "table:table-rows"
                {
                    n.all("table:table-row").collect()
                } else {
                    vec![]
                }
            })
            .take(1000)
            .collect();
        let parts: Vec<(String, String)> = t
            .attr("table:template-name")
            .and_then(|n| self.styles(scope).table_templates.get(n))
            .cloned()
            .unwrap_or_default();
        let flag = |k: &str| t.attr(k) == Some("true");
        let (first_row, last_row, first_col, last_col, band_rows, band_cols) = (
            flag("table:use-first-row-styles"),
            flag("table:use-last-row-styles"),
            flag("table:use-first-column-styles"),
            flag("table:use-last-column-styles"),
            flag("table:use-banding-rows-styles"),
            flag("table:use-banding-columns-styles"),
        );
        let nrows = rows_nodes.len();
        let part = |name: &str| parts.iter().find(|p| p.0 == name).map(|p| p.1.clone());
        // The template's cell style for a cell: first and last rows and
        // columns over banding over the body.
        let template = |ri: usize, ci: usize, ncols: usize| -> Option<String> {
            if parts.is_empty() {
                return None;
            }
            let mut s = part("body");
            if band_cols && ci % 2 == 1 {
                s = part("odd-columns").or(s);
            }
            if band_rows && ri % 2 == 1 {
                s = part("odd-rows").or(s);
            }
            if first_col && ci == 0 {
                s = part("first-column").or(s);
            }
            if last_col && ci + 1 == ncols {
                s = part("last-column").or(s);
            }
            if first_row && ri == 0 {
                s = part("first-row").or(s);
            }
            if last_row && ri + 1 == nrows {
                s = part("last-row").or(s);
            }
            s
        };
        let mut rows = vec![];
        for (ri, r) in rows_nodes.into_iter().enumerate() {
            let ncols = r
                .nodes()
                .filter(|c| c.name == "table:table-cell" || c.name == "table:covered-table-cell")
                .count();
            let h = self
                .styles(scope)
                .resolve("table-row", r.attr("table:style-name"))
                .len("style:row-height")
                .unwrap_or(0);
            let mut cells = vec![];
            let cell_nodes = r
                .nodes()
                .filter(|c| c.name == "table:table-cell" || c.name == "table:covered-table-cell");
            for (ci, c) in cell_nodes.take(1000).enumerate() {
                let covered = c.name == "table:covered-table-cell";
                let mut cp = self
                    .styles(scope)
                    .resolve("table-cell", template(ri, ci, ncols).as_deref());
                cp.overlay(
                    &self
                        .styles(scope)
                        .chain("table-cell", c.attr("table:style-name"))
                        .0,
                );
                let fill = match cp.get("fo:background-color") {
                    Some(v) if v != "transparent" => color(v)
                        .map(|rgb| Fill::Solid(Color::rgb(rgb)))
                        .unwrap_or_default(),
                    _ => match cp.get("draw:fill") {
                        Some("solid") | Some("gradient") | Some("bitmap") => self.fill(&cp, scope),
                        _ => Fill::None,
                    },
                };
                let border = |k: &str| -> Line {
                    let v = cp.get(k).or_else(|| cp.get("fo:border")).unwrap_or("none");
                    border_line(v)
                };
                let mut text = self
                    .text(c, &cp, None, scope, ctx, true, budget)?
                    .unwrap_or_default();
                let pad = |k: &str| {
                    cp.len(k)
                        .or_else(|| cp.len("fo:padding"))
                        .unwrap_or(91440 / 2)
                        .max(0)
                };
                text.body.insets = [
                    pad("fo:padding-left"),
                    pad("fo:padding-top"),
                    pad("fo:padding-right"),
                    pad("fo:padding-bottom"),
                ];
                text.body.anchor = match cp.get("style:vertical-align") {
                    Some("middle") => "ctr",
                    Some("bottom") => "b",
                    _ => "t",
                };
                let span = |k: &str| {
                    c.attr(k)
                        .and_then(|v| v.parse::<u32>().ok())
                        .unwrap_or(1)
                        .clamp(1, 1000)
                };
                cells.push(Cell {
                    text,
                    fill,
                    borders: [
                        border("fo:border-left"),
                        border("fo:border-right"),
                        border("fo:border-top"),
                        border("fo:border-bottom"),
                    ],
                    grid_span: span("table:number-columns-spanned"),
                    row_span: span("table:number-rows-spanned"),
                    h_merge: covered,
                    v_merge: false,
                });
            }
            rows.push(Row { h, cells });
        }
        if rows.is_empty() {
            return Ok(None);
        }
        let n = rows
            .iter()
            .map(|r| r.cells.len())
            .max()
            .unwrap_or(0)
            .max(cols.len());
        if cols.len() < n {
            cols.resize(n, 0);
        }
        // Widths and heights left out share the frame's.
        let known: Emu = cols.iter().sum();
        let unknown = cols.iter().filter(|&&w| w == 0).count() as Emu;
        if unknown > 0 {
            let each = ((xf.w - known).max(0) / unknown).max(91440);
            for w in &mut cols {
                if *w == 0 {
                    *w = each;
                }
            }
        }
        let nrows = rows.len() as Emu;
        for r in &mut rows {
            if r.h == 0 {
                r.h = (xf.h / nrows).max(91440);
            }
        }
        // A covered cell below a spanning one merges vertically.
        let spans: Vec<Vec<(u32, u32)>> = rows
            .iter()
            .map(|r| r.cells.iter().map(|c| (c.grid_span, c.row_span)).collect())
            .collect();
        for (ri, row) in spans.iter().enumerate() {
            for (ci, &(_, rs)) in row.iter().enumerate() {
                for k in 1..rs as usize {
                    if let Some(c) = rows.get_mut(ri + k).and_then(|r| r.cells.get_mut(ci)) {
                        c.v_merge = true;
                        c.h_merge = false;
                    }
                }
            }
        }
        Ok(Some(Table { cols, rows }))
    }
}

/// An ODF angle with or without its unit, in degrees.
fn angle_deg(s: &str) -> f64 {
    let s = s.trim();
    let v = |t: &str| t.trim().parse::<f64>().unwrap_or(0.0);
    if let Some(r) = s.strip_suffix("rad") {
        v(r).to_degrees()
    } else if let Some(g) = s.strip_suffix("grad") {
        v(g) * 0.9
    } else {
        v(s.trim_end_matches("deg"))
    }
}

/// Gradient and hatch angles: tenths of a degree without a unit.
fn angle_tenths(s: &str) -> f64 {
    let t = s.trim();
    if t.ends_with("deg") || t.ends_with("rad") || t.ends_with("grad") {
        angle_deg(t)
    } else {
        t.parse::<f64>().unwrap_or(0.0) / 10.0
    }
}

fn gradient(g: &Props, alpha: Option<u32>) -> Fill {
    let intensity = |c: Rgb, k: &str| {
        let f = g.get(k).and_then(percent).unwrap_or(1.0).clamp(0.0, 1.0);
        let ch = |s: u32| (((c >> s) & 0xFF) as f64 * f).round() as u32;
        ch(16) << 16 | ch(8) << 8 | ch(0)
    };
    let start = Color {
        rgb: intensity(
            g.color("draw:start-color").unwrap_or(0),
            "draw:start-intensity",
        ),
        alpha,
    };
    let end = Color {
        rgb: intensity(
            g.color("draw:end-color").unwrap_or(0xFFFFFF),
            "draw:end-intensity",
        ),
        alpha,
    };
    let border = (g
        .get("draw:border")
        .and_then(percent)
        .unwrap_or(0.0)
        .clamp(0.0, 1.0)
        * 100_000.0) as u32;
    let angle = g.get("draw:angle").map(angle_tenths).unwrap_or(0.0);
    let cx = g
        .get("draw:cx")
        .and_then(percent)
        .unwrap_or(0.5)
        .clamp(0.0, 1.0);
    let cy = g
        .get("draw:cy")
        .and_then(percent)
        .unwrap_or(0.5)
        .clamp(0.0, 1.0);
    let focus = [
        (cx * 100_000.0) as i32,
        (cy * 100_000.0) as i32,
        ((1.0 - cx) * 100_000.0) as i32,
        ((1.0 - cy) * 100_000.0) as i32,
    ];
    let (stops, kind) = match g.get("draw:style").unwrap_or("linear") {
        "axial" => (
            vec![
                (0, end),
                (border / 2, end),
                (50_000, start),
                (100_000 - border / 2, end),
                (100_000, end),
            ],
            GradientKind::Linear((90.0 - angle).rem_euclid(360.0)),
        ),
        "radial" | "ellipsoid" => (
            vec![(0, end), (100_000 - border, start), (100_000, start)],
            GradientKind::Path("circle", focus),
        ),
        "square" | "rectangular" => (
            vec![(0, end), (100_000 - border, start), (100_000, start)],
            GradientKind::Path("rect", focus),
        ),
        _ => (
            vec![(0, start), (border, start), (100_000, end)],
            GradientKind::Linear((90.0 - angle).rem_euclid(360.0)),
        ),
    };
    let mut stops = stops;
    stops.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    Fill::Gradient(Gradient { stops, kind })
}

fn dash_preset(d: Option<&Props>) -> &'static str {
    let Some(d) = d else { return "dash" };
    let n = |k: &str| d.get(k).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let l = |k: &str| {
        d.get(k)
            .map(|v| {
                percent(v)
                    .map(|f| f * 100.0)
                    .unwrap_or_else(|| len(v).unwrap_or(0) as f64 / 3600.0)
            })
            .unwrap_or(0.0)
    };
    let (d1, d2) = (n("draw:dots1"), n("draw:dots2"));
    let (l1, l2) = (l("draw:dots1-length"), l("draw:dots2-length"));
    let short = |v: f64| v <= 0.0 || v < 60.0;
    match (d1 > 0, d2 > 0) {
        (true, true) if short(l1) != short(l2) => {
            if d1.max(d2) > 1 {
                "sysDashDotDot"
            } else {
                "dashDot"
            }
        }
        (true, true) | (true, false) | (false, true) => {
            let lenv = l1.max(l2);
            if short(lenv) {
                "sysDot"
            } else if lenv > 300.0 {
                "lgDash"
            } else {
                "dash"
            }
        }
        _ => "dash",
    }
}

/// A table cell border ("0.5pt solid #000000").
fn border_line(v: &str) -> Line {
    let v = v.trim();
    if v == "none" || v.is_empty() || v == "hidden" {
        return Line::default();
    }
    let mut width = 9525;
    let mut rgb = 0;
    let mut dash = None;
    for t in v.split_whitespace() {
        if let Some(w) = len(t) {
            width = w.max(0);
        } else if let Some(c) = color(t) {
            rgb = c;
        } else if t == "dashed" {
            dash = Some("dash");
        } else if t == "dotted" {
            dash = Some("sysDot");
        }
    }
    Line {
        fill: Fill::Solid(Color::rgb(rgb)),
        width,
        dash,
        ..Line::default()
    }
}

fn ooxml_preset(name: &str) -> &'static str {
    const NAMES: &[&str] = &[
        "rect",
        "roundRect",
        "ellipse",
        "triangle",
        "rtTriangle",
        "diamond",
        "parallelogram",
        "trapezoid",
        "pentagon",
        "hexagon",
        "heptagon",
        "octagon",
        "decagon",
        "dodecagon",
        "star4",
        "star5",
        "star6",
        "star7",
        "star8",
        "star10",
        "star12",
        "star16",
        "star24",
        "star32",
        "rightArrow",
        "leftArrow",
        "upArrow",
        "downArrow",
        "leftRightArrow",
        "upDownArrow",
        "chevron",
        "homePlate",
        "plus",
        "can",
        "cube",
        "donut",
        "heart",
        "smileyFace",
        "sun",
        "moon",
        "cloud",
        "frame",
        "plaque",
        "bevel",
        "foldedCorner",
        "flowChartProcess",
        "flowChartDecision",
        "flowChartTerminator",
        "wave",
        "doubleWave",
        "snip1Rect",
        "snip2SameRect",
        "round1Rect",
        "round2SameRect",
        "teardrop",
        "pie",
        "chord",
        "arc",
        "blockArc",
        "lightningBolt",
        "noSmoking",
    ];
    NAMES.iter().copied().find(|n| *n == name).unwrap_or("rect")
}

/// The box around shapes.
fn bounds(shapes: &[Shape]) -> Xfrm {
    let mut x0 = i64::MAX;
    let mut y0 = i64::MAX;
    let mut x1 = i64::MIN;
    let mut y1 = i64::MIN;
    for s in shapes {
        x0 = x0.min(s.xfrm.x);
        y0 = y0.min(s.xfrm.y);
        x1 = x1.max(s.xfrm.x + s.xfrm.w);
        y1 = y1.max(s.xfrm.y + s.xfrm.h);
    }
    Xfrm {
        x: x0,
        y: y0,
        w: (x1 - x0).max(1),
        h: (y1 - y0).max(1),
        ..Xfrm::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_transform_to_box_and_angle() {
        let x = br#"<draw:rect xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" svg:width="2cm" svg:height="1cm" draw:transform="rotate (1.5707963267949) translate (5cm 5cm)"/>"#;
        let n = xml::parse(x, &mut xml::within(1 << 20)).unwrap();
        let xf = transform(&n);
        // Turned a quarter counterclockwise about its top left at (5, 5):
        // it covers x 5..6, y 3..5 (cm); its own box is centred there.
        assert_eq!((xf.w, xf.h), (720_000, 360_000));
        assert!((xf.rot - 270.0).abs() < 1e-6);
        assert_eq!((xf.x + xf.w / 2, xf.y + xf.h / 2), (1_980_000, 1_440_000));
    }
}
