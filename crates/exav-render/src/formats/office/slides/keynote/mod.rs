//! Apple Keynote documents of Keynote 6 (2013) and later: a ZIP, or a
//! package directory, of `Index/*.iwa` streams (in Keynote 6, inside a
//! nested `Index.zip`) holding protocol buffer archives, and of `Data/`
//! files for pictures. Messages are read by field number; the numbers used
//! are written where they are read, after the message definitions
//! keynote-parser (MIT, Peter Sobot) extracted from the application.
//!
//! KN.DocumentArchive (object 1): show 2. KN.ShowArchive: slideTree 3,
//! size 4, slideNumbersVisible 6. KN.SlideTreeArchive: rootSlideNode 1,
//! slides 2. KN.SlideNodeArchive: children 1, slide 2, isSkipped 4.
//! KN.SlideArchive: style 1, titlePlaceholder 5, bodyPlaceholder 6,
//! owned_drawables 7, template_slide 17, slideNumberPlaceholder 20,
//! drawables_z_order 42.

mod apxl;
mod apxl1;
mod chart;
mod shapes;
mod table;
mod text;

use crate::formats::office::common::iwa::Store;
use crate::formats::office::common::iwa::proto::Msg;
use crate::formats::office::slides::error::{Error, Result};
use crate::formats::office::slides::limits::Budget;
use crate::formats::office::slides::model::*;
use crate::formats::office::slides::package::Zip;
use std::collections::HashMap;

/// Message types ([keynote-parser]'s registry).
pub(crate) mod ty {
    pub const DOCUMENT: u32 = 1;
    pub const SHOW: u32 = 2;
    pub const SLIDE_NODE: u32 = 4;
    pub const SLIDE: u32 = 5;
    pub const PLACEHOLDER: u32 = 7;
    pub const SLIDE_STYLE: u32 = 9;
    pub const STORAGE: u32 = 2001;
    pub const STORAGE_2: u32 = 2005;
    pub const SHAPE_INFO: u32 = 2011;
    pub const CHARACTER_STYLE: u32 = 2021;
    pub const PARAGRAPH_STYLE: u32 = 2022;
    pub const LIST_STYLE: u32 = 2023;
    pub const TEXT_SHAPE_STYLE: u32 = 2025;
    pub const SHAPE: u32 = 3004;
    pub const IMAGE: u32 = 3005;
    pub const MOVIE: u32 = 3007;
    pub const GROUP: u32 = 3008;
    pub const CONNECTION_LINE: u32 = 3009;
    pub const SHAPE_STYLE: u32 = 3015;
    pub const MEDIA_STYLE: u32 = 3016;
    pub const TABLE_INFO: u32 = 6000;
    pub const CHART: u32 = 5021;
    pub const PACKAGE_METADATA: u32 = 11006;
}

/// Reads a document saved as one file.
pub(crate) fn read(z: Result<Zip>, budget: &mut Budget) -> Result<Presentation> {
    let mut z = z.map_err(|_| {
        Error::NotFormat("not a ZIP package (a Keynote document saved as a package directory must be read file by file)".into())
    })?;
    let names = z.names();
    check_kind(&names.iter().map(String::as_str).collect::<Vec<_>>())?;
    if let Some(name) = xml_member(names.iter().map(String::as_str)) {
        let name = name.to_string();
        let max = budget.limits.max_part;
        let data = z.get(&name, max, budget)?.unwrap_or_default();
        let xml = unzip_xml(&name, data, budget)?;
        return read_xml(&xml, apxl::Pkg::Zip(z, base_of(&name)), budget);
    }
    let max = budget.limits.max_part;
    let mut files: Vec<(String, Vec<u8>)> = vec![];
    if let Some(inner) = names.iter().find(|n| leaf(n) == "index.zip") {
        let data = z.get(inner, max, budget)?.unwrap_or_default();
        let mut iz = Zip::open(&data)?;
        for n in iz.names() {
            if n.ends_with(".iwa")
                && let Some(d) = iz.get(&n, max, budget)?
            {
                files.push((n, d));
            }
        }
    }
    for n in &names {
        if n.ends_with(".iwa")
            && let Some(d) = z.get(n, max, budget)?
        {
            files.push((n.clone(), d));
        }
    }
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    // Pictures are read when a slide uses them.
    let members: Vec<&str> = names
        .iter()
        .filter(|n| n.contains("Data/") && !n.ends_with('/'))
        .map(String::as_str)
        .collect();
    read_files(&refs, &members, Some(z), budget)
}

/// Whether `input` is a Keynote 1 to 5 XML document on its own (an
/// `.apxl` file), gzipped or not, rather than a package.
pub(crate) fn is_bare_xml(input: &[u8]) -> bool {
    let head = input.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(input);
    input.starts_with(&[0x1F, 0x8B])
        || head.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'<')
}

/// Reads an `.apxl` file.
pub(crate) fn read_bare(input: &[u8], budget: &mut Budget) -> Result<Presentation> {
    budget.alloc(input.len() as u64)?;
    let xml = unzip_xml("", input.to_vec(), budget)?;
    read_xml(&xml, apxl::Pkg::None, budget)
}

/// Reads a package directory given as its files.
pub(crate) fn read_package(files: &[(&str, &[u8])], budget: &mut Budget) -> Result<Presentation> {
    let names: Vec<&str> = files.iter().map(|f| f.0).collect();
    check_kind(&names)?;
    if let Some(name) = xml_member(names.iter().copied()) {
        let data = files
            .iter()
            .find(|f| f.0 == name)
            .map(|f| f.1.to_vec())
            .unwrap_or_default();
        budget.alloc(data.len() as u64)?;
        let xml = unzip_xml(name, data, budget)?;
        return read_xml(&xml, apxl::Pkg::Files(files, base_of(name)), budget);
    }
    let mut all: Vec<(String, Vec<u8>)> = vec![];
    if let Some((_, data)) = files.iter().find(|f| leaf(f.0) == "index.zip") {
        let max = budget.limits.max_part;
        let mut iz = Zip::open(data)?;
        for n in iz.names() {
            if n.ends_with(".iwa")
                && let Some(d) = iz.get(&n, max, budget)?
            {
                all.push((n, d));
            }
        }
    }
    let mut refs: Vec<(&str, &[u8])> = files.to_vec();
    refs.extend(all.iter().map(|(n, d)| (n.as_str(), d.as_slice())));
    read_files(&refs, &[], None, budget)
}

/// The directory of a package member, with its trailing "/".
fn base_of(name: &str) -> String {
    name.rfind('/')
        .map_or(String::new(), |i| name[..=i].to_string())
}

fn leaf(name: &str) -> String {
    name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase()
}

fn check_kind(names: &[&str]) -> Result<()> {
    if names
        .iter()
        .any(|n| matches!(leaf(n).as_str(), ".iwpv2" | ".iwph"))
    {
        return Err(Error::Encrypted);
    }
    Ok(())
}

/// The XML document of a Keynote 1 to 5 package: `index.apxl` or
/// `presentation.apxl`, gzipped or not, the one nearest the root.
fn xml_member<'n>(names: impl Iterator<Item = &'n str>) -> Option<&'n str> {
    names
        .filter(|n| {
            matches!(
                leaf(n).as_str(),
                "index.apxl" | "index.apxl.gz" | "presentation.apxl" | "presentation.apxl.gz"
            )
        })
        .min_by_key(|n| n.matches('/').count())
}

/// The XML of a member: gunzipped when it is, within `max_part`.
fn unzip_xml(name: &str, data: Vec<u8>, budget: &mut Budget) -> Result<Vec<u8>> {
    if !(name.ends_with(".gz") || data.starts_with(&[0x1F, 0x8B])) {
        return Ok(data);
    }
    use std::io::Read;
    let max = budget.limits.max_part;
    let mut out = vec![];
    let n = flate2::read::MultiGzDecoder::new(&data[..])
        .take(max + 1)
        .read_to_end(&mut out)
        .map_err(|e| Error::Malformed(format!("gzip: {e}")))?;
    if n as u64 > max {
        return Err(Error::TooLarge("a package part"));
    }
    budget.alloc(n as u64)?;
    Ok(out)
}

/// Reads a Keynote 1 to 5 document from its XML.
pub(crate) fn read_xml<'a>(
    xml: &[u8],
    pkg: apxl::Pkg<'a>,
    budget: &mut Budget,
) -> Result<Presentation> {
    let root = crate::formats::office::common::xml::parse(xml, &mut budget.tree())?;
    match root.name.as_str() {
        "key:presentation" => apxl::read(&root, pkg, budget),
        "presentation" => apxl1::read(&root, pkg, budget),
        _ => Err(Error::NotFormat("not a Keynote document".into())),
    }
}

/// A file of `Data/`: its bytes, or its name in the package, read when a
/// slide uses it.
#[derive(Clone, Copy)]
pub(crate) enum DataFile<'a> {
    Bytes(&'a [u8]),
    Member(&'a str),
}

/// Reads the `.iwa` streams and `Data/` files of `files`, and the `Data/`
/// files `members` names in `zip`.
fn read_files<'a>(
    files: &[(&'a str, &'a [u8])],
    members: &[&'a str],
    zip: Option<Zip<'a>>,
    budget: &mut Budget,
) -> Result<Presentation> {
    let mut store = Store::default();
    let mut data: HashMap<String, DataFile<'a>> = HashMap::new();
    for &(name, d) in files {
        if name.ends_with(".iwa") {
            let left = budget.limits.max_part.min(budget.limits.max_memory) as usize;
            let used = store.add(d, left);
            budget.alloc(used as u64 * 2)?;
        } else if let Some(i) = name.find("Data/") {
            data.insert(name[i + 5..].to_string(), DataFile::Bytes(d));
        }
    }
    for &name in members {
        if let Some(i) = name.find("Data/") {
            data.insert(name[i + 5..].to_string(), DataFile::Member(name));
        }
    }
    let doc = store
        .typed(1, ty::DOCUMENT)
        .or_else(|| {
            store
                .ids_of(ty::DOCUMENT)
                .first()
                .and_then(|&i| store.typed(i, ty::DOCUMENT))
        })
        .ok_or_else(|| {
            Error::NotFormat(
                "no Keynote document object (not a Keynote file, or a damaged one)".into(),
            )
        })?;
    let mut r = Reader {
        store: &store,
        data: datas(&store, &data),
        zip,
        failed: None,
        media: HashMap::new(),
        p: Presentation::default(),
        masters: HashMap::new(),
    };
    r.convert(doc, budget)?;
    Ok(r.p)
}

/// Data identifiers to their files, from the package metadata.
fn datas<'a>(store: &Store, files: &HashMap<String, DataFile<'a>>) -> HashMap<u64, DataFile<'a>> {
    let mut out = HashMap::new();
    for id in store.ids_of(ty::PACKAGE_METADATA) {
        let Some(m) = store.typed(id, ty::PACKAGE_METADATA) else {
            continue;
        };
        for d in m.msgs(4).take(1 << 16) {
            let Some(ident) = d.uint(1) else { continue };
            let names = [d.string(4), d.string(3)];
            for n in names.into_iter().flatten() {
                if let Some(f) = files.get(&n) {
                    out.insert(ident, *f);
                    break;
                }
                // Files are saved as "name-<identifier>.ext".
                let (stem, ext) = n.rsplit_once('.').unwrap_or((&n, ""));
                let alt = if ext.is_empty() {
                    format!("{stem}-{ident}")
                } else {
                    format!("{stem}-{ident}.{ext}")
                };
                if let Some(f) = files.get(&alt) {
                    out.insert(ident, *f);
                    break;
                }
            }
        }
    }
    out
}

/// Which properties message of a style.
#[derive(Clone, Copy)]
pub(crate) enum Props {
    /// TSD.ShapeStylePropertiesArchive: fill 1, stroke 2, opacity 3,
    /// shadow 4 (TSD.MediaStylePropertiesArchive: stroke 1, opacity 2,
    /// shadow 3).
    Shape,
    Media,
    /// TSWP.ShapeStylePropertiesArchive: shrink_to_fit 1,
    /// vertical_alignment 2, padding 6, paragraph_style 10.
    Text,
    /// KN.SlideStylePropertiesArchive.
    Slide,
    /// TSWP.CharacterStylePropertiesArchive of a character or paragraph
    /// style.
    Char,
    /// TSWP.ParagraphStylePropertiesArchive.
    Para,
}

impl Props {
    fn of<'a>(self, kind: u32, m: Msg<'a>) -> Option<Msg<'a>> {
        match (self, kind) {
            (Props::Shape, ty::SHAPE_STYLE) => m.msg(11),
            (Props::Shape, ty::TEXT_SHAPE_STYLE) => m.msg(1)?.msg(11),
            (Props::Media, ty::MEDIA_STYLE) => m.msg(11),
            (Props::Text, ty::TEXT_SHAPE_STYLE) => m.msg(11),
            (Props::Slide, ty::SLIDE_STYLE) => m.msg(11),
            (Props::Char, ty::CHARACTER_STYLE | ty::PARAGRAPH_STYLE) => m.msg(11),
            (Props::Para, ty::PARAGRAPH_STYLE) => m.msg(12),
            _ => None,
        }
    }
}

pub(crate) struct Reader<'a> {
    pub store: &'a Store,
    pub data: HashMap<u64, DataFile<'a>>,
    /// The package the `Data/` members are read from.
    zip: Option<Zip<'a>>,
    /// A picture the package could not give within the limits, raised
    /// after the slide that wanted it.
    failed: Option<Error>,
    pub media: HashMap<u64, Option<usize>>,
    pub p: Presentation,
    /// Template slides to their master's index.
    masters: HashMap<u64, usize>,
}

impl<'a> Reader<'a> {
    /// An image's media index, by data identifier.
    pub fn image(&mut self, id: u64) -> Option<usize> {
        if let Some(&m) = self.media.get(&id) {
            return m;
        }
        let bytes = match self.data.get(&id).copied() {
            Some(DataFile::Bytes(d)) => Some(d.to_vec()),
            Some(DataFile::Member(name)) => {
                let read = self.zip.as_mut().map(|z| z.read(name, 64 << 20));
                match read {
                    Some(Ok(d)) => d,
                    Some(Err(e)) => {
                        self.failed.get_or_insert(e);
                        None
                    }
                    None => None,
                }
            }
            None => None,
        };
        let m = bytes.and_then(|d| {
            let ext = crate::formats::office::slides::package::image_ext(&d)?;
            Some(self.p.add_media(ext, d))
        });
        self.media.insert(id, m);
        m
    }

    fn convert(&mut self, doc: Msg<'a>, budget: &mut Budget) -> Result<()> {
        let show = doc
            .reference(2)
            .and_then(|id| self.store.typed(id, ty::SHOW))
            .ok_or_else(|| Error::Malformed("no show".into()))?;
        let (w, h) = show
            .msg(4)
            .map(|s| (s.float(1).unwrap_or(1024.0), s.float(2).unwrap_or(768.0)))
            .unwrap_or((1024.0, 768.0));
        self.p.width = (f64::from(w) * 12700.0).round() as Emu;
        self.p.height = (f64::from(h) * 12700.0).round() as Emu;
        let numbers = show.boolean(6).unwrap_or(false);
        // The slides in order: the tree's list, else its root's children.
        let mut nodes: Vec<u64> = vec![];
        if let Some(tree) = show.msg(3) {
            nodes.extend(tree.references(2).take(100_000));
            if nodes.is_empty()
                && let Some(root) = tree.reference(1)
            {
                self.walk_nodes(root, &mut nodes, 0);
            }
        }
        let mut n = 0usize;
        for node_id in nodes {
            let Some(node) = self.store.typed(node_id, ty::SLIDE_NODE) else {
                continue;
            };
            let Some(slide_id) = node.reference(2) else {
                continue;
            };
            let Some((kind, slide)) = self.store.get(slide_id) else {
                continue;
            };
            if kind != ty::SLIDE {
                continue;
            }
            budget.slide(n)?;
            n += 1;
            self.p.total_slides = n;
            if !budget.wants(n - 1) {
                continue;
            }
            let skipped = node.boolean(4).unwrap_or(false);
            let s = self.slide(slide, n, numbers, skipped, budget)?;
            self.p.slides.push(s);
            if let Some(e) = self.failed.take() {
                return Err(e);
            }
        }
        if let Some(e) = self.failed.take() {
            return Err(e);
        }
        if self.p.masters.is_empty() {
            self.p.masters.push(Master::default());
        }
        Ok(())
    }

    fn walk_nodes(&self, id: u64, out: &mut Vec<u64>, depth: u32) {
        if depth > 64 || out.len() > 100_000 {
            return;
        }
        let Some(node) = self.store.typed(id, ty::SLIDE_NODE) else {
            return;
        };
        for c in node.references(1) {
            out.push(c);
            self.walk_nodes(c, out, depth + 1);
        }
    }

    /// A slide's background, through its style's parents.
    fn background(&mut self, style: Option<u64>) -> Option<Fill> {
        let props = self.find(style, Props::Slide, |p| p.msg(1))?;
        Some(shapes::fill(self, props))
    }

    /// A style and its parents (TSS.StyleArchive parent 3, in the style's
    /// super, which a text shape style nests one level deeper).
    pub fn chain(&self, style: Option<u64>) -> Vec<(u32, Msg<'a>)> {
        let mut out = vec![];
        let mut cur = style;
        while let Some(id) = cur {
            if out.len() >= 32 {
                break;
            }
            let Some((k, m)) = self.store.get(id) else {
                break;
            };
            out.push((k, m));
            let tss = if k == ty::TEXT_SHAPE_STYLE {
                m.msg(1).and_then(|s| s.msg(1))
            } else {
                m.msg(1)
            };
            cur = tss.and_then(|s| s.reference(3)).filter(|&p| p != id);
        }
        out
    }

    /// The first value `get` finds in the properties `which` of a style or
    /// of its nearest parent.
    pub fn find<T>(
        &self,
        style: Option<u64>,
        which: Props,
        get: impl Fn(Msg<'a>) -> Option<T>,
    ) -> Option<T> {
        self.chain(style)
            .into_iter()
            .find_map(|(k, m)| which.of(k, m).and_then(&get))
    }

    fn slide_flag(&self, style: Option<u64>, field: u32) -> Option<bool> {
        self.find(style, Props::Slide, |p| p.boolean(field))
    }

    fn master(&mut self, template: u64, budget: &mut Budget) -> Result<usize> {
        if let Some(&i) = self.masters.get(&template) {
            return Ok(i);
        }
        let mut m = Master {
            name: "Master".into(),
            layouts: vec![Layout {
                name: "Blank".into(),
                kind: "blank",
                show_master_shapes: true,
                ..Layout::default()
            }],
            ..Master::default()
        };
        if let Some((_, t)) = self.store.get(template) {
            m.background = self
                .background(t.reference(1))
                .or(Some(Fill::Solid(Color::rgb(0xFFFFFF))));
            m.name = t.string(10).unwrap_or_else(|| "Master".into());
            let placeholders: Vec<u64> = [5u32, 6, 20, 30]
                .iter()
                .filter_map(|&f| t.reference(f))
                .collect();
            let order: Vec<u64> = {
                let z: Vec<u64> = t.references(42).collect();
                if z.is_empty() {
                    t.references(7).collect()
                } else {
                    z
                }
            };
            for id in order.into_iter().take(10_000) {
                if placeholders.contains(&id) {
                    continue;
                }
                if let Some(s) = shapes::drawable(self, id, 1, budget, 0)? {
                    m.shapes.push(s);
                }
            }
        }
        let i = self.p.masters.len();
        self.p.masters.push(m);
        self.masters.insert(template, i);
        Ok(i)
    }

    fn slide(
        &mut self,
        s: Msg<'a>,
        number: usize,
        numbers: bool,
        skipped: bool,
        budget: &mut Budget,
    ) -> Result<Slide> {
        let style = s.reference(1);
        let mi = match s.reference(17) {
            Some(t) => self.master(t, budget)?,
            None => {
                if self.p.masters.is_empty() {
                    self.p.masters.push(Master::default());
                }
                0
            }
        };
        let background = self.background(style);
        let title_visible = self.slide_flag(style, 4).unwrap_or(true);
        let body_visible = self.slide_flag(style, 5).unwrap_or(true);
        let number_visible = self.slide_flag(style, 6).unwrap_or(numbers);
        let (title, body, num) = (s.reference(5), s.reference(6), s.reference(20));
        let mut order: Vec<u64> = s.references(42).collect();
        if order.is_empty() {
            order = s.references(7).collect();
            // Placeholders first, under the slide's own drawables.
            for p in [num, body, title].into_iter().flatten() {
                if !order.contains(&p) {
                    order.insert(0, p);
                }
            }
        }
        let mut out = vec![];
        for id in order.into_iter().take(10_000) {
            let visible = if Some(id) == title {
                title_visible
            } else if Some(id) == body {
                body_visible
            } else if Some(id) == num {
                number_visible
            } else {
                true
            };
            if !visible {
                continue;
            }
            if let Some(sh) = shapes::drawable(self, id, number, budget, 0)? {
                out.push(sh);
            }
        }
        Ok(Slide {
            name: None,
            master: mi,
            layout: 0,
            background,
            shapes: out,
            hidden: skipped,
            show_master_shapes: true,
        })
    }
}
