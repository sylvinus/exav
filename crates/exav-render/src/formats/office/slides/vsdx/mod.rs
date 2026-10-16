//! Visio drawings (.vsdx, .vsdm, .vstx, .vstm): an Open Packaging
//! Conventions package of XML parts ([MS-VSDX], and the Visio file format
//! reference). Each foreground page becomes a slide named as the page is, in
//! the pages' largest size; a background page becomes the master of the
//! pages that use it. Written from those specifications and sample files.

mod convert;
mod format;
mod formula;
mod geom;
mod resolve;
mod sheet;
mod text;

use crate::formats::office::common::cfb::Compound;
use crate::formats::office::common::xml::{self, Node};
use crate::formats::office::slides::error::{Error, Result};
use crate::formats::office::slides::limits::Budget;
use crate::formats::office::slides::model::*;
use crate::formats::office::slides::package::{Source, Zip};
use resolve::{Doc, Master as MasterPart};
use sheet::{local, Rels, Sheet};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

const CFB_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// The size of a page that does not give one: letter, landscape.
const DEFAULT_PAGE: (f64, f64) = (11.0, 8.5);

/// A package read from bytes. A compound file is a password protected
/// package (or a binary drawing, which is not read).
pub(crate) fn read_bytes(input: &[u8], budget: &mut Budget) -> Result<Presentation> {
    if input.starts_with(&CFB_SIGNATURE) {
        return Err(compound(input));
    }
    read(Zip::open(input)?, budget)
}

/// A package read part by part from `source`.
pub(crate) fn read_source(
    mut source: Box<dyn Source + '_>,
    budget: &mut Budget,
) -> Result<Presentation> {
    let mut head = [0u8; 8];
    let got = source
        .seek(SeekFrom::Start(0))
        .and_then(|_| source.read(&mut head))
        .map_err(|e| Error::Malformed(format!("the source: {e}")))?;
    if got == 8 && head == CFB_SIGNATURE {
        let mut bytes = vec![];
        source
            .seek(SeekFrom::Start(0))
            .and_then(|_| source.read_to_end(&mut bytes))
            .map_err(|e| Error::Malformed(format!("the source: {e}")))?;
        return Err(compound(&bytes));
    }
    read(Zip::from_source(source)?, budget)
}

fn compound(bytes: &[u8]) -> Error {
    let encrypted = Compound::open(bytes).is_some_and(|c| {
        c.names()
            .any(|n| n.eq_ignore_ascii_case("EncryptedPackage"))
    });
    if encrypted {
        Error::Encrypted
    } else {
        Error::NotFormat("a compound file, not a Visio package (binary .vsd is not read)".into())
    }
}

/// A relationship of a part: its type and the part it leads to.
struct Rel {
    id: String,
    kind: String,
    target: String,
}

/// The package path `target` names from the part in directory `dir`.
fn resolve(dir: &str, target: &str) -> String {
    let target = target.split('#').next().unwrap_or("");
    let mut parts: Vec<&str> = if target.starts_with('/') {
        vec![]
    } else {
        dir.split('/').filter(|s| !s.is_empty()).collect()
    };
    for seg in target.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

fn dir_of(part: &str) -> &str {
    part.rsplit_once('/').map_or("", |(d, _)| d)
}

fn parse_part(bytes: &[u8], budget: &mut Budget) -> Result<Node> {
    budget.alloc(bytes.len() as u64 * 3)?;
    Ok(xml::parse(bytes, xml::MAX_ELEMENTS)?)
}

/// The relationships of `part` ("" for the package).
fn rels_of(z: &mut Zip, part: &str, budget: &mut Budget) -> Result<Vec<Rel>> {
    let path = if part.is_empty() {
        "_rels/.rels".to_string()
    } else {
        let (d, n) = part.rsplit_once('/').unwrap_or(("", part));
        if d.is_empty() {
            format!("_rels/{n}.rels")
        } else {
            format!("{d}/_rels/{n}.rels")
        }
    };
    let max = budget.limits.max_part;
    let Some(bytes) = z.get(&path, max, budget)? else {
        // A member the archive lists and cannot give is encrypted.
        if z.names().contains(&path) {
            return Err(Error::Encrypted);
        }
        return Ok(vec![]);
    };
    let n = parse_part(&bytes, budget)?;
    let dir = dir_of(part);
    Ok(n.nodes()
        .filter(|r| local(&r.name) == "Relationship" && r.attr("TargetMode") != Some("External"))
        .take(1 << 16)
        .filter_map(|r| {
            Some(Rel {
                id: r.attr("Id")?.to_string(),
                kind: r.attr("Type").unwrap_or("").to_string(),
                target: resolve(dir, r.attr("Target")?),
            })
        })
        .collect())
}

fn by_id(rels: &[Rel]) -> HashMap<String, String> {
    rels.iter()
        .map(|r| (r.id.clone(), r.target.clone()))
        .collect()
}

fn of_kind<'a>(rels: &'a [Rel], suffix: &str) -> Option<&'a str> {
    rels.iter()
        .find(|r| r.kind.ends_with(suffix))
        .map(|r| r.target.as_str())
}

fn find_local<'a>(n: &'a Node, name: &str) -> Option<&'a Node> {
    let mut stack = vec![n];
    let mut seen = 0usize;
    while let Some(c) = stack.pop() {
        seen += 1;
        if seen > 100_000 {
            return None;
        }
        if local(&c.name) == name {
            return Some(c);
        }
        stack.extend(c.nodes());
    }
    None
}

/// The colour a theme element holds: its first child's `val`, or `lastClr`
/// of a system colour.
fn theme_rgb(n: &Node) -> Option<u32> {
    let c = n.nodes().next()?;
    let v = c.attr("val").or(c.attr("lastClr"))?;
    u32::from_str_radix(v.trim(), 16).ok()
}

/// The fonts and colours of a theme part.
fn read_theme(n: &Node, doc: &mut Doc) {
    let face = |kind: &str| {
        find_local(n, kind)
            .and_then(|f| f.nodes().find(|l| local(&l.name) == "latin"))
            .and_then(|l| l.attr("typeface"))
            .filter(|t| !t.is_empty())
            .map(str::to_string)
    };
    doc.major_font = face("majorFont");
    doc.minor_font = face("minorFont");
    if let Some(cs) = find_local(n, "clrScheme") {
        for name in [
            "dk1", "lt1", "accent1", "accent2", "accent3", "accent4", "accent5", "accent6",
        ] {
            let c = cs
                .nodes()
                .find(|c| local(&c.name) == name)
                .and_then(theme_rgb)
                .unwrap_or(0);
            doc.theme.scheme.push(c);
        }
    }
    doc.theme.background = find_local(n, "bkgnd").and_then(theme_rgb);
    if let Some(list) = find_local(n, "variationClrSchemeLst") {
        for v in list
            .nodes()
            .filter(|v| local(&v.name) == "variationClrScheme")
            .take(64)
        {
            doc.theme
                .variations
                .push(v.nodes().filter_map(theme_rgb).collect());
        }
    }
}

fn read_doc(n: &Node, budget: &mut Budget) -> Result<Doc> {
    let mut d = Doc::default();
    let empty = HashMap::new();
    let mut count = 0usize;
    for c in n.nodes() {
        match local(&c.name) {
            "Colors" => {
                for e in c.nodes().filter(|e| local(&e.name) == "ColorEntry") {
                    let ix = e.attr("IX").and_then(|v| v.trim().parse::<u32>().ok());
                    let rgb = e
                        .attr("RGB")
                        .and_then(|v| v.trim().strip_prefix('#'))
                        .and_then(|h| u32::from_str_radix(h, 16).ok());
                    if let (Some(ix), Some(rgb)) = (ix, rgb) {
                        d.colors.insert(ix, rgb);
                    }
                }
            }
            "FaceNames" => {
                for f in c
                    .nodes()
                    .filter(|f| local(&f.name) == "FaceName")
                    .take(65_536)
                {
                    d.faces
                        .push(f.attr("NameU").or(f.attr("Name")).unwrap_or("").to_string());
                }
            }
            "StyleSheets" => {
                for s in c.nodes().filter(|s| local(&s.name) == "StyleSheet") {
                    let sheet = sheet::parse(s, &Rels(&empty), &mut count, 0);
                    d.styles.insert(sheet.id, sheet);
                }
            }
            _ => {}
        }
    }
    budget.alloc(count as u64 * 512)?;
    Ok(d)
}

struct PageInfo {
    id: u32,
    name: String,
    background: bool,
    back_page: Option<u32>,
    sheet: Sheet,
    part: Option<String>,
    /// Width and height in inches of the drawing.
    size: (f64, f64),
    /// Inches of paper to each inch of the drawing.
    k: f64,
}

/// The longest side of a PPTX slide, in inches.
const MAX_SLIDE: f64 = 55.0;

/// Paper inches to each inch of a drawing: the page scale over the drawing
/// scale ([MS-VSDX] 2.2.2.3), made smaller where the paper would not fit a
/// slide.
fn paper_scale(sheet: &Sheet, size: (f64, f64)) -> f64 {
    let k = match (
        cell_num(sheet, "PageScale"),
        cell_num(sheet, "DrawingScale"),
    ) {
        (Some(p), Some(d)) => (p / d).clamp(1e-6, 1e6),
        _ => 1.0,
    };
    let longest = size.0.max(size.1) * k;
    if longest > MAX_SLIDE {
        k * MAX_SLIDE / longest
    } else {
        k
    }
}

fn cell_num(s: &Sheet, name: &str) -> Option<f64> {
    s.cells
        .get(name)
        .and_then(|c| c.v.as_deref())
        .and_then(formula::parse_number)
        .filter(|v| v.is_finite() && *v > 0.0)
}

fn read_pages(
    z: &mut Zip,
    part: &str,
    budget: &mut Budget,
    p: &mut Presentation,
) -> Result<Vec<PageInfo>> {
    let max = budget.limits.max_part;
    let Some(bytes) = z.get(part, max, budget)? else {
        p.warn("the pages part is missing");
        return Ok(vec![]);
    };
    let n = parse_part(&bytes, budget)?;
    let rels = by_id(&rels_of(z, part, budget)?);
    let mut out = vec![];
    let mut count = 0usize;
    for pg in n.nodes().filter(|c| local(&c.name) == "Page") {
        let sheet = pg
            .nodes()
            .find(|c| local(&c.name) == "PageSheet")
            .map(|s| sheet::parse(s, &Rels(&rels), &mut count, 0))
            .unwrap_or_default();
        let rel = pg
            .nodes()
            .find(|c| local(&c.name) == "Rel")
            .and_then(|r| r.attr("r:id").or(r.attr("id")));
        let size = (
            cell_num(&sheet, "PageWidth").unwrap_or(DEFAULT_PAGE.0),
            cell_num(&sheet, "PageHeight").unwrap_or(DEFAULT_PAGE.1),
        );
        out.push(PageInfo {
            k: paper_scale(&sheet, size),
            size,
            id: pg
                .attr("ID")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0),
            name: pg
                .attr("Name")
                .or(pg.attr("NameU"))
                .unwrap_or("")
                .to_string(),
            background: matches!(pg.attr("Background"), Some("1" | "true")),
            back_page: pg.attr("BackPage").and_then(|v| v.trim().parse().ok()),
            part: rel.and_then(|r| rels.get(r).cloned()),
            sheet,
        });
        if out.len() >= 1 << 20 {
            break;
        }
    }
    budget.alloc(count as u64 * 512)?;
    Ok(out)
}

/// The master parts of a Masters part, by master id.
fn read_master_parts(z: &mut Zip, part: &str, budget: &mut Budget) -> Result<HashMap<u32, String>> {
    let max = budget.limits.max_part;
    let Some(bytes) = z.get(part, max, budget)? else {
        return Ok(HashMap::new());
    };
    let n = parse_part(&bytes, budget)?;
    let rels = by_id(&rels_of(z, part, budget)?);
    let mut out = HashMap::new();
    for m in n.nodes().filter(|c| local(&c.name) == "Master") {
        let id = m.attr("ID").and_then(|v| v.trim().parse::<u32>().ok());
        let rel = m
            .nodes()
            .find(|c| local(&c.name) == "Rel")
            .and_then(|r| r.attr("r:id").or(r.attr("id")));
        if let (Some(id), Some(t)) = (id, rel.and_then(|r| rels.get(r))) {
            out.insert(id, t.clone());
        }
    }
    Ok(out)
}

/// The shapes of a page or master part (`root` is the name of its root
/// element), their relationships read.
fn read_shapes(
    z: &mut Zip,
    part: &str,
    root: &str,
    budget: &mut Budget,
    p: &mut Presentation,
) -> Result<Vec<Sheet>> {
    let max = budget.limits.max_part;
    let Some(bytes) = z.get(part, max, budget)? else {
        p.warn("a page or master part is missing");
        return Ok(vec![]);
    };
    let n = parse_part(&bytes, budget)?;
    if local(&n.name) != root {
        p.warn("a page or master part is not what its relationship says");
        return Ok(vec![]);
    }
    let rels = by_id(&rels_of(z, part, budget)?);
    let mut count = 0usize;
    let shapes: Vec<Sheet> = n
        .nodes()
        .filter(|c| local(&c.name) == "Shapes")
        .flat_map(|s| s.nodes())
        .filter(|s| local(&s.name) == "Shape")
        .map(|s| sheet::parse(s, &Rels(&rels), &mut count, 0))
        .collect();
    budget.alloc(count as u64 * 512)?;
    Ok(shapes)
}

fn collect_masters(shapes: &[Sheet], ids: &mut Vec<u32>, depth: u32) {
    if depth > 64 {
        return;
    }
    for s in shapes {
        if let Some(m) = s.master {
            if !ids.contains(&m) && ids.len() < 4096 {
                ids.push(m);
            }
        }
        collect_masters(&s.shapes, ids, depth + 1);
    }
}

/// Loads the masters the shapes use, and those these use.
fn load_masters(
    z: &mut Zip,
    parts: &HashMap<u32, String>,
    shapes: &[Sheet],
    masters: &mut HashMap<u32, MasterPart>,
    budget: &mut Budget,
    p: &mut Presentation,
) -> Result<()> {
    let mut want: Vec<u32> = vec![];
    collect_masters(shapes, &mut want, 0);
    let mut i = 0;
    while i < want.len() {
        let id = want[i];
        i += 1;
        if masters.contains_key(&id) {
            continue;
        }
        let Some(part) = parts.get(&id) else {
            continue;
        };
        let shapes = read_shapes(z, part, "MasterContents", budget, p)?;
        collect_masters(&shapes, &mut want, 0);
        masters.insert(id, MasterPart { shapes });
    }
    Ok(())
}

fn blank_master(name: &str, shapes: Vec<Shape>) -> Master {
    Master {
        name: name.to_string(),
        background: Some(Fill::Solid(Color::rgb(0xFFFFFF))),
        shapes,
        layouts: vec![Layout {
            name: "Blank".into(),
            kind: "blank",
            show_master_shapes: true,
            ..Layout::default()
        }],
        ..Master::default()
    }
}

pub(crate) fn read(mut z: Zip, budget: &mut Budget) -> Result<Presentation> {
    let max = budget.limits.max_part;
    let mut p = Presentation::default();

    let root = rels_of(&mut z, "", budget)?;
    let doc_part = match of_kind(&root, "/document") {
        Some(t) => t.to_string(),
        None => "visio/document.xml".to_string(),
    };
    let bytes = z
        .get(&doc_part, max, budget)?
        .ok_or_else(|| Error::NotFormat("no Visio document part".into()))?;
    let docx = parse_part(&bytes, budget)?;
    drop(bytes);
    if local(&docx.name) != "VisioDocument" {
        return Err(Error::NotFormat(format!(
            "not a Visio document: {}",
            local(&docx.name)
        )));
    }
    let mut doc = read_doc(&docx, budget)?;
    drop(docx);
    let doc_rels = rels_of(&mut z, &doc_part, budget)?;
    if let Some(theme) = of_kind(&doc_rels, "/theme") {
        if let Some(b) = z.get(theme, max, budget)? {
            if let Ok(n) = parse_part(&b, budget) {
                read_theme(&n, &mut doc);
            }
        }
    }
    let pages = match of_kind(&doc_rels, "/pages") {
        Some(part) => read_pages(&mut z, part, budget, &mut p)?,
        None => {
            p.warn("the document has no pages part");
            vec![]
        }
    };
    let master_parts = match of_kind(&doc_rels, "/masters") {
        Some(part) => read_master_parts(&mut z, part, budget)?,
        None => HashMap::new(),
    };

    let foreground: Vec<&PageInfo> = pages.iter().filter(|pg| !pg.background).collect();
    // The slide is the largest page.
    let (w, h) = foreground
        .iter()
        .map(|pg| (pg.size.0 * pg.k, pg.size.1 * pg.k))
        .reduce(|a, b| (a.0.max(b.0), a.1.max(b.1)))
        .unwrap_or(DEFAULT_PAGE);
    p.width = (w.min(MAX_SLIDE) * 914_400.0) as Emu;
    p.height = (h.min(MAX_SLIDE) * 914_400.0) as Emu;
    p.total_slides = foreground.len();
    p.masters.push(blank_master("Visio", vec![]));
    if foreground.is_empty() {
        p.warn("the drawing has no pages");
    }
    let names: Vec<String> = foreground.iter().map(|pg| pg.name.clone()).collect();

    let mut masters: HashMap<u32, MasterPart> = HashMap::new();
    let mut media: HashMap<String, Option<usize>> = HashMap::new();
    // A background page becomes a master, by the id of the page.
    let mut backgrounds: HashMap<u32, usize> = HashMap::new();
    for (i, page) in foreground.iter().enumerate() {
        budget.slide(i)?;
        if !budget.wants(i) {
            continue;
        }
        let mut master = 0usize;
        if let Some(bg) = page
            .back_page
            .and_then(|id| pages.iter().find(|b| b.id == id && b.background))
        {
            master = match backgrounds.get(&bg.id) {
                Some(&m) => m,
                None => {
                    let shapes = page_shapes(
                        &mut z,
                        bg,
                        &master_parts,
                        &doc,
                        &mut masters,
                        &mut media,
                        &names,
                        budget,
                        &mut p,
                    )?;
                    p.masters.push(blank_master(&bg.name, shapes));
                    backgrounds.insert(bg.id, p.masters.len() - 1);
                    p.masters.len() - 1
                }
            };
        }
        let shapes = page_shapes(
            &mut z,
            page,
            &master_parts,
            &doc,
            &mut masters,
            &mut media,
            &names,
            budget,
            &mut p,
        )?;
        p.slides.push(Slide {
            name: Some(page.name.clone()),
            master,
            layout: 0,
            background: None,
            shapes,
            hidden: false,
            show_master_shapes: true,
        });
    }
    Ok(p)
}

/// The model shapes of a page.
#[allow(clippy::too_many_arguments)]
fn page_shapes(
    z: &mut Zip,
    page: &PageInfo,
    master_parts: &HashMap<u32, String>,
    doc: &Doc,
    masters: &mut HashMap<u32, MasterPart>,
    media: &mut HashMap<String, Option<usize>>,
    names: &[String],
    budget: &mut Budget,
    p: &mut Presentation,
) -> Result<Vec<Shape>> {
    let Some(part) = page.part.as_deref() else {
        p.warn("a page has no part");
        return Ok(vec![]);
    };
    let tops = read_shapes(z, part, "PageContents", budget, p)?;
    load_masters(z, master_parts, &tops, masters, budget, p)?;
    let tree = resolve::Tree::build(doc, masters, &tops, budget)?;
    let layers = convert::layers(&page.sheet);
    let mut conv = convert::Conv {
        t: &tree,
        p,
        budget,
        zip: z,
        media,
        layers: &layers,
        slide_names: names,
        failed: None,
    };
    conv.page(page.size.1, page.k)
}
