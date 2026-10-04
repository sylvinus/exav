//! Print a stable summary of what the DWG/DXF engine draws for each file
//! given: every layout on a light and a dark ground, with counts, extents,
//! the layer table, warnings, stroke length per layer and per colour, the
//! text, and coarse occupancy grids of the strokes, fills and text anchors.
//! Two runs of it (before and after a change to the reader or the
//! tessellator) compare as "same picture" without exact buffer equality.
//!
//!     cargo run -p exav-render --no-default-features --features dwg \
//!         --example scene_stats -- [--entities] <file>...
//!
//! `--entities` prints instead what each model-space entity tessellates to on
//! its own, to attribute a difference to the entities behind it;
//! `--proxies` the custom entities and whether they have proxy graphics.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use exav_render::cad::EntityKind;
use exav_render::dwg::{
    Document, Drawing, Tessellator, FILL_BYTES, STROKE_BYTES, TEXT_RECORD_BYTES,
};

/// Cells per side of the occupancy grids.
const GRID: usize = 64;

fn f32_at(b: &[u8], at: usize) -> f64 {
    f64::from(f32::from_le_bytes(b[at..at + 4].try_into().unwrap()))
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// Four significant digits: what survives a different but equivalent
/// flattening or summation order.
fn sig(v: f64) -> String {
    if v == 0.0 || !v.is_finite() {
        return format!("{v}");
    }
    format!("{v:.3e}")
}

struct Grid {
    bits: Vec<bool>,
    box_: [f64; 4],
}

impl Grid {
    fn new(box_: [f64; 4]) -> Grid {
        Grid {
            bits: vec![false; GRID * GRID],
            box_,
        }
    }

    fn cell(&self, x: f64, y: f64) -> Option<(usize, usize)> {
        let [x0, y0, x1, y1] = self.box_;
        let (w, h) = ((x1 - x0).max(1e-12), (y1 - y0).max(1e-12));
        let cx = ((x - x0) / w * GRID as f64).floor();
        let cy = ((y - y0) / h * GRID as f64).floor();
        if !(cx.is_finite() && cy.is_finite()) {
            return None;
        }
        let clamp = |v: f64| v.clamp(0.0, (GRID - 1) as f64) as usize;
        // Points on the far edge belong to the last cell; points well
        // outside the box are not drawn.
        if cx < -1.0 || cy < -1.0 || cx > GRID as f64 || cy > GRID as f64 {
            return None;
        }
        Some((clamp(cx), clamp(cy)))
    }

    fn set(&mut self, x: f64, y: f64) {
        if let Some((cx, cy)) = self.cell(x, y) {
            self.bits[cy * GRID + cx] = true;
        }
    }

    fn segment(&mut self, a: [f64; 2], b: [f64; 2]) {
        let [x0, y0, x1, y1] = self.box_;
        let step = ((x1 - x0).max(y1 - y0) / GRID as f64 / 2.0).max(1e-12);
        let len = (b[0] - a[0]).hypot(b[1] - a[1]);
        let n = ((len / step).ceil() as usize).clamp(1, 4 * GRID);
        for i in 0..=n {
            let t = i as f64 / n as f64;
            self.set(a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t);
        }
    }

    fn triangle(&mut self, p: [[f64; 2]; 3]) {
        for q in p {
            self.set(q[0], q[1]);
        }
        let [x0, y0, x1, y1] = self.box_;
        let (cw, ch) = ((x1 - x0) / GRID as f64, (y1 - y0) / GRID as f64);
        if !(cw > 0.0 && ch > 0.0) {
            return;
        }
        let minx = p.iter().map(|q| q[0]).fold(f64::INFINITY, f64::min);
        let maxx = p.iter().map(|q| q[0]).fold(f64::NEG_INFINITY, f64::max);
        let miny = p.iter().map(|q| q[1]).fold(f64::INFINITY, f64::min);
        let maxy = p.iter().map(|q| q[1]).fold(f64::NEG_INFINITY, f64::max);
        let (Some((ax, ay)), Some((bx, by))) = (self.cell(minx, miny), self.cell(maxx, maxy))
        else {
            return;
        };
        let side = |a: [f64; 2], b: [f64; 2], c: [f64; 2]| {
            (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])
        };
        for cy in ay..=by {
            for cx in ax..=bx {
                let c = [x0 + (cx as f64 + 0.5) * cw, y0 + (cy as f64 + 0.5) * ch];
                let (d0, d1, d2) = (
                    side(p[0], p[1], c),
                    side(p[1], p[2], c),
                    side(p[2], p[0], c),
                );
                let neg = d0 < 0.0 || d1 < 0.0 || d2 < 0.0;
                let pos = d0 > 0.0 || d1 > 0.0 || d2 > 0.0;
                if !(neg && pos) {
                    self.bits[cy * GRID + cx] = true;
                }
            }
        }
    }

    /// One hex row per grid row, top first.
    fn hex(&self) -> String {
        let mut out = String::new();
        for row in (0..GRID).rev() {
            let mut v = 0u64;
            for col in 0..GRID {
                if self.bits[row * GRID + col] {
                    v |= 1 << col;
                }
            }
            let _ = write!(out, "{v:016x}");
            out.push(if row == 0 { '\n' } else { ' ' });
        }
        out
    }
}

fn summarise(out: &mut String, d: &Drawing) {
    let o = d.origin;
    let ext = [
        d.extents[0] as f64 + o[0],
        d.extents[1] as f64 + o[1],
        d.extents[2] as f64 + o[0],
        d.extents[3] as f64 + o[1],
    ];
    let _ = writeln!(out, "  drawn {:?}", d.layout);
    let _ = writeln!(
        out,
        "  counts strokes={} fills={} texts={} opaque_strokes={} opaque_fills={}",
        d.stroke_count(),
        d.fill_vertex_count(),
        d.text_count(),
        d.opaque_strokes,
        d.opaque_fills
    );
    let _ = writeln!(
        out,
        "  extents {} {} {} {}",
        sig(ext[0]),
        sig(ext[1]),
        sig(ext[2]),
        sig(ext[3])
    );
    let _ = writeln!(out, "  layers {}", d.layers_json());
    let _ = writeln!(out, "  warnings {}", d.warnings_json());

    let mut strokes = Grid::new(ext);
    let mut fills = Grid::new(ext);
    let mut anchors = Grid::new(ext);
    // Per layer: strokes, fill vertices, stroke length. Per colour and
    // flags: stroke length, fill vertices.
    let mut by_layer: BTreeMap<String, (usize, usize, f64)> = BTreeMap::new();
    let mut by_rgba: BTreeMap<(u32, u8), (f64, usize)> = BTreeMap::new();
    let layer_name = |attr: u32| {
        d.layers
            .get((attr & 0xffff) as usize)
            .map(|l| l.name.clone())
            .unwrap_or_else(|| format!("#{}", attr & 0xffff))
    };
    for s in d.strokes.as_chunks::<STROKE_BYTES>().0 {
        let a = [f32_at(s, 0) + o[0], f32_at(s, 4) + o[1]];
        let b = [f32_at(s, 8) + o[0], f32_at(s, 12) + o[1]];
        let (rgba, attr) = (u32_at(s, 16), u32_at(s, 20));
        let len = (b[0] - a[0]).hypot(b[1] - a[1]);
        strokes.segment(a, b);
        let e = by_layer.entry(layer_name(attr)).or_default();
        e.0 += 1;
        e.2 += len;
        by_rgba.entry((rgba, (attr >> 24) as u8)).or_default().0 += len;
    }
    for t in d.fills.as_chunks::<{ FILL_BYTES * 3 }>().0 {
        let p = |i: usize| {
            [
                f32_at(t, i * FILL_BYTES) + o[0],
                f32_at(t, i * FILL_BYTES + 4) + o[1],
            ]
        };
        fills.triangle([p(0), p(1), p(2)]);
        for i in 0..3 {
            let (rgba, attr) = (
                u32_at(t, i * FILL_BYTES + 8),
                u32_at(t, i * FILL_BYTES + 12),
            );
            by_layer.entry(layer_name(attr)).or_default().1 += 1;
            by_rgba.entry((rgba, (attr >> 24) as u8)).or_default().1 += 1;
        }
    }
    let mut texts: Vec<String> = Vec::new();
    for r in d.texts.as_chunks::<TEXT_RECORD_BYTES>().0 {
        anchors.set(f32_at(r, 0) + o[0], f32_at(r, 4) + o[1]);
        let at = u32_at(r, 32) as usize;
        let len = u16::from_le_bytes([r[36], r[37]]) as usize;
        let s = d
            .text_strings
            .get(at..at + len)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        texts.push(format!(
            "{s}|h={}|rot={}|align={},{}|face={}|rgba={:08x}",
            sig(f32_at(r, 8)),
            sig(f32_at(r, 12)),
            r[38],
            r[39],
            r[44],
            u32_at(r, 24)
        ));
    }
    texts.sort();

    let _ = writeln!(out, "  by_layer");
    for (name, (n, f, len)) in &by_layer {
        let _ = writeln!(
            out,
            "    {name:?} strokes={n} fills={f} length={}",
            sig(*len)
        );
    }
    let _ = writeln!(out, "  by_colour");
    for ((rgba, flags), (len, f)) in &by_rgba {
        let _ = writeln!(
            out,
            "    {rgba:08x}/{flags:02x} length={} fills={f}",
            sig(*len)
        );
    }
    let _ = writeln!(out, "  texts {}", texts.len());
    for t in &texts {
        let _ = writeln!(out, "    {t:?}");
    }
    let _ = write!(out, "  grid_strokes {}", strokes.hex());
    let _ = write!(out, "  grid_fills {}", fills.hex());
    let _ = write!(out, "  grid_texts {}", anchors.hex());
}

/// `--entities`: what each entity of model and paper space alone tessellates
/// to, by handle and type, on a light ground, with the box of its strokes and
/// fills.
fn per_entity(doc: &Document) {
    let drawing = doc.drawing();
    let mut t = Tessellator::new(drawing);
    for block in drawing
        .blocks
        .iter()
        .filter(|b| b.is_model_space() || b.is_paper_space())
    {
        println!("block {:?}", block.name);
        for e in &block.entities {
            t.clear_scene();
            t.tessellate_entity(e);
            let mut lo = [f64::INFINITY; 2];
            let mut hi = [f64::NEG_INFINITY; 2];
            let points = t
                .scene
                .strokes
                .iter()
                .flat_map(|s| [[s.x0, s.y0], [s.x1, s.y1]])
                .chain(t.scene.fills.iter().map(|f| [f.x, f.y]));
            for p in points {
                lo = [lo[0].min(p[0]), lo[1].min(p[1])];
                hi = [hi[0].max(p[0]), hi[1].max(p[1])];
            }
            let area: f64 = t
                .scene
                .fills
                .as_chunks::<3>()
                .0
                .iter()
                .map(|v| {
                    ((v[1].x - v[0].x) * (v[2].y - v[0].y) - (v[2].x - v[0].x) * (v[1].y - v[0].y))
                        .abs()
                        / 2.0
                })
                .sum();
            let length: f64 = t
                .scene
                .strokes
                .iter()
                .map(|s| (s.x1 - s.x0).hypot(s.y1 - s.y0))
                .sum();
            // Stroke length by the layer, colour and lineweight each stroke
            // resolved to.
            let mut by: BTreeMap<(String, u32, u32), f64> = BTreeMap::new();
            for s in &t.scene.strokes {
                let layer = t
                    .layers
                    .get((s.attr & 0xffff) as usize)
                    .map_or_else(|| "?".to_string(), |l| l.name.clone());
                *by.entry((layer, s.rgba, (s.attr >> 16) & 0xff))
                    .or_default() += (s.x1 - s.x0).hypot(s.y1 - s.y0);
            }
            let by: Vec<String> = by
                .iter()
                .map(|((l, rgba, lw), len)| format!("{l:?}/{rgba:08x}/{lw}:{}", sig(*len)))
                .collect();
            println!(
                "  {:x} {} layer={:?} strokes={} length={} fills={} area={} texts={} glyphs={} by=[{}] box={} {} {} {}",
                e.handle.0,
                e.type_name(),
                e.layer,
                t.scene.strokes.len(),
                sig(length),
                t.scene.fills.len(),
                sig(area),
                t.scene.texts.len(),
                t.warnings.stroke_glyphs,
                by.join(" "),
                sig(lo[0]),
                sig(lo[1]),
                sig(hi[0]),
                sig(hi[1])
            );
        }
    }
}

/// `--proxies`: the custom entities of every block, by type: how many have
/// proxy graphics that draw, how many have none or empty ones.
fn proxies(doc: &Document) {
    let mut by: BTreeMap<String, [usize; 3]> = BTreeMap::new();
    for e in doc.drawing().blocks.iter().flat_map(|b| &b.entities) {
        let EntityKind::Unknown(u) = &e.kind else {
            continue;
        };
        let slot = match &u.graphics {
            Some(g) if g.draws() => 0,
            Some(_) => 1,
            None => 2,
        };
        if slot > 0 && !u.is_custom() {
            continue;
        }
        by.entry(u.type_name.clone()).or_default()[slot] += 1;
    }
    for (t, [drawn, empty, none]) in by {
        println!("  {t} graphics={drawn} empty={empty} none={none}");
    }
}

fn main() {
    let mut files: Vec<String> = std::env::args().skip(1).collect();
    let mode = files
        .first()
        .filter(|a| *a == "--entities" || *a == "--proxies")
        .cloned();
    if mode.is_some() {
        files.remove(0);
    }
    let entities = mode.as_deref() == Some("--entities");
    if files.is_empty() {
        eprintln!("usage: scene_stats [--entities|--proxies] <file>...");
        std::process::exit(2);
    }
    for path in files {
        if mode.as_deref() == Some("--proxies") {
            println!("file {path}");
            match std::fs::read(&path).map(|b| Document::parse(&b)) {
                Ok(Ok(doc)) => proxies(&doc),
                Ok(Err(e)) => println!("parse error {e}"),
                Err(e) => println!("read error {e}"),
            }
            continue;
        }
        if entities {
            println!("file {path}");
            match std::fs::read(&path).map(|b| Document::parse(&b)) {
                Ok(Ok(doc)) => per_entity(&doc),
                Ok(Err(e)) => println!("parse error {e}"),
                Err(e) => println!("read error {e}"),
            }
            continue;
        }
        let mut out = String::new();
        let _ = writeln!(out, "file {path}");
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                let _ = writeln!(out, "read error {e}");
                print!("{out}");
                continue;
            }
        };
        match Document::parse(&bytes) {
            Err(e) => {
                let _ = writeln!(out, "parse error {e}");
            }
            Ok(doc) => {
                let _ = writeln!(out, "layouts {}", doc.layouts_json());
                for layout in doc.layouts() {
                    for (ground, rgb) in [("light", [255, 255, 255]), ("dark", [33, 40, 48])] {
                        let _ = writeln!(out, "layout {:?} {ground}", layout.name);
                        let d = doc.tessellate(Some(&layout.name), Some(rgb));
                        summarise(&mut out, &d);
                    }
                }
            }
        }
        print!("{out}");
    }
}
