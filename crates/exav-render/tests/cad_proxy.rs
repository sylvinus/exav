//! Proxy graphics (ODA spec 29) on tests/fixtures/cad/proxy (make.py there
//! writes the streams chunk by chunk). Two black-box oracles, both the ODA
//! File Converter's:
//!
//! - It writes the streams again when it writes a DWG, through its own
//!   drawing code (traits it finds redundant dropped, ByBlock and ByLayer
//!   resolved, R13 to R2000 without LWPOLYLINE chunks): each custom entity
//!   of each DWG must draw what the same entity of the source DXF draws.
//! - Its R12 DXF has no proxies: it writes what each draws as plain
//!   entities. Those must draw the same, but for the cases R12 cannot hold
//!   or the converter writes otherwise, whose values are checked here
//!   against what the stream says.

mod cad_common;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use cad_common::fixture;
use exav_render::cad::{Drawing, EntityKind, ProxyItem};
use exav_render::dwg::{Document, Tessellator};

/// make.py's CASES, in order, then the record of the class's own type.
const CASES: [&str; 18] = [
    "traits",
    "transforms",
    "curves",
    "fill",
    "filled curves",
    "texts",
    "shells",
    "mesh",
    "r12 lacks",
    "polylines",
    "no graphics",
    "empty graphics",
    "skipped",
    "lwpolyline",
    "out of range",
    "elliptical arcs",
    "edge on",
    "custom record",
];

const RELEASES: [&str; 8] = [
    "R13", "R14", "R2000", "R2004", "R2007", "R2010", "R2013", "R2018",
];

fn read(path: &str) -> Document {
    let bytes = fixture(path).unwrap_or_else(|| panic!("{path} is missing"));
    Document::parse(&bytes).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// What one entity draws on its own.
#[derive(Debug, Default)]
struct Stats {
    length: f64,
    area: f64,
    texts: usize,
    /// min x, min y, max x, max y of strokes and fills.
    bounds: [f64; 4],
    /// Stroke length by layer, colour and lineweight.
    by: BTreeMap<(String, u32, u32), f64>,
}

fn stats(t: &mut Tessellator<'_>, e: &exav_render::cad::Entity) -> Stats {
    t.clear_scene();
    t.tessellate_entity(e);
    let mut s = Stats {
        bounds: [
            f64::INFINITY,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NEG_INFINITY,
        ],
        texts: t.scene.texts.len(),
        ..Stats::default()
    };
    let mut point = |x: f64, y: f64| {
        s.bounds = [
            s.bounds[0].min(x),
            s.bounds[1].min(y),
            s.bounds[2].max(x),
            s.bounds[3].max(y),
        ];
    };
    for k in &t.scene.strokes {
        point(k.x0, k.y0);
        point(k.x1, k.y1);
    }
    for f in &t.scene.fills {
        point(f.x, f.y);
    }
    for k in &t.scene.strokes {
        let len = (k.x1 - k.x0).hypot(k.y1 - k.y0);
        s.length += len;
        let layer = t.layers[(k.attr & 0xffff) as usize].name.clone();
        *s.by
            .entry((layer, k.rgba, (k.attr >> 16) & 0xff))
            .or_default() += len;
    }
    s.area = t
        .scene
        .fills
        .as_chunks::<3>()
        .0
        .iter()
        .map(|v| {
            ((v[1].x - v[0].x) * (v[2].y - v[0].y) - (v[2].x - v[0].x) * (v[1].y - v[0].y)).abs()
                / 2.0
        })
        .sum();
    s
}

fn close(a: f64, b: f64) -> bool {
    a == b || (a - b).abs() <= 1e-6_f64.max(2e-3 * a.abs().max(b.abs()))
}

/// Where two drawings of an entity differ, empty when they agree.
fn differences(a: &Stats, b: &Stats) -> Vec<String> {
    let mut out = Vec::new();
    if !close(a.length, b.length) {
        out.push(format!("length {} vs {}", a.length, b.length));
    }
    if !close(a.area, b.area) {
        out.push(format!("area {} vs {}", a.area, b.area));
    }
    if a.texts != b.texts {
        out.push(format!("texts {} vs {}", a.texts, b.texts));
    }
    let span = (b.bounds[2] - b.bounds[0]).max(b.bounds[3] - b.bounds[1]);
    let near = |x: f64, y: f64| x == y || (x - y).abs() <= 2e-3 * span + 1e-6;
    if !a.bounds.iter().zip(&b.bounds).all(|(x, y)| near(*x, *y)) {
        out.push(format!("bounds {:?} vs {:?}", a.bounds, b.bounds));
    }
    for k in a.by.keys().chain(b.by.keys()) {
        let (x, y) = (
            a.by.get(k).copied().unwrap_or(0.0),
            b.by.get(k).copied().unwrap_or(0.0),
        );
        if !close(x, y) {
            out.push(format!("{k:?} {x} vs {y}"));
        }
    }
    out
}

/// The source's custom entities by case, with their handles.
fn cases(d: &Drawing) -> Vec<(&'static str, u64)> {
    let entities = &d.model_space().expect("model space").entities;
    let custom: Vec<u64> = entities
        .iter()
        .filter(|e| matches!(&e.kind, EntityKind::Unknown(u) if u.is_custom()))
        .map(|e| e.handle.0)
        .collect();
    assert_eq!(custom.len(), CASES.len(), "{custom:X?}");
    CASES.iter().copied().zip(custom).collect()
}

/// Each case's drawing in `doc`, by case name; `None` where it has no
/// entity of that handle.
fn drawn(doc: &Document, cases: &[(&'static str, u64)]) -> BTreeMap<&'static str, Option<Stats>> {
    let d = doc.drawing();
    let mut t = Tessellator::new(d);
    let ms = &d.model_space().expect("model space").entities;
    cases
        .iter()
        .map(|(name, h)| {
            let e = ms.iter().find(|e| e.handle.0 == *h);
            (*name, e.map(|e| stats(&mut t, e)))
        })
        .collect()
}

#[test]
fn every_release_draws_the_streams_as_the_source_does() {
    let src = read("proxy/src/proxy.dxf");
    let cases = cases(src.drawing());
    let want = drawn(&src, &cases);
    // R13's DXF keeps its proxies' graphics in AcDbZombieEntity.
    let files = RELEASES
        .iter()
        .map(|v| (*v, format!("proxy/dwg/{v}/proxy.dwg")))
        .chain([("R13", "proxy/r13/proxy.dxf".to_string())]);
    for (v, path) in files {
        let got = drawn(&read(&path), &cases);
        for (name, w) in &want {
            let (Some(w), Some(Some(g))) = (w, got.get(name)) else {
                panic!("{path} {name}: not in both");
            };
            let diff = differences(w, g);
            // The converter's R13 to R2000 DWGs have no LWPOLYLINE chunk: it
            // writes the wide segment's outline and fill, which an
            // LWPOLYLINE's widths are not drawn as. (Its R13 DXF keeps the
            // stream as it was.)
            if *name == "lwpolyline"
                && path.ends_with(".dwg")
                && matches!(v, "R13" | "R14" | "R2000")
            {
                assert!(w.area == 0.0 && g.area > 7.0, "{path}: {w:?} {g:?}");
                continue;
            }
            assert!(diff.is_empty(), "{path} {name}: {diff:?}");
        }
    }
}

#[test]
fn the_converters_r12_entities_draw_what_the_streams_draw() {
    let src = read("proxy/src/proxy.dxf");
    let cases = cases(src.drawing());
    let ours = drawn(&src, &cases);
    let r12 = drawn(&read("proxy/r12/proxy.dxf"), &cases);
    let get = |name: &str| {
        let ours = ours[name].as_ref().expect("in the source");
        (ours, r12[name].as_ref())
    };
    for name in [
        "transforms",
        "curves",
        "fill",
        "texts",
        "polylines",
        "skipped",
        "out of range",
        "elliptical arcs",
        "edge on",
        "custom record",
    ] {
        let (ours, theirs) = get(name);
        let theirs = theirs.unwrap_or_else(|| panic!("{name}: not in R12"));
        assert_eq!(differences(ours, theirs), Vec::<String>::new(), "{name}");
        assert!(ours.length > 0.0 || ours.texts > 0, "{name} draws");
    }
    // Nothing drawn, nothing written.
    for name in ["no graphics", "empty graphics"] {
        let (ours, theirs) = get(name);
        assert!(
            theirs.is_none() && ours.length == 0.0 && ours.area == 0.0,
            "{name}"
        );
    }

    let pi = std::f64::consts::PI;
    // Filled, a circle of 5 and a quarter sector of 5 (the converter: the
    // circle's outline); fill off, a chord arc's outline (the converter: a
    // filled segment).
    let (ours, theirs) = get("filled curves");
    let sector = 25.0 * pi / 4.0;
    assert!(close_to(ours.area, 25.0 * pi + sector, 0.01), "{ours:?}");
    assert!(
        close_to(ours.length, 5.0 * pi / 2.0 + 50f64.sqrt(), 0.001),
        "{ours:?}"
    );
    assert!(theirs.is_some_and(|t| t.area < ours.area));
    // Three faces: two edges hidden by none, one by its flag, one filled.
    let (ours, _) = get("shells");
    let tri = 20.0 + 200f64.sqrt();
    assert!(
        close_to(ours.length, 2.0 * tri + (tri - 10.0), 1e-9),
        "{ours:?}"
    );
    assert!(close_to(ours.area, 100.0, 1e-9), "{ours:?}");
    // A grid of 2 by 3: three columns of 5, two rows of 10.
    let (ours, theirs) = get("mesh");
    assert!(close_to(ours.length, 35.0, 1e-9), "{ours:?}");
    assert!(
        theirs.is_some_and(|t| t.length == 0.0),
        "R12's mesh is not drawn"
    );
    // The true colour is red, ACI 1 in R12; xline and ray wait for the
    // drawing's extents, so neither box has them.
    let (ours, theirs) = get("r12 lacks");
    let red = |s: &Stats| {
        s.by.iter()
            .filter(|(k, _)| k.1 == 0xff00_00ff)
            .map(|(_, l)| l)
            .sum::<f64>()
    };
    assert!(close_to(red(ours), 4.0, 1e-9) && theirs.is_some_and(|t| red(t) == red(ours)));
    // Widths are not drawn: the centre lines (the converter: R12 faces).
    let (ours, _) = get("lwpolyline");
    let bulge = 0.5f64;
    let chord = 10.0;
    let radius = chord / 2.0 / (2.0 * bulge.atan()).sin();
    let arc = radius * 4.0 * bulge.atan();
    assert!(close_to(ours.length, 30.0 + arc + 15.0, 0.002), "{ours:?}");
    // Traits: a layer the stream names is that layer, ByBlock the block
    // the entity is in (colour 7 here), the lineweight the stream's.
    let (ours, _) = get("traits");
    let on = |layer: &str, lw: u32| -> f64 {
        ours.by
            .iter()
            .filter(|(k, _)| k.0 == layer && k.2 == lw)
            .map(|(_, l)| l)
            .sum()
    };
    assert!(
        on("L1", 50) > 0.0 && on("0", 0) > 0.0 && on("L2", 0) > 0.0,
        "{ours:?}"
    );
}

fn close_to(a: f64, b: f64, rel: f64) -> bool {
    (a - b).abs() <= rel * b.abs().max(1e-9)
}

#[test]
fn custom_entities_without_graphics_are_counted() {
    let mut files = vec![
        "proxy/src/proxy.dxf".to_string(),
        "proxy/r13/proxy.dxf".to_string(),
    ];
    files.extend(RELEASES.iter().map(|v| format!("proxy/dwg/{v}/proxy.dwg")));
    for f in files {
        let doc = read(&f);
        let d = doc.tessellate(None, None);
        // "no graphics" and "empty graphics" (the converter gives the first
        // an empty stream in a DWG).
        assert_eq!(d.warnings.proxy_without_graphics, 2, "{f}");
        assert_eq!(d.warnings.unknown_entities, 0, "{f}");
        assert!(d.warnings_json().contains(r#""proxyWithoutGraphics":2"#));
    }
    let src = read("proxy/src/proxy.dxf");
    let graphics = |name: &str| {
        let (_, h) = cases(src.drawing())
            .into_iter()
            .find(|(n, _)| *n == name)
            .expect("a case");
        src.drawing()
            .model_space()
            .and_then(|b| b.entities.iter().find(|e| e.handle.0 == h))
            .and_then(|e| match &e.kind {
                EntityKind::Unknown(u) => Some(u.graphics.clone()),
                _ => None,
            })
            .expect("an unknown entity")
    };
    assert_eq!(graphics("no graphics"), None);
    assert!(graphics("empty graphics").is_some_and(|g| g.items.is_empty()));
    // The class's own record keeps its graphics in AcDbEntity.
    let g = graphics("custom record").expect("graphics");
    assert!(matches!(&g.items[..], [ProxyItem::Polyline { points, .. }] if points.len() == 2));
}

#[test]
fn a_damaged_stream_costs_its_entity_at_most() {
    for f in ["proxy/src/proxy.dxf", "proxy/dwg/R2018/proxy.dwg"] {
        let bytes = fixture(f).expect("fixture");
        let started = Instant::now();
        // The streams are most of each file's tail: cut and flip there.
        for k in 0..200usize {
            let at = bytes.len() / 2 + (bytes.len() / 2) * k / 200;
            let mut cut = bytes[..at].to_vec();
            if let Ok(doc) = Document::parse(&cut) {
                doc.tessellate(None, None);
            }
            cut = bytes.clone();
            cut[at] ^= 1 << (k % 8);
            if let Ok(doc) = Document::parse(&cut) {
                doc.tessellate(None, None);
            }
        }
        assert!(started.elapsed() < Duration::from_secs(30), "{f}");
    }
}
