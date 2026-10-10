//! The IFC reader against the closed-form expectations of the fixtures
//! `tests/fixtures/ifc/make.py` writes: per element its volume, extents,
//! surface area and colour, the openings subtracted, the units applied,
//! damaged and looping references survived.

use std::collections::HashMap;
use std::path::Path;

use exav_render::ifc::{read, Limits};
use exav_render::mesh::Scene;
use serde_json::Value;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ifc");

/// Per element (by name): triangles, extents, area, volume, colours.
#[derive(Debug)]
struct Stats {
    triangles: usize,
    min: [f64; 3],
    max: [f64; 3],
    area: f64,
    volume: f64,
    colors: Vec<Option<[f32; 4]>>,
    node: Option<u32>,
}

fn stats(s: &Scene) -> HashMap<String, Stats> {
    let mut out = HashMap::new();
    for e in &s.elements {
        let mut st = Stats {
            triangles: 0,
            min: [f64::INFINITY; 3],
            max: [f64::NEG_INFINITY; 3],
            area: 0.0,
            volume: 0.0,
            colors: Vec::new(),
            node: e.node,
        };
        let mut reference: Option<[f64; 3]> = None;
        for r in &e.ranges {
            let b = &s.batches[r.batch as usize];
            st.colors.push(b.color);
            let p = |i: u32| -> [f64; 3] {
                let k = i as usize * 3;
                [
                    b.positions[k] as f64,
                    b.positions[k + 1] as f64,
                    b.positions[k + 2] as f64,
                ]
            };
            for t in b.indices[r.first as usize..(r.first + r.count) as usize]
                .as_chunks::<3>()
                .0
            {
                let (a, bb, c) = (p(t[0]), p(t[1]), p(t[2]));
                for q in [a, bb, c] {
                    for (k, v) in q.iter().enumerate() {
                        st.min[k] = st.min[k].min(v + s.origin[k]);
                        st.max[k] = st.max[k].max(v + s.origin[k]);
                    }
                }
                let u = [bb[0] - a[0], bb[1] - a[1], bb[2] - a[2]];
                let v = [c[0] - a[0], c[1] - a[1], c[2] - a[2]];
                let n = [
                    u[1] * v[2] - u[2] * v[1],
                    u[2] * v[0] - u[0] * v[2],
                    u[0] * v[1] - u[1] * v[0],
                ];
                st.area += (n[0] * n[0] + n[1] * n[1] + n[2] * n[2]).sqrt() / 2.0;
                // About one point of the element: f32 positions far from
                // it would round the products away.
                let o = *reference.get_or_insert(a);
                let (a, bb, c) = (sub(a, o), sub(bb, o), sub(c, o));
                st.volume += (a[0] * (bb[1] * c[2] - bb[2] * c[1])
                    + a[1] * (bb[2] * c[0] - bb[0] * c[2])
                    + a[2] * (bb[0] * c[1] - bb[1] * c[0]))
                    / 6.0;
                st.triangles += 1;
            }
        }
        out.insert(e.name.clone(), st);
    }
    out
}

fn sub(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}

fn expected() -> serde_json::Map<String, Value> {
    let text = std::fs::read_to_string(Path::new(DIR).join("expected.json")).unwrap();
    serde_json::from_str::<Value>(&text)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

fn load(name: &str) -> Scene {
    let bytes = std::fs::read(Path::new(DIR).join(name)).unwrap();
    read(&bytes, &Limits::default()).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn f(v: &Value) -> f64 {
    v.as_f64().unwrap()
}

#[test]
fn every_fixture_matches_its_closed_form() {
    let mut failures = Vec::new();
    let mut checked = 0;
    for (file, exp) in expected() {
        let scene = load(&file);
        let got = stats(&scene);
        for (name, e) in exp["elements"].as_object().unwrap() {
            let Some(g) = got.get(name) else {
                failures.push(format!("{file} {name}: not drawn"));
                continue;
            };
            checked += 1;
            // Positions are f32 relative to the scene origin, which is near
            // the first element: 1e-4 relative covers their rounding 100 m
            // away.
            let tol = e.get("tol").map_or(1e-6, f).max(1e-4);
            if let Some(v) = e.get("volume") {
                let want = f(v);
                if (g.volume - want).abs() > tol * want.abs() + 1e-6 {
                    failures.push(format!("{file} {name}: volume {} not {want}", g.volume));
                }
            }
            if let Some(a) = e.get("area") {
                let want = f(a);
                if (g.area - want).abs() > tol * want + 1e-6 {
                    failures.push(format!("{file} {name}: area {} not {want}", g.area));
                }
            }
            for (key, got) in [("min", g.min), ("max", g.max)] {
                let Some(want) = e.get(key) else { continue };
                for k in 0..3 {
                    let w = f(&want[k]);
                    // Positions are f32 relative to the origin: 1e-5 m.
                    if (got[k] - w).abs() > 2e-5 {
                        failures.push(format!("{file} {name}: {key}[{k}] {} not {w}", got[k]));
                    }
                }
            }
            if let Some(c) = e.get("color") {
                let want: Option<Vec<f64>> = c.as_array().map(|a| a.iter().map(f).collect());
                let have = g
                    .colors
                    .first()
                    .copied()
                    .flatten()
                    .map(|c| c.iter().map(|&x| x as f64).collect::<Vec<_>>());
                let same = match (&want, &have) {
                    (None, None) => true,
                    (Some(w), Some(h)) => w.iter().zip(h).all(|(a, b)| (a - b).abs() < 1e-6),
                    _ => false,
                };
                if !same {
                    failures.push(format!("{file} {name}: colour {have:?} not {want:?}"));
                }
            }
        }
        for name in exp
            .get("absent")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if got.contains_key(name.as_str().unwrap()) {
                failures.push(format!("{file} {name}: drawn"));
            }
        }
        if let Some(d) = exp.get("damaged") {
            assert_eq!(scene.warnings.damaged, d.as_bool().unwrap(), "{file}");
        }
        if let Some(o) = exp.get("origin_near") {
            // Positions stay small: the origin carries the offset.
            for k in 0..3 {
                assert!(
                    (scene.origin[k] - f(&o[k])).abs() < 100.0,
                    "{file}: origin {:?}",
                    scene.origin
                );
            }
            let b = scene.bounds.unwrap();
            assert!(
                b.iter().flatten().all(|v| v.abs() < 100.0),
                "{file}: bounds {b:?}"
            );
        }
        if let Some(st) = exp.get("storey").and_then(Value::as_object) {
            for (name, storey) in st {
                let n = got[name].node.expect("contained");
                assert_eq!(scene.nodes[n as usize].name, storey.as_str().unwrap());
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {checked}:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(checked >= 50, "only {checked} elements checked");
}

#[test]
fn closed_solids_are_watertight() {
    // Without booleans (whose cuts leave T-junctions) every solid is
    // closed: each edge between two triangles, by position.
    for file in ["profiles.ifc", "tessellated.ifc", "mapped_units.ifc"] {
        let scene = load(file);
        for e in &scene.elements {
            if e.class == "IFCCOVERING" {
                continue;
            }
            let mut edges: HashMap<([u32; 3], [u32; 3]), u32> = HashMap::new();
            for r in &e.ranges {
                let b = &scene.batches[r.batch as usize];
                let key = |i: u32| {
                    let k = i as usize * 3;
                    [
                        b.positions[k].to_bits(),
                        b.positions[k + 1].to_bits(),
                        b.positions[k + 2].to_bits(),
                    ]
                };
                for t in b.indices[r.first as usize..(r.first + r.count) as usize]
                    .as_chunks::<3>()
                    .0
                {
                    for (x, y) in [(t[0], t[1]), (t[1], t[2]), (t[2], t[0])] {
                        let (a, c) = (key(x), key(y));
                        *edges
                            .entry(if a < c { (a, c) } else { (c, a) })
                            .or_insert(0) += 1;
                    }
                }
            }
            let open = edges.values().filter(|&&n| n != 2).count();
            assert_eq!(
                open, 0,
                "{file} {}: {open} edges not shared by two triangles",
                e.name
            );
        }
    }
}

#[test]
fn the_spatial_structure_is_a_tree_from_the_project() {
    let scene = load("solids.ifc");
    let classes: Vec<&str> = scene.nodes.iter().map(|n| n.class.as_str()).collect();
    assert_eq!(
        classes,
        ["IFCPROJECT", "IFCSITE", "IFCBUILDING", "IFCBUILDINGSTOREY"]
    );
    for (i, n) in scene.nodes.iter().enumerate().skip(1) {
        assert_eq!(n.parent, Some(i as u32 - 1));
    }
    assert!(scene.elements.iter().all(|e| e.node == Some(3)));
    assert!(scene.elements.iter().all(|e| e.global_id.len() == 22));
}

#[test]
fn the_triangle_budget_leaves_elements_out() {
    let bytes = std::fs::read(Path::new(DIR).join("profiles.ifc")).unwrap();
    let all = read(&bytes, &Limits::default()).unwrap();
    let some = read(&bytes, &Limits { max_triangles: 200 }).unwrap();
    assert!(some.triangles() <= 200);
    assert!(some.warnings.truncated > 0);
    assert_eq!(
        some.elements.len() + some.warnings.truncated as usize,
        all.elements.len()
    );
}

#[test]
fn the_z_section_has_its_top_flange_to_the_left() {
    // The specification's figure: top flange towards -x, bottom one +x.
    let scene = load("profiles.ifc");
    let e = scene.elements.iter().find(|e| e.name == "z shape").unwrap();
    let (mut top, mut bottom) = (Vec::new(), Vec::new());
    for r in &e.ranges {
        let b = &scene.batches[r.batch as usize];
        for &i in &b.indices[r.first as usize..(r.first + r.count) as usize] {
            let k = i as usize * 3;
            let (x, y) = (
                b.positions[k] as f64 + scene.origin[0],
                b.positions[k + 1] as f64 + scene.origin[1],
            );
            if y > 0.149 {
                top.push(x);
            } else if y < -0.149 {
                bottom.push(x);
            }
        }
    }
    // The member is at x = 22, the web 0.01 thick.
    assert!(
        top.iter().all(|&x| x < 22.0051) && top.iter().any(|&x| x < 21.92),
        "{top:?}"
    );
    assert!(
        bottom.iter().all(|&x| x > 21.9949) && bottom.iter().any(|&x| x > 22.08),
        "{bottom:?}"
    );
}

#[test]
fn not_ifc_is_an_error() {
    assert!(read(b"%PDF-1.7", &Limits::default()).is_err());
    assert!(read(b"", &Limits::default()).is_err());
}

#[test]
fn the_demo_house_has_its_walls_and_slab() {
    // The viewer's browser tests open the same file (see the viewer's framing.test.ts).
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/viewer/house.ifc"
    ))
    .unwrap();
    let scene = read(&bytes, &Limits::default()).unwrap();
    let mut classes: Vec<&str> = scene.elements.iter().map(|e| e.class.as_str()).collect();
    classes.sort();
    assert_eq!(
        classes,
        ["IFCSLAB", "IFCWALL", "IFCWALL", "IFCWALL", "IFCWALL"]
    );
    let st = stats(&scene);
    // 12 x 8 x 0.3 slab.
    assert!((st["Ground slab"].volume - 28.8).abs() < 1e-4);
}
