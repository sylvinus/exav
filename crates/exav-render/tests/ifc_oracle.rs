//! exav-render's IFC meshes against web-ifc's, element by element.
//!
//! `EXAV_DEBUG_IFC_WEBIFC=<dir>` names an installed web-ifc package (run as
//! a black box in node by `tests/ifc_oracle/webifc_stats.mjs`; 0.0.77 was
//! used); without it the test only says it skipped. It reads every fixture
//! of `tests/fixtures/ifc/` and the `.ifc` files of `EXAV_DEBUG_IFC_CORPUS`
//! (a directory, one level down too), and compares per element: extents
//! within 2% of the element's size (plus 2 mm), surface area within 5%,
//! and, for a closed mesh, enclosed volume within 5%.
//!
//! A fixture element that differs fails the test unless [`EXPLAINED`] says
//! why the oracle is the one that is wrong (each reason checked against the
//! fixture's closed form in tests/ifc.rs). Corpus files are reported: an
//! agreement count per file and the elements that differ.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use exav_render::ifc::{read, Limits};
use serde_json::Value;

/// (fixture, element name, why web-ifc 0.0.77 differs). Each of these
/// elements matches its closed form in tests/ifc.rs.
const EXPLAINED: &[(&str, &str, &str)] = &[
    ("profiles.ifc", "rectangle hollow", "web-ifc's section is 0.0136 m2, the definition's 0.4 x 0.3 minus 0.36 x 0.26 is 0.0264"),
    ("profiles.ifc", "t shape", "web-ifc's section is 0.0044 m2, flange plus web is 0.0063"),
    ("profiles.ifc", "z shape", "web-ifc draws it 0.1 wide; the figure's flanges are each FlangeWidth wide with the web, 0.19 overall"),
    ("profiles.ifc", "rounded rectangle", "web-ifc ignores RoundingRadius: square corners"),
    ("solids.ifc", "tapered", "web-ifc ignores EndSweptArea: a straight prism"),
    ("solids.ifc", "swept disk", "web-ifc ignores InnerRadius: no inner surface"),
    ("solids.ifc", "surface curve swept", "web-ifc's solid is 0.16 m3 for a 0.2 x 0.4 section along 3 m"),
    ("solids.ifc", "fixed reference swept", "web-ifc's solid is flat (no volume)"),
    ("mapped_units.ifc", "revolved degrees", "web-ifc's quarter tube is 0.272 m3; Pappus gives 0.346"),
];

struct Stat {
    name: String,
    class: String,
    min: [f64; 3],
    max: [f64; 3],
    area: f64,
    volume: f64,
    closed: bool,
}

fn ours(bytes: &[u8]) -> HashMap<u32, Stat> {
    let s = read(bytes, &Limits::default()).unwrap();
    let mut out = HashMap::new();
    for e in &s.elements {
        let mut st = Stat {
            name: e.name.clone(),
            class: e.class.clone(),
            min: [f64::INFINITY; 3],
            max: [f64::NEG_INFINITY; 3],
            area: 0.0,
            volume: 0.0,
            closed: true,
        };
        let mut edges: HashMap<([u32; 3], [u32; 3]), u32> = HashMap::new();
        let mut reference: Option<[f64; 3]> = None;
        for r in &e.ranges {
            let b = &s.batches[r.batch as usize];
            let p = |i: u32| {
                let k = i as usize * 3;
                [
                    b.positions[k] as f64,
                    b.positions[k + 1] as f64,
                    b.positions[k + 2] as f64,
                ]
            };
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
                let o = *reference.get_or_insert(a);
                let [a, bb, c] = [a, bb, c].map(|q| [q[0] - o[0], q[1] - o[1], q[2] - o[2]]);
                st.volume += (a[0] * (bb[1] * c[2] - bb[2] * c[1])
                    + a[1] * (bb[2] * c[0] - bb[0] * c[2])
                    + a[2] * (bb[0] * c[1] - bb[1] * c[0]))
                    / 6.0;
                for (x, y) in [(t[0], t[1]), (t[1], t[2]), (t[2], t[0])] {
                    let (kx, ky) = (key(x), key(y));
                    *edges
                        .entry(if kx < ky { (kx, ky) } else { (ky, kx) })
                        .or_insert(0) += 1;
                }
            }
        }
        st.closed = edges.values().all(|&n| n == 2);
        out.insert(e.id, st);
    }
    out
}

fn oracle(dir: &str, file: &Path) -> Option<HashMap<u32, Stat>> {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/ifc_oracle/webifc_stats.mjs"
    );
    let out = Command::new("node")
        .arg(script)
        .arg(dir)
        .arg(file)
        .output()
        .ok()?;
    let mut map = HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let arr = |k: &str| -> [f64; 3] { [0, 1, 2].map(|i| v[k][i].as_f64().unwrap_or(f64::NAN)) };
        map.insert(
            v["id"].as_u64()? as u32,
            Stat {
                name: String::new(),
                class: v["class"].as_str()?.to_string(),
                min: arr("min"),
                max: arr("max"),
                area: v["area"].as_f64()?,
                volume: v["volume"].as_f64()?,
                closed: true,
            },
        );
    }
    Some(map)
}

/// Why `a` (ours) and `b` (the oracle's) differ, if they do.
fn differ(a: &Stat, b: &Stat) -> Option<String> {
    let size = (0..3).map(|k| b.max[k] - b.min[k]).fold(1e-6, f64::max);
    let extents = (0..3)
        .map(|k| (a.min[k] - b.min[k]).abs().max((a.max[k] - b.max[k]).abs()))
        .fold(0.0, f64::max);
    if extents > 0.02 * size + 0.002 {
        return Some(format!("extents off by {extents:.4}"));
    }
    let area = (a.area - b.area).abs() / b.area.max(1e-12);
    if area > 0.05 {
        return Some(format!("area {:.4} vs {:.4}", a.area, b.area));
    }
    let volume = (a.volume.abs() - b.volume.abs()).abs() / b.volume.abs().max(1e-12);
    if a.closed && volume > 0.05 && b.volume.abs() > 1e-9 * size.powi(3) {
        return Some(format!("volume {:.6} vs {:.6}", a.volume, b.volume));
    }
    None
}

fn files() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> =
        std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ifc"))
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "ifc"))
            .collect();
    out.sort();
    out
}

fn corpus() -> Vec<PathBuf> {
    let Ok(dir) = std::env::var("EXAV_DEBUG_IFC_CORPUS") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut dirs = vec![PathBuf::from(dir)];
    let mut depth = 0;
    while let (Some(d), true) = (dirs.pop(), depth < 64) {
        depth += 1;
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("ifc")) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn elements_agree_with_web_ifc() {
    let Ok(dir) = std::env::var("EXAV_DEBUG_IFC_WEBIFC") else {
        eprintln!("skipped: EXAV_DEBUG_IFC_WEBIFC is not set");
        return;
    };
    let mut failures = Vec::new();
    let (mut agree, mut total, mut only_ours, mut only_theirs) = (0, 0, 0, 0);
    let fixtures: HashSet<PathBuf> = files().into_iter().collect();
    for file in files().into_iter().chain(corpus()) {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = std::fs::read(&file).unwrap();
        let ours = ours(&bytes);
        let Some(theirs) = oracle(&dir, &file) else {
            eprintln!("{name}: the oracle did not run");
            continue;
        };
        let (mut a, mut n) = (0, 0);
        let mut ids: Vec<&u32> = ours.keys().collect();
        ids.sort();
        for id in ids {
            let o = &ours[id];
            let Some(t) = theirs.get(id) else {
                only_ours += 1;
                eprintln!("  {name} #{id} {}: only ours", o.class);
                continue;
            };
            n += 1;
            match differ(o, t) {
                None => a += 1,
                Some(why) => {
                    let explained = EXPLAINED
                        .iter()
                        .find(|(f, n, _)| *f == name && *n == o.name);
                    eprintln!(
                        "  {name} #{id} {}: {why}{}",
                        o.class,
                        explained.map_or(String::new(), |e| format!(" (explained: {})", e.2))
                    );
                    if fixtures.contains(&file) && explained.is_none() {
                        failures.push(format!("{name} #{id} {}: {why}", o.class));
                    }
                }
            }
        }
        for (id, t) in &theirs {
            if !ours.contains_key(id) {
                only_theirs += 1;
                eprintln!("  {name} #{id} {}: only web-ifc", t.class);
            }
        }
        eprintln!("{name}: {a}/{n} agree");
        agree += a;
        total += n;
    }
    eprintln!("total: {agree}/{total} elements agree; {only_ours} drawn only by exav, {only_theirs} only by web-ifc");
    assert!(
        failures.is_empty(),
        "unexplained differences in the fixtures:\n{}",
        failures.join("\n")
    );
}
