//! Curved B-rep faces, sweep parameters, alignments, grid placements and
//! storeys of the IFC reader, against the fixtures `tests/fixtures/ifc/make.py`
//! writes. Their volumes, areas and extents are in `expected.json` and
//! checked by `tests/ifc.rs`; here, where the points of each mesh lie.
//! Hostile files are in `tests/ifc_hostile.rs`.

use std::path::Path;

use exav_render::ifc::{Limits, read};
use exav_render::mesh::Scene;
use serde_json::Value;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ifc");

type P = [f64; 3];

fn load(name: &str) -> Scene {
    let bytes = std::fs::read(Path::new(DIR).join(name)).unwrap();
    read(&bytes, &Limits::default()).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn expected(file: &str) -> Value {
    let text = std::fs::read_to_string(Path::new(DIR).join("expected.json")).unwrap();
    serde_json::from_str::<Value>(&text).unwrap()[file].clone()
}

/// The vertices of the element called `name`, in model coordinates.
fn vertices(s: &Scene, name: &str) -> Vec<P> {
    let e = s
        .elements
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("{name} is not drawn"));
    let mut out = Vec::new();
    for r in &e.ranges {
        let b = &s.batches[r.batch as usize];
        for &i in &b.indices[r.first as usize..(r.first + r.count) as usize] {
            let k = i as usize * 3;
            out.push([
                f64::from(b.positions[k]) + s.origin[0],
                f64::from(b.positions[k + 1]) + s.origin[1],
                f64::from(b.positions[k + 2]) + s.origin[2],
            ]);
        }
    }
    out
}

fn dist(a: P, b: P) -> f64 {
    ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2) + (a[2] - b[2]).powi(2)).sqrt()
}

/// How many distinct values `f` takes over the points, to a thousandth.
fn distinct(pts: &[P], f: impl Fn(P) -> f64) -> usize {
    let mut v: Vec<i64> = pts
        .iter()
        .map(|p| (f(*p) * 1000.0).round() as i64)
        .collect();
    v.sort_unstable();
    v.dedup();
    v.len()
}

#[test]
fn the_caps_of_a_sphere_have_every_vertex_on_it_at_many_latitudes() {
    let s = load("curved_faces.ifc");
    for (name, centre, sign) in [
        ("hemisphere", [0.0; 3], 1.0),
        ("bowl", [10.0, 0.0, 0.0], -1.0),
    ] {
        let pts = vertices(&s, name);
        for p in &pts {
            // f32 positions: a millionth of the radius.
            assert!((dist(*p, centre) - 2.0).abs() < 1e-5, "{name}: {p:?}");
            assert!(sign * p[2] >= -1e-5, "{name}: {p:?} on the wrong side");
        }
        // A flat disk would have one latitude, a cap has a ring each 11 degrees.
        assert!(distinct(&pts, |p| p[2]) >= 8, "{name}");
        // And the pole itself.
        assert!(
            pts.iter().any(|p| (p[2] - sign * 2.0).abs() < 1e-5),
            "{name}: no pole"
        );
    }
}

#[test]
fn a_patch_of_a_sphere_lies_on_it_between_its_parallels_and_meridians() {
    let s = load("curved_faces.ifc");
    let pts = vertices(&s, "sphere patch");
    let c = [20.0, 0.0, 0.0];
    for p in &pts {
        assert!((dist(*p, c) - 2.0).abs() < 1e-5, "{p:?}");
        let (x, y) = (p[0] - 20.0, p[1]);
        assert!(x >= -1e-5 && y >= -1e-5, "{p:?} outside the meridians");
        let lat = (p[2] / 2.0).asin();
        assert!(
            (0.3 - 1e-5..=0.9 + 1e-5).contains(&lat),
            "{p:?} latitude {lat}"
        );
    }
    assert!(distinct(&pts, |p| p[2]) >= 4);
}

#[test]
fn a_cap_cut_by_a_tilted_circle_is_bent_over_the_sphere_not_a_flat_polygon() {
    let s = load("curved_faces.ifc");
    for (name, x, cos_alpha) in [
        ("tilted cap", 70.0, 0.9),
        ("tilted cap with the pole", 80.0, 0.6),
    ] {
        let pts = vertices(&s, name);
        for p in &pts {
            assert!(
                (dist(*p, [x, 0.0, 0.0]) - 2.0).abs() < 1e-5,
                "{name}: {p:?}"
            );
            // Inside the circle: nearer than its edge to its axis.
            let n = 0.5f64.sqrt();
            let along = ((p[0] - x) * n + p[2] * n) / 2.0;
            // Points added along the rim are on the sphere between two of
            // its 32 samples (straight in the parameters, which bends near
            // a pole): up to a hundredth of the radius off the circle.
            assert!(
                along >= cos_alpha - 3e-2,
                "{name}: {p:?} outside the circle ({along})"
            );
        }
        // A flat polygon through the rim would have no vertex above it.
        let top = pts
            .iter()
            .map(|p| ((p[0] - x) * 0.5f64.sqrt() + p[2] * 0.5f64.sqrt()) / 2.0)
            .fold(0.0, f64::max);
        assert!(
            top > 0.999,
            "{name}: the middle of the cap is missing ({top})"
        );
    }
}

#[test]
fn a_quarter_torus_has_every_vertex_on_the_torus() {
    let s = load("curved_faces.ifc");
    let pts = vertices(&s, "torus elbow");
    for p in &pts {
        let rho = ((p[0] - 30.0).powi(2) + p[1].powi(2)).sqrt();
        let off = ((rho - 3.0).powi(2) + p[2].powi(2)).sqrt();
        assert!(
            (off - 1.0).abs() < 1e-5,
            "{p:?} is {off} from the axis circle"
        );
        assert!(
            p[0] >= 30.0 - 1e-5 && p[1] >= -1e-5,
            "{p:?} outside the quarter"
        );
    }
    // Round the tube, not along a chord through it.
    assert!(distinct(&pts, |p| p[2]) >= 16);
}

#[test]
fn a_tube_bounded_by_two_circles_is_a_cylinder() {
    let s = load("curved_faces.ifc");
    let pts = vertices(&s, "tube without seam");
    for p in &pts {
        let r = ((p[0] - 40.0).powi(2) + p[1].powi(2)).sqrt();
        assert!(
            (r - 1.5).abs() < 1e-5,
            "{p:?}: the disks only use their rims"
        );
    }
    assert!(pts.iter().any(|p| (p[2] - 4.0).abs() < 1e-5));
}

#[test]
fn a_trimmed_spline_face_is_the_part_inside_its_edges() {
    let s = load("curved_faces.ifc");
    let pts = vertices(&s, "spline patch");
    for p in &pts {
        let (x, y) = (p[0] - 50.0, p[1]);
        assert!(
            ((x * x + y * y).sqrt() - 2.0).abs() < 1e-5,
            "{p:?} is off the cylinder"
        );
        let deg = y.atan2(x).to_degrees();
        assert!(
            (15.0 - 1e-3..=75.0 + 1e-3).contains(&deg),
            "{p:?} at {deg} degrees"
        );
        assert!((1.0 - 1e-5..=4.0 + 1e-5).contains(&p[2]), "{p:?}");
    }
    assert!(pts.iter().any(|p| (p[2] - 1.0).abs() < 1e-5));
}

#[test]
fn a_spline_face_with_a_hole_has_no_vertex_inside_it() {
    let s = load("curved_faces.ifc");
    let pts = vertices(&s, "plate with hole");
    let from_centre = |p: &P| ((p[0] - 62.0).powi(2) + (p[1] - 2.0).powi(2)).sqrt();
    for p in &pts {
        assert!(from_centre(p) >= 1.0 - 1e-5, "{p:?} is inside the hole");
        assert!((0.5 - 1e-5..=3.5 + 1e-5).contains(&p[1]), "{p:?}");
    }
    // Some are on the hole's rim.
    assert!(pts.iter().any(|p| from_centre(p) < 1.0 + 1e-5));
}

#[test]
fn the_curved_faces_are_all_drawn_curved() {
    // Nothing fell back to the flat polygon through the edges.
    let s = load("curved_faces.ifc");
    assert!(s.warnings.unsupported.is_empty(), "{:?}", s.warnings);
}

/// The height of the fixture's profile at distance `x`.
fn height(x: f64) -> f64 {
    if x <= 200.0 {
        10.0 + 0.02 * x
    } else {
        14.0 - 0.01 * (x - 200.0)
    }
}

#[test]
fn an_alignment_passes_through_its_stations() {
    let s = load("alignment.ifc");
    let exp = expected("alignment.ifc");
    let st = &exp["stations"];
    let at = |k: &str| (st[k][0].as_f64().unwrap(), st[k][1].as_f64().unwrap());
    let pts = vertices(&s, "tube whole");
    let radius = exp["tube_radius"].as_f64().unwrap();
    // The curve's points are the centres of rings of points a radius off:
    // each station is a distance along, so its height is known.
    for (key, along) in [
        ("line_end", 100.0),
        ("clothoid_end", 160.0),
        ("left_arc_end", 280.0),
        // Half way round the right turn, a negative segment length.
        ("right_arc_mid", 330.0),
        ("right_arc_end", 380.0),
        ("end", 430.0),
    ] {
        let (x, y) = at(key);
        let c = [x, y, height(along)];
        let ring = pts
            .iter()
            .filter(|p| (dist(**p, c) - radius).abs() < 0.01)
            .count();
        assert!(ring >= 14, "{key} {c:?}: {ring} points a radius from it");
        // The last line runs along x again after the right turn: the end
        // of the tube is a disk square to it.
        if key == "end" {
            let cap: Vec<&P> = pts
                .iter()
                .filter(|p| (dist(**p, c) - radius).abs() < 0.01)
                .collect();
            assert!(cap.iter().all(|p| (p[0] - x).abs() < 0.01), "{cap:?}");
        }
        // The station is on the axis: the tube is never nearer than its radius.
        let nearest = pts
            .iter()
            .map(|p| dist(*p, c))
            .fold(f64::INFINITY, f64::min);
        assert!(
            nearest >= radius - 0.01,
            "{key} {c:?}: the tube comes within {nearest}"
        );
    }
}

#[test]
fn the_clothoid_ends_at_the_heading_the_arc_after_it_starts_with() {
    // A^2 = 300 * 60: the heading at its end is 60 / (2 * 300) = 0.1 radian,
    // so the ring of the tube there is square to a direction 0.1 off x.
    let s = load("alignment.ifc");
    let st = expected("alignment.ifc")["stations"].clone();
    let c = [
        st["clothoid_end"][0].as_f64().unwrap(),
        st["clothoid_end"][1].as_f64().unwrap(),
        height(160.0),
    ];
    let ring: Vec<P> = vertices(&s, "tube whole")
        .into_iter()
        .filter(|p| (dist(*p, c) - 0.5).abs() < 0.01)
        .collect();
    assert!(ring.len() >= 8);
    for p in &ring {
        let (dx, dy) = (p[0] - c[0], p[1] - c[1]);
        let along = dx * 0.1f64.cos() + dy * 0.1f64.sin();
        assert!(along.abs() < 0.03, "{p:?}: {along} along the heading");
    }
}

#[test]
fn a_linear_placement_without_a_cartesian_position_is_worked_out() {
    let s = load("alignment.ifc");
    let st = expected("alignment.ifc")["stations"].clone();
    let list = |k: &str| -> Vec<f64> {
        st[k]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_f64().unwrap())
            .collect()
    };
    let (at, half) = (list("column_at"), list("column_half"));
    let pts = vertices(&s, "column on the alignment");
    let (mut lo, mut hi) = ([f64::INFINITY; 3], [f64::NEG_INFINITY; 3]);
    for p in &pts {
        for k in 0..3 {
            lo[k] = lo[k].min(p[k]);
            hi[k] = hi[k].max(p[k]);
        }
    }
    // The curve is sampled finely for a placement: within a centimetre of
    // the arc.
    for k in 0..2 {
        assert!(
            ((lo[k] + hi[k]) / 2.0 - at[k]).abs() < 0.01,
            "{k}: {lo:?} {hi:?} {at:?}"
        );
        assert!(
            ((hi[k] - lo[k]) / 2.0 - half[k]).abs() < 0.01,
            "{k}: {lo:?} {hi:?} {half:?}"
        );
    }
    // Upright whatever the gradient.
    assert!((lo[2] - at[2]).abs() < 1e-3 && (hi[2] - at[2] - 4.0).abs() < 1e-3);
    assert!(s.warnings.unsupported.is_empty(), "{:?}", s.warnings);
}

#[test]
fn storeys_have_their_names_and_elevations_and_their_elements() {
    let s = load("storeys.ifc");
    let exp = expected("storeys.ifc");
    let storeys: Vec<(String, f64)> = s
        .nodes
        .iter()
        .filter(|n| n.class == "IFCBUILDINGSTOREY")
        .map(|n| {
            (
                n.name.clone(),
                n.elevation.expect("a storey has an elevation"),
            )
        })
        .collect();
    let want: Vec<(String, f64)> = exp["storeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v[0].as_str().unwrap().to_string(), v[1].as_f64().unwrap()))
        .collect();
    assert_eq!(storeys.len(), want.len());
    for (name, z) in &want {
        let got = storeys
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("{name}"));
        // Millimetres in the file, metres out.
        assert!((got.1 - z).abs() < 1e-9, "{name}: {}", got.1);
    }
    // Only storeys have one.
    assert!(
        s.nodes
            .iter()
            .filter(|n| n.class != "IFCBUILDINGSTOREY")
            .all(|n| n.elevation.is_none())
    );
    for (name, storey) in exp["membership"].as_object().unwrap() {
        let e = s
            .elements
            .iter()
            .find(|e| &e.name == name)
            .unwrap_or_else(|| panic!("{name}"));
        match storey.as_str() {
            Some(w) => {
                let k = e.storey.unwrap_or_else(|| panic!("{name} has no storey"));
                assert_eq!(s.nodes[k as usize].name, w, "{name}");
                assert_eq!(s.nodes[k as usize].class, "IFCBUILDINGSTOREY");
            }
            None => assert_eq!(e.storey, None, "{name}"),
        }
    }
    // The table is in the room, which is in level 1.
    let table = s.elements.iter().find(|e| e.name == "table").unwrap();
    assert_eq!(s.nodes[table.node.unwrap() as usize].class, "IFCSPACE");
}

#[test]
fn a_batch_holds_the_elements_of_one_storey() {
    // So that hiding a storey hides batches, edges included.
    let s = load("storeys.ifc");
    for e in &s.elements {
        for r in &e.ranges {
            assert_eq!(s.batches[r.batch as usize].storey, e.storey, "{}", e.name);
        }
    }
    // The three walls are one class and colour in three storeys.
    let walls: Vec<_> = s.batches.iter().filter(|b| b.class == "IFCWALL").collect();
    assert_eq!(walls.len(), 3);
}

#[test]
fn elements_contained_in_a_storey_have_it() {
    let s = load("solids.ifc");
    assert!(s.elements.iter().all(|e| e.storey == e.node));
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/viewer/house.ifc"
    ))
    .unwrap();
    let h = read(&bytes, &Limits::default()).unwrap();
    assert!(h.nodes.iter().any(|n| n.class == "IFCBUILDINGSTOREY"));
    assert!(h.elements.iter().all(|e| e.storey.is_some()));
}
