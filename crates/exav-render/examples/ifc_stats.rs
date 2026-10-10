//! Per-element statistics of an IFC (or STL) file as JSON, one line per
//! element: `{"id", "class", "triangles", "min", "max", "area", "volume"}`
//! in metres, model coordinates; then a last line with the warnings.
//! Used to compare with another reader (tests/ifc_oracle/).
//!
//! `cargo run --release --example ifc_stats --features ifc,stl -- FILE`

use exav_render::mesh::Scene;

fn main() {
    let path = std::env::args().nth(1).expect("usage: ifc_stats FILE");
    let bytes = std::fs::read(&path).expect("read");
    let started = std::time::Instant::now();
    let scene = if path.to_ascii_lowercase().ends_with(".stl") {
        exav_render::stl::read(&bytes, usize::MAX).expect("stl")
    } else {
        exav_render::ifc::read(&bytes, &exav_render::ifc::Limits::default()).expect("ifc")
    };
    let ms = started.elapsed().as_millis();
    print_stats(&scene);
    println!(
        "{{\"warnings\":{},\"elements\":{},\"triangles\":{},\"ms\":{}}}",
        warnings(&scene),
        scene.elements.len(),
        scene.triangles(),
        ms
    );
}

fn warnings(s: &Scene) -> String {
    let unsupported: Vec<String> = s
        .warnings
        .unsupported
        .iter()
        .map(|(k, v)| format!("\"{k}\":{v}"))
        .collect();
    format!(
        "{{\"unsupported\":{{{}}},\"invalid\":{},\"booleans_skipped\":{},\"truncated\":{},\"damaged\":{}}}",
        unsupported.join(","),
        s.warnings.invalid,
        s.warnings.booleans_skipped,
        s.warnings.truncated,
        s.warnings.damaged
    )
}

fn print_stats(s: &Scene) {
    for e in &s.elements {
        let mut lo = [f64::INFINITY; 3];
        let mut hi = [f64::NEG_INFINITY; 3];
        let (mut area, mut volume, mut triangles) = (0.0f64, 0.0f64, 0usize);
        let mut reference: Option<[f64; 3]> = None;
        let mut edges: std::collections::HashMap<([u32; 3], [u32; 3]), u32> =
            std::collections::HashMap::new();
        for r in &e.ranges {
            let b = &s.batches[r.batch as usize];
            let p = |i: u32| -> [f64; 3] {
                let k = i as usize * 3;
                [
                    b.positions[k] as f64 + s.origin[0],
                    b.positions[k + 1] as f64 + s.origin[1],
                    b.positions[k + 2] as f64 + s.origin[2],
                ]
            };
            for t in b.indices[r.first as usize..(r.first + r.count) as usize]
                .as_chunks::<3>()
                .0
            {
                let (a, bb, c) = (p(t[0]), p(t[1]), p(t[2]));
                for q in [a, bb, c] {
                    for (k, v) in q.iter().enumerate() {
                        lo[k] = lo[k].min(*v);
                        hi[k] = hi[k].max(*v);
                    }
                }
                let u = [bb[0] - a[0], bb[1] - a[1], bb[2] - a[2]];
                let v = [c[0] - a[0], c[1] - a[1], c[2] - a[2]];
                let n = [
                    u[1] * v[2] - u[2] * v[1],
                    u[2] * v[0] - u[0] * v[2],
                    u[0] * v[1] - u[1] * v[0],
                ];
                area += (n[0] * n[0] + n[1] * n[1] + n[2] * n[2]).sqrt() / 2.0;
                // Relative to one point of the element, for precision.
                let o = *reference.get_or_insert(a);
                let (a, bb, c) = (sub(a, o), sub(bb, o), sub(c, o));
                volume += (a[0] * (bb[1] * c[2] - bb[2] * c[1])
                    + a[1] * (bb[2] * c[0] - bb[0] * c[2])
                    + a[2] * (bb[0] * c[1] - bb[1] * c[0]))
                    / 6.0;
                triangles += 1;
            }
            // Edges by the bits of their corners, both ways.
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
                    let (kx, ky) = (key(x), key(y));
                    *edges
                        .entry(if kx < ky { (kx, ky) } else { (ky, kx) })
                        .or_insert(0) += 1;
                }
            }
        }
        // Closed: every edge between exactly two triangles.
        let closed = !edges.is_empty() && edges.values().all(|&n| n == 2);
        println!(
            "{{\"id\":{},\"class\":\"{}\",\"triangles\":{},\"min\":[{},{},{}],\"max\":[{},{},{}],\"area\":{},\"volume\":{},\"closed\":{}}}",
            e.id, e.class, triangles, lo[0], lo[1], lo[2], hi[0], hi[1], hi[2], area, volume, closed
        );
    }
}

fn sub(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}
