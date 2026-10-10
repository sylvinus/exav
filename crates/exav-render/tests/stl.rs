//! The STL reader against `tests/fixtures/stl/make.py`'s files: facets
//! counted, extents, enclosed volume, the two colour conventions, binary
//! files whose header says "solid", and damaged counts.

use std::path::Path;

use exav_render::stl::read;
use serde_json::Value;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/stl");

#[test]
fn every_fixture_reads_as_written() {
    let text = std::fs::read_to_string(Path::new(DIR).join("expected.json")).unwrap();
    let expected: Value = serde_json::from_str(&text).unwrap();
    for (file, e) in expected.as_object().unwrap() {
        let bytes = std::fs::read(Path::new(DIR).join(file)).unwrap();
        let s = read(&bytes, usize::MAX).unwrap_or_else(|err| panic!("{file}: {err}"));
        assert_eq!(
            s.triangles() as u64,
            e["triangles"].as_u64().unwrap(),
            "{file}"
        );
        assert_eq!(
            s.warnings.damaged,
            e.get("damaged").is_some_and(|d| d.as_bool().unwrap()),
            "{file}"
        );
        let b = s.batches.first().expect("one batch");
        if let (Some(lo), Some(hi)) = (e.get("min"), e.get("max")) {
            let bounds = s.bounds.unwrap();
            for k in 0..3 {
                assert_eq!(bounds[0][k] as f64, lo[k].as_f64().unwrap(), "{file}");
                assert_eq!(bounds[1][k] as f64, hi[k].as_f64().unwrap(), "{file}");
            }
        }
        if let Some(v) = e.get("volume") {
            let p = |i: u32| {
                let k = i as usize * 3;
                [
                    b.positions[k] as f64,
                    b.positions[k + 1] as f64,
                    b.positions[k + 2] as f64,
                ]
            };
            let volume: f64 = b
                .indices
                .as_chunks::<3>()
                .0
                .iter()
                .map(|t| {
                    let (a, bb, c) = (p(t[0]), p(t[1]), p(t[2]));
                    (a[0] * (bb[1] * c[2] - bb[2] * c[1])
                        + a[1] * (bb[2] * c[0] - bb[0] * c[2])
                        + a[2] * (bb[0] * c[1] - bb[1] * c[0]))
                        / 6.0
                })
                .sum();
            assert!(
                (volume - v.as_f64().unwrap()).abs() < 1e-9,
                "{file}: {volume}"
            );
            // Shaded flat, outward: each normal points away from the centre.
            for t in b.indices.as_chunks::<3>().0 {
                let k = t[0] as usize * 3;
                let n = [
                    b.normals[k] as f64,
                    b.normals[k + 1] as f64,
                    b.normals[k + 2] as f64,
                ];
                let c = p(t[0]);
                let out = (c[0] - 2.0) * n[0] + (c[1] - 2.5) * n[1] + (c[2] - 3.0) * n[2];
                assert!(out > 0.0, "{file}");
            }
        }
        match e.get("colors").and_then(Value::as_object) {
            Some(colors) => {
                let c = b
                    .colors
                    .as_ref()
                    .unwrap_or_else(|| panic!("{file}: no colours"));
                for (facet, rgb) in colors {
                    let k = facet.parse::<usize>().unwrap() * 9;
                    let want: Vec<u8> = rgb
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_u64().unwrap() as u8)
                        .collect();
                    assert_eq!(&c[k..k + 3], &want[..], "{file} facet {facet}");
                }
            }
            None => assert!(b.colors.is_none(), "{file}: colours"),
        }
    }
}

#[test]
fn the_demo_house_reads() {
    // The viewer's browser tests open the same file (see the viewer's framing.test.ts).
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/viewer/house.stl"
    ))
    .unwrap();
    let s = read(&bytes, usize::MAX).unwrap();
    assert!(s.triangles() > 0);
    assert!(!s.warnings.damaged);
}
