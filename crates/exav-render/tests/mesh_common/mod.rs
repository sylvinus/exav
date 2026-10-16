//! Shared by the OBJ, PLY and glTF tests: the shapes they are built from,
//! and what is measured on a [`Scene`] to check it. The measures are
//! computed here from the output's triangles, not from anything a reader
//! reports.
#![allow(dead_code)]

use std::time::{Duration, Instant};

use exav_render::mesh::Scene;

pub type P = [f64; 3];

/// The unit cube's corners, and its six faces as quads, counterclockwise
/// seen from outside.
pub const CUBE: [P; 8] = [
    [0., 0., 0.],
    [1., 0., 0.],
    [1., 1., 0.],
    [0., 1., 0.],
    [0., 0., 1.],
    [1., 0., 1.],
    [1., 1., 1.],
    [0., 1., 1.],
];
pub const CUBE_QUADS: [[usize; 4]; 6] = [
    [0, 3, 2, 1],
    [4, 5, 6, 7],
    [0, 1, 5, 4],
    [1, 2, 6, 5],
    [2, 3, 7, 6],
    [3, 0, 4, 7],
];

/// A tetrahedron of volume 1/6 and its four faces, outward.
pub const TETRA: [P; 4] = [[0., 0., 0.], [1., 0., 0.], [0., 1., 0.], [0., 0., 1.]];
pub const TETRA_FACES: [[usize; 3]; 4] = [[0, 2, 1], [0, 1, 3], [0, 3, 2], [1, 2, 3]];

/// Every triangle of the scene, from its corners.
pub fn triangles(s: &Scene) -> Vec<[P; 3]> {
    let mut out = Vec::new();
    for b in &s.batches {
        let p = |i: u32| {
            let k = i as usize * 3;
            [
                f64::from(b.positions[k]),
                f64::from(b.positions[k + 1]),
                f64::from(b.positions[k + 2]),
            ]
        };
        for t in b.indices.chunks(3) {
            out.push([p(t[0]), p(t[1]), p(t[2])]);
        }
    }
    out
}

fn cross(a: P, b: P) -> P {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}

fn sub(a: P, b: P) -> P {
    [a[0] - b[0], a[1] - b[1], a[2] - b[2]]
}

/// The volume a closed, outward-wound mesh encloses.
pub fn volume(s: &Scene) -> f64 {
    triangles(s)
        .iter()
        .map(|t| {
            let c = cross(t[1], t[2]);
            (t[0][0] * c[0] + t[0][1] * c[1] + t[0][2] * c[2]) / 6.0
        })
        .sum()
}

/// The sum of the triangles' areas.
pub fn area(s: &Scene) -> f64 {
    triangles(s)
        .iter()
        .map(|t| {
            let n = cross(sub(t[1], t[0]), sub(t[2], t[0]));
            (n[0] * n[0] + n[1] * n[1] + n[2] * n[2]).sqrt() / 2.0
        })
        .sum()
}

/// Smallest and largest corner, from the triangles.
pub fn extent(s: &Scene) -> [P; 2] {
    let mut lo = [f64::INFINITY; 3];
    let mut hi = [f64::NEG_INFINITY; 3];
    for t in triangles(s) {
        for p in t {
            for k in 0..3 {
                lo[k] = lo[k].min(p[k]);
                hi[k] = hi[k].max(p[k]);
            }
        }
    }
    [lo, hi]
}

pub fn near(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-5
}

pub fn assert_near(a: f64, b: f64, what: &str) {
    assert!(near(a, b), "{what}: {a} against {b}");
}

/// What a scene must always satisfy, however hostile the input: indices in
/// range, everything finite, bounds that match the triangles, normals of
/// unit length, elements inside the batch.
pub fn assert_sound(s: &Scene) {
    for b in &s.batches {
        assert_eq!(b.positions.len(), b.normals.len());
        assert_eq!(b.indices.len() % 3, 0);
        let vertices = (b.positions.len() / 3) as u32;
        assert!(b.indices.iter().all(|&i| i < vertices));
        assert!(b.positions.iter().all(|v| v.is_finite()));
        for n in b.normals.chunks(3) {
            let len = n.iter().map(|v| v * v).sum::<f32>().sqrt();
            assert!((len - 1.0).abs() < 1e-3, "normal {n:?}");
        }
        if let Some(c) = &b.colors {
            assert_eq!(c.len(), b.positions.len());
        }
    }
    for e in &s.elements {
        for r in &e.ranges {
            let b = &s.batches[r.batch as usize];
            assert!((r.first + r.count) as usize <= b.indices.len());
            assert_eq!(r.first % 3, 0);
            assert_eq!(r.count % 3, 0);
        }
    }
    if let Some(b) = s.bounds {
        assert!(b.iter().flatten().all(|v| v.is_finite()));
    }
    if s.triangles() > 0 {
        let [lo, hi] = extent(s);
        let b = s.bounds.expect("bounds");
        for k in 0..3 {
            assert_eq!(f64::from(b[0][k]), lo[k]);
            assert_eq!(f64::from(b[1][k]), hi[k]);
        }
    }
}

/// Runs `f` and fails if it takes longer than `limit`. Debug builds are
/// slow: the limits are for hanging, not for speed.
pub fn within<T>(limit: Duration, what: &str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    let took = start.elapsed();
    assert!(took < limit, "{what} took {took:?}");
    out
}

/// Feeds `read` the file cut at every length, and with every byte, and
/// every aligned four bytes, set to extreme values. A reader that panics
/// fails the test; what it answers is checked to be sound.
pub fn sweep(bytes: &[u8], read: impl Fn(&[u8]) -> Option<Scene>) {
    let check = |data: &[u8]| {
        if let Some(s) = read(data) {
            assert_sound(&s);
        }
    };
    for len in 0..bytes.len() {
        check(&bytes[..len]);
    }
    let mut copy = bytes.to_vec();
    for i in 0..bytes.len() {
        for v in [0x00, 0xff, 0x7f, 0x80] {
            copy[i] = v;
            check(&copy);
        }
        copy[i] = bytes[i];
    }
    for i in 0..bytes.len().saturating_sub(3) {
        for v in [0xff, 0x7f] {
            copy[i..i + 4].fill(v);
            check(&copy);
        }
        copy[i..i + 4].copy_from_slice(&bytes[i..i + 4]);
    }
}
