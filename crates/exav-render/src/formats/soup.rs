//! What the OBJ, PLY and glTF readers build their [`Scene`] with: polygons
//! in, one batch of flat or file-shaded triangles out, one [`Element`] per
//! group, object or node.
//!
//! The triangles are not welded: each has three vertices of its own, as in
//! the STL reader, so that a hostile file cannot make the reader do more than
//! linear work in the triangles it emits.

// Each reader uses some of the helpers.
#![allow(dead_code)]

use super::mesh::{Batch, Element, Range, Scene, cross, dot, sub};

/// Elements a scene may hold. Past them the triangles join the last one:
/// a file of a million one-face groups would otherwise hold a million names.
pub(crate) const MAX_ELEMENTS: usize = 10_000;

/// Characters of an element's name kept.
pub(crate) const MAX_NAME: usize = 128;

/// Largest coordinate kept. A vertex beyond it, or not a number, drops the
/// triangles it is in: one of them would send the viewer's camera to
/// infinity.
pub(crate) const MAX_COORD: f64 = 1e12;

/// Polygons of at most this many corners are ear-clipped; larger ones are
/// fanned from their first corner, which is linear.
const EAR_MAX: usize = 64;

/// Steps of ear-clipping a scene may spend. A polygon needs about its
/// corners squared, so the polygons of a file cost at most this much in
/// all; after it every polygon is fanned.
const EAR_WORK: u64 = 20_000_000;

/// The colour of a triangle without one, among coloured ones.
const NO_COLOR: [u8; 3] = [200, 200, 200];

/// One corner of a polygon, as the file gives it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Corner {
    pub p: [f32; 3],
    /// Not necessarily of unit length, or finite; those are not used.
    pub n: Option<[f32; 3]>,
    pub c: Option<[u8; 3]>,
}

/// Collects triangles within a budget.
pub(crate) struct Soup {
    batch: Batch,
    colors: Vec<u8>,
    elements: Vec<Element>,
    /// The name of the element the next triangle starts, if one is due.
    pending: Option<String>,
    max: usize,
    triangles: usize,
    work: u64,
    pub truncated: bool,
    /// Polygons with a corner out of range, and indices out of range, as the
    /// caller reports them.
    pub invalid: u32,
}

impl Soup {
    pub fn new(max_triangles: usize) -> Self {
        // Indices are `u32`: three vertices per triangle.
        let max = max_triangles.min(u32::MAX as usize / 3 - 1);
        Self {
            batch: Batch::default(),
            colors: Vec::new(),
            elements: Vec::new(),
            pending: Some(String::new()),
            max,
            triangles: 0,
            work: 0,
            truncated: false,
            invalid: 0,
        }
    }

    /// The next triangles belong to a new element called `name`; nothing is
    /// made of it if none follow.
    pub fn begin(&mut self, name: &str) {
        self.pending = Some(name.chars().take(MAX_NAME).collect());
    }

    pub fn triangles(&self) -> usize {
        self.triangles
    }

    pub fn full(&self) -> bool {
        self.triangles >= self.max
    }

    /// Adds the polygon as triangles. False once the budget is spent, which
    /// the caller takes as the end of the file.
    pub fn polygon(&mut self, corners: &[Corner]) -> bool {
        if corners.len() < 3 {
            return true;
        }
        if !corners.iter().all(|c| usable(c.p)) {
            self.invalid = self.invalid.saturating_add(1);
            return true;
        }
        if corners.len() == 3 {
            return self.emit(&corners[0], &corners[1], &corners[2]);
        }
        if corners.len() <= EAR_MAX
            && self.work < EAR_WORK
            && let Some(order) = self.ears(corners)
        {
            for t in order {
                if !self.emit(&corners[t[0]], &corners[t[1]], &corners[t[2]]) {
                    return false;
                }
            }
            return true;
        }
        for k in 1..corners.len() - 1 {
            if !self.emit(&corners[0], &corners[k], &corners[k + 1]) {
                return false;
            }
        }
        true
    }

    /// Triangles that cover a simple polygon, or `None` for a polygon that
    /// has no area or that ear-clipping cannot finish (self-intersecting).
    fn ears(&mut self, c: &[Corner]) -> Option<Vec<[usize; 3]>> {
        let p: Vec<[f64; 3]> = c.iter().map(|c| c.p.map(f64::from)).collect();
        // Newell's normal: the plane to flatten the polygon into.
        let mut n = [0.0f64; 3];
        for i in 0..p.len() {
            let (a, b) = (p[i], p[(i + 1) % p.len()]);
            n[0] += (a[1] - b[1]) * (a[2] + b[2]);
            n[1] += (a[2] - b[2]) * (a[0] + b[0]);
            n[2] += (a[0] - b[0]) * (a[1] + b[1]);
        }
        let axis = (0..3)
            .max_by(|&i, &j| n[i].abs().total_cmp(&n[j].abs()))
            .unwrap_or(2);
        if !n[axis].is_finite() || n[axis] == 0.0 {
            return None;
        }
        let (u, v) = ((axis + 1) % 3, (axis + 2) % 3);
        let flip = if n[axis] < 0.0 { -1.0 } else { 1.0 };
        let q: Vec<[f64; 2]> = p.iter().map(|p| [p[u] * flip, p[v]]).collect();
        // Twice the signed area of a, b, c: positive when counterclockwise.
        let area = |a: [f64; 2], b: [f64; 2], c: [f64; 2]| {
            (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])
        };
        let mut ring: Vec<usize> = (0..q.len()).collect();
        let mut out = Vec::with_capacity(q.len() - 2);
        while ring.len() > 3 {
            let m = ring.len();
            let mut clipped = false;
            for i in 0..m {
                self.work = self.work.saturating_add(m as u64);
                if self.work >= EAR_WORK {
                    return None;
                }
                let (a, b, c) = (ring[(i + m - 1) % m], ring[i], ring[(i + 1) % m]);
                if area(q[a], q[b], q[c]) <= 0.0 {
                    continue;
                }
                let inside = ring.iter().any(|&o| {
                    if o == a || o == b || o == c || q[o] == q[a] || q[o] == q[b] || q[o] == q[c] {
                        return false;
                    }
                    area(q[a], q[b], q[o]) >= 0.0
                        && area(q[b], q[c], q[o]) >= 0.0
                        && area(q[c], q[a], q[o]) >= 0.0
                });
                if !inside {
                    out.push([a, b, c]);
                    ring.remove(i);
                    clipped = true;
                    break;
                }
            }
            if !clipped {
                return None;
            }
        }
        out.push([ring[0], ring[1], ring[2]]);
        Some(out)
    }

    /// One triangle. False once the budget is spent; a triangle with no
    /// area is dropped without a word.
    fn emit(&mut self, a: &Corner, b: &Corner, c: &Corner) -> bool {
        if self.triangles >= self.max {
            self.truncated = true;
            return false;
        }
        let p = [a, b, c].map(|c| c.p.map(f64::from));
        let flat = cross(sub(p[1], p[0]), sub(p[2], p[0]));
        let len = dot(flat, flat).sqrt();
        if !len.is_finite() || len <= 0.0 {
            return true;
        }
        let flat = flat.map(|v| v / len);
        if self.pending.is_some() {
            self.open();
        }
        let base = (self.batch.positions.len() / 3) as u32;
        let any_color = [a, b, c].iter().any(|c| c.c.is_some());
        if any_color && self.colors.is_empty() {
            // The vertices before this one had none.
            for _ in 0..self.batch.positions.len() / 3 {
                self.colors.extend_from_slice(&NO_COLOR);
            }
        }
        for corner in [a, b, c] {
            self.batch.positions.extend_from_slice(&corner.p);
            let n = corner.n.and_then(unit).unwrap_or(flat.map(|v| v as f32));
            self.batch.normals.extend_from_slice(&n);
            if any_color || !self.colors.is_empty() {
                self.colors.extend_from_slice(&corner.c.unwrap_or(NO_COLOR));
            }
        }
        self.batch
            .indices
            .extend_from_slice(&[base, base + 1, base + 2]);
        self.triangles += 1;
        if let Some(r) = self.elements.last_mut().and_then(|e| e.ranges.first_mut()) {
            r.count += 3;
        }
        true
    }

    fn open(&mut self) {
        let name = self.pending.take().unwrap_or_default();
        if self.elements.len() >= MAX_ELEMENTS {
            return;
        }
        self.elements.push(Element {
            name,
            ranges: vec![Range {
                batch: 0,
                first: self.batch.indices.len() as u32,
                count: 0,
            }],
            ..Element::default()
        });
    }

    pub fn finish(mut self) -> Scene {
        let mut scene = Scene::default();
        if self.triangles > 0 {
            if !self.colors.is_empty() {
                self.batch.colors = Some(self.colors);
            }
            super::mesh::grow(&mut scene.bounds, &self.batch.positions);
            scene.batches.push(self.batch);
            scene.elements = self.elements;
        }
        scene.warnings.truncated = u32::from(self.truncated);
        scene.warnings.invalid = self.invalid;
        scene
    }
}

/// A coordinate that is a number of a size a camera can frame.
pub(crate) fn usable(p: [f32; 3]) -> bool {
    p.iter()
        .all(|&v| v.is_finite() && f64::from(v).abs() <= MAX_COORD)
}

/// The vector at unit length, or `None` for one that is zero or not finite.
fn unit(n: [f32; 3]) -> Option<[f32; 3]> {
    let n = n.map(f64::from);
    let len = dot(n, n).sqrt();
    (len.is_finite() && len > 1e-12).then(|| n.map(|v| (v / len) as f32))
}

/// A decimal number as text, or `None`.
pub(crate) fn number(token: &[u8]) -> Option<f64> {
    std::str::from_utf8(token).ok()?.parse().ok()
}

/// A colour component in 0..1 as a byte, clamped.
pub(crate) fn unit_byte(v: f64) -> u8 {
    (v.clamp(0.0, 1.0) * 255.0).round() as u8
}
