//! Clipping emitted geometry to a paper-space viewport boundary.
//!
//! A layout viewport shows model space through a window. Everything the model
//! draws outside that window has to be cut off, which happens after the
//! geometry is emitted rather than during the walk: the walk does not know
//! where an entity will land until its transform is applied.

/// The region a viewport keeps.
pub enum ClipShape {
    /// The common case: the viewport's own rectangle.
    Rect { min: [f64; 2], max: [f64; 2] },
    /// A non-rectangular clip boundary, as convex pieces plus its outline.
    ///
    /// Segments are cut against the outline, which handles concave shapes
    /// exactly. Triangles are cut against each piece, which needs the pieces to
    /// be convex; they come from the same band decomposition that fills hatches.
    Poly {
        outline: Vec<[f64; 2]>,
        pieces: Vec<[[f64; 2]; 3]>,
        min: [f64; 2],
        max: [f64; 2],
    },
}

impl ClipShape {
    pub fn rect(center: [f64; 2], width: f64, height: f64) -> ClipShape {
        let (hw, hh) = ((width.abs()) / 2.0, (height.abs()) / 2.0);
        ClipShape::Rect {
            min: [center[0] - hw, center[1] - hh],
            max: [center[0] + hw, center[1] + hh],
        }
    }

    /// A clip boundary given as a closed outline.
    ///
    /// Falls back to the outline's bounding box when the decomposition comes
    /// back empty, so a boundary we cannot triangulate still clips roughly
    /// rather than not at all.
    pub fn polygon(outline: Vec<[f64; 2]>) -> Option<ClipShape> {
        if outline.len() < 3 {
            return None;
        }
        let mut min = [f64::INFINITY; 2];
        let mut max = [f64::NEG_INFINITY; 2];
        for p in &outline {
            if !p[0].is_finite() || !p[1].is_finite() {
                return None;
            }
            min[0] = min[0].min(p[0]);
            min[1] = min[1].min(p[1]);
            max[0] = max[0].max(p[0]);
            max[1] = max[1].max(p[1]);
        }

        let flat = super::fill::fill_even_odd(std::slice::from_ref(&outline));
        let pieces: Vec<[[f64; 2]; 3]> = flat.as_chunks::<3>().0.to_vec();
        if pieces.is_empty() {
            return Some(ClipShape::Rect { min, max });
        }
        Some(ClipShape::Poly {
            outline,
            pieces,
            min,
            max,
        })
    }

    pub fn bounds(&self) -> ([f64; 2], [f64; 2]) {
        match self {
            ClipShape::Rect { min, max } => (*min, *max),
            ClipShape::Poly { min, max, .. } => (*min, *max),
        }
    }

    pub fn contains(&self, p: [f64; 2]) -> bool {
        let (min, max) = self.bounds();
        if p[0] < min[0] || p[0] > max[0] || p[1] < min[1] || p[1] > max[1] {
            return false;
        }
        match self {
            ClipShape::Rect { .. } => true,
            ClipShape::Poly { outline, .. } => point_in_polygon(p, outline),
        }
    }

    /// The part of segment `a`..`b` inside the shape, as parameter spans.
    pub fn clip_segment(&self, a: [f64; 2], b: [f64; 2], out: &mut Vec<(f64, f64)>) {
        out.clear();
        match self {
            ClipShape::Rect { min, max } => {
                if let Some(span) = liang_barsky(a, b, *min, *max) {
                    out.push(span);
                }
            }
            ClipShape::Poly {
                outline, min, max, ..
            } => {
                // Cheap reject before the per-edge work.
                if (a[0] < min[0] && b[0] < min[0])
                    || (a[0] > max[0] && b[0] > max[0])
                    || (a[1] < min[1] && b[1] < min[1])
                    || (a[1] > max[1] && b[1] > max[1])
                {
                    return;
                }
                let d = [b[0] - a[0], b[1] - a[1]];
                let mut ts: Vec<f64> = vec![0.0, 1.0];
                for i in 0..outline.len() {
                    let p = outline[i];
                    let q = outline[(i + 1) % outline.len()];
                    let e = [q[0] - p[0], q[1] - p[1]];
                    let denom = d[0] * e[1] - d[1] * e[0];
                    if denom.abs() < 1e-12 {
                        continue;
                    }
                    let w = [p[0] - a[0], p[1] - a[1]];
                    let t = (w[0] * e[1] - w[1] * e[0]) / denom;
                    let u = (w[0] * d[1] - w[1] * d[0]) / denom;
                    if (0.0..=1.0).contains(&t) && (0.0..=1.0).contains(&u) {
                        ts.push(t);
                    }
                }
                ts.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));

                // Each span between consecutive crossings is wholly in or out.
                let mut i = 0;
                while i + 1 < ts.len() {
                    let (t0, t1) = (ts[i], ts[i + 1]);
                    i += 1;
                    if t1 - t0 < 1e-12 {
                        continue;
                    }
                    let mid = (t0 + t1) * 0.5;
                    let p = [a[0] + d[0] * mid, a[1] + d[1] * mid];
                    if !point_in_polygon(p, outline) {
                        continue;
                    }
                    // Merge with the previous span when they touch, so a
                    // segment crossing a vertex stays one stroke.
                    match out.last_mut() {
                        Some(last) if (last.1 - t0).abs() < 1e-12 => last.1 = t1,
                        _ => out.push((t0, t1)),
                    }
                }
            }
        }
    }

    /// The part of a triangle inside the shape, as triangles.
    pub fn clip_triangle(&self, tri: [[f64; 2]; 3], out: &mut Vec<[[f64; 2]; 3]>) {
        out.clear();
        match self {
            ClipShape::Rect { min, max } => {
                let poly = clip_to_rect(&tri, *min, *max);
                fan(&poly, out);
            }
            ClipShape::Poly {
                pieces, min, max, ..
            } => {
                let (lo, hi) = tri_bounds(&tri);
                if lo[0] > max[0] || hi[0] < min[0] || lo[1] > max[1] || hi[1] < min[1] {
                    return;
                }
                for piece in pieces {
                    let (plo, phi) = tri_bounds(piece);
                    if lo[0] > phi[0] || hi[0] < plo[0] || lo[1] > phi[1] || hi[1] < plo[1] {
                        continue;
                    }
                    let poly = clip_to_triangle(&tri, piece);
                    fan(&poly, out);
                }
            }
        }
    }
}

fn tri_bounds(t: &[[f64; 2]; 3]) -> ([f64; 2], [f64; 2]) {
    let xs = [t[0][0], t[1][0], t[2][0]];
    let ys = [t[0][1], t[1][1], t[2][1]];
    (
        [
            xs.iter().cloned().fold(f64::INFINITY, f64::min),
            ys.iter().cloned().fold(f64::INFINITY, f64::min),
        ],
        [
            xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
            ys.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        ],
    )
}

/// Even-odd point-in-polygon, matching how the rest of the crate fills.
pub fn point_in_polygon(p: [f64; 2], poly: &[[f64; 2]]) -> bool {
    let mut inside = false;
    let n = poly.len();
    for i in 0..n {
        let a = poly[i];
        let b = poly[(i + 1) % n];
        // Half-open in y, so a vertex exactly on the ray counts once.
        if (a[1] > p[1]) != (b[1] > p[1]) {
            let t = (p[1] - a[1]) / (b[1] - a[1]);
            if p[0] < a[0] + t * (b[0] - a[0]) {
                inside = !inside;
            }
        }
    }
    inside
}

/// Liang-Barsky: the parameter span of `a`..`b` inside an axis-aligned box.
fn liang_barsky(a: [f64; 2], b: [f64; 2], min: [f64; 2], max: [f64; 2]) -> Option<(f64, f64)> {
    let d = [b[0] - a[0], b[1] - a[1]];
    let (mut t0, mut t1) = (0.0f64, 1.0f64);
    for axis in 0..2 {
        // p is the direction of the outward normal times the step.
        for (p, q) in [
            (-d[axis], a[axis] - min[axis]),
            (d[axis], max[axis] - a[axis]),
        ] {
            if p.abs() < 1e-12 {
                if q < 0.0 {
                    return None;
                }
                continue;
            }
            let r = q / p;
            if p < 0.0 {
                if r > t1 {
                    return None;
                }
                t0 = t0.max(r);
            } else {
                if r < t0 {
                    return None;
                }
                t1 = t1.min(r);
            }
        }
    }
    if t1 <= t0 {
        None
    } else {
        Some((t0, t1))
    }
}

/// Sutherland-Hodgman against the four edges of a box.
fn clip_to_rect(tri: &[[f64; 2]; 3], min: [f64; 2], max: [f64; 2]) -> Vec<[f64; 2]> {
    let mut poly: Vec<[f64; 2]> = tri.to_vec();
    // (axis, keep-greater, bound)
    let edges = [
        (0usize, true, min[0]),
        (0, false, max[0]),
        (1, true, min[1]),
        (1, false, max[1]),
    ];
    for (axis, keep_greater, bound) in edges {
        if poly.is_empty() {
            return poly;
        }
        let dist = |p: &[f64; 2]| {
            if keep_greater {
                p[axis] - bound
            } else {
                bound - p[axis]
            }
        };
        poly = clip_half_plane(&poly, dist);
    }
    poly
}

/// Sutherland-Hodgman against the three edges of a convex piece.
fn clip_to_triangle(tri: &[[f64; 2]; 3], clip: &[[f64; 2]; 3]) -> Vec<[f64; 2]> {
    let area2 = (clip[1][0] - clip[0][0]) * (clip[2][1] - clip[0][1])
        - (clip[2][0] - clip[0][0]) * (clip[1][1] - clip[0][1]);
    if area2.abs() < 1e-18 {
        return Vec::new();
    }
    // Orient the half-plane tests to the piece's own winding.
    let sign = if area2 > 0.0 { 1.0 } else { -1.0 };

    let mut poly: Vec<[f64; 2]> = tri.to_vec();
    for i in 0..3 {
        if poly.is_empty() {
            return poly;
        }
        let a = clip[i];
        let b = clip[(i + 1) % 3];
        let dist = move |p: &[f64; 2]| {
            sign * ((b[0] - a[0]) * (p[1] - a[1]) - (b[1] - a[1]) * (p[0] - a[0]))
        };
        poly = clip_half_plane(&poly, dist);
    }
    poly
}

/// Keep the part of `poly` where `dist` is non-negative.
fn clip_half_plane(poly: &[[f64; 2]], dist: impl Fn(&[f64; 2]) -> f64) -> Vec<[f64; 2]> {
    let mut out: Vec<[f64; 2]> = Vec::with_capacity(poly.len() + 2);
    for i in 0..poly.len() {
        let cur = poly[i];
        let prev = poly[(i + poly.len() - 1) % poly.len()];
        let (dc, dp) = (dist(&cur), dist(&prev));
        if dc >= 0.0 {
            if dp < 0.0 {
                out.push(lerp_at(prev, cur, dp, dc));
            }
            out.push(cur);
        } else if dp >= 0.0 {
            out.push(lerp_at(prev, cur, dp, dc));
        }
    }
    out
}

fn lerp_at(a: [f64; 2], b: [f64; 2], da: f64, db: f64) -> [f64; 2] {
    let t = da / (da - db);
    [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t]
}

fn fan(poly: &[[f64; 2]], out: &mut Vec<[[f64; 2]; 3]>) {
    // The clipped polygon is convex, so a fan from vertex 0 covers it.
    for i in 1..poly.len().saturating_sub(1) {
        out.push([poly[0], poly[i], poly[i + 1]]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn area(tris: &[[[f64; 2]; 3]]) -> f64 {
        tris.iter()
            .map(|t| {
                ((t[1][0] - t[0][0]) * (t[2][1] - t[0][1])
                    - (t[2][0] - t[0][0]) * (t[1][1] - t[0][1]))
                    .abs()
                    / 2.0
            })
            .sum()
    }

    #[test]
    fn segment_crossing_a_rect_keeps_only_the_inside() {
        let r = ClipShape::rect([0.0, 0.0], 2.0, 2.0);
        let mut spans = Vec::new();
        r.clip_segment([-5.0, 0.0], [5.0, 0.0], &mut spans);
        assert_eq!(spans.len(), 1);
        let (t0, t1) = spans[0];
        assert!((t0 - 0.4).abs() < 1e-9, "t0 {t0}");
        assert!((t1 - 0.6).abs() < 1e-9, "t1 {t1}");
    }

    #[test]
    fn segment_wholly_outside_is_dropped() {
        let r = ClipShape::rect([0.0, 0.0], 2.0, 2.0);
        let mut spans = Vec::new();
        r.clip_segment([5.0, 5.0], [6.0, 7.0], &mut spans);
        assert!(spans.is_empty());
    }

    #[test]
    fn triangle_clipped_to_a_rect_keeps_the_overlapping_area() {
        let r = ClipShape::rect([0.0, 0.0], 2.0, 2.0);
        let mut out = Vec::new();
        // Right-angled triangle covering the whole upper-right quadrant and more.
        r.clip_triangle([[0.0, 0.0], [10.0, 0.0], [0.0, 10.0]], &mut out);
        // Inside the box that triangle covers x>=0, y>=0, x+y<=10, which over
        // the unit square is the whole quadrant: 1 x 1.
        assert!((area(&out) - 1.0).abs() < 1e-9, "area {}", area(&out));
    }

    #[test]
    fn concave_outline_cuts_a_segment_into_two() {
        // A "U": the notch in the middle is outside the shape.
        let u = vec![
            [0.0, 0.0],
            [4.0, 0.0],
            [4.0, 4.0],
            [3.0, 4.0],
            [3.0, 1.0],
            [1.0, 1.0],
            [1.0, 4.0],
            [0.0, 4.0],
        ];
        let shape = ClipShape::polygon(u).unwrap();
        let mut spans = Vec::new();
        shape.clip_segment([-1.0, 2.0], [5.0, 2.0], &mut spans);
        assert_eq!(spans.len(), 2, "spans {spans:?}");
    }

    #[test]
    fn concave_outline_clips_a_triangle_to_its_arms() {
        let u = vec![
            [0.0, 0.0],
            [4.0, 0.0],
            [4.0, 4.0],
            [3.0, 4.0],
            [3.0, 1.0],
            [1.0, 1.0],
            [1.0, 4.0],
            [0.0, 4.0],
        ];
        let shape = ClipShape::polygon(u).unwrap();
        let mut out = Vec::new();
        // A band across the arms at y in [2,3]: 2 arms x 1 wide x 1 tall.
        shape.clip_triangle([[-1.0, 2.0], [5.0, 2.0], [-1.0, 3.0]], &mut out);
        let a = area(&out);
        // The triangle covers the left arm fully in that band and the right arm
        // partially; just assert it kept something and dropped the notch.
        assert!(a > 0.5 && a < 3.0, "area {a}");
        for t in &out {
            for p in t {
                assert!(
                    !(p[0] > 1.0 + 1e-9 && p[0] < 3.0 - 1e-9 && p[1] > 1.0 + 1e-9),
                    "vertex {p:?} landed in the notch"
                );
            }
        }
    }

    #[test]
    fn point_containment_follows_the_outline_not_the_box() {
        let u = vec![
            [0.0, 0.0],
            [4.0, 0.0],
            [4.0, 4.0],
            [3.0, 4.0],
            [3.0, 1.0],
            [1.0, 1.0],
            [1.0, 4.0],
            [0.0, 4.0],
        ];
        let shape = ClipShape::polygon(u).unwrap();
        assert!(shape.contains([0.5, 2.0]));
        assert!(!shape.contains([2.0, 2.0]));
        assert!(shape.contains([2.0, 0.5]));
    }
}
