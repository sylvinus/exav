//! Polygons with holes into triangles: holes joined to the outer loop by
//! bridges (Eberly, "Triangulation by Ear Clipping", 2002), then ear
//! clipping. The work is bounded: past it, what remains is fanned.

use super::math::{any_perpendicular, cross, dot, sub, unit, V2, V3};

/// Most point-in-triangle tests one polygon may cost before the rest of it
/// is fanned.
const WORK: usize = 40_000_000;

fn cross2(o: V2, a: V2, b: V2) -> f64 {
    (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0])
}

fn area(pts: &[V2], ring: &[u32]) -> f64 {
    let mut s = 0.0;
    for i in 0..ring.len() {
        let a = pts[ring[i] as usize];
        let b = pts[ring[(i + 1) % ring.len()] as usize];
        s += a[0] * b[1] - b[0] * a[1];
    }
    s / 2.0
}

/// Drops repeated and closing points; `None` when fewer than three remain.
fn clean(pts: &[V2], ring: &[u32], eps: f64) -> Option<Vec<u32>> {
    let mut out: Vec<u32> = Vec::with_capacity(ring.len());
    for &i in ring {
        let p = *pts.get(i as usize)?;
        if !(p[0].is_finite() && p[1].is_finite()) {
            return None;
        }
        if let Some(&l) = out.last() {
            let q = pts[l as usize];
            if (p[0] - q[0]).abs() <= eps && (p[1] - q[1]).abs() <= eps {
                continue;
            }
        }
        out.push(i);
    }
    while out.len() > 1 {
        let (a, b) = (pts[out[0] as usize], pts[out[out.len() - 1] as usize]);
        if (a[0] - b[0]).abs() <= eps && (a[1] - b[1]).abs() <= eps {
            out.pop();
        } else {
            break;
        }
    }
    (out.len() >= 3).then_some(out)
}

/// Triangles (counter-clockwise) covering the polygon `outer` minus
/// `holes`, as indices into `pts`. Either orientation of the loops is
/// accepted.
pub fn triangulate(pts: &[V2], outer: &[u32], holes: &[Vec<u32>]) -> Vec<[u32; 3]> {
    let mut lo = [f64::INFINITY; 2];
    let mut hi = [f64::NEG_INFINITY; 2];
    for &i in outer {
        if let Some(p) = pts.get(i as usize) {
            for k in 0..2 {
                lo[k] = lo[k].min(p[k]);
                hi[k] = hi[k].max(p[k]);
            }
        }
    }
    let size = (hi[0] - lo[0]).max(hi[1] - lo[1]);
    if !size.is_finite() || size <= 0.0 {
        return Vec::new();
    }
    let eps = size * 1e-10;
    let Some(mut ring) = clean(pts, outer, eps) else {
        return Vec::new();
    };
    let a = area(pts, &ring);
    if a.abs() <= size * size * 1e-14 {
        return Vec::new();
    }
    if a < 0.0 {
        ring.reverse();
    }
    let mut hs: Vec<Vec<u32>> = Vec::new();
    for h in holes {
        if let Some(mut h) = clean(pts, h, eps) {
            let ha = area(pts, &h);
            if ha.abs() <= size * size * 1e-14 {
                continue;
            }
            if ha > 0.0 {
                h.reverse();
            }
            hs.push(h);
        }
    }
    if hs.is_empty() && convex(pts, &ring) {
        return (1..ring.len() - 1)
            .map(|k| [ring[0], ring[k], ring[k + 1]])
            .collect();
    }
    // Rightmost holes first, each bridged to the ring as it stands.
    hs.sort_by(|a, b| {
        max_x(pts, b)
            .partial_cmp(&max_x(pts, a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    // Each bridge scans the ring as it has grown: past the work bound the
    // remaining holes are left filled.
    let mut work = 0usize;
    for h in hs {
        work = work.saturating_add(ring.len().saturating_mul(2));
        if work > WORK {
            break;
        }
        bridge(pts, &mut ring, &h);
    }
    clip(pts, ring, eps)
}

fn max_x(pts: &[V2], ring: &[u32]) -> f64 {
    ring.iter()
        .map(|&i| pts[i as usize][0])
        .fold(f64::NEG_INFINITY, f64::max)
}

fn convex(pts: &[V2], ring: &[u32]) -> bool {
    let n = ring.len();
    (0..n).all(|i| {
        cross2(
            pts[ring[i] as usize],
            pts[ring[(i + 1) % n] as usize],
            pts[ring[(i + 2) % n] as usize],
        ) >= 0.0
    })
}

/// Joins `hole` (clockwise) to `ring` (counter-clockwise) through a vertex
/// visible from the hole's rightmost one.
fn bridge(pts: &[V2], ring: &mut Vec<u32>, hole: &[u32]) {
    let (mi, &m) = match hole.iter().enumerate().max_by(|a, b| {
        let (pa, pb) = (pts[*a.1 as usize], pts[*b.1 as usize]);
        pa[0]
            .partial_cmp(&pb[0])
            .unwrap_or(std::cmp::Ordering::Equal)
    }) {
        Some(x) => x,
        None => return,
    };
    let mp = pts[m as usize];
    // The nearest edge crossed by the ray from M towards +x.
    let n = ring.len();
    let mut best: Option<(f64, usize)> = None;
    for i in 0..n {
        let a = pts[ring[i] as usize];
        let b = pts[ring[(i + 1) % n] as usize];
        if (a[1] > mp[1]) == (b[1] > mp[1]) {
            continue;
        }
        let t = (mp[1] - a[1]) / (b[1] - a[1]);
        let x = a[0] + t * (b[0] - a[0]);
        if x >= mp[0] && best.is_none_or(|(bx, _)| x < bx) {
            best = Some((x, i));
        }
    }
    let Some((ix, ei)) = best else {
        return;
    };
    let (a, b) = (ring[ei], ring[(ei + 1) % n]);
    let mut p = if pts[a as usize][0] > pts[b as usize][0] {
        (ei, a)
    } else {
        ((ei + 1) % n, b)
    };
    // A reflex vertex inside the triangle (M, I, P) would hide P: take the
    // one closest in angle to the ray.
    let ip = [ix, mp[1]];
    let pp = pts[p.1 as usize];
    let mut best_angle = f64::INFINITY;
    for k in 0..n {
        let v = ring[k];
        let q = pts[v as usize];
        if v == p.1 {
            continue;
        }
        let reflex = cross2(
            pts[ring[(k + n - 1) % n] as usize],
            q,
            pts[ring[(k + 1) % n] as usize],
        ) < 0.0;
        if !reflex || !in_triangle(mp, ip, pp, q) {
            continue;
        }
        let d = sub2(q, mp);
        let angle = d[1].abs().atan2(d[0]);
        if angle < best_angle {
            best_angle = angle;
            p = (k, v);
        }
    }
    let mut out = Vec::with_capacity(ring.len() + hole.len() + 2);
    out.extend_from_slice(&ring[..=p.0]);
    out.extend(hole[mi..].iter().chain(&hole[..mi]));
    out.push(m);
    out.push(p.1);
    out.extend_from_slice(&ring[p.0 + 1..]);
    *ring = out;
}

fn sub2(a: V2, b: V2) -> V2 {
    [a[0] - b[0], a[1] - b[1]]
}

/// Inside or on the border of the counter-clockwise or clockwise triangle.
fn in_triangle(a: V2, b: V2, c: V2, p: V2) -> bool {
    let d1 = cross2(a, b, p);
    let d2 = cross2(b, c, p);
    let d3 = cross2(c, a, p);
    let neg = d1 < 0.0 || d2 < 0.0 || d3 < 0.0;
    let pos = d1 > 0.0 || d2 > 0.0 || d3 > 0.0;
    !(neg && pos)
}

fn clip(pts: &[V2], ring: Vec<u32>, eps: f64) -> Vec<[u32; 3]> {
    let n = ring.len();
    let mut out = Vec::with_capacity(n.saturating_sub(2));
    let mut next: Vec<usize> = (0..n).map(|i| (i + 1) % n).collect();
    let mut prev: Vec<usize> = (0..n).map(|i| (i + n - 1) % n).collect();
    let mut left = n;
    let mut cur = 0;
    let mut stalled = 0;
    let mut work = 0usize;
    let p = |i: usize| pts[ring[i] as usize];
    let same = |a: V2, b: V2| (a[0] - b[0]).abs() <= eps && (a[1] - b[1]).abs() <= eps;
    while left > 3 {
        let (a, b, c) = (prev[cur], cur, next[cur]);
        let (pa, pb, pc) = (p(a), p(b), p(c));
        let turn = cross2(pa, pb, pc);
        let mut ear = turn > 0.0;
        if ear {
            let mut k = next[c];
            while k != a {
                work += 1;
                let q = p(k);
                if !same(q, pa) && !same(q, pb) && !same(q, pc) && in_triangle(pa, pb, pc, q) {
                    ear = false;
                    break;
                }
                k = next[k];
            }
        }
        // A spike (a bridge's doubled vertex) or a repeated point adds
        // nothing: dropped without a triangle. A vertex in the middle of a
        // straight edge stays, so that the triangles keep the edge's
        // points (no T-junction with the side faces).
        let flat = same(pa, pc) || same(pa, pb) || same(pb, pc);
        let forced = stalled > left || work > WORK;
        if ear || flat || forced {
            if ear || (!flat && forced && turn > 0.0) {
                out.push([ring[a], ring[b], ring[c]]);
            }
            next[a] = c;
            prev[c] = a;
            left -= 1;
            cur = c;
            stalled = 0;
        } else {
            cur = next[cur];
            stalled += 1;
        }
    }
    if left == 3 {
        let (a, b, c) = (prev[cur], cur, next[cur]);
        if cross2(p(a), p(b), p(c)) > 0.0 {
            out.push([ring[a], ring[b], ring[c]]);
        }
    }
    out
}

/// Triangles of a planar (or nearly) face in 3D: `loops[0]` the outer
/// boundary, the others holes. The triangles turn the way the outer loop
/// does.
pub fn triangulate_3d(pts: &[V3], loops: &[Vec<u32>]) -> Vec<[u32; 3]> {
    let Some(outer) = loops.first() else {
        return Vec::new();
    };
    if outer.len() < 3
        || outer
            .iter()
            .chain(loops.iter().skip(1).flatten())
            .any(|&i| i as usize >= pts.len())
    {
        return Vec::new();
    }
    if loops.len() == 1 && outer.len() == 3 {
        return vec![[outer[0], outer[1], outer[2]]];
    }
    // Newell's normal of the outer loop.
    let mut n = [0.0; 3];
    for i in 0..outer.len() {
        let a = pts[outer[i] as usize];
        let b = pts[outer[(i + 1) % outer.len()] as usize];
        n[0] += (a[1] - b[1]) * (a[2] + b[2]);
        n[1] += (a[2] - b[2]) * (a[0] + b[0]);
        n[2] += (a[0] - b[0]) * (a[1] + b[1]);
    }
    let Some(n) = unit(n) else {
        return Vec::new();
    };
    let u = any_perpendicular(n);
    let v = cross(n, u);
    let o = pts[outer[0] as usize];
    // Only this face's points, numbered locally.
    let mut global: Vec<u32> = Vec::new();
    let mut flat: Vec<V2> = Vec::new();
    let local: Vec<Vec<u32>> = loops
        .iter()
        .map(|l| {
            l.iter()
                .map(|&i| {
                    let d = sub(pts[i as usize], o);
                    flat.push([dot(d, u), dot(d, v)]);
                    global.push(i);
                    (global.len() - 1) as u32
                })
                .collect()
        })
        .collect();
    // Counter-clockwise in (u, v), whose normal is n: as the loop turns.
    triangulate(&flat, &local[0], &local[1..])
        .into_iter()
        .map(|t| t.map(|i| global[i as usize]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn total(pts: &[V2], tris: &[[u32; 3]]) -> f64 {
        tris.iter()
            .map(|t| cross2(pts[t[0] as usize], pts[t[1] as usize], pts[t[2] as usize]) / 2.0)
            .sum()
    }

    #[test]
    fn a_square_with_a_square_hole() {
        let pts = vec![
            [0., 0.],
            [4., 0.],
            [4., 4.],
            [0., 4.],
            [1., 1.],
            [1., 3.],
            [3., 3.],
            [3., 1.],
        ];
        let t = triangulate(&pts, &[0, 1, 2, 3], &[vec![4, 5, 6, 7]]);
        assert!((total(&pts, &t) - 12.0).abs() < 1e-9);
        assert!(t.iter().all(|t| cross2(
            pts[t[0] as usize],
            pts[t[1] as usize],
            pts[t[2] as usize]
        ) > 0.0));
    }

    #[test]
    fn clockwise_concave_input() {
        // An L, clockwise.
        let pts = vec![[0., 0.], [0., 2.], [1., 2.], [1., 1.], [2., 1.], [2., 0.]];
        let t = triangulate(&pts, &[0, 1, 2, 3, 4, 5], &[]);
        assert_eq!(t.len(), 4);
        assert!((total(&pts, &t) - 3.0).abs() < 1e-9);
    }

    #[test]
    fn two_holes_and_collinear_points() {
        let pts = vec![
            [0., 0.],
            [5., 0.],
            [10., 0.],
            [10., 4.],
            [0., 4.],
            [1., 1.],
            [2., 1.],
            [2., 3.],
            [1., 3.],
            [6., 1.],
            [8., 1.],
            [8., 3.],
            [6., 3.],
        ];
        let t = triangulate(
            &pts,
            &[0, 1, 2, 3, 4],
            &[vec![5, 6, 7, 8], vec![9, 10, 11, 12]],
        );
        assert!((total(&pts, &t) - (40.0 - 2.0 - 4.0)).abs() < 1e-9);
    }

    #[test]
    fn degenerate_input_gives_nothing() {
        let pts = vec![[0., 0.], [1., 1.], [2., 2.]];
        assert!(triangulate(&pts, &[0, 1, 2], &[]).is_empty());
        assert!(triangulate(&pts, &[0, 1, 9], &[]).is_empty());
        let nan = vec![[0., 0.], [f64::NAN, 1.], [2., 0.]];
        assert!(triangulate(&nan, &[0, 1, 2], &[]).is_empty());
    }

    #[test]
    fn a_t_section_is_covered_once() {
        // Web 0.01 wide, flange 0.2 wide on top: six triangles, no overlap.
        let (tw, wf, d, tf) = (0.01, 0.2, 0.25, 0.02);
        let pts = vec![
            [-tw / 2.0, -d / 2.0],
            [tw / 2.0, -d / 2.0],
            [tw / 2.0, d / 2.0 - tf],
            [wf / 2.0, d / 2.0 - tf],
            [wf / 2.0, d / 2.0],
            [-wf / 2.0, d / 2.0],
            [-wf / 2.0, d / 2.0 - tf],
            [-tw / 2.0, d / 2.0 - tf],
        ];
        let t = triangulate(&pts, &[0, 1, 2, 3, 4, 5, 6, 7], &[]);
        assert_eq!(t.len(), 6, "{t:?}");
        assert!((total(&pts, &t) - (wf * tf + (d - tf) * tw)).abs() < 1e-12);
    }

    #[test]
    fn a_face_in_3d_keeps_its_turn() {
        let pts = vec![[0., 0., 1.], [0., 2., 1.], [0., 2., 3.], [0., 0., 3.]];
        let t = triangulate_3d(&pts, &[vec![0, 1, 2, 3]]);
        assert_eq!(t.len(), 2);
        for t in t {
            let n = cross(
                sub(pts[t[1] as usize], pts[t[0] as usize]),
                sub(pts[t[2] as usize], pts[t[0] as usize]),
            );
            assert!(n[0] > 0.0);
        }
    }
}
