//! Faces of advanced B-reps on curved surfaces: cylinders, spheres, tori and
//! B-spline surfaces. A face is meshed in its surface's parameters: its
//! boundary is unrolled into (u, v), and the polygon that bounds it is meshed
//! there: a regular grid for a rectangle, else its triangles, bisected until
//! no side strays from the surface by more than a chord of a 32-chord circle
//! does.

use std::f64::consts::{FRAC_PI_2, TAU};

use super::curves::segments;
use super::math::{V2, V3, Xf, len, sub};
use super::spline::{MAX_DEGREE, Spline, expand_knots};
use super::step::Value;
use super::triangulate::triangulate;
use super::{Mesh, Reader};

/// Most triangles one face is bisected into.
const MAX_FACE_TRIANGLES: usize = 1 << 16;
/// Most boundary points of one face projected on a B-spline surface.
const MAX_PROJECTED: usize = 1 << 14;
/// Samples per side of the grid that starts the projection of a boundary.
const SEARCH_GRID: usize = 16;
/// Most points examined simplifying one loop.
const SIMPLIFY_WORK: usize = 1 << 24;

/// The angle `a`, a whole number of turns off, within half a turn of `prev`.
/// In one step: turns added one at a time take as many steps as the polyline
/// has wound, which a long spiral makes quadratic.
fn continuous(a: f64, prev: f64) -> f64 {
    a - TAU * ((a - prev) / TAU).round()
}

/// How far from its chord the surface may be at the middle of a triangle's
/// side, relative to the chord: that of a circle drawn with 32 chords, which
/// is how the curves that bound a face are sampled.
const MAX_SAG: f64 = 0.026;

/// How a polygon of parameters is meshed.
struct Tess<'f> {
    /// The grid for a rectangle of this extent: chords in `u` and in `v`.
    counts: &'f dyn Fn(V2) -> (usize, usize),
    /// A side of a triangle with a larger extent is split whatever its sag.
    max_extent: V2,
}

/// The indices of the points of the closed loop `uv` that stay when those
/// that lie within `tol` of the line between the two kept on either side
/// of them are dropped (Douglas-Peucker, from the first point and the
/// one furthest from it). The work is bounded: past it the rest is kept.
fn simplify(uv: &[V2], tol: f64) -> Vec<usize> {
    let n = uv.len();
    if n <= 4 || !tol.is_finite() || tol <= 0.0 {
        return (0..n).collect();
    }
    let far = (1..n)
        .max_by(|&i, &j| {
            let d = |k: usize| (uv[k][0] - uv[0][0]).hypot(uv[k][1] - uv[0][1]);
            d(i).total_cmp(&d(j))
        })
        .unwrap_or(1);
    let mut keep = vec![false; n];
    keep[0] = true;
    keep[far] = true;
    // Chains of indices a..b, the second one wrapping to the start.
    let mut stack = vec![(0usize, far), (far, n)];
    let mut work = 0usize;
    while let Some((a, b)) = stack.pop() {
        if b <= a + 1 {
            continue;
        }
        let (pa, pb) = (uv[a % n], uv[b % n]);
        let (dx, dy) = (pb[0] - pa[0], pb[1] - pa[1]);
        let l = dx.hypot(dy);
        let mut worst = (0.0f64, a);
        for k in a + 1..b {
            work += 1;
            let p = uv[k % n];
            let d = if l > 0.0 {
                ((p[0] - pa[0]) * dy - (p[1] - pa[1]) * dx).abs() / l
            } else {
                (p[0] - pa[0]).hypot(p[1] - pa[1])
            };
            if d > worst.0 {
                worst = (d, k);
            }
        }
        if worst.0 > tol && work < SIMPLIFY_WORK {
            keep[worst.1 % n] = true;
            stack.push((a, worst.1));
            stack.push((worst.1, b));
        } else if work >= SIMPLIFY_WORK {
            for k in a + 1..b {
                keep[k % n] = true;
            }
        }
    }
    let kept: Vec<usize> = (0..n).filter(|&i| keep[i]).collect();
    if kept.len() >= 3 {
        kept
    } else {
        (0..n).collect()
    }
}

/// The corners of the box round the points.
fn world_extent(pts: &[V3]) -> (V3, V3) {
    let mut lo = [f64::INFINITY; 3];
    let mut hi = [f64::NEG_INFINITY; 3];
    for p in pts {
        for k in 0..3 {
            lo[k] = lo[k].min(p[k]);
            hi[k] = hi[k].max(p[k]);
        }
    }
    (lo, hi)
}

/// The corners of the rectangle a boundary is, when its outer loop's points
/// all lie on the sides of the box round it and it has the box's area.
fn rectangle(b: &Boundary) -> Option<(V2, V2)> {
    if !b.holes.is_empty() {
        return None;
    }
    let pts: Vec<V2> = b.outer.iter().map(|&i| b.uv[i as usize]).collect();
    let (lo, hi) = extent(&pts);
    let (w, h) = (hi[0] - lo[0], hi[1] - lo[1]);
    if !(w > 0.0 && h > 0.0 && w.is_finite() && h.is_finite()) {
        return None;
    }
    // Projected points are a little off their sides.
    let tol = 1e-3 * w.max(h);
    let on_a_side = |p: &V2| {
        (p[0] - lo[0]).abs() <= tol
            || (hi[0] - p[0]).abs() <= tol
            || (p[1] - lo[1]).abs() <= tol
            || (hi[1] - p[1]).abs() <= tol
    };
    if !pts.iter().all(on_a_side) {
        return None;
    }
    let n = pts.len();
    let at = |i: usize| [pts[i % n][0] - lo[0], pts[i % n][1] - lo[1]];
    let area: f64 = (0..n)
        .map(|i| at(i)[0] * at(i + 1)[1] - at(i + 1)[0] * at(i)[1])
        .sum::<f64>()
        / 2.0;
    ((area.abs() - w * h).abs() <= 5e-3 * w * h).then_some((lo, hi))
}

/// An elementary surface and its parametrisation (ISO 10303-42), in the
/// placement `pos`. `u` is the angle round the axis. All three are turned
/// so that `d/du x d/dv` points out of the surface.
enum Surf {
    /// P = pos(r cos u, r sin u, v).
    Cylinder { pos: Xf, inv: Xf, r: f64 },
    /// P = pos(r cos v cos u, r cos v sin u, r sin v), v in -pi/2..pi/2.
    Sphere { pos: Xf, inv: Xf, r: f64 },
    /// P = pos((R + r cos v) cos u, (R + r cos v) sin u, r sin v).
    Torus {
        pos: Xf,
        inv: Xf,
        big: f64,
        small: f64,
    },
}

impl Surf {
    fn eval(&self, u: f64, v: f64) -> V3 {
        match self {
            Surf::Cylinder { pos, r, .. } => pos.point([r * u.cos(), r * u.sin(), v]),
            Surf::Sphere { pos, r, .. } => {
                // The poles exactly, not a rounding error off.
                if v.abs() >= FRAC_PI_2 - 1e-12 {
                    return pos.point([0.0, 0.0, r * v.signum()]);
                }
                pos.point([r * v.cos() * u.cos(), r * v.cos() * u.sin(), r * v.sin()])
            }
            Surf::Torus {
                pos, big, small, ..
            } => {
                let rho = big + small * v.cos();
                pos.point([rho * u.cos(), rho * u.sin(), small * v.sin()])
            }
        }
    }

    /// The parameters of a point on the surface, `u` (and `v` where it is an
    /// angle) within half a turn of those of the point before it.
    fn uv(&self, p: V3, prev: Option<V2>) -> V2 {
        let (inv, r) = match self {
            Surf::Cylinder { inv, r, .. } | Surf::Sphere { inv, r, .. } => (inv, *r),
            Surf::Torus { inv, big, .. } => (inv, *big),
        };
        let l = inv.point(p);
        let rho = l[0].hypot(l[1]);
        // On the axis the angle is any: that of the point before it.
        let mut u = if rho > 1e-9 * r {
            l[1].atan2(l[0])
        } else {
            prev.map_or(0.0, |q| q[0])
        };
        if let Some(q) = prev {
            u = continuous(u, q[0]);
        }
        let mut v = match self {
            Surf::Cylinder { .. } => l[2],
            Surf::Sphere { .. } => l[2].atan2(rho),
            Surf::Torus { big, .. } => l[2].atan2(rho - big),
        };
        if let (Surf::Torus { .. }, Some(q)) = (self, prev) {
            v = continuous(v, q[1]);
        }
        [u, v]
    }

    /// The chords across a rectangle of parameters, as many as the curves
    /// that bound a face of that size are sampled with. A cylinder is
    /// straight along `v`.
    fn counts(&self, extent: V2) -> (usize, usize) {
        let nu = segments(extent[0]);
        match self {
            Surf::Cylinder { .. } => (nu, 1),
            _ => (nu, segments(extent[1])),
        }
    }

    /// The parameter extent past which a chord is always split: the curve
    /// of a surface is never straighter than its chord looks.
    fn max_extent(&self) -> V2 {
        let quarter = TAU / 4.0;
        match self {
            Surf::Cylinder { .. } => [quarter, f64::INFINITY],
            _ => [quarter, quarter],
        }
    }

    /// Whether `v` is an angle that wraps.
    fn v_wraps(&self) -> bool {
        matches!(self, Surf::Torus { .. })
    }
}

/// A face's boundary in parameter space and in space: each point once,
/// the loops as indices into it.
struct Boundary {
    uv: Vec<V2>,
    world: Vec<V3>,
    outer: Vec<u32>,
    holes: Vec<Vec<u32>>,
}

impl Boundary {
    fn new() -> Self {
        Boundary {
            uv: Vec::new(),
            world: Vec::new(),
            outer: Vec::new(),
            holes: Vec::new(),
        }
    }

    fn push(&mut self, uv: V2, world: V3) -> u32 {
        self.uv.push(uv);
        self.world.push(world);
        (self.uv.len() - 1) as u32
    }
}

/// A closed loop unrolled: its parameters, each next to the one before, and
/// how many turns it makes round `u` and round `v` (the latter when `v`
/// wraps).
fn unroll(surf: &Surf, pts: &[V3]) -> (Vec<V2>, [i64; 2]) {
    let mut uv: Vec<V2> = Vec::with_capacity(pts.len());
    for &p in pts {
        uv.push(surf.uv(p, uv.last().copied()));
    }
    let (first, last) = (uv[0], uv[uv.len() - 1]);
    // The closing step, from the last point back to the first.
    let turns = |k: usize| ((first[k] - last[k]) / TAU).round();
    let wu = -turns(0);
    let wv = if surf.v_wraps() { -turns(1) } else { 0.0 };
    (uv, [wu as i64, wv as i64])
}

/// The parameters' bounding box.
fn extent(uv: &[V2]) -> (V2, V2) {
    let mut lo = [f64::INFINITY; 2];
    let mut hi = [f64::NEG_INFINITY; 2];
    for p in uv {
        for k in 0..2 {
            lo[k] = lo[k].min(p[k]);
            hi[k] = hi[k].max(p[k]);
        }
    }
    (lo, hi)
}

/// `uv` moved by whole turns, in the parameters that wrap, to lie round
/// `target`.
fn near(uv: &mut [V2], target: V2, wraps: [bool; 2]) {
    let (lo, hi) = extent(uv);
    for k in 0..2 {
        if wraps[k] {
            let shift = TAU * (((target[k] - (lo[k] + hi[k]) / 2.0) / TAU).round());
            for p in uv.iter_mut() {
                p[k] += shift;
            }
        }
    }
}

/// A loop that winds once round parameter `c`, unrolled with `c` growing:
/// the loop reversed when it winds the other way.
fn rising(surf: &Surf, pts: &[V3], c: usize) -> Option<(Vec<V2>, Vec<V3>)> {
    let (uv, wind) = unroll(surf, pts);
    if wind[c] == 1 {
        return Some((uv, pts.to_vec()));
    }
    let back: Vec<V3> = pts.iter().rev().copied().collect();
    let (uv, wind) = unroll(surf, &back);
    (wind[c] == 1).then_some((uv, back))
}

/// The band between two loops that each wind once round parameter `c`: a
/// polygon that follows the lower loop once round, climbs the seam to the
/// upper one, and follows that back.
fn band(surf: &Surf, a: &[V3], b: &[V3], c: usize) -> Option<Boundary> {
    let d = 1 - c;
    let ((a_uv, a_pts), (b_uv, b_pts)) = (rising(surf, a, c)?, rising(surf, b, c)?);
    let mean = |uv: &[V2]| uv.iter().map(|p| p[d]).sum::<f64>() / uv.len() as f64;
    // The lower loop first.
    let ((lo_uv, lo_pts), (hi_uv, hi_pts)) = if mean(&a_uv) <= mean(&b_uv) {
        ((a_uv, a_pts), (b_uv, b_pts))
    } else {
        ((b_uv, b_pts), (a_uv, a_pts))
    };
    let start = lo_uv[0][c];
    // The upper loop with its parameter taken into one turn from `start`,
    // started where it wraps.
    let wrapped: Vec<f64> = hi_uv
        .iter()
        .map(|p| start + (p[c] - start).rem_euclid(TAU))
        .collect();
    let n = wrapped.len();
    let first = (0..n)
        .find(|&i| wrapped[i] < wrapped[(i + n - 1) % n])
        .unwrap_or(0);
    let order: Vec<usize> = (0..n).map(|k| (first + k) % n).collect();
    // Where the upper loop crosses the seam: between its last point before
    // the wrap and its first one after.
    let (last, next) = (order[n - 1], order[0]);
    let (cl, cn) = (wrapped[last], wrapped[next] + TAU);
    let t = if cn > cl {
        (start + TAU - cl) / (cn - cl)
    } else {
        0.0
    };
    let seam = hi_uv[last][d] + t * (hi_uv[next][d] - hi_uv[last][d]);
    let at = |cc: f64, dd: f64| -> V2 {
        let mut p = [0.0; 2];
        p[c] = cc;
        p[d] = dd;
        p
    };
    let mut out = Boundary::new();
    for (uv, w) in lo_uv.iter().zip(&lo_pts) {
        let i = out.push(*uv, *w);
        out.outer.push(i);
    }
    let end = at(start + TAU, lo_uv[0][d]);
    let i = out.push(end, lo_pts[0]);
    out.outer.push(i);
    let right = at(start + TAU, seam);
    let i = out.push(right, surf.eval(right[0], right[1]));
    out.outer.push(i);
    for &k in order.iter().rev() {
        let i = out.push(at(wrapped[k], hi_uv[k][d]), hi_pts[k]);
        out.outer.push(i);
    }
    let left = at(start, seam);
    let i = out.push(left, surf.eval(left[0], left[1]));
    out.outer.push(i);
    Some(out)
}

/// The boundary of a face on `surf` in its parameters. `left`: the face is
/// on the left of its outer loop in (u, v), which is the case when the face
/// faces the way the surface does. A loop that does not wind round the
/// surface bounds the area inside it; one that winds round a sphere once
/// (a cap) bounds the area between it and a pole. `None` for the rest.
fn boundary(surf: &Surf, loops: &[Vec<V3>], left: bool) -> Option<Boundary> {
    let mut b = Boundary::new();
    let wraps = [true, surf.v_wraps()];
    let (outer_pts, hole_pts) = loops.split_first()?;
    let (outer_uv, wind) = unroll(surf, outer_pts);
    // Two loops that each wind once round the same parameter, without a
    // seam between them (as some writers leave a tube): the band between.
    if let [first, second] = loops {
        let (wa, wb) = (wind, unroll(surf, second).1);
        for c in 0..2 {
            let d = 1 - c;
            if wraps[c] && wa[c].abs() == 1 && wb[c].abs() == 1 && wa[d] == 0 && wb[d] == 0 {
                return band(surf, first, second, c);
            }
        }
    }
    match wind {
        [0, 0] => {
            for (uv, w) in outer_uv.iter().zip(outer_pts) {
                let i = b.push(*uv, *w);
                b.outer.push(i);
            }
        }
        [w @ (-1 | 1), 0] if matches!(surf, Surf::Sphere { .. }) => {
            let Surf::Sphere { pos, r, .. } = surf else {
                return None;
            };
            // Seen from the face's side the loop runs one way round the
            // axis; the face is on its left.
            let pole = (if left { w } else { -w }) as f64 * FRAC_PI_2;
            let (u0, v0) = (outer_uv[0][0], outer_uv[0][1]);
            let u1 = u0 + TAU * w as f64;
            for (uv, p) in outer_uv.iter().zip(outer_pts) {
                let i = b.push(*uv, *p);
                b.outer.push(i);
            }
            let end = b.push([u1, v0], outer_pts[0]);
            let pole_point = pos.point([0.0, 0.0, r * pole.signum()]);
            let (p1, p0) = (
                b.push([u1, pole], pole_point),
                b.push([u0, pole], pole_point),
            );
            b.outer.extend([end, p1, p0]);
        }
        _ => return None,
    }
    // Holes: loops that do not wind, turned into the outer loop's turn.
    let (lo, hi) = extent(&b.uv);
    let centre = [(lo[0] + hi[0]) / 2.0, (lo[1] + hi[1]) / 2.0];
    for h in hole_pts {
        let (mut uv, wind) = unroll(surf, h);
        if wind != [0, 0] {
            return None;
        }
        near(&mut uv, centre, wraps);
        let ring: Vec<u32> = uv.iter().zip(h).map(|(uv, w)| b.push(*uv, *w)).collect();
        b.holes.push(ring);
    }
    Some(b)
}

impl<'a> Reader<'a> {
    /// A face on a curved surface, `None` for a plane and for what is not
    /// handled (counted), which the caller draws flat from the face's loops.
    pub(super) fn surface_face(&mut self, p: &[Value], depth: u32) -> Option<Mesh> {
        let sid = p.get(1)?.id()?;
        let (sty, sp) = self.get(sid)?;
        let mut m = match sty {
            b"IFCBSPLINESURFACEWITHKNOTS" | b"IFCRATIONALBSPLINESURFACEWITHKNOTS" => {
                match self.spline_face(sty, &sp, p, depth) {
                    Some(m) => m,
                    None => {
                        self.unsupported(sty);
                        return None;
                    }
                }
            }
            b"IFCCYLINDRICALSURFACE" | b"IFCSPHERICALSURFACE" | b"IFCTOROIDALSURFACE" => {
                match self.quadric_face(sty, &sp, p, depth) {
                    Some(m) => m,
                    None => {
                        self.unsupported(sty);
                        return None;
                    }
                }
            }
            b"IFCPLANE" => return None,
            _ => {
                self.unsupported(sty);
                return None;
            }
        };
        // Meshed facing the way the surface does.
        if p.get(2).and_then(Value::boolean) == Some(false) {
            for t in &mut m.t {
                t.swap(1, 2);
            }
        }
        Some(m)
    }

    /// The loops of a face's bounds in space, the outer one first, each
    /// turned as its bound says.
    fn face_loops(&mut self, bounds: &[Value], depth: u32) -> Option<Vec<Vec<V3>>> {
        let mut loops: Vec<Vec<V3>> = Vec::new();
        let mut outer = None;
        for b in bounds.iter().filter_map(Value::id) {
            let (bty, bp) = self.get(b)?;
            let (lty, lp) = self.get(bp.first()?.id()?)?;
            let mut pts = match lty {
                b"IFCEDGELOOP" => {
                    let (pts, connected) = self.edge_loop_checked(&lp, depth)?;
                    // Edges flagged the wrong way round do not make a loop.
                    if !connected {
                        return None;
                    }
                    pts
                }
                b"IFCPOLYLOOP" => {
                    let pts: Vec<V3> = lp
                        .first()?
                        .list()?
                        .iter()
                        .map(|q| self.point(q.id()?))
                        .collect::<Option<_>>()?;
                    if pts.len() < 3 {
                        return None;
                    }
                    pts
                }
                _ => return None,
            };
            if bp.get(1).and_then(Value::boolean) == Some(false) {
                pts.reverse();
            }
            if bty == b"IFCFACEOUTERBOUND" && outer.is_none() {
                outer = Some(loops.len());
            }
            loops.push(pts);
        }
        if let Some(i) = outer {
            loops.swap(0, i);
        }
        (!loops.is_empty()).then_some(loops)
    }

    fn quadric_face(&mut self, sty: &[u8], sp: &[Value], p: &[Value], depth: u32) -> Option<Mesh> {
        let pos = self.axis2(sp.first()?.id()?)?;
        let inv = pos.inverse()?;
        let num = |i: usize| {
            sp.get(i)
                .and_then(Value::num)
                .filter(|v| *v > 0.0 && v.is_finite())
        };
        let surf = match sty {
            b"IFCCYLINDRICALSURFACE" => Surf::Cylinder {
                pos,
                inv,
                r: num(1)?,
            },
            b"IFCSPHERICALSURFACE" => Surf::Sphere {
                pos,
                inv,
                r: num(1)?,
            },
            _ => {
                let (big, small) = (num(1)?, num(2)?);
                // IfcToroidalSurface: MinorRadius < MajorRadius.
                if small >= big {
                    return None;
                }
                Surf::Torus {
                    pos,
                    inv,
                    big,
                    small,
                }
            }
        };
        let loops = self.face_loops(p.first()?.list()?, depth)?;
        let left = p.get(2).and_then(Value::boolean).unwrap_or(true);
        let b = boundary(&surf, &loops, left)?;
        let tess = Tess {
            counts: &|extent| surf.counts(extent),
            max_extent: surf.max_extent(),
        };
        self.tessellate(b, &tess, |u, v| Some(surf.eval(u, v)))
    }

    /// A face's polygon in parameter space as triangles on the surface
    /// `eval` gives. A rectangle of parameters is a regular grid; any other
    /// polygon is triangulated, and its triangles bisected across the side
    /// that strays furthest from the surface (the midpoint of the chord
    /// farther from the surface's point than a 32-chord circle's is) until
    /// none does. The corners of the polygon keep their points in space,
    /// the others are `eval` of their parameters.
    fn tessellate(
        &mut self,
        b: Boundary,
        tess: &Tess,
        eval: impl Fn(f64, f64) -> Option<V3>,
    ) -> Option<Mesh> {
        if let Some((lo, hi)) = rectangle(&b) {
            return self.grid(lo, hi, tess, eval);
        }
        let first = triangulate(&b.uv, &b.outer, &b.holes);
        if first.is_empty() {
            return None;
        }
        let (lo, hi) = world_extent(&b.world);
        let eps = len(sub(hi, lo)) * 1e-9;
        let cap = MAX_FACE_TRIANGLES.min(self.work).min(self.ops / 8);
        let mut evals_left = self.ops;
        let Boundary {
            mut uv, mut world, ..
        } = b;
        let mut leaves: Vec<[u32; 3]> = Vec::new();
        let mut stack: Vec<[u32; 3]> = first.into_iter().rev().collect();
        while let Some(t) = stack.pop() {
            // Past the budget the triangles stay as they are.
            if leaves.len() + stack.len() + 1 >= cap || evals_left < 3 {
                leaves.push(t);
                continue;
            }
            let side = |i: usize| (t[i], t[(i + 1) % 3]);
            // Sides longer than the extent are split, the longest first.
            let extents: Vec<f64> = (0..3)
                .map(|i| {
                    let (a, b) = side(i);
                    let (a, b) = (uv[a as usize], uv[b as usize]);
                    ((a[0] - b[0]).abs() / tess.max_extent[0])
                        .max((a[1] - b[1]).abs() / tess.max_extent[1])
                })
                .collect();
            let longest = (0..3)
                .max_by(|&i, &j| extents[i].total_cmp(&extents[j]))
                .unwrap_or(0);
            let (k, mid_world, mid_uv) = if extents[longest] > 1.0 && extents[longest].is_finite() {
                let (a, b) = side(longest);
                let (a, b) = (uv[a as usize], uv[b as usize]);
                let mid = [(a[0] + b[0]) / 2.0, (a[1] + b[1]) / 2.0];
                evals_left -= 1;
                (longest, eval(mid[0], mid[1])?, mid)
            } else {
                // The side whose midpoint is furthest off its chord.
                let mut worst: Option<(usize, f64, V3, V2)> = None;
                for i in 0..3 {
                    let (a, b) = side(i);
                    let (ua, ub) = (uv[a as usize], uv[b as usize]);
                    let mid = [(ua[0] + ub[0]) / 2.0, (ua[1] + ub[1]) / 2.0];
                    let (pa, pb) = (world[a as usize], world[b as usize]);
                    let on_surface = eval(mid[0], mid[1])?;
                    evals_left -= 1;
                    let chord = [
                        (pa[0] + pb[0]) / 2.0,
                        (pa[1] + pb[1]) / 2.0,
                        (pa[2] + pb[2]) / 2.0,
                    ];
                    let excess = len(sub(on_surface, chord)) - MAX_SAG * len(sub(pb, pa)) - eps;
                    if excess > 0.0 && worst.is_none_or(|w| excess > w.1) {
                        worst = Some((i, excess, on_surface, mid));
                    }
                }
                let Some((i, _, on_surface, mid)) = worst else {
                    leaves.push(t);
                    continue;
                };
                (i, on_surface, mid)
            };
            // The side from x to y is split, z is opposite.
            let (x, y, z) = (t[k], t[(k + 1) % 3], t[(k + 2) % 3]);
            let m = uv.len() as u32;
            uv.push(mid_uv);
            world.push(mid_world);
            stack.push([m, y, z]);
            stack.push([x, m, z]);
        }
        self.charge(self.ops - evals_left)?;
        Some(Mesh {
            p: world,
            t: leaves,
        })
    }

    /// The rectangle `lo`..`hi` of parameters as a regular grid.
    fn grid(
        &mut self,
        lo: V2,
        hi: V2,
        tess: &Tess,
        eval: impl Fn(f64, f64) -> Option<V3>,
    ) -> Option<Mesh> {
        let (nu, nv) = (tess.counts)([hi[0] - lo[0], hi[1] - lo[1]]);
        let (nu, nv) = (nu.max(1), nv.max(1));
        self.budget(nu.checked_mul(nv)?.checked_mul(2)?)?;
        self.charge((nu + 1) * (nv + 1))?;
        let mut m = Mesh::default();
        for i in 0..=nu {
            let u = lo[0] + (hi[0] - lo[0]) * i as f64 / nu as f64;
            for k in 0..=nv {
                let v = lo[1] + (hi[1] - lo[1]) * k as f64 / nv as f64;
                m.p.push(eval(u, v)?);
            }
        }
        let stride = (nv + 1) as u32;
        for i in 0..nu as u32 {
            for k in 0..nv as u32 {
                let a = i * stride + k;
                m.t.push([a, a + stride, a + stride + 1]);
                m.t.push([a, a + stride + 1, a + 1]);
            }
        }
        Some(m)
    }

    /// A face on a B-spline surface, cut by its bounds: their points
    /// projected on the surface give the polygon in its parameters. A face
    /// without bounds is the whole surface; so is one whose bounds are not
    /// on it, which is said.
    fn spline_face(&mut self, sty: &[u8], sp: &[Value], p: &[Value], depth: u32) -> Option<Mesh> {
        let spline = self.spline_surface(sp)?;
        let bounds = p.first().and_then(Value::list).unwrap_or(&[]);
        if bounds.iter().any(|b| b.id().is_some()) {
            let polygon = self.projected_boundary(&spline, bounds, depth);
            if let Some(m) = polygon.and_then(|b| self.spline_mesh(&spline, b)) {
                return Some(m);
            }
            self.unsupported(sty);
        }
        self.whole_spline(&spline)
    }

    /// The control net, knots and weights of `IfcBSplineSurfaceWithKnots`
    /// (or the rational one) as a [`Spline`].
    fn spline_surface(&mut self, p: &[Value]) -> Option<Spline> {
        let du = usize::try_from(p.first()?.int()?)
            .ok()
            .filter(|d| (1..=MAX_DEGREE).contains(d))?;
        let dv = usize::try_from(p.get(1)?.int()?)
            .ok()
            .filter(|d| (1..=MAX_DEGREE).contains(d))?;
        let rows: Vec<Vec<V3>> = p
            .get(2)?
            .list()?
            .iter()
            .map(|r| self.points(Some(r)))
            .collect::<Option<_>>()?;
        let (nu, nv) = (rows.len(), rows.first()?.len());
        let knots = |m: &Value, k: &Value, n: usize, d: usize| -> Option<Vec<f64>> {
            let mults: Vec<usize> = m
                .list()?
                .iter()
                .map(|x| usize::try_from(x.int()?).ok())
                .collect::<Option<_>>()?;
            let ks: Vec<f64> = k.list()?.iter().map(Value::num).collect::<Option<_>>()?;
            expand_knots(&mults, &ks, n, d)
        };
        let ku = knots(p.get(7)?, p.get(9)?, nu, du)?;
        let kv = knots(p.get(8)?, p.get(10)?, nv, dv)?;
        let weights: Option<Vec<Vec<f64>>> = match p.get(12) {
            Some(w) if !w.is_null() => Some(
                w.list()?
                    .iter()
                    .map(|r| {
                        r.list()?
                            .iter()
                            .map(Value::num)
                            .collect::<Option<Vec<f64>>>()
                    })
                    .collect::<Option<_>>()?,
            ),
            _ => None,
        };
        Spline::new(du, dv, &rows, ku, kv, weights)
    }

    /// The whole domain as a regular grid of points: four chords per
    /// control point each way, at least 4 and at most 64.
    fn whole_spline(&mut self, s: &Spline) -> Option<Mesh> {
        let rectangle = Boundary {
            uv: vec![
                [s.u.0, s.v.0],
                [s.u.1, s.v.0],
                [s.u.1, s.v.1],
                [s.u.0, s.v.1],
            ],
            world: Vec::new(),
            outer: vec![0, 1, 2, 3],
            holes: Vec::new(),
        };
        self.spline_mesh(s, rectangle)
    }

    /// A polygon of a B-spline surface's parameters as triangles.
    fn spline_mesh(&mut self, s: &Spline, b: Boundary) -> Option<Mesh> {
        let (su, sv) = (
            (s.nu_ctrl * 4).clamp(4, 64) as f64,
            (s.nv_ctrl * 4).clamp(4, 64) as f64,
        );
        let (du, dv) = (s.u.1 - s.u.0, s.v.1 - s.v.0);
        let counts = |e: V2| {
            let n = |chords: f64, share: f64| (chords * share).ceil().clamp(1.0, chords) as usize;
            (n(su, e[0] / du), n(sv, e[1] / dv))
        };
        // Past a control interval of parameters, a side is always split.
        let tess = Tess {
            counts: &counts,
            max_extent: [4.0 * du / su, 4.0 * dv / sv],
        };
        self.tessellate(b, &tess, |u, v| s.eval(u, v))
    }

    /// The loops of the bounds, their points projected on the surface.
    fn projected_boundary(&mut self, s: &Spline, bounds: &[Value], depth: u32) -> Option<Boundary> {
        let loops = self.face_loops(bounds, depth)?;
        let total: usize = loops.iter().map(Vec::len).sum();
        if total > MAX_PROJECTED {
            return None;
        }
        // The points of a coarse grid start each search.
        self.charge((SEARCH_GRID + 1) * (SEARCH_GRID + 1))?;
        let mut grid: Vec<(f64, f64, V3)> = Vec::new();
        for i in 0..=SEARCH_GRID {
            for k in 0..=SEARCH_GRID {
                let u = s.u.0 + (s.u.1 - s.u.0) * i as f64 / SEARCH_GRID as f64;
                let v = s.v.0 + (s.v.1 - s.v.0) * k as f64 / SEARCH_GRID as f64;
                grid.push((u, v, s.eval(u, v)?));
            }
        }
        let (lo, hi) = grid.iter().fold(
            ([f64::INFINITY; 3], [f64::NEG_INFINITY; 3]),
            |(mut lo, mut hi), g| {
                for k in 0..3 {
                    lo[k] = lo[k].min(g.2[k]);
                    hi[k] = hi[k].max(g.2[k]);
                }
                (lo, hi)
            },
        );
        // A boundary point is on the surface. A tenth of them may be off it
        // by a few percent of its size (a vertex that is not quite where
        // its edge ends); more, or any further, and the bounds are of
        // another surface.
        let size = len(sub(hi, lo)).max(1e-9);
        let (close, far) = (size * 1e-3, size * 5e-2);
        let mut off = 0usize;
        let mut b = Boundary::new();
        let mut evals = 0usize;
        let periods = [s.u.1 - s.u.0, s.v.1 - s.v.0];
        for (n, l) in loops.iter().enumerate() {
            let mut uv: Vec<V2> = Vec::with_capacity(l.len());
            for &q in l {
                let (u, v, d) = s.nearest(q, &grid, &mut evals)?;
                if d > far {
                    return None;
                }
                off += usize::from(d > close);
                let mut p = [u, v];
                // On a surface that closes on itself a point is at either
                // end of it: the one next to the point before.
                if let Some(prev) = uv.last() {
                    for k in 0..2 {
                        if s.closed[k] {
                            p[k] -= periods[k] * ((p[k] - prev[k]) / periods[k]).round();
                        }
                    }
                }
                uv.push(p);
            }
            // A loop that winds round a closed surface is not read.
            let (first, last) = (uv[0], uv[uv.len() - 1]);
            if (0..2).any(|k| s.closed[k] && ((first[k] - last[k]) / periods[k]).round() != 0.0) {
                return None;
            }
            // Sampled finely along curves: the points that keep the shape
            // to a thousandth of the loop's size are enough.
            let (lo, hi) = extent(&uv);
            let tol = 1e-3 * (hi[0] - lo[0]).max(hi[1] - lo[1]);
            let keep = simplify(&uv, tol);
            let ring: Vec<u32> = keep.iter().map(|&i| b.push(uv[i], l[i])).collect();
            if n == 0 {
                b.outer = ring;
            } else {
                b.holes.push(ring);
            }
        }
        self.charge(evals)?;
        (off * 10 <= total).then_some(b)
    }
}

#[cfg(test)]
mod tests {
    use super::super::math::{cross, dot};
    use super::*;

    /// The angle is brought next to the previous one by whole turns, however
    /// far apart they are: adding a turn at a time took a billion steps for
    /// a polyline wound a billion times.
    #[test]
    fn an_angle_is_unrolled_in_one_step_however_far_the_previous_one_is() {
        use std::f64::consts::PI;
        assert!((continuous(0.5, 0.5) - 0.5).abs() < 1e-12);
        assert!((continuous(3.0, -3.0) - (3.0 - TAU)).abs() < 1e-12);
        assert!((continuous(-3.0, 3.0) - (-3.0 + TAU)).abs() < 1e-12);
        for prev in [0.0, 7.0, -40.0, 1.0e6, -1.0e12] {
            for a in [-PI, -1.0, 0.0, 2.5, PI] {
                let c = continuous(a, prev);
                assert!((c - prev).abs() <= PI + 1e-6, "{a} next to {prev} gave {c}");
                let turns = (c - a) / TAU;
                assert!((turns - turns.round()).abs() < 1e-3, "{a} became {c}");
            }
        }
    }

    fn sphere() -> Surf {
        Surf::Sphere {
            pos: Xf::IDENTITY,
            inv: Xf::IDENTITY,
            r: 2.0,
        }
    }

    /// A circle of latitude `v`, counter-clockwise seen from +z.
    fn latitude(v: f64, n: usize) -> Vec<V3> {
        (0..n)
            .map(|k| sphere().eval(TAU * k as f64 / n as f64, v))
            .collect()
    }

    #[test]
    fn a_point_on_a_surface_goes_to_its_parameters_and_back() {
        let s = sphere();
        let p = s.eval(1.0, 0.5);
        let [u, v] = s.uv(p, None);
        assert!((u - 1.0).abs() < 1e-12 && (v - 0.5).abs() < 1e-12);
        let t = Surf::Torus {
            pos: Xf::IDENTITY,
            inv: Xf::IDENTITY,
            big: 3.0,
            small: 1.0,
        };
        let p = t.eval(-2.0, 2.5);
        let [u, v] = t.uv(p, None);
        assert!((u + 2.0).abs() < 1e-12 && (v - 2.5).abs() < 1e-12);
        // The poles are exact.
        assert_eq!(s.eval(0.3, FRAC_PI_2), [0.0, 0.0, 2.0]);
    }

    #[test]
    fn a_loop_round_a_pole_winds_once_and_the_face_is_on_its_left() {
        let s = sphere();
        let ring = latitude(1.0, 16);
        let (_, wind) = unroll(&s, &ring);
        assert_eq!(wind, [1, 0]);
        // Left of a loop that runs counter-clockwise seen from +z is the
        // north cap; the other way round, the south one.
        let b = boundary(&s, std::slice::from_ref(&ring), true).unwrap();
        assert!(b.uv.iter().any(|p| (p[1] - FRAC_PI_2).abs() < 1e-12));
        let b = boundary(&s, std::slice::from_ref(&ring), false).unwrap();
        assert!(b.uv.iter().any(|p| (p[1] + FRAC_PI_2).abs() < 1e-12));
        // Reversed, the loop winds the other way.
        let mut back = ring;
        back.reverse();
        let (_, wind) = unroll(&s, &back);
        assert_eq!(wind, [-1, 0]);
    }

    #[test]
    fn a_small_loop_that_does_not_wind_bounds_the_area_inside_it() {
        let s = sphere();
        // A square of latitude and longitude around (1, 0.2).
        let pts: Vec<V3> = [(0.9, 0.1), (1.1, 0.1), (1.1, 0.3), (0.9, 0.3)]
            .iter()
            .map(|&(u, v)| s.eval(u, v))
            .collect();
        let b = boundary(&s, &[pts], true).unwrap();
        assert_eq!(b.outer.len(), 4);
        assert!(boundary(&s, &[], true).is_none());
    }

    #[test]
    fn a_loop_that_winds_twice_is_not_a_face_here() {
        let s = sphere();
        let mut ring = latitude(0.5, 8);
        ring.extend(latitude(0.5, 8));
        assert!(boundary(&s, &[ring], true).is_none());
    }

    #[test]
    fn the_cross_product_of_the_parameter_derivatives_points_outwards() {
        // Counter-clockwise in (u, v) must be outward for the meshes to be.
        let eps = 1e-6;
        let c = cross_at(&sphere(), 0.7, 0.4, eps);
        let p = sphere().eval(0.7, 0.4);
        assert!(dot(c, p) > 0.0);
        let t = Surf::Torus {
            pos: Xf::IDENTITY,
            inv: Xf::IDENTITY,
            big: 3.0,
            small: 1.0,
        };
        let c = cross_at(&t, 0.7, 2.0, eps);
        let centre = [3.0 * 0.7f64.cos(), 3.0 * 0.7f64.sin(), 0.0];
        assert!(dot(c, sub(t.eval(0.7, 2.0), centre)) > 0.0);
    }

    fn cross_at(s: &Surf, u: f64, v: f64, eps: f64) -> V3 {
        let p = s.eval(u, v);
        cross(sub(s.eval(u + eps, v), p), sub(s.eval(u, v + eps), p))
    }
}
