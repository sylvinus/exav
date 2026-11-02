//! B-spline surfaces (`IfcBSplineSurfaceWithKnots`, and the rational one):
//! evaluation at a parameter pair, and the parameter pair nearest a point.

use super::math::{V3, add, dot, len, scale, sub};

/// Highest degree read.
pub const MAX_DEGREE: usize = 16;

/// A tensor-product B-spline surface, rational when it has weights.
pub struct Spline {
    du: usize,
    dv: usize,
    nv: usize,
    /// Control points, `nv` per row of `u`.
    ctrl: Vec<V3>,
    weights: Option<Vec<f64>>,
    ku: Vec<f64>,
    kv: Vec<f64>,
    /// The parameter domain.
    pub u: (f64, f64),
    pub v: (f64, f64),
    /// Control rows and columns.
    pub nu_ctrl: usize,
    pub nv_ctrl: usize,
    /// Whether the surface's two edges of `u` (of `v`) are the same curve.
    pub closed: [bool; 2],
}

/// A knot vector from multiplicities and values, checked: non-decreasing,
/// long enough for `n` control points of degree `p`, and no longer than a
/// valid one can be made to be.
pub fn expand_knots(mults: &[usize], values: &[f64], n: usize, p: usize) -> Option<Vec<f64>> {
    let total = mults.iter().try_fold(0usize, |a, &x| a.checked_add(x))?;
    if mults.len() != values.len() || total > n + 3 * p + 1 {
        return None;
    }
    let u: Vec<f64> = values
        .iter()
        .zip(mults)
        .flat_map(|(k, &m)| std::iter::repeat_n(*k, m))
        .collect();
    (u.len() > n + p && u.iter().all(|k| k.is_finite()) && u.array_windows().all(|[a, b]| b >= a))
        .then_some(u)
}

/// The knot span of `t`: the largest `k` in `p..n` with `knots[k] <= t`
/// (`t` is kept inside the domain). `knots` has more than `n + p` entries.
fn span(knots: &[f64], n: usize, p: usize, t: f64) -> usize {
    let t = t.clamp(knots[p], knots[n]);
    // Largest k in p..n-1 with knots[k] <= t.
    let (mut lo, mut hi) = (p, n - 1);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if knots[mid] <= t {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// The `p + 1` basis functions that are not zero in span `k` at `t`.
fn basis(knots: &[f64], p: usize, k: usize, t: f64, out: &mut [f64; MAX_DEGREE + 1]) {
    let mut left = [0.0; MAX_DEGREE + 1];
    let mut right = [0.0; MAX_DEGREE + 1];
    out[0] = 1.0;
    for j in 1..=p {
        left[j] = t - knots[k + 1 - j];
        right[j] = knots[k + j] - t;
        let mut saved = 0.0;
        for r in 0..j {
            let den = right[r + 1] + left[j - r];
            let temp = if den != 0.0 { out[r] / den } else { 0.0 };
            out[r] = saved + right[r + 1] * temp;
            saved = left[j - r] * temp;
        }
        out[j] = saved;
    }
}

impl Spline {
    /// `None` unless the data is a valid surface: degrees in range, a
    /// regular grid of control points with more than the degree of them
    /// each way, knots that fit, positive weights, a domain with area.
    pub fn new(
        du: usize,
        dv: usize,
        rows: &[Vec<V3>],
        ku: Vec<f64>,
        kv: Vec<f64>,
        weights: Option<Vec<Vec<f64>>>,
    ) -> Option<Spline> {
        if !(1..=MAX_DEGREE).contains(&du) || !(1..=MAX_DEGREE).contains(&dv) {
            return None;
        }
        let (nu, nv) = (rows.len(), rows.first()?.len());
        if rows.iter().any(|r| r.len() != nv) || nu <= du || nv <= dv {
            return None;
        }
        if ku.len() <= nu + du || kv.len() <= nv + dv {
            return None;
        }
        if let Some(w) = &weights
            && (w.len() != nu
                || w.iter()
                    .any(|r| r.len() != nv || r.iter().any(|x| x.is_nan() || *x <= 0.0)))
        {
            return None;
        }
        let (u, v) = ((ku[du], ku[nu]), (kv[dv], kv[nv]));
        if !(u.1 > u.0 && v.1 > v.0 && u.1.is_finite() && v.1.is_finite()) {
            return None;
        }
        let mut s = Spline {
            du,
            dv,
            nv,
            ctrl: rows.iter().flatten().copied().collect(),
            weights: weights.map(|w| w.into_iter().flatten().collect()),
            ku,
            kv,
            u,
            v,
            nu_ctrl: nu,
            nv_ctrl: nv,
            closed: [false; 2],
        };
        s.closed = [s.is_closed(0), s.is_closed(1)];
        Some(s)
    }

    /// Whether the surface meets itself where parameter `k` (0 for `u`)
    /// ends, along three lines across it.
    fn is_closed(&self, k: usize) -> bool {
        let (along, across) = if k == 0 {
            (self.u, self.v)
        } else {
            (self.v, self.u)
        };
        let at = |t: f64, share: f64| {
            let s = across.0 + (across.1 - across.0) * share;
            if k == 0 {
                self.eval(t, s)
            } else {
                self.eval(s, t)
            }
        };
        let mut lo = [f64::INFINITY; 3];
        let mut hi = [f64::NEG_INFINITY; 3];
        for c in &self.ctrl {
            for i in 0..3 {
                lo[i] = lo[i].min(c[i]);
                hi[i] = hi[i].max(c[i]);
            }
        }
        let tol = 1e-7 * len(sub(hi, lo)).max(1e-9);
        [0.25, 0.5, 0.75]
            .iter()
            .all(|&share| match (at(along.0, share), at(along.1, share)) {
                (Some(p), Some(q)) => len(sub(p, q)) <= tol,
                _ => false,
            })
    }

    /// `t` in parameter `k`: kept inside its domain, or brought into it by
    /// whole turns where the surface closes on itself.
    fn fold(&self, k: usize, t: f64) -> f64 {
        let (lo, hi) = if k == 0 { self.u } else { self.v };
        if self.closed[k] {
            lo + (t - lo).rem_euclid(hi - lo)
        } else {
            t.clamp(lo, hi)
        }
    }

    /// The point at `(u, v)`, which are kept inside the domain, or turned
    /// into it where the surface is closed; `None` for a point that is not
    /// finite.
    pub fn eval(&self, u: f64, v: f64) -> Option<V3> {
        let (nu, nv) = (self.nu_ctrl, self.nv_ctrl);
        let (u, v) = (self.fold(0, u), self.fold(1, v));
        let (ku, kv) = (
            span(&self.ku, nu, self.du, u),
            span(&self.kv, nv, self.dv, v),
        );
        let (mut bu, mut bv) = ([0.0; MAX_DEGREE + 1], [0.0; MAX_DEGREE + 1]);
        basis(&self.ku, self.du, ku, u, &mut bu);
        basis(&self.kv, self.dv, kv, v, &mut bv);
        let mut sum = [0.0; 3];
        let mut wsum = 0.0;
        for (a, &na) in bu.iter().enumerate().take(self.du + 1) {
            let row = ku - self.du + a;
            for (b, &nb) in bv.iter().enumerate().take(self.dv + 1) {
                let at = row * self.nv + kv - self.dv + b;
                let w = na * nb * self.weights.as_ref().map_or(1.0, |w| w[at]);
                let c = self.ctrl[at];
                sum = add(sum, scale(c, w));
                wsum += w;
            }
        }
        let p = scale(sum, 1.0 / wsum);
        (wsum.abs() > 1e-300 && p.iter().all(|x| x.is_finite())).then_some(p)
    }

    /// The parameters of the surface point nearest `target` and its
    /// distance: the nearest of `grid` (parameter pairs and their points),
    /// refined by Gauss-Newton steps, each kept only if it brings the
    /// point nearer. `evals` counts the surface evaluations made, with the
    /// search of the grid as one.
    pub fn nearest(
        &self,
        target: V3,
        grid: &[(f64, f64, V3)],
        evals: &mut usize,
    ) -> Option<(f64, f64, f64)> {
        let &(mut u, mut v, mut s) = grid.iter().min_by(|a, b| {
            let (da, db) = (len(sub(a.2, target)), len(sub(b.2, target)));
            da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
        })?;
        *evals += 1 + grid.len() / 64;
        let mut best = len(sub(s, target));
        let (hu, hv) = ((self.u.1 - self.u.0) * 1e-6, (self.v.1 - self.v.0) * 1e-6);
        for _ in 0..ITERATIONS {
            *evals += 3;
            let r = sub(s, target);
            // One-sided differences that stay inside the domain.
            let (u1, v1) = (
                if u + hu <= self.u.1 { u + hu } else { u - hu },
                if v + hv <= self.v.1 { v + hv } else { v - hv },
            );
            let su = scale(sub(self.eval(u1, v)?, s), 1.0 / (u1 - u));
            let sv = scale(sub(self.eval(u, v1)?, s), 1.0 / (v1 - v));
            let (a, b, c) = (dot(su, su), dot(su, sv), dot(sv, sv));
            let det = a * c - b * b;
            if det.is_nan() || det.abs() <= 1e-300 {
                break;
            }
            let (ru, rv) = (-dot(su, r), -dot(sv, r));
            let (du, dv) = ((c * ru - b * rv) / det, (a * rv - b * ru) / det);
            let mut step = 1.0;
            let mut moved = false;
            for _ in 0..4 {
                *evals += 1;
                let (nu, nv) = (
                    (u + step * du).clamp(self.u.0, self.u.1),
                    (v + step * dv).clamp(self.v.0, self.v.1),
                );
                let ns = self.eval(nu, nv)?;
                let nd = len(sub(ns, target));
                if nd < best {
                    let size = (nu - u).abs() / (self.u.1 - self.u.0)
                        + (nv - v).abs() / (self.v.1 - self.v.0);
                    (u, v, s, best) = (nu, nv, ns, nd);
                    moved = size > 1e-12;
                    break;
                }
                step /= 2.0;
            }
            if !moved {
                break;
            }
        }
        Some((u, v, best))
    }
}

/// Gauss-Newton steps per point.
pub const ITERATIONS: usize = 12;

#[cfg(test)]
mod tests {
    use super::*;

    /// A bilinear patch: degree 1 both ways over the unit square, lifted
    /// at one corner.
    fn patch() -> Spline {
        let rows = vec![
            vec![[0.0, 0.0, 0.0], [0.0, 1.0, 0.0]],
            vec![[1.0, 0.0, 0.0], [1.0, 1.0, 1.0]],
        ];
        let k = vec![0.0, 0.0, 1.0, 1.0];
        Spline::new(1, 1, &rows, k.clone(), k, None).unwrap()
    }

    #[test]
    fn a_bilinear_patch_is_evaluated_at_its_corners_and_middle() {
        let s = patch();
        assert_eq!(s.eval(0.0, 0.0), Some([0.0, 0.0, 0.0]));
        assert_eq!(s.eval(1.0, 1.0), Some([1.0, 1.0, 1.0]));
        assert_eq!(s.eval(0.5, 0.5), Some([0.5, 0.5, 0.25]));
        // Outside the domain the point is that of its edge.
        assert_eq!(s.eval(2.0, -1.0), s.eval(1.0, 0.0));
    }

    #[test]
    fn the_nearest_parameters_of_a_point_on_the_surface() {
        let s = patch();
        let grid: Vec<(f64, f64, V3)> = (0..=4)
            .flat_map(|i| (0..=4).map(move |j| (i as f64 / 4.0, j as f64 / 4.0)))
            .map(|(u, v)| (u, v, s.eval(u, v).unwrap()))
            .collect();
        let mut evals = 0;
        let (u, v, d) = s.nearest([0.3, 0.7, 0.21], &grid, &mut evals).unwrap();
        assert!(evals > 0);
        assert!(
            (u - 0.3).abs() < 1e-6 && (v - 0.7).abs() < 1e-6 && d < 1e-9,
            "{u} {v} {d}"
        );
        // A point high above it is nearest to the corner that is lifted.
        let (u, v, d) = s.nearest([0.3, 0.7, 5.0], &grid, &mut evals).unwrap();
        assert!((u - 1.0).abs() < 1e-6 && (v - 1.0).abs() < 1e-6, "{u} {v}");
        assert!((d - 4.0718546).abs() < 1e-6, "{d}");
    }

    #[test]
    fn knots_must_not_decrease_or_run_long() {
        assert!(expand_knots(&[2, 2], &[0.0, 1.0], 2, 1).is_some());
        assert!(expand_knots(&[2, 2], &[1.0, 0.0], 2, 1).is_none());
        assert!(expand_knots(&[usize::MAX, 2], &[0.0, 1.0], 2, 1).is_none());
        assert!(expand_knots(&[1_000_000], &[0.0], 2, 1).is_none());
        assert!(expand_knots(&[2, 2], &[0.0, f64::INFINITY], 2, 1).is_none());
    }
}
