//! Curves as polylines: polylines, indexed poly curves (line and arc
//! segments), composite and trimmed curves, circles, ellipses, lines and
//! B-splines (rational or not).

use std::f64::consts::TAU;

use super::math::{self, add, cross, dot, len, scale, sub, unit, Xf, V3};
use super::step::Value;
use super::{coords, Reader, MAX_DEPTH};

/// Chords per full turn of a circle.
pub const SEGMENTS_PER_TURN: f64 = 32.0;
/// Most points one curve may have: a B-spline is sampled from its control
/// points, an arc from its angle; nothing else multiplies the file's own.
const MAX_SAMPLES: usize = 1 << 16;

/// Chords for an arc of `sweep` radians.
/// At least four for any visible arc: a shallow arc of a large radius (a
/// curved curtain wall) would otherwise be one straight chord.
pub fn segments(sweep: f64) -> usize {
    let min = if sweep.abs() > 0.05 { 4.0 } else { 1.0 };
    ((sweep.abs() / TAU) * SEGMENTS_PER_TURN)
        .ceil()
        .clamp(min, 4.0 * SEGMENTS_PER_TURN) as usize
}

/// Appends `pts`, without the first if it repeats the last one there.
fn join(out: &mut Vec<V3>, pts: &[V3]) {
    let mut it = pts.iter();
    if let (Some(last), Some(first)) = (out.last(), pts.first()) {
        let tol = 1e-9 * (1.0 + len(*last));
        if len(sub(*last, *first)) <= tol {
            it.next();
        }
    }
    out.extend(it);
}

/// The circle through `a`, `m` and `b`, from `a` through `m` to `b`; a
/// line through the three when they are aligned.
pub fn arc3(a: V3, m: V3, b: V3) -> Vec<V3> {
    let u = sub(m, a);
    let v = sub(b, a);
    let w = cross(u, v);
    let ww = dot(w, w);
    let scale_ = dot(u, u).max(dot(v, v));
    if ww.is_nan() || ww <= 1e-18 * scale_ * scale_ {
        return vec![a, m, b];
    }
    let c = add(
        a,
        scale(
            add(scale(cross(v, w), dot(u, u)), scale(cross(w, u), dot(v, v))),
            1.0 / (2.0 * ww),
        ),
    );
    let r = len(sub(a, c));
    let Some(e1) = unit(sub(a, c)) else {
        return vec![a, m, b];
    };
    let Some(n) = unit(w) else {
        return vec![a, m, b];
    };
    let e2 = cross(n, e1);
    let angle = |p: V3| {
        let d = sub(p, c);
        let t = dot(d, e2).atan2(dot(d, e1));
        if t < 0.0 {
            t + TAU
        } else {
            t
        }
    };
    let (tm, tb) = (angle(m), angle(b));
    let sweep = if tm <= tb { tb } else { tb - TAU };
    let n_seg = segments(sweep);
    let mut out = Vec::with_capacity(n_seg + 1);
    out.push(a);
    for k in 1..n_seg {
        let t = sweep * k as f64 / n_seg as f64;
        out.push(add(c, add(scale(e1, r * t.cos()), scale(e2, r * t.sin()))));
    }
    out.push(b);
    out
}

/// A trimming value: a point or a parameter.
enum Trim {
    Point(V3),
    Param(f64),
}

impl<'a> Reader<'a> {
    pub fn points(&self, v: Option<&Value>) -> Option<Vec<V3>> {
        v?.list()?.iter().map(|p| self.point(p.id()?)).collect()
    }

    /// `IfcCartesianPointList2D`/`3D` coordinates.
    pub fn point_list(&self, id: u32) -> Option<Vec<V3>> {
        let (ty, p) = self.get(id)?;
        if !super::is(
            ty,
            &[b"IFCCARTESIANPOINTLIST2D", b"IFCCARTESIANPOINTLIST3D"],
        ) {
            return None;
        }
        p.first()?.list()?.iter().map(coords).collect()
    }

    /// A bounded curve's points in order; 2D curves have z = 0.
    pub fn curve(&mut self, id: u32, depth: u32) -> Option<Vec<V3>> {
        if depth > MAX_DEPTH {
            return None;
        }
        let (ty, p) = self.get(id)?;
        let pts = match ty {
            b"IFCPOLYLINE" => self.points(p.first())?,
            b"IFCINDEXEDPOLYCURVE" => self.indexed_poly_curve(&p)?,
            b"IFCCOMPOSITECURVE"
            | b"IFC2DCOMPOSITECURVE"
            | b"IFCCOMPOSITECURVEONSURFACE"
            | b"IFCOUTERBOUNDARYCURVE"
            | b"IFCBOUNDARYCURVE" => {
                let mut out = Vec::new();
                for seg in p.first()?.list()?.iter().filter_map(Value::id) {
                    let (sty, sp) = self.get(seg)?;
                    if !super::is(
                        sty,
                        &[
                            b"IFCCOMPOSITECURVESEGMENT",
                            b"IFCREPARAMETRISEDCOMPOSITECURVESEGMENT",
                        ],
                    ) {
                        self.unsupported(sty);
                        return None;
                    }
                    let mut pts = self.curve(sp.get(2)?.id()?, depth + 1)?;
                    if sp.get(1).and_then(Value::boolean) == Some(false) {
                        pts.reverse();
                    }
                    join(&mut out, &pts);
                    if out.len() > MAX_SAMPLES {
                        return None;
                    }
                }
                out
            }
            b"IFCTRIMMEDCURVE" => self.trimmed(&p, depth)?,
            b"IFCCIRCLE" | b"IFCELLIPSE" => {
                let (pos, a, b) = self.conic(ty, &p)?;
                let n = SEGMENTS_PER_TURN as usize;
                (0..=n)
                    .map(|k| conic_point(&pos, a, b, TAU * (k % n) as f64 / n as f64))
                    .collect()
            }
            b"IFCBSPLINECURVEWITHKNOTS" | b"IFCRATIONALBSPLINECURVEWITHKNOTS" => {
                self.bspline(&p)?.into_iter().map(|(_, q)| q).collect()
            }
            b"IFCPCURVE" | b"IFCSURFACECURVE" | b"IFCINTERSECTIONCURVE" | b"IFCSEAMCURVE" => {
                // The 3D curve; the p-curves are its images on surfaces.
                self.curve(p.first()?.id()?, depth + 1)?
            }
            _ => {
                self.unsupported(ty);
                return None;
            }
        };
        (pts.len() >= 2 && pts.len() <= MAX_SAMPLES).then_some(pts)
    }

    fn indexed_poly_curve(&self, p: &[Value]) -> Option<Vec<V3>> {
        let pts = self.point_list(p.first()?.id()?)?;
        let at = |i: &Value| -> Option<V3> {
            pts.get(usize::try_from(i.int()?.checked_sub(1)?).ok()?)
                .copied()
        };
        let segments = match p.get(1) {
            Some(v) if !v.is_null() => v.list()?,
            _ => return Some(pts),
        };
        let mut out: Vec<V3> = Vec::new();
        for s in segments {
            let Value::Typed(kind, inner) = s else {
                return None;
            };
            let idx = inner.list()?;
            match *kind {
                b"IFCLINEINDEX" => {
                    let seg: Vec<V3> = idx.iter().map(at).collect::<Option<_>>()?;
                    join(&mut out, &seg);
                }
                b"IFCARCINDEX" => {
                    if idx.len() != 3 {
                        return None;
                    }
                    join(&mut out, &arc3(at(&idx[0])?, at(&idx[1])?, at(&idx[2])?));
                }
                _ => return None,
            }
            if out.len() > MAX_SAMPLES {
                return None;
            }
        }
        Some(out)
    }

    /// A circle's or an ellipse's placement and semi-axes.
    fn conic(&self, ty: &[u8], p: &[Value]) -> Option<(Xf, f64, f64)> {
        let pos = self.axis2(p.first()?.id()?)?;
        let a = p.get(1)?.num()?;
        let b = if ty == b"IFCELLIPSE" {
            p.get(2)?.num()?
        } else {
            a
        };
        (a > 0.0 && b > 0.0 && a.is_finite() && b.is_finite()).then_some((pos, a, b))
    }

    fn trims(&self, v: Option<&Value>) -> Vec<Trim> {
        let Some(l) = v.and_then(Value::list) else {
            return Vec::new();
        };
        l.iter()
            .filter_map(|t| match t {
                Value::Ref(r) => self.point(*r).map(Trim::Point),
                other => other.num().map(Trim::Param),
            })
            .collect()
    }

    fn trimmed(&mut self, p: &[Value], depth: u32) -> Option<Vec<V3>> {
        let basis = p.first()?.id()?;
        let (t1, t2) = (self.trims(p.get(1)), self.trims(p.get(2)));
        let sense = p.get(3).and_then(Value::boolean).unwrap_or(true);
        let cartesian = p.get(4).and_then(Value::enumeration) == Some(b"CARTESIAN");
        let pick = |t: &[Trim]| -> Option<usize> {
            let point = t.iter().position(|x| matches!(x, Trim::Point(_)));
            let param = t.iter().position(|x| matches!(x, Trim::Param(_)));
            if cartesian {
                point.or(param)
            } else {
                param.or(point)
            }
        };
        let (i1, i2) = (pick(&t1)?, pick(&t2)?);
        let (bty, bp) = self.get(basis)?;
        match bty {
            b"IFCCIRCLE" | b"IFCELLIPSE" => {
                let (pos, a, b) = self.conic(bty, &bp)?;
                let inv = pos.inverse()?;
                let param = |t: &Trim| match t {
                    Trim::Param(v) => *v * self.angle,
                    Trim::Point(q) => {
                        let l = inv.point(*q);
                        (l[1] / b).atan2(l[0] / a)
                    }
                };
                let (s, mut e) = (param(&t1[i1]), param(&t2[i2]));
                // A parameter this far from the start is no arc, and adding a
                // turn to a float that large changes nothing, forever.
                if !(s.is_finite() && e.is_finite()) || (e - s).abs() > 1.0e6 {
                    return None;
                }
                if sense {
                    while e <= s + 1e-12 {
                        e += TAU;
                    }
                    while e - s > TAU + 1e-9 {
                        e -= TAU;
                    }
                } else {
                    while e >= s - 1e-12 {
                        e -= TAU;
                    }
                    while s - e > TAU + 1e-9 {
                        e += TAU;
                    }
                }
                let n = segments(e - s);
                let mut out: Vec<V3> = (0..=n)
                    .map(|k| conic_point(&pos, a, b, s + (e - s) * k as f64 / n as f64))
                    .collect();
                // The ends exactly where the trimming points say.
                if let Trim::Point(q) = t1[i1] {
                    out[0] = q;
                }
                if let Trim::Point(q) = t2[i2] {
                    out[n] = q;
                }
                Some(out)
            }
            b"IFCLINE" => {
                let o = self.point(bp.first()?.id()?)?;
                let vp = self.f.params(bp.get(1)?.id()?)?;
                let d = scale(self.direction(vp.first()?.id()?)?, vp.get(1)?.num()?);
                let at = |t: &Trim| match t {
                    Trim::Point(q) => *q,
                    Trim::Param(u) => add(o, scale(d, *u)),
                };
                Some(vec![at(&t1[i1]), at(&t2[i2])])
            }
            _ => {
                // Any other basis: sampled with parameters, cut between
                // the two trims.
                let samples: Vec<(f64, V3)> = match bty {
                    b"IFCPOLYLINE" => self
                        .points(bp.first())?
                        .into_iter()
                        .enumerate()
                        .map(|(i, q)| (i as f64, q))
                        .collect(),
                    b"IFCBSPLINECURVEWITHKNOTS" | b"IFCRATIONALBSPLINECURVEWITHKNOTS" => {
                        self.bspline(&bp)?
                    }
                    _ => {
                        let pts = self.curve(basis, depth + 1)?;
                        pts.into_iter()
                            .enumerate()
                            .map(|(i, q)| (i as f64, q))
                            .collect()
                    }
                };
                let param = |t: &Trim| match t {
                    Trim::Param(v) => *v,
                    Trim::Point(q) => samples
                        .iter()
                        .min_by(|a, b| {
                            len(sub(a.1, *q))
                                .partial_cmp(&len(sub(b.1, *q)))
                                .unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .map_or(0.0, |s| s.0),
                };
                let (s, e) = (param(&t1[i1]), param(&t2[i2]));
                let (lo, hi) = (s.min(e), s.max(e));
                let at = |t: f64| -> V3 {
                    let k = samples
                        .partition_point(|x| x.0 <= t)
                        .clamp(1, samples.len().max(1))
                        - 1;
                    match (samples.get(k), samples.get(k + 1)) {
                        (Some(a), Some(b)) if b.0 > a.0 => {
                            math::lerp(a.1, b.1, ((t - a.0) / (b.0 - a.0)).clamp(0.0, 1.0))
                        }
                        (Some(a), _) => a.1,
                        _ => [0.0; 3],
                    }
                };
                if samples.is_empty() {
                    return None;
                }
                let mut out = vec![at(lo)];
                out.extend(samples.iter().filter(|x| x.0 > lo && x.0 < hi).map(|x| x.1));
                out.push(at(hi));
                // From the first trim to the second.
                if s > e {
                    out.reverse();
                }
                Some(out)
            }
        }
    }

    /// A B-spline curve sampled, with each sample's parameter.
    fn bspline(&self, p: &[Value]) -> Option<Vec<(f64, V3)>> {
        let degree = usize::try_from(p.first()?.int()?)
            .ok()
            .filter(|d| (1..=16).contains(d))?;
        let ctrl = self.points(p.get(1))?;
        let mults: Vec<usize> = p
            .get(5)?
            .list()?
            .iter()
            .map(|m| usize::try_from(m.int()?).ok())
            .collect::<Option<_>>()?;
        let knots: Vec<f64> = p
            .get(6)?
            .list()?
            .iter()
            .map(Value::num)
            .collect::<Option<_>>()?;
        let weights: Option<Vec<f64>> = match p.get(8) {
            Some(w) => Some(w.list()?.iter().map(Value::num).collect::<Option<_>>()?),
            None => None,
        };
        let n = ctrl.len();
        let total = mults.iter().try_fold(0usize, |a, &m| a.checked_add(m))?;
        if mults.len() != knots.len() || total > n + 3 * degree + 1 || n <= degree {
            return None;
        }
        let u: Vec<f64> = knots
            .iter()
            .zip(&mults)
            .flat_map(|(k, &m)| std::iter::repeat_n(*k, m))
            .collect();
        if u.len() < n + degree + 1 || u.windows(2).any(|w| w[1] < w[0]) {
            return None;
        }
        if weights
            .as_ref()
            .is_some_and(|w| w.len() != n || w.iter().any(|v| *v <= 0.0))
        {
            return None;
        }
        let (lo, hi) = (u[degree], u[n]);
        // The parser keeps no NaN: knots are finite.
        if hi <= lo {
            return None;
        }
        let count = (n * 8).clamp(8, 1024);
        let mut out = Vec::with_capacity(count + 1);
        for k in 0..=count {
            let t = lo + (hi - lo) * k as f64 / count as f64;
            out.push((t, de_boor(degree, &ctrl, weights.as_deref(), &u, t)?));
        }
        Some(out)
    }
}

pub fn conic_point(pos: &Xf, a: f64, b: f64, t: f64) -> V3 {
    pos.point([a * t.cos(), b * t.sin(), 0.0])
}

/// The point at `t` (de Boor's algorithm, in homogeneous coordinates when
/// weighted).
pub fn de_boor(p: usize, ctrl: &[V3], w: Option<&[f64]>, u: &[f64], t: f64) -> Option<V3> {
    let n = ctrl.len();
    // The span: u[k] <= t < u[k + 1], k in p..n.
    let mut k = p;
    while k + 1 < n && u[k + 1] <= t {
        k += 1;
    }
    let mut d: Vec<[f64; 4]> = (0..=p)
        .map(|j| {
            let i = k + j - p;
            let wi = w.map_or(1.0, |w| w[i]);
            let c = ctrl[i];
            [c[0] * wi, c[1] * wi, c[2] * wi, wi]
        })
        .collect();
    for r in 1..=p {
        for j in (r..=p).rev() {
            let i = k + j - p;
            let den = u[i + p + 1 - r] - u[i];
            let a = if den.abs() > 0.0 {
                (t - u[i]) / den
            } else {
                0.0
            };
            let prev = d[j - 1];
            for (c, v) in d[j].iter_mut().enumerate() {
                *v = (1.0 - a) * prev[c] + a * *v;
            }
        }
    }
    let h = d[p];
    (h[3].abs() > 1e-300)
        .then(|| [h[0] / h[3], h[1] / h[3], h[2] / h[3]])
        .filter(|q| q.iter().all(|v| v.is_finite()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_points_make_the_arc_through_them() {
        let pts = arc3([1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [-1.0, 0.0, 0.0]);
        assert_eq!(pts.len(), 17);
        assert!(pts
            .iter()
            .all(|p| (len(*p) - 1.0).abs() < 1e-9 && p[1] >= -1e-12));
        // The other way round: through the bottom.
        let pts = arc3([1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [-1.0, 0.0, 0.0]);
        assert!(pts.iter().all(|p| p[1] <= 1e-12));
    }

    #[test]
    fn a_quadratic_bspline_is_a_parabola() {
        // Bezier control points: (0,0), (1,2), (2,0): y = 2t(1-t)*2 at x = 2t.
        let ctrl = [[0.0, 0.0, 0.0], [1.0, 2.0, 0.0], [2.0, 0.0, 0.0]];
        let u = [0.0, 0.0, 0.0, 1.0, 1.0, 1.0];
        let p = de_boor(2, &ctrl, None, &u, 0.5).unwrap();
        assert!((p[0] - 1.0).abs() < 1e-12 && (p[1] - 1.0).abs() < 1e-12);
        // A rational quarter circle.
        let ctrl = [[1.0, 0.0, 0.0], [1.0, 1.0, 0.0], [0.0, 1.0, 0.0]];
        let w = [1.0, std::f64::consts::FRAC_1_SQRT_2, 1.0];
        for k in 0..=10 {
            let p = de_boor(2, &ctrl, Some(&w), &u, k as f64 / 10.0).unwrap();
            assert!((len(p) - 1.0).abs() < 1e-12);
        }
    }
}
