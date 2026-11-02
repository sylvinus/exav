//! Geometry sections ([MS-VSDX] 2.2.3.2 and 2.4.2) as paths of lines and
//! cubic curves, in the shape's local coordinates in inches. One section is
//! one path; its rows are the vertices and segments of it.

use super::formula::parse_number;
use super::resolve::Tree;
use crate::formats::office::slides::error::{Error, Result};
use std::f64::consts::{FRAC_PI_2, PI, TAU};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Seg {
    Move(f64, f64),
    Line(f64, f64),
    Cubic([f64; 6]),
    Close,
}

#[derive(Debug, Default)]
pub struct GPath {
    pub fill: bool,
    pub stroke: bool,
    pub segs: Vec<Seg>,
}

/// Which side of the chord the arc of an ArcTo row bulges to for a positive
/// bow, looking from its start to its end: 1 is the left, -1 the right.
const BOW_SIDE: f64 = -1.0;

/// Coordinates past this are not drawings.
const LIMIT: f64 = 1.0e7;

struct Builder {
    segs: Vec<Seg>,
    cur: (f64, f64),
    start: (f64, f64),
    open: bool,
    /// Segments left to the shape.
    room: usize,
    eps: f64,
}

impl Builder {
    fn push(&mut self, s: Seg) -> Result<()> {
        if self.room == 0 {
            return Err(Error::TooLarge("geometry segments"));
        }
        self.room -= 1;
        self.segs.push(s);
        Ok(())
    }

    /// Ends the subpath: closed when it came back to where it started.
    fn finish(&mut self) -> Result<()> {
        if self.open
            && self.segs.len() > 2
            && (self.cur.0 - self.start.0).abs() <= self.eps
            && (self.cur.1 - self.start.1).abs() <= self.eps
        {
            self.push(Seg::Close)?;
        }
        self.open = false;
        Ok(())
    }

    fn move_to(&mut self, x: f64, y: f64) -> Result<()> {
        self.finish()?;
        self.push(Seg::Move(x, y))?;
        self.cur = (x, y);
        self.start = (x, y);
        self.open = true;
        Ok(())
    }

    fn ensure_open(&mut self) -> Result<()> {
        if !self.open {
            let (x, y) = self.cur;
            self.move_to(x, y)?;
        }
        Ok(())
    }

    fn line_to(&mut self, x: f64, y: f64) -> Result<()> {
        self.ensure_open()?;
        self.push(Seg::Line(x, y))?;
        self.cur = (x, y);
        Ok(())
    }

    fn cubic(&mut self, c: [f64; 6]) -> Result<()> {
        self.ensure_open()?;
        self.push(Seg::Cubic(c))?;
        self.cur = (c[4], c[5]);
        Ok(())
    }

    fn quad(&mut self, x1: f64, y1: f64, x: f64, y: f64) -> Result<()> {
        let (x0, y0) = self.cur;
        self.cubic([
            x0 + 2.0 / 3.0 * (x1 - x0),
            y0 + 2.0 / 3.0 * (y1 - y0),
            x + 2.0 / 3.0 * (x1 - x),
            y + 2.0 / 3.0 * (y1 - y),
            x,
            y,
        ])
    }

    /// An arc through the current point, `ctrl` and `end` on the ellipse
    /// whose major axis is turned by `ang` and whose axes are as `ratio`.
    fn arc_to(&mut self, end: (f64, f64), ctrl: (f64, f64), ang: f64, ratio: f64) -> Result<()> {
        let ratio = if ratio.is_finite() && ratio > 0.0 && ratio <= 1000.0 {
            ratio
        } else {
            1.0
        };
        let (s, c) = ang.sin_cos();
        // The ellipse as a circle: along its axes, the minor one stretched.
        let fwd = |p: (f64, f64)| (p.0 * c + p.1 * s, (-p.0 * s + p.1 * c) * ratio);
        let inv = |q: (f64, f64)| {
            let y = q.1 / ratio;
            (q.0 * c - y * s, q.0 * s + y * c)
        };
        let (q0, qc, q1) = (fwd(self.cur), fwd(ctrl), fwd(end));
        let Some((cx, cy, r)) = circumcircle(q0, qc, q1) else {
            return self.line_to(end.0, end.1);
        };
        if !(r.is_finite() && r < LIMIT) {
            return self.line_to(end.0, end.1);
        }
        let ang_of = |q: (f64, f64)| (q.1 - cy).atan2(q.0 - cx);
        let (a0, ac, a1) = (ang_of(q0), ang_of(qc), ang_of(q1));
        let ccw_end = (a1 - a0).rem_euclid(TAU);
        let ccw_ctrl = (ac - a0).rem_euclid(TAU);
        let sweep = if ccw_ctrl < ccw_end {
            ccw_end
        } else {
            ccw_end - TAU
        };
        let pieces = ((sweep.abs() / FRAC_PI_2).ceil() as usize).clamp(1, 4);
        let step = sweep / pieces as f64;
        let k = 4.0 / 3.0 * (step / 4.0).tan();
        self.ensure_open()?;
        let mut a = a0;
        for i in 0..pieces {
            let b = a + step;
            let p0 = (cx + r * a.cos(), cy + r * a.sin());
            let p3 = (cx + r * b.cos(), cy + r * b.sin());
            let p1 = (p0.0 - k * r * a.sin(), p0.1 + k * r * a.cos());
            let p2 = (p3.0 + k * r * b.sin(), p3.1 - k * r * b.cos());
            let (m1, m2) = (inv(p1), inv(p2));
            // The last piece ends exactly where the row says.
            let m3 = if i + 1 == pieces { end } else { inv(p3) };
            self.cubic([m1.0, m1.1, m2.0, m2.1, m3.0, m3.1])?;
            a = b;
        }
        Ok(())
    }

    /// A B-spline through the current point as its first control point,
    /// the `ctrl` points after it, the knots one to a control point and
    /// `last` closing the knot vector.
    fn spline(
        &mut self,
        ctrl: &[(f64, f64)],
        knots: &[f64],
        weights: &[f64],
        last: f64,
        degree: usize,
    ) -> Result<()> {
        let samples = nurbs(ctrl, knots, weights, last, degree);
        let end = *ctrl.last().unwrap_or(&self.cur);
        for p in samples {
            self.line_to(p.0, p.1)?;
        }
        if self.cur != end {
            self.line_to(end.0, end.1)?;
        }
        Ok(())
    }
}

/// Centre and radius of the circle through three points.
fn circumcircle(a: (f64, f64), b: (f64, f64), c: (f64, f64)) -> Option<(f64, f64, f64)> {
    let d = 2.0 * (a.0 * (b.1 - c.1) + b.0 * (c.1 - a.1) + c.0 * (a.1 - b.1));
    let scale =
        a.0.abs()
            .max(a.1.abs())
            .max(b.0.abs())
            .max(b.1.abs())
            .max(1e-9);
    if !d.is_finite() || d.abs() < 1e-12 * scale * scale {
        return None;
    }
    let (a2, b2, c2) = (
        a.0 * a.0 + a.1 * a.1,
        b.0 * b.0 + b.1 * b.1,
        c.0 * c.0 + c.1 * c.1,
    );
    let ux = (a2 * (b.1 - c.1) + b2 * (c.1 - a.1) + c2 * (a.1 - b.1)) / d;
    let uy = (a2 * (c.0 - b.0) + b2 * (a.0 - c.0) + c2 * (b.0 - a.0)) / d;
    let r = ((a.0 - ux).powi(2) + (a.1 - uy).powi(2)).sqrt();
    (ux.is_finite() && uy.is_finite()).then_some((ux, uy, r))
}

/// The basis functions of degree `p` at `u` in knot span `span`.
fn basis(span: usize, u: f64, p: usize, knots: &[f64]) -> Vec<f64> {
    let mut n = vec![0.0; p + 1];
    let mut left = vec![0.0; p + 1];
    let mut right = vec![0.0; p + 1];
    n[0] = 1.0;
    for j in 1..=p {
        left[j] = u - knots[span + 1 - j];
        right[j] = knots[span + j] - u;
        let mut saved = 0.0;
        for r in 0..j {
            let d = right[r + 1] + left[j - r];
            let t = if d == 0.0 { 0.0 } else { n[r] / d };
            n[r] = saved + right[r + 1] * t;
            saved = left[j - r] * t;
        }
        n[j] = saved;
    }
    n
}

/// Points along a NURBS, after its first control point and up to its last,
/// as a polyline fine enough to look like the curve. Without a valid knot
/// vector, the control polygon.
fn nurbs(
    ctrl: &[(f64, f64)],
    knots: &[f64],
    weights: &[f64],
    last: f64,
    degree: usize,
) -> Vec<(f64, f64)> {
    let count = ctrl.len();
    let polygon = || ctrl.iter().skip(1).copied().collect::<Vec<_>>();
    if count < 2 || degree == 0 || degree >= count || knots.len() != count || weights.len() != count
    {
        return polygon();
    }
    let n = count - 1;
    let mut u: Vec<f64> = knots.to_vec();
    u.extend(std::iter::repeat_n(last, degree + 1));
    if u.iter().any(|k| !k.is_finite()) || u.array_windows().any(|[a, b]| b < a) {
        return polygon();
    }
    let (lo, hi) = (u[degree], u[n + 1]);
    if hi <= lo {
        return polygon();
    }
    // Eight points on each span between distinct knots.
    let mut cuts: Vec<f64> = vec![lo];
    for &k in &u[degree..=n + 1] {
        if k > *cuts.last().unwrap_or(&lo) {
            cuts.push(k);
        }
    }
    let per = 8usize;
    let mut out = vec![];
    for [a, b] in cuts.array_windows() {
        for i in 1..=per {
            let t = a + (b - a) * i as f64 / per as f64;
            if out.len() >= 4096 {
                return polygon();
            }
            if t >= hi {
                break;
            }
            let span = (degree..=n)
                .rev()
                .find(|&s| u[s] <= t && t < u[s + 1])
                .unwrap_or(n);
            let b = basis(span, t, degree, &u);
            let (mut x, mut y, mut sum) = (0.0, 0.0, 0.0);
            for (j, nb) in b.iter().enumerate() {
                let i = span - degree + j;
                let wt = nb * weights[i];
                x += wt * ctrl[i].0;
                y += wt * ctrl[i].1;
                sum += wt;
            }
            if sum == 0.0 {
                return polygon();
            }
            out.push((x / sum, y / sum));
        }
    }
    out.push(ctrl[n]);
    out
}

/// The numbers in the arguments of `NURBS(...)` or `POLYLINE(...)`.
fn arguments(f: &str) -> Vec<f64> {
    let inner = match (f.find('('), f.rfind(')')) {
        (Some(a), Some(b)) if a < b => &f[a + 1..b],
        _ => return vec![],
    };
    inner
        .split(',')
        .map(|s| parse_number(s).unwrap_or(0.0))
        .take(60_000)
        .collect()
}

/// The paths of the geometry sections of shape `n`, `w` by `h` inches, at
/// most `max_segs` segments in all.
pub fn paths(t: &Tree, n: usize, w: f64, h: f64, max_segs: usize) -> Result<Vec<GPath>> {
    let mut out = vec![];
    let mut room = max_segs;
    let eps = 1e-6 * (1.0 + w.abs().max(h.abs()));
    let round = t
        .num(n, "Rounding")
        .filter(|r| r.is_finite())
        .map_or(0.0, |r| r.max(0.0));
    for six in t.sections(n, "Geometry") {
        let flag = |name: &str| {
            t.section_val(n, "Geometry", six, name)
                .and_then(|v| v.num())
                .is_some_and(|v| v != 0.0)
        };
        if flag("NoShow") {
            continue;
        }
        let mut b = Builder {
            segs: vec![],
            cur: (0.0, 0.0),
            start: (0.0, 0.0),
            open: false,
            room,
            eps,
        };
        rows(t, n, six, w, h, &mut b)?;
        b.finish()?;
        room = b.room;
        let mut segs = b.segs;
        if round > 0.0 {
            let rounded = round_corners(&segs, round.min(LIMIT));
            // Each corner is one segment more.
            let extra = rounded.len().saturating_sub(segs.len());
            room = room
                .checked_sub(extra)
                .ok_or(Error::TooLarge("geometry segments"))?;
            segs = rounded;
        }
        if !segs.is_empty() {
            out.push(GPath {
                fill: !flag("NoFill"),
                stroke: !flag("NoLine"),
                segs,
            });
        }
    }
    Ok(out)
}

/// The two ends of a corner's arc and its two handles.
type Arc = ((f64, f64), (f64, f64), (f64, f64), (f64, f64));

/// The subpaths of straight segments with their corners rounded by arcs of
/// radius `r` ([MS-VSDX] 2.4.4.298 Rounding): an arc is as long as the
/// shorter side leaves room for, half of it at most. Subpaths with curves
/// are left as they are.
fn round_corners(segs: &[Seg], r: f64) -> Vec<Seg> {
    let mut out = Vec::with_capacity(segs.len() + segs.len() / 2);
    let mut i = 0;
    while i < segs.len() {
        // One subpath: from a Move to the next Move.
        let mut j = i + 1;
        while j < segs.len() && !matches!(segs[j], Seg::Move(..)) {
            j += 1;
        }
        let sub = &segs[i..j];
        i = j;
        let straight = sub.iter().all(|s| !matches!(s, Seg::Cubic(_)));
        let (Seg::Move(x0, y0), true) = (sub[0], straight) else {
            out.extend_from_slice(sub);
            continue;
        };
        let closed = sub.last() == Some(&Seg::Close);
        let mut pts = vec![(x0, y0)];
        for s in &sub[1..] {
            if let Seg::Line(x, y) = s {
                pts.push((*x, *y));
            }
        }
        if closed && pts.len() > 1 && pts.first() == pts.last() {
            pts.pop();
        }
        let n = pts.len();
        if n < 3 {
            out.extend_from_slice(sub);
            continue;
        }
        // The two points of the arc at corner `k`, with its handles; `None`
        // where the corner is not one (a straight angle, or an end).
        let corner = |k: usize| -> Option<Arc> {
            if !closed && (k == 0 || k == n - 1) {
                return None;
            }
            let (a, b, c) = (pts[(k + n - 1) % n], pts[k], pts[(k + 1) % n]);
            let (u, v) = ((a.0 - b.0, a.1 - b.1), (c.0 - b.0, c.1 - b.1));
            let (lu, lv) = (u.0.hypot(u.1), v.0.hypot(v.1));
            if lu < 1e-12 || lv < 1e-12 {
                return None;
            }
            let (u, v) = ((u.0 / lu, u.1 / lu), (v.0 / lv, v.1 / lv));
            // The angle between the sides; its tangent length for radius r.
            let cos = (u.0 * v.0 + u.1 * v.1).clamp(-1.0, 1.0);
            let phi = cos.acos();
            if phi > PI - 1e-6 || phi < 1e-6 {
                return None;
            }
            let t = (r / (phi / 2.0).tan()).min(lu / 2.0).min(lv / 2.0);
            let radius = t * (phi / 2.0).tan();
            // The handle along the tangent for the arc that turns by
            // pi - phi.
            let turn = PI - phi;
            let handle = 4.0 / 3.0 * (turn / 4.0).tan() * radius;
            let p0 = (b.0 + u.0 * t, b.1 + u.1 * t);
            let p3 = (b.0 + v.0 * t, b.1 + v.1 * t);
            let p1 = (p0.0 - u.0 * handle, p0.1 - u.1 * handle);
            let p2 = (p3.0 - v.0 * handle, p3.1 - v.1 * handle);
            Some((p0, p1, p2, p3))
        };
        let corners: Vec<_> = (0..n).map(corner).collect();
        // Start where the first side ends: at the first corner's arc end,
        // or the first point.
        let start = match corners[0] {
            Some((_, _, _, p3)) if closed => p3,
            _ => pts[0],
        };
        out.push(Seg::Move(start.0, start.1));
        let order: Vec<usize> = if closed {
            (1..n).chain(std::iter::once(0)).collect()
        } else {
            (1..n).collect()
        };
        for k in order {
            match corners[k] {
                Some((p0, p1, p2, p3)) => {
                    out.push(Seg::Line(p0.0, p0.1));
                    out.push(Seg::Cubic([p1.0, p1.1, p2.0, p2.1, p3.0, p3.1]));
                }
                None => out.push(Seg::Line(pts[k].0, pts[k].1)),
            }
        }
        if closed {
            out.push(Seg::Close);
        }
    }
    out
}

fn rows(t: &Tree, n: usize, six: u32, w: f64, h: f64, b: &mut Builder) -> Result<()> {
    // A spline being collected: control points, knots, weights, last knot
    // and degree.
    type Spline = (Vec<(f64, f64)>, Vec<f64>, Vec<f64>, f64, usize);
    let mut spline: Option<Spline> = None;
    for (key, ty) in t.rows(n, "Geometry", Some(six)) {
        let v = |c: &str| {
            t.row_num(n, "Geometry", Some(six), &key, c)
                .filter(|v| v.is_finite())
                .map_or(0.0, |v| v.clamp(-LIMIT, LIMIT))
        };
        let ty = ty.unwrap_or("");
        if ty != "SplineKnot"
            && let Some((c, k, wt, last, d)) = spline.take()
        {
            b.spline(&c, &k, &wt, last, d)?;
        }
        match ty {
            "MoveTo" => b.move_to(v("X"), v("Y"))?,
            "RelMoveTo" => b.move_to(v("X") * w, v("Y") * h)?,
            "LineTo" => b.line_to(v("X"), v("Y"))?,
            "RelLineTo" => b.line_to(v("X") * w, v("Y") * h)?,
            "ArcTo" => {
                let (p0, p1) = (b.cur, (v("X"), v("Y")));
                let (dx, dy) = (p1.0 - p0.0, p1.1 - p0.1);
                let chord = dx.hypot(dy);
                let bow = v("A");
                if chord < 1e-9 || bow.abs() < 1e-9 {
                    b.line_to(p1.0, p1.1)?;
                } else {
                    let m = (
                        (p0.0 + p1.0) / 2.0 - dy / chord * bow * BOW_SIDE,
                        (p0.1 + p1.1) / 2.0 + dx / chord * bow * BOW_SIDE,
                    );
                    b.arc_to(p1, m, 0.0, 1.0)?;
                }
            }
            "EllipticalArcTo" => {
                b.arc_to((v("X"), v("Y")), (v("A"), v("B")), v("C"), v("D"))?;
            }
            "RelEllipticalArcTo" => {
                b.arc_to(
                    (v("X") * w, v("Y") * h),
                    (v("A") * w, v("B") * h),
                    v("C"),
                    v("D"),
                )?;
            }
            "Ellipse" => {
                let (cx, cy) = (v("X"), v("Y"));
                let (ux, uy) = (v("A") - cx, v("B") - cy);
                let (vx, vy) = (v("C") - cx, v("D") - cy);
                let pt = |t: f64| {
                    (
                        cx + ux * t.cos() + vx * t.sin(),
                        cy + uy * t.cos() + vy * t.sin(),
                    )
                };
                let d = |t: f64| (-ux * t.sin() + vx * t.cos(), -uy * t.sin() + vy * t.cos());
                let k = 4.0 / 3.0 * (PI / 8.0).tan();
                let p = pt(0.0);
                b.move_to(p.0, p.1)?;
                for i in 0..4 {
                    let (t0, t1) = (i as f64 * FRAC_PI_2, (i + 1) as f64 * FRAC_PI_2);
                    let (a, e) = (pt(t0), pt(t1));
                    let (da, de) = (d(t0), d(t1));
                    b.cubic([
                        a.0 + k * da.0,
                        a.1 + k * da.1,
                        e.0 - k * de.0,
                        e.1 - k * de.1,
                        e.0,
                        e.1,
                    ])?;
                }
                b.cur = b.start;
            }
            "InfiniteLine" => {
                let (p, q) = ((v("X"), v("Y")), (v("A"), v("B")));
                if let Some((a, e)) = clip_line(p, q, w, h) {
                    b.move_to(a.0, a.1)?;
                    b.line_to(e.0, e.1)?;
                }
            }
            "PolylineTo" => {
                let text = match t.row_val(n, "Geometry", Some(six), &key, "A") {
                    Some(super::formula::Val::Str(s)) => s,
                    _ => String::new(),
                };
                let a = arguments(&text);
                if a.len() >= 2 {
                    let (xs, ys) = (
                        if a[0] == 0.0 { w } else { 1.0 },
                        if a[1] == 0.0 { h } else { 1.0 },
                    );
                    for p in a[2..].as_chunks::<2>().0 {
                        b.line_to(
                            p[0].clamp(-LIMIT, LIMIT) * xs,
                            p[1].clamp(-LIMIT, LIMIT) * ys,
                        )?;
                    }
                }
                b.line_to(v("X"), v("Y"))?;
            }
            "NURBSTo" => {
                let text = match t.row_val(n, "Geometry", Some(six), &key, "E") {
                    Some(super::formula::Val::Str(s)) => s,
                    _ => String::new(),
                };
                let a = arguments(&text);
                let mut ctrl = vec![b.cur];
                let mut knots = vec![v("C")];
                let mut weights = vec![v("D")];
                let (last, degree) = (
                    a.first().copied().unwrap_or(1.0),
                    a.get(1).copied().unwrap_or(3.0),
                );
                if a.len() >= 4 {
                    let (xs, ys) = (
                        if a[2] == 0.0 { w } else { 1.0 },
                        if a[3] == 0.0 { h } else { 1.0 },
                    );
                    for p in a[4..].as_chunks::<4>().0 {
                        ctrl.push((
                            p[0].clamp(-LIMIT, LIMIT) * xs,
                            p[1].clamp(-LIMIT, LIMIT) * ys,
                        ));
                        knots.push(p[2]);
                        weights.push(p[3]);
                    }
                }
                ctrl.push((v("X"), v("Y")));
                knots.push(v("A"));
                weights.push(v("B"));
                b.spline(
                    &ctrl,
                    &knots,
                    &weights,
                    last,
                    degree.clamp(0.0, 25.0) as usize,
                )?;
            }
            "SplineStart" => {
                let ctrl = vec![b.cur, (v("X"), v("Y"))];
                spline = Some((
                    ctrl,
                    vec![v("B"), v("A")],
                    vec![1.0, 1.0],
                    v("C"),
                    v("D").clamp(0.0, 25.0) as usize,
                ));
            }
            "SplineKnot" => {
                if let Some((c, k, wt, _, _)) = spline.as_mut() {
                    c.push((v("X"), v("Y")));
                    k.push(v("A"));
                    wt.push(1.0);
                }
            }
            "RelCubBezTo" => b.cubic([
                v("A") * w,
                v("B") * h,
                v("C") * w,
                v("D") * h,
                v("X") * w,
                v("Y") * h,
            ])?,
            "RelQuadBezTo" => b.quad(v("A") * w, v("B") * h, v("X") * w, v("Y") * h)?,
            _ => {}
        }
    }
    if let Some((c, k, wt, last, d)) = spline.take() {
        b.spline(&c, &k, &wt, last, d)?;
    }
    Ok(())
}

/// The part of the line through `p` and `q` inside the box from the
/// origin to (`w`, `h`), either way round.
fn clip_line(p: (f64, f64), q: (f64, f64), w: f64, h: f64) -> Option<((f64, f64), (f64, f64))> {
    let d = (q.0 - p.0, q.1 - p.1);
    if d.0.abs() < 1e-12 && d.1.abs() < 1e-12 {
        return None;
    }
    let (mut lo, mut hi) = (f64::NEG_INFINITY, f64::INFINITY);
    for (p0, d0, a, b) in [
        (p.0, d.0, 0.0f64.min(w), 0.0f64.max(w)),
        (p.1, d.1, 0.0f64.min(h), 0.0f64.max(h)),
    ] {
        if d0.abs() < 1e-12 {
            if p0 < a || p0 > b {
                return None;
            }
        } else {
            let (t1, t2) = ((a - p0) / d0, (b - p0) / d0);
            lo = lo.max(t1.min(t2));
            hi = hi.min(t1.max(t2));
        }
    }
    (lo.is_finite() && hi.is_finite() && lo <= hi).then_some((
        (p.0 + lo * d.0, p.1 + lo * d.1),
        (p.0 + hi * d.0, p.1 + hi * d.1),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::slides::limits::{Budget, Limits};
    use crate::formats::office::slides::vsdx::resolve::{Doc, Master, tests::shapes};
    use std::collections::HashMap;

    fn geometry(rows: &str, w: f64, h: f64, max: usize) -> Result<Vec<GPath>> {
        let page = shapes(&format!(
            "<S><Shape ID='1'><Section N='Geometry' IX='0'><Cell N='NoFill' V='0'/>{rows}</Section></Shape></S>"
        ));
        let d = Doc::default();
        let m: HashMap<u32, Master> = HashMap::new();
        let t = Tree::build(&d, &m, &page, &mut Budget::new(Limits::default())).unwrap();
        paths(&t, t.roots[0], w, h, max)
    }

    fn row(i: u32, t: &str, cells: &[(&str, &str)]) -> String {
        let c: String = cells
            .iter()
            .map(|(n, v)| format!("<Cell N='{n}' V='{v}'/>"))
            .collect();
        format!("<Row T='{t}' IX='{i}'>{c}</Row>")
    }

    fn near(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-6
    }

    #[test]
    fn lines_and_relative_lines_close_where_they_start() {
        let rows = [
            row(1, "MoveTo", &[("X", "0"), ("Y", "0")]),
            row(2, "LineTo", &[("X", "2"), ("Y", "0")]),
            row(3, "RelLineTo", &[("X", "1"), ("Y", "1")]),
            row(4, "LineTo", &[("X", "0"), ("Y", "1")]),
            row(5, "RelLineTo", &[("X", "0"), ("Y", "0")]),
        ]
        .concat();
        let p = geometry(&rows, 2.0, 1.0, 100).unwrap();
        assert_eq!(p.len(), 1);
        assert!(p[0].fill && p[0].stroke);
        assert_eq!(
            p[0].segs,
            vec![
                Seg::Move(0.0, 0.0),
                Seg::Line(2.0, 0.0),
                Seg::Line(2.0, 1.0),
                Seg::Line(0.0, 1.0),
                Seg::Line(0.0, 0.0),
                Seg::Close
            ]
        );
    }

    #[test]
    fn an_open_path_is_not_closed_and_move_to_starts_another_subpath() {
        let rows = [
            row(1, "MoveTo", &[("X", "0"), ("Y", "0")]),
            row(2, "LineTo", &[("X", "1"), ("Y", "0")]),
            row(3, "MoveTo", &[("X", "5"), ("Y", "5")]),
            row(4, "LineTo", &[("X", "6"), ("Y", "5")]),
        ]
        .concat();
        let p = geometry(&rows, 1.0, 1.0, 100).unwrap();
        assert!(!p[0].segs.contains(&Seg::Close));
        assert_eq!(
            p[0].segs
                .iter()
                .filter(|s| matches!(s, Seg::Move(..)))
                .count(),
            2
        );
    }

    #[test]
    fn flags_hide_a_path_or_its_fill_and_line() {
        let page = shapes(
            "<S><Shape ID='1'>
              <Section N='Geometry' IX='0'><Cell N='NoFill' V='1'/><Cell N='NoLine' V='0'/>
                <Row T='MoveTo' IX='1'><Cell N='X' V='0'/><Cell N='Y' V='0'/></Row>
                <Row T='LineTo' IX='2'><Cell N='X' V='1'/><Cell N='Y' V='1'/></Row></Section>
              <Section N='Geometry' IX='1'><Cell N='NoShow' V='1'/>
                <Row T='MoveTo' IX='1'><Cell N='X' V='0'/><Cell N='Y' V='0'/></Row></Section>
              <Section N='Geometry' IX='2'><Cell N='NoLine' V='1'/>
                <Row T='MoveTo' IX='1'><Cell N='X' V='0'/><Cell N='Y' V='0'/></Row></Section></Shape></S>",
        );
        let d = Doc::default();
        let m = HashMap::new();
        let t = Tree::build(&d, &m, &page, &mut Budget::new(Limits::default())).unwrap();
        let p = paths(&t, 0, 1.0, 1.0, 100).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].fill, p[0].stroke), (false, true));
        assert_eq!((p[1].fill, p[1].stroke), (true, false));
    }

    #[test]
    fn an_elliptical_arc_passes_through_its_points_and_ends_where_it_says() {
        // A half circle of radius 1 about (1, 0) from (0, 0) to (2, 0) over
        // the top: the control point is the top of it.
        let rows = [
            row(1, "MoveTo", &[("X", "0"), ("Y", "0")]),
            row(
                2,
                "EllipticalArcTo",
                &[
                    ("X", "2"),
                    ("Y", "0"),
                    ("A", "1"),
                    ("B", "1"),
                    ("C", "0"),
                    ("D", "1"),
                ],
            ),
        ]
        .concat();
        let p = geometry(&rows, 2.0, 1.0, 100).unwrap();
        let cubics: Vec<[f64; 6]> = p[0]
            .segs
            .iter()
            .filter_map(|s| {
                if let Seg::Cubic(c) = s {
                    Some(*c)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(cubics.len(), 2);
        // The middle of the arc is the control point.
        assert!(near(cubics[0][4], 1.0) && near(cubics[0][5], 1.0));
        let last = cubics[1];
        assert_eq!((last[4], last[5]), (2.0, 0.0));
        // Every control point stays within the circle's bounding box.
        for c in &cubics {
            for p in c.chunks(2) {
                assert!(
                    p[0] > -0.01 && p[0] < 2.01 && p[1] > -0.01 && p[1] < 1.01,
                    "{p:?}"
                );
            }
        }
    }

    #[test]
    fn an_arc_with_a_bow_bulges_by_the_bow_to_the_right_of_its_direction() {
        let arc = |bow: &str| {
            let rows = [
                row(1, "MoveTo", &[("X", "0"), ("Y", "0")]),
                row(2, "ArcTo", &[("X", "2"), ("Y", "0"), ("A", bow)]),
            ]
            .concat();
            let p = geometry(&rows, 2.0, 1.0, 100).unwrap();
            let cubics: Vec<[f64; 6]> = p[0]
                .segs
                .iter()
                .filter_map(|s| {
                    if let Seg::Cubic(c) = s {
                        Some(*c)
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(cubics.len(), 2);
            (cubics[0], cubics[1])
        };
        // From the left to the right with a positive bow the arc dips: its
        // middle is half a unit below the middle of the chord.
        let (first, last) = arc("0.5");
        assert!(near(first[4], 1.0) && near(first[5], -0.5), "{first:?}");
        assert_eq!((last[4], last[5]), (2.0, 0.0));
        let (first, _) = arc("-0.5");
        assert!(near(first[4], 1.0) && near(first[5], 0.5), "{first:?}");
    }

    #[test]
    fn an_ellipse_row_is_a_closed_ellipse_through_its_points() {
        let rows = row(
            1,
            "Ellipse",
            &[
                ("X", "1"),
                ("Y", "1"),
                ("A", "2"),
                ("B", "1"),
                ("C", "1"),
                ("D", "2"),
            ],
        );
        let p = geometry(&rows, 2.0, 2.0, 100).unwrap();
        let c: Vec<[f64; 6]> = p[0]
            .segs
            .iter()
            .filter_map(|s| {
                if let Seg::Cubic(c) = s {
                    Some(*c)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(c.len(), 4);
        assert!(near(c[0][4], 1.0) && near(c[0][5], 2.0));
        // A circle of radius 1: the handle of the first quarter is 0.5523
        // along the tangent at (2, 1).
        assert!(
            near(c[0][0], 2.0) && near(c[0][1], 1.0 + 0.5522847498),
            "{:?}",
            c[0]
        );
        assert!(near(c[3][4], 2.0) && near(c[3][5], 1.0));
        assert_eq!(p[0].segs.last(), Some(&Seg::Close));
    }

    #[test]
    fn a_polyline_row_is_lines_relative_or_local() {
        let page = shapes(
            "<S><Shape ID='1'><Section N='Geometry' IX='0'>
              <Row T='MoveTo' IX='1'><Cell N='X' V='0'/><Cell N='Y' V='0'/></Row>
              <Row T='PolylineTo' IX='2'><Cell N='X' V='2'/><Cell N='Y' V='1'/><Cell N='A' V='POLYLINE(0, 0, 0.5, 0.5, 1, 0)'/></Row>
              </Section></Shape></S>",
        );
        let d = Doc::default();
        let m = HashMap::new();
        let t = Tree::build(&d, &m, &page, &mut Budget::new(Limits::default())).unwrap();
        let p = paths(&t, 0, 4.0, 2.0, 100).unwrap();
        assert_eq!(
            p[0].segs,
            vec![
                Seg::Move(0.0, 0.0),
                Seg::Line(2.0, 1.0),
                Seg::Line(4.0, 0.0),
                Seg::Line(2.0, 1.0)
            ]
        );
    }

    #[test]
    fn a_nurbs_follows_its_control_points_and_ends_at_the_last() {
        // A cubic Bezier: four control points, knots 0 0 0 0 | 1 1 1 1.
        let rows = [
            row(1, "MoveTo", &[("X", "0"), ("Y", "0")]),
            row(
                2,
                "NURBSTo",
                &[
                    ("X", "3"),
                    ("Y", "0"),
                    ("A", "0"),
                    ("B", "1"),
                    ("C", "0"),
                    ("D", "1"),
                    ("E", "NURBS(1, 3, 1, 1, 1,2,0,1, 2,2,0,1)"),
                ],
            ),
        ]
        .concat();
        let p = geometry(&rows, 3.0, 2.0, 1000).unwrap();
        let pts: Vec<(f64, f64)> = p[0]
            .segs
            .iter()
            .filter_map(|s| {
                if let Seg::Line(x, y) = s {
                    Some((*x, *y))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(*pts.last().unwrap(), (3.0, 0.0));
        assert!(pts.len() > 4);
        // The middle of the Bezier (0,0) (1,2) (2,2) (3,0) is (1.5, 1.5).
        let mid = pts
            .iter()
            .find(|p| near(p.0, 1.5))
            .expect("a point at x = 1.5");
        assert!(near(mid.1, 1.5), "{mid:?}");
        assert!(pts.iter().all(|p| p.1 <= 1.5 + 1e-9 && p.1 >= -1e-9));
    }

    #[test]
    fn a_nurbs_without_a_valid_knot_vector_is_its_control_polygon() {
        let rows = [
            row(1, "MoveTo", &[("X", "0"), ("Y", "0")]),
            row(
                2,
                "NURBSTo",
                &[
                    ("X", "3"),
                    ("Y", "0"),
                    ("A", "9"),
                    ("B", "1"),
                    ("C", "5"),
                    ("D", "1"),
                    ("E", "NURBS(1, 3, 1, 1, 1,2,0,1)"),
                ],
            ),
        ]
        .concat();
        let p = geometry(&rows, 3.0, 2.0, 1000).unwrap();
        assert_eq!(
            p[0].segs,
            vec![
                Seg::Move(0.0, 0.0),
                Seg::Line(1.0, 2.0),
                Seg::Line(3.0, 0.0)
            ]
        );
    }

    #[test]
    fn an_infinite_line_is_cut_at_the_box() {
        let rows = row(
            1,
            "InfiniteLine",
            &[("X", "0"), ("Y", "0"), ("A", "1"), ("B", "1")],
        );
        let p = geometry(&rows, 4.0, 2.0, 100).unwrap();
        assert_eq!(p[0].segs, vec![Seg::Move(0.0, 0.0), Seg::Line(2.0, 2.0)]);
        // A line that misses the box is not drawn.
        let rows = row(
            1,
            "InfiniteLine",
            &[("X", "9"), ("Y", "0"), ("A", "9"), ("B", "1")],
        );
        assert!(geometry(&rows, 4.0, 2.0, 100).unwrap().is_empty());
    }

    #[test]
    fn relative_bezier_rows_scale_with_the_shape() {
        let rows = [
            row(1, "RelMoveTo", &[("X", "0"), ("Y", "0")]),
            row(
                2,
                "RelCubBezTo",
                &[
                    ("X", "1"),
                    ("Y", "1"),
                    ("A", "0.25"),
                    ("B", "0"),
                    ("C", "1"),
                    ("D", "0.5"),
                ],
            ),
            row(
                3,
                "RelQuadBezTo",
                &[("X", "0"), ("Y", "0"), ("A", "1"), ("B", "1")],
            ),
        ]
        .concat();
        let p = geometry(&rows, 4.0, 2.0, 100).unwrap();
        assert_eq!(p[0].segs[1], Seg::Cubic([1.0, 0.0, 4.0, 1.0, 4.0, 2.0]));
        assert!(matches!(p[0].segs[2], Seg::Cubic(_)));
    }

    fn square() -> Vec<Seg> {
        vec![
            Seg::Move(0.0, 0.0),
            Seg::Line(1.0, 0.0),
            Seg::Line(1.0, 1.0),
            Seg::Line(0.0, 1.0),
            Seg::Line(0.0, 0.0),
            Seg::Close,
        ]
    }

    #[test]
    fn rounding_replaces_each_corner_of_a_closed_path_by_an_arc() {
        let p = round_corners(&square(), 0.25);
        assert_eq!(p.len(), 10);
        let at = |s: Seg, x: f64, y: f64| match s {
            Seg::Move(a, b) | Seg::Line(a, b) => near(a, x) && near(b, y),
            _ => false,
        };
        assert!(at(p[0], 0.25, 0.0) && at(p[1], 0.75, 0.0), "{p:?}");
        // The arc at (1, 0) leaves along the side and turns up; its handles
        // are 4/3 tan(pi/8) of the radius along the sides.
        let Seg::Cubic(c) = p[2] else { panic!("{p:?}") };
        let h = 4.0 / 3.0 * (std::f64::consts::PI / 8.0).tan() * 0.25;
        assert!(near(c[0], 0.75 + h) && near(c[1], 0.0), "{c:?}");
        assert!(near(c[2], 1.0) && near(c[3], 0.25 - h), "{c:?}");
        assert!(near(c[4], 1.0) && near(c[5], 0.25), "{c:?}");
        assert_eq!(p[9], Seg::Close);
        // Where the sides are short the arc is half of them at most.
        let big = round_corners(&square(), 10.0);
        assert!(at(big[0], 0.5, 0.0) && at(big[1], 0.5, 0.0), "{big:?}");
    }

    #[test]
    fn rounding_leaves_the_ends_of_an_open_path_and_paths_with_curves() {
        let open = vec![
            Seg::Move(0.0, 0.0),
            Seg::Line(1.0, 0.0),
            Seg::Line(1.0, 1.0),
        ];
        let p = round_corners(&open, 0.25);
        assert_eq!(p[0], Seg::Move(0.0, 0.0));
        assert!(
            matches!(p[1], Seg::Line(x, y) if near(x, 0.75) && near(y, 0.0)),
            "{p:?}"
        );
        assert_eq!(p.last(), Some(&Seg::Line(1.0, 1.0)));
        assert_eq!(p.len(), 4);
        let curved = vec![
            Seg::Move(0.0, 0.0),
            Seg::Cubic([0.0, 1.0, 1.0, 1.0, 1.0, 0.0]),
            Seg::Line(1.0, -1.0),
            Seg::Line(0.0, 0.0),
            Seg::Close,
        ];
        assert_eq!(round_corners(&curved, 0.25), curved);
        // A straight angle is not a corner; a point or a line is no polygon.
        let flat = vec![
            Seg::Move(0.0, 0.0),
            Seg::Line(1.0, 0.0),
            Seg::Line(2.0, 0.0),
        ];
        assert_eq!(round_corners(&flat, 0.25), flat);
        let two = vec![Seg::Move(0.0, 0.0), Seg::Line(1.0, 0.0)];
        assert_eq!(round_corners(&two, 0.25), two);
    }

    #[test]
    fn the_rounding_cell_rounds_the_shapes_paths() {
        let page = shapes(
            "<S><Shape ID='1'><Cell N='Rounding' V='0.25'/>
              <Section N='Geometry' IX='0'>
                <Row T='MoveTo' IX='1'><Cell N='X' V='0'/><Cell N='Y' V='0'/></Row>
                <Row T='LineTo' IX='2'><Cell N='X' V='1'/><Cell N='Y' V='0'/></Row>
                <Row T='LineTo' IX='3'><Cell N='X' V='1'/><Cell N='Y' V='1'/></Row>
                <Row T='LineTo' IX='4'><Cell N='X' V='0'/><Cell N='Y' V='1'/></Row>
                <Row T='LineTo' IX='5'><Cell N='X' V='0'/><Cell N='Y' V='0'/></Row></Section></Shape></S>",
        );
        let d = Doc::default();
        let m: HashMap<u32, Master> = HashMap::new();
        let t = Tree::build(&d, &m, &page, &mut Budget::new(Limits::default())).unwrap();
        let p = paths(&t, 0, 1.0, 1.0, 100).unwrap();
        assert_eq!(p[0].segs.len(), 10);
        // The segments it adds count against the shape's.
        assert!(paths(&t, 0, 1.0, 1.0, 8).is_err());
    }

    #[test]
    fn segments_are_bounded() {
        let mut rows = row(1, "MoveTo", &[("X", "0"), ("Y", "0")]);
        for i in 2..50 {
            rows.push_str(&row(i, "LineTo", &[("X", "1"), ("Y", "1")]));
        }
        assert!(geometry(&rows, 1.0, 1.0, 100).is_ok());
        assert_eq!(
            geometry(&rows, 1.0, 1.0, 20).err(),
            Some(Error::TooLarge("geometry segments"))
        );
    }

    #[test]
    fn hostile_numbers_do_not_panic() {
        let rows = [
            row(1, "MoveTo", &[("X", "1e308"), ("Y", "-1e308")]),
            row(
                2,
                "EllipticalArcTo",
                &[
                    ("X", "NaN"),
                    ("Y", "0"),
                    ("A", "1e300"),
                    ("B", "1"),
                    ("C", "1e300"),
                    ("D", "0"),
                ],
            ),
            row(
                3,
                "ArcTo",
                &[("X", "1e300"), ("Y", "1e-300"), ("A", "1e300")],
            ),
            row(4, "NURBSTo", &[("E", "NURBS(")]),
            row(5, "PolylineTo", &[("A", "POLYLINE(1)")]),
            row(6, "SplineStart", &[("D", "99")]),
            row(7, "SplineKnot", &[]),
        ]
        .concat();
        let _ = geometry(&rows, 1.0, 1.0, 10_000);
    }
}
