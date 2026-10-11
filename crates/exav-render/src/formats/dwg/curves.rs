//! Curve flattening. Everything the renderer draws is line segments, so arcs,
//! ellipses, bulges and splines are sampled here.

use std::f64::consts::TAU;

/// Sagitta error target as a fraction of radius. 0.001 gives ~70 segments for a
/// full circle, which holds up past the zoom levels a viewer reaches before
/// re-tessellation would kick in.
const SAGITTA_RATIO: f64 = 0.001;
const MIN_SEGMENTS: usize = 8;
const MAX_SEGMENTS: usize = 512;
/// Above it a spline is drawn as its control polygon.
const MAX_SPLINE_DEGREE: usize = 32;

/// Segment count for a circular sweep of `angle` radians.
fn segments_for_sweep(angle: f64) -> usize {
    // sagitta = r * (1 - cos(step/2)), so step = 2*acos(1 - ratio).
    let step = 2.0 * (1.0 - SAGITTA_RATIO).clamp(-1.0, 1.0).acos();
    let n = (angle.abs() / step).ceil() as usize;
    n.clamp(MIN_SEGMENTS, MAX_SEGMENTS)
}

/// A counter-clockwise sweep brought into (0, TAU], or None when the angles
/// are not finite. In one step: adding TAU until it is positive never ends
/// for an angle of 1e99, where TAU is below the float's resolution.
fn ccw_sweep(sweep: f64) -> Option<f64> {
    if !sweep.is_finite() {
        return None;
    }
    let s = sweep.rem_euclid(TAU);
    Some(if s > 0.0 { s } else { TAU })
}

/// Sample a circular arc counter-clockwise from `start` to `end` (radians).
pub fn flatten_arc(cx: f64, cy: f64, r: f64, start: f64, end: f64) -> Vec<[f64; 2]> {
    if !r.is_finite() || r <= 0.0 {
        return Vec::new();
    }
    // DWG arcs always run counter-clockwise from start to end.
    let Some(sweep) = ccw_sweep(end - start) else {
        return Vec::new();
    };
    let n = segments_for_sweep(sweep);
    let mut out = Vec::with_capacity(n + 1);
    for i in 0..=n {
        let a = start + sweep * (i as f64 / n as f64);
        out.push([cx + r * a.cos(), cy + r * a.sin()]);
    }
    out
}

pub fn flatten_circle(cx: f64, cy: f64, r: f64) -> Vec<[f64; 2]> {
    if !r.is_finite() || r <= 0.0 {
        return Vec::new();
    }
    let n = segments_for_sweep(TAU);
    let mut out = Vec::with_capacity(n + 1);
    for i in 0..=n {
        let a = TAU * (i as f64 / n as f64);
        out.push([cx + r * a.cos(), cy + r * a.sin()]);
    }
    out
}

/// Sample an ellipse. `major` is the major axis vector relative to the centre,
/// `ratio` the minor/major length ratio, and the parameters are eccentric
/// angles measured in the ellipse's own frame.
pub fn flatten_ellipse(
    cx: f64,
    cy: f64,
    major_x: f64,
    major_y: f64,
    ratio: f64,
    start_param: f64,
    end_param: f64,
) -> Vec<[f64; 2]> {
    let a = (major_x * major_x + major_y * major_y).sqrt();
    if !a.is_finite() || a <= 0.0 || !ratio.is_finite() {
        return Vec::new();
    }
    let b = a * ratio.abs();
    let rot = major_y.atan2(major_x);
    let (sin_r, cos_r) = rot.sin_cos();

    let sweep = end_param - start_param;
    // A full ellipse is stored as 0..2pi; treat a zero sweep as closed.
    let Some(sweep) = (if sweep.abs() < 1e-12 {
        Some(TAU)
    } else {
        ccw_sweep(sweep)
    }) else {
        return Vec::new();
    };

    // Use the larger semi-axis for the segment budget so flat ellipses stay smooth.
    let n = segments_for_sweep(sweep * (1.0 + (a / b.max(1e-12)).min(8.0)) / 2.0);
    let mut out = Vec::with_capacity(n + 1);
    for i in 0..=n {
        let t = start_param + sweep * (i as f64 / n as f64);
        let (sin_t, cos_t) = t.sin_cos();
        let ex = a * cos_t;
        let ey = b * sin_t;
        out.push([cx + ex * cos_r - ey * sin_r, cy + ex * sin_r + ey * cos_r]);
    }
    out
}

/// Expand a polyline bulge into arc points between `p0` and `p1`, excluding
/// `p0`.
///
/// Bulge is `tan(theta/4)` for the included angle theta, negative when the arc
/// runs clockwise from start to end (DXF convention). A counter-clockwise arc
/// keeps its centre on the left of the direction of travel, so a positive
/// bulge bows to the *right* of the chord.
pub fn flatten_bulge(p0: [f64; 2], p1: [f64; 2], bulge: f64) -> Vec<[f64; 2]> {
    if bulge.abs() < 1e-12 || !bulge.is_finite() {
        return vec![p1];
    }
    let dx = p1[0] - p0[0];
    let dy = p1[1] - p0[1];
    let chord = (dx * dx + dy * dy).sqrt();
    if chord < 1e-12 {
        return vec![p1];
    }

    // Signed included angle. This is the sweep, directly, with no normalising.
    let theta = 4.0 * bulge.atan();
    let half = theta / 2.0;
    let tan_half = half.tan();
    if !tan_half.is_finite() || tan_half.abs() < 1e-15 {
        return vec![p1];
    }

    // Centre lies on the left normal of the chord, at the apothem distance.
    // tan(theta/2) flips sign for |theta| > pi, which moves the centre across
    // the chord for major arcs without any special casing.
    let h = (chord / 2.0) / tan_half;
    let nx = -dy / chord;
    let ny = dx / chord;
    let cx = (p0[0] + p1[0]) / 2.0 + nx * h;
    let cy = (p0[1] + p1[1]) / 2.0 + ny * h;

    let r = ((p0[0] - cx).powi(2) + (p0[1] - cy).powi(2)).sqrt();
    if !r.is_finite() || r <= 0.0 {
        return vec![p1];
    }

    let a0 = (p0[1] - cy).atan2(p0[0] - cx);
    let n = segments_for_sweep(theta);
    let mut out = Vec::with_capacity(n);
    for i in 1..=n {
        let a = a0 + theta * (i as f64 / n as f64);
        out.push([cx + r * a.cos(), cy + r * a.sin()]);
    }
    // Land exactly on the stated endpoint instead of a sampled approximation.
    if let Some(last) = out.last_mut() {
        *last = p1;
    }
    out
}

/// Evaluate a NURBS curve with de Boor's algorithm and sample it uniformly.
///
/// `weights` may be empty for a non-rational curve.
pub fn flatten_spline(
    degree: usize,
    knots: &[f64],
    ctrl: &[[f64; 2]],
    weights: &[f64],
    closed: bool,
) -> Vec<[f64; 2]> {
    let n_ctrl = ctrl.len();
    if n_ctrl == 0 {
        return Vec::new();
    }
    // Each sample costs degree squared, plus a search through the knots: a
    // damaged file's degree of 50,000 over as many points is minutes of work.
    // AutoCAD's own splines stop at degree 26.
    if degree == 0
        || degree > MAX_SPLINE_DEGREE
        || n_ctrl <= degree
        || knots.len() != n_ctrl + degree + 1
    {
        // Malformed or degenerate: fall back to the control polygon, which is
        // the right shape for degree-1 splines and a safe approximation
        // otherwise.
        let mut pts = ctrl.to_vec();
        if closed && pts.len() > 1 {
            pts.push(pts[0]);
        }
        return pts;
    }

    let rational = weights.len() == n_ctrl;
    let t0 = knots[degree];
    let t1 = knots[n_ctrl];
    if !(t1 > t0) {
        return ctrl.to_vec();
    }

    // Budget by span count so long splines keep detail without exploding.
    let spans = n_ctrl - degree;
    let n = (spans * 16).clamp(MIN_SEGMENTS, 4096);

    let mut out = Vec::with_capacity(n + 1);
    for i in 0..=n {
        let t = t0 + (t1 - t0) * (i as f64 / n as f64);
        // Clamp inside the last span so the final point is on the curve.
        let t = t.min(t1 - 1e-12).max(t0);
        if let Some(p) = de_boor(degree, knots, ctrl, weights, rational, t) {
            out.push(p);
        }
    }
    out
}

/// Interpolate a smooth curve through a spline's fit points.
///
/// A SPLINE drawn through points stores no control points at all: the fit
/// points and the end tangents are the whole definition, and the curve is the
/// cubic that interpolates them. Joining them with straight lines instead turns
/// a two-point fit spline into a chord and a site contour into a polygon.
///
/// The parameterisation is chord length, which is what makes a unit end tangent
/// the right derivative to clamp with: along an arc-length parameter the
/// derivative of the curve has magnitude one.
pub fn fit_spline(
    points: &[[f64; 2]],
    begin_tangent: Option<[f64; 2]>,
    end_tangent: Option<[f64; 2]>,
    closed: bool,
) -> Vec<[f64; 2]> {
    // Repeated points give a zero-length span, which the solver divides by.
    let mut pts: Vec<[f64; 2]> = Vec::with_capacity(points.len());
    for p in points {
        if !p[0].is_finite() || !p[1].is_finite() {
            continue;
        }
        match pts.last() {
            Some(q) if (q[0] - p[0]).abs() < 1e-12 && (q[1] - p[1]).abs() < 1e-12 => {}
            _ => pts.push(*p),
        }
    }
    if closed && pts.len() > 2 {
        let first = pts[0];
        if (pts[pts.len() - 1][0] - first[0]).abs() > 1e-12
            || (pts[pts.len() - 1][1] - first[1]).abs() > 1e-12
        {
            pts.push(first);
        }
    }
    if pts.len() < 2 {
        return pts;
    }

    // Chord-length parameters.
    let mut t = Vec::with_capacity(pts.len());
    t.push(0.0);
    for w in pts.windows(2) {
        let d = (w[1][0] - w[0][0]).hypot(w[1][1] - w[0][1]);
        t.push(t[t.len() - 1] + d.max(1e-9));
    }

    let mx = second_derivatives(
        &t,
        &pts.iter().map(|p| p[0]).collect::<Vec<_>>(),
        begin_tangent.map(|v| v[0]),
        end_tangent.map(|v| v[0]),
    );
    let my = second_derivatives(
        &t,
        &pts.iter().map(|p| p[1]).collect::<Vec<_>>(),
        begin_tangent.map(|v| v[1]),
        end_tangent.map(|v| v[1]),
    );

    let spans = pts.len() - 1;
    let mut out: Vec<[f64; 2]> = Vec::with_capacity(spans * 4 + 1);
    out.push(pts[0]);
    for i in 0..spans {
        let h = t[i + 1] - t[i];

        // Sample each span for its own curvature. A site contour with 177 fit
        // points is already nearly straight between them and needs one segment
        // per span; a two-point spline bent by its end tangents needs many.
        // At the middle of a span the cubic sits (M0+M1)h²/16 off the chord,
        // which is the sag the sampling has to resolve.
        let offset = |m0: f64, m1: f64| (m0 + m1) * h * h / 16.0;
        let sag = offset(mx[i], mx[i + 1]).hypot(offset(my[i], my[i + 1]));
        let per_span = if sag <= SAGITTA_RATIO * h {
            1
        } else {
            ((sag / (SAGITTA_RATIO * h)).sqrt().ceil() as usize).clamp(2, 64)
        };

        for k in 1..=per_span {
            let u = t[i] + h * (k as f64 / per_span as f64);
            let a = (t[i + 1] - u) / h;
            let b = (u - t[i]) / h;
            let cubic = |y0: f64, y1: f64, m0: f64, m1: f64| {
                a * y0 + b * y1 + ((a * a * a - a) * m0 + (b * b * b - b) * m1) * h * h / 6.0
            };
            out.push([
                cubic(pts[i][0], pts[i + 1][0], mx[i], mx[i + 1]),
                cubic(pts[i][1], pts[i + 1][1], my[i], my[i + 1]),
            ]);
        }
    }
    out
}

/// Second derivatives of the interpolating cubic, by the Thomas algorithm.
///
/// A given end tangent clamps that end; without one the end is natural, which
/// is how AutoCAD fits a spline whose tangent was left free.
fn second_derivatives(t: &[f64], y: &[f64], d0: Option<f64>, dn: Option<f64>) -> Vec<f64> {
    let n = y.len();
    if n < 2 {
        return vec![0.0; n];
    }
    let h: Vec<f64> = t.windows(2).map(|w| w[1] - w[0]).collect();

    // Tridiagonal system, row i: lower[i] * m[i-1] + diag[i] * m[i] + upper[i] * m[i+1] = rhs[i]
    let mut lower = vec![0.0; n];
    let mut diag = vec![1.0; n];
    let mut upper = vec![0.0; n];
    let mut rhs = vec![0.0; n];

    for i in 1..n - 1 {
        lower[i] = h[i - 1];
        diag[i] = 2.0 * (h[i - 1] + h[i]);
        upper[i] = h[i];
        rhs[i] = 6.0 * ((y[i + 1] - y[i]) / h[i] - (y[i] - y[i - 1]) / h[i - 1]);
    }
    match d0 {
        Some(d) => {
            diag[0] = 2.0 * h[0];
            upper[0] = h[0];
            rhs[0] = 6.0 * ((y[1] - y[0]) / h[0] - d);
        }
        None => {
            diag[0] = 1.0;
            upper[0] = 0.0;
            rhs[0] = 0.0;
        }
    }
    match dn {
        Some(d) => {
            lower[n - 1] = h[n - 2];
            diag[n - 1] = 2.0 * h[n - 2];
            rhs[n - 1] = 6.0 * (d - (y[n - 1] - y[n - 2]) / h[n - 2]);
        }
        None => {
            lower[n - 1] = 0.0;
            diag[n - 1] = 1.0;
            rhs[n - 1] = 0.0;
        }
    }

    // Forward sweep.
    for i in 1..n {
        let w = if diag[i - 1].abs() < 1e-18 {
            0.0
        } else {
            lower[i] / diag[i - 1]
        };
        diag[i] -= w * upper[i - 1];
        rhs[i] -= w * rhs[i - 1];
    }
    // Back substitution.
    let mut m = vec![0.0; n];
    m[n - 1] = if diag[n - 1].abs() < 1e-18 {
        0.0
    } else {
        rhs[n - 1] / diag[n - 1]
    };
    for i in (0..n - 1).rev() {
        m[i] = if diag[i].abs() < 1e-18 {
            0.0
        } else {
            (rhs[i] - upper[i] * m[i + 1]) / diag[i]
        };
    }
    m
}

fn de_boor(
    degree: usize,
    knots: &[f64],
    ctrl: &[[f64; 2]],
    weights: &[f64],
    rational: bool,
    t: f64,
) -> Option<[f64; 2]> {
    let n_ctrl = ctrl.len();
    // Find the knot span containing t.
    let mut k = degree;
    while k < n_ctrl && knots[k + 1] <= t {
        k += 1;
    }
    if k >= n_ctrl {
        k = n_ctrl - 1;
    }

    // Work in homogeneous coordinates so rational splines fall out of the same loop.
    let mut d: Vec<[f64; 3]> = Vec::with_capacity(degree + 1);
    for j in 0..=degree {
        let idx = k + j - degree;
        let w = if rational { weights[idx] } else { 1.0 };
        d.push([ctrl[idx][0] * w, ctrl[idx][1] * w, w]);
    }

    for r in 1..=degree {
        for j in (r..=degree).rev() {
            let idx = k + j - degree;
            let denom = knots[idx + degree + 1 - r] - knots[idx];
            let alpha = if denom.abs() < 1e-12 {
                0.0
            } else {
                (t - knots[idx]) / denom
            };
            let prev = d[j - 1];
            let cur = d[j];
            d[j] = [
                prev[0] * (1.0 - alpha) + cur[0] * alpha,
                prev[1] * (1.0 - alpha) + cur[1] * alpha,
                prev[2] * (1.0 - alpha) + cur[2] * alpha,
            ];
        }
    }

    let p = d[degree];
    if p[2].abs() < 1e-12 {
        return None;
    }
    let out = [p[0] / p[2], p[1] / p[2]];
    if out[0].is_finite() && out[1].is_finite() {
        Some(out)
    } else {
        None
    }
}

#[cfg(test)]
mod fit_splines {
    use super::*;

    #[test]
    fn the_curve_passes_through_every_fit_point() {
        let pts = [[0.0, 0.0], [10.0, 5.0], [20.0, -5.0], [30.0, 0.0]];
        let out = fit_spline(&pts, None, None, false);
        for p in &pts {
            let near = out
                .iter()
                .map(|q| (q[0] - p[0]).hypot(q[1] - p[1]))
                .fold(f64::INFINITY, f64::min);
            assert!(near < 1e-6, "fit point {p:?} missed by {near}");
        }
    }

    #[test]
    fn it_bends_instead_of_joining_the_points_with_chords() {
        // Three points on a circle: the interpolant bulges away from the chord
        // between them, which is the whole difference from a polyline.
        let pts = [[0.0, 0.0], [10.0, 10.0], [20.0, 0.0]];
        let out = fit_spline(&pts, None, None, false);

        // Sample a quarter of the way along: a chord would be at y = 5.
        let q = out[out.len() / 4];
        assert!(q[1] > 5.2, "quarter point {q:?} sits on the chord");
    }

    #[test]
    fn an_end_tangent_sets_the_direction_it_leaves_at() {
        // Two fit points, both tangents pointing up: AutoCAD draws an S, not a
        // straight line, and this is the case a chord gets most wrong.
        let pts = [[0.0, 0.0], [10.0, 0.0]];
        let up = Some([0.0, 1.0]);
        let out = fit_spline(&pts, up, Some([0.0, -1.0]), false);
        assert!(out.len() > 8, "two points gave {} samples", out.len());

        let first_step = [out[1][0] - out[0][0], out[1][1] - out[0][1]];
        assert!(
            first_step[1] > first_step[0].abs(),
            "curve left the start going {first_step:?}, not upward"
        );
        // And it still lands on the last fit point.
        let last = out[out.len() - 1];
        assert!(
            (last[0] - 10.0).abs() < 1e-6 && last[1].abs() < 1e-6,
            "{last:?}"
        );
    }

    #[test]
    fn straight_fit_points_stay_straight() {
        let pts = [[0.0, 0.0], [5.0, 0.0], [10.0, 0.0], [15.0, 0.0]];
        let out = fit_spline(&pts, None, None, false);
        assert!(out.iter().all(|p| p[1].abs() < 1e-9), "a straight run bent");
    }

    #[test]
    fn a_closed_fit_spline_comes_back_to_its_start() {
        let pts = [[0.0, 0.0], [10.0, 0.0], [10.0, 10.0], [0.0, 10.0]];
        let out = fit_spline(&pts, None, None, true);
        let first = out[0];
        let last = out[out.len() - 1];
        assert!(
            (first[0] - last[0]).abs() < 1e-6 && (first[1] - last[1]).abs() < 1e-6,
            "{first:?} != {last:?}"
        );
    }

    #[test]
    fn repeated_and_degenerate_points_do_not_divide_by_zero() {
        let pts = [[1.0, 1.0], [1.0, 1.0], [1.0, 1.0]];
        let out = fit_spline(&pts, None, None, false);
        assert!(out.iter().all(|p| p[0].is_finite() && p[1].is_finite()));
        assert!(fit_spline(&[], None, None, false).is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::consts::PI;

    fn dist(a: [f64; 2], b: [f64; 2]) -> f64 {
        ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2)).sqrt()
    }

    /// `f`'s result, or a failure if it has not returned within five seconds
    /// (the thread is left spinning; the test binary exits anyway).
    fn finishes<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("did not return within 5 s")
    }

    /// The `drawing` fuzzer's first finding: a DWG arc whose end angle had
    /// become -1.2e99. Adding TAU until the sweep was positive never got
    /// there, TAU being below the resolution of a float that size.
    #[test]
    fn an_angle_far_out_of_range_neither_hangs_nor_draws_off_the_circle() {
        let pts = finishes(|| flatten_arc(3.0, 4.0, 2.0, 1.0, -1.2436659369434572e99));
        assert!(!pts.is_empty() && pts.len() <= MAX_SEGMENTS + 1);
        for p in &pts {
            assert!(
                (dist(*p, [3.0, 4.0]) - 2.0).abs() < 1e-9,
                "{p:?} is off the circle"
            );
        }
        let pts = finishes(|| flatten_ellipse(0.0, 0.0, 2.0, 0.0, 0.5, 0.0, -1e99));
        assert!(!pts.is_empty() && pts.len() <= MAX_SEGMENTS + 1);
        // An infinite or undefined angle has no arc to draw.
        assert!(finishes(|| flatten_arc(0.0, 0.0, 1.0, 0.0, f64::INFINITY)).is_empty());
        assert!(finishes(|| flatten_arc(0.0, 0.0, 1.0, f64::NAN, 1.0)).is_empty());
        assert!(
            finishes(|| flatten_ellipse(0.0, 0.0, 1.0, 0.0, 0.5, f64::NEG_INFINITY, 0.0))
                .is_empty()
        );
    }

    /// A sample costs degree squared: a damaged degree of 5000 over 6000
    /// points was a hundred billion steps.
    #[test]
    fn a_spline_of_absurd_degree_is_drawn_as_its_control_polygon_at_once() {
        let n = 6000;
        let degree = 5000;
        let ctrl: Vec<[f64; 2]> = (0..n).map(|i| [i as f64, (i % 7) as f64]).collect();
        let knots: Vec<f64> = (0..n + degree + 1)
            .map(|i| i.clamp(degree, n) as f64)
            .collect();
        let pts = finishes(move || flatten_spline(degree, &knots, &ctrl, &[], false));
        assert_eq!(pts.len(), n);
        assert_eq!(pts[123], [123.0, (123 % 7) as f64]);
    }

    #[test]
    fn an_arc_ending_before_it_starts_goes_the_long_way_round() {
        // From 0 to -90 degrees counter-clockwise is three quarters of a turn,
        // through the top and the left: past (0, 1) and (-1, 0), ending at (0, -1).
        let pts = flatten_arc(0.0, 0.0, 1.0, 0.0, -PI / 2.0);
        assert!(dist(*pts.last().unwrap(), [0.0, -1.0]) < 1e-9);
        let near = |q: [f64; 2]| pts.iter().any(|p| dist(*p, q) < 0.05);
        let diagonal = std::f64::consts::FRAC_1_SQRT_2;
        assert!(near([0.0, 1.0]) && near([-1.0, 0.0]) && !near([diagonal, -diagonal]));
        // A whole turn and a quarter is a quarter.
        let quarter = flatten_arc(0.0, 0.0, 1.0, 0.0, 2.5 * PI);
        assert!(dist(*quarter.last().unwrap(), [0.0, 1.0]) < 1e-9);
        assert!(!quarter.iter().any(|p| p[1] < -1e-9));
    }

    #[test]
    fn arc_endpoints_land_on_the_arc() {
        let pts = flatten_arc(10.0, 20.0, 5.0, 0.0, PI / 2.0);
        assert!(dist(pts[0], [15.0, 20.0]) < 1e-9);
        assert!(dist(*pts.last().unwrap(), [10.0, 25.0]) < 1e-9);
        // Every sample sits on the circle.
        for p in &pts {
            assert!((dist(*p, [10.0, 20.0]) - 5.0).abs() < 1e-9);
        }
    }

    #[test]
    fn arc_sweeps_counter_clockwise_across_zero() {
        // 315deg to 45deg must go the short way through 0, not the long way.
        let pts = flatten_arc(0.0, 0.0, 1.0, 7.0 * PI / 4.0, PI / 4.0);
        let mid = pts[pts.len() / 2];
        assert!(mid[0] > 0.9, "midpoint should be near +x, got {mid:?}");
    }

    #[test]
    fn circle_closes() {
        let pts = flatten_circle(0.0, 0.0, 3.0);
        assert!(dist(pts[0], *pts.last().unwrap()) < 1e-9);
    }

    #[test]
    fn ellipse_respects_rotation_and_ratio() {
        // Major axis along +y, ratio 0.5: extremes are (0,+-2) and (+-1,0).
        let pts = flatten_ellipse(0.0, 0.0, 0.0, 2.0, 0.5, 0.0, TAU);
        let max_y = pts.iter().map(|p| p[1]).fold(f64::MIN, f64::max);
        let max_x = pts.iter().map(|p| p[0]).fold(f64::MIN, f64::max);
        // Tolerance covers the sampling step, which need not land on the extreme.
        assert!((max_y - 2.0).abs() < 2e-3, "max_y {max_y}");
        assert!((max_x - 1.0).abs() < 2e-3, "max_x {max_x}");
    }

    #[test]
    fn semicircle_bulge_has_correct_radius() {
        // bulge = 1 is a half circle from (0,0) to (2,0) about centre (1,0).
        let pts = flatten_bulge([0.0, 0.0], [2.0, 0.0], 1.0);
        assert!(dist(*pts.last().unwrap(), [2.0, 0.0]) < 1e-9);
        for p in &pts {
            assert!(
                (dist(*p, [1.0, 0.0]) - 1.0).abs() < 1e-9,
                "point {p:?} not on unit circle about (1,0)"
            );
        }
        // Counter-clockwise keeps the centre on the left of travel, so a
        // positive bulge on a left-to-right chord dips below it.
        let apex = pts[pts.len() / 2 - 1];
        assert!(apex[1] < 0.0, "positive bulge must arc below, got {apex:?}");
    }

    #[test]
    fn negative_bulge_arcs_the_other_way() {
        let pts = flatten_bulge([0.0, 0.0], [2.0, 0.0], -1.0);
        let apex = pts[pts.len() / 2 - 1];
        assert!(apex[1] > 0.0, "negative bulge must arc above, got {apex:?}");
        // Mirror image of the positive case, same circle.
        for p in &pts {
            assert!((dist(*p, [1.0, 0.0]) - 1.0).abs() < 1e-9);
        }
    }

    #[test]
    fn major_arc_bulge_puts_centre_on_the_far_side() {
        // bulge = 2 gives theta = 4*atan(2) ~ 253.7deg, a major arc. The
        // apothem goes negative, moving the centre below the chord to (1,-0.75)
        // with radius 1.25, so the arc reaches down to y = -2.
        let pts = flatten_bulge([0.0, 0.0], [2.0, 0.0], 2.0);
        let min_y = pts.iter().map(|p| p[1]).fold(f64::MAX, f64::min);
        assert!(
            (min_y + 2.0).abs() < 1e-3,
            "expected a major arc reaching y=-2, got {min_y}"
        );
        for p in &pts {
            assert!(
                (dist(*p, [1.0, -0.75]) - 1.25).abs() < 1e-9,
                "{p:?} off circle"
            );
        }
        assert!(dist(*pts.last().unwrap(), [2.0, 0.0]) < 1e-9);
    }

    #[test]
    fn two_semicircle_bulges_close_into_a_full_circle() {
        // Both halves counter-clockwise about (1,0) must trace the whole circle.
        let lower = flatten_bulge([0.0, 0.0], [2.0, 0.0], 1.0);
        let upper = flatten_bulge([2.0, 0.0], [0.0, 0.0], 1.0);
        let min_y = lower.iter().map(|p| p[1]).fold(f64::MAX, f64::min);
        let max_y = upper.iter().map(|p| p[1]).fold(f64::MIN, f64::max);
        assert!((min_y + 1.0).abs() < 1e-3, "lower half min_y {min_y}");
        assert!((max_y - 1.0).abs() < 1e-3, "upper half max_y {max_y}");
    }

    #[test]
    fn degree_one_spline_is_the_control_polygon() {
        let ctrl = vec![[0.0, 0.0], [1.0, 1.0], [2.0, 0.0]];
        let knots = vec![0.0, 0.0, 1.0, 2.0, 2.0];
        let pts = flatten_spline(1, &knots, &ctrl, &[], false);
        // Every sample must lie on one of the two chords.
        for p in &pts {
            let on_first = (p[1] - p[0]).abs() < 1e-6 && p[0] <= 1.0 + 1e-9;
            let on_second = (p[1] - (2.0 - p[0])).abs() < 1e-6 && p[0] >= 1.0 - 1e-9;
            assert!(on_first || on_second, "point {p:?} off the control polygon");
        }
    }

    #[test]
    fn cubic_bezier_spline_matches_closed_form() {
        // A clamped cubic with 4 control points is exactly a Bezier curve.
        let ctrl = vec![[0.0, 0.0], [0.0, 1.0], [1.0, 1.0], [1.0, 0.0]];
        let knots = vec![0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0];
        let pts = flatten_spline(3, &knots, &ctrl, &[], false);
        let bezier = |t: f64| {
            let u = 1.0 - t;
            [
                3.0 * u * t * t + t * t * t,
                3.0 * u * u * t + 3.0 * u * t * t,
            ]
        };
        assert!(dist(pts[0], [0.0, 0.0]) < 1e-9);
        let n = pts.len() - 1;
        for (i, p) in pts.iter().enumerate() {
            let t = (i as f64 / n as f64).min(1.0 - 1e-12);
            assert!(
                dist(*p, bezier(t)) < 1e-6,
                "sample {i} {p:?} vs {:?}",
                bezier(t)
            );
        }
    }

    #[test]
    fn rational_spline_weights_pull_the_curve() {
        // A heavy middle weight drags a quadratic toward its middle control point.
        let ctrl = vec![[0.0, 0.0], [1.0, 1.0], [2.0, 0.0]];
        let knots = vec![0.0, 0.0, 0.0, 1.0, 1.0, 1.0];
        let light = flatten_spline(2, &knots, &ctrl, &[1.0, 1.0, 1.0], false);
        let heavy = flatten_spline(2, &knots, &ctrl, &[1.0, 8.0, 1.0], false);
        let apex_light = light.iter().map(|p| p[1]).fold(f64::MIN, f64::max);
        let apex_heavy = heavy.iter().map(|p| p[1]).fold(f64::MIN, f64::max);
        assert!(
            apex_heavy > apex_light,
            "weighted curve should rise higher: {apex_heavy} vs {apex_light}"
        );
    }

    #[test]
    fn malformed_spline_does_not_panic() {
        // Knot vector too short for the declared degree.
        let ctrl = vec![[0.0, 0.0], [1.0, 1.0]];
        let pts = flatten_spline(3, &[0.0, 1.0], &ctrl, &[], false);
        assert_eq!(pts.len(), 2);
    }

    #[test]
    fn degenerate_inputs_are_empty_not_panics() {
        assert!(flatten_arc(0.0, 0.0, 0.0, 0.0, 1.0).is_empty());
        assert!(flatten_circle(0.0, 0.0, -1.0).is_empty());
        assert!(flatten_ellipse(0.0, 0.0, 0.0, 0.0, 0.5, 0.0, 1.0).is_empty());
        assert!(flatten_spline(3, &[], &[], &[], false).is_empty());
    }
}

#[cfg(test)]
mod boundary_arc_regression {
    use super::*;

    /// A clockwise hatch boundary arc taken verbatim from a real drawing.
    ///
    /// Its angles are stored mirrored about the centre's horizontal axis. Used
    /// as-is they place the arc on the far side of its centre, 85000 units from
    /// the lines it joins, and the solid fill becomes a disc over the sheet.
    /// The check is boundary continuity: the arc has to meet its neighbours.
    #[test]
    fn clockwise_boundary_arc_meets_its_adjoining_lines() {
        let (cx, cy, r) = (39015704.3, -5604860.7, 42564.5);
        let (start, end) = (1.5782, 1.5829);

        // What the tessellator now does for counter_clockwise = false.
        let mut seg = flatten_arc(cx, cy, r, -end, -start);
        seg.reverse();

        // The edges either side of this arc in the file.
        let prev_line_end = [39015390.5, -5647424.0];
        let next_line_start = [39015187.3, -5647422.1];

        let d = |a: [f64; 2], b: [f64; 2]| ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2)).sqrt();
        assert!(
            d(seg[0], prev_line_end) < 5.0,
            "arc starts {:.1} from the previous edge",
            d(seg[0], prev_line_end)
        );
        assert!(
            d(*seg.last().unwrap(), next_line_start) < 5.0,
            "arc ends {:.1} from the next edge",
            d(*seg.last().unwrap(), next_line_start)
        );
    }

    #[test]
    fn taking_the_angles_at_face_value_is_what_produced_the_disc() {
        // Guards the premise: without negation the arc is nowhere near its
        // neighbours, which is exactly the failure that was visible on screen.
        let (cx, cy, r) = (39015704.3, -5604860.7, 42564.5);
        let seg = flatten_arc(cx, cy, r, 1.5782, 1.5829);
        let prev_line_end = [39015390.5, -5647424.0];
        let gap = ((seg[0][0] - prev_line_end[0]).powi(2) + (seg[0][1] - prev_line_end[1]).powi(2))
            .sqrt();
        assert!(
            gap > 80000.0,
            "expected the old failure mode, gap was {gap:.0}"
        );
    }

    /// The counter-clockwise arc from the same boundary needs no negation.
    #[test]
    fn counter_clockwise_boundary_arc_is_used_as_stored() {
        let (cx, cy, r) = (39018303.7, -5533581.5, 113919.8);
        let seg = flatten_arc(cx, cy, r, 4.6851, 4.6868);
        let next_line_start = [39015390.5, -5647464.0];
        let gap = ((seg.last().unwrap()[0] - next_line_start[0]).powi(2)
            + (seg.last().unwrap()[1] - next_line_start[1]).powi(2))
        .sqrt();
        assert!(
            gap < 60.0,
            "ccw arc should already meet its neighbour, gap {gap:.1}"
        );
    }
}
