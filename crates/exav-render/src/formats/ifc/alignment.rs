//! IFC4X3 curves along an alignment: `IfcCompositeCurve` of
//! `IfcCurveSegment`s (a line, a circle, a spiral or a polynomial curve cut
//! to a length and placed), `IfcGradientCurve` (a plan curve and a profile
//! in distance and height), and `IfcAxis2PlacementLinear`, a placement at a
//! distance along a curve.
//!
//! A curve segment's parent curve is parametrised by length from its own
//! origin. The segment takes the part of it from `SegmentStart` for
//! `SegmentLength` (against the parent's sense when that is negative), and
//! sets it down so that its first point is `Placement`'s location and its
//! direction there is `Placement`'s `RefDirection`: whatever the parent's
//! position or heading at `SegmentStart` was. Written from the entities'
//! published definitions (the curvature polynomials of the spirals as
//! buildingSMART gives them).

use std::f64::consts::TAU;

use super::curves::segments;
use super::math::{V3, Xf, add, cross, len, scale, sub, unit};
use super::step::Value;
use super::{MAX_DEPTH, Reader, first_proj_axis, is};

/// Most points one segment or curve may have.
const MAX_POINTS: usize = 1 << 16;
/// Most segments of one composite curve.
const MAX_SEGMENTS: usize = 1 << 14;
/// The multiple of the usual chords a curve is sampled with to place
/// something on it.
const FINE: usize = 16;

/// The nodes and weights of the 5-point Gauss-Legendre rule on -1..1.
const GAUSS: [(f64, f64); 5] = [
    (0.0, 0.568_888_888_888_888_9),
    (0.538_469_310_105_683_1, 0.478_628_670_499_366_5),
    (-0.538_469_310_105_683_1, 0.478_628_670_499_366_5),
    (0.906_179_845_938_664, 0.236_926_885_056_189_1),
    (-0.906_179_845_938_664, 0.236_926_885_056_189_1),
];

/// A distance along a curve, and the point there.
pub(super) type Station = (f64, V3);

/// What a segment is cut from.
enum Parent {
    /// A line, by its unit direction.
    Line(V3),
    /// A circle, by its placement and radius.
    Circle(Xf, f64),
    /// A spiral: its curvature is `sum(c[k] s^k)`.
    Spiral([f64; 8]),
    /// `Position` applied to polynomials of the parameter.
    Polynomial(Xf, [Vec<f64>; 3]),
}

impl Parent {
    /// The parent's point at parameter `s`, for the kinds that have one.
    fn point(&self, s: f64) -> Option<V3> {
        Some(match self {
            Parent::Line(d) => scale(*d, s),
            Parent::Circle(pos, r) => {
                let a = s / r;
                pos.point([r * a.cos(), r * a.sin(), 0.0])
            }
            Parent::Polynomial(pos, c) => {
                let at = |c: &Vec<f64>| c.iter().rev().fold(0.0, |acc, k| acc * s + k);
                pos.point([at(&c[0]), at(&c[1]), at(&c[2])])
            }
            Parent::Spiral(_) => return None,
        })
    }

    /// The heading of the spiral at `s`: the integral of its curvature.
    fn heading(c: &[f64; 8], s: f64) -> f64 {
        c.iter()
            .enumerate()
            .rev()
            .fold(0.0, |acc, (k, ck)| (acc + ck / (k as f64 + 1.0)) * s)
    }
}

/// Curvature coefficients from the terms of a polynomial spiral, the
/// constant term (`A0`) first: `1 / A0`, then `A1 / |A1^3|`, `1 / A2^3`,
/// `A3 / |A3^5|` and so on, a term that is absent being none. `None` for a
/// term of zero, which has no curvature.
fn curvature(terms: &[Option<f64>]) -> Option<[f64; 8]> {
    let mut c = [0.0; 8];
    for (k, term) in terms.iter().enumerate().take(8) {
        let Some(a) = *term else { continue };
        if a == 0.0 || !a.is_finite() {
            return None;
        }
        c[k] = if k % 2 == 1 {
            a / a.abs().powi(k as i32 + 2)
        } else {
            1.0 / a.powi(k as i32 + 1)
        };
    }
    Some(c)
}

impl<'a> Reader<'a> {
    /// The parent curve of an `IfcCurveSegment`.
    fn parent(&mut self, id: u32) -> Option<Parent> {
        let (ty, p) = self.get(id)?;
        let opt = |i: usize| p.get(i).filter(|v| !v.is_null()).and_then(Value::num);
        match ty {
            b"IFCLINE" => {
                let vp = self.f.params(p.get(1)?.id()?)?;
                Some(Parent::Line(self.direction(vp.first()?.id()?)?))
            }
            b"IFCCIRCLE" => {
                let pos = self.axis2(p.first()?.id()?)?;
                let r = p.get(1)?.num().filter(|r| *r > 0.0 && r.is_finite())?;
                Some(Parent::Circle(pos, r))
            }
            b"IFCCLOTHOID" => Some(Parent::Spiral(curvature(&[None, Some(opt(1)?)])?)),
            b"IFCSECONDORDERPOLYNOMIALSPIRAL" => {
                Some(Parent::Spiral(curvature(&[opt(3), opt(2), Some(opt(1)?)])?))
            }
            b"IFCTHIRDORDERPOLYNOMIALSPIRAL" => Some(Parent::Spiral(curvature(&[
                opt(4),
                opt(3),
                opt(2),
                Some(opt(1)?),
            ])?)),
            b"IFCSEVENTHORDERPOLYNOMIALSPIRAL" => Some(Parent::Spiral(curvature(&[
                opt(8),
                opt(7),
                opt(6),
                opt(5),
                opt(4),
                opt(3),
                opt(2),
                Some(opt(1)?),
            ])?)),
            b"IFCPOLYNOMIALCURVE" => {
                let pos = self.axis2(p.first()?.id()?)?;
                let coefficients = |i: usize| -> Option<Vec<f64>> {
                    match p.get(i) {
                        Some(v) if !v.is_null() => v
                            .list()?
                            .iter()
                            .map(|x| x.num().filter(|x| x.is_finite()))
                            .collect(),
                        _ => Some(Vec::new()),
                    }
                };
                let c = [coefficients(1)?, coefficients(2)?, coefficients(3)?];
                (c.iter().any(|c| c.len() > 1) && c.iter().all(|c| c.len() <= 16))
                    .then_some(Parent::Polynomial(pos, c))
            }
            _ => {
                self.unsupported(ty);
                None
            }
        }
    }

    /// An `IfcCurveSegment` as stations: the distance from its start and the
    /// point, the segment's own length last. `None` for a segment that is
    /// not usable.
    fn curve_segment(&mut self, id: u32) -> Option<Vec<Station>> {
        self.visit()?;
        let (ty, p) = self.get(id)?;
        if ty != b"IFCCURVESEGMENT" {
            self.unsupported(ty);
            return None;
        }
        let place = self.axis2(p.get(1)?.id()?)?;
        let s0 = p.get(2)?.num().filter(|v| v.is_finite())?;
        let signed = p.get(3)?.num().filter(|v| v.is_finite())?;
        let l = signed.abs();
        let sign = if signed < 0.0 { -1.0 } else { 1.0 };
        let parent = self.parent(p.get(4)?.id()?)?;
        // The parent's heading at the start, and its offsets from there, in
        // the frame whose x is the direction of travel.
        let offsets: Vec<(f64, V3)> = match &parent {
            Parent::Line(_) | Parent::Circle(..) | Parent::Polynomial(..) => {
                let n = match &parent {
                    Parent::Line(_) => 1,
                    Parent::Circle(_, r) => segments(l / r) * self.density,
                    _ => 32 * self.density,
                };
                let at = |u: f64| parent.point(s0 + sign * u);
                let origin = at(0.0)?;
                // The direction of travel from a step small next to the
                // segment and to the parameter.
                let h = (l.max(1e-3) * 1e-6).max(s0.abs() * 1e-12);
                let ahead = sub(at(h)?, origin);
                let heading = ahead[1].atan2(ahead[0]);
                let (c, s) = (heading.cos(), heading.sin());
                let mut out = Vec::with_capacity(n + 1);
                for k in 0..=n {
                    let u = l * k as f64 / n as f64;
                    let d = sub(at(u)?, origin);
                    out.push((u, [c * d[0] + s * d[1], -s * d[0] + c * d[1], d[2]]));
                }
                out
            }
            Parent::Spiral(c) => {
                // The heading of travel, then its integral by Gauss steps.
                let psi = |u: f64| {
                    let a = Parent::heading(c, s0 + sign * u);
                    if sign < 0.0 {
                        a + std::f64::consts::PI
                    } else {
                        a
                    }
                };
                let psi0 = psi(0.0);
                let mut turn = 0.0f64;
                for k in 1..=64 {
                    turn = turn.max((psi(l * k as f64 / 64.0) - psi0).abs());
                }
                if !turn.is_finite() {
                    return None;
                }
                let n = ((turn / (TAU / 64.0)).ceil() as usize).clamp(8, 512) * self.density;
                let mut out = Vec::with_capacity(n + 1);
                let mut at = [0.0; 3];
                out.push((0.0, at));
                for k in 0..n {
                    let (a, b) = (l * k as f64 / n as f64, l * (k + 1) as f64 / n as f64);
                    let (mid, half) = ((a + b) / 2.0, (b - a) / 2.0);
                    for (x, w) in GAUSS {
                        let a = psi(mid + half * x) - psi0;
                        at[0] += w * half * a.cos();
                        at[1] += w * half * a.sin();
                    }
                    out.push((b, at));
                }
                out
            }
        };
        let points: Vec<Station> = offsets
            .into_iter()
            .map(|(u, d)| (u, place.point(d)))
            .collect();
        (points.len() >= 2
            && points.len() <= MAX_POINTS
            && points.iter().all(|(_, q)| q.iter().all(|x| x.is_finite())))
        .then_some(points)
    }

    /// The segments of a composite curve as stations, the distance along
    /// the whole curve first; the segments are `IfcCurveSegment`s.
    pub(super) fn curve_segments(&mut self, segments: &[Value]) -> Option<Vec<Station>> {
        if segments.len() > MAX_SEGMENTS {
            return None;
        }
        let mut out: Vec<Station> = Vec::new();
        let mut start = 0.0;
        for id in segments.iter().filter_map(Value::id) {
            if out.len() > MAX_POINTS {
                return None;
            }
            let seg = self.curve_segment(id)?;
            let length = seg.last().map_or(0.0, |s| s.0);
            let skip = out
                .last()
                .is_some_and(|(_, q)| len(sub(*q, seg[0].1)) <= 1e-6 * (1.0 + len(*q)));
            // A segment starts where the one before it ended.
            for (u, q) in seg.into_iter().skip(skip as usize) {
                out.push((start + u, q));
            }
            start += length;
        }
        (out.len() >= 2 && out.len() <= MAX_POINTS).then_some(out)
    }

    /// An `IfcGradientCurve`: its plan curve lifted to the height its
    /// segments give at each distance along it.
    pub(super) fn gradient_curve(&mut self, p: &[Value], depth: u32) -> Option<Vec<Station>> {
        if depth > MAX_DEPTH {
            return None;
        }
        let profile = self.curve_segments(p.first()?.list()?)?;
        // The profile runs in (distance along, height).
        if profile.array_windows().any(|[a, b]| b.1[0] < a.1[0]) {
            return None;
        }
        let plan = self.stations(p.get(2)?.id()?, depth + 1)?;
        let height = |x: f64| -> f64 {
            let k = profile
                .partition_point(|s| s.1[0] <= x)
                .clamp(1, profile.len() - 1);
            let (a, b) = (profile[k - 1].1, profile[k].1);
            if b[0] > a[0] {
                a[1] + (b[1] - a[1]) * ((x - a[0]) / (b[0] - a[0])).clamp(0.0, 1.0)
            } else {
                a[1]
            }
        };
        let along = |x: f64| -> V3 {
            let k = plan.partition_point(|s| s.0 <= x).clamp(1, plan.len() - 1);
            let (a, b) = (plan[k - 1], plan[k]);
            let t = if b.0 > a.0 {
                ((x - a.0) / (b.0 - a.0)).clamp(0.0, 1.0)
            } else {
                0.0
            };
            [
                a.1[0] + (b.1[0] - a.1[0]) * t,
                a.1[1] + (b.1[1] - a.1[1]) * t,
                0.0,
            ]
        };
        // The distances of both, in order.
        let end = plan.last()?.0;
        let mut xs: Vec<f64> = plan.iter().map(|s| s.0).collect();
        xs.extend(
            profile
                .iter()
                .map(|s| s.1[0])
                .filter(|x| *x > plan[0].0 && *x < end),
        );
        xs.sort_by(f64::total_cmp);
        xs.dedup_by(|a, b| (*a - *b).abs() <= 1e-9 * (1.0 + a.abs()));
        let out: Vec<Station> = xs
            .into_iter()
            .map(|x| {
                let q = along(x);
                (x, [q[0], q[1], height(x)])
            })
            .collect();
        (out.len() >= 2 && out.len() <= 2 * MAX_POINTS).then_some(out)
    }

    /// A curve of an alignment as stations: `IfcCompositeCurve` of curve
    /// segments, `IfcGradientCurve`; any other bounded curve by the length
    /// along its points.
    pub(super) fn stations(&mut self, id: u32, depth: u32) -> Option<Vec<Station>> {
        if depth > MAX_DEPTH {
            return None;
        }
        let (ty, p) = self.get(id)?;
        let first_is_curve_segment = p
            .first()
            .and_then(Value::list)
            .and_then(|l| l.first())
            .and_then(Value::id)
            .and_then(|s| self.get(s))
            .is_some_and(|(t, _)| t == b"IFCCURVESEGMENT");
        if ty == b"IFCGRADIENTCURVE" {
            return self.gradient_curve(&p, depth);
        }
        if is(ty, &[b"IFCCOMPOSITECURVE", b"IFC2DCOMPOSITECURVE"]) && first_is_curve_segment {
            return self.curve_segments(p.first()?.list()?);
        }
        let pts = self.curve(id, depth + 1)?;
        let mut d = 0.0;
        let mut out = Vec::with_capacity(pts.len());
        for (i, q) in pts.iter().enumerate() {
            if i > 0 {
                d += len(sub(*q, pts[i - 1]));
            }
            out.push((d, *q));
        }
        Some(out)
    }

    /// An `IfcAxis2PlacementLinear` as a transform: the point a distance
    /// along its curve, offset to the left, up and along; its x axis along
    /// the curve's heading, its z axis the global one (`Axis` and
    /// `RefDirection`, when given, are read in the curve's frame: along it,
    /// to its left, up from it).
    pub(super) fn axis2_linear(&mut self, id: u32) -> Option<Xf> {
        let (ty, p) = self.get(id)?;
        if ty != b"IFCAXIS2PLACEMENTLINEAR" {
            return None;
        }
        let (pty, pp) = self.get(p.first()?.id()?)?;
        if pty != b"IFCPOINTBYDISTANCEEXPRESSION" {
            return None;
        }
        let num = |i: usize| {
            pp.get(i)
                .filter(|v| !v.is_null())
                .map_or(Some(0.0), |v| v.num().filter(|x| x.is_finite()))
        };
        let along = pp.first()?.num().filter(|x| x.is_finite())?;
        let (lateral, vertical, longitudinal) = (num(1)?, num(2)?, num(3)?);
        // A point is placed on the curve, not on a chord of it.
        self.density = FINE;
        let stations = self.stations(pp.get(4)?.id()?, 0);
        self.density = 1;
        let stations = stations?;
        let k = stations
            .partition_point(|s| s.0 <= along)
            .clamp(1, stations.len() - 1);
        let (a, b) = (stations[k - 1], stations[k]);
        let t = if b.0 > a.0 {
            ((along - a.0) / (b.0 - a.0)).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let point = add(a.1, scale(sub(b.1, a.1), t));
        let tangent = unit(sub(b.1, a.1))?;
        // To the left of the curve, and up from it.
        let left = unit([-tangent[1], tangent[0], 0.0])
            .unwrap_or_else(|| super::math::any_perpendicular(tangent));
        let up = unit(cross(tangent, left))?;
        let at = add(
            add(point, scale(left, lateral)),
            add(scale(up, vertical), scale(tangent, longitudinal)),
        );
        let in_frame = |v: Option<&Value>| -> Option<V3> {
            let d = self.direction(v?.id()?)?;
            unit(add(
                add(scale(tangent, d[0]), scale(left, d[1])),
                scale(up, d[2]),
            ))
        };
        let z = p
            .get(1)
            .and_then(|v| in_frame(Some(v)))
            .unwrap_or([0.0, 0.0, 1.0]);
        let x = first_proj_axis(z, in_frame(p.get(2)).or(Some(tangent)));
        let y = cross(z, x);
        let xf = Xf::new(x, y, z, at);
        xf.is_finite().then_some(xf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clothoid_has_the_curvature_that_grows_with_its_length() {
        // A = 100: the curvature is s / A^2, the heading s^2 / (2 A^2).
        let c = curvature(&[None, Some(100.0)]).unwrap();
        assert!((c[1] - 1.0 / 10_000.0).abs() < 1e-18);
        let s = 50.0;
        assert!((Parent::heading(&c, s) - s * s / (2.0 * 10_000.0)).abs() < 1e-15);
        // A negative constant turns the other way.
        let c = curvature(&[None, Some(-100.0)]).unwrap();
        assert!(Parent::heading(&c, s) < 0.0);
        // A term of zero is not a curve.
        assert!(curvature(&[None, Some(0.0)]).is_none());
        assert!(curvature(&[None, Some(f64::NAN)]).is_none());
    }

    #[test]
    fn the_polynomial_spirals_terms_follow_the_published_forms() {
        // A0 = 50: the constant curvature 1 / 50, the heading s / 50.
        let c = curvature(&[Some(50.0)]).unwrap();
        assert!((Parent::heading(&c, 10.0) - 0.2).abs() < 1e-15);
        // A2 = 2: s^2 / 8, and a heading of s^3 / 24.
        let c = curvature(&[None, None, Some(2.0)]).unwrap();
        assert!((c[2] - 0.125).abs() < 1e-15);
        assert!((Parent::heading(&c, 3.0) - 27.0 / 24.0).abs() < 1e-15);
        // A3 = 2 has the sign in front of 1 / |A3^5|.
        let c = curvature(&[None, None, None, Some(-2.0)]).unwrap();
        assert!((c[3] + 1.0 / 16.0).abs() < 1e-15);
    }

    #[test]
    fn a_polynomial_of_the_parameter_is_evaluated_by_horner() {
        let p = Parent::Polynomial(Xf::IDENTITY, [vec![0.0, 1.0], vec![1.0, 0.0, 2.0], vec![]]);
        let q = p.point(3.0).unwrap();
        assert_eq!(q, [3.0, 19.0, 0.0]);
    }
}
