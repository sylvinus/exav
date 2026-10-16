//! The directrix of a sweep between its start and end parameters
//! (`StartParam`, `EndParam` of `IfcSweptDiskSolid` and
//! `IfcDirectrixCurveSweptAreaSolid`): the curve's points from one
//! parameter to the other, by the parametrisation each kind of curve
//! publishes. A polyline's parameter is the index of its points, a
//! composite curve's the sum of its segments' parametric lengths, a circle's
//! an angle in the file's unit, a line's the multiple of its vector.

use std::f64::consts::TAU;

use super::curves::{conic_point, segments};
use super::math::{add, scale, sub, V3};
use super::step::Value;
use super::{is, Reader, MAX_DEPTH};

/// Most points of a curve that carries parameters.
const MAX_POINTS: usize = 1 << 16;

/// The points between parameters `s` and `e` (from `s` to `e`, the other
/// way when `e` is the smaller), the ends at those parameters. `None` when
/// they leave nothing between them. Parameters beyond the curve are its
/// ends. `samples` ascend in parameter.
fn cut(samples: &[(f64, V3)], s: f64, e: f64) -> Option<Vec<V3>> {
    let (first, last) = (samples.first()?.0, samples.last()?.0);
    if first.is_nan() || last.is_nan() || first > last {
        return None;
    }
    let (lo, hi) = (s.min(e).clamp(first, last), s.max(e).clamp(first, last));
    if hi.is_nan() || lo.is_nan() || hi <= lo {
        return None;
    }
    let at = |t: f64| -> V3 {
        let k = samples
            .partition_point(|x| x.0 <= t)
            .clamp(1, samples.len().max(2))
            - 1;
        match (samples.get(k), samples.get(k + 1)) {
            (Some(a), Some(b)) if b.0 > a.0 => add(
                a.1,
                scale(sub(b.1, a.1), ((t - a.0) / (b.0 - a.0)).clamp(0.0, 1.0)),
            ),
            (Some(a), _) => a.1,
            _ => [0.0; 3],
        }
    };
    let mut out = vec![at(lo)];
    out.extend(samples.iter().filter(|x| x.0 > lo && x.0 < hi).map(|x| x.1));
    out.push(at(hi));
    if s > e {
        out.reverse();
    }
    Some(out)
}

impl<'a> Reader<'a> {
    /// The directrix `id` from `start` to `end`, each a parameter value or
    /// null for the curve's own end. A curve whose parameters are not known
    /// is swept whole, and counted.
    pub(super) fn directrix(
        &mut self,
        id: u32,
        start: Option<&Value>,
        end: Option<&Value>,
        depth: u32,
    ) -> Option<Vec<V3>> {
        // Null for absent; a value that is no number is no sweep.
        let param = |v: Option<&Value>| -> Option<Option<f64>> {
            match v {
                Some(v) if !v.is_null() => v.num().filter(|x| x.is_finite()).map(Some),
                _ => Some(None),
            }
        };
        let (s, e) = (param(start)?, param(end)?);
        if s.is_none() && e.is_none() {
            return self.curve(id, depth + 1);
        }
        let ty = self.get(id)?.0;
        let Some(samples) = self.parametrised(id, s.zip(e), depth + 1) else {
            self.unsupported(ty);
            return self.curve(id, depth + 1);
        };
        let first = samples.first()?.0;
        let last = samples.last()?.0;
        cut(&samples, s.unwrap_or(first), e.unwrap_or(last))
    }

    /// The points of curve `id` with their parameters, ascending. `ends`
    /// are the sweep's parameters, which an unbounded line needs.
    fn parametrised(
        &mut self,
        id: u32,
        ends: Option<(f64, f64)>,
        depth: u32,
    ) -> Option<Vec<(f64, V3)>> {
        if depth > MAX_DEPTH {
            return None;
        }
        let (ty, p) = self.get(id)?;
        let indexed = |pts: Vec<V3>| -> Vec<(f64, V3)> {
            pts.into_iter()
                .enumerate()
                .map(|(i, q)| (i as f64, q))
                .collect()
        };
        let samples: Option<Vec<(f64, V3)>> = match ty {
            b"IFCPOLYLINE" => {
                Some(indexed(self.points(p.first())?)).filter(|s| s.len() <= MAX_POINTS)
            }
            b"IFCINDEXEDPOLYCURVE" => {
                // Straight parts only: an arc has no published parameter.
                let arcs = p.get(1).and_then(Value::list).is_some_and(|l| {
                    l.iter()
                        .any(|s| matches!(s, Value::Typed(k, _) if *k != b"IFCLINEINDEX"))
                });
                if arcs {
                    return None;
                }
                Some(indexed(self.curve(id, depth)?))
            }
            b"IFCTRIMMEDCURVE" => self.trimmed(&p, depth),
            b"IFCCIRCLE" | b"IFCELLIPSE" => {
                let (pos, a, b) = self.conic(ty, &p)?;
                let n = segments(TAU);
                Some(
                    (0..=n)
                        .map(|k| {
                            let t = TAU * k as f64 / n as f64;
                            (t / self.angle, conic_point(&pos, a, b, t))
                        })
                        .collect(),
                )
            }
            b"IFCLINE" => {
                let (s, e) = ends?;
                let o = self.point(p.first()?.id()?)?;
                let vp = self.f.params(p.get(1)?.id()?)?;
                let d = scale(self.direction(vp.first()?.id()?)?, vp.get(1)?.num()?);
                Some(vec![
                    (s.min(e), add(o, scale(d, s.min(e)))),
                    (s.max(e), add(o, scale(d, s.max(e)))),
                ])
            }
            b"IFCBSPLINECURVEWITHKNOTS" | b"IFCRATIONALBSPLINECURVEWITHKNOTS" => self.bspline(&p),
            b"IFCCOMPOSITECURVE" | b"IFC2DCOMPOSITECURVE" => {
                let list = p.first()?.list()?;
                // Segments of IFC4X3: stations along the curve.
                let curve_segments = list
                    .first()
                    .and_then(Value::id)
                    .and_then(|s| self.get(s))
                    .is_some_and(|(t, _)| t == b"IFCCURVESEGMENT");
                if curve_segments {
                    return self.curve_segments(list);
                }
                let mut out: Vec<(f64, V3)> = Vec::new();
                let mut acc = 0.0;
                for seg in list.iter().filter_map(Value::id) {
                    let (sty, sp) = self.get(seg)?;
                    if !is(
                        sty,
                        &[
                            b"IFCCOMPOSITECURVESEGMENT",
                            b"IFCREPARAMETRISEDCOMPOSITECURVESEGMENT",
                        ],
                    ) {
                        return None;
                    }
                    let parent = self.parametrised(sp.get(2)?.id()?, None, depth + 1)?;
                    let (t0, t1) = (parent.first()?.0, parent.last()?.0);
                    let own = t1 - t0;
                    let length = if sty == b"IFCREPARAMETRISEDCOMPOSITECURVESEGMENT" {
                        sp.get(3)?.num().filter(|l| *l > 0.0 && l.is_finite())?
                    } else {
                        own
                    };
                    let factor = if own > 0.0 { length / own } else { 0.0 };
                    let same = sp.get(1).and_then(Value::boolean).unwrap_or(true);
                    let mut part: Vec<(f64, V3)> = parent
                        .iter()
                        .map(|&(t, q)| (acc + if same { t - t0 } else { t1 - t } * factor, q))
                        .collect();
                    if !same {
                        part.reverse();
                    }
                    out.extend(part);
                    acc += length;
                    if out.len() > MAX_POINTS {
                        return None;
                    }
                }
                Some(out)
            }
            b"IFCGRADIENTCURVE" => self.gradient_curve(&p, depth),
            _ => None,
        };
        samples.filter(|s| s.len() >= 2 && s.windows(2).all(|w| w[1].0 >= w[0].0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn polyline() -> Vec<(f64, V3)> {
        vec![
            (0.0, [0.0, 0.0, 0.0]),
            (1.0, [2.0, 0.0, 0.0]),
            (2.0, [2.0, 2.0, 0.0]),
        ]
    }

    #[test]
    fn a_polyline_is_cut_between_parameters() {
        // Half way along the first segment to a quarter along the second.
        let c = cut(&polyline(), 0.5, 1.25).unwrap();
        assert_eq!(c, vec![[1.0, 0.0, 0.0], [2.0, 0.0, 0.0], [2.0, 0.5, 0.0]]);
        // The end first runs the curve the other way.
        let c = cut(&polyline(), 1.25, 0.5).unwrap();
        assert_eq!(c, vec![[2.0, 0.5, 0.0], [2.0, 0.0, 0.0], [1.0, 0.0, 0.0]]);
    }

    #[test]
    fn parameters_beyond_the_curve_are_its_ends_and_an_empty_range_is_none() {
        let c = cut(&polyline(), -5.0, 99.0).unwrap();
        assert_eq!(c.len(), 3);
        assert_eq!(c[0], [0.0; 3]);
        assert_eq!(c[2], [2.0, 2.0, 0.0]);
        assert!(cut(&polyline(), 1.0, 1.0).is_none());
        assert!(cut(&polyline(), 5.0, 9.0).is_none());
        assert!(cut(&polyline(), f64::NAN, 1.0).is_none());
        assert!(cut(&[], 0.0, 1.0).is_none());
        // Samples out of order are not a curve.
        assert!(cut(&[(1.0, [0.0; 3]), (0.0, [1.0; 3])], 0.0, 1.0).is_none());
    }
}
