//! `IfcGridPlacement`: an object placed at the intersection of two axes of
//! an `IfcGrid` (offset from them, in plan and in height), its x axis along
//! the first axis, along a given direction, or towards a second
//! intersection.

use std::collections::HashMap;

use super::math::{V3, Xf, cross, len, scale, sub, unit};
use super::step::Value;
use super::{Reader, step};

/// Most pairs of segments tried for one intersection.
const MAX_PAIRS: usize = 4_000_000;

/// An axis curve in the grid's plane.
enum Axis {
    /// A line, unbounded, by a point and a unit direction.
    Line(V3, V3),
    /// Segments between points.
    Poly(Vec<V3>),
}

/// A segment of an axis, offset: its start, its direction (not unit), and
/// whether it is bounded.
struct Segment {
    from: V3,
    along: V3,
    bounded: bool,
}

impl Axis {
    /// The segments, `offset` to the left of the way the axis runs (the
    /// other way when `same` is false).
    fn segments(&self, offset: f64, same: bool) -> Vec<Segment> {
        let shifted = |from: V3, along: V3| {
            let flip = if same { 1.0 } else { -1.0 };
            let left = unit([-along[1] * flip, along[0] * flip, 0.0]).unwrap_or([0.0; 3]);
            let along = scale(along, flip);
            let from = [from[0] + left[0] * offset, from[1] + left[1] * offset, 0.0];
            // Reversed, the segment starts at the other end.
            if same {
                Segment {
                    from,
                    along,
                    bounded: true,
                }
            } else {
                Segment {
                    from: [from[0] - along[0], from[1] - along[1], 0.0],
                    along,
                    bounded: true,
                }
            }
        };
        match self {
            Axis::Line(o, d) => {
                let mut s = shifted(*o, *d);
                s.bounded = false;
                vec![s]
            }
            Axis::Poly(pts) => pts
                .array_windows()
                .map(|&[a, b]| shifted(a, sub(b, a)))
                .collect(),
        }
    }
}

/// The first point at which two sets of segments cross, and the direction
/// of the first there.
fn cross_at(a: &[Segment], b: &[Segment]) -> Option<(V3, V3)> {
    let eps = 1e-9;
    for s in a {
        for t in b {
            let den = s.along[0] * t.along[1] - s.along[1] * t.along[0];
            if den.is_nan() || den.abs() <= 1e-12 * len(s.along) * len(t.along) {
                continue;
            }
            let (dx, dy) = (t.from[0] - s.from[0], t.from[1] - s.from[1]);
            let u = (dx * t.along[1] - dy * t.along[0]) / den;
            let v = (dx * s.along[1] - dy * s.along[0]) / den;
            let inside = |p: f64, bounded: bool| !bounded || (-eps..=1.0 + eps).contains(&p);
            if inside(u, s.bounded) && inside(v, t.bounded) {
                let at = [s.from[0] + s.along[0] * u, s.from[1] + s.along[1] * u, 0.0];
                return Some((at, unit(s.along)?));
            }
        }
    }
    None
}

impl<'a> Reader<'a> {
    /// The grid each axis belongs to.
    fn grid_of(&mut self, axis: u32) -> Option<u32> {
        if self.grids.is_none() {
            let mut map: HashMap<u32, u32> = HashMap::new();
            for g in self.f.of_type(b"IFCGRID") {
                let Some(p) = self.f.params(g) else { continue };
                for list in [7, 8, 9] {
                    for a in p
                        .get(list)
                        .and_then(Value::list)
                        .unwrap_or(&[])
                        .iter()
                        .filter_map(Value::id)
                    {
                        map.entry(a).or_insert(g);
                    }
                }
            }
            self.grids = Some(map);
        }
        self.grids.as_ref()?.get(&axis).copied()
    }

    /// An `IfcGridAxis`: its curve in the grid's plane and its sense.
    fn grid_axis(&mut self, id: u32, depth: u32) -> Option<(Axis, bool)> {
        let (ty, p) = self.get(id)?;
        if ty != b"IFCGRIDAXIS" {
            return None;
        }
        let same = p.get(2).and_then(Value::boolean).unwrap_or(true);
        let curve = p.get(1)?.id()?;
        let (cty, cp) = self.get(curve)?;
        if cty == b"IFCLINE" {
            let o = self.point(cp.first()?.id()?)?;
            let vp = self.f.params(cp.get(1)?.id()?)?;
            let d = self.direction(vp.first()?.id()?)?;
            return Some((Axis::Line(o, unit([d[0], d[1], 0.0])?), same));
        }
        let pts = self.curve(curve, depth + 1)?;
        Some((Axis::Poly(pts), same))
    }

    /// The point of an `IfcVirtualGridIntersection` in the grid's plane
    /// (height as given), the first axis's direction there, and the grid.
    fn grid_intersection(&mut self, id: u32) -> Option<(V3, V3, u32)> {
        let (ty, p) = self.get(id)?;
        if ty != b"IFCVIRTUALGRIDINTERSECTION" {
            return None;
        }
        let axes: Vec<u32> = p.first()?.list()?.iter().filter_map(Value::id).collect();
        let [first, second] = axes[..] else {
            return None;
        };
        let offsets: Vec<f64> = p
            .get(1)?
            .list()?
            .iter()
            .map(|v| v.num().filter(|x| x.is_finite()))
            .collect::<Option<_>>()?;
        let grid = self.grid_of(first)?;
        if self.grid_of(second)? != grid {
            return None;
        }
        let (a, same_a) = self.grid_axis(first, 0)?;
        let (b, same_b) = self.grid_axis(second, 0)?;
        let (sa, sb) = (
            a.segments(*offsets.first()?, same_a),
            b.segments(*offsets.get(1)?, same_b),
        );
        if sa.len().checked_mul(sb.len())? > MAX_PAIRS {
            return None;
        }
        self.charge(sa.len() * sb.len() / 64 + 1)?;
        let (at, along) = cross_at(&sa, &sb)?;
        Some((
            [at[0], at[1], offsets.get(2).copied().unwrap_or(0.0)],
            along,
            grid,
        ))
    }

    /// An `IfcGridPlacement`: the placement it hangs from and its transform
    /// there (in the grid's coordinates).
    pub(super) fn grid_placement(&mut self, p: &[Value]) -> Option<(Option<u32>, Xf)> {
        // IFC4X3 gives the placement the grid's own placement as
        // `PlacementRelTo`, ahead of the other attributes.
        let ifc4x3 = self.f.schema == step::Schema::Ifc4x3;
        let at = usize::from(ifc4x3);
        let (point, along, grid) = self.grid_intersection(p.get(at)?.id()?)?;
        let x = match p.get(at + 1) {
            Some(v) if !v.is_null() => {
                let id = v.id()?;
                if self.get(id).is_some_and(|(t, _)| t == b"IFCDIRECTION") {
                    let d = self.direction(id)?;
                    unit([d[0], d[1], 0.0])?
                } else {
                    let (other, _, g) = self.grid_intersection(id)?;
                    if g != grid {
                        return None;
                    }
                    unit([other[0] - point[0], other[1] - point[1], 0.0])?
                }
            }
            _ => unit([along[0], along[1], 0.0])?,
        };
        let z = [0.0, 0.0, 1.0];
        let local = Xf::new(x, cross(z, x), z, point);
        let parent = if ifc4x3 {
            p.first().and_then(Value::id)
        } else {
            None
        };
        let parent = parent.or_else(|| {
            self.f
                .params(grid)
                .and_then(|g| g.get(5).and_then(Value::id))
        });
        local.is_finite().then_some((parent, local))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(o: V3, d: V3) -> Axis {
        Axis::Line(o, unit(d).unwrap())
    }

    #[test]
    fn two_lines_cross_where_they_do() {
        let a = line([0.0, 2.0, 0.0], [1.0, 0.0, 0.0]).segments(0.0, true);
        let b = line([5.0, 0.0, 0.0], [0.0, 1.0, 0.0]).segments(0.0, true);
        let (p, d) = cross_at(&a, &b).unwrap();
        assert_eq!(p, [5.0, 2.0, 0.0]);
        assert_eq!(d, [1.0, 0.0, 0.0]);
        // Parallel lines do not.
        let c = line([0.0, 1.0, 0.0], [1.0, 0.0, 0.0]).segments(0.0, true);
        assert!(cross_at(&a, &c).is_none());
    }

    #[test]
    fn an_offset_is_to_the_left_of_the_way_the_axis_runs() {
        // The x axis offset by 1 is y = 1; run the other way, y = -1.
        let b = line([5.0, 0.0, 0.0], [0.0, 1.0, 0.0]);
        let a = line([0.0, 0.0, 0.0], [1.0, 0.0, 0.0]);
        let (p, _) = cross_at(&a.segments(1.0, true), &b.segments(0.0, true)).unwrap();
        assert_eq!(p, [5.0, 1.0, 0.0]);
        let (p, d) = cross_at(&a.segments(1.0, false), &b.segments(0.0, true)).unwrap();
        assert_eq!(p, [5.0, -1.0, 0.0]);
        assert_eq!(d, [-1.0, 0.0, 0.0]);
    }

    #[test]
    fn a_bounded_axis_stops_at_its_ends() {
        let short = Axis::Poly(vec![[0.0; 3], [2.0, 0.0, 0.0]]).segments(0.0, true);
        let b = line([5.0, -1.0, 0.0], [0.0, 1.0, 0.0]).segments(0.0, true);
        assert!(cross_at(&short, &b).is_none());
        let long = Axis::Poly(vec![[0.0; 3], [9.0, 0.0, 0.0]]).segments(0.0, true);
        assert_eq!(cross_at(&long, &b).unwrap().0, [5.0, 0.0, 0.0]);
    }
}
