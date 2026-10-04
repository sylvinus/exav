//! Profiles (`IfcProfileDef` and its subtypes) as 2D loops. Parameterised
//! profiles are centred on their bounding box (IFC2X3 onwards) and placed
//! by their optional `Position`.

use std::f64::consts::{FRAC_PI_2, PI, TAU};

use super::curves::{segments, SEGMENTS_PER_TURN};
use super::math::{Xf, V2, V3};
use super::step::Value;
use super::{Reader, MAX_DEPTH};

/// Closed areas, each an outer loop (counter-clockwise) and its holes
/// (clockwise); and open curves, which sweep into surfaces.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub areas: Vec<(Vec<V2>, Vec<Vec<V2>>)>,
    pub open: Vec<Vec<V2>>,
}

fn signed_area(l: &[V2]) -> f64 {
    let n = l.len();
    (0..n)
        .map(|i| l[i][0] * l[(i + 1) % n][1] - l[(i + 1) % n][0] * l[i][1])
        .sum::<f64>()
        / 2.0
}

/// Without a repeated closing point.
fn open_loop(mut l: Vec<V2>) -> Vec<V2> {
    while l.len() > 1 {
        let (a, b) = (l[0], l[l.len() - 1]);
        let tol = 1e-9 * (1.0 + a[0].abs().max(a[1].abs()));
        if (a[0] - b[0]).abs() <= tol && (a[1] - b[1]).abs() <= tol {
            l.pop();
        } else {
            break;
        }
    }
    l
}

impl Profile {
    fn area(outer: Vec<V2>, holes: Vec<Vec<V2>>) -> Profile {
        let mut p = Profile::default();
        p.push(outer, holes);
        p
    }

    fn push(&mut self, outer: Vec<V2>, holes: Vec<Vec<V2>>) {
        let mut outer = open_loop(outer);
        if outer.len() < 3 {
            return;
        }
        if signed_area(&outer) < 0.0 {
            outer.reverse();
        }
        let holes = holes
            .into_iter()
            .map(open_loop)
            .filter(|h| h.len() >= 3)
            .map(|mut h| {
                if signed_area(&h) > 0.0 {
                    h.reverse();
                }
                h
            })
            .collect();
        self.areas.push((outer, holes));
    }

    pub fn transform(&mut self, x: &Xf) {
        let f = |p: &mut V2| {
            let q = x.point([p[0], p[1], 0.0]);
            *p = [q[0], q[1]];
        };
        let mirrored = x.det() < 0.0;
        for (o, hs) in &mut self.areas {
            o.iter_mut().for_each(f);
            hs.iter_mut().flatten().for_each(f);
            if mirrored {
                o.reverse();
                hs.iter_mut().for_each(|h| h.reverse());
            }
        }
        self.open.iter_mut().flatten().for_each(f);
    }

    pub fn is_empty(&self) -> bool {
        self.areas.is_empty() && self.open.is_empty()
    }
}

fn rect(x: f64, y: f64) -> Vec<V2> {
    vec![
        [-x / 2.0, -y / 2.0],
        [x / 2.0, -y / 2.0],
        [x / 2.0, y / 2.0],
        [-x / 2.0, y / 2.0],
    ]
}

fn ellipse(a: f64, b: f64) -> Vec<V2> {
    let n = SEGMENTS_PER_TURN as usize;
    (0..n)
        .map(|k| {
            let t = TAU * k as f64 / n as f64;
            [a * t.cos(), b * t.sin()]
        })
        .collect()
}

/// Rounds the corners of a polygon: `radii[i]` at vertex `i` (0 for none),
/// convex or concave, each shrunk to fit its two edges.
pub fn fillet(pts: &[V2], radii: &[f64]) -> Vec<V2> {
    let n = pts.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let r = radii.get(i).copied().unwrap_or(0.0);
        let (p0, p1, p2) = (pts[(i + n - 1) % n], pts[i], pts[(i + 1) % n]);
        let d1 = [p0[0] - p1[0], p0[1] - p1[1]];
        let d2 = [p2[0] - p1[0], p2[1] - p1[1]];
        let (l1, l2) = (d1[0].hypot(d1[1]), d2[0].hypot(d2[1]));
        if !r.is_finite() || r <= 0.0 || l1 <= 0.0 || l2 <= 0.0 {
            out.push(p1);
            continue;
        }
        let u1 = [d1[0] / l1, d1[1] / l1];
        let u2 = [d2[0] / l2, d2[1] / l2];
        let cos = (u1[0] * u2[0] + u1[1] * u2[1]).clamp(-1.0, 1.0);
        let half = cos.acos() / 2.0;
        if half < 1e-6 || half > FRAC_PI_2 - 1e-6 {
            out.push(p1);
            continue;
        }
        // Distance from the corner to the tangent points, within the edges.
        let mut t = r / half.tan();
        let limit = l1.min(l2) * 0.5;
        let r = if t > limit {
            t = limit;
            limit * half.tan()
        } else {
            r
        };
        let bis = [u1[0] + u2[0], u1[1] + u2[1]];
        let bl = bis[0].hypot(bis[1]);
        let c = [
            p1[0] + bis[0] / bl * r / half.sin(),
            p1[1] + bis[1] / bl * r / half.sin(),
        ];
        let a = [p1[0] + u1[0] * t, p1[1] + u1[1] * t];
        let b = [p1[0] + u2[0] * t, p1[1] + u2[1] * t];
        let s = (a[1] - c[1]).atan2(a[0] - c[0]);
        let mut e = (b[1] - c[1]).atan2(b[0] - c[0]);
        // The short way round.
        while e - s > PI {
            e -= TAU;
        }
        while s - e > PI {
            e += TAU;
        }
        let k = segments(e - s).max(2);
        for j in 0..=k {
            let ang = s + (e - s) * j as f64 / k as f64;
            out.push([c[0] + r * ang.cos(), c[1] + r * ang.sin()]);
        }
    }
    out
}

impl<'a> Reader<'a> {
    /// A profile in the plane of its swept solid.
    pub fn profile(&mut self, id: u32, depth: u32) -> Option<Profile> {
        if depth > MAX_DEPTH {
            return None;
        }
        let (ty, p) = self.get(id)?;
        let num = |i: usize| p.get(i).and_then(Value::num).filter(|v| v.is_finite());
        let opt = |i: usize| num(i).unwrap_or(0.0).max(0.0);
        let pos = |r: &Self| r.axis2_or_identity(p.get(2));
        let positive = |v: f64| v > 0.0;
        let mut out = match ty {
            b"IFCRECTANGLEPROFILEDEF" => {
                let (x, y) = (
                    num(3).filter(|v| positive(*v))?,
                    num(4).filter(|v| positive(*v))?,
                );
                Profile::area(rect(x, y), Vec::new())
            }
            b"IFCROUNDEDRECTANGLEPROFILEDEF" => {
                let (x, y) = (
                    num(3).filter(|v| positive(*v))?,
                    num(4).filter(|v| positive(*v))?,
                );
                Profile::area(fillet(&rect(x, y), &[opt(5); 4]), Vec::new())
            }
            b"IFCRECTANGLEHOLLOWPROFILEDEF" => {
                let (x, y, t) = (
                    num(3).filter(|v| positive(*v))?,
                    num(4).filter(|v| positive(*v))?,
                    num(5).filter(|v| positive(*v))?,
                );
                let outer = fillet(&rect(x, y), &[opt(7); 4]);
                let holes = if 2.0 * t < x && 2.0 * t < y {
                    vec![fillet(&rect(x - 2.0 * t, y - 2.0 * t), &[opt(6); 4])]
                } else {
                    Vec::new()
                };
                Profile::area(outer, holes)
            }
            b"IFCCIRCLEPROFILEDEF" => {
                let r = num(3).filter(|v| positive(*v))?;
                Profile::area(ellipse(r, r), Vec::new())
            }
            b"IFCCIRCLEHOLLOWPROFILEDEF" => {
                let (r, t) = (
                    num(3).filter(|v| positive(*v))?,
                    num(4).filter(|v| positive(*v))?,
                );
                let holes = if t < r {
                    vec![ellipse(r - t, r - t)]
                } else {
                    Vec::new()
                };
                Profile::area(ellipse(r, r), holes)
            }
            b"IFCELLIPSEPROFILEDEF" => Profile::area(
                ellipse(
                    num(3).filter(|v| positive(*v))?,
                    num(4).filter(|v| positive(*v))?,
                ),
                Vec::new(),
            ),
            b"IFCISHAPEPROFILEDEF" | b"IFCASYMMETRICISHAPEPROFILEDEF" => {
                let asym = ty == b"IFCASYMMETRICISHAPEPROFILEDEF";
                let (wb, d, tw, tfb) = (num(3)?, num(4)?, num(5)?, num(6)?);
                let r = opt(7);
                let (wt, tft, rt) = if asym {
                    (num(8)?, num(9).unwrap_or(tfb), num(10).unwrap_or(r))
                } else {
                    (wb, tfb, r)
                };
                // IFC4: FlangeEdgeRadius of the symmetric I.
                let edge = if asym { 0.0 } else { opt(8) };
                if !(wb > 0.0
                    && wt > 0.0
                    && d > 0.0
                    && tw > 0.0
                    && tfb > 0.0
                    && tft > 0.0
                    && tfb + tft < d
                    && tw < wb.min(wt))
                {
                    return None;
                }
                let (y0, y1) = (-d / 2.0, d / 2.0);
                let pts = vec![
                    [-wb / 2.0, y0],
                    [wb / 2.0, y0],
                    [wb / 2.0, y0 + tfb],
                    [tw / 2.0, y0 + tfb],
                    [tw / 2.0, y1 - tft],
                    [wt / 2.0, y1 - tft],
                    [wt / 2.0, y1],
                    [-wt / 2.0, y1],
                    [-wt / 2.0, y1 - tft],
                    [-tw / 2.0, y1 - tft],
                    [-tw / 2.0, y0 + tfb],
                    [-wb / 2.0, y0 + tfb],
                ];
                let radii = [0.0, 0.0, edge, r, rt, edge, 0.0, 0.0, edge, rt, r, edge];
                Profile::area(fillet(&pts, &radii), Vec::new())
            }
            b"IFCLSHAPEPROFILEDEF" => {
                let d = num(3)?;
                let w = num(4).unwrap_or(d);
                let t = num(5)?;
                if !(d > 0.0 && w > 0.0 && t > 0.0 && t < d && t < w) {
                    return None;
                }
                let (x0, y0) = (-w / 2.0, -d / 2.0);
                let pts = vec![
                    [x0, y0],
                    [x0 + w, y0],
                    [x0 + w, y0 + t],
                    [x0 + t, y0 + t],
                    [x0 + t, y0 + d],
                    [x0, y0 + d],
                ];
                let radii = [0.0, 0.0, opt(7), opt(6), opt(7), 0.0];
                Profile::area(fillet(&pts, &radii), Vec::new())
            }
            b"IFCTSHAPEPROFILEDEF" => {
                let (d, wf, tw, tf) = (num(3)?, num(4)?, num(5)?, num(6)?);
                if !(d > 0.0 && wf > 0.0 && tw > 0.0 && tf > 0.0 && tf < d && tw < wf) {
                    return None;
                }
                let (r, fe, we) = (opt(7), opt(8), opt(9));
                let (y0, y1) = (-d / 2.0, d / 2.0);
                let pts = vec![
                    [-tw / 2.0, y0],
                    [tw / 2.0, y0],
                    [tw / 2.0, y1 - tf],
                    [wf / 2.0, y1 - tf],
                    [wf / 2.0, y1],
                    [-wf / 2.0, y1],
                    [-wf / 2.0, y1 - tf],
                    [-tw / 2.0, y1 - tf],
                ];
                let radii = [we, we, r, fe, 0.0, 0.0, fe, r];
                Profile::area(fillet(&pts, &radii), Vec::new())
            }
            b"IFCUSHAPEPROFILEDEF" => {
                let (d, wf, tw, tf) = (num(3)?, num(4)?, num(5)?, num(6)?);
                if !(d > 0.0 && wf > 0.0 && tw > 0.0 && tf > 0.0 && 2.0 * tf < d && tw < wf) {
                    return None;
                }
                let (r, e) = (opt(7), opt(8));
                let (x0, y0, y1) = (-wf / 2.0, -d / 2.0, d / 2.0);
                let pts = vec![
                    [x0, y0],
                    [x0 + wf, y0],
                    [x0 + wf, y0 + tf],
                    [x0 + tw, y0 + tf],
                    [x0 + tw, y1 - tf],
                    [x0 + wf, y1 - tf],
                    [x0 + wf, y1],
                    [x0, y1],
                ];
                let radii = [0.0, 0.0, e, r, r, e, 0.0, 0.0];
                Profile::area(fillet(&pts, &radii), Vec::new())
            }
            b"IFCCSHAPEPROFILEDEF" => {
                let (d, w, t, g) = (num(3)?, num(4)?, num(5)?, num(6)?);
                if !(d > 0.0
                    && w > 0.0
                    && t > 0.0
                    && g >= 0.0
                    && 2.0 * t < d
                    && 2.0 * t < w
                    && g < d / 2.0)
                {
                    return None;
                }
                let (x0, x1, y0, y1) = (-w / 2.0, w / 2.0, -d / 2.0, d / 2.0);
                let pts = if g > t {
                    vec![
                        [x0, y0],
                        [x1, y0],
                        [x1, y0 + g],
                        [x1 - t, y0 + g],
                        [x1 - t, y0 + t],
                        [x0 + t, y0 + t],
                        [x0 + t, y1 - t],
                        [x1 - t, y1 - t],
                        [x1 - t, y1 - g],
                        [x1, y1 - g],
                        [x1, y1],
                        [x0, y1],
                    ]
                } else {
                    // No lips: a channel.
                    vec![
                        [x0, y0],
                        [x1, y0],
                        [x1, y0 + t],
                        [x0 + t, y0 + t],
                        [x0 + t, y1 - t],
                        [x1, y1 - t],
                        [x1, y1],
                        [x0, y1],
                    ]
                };
                Profile::area(pts, Vec::new())
            }
            b"IFCZSHAPEPROFILEDEF" => {
                let (d, wf, tw, tf) = (num(3)?, num(4)?, num(5)?, num(6)?);
                if !(d > 0.0 && wf > 0.0 && tw > 0.0 && tf > 0.0 && 2.0 * tf < d && tw < wf) {
                    return None;
                }
                let (r, e) = (opt(7), opt(8));
                let (y0, y1) = (-d / 2.0, d / 2.0);
                // As the specification's figure: the top flange to the
                // left of the web, the bottom one to the right, each
                // FlangeWidth wide with the web's thickness.
                let pts = vec![
                    [-tw / 2.0, y0],
                    [wf - tw / 2.0, y0],
                    [wf - tw / 2.0, y0 + tf],
                    [tw / 2.0, y0 + tf],
                    [tw / 2.0, y1],
                    [tw / 2.0 - wf, y1],
                    [tw / 2.0 - wf, y1 - tf],
                    [-tw / 2.0, y1 - tf],
                ];
                let radii = [0.0, 0.0, e, r, 0.0, 0.0, e, r];
                Profile::area(fillet(&pts, &radii), Vec::new())
            }
            b"IFCTRAPEZIUMPROFILEDEF" => {
                let (xb, xt, y, off) = (num(3)?, num(4)?, num(5)?, num(6)?);
                if !(xb > 0.0 && xt > 0.0 && y > 0.0) {
                    return None;
                }
                let pts = vec![
                    [-xb / 2.0, -y / 2.0],
                    [xb / 2.0, -y / 2.0],
                    [-xb / 2.0 + off + xt, y / 2.0],
                    [-xb / 2.0 + off, y / 2.0],
                ];
                Profile::area(pts, Vec::new())
            }
            b"IFCARBITRARYCLOSEDPROFILEDEF" | b"IFCARBITRARYPROFILEDEFWITHVOIDS" => {
                let outer = self.curve(p.get(2)?.id()?, depth + 1)?;
                let mut holes = Vec::new();
                if ty == b"IFCARBITRARYPROFILEDEFWITHVOIDS" {
                    for h in p.get(3)?.list()?.iter().filter_map(Value::id) {
                        if let Some(c) = self.curve(h, depth + 1) {
                            holes.push(flat(&c));
                        }
                    }
                }
                Profile::area(flat(&outer), holes)
            }
            b"IFCARBITRARYOPENPROFILEDEF" => Profile {
                open: vec![flat(&self.curve(p.get(2)?.id()?, depth + 1)?)],
                ..Profile::default()
            },
            b"IFCCENTERLINEPROFILEDEF" => {
                let c = flat(&self.curve(p.get(2)?.id()?, depth + 1)?);
                let t = num(3).filter(|v| *v > 0.0)?;
                Profile::area(thicken(&c, t)?, Vec::new())
            }
            b"IFCDERIVEDPROFILEDEF" | b"IFCMIRROREDPROFILEDEF" => {
                let mut parent = self.profile(p.get(2)?.id()?, depth + 1)?;
                let x = if ty == b"IFCMIRROREDPROFILEDEF" {
                    // Derived: mirrored about the y axis.
                    Xf::new([-1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0], [0.0; 3])
                } else {
                    self.operator(p.get(3)?.id()?)?
                };
                parent.transform(&x);
                return Some(parent);
            }
            b"IFCCOMPOSITEPROFILEDEF" => {
                let mut all = Profile::default();
                for s in p.get(2)?.list()?.iter().filter_map(Value::id) {
                    let Some(mut sub) = self.profile(s, depth + 1) else {
                        continue;
                    };
                    all.areas.append(&mut sub.areas);
                    all.open.append(&mut sub.open);
                }
                return (!all.is_empty()).then_some(all);
            }
            _ => {
                self.unsupported(ty);
                return None;
            }
        };
        // Parameterised profiles have a Position; arbitrary ones none.
        let parameterised = !matches!(
            ty,
            b"IFCARBITRARYCLOSEDPROFILEDEF"
                | b"IFCARBITRARYPROFILEDEFWITHVOIDS"
                | b"IFCARBITRARYOPENPROFILEDEF"
                | b"IFCCENTERLINEPROFILEDEF"
        );
        if parameterised {
            out.transform(&pos(self)?);
        }
        (!out.is_empty()).then_some(out)
    }
}

fn flat(c: &[V3]) -> Vec<V2> {
    c.iter().map(|p| [p[0], p[1]]).collect()
}

/// The area within `t / 2` of an open polyline, mitred at its corners.
fn thicken(c: &[V2], t: f64) -> Option<Vec<V2>> {
    if c.len() < 2 {
        return None;
    }
    let h = t / 2.0;
    let normal = |a: V2, b: V2| -> Option<V2> {
        let (dx, dy) = (b[0] - a[0], b[1] - a[1]);
        let l = dx.hypot(dy);
        (l > 0.0).then(|| [-dy / l, dx / l])
    };
    let mut left = Vec::with_capacity(c.len());
    let mut right = Vec::with_capacity(c.len());
    for i in 0..c.len() {
        let n_in = if i > 0 { normal(c[i - 1], c[i]) } else { None };
        let n_out = if i + 1 < c.len() {
            normal(c[i], c[i + 1])
        } else {
            None
        };
        let n = match (n_in, n_out) {
            (Some(a), Some(b)) => {
                let m = [a[0] + b[0], a[1] + b[1]];
                let ml = m[0].hypot(m[1]);
                let cos = (m[0] * a[0] + m[1] * a[1]) / ml.max(1e-12);
                if ml < 1e-9 || cos < 0.2 {
                    a
                } else {
                    [m[0] / ml / cos, m[1] / ml / cos]
                }
            }
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => continue,
        };
        left.push([c[i][0] + n[0] * h, c[i][1] + n[1] * h]);
        right.push([c[i][0] - n[0] * h, c[i][1] - n[1] * h]);
    }
    right.reverse();
    left.extend(right);
    (left.len() >= 3).then_some(left)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fillet_takes_the_corner_area_off() {
        let sq = rect(2.0, 2.0);
        let r = 0.5;
        let f = fillet(&sq, &[r; 4]);
        let expected = 4.0 - (4.0 - PI) * r * r;
        assert!(
            (signed_area(&f) - expected).abs() < 0.01,
            "{}",
            signed_area(&f)
        );
    }

    #[test]
    fn a_concave_fillet_adds_area() {
        // An L whose inner corner (index 3) is rounded.
        let pts = vec![[0., 0.], [2., 0.], [2., 1.], [1., 1.], [1., 2.], [0., 2.]];
        let r = 0.25;
        let f = fillet(&pts, &[0., 0., 0., r, 0., 0.]);
        let expected = 3.0 + (1.0 - PI / 4.0) * r * r;
        assert!(
            (signed_area(&f) - expected).abs() < 0.002,
            "{}",
            signed_area(&f)
        );
    }

    #[test]
    fn a_thickened_line_is_a_rectangle() {
        let a = thicken(&[[0.0, 0.0], [4.0, 0.0]], 0.5).unwrap();
        assert!((signed_area(&a).abs() - 2.0).abs() < 1e-12);
    }
}
