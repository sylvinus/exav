//! Polylines with width, drawn as AutoCAD draws them: a filled band whose
//! width runs from each vertex's start width to its end width, along straight
//! and bulged segments alike, mitred where two segments meet. A DONUT is such
//! a polyline: two half-turn bulges with a width.

use super::curves;

/// One vertex of an LWPOLYLINE or a 2D POLYLINE, in its own coordinates.
#[derive(Clone, Copy, Debug)]
pub struct WideVertex {
    pub p: [f64; 2],
    pub bulge: f64,
    /// Width at this vertex and at the next one, for the segment it starts.
    pub start_width: f64,
    pub end_width: f64,
}

/// What a wide polyline draws.
#[derive(Default)]
pub struct Band {
    pub triangles: Vec<[[f64; 2]; 3]>,
    /// Each segment's outline, for `$FILLMODE` 0, which draws wide polylines
    /// as their edges.
    pub outlines: Vec<Vec<[f64; 2]>>,
    /// The segments without width, as point runs drawn as ordinary lines.
    pub thin: Vec<Vec<[f64; 2]>>,
}

/// A miter longer than this many half widths is cut back to a bevel: a
/// segment doubling back on itself would otherwise spike to infinity.
const MITER_LIMIT: f64 = 8.0;

/// A segment's cross sections: a centre point, its unit tangent and the
/// half width there, from its start to its end.
struct Segment {
    sections: Vec<([f64; 2], [f64; 2], f64)>,
    wide: bool,
}

fn normalize(v: [f64; 2]) -> Option<[f64; 2]> {
    let l = v[0].hypot(v[1]);
    (l > 1e-12 && l.is_finite()).then(|| [v[0] / l, v[1] / l])
}

fn rotate(v: [f64; 2], a: f64) -> [f64; 2] {
    let (s, c) = a.sin_cos();
    [v[0] * c - v[1] * s, v[0] * s + v[1] * c]
}

fn segment(a: WideVertex, b: [f64; 2]) -> Option<Segment> {
    let chord = normalize([b[0] - a.p[0], b[1] - a.p[1]])?;
    let (w0, w1) = (a.start_width.max(0.0), a.end_width.max(0.0));
    let wide = w0 > 0.0 || w1 > 0.0;
    let mut sections = Vec::new();
    if a.bulge.abs() < 1e-12 || !a.bulge.is_finite() {
        sections.push((a.p, chord, w0 / 2.0));
        sections.push((b, chord, w1 / 2.0));
    } else {
        // flatten_bulge samples the arc evenly by angle, so a sample's share
        // of the sweep is its share of the length: the width runs with it,
        // and the tangent turns from the chord's minus half the sweep to its
        // plus half.
        let theta = 4.0 * a.bulge.atan();
        let mut pts = vec![a.p];
        pts.extend(curves::flatten_bulge(a.p, b, a.bulge));
        let n = (pts.len() - 1) as f64;
        for (k, p) in pts.into_iter().enumerate() {
            let f = k as f64 / n;
            let t = rotate(chord, theta * (f - 0.5));
            sections.push((p, t, (w0 + (w1 - w0) * f) / 2.0));
        }
    }
    Some(Segment { sections, wide })
}

fn left(t: [f64; 2]) -> [f64; 2] {
    [-t[1], t[0]]
}

fn offset(p: [f64; 2], t: [f64; 2], d: f64) -> [f64; 2] {
    let n = left(t);
    [p[0] + n[0] * d, p[1] + n[1] * d]
}

/// Where the edge `p + s*ta` (offset `da` to the left) meets the edge
/// `p + s*tb` (offset `db`), within the miter limit.
fn miter(p: [f64; 2], ta: [f64; 2], da: f64, tb: [f64; 2], db: f64) -> Option<[f64; 2]> {
    let a = offset(p, ta, da);
    let b = offset(p, tb, db);
    let cross = ta[0] * tb[1] - ta[1] * tb[0];
    if cross.abs() < 1e-9 {
        return None;
    }
    let s = ((b[0] - a[0]) * tb[1] - (b[1] - a[1]) * tb[0]) / cross;
    let m = [a[0] + ta[0] * s, a[1] + ta[1] * s];
    let reach = (m[0] - p[0]).hypot(m[1] - p[1]);
    (reach <= MITER_LIMIT * da.abs().max(db.abs())).then_some(m)
}

/// The band of a polyline whose vertices carry widths.
pub fn band(verts: &[WideVertex], closed: bool) -> Band {
    let mut out = Band::default();
    if verts.len() < 2 {
        return out;
    }
    let count = if closed { verts.len() } else { verts.len() - 1 };
    let mut segments: Vec<Segment> = Vec::new();
    for i in 0..count {
        let b = verts[(i + 1) % verts.len()].p;
        if let Some(s) = segment(verts[i], b) {
            segments.push(s);
        }
    }
    // Each section's two edge points, before the joints move the ends.
    let mut edges: Vec<Vec<([f64; 2], [f64; 2])>> = segments
        .iter()
        .map(|s| {
            s.sections
                .iter()
                .map(|&(p, t, h)| (offset(p, t, h), offset(p, t, -h)))
                .collect()
        })
        .collect();
    // Mitre each joint between two wide segments: the end of one and the
    // start of the next move to where their edges cross.
    let joints = if closed {
        segments.len()
    } else {
        segments.len().saturating_sub(1)
    };
    for j in 0..joints {
        let (ia, ib) = (j, (j + 1) % segments.len());
        if ia == ib || !segments[ia].wide || !segments[ib].wide {
            continue;
        }
        let &(p, ta, ha) = segments[ia].sections.last().expect("two sections");
        let &(_, tb, hb) = &segments[ib].sections[0];
        let (Some(l), Some(r)) = (miter(p, ta, ha, tb, hb), miter(p, ta, -ha, tb, -hb)) else {
            continue;
        };
        *edges[ia].last_mut().expect("two sections") = (l, r);
        edges[ib][0] = (l, r);
    }

    for (s, e) in segments.iter().zip(&edges) {
        if !s.wide {
            out.thin
                .push(s.sections.iter().map(|&(p, _, _)| p).collect());
            continue;
        }
        for w in e.windows(2) {
            let ((l0, r0), (l1, r1)) = (w[0], w[1]);
            out.triangles.push([l0, r0, l1]);
            out.triangles.push([r0, r1, l1]);
        }
        let mut outline: Vec<[f64; 2]> = e.iter().map(|&(l, _)| l).collect();
        outline.extend(e.iter().rev().map(|&(_, r)| r));
        out.outlines.push(outline);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn area(t: &[[[f64; 2]; 3]]) -> f64 {
        t.iter()
            .map(|[a, b, c]| {
                ((b[0] - a[0]) * (c[1] - a[1]) - (c[0] - a[0]) * (b[1] - a[1])).abs() / 2.0
            })
            .sum()
    }

    fn v(x: f64, y: f64, bulge: f64, w0: f64, w1: f64) -> WideVertex {
        WideVertex {
            p: [x, y],
            bulge,
            start_width: w0,
            end_width: w1,
        }
    }

    #[test]
    fn a_straight_segment_is_its_length_by_its_width() {
        let b = band(
            &[v(0.0, 0.0, 0.0, 2.0, 2.0), v(10.0, 0.0, 0.0, 0.0, 0.0)],
            false,
        );
        assert!(
            (area(&b.triangles) - 20.0).abs() < 1e-9,
            "{}",
            area(&b.triangles)
        );
        assert!(b.thin.is_empty());
    }

    #[test]
    fn a_taper_to_a_point_is_half_the_rectangle() {
        let b = band(
            &[v(0.0, 0.0, 0.0, 4.0, 0.0), v(10.0, 0.0, 0.0, 0.0, 0.0)],
            false,
        );
        assert!(
            (area(&b.triangles) - 20.0).abs() < 1e-9,
            "{}",
            area(&b.triangles)
        );
    }

    #[test]
    fn a_donut_is_its_annulus() {
        // DONUT 8 inside, 12 outside: two half turns of radius 5, width 2.
        let b = band(
            &[v(-5.0, 0.0, 1.0, 2.0, 2.0), v(5.0, 0.0, 1.0, 2.0, 2.0)],
            true,
        );
        let annulus = std::f64::consts::PI * (6.0f64.powi(2) - 4.0f64.powi(2));
        let a = area(&b.triangles);
        assert!((a / annulus - 1.0).abs() < 0.01, "{a} vs {annulus}");
    }

    #[test]
    fn a_right_angle_is_mitred_without_a_notch_or_an_overlap() {
        // An L, width 2: the arms' area plus the corner square, once.
        let b = band(
            &[
                v(0.0, 0.0, 0.0, 2.0, 2.0),
                v(10.0, 0.0, 0.0, 2.0, 2.0),
                v(10.0, 10.0, 0.0, 0.0, 0.0),
            ],
            false,
        );
        let expected = 10.0 * 2.0 * 2.0;
        let a = area(&b.triangles);
        assert!((a - expected).abs() < 1e-9, "{a} vs {expected}");
        // The outer corner reaches (11, -1).
        assert!(b
            .triangles
            .iter()
            .flatten()
            .any(|p| (p[0] - 11.0).abs() < 1e-9 && (p[1] + 1.0).abs() < 1e-9));
    }

    #[test]
    fn segments_without_width_stay_lines() {
        let b = band(
            &[
                v(0.0, 0.0, 0.0, 0.0, 0.0),
                v(5.0, 0.0, 0.0, 1.0, 1.0),
                v(10.0, 0.0, 0.0, 0.0, 0.0),
            ],
            false,
        );
        assert_eq!(b.thin.len(), 1);
        assert!((area(&b.triangles) - 5.0).abs() < 1e-9);
    }

    #[test]
    fn a_hairpin_turn_is_cut_back_rather_than_spiking() {
        let b = band(
            &[
                v(0.0, 0.0, 0.0, 1.0, 1.0),
                v(10.0, 0.0, 0.0, 1.0, 1.0),
                v(0.0, 0.01, 0.0, 0.0, 0.0),
            ],
            false,
        );
        let far = b
            .triangles
            .iter()
            .flatten()
            .map(|p| p[0])
            .fold(f64::MIN, f64::max);
        assert!(far < 11.0, "{far}");
    }
}
