//! A dimension's graphics, for one saved without the anonymous block AutoCAD
//! draws it from: generators often leave the block out. The geometry follows
//! the definition points and the style's sizes; what this leaves to the
//! block (DIMTIH, DIMLUNIT's feet and inches, tolerances, alternate units,
//! arrows flipped outside a short dimension) is not drawn.

use crate::cad::{DimStyle, Dimension, DimensionKind, Vec3};

/// A style's sizes in drawing units (DIMSCALE applied) and how it writes
/// numbers.
pub struct Style {
    pub asz: f64,
    pub exo: f64,
    pub exe: f64,
    pub dle: f64,
    pub tsz: f64,
    pub txt: f64,
    pub gap: f64,
    /// Text above the dimension line, else centred on it, the line broken.
    pub above: bool,
    pub zin: i16,
    pub lfac: f64,
    pub dec: usize,
    pub adec: usize,
    pub dsep: char,
}

impl Style {
    pub fn new(s: &DimStyle) -> Style {
        let scale = if s.dimscale > 0.0 && s.dimscale.is_finite() {
            s.dimscale
        } else {
            1.0
        };
        let size = |v: f64| if v.is_finite() { v.abs() * scale } else { 0.0 };
        let places = |v: i16| usize::from(v.clamp(0, 8) as u8);
        Style {
            asz: size(s.dimasz),
            exo: size(s.dimexo),
            exe: size(s.dimexe),
            dle: size(s.dimdle),
            tsz: size(s.dimtsz),
            txt: size(s.dimtxt),
            gap: size(s.dimgap),
            above: s.dimtad != 0,
            zin: s.dimzin,
            lfac: if s.dimlfac.is_finite() && s.dimlfac != 0.0 {
                s.dimlfac.abs()
            } else {
                1.0
            },
            dec: places(s.dimdec),
            adec: places(s.dimadec),
            dsep: char::from_u32(u32::from(s.dimdsep.max(0) as u16))
                .filter(|c| !c.is_control())
                .unwrap_or('.'),
        }
    }
}

/// The text, its middle at `at`, turned by `rotation` (radians).
pub struct Label {
    pub text: String,
    pub at: [f64; 2],
    pub rotation: f64,
}

#[derive(Default)]
pub struct Graphics {
    pub lines: Vec<[[f64; 2]; 2]>,
    /// Centre, radius, start angle and signed sweep (radians).
    pub arcs: Vec<([f64; 2], f64, f64, f64)>,
    /// An arrowhead's tip, and a point it points away from.
    pub arrows: Vec<([f64; 2], [f64; 2])>,
    pub label: Option<Label>,
}

type P = [f64; 2];

fn p(v: Vec3) -> P {
    [v.x, v.y]
}
fn sub(a: P, b: P) -> P {
    [a[0] - b[0], a[1] - b[1]]
}
fn add(a: P, b: P) -> P {
    [a[0] + b[0], a[1] + b[1]]
}
fn mul(a: P, k: f64) -> P {
    [a[0] * k, a[1] * k]
}
fn dot(a: P, b: P) -> f64 {
    a[0] * b[0] + a[1] * b[1]
}
fn len(a: P) -> f64 {
    a[0].hypot(a[1])
}
fn unit(a: P) -> Option<P> {
    let l = len(a);
    (l > 1e-12 && l.is_finite()).then(|| mul(a, 1.0 / l))
}
fn perp(a: P) -> P {
    [-a[1], a[0]]
}
fn polar(a: f64) -> P {
    [a.cos(), a.sin()]
}

/// An angle turned to read left to right: in (-90, 90] degrees.
fn readable(a: f64) -> f64 {
    use std::f64::consts::{FRAC_PI_2, PI, TAU};
    let a = a.rem_euclid(TAU);
    if a > FRAC_PI_2 + 1e-9 && a <= 3.0 * FRAC_PI_2 + 1e-9 {
        a - PI
    } else if a > 3.0 * FRAC_PI_2 {
        a - TAU
    } else {
        a
    }
}

/// A number as the style writes it: its decimal places, its separator, and
/// leading (4) or trailing (8) zeros suppressed as DIMZIN says.
pub fn number(v: f64, places: usize, zin: i16, sep: char) -> String {
    // Halves away from zero, as AutoCAD rounds: formatting alone takes them
    // to even, 100.5 to 100.
    let k = 10f64.powi(places as i32);
    let rounded = (v * k).round() / k;
    let v = if rounded.is_finite() { rounded } else { v };
    let mut s = format!("{v:.places$}");
    if s.starts_with('-') && s[1..].chars().all(|c| c == '0' || c == '.') {
        s.remove(0);
    }
    if zin & 8 != 0 && s.contains('.') {
        s = s.trim_end_matches('0').trim_end_matches('.').to_string();
    }
    if zin & 4 != 0 {
        if let Some(rest) = s.strip_prefix("0.") {
            s = format!(".{rest}");
        } else if let Some(rest) = s.strip_prefix("-0.") {
            s = format!("-.{rest}");
        }
    }
    if sep != '.' {
        s = s.replace('.', &sep.to_string());
    }
    s
}

/// What the dimension says: its own text, where `<>` stands for the
/// measurement (empty is the measurement alone, a single space nothing).
fn content(d: &Dimension, measured: String) -> Option<String> {
    match d.text.as_str() {
        " " => None,
        "" => Some(measured),
        t => Some(t.replace("<>", &measured)),
    }
}

/// The text's middle the dimension stores (group 11), when it stores one:
/// a generator that leaves out the block leaves it at the origin too.
fn stored_text(d: &Dimension) -> Option<P> {
    let t = d.text_midpoint;
    (d.flags & 128 != 0 || t.x != 0.0 || t.y != 0.0).then(|| p(t))
}

pub fn graphics(d: &Dimension, s: &Style, measure: &dyn Fn(&str) -> f64) -> Option<Graphics> {
    match d.kind {
        DimensionKind::Linear | DimensionKind::Aligned => linear(d, s, measure),
        DimensionKind::Radius | DimensionKind::Diameter => radial(d, s),
        DimensionKind::Angular | DimensionKind::Angular3Point => angular(d, s),
        DimensionKind::Ordinate => ordinate(d, s),
    }
}

/// An extension line from `from` to `to` on the dimension line: `exo` short
/// of the feature, `exe` past the line.
fn extension(g: &mut Graphics, from: P, to: P, s: &Style) {
    if let Some(e) = unit(sub(to, from)) {
        if len(sub(to, from)) > s.exo {
            g.lines
                .push([add(from, mul(e, s.exo)), add(to, mul(e, s.exe))]);
        }
    }
}

/// The ends of a dimension line or arc: arrowheads, or with DIMTSZ ticks
/// at 45 degrees and the line run on by DIMDLE.
fn ends(g: &mut Graphics, a: P, b: P, s: &Style) {
    let Some(u) = unit(sub(b, a)) else {
        return;
    };
    if s.tsz > 0.0 {
        let t = mul(add(u, perp(u)), 0.5 * s.tsz);
        for c in [a, b] {
            g.lines.push([sub(c, t), add(c, t)]);
        }
    } else {
        g.arrows.push((a, b));
        g.arrows.push((b, a));
    }
}

fn linear(d: &Dimension, s: &Style, measure: &dyn Fn(&str) -> f64) -> Option<Graphics> {
    let (p1, p2, on) = (p(d.point13), p(d.point14), p(d.definition_point));
    let u = match d.kind {
        DimensionKind::Aligned => unit(sub(p2, p1)).unwrap_or([1.0, 0.0]),
        _ => polar(d.angle),
    };
    let a = add(on, mul(u, dot(sub(p1, on), u)));
    let b = add(on, mul(u, dot(sub(p2, on), u)));
    let mut g = Graphics::default();
    extension(&mut g, p1, a, s);
    extension(&mut g, p2, b, s);
    let measured = dot(sub(p2, p1), u).abs() * s.lfac;
    let rotation = if d.text_rotation != 0.0 {
        d.text_rotation
    } else {
        readable(u[1].atan2(u[0]))
    };
    let up = perp(polar(rotation));
    let mid = mul(add(a, b), 0.5);
    let label = content(d, number(measured, s.dec, s.zin, s.dsep)).map(|text| Label {
        at: stored_text(d).unwrap_or_else(|| {
            if s.above {
                add(mid, mul(up, s.gap + s.txt / 2.0))
            } else {
                mid
            }
        }),
        text,
        rotation,
    });
    let du = unit(sub(b, a)).unwrap_or(u);
    let run_on = if s.tsz > 0.0 {
        mul(du, s.dle)
    } else {
        [0.0, 0.0]
    };
    let (from, to) = (sub(a, run_on), add(b, run_on));
    // Text on the line breaks it, a gap either side.
    let cut = label.as_ref().filter(|l| {
        let off = sub(l.at, a);
        let along = dot(off, du);
        (dot(off, perp(du))).abs() < s.txt / 2.0 && along > 0.0 && along < len(sub(b, a))
    });
    match cut {
        Some(l) => {
            let half = measure(&l.text) * s.txt / 2.0 + s.gap;
            let along = dot(sub(l.at, a), du);
            let (c0, c1) = (add(a, mul(du, along - half)), add(a, mul(du, along + half)));
            if dot(sub(c0, from), du) > 0.0 {
                g.lines.push([from, c0]);
            }
            if dot(sub(to, c1), du) > 0.0 {
                g.lines.push([c1, to]);
            }
        }
        None => g.lines.push([from, to]),
    }
    ends(&mut g, a, b, s);
    g.label = label;
    Some(g)
}

fn radial(d: &Dimension, s: &Style) -> Option<Graphics> {
    let (far, near) = (p(d.definition_point), p(d.point15));
    let mut g = Graphics::default();
    let label_at = stored_text(d);
    let (measured, prefix) = match d.kind {
        DimensionKind::Radius => (len(sub(near, far)), "R"),
        _ => (len(sub(near, far)), "%%c"),
    };
    let u = unit(sub(near, far))?;
    match d.kind {
        DimensionKind::Radius => {
            // From the centre to the curve, or from the curve out to text
            // placed outside it.
            let outside = label_at.filter(|t| len(sub(*t, far)) > measured);
            match outside {
                Some(t) => g.lines.push([near, t]),
                None => g.lines.push([far, near]),
            }
            g.arrows.push((near, far));
        }
        _ => {
            g.lines.push([far, near]);
            g.arrows.push((near, far));
            g.arrows.push((far, near));
        }
    }
    let rotation = if d.text_rotation != 0.0 {
        d.text_rotation
    } else {
        readable(u[1].atan2(u[0]))
    };
    let mid = mul(add(far, near), 0.5);
    // The prefix is part of the measurement, `<>` included.
    let measured = format!(
        "{prefix}{}",
        number(measured * s.lfac, s.dec, s.zin, s.dsep)
    );
    g.label = content(d, measured).map(|text| Label {
        at: label_at.unwrap_or_else(|| add(mid, mul(perp(polar(rotation)), s.gap + s.txt / 2.0))),
        text,
        rotation,
    });
    Some(g)
}

/// Where two lines cross, each through two points.
fn crossing(a0: P, a1: P, b0: P, b1: P) -> Option<P> {
    let (r, q) = (sub(a1, a0), sub(b1, b0));
    let den = r[0] * q[1] - r[1] * q[0];
    if den.abs() < 1e-12 * len(r) * len(q) || !den.is_finite() {
        return None;
    }
    let t = ((b0[0] - a0[0]) * q[1] - (b0[1] - a0[1]) * q[0]) / den;
    Some(add(a0, mul(r, t)))
}

fn angular(d: &Dimension, s: &Style) -> Option<Graphics> {
    use std::f64::consts::{PI, TAU};
    // The two legs, as the rays out of the centre and the feature points
    // along each.
    let (centre, legs, on) = match d.kind {
        DimensionKind::Angular3Point => {
            let c = p(d.point15);
            (
                c,
                [[c, p(d.point13)], [c, p(d.point14)]],
                p(d.definition_point),
            )
        }
        _ => {
            let l1 = [p(d.point13), p(d.point14)];
            let l2 = [p(d.point15), p(d.definition_point)];
            (
                crossing(l1[0], l1[1], l2[0], l2[1])?,
                [l1, l2],
                p(d.point16),
            )
        }
    };
    let radius = len(sub(on, centre));
    if !(radius > 1e-12) {
        return None;
    }
    let theta = (on[1] - centre[1]).atan2(on[0] - centre[0]);
    let (start, sweep) = match d.kind {
        DimensionKind::Angular3Point => {
            let a1 = angle_of(sub(legs[0][1], centre))?;
            let a2 = angle_of(sub(legs[1][1], centre))?;
            let ccw = (a2 - a1).rem_euclid(TAU);
            if (theta - a1).rem_euclid(TAU) <= ccw {
                (a1, ccw)
            } else {
                (a2, TAU - ccw)
            }
        }
        _ => {
            // The sector of the four the two lines make that holds the arc's
            // point.
            let a1 = angle_of(sub(legs[0][1], legs[0][0]))?;
            let a2 = angle_of(sub(legs[1][1], legs[1][0]))?;
            let mut rays = [a1, a1 + PI, a2, a2 + PI].map(|a| a.rem_euclid(TAU));
            rays.sort_by(f64::total_cmp);
            let t = theta.rem_euclid(TAU);
            let i = rays.iter().rposition(|r| *r <= t).unwrap_or(3);
            let (lo, hi) = (rays[i], if i == 3 { rays[0] + TAU } else { rays[i + 1] });
            (lo, hi - lo)
        }
    };
    let mut g = Graphics::default();
    g.arcs.push((centre, radius, start, sweep));
    let e1 = add(centre, mul(polar(start), radius));
    let e2 = add(centre, mul(polar(start + sweep), radius));
    // An extension line from the leg's nearer feature point out to the arc,
    // when the arc lies beyond the leg.
    for (end, ray) in [(e1, polar(start)), (e2, polar(start + sweep))] {
        let leg = legs.iter().find(|l| {
            let dir = sub(l[1], l[0]);
            (dir[0] * ray[1] - dir[1] * ray[0]).abs() < 1e-9 * len(dir)
        });
        if let Some(leg) = leg {
            let ts: Vec<(f64, P)> = leg
                .iter()
                .map(|q| (dot(sub(*q, centre), ray), *q))
                .collect();
            let near = ts
                .iter()
                .min_by(|a, b| (a.0 - radius).abs().total_cmp(&(b.0 - radius).abs()))?;
            let (lo, hi) = (ts[0].0.min(ts[1].0), ts[0].0.max(ts[1].0));
            if radius > hi + 1e-9 || radius < lo - 1e-9 {
                extension(&mut g, near.1, end, s);
            }
        }
    }
    if s.tsz > 0.0 {
        ends(&mut g, e1, e2, s);
    } else {
        let t1 = perp(polar(start));
        let t2 = perp(polar(start + sweep));
        g.arrows.push((e1, add(e1, t1)));
        g.arrows.push((e2, sub(e2, t2)));
    }
    let mid = start + sweep / 2.0;
    let rotation = if d.text_rotation != 0.0 {
        d.text_rotation
    } else {
        readable(mid + PI / 2.0)
    };
    let lift = if s.above { s.gap + s.txt / 2.0 } else { 0.0 };
    let degrees = number(sweep.to_degrees(), s.adec, 0, s.dsep) + "%%d";
    g.label = content(d, degrees).map(|text| Label {
        at: stored_text(d).unwrap_or_else(|| add(centre, mul(polar(mid), radius + lift))),
        text,
        rotation,
    });
    Some(g)
}

fn angle_of(v: P) -> Option<f64> {
    unit(v).map(|u| u[1].atan2(u[0]))
}

fn ordinate(d: &Dimension, s: &Style) -> Option<Graphics> {
    use std::f64::consts::FRAC_PI_2;
    let (origin, feature, end) = (p(d.definition_point), p(d.point13), p(d.point14));
    let x_type = d.flags & 64 != 0;
    let mut g = Graphics::default();
    extension(&mut g, feature, end, s);
    let measured = if x_type {
        feature[0] - origin[0]
    } else {
        feature[1] - origin[1]
    };
    let rotation = if x_type { FRAC_PI_2 } else { 0.0 };
    let dir = unit(sub(end, feature)).unwrap_or(polar(rotation));
    g.label = content(d, number(measured.abs() * s.lfac, s.dec, s.zin, s.dsep)).map(|text| Label {
        at: stored_text(d).unwrap_or_else(|| add(end, mul(dir, s.gap + s.txt))),
        text,
        rotation,
    });
    Some(g)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_follow_the_style() {
        assert_eq!(number(12.5, 4, 0, '.'), "12.5000");
        assert_eq!(number(12.5, 4, 8, '.'), "12.5");
        assert_eq!(number(12.0, 2, 8, ','), "12");
        assert_eq!(number(0.25, 2, 4, ','), ",25");
        assert_eq!(number(-0.0001, 2, 0, '.'), "0.00");
        assert_eq!(number(100.5, 0, 0, '.'), "101");
        assert_eq!(number(2.25, 1, 0, '.'), "2.3");
    }

    #[test]
    fn readable_text_never_runs_upside_down() {
        use std::f64::consts::PI;
        assert!((readable(PI) - 0.0).abs() < 1e-12);
        assert!((readable(-PI / 2.0) - PI / 2.0).abs() < 1e-12);
        assert!((readable(PI / 2.0) - PI / 2.0).abs() < 1e-12);
        assert!((readable(0.3) - 0.3).abs() < 1e-12);
    }
}
