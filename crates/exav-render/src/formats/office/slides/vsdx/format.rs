//! Fill and line properties ([MS-VSDX] 2.2.7.1 and 2.2.7.2) as the model's
//! fills and lines.

use super::resolve::Tree;
use crate::formats::office::slides::model::{Arrow, Color, Fill, Gradient, GradientKind, Line};

const EMU_PER_INCH: f64 = 914_400.0;

/// A colour cell with its transparency cell (0 opaque to 1 transparent).
fn color(t: &Tree, n: usize, cell: &str, trans: &str) -> Color {
    let rgb = t.color(n, cell).unwrap_or(0);
    let tr = t.num(n, trans).unwrap_or(0.0).clamp(0.0, 1.0);
    Color {
        rgb,
        alpha: (tr > 0.0).then(|| ((1.0 - tr) * 100_000.0).round() as u32),
    }
}

/// A pattern cell: 0 without the cell, solid (1) for a themed one that
/// nothing resolves.
fn pattern(t: &Tree, n: usize, cell: &str) -> i64 {
    match t.val(n, cell) {
        Some(v) => v.num().map_or(1, |p| p as i64),
        None if t.find(n, cell).is_some() => 1,
        None => 0,
    }
}

/// The fill of shape `n`.
pub fn fill(t: &Tree, n: usize) -> Fill {
    // A pattern the cell does not give as a number (a themed one) is solid.
    let pattern = pattern(t, n, "FillPattern");
    if pattern == 0 {
        return Fill::None;
    }
    let fg = color(t, n, "FillForegnd", "FillForegndTrans");
    let bg = color(t, n, "FillBkgnd", "FillBkgndTrans");
    if t.num(n, "FillGradientEnabled") == Some(1.0)
        && let Some(g) = gradient(t, n)
    {
        return Fill::Gradient(g);
    }
    match pattern {
        1 => Fill::Solid(fg),
        2..=24 => Fill::Pattern {
            preset: PATTERNS[(pattern - 2) as usize],
            fg,
            bg,
        },
        25..=40 => Fill::Gradient(old_gradient(pattern, fg, bg)),
        _ => Fill::Solid(fg),
    }
}

/// The hatches 2 to 24, as the closest presets.
const PATTERNS: [&str; 23] = [
    "ltUpDiag",
    "smGrid",
    "diagCross",
    "ltDnDiag",
    "horz",
    "vert",
    "pct75",
    "pct50",
    "pct25",
    "pct10",
    "pct5",
    "dkHorz",
    "dkVert",
    "dkDnDiag",
    "dkUpDiag",
    "pct60",
    "pct90",
    "ltHorz",
    "ltVert",
    "dkDnDiag",
    "ltUpDiag",
    "smGrid",
    "smCheck",
];

/// The gradient patterns 25 to 40, blending the foreground into the
/// background: close, not exact.
fn old_gradient(pattern: i64, fg: Color, bg: Color) -> Gradient {
    let two = |a: Color, b: Color| vec![(0, a), (100_000, b)];
    let three = |a: Color, b: Color| vec![(0, a), (50_000, b), (100_000, a)];
    let (stops, kind) = match pattern {
        25 => (two(fg, bg), GradientKind::Linear(0.0)),
        26 => (three(bg, fg), GradientKind::Linear(0.0)),
        27 => (two(bg, fg), GradientKind::Linear(0.0)),
        28 => (two(fg, bg), GradientKind::Linear(90.0)),
        29 => (three(bg, fg), GradientKind::Linear(90.0)),
        30 => (two(bg, fg), GradientKind::Linear(90.0)),
        31 => (two(fg, bg), GradientKind::Linear(20.0)),
        32 => (two(bg, fg), GradientKind::Linear(340.0)),
        33 => (two(fg, bg), GradientKind::Linear(70.0)),
        34 => (two(bg, fg), GradientKind::Linear(110.0)),
        35 => (two(fg, bg), GradientKind::Path("rect", [50_000; 4])),
        36 => (
            two(fg, bg),
            GradientKind::Path("circle", [0, 0, 100_000, 100_000]),
        ),
        37 => (
            two(fg, bg),
            GradientKind::Path("circle", [100_000, 0, 0, 100_000]),
        ),
        38 => (
            two(fg, bg),
            GradientKind::Path("circle", [0, 100_000, 100_000, 0]),
        ),
        39 => (
            two(fg, bg),
            GradientKind::Path("circle", [100_000, 100_000, 0, 0]),
        ),
        _ => (two(fg, bg), GradientKind::Path("circle", [50_000; 4])),
    };
    Gradient { stops, kind }
}

/// The gradient of the FillGradient section and the direction cells.
fn gradient(t: &Tree, n: usize) -> Option<Gradient> {
    let mut stops: Vec<(u32, Color)> = vec![];
    for (key, _) in t.rows(n, "FillGradient", None) {
        let rgb = t
            .row_val(n, "FillGradient", None, &key, "GradientStopColor")
            .and_then(|v| t.to_color(&v))?;
        let tr = t
            .row_num(n, "FillGradient", None, &key, "GradientStopColorTrans")
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
        let pos = t
            .row_num(n, "FillGradient", None, &key, "GradientStopPosition")
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
        stops.push((
            (pos * 100_000.0).round() as u32,
            Color {
                rgb,
                alpha: (tr > 0.0).then(|| ((1.0 - tr) * 100_000.0).round() as u32),
            },
        ));
        if stops.len() >= 64 {
            break;
        }
    }
    if stops.len() < 2 {
        return None;
    }
    stops.sort_by_key(|s| s.0);
    let dir = t.num(n, "FillGradientDir").unwrap_or(0.0) as i64;
    let kind = match dir {
        0 => {
            let a = t.num(n, "FillGradientAngle").unwrap_or(0.0).to_degrees();
            // Counterclockwise from the x axis to clockwise on the screen.
            GradientKind::Linear((-a).rem_euclid(360.0))
        }
        1..=7 => GradientKind::Path("circle", origin(dir)),
        8..=12 => GradientKind::Path("rect", origin(dir)),
        _ => GradientKind::Path("shape", [50_000; 4]),
    };
    Some(Gradient { stops, kind })
}

/// Where a radial or rectangular gradient starts, as the focus rectangle of
/// a path gradient (left, top, right, bottom in 1/100000 of the shape).
fn origin(dir: i64) -> [i32; 4] {
    match dir {
        1 | 8 => [100_000, 100_000, 0, 0],
        2 | 9 => [0, 100_000, 100_000, 0],
        4 => [50_000, 100_000, 50_000, 0],
        5 => [50_000, 0, 50_000, 100_000],
        6 | 11 => [100_000, 0, 0, 100_000],
        7 | 12 => [0, 0, 100_000, 100_000],
        _ => [50_000; 4],
    }
}

/// The line of shape `n`; no fill for a transparent line.
pub fn line(t: &Tree, n: usize) -> Line {
    let pattern = pattern(t, n, "LinePattern");
    if pattern == 0 {
        return Line::default();
    }
    let weight = t.num(n, "LineWeight").unwrap_or(0.0).clamp(0.0, 100.0);
    // A weight of zero is the thinnest line there is.
    let width = if weight == 0.0 {
        6350
    } else {
        (weight * EMU_PER_INCH).round().max(1.0) as i64
    };
    let arrow = |cell: &str, size: &str| {
        let kind = t.num(n, cell).map_or(0, |v| v as i64);
        let kind = *ARROWS.get(usize::try_from(kind).ok()?)?;
        let size = match t.num(n, size).map_or(2, |v| v as i64) {
            ..=1 => "sm",
            2 => "med",
            _ => "lg",
        };
        (!kind.is_empty()).then_some(Arrow {
            kind,
            w: size,
            len: size,
        })
    };
    Line {
        fill: Fill::Solid(color(t, n, "LineColor", "LineColorTrans")),
        width,
        dash: dash(pattern),
        cap: match t.num(n, "LineCap").map(|c| c as i64) {
            Some(0) => Some("rnd"),
            Some(2) => Some("sq"),
            _ => None,
        },
        join: None,
        compound: None,
        head: arrow("BeginArrow", "BeginArrowSize"),
        tail: arrow("EndArrow", "EndArrowSize"),
    }
}

/// The dash preset closest to a line pattern; `None` is solid.
fn dash(p: i64) -> Option<&'static str> {
    Some(match p {
        2 | 8 => "dash",
        3 | 10 | 17 => "sysDot",
        4 | 6 | 11 | 18 => "dashDot",
        5 | 12 | 15 | 19 | 20 => "lgDashDotDot",
        7 | 14 | 16 | 21 | 22 => "lgDash",
        9 | 23 => "sysDash",
        13 => "sysDashDot",
        _ => return None,
    })
}

/// The line ends 1 to 45 as the closest of the model's ends; none for the
/// ones without one (bars and slashes).
const ARROWS: [&str; 46] = [
    "", "arrow", "stealth", "arrow", "triangle", "triangle", "triangle", "arrow", "stealth", "",
    "oval", "diamond", "arrow", "stealth", "triangle", "triangle", "triangle", "triangle",
    "triangle", "stealth", "oval", "diamond", "diamond", "", "", "", "", "arrow", "arrow", "oval",
    "oval", "oval", "oval", "oval", "diamond", "oval", "oval", "oval", "diamond", "triangle",
    "triangle", "oval", "oval", "arrow", "arrow", "arrow",
];

/// Whether shape `n` has effects that are not drawn: shadow, glow, bevel,
/// reflection or soft edges.
pub fn has_effects(t: &Tree, n: usize) -> bool {
    let on = |c: &str| t.num(n, c).is_some_and(|v| v > 0.0);
    on("ShapeShdwType")
        || on("GlowSize")
        || on("BevelTopType")
        || on("ReflectionSize")
        || on("SoftEdgesSize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::slides::limits::{Budget, Limits};
    use crate::formats::office::slides::vsdx::resolve::{Doc, Master, tests::shapes};
    use std::collections::HashMap;

    fn with<R>(styles: &str, shape: &str, f: impl Fn(&Tree, usize) -> R) -> R {
        let mut d = Doc::default();
        d.colors.insert(30, 0x112233);
        for s in shapes(&format!("<S>{styles}</S>")) {
            d.styles.insert(s.id, s);
        }
        let page = shapes(&format!("<S>{shape}</S>"));
        let m: HashMap<u32, Master> = HashMap::new();
        let t = Tree::build(&d, &m, &page, &mut Budget::new(Limits::default())).unwrap();
        f(&t, t.roots[0])
    }

    #[test]
    fn solid_fills_take_the_colour_and_transparency() {
        let f = with(
            "",
            "<Shape ID='1'><Cell N='FillPattern' V='1'/><Cell N='FillForegnd' V='#ff0000'/><Cell N='FillForegndTrans' V='0.25'/></Shape>",
            fill,
        );
        assert_eq!(
            f,
            Fill::Solid(Color {
                rgb: 0xFF0000,
                alpha: Some(75_000)
            })
        );
        // The colour table, and a pattern of 0.
        let f = with(
            "",
            "<Shape ID='1'><Cell N='FillPattern' V='1'/><Cell N='FillForegnd' V='30'/></Shape>",
            fill,
        );
        assert_eq!(f, Fill::Solid(Color::rgb(0x112233)));
        assert_eq!(
            with(
                "",
                "<Shape ID='1'><Cell N='FillPattern' V='0'/></Shape>",
                fill
            ),
            Fill::None
        );
        // Without a pattern cell there is no fill, and a themed one is solid.
        assert_eq!(with("", "<Shape ID='1'/>", fill), Fill::None);
        assert_eq!(
            with(
                "",
                "<Shape ID='1'><Cell N='FillPattern' V='Themed'/><Cell N='FillForegnd' V='2'/></Shape>",
                fill
            ),
            Fill::Solid(Color::rgb(0xFF0000))
        );
    }

    #[test]
    fn a_style_gives_what_the_shape_leaves_out() {
        let f = with(
            "<Shape ID='3'><Cell N='FillPattern' V='1'/><Cell N='FillForegnd' V='#00ff00'/></Shape>",
            "<Shape ID='1' FillStyle='3'><Cell N='FillForegnd' V='#0000ff'/></Shape>",
            fill,
        );
        assert_eq!(f, Fill::Solid(Color::rgb(0x0000FF)));
    }

    #[test]
    fn hatches_and_old_gradients() {
        let f = with(
            "",
            "<Shape ID='1'><Cell N='FillPattern' V='9'/><Cell N='FillForegnd' V='#000000'/><Cell N='FillBkgnd' V='#ffffff'/></Shape>",
            fill,
        );
        assert!(
            matches!(
                f,
                Fill::Pattern {
                    preset: "pct50",
                    ..
                }
            ),
            "{f:?}"
        );
        let f = with(
            "",
            "<Shape ID='1'><Cell N='FillPattern' V='27'/><Cell N='FillForegnd' V='#000000'/><Cell N='FillBkgnd' V='#ffffff'/></Shape>",
            fill,
        );
        let Fill::Gradient(g) = f else { panic!() };
        assert_eq!(g.stops[0].1.rgb, 0xFFFFFF);
        assert_eq!(g.stops[1].1.rgb, 0x000000);
    }

    #[test]
    fn a_gradient_of_stops_and_its_direction() {
        let shape = |dir: &str| {
            format!(
                "<Shape ID='1'><Cell N='FillPattern' V='1'/><Cell N='FillGradientEnabled' V='1'/>
                 <Cell N='FillGradientDir' V='{dir}'/><Cell N='FillGradientAngle' V='1.5707963267948966'/>
                 <Section N='FillGradient'>
                  <Row IX='1'><Cell N='GradientStopColor' V='#ff0000'/><Cell N='GradientStopColorTrans' V='0'/><Cell N='GradientStopPosition' V='1'/></Row>
                  <Row IX='0'><Cell N='GradientStopColor' V='#0000ff'/><Cell N='GradientStopColorTrans' V='0.5'/><Cell N='GradientStopPosition' V='0'/></Row>
                 </Section></Shape>"
            )
        };
        let Fill::Gradient(g) = with("", &shape("0"), fill) else {
            panic!()
        };
        // Stops by position; a quarter turn counterclockwise is three
        // quarters clockwise.
        assert_eq!(g.stops[0].0, 0);
        assert_eq!(g.stops[0].1.alpha, Some(50_000));
        assert_eq!(g.stops[1].1.rgb, 0xFF0000);
        assert_eq!(g.kind, GradientKind::Linear(270.0));
        let Fill::Gradient(g) = with("", &shape("3"), fill) else {
            panic!()
        };
        assert_eq!(g.kind, GradientKind::Path("circle", [50_000; 4]));
        let Fill::Gradient(g) = with("", &shape("12"), fill) else {
            panic!()
        };
        assert_eq!(g.kind, GradientKind::Path("rect", [0, 0, 100_000, 100_000]));
    }

    #[test]
    fn lines_have_weight_colour_dashes_and_ends() {
        let l = with(
            "",
            "<Shape ID='1'><Cell N='LinePattern' V='2'/><Cell N='LineWeight' V='0.0208333333'/><Cell N='LineColor' V='#102030'/>
             <Cell N='EndArrow' V='4'/><Cell N='EndArrowSize' V='3'/><Cell N='BeginArrow' V='10'/><Cell N='BeginArrowSize' V='0'/><Cell N='LineCap' V='0'/></Shape>",
            line,
        );
        assert_eq!(l.fill, Fill::Solid(Color::rgb(0x102030)));
        assert_eq!(l.width, 19_050);
        assert_eq!(l.dash, Some("dash"));
        assert_eq!(l.cap, Some("rnd"));
        let tail = l.tail.unwrap();
        assert_eq!((tail.kind, tail.w), ("triangle", "lg"));
        let head = l.head.unwrap();
        assert_eq!((head.kind, head.w), ("oval", "sm"));
        // No pattern, no line; weight 0 is thin; unknown ends are none.
        assert_eq!(with("", "<Shape ID='1'/>", line), Line::default());
        let l = with(
            "",
            "<Shape ID='1'><Cell N='LinePattern' V='1'/><Cell N='LineWeight' V='0'/><Cell N='EndArrow' V='99'/><Cell N='BeginArrow' V='24'/></Shape>",
            line,
        );
        assert_eq!((l.width, l.dash, l.tail, l.head), (6350, None, None, None));
    }

    #[test]
    fn effects_are_noticed() {
        assert!(with(
            "",
            "<Shape ID='1'><Cell N='ShapeShdwType' V='1'/></Shape>",
            has_effects
        ));
        assert!(!with(
            "",
            "<Shape ID='1'><Cell N='ShapeShdwType' V='0'/></Shape>",
            has_effects
        ));
    }
}
