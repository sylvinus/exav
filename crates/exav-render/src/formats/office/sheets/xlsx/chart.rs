//! Charts of the model to DrawingML chart parts (ECMA-376 part 1, 21.2).

use super::xml::{esc, rgb};
use crate::formats::office::sheets::model::{Chart, ChartKind, ChartSeries};
use crate::formats::office::sheets::numtext;
use std::fmt::Write as _;

fn rich(text: &str) -> String {
    let paras: String = text
        .split('\n')
        .map(|p| format!("<a:p><a:r><a:t>{}</a:t></a:r></a:p>", esc(p)))
        .collect();
    format!("<c:tx><c:rich><a:bodyPr/><a:lstStyle/>{paras}</c:rich></c:tx><c:overlay val=\"0\"/>")
}

fn str_cache(f: &Option<String>, vals: &[String]) -> String {
    let mut s = format!("<c:ptCount val=\"{}\"/>", vals.len());
    for (i, v) in vals.iter().enumerate() {
        let _ = write!(s, "<c:pt idx=\"{i}\"><c:v>{}</c:v></c:pt>", esc(v));
    }
    match f {
        Some(f) => format!(
            "<c:strRef><c:f>{}</c:f><c:strCache>{s}</c:strCache></c:strRef>",
            esc(f)
        ),
        None => format!("<c:strLit>{s}</c:strLit>"),
    }
}

fn num_cache(f: &Option<String>, vals: &[Option<f64>]) -> String {
    let mut s = String::from("<c:formatCode>General</c:formatCode>");
    let _ = write!(s, "<c:ptCount val=\"{}\"/>", vals.len());
    for (i, v) in vals.iter().enumerate() {
        if let Some(v) = v {
            let _ = write!(
                s,
                "<c:pt idx=\"{i}\"><c:v>{}</c:v></c:pt>",
                numtext::xml(*v)
            );
        }
    }
    match f {
        Some(f) => format!(
            "<c:numRef><c:f>{}</c:f><c:numCache>{s}</c:numCache></c:numRef>",
            esc(f)
        ),
        None => format!("<c:numLit>{s}</c:numLit>"),
    }
}

fn solid(c: u32) -> String {
    format!("<a:solidFill><a:srgbClr val=\"{}\"/></a:solidFill>", rgb(c))
}

fn lined(kind: ChartKind) -> bool {
    matches!(
        kind,
        ChartKind::Line | ChartKind::Scatter | ChartKind::Radar | ChartKind::Stock
    )
}

fn series(k: usize, s: &ChartSeries, kind: ChartKind) -> String {
    let mut x = format!("<c:ser><c:idx val=\"{k}\"/><c:order val=\"{k}\"/>");
    if s.name.is_some() || s.name_ref.is_some() {
        let _ = write!(
            x,
            "<c:tx>{}</c:tx>",
            str_cache(&s.name_ref, &[s.name.clone().unwrap_or_default()])
        );
    }
    if lined(kind) {
        let ln = match (s.line, s.color) {
            (false, _) => "<a:ln><a:noFill/></a:ln>".to_string(),
            (true, Some(c)) => format!("<a:ln w=\"28575\">{}</a:ln>", solid(c)),
            (true, None) => String::new(),
        };
        if !ln.is_empty() {
            let _ = write!(x, "<c:spPr>{ln}</c:spPr>");
        }
        if s.marker {
            match s.color {
                Some(c) => {
                    let _ = write!(
                        x,
                        "<c:marker><c:symbol val=\"circle\"/><c:size val=\"5\"/><c:spPr>{}</c:spPr></c:marker>",
                        solid(c)
                    );
                }
                None => {
                    x.push_str("<c:marker><c:symbol val=\"circle\"/><c:size val=\"5\"/></c:marker>")
                }
            }
        } else {
            x.push_str("<c:marker><c:symbol val=\"none\"/></c:marker>");
        }
    } else if let Some(c) = s.color {
        let _ = write!(x, "<c:spPr>{}</c:spPr>", solid(c));
    }
    for (i, c) in &s.point_colors {
        let _ = write!(
            x,
            "<c:dPt><c:idx val=\"{i}\"/><c:bubble3D val=\"0\"/><c:spPr>{}</c:spPr></c:dPt>",
            solid(*c)
        );
    }
    let cats = |tag: &str| -> String {
        match &s.cat_nums {
            Some(n) => format!("<c:{tag}>{}</c:{tag}>", num_cache(&s.cat_ref, n)),
            None if !s.cats.is_empty() || s.cat_ref.is_some() => {
                format!("<c:{tag}>{}</c:{tag}>", str_cache(&s.cat_ref, &s.cats))
            }
            None => String::new(),
        }
    };
    if matches!(kind, ChartKind::Scatter | ChartKind::Bubble) {
        x += &cats("xVal");
        let _ = write!(x, "<c:yVal>{}</c:yVal>", num_cache(&s.val_ref, &s.vals));
        if kind == ChartKind::Bubble {
            let sizes = if s.sizes.is_empty() {
                vec![Some(1.0); s.vals.len()]
            } else {
                s.sizes.clone()
            };
            let _ = write!(
                x,
                "<c:bubbleSize>{}</c:bubbleSize><c:bubble3D val=\"0\"/>",
                num_cache(&s.size_ref, &sizes)
            );
        } else {
            let _ = write!(x, "<c:smooth val=\"{}\"/>", u8::from(s.smooth));
        }
    } else {
        x += &cats("cat");
        let _ = write!(x, "<c:val>{}</c:val>", num_cache(&s.val_ref, &s.vals));
        if kind == ChartKind::Line {
            let _ = write!(x, "<c:smooth val=\"{}\"/>", u8::from(s.smooth));
        }
    }
    x.push_str("</c:ser>");
    x
}

struct AxisIds {
    cat: u32,
    val: u32,
}

fn axes(chart: &Chart, ids: &AxisIds, two_values: bool, secondary: bool) -> String {
    let title = |t: &Option<String>| {
        if secondary {
            String::new()
        } else {
            t.as_ref()
                .map(|t| format!("<c:title>{}</c:title>", rich(t)))
                .unwrap_or_default()
        }
    };
    let (mut cat_pos, mut val_pos) = if chart.horizontal {
        ("l", "b")
    } else {
        ("b", "l")
    };
    if secondary {
        (cat_pos, val_pos) = if chart.horizontal {
            ("r", "t")
        } else {
            ("t", "r")
        };
    }
    let first = if two_values { "valAx" } else { "catAx" };
    let cat_del = u8::from(chart.cat_axis_deleted || secondary);
    let val_del = u8::from(chart.val_axis_deleted);
    let grid = if chart.major_grid && !secondary {
        "<c:majorGridlines/>"
    } else {
        ""
    };
    let crosses = if secondary {
        "<c:crosses val=\"max\"/>"
    } else {
        "<c:crosses val=\"autoZero\"/>"
    };
    format!(
        "<c:{first}><c:axId val=\"{c}\"/><c:scaling><c:orientation val=\"minMax\"/></c:scaling><c:delete val=\"{cat_del}\"/><c:axPos val=\"{cat_pos}\"/>{}<c:numFmt formatCode=\"General\" sourceLinked=\"1\"/><c:majorTickMark val=\"out\"/><c:minorTickMark val=\"none\"/><c:tickLblPos val=\"nextTo\"/><c:crossAx val=\"{v}\"/><c:crosses val=\"autoZero\"/></c:{first}>\
         <c:valAx><c:axId val=\"{v}\"/><c:scaling><c:orientation val=\"minMax\"/></c:scaling><c:delete val=\"{val_del}\"/><c:axPos val=\"{val_pos}\"/>{grid}{}<c:numFmt formatCode=\"General\" sourceLinked=\"1\"/><c:majorTickMark val=\"out\"/><c:minorTickMark val=\"none\"/><c:tickLblPos val=\"nextTo\"/><c:crossAx val=\"{c}\"/>{crosses}<c:crossBetween val=\"between\"/></c:valAx>",
        title(&chart.cat_title),
        title(&chart.val_title),
        c = ids.cat,
        v = ids.val,
    )
}

/// One chart group (`c:barChart`, `c:lineChart`...) of `sers`.
fn group(chart: &Chart, kind: ChartKind, sers: &str, ids: &AxisIds) -> (String, bool) {
    let d3 = chart.three_d;
    let ax = format!("<c:axId val=\"{}\"/><c:axId val=\"{}\"/>", ids.cat, ids.val);
    let vary = u8::from(chart.vary_colors);
    match kind {
        ChartKind::Pie => {
            let tag = if d3 { "pie3DChart" } else { "pieChart" };
            let slice = if d3 {
                String::new()
            } else {
                format!(
                    "<c:firstSliceAng val=\"{}\"/>",
                    chart.first_slice.unwrap_or(0).min(360)
                )
            };
            (
                format!("<c:{tag}><c:varyColors val=\"{vary}\"/>{sers}{slice}</c:{tag}>"),
                false,
            )
        }
        ChartKind::Doughnut => (
            format!(
                "<c:doughnutChart><c:varyColors val=\"{vary}\"/>{sers}<c:firstSliceAng val=\"{}\"/><c:holeSize val=\"{}\"/></c:doughnutChart>",
                chart.first_slice.unwrap_or(0).min(360),
                chart.hole_size.unwrap_or(50).clamp(10, 90)
            ),
            false,
        ),
        ChartKind::Scatter => (
            format!(
                "<c:scatterChart><c:scatterStyle val=\"lineMarker\"/><c:varyColors val=\"{vary}\"/>{sers}{ax}</c:scatterChart>"
            ),
            true,
        ),
        ChartKind::Bubble => (
            format!("<c:bubbleChart><c:varyColors val=\"{vary}\"/>{sers}{ax}</c:bubbleChart>"),
            true,
        ),
        ChartKind::Radar | ChartKind::FilledRadar => {
            let style = if kind == ChartKind::FilledRadar {
                "filled"
            } else {
                "marker"
            };
            (
                format!(
                    "<c:radarChart><c:radarStyle val=\"{style}\"/><c:varyColors val=\"{vary}\"/>{sers}{ax}</c:radarChart>"
                ),
                false,
            )
        }
        ChartKind::Surface => (
            format!(
                "<c:surfaceChart><c:wireframe val=\"0\"/>{sers}{ax}<c:axId val=\"{}\"/></c:surfaceChart>",
                ids.val + 1
            ),
            false,
        ),
        ChartKind::Stock => (
            format!("<c:stockChart>{sers}<c:hiLowLines/>{ax}</c:stockChart>"),
            false,
        ),
        ChartKind::Line | ChartKind::Area => {
            let base = if kind == ChartKind::Area {
                "area"
            } else {
                "line"
            };
            let tag = format!("{base}{}Chart", if d3 { "3D" } else { "" });
            let grouping = if chart.grouping == "clustered" {
                "standard"
            } else {
                chart.grouping
            };
            let extra = if base == "line" && !d3 {
                "<c:marker val=\"1\"/>"
            } else {
                ""
            };
            (
                format!(
                    "<c:{tag}><c:grouping val=\"{grouping}\"/><c:varyColors val=\"{vary}\"/>{sers}{extra}{ax}</c:{tag}>"
                ),
                false,
            )
        }
        ChartKind::Bar => {
            let tag = if d3 { "bar3DChart" } else { "barChart" };
            let grouping = if chart.grouping == "standard" {
                "clustered"
            } else {
                chart.grouping
            };
            let overlap = match chart.overlap {
                Some(o) => format!("<c:overlap val=\"{}\"/>", o.clamp(-100, 100)),
                None if grouping == "stacked" || grouping == "percentStacked" => {
                    "<c:overlap val=\"100\"/>".into()
                }
                None => String::new(),
            };
            (
                format!(
                    "<c:{tag}><c:barDir val=\"{}\"/><c:grouping val=\"{grouping}\"/><c:varyColors val=\"{vary}\"/>{sers}<c:gapWidth val=\"{}\"/>{overlap}{ax}</c:{tag}>",
                    if chart.horizontal { "bar" } else { "col" },
                    chart.gap_width.unwrap_or(150).min(500)
                ),
                false,
            )
        }
    }
}

pub fn chart_xml(chart: &Chart) -> String {
    let mut x = String::from(concat!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#,
        "\n",
        r#"<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><c:roundedCorners val="0"/><c:chart>"#
    ));
    match &chart.title {
        Some(t) => {
            let _ = write!(
                x,
                "<c:title>{}</c:title><c:autoTitleDeleted val=\"0\"/>",
                rich(t)
            );
        }
        None => x.push_str("<c:autoTitleDeleted val=\"1\"/>"),
    }
    if chart.three_d {
        x.push_str(
            "<c:view3D><c:rotX val=\"15\"/><c:rotY val=\"20\"/><c:rAngAx val=\"1\"/></c:view3D>",
        );
    }
    x.push_str("<c:plotArea><c:layout/>");
    // Series grouped by the kind they are drawn as and their axis, in order
    // of first appearance.
    let mut groups: Vec<((ChartKind, bool), Vec<usize>)> = vec![];
    for (i, s) in chart.series.iter().enumerate() {
        let k = (s.kind.unwrap_or(chart.kind), s.secondary);
        match groups.iter_mut().find(|g| g.0 == k) {
            Some(g) => g.1.push(i),
            None => groups.push((k, vec![i])),
        }
    }
    if groups.is_empty() {
        groups.push(((chart.kind, false), vec![]));
    }
    let mut axes_xml = String::new();
    let mut have_primary = false;
    let mut have_secondary = false;
    for ((kind, secondary), idx) in &groups {
        let sers: String = idx
            .iter()
            .map(|&i| series(i, &chart.series[i], *kind))
            .collect();
        let ids = if *secondary {
            AxisIds { cat: 3, val: 4 }
        } else {
            AxisIds { cat: 1, val: 2 }
        };
        let (g, two_values) = group(chart, *kind, &sers, &ids);
        x.push_str(&g);
        if matches!(kind, ChartKind::Pie | ChartKind::Doughnut) {
            continue;
        }
        if *secondary && !have_secondary {
            have_secondary = true;
            axes_xml.push_str(&axes(chart, &ids, two_values, true));
        } else if !*secondary && !have_primary {
            have_primary = true;
            axes_xml.push_str(&axes(chart, &ids, two_values, false));
            if *kind == ChartKind::Surface {
                axes_xml.push_str("<c:serAx><c:axId val=\"3\"/><c:scaling><c:orientation val=\"minMax\"/></c:scaling><c:delete val=\"0\"/><c:axPos val=\"b\"/><c:tickLblPos val=\"nextTo\"/><c:crossAx val=\"2\"/></c:serAx>");
            }
        }
    }
    x.push_str(&axes_xml);
    if let Some(c) = chart.plot_fill {
        let _ = write!(x, "<c:spPr>{}</c:spPr>", solid(c));
    }
    x.push_str("</c:plotArea>");
    if let Some(pos) = chart.legend {
        let _ = write!(
            x,
            "<c:legend><c:legendPos val=\"{pos}\"/><c:overlay val=\"0\"/></c:legend>"
        );
    }
    x.push_str("<c:plotVisOnly val=\"1\"/><c:dispBlanksAs val=\"gap\"/></c:chart>");
    if let Some(c) = chart.area_fill {
        let _ = write!(x, "<c:spPr>{}</c:spPr>", solid(c));
    }
    x.push_str("</c:chartSpace>");
    x
}
