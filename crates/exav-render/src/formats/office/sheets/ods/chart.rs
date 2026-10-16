//! ODF charts (an embedded object's office:chart) to the chart model.

use super::dom::{self, Node};
use crate::formats::office::sheets::model::*;
use std::collections::HashMap;

fn text(n: &Node) -> String {
    let mut s = String::new();
    for (k, p) in n.all("text:p").enumerate() {
        if k > 0 {
            s.push('\n');
        }
        super::text_of(p, &mut s);
    }
    s
}

/// The first range of a cell range address.
fn range(addr: &str) -> Option<(String, Range)> {
    super::parse_range_addr(super::split_ranges(addr).next()?)
}

fn excel_ref(sheet: &str, r: &Range) -> String {
    let q = crate::formats::office::sheets::xls::formula::quote_sheet(sheet);
    let a = |row: u32, col: u32| format!("${}${}", col_name(col), u64::from(row) + 1);
    if r.r1 == r.r2 && r.c1 == r.c2 {
        format!("{q}!{}", a(r.r1, r.c1))
    } else {
        format!("{q}!{}:{}", a(r.r1, r.c1), a(r.r2, r.c2))
    }
}

/// Values of a range, from the workbook or the chart's own table.
struct Data<'a> {
    sheets: &'a [Sheet],
    local: HashMap<(u32, u32), Value>,
}

impl Data<'_> {
    fn cells(&self, sheet: &str, r: &Range) -> Vec<Value> {
        if r.area() > 100_000 {
            return vec![];
        }
        let local = sheet == "local-table";
        let sh = self.sheets.iter().find(|s| s.name == sheet);
        let mut out = vec![];
        for row in r.r1..=r.r2 {
            for col in r.c1..=r.c2 {
                let v = if local {
                    self.local.get(&(row, col)).cloned()
                } else {
                    sh.and_then(|s| s.cells.get(&(row, col)))
                        .map(|c| c.value.clone())
                };
                out.push(v.unwrap_or(Value::Empty));
            }
        }
        out
    }

    fn nums(&self, sheet: &str, r: &Range) -> Vec<Option<f64>> {
        self.cells(sheet, r)
            .into_iter()
            .map(|v| {
                if let Value::Number(n) = v {
                    Some(n)
                } else {
                    None
                }
            })
            .collect()
    }

    fn strs(&self, sheet: &str, r: &Range) -> Vec<String> {
        self.cells(sheet, r)
            .into_iter()
            .map(|v| v.display())
            .collect()
    }
}

fn local_table(doc: &Node) -> HashMap<(u32, u32), Value> {
    let mut out = HashMap::new();
    let Some(t) = doc.find("table:table") else {
        return out;
    };
    let mut rows: Vec<&Node> = vec![];
    fn gather<'a>(n: &'a Node, out: &mut Vec<&'a Node>, depth: u32) {
        for c in n.nodes() {
            match c.name.as_str() {
                "table:table-row" => out.push(c),
                "table:table-header-rows" | "table:table-rows" | "table:table-row-group"
                    if depth < 8 =>
                {
                    gather(c, out, depth + 1)
                }
                _ => {}
            }
        }
    }
    gather(t, &mut rows, 0);
    for (r, row) in rows.iter().enumerate().take(10_000) {
        let mut c = 0u32;
        for cell in row.all("table:table-cell").take(1000) {
            let v = match cell.attr("office:value-type") {
                Some("float" | "percentage" | "currency") => cell
                    .attr("office:value")
                    .and_then(|v| v.parse().ok())
                    .map_or(Value::Empty, Value::Number),
                Some("string") => Value::text(text(cell)),
                _ => Value::Empty,
            };
            out.insert((r as u32, c), v);
            c = c.saturating_add(
                cell.attr("table:number-columns-repeated")
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(1)
                    .min(1000),
            );
        }
    }
    out
}

pub(crate) fn read(xml: &[u8], anchor: Anchor, sheets: &[Sheet]) -> Option<Chart> {
    let doc = dom::parse(xml, 2_000_000).ok()?;
    let ch = doc.find("chart:chart")?;
    let mut styles: HashMap<String, &Node> = HashMap::new();
    if let Some(a) = doc.child("office:automatic-styles") {
        for s in a.all("style:style") {
            if let Some(n) = s.attr("style:name") {
                styles.insert(n.to_string(), s);
            }
        }
    }
    let props = |name: Option<&str>| {
        name.and_then(|n| styles.get(n))
            .and_then(|s| s.child("style:chart-properties"))
    };
    let graphic = |name: Option<&str>| {
        name.and_then(|n| styles.get(n))
            .and_then(|s| s.child("style:graphic-properties"))
    };
    let class = ch.attr("chart:class").unwrap_or("chart:bar");
    let kind_of = |c: &str| match c {
        "chart:line" => ChartKind::Line,
        "chart:area" => ChartKind::Area,
        "chart:circle" => ChartKind::Pie,
        "chart:ring" => ChartKind::Doughnut,
        "chart:scatter" => ChartKind::Scatter,
        "chart:radar" => ChartKind::Radar,
        "chart:filled-radar" => ChartKind::FilledRadar,
        "chart:bubble" => ChartKind::Bubble,
        "chart:stock" => ChartKind::Stock,
        "chart:surface" => ChartKind::Surface,
        _ => ChartKind::Bar,
    };
    let mut kind = kind_of(class);
    let plot = ch.child("chart:plot-area")?;
    let pp = props(plot.attr("chart:style-name"));
    let flag = |k: &str| pp.and_then(|p| p.attr(k)) == Some("true");
    let three_d = flag("chart:three-dimensional");
    if kind == ChartKind::Doughnut && three_d {
        kind = ChartKind::Pie;
    }
    let mut c = Chart::new(anchor, kind);
    c.horizontal = flag("chart:vertical");
    c.grouping = if flag("chart:percentage") {
        "percentStacked"
    } else if flag("chart:stacked") {
        "stacked"
    } else if kind == ChartKind::Bar {
        "clustered"
    } else {
        "standard"
    };
    c.three_d = three_d;
    if let Some(gw) = pp
        .and_then(|p| p.attr("chart:gap-width"))
        .and_then(|v| v.parse::<i64>().ok())
    {
        c.gap_width = Some(gw.clamp(0, 500) as u32);
    }
    if let Some(ov) = pp
        .and_then(|p| p.attr("chart:overlap"))
        .and_then(|v| v.parse::<i64>().ok())
    {
        c.overlap = Some(ov.clamp(-100, 100) as i32);
    }
    c.title = ch.child("chart:title").map(text).filter(|t| !t.is_empty());
    c.legend =
        ch.child("chart:legend")
            .map(|l| match l.attr("chart:legend-position").unwrap_or("end") {
                "start" => "l",
                "top" => "t",
                "bottom" => "b",
                "top-end" => "tr",
                _ => "r",
            });
    let data = Data {
        sheets,
        local: local_table(&doc),
    };
    let mut cat_range = None;
    for ax in plot.all("chart:axis") {
        let t = ax.child("chart:title").map(text).filter(|t| !t.is_empty());
        match ax.attr("chart:dimension") {
            Some("x") if ax.attr("chart:name").is_none_or(|n| n == "primary-x") => {
                c.cat_title = t;
                cat_range = ax
                    .child("chart:categories")
                    .and_then(|k| k.attr("table:cell-range-address"))
                    .and_then(range);
            }
            Some("y") if ax.attr("chart:name").is_none_or(|n| n == "primary-y") => {
                c.val_title = t;
                c.major_grid = ax.child("chart:grid").is_some();
            }
            _ => {}
        }
    }
    for s in plot.all("chart:series").take(256) {
        let mut cs = ChartSeries {
            line: true,
            ..Default::default()
        };
        // A series drawn otherwise than the chart: the bars and lines of a
        // combined chart (a ring's series say they are circles).
        let combinable =
            |k: ChartKind| matches!(k, ChartKind::Bar | ChartKind::Line | ChartKind::Area);
        let skind = s
            .attr("chart:class")
            .map(kind_of)
            .filter(|k| *k != kind && combinable(*k) && combinable(kind));
        let this_kind = skind.unwrap_or(kind);
        cs.kind = skind;
        cs.secondary = s
            .attr("chart:attached-axis")
            .is_some_and(|a| a.contains("secondary"));
        if let Some((sh, r)) = s.attr("chart:values-cell-range-address").and_then(range) {
            cs.vals = data.nums(&sh, &r);
            if sh != "local-table" {
                cs.val_ref = Some(excel_ref(&sh, &r));
            }
        }
        if let Some((sh, r)) = s.attr("chart:label-cell-address").and_then(range) {
            cs.name = data.strs(&sh, &r).into_iter().next();
            if sh != "local-table" {
                cs.name_ref = Some(excel_ref(&sh, &r));
            }
        }
        let domains: Vec<(String, Range)> = s
            .all("chart:domain")
            .filter_map(|d| d.attr("table:cell-range-address"))
            .filter_map(range)
            .collect();
        if matches!(this_kind, ChartKind::Scatter | ChartKind::Bubble) {
            // A bubble series' values are its sizes, its first domain its y
            // values and its second its x values; a scatter series' first
            // domain is its x values.
            let xs = if this_kind == ChartKind::Bubble {
                domains.get(1).or(domains.first())
            } else {
                domains.first()
            };
            if let Some((sh, r)) = xs.cloned().or(cat_range.clone()) {
                cs.cat_nums = Some(data.nums(&sh, &r));
                if sh != "local-table" {
                    cs.cat_ref = Some(excel_ref(&sh, &r));
                }
            }
            if this_kind == ChartKind::Bubble {
                if let Some((sh, r)) = domains.first() {
                    cs.sizes = std::mem::take(&mut cs.vals);
                    cs.size_ref = cs.val_ref.take();
                    cs.vals = data.nums(sh, r);
                    if sh != "local-table" {
                        cs.val_ref = Some(excel_ref(sh, r));
                    }
                }
            }
        } else if let Some((sh, r)) = &cat_range {
            cs.cats = data.strs(sh, r);
            if sh != "local-table" {
                cs.cat_ref = Some(excel_ref(sh, r));
            }
        }
        let sp = props(s.attr("chart:style-name"));
        if let Some(g) = graphic(s.attr("chart:style-name")) {
            let lined = matches!(
                this_kind,
                ChartKind::Line | ChartKind::Scatter | ChartKind::Radar
            );
            let key = if lined {
                "svg:stroke-color"
            } else {
                "draw:fill-color"
            };
            cs.color = g
                .attr(key)
                .and_then(|v| super::styles::parse_color(v).flatten());
            if lined && g.attr("draw:stroke") == Some("none") {
                cs.line = false;
            }
        }
        if let Some(sp) = sp {
            cs.marker = sp.attr("chart:symbol-type").is_some_and(|t| t != "none");
            cs.smooth = sp.attr("chart:interpolation").is_some_and(|i| i != "none");
        }
        // Points with their own colour (a pie's slices).
        let mut idx = 0u32;
        for p in s.all("chart:data-point").take(4096) {
            let n = p
                .attr("chart:repeated")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(1)
                .clamp(1, 4096);
            if let Some(col) = graphic(p.attr("chart:style-name"))
                .and_then(|g| g.attr("draw:fill-color"))
                .and_then(|v| super::styles::parse_color(v).flatten())
            {
                for k in 0..n {
                    cs.point_colors.push((idx + k, col));
                }
            }
            idx = idx.saturating_add(n);
        }
        c.series.push(cs);
    }
    Some(c)
}
