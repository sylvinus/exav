//! Drawings of a table: pictures, charts (embedded objects), text boxes and
//! shapes, anchored to a cell or to the page.

use super::styles::{parse_color, parse_len_pt};
use super::{Doc, paragraphs, parse_addr};
use crate::formats::office::common::xml::Node;
use crate::formats::office::sheets::error::Result;
use crate::formats::office::sheets::limits::Budget;
use crate::formats::office::sheets::model::*;

/// Column and row edges in points, as the document lays them out.
struct PtGrid {
    left: Vec<f64>,
    top: Vec<f64>,
    widths: Vec<f64>,
    heights: Vec<f64>,
}

impl PtGrid {
    fn new(sheet: &Sheet, digit_twips: f64, mc: u32, mr: u32) -> PtGrid {
        let col_pt = |c: u32| -> f64 {
            match sheet.col_info(c) {
                Some(ci) if ci.hidden => 0.0,
                Some(ci) => {
                    ci.width.or(sheet.default_col_width).unwrap_or(10.0) * digit_twips / 20.0
                }
                None => sheet.default_col_width.unwrap_or(10.0) * digit_twips / 20.0,
            }
        };
        let row_pt = |r: u32| -> f64 {
            match sheet.rows.get(&r) {
                Some(ri) if ri.hidden => 0.0,
                Some(ri) => ri.height.unwrap_or(sheet.default_row_height),
                None => sheet.default_row_height,
            }
        };
        let (mut left, mut widths, mut x) = (vec![], vec![], 0.0);
        for c in 0..=mc.min(MAX_COL) {
            let w = col_pt(c);
            left.push(x);
            widths.push(w);
            x += w;
        }
        let (mut top, mut heights, mut y) = (vec![], vec![], 0.0);
        for r in 0..=mr.min(MAX_ROW) {
            let h = row_pt(r);
            top.push(y);
            heights.push(h);
            y += h;
        }
        PtGrid {
            left,
            top,
            widths,
            heights,
        }
    }

    /// Edges past cell `far` (row, col) and past points (x, y).
    fn covering(sheet: &Sheet, digit_twips: f64, far: (u32, u32), x: f64, y: f64) -> PtGrid {
        let mut mc = far.1.saturating_add(2).min(MAX_COL);
        let mut mr = far.0.saturating_add(2).min(MAX_ROW);
        loop {
            let g = PtGrid::new(sheet, digit_twips, mc, mr);
            let wide =
                g.left.last().copied().unwrap_or(0.0) + g.widths.last().copied().unwrap_or(0.0) > x
                    || mc == MAX_COL;
            let tall =
                g.top.last().copied().unwrap_or(0.0) + g.heights.last().copied().unwrap_or(0.0) > y
                    || mr == MAX_ROW;
            if wide && tall {
                return g;
            }
            if !wide {
                mc = mc.saturating_mul(2).saturating_add(16).min(MAX_COL);
            }
            if !tall {
                mr = mr.saturating_mul(2).saturating_add(64).min(MAX_ROW);
            }
        }
    }

    fn cell(&self, r: u32, c: u32) -> (f64, f64) {
        let ci = (c as usize).min(self.left.len() - 1);
        let ri = (r as usize).min(self.top.len() - 1);
        (self.left[ci], self.top[ri])
    }

    /// The cell holding (x, y) and the offsets in it, in millionths.
    fn locate(&self, x: f64, y: f64) -> (u32, u32, i64, i64) {
        let c = self.left.partition_point(|&l| l <= x).saturating_sub(1);
        let r = self.top.partition_point(|&t| t <= y).saturating_sub(1);
        let frac = |off: f64, size: f64| {
            if size > 0.0 {
                ((off / size) * 1e6).clamp(0.0, 1e6) as i64
            } else {
                0
            }
        };
        (
            c as u32,
            r as u32,
            frac(x - self.left[c], self.widths[c]),
            frac(y - self.top[r], self.heights[r]),
        )
    }
}

fn len(n: &Node, k: &str) -> f64 {
    n.attr(k)
        .and_then(parse_len_pt)
        .unwrap_or(0.0)
        .clamp(-1e7, 1e7)
}

/// A frame's or shape's corners in points from the sheet's origin.
fn corners(f: &Node, cell: Option<(u32, u32)>, g: &PtGrid) -> (f64, f64, f64, f64) {
    let (x, y, w, h) = (
        len(f, "svg:x"),
        len(f, "svg:y"),
        len(f, "svg:width"),
        len(f, "svg:height"),
    );
    let (ox, oy) = cell.map_or((0.0, 0.0), |(r, c)| g.cell(r, c));
    let (x0, y0) = (ox + x, oy + y);
    let (x1, y1) = match f.attr("table:end-cell-address").and_then(parse_addr) {
        Some((_, r, c)) => {
            let (ex, ey) = g.cell(r, c);
            (ex + len(f, "table:end-x"), ey + len(f, "table:end-y"))
        }
        None => (x0 + w, y0 + h),
    };
    (x0, y0, x1, y1)
}

fn anchor(c: (f64, f64, f64, f64), g: &PtGrid) -> Anchor {
    let (x0, y0, x1, y1) = c;
    Anchor {
        from: g.locate(x0.min(x1).max(0.0), y0.min(y1).max(0.0)),
        to: g.locate(x0.max(x1).max(0.0), y0.max(y1).max(0.0)),
    }
}

fn image_ext(href: &str) -> &'static str {
    match href
        .rsplit('.')
        .next()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("png") => "png",
        Some("jpg" | "jpeg") => "jpeg",
        Some("gif") => "gif",
        Some("svg") => "svg",
        Some("emf") => "emf",
        Some("wmf") => "wmf",
        Some("bmp") => "bmp",
        Some("tif" | "tiff") => "tiff",
        _ => "png",
    }
}

/// Sniffs a picture without an extension.
fn sniff(d: &[u8]) -> Option<&'static str> {
    Some(match d {
        [0x89, b'P', b'N', b'G', ..] => "png",
        [0xFF, 0xD8, ..] => "jpeg",
        [b'G', b'I', b'F', ..] => "gif",
        [b'B', b'M', ..] => "bmp",
        [0xD7, 0xCD, 0xC6, 0x9A, ..] => "wmf",
        [1, 0, 0, 0, ..] if d.get(40..44) == Some(b" EMF") => "emf",
        _ => return None,
    })
}

fn geometry(n: &Node) -> Option<&'static str> {
    Some(match n.name.as_str() {
        "draw:rect" => "rect",
        "draw:ellipse" | "draw:circle" => "ellipse",
        "draw:line" | "draw:connector" => "line",
        "draw:polygon" | "draw:polyline" | "draw:path" | "draw:g" | "draw:frame" => "rect",
        "draw:custom-shape" => match n
            .child("draw:enhanced-geometry")
            .and_then(|g| g.attr("draw:type"))
            .unwrap_or("rectangle")
        {
            "ellipse" | "circle" => "ellipse",
            "round-rectangle" | "round-square" => "roundRect",
            "isosceles-triangle" => "triangle",
            "right-triangle" => "rtTriangle",
            "diamond" => "diamond",
            "hexagon" => "hexagon",
            "octagon" => "octagon",
            "parallelogram" => "parallelogram",
            "trapezoid" => "trapezoid",
            "pentagon" => "pentagon",
            "right-arrow" => "rightArrow",
            "left-arrow" => "leftArrow",
            "up-arrow" => "upArrow",
            "down-arrow" => "downArrow",
            "left-right-arrow" => "leftRightArrow",
            "star5" => "star5",
            "star4" => "star4",
            "star8" => "star8",
            "smiley" => "smileyFace",
            "can" => "can",
            "cube" => "cube",
            "heart" => "heart",
            "sun" => "sun",
            "moon" => "moon",
            "cloud-callout" | "cloud" => "cloud",
            "flowchart-process" => "flowChartProcess",
            "flowchart-decision" => "flowChartDecision",
            "flowchart-terminator" => "flowChartTerminator",
            "ring" => "donut",
            "cross" => "plus",
            _ => "rect",
        },
        _ => return None,
    })
}

/// The rotation of `draw:transform`'s rotate(), in degrees clockwise.
fn rotation(n: &Node) -> f64 {
    let Some(t) = n.attr("draw:transform") else {
        return 0.0;
    };
    let Some(i) = t.find("rotate") else {
        return 0.0;
    };
    let rest = &t[i + 6..];
    let inner = rest
        .trim_start()
        .strip_prefix('(')
        .and_then(|r| r.split(')').next())
        .unwrap_or("");
    let rad: f64 = inner.trim().parse().unwrap_or(0.0);
    if !rad.is_finite() {
        return 0.0;
    }
    // ODF rotates counterclockwise.
    (-rad.to_degrees()).rem_euclid(360.0)
}

fn shape(n: &Node, cell: Option<(u32, u32)>, g: &PtGrid, doc: &Doc, depth: u32) -> Vec<Shape> {
    let Some(geom) = geometry(n) else {
        return vec![];
    };
    if n.name == "draw:g" {
        if depth > 16 {
            return vec![];
        }
        return n
            .nodes()
            .take(4096)
            .flat_map(|c| shape(c, cell, g, doc, depth + 1))
            .collect();
    }
    // Where the application put the bottom right of the shape's bounding
    // box, when it says.
    let end = n
        .attr("table:end-cell-address")
        .and_then(parse_addr)
        .map(|(_, r, c)| {
            let (ex, ey) = g.cell(r, c);
            (ex + len(n, "table:end-x"), ey + len(n, "table:end-y"))
        });
    let rot = rotation(n);
    let c = if n.attr("svg:x1").is_some() {
        let (ox, oy) = cell.map_or((0.0, 0.0), |(r, c)| g.cell(r, c));
        let (x1, y1, x2, y2) = (
            ox + len(n, "svg:x1"),
            oy + len(n, "svg:y1"),
            ox + len(n, "svg:x2"),
            oy + len(n, "svg:y2"),
        );
        match end {
            Some((ex, ey)) => {
                let (dx, dy) = (ex - x1.max(x2), ey - y1.max(y2));
                (x1 + dx, y1 + dy, x2 + dx, y2 + dy)
            }
            None => (x1, y1, x2, y2),
        }
    } else if let (Some((ex, ey)), true) = (end, n.attr("draw:transform").is_some()) {
        // The unrotated box around the rotated one's center.
        let (w, h) = (len(n, "svg:width"), len(n, "svg:height"));
        let a = rot.to_radians();
        let (bw, bh) = (
            (w * a.cos()).abs() + (h * a.sin()).abs(),
            (w * a.sin()).abs() + (h * a.cos()).abs(),
        );
        let (cx, cy) = (ex - bw / 2.0, ey - bh / 2.0);
        (cx - w / 2.0, cy - h / 2.0, cx + w / 2.0, cy + h / 2.0)
    } else if n.attr("draw:transform").is_some() && n.attr("svg:x").is_none() {
        // A transformed shape: placed by the translate() of its transform.
        let t = n.attr("draw:transform").unwrap_or("");
        let tr = t
            .find("translate")
            .and_then(|i| t[i + 9..].trim_start().strip_prefix('('))
            .and_then(|r| r.split(')').next())
            .unwrap_or("");
        let mut it = tr
            .split([' ', ','])
            .filter(|s| !s.is_empty())
            .map(|s| parse_len_pt(s).unwrap_or(0.0));
        let (tx, ty) = (it.next().unwrap_or(0.0), it.next().unwrap_or(0.0));
        let (ox, oy) = cell.map_or((0.0, 0.0), |(r, c)| g.cell(r, c));
        let (w, h) = (len(n, "svg:width"), len(n, "svg:height"));
        // The translation moves the rotated top left corner; unrotate it to
        // the bounding box the anchor wants.
        let (x0, y0) = if rot != 0.0 {
            let a = -rot.to_radians();
            let (cx, cy) = (
                tx + (w * a.cos() - h * a.sin()) / 2.0,
                ty + (w * a.sin() + h * a.cos()) / 2.0,
            );
            (cx - w / 2.0, cy - h / 2.0)
        } else {
            (tx, ty)
        };
        (ox + x0, oy + y0, ox + x0 + w, oy + y0 + h)
    } else {
        corners(n, cell, g)
    };
    let mut shp = Shape::new(anchor(c, g), geom);
    if geom == "line" {
        shp.flip_h = c.2 < c.0;
        shp.flip_v = c.3 < c.1;
    }
    shp.rotation = rot;
    let gp = n
        .attr("draw:style-name")
        .and_then(|sn| doc.st.other("graphic", sn))
        .and_then(|s| s.child("style:graphic-properties"));
    let parent_gp = n
        .attr("draw:style-name")
        .and_then(|sn| doc.st.other("graphic", sn))
        .and_then(|s| s.attr("style:parent-style-name"))
        .and_then(|p| doc.st.other("graphic", p))
        .and_then(|s| s.child("style:graphic-properties"));
    let prop = |k: &str| {
        gp.and_then(|g| g.attr(k))
            .or_else(|| parent_gp.and_then(|g| g.attr(k)))
    };
    let filled = prop("draw:fill").is_none_or(|f| f != "none");
    if filled && geom != "line" {
        // The default fill of a shape is light blue in the application.
        shp.fill = Some(
            prop("draw:fill-color")
                .and_then(parse_color)
                .flatten()
                .unwrap_or(0x729FCF),
        );
    }
    if prop("draw:stroke") != Some("none") {
        shp.line = Some(
            prop("svg:stroke-color")
                .and_then(parse_color)
                .flatten()
                .unwrap_or(0x3465A4),
        );
        shp.line_width = prop("svg:stroke-width")
            .and_then(parse_len_pt)
            .map(|w| (w * 12700.0) as i64)
            .filter(|&w| w > 0);
        if prop("draw:stroke") == Some("dash") {
            shp.line_dash = Some("dash");
        }
        shp.head_arrow = prop("draw:marker-start").is_some();
        shp.tail_arrow = prop("draw:marker-end").is_some();
    }
    shp.text.text = paragraphs(n);
    if let Some(tb) = n.child("draw:text-box") {
        shp.text.text = paragraphs(tb);
    }
    shp.text.anchor = match prop("draw:textarea-vertical-align") {
        Some("middle") => Some("ctr"),
        Some("bottom") => Some("b"),
        Some("top") => Some("t"),
        _ => None,
    };
    shp.name = n.attr("draw:name").unwrap_or("").to_string();
    vec![shp]
}

pub(crate) fn read_drawings(
    t: &Node,
    doc: &mut Doc,
    wb: &mut Workbook,
    budget: &mut Budget,
    sheet: &mut Sheet,
    anchored: &[(u32, u32, &Node)],
    charts_out: &mut Vec<super::PendingChart>,
) -> Result<()> {
    let mut items: Vec<(Option<(u32, u32)>, &Node)> = anchored
        .iter()
        .map(|&(r, c, f)| (Some((r, c)), f))
        .collect();
    if let Some(shapes) = t.child("table:shapes") {
        items.extend(shapes.nodes().take(1 << 16).map(|n| (None, n)));
    }
    if items.is_empty() {
        return Ok(());
    }
    let f0 = wb.styles.get(0).font.clone();
    let digit = crate::formats::office::sheets::fonts::digit_twips(&f0.name, f0.size_pt());
    // Edges as far as the drawings reach (positions in points).
    let mut far = (0u32, 0u32);
    for (cell, n) in &items {
        if let Some((r, c)) = cell {
            far = (far.0.max(*r), far.1.max(*c));
        }
        if let Some((_, r, c)) = n.attr("table:end-cell-address").and_then(parse_addr) {
            far = (far.0.max(r), far.1.max(c));
        }
    }
    // Then as far as their extents reach.
    let probe = PtGrid::new(sheet, digit, far.1 + 1, far.0 + 1);
    let (mut max_x, mut max_y) = (0.0f64, 0.0f64);
    for (cell, n) in &items {
        let (ox, oy) = cell.map_or((0.0, 0.0), |(r, c)| probe.cell(r, c));
        max_x = max_x.max(ox + len(n, "svg:x").max(len(n, "svg:x2")) + len(n, "svg:width"));
        max_y = max_y.max(oy + len(n, "svg:y").max(len(n, "svg:y2")) + len(n, "svg:height"));
    }
    let g = PtGrid::covering(sheet, digit, far, max_x, max_y);
    for (cell, f) in items {
        if f.name != "draw:frame" {
            for s in shape(f, cell, &g, doc, 0) {
                if sheet.shapes.len() < 1 << 16 {
                    sheet.shapes.push(s);
                }
            }
            continue;
        }
        let a = anchor(corners(f, cell, &g), &g);
        // An embedded object's frame also has its replacement picture.
        if let Some(href) = f.child("draw:object").and_then(|o| o.attr("xlink:href")) {
            // Shown as its replacement picture when it is not a chart, where
            // that picture is in a format a reader draws.
            let fallback = f
                .child("draw:image")
                .and_then(|i| i.attr("xlink:href"))
                .and_then(|h| doc.parts.get(h.trim_start_matches("./")))
                .and_then(|d| {
                    let ext = sniff(d)?;
                    Some(Image {
                        anchor: a,
                        ext,
                        data: d.clone(),
                        name: f.attr("draw:name").unwrap_or("Object").to_string(),
                    })
                });
            charts_out.push((
                a,
                href.trim_start_matches("./")
                    .trim_end_matches('/')
                    .to_string(),
                fallback,
            ));
        } else if let Some(img) = f.child("draw:image") {
            let Some(href) = img.attr("xlink:href").map(|h| h.trim_start_matches("./")) else {
                continue;
            };
            let Some(data) = doc.parts.get(href) else {
                continue;
            };
            let ext = if href.contains('.') {
                image_ext(href)
            } else {
                sniff(data).unwrap_or("png")
            };
            budget.alloc(data.len() as u64)?;
            sheet.images.push(Image {
                anchor: a,
                ext,
                data: data.clone(),
                name: f.attr("draw:name").unwrap_or("Picture").to_string(),
            });
        } else if f.child("draw:text-box").is_some() {
            let mut s = shape(f, cell, &g, doc, 0);
            for x in &mut s {
                x.geom = "rect";
            }
            sheet.shapes.extend(s);
        }
    }
    Ok(())
}
