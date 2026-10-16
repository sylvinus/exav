//! Frames and shapes: pictures, text boxes and simple drawing shapes.

use super::Odt;
use crate::formats::office::common::base64;
use crate::formats::office::common::image;
use crate::formats::office::common::odf::{self, Props};
use crate::formats::office::common::xml::Node;
use crate::formats::office::docs::error::Result;
use crate::formats::office::docs::model::*;

impl Odt<'_> {
    fn picture_media(&mut self, n: &Node) -> Result<Option<usize>> {
        let max = self.b.limits.max_part as usize;
        let data = if let Some(b) = n.child("office:binary-data") {
            base64::decode(&odf::text_of(b), max)
        } else if let Some(h) = n.attr("xlink:href") {
            if let Some(&m) = self.image_cache.get(h) {
                return Ok(m);
            }
            let path = h.trim_start_matches("./");
            let d = match &mut self.zip {
                Some(z) if !path.contains("..") && !path.contains("://") => {
                    z.read(path, max as u64).ok().flatten()
                }
                _ => None,
            };
            let media = match d {
                Some(d) => match image::ext(&d) {
                    Some(ext) => {
                        self.b.alloc(d.len() as u64)?;
                        Some(self.doc.add_media(ext, d))
                    }
                    None => None,
                },
                None => None,
            };
            self.image_cache.insert(h.to_string(), media);
            return Ok(media);
        } else {
            None
        };
        let Some(d) = data else { return Ok(None) };
        match image::ext(&d) {
            Some(ext) => {
                self.b.alloc(d.len() as u64)?;
                Ok(Some(self.doc.add_media(ext, d)))
            }
            None => Ok(None),
        }
    }

    /// A frame or drawing shape as a drawing, if it holds something this
    /// converter draws.
    pub(crate) fn drawing(&mut self, n: &Node) -> Result<Option<Drawing>> {
        if self.depth > 12 {
            return Ok(None);
        }
        let ap = n
            .attr("draw:style-name")
            .map(|s| self.apply("graphic", s))
            .unwrap_or_default();
        let p: &Props = &ap.props;
        let anchor_type = n.attr("text:anchor-type").unwrap_or("paragraph");
        let w = n.attr("svg:width").and_then(odf::emu);
        let h = n.attr("svg:height").and_then(odf::emu);
        let x = n.attr("svg:x").and_then(odf::emu).unwrap_or(0);
        let y = n.attr("svg:y").and_then(odf::emu).unwrap_or(0);
        let descr = n
            .child("svg:desc")
            .map(odf::text_of)
            .or_else(|| n.child("svg:title").map(odf::text_of))
            .filter(|s| !s.is_empty());

        // What the frame holds.
        let mut kind = None;
        let mut natural = None;
        let mut frame_node = n;
        if n.name == "draw:frame" {
            for c in n.nodes() {
                match c.name.as_str() {
                    "draw:image" => {
                        if let Some(media) = self.picture_media(c)? {
                            natural = image::natural_emu(&self.doc.media[media].data);
                            let mut crop = Crop::default();
                            if let Some(clip) = p.get("graphic/fo:clip") {
                                // rect(top, right, bottom, left)
                                let nums: Vec<f64> = clip
                                    .trim_start_matches("rect(")
                                    .trim_end_matches(')')
                                    .split([',', ' '])
                                    .filter(|s| !s.is_empty())
                                    .filter_map(odf::pt)
                                    .collect();
                                if let (Some((nx, ny)), [t, r, b, l]) = (natural, nums.as_slice()) {
                                    let (fw, fh) = (nx as f64 / 12_700.0, ny as f64 / 12_700.0);
                                    if fw > 0.0 && fh > 0.0 {
                                        crop = Crop {
                                            t: (t / fh * 100_000.0) as i32,
                                            r: (r / fw * 100_000.0) as i32,
                                            b: (b / fh * 100_000.0) as i32,
                                            l: (l / fw * 100_000.0) as i32,
                                        };
                                    }
                                }
                            }
                            kind = Some(DrawingKind::Picture { media, crop });
                        }
                        break;
                    }
                    "draw:text-box" => {
                        let blocks = self.blocks(c)?;
                        let mut sh = Shape {
                            text: blocks,
                            ..Shape::default()
                        };
                        frame_style(p, &mut sh);
                        kind = Some(DrawingKind::Shape(sh));
                        frame_node = c;
                        break;
                    }
                    _ => {}
                }
            }
        } else {
            // A drawing shape directly in the text.
            let preset = match n.name.as_str() {
                "draw:rect" => "rect",
                "draw:ellipse" => "ellipse",
                "draw:line" | "draw:connector" => "line",
                "draw:custom-shape" => "rect",
                _ => return Ok(None),
            };
            let mut sh = Shape {
                preset,
                ..Shape::default()
            };
            frame_style(p, &mut sh);
            if n.nodes().any(|c| c.name == "text:p") {
                self.depth += 1;
                let blocks = self.blocks(n)?;
                self.depth -= 1;
                sh.text = blocks;
            }
            kind = Some(DrawingKind::Shape(sh));
        }
        let Some(kind) = kind else { return Ok(None) };
        let _ = frame_node;
        let (cx, cy) = match (w, h, natural) {
            (Some(w), Some(h), _) if w > 0 && h > 0 => (w, h),
            (Some(w), None, Some((nx, ny))) if w > 0 && nx > 0 => (w, w * ny / nx),
            (None, Some(h), Some((nx, ny))) if h > 0 && ny > 0 => (h * nx / ny, h),
            (_, _, Some((nx, ny))) => (nx, ny),
            (Some(w), Some(h), None) => (w.max(1), h.max(1)),
            _ => (914_400, 914_400),
        };
        let anchor = if anchor_type == "as-char" {
            None
        } else {
            let h_rel = match (p.get("graphic/style:horizontal-rel"), anchor_type) {
                (Some("page" | "page-start-margin" | "page-end-margin"), _) | (None, "page") => {
                    "page"
                }
                (Some("page-content"), _) => "margin",
                (Some("paragraph" | "paragraph-content"), _) => "column",
                (Some("char"), _) => "character",
                (_, "char") => "character",
                _ => "column",
            };
            let v_rel = match (p.get("graphic/style:vertical-rel"), anchor_type) {
                (Some("page"), _) | (None, "page") => "page",
                (Some("page-content"), _) => "margin",
                (Some("paragraph" | "paragraph-content"), _) => "paragraph",
                (Some("char" | "line" | "text"), _) | (_, "char") => "line",
                _ => "paragraph",
            };
            let mut a = Anchor {
                h_rel,
                v_rel,
                ..Anchor::default()
            };
            match p.get("graphic/style:horizontal-pos") {
                Some("center") => a.h_align = Some("center"),
                Some("right") => a.h_align = Some("right"),
                Some("left") => a.h_align = Some("left"),
                _ => a.h_off = x,
            }
            match p.get("graphic/style:vertical-pos") {
                Some("middle") => a.v_align = Some("center"),
                Some("bottom") => a.v_align = Some("bottom"),
                Some("top") => a.v_align = Some("top"),
                _ => a.v_off = y,
            }
            a.wrap = match p.get("graphic/style:wrap") {
                Some("none") => Wrap::TopBottom,
                Some("run-through") => Wrap::None,
                Some("left" | "right" | "parallel" | "dynamic" | "biggest") => Wrap::Square,
                _ => Wrap::Square,
            };
            a.behind = p.get("graphic/style:run-through") == Some("background");
            a.z = n
                .attr("draw:z-index")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            a.dist = [
                p.pt("graphic/fo:margin-top")
                    .map(|v| (v * 12_700.0) as i64)
                    .unwrap_or(0),
                p.pt("graphic/fo:margin-bottom")
                    .map(|v| (v * 12_700.0) as i64)
                    .unwrap_or(0),
                p.pt("graphic/fo:margin-left")
                    .map(|v| (v * 12_700.0) as i64)
                    .unwrap_or(0),
                p.pt("graphic/fo:margin-right")
                    .map(|v| (v * 12_700.0) as i64)
                    .unwrap_or(0),
            ];
            Some(a)
        };
        Ok(Some(Drawing {
            anchor,
            cx,
            cy,
            name: n.attr("draw:name").unwrap_or("Frame").to_string(),
            descr,
            kind,
        }))
    }
}

/// Fill and line of a graphic style.
fn frame_style(p: &Props, sh: &mut Shape) {
    sh.fill = match p.get("graphic/draw:fill") {
        Some("solid") => p
            .get("graphic/draw:fill-color")
            .and_then(odf::color)
            .map(Fill::Solid)
            .unwrap_or(Fill::None),
        _ => match p.get("graphic/fo:background-color").and_then(odf::color) {
            Some(c) => Fill::Solid(c),
            None => Fill::None,
        },
    };
    let stroke = p.get("graphic/draw:stroke");
    let border = p.get("graphic/fo:border").filter(|b| *b != "none");
    if stroke == Some("solid") || stroke == Some("dash") || border.is_some() {
        let (w, c) = match border {
            Some(b) => {
                let bd = super::props::border(b, None);
                (
                    bd.as_ref()
                        .map(|b| i64::from(b.size) * 1587)
                        .unwrap_or(9525),
                    bd.map(|b| b.color).unwrap_or(Color::Rgb(0)),
                )
            }
            None => (
                p.pt("graphic/svg:stroke-width")
                    .map(|v| (v * 12_700.0) as i64)
                    .unwrap_or(9525),
                p.get("graphic/svg:stroke-color")
                    .and_then(odf::color)
                    .map(Color::Rgb)
                    .unwrap_or(Color::Rgb(0)),
            ),
        };
        sh.line = Some(Line {
            color: c,
            width: w,
            dash: if stroke == Some("dash") {
                "dash"
            } else {
                "solid"
            },
        });
    }
    let pad = |k: &str, d: i64| {
        p.pt(&format!("graphic/fo:padding-{k}"))
            .or_else(|| p.pt("graphic/fo:padding"))
            .map(|v| (v * 12_700.0) as i64)
            .unwrap_or(d)
    };
    sh.insets = [
        pad("left", 0),
        pad("top", 0),
        pad("right", 0),
        pad("bottom", 0),
    ];
    sh.v_anchor = match p.get("graphic/draw:textarea-vertical-align") {
        Some("middle") => "ctr",
        Some("bottom") => "b",
        _ => "t",
    };
}
