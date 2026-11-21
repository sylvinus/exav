//! ODF styles of the spreadsheet converter: the shared ones
//! (`common::odf`, whose property keys carry the kind of property element:
//! `table-cell/fo:border-left`), read as the model's styles and differential
//! formats.

use super::numfmt;
use crate::formats::office::common::odf::{self, Props, StyleDef};
use crate::formats::office::common::xml::Node;
use crate::formats::office::sheets::model::*;
use std::collections::HashMap;
use std::rc::Rc;

const CELL: &str = "table-cell";

/// A style:map: (condition, applied style, base cell).
pub(crate) type StyleMap = (String, String, Option<String>);

/// "#RRGGBB" or "transparent" (Some(None)).
pub(crate) fn parse_color(s: &str) -> Option<Option<Rgb>> {
    if s == "transparent" {
        return Some(None);
    }
    // The shared reader also takes "#RGB" and spaces around.
    (s.len() == 7).then(|| odf::color(s)).flatten().map(Some)
}

/// "0.74pt solid #000000" to an XLSX border edge.
pub(crate) fn parse_border(s: &str) -> Edge {
    let s = s.trim();
    if s == "none" || s.is_empty() || s == "hidden" {
        return Edge::default();
    }
    let mut width = 0.75;
    let mut style = "solid";
    let mut color = Some(0);
    for t in s.split_whitespace() {
        if let Some(w) = odf::pt(t) {
            width = w;
        } else if t.starts_with('#') {
            color = parse_color(t).flatten();
        } else {
            match t {
                "thin" => width = 0.75,
                "medium" => width = 1.75,
                "thick" => width = 2.5,
                "solid" | "double" | "dotted" | "dashed" | "dash-dot" | "dash-dot-dot"
                | "fine-dashed" | "double-thin" | "groove" | "ridge" | "inset" | "outset" => {
                    style = t
                }
                _ => {}
            }
        }
    }
    let wide = width > 1.2;
    let x = match style {
        "double" | "double-thin" => "double",
        "dotted" => {
            if wide {
                "mediumDashDotDot"
            } else {
                "dotted"
            }
        }
        "dashed" => {
            if wide {
                "mediumDashed"
            } else {
                "dashed"
            }
        }
        "fine-dashed" => "hair",
        "dash-dot" => {
            if wide {
                "mediumDashDot"
            } else {
                "dashDot"
            }
        }
        "dash-dot-dot" => {
            if wide {
                "mediumDashDotDot"
            } else {
                "dashDotDot"
            }
        }
        _ => {
            if width < 0.6 {
                "hair"
            } else if width <= 1.1 {
                "thin"
            } else if width <= 2.25 {
                "medium"
            } else {
                "thick"
            }
        }
    };
    Edge {
        style: Some(x),
        color,
    }
}

fn pct(v: &str) -> Option<f64> {
    v.trim_end_matches('%').parse::<f64>().ok()
}

/// What a resolved style sets of a font, `None` for what it leaves alone.
#[derive(Default)]
struct TextLook {
    font: Option<String>,
    size: Option<f64>,
    /// A percentage of the size the style has no size to take of.
    size_of: Option<f64>,
    bold: Option<bool>,
    italic: Option<bool>,
    underline: Option<Option<&'static str>>,
    strike: Option<bool>,
    color: Option<Option<Rgb>>,
    vert: Option<Option<&'static str>>,
    outline: Option<bool>,
    shadow: Option<bool>,
}

/// What a resolved cell style sets, `None` for what it leaves alone.
#[derive(Default)]
struct Look {
    text: TextLook,
    bg: Option<Option<Rgb>>,
    left: Option<Edge>,
    right: Option<Edge>,
    top: Option<Edge>,
    bottom: Option<Edge>,
    diag_up: Option<Edge>,
    diag_down: Option<Edge>,
    halign: Option<Option<&'static str>>,
    valign: Option<Option<&'static str>>,
    wrap: Option<bool>,
    rotation: Option<u8>,
    shrink: Option<bool>,
    indent: Option<u8>,
    locked: Option<bool>,
    hidden: Option<bool>,
}

fn text_look(p: &Props, st: &odf::Styles) -> TextLook {
    let t = |k: &str| p.get(&format!("text/{k}"));
    let mut l = TextLook {
        font: t("style:font-name").map(|n| st.font(n)).or_else(|| {
            t("fo:font-family").map(|f| f.trim().trim_matches(['\'', '"']).to_string())
        }),
        ..TextLook::default()
    };
    if let Some(v) = t("fo:font-size") {
        // A percentage is left when no style gives a size to take it of.
        if let Some(f) = odf::percent(v) {
            l.size_of = Some(f);
        } else if let Some(pt) = odf::pt(v) {
            l.size = Some(pt.clamp(1.0, 409.0));
        }
    }
    if let Some(v) = t("fo:font-weight") {
        l.bold = Some(v == "bold" || v.parse::<u32>().is_ok_and(|w| w >= 600));
    }
    if let Some(v) = t("fo:font-style") {
        l.italic = Some(v == "italic" || v == "oblique");
    }
    if let Some(v) = t("style:text-underline-style") {
        let double = t("style:text-underline-type") == Some("double");
        l.underline = Some(match (v, double) {
            ("none", _) => None,
            (_, true) => Some("double"),
            _ => Some("single"),
        });
    }
    if let Some(v) = t("style:text-line-through-style") {
        l.strike = Some(v != "none");
    }
    // The automatic colour is the cell's own, as a transparent one.
    if t("style:use-window-font-color") == Some("true") {
        l.color = Some(None);
    } else if let Some(c) = t("fo:color").and_then(parse_color) {
        l.color = Some(c);
    }
    if let Some(v) = t("style:text-position") {
        let first = v.split_whitespace().next().unwrap_or("");
        l.vert = Some(if first == "super" || pct(first).is_some_and(|x| x > 0.0) {
            Some("superscript")
        } else if first == "sub" || pct(first).is_some_and(|x| x < 0.0) {
            Some("subscript")
        } else {
            None
        });
    }
    if let Some(v) = t("style:text-outline") {
        l.outline = Some(v == "true");
    }
    if let Some(v) = t("fo:text-shadow") {
        l.shadow = Some(v != "none");
    }
    l
}

fn look(p: &Props, st: &odf::Styles) -> Look {
    let c = |k: &str| p.get(&format!("table-cell/{k}"));
    let mut l = Look {
        text: text_look(p, st),
        ..Look::default()
    };
    if let Some(v) = c("fo:background-color").and_then(parse_color) {
        l.bg = Some(v);
    }
    let edge = |side: &str| {
        c(&format!("fo:border-{side}"))
            .or_else(|| c("fo:border"))
            .map(parse_border)
    };
    l.left = edge("left");
    l.right = edge("right");
    l.top = edge("top");
    l.bottom = edge("bottom");
    l.diag_up = c("style:diagonal-bl-tr").map(parse_border);
    l.diag_down = c("style:diagonal-tl-br").map(parse_border);
    if let Some(v) = c("style:vertical-align") {
        l.valign = Some(match v {
            "top" => Some("top"),
            "middle" => Some("center"),
            _ => None,
        });
    }
    if let Some(v) = c("fo:wrap-option") {
        l.wrap = Some(v == "wrap");
    }
    if let Some(v) = c("style:rotation-angle") {
        let a = v
            .trim_end_matches("deg")
            .trim()
            .parse::<f64>()
            .unwrap_or(0.0);
        let a = if a.is_finite() {
            (a.round() as i64).rem_euclid(360)
        } else {
            0
        };
        l.rotation = Some(if a == 0 {
            0
        } else if a <= 90 {
            a as u8
        } else if a >= 270 {
            (90 + 360 - a) as u8
        } else if a <= 180 {
            // Upside-down angles have no XLSX equivalent: the nearest.
            90
        } else {
            180
        });
    }
    if c("style:direction") == Some("ttb") {
        l.rotation = Some(255);
    }
    if let Some(v) = c("style:shrink-to-fit") {
        l.shrink = Some(v == "true");
    }
    if let Some(v) = c("style:cell-protect") {
        l.locked = Some(v.contains("protected") && !v.contains("none"));
        l.hidden = Some(v.contains("formula-hidden") || v.contains("hidden-and-protected"));
    }
    // `drop_value_aligned` has dropped it when the alignment follows the
    // value's type.
    if let Some(v) = p.get("paragraph/fo:text-align") {
        l.halign = Some(match v {
            "start" | "left" => Some("left"),
            "center" => Some("center"),
            "end" | "right" => Some("right"),
            "justify" => Some("justify"),
            _ => None,
        });
    }
    if let Some(pt) = p.margin("paragraph", "left").and_then(odf::pt) {
        l.indent = Some((pt / 10.0).round().clamp(0.0, 15.0) as u8);
    }
    l
}

/// The font a style gives, over the application's default one.
fn font_of(t: &TextLook) -> Font {
    let mut f = Font {
        name: "Liberation Sans".into(),
        size_centipt: 1000,
        bold: false,
        italic: false,
        underline: None,
        strike: false,
        color: None,
        vert_align: None,
        family: 0,
        charset: None,
        outline: false,
        shadow: false,
    };
    apply(&mut f, t);
    f
}

/// What a style sets of a font, over a font.
fn apply(f: &mut Font, t: &TextLook) {
    if let Some(n) = &t.font {
        f.name = n.clone();
    }
    if let Some(s) = t.size {
        f.size_centipt = (s * 100.0).round() as u32;
    } else if let Some(x) = t.size_of {
        f.size_centipt = (f64::from(f.size_centipt) * x)
            .round()
            .clamp(100.0, 40_900.0) as u32;
    }
    if let Some(b) = t.bold {
        f.bold = b;
    }
    if let Some(i) = t.italic {
        f.italic = i;
    }
    if let Some(u) = t.underline {
        f.underline = u;
    }
    if let Some(s) = t.strike {
        f.strike = s;
    }
    if let Some(c) = t.color {
        f.color = c;
    }
    if let Some(v) = t.vert {
        f.vert_align = v;
    }
    if let Some(o) = t.outline {
        f.outline = o;
    }
    if let Some(s) = t.shadow {
        f.shadow = s;
    }
}

/// A cell style whose horizontal alignment follows the value's type has none
/// of its own.
fn drop_value_aligned(props: &mut Vec<(String, String)>) {
    let by_type = props
        .iter()
        .any(|(k, v)| k == "table-cell/style:text-align-source" && v == "value-type");
    if by_type {
        props.retain(|(k, _)| k != "paragraph/fo:text-align");
    }
}

fn has_text(p: &Props) -> bool {
    p.iter().any(|(k, _)| k.starts_with("text/"))
}

pub(crate) struct Styles {
    sty: odf::Styles,
    display: HashMap<String, String>,
    maps: HashMap<String, Vec<StyleMap>>,
    data: HashMap<String, String>,
}

impl Styles {
    pub fn collect(roots: &[&Node]) -> Styles {
        let mut sty = odf::Styles::default();
        for r in roots {
            if let Some(ff) = r.child("office:font-face-decls") {
                sty.add(ff, false);
            }
        }
        let mut style_roots: Vec<(&Node, bool)> = vec![];
        for r in roots {
            for k in [
                "office:styles",
                "office:automatic-styles",
                "office:master-styles",
            ] {
                if let Some(s) = r.child(k) {
                    style_roots.push((s, k == "office:automatic-styles"));
                }
            }
        }
        let mut display = HashMap::new();
        let mut maps: HashMap<String, Vec<StyleMap>> = HashMap::new();
        for (sr, automatic) in &style_roots {
            sty.add(sr, *automatic);
            for st in sr.all("style:style") {
                let Some(name) = st
                    .attr("style:name")
                    .filter(|_| st.attr("style:family") == Some(CELL))
                else {
                    continue;
                };
                if let Some(d) = st.attr("style:display-name") {
                    display.insert(d.to_string(), name.to_string());
                }
                let m: Vec<StyleMap> = st
                    .all("style:map")
                    .take(64)
                    .filter_map(|m| {
                        Some((
                            m.attr("style:condition")?.to_string(),
                            m.attr("style:apply-style-name")?.to_string(),
                            m.attr("style:base-cell-address").map(str::to_string),
                        ))
                    })
                    .collect();
                // A style defined again replaces the conditions too.
                if m.is_empty() {
                    maps.remove(name);
                } else {
                    maps.insert(name.to_string(), m);
                }
            }
        }
        let nodes: Vec<&Node> = style_roots.iter().map(|(n, _)| *n).collect();
        let data = numfmt::collect(&nodes);
        for ((family, _), def) in &mut sty.styles {
            if family == CELL {
                drop_value_aligned(&mut def.props);
            }
        }
        if let Some(d) = sty.defaults.get_mut(CELL) {
            drop_value_aligned(d);
        }
        Styles {
            sty,
            display,
            maps,
            data,
        }
    }

    /// The properties of a style of another family (table, column, row,
    /// drawing, text) over its parents'.
    pub fn chain(&self, family: &str, name: Option<&str>) -> Rc<Props> {
        self.sty.chain(family, name)
    }

    /// Whether a text style of this name is defined.
    pub fn has_text_style(&self, name: &str) -> bool {
        self.sty.get("text", name).is_some()
    }

    /// The memory the resolved styles took since the last call, in bytes.
    pub fn take_charge(&self) -> u64 {
        self.sty.take_charge()
    }

    /// Whether the cell style has conditions (style:map).
    pub fn has_maps(&self, name: &str) -> bool {
        self.maps.contains_key(name)
    }

    pub fn maps(&self, name: &str) -> Vec<StyleMap> {
        self.maps.get(name).cloned().unwrap_or_default()
    }

    /// The number format code of the data style the cell style or its
    /// parents name.
    fn number_format(&self, data_style: Option<&str>) -> Option<String> {
        data_style.and_then(|d| self.data.get(d).cloned())
    }

    /// The model style of a cell style, with its parents and the defaults.
    pub fn style(&self, name: &str) -> Style {
        let p = self.sty.resolve(CELL, Some(name));
        let data = self
            .sty
            .lineage(CELL, Some(name))
            .into_iter()
            .find_map(|s| s.attr("style:data-style-name"));
        self.to_style(&look(&p, &self.sty), data)
    }

    /// The font of a cell style.
    pub fn font(&self, name: &str) -> Font {
        font_of(&text_look(&self.sty.resolve(CELL, Some(name)), &self.sty))
    }

    /// The font of a text style over a font, or `None` for a name that is
    /// no text style.
    pub fn span_font(&self, name: &str, over: &Font) -> Option<Font> {
        self.has_text_style(name).then(|| {
            let mut f = over.clone();
            let look = text_look(&self.sty.chain("text", Some(name)), &self.sty);
            apply(&mut f, &look);
            f
        })
    }

    fn to_style(&self, p: &Look, data_style: Option<&str>) -> Style {
        let font = font_of(&p.text);
        let fill = match p.bg.flatten() {
            Some(c) => Fill::solid(c),
            None => Fill::NONE,
        };
        let du = p.diag_up.clone().unwrap_or_default();
        let dd = p.diag_down.clone().unwrap_or_default();
        let diag = if du.style.is_some() {
            du.clone()
        } else {
            dd.clone()
        };
        Style {
            font,
            fill,
            border: Border {
                left: p.left.clone().unwrap_or_default(),
                right: p.right.clone().unwrap_or_default(),
                top: p.top.clone().unwrap_or_default(),
                bottom: p.bottom.clone().unwrap_or_default(),
                diagonal: diag,
                diag_up: du.style.is_some(),
                diag_down: dd.style.is_some(),
            },
            align: Align {
                horizontal: p.halign.flatten(),
                vertical: p.valign.flatten(),
                wrap: p.wrap.unwrap_or(false),
                indent: p.indent.unwrap_or(0),
                rotation: p.rotation.unwrap_or(0),
                shrink: p.shrink.unwrap_or(false),
                reading_order: 0,
            },
            numfmt: self
                .number_format(data_style)
                .unwrap_or_else(|| "General".into()),
            locked: p.locked.unwrap_or(true),
            hidden: p.hidden.unwrap_or(false),
        }
    }

    /// The differential format of a conditional style. A conditional
    /// format may name its style by its display name. In the application
    /// the conditional style replaces the cell's, so its font is written
    /// whole when it or its parents set any font property (`always_font`
    /// for style:map conditions).
    pub fn dxf(&self, name: &str, always_font: bool) -> Dxf {
        let name = if self.sty.get(CELL, name).is_some() {
            name.to_string()
        } else {
            self.display
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.to_string())
        };
        // What the style adds to the style every cell has, "Default".
        let line = self.sty.lineage(CELL, Some(&name));
        let own: Vec<&StyleDef> = line
            .iter()
            .copied()
            .filter(|s| s.attr("style:name") != Some("Default"))
            .collect();
        let mut p = Props::default();
        for s in own.iter().rev() {
            p.overlay(&s.props);
        }
        let mut with_default = Props::default();
        if let Some(d) = self.sty.get(CELL, "Default") {
            with_default.overlay(&d.props);
        }
        with_default.overlay_props(&p);
        let full = text_look(&self.sty.resolve(CELL, Some(&name)), &self.sty);
        let data = own.iter().find_map(|s| s.attr("style:data-style-name"));
        let mut l = look(&p, &self.sty);
        if always_font || has_text(&with_default) {
            l.text.color = Some(Some(full.color.flatten().unwrap_or(0)));
            l.text.bold = Some(full.bold.unwrap_or(false));
            l.text.italic = Some(full.italic.unwrap_or(false));
            l.text.strike = Some(full.strike.unwrap_or(false));
            l.text.underline = Some(full.underline.flatten());
        }
        let any_border =
            l.left.is_some() || l.right.is_some() || l.top.is_some() || l.bottom.is_some();
        Dxf {
            font_color: l.text.color.flatten(),
            bold: l.text.bold,
            italic: l.text.italic,
            underline: l.text.underline.map(|u| u.unwrap_or("none")),
            strike: l.text.strike,
            fill: l.bg.flatten().map(Fill::solid),
            border: any_border.then(|| Border {
                left: l.left.clone().unwrap_or_default(),
                right: l.right.clone().unwrap_or_default(),
                top: l.top.clone().unwrap_or_default(),
                bottom: l.bottom.clone().unwrap_or_default(),
                ..Default::default()
            }),
            numfmt: self.number_format(data),
        }
    }

    #[cfg(test)]
    pub fn walks(&self) -> usize {
        self.sty.walks()
    }
}
