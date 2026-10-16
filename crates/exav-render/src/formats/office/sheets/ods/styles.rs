//! ODF styles: cell styles with their parent chain resolved, to the model's
//! styles and differential formats.

use super::dom::{Child, Node};
use super::numfmt;
use crate::formats::office::sheets::model::*;
use std::collections::HashMap;

#[derive(Clone, Default, Debug, PartialEq)]
pub(crate) struct Props {
    pub font: Option<String>,
    pub size: Option<f64>,
    pub bold: Option<bool>,
    pub italic: Option<bool>,
    pub underline: Option<Option<&'static str>>,
    pub strike: Option<bool>,
    pub color: Option<Option<Rgb>>,
    pub vert: Option<Option<&'static str>>,
    pub outline: Option<bool>,
    pub shadow: Option<bool>,
    pub bg: Option<Option<Rgb>>,
    pub left: Option<Edge>,
    pub right: Option<Edge>,
    pub top: Option<Edge>,
    pub bottom: Option<Edge>,
    pub diag_up: Option<Edge>,
    pub diag_down: Option<Edge>,
    pub halign: Option<Option<&'static str>>,
    pub valign: Option<Option<&'static str>>,
    pub wrap: Option<bool>,
    pub rotation: Option<u8>,
    pub shrink: Option<bool>,
    pub indent: Option<u8>,
    pub data_style: Option<String>,
    pub locked: Option<bool>,
    pub hidden: Option<bool>,
    /// The style has text properties at all.
    pub text: bool,
}

macro_rules! over {
    ($a:ident, $b:ident, $($f:ident),*) => { $( if $b.$f.is_some() { $a.$f = $b.$f.clone(); } )* };
}

impl Props {
    pub fn overlay(&mut self, o: &Props) {
        self.text |= o.text;
        over!(
            self, o, font, size, bold, italic, underline, strike, color, vert, outline, shadow, bg,
            left, right, top, bottom, diag_up, diag_down, halign, valign, wrap, rotation, shrink,
            indent, data_style, locked, hidden
        );
    }
}

pub(crate) struct StyleDef {
    pub parent: Option<String>,
    pub props: Props,
    /// style:map: (condition, applied style, base cell).
    pub maps: Vec<(String, String, Option<String>)>,
}

/// A length to points.
pub(crate) fn parse_len_pt(s: &str) -> Option<f64> {
    let s = s.trim();
    let (num, unit) = s.split_at(
        s.find(|c: char| c.is_ascii_alphabetic() || c == '%')
            .unwrap_or(s.len()),
    );
    let v: f64 = num.trim().parse().ok()?;
    if !v.is_finite() {
        return None;
    }
    Some(match unit {
        "pt" | "" => v,
        "in" => v * 72.0,
        "cm" => v * 72.0 / 2.54,
        "mm" => v * 72.0 / 25.4,
        "pc" => v * 12.0,
        "px" => v * 0.75,
        _ => return None,
    })
}

/// "#RRGGBB" or "transparent" (Some(None)).
pub(crate) fn parse_color(s: &str) -> Option<Option<Rgb>> {
    if s == "transparent" {
        return Some(None);
    }
    let h = s.strip_prefix('#')?;
    if h.len() != 6 {
        return None;
    }
    u32::from_str_radix(h, 16).ok().map(Some)
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
        if let Some(w) = parse_len_pt(t) {
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

pub(crate) fn text_props(tp: &Node, fonts: &HashMap<String, String>, p: &mut Props) {
    // A declared font face, else the family named directly; a face that is
    // not declared is ignored.
    match tp.attr("style:font-name").and_then(|f| fonts.get(f)) {
        Some(fam) => p.font = Some(fam.clone()),
        None => {
            if let Some(f) = tp.attr("fo:font-family") {
                p.font = Some(f.trim().trim_matches('\'').trim_matches('"').to_string());
            }
        }
    }
    p.text = true;
    if let Some(v) = tp.attr("fo:font-size") {
        if !v.ends_with('%') {
            if let Some(pt) = parse_len_pt(v) {
                p.size = Some(pt.clamp(1.0, 409.0));
            }
        }
    }
    if let Some(v) = tp.attr("fo:font-weight") {
        p.bold = Some(v == "bold" || v.parse::<u32>().is_ok_and(|w| w >= 600));
    }
    if let Some(v) = tp.attr("fo:font-style") {
        p.italic = Some(v == "italic" || v == "oblique");
    }
    if let Some(v) = tp.attr("style:text-underline-style") {
        p.underline = Some(if v == "none" {
            None
        } else if tp.attr("style:text-underline-type") == Some("double") {
            Some("double")
        } else {
            Some("single")
        });
    }
    if let Some(v) = tp.attr("style:text-line-through-style") {
        p.strike = Some(v != "none");
    }
    if let Some(c) = tp.attr("fo:color").and_then(parse_color) {
        p.color = Some(c);
    }
    if tp.attr("style:use-window-font-color") == Some("true") {
        p.color = Some(None);
    }
    if let Some(v) = tp.attr("style:text-position") {
        let first = v.split_whitespace().next().unwrap_or("");
        p.vert = Some(if first == "super" || pct(first).is_some_and(|x| x > 0.0) {
            Some("superscript")
        } else if first == "sub" || pct(first).is_some_and(|x| x < 0.0) {
            Some("subscript")
        } else {
            None
        });
    }
    if let Some(v) = tp.attr("style:text-outline") {
        p.outline = Some(v == "true");
    }
    if let Some(v) = tp.attr("fo:text-shadow") {
        p.shadow = Some(v != "none");
    }
}

pub(crate) fn style_props(st: &Node, fonts: &HashMap<String, String>) -> Props {
    let mut p = Props::default();
    if let Some(d) = st.attr("style:data-style-name") {
        p.data_style = Some(d.to_string());
    }
    if let Some(tc) = st.child("style:table-cell-properties") {
        if let Some(c) = tc.attr("fo:background-color").and_then(parse_color) {
            p.bg = Some(c);
        }
        if let Some(v) = tc.attr("fo:border") {
            let e = parse_border(v);
            p.left = Some(e.clone());
            p.right = Some(e.clone());
            p.top = Some(e.clone());
            p.bottom = Some(e);
        }
        for (k, f) in [
            ("fo:border-left", 0),
            ("fo:border-right", 1),
            ("fo:border-top", 2),
            ("fo:border-bottom", 3),
        ] {
            if let Some(v) = tc.attr(k) {
                let e = parse_border(v);
                match f {
                    0 => p.left = Some(e),
                    1 => p.right = Some(e),
                    2 => p.top = Some(e),
                    _ => p.bottom = Some(e),
                }
            }
        }
        if let Some(v) = tc.attr("style:diagonal-bl-tr") {
            p.diag_up = Some(parse_border(v));
        }
        if let Some(v) = tc.attr("style:diagonal-tl-br") {
            p.diag_down = Some(parse_border(v));
        }
        if let Some(v) = tc.attr("style:vertical-align") {
            p.valign = Some(match v {
                "top" => Some("top"),
                "middle" => Some("center"),
                _ => None,
            });
        }
        if let Some(v) = tc.attr("fo:wrap-option") {
            p.wrap = Some(v == "wrap");
        }
        if let Some(v) = tc.attr("style:rotation-angle") {
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
            p.rotation = Some(if a == 0 {
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
        if tc.attr("style:direction") == Some("ttb") {
            p.rotation = Some(255);
        }
        if let Some(v) = tc.attr("style:shrink-to-fit") {
            p.shrink = Some(v == "true");
        }
        if let Some(v) = tc.attr("style:cell-protect") {
            p.locked = Some(v.contains("protected") && !v.contains("none"));
            p.hidden = Some(v.contains("formula-hidden") || v.contains("hidden-and-protected"));
        }
    }
    if let Some(pp) = st.child("style:paragraph-properties") {
        let fixed = st
            .child("style:table-cell-properties")
            .and_then(|t| t.attr("style:text-align-source"))
            != Some("value-type");
        if let Some(v) = pp.attr("fo:text-align") {
            if fixed {
                p.halign = Some(match v {
                    "start" | "left" => Some("left"),
                    "center" => Some("center"),
                    "end" | "right" => Some("right"),
                    "justify" => Some("justify"),
                    _ => None,
                });
            }
        }
        if let Some(pt) = pp.attr("fo:margin-left").and_then(parse_len_pt) {
            p.indent = Some((pt / 10.0).round().clamp(0.0, 15.0) as u8);
        }
    }
    if let Some(tp) = st.child("style:text-properties") {
        text_props(tp, fonts, &mut p);
    }
    p
}

pub(crate) struct Styles {
    pub defs: HashMap<String, StyleDef>,
    pub display: HashMap<String, String>,
    pub default: Props,
    pub data: HashMap<String, String>,
    pub fonts: HashMap<String, String>,
    /// Other families' styles: (family, name).
    pub other: HashMap<(String, String), Node>,
    cache: HashMap<String, Props>,
}

fn clone_node(n: &Node) -> Node {
    Node {
        name: n.name.clone(),
        attrs: n.attrs.clone(),
        children: n
            .children
            .iter()
            .map(|c| match c {
                Child::Node(x) => Child::Node(clone_node(x)),
                Child::Text(t) => Child::Text(t.clone()),
            })
            .collect(),
    }
}

impl Styles {
    pub fn collect(roots: &[&Node]) -> Styles {
        let mut fonts = HashMap::new();
        for r in roots {
            if let Some(ff) = r.child("office:font-face-decls") {
                for f in ff.all("style:font-face") {
                    if let Some(n) = f.attr("style:name") {
                        let fam = f
                            .attr("svg:font-family")
                            .unwrap_or(n)
                            .trim()
                            .trim_matches('\'')
                            .trim_matches('"')
                            .to_string();
                        fonts.insert(n.to_string(), fam);
                    }
                }
            }
        }
        let mut style_roots: Vec<&Node> = vec![];
        for r in roots {
            for k in [
                "office:styles",
                "office:automatic-styles",
                "office:master-styles",
            ] {
                if let Some(s) = r.child(k) {
                    style_roots.push(s);
                }
            }
        }
        let data = numfmt::collect(&style_roots);
        let mut defs = HashMap::new();
        let mut display = HashMap::new();
        let mut default = Props::default();
        let mut other = HashMap::new();
        for sr in &style_roots {
            for st in sr.nodes() {
                match st.name.as_str() {
                    "style:default-style" if st.attr("style:family") == Some("table-cell") => {
                        default = style_props(st, &fonts)
                    }
                    "style:style" => {
                        let fam = st.attr("style:family").unwrap_or("");
                        let Some(name) = st.attr("style:name") else {
                            continue;
                        };
                        if fam == "table-cell" {
                            if let Some(d) = st.attr("style:display-name") {
                                display.insert(d.to_string(), name.to_string());
                            }
                            let maps = st
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
                            defs.insert(
                                name.to_string(),
                                StyleDef {
                                    parent: st.attr("style:parent-style-name").map(str::to_string),
                                    props: style_props(st, &fonts),
                                    maps,
                                },
                            );
                        } else {
                            other.insert((fam.to_string(), name.to_string()), clone_node(st));
                        }
                    }
                    _ => {}
                }
            }
        }
        Styles {
            defs,
            display,
            default,
            data,
            fonts,
            other,
            cache: HashMap::new(),
        }
    }

    fn chain(&self, name: &str) -> Vec<String> {
        let mut chain = vec![];
        let mut cur = Some(name.to_string());
        while let Some(n) = cur {
            if chain.contains(&n) || chain.len() > 32 {
                break;
            }
            let parent = self.defs.get(&n).and_then(|d| d.parent.clone());
            chain.push(n);
            cur = parent;
        }
        chain
    }

    /// A style's properties with its parents' under them.
    pub fn resolve(&mut self, name: &str) -> Props {
        if let Some(p) = self.cache.get(name) {
            return p.clone();
        }
        let mut p = self.default.clone();
        for n in self.chain(name).iter().rev() {
            if let Some(d) = self.defs.get(n) {
                p.overlay(&d.props);
            }
        }
        if self.cache.len() < 1 << 16 {
            self.cache.insert(name.to_string(), p.clone());
        }
        p
    }

    pub fn other(&self, family: &str, name: &str) -> Option<&Node> {
        self.other.get(&(family.to_string(), name.to_string()))
    }

    pub fn to_style(&self, p: &Props) -> Style {
        let font = Font {
            name: p.font.clone().unwrap_or_else(|| "Liberation Sans".into()),
            size_centipt: (p.size.unwrap_or(10.0) * 100.0).round() as u32,
            bold: p.bold.unwrap_or(false),
            italic: p.italic.unwrap_or(false),
            underline: p.underline.flatten(),
            strike: p.strike.unwrap_or(false),
            color: p.color.flatten(),
            vert_align: p.vert.flatten(),
            family: 0,
            charset: None,
            outline: p.outline.unwrap_or(false),
            shadow: p.shadow.unwrap_or(false),
        };
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
        let numfmt = p
            .data_style
            .as_ref()
            .and_then(|d| self.data.get(d).cloned())
            .unwrap_or_else(|| "General".into());
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
            numfmt,
            locked: p.locked.unwrap_or(true),
            hidden: p.hidden.unwrap_or(false),
        }
    }

    /// The differential format of a conditional style. A conditional
    /// format may name its style by its display name. In the application
    /// the conditional style replaces the cell's, so its font is written
    /// whole when it or its parents set any font property (`always_font`
    /// for style:map conditions).
    pub fn dxf(&mut self, name: &str, always_font: bool) -> Dxf {
        let name = if self.defs.contains_key(name) {
            name.to_string()
        } else {
            self.display
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.to_string())
        };
        let mut p = Props::default();
        for n in self.chain(&name).iter().rev() {
            if n == "Default" {
                continue;
            }
            if let Some(d) = self.defs.get(n) {
                p.overlay(&d.props);
            }
        }
        let full = self.resolve(&name);
        let mut with_default = self
            .defs
            .get("Default")
            .map(|d| d.props.clone())
            .unwrap_or_default();
        with_default.overlay(&p);
        if always_font || with_default.text {
            p.color = Some(Some(full.color.flatten().unwrap_or(0)));
            p.bold = Some(full.bold.unwrap_or(false));
            p.italic = Some(full.italic.unwrap_or(false));
            p.strike = Some(full.strike.unwrap_or(false));
            p.underline = Some(full.underline.flatten());
        }
        let any_border =
            p.left.is_some() || p.right.is_some() || p.top.is_some() || p.bottom.is_some();
        Dxf {
            font_color: p.color.flatten(),
            bold: p.bold,
            italic: p.italic,
            underline: p.underline.map(|u| u.unwrap_or("none")),
            strike: p.strike,
            fill: p.bg.flatten().map(Fill::solid),
            border: any_border.then(|| Border {
                left: p.left.clone().unwrap_or_default(),
                right: p.right.clone().unwrap_or_default(),
                top: p.top.clone().unwrap_or_default(),
                bottom: p.bottom.clone().unwrap_or_default(),
                ..Default::default()
            }),
            numfmt: p
                .data_style
                .as_ref()
                .and_then(|d| self.data.get(d).cloned()),
        }
    }
}
