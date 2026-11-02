//! ODF styles ([ODF 1.2] part 1, 16): named and automatic styles with
//! their parent chains, default styles, gradients, hatches, images and dash
//! definitions, and the length and colour values of their properties.

use crate::formats::office::common::xml::Node;
use crate::formats::office::slides::model::{Emu, Rgb};
use std::collections::HashMap;

/// A length to EMU: cm, mm, in, pt, pc, px; a bare number is taken as cm
/// (the unit drawings use when none is given).
pub fn len(s: &str) -> Option<Emu> {
    let s = s.trim();
    let at = s
        .find(|c: char| c.is_ascii_alphabetic() || c == '%')
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(at);
    let v: f64 = num.trim().parse().ok()?;
    if !v.is_finite() {
        return None;
    }
    let emu = match unit {
        "cm" | "" => v * 360_000.0,
        "mm" => v * 36_000.0,
        "in" | "inch" => v * 914_400.0,
        "pt" => v * 12_700.0,
        "pc" => v * 152_400.0,
        "px" => v * 9_525.0,
        _ => return None,
    };
    Some(emu.clamp(-1e13, 1e13).round() as Emu)
}

// "#RRGGBB" as an `Rgb`, "50%" as 0.5, and the text of a node and its
// descendants, as the other ODF readers have them.
pub use crate::formats::office::common::odf::{color, percent, text_of};

/// One style: its parent and every property of its property elements,
/// keyed by qualified name.
#[derive(Clone, Debug, Default)]
pub struct StyleDef {
    pub parent: Option<String>,
    pub props: Vec<(String, String)>,
    /// A list style the style carries (graphic and presentation styles).
    pub list: Option<usize>,
}

/// Resolved properties: the last value of a key wins.
#[derive(Clone, Debug, Default)]
pub struct Props(pub Vec<(String, String)>);

impl Props {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.0.iter().rev().find(|p| p.0 == k).map(|p| p.1.as_str())
    }

    pub fn overlay(&mut self, o: &[(String, String)]) {
        self.0.extend(o.iter().cloned());
    }

    pub fn len(&self, k: &str) -> Option<Emu> {
        self.get(k).and_then(len)
    }

    pub fn color(&self, k: &str) -> Option<Rgb> {
        self.get(k).and_then(color)
    }

    pub fn is(&self, k: &str, v: &str) -> bool {
        self.get(k) == Some(v)
    }
}

/// A list style's levels: (level 1 to 10, element).
#[derive(Clone, Debug, Default)]
pub struct ListDef {
    pub levels: Vec<(usize, ListLevel)>,
}

#[derive(Clone, Debug, Default)]
pub struct ListLevel {
    /// bullet, number, image or none.
    pub kind: &'static str,
    pub bullet: Option<char>,
    pub num_format: String,
    pub num_suffix: String,
    pub start: u32,
    /// The picture of an image bullet: its package path, or "data:" and
    /// its base64 text.
    pub image: Option<String>,
    pub props: Props,
}

/// The styles of one scope (a document's content, or its masters).
#[derive(Default)]
pub struct Styles {
    /// (family, name) to style, automatic styles before common ones.
    pub styles: HashMap<(String, String), StyleDef>,
    pub defaults: HashMap<String, Vec<(String, String)>>,
    pub lists: Vec<ListDef>,
    pub list_names: HashMap<String, usize>,
    /// draw:gradient, draw:hatch, draw:fill-image, draw:stroke-dash,
    /// draw:marker, draw:opacity, by name.
    pub objects: HashMap<(String, String), Props>,
    /// Font face name to family.
    pub fonts: HashMap<String, String>,
    /// Page layouts' properties, by name.
    pub page_layouts: HashMap<String, Props>,
    /// Table templates: name to (part, cell style) pairs (first-row,
    /// body, odd-rows...).
    pub table_templates: HashMap<String, Vec<(String, String)>>,
}

fn props_of(n: &Node, out: &mut Vec<(String, String)>) {
    for (k, v) in &n.attrs {
        out.push((k.clone(), v.clone()));
    }
}

impl Styles {
    /// Reads the style elements under `n` (office:styles,
    /// office:automatic-styles, office:font-face-decls), later ones
    /// replacing earlier ones of the same name.
    pub fn add(&mut self, n: &Node) {
        for c in n.nodes() {
            match c.name.as_str() {
                "style:style" => {
                    let family = c.attr("style:family").unwrap_or("").to_string();
                    let name = c.attr("style:name").unwrap_or("").to_string();
                    let mut def = StyleDef {
                        parent: c.attr("style:parent-style-name").map(str::to_string),
                        ..StyleDef::default()
                    };
                    for p in c.nodes() {
                        if p.name.ends_with("-properties") {
                            props_of(p, &mut def.props);
                            if let Some(l) = p.child("text:list-style") {
                                def.list = Some(self.list(l));
                            }
                        }
                    }
                    self.styles.insert((family, name), def);
                }
                "table:table-template" => {
                    let name = c
                        .attr("text:style-name")
                        .or(c.attr("style:name"))
                        .or(c.attr("table:name"))
                        .unwrap_or("");
                    let parts = c
                        .nodes()
                        .filter_map(|p| {
                            let part = p.name.strip_prefix("table:")?;
                            Some((part.to_string(), p.attr("table:style-name")?.to_string()))
                        })
                        .collect();
                    self.table_templates.insert(name.to_string(), parts);
                }
                "style:page-layout" => {
                    let mut v = vec![];
                    for p in c.nodes() {
                        props_of(p, &mut v);
                    }
                    if let Some(name) = c.attr("style:name") {
                        self.page_layouts.insert(name.to_string(), Props(v));
                    }
                }
                "style:default-style" => {
                    let family = c.attr("style:family").unwrap_or("").to_string();
                    let mut v = vec![];
                    for p in c.nodes() {
                        if p.name.ends_with("-properties") {
                            props_of(p, &mut v);
                        }
                    }
                    self.defaults.insert(family, v);
                }
                "text:list-style" => {
                    let i = self.list(c);
                    if let Some(name) = c.attr("style:name") {
                        self.list_names.insert(name.to_string(), i);
                    }
                }
                "draw:gradient" | "draw:hatch" | "draw:fill-image" | "draw:stroke-dash"
                | "draw:marker" | "draw:opacity" => {
                    if let Some(name) = c.attr("draw:name") {
                        let mut p = vec![];
                        props_of(c, &mut p);
                        // A flat file holds the picture inline.
                        if let Some(b) = c.child("office:binary-data") {
                            p.push(("xlink:href".into(), format!("data:{}", b.own_text())));
                        }
                        self.objects
                            .insert((c.name.clone(), name.to_string()), Props(p));
                    }
                }
                "style:font-face" => {
                    if let (Some(name), Some(fam)) =
                        (c.attr("style:name"), c.attr("svg:font-family"))
                    {
                        let fam = fam.trim().trim_matches(['\'', '"']).to_string();
                        self.fonts.insert(name.to_string(), fam);
                    }
                }
                _ => {}
            }
        }
    }

    fn list(&mut self, l: &Node) -> usize {
        let mut def = ListDef::default();
        for lv in l.nodes() {
            let level = lv
                .attr("text:level")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1)
                .clamp(1, 10);
            let mut x = ListLevel {
                kind: match lv.name.as_str() {
                    "text:list-level-style-bullet" => "bullet",
                    "text:list-level-style-number" => "number",
                    "text:list-level-style-image" => "image",
                    _ => "none",
                },
                bullet: lv.attr("text:bullet-char").and_then(|s| s.chars().next()),
                num_format: lv.attr("style:num-format").unwrap_or("").to_string(),
                num_suffix: lv.attr("style:num-suffix").unwrap_or("").to_string(),
                start: lv
                    .attr("text:start-value")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1),
                image: lv.attr("xlink:href").map(str::to_string).or_else(|| {
                    lv.child("office:binary-data")
                        .map(|b| format!("data:{}", b.own_text()))
                }),
                ..ListLevel::default()
            };
            let mut p = vec![];
            for c in lv.nodes() {
                props_of(c, &mut p);
                for g in c.nodes() {
                    props_of(g, &mut p);
                }
            }
            x.props = Props(p);
            def.levels.push((level, x));
        }
        self.lists.push(def);
        self.lists.len() - 1
    }

    pub fn get(&self, family: &str, name: &str) -> Option<&StyleDef> {
        self.styles.get(&(family.to_string(), name.to_string()))
    }

    /// The style's properties over its parents', without a default.
    pub fn chain(&self, family: &str, name: Option<&str>) -> Props {
        let mut chain = vec![];
        let mut cur = name.map(str::to_string);
        while let Some(n) = cur.take() {
            if chain.len() > 32 {
                break;
            }
            if let Some(s) = self.get(family, &n) {
                chain.push(s);
                cur = s.parent.clone();
            }
        }
        let mut out = Props::default();
        for s in chain.iter().rev() {
            out.overlay(&s.props);
        }
        out
    }

    /// The style's properties over its parents' and its family's default.
    pub fn resolve(&self, family: &str, name: Option<&str>) -> Props {
        let mut chain = vec![];
        // A drawing object with no style has the style called "standard".
        let name = name.or((family == "graphic").then_some("standard"));
        let mut cur = name.map(str::to_string);
        // Presentation styles fall back to graphic ones of the same name.
        while let Some(n) = cur.take() {
            if chain.len() > 32 {
                break;
            }
            let s = self.get(family, &n).or_else(|| {
                if family == "presentation" {
                    self.get("graphic", &n)
                } else {
                    None
                }
            });
            if let Some(s) = s {
                chain.push(s);
                cur = s.parent.clone();
            }
        }
        let mut out = Props::default();
        let def_family = if family == "presentation" {
            "graphic"
        } else {
            family
        };
        if let Some(d) = self.defaults.get(def_family) {
            out.overlay(d);
        }
        for s in chain.iter().rev() {
            out.overlay(&s.props);
        }
        out
    }

    /// The list style a style or its parents carry.
    pub fn list_of(&self, family: &str, name: Option<&str>) -> Option<&ListDef> {
        let mut cur = name.map(str::to_string);
        let mut n = 0;
        while let Some(s) = cur.take() {
            n += 1;
            if n > 32 {
                break;
            }
            let st = self.get(family, &s).or_else(|| self.get("graphic", &s))?;
            if let Some(i) = st.list {
                return self.lists.get(i);
            }
            cur = st.parent.clone();
        }
        None
    }

    pub fn object(&self, kind: &str, name: &str) -> Option<&Props> {
        self.objects.get(&(kind.to_string(), name.to_string()))
    }

    pub fn font(&self, name: &str) -> String {
        self.fonts
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.trim_matches(['\'', '"']).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_and_colours() {
        assert_eq!(len("2.54cm"), Some(914_400));
        assert_eq!(len("1in"), Some(914_400));
        assert_eq!(len("10pt"), Some(127_000));
        assert_eq!(len("x"), None);
        assert_eq!(color("#3465a4"), Some(0x3465A4));
        assert_eq!(color("#fff"), Some(0xFFFFFF));
        assert_eq!(percent("50%"), Some(0.5));
    }

    #[test]
    fn styles_resolve_through_parents_and_defaults() {
        let x = br##"<office:styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"><style:default-style style:family="graphic"><style:graphic-properties draw:fill-color="#729fcf" draw:stroke="solid"/></style:default-style><style:style style:name="a" style:family="graphic"><style:graphic-properties draw:fill="solid"/></style:style><style:style style:name="b" style:family="graphic" style:parent-style-name="a"><style:graphic-properties draw:fill-color="#ff0000"/></style:style></office:styles>"##;
        let n = crate::formats::office::common::xml::parse(
            x,
            &mut crate::formats::office::common::xml::within(1 << 20),
        )
        .unwrap();
        let mut s = Styles::default();
        s.add(&n);
        let p = s.resolve("graphic", Some("b"));
        assert_eq!(p.get("draw:fill"), Some("solid"));
        assert_eq!(p.color("draw:fill-color"), Some(0xFF0000));
        assert_eq!(p.get("draw:stroke"), Some("solid"));
        // A presentation style falls back to a graphic one.
        assert_eq!(
            s.resolve("presentation", Some("a")).get("draw:fill"),
            Some("solid")
        );
        // `chain` leaves the default out.
        let p = s.chain("graphic", Some("b"));
        assert_eq!(p.get("draw:fill"), Some("solid"));
        assert_eq!(p.get("draw:stroke"), None);
    }
}
