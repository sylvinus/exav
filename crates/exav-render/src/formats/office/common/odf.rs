//! OpenDocument styles ([ODF 1.2] part 1, 16) as the text, spreadsheet and
//! drawing formats share them: named and automatic styles with their parent
//! chains, default styles, list styles, font faces and page layouts, and the
//! length, colour and percentage values of their properties.

use super::xml::Node;
use std::collections::HashMap;

/// A length in points: cm, mm, in, pt, pc, px (96 per inch), em and ex are
/// not lengths here. A bare number is taken as points.
pub fn pt(s: &str) -> Option<f64> {
    let s = s.trim();
    let at = s
        .find(|c: char| c.is_ascii_alphabetic() || c == '%')
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(at);
    let v: f64 = num.trim().parse().ok()?;
    if !v.is_finite() {
        return None;
    }
    let p = match unit {
        "pt" | "" => v,
        "cm" => v * 72.0 / 2.54,
        "mm" => v * 72.0 / 25.4,
        "in" | "inch" => v * 72.0,
        "pc" => v * 12.0,
        "px" => v * 0.75,
        _ => return None,
    };
    Some(p.clamp(-1e9, 1e9))
}

/// A length in twips (1/20 point).
pub fn twips(s: &str) -> Option<i32> {
    pt(s).map(|p| (p * 20.0).round() as i32)
}

/// A length in EMU.
pub fn emu(s: &str) -> Option<i64> {
    pt(s).map(|p| (p * 12_700.0).round() as i64)
}

/// "#RRGGBB" (or "#RGB") as 0xRRGGBB.
pub fn color(s: &str) -> Option<u32> {
    let h = s.trim().strip_prefix('#')?;
    if h.len() == 3 {
        let v = u32::from_str_radix(h, 16).ok()?;
        let (r, g, b) = ((v >> 8) & 0xF, (v >> 4) & 0xF, v & 0xF);
        return Some(((r * 17) << 16) | ((g * 17) << 8) | (b * 17));
    }
    if h.len() != 6 {
        return None;
    }
    u32::from_str_radix(h, 16).ok()
}

/// "50%" to 0.5.
pub fn percent(s: &str) -> Option<f64> {
    let v: f64 = s.trim().strip_suffix('%')?.trim().parse().ok()?;
    v.is_finite().then_some(v / 100.0)
}

/// Attributes as (qualified name, value).
pub type Attrs = Vec<(String, String)>;

/// One style: its parent and every property of its property elements, keyed
/// by the kind of property element and the qualified name of the attribute:
/// `text/fo:color`, `paragraph/fo:margin-left`.
#[derive(Clone, Debug, Default)]
pub struct StyleDef {
    pub parent: Option<String>,
    pub next: Option<String>,
    /// The attributes of the style element itself (style:display-name,
    /// style:list-style-name, style:master-page-name, ...).
    pub attrs: Vec<(String, String)>,
    pub props: Vec<(String, String)>,
    /// Elements inside property elements (tab stops, background images,
    /// drop caps), as (property element, child name, attributes).
    pub children: Vec<(String, String, Attrs)>,
    pub automatic: bool,
}

impl StyleDef {
    pub fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|a| a.0 == k).map(|a| a.1.as_str())
    }
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

    pub fn pt(&self, k: &str) -> Option<f64> {
        self.get(k).and_then(pt)
    }

    pub fn twips(&self, k: &str) -> Option<i32> {
        self.get(k).and_then(twips)
    }

    pub fn color(&self, k: &str) -> Option<u32> {
        self.get(k).and_then(color)
    }

    pub fn is(&self, k: &str, v: &str) -> bool {
        self.get(k) == Some(v)
    }
}

/// A list style's level.
#[derive(Clone, Debug, Default)]
pub struct ListLevel {
    /// bullet, number, image or none.
    pub kind: &'static str,
    pub attrs: Vec<(String, String)>,
    /// Properties of the level's list-level-properties and text-properties.
    pub props: Props,
    pub tabs: Vec<(String, String)>,
}

impl ListLevel {
    pub fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|a| a.0 == k).map(|a| a.1.as_str())
    }
}

/// A list style's levels: (level 1 to 10, definition).
#[derive(Clone, Debug, Default)]
pub struct ListDef {
    pub levels: Vec<(usize, ListLevel)>,
}

/// The styles of one scope (a document's content, or its styles part).
#[derive(Default)]
pub struct Styles {
    /// (family, name) to style; later definitions replace earlier ones.
    pub styles: HashMap<(String, String), StyleDef>,
    /// Style names in the order they were defined, per family.
    pub order: Vec<(String, String)>,
    pub defaults: HashMap<String, Vec<(String, String)>>,
    pub lists: Vec<ListDef>,
    pub list_names: HashMap<String, usize>,
    /// Font face name to family.
    pub fonts: HashMap<String, String>,
    /// Page layouts' properties by name, with their header and footer style
    /// properties under "header:" and "footer:" prefixes.
    pub page_layouts: HashMap<String, Props>,
}

fn attrs_of(n: &Node) -> Vec<(String, String)> {
    n.attrs.clone()
}

/// The attributes of a property element with its kind in front, so that
/// `fo:background-color` of text and of a paragraph stay apart:
/// `text/fo:background-color`, `paragraph/fo:background-color`.
fn prefixed(n: &Node) -> Vec<(String, String)> {
    let kind = n
        .name
        .rsplit(':')
        .next()
        .unwrap_or("")
        .trim_end_matches("-properties");
    n.attrs
        .iter()
        .map(|(k, v)| (format!("{kind}/{k}"), v.clone()))
        .collect()
}

impl Styles {
    /// Reads the style elements under `n` (office:styles,
    /// office:automatic-styles, office:font-face-decls).
    pub fn add(&mut self, n: &Node, automatic: bool) {
        for c in n.nodes() {
            match c.name.as_str() {
                "style:style" => {
                    let family = c.attr("style:family").unwrap_or("").to_string();
                    let name = c.attr("style:name").unwrap_or("").to_string();
                    let mut def = StyleDef {
                        parent: c.attr("style:parent-style-name").map(str::to_string),
                        next: c.attr("style:next-style-name").map(str::to_string),
                        attrs: attrs_of(c),
                        automatic,
                        ..StyleDef::default()
                    };
                    for p in c.nodes() {
                        if p.name.ends_with("-properties") {
                            def.props.extend(prefixed(p));
                            for g in p.nodes() {
                                def.children
                                    .push((p.name.clone(), g.name.clone(), attrs_of(g)));
                                // Tab stops sit one level further.
                                for t in g.nodes() {
                                    def.children.push((
                                        g.name.clone(),
                                        t.name.clone(),
                                        attrs_of(t),
                                    ));
                                }
                            }
                        }
                    }
                    let key = (family, name);
                    if !self.styles.contains_key(&key) {
                        self.order.push(key.clone());
                    }
                    self.styles.insert(key, def);
                }
                "style:page-layout" => {
                    let mut v = vec![];
                    for p in c.nodes() {
                        let prefix = match p.name.as_str() {
                            "style:header-style" => "header:",
                            "style:footer-style" => "footer:",
                            _ => "",
                        };
                        if prefix.is_empty() {
                            v.extend(attrs_of(p));
                            for g in p.nodes() {
                                if g.name == "style:columns" {
                                    v.push((
                                        "columns".into(),
                                        g.attr("fo:column-count").unwrap_or("1").into(),
                                    ));
                                    v.push((
                                        "columns-gap".into(),
                                        g.attr("fo:column-gap").unwrap_or("0").into(),
                                    ));
                                }
                            }
                        } else {
                            for g in p.nodes() {
                                for (k, val) in &g.attrs {
                                    v.push((format!("{prefix}{k}"), val.clone()));
                                }
                            }
                        }
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
                            v.extend(prefixed(p));
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

    /// Reads a text:list-style element (also in a style's properties),
    /// returning its index in `lists`.
    pub fn list(&mut self, l: &Node) -> usize {
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
                    "text:list-level-style-number" | "text:outline-level-style" => "number",
                    "text:list-level-style-image" => "image",
                    _ => "none",
                },
                attrs: attrs_of(lv),
                ..ListLevel::default()
            };
            let mut p = vec![];
            for c in lv.nodes() {
                p.extend(prefixed(c));
                for g in c.nodes() {
                    if g.name == "style:tab-stops" {
                        for t in g.nodes() {
                            x.tabs.extend(t.attrs.iter().cloned());
                        }
                    } else if g.name == "style:list-level-label-alignment" {
                        p.extend(
                            g.attrs
                                .iter()
                                .map(|(k, v)| (format!("label-alignment/{k}"), v.clone())),
                        );
                    }
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

    /// The style's properties over its parents' (family default first).
    pub fn resolve(&self, family: &str, name: Option<&str>) -> Props {
        let mut out = Props::default();
        if let Some(d) = self.defaults.get(family) {
            out.overlay(d);
        }
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
        for s in chain.iter().rev() {
            out.overlay(&s.props);
        }
        out
    }

    /// The font family a font face name stands for.
    pub fn font(&self, name: &str) -> String {
        self.fonts
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.trim_matches(['\'', '"']).to_string())
    }
}

/// The text of a node and its descendants.
pub fn text_of(n: &Node) -> String {
    use super::xml::Child;
    let mut s = String::new();
    for c in &n.children {
        match c {
            Child::Text(t) => s.push_str(t),
            Child::Node(k) => s.push_str(&text_of(k)),
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_and_colours() {
        assert_eq!(twips("2.54cm"), Some(1440));
        assert_eq!(twips("1in"), Some(1440));
        assert_eq!(emu("10pt"), Some(127_000));
        assert_eq!(twips("12px"), Some(180));
        assert_eq!(twips("x"), None);
        assert_eq!(twips("1em"), None);
        assert_eq!(color("#3465a4"), Some(0x3465A4));
        assert_eq!(color("#fff"), Some(0xFFFFFF));
        assert_eq!(percent("50%"), Some(0.5));
    }

    #[test]
    fn styles_resolve_through_parents_and_defaults() {
        let x = br##"<office:styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"><style:default-style style:family="paragraph"><style:paragraph-properties fo:margin-left="1cm" fo:text-align="start"/></style:default-style><style:style style:name="a" style:family="paragraph"><style:paragraph-properties fo:text-align="center"/></style:style><style:style style:name="b" style:family="paragraph" style:parent-style-name="a"><style:text-properties fo:color="#ff0000"/><style:paragraph-properties fo:margin-right="2cm"/></style:style><style:style style:name="c" style:family="paragraph" style:parent-style-name="b"><style:paragraph-properties fo:text-align="end"/></style:style></office:styles>"##;
        let n = super::super::xml::parse(x, &mut super::super::xml::within(1 << 20)).unwrap();
        let mut s = Styles::default();
        s.add(&n, false);
        let p = s.resolve("paragraph", Some("b"));
        // The parent overrides the default, the child adds to the parent.
        assert_eq!(p.get("paragraph/fo:text-align"), Some("center"));
        assert_eq!(p.get("paragraph/fo:margin-right"), Some("2cm"));
        assert_eq!(p.color("text/fo:color"), Some(0xFF0000));
        assert_eq!(p.get("paragraph/fo:margin-left"), Some("1cm"));
        assert_eq!(s.order.len(), 3);
        // A style's own value beats its parents' and the default.
        let p = s.resolve("paragraph", Some("c"));
        assert_eq!(p.get("paragraph/fo:text-align"), Some("end"));
        assert_eq!(p.get("paragraph/fo:margin-right"), Some("2cm"));
        // An unknown style resolves to the defaults.
        assert_eq!(
            s.resolve("paragraph", Some("missing"))
                .get("paragraph/fo:text-align"),
            Some("start")
        );
    }
}
