//! OpenDocument styles ([ODF 1.2] part 1, 16) as the text, presentation and
//! spreadsheet formats share them: named and automatic styles with their parent
//! chains, default styles, list styles, font faces and page layouts, and the
//! length, colour and percentage values of their properties.

use super::xml::Node;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// A length split into its number and its unit (possibly empty).
pub fn split_len(s: &str) -> Option<(f64, &str)> {
    let s = s.trim();
    let at = s
        .find(|c: char| c.is_ascii_alphabetic() || c == '%')
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(at);
    let v: f64 = num.trim().parse().ok()?;
    v.is_finite().then_some((v, unit))
}

/// A length in points: cm, mm, in, pt, pc, px (96 per inch), em and ex are
/// not lengths here. A bare number is taken as points.
pub fn pt(s: &str) -> Option<f64> {
    let (v, unit) = split_len(s)?;
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

/// What a percentage of a value gives: points when the value is a length, a
/// percentage when it is one, `None` otherwise.
fn taken_of(base: &str, f: f64) -> Option<String> {
    if let Some(b) = pt(base) {
        Some(format!("{}pt", b * f))
    } else {
        percent(base).map(|g| format!("{}%", g * f * 100.0))
    }
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
    /// Index in `Styles::lists` of the list style a property element of the
    /// style carries (graphic and presentation styles).
    pub list: Option<usize>,
}

impl StyleDef {
    pub fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|a| a.0 == k).map(|a| a.1.as_str())
    }
}

/// What a property takes in memory besides its key and value.
const ENTRY: u64 = 2 * size_of::<String>() as u64 + 16;

/// Font sizes a percentage of the levels before can be taken of (20.183).
const FONT_SIZES: &[&str] = &["text/fo:font-size", "text/style:font-size-complex"];

/// The sides of a paragraph margin.
const SIDES: &[&str] = &["left", "right", "top", "bottom"];

/// Attributes a producer writes together and a reader shows as one value, as
/// (attributes that say whether there is a line and which, all members). A
/// level that sets one of the first replaces what the levels before it set
/// through the members; a level that sets only another member (a colour, a
/// width) keeps the line of the levels before and changes that attribute.
const GROUPS: &[(&[&str], &[&str])] = &[
    (
        &["style:text-underline-style", "style:text-underline-type"],
        &[
            "style:text-underline-style",
            "style:text-underline-type",
            "style:text-underline-width",
            "style:text-underline-color",
        ],
    ),
    (
        &[
            "style:text-line-through-style",
            "style:text-line-through-type",
        ],
        &[
            "style:text-line-through-style",
            "style:text-line-through-type",
        ],
    ),
];

/// Attributes that give a value another attribute of the same property
/// element gives too ([ODF 1.2] part 1, 20): a level that sets the first
/// (with the value, when one is named) replaces what the levels before it set
/// through the others. A shorthand stands for the sides the level does not set
/// itself; a font is a declared face or a family (the readers take the face
/// first, so only a family drops it); the automatic colour and `fo:color` are
/// two ways to set the colour.
const REPLACES: &[(&str, Option<&str>, &[&str])] = &[
    (
        "fo:border",
        None,
        &[
            "fo:border-left",
            "fo:border-right",
            "fo:border-top",
            "fo:border-bottom",
        ],
    ),
    (
        "fo:padding",
        None,
        &[
            "fo:padding-left",
            "fo:padding-right",
            "fo:padding-top",
            "fo:padding-bottom",
        ],
    ),
    ("fo:color", None, &["style:use-window-font-color"]),
    ("style:use-window-font-color", Some("true"), &["fo:color"]),
    (
        "fo:margin",
        None,
        &[
            "fo:margin-left",
            "fo:margin-right",
            "fo:margin-top",
            "fo:margin-bottom",
        ],
    ),
    ("fo:font-family", None, &["style:font-name"]),
    ("style:font-family-asian", None, &["style:font-name-asian"]),
    (
        "style:font-family-complex",
        None,
        &["style:font-name-complex"],
    ),
];

/// Properties by key; a key set again takes the later value.
#[derive(Clone, Debug, Default)]
pub struct Props(HashMap<String, String>);

impl From<Vec<(String, String)>> for Props {
    fn from(v: Vec<(String, String)>) -> Props {
        Props(v.into_iter().collect())
    }
}

impl Props {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(String::as_str)
    }

    /// The number of properties.
    pub fn size(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// What the properties take in memory, about.
    pub fn bytes(&self) -> u64 {
        self.0
            .iter()
            .map(|(k, v)| (k.len() + v.len()) as u64 + ENTRY)
            .sum()
    }

    /// Lays a style's properties over its parents' (see `lay`).
    pub fn overlay(&mut self, o: &[(String, String)]) {
        self.lay(&mut o.iter().map(|(k, v)| (k, v)));
    }

    /// Lays resolved properties over others (see `lay`).
    pub fn overlay_props(&mut self, o: &Props) {
        self.lay(&mut o.0.iter());
    }

    /// A margin of a kind of property element (`paragraph`, `graphic`): the
    /// side's own attribute, else the `fo:margin` shorthand.
    pub fn margin(&self, kind: &str, side: &str) -> Option<&str> {
        self.get(&format!("{kind}/fo:margin-{side}"))
            .or_else(|| self.get(&format!("{kind}/fo:margin")))
    }

    /// Lays one level over the properties of the levels before it. A property
    /// can be set in several ways, and the nearest level wins whichever way it
    /// used (`REPLACES`, `GROUPS`). A percentage font size, and a percentage
    /// paragraph margin (20.199 to 20.202), is taken against the value the
    /// levels before it give; with none it stays a percentage. What one level
    /// sets in several ways is left to the readers.
    fn lay(&mut self, level: &mut dyn Iterator<Item = (&String, &String)>) {
        let level: Vec<_> = level.collect();
        let own = |k: &str| level.iter().find(|(x, _)| *x == k).map(|(_, v)| v.as_str());
        // Taken before the drops below remove the values they refer to.
        let mut taken: Vec<(String, String)> = Vec::new();
        for key in FONT_SIZES {
            if let Some(f) = own(key).and_then(percent)
                && let Some(s) = self.get(key).and_then(|b| taken_of(b, f))
            {
                taken.push(((*key).into(), s));
            }
        }
        for side in SIDES {
            let key = format!("paragraph/fo:margin-{side}");
            if let Some(f) = own(&key)
                .or_else(|| own("paragraph/fo:margin"))
                .and_then(percent)
                && let Some(s) = self.margin("paragraph", side).and_then(|b| taken_of(b, f))
            {
                taken.push((key, s));
            }
        }
        for (k, v) in &level {
            let Some((kind, attr)) = k.split_once('/') else {
                continue;
            };
            for (set, value, dropped) in REPLACES {
                if attr == *set && value.is_none_or(|x| x == v.as_str()) {
                    for d in *dropped {
                        self.0.remove(&format!("{kind}/{d}"));
                    }
                }
            }
            for (_, members) in GROUPS.iter().filter(|(lines, _)| lines.contains(&attr)) {
                for d in members.iter().filter(|d| **d != attr) {
                    self.0.remove(&format!("{kind}/{d}"));
                }
            }
        }
        self.0
            .extend(level.into_iter().map(|(k, v)| (k.clone(), v.clone())));
        self.0.extend(taken);
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
    /// The base64 text of a picture the level holds inline.
    pub data: Option<String>,
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
    /// draw:gradient, draw:hatch, draw:fill-image, draw:stroke-dash,
    /// draw:marker, draw:opacity: (element name, name) to attributes.
    pub objects: HashMap<(String, String), Props>,
    /// Table templates: name to (part, cell style) pairs (first-row, body,
    /// odd-rows...).
    pub table_templates: HashMap<String, Vec<(String, String)>>,
    resolved: Resolved,
}

/// (with the family default, family, name) of a resolution; `None` for a
/// name that is no style.
type ResolvedKey = (bool, String, Option<String>);

/// The resolved styles, and what they took in memory since the caller last
/// asked.
#[derive(Default)]
struct Resolved {
    map: RefCell<HashMap<ResolvedKey, Rc<Props>>>,
    charge: Cell<u64>,
    #[cfg(test)]
    walks: Cell<usize>,
}

/// The attributes of an element. One repeated is counted once, as
/// `Node::attr` reads it: the first.
fn attrs_of(n: &Node) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    n.attrs
        .iter()
        .filter(|(k, _)| seen.insert(k.as_str()))
        .cloned()
        .collect()
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
    attrs_of(n)
        .into_iter()
        .map(|(k, v)| (format!("{kind}/{k}"), v))
        .collect()
}

/// `v` with each key once, at the place of its last value, as setting the
/// pairs one after the other would leave them.
fn last_wins(v: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    let mut out: Vec<_> = v
        .into_iter()
        .rev()
        .filter(|(k, _)| seen.insert(k.clone()))
        .collect();
    out.reverse();
    out
}

impl Styles {
    /// Reads the style elements under `n` (office:styles,
    /// office:automatic-styles, office:font-face-decls).
    pub fn add(&mut self, n: &Node, automatic: bool) {
        self.resolved.map.get_mut().clear();
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
                            if let Some(l) = p.child("text:list-style") {
                                def.list = Some(self.list(l));
                            }
                            for g in p.nodes() {
                                if g.name == "text:list-style" {
                                    continue;
                                }
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
                    def.props = last_wins(def.props);
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
                                for (k, val) in attrs_of(g) {
                                    v.push((format!("{prefix}{k}"), val));
                                }
                            }
                        }
                    }
                    if let Some(name) = c.attr("style:name") {
                        self.page_layouts.insert(name.to_string(), Props::from(v));
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
                    self.defaults.insert(family, last_wins(v));
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
                "draw:gradient" | "draw:hatch" | "draw:fill-image" | "draw:stroke-dash"
                | "draw:marker" | "draw:opacity" => {
                    if let Some(name) = c.attr("draw:name") {
                        let mut p = attrs_of(c);
                        // A flat file holds the picture inline.
                        if let Some(b) = c.child("office:binary-data") {
                            p.push(("xlink:href".into(), format!("data:{}", b.own_text())));
                        }
                        self.objects
                            .insert((c.name.clone(), name.to_string()), Props::from(p));
                    }
                }
                "text:list-style" => {
                    let i = self.list(c);
                    if let Some(name) = c.attr("style:name") {
                        self.list_names.insert(name.to_string(), i);
                    }
                }
                "style:font-face" => {
                    // A face with no family stands for its own name.
                    if let Some(name) = c.attr("style:name") {
                        let fam = c.attr("svg:font-family").unwrap_or(name);
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
                data: lv.child("office:binary-data").map(|b| b.own_text()),
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
                            attrs_of(g)
                                .into_iter()
                                .map(|(k, v)| (format!("label-alignment/{k}"), v)),
                        );
                    }
                }
            }
            x.props = Props::from(p);
            def.levels.push((level, x));
        }
        self.lists.push(def);
        self.lists.len() - 1
    }

    pub fn get(&self, family: &str, name: &str) -> Option<&StyleDef> {
        self.styles.get(&(family.to_string(), name.to_string()))
    }

    /// The list style a style or its parents carry, the styles of `family`
    /// and then the graphic ones being looked at.
    pub fn list_of(&self, family: &str, name: Option<&str>) -> Option<&ListDef> {
        let mut cur = name;
        let mut n = 0;
        while let Some(s) = cur.take() {
            n += 1;
            if n > 32 {
                break;
            }
            let st = self.get(family, s).or_else(|| self.get("graphic", s))?;
            if let Some(i) = st.list {
                return self.lists.get(i);
            }
            cur = st.parent.as_deref();
        }
        None
    }

    /// A draw:gradient, draw:hatch... by its element name and its name.
    pub fn object(&self, kind: &str, name: &str) -> Option<&Props> {
        self.objects.get(&(kind.to_string(), name.to_string()))
    }

    /// The style and its parents of `family`, nearest first, as `resolve` and
    /// `chain` read them.
    pub fn lineage<'a>(&'a self, family: &str, name: Option<&'a str>) -> Vec<&'a StyleDef> {
        self.parents(family, name, false)
    }

    /// The style and its parents, nearest first. A style met again (one that
    /// is its own parent) ends the chain, and so does a chain of 33. With
    /// `via_graphic`, a name that is no style of `family` is looked up among
    /// the graphic styles.
    fn parents<'a>(
        &'a self,
        family: &str,
        name: Option<&'a str>,
        via_graphic: bool,
    ) -> Vec<&'a StyleDef> {
        let mut chain = vec![];
        let mut seen: Vec<&str> = vec![];
        let mut cur = name;
        while let Some(n) = cur.take() {
            if chain.len() > 32 || seen.contains(&n) {
                break;
            }
            seen.push(n);
            let s = self
                .get(family, n)
                .or_else(|| via_graphic.then(|| self.get("graphic", n)).flatten());
            if let Some(s) = s {
                chain.push(s);
                cur = s.parent.as_deref();
            }
        }
        chain
    }

    /// The properties of a style over its parents', resolved once per family
    /// and name: a later call gets the same properties.
    fn cached(&self, defaults: bool, family: &str, name: Option<&str>) -> Rc<Props> {
        let via_graphic = defaults && family == "presentation";
        // A name that is no style resolves as no name does.
        let name = name.filter(|n| {
            self.get(family, n).is_some() || (via_graphic && self.get("graphic", n).is_some())
        });
        let key = (defaults, family.to_string(), name.map(str::to_string));
        if let Some(p) = self.resolved.map.borrow().get(&key) {
            return Rc::clone(p);
        }
        #[cfg(test)]
        self.resolved.walks.set(self.resolved.walks.get() + 1);
        let mut out = Props::default();
        if defaults {
            // Presentation styles are graphic styles with more.
            let family = if via_graphic { "graphic" } else { family };
            if let Some(d) = self.defaults.get(family) {
                out.overlay(d);
            }
        }
        for s in self.parents(family, name, via_graphic).iter().rev() {
            out.overlay(&s.props);
        }
        let held =
            out.bytes() + (key.1.len() + key.2.as_ref().map_or(0, String::len)) as u64 + ENTRY;
        self.resolved.charge.set(self.resolved.charge.get() + held);
        let p = Rc::new(out);
        self.resolved.map.borrow_mut().insert(key, Rc::clone(&p));
        p
    }

    /// The style's properties over its parents' (family default first).
    pub fn resolve(&self, family: &str, name: Option<&str>) -> Rc<Props> {
        // A drawing object with no style has the style called "standard".
        let name = name.or((family == "graphic").then_some("standard"));
        self.cached(true, family, name)
    }

    /// The style's properties over its parents', with no family default.
    pub fn chain(&self, family: &str, name: Option<&str>) -> Rc<Props> {
        self.cached(false, family, name)
    }

    /// The memory the resolved styles took since the last call, in bytes.
    pub fn take_charge(&self) -> u64 {
        self.resolved.charge.take()
    }

    /// How many styles were resolved rather than found resolved.
    #[cfg(test)]
    pub(crate) fn walks(&self) -> usize {
        self.resolved.walks.get()
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

    #[test]
    fn a_style_that_is_its_own_parent_is_read_once() {
        let x = br##"<office:styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"><style:style style:name="a" style:family="paragraph" style:parent-style-name="a"><style:paragraph-properties fo:text-align="center"/></style:style></office:styles>"##;
        let n = super::super::xml::parse(x, &mut super::super::xml::within(1 << 20)).unwrap();
        let mut s = Styles::default();
        s.add(&n, false);
        let p = s.resolve("paragraph", Some("a"));
        assert_eq!(p.get("paragraph/fo:text-align"), Some("center"));
        assert_eq!(p.size(), 1, "{p:?}");
    }

    fn styles_of(x: &[u8]) -> Styles {
        let n = super::super::xml::parse(x, &mut super::super::xml::within(1 << 20)).unwrap();
        let mut s = Styles::default();
        s.add(&n, false);
        s
    }

    #[test]
    fn a_repeated_attribute_counts_once_as_the_reader_has_it() {
        let x = br##"<office:styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"><style:style style:name="a" style:family="paragraph"><style:text-properties fo:color="#ff0000" fo:font-size="9pt" fo:color="#00ff00"/></style:style><style:style style:name="b" style:family="paragraph"><style:text-properties fo:color="#111111"/><style:text-properties fo:color="#222222"/></style:style></office:styles>"##;
        let n = super::super::xml::parse(x, &mut super::super::xml::within(1 << 20)).unwrap();
        // The reader keeps both and `Node::attr` gives the first.
        let e = n
            .child("style:style")
            .unwrap()
            .child("style:text-properties");
        assert_eq!(e.unwrap().attrs.len(), 3);
        assert_eq!(e.unwrap().attr("fo:color"), Some("#ff0000"));
        let s = styles_of(x);
        assert_eq!(s.get("paragraph", "a").unwrap().props.len(), 2);
        let p = s.resolve("paragraph", Some("a"));
        assert_eq!(p.get("text/fo:color"), Some("#ff0000"));
        assert_eq!(p.size(), 2);
        // Across elements the later one wins, and the style keeps one.
        assert_eq!(s.get("paragraph", "b").unwrap().props.len(), 1);
        let p = s.resolve("paragraph", Some("b"));
        assert_eq!(p.get("text/fo:color"), Some("#222222"));
    }

    #[test]
    fn a_style_used_many_times_is_resolved_once() {
        let x = br##"<office:styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"><style:style style:name="a" style:family="paragraph"><style:text-properties fo:color="#ff0000"/></style:style><style:style style:name="b" style:family="paragraph" style:parent-style-name="a"><style:text-properties fo:font-size="9pt"/></style:style></office:styles>"##;
        let s = styles_of(x);
        for i in 0..1000 {
            let p = s.resolve("paragraph", Some("b"));
            assert_eq!(p.get("text/fo:color"), Some("#ff0000"));
            // Names that are no style resolve as one.
            s.resolve("paragraph", Some(&format!("missing{i}")));
        }
        assert_eq!(s.resolved.walks.get(), 2);
        let held = s.take_charge();
        assert!(held > 0);
        assert_eq!(s.take_charge(), 0);
        // Without the family default it is another resolution.
        assert_eq!(
            s.chain("paragraph", Some("b")).get("text/fo:color"),
            Some("#ff0000")
        );
        assert_eq!(s.resolved.walks.get(), 3);
        assert!(s.take_charge() > 0);
    }
}
