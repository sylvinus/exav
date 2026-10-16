//! The shapes of a page with what they inherit ([MS-VSDX] 2.2.5.4): from
//! the master shape they instantiate, and from style sheets. A cell is
//! looked up in the shape itself, then in its master shape, then in the
//! style sheet of its kind (line, fill or text) and the styles that one
//! inherits from. A cell found in a master is evaluated again from its
//! formula, as the shape that inherits it may have another size.

use super::formula::{self, Env, Val};
use super::sheet::{Cell, Sheet};
use crate::formats::office::slides::error::Result;
use crate::formats::office::slides::limits::Budget;
use std::cell::{Cell as StdCell, RefCell};
use std::collections::HashMap;

/// What the document part holds.
#[derive(Default)]
pub struct Doc {
    /// The colour table past the 24 fixed entries.
    pub colors: HashMap<u32, u32>,
    /// The font table, by position.
    pub faces: Vec<String>,
    pub styles: HashMap<u32, Sheet>,
    /// The theme's heading and body fonts.
    pub major_font: Option<String>,
    pub minor_font: Option<String>,
    pub theme: Theme,
}

/// The colours of the document's theme ([MS-VSDX] 2.2.7.4).
#[derive(Default)]
pub struct Theme {
    /// dk1, lt1, accent1 to accent6: what quick style colours 0 to 7 name.
    pub scheme: Vec<u32>,
    pub background: Option<u32>,
    /// The seven colours of each variation, which quick style colours 100
    /// to 106 name.
    pub variations: Vec<Vec<u32>>,
}

/// A master: its top-level shapes.
pub struct Master {
    pub shapes: Vec<Sheet>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    /// In the shape of the page.
    Local,
    /// In its master shape: evaluated again for this shape.
    Master,
    /// In a style sheet.
    Style,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Line,
    Fill,
    Text,
}

/// The style a cell is inherited from, by its name.
fn kind_of(name: &str) -> Option<Kind> {
    Some(match name {
        "LineWeight"
        | "LineColor"
        | "LinePattern"
        | "Rounding"
        | "EndArrowSize"
        | "BeginArrow"
        | "EndArrow"
        | "LineCap"
        | "BeginArrowSize"
        | "LineColorTrans"
        | "CompoundType"
        | "LineGradientEnabled"
        | "LineGradientDir"
        | "LineGradientAngle" => Kind::Line,
        "FillForegnd"
        | "FillBkgnd"
        | "FillPattern"
        | "ShdwForegnd"
        | "ShdwPattern"
        | "FillForegndTrans"
        | "FillBkgndTrans"
        | "ShdwForegndTrans"
        | "FillGradientEnabled"
        | "FillGradientDir"
        | "FillGradientAngle"
        | "RotateGradientWithShape"
        | "UseGroupGradient"
        | "ShapeShdwType"
        | "ShapeShdwOffsetX"
        | "ShapeShdwOffsetY"
        | "ShapeShdwObliqueAngle"
        | "ShapeShdwScaleFactor"
        | "ShapeShdwBlur"
        | "ShapeShdwShow"
        | "GlowSize"
        | "BevelTopType"
        | "ReflectionSize"
        | "SoftEdgesSize"
        | "QuickStyleFillColor"
        | "QuickStyleShadowColor"
        | "VariationColorIndex" => Kind::Fill,
        "QuickStyleLineColor" => Kind::Line,
        "QuickStyleFontColor" => Kind::Text,
        "LeftMargin" | "RightMargin" | "TopMargin" | "BottomMargin" | "VerticalAlign"
        | "TextBkgnd" | "TextBkgndTrans" | "DefaultTabStop" | "TextDirection" | "HideText" => {
            Kind::Text
        }
        _ => return None,
    })
}

fn section_kind(sec: &str) -> Option<Kind> {
    match sec {
        "Character" | "Paragraph" | "Tabs" => Some(Kind::Text),
        "FillGradient" => Some(Kind::Fill),
        "LineGradient" => Some(Kind::Line),
        _ => None,
    }
}

pub use super::sheet::RowKey;

pub struct Node<'a> {
    /// The shape of the page, then its master shape.
    pub layers: Vec<&'a Sheet>,
    /// Whether the first layer is a shape of the page and not a master's.
    pub inst: bool,
    /// The master the master layer is of.
    pub master: Option<u32>,
    pub children: Vec<usize>,
}

pub struct Tree<'a> {
    doc: &'a Doc,
    masters: &'a HashMap<u32, Master>,
    pub nodes: Vec<Node<'a>>,
    pub roots: Vec<usize>,
    /// The node of a master shape, by master and shape id: what `Sheet.N!`
    /// in the formula of an inherited cell names.
    by_master: HashMap<(u32, u32), usize>,
    memo: RefCell<HashMap<(usize, String), Option<Val>>>,
    steps: StdCell<u32>,
    depth: StdCell<u32>,
}

/// Formula evaluations for one page.
const MAX_EVALS: u32 = 2_000_000;
/// Nesting of groups and of masters instantiated in masters.
const MAX_NESTING: u32 = 48;

fn find_shape(shapes: &[Sheet], id: u32, depth: u32) -> Option<&Sheet> {
    if depth > MAX_NESTING {
        return None;
    }
    shapes.iter().find_map(|s| {
        if s.id == id {
            Some(s)
        } else {
            find_shape(&s.shapes, id, depth + 1)
        }
    })
}

impl<'a> Tree<'a> {
    /// The tree of `tops`, the top-level shapes of a page. Each node is
    /// charged to the budget as a shape.
    pub fn build(
        doc: &'a Doc,
        masters: &'a HashMap<u32, Master>,
        tops: &'a [Sheet],
        budget: &mut Budget,
    ) -> Result<Tree<'a>> {
        let mut t = Tree {
            doc,
            masters,
            nodes: vec![],
            roots: vec![],
            by_master: HashMap::new(),
            memo: RefCell::new(HashMap::new()),
            steps: StdCell::new(0),
            depth: StdCell::new(0),
        };
        for s in tops {
            let i = t.add(Some(s), None, None, budget, 0)?;
            t.roots.push(i);
        }
        Ok(t)
    }

    fn add(
        &mut self,
        inst: Option<&'a Sheet>,
        mshape: Option<&'a Sheet>,
        master: Option<u32>,
        budget: &mut Budget,
        depth: u32,
    ) -> Result<usize> {
        budget.shape(0)?;
        let masters: &'a HashMap<u32, Master> = self.masters;
        let (mut mshape, mut master) = (mshape, master);
        let mut inherited: &'a [Sheet] = &[];
        if let Some(m) = inst
            .and_then(|s| s.master)
            .filter(|m| masters.contains_key(m))
        {
            let shapes: &'a [Sheet] = &masters[&m].shapes;
            master = Some(m);
            if shapes.len() == 1 {
                mshape = Some(&shapes[0]);
            } else {
                mshape = None;
                inherited = shapes;
            }
        }
        if let Some(ms) = mshape {
            inherited = &ms.shapes;
        }
        let idx = self.nodes.len();
        self.nodes.push(Node {
            layers: inst.into_iter().chain(mshape).collect(),
            inst: inst.is_some(),
            master,
            children: vec![],
        });
        if let (Some(m), Some(ms)) = (master, mshape) {
            self.by_master.entry((m, ms.id)).or_insert(idx);
        }
        if depth >= MAX_NESTING {
            return Ok(idx);
        }
        let own: &'a [Sheet] = inst.map(|s| &s.shapes[..]).unwrap_or(&[]);
        let mut used = vec![false; own.len()];
        let mut kids = vec![];
        for mc in inherited {
            let pos = own
                .iter()
                .position(|c| c.master_shape == Some(mc.id) && c.master.is_none());
            kids.push(match pos {
                Some(p) => {
                    used[p] = true;
                    self.add(Some(&own[p]), Some(mc), master, budget, depth + 1)?
                }
                None => self.add(None, Some(mc), master, budget, depth + 1)?,
            });
        }
        for (i, c) in own.iter().enumerate() {
            if used[i] {
                continue;
            }
            // A MasterShape that is not a direct child of the master shape.
            let ms = match (c.master, c.master_shape, master) {
                (None, Some(id), Some(m)) => find_shape(&masters[&m].shapes, id, 0),
                _ => None,
            };
            kids.push(self.add(Some(c), ms, master, budget, depth + 1)?);
        }
        self.nodes[idx].children = kids;
        Ok(idx)
    }

    /// The first layer's answer to `f` that has one.
    fn first<T>(&self, n: usize, f: impl Fn(&'a Sheet) -> Option<T>) -> Option<T> {
        self.nodes[n].layers.iter().find_map(|l| f(l))
    }

    pub fn kind(&self, n: usize) -> &'a str {
        let node = &self.nodes[n];
        // The shape's own kind, else its master shape's.
        let inst = node.layers.first().filter(|_| node.inst);
        match (inst, node.layers.last()) {
            (Some(i), Some(m)) if i.kind == "Shape" && !std::ptr::eq(*i, *m) => &m.kind,
            (Some(i), _) => &i.kind,
            (None, Some(m)) => &m.kind,
            _ => "Shape",
        }
    }

    pub fn name(&self, n: usize) -> &'a str {
        self.first(n, |l| (!l.name.is_empty()).then_some(l.name.as_str()))
            .unwrap_or("")
    }

    pub fn deleted(&self, n: usize) -> bool {
        let node = &self.nodes[n];
        node.inst && node.layers.first().is_some_and(|l| l.del)
    }

    pub fn pieces(&self, n: usize) -> Option<&'a [super::sheet::Piece]> {
        self.first(n, |l| l.text.as_deref())
    }

    pub fn foreign(&self, n: usize) -> Option<&'a super::sheet::Foreign> {
        self.first(n, |l| l.foreign.as_ref())
    }

    fn style_id(&self, n: usize, k: Kind) -> Option<u32> {
        self.first(n, |l| match k {
            Kind::Line => l.line_style,
            Kind::Fill => l.fill_style,
            Kind::Text => l.text_style,
        })
    }

    /// The style sheets `n` inherits from for `k`: its own, then its parents.
    fn styles(&self, n: usize, k: Kind) -> Vec<&'a Sheet> {
        let mut out = vec![];
        let mut id = self.style_id(n, k);
        while let Some(i) = id {
            let Some(s) = self.doc.styles.get(&i) else {
                break;
            };
            if out.len() >= 16 || out.iter().any(|o: &&Sheet| std::ptr::eq(*o, s)) {
                break;
            }
            out.push(s);
            id = match k {
                Kind::Line => s.line_style,
                Kind::Fill => s.fill_style,
                Kind::Text => s.text_style,
            };
        }
        out
    }

    /// A cell by name: in the shape, its master shape, its styles.
    pub fn find(&self, n: usize, name: &str) -> Option<(&'a Cell, Origin)> {
        let node = &self.nodes[n];
        for (i, l) in node.layers.iter().enumerate() {
            if let Some(c) = l.cells.get(name) {
                if c.v.is_some() || c.formula().is_some() {
                    let o = if i == 0 && node.inst {
                        Origin::Local
                    } else {
                        Origin::Master
                    };
                    return Some((c, o));
                }
            }
        }
        let k = kind_of(name)?;
        self.styles(n, k)
            .into_iter()
            .find_map(|s| s.cells.get(name).filter(|c| c.v.is_some()))
            .map(|c| (c, Origin::Style))
    }

    pub fn val(&self, n: usize, name: &str) -> Option<Val> {
        let (c, o) = self.find(n, name)?;
        match self.cell_val(n, name, c, o)? {
            Val::Str(s) if s == "Themed" => self.themed(n, name),
            v => Some(v),
        }
    }

    /// The colour a quick style cell (`QuickStyleFillColor`...) names in
    /// the theme.
    fn theme_color(&self, n: usize, quick: &str) -> Option<u32> {
        let th = &self.doc.theme;
        // Only a shape or master that sets the quick style uses the theme;
        // the style sheets' own value is the one for "not set".
        let (c, o) = self.find(n, quick)?;
        if o == Origin::Style {
            return None;
        }
        let q = self.cell_val(n, quick, c, o)?.num()?;
        match q as i64 {
            i @ 0..=7 => th.scheme.get(i as usize).copied(),
            8 => th.background.or(th.scheme.get(1).copied()),
            // 200 to 206 are in files written by Visio 2013; the
            // specification names 100 to 106 only. Their colours are the
            // same variation colours.
            i @ (100..=106 | 200..=206) => {
                // An index the theme does not have (65534 is the one a
                // document without a variation gives) is the first.
                let v = self.num(n, "VariationColorIndex").unwrap_or(0.0).max(0.0) as usize;
                let v = th.variations.get(v).or(th.variations.first())?;
                v.get((i % 100) as usize).copied()
            }
            _ => None,
        }
    }

    /// What a cell the theme gives (`Themed`) is: the theme's colour for
    /// the quick style colours, the root style sheet's value otherwise.
    fn themed(&self, n: usize, name: &str) -> Option<Val> {
        let quick = match name {
            "FillForegnd" => "QuickStyleFillColor",
            "LineColor" => "QuickStyleLineColor",
            "ShdwForegnd" => "QuickStyleShadowColor",
            _ => "",
        };
        if let Some(c) = self.theme_color(n, quick) {
            return Some(Val::Color(c));
        }
        let c = self.doc.styles.get(&0)?.cells.get(name)?;
        Some(parse_val(c.v.as_deref()?)).filter(|v| *v != Val::Str("Themed".into()))
    }

    fn themed_row(&self, n: usize, cell: &str) -> Option<Val> {
        match cell {
            "Color" => self.theme_color(n, "QuickStyleFontColor").map(Val::Color),
            "Style" => Some(Val::Num(0.0)),
            "Font" => self.doc.minor_font.clone().map(Val::Str),
            _ => None,
        }
    }

    pub fn num(&self, n: usize, name: &str) -> Option<f64> {
        self.val(n, name).and_then(|v| v.num())
    }

    /// The colour of a cell: a `#RRGGBB` value, an RGB formula or an index
    /// of the colour table.
    pub fn color(&self, n: usize, name: &str) -> Option<u32> {
        self.to_color(&self.val(n, name)?)
    }

    pub fn to_color(&self, v: &Val) -> Option<u32> {
        match v {
            Val::Color(c) => Some(*c),
            Val::Num(x) => {
                formula::parse_color(&format!("{x}"), &|i| self.doc.colors.get(&i).copied())
            }
            Val::Str(s) => formula::parse_color(s, &|i| self.doc.colors.get(&i).copied()),
        }
    }

    /// The font a cell names: by its index in the font table, or by name.
    pub fn font(&self, v: &Val) -> Option<String> {
        let s = match v {
            Val::Str(s) => s.trim().to_string(),
            Val::Num(x) => format!("{x}"),
            Val::Color(_) => return None,
        };
        if s.is_empty() {
            return None;
        }
        if s == "Themed" {
            return self.doc.minor_font.clone();
        }
        match s.parse::<usize>() {
            Ok(i) => self.doc.faces.get(i).cloned(),
            Err(_) => Some(s),
        }
    }

    fn cell_val(&self, n: usize, key: &str, c: &Cell, o: Origin) -> Option<Val> {
        if o == Origin::Master {
            if let Some(v) = c.formula().and_then(|f| self.eval(n, key, f)) {
                return Some(v);
            }
        }
        match c.v.as_deref() {
            Some(v) => Some(parse_val(v)),
            None => c.formula().and_then(|f| self.eval(n, key, f)),
        }
    }

    fn eval(&self, n: usize, key: &str, f: &str) -> Option<Val> {
        let k = (n, key.to_string());
        if let Some(v) = self.memo.borrow().get(&k) {
            return v.clone();
        }
        let steps = self.steps.get();
        if steps >= MAX_EVALS || self.depth.get() >= 32 {
            return None;
        }
        self.steps.set(steps + 1);
        // A formula that depends on itself finds this and fails.
        self.memo.borrow_mut().insert(k.clone(), None);
        self.depth.set(self.depth.get() + 1);
        let v = formula::eval(f, &mut NodeEnv { t: self, node: n });
        self.depth.set(self.depth.get() - 1);
        self.memo.borrow_mut().insert(k, v.clone());
        v
    }

    /// The ids of the sections named `sec`, ascending.
    pub fn sections(&self, n: usize, sec: &str) -> Vec<u32> {
        let mut out: Vec<u32> = self.nodes[n]
            .layers
            .iter()
            .flat_map(|l| l.sections.iter())
            .filter(|s| s.name == sec && !s.del)
            .map(|s| s.ix.unwrap_or(0))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// The rows of a section with their types, merged over the master
    /// shape: by index in ascending order, or by name in the order of the
    /// master. A row the shape deletes is left out.
    pub fn rows(&self, n: usize, sec: &str, six: Option<u32>) -> Vec<(RowKey, Option<&'a str>)> {
        // The rows in order, with `None` where one was deleted, and where
        // each key is.
        let mut order: Vec<Option<RowKey>> = vec![];
        let mut at: HashMap<RowKey, usize> = HashMap::new();
        for l in self.nodes[n].layers.iter().rev() {
            for s in l.sections.iter().filter(|s| matches_section(s, sec, six)) {
                for r in &s.rows {
                    let key = match (r.ix, &r.n) {
                        (Some(i), _) => RowKey::Ix(i),
                        (None, Some(name)) => RowKey::Name(name.clone()),
                        _ => continue,
                    };
                    match (r.del, at.get(&key).copied()) {
                        (true, Some(p)) => {
                            order[p] = None;
                            at.remove(&key);
                        }
                        (false, None) => {
                            at.insert(key.clone(), order.len());
                            order.push(Some(key));
                        }
                        _ => {}
                    }
                }
            }
        }
        let mut keys: Vec<RowKey> = order.into_iter().flatten().collect();
        if keys.iter().all(|k| matches!(k, RowKey::Ix(_))) {
            keys.sort_by_key(|k| match k {
                RowKey::Ix(i) => *i,
                RowKey::Name(_) => 0,
            });
        }
        keys.into_iter()
            .map(|k| {
                let t = self.nodes[n].layers.iter().find_map(|l| {
                    l.sections
                        .iter()
                        .filter(|s| matches_section(s, sec, six))
                        .find_map(|s| s.find_row(&k))
                        .and_then(|r| r.t.as_deref())
                });
                (k, t)
            })
            .collect()
    }

    /// A cell of a row, wherever the layers have it.
    fn row_cell(
        &self,
        n: usize,
        sec: &str,
        six: Option<u32>,
        key: &RowKey,
        cell: &str,
    ) -> Option<(&'a Cell, Origin)> {
        let node = &self.nodes[n];
        for (i, l) in node.layers.iter().enumerate() {
            for s in l.sections.iter().filter(|s| matches_section(s, sec, six)) {
                if let Some(r) = s.find_row(key) {
                    if r.del {
                        return None;
                    }
                    if let Some(c) = r.cells.get(cell) {
                        if c.v.is_some() || c.formula().is_some() {
                            let o = if i == 0 && node.inst {
                                Origin::Local
                            } else {
                                Origin::Master
                            };
                            return Some((c, o));
                        }
                    }
                }
            }
        }
        let k = section_kind(sec)?;
        self.styles(n, k).into_iter().find_map(|st| {
            st.sections
                .iter()
                .filter(|s| matches_section(s, sec, six))
                .filter_map(|s| s.find_row(key))
                .find_map(|r| r.cells.get(cell).filter(|c| c.v.is_some()))
                .map(|c| (c, Origin::Style))
        })
    }

    pub fn row_val(
        &self,
        n: usize,
        sec: &str,
        six: Option<u32>,
        key: &RowKey,
        cell: &str,
    ) -> Option<Val> {
        let (c, o) = self.row_cell(n, sec, six, key, cell)?;
        let id = match key {
            RowKey::Ix(i) => i.to_string(),
            RowKey::Name(s) => s.clone(),
        };
        let k = format!("{sec}{}.{id}.{cell}", six.unwrap_or(0));
        match self.cell_val(n, &k, c, o)? {
            Val::Str(s) if s == "Themed" => self.themed_row(n, cell),
            v => Some(v),
        }
    }

    pub fn row_num(
        &self,
        n: usize,
        sec: &str,
        six: Option<u32>,
        key: &RowKey,
        cell: &str,
    ) -> Option<f64> {
        self.row_val(n, sec, six, key, cell).and_then(|v| v.num())
    }

    /// A cell of the section itself (NoFill, NoLine, NoShow).
    pub fn section_val(&self, n: usize, sec: &str, six: u32, cell: &str) -> Option<Val> {
        let node = &self.nodes[n];
        for (i, l) in node.layers.iter().enumerate() {
            for s in l
                .sections
                .iter()
                .filter(|s| s.name == sec && s.ix.unwrap_or(0) == six)
            {
                if let Some(c) = s.cells.get(cell) {
                    if c.v.is_some() || c.formula().is_some() {
                        let o = if i == 0 && node.inst {
                            Origin::Local
                        } else {
                            Origin::Master
                        };
                        let k = format!("{sec}{six}.{cell}");
                        return self.cell_val(n, &k, c, o);
                    }
                }
            }
        }
        None
    }

    /// A cell a formula names by path: `Geometry1.X2`, `User.Name`,
    /// `Scratch.A1`, `Controls.Row_1.Y`, `Char.Size`; a name alone is a cell
    /// of the shape.
    fn path_val(&self, n: usize, path: &str) -> Option<Val> {
        let Some((first, rest)) = path.split_once('.') else {
            return self.val(n, path);
        };
        let lower = first.to_ascii_lowercase();
        if let Some(id) = lower.strip_prefix("geometry") {
            let six = id.parse::<u32>().ok()?.checked_sub(1)?;
            return match split_digits(rest) {
                Some((cell, row)) => self.row_val(n, "Geometry", Some(six), &RowKey::Ix(row), cell),
                None => self.section_val(n, "Geometry", six, rest),
            };
        }
        let (name, cell) = match rest.split_once('.') {
            Some((a, b)) => (a, Some(b)),
            None => (rest, None),
        };
        match lower.as_str() {
            "user" | "prop" | "actions" | "controls" | "hyperlink" => {
                let sec = match lower.as_str() {
                    "user" => "User",
                    "prop" => "Property",
                    "actions" => "Actions",
                    "controls" => "Control",
                    _ => "Hyperlink",
                };
                let default = match lower.as_str() {
                    "actions" => "Menu",
                    "controls" => "X",
                    "hyperlink" => "Description",
                    _ => "Value",
                };
                self.row_val(
                    n,
                    sec,
                    None,
                    &RowKey::Name(name.to_string()),
                    cell.unwrap_or(default),
                )
            }
            "scratch" | "connections" => {
                let sec = if lower == "scratch" {
                    "Scratch"
                } else {
                    "Connection"
                };
                let (cell, id) = split_digits(rest).unwrap_or((rest, 1));
                self.row_val(n, sec, None, &RowKey::Ix(id.checked_sub(1)?), cell)
            }
            "char" | "para" => {
                let sec = if lower == "char" {
                    "Character"
                } else {
                    "Paragraph"
                };
                let (cell, id) = match rest.split_once('[') {
                    Some((c, i)) => (c, i.trim_end_matches(']').parse::<u32>().ok()?),
                    None => (rest, 1),
                };
                self.row_val(n, sec, None, &RowKey::Ix(id.checked_sub(1)?), cell)
            }
            _ => None,
        }
    }
}

fn matches_section(s: &super::sheet::Section, name: &str, six: Option<u32>) -> bool {
    s.name == name && !s.del && six.is_none_or(|i| s.ix.unwrap_or(0) == i)
}

/// `X12` as ("X", 12).
fn split_digits(s: &str) -> Option<(&str, u32)> {
    let at = s.find(|c: char| c.is_ascii_digit())?;
    if at == 0 {
        return None;
    }
    Some((&s[..at], s[at..].parse().ok()?))
}

/// A V attribute as a value.
pub fn parse_val(v: &str) -> Val {
    let t = v.trim();
    if let Some(h) = t.strip_prefix('#') {
        if h.len() == 6 {
            if let Ok(c) = u32::from_str_radix(h, 16) {
                return Val::Color(c);
            }
        }
    }
    match formula::parse_number(t) {
        Some(n) => Val::Num(n),
        None => Val::Str(v.to_string()),
    }
}

struct NodeEnv<'t, 'a> {
    t: &'t Tree<'a>,
    node: usize,
}

impl Env for NodeEnv<'_, '_> {
    fn cell(&mut self, sheet: Option<u32>, path: &str) -> Option<Val> {
        let target = match sheet {
            None => self.node,
            Some(id) => {
                let m = self.t.nodes[self.node].master?;
                *self.t.by_master.get(&(m, id))?
            }
        };
        self.t.path_val(target, path)
    }

    fn themeval(&mut self, args: &[Val]) -> Option<Val> {
        let Some(Val::Str(name)) = args.first() else {
            return None;
        };
        match name.as_str() {
            "LatinFont" => self.t.doc.minor_font.clone().map(Val::Str),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::formats::office::common::xml;
    use crate::formats::office::slides::limits::Limits;
    use crate::formats::office::slides::vsdx::sheet::{parse, Rels};

    pub fn shapes(x: &str) -> Vec<Sheet> {
        let n = xml::parse(x.as_bytes(), 100_000).unwrap();
        let rels = HashMap::new();
        n.nodes()
            .map(|s| parse(s, &Rels(&rels), &mut 0, 0))
            .collect()
    }

    fn doc(styles: &str) -> Doc {
        let mut d = Doc::default();
        for s in shapes(&format!("<S>{styles}</S>")) {
            d.styles.insert(s.id, s);
        }
        d
    }

    fn tree<'a>(d: &'a Doc, m: &'a HashMap<u32, Master>, page: &'a [Sheet]) -> Tree<'a> {
        let mut b = Budget::new(Limits::default());
        Tree::build(d, m, page, &mut b).unwrap()
    }

    #[test]
    fn a_cell_is_found_in_the_shape_then_the_master_then_the_styles() {
        let d = doc(
            "<Shape ID='0'><Cell N='LineWeight' V='0.5'/><Cell N='LinePattern' V='1'/></Shape>
             <Shape ID='1' LineStyle='0'><Cell N='LineWeight' V='0.25'/></Shape>",
        );
        let masters: HashMap<u32, Master> = [(
            7,
            Master {
                shapes: shapes(
                    "<S><Shape ID='2' LineStyle='1'><Cell N='Width' V='3'/><Cell N='LineColor' V='#ff0000'/></Shape></S>",
                ),
            },
        )]
        .into();
        let page = shapes(
            "<S><Shape ID='9' Master='7'><Cell N='Width' V='8'/><Cell N='Height' V='1'/></Shape></S>",
        );
        let t = tree(&d, &masters, &page);
        let n = t.roots[0];
        assert_eq!(t.num(n, "Width"), Some(8.0));
        assert_eq!(t.num(n, "Height"), Some(1.0));
        assert_eq!(t.color(n, "LineColor"), Some(0xFF0000));
        // The master shape's style, then the style's parent.
        assert_eq!(t.num(n, "LineWeight"), Some(0.25));
        assert_eq!(t.num(n, "LinePattern"), Some(1.0));
        assert_eq!(t.num(n, "FillPattern"), None);
        assert_eq!(t.num(n, "Nothing"), None);
    }

    #[test]
    fn a_formula_of_the_master_is_evaluated_for_the_size_of_the_instance() {
        let d = Doc::default();
        let masters: HashMap<u32, Master> = [(
            1,
            Master {
                shapes: shapes(
                    "<S><Shape ID='1'><Cell N='Width' V='2'/><Cell N='Height' V='1'/>
                      <Cell N='LocPinX' V='1' F='Width*0.5'/>
                      <Section N='User'><Row N='Gap'><Cell N='Value' V='0.25'/></Row></Section>
                      <Section N='Geometry' IX='0'><Cell N='NoFill' V='0' F='User.Gap&gt;1'/>
                       <Row T='LineTo' IX='1'><Cell N='X' V='2' F='Width-User.Gap'/><Cell N='Y' V='0'/></Row>
                       <Row T='LineTo' IX='2'><Cell N='X' V='2' F='Geometry1.X1'/><Cell N='Y' V='1' F='Height'/></Row>
                      </Section></Shape></S>",
                ),
            },
        )]
        .into();
        let page = shapes(
            "<S><Shape ID='5' Master='1'><Cell N='Width' V='10'/>
              <Section N='Geometry' IX='0'><Row T='LineTo' IX='2'><Cell N='Y' V='7'/></Row></Section></Shape></S>",
        );
        let t = tree(&d, &masters, &page);
        let n = t.roots[0];
        assert_eq!(t.num(n, "LocPinX"), Some(5.0));
        let rows = t.rows(n, "Geometry", Some(0));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].1, Some("LineTo"));
        let x = |r: usize| t.row_num(n, "Geometry", Some(0), &rows[r].0, "X");
        let y = |r: usize| t.row_num(n, "Geometry", Some(0), &rows[r].0, "Y");
        assert_eq!(x(0), Some(9.75));
        // A cell that follows another row's cell.
        assert_eq!(x(1), Some(9.75));
        // The instance's own cell, and a formula that reads the instance.
        assert_eq!(y(1), Some(7.0));
        assert_eq!(
            t.section_val(n, "Geometry", 0, "NoFill"),
            Some(Val::Num(0.0))
        );
    }

    #[test]
    fn a_master_with_one_shape_gives_its_children_to_the_instance() {
        let d = Doc::default();
        let masters: HashMap<u32, Master> = [(
            3,
            Master {
                shapes: shapes(
                    "<S><Shape ID='1' Type='Group'><Cell N='Width' V='4'/><Shapes>
                       <Shape ID='2'><Cell N='PinX' V='1' F='Sheet.1!Width*0.25'/><Cell N='Width' V='1'/></Shape>
                       <Shape ID='3'><Cell N='PinX' V='3'/></Shape></Shapes></Shape></S>",
                ),
            },
        )]
        .into();
        // The instance is twice as wide and changes the second child.
        let page = shapes(
            "<S><Shape ID='10' Type='Group' Master='3'><Cell N='Width' V='8'/><Shapes>
               <Shape ID='12' MasterShape='3'><Cell N='PinX' V='6'/></Shape>
               <Shape ID='13'/></Shapes></Shape></S>",
        );
        let t = tree(&d, &masters, &page);
        let g = t.roots[0];
        assert_eq!(t.kind(g), "Group");
        let kids = &t.nodes[g].children;
        // Master order, the child the instance overrides in place, then the
        // instance's own.
        assert_eq!(kids.len(), 3);
        assert_eq!(t.num(kids[0], "PinX"), Some(2.0));
        assert_eq!(t.num(kids[1], "PinX"), Some(6.0));
        assert!(t.nodes[kids[2]].layers.len() == 1);
        assert!(!t.deleted(kids[0]));
    }

    #[test]
    fn a_master_with_several_shapes_gives_them_as_subshapes() {
        let d = Doc::default();
        let masters: HashMap<u32, Master> = [(
            3,
            Master {
                shapes: shapes("<S><Shape ID='1'/><Shape ID='2'/></S>"),
            },
        )]
        .into();
        let page = shapes("<S><Shape ID='10' Master='3'/><Shape ID='11' Master='99'/></S>");
        let t = tree(&d, &masters, &page);
        assert_eq!(t.nodes[t.roots[0]].children.len(), 2);
        // A master that is not there is no master.
        assert!(t.nodes[t.roots[1]].children.is_empty());
    }

    #[test]
    fn formulas_that_loop_or_run_away_give_the_stored_value() {
        let d = Doc::default();
        let masters: HashMap<u32, Master> = [(
            1,
            Master {
                shapes: shapes(
                    "<S><Shape ID='1'><Cell N='Width' V='2' F='Height'/><Cell N='Height' V='3' F='Width'/></Shape></S>",
                ),
            },
        )]
        .into();
        let page = shapes("<S><Shape ID='5' Master='1'/></S>");
        let t = tree(&d, &masters, &page);
        let n = t.roots[0];
        // The loop is cut where it closes, with the value the cell holds.
        assert_eq!(t.num(n, "Width"), Some(2.0));
        assert_eq!(t.num(n, "Height"), Some(2.0));
    }

    #[test]
    fn rows_a_shape_deletes_are_left_out_and_fonts_resolve() {
        let d = Doc {
            faces: vec!["Arial".into(), "Calibri".into()],
            minor_font: Some("Segoe UI".into()),
            ..Doc::default()
        };
        let masters: HashMap<u32, Master> = [(
            1,
            Master {
                shapes: shapes(
                    "<S><Shape ID='1'><Section N='Geometry' IX='0'>
                      <Row T='MoveTo' IX='1'/><Row T='LineTo' IX='2'/><Row T='LineTo' IX='3'/></Section></Shape></S>",
                ),
            },
        )]
        .into();
        let page = shapes(
            "<S><Shape ID='5' Master='1'><Section N='Geometry' IX='0'><Row IX='2' Del='1'/></Section></Shape></S>",
        );
        let t = tree(&d, &masters, &page);
        let rows = t.rows(t.roots[0], "Geometry", Some(0));
        assert_eq!(
            rows.iter().map(|r| r.0.clone()).collect::<Vec<_>>(),
            vec![RowKey::Ix(1), RowKey::Ix(3)]
        );
        assert_eq!(t.font(&Val::Str("1".into())).as_deref(), Some("Calibri"));
        assert_eq!(t.font(&Val::Num(0.0)).as_deref(), Some("Arial"));
        assert_eq!(
            t.font(&Val::Str("Themed".into())).as_deref(),
            Some("Segoe UI")
        );
        assert_eq!(
            t.font(&Val::Str("Verdana".into())).as_deref(),
            Some("Verdana")
        );
        assert_eq!(t.font(&Val::Num(9.0)), None);
    }

    #[test]
    fn nodes_are_charged_to_the_budget() {
        let d = Doc::default();
        let masters = HashMap::new();
        let page = shapes("<S><Shape ID='1'/><Shape ID='2'/><Shape ID='3'/></S>");
        let mut b = Budget::new(Limits::default().with_max_shapes(2));
        assert!(Tree::build(&d, &masters, &page, &mut b).is_err());
    }
}
