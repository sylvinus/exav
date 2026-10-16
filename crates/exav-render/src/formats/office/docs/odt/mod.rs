//! OpenDocument text (ODT, OTT, FODT) to the document model.

mod frame;
mod list;
mod props;
mod table;
mod text;

use crate::formats::office::common::odf::{Attrs, Props, Styles};
use crate::formats::office::common::package::Zip;
use crate::formats::office::common::xml::{self, Node};
use crate::formats::office::docs::error::{Error, Result};
use crate::formats::office::docs::limits::Budget;
use crate::formats::office::docs::model::*;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Scope {
    Content,
    Master,
}

/// A style used on a paragraph or run: the named style it refers to and
/// the properties it adds.
#[derive(Clone, Debug, Default)]
pub(crate) struct Applied {
    pub style: Option<String>,
    pub rpr: RunProps,
    pub master: Option<String>,
    pub list_style: Option<String>,
    pub tabs: Vec<(String, String, Attrs)>,
    pub props: Props,
    pub break_after: bool,
}

pub(crate) struct Odt<'a> {
    pub b: &'a mut Budget,
    pub doc: Document,
    pub zip: Option<Zip<'a>>,
    pub cs: Styles,
    pub ms: Styles,
    pub styles_root: &'a Node,
    pub scope: Scope,
    ids: HashMap<(String, String), String>,
    used_ids: HashSet<String>,
    applied: HashMap<(Scope, String, String), Applied>,
    pub abstracts: HashMap<String, u32>,
    pub last_num: HashMap<String, u32>,
    pub list_ids: HashMap<String, (String, u32)>,
    pub outline_num: Option<u32>,
    pub next_bookmark: u32,
    pub bookmark_open: HashMap<String, u32>,
    pub annotation_ends: HashSet<String>,
    pub annotation_ids: HashMap<String, u32>,
    pub cur_master: String,
    pub pending_break: bool,
    pub depth: u32,
    pub image_cache: HashMap<String, Option<usize>>,
    pub even_odd: bool,
    pub in_header: bool,
}

pub(crate) fn read_odt(mut zip: Zip<'_>, budget: &mut Budget) -> Result<Document> {
    let max = budget.limits.max_part;
    if let Some(m) = zip.read("mimetype", 256)? {
        let m = String::from_utf8_lossy(&m);
        if !m
            .trim()
            .starts_with("application/vnd.oasis.opendocument.text")
        {
            return Err(Error::NotFormat(format!("mimetype {}", m.trim())));
        }
    }
    let content = zip
        .read("content.xml", max)?
        .ok_or_else(|| Error::NotFormat("no content.xml".into()))?;
    budget.alloc(content.len() as u64)?;
    let styles = zip.read("styles.xml", max)?.unwrap_or_default();
    budget.alloc(styles.len() as u64)?;
    if zip.names().iter().any(|n| n == "META-INF/manifest.xml") {
        if let Some(m) = zip.read("META-INF/manifest.xml", 1 << 22)? {
            if find(&m, b"manifest:encryption-data") {
                return Err(Error::Encrypted);
            }
        }
    }
    let content = xml::parse(&content, xml::MAX_ELEMENTS)?;
    let styles = if styles.is_empty() {
        Node::default()
    } else {
        xml::parse(&styles, xml::MAX_ELEMENTS)?
    };
    convert(&styles, &content, Some(zip), budget)
}

pub(crate) fn read_fodt(input: &[u8], budget: &mut Budget) -> Result<Document> {
    let root = xml::parse(input, xml::MAX_ELEMENTS)?;
    if root.name != "office:document" {
        return Err(Error::NotFormat(format!("root element {}", root.name)));
    }
    if let Some(m) = root.attr("office:mimetype") {
        if !m.starts_with("application/vnd.oasis.opendocument.text") {
            return Err(Error::NotFormat(format!("mimetype {m}")));
        }
    }
    // The one tree plays both parts: its styles and its content.
    convert(&root, &root, None, budget)
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn convert(
    styles_root: &Node,
    content_root: &Node,
    zip: Option<Zip<'_>>,
    budget: &mut Budget,
) -> Result<Document> {
    let mut o = Odt {
        b: budget,
        doc: Document::default(),
        zip,
        cs: Styles::default(),
        ms: Styles::default(),
        styles_root,
        scope: Scope::Content,
        ids: HashMap::new(),
        used_ids: HashSet::new(),
        applied: HashMap::new(),
        abstracts: HashMap::new(),
        last_num: HashMap::new(),
        list_ids: HashMap::new(),
        outline_num: None,
        next_bookmark: 1,
        bookmark_open: HashMap::new(),
        annotation_ends: HashSet::new(),
        annotation_ids: HashMap::new(),
        cur_master: String::new(),
        pending_break: false,
        depth: 0,
        image_cache: HashMap::new(),
        even_odd: false,
        in_header: false,
    };
    o.load(styles_root, content_root);
    o.build_styles();
    let body = content_root
        .child("office:body")
        .and_then(|b| b.child("office:text"))
        .ok_or_else(|| Error::NotFormat("no text body".into()))?;
    o.collect_annotation_ends(body);
    o.body(body)?;
    o.doc.settings.even_and_odd_headers = o.even_odd;
    Ok(o.doc)
}

/// ODF names write special characters as `_20_` (their hex code).
pub(crate) fn decode_name(n: &str) -> String {
    let mut out = String::new();
    let b = n.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'_' {
            if let Some(end) = n[i + 1..].find('_') {
                let hex = &n[i + 1..i + 1 + end];
                if (2..=6).contains(&hex.len()) {
                    if let Some(c) = u32::from_str_radix(hex, 16).ok().and_then(char::from_u32) {
                        out.push(c);
                        i += end + 2;
                        continue;
                    }
                }
            }
        }
        let ch = n[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

impl<'a> Odt<'a> {
    fn load(&mut self, styles_root: &Node, content_root: &Node) {
        let mut named = vec![];
        for n in styles_root.nodes() {
            match n.name.as_str() {
                "office:font-face-decls" | "office:styles" => named.push((n, false)),
                "office:automatic-styles" => {}
                _ => {}
            }
        }
        for (n, a) in &named {
            self.cs.add(n, *a);
            self.ms.add(n, *a);
        }
        if let Some(a) = styles_root.child("office:automatic-styles") {
            self.ms.add(a, true);
            // Page layouts live in the styles part and are used through it.
            self.cs.add(a, true);
        }
        if let Some(f) = content_root.child("office:font-face-decls") {
            self.cs.add(f, false);
        }
        if let Some(a) = content_root.child("office:automatic-styles") {
            self.cs.add(a, true);
        }
        // Outline numbering.
        if let Some(os) = styles_root
            .child("office:styles")
            .and_then(|s| s.child("text:outline-style"))
        {
            let i = self.cs.list(os);
            self.cs.list_names.insert("<outline>".into(), i);
        }
    }

    pub(crate) fn styles(&self) -> &Styles {
        match self.scope {
            Scope::Content => &self.cs,
            Scope::Master => &self.ms,
        }
    }

    fn style_id(&mut self, family: &str, name: &str) -> String {
        if let Some(i) = self.ids.get(&(family.to_string(), name.to_string())) {
            return i.clone();
        }
        let decoded = decode_name(name);
        let base: String = if decoded == "Standard" && family == "paragraph" {
            "Standard".into()
        } else {
            decoded.chars().filter(|c| c.is_alphanumeric()).collect()
        };
        let base = if base.is_empty() {
            "Style".to_string()
        } else if base.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            format!("S{base}")
        } else {
            base
        };
        let mut id = if family == "text" {
            format!("{base}Char")
        } else {
            base.clone()
        };
        let mut k = 2;
        while !self.used_ids.insert(id.clone()) {
            id = format!("{base}{k}");
            k += 1;
        }
        self.ids
            .insert((family.to_string(), name.to_string()), id.clone());
        id
    }

    /// The named style a style resolves to, with the properties of the
    /// automatic styles on the way.
    pub(crate) fn apply(&mut self, family: &str, name: &str) -> Applied {
        let key = (self.scope, family.to_string(), name.to_string());
        if let Some(a) = self.applied.get(&key) {
            return a.clone();
        }
        let mut chain: Vec<String> = vec![];
        let mut cur = Some(name.to_string());
        let mut named: Option<String> = None;
        while let Some(n) = cur.take() {
            if chain.len() > 32 {
                break;
            }
            let Some(def) = self.styles().get(family, &n) else {
                break;
            };
            if def.automatic {
                chain.push(n.clone());
                cur = def.parent.clone();
            } else {
                named = Some(n);
                break;
            }
        }
        let mut a = Applied::default();
        let mut props = Props::default();
        let mut tabs = vec![];
        let mut master = None;
        let mut list_style = None;
        for n in chain.iter().rev() {
            let Some(def) = self.styles().get(family, n) else {
                continue;
            };
            props.overlay(&def.props);
            tabs.extend(
                def.children
                    .iter()
                    .filter(|c| c.1 == "style:tab-stop")
                    .cloned(),
            );
            if let Some(m) = def.attr("style:master-page-name") {
                master = Some(m.to_string());
            }
            if let Some(l) = def.attr("style:list-style-name") {
                list_style = Some(l.to_string());
            }
        }
        // A named style can carry a master page or a list too.
        if let Some(n) = &named {
            let mut cur = Some(n.clone());
            let mut depth = 0;
            while let Some(c) = cur.take() {
                depth += 1;
                if depth > 32 {
                    break;
                }
                let Some(def) = self.styles().get(family, &c) else {
                    break;
                };
                if list_style.is_none() {
                    list_style = def.attr("style:list-style-name").map(str::to_string);
                }
                if master.is_none() {
                    master = def.attr("style:master-page-name").map(str::to_string);
                }
                cur = def.parent.clone();
            }
        }
        a.style = named.map(|n| self.style_id(family, &n));
        a.master = master.filter(|m| !m.is_empty());
        a.list_style = list_style.filter(|l| !l.is_empty());
        a.break_after = props.get("paragraph/fo:break-after") == Some("page");
        let base = self.base_size(family, name);
        let rpr = props::run_props(&props, self.styles(), base);
        a.rpr = rpr;
        a.tabs = tabs;
        a.props = props;
        self.applied.insert(key, a.clone());
        a
    }

    /// The font size (half points) percentages of `family`'s style refer to.
    fn base_size(&self, family: &str, name: &str) -> u32 {
        let p = self.styles().resolve(family, Some(name));
        p.pt("text/fo:font-size")
            .map(|v| (v * 2.0) as u32)
            .filter(|v| *v > 0)
            .unwrap_or(24)
    }

    fn build_styles(&mut self) {
        // Defaults.
        let dflt = self
            .cs
            .defaults
            .get("paragraph")
            .cloned()
            .unwrap_or_default();
        let dp = Props(dflt);
        let mut rpr = props::run_props(&dp, &self.cs, 24);
        if rpr.size.is_none() {
            rpr.size = Some(24);
            rpr.size_cs = Some(24);
        }
        self.doc.defaults_run = rpr;
        self.doc.defaults_para = props::para_props(&dp, false);
        if let Some(t) = dp.twips("paragraph/style:tab-stop-distance") {
            if t > 0 {
                self.doc.settings.default_tab_stop = Some(t);
            }
        }
        // Named styles.
        let order = self.cs.order.clone();
        let mut out = vec![];
        for (family, name) in order {
            if family != "paragraph" && family != "text" {
                continue;
            }
            let Some(def) = self.cs.get(&family, &name) else {
                continue;
            };
            if def.automatic {
                continue;
            }
            let def_attrs = def.attrs.clone();
            let parent = def.parent.clone();
            let next = def.next.clone();
            let children = def.children.clone();
            let props = Props(def.props.clone());
            let id = self.style_id(&family, &name);
            let display = def_attrs
                .iter()
                .find(|a| a.0 == "style:display-name")
                .map(|a| a.1.clone())
                .unwrap_or_else(|| decode_name(&name));
            let kind = if family == "paragraph" {
                StyleKind::Paragraph
            } else {
                StyleKind::Character
            };
            let heading = display
                .strip_prefix("Heading ")
                .and_then(|n| n.parse::<u32>().ok())
                .filter(|n| (1..=9).contains(n));
            let mut st = Style::new(
                &id,
                &match heading {
                    Some(n) => format!("heading {n}"),
                    None => display.clone(),
                },
                kind,
            );
            st.based_on = parent.map(|p| self.style_id(&family, &p));
            st.next = next.map(|p| self.style_id(&family, &p));
            let base = self.base_size(&family, &name);
            st.rpr = props::run_props(&props, &self.cs, base);
            if kind == StyleKind::Paragraph {
                st.ppr = props::para_props(&props, false);
                let left = props.twips("paragraph/fo:margin-left").unwrap_or(0);
                st.ppr.tabs = props::tabs(&children, left);
                if let Some(l) = def_attrs
                    .iter()
                    .find(|a| a.0 == "style:default-outline-level")
                    .and_then(|a| a.1.parse::<u32>().ok())
                {
                    st.ppr.outline_level = Some(l.saturating_sub(1).min(9));
                }
                if let Some(h) = heading {
                    st.ppr.outline_level = Some(h - 1);
                    st.q_format = true;
                }
                if display == "Standard" {
                    st.q_format = true;
                }
                // A heading's list style (outline numbering) goes with it.
                if let Some(ls) = def_attrs
                    .iter()
                    .find(|a| a.0 == "style:list-style-name")
                    .map(|a| a.1.clone())
                    .filter(|l| !l.is_empty())
                {
                    if let Some(nid) = self.list_num(&ls, true, false) {
                        st.ppr.num_id = Some(nid);
                        st.ppr.num_level = heading.map(|h| h - 1);
                    }
                }
            }
            out.push(st);
        }
        self.doc.styles = out;
    }

    // ---- pages and sections ----

    fn collect_annotation_ends(&mut self, n: &Node) {
        let mut stack = vec![n];
        while let Some(x) = stack.pop() {
            if x.name == "office:annotation-end" {
                if let Some(name) = x.attr("office:name") {
                    self.annotation_ends.insert(name.to_string());
                }
            }
            stack.extend(x.nodes());
        }
    }

    fn default_master(&self) -> String {
        let masters = self.styles_root.child("office:master-styles");
        let first = masters.and_then(|m| m.all("style:master-page").next());
        if let Some(m) = masters.and_then(|m| {
            m.all("style:master-page")
                .find(|p| p.attr("style:name") == Some("Standard"))
        }) {
            return m.attr("style:name").unwrap_or("Standard").to_string();
        }
        first
            .and_then(|m| m.attr("style:name"))
            .unwrap_or("Standard")
            .to_string()
    }

    /// The section a master page defines.
    fn section_of(&mut self, master: &str) -> Result<Section> {
        let mut s = Section {
            width: 11906,
            height: 16838,
            ..Section::default()
        };
        let node = self
            .styles_root
            .child("office:master-styles")
            .and_then(|m| {
                m.all("style:master-page")
                    .find(|p| p.attr("style:name") == Some(master))
            })
            .or_else(|| {
                self.styles_root
                    .child("office:master-styles")
                    .and_then(|m| m.all("style:master-page").next())
            });
        let Some(node) = node else { return Ok(s) };
        let layout = node
            .attr("style:page-layout-name")
            .and_then(|l| self.ms.page_layouts.get(l))
            .cloned()
            .unwrap_or_default();
        if let Some(v) = layout.twips("fo:page-width") {
            s.width = v;
        }
        if let Some(v) = layout.twips("fo:page-height") {
            s.height = v;
        }
        s.landscape = layout.get("style:print-orientation") == Some("landscape");
        for (k, slot) in [
            ("fo:margin-top", &mut s.top),
            ("fo:margin-bottom", &mut s.bottom),
            ("fo:margin-left", &mut s.left),
            ("fo:margin-right", &mut s.right),
        ] {
            if let Some(v) = layout.twips(k) {
                *slot = v;
            } else if let Some(v) = layout.twips("fo:margin") {
                *slot = v;
            }
        }
        if layout
            .get("style:writing-mode")
            .is_some_and(|w| w.starts_with("rl"))
        {
            s.bidi = true;
        }
        if let Some(f) = layout.get("style:num-format") {
            s.page_fmt = match f {
                "i" => Some("lowerRoman"),
                "I" => Some("upperRoman"),
                "a" => Some("lowerLetter"),
                "A" => Some("upperLetter"),
                _ => None,
            };
        }
        if let Some(n) = layout
            .get("style:first-page-number")
            .and_then(|v| v.parse::<u32>().ok())
        {
            s.page_start = Some(n);
        }
        // Page borders.
        for (name, slot) in [
            ("top", &mut s.page_borders.top),
            ("left", &mut s.page_borders.left),
            ("bottom", &mut s.page_borders.bottom),
            ("right", &mut s.page_borders.right),
        ] {
            let v = layout
                .get(&format!("fo:border-{name}"))
                .or_else(|| layout.get("fo:border"));
            if let Some(v) = v {
                *slot = props::border(v, None);
            }
        }
        // Headers and footers: the body starts below them.
        let mut top = s.top;
        let mut bottom = s.bottom;
        let mut header_blocks: [Option<Vec<Block>>; 3] = [None, None, None];
        let mut footer_blocks: [Option<Vec<Block>>; 3] = [None, None, None];
        self.scope = Scope::Master;
        self.in_header = true;
        for (is_header, names) in [
            (
                true,
                ["style:header", "style:header-left", "style:header-first"],
            ),
            (
                false,
                ["style:footer", "style:footer-left", "style:footer-first"],
            ),
        ] {
            for (k, n) in names.iter().enumerate() {
                let Some(h) = node.child(n) else { continue };
                if h.attr("style:display") == Some("false") {
                    continue;
                }
                let blocks = self.blocks(h)?;
                if is_header {
                    header_blocks[k] = Some(blocks);
                } else {
                    footer_blocks[k] = Some(blocks);
                }
            }
        }
        self.in_header = false;
        self.scope = Scope::Content;
        let height = |prefix: &str| {
            let h = layout
                .twips(&format!("{prefix}:fo:min-height"))
                .unwrap_or(0);
            let m = layout
                .twips(&format!("{prefix}:fo:margin-bottom"))
                .or_else(|| layout.twips(&format!("{prefix}:fo:margin-top")))
                .unwrap_or(0);
            (h, m)
        };
        if header_blocks.iter().any(|h| h.is_some()) {
            let (h, m) = height("header");
            s.header = top;
            top += h + m;
        }
        if footer_blocks.iter().any(|h| h.is_some()) {
            let (h, m) = height("footer");
            s.footer = bottom;
            bottom += h + m;
        }
        s.top = top;
        s.bottom = bottom;
        let [hd, hl, hf] = header_blocks;
        let [fd, fl, ff] = footer_blocks;
        s.headers = HeaderFooter {
            default: hd,
            even: hl,
            first: hf,
        };
        s.footers = HeaderFooter {
            default: fd,
            even: fl,
            first: ff,
        };
        s.title_page = s.headers.first.is_some() || s.footers.first.is_some();
        if s.headers.even.is_some() || s.footers.even.is_some() {
            self.even_odd = true;
        }
        Ok(s)
    }

    fn body(&mut self, body: &Node) -> Result<()> {
        self.cur_master = String::new();
        let blocks = self.blocks_top(body)?;
        self.doc.body = blocks;
        let m = if self.cur_master.is_empty() {
            self.default_master()
        } else {
            self.cur_master.clone()
        };
        self.doc.section = self.section_of(&m)?;
        Ok(())
    }

    /// Ends the section in progress on the last paragraph of `out`.
    pub(crate) fn end_section(&mut self, out: &mut Vec<Block>) -> Result<()> {
        let m = if self.cur_master.is_empty() {
            self.default_master()
        } else {
            self.cur_master.clone()
        };
        let s = self.section_of(&m)?;
        match out.last_mut() {
            Some(Block::Para(p)) if p.section.is_none() => p.section = Some(Box::new(s)),
            _ => out.push(Block::Para(Para {
                section: Some(Box::new(s)),
                ..Para::default()
            })),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn style_names_are_decoded() {
        assert_eq!(decode_name("Heading_20_1"), "Heading 1");
        assert_eq!(decode_name("List_5f_Bullet"), "List_Bullet");
        assert_eq!(decode_name("plain"), "plain");
        assert_eq!(decode_name("a_zz_b"), "a_zz_b");
        assert_eq!(decode_name("_20"), "_20");
    }
}
