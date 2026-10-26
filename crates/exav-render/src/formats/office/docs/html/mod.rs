//! HTML pages to the document model: Word's "Save as Web Page" (a `.doc` that
//! is HTML, the most common thing named `.doc` that is not a Word document) and
//! other pages read as documents. Text, headings, lists, tables, links, and the
//! character and paragraph formatting of the style sheet and the `style`
//! attributes. Data only: scripts, frames and forms are dropped, nothing is
//! fetched, a picture held in a `data:` address is embedded and one named by a
//! file or a URL is told by its alternative text, and a link is kept only when
//! it goes to a web, mail, phone or FTP address or to a place in the page.
//!
//! The tokenizer and the style sheets are the spreadsheet converter's (Excel's
//! HTML pages): [`crate::formats::office::sheets::html`].

use crate::formats::office::common::{base64, image};
use crate::formats::office::docs::error::{Error, Result};
use crate::formats::office::docs::limits::Budget;
use crate::formats::office::docs::model::*;
use crate::formats::office::sheets::css;
use crate::formats::office::sheets::html::{get, tokenize, Sheet, Token};
use crate::formats::office::sheets::textenc::html_utf8;
use std::borrow::Cow;
use std::collections::HashMap;

mod mime;

/// Open elements kept; deeper ones are read as text of their parent.
const MAX_DEPTH: usize = 128;
/// Twips in a pixel at 96 dpi.
const PX: f64 = 15.0;
/// EMU in a pixel.
const PX_EMU: i64 = 9525;
/// The widest a picture is drawn: the text width of a letter page.
const MAX_PICTURE: i64 = 5_943_600;

/// Elements that have no end tag.
const VOID: &[&str] = &[
    "br", "hr", "img", "meta", "link", "input", "col", "base", "area", "param", "wbr", "embed",
    "source", "track",
];
/// Elements whose content is not text of the page.
const HIDDEN: &[&str] = &[
    "head", "script", "style", "title", "xml", "noscript", "template", "iframe", "frameset",
    "select", "textarea", "object", "applet", "svg", "math", "canvas", "audio", "video",
];
/// Elements that start a paragraph of their own.
const BLOCKS: &[&str] = &[
    "p",
    "div",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "pre",
    "blockquote",
    "center",
    "address",
    "li",
    "dt",
    "dd",
    "ul",
    "ol",
    "dl",
    "form",
    "fieldset",
    "legend",
    "section",
    "article",
    "header",
    "footer",
    "nav",
    "main",
    "aside",
    "figure",
    "figcaption",
    "caption",
    "body",
    "menu",
    "dir",
    "listing",
    "xmp",
    "plaintext",
];

struct Frame {
    name: String,
    /// The character properties in force, from the document's root to here.
    run: RunProps,
    /// The paragraph properties a paragraph started here has.
    para: ParaProps,
    hidden: bool,
    /// Whitespace is kept (`pre`).
    pre: bool,
    /// A list: whether numbered, and the count so far.
    list: Option<(bool, u32)>,
}

struct CellB {
    blocks: Vec<Block>,
    colspan: u32,
    rowspan: u32,
    props: CellProps,
}

#[derive(Default)]
struct TableB {
    props: TableProps,
    rows: Vec<Vec<CellB>>,
    row: Option<Vec<CellB>>,
}

enum Cont {
    Body(Vec<Block>),
    Table(TableB),
    Cell(CellB),
}

struct Link {
    target: Option<String>,
    anchor: Option<String>,
    tooltip: Option<String>,
    content: Vec<Inline>,
}

struct Html<'a> {
    b: &'a mut Budget,
    doc: Document,
    css: Sheet,
    conts: Vec<Cont>,
    frames: Vec<Frame>,
    cur: Option<Para>,
    /// Bytes of text in `cur`, and whether it ends with a space.
    cur_len: usize,
    space: bool,
    links: Vec<Link>,
    next_bookmark: u32,
    pictures: Vec<mime::Picture>,
}

pub(crate) fn read(input: &[u8], budget: &mut Budget) -> Result<Document> {
    budget.alloc(input.len() as u64 * 6)?;
    // A page saved with its pictures in one MIME message is read from it.
    let (text, pictures): (Cow<str>, Vec<mime::Picture>) = match mime::parse(input, budget)? {
        Some(m) => (Cow::Owned(m.html), m.pictures),
        None => (html_utf8(input), vec![]),
    };
    let tokens = tokenize(&text).map_err(|_| Error::TooLarge("HTML elements"))?;
    if !tokens.iter().any(|t| {
        matches!(t, Token::Start { name, .. }
            if matches!(name.as_str(), "html" | "body" | "p" | "div" | "table" | "h1" | "span"))
    }) {
        return Err(Error::NotFormat("not an HTML document".into()));
    }
    let mut css = Sheet::default();
    let mut page = None;
    for (k, t) in tokens.iter().enumerate() {
        if let Token::Start { name, .. } = t {
            if name == "style" {
                if let Some(Token::Text(c)) = tokens.get(k + 1) {
                    css.add(c);
                    page = page.or_else(|| page_rule(c));
                }
            }
        }
    }
    let mut h = Html {
        b: budget,
        doc: Document::default(),
        css,
        conts: vec![Cont::Body(vec![])],
        frames: vec![],
        cur: None,
        cur_len: 0,
        space: true,
        links: vec![],
        next_bookmark: 1,
        pictures,
    };
    h.doc.defaults_run.size = Some(24);
    h.doc.defaults_run.fonts.ascii = Some("Times New Roman".into());
    h.doc.defaults_run.fonts.hansi = Some("Times New Roman".into());
    if let Some(s) = page {
        h.doc.section = s;
    }
    let mut root = Frame {
        name: String::new(),
        run: RunProps::default(),
        para: ParaProps::default(),
        hidden: false,
        pre: false,
        list: None,
    };
    {
        // What the style sheet says of the whole page.
        let mut d = vec![];
        h.css.lookup("body", &[], &mut d);
        apply_run(&d, &mut root.run);
        apply_para(&d, &mut root.para);
    }
    h.frames.push(root);
    for t in &tokens {
        match t {
            Token::Start {
                name,
                attrs,
                closed,
            } => h.start(name, attrs, *closed)?,
            Token::End(name) => h.end(name)?,
            Token::Text(s) => h.text(s)?,
            Token::Comment(_) => {}
        }
    }
    h.finish()?;
    Ok(h.doc)
}

impl Html<'_> {
    fn top(&self) -> &Frame {
        self.frames.last().expect("the root frame stays")
    }

    fn hidden(&self) -> bool {
        self.top().hidden
    }

    /// The declarations of an element: the style sheet's for its name and
    /// classes, then its `style` attribute's.
    fn decls(&self, name: &str, attrs: &[(String, String)]) -> Vec<(String, String)> {
        let classes: Vec<&str> = get(attrs, "class")
            .map(|c| c.split_whitespace().collect())
            .unwrap_or_default();
        let mut d = vec![];
        self.css.lookup(name, &classes, &mut d);
        if let Some(s) = get(attrs, "style") {
            d.extend(css::declarations(s));
        }
        d
    }

    // ------------------------------------------------------------ paragraphs

    /// The paragraph being built, started with the properties in force.
    fn para(&mut self) -> &mut Para {
        if self.cur.is_none() {
            let top = self.top();
            self.cur = Some(Para {
                props: top.para.clone(),
                mark: RunProps::default(),
                content: vec![],
                section: None,
            });
            self.cur_len = 0;
            self.space = true;
        }
        self.cur.as_mut().expect("just made")
    }

    fn add(&mut self, i: Inline) {
        if self.links.is_empty() {
            self.para().content.push(i);
        } else {
            self.para();
            if let Some(l) = self.links.last_mut() {
                l.content.push(i);
            }
        }
    }

    fn text(&mut self, s: &str) -> Result<()> {
        if self.hidden() {
            return Ok(());
        }
        let pre = self.top().pre;
        let mut out = String::with_capacity(s.len());
        if pre {
            out.push_str(&s.replace("\r\n", "\n").replace('\r', "\n"));
        } else {
            // White space runs to one space, and none after another.
            let mut after_space = self.space;
            for c in s.chars() {
                if matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c') {
                    if !after_space {
                        out.push(' ');
                        after_space = true;
                    }
                } else {
                    out.push(c);
                    after_space = false;
                }
            }
        }
        if out.is_empty() {
            return Ok(());
        }
        self.b.alloc(out.len() as u64 * 2)?;
        self.cur_len += out.len();
        self.space = out.ends_with(' ') || out.ends_with('\n');
        let props = self.top().run.clone();
        if pre {
            // Lines are breaks in the one paragraph.
            let mut items = vec![];
            for (n, line) in out.split('\n').enumerate() {
                if n > 0 {
                    items.push(RunItem::Break(BreakKind::Line));
                }
                if !line.is_empty() {
                    items.push(RunItem::Text(line.to_string()));
                }
            }
            self.add(Inline::Run(Run { props, items }));
        } else {
            self.add(Inline::Run(Run::text(props, out)));
        }
        Ok(())
    }

    /// Ends the paragraph being built. One with no content is dropped, unless
    /// `keep` (an element that is a line of its own).
    fn flush(&mut self, keep: bool) -> Result<()> {
        while let Some(l) = self.links.pop() {
            self.link_into(l);
        }
        // The next paragraph starts at the start of a line.
        self.space = true;
        let Some(mut p) = self.cur.take() else {
            return Ok(());
        };
        // Trailing white space is not shown.
        if let Some(Inline::Run(r)) = p.content.last_mut() {
            if let Some(RunItem::Text(t)) = r.items.last_mut() {
                let trimmed = t.trim_end_matches(' ').len();
                t.truncate(trimmed);
            }
        }
        // One with nothing to show (the white space between two blocks) is not
        // a paragraph.
        let empty = p.content.iter().all(|i| {
            matches!(i, Inline::Run(r)
                if r.items.iter().all(|it| matches!(it, RunItem::Text(t) if t.is_empty())))
        });
        if empty && !keep {
            return Ok(());
        }
        self.b.paragraph(self.cur_len)?;
        self.cur_len = 0;
        self.push_block(Block::Para(p));
        Ok(())
    }

    fn push_block(&mut self, b: Block) {
        match self.conts.last_mut() {
            Some(Cont::Body(v)) => v.push(b),
            Some(Cont::Cell(c)) => c.blocks.push(b),
            _ => {
                // Content between rows of a table: the cell after it, or the page.
                if let Some(Cont::Body(v)) = self.conts.iter_mut().rev().find_map(|c| match c {
                    Cont::Body(_) | Cont::Cell(_) => Some(c),
                    Cont::Table(_) => None,
                }) {
                    v.push(b);
                }
            }
        }
    }

    fn link_into(&mut self, l: Link) {
        let inline = Inline::Hyperlink {
            target: l.target,
            anchor: l.anchor,
            tooltip: l.tooltip,
            content: l.content,
        };
        match self.links.last_mut() {
            Some(outer) => outer.content.push(inline),
            None => self.para().content.push(inline),
        }
    }

    // -------------------------------------------------------------- elements

    fn push_frame(&mut self, name: &str, attrs: &[(String, String)]) {
        if self.frames.len() >= MAX_DEPTH {
            return;
        }
        let d = self.decls(name, attrs);
        let parent = self.top();
        let mut f = Frame {
            name: name.to_string(),
            run: parent.run.clone(),
            para: parent.para.clone(),
            hidden: parent.hidden || HIDDEN.contains(&name),
            pre: parent.pre || matches!(name, "pre" | "listing" | "xmp" | "plaintext"),
            list: None,
        };
        // What the element is, before what the page says of it.
        match name {
            "b" | "strong" | "th" => f.run.bold = Some(true),
            "i" | "em" | "cite" | "dfn" | "var" | "address" => f.run.italic = Some(true),
            "u" | "ins" => f.run.underline = Some("single"),
            "s" | "strike" | "del" => f.run.strike = Some(true),
            "sub" => f.run.vert_align = Some(VertAlign::Subscript),
            "sup" => f.run.vert_align = Some(VertAlign::Superscript),
            "small" => f.run.size = Some(f.run.size.unwrap_or(24).saturating_sub(2).max(2)),
            "big" => f.run.size = Some(f.run.size.unwrap_or(24) + 2),
            "code" | "tt" | "kbd" | "samp" | "pre" | "listing" | "xmp" | "plaintext" => {
                f.run.fonts.ascii = Some("Courier New".into());
                f.run.fonts.hansi = Some("Courier New".into());
                if name == "pre" {
                    f.run.size = Some(20);
                }
            }
            "mark" => f.run.highlight = Some("yellow"),
            // A link that goes somewhere looks like one.
            "a" if get(attrs, "href").is_some_and(|h| safe_link(h) != (None, None)) => {
                f.run.color = Some(Color::Rgb(0x0563C1));
                f.run.underline = Some("single");
            }
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                f.run.bold = Some(true);
                f.run.size = Some(match name {
                    "h1" => 48,
                    "h2" => 36,
                    "h3" => 28,
                    "h4" => 24,
                    "h5" => 20,
                    _ => 16,
                });
                f.para.keep_next = Some(true);
                f.para.space_before = Some(240);
                f.para.space_after = Some(120);
                f.para.outline_level = Some(u32::from(name.as_bytes()[1] - b'1'));
            }
            "p" | "div" | "dl" | "dt" => {}
            "blockquote" | "dd" => {
                f.para.ind_left = Some(f.para.ind_left.unwrap_or(0) + 720);
            }
            "center" => f.para.jc = Some(Jc::Center),
            "font" => {
                if let Some(c) = get(attrs, "color").and_then(rgb) {
                    f.run.color = Some(Color::Rgb(c));
                }
                if let Some(face) = get(attrs, "face") {
                    set_font(&mut f.run, face);
                }
                if let Some(n) = get(attrs, "size").and_then(|s| s.trim().parse::<i32>().ok()) {
                    // The seven sizes of the old `size` attribute, in half points.
                    let table = [14, 20, 24, 28, 36, 48, 72];
                    f.run.size = Some(table[(n.clamp(1, 7) - 1) as usize]);
                }
            }
            "ul" | "menu" | "dir" => f.list = Some((false, 0)),
            "ol" => {
                f.list = Some((
                    true,
                    get(attrs, "start")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(1)
                        - 1,
                ))
            }
            _ => {}
        }
        if let Some(a) = get(attrs, "align") {
            f.para.jc = jc(a).or(f.para.jc);
        }
        apply_run(&d, &mut f.run);
        if BLOCKS.contains(&name) || matches!(name, "td" | "th") {
            apply_para(&d, &mut f.para);
            if name == "p" && f.para.space_after.is_none() {
                f.para.space_after = Some(160);
            }
        }
        if d.iter().any(|(k, v)| {
            (k == "display" && v.trim().starts_with("none"))
                || (k == "mso-hide" && v.trim() == "all")
                || (k == "visibility" && v.trim() == "hidden")
        }) {
            f.hidden = true;
        }
        self.frames.push(f);
    }

    fn start(&mut self, name: &str, attrs: &[(String, String)], closed: bool) -> Result<()> {
        // An element that ends another.
        match name {
            "p" => self.close_to("p", &["td", "th", "li", "body", "div", "blockquote"])?,
            "li" => self.close_to("li", &["ul", "ol", "menu", "dir"])?,
            "dt" | "dd" => {
                self.close_to("dt", &["dl"])?;
                self.close_to("dd", &["dl"])?;
            }
            "tr" => {
                self.close_cell()?;
                self.close_to("tr", &["table"])?;
            }
            "td" | "th" => {
                self.close_cell()?;
            }
            "tbody" | "thead" | "tfoot" => self.close_cell()?,
            _ => {}
        }
        if self.hidden() && !matches!(name, "table") {
            if !VOID.contains(&name) && !closed {
                self.push_frame(name, attrs);
            }
            return Ok(());
        }
        match name {
            "br" => {
                self.add(Inline::Run(Run {
                    props: self.top().run.clone(),
                    items: vec![RunItem::Break(BreakKind::Line)],
                }));
                self.space = true;
                return Ok(());
            }
            "hr" => {
                self.flush(false)?;
                let mut p = Para::default();
                p.props.borders.bottom = Some(Border::single(6, Color::Auto));
                p.props.space_after = Some(120);
                self.b.paragraph(0)?;
                self.push_block(Block::Para(p));
                return Ok(());
            }
            "img" => return self.image(attrs),
            "wbr" => return Ok(()),
            _ => {}
        }
        if VOID.contains(&name) {
            return Ok(());
        }
        let block = BLOCKS.contains(&name);
        if block {
            self.flush(false)?;
        }
        match name {
            "table" => {
                self.flush(false)?;
                self.push_frame(name, attrs);
                let t = table_props(attrs, &self.decls(name, attrs));
                self.conts.push(Cont::Table(TableB {
                    props: t,
                    ..TableB::default()
                }));
            }
            "tr" => {
                self.push_frame(name, attrs);
                if let Some(Cont::Table(t)) = self.conts.last_mut() {
                    if let Some(r) = t.row.take() {
                        t.rows.push(r);
                    }
                    t.row = Some(vec![]);
                }
            }
            "td" | "th" => {
                // A cell with no row or table around it is not one.
                if !matches!(self.conts.last(), Some(Cont::Table(_))) {
                    return Ok(());
                }
                if let Some(Cont::Table(t)) = self.conts.last_mut() {
                    t.row.get_or_insert_with(Vec::new);
                }
                self.push_frame(name, attrs);
                let d = self.decls(name, attrs);
                let mut props = cell_props(attrs, &d);
                if name == "th" && props.v_align.is_none() {
                    props.v_align = Some(VAlign::Center);
                }
                if name == "th" {
                    if let Some(f) = self.frames.last_mut() {
                        f.para.jc = f.para.jc.or(Some(Jc::Center));
                    }
                }
                self.b.cell()?;
                let n = |k: &str| get(attrs, k).and_then(|v| v.trim().parse::<u32>().ok());
                self.conts.push(Cont::Cell(CellB {
                    blocks: vec![],
                    colspan: n("colspan").unwrap_or(1).clamp(1, 1000),
                    rowspan: n("rowspan").unwrap_or(1).clamp(1, 1000),
                    props,
                }));
            }
            "a" => {
                self.push_frame(name, attrs);
                if let Some(n) = get(attrs, "name").or_else(|| get(attrs, "id")) {
                    let id = self.next_bookmark;
                    self.next_bookmark += 1;
                    self.add(Inline::BookmarkStart {
                        id,
                        name: n.chars().take(40).collect(),
                    });
                    self.add(Inline::BookmarkEnd(id));
                }
                if let Some(href) = get(attrs, "href") {
                    let (target, anchor) = safe_link(href);
                    if target.is_some() || anchor.is_some() {
                        self.para();
                        self.links.push(Link {
                            target,
                            anchor,
                            tooltip: get(attrs, "title").map(|t| t.chars().take(200).collect()),
                            content: vec![],
                        });
                    }
                }
            }
            "li" => {
                self.push_frame(name, attrs);
                let (ordered, n, depth) = self.list_state();
                let marker = if ordered {
                    format!("{n}. ")
                } else {
                    format!(
                        "{} ",
                        ["\u{2022}", "\u{25E6}", "\u{25AA}"][(depth - 1).min(2)]
                    )
                };
                if let Some(f) = self.frames.last_mut() {
                    f.para.ind_left = Some(f.para.ind_left.unwrap_or(0) + 360 * depth as i32);
                    f.para.ind_hanging = Some(360);
                    f.para.space_after = f.para.space_after.or(Some(40));
                }
                self.text_marker(&marker);
            }
            _ => self.push_frame(name, attrs),
        }
        if closed && !matches!(name, "table" | "tr" | "td" | "th") {
            self.end(name)?;
        }
        Ok(())
    }

    /// Whether the list around, its count (this item's), and how deep it is.
    fn list_state(&mut self) -> (bool, u32, usize) {
        let depth = self.frames.iter().filter(|f| f.list.is_some()).count();
        for f in self.frames.iter_mut().rev() {
            if let Some((ordered, n)) = &mut f.list {
                *n += 1;
                return (*ordered, *n, depth);
            }
        }
        (false, 0, 1)
    }

    /// A list item's marker, in the item's own paragraph.
    fn text_marker(&mut self, m: &str) {
        let mut props = self.top().run.clone();
        props.bold = None;
        props.italic = None;
        self.cur_len += m.len();
        self.add(Inline::Run(Run::text(props, m)));
        self.space = true;
    }

    /// The picture a page's `src` names among those of its MIME message: by
    /// content ID (`cid:`), or by the location it was saved at or its file name.
    fn picture(&self, src: &str) -> Option<&[u8]> {
        if self.pictures.is_empty() {
            return None;
        }
        let s = src.trim().to_ascii_lowercase();
        let mut names = vec![];
        if let Some(id) = s.strip_prefix("cid:") {
            names.push(id.trim_matches(['<', '>']).to_string());
        } else {
            let plain = percent_decode(&s);
            for n in [s.as_str(), plain.as_str()] {
                names.push(n.to_string());
                if let Some(last) = n.rsplit(['/', '\\']).next() {
                    names.push(last.to_string());
                }
            }
        }
        self.pictures
            .iter()
            .find(|p| p.names.iter().any(|n| names.contains(n)))
            .map(|p| p.data.as_slice())
    }

    fn image(&mut self, attrs: &[(String, String)]) -> Result<()> {
        if self.hidden() {
            return Ok(());
        }
        let src = get(attrs, "src").unwrap_or("");
        let data = src
            .strip_prefix("data:")
            .and_then(|r| r.split_once(','))
            .filter(|(meta, _)| meta.contains("base64"))
            .and_then(|(_, b)| base64::decode(b, self.b.limits.max_part as usize))
            .or_else(|| self.picture(src).map(<[u8]>::to_vec));
        let media = data.and_then(|d| {
            let ext = image::ext(&d)?;
            Some((ext, d))
        });
        let Some((ext, d)) = media else {
            // Nothing to draw: the alternative text, as a browser shows it.
            let alt = get(attrs, "alt").map(str::trim).unwrap_or("");
            let text = if alt.is_empty() {
                "[image]".to_string()
            } else {
                format!("[{alt}]")
            };
            let mut props = self.top().run.clone();
            props.italic = Some(true);
            self.b.alloc(text.len() as u64)?;
            self.cur_len += text.len();
            self.add(Inline::Run(Run::text(props, text)));
            self.space = false;
            return Ok(());
        };
        self.b.alloc(d.len() as u64)?;
        let natural = image::natural_emu(&d);
        let dim = |k: &str| {
            get(attrs, k)
                .and_then(|v| v.trim().trim_end_matches("px").parse::<f64>().ok())
                .filter(|v| *v > 0.0)
                .map(|v| (v * PX_EMU as f64) as i64)
        };
        let (mut cx, mut cy) = match (dim("width"), dim("height"), natural) {
            (Some(w), Some(h), _) => (w, h),
            (Some(w), None, Some((nw, nh))) if nw > 0 => (w, w * nh / nw),
            (None, Some(h), Some((nw, nh))) if nh > 0 => (h * nw / nh, h),
            (_, _, Some(n)) => n,
            _ => (96 * PX_EMU, 96 * PX_EMU),
        };
        if cx > MAX_PICTURE {
            cy = cy * MAX_PICTURE / cx.max(1);
            cx = MAX_PICTURE;
        }
        let media = self.doc.add_media(ext, d);
        let drawing = Drawing {
            anchor: None,
            cx: cx.max(PX_EMU),
            cy: cy.max(PX_EMU),
            name: "Picture".into(),
            descr: get(attrs, "alt").map(|a| a.chars().take(200).collect()),
            kind: DrawingKind::Picture {
                media,
                crop: Crop::default(),
            },
        };
        self.add(Inline::Run(Run {
            props: self.top().run.clone(),
            items: vec![RunItem::Drawing(Box::new(drawing))],
        }));
        self.space = false;
        Ok(())
    }

    /// Closes the open element `name` if one is open, within the elements that
    /// stop the search.
    fn close_to(&mut self, name: &str, stop: &[&str]) -> Result<()> {
        let mut at = None;
        for (i, f) in self.frames.iter().enumerate().rev() {
            if f.name == name {
                at = Some(i);
                break;
            }
            if stop.contains(&f.name.as_str()) {
                break;
            }
        }
        if at.is_some() {
            self.end(name)?;
        }
        Ok(())
    }

    fn end(&mut self, name: &str) -> Result<()> {
        if VOID.contains(&name) {
            return Ok(());
        }
        let Some(at) = self.frames.iter().rposition(|f| f.name == name) else {
            return Ok(());
        };
        if at == 0 {
            return Ok(());
        }
        // What the elements opened since this one stay open for is closed.
        while self.frames.len() > at + 1 {
            let inner = self.top().name.clone();
            self.end(&inner)?;
        }
        match name {
            "td" | "th" => self.close_cell()?,
            "tr" => {
                self.close_cell()?;
                if let Some(Cont::Table(t)) = self.conts.last_mut() {
                    if let Some(r) = t.row.take() {
                        t.rows.push(r);
                    }
                }
            }
            "table" => {
                self.close_cell()?;
                self.flush(false)?;
                if let Some(Cont::Table(mut t)) = self.conts.pop() {
                    if let Some(r) = t.row.take() {
                        t.rows.push(r);
                    }
                    if let Some(table) = self.build_table(t) {
                        self.push_block(Block::Table(table));
                    }
                }
            }
            "a" => {
                if let Some(l) = self.links.pop() {
                    self.link_into(l);
                }
            }
            _ if BLOCKS.contains(&name) => {
                let keep = false;
                self.flush(keep)?;
            }
            _ => {}
        }
        if self.frames.len() > 1 {
            self.frames.pop();
        }
        Ok(())
    }

    /// Ends the cell being built, if one is.
    fn close_cell(&mut self) -> Result<()> {
        if !matches!(self.conts.last(), Some(Cont::Cell(_))) {
            return Ok(());
        }
        self.flush(false)?;
        // The frame of the cell goes with it, and what is open inside it.
        while let Some(f) = self.frames.last() {
            let name = f.name.clone();
            if name == "td" || name == "th" {
                self.frames.pop();
                break;
            }
            if self.frames.len() <= 1 || name == "table" || name == "tr" {
                break;
            }
            self.frames.pop();
        }
        if let Some(Cont::Cell(mut c)) = self.conts.pop() {
            if c.blocks.is_empty() {
                self.b.paragraph(0)?;
                c.blocks.push(Block::Para(Para::default()));
            }
            if let Some(Cont::Table(t)) = self.conts.last_mut() {
                t.row.get_or_insert_with(Vec::new).push(c);
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        // Whatever is left open ends with the document.
        loop {
            self.close_cell()?;
            match self.conts.last() {
                Some(Cont::Table(_)) => {
                    self.flush(false)?;
                    if let Some(Cont::Table(mut t)) = self.conts.pop() {
                        if let Some(r) = t.row.take() {
                            t.rows.push(r);
                        }
                        if let Some(table) = self.build_table(t) {
                            self.push_block(Block::Table(table));
                        }
                    }
                }
                _ => break,
            }
        }
        self.flush(false)?;
        let body = match self.conts.pop() {
            Some(Cont::Body(v)) => v,
            _ => vec![],
        };
        self.doc.body = body;
        if self.doc.body.is_empty() {
            self.b.paragraph(0)?;
            self.doc.body.push(Block::Para(Para::default()));
        }
        Ok(())
    }

    /// The model table of the cells read: the grid, and the cells a row span
    /// continues into the rows below.
    fn build_table(&mut self, t: TableB) -> Option<Table> {
        let rows: Vec<Vec<CellB>> = t.rows.into_iter().filter(|r| !r.is_empty()).collect();
        if rows.is_empty() {
            return None;
        }
        // Columns: the widest row, its row-spanned cells counted.
        let mut carry: HashMap<usize, (u32, u32)> = HashMap::new();
        let mut out_rows = vec![];
        let mut columns = 1usize;
        for row in rows {
            let mut cells = vec![];
            let mut col = 0usize;
            let mut it = row.into_iter();
            loop {
                if let Some(&(left, span)) = carry.get(&col) {
                    if left > 0 {
                        let props = CellProps {
                            grid_span: span,
                            v_merge: VMerge::Continue,
                            ..CellProps::default()
                        };
                        cells.push(Cell {
                            props,
                            content: vec![Block::Para(Para::default())],
                        });
                        carry.insert(col, (left - 1, span));
                        col += span as usize;
                        continue;
                    }
                }
                let Some(mut c) = it.next() else { break };
                c.props.grid_span = c.colspan;
                if c.rowspan > 1 {
                    c.props.v_merge = VMerge::Restart;
                    carry.insert(col, (c.rowspan - 1, c.colspan));
                }
                col += c.colspan as usize;
                cells.push(Cell {
                    props: c.props,
                    content: c.blocks,
                });
            }
            // A row span that reaches past the last cell of this row.
            while let Some(&(left, span)) = carry.get(&col) {
                if left == 0 {
                    break;
                }
                let props = CellProps {
                    grid_span: span,
                    v_merge: VMerge::Continue,
                    ..CellProps::default()
                };
                cells.push(Cell {
                    props,
                    content: vec![Block::Para(Para::default())],
                });
                carry.insert(col, (left - 1, span));
                col += span as usize;
            }
            columns = columns.max(col);
            out_rows.push(Row {
                props: RowProps::default(),
                cells,
            });
        }
        let columns = columns.min(1000);
        // The text area of the page, shared evenly.
        let width =
            (self.doc.section.width - self.doc.section.left - self.doc.section.right).max(1440);
        let grid = vec![(width / columns as i32).max(120); columns];
        Some(Table {
            props: t.props,
            grid,
            rows: out_rows,
        })
    }
}

// ------------------------------------------------------------------- values

fn rgb(s: &str) -> Option<u32> {
    css::color(s).flatten()
}

fn jc(v: &str) -> Option<Jc> {
    match v.trim().to_ascii_lowercase().as_str() {
        "center" | "middle" => Some(Jc::Center),
        "right" | "end" => Some(Jc::Right),
        "justify" => Some(Jc::Both),
        "left" | "start" => Some(Jc::Left),
        _ => None,
    }
}

/// `%20` and the like undone.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |x: u8| (x as char).to_digit(16);
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(a), Some(c)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((a * 16 + c) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A length in twips.
fn twips(v: &str) -> Option<i32> {
    css::length_pt(v, "pt").map(|p| (p * 20.0).round().clamp(-31_000.0, 31_000.0) as i32)
}

/// The first family of a `font-family` list that names a font.
fn set_font(r: &mut RunProps, families: &str) {
    for f in families.split(',') {
        let f = f.trim().trim_matches(['"', '\'']).trim();
        if f.is_empty() {
            continue;
        }
        if matches!(
            f.to_ascii_lowercase().as_str(),
            "serif" | "sans-serif" | "monospace" | "cursive" | "fantasy" | "system-ui" | "inherit"
        ) {
            if f.eq_ignore_ascii_case("monospace") {
                r.fonts.ascii = Some("Courier New".into());
                r.fonts.hansi = Some("Courier New".into());
            }
            continue;
        }
        r.fonts.ascii = Some(f.chars().take(64).collect());
        r.fonts.hansi = r.fonts.ascii.clone();
        return;
    }
}

fn apply_run(d: &[(String, String)], r: &mut RunProps) {
    for (k, v) in d {
        let v = v.trim();
        match k.as_str() {
            "color" => {
                if let Some(c) = css::color(v) {
                    r.color = Some(c.map_or(Color::Auto, Color::Rgb));
                }
            }
            "font-family" => set_font(r, v),
            "font-size" => {
                let pt = match v.to_ascii_lowercase().as_str() {
                    "xx-small" => Some(7.0),
                    "x-small" => Some(7.5),
                    "small" => Some(10.0),
                    "medium" => Some(12.0),
                    "large" => Some(13.5),
                    "x-large" => Some(18.0),
                    "xx-large" => Some(24.0),
                    other => css::length_pt(other, "pt"),
                };
                if let Some(pt) = pt.filter(|p: &f64| (1.0..=400.0).contains(p)) {
                    r.size = Some((pt * 2.0).round() as u32);
                }
            }
            "font-weight" => {
                let bold = match v {
                    "bold" | "bolder" => Some(true),
                    "normal" | "lighter" => Some(false),
                    n => n.parse::<u32>().ok().map(|n| n >= 600),
                };
                if bold.is_some() {
                    r.bold = bold;
                }
            }
            "font-style" => match v {
                "italic" | "oblique" => r.italic = Some(true),
                "normal" => r.italic = Some(false),
                _ => {}
            },
            "font-variant" => {
                if v.contains("small-caps") {
                    r.small_caps = Some(true);
                }
            }
            "text-transform" => {
                if v == "uppercase" {
                    r.caps = Some(true);
                }
            }
            "text-decoration" | "text-decoration-line" => {
                if v.contains("underline") {
                    r.underline = Some("single");
                }
                if v.contains("line-through") {
                    r.strike = Some(true);
                }
                if v == "none" {
                    r.underline = Some("none");
                    r.strike = Some(false);
                }
            }
            "background" | "background-color" => {
                let first = v.split_whitespace().next().unwrap_or("");
                if let Some(Some(c)) = css::color(first) {
                    r.shading = Some(Shading::fill(Color::Rgb(c)));
                }
            }
            "vertical-align" => match v {
                "super" => r.vert_align = Some(VertAlign::Superscript),
                "sub" => r.vert_align = Some(VertAlign::Subscript),
                "baseline" => r.vert_align = Some(VertAlign::Baseline),
                _ => {}
            },
            _ => {}
        }
    }
}

fn apply_para(d: &[(String, String)], p: &mut ParaProps) {
    for (k, v) in d {
        let v = v.trim();
        match k.as_str() {
            "text-align" => p.jc = jc(v).or(p.jc),
            "margin-left" => p.ind_left = twips(v).map(|t| t.max(0)).or(p.ind_left),
            "margin-right" => p.ind_right = twips(v).map(|t| t.max(0)).or(p.ind_right),
            "text-indent" => {
                if let Some(t) = twips(v) {
                    if t < 0 {
                        p.ind_hanging = Some(-t);
                        p.ind_first_line = None;
                    } else {
                        p.ind_first_line = Some(t);
                        p.ind_hanging = None;
                    }
                }
            }
            "margin-top" => p.space_before = twips(v).map(|t| t.max(0)).or(p.space_before),
            "margin-bottom" => p.space_after = twips(v).map(|t| t.max(0)).or(p.space_after),
            "margin" => {
                // One to four values: top, right, bottom, left.
                let parts: Vec<Option<i32>> = v.split_whitespace().map(twips).collect();
                let at = |i: usize| parts.get(i).copied().flatten().map(|t| t.max(0));
                match parts.len() {
                    1 => {
                        p.space_before = at(0).or(p.space_before);
                        p.space_after = at(0).or(p.space_after);
                        p.ind_left = at(0).or(p.ind_left);
                        p.ind_right = at(0).or(p.ind_right);
                    }
                    2 => {
                        p.space_before = at(0).or(p.space_before);
                        p.space_after = at(0).or(p.space_after);
                        p.ind_left = at(1).or(p.ind_left);
                        p.ind_right = at(1).or(p.ind_right);
                    }
                    3 | 4 => {
                        p.space_before = at(0).or(p.space_before);
                        p.ind_right = at(1).or(p.ind_right);
                        p.space_after = at(2).or(p.space_after);
                        p.ind_left = at(if parts.len() == 4 { 3 } else { 1 }).or(p.ind_left);
                    }
                    _ => {}
                }
            }
            "page-break-before" | "break-before" => {
                if matches!(v, "always" | "page" | "left" | "right") {
                    p.page_break_before = Some(true);
                }
            }
            "background" | "background-color" => {
                let first = v.split_whitespace().next().unwrap_or("");
                if let Some(Some(c)) = css::color(first) {
                    p.shading = Some(Shading::fill(Color::Rgb(c)));
                }
            }
            _ => {}
        }
    }
}

/// A CSS border (`1px solid #000`, `.5pt solid windowtext`) as a border.
fn border(v: &str) -> Option<Border> {
    let (mut width, mut style, mut color) = (None, None, Color::Auto);
    for t in v.split_whitespace() {
        let l = t.to_ascii_lowercase();
        match l.as_str() {
            "none" | "hidden" => return None,
            "solid" | "dashed" | "dotted" | "double" | "groove" | "ridge" | "inset" | "outset"
            | "hairline" => style = Some(l),
            "thin" => width = Some(0.75),
            "medium" => width = Some(1.5),
            "thick" => width = Some(2.25),
            _ => {
                if let Some(w) = css::length_pt(&l, "px") {
                    width = Some(w);
                } else if let Some(c) = css::color(&l) {
                    color = c.map_or(Color::Auto, Color::Rgb);
                }
            }
        }
    }
    let style = style?;
    let w: f64 = width.unwrap_or(0.75);
    if w <= 0.0 {
        return None;
    }
    Some(Border {
        style: match style.as_str() {
            "double" => "double",
            "dashed" => "dashed",
            "dotted" => "dotted",
            _ => "single",
        },
        size: (w * 8.0).round().clamp(2.0, 96.0) as u32,
        space: 0,
        color,
        shadow: false,
    })
}

fn table_props(attrs: &[(String, String)], d: &[(String, String)]) -> TableProps {
    let mut t = TableProps::default();
    let mut width = get(attrs, "width").map(str::to_string);
    for (k, v) in d {
        match k.as_str() {
            "width" => width = Some(v.clone()),
            "background" | "background-color" => {
                if let Some(Some(c)) = css::color(v.split_whitespace().next().unwrap_or("")) {
                    t.shading = Some(Shading::fill(Color::Rgb(c)));
                }
            }
            "margin-left" => t.indent = twips(v),
            _ => {}
        }
    }
    if let Some(w) = width {
        let w = w.trim();
        t.width = match w
            .strip_suffix('%')
            .and_then(|p| p.trim().parse::<f64>().ok())
        {
            Some(p) if (1.0..=100.0).contains(&p) => Some(Width::Pct((p * 50.0) as i32)),
            _ => twips(w).filter(|&n| n > 0).map(Width::Twips).or_else(|| {
                w.parse::<f64>()
                    .ok()
                    .filter(|&n| n > 0.0)
                    .map(|n| Width::Twips((n * PX) as i32))
            }),
        };
    }
    // `border="1"` draws every line; the style's border, the outside ones.
    let attr_border = get(attrs, "border")
        .and_then(|b| b.trim().parse::<f64>().ok())
        .filter(|&n| n > 0.0);
    let line =
        attr_border.map(|n| Border::single((n * 6.0).round().clamp(2.0, 48.0) as u32, Color::Auto));
    let css_border = d
        .iter()
        .rev()
        .find(|(k, _)| k == "border")
        .and_then(|(_, v)| border(v));
    if let Some(b) = line.clone().or(css_border.clone()) {
        t.borders = TableBorders {
            top: Some(b.clone()),
            left: Some(b.clone()),
            bottom: Some(b.clone()),
            right: Some(b.clone()),
            inside_h: line.clone(),
            inside_v: line,
        };
    }
    if let Some(p) = get(attrs, "cellpadding").and_then(|p| p.trim().parse::<f64>().ok()) {
        let m = (p.clamp(0.0, 100.0) * PX) as i32;
        t.cell_margins = Margins {
            top: Some(m),
            left: Some(m),
            bottom: Some(m),
            right: Some(m),
        };
    }
    if let Some(c) = get(attrs, "bgcolor").and_then(rgb) {
        t.shading = Some(Shading::fill(Color::Rgb(c)));
    }
    t
}

fn cell_props(attrs: &[(String, String)], d: &[(String, String)]) -> CellProps {
    let mut c = CellProps::default();
    let mut width = get(attrs, "width").map(str::to_string);
    let mut valign = get(attrs, "valign").map(str::to_string);
    for (k, v) in d {
        match k.as_str() {
            "width" => width = Some(v.clone()),
            "vertical-align" => valign = Some(v.clone()),
            "background" | "background-color" => {
                if let Some(Some(rgb)) = css::color(v.split_whitespace().next().unwrap_or("")) {
                    c.shading = Some(Shading::fill(Color::Rgb(rgb)));
                }
            }
            "border" => {
                let b = border(v);
                c.borders = TableBorders {
                    top: b.clone(),
                    left: b.clone(),
                    bottom: b.clone(),
                    right: b,
                    ..TableBorders::default()
                };
            }
            "border-top" => c.borders.top = border(v),
            "border-left" => c.borders.left = border(v),
            "border-bottom" => c.borders.bottom = border(v),
            "border-right" => c.borders.right = border(v),
            "white-space" => c.no_wrap = v.starts_with("nowrap"),
            _ => {}
        }
    }
    if let Some(color) = get(attrs, "bgcolor").and_then(rgb) {
        c.shading = Some(Shading::fill(Color::Rgb(color)));
    }
    if get(attrs, "nowrap").is_some() {
        c.no_wrap = true;
    }
    if let Some(w) = width {
        let w = w.trim();
        c.width = match w
            .strip_suffix('%')
            .and_then(|p| p.trim().parse::<f64>().ok())
        {
            Some(p) if (1.0..=100.0).contains(&p) => Some(Width::Pct((p * 50.0) as i32)),
            _ => twips(w).filter(|&n| n > 0).map(Width::Twips).or_else(|| {
                w.parse::<f64>()
                    .ok()
                    .filter(|&n| n > 0.0)
                    .map(|n| Width::Twips((n * PX) as i32))
            }),
        };
    }
    c.v_align = valign.and_then(|v| match v.trim() {
        "top" => Some(VAlign::Top),
        "middle" | "center" => Some(VAlign::Center),
        "bottom" => Some(VAlign::Bottom),
        _ => None,
    });
    c
}

/// Where a link goes: a web, mail, phone or FTP address (its target), or a
/// place in the page (its anchor). Nothing else: a script, a data address or a
/// path on the author's computer is not followed.
fn safe_link(href: &str) -> (Option<String>, Option<String>) {
    let h = href.trim();
    if let Some(a) = h.strip_prefix('#') {
        return (None, (!a.is_empty()).then(|| a.chars().take(40).collect()));
    }
    let lower = h.to_ascii_lowercase();
    if ["http://", "https://", "ftp://", "mailto:", "tel:"]
        .iter()
        .any(|p| lower.starts_with(p))
        && !h.chars().any(|c| c.is_control())
    {
        return (Some(h.chars().take(2000).collect()), None);
    }
    (None, None)
}

/// The page size and margins of the first `@page` rule that gives a size
/// (Word writes one for each section): `size: 595.3pt 841.9pt; margin: 72pt`.
fn page_rule(css_text: &str) -> Option<Section> {
    let mut rest = css_text;
    while let Some(at) = rest.find("@page") {
        let after = &rest[at + 5..];
        let open = after.find('{')?;
        let close = after[open..].find('}').map(|c| open + c)?;
        let d = css::declarations(&after[open + 1..close]);
        rest = &after[close..];
        let Some((_, size)) = d.iter().find(|(k, _)| k == "size") else {
            continue;
        };
        let nums: Vec<i32> = size
            .split_whitespace()
            .filter_map(twips)
            .filter(|&n| n > 0)
            .collect();
        let mut s = Section::default();
        let landscape = size.contains("landscape");
        match nums.as_slice() {
            [w, h] => {
                s.width = *w;
                s.height = *h;
            }
            [w] => {
                s.width = *w;
                s.height = *w;
            }
            _ => continue,
        }
        if landscape && s.width < s.height {
            std::mem::swap(&mut s.width, &mut s.height);
        }
        s.landscape = s.width > s.height;
        if let Some((_, m)) = d.iter().find(|(k, _)| k == "margin") {
            let v: Vec<i32> = m.split_whitespace().filter_map(twips).collect();
            let (t, r, b, l) = match v.as_slice() {
                [a] => (*a, *a, *a, *a),
                [a, b] => (*a, *b, *a, *b),
                [a, b, c] => (*a, *b, *c, *b),
                [a, b, c, d] => (*a, *b, *c, *d),
                _ => (1440, 1440, 1440, 1440),
            };
            s.top = t.max(0);
            s.right = r.max(0);
            s.bottom = b.max(0);
            s.left = l.max(0);
        }
        // A page too small to hold its margins keeps the defaults'.
        if s.width - s.left - s.right < 720 || s.height - s.top - s.bottom < 720 {
            continue;
        }
        return Some(s);
    }
    None
}
