//! Text content: paragraphs, headings, lists, notes, comments and fields.

use super::{Applied, Odt};
use crate::formats::office::common::odf::text_of;
use crate::formats::office::common::xml::{Child, Node};
use crate::formats::office::docs::error::Result;
use crate::formats::office::docs::limits::PARA_BYTES;
use crate::formats::office::docs::model::*;

#[derive(Clone, Debug)]
pub(crate) struct ListInfo {
    pub num_id: u32,
    pub level: u32,
    pub style: String,
}

struct Inl {
    rpr: RunProps,
    /// The last character written was a space (or the paragraph just began).
    space: bool,
}

/// A name a DOCX bookmark can hold.
pub(crate) fn bm_name(n: &str) -> String {
    let s: String = n
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    if s.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{s}")
    } else {
        s
    }
}

fn push_item(out: &mut Vec<Inline>, rpr: &RunProps, item: RunItem) {
    if let Some(Inline::Run(r)) = out.last_mut() {
        if r.props == *rpr {
            if let (RunItem::Text(t), Some(RunItem::Text(last))) = (&item, r.items.last_mut()) {
                last.push_str(t);
                return;
            }
            r.items.push(item);
            return;
        }
    }
    out.push(Inline::Run(Run {
        props: rpr.clone(),
        items: vec![item],
    }));
}

impl Odt<'_> {
    /// The blocks of the children of `n`.
    pub(crate) fn blocks(&mut self, n: &Node) -> Result<Vec<Block>> {
        let mut out = vec![];
        if self.depth > 24 {
            return Ok(out);
        }
        self.depth += 1;
        let mut r = Ok(());
        for c in n.nodes() {
            r = self.block(c, &mut out, None);
            if r.is_err() {
                break;
            }
        }
        self.depth -= 1;
        r?;
        Ok(out)
    }

    /// The blocks of the body: master pages switch sections.
    pub(crate) fn blocks_top(&mut self, body: &Node) -> Result<Vec<Block>> {
        let mut out = vec![];
        for c in body.nodes() {
            let family = match c.name.as_str() {
                "text:p" | "text:h" => Some("paragraph"),
                "table:table" => Some("table"),
                _ => None,
            };
            let master = family.and_then(|f| {
                let key = if c.name == "table:table" {
                    "table:style-name"
                } else {
                    "text:style-name"
                };
                c.attr(key).map(|s| (f, s.to_string()))
            });
            let mut first = false;
            let m = match master {
                Some((f, s)) => self.apply(f, &s).master,
                None => None,
            };
            if self.cur_master.is_empty() {
                self.cur_master = m.clone().unwrap_or_else(|| self.default_master());
                first = true;
            }
            if let Some(m) = m {
                if m != self.cur_master {
                    if !out.is_empty() {
                        self.end_section(&mut out)?;
                    }
                    self.cur_master = m;
                } else if !first && !out.is_empty() {
                    self.pending_break = true;
                }
            }
            let before = out.len();
            self.block(c, &mut out, None)?;
            if let Some(Block::Para(_)) = out.get(before) {
                // A forced break after a paragraph.
            }
            if c.name == "text:p" || c.name == "text:h" {
                if let Some(s) = c.attr("text:style-name") {
                    if self.apply("paragraph", s).break_after {
                        self.pending_break = true;
                    }
                }
            }
        }
        Ok(out)
    }

    pub(crate) fn block(
        &mut self,
        c: &Node,
        out: &mut Vec<Block>,
        list: Option<&ListInfo>,
    ) -> Result<()> {
        match c.name.as_str() {
            "text:p" | "text:h" => {
                let p = self.paragraph(c, list)?;
                out.push(Block::Para(p));
            }
            "text:list" => self.list(c, list, out)?,
            "text:numbered-paragraph" => {
                for k in c.nodes() {
                    if k.name == "text:p" || k.name == "text:h" {
                        let p = self.paragraph(k, None)?;
                        out.push(Block::Para(p));
                    }
                }
            }
            "table:table" => {
                if let Some(t) = self.table(c)? {
                    out.push(Block::Table(t));
                }
            }
            "text:section" => {
                if c.attr("text:display") != Some("none") {
                    for k in c.nodes() {
                        self.block(k, out, list)?;
                    }
                }
            }
            "text:table-of-content"
            | "text:table-index"
            | "text:illustration-index"
            | "text:object-index"
            | "text:user-index"
            | "text:alphabetical-index"
            | "text:bibliography"
            | "text:index-body"
            | "text:index-title" => {
                for k in c.nodes() {
                    if k.name == "text:index-body"
                        || k.name == "text:index-title"
                        || k.name == "text:p"
                        || k.name == "text:h"
                        || k.name == "table:table"
                        || k.name == "text:list"
                    {
                        self.block(k, out, list)?;
                    }
                }
            }
            n if n.starts_with("draw:") => {
                // A frame or shape directly in the body: a paragraph holds it.
                let mut para = Para::default();
                let mut ctx = Inl {
                    rpr: RunProps::default(),
                    space: true,
                };
                self.inline(c, &mut ctx, &mut para.content)?;
                out.push(Block::Para(para));
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn paragraph(&mut self, n: &Node, list: Option<&ListInfo>) -> Result<Para> {
        self.b.paragraph(PARA_BYTES as usize / 4)?;
        let style = n.attr("text:style-name").unwrap_or("");
        let ap: Applied = if style.is_empty() {
            Applied::default()
        } else {
            self.apply("paragraph", style)
        };
        let mut ppr = super::props::para_props(&ap.props, list.is_some());
        ppr.style = ap.style.clone();
        let left = ap.props.twips("paragraph/fo:margin-left").unwrap_or(0);
        let mut tabs = super::props::tabs(&ap.tabs, if list.is_some() { 0 } else { left });
        if !tabs.is_empty() {
            tabs.sort_by_key(|t| t.pos);
            ppr.tabs = tabs;
        }
        if self.pending_break {
            self.pending_break = false;
            ppr.page_break_before = Some(true);
        }
        // Numbering.
        let heading = if n.name == "text:h" {
            n.attr("text:outline-level")
                .and_then(|v| v.parse::<u32>().ok())
                .map(|l| l.clamp(1, 10))
        } else {
            None
        };
        match list {
            Some(l) if l.num_id > 0 => {
                ppr.num_id = Some(l.num_id);
                ppr.num_level = Some(l.level.min(8));
            }
            Some(_) => {
                // A list header: no number.
                ppr.num_id = Some(0);
            }
            None => {
                if let Some(h) = heading {
                    if n.attr("text:is-list-header") != Some("true") {
                        if let Some(id) = self.outline_num_id() {
                            ppr.num_id = Some(id);
                            ppr.num_level = Some((h - 1).min(8));
                        }
                    }
                    if ppr.outline_level.is_none() {
                        ppr.outline_level = Some((h - 1).min(8));
                    }
                } else if let Some(ls) = &ap.list_style {
                    // A paragraph style that names a list numbers its paragraphs.
                    if let Some(id) = self.list_num(ls, true, false) {
                        ppr.num_id = Some(id);
                        ppr.num_level = Some(0);
                    }
                }
            }
        }
        let mut para = Para {
            props: ppr,
            mark: ap.rpr.clone(),
            content: vec![],
            section: None,
        };
        let mut ctx = Inl {
            rpr: ap.rpr.clone(),
            space: true,
        };
        self.inline_children(n, &mut ctx, &mut para.content)?;
        Ok(para)
    }

    fn inline_children(&mut self, n: &Node, ctx: &mut Inl, out: &mut Vec<Inline>) -> Result<()> {
        for c in &n.children {
            match c {
                Child::Text(t) => self.text(t, ctx, out),
                Child::Node(k) => self.inline(k, ctx, out)?,
            }
        }
        Ok(())
    }

    /// Text with the white space ODF collapses.
    fn text(&mut self, t: &str, ctx: &mut Inl, out: &mut Vec<Inline>) {
        let mut s = String::with_capacity(t.len());
        for ch in t.chars() {
            if matches!(ch, ' ' | '\t' | '\r' | '\n') {
                if !ctx.space {
                    s.push(' ');
                    ctx.space = true;
                }
            } else {
                s.push(ch);
                ctx.space = false;
            }
        }
        if !s.is_empty() {
            push_item(out, &ctx.rpr, RunItem::Text(s));
        }
    }

    fn inline(&mut self, n: &Node, ctx: &mut Inl, out: &mut Vec<Inline>) -> Result<()> {
        if self.depth > 48 {
            return Ok(());
        }
        match n.name.as_str() {
            "text:span" => {
                let saved = ctx.rpr.clone();
                if let Some(s) = n.attr("text:style-name") {
                    let ap = self.apply("text", s);
                    ctx.rpr.overlay(&ap.rpr);
                    if ap.style.is_some() {
                        ctx.rpr.style = ap.style;
                    }
                }
                self.depth += 1;
                let r = self.inline_children(n, ctx, out);
                self.depth -= 1;
                ctx.rpr = saved;
                r?;
            }
            "text:s" => {
                let c = n
                    .attr("text:c")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(1)
                    .min(1 << 16);
                push_item(out, &ctx.rpr, RunItem::Text(" ".repeat(c)));
                ctx.space = false;
            }
            "text:tab" => {
                push_item(out, &ctx.rpr, RunItem::Tab);
                ctx.space = true;
            }
            "text:line-break" => {
                push_item(out, &ctx.rpr, RunItem::Break(BreakKind::Line));
                ctx.space = true;
            }
            "text:a" => {
                let saved = ctx.rpr.clone();
                if let Some(s) = n.attr("text:style-name") {
                    let ap = self.apply("text", s);
                    ctx.rpr.overlay(&ap.rpr);
                    if ap.style.is_some() {
                        ctx.rpr.style = ap.style;
                    }
                }
                let mut content = vec![];
                self.depth += 1;
                let r = self.inline_children(n, ctx, &mut content);
                self.depth -= 1;
                ctx.rpr = saved;
                r?;
                let href = n.attr("xlink:href").unwrap_or("");
                let (target, anchor) = if let Some(a) = href.strip_prefix('#') {
                    (None, Some(bm_name(a)))
                } else if href.is_empty()
                    || !crate::formats::office::docs::fields::safe_target(href)
                {
                    (None, None)
                } else {
                    (Some(href.to_string()), None)
                };
                if target.is_some() || anchor.is_some() {
                    out.push(Inline::Hyperlink {
                        target,
                        anchor,
                        tooltip: n.attr("office:title").map(str::to_string),
                        content,
                    });
                } else {
                    out.extend(content);
                }
            }
            "text:bookmark" | "text:reference-mark" => {
                if let Some(name) = n.attr("text:name") {
                    let id = self.next_bookmark;
                    self.next_bookmark += 1;
                    out.push(Inline::BookmarkStart {
                        id,
                        name: bm_name(name),
                    });
                    out.push(Inline::BookmarkEnd(id));
                }
            }
            "text:bookmark-start" | "text:reference-mark-start" => {
                if let Some(name) = n.attr("text:name") {
                    let id = self.next_bookmark;
                    self.next_bookmark += 1;
                    self.bookmark_open.insert(name.to_string(), id);
                    out.push(Inline::BookmarkStart {
                        id,
                        name: bm_name(name),
                    });
                }
            }
            "text:bookmark-end" | "text:reference-mark-end" => {
                if let Some(id) = n
                    .attr("text:name")
                    .and_then(|nm| self.bookmark_open.remove(nm))
                {
                    out.push(Inline::BookmarkEnd(id));
                }
            }
            "text:note" => self.note(n, ctx, out)?,
            "office:annotation" => self.annotation(n, ctx, out)?,
            "office:annotation-end" => {
                if let Some(id) = n
                    .attr("office:name")
                    .and_then(|nm| self.annotation_ids.get(nm))
                {
                    let id = *id;
                    out.push(Inline::CommentEnd(id));
                    push_item(out, &ctx.rpr, RunItem::CommentRef(id));
                }
            }
            "text:page-number" => {
                let t = text_of(n);
                self.field(out, ctx, " PAGE ", if t.is_empty() { "1" } else { &t });
            }
            "text:page-count" => {
                let t = text_of(n);
                self.field(out, ctx, " NUMPAGES ", if t.is_empty() { "1" } else { &t });
            }
            "text:bookmark-ref" | "text:reference-ref" => {
                let t = text_of(n);
                let name = n.attr("text:ref-name").unwrap_or("");
                self.field(out, ctx, &format!(" REF {} \\h ", bm_name(name)), &t);
            }
            "text:soft-page-break"
            | "text:tracked-changes"
            | "text:change"
            | "text:change-start"
            | "text:change-end"
            | "text:alphabetical-index-mark"
            | "text:alphabetical-index-mark-start"
            | "text:alphabetical-index-mark-end"
            | "text:toc-mark"
            | "text:toc-mark-start"
            | "text:toc-mark-end"
            | "text:user-index-mark"
            | "text:ruby-text"
            | "office:forms"
            | "svg:title"
            | "svg:desc"
            | "text:note-citation" => {}
            // A group is drawn as its members, one by one, so that their text
            // is kept.
            "draw:g" => {
                if self.depth <= 12 {
                    self.depth += 1;
                    let r = self.inline_children(n, ctx, out);
                    self.depth -= 1;
                    r?;
                }
            }
            n2 if n2.starts_with("draw:") => {
                if let Some(d) = self.drawing(n)? {
                    push_item(out, &ctx.rpr, RunItem::Drawing(Box::new(d)));
                }
            }
            _ => {
                // Fields and anything else: their text.
                self.depth += 1;
                let r = self.inline_children(n, ctx, out);
                self.depth -= 1;
                r?;
            }
        }
        Ok(())
    }

    fn field(&mut self, out: &mut Vec<Inline>, ctx: &Inl, instr: &str, result: &str) {
        out.push(Inline::Field {
            instr: instr.to_string(),
            props: ctx.rpr.clone(),
            result: vec![Inline::Run(Run::text(ctx.rpr.clone(), result))],
        });
    }

    fn note(&mut self, n: &Node, ctx: &mut Inl, out: &mut Vec<Inline>) -> Result<()> {
        let endnote = n.attr("text:note-class") == Some("endnote");
        let id = if endnote {
            self.doc.endnotes.len() as u32 + 1
        } else {
            self.doc.footnotes.len() as u32 + 1
        };
        // The note is reserved first so that its own notes number after it.
        let mut sup = ctx.rpr.clone();
        sup.vert_align = Some(VertAlign::Superscript);
        let item = if endnote {
            RunItem::EndnoteRef(id)
        } else {
            RunItem::FootnoteRef(id)
        };
        push_item(out, &sup, item);
        let slot = Note {
            id,
            content: vec![],
        };
        if endnote {
            self.doc.endnotes.push(slot);
        } else {
            self.doc.footnotes.push(slot);
        }
        let mut content = match n.child("text:note-body") {
            // A note in a note is read twice over, and never deep in the tree.
            Some(b) if self.note_level < 3 && self.depth < 40 => {
                let saved = self.depth;
                self.depth += 2;
                self.note_level += 1;
                let r = self.blocks(b);
                self.note_level -= 1;
                self.depth = saved;
                r?
            }
            _ => vec![],
        };
        // The mark the note starts with.
        let mark = Inline::Run(Run {
            props: RunProps {
                vert_align: Some(VertAlign::Superscript),
                ..RunProps::default()
            },
            items: vec![RunItem::NoteMark(endnote)],
        });
        match content.first_mut() {
            Some(Block::Para(p)) => {
                p.content.insert(0, mark);
                p.content
                    .insert(1, Inline::Run(Run::text(RunProps::default(), " ")));
            }
            _ => content.insert(
                0,
                Block::Para(Para {
                    content: vec![mark],
                    ..Para::default()
                }),
            ),
        }
        let list = if endnote {
            &mut self.doc.endnotes
        } else {
            &mut self.doc.footnotes
        };
        if let Some(s) = list.iter_mut().find(|s| s.id == id) {
            s.content = content;
        }
        Ok(())
    }

    fn annotation(&mut self, n: &Node, ctx: &mut Inl, out: &mut Vec<Inline>) -> Result<()> {
        let id = self.doc.comments.len() as u32;
        let author = n.child("dc:creator").map(text_of).unwrap_or_default();
        let date = n.child("dc:date").map(text_of).filter(|d| !d.is_empty());
        let initials: String = author
            .split_whitespace()
            .filter_map(|w| w.chars().next())
            .take(3)
            .collect();
        let mut blocks = vec![];
        self.depth += 2;
        for c in n.nodes() {
            if c.name == "text:p" || c.name == "text:list" || c.name == "table:table" {
                self.block(c, &mut blocks, None)?;
            }
        }
        self.depth -= 2;
        self.doc.comments.push(Comment {
            id,
            author,
            initials,
            date,
            content: blocks,
        });
        out.push(Inline::CommentStart(id));
        match n.attr("office:name") {
            Some(name) if self.annotation_ends.contains(name) => {
                self.annotation_ids.insert(name.to_string(), id);
            }
            _ => {
                out.push(Inline::CommentEnd(id));
                push_item(out, &ctx.rpr, RunItem::CommentRef(id));
            }
        }
        Ok(())
    }

    // ---- lists ----

    pub(crate) fn list(
        &mut self,
        n: &Node,
        parent: Option<&ListInfo>,
        out: &mut Vec<Block>,
    ) -> Result<()> {
        if self.depth > 24 {
            return Ok(());
        }
        let first_style = || {
            n.nodes()
                .flat_map(|i| i.nodes())
                .find(|p| p.name == "text:p" || p.name == "text:h")
                .and_then(|p| p.attr("text:style-name"))
                .map(str::to_string)
        };
        let style = n
            .attr("text:style-name")
            .map(str::to_string)
            .or_else(|| parent.map(|p| p.style.clone()))
            .or_else(|| first_style().and_then(|s| self.apply("paragraph", &s).list_style))
            .unwrap_or_default();
        let info = match parent {
            Some(p) => ListInfo {
                num_id: p.num_id,
                level: p.level + 1,
                style,
            },
            None => {
                let cont = n.attr("text:continue-numbering") == Some("true");
                let num = match n
                    .attr("text:continue-list")
                    .and_then(|id| self.list_ids.get(id))
                {
                    Some((_, num)) => Some(*num),
                    None => self.list_num(&style, cont, false),
                };
                if let (Some(id), Some(num)) = (n.attr("xml:id").or(n.attr("text:id")), num) {
                    self.list_ids.insert(id.to_string(), (style.clone(), num));
                }
                ListInfo {
                    num_id: num.unwrap_or(0),
                    level: 0,
                    style,
                }
            }
        };
        self.depth += 1;
        let mut r = Ok(());
        'items: for item in n.nodes() {
            let header = item.name == "text:list-header";
            if item.name != "text:list-item" && !header {
                continue;
            }
            let li = if header {
                ListInfo {
                    num_id: 0,
                    ..info.clone()
                }
            } else {
                info.clone()
            };
            for c in item.nodes() {
                r = match c.name.as_str() {
                    "text:list" => self.list(c, Some(&info), out),
                    _ => self.block(c, out, Some(&li)),
                };
                if r.is_err() {
                    break 'items;
                }
            }
        }
        self.depth -= 1;
        r
    }
}
