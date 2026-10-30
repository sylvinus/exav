//! Word 2003 XML (WordprocessingML 2003) to the document model.

mod props;

use crate::formats::office::common::base64;
use crate::formats::office::common::image;
use crate::formats::office::common::xml::{self, Node};
use crate::formats::office::docs::error::{Error, Result};
use crate::formats::office::docs::limits::Budget;
use crate::formats::office::docs::model::*;
use props::*;
use std::collections::HashMap;

struct Wml<'a> {
    b: &'a mut Budget,
    doc: Document,
    media: HashMap<String, usize>,
    bin: HashMap<String, Vec<u8>>,
    next_bookmark: u32,
    depth: u32,
    in_note: bool,
}

/// UTF-16 text (with a byte order mark) as UTF-8; other bytes as they are.
fn utf8(input: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let (le, rest) = match input {
        [0xFF, 0xFE, rest @ ..] => (true, rest),
        [0xFE, 0xFF, rest @ ..] => (false, rest),
        _ => return std::borrow::Cow::Borrowed(input),
    };
    let units: Vec<u16> = rest
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            if le {
                u16::from_le_bytes(*c)
            } else {
                u16::from_be_bytes(*c)
            }
        })
        .collect();
    std::borrow::Cow::Owned(String::from_utf16_lossy(&units).into_bytes())
}

pub(crate) fn read(input: &[u8], budget: &mut Budget) -> Result<Document> {
    let bytes = utf8(input);
    let root = xml::parse(&bytes, &mut budget.tree())?;
    if root.name != "w:wordDocument" {
        return Err(Error::NotFormat(format!("root element {}", root.name)));
    }
    let mut w = Wml {
        b: budget,
        doc: Document::default(),
        media: HashMap::new(),
        bin: HashMap::new(),
        next_bookmark: 1,
        depth: 0,
        in_note: false,
    };
    w.collect_bin(&root)?;
    if let Some(s) = root.child("w:styles") {
        w.styles(s);
    }
    if let Some(l) = root.child("w:lists") {
        w.lists(l);
    }
    if let Some(d) = root.child("w:docPr")
        && let Some(t) = d.child("w:defaultTabStop")
    {
        w.doc.settings.default_tab_stop = t.attr("w:val").and_then(|v| v.parse().ok());
    }
    let body = root
        .child("w:body")
        .ok_or_else(|| Error::NotFormat("no body".into()))?;
    let mut blocks = vec![];
    w.body(body, &mut blocks)?;
    // The section properties of the body end the last section; with none,
    // the last section end found takes their place.
    let final_sect = match body.child("w:sectPr") {
        Some(s) => Some(w.sect_pr(s)?),
        None => blocks.iter_mut().rev().find_map(|b| match b {
            Block::Para(p) => p.section.take().map(|s| *s),
            _ => None,
        }),
    };
    w.doc.body = blocks;
    w.doc.section = final_sect.unwrap_or_default();
    Ok(w.doc)
}

impl Wml<'_> {
    fn collect_bin(&mut self, n: &Node) -> Result<()> {
        let max = self.b.limits.max_part as usize;
        let mut stack = vec![n];
        while let Some(x) = stack.pop() {
            if x.name == "w:binData"
                && let Some(name) = x.attr("w:name")
            {
                let text = crate::formats::office::common::odf::text_of(x);
                if let Some(d) = base64::decode(&text, max) {
                    self.b.alloc(d.len() as u64)?;
                    self.bin.insert(name.to_string(), d);
                }
            }
            stack.extend(x.nodes());
        }
        Ok(())
    }

    fn media_of(&mut self, src: &str) -> Result<Option<usize>> {
        if let Some(m) = self.media.get(src) {
            return Ok(Some(*m));
        }
        let Some(d) = self.bin.get(src).cloned() else {
            return Ok(None);
        };
        let Some(ext) = image::ext(&d) else {
            return Ok(None);
        };
        let i = self.doc.add_media(ext, d);
        self.media.insert(src.to_string(), i);
        Ok(Some(i))
    }

    // ---- styles and lists ----

    fn styles(&mut self, n: &Node) {
        for s in n.all("w:style") {
            let kind = match s.attr("w:type") {
                Some("character") => StyleKind::Character,
                Some("table") => StyleKind::Table,
                Some("list") => StyleKind::Numbering,
                _ => StyleKind::Paragraph,
            };
            let Some(id) = s.attr("w:styleId") else {
                continue;
            };
            let name = s
                .child("w:name")
                .and_then(|n| n.attr("w:val"))
                .unwrap_or(id);
            let mut st = Style::new(id, name, kind);
            st.default = is_on(s.attr("w:default"));
            st.based_on = s
                .child("w:basedOn")
                .and_then(|n| n.attr("w:val"))
                .map(str::to_string);
            st.next = s
                .child("w:next")
                .and_then(|n| n.attr("w:val"))
                .map(str::to_string);
            st.q_format = s.child("w:qFormat").is_some();
            if let Some(p) = s.child("w:pPr") {
                st.ppr = para_props(p);
            }
            if let Some(r) = s.child("w:rPr") {
                st.rpr = run_props(r);
            }
            if kind == StyleKind::Table {
                st.tbl = Some(s.child("w:tblPr").map(table_props).unwrap_or_default());
            }
            self.doc.styles.push(st);
        }
    }

    fn lists(&mut self, n: &Node) {
        let mut defs: Vec<String> = vec![];
        for d in n.all("w:listDef") {
            let id = d.attr("w:listDefId").unwrap_or("").to_string();
            let mut levels = vec![];
            for l in d.all("w:lvl") {
                let mut lv = Level::default();
                if let Some(v) = l
                    .child("w:start")
                    .and_then(|s| s.attr("w:val"))
                    .and_then(|v| v.parse().ok())
                {
                    lv.start = v;
                }
                let nfc = l
                    .child("w:nfc")
                    .and_then(|s| s.attr("w:val"))
                    .and_then(|v| v.parse::<u8>().ok())
                    .unwrap_or(0);
                lv.fmt = crate::formats::office::docs::doc::lists::number_format(nfc);
                lv.text = l
                    .child("w:lvlText")
                    .and_then(|s| s.attr("w:val"))
                    .unwrap_or("")
                    .to_string();
                lv.jc = match l.child("w:lvlJc").and_then(|s| s.attr("w:val")) {
                    Some("center") => Jc::Center,
                    Some("right") => Jc::Right,
                    _ => Jc::Left,
                };
                lv.suff = match l.child("w:suff").and_then(|s| s.attr("w:val")) {
                    Some("Space" | "space") => "space",
                    Some("Nothing" | "nothing") => "nothing",
                    _ => "tab",
                };
                lv.legal = l.child("w:isLgl").is_some();
                lv.style = l
                    .child("w:pStyle")
                    .and_then(|s| s.attr("w:val"))
                    .map(str::to_string);
                if let Some(p) = l.child("w:pPr") {
                    lv.ppr = para_props(p);
                }
                if let Some(r) = l.child("w:rPr") {
                    lv.rpr = run_props(r);
                }
                levels.push(lv);
            }
            while levels.len() < 9 {
                levels.push(Level {
                    fmt: "none",
                    ..Level::default()
                });
            }
            levels.truncate(9);
            let aid = self.doc.numbering.abstracts.len() as u32;
            self.doc.numbering.abstracts.push(AbstractNum {
                id: aid,
                multi_level: true,
                levels,
            });
            defs.push(id);
        }
        for l in n.all("w:list") {
            let Some(ilfo) = l.attr("w:ilfo").and_then(|v| v.parse::<u32>().ok()) else {
                continue;
            };
            let abs = l
                .child("w:ilst")
                .and_then(|i| i.attr("w:val"))
                .and_then(|v| defs.iter().position(|d| d == v))
                .unwrap_or(0) as u32;
            let mut overrides = vec![];
            for o in l.all("w:lvlOverride") {
                let lvl = o.attr("w:ilvl").and_then(|v| v.parse().ok()).unwrap_or(0);
                let start = o
                    .child("w:startOverride")
                    .and_then(|s| s.attr("w:val"))
                    .and_then(|v| v.parse().ok());
                overrides.push((lvl, start, None));
            }
            self.doc.numbering.nums.push(Num {
                id: ilfo,
                abstract_id: abs,
                overrides,
            });
        }
    }

    // ---- body ----

    fn body(&mut self, n: &Node, out: &mut Vec<Block>) -> Result<()> {
        if self.depth > 24 {
            return Ok(());
        }
        self.depth += 1;
        let mut r = Ok(());
        for c in n.nodes() {
            r = match c.name.as_str() {
                "w:p" => self.para(c).map(|p| out.push(Block::Para(p))),
                "w:tbl" => self.table(c).map(|t| out.push(Block::Table(t))),
                "wx:sect" | "wx:sub-section" | "wx:pBdrGroup" | "w:customXml" | "w:sdt"
                | "w:sdtContent" | "wx:borders" => self.body(c, out),
                "w:sectPr" if n.name != "w:body" => {
                    // Ends a section: its properties go to the paragraph before.
                    self.sect_pr(c).map(|s| match out.last_mut() {
                        Some(Block::Para(p)) if p.section.is_none() => {
                            p.section = Some(Box::new(s))
                        }
                        _ => out.push(Block::Para(Para {
                            section: Some(Box::new(s)),
                            ..Para::default()
                        })),
                    })
                }
                _ => Ok(()),
            };
            if r.is_err() {
                break;
            }
        }
        self.depth -= 1;
        r
    }

    fn sect_pr(&mut self, n: &Node) -> Result<Section> {
        let mut s = Section {
            width: 12240,
            height: 15840,
            ..Section::default()
        };
        for c in n.nodes() {
            let v = c.attr("w:val");
            let num = |k: &str| c.attr(k).and_then(|x| x.parse::<i32>().ok());
            match c.name.as_str() {
                "w:type" => {
                    s.kind = match v {
                        Some("continuous") => SectionType::Continuous,
                        Some("even-page") => SectionType::EvenPage,
                        Some("odd-page") => SectionType::OddPage,
                        Some("next-column") => SectionType::NextColumn,
                        _ => SectionType::NextPage,
                    }
                }
                "w:pgSz" => {
                    if let Some(w) = num("w:w") {
                        s.width = w;
                    }
                    if let Some(h) = num("w:h") {
                        s.height = h;
                    }
                    s.landscape = c.attr("w:orient") == Some("landscape");
                }
                "w:pgMar" => {
                    for (k, slot) in [
                        ("w:top", &mut s.top),
                        ("w:left", &mut s.left),
                        ("w:bottom", &mut s.bottom),
                        ("w:right", &mut s.right),
                        ("w:header", &mut s.header),
                        ("w:footer", &mut s.footer),
                        ("w:gutter", &mut s.gutter),
                    ] {
                        if let Some(x) = num(k) {
                            *slot = x;
                        }
                    }
                }
                "w:cols" => {
                    s.columns.num = num("w:num").unwrap_or(1).max(1) as u32;
                    s.columns.space = num("w:space").unwrap_or(720);
                    s.columns.separator = is_on(c.attr("w:sep"));
                }
                "w:titlePg" => s.title_page = is_on(v),
                "w:pgNumType" => {
                    s.page_start = num("w:start").map(|x| x.max(0) as u32);
                    s.page_fmt = match c.attr("w:fmt") {
                        Some("lower-roman") => Some("lowerRoman"),
                        Some("upper-roman") => Some("upperRoman"),
                        Some("lower-letter") => Some("lowerLetter"),
                        Some("upper-letter") => Some("upperLetter"),
                        _ => None,
                    };
                }
                "w:hdr" | "w:ftr" => {
                    let header = c.name == "w:hdr";
                    let save = self.depth;
                    self.depth += 4;
                    let mut blocks = vec![];
                    self.body(c, &mut blocks)?;
                    self.depth = save;
                    let hf = if header {
                        &mut s.headers
                    } else {
                        &mut s.footers
                    };
                    match c.attr("w:type") {
                        Some("even") => {
                            hf.even = Some(blocks);
                            self.doc.settings.even_and_odd_headers = true;
                        }
                        Some("first") => hf.first = Some(blocks),
                        _ => hf.default = Some(blocks),
                    }
                }
                _ => {}
            }
        }
        Ok(s)
    }

    // ---- paragraphs ----

    fn para(&mut self, n: &Node) -> Result<Para> {
        self.b.paragraph(16)?;
        let mut p = Para::default();
        if let Some(pp) = n.child("w:pPr") {
            p.props = para_props(pp);
            if let Some(r) = pp.child("w:rPr") {
                p.mark = run_props(r);
            }
            if let Some(s) = pp.child("w:sectPr") {
                let s = self.sect_pr(s)?;
                p.section = Some(Box::new(s));
            }
        }
        self.inlines(n, &mut p.content)?;
        self.b.inlines(&p.content)?;
        Ok(p)
    }

    fn inlines(&mut self, n: &Node, out: &mut Vec<Inline>) -> Result<()> {
        if self.depth > 48 {
            return Ok(());
        }
        self.depth += 1;
        let mut r = Ok(());
        for c in n.nodes() {
            r = self.inline(c, out);
            if r.is_err() {
                break;
            }
        }
        self.depth -= 1;
        r
    }

    fn inline(&mut self, c: &Node, out: &mut Vec<Inline>) -> Result<()> {
        match c.name.as_str() {
            "w:r" => self.run(c, out)?,
            "w:hlink" => {
                let mut content = vec![];
                self.inlines(c, &mut content)?;
                let target = c
                    .attr("w:dest")
                    .map(str::to_string)
                    .filter(|t| crate::formats::office::docs::fields::safe_target(t));
                let anchor = c
                    .attr("w:bookmark")
                    .map(crate::formats::office::docs::rtf::bm_name);
                if target.is_some() || anchor.is_some() {
                    out.push(Inline::Hyperlink {
                        target,
                        anchor,
                        tooltip: c.attr("w:screenTip").map(str::to_string),
                        content,
                    });
                } else {
                    out.extend(content);
                }
            }
            "w:fldSimple" => {
                let mut result = vec![];
                self.inlines(c, &mut result)?;
                out.push(Inline::Field {
                    instr: c.attr("w:instr").unwrap_or("").to_string(),
                    props: RunProps::default(),
                    result,
                });
            }
            "w:bookmarkStart" => {
                if let Some(name) = c.attr("w:name") {
                    let id = c
                        .attr("w:id")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or_else(|| {
                            let i = self.next_bookmark;
                            self.next_bookmark += 1;
                            i
                        });
                    out.push(Inline::BookmarkStart {
                        id,
                        name: crate::formats::office::docs::rtf::bm_name(name),
                    });
                }
            }
            "w:bookmarkEnd" => {
                if let Some(id) = c.attr("w:id").and_then(|v| v.parse().ok()) {
                    out.push(Inline::BookmarkEnd(id));
                }
            }
            "aml:annotation" => self.annotation(c, out)?,
            "w:smartTag" | "w:customXml" | "w:ins" | "w:sdt" | "w:sdtContent" => {
                self.inlines(c, out)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn annotation(&mut self, c: &Node, out: &mut Vec<Inline>) -> Result<()> {
        match c.attr("w:type") {
            Some("Word.Comment") => {
                let id = self.doc.comments.len() as u32;
                let author = c.attr("aml:author").unwrap_or("").to_string();
                let initials: String = author
                    .split_whitespace()
                    .filter_map(|w| w.chars().next())
                    .take(3)
                    .collect();
                let mut blocks = vec![];
                if let Some(content) = c.child("aml:content") {
                    self.depth += 2;
                    self.body(content, &mut blocks)?;
                    self.depth -= 2;
                }
                self.doc.comments.push(Comment {
                    id,
                    author,
                    initials,
                    date: c.attr("aml:createdate").map(str::to_string),
                    content: blocks,
                });
                out.push(Inline::CommentStart(id));
                out.push(Inline::CommentEnd(id));
                out.push(Inline::Run(Run {
                    props: RunProps::default(),
                    items: vec![RunItem::CommentRef(id)],
                }));
            }
            Some("Word.Insertion") => {
                if let Some(content) = c.child("aml:content") {
                    self.inlines(content, out)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn run(&mut self, n: &Node, out: &mut Vec<Inline>) -> Result<()> {
        let props = n.child("w:rPr").map(run_props).unwrap_or_default();
        let mut items: Vec<RunItem> = vec![];
        let flush = |items: &mut Vec<RunItem>, out: &mut Vec<Inline>| {
            if !items.is_empty() {
                out.push(Inline::Run(Run {
                    props: props.clone(),
                    items: std::mem::take(items),
                }));
            }
        };
        for c in n.nodes() {
            match c.name.as_str() {
                "w:t" => {
                    let t = crate::formats::office::common::odf::text_of(c);
                    if !t.is_empty() {
                        items.push(RunItem::Text(t));
                    }
                }
                "w:tab" => items.push(RunItem::Tab),
                "w:br" => items.push(RunItem::Break(match c.attr("w:type") {
                    Some("page") => BreakKind::Page,
                    Some("column") => BreakKind::Column,
                    _ => BreakKind::Line,
                })),
                "w:cr" => items.push(RunItem::Break(BreakKind::Line)),
                "w:noBreakHyphen" => items.push(RunItem::NoBreakHyphen),
                "w:softHyphen" => items.push(RunItem::SoftHyphen),
                "w:pgNum" => items.push(RunItem::PageNumber),
                "w:sym" => {
                    let ch = c
                        .attr("w:char")
                        .and_then(|v| u16::from_str_radix(v, 16).ok());
                    if let (Some(font), Some(ch)) = (c.attr("w:font"), ch) {
                        items.push(RunItem::Symbol {
                            font: font.to_string(),
                            ch,
                        });
                    }
                }
                "w:footnoteRef" => items.push(RunItem::NoteMark(false)),
                "w:annotationRef" => {}
                "w:instrText" => {
                    flush(&mut items, out);
                    out.push(Inline::InstrText(
                        crate::formats::office::common::odf::text_of(c),
                    ));
                }
                "w:fldChar" => {
                    flush(&mut items, out);
                    out.push(Inline::FieldChar(match c.attr("w:fldCharType") {
                        Some("begin") => FieldCharKind::Begin,
                        Some("separate") => FieldCharKind::Separate,
                        _ => FieldCharKind::End,
                    }));
                }
                "w:footnote" => {
                    let id = self.doc.footnotes.len() as u32 + 1;
                    self.doc.footnotes.push(Note {
                        id,
                        content: vec![],
                    });
                    let mut blocks = vec![];
                    if !self.in_note {
                        self.in_note = true;
                        self.depth += 2;
                        let r = self.body(c, &mut blocks);
                        self.depth -= 2;
                        self.in_note = false;
                        r?;
                    }
                    if let Some(f) = self.doc.footnotes.iter_mut().find(|f| f.id == id) {
                        f.content = blocks;
                    }
                    items.push(RunItem::FootnoteRef(id));
                }
                "w:pict" => {
                    if let Some(d) = self.pict(c)? {
                        items.push(RunItem::Drawing(Box::new(d)));
                    }
                }
                _ => {}
            }
        }
        flush(&mut items, out);
        Ok(())
    }

    fn pict(&mut self, n: &Node) -> Result<Option<Drawing>> {
        // The picture's data is named by the image data of its shape.
        let Some(shape) = n.find("v:shape").or_else(|| n.find("v:rect")) else {
            return Ok(None);
        };
        let Some(src) = shape.child("v:imagedata").and_then(|i| i.attr("src")) else {
            return Ok(None);
        };
        let Some(media) = self.media_of(src)? else {
            return Ok(None);
        };
        let style = shape.attr("style").unwrap_or("");
        let dim = |k: &str| {
            style
                .split(';')
                .filter_map(|p| p.split_once(':'))
                .find(|(a, _)| a.trim() == k)
                .and_then(|(_, v)| crate::formats::office::common::odf::emu(v.trim()))
        };
        let natural = image::natural_emu(&self.doc.media[media].data);
        let (cx, cy) = match (dim("width"), dim("height"), natural) {
            (Some(w), Some(h), _) if w > 0 && h > 0 => (w, h),
            (_, _, Some(n)) => n,
            _ => (914_400, 914_400),
        };
        Ok(Some(Drawing {
            anchor: None,
            cx,
            cy,
            name: "Picture".into(),
            descr: None,
            kind: DrawingKind::Picture {
                media,
                crop: Crop::default(),
            },
        }))
    }

    // ---- tables ----

    fn table(&mut self, n: &Node) -> Result<Table> {
        let mut t = Table {
            props: n.child("w:tblPr").map(table_props).unwrap_or_default(),
            ..Table::default()
        };
        if let Some(g) = n.child("w:tblGrid") {
            t.grid = g
                .all("w:gridCol")
                .map(|c| c.attr("w:w").and_then(|v| v.parse().ok()).unwrap_or(0))
                .collect();
        }
        for r in n.all("w:tr") {
            let mut row = Row::default();
            if let Some(p) = r.child("w:trPr") {
                row_props(p, &mut row.props);
            }
            for c in r.all("w:tc") {
                self.b.cell()?;
                let mut cell = Cell::default();
                // A horizontally merged cell continues the one before it:
                // its content is dropped.
                let mut continues = false;
                if let Some(p) = c.child("w:tcPr") {
                    cell.props = cell_props(p);
                    continues = p
                        .child("w:hmerge")
                        .is_some_and(|m| m.attr("w:val") == Some("continue"));
                }
                if continues && let Some(prev) = row.cells.last_mut() {
                    prev.props.grid_span += cell.props.grid_span;
                    continue;
                }
                self.depth += 1;
                let r = self.body(c, &mut cell.content);
                self.depth -= 1;
                r?;
                row.cells.push(cell);
            }
            t.rows.push(row);
        }
        if t.grid.is_empty() {
            let n = t
                .rows
                .iter()
                .map(|r| {
                    r.cells
                        .iter()
                        .map(|c| c.props.grid_span as usize)
                        .sum::<usize>()
                })
                .max()
                .unwrap_or(1);
            t.grid = vec![9000 / n.max(1) as i32; n.max(1)];
        }
        Ok(t)
    }
}
