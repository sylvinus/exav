//! Rich Text Format ([RTF 1.9.1]) to the document model.

mod pict;
mod words;

use crate::formats::office::common::codepage;
use crate::formats::office::docs::error::{Error, Result};
use crate::formats::office::docs::fields::parse_hyperlink;
use crate::formats::office::docs::grid::{self, CellIn, RowIn};
use crate::formats::office::docs::limits::Budget;
use crate::formats::office::docs::model::*;
use exav_unpack::rtf::{Lexer, Tok};
use std::collections::HashMap;

const MAX_DEPTH: usize = 200;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Target {
    None,
    Para(u8),
    Cell(u8),
    Row(u8),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Dest {
    Body,
    Skip,
    FontTable,
    FontEntry(i32),
    ColorTable,
    StyleSheet,
    StyleEntry(usize),
    Pict,
    FldInst,
    FldRslt,
    Field,
    Note,
    HeaderFooter(bool, u8),
    ListTable,
    List(usize),
    ListLevel,
    LevelText,
    ListOverrideTable,
    ListOverride,
    Bookmark(bool),
    LevelNumbers,
    Upr,
}

impl Dest {
    /// Whether text in this destination is document text.
    fn is_text(&self) -> bool {
        matches!(
            self,
            Dest::Body | Dest::FldRslt | Dest::Field | Dest::Note | Dest::HeaderFooter(..)
        )
    }
}

#[derive(Clone)]
pub(crate) struct St {
    pub chp: RunProps,
    pub pap: ParaProps,
    pub ls: Option<i32>,
    pub ilvl: u32,
    pub intbl: bool,
    pub dest: Dest,
    pub uc: u32,
    pub cp: u16,
    pub tab_kind: TabKind,
    pub tab_leader: TabLeader,
    pub target: Target,
    pub story_pushed: bool,
    pub cbpat: Option<usize>,
    pub cfpat: Option<usize>,
    pub shading: i32,
    /// The list level being defined.
    pub level_tmp: Option<Level>,
}

impl St {
    fn new(cp: u16) -> St {
        St {
            chp: RunProps::default(),
            pap: ParaProps::default(),
            ls: None,
            ilvl: 0,
            intbl: false,
            dest: Dest::Body,
            uc: 1,
            cp,
            tab_kind: TabKind::Left,
            tab_leader: TabLeader::None,
            target: Target::None,
            story_pushed: false,
            cbpat: None,
            cfpat: None,
            shading: 0,
            level_tmp: None,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct CellDef {
    pub right: i32,
    pub borders: [Option<Option<Border>>; 4],
    pub shading: Option<Shading>,
    pub vmerge: u8,
    pub hmerge: u8,
    pub valign: u8,
    pub text_flow: u8,
    pub no_wrap: bool,
}

#[derive(Clone, Default)]
pub(crate) struct RowDef {
    pub left: i32,
    pub gap: i32,
    pub height: i32,
    pub header: bool,
    pub keep: bool,
    pub jc: Option<Jc>,
    pub cells: Vec<CellDef>,
    pub cur: CellDef,
    pub borders: TableBorders,
    pub bidi: bool,
}

/// A list override: list id, `\ls` id and the (level, start-at) pairs.
pub(crate) type Override = (i32, i32, Vec<(u32, i64)>);

pub(crate) struct Font {
    pub name: String,
    pub cp: u16,
}

pub(crate) struct RStyle {
    pub num: i32,
    pub kind: StyleKind,
    pub name: String,
    pub based: Option<i32>,
    pub next: Option<i32>,
    pub chp: RunProps,
    pub pap: ParaProps,
    pub ls: Option<i32>,
    pub ilvl: u32,
}

pub(crate) struct ListLevelDef {
    pub level: Level,
    pub text: Vec<u32>,
    pub numbers: Vec<u8>,
}

pub(crate) struct ListDef {
    pub id: i32,
    pub levels: Vec<ListLevelDef>,
    pub simple: bool,
}

struct TblState {
    rows: Vec<RowIn>,
    cells: Vec<CellIn>,
    cur: Vec<Block>,
    cell_defs: Vec<CellDef>,
}

#[derive(Default)]
pub(crate) struct Story {
    pub blocks: Vec<Block>,
    pub para: Option<Para>,
    table: Option<TblState>,
}

pub(crate) struct FieldFrame {
    pub instr: String,
    pub in_result: bool,
    pub sink: Vec<Inline>,
    pub props: RunProps,
    /// The field's marks were written to the paragraph (it spans paragraphs).
    pub broken: bool,
}

pub(crate) struct Parser<'a> {
    pub b: &'a mut Budget,
    pub doc: Document,
    pub lex: Lexer<'a>,
    pub stack: Vec<St>,
    pub fonts: HashMap<i32, Font>,
    pub colors: Vec<Color>,
    pub styles: Vec<RStyle>,
    pub lists: Vec<ListDef>,
    pub overrides: Vec<Override>,
    pub stories: Vec<Story>,
    pub fields: Vec<FieldFrame>,
    pub row: RowDef,
    pub cur_sect: Section,
    pub defaults: Section,
    pub buf: String,
    pub pending: Vec<u8>,
    pub pending_cp: u16,
    pub default_cp: u16,
    pub deff: i32,
    pub next_bookmark: u32,
    pub bookmarks: HashMap<String, u32>,
    pub pict: Option<pict::Pict>,
    pub note_endnote: bool,
    pub color_cur: [i32; 3],
    pub color_any: bool,
    pub list_ids: Vec<i32>,
    pub facing: bool,
    pub list_text: Vec<u32>,
    pub list_numbers: Vec<u8>,
    pub tokens: u64,
    /// The first memory charge that was refused, for the main loop to raise:
    /// text and runs are added from places that return nothing.
    pub over: Option<Error>,
}

pub(crate) fn read(input: &[u8], budget: &mut Budget) -> Result<Document> {
    let head = input.iter().take(64).copied().collect::<Vec<u8>>();
    let start = head
        .windows(5)
        .position(|w| w == b"{\\rtf")
        .ok_or_else(|| Error::NotFormat("no {\\rtf header".into()))?;
    let data = &input[start..];
    let mut p = Parser {
        b: budget,
        doc: Document::default(),
        lex: Lexer::new(data),
        stack: vec![],
        fonts: HashMap::new(),
        colors: vec![],
        styles: vec![],
        lists: vec![],
        overrides: vec![],
        stories: vec![Story::default()],
        fields: vec![],
        row: RowDef::default(),
        cur_sect: Section::default(),
        defaults: Section {
            width: 12240,
            height: 15840,
            left: 1800,
            right: 1800,
            top: 1440,
            bottom: 1440,
            ..Section::default()
        },
        buf: String::new(),
        pending: vec![],
        pending_cp: 1252,
        default_cp: 1252,
        deff: 0,
        next_bookmark: 1,
        bookmarks: HashMap::new(),
        pict: None,
        note_endnote: false,
        color_cur: [0; 3],
        color_any: false,
        list_ids: vec![],
        facing: false,
        list_text: vec![],
        list_numbers: vec![],
        tokens: 0,
        over: None,
    };
    p.cur_sect = p.defaults.clone();
    p.run()?;
    if let Some(e) = p.over.take() {
        return Err(e);
    }
    p.finish()
}

impl Parser<'_> {
    /// The innermost group's state; a document whose groups were closed
    /// early has the defaults.
    fn top(&mut self) -> &mut St {
        if self.stack.is_empty() {
            self.stack.push(St::new(self.default_cp));
        }
        let n = self.stack.len();
        &mut self.stack[n - 1]
    }

    fn run(&mut self) -> Result<()> {
        let max = self.b.limits.max_part;
        // The outermost group has been closed: a file with a `}` too many
        // (html2rtf writes them) goes on, as unrtf reads it, in a group of its
        // own.
        let mut closed = false;
        while let Some(t) = self.lex.next_tok() {
            self.tokens += 1;
            if self.tokens > 200_000_000 {
                return Err(Error::TooLarge("tokens"));
            }
            if let Some(e) = self.over.take() {
                return Err(e);
            }
            if closed && !matches!(t, Tok::Close) {
                closed = false;
                if matches!(t, Tok::Open | Tok::Word(..) | Tok::Text(_)) {
                    self.stack.push(St::new(self.default_cp));
                }
            }
            match t {
                Tok::Open => {
                    if self.stack.len() >= MAX_DEPTH {
                        return Err(Error::Malformed("groups nested too deep".into()));
                    }
                    self.flush_text();
                    let st = match self.stack.last() {
                        Some(s) => {
                            let mut c = s.clone();
                            c.story_pushed = false;
                            c
                        }
                        None => St::new(self.default_cp),
                    };
                    self.stack.push(st);
                }
                Tok::Close => {
                    self.flush_text();
                    if self.stack.is_empty() {
                        continue;
                    }
                    self.close_group()?;
                    closed = self.stack.is_empty();
                }
                Tok::Word(w, n) => {
                    if self.stack.is_empty() {
                        // Before the first group: only {\rtf starts the document.
                        continue;
                    }
                    // The text so far has the formatting the word will change.
                    self.flush_text();
                    self.word(w, n, max)?;
                }
                Tok::Hex(b) => {
                    if self.stack.is_empty() {
                        continue;
                    }
                    self.hex(b);
                }
                Tok::Sym(c) => {
                    if !self.stack.is_empty() {
                        self.symbol(c);
                    }
                }
                Tok::Text(t) => {
                    if self.stack.is_empty() {
                        continue;
                    }
                    self.text_bytes(t);
                }
            }
        }
        Ok(())
    }

    // ---- text ----

    fn hex(&mut self, b: u8) {
        let Some(dest) = self.stack.last().map(|s| s.dest.clone()) else {
            return;
        };
        if dest == Dest::LevelNumbers {
            self.list_numbers.push(b);
            return;
        }
        if dest.is_text()
            || matches!(
                dest,
                Dest::FontEntry(_)
                    | Dest::StyleEntry(_)
                    | Dest::Bookmark(_)
                    | Dest::FldInst
                    | Dest::LevelText
            )
        {
            let cp = self.stack.last().map(|s| s.cp).unwrap_or(1252);
            if self.pending_cp != cp {
                self.flush_text();
                self.pending_cp = cp;
            }
            self.pending.push(b);
            if dest == Dest::LevelText {
                self.flush_text();
            }
        }
    }

    fn text_bytes(&mut self, t: &[u8]) {
        let (dest, cp) = match self.stack.last() {
            Some(s) => (s.dest.clone(), s.cp),
            None => return,
        };
        match dest {
            Dest::Pict => self.pict_data(t),
            Dest::Skip | Dest::ColorTable | Dest::ListTable | Dest::ListOverrideTable => {
                if dest == Dest::ColorTable {
                    self.color_text(t);
                }
            }
            _ => {
                if self.pending_cp != cp {
                    self.flush_text();
                    self.pending_cp = cp;
                }
                self.pending.extend_from_slice(t);
            }
        }
    }

    fn color_text(&mut self, t: &[u8]) {
        if t.contains(&b';') {
            for _ in t.iter().filter(|c| **c == b';') {
                self.color_end();
            }
        }
    }

    fn color_end(&mut self) {
        let c = if self.color_any {
            let [r, g, b] = self.color_cur;
            Color::Rgb((r as u32 & 0xFF) << 16 | (g as u32 & 0xFF) << 8 | (b as u32 & 0xFF))
        } else {
            Color::Auto
        };
        if self.colors.len() < 1024 {
            self.colors.push(c);
        }
        self.color_cur = [0; 3];
        self.color_any = false;
    }

    /// Writes the pending bytes to wherever the current destination puts text.
    pub(crate) fn flush_text(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let bytes = std::mem::take(&mut self.pending);
        let s = if bytes.iter().all(|b| *b < 0x80) {
            String::from_utf8_lossy(&bytes).into_owned()
        } else {
            codepage::decode(&bytes, self.pending_cp)
        };
        self.put_str(&s);
    }

    pub(crate) fn put_str(&mut self, s: &str) {
        let Some(dest) = self.stack.last().map(|s| s.dest.clone()) else {
            return;
        };
        match dest {
            Dest::FontEntry(n) => {
                // A name ends at its semicolon, with or without a group around.
                match s.split_once(';') {
                    Some((name, _)) => {
                        self.buf.push_str(name);
                        let name = self.buf.trim().to_string();
                        self.buf.clear();
                        if let Some(f) = self.fonts.get_mut(&n)
                            && f.name.is_empty()
                        {
                            f.name = name;
                        }
                        self.top().dest = Dest::FontTable;
                    }
                    None => self.buf.push_str(s),
                }
            }
            Dest::StyleEntry(_) | Dest::Bookmark(_) => self.buf.push_str(s),
            Dest::FldInst => {
                if let Some(f) = self.fields.last_mut() {
                    f.instr.push_str(s);
                }
            }
            Dest::LevelText => {
                for c in s.chars() {
                    self.list_text.push(c as u32);
                }
            }
            d if d.is_text() => self.emit(s),
            _ => {}
        }
    }

    /// Document text with the formatting in effect.
    pub(crate) fn emit(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        // Control characters stand for nothing.
        let s: String = s.chars().filter(|c| *c >= ' ' || *c == '\t').collect();
        if s.is_empty() {
            return;
        }
        self.add_item(RunItem::Text(s));
    }

    /// `bytes` more held in the model. A refusal is kept for the main loop.
    fn charge(&mut self, bytes: usize) {
        if self.over.is_none()
            && let Err(e) = self.b.alloc(bytes as u64)
        {
            self.over = Some(e);
        }
    }

    pub(crate) fn add_item(&mut self, item: RunItem) {
        let text = match &item {
            RunItem::Text(t) => t.len(),
            _ => 0,
        };
        self.charge(text);
        let rp = self.top().chp.clone();
        let content = self.content_mut();
        if let Some(Inline::Run(r)) = content.last_mut()
            && r.props == rp
        {
            if let (RunItem::Text(t), Some(RunItem::Text(last))) = (&item, r.items.last_mut()) {
                last.push_str(t);
                return;
            }
            r.items.push(item);
            self.charge(size_of::<RunItem>());
            return;
        }
        content.push(Inline::Run(Run {
            props: rp,
            items: vec![item],
        }));
        self.charge(size_of::<Inline>() + size_of::<RunItem>());
    }

    fn story(&mut self) -> &mut Story {
        let n = self.stories.len();
        &mut self.stories[n - 1]
    }

    fn ensure_para(&mut self) {
        if self.story().para.is_none() {
            self.story().para = Some(Para::default());
        }
    }

    pub(crate) fn content_mut(&mut self) -> &mut Vec<Inline> {
        let in_result = self.fields.last().is_some_and(|f| f.in_result && !f.broken);
        if in_result {
            let n = self.fields.len();
            return &mut self.fields[n - 1].sink;
        }
        self.ensure_para();
        let Some(p) = self.story().para.as_mut() else {
            unreachable!("a paragraph was just ensured")
        };
        &mut p.content
    }

    fn symbol(&mut self, c: u8) {
        let dest = self.stack.last().map(|s| s.dest.clone());
        match c {
            b'*' => {
                // An ignorable destination: read the control word that follows.
                self.flush_text();
                let save = self.lex.p;
                match self.lex.next_tok() {
                    Some(Tok::Word(w, n)) => {
                        let known = words::star_destination(self, w, n);
                        if !known {
                            self.top().dest = Dest::Skip;
                        }
                    }
                    _ => self.lex.p = save,
                }
            }
            b'~' => self.char_item(RunItem::Text("\u{A0}".into()), dest),
            b'-' => self.char_item(RunItem::SoftHyphen, dest),
            b'_' => self.char_item(RunItem::NoBreakHyphen, dest),
            b'\\' | b'{' | b'}' => {
                let s = (c as char).to_string();
                self.flush_text();
                self.put_str(&s);
            }
            b':' | b'|' => {}
            _ => {}
        }
    }

    pub(crate) fn char_item(&mut self, item: RunItem, dest: Option<Dest>) {
        self.flush_text();
        if dest.is_some_and(|d| d.is_text()) {
            self.add_item(item);
        }
    }

    // ---- groups ----

    fn close_group(&mut self) -> Result<()> {
        let Some(st) = self.stack.pop() else {
            return Ok(());
        };
        match &st.dest {
            Dest::FontEntry(n) => {
                let name = self.buf.trim().trim_end_matches(';').trim().to_string();
                self.buf.clear();
                if let Some(f) = self.fonts.get_mut(n)
                    && f.name.is_empty()
                {
                    f.name = name;
                }
            }
            Dest::StyleEntry(i) => {
                let name = self.buf.trim().trim_end_matches(';').trim().to_string();
                self.buf.clear();
                if let Some(s) = self.styles.get_mut(*i) {
                    s.name = name;
                    s.chp = st.chp.clone();
                    s.pap = st.pap.clone();
                    s.ls = st.ls;
                    s.ilvl = st.ilvl;
                }
            }
            Dest::Bookmark(start) => {
                let name = self.buf.trim().to_string();
                self.buf.clear();
                if !name.is_empty() {
                    if *start {
                        let id = self.next_bookmark;
                        self.next_bookmark += 1;
                        self.bookmarks.insert(name.clone(), id);
                        let n = crate::formats::office::docs::rtf::bm_name(&name);
                        self.content_mut()
                            .push(Inline::BookmarkStart { id, name: n });
                    } else if let Some(id) = self.bookmarks.remove(&name) {
                        self.content_mut().push(Inline::BookmarkEnd(id));
                    }
                }
            }
            Dest::Pict => self.finish_pict(&st)?,
            Dest::Note => self.finish_note(&st)?,
            Dest::HeaderFooter(header, which) => self.finish_header(*header, *which)?,
            Dest::FldInst => {}
            Dest::FldRslt => {
                if let Some(f) = self.fields.last_mut() {
                    f.in_result = false;
                }
            }
            Dest::Field => self.finish_field(),
            Dest::List(_) | Dest::ListTable | Dest::ListOverrideTable | Dest::ListOverride => {}
            Dest::ListLevel => words::finish_level(self, &st),
            _ => {}
        }
        Ok(())
    }

    // ---- paragraphs and tables ----

    /// Closes the paragraph being written, if any, with the properties now in
    /// effect. `force` makes an empty one.
    pub(crate) fn close_para(&mut self, force: bool) -> Result<()> {
        // A field that spans the paragraph is written out as marks.
        self.break_fields();
        let st = self.top().clone();
        let has = self.story().para.is_some();
        if !has && !force {
            return Ok(());
        }
        let mut para = self.story().para.take().unwrap_or_default();
        self.b.paragraph(8)?;
        para.props = self.para_props(&st);
        para.mark = st.chp.clone();
        self.place(Block::Para(para), st.intbl)
    }

    fn para_props(&mut self, st: &St) -> ParaProps {
        let mut p = st.pap.clone();
        if let Some(ls) = st.ls.filter(|l| *l > 0) {
            p.num_id = Some(ls as u32);
            p.num_level = Some(st.ilvl.min(8));
        }
        if let Some(c) = st.cbpat.and_then(|i| self.colors.get(i).copied()) {
            let fore = st.cfpat.and_then(|i| self.colors.get(i).copied());
            p.shading = match (st.shading, fore) {
                (s, Some(f)) if s > 0 && s < 10000 => {
                    crate::formats::office::docs::rtf::blend(f, c, f64::from(s) / 10000.0)
                }
                _ => Some(Shading::fill(c)),
            };
        }
        p
    }

    fn place(&mut self, b: Block, intbl: bool) -> Result<()> {
        if intbl {
            let story = self.story();
            let t = story.table.get_or_insert_with(|| TblState {
                rows: vec![],
                cells: vec![],
                cur: vec![],
                cell_defs: vec![],
            });
            t.cur.push(b);
            return Ok(());
        }
        self.end_table();
        self.story().blocks.push(b);
        Ok(())
    }

    /// Closes the table in progress.
    pub(crate) fn end_table(&mut self) {
        let Some(t) = self.story().table.take() else {
            return;
        };
        let mut t = t;
        if !t.cur.is_empty() || !t.cells.is_empty() {
            // Cells without a row end: a row of what there is.
            let cur = std::mem::take(&mut t.cur);
            if !cur.is_empty() {
                t.cells.push(CellIn {
                    props: CellProps::default(),
                    content: cur,
                    merged_left: false,
                });
            }
            let cells = std::mem::take(&mut t.cells);
            if !cells.is_empty() {
                let edges = (0..=cells.len() as i32).map(|i| i * 1000).collect();
                t.rows.push(RowIn {
                    edges,
                    props: RowProps::default(),
                    cells,
                });
            }
        }
        if t.rows.is_empty() {
            return;
        }
        let first = t.cell_defs.first().cloned();
        let _ = first;
        let table = grid::build(t.rows, TableProps::default());
        self.story().blocks.push(Block::Table(table));
    }

    /// `\cell`.
    pub(crate) fn end_cell(&mut self) -> Result<()> {
        // The paragraph ends with the cell.
        let st = self.top().clone();
        if self.story().para.is_some() {
            self.close_para(false)?;
        } else if self.story().table.as_ref().is_none_or(|t| t.cur.is_empty()) {
            // An empty cell has an empty paragraph.
            let mut st2 = st.clone();
            st2.intbl = true;
            let n = self.stack.len();
            self.stack[n - 1] = st2;
            self.close_para(true)?;
            self.stack[n - 1] = st;
        }
        self.b.cell()?;
        let story = self.story();
        let t = story.table.get_or_insert_with(|| TblState {
            rows: vec![],
            cells: vec![],
            cur: vec![],
            cell_defs: vec![],
        });
        let content = std::mem::take(&mut t.cur);
        t.cells.push(CellIn {
            props: CellProps::default(),
            content,
            merged_left: false,
        });
        Ok(())
    }

    /// `\row`.
    pub(crate) fn end_row(&mut self) -> Result<()> {
        if self.story().para.is_some() {
            self.close_para(false)?;
        }
        let def = self.row.clone();
        let story = self.story();
        let t = story.table.get_or_insert_with(|| TblState {
            rows: vec![],
            cells: vec![],
            cur: vec![],
            cell_defs: vec![],
        });
        let mut cells = std::mem::take(&mut t.cells);
        if !t.cur.is_empty() {
            let content = std::mem::take(&mut t.cur);
            cells.push(CellIn {
                props: CellProps::default(),
                content,
                merged_left: false,
            });
        }
        let mut edges = vec![def.left];
        for c in &def.cells {
            edges.push(c.right);
        }
        let n = def.cells.len();
        let mut row = RowIn {
            edges,
            props: RowProps::default(),
            cells: vec![],
        };
        row.props.header = def.header;
        row.props.cant_split = def.keep;
        if def.height != 0 {
            row.props.height = Some(def.height.abs());
            row.props.height_exact = def.height < 0;
        }
        row.props.jc = def.jc;
        for (k, c) in cells.into_iter().enumerate() {
            let d = def.cells.get(k.min(n.saturating_sub(1)));
            let mut cp = CellProps::default();
            let mut merged = false;
            if let Some(d) = d.filter(|_| k < n) {
                cp.shading = d.shading.clone();
                cp.v_merge = match d.vmerge {
                    1 => VMerge::Restart,
                    2 => VMerge::Continue,
                    _ => VMerge::None,
                };
                cp.v_align = match d.valign {
                    1 => Some(VAlign::Center),
                    2 => Some(VAlign::Bottom),
                    _ => None,
                };
                cp.no_wrap = d.no_wrap;
                cp.text_direction = match d.text_flow {
                    1 => Some("btLr"),
                    2 => Some("tbRl"),
                    _ => None,
                };
                for (slot, b) in [
                    (&mut cp.borders.top, &d.borders[0]),
                    (&mut cp.borders.left, &d.borders[1]),
                    (&mut cp.borders.bottom, &d.borders[2]),
                    (&mut cp.borders.right, &d.borders[3]),
                ] {
                    *slot = match b {
                        None => None,
                        Some(Some(b)) => Some(b.clone()),
                        Some(None) => Some(Border {
                            style: "nil",
                            size: 0,
                            space: 0,
                            color: Color::Auto,
                            shadow: false,
                        }),
                    };
                }
                merged = d.hmerge == 2;
            }
            row.cells.push(CellIn {
                props: cp,
                content: c.content,
                merged_left: merged,
            });
        }
        row.edges.truncate(row.cells.len() + 1);
        while row.edges.len() < row.cells.len() + 1 {
            let last = row.edges.last().copied().unwrap_or(0);
            row.edges.push(last + 1000);
        }
        t.cell_defs = def.cells.clone();
        t.rows.push(row);
        Ok(())
    }

    // ---- fields ----

    pub(crate) fn begin_field(&mut self) {
        let props = self.top().chp.clone();
        self.fields.push(FieldFrame {
            instr: String::new(),
            in_result: false,
            sink: vec![],
            props,
            broken: false,
        });
    }

    fn finish_field(&mut self) {
        let Some(f) = self.fields.pop() else { return };
        if f.broken {
            self.content_mut()
                .push(Inline::FieldChar(FieldCharKind::End));
            return;
        }
        let instr = f.instr.trim().to_string();
        let word = instr
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let inl = match word.as_str() {
            "HYPERLINK" => {
                let (target, anchor, tip) = parse_hyperlink(&instr);
                if target.is_none() && anchor.is_none() {
                    f.sink
                } else {
                    vec![Inline::Hyperlink {
                        target,
                        anchor: anchor.map(|a| crate::formats::office::docs::rtf::bm_name(&a)),
                        tooltip: tip,
                        content: f.sink,
                    }]
                }
            }
            "XE" | "TC" | "TA" | "RD" => vec![],
            _ => vec![Inline::Field {
                instr: format!(" {instr} "),
                props: f.props,
                result: f.sink,
            }],
        };
        self.content_mut().extend(inl);
    }

    /// Writes the fields still open as marks, so that a paragraph can end.
    fn break_fields(&mut self) {
        if self.fields.is_empty() {
            return;
        }
        let n = self.fields.len();
        let mut out = vec![];
        for i in 0..n {
            if self.fields[i].broken {
                continue;
            }
            let f = &mut self.fields[i];
            out.push(Inline::FieldChar(FieldCharKind::Begin));
            out.push(Inline::InstrText(f.instr.clone()));
            if f.in_result {
                out.push(Inline::FieldChar(FieldCharKind::Separate));
            }
            out.append(&mut f.sink);
            f.broken = true;
        }
        self.ensure_para();
        if let Some(p) = self.story().para.as_mut() {
            p.content.extend(out);
        }
    }

    // ---- stories ----

    pub(crate) fn push_story(&mut self) {
        self.stories.push(Story::default());
        self.top().story_pushed = true;
    }

    fn pop_story(&mut self) -> Result<Vec<Block>> {
        if self.stories.len() <= 1 {
            return Ok(vec![]);
        }
        self.close_para_in_story()?;
        let mut s = self.stories.pop().unwrap_or_default();
        let _ = &mut s;
        let mut t = Story {
            blocks: s.blocks,
            para: None,
            table: s.table,
        };
        if t.table.is_some() {
            std::mem::swap(&mut t, self.story());
            self.end_table();
            std::mem::swap(&mut t, self.story());
            let blocks = t.blocks;
            return Ok(blocks);
        }
        Ok(t.blocks)
    }

    fn close_para_in_story(&mut self) -> Result<()> {
        if self.story().para.is_some() {
            let saved = self.stack.last().cloned();
            self.close_para(false)?;
            if let (Some(saved), Some(top)) = (saved, self.stack.last_mut()) {
                *top = saved;
            }
        }
        Ok(())
    }

    fn finish_note(&mut self, st: &St) -> Result<()> {
        let endnote = self.note_endnote;
        self.note_endnote = false;
        let _ = st;
        let mut blocks = self.pop_story()?;
        let list = if endnote {
            &mut self.doc.endnotes
        } else {
            &mut self.doc.footnotes
        };
        let id = list.len() as u32 + 1;
        // The number the note starts with is the mark.
        let _ = &mut blocks;
        list.push(Note {
            id,
            content: blocks,
        });
        let mut sup = self.top().chp.clone();
        sup.vert_align = Some(VertAlign::Superscript);
        let content = self.content_mut();
        content.push(Inline::Run(Run {
            props: sup,
            items: vec![if endnote {
                RunItem::EndnoteRef(id)
            } else {
                RunItem::FootnoteRef(id)
            }],
        }));
        Ok(())
    }

    fn finish_header(&mut self, header: bool, which: u8) -> Result<()> {
        let blocks = self.pop_story()?;
        if blocks.is_empty() {
            return Ok(());
        }
        let hf = if header {
            &mut self.cur_sect.headers
        } else {
            &mut self.cur_sect.footers
        };
        match which {
            0 => {
                hf.default = Some(blocks.clone());
                hf.even = hf.even.take().or(None);
            }
            1 => hf.even = Some(blocks),
            2 => hf.default = Some(blocks),
            _ => hf.first = Some(blocks),
        }
        Ok(())
    }

    /// `\sect`.
    pub(crate) fn end_section(&mut self) -> Result<()> {
        self.close_para(false)?;
        self.end_table();
        let sect = std::mem::replace(&mut self.cur_sect, self.defaults.clone());
        let mut next = sect.clone();
        next.headers = HeaderFooter::default();
        next.footers = HeaderFooter::default();
        let mut s = sect;
        if !s.title_page {
            s.headers.first = None;
            s.footers.first = None;
        }
        self.cur_sect = next;
        let blocks = &mut self.stories[0].blocks;
        match blocks.last_mut() {
            Some(Block::Para(p)) if p.section.is_none() => p.section = Some(Box::new(s)),
            _ => blocks.push(Block::Para(Para {
                section: Some(Box::new(s)),
                ..Para::default()
            })),
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Document> {
        self.flush_text();
        while self.stack.len() > 1 {
            self.stack.pop();
        }
        if self.stack.is_empty() {
            self.stack.push(St::new(self.default_cp));
        }
        self.close_para(false)?;
        self.end_table();
        let mut sect = self.cur_sect.clone();
        if !sect.title_page {
            sect.headers.first = None;
            sect.footers.first = None;
        }
        if !self.facing {
            sect.headers.even = None;
            sect.footers.even = None;
        }
        self.doc.section = sect;
        self.doc.body = std::mem::take(&mut self.stories[0].blocks);
        self.doc.settings.even_and_odd_headers = self.facing;
        words::build_styles(&mut self);
        words::build_lists(&mut self);
        if let Some(f) = self.fonts.get(&self.deff) {
            self.doc.defaults_run.fonts = Fonts {
                ascii: Some(f.name.clone()),
                hansi: Some(f.name.clone()),
                east_asia: Some(f.name.clone()),
                cs: Some(f.name.clone()),
            };
        }
        if self.doc.defaults_run.size.is_none() {
            self.doc.defaults_run.size = Some(24);
        }
        Ok(self.doc)
    }
}

/// A bookmark name a DOCX bookmark can hold.
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

/// `p` of `fore` over `back` as a flat colour.
pub(crate) fn blend(fore: Color, back: Color, p: f64) -> Option<Shading> {
    let rgb = |c: Color, auto: u32| match c {
        Color::Rgb(v) => v,
        Color::Auto => auto,
    };
    let (f, b) = (rgb(fore, 0), rgb(back, 0xFFFFFF));
    let mix = |s: u32| {
        let (x, y) = (f64::from((f >> s) & 0xFF), f64::from((b >> s) & 0xFF));
        (x * p + y * (1.0 - p)).round() as u32
    };
    Some(Shading::fill(Color::Rgb(
        mix(16) << 16 | mix(8) << 8 | mix(0),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bookmark_names() {
        assert_eq!(bm_name("a b-c"), "a_b_c");
        assert_eq!(bm_name("1x"), "_1x");
    }
}
