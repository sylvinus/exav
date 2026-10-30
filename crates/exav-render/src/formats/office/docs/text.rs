//! The words of a document model, in reading order, for a scanner or a
//! search. Taken from what the readers made; no DOCX is written.
//!
//! Text is what a reader sees: runs, table cells (a row to a line, its cells
//! separated by a tab), the text of text boxes and shapes, a picture's alt
//! text, headers and footers, footnotes, endnotes and comments, each of the
//! last four in a section of its own. It is not list numbering, a bookmark, a
//! field instruction, a page number, hidden text or a note's own mark.

use super::fields::parse_hyperlink;
use super::model::*;
use crate::formats::office::text::Out;
use std::collections::{HashMap, HashSet};

/// Nesting of tables, shapes and fields followed. Deeper content is left out.
const MAX_DEPTH: u32 = 64;
/// Complex fields open at once. Marks past it are counted, not tracked.
const MAX_FIELDS: usize = 64;
/// Bytes of a field instruction kept; the first word and a target are in it.
const MAX_INSTR: usize = 4096;
/// Links open at once. Out keeps 16; the rest are plain text.
const MAX_LINKS_OPEN: usize = 8;
/// Characters of white space held back between words.
const MAX_WS: usize = 256;
/// Tab separators held back between cells.
const MAX_TABS: usize = 4096;
/// Bytes of a header or footer compared with the ones before it.
const PROBE_CAP: usize = 1 << 20;

/// Writes the text of `doc` to `out`: the body, then headers and footers,
/// footnotes, endnotes and comments, each a section.
pub(crate) fn lines(doc: &Document, out: &mut Out) {
    let hidden = Hidden::new(doc);
    let mut w = Walk::new(&hidden, out);
    w.collect = true;
    w.blocks(&doc.body);
    w.end_story();
    w.collect = false;

    // The last section's properties are the document's.
    let mut sections = std::mem::take(&mut w.sections);
    sections.push(&doc.section);
    if !w.out.full() {
        w.out.section("headers and footers");
    }
    // A header the sections share is read once.
    let mut seen: HashSet<String> = HashSet::new();
    for s in sections {
        for hf in [&s.headers, &s.footers] {
            for blocks in [&hf.default, &hf.first, &hf.even].into_iter().flatten() {
                if w.out.full() {
                    return;
                }
                let mut probe = Out::new(PROBE_CAP);
                Walk::new(&hidden, &mut probe).blocks_story(blocks);
                let t = probe.finish();
                if !t.truncated && !seen.insert(t.text) {
                    continue;
                }
                w.blocks_story(blocks);
            }
        }
    }

    for (label, notes) in [("footnotes", &doc.footnotes), ("endnotes", &doc.endnotes)] {
        if w.out.full() {
            return;
        }
        w.out.section(label);
        for n in notes {
            w.blocks_story(&n.content);
        }
    }
    if w.out.full() {
        return;
    }
    w.out.section("comments");
    for c in &doc.comments {
        w.blocks_story(&c.content);
    }
}

/// Which styles hide their text.
struct Hidden<'a> {
    /// Style id to whether the style, or one it is based on, hides.
    styles: HashMap<&'a str, bool>,
    default: bool,
}

impl<'a> Hidden<'a> {
    fn new(doc: &'a Document) -> Hidden<'a> {
        let mut styles = HashMap::new();
        if doc.styles.iter().any(|s| s.rpr.vanish == Some(true)) {
            let by_id: HashMap<&str, &Style> =
                doc.styles.iter().map(|s| (s.id.as_str(), s)).collect();
            for s in &doc.styles {
                let mut cur = s;
                for _ in 0..32 {
                    if let Some(v) = cur.rpr.vanish {
                        styles.insert(s.id.as_str(), v);
                        break;
                    }
                    match cur.based_on.as_deref().and_then(|b| by_id.get(b)) {
                        Some(next) => cur = next,
                        None => break,
                    }
                }
            }
        }
        Hidden {
            styles,
            default: doc.defaults_run.vanish == Some(true),
        }
    }

    /// Whether the paragraph's style hides its text unless a run says
    /// otherwise.
    fn para(&self, p: &Para) -> bool {
        p.props
            .style
            .as_deref()
            .and_then(|s| self.styles.get(s))
            .copied()
            .unwrap_or(self.default)
    }

    /// Whether a run is hidden: its own setting, else its character style's,
    /// else the paragraph's.
    fn run(&self, props: &RunProps, para: bool) -> bool {
        props
            .vanish
            .or_else(|| {
                props
                    .style
                    .as_deref()
                    .and_then(|s| self.styles.get(s))
                    .copied()
            })
            .unwrap_or(para)
    }
}

/// What a paragraph leaves for after its own line.
enum Pending<'a> {
    Blocks(&'a [Block]),
    Alt(&'a str),
}

/// A complex field between its begin and end marks.
struct Frame {
    instr: String,
    /// The separator was met: what follows is the result.
    result: bool,
    /// The result is left out (a page number).
    skip: bool,
    /// How many links were open before the field's own: it closes down to
    /// that at its end.
    link: Option<usize>,
}

impl Frame {
    fn hides(&self) -> bool {
        !self.result || self.skip
    }
}

struct Link {
    target: String,
    /// Handed to `Out`: it has a label.
    open: bool,
}

struct Walk<'a, 'b> {
    hidden: &'b Hidden<'a>,
    out: &'b mut Out,
    depth: u32,
    /// Table cells being written: their paragraphs share a line.
    cell: u32,
    /// Cell separators owed before the next word.
    tabs: usize,
    /// A paragraph of this cell wrote text: a space owed before the next.
    cell_sep: bool,
    /// Nothing written yet on this line of the paragraph or cell.
    at_start: bool,
    /// White space after the last word, written only if a word follows.
    ws: String,
    fields: Vec<Frame>,
    /// Field begin marks past `MAX_FIELDS`, so that their ends pair.
    extra_fields: u32,
    /// Frames that hide what is written.
    hide: u32,
    links: Vec<Link>,
    pending: Vec<Pending<'a>>,
    /// The current paragraph's style hides.
    para_hidden: bool,
    /// Collect the sections that paragraphs end.
    collect: bool,
    sections: Vec<&'a Section>,
}

impl<'a, 'b> Walk<'a, 'b> {
    fn new(hidden: &'b Hidden<'a>, out: &'b mut Out) -> Walk<'a, 'b> {
        Walk {
            hidden,
            out,
            depth: 0,
            cell: 0,
            tabs: 0,
            cell_sep: false,
            at_start: true,
            ws: String::new(),
            fields: Vec::new(),
            extra_fields: 0,
            hide: 0,
            links: Vec::new(),
            pending: Vec::new(),
            para_hidden: false,
            collect: false,
            sections: Vec::new(),
        }
    }

    /// A header, a note or a comment: blocks that end with the story.
    fn blocks_story(&mut self, blocks: &'a [Block]) {
        self.blocks(blocks);
        self.end_story();
    }

    /// Ends the story: no field, link or line is left open for the next.
    fn end_story(&mut self) {
        self.close_links_to(0);
        self.fields.clear();
        self.extra_fields = 0;
        self.hide = 0;
        self.cell = 0;
        self.tabs = 0;
        self.cell_sep = false;
        self.new_line();
    }

    fn new_line(&mut self) {
        self.out.newline();
        self.at_start = true;
        self.ws.clear();
    }

    fn blocks(&mut self, blocks: &'a [Block]) {
        for b in blocks {
            if self.out.full() {
                return;
            }
            match b {
                Block::Para(p) => self.para(p),
                Block::Table(t) => self.table(t),
            }
        }
    }

    fn para(&mut self, p: &'a Para) {
        if self.collect
            && let Some(s) = p.section.as_deref()
        {
            self.sections.push(s);
        }
        self.para_hidden = self.hidden.para(p);
        self.at_start = true;
        self.ws.clear();
        self.inlines(&p.content);
        self.end_para();
        self.flush_pending();
    }

    /// Ends a paragraph: a line, or in a cell a space before the next one.
    fn end_para(&mut self) {
        if self.cell > 0 {
            if !self.at_start {
                self.cell_sep = true;
            }
            self.at_start = true;
            self.ws.clear();
        } else {
            self.new_line();
        }
    }

    /// The text of the drawings of the paragraph just ended.
    fn flush_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let items = std::mem::take(&mut self.pending);
        if self.depth >= MAX_DEPTH {
            return;
        }
        self.depth += 1;
        let collect = std::mem::replace(&mut self.collect, false);
        for p in items {
            if self.out.full() {
                break;
            }
            match p {
                Pending::Blocks(b) => self.blocks(b),
                Pending::Alt(a) => {
                    self.at_start = true;
                    self.put(a);
                    self.end_para();
                }
            }
        }
        self.collect = collect;
        self.depth -= 1;
    }

    fn table(&mut self, t: &'a Table) {
        if self.depth >= MAX_DEPTH {
            return;
        }
        self.depth += 1;
        // A table in a cell takes lines of its own.
        if self.cell > 0 {
            self.new_line();
        }
        let tabs = self.tabs;
        for row in &t.rows {
            if self.out.full() {
                break;
            }
            self.tabs = 0;
            for (i, c) in row.cells.iter().enumerate() {
                if i > 0 {
                    self.tabs = (self.tabs + 1).min(MAX_TABS);
                }
                self.cell += 1;
                self.cell_sep = false;
                self.at_start = true;
                self.ws.clear();
                self.blocks(&c.content);
                self.cell -= 1;
            }
            self.cell_sep = false;
            self.new_line();
        }
        self.tabs = tabs;
        self.cell_sep = false;
        self.depth -= 1;
    }

    fn inlines(&mut self, content: &'a [Inline]) {
        if self.depth >= MAX_DEPTH {
            return;
        }
        self.depth += 1;
        for i in content {
            if self.out.full() {
                break;
            }
            match i {
                Inline::Run(r) => self.run(r),
                Inline::FieldChar(k) => self.field_mark(*k),
                Inline::InstrText(s) => self.instr(s),
                Inline::Field { instr, result, .. } => {
                    let word = instr.split_whitespace().next().unwrap_or("");
                    if is_page_number(word) {
                        continue;
                    }
                    let mark = self.links.len();
                    if word.eq_ignore_ascii_case("HYPERLINK")
                        && let (Some(t), _, _) = parse_hyperlink(instr.trim())
                    {
                        self.push_link(t);
                    }
                    self.inlines(result);
                    self.close_links_to(mark);
                }
                Inline::Hyperlink {
                    target, content, ..
                } => {
                    let mark = self.links.len();
                    if let Some(t) = target {
                        self.push_link(t.clone());
                    }
                    self.inlines(content);
                    self.close_links_to(mark);
                }
                Inline::BookmarkStart { .. }
                | Inline::BookmarkEnd(_)
                | Inline::CommentStart(_)
                | Inline::CommentEnd(_) => {}
            }
        }
        self.depth -= 1;
    }

    fn run(&mut self, r: &'a Run) {
        if self.hide > 0 || self.hidden.run(&r.props, self.para_hidden) {
            return;
        }
        for it in &r.items {
            match it {
                RunItem::Text(t) => self.put(t),
                RunItem::Tab => self.put("\t"),
                RunItem::Break(_) => {
                    if self.cell > 0 {
                        self.put(" ");
                    } else {
                        self.new_line();
                    }
                }
                RunItem::NoBreakHyphen => self.put("-"),
                RunItem::Drawing(d) => match &d.kind {
                    DrawingKind::Picture { .. } => {
                        if let Some(a) = d.descr.as_deref().filter(|a| !a.trim().is_empty()) {
                            self.pending.push(Pending::Alt(a));
                        }
                    }
                    DrawingKind::Shape(s) => {
                        if !s.text.is_empty() {
                            self.pending.push(Pending::Blocks(&s.text));
                        }
                    }
                },
                // A soft hyphen shows only at a line end; a symbol is a glyph
                // of a font that has no mapping here; the notes' marks and the
                // page number are not words.
                RunItem::SoftHyphen
                | RunItem::Symbol { .. }
                | RunItem::FootnoteRef(_)
                | RunItem::EndnoteRef(_)
                | RunItem::NoteMark(_)
                | RunItem::CommentRef(_)
                | RunItem::PageNumber => {}
            }
        }
    }

    // ---- fields ----

    fn instr(&mut self, s: &str) {
        if self.extra_fields > 0 {
            return;
        }
        if let Some(f) = self.fields.last_mut()
            && !f.result
            && f.instr.len() < MAX_INSTR
        {
            f.instr.push_str(s);
        }
    }

    fn field_mark(&mut self, kind: FieldCharKind) {
        match kind {
            FieldCharKind::Begin => {
                if self.fields.len() >= MAX_FIELDS {
                    self.extra_fields += 1;
                    return;
                }
                self.fields.push(Frame {
                    instr: String::new(),
                    result: false,
                    skip: false,
                    link: None,
                });
                self.hide += 1;
            }
            FieldCharKind::Separate => {
                if self.extra_fields > 0 {
                    return;
                }
                let Some(f) = self.fields.last_mut() else {
                    return;
                };
                if f.result {
                    return;
                }
                f.result = true;
                self.hide = self.hide.saturating_sub(1);
                let instr = std::mem::take(&mut f.instr);
                let word = instr.split_whitespace().next().unwrap_or("");
                if is_page_number(word) {
                    f.skip = true;
                    self.hide += 1;
                } else if word.eq_ignore_ascii_case("HYPERLINK")
                    && let (Some(t), _, _) = parse_hyperlink(instr.trim())
                {
                    let mark = self.links.len();
                    self.push_link(t);
                    if let Some(f) = self.fields.last_mut() {
                        f.link = Some(mark);
                    }
                }
            }
            FieldCharKind::End => {
                if self.extra_fields > 0 {
                    self.extra_fields -= 1;
                    return;
                }
                let Some(f) = self.fields.pop() else {
                    return;
                };
                if f.hides() {
                    self.hide = self.hide.saturating_sub(1);
                }
                if let Some(mark) = f.link {
                    self.close_links_to(mark);
                }
            }
        }
    }

    // ---- links ----

    fn push_link(&mut self, target: String) {
        if !target.is_empty() && self.links.len() < MAX_LINKS_OPEN {
            self.links.push(Link {
                target,
                open: false,
            });
        }
    }

    /// Closes the links opened after the first `len`.
    fn close_links_to(&mut self, len: usize) {
        while self.links.len() > len {
            if let Some(l) = self.links.pop()
                && l.open
            {
                self.out.end_link();
            }
        }
    }

    // ---- text ----

    /// Text of a run. White space around words is kept between them only: not
    /// at the start of a paragraph nor at its end.
    fn put(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        let flat;
        let s = if self.cell > 0 && s.contains(is_line_or_tab) {
            flat = s
                .chars()
                .map(|c| if is_line_or_tab(c) { ' ' } else { c })
                .collect::<String>();
            flat.as_str()
        } else {
            s
        };
        let core = s.trim_matches(char::is_whitespace);
        if core.is_empty() {
            if !self.at_start {
                let room = MAX_WS.saturating_sub(self.ws.len());
                self.ws.extend(s.chars().take(room));
            }
            return;
        }
        let lead = s.len() - s.trim_start().len();
        self.lead();
        if !self.at_start {
            self.out.push(&s[..lead]);
        }
        for l in self.links.iter_mut().filter(|l| !l.open) {
            self.out.begin_link(&l.target);
            l.open = true;
        }
        self.out.push(core);
        self.at_start = false;
        self.ws.clear();
        self.ws.extend(s[lead + core.len()..].chars().take(MAX_WS));
    }

    /// Writes what is owed before a word: the cell separators, the space
    /// after the cell's last paragraph, the white space after the last word.
    fn lead(&mut self) {
        if self.tabs > 0 {
            self.out.push(&"\t".repeat(self.tabs));
            self.tabs = 0;
        }
        if self.cell_sep {
            self.out.push(" ");
            self.cell_sep = false;
        }
        if !self.at_start {
            self.out.push(&self.ws);
        }
        self.ws.clear();
    }
}

fn is_line_or_tab(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{2028}' | '\u{2029}'
    )
}

/// A field whose result is a page count or number.
fn is_page_number(word: &str) -> bool {
    ["PAGE", "NUMPAGES", "SECTIONPAGES"]
        .iter()
        .any(|w| word.eq_ignore_ascii_case(w))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::text::Text;

    fn read_capped(d: &Document, cap: usize) -> Text {
        let mut out = Out::new(cap);
        lines(d, &mut out);
        out.finish()
    }

    fn read(d: &Document) -> Text {
        read_capped(d, 1 << 20)
    }

    fn run(s: &str) -> Inline {
        Inline::Run(Run::text(RunProps::default(), s))
    }

    fn run_with(props: RunProps, s: &str) -> Inline {
        Inline::Run(Run::text(props, s))
    }

    fn hidden() -> RunProps {
        RunProps {
            vanish: Some(true),
            ..RunProps::default()
        }
    }

    fn items(items: Vec<RunItem>) -> Inline {
        Inline::Run(Run {
            props: RunProps::default(),
            items,
        })
    }

    fn para(content: Vec<Inline>) -> Block {
        Block::Para(Para {
            content,
            ..Para::default()
        })
    }

    fn p(s: &str) -> Block {
        para(vec![run(s)])
    }

    fn cell(content: Vec<Block>) -> Cell {
        Cell {
            content,
            ..Cell::default()
        }
    }

    fn table(rows: Vec<Vec<Vec<Block>>>) -> Block {
        Block::Table(Table {
            rows: rows
                .into_iter()
                .map(|r| Row {
                    cells: r.into_iter().map(cell).collect(),
                    ..Row::default()
                })
                .collect(),
            ..Table::default()
        })
    }

    fn doc(body: Vec<Block>) -> Document {
        Document {
            body,
            ..Document::default()
        }
    }

    fn body_text(body: Vec<Block>) -> String {
        read(&doc(body)).text
    }

    fn link(target: &str, content: Vec<Inline>) -> Inline {
        Inline::Hyperlink {
            target: Some(target.into()),
            anchor: None,
            tooltip: None,
            content,
        }
    }

    fn mark(k: FieldCharKind) -> Inline {
        Inline::FieldChar(k)
    }

    fn shape(text: Vec<Block>) -> RunItem {
        RunItem::Drawing(Box::new(Drawing {
            anchor: None,
            cx: 1,
            cy: 1,
            name: "s".into(),
            descr: None,
            kind: DrawingKind::Shape(Shape {
                text,
                ..Shape::default()
            }),
        }))
    }

    fn picture(descr: Option<&str>) -> RunItem {
        RunItem::Drawing(Box::new(Drawing {
            anchor: None,
            cx: 1,
            cy: 1,
            name: "Picture 1".into(),
            descr: descr.map(str::to_string),
            kind: DrawingKind::Picture {
                media: 0,
                crop: Crop::default(),
            },
        }))
    }

    #[test]
    fn runs_tabs_and_breaks_are_text_in_order() {
        let t = body_text(vec![
            p("one"),
            para(vec![items(vec![
                RunItem::Text("a".into()),
                RunItem::Tab,
                RunItem::Text("b".into()),
                RunItem::Break(BreakKind::Line),
                RunItem::Text("c".into()),
                RunItem::Break(BreakKind::Page),
                RunItem::Text("d".into()),
            ])]),
            p("two"),
        ]);
        assert_eq!(t, "one\na\tb\nc\nd\ntwo\n");
    }

    #[test]
    fn white_space_around_a_paragraph_goes_and_inside_it_stays() {
        let t = body_text(vec![
            p("  lead  trail  "),
            para(vec![run("x"), run("  "), run("y "), run(" z")]),
            para(vec![run("\t"), run("tabbed"), run("\t"), run("cols")]),
            p("   "),
        ]);
        assert_eq!(t, "lead  trail\nx  y  z\ntabbed\tcols\n");
    }

    #[test]
    fn the_hyphens_and_the_marks_of_a_run() {
        let t = body_text(vec![para(vec![items(vec![
            RunItem::Text("a".into()),
            RunItem::SoftHyphen,
            RunItem::Text("b".into()),
            RunItem::NoBreakHyphen,
            RunItem::Text("c".into()),
            RunItem::Symbol {
                font: "Wingdings".into(),
                ch: 0xF0FC,
            },
            RunItem::PageNumber,
            RunItem::FootnoteRef(1),
            RunItem::EndnoteRef(1),
            RunItem::NoteMark(false),
            RunItem::CommentRef(0),
        ])])]);
        assert_eq!(t, "ab-c\n");
    }

    #[test]
    fn bookmarks_comment_ranges_and_list_numbers_are_not_text() {
        let mut d = doc(vec![Block::Para(Para {
            props: ParaProps {
                num_id: Some(1),
                num_level: Some(0),
                ..ParaProps::default()
            },
            content: vec![
                Inline::BookmarkStart {
                    id: 1,
                    name: "chapter".into(),
                },
                Inline::CommentStart(0),
                run("item"),
                Inline::CommentEnd(0),
                Inline::BookmarkEnd(1),
            ],
            ..Para::default()
        })]);
        d.numbering.abstracts.push(AbstractNum {
            id: 0,
            multi_level: false,
            levels: vec![Level {
                text: "%1.".into(),
                ..Level::default()
            }],
        });
        assert_eq!(read(&d).text, "item\n");
    }

    #[test]
    fn a_row_is_a_line_and_its_cells_are_separated_by_a_tab() {
        let t = body_text(vec![
            p("before"),
            table(vec![
                vec![vec![p("a")], vec![p("b")], vec![p("c")]],
                vec![vec![p("d")], vec![], vec![p("f")]],
                vec![vec![], vec![p("h")], vec![]],
                vec![vec![], vec![], vec![]],
            ]),
            p("after"),
        ]);
        assert_eq!(t, "before\na\tb\tc\nd\t\tf\n\th\nafter\n");
    }

    #[test]
    fn the_paragraphs_of_a_cell_share_its_line() {
        let t = body_text(vec![table(vec![vec![
            vec![p("x"), p(""), p("y")],
            vec![para(vec![items(vec![
                RunItem::Text("a".into()),
                RunItem::Tab,
                RunItem::Text("b".into()),
                RunItem::Break(BreakKind::Line),
                RunItem::Text("c\nd".into()),
            ])])],
        ]])]);
        assert_eq!(t, "x y\ta b c d\n");
    }

    #[test]
    fn a_table_in_a_cell_takes_lines_of_its_own() {
        let inner = table(vec![vec![vec![p("x")], vec![p("y")]], vec![vec![p("z")]]]);
        let t = body_text(vec![
            table(vec![vec![vec![p("L"), inner], vec![p("R")]]]),
            p("end"),
        ]);
        assert_eq!(t, "L\nx\ty\nz\n\tR\nend\n");
    }

    #[test]
    fn tables_nested_past_the_bound_are_cut_without_overflowing() {
        let mut b = p("deep");
        for _ in 0..500 {
            b = table(vec![vec![vec![p("level"), b]]]);
        }
        let t = body_text(vec![b]);
        assert!(t.contains("level"));
        assert!(!t.contains("deep"));
    }

    #[test]
    fn hidden_runs_are_left_out_and_struck_ones_are_not() {
        let t = body_text(vec![
            para(vec![
                run("shown "),
                run_with(hidden(), "SECRET"),
                run(" shown"),
            ]),
            para(vec![
                run_with(
                    RunProps {
                        strike: Some(true),
                        dstrike: Some(true),
                        ..RunProps::default()
                    },
                    "struck",
                ),
                run_with(
                    RunProps {
                        vanish: Some(false),
                        ..RunProps::default()
                    },
                    " not hidden",
                ),
            ]),
            para(vec![run_with(hidden(), "ALL HIDDEN")]),
        ]);
        assert_eq!(t, "shown  shown\nstruck not hidden\n");
    }

    #[test]
    fn styles_hide_through_the_character_the_paragraph_and_the_defaults() {
        let style = |id: &str, kind, based_on: Option<&str>, vanish: Option<bool>| {
            let mut s = Style::new(id, id, kind);
            s.based_on = based_on.map(str::to_string);
            s.rpr.vanish = vanish;
            s
        };
        let run_in = |style: Option<&str>, vanish: Option<bool>, s: &str| {
            run_with(
                RunProps {
                    style: style.map(str::to_string),
                    vanish,
                    ..RunProps::default()
                },
                s,
            )
        };
        let styled = |style: &str, content: Vec<Inline>| {
            Block::Para(Para {
                props: ParaProps {
                    style: Some(style.into()),
                    ..ParaProps::default()
                },
                content,
                ..Para::default()
            })
        };
        let mut d = doc(vec![
            para(vec![run_in(Some("Hid"), None, "char style")]),
            para(vec![run_in(Some("Child"), None, "inherited")]),
            para(vec![run_in(Some("Shown"), None, "overridden")]),
            para(vec![run_in(Some("Hid"), Some(false), "direct wins")]),
            styled("HidPara", vec![run_in(None, None, "paragraph style")]),
            styled(
                "HidPara",
                vec![
                    run_in(None, Some(false), "kept"),
                    run_in(Some("Shown"), None, " kept2"),
                ],
            ),
            styled("Plain", vec![run_in(Some("Unknown"), None, "plain")]),
        ]);
        d.styles = vec![
            style("Hid", StyleKind::Character, None, Some(true)),
            style("Child", StyleKind::Character, Some("Hid"), None),
            style("Shown", StyleKind::Character, Some("Hid"), Some(false)),
            style("HidPara", StyleKind::Paragraph, None, Some(true)),
            style("Plain", StyleKind::Paragraph, None, None),
            // A loop in the chain ends.
            style("A", StyleKind::Character, Some("B"), None),
            style("B", StyleKind::Character, Some("A"), None),
        ];
        assert_eq!(
            read(&d).text,
            "overridden\ndirect wins\nkept kept2\nplain\n"
        );
        // The defaults hide what nothing says otherwise.
        d.styles.clear();
        d.defaults_run.vanish = Some(true);
        let t = read(&d).text;
        assert_eq!(t, "direct wins\nkept\n");
    }

    #[test]
    fn a_page_number_field_has_no_text_and_another_field_has_its_result() {
        let field = |instr: &str, result: &str| Inline::Field {
            instr: instr.into(),
            props: RunProps::default(),
            result: vec![run(result)],
        };
        let t = body_text(vec![para(vec![
            run("p"),
            field(" PAGE \\* MERGEFORMAT ", "7"),
            field(" numpages ", "9"),
            field("SECTIONPAGES", "2"),
            field(" REF target \\h ", "see"),
            field(" DATE ", "today"),
            items(vec![RunItem::PageNumber]),
        ])]);
        assert_eq!(t, "pseetoday\n");
    }

    #[test]
    fn complex_fields_show_their_result_and_never_their_instruction() {
        let begin = || mark(FieldCharKind::Begin);
        let sep = || mark(FieldCharKind::Separate);
        let end = || mark(FieldCharKind::End);
        let t = body_text(vec![
            // A page number, a nested field, a field with no result.
            para(vec![
                run("a "),
                begin(),
                Inline::InstrText(" PAGE ".into()),
                sep(),
                run("7"),
                end(),
                run("b "),
                begin(),
                Inline::InstrText(" IF ".into()),
                begin(),
                Inline::InstrText(" PAGE ".into()),
                sep(),
                run("1"),
                end(),
                run("hidden instruction text"),
                sep(),
                run("shown"),
                end(),
                run(" c"),
                begin(),
                Inline::InstrText(" SEQ x ".into()),
                end(),
                run(" d"),
            ]),
            // A field that ends in another paragraph.
            para(vec![
                begin(),
                Inline::InstrText(" PAGE ".into()),
                sep(),
                run("8"),
            ]),
            para(vec![run("9"), end(), run("tail")]),
            // Marks with no partner.
            para(vec![end(), sep(), Inline::InstrText("x".into()), run("ok")]),
        ]);
        assert_eq!(t, "a b shown c d\ntail\nok\n");
    }

    #[test]
    fn a_field_left_open_does_not_touch_the_next_story() {
        // A field left open hides the rest of its story. The next story
        // starts with no field: its separator has none to take.
        let mut d = doc(vec![para(vec![
            mark(FieldCharKind::Begin),
            Inline::InstrText(" PAGE ".into()),
            run("lost"),
        ])]);
        d.footnotes.push(Note {
            id: 1,
            content: vec![para(vec![
                mark(FieldCharKind::Separate),
                run("note"),
                mark(FieldCharKind::End),
                run(" more"),
            ])],
        });
        assert_eq!(read(&d).text, "note more\n");
    }

    #[test]
    fn field_marks_past_the_bound_are_counted() {
        // A page number whose result holds 200 fields: its end is the 201st
        // end, not the 65th.
        let mut content = vec![
            mark(FieldCharKind::Begin),
            Inline::InstrText(" PAGE ".into()),
            mark(FieldCharKind::Separate),
        ];
        for _ in 0..200 {
            content.push(mark(FieldCharKind::Begin));
            content.push(Inline::InstrText(" X ".into()));
            content.push(mark(FieldCharKind::Separate));
        }
        content.push(run("a"));
        for _ in 0..200 {
            content.push(mark(FieldCharKind::End));
        }
        content.push(run("b"));
        content.push(mark(FieldCharKind::End));
        content.push(run("c"));
        assert_eq!(body_text(vec![para(content)]), "c\n");
    }

    #[test]
    fn instructions_and_white_space_held_back_are_bounded() {
        let empty = Document::default();
        let hidden = Hidden::new(&empty);
        let mut out = Out::new(1 << 20);
        let mut w = Walk::new(&hidden, &mut out);
        w.field_mark(FieldCharKind::Begin);
        for _ in 0..1000 {
            w.instr(&"x".repeat(1000));
        }
        assert!(w.fields[0].instr.len() < MAX_INSTR + 1000);
        // A hundred thousand spaces between two words are cut.
        let t = body_text(vec![para(vec![
            run("a"),
            run(&" ".repeat(100_000)),
            run("b"),
        ])]);
        assert!(t.len() < 2 * MAX_WS && t.starts_with("a  ") && t.ends_with("b\n"));
        // And so are the cells between two words.
        let cells: Vec<Vec<Block>> = (0..5000).map(|_| vec![]).chain([vec![p("x")]]).collect();
        let t = body_text(vec![table(vec![cells])]);
        assert_eq!(t, format!("{}x\n", "\t".repeat(MAX_TABS)));
    }

    #[test]
    fn the_walk_stops_when_the_cap_is_reached() {
        let body: Vec<Block> = (0..1000)
            .map(|_| {
                Block::Para(Para {
                    content: vec![run("abcdefghij")],
                    section: Some(Box::new(Section::default())),
                    ..Para::default()
                })
            })
            .collect();
        let empty = Document::default();
        let hidden = Hidden::new(&empty);
        let mut out = Out::new(25);
        let mut w = Walk::new(&hidden, &mut out);
        w.collect = true;
        w.blocks(&body);
        assert!(w.sections.len() <= 3, "{}", w.sections.len());
        // Nothing after the cap is a link either.
        let d = doc(vec![
            para(vec![run(&"x".repeat(100))]),
            para(vec![link("https://t.test/", vec![run("late")])]),
        ]);
        let t = read_capped(&d, 10);
        assert!(t.truncated && t.links.is_empty());
    }

    #[test]
    fn a_link_is_its_label_then_its_target_and_the_pair_is_kept() {
        let d = doc(vec![para(vec![
            run("see "),
            link("https://example.org/x", vec![run("the site")]),
            run(" and "),
            link("https://example.org/", vec![run("https://example.org/")]),
            run(" and "),
            link("mailto:a@b.test", vec![run("a@b.test")]),
            run(" and "),
            Inline::Hyperlink {
                target: None,
                anchor: Some("mark".into()),
                tooltip: Some("tip".into()),
                content: vec![run("inner")],
            },
        ])]);
        let t = read(&d);
        assert_eq!(
            t.text,
            "see the site (https://example.org/x) and https://example.org/ and a@b.test and inner\n"
        );
        assert_eq!(
            t.links,
            [("the site".to_string(), "https://example.org/x".to_string())]
        );
    }

    #[test]
    fn a_link_is_labelled_with_the_text_it_encloses_only() {
        let t = read(&doc(vec![para(vec![
            run("a "),
            link(
                "https://t.test/",
                vec![run(" b "), run_with(hidden(), "H"), run("c ")],
            ),
            run(" d"),
        ])]));
        assert_eq!(t.text, "a  b c (https://t.test/)  d\n");
        assert_eq!(
            t.links,
            [("b c".to_string(), "https://t.test/".to_string())]
        );
        // No label, no link: nothing to point from.
        let t = read(&doc(vec![para(vec![
            run("x"),
            link("https://t.test/", vec![run_with(hidden(), "H")]),
            link("https://t.test/", vec![]),
        ])]));
        assert_eq!(t.text, "x\n");
        assert!(t.links.is_empty());
    }

    #[test]
    fn fields_make_links_too() {
        let begin = || mark(FieldCharKind::Begin);
        let t = read(&doc(vec![
            para(vec![
                begin(),
                Inline::InstrText(" HYPERLINK \"https://one.test/\" ".into()),
                mark(FieldCharKind::Separate),
                run("one"),
                mark(FieldCharKind::End),
                run(" "),
                Inline::Field {
                    instr: " HYPERLINK \"https://two.test/\" ".into(),
                    props: RunProps::default(),
                    result: vec![run("two")],
                },
                run(" "),
                // A script is no target; a bookmark alone is none either.
                Inline::Field {
                    instr: " HYPERLINK \"javascript:alert(1)\" ".into(),
                    props: RunProps::default(),
                    result: vec![run("bad")],
                },
                run(" "),
                Inline::Field {
                    instr: " HYPERLINK \\l \"_Toc1\" ".into(),
                    props: RunProps::default(),
                    result: vec![run("toc")],
                },
            ]),
            // The link ends with the field, across paragraphs too.
            para(vec![
                begin(),
                Inline::InstrText(" HYPERLINK \"https://three.test/\" ".into()),
                mark(FieldCharKind::Separate),
                run("three"),
            ]),
            para(vec![run("3b"), mark(FieldCharKind::End), run(" after")]),
        ]));
        assert_eq!(
            t.text,
            "one (https://one.test/) two (https://two.test/) bad toc\nthree\n3b (https://three.test/) after\n"
        );
        assert_eq!(t.links.len(), 3);
        assert_eq!(t.links[2].1, "https://three.test/");
    }

    #[test]
    fn links_nested_past_the_bound_are_plain_text() {
        let mut inner = vec![run("x")];
        for i in 0..40 {
            inner = vec![link(&format!("https://t.test/{i}"), inner)];
        }
        let t = read(&doc(vec![para(inner)]));
        // The outer links are kept; the inner ones are text.
        assert!(
            t.text
                .starts_with("x (https://t.test/32) (https://t.test/33)"),
            "{}",
            t.text
        );
        assert_eq!(t.text.matches(" (https://").count(), MAX_LINKS_OPEN);
        assert_eq!(t.links.len(), MAX_LINKS_OPEN);
    }

    #[test]
    fn a_link_in_a_cell_stays_in_the_cell() {
        let t = read(&doc(vec![table(vec![vec![
            vec![para(vec![link("https://t.test/", vec![run("a")])])],
            vec![p("b")],
        ]])]));
        assert_eq!(t.text, "a (https://t.test/)\tb\n");
    }

    #[test]
    fn the_text_of_a_shape_follows_its_paragraph() {
        let t = body_text(vec![
            para(vec![
                run("before "),
                items(vec![shape(vec![p("BOX one"), p("BOX two")])]),
                run("after"),
            ]),
            p("next"),
        ]);
        assert_eq!(t, "before after\nBOX one\nBOX two\nnext\n");
    }

    #[test]
    fn a_shape_in_a_cell_joins_the_cell() {
        let t = body_text(vec![table(vec![vec![
            vec![para(vec![run("a"), items(vec![shape(vec![p("BOX")])])])],
            vec![p("b")],
        ]])]);
        assert_eq!(t, "a BOX\tb\n");
    }

    #[test]
    fn shapes_nested_past_the_bound_are_cut_without_overflowing() {
        let mut b = p("deep");
        for _ in 0..500 {
            b = para(vec![run("level"), items(vec![shape(vec![b])])]);
        }
        let t = body_text(vec![b]);
        assert!(t.contains("level"));
        assert!(!t.contains("deep"));
    }

    #[test]
    fn a_picture_has_its_alt_text_and_nothing_else() {
        let t = body_text(vec![
            para(vec![run("a"), items(vec![picture(Some("A red kite"))])]),
            para(vec![items(vec![picture(None)])]),
            para(vec![items(vec![picture(Some("  "))])]),
            para(vec![
                run_with(hidden(), "h"),
                Inline::Run(Run {
                    props: hidden(),
                    items: vec![picture(Some("hidden alt"))],
                }),
            ]),
        ]);
        assert_eq!(t, "a\nA red kite\n");
    }

    fn section_with(header: Option<&str>, footer: Option<&str>) -> Section {
        let mut s = Section::default();
        s.headers.default = header.map(|h| vec![p(h)]);
        s.footers.default = footer.map(|h| vec![p(h)]);
        s
    }

    fn with_section(text: &str, s: Section) -> Block {
        Block::Para(Para {
            content: vec![run(text)],
            section: Some(Box::new(s)),
            ..Para::default()
        })
    }

    #[test]
    fn headers_and_footers_follow_the_body_in_a_section_each_header_once() {
        let mut d = doc(vec![
            with_section("one", section_with(Some("HEAD"), Some("FOOT"))),
            with_section("two", section_with(Some("HEAD"), Some("FOOT2"))),
            p("three"),
        ]);
        d.section = section_with(Some("HEAD"), Some("FOOT"));
        d.section.headers.first = Some(vec![p("FIRST")]);
        d.section.headers.even = Some(vec![p("EVEN")]);
        let t = read(&d);
        assert_eq!(t.text, "one\ntwo\nthree\nHEAD\nFOOT\nFOOT2\nFIRST\nEVEN\n");
        assert_eq!(t.sections.len(), 1);
        assert_eq!(t.sections[0].label, "headers and footers");
        assert_eq!(
            &t.text[t.sections[0].range.clone()],
            "HEAD\nFOOT\nFOOT2\nFIRST\nEVEN\n"
        );
    }

    #[test]
    fn only_the_sections_of_the_body_bring_headers() {
        // A section end inside a text box or a note is not a section of the
        // document; one in a table cell is.
        let mut hdr = Section::default();
        hdr.headers.default = Some(vec![p("IN SHAPE")]);
        let mut cellsec = Section::default();
        cellsec.headers.default = Some(vec![p("IN CELL")]);
        let shaped = Block::Para(Para {
            content: vec![items(vec![shape(vec![with_section("boxed", hdr)])])],
            ..Para::default()
        });
        let mut d = doc(vec![
            shaped,
            table(vec![vec![vec![with_section("c", cellsec)]]]),
        ]);
        d.footnotes.push(Note {
            id: 1,
            content: vec![with_section("n", section_with(Some("IN NOTE"), None))],
        });
        let t = read(&d);
        assert_eq!(t.text, "boxed\nc\nIN CELL\nn\n");
    }

    #[test]
    fn notes_and_comments_have_a_section_each_after_the_headers() {
        let mut d = doc(vec![p("body")]);
        d.section = section_with(Some("HEAD"), None);
        d.footnotes = vec![
            Note {
                id: 1,
                content: vec![para(vec![
                    items(vec![RunItem::NoteMark(false)]),
                    run(" first note"),
                ])],
            },
            Note {
                id: 2,
                content: vec![p("second note")],
            },
        ];
        d.endnotes = vec![Note {
            id: 1,
            content: vec![p("an endnote")],
        }];
        d.comments = vec![Comment {
            id: 0,
            author: "Ann Lee".into(),
            initials: "AL".into(),
            date: None,
            content: vec![p("a comment")],
        }];
        let t = read(&d);
        assert_eq!(
            t.text,
            "body\nHEAD\nfirst note\nsecond note\nan endnote\na comment\n"
        );
        let got: Vec<(&str, &str)> = t
            .sections
            .iter()
            .map(|s| (s.label.as_str(), &t.text[s.range.clone()]))
            .collect();
        assert_eq!(
            got,
            [
                ("headers and footers", "HEAD\n"),
                ("footnotes", "first note\nsecond note\n"),
                ("endnotes", "an endnote\n"),
                ("comments", "a comment\n"),
            ]
        );
    }

    #[test]
    fn a_document_without_notes_has_no_such_sections() {
        let t = read(&doc(vec![p("only the body")]));
        assert_eq!(t.text, "only the body\n");
        assert!(t.sections.is_empty());
    }

    #[test]
    fn the_cap_cuts_the_text_and_stops_the_walk() {
        let mut d = doc((0..1000).map(|_| p("abcdefghij")).collect());
        d.section = section_with(Some("HEAD"), None);
        d.comments = vec![Comment {
            id: 0,
            author: String::new(),
            initials: String::new(),
            date: None,
            content: vec![p("late")],
        }];
        let t = read_capped(&d, 25);
        assert!(t.truncated);
        assert!(t.text.len() <= 25, "{}", t.text.len());
        assert_eq!(t.text, "abcdefghij\nabcdefghij\nabc");
        assert!(t.sections.is_empty());
        // A cap that fits is not reached.
        let t = read_capped(&doc(vec![p("abc")]), 4);
        assert_eq!((t.text.as_str(), t.truncated), ("abc\n", false));
    }
}
