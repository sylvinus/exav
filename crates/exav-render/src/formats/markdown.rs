//! Markdown into a tree of data: blocks and inlines, never markup.
//!
//! CommonMark with tables and strikethrough, parsed by pulldown-cmark, whose
//! events are folded into [`Block`] and [`Inline`] here. Raw HTML is text (a
//! `<script>` is the characters `<script>`), an image is its alt text, and
//! the page that draws the tree decides what a link may do.
//!
//! A link is kept only when its target is an absolute http, https or mailto
//! address of at most [`MAX_TARGET`] bytes, with no space, control, line or
//! paragraph separator or bidirectional control character and, for http and
//! https, no credentials
//! (`https://bank.example@evil.example`). Any other is its label alone. The
//! drawing side checks the address again with its own URL reader, which is
//! the one that follows it.
//!
//! The work and the tree are bounded whatever the input: quotes and lists
//! nest to [`MAX_BLOCK_DEPTH`] and what is deeper is kept as one text block,
//! inlines to [`MAX_INLINE_DEPTH`] (deeper ones are dropped, their content
//! kept), a table has at most [`MAX_COLUMNS`] columns, and past
//! [`MAX_NODES`] nodes the rest of the document is left out and
//! [`Document::truncated`] is set. No step recurses on the input.

use pulldown_cmark::{Alignment, Event, LinkType, Options, Parser, Tag, TagEnd};

/// Nesting of block quotes and lists.
pub const MAX_BLOCK_DEPTH: usize = 10;
/// Nesting of emphasis, strong, strikethrough and links in a block.
pub const MAX_INLINE_DEPTH: usize = 32;
/// Blocks, inlines and table cells in a document.
pub const MAX_NODES: usize = 100_000;
/// Cells kept per table row.
pub const MAX_COLUMNS: usize = 64;
/// Bytes of a link target.
pub const MAX_TARGET: usize = 2048;
/// The largest list start number (nine digits, as CommonMark has it).
const MAX_START: u64 = 999_999_999;

/// The content of a paragraph, heading or table cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inline {
    Text(String),
    Code(String),
    /// A hard line break.
    Br,
    Em(Vec<Inline>),
    Strong(Vec<Inline>),
    Del(Vec<Inline>),
    /// `url` is an absolute http, https or mailto address, see the module.
    Link {
        url: String,
        children: Vec<Inline>,
    },
    /// Never loaded: the alt text, which may be empty.
    Image {
        alt: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Center,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Para(Vec<Inline>),
    Heading {
        level: u8,
        children: Vec<Inline>,
    },
    Code(String),
    Rule,
    Quote(Vec<Block>),
    List {
        ordered: bool,
        start: u64,
        /// No item has a paragraph of its own.
        tight: bool,
        items: Vec<Vec<Block>>,
    },
    Table {
        align: Vec<Option<Align>>,
        head: Vec<Vec<Inline>>,
        rows: Vec<Vec<Vec<Inline>>>,
    },
    /// Raw HTML, or what is nested deeper than [`MAX_BLOCK_DEPTH`], as text.
    Raw(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub blocks: Vec<Block>,
    /// [`MAX_NODES`] was reached: the rest of the document is left out.
    pub truncated: bool,
}

/// Reads `src`. The caller bounds its length.
pub fn parse(src: &str) -> Document {
    let mut b = Builder::default();
    b.stack.push(Open::Root(Vec::new()));
    let options = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH;
    for event in Parser::new_ext(src, options) {
        if b.truncated {
            break;
        }
        b.event(event);
    }
    b.finish()
}

// ── the text a reader sees ───────────────────────────────────────────────────

/// What [`visible_text`] gives back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Visible {
    pub text: String,
    /// `max_len` was reached: the rest of the document is left out.
    pub truncated: bool,
    /// Each link whose label is not its target, as `(label, target)`, for a
    /// check of what a link says against where it goes. At most 4096.
    pub links: Vec<(String, String)>,
    /// The parts of the text, in order, as a label and the bytes of `text`
    /// they cover (a sheet, a slide): to say where a match is. Empty for a
    /// document of one block.
    pub sections: Vec<(String, std::ops::Range<usize>)>,
    /// Why the document's text could not be read in full, when it is a kind
    /// of document that has some but this one's could not be taken out
    /// (encrypted, past a limit, damaged): what is in `text` is not all of it.
    pub unreadable: Option<String>,
}

fn newline(out: &mut String) {
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
}

/// The text of `src` as a reader sees it, for a scanner or a search: the
/// words of every block in order, one block per line, a table row on a line
/// with its cells apart by tabs, code and raw HTML as written, an image as its
/// alt text, and a link as its label followed by its target in parentheses
/// when the label is not the target. Unlike [`parse`], a link keeps its
/// target whatever it is (`javascript:` too): what a scanner looks for is what
/// a reader is being led to.
///
/// Reads events and builds no tree, so nesting costs nothing. The text is cut
/// at `max_len` bytes (a reference used many times repeats its target). The
/// caller bounds the length of `src`.
pub fn visible_text(src: &str, max_len: usize) -> Visible {
    let options = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH;
    let mut out = String::new();
    // Where each open link's label starts, and its target.
    let mut links: Vec<(usize, String)> = Vec::new();
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut truncated = false;
    for event in Parser::new_ext(src, options) {
        match event {
            Event::Text(s) | Event::Code(s) | Event::Html(s) | Event::InlineHtml(s) => {
                out.push_str(&s)
            }
            Event::SoftBreak | Event::HardBreak => out.push('\n'),
            Event::Rule => newline(&mut out),
            Event::Start(Tag::Link { dest_url, .. }) => {
                links.push((out.len(), dest_url.into_string()))
            }
            Event::End(TagEnd::Link) => {
                if let Some((start, url)) = links.pop() {
                    let label = out.get(start..).unwrap_or("");
                    if label != url && label != url.strip_prefix("mailto:").unwrap_or(&url) {
                        if pairs.len() < 4096 {
                            pairs.push((
                                label.trim().chars().take(2048).collect(),
                                url.chars().take(2048).collect(),
                            ));
                        }
                        out.push_str(" (");
                        out.push_str(&url);
                        out.push(')');
                    }
                }
            }
            Event::End(TagEnd::TableCell) => out.push('\t'),
            Event::End(
                TagEnd::Paragraph
                | TagEnd::Heading(_)
                | TagEnd::BlockQuote(_)
                | TagEnd::CodeBlock
                | TagEnd::HtmlBlock
                | TagEnd::List(_)
                | TagEnd::Item
                | TagEnd::Table
                | TagEnd::TableHead
                | TagEnd::TableRow,
            ) => {
                // A row ends its last cell's tab.
                if out.ends_with('\t') {
                    out.pop();
                }
                newline(&mut out);
            }
            _ => {}
        }
        if out.len() > max_len {
            let mut cut = max_len;
            while !out.is_char_boundary(cut) {
                cut -= 1;
            }
            out.truncate(cut);
            truncated = true;
            break;
        }
    }
    Visible {
        text: out,
        truncated,
        links: pairs,
        sections: Vec::new(),
        unreadable: None,
    }
}

// ── the builder ──────────────────────────────────────────────────────────────

enum Leaf {
    Para,
    Heading(u8),
    Cell,
}

enum Wrap {
    Base,
    Em,
    Strong,
    Del,
    Link(String),
    /// An inline nested past the limit: its content goes to the parent.
    Flat,
}

/// A paragraph, heading or table cell being read.
struct Run {
    leaf: Leaf,
    /// A tight list item's text, which has no paragraph event.
    implicit: bool,
    frames: Vec<(Wrap, Vec<Inline>)>,
    /// Nesting depth and alt text of an image being read.
    image: Option<(usize, String)>,
}

enum Open {
    Root(Vec<Block>),
    Quote(Vec<Block>),
    List {
        ordered: bool,
        start: u64,
        items: Vec<Vec<Block>>,
        loose: bool,
    },
    Item {
        blocks: Vec<Block>,
        paragraph: bool,
    },
    Table {
        align: Vec<Option<Align>>,
        head: Vec<Vec<Inline>>,
        rows: Vec<Vec<Vec<Inline>>>,
        row: Vec<Vec<Inline>>,
    },
    Code(String),
    Html(String),
}

#[derive(Default)]
struct Builder {
    stack: Vec<Open>,
    leaf: Option<Run>,
    nodes: usize,
    truncated: bool,
    /// Events left to the end of a container nested too deep.
    deep: usize,
    flat: String,
    finishing: bool,
}

fn safe_target(dest: &str) -> bool {
    if dest.len() > MAX_TARGET {
        return false;
    }
    let lower = dest.get(..8).unwrap_or(dest).to_ascii_lowercase();
    let web = lower.starts_with("http://") || lower.starts_with("https://");
    if !web && !lower.starts_with("mailto:") {
        return false;
    }
    let bad = |c: char| {
        let c = c as u32;
        c <= 0x20
            || (0x7f..=0x9f).contains(&c)
            || c == 0x2028
            || c == 0x2029
            || (0x202a..=0x202e).contains(&c)
            || (0x2066..=0x2069).contains(&c)
    };
    if dest.chars().any(bad) {
        return false;
    }
    if web {
        let rest = &dest[dest.find("//").map_or(0, |i| i + 2)..];
        // A backslash ends the authority too, as a URL reader takes it for
        // a slash.
        let authority = rest.split(['/', '\\', '?', '#']).next().unwrap_or("");
        if authority.is_empty() || authority.contains('@') {
            return false;
        }
    } else if dest.len() == "mailto:".len() {
        return false;
    }
    true
}

impl Builder {
    fn spend(&mut self) -> bool {
        // The containers open at the limit are closed with what they have.
        if self.finishing {
            return true;
        }
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            self.truncated = true;
        }
        !self.truncated
    }

    fn push_block(&mut self, block: Block) {
        if !self.spend() {
            return;
        }
        let target = self.stack.iter_mut().rev().find_map(|o| match o {
            Open::Root(b) | Open::Quote(b) | Open::Item { blocks: b, .. } => Some(b),
            _ => None,
        });
        if let Some(blocks) = target {
            blocks.push(block);
        }
    }

    fn nesting(&self) -> usize {
        self.stack
            .iter()
            .filter(|o| matches!(o, Open::Quote(_) | Open::List { .. }))
            .count()
    }

    /// A tight list item's text has no paragraph around it.
    fn leaf_mut(&mut self) -> &mut Run {
        self.leaf.get_or_insert_with(|| Run {
            leaf: Leaf::Para,
            implicit: true,
            frames: vec![(Wrap::Base, Vec::new())],
            image: None,
        })
    }

    fn start_leaf(&mut self, leaf: Leaf) {
        self.flush_implicit();
        self.leaf = Some(Run {
            leaf,
            implicit: false,
            frames: vec![(Wrap::Base, Vec::new())],
            image: None,
        });
    }

    fn flush_implicit(&mut self) {
        if self.leaf.as_ref().is_some_and(|l| l.implicit) {
            self.end_leaf();
        }
    }

    fn push_inline(&mut self, inline: Inline) {
        if let (Inline::Text(add), Some(Inline::Text(last))) = (
            &inline,
            self.leaf_mut()
                .frames
                .last_mut()
                .and_then(|f| f.1.last_mut()),
        ) {
            last.push_str(add);
            return;
        }
        if !self.spend() {
            return;
        }
        if let Some(f) = self.leaf_mut().frames.last_mut() {
            f.1.push(inline);
        }
    }

    fn start_inline(&mut self, wrap: Wrap) {
        let leaf = self.leaf_mut();
        let wrap = if leaf.frames.len() >= MAX_INLINE_DEPTH {
            Wrap::Flat
        } else {
            wrap
        };
        leaf.frames.push((wrap, Vec::new()));
    }

    fn end_inline(&mut self) {
        let Some(leaf) = self.leaf.as_mut() else {
            return;
        };
        if leaf.frames.len() < 2 {
            return;
        }
        let Some((wrap, children)) = leaf.frames.pop() else {
            return;
        };
        let inline = match wrap {
            Wrap::Em => Inline::Em(children),
            Wrap::Strong => Inline::Strong(children),
            Wrap::Del => Inline::Del(children),
            Wrap::Link(url) => Inline::Link { url, children },
            Wrap::Base | Wrap::Flat => {
                if let Some(parent) = leaf.frames.last_mut() {
                    parent.1.extend(children);
                }
                return;
            }
        };
        self.push_inline(inline);
    }

    fn end_leaf(&mut self) {
        while self.leaf.as_ref().is_some_and(|l| l.frames.len() > 1) {
            self.end_inline();
        }
        let Some(mut leaf) = self.leaf.take() else {
            return;
        };
        if let Some((_, alt)) = leaf.image.take() {
            // An image the page ended inside of: kept as what it had.
            leaf.frames[0].1.push(Inline::Image { alt });
        }
        let children = leaf.frames.pop().map(|f| f.1).unwrap_or_default();
        match leaf.leaf {
            Leaf::Para => self.push_block(Block::Para(children)),
            Leaf::Heading(level) => self.push_block(Block::Heading { level, children }),
            Leaf::Cell => {
                if !self.spend() {
                    return;
                }
                if let Some(Open::Table { row, .. }) = self.stack.last_mut() {
                    if row.len() < MAX_COLUMNS {
                        row.push(children);
                    }
                }
            }
        }
    }

    /// Closes the container on top of the stack into the one below it.
    fn close_top(&mut self) {
        if self.stack.len() < 2 {
            return;
        }
        let Some(top) = self.stack.pop() else { return };
        match top {
            Open::Root(_) => {}
            Open::Quote(blocks) => self.push_block(Block::Quote(blocks)),
            Open::List {
                ordered,
                start,
                items,
                loose,
            } => self.push_block(Block::List {
                ordered,
                start,
                tight: !loose,
                items,
            }),
            Open::Item { blocks, paragraph } => {
                if let Some(Open::List { items, loose, .. }) = self.stack.last_mut() {
                    items.push(blocks);
                    *loose |= paragraph;
                }
            }
            Open::Table {
                align, head, rows, ..
            } => self.push_block(Block::Table { align, head, rows }),
            Open::Code(mut s) => {
                if s.ends_with('\n') {
                    s.pop();
                }
                self.push_block(Block::Code(s));
            }
            Open::Html(s) => self.push_block(Block::Raw(s.trim_end_matches('\n').to_string())),
        }
    }

    fn open(&mut self, o: Open) {
        self.flush_implicit();
        self.stack.push(o);
    }

    fn container_start(&mut self, o: Open) {
        if self.nesting() >= MAX_BLOCK_DEPTH {
            self.flush_implicit();
            self.deep = 1;
            self.flat.clear();
        } else {
            self.open(o);
        }
    }

    /// Everything inside a container nested too deep, as the text of one block.
    fn event_deep(&mut self, event: Event<'_>) {
        match event {
            Event::Start(_) => self.deep += 1,
            Event::End(end) => {
                self.deep -= 1;
                let block_end = !matches!(
                    end,
                    TagEnd::Emphasis
                        | TagEnd::Strong
                        | TagEnd::Strikethrough
                        | TagEnd::Link
                        | TagEnd::Image
                        | TagEnd::TableCell
                );
                if block_end && !self.flat.is_empty() && !self.flat.ends_with('\n') {
                    self.flat.push('\n');
                }
                if self.deep == 0 {
                    let text = std::mem::take(&mut self.flat);
                    self.push_block(Block::Raw(text.trim_end_matches('\n').to_string()));
                }
            }
            Event::Text(s) | Event::Code(s) | Event::Html(s) | Event::InlineHtml(s) => {
                self.flat.push_str(&s)
            }
            Event::SoftBreak | Event::HardBreak => self.flat.push('\n'),
            _ => {}
        }
    }

    fn event_image(&mut self, event: &Event<'_>) {
        let Some(image) = self.leaf.as_mut().and_then(|l| l.image.as_mut()) else {
            return;
        };
        match event {
            Event::Start(Tag::Image { .. }) => image.0 += 1,
            Event::End(TagEnd::Image) => {
                image.0 -= 1;
                if image.0 == 0 {
                    let alt = std::mem::take(&mut image.1);
                    if let Some(l) = self.leaf.as_mut() {
                        l.image = None;
                    }
                    self.push_inline(Inline::Image { alt });
                }
            }
            // Tags in the description are kept as the text they are.
            Event::Text(s) | Event::Code(s) | Event::InlineHtml(s) | Event::Html(s) => {
                image.1.push_str(s)
            }
            Event::SoftBreak | Event::HardBreak => image.1.push(' '),
            _ => {}
        }
    }

    fn event(&mut self, event: Event<'_>) {
        if self.deep > 0 {
            return self.event_deep(event);
        }
        if self.leaf.as_ref().is_some_and(|l| l.image.is_some()) {
            return self.event_image(&event);
        }
        if let (Event::Text(s) | Event::Html(s), Some(Open::Code(text) | Open::Html(text))) =
            (&event, self.stack.last_mut())
        {
            text.push_str(s);
            return;
        }
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(end) => self.end(end),
            Event::Text(s) | Event::Html(s) | Event::InlineHtml(s) => {
                self.push_inline(Inline::Text(s.into_string()))
            }
            Event::Code(s) => self.push_inline(Inline::Code(s.into_string())),
            Event::SoftBreak => self.push_inline(Inline::Text("\n".to_string())),
            Event::HardBreak => self.push_inline(Inline::Br),
            Event::Rule => {
                self.flush_implicit();
                self.push_block(Block::Rule);
            }
            _ => {}
        }
    }

    fn start(&mut self, tag: Tag<'_>) {
        match tag {
            Tag::Paragraph => {
                if let Some(Open::Item { paragraph, .. }) = self.stack.last_mut() {
                    *paragraph = true;
                }
                self.start_leaf(Leaf::Para);
            }
            Tag::Heading { level, .. } => self.start_leaf(Leaf::Heading(level as u8)),
            Tag::BlockQuote(_) => self.container_start(Open::Quote(Vec::new())),
            Tag::List(first) => self.container_start(Open::List {
                ordered: first.is_some(),
                start: first.unwrap_or(1).min(MAX_START),
                items: Vec::new(),
                loose: false,
            }),
            Tag::Item => self.open(Open::Item {
                blocks: Vec::new(),
                paragraph: false,
            }),
            Tag::CodeBlock(_) => self.open(Open::Code(String::new())),
            Tag::HtmlBlock => self.open(Open::Html(String::new())),
            Tag::Table(align) => self.open(Open::Table {
                align: align
                    .iter()
                    .take(MAX_COLUMNS)
                    .map(|a| match a {
                        Alignment::None => None,
                        Alignment::Left => Some(Align::Left),
                        Alignment::Center => Some(Align::Center),
                        Alignment::Right => Some(Align::Right),
                    })
                    .collect(),
                head: Vec::new(),
                rows: Vec::new(),
                row: Vec::new(),
            }),
            Tag::TableHead | Tag::TableRow => {
                if let Some(Open::Table { row, .. }) = self.stack.last_mut() {
                    row.clear();
                }
            }
            Tag::TableCell => self.start_leaf(Leaf::Cell),
            Tag::Emphasis => self.start_inline(Wrap::Em),
            Tag::Strong => self.start_inline(Wrap::Strong),
            Tag::Strikethrough => self.start_inline(Wrap::Del),
            Tag::Link {
                link_type,
                dest_url,
                ..
            } => {
                // An address between angle brackets has no scheme of its own.
                let url = if link_type == LinkType::Email {
                    format!("mailto:{dest_url}")
                } else {
                    dest_url.into_string()
                };
                let wrap = if safe_target(&url) {
                    Wrap::Link(url)
                } else {
                    Wrap::Flat
                };
                self.start_inline(wrap);
            }
            Tag::Image { .. } => {
                self.leaf_mut().image = Some((1, String::new()));
            }
            _ => {}
        }
    }

    fn end(&mut self, end: TagEnd) {
        match end {
            TagEnd::Paragraph | TagEnd::Heading(_) | TagEnd::TableCell => self.end_leaf(),
            TagEnd::BlockQuote(_)
            | TagEnd::List(_)
            | TagEnd::Item
            | TagEnd::CodeBlock
            | TagEnd::HtmlBlock
            | TagEnd::Table => {
                self.flush_implicit();
                self.close_top();
            }
            TagEnd::TableHead | TagEnd::TableRow => {
                // A short row gets empty cells, up to the header's width.
                let missing = match self.stack.last() {
                    Some(Open::Table { align, row, .. }) => align.len().saturating_sub(row.len()),
                    _ => 0,
                };
                for _ in 0..missing {
                    if !self.spend() {
                        break;
                    }
                    if let Some(Open::Table { row, .. }) = self.stack.last_mut() {
                        row.push(Vec::new());
                    }
                }
                if let Some(Open::Table {
                    head, rows, row, ..
                }) = self.stack.last_mut()
                {
                    let done = std::mem::take(row);
                    if matches!(end, TagEnd::TableHead) {
                        *head = done;
                    } else {
                        rows.push(done);
                    }
                }
            }
            TagEnd::Emphasis | TagEnd::Strong | TagEnd::Strikethrough | TagEnd::Link => {
                self.end_inline()
            }
            _ => {}
        }
    }

    fn finish(mut self) -> Document {
        self.finishing = true;
        if self.deep > 0 && !self.flat.is_empty() {
            let text = std::mem::take(&mut self.flat);
            self.push_block(Block::Raw(text.trim_end_matches('\n').to_string()));
        }
        self.end_leaf();
        while self.stack.len() > 1 {
            self.close_top();
        }
        let blocks = match self.stack.pop() {
            Some(Open::Root(b)) => b,
            _ => Vec::new(),
        };
        Document {
            blocks,
            truncated: self.truncated,
        }
    }
}

// ── JSON ─────────────────────────────────────────────────────────────────────

fn string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn list<T>(out: &mut String, items: &[T], one: fn(&mut String, &T)) {
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        one(out, item);
    }
    out.push(']');
}

fn inline(out: &mut String, n: &Inline) {
    let wrapped = |out: &mut String, t: &str, c: &[Inline]| {
        out.push_str(&format!("{{\"t\":\"{t}\",\"c\":"));
        list(out, c, inline);
        out.push('}');
    };
    match n {
        Inline::Text(s) => {
            out.push_str("{\"t\":\"text\",\"s\":");
            string(out, s);
            out.push('}');
        }
        Inline::Code(s) => {
            out.push_str("{\"t\":\"code\",\"s\":");
            string(out, s);
            out.push('}');
        }
        Inline::Br => out.push_str("{\"t\":\"br\"}"),
        Inline::Em(c) => wrapped(out, "em", c),
        Inline::Strong(c) => wrapped(out, "strong", c),
        Inline::Del(c) => wrapped(out, "del", c),
        Inline::Link { url, children } => {
            out.push_str("{\"t\":\"link\",\"url\":");
            string(out, url);
            out.push_str(",\"c\":");
            list(out, children, inline);
            out.push('}');
        }
        Inline::Image { alt } => {
            out.push_str("{\"t\":\"image\",\"alt\":");
            string(out, alt);
            out.push('}');
        }
    }
}

fn inlines(out: &mut String, c: &[Inline]) {
    list(out, c, inline);
}

fn block(out: &mut String, b: &Block) {
    match b {
        Block::Para(c) => {
            out.push_str("{\"t\":\"p\",\"c\":");
            inlines(out, c);
            out.push('}');
        }
        Block::Heading { level, children } => {
            out.push_str(&format!("{{\"t\":\"h\",\"level\":{level},\"c\":"));
            inlines(out, children);
            out.push('}');
        }
        Block::Code(s) => {
            out.push_str("{\"t\":\"code\",\"s\":");
            string(out, s);
            out.push('}');
        }
        Block::Rule => out.push_str("{\"t\":\"hr\"}"),
        Block::Quote(c) => {
            out.push_str("{\"t\":\"quote\",\"c\":");
            list(out, c, block);
            out.push('}');
        }
        Block::List {
            ordered,
            start,
            tight,
            items,
        } => {
            out.push_str(&format!("{{\"t\":\"list\",\"ordered\":{ordered},\"start\":{start},\"tight\":{tight},\"items\":"));
            list(out, items, |out, item| list(out, item, block));
            out.push('}');
        }
        Block::Table { align, head, rows } => {
            out.push_str("{\"t\":\"table\",\"align\":");
            list(out, align, |out, a| {
                out.push_str(match a {
                    None => "null",
                    Some(Align::Left) => "\"left\"",
                    Some(Align::Center) => "\"center\"",
                    Some(Align::Right) => "\"right\"",
                })
            });
            out.push_str(",\"head\":");
            list(out, head, |out, c| inlines(out, c));
            out.push_str(",\"rows\":");
            list(out, rows, |out, row| {
                list(out, row, |out, c| inlines(out, c))
            });
            out.push('}');
        }
        Block::Raw(s) => {
            out.push_str("{\"t\":\"raw\",\"s\":");
            string(out, s);
            out.push('}');
        }
    }
}

impl Document {
    /// `{"blocks": [...], "truncated": bool}`; the page's `Block` and
    /// `Inline` types (`ts/text/markdown.ts`) are this shape.
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\"blocks\":");
        list(&mut out, &self.blocks, block);
        out.push_str(&format!(",\"truncated\":{}}}", self.truncated));
        out
    }
}
