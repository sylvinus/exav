//! The document model every reader fills and the DOCX writer serializes. It
//! follows WordprocessingML closely: properties are optional, a style is
//! named by its id, lengths are in twips, font sizes in half points, drawing
//! sizes in EMU.

pub type Emu = i64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    Auto,
    Rgb(u32),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Fonts {
    pub ascii: Option<String>,
    pub hansi: Option<String>,
    pub east_asia: Option<String>,
    pub cs: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Border {
    /// A ST_Border value: single, double, dotted, dashed, thick, ...
    pub style: &'static str,
    /// Eighths of a point.
    pub size: u32,
    /// Points between the border and the text.
    pub space: u32,
    pub color: Color,
    pub shadow: bool,
}

impl Border {
    pub fn single(size: u32, color: Color) -> Border {
        Border {
            style: "single",
            size,
            space: 0,
            color,
            shadow: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Shading {
    /// ST_Shd pattern: clear, solid, pct10, horzStripe, ...
    pub pattern: &'static str,
    pub fill: Option<Color>,
    pub color: Option<Color>,
}

impl Shading {
    pub fn fill(c: Color) -> Shading {
        Shading {
            pattern: "clear",
            fill: Some(c),
            color: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VertAlign {
    Baseline,
    Superscript,
    Subscript,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RunProps {
    pub style: Option<String>,
    pub fonts: Fonts,
    /// Half points.
    pub size: Option<u32>,
    pub size_cs: Option<u32>,
    pub bold: Option<bool>,
    pub bold_cs: Option<bool>,
    pub italic: Option<bool>,
    pub italic_cs: Option<bool>,
    pub caps: Option<bool>,
    pub small_caps: Option<bool>,
    pub strike: Option<bool>,
    pub dstrike: Option<bool>,
    pub vanish: Option<bool>,
    pub outline: Option<bool>,
    pub shadow: Option<bool>,
    pub emboss: Option<bool>,
    pub imprint: Option<bool>,
    /// ST_Underline: single, double, words, dotted, ...; "none" turns it
    /// off.
    pub underline: Option<&'static str>,
    pub underline_color: Option<Color>,
    pub color: Option<Color>,
    /// ST_HighlightColor: yellow, green, ...; "none" turns it off.
    pub highlight: Option<&'static str>,
    pub shading: Option<Shading>,
    pub vert_align: Option<VertAlign>,
    /// Twips added after each character.
    pub spacing: Option<i32>,
    /// Horizontal scale in percent.
    pub scale: Option<u32>,
    /// Half points raised (negative: lowered).
    pub position: Option<i32>,
    pub kerning: Option<u32>,
    pub lang: Option<String>,
    pub lang_east_asia: Option<String>,
    pub lang_bidi: Option<String>,
    pub rtl: Option<bool>,
    pub cs: Option<bool>,
    pub border: Option<Border>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Jc {
    Left,
    Center,
    Right,
    Both,
    Distribute,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineRule {
    Auto,
    Exact,
    AtLeast,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabKind {
    Left,
    Center,
    Right,
    Decimal,
    Bar,
    Clear,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabLeader {
    None,
    Dot,
    Hyphen,
    Underscore,
    MiddleDot,
    Heavy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tab {
    pub pos: i32,
    pub kind: TabKind,
    pub leader: TabLeader,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Borders {
    pub top: Option<Border>,
    pub left: Option<Border>,
    pub bottom: Option<Border>,
    pub right: Option<Border>,
    pub between: Option<Border>,
}

impl Borders {
    pub fn is_empty(&self) -> bool {
        self.top.is_none()
            && self.left.is_none()
            && self.bottom.is_none()
            && self.right.is_none()
            && self.between.is_none()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Frame {
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub height_exact: bool,
    pub x: Option<i32>,
    pub y: Option<i32>,
    /// page, margin, text
    pub h_anchor: Option<&'static str>,
    pub v_anchor: Option<&'static str>,
    pub x_align: Option<&'static str>,
    pub y_align: Option<&'static str>,
    pub wrap: Option<&'static str>,
    pub drop_cap: Option<&'static str>,
    pub lines: Option<u32>,
    pub h_space: Option<i32>,
    pub v_space: Option<i32>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParaProps {
    pub style: Option<String>,
    pub keep_next: Option<bool>,
    pub keep_lines: Option<bool>,
    pub page_break_before: Option<bool>,
    pub widow_control: Option<bool>,
    pub num_id: Option<u32>,
    pub num_level: Option<u32>,
    pub borders: Borders,
    pub shading: Option<Shading>,
    pub tabs: Vec<Tab>,
    pub suppress_line_numbers: Option<bool>,
    pub space_before: Option<i32>,
    pub space_after: Option<i32>,
    pub before_auto: Option<bool>,
    pub after_auto: Option<bool>,
    pub line: Option<i32>,
    pub line_rule: Option<LineRule>,
    pub ind_left: Option<i32>,
    pub ind_right: Option<i32>,
    pub ind_first_line: Option<i32>,
    pub ind_hanging: Option<i32>,
    pub contextual_spacing: Option<bool>,
    pub bidi: Option<bool>,
    pub jc: Option<Jc>,
    pub outline_level: Option<u32>,
    pub frame: Option<Frame>,
    pub snap_to_grid: Option<bool>,
}

/// A table's borders: the edges and the inside lines.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TableBorders {
    pub top: Option<Border>,
    pub left: Option<Border>,
    pub bottom: Option<Border>,
    pub right: Option<Border>,
    pub inside_h: Option<Border>,
    pub inside_v: Option<Border>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    Auto,
    /// Twips.
    Twips(i32),
    /// Fiftieths of a percent.
    Pct(i32),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Margins {
    pub top: Option<i32>,
    pub left: Option<i32>,
    pub bottom: Option<i32>,
    pub right: Option<i32>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TableProps {
    pub style: Option<String>,
    pub width: Option<Width>,
    pub jc: Option<Jc>,
    pub indent: Option<i32>,
    pub borders: TableBorders,
    pub shading: Option<Shading>,
    pub cell_margins: Margins,
    pub fixed_layout: bool,
    pub cell_spacing: Option<i32>,
    pub bidi: bool,
    /// Table positioned among the text (floating).
    pub float: Option<Frame>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RowProps {
    /// Twips; `height_exact` makes it exact, else a minimum.
    pub height: Option<i32>,
    pub height_exact: bool,
    pub header: bool,
    pub cant_split: bool,
    pub grid_before: u32,
    pub grid_after: u32,
    pub width_before: Option<Width>,
    pub width_after: Option<Width>,
    pub jc: Option<Jc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VMerge {
    None,
    Restart,
    Continue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VAlign {
    Top,
    Center,
    Bottom,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CellProps {
    pub width: Option<Width>,
    pub grid_span: u32,
    pub v_merge: VMerge,
    pub borders: TableBorders,
    pub shading: Option<Shading>,
    pub v_align: Option<VAlign>,
    pub margins: Margins,
    pub no_wrap: bool,
    pub fit_text: bool,
    /// lrTb, tbRl, btLr
    pub text_direction: Option<&'static str>,
}

impl Default for CellProps {
    fn default() -> Self {
        CellProps {
            width: None,
            grid_span: 1,
            v_merge: VMerge::None,
            borders: TableBorders::default(),
            shading: None,
            v_align: None,
            margins: Margins::default(),
            no_wrap: false,
            fit_text: false,
            text_direction: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Cell {
    pub props: CellProps,
    pub content: Vec<Block>,
}

#[derive(Clone, Debug, Default)]
pub struct Row {
    pub props: RowProps,
    pub cells: Vec<Cell>,
}

#[derive(Clone, Debug, Default)]
pub struct Table {
    pub props: TableProps,
    /// Column widths in twips.
    pub grid: Vec<i32>,
    pub rows: Vec<Row>,
}

/// Blocks are mostly paragraphs; boxing them would cost an allocation each.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Block {
    Para(Para),
    Table(Table),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakKind {
    Line,
    Page,
    Column,
}

#[derive(Clone, Debug)]
pub enum RunItem {
    Text(String),
    Tab,
    Break(BreakKind),
    NoBreakHyphen,
    SoftHyphen,
    Symbol {
        font: String,
        ch: u16,
    },
    Drawing(Box<Drawing>),
    FootnoteRef(u32),
    EndnoteRef(u32),
    /// The mark inside a footnote or endnote, repeating its number.
    NoteMark(bool),
    CommentRef(u32),
    /// The page number field in its simple form: PAGE, NUMPAGES.
    PageNumber,
}

#[derive(Clone, Debug, Default)]
pub struct Run {
    pub props: RunProps,
    pub items: Vec<RunItem>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldCharKind {
    Begin,
    Separate,
    End,
}

#[derive(Clone, Debug)]
pub enum Inline {
    Run(Run),
    /// A field mark whose partner is in another paragraph.
    FieldChar(FieldCharKind),
    InstrText(String),
    /// A field with its stored result.
    Field {
        instr: String,
        props: RunProps,
        result: Vec<Inline>,
    },
    Hyperlink {
        /// An external target, else `anchor`.
        target: Option<String>,
        anchor: Option<String>,
        tooltip: Option<String>,
        content: Vec<Inline>,
    },
    BookmarkStart {
        id: u32,
        name: String,
    },
    BookmarkEnd(u32),
    CommentStart(u32),
    CommentEnd(u32),
}

#[derive(Clone, Debug, Default)]
pub struct Para {
    pub props: ParaProps,
    /// The paragraph mark's character properties.
    pub mark: RunProps,
    pub content: Vec<Inline>,
    /// The section this paragraph ends.
    pub section: Option<Box<Section>>,
}

// ---- drawings ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wrap {
    None,
    Square,
    Tight,
    TopBottom,
    Through,
}

#[derive(Clone, Debug)]
pub struct Anchor {
    /// page, margin, column, character, paragraph, line, ...
    pub h_rel: &'static str,
    pub v_rel: &'static str,
    /// Offsets in EMU, or an alignment (left, center, right, top, ...).
    pub h_off: Emu,
    pub v_off: Emu,
    pub h_align: Option<&'static str>,
    pub v_align: Option<&'static str>,
    pub wrap: Wrap,
    pub behind: bool,
    pub z: u32,
    pub dist: [Emu; 4],
}

impl Default for Anchor {
    fn default() -> Self {
        Anchor {
            h_rel: "column",
            v_rel: "paragraph",
            h_off: 0,
            v_off: 0,
            h_align: None,
            v_align: None,
            wrap: Wrap::Square,
            behind: false,
            z: 0,
            dist: [0, 0, 0, 0],
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Crop {
    /// Thousandths of a percent of the picture, each side.
    pub l: i32,
    pub t: i32,
    pub r: i32,
    pub b: i32,
}

#[derive(Clone, Debug)]
pub struct Line {
    pub color: Color,
    /// EMU.
    pub width: Emu,
    pub dash: &'static str,
}

#[derive(Clone, Debug)]
pub enum Fill {
    None,
    Solid(u32),
}

#[derive(Clone, Debug)]
pub struct Shape {
    /// DrawingML preset geometry name: rect, ellipse, line, ...
    pub preset: &'static str,
    pub fill: Fill,
    pub line: Option<Line>,
    /// Text inside the shape.
    pub text: Vec<Block>,
    pub rot: i32,
    pub flip_h: bool,
    pub flip_v: bool,
    pub insets: [Emu; 4],
    pub v_anchor: &'static str,
}

impl Default for Shape {
    fn default() -> Self {
        Shape {
            preset: "rect",
            fill: Fill::None,
            line: None,
            text: vec![],
            rot: 0,
            flip_h: false,
            flip_v: false,
            insets: [91_440, 45_720, 91_440, 45_720],
            v_anchor: "t",
        }
    }
}

#[derive(Clone, Debug)]
pub enum DrawingKind {
    /// An index into `Document::media`.
    Picture {
        media: usize,
        crop: Crop,
    },
    Shape(Shape),
}

#[derive(Clone, Debug)]
pub struct Drawing {
    /// `None`: inline in the text.
    pub anchor: Option<Anchor>,
    pub cx: Emu,
    pub cy: Emu,
    pub name: String,
    pub descr: Option<String>,
    pub kind: DrawingKind,
}

#[derive(Clone, Debug)]
pub struct Media {
    pub ext: &'static str,
    pub data: Vec<u8>,
}

// ---- styles, numbering, sections ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StyleKind {
    Paragraph,
    Character,
    Table,
    Numbering,
}

#[derive(Clone, Debug)]
pub struct Style {
    pub id: String,
    pub name: String,
    pub kind: StyleKind,
    pub based_on: Option<String>,
    pub next: Option<String>,
    pub link: Option<String>,
    pub default: bool,
    pub q_format: bool,
    pub ui_priority: Option<u32>,
    pub hidden: bool,
    pub ppr: ParaProps,
    pub rpr: RunProps,
    pub tbl: Option<TableProps>,
}

impl Style {
    pub fn new(id: &str, name: &str, kind: StyleKind) -> Style {
        Style {
            id: id.to_string(),
            name: name.to_string(),
            kind,
            based_on: None,
            next: None,
            link: None,
            default: false,
            q_format: false,
            ui_priority: None,
            hidden: false,
            ppr: ParaProps::default(),
            rpr: RunProps::default(),
            tbl: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Level {
    pub start: i64,
    /// ST_NumberFormat: decimal, bullet, lowerLetter, upperRoman, ...
    pub fmt: &'static str,
    /// The text with %1..%9 for the counters.
    pub text: String,
    pub jc: Jc,
    /// tab, space, nothing
    pub suff: &'static str,
    pub style: Option<String>,
    pub ppr: ParaProps,
    pub rpr: RunProps,
    pub legal: bool,
    /// The level whose counter restarts this one: Some(0) never restarts.
    pub restart: Option<u32>,
}

impl Default for Level {
    fn default() -> Self {
        Level {
            start: 1,
            fmt: "decimal",
            text: String::new(),
            jc: Jc::Left,
            suff: "tab",
            style: None,
            ppr: ParaProps::default(),
            rpr: RunProps::default(),
            legal: false,
            restart: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AbstractNum {
    pub id: u32,
    pub multi_level: bool,
    pub levels: Vec<Level>,
}

#[derive(Clone, Debug, Default)]
pub struct Num {
    pub id: u32,
    pub abstract_id: u32,
    /// (level, start override, level definition override)
    pub overrides: Vec<(u32, Option<i64>, Option<Level>)>,
}

#[derive(Clone, Debug, Default)]
pub struct Numbering {
    pub abstracts: Vec<AbstractNum>,
    pub nums: Vec<Num>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionType {
    NextPage,
    Continuous,
    EvenPage,
    OddPage,
    NextColumn,
}

#[derive(Clone, Debug, Default)]
pub struct Columns {
    pub num: u32,
    pub space: i32,
    pub separator: bool,
    /// (width, space after) per column when unequal.
    pub widths: Vec<(i32, i32)>,
}

#[derive(Clone, Debug, Default)]
pub struct HeaderFooter {
    pub default: Option<Vec<Block>>,
    pub first: Option<Vec<Block>>,
    pub even: Option<Vec<Block>>,
}

#[derive(Clone, Debug)]
pub struct Section {
    pub kind: SectionType,
    pub width: i32,
    pub height: i32,
    pub landscape: bool,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
    pub left: i32,
    pub header: i32,
    pub footer: i32,
    pub gutter: i32,
    pub columns: Columns,
    pub title_page: bool,
    pub page_start: Option<u32>,
    pub page_fmt: Option<&'static str>,
    pub v_align: Option<&'static str>,
    pub rtl_gutter: bool,
    pub bidi: bool,
    pub page_borders: Borders,
    pub headers: HeaderFooter,
    pub footers: HeaderFooter,
    pub text_direction: Option<&'static str>,
    pub line_numbers: Option<(u32, u32, i32)>,
}

impl Default for Section {
    fn default() -> Self {
        Section {
            kind: SectionType::NextPage,
            width: 12240,
            height: 15840,
            landscape: false,
            top: 1440,
            right: 1440,
            bottom: 1440,
            left: 1440,
            header: 720,
            footer: 720,
            gutter: 0,
            columns: Columns::default(),
            title_page: false,
            page_start: None,
            page_fmt: None,
            v_align: None,
            rtl_gutter: false,
            bidi: false,
            page_borders: Borders::default(),
            headers: HeaderFooter::default(),
            footers: HeaderFooter::default(),
            text_direction: None,
            line_numbers: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Note {
    pub id: u32,
    pub content: Vec<Block>,
}

#[derive(Clone, Debug)]
pub struct Comment {
    pub id: u32,
    pub author: String,
    pub initials: String,
    pub date: Option<String>,
    pub content: Vec<Block>,
}

#[derive(Clone, Debug, Default)]
pub struct Settings {
    pub default_tab_stop: Option<i32>,
    pub even_and_odd_headers: bool,
    pub footnote_pos: Option<&'static str>,
    pub footnote_fmt: Option<&'static str>,
    pub footnote_start: Option<u32>,
    pub footnote_restart: Option<&'static str>,
    pub endnote_fmt: Option<&'static str>,
    pub endnote_start: Option<u32>,
    pub endnote_restart: Option<&'static str>,
    pub mirror_margins: bool,
    pub gutter_at_top: bool,
}

#[derive(Debug, Default)]
pub struct Document {
    pub defaults_run: RunProps,
    pub defaults_para: ParaProps,
    pub styles: Vec<Style>,
    pub numbering: Numbering,
    pub body: Vec<Block>,
    /// The last section's properties.
    pub section: Section,
    pub footnotes: Vec<Note>,
    pub endnotes: Vec<Note>,
    pub comments: Vec<Comment>,
    pub media: Vec<Media>,
    pub settings: Settings,
    pub warnings: Vec<String>,
}

impl Document {
    /// The index of a picture in `media`, adding it when new (by content).
    pub fn add_media(&mut self, ext: &'static str, data: Vec<u8>) -> usize {
        if let Some(i) = self
            .media
            .iter()
            .position(|m| m.ext == ext && m.data == data)
        {
            return i;
        }
        self.media.push(Media { ext, data });
        self.media.len() - 1
    }

    pub fn warn(&mut self, w: impl Into<String>) {
        if self.warnings.len() < 200 {
            self.warnings.push(w.into());
        }
    }
}

impl Run {
    pub fn text(props: RunProps, s: impl Into<String>) -> Run {
        Run {
            props,
            items: vec![RunItem::Text(s.into())],
        }
    }
}

fn over<T: Clone>(a: &mut Option<T>, b: &Option<T>) {
    if b.is_some() {
        *a = b.clone();
    }
}

impl RunProps {
    /// `o`'s set properties over these.
    pub fn overlay(&mut self, o: &RunProps) {
        over(&mut self.style, &o.style);
        over(&mut self.fonts.ascii, &o.fonts.ascii);
        over(&mut self.fonts.hansi, &o.fonts.hansi);
        over(&mut self.fonts.east_asia, &o.fonts.east_asia);
        over(&mut self.fonts.cs, &o.fonts.cs);
        over(&mut self.size, &o.size);
        over(&mut self.size_cs, &o.size_cs);
        over(&mut self.bold, &o.bold);
        over(&mut self.bold_cs, &o.bold_cs);
        over(&mut self.italic, &o.italic);
        over(&mut self.italic_cs, &o.italic_cs);
        over(&mut self.caps, &o.caps);
        over(&mut self.small_caps, &o.small_caps);
        over(&mut self.strike, &o.strike);
        over(&mut self.dstrike, &o.dstrike);
        over(&mut self.vanish, &o.vanish);
        over(&mut self.outline, &o.outline);
        over(&mut self.shadow, &o.shadow);
        over(&mut self.emboss, &o.emboss);
        over(&mut self.imprint, &o.imprint);
        over(&mut self.underline, &o.underline);
        over(&mut self.underline_color, &o.underline_color);
        over(&mut self.color, &o.color);
        over(&mut self.highlight, &o.highlight);
        over(&mut self.shading, &o.shading);
        over(&mut self.vert_align, &o.vert_align);
        over(&mut self.spacing, &o.spacing);
        over(&mut self.scale, &o.scale);
        over(&mut self.position, &o.position);
        over(&mut self.kerning, &o.kerning);
        over(&mut self.lang, &o.lang);
        over(&mut self.lang_east_asia, &o.lang_east_asia);
        over(&mut self.lang_bidi, &o.lang_bidi);
        over(&mut self.rtl, &o.rtl);
        over(&mut self.cs, &o.cs);
        over(&mut self.border, &o.border);
    }
}
