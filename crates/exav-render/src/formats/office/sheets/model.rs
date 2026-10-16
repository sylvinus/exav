//! The workbook as the readers fill it and the XLSX writer serializes it.
//! Units are XLSX's: column widths in characters as `<col width>` stores
//! them, row heights in points, colours as RGB.

use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

/// 0xRRGGBB.
pub type Rgb = u32;
/// Text shared between cells (an XLS string table entry is one allocation).
pub type Str = Rc<str>;

/// The error values a cell can hold in XLSX.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CellError {
    Null,
    Div0,
    Value,
    Ref,
    Name,
    Num,
    NA,
    GettingData,
}

impl CellError {
    pub fn name(self) -> &'static str {
        match self {
            CellError::Null => "#NULL!",
            CellError::Div0 => "#DIV/0!",
            CellError::Value => "#VALUE!",
            CellError::Ref => "#REF!",
            CellError::Name => "#NAME?",
            CellError::Num => "#NUM!",
            CellError::NA => "#N/A",
            CellError::GettingData => "#GETTING_DATA",
        }
    }

    /// The BIFF error code ([MS-XLS] 2.5.97 BErr).
    pub fn from_biff(code: u8) -> Option<CellError> {
        Some(match code {
            0x00 => CellError::Null,
            0x07 => CellError::Div0,
            0x0F => CellError::Value,
            0x17 => CellError::Ref,
            0x1D => CellError::Name,
            0x24 => CellError::Num,
            0x2A => CellError::NA,
            0x2B => CellError::GettingData,
            _ => return None,
        })
    }

    /// An error as text: one of XLSX's names, case folded.
    pub fn parse(s: &str) -> Option<CellError> {
        let t = s.trim();
        [
            CellError::Null,
            CellError::Div0,
            CellError::Value,
            CellError::Ref,
            CellError::Name,
            CellError::Num,
            CellError::NA,
            CellError::GettingData,
        ]
        .into_iter()
        .find(|e| e.name().eq_ignore_ascii_case(t))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Empty,
    Number(f64),
    Text(Str),
    Rich(Rc<[Run]>),
    Bool(bool),
    Error(CellError),
}

impl Value {
    pub fn text(s: impl Into<Str>) -> Value {
        Value::Text(s.into())
    }

    /// Bytes of text the value holds, for the memory budget.
    pub fn text_len(&self) -> usize {
        match self {
            Value::Text(t) => t.len(),
            Value::Rich(r) => r.iter().map(|r| r.text.len() + 64).sum(),
            _ => 0,
        }
    }

    /// The text a chart or a label shows for the value.
    pub fn display(&self) -> String {
        match self {
            Value::Text(t) => t.to_string(),
            Value::Rich(runs) => runs.iter().map(|r| r.text.as_str()).collect(),
            Value::Number(n) => crate::formats::office::sheets::numtext::shortest(*n),
            Value::Bool(b) => if *b { "TRUE" } else { "FALSE" }.into(),
            Value::Error(e) => e.name().into(),
            Value::Empty => String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Run {
    pub text: String,
    pub font: Option<Font>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Cell {
    pub value: Value,
    /// Excel syntax, without the leading `=`.
    pub formula: Option<Box<str>>,
    pub style: u32,
}

impl Cell {
    pub fn styled(style: u32) -> Cell {
        Cell {
            value: Value::Empty,
            formula: None,
            style,
        }
    }
}

/// A rectangle of cells, 0-based and inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Range {
    pub r1: u32,
    pub c1: u32,
    pub r2: u32,
    pub c2: u32,
}

impl Range {
    pub fn cell(r: u32, c: u32) -> Range {
        Range {
            r1: r,
            c1: c,
            r2: r,
            c2: c,
        }
    }

    pub fn area(&self) -> u64 {
        (u64::from(self.r2.saturating_sub(self.r1)) + 1)
            * (u64::from(self.c2.saturating_sub(self.c1)) + 1)
    }

    /// Ordered corners, clipped to XLSX's grid; `None` when nothing is left.
    pub fn clipped(self) -> Option<Range> {
        let (r1, r2) = (self.r1.min(self.r2), self.r1.max(self.r2));
        let (c1, c2) = (self.c1.min(self.c2), self.c1.max(self.c2));
        if r1 > MAX_ROW || c1 > MAX_COL {
            return None;
        }
        Some(Range {
            r1,
            c1,
            r2: r2.min(MAX_ROW),
            c2: c2.min(MAX_COL),
        })
    }
}

/// XLSX's last row and column, 0-based.
pub const MAX_ROW: u32 = 1_048_575;
pub const MAX_COL: u32 = 16_383;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Font {
    pub name: String,
    /// Points times 100, to keep the type hashable.
    pub size_centipt: u32,
    pub bold: bool,
    pub italic: bool,
    /// "single", "double", "singleAccounting", "doubleAccounting".
    pub underline: Option<&'static str>,
    pub strike: bool,
    pub color: Option<Rgb>,
    /// "superscript" or "subscript".
    pub vert_align: Option<&'static str>,
    pub family: u8,
    pub charset: Option<u8>,
    pub outline: bool,
    pub shadow: bool,
}

impl Default for Font {
    fn default() -> Self {
        Font {
            name: "Arial".into(),
            size_centipt: 1000,
            bold: false,
            italic: false,
            underline: None,
            strike: false,
            color: None,
            vert_align: None,
            family: 0,
            charset: None,
            outline: false,
            shadow: false,
        }
    }
}

impl Font {
    pub fn size_pt(&self) -> f64 {
        f64::from(self.size_centipt) / 100.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Fill {
    /// XLSX patternType; "none" when empty.
    pub pattern: &'static str,
    pub fg: Option<Rgb>,
    pub bg: Option<Rgb>,
}

impl Default for Fill {
    fn default() -> Self {
        Fill::NONE
    }
}

impl Fill {
    pub const NONE: Fill = Fill {
        pattern: "none",
        fg: None,
        bg: None,
    };

    pub fn solid(c: Rgb) -> Fill {
        Fill {
            pattern: "solid",
            fg: Some(c),
            bg: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct Edge {
    /// XLSX border style name; `None` for no line.
    pub style: Option<&'static str>,
    pub color: Option<Rgb>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct Border {
    pub left: Edge,
    pub right: Edge,
    pub top: Edge,
    pub bottom: Edge,
    pub diagonal: Edge,
    pub diag_up: bool,
    pub diag_down: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct Align {
    pub horizontal: Option<&'static str>,
    pub vertical: Option<&'static str>,
    pub wrap: bool,
    pub indent: u8,
    /// XLSX textRotation: 0 to 180, 255 for stacked.
    pub rotation: u8,
    pub shrink: bool,
    pub reading_order: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Style {
    pub font: Font,
    pub fill: Fill,
    pub border: Border,
    pub align: Align,
    pub numfmt: String,
    pub locked: bool,
    pub hidden: bool,
}

impl Default for Style {
    fn default() -> Self {
        Style {
            font: Font::default(),
            fill: Fill::NONE,
            border: Border::default(),
            align: Align::default(),
            numfmt: "General".into(),
            locked: true,
            hidden: false,
        }
    }
}

/// Styles, deduplicated. Index 0 is the default style.
#[derive(Default, Debug)]
pub struct Styles {
    pub list: Vec<Style>,
    index: HashMap<Style, u32>,
}

impl Styles {
    pub fn new(default: Style) -> Self {
        let mut s = Styles::default();
        s.add(default);
        s
    }

    pub fn add(&mut self, st: Style) -> u32 {
        if let Some(&i) = self.index.get(&st) {
            return i;
        }
        let i = u32::try_from(self.list.len()).unwrap_or(u32::MAX);
        self.index.insert(st.clone(), i);
        self.list.push(st);
        i
    }

    pub fn get(&self, i: u32) -> &Style {
        self.list.get(i as usize).unwrap_or(&self.list[0])
    }
}

#[derive(Clone, Debug, Default)]
pub struct ColInfo {
    pub first: u32,
    pub last: u32,
    pub width: Option<f64>,
    pub hidden: bool,
    pub style: Option<u32>,
    pub outline: u8,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RowInfo {
    pub height: Option<f64>,
    pub custom_height: bool,
    pub hidden: bool,
    pub style: Option<u32>,
    pub outline: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SheetState {
    #[default]
    Visible,
    Hidden,
    VeryHidden,
}

#[derive(Clone, Debug)]
pub struct Hyperlink {
    pub range: Range,
    pub url: Option<String>,
    pub location: Option<String>,
    pub tooltip: Option<String>,
    pub display: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Comment {
    pub row: u32,
    pub col: u32,
    pub author: String,
    pub text: String,
    pub visible: bool,
}

/// A differential format, for conditional formats.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Dxf {
    pub font_color: Option<Rgb>,
    pub bold: Option<bool>,
    pub italic: Option<bool>,
    pub underline: Option<&'static str>,
    pub strike: Option<bool>,
    pub fill: Option<Fill>,
    pub border: Option<Border>,
    pub numfmt: Option<String>,
}

/// A threshold of a colour scale, data bar or icon set.
#[derive(Clone, Debug, PartialEq)]
pub struct Cfvo {
    /// min, max, num, percent, percentile, formula.
    pub kind: &'static str,
    pub val: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CfKind {
    CellIs {
        operator: &'static str,
        formulas: Vec<String>,
    },
    Expression {
        formula: String,
    },
    ColorScale {
        cfvos: Vec<Cfvo>,
        colors: Vec<Rgb>,
    },
    DataBar {
        min: Cfvo,
        max: Cfvo,
        color: Rgb,
    },
    IconSet {
        set: String,
        cfvos: Vec<Cfvo>,
        reverse: bool,
        show_value: bool,
    },
    /// Any other rule type: its XLSX `type`, attributes and formulas.
    Other {
        kind: &'static str,
        attrs: Vec<(&'static str, String)>,
        formulas: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct CfRule {
    pub kind: CfKind,
    pub dxf: Option<Dxf>,
    pub stop: bool,
    /// The file's own priority (lower first); 0 when it has none, and the
    /// rule takes its place in the order of the sheet's rules.
    pub priority: u32,
}

#[derive(Clone, Debug)]
pub struct CondFormat {
    pub ranges: Vec<Range>,
    pub rules: Vec<CfRule>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Validation {
    pub ranges: Vec<Range>,
    pub kind: &'static str,
    pub operator: &'static str,
    pub formula1: Option<String>,
    pub formula2: Option<String>,
    pub allow_blank: bool,
    /// XLSX's inverted meaning: true hides the in-cell arrow.
    pub hide_dropdown: bool,
    pub show_input: bool,
    pub show_error: bool,
    pub error_style: &'static str,
    pub prompt_title: Option<String>,
    pub prompt: Option<String>,
    pub error_title: Option<String>,
    pub error: Option<String>,
}

/// Where a drawing sits: a cell and an offset in it, for each corner. The
/// offsets are millionths of that cell's width or height.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Anchor {
    /// col, row, col offset, row offset.
    pub from: (u32, u32, i64, i64),
    pub to: (u32, u32, i64, i64),
}

#[derive(Clone, Debug)]
pub struct Image {
    pub anchor: Anchor,
    pub ext: &'static str,
    pub data: Vec<u8>,
    pub name: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ChartSeries {
    pub name_ref: Option<String>,
    pub name: Option<String>,
    /// Categories (or the x values of a scatter or bubble chart).
    pub cat_ref: Option<String>,
    pub cats: Vec<String>,
    pub cat_nums: Option<Vec<Option<f64>>>,
    pub val_ref: Option<String>,
    pub vals: Vec<Option<f64>>,
    /// Bubble sizes.
    pub size_ref: Option<String>,
    pub sizes: Vec<Option<f64>>,
    pub color: Option<Rgb>,
    /// Point colours (a pie's slices), by index.
    pub point_colors: Vec<(u32, Rgb)>,
    pub smooth: bool,
    /// Line and scatter: markers shown.
    pub marker: bool,
    /// Line and scatter: the line drawn.
    pub line: bool,
    /// Combined charts: the kind this series is drawn as, when it differs.
    pub kind: Option<ChartKind>,
    /// On the secondary axis.
    pub secondary: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChartKind {
    Bar,
    Line,
    Area,
    Pie,
    Doughnut,
    Scatter,
    Radar,
    FilledRadar,
    Bubble,
    Stock,
    Surface,
}

#[derive(Clone, Debug)]
pub struct Chart {
    pub anchor: Anchor,
    pub kind: ChartKind,
    pub horizontal: bool,
    /// standard, clustered, stacked, percentStacked.
    pub grouping: &'static str,
    pub three_d: bool,
    pub title: Option<String>,
    pub legend: Option<&'static str>,
    pub series: Vec<ChartSeries>,
    pub cat_title: Option<String>,
    pub val_title: Option<String>,
    /// Colour by point (pies, and charts that ask for it).
    pub vary_colors: bool,
    pub gap_width: Option<u32>,
    pub overlap: Option<i32>,
    pub hole_size: Option<u32>,
    pub first_slice: Option<u32>,
    pub major_grid: bool,
    pub cat_axis_deleted: bool,
    pub val_axis_deleted: bool,
    /// The plot area's fill.
    pub plot_fill: Option<Rgb>,
    /// The chart area's fill.
    pub area_fill: Option<Rgb>,
}

impl Chart {
    pub fn new(anchor: Anchor, kind: ChartKind) -> Chart {
        Chart {
            anchor,
            kind,
            horizontal: false,
            grouping: "standard",
            three_d: false,
            title: None,
            legend: None,
            series: vec![],
            cat_title: None,
            val_title: None,
            vary_colors: matches!(kind, ChartKind::Pie | ChartKind::Doughnut),
            gap_width: None,
            overlap: None,
            hole_size: None,
            first_slice: None,
            major_grid: true,
            cat_axis_deleted: false,
            val_axis_deleted: false,
            plot_fill: None,
            area_fill: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ShapeText {
    pub text: String,
    pub font: Option<Font>,
    /// "l", "ctr", "r".
    pub align: Option<&'static str>,
    /// "t", "ctr", "b".
    pub anchor: Option<&'static str>,
}

#[derive(Clone, Debug)]
pub struct Shape {
    pub anchor: Anchor,
    /// DrawingML preset geometry: rect, ellipse, roundRect, line, ...
    pub geom: &'static str,
    pub fill: Option<Rgb>,
    pub line: Option<Rgb>,
    /// Line width in EMU.
    pub line_width: Option<i64>,
    pub line_dash: Option<&'static str>,
    pub head_arrow: bool,
    pub tail_arrow: bool,
    pub text: ShapeText,
    pub name: String,
    /// Degrees, clockwise.
    pub rotation: f64,
    pub flip_h: bool,
    pub flip_v: bool,
}

impl Shape {
    pub fn new(anchor: Anchor, geom: &'static str) -> Shape {
        Shape {
            anchor,
            geom,
            fill: None,
            line: None,
            line_width: None,
            line_dash: None,
            head_arrow: false,
            tail_arrow: false,
            text: ShapeText::default(),
            name: String::new(),
            rotation: 0.0,
            flip_h: false,
            flip_v: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Sheet {
    pub name: String,
    pub state: SheetState,
    pub cells: BTreeMap<(u32, u32), Cell>,
    /// Array formulas: the range each master cell covers.
    pub arrays: HashMap<(u32, u32), Range>,
    pub cols: Vec<ColInfo>,
    pub rows: BTreeMap<u32, RowInfo>,
    pub default_col_width: Option<f64>,
    pub base_col_width: Option<u32>,
    pub default_row_height: f64,
    pub default_row_custom: bool,
    pub default_row_hidden: bool,
    pub merges: Vec<Range>,
    /// Frozen rows and columns.
    pub freeze: Option<(u32, u32)>,
    pub top_left: Option<(u32, u32)>,
    pub show_grid: bool,
    pub show_zeros: bool,
    pub show_headers: bool,
    pub rtl: bool,
    pub tab_color: Option<Rgb>,
    pub zoom: u32,
    pub cond_formats: Vec<CondFormat>,
    pub validations: Vec<Validation>,
    pub hyperlinks: Vec<Hyperlink>,
    pub comments: Vec<Comment>,
    pub autofilter: Option<Range>,
    pub images: Vec<Image>,
    pub charts: Vec<Chart>,
    pub shapes: Vec<Shape>,
    pub protected: bool,
    pub outline_below: bool,
    pub outline_right: bool,
    /// A chart sheet: its one chart fills the sheet.
    pub chart_sheet: bool,
}

impl Sheet {
    pub fn new(name: String) -> Self {
        Sheet {
            name,
            default_row_height: 12.75,
            show_grid: true,
            show_zeros: true,
            show_headers: true,
            zoom: 100,
            outline_below: true,
            outline_right: true,
            ..Default::default()
        }
    }

    pub fn col_info(&self, c: u32) -> Option<&ColInfo> {
        self.cols.iter().find(|x| c >= x.first && c <= x.last)
    }
}

#[derive(Clone, Debug)]
pub struct DefinedName {
    pub name: String,
    pub sheet: Option<usize>,
    pub formula: String,
    pub hidden: bool,
}

#[derive(Debug)]
pub struct Workbook {
    pub sheets: Vec<Sheet>,
    pub styles: Styles,
    pub date1904: bool,
    pub names: Vec<DefinedName>,
    pub active: usize,
    pub first_tab: usize,
    /// What the reader left out or could not read.
    pub warnings: Vec<String>,
}

impl Workbook {
    pub fn new(default: Style) -> Self {
        Workbook {
            sheets: vec![],
            styles: Styles::new(default),
            date1904: false,
            names: vec![],
            active: 0,
            first_tab: 0,
            warnings: vec![],
        }
    }

    /// Records a warning, once, and at most a few hundred.
    pub fn warn(&mut self, w: impl Into<String>) {
        let w = w.into();
        if self.warnings.len() < 256 && !self.warnings.contains(&w) {
            self.warnings.push(w);
        }
    }
}

/// Link targets a reader may follow: not script and not data URLs.
pub fn safe_url(u: &str) -> bool {
    let l: String = u
        .trim_start()
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .take(16)
        .collect::<String>()
        .to_ascii_lowercase();
    !(l.starts_with("javascript:") || l.starts_with("vbscript:") || l.starts_with("data:"))
}

/// "A1" style column letters for 0-based `col`.
pub fn col_name(col: u32) -> String {
    let mut n = u64::from(col) + 1;
    let mut s = Vec::new();
    while n > 0 {
        let r = (n - 1) % 26;
        s.push(b'A' + r as u8);
        n = (n - 1) / 26;
    }
    s.reverse();
    String::from_utf8(s).unwrap_or_default()
}

pub fn cell_ref(row: u32, col: u32) -> String {
    format!("{}{}", col_name(col), u64::from(row) + 1)
}

pub fn range_ref(r: &Range) -> String {
    if r.r1 == r.r2 && r.c1 == r.c2 {
        cell_ref(r.r1, r.c1)
    } else {
        format!("{}:{}", cell_ref(r.r1, r.c1), cell_ref(r.r2, r.c2))
    }
}

/// "B12" or "$B$12" to 0-based (row, col).
pub fn parse_cell(s: &str) -> Option<(u32, u32)> {
    let s = s.trim();
    let b = s.as_bytes();
    let mut i = 0;
    if b.get(i) == Some(&b'$') {
        i += 1;
    }
    let ls = i;
    while i < b.len() && b[i].is_ascii_alphabetic() {
        i += 1;
    }
    let letters = &s[ls..i];
    if b.get(i) == Some(&b'$') {
        i += 1;
    }
    let digits = &s[i..];
    if letters.is_empty()
        || letters.len() > 3
        || digits.is_empty()
        || digits.len() > 7
        || !digits.bytes().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let mut col = 0u32;
    for ch in letters.bytes() {
        col = col * 26 + u32::from(ch.to_ascii_uppercase() - b'A' + 1);
    }
    let row: u32 = digits.parse().ok()?;
    Some((row.checked_sub(1)?, col.checked_sub(1)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references() {
        assert_eq!(col_name(0), "A");
        assert_eq!(col_name(25), "Z");
        assert_eq!(col_name(26), "AA");
        assert_eq!(col_name(16383), "XFD");
        assert_eq!(cell_ref(0, 0), "A1");
        assert_eq!(parse_cell("$XFD$1048576"), Some((1_048_575, 16383)));
        assert_eq!(parse_cell("b12"), Some((11, 1)));
        assert_eq!(parse_cell("A0"), None);
        assert_eq!(parse_cell("ABCD1"), None);
        assert_eq!(parse_cell("A99999999"), None);
        assert_eq!(
            range_ref(&Range {
                r1: 0,
                c1: 0,
                r2: 2,
                c2: 1
            }),
            "A1:B3"
        );
    }
}
