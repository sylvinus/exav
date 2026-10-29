//! The presentation model the readers fill and the PPTX writer serializes.
//! It follows DrawingML closely, with every property resolved by the
//! reader: colours are RGB, text carries its own sizes and fonts, and
//! shapes their own geometry, so that the PPTX does not depend on how a
//! renderer resolves inheritance.

/// English Metric Units: 914400 per inch, 12700 per point.
pub type Emu = i64;

/// 0xRRGGBB.
pub type Rgb = u32;

#[derive(Debug, Default)]
pub struct Presentation {
    /// Slide size.
    pub width: Emu,
    pub height: Emu,
    pub masters: Vec<Master>,
    pub slides: Vec<Slide>,
    /// Slides in the document, those not converted included.
    pub total_slides: usize,
    pub media: Vec<Media>,
    pub warnings: Vec<String>,
}

impl Presentation {
    /// Adds a picture, returning its index; identical bytes are kept once.
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
        let w = w.into();
        if !self.warnings.contains(&w) && self.warnings.len() < 100 {
            self.warnings.push(w);
        }
    }
}

#[derive(Debug)]
pub struct Media {
    /// png, jpeg, gif, bmp, tiff, emf, wmf, svg.
    pub ext: &'static str,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub name: String,
    /// dk1, lt1, dk2, lt2, accent1 to accent6, hlink, folHlink.
    pub colors: [Rgb; 12],
    pub major_font: String,
    pub minor_font: String,
}

impl Default for Theme {
    fn default() -> Self {
        Theme {
            name: "Office".into(),
            colors: [
                0x000000, 0xFFFFFF, 0x44546A, 0xE7E6E6, 0x4472C4, 0xED7D31, 0xA5A5A5, 0xFFC000,
                0x5B9BD5, 0x70AD47, 0x0563C1, 0x954F72,
            ],
            major_font: "Arial".into(),
            minor_font: "Arial".into(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Master {
    pub name: String,
    pub theme: Theme,
    pub background: Option<Fill>,
    pub shapes: Vec<Shape>,
    pub title_style: ListStyle,
    pub body_style: ListStyle,
    pub other_style: ListStyle,
    /// At least one is written, a blank one when empty.
    pub layouts: Vec<Layout>,
}

#[derive(Debug, Default)]
pub struct Layout {
    pub name: String,
    /// ST_SlideLayoutType: title, obj, blank, titleOnly, twoObj...
    pub kind: &'static str,
    pub background: Option<Fill>,
    pub shapes: Vec<Shape>,
    pub show_master_shapes: bool,
}

#[derive(Debug, Default)]
pub struct Slide {
    /// The page's name in a drawing; presentations leave it out.
    pub name: Option<String>,
    pub master: usize,
    pub layout: usize,
    pub background: Option<Fill>,
    pub shapes: Vec<Shape>,
    pub hidden: bool,
    pub show_master_shapes: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Xfrm {
    pub x: Emu,
    pub y: Emu,
    pub w: Emu,
    pub h: Emu,
    /// Degrees, clockwise.
    pub rot: f64,
    pub flip_h: bool,
    pub flip_v: bool,
}

#[derive(Debug, Clone)]
pub struct Shape {
    pub name: String,
    pub descr: String,
    pub xfrm: Xfrm,
    pub kind: ShapeKind,
    pub placeholder: Option<Placeholder>,
    pub link: Option<Link>,
    pub hidden: bool,
}

impl Shape {
    pub fn new(kind: ShapeKind, xfrm: Xfrm) -> Shape {
        Shape {
            name: String::new(),
            descr: String::new(),
            xfrm,
            kind,
            placeholder: None,
            link: None,
            hidden: false,
        }
    }
}

impl ShapeKind {
    /// What stands for a movie that cannot play, with no poster frame, in a
    /// box of `w` by `h`: a dark box with a white play triangle (`video`),
    /// or a pale box with a grey one (a sound).
    pub fn media_placeholder(w: Emu, h: Emu, video: bool) -> ShapeKind {
        let (w, h) = (w.max(1), h.max(1));
        let (back, mark) = if video {
            (0x202020, 0xFFFFFF)
        } else {
            (0xE8E8E8, 0x808080)
        };
        let side = (w.min(h) as f64 * 0.3).max(1.0);
        let (tw, th) = (side * 0.87, side);
        let triangle = Shape::new(
            ShapeKind::Sp(Box::new(Sp {
                geom: Geometry::preset("triangle"),
                fill: Fill::Solid(Color::rgb(mark)),
                ..Sp::default()
            })),
            Xfrm {
                x: ((w as f64 - tw) / 2.0).round() as Emu,
                y: ((h as f64 - th) / 2.0).round() as Emu,
                w: tw.round() as Emu,
                h: th.round() as Emu,
                // Pointing right.
                rot: 90.0,
                ..Xfrm::default()
            },
        );
        let back = Shape::new(
            ShapeKind::Sp(Box::new(Sp {
                fill: Fill::Solid(Color::rgb(back)),
                ..Sp::default()
            })),
            Xfrm {
                x: 0,
                y: 0,
                w,
                h,
                ..Xfrm::default()
            },
        );
        let child = Xfrm {
            x: 0,
            y: 0,
            w,
            h,
            ..Xfrm::default()
        };
        ShapeKind::Group(Box::new(Group {
            child,
            shapes: vec![back, triangle],
        }))
    }
}

#[derive(Debug, Clone)]
pub struct Placeholder {
    /// ST_PlaceholderType: title, body, ctrTitle, subTitle, dt, ftr,
    /// sldNum, obj, pic, tbl, chart...
    pub kind: &'static str,
    pub idx: Option<u32>,
}

impl Link {
    /// A link to `href`, unless empty, internal (#...), or of a scheme
    /// that runs code (javascript:, vbscript:, data:).
    pub fn url(href: &str) -> Option<Link> {
        let t = href.trim();
        let l = t.to_ascii_lowercase();
        if t.is_empty()
            || t.starts_with('#')
            || l.starts_with("javascript:")
            || l.starts_with("vbscript:")
            || l.starts_with("data:")
        {
            return None;
        }
        Some(Link::Url(t.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Link {
    Url(String),
    /// A slide of this presentation, 0-based.
    Slide(usize),
    NextSlide,
    PrevSlide,
    FirstSlide,
    LastSlide,
}

#[derive(Debug, Clone)]
pub enum ShapeKind {
    Sp(Box<Sp>),
    Pic(Box<Pic>),
    Group(Box<Group>),
    Table(Box<Table>),
    /// A DrawingML chart part's XML (c:chartSpace).
    Chart(String),
}

#[derive(Debug, Clone, Default)]
pub struct Sp {
    pub geom: Geometry,
    pub fill: Fill,
    pub line: Line,
    pub shadow: Option<Shadow>,
    pub text: Option<TextBody>,
    /// Written as a connector (p:cxnSp), which holds no text.
    pub connector: bool,
    /// Where the text goes in a custom geometry, as fractions of the
    /// shape (left, top, right, bottom); the whole shape when `None`.
    pub text_rect: Option<[f64; 4]>,
}

#[derive(Debug, Clone)]
pub struct Pic {
    pub media: usize,
    /// Fractions of the picture cut from the left, top, right, bottom,
    /// in 1/100000.
    pub crop: [i32; 4],
    pub geom: Geometry,
    pub line: Line,
    pub shadow: Option<Shadow>,
    /// 0 to 100000.
    pub alpha: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct Group {
    /// The children's coordinate space.
    pub child: Xfrm,
    pub shapes: Vec<Shape>,
}

#[derive(Debug, Clone, Default)]
pub struct Table {
    pub cols: Vec<Emu>,
    pub rows: Vec<Row>,
}

#[derive(Debug, Clone, Default)]
pub struct Row {
    pub h: Emu,
    pub cells: Vec<Cell>,
}

#[derive(Debug, Clone, Default)]
pub struct Cell {
    pub text: TextBody,
    pub fill: Fill,
    /// Left, right, top, bottom.
    pub borders: [Line; 4],
    pub grid_span: u32,
    pub row_span: u32,
    /// Covered by a cell to its left or above.
    pub h_merge: bool,
    pub v_merge: bool,
}

#[derive(Debug, Clone)]
pub enum Geometry {
    Preset {
        name: &'static str,
        /// Adjust values by guide name (adj, adj1...).
        adj: Vec<(&'static str, i64)>,
    },
    Custom(Vec<Path>),
}

impl Default for Geometry {
    fn default() -> Self {
        Geometry::Preset {
            name: "rect",
            adj: vec![],
        }
    }
}

impl Geometry {
    pub fn preset(name: &'static str) -> Geometry {
        Geometry::Preset { name, adj: vec![] }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Path {
    pub w: i64,
    pub h: i64,
    pub fill: bool,
    pub stroke: bool,
    pub cmds: Vec<PathCmd>,
}

#[derive(Debug, Clone, Copy)]
pub enum PathCmd {
    Move(i64, i64),
    Line(i64, i64),
    Cubic(i64, i64, i64, i64, i64, i64),
    Quad(i64, i64, i64, i64),
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Color {
    pub rgb: Rgb,
    /// 0 to 100000; `None` is opaque.
    pub alpha: Option<u32>,
}

impl Color {
    pub fn rgb(rgb: Rgb) -> Color {
        Color {
            rgb: rgb & 0xFF_FFFF,
            alpha: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum Fill {
    #[default]
    None,
    Solid(Color),
    Gradient(Gradient),
    Picture {
        media: usize,
        tile: bool,
    },
    Pattern {
        preset: &'static str,
        fg: Color,
        bg: Color,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Gradient {
    /// Position (0 to 100000) and colour.
    pub stops: Vec<(u32, Color)>,
    pub kind: GradientKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GradientKind {
    /// Angle in degrees, clockwise from left to right.
    Linear(f64),
    /// circle, rect or shape, with the focus rectangle (l, t, r, b) in
    /// 1/100000 of the shape.
    Path(&'static str, [i32; 4]),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Line {
    pub fill: Fill,
    pub width: Emu,
    /// ST_PresetLineDashVal, `None` for solid.
    pub dash: Option<&'static str>,
    pub cap: Option<&'static str>,
    pub join: Option<&'static str>,
    pub compound: Option<&'static str>,
    pub head: Option<Arrow>,
    pub tail: Option<Arrow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Arrow {
    /// triangle, stealth, diamond, oval, arrow.
    pub kind: &'static str,
    /// sm, med, lg.
    pub w: &'static str,
    pub len: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Shadow {
    pub color: Color,
    pub blur: Emu,
    pub dist: Emu,
    /// Degrees.
    pub dir: f64,
}

#[derive(Debug, Clone, Default)]
pub struct TextBody {
    pub body: BodyProps,
    pub paras: Vec<Paragraph>,
    /// Per-level defaults, written as the body's list style.
    pub levels: ListStyle,
}

#[derive(Debug, Clone)]
pub struct BodyProps {
    /// Left, top, right, bottom.
    pub insets: [Emu; 4],
    /// t, ctr, b.
    pub anchor: &'static str,
    pub anchor_ctr: bool,
    pub wrap: bool,
    /// vert, vert270, eaVert...
    pub vert: Option<&'static str>,
    pub autofit: Autofit,
    /// Text rotation in degrees.
    pub rot: f64,
    pub columns: u32,
}

impl Default for BodyProps {
    fn default() -> Self {
        BodyProps {
            insets: [91440, 45720, 91440, 45720],
            anchor: "t",
            anchor_ctr: false,
            wrap: true,
            vert: None,
            autofit: Autofit::None,
            rot: 0.0,
            columns: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Autofit {
    None,
    /// The shape grows with its text.
    Shape,
    /// The text shrinks: font scale and line spacing reduction, 1/1000 %.
    Normal(u32, u32),
}

#[derive(Debug, Clone, Default)]
pub struct Paragraph {
    pub props: ParaProps,
    pub runs: Vec<Run>,
    /// The paragraph mark's properties (an empty paragraph's height).
    pub end: RunProps,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParaProps {
    pub level: u8,
    /// l, ctr, r, just, dist.
    pub align: Option<&'static str>,
    pub margin: Option<Emu>,
    pub indent: Option<Emu>,
    pub line_spacing: Option<Spacing>,
    pub space_before: Option<Spacing>,
    pub space_after: Option<Spacing>,
    pub bullet: Option<Bullet>,
    pub tabs: Vec<(Emu, &'static str)>,
    pub default_tab: Option<Emu>,
    pub rtl: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Spacing {
    /// 1/1000 of a percent of the line: 100000 is single.
    Pct(i32),
    /// 1/100 of a point.
    Pts(i32),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Bullet {
    None,
    Char {
        ch: char,
        font: Option<String>,
        color: Option<Color>,
        /// 1/1000 of a percent of the text size.
        size: Option<u32>,
    },
    AutoNum {
        /// ST_TextAutonumberScheme.
        scheme: &'static str,
        start: u32,
        font: Option<String>,
        color: Option<Color>,
        size: Option<u32>,
    },
    /// A picture, by media index.
    Picture {
        media: usize,
        /// 1/1000 of a percent of the text size.
        size: Option<u32>,
    },
}

#[derive(Debug, Clone)]
pub struct Run {
    pub kind: RunKind,
    pub props: RunProps,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RunKind {
    Text(String),
    /// A line break within the paragraph.
    Break,
    /// A field: slidenum, datetime, datetime1... with its current text.
    Field(&'static str, String),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunProps {
    /// 1/100 of a point.
    pub size: Option<u32>,
    pub bold: Option<bool>,
    pub italic: Option<bool>,
    /// ST_TextUnderlineType: sng, dbl, none...
    pub underline: Option<&'static str>,
    /// sngStrike, dblStrike, noStrike.
    pub strike: Option<&'static str>,
    pub color: Option<Color>,
    pub font: Option<String>,
    pub ea_font: Option<String>,
    pub cs_font: Option<String>,
    pub sym_font: Option<String>,
    /// Superscript (positive) or subscript, 1/1000 of a percent.
    pub baseline: Option<i32>,
    /// all, small.
    pub caps: Option<&'static str>,
    /// Character spacing, 1/100 of a point.
    pub spacing: Option<i32>,
    pub shadow: Option<Shadow>,
    pub outline: Option<Line>,
    pub highlight: Option<Color>,
    pub link: Option<Link>,
    pub lang: Option<String>,
}

/// Paragraph and run defaults for each of the nine outline levels.
#[derive(Debug, Clone, Default)]
pub struct ListStyle {
    /// Up to nine, none until one is set. Nine inline are 6 KB, which every
    /// `TextBody` and `Sp` would take, on the stack of each function that
    /// builds a shape and again in the memory of each shape.
    pub levels: Vec<Option<(ParaProps, RunProps)>>,
}

impl ListStyle {
    pub fn is_empty(&self) -> bool {
        self.levels.iter().all(Option::is_none)
    }
}
