//! The drawing model.
//!
//! Shaped for drawing a file, not for editing or writing one: what a
//! renderer needs from the header, tables, blocks, layouts and objects, with
//! the DXF reference's names. Fields keep what the file stores, converted to
//! one unit per quantity (angles in radians, colours resolved from the ACI
//! and true colour groups), and leave interpretation (ByLayer resolution,
//! text formatting, alignment) to the renderer.

mod entity;
mod objects;
mod proxy;
mod tables;

pub use entity::*;
pub use objects::*;
pub use proxy::*;
pub use tables::*;

/// An object's handle: the hexadecimal number in group 5. Zero is no
/// object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Handle(pub u64);

impl Handle {
    pub const NULL: Handle = Handle(0);

    pub fn is_null(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Vec2 {
    pub x: f64,
    pub y: f64,
}

impl Vec2 {
    pub const fn new(x: f64, y: f64) -> Vec2 {
        Vec2 { x, y }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Vec3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vec3 {
    pub const fn new(x: f64, y: f64, z: f64) -> Vec3 {
        Vec3 { x, y, z }
    }

    /// The default extrusion direction, and the normal of a drawing's XY
    /// plane.
    pub const Z: Vec3 = Vec3::new(0.0, 0.0, 1.0);

    pub fn xy(self) -> Vec2 {
        Vec2::new(self.x, self.y)
    }
}

/// An entity or layer colour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Color {
    /// The entity's layer's colour (ACI 256).
    #[default]
    ByLayer,
    /// The colour of the block reference the entity is drawn through (ACI 0).
    ByBlock,
    /// An AutoCAD Color Index entry, 1 to 255.
    Index(u8),
    /// A true colour (group 420).
    Rgb(u8, u8, u8),
}

impl Color {
    /// From a group 62 value: 0 ByBlock, 256 ByLayer, 1-255 an index. A
    /// negative value is a layer turned off, with its colour as the absolute
    /// value; anything else out of range reads as ByLayer.
    pub fn from_aci(aci: i64) -> Color {
        match aci.unsigned_abs() {
            0 => Color::ByBlock,
            n @ 1..=255 => Color::Index(n as u8),
            _ => Color::ByLayer,
        }
    }

    /// From a group 420 value: `0x00RRGGBB`.
    pub fn from_rgb24(v: i64) -> Color {
        Color::Rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
    }

    /// From an `AcCmColor` raw value, as multileaders and their styles store
    /// colours: the top byte says how to read the rest.
    pub fn from_raw(v: i64) -> Color {
        let low = v & 0x00FF_FFFF;
        match (v >> 24) & 0xFF {
            0xC0 => Color::ByLayer,
            0xC1 => Color::ByBlock,
            0xC2 => Color::from_rgb24(low),
            0xC3 => Color::from_aci(low & 0xFF),
            _ => Color::ByLayer,
        }
    }
}

/// An entity's lineweight (group 370).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LineWeight {
    #[default]
    ByLayer,
    ByBlock,
    /// The drawing's default lineweight (`LWDEFAULT`).
    Default,
    /// Hundredths of a millimetre.
    Value(u16),
}

impl LineWeight {
    pub fn from_code(v: i64) -> LineWeight {
        match v {
            -1 => LineWeight::ByLayer,
            -2 => LineWeight::ByBlock,
            -3 => LineWeight::Default,
            0..=211 => LineWeight::Value(v as u16),
            // Out of the enumeration: the reference lists nothing above 211.
            _ => LineWeight::Default,
        }
    }
}

/// An entity's transparency (group 440).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Transparency {
    #[default]
    ByLayer,
    ByBlock,
    /// Opacity, 0 transparent to 255 opaque.
    Alpha(u8),
}

impl Transparency {
    /// From the stored 32-bit value: `0x01000000` ByBlock, `0x020000AA` an
    /// opacity `AA`, anything else ByLayer.
    pub fn from_code(v: i64) -> Transparency {
        if v & 0x0200_0000 != 0 {
            Transparency::Alpha(v as u8)
        } else if v & 0x0100_0000 != 0 {
            Transparency::ByBlock
        } else {
            Transparency::ByLayer
        }
    }
}

/// The release a file was saved as, from `$ACADVER`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    /// AC1009 and anything older.
    #[default]
    R12,
    R13,
    R14,
    R2000,
    R2004,
    R2007,
    R2010,
    R2013,
    R2018,
}

impl Version {
    pub fn from_acadver(s: &str) -> Version {
        match s.trim() {
            "AC1012" => Version::R13,
            "AC1014" => Version::R14,
            "AC1015" => Version::R2000,
            "AC1018" => Version::R2004,
            "AC1021" => Version::R2007,
            "AC1024" => Version::R2010,
            "AC1027" => Version::R2013,
            "AC1032" => Version::R2018,
            s if s.starts_with("AC1") && s > "AC1032" => Version::R2018,
            _ => Version::R12,
        }
    }

    /// From 2007 on strings are UTF-8 and `$DWGCODEPAGE` does not apply.
    pub fn is_unicode(self) -> bool {
        self >= Version::R2007
    }
}

/// The header variables a renderer reads. Absent ones take AutoCAD's
/// defaults for a new imperial drawing, as the DXF reference gives them.
#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    pub version: Version,
    /// `$ACADVER` as written, empty when absent.
    pub acadver: String,
    /// `$DWGCODEPAGE` as written, empty when absent.
    pub code_page: String,
    pub handle_seed: Handle,
    pub insbase: Vec3,
    pub extmin: Vec3,
    pub extmax: Vec3,
    pub limmin: Vec2,
    pub limmax: Vec2,
    pub pinsbase: Vec3,
    pub pextmin: Vec3,
    pub pextmax: Vec3,
    pub plimmin: Vec2,
    pub plimmax: Vec2,
    /// `$LTSCALE`, the global linetype scale.
    pub ltscale: f64,
    /// `$CELTSCALE`, the linetype scale new entities get.
    pub celtscale: f64,
    /// `$PSLTSCALE`: dashes in paper units through viewports.
    pub psltscale: bool,
    pub insunits: i16,
    /// `$MEASUREMENT`: 0 imperial, 1 metric.
    pub measurement: i16,
    pub lunits: i16,
    pub luprec: i16,
    pub textsize: f64,
    pub textstyle: String,
    pub clayer: String,
    pub dimstyle: String,
    pub dimscale: f64,
    pub dimasz: f64,
    pub dimtxt: f64,
    pub dimgap: f64,
    pub pdmode: i16,
    pub pdsize: f64,
    /// `$ANGBASE`, radians.
    pub angbase: f64,
    /// `$ANGDIR`: 1 clockwise.
    pub angdir: i16,
    pub tilemode: bool,
    pub lwdisplay: bool,
    pub fillmode: bool,
    pub mirrtext: bool,
}

impl Default for Header {
    fn default() -> Self {
        Header {
            version: Version::R12,
            acadver: String::new(),
            code_page: String::new(),
            handle_seed: Handle::NULL,
            insbase: Vec3::default(),
            extmin: Vec3::default(),
            extmax: Vec3::default(),
            limmin: Vec2::default(),
            limmax: Vec2::new(12.0, 9.0),
            pinsbase: Vec3::default(),
            pextmin: Vec3::default(),
            pextmax: Vec3::default(),
            plimmin: Vec2::default(),
            plimmax: Vec2::new(12.0, 9.0),
            ltscale: 1.0,
            celtscale: 1.0,
            psltscale: true,
            insunits: 0,
            measurement: 0,
            lunits: 2,
            luprec: 4,
            textsize: 0.2,
            textstyle: "STANDARD".to_string(),
            clayer: "0".to_string(),
            dimstyle: "STANDARD".to_string(),
            dimscale: 1.0,
            dimasz: 0.18,
            dimtxt: 0.18,
            dimgap: 0.09,
            pdmode: 0,
            pdsize: 0.0,
            angbase: 0.0,
            angdir: 0,
            tilemode: true,
            lwdisplay: false,
            fillmode: true,
            mirrtext: false,
        }
    }
}

/// The block record name every drawing keeps model space in.
pub const MODEL_SPACE: &str = "*Model_Space";
/// The block record of the active paper-space layout.
pub const PAPER_SPACE: &str = "*Paper_Space";

/// A block definition with its block record: a named list of entities drawn
/// wherever it is inserted. Model space and each layout's paper space are
/// blocks too.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Block {
    /// The BLOCK_RECORD table entry's handle, which entities name as their
    /// owner.
    pub record: Handle,
    /// The BLOCK entity's handle.
    pub handle: Handle,
    pub end_handle: Handle,
    pub name: String,
    /// Group 70: 1 anonymous, 2 has attribute definitions, 4 external
    /// reference, 8 overlay, 16 externally dependent, 32 resolved, 64
    /// referenced.
    pub flags: i16,
    pub base_point: Vec3,
    pub xref_path: String,
    pub description: String,
    pub layer: String,
    /// The LAYOUT object of a model or paper space block.
    pub layout: Handle,
    pub insert_units: i16,
    pub explodable: bool,
    pub scalable: bool,
    pub entities: Vec<Entity>,
}

impl Block {
    pub fn is_model_space(&self) -> bool {
        self.name.eq_ignore_ascii_case(MODEL_SPACE)
    }

    /// `*Paper_Space`, `*Paper_Space0`, `*Paper_Space1`...
    pub fn is_paper_space(&self) -> bool {
        self.name
            .get(..PAPER_SPACE.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(PAPER_SPACE))
    }

    pub fn is_xref(&self) -> bool {
        self.flags & 4 != 0
    }
}

/// Something the reader dropped or had to guess.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    pub kind: WarningKind,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WarningKind {
    /// The file ends inside a section or record.
    Truncated,
    /// A [`Limits`](super::Limits) bound was reached and data was dropped.
    LimitReached,
    /// A record or value that does not follow the format, skipped.
    Malformed,
    /// `$DWGCODEPAGE` names a code page this reader does not have; strings
    /// were read as Windows-1252.
    UnsupportedCodePage,
}

/// A whole drawing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Drawing {
    pub header: Header,
    pub layers: Vec<Layer>,
    pub linetypes: Vec<Linetype>,
    pub text_styles: Vec<TextStyle>,
    pub dim_styles: Vec<DimStyle>,
    pub vports: Vec<VPort>,
    /// Every block, model and paper space included, in table order.
    pub blocks: Vec<Block>,
    /// Model first, then paper-space layouts in tab order.
    pub layouts: Vec<Layout>,
    pub dictionaries: Vec<Dictionary>,
    pub sort_tables: Vec<SortEntsTable>,
    pub image_defs: Vec<ImageDef>,
    pub underlay_defs: Vec<UnderlayDef>,
    pub mline_styles: Vec<MLineStyle>,
    pub mleader_styles: Vec<MLeaderStyle>,
    /// The thumbnail the writer saved with the drawing, when it saved one
    /// a browser can show.
    pub preview: Option<Preview>,
    pub warnings: Vec<Warning>,
    /// Warnings past [`Limits::max_warnings`](super::Limits), counted only.
    pub warnings_dropped: usize,
}

/// A drawing's thumbnail, as a whole image file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    pub format: PreviewFormat,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreviewFormat {
    /// A BMP file: the device-independent bitmap DWG and DXF store, with
    /// the 14-byte file header they leave out put back.
    Bmp,
    Png,
}

impl PreviewFormat {
    pub fn mime(self) -> &'static str {
        match self {
            PreviewFormat::Bmp => "image/bmp",
            PreviewFormat::Png => "image/png",
        }
    }
}

impl Drawing {
    /// A block by name, ignoring ASCII case as AutoCAD does.
    pub fn block(&self, name: &str) -> Option<&Block> {
        self.blocks
            .iter()
            .find(|b| b.name.eq_ignore_ascii_case(name))
    }

    /// The block whose record has this handle.
    pub fn block_by_record(&self, record: Handle) -> Option<&Block> {
        if record.is_null() {
            return None;
        }
        self.blocks.iter().find(|b| b.record == record)
    }

    pub fn model_space(&self) -> Option<&Block> {
        self.block(MODEL_SPACE)
    }

    pub fn layer(&self, name: &str) -> Option<&Layer> {
        self.layers
            .iter()
            .find(|l| l.name.eq_ignore_ascii_case(name))
    }

    pub fn linetype(&self, name: &str) -> Option<&Linetype> {
        self.linetypes
            .iter()
            .find(|l| l.name.eq_ignore_ascii_case(name))
    }

    pub fn text_style(&self, name: &str) -> Option<&TextStyle> {
        self.text_styles
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
    }

    /// The root of the named object dictionary: the first dictionary of the
    /// OBJECTS section.
    pub fn root_dictionary(&self) -> Option<&Dictionary> {
        self.dictionaries.first()
    }

    pub fn dictionary(&self, handle: Handle) -> Option<&Dictionary> {
        if handle.is_null() {
            return None;
        }
        self.dictionaries.iter().find(|d| d.handle == handle)
    }

    /// Follow a path of entry names from the root dictionary, such as
    /// `["ACAD_LAYOUT", "Model"]`, to the handle it names.
    pub fn lookup(&self, path: &[&str]) -> Option<Handle> {
        let mut dict = self.root_dictionary()?;
        let (last, init) = path.split_last()?;
        for name in init {
            dict = self.dictionary(dict.get(name)?)?;
        }
        dict.get(last)
    }
}
