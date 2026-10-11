//! Symbol table entries.

use super::{Color, Handle, LineWeight, Vec2, Vec3};

/// A LAYER table entry.
#[derive(Clone, Debug, PartialEq)]
pub struct Layer {
    pub handle: Handle,
    pub name: String,
    /// Group 70: 1 frozen, 2 frozen in new viewports, 4 locked, 16/32/64
    /// external reference state.
    pub flags: i16,
    /// Never ByLayer or ByBlock in a well-formed file.
    pub color: Color,
    /// The colour number was negative: the layer is off.
    pub off: bool,
    pub linetype: String,
    /// Group 290: false means never plotted.
    pub plot: bool,
    pub lineweight: LineWeight,
    pub plot_style: Handle,
    pub material: Handle,
    /// Opacity from the layer's `AcCmTransparency` extended data, 255 when
    /// absent.
    pub alpha: u8,
}

impl Default for Layer {
    fn default() -> Self {
        Layer {
            handle: Handle::NULL,
            name: String::new(),
            flags: 0,
            color: Color::Index(7),
            off: false,
            linetype: "Continuous".to_string(),
            plot: true,
            lineweight: LineWeight::Default,
            plot_style: Handle::NULL,
            material: Handle::NULL,
            alpha: 255,
        }
    }
}

impl Layer {
    pub fn is_frozen(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn is_locked(&self) -> bool {
        self.flags & 4 != 0
    }
}

/// An LTYPE table entry: a dash pattern, possibly stamping text or shapes
/// along the line.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Linetype {
    pub handle: Handle,
    pub name: String,
    pub flags: i16,
    pub description: String,
    /// Group 40, the sum of the absolute element lengths.
    pub pattern_length: f64,
    pub elements: Vec<LinetypeElement>,
}

/// One dash (positive length), gap (negative) or dot (zero) of a linetype.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LinetypeElement {
    pub length: f64,
    /// Group 74: 1 absolute rotation, 2 embedded text, 4 embedded shape.
    pub flags: i16,
    pub shape_number: i16,
    /// The STYLE entry the text or shape is drawn with.
    pub style: Handle,
    pub scale: f64,
    /// Radians, relative to the line unless `flags & 1`.
    pub rotation: f64,
    pub offset: Vec2,
    /// The embedded text, when `flags & 2`.
    pub text: String,
}

impl LinetypeElement {
    pub fn has_text(&self) -> bool {
        self.flags & 2 != 0
    }

    pub fn has_shape(&self) -> bool {
        self.flags & 4 != 0
    }

    pub fn absolute_rotation(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// A STYLE table entry: a text style, or a shape file load request.
#[derive(Clone, Debug, PartialEq)]
pub struct TextStyle {
    pub handle: Handle,
    pub name: String,
    /// Group 70: 1 shape file, 4 vertical text.
    pub flags: i16,
    /// Fixed text height, 0 when not fixed.
    pub height: f64,
    pub width_factor: f64,
    /// Radians.
    pub oblique: f64,
    /// Group 71: 2 mirrored in X, 4 upside down.
    pub generation: i16,
    pub last_height: f64,
    /// Primary font file, `txt`, `romans.shx`, `arial.ttf`...
    pub font_file: String,
    pub bigfont_file: String,
    /// The TrueType family name from the style's `ACAD` extended data, empty
    /// when absent.
    pub font_family: String,
    /// Pitch, family, charset, italic and bold flags from the same data.
    pub font_flags: i64,
}

impl Default for TextStyle {
    fn default() -> Self {
        TextStyle {
            handle: Handle::NULL,
            name: String::new(),
            flags: 0,
            height: 0.0,
            width_factor: 1.0,
            oblique: 0.0,
            generation: 0,
            last_height: 0.0,
            font_file: String::new(),
            bigfont_file: String::new(),
            font_family: String::new(),
            font_flags: 0,
        }
    }
}

impl TextStyle {
    pub fn is_shape_file(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// A DIMSTYLE table entry, with the variables a renderer uses for leaders
/// and arrowheads.
#[derive(Clone, Debug, PartialEq)]
pub struct DimStyle {
    pub handle: Handle,
    pub name: String,
    pub flags: i16,
    pub dimscale: f64,
    pub dimasz: f64,
    pub dimexo: f64,
    pub dimexe: f64,
    pub dimdle: f64,
    pub dimtsz: f64,
    pub dimtxt: f64,
    pub dimgap: f64,
    pub dimclrd: Color,
    pub dimclre: Color,
    pub dimclrt: Color,
    pub dimlwd: LineWeight,
    pub dimlwe: LineWeight,
    /// Text style (group 340).
    pub dimtxsty: Handle,
    /// Arrowhead blocks (groups 341 to 344).
    pub dimldrblk: Handle,
    pub dimblk: Handle,
    pub dimblk1: Handle,
    pub dimblk2: Handle,
}

impl Default for DimStyle {
    fn default() -> Self {
        DimStyle {
            handle: Handle::NULL,
            name: String::new(),
            flags: 0,
            dimscale: 1.0,
            dimasz: 0.18,
            dimexo: 0.0625,
            dimexe: 0.18,
            dimdle: 0.0,
            dimtsz: 0.0,
            dimtxt: 0.18,
            dimgap: 0.09,
            dimclrd: Color::ByBlock,
            dimclre: Color::ByBlock,
            dimclrt: Color::ByBlock,
            dimlwd: LineWeight::ByBlock,
            dimlwe: LineWeight::ByBlock,
            dimtxsty: Handle::NULL,
            dimldrblk: Handle::NULL,
            dimblk: Handle::NULL,
            dimblk1: Handle::NULL,
            dimblk2: Handle::NULL,
        }
    }
}

/// A VPORT table entry: a tiled model-space viewport, `*Active` being the
/// one the drawing was saved with.
#[derive(Clone, Debug, PartialEq)]
pub struct VPort {
    pub handle: Handle,
    pub name: String,
    pub flags: i16,
    /// Where on the screen, 0 to 1.
    pub lower_left: Vec2,
    pub upper_right: Vec2,
    /// View centre in display coordinates.
    pub center: Vec2,
    pub view_direction: Vec3,
    pub target: Vec3,
    /// View height in drawing units.
    pub height: f64,
    /// Width over height.
    pub aspect_ratio: f64,
    /// Radians.
    pub twist: f64,
}

impl Default for VPort {
    fn default() -> Self {
        VPort {
            handle: Handle::NULL,
            name: String::new(),
            flags: 0,
            lower_left: Vec2::default(),
            upper_right: Vec2::new(1.0, 1.0),
            center: Vec2::default(),
            view_direction: Vec3::Z,
            target: Vec3::default(),
            height: 1.0,
            aspect_ratio: 1.0,
            twist: 0.0,
        }
    }
}
