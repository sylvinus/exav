//! Non-graphical objects a drawing depends on.

use super::{Color, Handle, LineWeight, Vec2, Vec3};

/// A LAYOUT object: model space or a paper-space sheet, with its page setup.
#[derive(Clone, Debug, PartialEq)]
pub struct Layout {
    pub handle: Handle,
    pub name: String,
    /// Group 70: 1 PSLTSCALE, 2 LIMCHECK while this layout is current.
    pub flags: i16,
    pub tab_order: i16,
    pub limits_min: Vec2,
    pub limits_max: Vec2,
    pub insertion_base: Vec3,
    pub extents_min: Vec3,
    pub extents_max: Vec3,
    pub elevation: f64,
    pub ucs_origin: Vec3,
    pub ucs_x_axis: Vec3,
    pub ucs_y_axis: Vec3,
    /// The block record holding this layout's entities.
    pub block_record: Handle,
    pub last_viewport: Handle,
    pub plot: PlotSettings,
}

impl Default for Layout {
    fn default() -> Self {
        Layout {
            handle: Handle::NULL,
            name: String::new(),
            flags: 0,
            tab_order: 0,
            limits_min: Vec2::default(),
            limits_max: Vec2::new(12.0, 9.0),
            insertion_base: Vec3::default(),
            extents_min: Vec3::default(),
            extents_max: Vec3::default(),
            elevation: 0.0,
            ucs_origin: Vec3::default(),
            ucs_x_axis: Vec3::new(1.0, 0.0, 0.0),
            ucs_y_axis: Vec3::new(0.0, 1.0, 0.0),
            block_record: Handle::NULL,
            last_viewport: Handle::NULL,
            plot: PlotSettings::default(),
        }
    }
}

impl Layout {
    pub fn is_model(&self) -> bool {
        self.name.eq_ignore_ascii_case("Model")
    }
}

/// The page setup a layout carries (the AcDbPlotSettings subclass).
#[derive(Clone, Debug, PartialEq)]
pub struct PlotSettings {
    pub page_setup_name: String,
    pub plot_device: String,
    pub paper_size: String,
    pub plot_view: String,
    pub style_sheet: String,
    /// Unprintable margins in millimetres: left, bottom, right, top.
    pub margins: [f64; 4],
    /// Physical paper size in millimetres.
    pub paper_width: f64,
    pub paper_height: f64,
    pub origin: Vec2,
    pub window_min: Vec2,
    pub window_max: Vec2,
    /// Custom scale: paper units per drawing units.
    pub scale_numerator: f64,
    pub scale_denominator: f64,
    /// Group 70: 1 plot viewport borders, 16 use standard scale, 1024 model
    /// type...
    pub flags: i32,
    /// 0 inches, 1 millimetres, 2 pixels.
    pub paper_units: i16,
    /// 0 none, 1 90° counterclockwise, 2 upside down, 3 90° clockwise.
    pub rotation: i16,
    pub plot_type: i16,
    pub standard_scale_type: i16,
    pub standard_scale: f64,
    pub image_origin: Vec2,
}

impl Default for PlotSettings {
    fn default() -> Self {
        PlotSettings {
            page_setup_name: String::new(),
            plot_device: String::new(),
            paper_size: String::new(),
            plot_view: String::new(),
            style_sheet: String::new(),
            margins: [0.0; 4],
            paper_width: 0.0,
            paper_height: 0.0,
            origin: Vec2::default(),
            window_min: Vec2::default(),
            window_max: Vec2::default(),
            scale_numerator: 1.0,
            scale_denominator: 1.0,
            flags: 0,
            paper_units: 0,
            rotation: 0,
            plot_type: 0,
            standard_scale_type: 0,
            standard_scale: 1.0,
            image_origin: Vec2::default(),
        }
    }
}

/// A DICTIONARY (or ACDBDICTIONARYWDFLT): named references to objects.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Dictionary {
    pub handle: Handle,
    pub owner: Handle,
    pub hard_owner: bool,
    pub cloning: i16,
    pub entries: Vec<(String, Handle)>,
}

impl Dictionary {
    pub fn get(&self, name: &str) -> Option<Handle> {
        self.entries
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, h)| *h)
    }
}

/// A SORTENTSTABLE: the draw order DRAWORDER set for one block.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SortEntsTable {
    pub handle: Handle,
    pub block_record: Handle,
    /// Entity handle and the handle it sorts as.
    pub entries: Vec<(Handle, Handle)>,
}

/// An IMAGEDEF: the file a raster image shows.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ImageDef {
    pub handle: Handle,
    pub file_name: String,
    /// Pixels.
    pub size: Vec2,
    /// One pixel in drawing units.
    pub pixel_size: Vec2,
    pub loaded: bool,
    /// 0 none, 2 centimetres, 5 inches.
    pub resolution_units: i16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UnderlayKind {
    #[default]
    Pdf,
    Dwf,
    Dgn,
}

/// A PDFDEFINITION, DWFDEFINITION or DGNDEFINITION.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UnderlayDef {
    pub handle: Handle,
    pub kind: UnderlayKind,
    pub file_name: String,
    /// The page or sheet shown.
    pub name: String,
}

/// An MLINESTYLE.
#[derive(Clone, Debug, PartialEq)]
pub struct MLineStyle {
    pub handle: Handle,
    pub name: String,
    /// Group 70: 1 fill, 2 miters, 16/32/64 start caps, 256/512/1024 end
    /// caps.
    pub flags: i16,
    pub description: String,
    pub fill_color: Color,
    /// Radians.
    pub start_angle: f64,
    pub end_angle: f64,
    pub elements: Vec<MLineStyleElement>,
}

impl Default for MLineStyle {
    fn default() -> Self {
        MLineStyle {
            handle: Handle::NULL,
            name: String::new(),
            flags: 0,
            description: String::new(),
            fill_color: Color::ByLayer,
            start_angle: std::f64::consts::FRAC_PI_2,
            end_angle: std::f64::consts::FRAC_PI_2,
            elements: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MLineStyleElement {
    pub offset: f64,
    pub color: Color,
    pub linetype: String,
}

/// An MLEADERSTYLE, with what a renderer falls back to when a multileader
/// does not override it.
#[derive(Clone, Debug, PartialEq)]
pub struct MLeaderStyle {
    pub handle: Handle,
    pub name: String,
    /// Group 170: 0 none, 1 block, 2 MTEXT, 3 tolerance.
    pub content_type: i16,
    /// Group 173: 0 invisible, 1 straight, 2 spline.
    pub leader_line_type: i16,
    pub leader_line_color: Color,
    pub leader_linetype: Handle,
    pub leader_lineweight: LineWeight,
    pub landing: bool,
    pub landing_gap: f64,
    pub dogleg: bool,
    pub dogleg_length: f64,
    pub arrowhead: Handle,
    pub arrowhead_size: f64,
    pub text_style: Handle,
    pub text_left_attachment: i16,
    pub text_right_attachment: i16,
    pub text_angle_type: i16,
    pub text_alignment_type: i16,
    pub text_color: Color,
    pub text_height: f64,
    pub text_frame: bool,
    pub block: Handle,
    pub block_color: Color,
    pub block_scale: Vec3,
    /// Radians.
    pub block_rotation: f64,
    pub block_connection: i16,
    pub scale: f64,
}

impl Default for MLeaderStyle {
    fn default() -> Self {
        MLeaderStyle {
            handle: Handle::NULL,
            name: String::new(),
            content_type: 2,
            leader_line_type: 1,
            leader_line_color: Color::ByBlock,
            leader_linetype: Handle::NULL,
            leader_lineweight: LineWeight::ByBlock,
            landing: true,
            landing_gap: 0.09,
            dogleg: true,
            dogleg_length: 0.36,
            arrowhead: Handle::NULL,
            arrowhead_size: 0.18,
            text_style: Handle::NULL,
            text_left_attachment: 1,
            text_right_attachment: 1,
            text_angle_type: 1,
            text_alignment_type: 0,
            text_color: Color::ByBlock,
            text_height: 0.18,
            text_frame: false,
            block: Handle::NULL,
            block_color: Color::ByBlock,
            block_scale: Vec3::new(1.0, 1.0, 1.0),
            block_rotation: 0.0,
            block_connection: 0,
            scale: 1.0,
        }
    }
}
