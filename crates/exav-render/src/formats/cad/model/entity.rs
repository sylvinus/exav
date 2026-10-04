//! Entities: the graphical objects of model space, paper space and blocks.

use super::{Color, Handle, LineWeight, ProxyGraphics, Transparency, UnderlayKind, Vec2, Vec3};

/// An entity: the properties every type shares, and its own data.
#[derive(Clone, Debug, PartialEq)]
pub struct Entity {
    pub handle: Handle,
    /// The block record (or, for an attribute, the insert) that owns it.
    pub owner: Handle,
    pub layer: String,
    /// `BYLAYER` when the file leaves it out, `BYBLOCK`, or a linetype name.
    pub linetype: String,
    pub color: Color,
    /// Colour book name (group 430), empty when none.
    pub color_name: String,
    pub lineweight: LineWeight,
    pub transparency: Transparency,
    pub linetype_scale: f64,
    pub invisible: bool,
    /// In paper space: group 67, or owned by a paper-space block.
    pub paper_space: bool,
    pub kind: EntityKind,
}

impl Default for Entity {
    fn default() -> Self {
        Entity {
            handle: Handle::NULL,
            owner: Handle::NULL,
            layer: "0".to_string(),
            linetype: "BYLAYER".to_string(),
            color: Color::ByLayer,
            color_name: String::new(),
            lineweight: LineWeight::ByLayer,
            transparency: Transparency::ByLayer,
            linetype_scale: 1.0,
            invisible: false,
            paper_space: false,
            kind: EntityKind::Unknown(Unknown::default()),
        }
    }
}

impl Entity {
    /// The DXF type name of the entity.
    pub fn type_name(&self) -> &str {
        self.kind.type_name()
    }
}

/// An entity's own data. The types drawings hold by the hundred thousand
/// (lines, arcs, polylines...) are inline; the larger ones are boxed, so
/// that every entity does not take the size of a multileader.
#[derive(Clone, Debug, PartialEq)]
pub enum EntityKind {
    Arc(Arc),
    Attribute(Box<Attribute>),
    AttributeDefinition(Box<Attribute>),
    Circle(Circle),
    Dimension(Box<Dimension>),
    Ellipse(Ellipse),
    Face3D(Face3D),
    Hatch(Box<Hatch>),
    Helix(Box<Helix>),
    Image(Box<Image>),
    Insert(Box<Insert>),
    Leader(Box<Leader>),
    Line(Line),
    LwPolyline(LwPolyline),
    MLine(Box<MLine>),
    MText(Box<MText>),
    MultiLeader(Box<MultiLeader>),
    Ole2Frame(Ole2Frame),
    Point(Point),
    Polyline(Polyline),
    Ray(Ray),
    Shape(Shape),
    Solid(Quad),
    Spline(Box<Spline>),
    Table(Box<Table>),
    Text(Box<Text>),
    Trace(Quad),
    Underlay(Box<Underlay>),
    Viewport(Box<Viewport>),
    Wipeout(Box<Image>),
    XLine(Ray),
    /// Any other type: kept with its common properties so it can be counted.
    Unknown(Unknown),
}

impl EntityKind {
    pub fn type_name(&self) -> &str {
        match self {
            EntityKind::Arc(_) => "ARC",
            EntityKind::Attribute(_) => "ATTRIB",
            EntityKind::AttributeDefinition(_) => "ATTDEF",
            EntityKind::Circle(_) => "CIRCLE",
            EntityKind::Dimension(_) => "DIMENSION",
            EntityKind::Ellipse(_) => "ELLIPSE",
            EntityKind::Face3D(_) => "3DFACE",
            EntityKind::Hatch(_) => "HATCH",
            EntityKind::Helix(_) => "HELIX",
            EntityKind::Image(_) => "IMAGE",
            EntityKind::Insert(_) => "INSERT",
            EntityKind::Leader(_) => "LEADER",
            EntityKind::Line(_) => "LINE",
            EntityKind::LwPolyline(_) => "LWPOLYLINE",
            EntityKind::MLine(_) => "MLINE",
            EntityKind::MText(_) => "MTEXT",
            EntityKind::MultiLeader(_) => "MULTILEADER",
            EntityKind::Ole2Frame(_) => "OLE2FRAME",
            EntityKind::Point(_) => "POINT",
            EntityKind::Polyline(_) => "POLYLINE",
            EntityKind::Ray(_) => "RAY",
            EntityKind::Shape(_) => "SHAPE",
            EntityKind::Solid(_) => "SOLID",
            EntityKind::Spline(_) => "SPLINE",
            EntityKind::Table(_) => "ACAD_TABLE",
            EntityKind::Text(_) => "TEXT",
            EntityKind::Trace(_) => "TRACE",
            EntityKind::Underlay(u) => match u.kind {
                UnderlayKind::Pdf => "PDFUNDERLAY",
                UnderlayKind::Dwf => "DWFUNDERLAY",
                UnderlayKind::Dgn => "DGNUNDERLAY",
            },
            EntityKind::Viewport(_) => "VIEWPORT",
            EntityKind::Wipeout(_) => "WIPEOUT",
            EntityKind::XLine(_) => "XLINE",
            EntityKind::Unknown(u) => &u.type_name,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Unknown {
    pub type_name: String,
    /// The proxy graphics the entity was saved with: DWG's graphics of the
    /// common entity data, DXF's groups 92 (160 from 2010) and 310 of
    /// AcDbEntity, or of AcDbProxyEntity (R13: AcDbZombieEntity) for
    /// ACAD_PROXY_ENTITY.
    pub graphics: Option<Box<ProxyGraphics>>,
}

impl Unknown {
    /// Whether the type is an application's custom entity: ACAD_PROXY_ENTITY,
    /// or a type that is not one of AutoCAD's own (TArch's TCH_WALL, Civil
    /// 3D's AECC_*...).
    pub fn is_custom(&self) -> bool {
        is_custom_type(&self.type_name)
    }
}

/// [`Unknown::is_custom`] for a DXF type name.
pub fn is_custom_type(name: &str) -> bool {
    // AutoCAD's types the model does not read: those of the DXF reference's
    // ENTITIES section (2012), and built-in classes of later releases.
    const AUTOCAD: &[&str] = &[
        "3DSOLID",
        "BODY",
        "REGION",
        "SURFACE",
        "EXTRUDEDSURFACE",
        "LOFTEDSURFACE",
        "REVOLVEDSURFACE",
        "SWEPTSURFACE",
        "PLANESURFACE",
        "NURBSURFACE",
        "MESH",
        "LIGHT",
        "SUN",
        "SECTION",
        "SECTIONOBJECT",
        "TOLERANCE",
        "OLEFRAME",
        "SEQEND",
        "VERTEX",
        "CAMERA",
        "GEOPOSITIONMARKER",
        "POINTCLOUD",
        "POINTCLOUDEX",
    ];
    name.eq_ignore_ascii_case("ACAD_PROXY_ENTITY")
        || !(name.is_empty()
            || name.starts_with("type ")
            || AUTOCAD.iter().any(|t| t.eq_ignore_ascii_case(name)))
}

/// Thickness and extrusion direction, which most planar types carry.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Plane {
    pub thickness: f64,
    /// The normal of the entity's object coordinate system.
    pub extrusion: Vec3,
}

impl Default for Plane {
    fn default() -> Self {
        Plane {
            thickness: 0.0,
            extrusion: Vec3::Z,
        }
    }
}

/// LINE, in world coordinates.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Line {
    pub start: Vec3,
    pub end: Vec3,
    pub plane: Plane,
}

/// POINT, in world coordinates.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Point {
    pub location: Vec3,
    /// Radians: the UCS X axis when the point was drawn, for `PDMODE` shapes.
    pub x_axis_angle: f64,
    pub plane: Plane,
}

/// CIRCLE, centre in object coordinates.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Circle {
    pub center: Vec3,
    pub radius: f64,
    pub plane: Plane,
}

/// ARC, centre in object coordinates, angles in radians counterclockwise.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Arc {
    pub center: Vec3,
    pub radius: f64,
    pub start_angle: f64,
    pub end_angle: f64,
    pub plane: Plane,
}

/// ELLIPSE, in world coordinates.
#[derive(Clone, Debug, PartialEq)]
pub struct Ellipse {
    pub center: Vec3,
    /// The major axis' end point, relative to the centre.
    pub major_axis: Vec3,
    pub extrusion: Vec3,
    /// Minor over major axis length.
    pub ratio: f64,
    /// Parameters, radians; 0 to 2π for a full ellipse.
    pub start_param: f64,
    pub end_param: f64,
}

impl Default for Ellipse {
    fn default() -> Self {
        Ellipse {
            center: Vec3::default(),
            major_axis: Vec3::new(1.0, 0.0, 0.0),
            extrusion: Vec3::Z,
            ratio: 1.0,
            start_param: 0.0,
            end_param: std::f64::consts::TAU,
        }
    }
}

/// SPLINE (also the curve inside a HELIX), in world coordinates.
#[derive(Clone, Debug, PartialEq)]
pub struct Spline {
    pub extrusion: Vec3,
    /// Group 70: 1 closed, 2 periodic, 4 rational, 8 planar, 16 linear.
    pub flags: i16,
    pub degree: i16,
    pub knots: Vec<f64>,
    pub control_points: Vec<Vec3>,
    /// Empty when every weight is 1.
    pub weights: Vec<f64>,
    pub fit_points: Vec<Vec3>,
    pub start_tangent: Option<Vec3>,
    pub end_tangent: Option<Vec3>,
    pub knot_tolerance: f64,
    pub control_point_tolerance: f64,
    pub fit_tolerance: f64,
}

impl Default for Spline {
    fn default() -> Self {
        Spline {
            extrusion: Vec3::Z,
            flags: 0,
            degree: 3,
            knots: Vec::new(),
            control_points: Vec::new(),
            weights: Vec::new(),
            fit_points: Vec::new(),
            start_tangent: None,
            end_tangent: None,
            knot_tolerance: 1e-7,
            control_point_tolerance: 1e-7,
            fit_tolerance: 1e-10,
        }
    }
}

impl Spline {
    pub fn is_closed(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// LWPOLYLINE, vertices in object coordinates.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LwPolyline {
    /// Group 70: 1 closed, 128 continuous linetype generation.
    pub flags: i16,
    pub constant_width: f64,
    pub elevation: f64,
    pub plane: Plane,
    pub vertices: Vec<LwVertex>,
}

impl LwPolyline {
    pub fn is_closed(&self) -> bool {
        self.flags & 1 != 0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LwVertex {
    pub point: Vec2,
    pub start_width: f64,
    pub end_width: f64,
    /// Tangent of a quarter of the arc's included angle; negative clockwise.
    pub bulge: f64,
}

/// What a POLYLINE is, from its flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolylineKind {
    /// Vertices in object coordinates, with bulges and widths.
    Polyline2D,
    /// Vertices in world coordinates.
    Polyline3D,
    /// An M by N grid of vertices.
    PolygonMesh,
    /// Vertices, then faces that index them.
    PolyfaceMesh,
}

/// POLYLINE with its VERTEX entities (the closing SEQEND is not kept).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Polyline {
    /// Group 70: 1 closed (in M), 2 curve fit, 4 spline fit, 8 3D, 16 mesh,
    /// 32 closed in N, 64 polyface, 128 continuous linetype generation.
    pub flags: i16,
    pub elevation: f64,
    pub default_start_width: f64,
    pub default_end_width: f64,
    /// Mesh vertex counts; for a polyface, vertex and face counts.
    pub m_count: i16,
    pub n_count: i16,
    pub m_density: i16,
    pub n_density: i16,
    /// Group 75: 0 none, 5 quadratic, 6 cubic B-spline, 8 Bezier.
    pub curve_type: i16,
    pub plane: Plane,
    pub vertices: Vec<Vertex>,
}

impl Polyline {
    pub fn kind(&self) -> PolylineKind {
        if self.flags & 64 != 0 {
            PolylineKind::PolyfaceMesh
        } else if self.flags & 16 != 0 {
            PolylineKind::PolygonMesh
        } else if self.flags & 8 != 0 {
            PolylineKind::Polyline3D
        } else {
            PolylineKind::Polyline2D
        }
    }

    pub fn is_closed(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// A POLYLINE's VERTEX.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Vertex {
    pub handle: Handle,
    pub location: Vec3,
    pub start_width: f64,
    pub end_width: f64,
    pub bulge: f64,
    /// Group 70: 1 curve-fit extra, 2 has tangent, 8 spline-fit extra, 16
    /// spline frame control point, 32 3D, 64 mesh, 128 polyface.
    pub flags: i16,
    /// Curve fit tangent direction, radians.
    pub tangent: f64,
    /// A polyface face's vertex indices, from 1; negative hides the edge
    /// starting there, 0 ends the face.
    pub indices: [i32; 4],
}

/// SOLID and TRACE: four corners in object coordinates, in the order the
/// file stores them (the third and fourth swapped relative to a polygon).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Quad {
    pub corners: [Vec3; 4],
    pub plane: Plane,
}

/// 3DFACE, in world coordinates.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Face3D {
    pub corners: [Vec3; 4],
    /// Group 70: bits 1, 2, 4, 8 hide the first to fourth edge.
    pub invisible_edges: i16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HAlign {
    #[default]
    Left,
    Center,
    Right,
    Aligned,
    Middle,
    Fit,
}

impl HAlign {
    pub fn from_code(v: i64) -> HAlign {
        match v {
            1 => HAlign::Center,
            2 => HAlign::Right,
            3 => HAlign::Aligned,
            4 => HAlign::Middle,
            5 => HAlign::Fit,
            _ => HAlign::Left,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VAlign {
    #[default]
    Baseline,
    Bottom,
    Middle,
    Top,
}

impl VAlign {
    pub fn from_code(v: i64) -> VAlign {
        match v {
            1 => VAlign::Bottom,
            2 => VAlign::Middle,
            3 => VAlign::Top,
            _ => VAlign::Baseline,
        }
    }
}

/// TEXT, and the text part of an attribute. Points in object coordinates.
#[derive(Clone, Debug, PartialEq)]
pub struct Text {
    /// The first alignment point.
    pub insertion: Vec3,
    /// The second alignment point (group 11), which places the text unless
    /// the alignment is left and baseline.
    pub alignment_point: Option<Vec3>,
    pub height: f64,
    pub value: String,
    /// Radians.
    pub rotation: f64,
    pub width_factor: f64,
    /// Radians.
    pub oblique: f64,
    pub style: String,
    /// Group 71: 2 mirrored in X, 4 upside down.
    pub generation: i16,
    pub h_align: HAlign,
    pub v_align: VAlign,
    pub plane: Plane,
}

impl Default for Text {
    fn default() -> Self {
        Text {
            insertion: Vec3::default(),
            alignment_point: None,
            height: 1.0,
            value: String::new(),
            rotation: 0.0,
            width_factor: 1.0,
            oblique: 0.0,
            style: "STANDARD".to_string(),
            generation: 0,
            h_align: HAlign::Left,
            v_align: VAlign::Baseline,
            plane: Plane::default(),
        }
    }
}

/// ATTRIB (an insert's attribute value) and ATTDEF (a block's attribute
/// definition).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Attribute {
    pub text: Text,
    pub tag: String,
    /// ATTDEF only.
    pub prompt: String,
    /// Group 70: 1 invisible, 2 constant, 4 verify, 8 preset.
    pub flags: i16,
    pub field_length: i16,
    pub lock_position: bool,
    /// A multiline attribute's text (group 101 embedded MTEXT).
    pub mtext: Option<Box<MText>>,
}

impl Attribute {
    pub fn is_invisible(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn is_constant(&self) -> bool {
        self.flags & 2 != 0
    }
}

/// INSERT, MINSERT when it has rows or columns. Insertion point in object
/// coordinates.
#[derive(Clone, Debug, PartialEq)]
pub struct Insert {
    pub block_name: String,
    pub insertion: Vec3,
    pub scale: Vec3,
    /// Radians.
    pub rotation: f64,
    pub columns: u16,
    pub rows: u16,
    pub column_spacing: f64,
    pub row_spacing: f64,
    pub extrusion: Vec3,
    /// The ATTRIB entities that follow it.
    pub attributes: Vec<Entity>,
}

impl Default for Insert {
    fn default() -> Self {
        Insert {
            block_name: String::new(),
            insertion: Vec3::default(),
            scale: Vec3::new(1.0, 1.0, 1.0),
            rotation: 0.0,
            columns: 1,
            rows: 1,
            column_spacing: 0.0,
            row_spacing: 0.0,
            extrusion: Vec3::Z,
            attributes: Vec::new(),
        }
    }
}

/// MTEXT columns (2007 and later).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MTextColumns {
    /// Group 75: 0 none, 1 static, 2 dynamic.
    pub kind: i16,
    pub count: i16,
    pub flow_reversed: bool,
    pub auto_height: bool,
    pub width: f64,
    pub gutter: f64,
    pub heights: Vec<f64>,
}

/// MTEXT. The text keeps its inline formatting codes.
#[derive(Clone, Debug, PartialEq)]
pub struct MText {
    pub insertion: Vec3,
    /// Character height.
    pub height: f64,
    /// Width the text wraps at; 0 for no wrapping.
    pub reference_width: f64,
    /// Group 46.
    pub defined_height: f64,
    /// Group 71: 1 top left ... 9 bottom right.
    pub attachment: i16,
    /// Group 72: 1 left to right, 3 top to bottom, 5 by style.
    pub drawing_direction: i16,
    pub style: String,
    pub extrusion: Vec3,
    /// The X axis direction (group 11), which wins over `rotation` when
    /// present.
    pub x_direction: Option<Vec3>,
    /// Radians (group 50).
    pub rotation: f64,
    pub line_spacing_style: i16,
    pub line_spacing_factor: f64,
    pub text: String,
    /// Group 90: 0 off, 1 colour, 2 drawing background, 16 text frame.
    pub background_fill: i32,
    pub background_color: Color,
    pub background_scale: f64,
    pub columns: Option<MTextColumns>,
}

impl Default for MText {
    fn default() -> Self {
        MText {
            insertion: Vec3::default(),
            height: 1.0,
            reference_width: 0.0,
            defined_height: 0.0,
            attachment: 1,
            drawing_direction: 1,
            style: "STANDARD".to_string(),
            extrusion: Vec3::Z,
            x_direction: None,
            rotation: 0.0,
            line_spacing_style: 1,
            line_spacing_factor: 1.0,
            text: String::new(),
            background_fill: 0,
            background_color: Color::ByLayer,
            background_scale: 1.5,
            columns: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DimensionKind {
    /// Rotated, horizontal or vertical.
    #[default]
    Linear,
    Aligned,
    Angular,
    Diameter,
    Radius,
    Angular3Point,
    Ordinate,
}

impl DimensionKind {
    pub fn from_code(v: i64) -> DimensionKind {
        match v & 7 {
            1 => DimensionKind::Aligned,
            2 => DimensionKind::Angular,
            3 => DimensionKind::Diameter,
            4 => DimensionKind::Radius,
            5 => DimensionKind::Angular3Point,
            6 => DimensionKind::Ordinate,
            _ => DimensionKind::Linear,
        }
    }
}

/// DIMENSION. What it looks like is the anonymous block it names.
#[derive(Clone, Debug, PartialEq)]
pub struct Dimension {
    pub kind: DimensionKind,
    /// Group 70 as stored: the kind in the low bits, 32 block used by this
    /// dimension only, 64 ordinate X, 128 user-placed text.
    pub flags: i16,
    pub block_name: String,
    pub style: String,
    /// Group 10, world coordinates.
    pub definition_point: Vec3,
    /// Group 11, object coordinates.
    pub text_midpoint: Vec3,
    /// Group 12: where the block is inserted, object coordinates.
    pub insertion_point: Vec3,
    /// Groups 13 to 15 (world) and 16 (object): their meaning depends on the
    /// kind.
    pub point13: Vec3,
    pub point14: Vec3,
    pub point15: Vec3,
    pub point16: Vec3,
    pub attachment: i16,
    pub line_spacing_style: i16,
    pub line_spacing_factor: f64,
    /// The measured value (group 42).
    pub measurement: f64,
    pub text: String,
    /// Radians.
    pub text_rotation: f64,
    pub horizontal_direction: f64,
    /// Linear: the dimension line's angle (group 50), radians.
    pub angle: f64,
    /// Linear: extension line obliquing (group 52), radians.
    pub oblique: f64,
    /// Radius and diameter: leader length (group 40).
    pub leader_length: f64,
    pub extrusion: Vec3,
    /// The block's insertion scale and rotation. A DXF file does not store
    /// them (the block is in place at scale one); a DWG does.
    pub insertion_scale: Vec3,
    pub insertion_rotation: f64,
}

impl Default for Dimension {
    fn default() -> Self {
        Dimension {
            kind: DimensionKind::Linear,
            flags: 0,
            block_name: String::new(),
            style: "STANDARD".to_string(),
            definition_point: Vec3::default(),
            text_midpoint: Vec3::default(),
            insertion_point: Vec3::default(),
            point13: Vec3::default(),
            point14: Vec3::default(),
            point15: Vec3::default(),
            point16: Vec3::default(),
            attachment: 5,
            line_spacing_style: 1,
            line_spacing_factor: 1.0,
            measurement: 0.0,
            text: String::new(),
            text_rotation: 0.0,
            horizontal_direction: 0.0,
            angle: 0.0,
            oblique: 0.0,
            leader_length: 0.0,
            extrusion: Vec3::Z,
            insertion_scale: Vec3::new(1.0, 1.0, 1.0),
            insertion_rotation: 0.0,
        }
    }
}

/// LEADER, the pre-2007 leader. Vertices in world coordinates.
#[derive(Clone, Debug, PartialEq)]
pub struct Leader {
    pub style: String,
    pub arrowhead: bool,
    /// Group 72: 0 straight, 1 spline.
    pub path_type: i16,
    /// Group 73: 0 text, 1 tolerance, 2 block, 3 no annotation.
    pub creation: i16,
    pub hookline_direction: i16,
    pub hookline: bool,
    pub text_height: f64,
    pub text_width: f64,
    pub vertices: Vec<Vec3>,
    /// Group 77: colour used when DIMCLRD is ByBlock.
    pub color: Color,
    pub annotation: Handle,
    pub extrusion: Vec3,
    pub horizontal_direction: Vec3,
    pub block_offset: Vec3,
    pub annotation_offset: Vec3,
}

impl Default for Leader {
    fn default() -> Self {
        Leader {
            style: "STANDARD".to_string(),
            arrowhead: true,
            path_type: 0,
            creation: 3,
            hookline_direction: 0,
            hookline: false,
            text_height: 0.0,
            text_width: 0.0,
            vertices: Vec::new(),
            color: Color::ByLayer,
            annotation: Handle::NULL,
            extrusion: Vec3::Z,
            horizontal_direction: Vec3::new(1.0, 0.0, 0.0),
            block_offset: Vec3::default(),
            annotation_offset: Vec3::default(),
        }
    }
}

/// One leader line of a multileader.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MLeaderLine {
    pub vertices: Vec<Vec3>,
    pub index: i32,
}

/// One leader (a root, in AutoCAD's terms) of a multileader: its lines, and
/// the landing that joins them to the content.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MLeaderRoot {
    /// The last leader line point, where the landing starts.
    pub connection_point: Vec3,
    /// The landing's direction.
    pub direction: Vec3,
    pub has_connection_point: bool,
    pub has_direction: bool,
    pub branch_index: i32,
    /// The landing's length.
    pub dogleg_length: f64,
    pub lines: Vec<MLeaderLine>,
    /// Group 271 (2010 and later): 0 horizontal, 1 vertical.
    pub attachment_direction: i16,
}

/// The geometry and content of a multileader (its CONTEXT_DATA).
#[derive(Clone, Debug, PartialEq)]
pub struct MLeaderContext {
    pub scale: f64,
    pub content_base: Vec3,
    pub text_height: f64,
    pub arrowhead_size: f64,
    pub landing_gap: f64,
    pub has_text: bool,
    pub text: String,
    pub text_normal: Vec3,
    pub text_style: Handle,
    pub text_location: Vec3,
    pub text_direction: Vec3,
    /// Radians.
    pub text_rotation: f64,
    pub text_width: f64,
    pub text_boundary_height: f64,
    pub line_spacing_factor: f64,
    pub line_spacing_style: i16,
    pub text_color: Color,
    /// Group 171: MTEXT attachment, 1 top left ... 9 bottom right.
    pub text_attachment: i16,
    pub text_flow_direction: i16,
    pub has_block: bool,
    pub block: Handle,
    pub block_normal: Vec3,
    pub block_position: Vec3,
    pub block_scale: Vec3,
    /// Radians.
    pub block_rotation: f64,
    pub block_color: Color,
    /// The block's 4 by 4 transform, row by row, when stored.
    pub block_transform: Vec<f64>,
    pub plane_origin: Vec3,
    pub plane_x_axis: Vec3,
    pub plane_y_axis: Vec3,
    pub plane_normal_reversed: bool,
    pub leaders: Vec<MLeaderRoot>,
}

impl Default for MLeaderContext {
    fn default() -> Self {
        MLeaderContext {
            scale: 1.0,
            content_base: Vec3::default(),
            text_height: 0.0,
            arrowhead_size: 0.0,
            landing_gap: 0.0,
            has_text: false,
            text: String::new(),
            text_normal: Vec3::Z,
            text_style: Handle::NULL,
            text_location: Vec3::default(),
            text_direction: Vec3::new(1.0, 0.0, 0.0),
            text_rotation: 0.0,
            text_width: 0.0,
            text_boundary_height: 0.0,
            line_spacing_factor: 1.0,
            line_spacing_style: 1,
            text_color: Color::ByBlock,
            text_attachment: 1,
            text_flow_direction: 1,
            has_block: false,
            block: Handle::NULL,
            block_normal: Vec3::Z,
            block_position: Vec3::default(),
            block_scale: Vec3::new(1.0, 1.0, 1.0),
            block_rotation: 0.0,
            block_color: Color::ByBlock,
            block_transform: Vec::new(),
            plane_origin: Vec3::default(),
            plane_x_axis: Vec3::new(1.0, 0.0, 0.0),
            plane_y_axis: Vec3::new(0.0, 1.0, 0.0),
            plane_normal_reversed: false,
            leaders: Vec::new(),
        }
    }
}

/// A multileader's attribute value for its block content.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MLeaderAttribute {
    pub definition: Handle,
    pub index: i16,
    pub width: f64,
    pub text: String,
}

/// MULTILEADER (MLEADER).
#[derive(Clone, Debug, PartialEq)]
pub struct MultiLeader {
    pub style: Handle,
    pub property_overrides: i64,
    /// Group 170: 0 invisible, 1 straight, 2 spline.
    pub leader_line_type: i16,
    pub leader_line_color: Color,
    pub leader_linetype: Handle,
    pub leader_lineweight: LineWeight,
    pub landing: bool,
    pub dogleg: bool,
    pub dogleg_length: f64,
    pub arrowhead: Handle,
    pub arrowhead_size: f64,
    /// Group 172: 0 none, 1 block, 2 MTEXT, 3 tolerance.
    pub content_type: i16,
    pub text_style: Handle,
    pub text_left_attachment: i16,
    pub text_right_attachment: i16,
    pub text_angle_type: i16,
    pub text_alignment_type: i16,
    pub text_color: Color,
    pub text_frame: bool,
    pub block: Handle,
    pub block_color: Color,
    pub block_scale: Vec3,
    /// Radians.
    pub block_rotation: f64,
    pub block_connection: i16,
    pub block_attributes: Vec<MLeaderAttribute>,
    pub text_attachment_point: i16,
    pub context: MLeaderContext,
}

impl Default for MultiLeader {
    fn default() -> Self {
        MultiLeader {
            style: Handle::NULL,
            property_overrides: 0,
            leader_line_type: 1,
            leader_line_color: Color::ByBlock,
            leader_linetype: Handle::NULL,
            leader_lineweight: LineWeight::ByBlock,
            landing: true,
            dogleg: true,
            dogleg_length: 0.0,
            arrowhead: Handle::NULL,
            arrowhead_size: 0.0,
            content_type: 2,
            text_style: Handle::NULL,
            text_left_attachment: 1,
            text_right_attachment: 1,
            text_angle_type: 1,
            text_alignment_type: 0,
            text_color: Color::ByBlock,
            text_frame: false,
            block: Handle::NULL,
            block_color: Color::ByBlock,
            block_scale: Vec3::new(1.0, 1.0, 1.0),
            block_rotation: 0.0,
            block_connection: 0,
            block_attributes: Vec::new(),
            text_attachment_point: 1,
            context: MLeaderContext::default(),
        }
    }
}

/// One element's parameters at one MLINE vertex.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MLineElement {
    /// Group 41: the offset along the miter, then where the element's
    /// pieces start and stop.
    pub parameters: Vec<f64>,
    pub fill_parameters: Vec<f64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MLineVertex {
    pub position: Vec3,
    pub direction: Vec3,
    pub miter: Vec3,
    pub elements: Vec<MLineElement>,
}

/// MLINE, in world coordinates.
#[derive(Clone, Debug, PartialEq)]
pub struct MLine {
    pub style_name: String,
    pub style: Handle,
    pub scale: f64,
    /// Group 70: 0 top, 1 zero, 2 bottom.
    pub justification: i16,
    /// Group 71: 1 has vertices, 2 closed, 4 no start caps, 8 no end caps.
    pub flags: i16,
    pub style_element_count: i16,
    pub start: Vec3,
    pub extrusion: Vec3,
    pub vertices: Vec<MLineVertex>,
}

impl Default for MLine {
    fn default() -> Self {
        MLine {
            style_name: String::new(),
            style: Handle::NULL,
            scale: 1.0,
            justification: 0,
            flags: 0,
            style_element_count: 0,
            start: Vec3::default(),
            extrusion: Vec3::Z,
            vertices: Vec::new(),
        }
    }
}

impl MLine {
    pub fn is_closed(&self) -> bool {
        self.flags & 2 != 0
    }
}

/// A hatch boundary edge, in object coordinates. Angles in radians, as the
/// file stores them (degrees converted).
#[derive(Clone, Debug, PartialEq)]
pub enum Edge {
    Line {
        start: Vec2,
        end: Vec2,
    },
    Arc {
        center: Vec2,
        radius: f64,
        start_angle: f64,
        end_angle: f64,
        counter_clockwise: bool,
    },
    /// `start_angle` and `end_angle` are DXF's 50 and 51: the angles of the
    /// end points from the major axis, not the ellipse's parameters there
    /// (a DWG stores the parameters: [`ellipse_angle`]).
    Ellipse {
        center: Vec2,
        /// End of the major axis, relative to the centre.
        major_axis: Vec2,
        ratio: f64,
        start_angle: f64,
        end_angle: f64,
        counter_clockwise: bool,
    },
    Spline {
        degree: i32,
        rational: bool,
        periodic: bool,
        knots: Vec<f64>,
        control_points: Vec<Vec2>,
        /// Empty when not rational.
        weights: Vec<f64>,
        fit_points: Vec<Vec2>,
        start_tangent: Option<Vec2>,
        end_tangent: Option<Vec2>,
    },
}

/// The angle from the major axis of the point at parameter `p` of an
/// ellipse whose minor axis is `ratio` times its major one, in the same
/// turn as `p` (so 2 pi stays 2 pi). The two are the same on the axes.
pub fn ellipse_angle(p: f64, ratio: f64) -> f64 {
    same_turn((ratio * p.sin()).atan2(p.cos()), p)
}

/// The parameter of the point at angle `a` from the major axis of an
/// ellipse of axis ratio `ratio` ([`ellipse_angle`] undone).
pub fn ellipse_param(a: f64, ratio: f64) -> f64 {
    same_turn(a.sin().atan2(ratio * a.cos()), a)
}

/// `v` moved by whole turns to the turn of `near`; `near` itself when
/// either is not finite (a ratio of 0 or a NaN from the file).
fn same_turn(v: f64, near: f64) -> f64 {
    let tau = std::f64::consts::TAU;
    let moved = v + tau * ((near - v) / tau).round();
    if moved.is_finite() && near.is_finite() {
        moved
    } else {
        near
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum BoundaryData {
    Polyline {
        closed: bool,
        /// Point and bulge.
        vertices: Vec<(Vec2, f64)>,
    },
    Edges(Vec<Edge>),
}

/// One hatch loop.
#[derive(Clone, Debug, PartialEq)]
pub struct BoundaryPath {
    /// Group 92: 1 external, 2 polyline, 4 derived, 8 text box, 16
    /// outermost.
    pub flags: i32,
    pub data: BoundaryData,
    /// The entities the loop was made from.
    pub sources: Vec<Handle>,
}

/// One line family of a hatch pattern, already scaled and rotated.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PatternLine {
    /// Radians.
    pub angle: f64,
    pub base: Vec2,
    pub offset: Vec2,
    pub dashes: Vec<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Gradient {
    /// Group 450: 0 solid, 1 gradient.
    pub kind: i32,
    pub name: String,
    /// Radians.
    pub angle: f64,
    pub shift: f64,
    /// Group 452: one colour plus a tint.
    pub single_color: bool,
    pub tint: f64,
    /// Position (group 463) and colour of each stop.
    pub colors: Vec<(f64, Color)>,
}

/// HATCH (and its solid and gradient fills).
#[derive(Clone, Debug, PartialEq)]
pub struct Hatch {
    pub elevation: f64,
    pub extrusion: Vec3,
    pub pattern_name: String,
    pub solid: bool,
    pub associative: bool,
    pub paths: Vec<BoundaryPath>,
    /// Group 75: 0 normal (odd parity), 1 outer, 2 ignore.
    pub style: i16,
    /// Group 76: 0 user defined, 1 predefined, 2 custom.
    pub pattern_type: i16,
    /// Radians.
    pub pattern_angle: f64,
    pub pattern_scale: f64,
    pub pattern_double: bool,
    pub pattern_lines: Vec<PatternLine>,
    pub pixel_size: f64,
    pub seeds: Vec<Vec2>,
    pub gradient: Option<Gradient>,
}

impl Default for Hatch {
    fn default() -> Self {
        Hatch {
            elevation: 0.0,
            extrusion: Vec3::Z,
            pattern_name: String::new(),
            solid: false,
            associative: false,
            paths: Vec::new(),
            style: 0,
            pattern_type: 1,
            pattern_angle: 0.0,
            pattern_scale: 1.0,
            pattern_double: false,
            pattern_lines: Vec::new(),
            pixel_size: 0.0,
            seeds: Vec::new(),
            gradient: None,
        }
    }
}

/// HELIX: its curve is the spline; the axis data says how it was made.
#[derive(Clone, Debug, PartialEq)]
pub struct Helix {
    pub spline: Spline,
    pub axis_base: Vec3,
    pub start_point: Vec3,
    pub axis_vector: Vec3,
    pub radius: f64,
    pub turns: f64,
    pub turn_height: f64,
    /// Group 290: true right-handed (counterclockwise).
    pub right_handed: bool,
    pub constraint: i16,
}

impl Default for Helix {
    fn default() -> Self {
        Helix {
            spline: Spline::default(),
            axis_base: Vec3::default(),
            start_point: Vec3::new(1.0, 0.0, 0.0),
            axis_vector: Vec3::Z,
            radius: 1.0,
            turns: 1.0,
            turn_height: 1.0,
            right_handed: true,
            constraint: 0,
        }
    }
}

/// RAY and XLINE, in world coordinates.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Ray {
    pub base: Vec3,
    pub direction: Vec3,
}

/// VIEWPORT: in a layout, a window onto model space.
#[derive(Clone, Debug, PartialEq)]
pub struct Viewport {
    /// Paper-space centre, width and height.
    pub center: Vec3,
    pub width: f64,
    pub height: f64,
    /// Group 68: 0 off, -1 on but not active, positive the stacking order.
    pub status: i16,
    pub id: i16,
    /// Model view centre, display coordinates (relative to `view_target`).
    pub view_center: Vec2,
    pub snap_base: Vec2,
    pub snap_spacing: Vec2,
    pub grid_spacing: Vec2,
    pub view_direction: Vec3,
    pub view_target: Vec3,
    pub lens_length: f64,
    pub front_clip: f64,
    pub back_clip: f64,
    /// Model units the window's height shows.
    pub view_height: f64,
    /// Radians.
    pub snap_angle: f64,
    /// Radians.
    pub twist: f64,
    pub circle_zoom: i16,
    pub frozen_layers: Vec<Handle>,
    /// Group 90: 0x20000 off, 0x10000 non-rectangular clipping, 0x4000 zoom
    /// locked...
    pub flags: i32,
    /// The entity it is clipped to, when not rectangular.
    pub clip_boundary: Handle,
    pub plot_style_sheet: String,
    pub render_mode: i16,
    pub elevation: f64,
    pub shade_plot_mode: i16,
}

impl Default for Viewport {
    fn default() -> Self {
        Viewport {
            center: Vec3::default(),
            width: 1.0,
            height: 1.0,
            status: 0,
            id: 0,
            view_center: Vec2::default(),
            snap_base: Vec2::default(),
            snap_spacing: Vec2::new(10.0, 10.0),
            grid_spacing: Vec2::new(10.0, 10.0),
            view_direction: Vec3::Z,
            view_target: Vec3::default(),
            lens_length: 50.0,
            front_clip: 0.0,
            back_clip: 0.0,
            view_height: 1.0,
            snap_angle: 0.0,
            twist: 0.0,
            circle_zoom: 100,
            frozen_layers: Vec::new(),
            flags: 0,
            clip_boundary: Handle::NULL,
            plot_style_sheet: String::new(),
            render_mode: 0,
            elevation: 0.0,
            shade_plot_mode: 0,
        }
    }
}

impl Viewport {
    /// On: a non-zero status and the off flag clear.
    pub fn is_on(&self) -> bool {
        self.status != 0 && self.flags & 0x20000 == 0
    }
}

/// IMAGE, and WIPEOUT (an image of nothing that masks what is beneath).
/// Points in world coordinates; the clip boundary in pixel coordinates.
#[derive(Clone, Debug, PartialEq)]
pub struct Image {
    pub class_version: i32,
    pub insertion: Vec3,
    /// One pixel along the image's bottom edge.
    pub u_vector: Vec3,
    /// One pixel along its left edge.
    pub v_vector: Vec3,
    /// Pixels.
    pub size: Vec2,
    pub image_def: Handle,
    /// Group 70: 1 show, 2 show unaligned, 4 clip, 8 transparent.
    pub display: i16,
    pub clipping: bool,
    pub brightness: i16,
    pub contrast: i16,
    pub fade: i16,
    pub reactor: Handle,
    /// Group 71: 1 rectangular, 2 polygonal.
    pub clip_type: i16,
    pub clip_vertices: Vec<Vec2>,
    /// Group 290: true keeps the inside of the boundary.
    pub clip_inside: bool,
}

impl Default for Image {
    fn default() -> Self {
        Image {
            class_version: 0,
            insertion: Vec3::default(),
            u_vector: Vec3::new(1.0, 0.0, 0.0),
            v_vector: Vec3::new(0.0, 1.0, 0.0),
            size: Vec2::default(),
            image_def: Handle::NULL,
            display: 0,
            clipping: false,
            brightness: 50,
            contrast: 50,
            fade: 0,
            reactor: Handle::NULL,
            clip_type: 1,
            clip_vertices: Vec::new(),
            clip_inside: false,
        }
    }
}

/// PDFUNDERLAY, DWFUNDERLAY, DGNUNDERLAY. Points in object coordinates.
#[derive(Clone, Debug, PartialEq)]
pub struct Underlay {
    pub kind: UnderlayKind,
    pub definition: Handle,
    pub insertion: Vec3,
    pub scale: Vec3,
    /// Radians.
    pub rotation: f64,
    pub extrusion: Vec3,
    /// Group 280: 1 clipped, 2 on, 4 monochrome, 8 adjust for background,
    /// 16 clip inside.
    pub flags: i16,
    pub contrast: i16,
    pub fade: i16,
    /// Two points are a rectangle's corners; more a polygon.
    pub clip_vertices: Vec<Vec2>,
}

impl Default for Underlay {
    fn default() -> Self {
        Underlay {
            kind: UnderlayKind::Pdf,
            definition: Handle::NULL,
            insertion: Vec3::default(),
            scale: Vec3::new(1.0, 1.0, 1.0),
            rotation: 0.0,
            extrusion: Vec3::Z,
            flags: 2,
            contrast: 100,
            fade: 0,
            clip_vertices: Vec::new(),
        }
    }
}

/// OLE2FRAME. The embedded object's bytes are not kept.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Ole2Frame {
    pub version: i16,
    pub description: String,
    pub upper_left: Vec3,
    pub lower_right: Vec3,
    /// Group 71: 1 link, 2 embedded, 3 static.
    pub ole_type: i16,
    /// Group 72: 0 model space, 1 paper space.
    pub tile_mode: i16,
    pub data_length: i64,
}

/// ACAD_TABLE. Its look is the anonymous block it names, like a dimension's.
#[derive(Clone, Debug, PartialEq)]
pub struct Table {
    pub block_name: String,
    pub insertion: Vec3,
    pub horizontal_direction: Vec3,
    pub style: Handle,
    pub block_record: Handle,
    pub rows: i32,
    pub columns: i32,
    pub row_heights: Vec<f64>,
    pub column_widths: Vec<f64>,
}

impl Default for Table {
    fn default() -> Self {
        Table {
            block_name: String::new(),
            insertion: Vec3::default(),
            horizontal_direction: Vec3::new(1.0, 0.0, 0.0),
            style: Handle::NULL,
            block_record: Handle::NULL,
            rows: 0,
            columns: 0,
            row_heights: Vec::new(),
            column_widths: Vec::new(),
        }
    }
}

/// SHAPE: a glyph of an SHX shape file.
#[derive(Clone, Debug, PartialEq)]
pub struct Shape {
    pub insertion: Vec3,
    pub size: f64,
    pub name: String,
    /// Radians.
    pub rotation: f64,
    pub width_factor: f64,
    /// Radians.
    pub oblique: f64,
    pub plane: Plane,
}

impl Default for Shape {
    fn default() -> Self {
        Shape {
            insertion: Vec3::default(),
            size: 1.0,
            name: String::new(),
            rotation: 0.0,
            width_factor: 1.0,
            oblique: 0.0,
            plane: Plane::default(),
        }
    }
}
