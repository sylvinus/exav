//! Proxy graphics (ODA spec 29): what an application's custom entity draws,
//! saved with it so that a program without the application can show it.
//! ACAD_PROXY_ENTITY carries them, and so does any custom entity written
//! while `$PROXYGRAPHICS` was 1.

use super::{Color, LineWeight, LwPolyline, Vec3};

/// The stream's primitives and the trait changes between them, in order.
/// Traits apply to the primitives after them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProxyGraphics {
    pub items: Vec<ProxyItem>,
}

impl ProxyGraphics {
    /// Whether any item draws something.
    pub fn draws(&self) -> bool {
        self.items.iter().any(ProxyItem::is_geometry)
    }
}

/// How the ends of an arc are joined (the arc type of ODA spec 29).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ArcKind {
    /// The arc alone.
    #[default]
    Simple,
    /// Closed through the centre.
    Sector,
    /// Closed by the chord.
    Chord,
}

impl ArcKind {
    pub fn from_code(v: u32) -> ArcKind {
        match v {
            1 => ArcKind::Sector,
            2 => ArcKind::Chord,
            _ => ArcKind::Simple,
        }
    }
}

/// One record of the stream. Points are in the entity's coordinates, the
/// transforms pushed so far applying.
#[derive(Clone, Debug, PartialEq)]
pub enum ProxyItem {
    /// 2
    Circle {
        center: Vec3,
        radius: f64,
        normal: Vec3,
    },
    /// 3: the circle through three points.
    Circle3P([Vec3; 3]),
    /// 4: from `start`, a direction from the centre, `sweep` radians
    /// counterclockwise about `normal`.
    Arc {
        center: Vec3,
        radius: f64,
        normal: Vec3,
        start: Vec3,
        sweep: f64,
        kind: ArcKind,
    },
    /// 5: the arc from the first point through the second to the third.
    Arc3P { points: [Vec3; 3], kind: ArcKind },
    /// 44, which the spec does not list: an elliptical arc from parameter
    /// `start` to `end` counterclockwise about `normal`, its major axis
    /// `rotation` radians from the X axis of the normal's object coordinate
    /// system (found by fitting the converter's R12 polylines).
    EllipticalArc(Box<ProxyEllipse>),
    /// 6, and 32 with a normal.
    Polyline {
        points: Vec<Vec3>,
        normal: Option<Vec3>,
    },
    /// 7: closed, filled while fill is on.
    Polygon(Vec<Vec3>),
    /// 8: `rows` by `columns` vertices, row after row.
    Mesh(Box<ProxyMesh>),
    /// 9
    Shell(Box<ProxyShell>),
    /// 10, 11, 36 and 38.
    Text(Box<ProxyText>),
    /// 12 (both ways) and 13 (from `base` through `through`).
    XLine {
        base: Vec3,
        through: Vec3,
        ray: bool,
    },
    /// 33: an LWPOLYLINE's own data, read as the drawing's release writes
    /// it.
    LwPolyline(Box<LwPolyline>),
    /// 14 (an AutoCAD Color Index, 0 ByBlock, 256 ByLayer) and 22 (an
    /// AcCmColor, `0xC2RRGGBB` a true colour).
    Color(Color),
    /// 16: an index into the drawing's layer table, in table order; past
    /// its end the layer does not change.
    Layer(u32),
    /// 18: an index into the linetype table without its ByLayer and ByBlock
    /// entries, in table order; 0xFFFFFFFF, 32767 and any index past the
    /// end ByLayer, 0xFFFFFFFE and 32766 ByBlock.
    Linetype(u32),
    /// 20: fill on but for 2, the value the ODA converter writes for off.
    Fill(bool),
    /// 23
    LineWeight(LineWeight),
    /// 24
    LinetypeScale(f64),
    /// 25
    Thickness(f64),
    /// 29: a 4x4 matrix, row after row, applied to points as columns, after
    /// the ones pushed before it. 30 reads as the identity.
    PushTransform(Box<[f64; 16]>),
    /// 31
    PopTransform,
}

impl ProxyItem {
    /// Whether the item draws, rather than set a trait or a transform.
    pub fn is_geometry(&self) -> bool {
        !matches!(
            self,
            ProxyItem::Color(_)
                | ProxyItem::Layer(_)
                | ProxyItem::Linetype(_)
                | ProxyItem::Fill(_)
                | ProxyItem::LineWeight(_)
                | ProxyItem::LinetypeScale(_)
                | ProxyItem::Thickness(_)
                | ProxyItem::PushTransform(_)
                | ProxyItem::PopTransform
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProxyEllipse {
    pub center: Vec3,
    pub normal: Vec3,
    pub major_radius: f64,
    pub minor_radius: f64,
    pub start: f64,
    pub end: f64,
    pub rotation: f64,
    pub kind: ArcKind,
}

/// A grid of vertices, with the visibility of each edge when the stream
/// gives it: the edges along each row first (rows x (columns - 1)), then
/// those between rows.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProxyMesh {
    pub rows: u32,
    pub columns: u32,
    pub vertices: Vec<Vec3>,
    pub edge_visible: Vec<bool>,
}

/// Faces on a list of vertices: each face is a count, then that many vertex
/// indices; a negative count is a hole in the face before it. Edge
/// visibility, when given, is per edge in face order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProxyShell {
    pub vertices: Vec<Vec3>,
    pub faces: Vec<i32>,
    pub edge_visible: Vec<bool>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProxyText {
    pub position: Vec3,
    pub normal: Vec3,
    /// Along the baseline; its length is not the text's.
    pub direction: Vec3,
    pub height: f64,
    pub width_factor: f64,
    /// Radians.
    pub oblique: f64,
    pub value: String,
    /// `%%` codes are not to be interpreted.
    pub raw: bool,
    /// The font file (11, 38), empty when the stream names none.
    pub font: String,
    pub big_font: String,
    /// The TrueType face (38).
    pub typeface: String,
    pub bold: bool,
    pub italic: bool,
    pub backwards: bool,
    pub upside_down: bool,
}

impl Default for ProxyText {
    fn default() -> Self {
        ProxyText {
            position: Vec3::default(),
            normal: Vec3::Z,
            direction: Vec3::new(1.0, 0.0, 0.0),
            height: 1.0,
            width_factor: 1.0,
            oblique: 0.0,
            value: String::new(),
            raw: false,
            font: String::new(),
            big_font: String::new(),
            typeface: String::new(),
            bold: false,
            italic: false,
            backwards: false,
            upside_down: false,
        }
    }
}
