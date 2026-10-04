//! Walk a drawing model and turn drawable entities into GPU buffers.

use std::collections::{HashMap, HashSet};

use crate::cad::{
    Color, Drawing as CadDrawing, Edge, Entity, EntityKind, HAlign, Handle, LineWeight,
    PolylineKind, Transparency, VAlign, MODEL_SPACE, PAPER_SPACE,
};

use super::clip::ClipShape;
use super::curves;
use super::fill;
use super::font;
use super::gradient::{self, Gradient};
use super::hatch;
use super::linetype::{self, dash_polyline, Pattern};
use super::palette::Palette;
use super::proxy;
use super::scene::{
    encode_fade_spacing, pack_attr, pack_rgba, Affine, Scene, FILL_FLAG_BACKGROUND, FLAG_CONTRAST,
};
use super::text;

fn h_align_of(a: HAlign) -> text::HAlign {
    match a {
        HAlign::Left => text::HAlign::Left,
        HAlign::Center => text::HAlign::Center,
        HAlign::Right => text::HAlign::Right,
        HAlign::Aligned => text::HAlign::Aligned,
        HAlign::Middle => text::HAlign::Middle,
        HAlign::Fit => text::HAlign::Fit,
    }
}

fn v_align_of(a: VAlign) -> text::VAlign {
    match a {
        VAlign::Baseline => text::VAlign::Baseline,
        VAlign::Bottom => text::VAlign::Bottom,
        VAlign::Middle => text::VAlign::Middle,
        VAlign::Top => text::VAlign::Top,
    }
}

/// Object-coordinate transform for an entity, or None if it is already in
/// world coordinates.
///
/// Only some entity types are stored in OCS. LINE, POINT, SPLINE, ELLIPSE,
/// 3DFACE and MLINE carry an extrusion vector but their coordinates are
/// already world-space, so applying the transform to them would mirror
/// geometry that was correct to begin with.
fn ocs_of(e: &EntityKind) -> Option<Affine> {
    let (n, elevation) = match e {
        EntityKind::Circle(x) => (x.plane.extrusion, x.center.z),
        EntityKind::Arc(x) => (x.plane.extrusion, x.center.z),
        EntityKind::LwPolyline(x) => (x.plane.extrusion, x.elevation),
        EntityKind::Polyline(x) if x.kind() == PolylineKind::Polyline2D => {
            (x.plane.extrusion, x.elevation)
        }
        EntityKind::Solid(x) | EntityKind::Trace(x) => (x.plane.extrusion, x.corners[0].z),
        EntityKind::Text(x) => (x.plane.extrusion, x.insertion.z),
        EntityKind::MText(x) => (x.extrusion, x.insertion.z),
        EntityKind::Attribute(x) | EntityKind::AttributeDefinition(x) => {
            (x.text.plane.extrusion, x.text.insertion.z)
        }
        EntityKind::Insert(x) => (x.extrusion, x.insertion.z),
        EntityKind::Hatch(x) => (x.extrusion, x.elevation),
        EntityKind::Dimension(d) => (d.extrusion, 0.0),
        _ => return None,
    };
    if n.z > 0.0 && n.x.abs() < 1e-12 && n.y.abs() < 1e-12 {
        return None;
    }
    Some(Affine::from_extrusion(n.x, n.y, n.z, elevation))
}

/// How a hatch wants its islands treated (group 75).
///
/// The drawing says so per hatch, and it changes what gets drawn: a rooflight
/// band modelled as an island containing a second island is blank under
/// `Outer` but hatched again in the middle under `Normal`.
fn island_style(h: &crate::cad::Hatch) -> fill::IslandStyle {
    match h.style {
        1 => fill::IslandStyle::Outer,
        2 => fill::IslandStyle::Ignore,
        _ => fill::IslandStyle::Normal,
    }
}

/// The next tab stop after `cursor`, in drawing units from the line's left edge.
///
/// A paragraph that declares its stops uses them. When none are declared there
/// is nothing to go on: neither Autodesk's documentation nor the DXF reference
/// says what MTEXT's default tab spacing is. Four times the text height is the
/// step AutoCAD's own editor appears to use and is the width of a typical list
/// indent; it is a guess, and it is only ever reached by text that tabs without
/// declaring where to.
fn next_tab_stop(cursor: f64, paragraph: &text::Paragraph, height: f64) -> f64 {
    if let Some(stop) = paragraph.tabs.iter().find(|s| **s > cursor + 1e-9) {
        return *stop;
    }
    let step = (height * 4.0).max(1e-9);
    ((cursor / step).floor() + 1.0) * step
}

/// Resolve a colour to RGB against the palette the background calls for.
///
/// An indexed colour has no single RGB value: AutoCAD resolves it against the
/// drawing area's background. See the palette module.
fn colour_rgb(c: &Color, palette: Palette) -> Option<(u8, u8, u8)> {
    match *c {
        Color::Index(i) if i > 0 => Some(palette.rgb(i)),
        Color::Rgb(r, g, b) => Some((r, g, b)),
        _ => None,
    }
}

/// Whether a colour is AutoCAD's colour 7, the one that flips to stay legible.
///
/// Index 7 is "white or black, whichever contrasts". Index 0 (ByBlock) and 256
/// (ByLayer) are resolved before this is reached, and a true colour is taken
/// literally however close to white it is.
fn is_contrast_color(c: &Color) -> bool {
    matches!(c, Color::Index(7))
}

/// A linetype definition: its run lengths plus any text it stamps along a line.
#[derive(Default)]
struct LineTypeDef {
    runs: Vec<f64>,
    labels: Vec<linetype::Label>,
}

/// The text a complex linetype embeds, ready to scale.
///
/// Shape elements are skipped: they name a glyph in an SHX shape file, which
/// cannot be shipped any more than an SHX font can (DESIGN.md section 5.3).
fn embedded_labels(doc: &CadDrawing, lt: &crate::cad::Linetype) -> Vec<linetype::Label> {
    let mut out = Vec::new();
    for (run, e) in lt.elements.iter().enumerate() {
        if !e.has_text() || e.text.is_empty() || !e.scale.is_finite() || e.scale <= 0.0 {
            continue;
        }
        // The element's scale multiplies the style's fixed height, or is the
        // height itself when the style leaves it free, which is the usual case.
        let style = doc
            .text_styles
            .iter()
            .find(|s| !e.style.is_null() && s.handle == e.style);
        let style_height = style.map(|s| s.height).unwrap_or(0.0);
        let height = if style_height > 0.0 {
            style_height * e.scale
        } else {
            e.scale
        };
        out.push(linetype::Label {
            run,
            text: text::decode_special(&e.text),
            height,
            offset: [e.offset.x, e.offset.y],
            rotation: e.rotation,
            absolute_rotation: e.absolute_rotation(),
            face: style.map(font::resolve_style).unwrap_or(font::Face::Stroke),
        });
    }
    out
}

/// A RAY or XLINE, held back until the drawing's extents are known.
struct InfiniteLine {
    base: [f64; 2],
    dir: [f64; 2],
    /// An XLINE runs both ways; a RAY only forwards.
    both_ways: bool,
    rgba: u32,
    attr: u32,
}

/// Model space to paper space, for one layout viewport.
///
/// The view centre is stored in display coordinates, whose origin sits at the
/// view target, so the model point shown in the middle of the window is the sum
/// of the two. Taking the view centre on its own aims the window at empty
/// space, which is how a sheet comes out holding nothing but its title block.
pub fn viewport_transform(
    paper_center: [f64; 2],
    paper_height: f64,
    view_center: [f64; 2],
    view_target: [f64; 2],
    view_height: f64,
    twist: f64,
) -> Affine {
    let scale = paper_height / view_height;
    // The twist angle turns the view, so the model turns the other way.
    let place = Affine::new(paper_center[0], paper_center[1], scale, scale, -twist);
    let recenter = Affine {
        a: 1.0,
        b: 0.0,
        c: 0.0,
        d: 1.0,
        e: -(view_center[0] + view_target[0]),
        f: -(view_center[1] + view_target[1]),
    };
    place.mul(&recenter)
}

/// Guards against block reference cycles in damaged files.
const MAX_BLOCK_DEPTH: u32 = 32;

/// One of the drawing's tabs: model space, or a paper-space sheet.
pub struct LayoutInfo {
    pub name: String,
    /// Block record holding the tab's own entities.
    pub block: String,
    pub is_model: bool,
    /// Position of the tab in AutoCAD's tab bar.
    pub tab_order: i16,
    /// The sheet, as `[min_x, min_y, max_x, max_y]` in paper units.
    pub limits: Option<[f64; 4]>,
}

pub struct LayerInfo {
    pub name: String,
    pub rgba: u32,
    pub lineweight: u8,
    pub off: bool,
    pub frozen: bool,
    /// Layer is on colour 7, so its geometry flips with the background.
    pub contrast: bool,
    /// Index into the tessellator's pattern table. 0 means continuous.
    pub linetype: usize,
}

/// What we could not draw. Surfaced to the host so gaps are visible rather than
/// silently missing.
#[derive(Default, Clone)]
pub struct Warnings {
    pub unknown_entities: u32,
    pub missing_blocks: u32,
    /// Text runs emitted. Not a gap in itself, but every one is drawn with a
    /// substituted font: SHX shapes cannot be shipped (DESIGN.md section 5.3).
    pub text_runs: u32,
    /// Glyphs of the count above drawn here as stroke geometry rather than
    /// handed to the host, because their style names a stroke font.
    pub stroke_glyphs: u32,
    /// Pattern hatches whose definition carried no line families.
    pub hatch_patterns_missing: u32,
    /// Pattern hatches cut short by the segment cap.
    pub hatch_patterns_truncated: u32,
    /// Images, underlays and OLE objects whose content lives in another file.
    /// Only their frame is drawn.
    pub external_references: u32,
    pub depth_exceeded: u32,
    /// Entities left out once the scene reached [`Tessellator::budget`].
    pub scene_truncated: u32,
    /// Custom entities (ACAD_PROXY_ENTITY, an application's own types) saved
    /// without proxy graphics, or with graphics that draw nothing: only the
    /// application that made them can show them.
    pub proxy_without_graphics: u32,
}

/// Default for [`Tessellator::budget`]: strokes and fill vertices one layout
/// may produce. The caps on each entity (pattern segments, dashes, gradient
/// triangles) do not compose: a MINSERT of a hatched block, blocks nested in
/// blocks, or many viewports onto the same model space multiply them. Four
/// times the largest real drawing measured (2.17M strokes); about 220 MB of
/// buffers.
pub const SCENE_BUDGET: usize = 8_000_000;

/// Inherited state as the block stack is walked.
#[derive(Clone, Copy)]
struct Ctx {
    xf: Affine,
    layer: u16,
    rgba: u32,
    /// Inherited colour is colour 7, for entities whose colour is ByBlock.
    contrast: bool,
    lw: u8,
    /// Inherited pattern index, for entities whose linetype is ByBlock.
    lt: usize,
    /// Extra factor on dash lengths. One everywhere except inside a viewport
    /// under PSLTSCALE, where it cancels the viewport's own scale.
    lt_scale: f64,
    depth: u32,
}

pub struct Tessellator<'a> {
    doc: &'a CadDrawing,
    /// Block index in `doc.blocks` by upper-case name, the first of a name
    /// winning as in [`CadDrawing::block`].
    block_index: HashMap<String, usize>,
    pub scene: Scene,
    /// Strokes and fill vertices the scene may hold. Once reached, the
    /// entities left are counted in `warnings.scene_truncated` and not drawn.
    /// [`SCENE_BUDGET`] unless set before the walk.
    pub budget: usize,
    pub layers: Vec<LayerInfo>,
    layer_index: HashMap<String, u16>,
    pub warnings: Warnings,
    /// Linetype definitions, in drawing units. Index 0 is continuous.
    patterns: Vec<LineTypeDef>,
    linetype_index: HashMap<String, usize>,
    /// LTSCALE, the drawing's global linetype scale.
    global_ltscale: f64,
    /// Entity handle to sort handle, from the drawing's SORTENTSTABLE objects.
    sort_keys: HashMap<u64, u64>,
    /// Rays and xlines, drawn once the extents they must be clipped to exist.
    pending_infinite: Vec<InfiniteLine>,
    /// Layer record handle to layer id, for per-viewport freezing.
    layer_by_handle: HashMap<u64, u16>,
    /// Layers frozen in the viewport currently being drawn. A layer can be
    /// frozen in one viewport and visible in the next, which the host's
    /// per-layer visibility cannot express, so it is baked in here.
    vp_frozen: HashSet<u16>,
    /// Face each text style resolves to, by upper-case style name. Built once,
    /// because a drawing names a handful of styles and uses them thousands of
    /// times.
    style_faces: HashMap<String, font::Face>,
    /// The same, by style handle: entities that reference a style by name are
    /// the common case, but leaders and dimensions point at one by handle.
    style_faces_by_handle: HashMap<u64, font::Face>,
    /// Which ACI table indexed colours resolve through.
    palette: Palette,
    /// Block names currently being expanded, to break reference cycles.
    stack: Vec<String>,
}

fn normalize(name: &str) -> String {
    name.to_ascii_uppercase()
}

impl<'a> Tessellator<'a> {
    fn scene_full(&self) -> bool {
        self.scene.strokes.len() + self.scene.fills.len() >= self.budget
    }

    pub fn new(doc: &'a CadDrawing) -> Tessellator<'a> {
        Tessellator::with_palette(doc, Palette::default())
    }

    /// Build against a particular ACI palette.
    ///
    /// Indexed colours resolve differently depending on the background they are
    /// read against, and layer colours are resolved here, so the palette has to
    /// be known before the walk starts.
    pub fn with_palette(doc: &'a CadDrawing, palette: Palette) -> Tessellator<'a> {
        let mut layers = Vec::new();
        let mut layer_index = HashMap::new();

        // Index 0 is the continuous pattern, which every solid line points at.
        let mut patterns: Vec<LineTypeDef> = vec![LineTypeDef::default()];
        let mut linetype_index: HashMap<String, usize> = HashMap::new();
        for lt in doc.linetypes.iter() {
            let runs: Vec<f64> = lt.elements.iter().map(|e| e.length).collect();
            let labels = embedded_labels(doc, lt);
            // A definition with no gaps draws solid; point it at index 0 so the
            // hot path skips the dashing machinery entirely. One that stamps
            // text along the line still has work to do either way.
            let idx = if runs.iter().any(|r| *r <= 0.0) || !labels.is_empty() {
                patterns.push(LineTypeDef { runs, labels });
                patterns.len() - 1
            } else {
                0
            };
            linetype_index.insert(normalize(&lt.name), idx);
        }
        let global_ltscale = if doc.header.ltscale > 0.0 {
            doc.header.ltscale
        } else {
            1.0
        };

        let mut layer_by_handle: HashMap<u64, u16> = HashMap::new();
        for layer in doc.layers.iter() {
            // The id is a u16 and the table would overflow it: the rest of
            // the layers fall back to the inherited one.
            if layers.len() >= u16::MAX as usize {
                break;
            }
            let (r, g, b) = colour_rgb(&layer.color, palette).unwrap_or((255, 255, 255));
            let idx = layers.len() as u16;
            layer_index.entry(normalize(&layer.name)).or_insert(idx);
            layer_by_handle.insert(layer.handle.0, idx);
            layers.push(LayerInfo {
                name: layer.name.clone(),
                rgba: pack_rgba(r, g, b, layer.alpha),
                lineweight: lineweight_value(layer.lineweight, 0),
                off: layer.off,
                frozen: layer.is_frozen(),
                contrast: is_contrast_color(&layer.color),
                linetype: linetype_index
                    .get(&normalize(&layer.linetype))
                    .copied()
                    .unwrap_or(0),
            });
        }

        // Every drawing has layer "0"; synthesise it if the table is odd.
        if !layer_index.contains_key("0") {
            let idx = layers.len() as u16;
            layer_index.insert("0".to_string(), idx);
            layers.push(LayerInfo {
                name: "0".to_string(),
                rgba: pack_rgba(255, 255, 255, 255),
                lineweight: 0,
                off: false,
                frozen: false,
                // The standard layer 0 is colour 7.
                contrast: true,
                linetype: 0,
            });
        }

        // AutoCAD's DRAWORDER command ("bring to front", "send to back") writes
        // a SORTENTSTABLE that overrides the natural entity order. Architects
        // lean on it constantly, most visibly to float a masking fill above a
        // hatch, so ignoring it paints those entities underneath instead.
        let mut sort_keys: HashMap<u64, u64> = HashMap::new();
        for t in &doc.sort_tables {
            for (entity, sort) in &t.entries {
                sort_keys.insert(entity.0, sort.0);
            }
        }

        let mut block_index: HashMap<String, usize> = HashMap::new();
        for (i, b) in doc.blocks.iter().enumerate() {
            block_index.entry(normalize(&b.name)).or_insert(i);
        }

        Tessellator {
            doc,
            block_index,
            scene: Scene::new(),
            budget: SCENE_BUDGET,
            layers,
            layer_index,
            warnings: Warnings::default(),
            patterns,
            linetype_index,
            global_ltscale,
            sort_keys,
            pending_infinite: Vec::new(),
            layer_by_handle,
            vp_frozen: HashSet::new(),
            style_faces: doc
                .text_styles
                .iter()
                .map(|s| (normalize(&s.name), font::resolve_style(s)))
                .collect(),
            style_faces_by_handle: doc
                .text_styles
                .iter()
                .map(|s| (s.handle.0, font::resolve_style(s)))
                .collect(),
            palette,
            stack: Vec::new(),
        }
    }

    /// Draw the held-back rays and xlines, clipped to the drawing's extents.
    ///
    /// They have to wait: an unbounded line has no extent of its own, and
    /// tessellating it first would stretch the drawing's bounds to wherever it
    /// happened to be cut off.
    fn flush_infinite_lines(&mut self) {
        if self.pending_infinite.is_empty() {
            return;
        }
        let origin = self.scene.origin();
        let ext = self.scene.extents_local();
        let (mut minx, mut miny) = (origin[0] + ext[0] as f64, origin[1] + ext[1] as f64);
        let (mut maxx, mut maxy) = (origin[0] + ext[2] as f64, origin[1] + ext[3] as f64);

        // With nothing else in the drawing there are no extents to clip against,
        // and a box at the world origin would discard every line that does not
        // pass through it. Fall back to the span of the base points.
        if self.scene.is_empty() {
            minx = f64::INFINITY;
            miny = f64::INFINITY;
            maxx = f64::NEG_INFINITY;
            maxy = f64::NEG_INFINITY;
            for line in &self.pending_infinite {
                if !line.base[0].is_finite() || !line.base[1].is_finite() {
                    continue;
                }
                minx = minx.min(line.base[0]);
                miny = miny.min(line.base[1]);
                maxx = maxx.max(line.base[0]);
                maxy = maxy.max(line.base[1]);
            }
            if !minx.is_finite() {
                return;
            }
        }

        // A margin keeps the clipped ends outside the visible drawing, and gives
        // the fallback box above a length to draw across.
        let pad = ((maxx - minx).max(maxy - miny) * 0.05).max(1.0);
        minx -= pad;
        miny -= pad;
        maxx += pad;
        maxy += pad;

        for line in std::mem::take(&mut self.pending_infinite) {
            let len = (line.dir[0] * line.dir[0] + line.dir[1] * line.dir[1]).sqrt();
            if !len.is_finite() || len < 1e-12 {
                continue;
            }
            let u = [line.dir[0] / len, line.dir[1] / len];

            // Slab clip: the parameter range where the line is inside the box.
            let mut t0 = if line.both_ways {
                f64::NEG_INFINITY
            } else {
                0.0
            };
            let mut t1 = f64::INFINITY;
            let mut outside = false;
            for (p, d, lo, hi) in [
                (line.base[0], u[0], minx, maxx),
                (line.base[1], u[1], miny, maxy),
            ] {
                if d.abs() < 1e-12 {
                    if p < lo || p > hi {
                        outside = true;
                    }
                    continue;
                }
                let (a, b) = ((lo - p) / d, (hi - p) / d);
                let (a, b) = if a <= b { (a, b) } else { (b, a) };
                t0 = t0.max(a);
                t1 = t1.min(b);
            }
            if outside || !(t1 > t0) || !t0.is_finite() || !t1.is_finite() {
                continue;
            }

            self.scene.push_stroke(
                line.base[0] + u[0] * t0,
                line.base[1] + u[1] * t0,
                line.base[0] + u[0] * t1,
                line.base[1] + u[1] * t1,
                line.rgba,
                line.attr,
            );
        }
    }

    /// Leader lines plus the label they point at.
    fn multi_leader(&mut self, m: &crate::cad::MultiLeader, ctx: &Ctx, rgba: u32, attr: u32) {
        let c = &m.context;

        // Every leader root contributes one or more polylines.
        for root in &c.leaders {
            for line in &root.lines {
                let pts: Vec<[f64; 2]> = line.vertices.iter().map(|p| [p.x, p.y]).collect();
                if pts.len() >= 2 {
                    self.push_transformed(&pts, false, &ctx.xf, rgba, attr, None);
                }
            }
            // The landing runs from the last leader point to the content.
            if root.dogleg_length.abs() > 1e-9 {
                let a = [root.connection_point.x, root.connection_point.y];
                let b = [
                    a[0] + root.direction.x * root.dogleg_length,
                    a[1] + root.direction.y * root.dogleg_length,
                ];
                self.push_transformed(&[a, b], false, &ctx.xf, rgba, attr, None);
            }
        }

        if c.has_text && !c.text.trim().is_empty() {
            let rotation = if c.text_direction.x != 0.0 || c.text_direction.y != 0.0 {
                c.text_direction.y.atan2(c.text_direction.x)
            } else {
                c.text_rotation
            };
            let height = if c.text_height > 0.0 {
                c.text_height
            } else {
                2.5
            };
            let spacing = height
                * text::MTEXT_LINE_SPACING
                * if c.line_spacing_factor > 0.0 {
                    c.line_spacing_factor
                } else {
                    1.0
                };
            let lines = text::mtext_lines(&c.text);
            let face = self.style_face_by_handle(c.text_style);
            // Attachment codes match MTEXT's.
            let (h_align, dy0) =
                text::mtext_layout(c.text_attachment as u8, lines.len(), height, spacing);
            let (sin_r, cos_r) = rotation.sin_cos();
            let text_rgba = match c.text_color {
                Color::ByLayer | Color::ByBlock => rgba,
                ref col => colour_rgb(col, self.palette)
                    .map(|(r, g, b)| pack_rgba(r, g, b, 255))
                    .unwrap_or(rgba),
            };

            for (i, line) in lines.iter().enumerate() {
                if line.is_empty() {
                    continue;
                }
                let dy = dy0 - i as f64 * spacing;
                self.push_text_run(
                    line.clone(),
                    c.text_location.x - dy * sin_r,
                    c.text_location.y + dy * cos_r,
                    height,
                    rotation,
                    1.0,
                    0.0,
                    h_align,
                    text::VAlign::Baseline,
                    ctx,
                    text_rgba,
                    attr,
                    face,
                );
            }
        }
    }

    /// Entities in the order the drawing wants them painted.
    ///
    /// Entities listed in a sort table use their sort handle; the rest keep
    /// their own handle, which is the order they were created in.
    fn in_draw_order<'e>(&self, entities: &'e [Entity]) -> Vec<&'e Entity> {
        let mut entities: Vec<&'e Entity> = entities.iter().collect();
        if self.sort_keys.is_empty() {
            return entities;
        }
        entities.sort_by_key(|e| {
            let h = e.handle.0;
            self.sort_keys.get(&h).copied().unwrap_or(h)
        });
        entities
    }

    /// A dimension style's arrowhead size in drawing units: DIMASZ scaled by
    /// DIMSCALE (0 there means "fit to the viewport", taken as 1). A style
    /// the drawing does not have falls back to the header's variables.
    fn arrow_size(&self, style: &str) -> f64 {
        let (size, scale) = match self
            .doc
            .dim_styles
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(style))
        {
            Some(s) => (s.dimasz, s.dimscale),
            None => (self.doc.header.dimasz, self.doc.header.dimscale),
        };
        let scale = if scale > 0.0 && scale.is_finite() {
            scale
        } else {
            1.0
        };
        let size = size * scale;
        if size.is_finite() && size > 0.0 {
            size
        } else {
            0.0
        }
    }

    /// A block by name, ignoring ASCII case.
    fn block(&self, name: &str) -> Option<&'a crate::cad::Block> {
        let doc: &'a CadDrawing = self.doc;
        self.block_index
            .get(&normalize(name))
            .and_then(|&i| doc.blocks.get(i))
    }

    /// Resolve an entity's linetype to a pattern index, following ByLayer and
    /// ByBlock through the block stack.
    fn linetype_of(&self, name: &str, layer: &LayerInfo, ctx: &Ctx) -> usize {
        match normalize(name).as_str() {
            "" | "BYLAYER" => layer.linetype,
            "BYBLOCK" => ctx.lt,
            other => self.linetype_index.get(other).copied().unwrap_or(0),
        }
    }

    /// Build the scaled pattern for an entity, or None when it draws solid.
    fn pattern_for(&self, idx: usize, entity_scale: f64, transform_scale: f64) -> Option<Pattern> {
        let def = self.patterns.get(idx)?;
        if def.runs.is_empty() {
            return None;
        }
        let entity_scale = if entity_scale > 0.0 {
            entity_scale
        } else {
            1.0
        };
        Pattern::with_labels(
            &def.runs,
            &def.labels,
            self.global_ltscale * entity_scale * transform_scale,
        )
    }

    fn layer_id(&self, name: &str) -> Option<u16> {
        self.layer_index.get(&normalize(name)).copied()
    }

    /// The face a text style resolves to. An unknown style name is AutoCAD's
    /// default, which is a stroke font.
    fn style_face(&self, style: &str) -> font::Face {
        self.style_faces
            .get(&normalize(style))
            .copied()
            .unwrap_or(font::Face::Stroke)
    }

    /// The same, for an entity that points at its style by handle.
    fn style_face_by_handle(&self, handle: Handle) -> font::Face {
        self.style_faces_by_handle
            .get(&handle.0)
            .copied()
            .filter(|_| !handle.is_null())
            .unwrap_or(font::Face::Stroke)
    }

    /// MTEXT content as the lines it is drawn on: the explicit `\P` breaks,
    /// then each paragraph broken to the entity's box width.
    fn wrap_mtext(
        &self,
        raw: &str,
        box_width: f64,
        height: f64,
        face: font::Face,
    ) -> Vec<text::Line> {
        let lines = text::mtext_spans(raw);
        if !(box_width > 0.0) || !(height > 0.0) {
            return lines;
        }
        // Widths are in cap heights and so is the DWG text height, so the box
        // converts by a single division.
        let max_cap = box_width / height;
        lines
            .iter()
            .flat_map(|l| {
                // A `\f` in the first run decides where the line breaks. Using
                // one face for the whole line keeps break points stable when a
                // colour or font change falls mid-sentence.
                let m =
                    font::Metrics::for_face(l.spans.first().and_then(|s| s.face).unwrap_or(face));
                text::wrap_spans(l, max_cap, &m)
            })
            .collect()
    }

    /// Draw one laid-out MTEXT line, honouring per-run colour, height and rules.
    ///
    /// A line of one run is handed to the renderer to align, which measures the
    /// string with the real font. A line of several has to be placed here,
    /// because each run starts where the one before it ended.
    #[allow(clippy::too_many_arguments)]
    fn push_mtext_line(
        &mut self,
        line: &text::Line,
        base_height: f64,
        x: f64,
        y: f64,
        rotation: f64,
        h_align: text::HAlign,
        ctx: &Ctx,
        rgba: u32,
        attr: u32,
        face: font::Face,
    ) {
        let spans = &line.spans;
        let height_of = |s: &text::Span| match s.height {
            text::SpanHeight::Factor(f) if f > 0.0 => base_height * f,
            text::SpanHeight::Absolute(h) if h > 0.0 => h,
            _ => base_height,
        };
        // A `\f` run draws in the face it names; the rest take the entity's.
        let face_of = |s: &text::Span| s.face.unwrap_or(face);

        // Where the line starts, from its paragraph's indents. The first line
        // of a paragraph can be indented differently from the rest, which is
        // what makes a numbered list hang.
        let indent = line.paragraph.indent
            + if line.first {
                line.paragraph.first_indent
            } else {
                0.0
            };
        let tabbed = spans.iter().any(|s| s.text.contains('\t'));

        let styled = tabbed
            || indent != 0.0
            || spans.iter().any(|s| {
                s.color.is_some()
                    || s.face.is_some_and(|f| f != face)
                    || s.underline
                    || s.overline
                    || s.strike
                    || height_of(s) != base_height
            });

        // Nothing to place: hand the whole line over as one run.
        if !styled
            || spans.len() == 1
                && !spans[0].underline
                && !spans[0].overline
                && !spans[0].strike
                && spans[0].color.is_none()
        {
            let text: String = spans.iter().map(|s| s.text.as_str()).collect();
            let height = spans.first().map(height_of).unwrap_or(base_height);
            let face = spans.first().map(face_of).unwrap_or(face);
            self.push_text_run(
                text,
                x,
                y,
                height,
                rotation,
                1.0,
                0.0,
                h_align,
                text::VAlign::Baseline,
                ctx,
                rgba,
                attr,
                face,
            );
            return;
        }

        // Lay the line out from its own left edge first. A tab stop is measured
        // from there, not from the anchor, so alignment can only be applied
        // once the whole line has been placed.
        let mut placed: Vec<(usize, String, f64, f64)> = Vec::new();
        let mut cursor = indent;
        for (i, span) in spans.iter().enumerate() {
            let height = height_of(span);
            for (n, piece) in span.text.split('\t').enumerate() {
                if n > 0 {
                    cursor = next_tab_stop(cursor, &line.paragraph, base_height);
                }
                if piece.is_empty() {
                    continue;
                }
                // Each run is measured in its own face, since a `\f` in the
                // middle of a line changes how wide the rest of it sits.
                let width = font::Metrics::for_face(face_of(span)).measure(piece) * height;
                placed.push((i, piece.to_string(), cursor, width));
                cursor += width;
            }
        }

        let offset = match h_align {
            text::HAlign::Center | text::HAlign::Middle => -cursor / 2.0,
            text::HAlign::Right => -cursor,
            _ => 0.0,
        };

        let (sin_r, cos_r) = rotation.sin_cos();
        for (i, piece, start, width) in placed {
            let span = &spans[i];
            let along = start + offset;
            let width = &width;
            let height = height_of(span);
            let (rgba, attr) = match span.color {
                Some(c) => self.span_colour(c, rgba, attr),
                None => (rgba, attr),
            };
            self.push_text_run(
                piece,
                x + along * cos_r,
                y + along * sin_r,
                height,
                rotation,
                1.0,
                0.0,
                text::HAlign::Left,
                text::VAlign::Baseline,
                ctx,
                rgba,
                attr,
                face_of(span),
            );

            // The three rules, as strokes along the run at the usual offsets.
            for (on, dy) in [
                (span.underline, -0.25 * height),
                (span.overline, 1.15 * height),
                (span.strike, 0.4 * height),
            ] {
                if !on {
                    continue;
                }
                let a = ctx.xf.apply(
                    x + along * cos_r - dy * sin_r,
                    y + along * sin_r + dy * cos_r,
                );
                let b = ctx.xf.apply(
                    x + (along + width) * cos_r - dy * sin_r,
                    y + (along + width) * sin_r + dy * cos_r,
                );
                self.scene.push_stroke(a[0], a[1], b[0], b[1], rgba, attr);
            }
        }
    }

    /// Resolve an MTEXT colour escape against the entity's own colour.
    fn span_colour(&self, c: text::SpanColor, rgba: u32, attr: u32) -> (u32, u32) {
        let alpha = (rgba >> 24) as u8;
        let contrast_bit = (FLAG_CONTRAST as u32) << 24;
        match c {
            text::SpanColor::Index(i) => match colour_rgb(&Color::Index(i), self.palette) {
                Some((r, g, b)) => (
                    pack_rgba(r, g, b, alpha),
                    // Only colour 7 flips with the background.
                    if i == 7 {
                        attr | contrast_bit
                    } else {
                        attr & !contrast_bit
                    },
                ),
                None => (rgba, attr),
            },
            text::SpanColor::Rgb(r, g, b) => (pack_rgba(r, g, b, alpha), attr & !contrast_bit),
        }
    }

    /// Tessellate model space.
    pub fn run(&mut self) {
        self.run_block(MODEL_SPACE, false);
    }

    /// The drawing's layout tabs, model first then by tab order.
    pub fn layouts(&self) -> Vec<LayoutInfo> {
        let mut by_handle: HashMap<u64, &str> = HashMap::new();
        for b in self.doc.blocks.iter().rev() {
            by_handle.insert(b.record.0, b.name.as_str());
        }

        let mut out: Vec<LayoutInfo> = Vec::new();
        for l in &self.doc.layouts {
            let block = match by_handle.get(&l.block_record.0).copied() {
                Some(name) if !name.is_empty() && !l.block_record.is_null() => name.to_string(),
                // A layout whose block record did not resolve is only usable if
                // it is the model tab, whose block name is fixed.
                _ if l.name.eq_ignore_ascii_case("Model") => MODEL_SPACE.to_string(),
                _ => continue,
            };
            if out.iter().any(|o| o.block == block) {
                continue;
            }
            let limits = [
                l.limits_min.x,
                l.limits_min.y,
                l.limits_max.x,
                l.limits_max.y,
            ];
            out.push(LayoutInfo {
                is_model: block.eq_ignore_ascii_case(MODEL_SPACE),
                name: l.name.clone(),
                block,
                tab_order: l.tab_order,
                limits: (limits.iter().all(|v| v.is_finite())
                    && limits[2] > limits[0]
                    && limits[3] > limits[1])
                    .then_some(limits),
            });
        }

        // Some drawings carry no LAYOUT objects at all (R13 and R14 DWG
        // saved by AutoCAD before layouts): model space still draws, and so
        // does paper space when it has something, as the tab DXF's readers
        // give it (Layout1, with the header's paper-space limits).
        if !out.iter().any(|o| o.is_model) {
            out.push(LayoutInfo {
                name: "Model".to_string(),
                block: MODEL_SPACE.to_string(),
                is_model: true,
                tab_order: 0,
                limits: None,
            });
        }
        let paper = self
            .doc
            .block(PAPER_SPACE)
            .is_some_and(|b| !b.entities.is_empty());
        if self.doc.layouts.is_empty() && paper {
            let h = &self.doc.header;
            let limits = [h.plimmin.x, h.plimmin.y, h.plimmax.x, h.plimmax.y];
            out.push(LayoutInfo {
                name: "Layout1".to_string(),
                block: PAPER_SPACE.to_string(),
                is_model: false,
                tab_order: 1,
                limits: (limits.iter().all(|v| v.is_finite())
                    && limits[2] > limits[0]
                    && limits[3] > limits[1])
                    .then_some(limits),
            });
        }
        out.sort_by_key(|l| (!l.is_model, l.tab_order));
        out
    }

    /// Tessellate one layout tab by its name, as `layouts()` reports it.
    pub fn run_layout(&mut self, name: &str) -> bool {
        let Some(layout) = self
            .layouts()
            .into_iter()
            .find(|l| l.name.eq_ignore_ascii_case(name))
        else {
            return false;
        };
        let block = layout.block.clone();
        self.run_block(&block, !layout.is_model);
        // The sheet, not the contents: see `Scene::set_extents`.
        if let Some(l) = layout.limits.filter(|_| !layout.is_model) {
            self.scene.set_extents([l[0], l[1]], [l[2], l[3]]);
        }
        true
    }

    /// Walk one space's entities.
    ///
    /// `paper` turns on viewport handling: in a layout a VIEWPORT is a window
    /// onto model space and has to be drawn through, while in model space the
    /// same entity is just a saved screen split and draws nothing.
    fn run_block(&mut self, block: &str, paper: bool) {
        let ctx = self.root_ctx();
        let entities: &'a [Entity] = match self.block(block) {
            Some(b) => &b.entities,
            None => &[],
        };

        // The first VIEWPORT of a layout stands for the sheet as a whole rather
        // than a window onto the model, and drawing through it would paste
        // model space across the whole page. It is identified by position, in
        // document order: the viewport id that would name it is assigned at
        // runtime and reads back as zero here.
        let sheet_view = paper
            .then(|| {
                entities
                    .iter()
                    .find(|e| matches!(e.kind, EntityKind::Viewport(_)))
                    .map(|e| e.handle.0)
            })
            .flatten();

        let roots = self.in_draw_order(entities);
        for e in roots {
            if paper {
                if let EntityKind::Viewport(v) = &e.kind {
                    self.scene.order = self.scene.order.saturating_add(1);
                    if Some(e.handle.0) != sheet_view {
                        self.viewport(v);
                    }
                    continue;
                }
            }
            self.entity(e, &ctx);
        }
        self.flush_infinite_lines();
        // The viewport walk emits model geometry and then throws most of it
        // away, so the bounds it grew along the way are far too large.
        if paper {
            self.scene.recompute_extents();
        }
    }

    fn root_ctx(&self) -> Ctx {
        Ctx {
            xf: Affine::IDENTITY,
            layer: self.layer_id("0").unwrap_or(0),
            // Nothing is inside a block at the root, so ByBlock falls back to
            // colour 7, which is what AutoCAD shows for a stray ByBlock entity.
            rgba: pack_rgba(255, 255, 255, 255),
            contrast: true,
            lw: 0,
            lt: 0,
            lt_scale: 1.0,
            depth: 0,
        }
    }

    /// Draw model space through one layout viewport.
    fn viewport(&mut self, v: &crate::cad::Viewport) {
        if !v.is_on() {
            return;
        }
        if !(v.view_height.is_finite() && v.view_height > 0.0) {
            return;
        }
        if !(v.width.is_finite() && v.height.is_finite() && v.width > 0.0 && v.height > 0.0) {
            return;
        }
        // A view along anything but the Z axis is a 3D projection, which this
        // viewer does not do. Drawing the plan into it would be wrong, not
        // merely incomplete.
        if v.view_direction.z.abs() < 1e-9
            || (v.view_direction.x.abs() + v.view_direction.y.abs()) > 1e-6
        {
            return;
        }

        let xf = viewport_transform(
            [v.center.x, v.center.y],
            v.height,
            [v.view_center.x, v.view_center.y],
            [v.view_target.x, v.view_target.y],
            v.view_height,
            v.twist,
        );

        let shape = self.clip_shape(v);
        self.vp_frozen = v
            .frozen_layers
            .iter()
            .filter_map(|h| self.layer_by_handle.get(&h.0).copied())
            .collect();

        // PSLTSCALE 1, which is AutoCAD's default, means dash lengths are
        // measured in paper units even for model-space objects seen through a
        // viewport: a dashed line looks the same on the sheet whatever scale
        // each viewport is at. Cancelling the viewport's scale here is what
        // makes that true, since the transform would otherwise stretch the
        // dashes along with the geometry.
        let view_scale = xf.scale_magnitude();
        let lt_scale = if self.doc.header.psltscale && view_scale > 1e-12 {
            1.0 / view_scale
        } else {
            1.0
        };

        let ctx = Ctx {
            xf,
            lt_scale,
            ..self.root_ctx()
        };
        let mark = self.scene.mark();
        let model: &'a [Entity] = match self.block(MODEL_SPACE) {
            Some(b) => &b.entities,
            None => &[],
        };
        let roots = self.in_draw_order(model);
        for e in roots {
            self.entity(e, &ctx);
        }
        self.flush_infinite_lines();
        #[cfg(feature = "vp-debug")]
        {
            let (min, max) = shape.bounds();
            let mut lo = [f64::INFINITY; 2];
            let mut hi = [f64::NEG_INFINITY; 2];
            for s in &self.scene.strokes[mark.strokes()..] {
                for p in [[s.x0, s.y0], [s.x1, s.y1]] {
                    lo[0] = lo[0].min(p[0]);
                    lo[1] = lo[1].min(p[1]);
                    hi[0] = hi[0].max(p[0]);
                    hi[1] = hi[1].max(p[1]);
                }
            }
            let inside = self.scene.strokes[mark.strokes()..]
                .iter()
                .filter(|s| shape.contains([s.x0, s.y0]))
                .count();
            eprintln!(
                "vp clip=({:.1},{:.1})..({:.1},{:.1}) emitted={} inside={inside} bbox=({:.1},{:.1})..({:.1},{:.1})",
                min[0],
                min[1],
                max[0],
                max[1],
                self.scene.strokes.len() - mark.strokes(),
                lo[0],
                lo[1],
                hi[0],
                hi[1]
            );
        }
        self.scene.clip_since(mark, &shape);
        self.vp_frozen.clear();
    }

    /// The region a viewport keeps: its own rectangle, or the boundary entity
    /// a clipped viewport points at.
    fn clip_shape(&self, v: &crate::cad::Viewport) -> ClipShape {
        let rect = ClipShape::rect([v.center.x, v.center.y], v.width, v.height);
        if v.clip_boundary.is_null() {
            return rect;
        }
        // The boundary is an entity of the same layout as a rule; viewports
        // are few, so a walk over the blocks to find it is cheap.
        let Some(e) = self
            .doc
            .blocks
            .iter()
            .flat_map(|b| b.entities.iter())
            .find(|e| e.handle == v.clip_boundary)
        else {
            return rect;
        };
        let outline = match &e.kind {
            EntityKind::LwPolyline(p) => {
                let pts: Vec<([f64; 2], f64)> = p
                    .vertices
                    .iter()
                    .map(|x| ([x.point.x, x.point.y], x.bulge))
                    .collect();
                expand_bulges(&pts, true)
            }
            EntityKind::Polyline(p) if p.kind() == PolylineKind::Polyline2D => {
                let pts: Vec<([f64; 2], f64)> = p
                    .vertices
                    .iter()
                    .map(|x| ([x.location.x, x.location.y], x.bulge))
                    .collect();
                expand_bulges(&pts, true)
            }
            EntityKind::Circle(c) => curves::flatten_circle(c.center.x, c.center.y, c.radius),
            EntityKind::Ellipse(el) => curves::flatten_ellipse(
                el.center.x,
                el.center.y,
                el.major_axis.x,
                el.major_axis.y,
                el.ratio,
                el.start_param,
                el.end_param,
            ),
            _ => return rect,
        };
        ClipShape::polygon(outline).unwrap_or(rect)
    }

    /// The key this entity is sorted by when painting. Exposed for diagnostics.
    pub fn draw_key(&self, e: &Entity) -> u64 {
        let h = e.handle.0;
        self.sort_keys.get(&h).copied().unwrap_or(h)
    }

    /// Drop the accumulated geometry, keeping the parsed tables.
    ///
    /// Building a tessellator resolves the layer, linetype and draw-order
    /// tables, which is linear in the size of the drawing. Diagnostics that
    /// inspect one entity at a time must reuse a single tessellator and clear
    /// between entities; constructing one per entity is quadratic and, on a
    /// drawing with a 100k-entry draw-order table, unusably slow.
    pub fn clear_scene(&mut self) {
        self.scene = Scene::new();
        self.warnings = Warnings::default();
        self.stack.clear();
    }

    /// Tessellate a single entity at the root context, block expansion
    /// included. Exposed for diagnostics and tests that need to attribute
    /// emitted geometry back to the entity that produced it.
    pub fn tessellate_entity(&mut self, e: &Entity) {
        let ctx = self.root_ctx();
        self.entity(e, &ctx);
    }

    /// Resolve layer, colour, lineweight and flags for an entity in a given
    /// context. Returns None when the entity should not be drawn at all.
    fn resolve(&self, common: &Entity, ctx: &Ctx) -> Option<(u16, u32, u8, u8)> {
        if common.invisible {
            return None;
        }

        // Inside a block, geometry on layer "0" adopts the insert's layer.
        // At the root, ctx.layer *is* layer "0", so this is a no-op there.
        let lid = if common.layer == "0" || common.layer.is_empty() {
            ctx.layer
        } else {
            match self.layer_id(&common.layer) {
                Some(id) => id,
                // Reference to a layer that is not in the table: fall back to
                // the inherited one rather than dropping the geometry.
                None => ctx.layer,
            }
        };

        // VPLAYER freeze: off in this viewport only.
        if !self.vp_frozen.is_empty() && self.vp_frozen.contains(&lid) {
            return None;
        }

        let layer = &self.layers[lid as usize];

        // Colour 7 flips with the background; every other colour, including a
        // true colour that happens to be white, is drawn as stored.
        let (rgba, contrast) = match common.color {
            Color::ByLayer => (layer.rgba, layer.contrast),
            Color::ByBlock => (ctx.rgba, ctx.contrast),
            ref c => {
                let (r, g, b) = colour_rgb(c, self.palette)?;
                let alpha = match common.transparency {
                    Transparency::Alpha(a) => a,
                    Transparency::ByBlock => (ctx.rgba >> 24) as u8,
                    Transparency::ByLayer => (layer.rgba >> 24) as u8,
                };
                (pack_rgba(r, g, b, alpha), is_contrast_color(c))
            }
        };
        let flags = if contrast { FLAG_CONTRAST } else { 0 };

        let lw = match common.lineweight {
            LineWeight::ByLayer => layer.lineweight,
            LineWeight::ByBlock => ctx.lw,
            other => lineweight_value(other, 0),
        };

        Some((lid, rgba, lw, flags))
    }

    fn entity(&mut self, e: &Entity, outer: &Ctx) {
        // Advance the draw order for every entity, drawn or not, so the
        // sequence matches the document's own.
        self.scene.order = self.scene.order.saturating_add(1);
        if self.scene_full() {
            self.warnings.scene_truncated = self.warnings.scene_truncated.saturating_add(1);
            return;
        }

        let Some((lid, rgba, lw, flags)) = self.resolve(e, outer) else {
            return;
        };
        let attr = pack_attr(lid, lw, flags);
        let contrast = flags & FLAG_CONTRAST != 0;

        let lt = self.linetype_of(&e.linetype, &self.layers[lid as usize], outer);

        // Fold the entity's own object-coordinate frame into the transform, so
        // every arm below can work in world coordinates.
        let owned;
        let ctx = match ocs_of(&e.kind) {
            Some(ocs) => {
                owned = Ctx {
                    xf: outer.xf.mul(&ocs),
                    ..*outer
                };
                &owned
            }
            None => outer,
        };
        let xf = &ctx.xf;

        // Dash pattern in world units. Block scaling stretches it, the way
        // AutoCAD scales a linetype with the block it lives in.
        let pattern = self.pattern_for(lt, e.linetype_scale, xf.scale_magnitude() * ctx.lt_scale);
        let pattern = pattern.as_ref();

        match &e.kind {
            EntityKind::Line(l) => {
                let a = xf.apply(l.start.x, l.start.y);
                let b = xf.apply(l.end.x, l.end.y);
                self.push_path(&[a, b], false, rgba, attr, pattern);
            }

            EntityKind::Circle(c) => {
                let pts = curves::flatten_circle(c.center.x, c.center.y, c.radius);
                self.push_transformed(&pts, false, xf, rgba, attr, pattern);
            }

            EntityKind::Arc(a) => {
                let pts = curves::flatten_arc(
                    a.center.x,
                    a.center.y,
                    a.radius,
                    a.start_angle,
                    a.end_angle,
                );
                self.push_transformed(&pts, false, xf, rgba, attr, pattern);
            }

            EntityKind::Ellipse(el) => {
                let pts = curves::flatten_ellipse(
                    el.center.x,
                    el.center.y,
                    el.major_axis.x,
                    el.major_axis.y,
                    el.ratio,
                    el.start_param,
                    el.end_param,
                );
                self.push_transformed(&pts, false, xf, rgba, attr, pattern);
            }

            EntityKind::LwPolyline(p) => {
                let pts: Vec<([f64; 2], f64)> = p
                    .vertices
                    .iter()
                    .map(|v| ([v.point.x, v.point.y], v.bulge))
                    .collect();
                let closed = p.is_closed();
                let flat = expand_bulges(&pts, closed);
                self.push_transformed(&flat, closed, xf, rgba, attr, pattern);
            }

            EntityKind::Polyline(p) if p.kind() == PolylineKind::Polyline2D => {
                let pts: Vec<([f64; 2], f64)> = p
                    .vertices
                    .iter()
                    .map(|v| ([v.location.x, v.location.y], v.bulge))
                    .collect();
                let closed = p.is_closed();
                let flat = expand_bulges(&pts, closed);
                self.push_transformed(&flat, closed, xf, rgba, attr, pattern);
            }

            EntityKind::Polyline(p) if p.kind() == PolylineKind::Polyline3D => {
                let pts: Vec<[f64; 2]> = p
                    .vertices
                    .iter()
                    .map(|v| [v.location.x, v.location.y])
                    .collect();
                self.push_transformed(&pts, p.is_closed(), xf, rgba, attr, pattern);
            }

            EntityKind::Spline(s) => {
                let pts = spline_points(s);
                self.push_transformed(&pts, false, xf, rgba, attr, pattern);
            }

            EntityKind::Point(p) => {
                // Zero-length stroke; the renderer draws it as a round dot.
                let a = xf.apply(p.location.x, p.location.y);
                self.scene.push_stroke(a[0], a[1], a[0], a[1], rgba, attr);
            }

            EntityKind::Solid(s) | EntityKind::Trace(s) => {
                // SOLID and TRACE store their corners in Z order, so corners 3
                // and 4 are swapped relative to polygon winding.
                let c = &s.corners;
                let q = [
                    xf.apply(c[0].x, c[0].y),
                    xf.apply(c[1].x, c[1].y),
                    xf.apply(c[3].x, c[3].y),
                    xf.apply(c[2].x, c[2].y),
                ];
                self.scene.push_triangle(q[0], q[1], q[2], rgba, attr);
                self.scene.push_triangle(q[0], q[2], q[3], rgba, attr);
            }

            EntityKind::Face3D(f) => {
                let c = &f.corners;
                let q = [
                    xf.apply(c[0].x, c[0].y),
                    xf.apply(c[1].x, c[1].y),
                    xf.apply(c[2].x, c[2].y),
                    xf.apply(c[3].x, c[3].y),
                ];
                // 3DFACE is an outline in a 2D view, not a filled region.
                self.push_path(&q, true, rgba, attr, pattern);
            }

            EntityKind::MLine(m) => {
                // Each style element is its own parallel run, offset from the
                // vertex along that vertex's miter direction.
                let elements = m
                    .vertices
                    .iter()
                    .map(|v| v.elements.len())
                    .max()
                    .unwrap_or(0);
                if elements == 0 {
                    // No element data: fall back to the spine.
                    let pts: Vec<[f64; 2]> = m
                        .vertices
                        .iter()
                        .map(|v| [v.position.x, v.position.y])
                        .collect();
                    self.push_transformed(&pts, m.is_closed(), xf, rgba, attr, pattern);
                } else {
                    for e in 0..elements {
                        let pts: Vec<[f64; 2]> = m
                            .vertices
                            .iter()
                            .map(|v| {
                                let off = v
                                    .elements
                                    .get(e)
                                    .and_then(|s| s.parameters.first().copied())
                                    .unwrap_or(0.0)
                                    * m.scale;
                                [
                                    v.position.x + v.miter.x * off,
                                    v.position.y + v.miter.y * off,
                                ]
                            })
                            .collect();
                        self.push_transformed(&pts, m.is_closed(), xf, rgba, attr, pattern);
                    }
                }
            }

            EntityKind::Helix(h) => {
                // A helix carries its own spline; in plan view that is the
                // projected spiral.
                let pts = if !h.spline.control_points.is_empty() {
                    let ctrl: Vec<[f64; 2]> =
                        h.spline.control_points.iter().map(|p| [p.x, p.y]).collect();
                    curves::flatten_spline(
                        h.spline.degree.max(0) as usize,
                        &h.spline.knots,
                        &ctrl,
                        &h.spline.weights,
                        h.spline.is_closed(),
                    )
                } else {
                    // Rebuild it parametrically when the spline is absent.
                    helix_points(h)
                };
                self.push_transformed(&pts, false, xf, rgba, attr, pattern);
            }

            EntityKind::Hatch(h) => self.hatch(h, ctx, rgba, attr),

            EntityKind::Insert(ins) => self.insert(ins, ctx, lid, rgba, contrast, lw, lt),

            EntityKind::Dimension(d) => {
                // AutoCAD bakes dimension graphics into an anonymous block.
                // Render that instead of reimplementing the dimension engine.
                let base = d;
                let child = Affine::new(
                    base.insertion_point.x,
                    base.insertion_point.y,
                    if base.insertion_scale.x != 0.0 {
                        base.insertion_scale.x
                    } else {
                        1.0
                    },
                    if base.insertion_scale.y != 0.0 {
                        base.insertion_scale.y
                    } else {
                        1.0
                    },
                    base.insertion_rotation,
                );
                self.expand_block(
                    &base.block_name,
                    &ctx.xf.mul(&child),
                    lid,
                    rgba,
                    contrast,
                    lw,
                    lt,
                    ctx.lt_scale,
                    ctx.depth,
                );
            }

            EntityKind::Text(t) => self.text(t, ctx, rgba, attr),

            EntityKind::Attribute(a) => self.attribute_text(&a.text, ctx, rgba, attr),

            EntityKind::MText(m) => {
                let height = if m.height > 0.0 { m.height } else { 1.0 };
                let face = self.style_face(&m.style);
                let lines = self.wrap_mtext(&m.text, m.reference_width, height, face);
                let spacing = height
                    * text::MTEXT_LINE_SPACING
                    * if m.line_spacing_factor > 0.0 {
                        m.line_spacing_factor
                    } else {
                        1.0
                    };

                // DWG stores the text direction as a vector when it has one.
                let rotation = match m.x_direction {
                    Some(d) if d.x != 0.0 || d.y != 0.0 => d.y.atan2(d.x),
                    _ => m.rotation,
                };
                let (h_align, dy0) =
                    text::mtext_layout(m.attachment as u8, lines.len(), height, spacing);

                let (sin_r, cos_r) = rotation.sin_cos();
                for (i, line) in lines.iter().enumerate() {
                    if line.spans.is_empty() {
                        continue;
                    }
                    // Lines stack along the text's own down direction.
                    let dy = dy0 - i as f64 * spacing;
                    let x = m.insertion.x - dy * sin_r;
                    let y = m.insertion.y + dy * cos_r;
                    self.push_mtext_line(
                        line, height, x, y, rotation, h_align, ctx, rgba, attr, face,
                    );
                }
            }

            // An ordinary ATTDEF is the template for an ATTRIB carried by the
            // insert, so drawing it too would double the text. A *constant*
            // attribute has no ATTRIB: the definition is the only copy, and
            // AutoCAD draws it.
            EntityKind::AttributeDefinition(a) if a.is_constant() => {
                self.attribute_text(&a.text, ctx, rgba, attr)
            }
            EntityKind::AttributeDefinition(_) => {}

            // Unbounded geometry cannot be tessellated before the drawing's
            // own extents are known, so it is held back and clipped to them
            // once the rest of the walk is done.
            EntityKind::Ray(r) => self.pending_infinite.push(InfiniteLine {
                base: xf.apply(r.base.x, r.base.y),
                dir: [
                    xf.a * r.direction.x + xf.c * r.direction.y,
                    xf.b * r.direction.x + xf.d * r.direction.y,
                ],
                both_ways: false,
                rgba,
                attr,
            }),
            EntityKind::XLine(l) => self.pending_infinite.push(InfiniteLine {
                base: xf.apply(l.base.x, l.base.y),
                dir: [
                    xf.a * l.direction.x + xf.c * l.direction.y,
                    xf.b * l.direction.x + xf.d * l.direction.y,
                ],
                both_ways: true,
                rgba,
                attr,
            }),

            // A WIPEOUT blanks everything beneath it. Its boundary is given in
            // image pixel coordinates along the u and v vectors.
            EntityKind::Wipeout(w) => {
                let to_world = |p: [f64; 2]| {
                    let x =
                        w.insertion.x + w.u_vector.x * (p[0] + 0.5) + w.v_vector.x * (p[1] + 0.5);
                    let y =
                        w.insertion.y + w.u_vector.y * (p[0] + 0.5) + w.v_vector.y * (p[1] + 0.5);
                    xf.apply(x, y)
                };
                let v = &w.clip_vertices;
                let poly: Vec<[f64; 2]> = if v.len() == 2 {
                    // Two vertices means opposite corners of a rectangle.
                    let (a, b) = (v[0], v[1]);
                    vec![[a.x, a.y], [b.x, a.y], [b.x, b.y], [a.x, b.y]]
                } else {
                    v.iter().map(|p| [p.x, p.y]).collect()
                };
                if poly.len() >= 3 {
                    let world: Vec<[f64; 2]> = poly.into_iter().map(to_world).collect();
                    let masked = pack_attr(lid, lw, FILL_FLAG_BACKGROUND);
                    for t in fill::fill_even_odd(&[world]).chunks(3) {
                        if t.len() == 3 {
                            self.scene.push_triangle(t[0], t[1], t[2], rgba, masked);
                        }
                    }
                }
            }

            // A TABLE draws through an anonymous block, the same trick
            // dimensions use.
            EntityKind::Table(t) => {
                let child = Affine::new(
                    t.insertion.x,
                    t.insertion.y,
                    1.0,
                    1.0,
                    t.horizontal_direction.y.atan2(t.horizontal_direction.x),
                );
                self.expand_block(
                    &t.block_name,
                    &ctx.xf.mul(&child),
                    lid,
                    rgba,
                    contrast,
                    lw,
                    lt,
                    ctx.lt_scale,
                    ctx.depth,
                );
            }

            EntityKind::MultiLeader(m) => self.multi_leader(m, ctx, rgba, attr),

            // The pre-2007 LEADER: a path, an optional arrowhead, and an
            // annotation that is a separate entity drawn on its own.
            EntityKind::Leader(l) => {
                let pts: Vec<[f64; 2]> = l.vertices.iter().map(|v| [v.x, v.y]).collect();
                if pts.len() < 2 {
                    return;
                }
                // Group 72: 1 is a spline path.
                if l.path_type == 1 {
                    let curve = curves::fit_spline(&pts, None, None, false);
                    self.push_transformed(&curve, false, xf, rgba, attr, pattern);
                } else {
                    self.push_transformed(&pts, false, xf, rgba, attr, pattern);
                }

                if l.arrowhead {
                    // A filled triangle at the first vertex, pointing back
                    // along the first segment, as long as the dimension
                    // style's arrow size (DIMASZ times DIMSCALE) and a third
                    // as wide: AutoCAD's default closed filled arrowhead.
                    let size = self.arrow_size(&l.style);
                    let d = [pts[1][0] - pts[0][0], pts[1][1] - pts[0][1]];
                    let len = d[0].hypot(d[1]);
                    if size > 0.0 && len > 1e-9 {
                        let u = [d[0] / len, d[1] / len];
                        let n = [-u[1], u[0]];
                        let base = [pts[0][0] + u[0] * size, pts[0][1] + u[1] * size];
                        let half = size / 6.0;
                        self.scene.push_triangle(
                            xf.apply(pts[0][0], pts[0][1]),
                            xf.apply(base[0] + n[0] * half, base[1] + n[1] * half),
                            xf.apply(base[0] - n[0] * half, base[1] - n[1] * half),
                            rgba,
                            attr,
                        );
                    }
                }
            }

            // The three that reference a file this viewer was never given. All
            // that can be drawn is the frame, which is what AutoCAD shows for
            // an image it cannot load, and the count so the host can say so.
            EntityKind::Image(img) => {
                self.warnings.external_references += 1;
                let u = [img.u_vector.x, img.u_vector.y];
                let v = [img.v_vector.x, img.v_vector.y];
                let o = [img.insertion.x, img.insertion.y];
                let (w, h) = (img.size.x, img.size.y);
                let corner = |a: f64, b: f64| {
                    [
                        o[0] + u[0] * a * w + v[0] * b * h,
                        o[1] + u[1] * a * w + v[1] * b * h,
                    ]
                };
                let frame = [
                    corner(0.0, 0.0),
                    corner(1.0, 0.0),
                    corner(1.0, 1.0),
                    corner(0.0, 1.0),
                ];
                self.push_transformed(&frame, true, xf, rgba, attr, pattern);
            }

            EntityKind::Underlay(u) => {
                self.warnings.external_references += 1;
                if u.clip_vertices.len() >= 2 {
                    let pts: Vec<[f64; 2]> = u.clip_vertices.iter().map(|p| [p.x, p.y]).collect();
                    // Two points are the corners of a rectangle, more are a path.
                    let frame = if pts.len() == 2 {
                        vec![
                            pts[0],
                            [pts[1][0], pts[0][1]],
                            pts[1],
                            [pts[0][0], pts[1][1]],
                        ]
                    } else {
                        pts
                    };
                    let placed = Affine::new(
                        u.insertion.x,
                        u.insertion.y,
                        if u.scale.x != 0.0 { u.scale.x } else { 1.0 },
                        if u.scale.y != 0.0 { u.scale.y } else { 1.0 },
                        u.rotation,
                    );
                    self.push_transformed(&frame, true, &xf.mul(&placed), rgba, attr, pattern);
                }
            }

            EntityKind::Ole2Frame(o) => {
                self.warnings.external_references += 1;
                let (a, b) = (o.upper_left, o.lower_right);
                let frame = [[a.x, a.y], [b.x, a.y], [b.x, b.y], [a.x, b.y]];
                self.push_transformed(&frame, true, xf, rgba, attr, pattern);
            }

            // A viewport is structural, not drawable in model space.
            EntityKind::Viewport(_) => {}

            // A custom entity draws what its application saved with it.
            EntityKind::Unknown(u) if u.graphics.as_ref().is_some_and(|g| g.draws()) => {
                if let Some(g) = &u.graphics {
                    let pieces = Ctx {
                        depth: ctx.depth + 1,
                        ..*ctx
                    };
                    self.proxy(g, e, &pieces);
                }
            }
            EntityKind::Unknown(u) if u.is_custom() => {
                self.warnings.proxy_without_graphics += 1;
            }

            // Meshes, SHAPE (a glyph of an SHX file, which cannot be shipped)
            // and every other type the model does not hold.
            EntityKind::Polyline(_) | EntityKind::Shape(_) | EntityKind::Unknown(_) => {
                self.warnings.unknown_entities += 1;
            }
        }
    }

    /// Proxy graphics, as the pieces [`proxy::explode`] makes of them, in
    /// the custom entity's own context.
    fn proxy(&mut self, g: &crate::cad::ProxyGraphics, owner: &Entity, ctx: &Ctx) {
        for piece in proxy::explode(g, owner, self.doc) {
            if self.scene_full() {
                break;
            }
            match piece.fill {
                None => self.entity(&piece.entity, ctx),
                Some(loops) => {
                    let Some((lid, rgba, lw, flags)) = self.resolve(&piece.entity, ctx) else {
                        continue;
                    };
                    let attr = pack_attr(lid, lw, flags);
                    let world: Vec<Vec<[f64; 2]>> = loops
                        .iter()
                        .map(|l| l.iter().map(|p| ctx.xf.apply(p[0], p[1])).collect())
                        .collect();
                    for t in fill::fill_even_odd(&world).chunks(3) {
                        if let [a, b, c] = t {
                            self.scene.push_triangle(*a, *b, *c, rgba, attr);
                        }
                    }
                }
            }
        }
    }

    /// TEXT. Any alignment other than the default measures from the second
    /// alignment point rather than the insertion point.
    fn text(&mut self, t: &crate::cad::Text, ctx: &Ctx, rgba: u32, attr: u32) {
        let default_align = t.h_align == HAlign::Left && t.v_align == VAlign::Baseline;
        let anchor = if default_align {
            t.insertion
        } else {
            t.alignment_point.unwrap_or(t.insertion)
        };
        let value = text::decode_special(&t.value);

        // Aligned and Fit stretch the string between two points rather than
        // anchoring it at one, so they need its width. Aligned scales the
        // height with it; Fit keeps the height and squeezes the glyphs
        // instead.
        let stretched = matches!(t.h_align, HAlign::Aligned | HAlign::Fit);
        let face = self.style_face(&t.style);
        if stretched {
            if let Some(second) = t.alignment_point {
                let first = t.insertion;
                let span = (second.x - first.x).hypot(second.y - first.y);
                let natural = font::Metrics::for_face(face).measure(&value) * t.height;
                if span > 1e-9 && natural > 1e-9 {
                    let factor = span / natural;
                    let fit = t.h_align == HAlign::Fit;
                    self.push_text_run(
                        value,
                        first.x,
                        first.y,
                        if fit { t.height } else { t.height * factor },
                        (second.y - first.y).atan2(second.x - first.x),
                        if fit { factor } else { 1.0 },
                        t.oblique,
                        text::HAlign::Left,
                        v_align_of(t.v_align),
                        ctx,
                        rgba,
                        attr,
                        face,
                    );
                    return;
                }
            }
        }

        self.push_text_run(
            value,
            anchor.x,
            anchor.y,
            t.height,
            t.rotation,
            t.width_factor,
            t.oblique,
            h_align_of(t.h_align),
            v_align_of(t.v_align),
            ctx,
            rgba,
            attr,
            face,
        );
    }

    /// The text of an ATTRIB, or of a constant ATTDEF: anchored like TEXT,
    /// without its Aligned and Fit stretching.
    fn attribute_text(&mut self, t: &crate::cad::Text, ctx: &Ctx, rgba: u32, attr: u32) {
        let default_align = t.h_align == HAlign::Left && t.v_align == VAlign::Baseline;
        let anchor = if default_align {
            t.insertion
        } else {
            t.alignment_point.unwrap_or(t.insertion)
        };
        let face = self.style_face(&t.style);
        self.push_text_run(
            text::decode_special(&t.value),
            anchor.x,
            anchor.y,
            t.height,
            t.rotation,
            t.width_factor,
            t.oblique,
            h_align_of(t.h_align),
            v_align_of(t.v_align),
            ctx,
            rgba,
            attr,
            face,
        );
    }

    /// Record a text run, carrying the block transform into its placement.
    ///
    /// A run on a stroke face is drawn here as geometry rather than handed to
    /// the host, which is what lets the drawing's lineweight decide how thick
    /// its letters are.
    #[allow(clippy::too_many_arguments)]
    fn push_text_run(
        &mut self,
        value: String,
        x: f64,
        y: f64,
        height: f64,
        rotation: f64,
        width_factor: f64,
        oblique: f64,
        h_align: text::HAlign,
        v_align: text::VAlign,
        ctx: &Ctx,
        rgba: u32,
        attr: u32,
        face: font::Face,
    ) {
        if value.trim().is_empty() {
            return;
        }
        let p = ctx.xf.apply(x, y);
        // Blocks rotate and scale their contents, so the text follows.
        let block_rotation = ctx.xf.b.atan2(ctx.xf.a);
        let scale = ctx.xf.scale_magnitude();
        self.warnings.text_runs += 1;
        let run = text::TextRun {
            x: p[0],
            y: p[1],
            height: if height > 0.0 { height * scale } else { scale },
            rotation: rotation + block_rotation,
            width_factor: if width_factor > 0.0 {
                width_factor
            } else {
                1.0
            },
            oblique,
            rgba,
            attr,
            h_align,
            v_align,
            text: value,
            face,
            order: self.scene.order,
        };
        match face {
            font::Face::Stroke => self.push_stroke_text(&run),
            font::Face::TrueType(_) => self.scene.push_text(run),
        }
    }

    /// Draw a run with the bundled stroke font, as geometry.
    ///
    /// This repeats the placement the host does for an outline run (anchor,
    /// width factor, oblique slant, rotation) because a stroke run never
    /// reaches the host to have it done there. The payoff is that every
    /// attribute already on the run applies for free: lineweight, colour, draw
    /// order, layer visibility and viewport clipping all come from `attr`.
    fn push_stroke_text(&mut self, run: &text::TextRun) {
        let stroke = super::stroke_font::newstroke();
        let height = run.height;
        if !(height > 0.0) {
            return;
        }
        let advance_scale = height * run.width_factor;
        let width: f64 = run
            .text
            .chars()
            .map(|c| stroke.advance(c) as f64 * advance_scale)
            .sum();

        // Aligned and Fit stretch between two points the record does not carry,
        // so they centre, as the host's path does.
        let dx = match run.h_align {
            text::HAlign::Center
            | text::HAlign::Middle
            | text::HAlign::Aligned
            | text::HAlign::Fit => -width / 2.0,
            text::HAlign::Right => -width,
            text::HAlign::Left => 0.0,
        };
        let dy = match run.v_align {
            text::VAlign::Middle => -height / 2.0,
            text::VAlign::Top => -height,
            text::VAlign::Baseline | text::VAlign::Bottom => 0.0,
        };

        let (sin_r, cos_r) = run.rotation.sin_cos();
        let tan_o = if run.oblique.abs() < std::f64::consts::FRAC_PI_2 {
            run.oblique.tan()
        } else {
            0.0
        };

        let mut pen = dx;
        let mut points: Vec<[f64; 2]> = Vec::new();
        self.warnings.stroke_glyphs += run.text.chars().count() as u32;
        for c in run.text.chars() {
            // A character the font lacks draws its "?" rather than a hole.
            if let Some(glyph) = stroke.glyph(c).or_else(|| stroke.glyph('?')) {
                for polyline in glyph.polylines() {
                    points.clear();
                    for p in polyline.points() {
                        // Glyph units are cap heights, so the text height is
                        // the only scale there is.
                        let gx = pen + p[0] as f64 * advance_scale;
                        let gy = dy + p[1] as f64 * height;
                        // Oblique leans the vertical, shifting x by height.
                        let sx = gx + gy * tan_o;
                        points.push([
                            run.x + sx * cos_r - gy * sin_r,
                            run.y + sx * sin_r + gy * cos_r,
                        ]);
                    }
                    self.scene.push_polyline(&points, false, run.rgba, run.attr);
                }
            }
            pen += stroke.advance(c) as f64 * advance_scale;
        }
    }

    fn push_transformed(
        &mut self,
        pts: &[[f64; 2]],
        closed: bool,
        xf: &Affine,
        rgba: u32,
        attr: u32,
        pattern: Option<&Pattern>,
    ) {
        if pts.len() < 2 {
            return;
        }
        let t: Vec<[f64; 2]> = pts.iter().map(|p| xf.apply(p[0], p[1])).collect();
        self.push_path(&t, closed, rgba, attr, pattern);
    }

    /// Emit a world-space path, dashed if the entity's linetype calls for it.
    fn push_path(
        &mut self,
        pts: &[[f64; 2]],
        closed: bool,
        rgba: u32,
        attr: u32,
        pattern: Option<&Pattern>,
    ) {
        if let Some(p) = pattern {
            // None means the pattern was too fine to be worth resolving, so
            // fall through to a solid line rather than emit millions of dashes.
            if let Some(segments) = dash_polyline(pts, closed, p) {
                for seg in segments {
                    self.scene
                        .push_stroke(seg[0][0], seg[0][1], seg[1][0], seg[1][1], rgba, attr);
                }
                self.push_line_labels(pts, closed, p, rgba, attr);
                return;
            }
        }
        self.scene.push_polyline(pts, closed, rgba, attr);
    }

    /// Stamp a complex linetype's text along a path it has just dashed.
    fn push_line_labels(
        &mut self,
        pts: &[[f64; 2]],
        closed: bool,
        pattern: &Pattern,
        rgba: u32,
        attr: u32,
    ) {
        if pattern.labels.is_empty() {
            return;
        }
        for place in linetype::dash_labels(pts, closed, pattern) {
            let label = &pattern.labels[place.label];
            let run = text::TextRun {
                x: place.x,
                y: place.y,
                height: label.height,
                rotation: place.angle,
                width_factor: 1.0,
                oblique: 0.0,
                rgba,
                attr,
                h_align: text::HAlign::Left,
                v_align: text::VAlign::Baseline,
                text: label.text.clone(),
                face: label.face,
                order: self.scene.order,
            };
            self.warnings.text_runs += 1;
            match label.face {
                font::Face::Stroke => self.push_stroke_text(&run),
                font::Face::TrueType(_) => self.scene.push_text(run),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn insert(
        &mut self,
        ins: &crate::cad::Insert,
        ctx: &Ctx,
        lid: u16,
        rgba: u32,
        contrast: bool,
        lw: u8,
        lt: usize,
    ) {
        let sx = if ins.scale.x != 0.0 { ins.scale.x } else { 1.0 };
        let sy = if ins.scale.y != 0.0 { ins.scale.y } else { 1.0 };

        // MINSERT repeats the block on a grid; a plain insert yields one point.
        // Walked rather than collected (65535 by 65535 points on a damaged
        // file), and left as soon as the scene is full.
        let (sin_r, cos_r) = ins.rotation.sin_cos();
        let columns = ins.columns;
        let grid = (0..ins.rows).flat_map(|row| (0..columns).map(move |col| (row, col)));
        for (row, col) in grid {
            if self.scene_full() {
                self.warnings.scene_truncated = self.warnings.scene_truncated.saturating_add(1);
                break;
            }
            let (dx, dy) = (
                col as f64 * ins.column_spacing,
                row as f64 * ins.row_spacing,
            );
            let p = [
                ins.insertion.x + dx * cos_r - dy * sin_r,
                ins.insertion.y + dx * sin_r + dy * cos_r,
            ];
            let child = Affine::new(p[0], p[1], sx, sy, ins.rotation);
            self.expand_block(
                &ins.block_name,
                &ctx.xf.mul(&child),
                lid,
                rgba,
                contrast,
                lw,
                lt,
                ctx.lt_scale,
                ctx.depth,
            );
        }

        // The insert's attributes (title-block fields, room tags) are not in
        // the block: each carries its own placement, in the insert's own
        // space, and takes the insert's properties where it says ByBlock.
        let attr_ctx = Ctx {
            xf: ctx.xf,
            layer: lid,
            rgba,
            contrast,
            lw,
            lt,
            lt_scale: ctx.lt_scale,
            depth: ctx.depth + 1,
        };
        for a in &ins.attributes {
            if let EntityKind::Attribute(at) = &a.kind {
                if !at.is_invisible() {
                    self.entity(a, &attr_ctx);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn expand_block(
        &mut self,
        block_name: &str,
        xf: &Affine,
        lid: u16,
        rgba: u32,
        contrast: bool,
        lw: u8,
        lt: usize,
        lt_scale: f64,
        depth: u32,
    ) {
        if block_name.is_empty() {
            return;
        }
        if depth >= MAX_BLOCK_DEPTH {
            self.warnings.depth_exceeded += 1;
            return;
        }
        let key = normalize(block_name);
        if self.stack.contains(&key) {
            // Cyclic block reference in a damaged file.
            self.warnings.depth_exceeded += 1;
            return;
        }

        let Some(block) = self.block(block_name) else {
            self.warnings.missing_blocks += 1;
            return;
        };

        // Block geometry is defined relative to the block's base point.
        let base = block.base_point;
        let local = xf.mul(&Affine {
            a: 1.0,
            b: 0.0,
            c: 0.0,
            d: 1.0,
            e: -base.x,
            f: -base.y,
        });

        // Blocks carry their own sort table, so order them too.
        let children = self.in_draw_order(&block.entities);
        if children.is_empty() {
            return;
        }

        let child_ctx = Ctx {
            xf: local,
            layer: lid,
            rgba,
            contrast,
            lw,
            lt,
            lt_scale,
            depth: depth + 1,
        };

        self.stack.push(key);
        for e in children {
            self.entity(e, &child_ctx);
        }
        self.stack.pop();
    }

    fn hatch(&mut self, h: &crate::cad::Hatch, ctx: &Ctx, rgba: u32, attr: u32) {
        use crate::cad::BoundaryData;

        // Flatten every loop to a point list in drawing coordinates.
        let mut loops: Vec<hatch::Loop> = Vec::new();
        for path in &h.paths {
            let mut pts: Vec<[f64; 2]> = Vec::new();
            let edges: &[Edge] = match &path.data {
                BoundaryData::Polyline { closed, vertices } => {
                    let vs: Vec<([f64; 2], f64)> =
                        vertices.iter().map(|(p, b)| ([p.x, p.y], *b)).collect();
                    pts.extend(expand_bulges(&vs, *closed));
                    &[]
                }
                BoundaryData::Edges(edges) => edges,
            };
            for edge in edges {
                match edge {
                    Edge::Line { start, end } => {
                        if pts.is_empty() {
                            pts.push([start.x, start.y]);
                        }
                        pts.push([end.x, end.y]);
                    }
                    Edge::Arc {
                        center,
                        radius,
                        start_angle,
                        end_angle,
                        counter_clockwise,
                    } => {
                        // A clockwise boundary arc is stored in a frame mirrored
                        // about the centre's horizontal axis, so its angles are
                        // negated. Taking them at face value puts the arc on the
                        // opposite side of its centre: for a kerb radius of
                        // 42564 that lands the "boundary" 85000 units from the
                        // lines it is supposed to join, and the solid fill
                        // becomes a disc covering the sheet. Negating makes the
                        // endpoints meet the adjoining edges exactly.
                        let (s, e) = if *counter_clockwise {
                            (*start_angle, *end_angle)
                        } else {
                            (-end_angle, -start_angle)
                        };
                        let mut seg = curves::flatten_arc(center.x, center.y, *radius, s, e);
                        if !counter_clockwise {
                            seg.reverse();
                        }
                        pts.extend(seg);
                    }
                    Edge::Ellipse {
                        center,
                        major_axis,
                        ratio,
                        start_angle,
                        end_angle,
                        ..
                    } => {
                        // The model has the end points' angles; the curve
                        // is flattened between its parameters there.
                        let seg = curves::flatten_ellipse(
                            center.x,
                            center.y,
                            major_axis.x,
                            major_axis.y,
                            *ratio,
                            crate::cad::ellipse_param(*start_angle, *ratio),
                            crate::cad::ellipse_param(*end_angle, *ratio),
                        );
                        pts.extend(seg);
                    }
                    Edge::Spline {
                        degree,
                        rational,
                        knots,
                        control_points,
                        weights,
                        ..
                    } => {
                        let ctrl: Vec<[f64; 2]> =
                            control_points.iter().map(|p| [p.x, p.y]).collect();
                        let seg = curves::flatten_spline(
                            (*degree).max(0) as usize,
                            knots,
                            &ctrl,
                            if *rational { weights } else { &[] },
                            false,
                        );
                        pts.extend(seg);
                    }
                }
            }
            // Drop the duplicated closing vertex; loops are implicitly closed.
            if pts.len() > 2 {
                let first = pts[0];
                let last = pts[pts.len() - 1];
                if (first[0] - last[0]).abs() < 1e-9 && (first[1] - last[1]).abs() < 1e-9 {
                    pts.pop();
                }
            }
            if pts.len() >= 3 {
                loops.push(pts);
            }
        }

        if loops.is_empty() {
            return;
        }

        // Boundary paths are never stroked; see the hatch module header.

        let gradient_fill = h.gradient.as_ref().filter(|g| g.kind != 0);
        if h.solid || gradient_fill.is_some() {
            // Band decomposition rather than ear clipping: it applies the
            // even-odd rule to all the loops at once, so islands need no
            // bridging and a boundary that ear clipping chokes on still fills
            // exactly. See the fill module.
            let tris = fill::fill_region(&loops, island_style(h));

            // A gradient is the same fill with a colour that varies across it,
            // evaluated per vertex in the entity's own coordinates.
            let palette = self.palette;
            let gradient = gradient_fill
                .and_then(|g| Gradient::new(g, rgba, palette))
                .map(|mut g| {
                    g.fit(&loops);
                    g
                });

            // A gradient names its own colours, so it never flips with the
            // background.
            let grad_attr = attr & !((FLAG_CONTRAST as u32) << 24);
            let mut pieces: Vec<[[f64; 2]; 3]> = Vec::new();
            let depth = gradient::depth_for(tris.len() / 3);

            for t in tris.chunks(3) {
                if t.len() < 3 {
                    continue;
                }
                let Some(g) = &gradient else {
                    self.scene.push_triangle(
                        ctx.xf.apply(t[0][0], t[0][1]),
                        ctx.xf.apply(t[1][0], t[1][1]),
                        ctx.xf.apply(t[2][0], t[2][1]),
                        rgba,
                        attr,
                    );
                    continue;
                };

                pieces.clear();
                gradient::subdivide([t[0], t[1], t[2]], g.max_edge(), depth, &mut pieces);
                for p in &pieces {
                    self.scene.push_triangle_shaded(
                        [
                            ctx.xf.apply(p[0][0], p[0][1]),
                            ctx.xf.apply(p[1][0], p[1][1]),
                            ctx.xf.apply(p[2][0], p[2][1]),
                        ],
                        [
                            g.color_at(p[0][0], p[0][1]),
                            g.color_at(p[1][0], p[1][1]),
                            g.color_at(p[2][0], p[2][1]),
                        ],
                        grad_attr,
                    );
                }
            }
            return;
        }

        // Pattern fill: draw the pattern's line families clipped to the region.
        let lines: Vec<hatch::PatternLine> = h
            .pattern_lines
            .iter()
            .map(|l| hatch::PatternLine {
                angle: l.angle,
                base: [l.base.x, l.base.y],
                offset: [l.offset.x, l.offset.y],
                dashes: l.dashes.clone(),
            })
            .collect();

        if lines.is_empty() {
            self.warnings.hatch_patterns_missing += 1;
            return;
        }

        let (segments, truncated) = hatch::pattern_segments(&loops, &lines, island_style(h));
        if truncated {
            self.warnings.hatch_patterns_truncated += 1;
        }

        // Record the pattern's spacing so the renderer can fade these lines
        // once they crowd below a pixel, instead of letting them saturate.
        let spacing = hatch::min_spacing(&lines) * ctx.xf.scale_magnitude();
        let fade = encode_fade_spacing(spacing);
        // The fade code shares the flags byte with the contrast flag, which
        // colour 7 needs to be drawn black on white: keep it.
        let attr = pack_attr(
            attr as u16,
            (attr >> 16) as u8,
            ((attr >> 24) as u8 & FLAG_CONTRAST) | fade,
        );

        for seg in segments {
            let a = ctx.xf.apply(seg[0][0], seg[0][1]);
            let b = ctx.xf.apply(seg[1][0], seg[1][1]);
            self.scene.push_stroke(a[0], a[1], b[0], b[1], rgba, attr);
        }
    }
}

/// Sample a helix in plan view from its axis parameters.
fn helix_points(h: &crate::cad::Helix) -> Vec<[f64; 2]> {
    let turns = h.turns.abs();
    if !turns.is_finite() || turns <= 0.0 || h.radius <= 0.0 {
        return Vec::new();
    }
    let n = ((turns * 64.0).ceil() as usize).clamp(8, 4096);
    let (sx, sy) = (
        h.start_point.x - h.axis_base.x,
        h.start_point.y - h.axis_base.y,
    );
    let a0 = sy.atan2(sx);
    let dir = if h.right_handed { 1.0 } else { -1.0 };
    (0..=n)
        .map(|i| {
            let a = a0 + dir * std::f64::consts::TAU * turns * (i as f64 / n as f64);
            [
                h.axis_base.x + h.radius * a.cos(),
                h.axis_base.y + h.radius * a.sin(),
            ]
        })
        .collect()
}

/// A SPLINE flattened: from its control points, or, for a spline drawn
/// through points that keeps none, the cubic that interpolates its fit
/// points.
fn spline_points(s: &crate::cad::Spline) -> Vec<[f64; 2]> {
    if s.control_points.is_empty() {
        let fit: Vec<[f64; 2]> = s.fit_points.iter().map(|p| [p.x, p.y]).collect();
        let tangent = |v: Option<crate::cad::Vec3>| {
            let v = v?;
            let len = (v.x * v.x + v.y * v.y).sqrt();
            (len > 1e-9).then(|| [v.x / len, v.y / len])
        };
        return curves::fit_spline(
            &fit,
            tangent(s.start_tangent),
            tangent(s.end_tangent),
            s.is_closed(),
        );
    }
    let ctrl: Vec<[f64; 2]> = s.control_points.iter().map(|p| [p.x, p.y]).collect();
    curves::flatten_spline(
        s.degree.max(0) as usize,
        &s.knots,
        &ctrl,
        &s.weights,
        s.is_closed(),
    )
}

/// Resolve a lineweight to hundredths of a millimetre, 0 meaning hairline.
fn lineweight_value(lw: LineWeight, inherited: u8) -> u8 {
    match lw {
        LineWeight::Value(v) if v > 0 => v.min(211) as u8,
        LineWeight::Value(_) => 0,
        LineWeight::Default => 0,
        LineWeight::ByLayer | LineWeight::ByBlock => inherited,
    }
}

/// Expand a vertex list carrying per-vertex bulges into a flat point list.
pub fn expand_bulges(verts: &[([f64; 2], f64)], closed: bool) -> Vec<[f64; 2]> {
    if verts.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(verts.len() + 8);
    out.push(verts[0].0);
    for i in 0..verts.len().saturating_sub(1) {
        let (p0, bulge) = verts[i];
        let p1 = verts[i + 1].0;
        out.extend(curves::flatten_bulge(p0, p1, bulge));
    }
    // Two vertices is enough to close: a circle is classically stored as a
    // closed polyline of two points, each bulging a half turn. Requiring three
    // dropped the second half, so every such circle came out as a semicircle:
    // as a hatch island that let the hatch run on into the hole.
    if closed && verts.len() >= 2 {
        let (p0, bulge) = verts[verts.len() - 1];
        let p1 = verts[0].0;
        let seg = curves::flatten_bulge(p0, p1, bulge);
        // The caller closes the loop, so drop the duplicated final point.
        if seg.len() > 1 {
            out.extend(&seg[..seg.len() - 1]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block holding one circle, inserted as a `rows` by `columns` MINSERT.
    fn minsert(rows: u16, columns: u16) -> CadDrawing {
        use crate::cad::{Block, Circle, Insert};
        let ring = Entity {
            kind: EntityKind::Circle(Circle {
                radius: 1.0,
                ..Circle::default()
            }),
            ..Entity::default()
        };
        let grid = Entity {
            kind: EntityKind::Insert(Box::new(Insert {
                block_name: "RING".to_string(),
                rows,
                columns,
                row_spacing: 3.0,
                column_spacing: 3.0,
                ..Insert::default()
            })),
            ..Entity::default()
        };
        CadDrawing {
            blocks: vec![
                Block {
                    name: MODEL_SPACE.to_string(),
                    entities: vec![grid],
                    ..Block::default()
                },
                Block {
                    name: "RING".to_string(),
                    entities: vec![ring],
                    ..Block::default()
                },
            ],
            ..CadDrawing::default()
        }
    }

    /// An R13 or R14 drawing AutoCAD saved has no LAYOUT objects: its paper
    /// space is a tab still, when it holds something, as DXF's readers give
    /// it.
    #[test]
    fn paper_space_without_a_layout_object_is_a_tab() {
        use crate::cad::{Block, Line};
        let mut doc = minsert(1, 1);
        let line = Entity {
            kind: EntityKind::Line(Line::default()),
            ..Entity::default()
        };
        doc.header.plimmax = crate::cad::Vec2::new(420.0, 297.0);
        doc.blocks.push(Block {
            name: PAPER_SPACE.to_string(),
            ..Block::default()
        });
        let names = |d: &CadDrawing| -> Vec<String> {
            Tessellator::new(d)
                .layouts()
                .into_iter()
                .map(|l| l.name)
                .collect()
        };
        assert_eq!(names(&doc), ["Model"], "an empty paper space");
        doc.blocks.last_mut().unwrap().entities.push(line);
        assert_eq!(names(&doc), ["Model", "Layout1"]);
        let l = Tessellator::new(&doc).layouts().pop().unwrap();
        assert!(!l.is_model);
        assert_eq!(l.limits, Some([0.0, 0.0, 420.0, 297.0]));
    }

    #[test]
    fn a_minsert_asking_past_the_budget_is_drawn_up_to_it() {
        // 160,000 rings of about seventy strokes: eleven million asked for.
        let doc = minsert(400, 400);
        let mut t = Tessellator::new(&doc);
        t.run();
        // Stopped between entities: over by one circle at most, and not short.
        let n = t.scene.strokes.len();
        assert!(
            (SCENE_BUDGET..SCENE_BUDGET + MAX_SEGMENTS_PER_CIRCLE).contains(&n),
            "{n} strokes"
        );
        assert!(t.warnings.scene_truncated > 0);
    }

    /// `array_points` allocated the whole grid first: 4.3 billion points.
    #[test]
    fn a_minsert_of_65535_by_65535_is_cut_short_at_once() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let doc = minsert(u16::MAX, u16::MAX);
            let mut t = Tessellator::new(&doc);
            t.run();
            let _ = tx.send((t.warnings.scene_truncated, t.scene.strokes.len()));
        });
        let (truncated, n) = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("did not return within 20 s");
        assert!(truncated > 0 && n < SCENE_BUDGET + MAX_SEGMENTS_PER_CIRCLE);
    }

    const MAX_SEGMENTS_PER_CIRCLE: usize = 513;

    fn tessellated(kind: EntityKind) -> Scene {
        let doc = CadDrawing::default();
        let mut t = Tessellator::new(&doc);
        t.tessellate_entity(&Entity {
            kind,
            ..Entity::default()
        });
        t.scene
    }

    /// TRACE is filled like SOLID, its corners in the same Z order.
    #[test]
    fn a_trace_is_filled_like_a_solid() {
        use crate::cad::{Quad, Vec3};
        let quad = Quad {
            corners: [
                Vec3::new(0.0, 0.0, 0.0),
                Vec3::new(4.0, 0.0, 0.0),
                Vec3::new(0.0, 1.0, 0.0),
                Vec3::new(4.0, 1.0, 0.0),
            ],
            ..Quad::default()
        };
        let solid = tessellated(EntityKind::Solid(quad.clone()));
        let trace = tessellated(EntityKind::Trace(quad));
        assert_eq!(trace.fills.len(), 6);
        let points = |s: &Scene| s.fills.iter().map(|v| [v.x, v.y]).collect::<Vec<_>>();
        assert_eq!(points(&trace), points(&solid));
    }

    /// A constant ATTDEF is drawn, and in its object coordinates like an
    /// ATTRIB: under an extrusion of -Z, X is mirrored.
    #[test]
    fn a_constant_attribute_definition_is_placed_in_its_ocs() {
        use crate::cad::{Attribute, Plane, Text, Vec3};
        let attdef = |extrusion| {
            EntityKind::AttributeDefinition(Box::new(Attribute {
                flags: 2,
                text: Text {
                    value: "FIXED".to_string(),
                    insertion: Vec3::new(10.0, 0.0, 0.0),
                    plane: Plane {
                        thickness: 0.0,
                        extrusion,
                    },
                    ..Text::default()
                },
                ..Attribute::default()
            }))
        };
        // The stroke font draws it, so the strokes say where it went.
        let xs = |s: Scene| {
            let x: Vec<f64> = s.strokes.iter().flat_map(|s| [s.x0, s.x1]).collect();
            assert!(!x.is_empty());
            (
                x.iter().copied().fold(f64::INFINITY, f64::min),
                x.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            )
        };
        let (lo, _) = xs(tessellated(attdef(Vec3::Z)));
        assert!((lo - 10.0).abs() < 0.5, "{lo}");
        let (_, hi) = xs(tessellated(attdef(Vec3::new(0.0, 0.0, -1.0))));
        assert!((hi + 10.0).abs() < 0.5, "{hi}");
    }

    #[test]
    fn bulge_free_vertices_pass_through() {
        let v = [([0.0, 0.0], 0.0), ([1.0, 0.0], 0.0), ([1.0, 1.0], 0.0)];
        let out = expand_bulges(&v, false);
        assert_eq!(out, vec![[0.0, 0.0], [1.0, 0.0], [1.0, 1.0]]);
    }

    #[test]
    fn bulged_segment_expands_to_an_arc() {
        let v = [([0.0, 0.0], 1.0), ([2.0, 0.0], 0.0)];
        let out = expand_bulges(&v, false);
        assert!(out.len() > 3, "expected an arc, got {} points", out.len());
        // A positive bulge sweeps counter-clockwise, dipping below the chord.
        let min_y = out.iter().map(|p| p[1]).fold(f64::MAX, f64::min);
        assert!((min_y + 1.0).abs() < 1e-3, "min_y {min_y}");
        assert_eq!(out[0], [0.0, 0.0]);
        assert_eq!(*out.last().unwrap(), [2.0, 0.0]);
    }

    #[test]
    fn closed_bulge_does_not_duplicate_the_seam_point() {
        let v = [([0.0, 0.0], 0.0), ([1.0, 0.0], 0.0), ([1.0, 1.0], 0.0)];
        let out = expand_bulges(&v, true);
        // Closing is the caller's job, so the first point must not reappear.
        assert_ne!(*out.last().unwrap(), out[0]);
    }

    #[test]
    fn lineweight_resolution() {
        assert_eq!(lineweight_value(LineWeight::Value(50), 9), 50);
        assert_eq!(lineweight_value(LineWeight::Default, 9), 0);
        assert_eq!(lineweight_value(LineWeight::ByLayer, 9), 9);
        assert_eq!(lineweight_value(LineWeight::ByBlock, 13), 13);
        // Out-of-range values clamp rather than wrapping through the u8 cast.
        assert_eq!(lineweight_value(LineWeight::Value(9999), 0), 211);
        assert_eq!(lineweight_value(LineWeight::Value(0), 9), 0);
    }
}

#[cfg(test)]
mod tab_stops {
    use super::*;

    #[test]
    fn a_declared_stop_is_used() {
        let p = text::Paragraph {
            tabs: vec![4.0, 12.0],
            ..Default::default()
        };
        assert_eq!(next_tab_stop(0.0, &p, 2.5), 4.0);
        assert_eq!(next_tab_stop(4.0, &p, 2.5), 12.0);
        // Past the last declared stop, the default step takes over.
        assert!(next_tab_stop(12.0, &p, 2.5) > 12.0);
    }

    #[test]
    fn without_declared_stops_it_steps_by_four_text_heights() {
        let p = text::Paragraph::default();
        assert_eq!(next_tab_stop(0.0, &p, 2.5), 10.0);
        assert_eq!(next_tab_stop(3.0, &p, 2.5), 10.0);
        assert_eq!(next_tab_stop(10.0, &p, 2.5), 20.0);
    }

    #[test]
    fn it_always_moves_forward() {
        let p = text::Paragraph {
            tabs: vec![1.0],
            ..Default::default()
        };
        for cursor in [0.0f64, 0.5, 1.0, 7.3, 99.0] {
            assert!(
                next_tab_stop(cursor, &p, 2.5) > cursor,
                "stalled at {cursor}"
            );
        }
    }
}

#[cfg(test)]
mod contrast_colour {
    use super::*;

    #[test]
    fn an_indexed_colour_resolves_through_the_chosen_palette() {
        // The same index is a different grey depending on the background it is
        // read against; a true colour is itself either way.
        assert_eq!(
            colour_rgb(&Color::Index(8), Palette::Light),
            Some((65, 65, 65))
        );
        assert_eq!(
            colour_rgb(&Color::Index(8), Palette::Dark),
            Some((128, 128, 128))
        );

        let white = Color::Rgb(255, 255, 255);
        assert_eq!(colour_rgb(&white, Palette::Light), Some((255, 255, 255)));
        assert_eq!(colour_rgb(&white, Palette::Dark), Some((255, 255, 255)));

        // ByLayer and ByBlock are resolved before a lookup gets here.
        assert_eq!(colour_rgb(&Color::ByLayer, Palette::Light), None);
    }

    #[test]
    fn only_colour_seven_flips_with_the_background() {
        assert!(is_contrast_color(&Color::Index(7)));
        // A true colour is taken literally, however white it is: a solid white
        // hatch is a mask, and flipping it paints a black box over the sheet.
        assert!(!is_contrast_color(&Color::Rgb(255, 255, 255)));
        assert!(!is_contrast_color(&Color::Index(1)));
        assert!(!is_contrast_color(&Color::Index(250)));
    }
}

#[cfg(test)]
mod viewport_view {
    use super::*;

    /// The second viewport of an A0 layout, from a real drawing.
    const PAPER_CENTER: [f64; 2] = [229.4, 566.9];
    const PAPER_HEIGHT: f64 = 379.2;
    const VIEW_CENTER: [f64; 2] = [32811.1, 785.3];
    const VIEW_TARGET: [f64; 2] = [-7226.9, -2950.6];
    const VIEW_HEIGHT: f64 = 1896.1;

    #[test]
    fn the_model_point_at_the_view_centre_lands_in_the_middle_of_the_window() {
        let xf = viewport_transform(
            PAPER_CENTER,
            PAPER_HEIGHT,
            VIEW_CENTER,
            VIEW_TARGET,
            VIEW_HEIGHT,
            0.0,
        );
        // The display-coordinate centre, resolved back to the model.
        let p = xf.apply(
            VIEW_CENTER[0] + VIEW_TARGET[0],
            VIEW_CENTER[1] + VIEW_TARGET[1],
        );
        assert!((p[0] - PAPER_CENTER[0]).abs() < 1e-6, "{p:?}");
        assert!((p[1] - PAPER_CENTER[1]).abs() < 1e-6, "{p:?}");

        // Ignoring the target would put the window 7.2 km off in model terms,
        // which on this sheet is roughly 1445 mm of paper: right off the page.
        let wrong = xf.apply(VIEW_CENTER[0], VIEW_CENTER[1]);
        assert!((wrong[0] - PAPER_CENTER[0]).abs() > 1000.0, "{wrong:?}");
    }

    #[test]
    fn the_view_height_sets_the_scale() {
        let xf = viewport_transform(
            PAPER_CENTER,
            PAPER_HEIGHT,
            VIEW_CENTER,
            VIEW_TARGET,
            VIEW_HEIGHT,
            0.0,
        );
        // A run of one view height in the model spans the window's height.
        let a = xf.apply(0.0, 0.0);
        let b = xf.apply(0.0, VIEW_HEIGHT);
        assert!((b[1] - a[1] - PAPER_HEIGHT).abs() < 1e-6, "{a:?} {b:?}");
    }

    #[test]
    fn a_viewport_scales_model_space_by_its_window_over_its_view() {
        // That A0 sheet: a 379.2 mm window onto 1896.1 model units, a fifth.
        // PSLTSCALE divides dash lengths by this scale, so it has to be right.
        let xf = viewport_transform(
            PAPER_CENTER,
            PAPER_HEIGHT,
            VIEW_CENTER,
            VIEW_TARGET,
            VIEW_HEIGHT,
            0.0,
        );
        let view_scale = xf.scale_magnitude();
        assert!(
            (view_scale - PAPER_HEIGHT / VIEW_HEIGHT).abs() < 1e-9,
            "scale {view_scale}"
        );
        assert!((view_scale - 0.2).abs() < 1e-4, "scale {view_scale}");
    }

    #[test]
    fn twist_turns_the_model_the_other_way() {
        // A view twisted a quarter turn shows model +X running down the sheet.
        let xf = viewport_transform(
            [0.0, 0.0],
            2.0,
            [0.0, 0.0],
            [0.0, 0.0],
            2.0,
            std::f64::consts::FRAC_PI_2,
        );
        let p = xf.apply(1.0, 0.0);
        assert!(p[0].abs() < 1e-9 && (p[1] + 1.0).abs() < 1e-9, "{p:?}");
    }
}

#[cfg(test)]
mod two_vertex_circle {
    use super::*;

    /// A circle stored the way DWG usually stores one: a closed polyline of two
    /// points, each with a half-turn bulge.
    fn circle_polyline(cx: f64, cy: f64, r: f64) -> Vec<([f64; 2], f64)> {
        vec![([cx - r, cy], 1.0), ([cx + r, cy], 1.0)]
    }

    #[test]
    fn a_two_point_closed_polyline_makes_a_whole_circle() {
        let pts = expand_bulges(&circle_polyline(0.0, 0.0, 70.0), true);
        let min_y = pts.iter().map(|p| p[1]).fold(f64::MAX, f64::min);
        let max_y = pts.iter().map(|p| p[1]).fold(f64::MIN, f64::max);

        // Both halves must be present, not just the one below the chord.
        assert!(
            (min_y + 70.0).abs() < 0.2,
            "missing lower half, min_y {min_y}"
        );
        assert!(
            (max_y - 70.0).abs() < 0.2,
            "missing upper half, max_y {max_y}"
        );

        // And every point sits on the circle.
        for p in &pts {
            let d = (p[0] * p[0] + p[1] * p[1]).sqrt();
            assert!((d - 70.0).abs() < 0.2, "point {p:?} off the circle");
        }
    }

    #[test]
    fn leaving_it_open_still_gives_only_one_half() {
        // Guards the premise: this is exactly what the bug produced.
        let pts = expand_bulges(&circle_polyline(0.0, 0.0, 70.0), false);
        let max_y = pts.iter().map(|p| p[1]).fold(f64::MIN, f64::max);
        assert!(max_y < 1.0, "an open polyline should not close the circle");
    }

    #[test]
    fn a_two_point_closed_straight_polyline_is_harmless() {
        let pts = expand_bulges(&[([0.0, 0.0], 0.0), ([10.0, 0.0], 0.0)], true);
        for p in &pts {
            assert!(p[1].abs() < 1e-9, "should stay on the line, got {p:?}");
            assert!(p[0] >= -1e-9 && p[0] <= 10.0 + 1e-9);
        }
    }

    #[test]
    fn a_three_point_closed_polyline_is_unchanged() {
        let pts = expand_bulges(
            &[([0.0, 0.0], 0.0), ([10.0, 0.0], 0.0), ([10.0, 10.0], 0.0)],
            true,
        );
        // Still open at the seam; the caller draws the closing edge.
        assert_ne!(*pts.last().unwrap(), pts[0]);
        assert_eq!(pts[0], [0.0, 0.0]);
    }
}
