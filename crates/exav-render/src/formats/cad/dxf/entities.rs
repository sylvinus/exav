//! ENTITIES (and block contents): one record to one [`Entity`].
//!
//! Each type is read from the groups after its AcDbEntity subclass, by
//! group code, in file order, as the DXF reference's tables for that type
//! give them. Repeated groups (vertices, knots) are appended in order; a
//! group whose meaning depends on what came before (hatch boundaries,
//! multileader context data) is read with that state.

use exav_unpack::dxf::{Parts, Record, Tag};

use super::Ctx;
use crate::formats::cad::model::*;

pub(super) fn p3(p: &mut Vec3, t: &Tag<'_>, base: i32) -> bool {
    match t.code.wrapping_sub(base) {
        0 => p.x = t.f64(),
        10 => p.y = t.f64(),
        20 => p.z = t.f64(),
        _ => return false,
    }
    true
}

pub(super) fn p2(p: &mut Vec2, t: &Tag<'_>, base: i32) -> bool {
    match t.code.wrapping_sub(base) {
        0 => p.x = t.f64(),
        10 => p.y = t.f64(),
        _ => return false,
    }
    true
}

fn deg(t: &Tag<'_>) -> f64 {
    t.f64().to_radians()
}

fn handle(t: &Tag<'_>) -> Handle {
    Handle(t.handle())
}

/// A repeated 3D point: `base` starts one, `base + 10` and `+ 20` fill it.
pub(super) fn push3(v: &mut Vec<Vec3>, t: &Tag<'_>, base: i32, ctx: &mut Ctx<'_>) -> bool {
    match t.code.wrapping_sub(base) {
        0 => {
            if ctx.room(v.len()) {
                v.push(Vec3::new(t.f64(), 0.0, 0.0));
            }
        }
        10 => {
            if let Some(p) = v.last_mut() {
                p.y = t.f64();
            }
        }
        20 => {
            if let Some(p) = v.last_mut() {
                p.z = t.f64();
            }
        }
        _ => return false,
    }
    true
}

pub(super) fn push2(v: &mut Vec<Vec2>, t: &Tag<'_>, base: i32, ctx: &mut Ctx<'_>) -> bool {
    match t.code.wrapping_sub(base) {
        0 => {
            if ctx.room(v.len()) {
                v.push(Vec2::new(t.f64(), 0.0));
            }
        }
        10 => {
            if let Some(p) = v.last_mut() {
                p.y = t.f64();
            }
        }
        _ => return false,
    }
    true
}

fn push_f64(v: &mut Vec<f64>, t: &Tag<'_>, ctx: &mut Ctx<'_>) {
    if ctx.room(v.len()) {
        v.push(t.f64());
    }
}

fn plane(p: &mut Plane, t: &Tag<'_>) -> bool {
    if t.code == 39 {
        p.thickness = t.f64();
        return true;
    }
    p3(&mut p.extrusion, t, 210)
}

pub(crate) fn entity(rec: &Record<'_>, ctx: &mut Ctx<'_>) -> Entity {
    let parts = Parts::new(&rec.tags, false);
    let mut e = Entity {
        handle: Handle(parts.handle()),
        owner: Handle(parts.owner()),
        ..Entity::default()
    };
    common(&parts, &mut e, ctx);
    let data = parts.after("AcDbEntity");
    let name = rec.type_name().to_ascii_uppercase();
    e.kind = match name.as_str() {
        "LINE" => EntityKind::Line(line(data)),
        "POINT" => EntityKind::Point(point(data)),
        "CIRCLE" => EntityKind::Circle(circle(data)),
        "ARC" => EntityKind::Arc(arc(data)),
        "ELLIPSE" => EntityKind::Ellipse(ellipse(data)),
        "SPLINE" => EntityKind::Spline(Box::new(spline(data, ctx))),
        "LWPOLYLINE" => EntityKind::LwPolyline(lwpolyline(data, ctx)),
        "POLYLINE" => EntityKind::Polyline(polyline(data)),
        "SOLID" => EntityKind::Solid(quad(data)),
        "TRACE" => EntityKind::Trace(quad(data)),
        "3DFACE" => EntityKind::Face3D(face3d(data)),
        "TEXT" => EntityKind::Text(Box::new(text(data, false, ctx).0)),
        "ATTRIB" => EntityKind::Attribute(Box::new(attribute(&parts, data, ctx))),
        "ATTDEF" => EntityKind::AttributeDefinition(Box::new(attribute(&parts, data, ctx))),
        "INSERT" => EntityKind::Insert(Box::new(insert(data, ctx))),
        "MTEXT" => {
            let mut m = mtext(data, ctx);
            if m.columns.is_none() {
                m.columns = parts.xdata("ACAD").and_then(|x| xdata_columns(x, ctx));
            }
            EntityKind::MText(Box::new(m))
        }
        "DIMENSION" | "ARC_DIMENSION" | "LARGE_RADIAL_DIMENSION" => {
            EntityKind::Dimension(Box::new(dimension(data, ctx)))
        }
        "LEADER" => EntityKind::Leader(Box::new(leader(data, ctx))),
        "MULTILEADER" | "MLEADER" => EntityKind::MultiLeader(Box::new(multileader(data, ctx))),
        "MLINE" => EntityKind::MLine(Box::new(mline(data, ctx))),
        "HATCH" => EntityKind::Hatch(Box::new(hatch(data, ctx))),
        "HELIX" => EntityKind::Helix(Box::new(helix(&parts, ctx))),
        "RAY" => EntityKind::Ray(ray(data)),
        "XLINE" => EntityKind::XLine(ray(data)),
        "VIEWPORT" => EntityKind::Viewport(Box::new(viewport(&parts, data, ctx))),
        "IMAGE" => EntityKind::Image(Box::new(image(data, ctx))),
        "WIPEOUT" => EntityKind::Wipeout(Box::new(image(data, ctx))),
        "PDFUNDERLAY" | "PDFREFERENCE" => {
            EntityKind::Underlay(Box::new(underlay(data, UnderlayKind::Pdf, ctx)))
        }
        "DWFUNDERLAY" | "DWFREFERENCE" => {
            EntityKind::Underlay(Box::new(underlay(data, UnderlayKind::Dwf, ctx)))
        }
        "DGNUNDERLAY" | "DGNREFERENCE" => {
            EntityKind::Underlay(Box::new(underlay(data, UnderlayKind::Dgn, ctx)))
        }
        "OLE2FRAME" => EntityKind::Ole2Frame(ole2frame(data, ctx)),
        "ACAD_TABLE" => EntityKind::Table(Box::new(table(&parts, ctx))),
        "SHAPE" => EntityKind::Shape(shape(data, ctx)),
        _ => EntityKind::Unknown(Unknown {
            type_name: rec.type_name(),
            graphics: graphics(&parts, ctx),
        }),
    };
    e
}

/// Proxy graphics: a size (92, 160 from 2010) and the 310 chunks after it,
/// in AcDbEntity or, for ACAD_PROXY_ENTITY, in AcDbProxyEntity (R13:
/// AcDbZombieEntity) before the entity's own data.
fn graphics(parts: &Parts<'_>, ctx: &mut Ctx<'_>) -> Option<Box<ProxyGraphics>> {
    fn sized<'p, 'a>(tags: &'p [Tag<'a>]) -> Option<(i64, &'p [Tag<'a>])> {
        let at = tags.windows(2).position(|w| {
            matches!(w.first(), Some(t) if t.code == 92 || t.code == 160)
                && matches!(w.get(1), Some(t) if t.code == 310)
        })?;
        Some((tags.get(at)?.int(), tags.get(at + 1..)?))
    }
    let (size, chunks) = sized(parts.common())
        .or_else(|| parts.subclass("AcDbProxyEntity").and_then(sized))
        .or_else(|| parts.subclass("AcDbZombieEntity").and_then(sized))?;
    let size = usize::try_from(size).ok()?;
    let mut data = Vec::new();
    for t in chunks.iter().take_while(|t| t.code == 310) {
        if data.len() >= size {
            break;
        }
        if !t.chunk_into(&mut data) {
            ctx.warn(
                WarningKind::Malformed,
                format!(
                    "{:X}: proxy graphics that are not hexadecimal",
                    parts.handle()
                ),
            );
            break;
        }
    }
    data.truncate(size);
    let code_page = ctx.code_page;
    let (g, problem) = crate::formats::cad::proxy::read(
        &data,
        &crate::formats::cad::proxy::Reading {
            version: crate::formats::cad::proxy::dwg_version(ctx.version),
            decode: &|b: &[u8]| code_page.decode(b),
            max_items: ctx.limits.max_items,
            max_string_bytes: ctx.limits.max_string_bytes,
        },
    );
    if let Some(p) = problem {
        ctx.warn(WarningKind::Malformed, format!("{:X}: {p}", parts.handle()));
    }
    Some(Box::new(g))
}

fn common(parts: &Parts<'_>, e: &mut Entity, ctx: &mut Ctx<'_>) {
    let mut aci = None;
    let mut rgb = None;
    for t in parts.common() {
        match t.code {
            8 => e.layer = ctx.text(t),
            6 => e.linetype = ctx.text(t),
            62 => aci = Some(t.int()),
            420 => rgb = Some(t.int()),
            430 => e.color_name = ctx.text(t),
            440 => e.transparency = Transparency::from_code(t.int()),
            370 => e.lineweight = LineWeight::from_code(t.int()),
            48 => e.linetype_scale = t.f64(),
            60 => e.invisible = t.bool(),
            67 => e.paper_space = t.bool(),
            _ => {}
        }
    }
    e.color = match (rgb, aci) {
        (Some(v), _) => Color::from_rgb24(v),
        (None, Some(v)) => Color::from_aci(v),
        (None, None) => Color::ByLayer,
    };
}

fn line(data: &[Tag<'_>]) -> Line {
    let mut l = Line::default();
    for t in data {
        let _ = p3(&mut l.start, t, 10) || p3(&mut l.end, t, 11) || plane(&mut l.plane, t);
    }
    l
}

fn point(data: &[Tag<'_>]) -> Point {
    let mut p = Point::default();
    for t in data {
        if p3(&mut p.location, t, 10) || plane(&mut p.plane, t) {
            continue;
        }
        if t.code == 50 {
            p.x_axis_angle = deg(t);
        }
    }
    p
}

fn circle(data: &[Tag<'_>]) -> Circle {
    let mut c = Circle::default();
    for t in data {
        if p3(&mut c.center, t, 10) || plane(&mut c.plane, t) {
            continue;
        }
        if t.code == 40 {
            c.radius = t.f64();
        }
    }
    c
}

fn arc(data: &[Tag<'_>]) -> Arc {
    let mut a = Arc::default();
    for t in data {
        if p3(&mut a.center, t, 10) || plane(&mut a.plane, t) {
            continue;
        }
        match t.code {
            40 => a.radius = t.f64(),
            50 => a.start_angle = deg(t),
            51 => a.end_angle = deg(t),
            _ => {}
        }
    }
    a
}

fn ellipse(data: &[Tag<'_>]) -> Ellipse {
    let mut e = Ellipse::default();
    for t in data {
        if p3(&mut e.center, t, 10) || p3(&mut e.major_axis, t, 11) || p3(&mut e.extrusion, t, 210)
        {
            continue;
        }
        match t.code {
            40 => e.ratio = t.f64(),
            41 => e.start_param = t.f64(),
            42 => e.end_param = t.f64(),
            _ => {}
        }
    }
    e
}

fn spline(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> Spline {
    let mut s = Spline::default();
    let mut start = Vec3::default();
    let mut end = Vec3::default();
    for t in data {
        if push3(&mut s.control_points, t, 10, ctx) || push3(&mut s.fit_points, t, 11, ctx) {
            continue;
        }
        if p3(&mut start, t, 12) {
            s.start_tangent = Some(start);
            continue;
        }
        if p3(&mut end, t, 13) {
            s.end_tangent = Some(end);
            continue;
        }
        if p3(&mut s.extrusion, t, 210) {
            continue;
        }
        match t.code {
            70 => s.flags = t.i16(),
            71 => s.degree = t.i16(),
            42 => s.knot_tolerance = t.f64(),
            43 => s.control_point_tolerance = t.f64(),
            44 => s.fit_tolerance = t.f64(),
            40 => push_f64(&mut s.knots, t, ctx),
            41 => push_f64(&mut s.weights, t, ctx),
            _ => {}
        }
    }
    s
}

fn lwpolyline(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> LwPolyline {
    let mut p = LwPolyline::default();
    for t in data {
        if plane(&mut p.plane, t) {
            continue;
        }
        match t.code {
            70 => p.flags = t.i16(),
            43 => p.constant_width = t.f64(),
            38 => p.elevation = t.f64(),
            10 => {
                if ctx.room(p.vertices.len()) {
                    p.vertices.push(LwVertex {
                        point: Vec2::new(t.f64(), 0.0),
                        ..LwVertex::default()
                    });
                }
            }
            20 | 40 | 41 | 42 => {
                let Some(v) = p.vertices.last_mut() else {
                    continue;
                };
                match t.code {
                    20 => v.point.y = t.f64(),
                    40 => v.start_width = t.f64(),
                    41 => v.end_width = t.f64(),
                    _ => v.bulge = t.f64(),
                }
            }
            _ => {}
        }
    }
    p
}

fn polyline(data: &[Tag<'_>]) -> Polyline {
    let mut p = Polyline::default();
    for t in data {
        if plane(&mut p.plane, t) {
            continue;
        }
        match t.code {
            30 => p.elevation = t.f64(),
            70 => p.flags = t.i16(),
            40 => p.default_start_width = t.f64(),
            41 => p.default_end_width = t.f64(),
            71 => p.m_count = t.i16(),
            72 => p.n_count = t.i16(),
            73 => p.m_density = t.i16(),
            74 => p.n_density = t.i16(),
            75 => p.curve_type = t.i16(),
            _ => {}
        }
    }
    p
}

pub(crate) fn vertex(rec: &Record<'_>, _ctx: &mut Ctx<'_>) -> Vertex {
    let parts = Parts::new(&rec.tags, false);
    let mut v = Vertex {
        handle: Handle(parts.handle()),
        ..Vertex::default()
    };
    for t in parts.after("AcDbEntity") {
        if p3(&mut v.location, t, 10) {
            continue;
        }
        match t.code {
            40 => v.start_width = t.f64(),
            41 => v.end_width = t.f64(),
            42 => v.bulge = t.f64(),
            70 => v.flags = t.i16(),
            50 => v.tangent = deg(t),
            71..=74 => {
                if let Some(slot) = v.indices.get_mut((t.code - 71) as usize) {
                    *slot = t.i32();
                }
            }
            _ => {}
        }
    }
    v
}

fn quad(data: &[Tag<'_>]) -> Quad {
    let mut q = Quad::default();
    let mut fourth = false;
    for t in data {
        if plane(&mut q.plane, t) {
            continue;
        }
        let [a, b, c, d] = &mut q.corners;
        if p3(a, t, 10) || p3(b, t, 11) || p3(c, t, 12) {
            continue;
        }
        if p3(d, t, 13) {
            fourth = true;
        }
    }
    if !fourth {
        q.corners[3] = q.corners[2];
    }
    q
}

fn face3d(data: &[Tag<'_>]) -> Face3D {
    let mut f = Face3D::default();
    let mut fourth = false;
    for t in data {
        let [a, b, c, d] = &mut f.corners;
        if p3(a, t, 10) || p3(b, t, 11) || p3(c, t, 12) {
            continue;
        }
        if p3(d, t, 13) {
            fourth = true;
            continue;
        }
        if t.code == 70 {
            f.invisible_edges = t.i16();
        }
    }
    if !fourth {
        f.corners[3] = f.corners[2];
    }
    f
}

/// TEXT, or the text part of ATTRIB and ATTDEF, where 73 is the field
/// length and 74 the vertical alignment. Also returns the tag field length
/// for attributes.
fn text(data: &[Tag<'_>], attrib: bool, ctx: &mut Ctx<'_>) -> (Text, i16) {
    let mut x = Text::default();
    let mut second = Vec3::default();
    let mut has_second = false;
    let mut field_length = 0;
    for t in data {
        if p3(&mut x.insertion, t, 10) || plane(&mut x.plane, t) {
            continue;
        }
        if p3(&mut second, t, 11) {
            has_second = true;
            continue;
        }
        match t.code {
            40 => x.height = t.f64(),
            1 => x.value = ctx.text(t),
            50 => x.rotation = deg(t),
            41 => x.width_factor = t.f64(),
            51 => x.oblique = deg(t),
            7 => x.style = ctx.text(t),
            71 => x.generation = t.i16(),
            72 => x.h_align = HAlign::from_code(t.int()),
            73 if attrib => field_length = t.i16(),
            73 => x.v_align = VAlign::from_code(t.int()),
            74 if attrib => x.v_align = VAlign::from_code(t.int()),
            _ => {}
        }
    }
    if has_second {
        x.alignment_point = Some(second);
    }
    (x, field_length)
}

/// ATTRIB and ATTDEF. With subclass markers the text is the AcDbText
/// class, and AcDbAttribute (or AcDbAttributeDefinition) holds the tag,
/// flags, field length (73), vertical alignment (74) and, from 2018, groups
/// (71, 72, 11) that mean something else than in AcDbText. An R12 record
/// mixes them all.
fn attribute(parts: &Parts<'_>, data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> Attribute {
    let (text_tags, own) = if parts.has_markers() {
        let own = parts
            .subclass("AcDbAttribute")
            .or_else(|| parts.subclass("AcDbAttributeDefinition"))
            .unwrap_or(&[]);
        (parts.subclass("AcDbText").unwrap_or(&[]), own)
    } else {
        (data, data)
    };
    // A multiline attribute carries an MTEXT after group 101.
    let (own, embedded) = match own.iter().position(|t| t.code == 101) {
        Some(i) => (
            own.get(..i).unwrap_or(&[]),
            Some(own.get(i + 1..).unwrap_or(&[])),
        ),
        None => (own, None),
    };
    let text_tags = match text_tags.iter().position(|t| t.code == 101) {
        Some(i) => text_tags.get(..i).unwrap_or(&[]),
        None => text_tags,
    };
    let (text, field_length) = text(text_tags, true, ctx);
    let mut a = Attribute {
        text,
        field_length,
        ..Attribute::default()
    };
    for t in own {
        match t.code {
            2 => a.tag = ctx.text(t),
            3 => a.prompt = ctx.text(t),
            70 => a.flags = t.i16(),
            73 => a.field_length = t.i16(),
            74 => a.text.v_align = VAlign::from_code(t.int()),
            // The last 280: the first, from 2010 on, is a version number.
            280 => a.lock_position = t.bool(),
            _ => {}
        }
    }
    if let Some(m) = embedded {
        a.mtext = Some(Box::new(mtext(m, ctx)));
    }
    a
}

fn insert(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> Insert {
    let mut i = Insert::default();
    for t in data {
        if p3(&mut i.insertion, t, 10) || p3(&mut i.extrusion, t, 210) {
            continue;
        }
        match t.code {
            2 => i.block_name = ctx.text(t),
            41 => i.scale.x = t.f64(),
            42 => i.scale.y = t.f64(),
            43 => i.scale.z = t.f64(),
            50 => i.rotation = deg(t),
            70 => i.columns = t.int().clamp(0, 65535) as u16,
            71 => i.rows = t.int().clamp(0, 65535) as u16,
            44 => i.column_spacing = t.f64(),
            45 => i.row_spacing = t.f64(),
            _ => {}
        }
    }
    i
}

fn mtext(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> MText {
    // From 2018 an MTEXT with columns repeats its geometry after group 101,
    // then the columns; the groups before it are the entity's own.
    let (data, embedded) = match data.iter().position(|t| t.code == 101) {
        Some(i) => (
            data.get(..i).unwrap_or(&[]),
            data.get(i + 1..).unwrap_or(&[]),
        ),
        None => (data, &[][..]),
    };
    let mut m = MText::default();
    let mut x_dir = Vec3::default();
    let mut has_x_dir = false;
    let mut bg_aci = None;
    let mut bg_rgb = None;
    let mut columns: Option<MTextColumns> = None;
    for t in data {
        if p3(&mut m.insertion, t, 10) || p3(&mut m.extrusion, t, 210) {
            continue;
        }
        if p3(&mut x_dir, t, 11) {
            has_x_dir = true;
            continue;
        }
        // Column groups follow 75; 48, 49 and 50 mean something else
        // before it.
        if let Some(c) = columns.as_mut() {
            match t.code {
                76 => c.count = t.i16(),
                78 => c.flow_reversed = t.bool(),
                79 => c.auto_height = t.bool(),
                48 => c.width = t.f64(),
                49 => c.gutter = t.f64(),
                50 => push_f64(&mut c.heights, t, ctx),
                _ => {}
            }
            if matches!(t.code, 76 | 78 | 79 | 48 | 49 | 50) {
                continue;
            }
        }
        match t.code {
            40 => m.height = t.f64(),
            41 => m.reference_width = t.f64(),
            46 => m.defined_height = t.f64(),
            71 => m.attachment = t.i16(),
            72 => m.drawing_direction = t.i16(),
            1 | 3 => ctx.append_text(&mut m.text, t),
            7 => m.style = ctx.text(t),
            50 => m.rotation = deg(t),
            73 => m.line_spacing_style = t.i16(),
            44 => m.line_spacing_factor = t.f64(),
            90 => m.background_fill = t.i32(),
            63 => bg_aci = Some(t.int()),
            421 => bg_rgb = Some(t.int()),
            45 => m.background_scale = t.f64(),
            75 => {
                columns = Some(MTextColumns {
                    kind: t.i16(),
                    ..MTextColumns::default()
                })
            }
            _ => {}
        }
    }
    if let std::borrow::Cow::Owned(t) = super::carets(&m.text) {
        m.text = t;
    }
    if has_x_dir {
        m.x_direction = Some(x_dir);
    }
    m.background_color = match (bg_rgb, bg_aci) {
        (Some(v), _) => Color::from_rgb24(v),
        (None, Some(v)) => Color::from_aci(v),
        (None, None) => Color::ByLayer,
    };
    m.columns = columns.or_else(|| embedded_columns(embedded, ctx));
    m
}

/// Before 2018 an MTEXT's columns are in its `ACAD` extended data, between
/// `ACAD_MTEXT_COLUMN_INFO_BEGIN` and `_END`: pairs of a 1070 group code
/// and its value (75 type, 79 auto height, 76 count, 78 flow reversed, 48
/// width, 49 gutter, 50 the number of heights, then the heights).
fn xdata_columns(x: &[Tag<'_>], ctx: &mut Ctx<'_>) -> Option<MTextColumns> {
    let start = x
        .iter()
        .position(|t| t.code == 1000 && t.is("ACAD_MTEXT_COLUMN_INFO_BEGIN"))?;
    let mut c = MTextColumns::default();
    let mut it = x.get(start + 1..).unwrap_or(&[]).iter();
    while let Some(t) = it.next() {
        if t.code != 1070 {
            break;
        }
        let Some(value) = it.next() else { break };
        match t.int() {
            75 => c.kind = value.i16(),
            79 => c.auto_height = value.bool(),
            76 => c.count = value.i16(),
            78 => c.flow_reversed = value.bool(),
            48 => c.width = value.f64(),
            49 => c.gutter = value.f64(),
            50 => {
                for _ in 0..value.int().clamp(0, x.len() as i64) {
                    match it.next() {
                        Some(h) if h.code == 1040 => push_f64(&mut c.heights, h, ctx),
                        _ => break,
                    }
                }
            }
            _ => {}
        }
    }
    (c.kind != 0).then_some(c)
}

/// The columns of a 2018 MTEXT's embedded object (ODA DWG specification
/// 20.4.46, whose DXF codes these are): 71 the type, 72 the count, 44
/// the width, 45 the gutter, 73 auto height, 74 flow reversed, 46 each
/// height.
fn embedded_columns(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> Option<MTextColumns> {
    let at = data.iter().position(|t| t.code == 71)?;
    let mut c = MTextColumns::default();
    for t in data.get(at..).unwrap_or(&[]) {
        match t.code {
            71 => c.kind = t.i16(),
            72 => c.count = t.i16(),
            44 => c.width = t.f64(),
            45 => c.gutter = t.f64(),
            73 => c.auto_height = t.bool(),
            74 => c.flow_reversed = t.bool(),
            46 => push_f64(&mut c.heights, t, ctx),
            _ => {}
        }
    }
    (c.kind != 0).then_some(c)
}

fn dimension(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> Dimension {
    let mut d = Dimension::default();
    for t in data {
        if p3(&mut d.definition_point, t, 10)
            || p3(&mut d.text_midpoint, t, 11)
            || p3(&mut d.insertion_point, t, 12)
            || p3(&mut d.point13, t, 13)
            || p3(&mut d.point14, t, 14)
            || p3(&mut d.point15, t, 15)
            || p3(&mut d.point16, t, 16)
            || p3(&mut d.extrusion, t, 210)
        {
            continue;
        }
        match t.code {
            2 => d.block_name = ctx.text(t),
            3 => d.style = ctx.text(t),
            70 => {
                d.flags = t.i16();
                d.kind = DimensionKind::from_code(t.int());
            }
            71 => d.attachment = t.i16(),
            72 => d.line_spacing_style = t.i16(),
            41 => d.line_spacing_factor = t.f64(),
            42 => d.measurement = t.f64(),
            1 => d.text = ctx.text(t),
            53 => d.text_rotation = deg(t),
            51 => d.horizontal_direction = deg(t),
            50 => d.angle = deg(t),
            52 => d.oblique = deg(t),
            40 => d.leader_length = t.f64(),
            _ => {}
        }
    }
    d
}

fn leader(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> Leader {
    let mut l = Leader::default();
    for t in data {
        if push3(&mut l.vertices, t, 10, ctx)
            || p3(&mut l.extrusion, t, 210)
            || p3(&mut l.horizontal_direction, t, 211)
            || p3(&mut l.block_offset, t, 212)
            || p3(&mut l.annotation_offset, t, 213)
        {
            continue;
        }
        match t.code {
            3 => l.style = ctx.text(t),
            71 => l.arrowhead = t.bool(),
            72 => l.path_type = t.i16(),
            73 => l.creation = t.i16(),
            74 => l.hookline_direction = t.i16(),
            75 => l.hookline = t.bool(),
            40 => l.text_height = t.f64(),
            41 => l.text_width = t.f64(),
            77 => l.color = Color::from_aci(t.int()),
            340 => l.annotation = handle(t),
            _ => {}
        }
    }
    l
}

#[derive(Clone, Copy, PartialEq)]
enum MlState {
    Top,
    Context,
    Leader,
    Line,
}

fn multileader(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> MultiLeader {
    let mut m = MultiLeader::default();
    let mut state = MlState::Top;
    for t in data {
        match state {
            MlState::Top => {
                if p3(&mut m.block_scale, t, 10) {
                    continue;
                }
                match t.code {
                    300 => state = MlState::Context,
                    340 => m.style = handle(t),
                    90 => m.property_overrides = t.int(),
                    170 => m.leader_line_type = t.i16(),
                    91 => m.leader_line_color = Color::from_raw(t.int()),
                    341 => m.leader_linetype = handle(t),
                    171 => m.leader_lineweight = LineWeight::from_code(t.int()),
                    290 => m.landing = t.bool(),
                    291 => m.dogleg = t.bool(),
                    41 => m.dogleg_length = t.f64(),
                    342 => m.arrowhead = handle(t),
                    42 => m.arrowhead_size = t.f64(),
                    172 => m.content_type = t.i16(),
                    343 => m.text_style = handle(t),
                    173 => m.text_left_attachment = t.i16(),
                    95 => m.text_right_attachment = t.i16(),
                    174 => m.text_angle_type = t.i16(),
                    175 => m.text_alignment_type = t.i16(),
                    92 => m.text_color = Color::from_raw(t.int()),
                    292 => m.text_frame = t.bool(),
                    344 => m.block = handle(t),
                    93 => m.block_color = Color::from_raw(t.int()),
                    43 => m.block_rotation = t.f64(),
                    176 => m.block_connection = t.i16(),
                    330 => {
                        if ctx.room(m.block_attributes.len()) {
                            m.block_attributes.push(MLeaderAttribute {
                                definition: handle(t),
                                ..MLeaderAttribute::default()
                            });
                        }
                    }
                    177 | 44 | 302 => {
                        if let Some(a) = m.block_attributes.last_mut() {
                            match t.code {
                                177 => a.index = t.i16(),
                                44 => a.width = t.f64(),
                                _ => a.text = ctx.text(t),
                            }
                        }
                    }
                    179 => m.text_attachment_point = t.i16(),
                    _ => {}
                }
            }
            MlState::Context => {
                let c = &mut m.context;
                if p3(&mut c.content_base, t, 10)
                    || p3(&mut c.text_normal, t, 11)
                    || p3(&mut c.text_location, t, 12)
                    || p3(&mut c.text_direction, t, 13)
                    || p3(&mut c.block_normal, t, 14)
                    || p3(&mut c.block_position, t, 15)
                    || p3(&mut c.block_scale, t, 16)
                    || p3(&mut c.plane_origin, t, 110)
                    || p3(&mut c.plane_x_axis, t, 111)
                    || p3(&mut c.plane_y_axis, t, 112)
                {
                    continue;
                }
                match t.code {
                    301 => state = MlState::Top,
                    302 => {
                        if ctx.room(c.leaders.len()) {
                            c.leaders.push(MLeaderRoot::default());
                        }
                        state = MlState::Leader;
                    }
                    40 => c.scale = t.f64(),
                    41 => c.text_height = t.f64(),
                    140 => c.arrowhead_size = t.f64(),
                    145 => c.landing_gap = t.f64(),
                    290 => c.has_text = t.bool(),
                    304 => c.text = ctx.text(t),
                    340 => c.text_style = handle(t),
                    42 => c.text_rotation = t.f64(),
                    43 => c.text_width = t.f64(),
                    44 => c.text_boundary_height = t.f64(),
                    45 => c.line_spacing_factor = t.f64(),
                    170 => c.line_spacing_style = t.i16(),
                    90 => c.text_color = Color::from_raw(t.int()),
                    171 => c.text_attachment = t.i16(),
                    172 => c.text_flow_direction = t.i16(),
                    296 => c.has_block = t.bool(),
                    341 => c.block = handle(t),
                    46 => c.block_rotation = t.f64(),
                    93 => c.block_color = Color::from_raw(t.int()),
                    47 => push_f64(&mut c.block_transform, t, ctx),
                    297 => c.plane_normal_reversed = t.bool(),
                    _ => {}
                }
            }
            MlState::Leader => {
                if t.code == 303 {
                    state = MlState::Context;
                    continue;
                }
                if t.code == 304 {
                    if let Some(r) = m.context.leaders.last_mut() {
                        if ctx.room(r.lines.len()) {
                            r.lines.push(MLeaderLine::default());
                        }
                    }
                    state = MlState::Line;
                    continue;
                }
                let Some(r) = m.context.leaders.last_mut() else {
                    continue;
                };
                if p3(&mut r.connection_point, t, 10) || p3(&mut r.direction, t, 11) {
                    continue;
                }
                match t.code {
                    290 => r.has_connection_point = t.bool(),
                    291 => r.has_direction = t.bool(),
                    90 => r.branch_index = t.i32(),
                    40 => r.dogleg_length = t.f64(),
                    271 => r.attachment_direction = t.i16(),
                    _ => {}
                }
            }
            MlState::Line => {
                if t.code == 305 {
                    state = MlState::Leader;
                    continue;
                }
                let Some(line) = m
                    .context
                    .leaders
                    .last_mut()
                    .and_then(|r| r.lines.last_mut())
                else {
                    continue;
                };
                if push3(&mut line.vertices, t, 10, ctx) {
                    continue;
                }
                if t.code == 91 {
                    line.index = t.i32();
                }
            }
        }
    }
    m
}

fn mline(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> MLine {
    let mut m = MLine::default();
    for t in data {
        if p3(&mut m.start, t, 10) || p3(&mut m.extrusion, t, 210) {
            continue;
        }
        if t.code == 11 {
            if ctx.room(m.vertices.len()) {
                m.vertices.push(MLineVertex::default());
            } else {
                continue;
            }
        }
        if let Some(v) = m.vertices.last_mut() {
            if p3(&mut v.position, t, 11) || p3(&mut v.direction, t, 12) || p3(&mut v.miter, t, 13)
            {
                continue;
            }
            match t.code {
                74 => {
                    if ctx.room(v.elements.len()) {
                        v.elements.push(MLineElement::default());
                    }
                    continue;
                }
                41 | 42 => {
                    if let Some(e) = v.elements.last_mut() {
                        let list = if t.code == 41 {
                            &mut e.parameters
                        } else {
                            &mut e.fill_parameters
                        };
                        if ctx.room(list.len()) {
                            list.push(t.f64());
                        }
                    }
                    continue;
                }
                _ => {}
            }
        }
        match t.code {
            2 => m.style_name = ctx.text(t),
            340 => m.style = handle(t),
            40 => m.scale = t.f64(),
            70 => m.justification = t.i16(),
            71 => m.flags = t.i16(),
            73 => m.style_element_count = t.i16(),
            _ => {}
        }
    }
    m
}

/// A read position in a list of groups, for the count-driven parts of a
/// hatch.
struct Cursor<'t, 'a> {
    tags: &'t [Tag<'a>],
    pos: usize,
}

impl<'t, 'a> Cursor<'t, 'a> {
    fn peek(&self) -> Option<&'t Tag<'a>> {
        self.tags.get(self.pos)
    }

    fn peek_code(&self) -> Option<i32> {
        self.peek().map(|t| t.code)
    }

    fn code_after(&self, n: usize) -> Option<i32> {
        self.tags.get(self.pos + n).map(|t| t.code)
    }

    fn next(&mut self) -> Option<&'t Tag<'a>> {
        let t = self.tags.get(self.pos)?;
        self.pos += 1;
        Some(t)
    }

    /// The next group if it has this code.
    fn take(&mut self, code: i32) -> Option<&'t Tag<'a>> {
        if self.peek_code() == Some(code) {
            self.next()
        } else {
            None
        }
    }

    fn f64(&mut self, code: i32) -> Option<f64> {
        self.take(code).map(|t| t.f64())
    }

    fn point2(&mut self, x: i32) -> Option<Vec2> {
        let px = self.f64(x)?;
        let py = self.f64(x + 10).unwrap_or(0.0);
        Some(Vec2::new(px, py))
    }

    /// How many items a count group promises, never more than there are
    /// groups left.
    fn count(&mut self, code: i32) -> usize {
        let left = self.tags.len().saturating_sub(self.pos);
        self.take(code)
            .map_or(0, |t| t.int().clamp(0, left as i64) as usize)
    }
}

fn hatch(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> Hatch {
    let mut h = Hatch::default();
    let mut c = Cursor { tags: data, pos: 0 };
    let mut gradient: Option<Gradient> = None;
    let mut seen_paths = false;
    while let Some(t) = c.next() {
        match t.code {
            30 if !seen_paths => h.elevation = t.f64(),
            210 | 220 | 230 => {
                let _ = p3(&mut h.extrusion, t, 210);
            }
            2 => h.pattern_name = ctx.text(t),
            70 => h.solid = t.bool(),
            71 => h.associative = t.bool(),
            91 => {
                seen_paths = true;
                let left = c.tags.len().saturating_sub(c.pos);
                let n = (t.int().clamp(0, left as i64)) as usize;
                for _ in 0..n {
                    if c.peek_code() != Some(92) {
                        break;
                    }
                    let path = boundary_path(&mut c, ctx);
                    if ctx.room(h.paths.len()) {
                        h.paths.push(path);
                    }
                }
            }
            75 => h.style = t.i16(),
            76 => h.pattern_type = t.i16(),
            52 => h.pattern_angle = deg(t),
            41 => h.pattern_scale = t.f64(),
            77 => h.pattern_double = t.bool(),
            78 => {
                let left = c.tags.len().saturating_sub(c.pos);
                let n = (t.int().clamp(0, left as i64)) as usize;
                for _ in 0..n {
                    if c.peek_code() != Some(53) {
                        break;
                    }
                    let line = pattern_line(&mut c, ctx);
                    if ctx.room(h.pattern_lines.len()) {
                        h.pattern_lines.push(line);
                    }
                }
            }
            47 => h.pixel_size = t.f64(),
            98 => {
                let left = c.tags.len().saturating_sub(c.pos);
                let n = (t.int().clamp(0, left as i64)) as usize;
                for _ in 0..n {
                    let Some(p) = c.point2(10) else { break };
                    if ctx.room(h.seeds.len()) {
                        h.seeds.push(p);
                    }
                }
            }
            450 => {
                gradient = Some(Gradient {
                    kind: t.i32(),
                    name: String::new(),
                    angle: 0.0,
                    shift: 0.0,
                    single_color: false,
                    tint: 0.0,
                    colors: Vec::new(),
                })
            }
            452 | 460 | 461 | 462 | 470 | 463 | 63 | 421 => {
                let Some(g) = gradient.as_mut() else {
                    continue;
                };
                match t.code {
                    452 => g.single_color = t.bool(),
                    460 => g.angle = t.f64(),
                    461 => g.shift = t.f64(),
                    462 => g.tint = t.f64(),
                    470 => g.name = ctx.text(t),
                    463 => {
                        if ctx.room(g.colors.len()) {
                            g.colors.push((t.f64(), Color::ByLayer));
                        }
                    }
                    63 => {
                        if let Some(stop) = g.colors.last_mut() {
                            if stop.1 == Color::ByLayer {
                                stop.1 = Color::from_aci(t.int());
                            }
                        }
                    }
                    _ => {
                        if let Some(stop) = g.colors.last_mut() {
                            stop.1 = Color::from_rgb24(t.int());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    h.gradient = gradient;
    h
}

fn boundary_path(c: &mut Cursor<'_, '_>, ctx: &mut Ctx<'_>) -> BoundaryPath {
    let flags = c.next().map_or(0, |t| t.i32());
    let data = if flags & 2 != 0 {
        let has_bulge = c.take(72).is_some_and(|t| t.bool());
        let closed = c.take(73).is_some_and(|t| t.bool());
        let n = c.count(93);
        let mut vertices = Vec::new();
        for _ in 0..n {
            let Some(p) = c.point2(10) else { break };
            let bulge = if has_bulge || c.peek_code() == Some(42) {
                c.f64(42).unwrap_or(0.0)
            } else {
                0.0
            };
            if ctx.room(vertices.len()) {
                vertices.push((p, bulge));
            }
        }
        BoundaryData::Polyline { closed, vertices }
    } else {
        let n = c.count(93);
        let mut edges = Vec::new();
        for _ in 0..n {
            if c.peek_code() != Some(72) {
                break;
            }
            let Some(edge) = edge(c, ctx) else { continue };
            if ctx.room(edges.len()) {
                edges.push(edge);
            }
        }
        BoundaryData::Edges(edges)
    };
    let mut sources = Vec::new();
    let n = c.count(97);
    for _ in 0..n {
        let Some(t) = c.take(330) else { break };
        if ctx.room(sources.len()) {
            sources.push(handle(t));
        }
    }
    BoundaryPath {
        flags,
        data,
        sources,
    }
}

fn edge(c: &mut Cursor<'_, '_>, ctx: &mut Ctx<'_>) -> Option<Edge> {
    let kind = c.next()?.int();
    Some(match kind {
        1 => Edge::Line {
            start: c.point2(10).unwrap_or_default(),
            end: c.point2(11).unwrap_or_default(),
        },
        2 => Edge::Arc {
            center: c.point2(10).unwrap_or_default(),
            radius: c.f64(40).unwrap_or(0.0),
            start_angle: c.f64(50).unwrap_or(0.0).to_radians(),
            end_angle: c.f64(51).unwrap_or(0.0).to_radians(),
            counter_clockwise: c.take(73).is_none_or(|t| t.bool()),
        },
        3 => Edge::Ellipse {
            center: c.point2(10).unwrap_or_default(),
            major_axis: c.point2(11).unwrap_or_default(),
            ratio: c.f64(40).unwrap_or(1.0),
            start_angle: c.f64(50).unwrap_or(0.0).to_radians(),
            end_angle: c.f64(51).unwrap_or(0.0).to_radians(),
            counter_clockwise: c.take(73).is_none_or(|t| t.bool()),
        },
        4 => {
            let degree = c.take(94).map_or(3, |t| t.i32());
            let rational = c.take(73).is_some_and(|t| t.bool());
            let periodic = c.take(74).is_some_and(|t| t.bool());
            let n_knots = c.count(95);
            let n_points = c.count(96);
            let mut knots = Vec::new();
            for _ in 0..n_knots {
                let Some(k) = c.f64(40) else { break };
                if ctx.room(knots.len()) {
                    knots.push(k);
                }
            }
            let mut control_points = Vec::new();
            let mut weights = Vec::new();
            for _ in 0..n_points {
                let Some(p) = c.point2(10) else { break };
                if let Some(w) = c.f64(42) {
                    if ctx.room(weights.len()) {
                        weights.push(w);
                    }
                }
                if ctx.room(control_points.len()) {
                    control_points.push(p);
                }
            }
            // From 2010 a spline edge has a fit point count (and the fit
            // points, then tangents); before, the next 97 is the path's own
            // source count. Told apart by version, or by what follows.
            let mut fit_points = Vec::new();
            let mut start_tangent = None;
            let mut end_tangent = None;
            let fit_follows = c.peek_code() == Some(97)
                && (ctx.version >= Version::R2010
                    || matches!(c.code_after(1), Some(11 | 12 | 13 | 97)));
            if fit_follows {
                let n_fit = c.count(97);
                for _ in 0..n_fit {
                    let Some(p) = c.point2(11) else { break };
                    if ctx.room(fit_points.len()) {
                        fit_points.push(p);
                    }
                }
                start_tangent = c.point2(12);
                end_tangent = c.point2(13);
            }
            if !rational && weights.iter().all(|w| *w == 1.0) {
                weights.clear();
            }
            Edge::Spline {
                degree,
                rational,
                periodic,
                knots,
                control_points,
                weights,
                fit_points,
                start_tangent,
                end_tangent,
            }
        }
        _ => {
            // An unknown edge type: skip to the next edge or the path's end.
            while let Some(code) = c.peek_code() {
                if matches!(code, 72 | 97 | 92) {
                    break;
                }
                c.next();
            }
            return None;
        }
    })
}

fn pattern_line(c: &mut Cursor<'_, '_>, ctx: &mut Ctx<'_>) -> PatternLine {
    let mut l = PatternLine {
        angle: c.f64(53).unwrap_or(0.0).to_radians(),
        ..PatternLine::default()
    };
    l.base.x = c.f64(43).unwrap_or(0.0);
    l.base.y = c.f64(44).unwrap_or(0.0);
    l.offset.x = c.f64(45).unwrap_or(0.0);
    l.offset.y = c.f64(46).unwrap_or(0.0);
    let n = c.count(79);
    for _ in 0..n {
        let Some(d) = c.f64(49) else { break };
        if ctx.room(l.dashes.len()) {
            l.dashes.push(d);
        }
    }
    l
}

fn helix(parts: &Parts<'_>, ctx: &mut Ctx<'_>) -> Helix {
    let mut h = Helix {
        spline: spline(parts.subclass("AcDbSpline").unwrap_or(&[]), ctx),
        ..Helix::default()
    };
    for t in parts.subclass("AcDbHelix").unwrap_or(&[]) {
        if p3(&mut h.axis_base, t, 10)
            || p3(&mut h.start_point, t, 11)
            || p3(&mut h.axis_vector, t, 12)
        {
            continue;
        }
        match t.code {
            40 => h.radius = t.f64(),
            41 => h.turns = t.f64(),
            42 => h.turn_height = t.f64(),
            290 => h.right_handed = t.bool(),
            280 => h.constraint = t.i16(),
            _ => {}
        }
    }
    h
}

fn ray(data: &[Tag<'_>]) -> Ray {
    let mut r = Ray::default();
    for t in data {
        let _ = p3(&mut r.base, t, 10) || p3(&mut r.direction, t, 11);
    }
    r
}

fn viewport(parts: &Parts<'_>, data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> Viewport {
    let mut v = Viewport::default();
    for t in data {
        if p3(&mut v.center, t, 10)
            || p2(&mut v.view_center, t, 12)
            || p2(&mut v.snap_base, t, 13)
            || p2(&mut v.snap_spacing, t, 14)
            || p2(&mut v.grid_spacing, t, 15)
            || p3(&mut v.view_direction, t, 16)
            || p3(&mut v.view_target, t, 17)
        {
            continue;
        }
        match t.code {
            40 => v.width = t.f64(),
            41 => v.height = t.f64(),
            68 => v.status = t.i16(),
            69 => v.id = t.i16(),
            42 => v.lens_length = t.f64(),
            43 => v.front_clip = t.f64(),
            44 => v.back_clip = t.f64(),
            45 => v.view_height = t.f64(),
            50 => v.snap_angle = deg(t),
            51 => v.twist = deg(t),
            72 => v.circle_zoom = t.i16(),
            // 331 in the 2012 reference; the converter writes 341 in 2000
            // files.
            331 | 341 => {
                if ctx.room(v.frozen_layers.len()) {
                    v.frozen_layers.push(handle(t));
                }
            }
            90 => v.flags = t.i32(),
            340 => v.clip_boundary = handle(t),
            1 => v.plot_style_sheet = ctx.text(t),
            281 => v.render_mode = t.i16(),
            146 => v.elevation = t.f64(),
            170 => v.shade_plot_mode = t.i16(),
            _ => {}
        }
    }
    if let Some(x) = parts.xdata("ACAD") {
        r12_viewport(&mut v, x, ctx);
    }
    v
}

/// The view of an R12 viewport, kept in its `ACAD` extended data after
/// `1000 MVIEW`: a version, the target, the direction, then numbered reals
/// and integers, and the frozen layers by name (1003).
fn r12_viewport(v: &mut Viewport, x: &[Tag<'_>], ctx: &mut Ctx<'_>) {
    let Some(start) = x.iter().position(|t| t.code == 1000 && t.is("MVIEW")) else {
        return;
    };
    // Groups after the opening brace and the version.
    let body = x.get(start + 3..).unwrap_or(&[]);
    let mut points = Vec::new();
    let mut scalars = Vec::new();
    for t in body {
        match t.code {
            1010 => points.push(Vec3::new(t.f64(), 0.0, 0.0)),
            1020 => {
                if let Some(p) = points.last_mut() {
                    p.y = t.f64();
                }
            }
            1030 => {
                if let Some(p) = points.last_mut() {
                    p.z = t.f64();
                }
            }
            1040 | 1070 => scalars.push(t.f64()),
            1002 => break,
            _ => {}
        }
        if scalars.len() > 64 {
            break;
        }
    }
    if let [target, direction, ..] = points.as_slice() {
        v.view_target = *target;
        v.view_direction = *direction;
    }
    let s = |i: usize| scalars.get(i).copied();
    if let Some(a) = s(0) {
        v.twist = a.to_radians();
    }
    if let Some(h) = s(1) {
        v.view_height = h;
    }
    if let (Some(x0), Some(y0)) = (s(2), s(3)) {
        v.view_center = Vec2::new(x0, y0);
    }
    if let Some(l) = s(4) {
        v.lens_length = l;
    }
    if let Some(f) = s(5) {
        v.front_clip = f;
    }
    if let Some(b) = s(6) {
        v.back_clip = b;
    }
    // The view mode (VIEWMODE): perspective, front and back clipping, UCS
    // follow, front clip not at eye, the low bits of the 2000 flags.
    if let Some(m) = s(7) {
        v.flags |= (m as i32) & 0x1F;
    }
    // Fast zoom, snap, grid, isometric snap and hide plot, as on/off values.
    for (i, bit) in [
        (9, 0x80),
        (11, 0x100),
        (12, 0x200),
        (13, 0x400),
        (22, 0x800),
    ] {
        if s(i).is_some_and(|x| x != 0.0) {
            v.flags |= bit;
        }
    }
    if let Some(z) = s(8) {
        v.circle_zoom = z as i16;
    }
    if let Some(a) = s(15) {
        v.snap_angle = a.to_radians();
    }
    if let (Some(x0), Some(y0)) = (s(16), s(17)) {
        v.snap_base = Vec2::new(x0, y0);
    }
    if let (Some(x0), Some(y0)) = (s(18), s(19)) {
        v.snap_spacing = Vec2::new(x0, y0);
    }
    if let (Some(x0), Some(y0)) = (s(20), s(21)) {
        v.grid_spacing = Vec2::new(x0, y0);
    }
    // Frozen layers by name, resolved to the layer table's handles (read
    // before any entity).
    for t in x.get(start..).unwrap_or(&[]) {
        if t.code != 1003 {
            continue;
        }
        let name = ctx.text(t);
        let found = ctx
            .layer_handles
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(&name))
            .map(|(_, h)| *h);
        if let Some(h) = found {
            if ctx.room(v.frozen_layers.len()) {
                v.frozen_layers.push(h);
            }
        }
    }
}

fn image(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> Image {
    let mut i = Image::default();
    for t in data {
        if p3(&mut i.insertion, t, 10)
            || p3(&mut i.u_vector, t, 11)
            || p3(&mut i.v_vector, t, 12)
            || p2(&mut i.size, t, 13)
            || push2(&mut i.clip_vertices, t, 14, ctx)
        {
            continue;
        }
        match t.code {
            90 => i.class_version = t.i32(),
            340 => i.image_def = handle(t),
            70 => i.display = t.i16(),
            280 => i.clipping = t.bool(),
            281 => i.brightness = t.i16(),
            282 => i.contrast = t.i16(),
            283 => i.fade = t.i16(),
            360 => i.reactor = handle(t),
            71 => i.clip_type = t.i16(),
            290 => i.clip_inside = t.bool(),
            _ => {}
        }
    }
    i
}

fn underlay(data: &[Tag<'_>], kind: UnderlayKind, ctx: &mut Ctx<'_>) -> Underlay {
    let mut u = Underlay {
        kind,
        ..Underlay::default()
    };
    for t in data {
        if p3(&mut u.insertion, t, 10)
            || p3(&mut u.extrusion, t, 210)
            || push2(&mut u.clip_vertices, t, 11, ctx)
        {
            continue;
        }
        match t.code {
            340 => u.definition = handle(t),
            41 => u.scale.x = t.f64(),
            42 => u.scale.y = t.f64(),
            43 => u.scale.z = t.f64(),
            50 => u.rotation = deg(t),
            280 => u.flags = t.i16(),
            281 => u.contrast = t.i16(),
            282 => u.fade = t.i16(),
            _ => {}
        }
    }
    u
}

fn ole2frame(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> Ole2Frame {
    let mut o = Ole2Frame::default();
    for t in data {
        if p3(&mut o.upper_left, t, 10) || p3(&mut o.lower_right, t, 11) {
            continue;
        }
        match t.code {
            70 => o.version = t.i16(),
            3 => o.description = ctx.text(t),
            71 => o.ole_type = t.i16(),
            72 => o.tile_mode = t.i16(),
            90 => o.data_length = t.int(),
            _ => {}
        }
    }
    o
}

fn table(parts: &Parts<'_>, ctx: &mut Ctx<'_>) -> Table {
    let mut tb = Table::default();
    let reference = match parts.subclass("AcDbBlockReference") {
        Some(r) => r,
        None => parts.after("AcDbEntity"),
    };
    for t in reference {
        if p3(&mut tb.insertion, t, 10) {
            continue;
        }
        if t.code == 2 {
            tb.block_name = ctx.text(t);
        }
    }
    // Cell data repeats 91, 92 and 11 with other meanings: the first of
    // each is the table's.
    let (mut rows, mut cols, mut dir) = (false, false, false);
    let mut direction = Vec3::default();
    for t in parts.subclass("AcDbTable").unwrap_or(&[]) {
        match t.code {
            342 => tb.style = handle(t),
            343 => tb.block_record = handle(t),
            11 | 21 | 31 if !dir => {
                let _ = p3(&mut direction, t, 11);
                if t.code == 31 {
                    dir = true;
                }
            }
            91 if !rows => {
                tb.rows = t.i32();
                rows = true;
            }
            92 if !cols => {
                tb.columns = t.i32();
                cols = true;
            }
            141 => push_f64(&mut tb.row_heights, t, ctx),
            142 => push_f64(&mut tb.column_widths, t, ctx),
            _ => {}
        }
    }
    if direction != Vec3::default() {
        tb.horizontal_direction = direction;
    }
    tb
}

fn shape(data: &[Tag<'_>], ctx: &mut Ctx<'_>) -> Shape {
    let mut s = Shape::default();
    for t in data {
        if p3(&mut s.insertion, t, 10) || plane(&mut s.plane, t) {
            continue;
        }
        match t.code {
            40 => s.size = t.f64(),
            2 => s.name = ctx.text(t),
            50 => s.rotation = deg(t),
            41 => s.width_factor = t.f64(),
            51 => s.oblique = deg(t),
            _ => {}
        }
    }
    s
}
