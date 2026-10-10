//! Each entity type's own data (ODA spec 20.4.3 to 20.4.88), after the
//! common data `exav_unpack::dwg` reads, into the model's [`EntityKind`].
//!
//! Values are read in the order the spec lists them, from the object's
//! data stream, its string stream (TV fields, R2007 on) and its handle
//! stream (the handles after the common ones). Where files differ from the
//! spec the comment says how that was found. Every count is checked against
//! the bits left before anything is reserved for it; items past
//! [`Limits::max_items`](crate::formats::cad::Limits) are read and dropped.

use exav_unpack::dwg::{BitError, BitResult, Bits, EedValue, Object, Version};

use super::tables::cmc;
use super::Ctx;
use crate::formats::cad::model::*;

/// The entities an INSERT or a POLYLINE owns (its ATTRIBs, its VERTEXes):
/// R13 to R2000 the first and last of a chain, R2004 on a list.
pub(crate) enum Followers {
    None,
    Chain(u64, u64),
    Owned(Vec<u64>),
}

fn v3(p: [f64; 3]) -> Vec3 {
    Vec3::new(p[0], p[1], p[2])
}

fn v2(p: [f64; 2]) -> Vec2 {
    Vec2::new(p[0], p[1])
}

/// A count read as `n`, which `min_bits` bits per item must fit in what is
/// left of `b`.
fn count(b: &Bits<'_>, n: i64, min_bits: u64) -> BitResult<usize> {
    let n = u64::try_from(n).map_err(|_| BitError::Invalid)?;
    if n.saturating_mul(min_bits.max(1)) > b.remaining() {
        return Err(BitError::End);
    }
    usize::try_from(n).map_err(|_| BitError::Invalid)
}

/// Push unless the list is at the item limit.
fn push<T>(ctx: &mut Ctx<'_, '_>, v: &mut Vec<T>, x: T) {
    if ctx.room(v.len()) {
        v.push(x);
    }
}

fn string(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<String> {
    let t = o.tv()?;
    Ok(ctx.string(t))
}

/// The name of the table entry a handle of the handle stream refers to.
fn entry(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>, what: &str) -> BitResult<String> {
    let h = o.handle_ref()?;
    Ok(ctx.referenced_name(h, what).unwrap_or_default())
}

/// A TEXT's, ATTRIB's, ATTDEF's or MTEXT's style: a null handle is DXF's
/// group 7 left out, which is STANDARD (DXF reference; an AutoCAD 2013
/// file's 731 TEXTs with a null style handle have no 7 in the converter's
/// DXF).
fn text_style(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<String> {
    let h = o.handle_ref()?;
    Ok(text_style_name(h, ctx.referenced_name(h, "text style")))
}

fn text_style_name(handle: u64, name: Option<String>) -> String {
    match name {
        _ if handle == 0 => "STANDARD".to_string(),
        n => n.unwrap_or_default(),
    }
}

/// The handles of the owned entities (R2004 on), `n` of them.
fn owned(o: &mut Object<'_>, n: u64) -> BitResult<Vec<u64>> {
    // A handle takes at least a byte.
    if n > o.handles.remaining() / 8 {
        return Err(BitError::End);
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        out.push(o.handle_ref()?);
    }
    Ok(out)
}

/// The owned-object count of R2004 on.
fn owned_count(o: &mut Object<'_>, v: Version) -> BitResult<u64> {
    if v >= Version::R2004 {
        u64::try_from(o.data.bl()?).map_err(|_| BitError::Invalid)
    } else {
        Ok(0)
    }
}

/// What a POLYLINE or INSERT's followers are, from its handle stream after
/// the type's own handles before them.
fn followers(o: &mut Object<'_>, v: Version, present: bool, n: u64) -> BitResult<Followers> {
    if !present {
        return Ok(Followers::None);
    }
    let f = if v >= Version::R2004 {
        Followers::Owned(owned(o, n)?)
    } else {
        let first = o.handle_ref()?;
        let last = o.handle_ref()?;
        Followers::Chain(first, last)
    };
    o.handle_ref()?; // SEQEND
    Ok(f)
}

/// Read the type's own data of `o`, whose DXF type is `name`.
pub(crate) fn read(
    ctx: &mut Ctx<'_, '_>,
    o: &mut Object<'_>,
    name: &str,
) -> BitResult<Option<(EntityKind, Followers)>> {
    let v = ctx.version;
    let none = |k: EntityKind| Ok(Some((k, Followers::None)));
    match o.type_code {
        0x01 => return none(EntityKind::Text(Box::new(text(ctx, o)?))),
        0x02 => return none(EntityKind::Attribute(Box::new(attribute(ctx, o, false)?))),
        0x03 => {
            return none(EntityKind::AttributeDefinition(Box::new(attribute(
                ctx, o, true,
            )?)))
        }
        0x07 | 0x08 => {
            let (i, f) = insert(ctx, o, o.type_code == 0x08)?;
            return Ok(Some((EntityKind::Insert(Box::new(i)), f)));
        }
        0x0F | 0x10 | 0x1D | 0x1E => {
            let (p, f) = polyline(ctx, o)?;
            return Ok(Some((EntityKind::Polyline(p), f)));
        }
        0x11 => return none(EntityKind::Arc(arc(o, v)?)),
        0x12 => return none(EntityKind::Circle(circle(o, v)?)),
        0x13 => return none(EntityKind::Line(line(o, v)?)),
        0x14..=0x1A => return none(EntityKind::Dimension(Box::new(dimension(ctx, o, name)?))),
        0x1B => return none(EntityKind::Point(point(o, v)?)),
        0x1C => return none(EntityKind::Face3D(face3d(o, v)?)),
        0x1F => return none(EntityKind::Solid(quad(o, v)?)),
        0x20 => return none(EntityKind::Trace(quad(o, v)?)),
        0x21 => return none(EntityKind::Shape(shape(o)?)),
        0x22 => return none(EntityKind::Viewport(Box::new(viewport(ctx, o)?))),
        0x23 => return none(EntityKind::Ellipse(ellipse(o)?)),
        0x24 => return none(EntityKind::Spline(Box::new(spline(ctx, o)?))),
        0x28 => return none(EntityKind::Ray(ray(o)?)),
        0x29 => return none(EntityKind::XLine(ray(o)?)),
        0x2C => return none(EntityKind::MText(Box::new(mtext(ctx, o)?))),
        0x2D => return none(EntityKind::Leader(Box::new(leader(ctx, o)?))),
        0x2F => return none(EntityKind::MLine(Box::new(mline(ctx, o)?))),
        _ => {}
    }
    // The other types by their class's DXF name (or a fixed code that
    // names one).
    match name {
        "LWPOLYLINE" => none(EntityKind::LwPolyline(lwpolyline(ctx, o)?)),
        "HATCH" => none(EntityKind::Hatch(Box::new(hatch(ctx, o)?))),
        "IMAGE" => none(EntityKind::Image(Box::new(image(ctx, o)?))),
        "WIPEOUT" => none(EntityKind::Wipeout(Box::new(image(ctx, o)?))),
        "OLE2FRAME" => none(EntityKind::Ole2Frame(ole2frame(o, v)?)),
        "ARC_DIMENSION" | "LARGE_RADIAL_DIMENSION" => {
            none(EntityKind::Dimension(Box::new(dimension(ctx, o, name)?)))
        }
        "MULTILEADER" => none(EntityKind::MultiLeader(Box::new(multileader(ctx, o)?))),
        "HELIX" => none(EntityKind::Helix(Box::new(helix(ctx, o)?))),
        "ACAD_TABLE" => none(EntityKind::Table(Box::new(table(ctx, o)?))),
        "PDFUNDERLAY" => none(EntityKind::Underlay(Box::new(underlay(
            ctx,
            o,
            UnderlayKind::Pdf,
        )?))),
        "DWFUNDERLAY" => none(EntityKind::Underlay(Box::new(underlay(
            ctx,
            o,
            UnderlayKind::Dwf,
        )?))),
        "DGNUNDERLAY" => none(EntityKind::Underlay(Box::new(underlay(
            ctx,
            o,
            UnderlayKind::Dgn,
        )?))),
        _ => Ok(None),
    }
}

/// ACAD_TABLE (spec 20.4.96): an INSERT's data, then until R2010 the
/// table's flags, direction, column widths and row heights (20.4.96.1).
/// From R2010 the rest is the table content (20.4.97), not read here: its
/// block (which draws it) and insertion point are.
fn table(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Table> {
    let v = ctx.version;
    let b = &mut o.data;
    let mut t = Table {
        insertion: v3(b.bd3()?),
        ..Table::default()
    };
    scale(b, v)?;
    b.bd()?; // rotation
    b.bd3()?; // extrusion
    let has_attribs = b.b()?;
    let n = if has_attribs { owned_count(o, v)? } else { 0 };
    let block = o.handle_ref()?;
    t.block_record = Handle(block);
    t.block_name = ctx.name(block).unwrap_or_default().to_string();
    followers(o, v, has_attribs, n)?;
    if v >= Version::R2010 {
        return Ok(t);
    }
    let b = &mut o.data;
    b.bs()?; // flags
    t.horizontal_direction = v3(b.bd3()?);
    let columns = b.bl()?;
    let rows = b.bl()?;
    t.columns = columns;
    t.rows = rows;
    let columns = count(b, i64::from(columns), 2)?;
    for _ in 0..columns {
        let w = o.data.bd()?;
        push(ctx, &mut t.column_widths, w);
    }
    let rows = count(&o.data, i64::from(rows), 2)?;
    for _ in 0..rows {
        let h = o.data.bd()?;
        push(ctx, &mut t.row_heights, h);
    }
    t.style = Handle(o.handle_ref()?);
    Ok(t)
}

/// PDF, DWF and DGN underlays (class PDFREFERENCE...), which the spec
/// leaves out: extrusion, insertion point (3BD), rotation (BD), scale
/// (3BD), flags, contrast and fade (RC), the clip boundary's vertex count
/// (BL) and vertices (2RD); the definition is the handle. Found on the
/// corpus's underlays, whose data ends exactly there in every version and
/// whose values are their DXF's (210, 10, 50, 41-43, 280-282, 11).
fn underlay(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>, kind: UnderlayKind) -> BitResult<Underlay> {
    let b = &mut o.data;
    let mut u = Underlay {
        kind,
        extrusion: v3(b.bd3()?),
        insertion: v3(b.bd3()?),
        rotation: b.bd()?,
        scale: v3(b.bd3()?),
        flags: i16::from(b.rc()?),
        contrast: i16::from(b.rc()?),
        fade: i16::from(b.rc()?),
        ..Underlay::default()
    };
    let n = i64::from(b.bl()?);
    let n = count(b, n, 128)?;
    for _ in 0..n {
        let p = v2(o.data.rd2()?);
        push(ctx, &mut u.clip_vertices, p);
    }
    u.definition = Handle(o.handle_ref()?);
    Ok(u)
}

/// HELIX, which the spec leaves out: a SPLINE's data, then the release
/// numbers (DXF 90, 91), the axis base point, start point and axis vector
/// (3BD), radius, turns and turn height (BD), handedness (B) and constraint
/// (RC), in DXF's order. Found on the corpus's HELIX entities, whose data
/// ends exactly there in every version.
fn helix(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Helix> {
    let spline = spline(ctx, o)?;
    let b = &mut o.data;
    b.bl()?; // major release
    b.bl()?; // maintenance release
    Ok(Helix {
        spline,
        axis_base: v3(b.bd3()?),
        start_point: v3(b.bd3()?),
        axis_vector: v3(b.bd3()?),
        radius: b.bd()?,
        turns: b.bd()?,
        turn_height: b.bd()?,
        right_handed: b.b()?,
        constraint: i16::from(b.rc()?),
    })
}

fn line(o: &mut Object<'_>, v: Version) -> BitResult<Line> {
    let b = &mut o.data;
    let (start, end) = if v >= Version::R2000 {
        // Spec 20.4.21: each end coordinate defaults to the start's.
        let z_zero = b.b()?;
        let x1 = b.rd()?;
        let x2 = b.dd(x1)?;
        let y1 = b.rd()?;
        let y2 = b.dd(y1)?;
        let (z1, z2) = if z_zero {
            (0.0, 0.0)
        } else {
            let z1 = b.rd()?;
            (z1, b.dd(z1)?)
        };
        (Vec3::new(x1, y1, z1), Vec3::new(x2, y2, z2))
    } else {
        (v3(b.bd3()?), v3(b.bd3()?))
    };
    let thickness = b.bt(v)?;
    let extrusion = v3(b.be(v)?);
    Ok(Line {
        start,
        end,
        plane: Plane {
            thickness,
            extrusion,
        },
    })
}

fn plane(b: &mut Bits<'_>, v: Version) -> BitResult<Plane> {
    let thickness = b.bt(v)?;
    let extrusion = v3(b.be(v)?);
    Ok(Plane {
        thickness,
        extrusion,
    })
}

fn point(o: &mut Object<'_>, v: Version) -> BitResult<Point> {
    let b = &mut o.data;
    let location = v3(b.bd3()?);
    let plane = plane(b, v)?;
    Ok(Point {
        location,
        plane,
        x_axis_angle: b.bd()?,
    })
}

fn circle(o: &mut Object<'_>, v: Version) -> BitResult<Circle> {
    let b = &mut o.data;
    let center = v3(b.bd3()?);
    let radius = b.bd()?;
    Ok(Circle {
        center,
        radius,
        plane: plane(b, v)?,
    })
}

fn arc(o: &mut Object<'_>, v: Version) -> BitResult<Arc> {
    let b = &mut o.data;
    let center = v3(b.bd3()?);
    let radius = b.bd()?;
    let plane = plane(b, v)?;
    Ok(Arc {
        center,
        radius,
        plane,
        start_angle: b.bd()?,
        end_angle: b.bd()?,
    })
}

fn ellipse(o: &mut Object<'_>) -> BitResult<Ellipse> {
    let b = &mut o.data;
    Ok(Ellipse {
        center: v3(b.bd3()?),
        major_axis: v3(b.bd3()?),
        extrusion: v3(b.bd3()?),
        ratio: b.bd()?,
        start_param: b.bd()?,
        end_param: b.bd()?,
    })
}

fn ray(o: &mut Object<'_>) -> BitResult<Ray> {
    let b = &mut o.data;
    Ok(Ray {
        base: v3(b.bd3()?),
        direction: v3(b.bd3()?),
    })
}

/// SOLID and TRACE (spec 20.4.35, 20.4.36): 2D corners at an elevation.
fn quad(o: &mut Object<'_>, v: Version) -> BitResult<Quad> {
    let b = &mut o.data;
    let thickness = b.bt(v)?;
    let z = b.bd()?;
    let mut corners = [Vec3::default(); 4];
    for c in &mut corners {
        let p = b.rd2()?;
        *c = Vec3::new(p[0], p[1], z);
    }
    let extrusion = v3(b.be(v)?);
    Ok(Quad {
        corners,
        plane: Plane {
            thickness,
            extrusion,
        },
    })
}

fn face3d(o: &mut Object<'_>, v: Version) -> BitResult<Face3D> {
    let b = &mut o.data;
    let mut f = Face3D::default();
    if v < Version::R2000 {
        for c in &mut f.corners {
            *c = v3(b.bd3()?);
        }
        f.invisible_edges = b.bs()?;
        return Ok(f);
    }
    // Spec 20.4.32: the first corner raw, each other a DD of the one
    // before.
    let no_flags = b.b()?;
    let z_zero = b.b()?;
    let x = b.rd()?;
    let y = b.rd()?;
    let z = if z_zero { 0.0 } else { b.rd()? };
    let mut prev = Vec3::new(x, y, z);
    f.corners[0] = prev;
    for c in f.corners.iter_mut().skip(1) {
        let x = b.dd(prev.x)?;
        let y = b.dd(prev.y)?;
        let z = b.dd(prev.z)?;
        prev = Vec3::new(x, y, z);
        *c = prev;
    }
    if !no_flags {
        f.invisible_edges = b.bs()?;
    }
    Ok(f)
}

fn shape(o: &mut Object<'_>) -> BitResult<Shape> {
    let b = &mut o.data;
    let insertion = v3(b.bd3()?);
    let size = b.bd()?;
    let rotation = b.bd()?;
    let width_factor = b.bd()?;
    let oblique = b.bd()?;
    let thickness = b.bd()?;
    // The shape's number in its file: DXF names it, which only the shape
    // file knows.
    b.bs()?;
    let extrusion = v3(b.bd3()?);
    Ok(Shape {
        insertion,
        size,
        name: String::new(),
        rotation,
        width_factor,
        oblique,
        plane: Plane {
            thickness,
            extrusion,
        },
    })
}

/// TEXT (spec 20.4.3), and the text part of ATTRIB and ATTDEF.
fn text(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Text> {
    let v = ctx.version;
    let mut t = Text::default();
    let b = &mut o.data;
    let mut alignment = None;
    let elevation;
    let insertion;
    if v >= Version::R2000 {
        let flags = b.rc()?;
        elevation = if flags & 1 == 0 { b.rd()? } else { 0.0 };
        insertion = b.rd2()?;
        if flags & 2 == 0 {
            let x = b.dd(insertion[0])?;
            let y = b.dd(insertion[1])?;
            alignment = Some([x, y]);
        }
        t.plane.extrusion = v3(b.be(v)?);
        t.plane.thickness = b.bt(v)?;
        t.oblique = if flags & 4 == 0 { b.rd()? } else { 0.0 };
        t.rotation = if flags & 8 == 0 { b.rd()? } else { 0.0 };
        t.height = b.rd()?;
        t.width_factor = if flags & 0x10 == 0 { b.rd()? } else { 1.0 };
        t.value = string(ctx, o)?;
        let b = &mut o.data;
        t.generation = if flags & 0x20 == 0 { b.bs()? } else { 0 };
        t.h_align = HAlign::from_code(if flags & 0x40 == 0 {
            i64::from(b.bs()?)
        } else {
            0
        });
        t.v_align = VAlign::from_code(if flags & 0x80 == 0 {
            i64::from(b.bs()?)
        } else {
            0
        });
    } else {
        elevation = b.bd()?;
        insertion = b.rd2()?;
        alignment = Some(b.rd2()?);
        t.plane.extrusion = v3(b.bd3()?);
        t.plane.thickness = b.bd()?;
        t.oblique = b.bd()?;
        t.rotation = b.bd()?;
        t.height = b.bd()?;
        t.width_factor = b.bd()?;
        t.value = string(ctx, o)?;
        let b = &mut o.data;
        t.generation = b.bs()?;
        t.h_align = HAlign::from_code(i64::from(b.bs()?));
        t.v_align = VAlign::from_code(i64::from(b.bs()?));
    }
    t.insertion = Vec3::new(insertion[0], insertion[1], elevation);
    // The second point places the text unless it is left and baseline
    // aligned, which is when DXF has it (group 11); a file that leaves it
    // out (R2000 on, flag 2) has (0, 0) there: the converter writes 11 as
    // zeros for such a centred ATTDEF.
    if t.h_align != HAlign::Left || t.v_align != VAlign::Baseline {
        let p = alignment.unwrap_or([0.0, 0.0]);
        t.alignment_point = Some(Vec3::new(p[0], p[1], elevation));
    }
    t.style = text_style(ctx, o)?;
    Ok(t)
}

/// ATTRIB (spec 20.4.4) and ATTDEF (20.4.5).
fn attribute(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>, definition: bool) -> BitResult<Attribute> {
    let v = ctx.version;
    let text = text(ctx, o)?;
    let mut a = Attribute {
        text,
        ..Attribute::default()
    };
    if v >= Version::R2010 {
        o.data.rc()?; // version
    }
    let kind = if v >= Version::R2018 { o.data.rc()? } else { 1 };
    if kind == 2 || kind == 4 {
        // A multiline attribute: an MTEXT's data, then the tag.
        let m = embedded_mtext(ctx, o)?;
        a.mtext = Some(Box::new(m));
        let n = o.data.bs()?;
        if n > 0 {
            let n = count(&o.data, i64::from(n), 8)?;
            o.data.skip(n as u64 * 8)?;
            o.handle_ref()?;
            o.data.bs()?;
        }
        a.tag = string(ctx, o)?;
        o.data.bs()?;
        a.flags = i16::from(o.data.rc()?);
        a.lock_position = o.data.b()?;
    } else {
        a.tag = string(ctx, o)?;
        a.field_length = o.data.bs()?;
        a.flags = i16::from(o.data.rc()?);
        if v >= Version::R2007 {
            a.lock_position = o.data.b()?;
        }
    }
    if definition {
        if v >= Version::R2010 {
            o.data.rc()?; // version
        }
        a.prompt = string(ctx, o)?;
    }
    Ok(a)
}

/// INSERT (spec 20.4.9) and MINSERT (20.4.10).
fn insert(
    ctx: &mut Ctx<'_, '_>,
    o: &mut Object<'_>,
    minsert: bool,
) -> BitResult<(Insert, Followers)> {
    let v = ctx.version;
    let b = &mut o.data;
    let mut i = Insert {
        insertion: v3(b.bd3()?),
        ..Insert::default()
    };
    i.scale = scale(b, v)?;
    i.rotation = b.bd()?;
    i.extrusion = v3(b.bd3()?);
    let has_attribs = b.b()?;
    // Spec 20.4.9 has the owned object count in every R2004 INSERT; it is
    // there only when attributes follow: an INSERT without them ends at the
    // has-attributes bit (its data stream of R2004 conversions has the same
    // 273 bits as R2000's).
    let n = if has_attribs { owned_count(o, v)? } else { 0 };
    if minsert {
        let b = &mut o.data;
        i.columns = b.bs()? as u16;
        i.rows = b.bs()? as u16;
        i.column_spacing = b.bd()?;
        i.row_spacing = b.bd()?;
    }
    let block = o.handle_ref()?;
    i.block_name = ctx.name(block).unwrap_or_default().to_string();
    let f = followers(o, v, has_attribs, n)?;
    Ok((i, f))
}

/// An INSERT's scale (spec 20.4.9): from R2000 two bits say which of the
/// three are stored.
fn scale(b: &mut Bits<'_>, v: Version) -> BitResult<Vec3> {
    if v < Version::R2000 {
        return Ok(v3(b.bd3()?));
    }
    Ok(match b.bb()? {
        3 => Vec3::new(1.0, 1.0, 1.0),
        1 => {
            let y = b.dd(1.0)?;
            let z = b.dd(1.0)?;
            Vec3::new(1.0, y, z)
        }
        2 => {
            let x = b.rd()?;
            Vec3::new(x, x, x)
        }
        _ => {
            let x = b.rd()?;
            let y = b.dd(x)?;
            let z = b.dd(x)?;
            Vec3::new(x, y, z)
        }
    })
}

/// The POLYLINEs (spec 20.4.16, 20.4.17, 20.4.33, 20.4.34), DXF's group 70
/// made of what each type stores.
fn polyline(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<(Polyline, Followers)> {
    let v = ctx.version;
    let mut p = Polyline::default();
    let b = &mut o.data;
    match o.type_code {
        0x0F => {
            p.flags = b.bs()?;
            p.curve_type = b.bs()?;
            p.default_start_width = b.bd()?;
            p.default_end_width = b.bd()?;
            p.plane.thickness = b.bt(v)?;
            p.elevation = b.bd()?;
            p.plane.extrusion = v3(b.be(v)?);
        }
        0x10 => {
            let spline = b.rc()?;
            let closed = b.rc()?;
            p.flags = 8;
            if spline & 1 != 0 {
                p.curve_type = 5;
            } else if spline & 2 != 0 {
                p.curve_type = 6;
            }
            if spline & 3 != 0 {
                p.flags |= 4;
            }
            if closed & 1 != 0 {
                p.flags |= 1;
            }
        }
        0x1D => {
            p.flags = 64;
            p.m_count = b.bs()?;
            p.n_count = b.bs()?;
        }
        _ => {
            p.flags = b.bs()? | 16;
            p.curve_type = b.bs()?;
            p.m_count = b.bs()?;
            p.n_count = b.bs()?;
            p.m_density = b.bs()?;
            p.n_density = b.bs()?;
        }
    }
    let n = owned_count(o, v)?;
    let f = followers(o, v, true, n)?;
    Ok((p, f))
}

/// A VERTEX of any kind (spec 20.4.11 to 20.4.15).
pub(crate) fn vertex(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Vertex> {
    let v = ctx.version;
    let b = &mut o.data;
    let mut x = Vertex {
        handle: Handle(o.handle),
        ..Vertex::default()
    };
    match o.type_code {
        0x0A => {
            x.flags = i16::from(b.rc()?);
            x.location = v3(b.bd3()?);
            let start = b.bd()?;
            if start < 0.0 {
                x.start_width = -start;
                x.end_width = -start;
            } else {
                x.start_width = start;
                x.end_width = b.bd()?;
            }
            x.bulge = b.bd()?;
            if v >= Version::R2010 {
                b.bl()?; // vertex ID
            }
            x.tangent = b.bd()?;
        }
        0x0B..=0x0D => {
            x.flags = i16::from(b.rc()?);
            x.location = v3(b.bd3()?);
        }
        0x0E => {
            // A face record: DXF's 70 is 128 for it, and it has no point.
            x.flags = 128;
            for i in &mut x.indices {
                *i = i32::from(b.bs()?);
            }
        }
        _ => return Err(BitError::Invalid),
    }
    Ok(x)
}

fn lwpolyline(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<LwPolyline> {
    let v = ctx.version;
    lwpolyline_bits(&mut o.data, v, &mut |n| ctx.room(n))
}

/// LWPOLYLINE's own data (spec 20.4.85), from its flags to its widths: an
/// object's, or what proxy graphics embed (spec 29, type 33). `room` says
/// whether a list of that many vertices takes one more.
pub(crate) fn lwpolyline_bits(
    b: &mut Bits<'_>,
    v: Version,
    room: &mut dyn FnMut(usize) -> bool,
) -> BitResult<LwPolyline> {
    let flags = b.bs()?;
    let mut p = LwPolyline::default();
    if flags & 4 != 0 {
        p.constant_width = b.bd()?;
    }
    if flags & 8 != 0 {
        p.elevation = b.bd()?;
    }
    if flags & 2 != 0 {
        p.plane.thickness = b.bd()?;
    }
    if flags & 1 != 0 {
        p.plane.extrusion = v3(b.bd3()?);
    }
    let n = i64::from(b.bl()?);
    let n = count(b, n, 2 * 2)?;
    let bulges = if flags & 16 != 0 {
        let k = i64::from(b.bl()?);
        count(b, k, 2)?
    } else {
        0
    };
    let ids = if v >= Version::R2010 && flags & 1024 != 0 {
        let k = i64::from(b.bl()?);
        count(b, k, 2)?
    } else {
        0
    };
    let widths = if flags & 32 != 0 {
        let k = i64::from(b.bl()?);
        count(b, k, 4)?
    } else {
        0
    };
    // DXF's group 70: closed (512 here), continuous linetype (256).
    p.flags = i16::from(flags & 512 != 0) | i16::from(flags & 256 != 0) << 7;
    let mut points: Vec<Vec2> = Vec::new();
    let mut prev = Vec2::default();
    for k in 0..n {
        let pt = if k == 0 || v < Version::R2000 {
            v2(b.rd2()?)
        } else {
            let x = b.dd(prev.x)?;
            let y = b.dd(prev.y)?;
            Vec2::new(x, y)
        };
        prev = pt;
        if room(points.len()) {
            points.push(pt);
        }
    }
    p.vertices = points
        .into_iter()
        .map(|point| LwVertex {
            point,
            ..LwVertex::default()
        })
        .collect();
    for k in 0..bulges {
        let bulge = b.bd()?;
        if let Some(x) = p.vertices.get_mut(k) {
            x.bulge = bulge;
        }
    }
    for _ in 0..ids {
        b.bl()?;
    }
    for k in 0..widths {
        let s = b.bd()?;
        let e = b.bd()?;
        if let Some(x) = p.vertices.get_mut(k) {
            x.start_width = s;
            x.end_width = e;
        }
    }
    Ok(p)
}

/// SPLINE (spec 20.4.40), and the curve of a HELIX.
fn spline(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Spline> {
    let v = ctx.version;
    let mut s = Spline::default();
    let b = &mut o.data;
    let mut scenario = b.bl()?;
    if v >= Version::R2013 {
        let flags1 = b.bl()?;
        let knot_parameter = b.bl()?;
        if flags1 & 4 != 0 {
            s.flags |= 1;
        }
        // Spec 20.4.40: custom knots, or no fit data, read as scenario 1.
        scenario = if knot_parameter == 15 || flags1 & 1 == 0 {
            1
        } else {
            2
        };
    }
    s.degree = b.bl()? as i16;
    let mut fit = 0;
    let (mut knots, mut ctrl, mut weighted) = (0, 0, false);
    if scenario == 2 {
        s.fit_tolerance = b.bd()?;
        let start = v3(b.bd3()?);
        let end = v3(b.bd3()?);
        s.start_tangent = (start != Vec3::default()).then_some(start);
        s.end_tangent = (end != Vec3::default()).then_some(end);
        let n = i64::from(b.bl()?);
        fit = count(b, n, 6)?;
    } else {
        let rational = b.b()?;
        let closed = b.b()?;
        let periodic = b.b()?;
        s.flags |= i16::from(closed) | i16::from(periodic) << 1 | i16::from(rational) << 2;
        s.knot_tolerance = b.bd()?;
        s.control_point_tolerance = b.bd()?;
        let n = i64::from(b.bl()?);
        knots = count(b, n, 2)?;
        let n = i64::from(b.bl()?);
        ctrl = count(b, n, 6)?;
        weighted = b.b()?;
    }
    for _ in 0..knots {
        let k = o.data.bd()?;
        push(ctx, &mut s.knots, k);
    }
    for _ in 0..ctrl {
        let p = v3(o.data.bd3()?);
        push(ctx, &mut s.control_points, p);
        if weighted {
            let w = o.data.bd()?;
            push(ctx, &mut s.weights, w);
        }
    }
    for _ in 0..fit {
        let p = v3(o.data.bd3()?);
        push(ctx, &mut s.fit_points, p);
    }
    Ok(s)
}

/// MTEXT (spec 20.4.46).
fn mtext(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<MText> {
    let mut m = mtext_body(ctx, o)?;
    if m.columns.is_none() {
        m.columns = eed_columns(ctx, o);
    }
    Ok(m)
}

/// Before 2018 an MTEXT's columns are in its `ACAD` extended data, between
/// `ACAD_MTEXT_COLUMN_INFO_BEGIN` and `_END`: pairs of a 1070 DXF code and
/// its value (75 type, 79 auto height, 76 count, 78 flow reversed, 48
/// width, 49 gutter, 50 the number of heights, then the heights). The
/// converter writes them so in every version to 2013.
fn eed_columns(ctx: &mut Ctx<'_, '_>, o: &Object<'_>) -> Option<MTextColumns> {
    let version = ctx.version;
    let eed = o.eed.iter().find(|e| ctx.is_app(e.app, "ACAD"))?;
    let items = eed.items(version);
    let is = |v: &EedValue<'_>, s: &str| match v {
        EedValue::Text(t) => t.eq_ignore_ascii_case(s.as_bytes()),
        EedValue::Unicode(t) => t.eq_ignore_ascii_case(s),
        _ => false,
    };
    let start = items
        .iter()
        .position(|(c, v)| *c == 1000 && is(v, "ACAD_MTEXT_COLUMN_INFO_BEGIN"))?;
    let mut c = MTextColumns::default();
    let mut it = items.iter().skip(start + 1);
    let number = |v: &EedValue<'_>| match v {
        EedValue::Short(x) => f64::from(*x),
        EedValue::Long(x) => f64::from(*x),
        EedValue::Real(x) => *x,
        _ => 0.0,
    };
    while let Some((code, v)) = it.next() {
        if *code != 1070 {
            break;
        }
        let EedValue::Short(group) = v else { break };
        let Some((_, value)) = it.next() else { break };
        let x = number(value);
        match group {
            75 => c.kind = x as i16,
            79 => c.auto_height = x != 0.0,
            76 => c.count = x as i16,
            78 => c.flow_reversed = x != 0.0,
            48 => c.width = x,
            49 => c.gutter = x,
            50 => {
                for _ in 0..(x.max(0.0) as usize).min(items.len()) {
                    match it.next() {
                        Some((1040, h)) => push(ctx, &mut c.heights, number(h)),
                        _ => break,
                    }
                }
            }
            _ => {}
        }
    }
    (c.kind != 0).then_some(c)
}

/// An MTEXT's data.
fn mtext_body(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<MText> {
    let v = ctx.version;
    let b = &mut o.data;
    let mut m = MText {
        insertion: v3(b.bd3()?),
        extrusion: v3(b.bd3()?),
        ..MText::default()
    };
    // The X axis, which DXF leaves out when it is the OCS's (the converter
    // writes no group 11 then, nor a rotation): the same text either way.
    let x = v3(b.bd3()?);
    m.x_direction = (x != Vec3::new(1.0, 0.0, 0.0)).then_some(x);
    m.reference_width = b.bd()?;
    if v >= Version::R2007 {
        m.defined_height = b.bd()?;
    }
    m.height = b.bd()?;
    m.attachment = b.bs()?;
    m.drawing_direction = b.bs()?;
    b.bd()?; // extents height
    b.bd()?; // extents width
    m.text = string(ctx, o)?;
    m.style = text_style(ctx, o)?;
    let b = &mut o.data;
    if v >= Version::R2000 {
        m.line_spacing_style = b.bs()?;
        m.line_spacing_factor = b.bd()?;
        b.b()?;
    }
    if v >= Version::R2004 {
        m.background_fill = b.bl()?;
        if m.background_fill & 1 != 0 || (v >= Version::R2018 && m.background_fill & 0x10 != 0) {
            m.background_scale = b.bd()?;
            let (c, _) = cmc(o, v)?;
            m.background_color = c;
            o.data.bl()?; // transparency
        }
    }
    if v >= Version::R2018 {
        let b = &mut o.data;
        let annotative = !b.b()?;
        if annotative {
            m.columns = super::objects::annotative_columns(ctx, o.xdictionary);
        } else {
            b.bs()?; // version
            b.b()?; // default flag
            o.handle_ref()?; // registered application
            let b = &mut o.data;
            b.bl()?; // attachment
            b.bd3()?; // X axis
            b.bd3()?; // insertion
            b.bd()?; // width
            b.bd()?; // height
            b.bd()?; // extents width
            b.bd()?; // extents height
            let kind = b.bs()?;
            if kind != 0 {
                let mut c = MTextColumns {
                    kind,
                    ..MTextColumns::default()
                };
                let n = i64::from(b.bl()?);
                c.count = n as i16;
                c.width = b.bd()?;
                c.gutter = b.bd()?;
                c.auto_height = b.b()?;
                c.flow_reversed = b.b()?;
                if !c.auto_height && kind == 2 {
                    let n = count(b, n, 2)?;
                    for _ in 0..n {
                        let h = o.data.bd()?;
                        push(ctx, &mut c.heights, h);
                    }
                }
                m.columns = Some(c);
            }
        }
    }
    Ok(m)
}

/// The MTEXT of a multiline attribute (2018): an MTEXT's fields "starting
/// from the entity mode" (spec 20.4.4), which are the common entity data
/// from the entity mode on (20.4.1), then the MTEXT's own; in the handle
/// stream, after the attribute's style, the common entity handles (20.4.2,
/// owner included, null) and the MTEXT's. Found on the converter's 2018 DWG
/// of tests/fixtures/cad/make.py's multiline ATTRIB, whose data and handles
/// end exactly there.
fn embedded_mtext(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<MText> {
    let b = &mut o.data;
    b.bb()?; // entity mode
    let reactors = u64::try_from(b.bl()?).map_err(|_| BitError::Invalid)?;
    let xdic_missing = b.b()?;
    b.b()?; // data store
    let color = b.bs()? as u16;
    if color & 0x8000 != 0 {
        b.bl()?; // RGB
    }
    if color & 0x2000 != 0 {
        b.bl()?; // transparency
    }
    b.bd()?; // linetype scale
    let linetype = b.bb()?;
    let plot_style = b.bb()?;
    let material = b.bb()?;
    b.rc()?; // shadow
    let styles = [b.b()?, b.b()?, b.b()?];
    b.bs()?; // invisible
    b.rc()?; // lineweight
    o.handle_ref()?; // owner
    if reactors > o.handles.remaining() / 8 {
        return Err(BitError::End);
    }
    for _ in 0..reactors {
        o.handle_ref()?;
    }
    if !xdic_missing {
        o.handle_ref()?;
    }
    if color & 0x4000 != 0 {
        o.handle_ref()?; // colour book
    }
    o.handle_ref()?; // layer
    for flags in [linetype, material, plot_style] {
        if flags == 3 {
            o.handle_ref()?;
        }
    }
    for present in styles {
        if present {
            o.handle_ref()?;
        }
    }
    mtext_body(ctx, o)
}

/// DIMENSION of every kind (spec 20.4.22 to 20.4.30).
fn dimension(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>, name: &str) -> BitResult<Dimension> {
    let v = ctx.version;
    let b = &mut o.data;
    let mut d = Dimension::default();
    if v >= Version::R2010 {
        b.rc()?; // version
    }
    d.extrusion = v3(b.bd3()?);
    let mid = b.rd2()?;
    let elevation = b.bd()?;
    let flags1 = b.rc()?;
    d.text = string(ctx, o)?;
    let b = &mut o.data;
    d.text_rotation = b.bd()?;
    d.horizontal_direction = b.bd()?;
    d.insertion_scale = v3(b.bd3()?);
    d.insertion_rotation = b.bd()?;
    if v >= Version::R2000 {
        d.attachment = b.bs()?;
        d.line_spacing_style = b.bs()?;
        d.line_spacing_factor = b.bd()?;
        d.measurement = b.bd()?;
    }
    if v >= Version::R2007 {
        b.b()?;
        b.b()?; // flip arrow 1
        b.b()?; // flip arrow 2
    }
    let ins = b.rd2()?;
    d.text_midpoint = Vec3::new(mid[0], mid[1], elevation);
    d.insertion_point = Vec3::new(ins[0], ins[1], elevation);
    let kind: i16 = match o.type_code {
        0x14 => 6,
        0x15 => 0,
        0x16 => 1,
        0x17 => 5,
        0x18 => 2,
        0x19 => 4,
        0x1A => 3,
        _ if name == "ARC_DIMENSION" => 5,
        _ => 4,
    };
    match o.type_code {
        0x14 => {
            d.definition_point = v3(b.bd3()?);
            d.point13 = v3(b.bd3()?);
            d.point14 = v3(b.bd3()?);
            let flags2 = b.rc()?;
            if flags2 & 1 != 0 {
                d.flags |= 64;
            }
        }
        0x15 | 0x16 => {
            d.point13 = v3(b.bd3()?);
            d.point14 = v3(b.bd3()?);
            d.definition_point = v3(b.bd3()?);
            d.oblique = b.bd()?;
            if o.type_code == 0x15 {
                d.angle = b.bd()?;
            }
        }
        0x17 => {
            d.definition_point = v3(b.bd3()?);
            d.point13 = v3(b.bd3()?);
            d.point14 = v3(b.bd3()?);
            d.point15 = v3(b.bd3()?);
        }
        0x18 => {
            let p = b.rd2()?;
            d.point16 = Vec3::new(p[0], p[1], elevation);
            d.point13 = v3(b.bd3()?);
            d.point14 = v3(b.bd3()?);
            d.point15 = v3(b.bd3()?);
            d.definition_point = v3(b.bd3()?);
        }
        0x19 => {
            d.definition_point = v3(b.bd3()?);
            d.point15 = v3(b.bd3()?);
            d.leader_length = b.bd()?;
        }
        0x1A => {
            d.point15 = v3(b.bd3()?);
            d.definition_point = v3(b.bd3()?);
            d.leader_length = b.bd()?;
        }
        _ if name == "ARC_DIMENSION" => {
            d.definition_point = v3(b.bd3()?);
            d.point13 = v3(b.bd3()?);
            d.point14 = v3(b.bd3()?);
            d.point15 = v3(b.bd3()?);
            b.b()?; // partial
            b.bd()?; // start angle
            b.bd()?; // end angle
            b.b()?; // has leader
            d.point16 = v3(b.bd3()?);
            b.bd3()?; // leader point 2
        }
        _ => {
            d.definition_point = v3(b.bd3()?);
            d.point13 = v3(b.bd3()?);
            d.leader_length = b.bd()?;
            d.point14 = v3(b.bd3()?);
            d.point15 = v3(b.bd3()?);
        }
    }
    // Group 70 (spec 20.4.22): the kind, 32 from bit 1, 128 when bit 0 is
    // clear.
    d.flags |= kind;
    if flags1 & 2 != 0 {
        d.flags |= 32;
    }
    if flags1 & 1 == 0 {
        d.flags |= 128;
    }
    d.kind = DimensionKind::from_code(i64::from(kind));
    d.style = entry(ctx, o, "dimension style")?;
    let block = o.handle_ref()?;
    d.block_name = ctx.name(block).unwrap_or_default().to_string();
    Ok(d)
}

/// LEADER (spec 20.4.47).
fn leader(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Leader> {
    let v = ctx.version;
    let b = &mut o.data;
    let mut l = Leader::default();
    b.b()?;
    l.creation = b.bs()?;
    l.path_type = b.bs()?;
    let n = i64::from(b.bl()?);
    let n = count(b, n, 6)?;
    for _ in 0..n {
        let p = v3(o.data.bd3()?);
        push(ctx, &mut l.vertices, p);
    }
    let b = &mut o.data;
    b.bd3()?; // origin
    l.extrusion = v3(b.bd3()?);
    l.horizontal_direction = v3(b.bd3()?);
    l.block_offset = v3(b.bd3()?);
    if v >= Version::R14 {
        l.annotation_offset = v3(b.bd3()?);
    }
    if v < Version::R2000 {
        b.bd()?; // DIMGAP
    }
    // The text box's height and width, which spec 20.4.47 has in every
    // version, are not in R2010 and later files: their LEADERs end 132
    // bits sooner than the same LEADERs of R2004, the bits after the end
    // point projection being those after the box there.
    if v < Version::R2010 {
        l.text_height = b.bd()?;
        l.text_width = b.bd()?;
    }
    l.hookline_direction = i16::from(b.b()?);
    l.arrowhead = b.b()?;
    if v < Version::R2000 {
        b.bs()?; // arrowhead type
        b.bd()?; // DIMASZ
        b.b()?;
        b.b()?;
        b.bs()?;
        l.color = Color::from_aci(i64::from(b.bs()?));
        b.b()?;
        b.b()?;
    } else {
        b.bs()?;
        b.b()?;
        b.b()?;
    }
    l.annotation = Handle(o.handle_ref()?);
    l.style = entry(ctx, o, "dimension style")?;
    Ok(l)
}

/// MLINE (spec 20.4.50).
fn mline(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<MLine> {
    let b = &mut o.data;
    let mut m = MLine {
        scale: b.bd()?,
        justification: i16::from(b.rc()?),
        start: v3(b.bd3()?),
        extrusion: v3(b.bd3()?),
        ..MLine::default()
    };
    m.flags = b.bs()?;
    let lines = b.rc()?;
    m.style_element_count = i16::from(lines);
    let n = i64::from(b.bs()?);
    let n = count(b, n, 18)?;
    for _ in 0..n {
        let b = &mut o.data;
        let mut x = MLineVertex {
            position: v3(b.bd3()?),
            direction: v3(b.bd3()?),
            miter: v3(b.bd3()?),
            ..MLineVertex::default()
        };
        for _ in 0..lines {
            let mut e = MLineElement::default();
            for fill in [false, true] {
                let b = &mut o.data;
                let k = i64::from(b.bs()?);
                let k = count(b, k, 2)?;
                for _ in 0..k {
                    let p = o.data.bd()?;
                    let list = if fill {
                        &mut e.fill_parameters
                    } else {
                        &mut e.parameters
                    };
                    push(ctx, list, p);
                }
            }
            push(ctx, &mut x.elements, e);
        }
        push(ctx, &mut m.vertices, x);
    }
    let style = o.handle_ref()?;
    m.style = Handle(style);
    m.style_name = object_name(ctx, style);
    Ok(m)
}

/// The name an object starts with (MLINESTYLE, spec 20.4.73), empty when
/// it cannot be read.
fn object_name(ctx: &mut Ctx<'_, '_>, h: u64) -> String {
    if let Some(n) = ctx.name(h) {
        return n.to_string();
    }
    let raw = match ctx.dwg.object(h) {
        Some(Ok(mut o)) if o.handle == h => o.tv().ok(),
        _ => None,
    };
    let name = raw.map(|t| ctx.string(t)).unwrap_or_default();
    ctx.names.insert(h, name.clone());
    name
}

/// HATCH (spec 20.4.75).
fn hatch(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Hatch> {
    let v = ctx.version;
    let mut h = Hatch::default();
    if v >= Version::R2004 {
        let b = &mut o.data;
        let mut g = Gradient {
            kind: b.bl()?,
            name: String::new(),
            angle: 0.0,
            shift: 0.0,
            single_color: false,
            tint: 0.0,
            colors: Vec::new(),
        };
        b.bl()?; // reserved
        g.angle = b.bd()?;
        g.shift = b.bd()?;
        g.single_color = b.bl()? != 0;
        g.tint = b.bd()?;
        let n = i64::from(b.bl()?);
        let n = count(b, n, 2 + 2 + 2 + 8)?;
        for _ in 0..n {
            let b = &mut o.data;
            let at = b.bd()?;
            b.bs()?;
            let raw = b.bl()?;
            b.rc()?;
            push(ctx, &mut g.colors, (at, Color::from_raw(i64::from(raw))));
        }
        g.name = string(ctx, o)?;
        h.gradient = Some(g);
    }
    let b = &mut o.data;
    h.elevation = b.bd()?;
    h.extrusion = v3(b.bd3()?);
    h.pattern_name = string(ctx, o)?;
    let b = &mut o.data;
    h.solid = b.b()?;
    // The gradient fields of a fill that is not a gradient mean nothing
    // (DXF reference, group 450); the converter leaves them out of its DXF
    // for a pattern fill, and for a solid one when they are empty (no name,
    // no colours).
    if h.gradient
        .as_ref()
        .is_some_and(|g| g.kind == 0 && (!h.solid || (g.name.is_empty() && g.colors.is_empty())))
    {
        h.gradient = None;
    }
    h.associative = b.b()?;
    let n = i64::from(b.bl()?);
    let n = count(b, n, 2 + 2)?;
    let mut sources = Vec::new();
    let mut pixel = false;
    for _ in 0..n {
        let (path, k) = boundary_path(ctx, o)?;
        pixel |= path.flags & 4 != 0;
        sources.push(k);
        push(ctx, &mut h.paths, path);
    }
    let b = &mut o.data;
    h.style = b.bs()?;
    h.pattern_type = b.bs()?;
    if !h.solid {
        h.pattern_angle = b.bd()?;
        h.pattern_scale = b.bd()?;
        h.pattern_double = b.b()?;
        let n = i64::from(b.bs()?);
        let n = count(b, n, 2 * 6)?;
        for _ in 0..n {
            let b = &mut o.data;
            let mut l = PatternLine {
                angle: b.bd()?,
                base: v2(b.bd2()?),
                offset: v2(b.bd2()?),
                dashes: Vec::new(),
            };
            let k = i64::from(b.bs()?);
            let k = count(b, k, 2)?;
            for _ in 0..k {
                let d = o.data.bd()?;
                push(ctx, &mut l.dashes, d);
            }
            push(ctx, &mut h.pattern_lines, l);
        }
    }
    let b = &mut o.data;
    if pixel {
        h.pixel_size = b.bd()?;
    }
    let n = i64::from(b.bl()?);
    let n = count(b, n, 128)?;
    for _ in 0..n {
        let p = v2(o.data.rd2()?);
        push(ctx, &mut h.seeds, p);
    }
    // The boundary objects of every path, in order, in the handle stream.
    for (path, k) in h.paths.iter_mut().zip(sources) {
        for _ in 0..k {
            let s = o.handle_ref()?;
            push(ctx, &mut path.sources, Handle(s));
        }
    }
    Ok(h)
}

/// One hatch boundary path and the count of its boundary objects.
fn boundary_path(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<(BoundaryPath, usize)> {
    let v = ctx.version;
    let b = &mut o.data;
    let flags = b.bl()?;
    let data = if flags & 2 == 0 {
        let n = i64::from(b.bl()?);
        let n = count(b, n, 8)?;
        let mut edges = Vec::new();
        for _ in 0..n {
            let e = edge(ctx, o, v)?;
            push(ctx, &mut edges, e);
        }
        BoundaryData::Edges(edges)
    } else {
        let bulges = b.b()?;
        let closed = b.b()?;
        let n = i64::from(b.bl()?);
        let n = count(b, n, 128)?;
        let mut vertices = Vec::new();
        for _ in 0..n {
            let b = &mut o.data;
            let p = v2(b.rd2()?);
            let bulge = if bulges { b.bd()? } else { 0.0 };
            push(ctx, &mut vertices, (p, bulge));
        }
        BoundaryData::Polyline { closed, vertices }
    };
    let b = &mut o.data;
    let k = i64::from(b.bl()?);
    // Each is a handle in the handle stream: at least a byte there.
    let k = count(&o.handles, k, 8)?;
    Ok((
        BoundaryPath {
            flags,
            data,
            sources: Vec::new(),
        },
        k,
    ))
}

fn edge(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>, v: Version) -> BitResult<Edge> {
    let b = &mut o.data;
    Ok(match b.rc()? {
        1 => Edge::Line {
            start: v2(b.rd2()?),
            end: v2(b.rd2()?),
        },
        2 => Edge::Arc {
            center: v2(b.rd2()?),
            radius: b.bd()?,
            start_angle: b.bd()?,
            end_angle: b.bd()?,
            counter_clockwise: b.b()?,
        },
        // The DWG has the ellipse's parameters at the ends where DXF has
        // their angles (a converted 30 degrees at ratio 0.5 is 0.857).
        3 => {
            let center = v2(b.rd2()?);
            let major_axis = v2(b.rd2()?);
            let ratio = b.bd()?;
            Edge::Ellipse {
                center,
                major_axis,
                ratio,
                start_angle: ellipse_angle(b.bd()?, ratio),
                end_angle: ellipse_angle(b.bd()?, ratio),
                counter_clockwise: b.b()?,
            }
        }
        4 => {
            let degree = b.bl()?;
            let rational = b.b()?;
            let periodic = b.b()?;
            let n = i64::from(b.bl()?);
            let knots_n = count(b, n, 2)?;
            let n = i64::from(b.bl()?);
            let points_n = count(b, n, 128)?;
            let mut knots = Vec::new();
            for _ in 0..knots_n {
                let k = o.data.bd()?;
                push(ctx, &mut knots, k);
            }
            let mut control_points = Vec::new();
            let mut weights = Vec::new();
            for _ in 0..points_n {
                let b = &mut o.data;
                let p = v2(b.rd2()?);
                push(ctx, &mut control_points, p);
                if rational {
                    let w = b.bd()?;
                    push(ctx, &mut weights, w);
                }
            }
            let mut fit_points = Vec::new();
            let (mut start_tangent, mut end_tangent) = (None, None);
            if v >= Version::R2010 {
                let b = &mut o.data;
                let n = i64::from(b.bl()?);
                let n = count(b, n, 128)?;
                for _ in 0..n {
                    let p = v2(o.data.rd2()?);
                    push(ctx, &mut fit_points, p);
                }
                if n > 0 {
                    let b = &mut o.data;
                    start_tangent = Some(v2(b.rd2()?));
                    end_tangent = Some(v2(b.rd2()?));
                }
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
        _ => return Err(BitError::Invalid),
    })
}

/// IMAGE (spec 20.4.80), and WIPEOUT, which the spec leaves out: its
/// records read as an IMAGE's.
fn image(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Image> {
    let v = ctx.version;
    let b = &mut o.data;
    let mut i = Image {
        class_version: b.bl()?,
        insertion: v3(b.bd3()?),
        u_vector: v3(b.bd3()?),
        v_vector: v3(b.bd3()?),
        size: v2(b.rd2()?),
        display: b.bs()?,
        clipping: b.b()?,
        brightness: i16::from(b.rc()?),
        contrast: i16::from(b.rc()?),
        fade: i16::from(b.rc()?),
        ..Image::default()
    };
    if v >= Version::R2010 {
        i.clip_inside = b.b()?;
    }
    i.clip_type = b.bs()?;
    if i.clip_type == 1 {
        for _ in 0..2 {
            let p = v2(o.data.rd2()?);
            push(ctx, &mut i.clip_vertices, p);
        }
    } else {
        let n = i64::from(b.bl()?);
        let n = count(b, n, 128)?;
        for _ in 0..n {
            let p = v2(o.data.rd2()?);
            push(ctx, &mut i.clip_vertices, p);
        }
    }
    i.image_def = Handle(o.handle_ref()?);
    i.reactor = Handle(o.handle_ref()?);
    Ok(i)
}

/// OLE2FRAME (spec 20.4.88): what the model keeps of it. The embedded data
/// is the scanner's (`exav_unpack::dwg`). DXF's tile mode (72) is not the
/// spec's R2000+ "Mode" (0 in every file seen, the converter's for a frame
/// given 72 = 0 or 1 alike): the converter writes 72 from where the frame
/// is (0 in model space, 1 in paper space or a block), which `blocks`
/// sets.
fn ole2frame(o: &mut Object<'_>, v: Version) -> BitResult<Ole2Frame> {
    let b = &mut o.data;
    let mut f = Ole2Frame {
        version: b.bs()?,
        ..Ole2Frame::default()
    };
    if v >= Version::R2000 {
        b.bs()?;
    }
    f.data_length = i64::from(b.bl()?);
    // The data is DXF's group 310 bytes: two bytes, then the frame's four
    // corners as 3RD, from the upper left (DXF 10) clockwise, the third
    // being DXF 11 (the corpus's OLE2FRAMEs, every version).
    if f.data_length >= 98 {
        b.skip(16)?;
        let corners = [b.rd3()?, b.rd3()?, b.rd3()?];
        f.upper_left = v3(corners[0]);
        f.lower_right = v3(corners[2]);
    }
    Ok(f)
}

/// VIEWPORT (spec 20.4.38). R13 and R14 keep only its paper-space frame
/// here; the view is in its extended data, as in R12 DXF.
fn viewport(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Viewport> {
    let v = ctx.version;
    let b = &mut o.data;
    let mut p = Viewport {
        center: v3(b.bd3()?),
        width: b.bd()?,
        height: b.bd()?,
        ..Viewport::default()
    };
    if v < Version::R2000 {
        mview(ctx, o, &mut p);
        return Ok(p);
    }
    p.view_target = v3(b.bd3()?);
    p.view_direction = v3(b.bd3()?);
    p.twist = b.bd()?;
    p.view_height = b.bd()?;
    p.lens_length = b.bd()?;
    p.front_clip = b.bd()?;
    p.back_clip = b.bd()?;
    p.snap_angle = b.bd()?;
    p.view_center = v2(b.rd2()?);
    p.snap_base = v2(b.rd2()?);
    p.snap_spacing = v2(b.rd2()?);
    p.grid_spacing = v2(b.rd2()?);
    p.circle_zoom = b.bs()?;
    if v >= Version::R2007 {
        b.bs()?; // grid major
    }
    let frozen = i64::from(b.bl()?);
    p.flags = b.bl()?;
    p.plot_style_sheet = string(ctx, o)?;
    let b = &mut o.data;
    p.render_mode = i16::from(b.rc()?);
    b.b()?; // UCS at origin
    b.b()?; // UCS per viewport
    b.bd3()?;
    b.bd3()?;
    b.bd3()?;
    p.elevation = b.bd()?;
    b.bs()?; // orthographic view type
    if v >= Version::R2004 {
        p.shade_plot_mode = b.bs()?;
    }
    let frozen = count(&o.handles, frozen, 8)?;
    for _ in 0..frozen {
        let h = o.handle_ref()?;
        push(ctx, &mut p.frozen_layers, Handle(h));
    }
    p.clip_boundary = Handle(o.handle_ref()?);
    Ok(p)
}

/// The view of an R13 or R14 viewport, in its `ACAD` extended data after
/// `MVIEW` as in R12 DXF: a version, the target, the direction, numbered
/// reals and integers, then the frozen layers.
fn mview(ctx: &mut Ctx<'_, '_>, o: &Object<'_>, p: &mut Viewport) {
    let version = ctx.version;
    for eed in &o.eed {
        if !ctx.is_app(eed.app, "ACAD") {
            continue;
        }
        let items = eed.items(version);
        let is_mview = |v: &EedValue<'_>| match v {
            EedValue::Text(t) => t.eq_ignore_ascii_case(b"MVIEW"),
            EedValue::Unicode(t) => t.eq_ignore_ascii_case("MVIEW"),
            _ => false,
        };
        let Some(start) = items.iter().position(|(c, v)| *c == 1000 && is_mview(v)) else {
            continue;
        };
        let mut points = Vec::new();
        let mut scalars: Vec<f64> = Vec::new();
        let mut frozen = Vec::new();
        // After the opening brace and the version.
        for (code, value) in items.iter().skip(start + 3) {
            match (code, value) {
                (1010, EedValue::Point(p)) => points.push(v3(*p)),
                (1040, EedValue::Real(x)) => scalars.push(*x),
                (1070, EedValue::Short(x)) => scalars.push(f64::from(*x)),
                (1003, EedValue::Handle(h)) => frozen.push(Handle(*h)),
                (1002, EedValue::Open(false)) if frozen.is_empty() => {}
                _ => {}
            }
        }
        if let [target, direction, ..] = points.as_slice() {
            p.view_target = *target;
            p.view_direction = *direction;
        }
        let s = |i: usize| scalars.get(i).copied();
        if let Some(a) = s(0) {
            p.twist = a.to_radians();
        }
        if let Some(h) = s(1) {
            p.view_height = h;
        }
        if let (Some(x), Some(y)) = (s(2), s(3)) {
            p.view_center = Vec2::new(x, y);
        }
        if let Some(l) = s(4) {
            p.lens_length = l;
        }
        if let Some(f) = s(5) {
            p.front_clip = f;
        }
        if let Some(b) = s(6) {
            p.back_clip = b;
        }
        if let Some(m) = s(7) {
            p.flags |= (m as i32) & 0x1F;
        }
        for (i, bit) in [
            (9, 0x80),
            (11, 0x100),
            (12, 0x200),
            (13, 0x400),
            (22, 0x800),
        ] {
            if s(i).is_some_and(|x| x != 0.0) {
                p.flags |= bit;
            }
        }
        if let Some(z) = s(8) {
            p.circle_zoom = z as i16;
        }
        if let Some(a) = s(15) {
            p.snap_angle = a.to_radians();
        }
        if let (Some(x), Some(y)) = (s(16), s(17)) {
            p.snap_base = Vec2::new(x, y);
        }
        if let (Some(x), Some(y)) = (s(18), s(19)) {
            p.snap_spacing = Vec2::new(x, y);
        }
        if let (Some(x), Some(y)) = (s(20), s(21)) {
            p.grid_spacing = Vec2::new(x, y);
        }
        for h in frozen {
            push(ctx, &mut p.frozen_layers, h);
        }
        return;
    }
}

/// MULTILEADER (spec 20.4.48), its context data (20.4.86) inside it.
fn multileader(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<MultiLeader> {
    let v = ctx.version;
    let mut m = MultiLeader::default();
    if v >= Version::R2010 {
        o.data.bs()?; // version
    }
    m.context = mleader_context(ctx, o)?;
    m.style = Handle(o.handle_ref()?);
    let b = &mut o.data;
    m.property_overrides = i64::from(b.bl()?);
    m.leader_line_type = b.bs()?;
    m.leader_line_color = cmc(o, v)?.0;
    m.leader_linetype = Handle(o.handle_ref()?);
    let b = &mut o.data;
    m.leader_lineweight = LineWeight::from_code(i64::from(b.bl()?));
    m.landing = b.b()?;
    m.dogleg = b.b()?;
    m.dogleg_length = b.bd()?;
    m.arrowhead = Handle(o.handle_ref()?);
    let b = &mut o.data;
    m.arrowhead_size = b.bd()?;
    m.content_type = b.bs()?;
    m.text_style = Handle(o.handle_ref()?);
    let b = &mut o.data;
    m.text_left_attachment = b.bs()?;
    m.text_right_attachment = b.bs()?;
    m.text_angle_type = b.bs()?;
    m.text_alignment_type = b.bs()?;
    m.text_color = cmc(o, v)?.0;
    m.text_frame = o.data.b()?;
    m.block = Handle(o.handle_ref()?);
    m.block_color = cmc(o, v)?.0;
    let b = &mut o.data;
    m.block_scale = v3(b.bd3()?);
    m.block_rotation = b.bd()?;
    m.block_connection = b.bs()?;
    b.b()?; // annotative
    if v < Version::R2010 {
        let n = i64::from(b.bl()?);
        let n = count(b, n, 1)?;
        for _ in 0..n {
            o.data.b()?;
            o.handle_ref()?;
        }
    }
    let b = &mut o.data;
    let n = i64::from(b.bl()?);
    let n = count(b, n, 2 + 2 + 2)?;
    for _ in 0..n {
        let definition = Handle(o.handle_ref()?);
        let text = string(ctx, o)?;
        let b = &mut o.data;
        let a = MLeaderAttribute {
            definition,
            text,
            index: b.bs()?,
            width: b.bd()?,
        };
        push(ctx, &mut m.block_attributes, a);
    }
    let b = &mut o.data;
    b.b()?; // text direction negative
    b.bs()?; // IPE align
    m.text_attachment_point = b.bs()?;
    b.bd()?; // scale
    if v >= Version::R2010 {
        b.bs()?; // attachment direction
        b.bs()?; // top attachment
        b.bs()?; // bottom attachment
    }
    if v >= Version::R2013 {
        b.b()?; // leader extended to text
    }
    Ok(m)
}

fn mleader_context(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<MLeaderContext> {
    let v = ctx.version;
    let mut c = MLeaderContext::default();
    let b = &mut o.data;
    let n = i64::from(b.bl()?);
    let n = count(b, n, 1 + 1 + 6 + 6 + 2 + 2 + 2 + 2)?;
    for _ in 0..n {
        let b = &mut o.data;
        let mut r = MLeaderRoot {
            has_connection_point: b.b()?,
            has_direction: b.b()?,
            connection_point: v3(b.bd3()?),
            direction: v3(b.bd3()?),
            ..MLeaderRoot::default()
        };
        let k = i64::from(b.bl()?);
        let k = count(b, k, 12)?;
        for _ in 0..k {
            o.data.bd3()?;
            o.data.bd3()?;
        }
        let b = &mut o.data;
        r.branch_index = b.bl()?;
        r.dogleg_length = b.bd()?;
        let k = i64::from(b.bl()?);
        let k = count(b, k, 2 + 2 + 2 + 2 + 2)?;
        for _ in 0..k {
            let b = &mut o.data;
            let mut line = MLeaderLine::default();
            let p = i64::from(b.bl()?);
            let p = count(b, p, 6)?;
            for _ in 0..p {
                let x = v3(o.data.bd3()?);
                push(ctx, &mut line.vertices, x);
            }
            // Spec 20.4.86 lists a break info count, a segment index and
            // start/end pairs once; the index and pairs repeat per break:
            // a line without breaks has its index right after the count.
            let b = &mut o.data;
            let breaks = i64::from(b.bl()?);
            let breaks = count(b, breaks, 4)?;
            for _ in 0..breaks {
                let b = &mut o.data;
                b.bl()?; // segment index
                let q = i64::from(b.bl()?);
                let q = count(b, q, 12)?;
                for _ in 0..q {
                    o.data.bd3()?;
                    o.data.bd3()?;
                }
            }
            line.index = o.data.bl()?;
            if v >= Version::R2010 {
                o.data.bs()?; // leader type
                cmc(o, v)?;
                o.handle_ref()?; // linetype
                let b = &mut o.data;
                b.bl()?; // lineweight
                b.bd()?; // arrow size
                o.handle_ref()?; // arrow
                o.data.bl()?; // override flags
            }
            push(ctx, &mut r.lines, line);
        }
        if v >= Version::R2010 {
            r.attachment_direction = o.data.bs()?;
        }
        push(ctx, &mut c.leaders, r);
    }
    let b = &mut o.data;
    c.scale = b.bd()?;
    c.content_base = v3(b.bd3()?);
    c.text_height = b.bd()?;
    c.arrowhead_size = b.bd()?;
    c.landing_gap = b.bd()?;
    b.bs()?; // left attachment
    b.bs()?; // right attachment
    b.bs()?; // text align
    b.bs()?; // attachment type
    c.has_text = b.b()?;
    if c.has_text {
        c.text = string(ctx, o)?;
        let b = &mut o.data;
        c.text_normal = v3(b.bd3()?);
        c.text_style = Handle(o.handle_ref()?);
        let b = &mut o.data;
        c.text_location = v3(b.bd3()?);
        c.text_direction = v3(b.bd3()?);
        c.text_rotation = b.bd()?;
        c.text_width = b.bd()?;
        c.text_boundary_height = b.bd()?;
        c.line_spacing_factor = b.bd()?;
        c.line_spacing_style = b.bs()?;
        c.text_color = cmc(o, v)?.0;
        let b = &mut o.data;
        c.text_attachment = b.bs()?;
        c.text_flow_direction = b.bs()?;
        cmc(o, v)?; // background colour
        let b = &mut o.data;
        b.bd()?; // background scale
        b.bl()?; // background transparency
        b.b()?;
        b.b()?;
        b.bs()?; // column type
        b.b()?;
        b.bd()?;
        b.bd()?;
        b.b()?;
        let k = i64::from(b.bl()?);
        let k = count(b, k, 2)?;
        for _ in 0..k {
            o.data.bd()?;
        }
        o.data.b()?; // word break
        o.data.b()?;
    } else {
        c.has_block = o.data.b()?;
        if c.has_block {
            c.block = Handle(o.handle_ref()?);
            let b = &mut o.data;
            c.block_normal = v3(b.bd3()?);
            c.block_position = v3(b.bd3()?);
            c.block_scale = v3(b.bd3()?);
            c.block_rotation = b.bd()?;
            c.block_color = cmc(o, v)?.0;
            for _ in 0..16 {
                let x = o.data.bd()?;
                c.block_transform.push(x);
            }
        }
    }
    let b = &mut o.data;
    c.plane_origin = v3(b.bd3()?);
    c.plane_x_axis = v3(b.bd3()?);
    c.plane_y_axis = v3(b.bd3()?);
    c.plane_normal_reversed = b.b()?;
    if v >= Version::R2010 {
        b.bs()?; // top attachment
        b.bs()?; // bottom attachment
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A null text style handle reads as DXF's default, STANDARD; a style
    /// the file has keeps its name, a dangling one none.
    #[test]
    fn a_null_text_style_is_standard() {
        assert_eq!(text_style_name(0, None), "STANDARD");
        assert_eq!(text_style_name(0x11, Some("ROMANS".into())), "ROMANS");
        assert_eq!(text_style_name(0x99, None), "");
    }
}
