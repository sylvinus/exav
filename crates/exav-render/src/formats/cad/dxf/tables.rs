//! TABLES section entries, and the BLOCK entity that opens a block
//! definition.

use exav_unpack::dxf::{Parts, Record, Tag};

use super::{Ctx, Raw};
use crate::formats::cad::model::*;

fn set_point(p: &mut Vec3, t: &Tag<'_>, base: i32) -> bool {
    match t.code - base {
        0 => p.x = t.f64(),
        10 => p.y = t.f64(),
        20 => p.z = t.f64(),
        _ => return false,
    }
    true
}

fn set_point2(p: &mut Vec2, t: &Tag<'_>, base: i32) -> bool {
    match t.code - base {
        0 => p.x = t.f64(),
        10 => p.y = t.f64(),
        _ => return false,
    }
    true
}

pub(crate) fn entry(table: &str, rec: &Record<'_>, raw: &mut Raw, ctx: &mut Ctx<'_>) {
    let expected = match table {
        "LAYER" | "LTYPE" | "STYLE" | "DIMSTYLE" | "VPORT" | "BLOCK_RECORD" => table,
        _ => return,
    };
    if !rec.is(expected) {
        ctx.warn(
            WarningKind::Malformed,
            format!("{} in table {table}, skipped", rec.type_name()),
        );
        return;
    }
    let parts = Parts::new(&rec.tags, table == "DIMSTYLE");
    let handle = Handle(parts.handle());
    match table {
        "LAYER" => raw.layers.push(layer(&parts, handle, ctx)),
        "LTYPE" => raw.linetypes.push(linetype(&parts, handle, ctx)),
        "STYLE" => raw.text_styles.push(text_style(&parts, handle, ctx)),
        "DIMSTYLE" => raw.dim_styles.push(dim_style(&parts, handle, ctx)),
        "VPORT" => raw.vports.push(vport(&parts, handle, ctx)),
        _ => raw.block_records.push(block_record(&parts, handle, ctx)),
    }
}

/// The groups after the head: the entry's own. R12 entries have no head
/// to skip, and their handle group (5) means nothing below.
fn body<'p, 'a>(parts: &'p Parts<'a>) -> &'p [Tag<'a>] {
    if parts.has_markers() {
        parts.after("AcDbSymbolTableRecord")
    } else {
        &parts.tags
    }
}

/// The entry's flags: the first group 70. A later one is another variable
/// (DIMSTYLE's DIMTFILLCLR, from 2007).
fn flags(parts: &Parts<'_>) -> i16 {
    body(parts)
        .iter()
        .find(|t| t.code == 70)
        .map_or(0, |t| t.i16())
}

fn layer(parts: &Parts<'_>, handle: Handle, ctx: &mut Ctx<'_>) -> Layer {
    let mut l = Layer {
        handle,
        flags: flags(parts),
        ..Layer::default()
    };
    let mut rgb = None;
    for t in body(parts) {
        match t.code {
            2 => l.name = ctx.text(t),
            62 => {
                let v = t.int();
                l.off = v < 0;
                l.color = Color::from_aci(v);
            }
            420 => rgb = Some(Color::from_rgb24(t.int())),
            6 => l.linetype = ctx.text(t),
            290 => l.plot = t.bool(),
            370 => l.lineweight = LineWeight::from_code(t.int()),
            390 => l.plot_style = Handle(t.handle()),
            347 => l.material = Handle(t.handle()),
            _ => {}
        }
    }
    if let Some(c) = rgb {
        l.color = c;
    }
    if let Some(x) = parts.xdata("AcCmTransparency") {
        if let Some(t) = x.iter().find(|t| t.code == 1071) {
            if let Transparency::Alpha(a) = Transparency::from_code(t.int()) {
                l.alpha = a;
            }
        }
    }
    l
}

fn linetype(parts: &Parts<'_>, handle: Handle, ctx: &mut Ctx<'_>) -> Linetype {
    let mut lt = Linetype {
        handle,
        flags: flags(parts),
        ..Linetype::default()
    };
    for t in body(parts) {
        if t.code == 49 {
            if ctx.room(lt.elements.len()) {
                lt.elements.push(LinetypeElement {
                    length: t.f64(),
                    scale: 1.0,
                    ..LinetypeElement::default()
                });
            }
            continue;
        }
        let Some(e) = lt.elements.last_mut() else {
            match t.code {
                2 => lt.name = ctx.text(t),
                3 => lt.description = ctx.text(t),
                40 => lt.pattern_length = t.f64(),
                _ => {}
            }
            continue;
        };
        match t.code {
            74 => e.flags = t.i16(),
            75 => e.shape_number = t.i16(),
            340 => e.style = Handle(t.handle()),
            46 => e.scale = t.f64(),
            50 => e.rotation = t.f64().to_radians(),
            44 => e.offset.x = t.f64(),
            45 => e.offset.y = t.f64(),
            9 => e.text = ctx.text(t),
            _ => {}
        }
    }
    lt
}

fn text_style(parts: &Parts<'_>, handle: Handle, ctx: &mut Ctx<'_>) -> TextStyle {
    let mut s = TextStyle {
        handle,
        flags: flags(parts),
        ..TextStyle::default()
    };
    for t in body(parts) {
        match t.code {
            2 => s.name = ctx.text(t),
            40 => s.height = t.f64(),
            41 => s.width_factor = t.f64(),
            50 => s.oblique = t.f64().to_radians(),
            71 => s.generation = t.i16(),
            42 => s.last_height = t.f64(),
            3 => s.font_file = ctx.text(t),
            4 => s.bigfont_file = ctx.text(t),
            _ => {}
        }
    }
    if let Some(x) = parts.xdata("ACAD") {
        for t in x {
            match t.code {
                1000 if s.font_family.is_empty() => s.font_family = ctx.text(t),
                1071 => s.font_flags = t.int(),
                _ => {}
            }
        }
    }
    s
}

fn dim_style(parts: &Parts<'_>, handle: Handle, ctx: &mut Ctx<'_>) -> DimStyle {
    let mut d = DimStyle {
        handle,
        flags: flags(parts),
        ..DimStyle::default()
    };
    let r13 = parts.has_markers();
    for t in body(parts) {
        match t.code {
            2 => d.name = ctx.text(t),
            40 => d.dimscale = t.f64(),
            41 => d.dimasz = t.f64(),
            42 => d.dimexo = t.f64(),
            44 => d.dimexe = t.f64(),
            46 => d.dimdle = t.f64(),
            140 => d.dimtxt = t.f64(),
            142 => d.dimtsz = t.f64(),
            147 => d.dimgap = t.f64(),
            176 => d.dimclrd = Color::from_aci(t.int()),
            177 => d.dimclre = Color::from_aci(t.int()),
            178 => d.dimclrt = Color::from_aci(t.int()),
            371 => d.dimlwd = LineWeight::from_code(t.int()),
            372 => d.dimlwe = LineWeight::from_code(t.int()),
            340 if r13 => d.dimtxsty = Handle(t.handle()),
            341 if r13 => d.dimldrblk = Handle(t.handle()),
            342 if r13 => d.dimblk = Handle(t.handle()),
            343 if r13 => d.dimblk1 = Handle(t.handle()),
            344 if r13 => d.dimblk2 = Handle(t.handle()),
            _ => {}
        }
    }
    d
}

fn vport(parts: &Parts<'_>, handle: Handle, ctx: &mut Ctx<'_>) -> VPort {
    let mut v = VPort {
        handle,
        flags: flags(parts),
        ..VPort::default()
    };
    for t in body(parts) {
        if set_point2(&mut v.lower_left, t, 10)
            || set_point2(&mut v.upper_right, t, 11)
            || set_point2(&mut v.center, t, 12)
            || set_point(&mut v.view_direction, t, 16)
            || set_point(&mut v.target, t, 17)
        {
            continue;
        }
        match t.code {
            2 => v.name = ctx.text(t),
            // 40 is what AutoCAD writes; the 2012 reference lists 45.
            40 | 45 => v.height = t.f64(),
            41 => v.aspect_ratio = t.f64(),
            51 => v.twist = t.f64().to_radians(),
            _ => {}
        }
    }
    v
}

fn block_record(parts: &Parts<'_>, handle: Handle, ctx: &mut Ctx<'_>) -> Block {
    let mut b = Block {
        record: handle,
        explodable: true,
        scalable: true,
        ..Block::default()
    };
    for t in body(parts) {
        match t.code {
            2 => b.name = ctx.text(t),
            340 => b.layout = Handle(t.handle()),
            70 => b.insert_units = t.i16(),
            280 => b.explodable = t.bool(),
            281 => b.scalable = t.bool(),
            _ => {}
        }
    }
    b
}

/// A BLOCK entity: name, flags, base point. Its owner is the block record.
pub(crate) fn block(rec: &Record<'_>, ctx: &mut Ctx<'_>) -> Block {
    let parts = Parts::new(&rec.tags, false);
    let mut b = Block {
        handle: Handle(parts.handle()),
        record: Handle(parts.owner()),
        explodable: true,
        scalable: true,
        ..Block::default()
    };
    for t in parts.common() {
        if t.code == 8 {
            b.layer = ctx.text(t);
        }
    }
    for t in parts.after("AcDbEntity") {
        if set_point(&mut b.base_point, t, 10) {
            continue;
        }
        match t.code {
            2 => b.name = ctx.text(t),
            70 => b.flags = t.i16(),
            1 => b.xref_path = ctx.text(t),
            4 => b.description = ctx.text(t),
            // A name only in group 3.
            3 if b.name.is_empty() => b.name = ctx.text(t),
            _ => {}
        }
    }
    b
}
