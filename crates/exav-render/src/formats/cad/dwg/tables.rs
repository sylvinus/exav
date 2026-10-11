//! The symbol tables (ODA spec 20.4.53 to 20.4.68): each control object
//! lists its entries' handles, and each entry starts with the same name and
//! flags.

use exav_unpack::dwg::{BitResult, EedValue, Object, Version};

use super::header::Vars;
use super::Ctx;
use crate::formats::cad::model::*;

/// The fixed type codes of the tables' objects (spec 20.3).
const LAYER: u16 = 0x33;
const STYLE: u16 = 0x35;
const LTYPE: u16 = 0x39;
const VPORT: u16 = 0x41;
const APPID: u16 = 0x43;
const DIMSTYLE: u16 = 0x45;

/// The handles a control object lists (spec 20.4.51 and on), nulls left
/// out. `extra` more than its count follow it: the block control's model
/// and paper space, the linetype control's ByLayer and ByBlock.
pub(crate) fn entries(ctx: &mut Ctx<'_, '_>, control: u64, what: &str, extra: u64) -> Vec<u64> {
    let Some(mut o) = ctx.object(control, what) else {
        return Vec::new();
    };
    let count = match o.data.bl() {
        Ok(n) => u64::try_from(n).unwrap_or(0),
        Err(e) => {
            ctx.warn(WarningKind::Malformed, format!("{what}: {e}"));
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    // A handle takes at least a byte: the count cannot be more.
    let n = (count + extra).min(o.handles.remaining() / 8);
    for _ in 0..n {
        match o.handle_ref() {
            Ok(0) => {}
            Ok(h) => out.push(h),
            Err(e) => {
                ctx.warn(
                    WarningKind::Malformed,
                    format!("{what}'s entries stop early: {e}"),
                );
                break;
            }
        }
    }
    out
}

/// The name and flags every entry starts with (spec 20.4.54 and others):
/// TV name, B 64-flag, BS xref index + 1, B xref dependent, group 70's 16.
///
/// The 64-flag is left out of the model's group 70: the ODA File Converter
/// sets it in every entry and block it writes to a DWG (tests/fixtures/
/// cad/make.py's entries, 70 = 0, come back with it) and clears it in every
/// one it writes to DXF, so it is bookkeeping that a DXF of the same
/// drawing does not have.
pub(crate) fn entry_head(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<(String, i16)> {
    let raw = o.tv()?;
    let name = ctx.string(raw);
    // The 64-flag. Then the xref index, which the spec has in every
    // version; from R2007 there is none: every APPID of the corpus's R2010
    // to R2018 conversions has 10 bits between its common data and its
    // string stream, the 64-flag, xdep and its byte (R2004: 12, with a BS of
    // 0 after the 64-flag), and LAYER and STYLE read so match their DXF.
    o.data.b()?;
    if ctx.version < Version::R2007 {
        o.data.bs()?; // xref index + 1
    }
    let dependent = o.data.b()?;
    Ok((name, i16::from(dependent) << 4))
}

/// Read every table the header names into `d`, and the names of their
/// entries into `ctx.names`.
pub(crate) fn read(ctx: &mut Ctx<'_, '_>, vars: &Vars, d: &mut Drawing) {
    for h in entries(ctx, vars.appid_control, "the APPID control", 0) {
        if let Some(mut o) = typed(ctx, h, APPID, "APPID") {
            match entry_head(ctx, &mut o) {
                Ok((name, _)) => {
                    ctx.apps.insert(h, name.clone());
                    ctx.names.insert(h, name);
                }
                Err(e) => bad(ctx, "APPID", h, e),
            }
        }
    }
    let ltypes = entries(ctx, vars.ltype_control, "the LTYPE control", 2);
    ctx.ltypes.clone_from(&ltypes);
    for h in ltypes {
        if let Some(mut o) = typed(ctx, h, LTYPE, "LTYPE") {
            match linetype(ctx, &mut o) {
                Ok(l) => {
                    ctx.names.insert(h, l.name.clone());
                    d.linetypes.push(l);
                }
                Err(e) => bad(ctx, "LTYPE", h, e),
            }
        }
    }
    for h in entries(ctx, vars.style_control, "the STYLE control", 0) {
        if let Some(mut o) = typed(ctx, h, STYLE, "STYLE") {
            match text_style(ctx, &mut o) {
                Ok(s) => {
                    ctx.names.insert(h, s.name.clone());
                    d.text_styles.push(s);
                }
                Err(e) => bad(ctx, "STYLE", h, e),
            }
        }
    }
    for h in entries(ctx, vars.layer_control, "the LAYER control", 0) {
        if let Some(mut o) = typed(ctx, h, LAYER, "LAYER") {
            match layer(ctx, &mut o) {
                Ok(l) => {
                    ctx.names.insert(h, l.name.clone());
                    d.layers.push(l);
                }
                Err(e) => bad(ctx, "LAYER", h, e),
            }
        }
    }
    for h in entries(ctx, vars.dimstyle_control, "the DIMSTYLE control", 0) {
        if let Some(mut o) = typed(ctx, h, DIMSTYLE, "DIMSTYLE") {
            match dim_style(ctx, &mut o) {
                Ok(s) => {
                    ctx.names.insert(h, s.name.clone());
                    d.dim_styles.push(s);
                }
                Err(e) => bad(ctx, "DIMSTYLE", h, e),
            }
        }
    }
    for h in entries(ctx, vars.vport_control, "the VPORT control", 0) {
        if let Some(mut o) = typed(ctx, h, VPORT, "VPORT") {
            match vport(ctx, &mut o) {
                Ok(v) => d.vports.push(v),
                Err(e) => bad(ctx, "VPORT", h, e),
            }
        }
    }
}

fn bad(ctx: &mut Ctx<'_, '_>, what: &str, h: u64, e: exav_unpack::dwg::BitError) {
    ctx.warn(
        WarningKind::Malformed,
        format!("{what} {h:X} could not be read: {e}"),
    );
}

/// The object of a handle when it has the type its table holds.
pub(crate) fn typed<'a>(
    ctx: &mut Ctx<'a, '_>,
    h: u64,
    type_code: u16,
    what: &str,
) -> Option<Object<'a>> {
    let o = ctx.object(h, what)?;
    if o.type_code != type_code {
        ctx.warn(
            WarningKind::Malformed,
            format!("{what} {h:X} is an object of type {}", o.type_code),
        );
        return None;
    }
    Some(o)
}

/// An entity or layer lineweight byte (R2000 on), which the spec does not
/// explain: an index into the lineweights the DXF reference lists, then
/// ByLayer, ByBlock and Default. Found with the ODA File Converter: an
/// R2000 file of a line and a layer per lineweight (ezdxf), converted to DWG,
/// gives 0 to 23 in order and 29, 30, 31; patching a line's byte to the
/// others and converting back to DXF gives 0 for 24 to 27 and ByLayer for 28
/// and 32 to 255.
pub(crate) fn lineweight(index: u8) -> LineWeight {
    const VALUES: [u16; 24] = [
        0, 5, 9, 13, 15, 18, 20, 25, 30, 35, 40, 50, 53, 60, 70, 80, 90, 100, 106, 120, 140, 158,
        200, 211,
    ];
    match index {
        24..=27 => LineWeight::Value(0),
        30 => LineWeight::ByBlock,
        31 => LineWeight::Default,
        i => VALUES
            .get(usize::from(i))
            .map_or(LineWeight::ByLayer, |v| LineWeight::Value(*v)),
    }
}

/// A CMC colour (spec 2.11), and the index as stored (negative for a layer
/// that is off, R13 to R2000). From R2004 the index is 0 and the colour is
/// the raw AcCmColor value of the BL that follows: the top byte says how
/// to read it (0xC3 an index in the low byte, 0xC2 a true colour: every
/// LAYER of the corpus's R2004 files has one or the other, its DXF 62 or
/// 420), then flags of the names that follow, which are not kept.
pub(crate) fn cmc(o: &mut Object<'_>, version: Version) -> BitResult<(Color, i16)> {
    let index = o.data.bs()?;
    if version < Version::R2004 {
        return Ok((Color::from_aci(i64::from(index)), index));
    }
    let raw = o.data.bl()? as u32;
    let flags = o.data.rc()?;
    if flags & 1 != 0 {
        o.tv()?;
    }
    if flags & 2 != 0 {
        o.tv()?;
    }
    Ok((Color::from_raw(i64::from(raw)), index))
}

fn layer(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Layer> {
    let (name, mut flags) = entry_head(ctx, o)?;
    let mut l = Layer {
        handle: Handle(o.handle),
        name,
        ..Layer::default()
    };
    // The spec calls the second bit (value 2 from 2000) "on"; it is set
    // when the layer is off: of the layers tests/fixtures/cad/make.py
    // writes, the converter sets it for HIDDEN_OFF alone, in R13, R14 and
    // 2000.
    let off;
    if ctx.version <= Version::R14 {
        let frozen = o.data.b()?;
        off = o.data.b()?;
        let frozen_new = o.data.b()?;
        let locked = o.data.b()?;
        flags |= i16::from(frozen) | i16::from(frozen_new) << 1 | i16::from(locked) << 2;
    } else {
        let values = o.data.bs()?;
        flags |= values & 1 | (values >> 1) & 6;
        off = values & 2 != 0;
        l.plot = values & 16 != 0;
        l.lineweight = lineweight(((values & 0x3E0) >> 5) as u8);
    }
    l.flags = flags;
    let (color, index) = cmc(o, ctx.version)?;
    l.off = off || index < 0;
    l.color = color;
    // Before 2004 a layer's transparency is in its AcCmTransparency
    // application's data, as in DXF.
    for eed in &o.eed {
        if !ctx.is_app(eed.app, "AcCmTransparency") {
            continue;
        }
        for (code, value) in eed.items(ctx.version) {
            if let (1071, EedValue::Long(v)) = (code, value) {
                if let Transparency::Alpha(a) = Transparency::from_code(i64::from(v)) {
                    l.alpha = a;
                }
            }
        }
    }
    // Handles: the xref block, then (2000) the plot style, (2007) the
    // material, the linetype.
    o.handle_ref()?;
    if ctx.version >= Version::R2000 {
        l.plot_style = Handle(o.handle_ref()?);
    }
    if ctx.version >= Version::R2007 {
        l.material = Handle(o.handle_ref()?);
    }
    // Linetypes are read first, so their names are known.
    let lt = o.handle_ref()?;
    if let Some(n) = ctx.name(lt) {
        l.linetype = n.to_string();
    }
    Ok(l)
}

fn linetype(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Linetype> {
    let (name, flags) = entry_head(ctx, o)?;
    let raw = o.tv()?;
    let mut lt = Linetype {
        handle: Handle(o.handle),
        name,
        flags,
        description: ctx.string(raw),
        pattern_length: o.data.bd()?,
        ..Linetype::default()
    };
    o.data.rc()?; // alignment, 'A'
    let count = o.data.rc()?;
    for _ in 0..count {
        let length = o.data.bd()?;
        let shape_number = o.data.bs()?;
        let x = o.data.rd()?;
        let y = o.data.rd()?;
        let scale = o.data.bd()?;
        let rotation = o.data.bd()?;
        let flags = o.data.bs()?;
        if lt.elements.len() < ctx.limits.max_items {
            lt.elements.push(LinetypeElement {
                length,
                flags,
                shape_number,
                style: Handle::NULL,
                scale,
                rotation,
                offset: Vec2::new(x, y),
                text: String::new(),
            });
        }
    }
    // The text elements' strings, at their shape number's offset in a
    // 256-byte area (512 from 2007, present only when a text uses it). The
    // spec's shape flag text has 2 for a shape and 4 for a text; it is DXF's
    // 74, 2 text and 4 shape: make.py's GAS_LINE text comes back with 2.
    let has_text = lt.elements.iter().any(LinetypeElement::has_text);
    let area = if ctx.version <= Version::R2004 {
        Some(o.data.bytes(256)?)
    } else if has_text {
        Some(o.data.bytes(512)?)
    } else {
        None
    };
    if let Some(area) = area {
        for i in 0..lt.elements.len() {
            let Some(e) = lt.elements.get(i) else {
                continue;
            };
            if !e.has_text() {
                continue;
            }
            let unicode = ctx.version >= Version::R2007;
            // From R2007 the area holds UTF-16 strings and the offset counts
            // characters: a second text after "SPR" has 4 and starts at
            // byte 8 of an R2010 file (R2004: 4, at byte 4).
            let at = usize::try_from(e.shape_number)
                .ok()
                .and_then(|n| n.checked_mul(if unicode { 2 } else { 1 }))
                .unwrap_or(usize::MAX);
            let s = area.get(at..).unwrap_or(&[]);
            let text = if unicode {
                let units: Vec<u16> = s
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .take_while(|u| *u != 0)
                    .collect();
                ctx.string(exav_unpack::dwg::Text::Unicode(String::from_utf16_lossy(
                    &units,
                )))
            } else {
                let end = s.iter().position(|b| *b == 0).unwrap_or(s.len());
                ctx.text(s.get(..end).unwrap_or(&[]))
            };
            // For a text the number was the offset; DXF's 75 is then 0.
            if let Some(e) = lt.elements.get_mut(i) {
                e.text = text;
                e.shape_number = 0;
            }
        }
    }
    o.handle_ref()?; // the xref block
    for e in &mut lt.elements {
        e.style = Handle(o.handle_ref()?);
    }
    Ok(lt)
}

fn text_style(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<TextStyle> {
    let (name, mut flags) = entry_head(ctx, o)?;
    // The spec lists "Vertical B (1 bit of flag)" then "shape file B (4
    // bit)": its bit values are right, its names swapped. The first bit is
    // set for exactly the STYLE entries whose DXF has 70 = 1 (shape file),
    // in R13, R14 and 2000 alike (the oracle test's corpus).
    let shape_file = o.data.b()?;
    let vertical = o.data.b()?;
    flags |= i16::from(shape_file) | i16::from(vertical) << 2;
    let mut s = TextStyle {
        handle: Handle(o.handle),
        name,
        flags,
        height: o.data.bd()?,
        width_factor: o.data.bd()?,
        oblique: o.data.bd()?,
        generation: i16::from(o.data.rc()?),
        last_height: o.data.bd()?,
        ..TextStyle::default()
    };
    let font = o.tv()?;
    s.font_file = ctx.string(font);
    let bigfont = o.tv()?;
    s.bigfont_file = ctx.string(bigfont);
    // The TrueType family and flags, in the ACAD application's data.
    for eed in &o.eed {
        if !ctx.is_app(eed.app, "ACAD") {
            continue;
        }
        for (code, value) in eed.items(ctx.version) {
            match (code, value) {
                (1000, EedValue::Text(t)) if s.font_family.is_empty() => {
                    s.font_family = ctx.text(t);
                }
                (1000, EedValue::Unicode(t)) if s.font_family.is_empty() => s.font_family = t,
                (1071, EedValue::Long(v)) => s.font_flags = i64::from(v),
                _ => {}
            }
        }
    }
    Ok(s)
}

fn dim_style(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<DimStyle> {
    let (name, flags) = entry_head(ctx, o)?;
    let mut s = DimStyle {
        handle: Handle(o.handle),
        name,
        flags,
        ..DimStyle::default()
    };
    let b = &mut o.data;
    if ctx.version <= Version::R14 {
        // DIMTOL to DIMSOXD
        for _ in 0..11 {
            b.b()?;
        }
        // DIMALTD, DIMZIN
        b.rc()?;
        b.rc()?;
        // DIMSD1, DIMSD2
        b.b()?;
        b.b()?;
        // DIMTOLJ, DIMJUST, DIMFIT
        for _ in 0..3 {
            b.rc()?;
        }
        b.b()?; // DIMUPT
                // DIMTZIN, DIMALTZ, DIMALTTZ, DIMTAD
        for _ in 0..4 {
            b.rc()?;
        }
        // DIMUNIT, DIMAUNIT, DIMDEC, DIMTDEC, DIMALTU, DIMALTTD
        for _ in 0..6 {
            b.bs()?;
        }
        s.dimscale = b.bd()?;
        s.dimasz = b.bd()?;
        s.dimexo = b.bd()?;
        b.bd()?; // DIMDLI
        s.dimexe = b.bd()?;
        b.bd()?; // DIMRND
        s.dimdle = b.bd()?;
        // DIMTP, DIMTM
        b.bd()?;
        b.bd()?;
        s.dimtxt = b.bd()?;
        b.bd()?; // DIMCEN
        s.dimtsz = b.bd()?;
        // DIMALTF, DIMLFAC, DIMTVP, DIMTFAC
        for _ in 0..4 {
            b.bd()?;
        }
        s.dimgap = b.bd()?;
        // DIMPOST, DIMAPOST, DIMBLK, DIMBLK1, DIMBLK2
        for _ in 0..5 {
            b.t()?;
        }
        s.dimclrd = Color::from_aci(i64::from(b.bs()?));
        s.dimclre = Color::from_aci(i64::from(b.bs()?));
        s.dimclrt = Color::from_aci(i64::from(b.bs()?));
    } else {
        // DIMPOST, DIMAPOST; from R2007 in the string stream, as are the
        // strings below, which are not kept.
        if ctx.version < Version::R2007 {
            b.t()?;
            b.t()?;
        }
        s.dimscale = b.bd()?;
        s.dimasz = b.bd()?;
        s.dimexo = b.bd()?;
        b.bd()?; // DIMDLI
        s.dimexe = b.bd()?;
        b.bd()?; // DIMRND
        s.dimdle = b.bd()?;
        // DIMTP, DIMTM
        b.bd()?;
        b.bd()?;
        if ctx.version >= Version::R2007 {
            // DIMFXL, DIMJOGANG
            b.bd()?;
            b.bd()?;
            // DIMTFILL, then DIMTFILLCLR, a CMC whose names would be in the
            // string stream.
            b.bs()?;
            b.bs()?;
            b.bl()?;
            b.rc()?;
        }
        // DIMTOL, DIMLIM, DIMTIH, DIMTOH, DIMSE1, DIMSE2
        for _ in 0..6 {
            b.b()?;
        }
        // DIMTAD, DIMZIN, DIMAZIN
        for _ in 0..3 {
            b.bs()?;
        }
        if ctx.version >= Version::R2007 {
            b.bs()?; // DIMARCSYM
        }
        s.dimtxt = b.bd()?;
        b.bd()?; // DIMCEN
        s.dimtsz = b.bd()?;
        // DIMALTF, DIMLFAC, DIMTVP, DIMTFAC
        for _ in 0..4 {
            b.bd()?;
        }
        s.dimgap = b.bd()?;
        b.bd()?; // DIMALTRND
        b.b()?; // DIMALT
        b.bs()?; // DIMALTD
                 // DIMTOFL, DIMSAH, DIMTIX, DIMSOXD
        for _ in 0..4 {
            b.b()?;
        }
        s.dimclrd = cmc(o, ctx.version)?.0;
        s.dimclre = cmc(o, ctx.version)?.0;
        s.dimclrt = cmc(o, ctx.version)?.0;
        let b = &mut o.data;
        // DIMADEC, DIMDEC, DIMTDEC, DIMALTU, DIMALTTD, DIMAUNIT, DIMFRAC,
        // DIMLUNIT, DIMDSEP, DIMTMOVE, DIMJUST
        for _ in 0..11 {
            b.bs()?;
        }
        // DIMSD1, DIMSD2
        b.b()?;
        b.b()?;
        // DIMTOLJ, DIMTZIN, DIMALTZ, DIMALTTZ
        for _ in 0..4 {
            b.bs()?;
        }
        b.b()?; // DIMUPT
        b.bs()?; // DIMFIT
        if ctx.version >= Version::R2007 {
            b.b()?; // DIMFXLON
        }
        if ctx.version >= Version::R2010 {
            b.b()?; // DIMTXTDIRECTION
            b.bd()?; // DIMALTMZF, then the string DIMALTMZS
            b.bd()?; // DIMMZF, then the string DIMMZS
        }
        s.dimlwd = LineWeight::from_code(i64::from(b.bs()?));
        s.dimlwe = LineWeight::from_code(i64::from(b.bs()?));
    }
    // "Seems to set the 0-bit (1) of the 70-group" (spec 20.4.68).
    if o.data.b()? {
        s.flags |= 1;
    }
    o.handle_ref()?; // the xref block
    s.dimtxsty = Handle(o.handle_ref()?);
    if ctx.version >= Version::R2000 {
        s.dimldrblk = Handle(o.handle_ref()?);
        s.dimblk = Handle(o.handle_ref()?);
        s.dimblk1 = Handle(o.handle_ref()?);
        s.dimblk2 = Handle(o.handle_ref()?);
    }
    Ok(s)
}

fn vport(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<VPort> {
    let (name, flags) = entry_head(ctx, o)?;
    let b = &mut o.data;
    let height = b.bd()?;
    // "Actually the aspect ratio times the view height" (spec 20.4.64).
    let aspect = b.bd()?;
    let center = b.rd2()?;
    let target = b.bd3()?;
    let direction = b.bd3()?;
    let twist = b.bd()?;
    // Lens length, front and back clip
    b.bd()?;
    b.bd()?;
    b.bd()?;
    b.read(4)?; // view mode
    if ctx.version >= Version::R2000 {
        b.rc()?; // render mode
    }
    if ctx.version >= Version::R2007 {
        b.b()?;
        b.rc()?;
        b.bd()?;
        b.bd()?;
        // Ambient colour, a CMC whose names are in the string stream.
        b.bs()?;
        b.bl()?;
        b.rc()?;
    }
    let lower_left = b.rd2()?;
    let upper_right = b.rd2()?;
    Ok(VPort {
        handle: Handle(o.handle),
        name,
        flags,
        lower_left: Vec2::new(lower_left[0], lower_left[1]),
        upper_right: Vec2::new(upper_right[0], upper_right[1]),
        center: Vec2::new(center[0], center[1]),
        view_direction: Vec3::new(direction[0], direction[1], direction[2]),
        target: Vec3::new(target[0], target[1], target[2]),
        height,
        aspect_ratio: if height != 0.0 {
            aspect / height
        } else {
            aspect
        },
        twist,
    })
}
