//! The objects a drawing depends on, as the DXF reader keeps them from the
//! OBJECTS section: dictionaries (ODA spec 20.4.44, 20.4.45), layouts with
//! their plot settings (20.4.84), draw order (20.4.93), image definitions
//! (20.4.81), underlay definitions, multiline styles (20.4.73) and
//! multileader styles (20.4.87). Every object of these types in the object
//! map is read, the root dictionary first; others are left alone.

use exav_unpack::dwg::{BitError, BitResult, Object, Version};

use super::blocks::number_viewports;
use super::header::Vars;
use super::tables::cmc;
use super::Ctx;
use crate::formats::cad::model::*;

fn v3(p: [f64; 3]) -> Vec3 {
    Vec3::new(p[0], p[1], p[2])
}

fn v2(p: [f64; 2]) -> Vec2 {
    Vec2::new(p[0], p[1])
}

fn string(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<String> {
    let t = o.tv()?;
    Ok(ctx.string(t))
}

/// `n` items of at least `min_bits` bits each must fit in `bits`.
fn count(n: i64, bits: u64, min_bits: u64) -> BitResult<usize> {
    let n = u64::try_from(n).map_err(|_| BitError::Invalid)?;
    if n.saturating_mul(min_bits) > bits {
        return Err(BitError::End);
    }
    usize::try_from(n).map_err(|_| BitError::Invalid)
}

/// The object types read, by DXF name.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dictionary,
    Layout,
    SortEnts,
    ImageDef,
    Underlay(UnderlayKind),
    MLineStyle,
    MLeaderStyle,
}

fn kind(name: &str) -> Option<Kind> {
    Some(match name {
        "DICTIONARY" | "ACDBDICTIONARYWDFLT" => Kind::Dictionary,
        "LAYOUT" => Kind::Layout,
        "SORTENTSTABLE" => Kind::SortEnts,
        "IMAGEDEF" => Kind::ImageDef,
        "PDFDEFINITION" => Kind::Underlay(UnderlayKind::Pdf),
        "DWFDEFINITION" => Kind::Underlay(UnderlayKind::Dwf),
        "DGNDEFINITION" => Kind::Underlay(UnderlayKind::Dgn),
        "MLINESTYLE" => Kind::MLineStyle,
        "MLEADERSTYLE" => Kind::MLeaderStyle,
        _ => return None,
    })
}

/// Read the objects into `d`, whose blocks are read.
pub(crate) fn read(ctx: &mut Ctx<'_, '_>, vars: &Vars, d: &mut Drawing) {
    let mut found: Vec<(u64, Kind)> = Vec::new();
    for &(handle, offset) in ctx.dwg.object_map() {
        let Ok(t) = ctx.dwg.type_at(offset) else {
            continue;
        };
        if ctx.dwg.is_entity(t) {
            continue;
        }
        if let Some(k) = ctx.dwg.type_name(t).as_deref().and_then(kind) {
            found.push((handle, k));
        }
    }
    // The root dictionary first, as DXF writes it.
    if let Some(i) = found.iter().position(|(h, _)| *h == vars.named_objects) {
        let root = found.remove(i);
        found.insert(0, root);
    }
    for (h, k) in found {
        let what = match k {
            Kind::Dictionary => "DICTIONARY",
            Kind::Layout => "LAYOUT",
            Kind::SortEnts => "SORTENTSTABLE",
            Kind::ImageDef => "IMAGEDEF",
            Kind::Underlay(_) => "underlay definition",
            Kind::MLineStyle => "MLINESTYLE",
            Kind::MLeaderStyle => "MLEADERSTYLE",
        };
        let Some(mut o) = ctx.object(h, what) else {
            continue;
        };
        let room = |ctx: &mut Ctx<'_, '_>, n: usize| ctx.room(n);
        let done = match k {
            Kind::Dictionary => dictionary(ctx, &mut o).map(|x| {
                if room(ctx, d.dictionaries.len()) {
                    d.dictionaries.push(x);
                }
            }),
            Kind::Layout => layout(ctx, &mut o).map(|x| {
                if room(ctx, d.layouts.len()) {
                    d.layouts.push(x);
                }
            }),
            Kind::SortEnts => sort_table(ctx, &mut o).map(|x| {
                if room(ctx, d.sort_tables.len()) {
                    d.sort_tables.push(x);
                }
            }),
            Kind::ImageDef => image_def(ctx, &mut o).map(|x| {
                if room(ctx, d.image_defs.len()) {
                    d.image_defs.push(x);
                }
            }),
            Kind::Underlay(kind) => underlay_def(ctx, &mut o, kind).map(|x| {
                if room(ctx, d.underlay_defs.len()) {
                    d.underlay_defs.push(x);
                }
            }),
            Kind::MLineStyle => mline_style(ctx, &mut o).map(|x| {
                if room(ctx, d.mline_styles.len()) {
                    d.mline_styles.push(x);
                }
            }),
            Kind::MLeaderStyle => mleader_style(ctx, &mut o).map(|x| {
                if room(ctx, d.mleader_styles.len()) {
                    d.mleader_styles.push(x);
                }
            }),
        };
        if let Err(e) = done {
            ctx.warn(
                WarningKind::Malformed,
                format!("{what} {h:X} could not be read: {e}"),
            );
        }
    }
}

/// DICTIONARY and ACDBDICTIONARYWDFLT (spec 20.4.44, 20.4.45): the names in
/// the data, their objects' handles after the common ones; the default
/// entry of the second follows them.
pub(crate) fn dictionary(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Dictionary> {
    let v = ctx.version;
    let n = i64::from(o.data.bl()?);
    let mut d = Dictionary {
        handle: Handle(o.handle),
        owner: Handle(o.owner),
        ..Dictionary::default()
    };
    // R14's byte, "unknown, always 0" in the spec, is the hard owner flag:
    // 1 in the corpus's R14 conversions where their DXF has 280 = 1, 0
    // in their root dictionaries.
    if v == Version::R14 {
        d.hard_owner = o.data.rc()? != 0;
    }
    if v >= Version::R2000 {
        d.cloning = o.data.bs()?;
        d.hard_owner = o.data.rc()? != 0;
    }
    // A handle takes at least a byte.
    let n = count(n, o.handles.remaining(), 8)?;
    let mut names = Vec::new();
    for _ in 0..n {
        let name = string(ctx, o)?;
        if ctx.room(names.len()) {
            names.push(name);
        }
    }
    // An erased entry stays as an empty name and a null handle, which DXF
    // leaves out.
    for name in names {
        let h = o.handle_ref()?;
        if h != 0 {
            d.entries.push((name, Handle(h)));
        }
    }
    Ok(d)
}

/// The entries of the dictionary of a handle; empty when it is not one or
/// cannot be read.
fn entries_of(ctx: &mut Ctx<'_, '_>, h: u64) -> Vec<(String, Handle)> {
    let Some(mut o) = ctx.object(h, "dictionary") else {
        return Vec::new();
    };
    if ctx.dwg.type_name(o.type_code).as_deref() != Some("DICTIONARY") {
        return Vec::new();
    }
    dictionary(ctx, &mut o)
        .map(|d| d.entries)
        .unwrap_or_default()
}

/// The columns of an annotative MTEXT of 2018, which it does not hold: its
/// extension dictionary's `AcDbContextDataManager`, then
/// `ACDB_ANNOTATIONSCALES`, names a context data object per annotation
/// scale (ACDB_MTEXTOBJECTCONTEXTDATA_CLASS); the default one's, else the
/// first's. That object, which the spec does not describe beyond its
/// common part (20.4.89, 20.4.71), was found on a corpus drawing's
/// annotative MTEXTs, whose data ends exactly after it and whose values
/// are the converter's DXF of them: BS version (70), B default (290; the
/// spec's "has file to extension dictionary" bit is not there), BL
/// attachment, 3BD X axis, 3BD insertion, BD width, BD defined height, BD
/// extents width and height, BL column type (71), then when not 0: BL
/// count (72), BD width (44), BD gutter (45), B auto height (73), B flow
/// reversed (74), and the heights (46) of dynamic columns without auto
/// height; the scale handle (340) in the handle stream.
pub(crate) fn annotative_columns(ctx: &mut Ctx<'_, '_>, xdictionary: u64) -> Option<MTextColumns> {
    let manager = entries_of(ctx, xdictionary)
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("AcDbContextDataManager"))?
        .1;
    let scales = entries_of(ctx, manager.0)
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("ACDB_ANNOTATIONSCALES"))?
        .1;
    let mut first = None;
    for (_, h) in entries_of(ctx, scales.0) {
        let Some(mut o) = ctx.object(h.0, "context data") else {
            continue;
        };
        if ctx.dwg.type_name(o.type_code).as_deref() != Some("ACDB_MTEXTOBJECTCONTEXTDATA_CLASS") {
            continue;
        }
        match mtext_context(ctx, &mut o) {
            Ok((true, c)) => return c,
            Ok((false, c)) => {
                if first.is_none() {
                    first = Some(c);
                }
            }
            Err(e) => ctx.warn(
                WarningKind::Malformed,
                format!("context data {:X} could not be read: {e}", h.0),
            ),
        }
    }
    first.flatten()
}

/// An ACDB_MTEXTOBJECTCONTEXTDATA_CLASS object: whether it is the default
/// context, and its columns.
fn mtext_context(
    ctx: &mut Ctx<'_, '_>,
    o: &mut Object<'_>,
) -> BitResult<(bool, Option<MTextColumns>)> {
    let b = &mut o.data;
    b.bs()?; // version
    let default = b.b()?;
    b.bl()?; // attachment
    b.bd3()?; // X axis
    b.bd3()?; // insertion
    b.bd()?; // width
    b.bd()?; // defined height
    b.bd()?; // extents width
    b.bd()?; // extents height
    let kind = b.bl()?;
    if kind == 0 {
        return Ok((default, None));
    }
    let mut c = MTextColumns {
        kind: i16::try_from(kind).map_err(|_| BitError::Invalid)?,
        ..MTextColumns::default()
    };
    let n = i64::from(b.bl()?);
    c.count = i16::try_from(n).map_err(|_| BitError::Invalid)?;
    c.width = b.bd()?;
    c.gutter = b.bd()?;
    c.auto_height = b.b()?;
    c.flow_reversed = b.b()?;
    if !c.auto_height && kind == 2 {
        let n = count(n, b.remaining(), 2)?;
        for _ in 0..n {
            let h = o.data.bd()?;
            if ctx.room(c.heights.len()) {
                c.heights.push(h);
            }
        }
    }
    Ok((default, Some(c)))
}

/// LAYOUT (spec 20.4.84): its plot settings, then its own data.
fn layout(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Layout> {
    let v = ctx.version;
    let mut l = Layout {
        handle: Handle(o.handle),
        ..Layout::default()
    };
    let mut p = PlotSettings {
        page_setup_name: string(ctx, o)?,
        plot_device: string(ctx, o)?,
        ..PlotSettings::default()
    };
    let b = &mut o.data;
    p.flags = i32::from(b.bs()?);
    for m in &mut p.margins {
        *m = b.bd()?;
    }
    p.paper_width = b.bd()?;
    p.paper_height = b.bd()?;
    p.paper_size = string(ctx, o)?;
    let b = &mut o.data;
    p.origin = v2(b.bd2()?);
    p.paper_units = b.bs()?;
    p.rotation = b.bs()?;
    p.plot_type = b.bs()?;
    p.window_min = v2(b.bd2()?);
    p.window_max = v2(b.bd2()?);
    if v <= Version::R2000 {
        p.plot_view = string(ctx, o)?;
    }
    let b = &mut o.data;
    p.scale_numerator = b.bd()?;
    p.scale_denominator = b.bd()?;
    p.style_sheet = string(ctx, o)?;
    let b = &mut o.data;
    p.standard_scale_type = b.bs()?;
    p.standard_scale = b.bd()?;
    p.image_origin = v2(b.bd2()?);
    if v >= Version::R2004 {
        b.bs()?; // shade plot mode
        b.bs()?; // shade plot resolution level
        b.bs()?; // shade plot custom DPI
    }
    l.name = string(ctx, o)?;
    let b = &mut o.data;
    l.tab_order = i16::try_from(b.bl()?).unwrap_or(i16::MAX);
    l.flags = b.bs()?;
    // The spec has the UCS origin (13) first and the insertion base (12)
    // after the limits; the other way round: a layout given 12 = (1.5,
    // 2.5, 3.5) and 13 = (7.25, 8.25, 9.25) reads so from the converter's
    // 2000 and 2018 DWGs (experiments/layout).
    l.insertion_base = v3(b.bd3()?);
    l.limits_min = v2(b.rd2()?);
    l.limits_max = v2(b.rd2()?);
    l.ucs_origin = v3(b.bd3()?);
    l.ucs_x_axis = v3(b.bd3()?);
    l.ucs_y_axis = v3(b.bd3()?);
    l.elevation = b.bd()?;
    b.bs()?; // orthographic view type
    l.extents_min = v3(b.bd3()?);
    l.extents_max = v3(b.bd3()?);
    if v >= Version::R2004 {
        // The viewport count, a BL, not the spec's RL: the corpus's R2004
        // LAYOUTs have 2 bits left after the extents (0).
        b.bl()?;
        let view = o.handle_ref()?;
        if view != 0 {
            p.plot_view = ctx.referenced_name(view, "view").unwrap_or_default();
        }
    }
    if v >= Version::R2007 {
        o.handle_ref()?; // visual style
    }
    l.block_record = Handle(o.handle_ref()?);
    l.last_viewport = Handle(o.handle_ref()?);
    l.plot = p;
    Ok(l)
}

/// SORTENTSTABLE (spec 20.4.93): the sort handles in the data stream, the
/// block record and the entities in the handle stream.
fn sort_table(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<SortEntsTable> {
    let n = i64::from(o.data.bl()?);
    // A handle takes at least a byte in both streams.
    let n = count(n, o.data.remaining().min(o.handles.remaining()), 8)?;
    let mut sorts = Vec::new();
    for _ in 0..n {
        let h = o.data.h()?.absolute(o.handle);
        if ctx.room(sorts.len()) {
            sorts.push(h);
        }
    }
    let mut s = SortEntsTable {
        handle: Handle(o.handle),
        block_record: Handle(o.handle_ref()?),
        ..SortEntsTable::default()
    };
    for sort in sorts {
        let e = o.handle_ref()?;
        s.entries.push((Handle(e), Handle(sort)));
    }
    Ok(s)
}

/// IMAGEDEF (spec 20.4.81).
fn image_def(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<ImageDef> {
    let b = &mut o.data;
    b.bl()?; // class version
    let size = v2(b.rd2()?);
    let file_name = string(ctx, o)?;
    let b = &mut o.data;
    Ok(ImageDef {
        handle: Handle(o.handle),
        file_name,
        size,
        loaded: b.b()?,
        resolution_units: i16::from(b.rc()?),
        pixel_size: v2(b.rd2()?),
    })
}

/// PDFDEFINITION, DWFDEFINITION, DGNDEFINITION, which the spec does not
/// describe: the file and the sheet's name, as DXF's groups 1 and 2.
fn underlay_def(
    ctx: &mut Ctx<'_, '_>,
    o: &mut Object<'_>,
    kind: UnderlayKind,
) -> BitResult<UnderlayDef> {
    Ok(UnderlayDef {
        handle: Handle(o.handle),
        kind,
        file_name: string(ctx, o)?,
        name: string(ctx, o)?,
    })
}

/// MLINESTYLE (spec 20.4.73). Its flags' bits are not DXF's: 1 and 2, 32
/// and 64, 512 and 1024 trade places.
fn mline_style(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<MLineStyle> {
    let v = ctx.version;
    let mut s = MLineStyle {
        handle: Handle(o.handle),
        name: string(ctx, o)?,
        description: string(ctx, o)?,
        ..MLineStyle::default()
    };
    let raw = o.data.bs()?;
    let swap = |f: i16, a: i16, b: i16| -> i16 {
        let (x, y) = (f & a != 0, f & b != 0);
        (f & !(a | b)) | if x { b } else { 0 } | if y { a } else { 0 }
    };
    s.flags = swap(swap(swap(raw, 1, 2), 32, 64), 512, 1024);
    s.fill_color = cmc(o, v)?.0;
    let b = &mut o.data;
    s.start_angle = b.bd()?;
    s.end_angle = b.bd()?;
    let n = b.rc()?;
    let mut linetypes = Vec::new();
    for _ in 0..n {
        let offset = o.data.bd()?;
        let color = cmc(o, v)?.0;
        if v < Version::R2018 {
            linetypes.push(Some(o.data.bs()?));
        } else {
            linetypes.push(None);
        }
        s.elements.push(MLineStyleElement {
            offset,
            color,
            linetype: String::new(),
        });
    }
    for (e, index) in s.elements.iter_mut().zip(linetypes) {
        e.linetype = match index {
            Some(i) => ltype_index(ctx, i),
            // DXF names ByLayer and ByBlock in capitals, as the index of
            // earlier versions gives them.
            None => {
                let h = o.handle_ref()?;
                let name = ctx.referenced_name(h, "linetype").unwrap_or_default();
                if name.eq_ignore_ascii_case("BYLAYER") || name.eq_ignore_ascii_case("BYBLOCK") {
                    name.to_ascii_uppercase()
                } else {
                    name
                }
            }
        };
    }
    Ok(s)
}

/// A multiline style element's linetype before R2018: an index, 32767
/// ByLayer, 32766 ByBlock, else the linetype at that place of the LTYPE
/// control's list, from 0 (tests/fixtures/cad/make.py's TRIPLE style: 4
/// for DASHED, 32766 and 32767 for its BYBLOCK and BYLAYER elements, in
/// the converter's R2000 DWG; flags 1043 there for its DXF 531).
fn ltype_index(ctx: &mut Ctx<'_, '_>, index: i16) -> String {
    match index {
        32767 => "BYLAYER".to_string(),
        32766 => "BYBLOCK".to_string(),
        i => usize::try_from(i)
            .ok()
            .and_then(|i| ctx.ltypes.get(i).copied())
            .and_then(|h| ctx.name(h).map(str::to_string))
            .unwrap_or_default(),
    }
}

/// MLEADERSTYLE (spec 20.4.87).
fn mleader_style(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<MLeaderStyle> {
    let v = ctx.version;
    let new_format =
        v >= Version::R2010 || o.eed.iter().any(|e| ctx.is_app(e.app, "ACAD_MLEADERVER"));
    let mut s = MLeaderStyle {
        handle: Handle(o.handle),
        ..MLeaderStyle::default()
    };
    let b = &mut o.data;
    if v >= Version::R2010 {
        b.bs()?; // version
    }
    s.content_type = b.bs()?;
    b.bs()?; // draw multileader order
    b.bs()?; // draw leader order
    b.bl()?; // maximum points
    b.bd()?; // first segment angle
    b.bd()?; // second segment angle
    s.leader_line_type = b.bs()?;
    s.leader_line_color = cmc(o, v)?.0;
    s.leader_linetype = Handle(o.handle_ref()?);
    let b = &mut o.data;
    s.leader_lineweight = LineWeight::from_code(i64::from(b.bl()?));
    s.landing = b.b()?;
    s.landing_gap = b.bd()?;
    s.dogleg = b.b()?;
    s.dogleg_length = b.bd()?;
    string(ctx, o)?; // description
    s.arrowhead = Handle(o.handle_ref()?);
    s.arrowhead_size = o.data.bd()?;
    string(ctx, o)?; // default text
    s.text_style = Handle(o.handle_ref()?);
    let b = &mut o.data;
    s.text_left_attachment = b.bs()?;
    s.text_right_attachment = b.bs()?;
    if new_format {
        s.text_angle_type = b.bs()?;
    }
    s.text_alignment_type = b.bs()?;
    s.text_color = cmc(o, v)?.0;
    let b = &mut o.data;
    s.text_height = b.bd()?;
    s.text_frame = b.b()?;
    if new_format {
        b.b()?; // always align text left
    }
    b.bd()?; // align space
    s.block = Handle(o.handle_ref()?);
    s.block_color = cmc(o, v)?.0;
    let b = &mut o.data;
    s.block_scale = v3(b.bd3()?);
    b.b()?; // block scale enabled
    s.block_rotation = b.bd()?;
    b.b()?; // block rotation enabled
    s.block_connection = b.bs()?;
    s.scale = b.bd()?;
    Ok(s)
}

/// What the DXF reader makes of the objects once read: layouts in tab
/// order with model space first, each layout's block linked to it when its
/// record does not say (R13, R14), multileader styles named by their
/// dictionary entries. And the viewports numbered and stacked as DXF has
/// them, from their layouts.
pub(crate) fn link(d: &mut Drawing) {
    d.layouts.sort_by_key(|l| (!l.is_model(), l.tab_order));
    for l in &d.layouts {
        if let Some(b) = d
            .blocks
            .iter_mut()
            .find(|b| b.record == l.block_record && b.layout.is_null())
        {
            b.layout = l.handle;
        }
    }
    for b in &mut d.blocks {
        let last = d
            .layouts
            .iter()
            .find(|l| l.block_record == b.record)
            .map_or(Handle::NULL, |l| l.last_viewport);
        number_viewports(b, last);
    }
    for s in &mut d.mleader_styles {
        if let Some((n, _)) = d
            .dictionaries
            .iter()
            .flat_map(|x| x.entries.iter())
            .find(|(_, h)| *h == s.handle)
        {
            s.name = n.clone();
        }
    }
}
