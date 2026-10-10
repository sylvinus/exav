//! Block records (ODA spec 20.4.52) with their BLOCK and ENDBLK entities
//! (20.4.6, 20.4.7) and the entities between them, which R13 to 2000 chain
//! from the record's first to its last by each entity's next handle, and
//! the record lists from R2004.

use std::collections::HashSet;

use exav_unpack::dwg::{BitResult, Bits, Object, Version};

use super::entities::{self, Followers};
use super::header::Vars;
use super::tables::{entries, entry_head, lineweight, typed};
use super::Ctx;
use crate::formats::cad::model::*;
use crate::formats::cad::proxy;

const BLOCK_HEADER: u16 = 0x31;
const BLOCK: u16 = 0x04;
const ENDBLK: u16 = 0x05;
const ATTRIB: u16 = 0x02;
const VERTEX_2D: u16 = 0x0A;
const VERTEX_FACE: u16 = 0x0E;

/// What a block record says, before its entities are read.
struct Record {
    block: Block,
    /// R13 to R2000: the first and last entity of the chain.
    first: u64,
    last: u64,
    /// R2004 on: the entities, in order.
    owned: Vec<u64>,
}

/// Every block record the block control lists, model and paper space
/// first, as DXF's BLOCK_RECORD table has them.
pub(crate) fn read(ctx: &mut Ctx<'_, '_>, vars: &Vars) -> Vec<Block> {
    let mut handles = entries(ctx, vars.block_control, "the BLOCK control", 2);
    // The control lists model and paper space last.
    for space in [vars.paper_space, vars.model_space] {
        if let Some(i) = handles.iter().position(|h| *h == space) {
            let h = handles.remove(i);
            handles.insert(0, h);
        }
    }
    // Every block's name first: entities name blocks by their record.
    let mut records = Vec::new();
    for h in handles {
        let Some(mut o) = typed(ctx, h, BLOCK_HEADER, "BLOCK_RECORD") else {
            continue;
        };
        let mut rec = match record(ctx, &mut o) {
            Ok(r) => r,
            Err(e) => {
                ctx.warn(
                    WarningKind::Malformed,
                    format!("BLOCK_RECORD {h:X} could not be read: {e}"),
                );
                continue;
            }
        };
        let block = &mut rec.block;
        if let Some(mut o) = typed(ctx, block.handle.0, BLOCK, "BLOCK") {
            if let Some(layer) = o.entity.as_ref().map(|e| e.layer) {
                block.layer = ctx
                    .referenced_name(layer, "layer")
                    .unwrap_or_else(|| "0".into());
            }
            // The record keeps an anonymous block's name without its
            // number (`*D`, `*Paper_Space`), the BLOCK entity with it.
            if let Ok(raw) = o.tv() {
                let full = canonical_name(ctx.string(raw));
                if numbered(&block.name, &full) {
                    block.name = full;
                }
            }
        }
        ctx.names.insert(h, block.name.clone());
        if block.end_handle.0 != 0 {
            let _ = typed(ctx, block.end_handle.0, ENDBLK, "ENDBLK");
        }
        records.push(rec);
    }
    let mut out = Vec::new();
    for rec in records {
        let mut block = rec.block;
        if rec.first != 0 {
            block.entities = chain(ctx, vars, &block, rec.first, rec.last);
        }
        if !rec.owned.is_empty() {
            block.entities = owned(ctx, vars, &block, &rec.owned);
        }
        if block.is_paper_space() {
            for e in &mut block.entities {
                e.paper_space = true;
                if let EntityKind::Insert(i) = &mut e.kind {
                    for a in &mut i.attributes {
                        a.paper_space = true;
                    }
                }
            }
        }
        // DXF's tile mode of an OLE2FRAME: 0 in model space, 1 elsewhere
        // (paper space, and a block, where the converter writes 1 too).
        let model = block.is_model_space();
        for e in &mut block.entities {
            if let EntityKind::Ole2Frame(f) = &mut e.kind {
                f.tile_mode = i16::from(!model);
            }
        }
        out.push(block);
    }
    out
}

/// A layout's viewports have no number or status in DWG (spec 20.4.38),
/// which DXF has (69, 68). As the converter writes them: an on viewport's
/// number is its place among the layout's viewports from 1 and its status
/// its place in the stack, the layout's last active viewport first, then
/// the others in order; one whose off flag (0x20000) is set has number -1
/// (but the first, the layout's overall viewport, 1) and status 0
/// (experiments/stacking: four viewports, the fourth last
/// active, give 68 = 2, 3, 4, 1 and 69 = 1, 2, 3, 4, in the current layout
/// and another alike; the third off gives 69 = -1, 68 absent, and the
/// fourth 68 = 3, 69 = 4).
pub(crate) fn number_viewports(block: &mut Block, last_active: Handle) {
    let on = |v: &Viewport| v.flags & 0x20000 == 0;
    let active_on = block
        .entities
        .iter()
        .any(|e| e.handle == last_active && matches!(&e.kind, EntityKind::Viewport(v) if on(v)));
    let (mut place, mut stack): (i16, i16) = (0, i16::from(active_on));
    for e in &mut block.entities {
        let handle = e.handle;
        if let EntityKind::Viewport(v) = &mut e.kind {
            place = place.saturating_add(1);
            if !on(v) {
                // The layout's overall viewport keeps its number when off
                // (experiments/vp-off: the converter's DXF has 69 = 1).
                v.id = if place == 1 { 1 } else { -1 };
                v.status = 0;
            } else if active_on && handle == last_active {
                v.id = place;
                v.status = 1;
            } else {
                stack = stack.saturating_add(1);
                v.id = place;
                v.status = stack;
            }
        }
    }
}

/// Whether `full` is `base` followed by a number, or `base` is empty.
fn numbered(base: &str, full: &str) -> bool {
    match full.get(..base.len()) {
        Some(head) if head.eq_ignore_ascii_case(base) => {
            let rest = full.get(base.len()..).unwrap_or("");
            base.is_empty() || (!rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
        }
        _ => false,
    }
}

/// R13 to R14 name the spaces in capitals; some later files keep R12's
/// `$MODEL_SPACE` and `$PAPER_SPACE` (an AutoCAD 2024 drawing of the local
/// corpus, `*Model_Space` in the converter's DXF), which the DXF reader
/// reads as the spaces too.
fn canonical_name(name: String) -> String {
    if name.eq_ignore_ascii_case(MODEL_SPACE) || name.eq_ignore_ascii_case("$MODEL_SPACE") {
        MODEL_SPACE.to_string()
    } else if name.eq_ignore_ascii_case(PAPER_SPACE) || name.eq_ignore_ascii_case("$PAPER_SPACE") {
        PAPER_SPACE.to_string()
    } else {
        name
    }
}

fn record(ctx: &mut Ctx<'_, '_>, o: &mut Object<'_>) -> BitResult<Record> {
    let v = ctx.version;
    let (name, dependent) = entry_head(ctx, o)?;
    let name = canonical_name(name);
    let anonymous = o.data.b()?;
    let has_attributes = o.data.b()?;
    let xref = o.data.b()?;
    let overlay = o.data.b()?;
    let flags = i16::from(anonymous)
        | i16::from(has_attributes) << 1
        | i16::from(xref) << 2
        | i16::from(overlay) << 3
        | dependent;
    if v >= Version::R2000 {
        // Loaded bit: not group 70's 32 (resolved), which says whether the
        // reader found the external file; the converter writes 4 alone for
        // unresolvable xrefs whose bit is 0.
        o.data.b()?;
    }
    // The owned object count, which the spec gives every R2004 record, is
    // there only when the block is not an xref, as the R13 to R2000 first
    // and last entity handles: two unresolvable xrefs of a test corpus
    // drawing have the same bits after their name in its R2000 and R2004
    // conversions, and read with a count their base point is (0, 0, 1),
    // their path empty, and the record runs past its end.
    let mut owned = 0u64;
    if v >= Version::R2004 && !xref && !overlay {
        owned = u64::try_from(o.data.bl()?).unwrap_or(0);
    }
    let base = o.data.bd3()?;
    let path = o.tv()?;
    let mut block = Block {
        record: Handle(o.handle),
        name,
        flags,
        base_point: Vec3::new(base[0], base[1], base[2]),
        xref_path: ctx.string(path),
        explodable: true,
        scalable: true,
        ..Block::default()
    };
    let mut inserts = 0u64;
    if v >= Version::R2000 {
        // One non-zero byte per INSERT handle at the end, then a zero.
        while o.data.rc()? != 0 {
            inserts += 1;
        }
        let description = o.tv()?;
        block.description = ctx.string(description);
        let preview = u64::try_from(o.data.bl()?).unwrap_or(u64::MAX);
        o.data.skip(preview.saturating_mul(8))?;
    }
    if v >= Version::R2007 {
        block.insert_units = o.data.bs()?;
        block.explodable = o.data.b()?;
        block.scalable = o.data.rc()? != 0;
    }

    o.handle_ref()?; // NULL
    block.handle = Handle(o.handle_ref()?);
    let (mut first, mut last) = (0, 0);
    if v <= Version::R2000 && !xref && !overlay {
        first = o.handle_ref()?;
        last = o.handle_ref()?;
    }
    let mut entities = Vec::new();
    if v >= Version::R2004 {
        // A handle takes at least a byte: the count cannot be more.
        let n = owned.min(o.handles.remaining() / 8);
        entities.reserve(n as usize);
        for _ in 0..n {
            entities.push(o.handle_ref()?);
        }
    }
    block.end_handle = Handle(o.handle_ref()?);
    if v >= Version::R2000 {
        let n = inserts.min(o.handles.remaining() / 8);
        for _ in 0..n {
            o.handle_ref()?;
        }
        block.layout = Handle(o.handle_ref()?);
    }
    Ok(Record {
        block,
        first,
        last,
        owned: entities,
    })
}

/// The entities a block record of R2004 on lists (spec 20.4.52).
fn owned(ctx: &mut Ctx<'_, '_>, vars: &Vars, block: &Block, handles: &[u64]) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for &h in handles {
        if !seen.insert(h) {
            ctx.warn(
                WarningKind::Malformed,
                format!("block {} lists entity {h:X} twice", block.name),
            );
            continue;
        }
        let Some(o) = ctx.object(h, "entity") else {
            continue;
        };
        if o.entity.is_none() {
            ctx.warn(
                WarningKind::Malformed,
                format!("{h:X} in block {} is not an entity", block.name),
            );
            continue;
        }
        if !ctx.count_entity() {
            break;
        }
        out.push(entity(ctx, vars, o, block.record));
    }
    out
}

/// The entities from `first` to `last` by their next handles.
fn chain(ctx: &mut Ctx<'_, '_>, vars: &Vars, block: &Block, first: u64, last: u64) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut at = first;
    loop {
        if !seen.insert(at) {
            ctx.warn(
                WarningKind::Malformed,
                format!("the entities of block {} loop at {at:X}", block.name),
            );
            break;
        }
        let Some(o) = ctx.object(at, "entity") else {
            break;
        };
        if o.entity.is_none() {
            ctx.warn(
                WarningKind::Malformed,
                format!("{at:X} in block {} is not an entity", block.name),
            );
            break;
        }
        let next = o.entity.as_ref().map_or(0, |e| e.next);
        if ctx.count_entity() {
            out.push(entity(ctx, vars, o, block.record));
        } else {
            break;
        }
        if at == last || next == 0 {
            break;
        }
        at = next;
    }
    out
}

/// An entity: its common data (spec 20.4.1, 20.4.2), its type's own, and
/// the entities it owns (an INSERT's ATTRIBs, a POLYLINE's VERTEXes). One
/// whose own data does not read is kept with its common data, as
/// [`EntityKind::Unknown`] of its type.
pub(crate) fn entity(
    ctx: &mut Ctx<'_, '_>,
    vars: &Vars,
    mut o: Object<'_>,
    record: Handle,
) -> Entity {
    let mut e = common(ctx, vars, &o, record);
    let EntityKind::Unknown(Unknown { type_name, .. }) = &e.kind else {
        return e;
    };
    if o.entity.is_none() {
        return e;
    }
    let type_name = type_name.clone();
    match entities::read(ctx, &mut o, &type_name) {
        Ok(Some((kind, follow))) => {
            e.kind = kind;
            match &mut e.kind {
                EntityKind::Insert(i) => {
                    i.attributes = attributes(ctx, vars, &e.handle, follow, record);
                    // An attribute is where its insert is.
                    for a in &mut i.attributes {
                        a.paper_space |= e.paper_space;
                    }
                }
                EntityKind::Polyline(p) => p.vertices = vertices(ctx, e.handle, follow),
                _ => {}
            }
        }
        Ok(None) => {}
        Err(err) => ctx.warn(
            WarningKind::Malformed,
            format!("{type_name} {:X} could not be read: {err}", o.handle),
        ),
    }
    if let EntityKind::Unknown(u) = &mut e.kind {
        u.graphics = graphics(ctx, &o);
    }
    e
}

/// The proxy graphics of an entity's common data (spec 20.4.1, 29).
fn graphics(ctx: &mut Ctx<'_, '_>, o: &Object<'_>) -> Option<Box<ProxyGraphics>> {
    let (at, len) = o.entity.as_ref()?.graphics?;
    let end = at.checked_add(len.checked_mul(8)?)?;
    let bytes = Bits::window(ctx.dwg.objects(), at, end)
        .bytes(usize::try_from(len).ok()?)
        .ok()?;
    let code_page = ctx.code_page;
    let (g, problem) = proxy::read(
        &bytes,
        &proxy::Reading {
            version: ctx.version,
            decode: &|b: &[u8]| code_page.decode(b),
            max_items: ctx.limits.max_items,
            max_string_bytes: ctx.limits.max_string_bytes,
        },
    );
    if let Some(p) = problem {
        ctx.warn(WarningKind::Malformed, format!("{:X}: {p}", o.handle));
    }
    Some(Box::new(g))
}

/// The handles of the entities an entity owns, in order: a chain from the
/// first to the last by their next handles (R13 to R2000), or its list.
fn follower_handles(ctx: &mut Ctx<'_, '_>, owner: Handle, f: Followers) -> Vec<u64> {
    let (first, last) = match f {
        Followers::None => return Vec::new(),
        Followers::Owned(list) => return list,
        Followers::Chain(first, last) => (first, last),
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut at = first;
    while at != 0 {
        if !seen.insert(at) {
            ctx.warn(
                WarningKind::Malformed,
                format!("the entities {:X} owns loop at {at:X}", owner.0),
            );
            break;
        }
        if !ctx.room(out.len()) {
            break;
        }
        out.push(at);
        if at == last {
            break;
        }
        at = match ctx.dwg.object(at) {
            Some(Ok(o)) => o.entity.map_or(0, |e| e.next),
            _ => 0,
        };
    }
    out
}

/// An INSERT's ATTRIBs.
fn attributes(
    ctx: &mut Ctx<'_, '_>,
    vars: &Vars,
    owner: &Handle,
    f: Followers,
    record: Handle,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for h in follower_handles(ctx, *owner, f) {
        let Some(o) = ctx.object(h, "attribute") else {
            continue;
        };
        if o.type_code != ATTRIB {
            ctx.warn(
                WarningKind::Malformed,
                format!(
                    "{h:X}, an attribute of {:X}, is of type {}",
                    owner.0, o.type_code
                ),
            );
            continue;
        }
        if !ctx.count_entity() {
            break;
        }
        let a = entity(ctx, vars, o, record);
        if ctx.room(out.len()) {
            out.push(a);
        }
    }
    out
}

/// A POLYLINE's VERTEXes.
fn vertices(ctx: &mut Ctx<'_, '_>, owner: Handle, f: Followers) -> Vec<Vertex> {
    let mut out = Vec::new();
    for h in follower_handles(ctx, owner, f) {
        let Some(mut o) = ctx.object(h, "vertex") else {
            continue;
        };
        if !(VERTEX_2D..=VERTEX_FACE).contains(&o.type_code) {
            ctx.warn(
                WarningKind::Malformed,
                format!(
                    "{h:X}, a vertex of {:X}, is of type {}",
                    owner.0, o.type_code
                ),
            );
            continue;
        }
        match entities::vertex(ctx, &mut o) {
            Ok(v) => {
                if ctx.room(out.len()) {
                    out.push(v);
                }
            }
            Err(e) => ctx.warn(
                WarningKind::Malformed,
                format!("VERTEX {h:X} could not be read: {e}"),
            ),
        }
    }
    out
}

/// An entity's common data (spec 20.4.1, 20.4.2) as the model's.
fn common(ctx: &mut Ctx<'_, '_>, vars: &Vars, o: &Object<'_>, record: Handle) -> Entity {
    let type_name = match ctx.dwg.type_name(o.type_code) {
        // The class names of underlays; DXF's record names.
        Some(n) if n == "PDFREFERENCE" => "PDFUNDERLAY".to_string(),
        Some(n) if n == "DWFREFERENCE" => "DWFUNDERLAY".to_string(),
        Some(n) if n == "DGNREFERENCE" => "DGNUNDERLAY".to_string(),
        Some(n) => n,
        None => format!("type {}", o.type_code),
    };
    let mut e = Entity {
        handle: Handle(o.handle),
        kind: EntityKind::Unknown(Unknown {
            type_name,
            graphics: None,
        }),
        ..Entity::default()
    };
    let Some(c) = &o.entity else {
        return e;
    };
    e.owner = if c.mode == 0 { Handle(o.owner) } else { record };
    e.paper_space = c.mode == 1;
    // A layer that is not in the file: layer 0, as the model's default.
    e.layer = ctx
        .referenced_name(c.layer, "layer")
        .unwrap_or_else(|| "0".into());
    let mut named = |h: u64, fallback: &str| {
        ctx.referenced_name(h, "linetype")
            .unwrap_or_else(|| fallback.into())
    };
    e.linetype = match c.linetype_flags {
        0 => "BYLAYER".to_string(),
        1 => named(vars.byblock, "BYBLOCK"),
        2 => named(vars.continuous, "Continuous"),
        _ => named(c.linetype, "BYLAYER"),
    };
    e.color = match c.color.rgb {
        Some(rgb) => Color::from_rgb24(i64::from(rgb)),
        None => Color::from_aci(i64::from(c.color.index)),
    };
    if ctx.version >= Version::R2000 {
        e.lineweight = lineweight(c.lineweight);
    }
    if let Some(t) = c.color.transparency {
        e.transparency = Transparency::from_code(i64::from(t));
    }
    e.linetype_scale = c.linetype_scale;
    e.invisible = c.invisible;
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_spaces_have_their_names_whatever_the_release_wrote() {
        for (written, read) in [
            ("*MODEL_SPACE", MODEL_SPACE),
            ("$MODEL_SPACE", MODEL_SPACE),
            ("*PAPER_SPACE", PAPER_SPACE),
            ("$Paper_Space", PAPER_SPACE),
            ("$OTHER", "$OTHER"),
        ] {
            assert_eq!(canonical_name(written.to_string()), read);
        }
    }
}
