//! Sections into one drawing: block records joined to their BLOCK
//! definitions, the ENTITIES section put into model or paper space, and
//! what an R12 file lacks (block records, layouts, handles) made up.

use std::collections::{HashMap, HashSet};

use super::{Ctx, Raw};
use crate::formats::cad::model::*;

/// Handles for table entries that have none (an R12 file saved without
/// handles), above any the file uses.
pub(crate) fn number_table_entries(raw: &mut Raw) {
    let mut next = table_max(raw).max(raw.header.handle_seed.0);
    let mut fresh = || {
        next = next.saturating_add(1);
        Handle(next)
    };
    for h in raw
        .layers
        .iter_mut()
        .map(|l| &mut l.handle)
        .chain(raw.linetypes.iter_mut().map(|l| &mut l.handle))
        .chain(raw.text_styles.iter_mut().map(|s| &mut s.handle))
        .chain(raw.dim_styles.iter_mut().map(|s| &mut s.handle))
        .chain(raw.vports.iter_mut().map(|v| &mut v.handle))
        .chain(raw.block_records.iter_mut().map(|b| &mut b.record))
    {
        if h.is_null() {
            *h = fresh();
        }
    }
}

fn table_max(raw: &Raw) -> u64 {
    raw.layers
        .iter()
        .map(|l| l.handle.0)
        .chain(raw.linetypes.iter().map(|l| l.handle.0))
        .chain(raw.text_styles.iter().map(|s| s.handle.0))
        .chain(raw.dim_styles.iter().map(|s| s.handle.0))
        .chain(raw.vports.iter().map(|v| v.handle.0))
        .chain(raw.block_records.iter().map(|b| b.record.0))
        .max()
        .unwrap_or(0)
}

/// R12 names model and paper space `$MODEL_SPACE` and `$PAPER_SPACE`.
fn canonical_name(name: &str) -> Option<&'static str> {
    if name.eq_ignore_ascii_case("$MODEL_SPACE") || name.eq_ignore_ascii_case(MODEL_SPACE) {
        Some(MODEL_SPACE)
    } else if name.eq_ignore_ascii_case("$PAPER_SPACE") || name.eq_ignore_ascii_case(PAPER_SPACE) {
        Some(PAPER_SPACE)
    } else {
        None
    }
}

fn entity_max(e: &Entity) -> u64 {
    let own = e.handle.0;
    match &e.kind {
        EntityKind::Insert(i) => i.attributes.iter().map(entity_max).fold(own, u64::max),
        EntityKind::Polyline(p) => p.vertices.iter().map(|v| v.handle.0).fold(own, u64::max),
        _ => own,
    }
}

fn number_entity(e: &mut Entity, owner: Handle, fresh: &mut impl FnMut() -> Handle) {
    if e.handle.is_null() {
        e.handle = fresh();
    }
    if e.owner.is_null() {
        e.owner = owner;
    }
    let me = e.handle;
    match &mut e.kind {
        EntityKind::Insert(i) => {
            for a in &mut i.attributes {
                number_entity(a, me, fresh);
            }
        }
        EntityKind::Polyline(p) => {
            for v in &mut p.vertices {
                if v.handle.is_null() {
                    v.handle = fresh();
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn build(mut raw: Raw, ctx: Ctx<'_>) -> Drawing {
    // A file without a TABLES section has not numbered its records yet.
    number_table_entries(&mut raw);

    for b in raw.block_records.iter_mut().chain(raw.blocks.iter_mut()) {
        if let Some(n) = canonical_name(&b.name) {
            b.name = n.to_string();
        }
    }

    // Records in table order, each joined to its definition.
    let mut blocks: Vec<Block> = std::mem::take(&mut raw.block_records);
    let mut filled = vec![false; blocks.len()];
    let mut record_at: HashMap<Handle, usize> = HashMap::new();
    let mut name_at: HashMap<String, usize> = HashMap::new();
    for (i, b) in blocks.iter().enumerate() {
        record_at.entry(b.record).or_insert(i);
        name_at.entry(b.name.to_ascii_uppercase()).or_insert(i);
    }
    for def in std::mem::take(&mut raw.blocks) {
        let by_owner = (!def.record.is_null())
            .then(|| record_at.get(&def.record).copied())
            .flatten();
        let at = by_owner.or_else(|| name_at.get(&def.name.to_ascii_uppercase()).copied());
        match at {
            Some(i) if !filled.get(i).copied().unwrap_or(true) => {
                if let (Some(b), Some(f)) = (blocks.get_mut(i), filled.get_mut(i)) {
                    *f = true;
                    let record = b.record;
                    let (layout, units, explodable, scalable) =
                        (b.layout, b.insert_units, b.explodable, b.scalable);
                    let name = if b.name.is_empty() {
                        def.name.clone()
                    } else {
                        b.name.clone()
                    };
                    *b = Block {
                        record,
                        name,
                        layout,
                        insert_units: units,
                        explodable,
                        scalable,
                        ..def
                    };
                }
            }
            _ => {
                // A definition without a record (R12), or a second one of
                // the same name: a block of its own.
                let record = if def.record.is_null() || record_at.contains_key(&def.record) {
                    Handle::NULL
                } else {
                    def.record
                };
                if !record.is_null() {
                    record_at.insert(record, blocks.len());
                }
                blocks.push(Block { record, ..def });
                filled.push(true);
            }
        }
    }

    // Model space always exists; paper space when the ENTITIES section has
    // something for it.
    let records: HashSet<Handle> = blocks
        .iter()
        .map(|b| b.record)
        .filter(|r| !r.is_null())
        .collect();
    let needs_paper = raw
        .entities
        .iter()
        .any(|e| e.paper_space && !records.contains(&e.owner));
    if !blocks.iter().any(|b| b.is_model_space()) {
        blocks.insert(
            0,
            Block {
                name: MODEL_SPACE.to_string(),
                explodable: true,
                scalable: true,
                ..Block::default()
            },
        );
    }
    if needs_paper
        && !blocks
            .iter()
            .any(|b| b.name.eq_ignore_ascii_case(PAPER_SPACE))
    {
        blocks.push(Block {
            name: PAPER_SPACE.to_string(),
            explodable: true,
            scalable: true,
            ..Block::default()
        });
    }

    // Handles for whatever has none, above every handle in the file.
    let mut max = raw.header.handle_seed.0.max(table_max(&raw));
    for b in &blocks {
        max = max.max(b.record.0).max(b.handle.0).max(b.end_handle.0);
        for e in &b.entities {
            max = max.max(entity_max(e));
        }
    }
    for e in &raw.entities {
        max = max.max(entity_max(e));
    }
    let mut next = max;
    let mut fresh = || {
        next = next.saturating_add(1);
        Handle(next)
    };
    for b in &mut blocks {
        if b.record.is_null() {
            b.record = fresh();
        }
        if b.handle.is_null() {
            b.handle = fresh();
        }
        if b.end_handle.is_null() {
            b.end_handle = fresh();
        }
        let owner = b.record;
        for e in &mut b.entities {
            number_entity(e, Handle::NULL, &mut fresh);
            if e.owner.is_null() {
                e.owner = owner;
            }
        }
    }

    // The ENTITIES section into the block each entity names as its owner,
    // or model or paper space by its paper-space flag.
    let mut by_record: HashMap<Handle, usize> = HashMap::new();
    for (i, b) in blocks.iter().enumerate() {
        by_record.entry(b.record).or_insert(i);
    }
    let model = blocks.iter().position(|b| b.is_model_space());
    let paper = blocks
        .iter()
        .position(|b| b.name.eq_ignore_ascii_case(PAPER_SPACE));
    for mut e in std::mem::take(&mut raw.entities) {
        let at = by_record
            .get(&e.owner)
            .copied()
            .or(if e.paper_space { paper } else { model });
        let Some(block) = at.and_then(|i| blocks.get_mut(i)) else {
            continue;
        };
        number_entity(&mut e, block.record, &mut fresh);
        block.entities.push(e);
    }
    // Writers leave group 67 out in the blocks of inactive layouts, an
    // INSERT's attributes included.
    for b in blocks.iter_mut().filter(|b| b.is_paper_space()) {
        for e in &mut b.entities {
            e.paper_space = true;
            if let EntityKind::Insert(i) = &mut e.kind {
                for a in &mut i.attributes {
                    a.paper_space = true;
                }
            }
        }
    }

    let mut layouts = std::mem::take(&mut raw.layouts);
    if layouts.is_empty() {
        let h = &raw.header;
        if let Some(m) = blocks.iter().find(|b| b.is_model_space()) {
            layouts.push(Layout {
                handle: fresh(),
                name: "Model".to_string(),
                limits_min: h.limmin,
                limits_max: h.limmax,
                insertion_base: h.insbase,
                extents_min: h.extmin,
                extents_max: h.extmax,
                block_record: m.record,
                ..Layout::default()
            });
        }
        if let Some(p) = blocks
            .iter()
            .find(|b| b.name.eq_ignore_ascii_case(PAPER_SPACE))
        {
            layouts.push(Layout {
                handle: fresh(),
                name: "Layout1".to_string(),
                tab_order: 1,
                limits_min: h.plimmin,
                limits_max: h.plimmax,
                insertion_base: h.pinsbase,
                extents_min: h.pextmin,
                extents_max: h.pextmax,
                block_record: p.record,
                ..Layout::default()
            });
        }
    }
    // Model first, then the tab order; stable for equal orders.
    layouts.sort_by_key(|l| (!l.is_model(), l.tab_order));
    for l in &layouts {
        if let Some(b) = blocks
            .iter_mut()
            .find(|b| b.record == l.block_record && b.layout.is_null())
        {
            b.layout = l.handle;
        }
    }

    // A multileader style's name is its dictionary entry's.
    for s in &mut raw.mleader_styles {
        if !s.name.is_empty() {
            continue;
        }
        if let Some((n, _)) = raw
            .dictionaries
            .iter()
            .flat_map(|d| d.entries.iter())
            .find(|(_, h)| *h == s.handle)
        {
            s.name = n.clone();
        }
    }

    Drawing {
        header: raw.header,
        layers: raw.layers,
        linetypes: raw.linetypes,
        text_styles: raw.text_styles,
        dim_styles: raw.dim_styles,
        vports: raw.vports,
        blocks,
        layouts,
        dictionaries: raw.dictionaries,
        sort_tables: raw.sort_tables,
        image_defs: raw.image_defs,
        underlay_defs: raw.underlay_defs,
        mline_styles: raw.mline_styles,
        mleader_styles: raw.mleader_styles,
        preview: raw.preview,
        warnings: ctx.warnings,
        warnings_dropped: ctx.warnings_dropped,
    }
}
