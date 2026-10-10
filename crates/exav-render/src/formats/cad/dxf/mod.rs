//! The DXF reader: exav-unpack's records into sections, sections into a
//! [`Drawing`].

mod build;
mod entities;
mod header;
mod objects;
mod tables;
#[cfg(test)]
mod tests;

use std::borrow::Cow;

use exav_unpack::dxf::{looks_like_dxf, Decoder, Parts, Record, Records, Stop, Tag, Value};

use super::model::*;
use super::{Error, Limits};

/// A DXF string with its control characters back (DXF reference, "ASCII
/// Control Characters in DXF Files"): AutoCAD writes one as a caret and the
/// letter 64 above it (`^J` for a line feed, `^I` for a tab), and a caret
/// as caret, space. A caret before anything else is left as written.
pub(crate) fn carets(s: &str) -> Cow<'_, str> {
    if !s.contains('^') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '^' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some(' ') => {
                chars.next();
                out.push('^');
            }
            Some(n @ '@'..='_') => {
                chars.next();
                out.push(char::from(n as u8 - 0x40));
            }
            _ => out.push('^'),
        }
    }
    Cow::Owned(out)
}

/// Reader state shared by the section parsers.
pub(crate) struct Ctx<'l> {
    pub limits: &'l Limits,
    pub decoder: Decoder,
    /// The drawing's code page also from 2007 on, for the strings of proxy
    /// graphics.
    pub code_page: Decoder,
    pub version: Version,
    pub warnings: Vec<Warning>,
    pub warnings_dropped: usize,
    /// Entities read so far, attributes included.
    pub entities: usize,
    entity_limit_hit: bool,
    /// The item limit was reported for the record being parsed.
    item_limit_hit: bool,
    /// Layer names and handles, once the tables are read: R12 viewports
    /// name their frozen layers.
    pub layer_handles: Vec<(String, Handle)>,
}

impl<'l> Ctx<'l> {
    fn new(limits: &'l Limits) -> Ctx<'l> {
        Ctx {
            limits,
            decoder: Decoder::GUESS,
            code_page: Decoder::GUESS,
            version: Version::R12,
            warnings: Vec::new(),
            warnings_dropped: 0,
            entities: 0,
            entity_limit_hit: false,
            item_limit_hit: false,
            layer_handles: Vec::new(),
        }
    }

    pub fn warn(&mut self, kind: WarningKind, message: impl Into<String>) {
        if self.warnings.len() < self.limits.max_warnings {
            self.warnings.push(Warning {
                kind,
                message: message.into(),
            });
        } else {
            self.warnings_dropped = self.warnings_dropped.saturating_add(1);
        }
    }

    /// A string value, decoded, its carets undone ([`carets`]) and cut to
    /// the string limit.
    pub fn text(&mut self, tag: &Tag<'_>) -> String {
        let s = self.text_as_written(tag);
        match carets(&s) {
            Cow::Owned(o) => o,
            Cow::Borrowed(_) => s,
        }
    }

    /// [`Ctx::text`] with the carets left in, for a string read in chunks.
    fn text_as_written(&mut self, tag: &Tag<'_>) -> String {
        let bytes = match tag.value {
            Value::Text(_) | Value::Bytes(_) => tag.bytes(),
            // A binary file's number where a string belongs.
            Value::Int(v) => return v.to_string(),
            Value::Double(v) => return v.to_string(),
        };
        let max = self.limits.max_string_bytes;
        let mut s = self.decoder.decode(bytes.get(..max).unwrap_or(bytes));
        if bytes.len() > max {
            self.warn(
                WarningKind::LimitReached,
                format!("a string of {} bytes was cut to {max}", bytes.len()),
            );
            let mut end = max.min(s.len());
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            s.truncate(end);
        }
        s
    }

    /// Append to a string already read (MTEXT chunks), within the limit,
    /// carets left in: a chunk may end inside one ([`carets`] the whole).
    pub fn append_text(&mut self, into: &mut String, tag: &Tag<'_>) {
        let more = self.text_as_written(tag);
        let room = self.limits.max_string_bytes.saturating_sub(into.len());
        if more.len() <= room {
            into.push_str(&more);
            return;
        }
        let mut end = room;
        while !more.is_char_boundary(end) {
            end -= 1;
        }
        into.push_str(more.get(..end).unwrap_or(""));
        self.warn(
            WarningKind::LimitReached,
            "a text was cut to the string limit",
        );
    }

    /// Whether a list of `len` items may take one more.
    pub fn room(&mut self, len: usize) -> bool {
        if len < self.limits.max_items {
            return true;
        }
        if !self.item_limit_hit {
            self.item_limit_hit = true;
            self.warn(
                WarningKind::LimitReached,
                format!("an entity or object had more than {} items", len),
            );
        }
        false
    }

    /// Count one entity; false once the limit is reached.
    pub fn count_entity(&mut self) -> bool {
        if self.entities < self.limits.max_entities {
            self.entities += 1;
            return true;
        }
        if !self.entity_limit_hit {
            self.entity_limit_hit = true;
            self.warn(
                WarningKind::LimitReached,
                format!("entities past the first {} were dropped", self.entities),
            );
        }
        false
    }

    fn start_record(&mut self) {
        self.item_limit_hit = false;
    }
}

/// What the sections hold before blocks and entities are put together.
#[derive(Default)]
pub(crate) struct Raw {
    pub header: Header,
    pub has_header: bool,
    pub layers: Vec<Layer>,
    pub linetypes: Vec<Linetype>,
    pub text_styles: Vec<TextStyle>,
    pub dim_styles: Vec<DimStyle>,
    pub vports: Vec<VPort>,
    /// BLOCK_RECORD entries: handle, name, layout, units, explodable,
    /// scalable.
    pub block_records: Vec<Block>,
    /// BLOCK definitions with their entities, and the owner handle each
    /// BLOCK gave.
    pub blocks: Vec<Block>,
    /// The ENTITIES section.
    pub entities: Vec<Entity>,
    pub layouts: Vec<Layout>,
    pub dictionaries: Vec<Dictionary>,
    pub sort_tables: Vec<SortEntsTable>,
    pub image_defs: Vec<ImageDef>,
    pub underlay_defs: Vec<UnderlayDef>,
    pub mline_styles: Vec<MLineStyle>,
    pub mleader_styles: Vec<MLeaderStyle>,
    pub preview: Option<Preview>,
}

struct Reader<'a, 'l> {
    records: Records<'a>,
    ctx: Ctx<'l>,
    raw: Raw,
}

pub(crate) fn read(bytes: &[u8], limits: &Limits) -> Result<Drawing, Error> {
    if !looks_like_dxf(bytes) {
        return Err(Error::NotDxf);
    }
    let mut r = Reader {
        records: Records::new(bytes),
        ctx: Ctx::new(limits),
        raw: Raw::default(),
    };
    let mut sections = 0;
    let mut ended = false;
    while let Some(rec) = r.records.next() {
        if rec.is("EOF") {
            ended = true;
            break;
        }
        if !rec.is("SECTION") {
            r.ctx.warn(
                WarningKind::Malformed,
                format!("{} outside any section, skipped", rec.type_name()),
            );
            continue;
        }
        sections += 1;
        r.section(rec);
    }
    if sections == 0 {
        return Err(Error::Damaged("no section".to_string()));
    }
    match r.records.stop().cloned() {
        Some(Stop::BadCode(at)) => r.ctx.warn(
            WarningKind::Malformed,
            format!("reading stopped at byte {at}: not a group code"),
        ),
        Some(Stop::Truncated) => r.ctx.warn(
            WarningKind::Truncated,
            format!("the file is cut short at byte {}", r.records.offset()),
        ),
        None if !ended => r
            .ctx
            .warn(WarningKind::Truncated, "the file ends without EOF"),
        None => {}
    }
    Ok(build::build(r.raw, r.ctx))
}

impl<'a> Reader<'a, '_> {
    fn section(&mut self, rec: Record<'a>) {
        let name = rec
            .tags
            .iter()
            .find(|t| t.code == 2)
            .map(|t| {
                String::from_utf8_lossy(t.bytes())
                    .trim()
                    .to_ascii_uppercase()
            })
            .unwrap_or_default();
        match name.as_str() {
            "HEADER" => {
                header::read(&rec.tags, &mut self.raw, &mut self.ctx);
                self.skip_to_endsec();
            }
            "TABLES" => self.tables(),
            "BLOCKS" => self.blocks(),
            "ENTITIES" => {
                let mut out = std::mem::take(&mut self.raw.entities);
                self.entities_until_end(&mut out);
                self.raw.entities = out;
                self.skip_to_endsec();
            }
            "OBJECTS" => self.objects(),
            "THUMBNAILIMAGE" => {
                self.raw.preview = super::preview::from_dxf(&rec.tags);
                self.skip_to_endsec();
            }
            _ => self.skip_to_endsec(),
        }
    }

    /// Whether the next record ends the section being read: ENDSEC, or one
    /// that only appears outside a section (a missing ENDSEC).
    fn at_section_end(&mut self) -> bool {
        match self.records.peek() {
            None => true,
            Some(r) => r.is("ENDSEC") || r.is("SECTION") || r.is("EOF"),
        }
    }

    fn skip_to_endsec(&mut self) {
        while !self.at_section_end() {
            self.records.next();
        }
        if self.records.peek().is_some_and(|r| r.is("ENDSEC")) {
            self.records.next();
        }
    }

    fn tables(&mut self) {
        while !self.at_section_end() {
            let Some(rec) = self.records.next() else {
                break;
            };
            if !rec.is("TABLE") {
                continue;
            }
            let table = rec
                .tags
                .iter()
                .find(|t| t.code == 2)
                .map(|t| {
                    String::from_utf8_lossy(t.bytes())
                        .trim()
                        .to_ascii_uppercase()
                })
                .unwrap_or_default();
            loop {
                if self.at_section_end() {
                    break;
                }
                let Some(entry) = self.records.next() else {
                    break;
                };
                if entry.is("ENDTAB") {
                    break;
                }
                if entry.is("TABLE") {
                    // A missing ENDTAB: start over with this table.
                    self.ctx.warn(
                        WarningKind::Malformed,
                        format!("table {table} has no ENDTAB"),
                    );
                    break;
                }
                self.ctx.start_record();
                tables::entry(&table, &entry, &mut self.raw, &mut self.ctx);
            }
        }
        self.skip_to_endsec();
        build::number_table_entries(&mut self.raw);
        self.ctx.layer_handles = self
            .raw
            .layers
            .iter()
            .map(|l| (l.name.clone(), l.handle))
            .collect();
    }

    fn blocks(&mut self) {
        while !self.at_section_end() {
            let Some(rec) = self.records.next() else {
                break;
            };
            if !rec.is("BLOCK") {
                if !rec.is("ENDBLK") {
                    self.ctx.warn(
                        WarningKind::Malformed,
                        format!("{} outside a block, skipped", rec.type_name()),
                    );
                }
                continue;
            }
            self.ctx.start_record();
            let mut block = tables::block(&rec, &mut self.ctx);
            let mut entities = Vec::new();
            self.entities_until_end(&mut entities);
            block.entities = entities;
            if let Some(end) = self.records.next_if(|r| r.is("ENDBLK")) {
                let parts = Parts::new(&end.tags, false);
                block.end_handle = Handle(parts.handle());
            }
            self.raw.blocks.push(block);
        }
        self.skip_to_endsec();
    }

    /// Entities up to ENDBLK, ENDSEC or the start of a block, which are left
    /// unread.
    fn entities_until_end(&mut self, out: &mut Vec<Entity>) {
        loop {
            match self.records.peek() {
                None => return,
                Some(r)
                    if r.is("ENDBLK")
                        || r.is("BLOCK")
                        || r.is("ENDSEC")
                        || r.is("SECTION")
                        || r.is("EOF") =>
                {
                    return
                }
                _ => {}
            }
            let Some(rec) = self.records.next() else {
                return;
            };
            if rec.is("SEQEND") || rec.is("VERTEX") || rec.is("ATTRIB") {
                self.ctx.warn(
                    WarningKind::Malformed,
                    format!("{} without its owner, skipped", rec.type_name()),
                );
                continue;
            }
            let counted = self.ctx.count_entity();
            self.ctx.start_record();
            let entity = counted.then(|| entities::entity(&rec, &mut self.ctx));
            // Followers are read either way, so that they are not taken for
            // entities of their own.
            match entity {
                Some(mut e) => {
                    self.followers(&mut e);
                    out.push(e);
                }
                None => {
                    let mut dropped = Entity::default();
                    self.followers(&mut dropped);
                }
            }
        }
    }

    /// The ATTRIB entities after an INSERT, the VERTEX entities after a
    /// POLYLINE, and the SEQEND that closes them.
    fn followers(&mut self, e: &mut Entity) {
        let (follower, is_insert) = match &e.kind {
            EntityKind::Insert(_) => ("ATTRIB", true),
            EntityKind::Polyline(_) => ("VERTEX", false),
            _ => return,
        };
        while let Some(rec) = self.records.next_if(|r| r.is(follower)) {
            self.ctx.start_record();
            match &mut e.kind {
                EntityKind::Insert(ins) if is_insert => {
                    if !self.ctx.count_entity() {
                        continue;
                    }
                    let a = entities::entity(&rec, &mut self.ctx);
                    if self.ctx.room(ins.attributes.len()) {
                        ins.attributes.push(a);
                    }
                }
                EntityKind::Polyline(p) => {
                    let v = entities::vertex(&rec, &mut self.ctx);
                    if self.ctx.room(p.vertices.len()) {
                        p.vertices.push(v);
                    }
                }
                _ => {}
            }
        }
        // The SEQEND, whose handle nothing needs.
        let _ = self.records.next_if(|r| r.is("SEQEND"));
    }

    fn objects(&mut self) {
        while !self.at_section_end() {
            let Some(rec) = self.records.next() else {
                break;
            };
            self.ctx.start_record();
            objects::object(&rec, &mut self.raw, &mut self.ctx);
        }
        self.skip_to_endsec();
    }
}
