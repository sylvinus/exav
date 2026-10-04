//! The DWG reader: `exav_unpack::dwg`'s objects into a [`Drawing`].
//!
//! The header variables name the table control objects; each control lists
//! its entries, read into the model's tables, and the block control its
//! block records, each with its BLOCK and ENDBLK entities and its entities
//! (a chain to R2000, a list from R2004). Each entity has its common data
//! (ODA spec 20.4.1 and 20.4.2) and its type's own (`entities`), an INSERT
//! its ATTRIBs and a POLYLINE its VERTEXes; a type the model does not hold,
//! or whose data does not read, is [`EntityKind::Unknown`] of its DXF type.
//! Then the objects of the object map the model holds (`objects`), and the
//! viewports numbered from their layouts.

mod blocks;
mod entities;
mod header;
mod objects;
mod tables;

pub(crate) use entities::lwpolyline_bits;

use std::collections::{HashMap, HashSet};

use exav_unpack::dwg::{self, Decoder, Dwg, Object, Text};

use super::model::*;
use super::{Error, Limits};

/// Reader state shared by the parts.
pub(crate) struct Ctx<'a, 'l> {
    pub dwg: &'a Dwg<'a>,
    pub version: dwg::Version,
    pub limits: &'l Limits,
    pub decoder: Decoder,
    /// The drawing's code page also from 2007 on, for the strings of proxy
    /// graphics.
    pub code_page: Decoder,
    pub warnings: Vec<Warning>,
    pub warnings_dropped: usize,
    pub entities: usize,
    entity_limit_hit: bool,
    item_limit_hit: bool,
    /// Table entry names by handle, for the handles objects refer by.
    pub names: HashMap<u64, String>,
    /// APPID names by handle, for extended data.
    pub apps: HashMap<u64, String>,
    /// The LTYPE control's entries in its order, ByLayer and ByBlock last.
    pub ltypes: Vec<u64>,
    /// References to entries that are not in the file, said once each.
    dangling: HashSet<u64>,
}

impl<'a> Ctx<'a, '_> {
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

    /// A T string: decoded, without the terminating zeros writers count,
    /// cut to the string limit.
    pub fn text(&mut self, bytes: &[u8]) -> String {
        let bytes = dwg::trim_zeros(bytes);
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

    /// A TV string ([`Ctx::text`] for bytes; UTF-16 strings cut to the
    /// string limit too, and their `\U+` escapes decoded: 2007 and later
    /// files keep a TEXT's or MTEXT's escapes as written).
    pub fn string(&mut self, t: Text) -> String {
        match t {
            Text::Bytes(b) => self.text(&b),
            Text::Unicode(s) => {
                let mut s = match Decoder::unescape(&s) {
                    std::borrow::Cow::Owned(u) => u,
                    std::borrow::Cow::Borrowed(_) => s,
                };
                let max = self.limits.max_string_bytes;
                if s.len() > max {
                    self.warn(
                        WarningKind::LimitReached,
                        format!("a string of {} bytes was cut to {max}", s.len()),
                    );
                    let mut end = max;
                    while !s.is_char_boundary(end) {
                        end -= 1;
                    }
                    s.truncate(end);
                }
                s
            }
        }
    }

    /// The object of a handle, with a warning when it cannot be read.
    pub fn object(&mut self, handle: u64, what: &str) -> Option<Object<'a>> {
        if handle == 0 {
            return None;
        }
        match self.dwg.object(handle) {
            Some(Ok(o)) if o.handle == handle => Some(o),
            Some(Ok(o)) => {
                self.warn(
                    WarningKind::Malformed,
                    format!(
                        "the object map points {what} {handle:X} at object {:X}",
                        o.handle
                    ),
                );
                None
            }
            Some(Err(e)) => {
                self.warn(
                    WarningKind::Malformed,
                    format!("{what} {handle:X} could not be read: {e}"),
                );
                None
            }
            None => {
                self.warn(
                    WarningKind::Malformed,
                    format!("{what} {handle:X} is not in the object map"),
                );
                None
            }
        }
    }

    /// Whether extended data's APPID handle names `app`, in any case: R13
    /// and R14 keep names in upper case (`ACCMTRANSPARENCY`).
    pub fn is_app(&self, handle: u64, app: &str) -> bool {
        self.apps
            .get(&handle)
            .is_some_and(|n| n.eq_ignore_ascii_case(app))
    }

    /// The name of the table entry a handle refers to, `None` for a null or
    /// unknown handle.
    pub fn name(&self, handle: u64) -> Option<&str> {
        self.names.get(&handle).map(String::as_str)
    }

    /// [`Ctx::name`], or the name of a table entry its control does not
    /// list, read from the entry itself: files exist whose entities use
    /// such entries (spec 20, "not all objects present in the file are
    /// actually used").
    pub fn entry_name(&mut self, handle: u64) -> Option<String> {
        if let Some(n) = self.names.get(&handle) {
            return Some(n.clone());
        }
        if handle == 0 {
            return None;
        }
        let mut o = match self.dwg.object(handle)? {
            Ok(o) if o.handle == handle => o,
            _ => return None,
        };
        // BLOCK_RECORD, LAYER, STYLE, LTYPE, VIEW, UCS, VPORT, APPID,
        // DIMSTYLE: entries, which start with their name.
        if !matches!(
            o.type_code,
            0x31 | 0x33 | 0x35 | 0x39 | 0x3D | 0x3F | 0x41 | 0x43 | 0x45
        ) {
            return None;
        }
        let raw = o.tv().ok()?;
        let name = self.string(raw);
        self.names.insert(handle, name.clone());
        Some(name)
    }

    /// [`Ctx::entry_name`] for a reference that must name an entry: a
    /// handle that names none is said once.
    pub fn referenced_name(&mut self, handle: u64, what: &str) -> Option<String> {
        let name = self.entry_name(handle);
        if name.is_none() && handle != 0 && self.dangling.insert(handle) {
            self.warn(
                WarningKind::Malformed,
                format!("{what} {handle:X} is referenced but not in the file"),
            );
        }
        name
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
                format!("an entity had more than {len} items"),
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
}

pub(crate) fn read(bytes: &[u8], limits: &Limits) -> Result<Drawing, Error> {
    let file = Dwg::open_with(bytes, limits.max_decompressed_bytes).map_err(|e| match e {
        dwg::Error::NotDwg => Error::NotDwg,
        dwg::Error::UnsupportedVersion(v) => Error::Unsupported(v),
        dwg::Error::Damaged(why) => Error::Damaged(why),
        dwg::Error::LimitExceeded(why) => Error::LimitExceeded(why),
    })?;
    let version = file.version();
    let code_page = dwg::code_page_name(file.code_page()).unwrap_or("");
    let (decoder, known) = Decoder::for_drawing(version.acadver(), code_page);
    let problems: Vec<String> = file.problems().to_vec();
    let mut ctx = Ctx {
        dwg: &file,
        version,
        limits,
        decoder,
        code_page: Decoder::for_drawing(dwg::Version::R2004.acadver(), code_page).0,
        warnings: Vec::new(),
        warnings_dropped: 0,
        entities: 0,
        entity_limit_hit: false,
        item_limit_hit: false,
        names: HashMap::new(),
        apps: HashMap::new(),
        ltypes: Vec::new(),
        dangling: HashSet::new(),
    };
    if !known {
        ctx.warn(
            WarningKind::UnsupportedCodePage,
            format!(
                "code page {} ({code_page}) is not supported; read as Windows-1252",
                ctx.dwg.code_page()
            ),
        );
    }
    for p in problems {
        ctx.warn(WarningKind::Malformed, p);
    }

    let vars = header::read(&mut ctx, code_page);
    let mut drawing = Drawing {
        header: vars.header.clone(),
        preview: super::preview::from_dwg(&ctx.dwg.preview()),
        ..Drawing::default()
    };
    tables::read(&mut ctx, &vars, &mut drawing);
    drawing.blocks = blocks::read(&mut ctx, &vars);
    objects::read(&mut ctx, &vars, &mut drawing);
    objects::link(&mut drawing);

    // The header names its current entries by handle.
    let named = |h: u64, fallback: &str| -> String {
        ctx.name(h)
            .map_or_else(|| fallback.to_string(), str::to_string)
    };
    drawing.header.clayer = named(vars.clayer, &drawing.header.clayer);
    drawing.header.textstyle = named(vars.textstyle, &drawing.header.textstyle);
    drawing.header.dimstyle = named(vars.dimstyle, &drawing.header.dimstyle);

    drawing.warnings = ctx.warnings;
    drawing.warnings_dropped = ctx.warnings_dropped;
    Ok(drawing)
}
