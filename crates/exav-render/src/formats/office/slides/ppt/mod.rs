//! PowerPoint 97 to 2003 presentations ([MS-PPT]): a compound file whose
//! "PowerPoint Document" stream holds the persist objects (document,
//! masters, slides, notes) located through the user edit chain, and whose
//! "Pictures" stream holds the pictures. Each main master becomes a slide
//! master, each title master a layout of its main master, and each slide a
//! slide with its shapes and text resolved against them. PowerPoint 95 has
//! records of its own (`ppt95`); PowerPoint 2 to 4 are only recognised
//! (`old`).

mod escher;
mod old;
mod ole;
mod pp9;
mod ppt95;
mod presets;
mod records;
mod shapes;
mod text;

use crate::formats::office::common::bytes::{Cur, u32_at};
use crate::formats::office::slides::error::{Error, Result};
use crate::formats::office::slides::limits::{Budget, SHAPE_BYTES, text_bytes};
use crate::formats::office::slides::model::*;
use escher::{OShape, Props};
use exav_unpack::cfb::Compound;
use records::{Children, Rec, read_at};
use std::borrow::Cow;
use std::collections::HashMap;
use text::{Cf, Levels, Pf, RawText, TColor, TextCtx};

/// Record types ([MS-PPT] 2.13.24).
pub(crate) mod rt {
    pub const DOCUMENT: u16 = 0x03E8;
    pub const DOCUMENT_ATOM: u16 = 0x03E9;
    pub const SLIDE: u16 = 0x03EE;
    pub const SLIDE_ATOM: u16 = 0x03EF;
    pub const ENVIRONMENT: u16 = 0x03F2;
    pub const SLIDE_PERSIST_ATOM: u16 = 0x03F3;
    pub const MAIN_MASTER: u16 = 0x03F8;
    pub const SLIDE_SHOW_SLIDE_INFO: u16 = 0x03F9;
    pub const EX_OBJ_LIST: u16 = 0x0409;
    pub const DRAWING_GROUP: u16 = 0x040B;
    pub const DRAWING: u16 = 0x040C;
    pub const FONT_COLLECTION: u16 = 0x07D5;
    pub const COLOR_SCHEME: u16 = 0x07F0;
    pub const EX_OBJ_REF_ATOM: u16 = 0x0BC1;
    pub const PLACEHOLDER_ATOM: u16 = 0x0BC3;
    pub const EX_OLE_OBJ_ATOM: u16 = 0x0FC3;
    pub const EX_EMBED: u16 = 0x0FCC;
    pub const EX_OLE_OBJ_STG: u16 = 0x1011;
    pub const OUTLINE_TEXT_REF: u16 = 0x0F9E;
    pub const TEXT_HEADER: u16 = 0x0F9F;
    pub const TEXT_CHARS: u16 = 0x0FA0;
    pub const STYLE_TEXT_PROP: u16 = 0x0FA1;
    pub const MASTER_TEXT_PROP: u16 = 0x0FA2;
    pub const TEXT_MASTER_STYLE: u16 = 0x0FA3;
    pub const TEXT_CF_EXCEPTION: u16 = 0x0FA4;
    pub const TEXT_PF_EXCEPTION: u16 = 0x0FA5;
    pub const TEXT_RULER: u16 = 0x0FA6;
    pub const TEXT_BYTES: u16 = 0x0FA8;
    pub const FONT_ENTITY: u16 = 0x0FB7;
    pub const CSTRING: u16 = 0x0FBA;
    pub const EX_HYPERLINK_ATOM: u16 = 0x0FD3;
    pub const EX_HYPERLINK: u16 = 0x0FD7;
    pub const SLIDE_NUMBER_MC: u16 = 0x0FD8;
    pub const HEADERS_FOOTERS: u16 = 0x0FD9;
    pub const HEADERS_FOOTERS_ATOM: u16 = 0x0FDA;
    pub const TEXT_INTERACTIVE_INFO: u16 = 0x0FDF;
    pub const SLIDE_LIST_WITH_TEXT: u16 = 0x0FF0;
    pub const INTERACTIVE_INFO: u16 = 0x0FF2;
    pub const INTERACTIVE_INFO_ATOM: u16 = 0x0FF3;
    pub const USER_EDIT_ATOM: u16 = 0x0FF5;
    pub const CURRENT_USER_ATOM: u16 = 0x0FF6;
    pub const DATE_TIME_MC: u16 = 0x0FF7;
    pub const GENERIC_DATE_MC: u16 = 0x0FF8;
    pub const HEADER_MC: u16 = 0x0FF9;
    pub const FOOTER_MC: u16 = 0x0FFA;
    pub const RTF_DATE_TIME_MC: u16 = 0x1015;
    pub const PERSIST_DIRECTORY_ATOM: u16 = 0x1772;
    pub const CRYPT_SESSION: u16 = 0x2F14;
}

/// Placeholder types ([MS-PPT] 2.13.21).
mod pt {
    pub const MASTER_TITLE: u8 = 0x01;
    pub const MASTER_BODY: u8 = 0x02;
    pub const MASTER_CENTER_TITLE: u8 = 0x03;
    pub const MASTER_SUBTITLE: u8 = 0x04;
    pub const MASTER_DATE: u8 = 0x07;
    pub const MASTER_SLIDE_NUMBER: u8 = 0x08;
    pub const MASTER_FOOTER: u8 = 0x09;
    pub const MASTER_HEADER: u8 = 0x0A;
    pub const TITLE: u8 = 0x0D;
    pub const BODY: u8 = 0x0E;
    pub const CENTER_TITLE: u8 = 0x0F;
    pub const SUBTITLE: u8 = 0x10;
    pub const VERTICAL_TITLE: u8 = 0x11;
    pub const VERTICAL_BODY: u8 = 0x12;
}

/// The persist object directory: identifier to stream offset.
fn persist_directory(stream: &[u8], current_edit: Option<usize>) -> HashMap<u32, usize> {
    let mut edits = vec![];
    let mut seen = vec![];
    let mut at = current_edit;
    // The chain, newest first; bounded and cycle-free.
    while let Some(off) = at {
        if seen.contains(&off) || seen.len() > 4096 {
            break;
        }
        seen.push(off);
        let Some(r) = read_at(stream, off).filter(|r| r.typ == rt::USER_EDIT_ATOM) else {
            break;
        };
        let mut c = r.cur();
        c.skip(8);
        let last = c.u32() as usize;
        let dir = c.u32() as usize;
        c.skip(4);
        // persistIdSeed: no identifier is larger.
        let seed = c.u32();
        edits.push((dir, (!c.short).then_some(seed)));
        at = (last != 0 && last < off).then_some(last);
    }
    if edits.is_empty() {
        // No usable chain: every persist directory in the stream, in order.
        for r in Children::new(stream) {
            if r.typ == rt::PERSIST_DIRECTORY_ATOM {
                edits.insert(0, (r.at, None));
            }
        }
    }
    let mut map = HashMap::new();
    for &(dir, seed) in edits.iter().rev() {
        let Some(r) = read_at(stream, dir).filter(|r| r.typ == rt::PERSIST_DIRECTORY_ATOM) else {
            continue;
        };
        let words = r.data.len() / 4;
        let word = |i: usize| u32_at(r.data, i * 4);
        // An entry header whose identifiers are all within the seed.
        let plausible = |h: u32, seed: u32| {
            let n = h >> 20;
            n > 0 && (h & 0xF_FFFF) + n - 1 <= seed
        };
        let mut p = 0;
        while p < words {
            let h = word(p);
            let id = h & 0xF_FFFF;
            let mut n = (h >> 20) as usize;
            // Some writers store a count past 4095 in the entry's 12 bits,
            // keeping the low ones: while what follows the entry cannot be
            // another, it is taken to be 4096 offsets longer.
            if let Some(seed) = seed {
                while p + 1 + n < words
                    && !plausible(word(p + 1 + n), seed)
                    && p + 1 + n + 4096 <= words
                {
                    n += 4096;
                }
            }
            for k in 0..n.min(words - p - 1) {
                map.insert(id + k as u32, word(p + 1 + k) as usize);
            }
            p += 1 + n;
            if map.len() > 1 << 20 {
                break;
            }
        }
    }
    map
}

/// Headers and footers settings ([MS-PPT] 2.4.15).
#[derive(Clone, Default)]
struct HeadersFooters {
    date: bool,
    user_date: bool,
    slide_number: bool,
    footer: bool,
    footer_text: String,
    date_text: String,
}

fn headers_footers(r: &Rec) -> HeadersFooters {
    let mut hf = HeadersFooters::default();
    for k in r.children() {
        match k.typ {
            rt::HEADERS_FOOTERS_ATOM => {
                let f = Cur::at(k.data, 2).u16();
                hf.date = f & 1 != 0;
                hf.user_date = f & 4 != 0;
                hf.slide_number = f & 8 != 0;
                hf.footer = f & 0x20 != 0;
            }
            rt::CSTRING if k.inst == 2 => hf.footer_text = utf16(k.data),
            rt::CSTRING if k.inst == 0 => hf.date_text = utf16(k.data),
            _ => {}
        }
    }
    hf
}

fn utf16(d: &[u8]) -> String {
    let u: Vec<u16> = d
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .take(1 << 16)
        .collect();
    let end = u.iter().position(|&c| c == 0).unwrap_or(u.len());
    String::from_utf16_lossy(&u[..end])
}

fn scheme_of(r: &Rec) -> Option<[Rgb; 8]> {
    let s = r
        .children()
        .find(|k| k.typ == rt::COLOR_SCHEME && k.inst == 1)?;
    let mut c = s.cur();
    let mut out = [0u32; 8];
    for x in &mut out {
        let (r, g, b, _) = (c.u8(), c.u8(), c.u8(), c.u8());
        *x = u32::from(r) << 16 | u32::from(g) << 8 | u32::from(b);
    }
    (!c.short).then_some(out)
}

const DEFAULT_SCHEME: [Rgb; 8] = [
    0xFFFFFF, 0x000000, 0x808080, 0x000000, 0x00CC99, 0x3333CC, 0xCCCCFF, 0xB2B2B2,
];

/// A main or title master as read.
struct MasterSlide<'a> {
    id: u32,
    title: bool,
    /// The main master a title master follows.
    follows: u32,
    flags: u16,
    scheme: [Rgb; 8],
    /// Text styles by text type (0 to 8), five levels each.
    styles: Vec<Option<Levels>>,
    shapes: Vec<OShape<'a>>,
    background: Option<OShape<'a>>,
    hf: Option<HeadersFooters>,
}

struct Reader<'a> {
    stream: &'a [u8],
    persist: HashMap<u32, usize>,
    fonts: Vec<String>,
    doc_pf: Pf,
    doc_cf: Cf,
    doc_style: Option<Levels>,
    /// The blip store's pictures, decoded when a shape uses them.
    blip_recs: Vec<Option<Rec<'a>>>,
    /// Their media indexes, once decoded.
    blips: Vec<Option<usize>>,
    /// Bytes of pictures decoded and not yet charged to the budget.
    pending: u64,
    defaults: Props<'a>,
    links: HashMap<u32, Link>,
    /// The persist identifier of each embedded object's storage, by the
    /// object's identifier.
    objects: HashMap<u32, u32>,
    slide_ids: Vec<u32>,
    /// Masters' shapes by identifier, for shapes that name one as theirs
    /// (hspMaster).
    master_props: HashMap<u32, Props<'a>>,
    /// The media index of each picture bullet, by its index.
    bullet_media: Vec<Option<usize>>,
    /// The document's PP9 master styles: text type, level, extension.
    doc9: Vec<(u16, usize, pp9::Pf9)>,
    p: Presentation,
}

pub(crate) fn read(input: &[u8], budget: &mut Budget) -> Result<Presentation> {
    if let Some(old) = old::open(input) {
        return old::read(&old);
    }
    let cf = Compound::open(input)
        .ok_or_else(|| Error::NotFormat("not an OLE2 compound file".into()))?;
    if let Some(old) = cf.stream(&["PP40"]).and_then(|s| old::parse(&s)) {
        return old::read(&old);
    }
    let max = budget.limits.max_part as usize;
    // Borrowed from the input when its sectors follow each other, as they
    // usually do; only a copy is charged.
    let stream = cf.stream_ref(&["PowerPoint Document"]).ok_or_else(|| {
        if cf.stream(&["PP97_DUALSTORAGE"]).is_some() || cf.names().any(|n| n.starts_with("PP")) {
            Error::Unsupported("PowerPoint 95 or earlier".into())
        } else {
            Error::NotFormat("no PowerPoint Document stream".into())
        }
    })?;
    let pictures = cf.stream_ref(&["Pictures"]).unwrap_or_default();
    for s in [&stream, &pictures] {
        if s.len() > max {
            return Err(Error::TooLarge("a stream"));
        }
        if let Cow::Owned(v) = s {
            budget.alloc(v.len() as u64)?;
        }
    }
    if cf.stream(&["EncryptedSummary"]).is_some() {
        return Err(Error::Encrypted);
    }
    // PowerPoint 95 has its own records.
    if ppt95::is95(&stream) {
        return ppt95::read(&stream, budget);
    }

    let mut current_edit = None;
    let current_user = cf.stream(&["Current User"]);
    if let Some(cu) = current_user
        && let Some(r) = read_at(&cu, 0).filter(|r| r.typ == rt::CURRENT_USER_ATOM)
    {
        let mut c = r.cur();
        c.skip(4);
        let token = c.u32();
        if token == 0xF3D1_C4DF {
            return Err(Error::Encrypted);
        }
        current_edit = Some(c.u32() as usize);
        c.skip(2);
        let version = c.u16();
        if version != 0x03F4 && version != 0 {
            return Err(Error::Unsupported(format!(
                "PowerPoint file version {version:#x}"
            )));
        }
    }
    let persist = persist_directory(&stream, current_edit);
    // The newest user edit's document, or the first document found.
    let doc_offset = current_edit
        .and_then(|off| read_at(&stream, off))
        .filter(|r| r.typ == rt::USER_EDIT_ATOM)
        .and_then(|r| {
            let c = Cur::at(r.data, 16);
            let id = c.clone().u32();
            if r.data.len() >= 32 && Cur::at(r.data, 28).u32() != 0 {
                return Some(Err(Error::Encrypted));
            }
            persist.get(&id).copied().map(Ok)
        })
        .transpose()?
        .or_else(|| persist.get(&1).copied())
        .filter(|&o| read_at(&stream, o).is_some_and(|r| r.typ == rt::DOCUMENT))
        .or_else(|| {
            Children::new(&stream)
                .filter(|r| r.typ == rt::DOCUMENT)
                .map(|r| r.at)
                .last()
        })
        .ok_or_else(|| Error::Malformed("no document record".into()))?;
    let doc = read_at(&stream, doc_offset)
        .ok_or_else(|| Error::Malformed("no document record".into()))?;
    if doc.children().any(|r| r.typ == rt::CRYPT_SESSION) {
        return Err(Error::Encrypted);
    }

    let mut r = Reader {
        stream: &stream,
        persist,
        fonts: vec![],
        doc_pf: Pf::default(),
        doc_cf: Cf::default(),
        doc_style: None,
        blip_recs: vec![],
        blips: vec![],
        pending: 0,
        defaults: Props::default(),
        links: HashMap::new(),
        objects: HashMap::new(),
        slide_ids: vec![],
        master_props: HashMap::new(),
        bullet_media: vec![],
        doc9: vec![],
        p: Presentation::default(),
    };
    r.document(&doc, &pictures, budget)?;
    Ok(r.p)
}

impl<'a> Reader<'a> {
    /// Decodes the pictures `props` names (the shape's and its fill's), once
    /// each: those of slides not converted are never read.
    fn want_blips(&mut self, props: &Props) {
        for id in [0x0104, 0x0186] {
            let Some(i) = props.get(id).and_then(|i| (i as usize).checked_sub(1)) else {
                continue;
            };
            if i >= self.blip_recs.len() || self.blips[i].is_some() {
                continue;
            }
            let decoded = self.blip_recs[i]
                .take()
                .and_then(|r| escher::blip(&r))
                .filter(|b| !b.data.is_empty());
            if let Some(b) = decoded {
                self.pending += b.data.len() as u64;
                self.blips[i] = Some(self.p.add_media(b.ext, b.data));
            }
        }
    }

    fn object(&self, id: u32) -> Option<Rec<'a>> {
        let off = *self.persist.get(&id)?;
        read_at(self.stream, off)
    }

    fn document(&mut self, doc: &Rec<'a>, pictures: &'a [u8], budget: &mut Budget) -> Result<()> {
        // Slide size, in master units.
        let mut size = (5760, 4320);
        let mut omit_title_footers = false;
        if let Some(a) = doc.child(rt::DOCUMENT_ATOM) {
            let mut c = a.cur();
            size = (c.i32(), c.i32());
            omit_title_footers = a.data.get(37).is_some_and(|&b| b != 0);
        }
        let to_emu = |v: i32| (f64::from(v.clamp(576, 1_000_000)) * 1587.5).round() as Emu;
        self.p.width = to_emu(size.0);
        self.p.height = to_emu(size.1);

        if let Some(env) = doc.child(rt::ENVIRONMENT) {
            for k in env.children() {
                match k.typ {
                    rt::FONT_COLLECTION => {
                        for f in k.children().filter(|f| f.typ == rt::FONT_ENTITY) {
                            let name = utf16(f.data.get(..64).unwrap_or(f.data));
                            let i = usize::from(f.inst);
                            if i < 4096 {
                                if self.fonts.len() <= i {
                                    self.fonts.resize(i + 1, String::new());
                                }
                                self.fonts[i] = name;
                            }
                        }
                    }
                    rt::TEXT_CF_EXCEPTION => self.doc_cf = text::read_cf(&mut k.cur()),
                    rt::TEXT_PF_EXCEPTION => {
                        let mut c = k.cur();
                        c.skip(2);
                        self.doc_pf = text::read_pf(&mut c);
                    }
                    rt::TEXT_MASTER_STYLE => self.doc_style = Some(text::read_master_style(&k)),
                    _ => {}
                }
            }
        }
        // The PowerPoint 2000 text extension: master styles with numbering
        // and picture bullets, and the pictures.
        if let Some(tags) = doc.child(pp9::PROG_TAGS) {
            for k in pp9::tag_records(&tags) {
                match k.typ {
                    pp9::TEXT_MASTER_STYLE9 => {
                        for (level, pf) in pp9::master_style9(&k) {
                            self.doc9.push((k.inst, level, pf));
                        }
                    }
                    pp9::BLIP_COLLECTION9 => {
                        for (i, rec) in pp9::bullet_pictures(&k) {
                            let i = usize::from(i);
                            if i >= 256 {
                                continue;
                            }
                            if self.bullet_media.len() <= i {
                                self.bullet_media.resize(i + 1, None);
                            }
                            if let Some(b) = escher::blip(&rec).filter(|b| !b.data.is_empty()) {
                                self.pending += b.data.len() as u64;
                                self.bullet_media[i] = Some(self.p.add_media(b.ext, b.data));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(dg) = doc.child(rt::DRAWING_GROUP)
            && let Some(dgg) = dg.child(0xF000)
        {
            self.blip_recs = escher::blip_records(&dgg, pictures);
            self.blips = vec![None; self.blip_recs.len()];
            if let Some(opt) = dgg.child(0xF00B) {
                self.defaults = escher::read_props(opt.data, opt.inst);
            }
        }
        if let Some(list) = doc.child(rt::EX_OBJ_LIST) {
            for h in list.children().filter(|h| h.typ == rt::EX_HYPERLINK) {
                let id = h
                    .child(rt::EX_HYPERLINK_ATOM)
                    .map(|a| Cur::new(a.data).u32());
                let target = h
                    .children()
                    .find(|s| s.typ == rt::CSTRING && s.inst == 1)
                    .map(|s| utf16(s.data));
                let location = h
                    .children()
                    .find(|s| s.typ == rt::CSTRING && s.inst == 3)
                    .map(|s| utf16(s.data));
                let link = match (target.as_deref().and_then(Link::url), location) {
                    (Some(u), _) => Some(u),
                    (None, Some(loc)) => loc
                        .split(',')
                        .nth(1)
                        .and_then(|n| n.trim().parse::<usize>().ok())
                        .filter(|&n| n > 0)
                        .map(|n| Link::Slide(n - 1)),
                    _ => None,
                };
                if let (Some(id), Some(link)) = (id, link) {
                    self.links.insert(id, link);
                }
            }
            // ExOleObjAtom: aspect, type, object id, subtype, persist id.
            for e in list.children().filter(|e| e.typ == rt::EX_EMBED) {
                if let Some(a) = e.child(rt::EX_OLE_OBJ_ATOM).filter(|a| a.data.len() >= 20) {
                    let mut c = a.cur();
                    c.skip(8);
                    let id = c.u32();
                    c.skip(4);
                    self.objects.insert(id, c.u32());
                }
            }
        }
        let doc_hf = doc
            .children()
            .find(|k| k.typ == rt::HEADERS_FOOTERS && k.inst == 3)
            .map(|k| headers_footers(&k))
            .unwrap_or_default();

        // Masters, main and title.
        let mut masters: Vec<MasterSlide> = vec![];
        let lists: Vec<Rec> = doc
            .children()
            .filter(|k| k.typ == rt::SLIDE_LIST_WITH_TEXT)
            .collect();
        for list in lists.iter().filter(|l| l.inst == 1) {
            for a in list.children().filter(|a| a.typ == rt::SLIDE_PERSIST_ATOM) {
                let mut c = a.cur();
                let pid = c.u32();
                c.skip(8);
                let id = c.u32();
                if let Some(m) = self.object(pid)
                    && let Some(ms) = self.master(&m, id, budget)?
                {
                    masters.push(ms);
                }
                if masters.len() > 1024 {
                    break;
                }
            }
        }
        fn index<'a>(shapes: &[OShape<'a>], out: &mut HashMap<u32, Props<'a>>, depth: u32) {
            for s in shapes {
                out.entry(s.spid).or_insert_with(|| s.props.clone());
                if depth < 32 {
                    index(&s.children, out, depth + 1);
                }
            }
        }
        for m in &masters {
            index(&m.shapes, &mut self.master_props, 0);
        }
        // Title masters' styles are their main master's.
        for i in 0..masters.len() {
            if masters[i].title
                && let Some(main) = masters
                    .iter()
                    .find(|m| !m.title && m.id == masters[i].follows)
            {
                let styles = main.styles.clone();
                masters[i].styles = styles;
            }
        }
        let mut model_of: HashMap<u32, (usize, usize)> = HashMap::new();
        for m in masters.iter().filter(|m| !m.title) {
            let mi = self.p.masters.len();
            let master = self.model_master(m, budget)?;
            self.p.masters.push(master);
            model_of.insert(m.id, (mi, 0));
        }
        for m in masters.iter().filter(|m| m.title) {
            let Some(&(mi, _)) = model_of
                .get(&m.follows)
                .or_else(|| model_of.values().next())
            else {
                continue;
            };
            let layout = self.title_layout(m, budget)?;
            let li = self.p.masters[mi].layouts.len();
            self.p.masters[mi].layouts.push(layout);
            model_of.insert(m.id, (mi, li));
        }
        if self.p.masters.is_empty() {
            self.p.masters.push(Master {
                layouts: vec![blank_layout()],
                ..Master::default()
            });
        }

        // Slides, with their outline text.
        let mut slides: Vec<(Rec<'a>, Vec<RawText>, u32)> = vec![];
        for list in lists.iter().filter(|l| l.inst == 0) {
            let kids: Vec<Rec> = list.children().collect();
            let mut i = 0;
            while i < kids.len() {
                let a = kids[i];
                i += 1;
                if a.typ != rt::SLIDE_PERSIST_ATOM {
                    continue;
                }
                let start = i;
                while i < kids.len() && kids[i].typ != rt::SLIDE_PERSIST_ATOM {
                    i += 1;
                }
                let bodies = text::read_bodies(kids[start..i].iter().copied());
                let mut c = a.cur();
                let pid = c.u32();
                c.skip(8);
                let slide_id = c.u32();
                if let Some(s) = self.object(pid).filter(|s| s.typ == rt::SLIDE) {
                    budget.slide(slides.len())?;
                    slides.push((s, bodies, slide_id));
                }
            }
        }
        if slides.is_empty() {
            // No usable slide list: the slides among the persist objects, in
            // identifier order, title masters left out.
            let master_offsets: Vec<usize> = lists
                .iter()
                .filter(|l| l.inst == 1)
                .flat_map(|l| l.children().filter(|a| a.typ == rt::SLIDE_PERSIST_ATOM))
                .filter_map(|a| self.persist.get(&Cur::new(a.data).u32()).copied())
                .collect();
            let mut ids: Vec<(u32, usize)> = self.persist.iter().map(|(&k, &v)| (k, v)).collect();
            ids.sort_unstable();
            for (_, off) in ids {
                if master_offsets.contains(&off) {
                    continue;
                }
                if let Some(s) = read_at(self.stream, off).filter(|s| s.typ == rt::SLIDE) {
                    budget.slide(slides.len())?;
                    slides.push((s, vec![], 0));
                }
            }
        }
        self.slide_ids = slides.iter().map(|s| s.2).collect();
        self.p.total_slides = slides.len();
        for (n, (s, outline, _)) in slides.iter().enumerate() {
            budget.alloc(std::mem::take(&mut self.pending))?;
            if !budget.wants(n) {
                continue;
            }
            let slide = self.slide(
                s,
                outline,
                n + 1,
                &masters,
                &model_of,
                &doc_hf,
                omit_title_footers,
                budget,
            )?;
            self.p.slides.push(slide);
        }
        budget.alloc(std::mem::take(&mut self.pending))?;
        Ok(())
    }

    fn master(
        &mut self,
        m: &Rec<'a>,
        id: u32,
        budget: &mut Budget,
    ) -> Result<Option<MasterSlide<'a>>> {
        let title = match m.typ {
            rt::MAIN_MASTER => false,
            rt::SLIDE => true,
            _ => return Ok(None),
        };
        // SlideAtom: layout, placeholder types, master, notes, flags.
        let (follows, flags) = match m.child(rt::SLIDE_ATOM) {
            Some(a) => (Cur::at(a.data, 12).u32(), Cur::at(a.data, 20).u16()),
            None => (0, 0),
        };
        let mut styles: Vec<Option<Levels>> = vec![None; 9];
        for k in m.children().filter(|k| k.typ == rt::TEXT_MASTER_STYLE) {
            if let Some(slot) = styles.get_mut(usize::from(k.inst)) {
                *slot = Some(text::read_master_style(&k));
            }
        }
        // Numbering and picture bullets of the PP9 extension, the master's
        // own over the document's.
        let own9: Vec<(u16, usize, pp9::Pf9)> = m
            .child(pp9::PROG_TAGS)
            .map(|t| {
                pp9::tag_records(&t)
                    .iter()
                    .filter(|k| k.typ == pp9::TEXT_MASTER_STYLE9)
                    .flat_map(|k| {
                        pp9::master_style9(k)
                            .into_iter()
                            .map(|(l, pf)| (k.inst, l, pf))
                            .collect::<Vec<_>>()
                    })
                    .collect()
            })
            .unwrap_or_default();
        for &(text_type, level, pf) in self.doc9.iter().chain(own9.iter()) {
            let slot = styles
                .get_mut(usize::from(text_type))
                .and_then(|s| s.get_or_insert_with(Levels::default).0.get_mut(level));
            if let Some(slot) = slot {
                slot.0.overlay9(&pf);
            }
        }
        let (shapes, background) = match m
            .child(rt::DRAWING)
            .and_then(|d| d.child(escher::DG_CONTAINER))
        {
            Some(dg) => {
                let d = escher::drawing(&dg);
                (d.shapes, d.background)
            }
            None => (vec![], None),
        };
        budget.alloc(SHAPE_BYTES * shapes.len() as u64)?;
        let hf = m
            .children()
            .find(|k| k.typ == rt::HEADERS_FOOTERS)
            .map(|k| headers_footers(&k));
        Ok(Some(MasterSlide {
            id,
            title,
            follows,
            flags,
            scheme: scheme_of(m).unwrap_or(DEFAULT_SCHEME),
            styles,
            shapes,
            background,
            hf,
        }))
    }

    /// The five levels of a text type, every property resolved.
    fn levels(&self, styles: &[Option<Levels>], text_type: u32) -> [(Pf, Cf); 5] {
        let mut pf = Pf {
            has_bullet: Some(false),
            align: Some(0),
            line_spacing: Some(100),
            space_before: Some(0),
            space_after: Some(0),
            margin: Some(0),
            indent: Some(0),
            ..Pf::default()
        };
        pf.overlay(&self.doc_pf);
        let mut cf = Cf {
            bold: Some(false),
            italic: Some(false),
            underline: Some(false),
            font: Some(0),
            size: Some(18),
            color: Some(TColor::Scheme(1)),
            ..Cf::default()
        };
        cf.overlay(&self.doc_cf);
        let mut out: [(Pf, Cf); 5] = std::array::from_fn(|_| (pf.clone(), cf.clone()));
        let apply = |out: &mut [(Pf, Cf); 5], l: &Levels| {
            // Each level of a style inherits the one above it.
            let mut prev: Option<(Pf, Cf)> = None;
            for (i, (lp, lc)) in l.0.iter().enumerate() {
                let (mut p, mut c) = prev.clone().unwrap_or_default();
                p.overlay(lp);
                c.overlay(lc);
                out[i].0.overlay(&p);
                out[i].1.overlay(&c);
                prev = Some((p, c));
            }
        };
        if let Some(d) = &self.doc_style {
            apply(&mut out, d);
        }
        // The body's text type picks the master style, placeholder or not
        // (a text box that took a placeholder's place keeps its type).
        let chain: &[u32] = match text_type {
            0 => &[0],
            6 => &[0, 6],
            1 => &[1],
            5 | 7 | 8 => &[1, text_type],
            2 => &[2],
            _ => &[4],
        };
        for &t in chain {
            if let Some(Some(l)) = styles.get(t as usize) {
                apply(&mut out, l);
            }
        }
        out
    }

    fn model_master(&mut self, m: &MasterSlide<'a>, budget: &mut Budget) -> Result<Master> {
        let bg = m
            .background
            .as_ref()
            .map(|b| self.background_fill(b, &m.scheme));
        let mut shapes = vec![];
        for s in &m.shapes {
            if master_placeholder_of(s).is_some() {
                continue;
            }
            if let Some(x) = self.shape(s, &SlideCtx::master(m), false, budget)? {
                shapes.push(x);
            }
        }
        let font = |i: Option<u16>| {
            i.and_then(|i| self.fonts.get(usize::from(i)).cloned())
                .filter(|f| !f.is_empty())
        };
        let title_font =
            font(self.levels(&m.styles, 0)[0].1.font).unwrap_or_else(|| "Arial".into());
        let body_font =
            font(self.levels(&m.styles, 1)[0].1.font).unwrap_or_else(|| title_font.clone());
        let s = &m.scheme;
        Ok(Master {
            name: "Master".into(),
            theme: Theme {
                name: "Office Theme".into(),
                colors: [
                    s[1], s[0], s[2], s[4], s[4], s[5], s[6], s[7], 0x5B9BD5, 0x70AD47, s[6], s[7],
                ],
                major_font: title_font,
                minor_font: body_font,
            },
            background: bg,
            shapes,
            layouts: vec![Layout {
                name: "Title and Content".into(),
                kind: "obj",
                show_master_shapes: true,
                ..Layout::default()
            }],
            ..Master::default()
        })
    }

    fn title_layout(&mut self, m: &MasterSlide<'a>, budget: &mut Budget) -> Result<Layout> {
        let master_bg = m.flags & 4 != 0;
        let bg = if master_bg {
            None
        } else {
            m.background
                .as_ref()
                .map(|b| self.background_fill(b, &m.scheme))
        };
        let mut shapes = vec![];
        for s in &m.shapes {
            if master_placeholder_of(s).is_some() {
                continue;
            }
            if let Some(x) = self.shape(s, &SlideCtx::master(m), false, budget)? {
                shapes.push(x);
            }
        }
        Ok(Layout {
            name: "Title Slide".into(),
            kind: "title",
            background: bg,
            shapes,
            show_master_shapes: m.flags & 1 != 0,
        })
    }

    /// A background shape's fill. The drawing's default properties are not
    /// its own: a colour it leaves out is the scheme's background.
    fn background_fill(&mut self, b: &OShape, scheme: &[Rgb; 8]) -> Fill {
        let mut props = Props(vec![escher::Prop {
            id: 0x0181,
            value: 0x0800_0000,
            complex: None,
        }]);
        props.overlay(&b.props);
        self.want_blips(&props);
        let refs = shapes::refs(&props, scheme);
        let ctx = shapes::Ctx {
            scheme,
            blips: &self.blips,
        };
        match shapes::fill(&props, &ctx, &refs) {
            Fill::None => Fill::Solid(Color::rgb(0xFFFFFF)),
            f => f,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn slide(
        &mut self,
        s: &Rec<'a>,
        outline: &[RawText],
        number: usize,
        masters: &[MasterSlide<'a>],
        model_of: &HashMap<u32, (usize, usize)>,
        doc_hf: &HeadersFooters,
        omit_title_footers: bool,
        budget: &mut Budget,
    ) -> Result<Slide> {
        let atom = s.child(rt::SLIDE_ATOM);
        let master_id = atom.map(|a| Cur::at(a.data, 12).u32()).unwrap_or(0);
        let flags = atom.map(|a| Cur::at(a.data, 20).u16()).unwrap_or(7);
        let master = masters
            .iter()
            .find(|m| m.id == master_id)
            .or_else(|| masters.iter().find(|m| !m.title));
        let main = master.and_then(|m| {
            if m.title {
                masters.iter().find(|x| !x.title && x.id == m.follows)
            } else {
                Some(m)
            }
        });
        let (mi, li) = master
            .and_then(|m| model_of.get(&m.id).copied())
            .unwrap_or((0, 0));
        let scheme = if flags & 2 != 0 {
            master.map(|m| m.scheme).unwrap_or(DEFAULT_SCHEME)
        } else {
            scheme_of(s)
                .or(master.map(|m| m.scheme))
                .unwrap_or(DEFAULT_SCHEME)
        };
        let styles: Vec<Option<Levels>> = main
            .map(|m| m.styles.clone())
            .unwrap_or_else(|| vec![None; 9]);
        let hidden = s
            .child(rt::SLIDE_SHOW_SLIDE_INFO)
            .is_some_and(|a| a.data.get(10).is_some_and(|f| f & 4 != 0));
        let hf = s
            .children()
            .find(|k| k.typ == rt::HEADERS_FOOTERS)
            .map(|k| headers_footers(&k))
            .or_else(|| master.and_then(|m| m.hf.clone()))
            .unwrap_or_else(|| doc_hf.clone());

        let (oshapes, bg) = match s
            .child(rt::DRAWING)
            .and_then(|d| d.child(escher::DG_CONTAINER))
        {
            Some(dg) => {
                let d = escher::drawing(&dg);
                (d.shapes, d.background)
            }
            None => (vec![], None),
        };
        let background = if flags & 4 != 0 {
            None
        } else {
            bg.as_ref().map(|b| self.background_fill(b, &scheme))
        };
        let ctx = SlideCtx {
            scheme,
            styles: &styles,
            master,
            outline,
            number,
            hf: &hf,
        };
        let mut out = vec![];
        for o in &oshapes {
            if let Some(x) = self.shape(o, &ctx, false, budget)? {
                out.push(x);
            }
        }
        // The master's date, footer and slide number shown on this slide.
        let title_slide = master.is_some_and(|m| m.title);
        if let Some(m) = master.filter(|_| !(title_slide && omit_title_footers)) {
            for o in &m.shapes {
                let Some(ph) = master_placeholder_of(o) else {
                    continue;
                };
                let show = match ph {
                    pt::MASTER_DATE => hf.date,
                    pt::MASTER_SLIDE_NUMBER => hf.slide_number,
                    pt::MASTER_FOOTER => hf.footer,
                    _ => false,
                };
                if show && let Some(x) = self.shape(o, &ctx, false, budget)? {
                    out.push(x);
                }
            }
        }
        Ok(Slide {
            name: None,
            master: mi,
            layout: li,
            background,
            shapes: out,
            hidden,
            show_master_shapes: flags & 1 != 0,
        })
    }

    /// The master placeholder a slide placeholder of type `ph` takes its
    /// position and properties from.
    fn master_placeholder<'m>(&self, ctx: &'m SlideCtx<'a, '_>, ph: u8) -> Option<&'m OShape<'a>> {
        let m = ctx.master?;
        let want: &[u8] = match ph {
            pt::TITLE | pt::VERTICAL_TITLE => &[pt::MASTER_TITLE, pt::MASTER_CENTER_TITLE],
            pt::CENTER_TITLE => &[pt::MASTER_CENTER_TITLE, pt::MASTER_TITLE],
            pt::SUBTITLE => &[pt::MASTER_SUBTITLE, pt::MASTER_BODY],
            pt::BODY | pt::VERTICAL_BODY => &[pt::MASTER_BODY, pt::MASTER_SUBTITLE],
            _ => &[],
        };
        want.iter().find_map(|w| {
            m.shapes
                .iter()
                .find(|s| master_placeholder_of(s) == Some(*w))
        })
    }

    fn shape(
        &mut self,
        o: &OShape<'a>,
        ctx: &SlideCtx<'a, '_>,
        in_group: bool,
        budget: &mut Budget,
    ) -> Result<Option<Shape>> {
        if o.flags & escher::F_DELETED != 0 {
            return Ok(None);
        }
        budget.shape(0)?;
        // A master's date, footer and slide number shown on a slide stay
        // placeholders there.
        let ph = placeholder_of(o).or_else(|| {
            master_placeholder_of(o).filter(|p| {
                matches!(
                    *p,
                    pt::MASTER_DATE | pt::MASTER_SLIDE_NUMBER | pt::MASTER_FOOTER
                )
            })
        });
        let master_ph = ph.and_then(|p| self.master_placeholder(ctx, p));
        let mut props = self.defaults.clone();
        if let Some(m) = master_ph {
            props.overlay(&m.props);
        }
        // The master shape it names as its own.
        let hsp = o
            .props
            .get(0x0301)
            .filter(|_| o.flags & escher::F_HAVE_MASTER != 0);
        if let Some(mp) = hsp.and_then(|id| self.master_props.get(&id)) {
            props.overlay(mp);
        }
        props.overlay(&o.props);
        let mut xf =
            shapes::xfrm(o, in_group).or_else(|| master_ph.and_then(|m| shapes::xfrm(m, false)));
        if o.is_group() {
            let Some(xf) = xf else { return Ok(None) };
            let g = o.group.unwrap_or([0, 0, 1, 1]);
            let mut kids = vec![];
            for c in &o.children {
                if let Some(x) = self.shape(c, ctx, true, budget)? {
                    kids.push(x);
                }
            }
            let child = Xfrm {
                x: g[0].into(),
                y: g[1].into(),
                w: i64::from(g[2].saturating_sub(g[0])).max(1),
                h: i64::from(g[3].saturating_sub(g[1])).max(1),
                ..Xfrm::default()
            };
            let mut s = Shape::new(
                ShapeKind::Group(Box::new(Group {
                    child,
                    shapes: kids,
                })),
                xf,
            );
            s.hidden = props.flag(0x03BF, 1) == Some(true);
            return Ok(Some(s));
        }
        let Some(xf) = xf.take() else { return Ok(None) };
        self.want_blips(&props);
        let sctx = shapes::Ctx {
            scheme: &ctx.scheme,
            blips: &self.blips,
        };
        let refs = shapes::refs(&props, &ctx.scheme);
        let line = shapes::line(&props, &refs);
        let shadow = shapes::shadow(&props, &refs);
        let pib = props.get(0x0104);
        let picture = pib.and_then(|i| {
            self.blips
                .get((i as usize).checked_sub(1)?)
                .copied()
                .flatten()
        });
        let chart = if o.flags & escher::F_OLE != 0 {
            self.ole_chart(o, budget)?
        } else {
            None
        };
        let kind = if let Some(xml) = chart {
            ShapeKind::Chart(xml)
        } else if let (Some(media), true) = (
            picture,
            o.spt == 75 || o.flags & escher::F_OLE != 0 || o.textbox.is_none(),
        ) {
            ShapeKind::Pic(Box::new(Pic {
                media,
                crop: shapes::crop(&props),
                geom: if o.spt == 75 || o.spt == 1 || o.spt == 0 {
                    Geometry::default()
                } else {
                    shapes::geometry(o, xf.w, xf.h)
                },
                line,
                shadow,
                alpha: None,
            }))
        } else if let Some(t) = props.complex(0x00C0).map(utf16).filter(|t| !t.is_empty()) {
            // WordArt: its text in its fill, filling the shape.
            ShapeKind::Sp(Box::new(Sp {
                geom: Geometry::default(),
                fill: Fill::None,
                line: Line::default(),
                shadow: None,
                text: Some(shapes::word_art(&props, &t, &refs, &sctx, xf.h)),
                ..Sp::default()
            }))
        } else {
            let connector = shapes::is_connector(o);
            let geom = shapes::geometry(o, xf.w, xf.h);
            let text = self.text_body(o, &props, ctx, master_ph);
            if let Some(t) = &text {
                budget.alloc(text_bytes(t))?;
            }
            ShapeKind::Sp(Box::new(Sp {
                geom,
                fill: if connector {
                    Fill::None
                } else {
                    shapes::fill(&props, &sctx, &refs)
                },
                line,
                shadow,
                text: if connector { None } else { text },
                connector: connector && o.textbox.is_none(),
                ..Sp::default()
            }))
        };
        let mut s = Shape::new(kind, xf);
        s.hidden = props.flag(0x03BF, 1) == Some(true);
        s.placeholder = ph.and_then(placeholder_kind);
        s.link = o.client_data.and_then(|cd| self.shape_link(&cd));
        Ok(Some(s))
    }

    /// The chart an OLE object shape holds, when it holds one.
    fn ole_chart(&self, o: &OShape<'a>, budget: &mut Budget) -> Result<Option<String>> {
        let stg = o
            .client_data
            .and_then(|cd| cd.child(rt::EX_OBJ_REF_ATOM))
            .filter(|a| a.data.len() >= 4)
            .and_then(|a| self.objects.get(&Cur::new(a.data).u32()))
            .and_then(|pid| self.object(*pid))
            .filter(|s| s.typ == rt::EX_OLE_OBJ_STG);
        match stg {
            Some(s) => ole::chart(&s, budget),
            None => Ok(None),
        }
    }

    fn shape_link(&self, cd: &Rec) -> Option<Link> {
        let info = cd
            .children()
            .find(|k| k.typ == rt::INTERACTIVE_INFO && k.inst == 0)?;
        let a = info.child(rt::INTERACTIVE_INFO_ATOM)?;
        let mut b = [0u8; 16];
        b.copy_from_slice(a.data.get(..16)?);
        self.link_of(&b)
    }

    fn link_of(&self, info: &[u8; 16]) -> Option<Link> {
        let id = u32::from_le_bytes([info[4], info[5], info[6], info[7]]);
        match info[8] {
            4 => self.links.get(&id).cloned(),
            3 => match info[10] {
                1 => Some(Link::NextSlide),
                2 => Some(Link::PrevSlide),
                3 => Some(Link::FirstSlide),
                4 => Some(Link::LastSlide),
                _ => None,
            },
            _ => None,
        }
    }

    fn text_body(
        &self,
        o: &OShape<'a>,
        props: &Props,
        ctx: &SlideCtx<'a, '_>,
        master_ph: Option<&OShape<'a>>,
    ) -> Option<TextBody> {
        let tb = o.textbox?;
        let mut bodies = text::read_bodies(tb.children());
        let ruler = tb.child(rt::TEXT_RULER).map(|r| text::read_ruler(r.data));
        let body = if let Some(r) = tb.child(rt::OUTLINE_TEXT_REF) {
            let i = Cur::new(r.data).u32() as usize;
            let mut b = ctx.outline.get(i)?.clone();
            if ruler.is_some() {
                b.ruler = ruler;
            }
            b
        } else {
            bodies.drain(..).next()?
        };
        let mut levels = self.levels(ctx.styles, body.text_type);
        // A placeholder's text follows its master placeholder's own
        // formatting (a title master's, chiefly) over the master styles.
        if let Some(mb) = master_ph
            .and_then(|m| m.textbox)
            .and_then(|tb| text::read_bodies(tb.children()).into_iter().next())
        {
            text::overlay_levels(&mut levels, &mb);
        }
        let links = |info: &[u8; 16]| self.link_of(info);
        let mut body = body;
        if let Some(tags) = o.client_data.and_then(|c| c.child(pp9::PROG_TAGS))
            && let Some(k) = pp9::tag_records(&tags)
                .iter()
                .find(|k| k.typ == pp9::STYLE_TEXT_PROP9)
        {
            body.pp9 = pp9::style_text_prop9(k.data);
        }
        let tctx = TextCtx {
            bullet_media: &self.bullet_media,
            fonts: &self.fonts,
            scheme: &ctx.scheme,
            base: &levels,
            slide_number: ctx.number,
            footer: &ctx.hf.footer_text,
            date: if ctx.hf.user_date {
                &ctx.hf.date_text
            } else {
                ""
            },
            links: &links,
        };
        let paras = text::paragraphs(&body, &tctx);
        Some(TextBody {
            body: shapes::body_props(props),
            paras,
            levels: ListStyle::default(),
        })
    }
}

/// What a slide's shapes are converted against.
struct SlideCtx<'a, 'b> {
    scheme: [Rgb; 8],
    styles: &'b [Option<Levels>],
    master: Option<&'b MasterSlide<'a>>,
    outline: &'b [RawText],
    number: usize,
    hf: &'b HeadersFooters,
}

static NO_HF: std::sync::LazyLock<HeadersFooters> =
    std::sync::LazyLock::new(HeadersFooters::default);

impl<'a, 'b> SlideCtx<'a, 'b> {
    fn master(m: &'b MasterSlide<'a>) -> SlideCtx<'a, 'b> {
        SlideCtx {
            scheme: m.scheme,
            styles: &m.styles,
            master: None,
            outline: &[],
            number: 1,
            hf: &NO_HF,
        }
    }
}

/// A slide shape's placeholder type: a position of -1 says it is none
/// ([MS-PPT] 2.7.8).
fn placeholder_of(s: &OShape) -> Option<u8> {
    let cd = s.client_data?;
    let a = cd.child(rt::PLACEHOLDER_ATOM)?;
    let pos = Cur::new(a.data).i32();
    let id = *a.data.get(4)?;
    (pos != -1 && id != 0).then_some(id)
}

/// A master shape's placeholder type, whatever its position: masters'
/// placeholders are written with -1 too.
fn master_placeholder_of(s: &OShape) -> Option<u8> {
    let a = s.client_data?.child(rt::PLACEHOLDER_ATOM)?;
    let id = *a.data.get(4)?;
    (id != 0).then_some(id)
}

fn placeholder_kind(ph: u8) -> Option<Placeholder> {
    let kind = match ph {
        pt::TITLE | pt::VERTICAL_TITLE | pt::MASTER_TITLE => "title",
        pt::CENTER_TITLE | pt::MASTER_CENTER_TITLE => "ctrTitle",
        pt::SUBTITLE | pt::MASTER_SUBTITLE => "subTitle",
        pt::BODY | pt::VERTICAL_BODY | pt::MASTER_BODY => "body",
        pt::MASTER_DATE => "dt",
        pt::MASTER_FOOTER => "ftr",
        pt::MASTER_SLIDE_NUMBER => "sldNum",
        pt::MASTER_HEADER => return None,
        _ => "obj",
    };
    Some(Placeholder {
        kind,
        idx: match kind {
            "title" | "ctrTitle" => None,
            "dt" => Some(10),
            "ftr" => Some(11),
            "sldNum" => Some(12),
            _ => Some(u32::from(ph)),
        },
    })
}

fn blank_layout() -> Layout {
    Layout {
        name: "Blank".into(),
        kind: "blank",
        show_master_shapes: true,
        ..Layout::default()
    }
}

#[cfg(test)]
mod tests {
    use super::records::build::rec;
    use super::*;

    /// A persist directory of one entry of `count` offsets (100, 101...),
    /// its header holding the count's low 12 bits, then a user edit naming
    /// it with `seed`.
    fn stream(count: u32, seed: u32) -> (Vec<u8>, usize) {
        let mut body = (1 | (count & 0xFFF) << 20).to_le_bytes().to_vec();
        for k in 0..count {
            body.extend((100 + k).to_le_bytes());
        }
        let mut s = rec(0, 0, rt::PERSIST_DIRECTORY_ATOM, &body);
        let edit_at = s.len();
        let mut edit = vec![0; 8];
        edit.extend(0u32.to_le_bytes()); // no earlier edit
        edit.extend(0u32.to_le_bytes()); // the directory, at 0
        edit.extend(1u32.to_le_bytes());
        edit.extend(seed.to_le_bytes());
        s.extend(rec(0, 0, rt::USER_EDIT_ATOM, &edit));
        (s, edit_at)
    }

    #[test]
    fn persist_counts_past_4095_as_some_writers_store_them() {
        let (s, at) = stream(6003, 6003);
        let map = persist_directory(&s, Some(at));
        assert_eq!(map.len(), 6003);
        assert_eq!(map.get(&6003), Some(&(100 + 6002)));
        // A sound directory is read as it is.
        let (s, at) = stream(300, 300);
        let map = persist_directory(&s, Some(at));
        assert_eq!((map.len(), map.get(&300)), (300, Some(&399)));
    }
}
