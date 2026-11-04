#![cfg_attr(
    not(feature = "decrypt"),
    allow(dead_code, unused_mut, unused_imports, unreachable_code)
)]
use crate::*;
use std::collections::HashMap;
use std::io::Cursor;

use super::pdf_objstm::{self, ObjStm};
#[cfg(feature = "decrypt")]
use super::pdf_parse::crypt::{CryptDict, Decoder};
use super::pdf_parse::filters;
use super::pdf_parse::lex::{Lexer, Token};
use super::pdf_parse::parse::{
    parse_indirect_object_body, parse_object, parse_stream_head, skip_stream_data,
};
use super::pdf_parse::types::Primitive;
use super::pdf_raster::{self, Decrypt};

/// ClamAV `Heuristics.PDF.ObfuscatedNameObject`: a PDF **name object** (`/Name`)
/// that hex-escapes (`#XX`) a character that never requires escaping (an ASCII
/// letter or digit) *and* whose de-escaped form is one of the sensitive
/// action/feature keywords malware hides this way (`/J#61vaScript` → `JavaScript`,
/// `/Ope#6eAction` → `OpenAction`). The PDF spec only needs `#`-escaping for
/// whitespace, the delimiters `()<>[]{}/%#`, and bytes outside `0x21..=0x7E`, so
/// escaping a plain alphanumeric is gratuitous.
///
/// Requiring the de-escaped name to be a *sensitive keyword* is deliberate: a lone
/// incidental escape in an ordinary name (e.g. `/C#31` → `C1`) is common in benign
/// PDFs and must not fire: stock ClamAV likewise flags the systematic
/// keyword-hiding case, not any single gratuitous escape. This keeps the heuristic
/// FP-safe enough to run by default.
pub fn has_obfuscated_name_object(data: &[u8]) -> bool {
    // Action/feature name objects abused to launch code or fetch remote content;
    // obfuscating one of these is the evasion signal (PDF spec keywords).
    const SENSITIVE: &[&[u8]] = &[
        b"JavaScript",
        b"JS",
        b"OpenAction",
        b"AA",
        b"Launch",
        b"URI",
        b"SubmitForm",
        b"ImportData",
        b"GoToR",
        b"GoToE",
        b"RichMediaExecute",
        b"EmbeddedFile",
        b"EmbeddedFiles",
        b"XFA",
    ];
    // Name-object terminators: PDF whitespace and delimiters.
    const TERM: &[u8] = b" \t\r\n\0()<>[]{}/%";
    let mut i = 0;
    while i < data.len() {
        if data[i] != b'/' {
            i += 1;
            continue;
        }
        // Scan the name token following `/`, decoding `#XX` escapes into `decoded`
        // and noting whether any escaped a gratuitous alphanumeric.
        let mut j = i + 1;
        let mut decoded: Vec<u8> = Vec::new();
        let mut gratuitous = false;
        while j < data.len() && !TERM.contains(&data[j]) {
            if data[j] == b'#'
                && j + 2 < data.len()
                && let Ok(b) =
                    u8::from_str_radix(std::str::from_utf8(&data[j + 1..j + 3]).unwrap_or("x"), 16)
            {
                if b.is_ascii_alphanumeric() {
                    gratuitous = true;
                }
                decoded.push(b);
                j += 3;
                continue;
            }
            decoded.push(data[j]);
            j += 1;
        }
        // Flag only an obfuscated *sensitive* name, not any incidental escape.
        if gratuitous && SENSITIVE.contains(&decoded.as_slice()) {
            return true;
        }
        i = j.max(i + 1);
    }
    false
}

/// PDF: emit each stream object's content, decoded through its `/Filter` chain
/// by the bounded readers (so a Flate bomb trips the budget), and the active
/// content of every object as the members `pdf-javascript` and `pdf-uris`.
///
/// The objects are found by scanning for `N G obj`, so a broken xref, common in
/// malicious PDFs, does not stop extraction. The objects inside object streams
/// are read from the decoded streams. The parser is depth-bounded
/// (`MAX_DEPTH`), avoiding nested-object stack overflow.
///
/// The active content is emitted after the scan, whatever ended it: a limit is
/// reported once the content found before it has been seen.
pub(crate) fn extract_pdf(data: &[u8], budget: &mut Budget, visit: Sink) -> crate::Extracted {
    // --- Phase 1: encryption ---
    // Without the `decrypt` feature there is no cipher stack; an encrypted PDF
    // is reported unsupported (never parsed as garbage, never silently clean).
    #[cfg(not(feature = "decrypt"))]
    if pdf_has_encrypt(data) {
        budget.count_entry()?;
        let e = Entry::unsupported(
            "pdf-encrypted".to_string(),
            data.len() as u64,
            true,
            "encrypted PDF",
        );
        return Ok(visit(e, budget));
    }

    #[cfg(feature = "decrypt")]
    let crypt_info = detect_encryption(data);

    #[cfg(feature = "decrypt")]
    let decoder = if let Some(ref encrypt_dict) = crypt_info {
        let doc_id = find_doc_id(data).unwrap_or_default();
        let mut candidates: Vec<&[u8]> = vec![b""];
        for pw in &budget.passwords {
            candidates.push(pw.as_bytes());
        }
        let mut found = None;
        let mut any_password_error = false;
        for pw in candidates {
            match Decoder::from_password(encrypt_dict, &doc_id, pw) {
                Ok(d) => {
                    found = Some(d);
                    break;
                }
                Err(_) => {
                    any_password_error = true;
                }
            }
        }
        match found {
            Some(d) => Some(d),
            None if any_password_error => {
                budget.count_entry()?;
                let e = Entry::unsupported(
                    "pdf-encrypted".to_string(),
                    data.len() as u64,
                    true,
                    "encrypted PDF",
                );
                return Ok(visit(e, budget));
            }
            None => None,
        }
    } else {
        None
    };

    // --- Phase 2: linear scan for objects ---
    // The strings of JavaScript actions and the URI/launch targets met on the
    // way are emitted as synthetic members after the scan, so signatures keyed
    // on `app.alert(`, `http://…`, launched commands, etc. match even when the
    // value is a direct string (indirect streams are already surfaced by the
    // stream path). ClamAV surfaces the same content.
    let mut harvest = Harvest::default();
    let walked = walk_objects(
        data,
        budget,
        visit,
        &mut harvest,
        #[cfg(feature = "decrypt")]
        decoder.as_ref(),
    );
    if matches!(walked, Ok(Some(_))) {
        return walked;
    }
    // A limit that ended the scan does not take the content found before it
    // away: the members are seen first and the limit is reported after them.
    let mut end = walked;
    for (name, acc) in [("pdf-javascript", harvest.js), ("pdf-uris", harvest.uri)] {
        if acc.is_empty() {
            continue;
        }
        if let Err(hit) = budget.count_entry() {
            end = end.and(Err(hit));
        }
        if let Some(r) = visit(Entry::new(name.to_string(), acc), budget) {
            return Ok(Some(r));
        }
    }
    end
}

/// The scan of [`extract_pdf`]: hands each stream object, decoded, to `visit`
/// and the strings of the actions of every object to `harvest`. It ends with
/// the first limit of the whole scan; `harvest` keeps what it took until then.
/// A stream past the object limit, or a string the harvest has no room for,
/// is left out and the scan goes on ([`Budget::skip`]).
fn walk_objects(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink,
    harvest: &mut Harvest,
    #[cfg(feature = "decrypt")] decoder: Option<&Decoder>,
) -> crate::Extracted {
    let mut lex = Lexer::new(data);
    // Decrypts the strings and streams an image's color space names, and the
    // object streams that hold objects it names.
    #[cfg(feature = "decrypt")]
    let decrypt = |id: u32, r#gen: u32, bytes: &mut Vec<u8>| {
        if let Some(dec) = decoder {
            dec.decrypt_stream(id, r#gen, bytes);
        }
    };
    #[cfg(not(feature = "decrypt"))]
    let decrypt = |_: u32, _: u32, _: &mut Vec<u8>| {};
    // Found by number when a stream's `/Filter`, `/DecodeParms` or, for an
    // image, `/ColorSpace` is a reference to one.
    let mut objects = Objects::new(data, &decrypt, budget.limits().max_buffer_bytes);
    while let Some((obj_id, r#gen, obj_start)) = lex.find_next_obj() {
        lex.set_pos(obj_start);
        let Some((obj, end)) = parse_indirect_object_body(&mut lex) else {
            // An object that does not parse (an unterminated string in it runs
            // to the end of the file) is not the end of the document: the scan
            // goes on from its start, as a reader going by the cross-reference
            // table reaches every object after it. Every object of a crafted
            // file can claim the rest of it, so the bytes parsed again are
            // charged to the extraction budget.
            budget.charge_reparsed(lex.pos().saturating_sub(obj_start) as u64)?;
            lex.set_pos(obj_start);
            continue;
        };
        // An object that does not end where it says (a string left open takes
        // the rest of the file for itself, and the dictionary round it still
        // parses) must not take the objects after it. Parsing resumes after the
        // first `endobj`, as a reader that goes by the cross-reference table
        // finds each of them. The bytes parsed again are charged as above.
        if let Some(p) = memchr::memmem::find(
            &data[obj_start.min(data.len())..end.min(data.len())],
            b"endobj",
        ) {
            let stop = obj_start + p + b"endobj".len();
            if end > stop {
                budget.charge_reparsed((end - stop) as u64)?;
                lex.set_pos(stop);
            }
        }
        budget.count_entry()?;

        // Harvest JS / URI / launch strings from this object's dictionary(s).
        // Strings are decrypted with the object key when the doc is encrypted,
        // so the recovered plaintext matches (same key schedule as streams).
        // The strings that references name are found with the room the budget
        // has left.
        objects.room = budget.left();
        objects.entries = budget.limits().max_members.saturating_sub(budget.files);
        harvest_actions(
            &obj,
            Source::Object(obj_id, r#gen),
            &mut objects,
            budget,
            harvest,
        );

        if let Primitive::Stream {
            info,
            data: mut stream_data,
        } = obj
        {
            #[cfg(feature = "decrypt")]
            if let Some(dec) = decoder {
                dec.decrypt_stream(obj_id, r#gen, &mut stream_data);
            }
            let raw_len = stream_data.len() as u64;
            let cap = budget.reserve()?;
            objects.room = budget.left();
            let info = resolve_filter_references(info, &mut objects);
            let outcome = apply_filters(&stream_data, &info, cap)?;
            if outcome.truncated {
                // The stream decoded past the cap, up to which it is held. Past
                // the object limit it is left out and the scan goes on with the
                // next object, its ratio the reason when that is past the limit
                // too.
                let spent = outcome.buf.len() as u64;
                match ratio_guard(raw_len, cap.saturating_add(1), budget) {
                    Err(hit) if cap == budget.limits().max_buffer_bytes => {
                        budget.commit(spent);
                        budget.skip(format_args!("{}", hit.reason));
                    }
                    _ => budget.over_cap(cap, spent, format_args!("pdf stream {obj_id} {gen}"))?,
                }
                budget.charge_reparsed(objects.take_parsed())?;
                continue;
            }
            let buf = outcome.buf;
            budget.commit(buf.len() as u64);
            // The objects inside an object stream are harvested as the ones
            // of the file are. A limit reached doing so is reported after the
            // member is seen, as for the objects its references named.
            let header = (pdf_objstm::may_be_object_stream(&info)
                && !outcome.decode_error
                && !outcome.unknown_filter)
                .then(|| object_stream_header(&buf, &info, &mut objects))
                .flatten();
            let contained = header.map(|(count, first)| {
                harvest_object_stream(&buf, count, first, &mut objects, budget, harvest)
            });
            // A stream whose bytes an implemented filter failed to decode is
            // content we failed to produce, not an empty object. Emitting it
            // as a zero-byte member says "scanned, nothing there" about bytes
            // nobody read, the silent skip this scanner exists to avoid. Say
            // so instead. But a stream that DECODED to empty (legal: an
            // empty page-content stream carries no bytes to hide) is a
            // scanned empty member, not an undecodable one.
            //
            // Image codecs (`apply_filters` stops at DCTDecode, JPXDecode,
            // CCITTFaxDecode) pass the raw bytes through, so those streams
            // are scanned as their raw content: the signatures match the
            // bytes either way.
            //
            // An undecodable stream's raw bytes are scanned in its place, as
            // ClamAV scans them: a filter that names Flate over data that is
            // not (a ZIP, say) hides nothing from that scan.
            let entry = if buf.is_empty() && raw_len > 0 && outcome.decode_error {
                let cap = budget.reserve()?;
                if raw_len > cap {
                    budget.over_cap(cap, 0, format_args!("pdf stream {obj_id} {gen}"))?;
                    budget.charge_reparsed(objects.take_parsed())?;
                    continue;
                }
                budget.commit(raw_len);
                let mut e = Entry::new(format!("pdf-obj-{obj_id}-{gen}"), stream_data);
                e.unsupported = Some("PDF stream could not be decoded; its raw bytes were scanned");
                e
            } else {
                let mut e = Entry::new(format!("pdf-obj-{obj_id}-{gen}"), buf);
                e.object_stream = header.is_some();
                if outcome.unknown_filter {
                    e.unsupported = Some(
                        "PDF stream uses a filter that is not decoded; its bytes were \
                         scanned as far as the filters before it decode them",
                    );
                } else if outcome.part_way {
                    e.unsupported = Some(
                        "PDF stream failed to decode part way; the bytes before the \
                         failure were scanned",
                    );
                }
                // An image whose bytes are samples says how to read them, for
                // a consumer that asked (`Budget::set_rasters`).
                if budget.rasters && !outcome.unknown_filter {
                    let room = budget.reserve().unwrap_or(0);
                    objects.room = budget.left();
                    e.raster =
                        pdf_raster::raster_of(&info, &mut objects, (obj_id, r#gen), &decrypt, room);
                }
                e
            };
            // The objects its references named were parsed again: charged
            // after the member is seen, so that a limit reached here does not
            // take its bytes out of the scan.
            let reparsed = objects.take_parsed();
            if let Some(r) = visit(entry, budget) {
                return Ok(Some(r));
            }
            budget.charge_reparsed(reparsed)?;
            if let Some(contained) = contained {
                contained?;
            }
        } else {
            // The objects the harvest followed were parsed again.
            budget.charge_reparsed(objects.take_parsed())?;
        }
    }
    // A string of the actions did not fit: the harvest stopped there, and the
    // objects after it were still scanned.
    if harvest.full {
        budget.skip(format_args!("pdf actions exceed budget"));
    }
    // The references into the object streams that were not read found
    // nothing: the rest of the scan went on without them.
    if objects.unread {
        return Err(LimitHit::new(
            "pdf object streams exceed budget".to_string(),
        ));
    }
    Ok(None)
}

/// PDF dictionary keys whose values carry executable/active content.
const JS_KEYS: &[&str] = &["JS", "JavaScript"];
/// Keys whose values carry a URI / launch target / submitted URL.
const URI_KEYS: &[&str] = &["URI", "URL", "Launch", "F", "Win", "SubmitForm"];

/// The strings of the active content of a document: the scripts, and the
/// URI/launch targets. Each string is followed by a line end.
#[derive(Default)]
struct Harvest {
    js: Vec<u8>,
    uri: Vec<u8>,
    /// A string did not fit in the room the budget has left, so nothing more
    /// is taken and the scan reports a limit.
    full: bool,
}

impl Harvest {
    /// Adds `string` to the targets (`uri`) or to the scripts, and charges it
    /// to the budget. A string that the budget has no room for, or that would
    /// take a member past `max_buffer_bytes`, is not added: the harvest is
    /// `full`.
    fn add(&mut self, uri: bool, string: &[u8], budget: &mut Budget) {
        let held = if uri { &mut self.uri } else { &mut self.js };
        let n = string.len() as u64 + 1;
        if n > budget.reserve().unwrap_or(0)
            || held.len() as u64 + n > budget.limits().max_buffer_bytes
        {
            self.full = true;
            return;
        }
        budget.commit(n);
        held.extend_from_slice(string);
        held.push(b'\n');
    }
}

/// Recursively walk a parsed object, collecting the strings of the keys of
/// active content (`/JS`, `/JavaScript`) and of URI/launch targets into `out`.
/// `held` says how the strings of `obj` are encrypted. Depth-bounded to match
/// the parser and to bound crafted nesting.
fn harvest_actions(
    obj: &Primitive,
    held: Source,
    objects: &mut Objects<'_>,
    budget: &mut Budget,
    out: &mut Harvest,
) {
    harvest_inner(obj, held, objects, budget, out, 0);
}

fn harvest_inner(
    obj: &Primitive,
    held: Source,
    objects: &mut Objects<'_>,
    budget: &mut Budget,
    out: &mut Harvest,
    depth: u32,
) {
    if depth > 32 || out.full {
        return;
    }
    match obj {
        Primitive::Dictionary(d) | Primitive::Stream { info: d, .. } => {
            for (key, val) in d {
                if JS_KEYS.contains(&key.as_str()) {
                    harvest_value(val, false, held, objects, budget, out);
                } else if URI_KEYS.contains(&key.as_str()) {
                    harvest_value(val, true, held, objects, budget, out);
                }
                harvest_inner(val, held, objects, budget, out, depth + 1);
            }
        }
        Primitive::Array(items) => {
            for it in items {
                harvest_inner(it, held, objects, budget, out, depth + 1);
            }
        }
        _ => {}
    }
}

/// Adds the string that the value of a key of active content is, or names, to
/// `out`. An object that a reference names is read only if it is a string: a
/// stream is a member of its own (a script, or an embedded file under `/F`),
/// and a dictionary is harvested as the object it is.
fn harvest_value(
    value: &Primitive,
    uri: bool,
    held: Source,
    objects: &mut Objects<'_>,
    budget: &mut Budget,
    out: &mut Harvest,
) {
    let (mut string, source) = match value {
        Primitive::Reference(_) => {
            // Following a reference parses the object it names, and the bytes
            // are charged once the object being harvested is done. Stop at
            // the room one member has: an array of links to one large object
            // would parse it for each.
            if objects.parsed >= budget.reserve().unwrap_or(0) {
                out.full = true;
                return;
            }
            let Some(found) = objects.follow_string(value) else {
                return;
            };
            found
        }
        _ => match value.as_str() {
            Some(s) => (s.to_vec(), Source::Held),
            None => return,
        },
    };
    source.or(held).decrypt(objects.decrypt, &mut string);
    out.add(uri, &string, budget);
}

/// The `/N` and `/First` of the stream with dictionary `info`, decoded to
/// `decoded`, if it is an object stream.
fn object_stream_header(
    decoded: &[u8],
    info: &HashMap<String, Primitive>,
    objects: &mut Objects<'_>,
) -> Option<(i64, i64)> {
    let mut number = |key: &str| {
        info.get(key)
            .and_then(|p| objects.follow(p))
            .and_then(|(value, _)| value.as_i64())
    };
    let (count, first) = (number("N")?, number("First")?);
    pdf_objstm::is_object_stream(info, count, first, decoded).then_some((count, first))
}

/// Gives each object inside the object stream `decoded`, of `count` objects
/// from `first`, to the harvest, as an object of the file is given. The stream
/// was decrypted as a whole, so the strings inside are plain. Each object
/// counts as an entry, and the bytes that more than one object parses are
/// charged as the objects of the file are when they are parsed again.
fn harvest_object_stream(
    decoded: &[u8],
    count: i64,
    first: i64,
    objects: &mut Objects<'_>,
    budget: &mut Budget,
    out: &mut Harvest,
) -> Result<(), LimitHit> {
    let left = budget.limits().max_members.saturating_sub(budget.files);
    let mut table = pdf_objstm::table(decoded, count, first, left.saturating_add(1));
    table.sort_by_key(|&(_, offset)| offset);
    let mut parsed_to = 0;
    for (_, offset) in table {
        if out.full {
            break;
        }
        budget.count_entry()?;
        let (object, end) = pdf_objstm::object_at(decoded, offset);
        budget.charge_reparsed(parsed_to.min(end).saturating_sub(offset) as u64)?;
        parsed_to = parsed_to.max(end);
        if let Some(object) = object {
            harvest_actions(&object, Source::Compressed, objects, budget, out);
        }
    }
    Ok(())
}

/// How the strings of an object that [`Objects::follow`] returned are
/// encrypted.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Source {
    /// Not reached through a reference: part of the object that held it.
    Held,
    /// An object of the file, with this number and generation: its strings
    /// are encrypted with the key of that object.
    Object(u32, u32),
    /// An object inside an object stream. The stream is decrypted as a whole,
    /// so the strings inside it are plain.
    Compressed,
}

impl Source {
    /// `self`, or `held` when the object was not reached through a reference.
    pub(crate) fn or(self, held: Source) -> Source {
        match self {
            Source::Held => held,
            found => found,
        }
    }

    /// Decrypts `bytes`, a string or a stream of the object, unless the object
    /// is inside an object stream.
    pub(crate) fn decrypt(self, decrypt: Decrypt<'_>, bytes: &mut Vec<u8>) {
        if let Source::Object(number, generation) = self {
            decrypt(number, generation, bytes);
        }
    }
}

/// The objects of a file: the last definition of each number, and its object
/// streams in file order.
struct Index {
    /// Number to `(generation, offset)`. The last definition wins, as in an
    /// incremental update.
    objects: HashMap<u32, (u32, usize)>,
    streams: Vec<ObjStm>,
}

impl Index {
    fn build(data: &[u8]) -> Self {
        let mut objects = HashMap::new();
        let mut streams = Vec::new();
        let mut lex = Lexer::new(data);
        let mut next = lex.find_next_obj();
        while let Some((number, generation, start)) = next {
            objects.insert(number, (generation, start));
            // An object's dictionary ends before the next definition starts,
            // so that the bytes read for each are the ones it owns.
            let following = lex.find_next_obj();
            let end = following.map_or(data.len(), |(_, _, at)| at);
            let mut head = Lexer::new(&data[..end]);
            head.set_pos(start);
            let Some(info) = parse_stream_head(&mut head) else {
                next = following;
                continue;
            };
            if pdf_objstm::may_be_object_stream(&info) {
                streams.push(ObjStm {
                    number,
                    generation,
                    start,
                    decoded: Vec::new(),
                });
            }
            // The data of a stream is not searched for definitions: text in
            // it is not an object of the file.
            lex.set_pos(head.pos());
            skip_stream_data(&mut lex);
            next = match following {
                Some((_, _, at)) if at > lex.pos() => {
                    lex.set_pos(at);
                    following
                }
                _ => lex.find_next_obj(),
            };
        }
        Index { objects, streams }
    }
}

/// An object inside an object stream.
#[derive(Clone, Copy)]
struct Member {
    /// Its object stream, as numbered in [`Index::streams`].
    stream: usize,
    /// Where it starts in what the stream decodes to.
    offset: usize,
    /// Where the object stream starts in the file, to compare with a
    /// definition outside it: the last in the file wins.
    at: usize,
}

/// The objects of a document, found by number when a stream names one.
pub(crate) struct Objects<'a> {
    data: &'a [u8],
    decrypt: Decrypt<'a>,
    /// The objects of the file, built on the first use.
    index: Option<Index>,
    /// The objects inside the object streams, by number, built on the first
    /// use. Each object stream is decoded once for it.
    members: Option<HashMap<u32, Member>>,
    /// Set while the object streams are read: a reference met then is looked
    /// up in the file only, so that no stream is read while another is.
    reading: bool,
    /// Bytes parsed or decoded to follow references since
    /// [`Self::take_parsed`]. Every stream of a crafted file can name the same
    /// large object, so the caller charges them to its budget.
    parsed: u64,
    /// The most the object streams may decode to, in all, until the caller sets
    /// it again: what the budget has left of the total. A decode takes its
    /// bytes out of it.
    pub(super) room: u64,
    /// The most one object stream may decode to.
    each: u64,
    /// The most entries the object streams may hold in all.
    pub(super) entries: u64,
    /// An object stream was not read, for lack of room: what it holds may be
    /// named by references that found nothing.
    unread: bool,
    /// The JBIG2 globals streams read so far, by object number: `None` for
    /// one that could not be read. Several images name the same stream.
    pub(super) globals: HashMap<u32, Option<std::sync::Arc<[u8]>>>,
}

impl<'a> Objects<'a> {
    fn new(data: &'a [u8], decrypt: Decrypt<'a>, each: u64) -> Self {
        Objects {
            data,
            decrypt,
            index: None,
            members: None,
            reading: false,
            parsed: 0,
            room: 0,
            each,
            entries: 0,
            unread: false,
            globals: HashMap::new(),
        }
    }

    /// The bytes parsed to follow references since the last call, and the ones
    /// [`Self::add_parsed`] counted.
    pub(crate) fn take_parsed(&mut self) -> u64 {
        std::mem::take(&mut self.parsed)
    }

    /// Counts `n` bytes made from an object that was followed, to be charged
    /// with the ones parsed.
    pub(crate) fn add_parsed(&mut self, n: u64) {
        self.parsed = self.parsed.saturating_add(n);
    }

    /// The object `p` names, and where it was found when it was reached
    /// through a reference; `p` itself when it is not one. A reference to a
    /// reference is followed, a loop of them not forever. `None`: it names
    /// nothing.
    pub(crate) fn follow(&mut self, p: &Primitive) -> Option<(Primitive, Source)> {
        self.follow_as(p, false)
    }

    /// [`Self::follow`] for a caller that wants a string: the string `p` names,
    /// and where it was found. An object of the file that does not begin as a
    /// string or a reference is not parsed, so naming a stream costs nothing.
    pub(crate) fn follow_string(&mut self, p: &Primitive) -> Option<(Vec<u8>, Source)> {
        match self.follow_as(p, true)? {
            (Primitive::String(s), from) => Some((s, from)),
            _ => None,
        }
    }

    fn follow_as(&mut self, p: &Primitive, string: bool) -> Option<(Primitive, Source)> {
        let mut at = p.clone();
        let mut from = Source::Held;
        for _ in 0..8 {
            let Primitive::Reference(id) = at else {
                return Some((at, from));
            };
            (at, from) = self.object(id, string)?;
        }
        None
    }

    /// The object numbered `id`: the last definition in the file, wherever it
    /// is, in the body of the file or inside an object stream. `string`: the
    /// caller wants a string, so an object of the file that does not begin as a
    /// string or a reference (a number) is not parsed.
    fn object(&mut self, id: u32, string: bool) -> Option<(Primitive, Source)> {
        let data = self.data;
        let index = self.index.get_or_insert_with(|| Index::build(data));
        let top = index.objects.get(&id).copied();
        let packed = self.member(id);
        if let Some(m) = packed
            && top.is_none_or(|(_, start)| start < m.at)
        {
            let decoded = &self.index.as_ref()?.streams[m.stream].decoded;
            let (object, end) = pdf_objstm::object_at(decoded, m.offset);
            self.parsed = self
                .parsed
                .saturating_add(end.saturating_sub(m.offset) as u64);
            return Some((object?, Source::Compressed));
        }
        let (r#gen, start) = top?;
        let mut lex = Lexer::new(data);
        lex.set_pos(start);
        if string && !matches!(lex.next_token(), Token::String(_) | Token::Integer(_)) {
            return None;
        }
        lex.set_pos(start);
        let parsed = parse_indirect_object_body(&mut lex);
        // An object that does not parse can have run to the end of the file.
        self.parsed = self
            .parsed
            .saturating_add(lex.pos().saturating_sub(start) as u64);
        Some((parsed?.0, Source::Object(id, r#gen)))
    }

    /// Where the object `id` is inside an object stream, if it is in one. The
    /// object streams are decoded the first time this is asked.
    fn member(&mut self, id: u32) -> Option<Member> {
        if self.reading || self.index.as_ref()?.streams.is_empty() {
            return None;
        }
        if self.members.is_none() {
            self.read_streams();
        }
        self.members.as_ref()?.get(&id).copied()
    }

    /// Decodes each object stream of the file once and lists the objects
    /// inside. Of several definitions of a number, the last in the file wins.
    fn read_streams(&mut self) {
        self.reading = true;
        let mut members: HashMap<u32, Member> = HashMap::new();
        let streams = self.index.as_ref().map_or(0, |i| i.streams.len());
        // Every object stream of a crafted file can run to the end of it, so
        // the reading stops once it has parsed as much as it may decode. The
        // caller charges what was parsed, and the scan reports the streams
        // left unread.
        let (before, allowed) = (self.parsed, self.room);
        for stream in 0..streams {
            if self.parsed.saturating_sub(before) >= allowed {
                self.unread = true;
                break;
            }
            let Some((at, table)) = self.read_stream(stream) else {
                continue;
            };
            for (number, offset) in table {
                if members.len() as u64 >= self.entries && !members.contains_key(&number) {
                    break;
                }
                members.insert(number, Member { stream, offset, at });
            }
        }
        self.reading = false;
        self.members = Some(members);
    }

    /// Decodes the object stream `i`, keeps what it decodes to, and returns
    /// where it starts in the file and where the objects inside it do. `None`:
    /// it cannot be read or is not an object stream, so no object is found in
    /// it.
    fn read_stream(&mut self, i: usize) -> Option<(usize, Vec<(u32, usize)>)> {
        let stream = self.index.as_ref()?.streams.get(i)?;
        let (number, generation, start) = (stream.number, stream.generation, stream.start);
        let mut lex = Lexer::new(self.data);
        lex.set_pos(start);
        let parsed = parse_indirect_object_body(&mut lex);
        self.parsed = self
            .parsed
            .saturating_add(lex.pos().saturating_sub(start) as u64);
        let (Primitive::Stream { info, mut data }, _) = parsed? else {
            return None;
        };
        (self.decrypt)(number, generation, &mut data);
        let info = resolve_filter_references(info, self);
        let cap = self.room.min(self.each);
        let outcome = apply_filters(&data, &info, cap).ok()?;
        if outcome.truncated {
            // What was decoded before the cut was work done: charged.
            self.add_parsed(cap);
            self.unread = true;
            return None;
        }
        if outcome.decode_error || outcome.unknown_filter {
            return None;
        }
        let decoded = outcome.buf;
        self.room = self.room.saturating_sub(decoded.len() as u64);
        self.add_parsed(decoded.len() as u64);
        let count = self.follow(info.get("N")?)?.0.as_i64()?;
        let first = self.follow(info.get("First")?)?.0.as_i64()?;
        if !pdf_objstm::is_object_stream(&info, count, first, &decoded) {
            return None;
        }
        let table = pdf_objstm::table(&decoded, count, first, self.entries);
        self.index.as_mut()?.streams[i].decoded = decoded;
        Some((start, table))
    }
}

/// `info` with the references in `/Filter` and `/DecodeParms` replaced by the
/// objects they name, which a PDF may use for either. The scan is object by
/// object, so a filter written as `7 0 R` was no filter at all, and the stream
/// was scanned compressed.
pub(crate) fn resolve_filter_references(
    mut info: HashMap<String, Primitive>,
    objects: &mut Objects<'_>,
) -> HashMap<String, Primitive> {
    let mut resolve = |p: &Primitive| -> Option<Primitive> {
        match objects.follow(p)?.0 {
            Primitive::Stream { .. } => None,
            other => Some(other),
        }
    };
    for key in ["Filter", "DecodeParms", "DP"] {
        let Some(value) = info.get(key) else {
            continue;
        };
        let resolved = match value {
            Primitive::Reference(_) => resolve(value),
            Primitive::Array(items)
                if items.iter().any(|i| matches!(i, Primitive::Reference(_))) =>
            {
                Some(Primitive::Array(
                    items
                        .iter()
                        .map(|i| resolve(i).unwrap_or(Primitive::Null))
                        .collect(),
                ))
            }
            _ => continue,
        };
        match resolved {
            Some(v) => {
                info.insert(key.to_string(), v);
            }
            // A reference to nothing: the stream names a filter it does not
            // give. Left as a name no decoder has, so the stream is reported.
            None if key == "Filter" => {
                info.insert(
                    key.to_string(),
                    Primitive::Name("<unresolved filter reference>".to_string()),
                );
            }
            None => {
                info.remove(key);
            }
        }
    }
    info
}

/// What decoding a stream's `/Filter` chain produced.
pub(crate) struct FilterOutcome {
    pub(crate) buf: Vec<u8>,
    /// An output cap was hit: the caller should treat the stream as over budget.
    pub(crate) truncated: bool,
    /// An implemented filter failed and nothing was recovered: the caller
    /// should report the stream undecodable rather than scan an empty buffer
    /// as though its bytes were examined. Distinct from "decoded to empty",
    /// which is a successful decode of an empty stream (legal, e.g. an empty
    /// page-content stream) and must NOT be reported undecodable.
    pub(crate) decode_error: bool,
    /// A filter decoded part of its input and failed on the rest: `buf` holds
    /// what came before the failure.
    pub(crate) part_way: bool,
    /// The chain names a filter that is neither decoded here nor an image
    /// codec: what follows it was not decoded, and `buf` is not the content.
    pub(crate) unknown_filter: bool,
}

/// A zlib stream decoded up to any damage, without its Adler-32 check.
fn salvage_zlib(data: &[u8], cap: u64) -> Salvaged {
    let failed = Salvaged {
        data: Vec::new(),
        over_cap: false,
        undecoded: true,
        cut_short: false,
    };
    match crate::inflate::zlib_body(data) {
        Some(body) => bounded_read_salvage(body, cap, true).unwrap_or(failed),
        None => failed,
    }
}

/// Decode a stream's raw bytes by applying its `/Filter` chain left to right,
/// honouring `/DecodeParms` (a single dict or an array aligned with the
/// filters). FlateDecode runs on the bounded `flate2` reader; the other PDF
/// filters use the pure decoders in [`filters`]. An unknown/unsupported filter
/// (e.g. an image codec like DCTDecode) stops the chain and passes through
/// whatever was decoded so far.
pub(crate) fn apply_filters(
    stream_data: &[u8],
    info: &HashMap<String, Primitive>,
    cap: u64,
) -> Result<FilterOutcome, LimitHit> {
    let names = filter_names(info);
    if names.is_empty() {
        let take = (stream_data.len() as u64).min(cap) as usize;
        return Ok(FilterOutcome {
            buf: stream_data[..take].to_vec(),
            truncated: stream_data.len() as u64 > cap,
            // No decoding involved: raw bytes pass through, nothing to fail.
            decode_error: false,
            part_way: false,
            unknown_filter: false,
        });
    }
    let parms = decode_parms_list(info, names.len());
    let mut buf = stream_data.to_vec();
    let mut part_way = false;
    let mut unknown_filter = false;
    // Whether an implemented filter failed with nothing recovered. Sticky
    // across the chain: only a successful decode producing content clears the
    // question, and the caller reports `unsupported` solely on
    // empty-output-with-error: a valid empty decode is a scanned empty member,
    // not an undecodable stream.
    let mut decode_error = false;
    for (idx, name) in names.iter().enumerate() {
        let parm = parms.get(idx).copied().flatten();
        let (out, truncated, err) = match name.as_str() {
            "FlateDecode" | "Fl" => {
                // Strict first: a valid-but-empty stream must succeed (the
                // caller emits it as a scanned empty member). Only on strict
                // failure fall back to salvage, and only if salvage ALSO
                // recovers nothing is the stream genuinely unreadable.
                // Salvage still matters: malware content is often in the
                // recoverable prefix, and PDF streams are commonly truncated
                // or patched. A leading-junk retry handles streams whose zlib
                // header is preceded by stray bytes.
                match bounded_read(flate2::read::ZlibDecoder::new(Cursor::new(&buf)), cap) {
                    Ok((out, truncated)) => (out, truncated, false),
                    Err(_) => {
                        let mut s = salvage_zlib(&buf, cap);
                        if s.data.is_empty()
                            && let Some(z) = buf.iter().position(|&b| b == 0x78)
                        {
                            s = salvage_zlib(&buf[z..], cap);
                        }
                        // Empty input decodes vacuously (nothing to fail on);
                        // only non-empty input decoding to nothing is an error.
                        let err = s.data.is_empty() && !buf.is_empty();
                        part_way |= s.undecoded && !s.data.is_empty();
                        (s.data, s.over_cap, err)
                    }
                }
            }
            // The pure decoders report no error channel, so an empty output
            // conservatively counts as a failure, today's behaviour,
            // unchanged. (A valid-but-empty LZW/ASCII85 stream is legal but
            // vanishingly rare in the wild, unlike empty Flate streams.)
            "LZWDecode" | "LZW" => {
                let (out, truncated) = filters::lzw_decode(&buf, early_change(parm), cap);
                let err = out.is_empty() && !buf.is_empty();
                (out, truncated, err)
            }
            "ASCII85Decode" | "A85" => {
                let (out, truncated) = filters::ascii85_decode(&buf, cap);
                let err = out.is_empty() && !buf.is_empty();
                (out, truncated, err)
            }
            "ASCIIHexDecode" | "AHx" => {
                let (out, truncated) = filters::ascii_hex_decode(&buf, cap);
                let err = out.is_empty() && !buf.is_empty();
                (out, truncated, err)
            }
            "RunLengthDecode" | "RL" => {
                let (out, truncated) = filters::run_length_decode(&buf, cap);
                let err = out.is_empty() && !buf.is_empty();
                (out, truncated, err)
            }
            // Unknown/unsupported filter: stop and emit what we have so far
            // (an image codec over raw bytes reads as the raw bytes, same as
            // ClamAV, which matches signatures against the stream content
            // without decoding image codecs either).
            // The identity crypt filter, which every reader passes over:
            // what a `/Crypt` before `/FlateDecode` leaves is still to be
            // inflated. (A named crypt filter is applied with the document's
            // key, in the pass that decrypts streams.)
            "Crypt" => continue,
            // An image codec ends the chain. Any other name is a filter no
            // decoder here has, and what follows it cannot be reached.
            "DCTDecode" | "DCT" | "JPXDecode" | "CCITTFaxDecode" | "CCF" | "JBIG2Decode" => break,
            _ => {
                unknown_filter = true;
                break;
            }
        };
        decode_error |= err;
        if truncated {
            return Ok(FilterOutcome {
                buf: out,
                truncated: true,
                decode_error,
                part_way,
                unknown_filter,
            });
        }
        buf = out;
    }
    let truncated = buf.len() as u64 > cap;
    Ok(FilterOutcome {
        buf,
        truncated,
        decode_error,
        part_way,
        unknown_filter,
    })
}

/// Collect the ordered list of filter names from `/Filter` (a single name or an
/// array of names).
pub(crate) fn filter_names(info: &HashMap<String, Primitive>) -> Vec<String> {
    match info.get("Filter") {
        Some(Primitive::Name(n)) => vec![n.clone()],
        Some(Primitive::Array(arr)) => arr
            .iter()
            .filter_map(|p| match p {
                Primitive::Name(n) => Some(n.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Map `/DecodeParms` to one optional dict per filter. A single dict applies to
/// the first filter; an array is aligned positionally with the filters (null /
/// non-dict entries yield `None`).
pub(crate) fn decode_parms_list(
    info: &HashMap<String, Primitive>,
    n: usize,
) -> Vec<Option<&HashMap<String, Primitive>>> {
    match info.get("DecodeParms").or_else(|| info.get("DP")) {
        Some(Primitive::Dictionary(d)) => {
            let mut v = vec![None; n];
            if n > 0 {
                v[0] = Some(d);
            }
            v
        }
        Some(Primitive::Array(arr)) => (0..n)
            .map(|i| match arr.get(i) {
                Some(Primitive::Dictionary(d)) => Some(d),
                _ => None,
            })
            .collect(),
        _ => vec![None; n],
    }
}

/// LZW `/EarlyChange`: 0 disables the one-code-early width bump; anything else
/// (including absent) is the PDF default of 1 → true.
fn early_change(parm: Option<&HashMap<String, Primitive>>) -> bool {
    !matches!(
        parm.and_then(|d| d.get("EarlyChange")),
        Some(Primitive::Integer(0))
    )
}

/// Parse the trailer dictionary (after the `trailer` keyword).
#[cfg(feature = "decrypt")]
fn parse_trailer_dict(data: &[u8]) -> Option<HashMap<String, Primitive>> {
    let trailer_pos = data.windows(7).position(|w| w == b"trailer")?;
    let mut lex = Lexer::new(data);
    lex.set_pos(trailer_pos + 7);
    if let Some(Primitive::Dictionary(dict)) = parse_object(&mut lex) {
        Some(dict)
    } else {
        None
    }
}

/// Check if a dictionary looks like a PDF encryption dictionary.
#[cfg(feature = "decrypt")]
fn is_encrypt_dict(dict: &HashMap<String, Primitive>) -> bool {
    dict.get("V").is_some()
        && dict.get("R").is_some()
        && dict.get("O").is_some()
        && dict.get("U").is_some()
}

/// Cheap `/Encrypt` presence check (no crypto), for the no-`decrypt` build.
#[cfg(not(feature = "decrypt"))]
fn pdf_has_encrypt(data: &[u8]) -> bool {
    data.windows(8).any(|w| w == b"/Encrypt")
}

/// Linear scan for an /Encrypt dictionary.
///
/// Two strategies:
/// 1. Look for an object whose dictionary contains `/Encrypt` (some generators embed it in the catalog).
/// 2. Look for a standalone encryption dictionary (has /V, /R, /O, /U keys): pypdf puts it
///    as a separate object, referenced from the trailer via indirect ref.
/// 3. Check the trailer dict directly for `/Encrypt` key.
#[cfg(feature = "decrypt")]
fn detect_encryption(data: &[u8]) -> Option<CryptDict> {
    let mut lex = Lexer::new(data);
    while let Some((_obj_id, _gen, obj_start)) = lex.find_next_obj() {
        lex.set_pos(obj_start);
        if let Some((Primitive::Dictionary(dict) | Primitive::Stream { info: dict, .. }, _end)) =
            parse_indirect_object_body(&mut lex)
        {
            // Strategy 1: dict contains an /Encrypt key
            if let Some(Primitive::Dictionary(enc)) = dict.get("Encrypt")
                && let Some(cd) = CryptDict::from_primitive(enc)
            {
                return Some(cd);
            }
            // Strategy 2: this IS the encrypt dict (standalone)
            if is_encrypt_dict(&dict)
                && let Some(cd) = CryptDict::from_primitive(&dict)
            {
                return Some(cd);
            }
        }
    }
    // Strategy 3: check trailer
    if let Some(trailer) = parse_trailer_dict(data)
        && let Some(Primitive::Dictionary(enc)) = trailer.get("Encrypt")
        && let Some(cd) = CryptDict::from_primitive(enc)
    {
        return Some(cd);
    }
    None
}

/// Find the document ID from the first /ID array found in any dictionary (objects or trailer).
#[cfg(feature = "decrypt")]
fn find_doc_id(data: &[u8]) -> Option<Vec<u8>> {
    // Check indirect objects
    let mut lex = Lexer::new(data);
    while let Some((_obj_id, _gen, obj_start)) = lex.find_next_obj() {
        lex.set_pos(obj_start);
        if let Some((Primitive::Dictionary(dict) | Primitive::Stream { info: dict, .. }, _end)) =
            parse_indirect_object_body(&mut lex)
            && let Some(Primitive::Array(arr)) = dict.get("ID")
            && let Some(Primitive::String(s)) = arr.first()
        {
            return Some(s.clone());
        }
    }
    // Check the trailer
    if let Some(trailer) = parse_trailer_dict(data)
        && let Some(Primitive::Array(arr)) = trailer.get("ID")
        && let Some(Primitive::String(s)) = arr.first()
    {
        return Some(s.clone());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn obfuscated_name_object_detection() {
        // Gratuitous escapes that spell a *sensitive* keyword → flagged.
        assert!(has_obfuscated_name_object(b"<</#4f#70enAction 2 0 R>>")); // /OpenAction
        assert!(has_obfuscated_name_object(b"/J#61vaScript")); // → JavaScript
        assert!(has_obfuscated_name_object(b"/La#75nch")); // → Launch
        // An incidental escape in an *ordinary* name is benign and must NOT fire
        // (this is the false positive that made it unsafe to run by default).
        assert!(!has_obfuscated_name_object(b"/Ty#70e")); // → Type (not sensitive)
        assert!(!has_obfuscated_name_object(b"/C#31")); // → C1 (a real benign-PDF FP)
        // No escapes, or only legitimate ones → not flagged.
        assert!(!has_obfuscated_name_object(b"/Type/Catalog/OpenAction"));
        assert!(!has_obfuscated_name_object(b"/JavaScript")); // unobfuscated → not flagged
        assert!(!has_obfuscated_name_object(b"/Weird#20Name")); // #20 = space, needs escaping
        assert!(!has_obfuscated_name_object(b"/Paren#28Name")); // #28 = '(', a delimiter
        assert!(!has_obfuscated_name_object(
            b"plain text with # but no name"
        ));
        // A trailing bare `#` must not panic or match.
        assert!(!has_obfuscated_name_object(b"/Name#"));
    }

    /// Minimal ASCII85 encoder (no `z` shorthand) for building chain fixtures.
    fn ascii85_encode(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in data.chunks(4) {
            let mut buf = [0u8; 4];
            buf[..chunk.len()].copy_from_slice(chunk);
            let val = u32::from_be_bytes(buf);
            let mut digits = [0u8; 5];
            let mut v = val;
            for d in digits.iter_mut().rev() {
                *d = (v % 85) as u8;
                v /= 85;
            }
            for &d in digits.iter().take(chunk.len() + 1) {
                out.push(b'!' + d);
            }
        }
        out.extend_from_slice(b"~>");
        out
    }

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// `/Filter [/ASCII85Decode /FlateDecode]` applied left to right recovers the
    /// original: raw = ascii85(flate(original)); ASCII85Decode then FlateDecode.
    #[test]
    fn chained_ascii85_then_flate() {
        let original = b"MALWARETEST chained filter payload \x00\x01\x02 the quick brown fox";
        let raw = ascii85_encode(&zlib_compress(original));

        let mut info: HashMap<String, Primitive> = HashMap::new();
        info.insert(
            "Filter".to_string(),
            Primitive::Array(vec![
                Primitive::Name("ASCII85Decode".to_string()),
                Primitive::Name("FlateDecode".to_string()),
            ]),
        );

        let outcome = apply_filters(&raw, &info, 1 << 20).unwrap();
        assert!(!outcome.truncated);
        assert!(!outcome.decode_error);
        assert_eq!(outcome.buf, original);
    }

    /// A valid-but-empty Flate stream (8 bytes of zlib wrapping zero content
    /// bytes, common as empty page-content) decodes successfully to nothing.
    /// It must surface as a scanned empty member, never as undecodable: the
    /// old emptiness check reported whole benign PDFs `UNSCANNABLE` for this.
    #[test]
    fn empty_flate_stream_is_clean_not_undecodable() {
        let raw = zlib_compress(b"");
        assert!(!raw.is_empty(), "the fixture itself must carry bytes");
        let mut info: HashMap<String, Primitive> = HashMap::new();
        info.insert(
            "Filter".to_string(),
            Primitive::Name("FlateDecode".to_string()),
        );
        let outcome = apply_filters(&raw, &info, 1 << 20).unwrap();
        assert!(!outcome.truncated);
        assert!(!outcome.decode_error);
        assert!(outcome.buf.is_empty());

        // End to end: no `unsupported` member may come out of it.
        let mut pdf = format!(
            "%PDF-1.5\n1 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
            raw.len()
        )
        .into_bytes();
        pdf.extend_from_slice(&raw);
        pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pdf, &pdf, &mut budget).unwrap();
        assert!(
            entries.iter().all(|e| e.unsupported.is_none()),
            "a valid empty stream must not poison the verdict: {:?}",
            entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
    }

    /// A `/Length 0` stream holds only the end of line before `endstream`,
    /// which is not data: an empty stream, not an undecodable one.
    #[test]
    fn the_line_end_before_endstream_is_not_data() {
        let pdf = b"%PDF-1.5\n12 0 obj\r\n<</Filter/FlateDecode/Length 0>>stream\r\n\r\nendstream\r\nendobj\ntrailer\n<< /Root 12 0 R >>\n%%EOF";
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pdf, pdf, &mut budget).unwrap();
        assert!(
            entries.iter().all(|e| e.unsupported.is_none()),
            "{:?}",
            entries
                .iter()
                .map(|e| (&e.name, e.unsupported))
                .collect::<Vec<_>>()
        );
    }

    /// Garbage behind `/FlateDecode` (no zlib header anywhere for the
    /// leading-junk retry to find) recovers nothing: still `unsupported`, so a
    /// file whose bytes are present but unread never scans as clean.
    #[test]
    fn corrupt_flate_stream_stays_undecodable() {
        // No zlib header anywhere (deliberately no 0x78 byte, so even the
        // leading-junk retry finds nothing to decode).
        let raw = b"\x00\x01\x02\x03not zlib, nothing usable here....";
        let mut info: HashMap<String, Primitive> = HashMap::new();
        info.insert(
            "Filter".to_string(),
            Primitive::Name("FlateDecode".to_string()),
        );
        let outcome = apply_filters(raw, &info, 1 << 20).unwrap();
        assert!(!outcome.truncated);
        assert!(outcome.decode_error);
        assert!(outcome.buf.is_empty());

        let mut pdf = format!(
            "%PDF-1.5\n1 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
            raw.len()
        )
        .into_bytes();
        pdf.extend_from_slice(raw);
        pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pdf, &pdf, &mut budget).unwrap();
        assert!(
            entries.iter().any(|e| e.unsupported
                == Some("PDF stream could not be decoded; its raw bytes were scanned")
                && e.data == raw),
            "a corrupt stream must stay surfaced, its raw bytes scanned: {:?}",
            entries
                .iter()
                .map(|e| (&e.name, e.unsupported))
                .collect::<Vec<_>>()
        );
    }

    /// A `stream` keyword followed by spaces before its line end, as some
    /// writers emit: the data starts after the line end, and decodes.
    #[test]
    fn spaces_after_the_stream_keyword_are_not_data() {
        let body = b"BT /F1 12 Tf (hidden payload) Tj ET";
        // A zlib stream with an 8 KiB window, header 58 09 as the writer
        // that does this emits: with no 0x78 to restart from, the stream
        // decodes only if its first byte is found.
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(body).unwrap();
        let mut z = vec![0x58, 0x09];
        z.extend(enc.finish().unwrap());
        let (mut a, mut b) = (1u32, 0u32);
        for &x in body.iter() {
            a = (a + u32::from(x)) % 65521;
            b = (b + a) % 65521;
        }
        z.extend_from_slice(&((b << 16) | a).to_be_bytes());
        assert!(
            !z.contains(&0x78),
            "the test needs a stream with no 0x78 byte"
        );
        let mut pdf = format!(
            "%PDF-1.3\n5 0 obj\r\n<< /Length {} /Filter /FlateDecode >> stream \r\n",
            z.len()
        )
        .into_bytes();
        pdf.extend_from_slice(&z);
        pdf.extend_from_slice(b"\r\nendstream\r\nendobj\r\ntrailer\n<< /Root 5 0 R >>\n%%EOF");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pdf, &pdf, &mut budget).unwrap();
        let obj = entries
            .iter()
            .find(|e| e.name == "pdf-obj-5-0")
            .expect("the stream object");
        assert_eq!(obj.unsupported, None);
        assert_eq!(obj.data, body);
    }

    /// A solid-white page image (1 MB of one byte, ratio ~1000:1) is ordinary
    /// scanner content, not a bomb: it must extract as a clean member, not
    /// trip the compression-ratio bomb guard into `LIMITS-EXCEEDED`.
    #[test]
    fn blank_page_image_is_not_a_ratio_bomb() {
        let white = vec![0xffu8; 1_030_656]; // 768x1342 grayscale, all white
        let raw = zlib_compress(&white);
        assert!(
            raw.len() as u64 * 1000 < white.len() as u64,
            "fixture must actually exceed the 1000:1 ratio"
        );
        let mut pdf = format!(
            "%PDF-1.5\n1 0 obj\n<< /Type /XObject /Subtype /Image /Width 768 /Height 1342 /BitsPerComponent 8 /ColorSpace /DeviceGray /Length {} /Filter /FlateDecode >>\nstream\n",
            raw.len()
        )
        .into_bytes();
        pdf.extend_from_slice(&raw);
        pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pdf, &pdf, &mut budget).unwrap();
        let img = entries
            .iter()
            .find(|e| e.unsupported.is_none() && e.data == white)
            .expect("the white image must come back as scanned content");
        assert_eq!(img.data.len(), white.len());
    }

    /// `/DecodeParms << /EarlyChange 0 >>` is threaded to the LZW decoder.
    #[test]
    fn early_change_parm_parsed() {
        let mut off: HashMap<String, Primitive> = HashMap::new();
        off.insert("EarlyChange".to_string(), Primitive::Integer(0));
        assert!(!early_change(Some(&off)));

        let mut on: HashMap<String, Primitive> = HashMap::new();
        on.insert("EarlyChange".to_string(), Primitive::Integer(1));
        assert!(early_change(Some(&on)));
        assert!(early_change(None));
    }

    /// An OpenAction JavaScript literal and a URI are harvested into their
    /// synthetic members so signatures match the active content directly.
    #[test]
    fn harvests_javascript_and_uri() {
        let pdf = b"%PDF-1.5\n\
1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert\\('EICAR-JS'\\)) >> >>\nendobj\n\
2 0 obj\n<< /Type /Annot /Subtype /Link /A << /S /URI /URI (http://evil.example/x) >> >>\nendobj\n\
trailer\n<< /Root 1 0 R >>\n%%EOF";
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pdf, pdf, &mut budget).unwrap();
        let js = entries
            .iter()
            .find(|e| e.name == "pdf-javascript")
            .expect("js member");
        assert!(
            js.data.windows(9).any(|w| w == b"app.alert"),
            "JS literal harvested: {:?}",
            String::from_utf8_lossy(&js.data)
        );
        let uris = entries
            .iter()
            .find(|e| e.name == "pdf-uris")
            .expect("uri member");
        assert!(
            uris.data.windows(4).any(|w| w == b"http"),
            "URI harvested: {:?}",
            String::from_utf8_lossy(&uris.data)
        );
    }

    /// Deeply nested `/JS` arrays must not blow the harvest recursion (bounded at
    /// depth 32) and a huge harvested value must stay budget-bounded, no panic.
    #[test]
    fn deeply_nested_and_large_harvest_no_panic() {
        let mut body = String::from("%PDF-1.5\n1 0 obj\n<< /JS ");
        for _ in 0..500 {
            body.push('[');
        }
        body.push_str("(app.alert)");
        for _ in 0..500 {
            body.push(']');
        }
        body.push_str(" >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF");
        let mut budget = Budget::new(Limits::default());
        let _ = extract(Format::Pdf, &body.as_bytes(), &mut budget).unwrap();
    }

    /// An object stream is decrypted as a whole, so the strings of the objects
    /// inside it are plain: the harvest and the color space reader must not
    /// decrypt them again.
    #[cfg(feature = "decrypt")]
    #[test]
    fn objects_in_an_object_stream_are_not_decrypted_twice() {
        // RC4, 40 bits, the user password is "test".
        let path = format!(
            "{}/test_data/pdf/rc4_40bit_encrypted.pdf",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut pdf = crate::read_fixture(&path).unwrap();
        let encrypt = detect_encryption(&pdf).unwrap();
        let id = find_doc_id(&pdf).unwrap();
        let dec = Decoder::from_password(&encrypt, &id, b"test").unwrap();

        let action = "<< /S /JavaScript /JS (app.alert\\(1\\)) >>\n";
        let space = "[/Indexed /DeviceRGB 0 <ff0000>]\n";
        let header = format!("7 0 8 {} ", action.len());
        let mut stream = zlib_compress(format!("{header}{action}{space}").as_bytes());
        // RC4 is its own inverse.
        dec.decrypt_stream(90, 0, &mut stream);
        pdf.extend_from_slice(
            format!(
                "\n90 0 obj\n<< /Type /ObjStm /N 2 /First {} /Filter /FlateDecode \
                 /Length {} >>\nstream\n",
                header.len(),
                stream.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&stream);
        pdf.extend_from_slice(
            b"\nendstream\nendobj\n91 0 obj\n<< /Subtype /Image /Width 1 /Height 1 \
              /BitsPerComponent 8 /ColorSpace 8 0 R /Length 1 >>\nstream\n\0\nendstream\nendobj\n",
        );

        let mut budget = Budget::with_passwords(Limits::default(), vec!["test".to_string()]);
        budget.set_rasters(true);
        let entries = extract(Format::Pdf, &pdf, &mut budget).unwrap();
        let js = entries.iter().find(|e| e.name == "pdf-javascript").unwrap();
        assert_eq!(js.data, b"app.alert(1)\n");
        let image = entries.iter().find(|e| e.name == "pdf-obj-91-0").unwrap();
        assert_eq!(
            image.raster.as_ref().map(|r| &r.space),
            Some(&RasterSpace::Indexed {
                base: Box::new(RasterSpace::Rgb),
                hival: 0,
                palette: vec![255, 0, 0],
            })
        );
    }

    /// A string object that a link names is decrypted with its own key, not with
    /// the key of the dictionary that names it.
    #[cfg(feature = "decrypt")]
    #[test]
    fn a_string_object_named_by_an_action_is_decrypted_with_its_own_key() {
        // RC4, 40 bits, the user password is "test".
        let path = format!(
            "{}/test_data/pdf/rc4_40bit_encrypted.pdf",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut pdf = crate::read_fixture(&path).unwrap();
        let encrypt = detect_encryption(&pdf).unwrap();
        let id = find_doc_id(&pdf).unwrap();
        let dec = Decoder::from_password(&encrypt, &id, b"test").unwrap();

        let mut link = b"http://evil.example/x".to_vec();
        // RC4 is its own inverse.
        dec.decrypt_stream(92, 0, &mut link);
        let hex: String = link.iter().map(|b| format!("{b:02x}")).collect();
        pdf.extend_from_slice(
            format!("\n92 0 obj\n<{hex}>\nendobj\n93 0 obj\n<< /S /URI /URI 92 0 R >>\nendobj\n")
                .as_bytes(),
        );

        let mut budget = Budget::with_passwords(Limits::default(), vec!["test".to_string()]);
        let entries = extract(Format::Pdf, &pdf, &mut budget).unwrap();
        let uris = entries.iter().find(|e| e.name == "pdf-uris").unwrap();
        assert_eq!(uris.data, b"http://evil.example/x\n");
    }

    /// A PDF with no active content emits no JS/URI members (no false members).
    #[test]
    fn no_actions_no_members() {
        let pdf =
            b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF";
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pdf, pdf, &mut budget).unwrap();
        assert!(
            entries
                .iter()
                .all(|e| e.name != "pdf-javascript" && e.name != "pdf-uris")
        );
    }
}
