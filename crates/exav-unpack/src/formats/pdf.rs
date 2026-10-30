#![cfg_attr(
    not(feature = "decrypt"),
    allow(dead_code, unused_mut, unused_imports, unreachable_code)
)]
use crate::*;
use std::collections::HashMap;
use std::io::Cursor;

#[cfg(feature = "decrypt")]
use super::pdf_parse::crypt::{CryptDict, Decoder};
use super::pdf_parse::filters;
use super::pdf_parse::lex::Lexer;
use super::pdf_parse::parse::{parse_indirect_object_body, parse_object};
use super::pdf_parse::types::Primitive;

/// PDF: emit each stream object's content. FlateDecode streams are decompressed
/// through the bounded reader (so a Flate bomb trips the budget); other streams
/// are passed through raw.
///
/// Uses a linear byte-scanning approach that finds `N G obj` patterns directly,
/// so a broken xref — common in malicious PDFs — doesn't stop extraction. The
/// parser is depth-bounded (`MAX_DEPTH`), avoiding nested-object stack overflow.
/// ClamAV `Heuristics.PDF.ObfuscatedNameObject`: a PDF **name object** (`/Name`)
/// that hex-escapes (`#XX`) a character that never requires escaping — an ASCII
/// letter or digit — *and* whose de-escaped form is one of the sensitive
/// action/feature keywords malware hides this way (`/J#61vaScript` → `JavaScript`,
/// `/Ope#6eAction` → `OpenAction`). The PDF spec only needs `#`-escaping for
/// whitespace, the delimiters `()<>[]{}/%#`, and bytes outside `0x21..=0x7E`, so
/// escaping a plain alphanumeric is gratuitous.
///
/// Requiring the de-escaped name to be a *sensitive keyword* is deliberate: a lone
/// incidental escape in an ordinary name (e.g. `/C#31` → `C1`) is common in benign
/// PDFs and must not fire — stock ClamAV likewise flags the systematic
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

pub(crate) fn extract_pdf<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
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
    // Accumulate active-content (JavaScript) and URI/launch targets across the
    // whole document; emit them as synthetic members after the object scan so
    // signatures keyed on `app.alert(`, `http://…`, launched commands, etc. match
    // even when the value is a direct string (indirect streams are already
    // surfaced by the stream path below). ClamAV surfaces the same content.
    let mut js_acc: Vec<u8> = Vec::new();
    let mut uri_acc: Vec<u8> = Vec::new();
    let mut lex = Lexer::new(data);
    // Where each object number is, found when a stream's `/Filter` or
    // `/DecodeParms` is a reference to one.
    let mut index: Option<HashMap<u32, usize>> = None;
    // Bytes read again because an object ended before its parse did, or did not
    // parse. Bounded, since every object of a crafted file can claim the rest of
    // it, and the bound is said when it is reached.
    let mut reread = 0u64;
    let reread_cap = (data.len() as u64)
        .saturating_mul(8)
        .saturating_add(1 << 20);
    let mut gave_up = false;
    while let Some((obj_id, r#gen, obj_start)) = lex.find_next_obj() {
        lex.set_pos(obj_start);
        let Some((obj, end)) = parse_indirect_object_body(&mut lex) else {
            // An object that does not parse (an unterminated string in it runs
            // to the end of the file) is not the end of the document: the scan
            // goes on from its start, as a reader going by the cross-reference
            // table reaches every object after it.
            reread = reread.saturating_add(lex.pos().saturating_sub(obj_start) as u64);
            if reread > reread_cap {
                gave_up = true;
            } else {
                lex.set_pos(obj_start);
            }
            continue;
        };
        // An object that does not end where it says (a string left open takes
        // the rest of the file for itself, and the dictionary round it still
        // parses) must not take the objects after it. Parsing resumes after the
        // first `endobj`, as a reader that goes by the cross-reference table
        // finds each of them.
        if let Some(p) = memchr::memmem::find(
            &data[obj_start.min(data.len())..end.min(data.len())],
            b"endobj",
        ) {
            let stop = obj_start + p + b"endobj".len();
            if end > stop {
                reread = reread.saturating_add((end - stop) as u64);
                if reread > reread_cap {
                    gave_up = true;
                } else {
                    lex.set_pos(stop);
                }
            }
        }
        budget.count_entry()?;

        // Harvest JS / URI / launch strings from this object's dictionary(s).
        // Strings are decrypted with the object key when the doc is encrypted,
        // so the recovered plaintext matches (same key schedule as streams).
        #[cfg(feature = "decrypt")]
        harvest_actions(
            &obj,
            decoder.as_ref(),
            (obj_id, r#gen),
            &mut js_acc,
            &mut uri_acc,
        );
        #[cfg(not(feature = "decrypt"))]
        harvest_actions(&obj, &mut js_acc, &mut uri_acc);

        if let Primitive::Stream {
            info,
            data: mut stream_data,
        } = obj
        {
            #[cfg(feature = "decrypt")]
            if let Some(ref dec) = decoder {
                dec.decrypt_stream(obj_id, r#gen, &mut stream_data);
            }
            let raw_len = stream_data.len() as u64;
            let cap = budget.reserve()?;
            let info = resolve_filter_references(info, data, &mut index);
            let outcome = apply_filters(&stream_data, &info, cap)?;
            if outcome.truncated {
                return Err(LimitHit::new("pdf stream exceeds budget".to_string()));
            }
            let buf = outcome.buf;
            ratio_guard(raw_len, buf.len() as u64, budget)?;
            budget.commit(buf.len() as u64);
            // A stream whose bytes an implemented filter failed to decode is
            // content we failed to produce, not an empty object. Emitting it
            // as a zero-byte member says "scanned, nothing there" about bytes
            // nobody read — the silent skip this scanner exists to avoid. Say
            // so instead. But a stream that DECODED to empty (legal — an
            // empty page-content stream carries no bytes to hide) is a
            // scanned empty member, not an undecodable one.
            //
            // Image codecs (`apply_filters` stops at DCTDecode, JPXDecode,
            // CCITTFaxDecode) pass the raw bytes through, so those streams
            // are scanned as their raw content — the signatures match the
            // bytes either way.
            //
            // An undecodable stream's raw bytes are scanned in its place, as
            // ClamAV scans them: a filter that names Flate over data that is
            // not (a ZIP, say) hides nothing from that scan.
            let entry = if buf.is_empty() && raw_len > 0 && outcome.decode_error {
                if raw_len > budget.reserve()? {
                    return Err(LimitHit::new("pdf stream exceeds budget".to_string()));
                }
                budget.commit(raw_len);
                let mut e = Entry::new(format!("pdf-obj-{obj_id}-{gen}"), stream_data);
                e.unsupported = Some("PDF stream could not be decoded; its raw bytes were scanned");
                e
            } else {
                let mut e = Entry::new(format!("pdf-obj-{obj_id}-{gen}"), buf);
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
                e
            };
            if let Some(r) = visit(entry, budget) {
                return Ok(Some(r));
            }
        }
    }

    if gave_up {
        budget.count_entry()?;
        if let Some(r) = visit(
            Entry::unsupported(
                "pdf-overlapping-objects".to_string(),
                data.len() as u64,
                false,
                "PDF objects run into one another more than can be read again; the rest of the file was not scanned object by object",
            ),
            budget,
        ) {
            return Ok(Some(r));
        }
    }

    // Emit the harvested active-content members (bounded by the budget like any
    // other member). Non-empty only.
    for (name, acc) in [("pdf-javascript", js_acc), ("pdf-uris", uri_acc)] {
        if acc.is_empty() {
            continue;
        }
        budget.count_entry()?;
        let cap = budget.reserve()?;
        if acc.len() as u64 > cap {
            return Err(LimitHit::new("pdf actions exceed budget".to_string()));
        }
        budget.commit(acc.len() as u64);
        if let Some(r) = visit(Entry::new(name.to_string(), acc), budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// PDF dictionary keys whose values carry executable/active content.
const JS_KEYS: &[&str] = &["JS", "JavaScript"];
/// Keys whose values carry a URI / launch target / submitted URL.
const URI_KEYS: &[&str] = &["URI", "URL", "Launch", "F", "Win", "SubmitForm"];

/// Recursively walk a parsed object, collecting the string values of active-
/// content keys (`/JS`, `/JavaScript`) into `js` and URI/launch targets into
/// `uri`. Depth-bounded to match the parser and to bound crafted nesting.
#[cfg(feature = "decrypt")]
fn harvest_actions(
    obj: &Primitive,
    decoder: Option<&Decoder>,
    obj_id: (u32, u32),
    js: &mut Vec<u8>,
    uri: &mut Vec<u8>,
) {
    harvest_inner(obj, decoder, obj_id, js, uri, 0);
}
#[cfg(not(feature = "decrypt"))]
fn harvest_actions(obj: &Primitive, js: &mut Vec<u8>, uri: &mut Vec<u8>) {
    harvest_inner(obj, js, uri, 0);
}

fn harvest_inner(
    obj: &Primitive,
    #[cfg(feature = "decrypt")] decoder: Option<&Decoder>,
    #[cfg(feature = "decrypt")] obj_id: (u32, u32),
    js: &mut Vec<u8>,
    uri: &mut Vec<u8>,
    depth: u32,
) {
    // Guard: bound recursion and total harvested size (crafted deep/huge dicts).
    if depth > 32 || js.len() + uri.len() > (4 << 20) {
        return;
    }
    match obj {
        Primitive::Dictionary(d) | Primitive::Stream { info: d, .. } => {
            for (key, val) in d {
                let target = if JS_KEYS.contains(&key.as_str()) {
                    Some(&mut *js)
                } else if URI_KEYS.contains(&key.as_str()) {
                    Some(&mut *uri)
                } else {
                    None
                };
                if let (Some(acc), Some(s)) = (target, val.as_str()) {
                    let mut bytes = s.to_vec();
                    #[cfg(feature = "decrypt")]
                    if let Some(dec) = decoder {
                        dec.decrypt_stream(obj_id.0, obj_id.1, &mut bytes);
                    }
                    acc.extend_from_slice(&bytes);
                    acc.push(b'\n');
                }
                #[cfg(feature = "decrypt")]
                harvest_inner(val, decoder, obj_id, js, uri, depth + 1);
                #[cfg(not(feature = "decrypt"))]
                harvest_inner(val, js, uri, depth + 1);
            }
        }
        Primitive::Array(items) => {
            for it in items {
                #[cfg(feature = "decrypt")]
                harvest_inner(it, decoder, obj_id, js, uri, depth + 1);
                #[cfg(not(feature = "decrypt"))]
                harvest_inner(it, js, uri, depth + 1);
            }
        }
        _ => {}
    }
}

/// `info` with the references in `/Filter` and `/DecodeParms` replaced by the
/// objects they name, which a PDF may use for either. The scan is object by
/// object, so a filter written as `7 0 R` was no filter at all, and the stream
/// was scanned compressed.
fn resolve_filter_references(
    mut info: HashMap<String, Primitive>,
    data: &[u8],
    index: &mut Option<HashMap<u32, usize>>,
) -> HashMap<String, Primitive> {
    let mut resolve = |p: &Primitive| -> Option<Primitive> {
        let mut at = p.clone();
        // A reference to a reference is followed, a loop of them not forever.
        for _ in 0..8 {
            let Primitive::Reference(id) = at else {
                return Some(at);
            };
            let index = index.get_or_insert_with(|| {
                let mut found = HashMap::new();
                let mut lex = Lexer::new(data);
                // The last definition of a number wins, as in an incremental
                // update.
                while let Some((n, _gen, start)) = lex.find_next_obj() {
                    found.insert(n, start);
                }
                found
            });
            let start = *index.get(&id)?;
            let mut lex = Lexer::new(data);
            lex.set_pos(start);
            at = match parse_indirect_object_body(&mut lex)?.0 {
                Primitive::Stream { .. } => return None,
                other => other,
            };
        }
        None
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
    /// which is a successful decode of an empty stream (legal — e.g. an empty
    /// page-content stream) and must NOT be reported undecodable.
    decode_error: bool,
    /// A filter decoded part of its input and failed on the rest: `buf` holds
    /// what came before the failure.
    part_way: bool,
    /// The chain names a filter that is neither decoded here nor an image
    /// codec: what follows it was not decoded, and `buf` is not the content.
    unknown_filter: bool,
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
    // empty-output-with-error — a valid empty decode is a scanned empty member,
    // not an undecodable stream.
    let mut decode_error = false;
    for (idx, name) in names.iter().enumerate() {
        let parm = parms.get(idx).copied().flatten();
        let (out, truncated, err) = match name.as_str() {
            "FlateDecode" | "Fl" => {
                // Strict first: a valid-but-empty stream must succeed (the
                // caller emits it as a scanned empty member). Only on strict
                // failure fall back to salvage — and only if salvage ALSO
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
            // conservatively counts as a failure — today's behaviour,
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
            // (an image codec over raw bytes reads as the raw bytes — same as
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
fn decode_parms_list(
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
/// 2. Look for a standalone encryption dictionary (has /V, /R, /O, /U keys) — pypdf puts it
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
    /// bytes — common as empty page-content) decodes successfully to nothing.
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
    /// depth 32) and a huge harvested value must stay budget-bounded — no panic.
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
