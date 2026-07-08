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
    while let Some((obj_id, gen, obj_start)) = lex.find_next_obj() {
        lex.set_pos(obj_start);
        let Some((obj, _end)) = parse_indirect_object_body(&mut lex) else {
            continue;
        };
        budget.count_entry()?;

        // Harvest JS / URI / launch strings from this object's dictionary(s).
        // Strings are decrypted with the object key when the doc is encrypted,
        // so the recovered plaintext matches (same key schedule as streams).
        #[cfg(feature = "decrypt")]
        harvest_actions(&obj, decoder.as_ref(), obj_id, &mut js_acc, &mut uri_acc);
        #[cfg(not(feature = "decrypt"))]
        harvest_actions(&obj, &mut js_acc, &mut uri_acc);

        if let Primitive::Stream {
            info,
            data: mut stream_data,
        } = obj
        {
            #[cfg(feature = "decrypt")]
            if let Some(ref dec) = decoder {
                dec.decrypt_stream(obj_id, &mut stream_data);
            }
            let raw_len = stream_data.len() as u64;
            let cap = budget.reserve()?;
            let (buf, truncated) = apply_filters(&stream_data, &info, cap)?;
            if truncated {
                return Err(LimitHit::new("pdf stream exceeds budget".to_string()));
            }
            ratio_guard(raw_len, buf.len() as u64, budget)?;
            budget.commit(buf.len() as u64);
            if let Some(r) = visit(Entry::new(format!("pdf-obj-{obj_id}-{gen}"), buf), budget) {
                return Ok(Some(r));
            }
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
    obj_id: u32,
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
    #[cfg(feature = "decrypt")] obj_id: u32,
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
                        dec.decrypt_stream(obj_id, &mut bytes);
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

/// Decode a stream's raw bytes by applying its `/Filter` chain left to right,
/// honouring `/DecodeParms` (a single dict or an array aligned with the
/// filters). FlateDecode runs on the bounded `flate2` reader; the other PDF
/// filters use the pure decoders in [`filters`]. An unknown/unsupported filter
/// (e.g. an image codec like DCTDecode) stops the chain and passes through
/// whatever was decoded so far. Returns `(bytes, truncated)` where `truncated`
/// means an output cap was hit and the caller should treat it as over budget.
fn apply_filters(
    stream_data: &[u8],
    info: &HashMap<String, Primitive>,
    cap: u64,
) -> Result<(Vec<u8>, bool), LimitHit> {
    let names = filter_names(info);
    if names.is_empty() {
        let take = (stream_data.len() as u64).min(cap) as usize;
        return Ok((stream_data[..take].to_vec(), stream_data.len() as u64 > cap));
    }
    let parms = decode_parms_list(info, names.len());
    let mut buf = stream_data.to_vec();
    for (idx, name) in names.iter().enumerate() {
        let parm = parms.get(idx).copied().flatten();
        let (out, truncated) = match name.as_str() {
            "FlateDecode" | "Fl" => {
                bounded_read(flate2::read::ZlibDecoder::new(Cursor::new(&buf)), cap)
                    .map_err(|e| LimitHit::new(format!("pdf flate: {e}")))?
            }
            "LZWDecode" | "LZW" => filters::lzw_decode(&buf, early_change(parm), cap),
            "ASCII85Decode" | "A85" => filters::ascii85_decode(&buf, cap),
            "ASCIIHexDecode" | "AHx" => filters::ascii_hex_decode(&buf, cap),
            "RunLengthDecode" | "RL" => filters::run_length_decode(&buf, cap),
            // Unknown/unsupported filter: stop and emit what we have so far.
            _ => break,
        };
        if truncated {
            return Ok((out, true));
        }
        buf = out;
    }
    let truncated = buf.len() as u64 > cap;
    Ok((buf, truncated))
}

/// Collect the ordered list of filter names from `/Filter` (a single name or an
/// array of names).
fn filter_names(info: &HashMap<String, Primitive>) -> Vec<String> {
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
            if let Some(Primitive::Dictionary(enc)) = dict.get("Encrypt") {
                if let Some(cd) = CryptDict::from_primitive(enc) {
                    return Some(cd);
                }
            }
            // Strategy 2: this IS the encrypt dict (standalone)
            if is_encrypt_dict(&dict) {
                if let Some(cd) = CryptDict::from_primitive(&dict) {
                    return Some(cd);
                }
            }
        }
    }
    // Strategy 3: check trailer
    if let Some(trailer) = parse_trailer_dict(data) {
        if let Some(Primitive::Dictionary(enc)) = trailer.get("Encrypt") {
            if let Some(cd) = CryptDict::from_primitive(enc) {
                return Some(cd);
            }
        }
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
        {
            if let Some(Primitive::Array(arr)) = dict.get("ID") {
                if let Some(Primitive::String(s)) = arr.first() {
                    return Some(s.clone());
                }
            }
        }
    }
    // Check the trailer
    if let Some(trailer) = parse_trailer_dict(data) {
        if let Some(Primitive::Array(arr)) = trailer.get("ID") {
            if let Some(Primitive::String(s)) = arr.first() {
                return Some(s.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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

        let (out, truncated) = apply_filters(&raw, &info, 1 << 20).unwrap();
        assert!(!truncated);
        assert_eq!(out, original);
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
        let _ = extract(Format::Pdf, body.as_bytes(), &mut budget).unwrap();
    }

    /// A PDF with no active content emits no JS/URI members (no false members).
    #[test]
    fn no_actions_no_members() {
        let pdf =
            b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF";
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pdf, pdf, &mut budget).unwrap();
        assert!(entries
            .iter()
            .all(|e| e.name != "pdf-javascript" && e.name != "pdf-uris"));
    }
}
