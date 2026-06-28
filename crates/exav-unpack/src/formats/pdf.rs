use crate::*;
use std::collections::HashMap;
use std::io::Cursor;

use super::pdf_parse::crypt::{CryptDict, Decoder};
use super::pdf_parse::lex::Lexer;
use super::pdf_parse::parse::{dict_has_flate, parse_indirect_object_body, parse_object};
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
    // --- Phase 1: detect encryption ---
    let crypt_info = detect_encryption(data);

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
    let mut lex = Lexer::new(data);
    while let Some((obj_id, gen, obj_start)) = lex.find_next_obj() {
        lex.set_pos(obj_start);
        let Some((obj, _end)) = parse_indirect_object_body(&mut lex) else {
            continue;
        };
        budget.count_entry()?;

        if let Primitive::Stream {
            info,
            data: mut stream_data,
        } = obj
        {
            if let Some(ref dec) = decoder {
                dec.decrypt_stream(obj_id, &mut stream_data);
            }
            let raw_len = stream_data.len() as u64;
            let cap = budget.reserve()?;
            let (buf, truncated) = if dict_has_flate(&info) {
                bounded_read(
                    flate2::read::ZlibDecoder::new(Cursor::new(&stream_data)),
                    cap,
                )
                .map_err(|e| LimitHit::new(format!("pdf flate: {e}")))?
            } else {
                let take = (stream_data.len() as u64).min(cap) as usize;
                (stream_data[..take].to_vec(), stream_data.len() as u64 > cap)
            };
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
    Ok(None)
}

/// Parse the trailer dictionary (after the `trailer` keyword).
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
fn is_encrypt_dict(dict: &HashMap<String, Primitive>) -> bool {
    dict.get("V").is_some()
        && dict.get("R").is_some()
        && dict.get("O").is_some()
        && dict.get("U").is_some()
}

/// Linear scan for an /Encrypt dictionary.
///
/// Two strategies:
/// 1. Look for an object whose dictionary contains `/Encrypt` (some generators embed it in the catalog).
/// 2. Look for a standalone encryption dictionary (has /V, /R, /O, /U keys) — pypdf puts it
///    as a separate object, referenced from the trailer via indirect ref.
/// 3. Check the trailer dict directly for `/Encrypt` key.
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
