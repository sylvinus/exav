#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// PDF: emit each stream object's content. FlateDecode streams are decompressed
/// through the bounded reader (so a Flate bomb trips the budget); other streams
/// are passed through raw.
///
/// Uses pdf-rs's object scanner, which lexes indirect objects directly (so a
/// broken xref — common in malicious PDFs — doesn't stop extraction) and is
/// depth-bounded (`MAX_DEPTH`), avoiding the nested-object stack overflow of
/// other PDF parsers. No RNG is linked.
pub(crate) fn extract_pdf<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    use pdf::file::{FileOptions, ScanItem};
    use pdf::primitive::Primitive;

    // Encrypted PDF: try the empty (standard) password first, then each pool
    // password. The `pdf` crate decrypts streams transparently once loaded with a
    // working password, so a correctly-passworded encrypted PDF is scanned like
    // any other. If the document is encrypted (`/Encrypt` present) and no password
    // unlocks it, emit a `PasswordProtected` signal instead of treating the
    // (undecryptable) streams as clean.
    let mut candidates: Vec<&[u8]> = vec![b""];
    for pw in &budget.passwords {
        candidates.push(pw.as_bytes());
    }
    let mut file = None;
    let mut saw_encrypt = false;
    for pw in candidates {
        match FileOptions::uncached().password(pw).load(data.to_vec()) {
            Ok(f) => {
                saw_encrypt = f.trailer.encrypt_dict.is_some();
                file = Some(f);
                break;
            }
            Err(e) => {
                // An `InvalidPassword` (or any error after we know it's encrypted)
                // means the file is encrypted but this password didn't work.
                if format!("{e}").to_ascii_lowercase().contains("password") {
                    saw_encrypt = true;
                }
            }
        }
    }
    let file = match file {
        Some(f) => f,
        None => {
            if saw_encrypt {
                budget.count_entry()?;
                let e = Entry::unsupported(
                    "pdf-encrypted".to_string(),
                    data.len() as u64,
                    true,
                    "encrypted PDF",
                );
                return Ok(visit(e, budget));
            }
            return Err(LimitHit::new("pdf: failed to load".to_string()));
        }
    };
    // A PDF that loaded but is encrypted with a password we don't have (e.g. it
    // opened with the empty user password yet streams remain undecryptable) is
    // still surfaced below via normal scanning; the explicit signal above covers
    // the load-failure case.
    let resolver = file.resolver();
    for item in file.scan() {
        let Ok(ScanItem::Object(id, Primitive::Stream(stream))) = item else {
            continue;
        };
        budget.count_entry()?;
        let cap = budget.reserve()?;
        // Raw (still-encoded) stream bytes; exav does the flate itself.
        let raw = stream
            .raw_data(&resolver)
            .map_err(|e| LimitHit::new(format!("pdf raw: {e}")))?;
        let (buf, truncated) = if stream_is_flate(&stream.info) {
            bounded_read(flate2::read::ZlibDecoder::new(Cursor::new(&raw[..])), cap)
                .map_err(|e| LimitHit::new(format!("pdf flate: {e}")))?
        } else {
            // Uncompressed (or a filter we don't decode): cap the raw content.
            let take = (raw.len() as u64).min(cap) as usize;
            (raw[..take].to_vec(), raw.len() as u64 > cap)
        };
        if truncated {
            return Err(LimitHit::new("pdf stream exceeds budget".to_string()));
        }
        ratio_guard(raw.len() as u64, buf.len() as u64, budget)?;
        budget.commit(buf.len() as u64);
        if let Some(r) = visit(Entry::new(format!("pdf-obj-{}-{}", id.id, id.gen), buf), budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// Whether a stream's `/Filter` includes `FlateDecode` (a bare name or in an
/// array of names).
fn stream_is_flate(info: &pdf::primitive::Dictionary) -> bool {
    use pdf::primitive::Primitive;
    match info.get("Filter") {
        Some(Primitive::Name(n)) => n.as_str() == "FlateDecode",
        Some(Primitive::Array(a)) => a
            .iter()
            .any(|p| matches!(p, Primitive::Name(n) if n.as_str() == "FlateDecode")),
        _ => false,
    }
}
