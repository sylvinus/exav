#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// PDF: emit each stream object's content. FlateDecode streams are decompressed
/// through the bounded reader (so a Flate bomb trips the budget); other streams
/// are passed through raw.
pub(crate) fn extract_pdf(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    let doc = lopdf::Document::load_mem(data).map_err(|e| LimitHit::new(format!("pdf: {e}")))?;
    let mut entries = Vec::new();
    for (id, obj) in &doc.objects {
        let lopdf::Object::Stream(stream) = obj else {
            continue;
        };
        budget.count_entry()?;
        let cap = budget.reserve()?;
        let flate = stream
            .filters()
            .map(|f| f.iter().any(|n| *n == b"FlateDecode"))
            .unwrap_or(false);
        let (buf, truncated) = if flate {
            bounded_read(
                flate2::read::ZlibDecoder::new(Cursor::new(&stream.content)),
                cap,
            )
            .map_err(|e| LimitHit::new(format!("pdf flate: {e}")))?
        } else {
            // Uncompressed (or filter we don't decode): cap the raw content.
            let take = (stream.content.len() as u64).min(cap) as usize;
            (
                stream.content[..take].to_vec(),
                stream.content.len() as u64 > cap,
            )
        };
        if truncated {
            return Err(LimitHit::new("pdf stream exceeds budget".to_string()));
        }
        ratio_guard(stream.content.len() as u64, buf.len() as u64, budget)?;
        budget.commit(buf.len() as u64);
        entries.push(Entry::new(format!("pdf-obj-{}-{}", id.0, id.1), buf));
    }
    Ok(entries)
}
