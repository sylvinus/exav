#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// 7-Zip: decode each entry's stream into a budgeted buffer. Uses the
/// pure-Rust `sevenz-rust2` reader (LZMA/LZMA2/PPMd/BCJ/Copy).
pub(crate) fn extract_7z(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    use sevenz_rust2::{ArchiveReader, Password};
    let mut reader = ArchiveReader::new(Cursor::new(data), Password::empty())
        .map_err(|e| LimitHit::new(format!("7z: {e}")))?;
    let mut entries = Vec::new();
    let mut limit: Option<LimitHit> = None;
    // `for_each_entries` streams each entry's decompressed bytes; we cap each
    // to the remaining budget and stop (return Ok(false)) when a bound is hit.
    let r = reader.for_each_entries(|entry, rd| {
        if entry.is_directory() {
            return Ok(true);
        }
        if let Err(h) = budget.count_entry() {
            limit = Some(h);
            return Ok(false);
        }
        let cap = match budget.reserve() {
            Ok(c) => c,
            Err(h) => {
                limit = Some(h);
                return Ok(false);
            }
        };
        let (buf, truncated) = match bounded_read(rd, cap) {
            Ok(x) => x,
            Err(e) => {
                limit = Some(LimitHit::new(format!("7z read: {e}")));
                return Ok(false);
            }
        };
        if truncated {
            limit = Some(LimitHit::new("7z member exceeds budget".to_string()));
            return Ok(false);
        }
        budget.commit(buf.len() as u64);
        entries.push(Entry::new(entry.name().to_string(), buf));
        Ok(true)
    });
    if let Some(h) = limit {
        return Err(h);
    }
    r.map_err(|e| LimitHit::new(format!("7z: {e}")))?;
    Ok(entries)
}
