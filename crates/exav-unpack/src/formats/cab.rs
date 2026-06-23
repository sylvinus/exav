#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

pub(crate) fn extract_cab(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    let mut cabinet =
        cab::Cabinet::new(Cursor::new(data)).map_err(|e| LimitHit::new(format!("cab: {e}")))?;
    // Collect names first so the immutable folder/file iteration doesn't borrow
    // the cabinet while we read (read_file needs &mut).
    let names: Vec<String> = cabinet
        .folder_entries()
        .flat_map(|f| f.file_entries().map(|e| e.name().to_string()))
        .collect();
    let mut entries = Vec::new();
    for name in names {
        budget.count_entry()?;
        let cap = budget.reserve()?;
        let reader = cabinet
            .read_file(&name)
            .map_err(|e| LimitHit::new(format!("cab '{name}': {e}")))?;
        let (buf, truncated) =
            bounded_read(reader, cap).map_err(|e| LimitHit::new(format!("cab read: {e}")))?;
        if truncated {
            return Err(LimitHit::new(format!("cab member '{name}' exceeds budget")));
        }
        budget.commit(buf.len() as u64);
        entries.push(Entry::new(name, buf));
    }
    Ok(entries)
}
