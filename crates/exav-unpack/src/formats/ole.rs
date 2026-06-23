#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// OLE2 / Compound File Binary (legacy Office, MSI): emit every stream so the
/// engine can match on macro/object/shellcode content.
pub(crate) fn extract_ole(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    let mut comp = cfb::CompoundFile::open(Cursor::new(data))
        .map_err(|e| LimitHit::new(format!("ole: {e}")))?;
    let paths: Vec<std::path::PathBuf> = comp
        .walk()
        .filter(|e| e.is_stream())
        .map(|e| e.path().to_path_buf())
        .collect();
    let mut entries = Vec::new();
    for p in paths {
        budget.count_entry()?;
        let cap = budget.reserve()?;
        let stream = comp
            .open_stream(&p)
            .map_err(|e| LimitHit::new(format!("ole stream: {e}")))?;
        let (buf, truncated) =
            bounded_read(stream, cap).map_err(|e| LimitHit::new(format!("ole read: {e}")))?;
        if truncated {
            return Err(LimitHit::new("ole stream exceeds budget".to_string()));
        }
        budget.commit(buf.len() as u64);
        entries.push(Entry::new(p.to_string_lossy().into_owned(), buf));
    }
    Ok(entries)
}
