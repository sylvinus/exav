#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

pub(crate) fn extract_tar(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    let mut archive = tar::Archive::new(Cursor::new(data));
    let mut entries = Vec::new();
    let iter = archive
        .entries()
        .map_err(|e| LimitHit::new(format!("tar: {e}")))?;
    for entry in iter {
        budget.count_entry()?;
        let mut entry = entry.map_err(|e| LimitHit::new(format!("tar entry: {e}")))?;
        let name = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "tar-entry".to_string());
        let cap = budget.reserve()?;
        let (buf, truncated) =
            bounded_read(&mut entry, cap).map_err(|e| LimitHit::new(format!("tar read: {e}")))?;
        if truncated {
            return Err(LimitHit::new(format!("tar member '{name}' exceeds budget")));
        }
        budget.commit(buf.len() as u64);
        entries.push(Entry::new(name, buf));
    }
    Ok(entries)
}
