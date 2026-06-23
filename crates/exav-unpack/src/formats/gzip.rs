#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

pub(crate) fn extract_gzip(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    use flate2::read::GzDecoder;
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let (out, truncated) = bounded_read(GzDecoder::new(Cursor::new(data)), cap)
        .map_err(|e| LimitHit::new(format!("gzip: {e}")))?;
    if truncated {
        return Err(LimitHit::new("gzip member exceeds budget".to_string()));
    }
    ratio_guard(data.len() as u64, out.len() as u64, budget)?;
    budget.commit(out.len() as u64);
    Ok(vec![Entry::new("gzip-content".to_string(), out)])
}
