#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

pub(crate) fn extract_bzip2(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let (out, truncated) = bounded_read(bzip2_rs::DecoderReader::new(Cursor::new(data)), cap)
        .map_err(|e| LimitHit::new(format!("bzip2: {e}")))?;
    if truncated {
        return Err(LimitHit::new("bzip2 member exceeds budget".to_string()));
    }
    ratio_guard(data.len() as u64, out.len() as u64, budget)?;
    budget.commit(out.len() as u64);
    Ok(vec![Entry::new("bzip2-content".to_string(), out)])
}
