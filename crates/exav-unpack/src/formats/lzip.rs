use crate::*;
use std::io::Cursor;

pub(crate) fn extract_lzip<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let reader = lzma_rust2::LzipReader::new(Cursor::new(data));
    let (out, truncated) =
        bounded_read(reader, cap).map_err(|e| LimitHit::new(format!("lzip: {e}")))?;
    if truncated {
        return Err(LimitHit::new("lzip member exceeds budget".to_string()));
    }
    ratio_guard(data.len() as u64, out.len() as u64, budget)?;
    budget.commit(out.len() as u64);
    Ok(visit(Entry::new("lzip-content".to_string(), out), budget))
}
