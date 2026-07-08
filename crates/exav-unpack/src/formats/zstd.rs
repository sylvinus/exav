use crate::*;
use std::io::Cursor;

pub(crate) fn extract_zstd<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?;
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(Cursor::new(data))
        .map_err(|e| LimitHit::new(format!("zstd: {e}")))?;
    let (out, truncated) =
        bounded_read(&mut decoder, cap).map_err(|e| LimitHit::new(format!("zstd: {e}")))?;
    if truncated {
        return Err(LimitHit::new("zstd member exceeds budget".to_string()));
    }
    ratio_guard(data.len() as u64, out.len() as u64, budget)?;
    budget.commit(out.len() as u64);
    Ok(visit(Entry::new("zstd-content".to_string(), out), budget))
}
