#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

pub(crate) fn extract_xz(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    budget.count_entry()?;
    let cap = budget.reserve()?;
    // lzma-rs is writer-based; cap the writer so a bomb can't allocate past the
    // budget (it stops and reports the overflow rather than decoding it all).
    let mut sink = CapWriter::new(cap);
    let mut input = std::io::BufReader::new(Cursor::new(data));
    match lzma_rs::xz_decompress(&mut input, &mut sink) {
        Ok(()) => {}
        Err(_) if sink.over => {
            return Err(LimitHit::new("xz member exceeds budget".to_string()));
        }
        Err(e) => return Err(LimitHit::new(format!("xz: {e}"))),
    }
    ratio_guard(data.len() as u64, sink.buf.len() as u64, budget)?;
    budget.commit(sink.buf.len() as u64);
    Ok(vec![Entry::new("xz-content".to_string(), sink.buf)])
}
