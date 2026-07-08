#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// LHA/LZH: decode each member with the pure-Rust `delharc` reader.
pub(crate) fn extract_lha<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let mut dec = delharc::LhaDecodeReader::new(Cursor::new(data))
        .map_err(|e| LimitHit::new(format!("lha: {e}")))?;
    loop {
        let header = dec.header();
        let is_dir = header.is_directory();
        let name = header.parse_pathname_to_str();
        if !is_dir && dec.is_decoder_supported() {
            budget.count_entry()?;
            let cap = budget.reserve()?;
            let (buf, truncated) =
                bounded_read(&mut dec, cap).map_err(|e| LimitHit::new(format!("lha read: {e}")))?;
            if truncated {
                return Err(LimitHit::new(format!("lha member '{name}' exceeds budget")));
            }
            budget.commit(buf.len() as u64);
            if let Some(r) = visit(Entry::new(name, buf), budget) {
                return Ok(Some(r));
            }
        }
        match dec.next_file() {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => return Err(LimitHit::new(format!("lha: {e}"))),
        }
    }
    Ok(None)
}
