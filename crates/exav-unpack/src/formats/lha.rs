#![allow(unused_imports)]
use crate::*;
use std::io::{BufReader, Cursor, Read, Seek, Write};

/// LHA/LZH: decode each member with the pure-Rust `delharc` reader.
pub(crate) fn extract_lha(data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    let mut dec = delharc::LhaDecodeReader::new(Cursor::new(data))
        .map_err(|e| LimitHit::new(format!("lha: {e}")))?;
    let mut entries = Vec::new();
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
            entries.push(Entry::new(name, buf));
        }
        match dec.next_file() {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => return Err(LimitHit::new(format!("lha: {e}"))),
        }
    }
    Ok(entries)
}
