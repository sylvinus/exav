#![allow(unused_imports)]
use crate::*;
use std::io::{Cursor, Read};

/// ARJ: decode each member with the pure-Rust `unarj-rs` reader. Methods 1-3 are
/// LHA `-lh6-`-compatible (decoded via `delharc`), method 4 is ARJ's own
/// "fastest" codec, method 0 is stored; each member is CRC-32 verified.
pub(crate) fn extract_arj<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    use unarj_rs::arj_archive::ArjArchieve;
    use unarj_rs::local_file_header::{CompressionMethod, FileType as ArjFileType};

    let mut arc =
        ArjArchieve::new(Cursor::new(data)).map_err(|e| LimitHit::new(format!("arj: {e}")))?;
    while let Some(header) = arc
        .get_next_entry()
        .map_err(|e| LimitHit::new(format!("arj: {e}")))?
    {
        // Count every entry (including skipped ones) so a malformed archive
        // whose member offsets don't advance can't loop unbounded.
        budget.count_entry()?;
        let supported = matches!(
            header.compression_method,
            CompressionMethod::Stored
                | CompressionMethod::CompressedMost
                | CompressionMethod::Compressed
                | CompressionMethod::CompressedFaster
                | CompressionMethod::CompressedFastest
        );
        // Directories (and members in an unsupported/no-data method) carry no
        // file content: advance past the compressed bytes and move on.
        if matches!(header.file_type, ArjFileType::Directory) || !supported {
            arc.skip(&header)
                .map_err(|e| LimitHit::new(format!("arj skip: {e}")))?;
            continue;
        }
        let cap = budget.reserve()?;
        // `read()` decompresses the whole member into memory, so bound it by the
        // declared uncompressed size *before* decoding to cap an extraction bomb.
        if header.original_size as u64 > cap {
            return Err(LimitHit::new(format!(
                "arj member '{}' exceeds budget",
                header.name
            )));
        }
        let name = header.name.clone();
        let buf = arc
            .read(&header)
            .map_err(|e| LimitHit::new(format!("arj read '{name}': {e}")))?;
        // Reject an implausible expansion ratio early, consistent with the other
        // extractors; the absolute `cap` above is the hard bound.
        ratio_guard(header.compressed_size as u64, buf.len() as u64, budget)?;
        budget.commit(buf.len() as u64);
        if let Some(r) = visit(Entry::new(name, buf), budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use crate::{extract, Budget, Format, Limits};

    #[test]
    fn extracts_arj_member() {
        // A method-1 (LH6) ARJ holding payload.txt = "INNER-ARJ-PAYLOAD-12345".
        let data = include_bytes!("../../tests/fixtures/sample.arj");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Arj, data, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "payload.txt");
        assert_eq!(entries[0].data, b"INNER-ARJ-PAYLOAD-12345");
    }
}
