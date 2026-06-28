#![allow(unused_imports)]
use crate::*;
use std::io::{Cursor, Read};

/// ARJ: decode each member with the vendored `arj_parse` reader.
///
/// Header parsing and encryption code vendored from
/// [unarc-rs](https://github.com/mkrueger/unarc-rs) (MIT OR Apache-2.0,
/// copyright Mike Krüger). Methods 1-3 are LHA `-lh6-`-compatible (decoded
/// via `delharc`), method 4 is ARJ's own "fastest" codec, method 0 is stored;
/// each member is CRC-32 verified.
pub(crate) fn extract_arj<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    use crate::formats::arj_parse::arj_archive::ArjArchive;
    use crate::formats::arj_parse::local_file_header::{
        CompressionMethod, FileType as ArjFileType,
    };

    let mut arc = ArjArchive::new(data.to_vec())
        .ok_or_else(|| LimitHit::corrupt("arj: invalid header or CRC".to_string()))?;

    while let Some(header) = arc.get_next_entry() {
        budget.count_entry()?;
        let supported = matches!(
            header.compression_method,
            CompressionMethod::Stored
                | CompressionMethod::CompressedMost
                | CompressionMethod::Compressed
                | CompressionMethod::CompressedFaster
                | CompressionMethod::CompressedFastest
        );
        if matches!(header.file_type, ArjFileType::Directory) || !supported {
            if !arc.skip(&header) {
                return Err(LimitHit::corrupt("arj: truncated entry".to_string()));
            }
            continue;
        }
        let cap = budget.reserve()?;
        if header.original_size as u64 > cap {
            return Err(LimitHit::new(format!(
                "arj member '{}' exceeds budget",
                header.name
            )));
        }
        let name = header.name.clone();
        let buf = arc.read(&header).ok_or_else(|| {
            LimitHit::corrupt(format!("arj read '{name}': decompression or CRC failed"))
        })?;
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

    #[test]
    fn arj_short_header_no_panic() {
        // Crafted ARJ: magic + header_size=4 + 4 bytes of header + valid CRC.
        // unarj-rs 0.2.1 panics in MainHeader::load_from when it tries to read
        // byte 5 of a 4-byte header.  After vendoring unarc-rs, this must
        // return an error instead of panicking.
        //
        // Layout:  [60 EA] [04 00] [00 00 00 00] [CRC32 LE]
        //            magic   hsize=4  header data    crc of header data
        let header_data: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
        let crc = crc32fast::hash(&header_data);
        let crc_bytes = crc.to_le_bytes();

        let data = [
            0x60,
            0xEA, // ARJ magic
            0x04,
            0x00, // header size = 4
            0x00,
            0x00,
            0x00,
            0x00, // 4-byte header data
            crc_bytes[0],
            crc_bytes[1],
            crc_bytes[2],
            crc_bytes[3], // CRC32
        ];

        // Call extract_arj directly (bypassing the catch_unwind in extract)
        // to prove the decoder does NOT panic on this input.
        let mut budget = Budget::new(Limits::default());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::extract_arj::<()>(&data, &mut budget, &mut |_, _| None)
        }));
        assert!(
            result.is_ok(),
            "ARJ decoder panicked on 4-byte header input"
        );
    }
}
