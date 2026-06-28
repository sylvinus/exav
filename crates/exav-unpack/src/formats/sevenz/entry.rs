//! Public entry point for 7z extraction.

use super::header::{ordered_coder_iter, parse_archive};
use super::parse::SIGNATURE_HEADER_SIZE;
use crate::*;
use std::io::{Cursor, Read};

/// Known encryption codec IDs (AES-256 + SHA-256 in 7z).
const ENCRYPTION_IDS: &[&[u8]] = &[
    &[0x06, 0xf1, 0x07, 0x01], // AES-256-SHA256
];

/// Check if a block's coder chain contains an unsupported codec (e.g. encryption).
fn has_unsupported_codec(block: &super::header::Block) -> Option<&'static str> {
    for coder in &block.coders {
        for &enc_id in ENCRYPTION_IDS {
            if coder.method_id.as_slice() == enc_id {
                return Some("7z AES-256 encryption");
            }
        }
        if !super::decode::is_known_codec(coder.method_id.as_slice()) {
            return Some("unsupported 7z codec");
        }
    }
    None
}

/// Extract files from a 7z archive.
pub(crate) fn extract_sevenz<R>(
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    let archive = match parse_archive(data) {
        Ok(a) => a,
        Err(e) => {
            // If parsing fails (e.g. encrypted header), emit a single
            // encrypted+unsupported entry so callers can detect the format.
            let reason = e.reason.as_str();
            let is_encrypted = reason.contains("unsupported codec")
                || reason.contains("unsupported 7z codec")
                || reason.contains("AES");
            if is_encrypted {
                budget.count_entry()?;
                let entry = Entry::unsupported(
                    "encrypted.7z".to_string(),
                    data.len() as u64,
                    true,
                    "7z: encrypted header, unsupported codec",
                );
                return Ok(visit(entry, budget));
            }
            return Err(e);
        }
    };

    for (file_idx, file) in archive.files.iter().enumerate() {
        if !file.has_stream || file.size == 0 {
            continue;
        }

        budget.count_entry()?;

        let name = if file.name.is_empty() {
            format!("entry_{file_idx}")
        } else {
            file.name.clone()
        };

        // Find which block this file belongs to
        match archive.stream_map.file_block.get(file_idx) {
            Some(Some(block_idx)) => {
                let block_idx = *block_idx;
                let block = &archive.blocks[block_idx];

                // Check for unsupported codecs (encryption, etc.)
                if let Some(reason) = has_unsupported_codec(block) {
                    let entry = Entry::unsupported(name, file.size, true, reason);
                    if let Some(r) = visit(entry, budget) {
                        return Ok(Some(r));
                    }
                    continue;
                }

                // Compute pack stream offset
                let pack_stream_idx = archive
                    .stream_map
                    .block_first_pack_stream
                    .get(block_idx)
                    .copied()
                    .unwrap_or(0);

                if pack_stream_idx >= archive.pack_sizes.len() {
                    continue;
                }

                let pack_offset = (SIGNATURE_HEADER_SIZE
                    + archive.pack_pos
                    + archive.stream_map.pack_stream_offsets[pack_stream_idx])
                    as usize;
                let pack_size = archive.pack_sizes[pack_stream_idx] as usize;

                if pack_offset + pack_size > data.len() {
                    continue;
                }

                let pack_data = &data[pack_offset..pack_offset + pack_size];

                // Build decoder chain — own the data for Box<dyn Read>
                let owned_pack_data = pack_data.to_vec();
                let reader = Cursor::new(owned_pack_data);
                let mut current_reader: Box<dyn Read> = Box::new(reader);

                // Find which sub-stream index this file is within the block
                let block_first_file = archive
                    .stream_map
                    .block_first_file
                    .get(block_idx)
                    .copied()
                    .unwrap_or(0);
                let sub_index = file_idx - block_first_file;

                if block.num_unpack_sub_streams > 1 {
                    // Solid block: decompress up to this file
                    let mut bytes_to_skip: u64 = 0;
                    for si in 0..sub_index {
                        let sub_file_idx = block_first_file + si;
                        if sub_file_idx < archive.files.len() {
                            bytes_to_skip += archive.files[sub_file_idx].size;
                        }
                    }

                    // Decompress entire block
                    for coder_idx in ordered_coder_iter(block) {
                        let coder = &block.coders[coder_idx];
                        current_reader = super::decode::wrap_coder(
                            current_reader,
                            coder,
                            block.unpack_sizes.iter().sum::<u64>() as usize,
                        )?;
                    }

                    let mut decompressed = Vec::new();
                    current_reader
                        .read_to_end(&mut decompressed)
                        .map_err(|e| LimitHit::corrupt(format!("7z: decompress: {e}")))?;

                    // Extract the file's portion
                    let start = bytes_to_skip as usize;
                    let end = (start + file.size as usize).min(decompressed.len());
                    if start < decompressed.len() {
                        let file_data = decompressed[start..end].to_vec();
                        let entry = Entry::new(name, file_data);
                        if let Some(r) = visit(entry, budget) {
                            return Ok(Some(r));
                        }
                    }
                } else {
                    // Non-solid: each file is independently compressed
                    let total_unpack: u64 = block.unpack_sizes.iter().sum();
                    for coder_idx in ordered_coder_iter(block) {
                        let coder = &block.coders[coder_idx];
                        current_reader = super::decode::wrap_coder(
                            current_reader,
                            coder,
                            total_unpack as usize,
                        )?;
                    }

                    let mut file_data = Vec::with_capacity(file.size as usize);
                    current_reader
                        .read_to_end(&mut file_data)
                        .map_err(|e| LimitHit::corrupt(format!("7z: decompress: {e}")))?;

                    file_data.truncate(file.size as usize);
                    let entry = Entry::new(name, file_data);
                    if let Some(r) = visit(entry, budget) {
                        return Ok(Some(r));
                    }
                }
            }
            _ => {
                // File has no associated block (empty file or directory)
            }
        }
    }

    Ok(None)
}
