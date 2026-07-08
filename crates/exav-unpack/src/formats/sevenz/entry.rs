//! Public entry point for 7z extraction.

use super::header::{ordered_coder_iter, parse_archive};
use super::parse::SIGNATURE_HEADER_SIZE;
use crate::*;
use std::io::{Cursor, Read};

/// True if any coder in the block is 7zAES encryption.
fn block_has_aes(block: &super::header::Block) -> bool {
    block
        .coders
        .iter()
        .any(|c| c.method_id.as_slice() == super::parse::ID_AES)
}

/// Check whether a block's coder chain contains a codec we cannot decode.
/// AES is decodable *iff* a password is available (and the `decrypt` feature is
/// on); with no password it is reported encrypted, as before.
fn has_unsupported_codec(block: &super::header::Block, has_password: bool) -> Option<&'static str> {
    for coder in &block.coders {
        if coder.method_id.as_slice() == super::parse::ID_AES {
            if has_password && cfg!(feature = "decrypt") {
                continue; // decodable — handled by wrap_coder with the password
            }
            return Some("7z AES-256 encryption");
        }
        if !super::decode::is_known_codec(coder.method_id.as_slice()) {
            return Some("unsupported 7z codec");
        }
    }
    None
}

/// Build the block's coder chain as a **forward-only `Read`** over its packed
/// data, without decoding it. The streaming path reads this incrementally (skip
/// to a file's offset, then `take(size)`) so the whole decompressed solid block
/// is never buffered. `password` is threaded to an AES coder (if any).
fn decode_block_reader(
    block: &super::header::Block,
    pack_data: &[u8],
    expected_total: u64,
    password: Option<&str>,
    max_buffer: u64,
) -> Result<Box<dyn Read>, LimitHit> {
    let mut current: Box<dyn Read> = Box::new(Cursor::new(pack_data.to_vec()));
    for coder_idx in ordered_coder_iter(block) {
        let coder = &block.coders[coder_idx];
        current = super::decode::wrap_coder(
            current,
            coder,
            expected_total as usize,
            password,
            max_buffer,
        )?;
    }
    Ok(current)
}

/// Run a block's full coder chain over its packed data and return the whole
/// decompressed block. `password` is threaded to an AES coder (if any). Used by
/// the buffered extractor and the AES branch of the streaming one.
fn decode_block(
    block: &super::header::Block,
    pack_data: &[u8],
    expected_total: u64,
    password: Option<&str>,
    max_buffer: u64,
) -> Result<Vec<u8>, LimitHit> {
    let mut current = decode_block_reader(block, pack_data, expected_total, password, max_buffer)?;
    // A 7z block is a *solid* unit that may hold many members; its decompressed
    // size can amplify far beyond the packed input. Bound it by the global
    // peak-buffer limit (read cap+1, then reject if it overran).
    let (out, truncated) = crate::bounded_read(&mut current, max_buffer)
        .map_err(|e| LimitHit::corrupt(format!("7z: decompress: {e}")))?;
    if truncated {
        return Err(LimitHit::new("7z block exceeds max-buffer".to_string()));
    }
    Ok(out)
}

/// Read and discard up to `n` decompressed bytes from `r`, returning how many
/// were actually skipped (fewer than `n` means the stream ended first). Constant
/// memory — used to advance a block reader to a file's offset within a solid
/// block without buffering the skipped prefix.
fn skip_reader(r: &mut dyn Read, n: u64) -> u64 {
    let mut skipped = 0u64;
    let mut buf = [0u8; 8192];
    while skipped < n {
        let want = ((n - skipped).min(buf.len() as u64)) as usize;
        match r.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(k) => skipped += k as u64,
            Err(_) => break,
        }
    }
    skipped
}

/// Streaming 7z extraction (pattern A): each file's solid block is built as a
/// forward-only `Read`; the file is emitted by skipping to its offset and handing
/// the visitor a `take(size)` window — the decompressed block is never buffered,
/// so a huge solid archive is scanned in bounded memory. AES members keep the
/// buffered CRC/password path (rare). The 7z container itself is still parsed
/// from `data` (the header lives at the end → random access), but its members'
/// decompressed output streams.
pub(crate) fn stream_sevenz<T>(
    data: &[u8],
    budget: &mut Budget,
    visit: crate::stream::StreamVisit<T>,
) -> Result<Option<T>, LimitHit> {
    use crate::stream::{visit_member, MemberMeta};
    let archive = match parse_archive(data) {
        Ok(a) => a,
        Err(e) => {
            let reason = e.reason.as_str();
            let is_encrypted = reason.contains("unsupported codec")
                || reason.contains("unsupported 7z codec")
                || reason.contains("AES");
            if is_encrypted {
                budget.count_entry()?;
                let meta = MemberMeta {
                    name: "encrypted.7z".to_string(),
                    comp_size: data.len() as u64,
                    encrypted: true,
                    unsupported: Some("7z: encrypted header, unsupported codec"),
                };
                return Ok(visit(&meta, None, budget));
            }
            return Err(e);
        }
    };
    let passwords: Vec<String> = budget.passwords.clone();
    let max_buffer = budget.limits.max_buffer_bytes();

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
        let block_idx = match archive.stream_map.file_block.get(file_idx).copied() {
            Some(Some(b)) => b,
            _ => continue, // no stream (empty file / directory)
        };
        let block = &archive.blocks[block_idx];
        let aes = block_has_aes(block);
        if let Some(reason) = has_unsupported_codec(block, !passwords.is_empty()) {
            let meta = MemberMeta {
                name,
                comp_size: file.size,
                encrypted: true,
                unsupported: Some(reason),
            };
            if let Some(r) = visit(&meta, None, budget) {
                return Ok(Some(r));
            }
            continue;
        }

        // Locate the packed data for the block (same derivation as extract_sevenz).
        let pack_stream_idx = archive
            .stream_map
            .block_first_pack_stream
            .get(block_idx)
            .copied()
            .unwrap_or(0);
        if pack_stream_idx >= archive.pack_sizes.len() {
            continue;
        }
        let pack_offset = match SIGNATURE_HEADER_SIZE
            .checked_add(archive.pack_pos)
            .and_then(|v| v.checked_add(archive.stream_map.pack_stream_offsets[pack_stream_idx]))
            .and_then(|v| usize::try_from(v).ok())
        {
            Some(v) => v,
            None => continue,
        };
        let pack_size = archive.pack_sizes[pack_stream_idx] as usize;
        let pack_end = match pack_offset.checked_add(pack_size) {
            Some(e) if e <= data.len() => e,
            _ => continue,
        };
        let pack_data = &data[pack_offset..pack_end];

        // Byte offset of this file within the (solid) block.
        let block_first_file = archive
            .stream_map
            .block_first_file
            .get(block_idx)
            .copied()
            .unwrap_or(0);
        let sub_index = file_idx.saturating_sub(block_first_file);
        let mut bytes_to_skip: u64 = 0;
        for si in 0..sub_index {
            let sub_file_idx = block_first_file + si;
            if sub_file_idx < archive.files.len() {
                bytes_to_skip = bytes_to_skip.saturating_add(archive.files[sub_file_idx].size);
            }
        }
        let block_total = super::header::folder_out_size(block);

        if aes {
            // Encrypted: decode the whole block (bounded), CRC-verify, try each
            // password — the buffered path, since streaming can't retry/verify.
            let mut file_data: Option<Vec<u8>> = None;
            for pw in passwords.iter().map(|p| Some(p.as_str())) {
                match decode_block(block, pack_data, block_total, pw, max_buffer) {
                    Ok(dec) => {
                        let start = bytes_to_skip as usize;
                        if start >= dec.len() {
                            continue;
                        }
                        let end = start.saturating_add(file.size as usize).min(dec.len());
                        let fd = dec[start..end].to_vec();
                        if file.has_crc {
                            let mut h = crc32fast::Hasher::new();
                            h.update(&fd);
                            if h.finalize() != file.crc {
                                continue;
                            }
                        }
                        file_data = Some(fd);
                        break;
                    }
                    Err(_) => continue,
                }
            }
            let r = match file_data {
                Some(fd) => {
                    let meta = MemberMeta {
                        name,
                        comp_size: file.size,
                        encrypted: false,
                        unsupported: None,
                    };
                    let mut cur = Cursor::new(fd);
                    visit(&meta, Some(&mut cur), budget)
                }
                None => {
                    let meta = MemberMeta {
                        name,
                        comp_size: file.size,
                        encrypted: true,
                        unsupported: Some("7z: wrong or missing password"),
                    };
                    visit(&meta, None, budget)
                }
            };
            if let Some(t) = r {
                return Ok(Some(t));
            }
            continue;
        }

        // Non-AES: stream. A file whose start is past the peak-buffer limit sits
        // in a block bigger than we would decode buffered — skip it, matching the
        // buffered path's `start >= decoded_len` guard.
        if bytes_to_skip > max_buffer {
            continue;
        }
        let mut reader = decode_block_reader(block, pack_data, block_total, None, max_buffer)?;
        if skip_reader(reader.as_mut(), bytes_to_skip) < bytes_to_skip {
            continue; // block ended before this file's offset
        }
        let mut window = reader.take(file.size);
        let meta = MemberMeta {
            name,
            comp_size: file.size,
            encrypted: false,
            unsupported: None,
        };
        if let Some(t) = visit_member(&meta, &mut window, budget, visit)? {
            return Ok(Some(t));
        }
    }
    Ok(None)
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

    // Clone candidate passwords out of the budget so they can be borrowed while
    // `budget` is used mutably (count_entry/visit) in the loop below.
    let passwords: Vec<String> = budget.passwords.clone();

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

                let aes = block_has_aes(block);

                // Check for unsupported codecs (encryption, etc.). AES is
                // decodable when a password is available; otherwise unsupported.
                if let Some(reason) = has_unsupported_codec(block, !passwords.is_empty()) {
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

                // pack_pos / pack_stream_offsets / pack_sizes are all derived from
                // attacker-controlled var-ints; a bare `+` panics under
                // overflow-checks. An offset that overflows can only point past
                // the file, so skip such a member.
                let pack_offset = match SIGNATURE_HEADER_SIZE
                    .checked_add(archive.pack_pos)
                    .and_then(|v| {
                        v.checked_add(archive.stream_map.pack_stream_offsets[pack_stream_idx])
                    })
                    .and_then(|v| usize::try_from(v).ok())
                {
                    Some(v) => v,
                    None => continue,
                };
                let pack_size = archive.pack_sizes[pack_stream_idx] as usize;

                let pack_end = match pack_offset.checked_add(pack_size) {
                    Some(e) if e <= data.len() => e,
                    _ => continue,
                };

                let pack_data = &data[pack_offset..pack_end];

                // Find which sub-stream index this file is within the block, and
                // how many bytes of the (whole-block) output precede it.
                let block_first_file = archive
                    .stream_map
                    .block_first_file
                    .get(block_idx)
                    .copied()
                    .unwrap_or(0);
                // `block_first_file` is expected to be <= `file_idx`, but the
                // stream map is built from attacker data — guard the subtraction
                // so a stale/inconsistent value can't underflow-panic.
                let sub_index = file_idx.saturating_sub(block_first_file);
                let mut bytes_to_skip: u64 = 0;
                for si in 0..sub_index {
                    let sub_file_idx = block_first_file + si;
                    if sub_file_idx < archive.files.len() {
                        // `size` comes from attacker sub-stream sizes; saturate the
                        // running total instead of overflow-panicking.
                        bytes_to_skip =
                            bytes_to_skip.saturating_add(archive.files[sub_file_idx].size);
                    }
                }
                let block_total: u64 = super::header::folder_out_size(block);

                // Candidate passwords: for an AES block, try each supplied
                // passphrase; otherwise a single non-encrypted decode.
                let candidates: Vec<Option<&str>> = if aes {
                    passwords.iter().map(|p| Some(p.as_str())).collect()
                } else {
                    vec![None]
                };

                let mut file_data: Option<Vec<u8>> = None;
                for pw in candidates {
                    match decode_block(
                        block,
                        pack_data,
                        block_total,
                        pw,
                        budget.limits.max_buffer_bytes(),
                    ) {
                        Ok(decompressed) => {
                            let start = bytes_to_skip as usize;
                            if start >= decompressed.len() {
                                continue;
                            }
                            // `start` and `file.size` are attacker-controlled;
                            // saturate so the `+` can't overflow-panic before the
                            // `.min(len)` clamps it back into range.
                            let end = start
                                .saturating_add(file.size as usize)
                                .min(decompressed.len());
                            let fd = decompressed[start..end].to_vec();
                            // For an AES member, verify the stored CRC so a wrong
                            // passphrase (which yields plausible-looking garbage
                            // for a stored/copy stream) is rejected rather than
                            // emitted as data.
                            if aes && file.has_crc {
                                let mut h = crc32fast::Hasher::new();
                                h.update(&fd);
                                let got = h.finalize();
                                if got != file.crc {
                                    continue; // wrong password — try the next one
                                }
                            }
                            file_data = Some(fd);
                            break;
                        }
                        // A decode error on an AES block is a wrong-password
                        // symptom; try the next candidate rather than aborting.
                        Err(_) if aes => continue,
                        Err(e) => return Err(e),
                    }
                }

                match file_data {
                    Some(fd) => {
                        let entry = Entry::new(name, fd);
                        if let Some(r) = visit(entry, budget) {
                            return Ok(Some(r));
                        }
                    }
                    // AES block we couldn't decrypt (no/incorrect password):
                    // report encrypted/unsupported, never silently clean.
                    None if aes => {
                        let entry = Entry::unsupported(
                            name,
                            file.size,
                            true,
                            "7z: wrong or missing password",
                        );
                        if let Some(r) = visit(entry, budget) {
                            return Ok(Some(r));
                        }
                    }
                    None => {}
                }
            }
            _ => {
                // File has no associated block (empty file or directory)
            }
        }
    }

    Ok(None)
}
