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

/// Decode a block whose coder graph is **not** a simple chain — in practice a
/// folder containing BCJ2, which takes four input streams instead of one.
///
/// The linear path above walks coders in order, feeding each the previous one's
/// output. That cannot express a coder with several inputs, so this resolves the
/// folder's bind-pair graph instead: every coder input is either bound to
/// another coder's output or fed by one of the block's packed streams, and each
/// is materialised on demand.
fn decode_block_graph(
    block: &super::header::Block,
    pack_streams: &[&[u8]],
    password: Option<&str>,
    max_buffer: u64,
) -> Result<Vec<u8>, LimitHit> {
    // Exclusive prefix sums: the global index of each coder's first in/out stream.
    let mut in_base = Vec::with_capacity(block.coders.len());
    let mut out_base = Vec::with_capacity(block.coders.len());
    let (mut i_acc, mut o_acc) = (0u64, 0u64);
    for c in &block.coders {
        in_base.push(i_acc);
        out_base.push(o_acc);
        i_acc += c.num_in_streams;
        o_acc += c.num_out_streams;
    }
    // Which coder produces a given global output index?
    let producer =
        |out_idx: u64| -> Option<usize> {
            block.coders.iter().enumerate().position(|(i, c)| {
                out_idx >= out_base[i] && out_idx < out_base[i] + c.num_out_streams
            })
        };

    // Materialise one coder's output, recursing through its inputs. Depth is
    // bounded by the coder count, and `seen` stops a bind-pair cycle in a forged
    // header from recursing forever.
    struct Graph<'a> {
        block: &'a super::header::Block,
        pack_streams: &'a [&'a [u8]],
        in_base: &'a [u64],
        out_base: &'a [u64],
        producer: &'a dyn Fn(u64) -> Option<usize>,
        password: Option<&'a str>,
        max_buffer: u64,
    }

    fn materialise(
        g: &Graph<'_>,
        coder_idx: usize,
        seen: &mut Vec<usize>,
    ) -> Result<Vec<u8>, LimitHit> {
        let block = g.block;
        let pack_streams = g.pack_streams;
        let in_base = g.in_base;
        let out_base = g.out_base;
        let producer = g.producer;
        let password = g.password;
        let max_buffer = g.max_buffer;
        if seen.contains(&coder_idx) {
            return Err(LimitHit::corrupt("7z: cyclic coder graph".to_string()));
        }
        seen.push(coder_idx);
        let coder = block
            .coders
            .get(coder_idx)
            .ok_or_else(|| LimitHit::corrupt("7z: coder index out of range".to_string()))?;

        // Resolve each input of this coder to a concrete buffer.
        let mut inputs: Vec<Vec<u8>> = Vec::new();
        for k in 0..coder.num_in_streams {
            let gi = in_base[coder_idx] + k;
            if let Some(bp) = block.bind_pairs.iter().find(|b| b.in_index == gi) {
                let src = producer(bp.out_index)
                    .ok_or_else(|| LimitHit::corrupt("7z: bind pair names no coder".to_string()))?;
                inputs.push(materialise(g, src, seen)?);
            } else {
                // Fed directly by one of the block's packed streams; their order
                // in `packed_streams` is the order of the packed data.
                let pos = block
                    .packed_streams
                    .iter()
                    .position(|&p| p as u64 == gi)
                    .ok_or_else(|| {
                        LimitHit::corrupt("7z: coder input has no source".to_string())
                    })?;
                let s = pack_streams
                    .get(pos)
                    .ok_or_else(|| LimitHit::corrupt("7z: packed stream missing".to_string()))?;
                inputs.push(s.to_vec());
            }
        }
        seen.pop();

        // Each coder declares its OWN output size; handing a sub-coder the
        // whole folder's size makes it decode far past its stream (LZMA reports
        // a distance overflow), so look up this coder's entry.
        let out_size = block
            .unpack_sizes
            .get(out_base[coder_idx] as usize)
            .copied()
            .unwrap_or_else(|| super::header::folder_out_size(block))
            as usize;
        if coder.method_id.as_slice() == super::parse::ID_BCJ2 {
            if inputs.len() != 4 {
                return Err(LimitHit::corrupt(
                    "7z BCJ2: expected four input streams".to_string(),
                ));
            }
            // BCJ2 writes into a buffer instead of through a `Read`, so the
            // `bounded_read` cap the linear chain below relies on never sees
            // this path. `out_size` is a header var-int and nothing else bounds
            // it, so refuse here — an allocation this large fails, and a failed
            // allocation aborts the process rather than unwinding, which the
            // per-file panic boundary cannot catch.
            if out_size as u64 > max_buffer {
                return Err(LimitHit::new("7z BCJ2 output exceeds max-buffer".into()));
            }
            return super::bcj2::decode(&inputs[0], &inputs[1], &inputs[2], &inputs[3], out_size);
        }
        let single = inputs
            .into_iter()
            .next()
            .ok_or_else(|| LimitHit::corrupt("7z: coder has no input".to_string()))?;
        let mut r = super::decode::wrap_coder(
            Box::new(Cursor::new(single)),
            coder,
            out_size,
            password,
            max_buffer,
        )?;
        let (buf, truncated) = crate::bounded_read(&mut r, max_buffer)
            .map_err(|e| LimitHit::corrupt(format!("7z: coder read: {e}")))?;
        if truncated {
            return Err(LimitHit::new("7z block exceeds max-buffer".into()));
        }
        Ok(buf)
    }

    // The block's result is the output nothing else consumes.
    let final_coder = (0..block.coders.len())
        .find(|&i| {
            let o = out_base[i];
            !block.bind_pairs.iter().any(|b| b.out_index == o)
        })
        .ok_or_else(|| LimitHit::corrupt("7z: no terminal coder".to_string()))?;
    let mut seen = Vec::new();
    let graph = Graph {
        block,
        pack_streams,
        in_base: &in_base,
        out_base: &out_base,
        producer: &producer,
        password,
        max_buffer,
    };
    materialise(&graph, final_coder, &mut seen)
}

/// Run a block's full coder chain over its packed data and return the whole
/// decompressed block. `password` is threaded to an AES coder (if any). Used by
/// the buffered extractor and the AES branch of the streaming one.
fn decode_block(
    block: &super::header::Block,
    pack_data: &[u8],
    pack_sizes: &[u64],
    expected_total: u64,
    password: Option<&str>,
    max_buffer: u64,
) -> Result<Vec<u8>, LimitHit> {
    // A folder whose coders take more inputs than there are coders cannot be a
    // simple chain (BCJ2 is the case in practice), so resolve the bind-pair
    // graph instead. `pack_data` covers the block's packed streams laid end to
    // end; split them by their declared sizes.
    if block.coders.iter().any(|c| c.num_in_streams > 1) {
        let mut slices: Vec<&[u8]> = Vec::with_capacity(pack_sizes.len());
        let mut off = 0usize;
        for s in pack_sizes {
            let end = off.saturating_add(*s as usize);
            if end > pack_data.len() {
                return Err(LimitHit::corrupt(
                    "7z: packed stream extends past the archive".to_string(),
                ));
            }
            slices.push(&pack_data[off..end]);
            off = end;
        }
        return decode_block_graph(block, &slices, password, max_buffer);
    }
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
    let archive = match parse_archive(data, &budget.passwords) {
        Ok(a) => a,
        Err(e) => {
            let reason = e.reason.as_str();
            let is_encrypted = reason.contains("unsupported codec")
                || reason.contains("unsupported 7z codec")
                || reason.contains("AES")
                || reason.contains("encrypted header");
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
    let max_buffer = budget.limits.max_buffer_bytes;

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
        // A folder can have several packed streams (BCJ2 folders have four),
        // laid end to end. Cover all of them, and keep the individual sizes so
        // the graph decoder can split them apart again.
        let n_pack = block.packed_streams.len().max(1);
        let block_pack_sizes: Vec<u64> = (0..n_pack)
            .filter_map(|k| archive.pack_sizes.get(pack_stream_idx + k).copied())
            .collect();
        let pack_size: usize = block_pack_sizes.iter().sum::<u64>() as usize;
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
                match decode_block(
                    block,
                    pack_data,
                    &block_pack_sizes,
                    block_total,
                    pw,
                    max_buffer,
                ) {
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
        // in a block bigger than we would decode buffered. Its bytes are not
        // reachable, and a member nobody looked at is reported rather than
        // dropped — the rest of the archive still scans.
        if bytes_to_skip > max_buffer {
            let meta = MemberMeta {
                name,
                comp_size: file.size,
                encrypted: false,
                unsupported: Some("7z: member starts past the peak-buffer limit"),
            };
            if let Some(t) = visit(&meta, None, budget) {
                return Ok(Some(t));
            }
            continue;
        }
        // A multi-input folder (BCJ2) cannot be streamed as a linear chain: its
        // filter needs all four streams present at once. Decode the block
        // buffered instead, bounded by the same peak-buffer limit.
        let mut reader: Box<dyn Read> = if block.coders.iter().any(|c| c.num_in_streams > 1) {
            let decoded = decode_block(
                block,
                pack_data,
                &block_pack_sizes,
                block_total,
                None,
                max_buffer,
            )?;
            Box::new(Cursor::new(decoded))
        } else {
            decode_block_reader(block, pack_data, block_total, None, max_buffer)?
        };
        if skip_reader(reader.as_mut(), bytes_to_skip) < bytes_to_skip {
            // The block ended before this file's offset: the sub-stream table
            // claims more content than the block decodes to. Every later member
            // of a solid block is in the same position, so leaving these out
            // quietly turns a truncated archive into a short, clean-looking one.
            let meta = MemberMeta {
                name,
                comp_size: file.size,
                encrypted: false,
                unsupported: Some("7z: solid block ended before this member"),
            };
            if let Some(t) = visit(&meta, None, budget) {
                return Ok(Some(t));
            }
            continue;
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
    let archive = match parse_archive(data, &budget.passwords) {
        Ok(a) => a,
        Err(e) => {
            // If parsing fails (e.g. encrypted header), emit a single
            // encrypted+unsupported entry so callers can detect the format.
            let reason = e.reason.as_str();
            let is_encrypted = reason.contains("unsupported codec")
                || reason.contains("unsupported 7z codec")
                || reason.contains("AES")
                || reason.contains("encrypted header");
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
                // Cover every packed stream of the folder (BCJ2 folders have
                // four, laid end to end), keeping the individual sizes so the
                // graph decoder can split them apart.
                let n_pack = block.packed_streams.len().max(1);
                let block_pack_sizes: Vec<u64> = (0..n_pack)
                    .filter_map(|k| archive.pack_sizes.get(pack_stream_idx + k).copied())
                    .collect();
                let pack_size: usize = block_pack_sizes.iter().sum::<u64>() as usize;

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
                        &block_pack_sizes,
                        block_total,
                        pw,
                        budget.limits.max_buffer_bytes,
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
                    // Not encrypted, and still no data: the block decoded
                    // shorter than the sub-stream table says it should, so this
                    // member's offset falls past the end of it. In a solid block
                    // every member after the cut is in the same position, and
                    // dropping them quietly leaves a truncated archive looking
                    // like a short and harmless one.
                    None => {
                        let entry = Entry::unsupported(
                            name,
                            file.size,
                            false,
                            "7z: solid block ended before this member",
                        );
                        if let Some(r) = visit(entry, budget) {
                            return Ok(Some(r));
                        }
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
