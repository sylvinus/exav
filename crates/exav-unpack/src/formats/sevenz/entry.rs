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
        // Each coder decodes to its own declared size, the one for its first
        // output stream; the folder's total is the last coder's.
        let first_out: u64 = block.coders[..coder_idx]
            .iter()
            .fold(0u64, |n, c| n.saturating_add(c.num_out_streams));
        let size = usize::try_from(first_out)
            .ok()
            .and_then(|i| block.unpack_sizes.get(i).copied())
            .unwrap_or(expected_total);
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        current = super::decode::wrap_coder(current, coder, size, password, max_buffer)?;
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
) -> Result<Decoded, LimitHit> {
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
    ) -> Result<Decoded, LimitHit> {
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
        let mut failed = None;
        for k in 0..coder.num_in_streams {
            let gi = in_base[coder_idx] + k;
            if let Some(bp) = block.bind_pairs.iter().find(|b| b.in_index == gi) {
                let src = producer(bp.out_index)
                    .ok_or_else(|| LimitHit::corrupt("7z: bind pair names no coder".to_string()))?;
                let (input, f) = materialise(g, src, seen)?;
                failed = failed.or(f);
                inputs.push(input);
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
        let out_size = crate::bytes::to_usize(
            usize::try_from(out_base[coder_idx])
                .ok()
                .and_then(|i| block.unpack_sizes.get(i))
                .copied()
                .unwrap_or_else(|| super::header::folder_out_size(block)),
        );
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
            return super::bcj2::decode(&inputs[0], &inputs[1], &inputs[2], &inputs[3], out_size)
                .map(|out| (out, failed));
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
        let (buf, f) = read_salvaged(&mut r, max_buffer)?;
        Ok((buf, failed.or(f)))
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
) -> Result<Decoded, LimitHit> {
    // A folder whose coders take more inputs than there are coders cannot be a
    // simple chain (BCJ2 is the case in practice), so resolve the bind-pair
    // graph instead. `pack_data` covers the block's packed streams laid end to
    // end; split them by their declared sizes.
    if block.coders.iter().any(|c| c.num_in_streams > 1) {
        let mut slices: Vec<&[u8]> = Vec::with_capacity(pack_sizes.len());
        let mut off = 0usize;
        for s in pack_sizes {
            let end = off.saturating_add(crate::bytes::to_usize(*s));
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
    // peak-buffer limit.
    read_salvaged(&mut current, max_buffer)
}

/// A block's output decoded whole, and the error that stopped it early, if
/// one did. What was decoded before the error is kept: members in it are
/// still scanned.
type Decoded = (Vec<u8>, Option<std::io::Error>);

/// Read `r` whole, up to `max_buffer` bytes, keeping what was decoded
/// before an error.
fn read_salvaged(r: &mut dyn Read, max_buffer: u64) -> Result<Decoded, LimitHit> {
    let s = crate::salvage(r, max_buffer);
    if s.over_cap {
        return Err(LimitHit::new("7z block exceeds max-buffer".to_string()));
    }
    // Every packed stream of a listed folder is in the file, so a decoder
    // that ran out of input was damaged as surely as one that failed.
    let failed = (s.undecoded || s.cut_short).then(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "7z: block failed to decode part way",
        )
    });
    Ok((s.data, failed))
}

/// The end of a block decoded whole: the error that stopped its decoder, or
/// the end of the block.
struct Failed(Option<std::io::Error>);

impl Read for Failed {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        self.0.take().map_or(Ok(0), Err)
    }
}

/// The decoder of the solid block being walked, and how many of its decoded
/// bytes have been read. The members of a block follow each other in it, so
/// the next one starts where this one left off: starting the decoder over for
/// each is a pass over the block per member.
struct Solid {
    block: usize,
    reader: Box<dyn Read>,
    pos: u64,
}

/// What is known of the passwords for the encrypted block being walked: the
/// one that decrypted a member, with the block it decrypted, and those that
/// are not it.
struct AesBlock {
    block: usize,
    good: Option<Vec<u8>>,
    wrong: Vec<bool>,
}

/// A reader that counts what is read through it.
struct Counted<'a> {
    inner: &'a mut dyn Read,
    read: u64,
}

impl Read for Counted<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(out)?;
        self.read += n as u64;
        Ok(n)
    }
}

/// Read and discard up to `n` decompressed bytes from `r`. Returns how many
/// were skipped (fewer than `n` means the stream ended or failed first) and
/// whether it failed. Constant memory: used to advance a block reader to a
/// file's offset within a solid block without buffering the skipped prefix.
fn skip_reader(r: &mut dyn Read, n: u64) -> (u64, bool) {
    let mut skipped = 0u64;
    let mut buf = [0u8; 8192];
    while skipped < n {
        let want = ((n - skipped).min(buf.len() as u64)) as usize;
        match r.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(k) => skipped += k as u64,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return (skipped, true),
        }
    }
    (skipped, false)
}

/// The packed bytes of folder `block_idx`, and the size of each of its packed
/// streams. A folder can have several (BCJ2 folders have four), laid end to
/// end; the sizes let the graph decoder split them apart again. `Err` says
/// why the header puts them out of reach.
fn block_pack_data<'a>(
    archive: &super::header::Archive,
    block_idx: usize,
    data: &'a [u8],
) -> Result<(&'a [u8], Vec<u64>), &'static str> {
    const MISSING: &str = "7z: folder names a packed stream the header does not list";
    const PAST_END: &str = "7z: packed data runs past the end of the archive";
    let block = &archive.blocks[block_idx];
    let first = archive
        .stream_map
        .block_first_pack_stream
        .get(block_idx)
        .copied()
        .ok_or(MISSING)?;
    let n_pack = block.packed_streams.len().max(1);
    let sizes = first
        .checked_add(n_pack)
        .and_then(|end| archive.pack_sizes.get(first..end))
        .ok_or(MISSING)?
        .to_vec();
    let start = SIGNATURE_HEADER_SIZE
        .checked_add(archive.pack_pos)
        .and_then(|v| v.checked_add(archive.stream_map.pack_stream_offsets[first]))
        .ok_or(PAST_END)?;
    let end = sizes
        .iter()
        .try_fold(start, |acc, &s| acc.checked_add(s))
        .ok_or(PAST_END)?;
    let range = usize::try_from(start)
        .ok()
        .zip(usize::try_from(end).ok())
        .ok_or(PAST_END)?;
    data.get(range.0..range.1)
        .map(|packed| (packed, sizes))
        .ok_or(PAST_END)
}

/// Walk a 7z archive. Its header is at the end, so the container is read whole;
/// each member's decompressed output then streams, which is where a solid
/// block can be far larger than the archive.
pub(crate) fn walk<T>(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    let data = crate::stream::read_whole(Format::SevenZip, src, budget)?;
    stream_sevenz(&data, budget, visit)
}

/// Streaming 7z extraction (pattern A): each file's solid block is built as a
/// forward-only `Read`; the file is emitted by skipping to its offset and handing
/// the visitor a `take(size)` window — the decompressed block is never buffered,
/// so a huge solid archive is scanned in bounded memory. AES members keep the
/// buffered CRC/password path (rare). The 7z container itself is still parsed
/// from `data` (the header lives at the end → random access), but its members'
/// decompressed output streams.
fn stream_sevenz<T>(
    data: &[u8],
    budget: &mut Budget,
    visit: crate::stream::Visit<T>,
) -> Result<Option<T>, LimitHit> {
    use crate::stream::{emit_bytes, emit_stream, MemberMeta};
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
                    size: None,
                    encrypted: true,
                    unsupported: Some("7z: encrypted header, unsupported codec"),
                    ..MemberMeta::default()
                };
                return Ok(visit(&meta, None, budget));
            }
            return Err(e);
        }
    };
    let passwords: Vec<String> = budget.passwords.clone();
    let max_buffer = budget.limits.max_buffer_bytes;
    let mut solid: Option<Solid> = None;
    let mut aes_state: Option<AesBlock> = None;
    // Sizes added up once, not for each member over the members before it.
    let mut before: Vec<u64> = Vec::with_capacity(archive.files.len() + 1);
    before.push(0);
    for f in &archive.files {
        before.push(before[before.len() - 1].saturating_add(f.size));
    }

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
        // From here on the header names a member with content, so whatever
        // keeps its bytes out of reach is reported, never skipped.
        let out_of_reach = |name: String, reason: &'static str| MemberMeta {
            name,
            comp_size: file.size,
            size: Some(file.size),
            unsupported: Some(reason),
            ..MemberMeta::default()
        };
        let Some(block_idx) = archive
            .stream_map
            .file_block
            .get(file_idx)
            .copied()
            .flatten()
        else {
            let meta = out_of_reach(name, "7z: member has no folder in the header");
            if let Some(r) = visit(&meta, None, budget) {
                return Ok(Some(r));
            }
            continue;
        };
        let block = &archive.blocks[block_idx];
        let aes = block_has_aes(block);
        if let Some(reason) = has_unsupported_codec(block, !passwords.is_empty()) {
            let meta = MemberMeta {
                name,
                comp_size: file.size,
                size: Some(file.size),
                encrypted: true,
                unsupported: Some(reason),
                ..MemberMeta::default()
            };
            if let Some(r) = visit(&meta, None, budget) {
                return Ok(Some(r));
            }
            continue;
        }

        let (pack_data, block_pack_sizes) = match block_pack_data(&archive, block_idx, data) {
            Ok(v) => v,
            Err(reason) => {
                let meta = out_of_reach(name, reason);
                if let Some(r) = visit(&meta, None, budget) {
                    return Ok(Some(r));
                }
                continue;
            }
        };

        // Byte offset of this file within the (solid) block.
        let block_first_file = archive
            .stream_map
            .block_first_file
            .get(block_idx)
            .copied()
            .unwrap_or(0);
        let bytes_to_skip: u64 = if file_idx > block_first_file {
            before[file_idx.min(archive.files.len())]
                .saturating_sub(before[block_first_file.min(archive.files.len())])
        } else {
            0
        };
        let block_total = super::header::folder_out_size(block);

        if aes {
            // Encrypted: decode the whole block (bounded), CRC-verify, try each
            // password — the buffered path, since streaming can't retry/verify.
            // The block is decrypted once, not once per member: each decryption
            // derives the key again (2^19 SHA-256 rounds or more) and decodes
            // the block. A password is dropped for the block when its decode
            // fails or its first member does not check out: a wrong key gives
            // garbage for every member, and a right one is told by the CRC.
            if aes_state.as_ref().is_none_or(|s| s.block != block_idx) {
                aes_state = Some(AesBlock {
                    block: block_idx,
                    good: None,
                    wrong: vec![false; passwords.len()],
                });
            }
            let Some(state) = aes_state.as_mut() else {
                continue;
            };
            let member = |dec: &[u8]| -> Option<Vec<u8>> {
                let start = crate::bytes::to_usize(bytes_to_skip);
                if start >= dec.len() {
                    return None;
                }
                let end = start
                    .saturating_add(crate::bytes::to_usize(file.size))
                    .min(dec.len());
                let fd = dec[start..end].to_vec();
                if file.has_crc {
                    let mut h = crc32fast::Hasher::new();
                    h.update(&fd);
                    if h.finalize() != file.crc {
                        return None;
                    }
                }
                Some(fd)
            };
            let mut file_data: Option<Vec<u8>> = None;
            if let Some(dec) = &state.good {
                file_data = member(dec);
            } else {
                for (i, pw) in passwords.iter().enumerate() {
                    if state.wrong[i] {
                        continue;
                    }
                    // A decode that fails is a wrong password as likely as
                    // damage: try the next one.
                    match decode_block(
                        block,
                        pack_data,
                        &block_pack_sizes,
                        block_total,
                        Some(pw.as_str()),
                        max_buffer,
                    ) {
                        Ok((dec, None)) => match member(&dec) {
                            Some(fd) => {
                                file_data = Some(fd);
                                state.good = Some(dec);
                                break;
                            }
                            None => state.wrong[i] = true,
                        },
                        Ok((_, Some(_))) | Err(_) => state.wrong[i] = true,
                    }
                }
            }
            let r = match file_data {
                // Decrypted, and still reported as encrypted: the plaintext is
                // scanned, and cracking the password does not erase the fact.
                Some(fd) => {
                    let meta = MemberMeta {
                        name,
                        comp_size: file.size,
                        size: Some(file.size),
                        encrypted: true,
                        ..MemberMeta::default()
                    };
                    emit_bytes(&meta, Some(fd), budget, visit)?
                }
                None => {
                    let meta = MemberMeta {
                        name,
                        comp_size: file.size,
                        size: Some(file.size),
                        encrypted: true,
                        unsupported: Some("7z: wrong or missing password"),
                        ..MemberMeta::default()
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
                size: Some(file.size),
                unsupported: Some("7z: member starts past the peak-buffer limit"),
                ..MemberMeta::default()
            };
            if let Some(t) = visit(&meta, None, budget) {
                return Ok(Some(t));
            }
            continue;
        }
        // A multi-input folder (BCJ2) cannot be streamed as a linear chain: its
        // filter needs all four streams present at once. Decode the block
        // buffered instead, bounded by the same peak-buffer limit.
        if !solid
            .as_ref()
            .is_some_and(|s| s.block == block_idx && s.pos <= bytes_to_skip)
        {
            let reader: Box<dyn Read> = if block.coders.iter().any(|c| c.num_in_streams > 1) {
                let (decoded, failed) = decode_block(
                    block,
                    pack_data,
                    &block_pack_sizes,
                    block_total,
                    None,
                    max_buffer,
                )?;
                Box::new(Cursor::new(decoded).chain(Failed(failed)))
            } else {
                decode_block_reader(block, pack_data, block_total, None, max_buffer)?
            };
            solid = Some(Solid {
                block: block_idx,
                reader,
                pos: 0,
            });
        }
        let Some(s) = solid.as_mut() else {
            continue;
        };
        let (skipped, failed) = skip_reader(s.reader.as_mut(), bytes_to_skip - s.pos);
        s.pos += skipped;
        if s.pos < bytes_to_skip {
            // The block ended before this file's offset: the sub-stream table
            // claims more content than the block decodes to. Every later member
            // of a solid block is in the same position, so leaving these out
            // quietly turns a truncated archive into a short, clean-looking one.
            let meta = MemberMeta {
                name,
                comp_size: file.size,
                size: Some(file.size),
                unsupported: Some(if failed {
                    "7z: solid block failed to decode before this member"
                } else {
                    "7z: solid block ended before this member"
                }),
                ..MemberMeta::default()
            };
            if let Some(t) = visit(&meta, None, budget) {
                return Ok(Some(t));
            }
            continue;
        }
        let mut window = Counted {
            inner: s.reader.as_mut(),
            read: 0,
        }
        .take(file.size);
        let meta = MemberMeta {
            name,
            comp_size: file.size,
            size: Some(file.size),
            ..MemberMeta::default()
        };
        let emitted = emit_stream(&meta, &mut window, budget, visit);
        // Where the next member of the block starts from: what was read,
        // which may be less than the member's size.
        s.pos += window.get_ref().read;
        if let Some(t) = emitted? {
            return Ok(Some(t));
        }
    }
    Ok(None)
}
