//! Public entry point for 7z extraction.

use super::header::ordered_coder_iter;
use super::parse::SIGNATURE_HEADER_SIZE;
use crate::*;
use std::io::Read;

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
                continue; // decodable: handled by wrap_coder with the password
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
pub(super) fn decode_block_reader<'a>(
    block: &super::header::Block,
    pack_data: Box<dyn Read + 'a>,
    expected_total: u64,
    password: Option<crate::kdf::Pass<'_>>,
    max_buffer: u64,
) -> Result<Box<dyn Read + 'a>, LimitHit> {
    let mut current = pack_data;
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

/// Each coder feeds one input and each input has one bind pair, as 7-Zip
/// requires. A coder that fed several would be built once for each, and the
/// coders under it with it, so a few dozen bind pairs would make a graph of
/// more readers than memory holds.
fn outputs_bound_once(block: &super::header::Block) -> Result<(), LimitHit> {
    let mut fed = vec![false; block.coders.len()];
    for bp in &block.bind_pairs {
        let mut first_out = 0u64;
        for (i, c) in block.coders.iter().enumerate() {
            let end = first_out.saturating_add(c.num_out_streams);
            if (first_out..end).contains(&bp.out_index) {
                if std::mem::replace(&mut fed[i], true) {
                    return Err(LimitHit::corrupt(
                        "7z: a coder's output is bound to two inputs".to_string(),
                    ));
                }
                break;
            }
            first_out = end;
        }
    }
    let mut ins: Vec<u64> = block.bind_pairs.iter().map(|b| b.in_index).collect();
    ins.sort_unstable();
    if ins.windows(2).any(|w| w[0] == w[1]) {
        return Err(LimitHit::corrupt(
            "7z: a coder input is bound to two outputs".to_string(),
        ));
    }
    Ok(())
}

/// A block whose coder graph is not a chain (BCJ2) as a reader: each coder
/// input is the reader of the coder bound to it, or its packed stream read
/// from its place in `src`, so the folder is decoded as it is read and none
/// of it is held. `pack_start` is where its packed streams start, laid end to
/// end with `pack_sizes`. `password` is for the AES coders, one of which 7-Zip
/// puts on each packed stream of an encrypted BCJ2 folder.
fn graph_reader<'a>(
    block: &super::header::Block,
    src: &'a dyn crate::source::ByteSource,
    pack_start: usize,
    pack_sizes: &[u64],
    password: Option<crate::kdf::Pass<'_>>,
    max_buffer: u64,
) -> Result<Box<dyn Read + 'a>, LimitHit> {
    outputs_bound_once(block)?;
    struct Graph<'g> {
        block: &'g super::header::Block,
        in_base: Vec<u64>,
        out_base: Vec<u64>,
        packed: Vec<(usize, usize)>,
        password: Option<crate::kdf::Pass<'g>>,
        max_buffer: u64,
    }
    fn coder_reader<'a>(
        g: &Graph<'_>,
        src: &'a dyn crate::source::ByteSource,
        idx: usize,
        seen: &mut Vec<usize>,
    ) -> Result<Box<dyn Read + 'a>, LimitHit> {
        if seen.contains(&idx) {
            return Err(LimitHit::corrupt("7z: cyclic coder graph".to_string()));
        }
        seen.push(idx);
        let coder = g
            .block
            .coders
            .get(idx)
            .ok_or_else(|| LimitHit::corrupt("7z: coder index out of range".to_string()))?;
        let mut inputs: Vec<Box<dyn Read + 'a>> = Vec::new();
        for k in 0..coder.num_in_streams {
            let gi = g.in_base[idx] + k;
            if let Some(bp) = g.block.bind_pairs.iter().find(|b| b.in_index == gi) {
                let from = g
                    .block
                    .coders
                    .iter()
                    .enumerate()
                    .position(|(i, c)| {
                        bp.out_index >= g.out_base[i]
                            && bp.out_index < g.out_base[i] + c.num_out_streams
                    })
                    .ok_or_else(|| LimitHit::corrupt("7z: bind pair names no coder".to_string()))?;
                inputs.push(coder_reader(g, src, from, seen)?);
            } else {
                let (start, end) = g
                    .block
                    .packed_streams
                    .iter()
                    .position(|&p| p as u64 == gi)
                    .and_then(|pos| g.packed.get(pos).copied())
                    .ok_or_else(|| {
                        LimitHit::corrupt("7z: coder input has no source".to_string())
                    })?;
                inputs.push(Box::new(crate::source::Reader::range(src, start, end)));
            }
        }
        seen.pop();
        let out_size = usize::try_from(g.out_base[idx])
            .ok()
            .and_then(|i| g.block.unpack_sizes.get(i))
            .copied()
            .unwrap_or_else(|| super::header::folder_out_size(g.block));
        if coder.method_id.as_slice() == super::parse::ID_BCJ2 {
            let four: [Box<dyn Read + 'a>; 4] = inputs.try_into().map_err(|_| {
                LimitHit::corrupt("7z BCJ2: expected four input streams".to_string())
            })?;
            let r = super::bcj2::Reader::new(four, out_size)
                .map_err(|e| LimitHit::corrupt(format!("7z BCJ2: {e}")))?;
            return Ok(Box::new(r));
        }
        let single = inputs
            .into_iter()
            .next()
            .ok_or_else(|| LimitHit::corrupt("7z: coder has no input".to_string()))?;
        super::decode::wrap_coder(
            single,
            coder,
            crate::bytes::to_usize(out_size),
            g.password,
            g.max_buffer,
        )
    }
    let (mut in_base, mut out_base) = (Vec::new(), Vec::new());
    let (mut i_acc, mut o_acc) = (0u64, 0u64);
    for c in &block.coders {
        in_base.push(i_acc);
        out_base.push(o_acc);
        i_acc = i_acc.saturating_add(c.num_in_streams);
        o_acc = o_acc.saturating_add(c.num_out_streams);
    }
    let mut packed = Vec::with_capacity(pack_sizes.len());
    let mut at = pack_start;
    for &s in pack_sizes {
        let end = at.saturating_add(crate::bytes::to_usize(s));
        packed.push((at, end));
        at = end;
    }
    let final_coder = (0..block.coders.len())
        .find(|&i| !block.bind_pairs.iter().any(|b| b.out_index == out_base[i]))
        .ok_or_else(|| LimitHit::corrupt("7z: no terminal coder".to_string()))?;
    let g = Graph {
        block,
        in_base,
        out_base,
        packed,
        password,
        max_buffer,
    };
    coder_reader(&g, src, final_coder, &mut Vec::new())
}

/// The reader of block `block`'s decoded bytes, from its packed streams laid
/// end to end in `pack_range` of `src`. `total` is the folder's size.
fn block_reader<'a>(
    block: &super::header::Block,
    src: &'a dyn crate::source::ByteSource,
    pack_range: (usize, usize),
    pack_sizes: &[u64],
    total: u64,
    password: Option<crate::kdf::Pass<'_>>,
    max_buffer: u64,
) -> Result<Box<dyn Read + 'a>, LimitHit> {
    // A coder with several inputs (BCJ2) is not a link of a chain: its filter
    // reads four streams at once, each its packed stream from the source or
    // the output of the coder bound to it.
    if block.coders.iter().any(|c| c.num_in_streams > 1) {
        return graph_reader(block, src, pack_range.0, pack_sizes, password, max_buffer);
    }
    let packed = Box::new(crate::source::Reader::range(
        src,
        pack_range.0,
        pack_range.1,
    ));
    decode_block_reader(block, packed, total, password, max_buffer)
}

/// The decoder of the solid block being walked, and how many of its decoded
/// bytes have been read. The members of a block follow each other in it, so
/// the next one starts where this one left off: starting the decoder over for
/// each is a pass over the block per member.
struct Solid<'a> {
    block: usize,
    reader: Box<dyn Read + 'a>,
    pos: u64,
}

/// Why the members of an encrypted folder with no CRC are reported: the
/// password that decoded them cannot be told from a wrong one.
const NO_CRC_TO_CHECK_THE_PASSWORD: &str =
    "7z: the folder has no CRC, so the password is not confirmed";

/// The first member of a folder that has bytes: what tells a password that
/// opens the folder from one that does not. `start` is where it begins in the
/// folder's decoded bytes. Its CRC, when the header gives one, is what the
/// folder's bytes must match; none of the members may have one, and then the
/// password that decodes up to the end of the member is taken.
struct Proof {
    start: u64,
    size: u64,
    crc: Option<u32>,
}

/// What is known of the passwords for the encrypted block being walked: the
/// one that opened it, and those that are not it.
struct AesBlock {
    block: usize,
    good: Option<usize>,
    wrong: Vec<bool>,
    proof: Option<Proof>,
}

/// The proof of folder `block_idx`: its first member with a CRC, else its
/// first with bytes. `before[i]` is the total size of the files before file
/// `i`.
fn proof_of(archive: &super::header::Archive, before: &[u64], block_idx: usize) -> Option<Proof> {
    let first = *archive.stream_map.block_first_file.get(block_idx)?;
    let origin = *before.get(first)?;
    let mut found: Option<Proof> = None;
    for (i, f) in archive.files.iter().enumerate().skip(first) {
        match archive.stream_map.file_block.get(i).copied().flatten() {
            Some(b) if b == block_idx => {}
            Some(_) => break,
            None => continue,
        }
        if f.size == 0 {
            continue;
        }
        let member = Proof {
            start: before.get(i)?.saturating_sub(origin),
            size: f.size,
            crc: f.has_crc.then_some(f.crc),
        };
        if member.crc.is_some() {
            return Some(member);
        }
        found.get_or_insert(member);
    }
    found
}

/// Whether `reader`, a block decoded with one password, gives the bytes of
/// `proof`: it reads as far as the end of the member, and when the header has
/// a CRC for the member, the bytes it reads must match it. A decoder that
/// fails or ends early did not open the folder.
///
/// The bytes of the password that opens the folder are read again to be
/// scanned and charged then. Those of a password that does not are charged
/// here, so that a list of them is bounded by the scan budget, and a member
/// the scan has not enough budget left to read is not decoded for nothing.
fn opens(reader: &mut dyn Read, proof: &Proof, budget: &mut Budget) -> Result<bool, LimitHit> {
    let end = proof.start.saturating_add(proof.size);
    if end > budget.remaining_scan() {
        return Err(LimitHit::of_kind(
            LimitKind::MaxScanSize,
            format!("scanned bytes > {}", budget.limits.max_scanned_bytes),
        ));
    }
    let (opened, read) = read_proof(reader, proof, end);
    if !opened {
        budget.charge_scan(read)?;
    }
    Ok(opened)
}

/// [`opens`] without the budget: whether the folder is opened, and how much of
/// it was read.
fn read_proof(reader: &mut dyn Read, proof: &Proof, end: u64) -> (bool, u64) {
    let mut crc = crc32fast::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut at = 0u64;
    while at < end {
        let want = usize::try_from(end - at).map_or(buf.len(), |r| r.min(buf.len()));
        let n = match reader.read(&mut buf[..want]) {
            Ok(0) => return (false, at),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return (false, at),
        };
        let member = usize::try_from(proof.start.saturating_sub(at)).map_or(n, |s| s.min(n));
        crc.update(&buf[member..n]);
        at += n as u64;
    }
    (proof.crc.is_none_or(|want| crc.finalize() == want), at)
}

/// One member of a block's decoded bytes: at most `left` bytes of `inner`,
/// counted in `read`. With a CRC, the member's end is an error when the bytes
/// do not match it. In an encrypted folder (`keyed`) that is `InvalidData`: the
/// key was wrong or the data is damaged, and the member is not to be taken for
/// scanned. Otherwise the folder decoded in full and only its checksum
/// disagrees, which is [`crate::checksum_mismatch`].
struct Window<'a> {
    inner: &'a mut dyn Read,
    left: u64,
    read: u64,
    crc: Option<(crc32fast::Hasher, u32)>,
    keyed: bool,
}

impl Read for Window<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            if let Some((crc, want)) = self.crc.take()
                && crc.finalize() != want
            {
                return Err(if self.keyed {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "7z: the member does not match its CRC",
                    )
                } else {
                    crate::checksum_mismatch("7z CRC-32")
                });
            }
            return Ok(0);
        }
        let want = usize::try_from(self.left).map_or(out.len(), |l| l.min(out.len()));
        let n = self.inner.read(&mut out[..want])?;
        self.left -= n as u64;
        self.read += n as u64;
        if let Some((crc, _)) = self.crc.as_mut() {
            crc.update(&out[..n]);
        }
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

/// Where the packed bytes of folder `block_idx` are in the archive, as
/// `[start, end)`, and the size of each of its packed streams. A folder can
/// have several (BCJ2 folders have four), laid end to end; the sizes let the
/// graph decoder split them apart again. `Err` says why the header puts them
/// out of reach.
fn block_pack_data(
    archive: &super::header::Archive,
    block_idx: usize,
    len: usize,
) -> Result<((usize, usize), Vec<u64>), &'static str> {
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
    (range.1 <= len).then_some((range, sizes)).ok_or(PAST_END)
}

/// Walk a 7z archive. Its header is at the end and is read from there; each
/// folder's packed bytes are read as its members are, so the archive is never
/// held, and each member's decompressed output streams, which is where a solid
/// block can be far larger than the archive.
pub(crate) fn walk(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<()>,
) -> Result<Option<()>, LimitHit> {
    stream_sevenz(src, budget, visit)
}

/// Streaming 7z extraction (pattern A): each file's solid block is built as a
/// forward-only `Read` over its packed bytes in the source; the file is emitted
/// by skipping to its offset and handing the visitor a window of `size` bytes.
/// The decompressed block is never buffered, so a huge solid archive is scanned
/// in bounded memory, whatever its coders: a folder with several packed streams
/// (BCJ2) and an encrypted one (AES) are read the same way.
fn stream_sevenz(
    src: &dyn crate::source::ByteSource,
    budget: &mut Budget,
    visit: crate::stream::Visit<()>,
) -> Result<Option<()>, LimitHit> {
    use crate::stream::{MemberMeta, emit_stream};
    let kdf = std::sync::Arc::clone(&budget.kdf);
    let archive = match super::header::parse_archive_with(
        src,
        &budget.passwords,
        &kdf,
        budget.limits.max_buffer_bytes,
    ) {
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
                    comp_size: src.len() as u64,
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

        let (pack_range, block_pack_sizes) = match block_pack_data(&archive, block_idx, src.len()) {
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

        // An encrypted folder is opened by the first password that decodes its
        // first member to the CRC the header gives it: nothing else tells a
        // right key from a wrong one. It is read as any other folder after
        // that, so that the first member is decoded twice, and each member is
        // checked against its CRC as it ends. A folder with no CRC at all is
        // read with the first password that decodes it, and its members are
        // reported: that password may be wrong.
        let mut word: Option<&str> = None;
        let mut unconfirmed = false;
        if aes {
            if aes_state.as_ref().is_none_or(|s| s.block != block_idx) {
                aes_state = Some(AesBlock {
                    block: block_idx,
                    good: None,
                    wrong: vec![false; passwords.len()],
                    proof: proof_of(&archive, &before, block_idx),
                });
            }
            let Some(state) = aes_state.as_mut() else {
                continue;
            };
            if state.good.is_none()
                && let Some(proof) = &state.proof
            {
                for (i, pw) in passwords.iter().enumerate() {
                    if state.wrong[i] {
                        continue;
                    }
                    let pass = crate::kdf::Pass {
                        word: pw.as_str(),
                        kdf: &kdf,
                    };
                    // A decoder that cannot be built with this password (the
                    // key is out of reach, the properties are bad) is as good
                    // as one that fails on its bytes.
                    let opened = match block_reader(
                        block,
                        src,
                        pack_range,
                        &block_pack_sizes,
                        block_total,
                        Some(pass),
                        max_buffer,
                    ) {
                        Ok(mut r) => opens(r.as_mut(), proof, budget)?,
                        Err(_) => false,
                    };
                    if opened {
                        state.good = Some(i);
                        break;
                    }
                    state.wrong[i] = true;
                }
            }
            word = state.good.map(|i| passwords[i].as_str());
            unconfirmed = state.proof.as_ref().is_some_and(|p| p.crc.is_none());
            if word.is_none() {
                let meta = MemberMeta {
                    name,
                    comp_size: file.size,
                    size: Some(file.size),
                    encrypted: true,
                    unsupported: Some("7z: wrong or missing password"),
                    ..MemberMeta::default()
                };
                if let Some(t) = visit(&meta, None, budget) {
                    return Ok(Some(t));
                }
                continue;
            }
        }

        if !solid
            .as_ref()
            .is_some_and(|s| s.block == block_idx && s.pos <= bytes_to_skip)
        {
            let pass = word.map(|word| crate::kdf::Pass { word, kdf: &kdf });
            let reader = match block_reader(
                block,
                src,
                pack_range,
                &block_pack_sizes,
                block_total,
                pass,
                max_buffer,
            ) {
                Ok(r) => r,
                // A coder over the object limit (a PPMd model): the members of
                // its folder are left out and the walk goes on.
                Err(hit) if !hit.is_corrupt() => {
                    let name = crate::tree::quoted(&name);
                    budget.skip(format_args!("member '{name}': {}", hit.reason));
                    continue;
                }
                Err(hit) => return Err(hit),
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
        // The members before this one in the block are decoded and dropped,
        // which is the work a scan limit is for: charged before it is done, so
        // a block that declares more than the limit allows is not decoded.
        let to_skip = bytes_to_skip.saturating_sub(s.pos);
        budget.charge_scan(to_skip)?;
        let (skipped, failed) = skip_reader(s.reader.as_mut(), to_skip);
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
        let mut window = Window {
            inner: s.reader.as_mut(),
            left: file.size,
            read: 0,
            crc: file.has_crc.then(|| (crc32fast::Hasher::new(), file.crc)),
            keyed: aes,
        };
        // Decrypted, and still reported as encrypted: the plaintext is
        // scanned, and cracking the password does not erase the fact.
        let meta = MemberMeta {
            name,
            comp_size: file.size,
            size: Some(file.size),
            encrypted: aes,
            unsupported: unconfirmed.then_some(NO_CRC_TO_CHECK_THE_PASSWORD),
            ..MemberMeta::default()
        };
        let emitted = emit_stream(&meta, &mut window, budget, visit);
        // Where the next member of the block starts from: what was read,
        // which may be less than the member's size.
        s.pos += window.read;
        if let Some(t) = emitted? {
            return Ok(Some(t));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::super::header::{BindPair, Block, Coder};
    use super::*;

    fn coder(ins: u64, outs: u64) -> Coder {
        Coder {
            method_id: super::super::parse::ID_BCJ2.to_vec(),
            num_in_streams: ins,
            num_out_streams: outs,
            properties: Vec::new(),
        }
    }

    fn block(coders: Vec<Coder>, binds: &[(u64, u64)]) -> Block {
        Block {
            coders,
            bind_pairs: binds
                .iter()
                .map(|&(in_index, out_index)| BindPair {
                    in_index,
                    out_index,
                })
                .collect(),
            packed_streams: Vec::new(),
            unpack_sizes: vec![16; 8],
            num_unpack_sub_streams: 1,
            has_crc: false,
            crc: 0,
        }
    }

    fn refused(b: &Block) -> String {
        let empty: &[u8] = &[];
        match graph_reader(b, &empty, 0, &[], None, 1 << 20) {
            Err(e) => e.reason,
            Ok(_) => String::new(),
        }
    }

    /// A folder that binds one output to several inputs, or one input to
    /// several outputs, is refused before any coder is built: built once per
    /// use, it would be exponential in the number of coders.
    #[test]
    fn a_folder_that_binds_a_stream_twice_is_refused_before_a_reader_is_built() {
        // Four inputs of one coder on the output of the next.
        let b = block(
            vec![coder(4, 1), coder(1, 1)],
            &[(0, 1), (1, 1), (2, 1), (3, 1)],
        );
        assert!(refused(&b).contains("two inputs"), "{}", refused(&b));
        // A coder of two outputs, each bound to an input of the coder above.
        let b = block(vec![coder(2, 1), coder(1, 2)], &[(0, 1), (1, 2)]);
        assert!(refused(&b).contains("two inputs"), "{}", refused(&b));
        // One input bound to two outputs.
        let b = block(
            vec![coder(2, 1), coder(1, 1), coder(1, 1)],
            &[(0, 1), (0, 2)],
        );
        assert!(refused(&b).contains("two outputs"), "{}", refused(&b));
        // A chain, each coder feeding the one above, is not.
        let b = block(vec![coder(2, 1), coder(1, 1)], &[(0, 1)]);
        assert!(!refused(&b).contains("two"), "{}", refused(&b));
    }
}
