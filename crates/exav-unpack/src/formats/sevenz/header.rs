//! 7z header parsing: signature header, streams info, folders, files, stream map.

use super::parse::*;
use crate::LimitHit;

// ─── Data structures ───────────────────────────────────────────────────────

pub(super) struct Coder {
    pub method_id: Vec<u8>,
    pub num_in_streams: u64,
    pub num_out_streams: u64,
    pub properties: Vec<u8>,
}

pub(super) struct BindPair {
    pub in_index: u64,
    pub out_index: u64,
}

pub(super) struct Block {
    pub coders: Vec<Coder>,
    pub bind_pairs: Vec<BindPair>,
    pub packed_streams: Vec<i64>,
    pub unpack_sizes: Vec<u64>,
    pub num_unpack_sub_streams: usize,
    pub has_crc: bool,
    pub crc: u32,
}

pub(super) struct FileEntry {
    pub name: String,
    pub has_stream: bool,
    pub is_directory: bool,
    pub size: u64,
    pub has_crc: bool,
    pub crc: u32,
}

pub(super) struct StreamMap {
    pub block_first_pack_stream: Vec<usize>,
    pub pack_stream_offsets: Vec<u64>,
    pub block_first_file: Vec<usize>,
    pub file_block: Vec<Option<usize>>,
}

pub(super) struct Archive {
    pub pack_pos: u64,
    pub pack_sizes: Vec<u64>,
    pub blocks: Vec<Block>,
    pub files: Vec<FileEntry>,
    pub stream_map: StreamMap,
}

// ─── Public entry point ────────────────────────────────────────────────────

pub(super) fn parse_archive(data: &[u8], passwords: &[String]) -> Result<Archive, LimitHit> {
    if data.len() < 32 {
        return Err(LimitHit::corrupt("7z: file too small".into()));
    }

    if data[0..6] != SIGNATURE {
        return Err(LimitHit::corrupt("7z: invalid signature".into()));
    }

    let version_major = data[6];
    let version_minor = data[7];
    if version_major != 0 {
        return Err(LimitHit::corrupt(format!(
            "7z: unsupported version {version_major}.{version_minor}"
        )));
    }

    let next_header_offset = u64::from_le_bytes(data[12..20].try_into().unwrap());
    let next_header_size = u64::from_le_bytes(data[20..28].try_into().unwrap());

    let nh_start = SIGNATURE_HEADER_SIZE
        .checked_add(next_header_offset)
        .and_then(|v| usize::try_from(v).ok())
        .ok_or_else(|| LimitHit::corrupt("7z: next header offset overflow".into()))?;
    let nh_end = nh_start
        .checked_add(next_header_size as usize)
        .ok_or_else(|| LimitHit::corrupt("7z: next header offset overflow".into()))?;
    if nh_end > data.len() {
        return Err(LimitHit::corrupt(
            "7z: next header extends past end of file".into(),
        ));
    }

    let nh = &data[nh_start..nh_end];
    let mut nr = SevenZReader::new(nh);

    let first_nid = nr.read_nid()?;

    let streams_data = match first_nid {
        NID_ENCODED_HEADER => {
            let mut streams_info = parse_streams_info(&mut nr)?;
            let uses_aes = streams_info
                .blocks
                .first()
                .map(|b| {
                    b.coders
                        .iter()
                        .any(|c| c.method_id.as_slice() == super::parse::ID_AES)
                })
                .unwrap_or(false);
            if uses_aes && !passwords.is_empty() {
                // Encrypted header (`-mhe=on`): try each candidate password; the
                // correct one yields bytes that parse as a valid 7z header.
                let mut decoded = None;
                for pw in passwords {
                    if let Ok(bytes) = decompress_encoded_header(data, &mut streams_info, Some(pw))
                    {
                        if parse_header(&bytes).is_ok() {
                            decoded = Some(bytes);
                            break;
                        }
                    }
                }
                decoded.ok_or_else(|| {
                    LimitHit::corrupt("7z: encrypted header (no password matched)".into())
                })?
            } else {
                // No password (or no AES): a `-mhe` header without a password
                // surfaces as unsupported via the AES coder, never a silent clean.
                decompress_encoded_header(data, &mut streams_info, None)?
            }
        }
        NID_HEADER => nh.to_vec(),
        _ => {
            return Err(LimitHit::corrupt(format!(
                "7z: unexpected NID {first_nid:#04x} at start of next header"
            )));
        }
    };

    parse_header(&streams_data)
}

// ─── Streams info parsing ──────────────────────────────────────────────────

struct StreamsInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    blocks: Vec<Block>,
    sub_streams_info: Option<SubStreamsInfo>,
}

struct SubStreamsInfo {
    unpack_sizes: Vec<u64>,
    has_crc: Vec<bool>,
    crcs: Vec<u32>,
}

fn parse_streams_info(r: &mut SevenZReader) -> Result<StreamsInfo, LimitHit> {
    let mut pack_pos = 0u64;
    let mut pack_sizes = Vec::new();
    let mut blocks = Vec::new();
    let mut sub_streams_info = None;

    loop {
        let nid = r.read_nid()?;
        match nid {
            NID_END => break,
            NID_PACK_INFO => {
                let info = parse_pack_info(r)?;
                pack_pos = info.0;
                pack_sizes = info.1;
            }
            NID_UNPACK_INFO => {
                blocks = parse_unpack_info(r)?;
            }
            NID_SUB_STREAMS_INFO => {
                sub_streams_info = Some(parse_sub_streams_info(r, &mut blocks)?);
            }
            NID_ADDITIONAL_STREAMS_INFO => {
                // Skip additional streams info (encoded header chains)
                // For now, just skip this and hope NID_END follows
                // A proper implementation would recursively decode
            }
            _ => {
                return Err(LimitHit::corrupt(format!(
                    "7z: unexpected NID {nid:#04x} in streams info"
                )));
            }
        }
    }

    Ok(StreamsInfo {
        pack_pos,
        pack_sizes,
        blocks,
        sub_streams_info,
    })
}

fn parse_pack_info(r: &mut SevenZReader) -> Result<(u64, Vec<u64>), LimitHit> {
    let pack_pos = read_var_u64(r)?;
    let num_pack_streams = read_var_usize(r)?;

    let mut pack_sizes = Vec::with_capacity(num_pack_streams.min(r.remaining()));

    loop {
        let nid = r.read_nid()?;
        match nid {
            NID_END => break,
            NID_SIZE => {
                for _ in 0..num_pack_streams {
                    pack_sizes.push(read_var_u64(r)?);
                }
            }
            NID_CRC => {
                let _all_defined = r.read_byte()?;
                for _ in 0..num_pack_streams {
                    let _crc = r.read_u32()?;
                }
            }
            _ => {
                return Err(LimitHit::corrupt(format!(
                    "7z: unexpected NID {nid:#04x} in pack info"
                )));
            }
        }
    }

    Ok((pack_pos, pack_sizes))
}

fn parse_unpack_info(r: &mut SevenZReader) -> Result<Vec<Block>, LimitHit> {
    let nid = r.read_nid()?;
    if nid != NID_FOLDER {
        return Err(LimitHit::corrupt(format!(
            "7z: expected NID_FOLDER in unpack info, got {nid:#04x}"
        )));
    }

    let num_blocks = read_var_usize(r)?;
    let _external = r.read_byte()?;

    let mut blocks = Vec::with_capacity(num_blocks.min(r.remaining()));
    for _ in 0..num_blocks {
        blocks.push(read_block(r)?);
    }

    loop {
        let nid = r.read_nid()?;
        match nid {
            NID_END => break,
            NID_CODERS_UNPACK_SIZE => {
                for block in &mut blocks {
                    let num_out = block
                        .coders
                        .iter()
                        .map(|c| c.num_out_streams as usize)
                        .sum::<usize>();
                    block.unpack_sizes = Vec::with_capacity(num_out.min(r.remaining()));
                    for _ in 0..num_out {
                        block.unpack_sizes.push(read_var_u64(r)?);
                    }
                }
            }
            NID_CRC => {
                let crcs_defined = BitSet::read_all_or_bits(r, num_blocks)?;
                for (i, block) in blocks.iter_mut().enumerate() {
                    if crcs_defined.get(i) {
                        block.has_crc = true;
                        block.crc = r.read_u32()?;
                    }
                }
            }
            _ => {
                return Err(LimitHit::corrupt(format!(
                    "7z: unexpected NID {nid:#04x} in unpack info"
                )));
            }
        }
    }

    Ok(blocks)
}

fn read_block(r: &mut SevenZReader) -> Result<Block, LimitHit> {
    let num_coders = read_var_usize(r)?;
    let mut coders = Vec::with_capacity(num_coders.min(r.remaining()));
    let mut total_in_streams: u64 = 0;
    let mut total_out_streams: u64 = 0;

    for _ in 0..num_coders {
        let bits = r.read_byte()?;
        let id_size = (bits & 0x0F) as usize;
        let is_simple = bits & 0x10 == 0;
        let has_attributes = bits & 0x20 != 0;
        let _more_methods = bits & 0x80 != 0;

        let method_id = r.read_bytes(id_size)?.to_vec();

        let (num_in, num_out) = if is_simple {
            (1u64, 1u64)
        } else {
            let ni = read_var_u64(r)?;
            let no = read_var_u64(r)?;
            (ni, no)
        };

        let properties = if has_attributes {
            let prop_size = read_var_usize(r)?;
            r.read_bytes(prop_size)?.to_vec()
        } else {
            Vec::new()
        };

        // A real 7z coder has a small, fixed number of in/out streams (at most
        // ~4, e.g. BCJ2). Reject absurd fuzzer-supplied counts: without this the
        // `total_*_streams` accumulation overflows `u64` (a panic under
        // overflow-checks) and the bind-pair / unpack-size allocations that use
        // the totals blow up.
        const MAX_CODER_STREAMS: u64 = 64;
        if num_in > MAX_CODER_STREAMS || num_out > MAX_CODER_STREAMS {
            return Err(LimitHit::corrupt("7z: coder stream count too large".into()));
        }
        total_in_streams += num_in;
        total_out_streams += num_out;

        coders.push(Coder {
            method_id,
            num_in_streams: num_in,
            num_out_streams: num_out,
            properties,
        });
    }

    let num_bind_pairs = (total_out_streams as usize)
        .saturating_sub(1)
        .min(num_coders);
    let mut bind_pairs = Vec::with_capacity(num_bind_pairs.min(r.remaining()));
    for _ in 0..num_bind_pairs {
        let in_index = read_var_u64(r)?;
        let out_index = read_var_u64(r)?;
        bind_pairs.push(BindPair {
            in_index,
            out_index,
        });
    }

    let num_packed_streams = (total_in_streams as usize).saturating_sub(num_bind_pairs);
    let packed_streams = if num_packed_streams == 1 {
        // `total_in_streams` is `MAX_CODER_STREAMS * num_coders`, i.e. up to ~64×
        // the input; bound the scratch allocation by the bytes left. A legitimate
        // folder has a tiny stream count so this never clamps real input, and the
        // `bp.in_index` bounds check below rejects any index past the clamp.
        let used_len = (total_in_streams as usize).min(r.remaining());
        let mut used = vec![false; used_len];
        for bp in &bind_pairs {
            // `in_index` is read from the input; reject an out-of-range value
            // rather than panic (fuzz-found: index underflow → OOB index).
            let i = bp.in_index as usize;
            if i >= used.len() {
                return Err(LimitHit::corrupt(
                    "7z: bind-pair in_index out of range".into(),
                ));
            }
            used[i] = true;
        }
        let idx = used.iter().position(|&u| !u).unwrap_or(0) as i64;
        vec![idx]
    } else {
        let mut ps = Vec::with_capacity(num_packed_streams.min(r.remaining()));
        for _ in 0..num_packed_streams {
            ps.push(read_var_u64(r)? as i64);
        }
        ps
    };

    Ok(Block {
        coders,
        bind_pairs,
        packed_streams,
        unpack_sizes: Vec::new(),
        num_unpack_sub_streams: 1,
        has_crc: false,
        crc: 0,
    })
}

fn parse_sub_streams_info(
    r: &mut SevenZReader,
    blocks: &mut [Block],
) -> Result<SubStreamsInfo, LimitHit> {
    let mut total_sub_streams: usize = blocks.iter().map(|b| b.num_unpack_sub_streams).sum();
    let mut unpack_sizes = vec![0u64; total_sub_streams];
    let mut has_crc = vec![false; total_sub_streams];
    let mut crcs = vec![0u32; total_sub_streams];

    // Read NID_NUM_UNPACK_STREAM first
    let mut nid = r.read_nid()?;
    if nid == NID_NUM_UNPACK_STREAM {
        total_sub_streams = 0;
        // `num_streams` is an attacker-controlled var-int. Without a bound the
        // running `total_sub_streams` accumulation overflows `usize` (a panic
        // under overflow-checks) and the `resize` calls below try to allocate an
        // astronomical number of elements (capacity-overflow / OOM abort — not
        // caught by the panic boundary). Every declared sub-stream ultimately
        // consumes header bytes (a size and/or CRC), so cap the total at the
        // bytes left to parse; the per-block value is clamped to whatever budget
        // remains so the stored `num_unpack_sub_streams` stays consistent with
        // the vector lengths used everywhere downstream.
        let cap = r.remaining();
        for block in blocks.iter_mut() {
            let num_streams = read_var_usize(r)?.min(cap.saturating_sub(total_sub_streams));
            block.num_unpack_sub_streams = num_streams;
            total_sub_streams += num_streams;
        }
        unpack_sizes.resize(total_sub_streams, 0);
        has_crc.resize(total_sub_streams, false);
        crcs.resize(total_sub_streams, 0);
        nid = r.read_nid()?;
    }

    // Read NID_SIZE: N-1 sizes per block (last is derived)
    let mut next_unpack_stream = 0usize;
    if nid == NID_SIZE {
        for block in blocks.iter() {
            if block.num_unpack_sub_streams == 0 {
                continue;
            }
            let mut sum: u64 = 0;
            for _ in 0..block.num_unpack_sub_streams - 1 {
                if next_unpack_stream < unpack_sizes.len() {
                    let size = read_var_u64(r)?;
                    unpack_sizes[next_unpack_stream] = size;
                    // `size` is an attacker-controlled var-int; a bare `+=` of two
                    // near-`u64::MAX` sizes overflows (panic under overflow-checks).
                    sum = sum.saturating_add(size);
                }
                next_unpack_stream += 1;
            }
            // Last size = folder output size - sum of the N-1 explicit sizes.
            let block_total: u64 = folder_out_size(block);
            if next_unpack_stream < unpack_sizes.len() {
                unpack_sizes[next_unpack_stream] = block_total.saturating_sub(sum);
            }
            next_unpack_stream += 1;
        }
        nid = r.read_nid()?;
    } else {
        // No NID_SIZE: each block has 1 sub-stream, size = folder output size.
        for block in blocks.iter() {
            if next_unpack_stream < unpack_sizes.len() {
                unpack_sizes[next_unpack_stream] = folder_out_size(block);
            }
            next_unpack_stream += 1;
        }
    }

    // Read NID_CRC if present
    // num_digests = sub-streams in blocks with >1 sub-stream or no folder CRC
    let mut num_digests = 0usize;
    for block in blocks.iter() {
        if block.num_unpack_sub_streams != 1 || !block.has_crc {
            num_digests += block.num_unpack_sub_streams;
        }
    }

    if nid == NID_CRC {
        let crc_defined = BitSet::read_all_or_bits(r, num_digests)?;
        let mut missing_crcs = vec![0u32; num_digests];
        for (i, crc) in missing_crcs.iter_mut().enumerate() {
            if crc_defined.get(i) {
                *crc = r.read_u32()?;
            }
        }

        // Map CRCs back to sub-streams
        let mut next_crc = 0usize;
        let mut next_missing_crc = 0usize;
        for block in blocks.iter() {
            if block.num_unpack_sub_streams == 1 && block.has_crc {
                // Use folder CRC
                if next_crc < has_crc.len() {
                    has_crc[next_crc] = true;
                    crcs[next_crc] = block.crc;
                }
                next_crc += 1;
            } else {
                for _ in 0..block.num_unpack_sub_streams {
                    if next_crc < has_crc.len() {
                        if next_missing_crc < num_digests && crc_defined.get(next_missing_crc) {
                            has_crc[next_crc] = true;
                        }
                        if next_missing_crc < num_digests {
                            crcs[next_crc] = missing_crcs[next_missing_crc];
                        }
                    }
                    next_crc += 1;
                    next_missing_crc += 1;
                }
            }
        }
        nid = r.read_nid()?;
    }

    if nid != NID_END {
        return Err(LimitHit::corrupt(format!(
            "7z: expected NID_END in sub-streams info, got {nid:#04x}"
        )));
    }

    Ok(SubStreamsInfo {
        unpack_sizes,
        has_crc,
        crcs,
    })
}

// ─── Files info parsing ────────────────────────────────────────────────────

fn parse_files_info(
    r: &mut SevenZReader,
    blocks: &[Block],
    sub_streams_info: &Option<SubStreamsInfo>,
) -> Result<Vec<FileEntry>, LimitHit> {
    // Bound by the bytes left in the header: every file consumes at least some
    // header bytes (name table / bit vectors), so a count larger than that is
    // malformed. Without this the `collect()` and `BitSet::new` below try to
    // pre-allocate an astronomical count and hit `capacity overflow`.
    let num_files = read_var_usize(r)?.min(r.remaining());
    let mut files: Vec<FileEntry> = (0..num_files)
        .map(|_| FileEntry {
            name: String::new(),
            has_stream: false,
            is_directory: false,
            size: 0,
            has_crc: false,
            crc: 0,
        })
        .collect();

    let mut empty_streams = BitSet::new(num_files);
    let mut empty_files = BitSet::new(num_files);

    loop {
        let prop_type = r.read_nid()?;
        if prop_type == NID_END {
            break;
        }
        let _prop_size = read_var_u64(r)?;

        match prop_type {
            NID_EMPTY_STREAM => {
                empty_streams = BitSet::read_bits(r, num_files, BitSet::new(num_files))?;
            }
            NID_EMPTY_FILE => {
                empty_files = BitSet::read_bits(r, num_files, BitSet::new(num_files))?;
            }
            NID_ANTI => {
                let _ = BitSet::read_bits(r, num_files, BitSet::new(num_files))?;
            }
            NID_NAME => {
                let external = r.read_byte()?;
                if external != 0 {
                    return Err(LimitHit::corrupt(
                        "7z: NID_NAME external != 0 not supported".into(),
                    ));
                }
                let name_bytes_size = (_prop_size as usize).saturating_sub(1);
                if name_bytes_size & 1 != 0 {
                    return Err(LimitHit::corrupt(
                        "7z: file names length is not even".into(),
                    ));
                }
                let name_data = r.read_bytes(name_bytes_size)?;
                // Parse UTF-16LE null-terminated strings, one per file
                let mut names = Vec::new();
                let mut i = 0;
                while i + 2 <= name_data.len() {
                    let mut code_units = Vec::new();
                    while i + 2 <= name_data.len() {
                        let cu = u16::from_le_bytes([name_data[i], name_data[i + 1]]);
                        i += 2;
                        if cu == 0 {
                            break;
                        }
                        code_units.push(cu);
                    }
                    names.push(String::from_utf16_lossy(&code_units));
                }
                for (idx, name) in names.into_iter().enumerate() {
                    if idx < num_files {
                        files[idx].name = name;
                    }
                }
            }
            NID_C_TIME | NID_A_TIME | NID_M_TIME => {
                let times_defined = BitSet::read_all_or_bits(r, num_files)?;
                let _external = r.read_byte()?;
                for i in 0..num_files {
                    if times_defined.get(i) {
                        let _ = r.read_u64()?;
                    }
                }
            }
            NID_WIN_ATTRIBUTES => {
                let attrs_defined = BitSet::read_all_or_bits(r, num_files)?;
                let _external = r.read_byte()?;
                for i in 0..num_files {
                    if attrs_defined.get(i) {
                        let _ = r.read_u32()?;
                    }
                }
            }
            _ => {
                // Skip unknown property
                let _ = r.read_bytes(_prop_size as usize)?;
            }
        }
    }

    // Post-process: determine has_stream / is_directory for each file
    let mut non_empty_counter = 0usize;

    let total_unpack_sub_streams: usize = blocks.iter().map(|b| b.num_unpack_sub_streams).sum();

    for (i, file) in files.iter_mut().enumerate().take(num_files) {
        if !empty_streams.get(i) {
            file.has_stream = true;
            file.is_directory = false;

            if non_empty_counter < total_unpack_sub_streams {
                file.size = sub_streams_info
                    .as_ref()
                    .map(|ssi| ssi.unpack_sizes[non_empty_counter])
                    .unwrap_or(0);
                file.has_crc = sub_streams_info
                    .as_ref()
                    .map(|ssi| ssi.has_crc[non_empty_counter])
                    .unwrap_or(false);
                file.crc = sub_streams_info
                    .as_ref()
                    .map(|ssi| ssi.crcs[non_empty_counter])
                    .unwrap_or(0);
            }
            non_empty_counter += 1;
        } else {
            file.has_stream = false;
            file.is_directory = !empty_files.get(i);
            file.size = 0;
        }
    }

    Ok(files)
}

// ─── Stream map ────────────────────────────────────────────────────────────

fn calculate_stream_map(blocks: &[Block], files: &[FileEntry], pack_sizes: &[u64]) -> StreamMap {
    let num_blocks = blocks.len();
    let num_files = files.len();

    let mut block_first_pack_stream = Vec::with_capacity(num_blocks);
    let mut cumulative = 0usize;
    for block in blocks {
        block_first_pack_stream.push(cumulative);
        cumulative += block.packed_streams.len();
    }

    let mut pack_stream_offsets = Vec::with_capacity(pack_sizes.len());
    let mut offset = 0u64;
    for &size in pack_sizes {
        pack_stream_offsets.push(offset);
        // `size` is an attacker-controlled var-int; a bare `+=` overflows `u64`
        // (panic under overflow-checks) once the running offset gets large.
        offset = offset.saturating_add(size);
    }

    let mut block_first_file = vec![0usize; num_blocks];
    let mut file_block = vec![None::<usize>; num_files];

    let mut current_block = 0usize;
    let mut sub_stream_in_block = 0usize;

    for (file_idx, file) in files.iter().enumerate() {
        if file.has_stream {
            if current_block < num_blocks {
                if sub_stream_in_block == 0 {
                    block_first_file[current_block] = file_idx;
                }
                file_block[file_idx] = Some(current_block);
                sub_stream_in_block += 1;
                if sub_stream_in_block >= blocks[current_block].num_unpack_sub_streams {
                    current_block += 1;
                    sub_stream_in_block = 0;
                }
            }
        } else {
            file_block[file_idx] = None;
        }
    }

    StreamMap {
        block_first_pack_stream,
        pack_stream_offsets,
        block_first_file,
        file_block,
    }
}

// ─── Decompress encoded header ─────────────────────────────────────────────

fn decompress_encoded_header(
    data: &[u8],
    streams_info: &mut StreamsInfo,
    password: Option<&str>,
) -> Result<Vec<u8>, LimitHit> {
    if streams_info.blocks.is_empty() {
        return Err(LimitHit::corrupt("7z: encoded header has no blocks".into()));
    }

    let block = &streams_info.blocks[0];
    if block.packed_streams.is_empty() {
        return Err(LimitHit::corrupt(
            "7z: encoded header block has no packed streams".into(),
        ));
    }

    let pack_idx = block.packed_streams[0] as usize;
    if pack_idx >= streams_info.pack_sizes.len() {
        return Err(LimitHit::corrupt("7z: invalid pack stream index".into()));
    }

    // Compute pack_stream_offsets on the fly from pack_sizes. All of pack_pos /
    // pack_sizes are attacker-controlled var-ints, so every add below must be
    // overflow-safe (a bare `+` panics under overflow-checks); a value that
    // overflows can only point past the file, which we reject anyway.
    let mut pack_stream_offset = 0u64;
    for i in 0..pack_idx {
        pack_stream_offset = pack_stream_offset.saturating_add(streams_info.pack_sizes[i]);
    }

    let pack_offset = SIGNATURE_HEADER_SIZE
        .checked_add(streams_info.pack_pos)
        .and_then(|v| v.checked_add(pack_stream_offset))
        .and_then(|v| usize::try_from(v).ok())
        .ok_or_else(|| LimitHit::corrupt("7z: pack stream offset overflow".into()))?;
    let pack_size = streams_info.pack_sizes[pack_idx] as usize;

    let pack_end = pack_offset
        .checked_add(pack_size)
        .filter(|&e| e <= data.len())
        .ok_or_else(|| LimitHit::corrupt("7z: pack stream extends past end of file".into()))?;

    let pack_data = &data[pack_offset..pack_end];
    // Sum of attacker-controlled coder output sizes: saturate instead of `.sum()`
    // (which panics on overflow). `cap_prealloc` bounds the resulting allocation.
    let total_unpack: u64 = block
        .unpack_sizes
        .iter()
        .copied()
        .fold(0u64, u64::saturating_add);

    // Build decoder chain and decompress
    // We must own the data so Box<dyn Read> can be 'static
    let owned_pack_data = pack_data.to_vec();
    let reader = std::io::Cursor::new(owned_pack_data);
    let mut current: Box<dyn std::io::Read> = Box::new(reader);

    // The 7z parser threads no `Budget`, so the encoded header/TOC is bounded by
    // the *default* global peak-buffer limit. A header is metadata (not the
    // operator's tuning surface), and it must be buffered whole for random-access
    // parsing — so a fixed default ceiling is the right bound here.
    let max_buffer = crate::Limits::default().max_buffer_bytes();

    let chain = ordered_coder_iter(block);
    for coder_idx in chain {
        let coder = &block.coders[coder_idx];
        // Header decompression: `password` is threaded so AES-encrypted headers
        // (`-mhe=on`) can be decrypted when a candidate password is supplied.
        current =
            super::decode::wrap_coder(current, coder, total_unpack as usize, password, max_buffer)?;
    }

    let (buf, truncated) = crate::bounded_read(&mut current, max_buffer)
        .map_err(|e| LimitHit::corrupt(format!("7z: decompress header: {e}")))?;
    if truncated {
        return Err(LimitHit::new("7z encoded header exceeds max-buffer".into()));
    }

    Ok(buf)
}

// ─── Parse the full header ─────────────────────────────────────────────────

fn parse_header(data: &[u8]) -> Result<Archive, LimitHit> {
    let mut r = SevenZReader::new(data);

    let mut streams = None;
    let mut files = None;

    loop {
        let nid = r.read_nid()?;
        match nid {
            NID_END => break,
            NID_HEADER => {}
            NID_ARCHIVE_PROPERTIES => loop {
                let prop = r.read_nid()?;
                if prop == NID_END {
                    break;
                }
                let size = read_var_u64(&mut r)?;
                let _skip = r.read_bytes(size as usize)?;
            },
            NID_MAIN_STREAMS_INFO => {
                streams = Some(parse_streams_info(&mut r)?);
            }
            NID_FILES_INFO => {
                let s = streams.as_ref().ok_or_else(|| {
                    LimitHit::corrupt("7z: NID_FILES_INFO before NID_MAIN_STREAMS_INFO".into())
                })?;
                files = Some(parse_files_info(&mut r, &s.blocks, &s.sub_streams_info)?);
            }
            _ => {
                return Err(LimitHit::corrupt(format!(
                    "7z: unexpected NID {nid:#04x} in header"
                )));
            }
        }
    }

    let streams =
        streams.ok_or_else(|| LimitHit::corrupt("7z: no streams info in header".into()))?;
    let files = files.ok_or_else(|| LimitHit::corrupt("7z: no files info in header".into()))?;

    let stream_map = calculate_stream_map(&streams.blocks, &files, &streams.pack_sizes);

    Ok(Archive {
        pack_pos: streams.pack_pos,
        pack_sizes: streams.pack_sizes,
        blocks: streams.blocks,
        files,
        stream_map,
    })
}

/// Walk the coder chain from the root input to the final output.
/// The folder's final decompressed size: the size of the one output stream not
/// consumed by a bind pair. For a single-coder folder this equals that coder's
/// output size; for a multi-coder chain (e.g. AES→Copy, or a BCJ filter over
/// LZMA) it is the *last* stage's output — NOT the sum of every coder's output,
/// which would double-count the intermediate streams.
pub(super) fn folder_out_size(block: &Block) -> u64 {
    let total_out: u64 = block.coders.iter().map(|c| c.num_out_streams).sum();
    for out in 0..total_out {
        if !block.bind_pairs.iter().any(|bp| bp.out_index == out) {
            return block.unpack_sizes.get(out as usize).copied().unwrap_or(0);
        }
    }
    // Malformed (every output bound): fall back to the last declared size.
    block.unpack_sizes.last().copied().unwrap_or(0)
}

pub(super) fn ordered_coder_iter(block: &Block) -> Vec<usize> {
    if block.coders.is_empty() {
        return Vec::new();
    }

    let start = if let Some(&ps) = block.packed_streams.first() {
        ps as usize
    } else {
        0
    };

    let mut chain = Vec::new();
    let mut current = start;
    let mut visited = std::collections::HashSet::new();

    loop {
        if visited.contains(&current) || current >= block.coders.len() {
            break;
        }
        visited.insert(current);

        chain.push(current);

        // 0-based global index of `current`'s first output stream = the number
        // of output streams declared by the coders before it. (Bind-pair
        // out_index values are 0-based, so this must be an exclusive prefix sum;
        // an inclusive `0..=current` would be off by one and never match the
        // bind pair for a multi-coder folder, stopping the chain early.)
        let mut output_stream = 0u64;
        for coder in block.coders.iter().take(current) {
            output_stream += coder.num_out_streams;
        }

        let next = block
            .bind_pairs
            .iter()
            .find(|bp| bp.out_index == output_stream);

        match next {
            Some(bp) => {
                let target_in = bp.in_index;
                let mut cumulative = 0u64;
                let mut next_coder = None;
                for (i, coder) in block.coders.iter().enumerate() {
                    if target_in >= cumulative && target_in < cumulative + coder.num_in_streams {
                        next_coder = Some(i);
                        break;
                    }
                    cumulative += coder.num_in_streams;
                }
                match next_coder {
                    Some(idx) => current = idx,
                    None => break,
                }
            }
            None => break,
        }
    }

    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_basic() {
        let data = [0x00];
        let mut r = SevenZReader::new(&data);
        assert_eq!(read_var_u64(&mut r).unwrap(), 0);

        let data = [0x7F];
        let mut r = SevenZReader::new(&data);
        assert_eq!(read_var_u64(&mut r).unwrap(), 127);

        let data = [0x80, 0x01];
        let mut r = SevenZReader::new(&data);
        assert_eq!(read_var_u64(&mut r).unwrap(), 1);
    }

    #[test]
    fn bitset_basic() {
        let mut bs = BitSet::new(10);
        assert!(!bs.get(0));
        bs.set(3, true);
        assert!(bs.get(3));
        assert!(!bs.get(4));
    }

    // ─── Fuzz-hardening regressions ─────────────────────────────────────────
    //
    // Each crafts the smallest byte sequence that reaches a specific vulnerable
    // parse site and asserts parsing returns (Ok or Err) without panicking.
    // Under `overflow-checks` an unfixed integer overflow panics and a huge
    // allocation aborts, so a clean return is the regression signal.
    //
    // These call `parse_archive` DIRECTLY rather than the public `extract`: the
    // latter wraps every decoder in a `catch_unwind` (lib.rs) that would swallow
    // a panic and mask the regression. (Same rationale as the arj/partition
    // tests, which bypass the containment boundary on purpose.)

    /// `read_var_u64` encoding of `u64::MAX` (0xFF marker + 8 value bytes).
    const VMAX: [u8; 9] = [0xFF; 9];

    /// Wrap a plaintext next-header body into a full 7z file: a 32-byte signature
    /// header (next-header offset 0, so the body follows immediately) + the body.
    fn wrap_archive(body: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; 32];
        data[0..6].copy_from_slice(&SIGNATURE);
        data[6] = 0; // major version
        data[7] = 4; // minor version
        data[20..28].copy_from_slice(&(body.len() as u64).to_le_bytes());
        data.extend_from_slice(body);
        data
    }

    fn extract_no_panic(data: &[u8]) {
        // The point is simply that parsing returns rather than panicking. Also
        // route through the public `extract` to exercise the full pipeline (its
        // catch_unwind makes this call infallible-by-panic; the direct call above
        // is what actually regresses the fix).
        let _ = parse_archive(data, &[]);
        let mut budget = crate::Budget::new(crate::Limits::default());
        let _ = crate::extract(crate::Format::SevenZip, data, &mut budget);
    }

    /// SubStreamsInfo with an absurd `NID_NUM_UNPACK_STREAM` count: the running
    /// `total_sub_streams` accumulation must not overflow and the `resize` must
    /// not attempt an astronomical allocation.
    #[test]
    fn fuzz_sub_streams_huge_count_no_panic() {
        let mut body = vec![
            0x01, // NID_HEADER
            0x04, // NID_MAIN_STREAMS_INFO
            0x06, // NID_PACK_INFO
            0x00, // pack_pos
            0x01, // num_pack_streams
            0x09, // NID_SIZE
            0x00, // pack size[0]
            0x00, // NID_END (pack info)
            0x07, // NID_UNPACK_INFO
            0x0B, // NID_FOLDER
            0x01, // num_blocks
            0x00, // external
            0x01, // num_coders
            0x01, // coder bits: id_size=1, simple, no attrs
            0x00, // method_id = COPY
            0x0C, // NID_CODERS_UNPACK_SIZE
            0x00, // unpack size
            0x00, // NID_END (unpack info)
            0x08, // NID_SUB_STREAMS_INFO
            0x0D, // NID_NUM_UNPACK_STREAM
        ];
        body.extend_from_slice(&VMAX); // num_streams = u64::MAX for the one block
        extract_no_panic(&wrap_archive(&body));
    }

    /// Two pack sizes near `u64::MAX`: the `pack_stream_offsets` accumulation in
    /// `calculate_stream_map` must not overflow.
    #[test]
    fn fuzz_pack_size_offset_overflow_no_panic() {
        let mut body = vec![
            0x01, // NID_HEADER
            0x04, // NID_MAIN_STREAMS_INFO
            0x06, // NID_PACK_INFO
            0x00, // pack_pos
            0x02, // num_pack_streams = 2
            0x09, // NID_SIZE
        ];
        body.extend_from_slice(&VMAX); // size[0] = u64::MAX
        body.extend_from_slice(&VMAX); // size[1] = u64::MAX
        body.extend_from_slice(&[
            0x00, // NID_END (pack info)
            0x07, // NID_UNPACK_INFO
            0x0B, // NID_FOLDER
            0x01, // num_blocks
            0x00, // external
            0x01, // num_coders
            0x01, // coder bits
            0x00, // method COPY
            0x0C, // NID_CODERS_UNPACK_SIZE
            0x00, // unpack size
            0x00, // NID_END (unpack info)
            0x00, // NID_END (streams info)
            0x05, // NID_FILES_INFO
            0x00, // num_files = 0
            0x00, // NID_END (files info)
            0x00, // NID_END (header)
        ]);
        extract_no_panic(&wrap_archive(&body));
    }

    /// Encoded header declaring `pack_pos = u64::MAX`: the pack-offset math in
    /// `decompress_encoded_header` must reject the overflow rather than panic.
    #[test]
    fn fuzz_encoded_header_pack_pos_overflow_no_panic() {
        let mut body = vec![
            0x17, // NID_ENCODED_HEADER
            0x06, // NID_PACK_INFO
        ];
        body.extend_from_slice(&VMAX); // pack_pos = u64::MAX
        body.extend_from_slice(&[
            0x01, // num_pack_streams
            0x09, // NID_SIZE
            0x01, // pack size = 1
            0x00, // NID_END (pack info)
            0x07, // NID_UNPACK_INFO
            0x0B, // NID_FOLDER
            0x01, // num_blocks
            0x00, // external
            0x01, // num_coders
            0x01, // coder bits
            0x00, // method COPY
            0x0C, // NID_CODERS_UNPACK_SIZE
            0x00, // unpack size
            0x00, // NID_END (unpack info)
            0x00, // NID_END (streams info)
        ]);
        extract_no_panic(&wrap_archive(&body));
    }

    /// Encoded header with an LZMA coder whose (short) properties byte is >= 32:
    /// the dict-size fallback `1u32 << props` must not shift-overflow.
    #[test]
    fn fuzz_lzma_short_props_shift_no_panic() {
        let body = vec![
            0x17, // NID_ENCODED_HEADER
            0x06, // NID_PACK_INFO
            0x00, // pack_pos = 0
            0x01, // num_pack_streams
            0x09, // NID_SIZE
            0x01, // pack size = 1
            0x00, // NID_END (pack info)
            0x07, // NID_UNPACK_INFO
            0x0B, // NID_FOLDER
            0x01, // num_blocks
            0x00, // external
            0x01, // num_coders
            0x23, // coder bits: id_size=3, has_attributes(0x20), simple
            0x03, 0x01, 0x01, // method_id = LZMA
            0x01, // prop_size = 1
            0x64, // properties = [100]  (>= 32 → would shift-overflow `1u32 << props`)
            0x0C, // NID_CODERS_UNPACK_SIZE
            0x00, // unpack size = 0
            0x00, // NID_END (unpack info)
            0x00, // NID_END (streams info)
        ];
        extract_no_panic(&wrap_archive(&body));
    }
}
