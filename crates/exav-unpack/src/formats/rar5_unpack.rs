//! Ported from libarchive's rar5.c (Copyright (c) 2018 Grzegorz Antoniak), BSD-2-Clause.
//!
//! RAR5 (`unpack50`) LZSS decompressor. This is a from-scratch Rust port of the
//! decompression core of libarchive's `archive_read_support_format_rar5.c`
//! (the LZ window, the Huffman bit reader, block parsing and the delta / x86 /
//! ARM filters). It is BSD-2-Clause-derived; the upstream copyright and full
//! licence text live in the repo's top-level `NOTICE` file.
//!
//! Scope: RAR5 members, which are all LZ: RAR 5.0 dropped PPMd. Solid groups
//! share one decoder ([`Unpacker50`]). A member split across volumes reaches
//! this module only once the volumes are joined (`rar::join_volumes`), and an
//! encrypted one only once decrypted. Everything is bounds-checked and never
//! panics on malformed input.

use crate::{Budget, LimitHit};

const HUFF_BC: usize = 20;
const HUFF_NC: usize = 306;
const HUFF_DC: usize = 64;
/// Distance codes of the RAR 7 algorithm (compression version 1), which
/// reach distances past any window this decoder allocates.
const HUFF_DCX: usize = 80;
const HUFF_LDC: usize = 16;
const HUFF_RC: usize = 44;
const HUFF_TABLE_SIZE_MAX: usize = HUFF_NC + HUFF_DCX + HUFF_RC + HUFF_LDC;

const G_UNPACK_WINDOW_SIZE: u64 = 0x20000;
const MAX_WINDOW_SIZE: u64 = 64 * 1024 * 1024;

/// A single decode (Huffman) table, mirroring libarchive's `struct decode_table`.
struct DecodeTable {
    size: u32,
    decode_len: [i32; 16],
    decode_pos: [u32; 16],
    quick_bits: u32,
    quick_len: Vec<u8>,  // 1 << quick_bits
    quick_num: Vec<u16>, // 1 << quick_bits
    decode_num: [u16; HUFF_NC],
}

impl DecodeTable {
    fn new() -> Self {
        DecodeTable {
            size: 0,
            decode_len: [0; 16],
            decode_pos: [0; 16],
            quick_bits: 0,
            quick_len: Vec::new(),
            quick_num: Vec::new(),
            decode_num: [0; HUFF_NC],
        }
    }
}

#[derive(Clone, Copy)]
enum FilterType {
    Delta,
    E8,
    E8E9,
    Arm,
}

struct FilterInfo {
    kind: FilterType,
    channels: u32,
    block_start: u64, // absolute window position
    block_length: u64,
}

/// Bit reader over the current block buffer (big-endian bit order, as in RAR5).
struct BitReader {
    bit_addr: i32, // 0..7
    in_addr: usize,
}

/// A stream that does not decode: damage.
fn err(reason: &str) -> LimitHit {
    LimitHit::corrupt(format!("rar5: {reason}"))
}

/// A stream that decodes to more than the scan's budget allows.
fn over(reason: &str) -> LimitHit {
    LimitHit::new(format!("rar5: {reason}"))
}

/// Big-endian helpers that never read out of bounds (missing bytes read as 0).
#[inline]
fn be32(p: &[u8], off: usize) -> u32 {
    let g = |i: usize| *p.get(off + i).unwrap_or(&0) as u32;
    (g(0) << 24) | (g(1) << 16) | (g(2) << 8) | g(3)
}
#[inline]
fn be24(p: &[u8], off: usize) -> u32 {
    let g = |i: usize| *p.get(off + i).unwrap_or(&0) as u32;
    (g(0) << 16) | (g(1) << 8) | g(2)
}

impl BitReader {
    fn new() -> Self {
        BitReader {
            bit_addr: 0,
            in_addr: 0,
        }
    }

    /// read_bits_32: 32 bits MSB-first from the current bit position.
    fn bits_32(&self, p: &[u8]) -> u32 {
        let mut bits = be32(p, self.in_addr);
        let ba = self.bit_addr as u32;
        bits = bits.wrapping_shl(ba);
        if ba != 0 {
            let extra = (*p.get(self.in_addr + 4).unwrap_or(&0) as u32) >> (8 - ba);
            bits |= extra;
        }
        bits
    }

    /// read_bits_16: 16 bits MSB-first.
    fn bits_16(&self, p: &[u8]) -> u16 {
        let bits = be24(p, self.in_addr) >> (8 - self.bit_addr as u32);
        (bits & 0xffff) as u16
    }

    fn skip(&mut self, n: i32) {
        let new_bits = self.bit_addr + n;
        self.in_addr += (new_bits >> 3) as usize;
        self.bit_addr = new_bits & 7;
    }

    /// read_consume_bits: read up to 16 bits then skip them.
    fn consume_bits(&mut self, p: &[u8], n: i32) -> i32 {
        let v = self.bits_16(p) as i32;
        let num = v >> (16 - n);
        self.skip(n);
        num
    }
}

/// create_decode_tables: build a Huffman decode table from bit lengths.
/// Returns false on an over-subscribed (invalid) table.
fn create_decode_tables(bit_length: &[u8], table: &mut DecodeTable, size: usize) -> bool {
    let mut lc = [0i32; 16];
    table.decode_num = [0; HUFF_NC];
    table.size = size as u32;
    table.quick_bits = if size == HUFF_NC { 10 } else { 7 };

    for &bl in bit_length.iter().take(size) {
        lc[(bl & 15) as usize] += 1;
    }
    lc[0] = 0;
    table.decode_pos[0] = 0;
    table.decode_len[0] = 0;

    let mut upper_limit: i32 = 0;
    for i in 1..16 {
        upper_limit += lc[i];
        table.decode_len[i] = upper_limit << (16 - i);
        table.decode_pos[i] = table.decode_pos[i - 1].wrapping_add(lc[i - 1] as u32);
        upper_limit <<= 1;
    }

    if upper_limit > 65536 {
        return false;
    }

    let mut decode_pos_clone = table.decode_pos;
    for (i, &bl) in bit_length.iter().enumerate().take(size) {
        let clen = (bl & 15) as usize;
        if clen > 0 {
            let last_pos = decode_pos_clone[clen] as usize;
            if last_pos < table.decode_num.len() {
                table.decode_num[last_pos] = i as u16;
            }
            decode_pos_clone[clen] += 1;
        }
    }

    let quick_data_size: i64 = 1i64 << table.quick_bits;
    table.quick_len = vec![0u8; quick_data_size as usize];
    table.quick_num = vec![0u16; quick_data_size as usize];

    let mut cur_len: usize = 1;
    for code in 0..quick_data_size {
        let bit_field = (code << (16 - table.quick_bits)) as i32;
        while cur_len < 16 && bit_field >= table.decode_len[cur_len] {
            cur_len += 1;
        }
        table.quick_len[code as usize] = cur_len as u8;

        let mut dist = bit_field - table.decode_len[cur_len - 1];
        dist >>= 16 - cur_len;
        let pos = table.decode_pos[cur_len & 15].wrapping_add(dist as u32) as usize;
        if cur_len < 16 && pos < size && pos < table.decode_num.len() {
            table.quick_num[code as usize] = table.decode_num[pos];
        } else {
            table.quick_num[code as usize] = 0;
        }
    }
    true
}

/// decode_number: decode one symbol using a decode table.
fn decode_number(br: &mut BitReader, table: &DecodeTable, p: &[u8]) -> u16 {
    let bitfield = (br.bits_16(p) & 0xfffe) as i32;

    if bitfield < table.decode_len[table.quick_bits as usize] {
        let code = (bitfield >> (16 - table.quick_bits)) as usize;
        if code < table.quick_len.len() {
            br.skip(table.quick_len[code] as i32);
            return table.quick_num[code];
        }
    }

    let bits = ((table.quick_bits as usize + 1)..15)
        .find(|&i| bitfield < table.decode_len[i])
        .unwrap_or(15);
    br.skip(bits as i32);

    let mut dist = bitfield - table.decode_len[bits - 1];
    dist >>= 16 - bits;
    let mut pos = table.decode_pos[bits].wrapping_add(dist as u32) as usize;
    if pos >= table.size as usize {
        pos = 0;
    }
    *table.decode_num.get(pos).unwrap_or(&0)
}

/// The decoder state for a single file member.
struct Unpacker {
    window_buf: Vec<u8>,
    window_mask: usize,
    window_size: usize,
    write_ptr: u64,
    last_write_ptr: u64,
    last_len: i32,
    dist_cache: [i32; 4],
    filters: std::collections::VecDeque<FilterInfo>,
    last_block_start: i64,
    last_block_length: i64,
    bd: DecodeTable,
    ld: DecodeTable,
    dd: DecodeTable,
    ldd: DecodeTable,
    rd: DecodeTable,
    /// Distance codes in the tables: [`HUFF_DC`], or [`HUFF_DCX`] for the RAR 7
    /// algorithm.
    dist_codes: usize,
    /// Where in the stream the current member's output starts. The x86 and
    /// ARM filters convert addresses relative to the member, which in a solid
    /// group is not the stream.
    file_start: u64,
    // current block context
    cur_block_size: usize,
    block_parsing_finished: bool,
    last_block: bool,
    bit_size: u8,
    // output
    out: Vec<u8>,
    /// Bytes of the member put out so far; a streamed member's `out` is
    /// drained as it goes.
    pushed: u64,
    cap: u64,
    /// The largest window the member's dictionary allows, and the largest the
    /// caller allows: a window sized to what the headers declare grows
    /// towards these when the stream goes on past it ([`Unpacker::make_room`]).
    dict: u64,
    window_limit: u64,
    /// The window had to grow past `window_limit`.
    over_limit: bool,
}

impl Unpacker {
    fn dist_cache_push(&mut self, value: i32) {
        self.dist_cache[3] = self.dist_cache[2];
        self.dist_cache[2] = self.dist_cache[1];
        self.dist_cache[1] = self.dist_cache[0];
        self.dist_cache[0] = value;
    }

    fn dist_cache_touch(&mut self, idx: usize) -> i32 {
        let dist = self.dist_cache[idx];
        let mut i = idx;
        while i > 0 {
            self.dist_cache[i] = self.dist_cache[i - 1];
            i -= 1;
        }
        self.dist_cache[0] = dist;
        dist
    }

    fn copy_string(&mut self, len: i32, dist: i32) -> Result<(), LimitHit> {
        if dist <= 0 || len < 0 {
            return Err(err("invalid copy_string params"));
        }
        let cmask = self.window_mask as u64;
        let write_ptr = self.write_ptr;
        let dist = dist as u64;
        // A distance past the start of the stream: unrar writes the whole
        // match as zeros, the part past the start included.
        let zeros = dist > write_ptr;
        for i in 0..len as u64 {
            let write_idx = ((write_ptr + i) & cmask) as usize;
            let read_idx = ((write_ptr + i).wrapping_sub(dist) & cmask) as usize;
            self.window_buf[write_idx] = if zeros { 0 } else { self.window_buf[read_idx] };
        }
        self.write_ptr += len as u64;
        Ok(())
    }

    /// Double a window smaller than the dictionary before the next decode
    /// step can wrap it: a stream longer than its headers declare reaches
    /// back as far as the dictionary. Nothing has wrapped yet, so every byte
    /// stays where it is.
    fn make_room(&mut self) -> Result<(), LimitHit> {
        let mut size = self.window_size as u64;
        // A step stops past half the window, after one more match.
        while size < self.dict && self.write_ptr + size / 2 + MAX_MATCH + 1 > size {
            size = (size * 2).min(self.dict);
        }
        if size == self.window_size as u64 {
            return Ok(());
        }
        if size > self.window_limit {
            self.over_limit = true;
            return Err(over(
                "the stream needs a window over the buffer limit (--max-object-bytes)",
            ));
        }
        let size = usize::try_from(size).map_err(|_| over("window too large"))?;
        self.window_buf.resize(size, 0);
        self.window_mask = size - 1;
        self.window_size = size;
        Ok(())
    }
}

/// The longest match: length code 43 (4,097 bytes) and 3 for a far distance.
const MAX_MATCH: u64 = 4100;

/// decode_code_length: derive a match/length value from a slot code.
fn decode_code_length(br: &mut BitReader, p: &[u8], code: u16) -> i32 {
    let mut length: i32 = 2;
    let lbits: i32;
    if code < 8 {
        lbits = 0;
        length += code as i32;
    } else {
        lbits = (code / 4 - 1) as i32;
        length += (4 | (code & 3) as i32) << lbits;
    }
    if lbits > 0 {
        length += br.consume_bits(p, lbits);
    }
    length
}

/// parse_block_header: read the 1..2-byte block header and validate its cksum.
/// Returns (block_size, header_len, flags_byte) or None on error.
fn parse_block_header(p: &[u8], off: usize) -> Option<(usize, usize, u8)> {
    let flags = *p.get(off)?;
    let cksum = *p.get(off + 1)?;
    let byte_count = ((flags >> 3) & 7) as usize;
    if byte_count > 2 {
        return None;
    }
    let block_size = match byte_count {
        0 => *p.get(off + 2)? as u32,
        1 => u16::from_le_bytes([*p.get(off + 2)?, *p.get(off + 3)?]) as u32,
        _ => {
            u32::from_le_bytes([*p.get(off + 2)?, *p.get(off + 3)?, *p.get(off + 4)?, 0])
                & 0x00FF_FFFF
        }
    };
    let calc =
        0x5A ^ flags ^ (block_size as u8) ^ ((block_size >> 8) as u8) ^ ((block_size >> 16) as u8);
    if calc != cksum {
        return None;
    }
    // header length = 2 (flags+cksum) + (byte_count+1) for the size field.
    Some((block_size as usize, 2 + byte_count + 1, flags))
}

/// parse_tables: RLE-decode the bit lengths, then build all five decode tables.
fn parse_tables(u: &mut Unpacker, br: &mut BitReader, p: &[u8]) -> Result<(), LimitHit> {
    let mut bit_length = [0u8; HUFF_BC];
    let mut nibble_mask = 0xF0u8;
    let mut nibble_shift = 4u8;
    let mut i = 0usize;
    let mut w = 0usize;
    const ESCAPE: u8 = 15;

    while w < HUFF_BC {
        if i >= u.cur_block_size {
            return Err(err("truncated huffman tables"));
        }
        let mut value = (p[i] & nibble_mask) >> nibble_shift;
        if nibble_mask == 0x0F {
            i += 1;
        }
        nibble_mask ^= 0xFF;
        nibble_shift ^= 4;

        if value == ESCAPE {
            if i >= u.cur_block_size {
                return Err(err("truncated huffman tables"));
            }
            value = (p[i] & nibble_mask) >> nibble_shift;
            if nibble_mask == 0x0F {
                i += 1;
            }
            nibble_mask ^= 0xFF;
            nibble_shift ^= 4;

            if value == 0 {
                bit_length[w] = ESCAPE;
                w += 1;
            } else {
                let mut k = 0;
                while k < value as usize + 2 && w < HUFF_BC {
                    bit_length[w] = 0;
                    w += 1;
                    k += 1;
                }
            }
        } else {
            bit_length[w] = value;
            w += 1;
        }
    }

    br.in_addr = i;
    br.bit_addr = (nibble_shift ^ 4) as i32;

    if !create_decode_tables(&bit_length, &mut u.bd, HUFF_BC) {
        return Err(err("bad bit-length table"));
    }

    let table_size = HUFF_NC + u.dist_codes + HUFF_RC + HUFF_LDC;
    let mut table = [0u8; HUFF_TABLE_SIZE_MAX];
    let mut i = 0usize;
    while i < table_size {
        // Guard against a runaway bit reader on malformed input.
        if br.in_addr >= u.cur_block_size + 4 {
            return Err(err("table bit reader overrun"));
        }
        let num = decode_number(br, &u.bd, p);
        if num < 16 {
            table[i] = num as u8;
            i += 1;
        } else if num < 18 {
            let mut n = br.bits_16(p);
            if num == 16 {
                n >>= 13;
                n += 3;
                br.skip(3);
            } else {
                n >>= 9;
                n += 11;
                br.skip(7);
            }
            if i == 0 {
                return Err(err("repeat with no previous code"));
            }
            while n > 0 && i < table_size {
                table[i] = table[i - 1];
                i += 1;
                n -= 1;
            }
        } else {
            let mut n = br.bits_16(p);
            if num == 18 {
                n >>= 13;
                n += 3;
                br.skip(3);
            } else {
                n >>= 9;
                n += 11;
                br.skip(7);
            }
            while n > 0 && i < table_size {
                table[i] = 0;
                i += 1;
                n -= 1;
            }
        }
    }

    let mut idx = 0usize;
    if !create_decode_tables(&table[idx..], &mut u.ld, HUFF_NC) {
        return Err(err("bad literal table"));
    }
    idx += HUFF_NC;
    if !create_decode_tables(&table[idx..], &mut u.dd, u.dist_codes) {
        return Err(err("bad distance table"));
    }
    idx += u.dist_codes;
    if !create_decode_tables(&table[idx..], &mut u.ldd, HUFF_LDC) {
        return Err(err("bad low-distance table"));
    }
    idx += HUFF_LDC;
    if !create_decode_tables(&table[idx..], &mut u.rd, HUFF_RC) {
        return Err(err("bad rep-distance table"));
    }
    Ok(())
}

/// parse_filter_data: read a 1..4-byte little-endian value, 8 bits at a time.
fn parse_filter_data(br: &mut BitReader, p: &[u8]) -> u32 {
    let bytes = br.consume_bits(p, 2) + 1;
    let mut data: u32 = 0;
    for i in 0..bytes {
        let byte = br.bits_16(p);
        data = data.wrapping_add(((byte >> 8) as u32) << (i * 8));
        br.skip(8);
    }
    data
}

/// Filters a stream may have waiting for their block.
const MAX_QUEUED_FILTERS: usize = 8192;

/// parse_filter: read a filter descriptor (code 256) and queue it.
fn parse_filter(u: &mut Unpacker, br: &mut BitReader, p: &[u8]) -> Result<(), LimitHit> {
    let block_start = parse_filter_data(br, p);
    let block_length = parse_filter_data(br, p);
    let filter_type = (br.bits_16(p) >> 13) as u32;
    br.skip(3);

    // Sanity checks mirroring is_valid_filter_block_start + bounds.
    let abs_start = block_start as i64 + u.write_ptr as i64;
    let valid_start = if u.last_block_start == 0 || u.last_block_length == 0 {
        true
    } else {
        abs_start >= u.last_block_start + u.last_block_length
    };
    if !(4..=0x400000).contains(&block_length)
        || !valid_start
        || (u.window_size > 0 && block_length as usize > u.window_size >> 1)
    {
        return Err(err("invalid filter"));
    }

    let kind = match filter_type {
        0 => FilterType::Delta,
        1 => FilterType::E8,
        2 => FilterType::E8E9,
        3 => FilterType::Arm,
        _ => return Err(err("unsupported filter type")),
    };

    let abs_block_start = u.write_ptr + block_start as u64;
    u.last_block_start = abs_block_start as i64;
    u.last_block_length = block_length as i64;

    let channels = if matches!(kind, FilterType::Delta) {
        (br.consume_bits(p, 5) + 1) as u32
    } else {
        0
    };

    // An encoder queues a few; more is damage, as in RAR3, and each would
    // hold memory no budget counts.
    if u.filters.len() >= MAX_QUEUED_FILTERS {
        return Err(err("too many filters"));
    }
    u.filters.push_back(FilterInfo {
        kind,
        channels,
        block_start: abs_block_start,
        block_length: block_length as u64,
    });
    Ok(())
}

/// do_uncompress_block: decode literals from the current block into the window.
/// Returns true if the block was fully consumed.
fn do_uncompress_block(u: &mut Unpacker, br: &mut BitReader, p: &[u8]) -> Result<bool, LimitHit> {
    let cmask = u.window_mask as u64;
    let bit_size = u.bit_size as i32;
    let block_end = u.cur_block_size as i32;

    loop {
        if (u.write_ptr - u.last_write_ptr) > (u.window_size as u64 >> 1) {
            // Don't grow by more than half the window at a time.
            return Ok(false);
        }
        if br.in_addr as i32 > block_end - 1
            || (br.in_addr as i32 == block_end - 1 && br.bit_addr >= bit_size)
        {
            return Ok(true);
        }

        let num = decode_number(br, &u.ld, p);

        if num < 256 {
            let write_idx = (u.write_ptr & cmask) as usize;
            u.window_buf[write_idx] = num as u8;
            u.write_ptr += 1;
            continue;
        } else if num >= 262 {
            let mut len = decode_code_length(br, p, num - 262);
            let dist_slot = decode_number(br, &u.dd, p);
            if dist_slot as usize >= HUFF_DC {
                return Err(err("distance beyond the window"));
            }
            let dbits: i32;
            let mut dist: i64 = 1;
            if dist_slot < 4 {
                dbits = 0;
                dist += dist_slot as i64;
            } else {
                dbits = (dist_slot / 2 - 1) as i32;
                dist += ((2 | (dist_slot & 1)) as i64) << dbits;
            }

            if dbits > 0 {
                if dbits >= 4 {
                    if dbits > 4 {
                        let mut add = br.bits_32(p);
                        br.skip(dbits - 4);
                        add = (add >> (36 - dbits)) << 4;
                        dist += add as i64;
                    }
                    let low_dist = decode_number(br, &u.ldd, p);
                    if dist >= i32::MAX as i64 - low_dist as i64 - 1 {
                        return Err(err("distance overflow"));
                    }
                    dist += low_dist as i64;
                } else {
                    dist += br.consume_bits(p, dbits) as i64;
                }
            }

            if dist > 0x100 {
                len += 1;
                if dist > 0x2000 {
                    len += 1;
                    if dist > 0x40000 {
                        len += 1;
                    }
                }
            }

            u.dist_cache_push(dist as i32);
            u.last_len = len;
            u.copy_string(len, dist as i32)?;
            continue;
        } else if num == 256 {
            parse_filter(u, br, p)?;
            continue;
        } else if num == 257 {
            if u.last_len != 0 {
                let d = u.dist_cache[0];
                u.copy_string(u.last_len, d)?;
            }
            continue;
        } else {
            // 258..=261
            let idx = (num - 258) as usize;
            let dist = u.dist_cache_touch(idx);
            let len_slot = decode_number(br, &u.rd, p);
            let len = decode_code_length(br, p, len_slot);
            u.last_len = len;
            u.copy_string(len, dist)?;
            continue;
        }
    }
}

/// Emit window data in range [begin, end) (absolute write-pointer coordinates)
/// to the output, handling circular-buffer wrap. Enforces the budget.
fn push_window_data(u: &mut Unpacker, begin: u64, end: u64) -> Result<(), LimitHit> {
    if end <= begin {
        return Ok(());
    }
    let total = end - begin;
    if u.pushed + total > u.cap {
        return Err(over("output exceeds budget"));
    }
    u.pushed += total;
    let wmask = u.window_mask as u64;
    let b = (begin & wmask) as usize;
    let e = (end & wmask) as usize;
    if b >= e {
        // wrapped
        u.out.extend_from_slice(&u.window_buf[b..]);
        u.out.extend_from_slice(&u.window_buf[..e]);
    } else {
        u.out.extend_from_slice(&u.window_buf[b..e]);
    }
    Ok(())
}

/// Run a filter over the window and append the transformed block to output.
fn run_filter(u: &mut Unpacker, flt: &FilterInfo) -> Result<(), LimitHit> {
    let blen = flt.block_length as usize;
    let wmask = u.window_mask as u64;
    let start = flt.block_start;

    // Gather the block into a linear buffer first.
    let mut buf = vec![0u8; blen];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = u.window_buf[((start + i as u64) & wmask) as usize];
    }

    let mut out = vec![0u8; blen];
    match flt.kind {
        FilterType::Delta => {
            let channels = flt.channels.max(1) as usize;
            let mut src_pos = 0usize;
            for ch in 0..channels {
                let mut prev_byte = 0u8;
                let mut dest_pos = ch;
                while dest_pos < blen {
                    prev_byte = prev_byte.wrapping_sub(buf[src_pos]);
                    out[dest_pos] = prev_byte;
                    src_pos += 1;
                    dest_pos += channels;
                }
            }
        }
        FilterType::E8 | FilterType::E8E9 => {
            out.copy_from_slice(&buf);
            let extended = matches!(flt.kind, FilterType::E8E9);
            let file_size: u32 = 0x1000000;
            let read_u32 = |b: &[u8], at: usize| -> u32 {
                let g = |k: usize| *b.get(at + k).unwrap_or(&0) as u32;
                g(0) | (g(1) << 8) | (g(2) << 16) | (g(3) << 24)
            };
            if blen >= 4 {
                let mut i = 0usize;
                while i < blen - 4 {
                    let b = buf[i];
                    i += 1;
                    if b == 0xE8 || (extended && b == 0xE9) {
                        let at = (i as u64 + flt.block_start).saturating_sub(u.file_start);
                        let offset = (at % file_size as u64) as u32;
                        let addr = read_u32(&buf, i);
                        if addr & 0x8000_0000 != 0 {
                            if (addr.wrapping_add(offset)) & 0x8000_0000 == 0 {
                                let v = addr.wrapping_add(file_size);
                                out[i..i + 4].copy_from_slice(&v.to_le_bytes());
                            }
                        } else if (addr.wrapping_sub(file_size)) & 0x8000_0000 != 0 {
                            let naddr = addr.wrapping_sub(offset);
                            out[i..i + 4].copy_from_slice(&naddr.to_le_bytes());
                        }
                        i += 4;
                    }
                }
            }
        }
        FilterType::Arm => {
            out.copy_from_slice(&buf);
            let read_u32 = |b: &[u8], at: usize| -> u32 {
                let g = |k: usize| *b.get(at + k).unwrap_or(&0) as u32;
                g(0) | (g(1) << 8) | (g(2) << 16) | (g(3) << 24)
            };
            if blen >= 4 {
                let mut i = 0usize;
                while i + 3 < blen {
                    if buf[i + 3] == 0xEB {
                        let mut offset = read_u32(&buf, i) & 0x00ff_ffff;
                        let at = (i as u64 + flt.block_start).saturating_sub(u.file_start);
                        offset = offset.wrapping_sub((at / 4) as u32);
                        offset = (offset & 0x00ff_ffff) | 0xeb00_0000;
                        out[i..i + 4].copy_from_slice(&offset.to_le_bytes());
                    }
                    i += 4;
                }
            }
        }
    }

    if u.pushed + blen as u64 > u.cap {
        return Err(over("filtered output exceeds budget"));
    }
    u.pushed += blen as u64;
    u.out.extend_from_slice(&out);
    u.last_write_ptr += blen as u64;
    Ok(())
}

/// apply_filters: emit pending output, running the next filter if its range is
/// fully unpacked. Returns true if it made progress (should be retried).
fn apply_filters(u: &mut Unpacker) -> Result<bool, LimitHit> {
    let Some((bs, len)) = u.filters.front().map(|f| (f.block_start, f.block_length)) else {
        return Ok(false);
    };
    if u.write_ptr > bs && u.write_ptr >= bs + len {
        if u.last_write_ptr == bs {
            if let Some(flt) = u.filters.pop_front() {
                run_filter(u, &flt)?;
            }
        } else {
            push_window_data(u, u.last_write_ptr, bs)?;
            u.last_write_ptr = bs;
        }
        return Ok(true);
    }
    Ok(false)
}

/// Entry point: decompress `packed` into at most `unpacked_size` bytes.
/// A RAR5 decoder that can be reused across the members of a **solid** group.
///
/// Each member carries its own block headers, but a solid member's first block
/// may declare no tables and continues writing into the window its predecessor
/// filled. Decoding it on a fresh window therefore yields plausible-looking
/// wrong bytes rather than an error, which is why every member's output is
/// checked against the CRC the archive records.
pub struct Unpacker50 {
    /// Boxed so that a walk holding this decoder across the visitor keeps the
    /// tables out of its stack frame.
    u: Box<Unpacker>,
    /// The member [`Self::start_member`] started.
    stream: Option<Stream5>,
}

/// Bytes past a block's end kept with it: the bit reader looks a few bytes
/// ahead of the last symbol it decodes, and sees there what the whole-input
/// path sees.
const BLOCK_LOOKAHEAD: usize = 64;

/// A streamed member's place in its packed data.
struct Stream5 {
    /// Packed bytes read from the source and not yet behind the current
    /// block, from `pend_at` in the member's packed data.
    pending: Vec<u8>,
    pend_at: u64,
    /// The member's packed size, as much of it as the source holds.
    packed_len: u64,
    /// Where the next block header is.
    consumed: u64,
    /// The current block from its data, and bytes after it up to
    /// [`BLOCK_LOOKAHEAD`]. Reads past it are zeros, as past the padded input.
    block: Vec<u8>,
    br: BitReader,
    out_pos: usize,
    done: bool,
}

impl Stream5 {
    /// The packed bytes `[from, to)` (fewer where the data ends), reading
    /// from `src` as far as `to`.
    fn bytes(&mut self, src: &mut dyn std::io::Read, from: u64, to: u64) -> Vec<u8> {
        let to = to.min(self.packed_len);
        while self.pend_at + (self.pending.len() as u64) < to {
            let at = self.pending.len();
            let want = (to - self.pend_at - at as u64).min(1 << 20) as usize;
            self.pending.resize(at + want, 0);
            let n = loop {
                match src.read(&mut self.pending[at..]) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    // The walk reports a source that failed.
                    Err(_) => break 0,
                }
            };
            self.pending.truncate(at + n);
            if n == 0 {
                // What the source does not give reads as zeros.
                self.packed_len = self.pend_at + self.pending.len() as u64;
                break;
            }
        }
        let a = from.saturating_sub(self.pend_at) as usize;
        let b = to.saturating_sub(self.pend_at) as usize;
        self.pending
            .get(a.min(self.pending.len())..b.min(self.pending.len()))
            .unwrap_or(&[])
            .to_vec()
    }

    /// Forget the packed bytes before `at`.
    fn drop_before(&mut self, at: u64) {
        let n = (at.saturating_sub(self.pend_at) as usize).min(self.pending.len());
        self.pending.drain(..n);
        self.pend_at += n as u64;
    }
}

/// Run what filters can run and move what is ready of the window to `out`.
fn drain_output(u: &mut Unpacker) -> Result<(), LimitHit> {
    loop {
        if apply_filters(u)? {
            continue;
        }
        let max_end_pos = match u.filters.front() {
            Some(flt) => flt.block_start.min(u.write_ptr),
            None => u.write_ptr,
        };
        if max_end_pos > u.last_write_ptr {
            let lw = u.last_write_ptr;
            push_window_data(u, lw, max_end_pos)?;
            u.last_write_ptr = max_end_pos;
        }
        return Ok(());
    }
}

/// Where a decode stands: an iteration that changes none of it made no
/// progress, and would make none again.
type Progress = (u64, usize, i32, u64, u64, usize, bool);

fn progress(u: &Unpacker, br: &BitReader, consumed: u64) -> Progress {
    (
        consumed,
        br.in_addr,
        br.bit_addr,
        u.write_ptr,
        u.last_write_ptr,
        u.filters.len(),
        u.block_parsing_finished,
    )
}

impl Unpacker50 {
    /// A decoder for the RAR 5.0 algorithm on a `window_size` window.
    ///
    /// Not inlined: the tables are built in this call's frame, which a caller
    /// that recurses into the visitor must not inherit.
    #[inline(never)]
    pub fn new(window_size: u64) -> Result<Self, LimitHit> {
        if window_size == 0 || window_size > MAX_WINDOW_SIZE || !window_size.is_power_of_two() {
            return Err(err("invalid window size"));
        }
        let ws = window_size as usize;
        Ok(Unpacker50 {
            u: Box::new(Unpacker {
                window_buf: vec![0u8; ws],
                window_mask: ws - 1,
                window_size: ws,
                write_ptr: 0,
                last_write_ptr: 0,
                last_len: 0,
                dist_cache: [0; 4],
                filters: std::collections::VecDeque::new(),
                last_block_start: 0,
                last_block_length: 0,
                bd: DecodeTable::new(),
                ld: DecodeTable::new(),
                dd: DecodeTable::new(),
                ldd: DecodeTable::new(),
                rd: DecodeTable::new(),
                dist_codes: HUFF_DC,
                file_start: 0,
                cur_block_size: 0,
                block_parsing_finished: true,
                last_block: false,
                bit_size: 0,
                out: Vec::new(),
                pushed: 0,
                cap: 0,
                dict: window_size,
                window_limit: window_size,
                over_limit: false,
            }),
            stream: None,
        })
    }

    /// Whether the stream needed a window over the limit the decoder was
    /// given.
    pub fn window_over_limit(&self) -> bool {
        self.u.over_limit
    }

    /// Decode one member, its whole stream: the bytes it holds past its
    /// declared size too, and as far as it goes when it ends before. `solid` says the member continues the previous one's
    /// stream, in which case the window and tables are kept. A declared size,
    /// or output, over what the budget has left is a limit.
    pub fn member(
        &mut self,
        packed: &[u8],
        unpacked_size: u64,
        solid: bool,
        budget: &mut Budget,
    ) -> Result<Vec<u8>, LimitHit> {
        let cap = budget.reserve()?;
        if unpacked_size > cap {
            return Err(over("declared size exceeds budget"));
        }
        self.reset_for(cap, solid);
        let u = &mut self.u;

        // Pad the input so the bit reader can always read 4 bytes past in_addr.
        let mut input = Vec::with_capacity(packed.len() + 8);
        input.extend_from_slice(packed);
        input.extend_from_slice(&[0u8; 8]);

        let mut consumed: usize = 0; // bytes of `packed` consumed for finished blocks
        let mut br = BitReader::new();
        // Slice covering the current block's data (set when a block starts).
        let mut block_off: usize = 0;

        loop {
            let before = progress(u, &br, consumed as u64);
            if u.block_parsing_finished {
                if consumed >= packed.len() {
                    break;
                }
                let (block_size, hdr_len, flags) =
                    parse_block_header(&input, consumed).ok_or_else(|| err("bad block header"))?;
                let table_present = (flags >> 7) & 1 == 1;
                u.last_block = (flags >> 6) & 1 == 1;
                u.bit_size = 1 + (flags & 7);

                let data_start = consumed + hdr_len;
                if data_start > packed.len() {
                    return Err(err("block header past end"));
                }
                // cur_block_size is the in-file block data (clamp to available).
                let avail = packed.len() - data_start;
                u.cur_block_size = block_size.min(avail);
                block_off = data_start;
                u.block_parsing_finished = false;

                br.in_addr = 0;
                br.bit_addr = 0;

                // The block buffer starts at block_off in `input` (padded).
                if table_present {
                    let p = &input[block_off..];
                    parse_tables(u, &mut br, p)?;
                }
                // Advance `consumed` past this whole block now (single-volume:
                // the block data is fully present).
                consumed = data_start + u.cur_block_size;
            }

            u.make_room()?;
            let finished = {
                let p = &input[block_off..];
                do_uncompress_block(u, &mut br, p)?
            };
            u.block_parsing_finished = finished;
            drain_output(u)?;

            if finished && u.last_block && u.filters.is_empty() {
                break;
            }
            if progress(u, &br, consumed as u64) == before {
                return Err(err("decode made no progress"));
            }
        }

        budget.commit(u.out.len() as u64);
        Ok(std::mem::take(&mut u.out))
    }

    /// A decoder on a window of `window` bytes, a power of two, for the
    /// algorithm `comp_info` names, the caller having charged the window to
    /// its limit. The window grows towards the dictionary when a stream goes
    /// on past it, up to `limit` bytes.
    pub fn with_window(window: u64, comp_info: u64, limit: u64) -> Result<Self, LimitHit> {
        if window == 0 || !window.is_power_of_two() || usize::try_from(window).is_err() {
            return Err(err("invalid window size"));
        }
        let mut dec = Self::new_unchecked(window as usize);
        if rar7_algorithm(comp_info) {
            dec.u.dist_codes = HUFF_DCX;
        }
        dec.u.dict = dictionary_size(comp_info).max(window);
        dec.u.window_limit = limit;
        Ok(dec)
    }

    fn new_unchecked(ws: usize) -> Self {
        let mut d = Self::new(G_UNPACK_WINDOW_SIZE).expect("the smallest window is valid");
        d.u.window_buf = vec![0u8; ws];
        d.u.window_mask = ws - 1;
        d.u.window_size = ws;
        d
    }

    /// The state a member starts from, `cap` the most it may put out: a solid
    /// one keeps the window.
    fn reset_for(&mut self, cap: u64, solid: bool) {
        if !solid {
            // A fresh stream: forget the previous member's window position, its
            // repeat-distance history and any half-run filters.
            self.u.write_ptr = 0;
            self.u.last_write_ptr = 0;
            self.u.last_len = 0;
            self.u.dist_cache = [0; 4];
            self.u.last_block_start = 0;
            self.u.last_block_length = 0;
            self.u.window_buf.fill(0);
        }
        self.u.file_start = self.u.last_write_ptr;
        self.u.filters.clear();
        self.u.block_parsing_finished = true;
        self.u.last_block = false;
        self.u.out = Vec::new();
        self.u.pushed = 0;
        self.u.cap = cap;
    }

    /// Start a member of `packed_len` packed bytes, read from a source as
    /// they are needed with [`Self::read_member`]: the streaming form of
    /// [`Self::member`], holding the window, one block of input (at most
    /// 16 MiB, the format's largest) and the output of one decode step. What
    /// reads it bounds its output.
    pub fn start_member(&mut self, packed_len: u64, solid: bool) {
        self.reset_for(u64::MAX, solid);
        self.stream = Some(Stream5 {
            pending: Vec::new(),
            pend_at: 0,
            packed_len,
            consumed: 0,
            block: Vec::new(),
            br: BitReader::new(),
            out_pos: 0,
            done: false,
        });
    }

    /// The next decoded bytes of the member [`Self::start_member`] started
    /// from its packed bytes in `src`, 0 at its end. The same steps as
    /// [`Self::member`], the output handed over as each step makes it.
    pub fn read_member(
        &mut self,
        buf: &mut [u8],
        src: &mut dyn std::io::Read,
    ) -> Result<usize, LimitHit> {
        let Some(s) = self.stream.as_mut() else {
            return Ok(0);
        };
        let u = &mut self.u;
        loop {
            if s.out_pos < u.out.len() {
                let n = (u.out.len() - s.out_pos).min(buf.len());
                buf[..n].copy_from_slice(&u.out[s.out_pos..s.out_pos + n]);
                s.out_pos += n;
                return Ok(n);
            }
            u.out.clear();
            s.out_pos = 0;
            if s.done || buf.is_empty() {
                return Ok(0);
            }
            let before = progress(u, &s.br, s.consumed);
            if u.block_parsing_finished {
                if s.consumed >= s.packed_len {
                    s.done = true;
                    continue;
                }
                // Past the data, zeros, as the whole-input path pads.
                let mut head = s.bytes(src, s.consumed, s.consumed + 6);
                head.resize(6, 0);
                let Some((block_size, hdr_len, flags)) = parse_block_header(&head, 0) else {
                    s.done = true;
                    return Err(err("bad block header"));
                };
                let table_present = (flags >> 7) & 1 == 1;
                u.last_block = (flags >> 6) & 1 == 1;
                u.bit_size = 1 + (flags & 7);
                let data_start = s.consumed + hdr_len as u64;
                if data_start > s.packed_len {
                    s.done = true;
                    return Err(err("block header past end"));
                }
                let avail = s.packed_len - data_start;
                u.cur_block_size = (block_size as u64).min(avail) as usize;
                let end = data_start + u.cur_block_size as u64;
                s.block = s.bytes(src, data_start, end + BLOCK_LOOKAHEAD as u64);
                // A source that gave less than it holds reads as zeros.
                if s.block.len() < u.cur_block_size + 8 {
                    s.block.resize(u.cur_block_size + 8, 0);
                }
                s.drop_before(end);
                u.block_parsing_finished = false;
                s.br.in_addr = 0;
                s.br.bit_addr = 0;
                if table_present && let Err(e) = parse_tables(u, &mut s.br, &s.block) {
                    s.done = true;
                    return Err(e);
                }
                s.consumed = end;
            }
            let step = u
                .make_room()
                .and_then(|()| do_uncompress_block(u, &mut s.br, &s.block));
            let finished = match step {
                Ok(f) => f,
                Err(e) => {
                    s.done = true;
                    return Err(e);
                }
            };
            u.block_parsing_finished = finished;
            if let Err(e) = drain_output(u) {
                s.done = true;
                return Err(e);
            }
            if finished && u.last_block && u.filters.is_empty() {
                s.done = true;
            } else if progress(u, &s.br, s.consumed) == before {
                s.done = true;
                return Err(err("decode made no progress"));
            }
        }
    }
}

/// Decompress a single, non-solid RAR5 member on a fresh window.
pub fn unpack50(
    packed: &[u8],
    unpacked_size: u64,
    window_size: u64,
    budget: &mut Budget,
) -> Result<Vec<u8>, LimitHit> {
    Unpacker50::new(window_size)?.member(packed, unpacked_size, false, budget)
}

/// Whether `comp_info`'s algorithm version (bits 0..5) is one this decoder
/// has: 0 (RAR 5.0) or 1 (RAR 7).
pub(crate) fn known_version(comp_info: u64) -> bool {
    comp_info & 0x3f <= 1
}

/// Whether `comp_info` selects the RAR 7 algorithm: version 1 (bits 0..5),
/// unless bit 20 says the data is the version 0 algorithm all the same.
fn rar7_algorithm(comp_info: u64) -> bool {
    comp_info & 0x3f == 1 && comp_info & 0x10_0000 == 0
}

/// The window to decode the member whose file header holds `comp_info` in: its
/// dictionary, 128 KiB << bits 10..14, plus for version 1 that size times bits
/// 15..19 over 32, rounded up to a power of two. No distance reaches past the
/// dictionary, so the larger window decodes the same bytes. 0 for a dictionary
/// over `MAX_WINDOW_SIZE`.
pub fn window_size_from_comp_info(comp_info: u64) -> u64 {
    let base = G_UNPACK_WINDOW_SIZE << ((comp_info >> 10) & 0x1f);
    let mut dict = base;
    if comp_info & 0x3f == 1 {
        dict += base / 32 * ((comp_info >> 15) & 0x1f);
    }
    if dict > MAX_WINDOW_SIZE {
        0
    } else {
        dict.next_power_of_two()
    }
}

/// The window [`window_size_from_comp_info`] gives, without its cap: the
/// streaming path charges it to the buffer limit instead.
pub fn dictionary_size(comp_info: u64) -> u64 {
    let base = G_UNPACK_WINDOW_SIZE << ((comp_info >> 10) & 0x1f);
    let mut dict = base;
    if comp_info & 0x3f == 1 {
        dict += base / 32 * ((comp_info >> 15) & 0x1f);
    }
    dict.next_power_of_two()
}

/// The window for a decoder started at the member whose header holds
/// `comp_info`, `output` being the bytes it produces from there to the end of
/// its solid run, when they are known: a distance past the bytes produced
/// writes zeros (`copy_string`), so a window that holds them all
/// decodes what the dictionary would. The dictionary when it is smaller, never less than 128 KiB. A
/// stream longer than its headers declare grows the window as it goes.
pub fn window_for(comp_info: u64, output: Option<u64>) -> u64 {
    let dict = dictionary_size(comp_info);
    output
        .and_then(|n| n.max(G_UNPACK_WINDOW_SIZE).checked_next_power_of_two())
        .map_or(dict, |w| w.min(dict))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;

    /// A stream that does not decode is damage; a member that declares more
    /// than the scan's budget allows is a limit.
    #[test]
    fn a_stream_that_does_not_decode_is_damage_and_a_huge_member_is_a_limit() {
        let mut budget = Budget::new(Limits::default());
        let e = unpack50(&[0xff; 4], 1000, 1 << 17, &mut budget).expect_err("not a stream");
        assert!(e.is_corrupt(), "{}", e.reason);
        let mut budget = Budget::new(Limits {
            max_extracted_bytes: 10,
            ..Limits::default()
        });
        let e = unpack50(&[0; 8], 1000, 1 << 17, &mut budget).expect_err("over the budget");
        assert!(!e.is_corrupt(), "{}", e.reason);
    }

    /// The filters waiting for their block are capped, and one more is damage.
    #[test]
    fn a_filter_past_the_queue_cap_is_damage() {
        let mut d = Unpacker50::new(1 << 17).unwrap();
        let u = &mut d.u;
        let queued = || FilterInfo {
            kind: FilterType::E8,
            channels: 0,
            block_start: 0,
            block_length: 4,
        };
        // A descriptor: start 16 and length 8, one byte each, then type E8.
        let p = [0b0000_0100, 0b0000_0000, 0b1000_0010, 0, 0, 0, 0, 0];
        let one = |u: &mut Unpacker| {
            // No block before it for this one to overlap.
            (u.last_block_start, u.last_block_length) = (0, 0);
            parse_filter(u, &mut BitReader::new(), &p)
        };
        u.filters
            .extend(std::iter::repeat_with(queued).take(MAX_QUEUED_FILTERS - 1));
        one(u).expect("the last one in the queue");
        assert_eq!(u.filters.back().map(|f| f.block_length), Some(8));
        let e = one(u).expect_err("past the cap");
        assert!(
            e.is_corrupt() && e.reason.contains("too many"),
            "{}",
            e.reason
        );
        assert_eq!(u.filters.len(), MAX_QUEUED_FILTERS);
    }

    /// A match from before the start of the stream is all zeros, the bytes
    /// that would come from the start included, as unrar writes it.
    #[test]
    fn a_match_from_before_the_start_writes_zeros() {
        let mut d = Unpacker50::new(1 << 17).unwrap();
        let u = &mut d.u;
        u.window_buf[..5].copy_from_slice(b"mjof ");
        u.write_ptr = 5;
        u.copy_string(8, 5).unwrap();
        u.copy_string(9, 15).unwrap();
        assert_eq!(&u.window_buf[..22], b"mjof mjof mjo\0\0\0\0\0\0\0\0\0");
    }

    #[test]
    fn window_size_calc() {
        assert_eq!(window_size_from_comp_info(0), 0x20000);
        assert_eq!(window_size_from_comp_info(1 << 10), 0x40000);
        // The size field is 5 bits: N = 16 is 8 GiB, past the cap, not 128 KiB.
        assert_eq!(window_size_from_comp_info(16 << 10), 0);
        // Version 1: 4 MiB plus 8/32 of it, rounded up to the next power of two.
        assert_eq!(
            window_size_from_comp_info(1 | (5 << 10) | (8 << 15)),
            8 << 20
        );
        // The fraction bits mean nothing in a version 0 header.
        assert_eq!(window_size_from_comp_info((5 << 10) | (8 << 15)), 4 << 20);
    }

    /// The ARM filter converts branch targets relative to the start of the
    /// member, so a block 64 bytes into a member converts the same whether
    /// the member starts the stream or follows 5000 bytes of another one in
    /// a solid group. A `BL` whose stored target is its own word index,
    /// 64 / 4, decodes to offset 0.
    #[test]
    fn the_arm_filter_counts_from_the_start_of_its_member() {
        let mut block = Vec::new();
        for i in 0..64u32 {
            let word = if i % 3 == 0 {
                0xeb00_0000 | (i * 4099)
            } else {
                i * 0x0101_0101
            };
            block.extend_from_slice(&word.to_le_bytes());
        }
        block[..4].copy_from_slice(&(0xeb00_0000u32 | 16).to_le_bytes());
        let run = |member_start: u64| -> Vec<u8> {
            let mut d = Unpacker50::new(1 << 17).unwrap();
            let u = &mut d.u;
            let at = member_start + 64;
            for (i, &b) in block.iter().enumerate() {
                let w = ((at + i as u64) as usize) & u.window_mask;
                u.window_buf[w] = b;
            }
            u.file_start = member_start;
            u.cap = u64::MAX;
            let f = FilterInfo {
                kind: FilterType::Arm,
                channels: 0,
                block_start: at,
                block_length: block.len() as u64,
            };
            run_filter(u, &f).unwrap();
            u.out.clone()
        };
        let alone = run(0);
        assert_eq!(&alone[..4], &0xeb00_0000u32.to_le_bytes());
        assert_eq!(run(5000), alone, "converted relative to the solid stream");
    }

    #[test]
    fn the_rar7_algorithm_is_version_1_without_bit_20() {
        assert!(rar7_algorithm(1));
        assert!(!rar7_algorithm(0));
        assert!(!rar7_algorithm(1 | 0x10_0000));
    }

    #[test]
    fn rejects_bad_window() {
        let mut b = Budget::new(Limits::default());
        assert!(unpack50(&[], 10, 0, &mut b).is_err());
        assert!(unpack50(&[], 10, 3, &mut b).is_err()); // not power of two
    }

    #[test]
    fn truncated_no_panic() {
        let mut b = Budget::new(Limits::default());
        let junk = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        for n in 0..junk.len() {
            let _ = unpack50(&junk[..n], 100, 0x20000, &mut b);
        }
    }
}
