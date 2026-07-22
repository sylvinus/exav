//! LZX as WIM uses it.
//!
//! The compression is the LZX of a cabinet, but the framing is not, which is why
//! the `lzxd` crate behind `cab`/`chm` cannot be pointed at a WIM chunk:
//!
//! | | cabinet | WIM |
//! |---|---|---|
//! | block size field | flat 24 bits | 1 bit "size is 32768", else 16 bits |
//! | stream extent | one stream per folder, reset every N blocks | one independent stream per chunk |
//! | E8 preprocessing | announced by a header bit | always on, against a fixed nominal file size |
//!
//! Implemented from the public LZX specification (the same one the cabinet
//! format documents) plus the two WIM deltas above. Bits come from 16-bit
//! **little-endian** words, most significant bit first.
//!
//! Every decoded resource is checked against the SHA-1 the image records, so a
//! mistake here surfaces as a reported resource rather than as plausible bytes
//! that are not the file.

/// Symbols 0..255 are literals; the rest encode (length, offset-slot) pairs.
const NUM_CHARS: usize = 256;
/// A main symbol's low three bits are the length; 7 means "read the length tree".
const NUM_PRIMARY_LENS: usize = 7;
const LEN_SLOTS: usize = NUM_PRIMARY_LENS + 1;
/// The length tree covers matches longer than the primary lengths reach.
const LENGTH_SYMBOLS: usize = 249;
/// The pre-tree that codes the other trees' code lengths.
const PRETREE_SYMBOLS: usize = 20;
const ALIGNED_SYMBOLS: usize = 8;
const MIN_MATCH: usize = 2;
/// No Huffman code in LZX is longer than this.
const MAX_CODE_LEN: u32 = 16;

/// Block types.
const BLOCK_VERBATIM: u32 = 1;
const BLOCK_ALIGNED: u32 = 2;
const BLOCK_UNCOMPRESSED: u32 = 3;

/// WIM applies E8 call translation against this nominal file size rather than
/// the real one, so the value is part of the format.
const E8_FILE_SIZE: i64 = 12_000_000;

/// Bits, taken from 16-bit little-endian words most significant bit first.
struct Bits<'a> {
    data: &'a [u8],
    /// Next byte to load; always even while reading bits.
    pos: usize,
    buf: u32,
    n: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Bits<'a> {
        Bits {
            data,
            pos: 0,
            buf: 0,
            n: 0,
        }
    }

    fn fill(&mut self, want: u32) -> Option<()> {
        while self.n < want {
            // Reading past the end is how a truncated chunk ends; the caller
            // notices because the output comes up short.
            let w = self.data.get(self.pos..self.pos + 2)?;
            self.pos += 2;
            self.buf = (self.buf << 16) | u16::from_le_bytes([w[0], w[1]]) as u32;
            self.n += 16;
        }
        Some(())
    }

    fn read(&mut self, k: u32) -> Option<u32> {
        if k == 0 {
            return Some(0);
        }
        self.fill(k)?;
        self.n -= k;
        let v = (self.buf >> self.n) & ((1u32 << k) - 1);
        self.buf &= (1u32 << self.n) - 1;
        Some(v)
    }

    fn peek(&mut self, k: u32) -> Option<u32> {
        self.fill(k)?;
        Some((self.buf >> (self.n - k)) & ((1u32 << k) - 1))
    }

    fn skip(&mut self, k: u32) {
        self.n -= k;
        self.buf &= (1u32 << self.n) - 1;
    }

    /// Drop any buffered bits and resume at the next 16-bit word. Used by
    /// uncompressed blocks, which carry byte-aligned data.
    fn align(&mut self) {
        self.buf = 0;
        self.n = 0;
    }
}

/// A canonical Huffman decoder held as code lengths, walked bit by bit. Slower
/// than a lookup table and with no table-construction edge cases to get wrong.
struct Huffman {
    first_code: [u32; MAX_CODE_LEN as usize + 1],
    first_index: [u32; MAX_CODE_LEN as usize + 1],
    count: [u32; MAX_CODE_LEN as usize + 1],
    sorted: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Option<Huffman> {
        let mut count = [0u32; MAX_CODE_LEN as usize + 1];
        for &l in lengths {
            if l as u32 > MAX_CODE_LEN {
                return None;
            }
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut first_code = [0u32; MAX_CODE_LEN as usize + 1];
        let mut first_index = [0u32; MAX_CODE_LEN as usize + 1];
        let (mut code, mut index) = (0u32, 0u32);
        for len in 1..=MAX_CODE_LEN as usize {
            code = (code + count[len - 1]) << 1;
            first_code[len] = code;
            first_index[len] = index;
            index += count[len];
        }
        let mut sorted = vec![0u16; index as usize];
        let mut next = first_index;
        for (sym, &l) in lengths.iter().enumerate() {
            if l == 0 {
                continue;
            }
            sorted[next[l as usize] as usize] = sym as u16;
            next[l as usize] += 1;
        }
        Some(Huffman {
            first_code,
            first_index,
            count,
            sorted,
        })
    }

    fn decode(&self, bits: &mut Bits) -> Option<u16> {
        for len in 1..=MAX_CODE_LEN {
            // The top `len` bits of the lookahead are the candidate code.
            let code = bits.peek(len)?;
            let n = self.count[len as usize];
            if n > 0 && code >= self.first_code[len as usize] {
                let idx = code - self.first_code[len as usize];
                if idx < n {
                    let sym = *self
                        .sorted
                        .get((self.first_index[len as usize] + idx) as usize)?;
                    bits.skip(len);
                    return Some(sym);
                }
            }
        }
        None
    }
}

/// The offset each position slot starts at, and how many extra bits follow it.
struct Slots {
    base: Vec<u32>,
    extra: Vec<u32>,
}

impl Slots {
    fn new(window_size: u32) -> Slots {
        let mut base = Vec::with_capacity(66);
        let mut extra = Vec::with_capacity(66);
        let mut b = 0u32;
        for s in 0..66usize {
            // Slots 0..3 address the first four offsets directly; after that each
            // pair of slots doubles the range it covers, capped at 17 extra bits.
            let e = if s < 4 {
                0
            } else {
                ((s as u32 >> 1) - 1).min(17)
            };
            base.push(b);
            extra.push(e);
            b = b.saturating_add(1u32 << e);
        }
        // The slot count is set by the window: the first slot whose base reaches
        // the window size is one past the last usable one.
        let n = base
            .iter()
            .position(|&x| x >= window_size)
            .unwrap_or(base.len() - 1);
        base.truncate(n);
        extra.truncate(n);
        Slots { base, extra }
    }
}

/// Code lengths for the three trees, carried across the blocks of one chunk:
/// each block's lengths are deltas against the block before it.
struct Trees {
    main: Vec<u8>,
    length: Vec<u8>,
    aligned: [u8; ALIGNED_SYMBOLS],
}

/// Read one tree's code lengths, which are delta-coded against `lens` and
/// compressed with a 20-symbol pre-tree.
fn read_lengths(bits: &mut Bits, lens: &mut [u8], first: usize, last: usize) -> Option<()> {
    let mut pre = [0u8; PRETREE_SYMBOLS];
    for p in pre.iter_mut() {
        *p = bits.read(4)? as u8;
    }
    let pretree = Huffman::new(&pre)?;

    let mut i = first;
    while i < last {
        let sym = pretree.decode(bits)?;
        match sym {
            // A run of "unchanged", i.e. zero-length, codes.
            17 => {
                let n = bits.read(4)? as usize + 4;
                for _ in 0..n {
                    *lens.get_mut(i)? = 0;
                    i += 1;
                    if i >= last {
                        break;
                    }
                }
            }
            18 => {
                let n = bits.read(5)? as usize + 20;
                for _ in 0..n {
                    *lens.get_mut(i)? = 0;
                    i += 1;
                    if i >= last {
                        break;
                    }
                }
            }
            // A run of one repeated delta.
            19 => {
                let n = bits.read(1)? as usize + 4;
                let d = pretree.decode(bits)?;
                if d > 16 {
                    return None;
                }
                let v = ((*lens.get(i)? as i32 - d as i32 + 17) % 17) as u8;
                for _ in 0..n {
                    *lens.get_mut(i)? = v;
                    i += 1;
                    if i >= last {
                        break;
                    }
                }
            }
            0..=16 => {
                let v = ((*lens.get(i)? as i32 - sym as i32 + 17) % 17) as u8;
                *lens.get_mut(i)? = v;
                i += 1;
            }
            _ => return None,
        }
    }
    Some(())
}

/// Undo WIM's E8 call translation: absolute call targets are rewritten back to
/// the relative form the instruction encoding uses.
fn undo_e8(out: &mut [u8]) {
    if out.len() <= 10 {
        return;
    }
    let end = out.len() - 10;
    let mut i = 0usize;
    while i < end {
        if out[i] != 0xE8 {
            i += 1;
            continue;
        }
        let target = i32::from_le_bytes([out[i + 1], out[i + 2], out[i + 3], out[i + 4]]) as i64;
        if target >= -(i as i64) && target < E8_FILE_SIZE {
            let rel = if target >= 0 {
                target - i as i64
            } else {
                target + E8_FILE_SIZE
            };
            out[i + 1..i + 5].copy_from_slice(&(rel as i32).to_le_bytes());
        }
        i += 5;
    }
}

/// Decompress one WIM LZX chunk into exactly `out_len` bytes.
pub(super) fn decompress(data: &[u8], out_len: usize) -> Option<Vec<u8>> {
    // Each chunk is its own stream over a window the size of the chunk.
    let window = out_len.next_power_of_two().max(1 << 15) as u32;
    let slots = Slots::new(window);
    let main_symbols = NUM_CHARS + slots.base.len() * LEN_SLOTS;

    let mut trees = Trees {
        main: vec![0u8; main_symbols],
        length: vec![0u8; LENGTH_SYMBOLS],
        aligned: [0u8; ALIGNED_SYMBOLS],
    };
    let mut bits = Bits::new(data);
    let mut out: Vec<u8> = Vec::with_capacity(out_len);
    // The three most recent match offsets, which slots 0..2 name directly.
    let mut r = [1u32, 1, 1];

    while out.len() < out_len {
        let block_type = bits.read(3)?;
        // The WIM delta: one bit saying the block is the default 32768 bytes,
        // otherwise a 16-bit size. A cabinet writes a flat 24-bit size here.
        let block_size = if bits.read(1)? == 1 {
            32768usize
        } else {
            bits.read(16)? as usize
        };
        let want = block_size.min(out_len - out.len());

        match block_type {
            BLOCK_UNCOMPRESSED => {
                bits.align();
                // The three recent offsets are restated in full, then the raw
                // bytes follow.
                let mut p = bits.pos;
                for slot in r.iter_mut() {
                    let v = data.get(p..p + 4)?;
                    *slot = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
                    p += 4;
                }
                let body = data.get(p..p + want)?;
                out.extend_from_slice(body);
                p += want;
                // Blocks are padded to an even length.
                bits.pos = p + (p & 1);
            }
            BLOCK_VERBATIM | BLOCK_ALIGNED => {
                if block_type == BLOCK_ALIGNED {
                    for a in trees.aligned.iter_mut() {
                        *a = bits.read(3)? as u8;
                    }
                }
                // The main tree is read in two halves: the literals, then the
                // match symbols.
                read_lengths(&mut bits, &mut trees.main, 0, NUM_CHARS)?;
                read_lengths(&mut bits, &mut trees.main, NUM_CHARS, main_symbols)?;
                read_lengths(&mut bits, &mut trees.length, 0, LENGTH_SYMBOLS)?;

                let main = Huffman::new(&trees.main)?;
                let length = Huffman::new(&trees.length)?;
                let aligned = if block_type == BLOCK_ALIGNED {
                    Some(Huffman::new(&trees.aligned)?)
                } else {
                    None
                };

                let target = out.len() + want;
                while out.len() < target {
                    let sym = main.decode(&mut bits)? as usize;
                    if sym < NUM_CHARS {
                        out.push(sym as u8);
                        continue;
                    }
                    let sym = sym - NUM_CHARS;
                    let len_header = sym % LEN_SLOTS;
                    let slot = sym / LEN_SLOTS;

                    let mut match_len = len_header;
                    if len_header == NUM_PRIMARY_LENS {
                        match_len = NUM_PRIMARY_LENS + length.decode(&mut bits)? as usize;
                    }
                    match_len += MIN_MATCH;

                    let offset = if slot < 3 {
                        // Slots 0..2 repeat a recent offset, promoting it.
                        let o = r[slot];
                        if slot != 0 {
                            r[slot] = r[0];
                            r[0] = o;
                        }
                        o
                    } else {
                        let extra = *slots.extra.get(slot)?;
                        let base = *slots.base.get(slot)?;
                        let low = match (&aligned, extra >= 3) {
                            // An aligned block splits the offset: the high bits
                            // are read raw, the low three come from their own
                            // tree.
                            (Some(a), true) => {
                                let hi = bits.read(extra - 3)? << 3;
                                hi | a.decode(&mut bits)? as u32
                            }
                            _ => bits.read(extra)?,
                        };
                        // Offsets 0..2 are spoken for by the repeat slots, so a
                        // real offset is biased by them.
                        let o = base.wrapping_add(low).wrapping_sub(2);
                        r[2] = r[1];
                        r[1] = r[0];
                        r[0] = o;
                        o
                    };

                    let offset = offset as usize;
                    if offset == 0 || offset > out.len() {
                        return None;
                    }
                    let take = match_len.min(out_len - out.len());
                    let start = out.len() - offset;
                    // Overlapping matches are legal, so copy byte by byte.
                    for k in 0..take {
                        let b = out[start + k];
                        out.push(b);
                    }
                }
            }
            _ => return None,
        }
        if want == 0 {
            return None; // no progress — malformed
        }
    }
    out.truncate(out_len);
    undo_e8(&mut out);
    Some(out)
}
