//! Ported from nwaples/rardecode (BSD-2-Clause).
//!
//! RAR3 (`unpack29`) decompressor: a from-scratch Rust port of the LZ/Huffman
//! decode core of nwaples/rardecode's `decode29.go`, `decode29_lz.go`,
//! `huffman.go`, `bit_reader.go`, `decode_reader.go`, `filters.go` and `vm.go`
//! (Copyright (c) 2015, Nicholas Waples, BSD-2-Clause). The upstream copyright
//! and full licence text live in the repo's top-level `NOTICE` file.
//!
//! Scope: non-encrypted RAR3 (unpack version 29) members, solid groups
//! included, compressed with LZ (RAR `-m1..-m5`) or PPMd blocks (decoded
//! through the vendored `ppmd7` model; see `read_ppmd_header`). The RAR3 filter
//! VM and the standard E8/E8E9/delta/itanium/RGB/audio filters are ported so
//! x86/audio/image-filtered streams decode correctly. The older unpack15/20/26
//! formats are not handled (rardecode does not support them either).
//! Everything is bounds-checked and never panics on malformed input.

use super::ppmd7::{
    PPMD7_MAX_MEM_SIZE, PPMD7_MAX_ORDER, PPMD7_MIN_MEM_SIZE, PPMD7_MIN_ORDER, Ppmd7, RangeDec,
    RarRangeDecoder, SYM_END,
};
use crate::{Budget, LimitHit};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Read;
use std::rc::Rc;

/// A stream that does not decode: damage.
fn err(reason: &str) -> LimitHit {
    LimitHit::corrupt(format!("rar3: {reason}"))
}

/// A stream that asks for more than the scan's budget allows.
fn over(reason: &str) -> LimitHit {
    LimitHit::new(format!("rar3: {reason}"))
}

// ---- streamed input ---------------------------------------------------------

/// Bytes the feed keeps ahead of the decoder. One decode step (a symbol, a
/// filter's data of at most 64 KiB, a block's tables, a PPMd symbol and its
/// escape) reads far less.
const LOOKAHEAD: usize = 128 * 1024;
/// Bytes kept behind the position, for the bits the bit reader gives back.
const KEEP_BEHIND: usize = 16;

/// A member's packed bytes as the streaming decoder reads them: a bounded
/// buffer topped up from the source between decode steps, shared by the bit
/// reader and the PPMd range decoder. Past the source's end it gives
/// [`MEMBER_PADDING`] zero bytes, as the whole-input path pads.
struct Feed {
    buf: Vec<u8>,
    pos: usize,
    ended: bool,
    /// A read went past the buffered bytes before the source ended: the
    /// lookahead was not enough, and the decode cannot be trusted.
    overrun: bool,
    /// [`MEMBER_PADDING`] follows the end of the source; not when the archive
    /// ends inside the member, whose bytes stop where the decode must.
    pad: bool,
}

impl Feed {
    fn new(pad: bool) -> Self {
        Feed {
            buf: Vec::new(),
            pos: 0,
            ended: false,
            overrun: false,
            pad,
        }
    }

    fn next(&mut self) -> Option<u8> {
        match self.buf.get(self.pos) {
            Some(&b) => {
                self.pos += 1;
                Some(b)
            }
            None => {
                if !self.ended {
                    self.overrun = true;
                }
                None
            }
        }
    }

    fn unread(&mut self, n: usize) {
        self.pos = self.pos.saturating_sub(n);
    }

    /// Read from `src` until [`LOOKAHEAD`] bytes are ahead or it ends.
    fn top_up(&mut self, src: &mut dyn Read) {
        if self.ended || self.buf.len() - self.pos >= LOOKAHEAD {
            return;
        }
        let drop = self.pos.saturating_sub(KEEP_BEHIND);
        self.buf.drain(..drop);
        self.pos -= drop;
        while self.buf.len() - self.pos < 2 * LOOKAHEAD {
            let at = self.buf.len();
            self.buf.resize(at + LOOKAHEAD, 0);
            let n = loop {
                match src.read(&mut self.buf[at..]) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    // The walk reports a source that failed.
                    Err(_) => break 0,
                }
            };
            self.buf.truncate(at + n);
            if n == 0 {
                self.ended = true;
                if self.pad {
                    self.buf.extend_from_slice(&[0u8; MEMBER_PADDING]);
                }
                return;
            }
        }
    }
}

/// RAR's range decoder (the arithmetic of [`RarRangeDecoder`]) reading a
/// [`Feed`] it shares with the bit reader.
struct FeedRangeDecoder {
    low: u32,
    code: u32,
    range: u32,
    bottom: u32,
    feed: Rc<RefCell<Feed>>,
    consumed: usize,
    out_of_data: bool,
    init_ok: bool,
}

impl FeedRangeDecoder {
    fn new(feed: Rc<RefCell<Feed>>) -> Self {
        let mut dec = FeedRangeDecoder {
            low: 0,
            code: 0,
            range: 0xFFFF_FFFF,
            bottom: 0x8000,
            feed,
            consumed: 0,
            out_of_data: false,
            init_ok: false,
        };
        let mut code = 0u32;
        for _ in 0..4 {
            code = (code << 8) | dec.read_byte();
        }
        dec.code = code;
        dec.init_ok = !dec.out_of_data && code != 0xFFFF_FFFF;
        dec
    }

    fn read_byte(&mut self) -> u32 {
        match self.feed.borrow_mut().next() {
            Some(b) => {
                self.consumed += 1;
                b as u32
            }
            None => {
                self.out_of_data = true;
                0
            }
        }
    }

    fn normalize(&mut self) {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= 1 << 24 {
                if self.range >= self.bottom {
                    break;
                }
                self.range = (0u32.wrapping_sub(self.low)) & (self.bottom - 1);
            }
            let b = self.read_byte();
            self.code = (self.code << 8) | b;
            self.range <<= 8;
            self.low <<= 8;
        }
    }
}

/// The range decoder of a PPMd block: over the member's bytes in memory, or
/// over the feed of a streamed member.
enum Rc3 {
    Mem(RarRangeDecoder),
    Feed(FeedRangeDecoder),
}

impl Rc3 {
    fn init_ok(&self) -> bool {
        match self {
            Rc3::Mem(r) => r.init_ok(),
            Rc3::Feed(r) => r.init_ok,
        }
    }
}

impl RangeDec for Rc3 {
    fn get_threshold(&mut self, total: u32) -> u32 {
        match self {
            Rc3::Mem(r) => r.get_threshold(total),
            Rc3::Feed(r) => {
                r.range /= total;
                (r.code.wrapping_sub(r.low)) / r.range
            }
        }
    }

    fn decode(&mut self, start: u32, size: u32) {
        match self {
            Rc3::Mem(r) => r.decode(start, size),
            Rc3::Feed(r) => {
                r.low = r.low.wrapping_add(start.wrapping_mul(r.range));
                r.range = r.range.wrapping_mul(size);
                r.normalize();
            }
        }
    }

    fn decode_bit(&mut self, size0: u32) -> u32 {
        match self {
            Rc3::Mem(r) => r.decode_bit(size0),
            Rc3::Feed(_) => {
                let scale = super::ppmd7::common::PPMD_BIN_SCALE;
                if self.get_threshold(scale) < size0 {
                    self.decode(0, size0);
                    0
                } else {
                    self.decode(size0, scale - size0);
                    1
                }
            }
        }
    }

    fn out_of_data(&self) -> bool {
        match self {
            Rc3::Mem(r) => r.out_of_data(),
            Rc3::Feed(r) => r.out_of_data,
        }
    }

    fn range(&self) -> u32 {
        match self {
            Rc3::Mem(r) => r.range(),
            Rc3::Feed(r) => r.range,
        }
    }

    fn bytes_consumed(&self) -> usize {
        match self {
            Rc3::Mem(r) => r.bytes_consumed(),
            Rc3::Feed(r) => r.consumed,
        }
    }
}

// ---- bit reader (bit_reader.go) -------------------------------------------

/// Big-endian (MSB-first) bit reader over an in-memory byte slice, matching
/// `rarBitReader`. Returns `None` on EOF (out of input).
struct BitReader {
    /// Owned rather than borrowed so the decoder can outlive any one member's
    /// packed data: a solid group hands the same decoder a fresh input stream
    /// per member while keeping its window and tables.
    data: Vec<u8>,
    /// For a streamed member, the input in place of `data`.
    feed: Option<Rc<RefCell<Feed>>>,
    pos: usize, // next byte index
    v: u64,     // accumulated bits
    n: u32,     // number of valid bits in v
}

impl BitReader {
    fn new(data: Vec<u8>) -> Self {
        BitReader {
            data,
            feed: None,
            pos: 0,
            v: 0,
            n: 0,
        }
    }

    fn with_feed(feed: Rc<RefCell<Feed>>) -> Self {
        BitReader {
            feed: Some(feed),
            ..BitReader::new(Vec::new())
        }
    }

    /// Give the whole bytes still buffered back to the feed, for the PPMd
    /// range decoder to read from the bit reader's byte position (call
    /// `align_byte` first).
    fn hand_back(&mut self) {
        if let Some(f) = &self.feed {
            f.borrow_mut().unread((self.n / 8) as usize);
        }
        self.v = 0;
        self.n = 0;
    }

    /// readBits: read n bits (n <= 32). Returns None if input is exhausted.
    fn read_bits(&mut self, n: u32) -> Option<u32> {
        while n > self.n {
            let c = match &self.feed {
                None => *self.data.get(self.pos)?,
                Some(f) => f.borrow_mut().next()?,
            };
            self.pos += 1;
            self.v = (self.v << 8) | c as u64;
            self.n += 8;
        }
        self.n -= n;
        Some(((self.v >> self.n) & ((1u64 << n) - 1)) as u32)
    }

    /// Whether every byte of the input has been read, so that a read that
    /// fails now fails for want of input.
    fn exhausted(&self) -> bool {
        match &self.feed {
            None => self.pos >= self.data.len(),
            Some(f) => {
                let f = f.borrow();
                f.ended && f.pos >= f.buf.len()
            }
        }
    }

    /// unreadBits: put back n bits.
    fn unread_bits(&mut self, n: u32) {
        self.n += n;
    }

    /// alignByte: drop bits down to the next byte boundary.
    fn align_byte(&mut self) {
        self.n -= self.n % 8;
    }

    /// readByte via the bit reader.
    fn read_byte(&mut self) -> Option<u8> {
        self.read_bits(8).map(|x| x as u8)
    }

    fn read_full(&mut self, p: &mut [u8]) -> Option<()> {
        for b in p.iter_mut() {
            *b = self.read_byte()?;
        }
        Some(())
    }

    /// Byte offset into `data` of the next unconsumed byte, assuming the reader
    /// is byte-aligned (call `align_byte` first). Buffered whole bytes still in
    /// `v` are counted as not-yet-consumed from `data`.
    fn byte_pos(&self) -> usize {
        self.pos - (self.n / 8) as usize
    }

    /// Reposition the reader to byte offset `off` in `data`, discarding any
    /// buffered bits. Used to resume after a PPMd block hands control back to
    /// the LZSS/block-header path at a byte boundary.
    fn seek_byte(&mut self, off: usize) {
        self.pos = off.min(self.data.len());
        self.v = 0;
        self.n = 0;
    }

    /// Reconstruct the byte stream from the current position onward, assuming
    /// the reader is byte-aligned (call `align_byte` first). The returned vector
    /// is any whole bytes still buffered in `v` (most-significant first)
    /// followed by the unread tail of `data`. Used to feed the PPMd range
    /// decoder, which consumes raw bytes (`ppmd_read`) from this same position.
    fn remaining_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut bits = self.n;
        // Buffered whole bytes, top to bottom.
        while bits >= 8 {
            bits -= 8;
            out.push(((self.v >> bits) & 0xff) as u8);
        }
        out.extend_from_slice(&self.data[self.pos.min(self.data.len())..]);
        out
    }

    /// readUint32: RAR V3 encoded uint32.
    fn read_uint32(&mut self) -> Option<u32> {
        let n = self.read_bits(2)?;
        if n != 1 {
            return self.read_bits(4u32 << n);
        }
        let n = self.read_bits(4)?;
        if n == 0 {
            let lo = self.read_bits(8)? as i32;
            let v = lo | (-1i32 << 8);
            return Some(v as u32);
        }
        let nlow = self.read_bits(4)?;
        Some((n << 4) | nlow)
    }
}

// ---- huffman decoder (huffman.go) -----------------------------------------

const MAX_CODE_LENGTH: u32 = 15;
const MAX_QUICK_BITS: u32 = 10;
const MAX_QUICK_SIZE: usize = 1 << MAX_QUICK_BITS;

struct HuffmanDecoder {
    limit: [i32; (MAX_CODE_LENGTH + 1) as usize],
    pos: [i32; (MAX_CODE_LENGTH + 1) as usize],
    symbol: Vec<i32>,
    min: u32,
    quickbits: u32,
    quicklen: [u32; MAX_QUICK_SIZE],
    quicksym: [i32; MAX_QUICK_SIZE],
}

impl HuffmanDecoder {
    fn new() -> Self {
        HuffmanDecoder {
            limit: [0; 16],
            pos: [0; 16],
            symbol: Vec::new(),
            min: 0,
            quickbits: 0,
            quicklen: [0; MAX_QUICK_SIZE],
            quicksym: [0; MAX_QUICK_SIZE],
        }
    }

    fn init(&mut self, code_lengths: &[u8]) {
        let mut count = [0i32; (MAX_CODE_LENGTH + 1) as usize];
        for &n in code_lengths {
            if n == 0 {
                continue;
            }
            if (n as usize) <= MAX_CODE_LENGTH as usize {
                count[n as usize] += 1;
            }
        }

        self.pos[0] = 0;
        self.limit[0] = 0;
        self.min = 0;
        for i in 1..=MAX_CODE_LENGTH as usize {
            self.limit[i] = self.limit[i - 1] + (count[i] << (MAX_CODE_LENGTH as usize - i));
            self.pos[i] = self.pos[i - 1] + count[i - 1];
            if self.min == 0 && self.limit[i] > 0 {
                self.min = i as u32;
            }
        }

        self.symbol.clear();
        self.symbol.resize(code_lengths.len(), 0);

        let mut c = self.pos;
        for (i, &n) in code_lengths.iter().enumerate() {
            if n != 0 && (n as usize) <= MAX_CODE_LENGTH as usize {
                let idx = c[n as usize] as usize;
                if idx < self.symbol.len() {
                    self.symbol[idx] = i as i32;
                }
                c[n as usize] += 1;
            }
        }

        self.quickbits = if code_lengths.len() >= 298 {
            MAX_QUICK_BITS
        } else {
            MAX_QUICK_BITS - 3
        };

        let mut bits: u32 = 1;
        for i in 0..(1usize << self.quickbits) {
            let v = (i as i32) << (MAX_CODE_LENGTH - self.quickbits);
            while v >= self.limit[bits as usize] && bits < MAX_CODE_LENGTH {
                bits += 1;
            }
            self.quicklen[i] = bits;

            let mut dist = v - self.limit[(bits - 1) as usize];
            dist >>= MAX_CODE_LENGTH - bits;
            let pos = self.pos[bits as usize] + dist;
            if pos >= 0 && (pos as usize) < self.symbol.len() {
                self.quicksym[i] = self.symbol[pos as usize];
            } else {
                self.quicksym[i] = 0;
            }
        }
    }

    /// readSym: decode one symbol. Returns None on decode failure / EOF.
    fn read_sym(&self, br: &mut BitReader) -> Option<i32> {
        let mut bits = MAX_CODE_LENGTH;
        let v = {
            let v = br.read_bits(MAX_CODE_LENGTH)?;
            v as i32
        };

        if v < self.limit[self.quickbits as usize] {
            let i = (v >> (MAX_CODE_LENGTH - self.quickbits)) as usize;
            br.unread_bits(MAX_CODE_LENGTH - self.quicklen[i]);
            return Some(self.quicksym[i]);
        }

        match ((self.min as usize)..=(MAX_CODE_LENGTH as usize)).find(|&i| v < self.limit[i]) {
            Some(i) => {
                bits = i as u32;
                br.unread_bits(MAX_CODE_LENGTH - bits);
            }
            // No limit matched; consume all 15 bits (bits stays at max).
            None => br.unread_bits(0),
        }

        let mut dist = v - self.limit[(bits - 1) as usize];
        dist >>= MAX_CODE_LENGTH - bits;
        let pos = self.pos[bits as usize] + dist;
        if pos < 0 || pos as usize >= self.symbol.len() {
            return None;
        }
        Some(self.symbol[pos as usize])
    }
}

/// readCodeLengthTable: read a new code-length table into `code_length`.
fn read_code_length_table(
    br: &mut BitReader,
    code_length: &mut [u8],
    add_old: bool,
) -> Result<(), LimitHit> {
    let mut bitlength = [0u8; 20];
    let mut i = 0usize;
    while i < bitlength.len() {
        let n = br.read_bits(4).ok_or_else(|| err("eof in bitlength"))?;
        if n == 0xf {
            let cnt = br.read_bits(4).ok_or_else(|| err("eof in bitlength"))? as usize;
            if cnt > 0 {
                // Skip cnt+2 entries (matches the Go for-loop's `i += cnt+1`
                // followed by the loop's own `i++`); they remain zero.
                i += cnt + 2;
                continue;
            }
        }
        if i < bitlength.len() {
            bitlength[i] = n as u8;
        }
        i += 1;
    }

    let mut bl = HuffmanDecoder::new();
    bl.init(&bitlength);

    let mut i = 0usize;
    let clen_len = code_length.len();
    let mut guard = 0u64;
    while i < clen_len {
        guard += 1;
        if guard > (clen_len as u64) * 4 + 1024 {
            return Err(err("code-length table runaway"));
        }
        let l = bl.read_sym(br).ok_or_else(|| err("bad code-length sym"))?;
        if l < 16 {
            if add_old {
                code_length[i] = (code_length[i].wrapping_add(l as u8)) & 0xf;
            } else {
                code_length[i] = l as u8;
            }
            i += 1;
            continue;
        }

        let mut count;
        let mut value = 0u8;
        if l == 16 || l == 18 {
            count = br.read_bits(3).ok_or_else(|| err("eof"))? as i32 + 3;
        } else {
            count = br.read_bits(7).ok_or_else(|| err("eof"))? as i32 + 11;
        }
        if l < 18 {
            if i == 0 {
                return Err(err("invalid length table"));
            }
            value = code_length[i - 1];
        }
        while count > 0 && i < clen_len {
            code_length[i] = value;
            i += 1;
            count -= 1;
        }
    }
    Ok(())
}

// ---- sliding window (decode_reader.go) ------------------------------------

const MIN_WINDOW_SIZE: usize = 0x40000;

struct Window {
    buf: Vec<u8>,
    mask: usize,
    r: usize, // read index
    w: usize, // write index
    l: usize, // pending copyBytes length
    o: usize, // pending copyBytes offset
    z: bool,  // pending copyBytes writes zeros
    /// Bytes decoded into the window since it was made.
    written: u64,
}

impl Window {
    fn new(log2size: u32) -> Self {
        let mut size = 1usize << log2size.min(30);
        if size < MIN_WINDOW_SIZE {
            size = MIN_WINDOW_SIZE;
        }
        Window {
            buf: vec![0u8; size],
            mask: size - 1,
            r: 0,
            w: 0,
            l: 0,
            o: 0,
            z: false,
            written: 0,
        }
    }

    fn buffered(&self) -> usize {
        (self.w.wrapping_sub(self.r)) & self.mask
    }

    fn available(&self) -> usize {
        (self.r.wrapping_sub(self.w).wrapping_sub(1)) & self.mask
    }

    fn write_byte(&mut self, c: u8) {
        self.buf[self.w] = c;
        self.w = (self.w + 1) & self.mask;
        self.written += 1;
    }

    fn copy_bytes(&mut self, len: usize, off: usize) {
        // A distance past the start of the stream: unrar writes the whole
        // match as zeros, the part past the start included.
        self.copy(len, off, off as u64 > self.written);
    }

    fn copy(&mut self, mut len: usize, off: usize, zeros: bool) {
        len &= self.mask;
        let n = self.available();
        if len > n {
            self.l = len - n;
            self.o = off;
            self.z = zeros;
            len = n;
        }
        self.written += len as u64;
        if zeros {
            while len > 0 {
                self.buf[self.w] = 0;
                self.w = (self.w + 1) & self.mask;
                len -= 1;
            }
            return;
        }
        let mut i = (self.w.wrapping_sub(off)) & self.mask;
        while len > 0 {
            self.buf[self.w] = self.buf[i];
            self.w = (self.w + 1) & self.mask;
            i = (i + 1) & self.mask;
            len -= 1;
        }
    }

    fn read(&mut self, p: &mut [u8]) -> usize {
        let mut n = 0usize;
        let mut p = p;
        if self.r > self.w {
            let take = (self.buf.len() - self.r).min(p.len());
            p[..take].copy_from_slice(&self.buf[self.r..self.r + take]);
            self.r = (self.r + take) & self.mask;
            n = take;
            p = &mut p[take..];
        }
        if self.r < self.w {
            let take = (self.w - self.r).min(p.len());
            p[..take].copy_from_slice(&self.buf[self.r..self.r + take]);
            self.r += take;
            n += take;
        }
        if self.l > 0 && n > 0 {
            let l = self.l;
            self.l = 0;
            self.copy(l, self.o, self.z);
        }
        n
    }
}

// ---- LZ decoder (decode29_lz.go) ------------------------------------------

const MAIN_SIZE: usize = 299;
const OFFSET_SIZE: usize = 60;
const LOW_OFFSET_SIZE: usize = 17;
const LENGTH_SIZE: usize = 28;
const TABLE_SIZE: usize = MAIN_SIZE + OFFSET_SIZE + LOW_OFFSET_SIZE + LENGTH_SIZE;

const LENGTH_BASE: [i32; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LENGTH_EXTRA_BITS: [u32; 28] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
const OFFSET_BASE: [i32; 60] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
    1048576, 1310720, 1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872,
    3670016, 3932160,
];
const OFFSET_EXTRA_BITS: [u32; 60] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18,
];
const SHORT_OFFSET_BASE: [i32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_OFFSET_EXTRA_BITS: [u32; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// Result of a single decode operation.
/// What the decoder found at the end of a block, from the two bits symbol 256
/// is followed by.
enum DecodeStep {
    Continue,
    Filter(Vec<u8>),
    /// A new block, with new tables, in the same member.
    EndOfBlock,
    /// The member ends here and the next one continues with the same tables.
    EndOfFile,
    /// The member ends here and the next one starts a block of its own. In a
    /// solid group this distinction decides whether the following member's data
    /// begins with a table, so getting it wrong decodes table bits as symbols.
    EndOfBlockAndFile,
}

struct Lz29 {
    code_length: [u8; TABLE_SIZE],
    main: HuffmanDecoder,
    offset_dec: HuffmanDecoder,
    low_offset_dec: HuffmanDecoder,
    length_dec: HuffmanDecoder,
    offset: [i32; 4],
    length: i32,
    low_offset: i32,
    low_offset_repeats: i32,
}

impl Lz29 {
    fn new() -> Self {
        Lz29 {
            code_length: [0; TABLE_SIZE],
            main: HuffmanDecoder::new(),
            offset_dec: HuffmanDecoder::new(),
            low_offset_dec: HuffmanDecoder::new(),
            length_dec: HuffmanDecoder::new(),
            offset: [0; 4],
            length: 0,
            low_offset: 0,
            low_offset_repeats: 0,
        }
    }

    fn reset(&mut self) {
        self.offset = [0; 4];
        self.length = 0;
        self.code_length = [0; TABLE_SIZE];
    }

    fn init(&mut self, br: &mut BitReader) -> Result<(), LimitHit> {
        self.low_offset = 0;
        self.low_offset_repeats = 0;

        let n = br.read_bits(1).ok_or_else(|| err("eof in lz init"))?;
        let add_old = n > 0;

        read_code_length_table(br, &mut self.code_length, add_old)?;

        self.main.init(&self.code_length[..MAIN_SIZE]);
        self.offset_dec
            .init(&self.code_length[MAIN_SIZE..MAIN_SIZE + OFFSET_SIZE]);
        self.low_offset_dec.init(
            &self.code_length[MAIN_SIZE + OFFSET_SIZE..MAIN_SIZE + OFFSET_SIZE + LOW_OFFSET_SIZE],
        );
        self.length_dec
            .init(&self.code_length[MAIN_SIZE + OFFSET_SIZE + LOW_OFFSET_SIZE..]);
        Ok(())
    }

    fn read_filter_data(&mut self, br: &mut BitReader) -> Result<Vec<u8>, LimitHit> {
        let flags = br.read_byte().ok_or_else(|| err("eof filter flags"))?;
        let mut n = (flags as i32 & 7) + 1;
        if n == 7 {
            n = br.read_bits(8).ok_or_else(|| err("eof"))? as i32 + 7;
        } else if n == 8 {
            n = br.read_bits(16).ok_or_else(|| err("eof"))? as i32;
        }
        // Rules of the format, which unrar refuses too: damage, not a limit.
        if !(0..=0x10000).contains(&n) {
            return Err(err("filter data too large"));
        }
        let mut buf = vec![0u8; n as usize + 1];
        buf[0] = flags;
        br.read_full(&mut buf[1..])
            .ok_or_else(|| err("eof filter data"))?;
        Ok(buf)
    }

    fn read_end_of_block(&mut self, br: &mut BitReader) -> Result<DecodeStep, LimitHit> {
        let n = br.read_bits(1).ok_or_else(|| err("eof eob"))?;
        if n > 0 {
            return Ok(DecodeStep::EndOfBlock);
        }
        let n = br.read_bits(1).ok_or_else(|| err("eof eob"))?;
        if n > 0 {
            return Ok(DecodeStep::EndOfBlockAndFile);
        }
        Ok(DecodeStep::EndOfFile)
    }

    fn decode(&mut self, win: &mut Window, br: &mut BitReader) -> Result<DecodeStep, LimitHit> {
        let sym = self.main.read_sym(br).ok_or_else(|| err("eof main sym"))?;

        if sym < 256 {
            win.write_byte(sym as u8);
            return Ok(DecodeStep::Continue);
        } else if sym == 256 {
            return self.read_end_of_block(br);
        } else if sym == 257 {
            return Ok(DecodeStep::Filter(self.read_filter_data(br)?));
        } else if sym == 258 {
            // use previous offset and length
        } else if sym < 263 {
            let i = (sym - 259) as usize;
            let offset = self.offset[i];
            // copy(d.offset[1:i+1], d.offset[:i])
            for k in (1..=i).rev() {
                self.offset[k] = self.offset[k - 1];
            }
            self.offset[0] = offset;

            let li = self.length_dec.read_sym(br).ok_or_else(|| err("eof len"))? as usize;
            if li >= 28 {
                return Err(err("len index oob"));
            }
            self.length = LENGTH_BASE[li] + 2;
            let bits = LENGTH_EXTRA_BITS[li];
            if bits > 0 {
                self.length += br.read_bits(bits).ok_or_else(|| err("eof"))? as i32;
            }
        } else if sym < 271 {
            let i = (sym - 263) as usize;
            // copy(d.offset[1:], d.offset[:])
            self.offset[3] = self.offset[2];
            self.offset[2] = self.offset[1];
            self.offset[1] = self.offset[0];
            let mut offset = SHORT_OFFSET_BASE[i] + 1;
            let bits = SHORT_OFFSET_EXTRA_BITS[i];
            if bits > 0 {
                offset += br.read_bits(bits).ok_or_else(|| err("eof"))? as i32;
            }
            self.offset[0] = offset;
            self.length = 2;
        } else {
            let i = (sym - 271) as usize;
            if i >= 28 {
                return Err(err("len index oob"));
            }
            self.length = LENGTH_BASE[i] + 3;
            let bits = LENGTH_EXTRA_BITS[i];
            if bits > 0 {
                self.length += br.read_bits(bits).ok_or_else(|| err("eof"))? as i32;
            }

            let oi = self.offset_dec.read_sym(br).ok_or_else(|| err("eof off"))? as usize;
            if oi >= 60 {
                return Err(err("off index oob"));
            }
            let mut offset = OFFSET_BASE[oi] + 1;
            let bits = OFFSET_EXTRA_BITS[oi];

            if bits >= 4 {
                if bits > 4 {
                    let n = br.read_bits(bits - 4).ok_or_else(|| err("eof"))? as i32;
                    offset += n << 4;
                }
                if self.low_offset_repeats > 0 {
                    self.low_offset_repeats -= 1;
                    offset += self.low_offset;
                } else {
                    let n = self
                        .low_offset_dec
                        .read_sym(br)
                        .ok_or_else(|| err("eof lowoff"))?;
                    if n == 16 {
                        self.low_offset_repeats = 15;
                        offset += self.low_offset;
                    } else {
                        offset += n;
                        self.low_offset = n;
                    }
                }
            } else if bits > 0 {
                offset += br.read_bits(bits).ok_or_else(|| err("eof"))? as i32;
            }

            if offset >= 0x2000 {
                self.length += 1;
                if offset >= 0x40000 {
                    self.length += 1;
                }
            }
            self.offset[3] = self.offset[2];
            self.offset[2] = self.offset[1];
            self.offset[1] = self.offset[0];
            self.offset[0] = offset;
        }

        if self.length < 0 || self.offset[0] <= 0 {
            return Err(err("invalid copy params"));
        }
        win.copy_bytes(self.length as usize, self.offset[0] as usize);
        Ok(DecodeStep::Continue)
    }
}

// ---- decoder29 (block header + filter parsing) ----------------------------

const MAX_CODE_SIZE: u32 = 0x10000;
const MAX_UNIQUE_FILTERS: u32 = 1024;
const VM_REGS: usize = 8;
const VM_GLOBAL_SIZE: u32 = 0x2000;
const VM_FIXED_GLOBAL_SIZE: u32 = 0x40;

/// A queued filter block (decode_reader.go `filterBlock`).
struct FilterBlock {
    length: usize,
    offset: usize, // relative to previous filter / read index
    reset: bool,
    filter_index: usize, // index into Decoder29.filters
    regs: [Option<u32>; VM_REGS - 1],
    global: Vec<u8>,
}

/// RAR3 PPMd block state. RAR3 PPMd is var.H (the same model as 7z), driven by
/// RAR's own range coder and framing (parsed in `read_ppmd_header`). The model
/// math is the vendored `Ppmd7`; the RAR-specific escape handling lives in the
/// PPMd decode loop in `unpack29`.
struct PpmdState {
    model: Ppmd7<Rc3>,
    /// Escape symbol: when a decoded byte equals this, the next symbol selects a
    /// control action (new table / EOD / match / literal).
    escape: u8,
    /// Offset into `packed` at which this PPMd block's byte stream began (the
    /// byte-aligned position right after the block's bit-level header). Adding
    /// the range decoder's `bytes_consumed()` yields the resume position for the
    /// next block on a PPMd→LZSS/new-table conversion.
    base_off: usize,
}

impl PpmdState {
    /// Absolute offset into `packed` consumed so far by this block's range
    /// decoder (= `base_off + range-decoder bytes consumed`).
    fn model_consumed(&self) -> usize {
        self.base_off + self.model.rc_bytes_consumed()
    }
}

struct Decoder29 {
    lz: Lz29,
    decode_is_ppm: bool,
    ppmd: Option<PpmdState>,
    /// Sub-allocator memory size in bytes, carried across PPMd blocks (only
    /// re-allocated when the 0x20 "reset" flag is set).
    ppmd_mem: u32,
    /// The most memory a PPMd block header may ask the model for: the
    /// archive's number, up to 256 MB, otherwise.
    ppmd_mem_limit: u64,
    /// The PPMd escape symbol: 2 until a block header sets another, then kept
    /// by the blocks after it that set none.
    ppmd_escape: u8,
    /// A PPMd block asked for more memory than `ppmd_mem_limit`.
    over_limit: bool,
    #[allow(dead_code)] // tracked during decode; not consumed by the caller
    eof: bool,
    fnum: usize,
    flen: Vec<i32>,
    filters: Vec<V3Filter>,
}

impl Decoder29 {
    fn new() -> Self {
        Decoder29 {
            lz: Lz29::new(),
            decode_is_ppm: false,
            ppmd: None,
            ppmd_mem: 0,
            ppmd_mem_limit: u64::MAX,
            ppmd_escape: 2,
            over_limit: false,
            eof: false,
            fnum: 0,
            flen: Vec::new(),
            filters: Vec::new(),
        }
    }

    fn init_filters(&mut self) {
        self.fnum = 0;
        self.flen.clear();
        self.filters.clear();
    }

    /// Perform one decode operation with the current decoder, writing into the
    /// sliding `win`. Dispatches to the PPMd path while a PPMd block is active.
    fn decode(&mut self, win: &mut Window, br: &mut BitReader) -> Result<DecodeStep, LimitHit> {
        if self.decode_is_ppm {
            return self.decode_ppmd_step(win, br);
        }
        self.lz.decode(win, br)
    }

    /// Decode a single RAR3 PPMd symbol into the sliding window. Mirrors the
    /// PPMd branch of libarchive's `read_data_compressed` (BSD-2-Clause), not
    /// UnRAR. Returns a `DecodeStep` so the surrounding `DecodeReader` flow
    /// (block headers, EOF) is shared with the LZSS path; this is what makes the
    /// RAR3 PPMd↔LZSS in-stream conversion work.
    fn decode_ppmd_step(
        &mut self,
        win: &mut Window,
        br: &mut BitReader,
    ) -> Result<DecodeStep, LimitHit> {
        let st = self.ppmd.as_mut().ok_or_else(|| err("no ppmd state"))?;
        let escape = st.escape;

        let sym = st.model.decode_symbol();
        if sym == SYM_END {
            return Ok(DecodeStep::EndOfFile);
        }
        if sym < 0 {
            return Err(err("ppmd bad symbol"));
        }

        if sym as u8 != escape {
            win.write_byte(sym as u8);
            return Ok(DecodeStep::Continue);
        }

        let code = st.model.decode_symbol();
        if code < 0 {
            return Err(err("ppmd bad escape symbol"));
        }
        match code {
            0 => {
                // New table / next block: resume the shared bit reader where the
                // PPMd range decoder left off and read the next block header.
                // A streamed member's range decoder read the shared feed, which
                // is already where it left off.
                if br.feed.is_some() {
                    br.hand_back();
                } else {
                    let resume = st.model_consumed();
                    br.seek_byte(resume);
                }
                self.read_block_header(br)?;
                Ok(DecodeStep::Continue)
            }
            2 => Ok(DecodeStep::EndOfFile), // End Of ppmd Data.
            3 => Err(err("ppmd filters unsupported")),
            4 => {
                let mut offset: usize = 0;
                for i in (0..3).rev() {
                    let b = st.model.decode_symbol();
                    if b < 0 {
                        return Err(err("ppmd eof in match offset"));
                    }
                    offset |= (b as usize) << (i * 8);
                }
                let length = st.model.decode_symbol();
                if length < 0 {
                    return Err(err("ppmd eof in match length"));
                }
                win.copy_bytes(length as usize + 32, offset + 2);
                Ok(DecodeStep::Continue)
            }
            5 => {
                let length = st.model.decode_symbol();
                if length < 0 {
                    return Err(err("ppmd eof in short length"));
                }
                win.copy_bytes(length as usize + 4, 1);
                Ok(DecodeStep::Continue)
            }
            _ => {
                // Any other secondary code: emit the escape byte as a literal.
                win.write_byte(sym as u8);
                Ok(DecodeStep::Continue)
            }
        }
    }

    /// Whether the PPMd block being decoded has read past its input.
    fn ppmd_out_of_data(&self) -> bool {
        self.decode_is_ppm && self.ppmd.as_ref().is_some_and(|st| st.model.out_of_data())
    }

    /// readBlockHeader: choose ppm or lz for the next block.
    fn read_block_header(&mut self, br: &mut BitReader) -> Result<(), LimitHit> {
        br.align_byte();
        let n = br.read_bits(1).ok_or_else(|| err("eof block header"))?;
        if n > 0 {
            self.decode_is_ppm = true;
            return self.read_ppmd_header(br);
        }
        self.decode_is_ppm = false;
        self.lz.init(br)
    }

    /// Parse the RAR3 PPMd block header and (re)initialise the var.H model + RAR
    /// range decoder. Framing mirrors libarchive's `parse_codes` PPMd branch
    /// (BSD-2-Clause), not UnRAR:
    ///
    /// * 7-bit `ppmd_flags`.
    /// * if `0x20`: 8-bit dictionary size, `mem = (n + 1) << 20` bytes, and the
    ///   model is (re)allocated/reset with `maxorder = (flags & 0x1F) + 1`
    ///   (orders > 16 are stretched: `16 + (order - 16) * 3`).
    /// * if `0x40`: 8-bit explicit escape symbol; else escape = 2.
    /// * otherwise (no `0x20`): solid continuation reusing the existing model —
    ///   only the range decoder is re-initialised.
    ///
    /// After the bit-level header the stream is byte-aligned; the RAR range
    /// decoder consumes the remaining member bytes from this position.
    fn read_ppmd_header(&mut self, br: &mut BitReader) -> Result<(), LimitHit> {
        let flags = br.read_bits(7).ok_or_else(|| err("eof ppmd flags"))?;
        let mut mem = self.ppmd_mem;
        if flags & 0x20 != 0 {
            let n = br.read_bits(8).ok_or_else(|| err("eof ppmd dict"))?;
            mem = (n + 1).saturating_mul(1 << 20);
            self.ppmd_mem = mem;
        }

        // The escape is kept from block to block until a header sets another.
        if flags & 0x40 != 0 {
            self.ppmd_escape = br.read_bits(8).ok_or_else(|| err("eof ppmd escape"))? as u8;
        }
        let escape = self.ppmd_escape;

        // The remaining member bytes feed the RAR range decoder (byte-aligned).
        br.align_byte();
        let base_off = br.byte_pos();
        let rc = match br.feed.clone() {
            Some(feed) => {
                br.hand_back();
                Rc3::Feed(FeedRangeDecoder::new(feed))
            }
            None => Rc3::Mem(RarRangeDecoder::new(br.remaining_bytes())),
        };
        if !rc.init_ok() {
            return Err(err("ppmd range init"));
        }

        if flags & 0x20 != 0 {
            // Reset: allocate a fresh model at the requested order/memory.
            let mut maxorder = (flags & 0x1F) + 1;
            if maxorder > 16 {
                maxorder = 16 + (maxorder - 16) * 3;
            }
            if !(PPMD7_MIN_ORDER..=PPMD7_MAX_ORDER).contains(&maxorder)
                || !(PPMD7_MIN_MEM_SIZE..=PPMD7_MAX_MEM_SIZE).contains(&mem)
            {
                return Err(err("invalid ppmd params"));
            }
            if u64::from(mem) > self.ppmd_mem_limit {
                self.over_limit = true;
                return Err(over("PPMd memory exceeds max-buffer"));
            }
            let model = Ppmd7::new(rc, maxorder, mem).ok_or_else(|| over("ppmd alloc"))?;
            self.ppmd = Some(PpmdState {
                model,
                escape,
                base_off,
            });
        } else {
            // Solid continuation: reuse the existing model (context tree / SEE /
            // suballocator) and only re-initialise the range decoder over the
            // new bytes, matching libarchive's `PpmdRAR_RangeDec_Init` call on a
            // continuation block. Requires a prior model.
            let st = self
                .ppmd
                .as_mut()
                .ok_or_else(|| err("ppmd continuation without model"))?;
            st.model.replace_rc(rc);
            st.escape = escape;
            st.base_off = base_off;
        }
        Ok(())
    }

    /// readVMCode: read the raw bytes for a vm filter's code/commands.
    fn read_vm_code(br: &mut BitReader) -> Result<Vec<u8>, LimitHit> {
        let n = br.read_uint32().ok_or_else(|| err("eof vmcode len"))?;
        if n > MAX_CODE_SIZE || n == 0 {
            return Err(err("invalid filter code size"));
        }
        let mut buf = vec![0u8; n as usize];
        br.read_full(&mut buf).ok_or_else(|| err("eof vmcode"))?;
        let mut x = 0u8;
        for &c in &buf[1..] {
            x ^= c;
        }
        if x != buf[0] {
            return Err(err("filter code checksum"));
        }
        Ok(buf)
    }

    /// parseVMFilter: parse a filter descriptor (the bytes from a 257 symbol).
    fn parse_vm_filter(&mut self, buf: &[u8]) -> Result<FilterBlock, LimitHit> {
        if buf.is_empty() {
            return Err(err("empty filter"));
        }
        let flags = buf[0];
        let mut br = BitReader::new(buf[1..].to_vec());
        let mut fb = FilterBlock {
            length: 0,
            offset: 0,
            reset: false,
            filter_index: 0,
            regs: [None; VM_REGS - 1],
            global: Vec::new(),
        };

        if flags & 0x80 > 0 {
            let n = br.read_uint32().ok_or_else(|| err("eof filt num"))?;
            if n == 0 {
                self.init_filters();
                fb.reset = true;
            } else {
                let n = n - 1;
                if n > MAX_UNIQUE_FILTERS {
                    return Err(err("too many unique filters"));
                }
                if n as usize > self.filters.len() {
                    return Err(err("filter index oob"));
                }
                self.fnum = n as usize;
            }
            if fb.reset {
                self.fnum = 0;
            }
        }

        // filter offset
        let mut n = br.read_uint32().ok_or_else(|| err("eof filt off"))?;
        if flags & 0x40 > 0 {
            n = n.wrapping_add(258);
        }
        fb.offset = n as usize;

        // filter length
        if self.fnum == self.flen.len() {
            self.flen.push(0);
        }
        if flags & 0x20 > 0 {
            let n = br.read_uint32().ok_or_else(|| err("eof filt len"))?;
            if self.fnum < self.flen.len() {
                self.flen[self.fnum] = n as i32;
            }
        }
        fb.length = *self.flen.get(self.fnum).unwrap_or(&0) as usize;

        // initial register values
        if flags & 0x10 > 0 {
            let mut bits = br
                .read_bits(VM_REGS as u32 - 1)
                .ok_or_else(|| err("eof regs"))?;
            for r in fb.regs.iter_mut() {
                if bits & 1 > 0 {
                    *r = Some(br.read_uint32().ok_or_else(|| err("eof reg val"))?);
                }
                bits >>= 1;
            }
        }

        // new filter: read its code
        if self.fnum == self.filters.len() {
            let code = Self::read_vm_code(&mut br)?;
            let f = get_v3_filter(&code)?;
            self.filters.push(f);
            self.flen.push(fb.length as i32);
        }
        if self.fnum >= self.filters.len() {
            return Err(err("filter index missing"));
        }
        fb.filter_index = self.fnum;

        // global data
        if flags & 0x08 > 0 {
            let n = br.read_uint32().ok_or_else(|| err("eof global len"))?;
            if n > VM_GLOBAL_SIZE - VM_FIXED_GLOBAL_SIZE {
                return Err(err("global too large"));
            }
            let mut g = vec![0u8; n as usize];
            br.read_full(&mut g).ok_or_else(|| err("eof global"))?;
            fb.global = g;
        }

        Ok(fb)
    }
}

// ---- top-level decode + filter pipeline (decode_reader.go) ----------------

const MAX_QUEUED_FILTERS: usize = 8192;

/// The most bytes a standard filter transforms together: an Itanium bundle
/// (an x86 address is 4). The last of a block cut by the end of the archive
/// may need bytes past it.
const FILTER_UNIT: usize = 16;

/// The streaming decode reader, ported from `decodeReader`.
struct DecodeReader {
    win: Window,
    dec: Decoder29,
    br: BitReader,
    tot: i64,
    outbuf: Vec<u8>,
    outbuf_pos: usize,
    eof: bool,
    /// Whether the current block's tables are still in force. Cleared when a
    /// member ends on `EndOfBlockAndFile`, so the next member of a solid group
    /// reads its own block header.
    tables_read: bool,
    err: Option<LimitHit>,
    /// The archive ends inside the member being decoded.
    cut: bool,
    /// It ended there, short of its size: what is missing is absent.
    cut_short: bool,
    // queued filterBlocks; offsets relative to previous filter in list.
    filters: VecDeque<QueuedFilter>,
}

/// A queued filter ready to run: resolved filter + captured regs/global.
struct QueuedFilter {
    length: usize,
    offset: usize,
    filter_index: usize,
    regs: [Option<u32>; VM_REGS - 1],
    global: Vec<u8>,
}

impl DecodeReader {
    fn queue_filter(&mut self, mut f: FilterBlock) -> Result<(), LimitHit> {
        if f.reset {
            self.filters.clear();
        }
        if self.filters.len() >= MAX_QUEUED_FILTERS {
            return Err(err("too many filters"));
        }
        for fb in &self.filters {
            if f.offset < fb.offset {
                return Err(err("filter before previous"));
            }
            f.offset -= fb.offset;
        }
        f.offset &= self.win.mask;
        f.length &= self.win.mask;
        self.filters.push_back(QueuedFilter {
            length: f.length,
            offset: f.offset,
            filter_index: f.filter_index,
            regs: f.regs,
            global: f.global,
        });
        Ok(())
    }

    /// A decode step failed with `e`. When the archive ends inside the member
    /// and every byte of it was read, it failed for want of the bytes the end
    /// took: the member ends here.
    fn fail(&mut self, e: LimitHit) {
        let exhausted = self.br.exhausted() || self.dec.ppmd_out_of_data();
        if self.cut && e.is_corrupt() && exhausted {
            self.eof = true;
            self.cut_short = true;
        } else {
            self.err = Some(e);
        }
    }

    /// Read the block header a member starts with, an error of it taken as
    /// [`Self::fail`] takes one.
    fn block_header(&mut self) -> Result<(), LimitHit> {
        if let Err(e) = self.dec.read_block_header(&mut self.br) {
            self.fail(e);
            if let Some(e) = self.err.take() {
                return Err(e);
            }
        }
        self.tables_read = true;
        Ok(())
    }

    /// fill: decode into the window, queueing any filters produced. A
    /// streamed member's feed is topped up from `src` before each step.
    fn fill(&mut self, src: &mut dyn Read) {
        if self.err.is_some() || self.eof {
            return;
        }
        let mut produced: Vec<FilterBlock> = Vec::new();
        let feed = self.br.feed.clone();
        while self.win.available() > 0 {
            if let Some(f) = &feed {
                f.borrow_mut().top_up(src);
            }
            let step = self.dec.decode(&mut self.win, &mut self.br);
            match step {
                Ok(DecodeStep::Continue) => continue,
                Ok(DecodeStep::Filter(buf)) => {
                    match self.dec.parse_vm_filter(&buf) {
                        Ok(mut fb) => {
                            fb.offset += self.win.buffered();
                            produced.push(fb);
                        }
                        Err(e) => {
                            self.fail(e);
                            break;
                        }
                    }
                    continue;
                }
                Ok(DecodeStep::EndOfBlock) => {
                    if let Err(e) = self.dec.read_block_header(&mut self.br) {
                        self.fail(e);
                        break;
                    }
                    continue;
                }
                Ok(DecodeStep::EndOfFile) => {
                    self.eof = true;
                    // PPMd's model ends a stream its input ran out of, before
                    // any symbol made of bytes that are not there.
                    self.cut_short = self.cut && self.dec.ppmd_out_of_data();
                    // PPMd's end of data ends its block as well as the file:
                    // the next member of a solid group starts with a header.
                    if self.dec.decode_is_ppm {
                        self.tables_read = false;
                    }
                    break;
                }
                Ok(DecodeStep::EndOfBlockAndFile) => {
                    self.eof = true;
                    self.tables_read = false;
                    break;
                }
                Err(e) => {
                    self.fail(e);
                    break;
                }
            }
        }
        if feed.is_some_and(|f| f.borrow().overrun) {
            self.err = Some(err("a decode step read past the input lookahead"));
            return;
        }
        for fb in produced {
            if let Err(e) = self.queue_filter(fb) {
                self.err = Some(e);
                return;
            }
        }
    }

    /// processFilters: run filters valid at the current read index into outbuf.
    fn process_filters(&mut self) -> Result<(), LimitHit> {
        // peek first
        let first_off = self.filters.front().map(|f| f.offset).unwrap_or(1);
        if first_off > 0 {
            return Ok(());
        }
        let mut f = self.filters.pop_front().unwrap();
        // The archive ends inside the block: the filters are causal, so the
        // bytes present filter to the start of what the block would, but for
        // the unit the end cuts.
        let cut_block = self.win.buffered() < f.length && self.cut_short && self.err.is_none();
        if cut_block {
            f.length = self.win.buffered();
        } else if self.win.buffered() < f.length {
            // fill() didn't return enough bytes.
            return match self.err.take() {
                Some(e) => Err(e),
                None => Err(err("invalid filter (short)")),
            };
        }
        let mut outbuf = vec![0u8; f.length];
        let n = self.win.read(&mut outbuf);
        outbuf.truncate(n);

        let mut cur = f;
        loop {
            // A new block's header clears the filter definitions, so a queued
            // filter can name one that is gone.
            let Some(filter) = self.dec.filters.get(cur.filter_index) else {
                return Err(err("filter no longer defined"));
            };
            outbuf = run_filter(filter, &cur.regs, &cur.global, outbuf, self.tot)?;
            match self.filters.front() {
                None => break,
                Some(nf) => {
                    if nf.offset != 0 {
                        // adjust next filter offset by bytes consumed
                        let off = nf.offset.saturating_sub(n);
                        self.filters.front_mut().unwrap().offset = off;
                        break;
                    }
                    if nf.length != outbuf.len() {
                        return Err(err("filter length mismatch"));
                    }
                }
            }
            cur = self.filters.pop_front().unwrap();
        }
        if cut_block {
            outbuf.truncate(outbuf.len().saturating_sub(FILTER_UNIT));
        }
        self.outbuf = outbuf;
        self.outbuf_pos = 0;
        Ok(())
    }

    /// Read decoded/filtered bytes into p; returns bytes written (0 at EOF).
    fn read(&mut self, p: &mut [u8], src: &mut dyn Read) -> Result<usize, LimitHit> {
        if self.outbuf_pos >= self.outbuf.len() {
            self.outbuf.clear();
            self.outbuf_pos = 0;
            if self.win.buffered() == 0 {
                self.fill(src);
                if self.win.buffered() == 0 {
                    return match self.err.take() {
                        Some(e) => Err(e),
                        None => Ok(0),
                    };
                }
            } else if let Some(f) = self.filters.front()
                && f.offset == 0
                && f.length > self.win.buffered()
            {
                self.fill(src);
            }
            if !self.filters.is_empty() {
                self.process_filters()?;
            }
        }

        let n;
        if self.outbuf_pos < self.outbuf.len() {
            let avail = &self.outbuf[self.outbuf_pos..];
            n = avail.len().min(p.len());
            p[..n].copy_from_slice(&avail[..n]);
            self.outbuf_pos += n;
        } else if let Some(f) = self.filters.front() {
            // read directly from window, up to start of next filter
            let limit = f.offset.min(p.len());
            n = self.win.read(&mut p[..limit]);
            self.filters.front_mut().unwrap().offset = f.offset.saturating_sub(n);
        } else {
            n = self.win.read(p);
        }
        self.tot += n as i64;
        Ok(n)
    }
}

// ---- entry point ----------------------------------------------------------

/// A RAR3 (unpack version 29) decoder that can be reused across the members of
/// a **solid** group.
///
/// In a solid archive the files are compressed as one continuous LZ stream:
/// each member has its own byte range of packed data and its own restarted bit
/// reader, but the sliding window, the Huffman tables and the PPMd model carry
/// over from the previous member. Decoding a solid member on a fresh window
/// therefore does not fail — it produces plausible-looking wrong bytes, which
/// is why every member's output is checked against the CRC the archive records.
pub struct Unpacker29 {
    /// Boxed: the tables and the PPMd model are about 50 KiB, and the walk
    /// that holds this decoder across the visitor must not carry them in its
    /// stack frame.
    dr: Box<DecodeReader>,
    /// Bytes the streamed member declares that are not out yet.
    left: u64,
}

impl Unpacker29 {
    /// `win_bits` is the window log2 size from the file header (typically
    /// 16..23). All members of a solid group share the window, so it is sized
    /// once, from the first member.
    ///
    /// Not inlined: the decoder is built in this call's frame, which a caller
    /// that recurses into the visitor must not inherit.
    #[inline(never)]
    pub fn new(win_bits: u32, budget: &mut Budget) -> Result<Self, LimitHit> {
        // The LZ sliding window is a whole-buffer allocation (RAR3 permits up to
        // a 1 GiB dictionary). Bound it by the global peak-buffer limit so it
        // can't dominate peak memory; a legitimate archive needing a larger
        // window is reported rather than silently OOMing (operators raise
        // --max-object-bytes).
        let win_bytes = 1u64 << win_bits.min(30);
        if win_bytes > budget.limits.max_buffer_bytes {
            return Err(over("RAR window exceeds max-buffer"));
        }
        let mut dec = Decoder29::new();
        dec.ppmd_mem_limit = budget.limits.max_buffer_bytes;
        dec.init_filters();
        dec.lz.reset();
        Ok(Unpacker29 {
            dr: Box::new(DecodeReader {
                win: Window::new(win_bits),
                dec,
                br: BitReader::new(Vec::new()),
                tot: 0,
                outbuf: Vec::new(),
                outbuf_pos: 0,
                eof: false,
                tables_read: false,
                err: None,
                cut: false,
                cut_short: false,
                filters: VecDeque::new(),
            }),
            left: 0,
        })
    }

    /// Say whether the archive ends inside the next member, before
    /// [`Self::member`] or [`Self::start_member`]: a decode that runs out of
    /// its bytes then ends the member short, the missing tail absent, as the
    /// RAR5 decoder ends one, instead of failing it.
    pub fn cut_by_archive_end(&mut self, cut: bool) {
        self.dr.cut = cut;
    }

    /// Decode one member, to its end-of-file code: the bytes it holds past
    /// its declared size too, and as far as it goes when it ends before. Past its declared size, a stream that fails ends there.
    /// `solid` says the member continues the previous one's stream, in which
    /// case the window and tables are kept. A declared size, or output, over
    /// what the budget has left is a limit.
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
        // Pad the input with a few zero bytes: RAR's LZSS/PPMd encoders don't
        // pad the bitstream, so decoding the final symbols of the last block can
        // require reading a bit or two past the packed data. A whole stream
        // reaches its end-of-file code before the zeros are read as symbols.
        // Mirrors the RAR5 unpacker's input padding. Not for a member the
        // archive ends inside: its decode stops where its bytes do.
        let mut padded = Vec::with_capacity(packed.len() + MEMBER_PADDING);
        padded.extend_from_slice(packed);
        if !self.dr.cut {
            padded.extend_from_slice(&[0u8; MEMBER_PADDING]);
        }
        self.dr.br = BitReader::new(padded);
        self.dr.eof = false;
        self.dr.err = None;
        self.dr.cut_short = false;
        // The x86 and Itanium filters convert addresses relative to the start
        // of the member, solid or not; counting from an earlier member's start
        // corrupted every executable after the first decoded member.
        self.dr.tot = 0;
        if !solid {
            // Filters never span the members of a solid group, so they are reset
            // either way.
            self.dr.filters.clear();
            self.dr.dec.init_filters();
        }
        // A non-solid member starts its own block; a solid one resumes the block
        // its predecessor was in the middle of, and reading a header here would
        // consume symbols as if they were table data.
        if !solid || !self.dr.tables_read {
            self.dr.block_header()?;
        }

        let mut out: Vec<u8> = Vec::with_capacity(unpacked_size.min(1 << 20) as usize);
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = match self.dr.read(&mut buf, &mut std::io::empty()) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.is_corrupt() && out.len() as u64 >= unpacked_size => break,
                Err(e) => return Err(e),
            };
            if out.len() as u64 + n as u64 > cap {
                return Err(over("output exceeds budget"));
            }
            out.extend_from_slice(&buf[..n]);
        }
        budget.commit(out.len() as u64);
        Ok(out)
    }

    /// Whether a PPMd block asked for a model over the buffer limit.
    pub fn over_limit(&self) -> bool {
        self.dr.dec.over_limit
    }

    /// Start a member whose packed bytes `src` gives as they are needed, to
    /// be read with [`Self::read_member`]: the streaming form of
    /// [`Self::member`], holding the window and a bounded lookahead of input.
    pub fn start_member(
        &mut self,
        unpacked_size: u64,
        solid: bool,
        src: &mut dyn Read,
    ) -> Result<(), LimitHit> {
        let feed = Rc::new(RefCell::new(Feed::new(!self.dr.cut)));
        feed.borrow_mut().top_up(src);
        self.dr.br = BitReader::with_feed(Rc::clone(&feed));
        self.dr.eof = false;
        self.dr.err = None;
        self.dr.cut_short = false;
        self.dr.tot = 0;
        self.left = unpacked_size;
        if !solid {
            self.dr.filters.clear();
            self.dr.dec.init_filters();
        }
        if !solid || !self.dr.tables_read {
            self.dr.block_header()?;
        }
        if feed.borrow().overrun {
            return Err(err("a block header read past the input lookahead"));
        }
        Ok(())
    }

    /// The next decoded bytes of the member [`Self::start_member`] started, 0
    /// at its end-of-file code, as [`Self::member`] reads it. What reads it
    /// bounds its output.
    pub fn read_member(&mut self, buf: &mut [u8], src: &mut dyn Read) -> Result<usize, LimitHit> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.dr.read(buf, src) {
            Ok(n) => {
                self.left = self.left.saturating_sub(n as u64);
                Ok(n)
            }
            Err(e) if e.is_corrupt() && self.left == 0 => {
                self.dr.eof = true;
                Ok(0)
            }
            Err(e) => Err(e),
        }
    }
}

/// Decompress a single, non-solid RAR3 member on a fresh window.
pub fn unpack29(
    packed: &[u8],
    unpacked_size: u64,
    win_bits: u32,
    budget: &mut Budget,
) -> Result<Vec<u8>, LimitHit> {
    Unpacker29::new(win_bits, budget)?.member(packed, unpacked_size, false, budget)
}

// ---- RAR3 filters (filters.go) --------------------------------------------

const FILE_SIZE: i64 = 0x1000000;

/// Zero bytes after a member's packed data: the encoders do not pad the
/// bitstream, so its last symbols can read a little past it.
const MEMBER_PADDING: usize = 16;
const VM_GLOBAL_ADDR: usize = 0x3C000;
const VM_SIZE: usize = 0x40000;
const VM_MASK: u32 = (VM_SIZE - 1) as u32;

/// A resolved RAR3 V3 filter: either a known standard filter or a VM program.
enum V3Filter {
    E8,
    E8E9,
    Itanium,
    Delta,
    Rgb,
    Audio,
    // RAR3 custom VM-bytecode filters are parsed but not yet executed
    // (deferred); the standard filters above are applied.
    #[allow(dead_code)]
    Vm(Box<VmFilter>),
}

/// crc of the code byte slice -> standard filter id.
fn standard_filter(code: &[u8]) -> Option<V3Filter> {
    let c = crc32_ieee(code);
    let l = code.len();
    match (c, l) {
        (0xad57_6887, 53) => Some(V3Filter::E8),
        (0x3cd7_e57e, 57) => Some(V3Filter::E8E9),
        (0x3769_893f, 120) => Some(V3Filter::Itanium),
        (0x0e06_077d, 29) => Some(V3Filter::Delta),
        (0x1c2c_5dc8, 149) => Some(V3Filter::Rgb),
        (0xbc85_e701, 216) => Some(V3Filter::Audio),
        _ => None,
    }
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// getV3Filter: resolve a code byte slice to a filter (standard or VM).
fn get_v3_filter(code: &[u8]) -> Result<V3Filter, LimitHit> {
    if let Some(f) = standard_filter(code) {
        return Ok(f);
    }
    if code.is_empty() {
        return Err(err("empty filter code"));
    }
    // Build a VM filter from the program.
    let mut r = BitReader::new(code[1..].to_vec()); // skip xor check byte
    let mut vf = VmFilter {
        exec_count: 0,
        global: Vec::new(),
        static_data: Vec::new(),
        code: Vec::new(),
    };
    let n = r.read_bits(1).ok_or_else(|| err("eof vm static"))?;
    if n > 0 {
        let m = r.read_uint32().ok_or_else(|| err("eof vm static len"))?;
        let len = (m as usize)
            .checked_add(1)
            .ok_or_else(|| err("static ovf"))?;
        if len > VM_SIZE {
            return Err(err("static too large"));
        }
        let mut s = vec![0u8; len];
        r.read_full(&mut s)
            .ok_or_else(|| err("eof vm static data"))?;
        vf.static_data = s;
    }
    // readCommands: returns whatever it parses; io.EOF is a normal terminator.
    vf.code = read_commands(&mut r)?;
    Ok(V3Filter::Vm(Box::new(vf)))
}

/// run_filter: apply a V3 filter to `buf`, returning transformed bytes.
fn run_filter(
    f: &V3Filter,
    regs: &[Option<u32>; VM_REGS - 1],
    _global: &[u8],
    buf: Vec<u8>,
    offset: i64,
) -> Result<Vec<u8>, LimitHit> {
    let r0 = regs.first().copied().flatten().unwrap_or(0);
    let r1 = regs.get(1).copied().flatten().unwrap_or(0);
    match f {
        V3Filter::E8 => Ok(filter_e8(0xe8, buf, offset)),
        V3Filter::E8E9 => Ok(filter_e8(0xe9, buf, offset)),
        V3Filter::Delta => Ok(filter_delta(r0 as usize, &buf)),
        V3Filter::Itanium => Ok(filter_itanium(buf, offset)),
        V3Filter::Rgb => Ok(filter_rgb(r0, r1, &buf)),
        V3Filter::Audio => Ok(filter_audio(r0 as usize, &buf)),
        V3Filter::Vm(_) => Err(err("vm filter not supported")),
    }
}

#[inline]
fn read_u32le(b: &[u8], at: usize) -> u32 {
    let g = |k: usize| *b.get(at + k).unwrap_or(&0) as u32;
    g(0) | (g(1) << 8) | (g(2) << 16) | (g(3) << 24)
}
#[inline]
fn write_u32le(b: &mut [u8], at: usize, v: u32) {
    if at + 4 <= b.len() {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// filterE8 (x86 E8/E8E9 call-address conversion), RAR3 variant (v5=false).
fn filter_e8(c: u8, mut buf: Vec<u8>, offset: i64) -> Vec<u8> {
    let mut off = offset as i32;
    let mut i = 0usize;
    // Process while at least 5 bytes remain from index i.
    while buf.len() >= 5 && i <= buf.len() - 5 {
        let ch = buf[i];
        off = off.wrapping_add(1);
        i += 1;
        if ch != 0xe8 && ch != c {
            continue;
        }
        let addr = read_u32le(&buf, i) as i32;
        if addr < 0 {
            if addr.wrapping_add(off) >= 0 {
                write_u32le(&mut buf, i, (addr as i64 + FILE_SIZE) as u32);
            }
        } else if (addr as i64) < FILE_SIZE {
            write_u32le(&mut buf, i, addr.wrapping_sub(off) as u32);
        }
        off = off.wrapping_add(4);
        i += 4;
    }
    buf
}

/// filterDelta: byte-deinterleave delta filter (n channels). Output is a new
/// buffer of the same length.
fn filter_delta(n: usize, buf: &[u8]) -> Vec<u8> {
    let l = buf.len();
    let mut res = vec![0u8; l];
    if n == 0 {
        return res;
    }
    let mut i = 0usize;
    // A channel past the data has no byte, and `n` is the archive's 32-bit
    // register.
    for j in 0..n.min(l) {
        let mut c = 0u8;
        let mut k = j;
        while k < l {
            c = c.wrapping_sub(buf[i]);
            i += 1;
            res[k] = c;
            k = k.saturating_add(n);
        }
    }
    res
}

fn get_bits(buf: &[u8], pos: usize, count: u32) -> u32 {
    let n = read_u32le(buf, pos / 8);
    let n = n >> (pos & 7);
    let mask = u32::MAX >> (32 - count);
    n & mask
}
fn set_bits(buf: &mut [u8], pos: usize, count: u32, bits: u32) {
    let mut mask = u32::MAX >> (32 - count);
    mask <<= pos & 7;
    let bits = bits << (pos & 7);
    let mut n = read_u32le(buf, pos / 8);
    n = (n & !mask) | (bits & mask);
    write_u32le(buf, pos / 8, n);
}

const ITANIUM_BYTE_MASK: [u32; 16] = [4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];

fn filter_itanium(mut buf: Vec<u8>, offset: i64) -> Vec<u8> {
    let mut file_offset = (offset as u32) >> 4;
    let mut b = 0usize;
    while buf.len() > b + 21 {
        let c = (buf[b] & 0x1f) as i32 - 0x10;
        if c >= 0 {
            let mask = ITANIUM_BYTE_MASK[c as usize];
            if mask != 0 {
                for ii in 0u32..=2 {
                    if mask & (1 << ii) == 0 {
                        continue;
                    }
                    let pos = (ii * 41 + 18) as usize;
                    if get_bits(&buf[b..], pos + 24, 4) == 5 {
                        let mut n = get_bits(&buf[b..], pos, 20);
                        n = n.wrapping_sub(file_offset);
                        let slice = &mut buf[b..];
                        set_bits(slice, pos, 20, n);
                    }
                }
            }
        }
        file_offset = file_offset.wrapping_add(1);
        b += 16;
    }
    buf
}

fn abs_i(n: i32) -> i32 {
    if n < 0 { -n } else { n }
}

fn filter_rgb(r0: u32, r1: u32, buf: &[u8]) -> Vec<u8> {
    let Some(width) = (r0 as i32).checked_sub(3) else {
        return buf.to_vec();
    };
    let pos_r = r1 as i32;
    let l = buf.len();
    let mut res = vec![0u8; l];
    if pos_r < 0 || width < 0 {
        return buf.to_vec();
    }
    let width = width as usize;
    let mut src = 0usize;
    for c in 0..3usize {
        let mut prev_byte = 0i32;
        let mut i = c;
        while i < l {
            let predicted = if i >= width && i - width >= 3 {
                let upper_pos = i - width;
                let upper_byte = res[upper_pos] as i32;
                let upper_left_byte = res[upper_pos - 3] as i32;
                let mut p = prev_byte + upper_byte - upper_left_byte;
                let pa = abs_i(p - prev_byte);
                let pb = abs_i(p - upper_byte);
                let pc = abs_i(p - upper_left_byte);
                if pa <= pb && pa <= pc {
                    p = prev_byte;
                } else if pb <= pc {
                    p = upper_byte;
                } else {
                    p = upper_left_byte;
                }
                p
            } else {
                prev_byte
            };
            let cur = *buf.get(src).unwrap_or(&0) as i32;
            src += 1;
            prev_byte = (predicted - cur) & 0xFF;
            res[i] = prev_byte as u8;
            i += 3;
        }
    }
    let mut i = pos_r as usize;
    while l >= 2 && i < l - 2 {
        let c = res[i + 1];
        res[i] = res[i].wrapping_add(c);
        res[i + 2] = res[i + 2].wrapping_add(c);
        i += 3;
    }
    res
}

fn filter_audio(chans: usize, buf: &[u8]) -> Vec<u8> {
    let l = buf.len();
    let mut res = vec![0u8; l];
    if chans == 0 {
        return res;
    }
    let mut src = 0usize;
    for c in 0..chans.min(l) {
        let mut prev_byte = 0i32;
        let mut byte_count = 0i32;
        let mut diff = [0i32; 7];
        let mut d = [0i32; 3];
        let mut k = [0i32; 3];
        let mut i = c;
        while i < l {
            let mut predicted = (prev_byte << 3) + k[0] * d[0] + k[1] * d[1] + k[2] * d[2];
            predicted = (predicted >> 3) as i8 as i32;

            let cur_byte = *buf.get(src).unwrap_or(&0) as i8 as i32;
            src += 1;
            predicted -= cur_byte;
            res[i] = predicted as u8;

            let dd = cur_byte << 3;
            diff[0] += abs_i(dd);
            diff[1] += abs_i(dd - d[0]);
            diff[2] += abs_i(dd + d[0]);
            diff[3] += abs_i(dd - d[1]);
            diff[4] += abs_i(dd + d[1]);
            diff[5] += abs_i(dd - d[2]);
            diff[6] += abs_i(dd + d[2]);

            let prev_delta = (predicted - prev_byte) as i8 as i32;
            prev_byte = predicted;
            d[2] = d[1];
            d[1] = prev_delta - d[0];
            d[0] = prev_delta;

            if byte_count & 0x1f == 0 {
                let mut min = diff[0];
                diff[0] = 0;
                let mut n = 0i32;
                for (j, dval) in diff.iter_mut().enumerate().skip(1) {
                    if *dval < min {
                        min = *dval;
                        n = j as i32;
                    }
                    *dval = 0;
                }
                n -= 1;
                if n >= 0 {
                    let m = (n / 2) as usize;
                    if n % 2 == 0 {
                        if k[m] >= -16 {
                            k[m] -= 1;
                        }
                    } else if k[m] < 16 {
                        k[m] += 1;
                    }
                }
            }
            byte_count += 1;
            i = i.saturating_add(chans);
        }
    }
    res
}

// ---- RAR3 VM (vm.go) ------------------------------------------------------
//
// The VM is ported so VM-based (non-standard) filters can be recognised, but
// executing arbitrary VM programs is intentionally NOT performed (a VM filter
// makes the whole member undecodable here). The command parser is retained so
// `get_v3_filter` consumes the program bytes correctly even for the standard
// filters (which never reach the VM path) and so the structure mirrors the
// upstream; full VM execution is out of scope and such members fall back to
// metadata-only.

#[allow(dead_code)] // populated by the parser; the RAR3 filter VM isn't run yet
struct VmFilter {
    exec_count: u32,
    global: Vec<u8>,
    static_data: Vec<u8>,
    code: Vec<Command>,
}

#[derive(Clone)]
struct Command {
    _op: u8,
    _bm: bool,
    _nops: usize,
}

const VM_OP_TABLE_LEN: u32 = 40;

/// readCommands: parse the VM program, consuming all bytes. Operand bytes are
/// parsed only enough to advance the bit reader; we do not execute.
fn read_commands(br: &mut BitReader) -> Result<Vec<Command>, LimitHit> {
    let mut cmds = Vec::new();
    let mut guard = 0u64;
    loop {
        guard += 1;
        if guard > 1_000_000 {
            return Err(err("vm program too long"));
        }
        let mut code = match br.read_bits(4) {
            Some(c) => c,
            None => return Ok(cmds), // EOF terminates
        };
        if code & 0x08 > 0 {
            let n = match br.read_bits(2) {
                Some(n) => n,
                None => return Ok(cmds),
            };
            code = ((code << 2) | n).wrapping_sub(24);
        }
        if code >= VM_OP_TABLE_LEN {
            return Err(err("invalid vm instruction"));
        }
        let (byte_mode, nops, jop) = vm_op_info(code);
        let mut bm = false;
        if byte_mode {
            match br.read_bits(1) {
                Some(n) => bm = n > 0,
                None => return Ok(cmds),
            }
        }
        if nops > 0 {
            if decode_arg(br, bm).is_none() {
                return Ok(cmds);
            }
            if nops == 2 {
                if decode_arg(br, bm).is_none() {
                    return Ok(cmds);
                }
            } else if jop {
                // fixJumpOp uses an immediate; nothing to consume beyond arg.
            }
        }
        cmds.push(Command {
            _op: code as u8,
            _bm: bm,
            _nops: nops,
        });
    }
}

/// (supports_byte_mode, num_operands, is_jump) for VM opcode `code`.
fn vm_op_info(code: u32) -> (bool, usize, bool) {
    // Mirror of the `ops` table in vm.go.
    const T: [(bool, usize, bool); 40] = [
        (true, 2, false),  // mov
        (true, 2, false),  // cmp
        (true, 2, false),  // add
        (true, 2, false),  // sub
        (false, 1, true),  // jz
        (false, 1, true),  // jnz
        (true, 1, false),  // inc
        (true, 1, false),  // dec
        (false, 1, true),  // jmp
        (true, 2, false),  // xor
        (true, 2, false),  // and
        (true, 2, false),  // or
        (true, 2, false),  // test
        (false, 1, true),  // js
        (false, 1, true),  // jns
        (false, 1, true),  // jb
        (false, 1, true),  // jbe
        (false, 1, true),  // ja
        (false, 1, true),  // jae
        (false, 1, false), // push
        (false, 1, false), // pop
        (false, 1, true),  // call
        (false, 0, false), // ret
        (true, 1, false),  // not
        (true, 2, false),  // shl
        (true, 2, false),  // shr
        (true, 2, false),  // sar
        (true, 1, false),  // neg
        (false, 0, false), // pusha
        (false, 0, false), // popa
        (false, 0, false), // pushf
        (false, 0, false), // popf
        (false, 2, false), // movzx
        (false, 2, false), // movsx
        (true, 2, false),  // xchg
        (true, 2, false),  // mul
        (true, 2, false),  // div
        (true, 2, false),  // adc
        (true, 2, false),  // sbb
        (false, 0, false), // print
    ];
    T[code as usize]
}

/// decodeArg: consume the bits of a VM operand. Returns Some(()) on success.
fn decode_arg(br: &mut BitReader, byte_mode: bool) -> Option<()> {
    let n = br.read_bits(1)?;
    if n > 0 {
        br.read_bits(3)?; // register
        return Some(());
    }
    let n = br.read_bits(1)?;
    if n == 0 {
        // immediate
        if byte_mode {
            br.read_bits(8)?;
        } else {
            br.read_uint32()?;
        }
        return Some(());
    }
    let n = br.read_bits(1)?;
    if n == 0 {
        br.read_bits(3)?; // register indirect
        return Some(());
    }
    let n = br.read_bits(1)?;
    if n == 0 {
        br.read_bits(3)?; // base + index
        br.read_uint32()?;
        return Some(());
    }
    br.read_uint32()?; // direct
    Some(())
}

#[allow(dead_code)]
const VM_GLOBAL_ADDR_USE: usize = VM_GLOBAL_ADDR; // keep constants referenced
#[allow(dead_code)]
const VM_MASK_USE: u32 = VM_MASK;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;

    /// A stream that does not decode is damage; a member that declares more
    /// than the scan's budget allows, or a window past the buffer limit, is a
    /// limit.
    #[test]
    fn a_stream_that_does_not_decode_is_damage_and_a_huge_member_is_a_limit() {
        let mut budget = Budget::new(Limits::default());
        let e = unpack29(&[0xff; 4], 1000, 20, &mut budget).expect_err("not a stream");
        assert!(e.is_corrupt(), "{}", e.reason);
        let mut budget = Budget::new(Limits {
            max_extracted_bytes: 10,
            ..Limits::default()
        });
        let e = unpack29(&[0; 8], 1000, 20, &mut budget).expect_err("over the budget");
        assert!(!e.is_corrupt(), "{}", e.reason);
        let mut budget = Budget::new(Limits {
            max_buffer_bytes: 1 << 10,
            ..Limits::default()
        });
        let e = unpack29(&[0; 8], 10, 20, &mut budget).expect_err("window over the buffer limit");
        assert!(!e.is_corrupt(), "{}", e.reason);
    }

    /// The filter's registers come from the archive: one that is `i32::MIN`
    /// after the subtraction of 3 leaves the data as it was, not a panic.
    /// The channel count is a 32-bit register of the archive's: one far past
    /// the data is not four billion passes over it.
    #[test]
    fn delta_and_audio_filters_with_a_register_of_billions_finish_at_once() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let start = std::time::Instant::now();
        assert_eq!(filter_delta(u32::MAX as usize, &data).len(), data.len());
        assert_eq!(filter_audio(u32::MAX as usize, &data).len(), data.len());
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    /// A PPMd block header asks for the model's memory (up to 256 MB, the
    /// archive's number): over the budget's buffer limit it is refused before
    /// the allocation.
    #[test]
    fn a_ppmd_header_asking_for_more_than_the_buffer_limit_is_refused() {
        // 7 bits of flags (reset, order 6), 8 bits of size (16 MB), then bytes
        // for the range decoder.
        let mut bytes = vec![0b0100_1010, 0b0001_1110];
        bytes.extend_from_slice(&[0u8; 64]);
        let mut dec = Decoder29::new();
        dec.ppmd_mem_limit = 1 << 20;
        let e = dec
            .read_ppmd_header(&mut BitReader::new(bytes.clone()))
            .unwrap_err();
        assert!(e.reason.contains("exceeds max-buffer"), "{}", e.reason);
        // Within the limit it gets as far as the model.
        dec.ppmd_mem_limit = 64 << 20;
        let r = dec.read_ppmd_header(&mut BitReader::new(bytes));
        assert!(
            r.as_ref()
                .err()
                .is_none_or(|e| !e.reason.contains("exceeds max-buffer")),
            "{:?}",
            r.err().map(|e| e.reason)
        );
    }

    /// A queued filter whose definition a later block header cleared is an
    /// error, not an index past the list.
    #[test]
    fn a_queued_filter_without_a_definition_is_an_error() {
        let mut b = Budget::new(Limits::default());
        let mut u = Unpacker29::new(16, &mut b).unwrap();
        u.dr.filters.push_back(QueuedFilter {
            length: 0,
            offset: 0,
            filter_index: 3,
            regs: [None; VM_REGS - 1],
            global: Vec::new(),
        });
        assert!(u.dr.process_filters().is_err());
    }

    #[test]
    fn an_rgb_filter_with_a_register_at_the_bottom_of_i32_changes_nothing() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        for r0 in [0x8000_0000u32, 0x8000_0001, 0x8000_0002] {
            assert_eq!(filter_rgb(r0, 0, &data), data, "r0 {r0:#x}");
        }
    }

    #[test]
    fn truncated_no_panic() {
        let mut b = Budget::new(Limits::default());
        let junk: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        for n in 0..junk.len().min(300) {
            let _ = unpack29(&junk[..n], 4096, 20, &mut b);
        }
    }

    #[test]
    fn window_sizes_ok() {
        // A small window still allocates at least the minimum.
        let w = Window::new(10);
        assert!(w.buf.len() >= MIN_WINDOW_SIZE);
        let w = Window::new(22);
        assert_eq!(w.buf.len(), 1 << 22);
    }

    /// A match from before the start of the stream is all zeros, the bytes
    /// that would come from the start included, as unrar writes it.
    #[test]
    fn a_match_from_before_the_start_writes_zeros() {
        let mut w = Window::new(10);
        for &c in b"mjof " {
            w.write_byte(c);
        }
        w.copy_bytes(8, 5);
        w.copy_bytes(9, 15);
        let mut out = vec![0u8; 64];
        let n = w.read(&mut out);
        assert_eq!(&out[..n], b"mjof mjof mjo\0\0\0\0\0\0\0\0\0");
    }

    /// The part of such a match the window had no room for is zeros too,
    /// though the window holds that far back by then.
    #[test]
    fn the_rest_of_a_match_from_before_the_start_is_zeros() {
        let mut w = Window::new(18);
        let size = w.buf.len();
        for _ in 0..size - 4 {
            w.write_byte(b'a');
        }
        w.copy_bytes(9, size - 2);
        let mut out = vec![0u8; size];
        assert_eq!(w.read(&mut out), size - 1);
        assert_eq!(&out[size - 4..size - 1], [0; 3]);
        assert_eq!(w.read(&mut out), 6);
        assert_eq!(&out[..6], [0; 6]);
    }
}
