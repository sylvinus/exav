//! AZO — ESTsoft's own compression algorithm, used by EGG and ALZ.
//!
//! Ported from `EggDotNet` (MIT, see NOTICE), which is the only permissively
//! licensed implementation in existence. ESTsoft's own `UnEgg` library cannot be
//! used: its licence forbids commercial use without approval *and* forbids using
//! it to develop a compression algorithm.
//!
//! The shape is a binary range coder driving an LZ77 back-reference scheme:
//!
//! - **[`EntropyCode`]** — a range coder over a bit-level reader. Every decision
//!   below is a call into it with an adaptive probability.
//! - **[`BitProb`]** — a binary-tree probability model over an `n`-bit symbol:
//!   one context per prefix, so the high bits condition the low ones.
//! - **[`PredictProb`]** — *two* such models per context, one keyed on the full
//!   previous symbol and one on a shifted (coarser) version. A per-context
//!   `lucky` counter tracks which has been predicting better and reads from the
//!   winner while still updating the loser. This is the part that makes AZO more
//!   than an LZ77.
//! - **match / literal** — one bit chooses between them; matches come from a
//!   distance/length pair, each with a code table plus extra bits, and both a
//!   recent-distance history and a 128-entry dictionary of recent (position,
//!   length) pairs can supply a match directly.
//!
//! Verification is not against this code: every EGG block records a CRC-32 of
//! its decompressed bytes, written by ESTsoft's compressor, and the caller only
//! accepts a block whose output reproduces it.

use crate::formats::azo_tables as tbl;

/// `'1'` — the only AZO stream version there is.
const VERSION: u8 = 0x31;
/// A block whose compressed form saved less than this is stored verbatim.
const REDUCE_MIN: usize = 8;

const ALPHA_SIZE: u32 = 1 << 8;
const MATCH_LENGTH_CODE_SIZE: u32 = 1 << 7;
const MATCH_DIST_CODE_SIZE: u32 = 1 << 7;
const MATCH_MIN_LENGTH: u32 = 2;
const MATCH_MIN_DIST: u32 = 1;
const MATCH_DIST_SGAP: u32 = 16;
const MATCH_DIST_GAP: u32 = 4;
const DISTANCE_HISTORY_SIZE: u32 = 1 << 1;
const DICTIONARY_SIZE: u32 = 1 << 7;
const DICTIONARY_HISTORY_SIZE: u32 = 2;
const ALPHACODE_PREDICT_SHIFT: u32 = 5;
const LENGTHCODE_PREDICT_SHIFT: u32 = 4;
/// Context order for [`BoolState`]: the last 8 decisions select the slot.
const SCALE_N: u32 = 8;

/// `floor(log2(x))`, matching the reference's `log(x)/log(2)` truncation.
/// `x == 0` cannot occur at any call site (every argument is `n - 1` for
/// `n >= 2`, or a positive quotient), but it is defined rather than panicking.
fn log2(x: u32) -> u32 {
    if x == 0 {
        0
    } else {
        31 - x.leading_zeros()
    }
}

/// Reads individual bits, MSB-first within each byte.
struct BitCode<'a> {
    buf: &'a [u8],
    /// Total readable bits.
    bits: usize,
    idx: usize,
    remain: u32,
    read: usize,
}

impl<'a> BitCode<'a> {
    fn new(buf: &'a [u8]) -> Self {
        BitCode {
            buf,
            bits: buf.len() * 8,
            idx: 0,
            remain: 8,
            read: 0,
        }
    }

    /// One bit; `false` once the buffer is exhausted, which ends the block.
    fn bit(&mut self) -> bool {
        if self.read >= self.bits || self.idx >= self.buf.len() {
            return false;
        }
        self.read += 1;
        self.remain -= 1;
        let v = self.buf[self.idx] & (1u8 << self.remain) != 0;
        if self.remain == 0 {
            self.idx += 1;
            self.remain = 8;
        }
        v
    }

    /// `n` bits (n <= 8) as the low bits of a byte.
    fn bits_of(&mut self, mut n: u32) -> u8 {
        if self.bits < self.read + n as usize {
            return 0;
        }
        self.read += n as usize;
        let mut value: u8 = 0;
        if self.remain <= n {
            n -= self.remain;
            let b = self.buf.get(self.idx).copied().unwrap_or(0);
            self.idx += 1;
            value = (b & ((1u16 << self.remain) - 1) as u8) << n;
            self.remain = 8;
            while n >= 8 {
                n -= 8;
                let b = self.buf.get(self.idx).copied().unwrap_or(0);
                self.idx += 1;
                value |= b << n;
            }
        }
        if n != 0 {
            self.remain -= n;
            let b = self.buf.get(self.idx).copied().unwrap_or(0);
            value |= (b >> self.remain) & ((1u16 << n) - 1) as u8;
        }
        value
    }

    fn read_size(&self) -> usize {
        self.read
    }
}

/// Binary range coder. `low`/`up` bound the current interval and `tag` holds the
/// bits read from the stream; each decision narrows the interval and rescales.
struct EntropyCode<'a> {
    low: u32,
    up: u32,
    tag: u32,
    bit: BitCode<'a>,
}

const MSB: u32 = 1 << 31;
const SMSB: u32 = 1 << 30;

impl<'a> EntropyCode<'a> {
    fn new(buf: &'a [u8]) -> Self {
        EntropyCode {
            low: u32::MIN,
            up: u32::MAX,
            tag: 0,
            bit: BitCode::new(buf),
        }
    }

    /// Prime `tag` with the first 32 bits.
    fn initialize(&mut self) {
        for i in 0..4u32 {
            let b = self.bit.bits_of(8);
            self.tag |= (b as u32) << ((3 - i) * 8);
        }
    }

    fn rescale(&mut self) {
        // Interval fully inside one half: shift the shared top bit out.
        while (self.low & MSB) == (self.up & MSB) {
            let b = self.bit.bit();
            self.tag = (self.tag << 1) | b as u32;
            self.low <<= 1;
            self.up = (self.up << 1) | 1;
        }
        // Straddling the midpoint: shift out the second bit and flip the top.
        while (self.low & SMSB) != 0 && (self.up & SMSB) == 0 {
            let b = self.bit.bit();
            self.tag = (self.tag << 1) | b as u32;
            self.tag ^= MSB;
            self.low = (self.low << 1) & (MSB - 1);
            self.up = (self.up << 1) | 1 | MSB;
        }
    }

    /// Interval step for `total_bit` bits of precision.
    fn step(&self, total_bit: u32) -> u32 {
        if self.low == u32::MIN && self.up == u32::MAX {
            1u32 << (32 - total_bit)
        } else {
            (self.up.wrapping_sub(self.low).wrapping_add(1)) >> total_bit
        }
    }

    /// Decode `total_bit` raw bits (used for a match code's extra bits).
    fn code_raw(&mut self, total_bit: u32) -> u32 {
        if total_bit == 0 {
            // The reference still narrows the interval for a zero-bit read;
            // `step` would shift by 32, which is UB in Rust and a no-op in C#.
            // No extra-bit entry is 0 at a call site that reaches here, but
            // guarding keeps a malformed table from becoming a panic.
            return 0;
        }
        let t = self.step(total_bit);
        if t == 0 {
            return 0;
        }
        let v = (self.tag.wrapping_sub(self.low)) / t;
        self.up = self.low.wrapping_add(t.wrapping_mul(v + 1)).wrapping_sub(1);
        self.low = self.low.wrapping_add(t.wrapping_mul(v));
        self.rescale();
        v
    }

    /// Decode one bit against `cum_count` out of `1 << total_bit`.
    fn code_bit(&mut self, cum_count: u32, total_bit: u32) -> bool {
        let t = self.step(total_bit);
        if t == 0 {
            return false;
        }
        let v = (self.tag.wrapping_sub(self.low)) / t;
        if v >= cum_count {
            self.low = self.low.wrapping_add(t.wrapping_mul(cum_count));
        } else {
            self.up = self
                .low
                .wrapping_add(t.wrapping_mul(cum_count))
                .wrapping_sub(1);
        }
        self.rescale();
        v >= cum_count
    }

    /// Bytes consumed, rounded up — the block is only valid if this equals the
    /// declared compressed size.
    fn size(&self) -> usize {
        self.bit.read_size().div_ceil(8)
    }
}

/// One adaptive bit, contexted on the last `SCALE_N` decisions.
struct BoolState {
    prob: Vec<u32>,
    state: u32,
    mask: u32,
}

const BOOL_TOTAL_BIT: u32 = 12;
const BOOL_TOTAL: u32 = 1 << BOOL_TOTAL_BIT;

impl BoolState {
    fn new() -> Self {
        let n = 1u32 << SCALE_N;
        BoolState {
            prob: vec![BOOL_TOTAL / 2; n as usize],
            state: 0,
            mask: n - 1,
        }
    }

    fn code(&mut self, e: &mut EntropyCode) -> bool {
        let p = self.prob[self.state as usize];
        let b = e.code_bit(p, BOOL_TOTAL_BIT);
        let shift = BOOL_TOTAL_BIT - 6;
        let p = &mut self.prob[self.state as usize];
        if !b {
            *p += (BOOL_TOTAL - *p) >> shift;
        } else {
            *p -= *p >> shift;
        }
        self.state = ((self.state << 1) & self.mask) | b as u32;
        b
    }
}

/// A symbol of `bit_n` bits, decoded MSB-first with one probability per prefix.
struct BitProb {
    bit_n: i32,
    prob: Vec<u32>,
}

const BP_TOTAL_BIT: u32 = 10;
const BP_TOTAL: u32 = 1 << BP_TOTAL_BIT;

impl BitProb {
    fn new(n: u32) -> Self {
        let bit_n = log2(n - 1) as i32 + 1;
        BitProb {
            bit_n,
            prob: vec![BP_TOTAL / 2; 1usize << bit_n],
        }
    }

    fn code(&mut self, e: &mut EntropyCode) -> u32 {
        let mut value = 0u32;
        let mut pre = 1u32;
        for i in (0..self.bit_n).rev() {
            let p = self.prob[pre as usize];
            let v = e.code_bit(p, BP_TOTAL_BIT);
            if v {
                value |= 1u32 << i;
            }
            pre = (pre << 1) | v as u32;
        }
        self.update(value);
        value
    }

    fn update(&mut self, value: u32) {
        let mut pre = 1u32;
        for i in (0..self.bit_n).rev() {
            let v = (value >> i) & 1;
            let shift = BP_TOTAL_BIT - 6;
            let p = &mut self.prob[pre as usize];
            if v == 0 {
                *p += (BP_TOTAL - *p) >> shift;
            } else {
                *p -= *p >> shift;
            }
            pre = (pre << 1) | v;
        }
    }

    /// Which of the two models assigned `value` the higher probability.
    fn compare(&self, other: &BitProb, value: u32) -> i32 {
        let mut p1: u32 = 1;
        let mut p2: u32 = 1;
        let mut pre = 1u32;
        for i in (0..self.bit_n).rev() {
            let a = self.prob[pre as usize];
            let b = other.prob[pre as usize];
            let v = ((value >> i) & 1) > 0;
            // Renormalise before either product can overflow.
            let t = (p1 | p2) & (((1u32 << BP_TOTAL_BIT) - 1) << (32 - BP_TOTAL_BIT));
            if t != 0 {
                p1 >>= BP_TOTAL_BIT;
                p2 >>= BP_TOTAL_BIT;
            }
            p1 = p1.wrapping_mul(if v { BP_TOTAL - a } else { a });
            p2 = p2.wrapping_mul(if v { BP_TOTAL - b } else { b });
            pre = (pre << 1) | v as u32;
        }
        match p1.cmp(&p2) {
            std::cmp::Ordering::Greater => 1,
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
        }
    }
}

/// Two models per context — fine-grained and coarse — with a running score
/// picking which to decode from. The loser is still updated, so it stays a
/// candidate.
struct PredictProb {
    shift: u32,
    prob1: Vec<BitProb>,
    prob2: Vec<BitProb>,
    lucky: Vec<i32>,
}

impl PredictProb {
    fn new(key: u32, n: u32, shift: u32) -> Self {
        PredictProb {
            shift,
            prob1: (0..key).map(|_| BitProb::new(n)).collect(),
            prob2: (0..(key >> shift)).map(|_| BitProb::new(n)).collect(),
            lucky: vec![0; key as usize],
        }
    }

    fn code(&mut self, e: &mut EntropyCode, pre: u32) -> u32 {
        let i1 = pre as usize;
        let i2 = (pre >> self.shift) as usize;
        if i1 >= self.prob1.len() || i2 >= self.prob2.len() {
            return 0;
        }
        let v = if self.lucky[i1] >= 0 {
            let v = self.prob1[i1].code(e);
            self.prob2[i2].update(v);
            v
        } else {
            let v = self.prob2[i2].code(e);
            self.prob1[i1].update(v);
            v
        };
        let r = self.prob1[i1].compare(&self.prob2[i2], v);
        self.lucky[i1] += r;
        v
    }
}

/// Most-recently-used list of values, any of which can be named directly.
struct HistoryList {
    rep: Vec<u32>,
    state: BoolState,
    prob: BitProb,
}

impl HistoryList {
    fn new(init: u32, n: u32) -> Self {
        HistoryList {
            rep: (0..n).map(|i| init + i).collect(),
            state: BoolState::new(),
            prob: BitProb::new(n),
        }
    }

    fn add(&mut self, value: u32) {
        self.rep.rotate_right(1);
        self.rep[0] = value;
    }

    /// Move-to-front from `del_idx`, leaving the tail beyond it untouched.
    fn add_at(&mut self, value: u32, del_idx: usize) {
        let end = (del_idx + 1).min(self.rep.len());
        self.rep[..end].rotate_right(1);
        self.rep[0] = value;
    }

    fn code(&mut self, e: &mut EntropyCode) -> Option<u32> {
        if !self.state.code(e) {
            return None;
        }
        let idx = self.prob.code(e) as usize;
        if idx >= self.rep.len() {
            return None;
        }
        let value = self.rep[idx];
        self.add_at(value, idx);
        Some(value)
    }
}

/// A history list backed by a full symbol model when the history misses.
struct SymbolCode {
    history: HistoryList,
    prob: BitProb,
}

impl SymbolCode {
    fn new(n: u32, history_n: u32) -> Self {
        SymbolCode {
            history: HistoryList::new(0, history_n),
            prob: BitProb::new(n),
        }
    }

    fn code(&mut self, e: &mut EntropyCode) -> u32 {
        if let Some(v) = self.history.code(e) {
            return v;
        }
        let v = self.prob.code(e);
        self.history.add(v);
        v
    }
}

/// The 128 most recent matches, addressable by index so a repeat costs one
/// symbol instead of a distance and a length.
struct DictionaryTable {
    pos: Vec<u32>,
    len: Vec<u32>,
    find_state: BoolState,
    prob: SymbolCode,
}

impl DictionaryTable {
    fn new() -> Self {
        let n = DICTIONARY_SIZE as usize;
        DictionaryTable {
            pos: vec![0; n],
            len: (0..n).map(|i| MATCH_MIN_LENGTH + i as u32).collect(),
            find_state: BoolState::new(),
            prob: SymbolCode::new(DICTIONARY_SIZE, DICTIONARY_HISTORY_SIZE),
        }
    }

    fn code(&mut self, e: &mut EntropyCode) -> Option<(u32, u32)> {
        if !self.find_state.code(e) {
            return None;
        }
        let n = self.prob.code(e) as usize;
        if n >= self.pos.len() {
            return None;
        }
        let (p, l) = (self.pos[n], self.len[n]);
        self.update_at(p, l, n);
        Some((p, l))
    }

    fn add(&mut self, pos: u32, len: u32) {
        self.pos.rotate_right(1);
        self.len.rotate_right(1);
        self.pos[0] = pos;
        self.len[0] = len;
    }

    fn update_at(&mut self, pos: u32, len: u32, del_idx: usize) {
        let end = (del_idx + 1).min(self.pos.len());
        self.pos[..end].rotate_right(1);
        self.len[..end].rotate_right(1);
        self.pos[0] = pos;
        self.len[0] = len;
    }
}

/// Map a distance to its table index, mirroring the encoder's bucketing.
fn match_dist_code(mut value: u32) -> u32 {
    value -= MATCH_MIN_DIST;
    if value < MATCH_DIST_SGAP {
        return value;
    }
    value -= MATCH_DIST_SGAP;
    let extra = log2(value / MATCH_DIST_GAP + 1);
    MATCH_DIST_SGAP
        + extra * MATCH_DIST_GAP
        + (value - ((1u32 << extra) - 1) * MATCH_DIST_GAP) / (1u32 << extra)
}

struct DistanceCode {
    history: HistoryList,
    prob: BitProb,
}

impl DistanceCode {
    fn new() -> Self {
        DistanceCode {
            history: HistoryList::new(MATCH_MIN_DIST, DISTANCE_HISTORY_SIZE),
            prob: BitProb::new(MATCH_DIST_CODE_SIZE),
        }
    }

    fn code(&mut self, e: &mut EntropyCode) -> u32 {
        if let Some(d) = self.history.code(e) {
            return d;
        }
        let idx = self.prob.code(e) as usize;
        let mut dist = tbl::MATCH_DIST_CODE[idx.min(tbl::MATCH_DIST_CODE.len() - 1)];
        if idx < tbl::MATCH_DIST_EXTRABIT.len() {
            dist += e.code_raw(tbl::MATCH_DIST_EXTRABIT[idx]);
        }
        self.history.add(dist);
        dist
    }
}

struct LengthCode {
    prob: PredictProb,
}

impl LengthCode {
    fn new() -> Self {
        LengthCode {
            prob: PredictProb::new(
                MATCH_DIST_CODE_SIZE,
                MATCH_LENGTH_CODE_SIZE,
                LENGTHCODE_PREDICT_SHIFT,
            ),
        }
    }

    fn code(&mut self, e: &mut EntropyCode, dist_code: u32) -> u32 {
        let idx = self.prob.code(e, dist_code) as usize;
        let mut len = tbl::MATCH_LENGTH_CODE[idx.min(tbl::MATCH_LENGTH_CODE.len() - 1)];
        if idx < tbl::MATCH_LENGTH_EXTRABIT.len() {
            len += e.code_raw(tbl::MATCH_LENGTH_EXTRABIT[idx]);
        }
        len
    }
}

/// Decode one block into `out`. `Err` on any structural inconsistency — the
/// caller reports rather than delivering a partial buffer.
fn decode_block(inbuf: &[u8], out: &mut [u8]) -> Result<(), ()> {
    if inbuf.len() + REDUCE_MIN > out.len() {
        // Not worth compressing: the block is stored verbatim.
        if inbuf.len() == out.len() {
            out.copy_from_slice(inbuf);
            return Ok(());
        }
        return Err(());
    }

    let mut e = EntropyCode::new(inbuf);
    let mut match_state = BoolState::new();
    let mut dict = DictionaryTable::new();
    let mut dist_code = DistanceCode::new();
    let mut len_code = LengthCode::new();
    let mut alpha = PredictProb::new(ALPHA_SIZE, ALPHA_SIZE, ALPHACODE_PREDICT_SHIFT);

    e.initialize();
    out[0] = alpha.code(&mut e, 0) as u8;

    let mut i = 1usize;
    while i < out.len() {
        let advance = if !match_state.code(&mut e) {
            out[i] = alpha.code(&mut e, out[i - 1] as u32) as u8;
            1u32
        } else {
            let (dist, length) = match dict.code(&mut e) {
                Some((dict_pos, len)) => ((i as u32).wrapping_sub(dict_pos), len),
                None => {
                    let d = dist_code.code(&mut e);
                    let l = len_code.code(&mut e, match_dist_code(d));
                    dict.add(i as u32, l);
                    (d, l)
                }
            };
            // A back-reference before the start, or running past the end, means
            // the stream is not what it claims.
            let d = dist as usize;
            let l = length as usize;
            if d == 0 || d > i || i + l > out.len() {
                return Err(());
            }
            for k in 0..l {
                out[i + k] = out[i - d + k];
            }
            length
        };
        if advance == 0 {
            return Err(());
        }
        i += advance as usize;
    }

    // The reference requires the coder to have consumed exactly the declared
    // input; a short or long read means a mis-decode that happened to terminate.
    if e.size() != inbuf.len() {
        return Err(());
    }
    Ok(())
}

/// Decompress a complete AZO stream.
///
/// `None` on any malformed input — never a partial buffer, because a prefix of a
/// wrong decode is exactly the plausible-looking output this project refuses to
/// scan as if it were content.
pub(crate) fn decompress(data: &[u8], cap: u64) -> Option<Vec<u8>> {
    // Stream header: version byte, then one reserved (filter) byte.
    if data.len() < 2 || data[0] != VERSION {
        return None;
    }
    let mut p = 2usize;
    let mut out: Vec<u8> = Vec::new();

    loop {
        let Some(h) = data.get(p..p + 12) else {
            // No further block header: a well-formed stream ends on the
            // zero-size block below, so running out here is truncation.
            return None;
        };
        // Big-endian, unlike everything else in EGG.
        let block_size = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) as usize;
        let comp_size = u32::from_be_bytes([h[4], h[5], h[6], h[7]]) as usize;
        let check = u32::from_be_bytes([h[8], h[9], h[10], h[11]]);
        if block_size < comp_size || ((block_size as u32) ^ (comp_size as u32)) != check {
            return None;
        }
        p += 12;

        if block_size == 0 || comp_size == 0 {
            return Some(out); // end of stream
        }
        if out.len() as u64 + block_size as u64 > cap {
            return None;
        }
        let raw = data.get(p..p.checked_add(comp_size)?)?;
        p += comp_size;

        let mut block = vec![0u8; block_size];
        decode_block(raw, &mut block).ok()?;
        out.extend_from_slice(&block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_azo_stream_is_rejected() {
        assert!(decompress(b"", 1 << 20).is_none());
        assert!(decompress(b"\x00\x00", 1 << 20).is_none());
        assert!(decompress(b"1", 1 << 20).is_none());
    }

    #[test]
    fn a_block_header_that_contradicts_itself_is_rejected() {
        // block_size ^ comp_size must equal the check word.
        let mut v = vec![VERSION, 0];
        v.extend_from_slice(&100u32.to_be_bytes());
        v.extend_from_slice(&10u32.to_be_bytes());
        v.extend_from_slice(&0xDEADu32.to_be_bytes());
        assert!(decompress(&v, 1 << 20).is_none());
    }

    #[test]
    fn an_empty_terminating_block_ends_the_stream() {
        let mut v = vec![VERSION, 0];
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(decompress(&v, 1 << 20), Some(Vec::new()));
    }

    #[test]
    fn a_verbatim_block_round_trips() {
        // insize + 8 > outsize with insize == outsize: stored, not coded.
        let body = b"stored bytes";
        let mut v = vec![VERSION, 0];
        v.extend_from_slice(&(body.len() as u32).to_be_bytes());
        v.extend_from_slice(&(body.len() as u32).to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes()); // n ^ n == 0
        v.extend_from_slice(body);
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(decompress(&v, 1 << 20), Some(body.to_vec()));
    }

    #[test]
    fn the_output_cap_is_honoured() {
        let body = b"stored bytes";
        let mut v = vec![VERSION, 0];
        v.extend_from_slice(&(body.len() as u32).to_be_bytes());
        v.extend_from_slice(&(body.len() as u32).to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(body);
        assert!(decompress(&v, 4).is_none());
    }

    #[test]
    fn hostile_streams_never_panic() {
        // The decoder indexes tables and the output buffer from decoded values,
        // so every one of those must be bounds-checked rather than trusted.
        let mut seed: u32 = 0x1234_5678;
        for _ in 0..400 {
            let mut v = vec![VERSION, 0];
            let n = 40 + (seed % 200) as usize;
            for _ in 0..n {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                v.push((seed >> 16) as u8);
            }
            let _ = decompress(&v, 1 << 20);
        }
    }

    #[test]
    fn log2_matches_the_reference_truncation() {
        assert_eq!(log2(1), 0);
        assert_eq!(log2(2), 1);
        assert_eq!(log2(3), 1);
        assert_eq!(log2(255), 7);
        assert_eq!(log2(256), 8);
    }
}
