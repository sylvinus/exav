//! LZFSE, Apple's codec for DMG `lzfse` runs, decoded: its raw (`bvx-`),
//! LZVN (`bvxn`) and FSE (`bvx1`, `bvx2`) blocks, up to the end-of-stream
//! block (`bvx$`).
//!
//! A port of the decoder of Apple's reference implementation (`lzfse`,
//! BSD-3-Clause, attributed in `NOTICE`). It decodes a slice whole into a
//! capped buffer, so the reference's resumable state and its wide, unchecked
//! copies are gone. A damaged stream the reference decodes is decoded to the
//! same bytes: its literal buffer and decoding tables are kept across blocks
//! as it keeps them, since a damaged block reads what earlier ones left
//! there. Where it would read memory it never wrote instead (an LZVN match
//! reusing a distance before there is one, or reaching back past the
//! output's start), the stream is invalid here.

use crate::Salvaged;

const END_OF_STREAM: u32 = 0x2478_7662; // bvx$
const UNCOMPRESSED: u32 = 0x2d78_7662; // bvx-
const COMPRESSED_V1: u32 = 0x3178_7662; // bvx1
const COMPRESSED_V2: u32 = 0x3278_7662; // bvx2
const COMPRESSED_LZVN: u32 = 0x6e78_7662; // bvxn

const L_SYMBOLS: usize = 20;
const M_SYMBOLS: usize = 20;
const D_SYMBOLS: usize = 64;
const LITERAL_SYMBOLS: usize = 256;
const L_STATES: usize = 64;
const M_STATES: usize = 64;
const D_STATES: usize = 256;
const LITERAL_STATES: usize = 1024;
const MATCHES_PER_BLOCK: u32 = 10_000;
const LITERALS_PER_BLOCK: u32 = 4 * MATCHES_PER_BLOCK;
/// The reference's literal buffer, which a damaged block's matches may read
/// past the literals it decoded.
const LITERAL_BUFFER: usize = LITERALS_PER_BLOCK as usize + 64;
/// `sizeof(lzfse_compressed_block_header_v1)`, padding included.
const V1_HEADER: usize = 772;
/// Where a v2 header's frequency tables start.
const V2_FREQ: usize = 32;

const L_EXTRA_BITS: [u8; L_SYMBOLS] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8];
const L_BASE: [i32; L_SYMBOLS] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60,
];
const M_EXTRA_BITS: [u8; M_SYMBOLS] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11];
const M_BASE: [i32; M_SYMBOLS] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312,
];
const D_EXTRA_BITS: [u8; D_SYMBOLS] = [
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
    8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14,
    14, 14, 15, 15, 15, 15,
];
const D_BASE: [i32; D_SYMBOLS] = [
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108, 124, 156, 188, 220,
    252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092,
    5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956, 49148,
    57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
];

enum Stop {
    /// The input ended before the end-of-stream block.
    Truncated,
    /// The input is not an LZFSE stream.
    Invalid,
    /// The output reached the cap.
    Full,
}

/// Decode `input` up to `cap` bytes, salvaging what came out before an
/// error, as [`crate::salvage`] reports a reader's.
pub(crate) fn decode(input: &[u8], cap: u64) -> Salvaged {
    let limit = usize::try_from(cap).unwrap_or(usize::MAX).saturating_add(1);
    let mut out = Out {
        buf: Vec::new(),
        limit,
    };
    let stop = run(input, &mut out);
    let mut data = out.buf;
    let over_cap = data.len() > limit - 1;
    data.truncate(limit - 1);
    Salvaged {
        data,
        over_cap,
        undecoded: matches!(stop, Some(Stop::Invalid)),
        cut_short: matches!(stop, Some(Stop::Truncated)),
    }
}

/// The output, which LZVN and LZFSE matches reach back into across blocks.
struct Out {
    buf: Vec<u8>,
    limit: usize,
}

impl Out {
    fn literal(&mut self, bytes: &[u8]) -> Result<(), Stop> {
        let room = self.limit - self.buf.len();
        self.buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
        match bytes.len() > room {
            true => Err(Stop::Full),
            false => Ok(()),
        }
    }

    /// `len` bytes from `dist` back, byte by byte: the copy may overlap
    /// what it writes.
    fn copy(&mut self, dist: usize, len: usize) -> Result<(), Stop> {
        if dist == 0 || dist > self.buf.len() {
            return Err(Stop::Invalid);
        }
        for _ in 0..len {
            if self.buf.len() == self.limit {
                return Err(Stop::Full);
            }
            self.buf.push(self.buf[self.buf.len() - dist]);
        }
        Ok(())
    }
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        crate::bytes::at(d, at, 4)?.try_into().ok()?,
    ))
}

/// What the reference keeps in its decoder state from block to block, zeros
/// at first: a block only overwrites the part it decodes or lays out.
struct Kept {
    literals: Vec<u8>,
    literal: Vec<Entry>,
    l: Vec<ValueEntry>,
    m: Vec<ValueEntry>,
    d: Vec<ValueEntry>,
}

/// `None` at the end-of-stream block.
fn run(input: &[u8], out: &mut Out) -> Option<Stop> {
    let mut pos = 0;
    let mut kept = Kept {
        literals: vec![0; LITERAL_BUFFER],
        literal: vec![Entry::default(); LITERAL_STATES],
        l: vec![ValueEntry::default(); L_STATES],
        m: vec![ValueEntry::default(); M_STATES],
        d: vec![ValueEntry::default(); D_STATES],
    };
    loop {
        let Some(magic) = u32_at(input, pos) else {
            return Some(Stop::Truncated);
        };
        let r = match magic {
            END_OF_STREAM => return None,
            UNCOMPRESSED => uncompressed(input, pos, out),
            COMPRESSED_LZVN => lzvn_block(input, pos, out),
            COMPRESSED_V1 | COMPRESSED_V2 => fse_block(input, pos, magic, &mut kept, out),
            _ => Err(Stop::Invalid),
        };
        match r {
            Ok(next) => pos = next,
            Err(e) => return Some(e),
        }
    }
}

fn uncompressed(input: &[u8], pos: usize, out: &mut Out) -> Result<usize, Stop> {
    let n = u32_at(input, pos + 4).ok_or(Stop::Truncated)? as usize;
    let data = &input[(pos + 8).min(input.len())..];
    out.literal(&data[..n.min(data.len())])?;
    match data.len() < n {
        true => Err(Stop::Truncated),
        false => Ok(pos + 8 + n),
    }
}

fn lzvn_block(input: &[u8], pos: usize, out: &mut Out) -> Result<usize, Stop> {
    let n_raw = u32_at(input, pos + 4).ok_or(Stop::Truncated)? as usize;
    let n_payload = u32_at(input, pos + 8).ok_or(Stop::Truncated)? as usize;
    let rest = &input[pos + 12..];
    let payload = &rest[..n_payload.min(rest.len())];
    let end = out.buf.len().saturating_add(n_raw);
    // The block's output stops at its declared size, as at the output limit:
    // whichever comes first ends it, after the part of an instruction that
    // fits.
    let saved = out.limit;
    out.limit = saved.min(end);
    let result = lzvn(payload, out);
    out.limit = saved;
    match result {
        Err(Stop::Full) if end < saved => Err(Stop::Invalid),
        Err(Stop::Full) => Err(Stop::Full),
        Ok(used) if used == n_payload && out.buf.len() == end => Ok(pos + 12 + n_payload),
        // Out of payload before the end opcode: cut if the input ends there.
        Err(Stop::Truncated) if rest.len() < n_payload => Err(Stop::Truncated),
        _ => Err(Stop::Invalid),
    }
}

/// Decode an LZVN payload. The bytes it used, once it reaches its
/// end-of-stream opcode. `Truncated` when the payload ends before that.
fn lzvn(src: &[u8], out: &mut Out) -> Result<usize, Stop> {
    enum Op {
        LiteralMatch {
            len: usize,
            l: usize,
            m: usize,
            d: Option<usize>,
        },
        Match {
            len: usize,
            m: usize,
        },
        Literal {
            len: usize,
            l: usize,
        },
        Nop,
        End,
        Undefined,
    }
    let mut i = 0;
    let mut d = 0usize;
    loop {
        // Every opcode but the end is followed by at least one byte, the next
        // opcode's.
        let left = src.len() - i;
        let opc = *src.get(i).ok_or(Stop::Truncated)?;
        let op = match opc {
            6 => Op::End,
            14 | 22 => Op::Nop,
            0xe0 => Op::Literal {
                len: 2,
                l: *src.get(i + 1).ok_or(Stop::Truncated)? as usize + 16,
            },
            0xe1..=0xef => Op::Literal {
                len: 1,
                l: (opc & 15) as usize,
            },
            0xf0 => Op::Match {
                len: 2,
                m: *src.get(i + 1).ok_or(Stop::Truncated)? as usize + 16,
            },
            0xf1..=0xff => Op::Match {
                len: 1,
                m: (opc & 15) as usize,
            },
            0x70..=0x7f | 0xd0..=0xdf => Op::Undefined,
            0xa0..=0xbf => Op::LiteralMatch {
                len: 3,
                l: ((opc >> 3) & 3) as usize,
                m: 0,
                d: None,
            },
            _ => match opc & 7 {
                7 => Op::LiteralMatch {
                    len: 3,
                    l: (opc >> 6) as usize,
                    m: ((opc >> 3) & 7) as usize + 3,
                    d: None,
                },
                6 if opc >= 64 => Op::LiteralMatch {
                    len: 1,
                    l: (opc >> 6) as usize,
                    m: ((opc >> 3) & 7) as usize + 3,
                    d: Some(d),
                },
                6 => Op::Undefined,
                _ => Op::LiteralMatch {
                    len: 2,
                    l: (opc >> 6) as usize,
                    m: ((opc >> 3) & 7) as usize + 3,
                    d: None,
                },
            },
        };
        match op {
            Op::End => {
                return match left >= 8 {
                    true => Ok(i + 8),
                    false => Err(Stop::Truncated),
                }
            }
            Op::Undefined => return Err(Stop::Invalid),
            Op::Nop => {
                if left <= 1 {
                    return Err(Stop::Truncated);
                }
                i += 1;
            }
            Op::Literal { len, l } => {
                if left <= len + l {
                    return Err(Stop::Truncated);
                }
                out.literal(&src[i + len..i + len + l])?;
                i += len + l;
            }
            Op::Match { len, m } => {
                if left <= len {
                    return Err(Stop::Truncated);
                }
                i += len;
                out.copy(d, m)?;
            }
            Op::LiteralMatch {
                len,
                l,
                mut m,
                d: dist,
            } => {
                if left <= len + l {
                    return Err(Stop::Truncated);
                }
                d = match (len, dist) {
                    (_, Some(prev)) => prev,
                    (2, None) => ((opc & 7) as usize) << 8 | src[i + 1] as usize,
                    (_, None) => {
                        let v = u16::from_le_bytes([src[i + 1], src[i + 2]]) as usize;
                        if opc & 0xe0 == 0xa0 {
                            m = ((((opc & 7) as usize) << 2) | (v & 3)) + 3;
                            v >> 2
                        } else {
                            v
                        }
                    }
                };
                out.literal(&src[i + len..i + len + l])?;
                i += len + l;
                out.copy(d, m)?;
            }
        }
    }
}

/// A block's header, as the reference's `lzfse_compressed_block_header_v1`.
struct Header {
    n_literals: u32,
    n_matches: u32,
    n_literal_payload: usize,
    n_lmd_payload: usize,
    literal_bits: i32,
    literal_state: [u16; 4],
    lmd_bits: i32,
    l_state: u16,
    m_state: u16,
    d_state: u16,
    /// `l_freq`, `m_freq`, `d_freq` and `literal_freq`, in that order.
    freq: [u16; L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS],
}

fn fse_block(
    input: &[u8],
    pos: usize,
    magic: u32,
    kept: &mut Kept,
    out: &mut Out,
) -> Result<usize, Stop> {
    let (h, header_size) = match magic {
        COMPRESSED_V2 => header_v2(input, pos)?,
        _ => header_v1(input, pos)?,
    };
    // Header fields: on wasm32 their sum can pass `usize::MAX`.
    let lmd_start = (pos + header_size).checked_add(h.n_literal_payload);
    let block_end = lmd_start.and_then(|s| s.checked_add(h.n_lmd_payload));
    let (Some(lmd_start), Some(block_end)) = (lmd_start, block_end.filter(|&e| e <= input.len()))
    else {
        return Err(Stop::Truncated);
    };
    check(&h)?;
    let (l_freq, rest) = h.freq.split_at(L_SYMBOLS);
    let (m_freq, rest) = rest.split_at(M_SYMBOLS);
    let (d_freq, literal_freq) = rest.split_at(D_SYMBOLS);
    decoder_table(&mut kept.literal, literal_freq);
    value_table(&mut kept.l, l_freq, &L_EXTRA_BITS, &L_BASE);
    value_table(&mut kept.m, m_freq, &M_EXTRA_BITS, &M_BASE);
    value_table(&mut kept.d, d_freq, &D_EXTRA_BITS, &D_BASE);
    let Kept {
        literals,
        literal: literal_table,
        l: l_table,
        m: m_table,
        d: d_table,
    } = kept;

    {
        // The reference bounds even this stream's first bytes by the input's
        // start, not the payload's: a payload of 7 bytes is read as 8.
        let mut s = Stream::new(input, 0, lmd_start, h.literal_bits)?;
        let mut state = h.literal_state;
        // `check` bounds `n_literals` by the buffer.
        let n = (h.n_literals as usize).next_multiple_of(4);
        for quad in literals[..n].as_chunks_mut::<4>().0 {
            s.flush()?;
            for (byte, st) in quad.iter_mut().zip(state.iter_mut()) {
                let e = literal_table.get(*st as usize).ok_or(Stop::Invalid)?;
                *st = e.delta.wrapping_add(s.pull(e.k)? as u16);
                *byte = e.symbol;
            }
        }
    }

    let mut s = Stream::new(input, lmd_start, block_end, h.lmd_bits)?;
    let (mut l_state, mut m_state, mut d_state) = (h.l_state, h.m_state, h.d_state);
    let mut lit = 0usize;
    // No distance yet: a match that reuses it is invalid.
    let mut d: i64 = -1;
    for _ in 0..h.n_matches {
        s.flush()?;
        let l = s.value(l_table, &mut l_state)? as usize;
        let m = s.value(m_table, &mut m_state)? as usize;
        let new_d = s.value(d_table, &mut d_state)?;
        if new_d != 0 {
            d = i64::from(new_d);
        }
        // The reference's bound, one byte short of its buffer's end.
        let literal = literals
            .get(lit..lit + l)
            .filter(|_| lit + l < LITERAL_BUFFER);
        let literal = literal.ok_or(Stop::Invalid)?;
        if d < 0 || d as usize > out.buf.len() + l {
            return Err(Stop::Invalid);
        }
        out.literal(literal)?;
        lit += l;
        if m > 0 {
            out.copy(d as usize, m)?;
        }
    }
    Ok(block_end)
}

fn header_v1(input: &[u8], pos: usize) -> Result<(Header, usize), Stop> {
    let h = crate::bytes::at(input, pos, V1_HEADER).ok_or(Stop::Truncated)?;
    let u32_ = |o: usize| u32::from_le_bytes(h[o..o + 4].try_into().unwrap());
    let u16_ = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]);
    let mut freq = [0u16; L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS];
    for (i, f) in freq.iter_mut().enumerate() {
        *f = u16_(50 + 2 * i);
    }
    let header = Header {
        n_literals: u32_(12),
        n_matches: u32_(16),
        n_literal_payload: u32_(20) as usize,
        n_lmd_payload: u32_(24) as usize,
        literal_bits: u32_(28) as i32,
        literal_state: [u16_(32), u16_(34), u16_(36), u16_(38)],
        lmd_bits: u32_(40) as i32,
        l_state: u16_(44),
        m_state: u16_(46),
        d_state: u16_(48),
        freq,
    };
    Ok((header, V1_HEADER))
}

fn header_v2(input: &[u8], pos: usize) -> Result<(Header, usize), Stop> {
    let fixed = crate::bytes::at(input, pos, V2_FREQ).ok_or(Stop::Truncated)?;
    let packed = |i: usize| u64::from_le_bytes(fixed[8 + 8 * i..16 + 8 * i].try_into().unwrap());
    let (v0, v1, v2) = (packed(0), packed(1), packed(2));
    let field = |v: u64, offset: u32, bits: u32| ((v >> offset) & ((1 << bits) - 1)) as u32;
    let header_size = field(v2, 0, 32) as usize;
    if header_size < V2_FREQ {
        return Err(Stop::Invalid);
    }
    let tables =
        crate::bytes::at(input, pos + V2_FREQ, header_size - V2_FREQ).ok_or(Stop::Truncated)?;
    let mut freq = [0u16; L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS];
    // No tables at all is allowed: every frequency is zero.
    if !tables.is_empty() {
        let (mut accum, mut accum_bits, mut next) = (0u32, 0u32, 0usize);
        for f in freq.iter_mut() {
            while next < tables.len() && accum_bits + 8 <= 32 {
                accum |= u32::from(tables[next]) << accum_bits;
                accum_bits += 8;
                next += 1;
            }
            let (value, bits) = freq_value(accum);
            if bits > accum_bits {
                return Err(Stop::Invalid);
            }
            *f = value;
            accum >>= bits;
            accum_bits -= bits;
        }
        if accum_bits >= 8 || next != tables.len() {
            return Err(Stop::Invalid);
        }
    }
    let header = Header {
        n_literals: field(v0, 0, 20),
        n_literal_payload: field(v0, 20, 20) as usize,
        n_matches: field(v0, 40, 20),
        literal_bits: field(v0, 60, 3) as i32 - 7,
        literal_state: [0, 10, 20, 30].map(|o| field(v1, o, 10) as u16),
        n_lmd_payload: field(v1, 40, 20) as usize,
        lmd_bits: field(v1, 60, 3) as i32 - 7,
        l_state: field(v2, 32, 10) as u16,
        m_state: field(v2, 42, 10) as u16,
        d_state: field(v2, 52, 10) as u16,
        freq,
    };
    Ok((header, header_size))
}

/// One frequency of a v2 header's tables, and the bits it took.
fn freq_value(bits: u32) -> (u16, u32) {
    const NBITS: [u8; 32] = [
        2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3,
        2, 14,
    ];
    const VALUE: [u8; 32] = [
        0, 2, 1, 4, 0, 3, 1, 0, 0, 2, 1, 5, 0, 3, 1, 0, 0, 2, 1, 6, 0, 3, 1, 0, 0, 2, 1, 7, 0, 3,
        1, 0,
    ];
    let b = (bits & 31) as usize;
    match NBITS[b] {
        8 => (8 + ((bits >> 4) & 0xf) as u16, 8),
        14 => (24 + ((bits >> 4) & 0x3ff) as u16, 14),
        n => (u16::from(VALUE[b]), u32::from(n)),
    }
}

/// The reference's `lzfse_check_block_header_v1`.
fn check(h: &Header) -> Result<(), Stop> {
    let sum = |f: &[u16]| f.iter().map(|&v| v as usize).sum::<usize>();
    let (l, rest) = h.freq.split_at(L_SYMBOLS);
    let (m, rest) = rest.split_at(M_SYMBOLS);
    let (d, literal) = rest.split_at(D_SYMBOLS);
    let ok = h.n_literals <= LITERALS_PER_BLOCK
        && h.n_matches <= MATCHES_PER_BLOCK
        && h.literal_state
            .iter()
            .all(|&s| (s as usize) < LITERAL_STATES)
        && (h.l_state as usize) < L_STATES
        && (h.m_state as usize) < M_STATES
        && (h.d_state as usize) < D_STATES
        && sum(l) <= L_STATES
        && sum(m) <= M_STATES
        && sum(d) <= D_STATES
        && sum(literal) <= LITERAL_STATES;
    match ok {
        true => Ok(()),
        false => Err(Stop::Invalid),
    }
}

#[derive(Clone, Copy, Default)]
struct Entry {
    k: u32,
    symbol: u8,
    delta: u16,
}

#[derive(Clone, Copy, Default)]
struct ValueEntry {
    total_bits: u32,
    value_bits: u32,
    delta: u16,
    vbase: i32,
}

/// The states each symbol reaches, as `fse_init_decoder_table` lays them
/// out in `t`. States past the frequencies' sum keep what they held.
fn decoder_table(t: &mut [Entry], freq: &[u16]) {
    let mut at = 0;
    for (symbol, &f) in freq.iter().enumerate() {
        for (j, (k, delta)) in transitions(t.len(), f).enumerate() {
            t[at + j] = Entry {
                k,
                symbol: symbol as u8,
                delta,
            };
        }
        at += f as usize;
    }
}

fn value_table(t: &mut [ValueEntry], freq: &[u16], extra: &[u8], base: &[i32]) {
    let mut at = 0;
    for (symbol, &f) in freq.iter().enumerate() {
        for (j, (k, delta)) in transitions(t.len(), f).enumerate() {
            t[at + j] = ValueEntry {
                total_bits: k + u32::from(extra[symbol]),
                value_bits: u32::from(extra[symbol]),
                delta,
                vbase: base[symbol],
            };
        }
        at += f as usize;
    }
}

/// For each of a symbol's `f` states: the bits read and the next state's
/// base. [`check`] has bounded `f` by `nstates`.
fn transitions(nstates: usize, f: u16) -> impl Iterator<Item = (u32, u16)> {
    let n = nstates as u32;
    let f = u32::from(f);
    let k = f.leading_zeros().saturating_sub(n.leading_zeros());
    let j0 = ((2 * n) >> k).saturating_sub(f);
    (0..f).map(move |j| match j < j0 {
        true => (k, (((f + j) << k) - n) as u16),
        false => (k - 1, ((j - j0) << (k - 1)) as u16),
    })
}

/// A bit stream read backwards from `end`, 56 to 63 bits held: the
/// reference's 64-bit `fse_in_stream`. Its first bytes are after `start`;
/// later reads may run past that, as the encoder's last flush does, but not
/// past the input's start.
struct Stream<'a> {
    input: &'a [u8],
    pos: usize,
    accum: u64,
    bits: u32,
}

impl<'a> Stream<'a> {
    fn new(input: &'a [u8], start: usize, end: usize, n: i32) -> Result<Self, Stop> {
        let width = if n != 0 { 8 } else { 7 };
        if end < start + width {
            return Err(Stop::Invalid);
        }
        let pos = end - width;
        let mut b = [0u8; 8];
        b[..width].copy_from_slice(&input[pos..end]);
        let accum = u64::from_le_bytes(b);
        let bits = i64::from(n) + 8 * width as i64;
        if !(56..64).contains(&bits) || accum >> bits != 0 {
            return Err(Stop::Invalid);
        }
        Ok(Stream {
            input,
            pos,
            accum,
            bits: bits as u32,
        })
    }

    fn flush(&mut self) -> Result<(), Stop> {
        let n = (63 - self.bits) & !7;
        let pos = self.pos.checked_sub(n as usize / 8).ok_or(Stop::Invalid)?;
        let mut b = [0u8; 8];
        b[..n as usize / 8].copy_from_slice(&self.input[pos..self.pos]);
        self.pos = pos;
        if n > 0 {
            self.accum = (self.accum << n) | u64::from_le_bytes(b);
        }
        self.bits += n;
        Ok(())
    }

    fn pull(&mut self, n: u32) -> Result<u64, Stop> {
        self.bits = self.bits.checked_sub(n).ok_or(Stop::Invalid)?;
        let v = self.accum >> self.bits;
        self.accum &= (1u64 << self.bits) - 1;
        Ok(v)
    }

    fn value(&mut self, t: &[ValueEntry], state: &mut u16) -> Result<i32, Stop> {
        let e = t.get(*state as usize).ok_or(Stop::Invalid)?;
        let v = self.pull(e.total_bits)? as u32;
        *state = e.delta.wrapping_add((v >> e.value_bits) as u16);
        Ok(e.vbase + (v & ((1 << e.value_bits) - 1)) as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::decode;

    fn encode(data: &[u8]) -> Vec<u8> {
        let mut enc = Vec::new();
        lzfse_rust::encode_bytes(data, &mut enc).unwrap();
        enc
    }

    /// Text with repeats near and far, so the encoder emits matches of every
    /// length and distance class.
    fn text(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        let mut out: Vec<u8> = Vec::with_capacity(n);
        while out.len() < n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            match (x % 4, out.len()) {
                (0, len) if len > 300 => {
                    let back = 1 + (x >> 8) as usize % len.min(200_000);
                    let len_ = 3 + (x >> 40) as usize % 300;
                    for _ in 0..len_ {
                        out.push(out[out.len() - back]);
                    }
                }
                (1, _) => out.push(b'a' + (x >> 20) as u8 % 26),
                _ => out.extend_from_slice(b"the quick brown fox "),
            }
        }
        out.truncate(n);
        out
    }

    fn magics(enc: &[u8]) -> bool {
        enc.windows(4).any(|w| w == b"bvx2")
    }

    #[test]
    fn every_block_kind_decodes_to_what_was_encoded() {
        for (n, kind) in [
            (0, &b"bvx$"[..]),
            (11, b"bvx-"),
            (3000, b"bvxn"),
            (100_000, b"bvx2"),
            (3_000_000, b"bvx2"),
        ] {
            let data = text(n, n as u64 + 1);
            let enc = encode(&data);
            assert!(
                enc.windows(4).any(|w| w == kind),
                "{n} bytes: no {kind:?} block"
            );
            let s = decode(&enc, u64::MAX);
            assert!(!s.undecoded && !s.cut_short && !s.over_cap, "{n} bytes");
            assert!(s.data == data, "{n} bytes decode differently");
        }
    }

    /// An LZVN block with each opcode once, by hand, and what it decodes to,
    /// built without the decoder.
    fn every_lzvn_opcode() -> (Vec<u8>, Vec<u8>) {
        fn copy(out: &mut Vec<u8>, d: usize, m: usize) {
            for _ in 0..m {
                out.push(out[out.len() - d]);
            }
        }
        let mut p = Vec::new();
        let mut want = Vec::new();
        // Large literal: 16 + 4 bytes.
        p.extend_from_slice(&[0xe0, 4]);
        p.extend_from_slice(b"abcdefghijklmnopqrst");
        want.extend_from_slice(b"abcdefghijklmnopqrst");
        // Small distance (LLMMMDDD): L 1, M 4, D 5.
        p.extend_from_slice(&[0b0100_1000, 5, b'X']);
        want.push(b'X');
        copy(&mut want, 5, 4);
        // Medium distance (101LLMMM): L 0, M 5, D 10.
        p.extend_from_slice(&[0b1010_0000, (10 << 2) | 2, 0]);
        copy(&mut want, 10, 5);
        // Large distance (LLMMM111): L 0, M 3, D 12.
        p.extend_from_slice(&[0b0000_0111, 12, 0]);
        copy(&mut want, 12, 3);
        // Previous distance (LLMMM110): L 2, M 5.
        p.extend_from_slice(&[0b1001_0110, b'Y', b'Z']);
        want.extend_from_slice(b"YZ");
        copy(&mut want, 12, 5);
        // Small match: M 3. Large match: M 16 + 1.
        p.push(0xf3);
        copy(&mut want, 12, 3);
        p.extend_from_slice(&[0xf0, 1]);
        copy(&mut want, 12, 17);
        // Small literal, a no-op, the end.
        p.extend_from_slice(&[0xe2, b'!', b'?', 0x0e, 6, 0, 0, 0, 0, 0, 0, 0]);
        want.extend_from_slice(b"!?");

        let mut s = b"bvxn".to_vec();
        s.extend_from_slice(&(want.len() as u32).to_le_bytes());
        s.extend_from_slice(&(p.len() as u32).to_le_bytes());
        s.extend(p);
        s.extend_from_slice(b"bvx$");
        (s, want)
    }

    /// A stream of one bvx2 block, its header rewritten as the bvx1 header
    /// the reference reads the same way. The frequencies are decoded here,
    /// not by `header_v2`.
    fn as_v1(enc: &[u8]) -> Vec<u8> {
        assert!(enc.starts_with(b"bvx2"));
        let packed = |i: usize| u64::from_le_bytes(enc[8 + 8 * i..16 + 8 * i].try_into().unwrap());
        let (v0, v1, v2) = (packed(0), packed(1), packed(2));
        let f = |v: u64, o: u32, b: u32| ((v >> o) & ((1u64 << b) - 1)) as u32;
        let header_size = f(v2, 0, 32) as usize;
        let mut freq = Vec::new();
        let mut table = enc[32..header_size].iter();
        let (mut acc, mut bits) = (0u64, 0u32);
        while freq.len() < 360 {
            while bits <= 24 {
                acc |= u64::from(table.next().copied().unwrap_or(0)) << bits;
                bits += 8;
            }
            let (v, n) = match acc & 31 {
                b if b & 15 == 7 => (8 + ((acc >> 4) & 0xf), 8),
                b if b & 15 == 15 => (24 + ((acc >> 4) & 0x3ff), 14),
                b if b & 1 == 0 => ((b >> 1) & 1, 2),
                b if b & 3 == 1 => (2 + ((b >> 2) & 1), 3),
                b => (4 + ((b >> 3) & 3), 5),
            };
            freq.push(v as u16);
            acc >>= n;
            bits -= n;
        }
        let (lit, lmd) = (f(v0, 20, 20), f(v1, 40, 20));
        let mut h = Vec::new();
        h.extend_from_slice(b"bvx1");
        for v in [
            u32::from_le_bytes(enc[4..8].try_into().unwrap()),
            lit + lmd,
            f(v0, 0, 20),
            f(v0, 40, 20),
            lit,
            lmd,
            (f(v0, 60, 3) as i32 - 7) as u32,
        ] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        for k in 0..4 {
            h.extend_from_slice(&(f(v1, 10 * k, 10) as u16).to_le_bytes());
        }
        h.extend_from_slice(&(f(v1, 60, 3) as i32 - 7).to_le_bytes());
        for o in [32, 42, 52] {
            h.extend_from_slice(&(f(v2, o, 10) as u16).to_le_bytes());
        }
        for v in freq {
            h.extend_from_slice(&v.to_le_bytes());
        }
        h.resize(772, 0);
        let body = header_size + (lit + lmd) as usize;
        h.extend_from_slice(&enc[header_size..body]);
        assert_eq!(&enc[body..], b"bvx$", "one block");
        h.extend_from_slice(b"bvx$");
        h
    }

    #[test]
    fn a_block_with_uncompressed_tables_decodes() {
        let data = text(30_000, 11);
        let v1 = as_v1(&encode(&data));
        let s = decode(&v1, u64::MAX);
        assert!(!s.undecoded && !s.cut_short);
        assert!(s.data == data);
    }

    #[test]
    fn every_lzvn_opcode_decodes() {
        let (stream, want) = every_lzvn_opcode();
        let s = decode(&stream, u64::MAX);
        assert!(!s.undecoded && !s.cut_short);
        assert_eq!(s.data, want);
    }

    #[test]
    fn incompressible_data_decodes() {
        let data: Vec<u8> = text(200_000, 7)
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let enc = encode(&data);
        assert_eq!(decode(&enc, u64::MAX).data, data);
    }

    #[test]
    fn the_cap_holds() {
        let data = text(100_000, 3);
        let s = decode(&encode(&data), 1000);
        assert!(s.over_cap && !s.undecoded);
        assert_eq!(s.data, data[..1000]);
    }

    #[test]
    fn a_cut_stream_keeps_its_whole_blocks_and_says_so() {
        let first = text(3000, 5);
        let mut enc = encode(&first);
        enc.truncate(enc.len() - 4); // the end-of-stream block
        enc.extend(encode(&text(100_000, 6)));
        assert!(magics(&enc));
        let s = decode(&enc[..enc.len() - 100], u64::MAX);
        assert!(s.cut_short && !s.undecoded);
        assert!(s.data.starts_with(&first));
    }

    #[test]
    fn damage_is_invalid_not_a_panic() {
        assert!(decode(b"bvxZ\0\0\0\0", 100).undecoded);
        let enc = encode(&text(100_000, 9));
        for at in (0..enc.len()).step_by(97) {
            for bit in [0x01, 0x10, 0x80] {
                let mut bad = enc.clone();
                bad[at] ^= bit;
                let _ = decode(&bad, 1 << 20);
            }
        }
    }

    /// A stream of one LZVN block: "abc", then a match of 5 from 3 back (so
    /// 8 bytes), then the end opcode, and the end-of-stream block.
    fn lzvn_stream(n_raw: u32, n_payload: u32, with_end_opcode: bool) -> Vec<u8> {
        let mut p = vec![0xe3, b'a', b'b', b'c', 0x10, 0x03];
        if with_end_opcode {
            p.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        }
        let mut s = b"bvxn".to_vec();
        s.extend_from_slice(&n_raw.to_le_bytes());
        s.extend_from_slice(&n_payload.to_le_bytes());
        s.extend(p);
        s.extend_from_slice(b"bvx$");
        s
    }

    #[test]
    fn the_lzvn_stream_of_these_tests_decodes() {
        let s = decode(&lzvn_stream(8, 14, true), 100);
        assert!(!s.undecoded && !s.cut_short && !s.over_cap);
        assert_eq!(s.data, b"abcabcab");
    }

    #[test]
    fn an_lzvn_payload_longer_than_the_input_that_still_ends_is_damaged_not_cut() {
        // The end opcode is reached, 6 bytes short of the declared payload.
        let mut s = lzvn_stream(8, 20, true);
        s.truncate(s.len() - 4);
        let r = decode(&s, 100);
        assert!(
            r.undecoded && !r.cut_short,
            "{:?}",
            (r.undecoded, r.cut_short)
        );
        assert_eq!(r.data, b"abcabcab");
    }

    #[test]
    fn an_lzvn_payload_cut_before_its_end_opcode_is_cut() {
        let mut s = lzvn_stream(8, 14, true);
        s.truncate(12 + 6);
        let r = decode(&s, 100);
        assert!(r.cut_short && !r.undecoded);
        // The match is left out: an instruction needs the next opcode's byte.
        assert_eq!(r.data, b"abc");
        // The same payload with the input whole is damaged.
        let r = decode(&lzvn_stream(8, 6, false), 100);
        assert!(r.undecoded && !r.cut_short);
    }

    #[test]
    fn an_lzvn_instruction_past_the_block_size_is_damaged_and_clipped() {
        let r = decode(&lzvn_stream(6, 14, true), 100);
        assert!(r.undecoded && !r.over_cap);
        assert_eq!(r.data, b"abcabc");
    }

    #[test]
    fn the_output_limit_comes_before_a_block_size_it_is_inside_of() {
        // The block's declared 6 bytes are past the cap of 4.
        let r = decode(&lzvn_stream(6, 14, true), 4);
        assert!(r.over_cap && !r.undecoded);
        assert_eq!(r.data, b"abca");
    }

    /// The reference's verdict codes (`lzfse_oracle.c`) for what `decode`
    /// found: output past the limit is reported first.
    fn verdict(s: &crate::Salvaged) -> u8 {
        match (s.over_cap, s.cut_short, s.undecoded) {
            (true, _, _) => 1,
            (_, true, _) => 2,
            (_, _, true) => 3,
            _ => 0,
        }
    }

    /// What `decode` says of a stream, against what the reference says of it
    /// with a destination of `limit` bytes, run twice with different fills of
    /// that destination. `None` when they agree.
    ///
    /// The reference counts a failed block's last instruction out of the
    /// bytes it reports, writes the part of an LZVN match that fits the
    /// block's size, and calls an LZVN payload that ends before its end opcode
    /// "destination full", so on a failure the two outputs are held to agree
    /// as far as both go, and to a failure of some kind. A stream whose output
    /// depends on the fill is one the reference read unwritten memory for,
    /// which is invalid here.
    fn disagreement(
        input: &[u8],
        limit: u32,
        reference: &(u8, Vec<u8>),
        other_fill: &(u8, Vec<u8>),
    ) -> Option<&'static str> {
        let s = decode(input, u64::from(limit));
        let (status, out) = reference;
        if reference != other_fill {
            return (!s.undecoded && !s.over_cap).then_some("read of unwritten memory accepted");
        }
        let ours = verdict(&s);
        match status {
            0 if ours != 0 => Some("a stream the reference decodes is not"),
            0 if s.data != *out => Some("output differs"),
            0 => None,
            _ if ours == 0 => Some("a stream the reference refuses is decoded"),
            _ if !s.data.starts_with(out) && !out.starts_with(&s.data) => Some("outputs diverge"),
            1 if out.len() == limit as usize && (ours != 1 || s.data != *out) => {
                Some("output past the limit differs")
            }
            2 if ours == 3 => Some("cut stream called damaged"),
            // An LZVN payload cut inside its end opcode, after all its output:
            // the reference's size check calls it an error.
            3 if ours == 2 && s.data != *out => Some("damaged stream called cut"),
            _ => None,
        }
    }

    /// Streams the reference decodes, cut or damaged in many ways, and the
    /// bytes it wrote before it stopped, against `decode`. Needs the oracle
    /// built by `tests/oracle/build.sh`:
    /// `EXAV_LZFSE_ORACLE=... cargo test -p exav-unpack --lib -- --ignored lzfse_oracle`.
    #[test]
    #[ignore = "needs the reference decoder: tests/oracle/build.sh, EXAV_LZFSE_ORACLE"]
    fn lzfse_oracle_agrees_on_damaged_streams() {
        let rounds: usize = std::env::var("EXAV_DEBUG_ORACLE_ROUNDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3000);
        let mut bases: Vec<(Vec<u8>, usize)> = Vec::new();
        for (n, seed) in [(0, 1), (11, 2), (3000, 3), (30_000, 4), (100_000, 5)] {
            let enc = encode(&text(n, seed));
            bases.push((enc, 800));
        }
        bases.push((as_v1(&encode(&text(30_000, 11))), 800));
        bases.push((every_lzvn_opcode().0, 200));
        let mut two = encode(&text(3000, 6));
        two.truncate(two.len() - 4);
        two.extend(encode(&text(40_000, 7)));
        bases.push((two, 800));
        let mut rng = crate::oracle::Rng(0x9e37_79b9_7f4a_7c15);
        let mut jobs = Vec::new();
        for (base, hot) in &bases {
            jobs.push((u32::MAX >> 8, base.clone()));
            for _ in 0..rounds {
                let bad = rng.damage(base, *hot);
                let limit = match rng.below(3) {
                    0 => 1 << 20,
                    1 => rng.below(base.len() * 4 + 1) as u32,
                    _ => 1 << 24,
                };
                jobs.push((limit, bad));
            }
        }
        let replies = crate::oracle::run("EXAV_LZFSE_ORACLE", &["0"], &jobs);
        let others = crate::oracle::run("EXAV_LZFSE_ORACLE", &["255"], &jobs);
        let mut bad = Vec::new();
        // The reference's verdict by ours.
        let mut matrix = [[0usize; 4]; 4];
        for (((limit, input), reply), other) in jobs.iter().zip(&replies).zip(&others) {
            let s = decode(input, u64::from(*limit));
            matrix[usize::from(reply.0)][usize::from(verdict(&s))] += 1;
            if let Some(why) = disagreement(input, *limit, reply, other) {
                let ours = (s.data.len(), s.over_cap, s.cut_short, s.undecoded);
                crate::oracle::dump("lzfse", bad.len(), input, &reply.1, &s.data);
                bad.push((why, *limit, (reply.0, reply.1.len()), ours, input.clone()));
            }
        }
        eprintln!(
            "{} streams; rows the reference's verdict (ok, full, cut, error), columns ours: {matrix:?}",
            jobs.len()
        );
        for (why, limit, reference, ours, input) in bad.iter().take(5) {
            eprintln!("{why}: limit {limit}, {} bytes", input.len());
            eprintln!("  reference (status, written) {reference:?}");
            eprintln!("  ours (written, over cap, cut, undecoded) {ours:?}");
            let head: Vec<String> = input.iter().take(48).map(|b| format!("{b:02x}")).collect();
            eprintln!("  {}", head.join(" "));
        }
        assert!(
            bad.is_empty(),
            "{} of {} streams differ",
            bad.len(),
            jobs.len()
        );
    }
}
