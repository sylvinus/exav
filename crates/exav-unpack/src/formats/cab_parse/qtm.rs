//! Quantum decompression (CAB `typeCompress` low nibble 2).
//!
//! Quantum is an arithmetic coder over adaptive frequency models, used by
//! Office-97-era cabinets. It matters because **the victim can still open it**:
//! 7-Zip decompresses Quantum cabinets byte-exactly today, so an attacker can
//! ship one to a target that opens it fine while scanners that skip the codec
//! see nothing. Rarity in a corpus is an argument for an attacker choosing it,
//! not against.
//!
//! # Provenance
//!
//! Microsoft published the cabinet *container* but never the Quantum
//! *compressor* — it was licensed third-party technology. This implementation
//! was written from a functional specification of the format (bit order, coder
//! registers, model inventory, update and rescale rules, slot tables, window
//! semantics), not from any existing decoder's source. `cabextract`/libmspack is
//! used only as an **oracle**: its output is compared against ours, which is the
//! same relationship the project has with `clamscan` and `innoextract` — an
//! external oracle, never a round-trip against an encoder written alongside.
//!
//! # Shape of the format
//!
//! * A folder is a sequence of frames of at most 32 768 bytes; in a cabinet one
//!   CFDATA block is exactly one frame.
//! * The **coder** resets at every frame; the **window and models do not**.
//!   Matches routinely reach back across block boundaries — that is the point of
//!   a multi-block folder.
//! * One MSB-first bitstream feeds both the arithmetic decoder and the *raw*
//!   extra-bit fields of match offsets and lengths, strictly interleaved. The
//!   extra bits are **not** arithmetic-coded.

use std::io;

/// Frames are at most this many bytes; one CFDATA block carries one frame.
const FRAME_SIZE: usize = 32768;
/// Model totals are rescaled once they exceed this.
const RESCALE_AT: u32 = 3800;
/// Frequency added to the decoded symbol on every update.
const INCREMENT: u32 = 8;

/// Extra-bit count for position slot `i`: `max(0, i - 2) >> 1`.
fn position_extra(i: usize) -> u32 {
    (i.saturating_sub(2) >> 1) as u32
}

/// Base offset for position slot `i`: the sum of `2^extra(j)` for all `j < i`.
fn position_base(i: usize) -> u32 {
    (0..i).map(|j| 1u32 << position_extra(j)).sum()
}

/// Extra-bit count for length slot `i`. Slot 26 is a terminal entry with none.
fn length_extra(i: usize) -> u32 {
    if i >= 26 {
        0
    } else {
        (i.saturating_sub(2) >> 2) as u32
    }
}

/// Base length for length slot `i`; slot 26 is the terminal value 254.
fn length_base(i: usize) -> u32 {
    if i >= 26 {
        254
    } else {
        (0..i).map(|j| 1u32 << length_extra(j)).sum()
    }
}

/// An adaptive frequency model.
///
/// `cum[i]` is the cumulative frequency at slot `i`, strictly decreasing, with
/// `cum[n]` a permanent zero sentinel. `sym[i]` is the symbol value currently
/// held in slot `i` — symbols migrate between slots (see [`Model::rescale`]), so
/// a slot index is never a symbol value.
struct Model {
    sym: Vec<u16>,
    cum: Vec<u32>,
    /// Counts down to the periodic reordering; starts at 4, then every 50.
    countdown: u32,
}

impl Model {
    /// Every symbol starts with frequency 1, in ascending value order.
    fn new(base: u16, n: usize) -> Self {
        Model {
            sym: (0..n).map(|i| base + i as u16).collect(),
            cum: (0..=n).map(|i| (n - i) as u32).collect(),
            countdown: 4,
        }
    }

    fn total(&self) -> u32 {
        self.cum[0]
    }

    /// Raise the decoded symbol's frequency, rescaling when the total grows too
    /// large for the coder's arithmetic to stay exact.
    fn update(&mut self, slot: usize) {
        for c in self.cum[..=slot].iter_mut() {
            *c += INCREMENT;
        }
        if self.total() > RESCALE_AT {
            self.rescale();
        }
    }

    /// Halve all frequencies, and on every 4th-then-50th call also reorder the
    /// slots by frequency.
    ///
    /// The reordering is what keeps hot symbols at low slot indices, where the
    /// linear search in [`Decoder::decode_symbol`] finds them first.
    fn rescale(&mut self) {
        let n = self.sym.len();
        self.countdown = self.countdown.saturating_sub(1);
        if self.countdown != 0 {
            // Plain halving, from the top down so each slot can be clamped
            // against the already-processed slot below it. Every symbol keeps a
            // frequency of at least 1, which the coder relies on.
            for i in (0..n).rev() {
                let halved = self.cum[i] / 2;
                self.cum[i] = halved.max(self.cum[i + 1] + 1);
            }
            return;
        }
        self.countdown = 50;

        // 1. Cumulative -> individual frequencies, ascending so that each slot
        //    still sees the NEXT slot's untouched cumulative value.
        // `+1 then halve` is a ceiling divide, and it is what guarantees every
        // symbol keeps a frequency of at least 1 — a symbol that reached 0 would
        // become undecodable and desynchronise the stream permanently.
        let mut freq: Vec<u32> = (0..n)
            .map(|i| (self.cum[i] - self.cum[i + 1]).div_ceil(2))
            .collect();

        // 2. Sort by frequency, descending, by this exact exchange procedure.
        //    It is deliberately not a library sort: it is not stable, and the
        //    element at `i` is replaced mid-scan, so equal frequencies end up in
        //    an order a stable sort does not reproduce. Ties are common after
        //    halving, and substituting a sort here yields a decoder that tracks
        //    the reference for a while and then silently diverges.
        for i in 0..n.saturating_sub(1) {
            for j in (i + 1)..n {
                if freq[j] > freq[i] {
                    freq.swap(i, j);
                    self.sym.swap(i, j);
                }
            }
        }

        // 3. Individual -> cumulative, from the top down.
        self.cum[n] = 0;
        for i in (0..n).rev() {
            self.cum[i] = self.cum[i + 1] + freq[i];
        }
    }
}

/// MSB-first bit reader shared by the arithmetic decoder and the raw extra-bit
/// fields. Reads past the end yield zero bits: the coder legitimately runs a few
/// bits beyond the payload at the end of a frame, because it is always 16 bits
/// ahead of the symbols it has produced.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Bits consumed past the end — a corruption signal when it grows large.
    overrun: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            overrun: 0,
        }
    }

    fn bit(&mut self) -> u32 {
        let byte = self.pos >> 3;
        let b = match self.data.get(byte) {
            Some(&v) => (v >> (7 - (self.pos & 7))) as u32 & 1,
            None => {
                self.overrun += 1;
                0
            }
        };
        self.pos += 1;
        b
    }

    fn bits(&mut self, n: u32) -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.bit();
        }
        v
    }
}

/// The arithmetic decoder: three 16-bit registers over the shared bitstream.
struct Decoder<'a> {
    br: BitReader<'a>,
    low: u32,
    high: u32,
    code: u32,
}

impl<'a> Decoder<'a> {
    /// Frame start: the interval is the whole range and 16 bits are loaded.
    fn new(data: &'a [u8]) -> Self {
        let mut br = BitReader::new(data);
        let code = br.bits(16);
        Decoder {
            br,
            low: 0,
            high: 0xFFFF,
            code,
        }
    }

    fn decode_symbol(&mut self, m: &mut Model) -> io::Result<u16> {
        let total = m.total();
        let range = self.high - self.low + 1;
        // Both the -1 and the +1 are required; dropping either yields a decoder
        // that is correct except on interval boundaries.
        let target = ((self.code - self.low + 1) * total - 1) / range;

        let n = m.sym.len();
        let mut slot = n - 1;
        for i in 1..=n {
            if m.cum[i] <= target {
                slot = i - 1;
                break;
            }
        }
        let symbol = m.sym[slot];

        // Narrow the interval; both bounds use the OLD low.
        let low = self.low;
        self.high = low + (m.cum[slot] * range) / total - 1;
        self.low = low + (m.cum[slot + 1] * range) / total;

        m.update(slot);
        self.renormalise();

        // With every model total <= 3808 and the post-renormalisation range
        // >= 16385, this cannot fire on a stream we produced ourselves; it means
        // the input drove us somewhere unreachable.
        if self.high < self.low {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Quantum: arithmetic decoder interval collapsed",
            ));
        }
        Ok(symbol)
    }

    fn renormalise(&mut self) {
        loop {
            let same_top = (self.low & 0x8000) == (self.high & 0x8000);
            // Straddle: the interval spans the midpoint without either bound
            // resolving. Correct the second-most-significant bit of all three
            // registers, then shift — the shift is what discards the ambiguity.
            let straddle = (self.low & 0x4000) != 0 && (self.high & 0x4000) == 0;
            if !same_top && !straddle {
                return;
            }
            if !same_top {
                self.low &= 0x3FFF;
                self.high |= 0x4000;
                self.code ^= 0x4000;
            }
            self.low = (self.low << 1) & 0xFFFF;
            self.high = ((self.high << 1) | 1) & 0xFFFF;
            self.code = ((self.code << 1) | self.br.bit()) & 0xFFFF;
        }
    }
}

/// Folder-scoped Quantum state: the window and the models outlive every frame.
pub(crate) struct QuantumDecompressor {
    window: Vec<u8>,
    /// Write cursor, modulo the window size.
    wpos: usize,
    /// Bytes decoded so far in this folder, to detect matches reaching back
    /// before anything was written.
    produced: u64,
    selector: Model,
    literal: [Model; 4],
    /// Position models for match lengths 3, 4 and >= 5.
    position: [Model; 3],
    length: Model,
}

impl QuantumDecompressor {
    /// `window_bits` is the exponent from `typeCompress` bits 8..12 (10..=21).
    pub(crate) fn new(window_bits: u16) -> io::Result<Self> {
        if !(10..=21).contains(&window_bits) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Quantum: invalid window exponent {window_bits}"),
            ));
        }
        let w = window_bits as usize;
        // The position models are sized from the window: only 2*W slots are
        // reachable, and the two short-match models are further capped. Sizing
        // these from a constant desynchronises decoding rather than erroring.
        let slots_long = 2 * w;
        Ok(QuantumDecompressor {
            window: vec![0; 1usize << w],
            wpos: 0,
            produced: 0,
            selector: Model::new(0, 7),
            literal: [
                Model::new(0, 64),
                Model::new(64, 64),
                Model::new(128, 64),
                Model::new(192, 64),
            ],
            position: [
                Model::new(0, slots_long.min(24)),
                Model::new(0, slots_long.min(36)),
                Model::new(0, slots_long),
            ],
            length: Model::new(0, 27),
        })
    }

    /// Decode one frame (one CFDATA block) of `out_len` bytes.
    pub(crate) fn decompress_block(&mut self, data: &[u8], out_len: usize) -> io::Result<Vec<u8>> {
        if out_len > FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Quantum: frame declares {out_len} bytes, max is {FRAME_SIZE}"),
            ));
        }
        let mut out = Vec::with_capacity(out_len);
        let mut dec = Decoder::new(data);
        let mask = self.window.len() - 1;

        while out.len() < out_len {
            let selector = dec.decode_symbol(&mut self.selector)?;
            match selector {
                0..=3 => {
                    let byte = dec.decode_symbol(&mut self.literal[selector as usize])? as u8;
                    self.window[self.wpos] = byte;
                    self.wpos = (self.wpos + 1) & mask;
                    self.produced += 1;
                    out.push(byte);
                }
                4..=6 => {
                    // For selector 6 the LENGTH is decoded before the position;
                    // reversing them desynchronises the stream.
                    let (len, pos_model) = if selector == 6 {
                        let slot = dec.decode_symbol(&mut self.length)? as usize;
                        if slot >= 27 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Quantum: length slot out of range",
                            ));
                        }
                        let extra = dec.br.bits(length_extra(slot));
                        (length_base(slot) + extra + 5, 2usize)
                    } else if selector == 4 {
                        (3u32, 0usize)
                    } else {
                        (4u32, 1usize)
                    };

                    let m = &mut self.position[pos_model];
                    let slot = dec.decode_symbol(m)? as usize;
                    let extra = dec.br.bits(position_extra(slot));
                    let offset = position_base(slot) + extra + 1;

                    // A match may freely wrap the window, but never overshoot the
                    // frame: the encoder guarantees it, so an overshoot means
                    // corrupt or misparsed input. Reject rather than truncate —
                    // a truncated match leaves the window and models in a state
                    // that goes on producing plausible garbage.
                    if out.len() + len as usize > out_len {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Quantum: match overshoots the end of the frame",
                        ));
                    }
                    // A match may reach back before anything was written in this
                    // folder. No encoder produces that, but the window is
                    // zero-filled, so the result is well defined and reference
                    // decoders hand it back rather than refusing. exav decodes
                    // what a real extractor decodes: refusing here would let an
                    // attacker put content out of reach of the scan by shipping
                    // a CAB the victim's extractor opens without complaint.
                    // `src` is masked to the window below, so this stays in
                    // bounds whatever the offset.

                    // Byte at a time, mandatory: `offset` may be less than `len`,
                    // in which case the copy is self-overlapping and produces a
                    // periodic run. A block move that reads the source before
                    // writing gives the wrong answer.
                    let mut src = (self.wpos + self.window.len() - offset as usize) & mask;
                    for _ in 0..len {
                        let b = self.window[src];
                        self.window[self.wpos] = b;
                        src = (src + 1) & mask;
                        self.wpos = (self.wpos + 1) & mask;
                        out.push(b);
                    }
                    self.produced += len as u64;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Quantum: selector out of range",
                    ))
                }
            }
        }

        // A few bits of over-read are normal at frame end (the coder runs 16
        // bits ahead). A large one means we were decoding something that was not
        // a Quantum frame.
        if dec.br.overrun > 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Quantum: ran past the end of the compressed block",
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_tables_match_the_format() {
        // Spot values from the specification's table.
        assert_eq!((position_base(0), position_extra(0)), (0, 0));
        assert_eq!((position_base(4), position_extra(4)), (4, 1));
        assert_eq!((position_base(8), position_extra(8)), (16, 3));
        assert_eq!((position_base(20), position_extra(20)), (1024, 9));
        assert_eq!((position_base(41), position_extra(41)), (1572864, 19));
        // Slot 2W-1 must end exactly at 2^W, which is what makes 2W slots the
        // right count for a 2^W window.
        for w in 10..=21usize {
            let last = 2 * w - 1;
            let end = position_base(last) + (1u32 << position_extra(last));
            assert_eq!(end, 1u32 << w, "window {w} slot {last}");
        }
    }

    #[test]
    fn length_table_covers_5_to_259_contiguously() {
        let mut next = 5u32;
        for slot in 0..27 {
            let base = length_base(slot) + 5;
            assert_eq!(base, next, "slot {slot} starts a gap");
            next = base + (1u32 << length_extra(slot));
        }
        assert_eq!(next, 260, "coverage must end at 259 inclusive");
    }

    #[test]
    fn model_starts_uniform_and_totals_its_slot_count() {
        let m = Model::new(64, 64);
        assert_eq!(m.total(), 64);
        assert_eq!(m.sym[0], 64);
        assert_eq!(m.sym[63], 127);
        assert_eq!(m.cum[64], 0, "sentinel");
        for i in 0..64 {
            assert_eq!(m.cum[i] - m.cum[i + 1], 1, "every symbol starts at 1");
        }
    }

    #[test]
    fn rescale_keeps_every_symbol_reachable() {
        // Drive one symbol hard enough to force many rescales, including the
        // reordering ones, and check the model stays well-formed: strictly
        // decreasing cumulative frequencies, so every symbol keeps a non-zero
        // interval and remains decodable.
        let mut m = Model::new(0, 27);
        for _ in 0..5000 {
            m.update(3);
            for i in 0..m.sym.len() {
                assert!(
                    m.cum[i] > m.cum[i + 1],
                    "symbol at slot {i} lost its frequency interval"
                );
            }
        }
        let mut seen: Vec<u16> = m.sym.clone();
        seen.sort_unstable();
        assert_eq!(seen, (0..27).collect::<Vec<u16>>(), "a symbol went missing");
    }

    #[test]
    fn rejects_an_impossible_window() {
        assert!(QuantumDecompressor::new(9).is_err());
        assert!(QuantumDecompressor::new(22).is_err());
        assert!(QuantumDecompressor::new(15).is_ok());
    }
}
