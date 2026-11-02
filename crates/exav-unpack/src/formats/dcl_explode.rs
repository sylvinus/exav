//! PKWARE Data Compression Library "implode", decoded. Not ZIP's method 6
//! implode: this is the codec of InstallShield `.z` members.
//!
//! The algorithm and the code-length tables are those of Mark Adler's
//! `blast.c` (zlib `contrib/blast`, zlib licence), as the `explode` crate
//! 0.1.2 (Aaron Griffith, MIT) ports them; both attributed in `NOTICE`. This
//! one decodes a slice whole into a capped buffer, which drops `explode`'s
//! byte-at-a-time state machine and its `arraydeque` window: the output is
//! the window.

use crate::Salvaged;

/// `blast.c`'s code lengths, run-length packed: each byte is a length in its
/// low nibble, repeated one more time than its high nibble.
const LITERAL_LENGTHS: &[u8] = &[
    11, 124, 8, 7, 28, 7, 188, 13, 76, 4, 10, 8, 12, 10, 12, 10, 8, 23, 8, 9, 7, 6, 7, 8, 7, 6, 55,
    8, 23, 24, 12, 11, 7, 9, 11, 12, 6, 7, 22, 5, 7, 24, 6, 11, 9, 6, 7, 22, 7, 11, 38, 7, 9, 8,
    25, 11, 8, 11, 9, 12, 8, 12, 5, 38, 5, 38, 5, 11, 7, 5, 6, 21, 6, 10, 53, 8, 7, 24, 10, 27, 44,
    253, 253, 253, 252, 252, 252, 13, 12, 45, 12, 45, 12, 61, 12, 45, 44, 173,
];
const LENGTH_LENGTHS: &[u8] = &[2, 35, 36, 53, 38, 23];
const DISTANCE_LENGTHS: &[u8] = &[2, 20, 53, 230, 247, 151, 248];

const LENGTH_BASE: [usize; 16] = [3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264];
const LENGTH_EXTRA: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
/// The length that ends the stream.
const END: usize = 519;
const MAX_BITS: usize = 13;

/// A canonical Huffman code: how many codes of each length, and the symbols
/// in code order.
struct Huffman {
    count: [u16; MAX_BITS + 1],
    symbol: Vec<u8>,
}

impl Huffman {
    fn new(packed: &[u8]) -> Huffman {
        let mut lengths = Vec::with_capacity(256);
        for &b in packed {
            lengths.extend(std::iter::repeat_n(b & 15, usize::from(b >> 4) + 1));
        }
        let mut count = [0u16; MAX_BITS + 1];
        for &l in &lengths {
            count[usize::from(l)] += 1;
        }
        let mut offs = [0usize; MAX_BITS + 2];
        for len in 1..=MAX_BITS {
            offs[len + 1] = offs[len] + usize::from(count[len]);
        }
        let mut symbol = vec![0u8; offs[MAX_BITS + 1]];
        for (s, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbol[offs[usize::from(l)]] = s as u8;
                offs[usize::from(l)] += 1;
            }
        }
        Huffman { count, symbol }
    }
}

enum Stop {
    /// The input ended before the end code.
    Truncated,
    /// The input is not a DCL stream.
    Invalid,
    /// The output reached the cap.
    Full,
}

struct Bits<'a> {
    input: &'a [u8],
    pos: usize,
    buf: u32,
    count: u32,
}

impl Bits<'_> {
    fn bits(&mut self, n: u32) -> Result<u32, Stop> {
        while self.count < n {
            let b = *self.input.get(self.pos).ok_or(Stop::Truncated)?;
            self.pos += 1;
            self.buf |= u32::from(b) << self.count;
            self.count += 8;
        }
        let v = self.buf & ((1 << n) - 1);
        self.buf >>= n;
        self.count -= n;
        Ok(v)
    }

    /// One symbol of `h`. The codes are stored bit-inverted.
    fn decode(&mut self, h: &Huffman) -> Result<usize, Stop> {
        let (mut code, mut first, mut index) = (0usize, 0usize, 0usize);
        for len in 1..=MAX_BITS {
            code |= (self.bits(1)? ^ 1) as usize;
            let count = usize::from(h.count[len]);
            if code < first + count {
                return Ok(usize::from(h.symbol[index + code - first]));
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(Stop::Invalid)
    }
}

/// Decode `input` up to `cap` bytes, salvaging what came out before an
/// error, as [`crate::salvage`] reports a reader's.
pub(crate) fn explode(input: &[u8], cap: u64) -> Salvaged {
    let limit = usize::try_from(cap).unwrap_or(usize::MAX).saturating_add(1);
    let mut out = Vec::new();
    let stop = run(input, limit, &mut out);
    let over_cap = out.len() > limit - 1;
    out.truncate(limit - 1);
    Salvaged {
        data: out,
        over_cap,
        undecoded: matches!(stop, Some(Stop::Invalid)),
        cut_short: matches!(stop, Some(Stop::Truncated)),
    }
}

/// `None` at the end code.
fn run(input: &[u8], limit: usize, out: &mut Vec<u8>) -> Option<Stop> {
    let mut b = Bits {
        input,
        pos: 0,
        buf: 0,
        count: 0,
    };
    // Each header byte is judged as it is read: a bad first byte is damage
    // whether or not a second follows.
    let coded = match b.bits(8) {
        Ok(coded @ 0..=1) => coded == 1,
        Ok(_) => return Some(Stop::Invalid),
        Err(e) => return Some(e),
    };
    let dict = match b.bits(8) {
        Ok(dict @ 4..=6) => dict,
        Ok(_) => return Some(Stop::Invalid),
        Err(e) => return Some(e),
    };
    let literal = Huffman::new(LITERAL_LENGTHS);
    let length = Huffman::new(LENGTH_LENGTHS);
    let distance = Huffman::new(DISTANCE_LENGTHS);
    let step = |b: &mut Bits, out: &mut Vec<u8>| -> Result<bool, Stop> {
        if b.bits(1)? == 0 {
            let byte = match coded {
                true => b.decode(&literal)?,
                false => b.bits(8)? as usize,
            };
            out.push(byte as u8);
            return Ok(true);
        }
        let symbol = b.decode(&length)?;
        let len = LENGTH_BASE[symbol] + b.bits(u32::from(LENGTH_EXTRA[symbol]))? as usize;
        if len == END {
            return Ok(false);
        }
        let extra = if len == 2 { 2 } else { dict };
        let dist = (b.decode(&distance)? << extra) + b.bits(extra)? as usize + 1;
        // At most 4,096 back, which the window always holds once that much
        // has come out.
        if dist > out.len() {
            return Err(Stop::Invalid);
        }
        for _ in 0..len {
            out.push(out[out.len() - dist]);
        }
        Ok(true)
    };
    loop {
        if out.len() >= limit {
            return Some(Stop::Full);
        }
        match step(&mut b, out) {
            Ok(true) => {}
            Ok(false) => return None,
            Err(e) => return Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::explode;

    /// `blast.c`'s own example.
    const AIAI: &[u8] = &[0x00, 0x04, 0x82, 0x24, 0x25, 0x8f, 0x80, 0x7f];

    #[test]
    fn blast_example() {
        let s = explode(AIAI, 1 << 20);
        assert_eq!(s.data, b"AIAIAIAIAIAIA");
        assert!(!s.over_cap && !s.undecoded && !s.cut_short);
    }

    #[test]
    fn trailing_bytes_are_left_alone() {
        let mut input = AIAI.to_vec();
        input.push(42);
        assert_eq!(explode(&input, 1 << 20).data, b"AIAIAIAIAIAIA");
    }

    #[test]
    fn a_cut_stream_keeps_what_it_decoded() {
        let s = explode(&AIAI[..AIAI.len() - 1], 1 << 20);
        assert!(s.cut_short && !s.undecoded);
        assert!(b"AIAIAIAIAIAIA".starts_with(&s.data));
    }

    #[test]
    fn the_cap_holds() {
        let s = explode(AIAI, 5);
        assert!(s.over_cap);
        assert_eq!(s.data, b"AIAIA");
    }

    #[test]
    fn a_bad_header_or_distance_is_invalid() {
        assert!(explode(&[2, 4, 0], 100).undecoded);
        assert!(explode(&[0, 7, 0], 100).undecoded);
        // A bad first byte is damage even with no second byte after it, and
        // an input that ends inside the header is cut.
        let s = explode(&[2], 100);
        assert!(s.undecoded && !s.cut_short);
        let s = explode(&[1], 100);
        assert!(s.cut_short && !s.undecoded);
        // A match first, before any output to copy from.
        assert!(explode(&[0, 4, 0xff, 0xff, 0xff], 100).undecoded);
    }

    /// The reference's verdict codes (`dcl_oracle.c`) for what `explode` found:
    /// output past the cap is reported first.
    fn verdict(s: &crate::Salvaged) -> u8 {
        match (s.over_cap, s.cut_short, s.undecoded) {
            (true, _, _) => 1,
            (_, true, _) => 2,
            (_, _, true) => 3,
            _ => 0,
        }
    }

    /// Streams of every kind of damage, against `blast.c`'s verdict and the
    /// bytes it wrote. Needs the oracle built by `tests/oracle/build.sh`:
    /// `EXAV_DCL_ORACLE=... cargo test -p exav-unpack --lib -- --ignored dcl_oracle`.
    #[test]
    #[ignore = "needs the reference decoder: tests/oracle/build.sh, EXAV_DCL_ORACLE"]
    fn dcl_oracle_agrees_on_damaged_streams() {
        let rounds: usize = std::env::var("EXAV_DEBUG_ORACLE_ROUNDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5000);
        let z = crate::read_fixture(&format!(
            "{}/tests/fixtures/ishieldz/undhr.z",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let u32_at = |o: usize| u32::from_le_bytes(z[o..o + 4].try_into().unwrap()) as usize;
        let mut bases: Vec<(Vec<u8>, usize)> = vec![
            (AIAI.to_vec(), 8),
            (z[255..u32_at(41)].to_vec(), 40),
            // Headers of both literal modes and every window, then bit noise.
            (
                vec![0, 4, 0x55, 0xaa, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
                10,
            ),
            (
                vec![1, 6, 0x55, 0xaa, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
                10,
            ),
        ];
        let mut rng = crate::oracle::Rng(0x2545_f491_4f6c_dd1d);
        let mut jobs = Vec::new();
        for (base, hot) in bases.drain(..) {
            jobs.push((u32::MAX >> 8, base.clone()));
            for _ in 0..rounds {
                let bad = rng.damage(&base, hot);
                let cap = match rng.below(3) {
                    0 => 1 << 20,
                    1 => rng.below(base.len() * 8 + 1) as u32,
                    _ => 1 << 24,
                };
                jobs.push((cap, bad));
            }
        }
        // Noise after a valid header, for every window and both literal modes.
        for i in 0..rounds {
            let mut v = vec![(i % 2) as u8, 4 + (i % 3) as u8];
            v.extend((0..1 + rng.below(60)).map(|_| rng.next() as u8));
            jobs.push((1 << 20, v));
        }
        let replies = crate::oracle::run("EXAV_DCL_ORACLE", &[], &jobs);
        let mut bad = Vec::new();
        let mut matrix = [[0usize; 4]; 4];
        for ((cap, input), reply) in jobs.iter().zip(&replies) {
            let s = explode(input, u64::from(*cap));
            let ours = verdict(&s);
            matrix[usize::from(reply.0)][usize::from(ours)] += 1;
            // Past the cap the reference may meet an error first, in the
            // window it was writing.
            let at_cap = reply.1.len() == *cap as usize && ours == 1;
            if s.data != reply.1 || (ours != reply.0 && !at_cap) {
                crate::oracle::dump("dcl", bad.len(), input, &reply.1, &s.data);
                bad.push((
                    *cap,
                    reply.0,
                    reply.1.len(),
                    ours,
                    s.data.len(),
                    input.clone(),
                ));
            }
        }
        eprintln!(
            "{} streams; rows the reference's verdict (ok, full, cut, error), columns ours: {matrix:?}",
            jobs.len()
        );
        for (cap, status, written, ours, data, input) in bad.iter().take(5) {
            eprintln!(
                "cap {cap}: reference ({status}, {written} bytes), ours ({ours}, {data} bytes), input {:02x?}",
                &input[..input.len().min(32)]
            );
        }
        assert!(
            bad.is_empty(),
            "{} of {} streams differ",
            bad.len(),
            jobs.len()
        );
    }
}
