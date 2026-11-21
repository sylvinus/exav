//! The PKZIP 1.x methods of a ZIP member: Shrink (1), Reduce (2 to 5) and
//! Implode (6), written from APPNOTE.TXT sections 5.1 to 5.3 (PKWARE's public
//! specification).
//!
//! Each decodes as it is read. The memory of a decoder depends on the format
//! only (a 13-bit code table, a window of 8 KiB), never on a size the archive
//! declares. A member of a known size ends at that size; one of an unknown size
//! ends where its input does, at a code boundary.

use std::io::{self, BufRead, BufReader, Read};

/// Both windows of Implode (4 KiB and 8 KiB) and the widest of Reduce (4 KiB).
const WINDOW: usize = 8192;
/// Shrink's codes are at most 13 bits.
const TABLE: usize = 1 << 13;
const DLE: u8 = 144;
/// What a decoder reads at most to pass on in one call.
const BATCH: usize = 4096;

fn invalid(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why)
}

fn cut() -> io::Error {
    io::ErrorKind::UnexpectedEof.into()
}

/// Bits taken from the low end of each byte first.
struct Bits<'a> {
    src: BufReader<Box<dyn Read + 'a>>,
    acc: u32,
    held: u32,
}

impl<'a> Bits<'a> {
    fn new(raw: Box<dyn Read + 'a>) -> Self {
        Bits {
            src: BufReader::new(raw),
            acc: 0,
            held: 0,
        }
    }

    fn next_byte(&mut self) -> io::Result<Option<u8>> {
        loop {
            match self.src.fill_buf() {
                Ok([]) => return Ok(None),
                Ok(b) => {
                    let v = b[0];
                    self.src.consume(1);
                    return Ok(Some(v));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// `want` bits, at most 16.
    fn get(&mut self, want: u32) -> io::Result<u32> {
        while self.held < want {
            let b = self.next_byte()?.ok_or_else(cut)?;
            self.acc |= u32::from(b) << self.held;
            self.held += 8;
        }
        let v = self.acc & ((1u32 << want) - 1);
        self.acc >>= want;
        self.held -= want;
        Ok(v)
    }

    /// Whether less than a byte is left: what remains is padding, or a code
    /// cut short.
    fn at_end(&mut self) -> io::Result<bool> {
        if self.held >= 8 {
            return Ok(false);
        }
        loop {
            match self.src.fill_buf() {
                Ok(b) => return Ok(b.is_empty()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// The last `WINDOW` bytes written, zero before the start (APPNOTE 5.2.5 and
/// 5.3.9).
struct Window {
    buf: Vec<u8>,
    at: usize,
}

impl Window {
    fn new() -> Self {
        Window {
            buf: vec![0; WINDOW],
            at: 0,
        }
    }

    fn put(&mut self, b: u8, out: &mut Vec<u8>) {
        self.buf[self.at] = b;
        self.at = (self.at + 1) % WINDOW;
        out.push(b);
    }

    /// `len` bytes from `dist` back, `dist` in `1..=WINDOW`.
    fn copy(&mut self, dist: usize, len: usize, out: &mut Vec<u8>) {
        let mut from = (self.at + WINDOW - dist) % WINDOW;
        for _ in 0..len {
            let b = self.buf[from];
            from = (from + 1) % WINDOW;
            self.put(b, out);
        }
    }
}

/// What a step of a decoder came to.
enum Step {
    More,
    /// The input ended where a code could start.
    End,
}

// ---- Shrink (APPNOTE 5.1) ----

struct Shrink<'a> {
    bits: Bits<'a>,
    /// Bits per code, 9 to 13.
    size: u32,
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    used: Vec<bool>,
    /// No code below this one is free.
    hint: usize,
    prev: Option<usize>,
}

impl<'a> Shrink<'a> {
    fn new(bits: Bits<'a>) -> Self {
        Shrink {
            bits,
            size: 9,
            prefix: vec![0; TABLE],
            suffix: vec![0; TABLE],
            used: vec![false; TABLE],
            hint: 257,
            prev: None,
        }
    }

    /// The lowest code free to take a new string.
    fn free_slot(&mut self) -> Option<usize> {
        while self.hint < TABLE && self.used[self.hint] {
            self.hint += 1;
        }
        (self.hint < TABLE).then_some(self.hint)
    }

    /// The string of `code`, appended to `out`.
    fn expand(&self, code: usize, out: &mut Vec<u8>) -> io::Result<()> {
        let start = out.len();
        let mut c = code;
        for _ in 0..=TABLE {
            if c < 256 {
                out.push(c as u8);
                out[start..].reverse();
                return Ok(());
            }
            if !self.used[c] {
                break;
            }
            out.push(self.suffix[c]);
            c = usize::from(self.prefix[c]);
        }
        out.truncate(start);
        Err(invalid("shrink: a code with no string"))
    }

    /// Frees every code that no other code builds on (5.1.3).
    fn clear(&mut self) {
        let mut parent = vec![false; TABLE];
        for c in 257..TABLE {
            if self.used[c] {
                parent[usize::from(self.prefix[c])] = true;
            }
        }
        for (used, parent) in self.used.iter_mut().zip(&parent).skip(257) {
            *used &= *parent;
        }
        self.hint = 257;
    }

    fn advance(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        let code = self.bits.get(self.size)? as usize;
        if code == 256 {
            match self.bits.get(self.size)? {
                1 if self.size < 13 => self.size += 1,
                1 => return Err(invalid("shrink: a code size past 13 bits")),
                2 => self.clear(),
                _ => return Err(invalid("shrink: an unknown control code")),
            }
            return Ok(());
        }
        let slot = self.free_slot();
        let start = out.len();
        if code < 256 || self.used[code] {
            self.expand(code, out)?;
        } else if let (Some(prev), true) = (self.prev, slot == Some(code)) {
            // The string about to be added: the previous one and its first byte.
            self.expand(prev, out)?;
            let first = out[start];
            out.push(first);
        } else {
            return Err(invalid("shrink: a code with no string"));
        }
        if let (Some(prev), Some(slot)) = (self.prev, slot) {
            self.prefix[slot] = prev as u16;
            self.suffix[slot] = out[start];
            self.used[slot] = true;
        }
        self.prev = Some(code);
        Ok(())
    }
}

// ---- Reduce (APPNOTE 5.2) ----

struct Reduce<'a> {
    bits: Bits<'a>,
    win: Window,
    /// The follower sets, 32 bytes of room each.
    followers: Vec<u8>,
    count: [u8; 256],
    /// Bits of an index into the set of each byte.
    width: [u32; 256],
    last: usize,
    state: u8,
    /// Bits of the length in the byte after the marker.
    len_bits: u32,
    v: u8,
    len: usize,
}

impl<'a> Reduce<'a> {
    fn new(mut bits: Bits<'a>, factor: u32) -> io::Result<Self> {
        let mut followers = vec![0u8; 256 * 32];
        let mut count = [0u8; 256];
        let mut width = [1u32; 256];
        for j in (0..256).rev() {
            let n = bits.get(6)? as usize;
            if n > 32 {
                return Err(invalid("reduce: a follower set of more than 32 bytes"));
            }
            for k in 0..n {
                followers[j * 32 + k] = bits.get(8)? as u8;
            }
            count[j] = n as u8;
            // Bits to write n - 1, and at least one.
            width[j] = (u32::BITS - (n as u32).saturating_sub(1).leading_zeros()).max(1);
        }
        Ok(Reduce {
            bits,
            win: Window::new(),
            followers,
            count,
            width,
            last: 0,
            state: 0,
            len_bits: 8 - factor,
            v: 0,
            len: 0,
        })
    }

    fn advance(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        let set = self.last;
        let n = self.count[set];
        let c = if n == 0 || self.bits.get(1)? != 0 {
            self.bits.get(8)? as u8
        } else {
            let i = self.bits.get(self.width[set])? as usize;
            if i >= usize::from(n) {
                return Err(invalid("reduce: an index past its follower set"));
            }
            self.followers[set * 32 + i]
        };
        self.last = usize::from(c);
        let mask = (1u8 << self.len_bits) - 1;
        match self.state {
            0 if c == DLE => self.state = 1,
            0 => self.win.put(c, out),
            1 if c == 0 => {
                self.win.put(DLE, out);
                self.state = 0;
            }
            1 => {
                self.v = c;
                self.len = usize::from(c & mask);
                self.state = if c & mask == mask { 2 } else { 3 };
            }
            2 => {
                self.len += usize::from(c);
                self.state = 3;
            }
            _ => {
                let high = usize::from(self.v >> self.len_bits);
                self.win
                    .copy((high << 8 | usize::from(c)) + 1, self.len + 3, out);
                self.state = 0;
            }
        }
        Ok(())
    }
}

// ---- Implode (APPNOTE 5.3) ----

/// The Shannon-Fano code of 5.3.8, read a bit at a time from its first bit.
struct Tree {
    /// The first code of each length, right aligned.
    first: [u32; 17],
    count: [u16; 17],
    /// Where the symbols of each length begin in `syms`.
    start: [u16; 17],
    /// Symbols in the order of their codes, the shortest length last.
    syms: Vec<u16>,
}

impl Tree {
    /// A tree of `n` symbols as stored at the start of the data (5.3.7).
    fn read(bits: &mut Bits<'_>, n: usize) -> io::Result<Tree> {
        let rows = bits.get(8)? + 1;
        let mut lens: Vec<u8> = Vec::with_capacity(n);
        for _ in 0..rows {
            let b = bits.get(8)?;
            let run = (b >> 4) as usize + 1;
            if lens.len() + run > n {
                return Err(invalid("implode: a tree with more lengths than symbols"));
            }
            lens.resize(lens.len() + run, (b & 15) as u8 + 1);
        }
        if lens.len() != n {
            return Err(invalid("implode: a tree with fewer lengths than symbols"));
        }
        Tree::build(&lens)
    }

    fn build(lens: &[u8]) -> io::Result<Tree> {
        let mut order: Vec<usize> = (0..lens.len()).collect();
        // Stable: equal lengths keep their order in the file.
        order.sort_by_key(|&i| lens[i]);
        let mut t = Tree {
            first: [0; 17],
            count: [0; 17],
            start: [0; 17],
            syms: Vec::with_capacity(lens.len()),
        };
        let (mut code, mut step, mut last) = (0u32, 0u32, 0u8);
        for &sym in order.iter().rev() {
            code += step;
            let len = lens[sym];
            if len != last {
                last = len;
                step = 1 << (16 - len);
            }
            if code >= 1 << 16 {
                return Err(invalid("implode: code lengths that no code has room for"));
            }
            let l = usize::from(len);
            if t.count[l] == 0 {
                t.first[l] = code >> (16 - len);
                t.start[l] = t.syms.len() as u16;
            }
            t.count[l] += 1;
            t.syms.push(sym as u16);
        }
        Ok(t)
    }

    fn decode(&self, bits: &mut Bits<'_>) -> io::Result<usize> {
        let mut code = 0u32;
        for l in 1..=16 {
            code = code << 1 | bits.get(1)?;
            if self.count[l] > 0 && code >= self.first[l] {
                let k = code - self.first[l];
                if k < u32::from(self.count[l]) {
                    return Ok(usize::from(
                        self.syms[usize::from(self.start[l]) + k as usize],
                    ));
                }
            }
        }
        Err(invalid("implode: bits that are no code"))
    }
}

struct Implode<'a> {
    bits: Bits<'a>,
    win: Window,
    literals: Option<Tree>,
    lengths: Tree,
    distances: Tree,
    /// Bits of the distance read apart from its tree: 6 for a 4 KiB window, 7
    /// for 8 KiB.
    low_bits: u32,
    min_len: usize,
}

impl<'a> Implode<'a> {
    fn new(mut bits: Bits<'a>, flags: u16) -> io::Result<Self> {
        let literals = if flags & 4 != 0 {
            Some(Tree::read(&mut bits, 256)?)
        } else {
            None
        };
        let lengths = Tree::read(&mut bits, 64)?;
        let distances = Tree::read(&mut bits, 64)?;
        Ok(Implode {
            bits,
            win: Window::new(),
            min_len: if literals.is_some() { 3 } else { 2 },
            literals,
            lengths,
            distances,
            low_bits: if flags & 2 != 0 { 7 } else { 6 },
        })
    }

    fn advance(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        if self.bits.get(1)? != 0 {
            let b = match &self.literals {
                Some(t) => t.decode(&mut self.bits)? as u8,
                None => self.bits.get(8)? as u8,
            };
            self.win.put(b, out);
            return Ok(());
        }
        let low = self.bits.get(self.low_bits)? as usize;
        let high = self.distances.decode(&mut self.bits)?;
        let sym = self.lengths.decode(&mut self.bits)?;
        let mut len = sym + self.min_len;
        if sym == 63 {
            len += self.bits.get(8)? as usize;
        }
        self.win.copy((high << self.low_bits | low) + 1, len, out);
        Ok(())
    }
}

// ---- The reader ----

enum Codec<'a> {
    /// A member of no bytes: nothing is read.
    Empty,
    Shrink(Box<Shrink<'a>>),
    Reduce(Box<Reduce<'a>>),
    Implode(Box<Implode<'a>>),
}

impl<'a> Codec<'a> {
    fn advance(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Codec::Empty => Ok(()),
            Codec::Shrink(c) => c.advance(out),
            Codec::Reduce(c) => c.advance(out),
            Codec::Implode(c) => c.advance(out),
        }
    }

    fn bits(&mut self) -> Option<&mut Bits<'a>> {
        match self {
            Codec::Empty => None,
            Codec::Shrink(c) => Some(&mut c.bits),
            Codec::Reduce(c) => Some(&mut c.bits),
            Codec::Implode(c) => Some(&mut c.bits),
        }
    }

    /// Whether the decoder is between two elements of its stream.
    fn between(&self) -> bool {
        match self {
            Codec::Reduce(c) => c.state == 0,
            _ => true,
        }
    }

    fn step(&mut self, out: &mut Vec<u8>) -> io::Result<Step> {
        let Some(bits) = self.bits() else {
            return Ok(Step::End);
        };
        let padding_only = bits.at_end()?;
        match self.advance(out) {
            Ok(()) => Ok(Step::More),
            Err(e)
                if e.kind() == io::ErrorKind::UnexpectedEof && padding_only && self.between() =>
            {
                Ok(Step::End)
            }
            Err(e) => Err(e),
        }
    }
}

struct Legacy<'a> {
    codec: Codec<'a>,
    pending: Vec<u8>,
    at: usize,
    /// Bytes still to come, when the member declares its size.
    left: Option<u64>,
    failed: Option<(io::ErrorKind, String)>,
    finished: bool,
}

impl Read for Legacy<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min(BATCH);
        loop {
            if self.at < self.pending.len() {
                let n = buf.len().min(self.pending.len() - self.at);
                buf[..n].copy_from_slice(&self.pending[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            self.pending.clear();
            self.at = 0;
            if let Some((kind, why)) = &self.failed {
                return Err(io::Error::new(*kind, why.clone()));
            }
            if self.finished {
                return Ok(0);
            }
            while self.pending.len() < want && self.failed.is_none() && !self.finished {
                if self.left == Some(0) {
                    self.finished = true;
                    break;
                }
                let before = self.pending.len();
                match self.codec.step(&mut self.pending) {
                    Ok(Step::More) => {}
                    // The input ran out: of a member of a declared size, that
                    // is a cut.
                    Ok(Step::End) if self.left.is_some() => {
                        self.failed = Some((io::ErrorKind::UnexpectedEof, cut().to_string()));
                    }
                    Ok(Step::End) => self.finished = true,
                    Err(e) => self.failed = Some((e.kind(), e.to_string())),
                }
                if let Some(left) = self.left {
                    let made = ((self.pending.len() - before) as u64).min(left);
                    self.pending.truncate(before + made as usize);
                    self.left = Some(left - made);
                }
            }
        }
    }
}

/// A decoder for ZIP `method` 1 to 6 over the member's raw bytes. `flags` are
/// the general purpose bits of its header (Implode takes its window and its
/// trees from them); `size` is the uncompressed size, `None` when unknown. An
/// error is the codec's own header cut short (`UnexpectedEof`) or unreadable.
pub(crate) fn decoder<'a>(
    method: u16,
    raw: Box<dyn Read + 'a>,
    flags: u16,
    size: Option<u64>,
) -> io::Result<Box<dyn Read + 'a>> {
    let codec = if size == Some(0) {
        Codec::Empty
    } else {
        let bits = Bits::new(raw);
        match method {
            1 => Codec::Shrink(Box::new(Shrink::new(bits))),
            2..=5 => Codec::Reduce(Box::new(Reduce::new(bits, u32::from(method) - 1)?)),
            6 => Codec::Implode(Box::new(Implode::new(bits, flags)?)),
            _ => return Err(invalid("not a PKZIP 1.x method")),
        }
    };
    Ok(Box::new(Legacy {
        codec,
        pending: Vec::new(),
        at: 0,
        left: size,
        failed: None,
        finished: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(value, bits)` fields packed low bit first.
    fn pack(fields: &[(u32, u32)]) -> Vec<u8> {
        let (mut out, mut acc, mut held) = (Vec::new(), 0u64, 0u32);
        for &(v, n) in fields {
            acc |= u64::from(v) << held;
            held += n;
            while held >= 8 {
                out.push(acc as u8);
                acc >>= 8;
                held -= 8;
            }
        }
        if held > 0 {
            out.push(acc as u8);
        }
        out
    }

    /// Everything the decoder gives, and how it ended.
    fn run(method: u16, raw: &[u8], flags: u16, size: Option<u64>) -> (Vec<u8>, io::Result<()>) {
        let mut r = decoder(method, Box::new(raw), flags, size).unwrap();
        let mut out = Vec::new();
        let mut chunk = [0u8; 7];
        loop {
            match r.read(&mut chunk) {
                Ok(0) => return (out, Ok(())),
                Ok(n) => out.extend_from_slice(&chunk[..n]),
                Err(e) => return (out, Err(e)),
            }
        }
    }

    /// A stream of the codes `a`, `b`, `c` at 9 bits.
    fn abc() -> Vec<u8> {
        pack(&[(97, 9), (98, 9), (99, 9)])
    }

    #[test]
    fn shrink_of_unknown_size_ends_with_its_input() {
        let (out, end) = run(1, &abc(), 0, None);
        assert_eq!(out, b"abc");
        assert!(end.is_ok());
    }

    #[test]
    fn shrink_of_declared_size_ends_at_that_size_or_is_cut() {
        let (out, end) = run(1, &abc(), 0, Some(2));
        assert_eq!(out, b"ab");
        assert!(end.is_ok());
        let (out, end) = run(1, &abc(), 0, Some(4));
        assert_eq!(out, b"abc");
        assert_eq!(end.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_declared_size_can_end_inside_a_string() {
        // `a`, `b`, then code 257, the string `ab` they made.
        let raw = pack(&[(97, 9), (98, 9), (257, 9)]);
        assert_eq!(run(1, &raw, 0, Some(4)).0, b"abab");
        let (out, end) = run(1, &raw, 0, Some(3));
        assert_eq!(out, b"aba");
        assert!(end.is_ok());
    }

    /// Follower sets all empty: every byte of the data is a literal of 8 bits.
    fn reduce_stream(data: &[u8]) -> Vec<u8> {
        let mut fields = vec![(0, 6); 256];
        fields.extend(data.iter().map(|&b| (u32::from(b), 8)));
        pack(&fields)
    }

    #[test]
    fn reduce_escapes_the_marker_and_copies_back() {
        // 'h', DLE 0 (a literal DLE), 'i'; then 'a' and DLE with V = 2 and
        // distance byte 0: 2 + 3 bytes from one back (factor 4: 4 length bits).
        let raw = reduce_stream(&[b'h', 144, 0, b'i', b'a', 144, 2, 0]);
        let (out, end) = run(5, &raw, 0, None);
        assert_eq!(out, b"h\x90iaaaaaa");
        assert!(end.is_ok());
    }

    #[test]
    fn reduce_cut_inside_a_copy_is_cut_not_clean() {
        let raw = reduce_stream(&[b'a', 144, 2]);
        let (out, end) = run(5, &raw, 0, None);
        assert_eq!(out, b"a");
        assert_eq!(end.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_header_cut_short_is_told_from_one_that_is_wrong() {
        for method in [2, 6] {
            let e = decoder(method, Box::new(&[][..]), 0, Some(10))
                .err()
                .unwrap();
            assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof, "{method}");
        }
        // 64 lengths of 1 bit leave no room for the codes.
        let mut raw = vec![3];
        raw.extend_from_slice(&[0xf0; 4]);
        let e = decoder(6, Box::new(&raw[..]), 0, Some(10)).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_member_of_no_bytes_reads_nothing() {
        for method in 1..=6 {
            let (out, end) = run(method, &[], 0, Some(0));
            assert!(out.is_empty() && end.is_ok(), "{method}");
        }
    }
}
