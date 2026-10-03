//! Literal anchors found in an object, through a few filters that stay in cache
//! instead of an automaton.
//!
//! An automaton is stepped at every byte, and one over a million anchors is
//! tens of megabytes of states, each step a cache miss. Here each anchor is
//! indexed by windows of its bytes instead: the anchor itself when it is 1 to
//! 3 bytes long, 4 bytes of it when it is 4 or 5, and when it is longer, which
//! is nearly all of them, [`STRIDE`] consecutive 6-byte windows (4 bytes again
//! if it has no such windows that are not one repeated byte). A scan reads
//! the bytes at every position of the object once, folded to lowercase. The
//! short windows are looked up at every position, first in one table of the
//! first two bytes of every short window; the long ones only at every
//! [`STRIDE`]th position, which one of an anchor's consecutive windows always
//! starts at, in a filter of a few megabytes. Only a position that passes is
//! looked up in the width's table of windows, and every anchor behind that
//! window compared whole.
//!
//! An anchor's windows are the ones the signature set shares least, since
//! every anchor behind a window is compared wherever the window occurs.
//! Windows are case-folded for the case-sensitive anchors as for the others,
//! so one lookup serves both; a case-sensitive anchor is then compared exactly.
//!
//! An anchor made of one repeated byte is indexed by its first bytes. Inside
//! a long run of its byte it matches at every position, and there it is
//! reported as one run of starts rather than looked up position by position:
//! a run of zeros costs what its edges do ([`sweep`]).
//!
//! The index is stored as its anchors and, per width, the windows they are
//! found by; the tables a scan looks up are derived from those at load.

mod rarity;
mod sweep;

#[cfg(feature = "yara")]
pub(crate) use rarity::structural;
#[cfg(test)]
pub(crate) use rarity::FILTER_MIN_BODIES;
pub(crate) use rarity::{anchor_score, GramStats};
pub(crate) use sweep::sweep;
#[cfg(test)]
pub(crate) use sweep::{MIN_SKIP_RUN, NO_RUN_COLLAPSE, SWEEP_WINDOW};

use crate::byte_source::ByteSource;

/// ASCII lowercasing, as a table.
pub(crate) static FOLD: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = (i as u8).to_ascii_lowercase();
        i += 1;
    }
    t
};

/// Bytes of each width of window, narrowest first.
const WIDTH: [usize; 5] = [1, 2, 3, 4, 6];

/// The classes of window the two-byte table answers for: exactly for the
/// first two, as a first filter for the others.
const SHORT: usize = 4;

/// The class of the widest windows, which index the long anchors.
const LONG: usize = 4;

/// The widest window: positions whose window lies inside a skipped run hold
/// no anchor but one of its byte.
pub(crate) const GRAM: usize = WIDTH[LONG];

/// One position in this many is looked up for the long windows; a long anchor
/// is indexed by as many consecutive windows, so one of them starts there.
/// Fewer lookups against more keys in the filter.
const STRIDE: usize = 2;

/// Positions read and looked up together: their filter words are loaded
/// before any is tested, so the processor waits on them at once.
const BATCH: usize = 8;

/// An empty slot of a window table.
const EMPTY: u32 = u32::MAX;

/// Bits of filter per distinct window.
const FILTER_BITS_PER_KEY: usize = 64;

/// Largest filter, in words: 8 MiB.
const MAX_FILTER_WORDS: usize = 1 << 20;

/// One anchor behind a window: its bytes in the pool, lowercased when it is
/// case-insensitive, and where the window starts in it.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Entry {
    off: u32,
    len: u32,
    back: u32,
    /// The partition, with [`NOCASE`] set when the anchor is case-insensitive.
    part: u32,
    value: u32,
    /// For an anchor of one repeated byte, its index in [`Grams::uniform`]
    /// plus one; zero for any other. Derived, not stored.
    run: u32,
}

/// [`Entry::part`]'s flag for a case-insensitive anchor.
const NOCASE: u32 = 1 << 31;

/// The windows of one width.
#[derive(Default)]
struct Class {
    /// Two bits per window, both in one word. Empty for the classes the
    /// two-byte table answers for exactly.
    filter: Vec<u64>,
    /// The distinct windows, open-addressed: an index into `keys`, or [`EMPTY`].
    slots: Vec<u32>,
    keys: Vec<u64>,
    /// Window `i`'s anchors are `entries[start[i]..start[i + 1]]`.
    start: Vec<u32>,
    /// Sorted by window.
    entries: Vec<Entry>,
}

/// An anchor of one byte repeated, reported by runs of it.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Uniform {
    /// The byte, lowercased when case-insensitive.
    byte: u8,
    len: u32,
    part: u32,
    value: u32,
}

/// The anchors of every partition.
#[derive(Default)]
pub(crate) struct Grams {
    classes: [Class; 5],
    pool: Vec<u8>,
    uniform: Vec<Uniform>,
    /// Per first two bytes of a window, folded: bit `c` when a window of
    /// class `c < SHORT` starts with them.
    first: Vec<u8>,
}

/// One object's scan: the partitions to report, the object, and per anchor of
/// one repeated byte, the start below which its run has been reported.
pub(crate) struct Scan<'a, H: ?Sized> {
    active: &'a [bool],
    hay: &'a H,
    marks: Vec<usize>,
}

/// An anchor to index: its partition, case, value in that partition, and
/// bytes, which the index lowercases when case-insensitive.
pub(crate) struct IndexAnchor<'a> {
    pub(crate) part: u32,
    pub(crate) nocase: bool,
    pub(crate) value: u32,
    pub(crate) bytes: &'a [u8],
}

/// Spreads every bit of a window into the high half and the low bits.
#[inline(always)]
fn mix(k: u64) -> u64 {
    let h = k.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^ (h >> 32)
}

/// ASCII-lowercases each byte of `x`.
#[inline(always)]
fn fold8(x: u64) -> u64 {
    const L: u64 = 0x0101_0101_0101_0101;
    let ascii = !x & (0x80 * L);
    let low = x & (0x7f * L);
    let from_a = low + (0x80 - b'A' as u64) * L;
    let past_z = low + (0x80 - b'Z' as u64 - 1) * L;
    let upper = from_a & !past_z & ascii;
    x | (upper >> 2)
}

/// The bits of a little-endian word that hold a window of `w` bytes.
const fn mask(w: usize) -> u64 {
    if w >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * w)) - 1
    }
}

/// The first bytes of `s`, up to eight, folded, as a little-endian word.
fn word_of(s: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    for (d, &c) in b.iter_mut().zip(s) {
        *d = FOLD[c as usize];
    }
    u64::from_le_bytes(b)
}

fn is_uniform(a: &[u8]) -> bool {
    a.iter().all(|&b| b == a[0])
}

/// Where an anchor is indexed: its class, and where in it each of its windows
/// starts, the ones `stats` says the set shares least.
fn place(a: &[u8], stats: &GramStats) -> (usize, Vec<usize>) {
    let cost = |w: &[u8]| rarity::window_cost(w, stats);
    if a.len() >= GRAM && !is_uniform(a) {
        // `STRIDE` consecutive windows, none of one repeated byte, since a
        // position inside a run is not looked up: the run whose dearest
        // window costs least.
        let costs: Vec<_> = a
            .windows(GRAM)
            .map(|w| (!is_uniform(w)).then(|| cost(w)))
            .collect();
        let best = (0..costs.len().saturating_sub(STRIDE - 1))
            .filter_map(|b| {
                costs[b..b + STRIDE]
                    .iter()
                    .copied()
                    .collect::<Option<Vec<_>>>()
                    .map(|c| (c, b))
            })
            .min_by_key(|(c, b)| (c.iter().max().copied(), *b));
        if let Some((_, b)) = best {
            return (LONG, (b..b + STRIDE).collect());
        }
    }
    let c = match a.len() {
        1 => 0,
        2 => 1,
        3 => 2,
        _ => 3,
    };
    let w = WIDTH[c];
    if is_uniform(a) {
        return (c, vec![0]);
    }
    let back = a
        .windows(w)
        .enumerate()
        .filter(|(_, x)| !is_uniform(x))
        .min_by_key(|&(b, x)| (cost(x), b))
        .map(|(b, _)| b)
        .expect("an anchor of more than one byte value has a varied window");
    (c, vec![back])
}

impl Class {
    /// The class of width `w` over `entries`, sorted by window, whose bytes
    /// are in `pool`.
    fn build(w: usize, pool: &[u8], entries: Vec<Entry>) -> Class {
        let mut c = Class {
            entries,
            ..Class::default()
        };
        if c.entries.is_empty() {
            return c;
        }
        for (i, e) in c.entries.iter().enumerate() {
            let k = window(pool, e, w);
            if c.keys.last() != Some(&k) {
                c.keys.push(k);
                c.start.push(i as u32);
            }
        }
        c.start.push(c.entries.len() as u32);
        if w > 2 {
            let words = (c.keys.len() * FILTER_BITS_PER_KEY / 64)
                .next_power_of_two()
                .clamp(64, MAX_FILTER_WORDS);
            c.filter = vec![0; words];
        }
        c.slots = vec![EMPTY; (c.keys.len() * 2).next_power_of_two()];
        for (i, &k) in c.keys.iter().enumerate() {
            let h = mix(k);
            if !c.filter.is_empty() {
                let w = c.word(h);
                c.filter[w] |= Self::bits(h);
            }
            let mut s = c.slot(h);
            while c.slots[s] != EMPTY {
                s = (s + 1) & (c.slots.len() - 1);
            }
            c.slots[s] = i as u32;
        }
        c
    }

    #[inline(always)]
    fn word(&self, h: u64) -> usize {
        (h >> (64 - self.filter.len().trailing_zeros())) as usize
    }

    #[inline(always)]
    fn bits(h: u64) -> u64 {
        1 << (h & 63) | 1 << ((h >> 6) & 63)
    }

    #[inline(always)]
    fn slot(&self, h: u64) -> usize {
        (h >> 12) as usize & (self.slots.len() - 1)
    }

    /// Whether window `k` may be indexed.
    #[inline(always)]
    fn maybe(&self, k: u64) -> bool {
        let h = mix(k);
        let b = Self::bits(h);
        self.filter[self.word(h)] & b == b
    }

    /// The anchors behind window `k`.
    fn entries(&self, k: u64) -> &[Entry] {
        if self.slots.is_empty() {
            return &[];
        }
        let mut s = self.slot(mix(k));
        loop {
            let i = self.slots[s];
            if i == EMPTY {
                return &[];
            }
            let i = i as usize;
            if self.keys[i] == k {
                return &self.entries[self.start[i] as usize..self.start[i + 1] as usize];
            }
            s = (s + 1) & (self.slots.len() - 1);
        }
    }
}

/// The window of `w` bytes `e` is indexed by, folded.
fn window(pool: &[u8], e: &Entry, w: usize) -> u64 {
    let at = (e.off + e.back) as usize;
    word_of(&pool[at..at + w]) & mask(w)
}

impl Grams {
    /// Index `anchors`, each by the windows `stats` says the set shares least.
    pub(crate) fn build(anchors: &[IndexAnchor], stats: &GramStats) -> Grams {
        let mut pool = Vec::new();
        let mut lists: [Vec<Entry>; 5] = Default::default();
        for a in anchors {
            let off = pool.len() as u32;
            pool.extend(
                a.bytes
                    .iter()
                    .map(|&b| if a.nocase { FOLD[b as usize] } else { b }),
            );
            let (c, backs) = place(&pool[off as usize..], stats);
            lists[c].extend(backs.into_iter().map(|back| Entry {
                off,
                len: a.bytes.len() as u32,
                back: back as u32,
                part: a.part | if a.nocase { NOCASE } else { 0 },
                value: a.value,
                run: 0,
            }));
        }
        for (c, list) in lists.iter_mut().enumerate() {
            list.sort_by_cached_key(|e| (window(&pool, e, WIDTH[c]), e.part, e.value, e.back));
        }
        Grams::index(pool, lists)
    }

    /// The tables a scan looks up, derived from the anchors in `pool` and
    /// each class's entries, sorted by window.
    fn index(pool: Vec<u8>, lists: [Vec<Entry>; 5]) -> Grams {
        let mut g = Grams {
            pool,
            ..Grams::default()
        };
        for (c, mut list) in lists.into_iter().enumerate() {
            for e in &mut list {
                let a = &g.pool[e.off as usize..(e.off + e.len) as usize];
                if e.back == 0 && is_uniform(a) {
                    g.uniform.push(Uniform {
                        byte: a[0],
                        len: e.len,
                        part: e.part,
                        value: e.value,
                    });
                    e.run = g.uniform.len() as u32;
                }
            }
            g.classes[c] = Class::build(WIDTH[c], &g.pool, list);
        }
        let mut t = vec![0u8; 1 << 16];
        for (c, class) in g.classes[..SHORT].iter().enumerate() {
            for &k in &class.keys {
                match WIDTH[c] {
                    1 => (0..256).for_each(|second| t[k as usize | second << 8] |= 1 << c),
                    _ => t[(k & 0xffff) as usize] |= 1 << c,
                }
            }
        }
        g.first = t;
        g
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.classes.iter().all(|c| c.keys.is_empty())
    }

    /// The state of one object's scan: [`Self::scan`] and the rest take it.
    pub(crate) fn start<'a, H: ByteSource + ?Sized>(
        &self,
        active: &'a [bool],
        hay: &'a H,
    ) -> Scan<'a, H> {
        Scan {
            active,
            hay,
            marks: vec![0; self.uniform.len()],
        }
    }

    /// Hand `f` every anchor whose window starts at a position of
    /// `buf[from..to]` where eight bytes can be read. `buf` is the window of
    /// the object at `at`. `false` when `f` asks to stop.
    pub(crate) fn scan<H: ByteSource + ?Sized>(
        &self,
        s: &mut Scan<H>,
        buf: &[u8],
        at: usize,
        from: usize,
        to: usize,
        f: &mut impl FnMut(usize, u32, usize, usize, usize) -> bool,
    ) -> bool {
        let to = to.min(buf.len().saturating_sub(7));
        let upto = at + to;
        let mut i = from;
        while i + BATCH <= to {
            let block: &[u8; BATCH + 7] = buf[i..i + BATCH + 7].try_into().unwrap();
            let x: [u64; BATCH] = std::array::from_fn(|j| {
                fold8(u64::from_le_bytes(block[j..j + 8].try_into().unwrap()))
            });
            if !self.probe_block(s, &x, at + i, buf, at, upto, f) {
                return false;
            }
            i += BATCH;
        }
        for p in i..to {
            let x = fold8(u64::from_le_bytes(buf[p..p + 8].try_into().unwrap()));
            let long = (at + p).is_multiple_of(STRIDE) && self.long_maybe(x);
            if !self.probe(s, x, long, at + p, buf, at, upto, f) {
                return false;
            }
        }
        true
    }

    /// [`Self::scan`] at the positions `from..to` of the object, reading them
    /// from it: those whose eight bytes run past a window held in memory.
    pub(crate) fn scan_source<H: ByteSource + ?Sized>(
        &self,
        s: &mut Scan<H>,
        from: usize,
        to: usize,
        f: &mut impl FnMut(usize, u32, usize, usize, usize) -> bool,
    ) -> bool {
        let to = to.min(s.hay.len());
        if from >= to {
            return true;
        }
        // Past the end of the object the bytes are zeros: an anchor that
        // would need them is refused by its length when compared.
        let mut buf = s.hay.window(from, to - from + 7).into_owned();
        buf.resize(to - from + 7, 0);
        self.scan(s, &buf, from, 0, to - from, f)
    }

    /// Whether the long window of `x` may be indexed.
    #[inline(always)]
    fn long_maybe(&self, x: u64) -> bool {
        let long = &self.classes[LONG];
        !long.filter.is_empty() && long.maybe(x & mask(GRAM))
    }

    /// [`Self::probe`] at the [`BATCH`] positions from `pos`, whose first eight
    /// bytes, folded, are `x`: every long window's filter word is read before
    /// any is tested.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn probe_block<H: ByteSource + ?Sized>(
        &self,
        s: &mut Scan<H>,
        x: &[u64; BATCH],
        pos: usize,
        buf: &[u8],
        at: usize,
        upto: usize,
        f: &mut impl FnMut(usize, u32, usize, usize, usize) -> bool,
    ) -> bool {
        let long = &self.classes[LONG];
        let mut hit = [false; BATCH];
        if !long.filter.is_empty() {
            let first = (STRIDE - pos % STRIDE) % STRIDE;
            let mut h = [0u64; BATCH];
            let mut words = [0u64; BATCH];
            for j in (first..BATCH).step_by(STRIDE) {
                h[j] = mix(x[j] & mask(GRAM));
                words[j] = long.filter[long.word(h[j])];
            }
            for j in (first..BATCH).step_by(STRIDE) {
                let b = Class::bits(h[j]);
                hit[j] = words[j] & b == b;
            }
        }
        (0..BATCH).all(|j| self.probe(s, x[j], hit[j], pos + j, buf, at, upto, f))
    }

    /// Look up the short windows at `pos`, whose first eight bytes, folded,
    /// are `x`, and resolve those that pass, then the long one when `long`
    /// says its filter passed.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn probe<H: ByteSource + ?Sized>(
        &self,
        s: &mut Scan<H>,
        x: u64,
        long: bool,
        pos: usize,
        buf: &[u8],
        at: usize,
        upto: usize,
        f: &mut impl FnMut(usize, u32, usize, usize, usize) -> bool,
    ) -> bool {
        let first = self.first[(x & 0xffff) as usize];
        if first != 0 {
            for (c, class) in self.classes[..SHORT].iter().enumerate() {
                let k = x & mask(WIDTH[c]);
                // A window of two bytes or fewer is answered by the table.
                if first & (1 << c) != 0
                    && (WIDTH[c] <= 2 || class.maybe(k))
                    && !self.resolve(s, class, k, pos, buf, at, upto, f)
                {
                    return false;
                }
            }
        }
        !long
            || self.resolve(
                s,
                &self.classes[LONG],
                x & mask(GRAM),
                pos,
                buf,
                at,
                upto,
                f,
            )
    }

    /// Report the anchors of one repeated byte that match at the positions
    /// `from..to`, inside a run of byte `b` that ends at `end`: each as one
    /// run of starts.
    pub(crate) fn run<H: ByteSource + ?Sized>(
        &self,
        s: &Scan<H>,
        b: u8,
        from: usize,
        to: usize,
        end: usize,
        f: &mut impl FnMut(usize, u32, usize, usize, usize) -> bool,
    ) -> bool {
        for &u in &self.uniform {
            let nocase = u.part & NOCASE != 0;
            let byte_matches = match nocase {
                true => FOLD[b as usize] == u.byte,
                false => b == u.byte,
            };
            let part = (u.part & !NOCASE) as usize;
            if !byte_matches || !s.active[part] {
                continue;
            }
            // A case-insensitive anchor goes on matching past the run, into
            // the other case of its letter.
            let len = u.len as usize;
            let reach = match nocase {
                true => {
                    end + s
                        .hay
                        .window(end, len)
                        .iter()
                        .take_while(|&&c| FOLD[c as usize] == u.byte)
                        .count()
                }
                false => end,
            };
            let last = to.min((reach + 1).saturating_sub(len));
            if last > from && !f(part, u.value, from, len, last - from) {
                return false;
            }
        }
        true
    }

    /// Compare every active anchor behind window `k` of `class`, found at
    /// `pos`, and report those that match. An anchor of one repeated byte is
    /// reported for every start of the run it is in, up to `upto`, at once,
    /// and not again at those starts. Out of line: the loop that calls it
    /// keeps its state in registers.
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn resolve<H: ByteSource + ?Sized>(
        &self,
        sc: &mut Scan<H>,
        class: &Class,
        k: u64,
        pos: usize,
        buf: &[u8],
        at: usize,
        upto: usize,
        f: &mut impl FnMut(usize, u32, usize, usize, usize) -> bool,
    ) -> bool {
        let hay = sc.hay;
        let byte = |q: usize| match q.checked_sub(at) {
            Some(i) if i < buf.len() => buf[i],
            _ => hay.window(q, 1).first().copied().unwrap_or(0),
        };
        for e in class.entries(k) {
            let part = (e.part & !NOCASE) as usize;
            if !sc.active[part] {
                continue;
            }
            let Some(s) = pos.checked_sub(e.back as usize) else {
                continue;
            };
            if e.run != 0 && s < sc.marks[e.run as usize - 1] {
                continue;
            }
            let len = e.len as usize;
            if s + len > hay.len() {
                continue;
            }
            let want = &self.pool[e.off as usize..e.off as usize + len];
            let nocase = e.part & NOCASE != 0;
            let held;
            let got: &[u8] = if s >= at && s + len <= at + buf.len() {
                &buf[s - at..s - at + len]
            } else {
                held = hay.window(s, len);
                &held
            };
            let same = match nocase {
                true => {
                    got.len() == len && got.iter().zip(want).all(|(&g, &w)| FOLD[g as usize] == w)
                }
                false => got == want,
            };
            if !same {
                continue;
            }
            let mut count = 1;
            if e.run != 0 {
                // The rest of the run, as far as a start before `upto` can
                // reach.
                let (b, reach) = (want[0], (upto + len - 1).min(hay.len()));
                let mut q = s + len;
                while q < reach
                    && (if nocase {
                        FOLD[byte(q) as usize]
                    } else {
                        byte(q)
                    }) == b
                {
                    q += 1;
                }
                let last = (q + 1 - len).min(upto).max(s + 1);
                sc.marks[e.run as usize - 1] = last;
                count = last - s;
            }
            if !f(part, e.value, s, len, count) {
                return false;
            }
        }
        true
    }

    /// Write the index: its anchors, and per class, the entries that index
    /// them.
    pub(crate) fn write<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        use crate::database::{enc_bytes, enc_u32s};
        enc_bytes(&self.pool, w)?;
        for c in &self.classes {
            let entries: Vec<u32> = c
                .entries
                .iter()
                .flat_map(|e| [e.off, e.len, e.back, e.part, e.value])
                .collect();
            enc_u32s(&entries, w)?;
        }
        Ok(())
    }

    /// Read what [`Self::write`] wrote, checked against `values[p]`, the number
    /// of values of partition `p`, so a scan can index with what it holds.
    pub(crate) fn read<R: crate::database::PayloadRead>(
        r: &mut R,
        values: &[usize],
    ) -> std::io::Result<Grams> {
        use crate::database::{dec_bytes, dec_u32s};
        let bad = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "corrupt signature database (anchor index)",
            )
        };
        let pool = dec_bytes(r)?;
        let mut lists: [Vec<Entry>; 5] = Default::default();
        for (c, list) in lists.iter_mut().enumerate() {
            let flat = dec_u32s(r)?;
            let (chunks, rest) = flat.as_chunks::<5>();
            if !rest.is_empty() {
                return Err(bad());
            }
            let w = WIDTH[c];
            *list = chunks
                .iter()
                .map(|&[off, len, back, part, value]| Entry {
                    off,
                    len,
                    back,
                    part,
                    value,
                    run: 0,
                })
                .collect();
            let fits = |e: &Entry| {
                (e.back as usize)
                    .checked_add(w)
                    .is_some_and(|end| end <= e.len as usize)
                    && (e.off as usize)
                        .checked_add(e.len as usize)
                        .is_some_and(|end| end <= pool.len())
                    && values
                        .get((e.part & !NOCASE) as usize)
                        .is_some_and(|&n| (e.value as usize) < n)
            };
            if !list.iter().all(fits)
                || !list
                    .windows(2)
                    .all(|p| window(&pool, &p[0], w) <= window(&pool, &p[1], w))
            {
                return Err(bad());
            }
        }
        Ok(Grams::index(pool, lists))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_source::BlockCache;

    #[test]
    fn fold8_is_ascii_lowercasing() {
        for b in 0..=255u8 {
            let x = u64::from_le_bytes([b, b'A', b, b'z', 0x80 | b, b'@', b'[', b]);
            let want = u64::from_le_bytes(x.to_le_bytes().map(|c| c.to_ascii_lowercase()));
            assert_eq!(fold8(x), want, "{b:#x}");
        }
    }

    /// `anchors` as `(partition, nocase, bytes)`, indexed with statistics over
    /// themselves.
    fn index(anchors: &[(u32, bool, Vec<u8>)]) -> Grams {
        let stats = GramStats::build(anchors.len(), |f| anchors.iter().for_each(|(.., a)| f(a)));
        let index: Vec<IndexAnchor> = anchors
            .iter()
            .enumerate()
            .map(|(v, (part, nocase, bytes))| IndexAnchor {
                part: *part,
                nocase: *nocase,
                value: v as u32,
                bytes,
            })
            .collect();
        Grams::build(&index, &stats)
    }

    /// Every place each anchor occurs in `hay`, in its case, for the active
    /// partitions: what a sweep has to find.
    fn searched(
        anchors: &[(u32, bool, Vec<u8>)],
        hay: &[u8],
        active: &[bool],
    ) -> Vec<(usize, u32, usize, usize)> {
        let mut want = Vec::new();
        for (v, (part, nocase, a)) in anchors.iter().enumerate() {
            if !active[*part as usize] || a.len() > hay.len() {
                continue;
            }
            for s in 0..=hay.len() - a.len() {
                let w = &hay[s..s + a.len()];
                if (*nocase && w.eq_ignore_ascii_case(a)) || (!*nocase && w == &a[..]) {
                    want.push((*part as usize, v as u32, s, a.len()));
                }
            }
        }
        want.sort_unstable();
        want
    }

    /// A sweep's hits, expanded and sorted as [`searched`] gives them, and how
    /// many reports they came as.
    fn swept<H: ByteSource + ?Sized>(
        g: &Grams,
        hay: &H,
        active: &[bool],
    ) -> (Vec<(usize, u32, usize, usize)>, usize) {
        let (mut got, mut reports) = (Vec::new(), 0);
        assert!(sweep(g, active, hay, &mut |p, v, s, l, n| {
            reports += 1;
            got.extend((s..s + n).map(|s| (p, v, s, l)));
            true
        }));
        got.sort_unstable();
        (got, reports)
    }

    /// Every anchor, of every width, is found at every place it occurs and
    /// nowhere else, in its case, in memory or read through a cache; a run of
    /// one byte comes as a few reports; the index survives a round trip and
    /// refuses a value its partition lacks.
    #[test]
    fn every_occurrence_is_found_once() {
        let anchors: Vec<(u32, bool, Vec<u8>)> = [
            (0, false, &b"MZ\x90\x00\x03\x00"[..]),
            (0, false, b"\x00\x00\x00\x00\x00\x01\x02"),
            (1, true, b"http://evil"),
            (1, false, b"Http://Evil"),
            (0, false, b"abcdefgh"),
            (1, false, b"xxabcdefghyy"),
            (0, false, b"PK"),
            (1, true, b"ab"),
            (0, false, b"\x00\xe8"),
            (1, false, b"xyz"),
            (0, true, b"evil"),
            (1, false, b"\x00\x00\x00\x00\x01"),
            (0, false, b"\x00\x00\x00\x00\x00\x00\x00\x00"),
            (1, false, b"--"),
            (0, false, b"q"),
            (1, true, b"Z"),
            (0, false, b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
        ]
        .iter()
        .map(|&(p, n, a)| (p, n, a.to_vec()))
        .collect();
        let g = index(&anchors);
        let mut hay =
            b"..MZ\x90\x00\x03\x00..HTTP://EVIL..Http://Evil..PK.Ab.aB.\x00\xe8xyzXYZq.z".to_vec();
        hay.extend_from_slice(
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02xxabcdefghyy..abcdefg----------",
        );
        hay.extend(std::iter::repeat_n(0u8, 300));
        hay.extend_from_slice(b"\x01");
        hay.extend(std::iter::repeat_n(0u8, 20));
        hay.extend(std::iter::repeat_n(b'Z', 100));
        let src = BlockCache::with_sizes(std::io::Cursor::new(hay.clone()), 13, 8 * 13).unwrap();
        for active in [[true, true], [true, false], [false, true]] {
            let want = searched(&anchors, &hay, &active);
            assert_eq!(swept(&g, &hay[..], &active).0, want, "{active:?}");
            assert_eq!(
                swept(&g, &src, &active).0,
                want,
                "{active:?}, read through a cache"
            );
        }
        let want = searched(&anchors, &hay, &[true, true]);
        let (_, reports) = swept(&g, &hay[..], &[true, true]);
        assert!(
            reports < want.len() / 4,
            "{reports} reports for {} matches",
            want.len()
        );
        let mut blob = Vec::new();
        g.write(&mut blob).unwrap();
        let back = Grams::read(&mut &blob[..], &[17, 17]).unwrap();
        for (a, b) in back.classes.iter().zip(&g.classes) {
            assert_eq!(
                (&a.keys, &a.start, &a.entries, &a.slots, &a.filter),
                (&b.keys, &b.start, &b.entries, &b.slots, &b.filter)
            );
        }
        assert_eq!(
            (back.pool, back.uniform, back.first),
            (g.pool, g.uniform, g.first)
        );
        assert!(
            Grams::read(&mut &blob[..], &[17, 3]).is_err(),
            "a value past its partition"
        );
    }

    /// A case-insensitive anchor of one repeated letter matches across the end
    /// of a skipped run of that letter into its other case, at every start
    /// that reaches there.
    #[test]
    fn a_nocase_run_anchor_runs_on_into_the_other_case() {
        let anchors: Vec<(u32, bool, Vec<u8>)> = vec![
            (0, true, b"aaaaaaa".to_vec()),
            (0, false, b"aaaaaaa".to_vec()),
        ];
        let g = index(&anchors);
        for tail in [&b"Ax"[..], b"AAAAAAAAx", b"AaAax", b"A"] {
            let mut hay = vec![b'a'; 100];
            hay.extend_from_slice(tail);
            assert_eq!(
                swept(&g, &hay[..], &[true]).0,
                searched(&anchors, &hay, &[true]),
                "{tail:?}"
            );
        }
    }

    /// Random anchors over a small alphabet, partitions and cases, swept over
    /// haystacks full of runs and copies of them: exactly what a search for
    /// each finds, in memory and through small cache blocks, across windows.
    #[test]
    fn random_anchors_are_found_as_searched() {
        let mut state = 0x9a3f_e107_b2c4_d5e6_u64;
        let mut next = |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n as u64) as usize
        };
        const ALPHA: &[u8] = b"aAb\x00\xff";
        for round in 0..120 {
            let anchors: Vec<(u32, bool, Vec<u8>)> = (0..1 + next(30))
                .map(|_| {
                    let len = [1, 2, 3, 4, 5, 6, 7, 9, 14, 40][next(10)];
                    let nocase = next(3) == 0;
                    let a: Vec<u8> = (0..len).map(|_| ALPHA[next(ALPHA.len())]).collect();
                    (next(3) as u32, nocase, a)
                })
                .collect();
            let g = index(&anchors);
            let mut hay = Vec::new();
            while hay.len() < 3000 + next(3000) {
                match next(5) {
                    0 => hay.extend(std::iter::repeat_n(
                        ALPHA[next(ALPHA.len())],
                        [3, 70, 900, 2500][next(4)],
                    )),
                    1 => {
                        let a = &anchors[next(anchors.len())].2;
                        hay.extend(a.iter().map(|&c| {
                            if next(2) == 0 {
                                c.to_ascii_uppercase()
                            } else {
                                c
                            }
                        }));
                    }
                    _ => hay.push(ALPHA[next(ALPHA.len())]),
                }
            }
            let src =
                BlockCache::with_sizes(std::io::Cursor::new(hay.clone()), 61, 4 * 61).unwrap();
            for active in [[true, true, true], [false, true, false]] {
                let want = searched(&anchors, &hay, &active);
                assert_eq!(
                    swept(&g, &hay[..], &active).0,
                    want,
                    "round {round} {active:?}"
                );
                assert_eq!(
                    swept(&g, &src, &active).0,
                    want,
                    "round {round} {active:?}, through a cache"
                );
            }
        }
    }
}
