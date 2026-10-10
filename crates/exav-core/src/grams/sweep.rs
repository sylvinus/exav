//! One pass over an object, a window at a time, looking up the anchors of a
//! [`Grams`] at every position but inside long runs of one byte.

use super::{Grams, Scan, GRAM};
use crate::byte_source::ByteSource;

/// Bytes of the object [`sweep`] reads at a time; in memory, a slice of it.
/// Small in tests, so their haystacks cross windows.
pub(crate) const SWEEP_WINDOW: usize = if cfg!(test) { 1000 } else { 1 << 20 };

/// Shortest run of one byte [`sweep`] skips any of. A shorter one would save a
/// few dozen lookups at most.
pub(crate) const MIN_SKIP_RUN: usize = 64;

/// Whole aligned words inside any run of [`MIN_SKIP_RUN`] bytes: seven of its
/// bytes at most can fall before the first one.
const RUN_WORDS: usize = (MIN_SKIP_RUN - 7) / 8;

/// Whether [`sweep`] collapses runs of one repeated byte: always, except on a
/// test thread that compares both ways.
fn run_collapse_enabled() -> bool {
    #[cfg(test)]
    return !NO_RUN_COLLAPSE.with(|c| c.get());
    #[cfg(not(test))]
    true
}

#[cfg(test)]
thread_local! {
    /// Turns [`run_collapse_enabled`] off on this thread, for the tests that
    /// compare both ways.
    pub(crate) static NO_RUN_COLLAPSE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Look up the anchors of `g` at every position of `hay`, for the partitions
/// `active` keeps, handing `f` each one found as `(partition, value, start,
/// len, count)`: the anchor of `len` bytes matched at `start`, `start + 1`, ...
/// `count` times over. Stops when `f` returns `false`; returns whether the
/// sweep reached the end.
///
/// Inside a run of one repeated byte, a position whose widest window lies in
/// the run can only start an anchor of that byte, so past its first position
/// a run of at least [`MIN_SKIP_RUN`] bytes is not looked up position by
/// position: each anchor of its byte is reported for the whole stretch at once.
///
/// Within a window, anchors come in the order their windows start.
pub(crate) fn sweep<H: ByteSource + ?Sized>(
    g: &Grams,
    active: &[bool],
    hay: &H,
    f: &mut impl FnMut(usize, u32, usize, usize, usize) -> bool,
) -> bool {
    if g.is_empty() {
        return true;
    }
    let mut sc = g.start(active, hay);
    let collapse = run_collapse_enabled();
    let mut skips = Vec::new();
    let mut at = 0;
    while at < hay.len() {
        let buf = hay.window(at, (hay.len() - at).min(SWEEP_WINDOW));
        if buf.is_empty() {
            break;
        }
        skips.clear();
        let next = match collapse {
            true => plan_skips(&buf, at, hay, &mut skips),
            false => at + buf.len(),
        };
        if !sweep_window(g, &mut sc, &buf, at, next, &skips, f) {
            return false;
        }
        at = next;
    }
    true
}

/// [`sweep`] over the window `buf` at `at`, the next one starting at `next`,
/// past the runs `skips`.
fn sweep_window<H: ByteSource + ?Sized>(
    g: &Grams,
    sc: &mut Scan<H>,
    buf: &[u8],
    at: usize,
    next: usize,
    skips: &[Skip],
    f: &mut impl FnMut(usize, u32, usize, usize, usize) -> bool,
) -> bool {
    // The positions whose eight bytes are in `buf`, and past them, those
    // read from the object: across into the next window, or past a run that
    // goes on beyond this one, just before the next window starts after it.
    let fits = buf.len().saturating_sub(7);
    let (mut from, mut across) = (0, at + fits);
    for s in skips {
        let (lo, hi) = (at + s.start + 1, s.end.saturating_sub(GRAM - 1));
        if hi <= lo {
            continue;
        }
        if !g.scan(sc, buf, at, from, (lo - at).min(fits), f)
            || !g.run(sc, buf[s.start], lo, hi, s.end, f)
        {
            return false;
        }
        from = from.max(hi - at);
        across = across.max(hi);
    }
    g.scan(sc, buf, at, from, fits, f) && g.scan_source(sc, across, next, f)
}

/// A run of one byte [`sweep`] skips: it starts at `start` in its window and
/// ends at `end` in the object.
struct Skip {
    start: usize,
    end: usize,
}

/// The runs to skip in `buf`, at `at` in `hay`; returns where in `hay` the
/// next window starts, past the end of a run that goes on beyond this one.
#[inline(never)]
fn plan_skips<H: ByteSource + ?Sized>(
    buf: &[u8],
    at: usize,
    hay: &H,
    skips: &mut Vec<Skip>,
) -> usize {
    let mut from = 0;
    while let Some((r, n)) = next_long_run(buf, from) {
        let b = buf[r];
        let mut end = at + r + n;
        if r + n == buf.len() {
            hay.chunks(end, hay.len(), &mut |_, c| {
                let same = c.iter().take_while(|&&x| x == b).count();
                end += same;
                same == c.len()
            });
        }
        skips.push(Skip { start: r, end });
        if end >= at + buf.len() {
            return end;
        }
        from = end - at;
    }
    at + buf.len()
}

/// The first run of at least [`MIN_SKIP_RUN`] equal bytes in `s[from..]`, as
/// `(start, len)`. Such a run holds [`RUN_WORDS`] whole eight-byte-aligned words
/// of its byte, so the search reads words, and bytes only at a found run's
/// edges. Executables are full of short runs of zeros, which this passes over
/// a word at a time.
fn next_long_run(s: &[u8], from: usize) -> Option<(usize, usize)> {
    let word = |w: usize| u64::from_le_bytes(s[w..w + 8].try_into().unwrap());
    let mut w = from.next_multiple_of(8);
    while w + 8 <= s.len() {
        let x = word(w);
        if x != (x & 0xff).wrapping_mul(0x0101_0101_0101_0101) {
            w += 8;
            continue;
        }
        // The aligned words equal to this one, from it on.
        let mut e = w + 8;
        while e + 8 <= s.len() && word(e) == x {
            e += 8;
        }
        if e - w < RUN_WORDS * 8 {
            w = e;
            continue;
        }
        let c = s[w];
        let start = w - s[from..w].iter().rev().take_while(|&&b| b == c).count();
        let end = e + s[e..].iter().take_while(|&&b| b == c).count();
        if end - start >= MIN_SKIP_RUN {
            return Some((start, end - start));
        }
        w = end.next_multiple_of(8);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `next_long_run` finds exactly the first run of at least `MIN_SKIP_RUN`
    /// bytes, whatever its alignment and length, next to other runs, and at
    /// the buffer's edges.
    #[test]
    fn long_runs_are_found_at_any_alignment() {
        let naive = |s: &[u8], from: usize| {
            let mut i = from;
            for r in s[from..].chunk_by(|a, b| a == b) {
                if r.len() >= MIN_SKIP_RUN {
                    return Some((i, r.len()));
                }
                i += r.len();
            }
            None
        };
        for pre in 0..20 {
            for len in [1, 7, 8, 15, 56, 57, 62, 63, 64, 65, 71, 72, 200] {
                for (other, other_len) in [(0u8, 0), (1, 30), (0, 63), (2, 64)] {
                    for post in [0, 1, 9] {
                        let mut s = vec![7u8; pre];
                        s.extend(std::iter::repeat_n(other, other_len));
                        s.extend(std::iter::repeat_n(0u8, len));
                        s.extend(std::iter::repeat_n(5u8, post));
                        for from in [0, pre / 2, pre] {
                            assert_eq!(
                                next_long_run(&s, from),
                                naive(&s, from),
                                "pre {pre} len {len} other {other}x{other_len} post {post} from {from}"
                            );
                        }
                    }
                }
            }
        }
    }
}
