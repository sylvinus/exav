//! How common a literal is likely to be in a scanned object: what picks the
//! literal a signature is found by, and the window of it the index looks up.

use super::FOLD;

/// How many signature literals contain each short byte sequence, case-folded,
/// counted over the set being built.
///
/// This is the selectivity signal, derived from the signature set itself rather
/// than shipped alongside it. A literal that hundreds of signatures are written
/// around (`"http://"`, `"target=\""`, `"<script"`) is a literal that appears
/// constantly in real files, because that is *why* so many signatures mention
/// it. Popularity among signatures is a proxy for popularity in content, and it
/// costs nothing to obtain: no reference corpus to assemble, nothing to ship,
/// nothing to go stale. Rebuild the database and the statistic rebuilds with it.
///
/// The proxy is not exact. A sequence common in malware but rare in benign
/// files is over-penalised, and one ubiquitous in benign files that no
/// signature mentions is under-penalised. Both cost a worse anchor and nothing
/// else: verification re-checks the whole pattern whatever triggered it, so the
/// choice can never change a verdict.
#[derive(Default)]
pub(crate) struct GramStats {
    /// Gram (2-4 bytes, length-tagged) to the number of literals containing it.
    /// Grams in a single literal are absent: `log2(1)` is zero, the same score
    /// as "never seen", and they are most of the distinct grams of a full set.
    counts: rustc_hash::FxHashMap<u64, u32>,
}

/// Bits per presence filter. 2^28 bits is 32 MiB, ~8% occupancy against the
/// ~22M distinct grams of a full set, so few singletons are wrongly promoted to
/// the counting map, and a promotion costs only the memory, never a wrong
/// count, since the second pass counts what it actually sees.
const SEEN_BITS: usize = 1 << 28;

/// Literal count from which the repeat filter is worth its fixed cost. Below it
/// the two bitsets would be 64 MiB to filter a handful of grams, which is what
/// every in-process engine build does, from a unit test to a small sig dir.
pub(crate) const FILTER_MIN_BODIES: usize = 100_000;

/// A gram's key: its bytes folded, tagged with the length so `"ab"` and the
/// prefix of `"abcd"` cannot collide. Lengths are 2..=4, so this is lossless.
fn gram_key(g: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in g {
        v = (v << 8) | FOLD[b as usize] as u64;
    }
    v | ((g.len() as u64) << 56)
}

/// Every gram of `lit` to CREDIT while counting: all windows of 2, 3 and 4
/// bytes.
///
/// Counting and lookup have to agree on what a gram's count means, and the
/// obvious shortcut, crediting only the window size the lookup will use, is
/// wrong. Lookup asks a 2-byte literal about a 2-gram; if only 2-byte literals
/// ever credited 2-grams, `"//"` would be counted from the handful of two-byte
/// signatures rather than from the tens of thousands of literals that contain
/// it. Short ubiquitous literals then look rare, score well, and win the
/// anchor: the exact inversion this is built to prevent.
fn count_grams_of(lit: &[u8], out: &mut Vec<u64>) {
    out.clear();
    for n in 2..=4usize {
        if lit.len() < n {
            break;
        }
        out.extend(lit.windows(n).map(gram_key));
    }
    out.sort_unstable();
    out.dedup();
}

impl GramStats {
    /// Count grams over every literal `each` yields; `literals` is about how
    /// many it yields, which sizes the work.
    ///
    /// Past [`FILTER_MIN_BODIES`] the repeat filter pays for itself and `each`
    /// is called twice: once to find which grams repeat, once to count only
    /// those. Below it the filter's fixed 64 MiB would dwarf the data it is
    /// filtering, so the counts are taken exactly in a single pass. Both give
    /// identical scores: a gram the filter drops appears in one literal, and
    /// `log2(1)` is the zero an absent gram scores.
    pub(crate) fn build(literals: usize, mut each: impl FnMut(&mut dyn FnMut(&[u8]))) -> Self {
        let mut buf: Vec<u64> = Vec::new();
        let mut counts: rustc_hash::FxHashMap<u64, u32> = rustc_hash::FxHashMap::default();
        if literals < FILTER_MIN_BODIES {
            each(&mut |lit| {
                count_grams_of(lit, &mut buf);
                for &k in &buf {
                    *counts.entry(k).or_insert(0) += 1;
                }
            });
            return GramStats { counts };
        }
        let mut once = vec![0u64; SEEN_BITS / 64];
        let mut twice = vec![0u64; SEEN_BITS / 64];
        let mark = |bits: &mut [u64], i: usize| bits[i >> 6] |= 1 << (i & 63);
        let test = |bits: &[u64], i: usize| bits[i >> 6] >> (i & 63) & 1 == 1;
        let slot = |k: u64| {
            (k.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - SEEN_BITS.trailing_zeros())) as usize
        };
        // Pass 1: which grams appear in more than one literal.
        each(&mut |lit| {
            count_grams_of(lit, &mut buf);
            for &k in &buf {
                let i = slot(k);
                if test(&once, i) {
                    mark(&mut twice, i);
                } else {
                    mark(&mut once, i);
                }
            }
        });
        drop(once);
        // Pass 2: count the repeats. Per literal, not per occurrence, so a
        // sequence repeated inside one literal does not look popular.
        each(&mut |lit| {
            count_grams_of(lit, &mut buf);
            for &k in &buf {
                if test(&twice, slot(k)) {
                    *counts.entry(k).or_insert(0) += 1;
                }
            }
        });
        GramStats { counts }
    }

    /// How many literals contain `lit`, bounded above: a literal occurs in at
    /// most as many literals as its rarest gram does, and the widest gram it
    /// holds gives the tightest such bound. Erring high is the safe direction:
    /// it can only make a literal look like a worse anchor.
    pub(crate) fn popularity(&self, lit: &[u8]) -> u32 {
        if lit.len() < 2 {
            return 0;
        }
        lit.windows(lit.len().min(4))
            .map(|g| self.counts.get(&gram_key(g)).copied().unwrap_or(0))
            .min()
            .unwrap_or(0)
    }
}

/// `floor(log2(c))`, and 0 for the "nothing known" counts 0 and 1: an unseen
/// literal is never penalised, and the penalty grows with an order of
/// magnitude rather than with a raw count that spans 1..10^6.
fn log2_floor(c: u32) -> isize {
    if c <= 1 {
        0
    } else {
        c.ilog2() as isize
    }
}

/// How rare `b` should be from its bytes alone. A low-entropy run (a constant
/// byte like a zero or 0xFF pad, or a 2-symbol repeat) matches repetitive
/// content, PE padding and BSS, millions of times, so it is a terrible
/// prefilter even when long; a varied run scores its length.
pub(crate) fn structural(b: &[u8]) -> isize {
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &x in b {
        if !seen[x as usize] {
            seen[x as usize] = true;
            distinct += 1;
        }
    }
    match distinct {
        0 | 1 => 1,
        2 => 3.min(b.len()) as isize,
        _ => b.len() as isize,
    }
}

/// Selectivity of a candidate anchor, higher is rarer: [`structural`], less
/// how many signature literals share it.
///
/// Length alone is not selectivity: `"http://"` is 7 varied bytes, yet it is
/// the single worst anchor on web and office content, while a shorter literal
/// of the same body (`":7878"`) occurs essentially never. Both terms are
/// log-scaled, length standing in for how rare a run should be and the count
/// for how common it actually is, so the difference reads as a selectivity
/// estimate. Deliberately signed and unsaturated: clamping at zero puts every
/// ubiquitous literal in a tie that the length tie-break then resolves
/// backwards, handing the anchor to the *longest* common run. `stats` is `None`
/// while a body is first parsed, before the set is known.
pub(crate) fn anchor_score(b: &[u8], stats: Option<&GramStats>) -> isize {
    structural(b) - stats.map_or(0, |s| log2_floor(s.popularity(b)))
}

/// What looking a window of anchor bytes up at every position is expected to
/// cost, lower is better: how many literals share it, then how plain its bytes
/// are (padding and blanks first, then few distinct bytes).
pub(crate) fn window_cost(w: &[u8], stats: &GramStats) -> (isize, usize) {
    let mut seen = [false; 256];
    let mut distinct = 0;
    let mut weight = 0;
    for &b in w {
        weight += match b {
            0x00 => 3,
            0xff => 2,
            b' ' | b'\n' | b'\r' | b'\t' | 0x90 | 0xcc => 1,
            _ => 0,
        };
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
    }
    (log2_floor(stats.popularity(w)), weight + w.len() - distinct)
}
