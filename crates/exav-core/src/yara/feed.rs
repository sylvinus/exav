//! YARA's pattern search, made while the one read of an object goes by.
//!
//! The read of an object not held in memory hands this the bytes in order,
//! once. From them it slates the patterns whose atoms occur, as
//! [`PatternGate::select`] does, and finds the matches of the patterns that
//! are slated, which [`Scanner`](crate::yara::Scanner) would otherwise read
//! the object again for:
//!
//! * A literal or base64 pattern is searched around the atoms found. A match
//!   holds one, so it starts within the pattern's longest needle before it;
//!   those segments of the object are searched once fed. A pattern with no
//!   atom is searched all over.
//! * A regexp or hex pattern follows the bytes with its lazy DFAs, from the
//!   first atom found less the longest a match can be, or from the start of
//!   the object when it has no longest or no atom. A search that starts over
//!   inside bytes that passed, and the run back over a match, read them
//!   again from the cache. Both are charged to the pattern's steps the way
//!   a read of its own charges them.
//!
//! A result the read cannot vouch for is not handed over: a pattern whose
//! searches reached their limit, kept all the matches it may, could not
//! follow the object, or whose state tables did not fit in the memory given
//! them is left to the search [`Scanner`](crate::yara::Scanner) makes after
//! the read, which gives what it always gave.

use std::collections::BTreeMap;

use crate::byte_source::{ByteSource, CHUNK};
use crate::engine::WholeLimits;
use crate::grams::Sweeper;
use crate::yara::atoms::PatternGate;
use crate::yara::matcher::{Found, RegexTap, WindowedTap};
use crate::yara::scanner::Rules;

/// Bytes of the object searched together for the patterns that an atom found
/// in or near them names. Small in tests, so that hits fall near the edges.
const SEG: usize = if cfg!(test) { 64 } else { 4096 };

/// How the patterns of a rule set are fed, worked out once.
pub(crate) struct FeedPlan {
    /// Per partition and atom, the literal and base64 patterns behind it.
    windowed: [Vec<Vec<usize>>; 2],
    /// Per partition and atom, the most bytes from the start of a match of
    /// one of those patterns to the atom in it.
    span: [Vec<usize>; 2],
    /// The patterns with no atom, which are searched all over.
    ungated_windowed: Vec<usize>,
    ungated_regex: Vec<usize>,
    /// Whether any atom has a literal or base64 pattern behind it.
    any_windowed: bool,
}

impl FeedPlan {
    pub(crate) fn new(rules: &Rules) -> Self {
        let gate = &rules.gate;
        let by_atom = |part: usize| vec![Vec::new(); gate.atoms(part)];
        let mut windowed = [by_atom(0), by_atom(1)];
        let mut span = [vec![0; gate.atoms(0)], vec![0; gate.atoms(1)]];
        for part in 0..2 {
            for value in 0..gate.atoms(part) {
                for &pid in gate.members(part, value as u32) {
                    let p = &rules.patterns[pid];
                    if p.windowed() {
                        windowed[part][value].push(pid);
                        span[part][value] = span[part][value].max(p.hit_span());
                    }
                }
            }
        }
        let (mut ungated_windowed, mut ungated_regex) = (Vec::new(), Vec::new());
        for (pid, p) in rules.patterns.iter().enumerate() {
            if gate.is_ungated(pid) {
                match p.windowed() {
                    true => ungated_windowed.push(pid),
                    false => ungated_regex.push(pid),
                }
            }
        }
        FeedPlan {
            any_windowed: windowed.iter().flatten().any(|v| !v.is_empty()),
            windowed,
            span,
            ungated_windowed,
            ungated_regex,
        }
    }
}

/// What the answer of the search is made of.
pub(crate) struct YaraPass {
    /// Per pattern, whether it runs: the patterns with an atom found, and
    /// those with none.
    pub(crate) run: Vec<bool>,
    /// Per pattern, its matches, where the read found them.
    pub(crate) found: Vec<Option<Found>>,
}

/// The atoms found, and what they name.
struct Hits<'a> {
    gate: &'a PatternGate,
    plan: &'a FeedPlan,
    run: Vec<bool>,
    /// Patterns not slated yet that have an atom.
    unslated: usize,
    /// Per partition and atom, whether it was found, and so its patterns slated.
    seen: [Vec<bool>; 2],
    /// Per partition and atom, the segments the last hit of it marked.
    marked: [Vec<(usize, usize)>; 2],
    /// Segments to search, and the atoms that name them.
    dirty: BTreeMap<usize, Vec<(u8, u32)>>,
    /// Stretches of segments an atom names that are too long to list.
    long: Vec<Stretch>,
    /// The patterns slated since last asked, with where their first atom was.
    slated: Vec<(usize, usize)>,
}

/// Segments `lo..=hi` that the atom `value` of partition `part` names, left
/// to search from `lo`.
struct Stretch {
    lo: usize,
    hi: usize,
    part: u8,
    value: u32,
}

/// Most segments a hit names that are listed one by one: a longer stretch, a
/// run of one byte, is kept as one.
const LISTED: usize = 8;

impl Hits<'_> {
    /// The atom `value` of partition `part` was found at `start`, `count`
    /// times over, at `start`, `start + 1`...
    fn hit(&mut self, part: usize, value: u32, start: usize, count: usize) {
        let v = value as usize;
        if !self.seen[part][v] {
            self.seen[part][v] = true;
            for &pid in self.gate.members(part, value) {
                if !self.run[pid] {
                    self.run[pid] = true;
                    self.unslated -= 1;
                    self.slated.push((pid, start));
                }
            }
        }
        if self.plan.windowed[part][v].is_empty() {
            return;
        }
        // The starts of the matches this atom can be in.
        let lo = start.saturating_sub(self.plan.span[part][v]) / SEG;
        let hi = (start + count.max(1) - 1) / SEG;
        let prev = self.marked[part][v];
        if prev == (lo, hi) {
            return;
        }
        if hi - lo > LISTED {
            self.long.push(Stretch {
                lo,
                hi,
                part: part as u8,
                value,
            });
        } else {
            for seg in lo..=hi {
                if seg < prev.0 || seg > prev.1 {
                    self.dirty.entry(seg).or_default().push((part as u8, value));
                }
            }
        }
        self.marked[part][v] = (lo, hi);
    }
}

/// The search of a rule set's patterns in an object read once.
pub(crate) struct YaraFeed<'a> {
    rules: &'a Rules,
    plan: &'a FeedPlan,
    src: &'a dyn ByteSource,
    len: usize,
    /// Steps a regexp pattern may make, and the memory the state tables of
    /// the regexp searches may take together.
    steps: usize,
    memory: usize,
    sweeper: Option<Sweeper<'a, dyn ByteSource + 'a>>,
    hits: Hits<'a>,
    /// Bytes fed so far.
    end: usize,
    /// The ungated literal and base64 patterns are searched up to here.
    searched: usize,
    begun: bool,
    lits: Vec<Option<WindowedTap>>,
    rxs: Vec<Option<RegexTap<'a>>>,
    /// The regexp patterns that still take bytes.
    active: Vec<usize>,
    /// The regexp patterns that were followed and not given up.
    made: Vec<usize>,
}

impl<'a> YaraFeed<'a> {
    /// The search of `rules` over `src`, which `whole` limits. `None` when
    /// the rules have no pattern.
    pub(crate) fn new(
        rules: &'a Rules,
        src: &'a dyn ByteSource,
        whole: &WholeLimits,
    ) -> Option<Self> {
        let n = rules.patterns.len();
        if n == 0 {
            return None;
        }
        let plan = rules.feed_plan.get_or_init(|| FeedPlan::new(rules));
        let gate = &rules.gate;
        let run: Vec<bool> = (0..n).map(|pid| gate.is_ungated(pid)).collect();
        let unslated = run.iter().filter(|&&r| !r).count();
        let mut lits: Vec<Option<WindowedTap>> = (0..n).map(|_| None).collect();
        for &pid in &plan.ungated_windowed {
            lits[pid] = Some(WindowedTap::new(rules.anchored[pid]));
        }
        Some(YaraFeed {
            rules,
            plan,
            src,
            len: src.len(),
            steps: whole.regex_steps,
            memory: whole.search_bytes,
            sweeper: (unslated > 0).then(|| gate.sweeper(src)),
            hits: Hits {
                gate,
                plan,
                run,
                unslated,
                seen: [vec![false; gate.atoms(0)], vec![false; gate.atoms(1)]],
                marked: [vec![(1, 0); gate.atoms(0)], vec![(1, 0); gate.atoms(1)]],
                dirty: BTreeMap::new(),
                long: Vec::new(),
                slated: Vec::new(),
            },
            end: 0,
            searched: 0,
            begun: false,
            lits,
            rxs: (0..n).map(|_| None).collect(),
            active: Vec::new(),
            made: Vec::new(),
        })
    }

    /// The bytes `at..at + w.len()` of the object, following those fed before.
    pub(crate) fn feed(&mut self, at: usize, w: &[u8]) {
        debug_assert_eq!(at, self.end, "the bytes come in order");
        self.begin();
        self.end = at + w.len();
        let rules = self.rules;
        // Atoms first: they slate patterns, and name the stretches to search.
        if (self.hits.unslated > 0 || self.plan.any_windowed)
            && let Some(sweeper) = &mut self.sweeper
        {
            let hits = &mut self.hits;
            sweeper.feed(at, w, None, &mut |part, value, start, _, count| {
                hits.hit(part, value, start, count);
                true
            });
        }
        for (pid, first) in std::mem::take(&mut self.hits.slated) {
            if rules.patterns[pid].windowed() {
                self.lits[pid] = Some(WindowedTap::new(rules.anchored[pid]));
            } else {
                self.start_regex(pid, Some(first));
            }
        }
        self.feed_regexes(at, w);
        self.search_ungated(self.end);
        self.close(false);
    }

    /// Whether more of the object is to come.
    pub(crate) fn wants_more(&self) -> bool {
        self.end < self.len
    }

    /// The answer, when all of the object was fed.
    pub(crate) fn finish(mut self) -> Option<YaraPass> {
        if self.end < self.len {
            return None;
        }
        self.begin();
        self.close(true);
        let src = self.src;
        for &pid in &self.active {
            if let Some(tap) = self.rxs[pid].as_mut() {
                tap.finish(src);
            }
        }
        let YaraFeed {
            hits, lits, rxs, ..
        } = self;
        let found = hits
            .run
            .iter()
            .zip(lits.into_iter().zip(rxs))
            .map(|(&run, (lit, rx))| match run {
                true => lit
                    .and_then(WindowedTap::found)
                    .or(rx.and_then(RegexTap::found)),
                false => None,
            })
            .collect();
        Some(YaraPass {
            run: hits.run,
            found,
        })
    }

    /// The patterns that run whatever the object holds start with it.
    fn begin(&mut self) {
        if std::mem::replace(&mut self.begun, true) {
            return;
        }
        let plan = self.plan;
        for &pid in &plan.ungated_regex {
            self.start_regex(pid, None);
        }
    }

    /// Follow the object with regexp pattern `pid`, whose first atom was at
    /// `hit` if it has one. A pattern that cannot be followed, or is anchored
    /// at an offset, is left to the search made after the read.
    fn start_regex(&mut self, pid: usize, hit: Option<usize>) {
        let rules = self.rules;
        if rules.anchored[pid].is_some() {
            return;
        }
        let Some(fullword) = rules.patterns[pid].regex_fullword() else {
            return;
        };
        let Some(regexes) = rules.stream_regexes[pid]
            .get_or_init(|| rules.defs[pid].stream_regexes())
            .as_ref()
        else {
            return;
        };
        if let Some(tap) = RegexTap::new(regexes, fullword, self.steps, self.src, hit) {
            self.rxs[pid] = Some(tap);
            self.active.push(pid);
            self.made.push(pid);
        }
    }

    /// Hand the regexp patterns the window, and drop those it spoils.
    fn feed_regexes(&mut self, at: usize, w: &[u8]) {
        let src = self.src;
        let mut i = 0;
        while i < self.active.len() {
            let pid = self.active[i];
            let Some(tap) = self.rxs[pid].as_mut() else {
                self.active.swap_remove(i);
                continue;
            };
            tap.feed(src, at, w);
            if tap.spoiled() {
                self.rxs[pid] = None;
                self.active.swap_remove(i);
            } else if tap.is_over() {
                self.active.swap_remove(i);
            } else {
                i += 1;
            }
        }
        self.trim();
    }

    /// Give up the regexp patterns with the most state until what they hold
    /// fits in the memory given them.
    fn trim(&mut self) {
        let size =
            |rxs: &[Option<RegexTap<'a>>], pid: usize| rxs[pid].as_ref().map_or(0, |t| t.memory());
        let mut total: usize = self.made.iter().map(|&pid| size(&self.rxs, pid)).sum();
        while total > self.memory {
            let Some(&pid) = self.made.iter().max_by_key(|&&pid| size(&self.rxs, pid)) else {
                return;
            };
            total -= size(&self.rxs, pid);
            self.rxs[pid] = None;
            self.active.retain(|&p| p != pid);
            self.made.retain(|&p| p != pid);
        }
    }

    /// Search the patterns with no atom over what was fed.
    fn search_ungated(&mut self, upto: usize) {
        let plan = self.plan;
        while self.searched < upto {
            let hi = (self.searched + CHUNK).min(upto);
            self.search_span(&plan.ungated_windowed, self.searched, hi);
            self.searched = hi;
        }
    }

    /// Search the segments that were fed, or all of them. A hit that comes
    /// later and names one again has it searched again, which finds the same
    /// matches: they are sorted and deduplicated at the end.
    fn close(&mut self, all: bool) {
        let plan = self.plan;
        while let Some(entry) = self.hits.dirty.first_entry() {
            let seg = *entry.key();
            if !all && (seg + 1) * SEG > self.end {
                break;
            }
            let atoms = entry.remove();
            let mut pids: Vec<usize> = atoms
                .iter()
                .flat_map(|&(part, value)| &plan.windowed[part as usize][value as usize])
                .copied()
                .collect();
            pids.sort_unstable();
            pids.dedup();
            let (lo, hi) = (seg * SEG, ((seg + 1) * SEG).min(self.len));
            if lo < hi {
                self.search_span(&pids, lo, hi);
            }
        }
        // The long stretches, as far as they were fed, a chunk at a time.
        let fed = if all { usize::MAX } else { self.end / SEG };
        for mut s in std::mem::take(&mut self.hits.long) {
            let pids = &plan.windowed[s.part as usize][s.value as usize];
            let upto = fed.min(s.hi.saturating_add(1));
            while s.lo < upto {
                let next = (s.lo + CHUNK / SEG).min(upto);
                let (lo, hi) = (s.lo * SEG, (next * SEG).min(self.len));
                if lo < hi {
                    self.search_span(pids, lo, hi);
                }
                s.lo = next;
            }
            if s.lo <= s.hi {
                self.hits.long.push(s);
            }
        }
    }

    /// Search the match starts `lo..hi` of the literal and base64 patterns
    /// `pids`, in one read of what they need around them. A read that comes
    /// back short leaves them to the search made after.
    fn search_span(&mut self, pids: &[usize], lo: usize, hi: usize) {
        if pids.is_empty() {
            return;
        }
        let (rules, src) = (self.rules, self.src);
        let (mut before, mut after) = (0, 0);
        for &pid in pids {
            let (b, a) = rules.patterns[pid].reach();
            (before, after) = (before.max(b), after.max(a));
        }
        let from = lo.saturating_sub(before);
        let to = hi.saturating_add(after).min(self.len);
        let w = src.window(from, to - from);
        for &pid in pids {
            let Some(tap) = self.lits[pid].as_mut() else {
                continue;
            };
            if w.len() == to - from {
                tap.search(&rules.patterns[pid], &w, lo - from..hi - from, from);
            } else {
                self.lits[pid] = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::byte_source::BlockCache;
    use crate::yara::compiler::Compiler;

    fn rules(src: &str) -> Rules {
        let mut c = Compiler::new();
        c.add_source(src).expect("compile");
        c.build()
    }

    /// The patterns the read slates to run are those the prefilter selects,
    /// in memory and through a cache, whatever the pieces the object comes in;
    /// without all of the object there is no answer.
    #[test]
    fn the_read_slates_the_patterns_whose_atoms_occur() {
        let rules = rules(
            r#"
            rule a { strings: $a = "abcd" $b = "xyz" condition: any of them }
            rule b { strings: $c = "hello" nocase $d = { 78 79 7a ?? 00 00 00 00 00 00 00 00 00 } condition: any of them }
            rule c { strings: $e = /[a-z]{3}zzzz/ $g = /q\x00{6}q/ nocase condition: any of them }
            rule d { strings: $f = "free" xor $h = /[a-z]{30,}/ condition: any of them }
            "#,
        );
        let mut state = 0x5eed_u64;
        let mut next = |n: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % n as u64) as usize
        };
        let whole = WholeLimits::NONE;
        let mut slated = [0; 2];
        for _ in 0..200 {
            let mut hay = Vec::new();
            for _ in 0..1 + next(8) {
                match next(4) {
                    0 => hay.extend(std::iter::repeat_n(
                        b"\0zZ"[next(3)],
                        [3, 11, 12, 70, 3000][next(5)],
                    )),
                    1 => hay.extend_from_slice(
                        [
                            &b"abcd"[..],
                            b"HeLLo",
                            b"xyz",
                            b"Q\0\0\0\0\0\0Q",
                            b"abczzzz",
                        ][next(5)],
                    ),
                    _ => hay.extend((0..next(40)).map(|_| b"abcdxyzhelo\0HELOQ"[next(17)])),
                }
            }
            let cache = BlockCache::with_sizes(Cursor::new(hay.clone()), 64, 1024).unwrap();
            let want = rules.gate.select(&cache);
            for (i, &w) in want.iter().enumerate() {
                slated[w as usize] += (!rules.gate.is_ungated(i)) as usize;
            }
            for piece in [1, 7, 64, 1000, 5000] {
                let feed = |upto: usize| {
                    let mut feed = rules.feed(&cache, &whole).expect("patterns");
                    for (i, w) in hay[..upto].chunks(piece).enumerate() {
                        feed.feed(i * piece, w);
                    }
                    feed
                };
                let all = feed(hay.len());
                assert!(!all.wants_more());
                let pass = all.finish().expect("all of the object was fed");
                assert_eq!(pass.run, want, "{piece}, {hay:?}");
                let half = feed(hay.len() / 2);
                assert!(hay.len() < 2 || half.wants_more());
                assert!(hay.len() < 2 || half.finish().is_none(), "{piece}, {hay:?}");
            }
        }
        // Some gated patterns were slated and some were not.
        assert!(slated[0] > 50 && slated[1] > 50, "{slated:?}");
    }

    /// A long run of one byte names millions of segments for an atom made of
    /// it, and the read keeps one entry for the run and not one for each.
    #[test]
    fn a_run_of_one_byte_is_kept_as_one_entry() {
        let rules = rules(
            r#"rule z { strings: $z = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" condition: $z }"#,
        );
        let h = vec![0u8; 900_000];
        let cache = BlockCache::with_sizes(Cursor::new(h.clone()), 4096, 1 << 16).unwrap();
        let mut feed = rules.feed(&cache, &WholeLimits::NONE).expect("patterns");
        let mut most = 0;
        for (i, w) in h[..].chunks(1000).enumerate() {
            feed.feed(i * 1000, w);
            most = most.max(feed.hits.dirty.len() + feed.hits.long.len());
        }
        assert!(most <= 16, "{most} entries");
        let pass = feed.finish().expect("all of the object was fed");
        let found = pass.found[0].as_ref().expect("found in the read");
        assert_eq!(found.matches.len(), 900_000 - 11);
    }
}
