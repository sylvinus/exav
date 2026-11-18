//! Regular expressions over a [`ByteSource`], answering what a `regex`
//! `meta::Regex` answers over the same bytes held in memory.
//!
//! `meta::Regex` finds a leftmost-first match with a forward lazy DFA, which
//! reports where the match ends, then an anchored reverse lazy DFA run back from
//! that end, which reports where it starts. Both are driven here one byte at a
//! time through the source, so nothing is held but the DFAs' caches. The
//! start states, the one-byte delay of match states and the end-of-input
//! transitions are handled as `regex-automata`'s own searches handle them.
//!
//! A lazy DFA cannot follow everything a `meta::Regex` can: a Unicode word
//! boundary against a non-ASCII byte makes it quit. That is reported as
//! [`GaveUp`], never as an answer.

use std::borrow::Cow;

use regex_automata::hybrid::LazyStateID;
use regex_automata::hybrid::dfa::{Cache, DFA};
use regex_automata::nfa::thompson::{self, WhichCaptures};
use regex_automata::util::start;
use regex_automata::util::syntax;
use regex_automata::{Anchored, MatchKind};
use regex_syntax::hir::Hir;

use crate::byte_source::ByteSource;

/// Bytes read from the source at a time.
const STEP: usize = 64 * 1024;

/// The DFAs met a construct they cannot follow over these bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GaveUp;

/// The lazy DFAs' state tables, grown as a search needs them.
pub(crate) struct Caches {
    fwd: Cache,
    rev: Cache,
    /// Bytes read from the source by the searches made with these caches
    /// since [`Self::take_read`].
    #[cfg_attr(not(feature = "yara"), allow(dead_code))]
    read: usize,
}

impl Caches {
    /// The bytes the searches since the last call read.
    #[cfg_attr(not(feature = "yara"), allow(dead_code))]
    pub(crate) fn take_read(&mut self) -> usize {
        std::mem::take(&mut self.read)
    }

    /// The memory the DFAs' state tables take.
    #[cfg_attr(not(feature = "yara"), allow(dead_code))]
    pub(crate) fn memory(&self) -> usize {
        self.fwd.memory_usage() + self.rev.memory_usage()
    }
}

/// A forward search that is handed the bytes after the ones it has taken.
struct Forward {
    sid: LazyStateID,
    /// Where the last match it saw ends.
    end: Option<usize>,
    /// Where it began.
    start: usize,
    /// The next byte it takes; where it stopped, once it is over.
    at: usize,
}

pub(crate) struct StreamRegex {
    fwd: DFA,
    rev: DFA,
    /// The pattern can only match at the start of a search.
    anchored: bool,
    /// The most bytes a match can span, if the pattern has a longest.
    max_len: Option<usize>,
}

impl StreamRegex {
    /// The regex `regex::bytes::RegexBuilder::new(pattern)` builds, with
    /// `unicode(false)` and `size_limit(nfa_limit)`: bytes matched as PCRE does
    /// without UTF. `None` where that would fail, or where the lazy DFAs cannot
    /// be built.
    pub(crate) fn bytes_regex(pattern: &str, nfa_limit: usize) -> Option<Self> {
        let config = syntax::Config::new().utf8(false).unicode(false);
        let hir = syntax::parse_with(pattern, &config).ok()?;
        Self::from_hir(&hir, Some(nfa_limit))
    }

    /// A regex over a parsed pattern, matching as a `meta::Regex` built from
    /// the same HIR does.
    pub(crate) fn from_hir(hir: &Hir, nfa_limit: Option<usize>) -> Option<Self> {
        let nfa_config = thompson::Config::new()
            .utf8(false)
            .nfa_size_limit(nfa_limit)
            .which_captures(WhichCaptures::None);
        let nfa = thompson::Compiler::new()
            .configure(nfa_config.clone())
            .build_from_hir(hir)
            .ok()?;
        let nfarev = thompson::Compiler::new()
            .configure(nfa_config.reverse(true))
            .build_from_hir(hir)
            .ok()?;
        let anchored = nfa.is_always_start_anchored();
        let max_len = hir.properties().maximum_len();
        let config = DFA::config()
            .unicode_word_boundary(true)
            // Clearing the cache is slower, never wrong; giving up would be.
            .minimum_cache_clear_count(None)
            .cache_capacity(16 << 20);
        let fwd = DFA::builder()
            .configure(config.clone().match_kind(MatchKind::LeftmostFirst))
            .build_from_nfa(nfa)
            .ok()?;
        let rev = DFA::builder()
            .configure(config.match_kind(MatchKind::All))
            .build_from_nfa(nfarev)
            .ok()?;
        Some(StreamRegex {
            fwd,
            rev,
            anchored,
            max_len,
        })
    }

    /// The most bytes a match can span, if it has a most.
    #[cfg_attr(not(feature = "yara"), allow(dead_code))]
    pub(crate) fn max_len(&self) -> Option<usize> {
        self.max_len
    }

    /// Scratch space for searches with this regex, kept across searches.
    pub(crate) fn caches(&self) -> Caches {
        Caches {
            fwd: self.fwd.create_cache(),
            rev: self.rev.create_cache(),
            read: 0,
        }
    }

    /// Whether the pattern matches anywhere in `src`.
    pub(crate) fn is_match(&self, src: &dyn ByteSource) -> Result<bool, GaveUp> {
        let mut caches = self.caches();
        Ok(self
            .forward(&mut caches, src, 0, true, Anchored::No)?
            .is_some())
    }

    /// The bytes that [`Self::find`] reads from `start` over `data`, which a
    /// `meta::Regex` search does not say: the forward DFA's, and the reverse
    /// one's run back over the match, `reverse_len` bytes at most. At most
    /// `room` + 1 are looked at; a search that goes on after `room` is cut
    /// there, and the count is more than `room`. `None` where the DFA gives up.
    #[cfg_attr(not(feature = "yara"), allow(dead_code))]
    pub(crate) fn read_forward(
        &self,
        caches: &mut Caches,
        data: &[u8],
        start: usize,
        room: usize,
        reverse_len: usize,
    ) -> Option<usize> {
        let end = data.len().min(start.saturating_add(room).saturating_add(1));
        let input = regex_automata::Input::new(data).span(start..end);
        let cache = &mut caches.fwd;
        let (before, clears) = (cache.search_total_len(), cache.clear_count());
        self.fwd.try_search_fwd(cache, &input).ok()?;
        (cache.clear_count() == clears).then(|| {
            cache
                .search_total_len()
                .saturating_sub(before)
                .saturating_add(reverse_len)
        })
    }

    /// The leftmost-first match starting at or after `start`, as `(start,
    /// end)`: what `meta::Regex::find` returns for `Input::new(bytes).span(start..)`.
    pub(crate) fn find(
        &self,
        caches: &mut Caches,
        src: &dyn ByteSource,
        start: usize,
    ) -> Result<Option<(usize, usize)>, GaveUp> {
        let Some(end) = self.forward(caches, src, start, false, Anchored::No)? else {
            return Ok(None);
        };
        if end == start || self.anchored {
            return Ok(Some((start, end)));
        }
        let from = self.reverse(caches, src, start, end)?.ok_or(GaveUp)?;
        Ok(Some((from, end)))
    }

    /// The end of the leftmost-first match that starts at `start`, if one
    /// does: what `meta::Regex::find` returns for that span, anchored.
    #[cfg_attr(not(feature = "yara"), allow(dead_code))]
    pub(crate) fn find_at(
        &self,
        caches: &mut Caches,
        src: &dyn ByteSource,
        start: usize,
    ) -> Result<Option<usize>, GaveUp> {
        self.forward(caches, src, start, false, Anchored::Yes)
    }

    /// The matches `meta::Regex::find_iter` yields over `src`, until `f`
    /// returns `false`.
    #[cfg(test)]
    pub(crate) fn for_each(
        &self,
        src: &dyn ByteSource,
        f: &mut dyn FnMut(usize, usize) -> bool,
    ) -> Result<(), GaveUp> {
        let mut caches = self.caches();
        let len = src.len();
        let mut start = 0;
        let mut last_end: Option<usize> = None;
        while start <= len {
            let Some((mut s, mut e)) = self.find(&mut caches, src, start)? else {
                return Ok(());
            };
            // An empty match where the last one ended is skipped by searching
            // again one byte on.
            if s == e && Some(e) == last_end {
                start += 1;
                if start > len {
                    return Ok(());
                }
                match self.find(&mut caches, src, start)? {
                    Some(m) => (s, e) = m,
                    None => return Ok(()),
                }
            }
            if !f(s, e) {
                return Ok(());
            }
            start = e;
            last_end = Some(e);
        }
        Ok(())
    }

    /// End of the leftmost-first match starting at or after `start` (the first
    /// match end at all when `earliest`), or at `start` when `anchored`.
    fn forward(
        &self,
        caches: &mut Caches,
        src: &dyn ByteSource,
        start: usize,
        earliest: bool,
        anchored: Anchored,
    ) -> Result<Option<usize>, GaveUp> {
        let mut at = start;
        let out = self.forward_to(&mut caches.fwd, src, start, earliest, anchored, &mut at);
        caches.read += at.saturating_sub(start);
        out
    }

    /// [`Self::forward`], leaving in `at` where it stopped reading.
    fn forward_to(
        &self,
        cache: &mut Cache,
        src: &dyn ByteSource,
        start: usize,
        earliest: bool,
        anchored: Anchored,
        at: &mut usize,
    ) -> Result<Option<usize>, GaveUp> {
        let len = src.len();
        if start > len {
            return Ok(None);
        }
        let behind = (start > 0).then(|| byte(src, start - 1));
        let mut f = self.forward_begin(cache, start, behind, anchored)?;
        while f.at < len {
            let w = src.window(f.at, (len - f.at).min(STEP));
            if w.is_empty() {
                return Err(GaveUp);
            }
            let taken = self.forward_take(cache, &mut f, &w, earliest);
            *at = f.at;
            if let Some(end) = taken? {
                return Ok(end);
            }
        }
        self.forward_eoi(cache, f)
    }

    /// A forward search from `start`, given the byte before it if there is one.
    fn forward_begin(
        &self,
        cache: &mut Cache,
        start: usize,
        behind: Option<u8>,
        anchored: Anchored,
    ) -> Result<Forward, GaveUp> {
        let config = start::Config::new().anchored(anchored).look_behind(behind);
        let sid = self.fwd.start_state(cache, &config).map_err(|_| GaveUp)?;
        Ok(Forward {
            sid,
            end: None,
            start,
            at: start,
        })
    }

    /// Hand the search `w`, the bytes that follow those it has taken.
    /// `Some(end)` when the search is over, `end` being where its match ends
    /// if it found one; `None` when it wants more. `earliest` ends it at the
    /// first match end.
    fn forward_take(
        &self,
        cache: &mut Cache,
        f: &mut Forward,
        w: &[u8],
        earliest: bool,
    ) -> Result<Option<Option<usize>>, GaveUp> {
        for &b in w {
            f.sid = next(&self.fwd, cache, f.sid, b)?;
            if f.sid.is_tagged() {
                // Matches are delayed by one byte: this state says a match
                // ended just before `f.at`.
                if f.sid.is_match() {
                    f.end = Some(f.at);
                    if earliest {
                        return Ok(Some(f.end));
                    }
                } else if f.sid.is_dead() {
                    return Ok(Some(f.end));
                } else if f.sid.is_quit() {
                    return Err(GaveUp);
                }
            }
            f.at += 1;
        }
        Ok(None)
    }

    /// The object ended after the bytes the search took: where its match
    /// ends, if it found one.
    fn forward_eoi(&self, cache: &mut Cache, f: Forward) -> Result<Option<usize>, GaveUp> {
        let sid = self.fwd.next_eoi_state(cache, f.sid).map_err(|_| GaveUp)?;
        Ok(if sid.is_match() { Some(f.at) } else { f.end })
    }

    /// Start of the match ending at `end`, found by the anchored reverse DFA
    /// run back towards `start`.
    fn reverse(
        &self,
        caches: &mut Caches,
        src: &dyn ByteSource,
        start: usize,
        end: usize,
    ) -> Result<Option<usize>, GaveUp> {
        let mut low = end;
        let out = self.reverse_to(&mut caches.rev, src, start, end, &mut low);
        caches.read += end.saturating_sub(low);
        out
    }

    /// [`Self::reverse`], leaving in `low` where it stopped reading.
    fn reverse_to(
        &self,
        cache: &mut Cache,
        src: &dyn ByteSource,
        start: usize,
        end: usize,
        low: &mut usize,
    ) -> Result<Option<usize>, GaveUp> {
        let behind = (end < src.len()).then(|| byte(src, end));
        let config = start::Config::new()
            .anchored(Anchored::Yes)
            .look_behind(behind);
        let mut sid = self.rev.start_state(cache, &config).map_err(|_| GaveUp)?;
        let mut from = None;
        let mut hi = end;
        while hi > start {
            let lo = hi.saturating_sub(STEP).max(start);
            let w = src.window(lo, hi - lo);
            if w.len() != hi - lo {
                return Err(GaveUp);
            }
            for (k, &b) in w.iter().enumerate().rev() {
                let at = lo + k;
                *low = at;
                sid = next(&self.rev, cache, sid, b)?;
                if sid.is_tagged() {
                    if sid.is_match() {
                        from = Some(at + 1);
                    } else if sid.is_dead() {
                        return Ok(from);
                    } else if sid.is_quit() {
                        return Err(GaveUp);
                    }
                }
            }
            hi = lo;
        }
        if start > 0 {
            sid = next(&self.rev, cache, sid, byte(src, start - 1))?;
            if sid.is_match() {
                from = Some(start);
            } else if sid.is_quit() {
                return Err(GaveUp);
            }
        } else {
            sid = self.rev.next_eoi_state(cache, sid).map_err(|_| GaveUp)?;
            if sid.is_match() {
                from = Some(0);
            }
        }
        Ok(from)
    }
}

/// The matches a loop of [`StreamRegex::find`] enumerates over an object,
/// each search beginning one byte after the start of the last match, found as
/// the object's bytes arrive in order. Each match comes with the bytes that
/// the searches which found it read, as [`Caches::take_read`] counts them.
#[cfg_attr(not(feature = "yara"), allow(dead_code))]
pub(crate) struct Enumerator<'a> {
    sr: &'a StreamRegex,
    caches: Caches,
    /// The search under way; none once the enumeration is over.
    search: Option<Forward>,
    /// What the first match is charged beyond what its search reads: the
    /// bytes before where the enumeration began, which a search from the start
    /// of the object reads too.
    skipped: usize,
}

#[cfg_attr(not(feature = "yara"), allow(dead_code))]
impl<'a> Enumerator<'a> {
    /// The enumeration of the matches that start at or after `first`: none
    /// if that is past the end of `src`.
    pub(crate) fn new(
        sr: &'a StreamRegex,
        src: &dyn ByteSource,
        first: usize,
    ) -> Result<Self, GaveUp> {
        let mut caches = sr.caches();
        let search = if first > src.len() {
            None
        } else {
            let behind = (first > 0).then(|| byte(src, first - 1));
            Some(sr.forward_begin(&mut caches.fwd, first, behind, Anchored::No)?)
        };
        Ok(Enumerator {
            sr,
            caches,
            search,
            skipped: first,
        })
    }

    /// The memory the searches' state tables take.
    pub(crate) fn memory(&self) -> usize {
        self.caches.memory()
    }

    /// Whether no more matches can come.
    pub(crate) fn is_over(&self) -> bool {
        self.search.is_none()
    }

    /// No more matches can come: the state tables are not needed.
    fn stop(&mut self) {
        self.search = None;
        self.caches = self.sr.caches();
    }

    /// The bytes `at..at + w.len()` of `src`, which follow those given
    /// before. Each match found goes to `on_match(start, end, read)`, which
    /// says whether to go on. `Ok(false)` once the enumeration is over.
    pub(crate) fn feed(
        &mut self,
        src: &dyn ByteSource,
        at: usize,
        w: &[u8],
        on_match: &mut dyn FnMut(usize, usize, usize) -> bool,
    ) -> Result<bool, GaveUp> {
        self.drive(src, at, w, false, on_match)
    }

    /// `src` ends after the bytes given: the matches that remain.
    pub(crate) fn finish(
        &mut self,
        src: &dyn ByteSource,
        on_match: &mut dyn FnMut(usize, usize, usize) -> bool,
    ) -> Result<(), GaveUp> {
        self.drive(src, src.len(), &[], true, on_match).map(|_| ())
    }

    /// Take the bytes up to `at + w.len()`, those before `at` being read
    /// from `src` again when a search starts over inside them.
    fn drive(
        &mut self,
        src: &dyn ByteSource,
        at: usize,
        w: &[u8],
        last: bool,
        on_match: &mut dyn FnMut(usize, usize, usize) -> bool,
    ) -> Result<bool, GaveUp> {
        let upto = at + w.len();
        loop {
            let Some(f) = self.search.as_mut() else {
                return Ok(false);
            };
            let mut over = None;
            while f.at < upto {
                let chunk = if f.at >= at {
                    Cow::Borrowed(&w[f.at - at..])
                } else {
                    src.window(f.at, (at - f.at).min(STEP))
                };
                if chunk.is_empty() {
                    return Err(GaveUp);
                }
                if let Some(end) = self
                    .sr
                    .forward_take(&mut self.caches.fwd, f, &chunk, false)?
                {
                    over = Some(end);
                    break;
                }
            }
            let (start, read, end) = match over {
                Some(end) => (f.start, f.at - f.start, end),
                None if last => {
                    let (start, read) = (f.start, f.at - f.start);
                    let f = self.search.take().ok_or(GaveUp)?;
                    let end = self.sr.forward_eoi(&mut self.caches.fwd, f)?;
                    (start, read, end)
                }
                None => return Ok(true),
            };
            let Some(end) = end else {
                self.stop();
                return Ok(false);
            };
            let mut read = read + std::mem::take(&mut self.skipped);
            let (s, e) = if end == start || self.sr.anchored {
                (start, end)
            } else {
                let mut low = end;
                let from = self
                    .sr
                    .reverse_to(&mut self.caches.rev, src, start, end, &mut low);
                read += end.saturating_sub(low);
                (from?.ok_or(GaveUp)?, end)
            };
            let go_on = on_match(s, e, read);
            let next = s + 1;
            if !go_on || next > src.len() {
                self.stop();
                return Ok(false);
            }
            let behind = Some(byte(src, s));
            self.search =
                Some(
                    self.sr
                        .forward_begin(&mut self.caches.fwd, next, behind, Anchored::No)?,
                );
        }
    }
}

fn next(dfa: &DFA, cache: &mut Cache, sid: LazyStateID, b: u8) -> Result<LazyStateID, GaveUp> {
    dfa.next_state(cache, sid, b).map_err(|_| GaveUp)
}

fn byte(src: &dyn ByteSource, at: usize) -> u8 {
    src.window(at, 1).first().copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_source::BlockCache;
    use std::io::Cursor;

    const PATTERNS: &[&str] = &[
        "abc",
        "a+b",
        "a*",
        "(a|ab)(c|bcd)",
        "^ab",
        "ab$",
        "(?m)^ab$",
        r"\bword\b",
        r"\Bor",
        "[0-9]{3,5}",
        "x?",
        "(?s).+z",
        ".+z",
        "(?i)HeLLo",
        r"\x00\xff+",
        "a{2,}?b",
        "(ab|a)+c",
        r"(?-u)\bfoo",
        "",
        "q|",
        "b+$",
        r"\Aa",
        r"z\z",
        "[^a]{2}",
        r"(?-u)\b\w",
        r"(?-u)\B\w",
        r"(?m)^\w",
    ];

    fn haystacks() -> Vec<Vec<u8>> {
        let mut out = vec![
            b"".to_vec(),
            b"abc".to_vec(),
            b"xxabcdxxaab ab\nab abab".to_vec(),
            b"a word, words wordy word".to_vec(),
            b"12 1234 123456 99999z".to_vec(),
            b"hello HELLO hElLo\x00\xff\xff\xffaab aaab".to_vec(),
            b"caf\xc3\xa9 word \xe9word foo\xe9foo".to_vec(),
        ];
        let mut state = 7u64;
        for _ in 0..20 {
            let mut h = Vec::new();
            for _ in 0..(state % 300) as usize {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let alphabet = b"abcdqxz \n09\xe9\x00word";
                h.push(alphabet[(state % alphabet.len() as u64) as usize]);
            }
            out.push(h);
        }
        out
    }

    /// The matches of a loop of searches, each from one byte past the start of the last
    /// match, from `first`, with the bytes each search read.
    fn searched(
        sr: &StreamRegex,
        src: &dyn ByteSource,
        first: usize,
    ) -> Option<Vec<(usize, usize, usize)>> {
        let mut caches = sr.caches();
        let mut out = Vec::new();
        let mut start = first;
        while start <= src.len() {
            match sr.find(&mut caches, src, start).ok()? {
                Some((s, e)) => {
                    out.push((s, e, caches.take_read()));
                    start = s + 1;
                }
                None => break,
            }
        }
        // What a search from the start of the object reads before `first`.
        if let Some(m) = out.first_mut() {
            m.2 += first;
        }
        Some(out)
    }

    /// An enumerator is handed the bytes in pieces of any size, from any
    /// start. It finds the matches the loop of searches finds, each with the
    /// bytes that loop reads for it, and gives up where that loop does.
    #[test]
    fn an_enumerator_finds_what_a_loop_of_searches_finds() {
        for p in PATTERNS {
            let sr = StreamRegex::bytes_regex(p, 16 << 20).unwrap();
            for h in haystacks() {
                let src = BlockCache::with_sizes(Cursor::new(h.clone()), 3, 12).unwrap();
                for first in [0, 1, h.len() / 2, h.len()] {
                    let want = searched(&sr, &src, first);
                    for piece in [1, 2, 5, 64, 1000] {
                        let mut en = Enumerator::new(&sr, &src, first).unwrap();
                        let mut got = Vec::new();
                        let mut step = |s, e, read| {
                            got.push((s, e, read));
                            true
                        };
                        let mut failed = false;
                        for (i, w) in h[..].chunks(piece).enumerate() {
                            failed |= en.feed(&src, i * piece, w, &mut step).is_err();
                        }
                        failed |= en.finish(&src, &mut step).is_err();
                        let ctx = format!("/{p}/ from {first}, pieces of {piece} on {h:?}");
                        match want {
                            Some(ref want) => {
                                assert!(!failed, "{ctx}");
                                assert_eq!(&got, want, "{ctx}");
                                assert!(en.is_over(), "{ctx}");
                            }
                            None => assert!(failed, "{ctx}"),
                        }
                    }
                }
            }
        }
    }

    /// An enumerator that is told to stop, or is out of matches, takes no
    /// more bytes and holds no more state than a new one.
    #[test]
    fn an_enumerator_stops_where_it_is_told_to() {
        let sr = StreamRegex::bytes_regex("a+", 16 << 20).unwrap();
        let h = b"aaa bbb aaa".to_vec();
        let src = BlockCache::with_sizes(Cursor::new(h.clone()), 3, 12).unwrap();
        let mut en = Enumerator::new(&sr, &src, 0).unwrap();
        let mut got = Vec::new();
        let more = en.feed(&src, 0, &h, &mut |s, e, _| {
            got.push((s, e));
            false
        });
        assert_eq!(more, Ok(false));
        assert_eq!(got, [(0, 3)]);
        assert!(en.is_over());
        assert_eq!(en.memory(), sr.caches().memory());
        assert_eq!(
            en.finish(&src, &mut |_, _, _| panic!("no more matches")),
            Ok(())
        );
    }

    #[test]
    fn matches_what_the_in_memory_regex_matches() {
        for p in PATTERNS {
            let re = regex::bytes::RegexBuilder::new(p)
                .unicode(false)
                .build()
                .unwrap();
            let sr = StreamRegex::bytes_regex(p, 16 << 20).unwrap();
            for h in haystacks() {
                // Blocks of 3 bytes: every read crosses a seam somewhere.
                let src = BlockCache::with_sizes(Cursor::new(h.clone()), 3, 12).unwrap();
                let want: Vec<(usize, usize)> =
                    re.find_iter(&h).map(|m| (m.start(), m.end())).collect();
                let mut got = Vec::new();
                match sr.for_each(&src, &mut |s, e| {
                    got.push((s, e));
                    true
                }) {
                    Ok(()) => assert_eq!(got, want, "/{p}/ on {:?}", String::from_utf8_lossy(&h)),
                    // A Unicode word boundary meeting non-ASCII input.
                    Err(GaveUp) => assert!(p.contains(r"\b") || p.contains(r"\B")),
                }
                if let Ok(m) = sr.is_match(&src) {
                    assert_eq!(m, re.is_match(&h), "/{p}/");
                }
                let mut caches = sr.caches();
                for start in 0..=h.len() {
                    let want = re.find_at(&h, start).map(|m| (m.start(), m.end()));
                    if let Ok(m) = sr.find(&mut caches, &src, start) {
                        assert_eq!(m, want, "/{p}/ at {start}");
                    }
                }
            }
        }
    }
}
