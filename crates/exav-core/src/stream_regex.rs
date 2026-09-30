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
}

pub(crate) struct StreamRegex {
    fwd: DFA,
    rev: DFA,
    /// The pattern can only match at the start of a search.
    anchored: bool,
}

impl StreamRegex {
    /// The regex `regex::bytes::RegexBuilder::new(pattern)` builds, with
    /// `size_limit(nfa_limit)`. `None` where that would fail, or where the lazy
    /// DFAs cannot be built.
    pub(crate) fn bytes_regex(pattern: &str, nfa_limit: usize) -> Option<Self> {
        let hir = syntax::parse_with(pattern, &syntax::Config::new().utf8(false)).ok()?;
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
        Some(StreamRegex { fwd, rev, anchored })
    }

    /// Scratch space for searches with this regex, kept across searches.
    pub(crate) fn caches(&self) -> Caches {
        Caches {
            fwd: self.fwd.create_cache(),
            rev: self.rev.create_cache(),
        }
    }

    /// Whether the pattern matches anywhere in `src`.
    pub(crate) fn is_match(&self, src: &dyn ByteSource) -> Result<bool, GaveUp> {
        let mut caches = self.caches();
        Ok(self.forward(&mut caches.fwd, src, 0, true)?.is_some())
    }

    /// The leftmost-first match starting at or after `start`, as `(start,
    /// end)`: what `meta::Regex::find` returns for `Input::new(bytes).span(start..)`.
    pub(crate) fn find(
        &self,
        caches: &mut Caches,
        src: &dyn ByteSource,
        start: usize,
    ) -> Result<Option<(usize, usize)>, GaveUp> {
        let Some(end) = self.forward(&mut caches.fwd, src, start, false)? else {
            return Ok(None);
        };
        if end == start || self.anchored {
            return Ok(Some((start, end)));
        }
        let from = self
            .reverse(&mut caches.rev, src, start, end)?
            .ok_or(GaveUp)?;
        Ok(Some((from, end)))
    }

    /// The matches `meta::Regex::find_iter` yields over `src`, until `f`
    /// returns `false`.
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
    /// match end at all when `earliest`).
    fn forward(
        &self,
        cache: &mut Cache,
        src: &dyn ByteSource,
        start: usize,
        earliest: bool,
    ) -> Result<Option<usize>, GaveUp> {
        let len = src.len();
        if start > len {
            return Ok(None);
        }
        let behind = (start > 0).then(|| byte(src, start - 1));
        let config = start::Config::new()
            .anchored(Anchored::No)
            .look_behind(behind);
        let mut sid = self.fwd.start_state(cache, &config).map_err(|_| GaveUp)?;
        let mut end = None;
        let mut at = start;
        while at < len {
            let w = src.window(at, (len - at).min(STEP));
            if w.is_empty() {
                return Err(GaveUp);
            }
            for &b in w.iter() {
                sid = next(&self.fwd, cache, sid, b)?;
                if sid.is_tagged() {
                    // Matches are delayed by one byte: this state says a match
                    // ended just before `at`.
                    if sid.is_match() {
                        end = Some(at);
                        if earliest {
                            return Ok(end);
                        }
                    } else if sid.is_dead() {
                        return Ok(end);
                    } else if sid.is_quit() {
                        return Err(GaveUp);
                    }
                }
                at += 1;
            }
        }
        sid = self.fwd.next_eoi_state(cache, sid).map_err(|_| GaveUp)?;
        if sid.is_match() {
            end = Some(len);
        }
        Ok(end)
    }

    /// Start of the match ending at `end`, found by the anchored reverse DFA
    /// run back towards `start`.
    fn reverse(
        &self,
        cache: &mut Cache,
        src: &dyn ByteSource,
        start: usize,
        end: usize,
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

fn next(
    dfa: &DFA,
    cache: &mut Cache,
    sid: regex_automata::hybrid::LazyStateID,
    b: u8,
) -> Result<regex_automata::hybrid::LazyStateID, GaveUp> {
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

    #[test]
    fn matches_what_the_in_memory_regex_matches() {
        for p in PATTERNS {
            let re = regex::bytes::Regex::new(p).unwrap();
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
