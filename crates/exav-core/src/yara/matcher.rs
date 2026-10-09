//! Compiled pattern matchers.
//!
//! Each YARA string/pattern is lowered to a [`PatternMatcher`] that, given a
//! buffer, produces the list of match offsets+lengths. Three kinds:
//!
//! * `Literal`: text patterns (with `nocase`/`ascii`/`wide`/`xor`/`base64`/
//!   `base64wide`/`fullword` handled by expanding into concrete needles).
//! * `Regex`: regexp patterns, run anchored at every start offset so that
//!   overlapping matches are reported the way YARA does.
//! * `Hex`: hex patterns, lowered to an equivalent byte regexp and run like
//!   `Regex` (YARA hex jumps behave like lazy `.{a,b}?` over *any* byte).

use std::ops::Range;

use base64::Engine;
use regex_automata::{meta, meta::Regex, util::syntax, Input};
use regex_syntax::hir::{self, Hir, HirKind};
use regex_syntax::ParserBuilder;
use serde::{Deserialize, Serialize};

use crate::byte_source::{ByteSource, CHUNK};
use crate::stream_regex::{GaveUp, StreamRegex};
use crate::yara::error::{Error, Result};

/// A single match: byte offset and length within the scanned buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Match {
    pub offset: usize,
    pub len: usize,
}

/// One concrete byte needle for a literal pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Needle {
    pub bytes: Vec<u8>,
    /// ASCII case-insensitive comparison (`nocase`).
    pub nocase: bool,
    /// This needle is a `wide` (zero-interleaved) form, which changes how
    /// `fullword` boundaries are checked.
    pub wide: bool,
}

/// A compiled matcher for one pattern.
pub(crate) enum PatternMatcher {
    Literal {
        needles: Vec<Needle>,
        /// XOR key range (inclusive) if the `xor` modifier is present.
        xor: Option<(u8, u8)>,
        fullword: bool,
    },
    Regex {
        re: Regex,
        fullword: bool,
        /// This regexp matches the `wide` (zero-interleaved) form, which changes
        /// how `fullword` boundaries are checked (2-byte neighbours).
        wide: bool,
    },
    /// A `wide ascii` regexp: the union of matches of the plain form and the
    /// widened form (yara-x runs both as separate sub-patterns).
    RegexMulti {
        ascii: Regex,
        wide: Regex,
        fullword: bool,
    },
    /// Hex pattern compiled to an equivalent byte regexp.
    Hex { re: Regex },
    /// `base64` / `base64wide` patterns: each candidate found by substring
    /// search is verified by decoding, exactly like yara-x, to avoid the false
    /// positives the naive substring approach would produce.
    Base64 { entries: Vec<Base64Sub> },
}

/// One base64 sub-pattern to search for, plus what is needed to verify it.
pub(crate) struct Base64Sub {
    /// The (possibly widened) base64 bytes searched for in the data.
    pub searched: Vec<u8>,
    /// The pre-encoded pattern bytes the decoded data must contain.
    pub pattern: Vec<u8>,
    pub padding: u8,
    pub wide: bool,
    pub engine: base64::engine::GeneralPurpose,
}

// ---------------------------------------------------------------------------
// Serializable pattern definitions
// ---------------------------------------------------------------------------
//
// A [`PatternMatcher`] holds a compiled `regex_automata::meta::Regex` (and a
// `base64` engine), neither of which is serde-serializable and neither of which
// can hand back the source it was built from. So the on-disk database does NOT
// store the compiled matcher; it stores a [`PatternDef`], the pattern's
// *definition* (regex source + flags, or the literal/base64 needle bytes), from
// which [`PatternDef::compile`] rebuilds an identical `PatternMatcher` on load.
// Rebuilding a single pattern's regex is cheap; the aggregate cost that the
// serialized database avoids is the atom index build (see
// [`crate::yara::atoms`]), which is serialized separately.

/// The serializable definition of one `base64`/`base64wide` sub-pattern. Mirrors
/// [`Base64Sub`] but stores the base64 `alphabet` (to rebuild the non-serde
/// `engine`) instead of the compiled engine itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Base64SubDef {
    pub searched: Vec<u8>,
    pub pattern: Vec<u8>,
    pub padding: u8,
    pub wide: bool,
    /// The custom base64 alphabet (`None` = standard), used to rebuild `engine`.
    pub alphabet: Option<String>,
}

/// The serializable definition of one compiled pattern. Recompiled into a
/// [`PatternMatcher`] by [`PatternDef::compile`]. For regexp/hex patterns only
/// the regex SOURCE + flags are stored (the compiled automaton is rebuilt); for
/// literal/base64 patterns the concrete needle bytes + modifiers are stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum PatternDef {
    Literal {
        needles: Vec<Needle>,
        xor: Option<(u8, u8)>,
        fullword: bool,
    },
    Regex {
        src: String,
        ci: bool,
        dotall: bool,
        fullword: bool,
        wide: bool,
    },
    RegexMulti {
        src: String,
        ci: bool,
        dotall: bool,
        fullword: bool,
    },
    Hex {
        /// The byte-regex source the hex pattern was lowered to.
        re_src: String,
    },
    Base64 {
        entries: Vec<Base64SubDef>,
    },
}

impl PatternDef {
    /// Rebuilds the runtime [`PatternMatcher`], recompiling per-pattern regexes
    /// (and base64 engines) from their stored source. The construction is
    /// identical, step for step, to the compiler's fresh lowering, so a matcher
    /// rebuilt from a def behaves byte-for-byte like the originally compiled one.
    pub(crate) fn compile(&self) -> Result<PatternMatcher> {
        Ok(match self {
            PatternDef::Literal {
                needles,
                xor,
                fullword,
            } => PatternMatcher::Literal {
                needles: needles.clone(),
                xor: *xor,
                fullword: *fullword,
            },
            PatternDef::Regex {
                src,
                ci,
                dotall,
                fullword,
                wide,
            } => {
                let re = if *wide {
                    build_wide_regex(src, *ci, *dotall)?
                } else {
                    build_regex(src, *ci, *dotall)?
                };
                PatternMatcher::Regex {
                    re,
                    fullword: *fullword,
                    wide: *wide,
                }
            }
            PatternDef::RegexMulti {
                src,
                ci,
                dotall,
                fullword,
            } => PatternMatcher::RegexMulti {
                ascii: build_regex(src, *ci, *dotall)?,
                wide: build_wide_regex(src, *ci, *dotall)?,
                fullword: *fullword,
            },
            PatternDef::Hex { re_src } => PatternMatcher::Hex {
                re: build_regex(re_src, false, false)?,
            },
            PatternDef::Base64 { entries } => {
                let entries = entries
                    .iter()
                    .map(|e| {
                        Ok(Base64Sub {
                            searched: e.searched.clone(),
                            pattern: e.pattern.clone(),
                            padding: e.padding,
                            wide: e.wide,
                            engine: b64_engine(e.alphabet.as_deref())?,
                        })
                    })
                    .collect::<Result<_>>()?;
                PatternMatcher::Base64 { entries }
            }
        })
    }
}

/// Builds a NO_PAD base64 engine for the given alphabet (standard if `None`).
/// Shared by the compiler (fresh lowering) and [`PatternDef::compile`] (load).
/// An alphabet read from a database is not trusted: one that is not 64 distinct
/// printable characters is an error.
pub(crate) fn b64_engine(alphabet: Option<&str>) -> Result<base64::engine::GeneralPurpose> {
    let alph = match alphabet {
        None => base64::alphabet::STANDARD,
        Some(a) => base64::alphabet::Alphabet::new(a)
            .map_err(|e| Error::new(format!("invalid base64 alphabet: {e}")))?,
    };
    Ok(base64::engine::GeneralPurpose::new(
        &alph,
        base64::engine::general_purpose::NO_PAD,
    ))
}

#[inline]
fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Full-word boundary check, byte-for-byte identical to yara-x's
/// `verify_full_word` (fullword modifier: neighbours must be non-alphanumeric;
/// underscore is NOT a word byte here, unlike regex `\b`).
fn verify_full_word(data: &[u8], start: usize, end: usize, wide: bool, xor_key: u8) -> bool {
    let before = &data[start.saturating_sub(2)..start];
    let after = &data[end..(end + 2).min(data.len())];
    full_word_between(before, after, wide, xor_key)
}

/// [`verify_full_word`] given the (up to) two bytes before the match and the
/// (up to) two bytes after it.
fn full_word_between(before: &[u8], after: &[u8], wide: bool, xor_key: u8) -> bool {
    if wide {
        if let [a, b] = before {
            if (b ^ xor_key) == 0 && is_word(a ^ xor_key) {
                return false;
            }
        }
        if let [a, b] = after {
            if (b ^ xor_key) == 0 && is_word(a ^ xor_key) {
                return false;
            }
        }
    } else {
        if before.last().is_some_and(|b| is_word(b ^ xor_key)) {
            return false;
        }
        if after.first().is_some_and(|b| is_word(b ^ xor_key)) {
            return false;
        }
    }
    true
}

/// [`verify_full_word`] over a source, reading only the neighbours.
fn full_word_in(src: &dyn ByteSource, start: usize, end: usize, wide: bool) -> bool {
    let from = start.saturating_sub(2);
    let before = src.window(from, start - from);
    let after = src.window(end, 2);
    full_word_between(&before, &after, wide, 0)
}

#[inline]
fn needle_hit(data: &[u8], pos: usize, n: &Needle, key: u8) -> bool {
    let bytes = &n.bytes;
    if pos + bytes.len() > data.len() {
        return false;
    }
    let hay = &data[pos..pos + bytes.len()];
    if n.nocase {
        for (&d, &p) in hay.iter().zip(bytes) {
            if !d.eq_ignore_ascii_case(&(p ^ key)) {
                return false;
            }
        }
    } else {
        for (&d, &p) in hay.iter().zip(bytes) {
            if d != (p ^ key) {
                return false;
            }
        }
    }
    true
}

/// Matches one pattern keeps. Past it the rest are dropped and the pattern's
/// search is incomplete. yara-x stops at the same count.
pub(crate) const MAX_MATCHES: usize = 1_000_000;

/// The matches found for one pattern.
pub(crate) struct Found {
    /// Sorted by offset then length, without duplicates.
    pub matches: Vec<Match>,
    /// Every match was found: the pattern stayed under [`MAX_MATCHES`] and
    /// was searched through the whole object.
    pub complete: bool,
}

/// Matches as they are found, up to [`MAX_MATCHES`].
struct Collector {
    out: Vec<Match>,
    full: bool,
}

impl Collector {
    fn new() -> Self {
        Collector {
            out: Vec::new(),
            full: false,
        }
    }

    fn push(&mut self, offset: usize, len: usize) {
        if self.out.len() < MAX_MATCHES {
            self.out.push(Match { offset, len });
        } else {
            self.full = true;
        }
    }
}

/// A pattern's regexes as a search over a source runs them, each with
/// whether it is the `wide` form.
pub(crate) type StreamRegexes = Vec<(StreamRegex, bool)>;

/// Hands out a pattern's [`StreamRegexes`], built on first use.
pub(crate) type RegexSource<'s> = &'s dyn Fn() -> Option<&'s StreamRegexes>;

/// Cap on the NFA one regexp compiles to.
const NFA_SIZE_LIMIT: usize = 64 << 20;
impl PatternDef {
    /// The regexes of a regexp or hex pattern for a search over a source,
    /// matching what [`PatternDef::compile`]'s `meta` regexes match. `None`
    /// for other patterns, or where one cannot be built.
    pub(crate) fn stream_regexes(&self) -> Option<StreamRegexes> {
        let build = |src: &str, ci: bool, dotall: bool, wide: bool| {
            let hir = parse_hir(src, ci, dotall).ok()?;
            let hir = if wide { widen_hir(hir) } else { hir };
            Some((StreamRegex::from_hir(&hir, Some(NFA_SIZE_LIMIT))?, wide))
        };
        match self {
            PatternDef::Regex {
                src,
                ci,
                dotall,
                wide,
                ..
            } => Some(vec![build(src, *ci, *dotall, *wide)?]),
            PatternDef::RegexMulti {
                src, ci, dotall, ..
            } => Some(vec![
                build(src, *ci, *dotall, false)?,
                build(src, *ci, *dotall, true)?,
            ]),
            PatternDef::Hex { re_src } => Some(vec![build(re_src, false, false, false)?]),
            PatternDef::Literal { .. } | PatternDef::Base64 { .. } => None,
        }
    }
}

/// [`PatternMatcher::find_all`] of several [windowed](PatternMatcher::windowed)
/// patterns over a source not held in memory, in one read of it rather than a
/// read each: every window holds what any of their matches needs around it.
pub(crate) fn find_all_windowed(pats: &[&PatternMatcher], src: &dyn ByteSource) -> Vec<Found> {
    let (before, after) = pats
        .iter()
        .map(|p| p.reach())
        .fold((0, 0), |(b, a), (pb, pa)| (b.max(pb), a.max(pa)));
    let len = src.len();
    let mut outs: Vec<Collector> = pats.iter().map(|_| Collector::new()).collect();
    let mut complete = true;
    let mut base = 0;
    while base < len && outs.iter().any(|o| !o.full) {
        let end = (base + CHUNK).min(len);
        let from = base.saturating_sub(before);
        let to = end.saturating_add(after).min(len);
        let w = src.window(from, to - from);
        if w.len() != to - from {
            complete = false;
            break;
        }
        for (p, out) in pats.iter().zip(&mut outs) {
            if !out.full {
                p.search(&w, base - from..end - from, from, out);
            }
        }
        base = end;
    }
    outs.into_iter()
        .map(|out| {
            let mut matches = out.out;
            matches.sort_unstable_by(|a, b| a.offset.cmp(&b.offset).then(a.len.cmp(&b.len)));
            matches.dedup();
            Found {
                matches,
                complete: complete && !out.full,
            }
        })
        .collect()
}

impl PatternMatcher {
    /// Whether [`find_all_windowed`] searches this pattern: a literal or a
    /// base64 one, whose matches need a bounded context around them.
    pub(crate) fn windowed(&self) -> bool {
        matches!(
            self,
            PatternMatcher::Literal { .. } | PatternMatcher::Base64 { .. }
        )
    }

    /// Every match in `src`. `stream` supplies the pattern's regexes for a
    /// source not held in memory; `materialize` is the largest such source
    /// read whole when they cannot follow it.
    pub(crate) fn find_all(
        &self,
        src: &dyn ByteSource,
        stream: RegexSource<'_>,
        materialize: usize,
    ) -> Found {
        let mut out = Collector::new();
        let mut complete = true;
        match src.as_slice() {
            Some(data) => self.search(data, 0..data.len(), 0, &mut out),
            None => complete = self.search_source(src, stream, materialize, &mut out),
        }
        let mut matches = out.out;
        matches.sort_unstable_by(|a, b| a.offset.cmp(&b.offset).then(a.len.cmp(&b.len)));
        matches.dedup();
        Found {
            matches,
            complete: complete && !out.full,
        }
    }

    /// The matches starting at a position in `keep` of `data`, reported at
    /// `origin` plus their position. `data` holds whatever each match needs
    /// around it (see [`Self::reach`]) or ends where the object ends.
    fn search(&self, data: &[u8], keep: Range<usize>, origin: usize, out: &mut Collector) {
        match self {
            PatternMatcher::Literal {
                needles,
                xor,
                fullword,
            } => match xor {
                // Non-xor (single key 0): exact byte search. The case-sensitive
                // form uses `memmem` (SIMD substring search) instead of a
                // per-position loop; the `nocase` form keeps the byte loop.
                None => {
                    for n in needles {
                        if n.bytes.is_empty() || n.bytes.len() > data.len() {
                            continue;
                        }
                        let last = data.len() - n.bytes.len();
                        if n.nocase {
                            for pos in keep.start..keep.end.min(last + 1) {
                                if needle_hit(data, pos, n, 0) {
                                    let end = pos + n.bytes.len();
                                    if !*fullword || verify_full_word(data, pos, end, n.wide, 0) {
                                        out.push(origin + pos, n.bytes.len());
                                    }
                                }
                            }
                        } else {
                            // Overlapping search: YARA reports a match at EVERY
                            // start offset (e.g. `"aaaa"` in `"aaaaaa"` → 3), so
                            // we advance the search window by one byte, not by the
                            // needle length (which `memmem::find_iter` would do).
                            let mut base = keep.start;
                            while let Some(off) = memchr::memmem::find(&data[base..], &n.bytes) {
                                let pos = base + off;
                                if pos >= keep.end {
                                    break;
                                }
                                let end = pos + n.bytes.len();
                                if !*fullword || verify_full_word(data, pos, end, n.wide, 0) {
                                    out.push(origin + pos, n.bytes.len());
                                }
                                base = pos + 1;
                            }
                        }
                    }
                }
                // XOR: scan every position for every key.
                Some((s, e)) => {
                    let keys: Vec<u8> = (*s..=*e).collect();
                    for n in needles {
                        if n.bytes.is_empty() || n.bytes.len() > data.len() {
                            continue;
                        }
                        let last = data.len() - n.bytes.len();
                        for pos in keep.start..keep.end.min(last + 1) {
                            for &key in &keys {
                                if needle_hit(data, pos, n, key) {
                                    let end = pos + n.bytes.len();
                                    if !*fullword || verify_full_word(data, pos, end, n.wide, key) {
                                        out.push(origin + pos, n.bytes.len());
                                    }
                                    // A given position can only be XOR-decoded by
                                    // one key at a time for a fixed plaintext, but
                                    // other keys may also spuriously hit; record
                                    // the first hit and move on to keep counts sane.
                                    break;
                                }
                            }
                        }
                    }
                }
            },
            // Regexes are only searched whole: their matches have no bound.
            PatternMatcher::Regex { re, fullword, wide } => {
                anchored_matches(re, data, out, *fullword, *wide);
            }
            PatternMatcher::RegexMulti {
                ascii,
                wide,
                fullword,
            } => {
                anchored_matches(ascii, data, out, *fullword, false);
                anchored_matches(wide, data, out, *fullword, true);
            }
            PatternMatcher::Hex { re } => {
                anchored_matches(re, data, out, false, false);
            }
            PatternMatcher::Base64 { entries } => {
                for e in entries {
                    if e.searched.is_empty() || e.searched.len() > data.len() {
                        continue;
                    }
                    let last = data.len() - e.searched.len();
                    for pos in keep.start..keep.end.min(last + 1) {
                        if data[pos..].starts_with(&e.searched) {
                            if let Some(r) = verify_base64(
                                &e.pattern,
                                data,
                                e.padding as usize,
                                pos,
                                &e.engine,
                                e.wide,
                            ) {
                                out.push(origin + r.0, r.1 - r.0);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Bytes a literal or base64 match at `pos` is checked against: how many
    /// before `pos`, and how many from `pos` on.
    fn reach(&self) -> (usize, usize) {
        match self {
            // The needle, and two bytes each side for `fullword`.
            PatternMatcher::Literal { needles, .. } => {
                let longest = needles.iter().map(|n| n.bytes.len()).max().unwrap_or(0);
                (2, longest + 2)
            }
            // What `verify_base64` decodes: from up to 3 characters before
            // the match (twice that when wide) to its decode length after.
            PatternMatcher::Base64 { entries } => {
                let after = entries
                    .iter()
                    .map(|e| {
                        let len = base64::encoded_len(e.pattern.len(), false).unwrap_or(0);
                        e.searched.len().max(2 * (len + 5))
                    })
                    .max()
                    .unwrap_or(0);
                (6, after)
            }
            PatternMatcher::Regex { .. }
            | PatternMatcher::RegexMulti { .. }
            | PatternMatcher::Hex { .. } => (0, 0),
        }
    }

    /// [`Self::search`] over a source not held in memory. `false` when some
    /// of it could not be searched.
    fn search_source(
        &self,
        src: &dyn ByteSource,
        stream: RegexSource<'_>,
        materialize: usize,
        out: &mut Collector,
    ) -> bool {
        let len = src.len();
        match self {
            PatternMatcher::Literal { .. } | PatternMatcher::Base64 { .. } => {
                // Chunks, each read with the bytes its matches need around them.
                let (before, after) = self.reach();
                let mut base = 0;
                while base < len && !out.full {
                    let end = (base + CHUNK).min(len);
                    let from = base.saturating_sub(before);
                    let to = end.saturating_add(after).min(len);
                    let w = src.window(from, to - from);
                    if w.len() != to - from {
                        return false;
                    }
                    self.search(&w, base - from..end - from, from, out);
                    base = end;
                }
                true
            }
            PatternMatcher::Regex { fullword, .. }
            | PatternMatcher::RegexMulti { fullword, .. } => {
                let fullword = *fullword;
                self.search_regexes(src, stream, materialize, fullword, out)
            }
            PatternMatcher::Hex { .. } => self.search_regexes(src, stream, materialize, false, out),
        }
    }

    fn search_regexes(
        &self,
        src: &dyn ByteSource,
        stream: RegexSource<'_>,
        materialize: usize,
        fullword: bool,
        out: &mut Collector,
    ) -> bool {
        let found = stream().and_then(|regexes| {
            let mut found = Collector::new();
            for (sr, wide) in regexes.iter() {
                stream_matches(sr, src, &mut found, fullword, *wide).ok()?;
            }
            Some(found)
        });
        if let Some(found) = found {
            out.full |= found.full;
            out.out.extend(found.out);
            return true;
        }
        // The lazy DFAs gave up, or could not be built: the object is searched
        // whole, as in memory, if it may be read whole.
        match src.materialize(materialize) {
            Some(data) => {
                self.search(&data, 0..data.len(), 0, out);
                true
            }
            None => false,
        }
    }
}

/// Records one match per start offset at which the regexp matches, reproducing
/// YARA's overlapping-match semantics (e.g. `/a{1,}/` on `aaaaa` yields five
/// matches).
///
/// This is a leftmost-first *unanchored* sweep that is provably identical to the
/// old "anchor at every offset" loop, but O(matches) instead of O(n²): an
/// unanchored `find` from `start` returns the leftmost match `s ≥ start`, and
/// because the meta engine uses the same leftmost-first semantics, that match is
/// byte-for-byte the one an anchored search at `s` would produce. No offset in
/// `[start, s)` can begin a match (else it would be the leftmost), so nothing is
/// skipped; resuming at `s + 1` then enumerates every match-start in order.
fn anchored_matches(re: &Regex, data: &[u8], out: &mut Collector, fullword: bool, wide: bool) {
    let len = data.len();
    let mut start = 0;
    while start <= len && !out.full {
        let input = Input::new(data).span(start..len);
        match re.find(input) {
            Some(m) => {
                let s = m.start();
                let e = m.end();
                if e > s && (!fullword || verify_full_word(data, s, e, wide, 0)) {
                    out.push(s, e - s);
                }
                start = s + 1;
            }
            None => break,
        }
    }
}

/// [`anchored_matches`] over a source, with the regex stepped through it.
fn stream_matches(
    sr: &StreamRegex,
    src: &dyn ByteSource,
    out: &mut Collector,
    fullword: bool,
    wide: bool,
) -> std::result::Result<(), GaveUp> {
    let mut caches = sr.caches();
    let len = src.len();
    let mut start = 0;
    while start <= len && !out.full {
        match sr.find(&mut caches, src, start)? {
            Some((s, e)) => {
                if e > s && (!fullword || full_word_in(src, s, e, wide)) {
                    out.push(s, e - s);
                }
                start = s + 1;
            }
            None => break,
        }
    }
    Ok(())
}

/// Verifies that `pattern` actually matches in base64 form at `match_start`.
/// Returns the `(start, end)` byte range on success. Close port of yara-x's
/// `verify_base64` (see LICENSE-YARA-X).
fn verify_base64(
    pattern: &[u8],
    data: &[u8],
    padding: usize,
    match_start: usize,
    engine: &base64::engine::GeneralPurpose,
    wide: bool,
) -> Option<(usize, usize)> {
    if pattern.is_empty() {
        return None;
    }
    let len = base64::encoded_len(pattern.len(), false)?;

    let (mut decode_start_delta, mut decode_len, mut match_len) = match padding {
        0 => match len % 4 {
            0 => (0, len, len),
            2 => (0, len + 2, len - 1),
            3 => (0, len + 1, len - 1),
            _ => return None,
        },
        1 => match len % 4 {
            0 => (2, len + 4, len - 1),
            2 => (2, len + 2, len - 2),
            3 => (2, len + 1, len - 1),
            _ => return None,
        },
        2 => match len % 4 {
            0 => (3, len + 4, len - 1),
            2 => (3, len + 2, len - 1),
            3 => (3, len + 5, len - 1),
            _ => return None,
        },
        _ => return None,
    };

    if wide {
        decode_start_delta *= 2;
        decode_len *= 2;
        match_len *= 2;
    }

    let decode_start = match_start.checked_sub(decode_start_delta)?;
    let mut end = decode_start + decode_len;
    if end > data.len() {
        end = data.len();
    }
    let slice = &data[decode_start..end];

    let encoded: Vec<u8> = if wide {
        let mut ascii = Vec::with_capacity(slice.len() / 2 + 1);
        for (i, &b) in slice.iter().enumerate() {
            if i % 2 == 0 {
                if b != b'=' {
                    ascii.push(b);
                }
            } else if b != 0 {
                return None;
            }
        }
        ascii
    } else {
        let mut s = slice;
        if s.ends_with(b"==") {
            s = &s[..s.len().saturating_sub(2)];
        } else if s.ends_with(b"=") {
            s = &s[..s.len().saturating_sub(1)];
        }
        s.to_vec()
    };

    let mut decoded = vec![0u8; base64::decoded_len_estimate(encoded.len())];
    let decoded_len = engine.decode_slice(&encoded, &mut decoded).ok()?;
    decoded.truncate(decoded_len);

    let decoded_pattern = decoded.get(padding..padding + pattern.len())?;
    if pattern == decoded_pattern {
        Some((match_start, match_start + match_len))
    } else {
        None
    }
}

/// Interleave a zero byte after every byte (`wide` transform).
pub(crate) fn widen(bytes: &[u8]) -> Vec<u8> {
    let mut w = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        w.push(b);
        w.push(0);
    }
    w
}

/// Builds a byte-oriented [`Regex`] with YARA semantics: no Unicode by default
/// (`.` matches any byte except `\n`, `\w`/`\d` are ASCII), matching allowed at
/// non-UTF-8 boundaries. `case_insensitive` and `dot_matches_new_line` map to
/// the `/i` and `/s` flags. Inline flags in the pattern (`(?u)`, `(?m)`, …) are
/// honoured by the engine.
pub(crate) fn build_regex(
    pattern: &str,
    case_insensitive: bool,
    dot_matches_new_line: bool,
) -> Result<Regex> {
    let normalized = normalize_yara_regex(pattern);
    let cfg = syntax::Config::new()
        .unicode(false)
        .utf8(false)
        .case_insensitive(case_insensitive)
        .dot_matches_new_line(dot_matches_new_line)
        .multi_line(false);
    // Caps on what compiling one rule may allocate. A bounded-repetition
    // pattern expands during construction, so a rule can ask for far more
    // memory than its source suggests, and the failure lands at database-load
    // time where it is least expected. These are failsafes over trusted
    // content (the database is a trusted input), so they are set high enough
    // that no reasonable rule meets them, and a rule that does is rejected by
    // name rather than taking the process with it.
    //
    // This is not a defence against catastrophic backtracking: `regex-automata`
    // builds finite automata and does not backtrack. The risk here is
    // compile-time memory, not match-time blowup.
    let limits = meta::Config::new()
        .nfa_size_limit(Some(NFA_SIZE_LIMIT))
        .dfa_size_limit(Some(16 << 20))
        .onepass_size_limit(Some(8 << 20));
    Regex::builder()
        .syntax(cfg)
        .configure(limits)
        .build(&normalized)
        .map_err(|e| Error::new(format!("invalid regexp `/{pattern}/`: {e}")))
}

/// Parses a normalized YARA regexp into a byte-oriented [`Hir`] using the SAME
/// syntax configuration [`build_regex`] compiles under (no Unicode, matching
/// allowed at non-UTF-8 boundaries). Shared by the `wide`-regexp lowering below
/// and the atom extractor ([`crate::yara::atoms`]) so both see an identical HIR.
pub(crate) fn parse_hir(
    src: &str,
    case_insensitive: bool,
    dot_matches_new_line: bool,
) -> Result<Hir> {
    let normalized = normalize_yara_regex(src);
    let mut parser = ParserBuilder::new()
        .utf8(false)
        .unicode(false)
        .case_insensitive(case_insensitive)
        .dot_matches_new_line(dot_matches_new_line)
        .multi_line(false)
        .build();
    parser
        .parse(&normalized)
        .map_err(|e| Error::new(format!("invalid regexp `/{src}/`: {e}")))
}

/// Rewrites an [`Hir`] into its `wide` (UTF-16LE) form: every byte the regexp
/// would consume is followed by a mandatory `\x00`. This reproduces yara-x's
/// `wide`-regexp semantics exactly: yara-x matches such a pattern against a
/// stream in which each data byte is interleaved with a zero byte, and reports a
/// match length of `2 × (bytes consumed)` (the trailing zero of the last byte is
/// part of the match). Widening a literal interleaves a zero after every byte;
/// widening a class matches one class byte then a zero; repetitions/alternations/
/// captures/concats widen their children (so the zero-interleaving is applied
/// per matched byte inside a repetition); zero-width looks/anchors are preserved
/// unchanged (they consume no byte, hence add no zero).
pub(crate) fn widen_hir(hir: Hir) -> Hir {
    match hir.into_kind() {
        HirKind::Empty => Hir::empty(),
        HirKind::Literal(hir::Literal(bytes)) => {
            let mut w = Vec::with_capacity(bytes.len() * 2);
            for &b in bytes.iter() {
                w.push(b);
                w.push(0);
            }
            Hir::literal(w)
        }
        HirKind::Class(class) => Hir::concat(vec![Hir::class(class), Hir::literal([0u8])]),
        HirKind::Look(look) => Hir::look(look),
        HirKind::Repetition(mut rep) => {
            rep.sub = Box::new(widen_hir(*rep.sub));
            Hir::repetition(rep)
        }
        HirKind::Capture(mut cap) => {
            cap.sub = Box::new(widen_hir(*cap.sub));
            Hir::capture(cap)
        }
        HirKind::Concat(subs) => Hir::concat(subs.into_iter().map(widen_hir).collect()),
        HirKind::Alternation(subs) => Hir::alternation(subs.into_iter().map(widen_hir).collect()),
    }
}

/// Builds a [`Regex`] for a `wide` regexp pattern: the pattern is lowered to an
/// [`Hir`], widened via [`widen_hir`], and compiled from that HIR under the same
/// byte-oriented (non-UTF-8) engine configuration as [`build_regex`].
pub(crate) fn build_wide_regex(
    pattern: &str,
    case_insensitive: bool,
    dot_matches_new_line: bool,
) -> Result<Regex> {
    let hir = parse_hir(pattern, case_insensitive, dot_matches_new_line)?;
    let wide = widen_hir(hir);
    // Build straight from the byte-oriented HIR. `utf8_empty(false)` mirrors the
    // `syntax::Config::utf8(false)` used by `build_regex`, so matching is allowed
    // at non-UTF-8 boundaries (relevant since the widened stream is full of
    // interleaved `\x00`s).
    Regex::builder()
        .configure(Regex::config().utf8_empty(false))
        .build_from_hir(&wide)
        .map_err(|e| Error::new(format!("invalid wide regexp `/{pattern}/`: {e}")))
}

/// Normalizes YARA-flavour quantifiers that the Rust regex crate rejects:
/// `{,n}` -> `{0,n}` and spaces inside `{ .. }` counted repetitions are
/// stripped (`{1, 2}` -> `{1,2}`). Character classes and escapes are left
/// untouched. Operates on bytes and only ever inserts ASCII, so the output is
/// valid UTF-8 whenever the input is.
pub(crate) fn normalize_yara_regex(src: &str) -> String {
    let b = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len() + 4);
    let mut i = 0;
    let mut in_class = false;
    while i < b.len() {
        let c = b[i];
        if c == b'\\' {
            out.push(c);
            if i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_class {
            out.push(c);
            if c == b']' {
                in_class = false;
            }
            i += 1;
            continue;
        }
        if c == b'[' {
            in_class = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == b'{' {
            if let Some(rel) = b[i + 1..].iter().position(|&x| x == b'}') {
                let close = i + 1 + rel;
                let inner = &src[i + 1..close];
                let is_quant = inner
                    .chars()
                    .all(|ch| ch.is_ascii_digit() || ch == ',' || ch.is_whitespace())
                    && inner.chars().any(|ch| ch.is_ascii_digit() || ch == ',');
                if is_quant {
                    let cleaned: String = inner.chars().filter(|ch| !ch.is_whitespace()).collect();
                    let cleaned = if let Some(rest) = cleaned.strip_prefix(',') {
                        format!("0,{rest}")
                    } else {
                        cleaned
                    };
                    out.push(b'{');
                    out.extend_from_slice(cleaned.as_bytes());
                    out.push(b'}');
                    i = close + 1;
                    continue;
                }
            }
            out.push(c);
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| src.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base64_def(searched: &[u8], pattern: &[u8], alphabet: Option<&str>) -> PatternDef {
        PatternDef::Base64 {
            entries: vec![Base64SubDef {
                searched: searched.to_vec(),
                pattern: pattern.to_vec(),
                padding: 0,
                wide: false,
                alphabet: alphabet.map(String::from),
            }],
        }
    }

    fn found(def: &PatternDef, data: &[u8]) -> Vec<Match> {
        let mut out = Collector::new();
        def.compile()
            .unwrap()
            .search(data, 0..data.len(), 0, &mut out);
        out.out
    }

    /// The rules of a database are not trusted: an alphabet that is not 64
    /// distinct characters is an error, not a panic.
    #[test]
    fn a_stored_base64_alphabet_of_the_wrong_length_is_refused() {
        assert!(base64_def(b"YWJj", b"abc", Some("abc")).compile().is_err());
        assert!(base64_def(b"YWJj", b"abc", None).compile().is_ok());
    }

    /// A stored pattern with nothing to decode to has no match to report: it
    /// matched with a length of zero at every place its needle was.
    #[test]
    fn a_stored_base64_pattern_that_is_empty_matches_nothing() {
        assert_eq!(
            found(&base64_def(b"YWJj", b"abc", None), b"..YWJj..").len(),
            1
        );
        assert!(found(&base64_def(b"YWJj", b"", None), b"..YWJj..").is_empty());
    }
}
