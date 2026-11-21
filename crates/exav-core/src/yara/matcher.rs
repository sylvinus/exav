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
use regex_automata::{Anchored, Input, meta, meta::Regex, util::syntax};
use regex_syntax::ParserBuilder;
use regex_syntax::hir::{self, Hir, HirKind};
use serde::{Deserialize, Serialize};

use crate::byte_source::{ByteSource, CHUNK};
use crate::fancy_regex::STEP_BYTES;
use crate::stream_regex::{Enumerator, GaveUp, StreamRegex};
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
        if let [a, b] = before
            && (b ^ xor_key) == 0
            && is_word(a ^ xor_key)
        {
            return false;
        }
        if let [a, b] = after
            && (b ^ xor_key) == 0
            && is_word(a ^ xor_key)
        {
            return false;
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
    /// Every match was found: the pattern stayed under [`MAX_MATCHES`], was
    /// searched through the whole object (at its offset, if it is anchored
    /// there), and its regexp searches did not reach the limit of their work.
    pub complete: bool,
    /// The pattern has more than [`MAX_MATCHES`] matches. Implies `!complete`.
    pub capped: bool,
    /// Why a regexp or hex pattern's search stopped short, when it did.
    pub regex_cut: Option<RegexCut>,
}

/// Why the search of a regexp or hex pattern did not finish.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum RegexCut {
    /// Its searches made the steps they may (`--max-regex-steps`).
    Steps,
    /// It needed the object whole, past the size read whole
    /// (`--max-object-bytes`).
    Whole,
}

/// Matches as they are found, up to [`MAX_MATCHES`], and the work left to the
/// regexp searches that find them.
struct Collector {
    out: Vec<Match>,
    /// The offset the pattern is anchored at ([`crate::yara::ir::anchors`]):
    /// matches elsewhere are not kept.
    only: Option<usize>,
    full: bool,
    /// Bytes that the searches of the pattern may still read, `usize::MAX`
    /// for no limit.
    room: usize,
    /// A search was left undone for want of room.
    spent: bool,
}

impl Collector {
    /// A collector whose regexp searches may make `steps` steps, a step
    /// being [`STEP_BYTES`] bytes read.
    fn new(steps: usize) -> Self {
        Collector {
            out: Vec::new(),
            only: None,
            full: false,
            room: steps.saturating_mul(STEP_BYTES),
            spent: false,
        }
    }

    /// No more matches can be had: the pattern is at [`MAX_MATCHES`] or out
    /// of room.
    fn done(&self) -> bool {
        self.full || self.spent
    }

    fn limited(&self) -> bool {
        self.room != usize::MAX
    }

    /// Charges `bytes` read by a search; `false` when that is more than the
    /// room left.
    fn spend(&mut self, bytes: usize) -> bool {
        if !self.limited() {
            return true;
        }
        match self.room.checked_sub(bytes) {
            Some(left) => {
                self.room = left;
                true
            }
            None => {
                self.room = 0;
                self.spent = true;
                false
            }
        }
    }

    /// The collector of a pattern anchored at `only`, if it is.
    fn only(mut self, only: Option<usize>) -> Self {
        self.only = only;
        self
    }

    fn push(&mut self, offset: usize, len: usize) {
        if self.only.is_some_and(|at| at != offset) {
            return;
        }
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
    // No regexp among them: nothing to limit, nothing to measure.
    let no_regexes = || None;
    let mut outs: Vec<Collector> = pats.iter().map(|_| Collector::new(usize::MAX)).collect();
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
                p.search(&w, base - from..end - from, from, &no_regexes, out);
            }
        }
        base = end;
    }
    outs.into_iter()
        .map(|out| sorted(out.out, complete && !out.full, out.full))
        .collect()
}

/// The matches of a [windowed](PatternMatcher::windowed) pattern, found a
/// stretch of the object at a time as a read of it goes by.
pub(crate) struct WindowedTap {
    out: Collector,
}

impl WindowedTap {
    /// The tap of a pattern anchored at `only`, if it is.
    pub(crate) fn new(only: Option<usize>) -> Self {
        WindowedTap {
            out: Collector::new(usize::MAX).only(only),
        }
    }

    /// Search the starts `keep` of `data`, which is the object from `origin`
    /// on and holds what a match at those starts needs around it.
    pub(crate) fn search(
        &mut self,
        p: &PatternMatcher,
        data: &[u8],
        keep: Range<usize>,
        origin: usize,
    ) {
        if !self.out.full {
            p.search(data, keep, origin, &|| None, &mut self.out);
        }
    }

    /// The matches, unless the pattern has more than it keeps: then it is
    /// searched again, as [`PatternMatcher::find_all`] does.
    pub(crate) fn found(self) -> Option<Found> {
        (!self.out.full).then(|| sorted(self.out.out, true, false))
    }
}

/// `matches` sorted by offset then length, without duplicates.
fn sorted(mut matches: Vec<Match>, complete: bool, capped: bool) -> Found {
    matches.sort_unstable_by(|a, b| a.offset.cmp(&b.offset).then(a.len.cmp(&b.len)));
    matches.dedup();
    Found {
        matches,
        complete,
        capped,
        regex_cut: None,
    }
}

/// The matches of a regexp pattern, found as a read of the object goes by:
/// the searches [`PatternMatcher::find_all`] makes over a source, each
/// regexp's from where its first match can start. The searches charge the
/// pattern's steps as that does, so a pattern that reaches its limit, keeps
/// more matches than it may or cannot be followed is [`Self::found`] as
/// `None`, to be searched again the way it always was.
pub(crate) struct RegexTap<'r> {
    runs: Vec<(Enumerator<'r>, bool)>,
    fullword: bool,
    out: Collector,
    /// A search could not follow the object.
    gave_up: bool,
}

impl<'r> RegexTap<'r> {
    /// The tap of a pattern's `regexes`, which may use `steps` steps. `hit` is
    /// where an atom every match holds was first found, or `None` for a
    /// pattern with no such atom, searched from the start of the object.
    pub(crate) fn new(
        regexes: &'r StreamRegexes,
        fullword: bool,
        steps: usize,
        src: &dyn ByteSource,
        hit: Option<usize>,
    ) -> Option<Self> {
        let mut runs = Vec::new();
        for (sr, wide) in regexes {
            // No match starts before its atom less the longest a match is,
            // less the few bytes by which the sweep reports atoms out of order.
            let first = match (hit, sr.max_len()) {
                (Some(hit), Some(longest)) => hit.saturating_sub(longest.saturating_add(ATOM_SKEW)),
                _ => 0,
            };
            runs.push((Enumerator::new(sr, src, first).ok()?, *wide));
        }
        Some(RegexTap {
            runs,
            fullword,
            out: Collector::new(steps),
            gave_up: false,
        })
    }

    /// Whether the matches found so far are not the pattern's: it gave up,
    /// reached its limit or kept all the matches it may.
    pub(crate) fn spoiled(&self) -> bool {
        self.gave_up || self.out.done()
    }

    /// The memory the searches' state tables take.
    pub(crate) fn memory(&self) -> usize {
        self.runs.iter().map(|(en, _)| en.memory()).sum()
    }

    /// Whether no more matches can come, or the tap is spoiled.
    pub(crate) fn is_over(&self) -> bool {
        self.spoiled() || self.runs.iter().all(|(en, _)| en.is_over())
    }

    /// The bytes `at..at + w.len()` of `src`, which follow those given before.
    pub(crate) fn feed(&mut self, src: &dyn ByteSource, at: usize, w: &[u8]) {
        let fullword = self.fullword;
        for (en, wide) in &mut self.runs {
            if self.gave_up || self.out.done() {
                return;
            }
            let out = &mut self.out;
            let step = &mut |s, e, read| found_match(src, out, fullword, *wide, s, e, read);
            self.gave_up |= en.feed(src, at, w, step).is_err();
        }
    }

    /// `src` ends after the bytes given.
    pub(crate) fn finish(&mut self, src: &dyn ByteSource) {
        let fullword = self.fullword;
        for (en, wide) in &mut self.runs {
            if self.gave_up || self.out.done() {
                return;
            }
            let out = &mut self.out;
            let step = &mut |s, e, read| found_match(src, out, fullword, *wide, s, e, read);
            self.gave_up |= en.finish(src, step).is_err();
        }
    }

    /// The matches, unless the tap is spoiled.
    pub(crate) fn found(self) -> Option<Found> {
        (!self.spoiled()).then(|| sorted(self.out.out, true, false))
    }
}

/// A margin on where the searches of a regexp pattern begin. The sweep
/// reports an atom where its indexed window is, which is not its start, so
/// atoms do not come in order of their starts; the first found starts less
/// than the length of the earliest one past it, which this covers whatever
/// that length (an atom is 16 bytes at most).
pub(crate) const ATOM_SKEW: usize = 16;

/// One match of a regexp, found by searches that read `read` bytes: kept
/// unless `fullword` refuses it, and charged. `true` while the pattern may go on.
fn found_match(
    src: &dyn ByteSource,
    out: &mut Collector,
    fullword: bool,
    wide: bool,
    s: usize,
    e: usize,
    read: usize,
) -> bool {
    if e > s && (!fullword || full_word_in(src, s, e, wide)) {
        out.push(s, e - s);
    }
    if s < src.len() {
        out.spend(read);
    }
    !out.done()
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

    /// For a windowed pattern, the most bytes from the start of a match to
    /// any byte of the match, so that a literal found in it lies within this
    /// many bytes after the start.
    pub(crate) fn hit_span(&self) -> usize {
        match self {
            PatternMatcher::Literal { needles, .. } => {
                needles.iter().map(|n| n.bytes.len()).max().unwrap_or(0)
            }
            PatternMatcher::Base64 { entries } => {
                entries.iter().map(|e| e.searched.len()).max().unwrap_or(0)
            }
            _ => 0,
        }
    }

    /// For a regexp or hex pattern, whether `fullword` is set on it.
    pub(crate) fn regex_fullword(&self) -> Option<bool> {
        match self {
            PatternMatcher::Regex { fullword, .. }
            | PatternMatcher::RegexMulti { fullword, .. } => Some(*fullword),
            PatternMatcher::Hex { .. } => Some(false),
            PatternMatcher::Literal { .. } | PatternMatcher::Base64 { .. } => None,
        }
    }

    /// Every match in `src`. `stream` supplies the pattern's regexes for a
    /// source not held in memory, and for the count of what searches in
    /// memory read; `materialize` is the largest such source read whole when
    /// they cannot follow it. The regexp searches of the pattern make at most
    /// `steps` steps: past that the matches found are kept and the result is
    /// not complete. A pattern anchored at `only` keeps its match there alone.
    pub(crate) fn find_all(
        &self,
        src: &dyn ByteSource,
        stream: RegexSource<'_>,
        materialize: usize,
        steps: usize,
        only: Option<usize>,
    ) -> Found {
        let mut out = Collector::new(steps).only(only);
        let mut complete = true;
        match src.as_slice() {
            Some(data) => self.search(data, 0..data.len(), 0, stream, &mut out),
            None => complete = self.search_source(src, stream, materialize, &mut out),
        }
        let regexp = self.regex_fullword().is_some();
        let regex_cut = if !regexp || out.full {
            None
        } else if out.spent {
            Some(RegexCut::Steps)
        } else if !complete && src.len() > materialize {
            Some(RegexCut::Whole)
        } else {
            None
        };
        let complete = complete && !out.full && !out.spent;
        Found {
            regex_cut,
            ..sorted(out.out, complete, out.full)
        }
    }

    /// The matches starting at a position in `keep` of `data`, reported at
    /// `origin` plus their position. `data` holds whatever each match needs
    /// around it (see [`Self::reach`]) or ends where the object ends.
    fn search(
        &self,
        data: &[u8],
        keep: Range<usize>,
        origin: usize,
        stream: RegexSource<'_>,
        out: &mut Collector,
    ) {
        // Anchored at an offset: the one start there.
        let (data, keep) = match out.only {
            Some(at) if self.windowed() => {
                let end = keep.end.min(at.saturating_add(1).saturating_sub(origin));
                let start = keep.start.max(at.saturating_sub(origin)).min(end);
                (&data[..data.len().min(end + self.reach().1)], start..end)
            }
            _ => (data, keep),
        };
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
                // XOR: a position can only match with the key that turns its
                // first byte into the needle's (an exact comparison), so the
                // keys are not tried one by one. `nocase` is not combined with
                // `xor`, but a needle that were would match two keys: it keeps
                // the loop over the range.
                Some((s, e)) => {
                    let keys: Vec<u8> = (*s..=*e).collect();
                    for n in needles {
                        if n.bytes.is_empty() || n.bytes.len() > data.len() {
                            continue;
                        }
                        let last = data.len() - n.bytes.len();
                        for pos in keep.start..keep.end.min(last + 1) {
                            let first;
                            let candidates: &[u8] = if n.nocase {
                                &keys
                            } else {
                                first = [data[pos] ^ n.bytes[0]];
                                if first[0] < *s || first[0] > *e {
                                    continue;
                                }
                                &first
                            };
                            for &key in candidates {
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
                anchored_matches(re, (stream, 0), data, out, *fullword, *wide);
            }
            PatternMatcher::RegexMulti {
                ascii,
                wide,
                fullword,
            } => {
                anchored_matches(ascii, (stream, 0), data, out, *fullword, false);
                anchored_matches(wide, (stream, 1), data, out, *fullword, true);
            }
            PatternMatcher::Hex { re } => {
                anchored_matches(re, (stream, 0), data, out, false, false);
            }
            PatternMatcher::Base64 { entries } => {
                for e in entries {
                    if e.searched.is_empty() || e.searched.len() > data.len() {
                        continue;
                    }
                    let last = data.len() - e.searched.len();
                    for pos in keep.start..keep.end.min(last + 1) {
                        if data[pos..].starts_with(&e.searched)
                            && let Some(r) = verify_base64(
                                &e.pattern,
                                data,
                                e.padding as usize,
                                pos,
                                &e.engine,
                                e.wide,
                            )
                        {
                            out.push(origin + r.0, r.1 - r.0);
                        }
                    }
                }
            }
        }
    }

    /// Bytes a literal or base64 match at `pos` is checked against: how many
    /// before `pos`, and how many from `pos` on.
    pub(crate) fn reach(&self) -> (usize, usize) {
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
                // Anchored at an offset, the one chunk from there.
                let (before, after) = self.reach();
                let (mut base, stop) = match out.only {
                    Some(at) => (at.min(len), at.saturating_add(1).min(len)),
                    None => (0, len),
                };
                while base < stop && !out.full {
                    let end = (base + CHUNK).min(stop);
                    let from = base.saturating_sub(before);
                    let to = end.saturating_add(after).min(len);
                    let w = src.window(from, to - from);
                    if w.len() != to - from {
                        return false;
                    }
                    self.search(&w, base - from..end - from, from, stream, out);
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
        let mut found = Collector::new(0).only(out.only);
        found.room = out.room;
        let streamed = stream().is_some_and(|regexes| {
            regexes
                .iter()
                .all(|(sr, wide)| stream_matches(sr, src, &mut found, fullword, *wide).is_ok())
        });
        // What the attempt read counts, whether or not it went through.
        out.room = found.room;
        out.spent |= found.spent;
        if streamed {
            out.full |= found.full;
            out.out.extend(found.out);
            return true;
        }
        // The lazy DFAs gave up, or could not be built: the object is searched
        // whole, as in memory, if it may be read whole.
        match src.materialize(materialize) {
            Some(data) => {
                self.search(&data, 0..data.len(), 0, stream, out);
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
/// old "anchor at every offset" loop, with one search per match instead of one
/// per offset: an unanchored `find` from `start` returns the leftmost match
/// `s ≥ start`, and because the meta engine uses the same leftmost-first
/// semantics, that match is byte-for-byte the one an anchored search at `s`
/// would produce. No offset in `[start, s)` can begin a match (else it would be
/// the leftmost), so nothing is skipped; resuming at `s + 1` then enumerates
/// every match-start in order.
///
/// Each search reads to the end of its match, so a regexp with long matches
/// that start at every offset (`/[a-z]{40,}/` over a long run of letters) reads
/// the run once per match. What the searches read is charged to `out`, and
/// the sweep stops when that is more than it has room for. A search reads
/// forward to where its match ends and the lookahead after it, and back over
/// the match to find where it starts. `meta::Regex` does not say how far a
/// search reads, so the forward read is counted by the lazy DFAs of `stream`'s
/// `i`th regex, built when the first match is found; where they cannot count,
/// a search is charged all the object that follows its start.
fn anchored_matches(
    re: &Regex,
    (stream, i): (RegexSource<'_>, usize),
    data: &[u8],
    out: &mut Collector,
    fullword: bool,
    wide: bool,
) {
    let len = data.len();
    // Anchored at an offset: one search there, which reads what one search
    // reads, so it is not charged.
    if let Some(at) = out.only {
        if at <= len
            && let Some(m) = re.find(Input::new(data).span(at..len).anchored(Anchored::Yes))
            && m.end() > m.start()
            && (!fullword || verify_full_word(data, m.start(), m.end(), wide, 0))
        {
            out.push(m.start(), m.len());
        }
        return;
    }
    let mut start = 0;
    let mut counter = None;
    while start <= len && !out.done() {
        let input = Input::new(data).span(start..len);
        let Some(m) = re.find(input) else {
            break;
        };
        let (s, e) = (m.start(), m.end());
        if e > s && (!fullword || verify_full_word(data, s, e, wide, 0)) {
            out.push(s, e - s);
        }
        let from = start;
        start = s + 1;
        if start > len || !out.limited() {
            continue;
        }
        let counter = counter.get_or_insert_with(|| {
            let regexes = stream()?;
            let (sr, _) = regexes.get(i)?;
            Some((sr, sr.caches()))
        });
        let read = counter
            .as_mut()
            .and_then(|(sr, caches)| sr.read_forward(caches, data, from, out.room, e - s))
            .unwrap_or(len - from);
        out.spend(read);
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
    if let Some(at) = out.only {
        if let Some(end) = sr.find_at(&mut caches, src, at)?
            && end > at
            && (!fullword || full_word_in(src, at, end, wide))
        {
            out.push(at, end - at);
        }
        return Ok(());
    }
    let mut start = 0;
    while start <= len && !out.done() {
        let found = sr.find(&mut caches, src, start)?;
        let read = caches.take_read();
        match found {
            Some((s, e)) => {
                if e > s && (!fullword || full_word_in(src, s, e, wide)) {
                    out.push(s, e - s);
                }
                start = s + 1;
                if start <= len {
                    out.spend(read);
                }
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

    let decoded_pattern = crate::bytes::at(&decoded, padding, pattern.len())?;
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
        let mut out = Collector::new(usize::MAX);
        def.compile()
            .unwrap()
            .search(data, 0..data.len(), 0, &|| None, &mut out);
        out.out
    }

    /// The rules of a database are not trusted: an alphabet that is not 64
    /// distinct characters is an error, not a panic.
    #[test]
    fn a_stored_base64_alphabet_of_the_wrong_length_is_refused() {
        assert!(base64_def(b"YWJj", b"abc", Some("abc")).compile().is_err());
        assert!(base64_def(b"YWJj", b"abc", None).compile().is_ok());
    }

    fn xor_offsets(rule: &str, data: &[u8]) -> Vec<usize> {
        let rules = crate::yara::compile(rule).unwrap();
        let results = crate::yara::Scanner::new(&rules).scan(data).unwrap();
        let mut found = Vec::new();
        for r in results.matching_rules() {
            for p in r.patterns() {
                found.extend(p.matches().map(|m| m.offset()));
            }
        }
        found
    }

    /// Each key of `xor(1-255)` finds the needle where it was encoded with it,
    /// and the plain needle (key 0) is outside the range.
    #[test]
    fn xor_finds_each_key_where_it_was_used() {
        let mut data = vec![0x55u8; 80];
        for (at, key) in [(3usize, 1u8), (20, 0x80), (40, 255)] {
            for (i, b) in b"secret".iter().enumerate() {
                data[at + i] = b ^ key;
            }
        }
        data[60..66].copy_from_slice(b"secret");
        let rule = r#"rule x { strings: $a = "secret" xor(1-255) condition: $a }"#;
        assert_eq!(xor_offsets(rule, &data), [3, 20, 40]);
        // The same, as a wide string, and with a narrower range.
        let wide: Vec<u8> = b"secret".iter().flat_map(|b| [b ^ 7, 7]).collect();
        let mut data = vec![0x55u8; 40];
        data[5..5 + wide.len()].copy_from_slice(&wide);
        let rule = r#"rule x { strings: $a = "secret" wide xor(7-9) condition: $a }"#;
        assert_eq!(xor_offsets(rule, &data), [5]);
        let rule = r#"rule x { strings: $a = "secret" wide xor(8-9) condition: $a }"#;
        assert!(xor_offsets(rule, &data).is_empty());
    }

    /// Found by `fuzz/fuzz_targets/analyze.rs` as a scan of 64 KB taking
    /// seconds: every position was tried with every key in the range, 255
    /// times the work. The needle's first byte decides the one key a position
    /// can match with.
    #[test]
    fn a_wide_xor_range_does_not_cost_a_comparison_per_key_per_position() {
        let rules =
            crate::yara::compile(r#"rule x { strings: $a = "secret" xor(1-255) condition: $a }"#)
                .unwrap();
        let data = vec![0u8; 16 << 20];
        let start = std::time::Instant::now();
        let results = crate::yara::Scanner::new(&rules).scan(&data).unwrap();
        let took = start.elapsed();
        assert_eq!(results.matching_rules().len(), 0);
        assert!(
            took < std::time::Duration::from_secs(2),
            "16 MiB took {took:?}"
        );
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
