//! `.ndb` / `.ldb` signature matching.
//!
//! `.ndb` bodies are hex with wildcards (`??`, nibble `a?`/`?a`, `*`,
//! `{n}`/`{n-m}`/`{-m}`/`{n-}` and the `[n-m]`/`[n]` byte-range form,
//! `(aa|bb)` alternates, `!(...)` negation).
//! Pure-literal matching can't express those, so this engine compiles each
//! body to a token program, pre-filters with one Aho-Corasick automaton over
//! a literal *anchor* per signature, and verifies the full program at each
//! candidate position (bounded by a step budget to prevent catastrophic
//! backtracking on hostile input).
//!
//! `.ldb` logical signatures compose subsignatures (each an `.ndb` body) with
//! a boolean expression. Verification runs only on a bounded in-memory buffer
//! (the streaming path stays literal-only).
//!
//! Not supported (counted, never silently dropped): `EP`/`Sx`-relative
//! offsets, PCRE subsignatures, bytecode, and patterns whose only literal run
//! is shorter than [`MIN_ANCHOR`] or sits behind a non-leading variable gap.

use daachorse::{DoubleArrayAhoCorasick, DoubleArrayAhoCorasickBuilder};
use serde::{Deserialize, Serialize};

use crate::filetype::FileType;
use crate::pe::PeLayout;

/// Minimum literal length usable as an Aho-Corasick anchor.
const MIN_ANCHOR: usize = 2;
/// Per-candidate verification step budget (bounds backtracking).
const VERIFY_BUDGET: u64 = 200_000;

/// One element of a compiled body pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Elem {
    Bytes(Vec<u8>),
    AnyByte,
    HiNibble(u8),
    LoNibble(u8),
    Gap { min: usize, max: Option<usize> },
    Alt { opts: Vec<Vec<u8>>, neg: bool },
}

impl Elem {
    /// Fixed byte width, or `None` if variable.
    fn width(&self) -> Option<usize> {
        match self {
            Elem::Bytes(b) => Some(b.len()),
            Elem::AnyByte | Elem::HiNibble(_) | Elem::LoNibble(_) => Some(1),
            Elem::Gap { min, max } => match max {
                Some(m) if m == min => Some(*min),
                _ => None,
            },
            Elem::Alt { opts, .. } => {
                let l = opts.first().map(|o| o.len()).unwrap_or(0);
                if opts.iter().all(|o| o.len() == l) {
                    Some(l)
                } else {
                    None
                }
            }
        }
    }
}

/// Where a body's literal anchor sits relative to the pattern start.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Prefix {
    /// All elements before the anchor are fixed-width (sum = n).
    Fixed { anchor_idx: usize, len: usize },
    /// A single leading variable gap precedes the anchor (start floats).
    Floating { anchor_idx: usize },
}

/// Offset constraint on where the pattern start may sit. `shift` is the
/// optional `,maxshift` window width.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Offset {
    Any,
    /// start in [n, n+shift]
    Abs {
        n: u64,
        shift: u64,
    },
    /// start in [filelen-n, filelen-n+shift]
    Eof {
        n: u64,
        shift: u64,
    },
    /// relative to the entry point file offset: start ≈ EP + delta
    Ep {
        delta: i64,
        shift: u64,
    },
    /// relative to section `idx`'s file offset: start ≈ Sidx + delta
    Sec {
        idx: usize,
        delta: i64,
        shift: u64,
    },
    /// relative to the last section's file offset: start ≈ SL + delta
    SecLast {
        delta: i64,
        shift: u64,
    },
}

/// A compiled body plus where it came from. The literal anchor used to build
/// the Aho-Corasick automaton is kept separately (in `EngineBuilder`'s
/// concatenated `anchor_buf`) and dropped after the build — it is never needed
/// during scanning.
#[derive(Serialize, Deserialize)]
struct Body {
    /// The token program to verify at each anchor hit. `None` for a pure
    /// literal whose anchor IS the whole pattern — then an Aho-Corasick hit is
    /// already a full match (subject only to the offset), so no per-body token
    /// allocation is kept. This is the common case and the main memory saver.
    elems: Option<Vec<Elem>>,
    prefix: Prefix,
    offset: Offset,
    target: u8,
    /// ASCII-case-insensitive match (the `i` subsig modifier).
    nocase: bool,
    owner: Owner,
}

/// True if a pure literal whose anchor equals the whole pattern (an AC hit is
/// already a full match, so no stored token program is needed).
fn is_literal_only(elems: &[Elem], prefix: &Prefix) -> bool {
    matches!(
        prefix,
        Prefix::Fixed {
            anchor_idx: 0,
            len: 0
        }
    ) && matches!(elems, [Elem::Bytes(_)])
}

#[derive(Serialize, Deserialize)]
enum Owner {
    Ndb(String),
    /// A logical-signature subsignature (its owning `Ldb` tracks body ids).
    LdbSub,
}

/// A logical signature: a boolean expression over its subsignatures.
#[derive(Serialize, Deserialize)]
struct Ldb {
    name: String,
    target: u8,
    /// The expression parsed once at load (not re-parsed per scan).
    expr: Node,
    /// Whether `expr` is satisfied by an all-zero count vector. Almost always
    /// false (a real sig needs a subsig to match), so when no subsig matched a
    /// file the whole logical-sig pass can be skipped for all but these.
    fires_on_empty: bool,
    /// One entry per subsignature number (positional — referenced by index in
    /// the logical expression and in trigger fields).
    subs: Vec<SubSig>,
}

/// A logical-signature subsignature: a normal hex/pattern body group, a PCRE
/// regex, or a byte-compare. PCRE and byte-compare are evaluated *after* the
/// normal subsigs (they reference earlier subsigs' matches/offsets).
#[derive(Serialize, Deserialize)]
enum SubSig {
    /// Normal subsig: AC-anchored body ids (an `aw` modifier yields several);
    /// matched if any body matched. Count = sum of body match counts.
    Bodies(Vec<usize>),
    Pcre(PcreSub),
    Bcomp(BcompSub),
}

/// A `Trigger/PCRE/[flags]` subsignature. The compiled regex is built lazily
/// and not serialized (a cache stores only the pattern/flags).
#[derive(Serialize, Deserialize)]
struct PcreSub {
    /// Logical expression over preceding subsigs that gates the regex.
    trigger: Node,
    pattern: String,
    ci: bool,
    dotall: bool,
    multiline: bool,
    #[serde(skip)]
    re: std::sync::OnceLock<Option<regex::bytes::Regex>>,
}

impl PcreSub {
    /// Lazily compile and run the regex over `buf`. Patterns the (linear-time,
    /// DoS-safe) `regex` engine can't express (backreferences/lookaround) fail
    /// to compile and never match — those PCRE subsigs are unsupported.
    fn is_match(&self, buf: &[u8]) -> bool {
        let re = self.re.get_or_init(|| {
            let mut flags = String::new();
            if self.ci {
                flags.push('i');
            }
            if self.dotall {
                flags.push('s');
            }
            if self.multiline {
                flags.push('m');
            }
            let pat = if flags.is_empty() {
                self.pattern.clone()
            } else {
                format!("(?{flags}){}", self.pattern)
            };
            regex::bytes::RegexBuilder::new(&pat)
                .size_limit(16 * 1024 * 1024)
                .dfa_size_limit(16 * 1024 * 1024)
                .build()
                .ok()
        });
        re.as_ref().map(|r| r.is_match(buf)).unwrap_or(false)
    }
}

/// A `trigger(offset#byte_options#comparisons)` byte-compare subsignature.
#[derive(Serialize, Deserialize)]
struct BcompSub {
    /// Subsig whose match start anchors the offset; evaluated only if it hit.
    trigger: usize,
    /// Signed byte offset from the trigger match start (`<<` negative).
    offset: i64,
    /// Numeric type: how to read the bytes at the offset.
    kind: BcompKind,
    /// Big-endian when reading raw binary (`il`/`ib`); ignored for text.
    big_endian: bool,
    /// Number of bytes to read/parse.
    num_bytes: usize,
    /// Require exactly `num_bytes` available (the `e` flag / implied for raw).
    exact: bool,
    /// One or two `(symbol, value)` comparisons (AND-ed).
    cmps: Vec<(Cmp, i64)>,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq)]
enum BcompKind {
    Hex,
    Dec,
    Auto,
    Raw,
}

impl BcompSub {
    /// Extract the value at `trigger_off + offset` and test the comparisons.
    fn matches(&self, buf: &[u8], trigger_off: u32) -> bool {
        let pos = trigger_off as i64 + self.offset;
        if pos < 0 || pos as usize > buf.len() {
            return false;
        }
        let rest = &buf[pos as usize..];
        let val: i64 = match self.kind {
            BcompKind::Raw => {
                if rest.len() < self.num_bytes {
                    return false;
                }
                let mut v = 0u64;
                for (i, &byte) in rest.iter().take(self.num_bytes).enumerate() {
                    let b = byte as u64;
                    if self.big_endian {
                        v = (v << 8) | b;
                    } else {
                        v |= b << (8 * i);
                    }
                }
                v as i64
            }
            _ => {
                // Text: read up to num_bytes ASCII chars in the chosen base.
                let take = rest.len().min(self.num_bytes);
                let slice = &rest[..take];
                if self.exact && take < self.num_bytes {
                    return false;
                }
                let s: String = slice.iter().map(|&b| b as char).collect();
                let s = s.trim();
                let radix = match self.kind {
                    BcompKind::Hex => 16,
                    BcompKind::Dec => 10,
                    BcompKind::Auto => {
                        if s.starts_with("0x") || s.starts_with("0X") {
                            16
                        } else {
                            10
                        }
                    }
                    BcompKind::Raw => unreachable!(),
                };
                let s = s.trim_start_matches("0x").trim_start_matches("0X");
                let digits: String = s
                    .chars()
                    .take_while(|c| c.is_digit(radix))
                    .collect();
                match i64::from_str_radix(&digits, radix) {
                    Ok(v) => v,
                    Err(_) => return false,
                }
            }
        };
        self.cmps.iter().all(|&(c, x)| cmp_ok_signed(c, val, x))
    }
}

fn cmp_ok_signed(c: Cmp, v: i64, x: i64) -> bool {
    match c {
        Cmp::Eq => v == x,
        Cmp::Gt => v > x,
        Cmp::Lt => v < x,
    }
}

impl Ldb {
    /// Evaluate the logical expression for this signature. `body_count`/
    /// `body_off` give per-body match count and first-match file offset (for
    /// normal subsigs); PCRE and byte-compare subsigs are evaluated here over
    /// `buf`, after the normal subsig counts are known (their triggers
    /// reference earlier subsigs).
    fn eval(
        &self,
        buf: &[u8],
        body_count: &dyn Fn(usize) -> u32,
        body_off: &dyn Fn(usize) -> Option<u32>,
    ) -> bool {
        let n = self.subs.len();
        let mut c = vec![0u32; n];
        // Pass 1: normal subsigs from AC body counts.
        for (i, s) in self.subs.iter().enumerate() {
            if let SubSig::Bodies(ids) = s {
                c[i] = ids.iter().map(|&b| body_count(b)).sum();
            }
        }
        // Pass 2: PCRE / byte-compare (reference earlier subsigs).
        for (i, s) in self.subs.iter().enumerate() {
            match s {
                SubSig::Pcre(p) => {
                    if p.trigger.eval(&|j| c.get(j).copied().unwrap_or(0)) && p.is_match(buf) {
                        c[i] = 1;
                    }
                }
                SubSig::Bcomp(b) => {
                    if b.trigger < n && c[b.trigger] > 0 {
                        // Offset anchored at the trigger subsig's first match.
                        if let SubSig::Bodies(ids) = &self.subs[b.trigger] {
                            if let Some(off) = ids.iter().filter_map(|&id| body_off(id)).min() {
                                if b.matches(buf, off) {
                                    c[i] = 1;
                                }
                            }
                        }
                    }
                }
                SubSig::Bodies(_) => {}
            }
        }
        self.expr.eval(&|i| c.get(i).copied().unwrap_or(0))
    }
}

/// One compiled variant of a body: tokens, anchor, prefix, nocase flag, offset.
type Compiled = (Vec<Elem>, Vec<u8>, Prefix, bool, Offset);

/// Builds a [`SigEngine`] from `.ndb` / `.ldb` text.
#[derive(Default)]
pub struct EngineBuilder {
    bodies: Vec<Body>,
    /// All anchor bytes concatenated, with a (start, len) range per body
    /// (parallel to `bodies`). One buffer instead of a million small Vecs;
    /// consumed at build time.
    anchor_buf: Vec<u8>,
    anchor_ranges: Vec<(u32, u32)>,
    ldbs: Vec<Ldb>,
    unsupported: usize,
}

impl EngineBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    fn push_anchor(&mut self, a: &[u8]) {
        let start = self.anchor_buf.len() as u32;
        self.anchor_buf.extend_from_slice(a);
        self.anchor_ranges.push((start, a.len() as u32));
    }

    /// Add a plain literal signature (no wildcards/offset). Used to fold the
    /// built-in EICAR test pattern into the engine so in-memory scans don't
    /// also need the streaming literal automaton.
    pub fn add_literal(&mut self, name: &str, bytes: &[u8]) {
        if bytes.len() < MIN_ANCHOR {
            return;
        }
        self.push_anchor(bytes);
        self.bodies.push(Body {
            elems: None,
            prefix: Prefix::Fixed {
                anchor_idx: 0,
                len: 0,
            },
            offset: Offset::Any,
            target: 0,
            nocase: false,
            owner: Owner::Ndb(name.to_string()),
        });
    }

    /// Add `.ndb` lines (`Name:Target:Offset:HexBody[:min[:max]]`).
    pub fn add_ndb(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(4, ':');
            let name = parts.next().unwrap_or("").to_string();
            let target: u8 = parts
                .next()
                .and_then(|t| t.trim().parse().ok())
                .unwrap_or(0);
            let offset = parts.next().map(parse_offset).unwrap_or(Some(Offset::Any));
            let body = parts.next();
            match (offset, body) {
                (Some(offset), Some(hex)) => match compile_body(hex) {
                    Some((elems, anchor, prefix)) => {
                        let elems = if is_literal_only(&elems, &prefix) {
                            None
                        } else {
                            Some(elems)
                        };
                        self.push_anchor(&anchor);
                        self.bodies.push(Body {
                            elems,
                            prefix,
                            offset,
                            target,
                            nocase: false,
                            owner: Owner::Ndb(name),
                        });
                    }
                    None => self.unsupported += 1,
                },
                _ => self.unsupported += 1,
            }
        }
    }

    /// Add `.ldb` lines (`Name;TDB;Expr;Sub0;Sub1;...`).
    pub fn add_ldb(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !self.add_ldb_line(line) {
                self.unsupported += 1;
            }
        }
    }

    fn add_ldb_line(&mut self, line: &str) -> bool {
        let parts: Vec<&str> = line.split(';').collect();
        if parts.len() < 4 {
            return false;
        }
        let name = parts[0].to_string();
        let target = parse_tdb_target(parts[1]);
        let nsubs = parts.len() - 3;
        // Classify + parse every subsignature first; commit only if all parse.
        let mut parsed: Vec<ParsedSub> = Vec::with_capacity(nsubs);
        for sub in &parts[3..] {
            match classify_subsig(sub) {
                Some(p) => parsed.push(p),
                None => return false,
            }
        }
        // Parse the expression once, here, and keep the AST.
        let expr = match parse_expr(parts[2]) {
            Some(node) => node,
            None => return false,
        };
        // Every referenced subsig (in the expr and in PCRE/bcomp triggers) must
        // be in range; bcomp/pcre triggers may only reference *normal* subsigs.
        if parsed.is_empty() || !expr.ids_within(nsubs) {
            return false;
        }
        for p in &parsed {
            match p {
                ParsedSub::Pcre(ps) if !ps.trigger.ids_within(nsubs) => return false,
                ParsedSub::Bcomp(bs) if bs.trigger >= nsubs => return false,
                _ => {}
            }
        }
        let fires_on_empty = expr.eval(&|_| 0);
        let mut subs = Vec::with_capacity(nsubs);
        for p in parsed {
            let sub = match p {
                ParsedSub::Bodies(variants) => {
                    let mut ids = Vec::with_capacity(variants.len());
                    for (elems, anchor, prefix, nocase, offset) in variants {
                        let elems = if is_literal_only(&elems, &prefix) {
                            None
                        } else {
                            Some(elems)
                        };
                        ids.push(self.bodies.len());
                        self.push_anchor(&anchor);
                        self.bodies.push(Body {
                            elems,
                            prefix,
                            offset,
                            target,
                            nocase,
                            owner: Owner::LdbSub,
                        });
                    }
                    SubSig::Bodies(ids)
                }
                ParsedSub::Pcre(ps) => SubSig::Pcre(ps),
                ParsedSub::Bcomp(bs) => SubSig::Bcomp(bs),
            };
            subs.push(sub);
        }
        self.ldbs.push(Ldb {
            name,
            target,
            expr,
            fires_on_empty,
            subs,
        });
        true
    }

    pub fn unsupported(&self) -> usize {
        self.unsupported
    }

    pub fn signature_count(&self) -> usize {
        self.bodies
            .iter()
            .filter(|b| matches!(b.owner, Owner::Ndb(_)))
            .count()
            + self.ldbs.len()
    }

    pub fn build(mut self) -> SigEngine {
        // Case-sensitive and ASCII-case-insensitive (`i` modifier) anchors go
        // into separate automatons. Identical anchors are de-duplicated into one
        // automaton pattern that fans out to every body sharing it (a full
        // a full DB has ~1M anchors, ~24% of them duplicates).
        //
        // Building the double-array automaton is memory-heavy, so keep the
        // build-time peak down: the case-sensitive anchors (the bulk) are kept
        // as borrowed slices into `anchor_buf` rather than copied, and each
        // de-dup map is dropped before its automaton is built.
        let anchor_buf = std::mem::take(&mut self.anchor_buf);
        let anchor_ranges = std::mem::take(&mut self.anchor_ranges);
        let mut cs: AnchorGroups<&[u8]> = AnchorGroups::new();
        // The case-insensitive automaton matches a lowercased haystack, so its
        // anchors are stored lowercased (and thus owned).
        let mut ci: AnchorGroups<Vec<u8>> = AnchorGroups::new();
        for (id, b) in self.bodies.iter().enumerate() {
            let (s, l) = anchor_ranges[id];
            let anchor = &anchor_buf[s as usize..(s + l) as usize];
            if b.nocase {
                ci.add(anchor.to_ascii_lowercase(), id);
            } else {
                cs.add(anchor, id);
            }
        }
        let (ac, cs_groups) = cs.finish();
        let (ac_ci, ci_groups) = ci.finish();
        drop(anchor_buf);
        drop(anchor_ranges);
        SigEngine {
            ac,
            ac_ci,
            cs_groups,
            ci_groups,
            bodies: self.bodies,
            ldbs: self.ldbs,
            unsupported: self.unsupported,
        }
    }
}

/// Accumulates distinct anchors and the bodies that share each, then builds a
/// double-array Aho-Corasick whose stored value is the group index. The key
/// type `K` is a borrowed slice for the (large) case-sensitive set and an owned
/// `Vec<u8>` for the lowercased case-insensitive set.
struct AnchorGroups<K> {
    index: std::collections::HashMap<K, u32>,
    patterns: Vec<K>,
    groups: Vec<Vec<usize>>,
}

impl<K: Eq + std::hash::Hash + Clone + AsRef<[u8]>> AnchorGroups<K> {
    fn new() -> Self {
        Self {
            index: std::collections::HashMap::new(),
            patterns: Vec::new(),
            groups: Vec::new(),
        }
    }

    fn add(&mut self, anchor: K, body: usize) {
        let g = match self.index.get(&anchor) {
            Some(&g) => g as usize,
            None => {
                let g = self.patterns.len();
                self.index.insert(anchor.clone(), g as u32);
                self.patterns.push(anchor);
                self.groups.push(Vec::new());
                g
            }
        };
        self.groups[g].push(body);
    }

    fn finish(mut self) -> (Option<DoubleArrayAhoCorasick<u32>>, Vec<Vec<usize>>) {
        // The de-dup map isn't needed for the build; free it first so it
        // doesn't coexist with the automaton's construction peak.
        self.index = std::collections::HashMap::new();
        if self.patterns.is_empty() {
            return (None, Vec::new());
        }
        let ac = DoubleArrayAhoCorasickBuilder::new()
            .match_kind(daachorse::MatchKind::Standard)
            .build_with_values(self.patterns.iter().zip(0u32..))
            .ok();
        (ac, self.groups)
    }
}

/// A compiled signature set: a double-array Aho-Corasick over distinct anchors
/// (case-sensitive and case-insensitive) + per-body verifiers + logical-sig
/// expressions. Each automaton's stored value indexes a group of body ids that
/// share that anchor.
pub struct SigEngine {
    ac: Option<DoubleArrayAhoCorasick<u32>>,
    ac_ci: Option<DoubleArrayAhoCorasick<u32>>,
    cs_groups: Vec<Vec<usize>>,
    ci_groups: Vec<Vec<usize>>,
    bodies: Vec<Body>,
    ldbs: Vec<Ldb>,
    pub unsupported: usize,
}

/// One matching pass: an automaton, its anchor→body-id groups, and the
/// haystack to scan (the original buffer, or its lowercased copy for the
/// case-insensitive automaton).
type Pass<'a> = (
    &'a Option<DoubleArrayAhoCorasick<u32>>,
    &'a Vec<Vec<usize>>,
    &'a [u8],
);

impl SigEngine {
    pub fn is_empty(&self) -> bool {
        self.bodies.is_empty()
    }

    /// Serialize to the on-disk cache: each double-array automaton via
    /// daachorse's own format, the rest via bincode (by reference, no clone).
    pub(crate) fn write_cache<W: std::io::Write>(&self, mut w: W) -> std::io::Result<()> {
        use crate::cache::enc;
        let ac = self.ac.as_ref().map(|a| a.serialize());
        let ac_ci = self.ac_ci.as_ref().map(|a| a.serialize());
        enc(&ac, &mut w)?;
        enc(&ac_ci, &mut w)?;
        enc(&self.cs_groups, &mut w)?;
        enc(&self.ci_groups, &mut w)?;
        enc(&self.bodies, &mut w)?;
        enc(&self.ldbs, &mut w)?;
        enc(&self.unsupported, &mut w)?;
        Ok(())
    }

    /// Reverse of [`write_cache`]. The daachorse bytes come from a cache file
    /// this build wrote and validated (magic + version), so the unchecked
    /// deserialize is sound.
    pub(crate) fn read_cache<R: std::io::Read>(mut r: R) -> std::io::Result<Self> {
        use crate::cache::dec;
        let ac_bytes: Option<Vec<u8>> = dec(&mut r)?;
        let ac_ci_bytes: Option<Vec<u8>> = dec(&mut r)?;
        let cs_groups = dec(&mut r)?;
        let ci_groups = dec(&mut r)?;
        let bodies = dec(&mut r)?;
        let ldbs = dec(&mut r)?;
        let unsupported = dec(&mut r)?;
        let deser = |b: Vec<u8>| unsafe { DoubleArrayAhoCorasick::deserialize_unchecked(&b).0 };
        Ok(SigEngine {
            ac: ac_bytes.map(deser),
            ac_ci: ac_ci_bytes.map(deser),
            cs_groups,
            ci_groups,
            bodies,
            ldbs,
            unsupported,
        })
    }

    /// Number of loaded signatures (ndb bodies + logical signatures).
    pub fn signature_count(&self) -> usize {
        self.bodies
            .iter()
            .filter(|b| matches!(b.owner, Owner::Ndb(_)))
            .count()
            + self.ldbs.len()
    }

    /// Scan an in-memory buffer of the given type. Returns the first matching
    /// signature name and the match offset.
    pub fn scan(&self, buf: &[u8], ft: FileType) -> Option<(String, u64)> {
        self.scan_with_layout(buf, ft, None)
    }

    /// As [`scan`], with PE layout for resolving `EP`/section-relative offsets.
    pub fn scan_with_layout(
        &self,
        buf: &[u8],
        ft: FileType,
        layout: Option<&PeLayout>,
    ) -> Option<(String, u64)> {
        // Per-LDB-subsig match counts; only allocated when there are logical
        // signatures (otherwise no LdbSub body exists and counts is unused).
        let (mut counts, mut offs) = if self.ldbs.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            (vec![0u32; self.bodies.len()], vec![u32::MAX; self.bodies.len()])
        };
        let mut any_sub = false;

        // An anchor hit fans out to every body sharing that anchor (the group).
        // A verified NDB body is an immediate detection; an LDB subsignature
        // accumulates a per-body count and first-match offset (the latter
        // anchors byte-compare subsigs). The case-insensitive automaton matches
        // against a lowercased copy of the haystack; positions line up with the
        // original (ASCII lowercasing preserves length), so verification still
        // runs against `buf`.
        // Only allocate the lowercased copy if there are case-insensitive sigs.
        let lower = self.ac_ci.as_ref().map(|_| buf.to_ascii_lowercase());
        let passes: [Pass; 2] = [
            (&self.ac, &self.cs_groups, buf),
            (
                &self.ac_ci,
                &self.ci_groups,
                lower.as_deref().unwrap_or(&[]),
            ),
        ];
        for (ac, groups, hay) in passes {
            let Some(ac) = ac else { continue };
            for m in ac.find_overlapping_iter(hay) {
                for &bid in &groups[m.value() as usize] {
                    let body = &self.bodies[bid];
                    if !target_ok(body.target, ft) {
                        continue;
                    }
                    if let Some(start) = verify(body, buf, m.start(), layout) {
                        match &body.owner {
                            Owner::Ndb(name) => return Some((name.clone(), start)),
                            // counts is non-empty whenever LdbSub bodies exist.
                            Owner::LdbSub => {
                                counts[bid] = counts[bid].saturating_add(1);
                                let s = start.min(u32::MAX as u64 - 1) as u32;
                                if offs[bid] == u32::MAX || s < offs[bid] {
                                    offs[bid] = s;
                                }
                                any_sub = true;
                            }
                        }
                    }
                }
            }
        }

        // If no subsignature matched, only logical sigs that fire on an empty
        // count vector (vanishingly rare) can hit — skip the rest entirely.
        let body_off = |b: usize| -> Option<u32> {
            match offs[b] {
                u32::MAX => None,
                o => Some(o),
            }
        };
        for ldb in &self.ldbs {
            if (!any_sub && !ldb.fires_on_empty) || !target_ok(ldb.target, ft) {
                continue;
            }
            if ldb.eval(buf, &|b| counts[b], &body_off) {
                return Some((ldb.name.clone(), 0));
            }
        }
        None
    }

    /// Collect *every* matching signature (NDB bodies + logical sigs), not just
    /// the first — used by `--allmatch`. Names are de-duplicated.
    pub fn scan_all_with_layout(
        &self,
        buf: &[u8],
        ft: FileType,
        layout: Option<&PeLayout>,
        out: &mut Vec<(String, u64)>,
    ) {
        let (mut counts, mut offs) = if self.ldbs.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            (vec![0u32; self.bodies.len()], vec![u32::MAX; self.bodies.len()])
        };
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let lower = self.ac_ci.as_ref().map(|_| buf.to_ascii_lowercase());
        let passes: [Pass; 2] = [
            (&self.ac, &self.cs_groups, buf),
            (
                &self.ac_ci,
                &self.ci_groups,
                lower.as_deref().unwrap_or(&[]),
            ),
        ];
        for (ac, groups, hay) in passes {
            let Some(ac) = ac else { continue };
            for m in ac.find_overlapping_iter(hay) {
                for &bid in &groups[m.value() as usize] {
                    let body = &self.bodies[bid];
                    if !target_ok(body.target, ft) {
                        continue;
                    }
                    if let Some(start) = verify(body, buf, m.start(), layout) {
                        match &body.owner {
                            Owner::Ndb(name) => {
                                if seen.insert(name.clone()) {
                                    out.push((name.clone(), start));
                                }
                            }
                            Owner::LdbSub => {
                                counts[bid] = counts[bid].saturating_add(1);
                                let s = start.min(u32::MAX as u64 - 1) as u32;
                                if offs[bid] == u32::MAX || s < offs[bid] {
                                    offs[bid] = s;
                                }
                            }
                        }
                    }
                }
            }
        }
        let body_off = |b: usize| -> Option<u32> {
            match offs[b] {
                u32::MAX => None,
                o => Some(o),
            }
        };
        for ldb in &self.ldbs {
            if !target_ok(ldb.target, ft) {
                continue;
            }
            if ldb.eval(buf, &|b| counts[b], &body_off) && seen.insert(ldb.name.clone()) {
                out.push((ldb.name.clone(), 0));
            }
        }
    }

    /// For each matching logical signature, return its name and the per-subsig
    /// match offsets: `offsets[i]` is the file offset where subsignature `i`
    /// first matched, or `u32::MAX` (`CLI_OFF_NONE`) if it didn't. Drives
    /// bytecode triggers, whose programs read `__clambc_match_offsets[i]` to
    /// locate the pattern they were gated on (a plain match count loses the
    /// position, which most trigger programs need to seek/verify).
    pub fn scan_logical_offsets(
        &self,
        buf: &[u8],
        ft: FileType,
        layout: Option<&PeLayout>,
        out: &mut Vec<(String, Vec<u32>)>,
    ) {
        if self.ldbs.is_empty() {
            return;
        }
        let mut counts = vec![0u32; self.bodies.len()];
        // First-match offset per body.
        let mut offs = vec![u32::MAX; self.bodies.len()];
        let mut any_sub = false;
        let lower = self.ac_ci.as_ref().map(|_| buf.to_ascii_lowercase());
        let passes: [Pass; 2] = [
            (&self.ac, &self.cs_groups, buf),
            (&self.ac_ci, &self.ci_groups, lower.as_deref().unwrap_or(&[])),
        ];
        for (ac, groups, hay) in passes {
            let Some(ac) = ac else { continue };
            for m in ac.find_overlapping_iter(hay) {
                for &bid in &groups[m.value() as usize] {
                    let body = &self.bodies[bid];
                    if !target_ok(body.target, ft) {
                        continue;
                    }
                    if let Some(start) = verify(body, buf, m.start(), layout) {
                        if let Owner::LdbSub = &body.owner {
                            counts[bid] = counts[bid].saturating_add(1);
                            // Clamp below `u32::MAX` so a real offset can never
                            // collide with the `CLI_OFF_NONE` (`u32::MAX`)
                            // "no match" sentinel used in `offs` (only matters
                            // for the 4 GiB boundary, where a u32 offset is
                            // already lossy).
                            let s = start.min(u32::MAX as u64 - 1) as u32;
                            if offs[bid] == u32::MAX || s < offs[bid] {
                                offs[bid] = s;
                            }
                            any_sub = true;
                        }
                    }
                }
            }
        }
        let body_off = |b: usize| -> Option<u32> {
            match offs[b] {
                u32::MAX => None,
                o => Some(o),
            }
        };
        for ldb in &self.ldbs {
            if (!any_sub && !ldb.fires_on_empty) || !target_ok(ldb.target, ft) {
                continue;
            }
            if ldb.eval(buf, &|b| counts[b], &body_off) {
                // Per-subsig offset = the earliest match among a normal subsig's
                // bodies (its `aw`-style variants); `CLI_OFF_NONE` for a subsig
                // that didn't match or is a PCRE/byte-compare (no anchor point).
                let so = ldb
                    .subs
                    .iter()
                    .map(|s| match s {
                        SubSig::Bodies(ids) => {
                            ids.iter().map(|&b| offs[b]).min().unwrap_or(u32::MAX)
                        }
                        _ => u32::MAX,
                    })
                    .collect();
                out.push((ldb.name.clone(), so));
            }
        }
    }
}

fn target_ok(target: u8, ft: FileType) -> bool {
    match target {
        0 => true,
        1 => ft == FileType::Pe,
        2 => ft == FileType::Ole, // OLE2 (legacy MS Office / MSI)
        6 => ft == FileType::Elf,
        9 => ft == FileType::MachO,
        10 => ft == FileType::Pdf,
        // HTML(3)/mail(4)/text(7)/graphics(5)/flash(11)/Java(12)/... — exav
        // doesn't positively type all of these. Run such a signature only on
        // text-ish or unidentified content; NEVER on a file we HAVE positively
        // typed as a different binary/container kind. Otherwise a foreign-target
        // signature false-positives (e.g. an OLE2- or Java-target sig hitting a
        // gzip/rtf/docx — observed in clamscan differential testing).
        _ => matches!(
            ft,
            FileType::Unknown | FileType::Rtf | FileType::Script | FileType::Email
        ),
    }
}

fn verify(body: &Body, buf: &[u8], anchor_start: usize, layout: Option<&PeLayout>) -> Option<u64> {
    // Pure literal: the Aho-Corasick hit is already the full match; only the
    // offset constraint remains.
    let elems = match &body.elems {
        None => {
            return offset_ok(&body.offset, anchor_start as u64, buf.len() as u64, layout)
                .then_some(anchor_start as u64);
        }
        Some(e) => e,
    };
    let (start, from_idx) = match body.prefix {
        Prefix::Fixed { len, .. } => {
            if anchor_start < len {
                return None;
            }
            (anchor_start - len, 0)
        }
        Prefix::Floating { anchor_idx } => (anchor_start, anchor_idx),
    };
    let mut budget = VERIFY_BUDGET;
    if match_forward(&elems[from_idx..], buf, start, body.nocase, &mut budget)
        && offset_ok(&body.offset, start as u64, buf.len() as u64, layout)
    {
        Some(start as u64)
    } else {
        None
    }
}

fn bytes_eq(a: &[u8], b: &[u8], nocase: bool) -> bool {
    if nocase {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn offset_ok(off: &Offset, start: u64, filelen: u64, layout: Option<&PeLayout>) -> bool {
    let window = |base: u64, shift: u64| start >= base && start <= base.saturating_add(shift);
    match *off {
        Offset::Any => true,
        Offset::Abs { n, shift } => window(n, shift),
        // `EOF-n` anchors `n` bytes before end of file. If `n` exceeds the
        // file length the anchor is before offset 0 — treated as no
        // match; without this guard `saturating_sub` collapses it to offset 0
        // and a pattern at the start of a short file would falsely match.
        Offset::Eof { n, shift } => n <= filelen && window(filelen - n, shift),
        Offset::Ep { delta, shift } => match layout.and_then(|l| l.entry) {
            Some(ep) => add_delta(ep, delta)
                .map(|t| window(t, shift))
                .unwrap_or(false),
            None => false,
        },
        Offset::Sec { idx, delta, shift } => {
            match layout.and_then(|l| l.section_rawptrs.get(idx).copied()) {
                Some(p) => add_delta(p, delta)
                    .map(|t| window(t, shift))
                    .unwrap_or(false),
                None => false,
            }
        }
        Offset::SecLast { delta, shift } => {
            match layout.and_then(|l| l.section_rawptrs.last().copied()) {
                Some(p) => add_delta(p, delta)
                    .map(|t| window(t, shift))
                    .unwrap_or(false),
                None => false,
            }
        }
    }
}

fn add_delta(base: u64, delta: i64) -> Option<u64> {
    if delta >= 0 {
        base.checked_add(delta as u64)
    } else {
        base.checked_sub((-delta) as u64)
    }
}

/// Match the token program against `buf` at `pos`. Backtracks over gaps and
/// alternations; `budget` bounds total work. `nocase` folds ASCII case on
/// literal comparisons (the `i` subsig modifier).
fn match_forward(toks: &[Elem], buf: &[u8], pos: usize, nocase: bool, budget: &mut u64) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    let (head, rest) = match toks.split_first() {
        None => return true,
        Some(x) => x,
    };
    match head {
        Elem::Bytes(b) => {
            buf.len() >= pos + b.len()
                && bytes_eq(&buf[pos..pos + b.len()], b, nocase)
                && match_forward(rest, buf, pos + b.len(), nocase, budget)
        }
        Elem::AnyByte => pos < buf.len() && match_forward(rest, buf, pos + 1, nocase, budget),
        Elem::HiNibble(h) => {
            pos < buf.len()
                && buf[pos] >> 4 == *h
                && match_forward(rest, buf, pos + 1, nocase, budget)
        }
        Elem::LoNibble(l) => {
            pos < buf.len()
                && buf[pos] & 0x0f == *l
                && match_forward(rest, buf, pos + 1, nocase, budget)
        }
        Elem::Gap { min, max } => {
            let avail = buf.len().saturating_sub(pos);
            let hi = max.unwrap_or(avail).min(avail);
            for g in *min..=hi {
                if match_forward(rest, buf, pos + g, nocase, budget) {
                    return true;
                }
                if *budget == 0 {
                    return false;
                }
            }
            false
        }
        Elem::Alt { opts, neg } => {
            if *neg {
                let l = opts.first().map(|o| o.len()).unwrap_or(0);
                if l == 0 || pos + l > buf.len() {
                    return false;
                }
                let cur = &buf[pos..pos + l];
                !opts.iter().any(|o| bytes_eq(o, cur, nocase))
                    && match_forward(rest, buf, pos + l, nocase, budget)
            } else {
                opts.iter().any(|o| {
                    buf.len() >= pos + o.len()
                        && bytes_eq(&buf[pos..pos + o.len()], o, nocase)
                        && match_forward(rest, buf, pos + o.len(), nocase, budget)
                })
            }
        }
    }
}

/// Parse an `.ldb` subsignature: `[Offset:]HexBody[::Modifiers]`. Expands to
/// one or more compiled variants (ASCII and/or wide). `None` if unsupported
/// (PCRE, an unsupported offset, or a wide pattern that isn't pure-literal).
/// A subsignature parsed but not yet committed to the engine.
enum ParsedSub {
    Bodies(Vec<Compiled>),
    Pcre(PcreSub),
    Bcomp(BcompSub),
}

/// Classify and parse one subsignature: byte-compare (`N(..#..#..)`), PCRE
/// (`Trigger/regex/flags`), or a normal hex/pattern body.
fn classify_subsig(s: &str) -> Option<ParsedSub> {
    if let Some(b) = parse_bcomp_subsig(s) {
        return Some(ParsedSub::Bcomp(b));
    }
    if s.contains('/') {
        return parse_pcre_subsig(s).map(ParsedSub::Pcre);
    }
    parse_subsig(s).map(ParsedSub::Bodies)
}

/// Parse a numeric value that may be hex (`0x..`) or decimal.
fn parse_num(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()
    } else {
        s.parse::<i64>().ok()
    }
}

/// Parse `Trigger/PCRE/[flags]`. The regex is delimited by the first and last
/// `/`; flags `i`/`s`/`m` map to case-insensitive/dotall/multiline (other
/// Flags like `g`/`r`/`e` are accepted but don't change a match/no-match
/// result here).
fn parse_pcre_subsig(s: &str) -> Option<PcreSub> {
    let first = s.find('/')?;
    let last = s.rfind('/')?;
    if last <= first {
        return None;
    }
    let trigger = parse_expr(&s[..first])?;
    let pattern = &s[first + 1..last];
    if pattern.is_empty() {
        return None;
    }
    let flags = &s[last + 1..];
    Some(PcreSub {
        trigger,
        pattern: pattern.to_string(),
        ci: flags.contains('i'),
        dotall: flags.contains('s'),
        multiline: flags.contains('m'),
        re: std::sync::OnceLock::new(),
    })
}

/// Parse `subsigid(offset#byte_options#comparisons)`.
fn parse_bcomp_subsig(s: &str) -> Option<BcompSub> {
    let lp = s.find('(')?;
    let rp = s.strip_suffix(')')?.len(); // index of the trailing ')'
    if rp <= lp {
        return None;
    }
    let trigger: usize = s[..lp].trim().parse().ok()?;
    let inner = &s[lp + 1..rp];
    let mut fields = inner.split('#');
    let off_s = fields.next()?;
    let opts_s = fields.next()?;
    let cmps_s = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    // offset: `>>N` positive, `<<N` negative.
    let (neg, num) = if let Some(n) = off_s.strip_prefix(">>") {
        (false, n)
    } else if let Some(n) = off_s.strip_prefix("<<") {
        (true, n)
    } else {
        return None;
    };
    let mag = parse_num(num)?;
    let offset = if neg { -mag } else { mag };
    // byte_options: [h|d|a|i][l|b]?[e]? num_bytes
    let mut ch = opts_s.chars().peekable();
    let kind = match ch.next()? {
        'h' => BcompKind::Hex,
        'd' => BcompKind::Dec,
        'a' => BcompKind::Auto,
        'i' => BcompKind::Raw,
        _ => return None,
    };
    let mut big_endian = matches!(kind, BcompKind::Dec); // decimal implies big-endian
    let mut exact = matches!(kind, BcompKind::Raw); // raw implies exact
    if matches!(ch.peek(), Some('l') | Some('b')) {
        big_endian = ch.next() == Some('b');
    }
    if ch.peek() == Some(&'e') {
        ch.next();
        exact = true;
    }
    let nb: String = ch.collect();
    let num_bytes = parse_num(&nb)?;
    if num_bytes <= 0 || num_bytes > 1024 {
        return None;
    }
    if kind == BcompKind::Raw && !matches!(num_bytes, 1 | 2 | 4 | 8) {
        return None;
    }
    // comparisons: one or two `symbolvalue`, comma-separated.
    let mut cmps = Vec::new();
    for set in cmps_s.split(',') {
        let set = set.trim();
        // `set` can be empty (e.g. a trailing comma in a hostile `.ldb`/CVD);
        // `split_at(1)` would panic, so reject an empty comparison instead.
        let sym = set.get(..1)?;
        let val = &set[1..];
        let c = match sym {
            "<" => Cmp::Lt,
            ">" => Cmp::Gt,
            "=" => Cmp::Eq,
            _ => return None,
        };
        cmps.push((c, parse_num(val)?));
    }
    if cmps.is_empty() || cmps.len() > 2 {
        return None;
    }
    Some(BcompSub {
        trigger,
        offset,
        kind,
        big_endian,
        num_bytes: num_bytes as usize,
        exact,
        cmps,
    })
}

fn parse_subsig(s: &str) -> Option<Vec<Compiled>> {
    if s.is_empty() || s.contains('/') {
        return None; // empty or PCRE
    }
    let (core, flags) = match s.split_once("::") {
        Some((c, f)) => (c, f),
        None => (s, ""),
    };
    // An offset prefix is everything before the first ':' (hex bodies have no
    // ':'). No ':' means offset "any".
    let (offset, body) = match core.split_once(':') {
        Some((o, b)) => (parse_offset(o)?, b),
        None => (Offset::Any, core),
    };
    let nocase = flags.contains('i');
    let wide = flags.contains('w');
    let ascii = flags.contains('a') || !wide;

    let mut out = Vec::new();
    if ascii {
        let (e, a, p) = compile_body(body)?;
        out.push((e, a, p, nocase, offset.clone()));
    }
    if wide {
        match compile_wide(body) {
            Some((e, a, p)) => out.push((e, a, p, nocase, offset)),
            // A wide pattern we can't widen (non-literal): keep the ascii
            // variant if we made one, otherwise the subsig is unsupported.
            None if ascii => {}
            None => return None,
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Compile the wide (UTF-16LE) form of a hex body: each byte is interleaved
/// with `0x00`, wildcards each match one wide char, and gaps count wide chars.
fn compile_wide(body: &str) -> Option<(Vec<Elem>, Vec<u8>, Prefix)> {
    let elems = widen_elems(parse_elems(body)?);
    let prefix = pick_anchor(&elems)?;
    let anchor_idx = match prefix {
        Prefix::Fixed { anchor_idx, .. } | Prefix::Floating { anchor_idx } => anchor_idx,
    };
    let anchor = match &elems[anchor_idx] {
        Elem::Bytes(b) => b.clone(),
        _ => return None,
    };
    Some((elems, anchor, prefix))
}

/// Transform a token program into its UTF-16LE form.
fn widen_elems(elems: Vec<Elem>) -> Vec<Elem> {
    fn widen_bytes(v: &[u8]) -> Vec<u8> {
        let mut w = Vec::with_capacity(v.len() * 2);
        for &b in v {
            w.push(b);
            w.push(0);
        }
        w
    }
    let mut out = Vec::with_capacity(elems.len());
    for e in elems {
        match e {
            Elem::Bytes(v) => out.push(Elem::Bytes(widen_bytes(&v))),
            Elem::AnyByte => {
                out.push(Elem::AnyByte);
                out.push(Elem::Bytes(vec![0]));
            }
            Elem::HiNibble(h) => {
                out.push(Elem::HiNibble(h));
                out.push(Elem::Bytes(vec![0]));
            }
            Elem::LoNibble(l) => {
                out.push(Elem::LoNibble(l));
                out.push(Elem::Bytes(vec![0]));
            }
            Elem::Gap { min, max } => out.push(Elem::Gap {
                min: min.saturating_mul(2),
                max: max.map(|m| m.saturating_mul(2)),
            }),
            Elem::Alt { opts, neg } => out.push(Elem::Alt {
                opts: opts.iter().map(|o| widen_bytes(o)).collect(),
                neg,
            }),
        }
    }
    out
}

/// Compile a hex body to (elements, anchor literal, prefix classification).
/// Returns `None` if it uses an unsupported construct or has no usable anchor.
fn compile_body(hex: &str) -> Option<(Vec<Elem>, Vec<u8>, Prefix)> {
    let elems = parse_elems(hex)?;
    let prefix = pick_anchor(&elems)?;
    let anchor_idx = match prefix {
        Prefix::Fixed { anchor_idx, .. } | Prefix::Floating { anchor_idx } => anchor_idx,
    };
    let anchor = match &elems[anchor_idx] {
        Elem::Bytes(b) => b.clone(),
        _ => return None,
    };
    Some((elems, anchor, prefix))
}

fn parse_elems(hex: &str) -> Option<Vec<Elem>> {
    let bytes = hex.as_bytes();
    let mut i = 0;
    let mut elems: Vec<Elem> = Vec::new();
    let mut lit: Vec<u8> = Vec::new();
    macro_rules! flush {
        () => {
            if !lit.is_empty() {
                elems.push(Elem::Bytes(std::mem::take(&mut lit)));
            }
        };
    }
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' => {
                i += 1;
            }
            b'*' => {
                flush!();
                elems.push(Elem::Gap { min: 0, max: None });
                i += 1;
            }
            b'{' => {
                flush!();
                let end = hex[i..].find('}')? + i;
                elems.push(parse_gap(&hex[i + 1..end])?);
                i = end + 1;
            }
            // `[n-m]` (or `[n]`) is a byte-range gap — same matching semantics
            // as `{n-m}`. It is used as an AC boundary (anchoring distance)
            // but for what actually matches it is just a variable gap.
            b'[' => {
                flush!();
                let end = hex[i..].find(']')? + i;
                elems.push(parse_gap(&hex[i + 1..end])?);
                i = end + 1;
            }
            b'!' if bytes.get(i + 1) == Some(&b'(') => {
                flush!();
                let end = hex[i..].find(')')? + i;
                elems.push(parse_alt(&hex[i + 2..end], true)?);
                i = end + 1;
            }
            b'(' => {
                flush!();
                let end = hex[i..].find(')')? + i;
                elems.push(parse_alt(&hex[i + 1..end], false)?);
                i = end + 1;
            }
            _ => {
                // A nibble pair.
                let a = bytes[i];
                let b = *bytes.get(i + 1)?;
                let hi = nibble(a);
                let lo = nibble(b);
                match (a == b'?', b == b'?', hi, lo) {
                    (true, true, _, _) => {
                        flush!();
                        elems.push(Elem::AnyByte);
                    }
                    (false, true, Some(h), _) => {
                        flush!();
                        elems.push(Elem::HiNibble(h));
                    }
                    (true, false, _, Some(l)) => {
                        flush!();
                        elems.push(Elem::LoNibble(l));
                    }
                    (false, false, Some(h), Some(l)) => lit.push((h << 4) | l),
                    _ => return None,
                }
                i += 2;
            }
        }
    }
    flush!();
    if elems.is_empty() {
        None
    } else {
        Some(elems)
    }
}

fn parse_gap(spec: &str) -> Option<Elem> {
    let spec = spec.trim();
    if let Some(rest) = spec.strip_prefix('-') {
        Some(Elem::Gap {
            min: 0,
            max: Some(rest.trim().parse().ok()?),
        })
    } else if let Some(pre) = spec.strip_suffix('-') {
        Some(Elem::Gap {
            min: pre.trim().parse().ok()?,
            max: None,
        })
    } else if let Some((a, b)) = spec.split_once('-') {
        Some(Elem::Gap {
            min: a.trim().parse().ok()?,
            max: Some(b.trim().parse().ok()?),
        })
    } else {
        let n = spec.parse().ok()?;
        Some(Elem::Gap {
            min: n,
            max: Some(n),
        })
    }
}

fn parse_alt(spec: &str, neg: bool) -> Option<Elem> {
    let mut opts = Vec::new();
    for part in spec.split('|') {
        opts.push(decode_plain_hex(part.trim())?);
    }
    if opts.is_empty() || opts.iter().any(|o| o.is_empty()) {
        return None;
    }
    if neg && !opts.iter().all(|o| o.len() == opts[0].len()) {
        return None; // negated alternates must be equal length
    }
    Some(Elem::Alt { opts, neg })
}

/// Choose the literal anchor and classify its prefix.
fn pick_anchor(elems: &[Elem]) -> Option<Prefix> {
    // Pick the *longest* literal run reachable through an all-fixed-width
    // prefix. A longer anchor is far more selective, so the Aho-Corasick
    // prefilter yields far fewer spurious candidates to verify — the dominant
    // scan cost. Any element before the chosen anchor is fixed-width, so
    // `len` (the byte distance back to the pattern start) stays exact.
    let mut fixed = 0usize;
    let mut best: Option<Prefix> = None;
    let mut best_len = 0usize;
    for (i, e) in elems.iter().enumerate() {
        if let Elem::Bytes(b) = e {
            if b.len() >= MIN_ANCHOR && b.len() > best_len {
                best_len = b.len();
                best = Some(Prefix::Fixed {
                    anchor_idx: i,
                    len: fixed,
                });
            }
        }
        match e.width() {
            Some(w) => fixed += w,
            None => break, // first variable element ends the fixed prefix
        }
    }
    if let Some(p) = best {
        return Some(p);
    }
    // Floating: a single leading variable gap, then a usable literal.
    if matches!(elems.first(), Some(Elem::Gap { .. })) {
        if let Some(Elem::Bytes(b)) = elems.get(1) {
            if b.len() >= MIN_ANCHOR {
                return Some(Prefix::Floating { anchor_idx: 1 });
            }
        }
    }
    None
}

fn parse_offset(s: &str) -> Option<Offset> {
    let s = s.trim();
    if s == "*" {
        return Some(Offset::Any);
    }
    let (spec, shift) = match s.split_once(',') {
        Some((a, b)) => (a.trim(), b.trim().parse().unwrap_or(0)),
        None => (s, 0),
    };
    if let Some(rest) = spec.strip_prefix("EOF-") {
        Some(Offset::Eof {
            n: rest.trim().parse().ok()?,
            shift,
        })
    } else if let Some(rest) = spec.strip_prefix("EP") {
        Some(Offset::Ep {
            delta: parse_delta(rest)?,
            shift,
        })
    } else if let Some(rest) = spec.strip_prefix('S') {
        if let Some(d) = rest.strip_prefix('L') {
            Some(Offset::SecLast {
                delta: parse_delta(d)?,
                shift,
            })
        } else {
            // S<idx>[+/-delta]
            let cut = rest.find(['+', '-']).unwrap_or(rest.len());
            let idx: usize = rest[..cut].parse().ok()?;
            Some(Offset::Sec {
                idx,
                delta: parse_delta(&rest[cut..])?,
                shift,
            })
        }
    } else if let Ok(n) = spec.parse::<u64>() {
        Some(Offset::Abs { n, shift })
    } else {
        // VI, SEx, and other offset kinds are not yet supported.
        None
    }
}

/// Parse a signed delta like "", "+5", "-12".
fn parse_delta(s: &str) -> Option<i64> {
    if s.is_empty() {
        Some(0)
    } else {
        s.parse().ok()
    }
}

fn parse_tdb_target(tdb: &str) -> u8 {
    for field in tdb.split(',') {
        if let Some(v) = field.trim().strip_prefix("Target:") {
            return v.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn decode_plain_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

// --- Logical-signature expression evaluation -------------------------------

#[derive(Clone, Copy, Serialize, Deserialize)]
enum Cmp {
    Eq,
    Gt,
    Lt,
}

/// A parsed logical expression.
#[derive(Serialize, Deserialize)]
enum Node {
    /// Bare subsig: matched at least once.
    Sub(usize),
    /// Subsig match-count compared to x.
    SubCmp(usize, Cmp, u32),
    /// Group: total matches across `ids` compared to x, and (if Some) at least
    /// y *distinct* subsigs in the group matched.
    GroupCmp(Vec<usize>, Cmp, u32, Option<u32>),
    And(Vec<Node>),
    Or(Vec<Node>),
}

fn cmp_ok(c: Cmp, v: u32, x: u32) -> bool {
    match c {
        Cmp::Eq => v == x,
        Cmp::Gt => v > x,
        Cmp::Lt => v < x,
    }
}

impl Node {
    fn eval(&self, count: &dyn Fn(usize) -> u32) -> bool {
        match self {
            Node::Sub(i) => count(*i) > 0,
            Node::SubCmp(i, c, x) => cmp_ok(*c, count(*i), *x),
            Node::GroupCmp(ids, c, x, y) => {
                let total: u32 = ids.iter().map(|&i| count(i)).sum();
                if !cmp_ok(*c, total, *x) {
                    return false;
                }
                match y {
                    Some(y) => ids.iter().filter(|&&i| count(i) > 0).count() as u32 >= *y,
                    None => true,
                }
            }
            Node::And(v) => v.iter().all(|n| n.eval(count)),
            Node::Or(v) => v.iter().any(|n| n.eval(count)),
        }
    }

    fn collect_ids(&self, out: &mut Vec<usize>) {
        match self {
            Node::Sub(i) | Node::SubCmp(i, _, _) => out.push(*i),
            Node::GroupCmp(ids, ..) => out.extend_from_slice(ids),
            Node::And(v) | Node::Or(v) => v.iter().for_each(|n| n.collect_ids(out)),
        }
    }

    /// True if every subsig id referenced is `< nsubs`.
    fn ids_within(&self, nsubs: usize) -> bool {
        match self {
            Node::Sub(i) | Node::SubCmp(i, _, _) => *i < nsubs,
            Node::GroupCmp(ids, ..) => ids.iter().all(|&i| i < nsubs),
            Node::And(v) | Node::Or(v) => v.iter().all(|n| n.ids_within(nsubs)),
        }
    }
}

fn parse_expr(expr: &str) -> Option<Node> {
    let tokens: Vec<u8> = expr.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut p = Parser { s: &tokens, i: 0 };
    let node = p.or()?;
    if p.i == p.s.len() {
        Some(node)
    } else {
        None
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn or(&mut self) -> Option<Node> {
        let mut v = vec![self.and()?];
        while self.peek() == Some(b'|') {
            self.i += 1;
            v.push(self.and()?);
        }
        Some(if v.len() == 1 {
            v.pop().unwrap()
        } else {
            Node::Or(v)
        })
    }

    fn and(&mut self) -> Option<Node> {
        let mut v = vec![self.atom()?];
        while self.peek() == Some(b'&') {
            self.i += 1;
            v.push(self.atom()?);
        }
        Some(if v.len() == 1 {
            v.pop().unwrap()
        } else {
            Node::And(v)
        })
    }

    fn atom(&mut self) -> Option<Node> {
        match self.peek()? {
            b'(' => {
                self.i += 1;
                let inner = self.or()?;
                if self.peek() != Some(b')') {
                    return None;
                }
                self.i += 1;
                // A count modifier on a group counts total matches across the
                // group's subsigs (and, with `,y`, distinct subsigs matched).
                if let Some(cmp) = self.cmp() {
                    let (x, y) = self.count_args()?;
                    let mut ids = Vec::new();
                    inner.collect_ids(&mut ids);
                    Some(Node::GroupCmp(ids, cmp, x, y))
                } else {
                    Some(inner)
                }
            }
            b'0'..=b'9' => {
                let sub = self.number()?;
                if let Some(cmp) = self.cmp() {
                    let (x, _y) = self.count_args()?; // single subsig: y is ignored
                    Some(Node::SubCmp(sub, cmp, x))
                } else {
                    Some(Node::Sub(sub))
                }
            }
            _ => None,
        }
    }

    fn cmp(&mut self) -> Option<Cmp> {
        let c = match self.peek()? {
            b'=' => Cmp::Eq,
            b'>' => Cmp::Gt,
            b'<' => Cmp::Lt,
            _ => return None,
        };
        self.i += 1;
        Some(c)
    }

    /// Parse `x` or `x,y` after a comparison operator.
    fn count_args(&mut self) -> Option<(u32, Option<u32>)> {
        let x = self.number()? as u32;
        if self.peek() == Some(b',') {
            self.i += 1;
            Some((x, Some(self.number()? as u32)))
        } else {
            Some((x, None))
        }
    }

    fn number(&mut self) -> Option<usize> {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        if self.i == start {
            return None;
        }
        std::str::from_utf8(&self.s[start..self.i])
            .ok()?
            .parse()
            .ok()
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ndb(line: &str) -> SigEngine {
        let mut b = EngineBuilder::new();
        b.add_ndb(line);
        b.build()
    }

    /// Decode hex (whitespace ignored) so test buffers hold the real bytes a
    /// signature matches, not their ASCII spelling.
    fn hx(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        decode_plain_hex(&clean).unwrap()
    }

    #[test]
    fn literal_and_wildcards() {
        let e = ndb("L:0:*:cafebabe");
        assert!(e
            .scan(&hx("0000 cafebabe 0000"), FileType::Unknown)
            .is_some());

        let w = ndb("W:0:*:cafe??babe"); // ?? any byte
        assert!(w.scan(&hx("cafe 99 babe"), FileType::Unknown).is_some());
        assert!(w.scan(&hx("cafe babe"), FileType::Unknown).is_none());

        let n = ndb("N:0:*:cafec?fe"); // c? high nibble
        assert!(n.scan(&hx("cafe c0 fe"), FileType::Unknown).is_some());
        assert!(n.scan(&hx("cafe a0 fe"), FileType::Unknown).is_none());

        let g = ndb("G:0:*:deadbeef*cafebabe"); // unbounded gap
        assert!(g
            .scan(&hx("deadbeef 11223344 cafebabe"), FileType::Unknown)
            .is_some());

        let b = ndb("B:0:*:deadbeef{1-3}cafebabe"); // bounded gap
        assert!(b
            .scan(&hx("deadbeef 1122 cafebabe"), FileType::Unknown)
            .is_some());
        assert!(b
            .scan(&hx("deadbeef 112233445566 cafebabe"), FileType::Unknown)
            .is_none());

        let a = ndb("A:0:*:cafe(dead|beef)"); // alternation
        assert!(a.scan(&hx("cafe beef"), FileType::Unknown).is_some());
        assert!(a.scan(&hx("cafe c0c0"), FileType::Unknown).is_none());

        let x = ndb("X:0:*:cafe!(dead)"); // negated alternation
        assert!(x.scan(&hx("cafe beef"), FileType::Unknown).is_some());
        assert!(x.scan(&hx("cafe dead"), FileType::Unknown).is_none());

        let f = ndb("F:0:*:*cafebabe"); // leading * (floating anchor)
        assert!(f
            .scan(&hx("11223344 cafebabe"), FileType::Unknown)
            .is_some());
    }

    #[test]
    fn target_filtering() {
        let e = ndb("P:1:*:cafebabe"); // target 1 = PE only
        assert!(e.scan(&hx("00 cafebabe 00"), FileType::Pe).is_some());
        assert!(e.scan(&hx("00 cafebabe 00"), FileType::Unknown).is_none());
    }

    #[test]
    fn absolute_offset() {
        let e = ndb("O:0:2:cafebabe");
        assert!(e.scan(&hx("0000 cafebabe"), FileType::Unknown).is_some()); // at offset 2
        assert!(e
            .scan(&hx("00000000 cafebabe"), FileType::Unknown)
            .is_none()); // at offset 4
    }

    #[test]
    fn eof_offset_underflow_no_false_positive() {
        // `EOF-100` on a file shorter than 100 bytes: the anchor is before the
        // start, so it must NOT collapse to offset 0 and match there.
        let e = ndb("O:0:EOF-100:cafebabe");
        assert!(e.scan(&hx("cafebabe"), FileType::Unknown).is_none());
        // Sanity: a correctly anchored EOF match still works.
        let ok = ndb("O:0:EOF-4:cafebabe");
        assert!(ok.scan(&hx("0000 cafebabe"), FileType::Unknown).is_some());
    }

    #[test]
    fn unmodeled_target_scoped_to_untyped_files() {
        // An HTML-target (4) signature must not fire on a file we positively
        // type as a PE (false positive), but should still run on Unknown
        // content (which is where an HTML file lands, since we don't type it).
        let e = ndb("X:4:*:cafebabe");
        assert!(e.scan(&hx("cafebabe"), FileType::Unknown).is_some());
        assert!(e.scan(&hx("cafebabe"), FileType::Pe).is_none());
        // A PE-target (1) signature still works on a PE.
        let pe = ndb("X:1:*:cafebabe");
        assert!(pe.scan(&hx("cafebabe"), FileType::Pe).is_some());
    }

    #[test]
    fn wildcard_only_is_unsupported() {
        let mut b = EngineBuilder::new();
        b.add_ndb("S:0:*:??"); // no usable anchor
        assert_eq!(b.unsupported(), 1);
    }

    #[test]
    fn logical_signature() {
        let mut b = EngineBuilder::new();
        b.add_ldb("Demo.Both;Target:0;0&1;deadbeef;cafebabe");
        let e = b.build();
        assert!(e
            .scan(&hx("00 deadbeef 00 cafebabe 00"), FileType::Unknown)
            .is_some());
        assert!(e.scan(&hx("00 deadbeef 00"), FileType::Unknown).is_none());
        assert!(e.scan(&hx("00 cafebabe 00"), FileType::Unknown).is_none());
    }

    #[test]
    fn logical_or_and_counts() {
        let mut b = EngineBuilder::new();
        b.add_ldb("Demo.Or;Target:0;0|1;aaaaaa;bbbbbb");
        let e = b.build();
        assert!(e.scan(&hx("00 aaaaaa 00"), FileType::Unknown).is_some());

        let mut b2 = EngineBuilder::new();
        b2.add_ldb("Demo.Count;Target:0;0=2;abcd");
        let e2 = b2.build();
        assert!(e2.scan(&hx("abcd 5f abcd"), FileType::Unknown).is_some()); // exactly 2
        assert!(e2.scan(&hx("abcd"), FileType::Unknown).is_none()); // only 1
    }

    #[test]
    fn ldb_subsig_modifiers() {
        // "malware" = 6d 61 6c 77 61 72 65 ; "MALWARE" = 4d 41 4c 57 41 52 45
        // `::i` (nocase) matches the uppercase bytes; without it, it doesn't.
        let mut bi = EngineBuilder::new();
        bi.add_ldb("Demo.I;Target:0;0;6d616c77617265::i");
        assert!(bi
            .build()
            .scan(&hx("4d414c57415245"), FileType::Unknown)
            .is_some());
        let mut bn = EngineBuilder::new();
        bn.add_ldb("Demo.NoI;Target:0;0;6d616c77617265");
        assert!(bn
            .build()
            .scan(&hx("4d414c57415245"), FileType::Unknown)
            .is_none());

        // `::w` (wide) matches the UTF-16LE form (each byte + 00), not ASCII.
        let mut bw = EngineBuilder::new();
        bw.add_ldb("Demo.W;Target:0;0;6d616c77617265::w");
        let ew = bw.build();
        assert!(ew
            .scan(&hx("6d006100 6c007700 61007200 6500"), FileType::Unknown)
            .is_some());
        assert!(ew.scan(&hx("6d616c77617265"), FileType::Unknown).is_none());

        // `::aw` matches either ASCII or wide.
        let mut ba = EngineBuilder::new();
        ba.add_ldb("Demo.AW;Target:0;0;6d616c77617265::aw");
        let ea = ba.build();
        assert!(ea.scan(&hx("6d616c77617265"), FileType::Unknown).is_some());
        assert!(ea
            .scan(&hx("6d006100 6c007700 61007200 6500"), FileType::Unknown)
            .is_some());

        // wide with a `??` wildcard: "ma<any>l" -> m00 a00 <any>00 l00
        let mut bww = EngineBuilder::new();
        bww.add_ldb("Demo.WW;Target:0;0;6d61??6c::w");
        assert!(bww
            .build()
            .scan(&hx("6d00 6100 9900 6c00"), FileType::Unknown)
            .is_some());
    }

    #[test]
    fn ldb_pcre_subsig() {
        // subsig0: literal "malware"; subsig1: a PCRE (triggered by subsig 0)
        // matching `payload[0-9]+`. Expression requires both.
        let mut b = EngineBuilder::new();
        b.add_ldb("Demo.Pcre;Engine:81-255,Target:0;0&1;6d616c77617265;0/payload[0-9]+/");
        assert_eq!(b.unsupported(), 0, "PCRE subsig should load");
        let e = b.build();
        assert!(e
            .scan(b"x malware x payload42 x", FileType::Unknown)
            .is_some());
        // Trigger present but the regex fails -> no detection.
        assert!(e
            .scan(b"x malware x payloadZZ x", FileType::Unknown)
            .is_none());
        // No trigger -> the PCRE is never evaluated.
        assert!(e.scan(b"clean payload99", FileType::Unknown).is_none());

        // Case-insensitive flag.
        let mut bi = EngineBuilder::new();
        bi.add_ldb("Demo.PcreI;Engine:81-255,Target:0;0&1;6d616c77617265;0/PAYLOAD/i");
        assert!(bi
            .build()
            .scan(b"malware payload", FileType::Unknown)
            .is_some());
    }

    #[test]
    fn ldb_byte_compare_subsig() {
        // subsig0: literal "ANCHOR"; subsig1: byte-compare reading 4 decimal
        // ASCII bytes at +6 from the anchor and testing `= 1234`.
        let mut b = EngineBuilder::new();
        b.add_ldb("Demo.Bcomp;Engine:81-255,Target:0;0&1;414e43484f52;0(>>6#d4#=1234)");
        assert_eq!(b.unsupported(), 0, "byte-compare subsig should load");
        let e = b.build();
        assert!(e.scan(b"ANCHOR1234tail", FileType::Unknown).is_some());
        // Same anchor, different value -> comparison fails.
        assert!(e.scan(b"ANCHOR9999tail", FileType::Unknown).is_none());

        // Raw little-endian binary compare: 2 bytes at the anchor start `> 0`.
        let mut br = EngineBuilder::new();
        br.add_ldb("Demo.BcompRaw;Engine:81-255,Target:0;0&1;414e43484f52;0(>>6#il2#>0)");
        assert!(br
            .build()
            .scan(b"ANCHOR\x01\x00rest", FileType::Unknown)
            .is_some());
    }

    #[test]
    fn ep_and_section_offsets() {
        // EP+4: the pattern must start at (entry file offset) + 4 = 6.
        let e = ndb("E:0:EP+4:cafebabe");
        let layout = PeLayout {
            entry: Some(2),
            section_rawptrs: vec![0, 0x800],
        };
        let buf = hx("00000000 0000 cafebabe"); // cafebabe at offset 6
        assert!(e
            .scan_with_layout(&buf, FileType::Pe, Some(&layout))
            .is_some());
        // Without layout the EP offset can't be resolved -> no match.
        assert!(e.scan(&buf, FileType::Pe).is_none());

        // S0+2: relative to section 0's file offset (0) + 2 = 2.
        let s = ndb("S:0:S0+2:cafebabe");
        assert!(s
            .scan_with_layout(&hx("0000 cafebabe"), FileType::Pe, Some(&layout))
            .is_some());
    }

    #[test]
    fn ldb_group_count() {
        // (0|1|2)>1: total matches across subsigs 0,1,2 must exceed 1.
        let mut b = EngineBuilder::new();
        b.add_ldb("Demo.Grp;Target:0;(0|1|2)>1;deadbeef;cafebabe;0badf00d");
        let e = b.build();
        assert!(e
            .scan(&hx("deadbeef cafebabe"), FileType::Unknown)
            .is_some());
        assert!(e.scan(&hx("deadbeef"), FileType::Unknown).is_none());

        // comma form (0|1|2)>1,2: total>1 AND >=2 distinct subsigs matched.
        let mut b2 = EngineBuilder::new();
        b2.add_ldb("Demo.GrpY;Target:0;(0|1|2)>1,2;abcd;ef01;2345");
        let e2 = b2.build();
        // subsig 0 twice: total 2 (>1) but only 1 distinct -> no match
        assert!(e2.scan(&hx("abcd abcd"), FileType::Unknown).is_none());
        // two distinct subsigs: total 2 (>1) and 2 distinct -> match
        assert!(e2.scan(&hx("abcd ef01"), FileType::Unknown).is_some());
    }

    #[test]
    fn ldb_subsig_offset_prefix() {
        // Subsignature with a numeric offset prefix: must match at offset 2.
        let mut b = EngineBuilder::new();
        b.add_ldb("Demo.Off;Target:0;0;2:cafebabe");
        let e = b.build();
        assert!(e.scan(&hx("0000 cafebabe"), FileType::Unknown).is_some());
        assert!(e
            .scan(&hx("00000000 cafebabe"), FileType::Unknown)
            .is_none());
    }
}
