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
use std::cell::RefCell;

use crate::filetype::FileType;
use crate::pe::PeLayout;

/// The container types referenced by `Container:CL_TYPE_*` TDB constraints in
/// the logical-signature format that exav can determine provenance for. A
/// signature with such a constraint fires only when its *immediate* container is
/// of this type; at the top level (no container) a constrained signature never
/// fires. Container types exav can't reliably identify are parsed as "no
/// constraint" (left unenforced — strictly no new false negatives), so this enum
/// lists only the ones with accurate provenance. Named after the `CL_TYPE_*`
/// tokens of the signature format.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum ClType {
    Zip,
    OoxmlWord,
    OoxmlXl,
    OoxmlPpt,
    Msole2,
    Mail,
    Pdf,
    Mscab,
    Rar,
    SevenZip,
    Iso,
    Lha,
    Tar,
    Gzip,
    Bzip,
    Xz,
    Cpio,
    Ar,
    Zstd,
}

impl ClType {
    /// Map a `CL_TYPE_*` token (the value after `Container:`) to a [`ClType`].
    /// Returns `None` for `CL_TYPE_ANY` and for any token exav doesn't model, so
    /// such constraints are left unenforced rather than risk a false negative.
    fn from_cl_token(t: &str) -> Option<ClType> {
        Some(match t {
            "CL_TYPE_ZIP" => ClType::Zip,
            "CL_TYPE_OOXML_WORD" => ClType::OoxmlWord,
            "CL_TYPE_OOXML_XL" => ClType::OoxmlXl,
            "CL_TYPE_OOXML_PPT" => ClType::OoxmlPpt,
            "CL_TYPE_MSOLE2" => ClType::Msole2,
            "CL_TYPE_MAIL" => ClType::Mail,
            "CL_TYPE_PDF" => ClType::Pdf,
            "CL_TYPE_MSCAB" => ClType::Mscab,
            "CL_TYPE_RAR" => ClType::Rar,
            "CL_TYPE_7Z" => ClType::SevenZip,
            "CL_TYPE_ISO9660" => ClType::Iso,
            "CL_TYPE_LHA_LZH" => ClType::Lha,
            "CL_TYPE_POSIX_TAR" | "CL_TYPE_OLD_TAR" | "CL_TYPE_GNU_TAR" => ClType::Tar,
            "CL_TYPE_GZ" => ClType::Gzip,
            "CL_TYPE_BZ" => ClType::Bzip,
            "CL_TYPE_XZ" => ClType::Xz,
            "CL_TYPE_CPIO_NEWC" | "CL_TYPE_CPIO_CRC" | "CL_TYPE_CPIO_ODC" | "CL_TYPE_CPIO_OLD" => {
                ClType::Cpio
            }
            "CL_TYPE_AR" => ClType::Ar,
            "CL_TYPE_ZSTD" => ClType::Zstd,
            _ => return None,
        })
    }
}

/// Parse a `Container:CL_TYPE_*` TDB attribute into a [`ClType`] to enforce.
/// Absent, `CL_TYPE_ANY`, or an unmodeled type → `None` (no enforcement).
fn parse_tdb_container(tdb: &str) -> Option<ClType> {
    for field in tdb.split(',') {
        if let Some(v) = field.trim().strip_prefix("Container:") {
            return ClType::from_cl_token(v.trim());
        }
    }
    None
}

/// Parse `IconGroup1:<name>` / `IconGroup2:<name>` TDB attributes. Each is
/// optional; returns `(group1, group2)`. Group names are byte-exact (no hex
/// decoding) and case-sensitive.
fn parse_tdb_icongroups(tdb: &str) -> (Option<String>, Option<String>) {
    let mut g1 = None;
    let mut g2 = None;
    for field in tdb.split(',') {
        let f = field.trim();
        if let Some(v) = f.strip_prefix("IconGroup1:") {
            g1 = Some(v.to_string());
        } else if let Some(v) = f.strip_prefix("IconGroup2:") {
            g2 = Some(v.to_string());
        }
    }
    (g1, g2)
}

/// Minimum literal length usable as an Aho-Corasick anchor.
const MIN_ANCHOR: usize = 2;

thread_local! {
    /// Per-thread reusable LDB-subsig scratch (`counts` + first-match `offs`),
    /// grown to the largest engine seen and always stored in a clean state
    /// (all `0` / `u32::MAX`). Reused across scans so a scan pays only for the
    /// bodies it actually touches, not a full re-zero of every body each call
    /// (~10 MiB for a full database).
    static LDB_SCRATCH: RefCell<(Vec<u32>, Vec<u32>)> =
        const { RefCell::new((Vec::new(), Vec::new())) };
}

/// RAII handle over the thread-local LDB scratch. On drop it resets only the
/// touched entries and returns the buffers to the thread-local, preserving the
/// clean-when-stored invariant across the scan functions' early returns.
struct Scratch {
    counts: Vec<u32>,
    offs: Vec<u32>,
    /// Body ids whose `counts`/`offs` were modified this scan (the reset set).
    touched: Vec<usize>,
}

impl Scratch {
    /// Acquire a clean scratch with at least `n` entries. `n == 0` (engine has
    /// no logical signatures) yields empty buffers without disturbing the
    /// cached ones. Grow-only, so two engines of different sizes sharing a
    /// thread don't thrash the allocation.
    fn acquire(n: usize) -> Self {
        if n == 0 {
            return Scratch {
                counts: Vec::new(),
                offs: Vec::new(),
                touched: Vec::new(),
            };
        }
        let (mut counts, mut offs) = LDB_SCRATCH.with(|s| s.replace((Vec::new(), Vec::new())));
        if counts.len() < n {
            counts.resize(n, 0);
            offs.resize(n, u32::MAX);
        }
        Scratch {
            counts,
            offs,
            touched: Vec::new(),
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if self.counts.is_empty() {
            return; // the `n == 0` case never borrowed the thread-local
        }
        for &b in &self.touched {
            self.counts[b] = 0;
            self.offs[b] = u32::MAX;
        }
        let counts = std::mem::take(&mut self.counts);
        let offs = std::mem::take(&mut self.offs);
        LDB_SCRATCH.with(|s| *s.borrow_mut() = (counts, offs));
    }
}
/// Per-candidate verification step cap: bounds backtracking on a *single*
/// pattern (gaps/alternations) so one pathological body can't loop unboundedly,
/// the same idea as a regex step limit. Each `verify` call gets a fresh budget.
/// With the memmem gap fast path a legitimate match needs very few steps; this
/// only caps deliberately hostile backtracking. There is no per-scan "give up"
/// budget — fan-out is bounded structurally (selective across-gap
/// [`Prefix::Internal`] anchors keyed on a rare literal instead of a zero-run,
/// plus an offset gate applied *before* `match_forward` for pinned-offset sigs),
/// so a scan always completes rather than being abandoned as `LimitsExceeded`.
const VERIFY_BUDGET: u64 = 200_000;

thread_local! {
    /// Diagnostic: (slowest token-verify microseconds, its body id).
    static DIAG_SLOW: std::cell::Cell<(u64, usize)> = const { std::cell::Cell::new((0, 0)) };
}

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
    /// The anchor sits past one or more *variable* gaps from the pattern start
    /// (`elems[..anchor_idx]` contains a `Gap`/`Alt`). Verification matches both
    /// forward from the anchor and *backward* across the preceding gaps. Chosen
    /// only when a literal after a gap is markedly more selective than anything
    /// in the fixed prefix (e.g. a constant zero-run is the only pre-gap literal)
    /// — and only for `Offset::Any` patterns, so the floating pattern start never
    /// needs to satisfy a fixed offset.
    Internal { anchor_idx: usize },
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
    /// A direct `.ndb` (or built-in literal) signature: its clean detection name
    /// plus whether it came from an unofficial (non-`.cvd`) database. The
    /// `.UNOFFICIAL` suffix is NEVER baked into `name`; the report layer appends
    /// it (gated on compat mode) using this `unofficial` bit. One cache thus
    /// serves both compat and non-compat scans.
    Ndb { name: String, unofficial: bool },
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
    /// Optional `FileSize:min-max` TDB constraint (inclusive); the scanned
    /// object's length must fall within it for the signature to fire.
    file_size: Option<(u64, u64)>,
    /// Optional `Container:CL_TYPE_*` TDB constraint: the signature fires only
    /// when the object's *immediate* container is of this type (and never at the
    /// top level, where there is no container). `None` = unconstrained.
    container: Option<ClType>,
    /// Optional `IconGroup1:`/`IconGroup2:` TDB constraint: when set, the
    /// signature additionally requires the scanned PE's icon to perceptually
    /// match an `.idb` entry whose group1/group2 names satisfy these (each
    /// `None` ⇒ `"*"` wildcard). Only meaningful on PE targets. `None`/`None` =
    /// no icon constraint.
    icon_group: Option<(Option<String>, Option<String>)>,
    /// Whether this logical signature came from an unofficial (non-`.cvd`)
    /// database. Carried as clean provenance; the `.UNOFFICIAL` suffix is applied
    /// only at report time (compat mode), never baked into `name`.
    #[serde(default)]
    unofficial: bool,
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
    /// `fuzzy_img#<hash>`: matched if the scanned object is an image whose 64-bit
    /// perceptual hash equals this one. The current signature format supports
    /// only Hamming distance 0, so matching is exact equality.
    Fuzzy([u8; 8]),
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
    /// Backtracking fallback (lookaround/backreferences) the linear `regex`
    /// engine can't compile. Run over a latin-1 mapping of the bytes.
    #[serde(skip)]
    fancy: std::sync::OnceLock<Option<fancy_regex::Regex>>,
}

impl PcreSub {
    /// Inline-flag prefix (`(?ism)`) applied to this subsig's pattern.
    fn flagged_pattern(&self) -> String {
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
        if flags.is_empty() {
            self.pattern.clone()
        } else {
            format!("(?{flags}){}", self.pattern)
        }
    }

    /// Lazily compile and run the regex over `buf`. The linear-time, DoS-safe
    /// `regex` engine handles the vast majority of patterns. The few using
    /// lookaround / backreferences (not regular languages) can't compile there;
    /// they fall back to the backtracking `fancy-regex`, run over a LOSSLESS
    /// latin-1 mapping of the bytes (each byte `0x00..=0xff` → `U+0000..=U+00FF`)
    /// so it works on binary content, not just text. ClamAV writes high bytes as
    /// `\xNN`, which map to the same codepoints, so matching is byte-equivalent.
    /// A bounded backtrack budget plus trigger-gating keep it DoS- and FP-safe.
    fn is_match(&self, buf: &[u8]) -> bool {
        let re = self.re.get_or_init(|| {
            regex::bytes::RegexBuilder::new(&self.flagged_pattern())
                .size_limit(16 * 1024 * 1024)
                .dfa_size_limit(16 * 1024 * 1024)
                .build()
                .ok()
        });
        if let Some(r) = re {
            return r.is_match(buf);
        }
        let fre = self.fancy.get_or_init(|| {
            fancy_regex::RegexBuilder::new(&self.flagged_pattern())
                .backtrack_limit(1_000_000)
                .build()
                .ok()
        });
        let Some(r) = fre.as_ref() else {
            return false;
        };
        // Lossless byte→char (latin-1) mapping so the str engine sees the bytes.
        let mapped: String = buf.iter().map(|&b| b as char).collect();
        r.is_match(&mapped).unwrap_or(false)
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
                let digits: String = s.chars().take_while(|c| c.is_digit(radix)).collect();
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
    /// Whether the scanned object's length satisfies the `FileSize:` TDB
    /// constraint (no constraint → always true).
    fn size_ok(&self, len: usize) -> bool {
        match self.file_size {
            Some((min, max)) => {
                let n = len as u64;
                n >= min && n <= max
            }
            None => true,
        }
    }

    /// Whether the current container context satisfies the `Container:` TDB
    /// constraint. An unconstrained sig always passes. A constrained sig fires
    /// only when the immediate container matches — in particular never at the
    /// top level (`cur == None`), per the signature format, which scopes such
    /// sigs to content extracted from a container of that type.
    fn container_ok(&self, cur: Option<ClType>) -> bool {
        match self.container {
            Some(req) => cur == Some(req),
            None => true,
        }
    }

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
        img_hash: Option<[u8; 8]>,
        icon_ctx: Option<&IconCtx>,
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
                SubSig::Fuzzy(h) => {
                    if img_hash == Some(*h) {
                        c[i] = 1;
                    }
                }
                SubSig::Bodies(_) => {}
            }
        }
        if !self.expr.eval(&|i| c.get(i).copied().unwrap_or(0)) {
            return false;
        }
        // The structural condition holds. If the signature carries an
        // `IconGroup1/2` constraint, the PE's icon must additionally match an
        // `.idb` entry in the requested group(s); without an icon context (no
        // `.idb` loaded, or the input is not a PE) the constraint can't be
        // satisfied, so the sig does not fire.
        if let Some((g1, g2)) = &self.icon_group {
            match icon_ctx {
                Some(ctx) => ctx.matches(g1.as_deref(), g2.as_deref()),
                None => false,
            }
        } else {
            true
        }
    }
}

/// Per-scan icon-matching context: the loaded `.idb` database plus the PE's
/// computed icon metrics (computed lazily, once per scan, by the caller). An
/// `IconGroup`-constrained logical signature fires only when [`Self::matches`]
/// confirms a perceptual icon match.
pub struct IconCtx<'a> {
    icons: &'a crate::icon::IconDb,
    metrics: &'a [crate::icon::IconMetric],
}

impl<'a> IconCtx<'a> {
    pub fn new(icons: &'a crate::icon::IconDb, metrics: &'a [crate::icon::IconMetric]) -> Self {
        IconCtx { icons, metrics }
    }
    fn matches(&self, g1: Option<&str>, g2: Option<&str>) -> bool {
        self.icons.match_pe(self.metrics, g1, g2).is_some()
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
    /// When false (the default, matching ClamAV's `DetectPUA off`), `PUA.*`
    /// signatures are dropped at load. Set true to include them.
    detect_pua: bool,
}

impl EngineBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Include `PUA.*` signatures (ClamAV `--detect-pua`). Off by default.
    pub fn set_detect_pua(&mut self, on: bool) {
        self.detect_pua = on;
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
            owner: Owner::Ndb {
                name: name.to_string(),
                unofficial: false,
            },
        });
    }

    /// Add `.ndb` lines (`Name:Target:Offset:HexBody[:min[:max]]`). `unofficial`
    /// marks signatures from a non-`.cvd` database, so a compat-mode report
    /// suffixes them with `.UNOFFICIAL`.
    pub fn add_ndb(&mut self, text: &str, unofficial: bool) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(4, ':');
            let name = parts.next().unwrap_or("").to_string();
            // PUA signatures are off by default in ClamAV (`DetectPUA`); skip to
            // match unless explicitly enabled.
            if is_pua(&name) && !self.detect_pua {
                continue;
            }
            let target: u8 = parts
                .next()
                .and_then(|t| t.trim().parse().ok())
                .unwrap_or(0);
            let offset = parts.next().map(parse_offset).unwrap_or(Some(Offset::Any));
            // The remainder is `HexBody[:minFL[:maxFL]]`. NDB hex bodies never
            // contain ':', so split it off; without this the flevel suffix is
            // folded into the body and fails to compile (~1k sigs lost as
            // "unsupported"). Enforce the flevel window like ClamAV does.
            let rest = parts.next();
            let (body, flevel_ok_here) = match rest {
                Some(r) => {
                    let mut it = r.splitn(3, ':');
                    let hex = it.next().unwrap_or("");
                    let min = it.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                    let max = it
                        .next()
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(u32::MAX);
                    (Some(hex), flevel_ok(min, max))
                }
                None => (None, true),
            };
            if !flevel_ok_here {
                continue; // sig is for a different engine flevel — skip like ClamAV
            }
            match (offset, body) {
                (Some(offset), Some(hex)) => match compile_body(hex, matches!(offset, Offset::Any))
                {
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
                            owner: Owner::Ndb { name, unofficial },
                        });
                    }
                    None => self.unsupported += 1,
                },
                _ => self.unsupported += 1,
            }
        }
    }

    /// Add `.ldb` lines (`Name;TDB;Expr;Sub0;Sub1;...`). `unofficial` marks
    /// signatures from a non-`.cvd` database (suffixed `.UNOFFICIAL` in compat).
    pub fn add_ldb(&mut self, text: &str, unofficial: bool) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !self.add_ldb_line(line, unofficial) {
                self.unsupported += 1;
            }
        }
    }

    fn add_ldb_line(&mut self, line: &str, unofficial: bool) -> bool {
        let parts: Vec<&str> = line.split(';').collect();
        if parts.len() < 4 {
            return false;
        }
        // PUA (Potentially Unwanted Application) signatures are OFF by default in
        // ClamAV (DetectPUA); a drop-in must match that, so don't load them
        // unless explicitly enabled.
        if is_pua(parts[0]) && !self.detect_pua {
            return false;
        }
        // An `IconGroup1:`/`IconGroup2:` TDB constraint gates the signature on a
        // PE-icon perceptual match (see [`crate::icon`]). We load the sig and
        // store the group-name constraint; at match time the structural part
        // must hold AND the PE's icon must match an `.idb` entry in the
        // requested group(s) — otherwise the sig does not fire.
        let icon_group = {
            let (g1, g2) = parse_tdb_icongroups(parts[1]);
            if g1.is_some() || g2.is_some() {
                Some((g1, g2))
            } else {
                None
            }
        };
        // Engine flevel window: load only when our flevel is in range, exactly as
        // ClamAV does (skips future-engine sigs and deprecated ones).
        let (emin, emax) = parse_tdb_engine(parts[1]);
        if !flevel_ok(emin, emax) {
            return false;
        }
        let name = parts[0].to_string();
        let target = parse_tdb_target(parts[1]);
        let file_size = parse_tdb_filesize(parts[1]);
        let container = parse_tdb_container(parts[1]);
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
                ParsedSub::Fuzzy(h) => SubSig::Fuzzy(h),
            };
            subs.push(sub);
        }
        self.ldbs.push(Ldb {
            name,
            target,
            expr,
            fires_on_empty,
            subs,
            file_size,
            container,
            icon_group,
            unofficial,
        });
        true
    }

    pub fn unsupported(&self) -> usize {
        self.unsupported
    }

    pub fn signature_count(&self) -> usize {
        self.bodies
            .iter()
            .filter(|b| matches!(b.owner, Owner::Ndb { .. }))
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
        let (body_ldb, fires_empty) = ldb_indexes(self.bodies.len(), &self.ldbs);
        let targets = self.bodies.iter().map(|b| b.target).collect();
        let fuzzy_ldbs = fuzzy_ldb_indices(&self.ldbs);
        let has_fuzzy = !fuzzy_ldbs.is_empty();
        SigEngine {
            ac,
            ac_ci,
            cs_groups,
            ci_groups,
            bodies: self.bodies,
            ldbs: self.ldbs,
            unsupported: self.unsupported,
            targets,
            body_ldb,
            fires_empty,
            has_fuzzy,
            fuzzy_ldbs,
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
    /// Per-body target type, in a compact array parallel to `bodies`. Checked
    /// before the (large, cache-cold) `bodies` array on every anchor fan-out, so
    /// a body whose target doesn't match the file type is rejected from L2 cache
    /// instead of paying a random miss into the full body table — the dominant
    /// cost on type-mismatched fan-out (the common case). Derived from `bodies`.
    targets: Vec<u8>,
    /// For each body id, the index of the logical signature it belongs to (a
    /// subsignature body), or `u32::MAX` for `.ndb` bodies. Lets a scan evaluate
    /// only the logical sigs whose subsigs actually matched, instead of all of
    /// them (the dominant per-scan cost otherwise).
    body_ldb: Vec<u32>,
    /// Logical signatures whose expression is satisfied by an all-zero count
    /// vector (rare). These must be evaluated even when no subsignature matched.
    fires_empty: Vec<u32>,
    /// Whether any loaded logical sig has a `fuzzy_img#` subsig. When false (the
    /// common case), the per-scan image perceptual hash is never computed.
    /// Derived from `ldbs` (recomputed after a cache load).
    has_fuzzy: bool,
    /// Indices of logical sigs containing a `fuzzy_img#` subsig. Such sigs may
    /// have no AC-anchored body subsig (nothing "touches" them), so they must be
    /// evaluated for image inputs regardless of which bodies matched. Empty in
    /// the common case. Derived from `ldbs`.
    fuzzy_ldbs: Vec<u32>,
}

/// Indices of logical signatures carrying a `fuzzy_img#` subsignature.
fn fuzzy_ldb_indices(ldbs: &[Ldb]) -> Vec<u32> {
    ldbs.iter()
        .enumerate()
        .filter(|(_, l)| l.subs.iter().any(|s| matches!(s, SubSig::Fuzzy(_))))
        .map(|(i, _)| i as u32)
        .collect()
}

/// Build the `body_ldb` reverse index and the `fires_empty` list from the parsed
/// logical signatures. Derived data (recomputed after a cache load), so the
/// on-disk cache format is unaffected.
fn ldb_indexes(n_bodies: usize, ldbs: &[Ldb]) -> (Vec<u32>, Vec<u32>) {
    let mut body_ldb = vec![u32::MAX; n_bodies];
    let mut fires_empty = Vec::new();
    for (li, ldb) in ldbs.iter().enumerate() {
        if ldb.fires_on_empty {
            fires_empty.push(li as u32);
        }
        for sub in &ldb.subs {
            if let SubSig::Bodies(ids) = sub {
                for &bid in ids {
                    if bid < n_bodies {
                        body_ldb[bid] = li as u32;
                    }
                }
            }
        }
    }
    (body_ldb, fires_empty)
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
    /// this build wrote and validated (magic + version).
    pub(crate) fn read_cache<R: std::io::Read>(mut r: R) -> std::io::Result<Self> {
        use crate::cache::dec;
        let ac_bytes: Option<Vec<u8>> = dec(&mut r)?;
        let ac_ci_bytes: Option<Vec<u8>> = dec(&mut r)?;
        let cs_groups = dec(&mut r)?;
        let ci_groups = dec(&mut r)?;
        let bodies: Vec<Body> = dec(&mut r)?;
        let ldbs: Vec<Ldb> = dec(&mut r)?;
        let unsupported = dec(&mut r)?;
        let deser = |b: Vec<u8>| DoubleArrayAhoCorasick::deserialize(&b).unwrap().0;
        let (body_ldb, fires_empty) = ldb_indexes(bodies.len(), &ldbs);
        let targets = bodies.iter().map(|b| b.target).collect();
        let fuzzy_ldbs = fuzzy_ldb_indices(&ldbs);
        let has_fuzzy = !fuzzy_ldbs.is_empty();
        Ok(SigEngine {
            ac: ac_bytes.map(deser),
            ac_ci: ac_ci_bytes.map(deser),
            cs_groups,
            ci_groups,
            bodies,
            ldbs,
            unsupported,
            targets,
            body_ldb,
            fires_empty,
            has_fuzzy,
            fuzzy_ldbs,
        })
    }

    /// Number of loaded signatures (ndb bodies + logical signatures).
    pub fn signature_count(&self) -> usize {
        self.bodies
            .iter()
            .filter(|b| matches!(b.owner, Owner::Ndb { .. }))
            .count()
            + self.ldbs.len()
    }

    /// Number of loaded logical sigs carrying a `fuzzy_img#` subsig (diagnostic).
    pub fn fuzzy_sig_count(&self) -> usize {
        self.fuzzy_ldbs.len()
    }

    /// Scan an in-memory buffer of the given type. Returns the first matching
    /// signature's clean name, the match offset, and whether the matched
    /// signature came from an unofficial database (the report layer appends
    /// `.UNOFFICIAL` in compat mode).
    pub fn scan(&self, buf: &[u8], ft: FileType) -> Option<(String, u64, bool)> {
        self.scan_with_layout(buf, ft, None, None)
    }

    /// Describe a body's compiled pattern (diagnostic).
    pub fn describe_body(&self, bid: usize) -> String {
        let b = &self.bodies[bid];
        let owner = match &b.owner {
            Owner::Ndb { name, .. } => name.clone(),
            Owner::LdbSub => "<ldbsub>".to_string(),
        };
        let elems = match &b.elems {
            None => "<literal-only>".to_string(),
            Some(e) => e
                .iter()
                .map(|x| match x {
                    Elem::Bytes(b) => format!("B{}", b.len()),
                    Elem::AnyByte => "?".to_string(),
                    Elem::HiNibble(_) | Elem::LoNibble(_) => "n".to_string(),
                    Elem::Gap { min, max } => format!("G{{{},{:?}}}", min, max),
                    Elem::Alt { opts, neg } => {
                        format!("A{}{}", if *neg { "!" } else { "" }, opts.len())
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
        };
        format!("{owner} :: {elems}")
    }

    /// Slowest token verify seen by the last `scan_diag` (microseconds, bid).
    pub fn diag_slowest(&self) -> (u64, usize) {
        DIAG_SLOW.with(|c| c.get())
    }

    /// Diagnostic breakdown of one scan's match work (no early return), for
    /// performance analysis: per-pass anchor hits, fan-out, and the verify
    /// split. `(cs_hits, ci_hits, fanout, target_reject, literal, token, ok)`.
    pub fn scan_diag(&self, buf: &[u8], ft: FileType, layout: Option<&PeLayout>) -> [u64; 7] {
        DIAG_SLOW.with(|c| c.set((0, 0)));
        let lower = self.ac_ci.as_ref().map(|_| buf.to_ascii_lowercase());
        let passes: [(_, _, _, usize); 2] = [
            (&self.ac, &self.cs_groups, buf, 0usize),
            (
                &self.ac_ci,
                &self.ci_groups,
                lower.as_deref().unwrap_or(&[]),
                1,
            ),
        ];
        let (mut cs_hits, mut ci_hits, mut fanout) = (0u64, 0u64, 0u64);
        let (mut treject, mut lit, mut tok, mut ok) = (0u64, 0u64, 0u64, 0u64);
        for (ac, groups, hay, which) in passes {
            let Some(ac) = ac else { continue };
            for m in ac.find_overlapping_iter(hay) {
                if which == 0 {
                    cs_hits += 1;
                } else {
                    ci_hits += 1;
                }
                let group = &groups[m.value() as usize];
                fanout += group.len() as u64;
                for &bid in group {
                    if !target_ok(self.targets[bid], ft) {
                        treject += 1;
                        continue;
                    }
                    let body = &self.bodies[bid];
                    if body.elems.is_none() {
                        lit += 1;
                    } else {
                        tok += 1;
                    }
                    let t = std::time::Instant::now();
                    if verify(body, buf, m.start(), layout).is_some() {
                        ok += 1;
                    }
                    let us = t.elapsed().as_micros() as u64;
                    if us > DIAG_SLOW.with(|c| c.get().0) {
                        DIAG_SLOW.with(|c| c.set((us, bid)));
                    }
                }
            }
        }
        [cs_hits, ci_hits, fanout, treject, lit, tok, ok]
    }

    /// Per-anchor-length fan-out histogram for one scan (diagnostic). Returns,
    /// indexed by anchor byte length (0..=15, last bucket = >=15), a tuple of
    /// (anchor_hits, total_fanout). Lets us see which anchor lengths drive the
    /// verify explosion on dense content.
    pub fn scan_diag_hist(&self, buf: &[u8], _ft: FileType) -> Vec<(u64, u64)> {
        let mut hist = vec![(0u64, 0u64); 16];
        let lower = self.ac_ci.as_ref().map(|_| buf.to_ascii_lowercase());
        let passes: [(_, _, _); 2] = [
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
                let len = (m.end() - m.start()).min(15);
                let g = groups[m.value() as usize].len() as u64;
                hist[len].0 += 1;
                hist[len].1 += g;
            }
        }
        hist
    }

    /// Fixed literal-byte constraints of a body relative to its anchor start,
    /// reachable without crossing a variable-width element. `(rel_offset, byte)`.
    /// Used to evaluate secondary discriminators for over-large anchor groups.
    fn body_constraints(&self, bid: usize, out: &mut Vec<(i32, u8)>) {
        out.clear();
        let body = &self.bodies[bid];
        let Some(elems) = &body.elems else { return };
        let (start_idx, mut off) = match body.prefix {
            Prefix::Fixed { len, .. } => (0usize, -(len as i32)),
            Prefix::Floating { anchor_idx } | Prefix::Internal { anchor_idx } => (anchor_idx, 0i32),
        };
        for e in &elems[start_idx..] {
            match e {
                Elem::Bytes(b) => {
                    for (j, &x) in b.iter().enumerate() {
                        out.push((off + j as i32, x));
                    }
                    off += b.len() as i32;
                }
                other => match other.width() {
                    Some(w) => off += w as i32,
                    None => break,
                },
            }
        }
    }

    /// Diagnostic: for one scan, the groups that contribute the most fan-out,
    /// each with its discriminability — the best single secondary byte offset and
    /// the fraction of bodies it constrains. Prints nothing; returns rows of
    /// `(anchor_len, group_size, hits, fanout_contrib, best_off, coverage_pct)`.
    pub fn scan_diag_groups(
        &self,
        buf: &[u8],
        _ft: FileType,
    ) -> Vec<(usize, usize, u64, u64, i32, u32)> {
        // Count hits per group value (case-sensitive pass only — it dominates).
        let mut hits: std::collections::HashMap<u32, (u64, usize)> =
            std::collections::HashMap::new();
        if let Some(ac) = &self.ac {
            for m in ac.find_overlapping_iter(buf) {
                let len = m.end() - m.start();
                hits.entry(m.value()).or_insert((0, len)).0 += 1;
            }
        }
        let mut rows: Vec<(usize, usize, u64, u64, i32, u32)> = Vec::new();
        let mut cons = Vec::new();
        for (val, (h, anchor_len)) in hits {
            let group = &self.cs_groups[val as usize];
            let gsize = group.len();
            let fanout = h * gsize as u64;
            if fanout < 50_000 {
                continue;
            }
            // Best secondary discriminator: the relative offset (OUTSIDE the
            // anchor, which is identical across the group) whose byte-value split
            // minimizes the worst-case bucket = unconstrained + largest value
            // bucket. Lower max-bucket = more fan-out eliminated.
            // off -> (byte -> count), and per-off unconstrained count.
            let mut buckets: std::collections::HashMap<i32, [u32; 256]> =
                std::collections::HashMap::new();
            let mut constrained: std::collections::HashMap<i32, u32> =
                std::collections::HashMap::new();
            for &bid in group {
                self.body_constraints(bid, &mut cons);
                let mut seen_off: std::collections::HashSet<i32> = std::collections::HashSet::new();
                for &(o, b) in &cons {
                    if o >= 0 && (o as usize) < anchor_len {
                        continue; // inside the shared anchor: no discrimination
                    }
                    if seen_off.insert(o) {
                        buckets.entry(o).or_insert([0; 256])[b as usize] += 1;
                        *constrained.entry(o).or_insert(0) += 1;
                    }
                }
            }
            let mut best_off = 0i32;
            let mut best_maxbucket = gsize as u32; // no discriminator => whole group
            for (&o, bk) in &buckets {
                let unconstrained = gsize as u32 - constrained[&o];
                let maxval = *bk.iter().max().unwrap();
                let mb = unconstrained + maxval;
                if mb < best_maxbucket {
                    best_maxbucket = mb;
                    best_off = o;
                }
            }
            // Report the worst-case post-discrimination group size as "coverage".
            rows.push((anchor_len, gsize, h, fanout, best_off, best_maxbucket));
        }
        rows.sort_by_key(|r| std::cmp::Reverse(r.3));
        rows.truncate(20);
        rows
    }

    /// As [`scan`], with PE layout for resolving `EP`/section-relative offsets.
    /// Logical-sig indices to evaluate for a scan: those owning a matched subsig
    /// body (`touched`) plus the always-check `fires_empty` set. Sorted+deduped,
    /// so iterating the result preserves the first-match-by-index semantics of
    /// scanning every ldb in order — while skipping the ~all that can't fire.
    /// The scanned object's 64-bit image perceptual hash, computed once per scan
    /// and only when a `fuzzy_img#` subsig is loaded and the bytes look like an
    /// image (so non-image scans pay nothing). Used by `SubSig::Fuzzy`.
    fn maybe_img_hash(&self, buf: &[u8]) -> Option<[u8; 8]> {
        if self.has_fuzzy && crate::fuzzy_img::looks_like_image(buf) {
            crate::fuzzy_img::phash(buf)
        } else {
            None
        }
    }

    /// Logical sigs worth evaluating for this scan: those whose subsig bodies
    /// matched, plus the always-on `fires_empty` set, plus — when the object is
    /// an image (`include_fuzzy`) — the `fuzzy_img#` sigs (which have no body to
    /// touch them).
    fn candidate_ldbs(&self, touched: &[usize], include_fuzzy: bool) -> Vec<u32> {
        let mut cand: Vec<u32> =
            Vec::with_capacity(touched.len() + self.fires_empty.len() + self.fuzzy_ldbs.len());
        for &b in touched {
            let l = self.body_ldb[b];
            if l != u32::MAX {
                cand.push(l);
            }
        }
        cand.extend_from_slice(&self.fires_empty);
        if include_fuzzy {
            cand.extend_from_slice(&self.fuzzy_ldbs);
        }
        cand.sort_unstable();
        cand.dedup();
        cand
    }

    pub fn scan_with_layout(
        &self,
        buf: &[u8],
        ft: FileType,
        layout: Option<&PeLayout>,
        container: Option<ClType>,
    ) -> Option<(String, u64, bool)> {
        self.scan_with_icons(buf, ft, layout, container, None)
    }

    /// As [`Self::scan_with_layout`] but with a per-scan icon-matching context
    /// so `IconGroup1/2`-constrained logical signatures can be evaluated.
    /// Returns `(clean_name, offset, unofficial)`.
    pub fn scan_with_icons(
        &self,
        buf: &[u8],
        ft: FileType,
        layout: Option<&PeLayout>,
        container: Option<ClType>,
        icon_ctx: Option<&IconCtx>,
    ) -> Option<(String, u64, bool)> {
        // Per-LDB-subsig match counts; only allocated when there are logical
        // signatures (otherwise no LdbSub body exists and counts is unused).
        let mut sc = Scratch::acquire(if self.ldbs.is_empty() {
            0
        } else {
            self.bodies.len()
        });
        let counts = &mut sc.counts;
        let offs = &mut sc.offs;
        let touched = &mut sc.touched;

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
                let group = &groups[m.value() as usize];
                for &bid in group {
                    // Compact target prefilter: reject type-mismatched bodies
                    // from L2 cache before the random miss into `bodies`.
                    if !target_ok(self.targets[bid], ft) {
                        continue;
                    }
                    let body = &self.bodies[bid];
                    if let Some(start) = verify(body, buf, m.start(), layout) {
                        match &body.owner {
                            Owner::Ndb { name, unofficial } => {
                                return Some((name.clone(), start, *unofficial))
                            }
                            // counts is non-empty whenever LdbSub bodies exist.
                            Owner::LdbSub => {
                                if counts[bid] == 0 {
                                    touched.push(bid);
                                }
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

        // If no subsignature matched, only logical sigs that fire on an empty
        // count vector (vanishingly rare) can hit — skip the rest entirely.
        let body_off = |b: usize| -> Option<u32> {
            match offs[b] {
                u32::MAX => None,
                o => Some(o),
            }
        };
        let img_hash = self.maybe_img_hash(buf);
        for li in self.candidate_ldbs(&touched[..], img_hash.is_some()) {
            let ldb = &self.ldbs[li as usize];
            if !target_ok(ldb.target, ft) || !ldb.size_ok(buf.len()) || !ldb.container_ok(container)
            {
                continue;
            }
            if ldb.eval(buf, &|b| counts[b], &body_off, img_hash, icon_ctx) {
                return Some((ldb.name.clone(), 0, ldb.unofficial));
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
        container: Option<ClType>,
        out: &mut Vec<(String, u64, bool)>,
    ) {
        self.scan_all_with_icons(buf, ft, layout, container, None, out)
    }

    /// As [`Self::scan_all_with_layout`] with an icon-matching context. Each
    /// pushed tuple is `(clean_name, offset, unofficial)`.
    pub fn scan_all_with_icons(
        &self,
        buf: &[u8],
        ft: FileType,
        layout: Option<&PeLayout>,
        container: Option<ClType>,
        icon_ctx: Option<&IconCtx>,
        out: &mut Vec<(String, u64, bool)>,
    ) {
        let mut sc = Scratch::acquire(if self.ldbs.is_empty() {
            0
        } else {
            self.bodies.len()
        });
        let counts = &mut sc.counts;
        let offs = &mut sc.offs;
        let touched = &mut sc.touched;
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
                    if !target_ok(self.targets[bid], ft) {
                        continue;
                    }
                    let body = &self.bodies[bid];
                    if let Some(start) = verify(body, buf, m.start(), layout) {
                        match &body.owner {
                            Owner::Ndb { name, unofficial } => {
                                if seen.insert(name.clone()) {
                                    out.push((name.clone(), start, *unofficial));
                                }
                            }
                            Owner::LdbSub => {
                                if counts[bid] == 0 {
                                    touched.push(bid);
                                }
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
        let img_hash = self.maybe_img_hash(buf);
        for li in self.candidate_ldbs(&touched[..], img_hash.is_some()) {
            let ldb = &self.ldbs[li as usize];
            if !target_ok(ldb.target, ft) || !ldb.size_ok(buf.len()) || !ldb.container_ok(container)
            {
                continue;
            }
            if ldb.eval(buf, &|b| counts[b], &body_off, img_hash, icon_ctx)
                && seen.insert(ldb.name.clone())
            {
                out.push((ldb.name.clone(), 0, ldb.unofficial));
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
        container: Option<ClType>,
        out: &mut Vec<(String, Vec<u32>)>,
    ) {
        if self.ldbs.is_empty() {
            return;
        }
        let mut sc = Scratch::acquire(self.bodies.len());
        let counts = &mut sc.counts;
        let offs = &mut sc.offs;
        let touched = &mut sc.touched;
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
                    if !target_ok(self.targets[bid], ft) {
                        continue;
                    }
                    let body = &self.bodies[bid];
                    if let Some(start) = verify(body, buf, m.start(), layout) {
                        if let Owner::LdbSub = &body.owner {
                            if counts[bid] == 0 {
                                touched.push(bid);
                            }
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
        let img_hash = self.maybe_img_hash(buf);
        for li in self.candidate_ldbs(&touched[..], img_hash.is_some()) {
            let ldb = &self.ldbs[li as usize];
            if !target_ok(ldb.target, ft) || !ldb.size_ok(buf.len()) || !ldb.container_ok(container)
            {
                continue;
            }
            if ldb.eval(buf, &|b| counts[b], &body_off, img_hash, None) {
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
        // HTML(3): apply only to content typed as HTML (or RTF, which can carry
        // HTML-ish exploit markup) — NOT every text-ish/unknown buffer, or an
        // HTML-exploit sig false-positives on plain JavaScript (observed:
        // `Html.Exploit.CVE_2017_11861` firing on obfuscated npm JS that contains
        // `Uint32Array(0x..)`).
        3 => matches!(ft, FileType::Html | FileType::Rtf),
        // mail(4)/text(7): apply to text-ish types (incl. the content-detected
        // `Text`), NOT binary `Unknown` — ClamAV types text vs binary and runs
        // text sigs only on text. `Target:0` still covers everything.
        4 | 7 => matches!(
            ft,
            FileType::Text | FileType::Rtf | FileType::Script | FileType::Email | FileType::Html
        ),
        // graphics(5)/flash(11)/Java(12)/internal(13)/other(14)/...: exav can't
        // positively identify these content types, so running a target-N sig
        // would false-positive on unrelated content (observed: a Java CVE sig
        // firing on apk/zip members). Skip until those types are modelled.
        _ => false,
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
    // Fresh per-call backtracking budget: bounds this one pattern's gap/alt
    // backtracking (like a regex step limit). It is not shared across the scan,
    // so a benign file with many cheap verifies is never penalised.
    let mut budget = VERIFY_BUDGET;
    let filelen = buf.len() as u64;
    let off_at = |start: usize| offset_ok(&body.offset, start as u64, filelen, layout);
    let result = match body.prefix {
        Prefix::Fixed { len, .. } => {
            if anchor_start < len {
                None
            } else {
                let start = anchor_start - len;
                // The pattern start is known up front, so apply the (cheap)
                // offset constraint BEFORE the expensive backtracking match.
                // Offset-pinned sigs (EP+0/Abs/Sec) whose only viable anchor is a
                // common run (e.g. a zero triple) hit thousands of times per file;
                // this rejects all but the ~one hit at the pinned position without
                // ever running `match_forward`. For `Offset::Any` the gate is a
                // constant `true`, so nothing is lost on the common case.
                if !off_at(start) {
                    None
                } else {
                    match_forward(elems, buf, start, body.nocase, &mut budget).then_some(start)
                }
            }
        }
        Prefix::Floating { anchor_idx } => {
            if !off_at(anchor_start) {
                None
            } else {
                match_forward(
                    &elems[anchor_idx..],
                    buf,
                    anchor_start,
                    body.nocase,
                    &mut budget,
                )
                .then_some(anchor_start)
            }
        }
        // Anchor sits past variable gaps: confirm the suffix forward from the
        // anchor, then the prefix backward across the gaps to the pattern start.
        // The start is only known after backward matching, so the offset gate
        // runs last (these are `Offset::Any`-only, so it is a no-op anyway).
        Prefix::Internal { anchor_idx } => {
            if match_forward(
                &elems[anchor_idx..],
                buf,
                anchor_start,
                body.nocase,
                &mut budget,
            ) {
                match_backward(
                    &elems[..anchor_idx],
                    buf,
                    anchor_start,
                    body.nocase,
                    &mut budget,
                )
                .filter(|&start| off_at(start))
            } else {
                None
            }
        }
    };
    let _ = budget; // per-call budget; nothing shared to write back
    result.map(|start| start as u64)
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
            if *min > hi {
                return false;
            }
            // Fast path: a gap followed by a literal. Instead of testing every
            // gap length byte-by-byte (O(gap), and budget-burning when the
            // literal is absent — the dominant cost on type-matched fan-out),
            // SIMD-search for each occurrence of that literal within the gap
            // window and recurse only there. Case-sensitive only (memmem can't
            // fold case); the `nocase` path keeps the scalar fallback.
            if !nocase {
                if let Some((Elem::Bytes(lit), tail)) = rest.split_first() {
                    if !lit.is_empty() {
                        let lo = pos + *min;
                        let last_start = pos + hi; // literal may start up to here
                        if lo > last_start || lo >= buf.len() {
                            return false;
                        }
                        let end = (last_start + lit.len()).min(buf.len());
                        // Greedy fast path for an UNBOUNDED gap (`*`) whose
                        // literal is itself followed by another unbounded gap (or
                        // the pattern end): the first occurrence is optimal, so no
                        // backtracking over occurrences is needed. This collapses
                        // the combinatorial blow-up of `lit*lit*lit…` chains
                        // (polymorphic-malware sigs) from exponential to linear,
                        // with identical results — if the tail can't match after
                        // the first occurrence, a later occurrence (further right,
                        // less room) can't either.
                        let greedy = max.is_none()
                            && matches!(tail.first(), None | Some(Elem::Gap { max: None, .. }));
                        if greedy {
                            return match memchr::memmem::find(&buf[lo..end], lit) {
                                Some(off) => {
                                    *budget = budget.saturating_sub(1);
                                    match_forward(tail, buf, lo + off + lit.len(), nocase, budget)
                                }
                                None => false,
                            };
                        }
                        for off in memchr::memmem::find_iter(&buf[lo..end], lit) {
                            if *budget == 0 {
                                return false;
                            }
                            *budget -= 1;
                            if match_forward(tail, buf, lo + off + lit.len(), nocase, budget) {
                                return true;
                            }
                        }
                        return false;
                    }
                }
            }
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

/// Match a token program *backward* so it ends exactly at `end`, returning the
/// start position (where the first token begins). The mirror of [`match_forward`]
/// for verifying an [`Prefix::Internal`] anchor's preceding context across
/// variable gaps. `budget` bounds backtracking work. Only reached on the rare,
/// selective internal anchors, so it keeps the simple scalar gap loop (no SIMD
/// fast path) — clarity over a micro-optimization that never runs hot.
fn match_backward(
    toks: &[Elem],
    buf: &[u8],
    end: usize,
    nocase: bool,
    budget: &mut u64,
) -> Option<usize> {
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    let (last, rest) = match toks.split_last() {
        None => return Some(end), // no preceding context: pattern starts at `end`
        Some(x) => x,
    };
    match last {
        Elem::Bytes(b) => {
            if end < b.len() || !bytes_eq(&buf[end - b.len()..end], b, nocase) {
                return None;
            }
            match_backward(rest, buf, end - b.len(), nocase, budget)
        }
        Elem::AnyByte => {
            if end == 0 {
                return None;
            }
            match_backward(rest, buf, end - 1, nocase, budget)
        }
        Elem::HiNibble(h) => {
            if end == 0 || buf[end - 1] >> 4 != *h {
                return None;
            }
            match_backward(rest, buf, end - 1, nocase, budget)
        }
        Elem::LoNibble(l) => {
            if end == 0 || buf[end - 1] & 0x0f != *l {
                return None;
            }
            match_backward(rest, buf, end - 1, nocase, budget)
        }
        Elem::Gap { min, max } => {
            let hi = max.unwrap_or(end).min(end);
            if *min > hi {
                return None;
            }
            for g in *min..=hi {
                if let Some(s) = match_backward(rest, buf, end - g, nocase, budget) {
                    return Some(s);
                }
                if *budget == 0 {
                    return None;
                }
            }
            None
        }
        Elem::Alt { opts, neg } => {
            if *neg {
                let l = opts.first().map(|o| o.len()).unwrap_or(0);
                if l == 0 || end < l {
                    return None;
                }
                let cur = &buf[end - l..end];
                if opts.iter().any(|o| bytes_eq(o, cur, nocase)) {
                    return None;
                }
                match_backward(rest, buf, end - l, nocase, budget)
            } else {
                for o in opts {
                    if end >= o.len() && bytes_eq(&buf[end - o.len()..end], o, nocase) {
                        if let Some(s) = match_backward(rest, buf, end - o.len(), nocase, budget) {
                            return Some(s);
                        }
                    }
                    if *budget == 0 {
                        return None;
                    }
                }
                None
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
    Fuzzy([u8; 8]),
}

/// Classify and parse one subsignature: byte-compare (`N(..#..#..)`), PCRE
/// (`Trigger/regex/flags`), or a normal hex/pattern body.
fn classify_subsig(s: &str) -> Option<ParsedSub> {
    if let Some(rest) = s.strip_prefix("fuzzy_img#") {
        return parse_fuzzy_subsig(rest).map(ParsedSub::Fuzzy);
    }
    if let Some(b) = parse_bcomp_subsig(s) {
        return Some(ParsedSub::Bcomp(b));
    }
    if s.contains('/') {
        return parse_pcre_subsig(s).map(ParsedSub::Pcre);
    }
    parse_subsig(s).map(ParsedSub::Bodies)
}

/// Parse the body of a `fuzzy_img#<16-hex>[#<distance>]` subsignature (the
/// `fuzzy_img#` prefix already stripped). Returns the 8-byte hash. Only Hamming
/// distance 0 is supported by the current signature format, so a non-zero
/// `#distance` suffix makes the subsig unsupported (dropped).
fn parse_fuzzy_subsig(rest: &str) -> Option<[u8; 8]> {
    let mut parts = rest.split('#');
    let hash = parts.next()?;
    if let Some(dist) = parts.next() {
        if dist.trim().parse::<u32>().ok()? != 0 {
            return None;
        }
    }
    if parts.next().is_some() || hash.len() != 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
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
        fancy: std::sync::OnceLock::new(),
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

    let allow_internal = matches!(offset, Offset::Any);
    let mut out = Vec::new();
    if ascii {
        let (e, a, p) = compile_body(body, allow_internal)?;
        out.push((e, a, p, nocase, offset.clone()));
    }
    if wide {
        match compile_wide(body, allow_internal) {
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
fn compile_wide(body: &str, allow_internal: bool) -> Option<(Vec<Elem>, Vec<u8>, Prefix)> {
    let elems = widen_elems(parse_elems(body)?);
    let prefix = pick_anchor(&elems, allow_internal)?;
    let anchor_idx = match prefix {
        Prefix::Fixed { anchor_idx, .. }
        | Prefix::Floating { anchor_idx }
        | Prefix::Internal { anchor_idx } => anchor_idx,
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
fn compile_body(hex: &str, allow_internal: bool) -> Option<(Vec<Elem>, Vec<u8>, Prefix)> {
    let elems = parse_elems(hex)?;
    let prefix = pick_anchor(&elems, allow_internal)?;
    let anchor_idx = match prefix {
        Prefix::Fixed { anchor_idx, .. }
        | Prefix::Floating { anchor_idx }
        | Prefix::Internal { anchor_idx } => anchor_idx,
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
/// Selectivity score of a candidate anchor run. A low-entropy run (a constant
/// byte like a zero/0xFF pad, or a 2-symbol repeat) matches repetitive content
/// — PE padding, BSS — millions of times, so it is a terrible prefilter even
/// when long. Down-rank such runs sharply so a shorter but varied run wins; a
/// genuinely varied run scores its length (longer = rarer = better).
fn anchor_score(b: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &x in b {
        if !seen[x as usize] {
            seen[x as usize] = true;
            distinct += 1;
        }
    }
    match distinct {
        0 | 1 => 1,          // constant run: near-useless anchor
        2 => 3.min(b.len()), // 2-symbol repeat (e.g. ababab): weak
        _ => b.len(),        // varied: length is the selectivity
    }
}

fn pick_anchor(elems: &[Elem], allow_internal: bool) -> Option<Prefix> {
    // Pick the most *selective* literal run as the Aho-Corasick anchor (highest
    // [`anchor_score`], tie-break longer), not merely the longest: a long
    // constant run is a far worse prefilter than a shorter varied one. Fewer
    // spurious AC hits → fewer verifies, the dominant scan cost.
    //
    // The anchor in the *fixed-width prefix* (before the first variable gap) is
    // free to verify — its distance back to the pattern start (`len`) is exact.
    // But some patterns have only a useless literal there (a zero-run) while a
    // rare literal sits past a gap. For those, anchoring past the gap (`Internal`)
    // and verifying backward across it slashes AC hits by orders of magnitude.
    // We only take an internal anchor when it is *strictly more selective* than
    // the best fixed-prefix one and the pattern offset is `*` (so the floating
    // start need not satisfy a fixed offset) — passed via `allow_internal`.
    let mut fixed = 0usize;
    let mut in_fixed_prefix = true;
    // (score, len, prefix) for the best fixed-prefix candidate and the best
    // candidate anywhere.
    let mut best_fixed: Option<(usize, usize, Prefix)> = None;
    let mut best_any: Option<(usize, usize, usize)> = None; // (score, len, idx)
    for (i, e) in elems.iter().enumerate() {
        if let Elem::Bytes(b) = e {
            if b.len() >= MIN_ANCHOR {
                let score = anchor_score(b);
                let better = |cur: &Option<(usize, usize, Prefix)>| match cur {
                    Some((s, l, _)) => score > *s || (score == *s && b.len() > *l),
                    None => true,
                };
                if in_fixed_prefix && better(&best_fixed) {
                    best_fixed = Some((
                        score,
                        b.len(),
                        Prefix::Fixed {
                            anchor_idx: i,
                            len: fixed,
                        },
                    ));
                }
                let any_better = match &best_any {
                    Some((s, l, _)) => score > *s || (score == *s && b.len() > *l),
                    None => true,
                };
                if any_better {
                    best_any = Some((score, b.len(), i));
                }
            }
        }
        match e.width() {
            Some(w) => fixed += w,
            None => in_fixed_prefix = false, // past the first variable element
        }
    }
    // Prefer an internal anchor only when it beats the fixed-prefix one.
    if allow_internal {
        if let Some((any_score, _, idx)) = best_any {
            let fixed_score = best_fixed.as_ref().map(|(s, ..)| *s).unwrap_or(0);
            if any_score > fixed_score {
                // A single leading gap is the cheap `Floating` fast path, not the
                // general backward-matching `Internal`.
                if idx == 1 && matches!(elems.first(), Some(Elem::Gap { .. })) {
                    return Some(Prefix::Floating { anchor_idx: 1 });
                }
                if idx > 0 {
                    return Some(Prefix::Internal { anchor_idx: idx });
                }
            }
        }
    }
    if let Some((.., p)) = best_fixed {
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

/// A PUA (Potentially Unwanted Application) signature name. ClamAV gates these
/// behind `DetectPUA` (off by default); exav skips them to match that default.
fn is_pua(name: &str) -> bool {
    name.starts_with("PUA.")
}

/// exav's reported ClamAV functionality level. Signatures carry an engine
/// `min-max` flevel window (LDB `Engine:` TDB, or trailing `:min:max` fields on
/// `.ndb` lines); ClamAV loads a sig only when its flevel falls in that window.
/// We mirror that with the flevel of the ClamAV release whose databases we read
/// (1.4.x ⇒ 213), so we load exactly the sigs ClamAV would — skipping ones meant
/// for a newer engine (features we may lack) and, importantly, *deprecated* ones
/// (`max < 213`) that ClamAV no longer runs, which would otherwise false-positive.
const EXAV_FLEVEL: u32 = 213;

/// Whether `EXAV_FLEVEL` falls within a sig's `[min, max]` engine window.
fn flevel_ok(min: u32, max: u32) -> bool {
    EXAV_FLEVEL >= min && EXAV_FLEVEL <= max
}

/// Parse an LDB `Engine:min-max` TDB attribute into `(min, max)`; absent or
/// unparseable ⇒ `(0, u32::MAX)` (no constraint).
fn parse_tdb_engine(tdb: &str) -> (u32, u32) {
    for field in tdb.split(',') {
        if let Some(v) = field.trim().strip_prefix("Engine:") {
            if let Some((a, b)) = v.trim().split_once('-') {
                return (
                    a.trim().parse().unwrap_or(0),
                    b.trim().parse().unwrap_or(u32::MAX),
                );
            }
        }
    }
    (0, u32::MAX)
}

fn parse_tdb_target(tdb: &str) -> u8 {
    for field in tdb.split(',') {
        if let Some(v) = field.trim().strip_prefix("Target:") {
            return v.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Parse a `FileSize:min-max` TDB attribute into an inclusive `(min, max)`
/// range. Accepts `n` (exact), `n-m`, `n-` (min only), and `-m` (max only).
/// Returns `None` if absent or unparseable (treated as "no constraint").
fn parse_tdb_filesize(tdb: &str) -> Option<(u64, u64)> {
    for field in tdb.split(',') {
        if let Some(v) = field.trim().strip_prefix("FileSize:") {
            let v = v.trim();
            return match v.split_once('-') {
                Some((a, b)) => {
                    let min = a.trim().parse().unwrap_or(0);
                    let max = b.trim().parse().unwrap_or(u64::MAX);
                    Some((min, max))
                }
                None => v.parse().ok().map(|n| (n, n)),
            };
        }
    }
    None
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
        b.add_ndb(line, false);
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
    fn text_target_scoped_to_text_not_binary() {
        // A text-target (7) signature runs on `Text` content but NOT on a PE
        // (false positive) nor on binary `Unknown` — ClamAV types text vs binary.
        let e = ndb("X:7:*:68656c6c6f"); // "hello"
        assert!(e.scan(b"hello", FileType::Text).is_some());
        assert!(e.scan(b"hello", FileType::Pe).is_none());
        assert!(e.scan(b"hello", FileType::Unknown).is_none());
        // A PE-target (1) signature still works on a PE.
        let pe = ndb("X:1:*:cafebabe");
        assert!(pe.scan(&hx("cafebabe"), FileType::Pe).is_some());
    }

    #[test]
    fn wildcard_only_is_unsupported() {
        let mut b = EngineBuilder::new();
        b.add_ndb("S:0:*:??", false); // no usable anchor
        assert_eq!(b.unsupported(), 1);
    }

    #[test]
    fn logical_signature() {
        let mut b = EngineBuilder::new();
        b.add_ldb("Demo.Both;Target:0;0&1;deadbeef;cafebabe", false);
        let e = b.build();
        assert!(e
            .scan(&hx("00 deadbeef 00 cafebabe 00"), FileType::Unknown)
            .is_some());
        assert!(e.scan(&hx("00 deadbeef 00"), FileType::Unknown).is_none());
        assert!(e.scan(&hx("00 cafebabe 00"), FileType::Unknown).is_none());
    }

    #[test]
    fn scratch_is_reset_between_scans() {
        // Reusing the thread-local LDB scratch must not let one scan's subsig
        // matches leak into the next. `0&1` requires BOTH subsigs in one object.
        let mut b = EngineBuilder::new();
        b.add_ldb("Demo.AndTwo;Target:0;0&1;deadbeef;cafebabe", false);
        let e = b.build();
        // First scan matches subsig 0 only (touches its count).
        assert!(e.scan(&hx("00 deadbeef 00"), FileType::Unknown).is_none());
        // Second scan matches subsig 1 only; if subsig 0's count leaked from the
        // first scan, the AND would falsely fire. It must stay clean → None.
        assert!(e.scan(&hx("00 cafebabe 00"), FileType::Unknown).is_none());
        // Both together still detect, proving the sig is otherwise live.
        assert!(e
            .scan(&hx("00 deadbeef cafebabe 00"), FileType::Unknown)
            .is_some());
    }

    #[test]
    fn gap_then_literal_backtracks_to_later_occurrence() {
        // aabb{0-20}ccdd??ff: anchor is "aabb"; after the gap the literal "ccdd"
        // appears twice — the first is NOT followed by `..ff`, the second is.
        // The memmem fast path must try BOTH occurrences (not just the first).
        let mut b = EngineBuilder::new();
        b.add_ndb("S.Multi:0:*:aabb{0-20}ccdd??ff", false);
        let e = b.build();
        // AA BB 99 | CC DD 00 11 (ccdd, ?=00, then 11≠ff) | CC DD 00 FF (match)
        assert!(e
            .scan(&hx("aabb 99 ccdd 0011 ccdd 00ff"), FileType::Unknown)
            .is_some());
        // Only the failing first occurrence present → no match.
        assert!(e
            .scan(&hx("aabb 99 ccdd 0011 ccdd 0011"), FileType::Unknown)
            .is_none());
    }

    #[test]
    fn star_chain_greedy_matches_correctly() {
        // `aa*bb*cc` (unbounded gaps): greedy first-occurrence must still find
        // the match, and must respect ordering (cc after bb after aa).
        let mut b = EngineBuilder::new();
        b.add_ndb("S.Chain:0:*:aabbccdd*1122*3344", false);
        let e = b.build();
        // aabbccdd ... 1122 ... 3344  → matches.
        assert!(e
            .scan(&hx("aabbccdd 99 1122 99 3344"), FileType::Unknown)
            .is_some());
        // 3344 present but BEFORE 1122 → ordering fails → no match.
        assert!(e
            .scan(&hx("aabbccdd 99 3344 99 1122"), FileType::Unknown)
            .is_none());
        // 3344 missing → no match.
        assert!(e
            .scan(&hx("aabbccdd 99 1122 99 5566"), FileType::Unknown)
            .is_none());
        // A second 1122 occurrence: greedy takes the first; 3344 after it → match.
        assert!(e
            .scan(&hx("aabbccdd 1122 00 1122 3344"), FileType::Unknown)
            .is_some());
    }

    #[test]
    fn gap_max_bound_excludes_far_literal() {
        // aabb{0-3}ccdd: the literal sits beyond the gap's max distance → no
        // match (the memmem window must respect `max`).
        let mut b = EngineBuilder::new();
        b.add_ndb("S.Bound:0:*:aabb{0-3}ccdd", false);
        let e = b.build();
        assert!(e.scan(&hx("aabb 00 ccdd"), FileType::Unknown).is_some()); // gap 1
                                                                           // 6-byte gap > max 3 → must NOT match.
        assert!(e
            .scan(&hx("aabb 0011223344 55 ccdd"), FileType::Unknown)
            .is_none());
    }

    #[test]
    fn ndb_flevel_suffix_parsed_and_enforced() {
        // A trailing `:minFL` must be split off the hex body (not folded in) and
        // enforced. In-range loads; out-of-range (future engine) is skipped.
        let mut b = EngineBuilder::new();
        b.add_ndb("In.Range:0:*:deadbeef:74", false); // min 74 <= 213
        b.add_ndb("Future.Sig:0:*:cafebabe:9999", false); // min 9999 > 213 -> skip
        let e = b.build();
        assert!(e.scan(&hx("00 deadbeef 00"), FileType::Unknown).is_some());
        assert!(e.scan(&hx("00 cafebabe 00"), FileType::Unknown).is_none());
    }

    #[test]
    fn pua_off_by_default_on_with_flag() {
        // Default: PUA.* signatures are dropped.
        let mut b = EngineBuilder::new();
        b.add_ndb("PUA.Win.Tool.Demo:0:*:deadbeef", false);
        let e = b.build();
        assert!(e.scan(&hx("00 deadbeef 00"), FileType::Unknown).is_none());
        // With detect_pua: loaded and detected.
        let mut b2 = EngineBuilder::new();
        b2.set_detect_pua(true);
        b2.add_ndb("PUA.Win.Tool.Demo:0:*:deadbeef", false);
        let e2 = b2.build();
        assert!(e2.scan(&hx("00 deadbeef 00"), FileType::Unknown).is_some());
    }

    #[test]
    fn pcre_backreference_via_fancy_regex() {
        // A PCRE subsig using a backreference: the linear `regex` engine can't
        // compile it, so the trigger-gated fancy-regex fallback (latin-1 byte
        // mapping) handles it — over BINARY content, not just text.
        let mut b = EngineBuilder::new();
        assert!(b.add_ldb_line("Test.Backref;Target:0;0&1;4141;0/(.)\\1\\1/", false));
        let e = b.build();
        // Binary buffer (has a NUL + high bytes) containing "AAA": both the
        // anchor "AA" and the triple-backref `(.)\1\1` match via the byte mapping.
        assert!(e.scan(b"\x00\xffAAA\x80", FileType::Unknown).is_some());
        // "AAB": anchor matches but the triple-backref does not.
        assert!(e.scan(b"\x00\xffAAB\x80", FileType::Unknown).is_none());
    }

    #[test]
    fn pcre_backtracking_is_bounded() {
        // A classic catastrophic-backtracking pattern (nested quantifier +
        // backreference, forcing the fancy-regex path) on adversarial all-`a`
        // input must NOT hang: the backtrack limit bounds it and `is_match`
        // returns no-match quickly.
        let mut b = EngineBuilder::new();
        assert!(b.add_ldb_line("Test.Redos;Target:0;0&1;6161;0/(a+)+\\1c/", false));
        let e = b.build();
        let adversarial = vec![b'a'; 100]; // 100 'a's, no trailing 'c'
        let start = std::time::Instant::now();
        let hit = e.scan(&adversarial, FileType::Unknown);
        let elapsed = start.elapsed();
        assert!(hit.is_none());
        assert!(
            elapsed.as_secs() < 3,
            "backtracking must be bounded, took {elapsed:?}"
        );
    }

    #[test]
    fn ldb_engine_window_enforced() {
        let mut b = EngineBuilder::new();
        // Engine:0-50 is deprecated for flevel 213 -> must be skipped.
        assert!(!b.add_ldb_line("Old.Sig;Engine:0-50,Target:0;0;deadbeef", false));
        // Engine:90-255 includes 213 -> loads.
        assert!(b.add_ldb_line("Cur.Sig;Engine:90-255,Target:0;0;deadbeef", false));
    }

    #[test]
    fn internal_anchor_across_gap() {
        // The only pre-gap literal run >=2 is the constant zero triple `000000`
        // (anchor_score 1, matches everywhere); the rare varied run `8606` sits
        // *after* a `{0-8}` gap. `pick_anchor` must choose `8606` as an Internal
        // anchor and verify the `e8 ?? 000000 {gap}` prefix backward.
        let mut b = EngineBuilder::new();
        b.add_ndb("V:0:*:e8??000000{0-8}8606", false);
        let e = b.build();
        // e8 7a 000000 | 99 (1-byte gap) | 8606  → full pattern present.
        assert!(e
            .scan(&hx("e8 7a 000000 99 8606"), FileType::Unknown)
            .is_some());
        // The rare anchor `8606` present but the backward `e8 ?? 000000` context
        // is absent → must NOT match (backward verify rejects).
        assert!(e
            .scan(&hx("11 22 334455 99 8606"), FileType::Unknown)
            .is_none());
        // Anchor present, prefix present, but the gap (10 bytes) exceeds max 8 →
        // backward gap bound must reject.
        assert!(e
            .scan(
                &hx("e8 7a 000000 00112233445566778899 8606"),
                FileType::Unknown
            )
            .is_none());
        // A buffer full of zero triples (what made the old anchor explode) but no
        // `8606` → the selective internal anchor never fires → no match, no work.
        assert!(e
            .scan(&hx("000000 000000 000000 000000 000000"), FileType::Unknown)
            .is_none());
    }

    #[test]
    fn internal_anchor_offset_constrained_falls_back() {
        // With a non-`*` offset the floating start must satisfy the offset, so
        // Internal anchoring is disallowed — the engine must still detect using
        // the fixed-prefix (zero-run) anchor, just without the selectivity win.
        let mut b = EngineBuilder::new();
        b.add_ndb("VO:0:0:e8??000000{0-8}8606", false);
        let e = b.build();
        // Pattern at offset 0 → matches.
        assert!(e
            .scan(&hx("e8 7a 000000 99 8606"), FileType::Unknown)
            .is_some());
        // Same pattern at offset 1 → offset-0 constraint rejects.
        assert!(e
            .scan(&hx("00 e8 7a 000000 99 8606"), FileType::Unknown)
            .is_none());
    }

    #[test]
    fn filesize_tdb_constraint() {
        let mut b = EngineBuilder::new();
        // The object must be 5..=6 bytes for this logical sig to fire.
        b.add_ldb("Demo.Size;Target:0,FileSize:5-6;0;deadbeef", false);
        let e = b.build();
        // 6-byte object containing the pattern → within range → matches.
        assert!(e.scan(&hx("00 deadbeef 00"), FileType::Unknown).is_some());
        // 7-byte object → outside range → suppressed despite the pattern match.
        assert!(e
            .scan(&hx("00 deadbeef 00 00"), FileType::Unknown)
            .is_none());
    }

    #[test]
    fn ldb_fuzzy_img_subsig() {
        // A solid (non-black) image hashes to 8000000000000000 (spec anchor).
        let png = {
            let img = image::RgbImage::from_pixel(48, 48, image::Rgb([200, 30, 30]));
            let mut out = std::io::Cursor::new(Vec::new());
            image::DynamicImage::ImageRgb8(img)
                .write_to(&mut out, image::ImageFormat::Png)
                .unwrap();
            out.into_inner()
        };
        let mut b = EngineBuilder::new();
        b.add_ldb(
            "Demo.FuzzyImg;Engine:150-255,Target:0;0;fuzzy_img#8000000000000000",
            false,
        );
        let e = b.build();
        // Matches the image with the right hash (a fuzzy-only sig has no AC body,
        // so this also exercises the image-input candidate path).
        assert!(e.scan(&png, FileType::Unknown).is_some());
        // A different hash must not match.
        let mut b2 = EngineBuilder::new();
        b2.add_ldb(
            "Demo.FuzzyImg2;Engine:150-255,Target:0;0;fuzzy_img#deadbeefdeadbeef",
            false,
        );
        assert!(b2.build().scan(&png, FileType::Unknown).is_none());
        // Non-image input never matches a fuzzy sig (and pays no hashing cost).
        assert!(e
            .scan(b"plain text, not an image", FileType::Unknown)
            .is_none());
        // Non-zero hamming distance is unsupported ⇒ subsig dropped ⇒ no match.
        let mut b3 = EngineBuilder::new();
        b3.add_ldb(
            "Demo.FuzzyDist;Engine:150-255,Target:0;0;fuzzy_img#8000000000000000#5",
            false,
        );
        assert!(b3.build().scan(&png, FileType::Unknown).is_none());
    }

    #[test]
    fn ldb_container_constraint_enforced() {
        let mut b = EngineBuilder::new();
        b.add_ldb(
            "Demo.Contained;Engine:80-255,Container:CL_TYPE_OOXML_WORD,Target:0;0;deadbeef",
            false,
        );
        let e = b.build();
        let buf = hx("00 deadbeef 00");
        // Top level (no container) -> a Container-scoped sig must NOT fire.
        assert!(e.scan(&buf, FileType::Unknown).is_none());
        // Inside the wrong container -> no fire.
        assert!(e
            .scan_with_layout(&buf, FileType::Unknown, None, Some(ClType::Zip))
            .is_none());
        // Inside the right container -> fires.
        assert!(e
            .scan_with_layout(&buf, FileType::Unknown, None, Some(ClType::OoxmlWord))
            .is_some());
        // An unconstrained sig fires regardless of container context.
        let mut b2 = EngineBuilder::new();
        b2.add_ldb("Demo.Free;Target:0;0;deadbeef", false);
        assert!(b2.build().scan(&buf, FileType::Unknown).is_some());
        // An unmodeled / CL_TYPE_ANY container token is left unenforced (fires
        // at top level like an unconstrained sig).
        let mut b3 = EngineBuilder::new();
        b3.add_ldb("Demo.Any;Container:CL_TYPE_ANY,Target:0;0;deadbeef", false);
        assert!(b3.build().scan(&buf, FileType::Unknown).is_some());
    }

    #[test]
    fn logical_or_and_counts() {
        let mut b = EngineBuilder::new();
        b.add_ldb("Demo.Or;Target:0;0|1;aaaaaa;bbbbbb", false);
        let e = b.build();
        assert!(e.scan(&hx("00 aaaaaa 00"), FileType::Unknown).is_some());

        let mut b2 = EngineBuilder::new();
        b2.add_ldb("Demo.Count;Target:0;0=2;abcd", false);
        let e2 = b2.build();
        assert!(e2.scan(&hx("abcd 5f abcd"), FileType::Unknown).is_some()); // exactly 2
        assert!(e2.scan(&hx("abcd"), FileType::Unknown).is_none()); // only 1
    }

    #[test]
    fn ldb_subsig_modifiers() {
        // "malware" = 6d 61 6c 77 61 72 65 ; "MALWARE" = 4d 41 4c 57 41 52 45
        // `::i` (nocase) matches the uppercase bytes; without it, it doesn't.
        let mut bi = EngineBuilder::new();
        bi.add_ldb("Demo.I;Target:0;0;6d616c77617265::i", false);
        assert!(bi
            .build()
            .scan(&hx("4d414c57415245"), FileType::Unknown)
            .is_some());
        let mut bn = EngineBuilder::new();
        bn.add_ldb("Demo.NoI;Target:0;0;6d616c77617265", false);
        assert!(bn
            .build()
            .scan(&hx("4d414c57415245"), FileType::Unknown)
            .is_none());

        // `::w` (wide) matches the UTF-16LE form (each byte + 00), not ASCII.
        let mut bw = EngineBuilder::new();
        bw.add_ldb("Demo.W;Target:0;0;6d616c77617265::w", false);
        let ew = bw.build();
        assert!(ew
            .scan(&hx("6d006100 6c007700 61007200 6500"), FileType::Unknown)
            .is_some());
        assert!(ew.scan(&hx("6d616c77617265"), FileType::Unknown).is_none());

        // `::aw` matches either ASCII or wide.
        let mut ba = EngineBuilder::new();
        ba.add_ldb("Demo.AW;Target:0;0;6d616c77617265::aw", false);
        let ea = ba.build();
        assert!(ea.scan(&hx("6d616c77617265"), FileType::Unknown).is_some());
        assert!(ea
            .scan(&hx("6d006100 6c007700 61007200 6500"), FileType::Unknown)
            .is_some());

        // wide with a `??` wildcard: "ma<any>l" -> m00 a00 <any>00 l00
        let mut bww = EngineBuilder::new();
        bww.add_ldb("Demo.WW;Target:0;0;6d61??6c::w", false);
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
        b.add_ldb(
            "Demo.Pcre;Engine:81-255,Target:0;0&1;6d616c77617265;0/payload[0-9]+/",
            false,
        );
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
        bi.add_ldb(
            "Demo.PcreI;Engine:81-255,Target:0;0&1;6d616c77617265;0/PAYLOAD/i",
            false,
        );
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
        b.add_ldb(
            "Demo.Bcomp;Engine:81-255,Target:0;0&1;414e43484f52;0(>>6#d4#=1234)",
            false,
        );
        assert_eq!(b.unsupported(), 0, "byte-compare subsig should load");
        let e = b.build();
        assert!(e.scan(b"ANCHOR1234tail", FileType::Unknown).is_some());
        // Same anchor, different value -> comparison fails.
        assert!(e.scan(b"ANCHOR9999tail", FileType::Unknown).is_none());

        // Raw little-endian binary compare: 2 bytes at the anchor start `> 0`.
        let mut br = EngineBuilder::new();
        br.add_ldb(
            "Demo.BcompRaw;Engine:81-255,Target:0;0&1;414e43484f52;0(>>6#il2#>0)",
            false,
        );
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
            .scan_with_layout(&buf, FileType::Pe, Some(&layout), None)
            .is_some());
        // Without layout the EP offset can't be resolved -> no match.
        assert!(e.scan(&buf, FileType::Pe).is_none());

        // S0+2: relative to section 0's file offset (0) + 2 = 2.
        let s = ndb("S:0:S0+2:cafebabe");
        assert!(s
            .scan_with_layout(&hx("0000 cafebabe"), FileType::Pe, Some(&layout), None)
            .is_some());
    }

    #[test]
    fn ldb_group_count() {
        // (0|1|2)>1: total matches across subsigs 0,1,2 must exceed 1.
        let mut b = EngineBuilder::new();
        b.add_ldb(
            "Demo.Grp;Target:0;(0|1|2)>1;deadbeef;cafebabe;0badf00d",
            false,
        );
        let e = b.build();
        assert!(e
            .scan(&hx("deadbeef cafebabe"), FileType::Unknown)
            .is_some());
        assert!(e.scan(&hx("deadbeef"), FileType::Unknown).is_none());

        // comma form (0|1|2)>1,2: total>1 AND >=2 distinct subsigs matched.
        let mut b2 = EngineBuilder::new();
        b2.add_ldb("Demo.GrpY;Target:0;(0|1|2)>1,2;abcd;ef01;2345", false);
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
        b.add_ldb("Demo.Off;Target:0;0;2:cafebabe", false);
        let e = b.build();
        assert!(e.scan(&hx("0000 cafebabe"), FileType::Unknown).is_some());
        assert!(e
            .scan(&hx("00000000 cafebabe"), FileType::Unknown)
            .is_none());
    }
}
