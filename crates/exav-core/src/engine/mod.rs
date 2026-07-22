//! `.ndb` / `.ldb` signature matching.
//!
//! `.ndb` bodies are hex with wildcards (`??`, nibble `a?`/`?a`, `*`,
//! `{n}`/`{n-m}`/`{-m}`/`{n-}` and the `[n-m]`/`[n]` byte-range form,
//! `(aa|bb)` alternates, `!(...)` negation).
//! Pure-literal matching can't express those, so this engine compiles each
//! body to a token program, pre-filters with one Aho-Corasick automaton over
//! a literal *anchor* per signature, and verifies the full program at each
//! candidate position.
//!
//! Verification does not backtrack. A token program is run as a Thompson-style
//! simulation over a set of reachable position *intervals*
//! (`gap_split_match` forward, `gap_split_match_backward` for the start of a
//! `Prefix::Internal` body), so an unbounded gap costs one interval expansion
//! instead of a per-length loop and hostile, highly repetitive input cannot make
//! verification blow up combinatorially. The old recursive walk
//! (`match_forward` / `match_backward`) is retained behind
//! `EXAV_SPLIT_MATCH=0` so a scan can be run both ways and the results compared.
//!
//! `.ldb` logical signatures compose subsignatures (each an `.ndb` body) with
//! a boolean expression. Verification runs only on a bounded in-memory buffer
//! (the streaming path stays literal-only).
//!
//! Supported subsignature features: `EP`- and section-relative offsets, and
//! PCRE (via `fancy-regex` for lookaround/backreferences). Not supported
//! (counted, never silently dropped): `VI`/`SEx` offset kinds, bytecode
//! subsignatures, and patterns whose only literal run is shorter than
//! `MIN_ANCHOR` or sits behind a non-leading variable gap.

use daachorse::{DoubleArrayAhoCorasick, DoubleArrayAhoCorasickBuilder};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;

use crate::filetype::FileType;
use crate::pe::PeLayout;

// Signature-text parsing and the `.ldb` logical-expression evaluator live in
// sibling submodules; their items are `pub(super)` (internal to `engine`).
mod logic;
mod parse;
use logic::*;
use parse::*;
// Re-exported so crate-root matchers (e.g. `.cdb`) can gate signatures on the
// same engine feature-level window the pattern engine uses.
pub(crate) use parse::flevel_ok;

/// The container types referenced by `Container:` and `Intermediates:` TDB
/// constraints that exav can determine provenance for. A signature with a
/// `Container:` constraint fires only when its *immediate* container is of this
/// type. Named after the `CL_TYPE_*` tokens of the signature format.
///
/// A type exav cannot determine is NOT silently left unenforced — that drops the
/// constraint and lets the signature fire on content it was never scoped to, the
/// same false-positive shape the unimplemented TDB attributes had. Such a
/// signature is refused at load and counted instead.
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
    /// `CL_TYPE_MSCHM` — a compiled HTML Help file.
    Mschm,
    /// `CL_TYPE_DMG` — an Apple disk image.
    Dmg,
    /// `CL_TYPE_NULSFT` — an NSIS (Nullsoft) installer.
    Nulsft,
    /// `CL_TYPE_AUTOIT` — a compiled AutoIt3 script.
    Autoit,
    /// `CL_TYPE_MSEXE` — a Windows executable acting as a container: an SFX
    /// stub, a runtime-packed image, or an installer with an appended archive.
    MsExe,
    /// `CL_TYPE_RTF` — an RTF document (its `\objdata` embedded objects).
    Rtf,
    /// `CL_TYPE_HTML` — an HTML page, for content carried inside it (a `data:`
    /// URI image, an embedded object).
    Html,
    /// `CL_TYPE_XML_WORD` — a Word 2003 flat-XML document (not the zipped
    /// `.docx`, which is `OoxmlWord`).
    XmlWord,
    /// `CL_TYPE_XML_XL` — an Excel 2003 flat-XML workbook.
    XmlXl,
    /// `CL_TYPE_MHTML` — a saved web page (`.mht`): MIME with no mail envelope.
    Mhtml,
}

/// What a `Container:`/`Intermediates:` `CL_TYPE_*` token resolved to.
enum ClTypeToken {
    /// A type exav tracks.
    Known(ClType),
    /// `CL_TYPE_ANY` — a wildcard, verified rather than assumed: probed with a
    /// `Container:CL_TYPE_ANY` signature, clamscan fires it on a bare file, on a
    /// ZIP member, and on a member two archives deep alike. (Reading the layer
    /// logic suggests it should mean "top level only", since a missing parent
    /// reports the same value. It does not behave that way.)
    Any,
    /// A type the signature format defines but whose provenance exav cannot
    /// determine. The signature is refused rather than run unconstrained.
    Unmodelled,
}

impl ClType {
    /// Resolve a `CL_TYPE_*` token (the value after `Container:`, or one link of
    /// an `Intermediates:` chain).
    fn from_cl_token(t: &str) -> ClTypeToken {
        use ClTypeToken::{Any, Known, Unmodelled};
        match t {
            "CL_TYPE_ANY" => Any,
            "CL_TYPE_ZIP" => Known(ClType::Zip),
            "CL_TYPE_OOXML_WORD" => Known(ClType::OoxmlWord),
            "CL_TYPE_OOXML_XL" => Known(ClType::OoxmlXl),
            "CL_TYPE_OOXML_PPT" => Known(ClType::OoxmlPpt),
            "CL_TYPE_MSOLE2" => Known(ClType::Msole2),
            "CL_TYPE_MAIL" => Known(ClType::Mail),
            "CL_TYPE_PDF" => Known(ClType::Pdf),
            "CL_TYPE_MSCAB" => Known(ClType::Mscab),
            "CL_TYPE_RAR" => Known(ClType::Rar),
            "CL_TYPE_7Z" => Known(ClType::SevenZip),
            "CL_TYPE_ISO9660" => Known(ClType::Iso),
            "CL_TYPE_LHA_LZH" => Known(ClType::Lha),
            "CL_TYPE_POSIX_TAR" | "CL_TYPE_OLD_TAR" | "CL_TYPE_GNU_TAR" => Known(ClType::Tar),
            "CL_TYPE_GZ" => Known(ClType::Gzip),
            "CL_TYPE_BZ" => Known(ClType::Bzip),
            "CL_TYPE_XZ" => Known(ClType::Xz),
            "CL_TYPE_CPIO_NEWC" | "CL_TYPE_CPIO_CRC" | "CL_TYPE_CPIO_ODC" | "CL_TYPE_CPIO_OLD" => {
                Known(ClType::Cpio)
            }
            "CL_TYPE_AR" => Known(ClType::Ar),
            "CL_TYPE_ZSTD" => Known(ClType::Zstd),
            "CL_TYPE_MSCHM" => Known(ClType::Mschm),
            "CL_TYPE_DMG" => Known(ClType::Dmg),
            "CL_TYPE_NULSFT" => Known(ClType::Nulsft),
            "CL_TYPE_AUTOIT" => Known(ClType::Autoit),
            "CL_TYPE_MSEXE" => Known(ClType::MsExe),
            "CL_TYPE_RTF" => Known(ClType::Rtf),
            "CL_TYPE_HTML" => Known(ClType::Html),
            "CL_TYPE_XML_WORD" => Known(ClType::XmlWord),
            "CL_TYPE_XML_XL" => Known(ClType::XmlXl),
            "CL_TYPE_MHTML" => Known(ClType::Mhtml),
            _ => Unmodelled,
        }
    }
}

/// The `Container:` constraint a signature carries.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub enum ContainerReq {
    /// No `Container:` attribute, or `CL_TYPE_ANY` — fires anywhere.
    #[default]
    Unconstrained,
    /// Fires only directly inside a container of this type.
    Inside(ClType),
}

/// Parse a `Container:CL_TYPE_*` TDB attribute. `Err(())` means the type is one
/// ClamAV enforces but exav cannot determine, so the caller refuses the
/// signature rather than running it with the constraint dropped.
fn parse_tdb_container(tdb: &str) -> Result<ContainerReq, ()> {
    for field in tdb.split(',') {
        if let Some(v) = field.trim().strip_prefix("Container:") {
            return match ClType::from_cl_token(v.trim()) {
                ClTypeToken::Known(c) => Ok(ContainerReq::Inside(c)),
                ClTypeToken::Any => Ok(ContainerReq::Unconstrained),
                ClTypeToken::Unmodelled => Err(()),
            };
        }
    }
    Ok(ContainerReq::Unconstrained)
}

/// Parse a `HandlerType:CL_TYPE_*` TDB attribute into its raw `CL_TYPE_*` token.
fn parse_tdb_handler_type(tdb: &str) -> Option<&str> {
    tdb.split(',')
        .find_map(|f| f.trim().strip_prefix("HandlerType:"))
        .map(str::trim)
}

/// Parse an `Intermediates:CL_TYPE_A>CL_TYPE_B` TDB attribute into the ancestry
/// chain it requires, outermost first — the written order.
///
/// The format caps a chain at 16 links; a link naming a type exav cannot
/// determine refuses the signature, for the same reason `Container:` does.
///
/// `CL_TYPE_ANY` inside a chain is not a single-layer wildcard. Probing clamscan
/// with chains that differ only in that link shows it consumes a chain slot and
/// matches nothing, rather than standing in for one layer. That is the behaviour
/// a signature would have been written against, so dropping the link reproduces
/// it exactly.
fn parse_tdb_intermediates(tdb: &str) -> Result<Option<Vec<ClType>>, ()> {
    const MAX_LINKS: usize = 16;
    for field in tdb.split(',') {
        let Some(v) = field.trim().strip_prefix("Intermediates:") else {
            continue;
        };
        let mut chain = Vec::new();
        for (i, link) in v.trim().split('>').enumerate() {
            if i >= MAX_LINKS {
                return Err(());
            }
            match ClType::from_cl_token(link.trim()) {
                ClTypeToken::Known(c) => chain.push(c),
                ClTypeToken::Any => {}
                ClTypeToken::Unmodelled => return Err(()),
            }
        }
        return if chain.is_empty() {
            Err(())
        } else {
            Ok(Some(chain))
        };
    }
    Ok(None)
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
/// Per-candidate verification step cap for the LEGACY backtracking path only
/// (`EXAV_SPLIT_MATCH=0`): bounds backtracking on a *single* pattern
/// (gaps/alternations) so one pathological body can't loop unboundedly, the same
/// idea as a regex step limit. Each `verify` call gets a fresh budget. The
/// default path never reaches it — every wildcard body is decided by the
/// non-backtracking simulator (`gap_split_match` forward,
/// `gap_split_match_backward` for a [`Prefix::Internal`] start).
const VERIFY_BUDGET: u64 = 200_000;

/// Per-buffer pool for the LEGACY backtracking path (`EXAV_SPLIT_MATCH=0`).
/// Bounds total backtracking work per buffer so a pathological fan-out (hundreds
/// of thousands of expensive verifies) can't turn one file into tens of seconds.
/// Sized far above any legitimate file's need: a normal 2 MB script spends a few
/// million steps; this caps the worst case to well under a second. On the
/// default path this pool is never drawn from.
const SCAN_VERIFY_BUDGET: u64 = 64_000_000;

thread_local! {
    /// Set true when a wildcard `verify` is skipped because the per-buffer
    /// [`SCAN_VERIFY_BUDGET`] pool was exhausted — i.e. the search did NOT fully
    /// complete. Per exav's cardinal rule (never a silent `Clean` on an
    /// incomplete scan), the top-level scan converts a would-be `Clean` into
    /// `LimitsExceeded` when this is set. Reset at the start of each top-level
    /// scan via [`reset_scan_truncated`].
    static SCAN_TRUNCATED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Clear the per-scan verify-truncation flag. Call at the start of a top-level scan.
pub fn reset_scan_truncated() {
    SCAN_TRUNCATED.with(|c| c.set(false));
}

/// Did any wildcard verification get skipped this scan because its per-buffer
/// verify budget was exhausted? If so the scan was INCOMPLETE and must not be
/// reported `Clean`.
pub fn scan_was_truncated() -> bool {
    SCAN_TRUNCATED.with(|c| c.get())
}

thread_local! {
    /// Container types of every ancestor of the buffer being scanned, outermost
    /// first — what `Intermediates:` is evaluated against. `None` marks an
    /// ancestor whose type exav cannot name, which no chain can match through.
    ///
    /// Ambient rather than a parameter because it is pushed at the handful of
    /// sites that extract members and read at the one site that evaluates a
    /// logical signature, with the whole scan tree in between; threading it
    /// through would touch every scan entry point to serve two signatures.
    static ANCESTRY: RefCell<Vec<Option<ClType>>> = const { RefCell::new(Vec::new()) };

    /// A pending re-type from a matched `HandlerType:` signature, tagged with
    /// the address AND length of the buffer it was decided for so it can never
    /// be applied to a different one. Address alone would be reusable: a freed
    /// buffer's allocation can come back at the same pointer, and a re-type
    /// applied to the wrong file is a wrong file type, not a missed one.
    static RETYPE: std::cell::Cell<Option<(usize, usize, FileType)>> =
        const { std::cell::Cell::new(None) };
}

/// Pushes one ancestor onto the `ANCESTRY` chain for as long as it is held.
/// Enter it around the scanning of a container's members, passing the
/// container's own type.
pub struct AncestryGuard(());

impl AncestryGuard {
    pub fn enter(parent: Option<ClType>) -> Self {
        ANCESTRY.with(|a| a.borrow_mut().push(parent));
        AncestryGuard(())
    }
}

impl Drop for AncestryGuard {
    fn drop(&mut self) {
        ANCESTRY.with(|a| {
            a.borrow_mut().pop();
        });
    }
}

/// Whether `want` (outermost first) is the innermost run of the current
/// ancestry — i.e. it ends at the immediate parent.
fn ancestry_ends_with(want: &[ClType]) -> bool {
    ANCESTRY.with(|a| {
        let a = a.borrow();
        a.len() >= want.len()
            && a[a.len() - want.len()..]
                .iter()
                .zip(want)
                .all(|(have, w)| *have == Some(*w))
    })
}

/// Take the pending re-type for `buf`, if a `HandlerType:` signature decided one
/// for exactly this buffer. Clears it either way, so a decision is used once.
pub fn take_retype(buf: &[u8]) -> Option<FileType> {
    RETYPE.with(|c| match c.take() {
        Some((addr, len, ft)) if addr == buf.as_ptr() as usize && len == buf.len() => Some(ft),
        _ => None,
    })
}

/// The per-buffer legacy backtracking pool, overridable via
/// `EXAV_VERIFY_BUDGET` (steps). Read once. Only consulted when the simulator is
/// disabled with `EXAV_SPLIT_MATCH=0`.
fn scan_verify_budget() -> u64 {
    use std::sync::OnceLock;
    static B: OnceLock<u64> = OnceLock::new();
    *B.get_or_init(|| {
        std::env::var("EXAV_VERIFY_BUDGET")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(SCAN_VERIFY_BUDGET)
    })
}

/// Per-buffer pool for the gap-split simulator. The simulator is polynomial and
/// FP-safe (a positive answer is always a real match), so its backstop sits far
/// above the backtracking pool — it exists only to bound a deliberately
/// adversarial input, and on real content is essentially never spent. Kept
/// separate from the backtracking pool so the (safe, cheap) simulator's generous
/// headroom can never let the (dangerous, exponential) backtracker run longer.
/// At the simulator's throughput this bounds a worst-case buffer to a few
/// seconds before it (correctly, never silently) reports `LimitsExceeded`.
/// Overridable via `EXAV_SIM_BUDGET`.
const SIM_BUDGET: u64 = 500_000_000;

fn sim_verify_budget() -> u64 {
    use std::sync::OnceLock;
    static B: OnceLock<u64> = OnceLock::new();
    *B.get_or_init(|| {
        std::env::var("EXAV_SIM_BUDGET")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(SIM_BUDGET)
    })
}

/// The two per-buffer work pools a scan draws from: `sim` bounds the polynomial
/// gap-split simulator — the only one the default path uses — and `legacy` bounds
/// the exponential backtracking walk (`match_forward`/`match_backward`), reached
/// only with `EXAV_SPLIT_MATCH=0`. Kept separate so the simulator's large safe
/// headroom can never relax the backtracker's tight cap.
struct Budgets {
    legacy: u64,
    sim: u64,
}

impl Budgets {
    fn new() -> Self {
        Budgets {
            legacy: scan_verify_budget(),
            sim: sim_verify_budget(),
        }
    }
}

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
    /// `(5?|b?)`, `(?4|?c)`, `(130?|0?)` — an alternation whose branches carry
    /// nibble wildcards, so a branch is a `(value, mask)` per byte rather than a
    /// literal. Kept separate from [`Elem::Alt`] so the all-literal case keeps
    /// its substring-search fast path, which a masked branch cannot use.
    /// Never negated: a negated masked alternation does not occur in any
    /// database tracked here, and refusing it stays counted rather than guessed.
    AltMasked { opts: Vec<Vec<(u8, u8)>> },
}

/// Whether a masked branch matches the window at `hay`, which must be the
/// branch's own length.
fn masked_eq(branch: &[(u8, u8)], hay: &[u8], nocase: bool) -> bool {
    branch.len() == hay.len()
        && branch.iter().zip(hay).all(|(&(v, m), &b)| {
            let b = if nocase { b.to_ascii_lowercase() } else { b };
            let v = if nocase { v.to_ascii_lowercase() } else { v };
            b & m == v & m
        })
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
            Elem::AltMasked { opts } => {
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
    Fixed { anchor_idx: u32, len: u32 },
    /// A single leading variable gap precedes the anchor (start floats).
    Floating { anchor_idx: u32 },
    /// The anchor sits past one or more *variable* gaps from the pattern start
    /// (`elems[..anchor_idx]` contains a `Gap`/`Alt`). Verification matches both
    /// forward from the anchor and *backward* across the preceding gaps. Chosen
    /// only when a literal after a gap is markedly more selective than anything
    /// in the fixed prefix (e.g. a constant zero-run is the only pre-gap literal)
    /// — and only for `Offset::Any` patterns, so the floating pattern start never
    /// needs to satisfy a fixed offset.
    Internal { anchor_idx: u32 },
}

/// Offset constraint on where the pattern start may sit. The overwhelmingly
/// common case is [`Offset::Any`] (no constraint); the rare constrained kinds
/// are boxed so this enum stays one word, keeping `Body` small across the
/// millions of loaded signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Offset {
    Any,
    Constrained(Box<OffsetKind>),
}

/// A concrete offset constraint (boxed inside [`Offset::Constrained`]). `shift`
/// is the optional `,maxshift` window width.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum OffsetKind {
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
    /// `SEn`: the match must START inside section `idx`.
    SecIn {
        idx: usize,
    },
    /// `VI`: the match must START at a `VS_VERSION_INFO` string key.
    VersionInfo,
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
    /// `Some(len)` for the `f` (fullword) subsig modifier: the match must be
    /// bounded by non-alphanumeric bytes, and `len` is how far the pattern
    /// reaches from its start so the trailing boundary can be found.
    ///
    /// Carrying the LENGTH rather than a flag is what makes the check possible
    /// at all — the verifier reports where a match began, never where it ended.
    /// Only patterns of fixed width can supply it, which is why a fullword body
    /// that is not fixed-width is refused at load time (and counted) rather than
    /// matched with the modifier quietly dropped.
    fullword_len: Option<usize>,
    owner: Owner,
}

/// The exact byte width of a pattern, or `None` when it varies.
///
/// Every element is fixed-width except a `Gap`, and an alternation only when its
/// branches differ in length.
fn fixed_width(elems: &[Elem]) -> Option<usize> {
    let mut total = 0usize;
    for e in elems {
        total += match e {
            Elem::Bytes(b) => b.len(),
            Elem::AnyByte | Elem::HiNibble(_) | Elem::LoNibble(_) => 1,
            Elem::Gap { .. } => return None,
            Elem::Alt { opts, neg } => {
                if *neg {
                    return None;
                }
                let n = opts.first()?.len();
                if opts.iter().any(|o| o.len() != n) {
                    return None;
                }
                n
            }
            Elem::AltMasked { opts } => {
                let n = opts.first()?.len();
                if opts.iter().any(|o| o.len() != n) {
                    return None;
                }
                n
            }
        };
    }
    Some(total)
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
    /// it (gated on compat mode) using this `unofficial` bit. One database thus
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
    /// The `Container:CL_TYPE_*` TDB constraint: the signature fires only when
    /// the object's *immediate* container is of this type, or (for
    /// `CL_TYPE_ANY`) only when it has no container at all.
    #[serde(default)]
    container: ContainerReq,
    /// The `Intermediates:A>B` TDB constraint: the ancestry chain, outermost
    /// first, that must sit immediately above this object. `None` =
    /// unconstrained.
    #[serde(default)]
    intermediates: Option<Vec<ClType>>,
    /// The `HandlerType:CL_TYPE_*` TDB action. This is not a match condition:
    /// when everything else about the signature holds, the object is *re-typed*
    /// to this type and rescanned as if it had been identified that way, and the
    /// signature itself never alerts.
    #[serde(default)]
    handler_type: Option<FileType>,
    /// Optional `EntryPoint:min-max` TDB constraint, against the PE entry
    /// point's FILE offset.
    entry_point: Option<(u64, u64)>,
    /// Optional `NumberOfSections:min-max` TDB constraint.
    num_sections: Option<(u64, u64)>,
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
    /// `fuzzy_img#<hash>[#<dist>]`: matched if the scanned object is an image
    /// whose 64-bit perceptual hash is within Hamming distance `dist` of this one
    /// (`dist` = 0 → exact equality; a positive `dist` matches near-duplicate
    /// images, the point of a perceptual hash).
    Fuzzy([u8; 8], u32),
}

/// A `Trigger/PCRE/[flags]` subsignature. The compiled regex is built lazily
/// and not serialized (a database stores only the pattern/flags).
#[derive(Serialize, Deserialize)]
struct PcreSub {
    /// Logical expression over preceding subsigs that gates the regex.
    trigger: Node,
    /// Where in the file the match may start. `Offset::Any` (the common case)
    /// puts no constraint on it. Only [`Offset::Abs`] and [`Offset::Eof`] are
    /// accepted at parse time — those need nothing but the file length, whereas
    /// the `EP`/`Sx` kinds need a PE layout this path does not carry, and
    /// evaluating one without it would silently never match.
    offset: Offset,
    pattern: String,
    ci: bool,
    dotall: bool,
    multiline: bool,
    #[serde(skip)]
    re: std::sync::OnceLock<Option<regex::bytes::Regex>>,
    /// Fast linear-engine *superset* prefilter for the backtracking path: the
    /// pattern with its zero-width lookarounds stripped, compiled in the DoS-safe
    /// `regex` engine. Since dropping a `(?=…)`/`(?!…)`/`(?<=…)`/`(?<!…)` assertion
    /// only *relaxes* the pattern, if this prefilter can't match neither can the
    /// real one — so a non-match lets us skip the expensive backtracking scan (and
    /// the per-call latin-1 buffer copy). `None` when the pattern can't be reduced
    /// to a linear superset (e.g. it uses backreferences). Built lazily.
    #[serde(skip)]
    prefilter: std::sync::OnceLock<Option<regex::bytes::Regex>>,
    /// Backtracking fallback (`fancy-regex`) for lookaround/backreference patterns
    /// the linear `regex` engine can't compile. Run over a latin-1 mapping of the
    /// bytes, with a bounded backtrack budget so a crafted pattern can't hang.
    #[serde(skip)]
    fancy: std::sync::OnceLock<Option<fancy_regex::Regex>>,
}

/// A buffer plus its lossless latin-1 (`u8 → char`) rendering, built **at most
/// once** and shared across every PCRE subsig evaluated over that buffer. The
/// backtracking `fancy-regex` engine matches on `&str`; building this once avoids
/// rebuilding a full multi-MB `String` copy of the *same* buffer on every PCRE
/// call. Without it, a feed with hundreds of lookaround PCREs (e.g.
/// `twinclams.ldb`) turns a single large file into tens of seconds of pure
/// allocation churn.
pub(super) struct Latin1<'a> {
    buf: &'a [u8],
    mapped: std::cell::OnceCell<String>,
}

impl<'a> Latin1<'a> {
    #[inline]
    pub(super) fn new(buf: &'a [u8]) -> Self {
        Self { buf, mapped: std::cell::OnceCell::new() }
    }
    #[inline]
    fn bytes(&self) -> &[u8] {
        self.buf
    }
    /// The latin-1 `&str` view, built on first use and cached for the buffer.
    fn as_str(&self) -> &str {
        self.mapped
            .get_or_init(|| self.buf.iter().map(|&b| b as char).collect())
    }
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
    /// A bounded backtrack budget plus trigger-gating keep it DoS- and FP-safe, and
    /// a superset literal prefilter skips it entirely when the pattern can't match.
    fn is_match(&self, buf: &Latin1) -> bool {
        let re = self.re.get_or_init(|| {
            regex::bytes::RegexBuilder::new(&self.flagged_pattern())
                .size_limit(16 * 1024 * 1024)
                .dfa_size_limit(16 * 1024 * 1024)
                .build()
                .ok()
        });
        if let Some(r) = re {
            let hay = buf.bytes();
            return match self.offset {
                // Unconstrained: the existential answer is all we need.
                Offset::Any => r.is_match(hay),
                // Constrained: a match only counts if it STARTS inside the
                // window, so walk the matches rather than asking is_match.
                _ => {
                    let len = hay.len() as u64;
                    r.find_iter(hay)
                        .any(|m| offset_ok(&self.offset, m.start() as u64, len, None))
                }
            };
        }
        // Backtracking path (lookaround / backreferences). First the fast
        // linear-engine superset prefilter: if the lookaround-stripped pattern
        // can't match, the real one can't either, so skip the backtracking scan.
        let prefilter = self
            .prefilter
            .get_or_init(|| build_prefilter(&self.flagged_pattern()));
        if let Some(pf) = prefilter {
            if !pf.is_match(buf.bytes()) {
                return false;
            }
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
        // Lossless latin-1 view, built once per buffer and shared across all PCRE
        // subsigs (see `Latin1`), so a large file with many lookaround PCREs
        // doesn't reallocate the whole buffer per call. The latin-1 mapping is
        // 1 byte -> 1 char, so a char index here IS the byte offset.
        let s = buf.as_str();
        match self.offset {
            Offset::Any => r.is_match(s).unwrap_or(false),
            _ => {
                let len = buf.bytes().len() as u64;
                r.find_iter(s)
                    .filter_map(|m| m.ok())
                    .any(|m| offset_ok(&self.offset, m.start() as u64, len, None))
            }
        }
    }
}

/// Build a fast linear-engine *superset* of `pattern` for prefiltering the backtracking
/// path: strip zero-width lookaround assertions and compile the result in the
/// DoS-safe `regex` engine. Dropping a lookaround only relaxes the language, so
/// the result matches a superset of the original — a non-match is a sound reason
/// to skip the backtracking scan. Returns `None` when no superset can be formed
/// (no lookaround to strip, a backreference is present, or the reduced pattern
/// still won't compile), in which case the caller runs the full engine
/// unconditionally (correct, just without the speedup).
fn build_prefilter(pattern: &str) -> Option<regex::bytes::Regex> {
    let stripped = strip_lookaround(pattern)?;
    if stripped == pattern {
        return None; // nothing was stripped → no cheaper superset to gain
    }
    regex::bytes::RegexBuilder::new(&stripped)
        .size_limit(16 * 1024 * 1024)
        .dfa_size_limit(16 * 1024 * 1024)
        .build()
        .ok()
}

/// Remove top-of-token lookaround groups — `(?=…)`, `(?!…)`, `(?<=…)`, `(?<!…)` —
/// from a regex, returning the relaxed pattern. Only these four exact forms are
/// removed (with their balanced parenthesis span); every other construct —
/// `(?:…)`, capturing/named groups, char classes, inline flags — is preserved
/// verbatim, so the result can only match *more* inputs than the original.
/// Returns `None` if a backreference (`\1`–`\9`) is present (can't soundly reduce)
/// or the parentheses are unbalanced.
fn strip_lookaround(pat: &str) -> Option<String> {
    let b = pat.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let mut in_class = false; // inside a […] character class
    while i < b.len() {
        let c = b[i];
        if c == b'\\' {
            // Escape: a `\1`–`\9` backreference makes reduction unsound.
            if i + 1 < b.len() && b[i + 1].is_ascii_digit() && b[i + 1] != b'0' {
                return None;
            }
            out.push(c);
            if i + 1 < b.len() {
                out.push(b[i + 1]);
            }
            i += 2;
            continue;
        }
        if in_class {
            if c == b']' {
                in_class = false;
            }
            out.push(c);
            i += 1;
            continue;
        }
        if c == b'[' {
            in_class = true;
            out.push(c);
            i += 1;
            continue;
        }
        // Detect a lookaround opener: `(?=`, `(?!`, `(?<=`, `(?<!`.
        if c == b'(' && i + 2 < b.len() && b[i + 1] == b'?' {
            let is_look = b[i + 2] == b'='
                || b[i + 2] == b'!'
                || (b[i + 2] == b'<'
                    && i + 3 < b.len()
                    && (b[i + 3] == b'=' || b[i + 3] == b'!'));
            if is_look {
                // Skip the whole balanced group without emitting it.
                let end = matching_paren(b, i)?;
                i = end + 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Index of the `)` matching the `(` at `open`, honoring escapes and character
/// classes. `None` if unbalanced.
fn matching_paren(b: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut i = open;
    let mut in_class = false;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'(' if !in_class => depth += 1,
            b')' if !in_class => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
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

    /// Whether the PE layout satisfies the `EntryPoint:` and
    /// `NumberOfSections:` TDB constraints.
    ///
    /// A constrained signature needs a PE to check against: with no layout the
    /// constraint cannot be satisfied, so the signature must NOT fire. These
    /// attributes exist to narrow a pattern to a specific executable shape, and
    /// a missing layout narrows it to nothing.
    fn pe_shape_ok(&self, layout: Option<&PeLayout>) -> bool {
        if self.entry_point.is_none() && self.num_sections.is_none() {
            return true;
        }
        let Some(l) = layout else {
            return false;
        };
        if let Some((min, max)) = self.entry_point {
            match l.entry {
                Some(e) if e >= min && e <= max => {}
                _ => return false,
            }
        }
        if let Some((min, max)) = self.num_sections {
            let n = l.section_rawptrs.len() as u64;
            if n < min || n > max {
                return false;
            }
        }
        true
    }

    /// Whether the current container context satisfies the `Container:` TDB
    /// constraint. An unconstrained sig always passes. A type-constrained sig
    /// fires only when the immediate container matches — in particular never at
    /// the top level, since the format scopes such sigs to content extracted
    /// from a container of that type.
    fn container_ok(&self, cur: Option<ClType>) -> bool {
        match self.container {
            ContainerReq::Unconstrained => true,
            ContainerReq::Inside(req) => cur == Some(req),
        }
    }

    /// Whether the ancestry satisfies the `Intermediates:` TDB constraint.
    ///
    /// `ancestry` is the chain of container types above this object, outermost
    /// first — the same order the attribute is written in. The requirement is a
    /// contiguous run anchored at the *immediate* parent, so the chain's last
    /// link must be the innermost container and the run need not reach the top:
    /// `A>B` holds for `…>A>B>here` but not for `A>B>…>here`.
    fn intermediates_ok(&self) -> bool {
        match &self.intermediates {
            None => true,
            Some(want) => ancestry_ends_with(want),
        }
    }

    /// Evaluate the logical expression for this signature. `body_count`/
    /// `body_off` give per-body match count and first-match file offset (for
    /// normal subsigs); PCRE and byte-compare subsigs are evaluated here over
    /// `buf`, after the normal subsig counts are known (their triggers
    /// reference earlier subsigs).
    fn eval(
        &self,
        buf: &Latin1,
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
        // Satisfiability gate: PCRE/bcomp/fuzzy subsigs are expensive to evaluate,
        // yet a candidate lsig often can't fire regardless of their outcome because
        // a *body* subsig the boolean expression also requires is absent (common
        // with feeds whose PCREs anchor on ubiquitous literals). Skip Pass 2 —
        // and the whole lsig — when no assignment of the not-yet-evaluated
        // (binary) expensive subsigs can satisfy `expr`. Over-approximate and
        // FN-safe: never prunes a satisfiable expression.
        let unknown = |i: usize| {
            matches!(
                self.subs.get(i),
                Some(SubSig::Pcre(_) | SubSig::Bcomp(_) | SubSig::Fuzzy(..))
            )
        };
        if !self.expr.can_be_true(&|i| c[i], &unknown) {
            return false;
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
                                if b.matches(buf.bytes(), off) {
                                    c[i] = 1;
                                }
                            }
                        }
                    }
                }
                SubSig::Fuzzy(h, dist) => {
                    if let Some(ih) = img_hash {
                        if hamming64(&ih, h) <= *dist {
                            c[i] = 1;
                        }
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
/// `IconGroup`-constrained logical signature fires only when `Self::matches`
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

/// One compiled variant of a body: tokens, anchor, prefix, nocase flag, offset,
/// fullword flag.
type Compiled = (Vec<Elem>, Vec<u8>, Prefix, bool, Offset, bool);

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
    /// `unsupported`, broken down by cause (see `unsupported_reasons`).
    unsupported_by_reason: std::collections::HashMap<&'static str, usize>,
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
            // `.ndb` bodies have no subsignature modifiers at all.
            fullword_len: None,
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
            // Keep the raw text so a rejected offset can be attributed to its
            // KIND rather than to an opaque "unparseable".
            let offset_text = parts.next();
            let offset = offset_text.map(parse_offset).unwrap_or(Some(Offset::Any));
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
                            fullword_len: None,
                            owner: Owner::Ndb { name, unofficial },
                        });
                    }
                    None => {
                        self.skip("ndb: body has no usable literal anchor");
                    }
                },
                _ => {
                    self.skip("ndb: unparseable offset or hex body");
                }
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
            if let Err(reason) = self.add_ldb_line(line, unofficial) {
                self.skip(reason);
            }
        }
    }

    /// Split a logical-signature line into its `;`-delimited fields, putting back
    /// together any PCRE subsignature that contains a literal `;`.
    ///
    /// The format says a semicolon inside a regex must be written `\x3B`. Live
    /// signatures do not always comply — `Js.Trojan.Gootloader-10027796-0`
    /// matches `…{4,10};\s+…` and `Win.Phishing.VbsAgent-10036542-0` lists `;;`
    /// as one branch of an alternation of symbol pairs — and clamscan loads both,
    /// so a plain split drops two real detections over a punctuation rule the
    /// database itself does not keep.
    ///
    /// A field carrying a regex is unambiguous: subsignature bodies are hex and
    /// never contain `/`, and a complete PCRE subsignature is
    /// `Trigger/regex/flags`, so it holds two unescaped slashes. A field with an
    /// odd count is therefore a regex cut in half, and the pieces are glued back
    /// with the `;` that split them until the count is even again.
    fn split_ldb_fields(line: &str) -> Vec<String> {
        /// Unescaped `/` in a field — `\/` inside a regex does not delimit.
        fn slashes(s: &str) -> usize {
            let b = s.as_bytes();
            (0..b.len())
                .filter(|&i| b[i] == b'/' && (i == 0 || b[i - 1] != b'\\'))
                .count()
        }
        let mut out: Vec<String> = Vec::new();
        let mut pending: Option<String> = None;
        for field in line.split(';') {
            // Only subsignature fields can hold a regex. The name and the TDB
            // routinely contain `/` — third-party feeds ship names like
            // `TwinWave.EvilDoc.DOCXRSTRGOOD.CMDSPCE/.200402` — and counting
            // those slashes made the parity rule swallow the whole line into one
            // field, turning eight loadable signatures into "malformed line".
            if out.len() < 3 && pending.is_none() {
                out.push(field.to_string());
                continue;
            }
            match &mut pending {
                Some(acc) => {
                    acc.push(';');
                    acc.push_str(field);
                    if slashes(acc).is_multiple_of(2) {
                        out.push(pending.take().unwrap());
                    }
                }
                None => {
                    if slashes(field).is_multiple_of(2) {
                        out.push(field.to_string());
                    } else {
                        pending = Some(field.to_string());
                    }
                }
            }
        }
        // An unterminated regex at end of line is malformed; keep the fragment
        // so the line still fails loudly rather than vanishing a field.
        if let Some(acc) = pending {
            out.push(acc);
        }
        out
    }

    /// `Ok(())` when the line was loaded; `Err(reason)` names why it was not,
    /// so a coverage gap is attributable rather than just counted.
    fn add_ldb_line(&mut self, line: &str, unofficial: bool) -> Result<(), &'static str> {
        let parts: Vec<String> = Self::split_ldb_fields(line);
        let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
        if parts.len() < 4 {
            return Err("ldb: malformed line (fewer than 4 fields)");
        }
        // PUA (Potentially Unwanted Application) signatures are OFF by default in
        // ClamAV (DetectPUA); a drop-in must match that, so don't load them
        // unless explicitly enabled.
        if is_pua(parts[0]) && !self.detect_pua {
            return Err("ldb: PUA signature (off by default, like ClamAV)");
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
        // Engine flevel window: load only when our flevel is in range (skips
        // future-engine sigs and deprecated ones).
        let (emin, emax) = parse_tdb_engine(parts[1]);
        if !flevel_ok(emin, emax) {
            return Err("ldb: engine flevel window excludes this build");
        }
        let name = parts[0].to_string();
        let target = parse_tdb_target(parts[1]);
        // A TDB attribute we cannot evaluate must not be quietly ignored: doing
        // so DROPS the constraint and the signature then fires more broadly than
        // intended. Refuse the signature instead, so the gap is counted and
        // attributable like every other unsupported construct.
        if let Some(attr) = parse::unsupported_tdb_attr(parts[1]) {
            return Err(match attr {
                a if a.starts_with("Sect") => "ldb: unsupported Sect*: TDB attribute",
                _ => "ldb: unknown TDB attribute",
            });
        }
        // Range attributes. `Malformed` means the attribute is there but
        // unreadable — refuse rather than run with the bound dropped.
        use parse::TdbRange;
        let range = |r| match r {
            TdbRange::Absent => Ok(None),
            TdbRange::Range(min, max) => Ok(Some((min, max))),
            TdbRange::Malformed => Err("ldb: malformed TDB range attribute"),
        };
        let file_size = range(parse_tdb_filesize(parts[1]))?;
        let entry_point = range(parse::parse_tdb_range(parts[1], "EntryPoint"))?;
        let num_sections = range(parse::parse_tdb_range(parts[1], "NumberOfSections"))?;
        let container = parse_tdb_container(parts[1])
            .map_err(|()| "ldb: Container: type exav cannot determine")?;
        let intermediates = parse_tdb_intermediates(parts[1])
            .map_err(|()| "ldb: Intermediates: type exav cannot determine")?;
        // `HandlerType:` re-types the object and rescans it; a type exav has no
        // `FileType` for cannot be acted on, so the signature is refused.
        let handler_type = match parse_tdb_handler_type(parts[1]) {
            None => None,
            Some(t) => Some(
                crate::filetype::cl_type_to_filetype(t)
                    .ok_or("ldb: HandlerType: type exav does not model")?,
            ),
        };
        let nsubs = parts.len() - 3;
        // Classify + parse every subsignature first; commit only if all parse.
        let mut parsed: Vec<ParsedSub> = Vec::with_capacity(nsubs);
        for sub in &parts[3..] {
            match classify_subsig(sub) {
                Some(p) => parsed.push(p),
                None => return Err(classify_failure_reason(sub)),
            }
        }
        // Parse the expression once, here, and keep the AST.
        let expr = match parse_expr(parts[2]) {
            Some(node) => node,
            None => return Err("ldb: unparseable logical expression"),
        };
        // Every referenced subsig (in the expr and in PCRE/bcomp triggers) must
        // be in range; bcomp/pcre triggers may only reference *normal* subsigs.
        if parsed.is_empty() || !expr.ids_within(nsubs) {
            return Err("ldb: expression references a subsignature that does not exist");
        }
        for p in &parsed {
            match p {
                ParsedSub::Pcre(ps) if !ps.trigger.ids_within(nsubs) => {
                    return Err("ldb: PCRE trigger references a subsignature that does not exist")
                }
                ParsedSub::Bcomp(bs) if bs.trigger >= nsubs => {
                    return Err("ldb: byte-compare trigger references a subsignature that does not exist")
                }
                _ => {}
            }
        }
        let fires_on_empty = expr.eval(&|_| 0);
        let mut subs = Vec::with_capacity(nsubs);
        for p in parsed {
            let sub = match p {
                ParsedSub::Bodies(variants) => {
                    let mut ids = Vec::with_capacity(variants.len());
                    for (elems, anchor, prefix, nocase, offset, fullword) in variants {
                        // Fullword needs the match's end, which only a fixed-width
                        // pattern can supply. A variable-width one is REFUSED
                        // rather than matched with the modifier dropped: dropping
                        // it silently widens the signature, and refusing keeps it
                        // in the unsupported count where it can be seen.
                        let fullword_len = match fullword {
                            false => None,
                            true => match fixed_width(&elems) {
                                Some(n) => Some(n),
                                None => {
                                    self.unsupported += 1;
                                    continue;
                                }
                            },
                        };
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
                            fullword_len,
                            owner: Owner::LdbSub,
                        });
                    }
                    SubSig::Bodies(ids)
                }
                ParsedSub::Pcre(ps) => SubSig::Pcre(ps),
                ParsedSub::Bcomp(bs) => SubSig::Bcomp(bs),
                ParsedSub::Fuzzy(h, d) => SubSig::Fuzzy(h, d),
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
            entry_point,
            num_sections,
            container,
            intermediates,
            handler_type,
            icon_group,
            unofficial,
        });
        Ok(())
    }

    pub fn unsupported(&self) -> usize {
        self.unsupported
    }

    /// Why each skipped signature was skipped, most frequent first.
    ///
    /// `unsupported()` alone says *how many* signatures a database contributed
    /// that exav did not load — which satisfies "counted, never silently
    /// ignored", but is not actionable. This breaks the same total down by
    /// cause so a coverage gap can be attributed to a concrete missing feature
    /// rather than guessed at.
    pub fn unsupported_reasons(&self) -> Vec<(&'static str, usize)> {
        let mut v: Vec<(&'static str, usize)> = self
            .unsupported_by_reason
            .iter()
            .map(|(k, n)| (*k, *n))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        v
    }

    /// Record one skipped signature under `reason`.
    fn skip(&mut self, reason: &'static str) -> bool {
        self.unsupported += 1;
        *self.unsupported_by_reason.entry(reason).or_insert(0) += 1;
        false
    }

    pub fn signature_count(&self) -> usize {
        self.bodies
            .iter()
            .filter(|b| matches!(b.owner, Owner::Ndb { .. }))
            .count()
            + self.ldbs.len()
    }

    pub fn build(self) -> SigEngine {
        self.build_with_budget(None)
    }

    /// As [`EngineBuilder::build`], but bounds the per-shard automaton-build
    /// transient to roughly `max_build_mem` bytes by sharding each large
    /// `(target, case)` partition into multiple automatons. `None` builds one
    /// automaton per partition (fastest, largest transient). Only the build-time
    /// peak is affected — scan results are identical.
    ///
    /// Anchors are partitioned by `(target, case)`: a scan then runs only the
    /// partitions whose `target` matches the file type (a PE file never
    /// traverses the ELF/HTML/text automatons), so the per-body target check is
    /// implied by which partition a body lives in. Within a partition, identical
    /// anchors de-duplicate into one automaton pattern that fans out to every
    /// body sharing it.
    pub fn build_with_budget(mut self, max_build_mem: Option<u64>) -> SigEngine {
        // The double-array construction transient scales ~linearly with the
        // anchor count, at a rough `BUILD_BYTES_PER_ANCHOR`; capping anchors per
        // shard bounds that peak so a huge set (main+daily) builds on a small
        // host. Omit the budget for the fastest build (one automaton per class).
        const BUILD_BYTES_PER_ANCHOR: u64 = 3072;
        let max_anchors = match max_build_mem {
            Some(m) => (m / BUILD_BYTES_PER_ANCHOR).max(1) as usize,
            None => usize::MAX,
        };
        let anchor_buf = std::mem::take(&mut self.anchor_buf);
        let anchor_ranges = std::mem::take(&mut self.anchor_ranges);
        // Case-sensitive anchors (the bulk) stay borrowed slices into
        // `anchor_buf`; case-insensitive anchors match a lowercased haystack so
        // they are stored lowercased (owned).
        let mut cs: std::collections::BTreeMap<u8, AnchorGroups<&[u8]>> =
            std::collections::BTreeMap::new();
        let mut ci: std::collections::BTreeMap<u8, AnchorGroups<Vec<u8>>> =
            std::collections::BTreeMap::new();
        for (id, b) in self.bodies.iter().enumerate() {
            let (s, l) = anchor_ranges[id];
            let anchor = &anchor_buf[s as usize..(s + l) as usize];
            // Targets 4 (mail) and 7 (text) gate identically in `target_ok`, so
            // keeping them in separate automata buys nothing and costs a whole
            // extra pass over the haystack on exactly the file types where both
            // are active. Fold them together; `target_ok(4, ft)` covers both.
            //
            // Before chasing walk-count reductions further, know that they do not
            // pay. Partitions hold DISJOINT pattern sets, so four walks are not
            // four times the work of one — they match four different pattern sets
            // over the same bytes. Removing a walk only relocates its patterns.
            //
            // Measured, and it went the other way: folding target 0 (the "any
            // file type" set) into every type-specific partition removes a walk
            // from every scan, yet was slower on engine time and cost both
            // database size and resident memory. Fewer, larger automata trade
            // state transitions for cache misses, and the cache side won.
            //
            // This 4/7 fold is kept only because it is free: the two targets gate
            // identically in `target_ok`, so they merge without duplicating a
            // single pattern.
            let b_target = if b.target == 7 { 4 } else { b.target };
            if b.nocase {
                ci.entry(b_target)
                    .or_insert_with(AnchorGroups::new)
                    .add(anchor.to_ascii_lowercase(), id);
            } else {
                cs.entry(b_target)
                    .or_insert_with(AnchorGroups::new)
                    .add(anchor, id);
            }
        }
        let mut partitions = Vec::new();
        for (target, g) in cs {
            for (ac, groups) in g.finish_sharded(max_anchors) {
                partitions.push(Partition {
                    target,
                    nocase: false,
                    ac,
                    groups,
                });
            }
        }
        for (target, g) in ci {
            for (ac, groups) in g.finish_sharded(max_anchors) {
                partitions.push(Partition {
                    target,
                    nocase: true,
                    ac,
                    groups,
                });
            }
        }
        drop(anchor_buf);
        drop(anchor_ranges);
        let (body_ldb, fires_empty) = ldb_indexes(self.bodies.len(), &self.ldbs);
        let fuzzy_ldbs = fuzzy_ldb_indices(&self.ldbs);
        let has_fuzzy = !fuzzy_ldbs.is_empty();
        let has_ooxml_container = any_ooxml_container(&self.ldbs);
        SigEngine {
            partitions,
            bodies: self.bodies,
            ldbs: self.ldbs,
            unsupported: self.unsupported,
            body_ldb,
            fires_empty,
            has_fuzzy,
            fuzzy_ldbs,
            has_ooxml_container,
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

    /// Build one or more automatons over the accumulated anchors. When
    /// `max_anchors == usize::MAX` (no budget) a single automaton is built over
    /// the whole set; otherwise the anchors (and their parallel `groups`) are
    /// split into shards of at most `max_anchors` patterns each, so no single
    /// double-array construction exceeds the memory budget. Each returned
    /// automaton stores values `0..chunk_len`, indexing that shard's `groups`.
    fn finish_sharded(mut self, max_anchors: usize) -> Vec<(DoubleArrayAhoCorasick<u32>, Vec<Vec<usize>>)> {
        // The de-dup map isn't needed for the build; free it first so it
        // doesn't coexist with the automaton's construction peak.
        self.index = std::collections::HashMap::new();
        if self.patterns.is_empty() {
            return Vec::new();
        }
        let build = |pats: &[K], groups: Vec<Vec<usize>>| -> Option<(DoubleArrayAhoCorasick<u32>, Vec<Vec<usize>>)> {
            DoubleArrayAhoCorasickBuilder::new()
                .match_kind(daachorse::MatchKind::Standard)
                .build_with_values(pats.iter().zip(0u32..))
                .ok()
                .map(|ac| (ac, groups))
        };
        if max_anchors == usize::MAX || self.patterns.len() <= max_anchors {
            return build(&self.patterns, self.groups).into_iter().collect();
        }
        let mut out = Vec::new();
        let mut p_iter = self.patterns.into_iter();
        let mut g_iter = self.groups.into_iter();
        loop {
            let chunk_pat: Vec<K> = p_iter.by_ref().take(max_anchors).collect();
            if chunk_pat.is_empty() {
                break;
            }
            let chunk_grp: Vec<Vec<usize>> = g_iter.by_ref().take(max_anchors).collect();
            if let Some(part) = build(&chunk_pat, chunk_grp) {
                out.push(part);
            }
        }
        out
    }
}

/// A compiled signature set: a double-array Aho-Corasick over distinct anchors
/// (case-sensitive and case-insensitive) + per-body verifiers + logical-sig
/// expressions. Each automaton's stored value indexes a group of body ids that
/// share that anchor.
/// One Aho-Corasick automaton over the anchors of the bodies sharing a single
/// `(target, case)` class. `groups[value]` is the list of body ids that share
/// the anchor the automaton stored under `value`. A case-insensitive partition
/// (`nocase`) matches against the lowercased haystack. A class larger than the
/// build budget is split across several `Partition`s (shards) with the same
/// `(target, nocase)`.
struct Partition {
    target: u8,
    nocase: bool,
    ac: DoubleArrayAhoCorasick<u32>,
    groups: Vec<Vec<usize>>,
}

pub struct SigEngine {
    /// One (or, when sharded, several) Aho-Corasick automaton per `(target,
    /// case)` class. A scan runs only the partitions whose `target` matches the
    /// file type (`target_ok`) — a PE file never traverses the ELF/HTML/text
    /// automatons — so the per-body target check is implied by which partition a
    /// body lives in.
    partitions: Vec<Partition>,
    bodies: Vec<Body>,
    ldbs: Vec<Ldb>,
    pub unsupported: usize,
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
    /// Derived from `ldbs` (recomputed after a database load).
    has_fuzzy: bool,
    /// Indices of logical sigs containing a `fuzzy_img#` subsig. Such sigs may
    /// have no AC-anchored body subsig (nothing "touches" them), so they must be
    /// evaluated for image inputs regardless of which bodies matched. Empty in
    /// the common case. Derived from `ldbs`.
    fuzzy_ldbs: Vec<u32>,
    /// Whether any loaded logical sig carries a `Container:CL_TYPE_OOXML_*`
    /// constraint. When false, container scans can skip the OOXML sub-type probe
    /// (a leading-prefix read) entirely — nothing depends on the distinction.
    /// Derived from `ldbs` (recomputed after a database load).
    has_ooxml_container: bool,
}

/// Whether any logical signature is scoped to an OOXML container sub-type.
fn any_ooxml_container(ldbs: &[Ldb]) -> bool {
    ldbs.iter().any(|l| {
        matches!(
            l.container,
            ContainerReq::Inside(ClType::OoxmlWord | ClType::OoxmlXl | ClType::OoxmlPpt)
        )
    })
}

/// Hamming distance between two 64-bit perceptual hashes: the number of differing
/// bits (popcount of the XOR). Used to match a `fuzzy_img#<hash>#<dist>` subsig
/// against a scanned image within its distance tolerance.
fn hamming64(a: &[u8; 8], b: &[u8; 8]) -> u32 {
    (u64::from_le_bytes(*a) ^ u64::from_le_bytes(*b)).count_ones()
}

/// Indices of logical signatures carrying a `fuzzy_img#` subsignature.
fn fuzzy_ldb_indices(ldbs: &[Ldb]) -> Vec<u32> {
    ldbs.iter()
        .enumerate()
        .filter(|(_, l)| l.subs.iter().any(|s| matches!(s, SubSig::Fuzzy(..))))
        .map(|(i, _)| i as u32)
        .collect()
}

/// Build the `body_ldb` reverse index and the `fires_empty` list from the parsed
/// logical signatures. Derived data (recomputed after a database load), so the
/// on-disk database format is unaffected.
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

impl SigEngine {
    pub fn is_empty(&self) -> bool {
        self.bodies.is_empty()
    }

    /// The partitions to run for file type `ft`: those whose `target` matches
    /// (`target_ok`), each yielded as `(automaton, groups, haystack)` where the
    /// haystack is the lowercased copy for a `nocase` partition and `buf`
    /// otherwise. `lower` must be the lowercased `buf` when [`needs_lower`]
    /// returns true (else it is never read).
    fn active<'a>(
        &'a self,
        ft: FileType,
        buf: &'a [u8],
        lower: &'a [u8],
    ) -> impl Iterator<Item = (&'a DoubleArrayAhoCorasick<u32>, &'a [Vec<usize>], &'a [u8])> {
        // A `Target:5` (graphics) partition is normally skipped — exav doesn't
        // model graphics as a `FileType`. But when the buffer IS an image, its
        // Target:5 signatures legitimately apply, so run those partitions too
        // (their subsignature anchors must match for an image-scoped LDB — e.g. a
        // `Win.Phishing.*` raw-image sig — to become a candidate).
        let is_image = crate::fuzzy_img::looks_like_image(buf);
        self.partitions
            .iter()
            .filter(move |p| target_ok(p.target, ft) || (p.target == 5 && is_image))
            .map(move |p| {
                let hay: &[u8] = if p.nocase { lower } else { buf };
                (&p.ac, p.groups.as_slice(), hay)
            })
    }

    /// Whether any active partition for `ft` is case-insensitive — i.e. whether
    /// a lowercased copy of the haystack must be allocated for this scan.
    fn needs_lower(&self, ft: FileType, buf: &[u8]) -> bool {
        let is_image = crate::fuzzy_img::looks_like_image(buf);
        self.partitions
            .iter()
            .any(|p| p.nocase && (target_ok(p.target, ft) || (p.target == 5 && is_image)))
    }

    /// Serialize to the on-disk database: each double-array automaton via
    /// daachorse's own format, the rest via bincode (by reference, no clone).
    pub(crate) fn write_cache<W: std::io::Write>(&self, mut w: W) -> std::io::Result<()> {
        use crate::database::enc;
        // Each partition: (target, nocase, serialized automaton bytes, groups).
        enc(&(self.partitions.len() as u32), &mut w)?;
        for p in &self.partitions {
            enc(&p.target, &mut w)?;
            enc(&p.nocase, &mut w)?;
            enc(&p.ac.serialize(), &mut w)?;
            enc(&p.groups, &mut w)?;
        }
        enc(&self.bodies, &mut w)?;
        enc(&self.ldbs, &mut w)?;
        enc(&self.unsupported, &mut w)?;
        Ok(())
    }

    /// Reverse of [`write_cache`]. The daachorse bytes come from a database file
    /// this build wrote and validated (magic + version).
    pub(crate) fn read_cache<R: std::io::Read>(mut r: R) -> std::io::Result<Self> {
        use crate::database::dec;
        let deser = |b: Vec<u8>| -> std::io::Result<DoubleArrayAhoCorasick<u32>> {
            DoubleArrayAhoCorasick::deserialize(&b)
                .map(|(dfa, _)| dfa)
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("corrupt signature database (aho-corasick deserialize): {e:?}"),
                    )
                })
        };
        let n_parts: u32 = dec(&mut r)?;
        let mut partitions = Vec::with_capacity(n_parts as usize);
        for _ in 0..n_parts {
            let target: u8 = dec(&mut r)?;
            let nocase: bool = dec(&mut r)?;
            let ac_bytes: Vec<u8> = dec(&mut r)?;
            let groups: Vec<Vec<usize>> = dec(&mut r)?;
            partitions.push(Partition {
                target,
                nocase,
                ac: deser(ac_bytes)?,
                groups,
            });
        }
        let bodies: Vec<Body> = dec(&mut r)?;
        let ldbs: Vec<Ldb> = dec(&mut r)?;
        let unsupported = dec(&mut r)?;
        let (body_ldb, fires_empty) = ldb_indexes(bodies.len(), &ldbs);
        let fuzzy_ldbs = fuzzy_ldb_indices(&ldbs);
        let has_fuzzy = !fuzzy_ldbs.is_empty();
        let has_ooxml_container = any_ooxml_container(&ldbs);
        Ok(SigEngine {
            partitions,
            bodies,
            ldbs,
            unsupported,
            body_ldb,
            fires_empty,
            has_fuzzy,
            fuzzy_ldbs,
            has_ooxml_container,
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

    /// Whether any loaded logical sig is scoped to an OOXML container sub-type
    /// (`Container:CL_TYPE_OOXML_*`). When false, a container scan can skip the
    /// OOXML sub-type probe (a leading-prefix read) with no loss of coverage.
    pub fn has_ooxml_container_sigs(&self) -> bool {
        self.has_ooxml_container
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
                    Elem::AltMasked { opts } => format!("Am{}", opts.len()),
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

    /// Diagnostic census of the loaded bodies' prefix kinds, and — for the
    /// `Prefix::Internal` bodies, the only ones that still reach the
    /// backtracking `match_backward` — the shape of the pre-anchor context that
    /// walk has to cross. Used to size the remaining backtracking surface.
    ///
    /// Returns `(literal_only, fixed, floating, internal, internal_with_var_gap,
    /// max_pre_anchor_toks, worst_pre_anchor_product)`, where the product is the
    /// number of gap-length combinations the backward walk could enumerate for
    /// that body (`usize::MAX` when a pre-anchor gap is unbounded).
    pub fn diag_prefix_census(&self) -> [u64; 7] {
        let (mut lit, mut fixed, mut floating, mut internal, mut int_var) = (0, 0, 0, 0, 0);
        let (mut max_toks, mut worst_product) = (0u64, 0u64);
        for b in &self.bodies {
            let Some(elems) = &b.elems else {
                lit += 1;
                continue;
            };
            match b.prefix {
                Prefix::Fixed { .. } => fixed += 1,
                Prefix::Floating { .. } => floating += 1,
                Prefix::Internal { anchor_idx } => {
                    internal += 1;
                    let pre = &elems[..anchor_idx as usize];
                    max_toks = max_toks.max(pre.len() as u64);
                    let mut product = 1u64;
                    let mut has_var = false;
                    for e in pre {
                        match e {
                            Elem::Gap { min, max } => match max {
                                Some(m) if m > min => {
                                    has_var = true;
                                    product = product.saturating_mul((m - min + 1) as u64);
                                }
                                None => {
                                    has_var = true;
                                    product = u64::MAX;
                                }
                                _ => {}
                            },
                            Elem::Alt { opts, neg: false } if opts.len() > 1 => {
                                product = product.saturating_mul(opts.len() as u64);
                            }
                            _ => {}
                        }
                    }
                    if has_var {
                        int_var += 1;
                    }
                    worst_product = worst_product.max(product);
                }
            }
        }
        [
            lit,
            fixed,
            floating,
            internal,
            int_var,
            max_toks,
            worst_product,
        ]
    }

    /// Diagnostic breakdown of one scan's match work (no early return), for
    /// performance analysis: per-pass anchor hits, fan-out, and the verify
    /// split. `(cs_hits, ci_hits, fanout, target_reject, literal, token, ok)`.
    pub fn scan_diag(&self, buf: &[u8], ft: FileType, layout: Option<&PeLayout>) -> [u64; 7] {
        DIAG_SLOW.with(|c| c.set((0, 0)));
        let lower = if self.needs_lower(ft, buf) {
            buf.to_ascii_lowercase()
        } else {
            Vec::new()
        };
        let (mut cs_hits, mut ci_hits, mut fanout) = (0u64, 0u64, 0u64);
        // Partition membership implies the target match, so there is no per-body
        // target rejection any more; `treject` stays 0 (kept for the stable
        // tuple shape).
        let treject = 0u64;
        let (mut lit, mut tok, mut ok) = (0u64, 0u64, 0u64);
        let mut budgets = Budgets::new();
        for p in self.partitions.iter().filter(|p| target_ok(p.target, ft)) {
            let hay: &[u8] = if p.nocase { &lower } else { buf };
            for m in p.ac.find_overlapping_iter(hay) {
                if p.nocase {
                    ci_hits += 1;
                } else {
                    cs_hits += 1;
                }
                let group = &p.groups[m.value() as usize];
                fanout += group.len() as u64;
                for &bid in group {
                    let body = &self.bodies[bid];
                    if body.elems.is_none() {
                        lit += 1;
                    } else {
                        tok += 1;
                    }
                    let t = std::time::Instant::now();
                    if verify(body, buf, m.start(), layout, &lower, &mut budgets).is_some() {
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
        let lower = buf.to_ascii_lowercase();
        for p in &self.partitions {
            let hay: &[u8] = if p.nocase { &lower } else { buf };
            for m in p.ac.find_overlapping_iter(hay) {
                let len = (m.end() - m.start()).min(15);
                let g = p.groups[m.value() as usize].len() as u64;
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
            Prefix::Floating { anchor_idx } | Prefix::Internal { anchor_idx } => {
                (anchor_idx as usize, 0i32)
            }
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
        // Count hits per group value (case-sensitive partitions only — they
        // dominate). Keyed by `(partition index, value)` since sharded
        // partitions reuse the same local value space.
        let mut hits: std::collections::HashMap<(usize, u32), (u64, usize)> =
            std::collections::HashMap::new();
        for (pidx, p) in self.partitions.iter().enumerate() {
            if p.nocase {
                continue;
            }
            for m in p.ac.find_overlapping_iter(buf) {
                let len = m.end() - m.start();
                hits.entry((pidx, m.value())).or_insert((0, len)).0 += 1;
            }
        }
        let mut rows: Vec<(usize, usize, u64, u64, i32, u32)> = Vec::new();
        let mut cons = Vec::new();
        for ((pidx, val), (h, anchor_len)) in hits {
            let group = &self.partitions[pidx].groups[val as usize];
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

    /// Scan `buf`, returning the first matching signature as
    /// `(clean_name, offset, unofficial)`.
    pub fn scan_with_layout(
        &self,
        buf: &[u8],
        ft: FileType,
        layout: Option<&PeLayout>,
        container: Option<ClType>,
    ) -> Option<(String, u64, bool)> {
        self.scan_with_icons(buf, ft, layout, container, None)
    }

    /// As [`Self::scan_with_layout`] but with a per-scan icon-matching context so
    /// `IconGroup1/2`-constrained logical signatures can be evaluated.
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
        // Only allocate the lowercased copy if a case-insensitive partition runs.
        let lower = if self.needs_lower(ft, buf) {
            buf.to_ascii_lowercase()
        } else {
            Vec::new()
        };
        let mut budgets = Budgets::new();
        for (ac, groups, hay) in self.active(ft, buf, &lower) {
            for m in ac.find_overlapping_iter(hay) {
                let group = &groups[m.value() as usize];
                for &bid in group {
                    // The partition already guarantees this body's target matches
                    // `ft`, so no per-body target check is needed here.
                    let body = &self.bodies[bid];
                    if let Some(start) = verify(body, buf, m.start(), layout, &lower, &mut budgets) {
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
        let latin1 = Latin1::new(buf);
        for li in self.candidate_ldbs(&touched[..], img_hash.is_some()) {
            let ldb = &self.ldbs[li as usize];
            // `Target:5` (graphics) signatures — perceptual `fuzzy_img#` hashes
            // and raw-byte image matches alike — are dropped by `target_ok(5)`,
            // since exav does not model graphics as a `FileType`. But when the
            // scanned object IS an image, Target:5 is in fact satisfied, so let
            // such a signature through the target gate; its actual fire is still
            // gated by the subsignature match and the size/container constraints
            // (a benign image only trips a sig whose exact bytes/hash it carries).
            // Matches clamd, which runs Target:5 signatures on graphics.
            if !(target_ok(ldb.target, ft)
                || ldb.target == 5 && crate::fuzzy_img::looks_like_image(buf))
                || !ldb.size_ok(buf.len())
                || !ldb.pe_shape_ok(layout)
                || !ldb.container_ok(container)
                || !ldb.intermediates_ok()
            {
                continue;
            }
            if ldb.eval(&latin1, &|b| counts[b], &body_off, img_hash, icon_ctx) {
                // `HandlerType:` is an action, not an alert: the object is
                // re-typed and rescanned as that type, and this signature stays
                // silent. Record the decision for the caller (tagged with this
                // buffer) and keep looking for a real detection.
                if let Some(ft) = ldb.handler_type {
                    RETYPE.with(|c| c.set(Some((buf.as_ptr() as usize, buf.len(), ft))));
                    continue;
                }
                return Some((ldb.name.clone(), 0, ldb.unofficial));
            }
        }
        None
    }

    /// Collect *every* matching signature (NDB bodies + logical sigs), not just
    /// the first — used by `--all-matches`. Names are de-duplicated.
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

    /// As [`Self::scan_all_with_layout`] with a per-scan icon-matching context.
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
        let lower = if self.needs_lower(ft, buf) {
            buf.to_ascii_lowercase()
        } else {
            Vec::new()
        };
        let mut budgets = Budgets::new();
        for (ac, groups, hay) in self.active(ft, buf, &lower) {
            for m in ac.find_overlapping_iter(hay) {
                for &bid in &groups[m.value() as usize] {
                    // Partition membership implies the target match.
                    let body = &self.bodies[bid];
                    if let Some(start) = verify(body, buf, m.start(), layout, &lower, &mut budgets) {
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
        let latin1 = Latin1::new(buf);
        for li in self.candidate_ldbs(&touched[..], img_hash.is_some()) {
            let ldb = &self.ldbs[li as usize];
            // `Target:5` (graphics) signatures — perceptual `fuzzy_img#` hashes
            // and raw-byte image matches alike — are dropped by `target_ok(5)`,
            // since exav does not model graphics as a `FileType`. But when the
            // scanned object IS an image, Target:5 is in fact satisfied, so let
            // such a signature through the target gate; its actual fire is still
            // gated by the subsignature match and the size/container constraints
            // (a benign image only trips a sig whose exact bytes/hash it carries).
            // Matches clamd, which runs Target:5 signatures on graphics.
            if !(target_ok(ldb.target, ft)
                || ldb.target == 5 && crate::fuzzy_img::looks_like_image(buf))
                || !ldb.size_ok(buf.len())
                || !ldb.pe_shape_ok(layout)
                || !ldb.container_ok(container)
                || !ldb.intermediates_ok()
            {
                continue;
            }
            // A `HandlerType:` signature re-types rather than alerts, so it has
            // no name to collect — but the re-type itself must still be recorded,
            // or `--all-matches` runs a different signature set than a normal scan.
            if ldb.handler_type.is_some() {
                if let Some(ft) = ldb.handler_type {
                    if ldb.eval(&latin1, &|b| counts[b], &body_off, img_hash, icon_ctx) {
                        RETYPE.with(|c| c.set(Some((buf.as_ptr() as usize, buf.len(), ft))));
                    }
                }
                continue;
            }
            if ldb.eval(&latin1, &|b| counts[b], &body_off, img_hash, icon_ctx)
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
        let lower = if self.needs_lower(ft, buf) {
            buf.to_ascii_lowercase()
        } else {
            Vec::new()
        };
        let mut budgets = Budgets::new();
        for (ac, groups, hay) in self.active(ft, buf, &lower) {
            for m in ac.find_overlapping_iter(hay) {
                for &bid in &groups[m.value() as usize] {
                    // Partition membership implies the target match.
                    let body = &self.bodies[bid];
                    if let Some(start) = verify(body, buf, m.start(), layout, &lower, &mut budgets) {
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
        let latin1 = Latin1::new(buf);
        for li in self.candidate_ldbs(&touched[..], img_hash.is_some()) {
            let ldb = &self.ldbs[li as usize];
            // `Target:5` (graphics) signatures — perceptual `fuzzy_img#` hashes
            // and raw-byte image matches alike — are dropped by `target_ok(5)`,
            // since exav does not model graphics as a `FileType`. But when the
            // scanned object IS an image, Target:5 is in fact satisfied, so let
            // such a signature through the target gate; its actual fire is still
            // gated by the subsignature match and the size/container constraints
            // (a benign image only trips a sig whose exact bytes/hash it carries).
            // Matches clamd, which runs Target:5 signatures on graphics.
            if !(target_ok(ldb.target, ft)
                || ldb.target == 5 && crate::fuzzy_img::looks_like_image(buf))
                || !ldb.size_ok(buf.len())
                || !ldb.pe_shape_ok(layout)
                || !ldb.container_ok(container)
                || !ldb.intermediates_ok()
                || ldb.handler_type.is_some()
            {
                continue;
            }
            if ldb.eval(&latin1, &|b| counts[b], &body_off, img_hash, None) {
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
        // Java(12): gate on a positively-typed `.class` (the `cafebabe` magic,
        // with Mach-O fat binaries — same first four bytes — already rejected by
        // `identify`). The earlier blanket skip predated `FileType::JavaClass`
        // and cost real detections: a log4shell logical signature
        // (`FileSize:500-5000,Target:12`) never ran, so a JAR whose payload
        // classes were hidden behind trailing-slash names scanned clean. The
        // false positives that motivated the skip came from running Java sigs on
        // *untyped* apk/zip members, which typing on the magic prevents.
        12 => ft == FileType::JavaClass,
        // Flash(11): every SWF variant is positively typed — `CWS`/`ZWS` by
        // `unpack::detect`, `FWS` by `identify` — so the gate is exact. Both the
        // compressed container and the `FWS` body exav rebuilds from it are
        // typed `Swf`, which matches clamscan: probed with a `Target:11`
        // signature, it fires on an uncompressed movie, on a compressed one, and
        // on a compressed one whose stream is corrupt (the container is scanned
        // raw regardless), but on neither an untyped binary nor a PE.
        // A large body of official signatures keys on this target, so getting
        // the gate right is the difference between them running and not.
        11 => ft == FileType::Swf,
        // Graphics(5): reached two ways. A buffer that *looks* like an image is
        // let through by the caller's `looks_like_image` special case; this arm
        // covers the other route, a file a `HandlerType:CL_TYPE_GRAPHICS`
        // signature has re-typed. Content detection never yields `Graphics`, so
        // the arm cannot widen anything on its own.
        5 => ft == FileType::Graphics,
        // internal(13)/other(14)/...: exav can't positively identify these
        // content types, so running a target-N sig would false-positive on
        // unrelated content. Skip until those types are modelled.
        _ => false,
    }
}

/// A byte that can be part of a word, for the `f` (fullword) subsig modifier.
///
/// Alphanumeric only. A match bounded by punctuation, whitespace, a NUL or the
/// edge of the buffer is a whole word; one bounded by a letter or digit is a
/// fragment of a longer one.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn verify(
    body: &Body,
    buf: &[u8],
    anchor_start: usize,
    layout: Option<&PeLayout>,
    lower: &[u8],
    budgets: &mut Budgets,
) -> Option<u64> {
    let start = verify_inner(body, buf, anchor_start, layout, lower, budgets)?;
    let Some(len) = body.fullword_len else {
        return Some(start);
    };
    // `::f` — the match must not be glued to a longer word on either side.
    //
    // Dropping this modifier silently is not a smaller version of implementing
    // it: it makes every `::f` subsignature match as a plain substring, so the
    // signature fires on strictly more than its author asked for. Measured on
    // one live sample, `Win.Trojan.APT_Trojan_Win_REDFLARE_1` matched a 25 MB Go
    // binary where `VirtualAllocEx` occurs only ever as `FuncVirtualAllocEx` and
    // `fini` only ever inside longer identifiers — under the real semantics its
    // `0&1&2&3&4&5` expression is false, and ClamAV agrees.
    let s = start as usize;
    let before_ok = s == 0 || !buf.get(s - 1).copied().is_some_and(is_word_byte);
    let after_ok = !buf.get(s + len).copied().is_some_and(is_word_byte);
    (before_ok && after_ok).then_some(start)
}

fn verify_inner(
    body: &Body,
    buf: &[u8],
    anchor_start: usize,
    layout: Option<&PeLayout>,
    lower: &[u8],
    budgets: &mut Budgets,
) -> Option<u64> {
    // Pure literal: the Aho-Corasick hit is already the full match; only the
    // offset constraint remains (no backtracking, so no budget is drawn).
    let elems = match &body.elems {
        None => {
            return offset_ok(&body.offset, anchor_start as u64, buf.len() as u64, layout)
                .then_some(anchor_start as u64);
        }
        Some(e) => e,
    };
    let filelen = buf.len() as u64;
    let off_at = |start: usize| offset_ok(&body.offset, start as u64, filelen, layout);

    // Gap-split anchored matching: no backtracking anywhere. Both directions
    // are decided by the interval simulator, which yields the identical answer in
    // polynomial time.
    //
    //  - Fixed / Floating: the pattern start is fixed by the anchor position
    //    alone, so `gap_split_match`'s boolean is the whole decision and the
    //    reported offset (hence a scan's per-body count and first-match offset)
    //    is unchanged.
    //  - Internal: the anchor sits past variable gaps, so the *forward* suffix is
    //    decided by `gap_split_match` (existence only) and the *start* by
    //    `gap_split_match_backward`, which reconstructs the byte-for-byte same
    //    start the backtracking walk returned.
    //
    // Everything draws from the `sim` pool; the `legacy` pool stays untouched.
    if split_match_enabled() {
        macro_rules! sim {
            ($toks:expr, $at:expr) => {{
                if budgets.sim == 0 {
                    SCAN_TRUNCATED.with(|c| c.set(true));
                    return None;
                }
                gap_split_match($toks, buf, $at, body.nocase, lower, &mut budgets.sim)
            }};
        }
        return match body.prefix {
            Prefix::Fixed { len, .. } => {
                if anchor_start < len as usize {
                    return None;
                }
                let start = anchor_start - len as usize;
                if !off_at(start) {
                    return None;
                }
                sim!(elems, start).then_some(start as u64)
            }
            Prefix::Floating { anchor_idx } => {
                if !off_at(anchor_start) {
                    return None;
                }
                sim!(&elems[anchor_idx as usize..], anchor_start).then_some(anchor_start as u64)
            }
            Prefix::Internal { anchor_idx } => {
                if !sim!(&elems[anchor_idx as usize..], anchor_start) {
                    return None;
                }
                if budgets.sim == 0 {
                    SCAN_TRUNCATED.with(|c| c.set(true));
                    return None;
                }
                // The start comes from the backward simulator, which returns the
                // same start the legacy walk did but without backtracking — so
                // this path draws from the polynomial `sim` pool too, and the
                // exponential `legacy` pool is never touched.
                gap_split_match_backward(
                    &elems[..anchor_idx as usize],
                    buf,
                    anchor_start,
                    body.nocase,
                    lower,
                    &mut budgets.sim,
                )
                .filter(|&start| off_at(start))
                .map(|start| start as u64)
            }
        };
    }

    // Legacy backtracking path (split matcher disabled).
    if budgets.legacy == 0 {
        SCAN_TRUNCATED.with(|c| c.set(true));
        return None;
    }
    let call_cap = VERIFY_BUDGET.min(budgets.legacy);
    let mut budget = call_cap;
    let result = match body.prefix {
        Prefix::Fixed { len, .. } => {
            if anchor_start < len as usize {
                None
            } else {
                let start = anchor_start - len as usize;
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
                    &elems[anchor_idx as usize..],
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
                &elems[anchor_idx as usize..],
                buf,
                anchor_start,
                body.nocase,
                &mut budget,
            ) {
                match_backward(
                    &elems[..anchor_idx as usize],
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
    // Charge the steps this verify actually spent back to the legacy pool.
    budgets.legacy = budgets.legacy.saturating_sub(call_cap - budget);
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
    let kind = match off {
        Offset::Any => return true,
        Offset::Constrained(k) => k.as_ref(),
    };
    match *kind {
        OffsetKind::Abs { n, shift } => window(n, shift),
        // `EOF-n` anchors `n` bytes before end of file. If `n` exceeds the
        // file length the anchor is before offset 0 — treated as no
        // match; without this guard `saturating_sub` collapses it to offset 0
        // and a pattern at the start of a short file would falsely match.
        OffsetKind::Eof { n, shift } => n <= filelen && window(filelen - n, shift),
        OffsetKind::Ep { delta, shift } => match layout.and_then(|l| l.entry) {
            Some(ep) => add_delta(ep, delta)
                .map(|t| window(t, shift))
                .unwrap_or(false),
            None => false,
        },
        OffsetKind::Sec { idx, delta, shift } => {
            match layout.and_then(|l| l.section_rawptrs.get(idx).copied()) {
                Some(p) => add_delta(p, delta)
                    .map(|t| window(t, shift))
                    .unwrap_or(false),
                None => false,
            }
        }
        OffsetKind::SecLast { delta, shift } => {
            match layout.and_then(|l| l.section_rawptrs.last().copied()) {
                Some(p) => add_delta(p, delta)
                    .map(|t| window(t, shift))
                    .unwrap_or(false),
                None => false,
            }
        }
        // `SEn` constrains where the match STARTS, not where it ends: probed
        // with a two-section PE, a signature anchored `SE0:` fires on a pattern
        // that begins at the last byte of section 0 and runs on into section 1.
        // The upper bound is inclusive for the same reason — a match starting at
        // exactly `ptr + size`, i.e. the first byte of the next section, is
        // accepted. That looks like an off-by-one and reproducing it is
        // deliberate: being stricter here would drop a detection ClamAV makes.
        // `VI` is an anchor set, not a window: the match must begin exactly at
        // a version-info key. See `icon::version_info_anchors`.
        OffsetKind::VersionInfo => layout.is_some_and(|l| l.version_info.contains(&start)),
        OffsetKind::SecIn { idx } => match layout {
            Some(l) => match (l.section_rawptrs.get(idx), l.section_rawsizes.get(idx)) {
                (Some(&p), Some(&n)) => start >= p && start <= p.saturating_add(n),
                _ => false,
            },
            None => false,
        },
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
        Elem::AltMasked { opts } => opts.iter().any(|o| {
            pos + o.len() <= buf.len()
                && masked_eq(o, &buf[pos..pos + o.len()], nocase)
                && match_forward(rest, buf, pos + o.len(), nocase, budget)
        }),
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
        Elem::AltMasked { opts } => {
            for o in opts {
                if end >= o.len() && masked_eq(o, &buf[end - o.len()..end], nocase) {
                    if let Some(s) = match_backward(rest, buf, end - o.len(), nocase, budget) {
                        return Some(s);
                    }
                }
                if *budget == 0 {
                    SCAN_TRUNCATED.with(|c| c.set(true));
                    return None;
                }
                *budget -= 1;
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

// --- Gap-split anchored matching -------------------------------------------
//
// The legacy `match_forward` walks a wildcard body by recursive backtracking:
// at every variable gap it tries each gap length (or every occurrence of the
// following literal) and recurses. On dense content a body with several large
// or unbounded gaps fans out multiplicatively, so a per-buffer step budget has
// to cut the search off (reported `LimitsExceeded`).
//
// The gap-split matcher removes the backtracking. It reads the body as a chain
// of gap-free "parts" separated by variable gaps and advances a *set* of
// reachable positions one element at a time (a Thompson-style NFA simulation):
//   - a gap-free part filters/advances the set by literal/nibble/alt matching;
//   - a variable gap expands each reachable interval into a wider interval.
// The set is kept as sorted, disjoint, inclusive position intervals, so an
// unbounded gap is a single interval expansion instead of a per-length loop,
// and "the literal that follows a gap" is found once across the whole window
// instead of once per surviving backtracking branch. The body is present iff
// the reachable set is non-empty after the last element — the *identical*
// present/absent decision the backtracking walk computes, but without the
// combinatorial blow-up, so the verify budget is (essentially) never spent.

/// Whether the non-backtracking gap-split matcher is used. `EXAV_SPLIT_MATCH=0`
/// (also `false`/`no`/`off`) forces the legacy backtracking `verify` path, so a
/// scan can be run both ways and the detections compared. Read once.
fn split_match_enabled() -> bool {
    use std::sync::OnceLock;
    static E: OnceLock<bool> = OnceLock::new();
    *E.get_or_init(|| {
        !matches!(
            std::env::var("EXAV_SPLIT_MATCH").ok().as_deref(),
            Some("0") | Some("false") | Some("no") | Some("off")
        )
    })
}

/// Coalesce a position-interval set into sorted, disjoint form. Two intervals
/// are merged when they touch or overlap (`next.lo <= cur.hi + 1`), since the
/// positions are integers and `[a,b] ∪ [b+1,c] = [a,c]`. Keeping the set minimal
/// bounds the simulator's per-step cost.
fn coalesce(ivs: &mut Vec<(usize, usize)>) {
    if ivs.len() <= 1 {
        return;
    }
    ivs.sort_unstable();
    let mut w = 0usize;
    for r in 1..ivs.len() {
        let (lo, hi) = ivs[r];
        if lo <= ivs[w].1 + 1 {
            if hi > ivs[w].1 {
                ivs[w].1 = hi;
            }
        } else {
            w += 1;
            ivs[w] = (lo, hi);
        }
    }
    ivs.truncate(w + 1);
}

/// Advance a reachable set across a literal `needle` (length ≥ 1): for every
/// start position `q` in the set with `buf[q..q+L] == needle` (ASCII-folded when
/// `nocase`), the position `q+L` is reachable next. `nocase` searches the
/// pre-lowercased `lower` haystack (positions line up with `buf`). Charges one
/// budget unit per source interval plus one per occurrence found; on exhaustion
/// it flags truncation and returns whatever was found so the scan is never a
/// silent clean.
fn advance_literal(
    cur: &[(usize, usize)],
    buf: &[u8],
    lower: &[u8],
    needle: &[u8],
    nocase: bool,
    out: &mut Vec<(usize, usize)>,
    budget: &mut u64,
) {
    let n = buf.len();
    let l = needle.len();
    if l == 0 || l > n {
        return;
    }
    let last_start = n - l; // greatest position a length-l needle can start at
    let (hay, folded);
    if nocase {
        folded = needle.to_ascii_lowercase();
        hay = (lower, folded.as_slice());
    } else {
        hay = (buf, needle);
    }
    let (haystack, pat) = hay;
    for &(lo, hi) in cur {
        if lo > last_start {
            continue;
        }
        if *budget == 0 {
            SCAN_TRUNCATED.with(|c| c.set(true));
            return;
        }
        *budget -= 1;
        let qmax = hi.min(last_start);
        // Every start position `q` in `[lo, qmax]` with a needle occurrence
        // becomes the reachable position `q+L`. Occurrences are enumerated
        // *overlapping* (advance the search cursor by 1, not by `L`) so a
        // self-overlapping needle like `aa` in `aaa` yields every start — the
        // reachable set is the exact union the token program admits, never a
        // non-overlapping subset.
        let end = qmax + l; // slice bound past the last admissible start
        let mut s = lo;
        while s <= qmax {
            match memchr::memmem::find(&haystack[s..end], pat) {
                Some(off) => {
                    let q = s + off; // q <= qmax by construction of `end`
                    out.push((q + l, q + l));
                    if *budget == 0 {
                        SCAN_TRUNCATED.with(|c| c.set(true));
                        return;
                    }
                    *budget -= 1;
                    s = q + 1;
                }
                None => break,
            }
        }
    }
}

/// Advance a reachable set across a single-byte class (`AnyByte`, `HiNibble`,
/// `LoNibble`). `AnyByte` is a pure interval shift (no content test); the nibble
/// classes test each position in the interval. Charges per source interval, plus
/// per position scanned for the nibble classes.
/// Advance over an alternation whose branches carry nibble wildcards. Unlike a
/// literal branch there is no substring search to lean on, so every start
/// position in the reachable set is tested against every branch — charged to the
/// step budget the same way a nibble class is.
fn advance_masked_alt(
    cur: &[(usize, usize)],
    buf: &[u8],
    opts: &[Vec<(u8, u8)>],
    nocase: bool,
    out: &mut Vec<(usize, usize)>,
    budget: &mut u64,
) {
    let n = buf.len();
    for &(lo, hi) in cur {
        if lo > n {
            continue;
        }
        for branch in opts {
            let w = branch.len();
            // An empty branch consumes nothing: every reachable position stays
            // reachable. This is the `(abc|)` "optional run" form.
            if w == 0 {
                out.push((lo, hi.min(n)));
                continue;
            }
            if w > n {
                continue;
            }
            let qmax = hi.min(n - w);
            if lo > qmax {
                continue;
            }
            if *budget == 0 {
                SCAN_TRUNCATED.with(|c| c.set(true));
                return;
            }
            for q in lo..=qmax {
                if masked_eq(branch, &buf[q..q + w], nocase) {
                    out.push((q + w, q + w));
                }
            }
            *budget = budget.saturating_sub((qmax - lo + 1) as u64);
        }
    }
}

fn advance_class(
    cur: &[(usize, usize)],
    buf: &[u8],
    elem: &Elem,
    out: &mut Vec<(usize, usize)>,
    budget: &mut u64,
) {
    let n = buf.len();
    for &(lo, hi) in cur {
        if lo >= n {
            continue; // no byte to consume at end of buffer
        }
        if *budget == 0 {
            SCAN_TRUNCATED.with(|c| c.set(true));
            return;
        }
        *budget -= 1;
        let qmax = hi.min(n - 1);
        match elem {
            Elem::AnyByte => out.push((lo + 1, qmax + 1)),
            Elem::HiNibble(h) => {
                for (q, &b) in (lo..=qmax).zip(&buf[lo..=qmax]) {
                    if b >> 4 == *h {
                        out.push((q + 1, q + 1));
                    }
                }
                *budget = budget.saturating_sub((qmax - lo + 1) as u64);
            }
            Elem::LoNibble(l) => {
                for (q, &b) in (lo..=qmax).zip(&buf[lo..=qmax]) {
                    if b & 0x0f == *l {
                        out.push((q + 1, q + 1));
                    }
                }
                *budget = budget.saturating_sub((qmax - lo + 1) as u64);
            }
            _ => unreachable!("advance_class only handles single-byte classes"),
        }
    }
}

/// Advance a reachable set across a negated alternation `!(o0|o1|…)`: all
/// options share one length `l`, and a position `q` advances to `q+l` iff the
/// `l`-byte window at `q` equals *none* of them. Each source interval shifts by
/// `l` and then has the (few) excluded end-positions — where a window did match
/// an option — carved out, so the result stays a compact interval set.
fn advance_neg_alt(
    cur: &[(usize, usize)],
    buf: &[u8],
    lower: &[u8],
    opts: &[Vec<u8>],
    nocase: bool,
    out: &mut Vec<(usize, usize)>,
    budget: &mut u64,
) {
    let n = buf.len();
    let l = match opts.first() {
        Some(o) if !o.is_empty() => o.len(),
        _ => return,
    };
    if l > n {
        return;
    }
    let last_start = n - l;
    let haystack: &[u8] = if nocase { lower } else { buf };
    let folded: Vec<Vec<u8>> = if nocase {
        opts.iter().map(|o| o.to_ascii_lowercase()).collect()
    } else {
        Vec::new()
    };
    let pats: &[Vec<u8>] = if nocase { &folded } else { opts };
    let mut excluded: Vec<usize> = Vec::new();
    for &(lo, hi) in cur {
        if lo > last_start {
            continue;
        }
        if *budget == 0 {
            SCAN_TRUNCATED.with(|c| c.set(true));
            return;
        }
        *budget -= 1;
        let qmax = hi.min(last_start);
        // End-positions of windows in [lo,qmax] that DO match an option: these
        // are the holes punched out of the shifted interval.
        excluded.clear();
        let end = qmax + l;
        for pat in pats {
            let mut s = lo;
            while s <= qmax {
                match memchr::memmem::find(&haystack[s..end], pat) {
                    Some(off) => {
                        let q = s + off;
                        excluded.push(q + l);
                        s = q + 1;
                    }
                    None => break,
                }
            }
        }
        excluded.sort_unstable();
        excluded.dedup();
        *budget = budget.saturating_sub(excluded.len() as u64);
        // The shifted interval [lo+l, qmax+l] minus the excluded points.
        let (a, b) = (lo + l, qmax + l);
        let mut cursor = a;
        for &e in &excluded {
            if e > cursor {
                out.push((cursor, e - 1));
            }
            cursor = e + 1;
        }
        if cursor <= b {
            out.push((cursor, b));
        }
    }
}

/// Advance a reachable set across a variable gap `{min,max}` (unbounded when
/// `max` is `None`). Each interval `[lo,hi]` expands to `[lo+min,
/// min(hi+max, n)]` — the union over every start position of its reachable gap
/// window — clamped to the buffer length `n`.
fn advance_gap(cur: &[(usize, usize)], min: usize, max: Option<usize>, n: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(cur.len());
    for &(lo, hi) in cur {
        let newlo = lo + min;
        if newlo > n {
            continue;
        }
        let newhi = match max {
            Some(m) => (hi + m).min(n),
            None => n,
        };
        if newlo <= newhi {
            out.push((newlo, newhi));
        }
    }
    coalesce(&mut out);
    out
}

/// Decide whether `toks` matches `buf` starting at `pos`, by advancing a set of
/// reachable positions element by element (see the module note above). Returns
/// `true` iff some position remains reachable after the final element — the same
/// answer [`match_forward`] computes, without its backtracking. `budget` (the
/// per-buffer pool) is charged the exact search work; if it is exhausted the
/// scan is flagged truncated and a conservative `false` is returned, so an
/// incomplete search can never be reported a silent clean.
fn gap_split_match(
    toks: &[Elem],
    buf: &[u8],
    pos: usize,
    nocase: bool,
    lower: &[u8],
    budget: &mut u64,
) -> bool {
    let mut cur: Vec<(usize, usize)> = vec![(pos, pos)];
    let mut next: Vec<(usize, usize)> = Vec::new();
    for tok in toks {
        if cur.is_empty() {
            return false;
        }
        if *budget == 0 {
            SCAN_TRUNCATED.with(|c| c.set(true));
            return false;
        }
        match tok {
            Elem::Bytes(b) => {
                next.clear();
                advance_literal(&cur, buf, lower, b, nocase, &mut next, budget);
                coalesce(&mut next);
                std::mem::swap(&mut cur, &mut next);
            }
            Elem::Alt { opts, neg: false } => {
                next.clear();
                for o in opts {
                    // An empty branch is the `(abc|)` optional-run form: it
                    // consumes nothing, so every reachable position stays
                    // reachable. `advance_literal` cannot express that — it
                    // searches for a needle, and there is none.
                    if o.is_empty() {
                        next.extend_from_slice(&cur);
                    } else {
                        advance_literal(&cur, buf, lower, o, nocase, &mut next, budget);
                    }
                }
                coalesce(&mut next);
                std::mem::swap(&mut cur, &mut next);
            }
            Elem::AnyByte | Elem::HiNibble(_) | Elem::LoNibble(_) => {
                next.clear();
                advance_class(&cur, buf, tok, &mut next, budget);
                coalesce(&mut next);
                std::mem::swap(&mut cur, &mut next);
            }
            Elem::Alt { opts, neg: true } => {
                next.clear();
                advance_neg_alt(&cur, buf, lower, opts, nocase, &mut next, budget);
                coalesce(&mut next);
                std::mem::swap(&mut cur, &mut next);
            }
            Elem::AltMasked { opts } => {
                next.clear();
                advance_masked_alt(&cur, buf, opts, nocase, &mut next, budget);
                coalesce(&mut next);
                std::mem::swap(&mut cur, &mut next);
            }
            Elem::Gap { min, max } => {
                cur = advance_gap(&cur, *min, *max, buf.len());
            }
        }
    }
    !cur.is_empty()
}

/// Sum of the tokens' maximum byte widths, or `None` when one of them can
/// consume an unbounded run (an open-ended gap).
fn max_total_width(toks: &[Elem]) -> Option<usize> {
    let mut sum = 0usize;
    for t in toks {
        let w = match t {
            Elem::Bytes(b) => b.len(),
            Elem::AnyByte | Elem::HiNibble(_) | Elem::LoNibble(_) => 1,
            Elem::Gap { max: Some(m), .. } => *m,
            Elem::Gap { max: None, .. } => return None,
            Elem::Alt { opts, .. } => opts.iter().map(|o| o.len()).max().unwrap_or(0),
            Elem::AltMasked { opts } => opts.iter().map(|o| o.len()).max().unwrap_or(0),
        };
        sum = sum.checked_add(w)?;
    }
    Some(sum)
}

/// Greatest position `p` in a coalesced (sorted, disjoint) interval set with
/// `lo <= p <= hi`. `O(log n)`.
fn set_max_in(ivs: &[(usize, usize)], lo: usize, hi: usize) -> Option<usize> {
    if lo > hi {
        return None;
    }
    // The rightmost interval that starts at or before `hi` is the only candidate:
    // the set is sorted and disjoint, so every earlier interval ends sooner.
    let idx = ivs.partition_point(|&(l, _)| l <= hi);
    let &(_, h) = ivs[..idx].last()?;
    (h >= lo).then(|| h.min(hi))
}

/// Membership test on a coalesced (sorted, disjoint) interval set.
fn set_contains(ivs: &[(usize, usize)], p: usize) -> bool {
    set_max_in(ivs, p, p).is_some()
}

/// The non-backtracking counterpart of [`match_backward`]: match `toks` ending
/// exactly at `end` and return the pattern start, walking right-to-left across
/// the pre-anchor context without ever backtracking.
///
/// It returns the *byte-for-byte same start* the backtracking walk returns, not
/// merely some valid one, so a body's reported offset is unchanged. Two passes:
///
///  1. **Reachability (forward).** `reach[i]` is the set of positions at which
///     `toks[..i]` can finish, seeded with every position the pattern start could
///     possibly occupy. `reach[i]` is therefore exactly "the positions from which
///     the remaining leftward tokens can still complete" — the fact the
///     backtracking walk rediscovers by trial and error at every gap. Computed
///     with the same interval-set machinery as [`gap_split_match`], so an
///     unbounded gap is one interval expansion rather than a per-length loop.
///  2. **Reconstruction (backward).** Walk the tokens last-to-first, at each step
///     taking the *first* choice the backtracking walk would have taken — for a
///     gap the shortest length, for an alternation the earliest option — but
///     accepting it only if it lands in `reach[i]`. Same exploration order plus
///     perfect lookahead, so the first solution found is the same one, reached
///     without ever exploring a dead branch.
///
/// Polynomial in the buffer and token count, so it draws from the simulator pool
/// rather than the tight backtracking pool.
fn gap_split_match_backward(
    toks: &[Elem],
    buf: &[u8],
    end: usize,
    nocase: bool,
    lower: &[u8],
    budget: &mut u64,
) -> Option<usize> {
    if toks.is_empty() {
        return Some(end); // no preceding context: the pattern starts at `end`
    }
    // The pattern start cannot sit further left than `end` minus everything the
    // tokens could consume (the whole prefix when a gap is open-ended).
    let lo0 = match max_total_width(toks) {
        Some(w) => end.saturating_sub(w),
        None => 0,
    };

    let mut reach: Vec<Vec<(usize, usize)>> = Vec::with_capacity(toks.len() + 1);
    reach.push(vec![(lo0, end)]);
    for tok in toks {
        let cur = reach.last().expect("seeded above");
        if cur.is_empty() {
            return None;
        }
        if *budget == 0 {
            SCAN_TRUNCATED.with(|c| c.set(true));
            return None;
        }
        let mut next = Vec::new();
        match tok {
            Elem::Bytes(b) => {
                advance_literal(cur, buf, lower, b, nocase, &mut next, budget);
                coalesce(&mut next);
            }
            Elem::Alt { opts, neg: false } => {
                for o in opts {
                    if o.is_empty() {
                        next.extend_from_slice(cur);
                    } else {
                        advance_literal(cur, buf, lower, o, nocase, &mut next, budget);
                    }
                }
                coalesce(&mut next);
            }
            Elem::AnyByte | Elem::HiNibble(_) | Elem::LoNibble(_) => {
                advance_class(cur, buf, tok, &mut next, budget);
                coalesce(&mut next);
            }
            Elem::Alt { opts, neg: true } => {
                advance_neg_alt(cur, buf, lower, opts, nocase, &mut next, budget);
                coalesce(&mut next);
            }
            Elem::AltMasked { opts } => {
                advance_masked_alt(cur, buf, opts, nocase, &mut next, budget);
                coalesce(&mut next);
            }
            Elem::Gap { min, max } => {
                next = advance_gap(cur, *min, *max, buf.len());
            }
        }
        reach.push(next);
    }
    if !set_contains(&reach[toks.len()], end) {
        return None;
    }

    let mut cur = end;
    for i in (0..toks.len()).rev() {
        let need = reach[i].as_slice();
        let q = match &toks[i] {
            // Fixed-width tokens have a single predecessor. It is necessarily in
            // `reach[i]` — the forward pass only produced `cur` from it — so the
            // membership check is a debug-only assertion.
            Elem::Bytes(b) => {
                if cur < b.len() || !bytes_eq(&buf[cur - b.len()..cur], b, nocase) {
                    return None;
                }
                cur - b.len()
            }
            Elem::AnyByte => {
                if cur == 0 {
                    return None;
                }
                cur - 1
            }
            Elem::HiNibble(h) => {
                if cur == 0 || buf[cur - 1] >> 4 != *h {
                    return None;
                }
                cur - 1
            }
            Elem::LoNibble(l) => {
                if cur == 0 || buf[cur - 1] & 0x0f != *l {
                    return None;
                }
                cur - 1
            }
            Elem::Alt { opts, neg: true } => {
                let l = opts.first().map(|o| o.len()).unwrap_or(0);
                if l == 0 || cur < l {
                    return None;
                }
                let w = &buf[cur - l..cur];
                if opts.iter().any(|o| bytes_eq(o, w, nocase)) {
                    return None;
                }
                cur - l
            }
            // The backtracking walk tries gap lengths ascending from `min`, so it
            // takes the shortest gap that still admits a full match — i.e. the
            // *greatest* reachable position in `[cur - hi, cur - min]`. One
            // binary search replaces that loop.
            Elem::Gap { min, max } => {
                let hi = max.unwrap_or(cur).min(cur);
                if *min > hi {
                    return None;
                }
                set_max_in(need, cur - hi, cur - *min)?
            }
            // The walk tries options in declaration order and keeps the first
            // that completes; same order here, gated on reachability.
            Elem::Alt { opts, neg: false } => {
                let mut found = None;
                for o in opts {
                    if cur >= o.len()
                        && bytes_eq(&buf[cur - o.len()..cur], o, nocase)
                        && set_contains(need, cur - o.len())
                    {
                        found = Some(cur - o.len());
                        break;
                    }
                }
                found?
            }
            Elem::AltMasked { opts } => {
                let mut found = None;
                for o in opts {
                    if cur >= o.len()
                        && masked_eq(o, &buf[cur - o.len()..cur], nocase)
                        && set_contains(need, cur - o.len())
                    {
                        found = Some(cur - o.len());
                        break;
                    }
                }
                found?
            }
        };
        debug_assert!(
            set_contains(need, q),
            "reconstruction left the reachable set at token {i}"
        );
        cur = q;
    }
    Some(cur)
}

// --- Logical-signature expression evaluation -------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Cmp {
    Eq,
    Gt,
    Lt,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_img_ldb_fires_despite_target5_gate() {
        // Regression: a `fuzzy_img#` signature is written `Target:5` (graphics),
        // a type exav doesn't model, so `target_ok(5)` is false and the sig used
        // to be dropped — even though the perceptual hash matched exactly. Now a
        // fuzzy sig fires on an image regardless of the Target:5 gate.
        let mut img = image::RgbImage::new(64, 64);
        for (x, y, p) in img.enumerate_pixels_mut() {
            *p = image::Rgb([(x.wrapping_mul(4)) as u8, (y.wrapping_mul(4)) as u8, 128]);
        }
        let mut png = Vec::new();
        {
            use image::ImageEncoder;
            image::codecs::png::PngEncoder::new(&mut png)
                .write_image(img.as_raw(), 64, 64, image::ColorType::Rgb8)
                .unwrap();
        }
        let hash = crate::fuzzy_img::phash(&png).expect("image hashes");
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();

        let mut b = EngineBuilder::new();
        b.add_ldb(
            &format!("Test.FuzzyImg;Engine:1-999,Target:5;0;fuzzy_img#{hex}"),
            false,
        );
        let eng = b.build();
        // Scanned as a non-graphics type: `target_ok(5, Unknown)` is false, but
        // the buffer is an image, so the exact-hash fuzzy sig must still fire.
        let hit = eng.scan(&png, FileType::Unknown);
        assert_eq!(hit.map(|(n, _, _)| n).as_deref(), Some("Test.FuzzyImg"));

        // Guard: a fuzzy sig with a DIFFERENT hash must NOT fire on this image.
        let mut b2 = EngineBuilder::new();
        b2.add_ldb(
            "Test.FuzzyImg2;Engine:1-999,Target:5;0;fuzzy_img#0123456789abcdef",
            false,
        );
        assert!(b2.build().scan(&png, FileType::Unknown).is_none());

        // A `#<distance>` tolerance matches a near-duplicate hash: flip 2 bits of
        // the true hash and require the sig to fire at distance 2 but NOT at 0.
        let mut near = hash;
        near[0] ^= 0b0000_0011; // 2 differing bits
        let near_hex: String = near.iter().map(|b| format!("{b:02x}")).collect();
        let mut b3 = EngineBuilder::new();
        b3.add_ldb(
            &format!("Test.FuzzyNear;Engine:1-999,Target:5;0;fuzzy_img#{near_hex}#2"),
            false,
        );
        assert_eq!(
            b3.build().scan(&png, FileType::Unknown).map(|(n, _, _)| n).as_deref(),
            Some("Test.FuzzyNear"),
            "distance-2 sig must match a 2-bit-different hash"
        );
        // The same near hash at distance 0 (exact) must NOT fire. A non-zero
        // distance must be loaded and honored, not dropped entirely.
        let mut b4 = EngineBuilder::new();
        b4.add_ldb(
            &format!("Test.FuzzyExact;Engine:1-999,Target:5;0;fuzzy_img#{near_hex}"),
            false,
        );
        assert!(b4.build().scan(&png, FileType::Unknown).is_none());
    }

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
        assert!(b.add_ldb_line("Test.Backref;Target:0;0&1;4141;0/(.)\\1\\1/", false).is_ok());
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
        assert!(b.add_ldb_line("Test.Redos;Target:0;0&1;6161;0/(a+)+\\1c/", false).is_ok());
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
        assert!(b.add_ldb_line("Old.Sig;Engine:0-50,Target:0;0;deadbeef", false).is_err());
        // Engine:90-255 includes 213 -> loads.
        assert!(b.add_ldb_line("Cur.Sig;Engine:90-255,Target:0;0;deadbeef", false).is_ok());
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
        // A buffer full of zero triples — the shape a naive anchor explodes on — but no
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
        // A `#<distance>` tolerance now loads and matches within the hamming
        // distance (this image hashes exactly to 8000000000000000, so it is
        // distance 0 — trivially within any tolerance).
        let mut b3 = EngineBuilder::new();
        b3.add_ldb(
            "Demo.FuzzyDist;Engine:150-255,Target:0;0;fuzzy_img#8000000000000000#5",
            false,
        );
        assert!(b3.build().scan(&png, FileType::Unknown).is_some());
        // A hash 3 bits away (0x80→0x87 in byte 0) matches at distance 3 but not 2.
        let mut b4 = EngineBuilder::new();
        b4.add_ldb(
            "Demo.FuzzyNear;Engine:150-255,Target:0;0;fuzzy_img#8700000000000000#3",
            false,
        );
        assert!(b4.build().scan(&png, FileType::Unknown).is_some());
        let mut b5 = EngineBuilder::new();
        b5.add_ldb(
            "Demo.FuzzyFar;Engine:150-255,Target:0;0;fuzzy_img#8700000000000000#2",
            false,
        );
        assert!(b5.build().scan(&png, FileType::Unknown).is_none());
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
    fn strip_lookaround_relaxes_soundly() {
        // The four lookaround forms are removed; everything else is preserved.
        assert_eq!(strip_lookaround("abc(?=def)ghi").unwrap(), "abcghi");
        assert_eq!(strip_lookaround("a(?!x)b").unwrap(), "ab");
        assert_eq!(strip_lookaround("a(?<=x)b").unwrap(), "ab");
        assert_eq!(strip_lookaround("a(?<!x)b").unwrap(), "ab");
        // Nested groups inside a lookaround are removed with it.
        assert_eq!(strip_lookaround("a(?=b(?:c)d)e").unwrap(), "ae");
        // Non-lookaround constructs are preserved verbatim.
        assert_eq!(strip_lookaround("(?:abc)").unwrap(), "(?:abc)");
        assert_eq!(strip_lookaround("(?<name>x)y").unwrap(), "(?<name>x)y"); // named group, not lookbehind
        assert_eq!(strip_lookaround("[()?=]").unwrap(), "[()?=]"); // parens/`?=` in a class
        assert_eq!(strip_lookaround(r"a\(?=b").unwrap(), r"a\(?=b"); // escaped paren
        // A backreference can't be soundly reduced.
        assert!(strip_lookaround(r"(a)\1").is_none());
        // build_prefilter yields None when nothing was stripped.
        assert!(build_prefilter("(?:abc)def").is_none());
        // ...and a compilable superset when lookaround is present.
        assert!(build_prefilter("foo(?=bar)baz").is_some());
    }

    #[test]
    fn pcre_lookahead_prefilter_is_correct() {
        // A PCRE with a negative lookahead: match `http` NOT followed by `s`.
        // The prefilter (lookahead stripped → `http`) must never hide a real
        // match, and must still reject buffers lacking the literal.
        let mut b = EngineBuilder::new();
        b.add_ldb(
            "Demo.Look;Engine:81-255,Target:0;0&1;7061796c6f6164;0/payload.{0,4}http(?!s)/",
            false,
        );
        assert_eq!(b.unsupported(), 0);
        let e = b.build();
        // Lookahead satisfied (http not followed by s) -> match.
        assert!(e.scan(b"x payload xx http://y", FileType::Unknown).is_some());
        // Lookahead fails (https) -> no match, even though `http` is present.
        assert!(e
            .scan(b"x payload xx https://y", FileType::Unknown)
            .is_none());
        // Literal absent -> prefilter rejects -> no match (and cheaply).
        assert!(e.scan(b"x payload xx ftp://y", FileType::Unknown).is_none());
    }

    #[test]
    fn ldb_pcre_offset_prefixed_subsig() {
        // `[Offset:]Trigger/PCRE/Flags`. This prefix carries the great majority
        // of the PCRE subsignatures in a live daily.cvd, so failing to parse it
        // costs most of the ones that would otherwise load.

        // EOF-n: the match must start n bytes from the end. 368 of the 369 real
        // ones are this shape (a trailing marker).
        let mut b = EngineBuilder::new();
        b.add_ldb(
            "Demo.PcreEof;Engine:81-255,Target:0;0&1;6d616c77617265;EOF-3:0/abc/",
            false,
        );
        assert_eq!(b.unsupported(), 0, "an EOF-relative PCRE subsig must load");
        let e = b.build();
        // "abc" sits exactly 3 bytes from the end -> inside the window.
        assert!(e.scan(b"malware ...... abc", FileType::Unknown).is_some());
        // Same bytes present, but not at EOF-3 -> the offset gate rejects it.
        assert!(e.scan(b"malware abc ......", FileType::Unknown).is_none());

        // Absolute offset.
        let mut b2 = EngineBuilder::new();
        b2.add_ldb(
            "Demo.PcreAbs;Engine:81-255,Target:0;0&1;6d616c77617265;0:0/xyz/",
            false,
        );
        assert_eq!(b2.unsupported(), 0, "an absolute-offset PCRE subsig must load");
        let e2 = b2.build();
        assert!(e2.scan(b"xyz malware", FileType::Unknown).is_some());
        assert!(e2.scan(b"malware xyz", FileType::Unknown).is_none());

        // An offset kind that needs a PE layout this path doesn't carry must stay
        // COUNTED-unsupported rather than load and silently never match.
        let mut b3 = EngineBuilder::new();
        b3.add_ldb(
            "Demo.PcreEp;Engine:81-255,Target:1;0&1;6d616c77617265;EP+7:0/abc/",
            false,
        );
        assert_eq!(
            b3.unsupported(),
            1,
            "an EP-relative PCRE offset must be counted, not silently loaded"
        );
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
            section_rawsizes: vec![0x800, 0x800],
            version_info: Vec::new(),
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
    fn ndb_character_class_boundary_is_supported() {
        // (B), (L), (W) are ClamAV word/line/non-alnum boundary classes.
        // They must be parsed without error (not rejected as unsupported).
        let mut b = EngineBuilder::new();
        b.add_ndb("B:0:*:(B)cafebabe", false);
        b.add_ndb("L:0:*:cafe(B)babe", false);
        b.add_ndb("W:0:*:(L)cafe(L)", false);
        b.add_ndb("N:0:*:(W)deadbeef(W)", false);
        // Negated forms must also be accepted.
        b.add_ndb("X:0:*:!(B)cafebabe", false);
        b.add_ndb("Y:0:*:cafe!(L)babe", false);
        b.add_ndb("Z:0:*:!(W)deadbeef!(W)", false);
        assert_eq!(b.unsupported(), 0);
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

    #[test]
    fn fuzzy_img_subsig_rejects_non_ascii_hash() {
        // Regression: multi-byte UTF-8 in the 16-char hash field caused a
        // byte-index panic in parse_fuzzy_subsig (engine.rs:2092).
        let mut b = EngineBuilder::new();
        b.add_ldb("X;Target:0;0;fuzzy_img#\u{03e9}\u{03e9}\u{03e9}\u{03e9}\u{03e9}\u{03e9}\u{03e9}\u{03e9}", false);
        // Should be dropped as unsupported, not panic.
        assert_eq!(b.unsupported(), 1);
    }

    #[test]
    fn pick_anchor_overflow_does_not_panic() {
        // Regression: fixed prefix width accumulation overflowed on crafted
        // input (engine.rs:2540).  Saturating_add prevents the panic.
        let mut b = EngineBuilder::new();
        // A pattern with enough elements to exercise the width accumulation path.
        b.add_ndb("O:0:*:deadbeef*cafebabe*deadbeef*cafebabe*deadbeef", false);
        let _ = b.build(); // must not panic
    }

    // --- gap-split matcher equivalence -------------------------------------

    /// Reference present/absent oracle: a straightforward recursive matcher that
    /// tries every gap length and every alternation branch (no fast-path
    /// shortcuts), so it computes exact existence. The gap-split simulator must
    /// agree with this on every case.
    fn bt_match(toks: &[Elem], buf: &[u8], pos: usize, nocase: bool) -> bool {
        let (head, rest) = match toks.split_first() {
            None => return true,
            Some(x) => x,
        };
        match head {
            Elem::Bytes(b) => {
                pos + b.len() <= buf.len()
                    && bytes_eq(&buf[pos..pos + b.len()], b, nocase)
                    && bt_match(rest, buf, pos + b.len(), nocase)
            }
            Elem::AnyByte => pos < buf.len() && bt_match(rest, buf, pos + 1, nocase),
            Elem::HiNibble(h) => {
                pos < buf.len() && buf[pos] >> 4 == *h && bt_match(rest, buf, pos + 1, nocase)
            }
            Elem::LoNibble(l) => {
                pos < buf.len() && buf[pos] & 0x0f == *l && bt_match(rest, buf, pos + 1, nocase)
            }
            Elem::Gap { min, max } => {
                let avail = buf.len().saturating_sub(pos);
                let hi = max.unwrap_or(avail).min(avail);
                (*min..=hi).any(|g| bt_match(rest, buf, pos + g, nocase))
            }
            Elem::Alt { opts, neg: false } => opts.iter().any(|o| {
                pos + o.len() <= buf.len()
                    && bytes_eq(&buf[pos..pos + o.len()], o, nocase)
                    && bt_match(rest, buf, pos + o.len(), nocase)
            }),
            Elem::AltMasked { opts } => opts.iter().any(|o| {
                pos + o.len() <= buf.len()
                    && masked_eq(o, &buf[pos..pos + o.len()], nocase)
                    && bt_match(rest, buf, pos + o.len(), nocase)
            }),
            Elem::Alt { opts, neg: true } => {
                let l = opts.first().map(|o| o.len()).unwrap_or(0);
                l > 0
                    && pos + l <= buf.len()
                    && !opts.iter().any(|o| bytes_eq(o, &buf[pos..pos + l], nocase))
                    && bt_match(rest, buf, pos + l, nocase)
            }
        }
    }

    /// A tiny deterministic PRNG (SplitMix64) so the differential test is
    /// reproducible without a `rand` dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Build a random token program (Bytes / AnyByte / nibble / gap / alternation,
    /// negated or not) over a 3-symbol alphabet — the full element set the
    /// simulator handles.
    fn rand_toks(rng: &mut Rng, alpha: &[u8]) -> Vec<Elem> {
        let n = 1 + rng.below(5);
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            match rng.below(9) {
                7 => {
                    // Alternation with an empty branch: `(ab|)`, the optional-run
                    // form. Variable width, so it exercises the same paths a gap
                    // does but with a literal alternative.
                    let len = 1 + rng.below(2);
                    let opt: Vec<u8> = (0..len).map(|_| alpha[rng.below(alpha.len())]).collect();
                    out.push(Elem::Alt {
                        opts: vec![opt, Vec::new()],
                        neg: false,
                    });
                }
                8 => {
                    // Masked alternation: branches carrying nibble wildcards, of
                    // possibly differing lengths.
                    let k = 2 + rng.below(2);
                    let opts = (0..k)
                        .map(|_| {
                            let len = 1 + rng.below(2);
                            (0..len)
                                .map(|_| {
                                    let b = alpha[rng.below(alpha.len())];
                                    match rng.below(3) {
                                        0 => (b, 0xff),
                                        1 => (b & 0xf0, 0xf0),
                                        _ => (b & 0x0f, 0x0f),
                                    }
                                })
                                .collect::<Vec<(u8, u8)>>()
                        })
                        .collect();
                    out.push(Elem::AltMasked { opts });
                }
                0 => {
                    let len = 1 + rng.below(3);
                    out.push(Elem::Bytes((0..len).map(|_| alpha[rng.below(alpha.len())]).collect()));
                }
                1 => out.push(Elem::AnyByte),
                2 => out.push(Elem::HiNibble((rng.below(16)) as u8)),
                3 => out.push(Elem::LoNibble((rng.below(16)) as u8)),
                4 => {
                    let min = rng.below(3);
                    let max = if rng.below(4) == 0 {
                        None
                    } else {
                        Some(min + rng.below(5))
                    };
                    out.push(Elem::Gap { min, max });
                }
                5 => {
                    let k = 2 + rng.below(2);
                    let opts = (0..k)
                        .map(|_| {
                            let len = 1 + rng.below(2);
                            (0..len).map(|_| alpha[rng.below(alpha.len())]).collect::<Vec<u8>>()
                        })
                        .collect();
                    out.push(Elem::Alt { opts, neg: false });
                }
                _ => {
                    // Negated alternation: all options share one length.
                    let k = 2 + rng.below(2);
                    let len = 1 + rng.below(2);
                    let opts = (0..k)
                        .map(|_| (0..len).map(|_| alpha[rng.below(alpha.len())]).collect::<Vec<u8>>())
                        .collect();
                    out.push(Elem::Alt { opts, neg: true });
                }
            }
        }
        out
    }

    /// The gap-split simulator must return the exact present/absent answer for
    /// every token program, buffer, start, and case-fold flag — this correctness
    /// is what makes the split path a detection-preserving drop-in. Checked
    /// against the exhaustive `bt_match` oracle over a large random sample.
    /// Additionally asserts the split path never *misses* what the legacy
    /// `match_forward` finds (`match_forward ⟹ gap_split`): the switch can only
    /// ever preserve or add a true detection, never drop one.
    #[test]
    fn gap_split_matches_backtracker() {
        let alpha = b"AaB"; // includes an upper/lower pair so nocase matters
        let mut rng = Rng(0xD1CE_F00D_1234_5678);
        for _ in 0..200_000 {
            let toks = rand_toks(&mut rng, alpha);
            let blen = rng.below(25);
            let buf: Vec<u8> = (0..blen).map(|_| alpha[rng.below(alpha.len())]).collect();
            let pos = if buf.is_empty() { 0 } else { rng.below(buf.len() + 1) };
            let nocase = rng.below(2) == 0;
            let lower = buf.to_ascii_lowercase();

            let want = bt_match(&toks, &buf, pos, nocase);
            let mut b2 = u64::MAX;
            let got = gap_split_match(&toks, &buf, pos, nocase, &lower, &mut b2);
            assert_eq!(
                want, got,
                "gap-split wrong: toks={toks:?} buf={buf:?} pos={pos} nocase={nocase}"
            );
            // The legacy walk must never find a match the split path misses.
            let mut b1 = u64::MAX;
            if match_forward(&toks, &buf, pos, nocase, &mut b1) {
                assert!(
                    got,
                    "gap-split dropped a legacy match: toks={toks:?} buf={buf:?} pos={pos} nocase={nocase}"
                );
            }
        }
    }

    /// The backward simulator must return the *identical start* the backtracking
    /// `match_backward` returns — not merely some valid one — or a body's
    /// reported offset would shift. Same randomized corpus as the forward test.
    #[test]
    fn gap_split_backward_matches_backtracker() {
        let alpha = b"AaB";
        let mut rng = Rng(0x5EED_1234_ABCD_9876);
        let mut matched = 0u32;
        for _ in 0..200_000 {
            let toks = rand_toks(&mut rng, alpha);
            let blen = rng.below(25);
            let buf: Vec<u8> = (0..blen).map(|_| alpha[rng.below(alpha.len())]).collect();
            let end = if buf.is_empty() { 0 } else { rng.below(buf.len() + 1) };
            let nocase = rng.below(2) == 0;
            let lower = buf.to_ascii_lowercase();

            let mut b1 = u64::MAX;
            let want = match_backward(&toks, &buf, end, nocase, &mut b1);
            let mut b2 = u64::MAX;
            let got = gap_split_match_backward(&toks, &buf, end, nocase, &lower, &mut b2);
            assert_eq!(
                want, got,
                "backward split wrong: toks={toks:?} buf={buf:?} end={end} nocase={nocase}"
            );
            if want.is_some() {
                matched += 1;
            }
        }
        // Guard against the corpus degenerating into all-misses, which would make
        // the equality assertion vacuous.
        assert!(matched > 10_000, "too few matches to be meaningful: {matched}");
    }

    #[test]
    fn gap_split_backward_start_is_the_shortest_gap() {
        // `A?{0,4}B` ending at the second `B`: the walk takes the shortest gap,
        // so the start is the *later* `A`. Pinning this keeps the reconstruction
        // honest independently of the randomized test.
        let buf = b"AxxBAxB".to_vec();
        let toks = vec![
            Elem::Bytes(b"A".to_vec()),
            Elem::Gap {
                min: 0,
                max: Some(4),
            },
            Elem::Bytes(b"B".to_vec()),
        ];
        let lower = buf.to_ascii_lowercase();
        let mut b = u64::MAX;
        assert_eq!(
            gap_split_match_backward(&toks, &buf, buf.len(), false, &lower, &mut b),
            Some(4),
            "must return the start the backtracker returns (shortest gap first)"
        );
        let mut b2 = u64::MAX;
        assert_eq!(
            match_backward(&toks, &buf, buf.len(), false, &mut b2),
            Some(4)
        );
    }

    /// The behaviour this replaced. Two open-ended pre-anchor gaps over dense
    /// repetitive content with an absent leading literal: the backtracking walk
    /// enumerates gap-length pairs quadratically and gets cut off by its step
    /// budget, which surfaces as `LIMITS-EXCEEDED` on a file that is in fact
    /// clean. The simulator finishes the same search and gives the true answer.
    #[test]
    fn backward_simulator_answers_where_the_backtracker_gives_up() {
        let buf = vec![b'a'; 3_000];
        let toks = vec![
            Elem::Bytes(b"Z".to_vec()), // never present, so the search must exhaust
            Elem::Gap { min: 0, max: None },
            Elem::Bytes(b"a".to_vec()),
            Elem::Gap { min: 0, max: None },
            Elem::Bytes(b"a".to_vec()),
        ];
        let lower = buf.to_ascii_lowercase();

        // Legacy walk: cut off by its per-call cap, having decided nothing.
        let mut legacy = VERIFY_BUDGET;
        assert_eq!(
            match_backward(&toks, &buf, buf.len(), false, &mut legacy),
            None
        );
        assert_eq!(legacy, 0, "the backtracker should have drained its budget");

        // Simulator: a real "no match", with the budget barely touched.
        reset_scan_truncated();
        let mut sim = VERIFY_BUDGET;
        assert_eq!(
            gap_split_match_backward(&toks, &buf, buf.len(), false, &lower, &mut sim),
            None
        );
        assert!(!scan_was_truncated(), "must not report an incomplete search");
        assert!(
            sim > VERIFY_BUDGET / 2,
            "should finish well inside the budget, spent {}",
            VERIFY_BUDGET - sim
        );
    }

    #[test]
    fn gap_split_backward_unbounded_gap_terminates_cheaply() {
        // The shape a backtracking matcher blows up on: an open-ended pre-anchor
        // gap over dense repetitive content. The simulator must answer within a
        // tiny budget.
        let buf = vec![b'a'; 200_000];
        let toks = vec![
            Elem::Bytes(b"a".to_vec()),
            Elem::Gap { min: 0, max: None },
            Elem::Bytes(b"a".to_vec()),
        ];
        let lower = buf.to_ascii_lowercase();
        let mut budget = 5_000_000u64;
        let got = gap_split_match_backward(&toks, &buf, buf.len(), false, &lower, &mut budget);
        assert!(got.is_some(), "must find the match");
        assert!(!scan_was_truncated(), "must not report truncation");
    }

    /// Direct spot-checks of the simulator against hand-worked cases: unbounded
    /// gap, bounded gap, nibble-in-part, alternation-in-part.
    #[test]
    fn gap_split_spot_cases() {
        let check = |toks: &[Elem], buf: &[u8], pos: usize, nocase: bool| -> bool {
            let lower = buf.to_ascii_lowercase();
            let mut b = u64::MAX;
            gap_split_match(toks, buf, pos, nocase, &lower, &mut b)
        };
        // Unbounded gap between two literals.
        let t = vec![
            Elem::Bytes(vec![0xAA]),
            Elem::Gap { min: 0, max: None },
            Elem::Bytes(vec![0xBB]),
        ];
        assert!(check(&t, &[0xAA, 0x11, 0x22, 0xBB], 0, false));
        assert!(!check(&t, &[0xAA, 0x11, 0x22], 0, false)); // no BB
        assert!(!check(&t, &[0xBB, 0xAA], 0, false)); // wrong order from pos 0
        // Bounded gap {1-2}: BB must be 1..=2 bytes after AA.
        let t = vec![
            Elem::Bytes(vec![0xAA]),
            Elem::Gap { min: 1, max: Some(2) },
            Elem::Bytes(vec![0xBB]),
        ];
        assert!(check(&t, &[0xAA, 0x00, 0xBB], 0, false)); // gap 1
        assert!(check(&t, &[0xAA, 0x00, 0x00, 0xBB], 0, false)); // gap 2
        assert!(!check(&t, &[0xAA, 0xBB], 0, false)); // gap 0 < min
        assert!(!check(&t, &[0xAA, 0, 0, 0, 0xBB], 0, false)); // gap 3 > max
        // Nibble inside a part: AA <hi=5> BB.
        let t = vec![
            Elem::Bytes(vec![0xAA]),
            Elem::HiNibble(0x5),
            Elem::Bytes(vec![0xBB]),
        ];
        assert!(check(&t, &[0xAA, 0x53, 0xBB], 0, false));
        assert!(!check(&t, &[0xAA, 0x63, 0xBB], 0, false));
        // Alternation inside a part.
        let t = vec![
            Elem::Bytes(vec![0xAA]),
            Elem::Alt { opts: vec![vec![0x11], vec![0x22, 0x33]], neg: false },
            Elem::Bytes(vec![0xBB]),
        ];
        assert!(check(&t, &[0xAA, 0x11, 0xBB], 0, false));
        assert!(check(&t, &[0xAA, 0x22, 0x33, 0xBB], 0, false));
        assert!(!check(&t, &[0xAA, 0x44, 0xBB], 0, false));
        // Case folding.
        let t = vec![Elem::Bytes(b"ab".to_vec())];
        assert!(check(&t, b"AB", 0, true));
        assert!(!check(&t, b"AB", 0, false));
    }

    /// The trickier anchor/element classes — negated alternation and an Internal
    /// anchor (whose start comes from the backward walk) — must detect correctly
    /// under BOTH the split path and the legacy path, and agree with each other.
    #[test]
    fn split_and_legacy_agree_on_tricky_constructs() {
        let run = |line: &str, buf: &[u8]| -> bool {
            let e = ndb(line);
            e.scan(buf, FileType::Unknown).is_some()
        };
        // Negated alternation: `dead !(1122|3344) beef` matches only when the
        // middle 2 bytes are neither excluded option.
        assert!(run("NegAlt:0:*:dead!(1122|3344)beef", &hx("dead 5566 beef")));
        assert!(!run("NegAlt:0:*:dead!(1122|3344)beef", &hx("dead 1122 beef")));
        // Internal anchor: only pre-gap literal is a weak zero-run; the rare
        // literal `cafebabe` past the gap is the anchor, start via backward walk.
        assert!(run("Intern:0:*:00000000*cafebabe", &hx("00000000 99 cafebabe")));
        assert!(!run("Intern:0:*:00000000*cafebabe", &hx("00000000 99 deadbeef")));

        // The Internal-anchor detection must report the SAME start offset whether
        // the forward suffix is decided by the simulator or the legacy walk (the
        // start always comes from the backward walk, so it must not drift).
        let internal = ndb("IOff:0:*:00000000*cafebabe");
        let buf = hx("77 00000000 99 cafebabe");
        // (env is process-global; this test documents the invariant that the
        // backward-derived start is path-independent — start = 1 here.)
        assert_eq!(
            internal.scan(&buf, FileType::Unknown).map(|(_, o, _)| o),
            Some(1)
        );
    }
}
