//! Streaming, size-unbounded file scanner.
//!
//! Every input goes through one scan, [`scan_seekable`] ([`scan_path`] opens a
//! file and hands it over), and every object in it, the input and whatever is
//! unpacked from it, goes through the same pipeline whatever its size: an
//! object within `limits.max_buffer_bytes` ([`ScanOptions::limits`]) is held in memory, a larger
//! one is read through a block cache of bounded size (or, for a decoded member,
//! a spill file), and a container's members are decoded as they are read. The
//! checks that parse an object whole (a container format read whole) do not
//! run on one over that limit, nor do a PE's structure checks when its image,
//! the part up to the end of its last section, is over it, and a scan that
//! finds nothing is then reported `LimitsExceeded`.
//!
//! # Anti-evasion invariants
//!
//! A scanner's limits are an attack surface: anything that makes the scanner
//! *stop looking* is a bypass primitive an adversary will reach for (pad past a
//! size cap, nest past a depth cap, use an unsupported codec, …). These rules
//! are therefore security properties rather than ergonomics:
//!
//! 1. **A detection always beats a limit.** If a signature matches, the verdict
//!    is [`Verdict::Infected`], never downgraded to `LimitsExceeded`/`Clean`
//!    because some *other* part of the input tripped a budget. Limits bound
//!    work; they never suppress a hit already found.
//! 2. **Never refuse by size without scanning.** An input over
//!    `--max-input-bytes` is not skipped wholesale: its first
//!    `--max-input-bytes` get the same scan as a smaller input, so a
//!    detectable payload there is reported. Only then, with nothing found, do
//!    we fall back to a limit verdict. (Otherwise `cat malware huge.pad > evil`
//!    is a one-line bypass.)
//! 3. **Not-fully-scanned is never `Clean`.** Anything we couldn't fully examine
//!    (a size/ratio/depth/scan-byte limit, [`Verdict::LimitsExceeded`], or a
//!    recognised-but-undecodable container, [`Verdict::Unscannable`], e.g. an
//!    unsupported codec or encryption) yields a distinct non-clean verdict.
//!    Callers must treat both as suspicious, never as a pass.
//!
//! Sizes and limits are 64-bit; an input a 32-bit build cannot address is
//! reported over the limit (see [`scan_seekable`]).

// The engine and every parser it drives are safe Rust. Enforce it: hostile
// input must never reach an `unsafe` block here (the only `unsafe` in the
// workspace is the CLI daemon's libc syscalls). `exav-unpack` forbids it too.
#![forbid(unsafe_code)]

// ---- Stable public API surface -------------------------------------------
// These modules are covered by semver. `filetype` is public because it is
// returned by `Scanner::identify`.
/// Authenticode (PE code-signing) triage without RSA: recompute the PE hash and
/// compare it to the signature's embedded digest, and extract signer-cert fields.
pub mod authenticode;
pub mod database;
/// Opt-in structured-data (DLP) heuristics: credit-card / SSN counting, a
/// data-exfiltration signal.
#[cfg(feature = "dlp")]
pub mod dlp;
pub mod filetype;
pub mod loader;
#[cfg(feature = "phishing")]
pub mod phishing;
pub mod profile;
pub mod source;
pub mod spill;
/// Temp files for the test suite, so testing needs no temp-file dependency.
#[cfg(test)]
mod tmpfile;
/// Archive/container extraction lives in its own crate; re-exported so
/// `exav_core::unpack` and the `ScanOptions::limits` type stay stable.
pub use exav_unpack as unpack;

/// The largest object a scan copies lowercased while matching it; a larger
/// one is lowercased as it is read. With an image's decoded pixels, the only
/// memory matching takes beside the object itself.
pub const LOWERCASE_COPY_MAX: u64 = engine::LOWER_COPY_MAX as u64;

// ---- Engine internals (NOT a stable API) ---------------------------------
// The signature IR/matcher, bytecode interpreter, and parsing primitives. They
// are crate-private by default and only exposed as `pub` under the
// `unstable-internals` feature (for tooling / the in-crate examples); no semver
// guarantee applies to them. See the feature docs in Cargo.toml.
macro_rules! engine_internals {
    ($($m:ident),+ $(,)?) => {
        $(
            #[cfg(feature = "unstable-internals")]
            pub mod $m;
            // Without the feature these modules are crate-private. Many of their
            // `pub` items exist for the unstable-internals surface / examples and
            // so are unused within the lean build; don't warn on that (they are
            // exercised again once the feature re-exposes them). Scoped to the
            // engine internals only, so real dead code elsewhere still warns.
            #[cfg(not(feature = "unstable-internals"))]
            #[allow(dead_code, unused_imports, clippy::wrong_self_convention)]
            mod $m;
        )+
    };
}
engine_internals!(
    bytecode, container, cvd, engine, fuzzy, hashes, hexsig, icon, jsnorm, ml, normalize, patterns,
    pe,
);

mod byte_source;
mod bytes;
// For the vendored fancy-regex, written against `alloc`.
extern crate alloc;
/// fancy-regex with fixes it has not released yet, vendored as upstream wrote
/// it: see `fancy_regex/README.md`.
#[allow(dead_code, unused_imports, private_interfaces, clippy::all)]
#[rustfmt::skip]
mod fancy_regex;
mod grams;
mod mail_inside;
mod pass;
mod stream_regex;

// YARA rule support. The native engine (compiler/scanner/modules) lives in-tree
// under `src/yara/`. This module is `pub` (not an `engine_internals!` member) so
// that a consumer who wants YARA alone can reach the compiler and scanner
// without going through a scan. It is ALWAYS compiled: the `yara::YaraDb` type
// is part of the on-disk database format regardless of the `yara` feature,
// while the actual compiler/matcher submodules inside it are gated on `feature = "yara"`.
pub mod yara;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use byte_source::ByteSource;
use filetype::FileType;
use fuzzy::FuzzyDb;
#[cfg(test)]
use hashes::digests_of;
use hashes::{HashDb, SectionHashDb};
use ml::Model;
use unpack::Budget;
use unpack::tree;

/// Default of [`ScanOptions::min_scan_bytes`]: clamscan scans no object
/// under 6 bytes, top-level file or member, whatever the signature type.
pub const MIN_SCAN_BYTES: u64 = 6;

/// Default of [`ScanOptions::max_qr_pixels`]: exav-render's. This and the four
/// below exist with the `qr` feature, the only build that reads QR codes;
/// without it the options default to no limit and nothing reads them.
#[cfg(feature = "qr")]
pub const DEFAULT_MAX_QR_PIXELS: u64 = exav_render::qr::DEFAULT_MAX_PIXELS;
/// Default of [`ScanOptions::max_qr_millis`].
#[cfg(feature = "qr")]
pub const DEFAULT_MAX_QR_MILLIS: u64 = exav_render::qr::DEFAULT_MAX_TIME.as_millis() as u64;
/// Default of [`ScanOptions::max_qr_codes`].
#[cfg(feature = "qr")]
pub const DEFAULT_MAX_QR_CODES: u64 = exav_render::qr::DEFAULT_MAX_CODES as u64;
/// Default of [`ScanOptions::max_qr_finders`].
#[cfg(feature = "qr")]
pub const DEFAULT_MAX_QR_FINDERS: u64 = exav_render::qr::DEFAULT_MAX_FINDERS as u64;
/// Default of [`ScanOptions::max_qr_grids`].
#[cfg(feature = "qr")]
pub const DEFAULT_MAX_QR_GRIDS: u64 = exav_render::qr::DEFAULT_MAX_GRIDS as u64;

/// A QR option's default: `Some` of the constant with the `qr` feature, else no
/// limit.
macro_rules! qr_default {
    ($constant:ident) => {{
        #[cfg(feature = "qr")]
        {
            Some($constant)
        }
        #[cfg(not(feature = "qr"))]
        {
            None
        }
    }};
}

/// Smallest object a whole-file hash signature (`.hdb`/`.hsb`) may be matched
/// against, whatever [`ScanOptions::min_scan_bytes`] is.
///
/// ClamAV scans no object under 6 bytes, so a hash signature with a smaller
/// declared size never fires there; a current main+daily set has six. Matched
/// on a short object they are false positives, measured on inputs ClamAV
/// reports OK:
///
///   * a 1-byte file holding `V` matched `Win.Trojan.Agent-1720205`;
///   * the 2 bytes `\x00\x00` that a benign PDF's 2x2 image XObject decodes to
///     matched `Win.Malware.Agent-7761897-0`.
///
/// The allow-list (`.fp`/`.sfp`) is matched with the same machinery and is
/// not floored: a suppression that stopped working would cause exactly the
/// false positives this prevents.
const MIN_HASH_MATCH_BYTES: u64 = 6;

/// What a scan reports when a per-buffer bound (the step pool, or the
/// repeated-anchor cap) ended the signature search before it finished.
///
/// Shared by the single-verdict and all-match paths so the two cannot drift
/// apart in what they call the same condition.
const SEARCH_INCOMPLETE: &str = "scan budget exhausted, signature search incomplete";

/// Whether a whole-file hash signature may be matched against an object of
/// this size. See [`MIN_HASH_MATCH_BYTES`].
fn hash_matchable(size: u64) -> bool {
    size >= MIN_HASH_MATCH_BYTES
}

/// What the scan of one object works out about all of it, once however many
/// steps ask. Each costs a read of the whole object, which for one not held in
/// memory is a read of its whole source: for such an object, the first step to
/// ask makes one read for all of them.
pub(crate) struct Facts<'a> {
    data: &'a dyn ByteSource,
    /// What [`unpack::detect`] makes of it: it reads the start of the object,
    /// its end, and the places its structure names.
    fmt: std::cell::OnceCell<Option<unpack::Format>>,
    /// Its whole-object digests, for the allowlist and the hash signatures.
    digests: std::cell::OnceCell<hashes::Digests>,
    /// What carving finds in it.
    embedded: std::cell::RefCell<Option<pe::Embedded>>,
    /// How many of each kind carving lists.
    caps: pe::CarveCaps,
    /// What the search for a message inside it found in the one read, until a
    /// step asks.
    mail: std::cell::RefCell<Option<mail_inside::Search>>,
    /// For an object not held in memory, what the one read is for, until it
    /// is made.
    shared: std::cell::Cell<Option<Shared>>,
    /// What the matching core will run over the object, until the read that
    /// feeds the signature sweep and YARA's patterns is made.
    matching: std::cell::Cell<Option<pass::Matching<'a>>>,
    /// What the signature engine found in that read, until the core takes it.
    engine_run: std::cell::RefCell<Option<pass::EngineRun>>,
    /// What that read found of YARA's patterns: those slated to run, and
    /// their matches.
    yara_pass: std::cell::RefCell<Option<yara::YaraPass>>,
    /// Whether the object holds a UPX pack header in its start: known once
    /// detection has read the start, else once asked.
    upx: std::cell::OnceCell<bool>,
    /// How often each byte occurs in it, when that read counted them.
    counts: std::cell::OnceCell<Box<[u64; 256]>>,
}

/// What the one read of an object not held in memory computes: the digests
/// `want` names, carving's search when `carve`, and the search for a message
/// inside it when `mail`.
#[derive(Clone, Copy)]
struct Shared {
    want: hashes::Want,
    carve: bool,
    /// Far candidates carving holds before it checks them.
    far: usize,
    /// Count the bytes, for the static model.
    counts: bool,
    /// Search for a message inside it, as clamscan reads one from a text file.
    mail: bool,
    /// How many of each kind carving lists.
    caps: pe::CarveCaps,
}

impl<'a> Facts<'a> {
    /// The facts of `data`, each worked out by a read of its own when asked.
    pub(crate) fn new(data: &'a dyn ByteSource) -> Self {
        Facts {
            data,
            fmt: std::cell::OnceCell::new(),
            digests: std::cell::OnceCell::new(),
            embedded: std::cell::RefCell::new(None),
            caps: pe::CarveCaps::default(),
            mail: std::cell::RefCell::new(None),
            shared: std::cell::Cell::new(None),
            matching: std::cell::Cell::new(None),
            engine_run: std::cell::RefCell::new(None),
            yara_pass: std::cell::RefCell::new(None),
            upx: std::cell::OnceCell::new(),
            counts: std::cell::OnceCell::new(),
        }
    }

    /// The facts of `data` scanned by `db`, carved when `carve`: when `data`
    /// is not held in memory, all worked out in one read of it.
    fn for_scan(data: &'a dyn ByteSource, db: &Scanner, carve: bool, opts: &ScanOptions) -> Self {
        let mut facts = Facts::new(data);
        facts.caps = pe::CarveCaps::of(&opts.limits);
        if data.as_slice().is_none() {
            // Only an executable has its bytes counted for the static model.
            let executable = data.window(0, 2).as_ref() == b"MZ";
            facts.shared.set(Some(Shared {
                want: digests_wanted_by(db, data.len() as u64),
                carve,
                far: opts.carve_pending(),
                counts: executable && opts.heuristics,
                mail: cfg!(feature = "email") && !executable,
                caps: facts.caps,
            }));
        }
        facts
    }

    pub(crate) fn format(&self) -> Option<unpack::Format> {
        *self.fmt.get_or_init(|| {
            let (format, upx) = unpack::detect_with_upx(self.data);
            if let Some(upx) = upx {
                let _ = self.upx.set(upx);
            }
            format
        })
    }

    /// The digests the allowlist and the hash signatures of `db` can match at
    /// this object's size, all computed in one read of it, and none that no
    /// signature there could use.
    fn digests(&self, db: &Scanner) -> &hashes::Digests {
        // Wanting none reads nothing: no reason to make the read yet.
        if self
            .shared
            .get()
            .is_some_and(|s| s.want != hashes::Want::default())
        {
            self.read_once(pass::Why::Search);
        }
        self.digests.get_or_init(|| {
            hashes::digests_wanted(self.data, digests_wanted_by(db, self.data.len() as u64))
        })
    }

    /// What carving finds in the object, taken: carving runs once.
    fn embedded(&self) -> pe::Embedded {
        self.read_once(pass::Why::Search);
        self.embedded
            .take()
            .unwrap_or_else(|| pe::embedded_in(self.data, self.caps))
    }
}

/// The digests the allowlist and the hash signatures of `db` can match on an
/// object of `size` bytes.
fn digests_wanted_by(db: &Scanner, size: u64) -> hashes::Want {
    let mut want = db.allow.wants(size);
    if hash_matchable(size) {
        want = want.union(db.hashes.wants(size));
    }
    want
}

/// The container type that members extracted from a container of this `fmt`
/// (over `data`) belong to, used to enforce `Container:CL_TYPE_*` TDB
/// constraints on the members. `None` for formats exav doesn't map to a
/// container type (those constraints stay unenforced). A ZIP is further
/// classified into its OOXML sub-type (Word/Excel/PowerPoint) when it is an
/// Office Open XML document, since the signature format scopes many sigs to the
/// `CL_TYPE_OOXML_*` types rather than plain `CL_TYPE_ZIP`.
fn container_cltype(fmt: unpack::Format, data: &dyn ByteSource) -> Option<engine::ClType> {
    use engine::ClType;
    use unpack::Format;
    Some(match fmt {
        Format::Ole => ClType::Msole2,
        Format::Pdf => ClType::Pdf,
        // A MIME document with no mail envelope is a saved web page, and its
        // parts carry `CL_TYPE_MHTML` rather than `CL_TYPE_MAIL`. The two are
        // mutually exclusive.
        Format::Email => {
            if filetype::looks_like_mhtml(&data.window(0, 8192)) {
                ClType::Mhtml
            } else {
                ClType::Mail
            }
        }
        Format::Cab => ClType::Mscab,
        Format::Rar => ClType::Rar,
        Format::SevenZip => ClType::SevenZip,
        Format::Iso => ClType::Iso,
        Format::Lha => ClType::Lha,
        Format::Tar => ClType::Tar,
        Format::Gzip => ClType::Gzip,
        Format::Bzip2 => ClType::Bzip,
        Format::Xz => ClType::Xz,
        Format::Cpio => ClType::Cpio,
        Format::Ar => ClType::Ar,
        Format::Zstd => ClType::Zstd,
        Format::Zip => ooxml_subtype(data).unwrap_or(ClType::Zip),
        Format::Chm => ClType::Mschm,
        Format::Dmg => ClType::Dmg,
        Format::Nsis => ClType::Nulsft,
        Format::Autoit => ClType::Autoit,
        Format::Rtf => ClType::Rtf,
        // A Windows executable acting as a container: an SFX stub with an
        // archive appended, a runtime-packed image, or an installer. All are
        // `CL_TYPE_MSEXE` to the signature format: the members' parent is the
        // executable, whatever wrapped them inside it.
        Format::Sfx | Format::PePacked | Format::Upx | Format::Inno => ClType::MsExe,
        _ => return None,
    })
}

/// The container type of a markup document that carries embedded base64 assets,
/// or `None` if this buffer is not one.
///
/// The two flat-XML Office types are single-file documents (no ZIP, so nothing
/// an unpacker would open), identified by the processing instruction Office
/// writes at the top. They are NOT the zipped `.docx`/`.xlsx`, which carry their
/// own `CL_TYPE_OOXML_*` types.
#[cfg(feature = "base64scan")]
fn markup_cltype(ft: FileType, data: &[u8]) -> Option<engine::ClType> {
    use engine::ClType;
    if !matches!(ft, FileType::Html | FileType::Text | FileType::Script) {
        return None;
    }
    let head = &data[..data.len().min(4096)];
    let has = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
    if has(b"progid=\"Word.Document\"") || has(b"<w:wordDocument") {
        return Some(ClType::XmlWord);
    }
    if has(b"progid=\"Excel.Sheet\"") || has(b"<x:ExcelWorkbook") {
        return Some(ClType::XmlXl);
    }
    if ft == FileType::Html {
        return Some(ClType::Html);
    }
    None
}

/// The container type a *text carrier* lends to content decoded out of it (a
/// `data:` URI payload, an embedded base64 blob). Only the carriers exav can
/// name; `None` means the caller keeps whatever container it already had.
///
/// Its one caller sits behind `base64scan`, so this is dead in a build without
/// it: a configuration that decodes nothing out of a carrier in the first place.
#[cfg_attr(not(feature = "base64scan"), allow(dead_code))]
fn carrier_cltype(ft: FileType) -> Option<engine::ClType> {
    use engine::ClType;
    Some(match ft {
        FileType::Html => ClType::Html,
        FileType::Rtf => ClType::Rtf,
        FileType::Email => ClType::Mail,
        _ => return None,
    })
}

/// Detect whether a ZIP is an Office Open XML document and which kind, by the
/// member names present in its central directory, read as the extraction reads
/// it ([`unpack::package_kinds_in`]). A `.docx`/`.xlsx`/`.pptx` is the
/// `CL_TYPE_OOXML_*` container type (not plain `CL_TYPE_ZIP`) in the signature
/// format, and many sigs are scoped to those types; typing them this way keeps
/// such sigs firing on real Office documents while staying off plain ZIPs. A
/// ZIP with the parts of several kinds is the first of Word, Excel, PowerPoint.
#[cfg(any(feature = "zip", feature = "all-formats"))]
fn ooxml_subtype(data: &dyn ByteSource) -> Option<engine::ClType> {
    use engine::ClType;
    unpack::package_kinds_in(data)
        .into_iter()
        .find_map(|kind| match kind {
            "docx" => Some(ClType::OoxmlWord),
            "xlsx" => Some(ClType::OoxmlXl),
            "pptx" => Some(ClType::OoxmlPpt),
            _ => None,
        })
}

/// Without the ZIP reader no ZIP is opened, so none has members to type.
#[cfg(not(any(feature = "zip", feature = "all-formats")))]
fn ooxml_subtype(_: &dyn ByteSource) -> Option<engine::ClType> {
    None
}

/// Produce the final reported signature name from a matcher's CLEAN name plus
/// its per-signature `unofficial` provenance. In ClamAV-compat mode an
/// unofficial-database detection is suffixed `.UNOFFICIAL` (the `YARA.` prefix is
/// already part of the clean name the YARA matcher produces); otherwise, and for
/// official `.cvd` signatures, the clean name is reported verbatim. This is the
/// single point where the suffix is applied, so one loaded database serves
/// both compat and non-compat scans.
pub(crate) fn report_name(name: &str, unofficial: bool, suffix: bool) -> String {
    if suffix && unofficial && !name.ends_with(".UNOFFICIAL") {
        format!("{name}.UNOFFICIAL")
    } else {
        name.to_string()
    }
}

/// How a detection was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum Method {
    Pattern,
    Hash,
    Heuristic,
    Fuzzy,
    /// The hand-weighted static scorer behind `Heuristics.Static.Suspect.*`.
    /// Separate from [`Method::Heuristic`] because it reports a *score* rather
    /// than a structural fact, so a caller can weight it differently. Not a
    /// trained model, and deliberately not named as though it were one.
    Static,
    Bytecode,
    Yara,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Pattern => "pattern",
            Method::Hash => "hash",
            Method::Heuristic => "heuristic",
            Method::Fuzzy => "fuzzy",
            Method::Static => "static",
            Method::Bytecode => "bytecode",
            Method::Yara => "yara",
        }
    }
}

/// Outcome of scanning one input.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum Verdict {
    Clean,
    Infected {
        signature: String,
        offset: u64,
        method: Method,
    },
    /// A resource limit (size/ratio/recursion/scan-bytes) prevented a full scan;
    /// the input is not known to be clean.
    LimitsExceeded {
        reason: String,
    },
    /// A container/member was recognised but could not be decoded for a
    /// NON-limit reason: an unsupported compression method (e.g. RAR PPMd).
    /// Distinct from `LimitsExceeded` (not a resource issue) and from `Clean`
    /// (we know there is content we couldn't examine). The `reason` names what
    /// was skipped.
    Unscannable {
        reason: String,
    },
    /// A member is encrypted: we recognised it but can't read its content
    /// without a password. Distinct from `Unscannable` because it is
    /// *actionable*: a caller can prompt for a password and re-scan with
    /// [`ScanOptions::passwords`] set. Takes precedence over `Unscannable` when
    /// both occur (it's the one the user can do something about).
    PasswordProtected {
        reason: String,
    },
}

/// Coarse classification of a [`Verdict`], the single source of truth for
/// summary counters and exit codes across every front-end (one-shot CLI, the
/// clamd daemon, and the daemon client). Keep counting/exit logic keyed on this,
/// never on the rendered string, so the three surfaces can't drift apart.
/// Deliberately NOT `#[non_exhaustive]`, unlike [`Verdict`]. This enum exists
/// so that exit codes and output shape are decided in one place, and the value
/// of that is the compiler refusing to build until every consumer has handled a
/// new category. A wildcard arm is exactly what must not happen here: it would
/// quietly give a future outcome some existing exit code. There are four
/// categories and adding one is a deliberate act inside this workspace, so the
/// cost of the break is small and lands on the people who caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictCategory {
    /// Fully scanned, nothing found. Reported `OK`, exit `0`.
    Clean,
    /// A signature matched. Reported `FOUND`, exit `1`.
    Infected,
    /// Work happened and stopped short of the end: a budget ran out, a
    /// container would not decode, or the content is encrypted. Reported
    /// `PARTIAL` under one of the three categories
    /// ([`Verdict::status_tag`]), exit `3`: never a silent pass.
    ///
    /// Distinct from an *error*, which is exav failing to do its job at all
    /// (an unreadable path, a database that would not load) and exits `2`.
    /// A caller needs to tell "the scanner is broken" from "this object needs
    /// a decision", so they do not share a code.
    Partial,
}

impl Verdict {
    /// The coarse [`VerdictCategory`] for counters/exit codes.
    pub fn category(&self) -> VerdictCategory {
        match self {
            Verdict::Clean => VerdictCategory::Clean,
            Verdict::Infected { .. } => VerdictCategory::Infected,
            Verdict::LimitsExceeded { .. }
            | Verdict::Unscannable { .. }
            | Verdict::PasswordProtected { .. } => VerdictCategory::Partial,
        }
    }

    /// The clamscan/clamd status tag: `FOUND`, `OK`, `LIMITS-EXCEEDED`,
    /// `UNSCANNABLE`, or `PASSWORD-PROTECTED`. For `Infected` the signature name
    /// precedes this tag in output; for the others the variant's `reason` does.
    pub fn status_tag(&self) -> &'static str {
        match self {
            Verdict::Clean => "OK",
            Verdict::Infected { .. } => "FOUND",
            Verdict::LimitsExceeded { .. } => "LIMITS-EXCEEDED",
            Verdict::Unscannable { .. } => "UNSCANNABLE",
            Verdict::PasswordProtected { .. } => "PASSWORD-PROTECTED",
        }
    }

    /// The human-readable detail: the signature name for `Infected`, the reason
    /// string for the partial verdicts, `None` for `Clean`.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Verdict::Clean => None,
            Verdict::Infected { signature, .. } => Some(signature),
            Verdict::LimitsExceeded { reason }
            | Verdict::Unscannable { reason }
            | Verdict::PasswordProtected { reason } => Some(reason),
        }
    }
}

/// An informational finding (type, entropy, imphash, skipped sub-objects).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct Finding {
    pub label: String,
    pub detail: String,
}

impl Finding {
    pub fn new(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            detail: detail.into(),
        }
    }
}

/// The serialised phishing-DB parts stored in the prebuilt database: `(protected
/// domains, `M:` allow-list pairs, `X:` regex source pairs)`. Defined
/// unconditionally (the `phishing` feature only gates the *matcher*, not the
/// database format) so a database round-trips identically regardless of features.
pub(crate) type PhishingPartsOwned = (Vec<String>, Vec<(String, String)>, Vec<(String, String)>);

/// Full result of a scan.
///
/// New fields may appear in any release. Build with [`ScanReport::new`],
/// never with a struct literal, which a new field would break.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct ScanReport {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    /// A report from a verdict and its findings.
    pub fn new(verdict: Verdict, findings: Vec<Finding>) -> Self {
        Self { verdict, findings }
    }

    fn clean(findings: Vec<Finding>) -> Self {
        Self {
            verdict: Verdict::Clean,
            findings,
        }
    }
    fn infected(signature: String, offset: u64, method: Method, findings: Vec<Finding>) -> Self {
        Self {
            verdict: Verdict::Infected {
                signature,
                offset,
                method,
            },
            findings,
        }
    }

    fn limits(reason: String, findings: Vec<Finding>) -> Self {
        Self {
            verdict: Verdict::LimitsExceeded {
                reason: one_line(reason),
            },
            findings,
        }
    }
    fn unscannable(reason: String, findings: Vec<Finding>) -> Self {
        Self {
            verdict: Verdict::Unscannable {
                reason: one_line(reason),
            },
            findings,
        }
    }
    fn password_protected(reason: String, findings: Vec<Finding>) -> Self {
        Self {
            verdict: Verdict::PasswordProtected {
                reason: one_line(reason),
            },
            findings,
        }
    }
}

/// A verdict reason with its control characters, bidirectional controls and
/// line separators replaced, as in a location ([`tree::shown_text`]).
///
/// Reasons quote container member names, which come from the file being
/// scanned. Every front-end prints the reason inside a line-framed reply (the
/// clamd protocol, the clamscan-style CLI line, the `--log` file), so a newline
/// in a member name would let the file write a line of its own, such as a
/// second `stream: OK` for a client that reads the last line it gets.
fn one_line(reason: String) -> String {
    match tree::shown_text(&reason) {
        std::borrow::Cow::Borrowed(_) => reason,
        std::borrow::Cow::Owned(shown) => shown,
    }
}

/// Options controlling a scan and its limits.
///
/// New fields may appear in any release. Build with
/// `ScanOptions::default()` and assign the fields you care about, never with
/// a struct literal, which a new field would break.
#[derive(Clone)]
#[non_exhaustive]
pub struct ScanOptions {
    /// Max bytes for a single top-level file. `None` = unlimited (default).
    /// Exceeding yields `LimitsExceeded`. Applied by [`scan_seekable`] and the
    /// scans over a reader; [`analyze`] and the other functions over a slice
    /// scan the slice whole.
    pub max_scan_size: Option<u64>,
    /// Memory of the block cache of an object read in place, in bytes
    /// (`--object-cache-bytes`): an object past `limits.max_buffer_bytes`, a spilled
    /// member or view, a spilled stream. One cache for each such object being
    /// scanned, nested ones included. Carving also holds up to this much of
    /// candidates waiting for a check while it reads such an object. Default
    /// 32 MiB.
    pub object_cache_bytes: u64,
    /// One block of that cache, in bytes (`--object-cache-block-bytes`): the
    /// unit it reads from the object, and over HTTP what a read at an offset
    /// elsewhere fetches. Default 1 MiB.
    pub object_cache_block_bytes: u64,
    /// Over HTTP, the most one range request fetches (`--http-request-bytes`),
    /// reached by a read that goes on from where the last stopped, which asks
    /// for twice as much each time from one block. Default 8 MiB.
    pub http_request_bytes: u64,
    /// Over HTTP, the most one request may take, from connecting to the last
    /// byte of its body, in seconds (`--http-timeout-secs`). `None`: no limit.
    /// Default 120.
    pub http_timeout_secs: Option<u64>,
    /// Over HTTP, the redirects followed to reach the object
    /// (`--http-max-redirects`), none of them to another scheme. `None`: no
    /// limit. Default 10.
    pub http_max_redirects: Option<u32>,
    /// Over HTTP, whether a redirect may lead to a host with a loopback,
    /// private, link-local, shared-address or unspecified address
    /// (`--http-redirect-private`). Default off.
    pub http_redirect_private: bool,
    /// Over HTTP, download an object past `limits.max_buffer_bytes` once into a
    /// spill file and scan it from there (`--http-spill`), one transfer in
    /// place of one for each pass. Needs [`Self::spill`]. Default off.
    pub http_spill: bool,
    /// Largest object PCRE subsignatures run on (`--max-pcre-bytes`); on a
    /// larger one they do not match, as ClamAV's `PCREMaxFileSize` has it,
    /// and the scan is incomplete (not under `clamav_compat`, as in ClamAV).
    /// `None` = no limit (default); 100 MiB under `--clamav-compat`.
    pub max_pcre_bytes: Option<u64>,
    /// Most steps one search may make in a regex engine that a crafted
    /// pattern or object can make take long (`--max-regex-steps`): a PCRE
    /// subsignature that uses lookaround or a back reference, and a YARA
    /// regexp. A search is the work of one subsignature or pattern on one
    /// object. Each engine counts its own unit: a backtrack of a PCRE is a
    /// step, and so is each 32 bytes that a part of it handed to the linear
    /// engine, or a back reference, reads; a YARA regexp makes a step for
    /// each 32 bytes its searches read. A search that reaches the limit stops,
    /// the matches found before it still count, and the scan is incomplete
    /// (`LIMITS-EXCEEDED`) unless something is found. `None` = no limit.
    /// Default 100,000,000.
    pub max_regex_steps: Option<u64>,
    /// Steps the conditions of the YARA rules may take in one scan, all the
    /// rules together (`--max-yara-steps`). A rule's range loop takes its
    /// bounds from the rule, not from the object. A condition that runs out
    /// does not match, nor do those after it, and the scan is incomplete
    /// (`LIMITS-EXCEEDED`) unless something is found. `None` = no limit.
    /// Default 20,000,000, also under `--clamav-compat`.
    pub max_yara_steps: Option<u64>,
    /// Steps the verifier of the body signatures with wildcards and gaps may
    /// take per MiB of an object (`--max-matcher-steps`), counted for an
    /// object of at least 256 MiB: one that size or smaller has 256 times this
    /// many, a larger one in proportion. One group of signatures that share an
    /// anchor may take a 32nd of that. A search that reaches either stops, the
    /// matches found before it still count, and the scan is incomplete
    /// (`LIMITS-EXCEEDED`) unless something is found. `None` = no limit.
    /// Default 2,000,000.
    pub max_matcher_steps: Option<u64>,
    /// Smallest object scanned (`--min-scan-bytes`): a smaller one, at any
    /// depth, is neither matched nor unpacked and counts as clean, as ClamAV
    /// does not scan an object under 6 bytes. `0` scans everything. Default 6.
    pub min_scan_bytes: u64,
    /// Enable exav's *exclusive* structural heuristics: TLSH fuzzy matching, the
    /// static suspicion scorer (`Heuristics.Static.Suspect.*`), and the packed-with-injection
    /// heuristic. These have no stock-ClamAV analog, so they stay off under
    /// `--clamav-compat` (enabling them would count as false positives in a diff
    /// run). Archive extraction is always performed regardless of this flag.
    pub heuristics: bool,
    /// The heuristics stock ClamAV runs *by default* and that carry exact
    /// ClamAV-compatible names: `Heuristics.PDF.ObfuscatedNameObject` and imphash
    /// (`.imp`) matching. **On by default**: these are FP-safe (imphash is an
    /// exact DB signature; the PDF check counts only gratuitous escapes), so exav
    /// out of the box does every reasonable ClamAV-default match. Kept separate
    /// from [`heuristics`](Self::heuristics) so this parity subset stays on under
    /// `--clamav-compat` while the exav-exclusive TLSH/ML analysis (higher FP risk,
    /// no ClamAV analog) does not. `--detect exav-heuristics` is the superset and implies this.
    /// The PDF check also reads the objects inside object streams, except under
    /// `--clamav-compat`.
    pub clamav_heuristics: bool,
    /// Report findings under ClamAV's vocabulary where the two engines describe
    /// the same fact differently. Set by [`ScanOptions::clamav_compat`].
    ///
    /// This changes NAMES, and it leaves out the reach exav has beyond ClamAV's
    /// where a differential run would count it as a disagreement (a visible-text
    /// view, QR codes, the `.imp` match of a PE32+). It does not adopt a check
    /// it believes is wrong: compat is about feature scope and the strings a
    /// drop-in replacement must emit, not about reproducing another engine's
    /// judgement.
    ///
    /// The one name is that of an ELF whose section-header table has been
    /// stripped. exav reports that as what it is; ClamAV calls it a broken
    /// executable, and a gateway filtering on ClamAV's exact string needs to
    /// keep matching. The PE32+ is the one clamscan makes no import hash for.
    pub clamav_compat: bool,
    /// Limits for recursive unpacking / bomb defenses.
    ///
    /// `limits.max_buffer_bytes` (`--max-object-bytes`) is also the largest
    /// object the scan holds in memory. A larger one gets the same scan, read
    /// through a block cache or, for a decoded member, a spill file; the checks
    /// that parse an object whole do not run on it, and if nothing is found it
    /// is reported `LimitsExceeded`. A decoded member over it with no spill to
    /// go to has its first bytes up to the limit scanned, and is reported.
    pub limits: unpack::Limits,
    /// Restrict exav's unpacking reach to stock ClamAV's, so a differential run
    /// against `clamscan` doesn't count exav's extra reach as a disagreement.
    /// Narrows three things to ClamAV's scope: (1) archive extractors, skipping
    /// the formats stock ClamAV does not open (measured with clamscan 1.4.3):
    /// `ar` (Unix archive / `.deb` / `.a`), `lzip`, Inno Setup, Zoo, StuffIt,
    /// ACE, ARC, lz4, zstd, lrzip, WIM, InstallShield `ISc(` cabinets and `.z`
    /// archives, AppleSingle and AppleDouble, the filesystem images (ext, FAT,
    /// NTFS, exFAT, SquashFS, cramfs, romfs, EROFS), `.lnk`, `.pyc`, Java
    /// classes, AI models, KWAJ, and an SZDD that ClamAV rejects, and the
    /// magic-dispatched disk-image / Unix `compress` formats except DMG (which
    /// ClamAV opens, as it does cpio and xar); (2) what is carved out of
    /// another file: not gzip, bzip2 or xz streams, and of executables only a
    /// PE behind a PE; (3) UPX: to PE only (ClamAV's UPX unpacker runs only from
    /// its PE path, never ELF/Mach-O).
    /// A format ClamAV opens for some codecs only (ZIP, 7z, EGG, DMG) stays on
    /// for all of them.
    ///
    /// The other PE runtime packers stay **on**: ClamAV unpacks those too, and
    /// switching an unpacker off would not make a run comparable, it would make
    /// it miss a packed dropper. Compat narrows *scope and naming*, never
    /// coverage of content that is there to be found. Default off. This
    /// deliberately *reduces* exav's detection capability for reproducibility, so
    /// it is a diff-testing aid, **not for production**. It is one of the
    /// behaviours the CLI's `--clamav-compat` turns on.
    pub restrict_extractors: bool,
    /// Decode long base64 blobs found in text/script buffers and rescan any that
    /// decode to a real executable (PE/ELF/Mach-O/OLE), catching a PE stashed as
    /// a base64 string in a PowerShell/JS/VBS dropper or an RTF body, invisible to
    /// a signature that matches the decoded bytes. **On by default** (exav-exclusive
    /// reach beyond stock ClamAV); off under `--clamav-compat` and via `--no-base64`.
    /// FP-safe: only a decode with a valid executable header is rescanned.
    pub decode_base64: bool,
    /// Append `.UNOFFICIAL` to signature names that come from unofficial
    /// databases, matching stock `clamscan`'s output. Purely
    /// cosmetic: it changes only how a detection is *named*, never whether it
    /// fires. Default off. (The other behaviour `--clamav-compat` turns on.)
    pub unofficial_suffix: bool,
    /// Password(s) to try when decrypting encrypted archive members. Empty by
    /// default. When a scan returns [`Verdict::PasswordProtected`], a caller can
    /// set this and re-scan.
    pub passwords: Vec<String>,
    /// Verify archive checksums (CRCs) during extraction. **Off by default**: a
    /// scanner scans decompressed content regardless of integrity metadata, so a
    /// corrupted checksum can't hide a payload from detection (this matches
    /// ClamAV, which ignores CRCs when scanning). Only has effect when exav-core
    /// is built with the `checksums` feature; otherwise checksums are never
    /// verified. Turn on only for extract-for-real use where a bad CRC is a
    /// genuine "corrupt file" signal.
    pub verify_checksums: bool,
    /// DLP structured-data heuristic (ClamAV `--structured-cc-count`): alert with
    /// `Heuristics.Structured.CreditCardNumber` when a textual buffer contains at
    /// least this many valid credit-card numbers (`Some(0)` is 1). `None`
    /// (default) = off. Requires the `dlp` feature.
    pub structured_cc_count: Option<u32>,
    /// DLP structured-data heuristic (ClamAV `--structured-ssn-count`): alert with
    /// `Heuristics.Structured.SSN` when a textual buffer contains at least this
    /// many valid US SSNs (`Some(0)` is 1). `None` (default) = off. Requires the
    /// `dlp` feature.
    pub structured_ssn_count: Option<u32>,
    /// Opt-in ClamAV heuristic (`--alert-encrypted`): report an encrypted /
    /// password-protected member as `Heuristics.Encrypted.*` (a detection)
    /// instead of the default actionable [`Verdict::PasswordProtected`]. Off by
    /// default (matching ClamAV); when off the encrypted verdict is unchanged.
    pub alert_encrypted: bool,
    /// Opt-in ClamAV heuristic (`--alert-macros`): report
    /// `Heuristics.OLE2.ContainsMacros` when an OLE2/OOXML document carries a VBA
    /// macro project. Off by default (matching ClamAV).
    pub alert_macros: bool,
    /// Opt-in ClamAV heuristic (`--alert-exceeds-max` / `AlertExceedsMax`):
    /// report a scan-limit stop as a **detection** named
    /// `Heuristics.Limits.Exceeded.*` instead of the default `LIMITS-EXCEEDED`
    /// status.
    ///
    /// This is the bridge between the two vocabularies. exav models "could not
    /// finish scanning" as its own verdict, which is honest but needs the clamd
    /// `ERROR` reply shape; ClamAV models the same condition as a heuristic
    /// alert, which is an ordinary `FOUND`. A drop-in deployment that already
    /// keys on `Heuristics.Limits.Exceeded.*` gets the names it expects.
    pub alert_exceeds_max: bool,
    /// Opt-in ClamAV heuristic (`--alert-partition-intersection` /
    /// `AlertPartitionIntersection`): report `Heuristics.GPTPartitionIntersection`,
    /// `Heuristics.APMPartitionIntersection` or `Heuristics.MBRPartitionnIntersect`
    /// when a disk image's partition entries overlap. Off by default.
    pub alert_partition_intersection: bool,
    /// Opt-in ClamAV heuristic (`--alert-broken` / `AlertBrokenExecutables`):
    /// report `Heuristics.Broken.Executable` for a file that carries a PE, ELF
    /// or Mach-O magic but whose headers do not parse. Off by default.
    pub alert_broken: bool,
    /// Opt-in ClamAV heuristic (`--alert-broken-media`): report
    /// `Heuristics.Broken.Media.*` for a structurally invalid image/media file
    /// (GIF, PNG, TIFF and JPEG container validation). Off by default.
    pub alert_broken_media: bool,
    /// Opt-in heuristic (`exav --detect packed`): report `Heuristics.Packed.*` for an
    /// executable behind a packer or protector exav cannot unpack.
    ///
    /// Reported IN ADDITION TO the unscannable signal, never instead of it. The
    /// two say different things ("this is VMProtect" and "its original code was
    /// not recovered"), and a scanner that emits only the second leaves every
    /// commercially-protected binary on the ERROR line, where gateways read it as
    /// scanner failure rather than as a fact about the file. The heuristic also
    /// stays correct once a given packer becomes unpackable: the file was still
    /// packed, and that remains worth saying.
    pub alert_packed: bool,
    /// Opt-in phishing heuristic (`--alert-phishing`, emitting ClamAV-compatible
    /// `Heuristics.Phishing.Email.*` names): report when an HTML/text buffer contains a
    /// link whose visible text spoofs a different domain than its `href`, hides
    /// the real host behind userinfo, or points at an IP literal under a brand
    /// name. Off by default.
    pub alert_phishing: bool,
    /// Read the QR codes in images (feature `qr`): each payload is matched as
    /// a text view, and each link in one is judged by [`Self::alert_phishing`].
    /// Off by default, and never under `clamav_compat`.
    pub qr_codes: bool,
    /// Pixels an image may have for its QR codes to be read; `None`: no
    /// limit. A larger image marks the scan incomplete.
    pub max_qr_pixels: Option<u64>,
    /// Milliseconds the reading of one image's QR codes may take; `None`: no
    /// limit. A reading cut short marks the scan incomplete.
    pub max_qr_millis: Option<u64>,
    /// QR codes read in one image; `None`: all. An image with more marks the
    /// scan incomplete.
    pub max_qr_codes: Option<u64>,
    /// Finder patterns (the square a QR code has in three corners) found in
    /// one image; `None`: all. An image with more marks the scan incomplete.
    pub max_qr_finders: Option<u64>,
    /// Groups of three finder patterns tried as a QR code in one image;
    /// `None`: all. An image with more marks the scan incomplete.
    pub max_qr_grids: Option<u64>,
    /// Opt-in Authenticode heuristic: report `Heuristics.Authenticode.HashMismatch`
    /// when a code-signed PE's embedded digest does NOT cover the current file
    /// bytes (i.e. the file was modified or had data appended after signing, a
    /// classic trojanized-signed-binary trick). Triage only: exav does not verify
    /// the RSA signature (see `authenticode`). Off by default.
    pub alert_broken_authenticode: bool,
    /// Identity of the top-level object being scanned (a file path). Additive
    /// and defaults to `None`, so the byte-only [`analyze`] API is unchanged.
    /// When set, [`scan_path`] fills it from the path; it supplies the YARA
    /// external variables (`filepath`/`filename`/`extension`) so signature-base
    /// rules that reference them can match. Left `None`, those externals stay
    /// undefined (and such rules do not match). It never affects any non-YARA
    /// detection.
    pub filename: Option<String>,
    /// Where a scan may write what it makes of an object too large to hold in
    /// memory (its normalised text, a member too large to buffer), to read it
    /// back at any offset. `None`: nowhere, and what needed it is reported as
    /// not fully scanned. See [`spill`].
    pub spill: Option<std::sync::Arc<dyn spill::Spill>>,
}

impl ScanOptions {
    /// The block and capacity, in bytes, of a block cache: at least a byte a
    /// block, and room for two.
    pub(crate) fn cache_sizes(&self) -> (usize, usize) {
        let block = usize::try_from(self.object_cache_block_bytes)
            .unwrap_or(usize::MAX)
            .max(1);
        let bytes = usize::try_from(self.object_cache_bytes).unwrap_or(usize::MAX);
        (block, bytes)
    }

    /// `limits.max_buffer_bytes` as a length. One past what the build can address
    /// (4 GiB on a 32-bit target) is no limit; a cast would wrap it to a small one.
    pub(crate) fn hold_limit(&self) -> usize {
        usize::try_from(self.limits.max_buffer_bytes).unwrap_or(usize::MAX)
    }

    /// How a walk of containers is set up: what it holds of a member in
    /// memory, and where the rest may go.
    fn walk(&self) -> tree::Walk<'_> {
        tree::Walk {
            hold: tree::Hold {
                limit: self.limits.max_buffer_bytes,
                spill: self.spill.as_deref(),
                cache: self.cache_sizes(),
                large: tree::Large::Source,
            },
            sets: true,
            // The scanner reads an object a second way where its order of
            // work says (`tree::derive`), not after the members.
            second_readings: false,
        }
    }

    /// How many far candidates carving holds before it checks them: their
    /// 16 bytes each fill no more than the object cache does.
    pub(crate) fn carve_pending(&self) -> usize {
        usize::try_from(self.object_cache_bytes / 16)
            .unwrap_or(usize::MAX)
            .max(1)
    }

    /// How an http(s) source is fetched under these options.
    #[cfg(feature = "http")]
    pub fn http_config(&self) -> source::HttpConfig {
        source::HttpConfig {
            timeout: self.http_timeout_secs.map(std::time::Duration::from_secs),
            max_redirects: self.http_max_redirects,
            redirect_to_private: self.http_redirect_private,
        }
    }

    /// A block cache over `reader`, sized by these options.
    pub(crate) fn object_cache<R: Read + Seek>(
        &self,
        reader: R,
    ) -> io::Result<byte_source::BlockCache<R>> {
        let (block, bytes) = self.cache_sizes();
        byte_source::BlockCache::with_sizes(reader, block, bytes)
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_scan_size: None,
            object_cache_bytes: unpack::source::CACHE_BYTES as u64,
            object_cache_block_bytes: 1024 * 1024,
            http_request_bytes: 8 * 1024 * 1024,
            http_timeout_secs: Some(120),
            http_max_redirects: Some(10),
            http_redirect_private: false,
            http_spill: false,
            max_pcre_bytes: None,
            max_regex_steps: Some(engine::DEFAULT_REGEX_STEPS as u64),
            max_yara_steps: Some(engine::DEFAULT_YARA_STEPS),
            max_matcher_steps: Some(engine::DEFAULT_MATCHER_STEPS),
            min_scan_bytes: MIN_SCAN_BYTES,
            heuristics: false,
            // ClamAV-default matchings (PDF obfuscation, imphash) are on out of the
            // box: FP-safe and part of a faithful default scan. The exav-exclusive
            // TLSH/ML heuristics above stay opt-in.
            clamav_heuristics: true,
            clamav_compat: false,
            limits: unpack::Limits::default(),
            restrict_extractors: false,
            decode_base64: true,
            unofficial_suffix: false,
            passwords: Vec::new(),
            verify_checksums: false,
            structured_cc_count: None,
            structured_ssn_count: None,
            alert_encrypted: false,
            alert_exceeds_max: false,
            alert_partition_intersection: false,
            alert_broken: false,
            alert_macros: false,
            alert_broken_media: false,
            alert_packed: false,
            alert_phishing: false,
            qr_codes: false,
            max_qr_pixels: qr_default!(DEFAULT_MAX_QR_PIXELS),
            max_qr_millis: qr_default!(DEFAULT_MAX_QR_MILLIS),
            max_qr_codes: qr_default!(DEFAULT_MAX_QR_CODES),
            max_qr_finders: qr_default!(DEFAULT_MAX_QR_FINDERS),
            max_qr_grids: qr_default!(DEFAULT_MAX_QR_GRIDS),
            alert_broken_authenticode: false,
            filename: None,
            spill: None,
        }
    }
}

impl ScanOptions {
    /// Preset matching a stock ClamAV build's default limits and capabilities,
    /// for apples-to-apples differential testing against `clamscan`. Sets the
    /// documented ClamAV defaults (max-filesize 100M, max-scansize 400M,
    /// max-recursion 17, max-files 10000) and enables the capability mask that
    /// disables exav-exclusive extractors. Note: a *real* ClamAV's capabilities
    /// also depend on its build flags (e.g. `libclamunrar`); this matches the
    /// documented defaults, not a specific binary.
    pub fn clamav_compat() -> Self {
        let mut limits = unpack::Limits::default();
        limits.max_recursion = 17;
        limits.max_members = 10_000;
        limits.max_extracted_bytes = 400 * 1024 * 1024;
        Self {
            max_scan_size: Some(100 * 1024 * 1024),
            object_cache_bytes: unpack::source::CACHE_BYTES as u64,
            object_cache_block_bytes: 1024 * 1024,
            http_request_bytes: 8 * 1024 * 1024,
            http_timeout_secs: Some(120),
            http_max_redirects: Some(10),
            http_redirect_private: false,
            http_spill: false,
            // ClamAV's PCREMaxFileSize default.
            max_pcre_bytes: Some(100 * 1024 * 1024),
            max_regex_steps: Some(engine::DEFAULT_REGEX_STEPS as u64),
            max_yara_steps: Some(engine::DEFAULT_YARA_STEPS),
            max_matcher_steps: Some(engine::DEFAULT_MATCHER_STEPS),
            min_scan_bytes: MIN_SCAN_BYTES,
            // exav-exclusive TLSH/ML stay off (they'd be diff-run false positives);
            // the ClamAV-default heuristics are on to match stock clamscan.
            heuristics: false,
            clamav_heuristics: true,
            clamav_compat: true,
            limits,
            restrict_extractors: true,
            // base64-decoding reaches beyond stock ClamAV; off for parity.
            decode_base64: false,
            unofficial_suffix: true,
            passwords: Vec::new(),
            // ClamAV ignores CRCs when scanning; match it.
            verify_checksums: false,
            structured_cc_count: None,
            structured_ssn_count: None,
            alert_encrypted: false,
            alert_exceeds_max: false,
            alert_partition_intersection: false,
            alert_broken: false,
            alert_macros: false,
            alert_broken_media: false,
            alert_packed: false,
            alert_phishing: false,
            qr_codes: false,
            max_qr_pixels: qr_default!(DEFAULT_MAX_QR_PIXELS),
            max_qr_millis: qr_default!(DEFAULT_MAX_QR_MILLIS),
            max_qr_codes: qr_default!(DEFAULT_MAX_QR_CODES),
            max_qr_finders: qr_default!(DEFAULT_MAX_QR_FINDERS),
            max_qr_grids: qr_default!(DEFAULT_MAX_QR_GRIDS),
            alert_broken_authenticode: false,
            filename: None,
            spill: None,
        }
    }
}

/// The loaded signature database and detection models.
///
/// Construct one with [`Scanner::builtin`], [`loader::load`], or [`loader::Builder`],
/// and query it through its methods. The fields hold internal engine types and
/// are crate-private (not part of the stable API); their layout may change
/// between releases.
pub struct Scanner {
    /// The `.ndb`/`.ldb`/`.db` signature matcher.
    pub(crate) engine: engine::SigEngine,
    pub(crate) hashes: HashDb,
    /// `.mdb`/`.mdu`/`.msb` PE section-hash signatures.
    pub(crate) sections: SectionHashDb,
    pub(crate) fuzzy: FuzzyDb,
    /// `.cdb` container-metadata signatures.
    pub(crate) cdb: container::CdbDb,
    /// `.yar`/`.yara` YARA rules (the native engine under [`yara`]).
    pub(crate) yara: yara::YaraDb,
    /// `.fp`/`.sfp` whole-file hash allowlist: a match here clears a detection.
    pub(crate) allow: HashDb,
    /// `.ign`/`.ign2` signature names to suppress.
    pub(crate) ignored: std::collections::HashSet<String>,
    /// Loaded `.cbc` bytecode programs, with their triggers/hooks, executed in
    /// a memory-safe sandbox when their gate fires (see [`bytecode::runtime`]).
    pub(crate) bytecode: bytecode::runtime::BytecodeRuntime,
    pub(crate) model: Box<dyn Model>,
    pub(crate) ml_threshold: f32,
    /// `.ftm` file-type magic rules; consulted only when content-based
    /// [`filetype::identify`] is inconclusive (see [`Scanner::identify`]).
    pub(crate) ftm: filetype::FtmMagics,
    /// `.idb` PE-icon perceptual-hash database, used to satisfy `IconGroup1/2`
    /// constraints on logical signatures (see [`icon`]).
    pub(crate) icons: icon::IconDb,
    /// `.crb` Authenticode certificate block-list: a signed PE carrying a matching
    /// signer certificate is reported (identity match, no RSA verification).
    pub(crate) crb: authenticode::CrbDb,
    /// Passwords loaded from `.pwdb` files (ClamAV password database). Tried
    /// (unioned with [`ScanOptions::passwords`]) when decrypting encrypted
    /// archive members. The official CVDs ship none; this is user-supplied.
    pub(crate) passwords: Vec<String>,
    /// Version number and build-time of the newest loaded `.cvd`/`.cld` container
    /// (the one with the highest version: the daily set in a normal ClamAV DB
    /// dir), for the clamd-compatible daemon `VERSION`/`VERSIONCOMMANDS` replies.
    /// `None` when only loose signatures or the built-in baseline were loaded.
    pub(crate) db_version: Option<(u32, String)>,
    /// `.pdb`/`.gdb` domain-list + `.wdb` allow-list, consulted by the opt-in
    /// phishing heuristic (`--alert-phishing`) for scoping / FP suppression.
    #[cfg(feature = "phishing")]
    pub(crate) phishing: phishing::PhishingDb,
}

/// Low-level access to the internal signature engine. Gated behind
/// `unstable-internals` (used by the diagnostic examples/tooling); the returned
/// [`engine::SigEngine`] is not part of the stable API.
#[cfg(feature = "unstable-internals")]
impl Scanner {
    pub fn engine(&self) -> &engine::SigEngine {
        &self.engine
    }

    /// Assemble a [`Scanner`] from individually-built subsystems over the
    /// [`Scanner::builtin`] baseline (which supplies `sections`,
    /// `yara`, `model`, `ftm`, `bytecode`, …). For fuzzing / low-level tooling
    /// that constructs sub-databases directly; not part of the stable API.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        engine: engine::SigEngine,
        hashes: hashes::HashDb,
        fuzzy: fuzzy::FuzzyDb,
        cdb: container::CdbDb,
        icons: icon::IconDb,
        allow: hashes::HashDb,
        ignored: std::collections::HashSet<String>,
    ) -> Self {
        Self {
            engine,
            hashes,
            fuzzy,
            cdb,
            icons,
            allow,
            ignored,
            ..Self::builtin()
        }
    }
}

impl Scanner {
    /// Passwords loaded from `.pwdb` files, tried (in addition to
    /// [`ScanOptions::passwords`]) when decrypting encrypted archive members.
    pub fn passwords(&self) -> &[String] {
        &self.passwords
    }

    /// Built-in baseline database (EICAR pattern, heuristic model).
    pub fn builtin() -> Self {
        let mut eb = engine::EngineBuilder::new();
        eb.add_literal("Exav.Test.EICAR", patterns::eicar());
        Self {
            engine: eb.build(),
            hashes: HashDb::new(),
            sections: SectionHashDb::new(),
            fuzzy: FuzzyDb::new(),
            cdb: container::CdbDb::new(),
            yara: yara::YaraDb::new(),
            allow: HashDb::new(),
            ignored: std::collections::HashSet::new(),
            bytecode: bytecode::runtime::BytecodeRuntime::empty(),
            model: Box::new(ml::HeuristicModel),
            ml_threshold: 0.85,
            ftm: filetype::FtmMagics::default(),
            icons: icon::IconDb::new(),
            crb: authenticode::CrbDb::default(),
            passwords: Vec::new(),
            db_version: None,
            #[cfg(feature = "phishing")]
            phishing: phishing::PhishingDb::default(),
        }
    }

    /// Version number and build-time of the newest loaded signature container
    /// (the daily CVD in a normal ClamAV database dir), or `None` if only loose
    /// files / the baseline were loaded. Feeds the clamd-compatible daemon
    /// `VERSION` reply (its `/<dbver>/<dbtime>` fields, which `clamdtop` shows).
    pub fn db_version(&self) -> Option<(u32, &str)> {
        self.db_version.as_ref().map(|(v, t)| (*v, t.as_str()))
    }

    /// File type of `data`: content-based [`filetype::identify`], falling back to
    /// loaded `.ftm` magic rules only when content detection is inconclusive
    /// (`Unknown`), so native typing is never overridden.
    pub fn identify(&self, data: &[u8]) -> FileType {
        self.identify_source(&data)
    }

    /// As [`Self::identify`], over an object that need not be held in memory.
    pub(crate) fn identify_source(&self, data: &dyn ByteSource) -> FileType {
        self.identify_facts(&Facts::new(data))
    }

    /// As [`Self::identify_source`], sharing what detection finds with the
    /// other steps that ask `facts`.
    pub(crate) fn identify_facts(&self, facts: &Facts) -> FileType {
        profile::timed("filetype", facts.data.len() as u64, || {
            self.identify_inner(facts)
        })
    }

    fn identify_inner(&self, facts: &Facts) -> FileType {
        self.identify_as(facts.data, &|| facts.format())
    }

    /// The type of `data`, `format` giving what detection makes of it.
    fn identify_as(
        &self,
        data: &dyn ByteSource,
        format: &dyn Fn() -> Option<unpack::Format>,
    ) -> FileType {
        let mut ft = filetype::identify_source_with(data, format);
        if ft == FileType::Unknown
            && let Some(f) = self.ftm.identify_source(data)
        {
            ft = f;
        }
        // The bzip2 (`BZh`), CAB (`MSCF`), gzip (`1f 8b`) and ARJ (`60 ea`)
        // file-type magics are short and collide with ordinary binary data; a
        // false hit (e.g. a `BZh4…`, `MSCF…` or `1f8b08…` byte-run inside an ISO
        // member or PE overlay) would be routed to that decoder, fail deep in
        // parsing, and report the whole object UNSCANNABLE / LIMITS-EXCEEDED.
        // `.ftm` rules match on those weak prefixes, so confirm each against the
        // extractor's stronger magic check (block magic for bzip2, zero
        // `reserved1` for CAB, deflate CM + flag bits for gzip, the header CRC
        // for ARJ) before trusting the typing; a false hit is scanned as raw bytes.
        // A bzip2 or xz magic is also how a UDIF disk image whose data fork
        // opens with its first run starts, which `detect` types by its trailer.
        let false_archive = match ft {
            FileType::Bzip2 => format() != Some(unpack::Format::Bzip2),
            FileType::Xz => format() != Some(unpack::Format::Xz),
            FileType::Cab => format() != Some(unpack::Format::Cab),
            FileType::Gzip => format() != Some(unpack::Format::Gzip),
            FileType::Arj => format() != Some(unpack::Format::Arj),
            _ => false,
        };
        if false_archive {
            return FileType::Unknown;
        }
        ft
    }

    /// Distinct signatures loaded.
    pub fn signature_count(&self) -> usize {
        self.engine.signature_count()
            + self.hashes.len()
            + self.sections.len()
            + self.fuzzy.len()
            + self.cdb.len()
            + self.yara.len()
    }

    /// Number of loaded `.cbc` bytecode programs.
    pub fn bytecode_count(&self) -> usize {
        self.bytecode.len()
    }

    /// Run every loaded bytecode program against `data` ignoring its gate, for
    /// testing/differential validation. Returns `(detection, program_index)`
    /// for each program that detects with no unsupported op. Not part of the
    /// stable API.
    #[cfg(feature = "unstable-internals")]
    pub fn run_bytecodes_forced(&self, data: &[u8]) -> Vec<(String, usize)> {
        self.bytecode.run_all_forced(data)
    }

    /// Source signatures that could not be loaded (e.g. unsupported `.ndb`
    /// wildcards, PCRE/bytecode subsignatures). A database written by
    /// [`database::write`] also counts the logical signatures with a PCRE
    /// that neither regex engine builds; one loaded from source files does not.
    pub fn unsupported_count(&self) -> usize {
        self.engine.unsupported
    }
}

/// Scan a local file: [`scan_seekable`] over the opened file, with its path
/// as the YARA `filepath`/`filename`/`extension` unless `opts.filename` is
/// set. The file must be able to seek; a FIFO or other stream is buffered by
/// the caller first. A FIFO named here is an [`io::ErrorKind::Unsupported`]
/// error, and the open does not wait for a writer.
///
/// # Errors
///
/// The `io::Error` covers only reaching the file: opening, reading, seeking.
/// **Nothing about the scan's outcome is reported this way.** A file that could
/// not be decoded, that exhausted a budget, or that turned out to be encrypted
/// is a successful call returning a [`ScanReport`] whose [`Verdict`] says so.
///
/// An `Err` means the file was not scanned: report it as an error, never as
/// clean. An `Ok` is not "clean" either until its verdict says so.
///
/// # Panics
///
/// Individual decoders are wrapped, so malformed content yields a verdict
/// rather than unwinding. Two failure modes are outside that boundary and will
/// take the process down: an allocation large enough to abort, and stack
/// exhaustion from a deeply self-nested file. A caller that must survive
/// arbitrary input needs an out-of-process bound; see `SECURITY.md`.
pub fn scan_path(db: &Scanner, path: &Path, opts: &ScanOptions) -> io::Result<ScanReport> {
    let opts = named(opts, path);
    let (file, size) = open_file(path)?;
    scan_seekable(db, file, size, &opts)
}

/// The platform's `O_NONBLOCK`, whose value differs between systems and, on
/// Linux, between architectures. Written here rather than taken from the
/// `libc` crate; a test compares it with `libc`'s.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "mips32r6",
        target_arch = "mips64r6"
    )
))]
const O_NONBLOCK: i32 = 0o200;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "sparc", target_arch = "sparc64")
))]
const O_NONBLOCK: i32 = 0x4000;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    not(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "mips32r6",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64"
    ))
))]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NONBLOCK: i32 = 0x4;
#[cfg(any(target_os = "solaris", target_os = "illumos"))]
const O_NONBLOCK: i32 = 0x80;
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "solaris",
        target_os = "illumos"
    ))
))]
compile_error!("O_NONBLOCK is not written for this system: add its value next to the others");

/// Open `path` to be read, with its size. A FIFO is refused, as a file that
/// cannot be scanned in place: the type is read from the open descriptor, and
/// the open does not wait for a writer, so a path that became a FIFO after the
/// caller looked at it does not hold the scan.
///
/// On Unix the descriptor stays `O_NONBLOCK`, which a regular file ignores.
fn open_file(path: &Path) -> io::Result<(File, u64)> {
    let mut open = std::fs::OpenOptions::new();
    open.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut open, O_NONBLOCK);
    let file = open.open(path)?;
    let meta = file.metadata()?;
    #[cfg(unix)]
    if std::os::unix::fs::FileTypeExt::is_fifo(&meta.file_type()) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Not supported file type",
        ));
    }
    Ok((file, meta.len()))
}

/// As [`analyze_all_seekable`], for the file at `path`, named for YARA as
/// [`scan_path`] names it.
pub fn analyze_all_path(
    db: &Scanner,
    path: &Path,
    opts: &ScanOptions,
) -> io::Result<(Vec<(String, Method)>, AllMatchOutcome)> {
    let opts = named(opts, path);
    let (file, size) = open_file(path)?;
    analyze_all_seekable(db, file, size, &opts)
}

/// `opts` with the file at `path` as YARA's `filepath`, `filename` and
/// `extension`, unless the caller set a name.
fn named<'a>(opts: &'a ScanOptions, path: &Path) -> std::borrow::Cow<'a, ScanOptions> {
    if opts.filename.is_some() {
        return std::borrow::Cow::Borrowed(opts);
    }
    let mut o = opts.clone();
    o.filename = Some(path.to_string_lossy().into_owned());
    std::borrow::Cow::Owned(o)
}

/// Whether the object's whole-file hash is on the `.fp`/`.sfp` allowlist.
fn allowlisted(db: &Scanner, facts: &Facts) -> bool {
    !db.allow.is_empty()
        && db
            .allow
            .lookup(facts.digests(db), facts.data.len() as u64)
            .is_some()
}

/// Build every structure a scan initialises lazily (compiled YARA rules and
/// their automata), so a process that forks workers after loading shares them
/// copy-on-write instead of each worker building its own.
pub fn warm_up(db: &Scanner) {
    const PROBE: &[u8] = b"MZ\x90\x00\x00\x00\x00\x00";
    let _ = analyze(db, PROBE, &ScanOptions::default());
}

/// As [`scan_seekable`], additionally returning the container-member path of the
/// detection (e.g. `"inner.zip/evil.exe"`), or `None` for a top-level detection
/// or a clean scan. Used by the daemon's location-aware `EXINSTREAM` reply.
pub fn scan_seekable_located<R: Read + Seek>(
    db: &Scanner,
    reader: R,
    size: u64,
    opts: &ScanOptions,
) -> io::Result<(ScanReport, Option<String>)> {
    let mut first_at = None;
    let report = scan_seekable_addressing(
        db,
        reader,
        size,
        opts,
        byte_source::ADDRESSABLE,
        &mut first_at,
    )?;
    Ok((report, first_at))
}

/// Scan an input: the one scan every entry point runs, whether the bytes come
/// from a file, a buffered stream (stdin, `INSTREAM`, ICAP) or an HTTP range
/// source.
///
/// `size` is the input's full size. Past `--max-input-bytes` the reader need
/// only hold the first `max_scan_size` bytes: those get the whole scan, and
/// with no detection in them the input is reported over the limit. So is an
/// input longer than the build can address (4 GiB on a 32-bit target).
///
/// An input within `limits.max_buffer_bytes` is read into memory; a larger one is
/// read through a block cache of bounded size, by offset, as the scan needs it.
/// Either way it gets the same scan.
pub fn scan_seekable<R: Read + Seek>(
    db: &Scanner,
    reader: R,
    size: u64,
    opts: &ScanOptions,
) -> io::Result<ScanReport> {
    scan_seekable_addressing(db, reader, size, opts, byte_source::ADDRESSABLE, &mut None)
}

/// The most bytes of an input that are scanned: `--max-input-bytes` or what
/// the build can address, whichever is less.
fn size_ceiling(opts: &ScanOptions, addressable: u64) -> u64 {
    opts.max_scan_size
        .map_or(addressable, |max| max.min(addressable))
}

/// [`scan_seekable`] on a build that addresses `addressable` bytes.
fn scan_seekable_addressing<R: Read + Seek>(
    db: &Scanner,
    mut reader: R,
    size: u64,
    opts: &ScanOptions,
    addressable: u64,
    first_at: &mut Option<String>,
) -> io::Result<ScanReport> {
    // Thread-local, so it carries over from whatever this thread scanned last
    // unless every entry point clears it.
    engine::reset_scan_truncated();
    let max = size_ceiling(opts, addressable);
    if size > max {
        // Invariant 2 (see crate docs): scan what is within the limit
        // before refusing by size, so a detection in it still wins.
        let head = scan_within(db, Window::new(&mut reader, max)?, max, opts, first_at)?;
        if head.verdict.category() == VerdictCategory::Infected {
            return Ok(head);
        }
        return Ok(max_file_size_report(size, max, opts));
    }
    scan_within(db, reader, size, opts, first_at)
}

/// [`scan_seekable`] for an input within `--max-input-bytes`.
fn scan_within<R: Read + Seek>(
    db: &Scanner,
    mut reader: R,
    size: u64,
    opts: &ScanOptions,
    first_at: &mut Option<String>,
) -> io::Result<ScanReport> {
    if let Some(data) = held(&mut reader, size, opts.limits.max_buffer_bytes)? {
        return Ok(analyze_source_at(db, &data.as_slice(), opts, first_at));
    }
    let cache = opts.object_cache(reader)?;
    let report = analyze_source_at(db, &cache, opts, first_at);
    // A read that failed part way leaves bytes the scan never saw, unless
    // what it saw holds a signature's match: a heuristic or a rule can come
    // of the bytes that are missing.
    if let Some(e) = cache.read_error()
        && !matches!(
            report.verdict,
            Verdict::Infected {
                method: Method::Pattern | Method::Hash,
                ..
            }
        )
    {
        return Err(io::Error::other(e));
    }
    Ok(report)
}

/// An input of `size` bytes read from its start: in memory when it is within
/// `hold`, `None` when it is to be read through the block cache. A descriptor
/// passed over a socket (`FILDES`) shares its offset with the sender, who may
/// have left it anywhere; a pipe has no offset, and gives what it holds.
fn held<R: Read + Seek>(reader: &mut R, size: u64, hold: u64) -> io::Result<Option<Vec<u8>>> {
    match reader.seek(SeekFrom::Start(0)) {
        Err(e) if e.kind() != io::ErrorKind::NotSeekable => return Err(e),
        _ => {}
    }
    if size > hold {
        return Ok(None);
    }
    // Bounded, so a source whose size under-reports its length cannot
    // stream unbounded.
    let mut data = Vec::new();
    unpack::source::read_capped(reader, &mut data, hold.saturating_add(1))?;
    if data.len() as u64 <= hold {
        return Ok(Some(data));
    }
    // It grew while it was read: scanned as the larger object it now is, if it
    // says it is. A device that reads on without end (`/dev/zero`) measures
    // nothing, and a scan of its measure would be of no bytes.
    let end = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;
    if end <= hold {
        return Err(io::Error::other(format!(
            "the source gave more than {hold} bytes and says it has {end}: \
             it is not a file with a length, and cannot be scanned as one"
        )));
    }
    Ok(None)
}

/// The first `len` bytes of a seekable source, as a seekable source of its own.
struct Window<R> {
    inner: R,
    len: u64,
    pos: u64,
}

impl<R: Read + Seek> Window<R> {
    fn new(mut inner: R, len: u64) -> io::Result<Self> {
        inner.seek(SeekFrom::Start(0))?;
        Ok(Self { inner, len, pos: 0 })
    }
}

impl<R: Read> Read for Window<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let room = self.len.saturating_sub(self.pos);
        let want = (buf.len() as u64).min(room) as usize;
        if want == 0 {
            return Ok(0);
        }
        let n = self.inner.read(&mut buf[..want])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Seek> Seek for Window<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(o) => Some(o),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        self.pos = self.inner.seek(SeekFrom::Start(target))?;
        Ok(self.pos)
    }
}

/// Build an extraction [`Budget`] carrying the password pool for decrypting
/// encrypted archive members: the union of the database `.pwdb` pool and the
/// runtime [`ScanOptions::passwords`]. Runtime passwords are tried first (a
/// caller responding to a `PasswordProtected` verdict wins), then the `.pwdb`
/// pool; duplicates are dropped, preserving order.
fn scan_budget(db: &Scanner, opts: &ScanOptions) -> Budget {
    let mut pool: Vec<String> = Vec::with_capacity(opts.passwords.len() + db.passwords.len());
    for pw in opts.passwords.iter().chain(db.passwords.iter()) {
        if !pool.contains(pw) {
            pool.push(pw.clone());
        }
    }
    let mut b = Budget::with_passwords(opts.limits.clone(), pool);
    b.set_verify_checksums(opts.verify_checksums);
    // Only the QR search reads the pixels of a PDF image.
    b.set_rasters(cfg!(feature = "qr") && opts.qr_codes && !opts.clamav_compat);
    b
}

/// ClamAV's alert name for a budget stop. The kind is carried on the
/// [`unpack::LimitHit`] as a type rather than parsed back out of the reason
/// text, so rewording a message can never silently change the alert.
fn limits_alert_name(kind: unpack::LimitKind) -> Option<&'static str> {
    use unpack::LimitKind as K;
    match kind {
        K::MaxScanSize => Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        K::MaxFileSize => Some("Heuristics.Limits.Exceeded.MaxFileSize"),
        K::MaxFiles => Some("Heuristics.Limits.Exceeded.MaxFiles"),
        K::MaxRecursion => Some("Heuristics.Limits.Exceeded.MaxRecursion"),
        K::MaxScanTime => Some("Heuristics.Limits.Exceeded.MaxScanTime"),
        // Malformed input, not a budget stop, so no budget alert names it.
        K::Corrupt => None,
        // `LimitKind` is `#[non_exhaustive]`. A kind added later and not named
        // here has no alert, and the caller falls back to the `LimitsExceeded`
        // verdict carrying the real reason. Carrying the kind as a type is what
        // lets the name be looked up instead of guessed; a guess here would put
        // one budget's name on another budget's stop.
        _ => None,
    }
}

/// The report for a top-level file larger than `max_scan_size`.
///
/// This is ClamAV's `MaxFileSize` condition, so under `--partial-as found` it
/// reports under ClamAV's own name for it, `Heuristics.Limits.Exceeded.*`,
/// which a ClamAV-shaped pipeline matches, rather than a synthesised
/// `Heuristics.Exav.*` that nothing does. Both entry points that enforce the
/// ceiling come through here, so the two cannot name one condition two ways,
/// and the kind is passed as a type so the name is looked up and never guessed.
fn max_file_size_report(size: u64, max: u64, opts: &ScanOptions) -> ScanReport {
    match max_file_size(size, max, opts) {
        Ok(name) => ScanReport::infected(name.to_string(), 0, Method::Heuristic, Vec::new()),
        Err(reason) => ScanReport::limits(reason, Vec::new()),
    }
}

/// The alert a top-level file larger than [`size_ceiling`] is reported as
/// under `--alert-exceeds-max`, or else the reason it is over the limit.
fn max_file_size(size: u64, max: u64, opts: &ScanOptions) -> Result<&'static str, String> {
    if opts.alert_exceeds_max
        && let Some(name) = limits_alert_name(unpack::LimitKind::MaxFileSize)
    {
        return Ok(name);
    }
    if opts.max_scan_size == Some(max) {
        return Err(format!(
            "file size {size} exceeds max-input-bytes {max}; scanned first {max} bytes only"
        ));
    }
    Err(format!(
        "file size {size} is past the {max} bytes this build can address; \
         scanned first {max} bytes only"
    ))
}

/// Turn a budget stop into an outcome, honouring `--alert-exceeds-max`.
///
/// The flag only changes the *shape* of the report, never whether the scan is
/// treated as complete: a kind with no alert name keeps the `LimitsExceeded`
/// verdict and its reason.
fn limits_outcome(opts: &ScanOptions, kind: unpack::LimitKind, reason: String) -> DeepOutcome {
    if opts.alert_exceeds_max
        && let Some(name) = limits_alert_name(kind)
    {
        return DeepOutcome::Infected {
            signature: name.to_string(),
            offset: 0,
            method: Method::Heuristic,
        };
    }
    DeepOutcome::Limits(reason)
}

/// [`limits_outcome`] for a stop inside the object `sink` is under: an alert
/// is located there, as a detection is.
fn limits_outcome_at(
    opts: &ScanOptions,
    sink: &mut Sink,
    kind: unpack::LimitKind,
    reason: String,
) -> DeepOutcome {
    let outcome = limits_outcome(opts, kind, reason);
    if matches!(outcome, DeepOutcome::Infected { .. }) {
        sink.record();
    }
    outcome
}

/// Map an extraction [`unpack::LimitHit`] to an outcome: a resource bound is
/// `Limits` (or its alert under `--alert-exceeds-max`); undecodable content is
/// `Unscannable`.
fn outcome_for_hit(hit: unpack::LimitHit, opts: &ScanOptions, sink: &mut Sink) -> DeepOutcome {
    match tree::ReasonKind::from_limit(hit.kind) {
        tree::ReasonKind::Limit(kind) => limits_outcome_at(opts, sink, kind, hit.reason),
        kind => DeepOutcome::Unscannable(tree::Reason {
            kind,
            text: hit.reason,
            at: String::new(),
        }),
    }
}

/// Scan the part of a member that decoded before the stream ended as `end`.
/// Every byte that decoded is scanned. A member that ran out of input has its
/// tail absent, not hidden, and a clean scan of it is a real Clean: exav scans
/// for malware, it is not a file-integrity validator. Undecodable bytes still
/// present keep the not-fully-scanned verdict.
#[allow(clippy::too_many_arguments)]
fn scan_salvaged(
    cx: &MemberCtx<'_>,
    reasons: &mut tree::Reasons,
    path: tree::Path<'_>,
    data: &dyn ByteSource,
    meta: Option<&unpack::MemberMeta>,
    end: &tree::End,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    let o = member_content_scan(cx, reasons, path, data, meta, budget, findings, sink);
    if o.is_none()
        && let tree::End::Damaged(why) = end
    {
        note(
            reasons,
            &path,
            tree::ReasonKind::Damaged,
            format!(
                "member decode error (salvaged {} B, no match): {why}",
                data.len()
            ),
        );
    }
    o
}

/// Note a reason that does not stop the walk, for the object at `path`.
fn note(reasons: &mut tree::Reasons, path: &tree::Path<'_>, kind: tree::ReasonKind, text: String) {
    reasons.add_at(
        tree::Reason {
            kind,
            text,
            at: String::new(),
        },
        path,
    );
}

/// One member of a container walk: its metadata, then its bytes, scanned as an
/// object one level down. `Some` means the walk must stop.
#[allow(clippy::too_many_arguments)]
fn visit_member(
    cx: &MemberCtx<'_>,
    encrypted: &mut Option<&'static str>,
    node: &tree::Node<'_>,
    meta: &unpack::MemberMeta,
    reasons: &mut tree::Reasons,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    if let Some(o) = member_metadata_scan(cx, encrypted, node, meta, reasons, sink) {
        return Some(o);
    }
    // No bytes: nothing decoded and the metadata above is all this member has,
    // or it is a part of a byte-split set, held to be scanned with the rest.
    let data = node.source()?;
    let o = if node.end.is_complete() {
        member_content_scan(
            cx,
            reasons,
            node.path,
            data,
            Some(meta),
            budget,
            findings,
            sink,
        )
    } else {
        scan_salvaged(
            cx,
            reasons,
            node.path,
            data,
            Some(meta),
            &node.end,
            budget,
            findings,
            sink,
        )
    };
    // The first bytes of a member too large to hold, and nowhere to write it.
    let Some(why) = node.capped else {
        return o;
    };
    if o.is_some() {
        return o;
    }
    match limits_outcome_at(
        cx.opts,
        sink,
        unpack::LimitKind::MaxFileSize,
        why.to_string(),
    ) {
        DeepOutcome::Limits(r) => {
            note(
                reasons,
                &node.path,
                tree::ReasonKind::Limit(unpack::LimitKind::MaxFileSize),
                r,
            );
            None
        }
        alert => Some(alert),
    }
}

/// The members of one container, scanned as objects one level down.
struct Members<'a, 'b> {
    cx: &'a MemberCtx<'a>,
    findings: &'a mut Vec<Finding>,
    sink: &'a mut Sink<'b>,
    /// The `--alert-encrypted` name for a member stored encrypted whose
    /// content was read anyway (decrypted, or not encrypted after all): held
    /// until the walk ends, so a signature in that content wins over it.
    encrypted: Option<&'static str>,
    /// The first limit a member's own scan ended in while scan budget was
    /// left: held until the walk ends, so the members after it are scanned.
    limit: Option<String>,
}

impl tree::Visitor<DeepOutcome> for Members<'_, '_> {
    fn visit(
        &mut self,
        node: &tree::Node<'_>,
        cx: &mut tree::Cx<'_>,
        reasons: &mut tree::Reasons,
    ) -> tree::Flow<DeepOutcome> {
        // A detection in the member, or deeper, is located at its path.
        let mut sink = self.sink.under(node.path);
        let budget = cx.budget();
        let outcome = match node.meta {
            Some(meta) => visit_member(
                self.cx,
                &mut self.encrypted,
                node,
                meta,
                reasons,
                budget,
                self.findings,
                &mut sink,
            ),
            // A set rejoined from its parts: its metadata was read part by part.
            None => node.source().and_then(|data| {
                member_content_scan(
                    self.cx,
                    reasons,
                    node.path,
                    data,
                    None,
                    budget,
                    self.findings,
                    &mut sink,
                )
            }),
        };
        match outcome {
            // A member that is a container whose walk met a limit leaves the
            // rest of this one to scan, while there is budget to scan it.
            Some(DeepOutcome::Limits(text)) if budget.remaining_scan() > 0 => {
                self.limit.get_or_insert(text);
                tree::Flow::Leaf
            }
            Some(stop) => tree::Flow::Stop(stop),
            None => tree::Flow::Leaf,
        }
    }
}

/// Walk a container's members, each scanned as an object one level down.
///
/// What does not stop the walk (a member encrypted, undecodable, or cut short
/// by a limit) is kept on a tally and decides the verdict once every member has
/// been seen, so an early bad member cannot mask a malicious sibling, and "not
/// fully scanned is never Clean" holds.
#[allow(clippy::too_many_arguments)]
fn walk_members(
    db: &Scanner,
    data: &dyn ByteSource,
    obj: Obj<'_>,
    ft: FileType,
    fmt: unpack::Format,
    opts: &ScanOptions,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> DeepOutcome {
    let walk = opts.walk();
    let mut cx = tree::Cx::new(&walk, budget);
    // A container at the depth limit is not opened: nothing of it is read.
    if let Some(hit) = cx.depth_hit(obj.depth) {
        return outcome_for_hit(hit, opts, sink);
    }
    // The type the members belong to, so signatures scoped with
    // `Container:CL_TYPE_*` fire only inside their intended container. A ZIP
    // is sub-typed as OOXML Word/Excel/PowerPoint by its part names.
    let member_container = container_cltype(fmt, data);
    // The members are one layer below this container, so it is on their
    // ancestry (`Intermediates:`).
    let link = engine::Link::new(obj.ancestry, member_container);
    let mctx = MemberCtx {
        db,
        opts,
        container_size: data.len() as u64,
        container_is_ole: fmt == unpack::Format::Ole,
        member_container,
        ancestry: engine::Ancestors::of(&link),
        ft,
        fmt,
        depth: obj.depth,
        message_inside: obj.message_inside,
    };
    let mut members = Members {
        cx: &mctx,
        findings: &mut *findings,
        sink: &mut *sink,
        encrypted: None,
        limit: None,
    };
    // Inclusive wall time: this drives the member scans, so `unpack_us`
    // contains the member matchers' time too, and `emu_us` splits the
    // emulator's share of it out.
    let below = profile::timed("unpack", data.len() as u64, || {
        cx.members(&obj.path, obj.depth, data, fmt, &mut members)
    });
    let encrypted = members.encrypted.take();
    let limit = members.limit.take();
    let tree::Descent { ended, reasons, .. } = below;
    let terminal = match ended {
        tree::Ended::Complete => None,
        tree::Ended::Stopped(outcome) => Some(outcome),
        tree::Ended::Limit(hit) => Some(outcome_for_hit(hit, opts, sink)),
    };
    if let Some(name) = encrypted
        && !matches!(terminal, Some(DeepOutcome::Infected { .. }))
        && let Some(o) = sink.hit(name.to_string(), 0, Method::Heuristic)
    {
        return o;
    }
    // A bound a reader noted on a member is reported as the walk's own stops
    // are, as its alert under `--alert-exceeds-max`, and that is a detection:
    // it beats password protection and a stop at damage.
    if opts.alert_exceeds_max
        && !matches!(terminal, Some(DeepOutcome::Infected { .. }))
        && let Some(tree::Reason {
            kind: tree::ReasonKind::Limit(kind),
            text,
            ..
        }) = &reasons.limits
        && limits_alert_name(*kind).is_some()
    {
        return limits_outcome_at(opts, sink, *kind, text.clone());
    }
    // Password protection over a limit over the rest, as the reasons fold,
    // and a detection over all: a walk that stopped at a limit or at damage
    // still reports a member it found encrypted before.
    let terminal = terminal
        .filter(|t| matches!(t, DeepOutcome::Infected { .. }) || reasons.password.is_none());
    terminal.unwrap_or_else(|| match reasons.into_first() {
        // A bound a reader noted on a member is reported as the walk's own
        // stops are, as its alert under `--alert-exceeds-max`.
        Some(tree::Reason {
            kind: tree::ReasonKind::Limit(kind),
            text,
            ..
        }) if !matches!(kind, unpack::LimitKind::Corrupt) => {
            limits_outcome_at(opts, sink, kind, text)
        }
        Some(r) if r.kind == tree::ReasonKind::Password || limit.is_none() => reason_outcome(r),
        _ => limit.map_or(DeepOutcome::Clean, DeepOutcome::Limits),
    })
}

/// The verdict of a multi-volume archive, reported against one of its parts.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VolumeSetVerdict {
    /// The part this verdict is attributed to: one of the names given.
    pub name: String,
    /// The name of the archive the part belongs to (`big.7z` for `big.7z.001`).
    pub set: String,
    pub report: ScanReport,
}

/// Every detection in a multi-volume archive, reported against one of its
/// parts: [`VolumeSetVerdict`] for the `_all` entry points.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VolumeSetMatches {
    /// The part this result is attributed to: one of the names given.
    pub name: String,
    /// The name of the archive the part belongs to.
    pub set: String,
    /// The detections, as [`analyze_all_with_outcome`] lists them.
    pub found: Vec<(String, Method)>,
    /// Whether the search finished. A set that cannot be joined has no
    /// detections and an [`AllMatchOutcome::Unscannable`] outcome.
    pub outcome: AllMatchOutcome,
}

/// Scan the **multi-volume archives** spread across a group of files that
/// arrived together: a directory, a client's multi-file request.
///
/// A set like `big.7z.001`, `.002`, `.003` is one archive cut into pieces at
/// arbitrary byte offsets. Handed to a scanner one file at a time, no piece
/// decodes and all of them report clean, so whatever the archive holds is never
/// looked at. This rejoins each set and scans it as the file it is.
///
/// Cheap to call on anything. `fetch` is invoked **only** for names that parse
/// as a part of a byte-split set, so pointing this at a directory of large
/// files costs one name parse each and reads nothing.
///
/// A part that cannot be read, or that the collector will not hold, takes its
/// whole set with it. Byte-split naming records no part count, so a set missing
/// its LAST part still looks contiguous and would join into a truncated prefix,
/// which parses as the archive and scans clean. The set is reported
/// `Unscannable` instead, each part read and not held included. The caller's
/// own scan of a part says only that the fragment is not malware itself.
///
/// Returns one entry per *part*, each carrying the verdict of the archive that
/// part belongs to, including `Unscannable` for a set with a hole in it, whose
/// bytes belong to an archive nothing can read. Callers report these against
/// the part's own name: one result per file, and a piece of an infected archive
/// is not a clean file.
///
/// Format-aware volumes (RAR `.partN`, ZIP `.zNN`) are **not** handled here.
/// Each of those carries its own headers and a member's data resumes past the
/// next volume's header, so concatenating them yields garbage that still looks
/// like an archive: the join has to be done by the format's own decoder.
#[inline]
pub fn analyze_volume_sets<F>(
    db: &Scanner,
    names: &[String],
    opts: &ScanOptions,
    mut fetch: F,
) -> Vec<VolumeSetVerdict>
where
    F: FnMut(&str) -> io::Result<Vec<u8>>,
{
    first_verdicts(byte_split_sets(db, names, opts, false, &mut fetch))
}

/// As [`analyze_volume_sets`], listing every detection of each set as
/// [`analyze_all_with_outcome`] does, in place of the first.
#[inline]
pub fn analyze_volume_sets_all<F>(
    db: &Scanner,
    names: &[String],
    opts: &ScanOptions,
    mut fetch: F,
) -> Vec<VolumeSetMatches>
where
    F: FnMut(&str) -> io::Result<Vec<u8>>,
{
    all_matches(byte_split_sets(db, names, opts, true, &mut fetch))
}

/// A set scanned: its parts, its name and what the scan found.
struct ScannedSet {
    parts: Vec<String>,
    set: String,
    scan: SetScan,
}

/// What the scan of a set found: the first match or every match.
enum SetScan {
    First(ScanReport),
    All(Vec<(String, Method)>, AllMatchOutcome),
}

/// Scan a joined set, or report why it could not be joined. `all` lists every
/// detection instead of the first.
fn scan_set(
    db: &Scanner,
    opts: &ScanOptions,
    all: bool,
    joined: Result<&dyn ByteSource, String>,
) -> SetScan {
    match (joined, all) {
        (Ok(src), false) => SetScan::First(analyze_joined(db, src, opts)),
        (Ok(src), true) => {
            let (found, outcome) = analyze_all_joined(db, src, opts);
            SetScan::All(found, outcome)
        }
        (Err(why), false) => SetScan::First(ScanReport::unscannable(why, Vec::new())),
        (Err(why), true) => SetScan::All(Vec::new(), AllMatchOutcome::Unscannable(one_line(why))),
    }
}

/// The scan of each set under every one of its parts, as [`VolumeSetVerdict`]s.
fn first_verdicts(sets: Vec<ScannedSet>) -> Vec<VolumeSetVerdict> {
    let mut out = Vec::new();
    for ScannedSet { parts, set, scan } in sets {
        // Built by `scan_set` with `all` false.
        if let SetScan::First(report) = scan {
            for part in parts {
                out.push(VolumeSetVerdict {
                    name: part,
                    set: set.clone(),
                    report: report.clone(),
                });
            }
        }
    }
    out
}

/// The scan of each set under every one of its parts, as [`VolumeSetMatches`].
fn all_matches(sets: Vec<ScannedSet>) -> Vec<VolumeSetMatches> {
    let mut out = Vec::new();
    for ScannedSet { parts, set, scan } in sets {
        // Built by `scan_set` with `all` true.
        if let SetScan::All(found, outcome) = scan {
            for part in parts {
                out.push(VolumeSetMatches {
                    name: part,
                    set: set.clone(),
                    found: found.clone(),
                    outcome: outcome.clone(),
                });
            }
        }
    }
    out
}

/// Rejoin each byte-split set among `names` and scan it with [`scan_set`].
fn byte_split_sets(
    db: &Scanner,
    names: &[String],
    opts: &ScanOptions,
    all: bool,
    fetch: &mut dyn FnMut(&str) -> io::Result<Vec<u8>>,
) -> Vec<ScannedSet> {
    // Each set gets its own budget, as every file in a scan does. A set needs at
    // least two parts, and the caller scans each of those parts on its own
    // anyway, so rejoining adds at most one budgeted scan per two files the
    // caller had already committed to. Held bytes across all sets are capped by
    // the rejoin, so no aggregate budget is threaded through here.
    unpack::volume::rejoin_byte_split(names, opts.limits.max_buffer_bytes, fetch)
        .into_iter()
        .map(|set| {
            let scan = match &set.state {
                unpack::volume::State::Joined(data) => {
                    let bytes: &[u8] = data;
                    scan_set(db, opts, all, Ok(&bytes))
                }
                unpack::volume::State::Unjoinable(reason) => {
                    scan_set(db, opts, all, Err(reason.to_string()))
                }
            };
            ScannedSet {
                parts: set.parts,
                set: set.set,
                scan,
            }
        })
        .collect()
}

/// The sets of **format-aware volumes** among a group of files that arrived
/// together, each put back into the one archive it was cut from and scanned:
/// RAR (`x.part1.rar`, `x.part2.rar`, ..., or `x.rar`, `x.r00`, ...), ZIP
/// (`x.z01`, `x.z02`, ..., `x.zip`) and CAB (`a.cab`, `b.cab`, as each header
/// names the one after it). Each volume carries its own headers, so the join is
/// the format's, not a concatenation, and the parts of a set scanned alone are
/// cut short.
///
/// `fetch(name, None)` is a whole file and `fetch(name, Some(n))` its first `n`
/// bytes. Whole files are fetched only for the parts of a set, up to
/// `max-object-bytes` of them together; the heads of `.cab` files are read to
/// find which of them name a neighbour. Names are labels, never paths: a
/// cabinet's own header names its neighbours, and they are looked for in
/// `names` only. [`analyze_split_sets_seekable`] reads the parts where they
/// lie instead, with no limit on the size of a set.
///
/// As [`analyze_volume_sets`]: one entry per *part*, with the verdict of the
/// archive that part belongs to, `Unscannable` for a set with a hole in it or
/// one that does not fit together. A file that is not part of a set is not in
/// the result.
#[cfg(feature = "all-formats")]
pub fn analyze_split_sets<F>(
    db: &Scanner,
    names: &[String],
    opts: &ScanOptions,
    mut fetch: F,
) -> Vec<VolumeSetVerdict>
where
    F: FnMut(&str, Option<usize>) -> io::Result<Vec<u8>>,
{
    first_verdicts(split_sets(
        db,
        names,
        opts,
        false,
        &mut unpack::volume::Parts::Memory(&mut fetch),
    ))
}

/// As [`analyze_split_sets`], reading each part where it lies: `open(name)`
/// is the file, which is read through a block cache as the scan needs it, the
/// caches of a set sharing `object_cache_bytes`. The parts of a RAR or ZIP set
/// are read as the one archive they were cut from, whatever its size, so the
/// memory a set takes does not grow with it. A CAB set is joined in memory, up
/// to `max-object-bytes`, as [`analyze_split_sets`] does.
///
/// A set is read with its parts open together.
#[cfg(feature = "all-formats")]
pub fn analyze_split_sets_seekable<R, F>(
    db: &Scanner,
    names: &[String],
    opts: &ScanOptions,
    mut open: F,
) -> Vec<VolumeSetVerdict>
where
    R: Read + Seek + 'static,
    F: FnMut(&str) -> io::Result<R>,
{
    let mut part = cached_part(opts, &mut open);
    first_verdicts(split_sets(
        db,
        names,
        opts,
        false,
        &mut unpack::volume::Parts::Files(&mut part),
    ))
}

/// As [`analyze_split_sets_seekable`], listing every detection of each set as
/// [`analyze_all_with_outcome`] does, in place of the first.
#[cfg(feature = "all-formats")]
pub fn analyze_split_sets_seekable_all<R, F>(
    db: &Scanner,
    names: &[String],
    opts: &ScanOptions,
    mut open: F,
) -> Vec<VolumeSetMatches>
where
    R: Read + Seek + 'static,
    F: FnMut(&str) -> io::Result<R>,
{
    let mut part = cached_part(opts, &mut open);
    all_matches(split_sets(
        db,
        names,
        opts,
        true,
        &mut unpack::volume::Parts::Files(&mut part),
    ))
}

/// Each part of a set opened through a block cache, the caches of a set sharing
/// `object_cache_bytes`.
#[cfg(feature = "all-formats")]
fn cached_part<'a, R, F>(
    opts: &'a ScanOptions,
    open: &'a mut F,
) -> impl FnMut(&str, usize) -> io::Result<Box<dyn ByteSource>> + 'a
where
    R: Read + Seek + 'static,
    F: FnMut(&str) -> io::Result<R>,
{
    move |name: &str, of: usize| {
        let (block, bytes) = opts.cache_sizes();
        // Room for two blocks at least in each cache: smaller blocks when
        // there are many parts.
        let share = bytes / of.max(1);
        let block = block.min((share / 2).max(4096));
        Ok(Box::new(byte_source::BlockCache::with_sizes(
            open(name)?,
            block,
            share,
        )?))
    }
}

/// Plan and join each set of format-aware volumes among `names` and scan it
/// with [`scan_set`].
#[cfg(feature = "all-formats")]
fn split_sets(
    db: &Scanner,
    names: &[String],
    opts: &ScanOptions,
    all: bool,
    files: &mut unpack::volume::Parts<'_>,
) -> Vec<ScannedSet> {
    let mut held_total = 0usize;
    let mut out = Vec::new();
    for set in unpack::volume::plan(names, files) {
        let joined = unpack::volume::join(&set, files, opts.hold_limit(), &mut held_total);
        out.push(ScannedSet {
            scan: scan_set(db, opts, all, joined.as_deref().map_err(String::clone)),
            parts: set.parts,
            set: set.name,
        });
    }
    out
}

/// [`analyze_joined`] listing every detection. A part that could not be read
/// leaves bytes the scan never saw, so the search is not complete, whatever it
/// found.
fn analyze_all_joined(
    db: &Scanner,
    joined: &dyn ByteSource,
    opts: &ScanOptions,
) -> (Vec<(String, Method)>, AllMatchOutcome) {
    let (found, outcome) = analyze_all_source(db, joined, opts);
    match (&outcome, joined.read_error()) {
        (AllMatchOutcome::Complete, Some(_)) => (
            found,
            AllMatchOutcome::Unscannable(
                "part of a multi-volume set one of whose volumes could not be read".to_string(),
            ),
        ),
        _ => (found, outcome),
    }
}

/// [`analyze_source`] over the parts of a set read as one archive. A part that
/// could not be read leaves bytes the scan never saw, so a scan that found
/// nothing is not clean.
fn analyze_joined(db: &Scanner, joined: &dyn ByteSource, opts: &ScanOptions) -> ScanReport {
    let report = analyze_source(db, joined, opts);
    match (&report.verdict, joined.read_error()) {
        (Verdict::Clean, Some(_)) => ScanReport::unscannable(
            "part of a multi-volume set one of whose volumes could not be read".to_string(),
            report.findings,
        ),
        _ => report,
    }
}

/// Without `all-formats` no archive format is read, so no part of a set of
/// volumes is known to belong to one: nothing is joined.
#[cfg(not(feature = "all-formats"))]
pub fn analyze_split_sets<F>(
    _db: &Scanner,
    _names: &[String],
    _opts: &ScanOptions,
    _fetch: F,
) -> Vec<VolumeSetVerdict>
where
    F: FnMut(&str, Option<usize>) -> io::Result<Vec<u8>>,
{
    Vec::new()
}

/// As [`analyze_split_sets`] without `all-formats`: nothing is joined.
#[cfg(not(feature = "all-formats"))]
pub fn analyze_split_sets_seekable<R, F>(
    _db: &Scanner,
    _names: &[String],
    _opts: &ScanOptions,
    _open: F,
) -> Vec<VolumeSetVerdict>
where
    R: Read + Seek + 'static,
    F: FnMut(&str) -> io::Result<R>,
{
    Vec::new()
}

/// As [`analyze_split_sets_seekable_all`] without `all-formats`: nothing is
/// joined.
#[cfg(not(feature = "all-formats"))]
pub fn analyze_split_sets_seekable_all<R, F>(
    _db: &Scanner,
    _names: &[String],
    _opts: &ScanOptions,
    _open: F,
) -> Vec<VolumeSetMatches>
where
    R: Read + Seek + 'static,
    F: FnMut(&str) -> io::Result<R>,
{
    Vec::new()
}

/// Scan an object held in memory: [`scan_seekable`] without the reader, and
/// without its [`ScanOptions::max_scan_size`] check: the slice is scanned
/// whole.
pub fn analyze(db: &Scanner, data: &[u8], opts: &ScanOptions) -> ScanReport {
    analyze_source(db, &data, opts)
}

/// As [`analyze`], over an object that need not be held in memory.
fn analyze_source(db: &Scanner, data: &dyn ByteSource, opts: &ScanOptions) -> ScanReport {
    analyze_source_at(db, data, opts, &mut None)
}

/// [`analyze_source`], with the location of the first detection that is in a
/// container left in `first_at`.
fn analyze_source_at(
    db: &Scanner,
    data: &dyn ByteSource,
    opts: &ScanOptions,
    first_at: &mut Option<String>,
) -> ScanReport {
    engine::reset_scan_truncated();
    let mut findings = Vec::new();
    let mut budget = scan_budget(db, opts);
    let outcome = scan_object(
        db,
        data,
        Obj::top(opts),
        opts,
        &mut budget,
        &mut findings,
        &mut Sink::first(&db.ignored, first_at),
    );
    report_of_outcome(outcome, findings, opts)
}

/// Turn a walk's outcome into the report a caller sees.
///
/// The walk speaks one currency, [`DeepOutcome`], whatever entry point drove
/// it; this is the single place that becomes a [`ScanReport`].
///
/// "Not-fully-scanned is never Clean" holds in EVERY mode: exav never
/// downgrades a real safety verdict to `Clean` to mimic clam's silent `OK`.
/// compat matches clam's capabilities and naming, not this. (A diff harness
/// should bucket exav-`UNSCANNABLE` vs clam-`OK` as an expected capability
/// difference, not have exav lie.)
fn report_of_outcome(
    outcome: DeepOutcome,
    findings: Vec<Finding>,
    opts: &ScanOptions,
) -> ScanReport {
    match outcome {
        DeepOutcome::Infected {
            signature,
            offset,
            method,
        } => ScanReport::infected(signature, offset, method, findings),
        DeepOutcome::Limits(reason) => ScanReport::limits(reason, findings),
        DeepOutcome::Unscannable(reason) => ScanReport::unscannable(reason.text, findings),
        DeepOutcome::PasswordProtected(reason) => {
            ScanReport::password_protected(reason.text, findings)
        }
        DeepOutcome::Clean => match unfinished(opts) {
            Some(outcome) => report_of_outcome(outcome, findings, opts),
            None => ScanReport::clean(findings),
        },
    }
}

/// What a walk that found nothing amounts to when a check did not finish:
/// the size limit, when an object too large to hold kept one from running,
/// else a malformed part of the object that a check could not read, else an
/// incomplete search (a per-buffer bound ran out). `None` when the walk was
/// complete and `Clean` is the true answer.
fn unfinished(opts: &ScanOptions) -> Option<DeepOutcome> {
    if let Some(reason) = engine::scan_over_size() {
        return Some(limits_outcome(opts, unpack::LimitKind::MaxFileSize, reason));
    }
    if let Some(reason) = engine::scan_capped() {
        return Some(limits_outcome(opts, unpack::LimitKind::MaxFiles, reason));
    }
    if let Some(reason) = engine::scan_unreadable() {
        return Some(DeepOutcome::Unscannable(tree::Reason {
            kind: tree::ReasonKind::Damaged,
            text: reason,
            at: String::new(),
        }));
    }
    engine::scan_was_truncated().then(|| {
        DeepOutcome::Limits(engine::scan_search_cut().unwrap_or_else(|| SEARCH_INCOMPLETE.into()))
    })
}

/// Every detection on `data` or its (recursively unpacked) members,
/// de-duplicated by name: the data behind `--all-matches`.
///
/// This is [`scan_object`], the same walk a normal scan uses, driven by a sink
/// that collects instead of stopping. Every heuristic, decoder and recursion
/// step is therefore shared by construction: all-match cannot see less than a
/// normal scan, because it *is* a normal scan that declines to stop.
///
/// An allowlisted file yields nothing; ignored names are dropped, the same
/// suppression as a normal scan.
///
/// The second tuple element tells you whether that walk finished. A scan that
/// hit a limit, hit content it could not read, or could not decrypt a member
/// is a *partial* answer: an empty detection list means "nothing found in the
/// part that was scanned", not "nothing found". Callers that report to a user
/// must interpret [`AllMatchOutcome`] rather than call [`analyze_all`], which
/// throws it away.
pub fn analyze_all_with_outcome(
    db: &Scanner,
    data: &[u8],
    opts: &ScanOptions,
) -> (Vec<(String, Method)>, AllMatchOutcome) {
    analyze_all_source(db, &data, opts)
}

/// As [`analyze_all_with_outcome`], over a seekable input of `size` bytes.
/// One too large to hold is read through a block cache of bounded size, so
/// every detection is listed whatever the input's size.
///
/// Past `--max-input-bytes`, or what the build can address, what the first
/// bytes hold is listed and the input is reported over the limit, as
/// [`scan_seekable`] reports it.
pub fn analyze_all_seekable<R: Read + Seek>(
    db: &Scanner,
    reader: R,
    size: u64,
    opts: &ScanOptions,
) -> io::Result<(Vec<(String, Method)>, AllMatchOutcome)> {
    analyze_all_addressing(db, reader, size, opts, byte_source::ADDRESSABLE)
}

/// [`analyze_all_seekable`] on a build that addresses `addressable` bytes.
fn analyze_all_addressing<R: Read + Seek>(
    db: &Scanner,
    mut reader: R,
    size: u64,
    opts: &ScanOptions,
    addressable: u64,
) -> io::Result<(Vec<(String, Method)>, AllMatchOutcome)> {
    let max = size_ceiling(opts, addressable);
    if size > max {
        let (mut names, outcome) = all_within(db, Window::new(&mut reader, max)?, max, opts)?;
        return Ok(match max_file_size(size, max, opts) {
            Ok(name) => {
                names.push((name.to_string(), Method::Heuristic));
                (names, outcome)
            }
            Err(reason) => (names, AllMatchOutcome::LimitsExceeded(reason)),
        });
    }
    all_within(db, reader, size, opts)
}

/// [`analyze_all_seekable`] for an input within `--max-input-bytes`.
fn all_within<R: Read + Seek>(
    db: &Scanner,
    mut reader: R,
    size: u64,
    opts: &ScanOptions,
) -> io::Result<(Vec<(String, Method)>, AllMatchOutcome)> {
    if let Some(data) = held(&mut reader, size, opts.limits.max_buffer_bytes)? {
        return Ok(analyze_all_with_outcome(db, &data, opts));
    }
    let cache = opts.object_cache(reader)?;
    let (names, outcome) = analyze_all_source(db, &cache, opts);
    // A read that failed part way leaves bytes the scan never saw: what it
    // found is listed, with a signature's match among it, and the scan is
    // not complete.
    let matched = names
        .iter()
        .any(|(_, m)| matches!(m, Method::Pattern | Method::Hash));
    match cache.read_error() {
        Some(e) if !matched => Err(io::Error::other(e)),
        Some(e) => Ok((names, AllMatchOutcome::Unscannable(e))),
        None => Ok((names, outcome)),
    }
}

fn analyze_all_source(
    db: &Scanner,
    data: &dyn ByteSource,
    opts: &ScanOptions,
) -> (Vec<(String, Method)>, AllMatchOutcome) {
    // The flag is thread-local and sticky, so it has to be cleared per scan the
    // way `analyze` clears it. Before this function read it the omission was
    // invisible; with the read below, a stale `true` from an earlier scan on
    // this thread would report a complete search as truncated.
    engine::reset_scan_truncated();
    let (mut names, outcome) = analyze_all_raw(db, data, opts);
    let outcome = match outcome {
        Some(DeepOutcome::Limits(r)) => AllMatchOutcome::LimitsExceeded(one_line(r)),
        Some(DeepOutcome::Unscannable(r)) => AllMatchOutcome::Unscannable(one_line(r.text)),
        Some(DeepOutcome::PasswordProtected(r)) => {
            AllMatchOutcome::PasswordProtected(one_line(r.text))
        }
        // A walk stopped by a budget under `--alert-exceeds-max` ends as the
        // alert (`limits_outcome`): a detection by name, as the unfinished
        // search below is, and not a clean end.
        Some(DeepOutcome::Infected {
            signature, method, ..
        }) => {
            if !names.iter().any(|(n, _)| *n == signature) {
                names.push((signature, method));
            }
            AllMatchOutcome::Complete
        }
        // The same cardinal rule the single-verdict paths apply, which this one
        // was missing: a search that did not finish must not be presented as a
        // complete one. There it downgrades a would-be `Clean`; here there is no
        // verdict to downgrade (the detections stand), so it becomes the
        // outcome that travels alongside them, and the caller reports both.
        _ => match unfinished(opts) {
            Some(DeepOutcome::Infected {
                signature, method, ..
            }) => {
                if !names.iter().any(|(n, _)| *n == signature) {
                    names.push((signature, method));
                }
                AllMatchOutcome::Complete
            }
            Some(DeepOutcome::Limits(r)) => AllMatchOutcome::LimitsExceeded(one_line(r)),
            Some(DeepOutcome::Unscannable(r)) => AllMatchOutcome::Unscannable(one_line(r.text)),
            _ => AllMatchOutcome::Complete,
        },
    };
    (names, outcome)
}

fn analyze_all_raw(
    db: &Scanner,
    data: &dyn ByteSource,
    opts: &ScanOptions,
) -> (Vec<(String, Method)>, Option<DeepOutcome>) {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut findings = Vec::new();
    let mut budget = scan_budget(db, opts);
    let mut first_at = None;
    let mut sink = Sink {
        mode: SinkMode::All {
            out: &mut out,
            seen: &mut seen,
            ignored: &db.ignored,
        },
        at: root_path(),
        first_at: &mut first_at,
    };
    let outcome = scan_object(
        db,
        data,
        Obj::top(opts),
        opts,
        &mut budget,
        &mut findings,
        &mut sink,
    );
    (out, Some(outcome))
}

/// Every detection on `data`, as [`analyze_all_with_outcome`], discarding the
/// partial outcome.
///
/// Callers that report to a user want [`analyze_all_with_outcome`]: dropping the
/// outcome turns "this file was not fully scanned" into silence, and an empty
/// detection list then prints as OK. Kept for callers that only want
/// the names.
pub fn analyze_all(db: &Scanner, data: &[u8], opts: &ScanOptions) -> Vec<(String, Method)> {
    analyze_all_with_outcome(db, data, opts).0
}

/// The partial outcome of an all-match scan, when there is one.
///
/// All-match and a normal scan may legitimately differ in HOW MANY signatures
/// they list. They must never differ on whether the file was fully scanned:
/// that is a property of the walk, not of how many results it was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllMatchOutcome {
    /// Fully scanned.
    Complete,
    /// A resource limit stopped the walk.
    LimitsExceeded(String),
    /// Content was present but could not be read.
    Unscannable(String),
    /// Content was encrypted and no password worked.
    PasswordProtected(String),
}

/// The structural checks on an object as a whole, rather than on what is
/// inside it. Those that parse it whole do not run on an object over the
/// `limits.max_buffer_bytes`, and the scan says so (see [`whole`]).
///
/// `Some(outcome)` means the walk must stop and return it.
#[cfg_attr(not(feature = "pdf"), allow(unused_variables))]
fn whole_buffer_heuristics(
    src: &dyn ByteSource,
    ft: FileType,
    embedded: bool,
    object_stream: bool,
    opts: &ScanOptions,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    // Read once, and only if a check that applies needs it.
    let all = std::cell::OnceCell::new();
    let whole = || {
        all.get_or_init(|| whole(src, opts, "the whole-file structural heuristics"))
            .as_deref()
    };
    let head = src.window(0, 16);
    let executable = [
        &b"MZ"[..],
        b"\x7fELF",
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
    ]
    .iter()
    .any(|m| head.starts_with(m));
    // Overlapping ZIP local file records: a parser-confusion technique where two
    // readers disagree about where a member starts, so the archive shows one
    // file to the scanner and another to the tool that opens it. ClamAV alerts
    // on this by default, and the threshold is >5 because a handful of overlaps
    // occur in oddly-built but benign archives, while a confusion attack needs
    // many.
    if (opts.clamav_heuristics || opts.heuristics) && ft == FileType::Zip {
        const OVERLAP_THRESHOLD: usize = 5;
        if unpack::overlapping_local_records(src) > OVERLAP_THRESHOLD
            && let Some(o) = sink.hit(
                "Heuristics.Zip.OverlappingFiles".to_string(),
                0,
                Method::Heuristic,
            )
        {
            return Some(o);
        }
    }

    // An XZ stream declares the dictionary size a decoder must allocate before
    // producing a single byte, so an absurd declaration costs memory whether or
    // not the stream holds anything. ClamAV alerts on this with no way to switch
    // it off; exav already refuses to allocate past its cap, so this reports the
    // condition rather than letting it surface as an opaque decode failure.
    if ft == FileType::Xz {
        // The stream header and the first block header, which is at most
        // 1024 bytes.
        if let Some(dict) = unpack::xz_declared_dict_size(&src.window(0, 12 + 1024 + 64))
            && dict > unpack::XZ_MAX_DICT
            && let Some(o) = sink.hit(
                "Heuristics.XZ.DicSizeLimit".to_string(),
                0,
                Method::Heuristic,
            )
        {
            return Some(o);
        }
    }

    // Images whose container does not hold together. Opt-in, matching ClamAV:
    // a viewer renders a truncated GIF happily, and that forgiveness is what
    // exploit writers aim at, so the mismatch between "renders" and "parses" is
    // itself the signal.
    // Checked only for the formats `broken_media_alert` knows.
    let media = [
        &b"GIF87a"[..],
        b"GIF89a",
        b"\x89PNG",
        b"II\x2a\x00",
        b"MM\x00\x2a",
        b"\xff\xd8",
    ]
    .iter()
    .any(|m| head.starts_with(m));
    if opts.alert_broken_media
        && media
        && let Some(name) = whole().and_then(unpack::broken_media_alert)
        && let Some(o) = sink.hit(name.to_string(), 0, Method::Heuristic)
    {
        return Some(o);
    }

    // A file that claims to be an executable and whose headers describe a
    // layout no loader could map. The signal is the contradiction: ordinary
    // software ships well-formed headers, while truncation, corruption and
    // droppers that lean on a forgiving loader do not. Reads only the headers,
    // so it runs whatever the object's size.
    //
    // Neither this nor the stripped-ELF check below runs on an executable
    // carved out of its host: that is a candidate found by its magic, and one
    // that does not parse is a fragment or a false hit, not a broken file.
    // clamscan `--alert-broken` agrees: it reports a broken PE or ELF alone and
    // not embedded in another file.
    if opts.alert_broken
        && executable
        && !embedded
        && pe::looks_broken_in(src)
        && let Some(o) = sink.hit(
            "Heuristics.Broken.Executable".to_string(),
            0,
            Method::Heuristic,
        )
    {
        return Some(o);
    }
    // An ELF whose section-header table has been stripped. Detected in BOTH
    // modes; only the name differs. It is not breakage (the program headers are
    // intact and the binary runs), but no toolchain zeroes the entry size, so it
    // is a deliberate anti-analysis step worth reporting under its own name.
    //
    // ClamAV files it under `Heuristics.Broken.Executable`. exav says what it
    // actually found, and under `--clamav-compat` says what ClamAV would, because
    // a gateway filtering on ClamAV's exact string has to keep matching. What is
    // reported never changes; only the vocabulary does.
    if opts.alert_broken && !embedded && pe::elf_section_headers_stripped_in(src) {
        let name = if opts.clamav_compat {
            "Heuristics.Broken.Executable"
        } else {
            "Heuristics.ELF.StrippedSectionHeaders"
        };
        if let Some(o) = sink.hit(name.to_string(), 0, Method::Heuristic) {
            return Some(o);
        }
    }

    // Overlapping partition entries: two partitions claiming the same sectors,
    // so the image shows one filesystem to whatever mounts it and another to
    // whatever scans it. Parser confusion one layer below the ZIP case above.
    // Opt-in, matching ClamAV's `--alert-partition-intersection`.
    if opts.alert_partition_intersection
        && let Some(name) = unpack::partition_intersection_alert(src, &opts.limits)
        && let Some(o) = sink.hit(name.to_string(), 0, Method::Heuristic)
    {
        return Some(o);
    }

    // ClamAV `Heuristics.PDF.ObfuscatedNameObject`: a PDF whose name objects
    // hex-escape plain alphanumerics (`/J#61vaScript`) to hide keywords from
    // naive scanners. Structural and FP-safe: only gratuitous escapes count.
    // Applied to the raw document, before the PDF is unpacked, as ClamAV does.
    // exav also applies it to the text of the object streams the PDF reader
    // decoded. That reach is exav's own, off under `--clamav-compat`.
    #[cfg(feature = "pdf")]
    if (opts.clamav_heuristics || opts.heuristics)
        && (ft == FileType::Pdf || (object_stream && !opts.clamav_compat))
        && whole().is_some_and(unpack::has_obfuscated_name_object)
        && let Some(o) = sink.hit(
            "Heuristics.PDF.ObfuscatedNameObject".to_string(),
            0,
            Method::Heuristic,
        )
    {
        return Some(o);
    }
    None
}

/// Where a walk sends its detections, and whether it wants the walk to go on.
///
/// A normal scan and `--all-matches` are the same traversal answering one question
/// differently: *is this hit enough?* That is the only difference, so it is the
/// only thing parameterised: the traversal reports to a sink rather than
/// returning a verdict, and there is exactly one traversal.
///
/// Two walks cannot be kept in step by discipline. Each capability added to one
/// and not the other changes *which signatures and heuristics run*, silently,
/// and the symptom is a clean verdict rather than an error.
struct Sink<'a> {
    mode: SinkMode<'a>,
    /// Where the object being scanned is.
    at: tree::Path<'a>,
    /// Where the first detection was, when it was inside a container: a path
    /// of member names, as [`tree::PathStyle::Located`] writes it.
    first_at: &'a mut Option<String>,
}

enum SinkMode<'a> {
    /// Stop at the first detection that is not on the `.ign`/`.ign2` list: a
    /// normal scan. An ignored name must not end the walk, as that would leave the
    /// rest of the object unscanned on the strength of a match the operator
    /// asked to have ignored.
    First(&'a std::collections::HashSet<String>),
    /// Collect every distinct detection and keep walking (`--all-matches`).
    All {
        out: &'a mut Vec<(String, Method)>,
        seen: &'a mut std::collections::HashSet<String>,
        /// `.ign`/`.ign2` names. Checked here because the name is already
        /// `.UNOFFICIAL`-suffixed by this point, which is what an ignore entry
        /// names.
        ignored: &'a std::collections::HashSet<String>,
    },
}

/// The top-level object: a path with nothing below it.
fn root_path() -> tree::Path<'static> {
    tree::Path::root(tree::Name::stored(""))
}

impl<'a> Sink<'a> {
    /// A normal scan, stopping at the first detection not on `ignored`.
    fn first(
        ignored: &'a std::collections::HashSet<String>,
        first_at: &'a mut Option<String>,
    ) -> Self {
        Sink {
            mode: SinkMode::First(ignored),
            at: root_path(),
            first_at,
        }
    }

    /// The same sink, for what is at `at`: a detection made through it is
    /// located there.
    fn under<'b>(&'b mut self, at: tree::Path<'b>) -> Sink<'b> {
        Sink {
            mode: match &mut self.mode {
                SinkMode::First(ignored) => SinkMode::First(ignored),
                SinkMode::All { out, seen, ignored } => SinkMode::All { out, seen, ignored },
            },
            at,
            first_at: &mut *self.first_at,
        }
    }

    /// Record the location of a detection, unless one is recorded already
    /// (first detection wins, matching first-match scan semantics). A
    /// detection in the top-level object has no location.
    ///
    /// Must be reached from EVERY site that returns a detection, including
    /// ones that merely re-wrap a recursive result: first-write-wins makes the
    /// redundant calls no-ops, while a missing call silently reports a nested
    /// hit as though it had matched the container's own bytes. The consequence
    /// is not cosmetic: a detection inside an RTF-embedded PE then looks like a
    /// `Target:1` (PE-only) signature firing on an RTF file, which is
    /// indistinguishable from a target-gating bug until you check whether the
    /// signature's bytes exist in the container at all.
    fn record(&mut self) {
        if self.at.depth() > 0 && self.first_at.is_none() {
            *self.first_at = Some(self.at.render(tree::PathStyle::Located));
        }
    }

    /// Record a detection. `Some(outcome)` means this walk must stop and return
    /// it; `None` means carry on looking.
    fn hit(&mut self, signature: String, offset: u64, method: Method) -> Option<DeepOutcome> {
        match &mut self.mode {
            SinkMode::First(ignored) => {
                if ignored.contains(&signature) {
                    return None;
                }
                self.record();
                Some(DeepOutcome::Infected {
                    signature,
                    offset,
                    method,
                })
            }
            SinkMode::All { out, seen, ignored } => {
                if !ignored.contains(&signature) && seen.insert(signature.clone()) {
                    out.push((signature, method));
                }
                self.record();
                None
            }
        }
    }

    /// Whether the matching core should gather every match rather than stop at
    /// the first. Only the core branches on this; the traversal never does.
    fn wants_all(&self) -> bool {
        matches!(self.mode, SinkMode::All { .. })
    }
}

enum DeepOutcome {
    Clean,
    Infected {
        signature: String,
        offset: u64,
        method: Method,
    },
    /// A bound was reached. In a part of an object it is kept, as the two
    /// below, unless the scan budget is used up ([`part_outcome`]).
    Limits(String),
    /// A member was recognised but couldn't be decoded (unsupported method).
    /// It does not stop the scan of sibling members; it's remembered and
    /// surfaced only if nothing infected is found.
    Unscannable(tree::Reason),
    /// An encrypted member: like `Unscannable` but actionable (re-scan with a
    /// password). Takes precedence over `Limits` and `Unscannable`
    /// ([`defer`]).
    PasswordProtected(tree::Reason),
}

/// Everything a container-member scan needs that does not vary between the
/// members of one container.
///
/// Bundled because the same per-member logic runs from two places: the walk's
/// visitor as members arrive, and, after the walk, over the files rejoined
/// from a multi-volume set.
struct MemberCtx<'a> {
    db: &'a Scanner,
    opts: &'a ScanOptions,
    container_size: u64,
    container_is_ole: bool,
    /// The `CL_TYPE_*` each member belongs to, so `Container:`-scoped signatures
    /// fire only inside their intended container.
    member_container: Option<engine::ClType>,
    /// The containers above the members, this one included.
    ancestry: engine::Ancestors<'a>,
    ft: FileType,
    fmt: unpack::Format,
    depth: u32,
    /// The container is a message found inside a text ([`Obj::message_inside`]).
    #[cfg_attr(not(feature = "email"), allow(dead_code))]
    message_inside: bool,
}

/// What a reason ends a container with: password protection, a bound reached,
/// or not fully scanned. The first reason of a container is the one it ends
/// with: password protection over a limit over the rest, and a limit is one
/// that cut the analysis of something short without stopping the walk.
fn reason_outcome(reason: tree::Reason) -> DeepOutcome {
    match reason.kind.class() {
        tree::ReasonClass::Password => DeepOutcome::PasswordProtected(reason),
        tree::ReasonClass::Limits => DeepOutcome::Limits(reason.text),
        tree::ReasonClass::Unscannable => DeepOutcome::Unscannable(reason),
    }
}

/// The checks that read a member's *metadata* (name, size, position,
/// encryption) rather than its content.
///
/// Run as each member arrives, before any decision about its bytes, so
/// positions stay in container order even for members whose content is held
/// back to be rejoined. `size_real` is its decoded size, or its size in the
/// container when it was not decoded. `sink` is under the member's path.
fn member_metadata_scan(
    cx: &MemberCtx<'_>,
    encrypted: &mut Option<&'static str>,
    node: &tree::Node<'_>,
    e: &unpack::MemberMeta,
    reasons: &mut tree::Reasons,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    // `.cdb` container-metadata signatures match on the member's
    // name/size/encryption/position within this container. `FilePos` counts
    // members from 1, matching ClamAV.
    let member_pos = node.index;
    let size_real = node.size;
    // The member's metadata (name/size/pos) is still valid even when its
    // content couldn't be decompressed, so `.cdb` matching below still runs;
    // record that its bytes went unscanned.
    // Opt-in ClamAV heuristic (`--alert-encrypted`): an encrypted member is a
    // detection, upgrading the default actionable PasswordProtected verdict to
    // `Heuristics.Encrypted.*`. A detection beats a limit, so return eagerly.
    // Off by default → verdict untouched.
    //
    // Gated on the encryption alone, NOT on whether the content was also
    // unreadable. Those are two independent facts, and tying them together lets
    // succeeding at decryption ERASE the report: a member exav cracks with a pool
    // password (`VelvetSweatshop` for Office, the malware-convention list for
    // ZIP) reaches here with `encrypted: false, unsupported: None`, so a rule
    // keyed on undecodable content would never see it: exav would decrypt the
    // document, scan the plaintext, and say nothing about it having been
    // encrypted at all.
    //
    // Decrypting stays a genuine advantage over clamd: the recovered plaintext is
    // still scanned for real signatures. It just no longer costs us the fact.
    // A member we could NOT read reports here and now: there is no content
    // coming that could outrank it. A member we DECRYPTED is different: its
    // plaintext is about to be scanned, and a real signature in that plaintext
    // must win over "this was encrypted", so under first-match the heuristic
    // would otherwise pre-empt the detection it is standing in for.
    //
    // Under `--all-matches` both belong in the output and neither pre-empts
    // anything, so the decrypted case reports there. Under first-match it is
    // held, and reported once the walk ends if nothing else was found.
    //
    // A ZIP member alerts as ClamAV's does, on its local header: bit 0 set and
    // bit 13 (headers masked) clear, whatever the central directory says. APK
    // packers set the bit in one header only.
    let alert = e
        .zip_local_flags
        .map_or(e.encrypted, |f| f & 0x0001 != 0 && f & 0x2000 == 0);
    if alert && cx.opts.alert_encrypted {
        if e.unsupported.is_some() || sink.wants_all() {
            if let Some(o) = sink.hit(
                encrypted_heuristic_name(cx.fmt).to_string(),
                0,
                Method::Heuristic,
            ) {
                return Some(o);
            }
        } else {
            encrypted.get_or_insert(encrypted_heuristic_name(cx.fmt));
        }
    }
    // Opt-in (`--detect packed`): name the packer as well as reporting that its
    // payload went unread. Same rule as the encryption case above: two facts,
    // both true, both reported. Only a packer reader's member: in an archive
    // the name is whatever the archive says.
    if cx.opts.alert_packed
        && matches!(cx.fmt, unpack::Format::PePacked | unpack::Format::Upx)
        && let Some(n) = packed_heuristic_name(&e.name)
        && let Some(o) = sink.hit(n, 0, Method::Heuristic)
    {
        return Some(o);
    }
    #[cfg(feature = "email")]
    let template = cx.message_inside && e.unsupported == Some(unpack::MULTIPART_NOT_FOUND);
    #[cfg(not(feature = "email"))]
    let template = false;
    // Only an encrypted member we could NOT read is password-blocked. A
    // decrypted one has its content and must not degrade the verdict to
    // PasswordProtected; this is the one place the two facts stay
    // deliberately separate.
    if let Some(reason) = tree::Reason::of_member(e).filter(|_| !template) {
        reasons.add_at(reason, &node.path);
    }
    // Opt-in ClamAV heuristic (`--alert-macros`): an OLE2 document carrying a
    // VBA project surfaces `vba_project*` artifacts from the OLE extractor;
    // their presence means the document has macros.
    if cx.opts.alert_macros && cx.container_is_ole {
        // ClamAV suffixes the macro dialect: `.VBA` for a VBA project, `.XLM`
        // for an Excel 4.0 macro sheet. Emitting the bare name looked harmless
        // and is not: a gateway filtering on ClamAV's exact string matches
        // neither of ours.
        if let Some(kind) = macro_dialect(&e.name)
            && let Some(o) = sink.hit(
                format!("Heuristics.OLE2.ContainsMacros.{kind}"),
                0,
                Method::Heuristic,
            )
        {
            return Some(o);
        }
    }
    if !cx.db.cdb.is_empty() {
        // ClamAV matches a ZIP member's central-directory record and its local
        // header each, so the encryption field matches either one's bit 0.
        let local = e.zip_local_flags.map(|f| f & 0x0001 != 0);
        let records = std::iter::once(e.encrypted).chain(local.filter(|&l| l != e.encrypted));
        let mut reported = None;
        for encrypted in records {
            let member = container::Member {
                name: &e.name,
                size_in_container: e.comp_size,
                size_real,
                encrypted,
                pos: member_pos,
            };
            let Some((sig, unofficial)) = profile::timed("cdb", 0, || {
                cx.db.cdb.matches(cx.ft, cx.container_size, &member)
            }) else {
                continue;
            };
            if reported.as_ref() == Some(&sig) {
                continue;
            }
            if let Some(o) = sink.hit(
                report_name(&sig, unofficial, cx.opts.unofficial_suffix),
                0,
                Method::Hash,
            ) {
                return Some(o);
            }
            reported = Some(sig);
        }
    }
    None
}

/// Smallest and largest member worth remembering as scanned clean: below the
/// first, scanning again costs about what the digest does; past the second, the
/// digest is another read of a very large object.
const CLEAN_MEMO_MIN: usize = 64 * 1024;
const CLEAN_MEMO_MAX: usize = 512 * 1024 * 1024;

/// A digest of a member's bytes and of what a scan of it reads from its place:
/// the type of its container, the type its container forces on it, the types
/// above it, the extension of its name (its whole name when the text view
/// reads it), how its bytes are read as pixels and whether it is a PDF object
/// stream. `None` for a member outside the sizes worth remembering.
fn clean_memo_key(
    cx: &MemberCtx<'_>,
    name: &str,
    core_type: Option<FileType>,
    raster: Option<&unpack::Raster>,
    object_stream: bool,
    data: &dyn ByteSource,
) -> Option<[u8; 32]> {
    use sha2::Digest;
    let len = data.len();
    if !(CLEAN_MEMO_MIN..=CLEAN_MEMO_MAX).contains(&len) {
        return None;
    }
    let ext = name
        .rsplit_once('.')
        .map_or("", |(_, e)| e)
        .to_ascii_lowercase();
    // The text view reads a part by its whole name (`word/document.xml` has
    // text, `a.xml` none), so a member it reads is remembered by its name.
    #[cfg(feature = "visible-text")]
    let part = if !cx.opts.clamav_compat && exav_render::text::wants(name, data) {
        name
    } else {
        ""
    };
    #[cfg(not(feature = "visible-text"))]
    let part = "";
    // A JBIG2 image's globals go in as bytes, not in the raster's Debug text,
    // which is four times as long and made again for each image naming them.
    let globals = match raster.and_then(|r| r.codec.as_ref()) {
        Some(unpack::RasterCodec::Jbig2 {
            globals: Some(g), ..
        }) => Some(g.clone()),
        _ => None,
    };
    let raster = raster.map(|r| {
        let mut r = r.clone();
        if let Some(unpack::RasterCodec::Jbig2 { globals, .. }) = &mut r.codec {
            *globals = None;
        }
        r
    });
    let globals_len = globals.as_ref().map(|g| g.len());
    let mut h = sha2::Sha256::new();
    h.update(
        format!(
            "{:?}|{core_type:?}|{:?}|{ext}|{part:?}|{raster:?}|{object_stream}|{globals_len:?}|{len}|",
            cx.member_container,
            cx.ancestry.snapshot()
        )
        .as_bytes(),
    );
    if let Some(g) = &globals {
        h.update(&g[..]);
    }
    let mut at = 0;
    while at < len {
        let w = data.window(at, byte_source::CHUNK.min(len - at));
        if w.is_empty() {
            return None;
        }
        h.update(&w[..]);
        at += w.len();
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&h.finalize());
    Some(key)
}

/// Scan one member's bytes, as an object one level below its container.
///
/// Split from [`member_metadata_scan`] because a member of a multi-volume set
/// has its metadata read on arrival but its content scanned only after the
/// container ends, once the set has been rejoined. `path` is the member's, or
/// the rejoined file's. `meta` is its container's account of it, when there is
/// one: how to read its bytes as pixels, when they are raw samples, and whether
/// it is a PDF object stream.
#[allow(clippy::too_many_arguments)]
fn member_content_scan(
    cx: &MemberCtx<'_>,
    reasons: &mut tree::Reasons,
    path: tree::Path<'_>,
    data: &dyn ByteSource,
    meta: Option<&unpack::MemberMeta>,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    let name = path.name().raw;
    let raster = meta.and_then(|m| m.raster.as_ref());
    let object_stream = meta.is_some_and(|m| m.object_stream);
    // Textual content extracted from an OLE2 document is matched in OLE
    // context: its type is forced to MSOLE2 so `Target:2` macro sigs apply and
    // `Target:7` (ascii-text) sigs do NOT. Without this a generic text macro
    // sig (e.g. `Doc.Downloader.Macro-25` on the standard `Name="Project"…`
    // PROJECT stream) false-positives on benign macro documents. Binary streams
    // (an embedded PE, etc.) keep their own type so embedded-executable
    // detection is preserved.
    let core_type = if cx.container_is_ole
        && is_textual_type(profile::timed("filetype", data.len() as u64, || {
            filetype::identify_source(data)
        })) {
        Some(FileType::Ole)
    } else {
        None
    };
    let obj = Obj {
        depth: cx.depth + 1,
        container: cx.member_container,
        ancestry: cx.ancestry,
        core_type,
        filename: None,
        name: Some(name),
        raster,
        object_stream,
        path,
        core: true,
        carve: true,
        embedded: false,
        in_sectors: false,
        message_inside: false,
    };
    // The same bytes in the same place, already scanned clean at this depth or
    // shallower, cannot give a different answer, and a document that holds
    // copies of itself would otherwise be scanned once per copy.
    let seen = clean_memo_key(cx, name, core_type, raster, object_stream, data);
    if seen
        .as_ref()
        .is_some_and(|k| engine::clean_seen(k, obj.depth))
    {
        return None;
    }
    let truncated_before = engine::scan_was_truncated();
    let outcome = scan_object(cx.db, data, obj, cx.opts, budget, findings, sink);
    if let (DeepOutcome::Clean, Some(k)) = (&outcome, seen) {
        // A scan that stopped short on the way has not seen all of it.
        if truncated_before || !engine::scan_was_truncated() {
            engine::clean_seen_insert(k, obj.depth);
        }
    }
    match outcome {
        DeepOutcome::Clean => None,
        // What was not fully examined under the member is kept as a reason of
        // this container, not propagated as a stop: keep scanning the rest of
        // it.
        DeepOutcome::Unscannable(r) | DeepOutcome::PasswordProtected(r) => {
            reasons.add_at(r, &path);
            None
        }
        // A name on the ignore list is not a detection. Carrying on rather than
        // returning matters: ending the walk here would leave the container's
        // remaining members unscanned on the strength of a match the operator
        // asked to be ignored, so a real detection later in the container would
        // never be reached.
        DeepOutcome::Infected { ref signature, .. } if cx.db.ignored.contains(signature) => None,
        other => Some(other),
    }
}

/// Where an object sits in the scan, and what its container decided about it.
#[derive(Clone, Copy)]
struct Obj<'a> {
    /// Nesting depth; the input is at 0.
    depth: u32,
    /// The type of the container the object sits in, for `Container:`-scoped
    /// signatures. Inherited by what is carved or decoded out of the object,
    /// rather than over-matching.
    container: Option<engine::ClType>,
    /// The types of the containers above it, for `Intermediates:`-scoped
    /// signatures.
    ancestry: engine::Ancestors<'a>,
    /// The type the matching core takes the object for, when its container
    /// decides that (a textual OLE stream is matched as OLE); else its own.
    core_type: Option<FileType>,
    /// The input's name, for YARA's filename externals. Nothing inside the
    /// input has one.
    filename: Option<&'a str>,
    /// The name the object has where it sits (the input's, or a member's), for
    /// what only a name says, like which text format a plain file is. Unlike
    /// `filename`, a member has one; what is carved or decoded does not.
    #[cfg_attr(not(feature = "visible-text"), allow(dead_code))]
    name: Option<&'a str>,
    /// How its container says to read its bytes as pixels, for a member that
    /// is raw samples (a PDF image); nothing carved or decoded out of an
    /// object has one.
    #[cfg_attr(not(feature = "qr"), allow(dead_code))]
    raster: Option<&'a unpack::Raster>,
    /// Whether its container says it is a PDF object stream, decoded; nothing
    /// carved or decoded out of an object is one.
    object_stream: bool,
    /// The names of the containers above it, and its own: where a detection in
    /// it is located. What is carved or read a second way from an object has
    /// its path, and what is decoded out of its text a name of its own.
    path: tree::Path<'a>,
    /// Whether to match the object's own bytes. Off for an archive carved out
    /// of an object whose own match already covered them.
    core: bool,
    /// Whether to carve embedded executables and archives out of the object.
    /// Off for what carving or decoding produced: its parent already
    /// enumerated every offset in it, and carving again would rescan the same
    /// overlapping regions, the source of a large scan amplification.
    carve: bool,
    /// Whether the object was carved out of its host at an offset, found by a
    /// magic rather than typed as a whole. It runs to the host's end, whatever
    /// its headers say.
    embedded: bool,
    /// Whether the object was carved out of a compound file. Its sectors are
    /// not in the order of its streams, so an archive found in it by a magic
    /// is not read: the walk of the file reads the streams.
    in_sectors: bool,
    /// Whether the object is a message found inside a text, whose every byte
    /// was scanned as that text: a multipart its headers name and it does not
    /// hold is a template or an example, not a part left unread.
    message_inside: bool,
}

impl<'a> Obj<'a> {
    /// The input.
    fn top(opts: &'a ScanOptions) -> Self {
        Obj {
            depth: 0,
            container: None,
            ancestry: engine::Ancestors::NONE,
            core_type: None,
            filename: opts.filename.as_deref(),
            name: opts.filename.as_deref(),
            raster: None,
            object_stream: false,
            path: root_path(),
            core: true,
            carve: true,
            embedded: false,
            in_sectors: false,
            message_inside: false,
        }
    }

    /// Something found inside this object, one level down, in `container`.
    /// It is at the object's path until it is given a name of its own.
    fn inner(self, container: Option<engine::ClType>) -> Self {
        Obj {
            depth: self.depth + 1,
            container,
            ancestry: self.ancestry,
            core_type: None,
            filename: None,
            name: None,
            raster: None,
            object_stream: false,
            path: self.path,
            core: true,
            carve: true,
            embedded: false,
            in_sectors: false,
            message_inside: false,
        }
    }
}

/// Scan one object and everything inside it: the one pipeline every object
/// goes through, the input and whatever is unpacked, decoded or carved out of
/// it, whatever its size and wherever it sits.
///
/// An archive's members are scanned before its own bytes, so a detection in a
/// member is attributed to it rather than to the container that happens to
/// hold its bytes stored. Anything else is matched first, then analysed.
fn scan_object(
    db: &Scanner,
    data: &dyn ByteSource,
    obj: Obj<'_>,
    opts: &ScanOptions,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> DeepOutcome {
    if (data.len() as u64) < opts.min_scan_bytes {
        return DeepOutcome::Clean;
    }
    // A detection in the object, or deeper, is located at its path.
    let mut here = sink.under(obj.path);
    let sink = &mut here;
    // Content the operator has vouched for (`.fp`/`.sfp`): neither it nor
    // anything inside it is a detection. Keyed on the object's bytes, so an
    // entry means the same thing wherever the object is found.
    let carve = obj.carve && obj.depth < budget.limits().max_recursion;
    let facts = Facts::for_scan(data, db, carve, opts);
    if obj.core {
        facts.will_match(pass::Matching {
            db,
            opts,
            container: obj.container,
            ancestry: obj.ancestry,
            core_type: obj.core_type,
            all: sink.wants_all(),
        });
    }
    if allowlisted(db, &facts) {
        return DeepOutcome::Clean;
    }
    let ft = db.identify_facts(&facts);
    let fmt = container_of(&facts, &obj, opts, None);
    match fmt {
        Some(fmt) if !ft.is_executable() => {
            scan_archive(db, &facts, obj, ft, fmt, opts, budget, findings, sink)
        }
        fmt => scan_file(db, &facts, obj, ft, fmt, opts, budget, findings, sink),
    }
}

/// What the scan of an object has read of it, for the typer to ask: what
/// detection made of it, the executable held for the checks of the packers (or
/// the image of a PE too large to hold, and the scan says when neither can be
/// held) and whether it holds a UPX header.
struct Seen<'a, 'b> {
    facts: &'a Facts<'b>,
    opts: &'a ScanOptions,
}

impl tree::Observed for Seen<'_, '_> {
    fn format(&self) -> Option<unpack::Format> {
        self.facts.format()
    }

    fn executable(&self, kind: unpack::Executable) -> Option<std::borrow::Cow<'_, [u8]>> {
        let what = "the UPX and packer checks";
        match kind {
            unpack::Executable::Pe => pe_part(self.facts.data, self.opts, what),
            _ => whole(self.facts.data, self.opts, what),
        }
    }

    fn upx_header(&self) -> bool {
        self.facts.upx_header()
    }
}

/// What a type a signature gave an object (`HandlerType:`) says reads it.
fn declared_by(ft: FileType) -> tree::Declared {
    match ft {
        FileType::Pe => tree::Declared::Executable(unpack::Executable::Pe),
        FileType::Elf => tree::Declared::Executable(unpack::Executable::Elf),
        FileType::MachO => tree::Declared::Executable(unpack::Executable::MachO),
        // The format whose type it is: `Unknown` is the type of many.
        _ if ft != FileType::Unknown => unpack::Format::ALL
            .iter()
            .copied()
            .find(|&f| filetype::filetype_of_format(f) == ft)
            .map_or(tree::Declared::Other, tree::Declared::Format),
        _ => tree::Declared::Other,
    }
}

/// The format that reads the object `facts` holds, if one does: as the typer of
/// the walk finds it, which gets from the scan what it has read. `declared`:
/// the type a signature gave it.
fn container_of(
    facts: &Facts<'_>,
    obj: &Obj<'_>,
    opts: &ScanOptions,
    declared: Option<FileType>,
) -> Option<unpack::Format> {
    let typing = tree::Typing {
        scanner: true,
        clamav: opts.restrict_extractors,
        // An image carved out of a compound file runs to the file's end, and
        // the archive found in it is bytes of the file, whose sectors are not
        // in the order of the stream that holds it: the walk of the file reads
        // the stream.
        sfx: !obj.in_sectors,
    };
    match typing.type_source(
        facts.data,
        u64::MAX,
        &Seen { facts, opts },
        declared.map(declared_by),
    ) {
        tree::Typed::Container(format) => Some(format),
        tree::Typed::Plain | tree::Typed::Unchecked(_) => None,
    }
}

/// [`scan_object`] for an archive: what is inside it, then its own bytes.
#[allow(clippy::too_many_arguments)]
fn scan_archive(
    db: &Scanner,
    facts: &Facts,
    obj: Obj<'_>,
    ft: FileType,
    fmt: unpack::Format,
    opts: &ScanOptions,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> DeepOutcome {
    let data = facts.data;
    // Only an OLE file's executables are carved from its own bytes, below.
    facts.carve_only(fmt == unpack::Format::Ole);
    if obj.depth == 0 {
        findings.push(Finding::new("type", ft.as_str()));
    }
    let mut carried = DeepOutcome::Clean;
    if let Some(o) = scan_carried(
        db,
        data,
        obj,
        ft,
        opts,
        budget,
        findings,
        sink,
        &mut carried,
    ) {
        return o;
    }
    let mut members = walk_members(db, data, obj, ft, fmt, opts, budget, findings, sink);
    // What the encoded files in the object turned up, if the walk found nothing.
    defer(&mut members, carried);
    // Matched whatever stopped the walk short of a detection: a detection beats
    // a limit.
    if matches!(members, DeepOutcome::Infected { .. }) || !obj.core {
        return members;
    }
    let mut outcome = members;
    let writes = write_limits(budget);
    let rest = match core(
        db,
        facts,
        obj.core_type.unwrap_or(ft),
        obj,
        opts,
        writes,
        budget,
        sink,
    ) {
        Ok(rest) => rest,
        Err(stop) => return stop,
    };
    if let Some(o) = scan_unpacked(
        db,
        rest.unpacked,
        obj,
        opts,
        budget,
        findings,
        sink,
        &mut outcome,
    ) {
        return o;
    }
    // A file can be two archives. The magic at its start types it as one, and a
    // reader that goes by another structure opens the other: a ZIP appended to a
    // PDF, a tar or a gzip is the archive `unzip` finds by the record at the end
    // of the file, and an ISO or ext image may begin with an archive's magic in
    // the space it leaves free. What the first walk did not reach is walked as
    // the second.
    if obj.carve && obj.depth < budget.limits().max_recursion {
        let second = Obj {
            carve: false,
            embedded: true,
            ..obj.inner(obj.container)
        };
        if fmt != unpack::Format::Zip {
            let appended = tree::derive(data, tree::DeriveKind::AppendedZip, budget.limits());
            for child in &appended.children {
                let Some(sub) = child.source() else { continue };
                let o = scan_child(db, sub, child.name(), second, opts, budget, findings, sink);
                if let Some(stop) = part_outcome(budget, &mut outcome, o) {
                    return stop;
                }
            }
        }
        let again = tree::derive(data, tree::DeriveKind::AlsoReadsAs(fmt), budget.limits());
        for child in &again.children {
            let tree::DerivedBody::ReadAs(other) = child.body else {
                continue;
            };
            let o = walk_members(
                db,
                data,
                second,
                filetype::filetype_of_format(other),
                other,
                opts,
                budget,
                findings,
                sink,
            );
            if let Some(stop) = part_outcome(budget, &mut outcome, o) {
                return stop;
            }
        }
    }
    // An OLE2 file's executables are also carved from its own bytes, each
    // scanned from its header to the end of the file, as ClamAV carves them.
    // Its streams are sectors laid out in any order, so what follows an
    // executable in the file is not what follows it in its stream, and a
    // signature written against ClamAV's carving can match those bytes.
    if fmt == unpack::Format::Ole && obj.carve && obj.depth < budget.limits().max_recursion {
        let carved = Obj {
            carve: false,
            embedded: true,
            in_sectors: true,
            ..obj.inner(obj.container)
        };
        let embedded = facts.embedded();
        for off in embedded.pe {
            let sub = &byte_source::Sub::new(data, off, data.len() - off);
            let o = scan_child(db, sub, None, carved, opts, budget, findings, sink);
            if let Some(stop) = part_outcome(budget, &mut outcome, o) {
                return stop;
            }
        }
        // Only PE images are carved here, so only their cap counts.
        if embedded.pe_capped {
            engine::mark_capped(|| carving_capped(facts.caps));
        }
    }
    outcome
}

/// What an object carries encoded in its own bytes, and the checks that read
/// it as a whole: the steps before unpacking that archives and other objects
/// share. `Some` means the walk must stop.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(feature = "base64scan"), allow(unused_variables, clippy::ptr_arg))]
fn scan_carried(
    db: &Scanner,
    data: &dyn ByteSource,
    obj: Obj<'_>,
    ft: FileType,
    opts: &ScanOptions,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
    deferred: &mut DeepOutcome,
) -> Option<DeepOutcome> {
    // Embedded base64-encoded executables. Scripts/RTF/HTML carriers stash a
    // PE/ELF as a long base64 string (PowerShell reflective loaders, JS/VBS
    // droppers) that is invisible to a signature matching the decoded bytes.
    // Decode such blobs (in a text-ish buffer) and rescan any that decode to a
    // real executable. Bounded by recursion depth and the scan budget;
    // exav-exclusive, so off under `--clamav-compat` and `--no-base64`.
    #[cfg(feature = "base64scan")]
    if opts.decode_base64 && text_anywhere(data) {
        let runs = tree::derive(data, tree::DeriveKind::Base64Runs, budget.limits());
        if let Some(o) = limit_at_payloads(opts, obj, runs.children.first(), budget, sink, deferred)
        {
            return Some(o);
        }
        let below = obj.depth < budget.limits().max_recursion;
        if runs.capped && below {
            engine::mark_capped(base64_capped);
        }
        for child in runs.children.iter().filter(|_| below) {
            let Some(payload) = child.source() else {
                continue;
            };
            // The decoded run has a name (`child.name()`) so a hit inside it is
            // attributable. Without it the detection reports no location and
            // reads as a match on the carrier's own bytes, which is how a
            // correct `Win.Trojan.Mimikatz` hit, on a PE base64-encoded inside
            // an RTF, looked like a PE-only signature firing on an RTF.
            // The payload's container is the CARRIER, not whatever the carrier
            // itself sits in: a `data:` URI image inside an HTML page has
            // `Container:CL_TYPE_HTML`, which is how a family of phishing
            // signatures scopes a logo's perceptual hash so it fires on a page
            // and not on the same image standing alone.
            let payload_container = carrier_cltype(ft).or(obj.container);
            let link = engine::Link::new(obj.ancestry, payload_container);
            let inner = Obj {
                carve: false,
                ancestry: engine::Ancestors::of(&link),
                ..obj.inner(payload_container)
            };
            let o = scan_child(
                db,
                payload,
                child.name(),
                inner,
                opts,
                budget,
                findings,
                sink,
            );
            if let Some(stop) = part_outcome(budget, deferred, o) {
                return Some(stop);
            }
        }
    }

    // Assets embedded straight into a markup document: a `data:` URI image on
    // an HTML page, a base64 element body in a Word/Excel 2003 flat-XML file.
    // Distinct from the base64-executable pass above, which only decodes runs
    // starting with an executable magic: here the payload is usually the lure
    // IMAGE, and it is the image that signatures key on. Extracting it is what
    // makes `Container:CL_TYPE_HTML`/`_XML_WORD`/`_XML_XL` satisfiable at all:
    // those constraints exist to separate "this image, in a document" from
    // "this image, on its own".
    #[cfg(feature = "base64scan")]
    if opts.decode_base64
        && let Some(mc) = markup_cltype(ft, &data.window(0, 4096))
    {
        let link = engine::Link::new(obj.ancestry, Some(mc));
        let assets = tree::derive(data, tree::DeriveKind::MarkupAssets, budget.limits());
        if let Some(o) =
            limit_at_payloads(opts, obj, assets.children.first(), budget, sink, deferred)
        {
            return Some(o);
        }
        let below = obj.depth < budget.limits().max_recursion;
        if assets.capped && below {
            engine::mark_capped(base64_capped);
        }
        for child in assets.children.iter().filter(|_| below) {
            let Some(payload) = child.source() else {
                continue;
            };
            let inner = Obj {
                carve: false,
                ancestry: engine::Ancestors::of(&link),
                ..obj.inner(Some(mc))
            };
            let o = scan_child(
                db,
                payload,
                child.name(),
                inner,
                opts,
                budget,
                findings,
                sink,
            );
            if let Some(stop) = part_outcome(budget, deferred, o) {
                return Some(stop);
            }
        }
    }

    whole_buffer_heuristics(data, ft, obj.embedded, obj.object_stream, opts, sink)
}

/// An object at the depth limit does not decode the payloads of its text, and
/// says so when there is one: a limit, at the first of them. A limit that is
/// an alert ends the walk; any other is held for the end of it, so a detection
/// still beats it. `first` is the first payload found, if any.
#[cfg(feature = "base64scan")]
fn limit_at_payloads(
    opts: &ScanOptions,
    obj: Obj<'_>,
    first: Option<&tree::DerivedChild<'_>>,
    budget: &mut Budget,
    sink: &mut Sink,
    deferred: &mut DeepOutcome,
) -> Option<DeepOutcome> {
    let first = first?;
    let walk = opts.walk();
    let hit = tree::Cx::new(&walk, budget).depth_hit(obj.depth)?;
    let at = first.name().map_or(obj.path, |name| obj.path.child(name));
    match limits_outcome_at(opts, &mut sink.under(at), hit.kind, hit.reason) {
        stop @ DeepOutcome::Infected { .. } => Some(stop),
        held => {
            defer(deferred, held);
            None
        }
    }
}

/// [`scan_object`] for content found inside another object rather than
/// decoded from a container, charged to the scan budget (a container's
/// members are charged as they are decoded). `inner` is the object as its
/// parent made it; `name` is its segment of the path, if it has one.
#[allow(clippy::too_many_arguments)]
fn scan_child(
    db: &Scanner,
    data: &dyn ByteSource,
    name: Option<tree::Name<'_>>,
    inner: Obj<'_>,
    opts: &ScanOptions,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> DeepOutcome {
    let walk = opts.walk();
    let mut cx = tree::Cx::new(&walk, budget);
    let at = inner.path;
    let scanned = cx.child(&at, name, data.len(), |cx, path| {
        scan_object(
            db,
            data,
            Obj { path, ..inner },
            opts,
            cx.budget(),
            findings,
            sink,
        )
    });
    match scanned {
        Ok(outcome) => outcome,
        Err(refused) => limits_outcome_at(
            opts,
            &mut sink.under(refused.at),
            refused.hit.kind,
            refused.hit.reason,
        ),
    }
}

/// Scan the buffers a bytecode unpacker made of an object, each as an object of
/// its own. `Some` means the walk must stop; an outcome that does not stop it
/// goes to `deferred`.
#[allow(clippy::too_many_arguments)]
fn scan_unpacked(
    db: &Scanner,
    bufs: Vec<Vec<u8>>,
    obj: Obj<'_>,
    opts: &ScanOptions,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
    deferred: &mut DeepOutcome,
) -> Option<DeepOutcome> {
    for (i, buf) in bufs.into_iter().enumerate() {
        // The unpacker gives the buffer no name, so its index is its identity.
        let name = format!("bytecode-unpacked-{}", i + 1);
        let name = tree::Name::new(&name, tree::NameKind::Derived);
        // An unpacker that fires again on its own output would never stop.
        let walk = opts.walk();
        // Kept as a payload's limit is, so the checks after it still run; the
        // buffers after it are as deep.
        if let Some(hit) = tree::Cx::new(&walk, budget).depth_hit(obj.depth) {
            let at = obj.path.child(name);
            let o = limits_outcome_at(opts, &mut sink.under(at), hit.kind, hit.reason);
            return part_outcome(budget, deferred, o);
        }
        let o = scan_child(
            db,
            &buf,
            Some(name),
            obj.inner(obj.container),
            opts,
            budget,
            findings,
            sink,
        );
        if let Some(stop) = part_outcome(budget, deferred, o) {
            return Some(stop);
        }
    }
    None
}

/// Keep an outcome that does not stop the walk, as a container keeps its
/// reasons: password protection over a limit over the rest, the first of each.
fn defer(slot: &mut DeepOutcome, outcome: DeepOutcome) {
    let rank = |o: &DeepOutcome| match o {
        DeepOutcome::Clean => 0,
        DeepOutcome::Unscannable(_) => 1,
        DeepOutcome::Limits(_) => 2,
        DeepOutcome::PasswordProtected(_) => 3,
        DeepOutcome::Infected { .. } => 4,
    };
    if rank(&outcome) > rank(slot) {
        *slot = outcome;
    }
}

/// What the scan of the rest of an object does with the outcome of one of its
/// parts (a payload, a carved image or archive, a second reading): a detection
/// ends it, and so does a limit once the scan budget is used up, as nothing
/// more can be scanned. Any other outcome is kept ([`defer`]), so that a
/// detection in another part still beats it.
fn part_outcome(
    budget: &Budget,
    deferred: &mut DeepOutcome,
    outcome: DeepOutcome,
) -> Option<DeepOutcome> {
    match outcome {
        DeepOutcome::Clean => None,
        o @ DeepOutcome::Infected { .. } => Some(o),
        o @ DeepOutcome::Limits(_) if budget.remaining_scan() == 0 => Some(o),
        o => {
            defer(deferred, o);
            None
        }
    }
}

/// The second reading of a self-extractor: its stub, when UPX packed, read as
/// UPX is and scanned as the executable it unpacks to. Only a detection is
/// kept. A limit, damage or a method UPX does not support in the stub is not a
/// reason of the scan (the stub is read as well as the archive, not instead of
/// it), and the alerts about the reading itself are off, so that it cannot end
/// the scan in a detection that is not of the unpacked stub.
#[allow(clippy::too_many_arguments)]
fn scan_sfx_stub(
    db: &Scanner,
    facts: &Facts,
    obj: Obj<'_>,
    ft: FileType,
    opts: &ScanOptions,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    let data = facts.data;
    // ClamAV unpacks UPX out of a PE only.
    if !facts.upx_header() || (opts.clamav_compat && !data.window(0, 2).starts_with(b"MZ")) {
        return None;
    }
    let stub = byte_source::Sub::new(data, 0, unpack::sfx_stub_len(data)?);
    if !unpack::is_upx_source(&stub) {
        return None;
    }
    let mut quiet = opts.clone();
    quiet.alert_exceeds_max = false;
    quiet.alert_encrypted = false;
    quiet.alert_packed = false;
    let verdict = walk_members(
        db,
        &stub,
        obj,
        ft,
        unpack::Format::Upx,
        &quiet,
        budget,
        findings,
        sink,
    );
    matches!(verdict, DeepOutcome::Infected { .. }).then_some(verdict)
}

/// [`scan_object`] for anything but an archive: its own bytes, then what is
/// inside it (a packed or installer executable's payload, carved images) and
/// the structural heuristics.
#[allow(clippy::too_many_arguments)]
fn scan_file(
    db: &Scanner,
    facts: &Facts,
    obj: Obj<'_>,
    ft: FileType,
    fmt: Option<unpack::Format>,
    opts: &ScanOptions,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> DeepOutcome {
    let data = facts.data;
    let (depth, container) = (obj.depth, obj.container);
    let mut unpacked = Vec::new();
    let (ft, fmt) = if obj.core {
        let mut writes = write_limits(budget);
        let rest = match core(
            db,
            facts,
            obj.core_type.unwrap_or(ft),
            obj,
            opts,
            writes,
            budget,
            sink,
        ) {
            Ok(rest) => rest,
            Err(stop) => return stop,
        };
        unpacked = rest.unpacked;
        // A `HandlerType:` signature that matched says "treat this as type T":
        // programmable file-type identification, filling in where the magic
        // tables cannot (a PDF exploit recognised by its object layout rather
        // than a `%PDF` header still gets opened as a PDF). Only a genuine
        // change is taken, which also makes a loop impossible.
        match rest.retype.filter(|t| *t != ft) {
            None => (ft, fmt),
            Some(retyped) => {
                // Worth something only if the object is matched AS the new
                // type, and unpacked as it.
                let written: u64 = unpacked.iter().map(|b| b.len() as u64).sum();
                writes.total = writes.total.saturating_sub(written);
                match core(db, facts, retyped, obj, opts, writes, budget, sink) {
                    Ok(rest) => unpacked.extend(rest.unpacked),
                    Err(stop) => return stop,
                }
                let fmt = container_of(facts, &obj, opts, Some(retyped));
                (retyped, fmt)
            }
        }
    } else {
        (ft, fmt)
    };
    if depth == 0 {
        findings.push(Finding::new("type", ft.as_str()));
    }
    // A verdict that does not stop the walk and has not been reported yet,
    // because what follows still has to run. `Clean` until one is produced.
    let mut deferred = DeepOutcome::Clean;
    if let Some(o) = scan_unpacked(
        db,
        unpacked,
        obj,
        opts,
        budget,
        findings,
        sink,
        &mut deferred,
    ) {
        return o;
    }
    if let Some(o) = scan_carried(
        db,
        data,
        obj,
        ft,
        opts,
        budget,
        findings,
        sink,
        &mut deferred,
    ) {
        return o;
    }

    // A packed or installer executable, or an object a `HandlerType:`
    // signature retyped as a container.
    if let Some(fmt) = fmt {
        let verdict = walk_members(db, data, obj, ft, fmt, opts, budget, findings, sink);
        // A packed executable is not only a container, it is also a *carrier*.
        // Unpacking accounts for the image the stub rebuilds; it accounts for
        // nothing appended to the file, and stapling an archive or a second PE
        // onto the end of a packed dropper is one of the commonest shapes there
        // is. For every other format, returning here is right. For these two, a
        // result with no detection falls through to the carving below, carrying
        // its reason with it so that it is still reported if nothing is carved.
        let packed_executable = matches!(fmt, unpack::Format::Upx | unpack::Format::PePacked);
        if let Some(stop) = part_outcome(budget, &mut deferred, verdict) {
            return stop;
        }
        if !packed_executable {
            if fmt == unpack::Format::Sfx
                && let Some(o) = scan_sfx_stub(db, facts, obj, ft, opts, budget, findings, sink)
            {
                return o;
            }
            // The members come first. The executable of an installer or
            // self-extractor then gets the lookups of any other PE: its
            // `tlsh:` lines, then the signatures on its imports, as clamscan
            // matches them.
            if ft == FileType::Pe
                && let Some(o) = tlsh_hit(db, data, opts, sink)
                    .or_else(|| installer_imports(db, data, opts, sink))
            {
                return o;
            }
            return deferred;
        }
    }

    // A message inside a text file, or binary data, as clamscan reads one: two
    // header lines close enough make the file a message. It is read from the
    // start of their header block with the reader every message goes through.
    // Compat does not turn it off: ClamAV does it.
    #[cfg(feature = "email")]
    if fmt.is_none()
        && let Some(whole) = mail_inside_reach(ft, data)
        && let Some(at) = facts.mail_start(
            whole,
            usize::try_from(budget.limits().max_buffer_bytes).unwrap_or(usize::MAX),
        )
    {
        let sub = &byte_source::Sub::new(data, at, data.len() - at);
        let message = Obj {
            message_inside: true,
            raster: None,
            object_stream: false,
            ..obj
        };
        let verdict = walk_members(
            db,
            sub,
            message,
            FileType::Email,
            unpack::Format::Email,
            opts,
            budget,
            findings,
            sink,
        );
        if let Some(stop) = part_outcome(budget, &mut deferred, verdict) {
            return stop;
        }
    }

    // Embedded executables: scan PE/ELF images appended/embedded at a non-zero
    // offset (file-infectors, droppers, self-extractors; on Windows via PE, on
    // Linux via ELF). Each carved image is scanned as an object of its own (so
    // its PE-relative offsets resolve and its section hashes match), charged
    // against the cumulative scan budget so a crafted disk image (e.g. a 58 MB
    // VHD full of PEs) trips `LimitsExceeded` instead of running for hours.
    // Structural, not heuristic, so it runs regardless of the flag, bounded by
    // recursion depth and the embedded-image cap. The carved image inherits the
    // container its host sits in.
    if obj.carve && depth < budget.limits().max_recursion {
        let carved = Obj {
            carve: false,
            embedded: true,
            ..obj.inner(container)
        };
        // Every candidate of every kind, found in one read of the object.
        let embedded = facts.embedded();
        let capped = embedded.pe_capped || embedded.others_capped;
        // ClamAV scans a PE appended to a PE and no other embedded image: not a
        // PE out of a text file, a PNG, binary data or an ELF, nor an ELF or a
        // Mach-O (thin or fat) out of any file (clamscan 1.4.3).
        let restrict = opts.restrict_extractors;
        let images = embedded
            .pe
            .into_iter()
            .filter(|_| !restrict || ft == FileType::Pe)
            .chain(embedded.elf.into_iter().filter(|_| !restrict))
            .chain(embedded.macho.into_iter().filter(|_| !restrict));
        for off in images {
            let sub = &byte_source::Sub::new(data, off, data.len() - off);
            // An image that could not be read whole is reported if nothing
            // else is found, and does not stop the scan of the rest of the
            // carrier.
            let o = scan_child(db, sub, None, carved, opts, budget, findings, sink);
            if let Some(stop) = part_outcome(budget, &mut deferred, o) {
                return stop;
            }
        }

        // Embedded archives: a ZIP/CAB/7z/RAR/ARJ/GZIP/XZ appended to or stapled
        // inside a carrier (droppers, SFX stubs, PE overlays). The offset-0 scan
        // never types these, so carve each candidate whose magic is confirmed by
        // the unpacker's own checks (skips coincidental byte-runs) and unpack
        // it. Those read the candidate's first bytes: a coincidental magic
        // costs no search through the rest of the object. The carrier's own
        // match already covered the archive's bytes, so only what is inside it
        // is new.
        for off in embedded.archives {
            let sub = &byte_source::Sub::new(data, off, data.len() - off);
            let Some(fmt) = unpack::detect_archive_start(sub) else {
                continue;
            };
            // ClamAV carves a ZIP, 7z or CAB out of the middle of a file, but
            // not a gzip, bzip2 or xz stream (clamscan 1.4.3, each appended to a
            // PE, an ELF, a PNG, a text file and binary data).
            if opts.restrict_extractors
                && matches!(
                    fmt,
                    unpack::Format::Gzip | unpack::Format::Bzip2 | unpack::Format::Xz
                )
            {
                continue;
            }
            let archive = Obj {
                core: false,
                ..carved
            };
            match scan_child(db, sub, None, archive, opts, budget, findings, sink) {
                // A real detection in an appended/stapled archive is the whole
                // point of carving: surface it. A limit (a decompression bomb
                // in a real appended archive) is reported if nothing else is
                // found in the carrier.
                o @ (DeepOutcome::Infected { .. } | DeepOutcome::Limits(_)) => {
                    if let Some(stop) = part_outcome(budget, &mut deferred, o) {
                        return stop;
                    }
                }
                // An encrypted archive appended to a picture or document (a
                // polyglot: archive tools open it by its directory at the end)
                // is reported once its structure proves it is really there.
                // Executables are left to the SFX detector. 7z and RAR magics
                // are long enough that a parse reaching an encrypted member
                // is proof already; ZIP's four bytes are not.
                pw @ DeepOutcome::PasswordProtected(_)
                    if !ft.is_executable()
                        && (fmt != unpack::Format::Zip
                            || whole(sub, opts, "the check of an appended ZIP's directory")
                                .is_some_and(|w| unpack::zip_directory_is_consistent(&w))) =>
                {
                    defer(&mut deferred, pw);
                }
                // Clean, or a carve that could not be decoded (Unscannable /
                // PasswordProtected): the candidate was found by a short magic that
                // collides with ordinary binary data (a false `1f8b08` / `PK\x03\x04`
                // byte-run inside a PE), so it is not really an archive here. The
                // carrier buffer is already fully pattern-scanned, so a failed guess
                // must NOT poison it as UNSCANNABLE: that is a false positive
                // against `clamscan`, which reports such carriers clean. Move on.
                _ => {}
            }
        }

        // Past a cap, an embedded image or archive was not scanned: without
        // this, padding a dropper with decoys would hide the real payload.
        if capped {
            engine::mark_capped(|| carving_capped(facts.caps));
        }
    }

    // DLP structured-data heuristic (opt-in, ClamAV `--structured-*-count`): count
    // credit-card / SSN numbers in reasonably-sized textual buffers and alert when
    // a threshold is met. Driven solely by the ScanOptions thresholds, so it runs
    // independently of `--detect exav-heuristics` (matching ClamAV, where
    // `CL_SCAN_HEURISTIC_STRUCTURED` is its own switch). Runs at every recursion
    // level, so structured data inside an extracted archive member is caught too.
    #[cfg(feature = "dlp")]
    if let Some(o) = structured_data_scan(data, opts, sink) {
        return o;
    }

    // Phishing heuristic (opt-in, ClamAV `--alert-phishing`): flag link-spoofing
    // in HTML/text bodies. Like the DLP heuristic it is driven by its own flag,
    // independent of `--detect exav-heuristics`, and runs at every recursion level (so a
    // phishing HTML part inside an email/archive is caught too).
    #[cfg(feature = "phishing")]
    if let Some(o) = phishing_scan(db, data, opts, sink) {
        return o;
    }

    // Authenticode inspection (independent of `--detect exav-heuristics`, like phishing/DLP).
    // One reading of the signature serves both checks:
    //   * `.crb` certificate block-list: a signed PE carrying a blocked signer
    //     cert is reported (always on when a `.crb` DB is loaded);
    //   * opt-in `alert_broken_authenticode`: the embedded digest does not cover
    //     the file (tampered with / appended-to after signing).
    // Only a PE carries one. Its headers and certificate table are held, and the
    // digest, which is of all of the file, is made as the file is read.
    let signed =
        (opts.alert_broken_authenticode || !db.crb.is_empty()) && data.window(0, 2)[..] == *b"MZ";
    let sig = if signed {
        match authenticode::inspect(data, opts.alert_broken_authenticode, opts.hold_limit()) {
            Ok(sig) => sig,
            Err(held) => {
                engine::mark_over_size(|| {
                    over_size(
                        data.len(),
                        opts,
                        &format!(
                            "the Authenticode checks did not run: they read its headers and \
                             certificate table whole, and one is {held} bytes"
                        ),
                    )
                });
                None
            }
        }
    } else {
        None
    };
    if let Some(sig) = sig {
        for cert in &sig.certs {
            if let Some(name) = db.crb.blocked(cert)
                && let Some(o) = sink.hit(name.to_string(), 0, Method::Hash)
            {
                return o;
            }
        }
        if opts.alert_broken_authenticode
            && !sig.digest_matches
            && let Some(o) = sink.hit(
                "Heuristics.Authenticode.HashMismatch".to_string(),
                0,
                Method::Heuristic,
            )
        {
            return o;
        }
    }

    // Nothing below fires unless at least the ClamAV-default heuristics are on
    // (on by default; `--detect exav-heuristics` is the superset and also enables them).
    if !opts.clamav_heuristics && !opts.heuristics {
        return deferred;
    }

    if let Some(o) = tlsh_hit(db, data, opts, sink) {
        return o;
    }

    // Parsed from all of the PE, or its image if it is too large to hold (see
    // `pe_part`), so read only when something below uses it.
    let views = import_views(db, opts);
    let what = "the PE import and static-model checks";
    let image = if ft == FileType::Pe && (views.clamscan || views.listed) {
        pe_part(data, opts, what)
    } else {
        None
    };
    if let Some(image) = image {
        let info =
            match pe::analyze_within(&image, data.len(), opts.hold_limit(), views, &mut |n| {
                budget.charge_scan(n)
            }) {
                Ok(info) => info,
                Err(cut) => {
                    return match mark_imports_cut(cut, image.len(), data.len(), opts, sink, what) {
                        Some(outcome) => outcome,
                        None => deferred,
                    };
                }
            };
        if let Some(info) = info {
            if info.import_fault && !(obj.embedded && info.import_absent) {
                mark_import_fault(image.len(), data.len(), opts, what);
            }
            // imphash (`.imp`) matching is a ClamAV default (matched whenever the
            // loaded DB carries `.imp` sigs), so it runs under `clamav_heuristics`
            // (i.e. under `--clamav-compat` too). The exav-exclusive static scorer,
            // packed-injection heuristic, and the `-v` diagnostic findings below
            // stay behind the full `--detect exav-heuristics` flag.
            if let Some(hit) = imphash_hit(
                db,
                opts,
                info.is_64,
                (&info.imphash, info.imphash_len),
                &info.pe_imphash,
            ) && let Some(o) = sink.hit(hit, 0, Method::Fuzzy)
            {
                return o;
            }
            if opts.heuristics {
                if depth == 0 {
                    findings.push(Finding::new(
                        "imphash",
                        if info.imphash.is_empty() {
                            "-".into()
                        } else {
                            info.imphash.clone()
                        },
                    ));
                    // The value of `imphash:` lines and `pe.imphash()`, which is
                    // not the `.imp` hash above.
                    findings.push(Finding::new(
                        "pe-imphash",
                        if info.pe_imphash.is_empty() {
                            "-".into()
                        } else {
                            info.pe_imphash.clone()
                        },
                    ));
                    findings.push(Finding::new(
                        "max-section-entropy",
                        format!("{:.2}", info.max_entropy),
                    ));
                    if !info.suspicious_imports.is_empty() {
                        findings.push(Finding::new(
                            "suspicious-imports",
                            info.suspicious_imports.join(", "),
                        ));
                    }
                }
                // The byte histogram and size are of all of the object: counted
                // in the one read of it, or by a read of their own.
                let score = profile::timed("static", data.len() as u64, || {
                    db.model
                        .score(&ml::extract_counted(data, facts.byte_counts(), Some(&info)))
                });
                if depth == 0 {
                    findings.push(Finding::new(
                        "static-score",
                        format!("{score:.2} ({})", db.model.name()),
                    ));
                }
                if score >= db.ml_threshold
                    && let Some(o) = sink.hit(
                        format!("Heuristics.Static.Suspect.{:.0}", score * 100.0),
                        0,
                        Method::Static,
                    )
                {
                    return o;
                }
                if info.looks_packed()
                    && info.suspicious_imports.len() >= 2
                    && let Some(o) = sink.hit(
                        "Heuristics.PE.PackedWithInjectionImports".to_string(),
                        0,
                        Method::Heuristic,
                    )
                {
                    return o;
                }
            }
        }
    }
    deferred
}

/// Which readings of a PE's import table the scan needs: the `.imp` hash if
/// `.imp` signatures are loaded, `pe.imphash()` if `imphash:` lines are, and
/// both for the diagnostics and the static checks of `--detect exav-heuristics`.
fn import_views(db: &Scanner, opts: &ScanOptions) -> pe::Views {
    pe::Views {
        clamscan: db.fuzzy.has_imp() || opts.heuristics,
        listed: db.fuzzy.has_pe_imphash() || opts.heuristics,
    }
}

/// The signature the import hashes of a PE match, if any: `.imp` first, with
/// the hash as clamscan makes it and the length of what it is of, then
/// `imphash:` lines with the one `pe.imphash()` gives.
///
/// clamscan makes no import hash for a PE32+, so a PE32+ matches no `.imp`
/// signature under `--clamav-compat`.
fn imphash_hit(
    db: &Scanner,
    opts: &ScanOptions,
    is_64: bool,
    (imp, imp_len): (&str, usize),
    pe_imphash: &str,
) -> Option<String> {
    let imp = if opts.clamav_compat && is_64 {
        None
    } else {
        db.fuzzy.match_imp(imp, imp_len as u64)
    };
    imp.or_else(|| db.fuzzy.match_pe_imphash(pe_imphash))
}

/// What a check of a PE's imports that was cut short (`what`) makes of the
/// scan, for an `image` of `image_len` bytes cut from an object of `data_len`.
/// `Some` ends the scan with that outcome; otherwise the scan has been marked
/// and goes on without the check.
fn mark_imports_cut(
    cut: pe::Cut,
    image_len: usize,
    data_len: usize,
    opts: &ScanOptions,
    sink: &mut Sink,
    what: &str,
) -> Option<DeepOutcome> {
    match cut {
        // The sections' entropy is read in bytes that count as scanned.
        pe::Cut::Scanned(hit) => return Some(limits_outcome_at(opts, sink, hit.kind, hit.reason)),
        // The names a crafted import table repeats were going to take
        // more than an object may take in memory.
        pe::Cut::Names => engine::mark_over_size(|| {
            format!(
                "{what} did not run: the names of its imports, copied for each import that \
                 refers to one, come to more than the {}-byte limit (--max-object-bytes)",
                opts.limits.max_buffer_bytes
            )
        }),
        // Without its imports the checks did not run, and the scan says so.
        // Whether it is a limit depends on why: a table that would take too
        // much to parse is; one that does not parse is malformed, unless the
        // image is cut from a larger object, whose table may point outside it.
        pe::Cut::Imports(pe::Unread::TooLarge) => engine::mark_over_size(|| {
            format!(
                "{what} did not run: the import table of the PE would take more than \
                 {} bytes to parse (--max-object-bytes)",
                opts.limits.max_buffer_bytes
            )
        }),
        pe::Cut::Imports(pe::Unread::Malformed) if image_len < data_len => {
            engine::mark_over_size(|| {
                over_size(
                    data_len,
                    opts,
                    &format!(
                        "{what} did not run: the import table of the PE does not parse from \
                         its image of {image_len} bytes"
                    ),
                )
            })
        }
        pe::Cut::Imports(pe::Unread::Malformed) => engine::mark_unreadable(|| {
            format!("{what} did not run: the import table of the PE does not parse")
        }),
    }
    None
}

/// A descriptor of the import table did not parse: the checks (`what`) ran on
/// the others, and the scan says it did not see all, unless one of them finds
/// something. Whether it is a limit depends, as in [`mark_imports_cut`], on the
/// image being cut from a larger object.
fn mark_import_fault(image_len: usize, data_len: usize, opts: &ScanOptions, what: &str) {
    if image_len < data_len {
        engine::mark_over_size(|| {
            over_size(
                data_len,
                opts,
                &format!(
                    "{what} ran on part of the import table: a descriptor of it does not \
                     parse from its image of {image_len} bytes"
                ),
            )
        });
    } else {
        engine::mark_unreadable(|| {
            format!("{what} ran on part of the import table: a descriptor of it does not parse")
        });
    }
}

/// The `tlsh:` lookup on all of the object's bytes. TLSH is exav-exclusive
/// (ClamAV has none), so it stays behind the full `--detect exav-heuristics`
/// flag and is off under `--clamav-compat`.
fn tlsh_hit(
    db: &Scanner,
    data: &dyn ByteSource,
    opts: &ScanOptions,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    if !opts.heuristics {
        return None;
    }
    let hit = profile::timed("fuzzy", data.len() as u64, || {
        db.fuzzy.match_tlsh_source(data)
    })?;
    sink.hit(hit, 0, Method::Fuzzy)
}

/// The signature checks on the imports of the executable of an installer or
/// self-extractor (NSIS, Inno Setup, AutoIt, SFX), whose scan ends with its
/// members and so never reaches the checks of [`scan_file`]: `.imp`
/// signatures and `imphash:` lines, as clamscan matches its `.imp` signatures
/// against the executable. Not the static checks (the scoring of a PE by its
/// entropy and imports), which have never run on the executable of an
/// installer: the early return in [`scan_file`] keeps them from it.
fn installer_imports(
    db: &Scanner,
    data: &dyn ByteSource,
    opts: &ScanOptions,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    if !(opts.clamav_heuristics || opts.heuristics) {
        return None;
    }
    let views = pe::Views {
        clamscan: db.fuzzy.has_imp(),
        listed: db.fuzzy.has_pe_imphash(),
    };
    if !(views.clamscan || views.listed) {
        return None;
    }
    let what = "the PE import hash check";
    let image = pe_part(data, opts, what)?;
    let names = opts.hold_limit();
    let imported = match pe::imports_within(&image, data.len(), names, views) {
        Ok(imported) => imported?,
        Err(cut) => return mark_imports_cut(cut, image.len(), data.len(), opts, sink, what),
    };
    if imported.import_fault {
        mark_import_fault(image.len(), data.len(), opts, what);
    }
    let hit = imphash_hit(
        db,
        opts,
        imported.is_64,
        (&imported.imphash, imported.imphash_len),
        &imported.pe_imphash,
    )?;
    sink.hit(hit, 0, Method::Fuzzy)
}

/// `Heuristics.Packed.<Packer>` for a member the PE-packer extractor surfaced as
/// an image it could not unpack, or `None` for anything else.
///
/// The packer name arrives already spelled the way it should be reported:
/// `pepack::packer_name` owns that vocabulary and writes it into the member name
/// as `"<Packer>-packed image"`. Nothing is re-derived here, so adding a packer
/// there makes it reportable here with no second table to forget to update.
fn packed_heuristic_name(member: &str) -> Option<String> {
    let packer = member.strip_suffix("-packed image")?;
    if packer.is_empty() {
        return None;
    }
    Some(format!("Heuristics.Packed.{packer}"))
}

/// The `Heuristics.Encrypted.*` name for an encrypted member of a container of
/// format `fmt` (ClamAV's `--alert-encrypted` naming), format-specific where
/// ClamAV distinguishes it, else the generic `.Archive`.
fn encrypted_heuristic_name(fmt: unpack::Format) -> &'static str {
    use unpack::Format;
    match fmt {
        Format::Zip => "Heuristics.Encrypted.Zip",
        Format::Rar => "Heuristics.Encrypted.RAR",
        Format::SevenZip => "Heuristics.Encrypted.7Zip",
        Format::Pdf => "Heuristics.Encrypted.PDF",
        // `OLE2`, not `Doc`. ClamAV's *config option* is `AlertEncryptedDoc`,
        // but the *signature name* it emits is `Heuristics.Encrypted.OLE2`,
        // observed 468 times against 0 for `.Doc` over a corpus run. A gateway
        // filtering on ClamAV's exact string never matched ours.
        Format::Ole => "Heuristics.Encrypted.OLE2",
        _ => "Heuristics.Encrypted.Archive",
    }
}

fn macro_dialect(name: &str) -> Option<&'static str> {
    match name {
        "vba_project" | "vba_project_raw" => Some("VBA"),
        "xlm_macro" => Some("XLM"),
        _ => None,
    }
}

/// Run the opt-in DLP structured-data heuristic over `data`. Returns an
/// `Infected` outcome with a ClamAV-compatible name when a configured threshold
/// is met, else `None`. Only runs when a threshold is set, on textual buffers.
/// The counters are linear and allocate nothing, so the whole buffer is counted.
#[cfg(feature = "dlp")]
fn structured_data_scan(
    data: &dyn ByteSource,
    opts: &ScanOptions,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    if opts.structured_cc_count.is_none() && opts.structured_ssn_count.is_none() {
        return None;
    }
    if !normalize::is_textual(&data.window(0, normalize::SAMPLE)) {
        return None;
    }
    let count_cards = || match data.as_slice() {
        Some(d) => dlp::count_credit_cards(d),
        None => dlp::count_credit_cards_in(&mut byte_source::Stepper::new(data)),
    };
    let count_ssns = || match data.as_slice() {
        Some(d) => dlp::count_ssns(d, dlp::SsnMode::Both),
        None => dlp::count_ssns_in(&mut byte_source::Stepper::new(data), dlp::SsnMode::Both),
    };
    // A threshold of 0 is 1, as in ClamAV: no number found is never a detection.
    if let Some(threshold) = opts.structured_cc_count
        && count_cards() >= threshold.max(1) as usize
        && let Some(o) = sink.hit(
            "Heuristics.Structured.CreditCardNumber".to_string(),
            0,
            Method::Heuristic,
        )
    {
        return Some(o);
    }
    if let Some(threshold) = opts.structured_ssn_count
        && count_ssns() >= threshold.max(1) as usize
        && let Some(o) = sink.hit(
            "Heuristics.Structured.SSN".to_string(),
            0,
            Method::Heuristic,
        )
    {
        return Some(o);
    }
    None
}

/// Run the opt-in phishing heuristic over `data`. Returns an `Infected` outcome
/// with a ClamAV-compatible name when a spoofed link is found, else `None`. Only
/// runs when the flag is set, on textual buffers. A scan that stopped at its
/// allow-list budget marks the scan incomplete.
#[cfg(feature = "phishing")]
fn phishing_scan(
    db: &Scanner,
    data: &dyn ByteSource,
    opts: &ScanOptions,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    if !opts.alert_phishing {
        return None;
    }
    if !normalize::is_textual(&data.window(0, normalize::SAMPLE)) {
        return None;
    }
    let (found, complete) = phishing::scan_complete_source(data, &db.phishing);
    if !complete {
        engine::mark_scan_truncated();
    }
    sink.hit(found?.signature().to_string(), 0, Method::Heuristic)
}

/// A PE, for the checks that parse its structure (see [`pe_part`]).
fn pe_image<'a>(
    ft: FileType,
    data: &'a dyn ByteSource,
    opts: &ScanOptions,
) -> Option<std::borrow::Cow<'a, [u8]>> {
    if ft == FileType::Pe {
        pe_part(data, opts, "the PE layout, icon and section checks")
    } else {
        None
    }
}

/// A PE held in memory, for a check that parses its structure: all of it when
/// it is held, or at most `limits.max_buffer_bytes` bytes (see [`whole`]), else its
/// image, which is the part up to the end of the last section's data, with
/// the headers. Most of an executable too large to hold is an overlay
/// (installers, self-extractors), and the structure is in the image. `None`
/// when that does not fit either or the headers do not parse, and the scan is
/// then reported as over the size limit: `what` applied and did not run.
///
/// A check that also needs what follows the image, or the length of the
/// object, takes them from the object itself.
fn pe_part<'a>(
    data: &'a dyn ByteSource,
    opts: &ScanOptions,
    what: &str,
) -> Option<std::borrow::Cow<'a, [u8]>> {
    let limit = opts.hold_limit();
    let part = data
        .materialize(limit)
        .or_else(|| pe::image_in(data, limit));
    if part.is_none() {
        engine::mark_over_size(|| {
            let why = match pe::extent(data, limit) {
                Some(e) => format!(
                    "{what} did not run: the PE's image, up to the end of its last \
                     section, is {} bytes",
                    e.image
                ),
                None => format!("{what} did not run"),
            };
            over_size(data.len(), opts, &why)
        });
    }
    part
}

/// All of `data`, for a check that parses an object whole: the object itself
/// when it is held in memory, or read into memory when it is at most
/// `limits.max_buffer_bytes`. `None` otherwise, and the scan is then reported as
/// over the size limit: `what` applied and did not run.
fn whole<'a>(
    data: &'a dyn ByteSource,
    opts: &ScanOptions,
    what: &str,
) -> Option<std::borrow::Cow<'a, [u8]>> {
    let whole = data.materialize(opts.hold_limit());
    if whole.is_none() {
        engine::mark_over_size(|| over_size(data.len(), opts, &format!("{what} did not run")));
    }
    whole
}

/// Why an object carving reached its cap on is not fully scanned.
fn carving_capped(caps: pe::CarveCaps) -> String {
    format!(
        "more embedded files than carving scans in one object ({} executables of \
         each kind, {} archives): the rest were not scanned \
         (--max-carved-executables, --max-carved-archives)",
        caps.executables, caps.archives,
    )
}

/// Why something was skipped on an object of `len` bytes: it is over the
/// object limit, and `consequence`.
fn over_size(len: usize, opts: &ScanOptions, consequence: &str) -> String {
    format!(
        "object is {len} bytes, over the {}-byte object limit \
         (--max-object-bytes): {consequence}",
        opts.limits.max_buffer_bytes
    )
}

/// Whether a detection is on the `.ign`/`.ign2` list, under the name it would
/// be reported as (`suffix` is [`ScanOptions::unofficial_suffix`]).
///
/// Checked where each matcher picks its hit rather than on the finished
/// report: a first-match scan that stopped on an ignored signature would never
/// look for a real one further on, and the report would then be cleared.
fn is_ignored(db: &Scanner, name: &str, unofficial: bool, suffix: bool) -> bool {
    !db.ignored.is_empty() && db.ignored.contains(&report_name(name, unofficial, suffix))
}

/// Whether clamscan reads a message from inside an object of this type, and
/// whether all through it: it does in a text file and in binary data, and only at
/// the start of a page of HTML. Not in a file of a type of its own (an
/// executable, a picture, a document, an archive).
#[cfg(feature = "email")]
fn mail_inside_reach(ft: FileType, data: &dyn ByteSource) -> Option<bool> {
    match ft {
        FileType::Text | FileType::Script => Some(true),
        FileType::Unknown => (!engine::looks_like_image(data, false)).then_some(true),
        FileType::Html => Some(false),
        _ => None,
    }
}

/// Whether a file type is text-ish (not a positively-typed binary/container).
/// Used to decide which OLE-extracted streams to scan in OLE context.
fn is_textual_type(ft: FileType) -> bool {
    matches!(
        ft,
        FileType::Text
            | FileType::Unknown
            | FileType::Script
            | FileType::Html
            | FileType::Rtf
            | FileType::Email
    )
}

/// Cheap "is this buffer mostly text?" gate for the base64 payload scan: sample
/// the head and require ≥90% printable-ASCII/whitespace, so we only trial-decode
/// base64 in script/document carriers, never in binaries (which is where a
/// base64-looking byte-run is both costly to scan and a false decode).
#[cfg(feature = "base64scan")]
fn mostly_text(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(8192)];
    if sample.len() < 64 {
        return false;
    }
    let printable = sample
        .iter()
        .filter(|&&b| b == b'\t' || b == b'\r' || b == b'\n' || (0x20..=0x7e).contains(&b))
        .count();
    printable * 100 >= sample.len() * 90
}

/// Whether any stretch of `data` is text, going by up to four 8 KiB samples (its
/// start, its end and the thirds between, stopping at the first that has any)
/// and by the kilobytes of a sample one by one. A script behind a binary header
/// or a long comment of high bytes is text where it matters. Each sample over a
/// cache is a block of it read, so a binary object pays at most three more than
/// the first.
#[cfg(feature = "base64scan")]
fn text_anywhere(data: &dyn ByteSource) -> bool {
    const SAMPLE: usize = 8192;
    let texty = |at: usize| data.window(at, SAMPLE).chunks(1024).any(mostly_text);
    let len = data.len();
    if len <= SAMPLE {
        return texty(0);
    }
    let last = len - SAMPLE;
    [0, last, last / 3, last / 3 * 2].into_iter().any(texty)
}

/// Why an object that has more base64-encoded files than are decoded in one
/// object is not fully scanned.
#[cfg(feature = "base64scan")]
fn base64_capped() -> String {
    "more base64-encoded executables, archives or images than are decoded in one object: \
     the rest were not scanned (--max-base64-payloads, --max-base64-runs, --max-page-assets)"
        .to_string()
}

/// The normalised views of `data` a textual file is matched against, in order.
/// The caller makes each with [`make_view`] and drops it before the next.
///
/// Each one is a full-size copy of `data`. Materialising the set before
/// scanning any of it put two (four for a script) in memory at once, on top
/// of the buffer they were derived from, and nesting stacks that: a container,
/// its member and that member's own member are each mid-scan while the walk is
/// inside them. Making one at a time keeps the peak at one copy without
/// changing which views are scanned or in what order.
///
/// Each comes with the type it is matched as, which decides the signatures
/// that apply. As clamscan does, an HTML object has its HTML view and a text
/// object its text view, each not the other. An RTF has both, which clamscan
/// does not give it: see "A pure-ASCII RTF is text" in the quirks guide.
///
/// A message whose head has markup gets an HTML object's views, so that typing
/// it as a message does not take them away.
///
/// Under `compat` an HTML object has no view of the whole page through the
/// script normaliser: clamscan normalises its script elements only, which the
/// scripts view holds.
fn normalizations(ft: FileType, data: &dyn ByteSource, compat: bool) -> Vec<(ViewKind, FileType)> {
    let head = data.window(0, 8192);
    let (kind, as_type) = match ft {
        FileType::Rtf => {
            return vec![
                (ViewKind::Html, FileType::HtmlView),
                (ViewKind::Text, FileType::TextView),
            ];
        }
        FileType::Html => (ViewKind::Html, FileType::HtmlView),
        FileType::Email if filetype::looks_like_html(&head) => (ViewKind::Html, FileType::HtmlView),
        _ => (ViewKind::Text, FileType::TextView),
    };
    let mut v = vec![(kind, as_type)];
    if kind == ViewKind::Html || looks_like_script(ft, &head) {
        v.push((ViewKind::Javascript, as_type));
        if !(compat && kind == ViewKind::Html) {
            v.push((ViewKind::Deobfuscated, as_type));
        }
    }
    // The scripts of a page, which clamscan matches as text as well.
    if kind == ViewKind::Html {
        v.push((ViewKind::PageScripts, FileType::ScriptView));
    }
    v
}

/// The text a reader sees in the object `data` called `name` (Markdown, HTML,
/// an Office or OpenDocument XML part, PDF, a drawing): its words, and where
/// each link leads (`exav_render::text`).
///
/// The text as a text view is matched, and each link whose label is not its
/// target as `(label, target)`.
///
/// `None` when the object has none, or when it cannot be made, and the scan is
/// then marked incomplete: the object is past `limits.max_buffer_bytes`, so it is
/// neither held in memory nor read whole. A text cut at four times the object and a little,
/// which no real document comes to, and a PDF past the extraction limits, mark
/// the scan incomplete too; what was made is still scanned. So does an
/// office document (with `visible-text-office`) whose text cannot be taken
/// out: encrypted, past a limit, damaged.
#[cfg(feature = "visible-text")]
fn visible_text_view(name: &str, data: &dyn ByteSource, opts: &ScanOptions) -> Option<VisibleView> {
    if !exav_render::text::wants(name, data) {
        return None;
    }
    let bytes = whole(data, opts, "the reading of its visible text")?;
    let cap = bytes
        .len()
        .saturating_mul(4)
        .saturating_add(64 << 10)
        .min(opts.hold_limit());
    let visible = exav_render::text::visible_text(name, &bytes, cap, &opts.limits)?;
    if visible.truncated {
        engine::mark_scan_truncated();
    }
    // A document of a kind that has text, whose text could not be taken out
    // (encrypted, past a limit, damaged): its bytes are still scanned, and the
    // scan is not complete.
    if visible.unreadable.is_some() {
        engine::mark_scan_truncated();
        return None;
    }
    // As any text view is, so that `Target:7` signatures, written against the
    // lowercased, whitespace-collapsed form, apply.
    Some(VisibleView {
        text: normalize::text(visible.text.as_bytes()),
        links: visible.links,
    })
}

/// A document's visible text as a text view, and its links.
#[cfg(any(feature = "visible-text", feature = "qr"))]
struct VisibleView {
    text: Vec<u8>,
    /// Each link whose label is not its target, as `(label, target)`.
    links: Vec<(String, String)>,
}

/// The payloads of the QR codes in the image `data` (`exav_render::qr`), one
/// to a line, as a text view, and each that is a web address as a link with
/// no label, for the phishing check. `raster` says how to read `data` as pixels
/// when it is raw samples (a PDF image) rather than an image file.
///
/// `None` when it is not an image, or has no code. An image too large to
/// decode within the buffer limit or past `max_qr_pixels`, and a reading cut
/// by `max_qr_millis`, `max_qr_codes`, `max_qr_finders`, `max_qr_grids` or the
/// buffer limit (the memory of the search), mark the scan incomplete. So does
/// an image that is recognised and does not decode, or a PDF image (raw
/// samples, CCITT, JBIG2) that is not read: the scan is then unscannable.
#[cfg(feature = "qr")]
fn qr_view(
    data: &dyn ByteSource,
    raster: Option<&unpack::Raster>,
    opts: &ScanOptions,
) -> Option<VisibleView> {
    if !exav_render::qr::wants(&data.window(0, 64), raster) {
        return None;
    }
    let bytes = whole(data, opts, "the reading of its QR codes")?;
    let found = exav_render::qr::search(
        &bytes,
        raster,
        &exav_render::qr::Settings {
            max_pixels: opts.max_qr_pixels,
            max_millis: opts.max_qr_millis,
            max_codes: opts.max_qr_codes,
            max_finders: opts.max_qr_finders,
            max_grids: opts.max_qr_grids,
            max_buffer_bytes: opts.limits.max_buffer_bytes,
        },
    )?;
    if let Some(why) = found.cut {
        engine::mark_capped(|| why);
    }
    if let Some(why) = found.unread {
        engine::mark_unreadable(|| why);
    }
    if found.payloads.is_empty() {
        return None;
    }
    let mut text = String::new();
    let mut links = Vec::new();
    for p in &found.payloads {
        text.push_str(p);
        text.push('\n');
        let lower = p.trim_start().to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            links.push((String::new(), p.trim().to_string()));
        }
    }
    Some(VisibleView {
        text: normalize::text(text.as_bytes()),
        links,
    })
}

/// A normalised view of an object: [`normalize`]'s three, and [`jsnorm`]'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewKind {
    Html,
    Text,
    Javascript,
    /// The whole object through the script normaliser in its decoding mode.
    /// exav's own: clamscan has no such view.
    Deobfuscated,
    /// The `<script>` elements of a page, normalised as script in clamscan's
    /// mode, which the signatures written against its output match.
    PageScripts,
    /// Their contents before that, which [`ViewKind::PageScripts`] spills
    /// for an object not held in memory.
    HtmlScripts,
}

/// A normalised view, held in memory or read back from a spill file.
enum View {
    Mem(Vec<u8>),
    Spilled(spill::Spilled),
}

impl View {
    fn source(&self) -> &dyn ByteSource {
        match self {
            View::Mem(v) => v,
            View::Spilled(s) => s,
        }
    }
}

/// `kind`'s view of `data`: made in memory when `data` is held there, else
/// written to the host's spill. `None` when it cannot be made, and the scan is
/// then marked incomplete.
fn make_view(kind: ViewKind, data: &dyn ByteSource, opts: &ScanOptions) -> Option<View> {
    if kind == ViewKind::Deobfuscated {
        // Bounded by its own cap, so held in memory either way.
        let (view, cut) = jsnorm::normalize_source(data, jsnorm::Mode::Decoding);
        // The raw bytes are still scanned in full; only this view is short.
        if cut {
            engine::mark_scan_truncated();
        }
        return Some(View::Mem(view));
    }
    if kind == ViewKind::PageScripts {
        // The scripts the HTML view holds, normalised as script, each on its own.
        let scripts = make_view(ViewKind::HtmlScripts, data, opts)?;
        let (view, cut) = jsnorm::normalize_scripts(scripts.source());
        if cut {
            engine::mark_scan_truncated();
        }
        if let Some(e) = scripts.source().read_error() {
            engine::mark_unreadable(|| e);
        }
        return Some(View::Mem(view));
    }
    if let Some(d) = data.as_slice() {
        return Some(View::Mem(match kind {
            ViewKind::Html => normalize::html(d),
            ViewKind::Text => normalize::text(d),
            ViewKind::HtmlScripts => normalize::scripts(d),
            _ => normalize::javascript(d),
        }));
    }
    let not_made = |why: &str| {
        engine::mark_over_size(|| {
            over_size(
                data.len(),
                opts,
                &format!("its normalised text views were not scanned: {why}"),
            )
        })
    };
    let file = match &opts.spill {
        Some(spill) => spill.create(),
        None => Err("spilling to disk is off".to_string()),
    };
    let file = match file {
        Ok(file) => file,
        Err(e) => {
            not_made(&e);
            return None;
        }
    };
    let mut out = spill::SpillOut::new(file);
    let mut src = byte_source::Stepper::new(data);
    match kind {
        ViewKind::Html => normalize::html_into(&mut src, &mut out),
        ViewKind::Text => normalize::text_into(&mut src, &mut out),
        ViewKind::HtmlScripts => {
            let mut s = normalize::Scripts::new(out);
            normalize::scripts_into(&mut src, &mut s);
            out = s.into_inner();
        }
        _ => normalize::javascript_into(&mut src, &mut out),
    }
    match out.finish(opts.cache_sizes()) {
        Ok(spilled) => Some(View::Spilled(spilled)),
        Err(e) => {
            not_made(&e);
            None
        }
    }
}

/// True if `data` looks like JavaScript / generic script and is worth running
/// the JS normaliser over (in addition to the HTML/text normalisers). Covers
/// shebang scripts and HTML (`FileType::Script` / `FileType::Html`), any text
/// embedding a `<script` tag, and `.js`-ish textual buffers exhibiting common
/// JS obfuscation primitives (`eval`/`unescape`/`fromCharCode`/`function`).
/// Reads the first 8 KiB.
fn looks_like_script(ft: FileType, data: &[u8]) -> bool {
    if matches!(ft, FileType::Script | FileType::Html) {
        return true;
    }
    let head = &data[..data.len().min(8192)];
    let contains_ci = |needle: &[u8]| -> bool {
        needle.len() <= head.len()
            && head
                .windows(needle.len())
                .any(|w| w.eq_ignore_ascii_case(needle))
    };
    contains_ci(b"<script")
        || contains_ci(b"fromcharcode")
        || contains_ci(b"charcodeat")
        || contains_ci(b"unescape(")
        || contains_ci(b"decodeuricomponent")
        || contains_ci(b"eval(")
        || contains_ci(b"function(")
        || contains_ci(b"function (")
        // Common malicious JScript/VBScript dropper markers (the latter rarely
        // carry an `eval`/`function` trigger). Gating only decides whether the
        // normalised script buffer is produced; it can never cause a match.
        || contains_ci(b"activexobject")
        || contains_ci(b"createobject")
        || contains_ci(b"wscript")
}

/// What the matching core leaves for the rest of an object's scan.
struct CoreRest {
    /// The buffers a bytecode unpacker made of the object: content that exists
    /// nowhere else, to scan as objects of their own.
    unpacked: Vec<Vec<u8>>,
    /// The type a `HandlerType:` signature gave the object, if one matched.
    retype: Option<FileType>,
}

/// What bytecode programs may write for one object: no output larger than a
/// buffer the scan may hold, and all of it within the bytes the scan has left.
/// The output is charged to the budget when it is scanned.
fn write_limits(budget: &Budget) -> bytecode::exec::WriteLimits {
    bytecode::exec::WriteLimits {
        file: budget.limits().max_buffer_bytes,
        total: budget.remaining_scan(),
        memory: budget.limits().max_bytecode_memory_bytes,
    }
}

/// The layout the engine resolves `EP`/section-relative offsets with: a PE's,
/// from `image` (see [`pe_image`]), and an ELF's or a Mach-O's, read from its
/// headers.
fn layout_of(ft: FileType, image: Option<&[u8]>, data: &dyn ByteSource) -> Option<pe::PeLayout> {
    image.and_then(pe::layout).or_else(|| match ft {
        FileType::Elf => pe::elf_layout(data),
        FileType::MachO => pe::macho_layout(data),
        _ => None,
    })
}

/// The bounds the engine reads an object whole within, and the formats it
/// hashes images as.
fn whole_limits(opts: &ScanOptions) -> engine::WholeLimits {
    engine::WholeLimits {
        materialize: opts.hold_limit(),
        pcre: opts
            .max_pcre_bytes
            .map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX)),
        pcre_said: !opts.clamav_compat,
        regex_steps: opts
            .max_regex_steps
            .map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX)),
        yara_steps: opts.max_yara_steps,
        matcher_steps: opts.max_matcher_steps,
        all_image_formats: !opts.clamav_compat,
        // What lies within a quarter of a block of a hit is held while the
        // sweep is there.
        near_reach: (opts.cache_sizes().0 / 4).max(1),
        // The hits set aside take no more than a cache does.
        deferred_bytes: opts.cache_sizes().1,
        search_bytes: opts.cache_sizes().1,
    }
}

/// The matching core over an object's own bytes, `ft` being the type it is
/// matched as. Every detection goes to `sink`; `Err` means the walk must stop.
#[allow(clippy::too_many_arguments)]
fn core(
    db: &Scanner,
    facts: &Facts,
    ft: FileType,
    obj: Obj<'_>,
    opts: &ScanOptions,
    writes: bytecode::exec::WriteLimits,
    budget: &mut Budget,
    sink: &mut Sink,
) -> Result<CoreRest, DeepOutcome> {
    let data = facts.data;
    let unpacked = core_matches(db, facts, ft, obj, opts, writes, budget, sink);
    // Taken whatever the outcome, so it cannot outlive this object and retype
    // a later one at the same address.
    let retype = engine::take_retype_source(data);
    unpacked.map(|unpacked| CoreRest { unpacked, retype })
}

/// [`core`]'s matching: the signature engine over the object's bytes and their
/// normalised views, bytecode, PE section hashes, the whole-file hash, YARA.
///
/// The single place a normal scan and `--all-matches` differ: the engine is
/// asked for the first match, or for all of them. The traversal above never
/// branches on the mode.
#[allow(clippy::too_many_arguments)]
fn core_matches(
    db: &Scanner,
    facts: &Facts,
    ft: FileType,
    obj: Obj<'_>,
    opts: &ScanOptions,
    writes: bytecode::exec::WriteLimits,
    budget: &mut Budget,
    sink: &mut Sink,
) -> Result<Vec<Vec<u8>>, DeepOutcome> {
    let data = facts.data;
    let suffix = opts.unofficial_suffix;
    let materialize = opts.hold_limit();
    let whole = whole_limits(opts);
    let all = sink.wants_all();
    // The engine passes over an ignored (`.ign`/`.ign2`) match to look for the
    // next one; every other matcher's hits are ignored by the sink.
    let skip = |name: &str, unofficial: bool| is_ignored(db, name, unofficial, suffix);
    let mut hit = |name: &str, unofficial: bool, offset: u64, method: Method| match sink.hit(
        report_name(name, unofficial, suffix),
        offset,
        method,
    ) {
        Some(stop) => Err(stop),
        None => Ok(()),
    };
    // A PE's structure (layout, icons, section table) is parsed from all of it,
    // or from its image when it is too large to hold.
    let image = pe_image(ft, data, opts);
    let layout = layout_of(ft, image.as_deref(), data);
    // PE-icon perceptual metrics for `IconGroup1/2`-constrained logical
    // signatures: computed only for a PE when `.idb` entries are loaded. They
    // gate such sigs (the structural condition must also hold); see [`icon`].
    let icon_metrics = match &image {
        Some(image) if !db.icons.is_empty() => {
            profile::timed("icon", data.len() as u64, || icon::pe_icon_metrics(image))
        }
        _ => Vec::new(),
    };
    let icon_ctx = engine::IconCtx::new(&db.icons, &icon_metrics);
    // The bytecode triggers that fire on the raw bytes, found in the same
    // sweep as every other signature.
    let mut fired = Vec::new();
    // `as_type` is `ft` for the object's own bytes, the view's type for a view.
    // `answer` is what the read that fed the engine found in the object, when it
    // ran it as `as_type`: used in place of a pass over `src`.
    let mut engine_pass = |src: &dyn ByteSource,
                           as_type: FileType,
                           layout: Option<&pe::PeLayout>,
                           icons: Option<&engine::IconCtx>,
                           fired: Option<&mut Vec<engine::Fired>>,
                           answer: Option<pass::EngineRun>|
     -> Result<(), DeepOutcome> {
        let mut found = Vec::new();
        match answer {
            Some(run) => {
                run.apply(src);
                if let Some(fired) = fired {
                    fired.extend(run.fired);
                }
                found = run.found;
            }
            None => profile::timed("engine", src.len() as u64, || {
                let (c, above) = (obj.container, obj.ancestry);
                if all {
                    db.engine.scan_all_fed(
                        src, as_type, layout, c, above, icons, &mut found, whole, fired, None,
                    );
                } else {
                    found.extend(db.engine.scan_first_fed(
                        src, as_type, layout, c, above, icons, &skip, whole, fired, None,
                    ));
                }
            }),
        }
        for (name, off, unofficial) in found {
            hit(&name, unofficial, off, Method::Pattern)?;
        }
        Ok(())
    };
    // The object's own bytes.
    engine_pass(
        data,
        ft,
        layout.as_ref(),
        Some(&icon_ctx),
        Some(&mut fired),
        facts.engine_answer(ft),
    )?;
    // Normalised-content passes: HTML/text (`Target:3/7`) signatures are
    // written against canonicalised content, not raw bytes. Only worth making
    // for a textual object: a Target:0 pattern has already run against the
    // raw bytes, so for a positively-typed binary they are pure cost.
    // `is_textual` alone does not say so: it counts 0x80..=0xff as text, and
    // most packed binaries carry few NULs.
    if !db.engine.is_empty()
        && is_textual_type(ft)
        && normalize::is_textual(&data.window(0, normalize::SAMPLE))
    {
        // One at a time: each is a full-size copy of `data`, and nesting
        // stacks them (a container, its member and that member's member are
        // each mid-scan while the walk is inside them).
        for (kind, as_type) in normalizations(ft, data, opts.clamav_compat) {
            let Some(view) = profile::timed("normalize", data.len() as u64, || {
                make_view(kind, data, opts)
            }) else {
                continue;
            };
            engine_pass(view.source(), as_type, None, None, None, None)?;
            // A view read back from the spill that failed part way was not
            // matched whole.
            if let Some(e) = view.source().read_error() {
                engine::mark_unreadable(|| e);
            }
        }
    }
    // The payloads of the QR codes in an image, a link among them judged as a
    // link of a document is (reported below, once the views are matched).
    #[cfg(feature = "qr")]
    let mut qr_phish = None;
    #[cfg(feature = "qr")]
    if opts.qr_codes
        && !opts.clamav_compat
        && !db.engine.is_empty()
        && let Some(view) =
            profile::timed("qr", data.len() as u64, || qr_view(data, obj.raster, opts))
    {
        engine_pass(&view.text, FileType::TextView, None, None, None, None)?;
        if opts.alert_phishing {
            let (found, complete) = phishing::scan_links(&view.links, &db.phishing);
            if !complete {
                engine::mark_scan_truncated();
            }
            qr_phish = found;
        }
    }
    // The words of a document, and where each link leads: what a reader sees,
    // which the bytes above do not give (a label naming one site over a target
    // on another, markup, an entity, a compressed stream or an escape in the
    // middle of a signature's text).
    #[cfg(feature = "visible-text")]
    if !opts.clamav_compat
        && !db.engine.is_empty()
        && let Some(view) = profile::timed("visible-text", data.len() as u64, || {
            visible_text_view(obj.name.unwrap_or(""), data, opts)
        })
    {
        // Reported where the document is, as the other views are.
        engine_pass(&view.text, FileType::TextView, None, None, None, None)?;
        // A link that says one site and goes to another, in a document
        // that is not HTML: judged as an anchor of an HTML one is.
        if opts.alert_phishing {
            let (found, complete) = phishing::scan_links(&view.links, &db.phishing);
            if !complete {
                engine::mark_scan_truncated();
            }
            if let Some(p) = found {
                hit(p.signature(), false, 0, Method::Heuristic)?;
            }
        }
    }
    #[cfg(feature = "qr")]
    if let Some(p) = qr_phish {
        hit(p.signature(), false, 0, Method::Heuristic)?;
    }
    // Bytecode programs whose trigger/hook fires (gated execution). Their
    // names are reported verbatim, never `.UNOFFICIAL`-suffixed.
    let mut unpacked = Vec::new();
    if !db.bytecode.is_empty() {
        let (det, extracted) = profile::timed("bytecode", data.len() as u64, || {
            db.bytecode
                .scan_source(data, ft, materialize, &fired, writes)
        });
        if let Some((name, _)) = det {
            hit(&name, false, 0, Method::Bytecode)?;
        }
        unpacked = extracted;
    }
    if !db.sections.is_empty()
        && let Some(image) = &image
    {
        // Sections may overlap, each as long as the object: the bytes hashed
        // are charged to the scan, as bytes matched are, and not left to the
        // size of the object.
        let mut over = None;
        let found: Vec<_> = profile::timed("sections", data.len() as u64, || {
            let mut found = Vec::new();
            for (size, slice) in pe::section_slices(image) {
                if db.sections.wants(size) != hashes::Want::default()
                    && let Err(limit) = budget.charge_scan(slice.len() as u64)
                {
                    over = Some(limit);
                    break;
                }
                let digests = hashes::section_digests(&db.sections, size, slice);
                found.extend(db.sections.lookup(size, &digests));
            }
            found
        });
        for (name, unofficial) in found {
            hit(&name, unofficial, 0, Method::Hash)?;
        }
        if let Some(limit) = over {
            return Err(limits_outcome_at(opts, sink, limit.kind, limit.reason));
        }
    }
    if !db.hashes.is_empty()
        && hash_matchable(data.len() as u64)
        && let Some((name, unofficial)) = profile::timed("hashes", data.len() as u64, || {
            db.hashes.lookup(facts.digests(db), data.len() as u64)
        })
    {
        hit(&name, unofficial, 0, Method::Hash)?;
    }
    if !db.yara.is_empty() {
        let unofficial = db.yara.unofficial();
        for name in profile::timed("yara", data.len() as u64, || {
            db.yara
                .scan_source(data, obj.filename, obj.embedded, &whole, facts.yara_pass())
        }) {
            hit(&name, unofficial, 0, Method::Yara)?;
        }
    }
    Ok(unpacked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use patterns::eicar;
    use std::io::Cursor;

    /// The default options with the object limit set to `max`.
    fn holding(max: u64) -> ScanOptions {
        let mut opts = ScanOptions::default();
        opts.limits.max_buffer_bytes = max;
        opts
    }

    #[cfg(unix)]
    #[test]
    fn o_nonblock_is_the_platforms() {
        assert_eq!(O_NONBLOCK, libc::O_NONBLOCK);
    }

    /// A reader that counts the bytes read through it.
    struct Counting(
        Cursor<Vec<u8>>,
        std::sync::Arc<std::sync::atomic::AtomicU64>,
    );

    impl std::io::Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.0.read(buf)?;
            self.1
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            Ok(n)
        }
    }

    impl std::io::Seek for Counting {
        fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
            self.0.seek(p)
        }
    }

    /// `limits.max_buffer_bytes` is the one setting that decides whether an
    /// object is held: with only it lowered, an object past it is read through
    /// the block cache, in blocks, and not into memory in one read.
    #[test]
    fn lowering_only_the_object_limit_reads_through_the_block_cache() {
        /// A reader that remembers the largest read it was asked for.
        struct Widest(
            Cursor<Vec<u8>>,
            std::sync::Arc<std::sync::atomic::AtomicUsize>,
        );
        impl std::io::Read for Widest {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.1
                    .fetch_max(buf.len(), std::sync::atomic::Ordering::Relaxed);
                self.0.read(buf)
            }
        }
        impl std::io::Seek for Widest {
            fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
                self.0.seek(p)
            }
        }
        const BLOCK: usize = 4096;
        let data = vec![b'.'; 256 * 1024];
        let db = Scanner::builtin();
        let widest = |opts: &ScanOptions| {
            let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let reader = Widest(Cursor::new(data.clone()), seen.clone());
            scan_seekable(&db, reader, data.len() as u64, opts).unwrap();
            seen.load(std::sync::atomic::Ordering::Relaxed)
        };
        let held = ScanOptions {
            object_cache_block_bytes: BLOCK as u64,
            ..ScanOptions::default()
        };
        assert!(widest(&held) > BLOCK, "the object is held by default");
        let mut cached = held.clone();
        cached.limits.max_buffer_bytes = BLOCK as u64;
        assert!(
            widest(&cached) <= BLOCK,
            "past the limit it is read in blocks"
        );
    }

    /// How many times over a scan by `db` reads `data` from a source it does
    /// not hold in memory.
    fn passes_over(db: &Scanner, data: &[u8]) -> f64 {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        let read = Arc::new(AtomicU64::new(0));
        let reader = Counting(Cursor::new(data.to_vec()), read.clone());
        // A cache under the size of the objects the tests read, so that a
        // second read of a part of one goes back to the source.
        let opts = ScanOptions {
            object_cache_bytes: 8 << 20,
            object_cache_block_bytes: 64 << 10,
            ..holding(1 << 20)
        };
        scan_seekable(db, reader, data.len() as u64, &opts).unwrap();
        read.load(Ordering::Relaxed) as f64 / data.len() as f64
    }

    /// Every full read of an object not held in memory is counted, per kind of
    /// object and of signature set. Each is a read of the source, for an HTTP
    /// one a download, so a change that adds one fails here: raising a bound
    /// needs the maintainer's approval, not a new expectation.
    ///
    /// One read serves carving, the digests when a hash signature has the
    /// object's size, the search of a text file for a message in it, the
    /// signature sweep and YARA's patterns; detection reads the object's
    /// start and end. A signature with an unbounded gap, whose literal after it is
    /// searched through the rest of the object once the sweep is over, adds
    /// at most one more. The cache is smaller than the object, so a part it
    /// no longer holds that is read again is read from the source again: an
    /// extra pass over the object shows as the third of it that the cache
    /// has evicted. Each bound allows a tenth of a read more, for window
    /// seams and headers read again.
    #[test]
    fn a_streamed_object_is_read_a_few_times() {
        let size = 12 << 20;
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut noise: Vec<u8> = (0..size)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect();
        // No magic a carver or a format check would stop at by chance.
        for w in 0..noise.len() - 1 {
            if matches!(
                &noise[w..w + 2],
                b"MZ" | b"PK" | b"7z" | b"BZ" | b"\x1f\x8b" | b"Ra" | b"MS"
            ) {
                noise[w] ^= 0x80;
            }
        }
        let db = |hash_size: usize| {
            let mut l = loader::Builder::new();
            l.add_named_bytes("a.ndb", b"Sig.Pat:0:*:0badc0de0badf00d0bad\n", true);
            l.add_named_bytes(
                "b.ldb",
                b"Sig.Gap;Engine:51-255,Target:0;0&1;0badf00d;0badc0de*d00d\n",
                true,
            );
            let hdb = format!("0123456789abcdef0123456789abcdef:{hash_size}:Sig.Hash\n");
            l.add_named_bytes("c.hdb", hdb.as_bytes(), true);
            let hsb = format!("{}:{hash_size}:Sig.Sha\n", "ab".repeat(32));
            l.add_named_bytes("d.hsb", hsb.as_bytes(), true);
            let fp = format!("fedcba9876543210fedcba9876543210:{hash_size}:Some.Good\n");
            l.add_named_bytes("e.fp", fp.as_bytes(), true);
            #[cfg(feature = "yara")]
            l.add_named_bytes(
                "f.yar",
                b"rule Never { strings: $a = \"needle not in the noise\" condition: $a }\n",
                true,
            );
            l.build().unwrap()
        };
        let (other_size, this_size) = (db(12345), db(size));
        let mut pe = noise.clone();
        pe[..2].copy_from_slice(b"MZ");
        let mut gap = noise.clone();
        gap[1000..1004].copy_from_slice(&[0x0b, 0xad, 0xc0, 0xde]);
        // Text with a message in it near its end, past the first megabyte.
        let line = b"the quick brown fox jumps over the lazy dog\n";
        let plain: Vec<u8> = line.iter().copied().cycle().take(size).collect();
        let mut text = plain.clone();
        let at = (size - (4 << 10)) / line.len() * line.len();
        let message = b"MIME-Version: 1.0\nContent-Type: text/plain\n\nhi\n";
        text[at..at + message.len()].copy_from_slice(message);
        #[cfg_attr(not(feature = "yara"), allow(unused_mut))]
        let mut cases: Vec<(&str, &Scanner, &[u8], f64)> = vec![
            ("unknown", &other_size, &noise, 1.0),
            ("PE", &other_size, &pe, 1.0),
            ("unknown, hashed", &this_size, &noise, 1.0),
            ("PE, hashed", &this_size, &pe, 1.0),
            ("unknown, a gap to the end", &other_size, &gap, 1.4),
            // A text file is searched once more for the base64 it holds.
            ("text", &other_size, &plain, 1.4),
            ("text, a message in it", &other_size, &text, 1.4),
        ];
        // YARA patterns of every kind, found all through the object: a literal,
        // a wide one, a regexp with a few bytes before its atom, an open one,
        // a hex pattern, a regexp with no atom and an xor one.
        #[cfg(feature = "yara")]
        let yara = {
            let mut l = loader::Builder::new();
            l.add_named_bytes(
                "g.yar",
                r#"
                rule Lit { strings: $a = "needle in the noise" nocase $w = "wideneedle text" wide condition: any of them }
                rule Bounded { strings: $r = /[a-z]{3}needle[0-9]{3}/ condition: $r }
                rule Open { strings: $u = /ne+dle[a-z]+ok/ condition: $u }
                rule Hex { strings: $h = { 6e 65 65 64 [2-4] 69 6e } condition: $h }
                rule Free { strings: $f = /[a-z0-9]{30,}ZZ/ $x = "xorneedle" xor condition: any of them }
                "#
                .as_bytes(),
                true,
            );
            l.build().unwrap()
        };
        #[cfg(feature = "yara")]
        let planted = {
            let mut d = noise.clone();
            let wide: Vec<u8> = b"wideneedle text".iter().flat_map(|&b| [b, 0]).collect();
            let xor: Vec<u8> = b"xorneedle".iter().map(|b| b ^ 5).collect();
            for (at, text) in [
                (1 << 20, &b"NEEDLE in the NOISE"[..]),
                (2 << 20, &wide),
                (3 << 20, b"abcneedle123"),
                (4 << 20, b"neeeedleabcok"),
                (5 << 20, b"needxxin"),
                (6 << 20, b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaZZ"),
                (7 << 20, &xor),
                (size - 20, b"abcneedle123"),
            ] {
                d[at..at + text.len()].copy_from_slice(text);
            }
            d
        };
        #[cfg(feature = "yara")]
        cases.push(("unknown, YARA patterns found", &yara, &planted, 1.0));
        for (what, db, data, bound) in cases {
            let passes = passes_over(db, data);
            assert!(
                passes <= bound + 0.1,
                "{what}: read {passes:.2} times over, the bound is {bound}"
            );
        }
    }

    /// A message inside a text file too large to hold is found in the read of
    /// it that the other searches share, and read from where its headers start.
    #[cfg(feature = "email")]
    #[test]
    fn a_message_inside_a_streamed_text_file_is_read() {
        let size = 12 << 20;
        let line = b"the quick brown fox jumps over the lazy dog\n";
        let mut text: Vec<u8> = line.iter().copied().cycle().take(size).collect();
        let message = "Cc: a@example.com\nMIME-Version: 1.0\nContent-Type: multipart/mixed; \
                       boundary=\"BB\"\n\n--BB\nContent-Type: text/plain\n\nhi\n--BB\n\
                       Content-Type: application/octet-stream\n\
                       Content-Transfer-Encoding: base64\n\nTUVNQkVSUEFZTE9BRA==\n--BB--\n";
        let at = (size - (4 << 10)) / line.len() * line.len();
        text[at..at + message.len()].copy_from_slice(message.as_bytes());
        let mut l = loader::Builder::new();
        l.add_named_bytes("a.ndb", b"Sig.Msg:0:0:4d454d4245525041594c4f4144\n", true);
        let db = l.build().unwrap();
        let opts = ScanOptions {
            object_cache_bytes: 8 << 20,
            object_cache_block_bytes: 64 << 10,
            ..holding(1 << 20)
        };
        let report = scan_seekable(&db, Cursor::new(text), size as u64, &opts).unwrap();
        assert!(
            matches!(report.verdict, Verdict::Infected { .. }),
            "{:?}",
            report.verdict
        );
    }

    /// The headers of a message with none of its parts, inside a text read as
    /// it streams, are not reported as a part left unread: the text was scanned
    /// whole.
    #[cfg(feature = "email")]
    #[test]
    fn the_headers_of_a_message_inside_a_streamed_text_are_not_reported() {
        let size = 12 << 20;
        let line = b"the quick brown fox jumps over the lazy dog\n";
        let mut text: Vec<u8> = line.iter().copied().cycle().take(size).collect();
        let headers = "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"BB\"\n\n";
        let at = (size - (4 << 10)) / line.len() * line.len();
        text[at..at + headers.len()].copy_from_slice(headers.as_bytes());
        let mut l = loader::Builder::new();
        l.add_named_bytes("a.ndb", b"Sig.Msg:0:0:4d454d4245525041594c4f4144\n", true);
        let db = l.build().unwrap();
        // The text views of a file this size are read from a spill.
        let opts = ScanOptions {
            object_cache_bytes: 8 << 20,
            object_cache_block_bytes: 64 << 10,
            spill: Some(std::sync::Arc::new(unpack::spill::MemSpill::new())),
            ..holding(1 << 20)
        };
        let report = scan_seekable(&db, Cursor::new(text), size as u64, &opts).unwrap();
        assert_eq!(report.verdict, Verdict::Clean);
    }

    /// The size of the cache of an object read in place and of its blocks are
    /// the scan's: a cache past the object serves the later reads of it from
    /// memory, and a smaller block is more reads of the source.
    #[test]
    fn the_object_cache_follows_the_options() {
        use std::sync::atomic::{AtomicU64, Ordering};
        struct Tally(Cursor<Vec<u8>>, std::sync::Arc<(AtomicU64, AtomicU64)>);
        impl std::io::Read for Tally {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.read(buf)?;
                self.1.0.fetch_add(n as u64, Ordering::Relaxed);
                self.1.1.fetch_add(1, Ordering::Relaxed);
                Ok(n)
            }
        }
        impl std::io::Seek for Tally {
            fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
                self.0.seek(p)
            }
        }
        // Noise with no magic, a hash signature of its size: detection, the
        // digests and the sweep are served by one read of it. A signature
        // whose first literal sits near the start and whose second never
        // occurs sends a search through the rest of the object once the sweep
        // is over: the read that a cache smaller than the object cannot serve
        // from memory.
        let size = 12 << 20;
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut noise: Vec<u8> = (0..size)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect();
        for w in 0..noise.len() - 1 {
            if matches!(
                &noise[w..w + 2],
                b"MZ" | b"PK" | b"7z" | b"BZ" | b"\x1f\x8b" | b"Ra" | b"MS"
            ) {
                noise[w] ^= 0x80;
            }
        }
        noise[1 << 20..(1 << 20) + 10].copy_from_slice(b"\x0b\xad\xc0\xde\x0b\xad\xf0\x0d\x0b\xad");
        let mut l = loader::Builder::new();
        l.add_named_bytes(
            "a.ndb",
            b"Sig.Pat:0:*:0badc0de0badf00d0bad*5eadbeef5eadbeefcafe\n",
            true,
        );
        let hdb = format!("0123456789abcdef0123456789abcdef:{size}:Sig.Hash\n");
        l.add_named_bytes("c.hdb", hdb.as_bytes(), true);
        let db = l.build().unwrap();
        // (bytes read from the source, reads of it) for a scan.
        let reads = |cache: u64, block: u64| {
            let tally = std::sync::Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
            let opts = ScanOptions {
                object_cache_bytes: cache,
                object_cache_block_bytes: block,
                ..holding(1 << 20)
            };
            let reader = Tally(Cursor::new(noise.clone()), tally.clone());
            let report = scan_seekable(&db, reader, size as u64, &opts).unwrap();
            assert_eq!(report.verdict, Verdict::Clean);
            (
                tally.0.load(Ordering::Relaxed),
                tally.1.load(Ordering::Relaxed),
            )
        };
        let (small, small_reads) = reads(8 << 20, 64 << 10);
        let (big, _) = reads(16 << 20, 64 << 10);
        // Smaller than the object: the parts the cache cannot keep across
        // passes are read again.
        assert!(small > size as u64 * 5 / 4, "{small}");
        assert!(big <= size as u64 + (1 << 20), "{big}");
        let (_, fine_reads) = reads(8 << 20, 4 << 10);
        assert!(
            fine_reads > 8 * small_reads,
            "{fine_reads} vs {small_reads}"
        );
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A marker in the start of an object types it, held or streamed. Past
    /// the start, detection does not read it and the object keeps its type.
    #[cfg(feature = "all-formats")]
    #[test]
    fn a_marker_types_an_object_in_its_start_only() {
        let needle = b"needle in the mail";
        // A message told by its MIME headers: it does not start with one of the
        // headers that type a message by themselves.
        let mut mail =
            b"Content-Type: text/plain\r\nMIME-Version: 1.0\r\nSubject: hi\r\n\r\n".to_vec();
        mail.extend_from_slice(needle);
        // Longer than the start that detection reads.
        mail.resize(5 << 20, b'.');
        // A compiled AutoIt script's marker after its GUID types such a
        // message as AutoIt.
        let script = |at: usize| {
            let mut m = mail.clone();
            let marker = [
                &[
                    0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86,
                    0xD6, 0x48, 0x7D,
                ][..],
                b"AU3!EA06",
            ]
            .concat();
            m.splice(at..at, marker);
            m
        };
        let near = script(1 << 20);
        let far = script(mail.len());
        let mut l = loader::Builder::new();
        let sig = format!("Sig.Mail;Engine:51-255,Target:4;0;{}\n", hex_of(needle));
        l.add_named_bytes("a.ldb", sig.as_bytes(), true);
        let db = l.build().unwrap();
        let opts = holding(1 << 20);
        let streamed = |data: &[u8]| {
            scan_seekable(&db, Cursor::new(data.to_vec()), data.len() as u64, &opts)
                .unwrap()
                .verdict
        };
        let held = |data: &[u8]| analyze(&db, data, &opts).verdict;
        let name = |v: &Verdict| match v {
            Verdict::Infected { signature, .. } => Some(signature.clone()),
            _ => None,
        };
        // A mail, with the marker past its start too: its target applies,
        // held or not.
        for data in [&mail, &far] {
            assert_eq!(name(&held(data)).as_deref(), Some("Sig.Mail"));
            assert_eq!(name(&streamed(data)).as_deref(), Some("Sig.Mail"));
        }
        // With the marker in the start it is a compiled script, which no mail
        // signature applies to. Streamed, its format is not read (it is over
        // the limit), and the scan says so.
        let want = held(&near);
        assert_eq!(name(&want), None, "{want:?}");
        let got = streamed(&near);
        assert!(matches!(got, Verdict::LimitsExceeded { .. }), "{got:?}");
    }

    /// What the engine's run in the read of a streamed object leaves in the
    /// scan (a check that did not run to the end) is kept only if the
    /// matching core takes the answer: an object cleared by the allowlist
    /// before it is not made incomplete by a check it never used.
    #[test]
    fn an_allowlisted_object_is_not_made_incomplete_by_the_read() {
        use md5::{Digest, Md5};
        // Not text, so that no view of text is made and skipped.
        let mut data = vec![0u8; 3 << 20];
        data[100..107].copy_from_slice(b"TRIGGER");
        data[107..111].copy_from_slice(b"abab");
        let size = data.len();
        // A regular expression with a back reference needs the object whole,
        // which a scan that holds 1 MiB at most cannot give it.
        let sig = format!(
            "Sig.Backref;Engine:81-255,Target:0;0&1;{};0/(ab)\\1/\n",
            hex_of(b"TRIGGER")
        );
        let build = |allow: bool| {
            let mut l = loader::Builder::new();
            l.add_named_bytes("a.ldb", sig.as_bytes(), true);
            if allow {
                let fp = format!("{}:{size}:Some.Good\n", hex_of(&Md5::digest(&data)));
                l.add_named_bytes("b.fp", fp.as_bytes(), true);
            }
            l.build().unwrap()
        };
        let opts = holding(1 << 20);
        let run = |db: &Scanner| {
            scan_seekable(db, Cursor::new(data.clone()), size as u64, &opts)
                .unwrap()
                .verdict
        };
        // The check did not run, and the scan says so.
        assert!(
            matches!(run(&build(false)), Verdict::LimitsExceeded { .. }),
            "control"
        );
        assert_eq!(run(&build(true)), Verdict::Clean);
    }

    /// A source that reads on without end and measures itself as empty (a
    /// character device such as `/dev/zero`) is an error, not a clean scan of
    /// nothing.
    #[test]
    fn a_source_with_no_length_is_an_error_not_a_clean_scan() {
        struct Endless;
        impl std::io::Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                buf.fill(0);
                Ok(buf.len())
            }
        }
        impl std::io::Seek for Endless {
            fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
                Ok(0)
            }
        }
        let opts = holding(4096);
        let e = scan_seekable(&Scanner::builtin(), Endless, 0, &opts).unwrap_err();
        assert!(e.to_string().contains("not a file with a length"), "{e}");
        let e = analyze_all_seekable(&Scanner::builtin(), Endless, 0, &opts).unwrap_err();
        assert!(e.to_string().contains("not a file with a length"), "{e}");
        // A file that grew while it was read is still scanned as what it is.
        let big = std::io::Cursor::new(vec![b'a'; 10_000]);
        assert!(scan_seekable(&Scanner::builtin(), big, 100, &opts).is_ok());
    }

    /// A read that fails part way through an object read in place: a
    /// detection before it is the answer, and with none the scan is an error.
    #[test]
    fn a_detection_before_a_failed_read_is_kept() {
        struct FailsAfter(Cursor<Vec<u8>>, u64);
        impl Read for FailsAfter {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let room = self.1.saturating_sub(self.0.position());
                if room == 0 {
                    return Err(io::Error::other("the disk went away"));
                }
                let n = buf.len().min(room as usize);
                self.0.read(&mut buf[..n])
            }
        }
        impl Seek for FailsAfter {
            fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
                self.0.seek(to)
            }
        }
        let mut data = eicar().to_vec();
        data.resize(4 << 20, b'.');
        let size = data.len() as u64;
        let opts = holding(4096);
        let db = Scanner::builtin();
        let reader = |d: &[u8]| FailsAfter(Cursor::new(d.to_vec()), 1 << 20);
        let report = scan_seekable(&db, reader(&data), size, &opts).unwrap();
        assert!(
            matches!(report.verdict, Verdict::Infected { .. }),
            "{:?}",
            report.verdict
        );
        let (names, outcome) = analyze_all_seekable(&db, reader(&data), size, &opts).unwrap();
        assert!(!names.is_empty());
        assert!(
            matches!(outcome, AllMatchOutcome::Unscannable(_)),
            "{outcome:?}"
        );
        let clean = vec![b'.'; data.len()];
        assert!(scan_seekable(&db, reader(&clean), size, &opts).is_err());
        assert!(analyze_all_seekable(&db, reader(&clean), size, &opts).is_err());
    }

    /// A descriptor passed over a socket shares its offset with the sender: an
    /// input is scanned from its start wherever its reader was left.
    #[test]
    fn a_seekable_input_is_read_from_its_start() {
        let db = Scanner::builtin();
        let size = eicar().len() as u64;
        let at_end = || {
            let mut c = Cursor::new(eicar().to_vec());
            c.set_position(size);
            c
        };
        for opts in [ScanOptions::default(), holding(16)] {
            let report = scan_seekable(&db, at_end(), size, &opts).unwrap();
            assert!(
                matches!(report.verdict, Verdict::Infected { .. }),
                "{:?}",
                report.verdict
            );
            let (found, _) = analyze_all_seekable(&db, at_end(), size, &opts).unwrap();
            assert!(!found.is_empty());
        }
    }

    /// The one read of a streamed object finds what each step's own read of
    /// it would, whichever step asks first.
    #[test]
    fn one_read_serves_every_step() {
        use byte_source::CHUNK;
        // Longer than the start detection reads.
        let mut data = vec![b'.'; (5 << 20) + 77];
        let mut pe = b"MZ".to_vec();
        pe.resize(0x3c, 0);
        pe.extend_from_slice(&0x40u32.to_le_bytes());
        pe.extend_from_slice(b"PE\0\0\x4c\x01\x03\0");
        pe.resize(0x40 + 20, 0);
        pe.extend_from_slice(&0xe0u16.to_le_bytes());
        pe.extend_from_slice(&[0, 0, 0x0b, 0x01]);
        let mut elf = b"\x7fELF\x02\x01\x01".to_vec();
        elf.resize(16, 0);
        elf.extend_from_slice(&2u16.to_le_bytes());
        let mut put = |at: usize, bytes: &[u8]| data[at..at + bytes.len()].copy_from_slice(bytes);
        put(0, &pe);
        put(CHUNK - 1, &pe);
        put(2 * CHUNK - 3, &elf);
        put(3 * CHUNK - 5, b"7z\xbc\xaf\x27\x1c");
        put(4 * CHUNK - 2, b"PK\x03\x04");
        put(
            5 * CHUNK - 19,
            &[
                0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6,
                0x48, 0x7D, b'A', b'U', b'3', b'!', b'E', b'A', b'0', b'6',
            ],
        );
        // A UPX pack header whose fields lie across the seam of a window (the
        // bare layout: the method at +10, the sizes at +20 and +24).
        let upx = 2 * CHUNK - 20;
        put(upx + 4, b"UPX!");
        put(upx + 10, &[2]);
        put(upx + 20, &100u32.to_le_bytes());
        put(upx + 24, &100u32.to_le_bytes());
        let mut without_upx = data.clone();
        without_upx[upx + 10] = 0;
        let size = data.len();
        let mut l = loader::Builder::new();
        let hdb = format!("0123456789abcdef0123456789abcdef:{size}:Sig.Hash\n");
        l.add_named_bytes("a.hdb", hdb.as_bytes(), true);
        let hsb = format!("{}:{size}:Sig.Sha\n", "ab".repeat(32));
        l.add_named_bytes("b.hsb", hsb.as_bytes(), true);
        let db = l.build().unwrap();

        let slice: &[u8] = &data;
        let want_fmt = unpack::detect(&slice);
        let want_embedded = pe::embedded_in(&slice, pe::CarveCaps::default());
        let want_digests = hashes::digests_wanted(&slice, digests_wanted_by(&db, size as u64));
        // Found in the start, in a build that has it.
        #[cfg(feature = "all-formats")]
        assert_eq!(want_fmt, Some(unpack::Format::Autoit));
        assert!(!want_embedded.pe.is_empty() && !want_embedded.archives.is_empty());
        assert!(want_digests.md5.is_some() && want_digests.sha256.is_some());
        // The search for a UPX header and the byte counts of the static model.
        assert!(pe::upx_header_in(&slice) || !pe::upx_compiled_in());
        assert!(!pe::upx_header_in(&&without_upx[..]));
        let mut want_counts = [0u64; 256];
        data.iter().for_each(|&b| want_counts[b as usize] += 1);
        let heuristics = ScanOptions {
            heuristics: true,
            ..ScanOptions::default()
        };
        for first in 0..5 {
            let cache =
                byte_source::BlockCache::with_sizes(Cursor::new(data.clone()), 4093, 16 * 4093)
                    .unwrap();
            let facts = Facts::for_scan(&cache, &db, true, &heuristics);
            let mut embedded = None;
            for step in (0..5).map(|k| (first + k) % 5) {
                match step {
                    0 => assert_eq!(facts.format(), want_fmt, "first {first}"),
                    1 => embedded = Some(facts.embedded()),
                    3 => assert_eq!(facts.upx_header(), pe::upx_compiled_in(), "first {first}"),
                    4 => assert_eq!(facts.byte_counts(), Some(&want_counts), "first {first}"),
                    _ => {
                        let d = facts.digests(&db);
                        let w = &want_digests;
                        assert_eq!(
                            (&d.md5, &d.sha1, &d.sha256),
                            (&w.md5, &w.sha1, &w.sha256),
                            "first {first}"
                        );
                    }
                }
            }
            let got = embedded.unwrap();
            assert_eq!(
                (got.pe, got.elf, got.macho, got.archives),
                (
                    want_embedded.pe.clone(),
                    want_embedded.elf.clone(),
                    want_embedded.macho.clone(),
                    want_embedded.archives.clone()
                ),
                "first {first}"
            );
        }
        // No header, no UPX; and an object that is not an executable has
        // neither searched.
        let cache =
            byte_source::BlockCache::with_sizes(Cursor::new(without_upx), 4093, 16 * 4093).unwrap();
        let facts = Facts::for_scan(&cache, &db, true, &heuristics);
        assert!(!facts.upx_header());
        assert!(facts.byte_counts().is_some());
        let mut text = data.clone();
        text[..2].copy_from_slice(b"..");
        let cache =
            byte_source::BlockCache::with_sizes(Cursor::new(text), 4093, 16 * 4093).unwrap();
        let facts = Facts::for_scan(&cache, &db, true, &heuristics);
        assert!(facts.byte_counts().is_none());
        assert!(facts.upx.get().is_none());
    }

    /// A step that needs no read of a streamed object does not start the one
    /// read for the others: no digest wanted at its size, or an object
    /// detection holds whole in the start it reads anyway.
    #[test]
    fn a_step_that_needs_no_read_makes_none() {
        use std::sync::atomic::{AtomicU64, Ordering};
        // An allowlist entry at another size: the allowlist is asked, and
        // wants no digest.
        let mut l = loader::Builder::new();
        l.add_named_bytes(
            "a.fp",
            b"fedcba9876543210fedcba9876543210:12345:Some.Good\n",
            true,
        );
        let db = l.build().unwrap();
        for len in [1 << 20, 5 << 20] {
            let read = std::sync::Arc::new(AtomicU64::new(0));
            let reader = Counting(Cursor::new(vec![b'.'; len]), read.clone());
            let cache = byte_source::BlockCache::with_sizes(reader, 4093, 16 * 4093).unwrap();
            let facts = Facts::for_scan(&cache, &db, false, &ScanOptions::default());
            let before = read.load(Ordering::Relaxed);
            assert!(!allowlisted(&db, &facts));
            assert_eq!(
                read.load(Ordering::Relaxed),
                before,
                "{len}: the allowlist read it"
            );
            facts.format();
            let passes = (read.load(Ordering::Relaxed) - before) as f64 / len as f64;
            // Its start and its end: never all of it, and nothing twice.
            assert!(
                passes <= 1.1,
                "{len}: detection read it {passes:.2} times over"
            );
        }
    }

    /// The hits the engine sets aside until its sweep ends, and the regex
    /// searches, are bounded by settings: the object cache, a quarter of its
    /// block, and the step budget.
    #[test]
    fn the_engine_limits_come_from_the_options() {
        let mut opts = ScanOptions {
            object_cache_bytes: 7 << 20,
            object_cache_block_bytes: 1 << 20,
            max_regex_steps: Some(5),
            max_matcher_steps: Some(3),
            ..ScanOptions::default()
        };
        // The step the options document.
        assert_eq!(fancy_regex::STEP_BYTES, 32);
        let whole = whole_limits(&opts);
        assert_eq!(whole.deferred_bytes, 7 << 20);
        assert_eq!(whole.search_bytes, 7 << 20);
        assert_eq!(whole.near_reach, 1 << 18);
        assert_eq!(whole.regex_steps, 5);
        opts.max_regex_steps = None;
        assert_eq!(whole_limits(&opts).regex_steps, usize::MAX);
        assert_eq!(whole.matcher_steps, Some(3));
        opts.max_matcher_steps = None;
        assert_eq!(whole_limits(&opts).matcher_steps, None);
    }

    #[test]
    fn verdict_classification_is_single_source_of_truth() {
        let cases = [
            (Verdict::Clean, VerdictCategory::Clean, "OK", None),
            (
                Verdict::Infected {
                    signature: "Win.Test".into(),
                    offset: 0,
                    method: Method::Pattern,
                },
                VerdictCategory::Infected,
                "FOUND",
                Some("Win.Test"),
            ),
            (
                Verdict::LimitsExceeded {
                    reason: "too big".into(),
                },
                VerdictCategory::Partial,
                "LIMITS-EXCEEDED",
                Some("too big"),
            ),
            (
                Verdict::Unscannable {
                    reason: "rar ppmd".into(),
                },
                VerdictCategory::Partial,
                "UNSCANNABLE",
                Some("rar ppmd"),
            ),
            (
                Verdict::PasswordProtected {
                    reason: "encrypted".into(),
                },
                VerdictCategory::Partial,
                "PASSWORD-PROTECTED",
                Some("encrypted"),
            ),
        ];
        for (v, cat, tag, detail) in cases {
            assert_eq!(v.category(), cat, "category for {v:?}");
            assert_eq!(v.status_tag(), tag, "tag for {v:?}");
            assert_eq!(v.detail(), detail, "detail for {v:?}");
        }
    }

    #[test]
    #[cfg(any(feature = "zip", feature = "all-formats"))]
    fn ooxml_subtype_detection() {
        use engine::ClType;
        // A ZIP whose central directory names the OOXML package descriptor plus
        // the Word main part is typed as OOXML_WORD (not plain ZIP).
        let docx = build_zip(&[
            ("[Content_Types].xml", b"<Types/>".as_ref()),
            ("word/document.xml", b"<doc/>"),
        ]);
        assert_eq!(
            container_cltype(unpack::Format::Zip, &docx),
            Some(ClType::OoxmlWord)
        );
        let xlsx = build_zip(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("xl/workbook.xml", b"<wb/>"),
        ]);
        assert_eq!(
            container_cltype(unpack::Format::Zip, &xlsx),
            Some(ClType::OoxmlXl)
        );
        // A plain ZIP (no OOXML package descriptor) stays CL_TYPE_ZIP.
        let plain = build_zip(&[("readme.txt", b"hello")]);
        assert_eq!(
            container_cltype(unpack::Format::Zip, &plain),
            Some(ClType::Zip)
        );
        // Non-ZIP containers map to their fixed types.
        assert_eq!(
            container_cltype(unpack::Format::Email, b""),
            Some(ClType::Mail)
        );
    }

    /// The package is told by the members of its central directory, not by
    /// names that appear elsewhere in the bytes.
    #[test]
    #[cfg(any(feature = "zip", feature = "all-formats"))]
    fn ooxml_subtype_is_told_by_the_directory() {
        use engine::ClType;
        let sub = |zip: &Vec<u8>| container_cltype(unpack::Format::Zip, zip);
        let word = [
            ("[Content_Types].xml", &b"<Types/>"[..]),
            ("word/document.xml", b"<d/>"),
        ];
        // The member order is the writer's.
        let props_first = zip_bytes(&[
            ("docProps/app.xml", b"<p/>", true),
            ("[Content_Types].xml", b"<Types/>", true),
            ("word/document.xml", b"<d/>", true),
        ]);
        assert_eq!(sub(&props_first), Some(ClType::OoxmlWord));
        let deck = zip_bytes(&[
            ("[Content_Types].xml", b"<Types/>", true),
            ("ppt/presentation.xml", b"<p/>", true),
        ]);
        assert_eq!(sub(&deck), Some(ClType::OoxmlPpt));
        let both = zip_bytes(&[
            ("[Content_Types].xml", b"<Types/>", true),
            ("xl/workbook.xml", b"<w/>", true),
            ("word/document.xml", b"<d/>", true),
        ]);
        assert_eq!(sub(&both), Some(ClType::OoxmlWord));
        // Part names written in a member's data name no member.
        let quoted = zip_bytes(&[("notes.txt", b"[Content_Types].xml word/document.xml", true)]);
        assert_eq!(sub(&quoted), Some(ClType::Zip));
        // Nor does a directory that will not open give any.
        let mut cut = zip_bytes(&word.map(|(n, d)| (n, d, true)));
        cut.truncate(cut.len() - 30);
        assert_eq!(sub(&cut), Some(ClType::Zip));
        // A part deeper in the tree is not the main part.
        let deeper = zip_bytes(&[
            ("[Content_Types].xml", b"<Types/>", true),
            ("backup/word/document.xml", b"<d/>", true),
        ]);
        assert_eq!(sub(&deeper), Some(ClType::Zip));
        // A binary workbook has the workbook part of its own.
        let binary = zip_bytes(&[
            ("[Content_Types].xml", b"<Types/>", true),
            ("xl/workbook.bin", b"\0", true),
        ]);
        assert_eq!(sub(&binary), Some(ClType::OoxmlXl));
    }

    fn build_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
        use exav_unpack::zip_write::{FileOptions, ZipWriter};
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in members {
            w.start_file(name, FileOptions::default()).unwrap();
            std::io::Write::write_all(&mut w, body).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    /// As [`build_zip`], with every member deflated.
    #[cfg(any(feature = "zip", feature = "all-formats"))]
    fn build_zip_deflated(members: &[(&str, &[u8])]) -> Vec<u8> {
        use exav_unpack::zip_write::{FileOptions, Method, ZipWriter};
        let opts = FileOptions::default().method(Method::Deflated);
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in members {
            w.start_file(name, opts).unwrap();
            std::io::Write::write_all(&mut w, body).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    /// A database built from loose signature files, `(file name, contents)`.
    fn db_from(files: &[(&str, &str)]) -> Scanner {
        let mut b = loader::Builder::new();
        for (name, text) in files {
            b.add_named_bytes(name, text.as_bytes(), false);
        }
        b.build().unwrap()
    }

    fn seekable(db: &Scanner, data: &[u8], opts: &ScanOptions) -> Verdict {
        scan_seekable(db, Cursor::new(data), data.len() as u64, opts)
            .unwrap()
            .verdict
    }

    fn infected_as(v: &Verdict) -> Option<&str> {
        match v {
            Verdict::Infected { signature, .. } => Some(signature),
            _ => None,
        }
    }

    /// A YARA rule is named like any other signature: `.UNOFFICIAL` only when
    /// the scan asks for ClamAV's naming, and an ignored rule does not hide the
    /// next one that matches.
    #[test]
    #[cfg(feature = "yara")]
    fn yara_names_follow_the_scan_options() {
        let rules = "rule first { strings: $a = \"yaramarker\" condition: $a }\n\
                     rule second { strings: $a = \"yaramarker\" condition: $a }\n";
        let db = db_from(&[("r.yar", rules)]);
        let data = b"xx yaramarker xx";
        let compat = ScanOptions {
            unofficial_suffix: true,
            ..ScanOptions::default()
        };
        let opts = ScanOptions::default();
        assert_eq!(
            infected_as(&analyze(&db, data, &opts).verdict),
            Some("YARA.first")
        );
        assert_eq!(
            seekable(&db, data, &opts),
            analyze(&db, data, &opts).verdict
        );
        assert_eq!(
            infected_as(&analyze(&db, data, &compat).verdict),
            Some("YARA.first.UNOFFICIAL")
        );
        let all: Vec<String> = analyze_all(&db, data, &opts)
            .into_iter()
            .map(|h| h.0)
            .collect();
        assert!(all.contains(&"YARA.first".to_string()), "{all:?}");
        assert!(all.contains(&"YARA.second".to_string()), "{all:?}");

        let db = db_from(&[("r.yar", rules), ("r.ign2", "YARA.first\n")]);
        assert_eq!(
            infected_as(&analyze(&db, data, &opts).verdict),
            Some("YARA.second")
        );
        let all: Vec<String> = analyze_all(&db, data, &opts)
            .into_iter()
            .map(|h| h.0)
            .collect();
        assert_eq!(all, ["YARA.second"]);
    }

    /// A YARA condition that runs out of evaluation steps did not decide
    /// anything, so the scan is incomplete rather than clean.
    #[test]
    #[cfg(feature = "yara")]
    fn a_yara_rule_out_of_steps_is_not_a_clean_scan() {
        let rules = "rule endless { condition: for all i in (0..100000000) : ( i >= 0 ) }\n";
        let db = db_from(&[("r.yar", rules)]);
        let opts = ScanOptions::default();
        let data = b"just some text";
        for v in [
            analyze(&db, data, &opts).verdict,
            seekable(&db, data, &opts),
        ] {
            assert!(matches!(v, Verdict::LimitsExceeded { .. }), "{v:?}");
        }
    }

    /// A top-level archive gets the full matching core over its own bytes, as
    /// it does when nested in another archive. The wildcard signature matches
    /// only a member NAME, i.e. the raw container; the hash is the container's.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn a_top_level_container_gets_the_full_engine_over_its_own_bytes() {
        let zip = build_zip(&[("payload_marker.txt", b"nothing to see here")]);
        let wild = db_from(&[("w.ndb", "Test.ZipName:0:*:7061796c6f6164??6d61726b6572\n")]);
        let d = digests_of(&zip);
        let hash = db_from(&[(
            "h.hdb",
            &format!("{}:{}:Test.ZipHash\n", d.md5_hex(), zip.len()),
        )]);
        let opts = ScanOptions::default();

        assert_eq!(
            infected_as(&seekable(&wild, &zip, &opts)),
            Some("Test.ZipName")
        );
        assert_eq!(
            infected_as(&seekable(&hash, &zip, &opts)),
            Some("Test.ZipHash")
        );

        let dir = crate::tmpfile::TempDir::new().unwrap();
        let path = dir.path().join("t.zip");
        std::fs::write(&path, &zip).unwrap();
        let on_disk = scan_path(&wild, &path, &opts).unwrap().verdict;
        assert_eq!(infected_as(&on_disk), Some("Test.ZipName"));

        // A logical signature and a YARA rule over the same name: in the
        // container's bytes only, never in its member's.
        let ldb = db_from(&[(
            "l.ldb",
            "Test.ZipLdb;Engine:51-255,Target:0;0&1;7061796c6f6164;6d61726b6572\n",
        )]);
        assert_eq!(
            infected_as(&seekable(&ldb, &zip, &opts)),
            Some("Test.ZipLdb")
        );
        assert_eq!(
            infected_as(&scan_path(&ldb, &path, &opts).unwrap().verdict),
            Some("Test.ZipLdb")
        );
        #[cfg(feature = "yara")]
        {
            let yara = db_from(&[(
                "r.yar",
                "rule zip_name { strings: $a = \"payload_marker\" condition: $a }\n",
            )]);
            assert_eq!(
                infected_as(&seekable(&yara, &zip, &opts)),
                Some("YARA.zip_name")
            );
        }
    }

    /// A detection in a member stored in an archive is the member's, at any
    /// depth: the members are scanned before the container's own bytes, which
    /// hold the same bytes stored.
    #[test]
    #[cfg(any(feature = "zip", feature = "all-formats"))]
    fn a_stored_member_is_attributed_to_itself_at_any_depth() {
        let stored = |name: &str, body: &[u8]| zip_bytes(&[(name, body, true)]);
        let inner = stored("eicar.txt", eicar());
        let outer = stored("inner.zip", &inner);
        let db = Scanner::builtin();
        let opts = ScanOptions::default();
        for (data, want) in [(&inner, "eicar.txt"), (&outer, "inner.zip/eicar.txt")] {
            let (r, loc) =
                scan_seekable_located(&db, Cursor::new(data), data.len() as u64, &opts).unwrap();
            assert!(matches!(r.verdict, Verdict::Infected { .. }), "{r:?}");
            assert_eq!(loc.as_deref(), Some(want));
        }
    }

    /// An ignored signature is passed over, not stopped at: a real detection in
    /// a later member must still be found, in memory and through a reader alike.
    #[test]
    #[cfg(any(feature = "zip", feature = "all-formats"))]
    fn an_ignored_signature_does_not_hide_a_later_member() {
        let db = db_from(&[
            ("a.ndb", "Test.Noisy:0:*:6e6f697379626974\n"),
            ("a.ign2", "Test.Noisy\n"),
        ]);
        // Padding makes the deflater emit Huffman-coded blocks rather than
        // stored ones, which would leave the member bytes readable raw.
        let pad = |core: &[u8]| [&[b'.'; 4096][..], core, &[b'.'; 4096][..]].concat();
        let noisy = pad(b"xx noisybit xx");
        let payload = pad(eicar());
        let zip = build_zip_deflated(&[("a.txt", &noisy), ("b.txt", &payload)]);
        // Only the member walk can find them, not the pass over the raw bytes.
        assert!(!contains_window(&zip, b"noisybit") && !contains_window(&zip, eicar()));
        let opts = ScanOptions::default();
        for v in [
            analyze(&db, &zip, &opts).verdict,
            seekable(&db, &zip, &opts),
        ] {
            assert_eq!(infected_as(&v), Some("Eicar-Test-Signature"), "{v:?}");
        }
        // And on its own the ignored match is no detection at all.
        let quiet = build_zip_deflated(&[("a.txt", &noisy)]);
        assert_eq!(seekable(&db, &quiet, &opts), Verdict::Clean);

        // Both in one buffer: the matcher itself has to pass over the ignored
        // hit, since a first-match scan would otherwise stop there.
        let mut both = b"noisybit ".to_vec();
        both.extend_from_slice(eicar());
        assert_eq!(
            infected_as(&analyze(&db, &both, &opts).verdict),
            Some("Eicar-Test-Signature")
        );

        // The same through a detection that is not a byte match: a `.cdb`
        // member-name signature on the first member.
        let db = db_from(&[
            ("c.cdb", "Test.CdbName:CL_TYPE_ZIP:*:a\\.txt:*:*:*:*:*:\n"),
            ("c.ign2", "Test.CdbName\n"),
        ]);
        for v in [
            analyze(&db, &zip, &opts).verdict,
            seekable(&db, &zip, &opts),
        ] {
            assert_eq!(infected_as(&v), Some("Eicar-Test-Signature"), "{v:?}");
        }

        // `.ign`'s `db:line:name` form, and the scan of a path.
        let db = db_from(&[
            ("a.ndb", "Test.Noisy:0:*:6e6f697379626974\n"),
            ("a.ign", "a.ndb:1:Test.Noisy\n"),
        ]);
        for v in [
            analyze(&db, &zip, &opts).verdict,
            seekable(&db, &zip, &opts),
        ] {
            assert_eq!(infected_as(&v), Some("Eicar-Test-Signature"), "{v:?}");
        }
        // No temp directory under WASI.
        #[cfg(not(target_family = "wasm"))]
        {
            let dir = crate::tmpfile::TempDir::new().unwrap();
            let path = dir.path().join("t.zip");
            std::fs::write(&path, &zip).unwrap();
            let v = scan_path(&db, &path, &opts).unwrap().verdict;
            assert_eq!(infected_as(&v), Some("Eicar-Test-Signature"), "{v:?}");
        }
    }

    /// An all-match scan lists every detection in an object too large to
    /// hold, as in one held whole.
    #[test]
    fn all_matches_lists_every_detection_past_the_object_limit() {
        let db = db_from(&[
            ("a.ndb", "Test.One:0:*:6f6e656d61726b6572\n"),
            ("b.ndb", "Test.Two:0:*:74776f6d61726b6572\n"),
        ]);
        let mut data = b"xx onemarker xx".to_vec();
        data.resize(512 * 1024, b' ');
        data.extend_from_slice(b"xx twomarker xx");
        let opts = holding(4096);
        let (all, _) =
            analyze_all_seekable(&db, Cursor::new(&data), data.len() as u64, &opts).unwrap();
        let mut names: Vec<_> = all.iter().map(|(n, _)| n.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["Test.One", "Test.Two"]);
    }

    /// YARA's filename externals are set for a top-level archive, under a
    /// first-match scan and under `--all-matches` alike.
    #[test]
    #[cfg(all(feature = "yara", any(feature = "zip", feature = "all-formats")))]
    fn yara_sees_a_top_level_archives_name() {
        let db = db_from(&[(
            "r.yar",
            "rule by_ext { condition: extension == \".zip\" }\n",
        )]);
        let zip = build_zip(&[("a.txt", b"nothing")]);
        let opts = ScanOptions {
            filename: Some("/srv/in/t.zip".to_string()),
            ..ScanOptions::default()
        };
        assert_eq!(
            infected_as(&seekable(&db, &zip, &opts)),
            Some("YARA.by_ext")
        );
        let (all, _) =
            analyze_all_seekable(&db, Cursor::new(&zip), zip.len() as u64, &opts).unwrap();
        assert!(all.iter().any(|(n, _)| n == "YARA.by_ext"), "{all:?}");
        assert_eq!(seekable(&db, &zip, &ScanOptions::default()), Verdict::Clean);
        // A file scanned by its path is named by it, in both modes.
        let dir = std::env::temp_dir().join(format!("exav-yara-name-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.zip");
        std::fs::write(&path, &zip).unwrap();
        let plain = ScanOptions::default();
        let first = scan_path(&db, &path, &plain).unwrap().verdict;
        let (all, _) = analyze_all_path(&db, &path, &plain).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(infected_as(&first), Some("YARA.by_ext"));
        assert!(all.iter().any(|(n, _)| n == "YARA.by_ext"), "{all:?}");
    }

    /// `--detect packed` names the packer of an image a packer reader could
    /// not unpack; an archive member named like one is only a name.
    #[test]
    #[cfg(feature = "all-formats")]
    fn the_packed_heuristic_reads_only_a_packer_readers_members() {
        let opts = ScanOptions {
            alert_packed: true,
            ..ScanOptions::default()
        };
        let db = Scanner::builtin();
        // A PE whose sections are ASPack's, which exav does not unpack.
        let (lfanew, opt_size) = (0x80, 0xe0);
        let table = lfanew + 24 + opt_size;
        let mut pe = vec![0u8; 0x400];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(lfanew as u32).to_le_bytes());
        pe[lfanew..lfanew + 4].copy_from_slice(b"PE\0\0");
        pe[lfanew + 4..lfanew + 6].copy_from_slice(&0x14c_u16.to_le_bytes());
        pe[lfanew + 6..lfanew + 8].copy_from_slice(&2u16.to_le_bytes());
        pe[lfanew + 20..lfanew + 22].copy_from_slice(&(opt_size as u16).to_le_bytes());
        pe[lfanew + 24..lfanew + 26].copy_from_slice(&0x10b_u16.to_le_bytes());
        pe[lfanew + 40..lfanew + 44].copy_from_slice(&0x1000_u32.to_le_bytes());
        for (i, name) in [&b".aspack"[..], b".adata"].into_iter().enumerate() {
            let s = table + i * 40;
            pe[s..s + name.len()].copy_from_slice(name);
            pe[s + 8..s + 12].copy_from_slice(&0x1000_u32.to_le_bytes());
            pe[s + 12..s + 16].copy_from_slice(&(0x1000 * (i as u32 + 1)).to_le_bytes());
            pe[s + 16..s + 20].copy_from_slice(&0x200_u32.to_le_bytes());
            pe[s + 20..s + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        }
        assert_eq!(
            infected_as(&analyze(&db, &pe, &opts).verdict),
            Some("Heuristics.Packed.ASPack")
        );
        let zip = build_zip(&[("Evil-packed image", b"nothing")]);
        assert_eq!(analyze(&db, &zip, &opts).verdict, Verdict::Clean);
    }

    /// An image whose pixels would take more than `--max-object-bytes` is not
    /// decoded, and a loaded `fuzzy_img#` signature is then undecided: the
    /// scan is `LIMITS-EXCEEDED`, not clean. A 2000x2000 PNG, 12 MB of pixels
    /// from a few KB, under a 1 MiB limit.
    #[test]
    #[cfg(feature = "image-hash")]
    fn an_image_too_large_to_decode_leaves_a_fuzzy_signature_undecided() {
        let img = image::RgbImage::from_pixel(2000, 2000, image::Rgb([90, 90, 90]));
        let mut png = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut png, image::ImageFormat::Png)
            .unwrap();
        let png = png.into_inner();
        let db = db_from(&[(
            "f.ldb",
            "Test.Fuzzy;Engine:150-255,Target:0;0;fuzzy_img#0123456789abcdef\n",
        )]);
        let opts = holding(1 << 20);
        assert!((png.len() as u64) < opts.limits.max_buffer_bytes);
        assert!(
            matches!(
                analyze(&db, &png, &opts).verdict,
                Verdict::LimitsExceeded { .. }
            ),
            "{:?}",
            analyze(&db, &png, &opts).verdict
        );
        assert_eq!(
            analyze(&db, &png, &ScanOptions::default()).verdict,
            Verdict::Clean
        );
    }

    /// No object is held in memory past `--max-object-bytes`, a container its
    /// format reads whole included: a 40 KB compound file is scanned under the
    /// default limit, and is a limit under a 4 KiB one, through a reader and
    /// in memory alike.
    #[test]
    #[cfg(any(feature = "ole", feature = "all-formats"))]
    fn the_object_limit_also_bounds_a_container_read_whole() {
        use std::io::Write;
        let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        cf.create_stream("/pad")
            .unwrap()
            .write_all(&[b'.'; 20000])
            .unwrap();
        cf.create_stream("/payload")
            .unwrap()
            .write_all(b"harmless")
            .unwrap();
        let ole = cf.into_inner().into_inner();
        let db = Scanner::builtin();
        let opts = ScanOptions::default();
        assert_eq!(seekable(&db, &ole, &opts), Verdict::Clean);
        let opts = holding(4096);
        assert!(opts.limits.max_buffer_bytes < ole.len() as u64);
        for v in [
            seekable(&db, &ole, &opts),
            analyze(&db, &ole, &opts).verdict,
        ] {
            assert!(matches!(v, Verdict::LimitsExceeded { .. }), "{v:?}");
        }
    }

    /// An LHA member in a method there is no decoder for (`-lh9-`) leaves the
    /// archive `UNSCANNABLE`; a detection in another member still wins.
    #[test]
    #[cfg(any(feature = "lha", feature = "all-formats"))]
    fn an_lha_member_nothing_decodes_is_unscannable() {
        // A level-0 member: header size and checksum, then method, sizes,
        // time, attribute, level, name and the content's CRC-16.
        fn member(method: &[u8; 5], name: &[u8], body: &[u8]) -> Vec<u8> {
            let crc = body.iter().fold(0u16, |mut crc, &b| {
                crc ^= b as u16;
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xA001
                    } else {
                        crc >> 1
                    };
                }
                crc
            });
            let mut h = method.to_vec();
            h.extend_from_slice(&(body.len() as u32).to_le_bytes());
            h.extend_from_slice(&(body.len() as u32).to_le_bytes());
            h.extend_from_slice(&[0, 0, 0x21, 0x5a, 0x20, 0]);
            h.push(name.len() as u8);
            h.extend_from_slice(name);
            h.extend_from_slice(&crc.to_le_bytes());
            let sum = h.iter().fold(0u8, |s, &b| s.wrapping_add(b));
            [&[h.len() as u8, sum][..], &h, body].concat()
        }
        let lha = |first: &[u8]| {
            [
                member(b"-lh0-", b"a.txt", first),
                member(b"-lh9-", b"b.txt", b"12345678"),
                vec![0],
            ]
            .concat()
        };
        let db = Scanner::builtin();
        let opts = ScanOptions::default();
        let clean = lha(b"hello there");
        assert!(
            matches!(
                analyze(&db, &clean, &opts).verdict,
                Verdict::Unscannable { .. }
            ),
            "{:?}",
            analyze(&db, &clean, &opts).verdict
        );
        assert!(matches!(
            seekable(&db, &clean, &opts),
            Verdict::Unscannable { .. }
        ));
        let infected = lha(eicar());
        assert!(infected_as(&analyze(&db, &infected, &opts).verdict).is_some());
    }

    /// A WebP is graphics to a `Target:5` signature by default, and not under
    /// `--clamav-compat`, as clamscan has it: the option reaches the engine.
    #[test]
    #[cfg(feature = "image-hash")]
    fn clamav_compat_keeps_target_5_to_clamscans_graphics() {
        let img = image::RgbImage::from_pixel(32, 32, image::Rgb([10, 200, 30]));
        let mut webp = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut webp, image::ImageFormat::WebP)
            .unwrap();
        let webp = webp.into_inner();
        let db = db_from(&[("w.ldb", "Test.Graphics;Engine:51-255,Target:5;0;52494646\n")]);
        assert_eq!(
            infected_as(&analyze(&db, &webp, &ScanOptions::default()).verdict),
            Some("Test.Graphics")
        );
        assert_eq!(
            analyze(&db, &webp, &ScanOptions::clamav_compat()).verdict,
            Verdict::Clean
        );
    }

    /// A whole-file allowlist entry clears the file whichever way it is
    /// scanned: in memory, through a reader and from a path, by MD5 (`.fp`)
    /// or by SHA-256 (`.sfp`).
    #[test]
    #[cfg(any(feature = "zip", feature = "all-formats"))]
    fn an_allowlisted_file_is_clean_on_every_scan_path() {
        let zip = build_zip(&[("b.txt", eicar())]);
        let d = digests_of(&zip);
        // No temp directory under WASI: the scan of a path is native only.
        #[cfg(not(target_family = "wasm"))]
        let dir = crate::tmpfile::TempDir::new().unwrap();
        #[cfg(not(target_family = "wasm"))]
        let path = dir.path().join("t.zip");
        #[cfg(not(target_family = "wasm"))]
        std::fs::write(&path, &zip).unwrap();
        let opts = ScanOptions::default();
        for (file, line) in [
            ("x.fp", format!("{}:{}:Allowed\n", d.md5_hex(), zip.len())),
            (
                "x.sfp",
                format!("{}:{}:Allowed\n", d.sha256_hex(), zip.len()),
            ),
        ] {
            let db = db_from(&[(file, &line)]);
            assert_eq!(analyze(&db, &zip, &opts).verdict, Verdict::Clean, "{file}");
            assert_eq!(seekable(&db, &zip, &opts), Verdict::Clean, "{file}");
            #[cfg(not(target_family = "wasm"))]
            assert_eq!(
                scan_path(&db, &path, &opts).unwrap().verdict,
                Verdict::Clean,
                "{file}"
            );
        }
        // The entry is what clears it.
        assert!(infected_as(&seekable(&Scanner::builtin(), &zip, &opts)).is_some());
    }

    /// A file too large to hold gets the full engine, read through a block
    /// cache: a wildcard signature is found as well as a literal one. A clean
    /// text file is clean only when its normalised views could be made, which
    /// takes a spill.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn a_file_over_the_object_limit_gets_the_full_engine() {
        let db = db_from(&[
            ("w.ndb", "Test.Wild:0:*:6576696c??7061796c6f6164\n"),
            ("l.ndb", "Test.Literal:0:*:6d61726b65726d61726b6572\n"),
        ]);
        let opts = holding(64);
        let mut wild = b"xx evil1payload xx".to_vec();
        wild.resize(1024, b' ');
        let mut literal = b"xx markermarker xx".to_vec();
        literal.resize(1024, b' ');
        let mut clean = b"xx nothing to see xx".to_vec();
        clean.resize(1024, b' ');

        let dir = crate::tmpfile::TempDir::new().unwrap();
        let path = dir.path().join("big.txt");
        for (data, want) in [(&wild, "Test.Wild"), (&literal, "Test.Literal")] {
            std::fs::write(&path, data).unwrap();
            for v in [
                seekable(&db, data, &opts),
                scan_path(&db, &path, &opts).unwrap().verdict,
            ] {
                assert_eq!(infected_as(&v), Some(want), "{v:?}");
            }
        }
        // A PCRE subsignature and a YARA rule past the limit too.
        let mut rules = vec![(
            "p.ldb",
            "Test.Pcre;Engine:81-255,Target:0;0&1;6f6e6c79;0/only[0-9]+pcre/\n",
        )];
        if cfg!(feature = "yara") {
            rules.push((
                "r.yar",
                "rule big_y { strings: $a = \"yara-only-marker\" condition: $a }\n",
            ));
        }
        let more = db_from(&rules);
        let mut pcre = b"xx only42pcre xx".to_vec();
        pcre.resize(1024, b' ');
        let mut yara = b"xx yara-only-marker xx".to_vec();
        yara.resize(1024, b' ');
        let mut cases = vec![(&pcre, "Test.Pcre")];
        if cfg!(feature = "yara") {
            cases.push((&yara, "YARA.big_y"));
        }
        for (data, want) in cases {
            std::fs::write(&path, data).unwrap();
            for v in [
                seekable(&more, data, &opts),
                scan_path(&more, &path, &opts).unwrap().verdict,
            ] {
                assert_eq!(infected_as(&v), Some(want), "{v:?}");
            }
        }
        assert!(
            matches!(seekable(&db, &clean, &opts), Verdict::LimitsExceeded { .. }),
            "without a spill the text views were not scanned"
        );
        let spilling = ScanOptions {
            spill: Some(std::sync::Arc::new(unpack::spill::MemSpill::new())),
            ..opts.clone()
        };
        assert_eq!(seekable(&db, &clean, &spilling), Verdict::Clean);
    }

    /// A size-limit reason names the flag an operator would raise.
    #[test]
    fn the_size_limit_reason_names_the_real_flag() {
        let opts = ScanOptions {
            max_scan_size: Some(4),
            ..ScanOptions::default()
        };
        match seekable(&Scanner::builtin(), b"more than four bytes", &opts) {
            Verdict::LimitsExceeded { reason } => {
                assert!(reason.contains("max-input-bytes"), "{reason}")
            }
            other => panic!("expected a limit, got {other:?}"),
        }
    }

    /// Past `--max-input-bytes` an all-match scan lists what the first bytes
    /// hold and reports the rest unscanned, as a single-match scan does: it
    /// neither reads past the limit nor calls the input complete.
    #[test]
    fn an_all_match_scan_keeps_to_the_input_limit() {
        let db = db_from(&[(
            "t.ndb",
            "Test.Head:0:*:4558415654455354\nTest.Tail:0:*:5441494c5441494c\n",
        )]);
        let mut data = b"EXAVTEST".to_vec();
        data.extend(std::iter::repeat_n(b'.', 10_000));
        data.extend_from_slice(b"TAILTAIL");
        let opts = ScanOptions {
            max_scan_size: Some(4096),
            ..ScanOptions::default()
        };
        let all = |data: &[u8], opts: &ScanOptions| {
            analyze_all_seekable(&db, Cursor::new(data), data.len() as u64, opts).unwrap()
        };
        let (names, outcome) = all(&data, &opts);
        let names: Vec<_> = names.into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["Test.Head"]);
        match outcome {
            AllMatchOutcome::LimitsExceeded(reason) => {
                assert!(reason.contains("max-input-bytes"), "{reason}")
            }
            other => panic!("expected a limit, got {other:?}"),
        }
        // Nothing in the first bytes: the limit alone, as a single-match scan
        // reports it.
        let (names, outcome) = all(&data[8..], &opts);
        assert!(names.is_empty(), "{names:?}");
        assert!(
            matches!(outcome, AllMatchOutcome::LimitsExceeded(_)),
            "{outcome:?}"
        );
        // Under ClamAV's alert, by ClamAV's name for it.
        let alerting = ScanOptions {
            alert_exceeds_max: true,
            ..opts.clone()
        };
        let want = seekable(&db, &data[8..], &alerting);
        let (names, _) = all(&data[8..], &alerting);
        let names: Vec<_> = names.into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            Some(names.as_slice()),
            infected_as(&want).map(|n| vec![n.to_string()]).as_deref()
        );
        // Within the limit, the whole input.
        let (names, outcome) = all(&data, &ScanOptions::default());
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(matches!(outcome, AllMatchOutcome::Complete), "{outcome:?}");
    }

    /// An input longer than the build addresses (4 GiB on a 32-bit target;
    /// here a build that addresses 4096 bytes) is scanned as far as it goes
    /// and reported over a limit, never read as if it ended there. A detection
    /// in the part scanned still wins, and the reason names the real cause.
    #[test]
    fn an_input_longer_than_the_build_addresses_is_reported_not_cut() {
        const ADDRESSABLE: u64 = 4096;
        let db = db_from(&[(
            "t.ndb",
            "Test.Head:0:*:4558415654455354\nTest.Tail:0:*:5441494c5441494c\n",
        )]);
        let mut data = b"EXAVTEST".to_vec();
        data.extend(std::iter::repeat_n(b'.', 10_000));
        data.extend_from_slice(b"TAILTAIL");
        let one = |data: &[u8], opts: &ScanOptions| {
            scan_seekable_addressing(
                &db,
                Cursor::new(data.to_vec()),
                data.len() as u64,
                opts,
                ADDRESSABLE,
                &mut None,
            )
            .unwrap()
            .verdict
        };
        let all = |data: &[u8], opts: &ScanOptions| {
            let (names, outcome) = analyze_all_addressing(
                &db,
                Cursor::new(data.to_vec()),
                data.len() as u64,
                opts,
                ADDRESSABLE,
            )
            .unwrap();
            (
                names.into_iter().map(|(n, _)| n).collect::<Vec<_>>(),
                outcome,
            )
        };
        let opts = ScanOptions::default();
        // A detection in the first 4096 bytes is found.
        assert_eq!(infected_as(&one(&data, &opts)), Some("Test.Head"));
        assert_eq!(all(&data, &opts).0, ["Test.Head"]);
        // None there: the limit, with the real cause. The tail is not read.
        let head = &data[8..];
        let first = match one(head, &opts) {
            Verdict::LimitsExceeded { reason } => Some(reason),
            _ => None,
        };
        let every = match all(head, &opts) {
            (names, AllMatchOutcome::LimitsExceeded(reason)) if names.is_empty() => Some(reason),
            _ => None,
        };
        for (name, got) in [("first match", first), ("all matches", every)] {
            let reason = got.unwrap_or_else(|| panic!("{name}: not a limit"));
            assert!(reason.contains("can address"), "{name}: {reason}");
            assert!(reason.contains("4096"), "{name}: {reason}");
            assert!(!reason.contains("max-input-bytes"), "{name}: {reason}");
        }
        // The flag's own limit, when it is the lower, keeps its reason.
        let flagged = ScanOptions {
            max_scan_size: Some(1000),
            ..ScanOptions::default()
        };
        match one(head, &flagged) {
            Verdict::LimitsExceeded { reason } => {
                assert!(reason.contains("max-input-bytes 1000"), "{reason}")
            }
            other => panic!("expected a limit, got {other:?}"),
        }
        // And a flag set past what the build addresses does not raise it.
        let past = ScanOptions {
            max_scan_size: Some(1 << 40),
            ..ScanOptions::default()
        };
        match one(head, &past) {
            Verdict::LimitsExceeded { reason } => {
                assert!(reason.contains("can address"), "{reason}")
            }
            other => panic!("expected a limit, got {other:?}"),
        }
        // Under ClamAV's alert, by ClamAV's name for the size condition.
        let alerting = ScanOptions {
            alert_exceeds_max: true,
            ..ScanOptions::default()
        };
        assert_eq!(
            infected_as(&one(head, &alerting)),
            Some("Heuristics.Limits.Exceeded.MaxFileSize")
        );
        // Within what it addresses, the whole input as before.
        assert_eq!(one(&data[8..4000], &opts), Verdict::Clean);
        assert!(matches!(
            all(&data[8..4000], &opts),
            (names, AllMatchOutcome::Complete) if names.is_empty()
        ));
    }

    /// The `.fp` allowlist covers a top-level archive, not only its members.
    #[test]
    fn an_allowlisted_top_level_archive_is_clean() {
        let zip = build_zip(&[("b.txt", eicar())]);
        let d = digests_of(&zip);
        let db = db_from(&[("x.fp", &format!("{}:{}:Allowed\n", d.md5_hex(), zip.len()))]);
        assert_eq!(seekable(&db, &zip, &ScanOptions::default()), Verdict::Clean);
    }

    /// The incomplete-search flag is per scan. Left over from an earlier scan
    /// on the same thread, it turned a clean archive into LIMITS-EXCEEDED.
    #[test]
    #[cfg(any(feature = "zip", feature = "all-formats"))]
    fn a_previous_scans_truncation_does_not_leak_into_the_next() {
        let zip = build_zip(&[("a.txt", b"harmless")]);
        engine::mark_scan_truncated();
        assert_eq!(
            seekable(&Scanner::builtin(), &zip, &ScanOptions::default()),
            Verdict::Clean
        );
    }

    /// What a bytecode unpacker made at the depth limit is a limit kept for
    /// the end of its object's scan, as a payload's is, so the checks after
    /// it still run; under `--alert-exceeds-max` it is a detection and ends it.
    #[test]
    fn an_unpacked_buffer_at_the_depth_limit_is_kept() {
        let db = Scanner::builtin();
        let mut opts = ScanOptions::default();
        opts.limits.max_recursion = 0;
        let run = |opts: &ScanOptions| {
            let mut budget = scan_budget(&db, opts);
            let mut first_at = None;
            let mut sink = Sink {
                mode: SinkMode::First(&db.ignored),
                at: root_path(),
                first_at: &mut first_at,
            };
            let mut deferred = DeepOutcome::Clean;
            let bufs = vec![b"unpacked".to_vec(), b"twice".to_vec()];
            let stop = scan_unpacked(
                &db,
                bufs,
                Obj::top(opts),
                opts,
                &mut budget,
                &mut Vec::new(),
                &mut sink,
                &mut deferred,
            );
            let show = |o: &DeepOutcome| match o {
                DeepOutcome::Clean => "clean".to_string(),
                DeepOutcome::Infected { signature, .. } => signature.clone(),
                DeepOutcome::Limits(r) => format!("limits: {r}"),
                DeepOutcome::Unscannable(r) | DeepOutcome::PasswordProtected(r) => r.text.clone(),
            };
            (stop.as_ref().map(show), show(&deferred))
        };
        assert_eq!(
            run(&opts),
            (None, "limits: recursion depth exceeds 0".to_string())
        );
        opts.alert_exceeds_max = true;
        let (stop, _) = run(&opts);
        assert_eq!(
            stop.as_deref(),
            Some("Heuristics.Limits.Exceeded.MaxRecursion")
        );
    }

    /// A member name is file content. Quoted in a reason, a newline in it would
    /// write a line of its own into a line-framed reply.
    #[test]
    fn a_member_name_cannot_add_a_line_to_the_verdict() {
        let mut t = tar::Builder::new(Vec::new());
        let body = vec![b'A'; 5000];
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        t.append_data(&mut h, "x\nstream: OK\n", &body[..]).unwrap();
        let tarball = t.into_inner().unwrap();

        let mut opts = ScanOptions::default();
        opts.limits.max_scanned_bytes = 1024;
        match seekable(&Scanner::builtin(), &tarball, &opts) {
            Verdict::LimitsExceeded { reason } => {
                assert!(reason.contains("x_stream: OK_"), "{reason}");
                assert!(!reason.contains('\n'), "{reason:?}");
            }
            other => panic!("expected a limit, got {other:?}"),
        }
    }

    /// Nor can it make the reason read in another order, or end a line for a
    /// reader that takes U+2028 for one: replaced as in a location.
    #[test]
    fn a_member_name_cannot_reorder_or_split_the_reason() {
        let mut t = tar::Builder::new(Vec::new());
        let body = vec![b'A'; 5000];
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        t.append_data(&mut h, "x\u{202e}gpj.exe\u{2028}y\u{2066}", &body[..])
            .unwrap();
        let tarball = t.into_inner().unwrap();

        let mut opts = ScanOptions::default();
        opts.limits.max_scanned_bytes = 1024;
        match seekable(&Scanner::builtin(), &tarball, &opts) {
            Verdict::LimitsExceeded { reason } => {
                assert!(reason.contains("x_gpj.exe_y_"), "{reason}");
            }
            other => panic!("expected a limit, got {other:?}"),
        }
    }

    /// 128 KiB of text that differs with `seed`.
    #[cfg(feature = "all-formats")]
    fn memo_body(seed: usize) -> Vec<u8> {
        let text: String = (0..4096)
            .map(|i| format!("line {seed} {i} of a member with nothing in it\n"))
            .collect();
        text.as_bytes()[..128 * 1024].to_vec()
    }

    /// A stored zip of `n` members of `memo_body`, the same in each when `same`.
    #[cfg(feature = "all-formats")]
    fn memo_zip(n: usize, same: bool) -> Vec<u8> {
        use exav_unpack::zip_write::{FileOptions, Method, ZipWriter};
        use std::io::Write;
        let stored = FileOptions::default().method(Method::Stored);
        let mut z = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for k in 0..n {
            z.start_file(&format!("member{k}.txt"), stored).unwrap();
            z.write_all(&memo_body(if same { 0 } else { k })).unwrap();
        }
        z.finish().unwrap().into_inner()
    }

    #[cfg(feature = "all-formats")]
    fn clean_skips_of(data: &[u8]) -> (Verdict, u64) {
        engine::CLEAN_SKIPS.with(|c| c.set(0));
        let v = analyze(&Scanner::builtin(), data, &ScanOptions::default()).verdict;
        (v, engine::CLEAN_SKIPS.with(|c| c.get()))
    }

    /// Bytes already scanned clean in the same place are not scanned again:
    /// the first of 40 copies is scanned and the other 39 are not.
    #[test]
    #[cfg(feature = "all-formats")]
    fn copies_of_a_clean_member_are_scanned_once() {
        assert_eq!(clean_skips_of(&memo_zip(40, true)), (Verdict::Clean, 39));
    }

    /// The control: members that differ are each scanned.
    #[test]
    #[cfg(feature = "all-formats")]
    fn members_that_differ_are_each_scanned() {
        assert_eq!(clean_skips_of(&memo_zip(40, false)), (Verdict::Clean, 0));
    }

    /// Members under the size worth remembering are scanned every time.
    #[test]
    #[cfg(feature = "all-formats")]
    fn small_copies_are_each_scanned() {
        use exav_unpack::zip_write::{FileOptions, Method, ZipWriter};
        use std::io::Write;
        let stored = FileOptions::default().method(Method::Stored);
        let mut z = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for k in 0..10 {
            z.start_file(&format!("m{k}.txt"), stored).unwrap();
            z.write_all(&memo_body(0)[..1000]).unwrap();
        }
        let z = z.finish().unwrap().into_inner();
        assert_eq!(clean_skips_of(&z), (Verdict::Clean, 0));
    }

    /// A copy that is not clean is found wherever it is, after clean ones with
    /// the same start.
    #[test]
    #[cfg(feature = "all-formats")]
    fn an_infected_member_after_clean_copies_is_found() {
        use exav_unpack::zip_write::{FileOptions, Method, ZipWriter};
        use std::io::Write;
        let stored = FileOptions::default().method(Method::Stored);
        // Deflated, so the signature is in the member only, not in the zip's bytes.
        let deflated = FileOptions::default().method(Method::Deflated);
        let mut z = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for k in 0..3 {
            z.start_file(&format!("clean{k}.bin"), stored).unwrap();
            z.write_all(&memo_body(0)).unwrap();
        }
        let mut dirty = memo_body(0);
        dirty.extend_from_slice(&[eicar(), b"\n"].concat().repeat(64));
        z.start_file("dirty.bin", deflated).unwrap();
        z.write_all(&dirty).unwrap();
        let z = z.finish().unwrap().into_inner();
        let (v, skips) = clean_skips_of(&z);
        assert_eq!(skips, 2);
        assert!(matches!(v, Verdict::Infected { .. }), "{v:?}");
    }

    /// The memo remembers the shallowest depth a clean scan was at: a copy
    /// deeper than that is covered, one shallower is not.
    #[test]
    fn a_clean_copy_covers_only_the_same_depth_or_deeper() {
        engine::reset_scan_truncated();
        let key = [7u8; 32];
        assert!(!engine::clean_seen(&key, 3));
        engine::clean_seen_insert(key, 3);
        assert!(!engine::clean_seen(&key, 2));
        assert!(engine::clean_seen(&key, 3));
        assert!(engine::clean_seen(&key, 9));
        engine::clean_seen_insert(key, 1);
        assert!(engine::clean_seen(&key, 1));
        assert!(!engine::clean_seen(&key, 0));
        // A new scan starts with nothing remembered.
        engine::reset_scan_truncated();
        assert!(!engine::clean_seen(&key, 9));
    }

    #[test]
    fn detects_eicar_pattern() {
        let db = Scanner::builtin();
        let r = analyze(&db, eicar(), &ScanOptions::default());
        assert!(matches!(
            r.verdict,
            Verdict::Infected {
                method: Method::Pattern,
                ..
            }
        ));
    }

    #[test]
    #[cfg(feature = "all-formats")]
    fn detects_cdb_container_metadata() {
        use std::io::Write;
        // A ZIP holding a member named like an executable dropper.
        let mut zbuf = Vec::new();
        {
            let mut zw = exav_unpack::zip_write::ZipWriter::new(Cursor::new(&mut zbuf));
            zw.start_file(
                "payload_dropper.exe",
                exav_unpack::zip_write::FileOptions::default(),
            )
            .unwrap();
            zw.write_all(b"harmless looking bytes").unwrap();
            zw.finish().unwrap();
        }
        let mut db = Scanner::builtin();
        // Match any ZIP containing a `*.exe` member, by container metadata alone.
        db.cdb
            .extend_from_text("Test.Cdb.Dropper:CL_TYPE_ZIP:*:.*\\.exe:*:*:*:*:*:\n");
        let r = analyze(&db, &zbuf, &ScanOptions::default());
        match r.verdict {
            Verdict::Infected { signature, .. } => assert_eq!(signature, "Test.Cdb.Dropper"),
            other => panic!("expected .cdb detection, got {other:?}"),
        }
    }

    /// ClamAV's `.ftm` types anything starting `60 EA` as ARJ. An object that
    /// only happens to start that way must not be opened as a damaged ARJ and
    /// reported `UNSCANNABLE`; a real one still is ARJ.
    #[test]
    #[cfg(feature = "all-formats")]
    fn ftm_arj_typing_needs_a_real_header() {
        let mut db = Scanner::builtin();
        db.ftm
            .extend_from_text("0:0:60ea:ARJ:CL_TYPE_ANY:CL_TYPE_ARJ\n");
        let fake = b"\x60\xea\x10\x00 not an ARJ header, just bytes";
        assert_eq!(db.identify(fake), FileType::Unknown);
        let r = analyze(&db, fake, &ScanOptions::default());
        assert!(matches!(r.verdict, Verdict::Clean), "{:?}", r.verdict);
        let real = include_bytes!("../../exav-unpack/tests/fixtures/sample.arj");
        assert_eq!(db.identify(real), FileType::Arj);
    }

    /// Every normalised view a textual file is matched against must still be
    /// produced, and each must be built only when asked for.
    ///
    /// The views are handed out as thunks so the scanner holds one full-size
    /// copy at a time instead of all of them, measured at 270 MB saved on a
    /// 97 MB script. The risk in that shape is silently losing a view: a
    /// dropped normalisation costs detections and nothing fails, because the
    /// remaining views still match everything they always did.
    #[test]
    fn every_normalization_view_is_still_offered() {
        let script = b"<script>EVAL(/* c */unescape('%61'))</script>";
        let plain = b"just some plain prose, with nothing executable about it";

        // `Html` and `Script` are script-like whatever they contain; `Text`
        // earns the two extra views only from what is in the bytes.
        assert_eq!(
            normalizations(FileType::Text, plain, false),
            [(ViewKind::Text, FileType::TextView)],
            "a non-script textual file is matched against its text view"
        );
        assert_eq!(
            normalizations(FileType::Text, script, false).len(),
            3,
            "script-shaped content adds the javascript and jsnorm views"
        );
        assert_eq!(
            normalizations(FileType::Html, plain, false),
            [
                (ViewKind::Html, FileType::HtmlView),
                (ViewKind::Javascript, FileType::HtmlView),
                (ViewKind::Deobfuscated, FileType::HtmlView),
                (ViewKind::PageScripts, FileType::ScriptView)
            ],
            "an HTML file is script-like by type, whatever it holds"
        );
        assert_eq!(normalizations(FileType::Rtf, script, false).len(), 2);

        // And each one produces something to scan.
        for (i, (kind, _)) in normalizations(FileType::Text, script, false)
            .into_iter()
            .enumerate()
        {
            let view = make_view(kind, script, &ScanOptions::default()).expect("a view");
            assert!(
                !view.source().is_empty(),
                "normalisation {i} produced nothing"
            );
        }
    }

    #[test]
    fn detects_normalized_html_signature() {
        // Signature for lowercase "<script>evil", which only appears after
        // normalising mixed-case + entity-encoded HTML (`&#x69;` -> 'i').
        let mut db = Scanner::builtin();
        let mut eb = engine::EngineBuilder::new();
        eb.add_ndb("Test.Html:0:*:3c7363726970743e6576696c", false);
        db.engine = eb.build();
        let raw = b"<SCRIPT>EV&#x69;L</SCRIPT> and more <b>html</b>";
        // The literal is absent from the raw bytes; only normalisation reveals it.
        assert!(
            !raw.windows(12).any(|w| w == b"<script>evil"),
            "literal must not be present pre-normalisation"
        );
        let r = analyze(&db, raw, &ScanOptions::default());
        assert!(
            matches!(
                r.verdict,
                Verdict::Infected {
                    method: Method::Pattern,
                    ..
                }
            ),
            "expected normalized-HTML detection, got {:?}",
            r.verdict
        );
    }

    #[test]
    fn detects_normalized_javascript_signature() {
        // Signature for lowercased, whitespace-collapsed "eval(unescape(",
        // which only appears after JS normalisation of uppercased, comment-laden
        // source.
        let target: &[u8] = b"eval(unescape(";
        let hex: String = target.iter().map(|b| format!("{b:02x}")).collect();
        let mut db = Scanner::builtin();
        let mut eb = engine::EngineBuilder::new();
        eb.add_ndb(&format!("Test.Js:0:*:{hex}"), false);
        db.engine = eb.build();
        let raw = b"EVAL(/* c */unescape('%61'))";
        assert!(
            !raw.windows(target.len()).any(|w| w == target),
            "literal must not be present pre-normalisation"
        );
        let r = analyze(&db, raw, &ScanOptions::default());
        assert!(
            matches!(
                r.verdict,
                Verdict::Infected {
                    method: Method::Pattern,
                    ..
                }
            ),
            "expected normalized-JS detection, got {:?}",
            r.verdict
        );
    }

    #[test]
    fn detects_hash_signature() {
        let mut db = Scanner::builtin();
        let d = digests_of(b"some clean-looking content");
        db.hashes
            .extend_from_text(&format!("{}:*:Test.ByHash\n", d.sha256_hex()));
        db.hashes.finalize();
        let r = analyze(&db, b"some clean-looking content", &ScanOptions::default());
        match r.verdict {
            Verdict::Infected {
                signature,
                method: Method::Hash,
                ..
            } => {
                assert_eq!(signature, "Test.ByHash")
            }
            other => panic!("expected hash detection, got {other:?}"),
        }
    }

    /// Whole-file hash signatures stop applying at [`MIN_HASH_MATCH_BYTES`],
    /// even with every object scanned: 5 bytes is refused, 6 matches. ClamAV
    /// 1.4.3 with an equivalent `.hdb` reports OK up to 5 bytes and FOUND
    /// from 6.
    #[test]
    fn hash_signatures_do_not_match_tiny_objects() {
        let opts = ScanOptions {
            min_scan_bytes: 0,
            ..ScanOptions::default()
        };
        for n in 1..=8usize {
            let data: Vec<u8> = (0..n).map(|i| b'A' + (i % 26) as u8).collect();
            let mut db = Scanner::builtin();
            let d = digests_of(&data);
            db.hashes
                .extend_from_text(&format!("{}:{}:Test.Tiny{}\n", d.md5_hex(), n, n));
            db.hashes.finalize();
            let hit = matches!(analyze(&db, &data, &opts).verdict, Verdict::Infected { .. });
            assert_eq!(
                hit,
                n >= 6,
                "{n}-byte object: hash match should be {}",
                n >= 6
            );
        }
    }

    /// The allow-list shares the hash machinery but must NOT inherit the floor:
    /// a suppression that quietly stopped working would reintroduce exactly the
    /// false positives the floor removes.
    #[test]
    fn allowlist_still_applies_below_the_hash_floor() {
        // A 4-byte body carrying a pattern detection, then allow-listed by hash.
        let opts = ScanOptions {
            min_scan_bytes: 0,
            ..ScanOptions::default()
        };
        let mut db = Scanner::builtin();
        let mut eb = engine::EngineBuilder::new();
        eb.add_ndb("Test.Tiny.Pattern:0:*:61626364", false); // "abcd"
        db.engine = eb.build();
        let r = analyze(&db, b"abcd", &opts);
        assert!(
            matches!(r.verdict, Verdict::Infected { .. }),
            "pattern must still match a 4-byte object: {:?}",
            r.verdict
        );
        let d = digests_of(b"abcd");
        db.allow
            .extend_from_text(&format!("{}:4:Test.Allow\n", d.md5_hex()));
        db.allow.finalize();
        let r = analyze(&db, b"abcd", &opts);
        assert!(
            !matches!(r.verdict, Verdict::Infected { .. }),
            "allow-list must suppress below the hash floor: {:?}",
            r.verdict
        );
    }

    /// An object under `min_scan_bytes` is not scanned, nested or not, as
    /// clamscan 1.5.4 does not match `ABC` in a top-level or gzipped `ABCDE`
    /// and does in `ABCDEF`. `0` scans it.
    #[test]
    fn objects_under_the_minimum_are_not_scanned() {
        use std::io::Write;
        let mut db = Scanner::builtin();
        let mut eb = engine::EngineBuilder::new();
        eb.add_ndb("Test.Small:0:*:414243", false); // "ABC"
        db.engine = eb.build();
        let gz = |p: &[u8]| {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(p).unwrap();
            e.finish().unwrap()
        };
        let all = ScanOptions {
            min_scan_bytes: 0,
            ..ScanOptions::default()
        };
        for (n, opts, found) in [
            (5, ScanOptions::default(), false),
            (6, ScanOptions::default(), true),
            (5, all, true),
        ] {
            let p = &b"ABCDEF"[..n];
            for (what, data) in [("top-level", p.to_vec()), ("gzipped", gz(p))] {
                let r = analyze(&db, &data, &opts);
                assert_eq!(
                    matches!(r.verdict, Verdict::Infected { .. }),
                    found,
                    "{what} {n} bytes, minimum {}: {:?}",
                    opts.min_scan_bytes,
                    r.verdict
                );
            }
        }
    }

    #[test]
    fn clean_is_clean() {
        let db = Scanner::builtin();
        let r = analyze(&db, b"nothing to see", &ScanOptions::default());
        assert_eq!(r.verdict, Verdict::Clean);
    }

    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn allowlist_and_ignore_suppress_detection() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.ndb"), "Demo.Hit:0:*:cafebabe\n").unwrap();
        let data = b"\x00\xca\xfe\xba\xbe\x00".to_vec(); // contains the bytes CA FE BA BE
        let opts = ScanOptions::default();

        // Detected with no allowlist.
        let db = loader::load(dir.path()).unwrap();
        assert!(matches!(
            analyze(&db, &data, &opts).verdict,
            Verdict::Infected { .. }
        ));

        // `.fp` allowlisting this file's hash clears the detection.
        let d = digests_of(&data);
        std::fs::write(
            dir.path().join("b.fp"),
            format!("{}:*:Allowed\n", d.md5_hex()),
        )
        .unwrap();
        assert_eq!(
            analyze(&loader::load(dir.path()).unwrap(), &data, &opts).verdict,
            Verdict::Clean
        );
        std::fs::remove_file(dir.path().join("b.fp")).unwrap();

        // `.ign2` ignoring the signature name also clears it.
        std::fs::write(dir.path().join("c.ign2"), "Demo.Hit\n").unwrap();
        assert_eq!(
            analyze(&loader::load(dir.path()).unwrap(), &data, &opts).verdict,
            Verdict::Clean
        );
    }

    /// A match across the block cache's block boundaries is found, at its
    /// offset in the object.
    #[test]
    fn detects_across_buffer_boundary() {
        let db = Scanner::builtin();
        let mut data = vec![b'A'; 3_000_000];
        data.extend_from_slice(eicar());
        data.extend(std::iter::repeat_n(b'B', 3_000_000));
        let opts = holding(1 << 20);
        let size = data.len() as u64;
        let r = scan_seekable(&db, Cursor::new(data), size, &opts).unwrap();
        match r.verdict {
            Verdict::Infected { offset, .. } => assert_eq!(offset, 3_000_000),
            other => panic!("expected infection, got {other:?}"),
        }
    }

    #[test]
    fn finds_eicar_inside_gzip() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(eicar()).unwrap();
        let blob = e.finish().unwrap();
        let db = Scanner::builtin();
        let r = analyze(&db, &blob, &ScanOptions::default());
        assert!(matches!(r.verdict, Verdict::Infected { .. }));
    }

    fn write_temp(bytes: &[u8]) -> crate::tmpfile::TempFile {
        let f = crate::tmpfile::TempFile::new().unwrap();
        std::fs::write(f.path(), bytes).unwrap();
        f
    }

    /// `opts` with somewhere to spill what is too large to hold.
    fn spilling(opts: ScanOptions) -> ScanOptions {
        ScanOptions {
            spill: Some(std::sync::Arc::new(unpack::spill::MemSpill::new())),
            ..opts
        }
    }

    /// A seekable source that serves the object once and then fails.
    ///
    /// Models the case that actually bites: not a source that is broken from
    /// the start (that fails the first read and is obviously an error) but one
    /// that works, gets re-read, and dies the second time. A flaky range server
    /// is exactly this, and a scan re-reads a container to run the checks that
    /// need its whole bytes.
    struct FailsOnReread {
        data: Vec<u8>,
        pos: u64,
        served: u64,
    }

    impl Read for FailsOnReread {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.served >= self.data.len() as u64 {
                return Err(io::Error::other("simulated source failure on re-read"));
            }
            let end = (self.pos as usize + out.len()).min(self.data.len());
            let n = end.saturating_sub(self.pos as usize);
            if n == 0 {
                return Ok(0);
            }
            out[..n].copy_from_slice(&self.data[self.pos as usize..end]);
            self.pos += n as u64;
            self.served += n as u64;
            Ok(n)
        }
    }

    impl Seek for FailsOnReread {
        fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
            self.pos = match p {
                SeekFrom::Start(o) => o,
                SeekFrom::End(o) => (self.data.len() as i64 + o) as u64,
                SeekFrom::Current(o) => (self.pos as i64 + o) as u64,
            };
            Ok(self.pos)
        }
    }

    /// A source that dies mid-scan must never come back `Clean`.
    ///
    /// The bytes it failed to deliver still exist. This is not truncation,
    /// where the content really is absent and a clean answer is honest, so
    /// the only truthful outcomes are a detection, a partial verdict, or an
    /// error to the caller.
    #[test]
    fn a_source_that_fails_on_re_read_is_never_reported_clean() {
        let blob = zip_bytes(&[("a.txt", b"harmless padding here", false)]);
        let size = blob.len() as u64;
        let db = Scanner::builtin();
        let src = FailsOnReread {
            data: blob,
            pos: 0,
            served: 0,
        };
        match scan_seekable(&db, src, size, &ScanOptions::default()) {
            // Surfacing the io error to the caller is a fine answer: it is an
            // error, which is the thing that must not become an OK.
            Err(_) => {}
            Ok(rep) => assert!(
                !matches!(rep.verdict, Verdict::Clean),
                "a source that failed on re-read reported Clean: {:?}",
                rep.verdict
            ),
        }
    }

    /// A container over the object limit whose format is read whole
    /// (here OLE2) has its members unscanned, so the verdict is LimitsExceeded,
    /// never Clean.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn oversize_container_read_whole_is_limits_not_clean() {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut comp = cfb::CompoundFile::create(&mut buf).unwrap();
            let mut s = comp.create_stream("data").unwrap();
            s.write_all(&vec![b'A'; 4096]).unwrap();
            s.flush().unwrap();
        }
        let blob = buf.into_inner();
        let f = write_temp(&blob);
        let db = Scanner::builtin();
        let opts = holding(1);
        let r = scan_path(&db, f.path(), &opts).unwrap();
        assert!(
            matches!(r.verdict, Verdict::LimitsExceeded { .. }),
            "got {:?}",
            r.verdict
        );
    }

    // A gzip/tar whose size exceeds `limits.max_buffer_bytes` is walked
    // member-by-member off disk, never held whole, and its members, too large
    // to hold as well, go through the spill: the cap bounds memory without
    // bounding what the scan can find.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn streamed_gzip_over_cap_finds_eicar() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(eicar()).unwrap();
        let blob = e.finish().unwrap();
        let f = write_temp(&blob);
        let db = Scanner::builtin();
        let opts = spilling(holding(1));
        let r = scan_path(&db, f.path(), &opts).unwrap();
        assert!(
            matches!(r.verdict, Verdict::Infected { .. }),
            "got {:?}",
            r.verdict
        );
    }

    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn streamed_tar_over_cap_finds_eicar() {
        let mut ar = tar::Builder::new(Vec::new());
        // A benign padding member first, then the payload: proves the walk
        // continues past clean members without buffering the whole archive.
        let pad = vec![b'Z'; 8192];
        let mut h = tar::Header::new_gnu();
        h.set_size(pad.len() as u64);
        h.set_cksum();
        ar.append_data(&mut h, "pad.bin", &pad[..]).unwrap();
        let mut h2 = tar::Header::new_gnu();
        h2.set_size(eicar().len() as u64);
        h2.set_cksum();
        ar.append_data(&mut h2, "evil.com", eicar()).unwrap();
        let blob = ar.into_inner().unwrap();
        let f = write_temp(&blob);
        let db = Scanner::builtin();
        let opts = spilling(holding(1));
        let r = scan_path(&db, f.path(), &opts).unwrap();
        assert!(
            matches!(r.verdict, Verdict::Infected { .. }),
            "got {:?}",
            r.verdict
        );
    }

    // A container's own whole-file hash is matched as well as its members.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn streamed_container_whole_file_hash_detected() {
        let mut ar = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(5);
        h.set_cksum();
        ar.append_data(&mut h, "a.txt", &b"hello"[..]).unwrap();
        let blob = ar.into_inner().unwrap();
        let mut db = Scanner::builtin();
        let d = digests_of(&blob);
        db.hashes
            .extend_from_text(&format!("{}:*:Test.TarWholeHash\n", d.sha256_hex()));
        db.hashes.finalize();
        let f = write_temp(&blob);
        let r = scan_path(&db, f.path(), &ScanOptions::default()).unwrap();
        match r.verdict {
            Verdict::Infected { signature, .. } => assert_eq!(signature, "Test.TarWholeHash"),
            other => panic!("expected whole-file-hash detection, got {other:?}"),
        }
    }

    // A gzip NESTED inside a tar, whose decompressed content exceeds both
    // `max_buffer_bytes`, with EICAR buried past it: the member is decoded as
    // it is read and spilled, not capped or truncated at the limit. With
    // nowhere to spill it, it is reported, not cleared.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn nested_gzip_over_entry_cap_is_streamed_and_found() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        // gzip whose decompressed content (padding + EICAR at the end) far exceeds
        // the tiny per-member buffer cap set below.
        let mut payload = vec![b'Z'; 4096];
        payload.extend_from_slice(eicar());
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(&payload).unwrap();
        let gz = e.finish().unwrap();
        // Wrap the .gz as a member of a tar (the streamed top-level container).
        let mut ar = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(gz.len() as u64);
        h.set_cksum();
        ar.append_data(&mut h, "payload.gz", &gz[..]).unwrap();
        let blob = ar.into_inner().unwrap();
        let f = write_temp(&blob);
        let db = Scanner::builtin();
        // The per-member buffer cap (256 bytes) is far below the 4 KiB+ of
        // decompressed content, so this pins that a nested gzip is streamed
        // rather than capped or truncated at that boundary.
        let mut opts = ScanOptions::default();
        opts.limits.max_buffer_bytes = 256;
        let r = scan_path(&db, f.path(), &spilling(opts.clone())).unwrap();
        assert!(
            matches!(r.verdict, Verdict::Infected { .. }),
            "nested gzip past the entry cap must be streamed and detected, got {:?}",
            r.verdict
        );
        match scan_path(&db, f.path(), &opts).unwrap().verdict {
            Verdict::LimitsExceeded { reason } => {
                assert!(reason.contains("could not be spilled"), "{reason}")
            }
            other => panic!("expected a limit without a spill, got {other:?}"),
        }
    }

    // Flat content larger than the object limit gets the full engine
    // through a block cache, so a signature in it is found.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn oversize_flat_text_with_signature_is_found() {
        let mut data = vec![b'A'; 100];
        data.extend_from_slice(eicar());
        let f = write_temp(&data);
        let db = Scanner::builtin();
        let opts = holding(1);
        let r = scan_path(&db, f.path(), &opts).unwrap();
        assert!(matches!(r.verdict, Verdict::Infected { .. }));
    }

    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn oversize_flat_text_is_a_limit_not_clean() {
        let f = write_temp(&vec![b'Z'; 5000]);
        let db = Scanner::builtin();
        let opts = holding(1);
        let r = scan_path(&db, f.path(), &opts).unwrap();
        assert!(matches!(r.verdict, Verdict::LimitsExceeded { .. }));
    }

    /// Whether `needle` is anywhere in the raw bytes of `haystack`.
    #[cfg(any(feature = "zip", feature = "all-formats"))]
    fn contains_window(haystack: &dyn ByteSource, needle: &[u8]) -> bool {
        haystack.find(needle, 0, haystack.len()).is_some()
    }

    fn zip_bytes(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
        use exav_unpack::zip_write::{FileOptions, Method, ZipWriter};
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let mut w = ZipWriter::new(Cursor::new(&mut buf));
            for (name, data, stored) in members {
                let opts = if *stored {
                    FileOptions::default().method(Method::Stored)
                } else {
                    FileOptions::default()
                };
                w.start_file(name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    /// A database whose one signature is `MARK` anywhere.
    #[cfg(feature = "all-formats")]
    fn mark_db() -> Scanner {
        let mut l = loader::Builder::new();
        l.add_named_bytes("m.ndb", b"Test.Mark:0:*:4d41524b2d6174\n", true);
        l.build().unwrap()
    }

    /// `n` bytes of noise ending with the mark.
    #[cfg(feature = "all-formats")]
    fn ends_marked(n: usize) -> Vec<u8> {
        let mut d: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8 | 0x80).collect();
        d[n - 7..].copy_from_slice(b"MARK-at");
        d
    }

    /// Options under which 64 KiB is too large to hold, and how many spill
    /// files they made.
    #[cfg(feature = "all-formats")]
    fn small_limit(spill: bool) -> (ScanOptions, std::sync::Arc<unpack::spill::MemSpill>) {
        let made = std::sync::Arc::new(unpack::spill::MemSpill::new());
        let opts = ScanOptions {
            spill: spill.then(|| std::sync::Arc::clone(&made) as std::sync::Arc<dyn spill::Spill>),
            ..holding(64 * 1024)
        };
        (opts, made)
    }

    #[cfg(feature = "all-formats")]
    fn scan_of(db: &Scanner, data: &[u8], opts: &ScanOptions) -> Verdict {
        let size = data.len() as u64;
        scan_seekable(db, Cursor::new(data.to_vec()), size, opts)
            .unwrap()
            .verdict
    }

    /// A stored member over the limit is read where it is in the archive: all
    /// of it, to its last byte, with no spill file made or needed.
    #[test]
    #[cfg(feature = "all-formats")]
    fn a_stored_member_over_the_limit_is_read_in_place() {
        let db = mark_db();
        let blob = zip_bytes(&[("a", b"small", true), ("big", &ends_marked(300_000), true)]);
        let (opts, made) = small_limit(true);
        let v = scan_of(&db, &blob, &opts);
        assert!(matches!(v, Verdict::Infected { .. }), "{v:?}");
        assert_eq!(made.made(), 0, "a spill file was made");
        // With nowhere to spill too.
        let (opts, _) = small_limit(false);
        let v = scan_of(&db, &blob, &opts);
        assert!(matches!(v, Verdict::Infected { .. }), "{v:?}");
        // A deflated member over the limit still goes to the spill.
        let blob = zip_bytes(&[("big", &ends_marked(300_000), false)]);
        let (opts, made) = small_limit(true);
        let v = scan_of(&db, &blob, &opts);
        assert!(matches!(v, Verdict::Infected { .. }), "{v:?}");
        assert_eq!(made.made(), 1);
    }

    /// An archive stored in an archive, both over the limit, is opened where
    /// it lies, and so is its member.
    #[test]
    #[cfg(feature = "all-formats")]
    fn an_archive_in_a_stored_member_is_opened() {
        let db = mark_db();
        // Deflated, so the mark is not in the bytes of either archive.
        let inner = zip_bytes(&[
            ("pad", &[0x90; 100_000], true),
            ("deep", &ends_marked(1000), false),
        ]);
        let blob = zip_bytes(&[("pad", &[0x90; 100_000], true), ("inner.zip", &inner, true)]);
        let (opts, _) = small_limit(false);
        let v = scan_of(&db, &blob, &opts);
        assert!(matches!(v, Verdict::Infected { .. }), "{v:?}");
    }

    /// A stored member whose declared size runs past the end of the archive is
    /// scanned as far as the archive goes, as one held in memory is: what is
    /// cut is absent, not hidden (docs/QUIRKS.md).
    #[test]
    #[cfg(feature = "all-formats")]
    fn a_member_past_the_end_of_its_archive_is_scanned_as_far_as_it_goes() {
        let db = mark_db();
        let cut = |body: &[u8]| {
            let mut blob = zip_bytes(&[("big", body, true)]);
            // Both headers say 200,000 bytes, compressed and not.
            let size = 200_000u32.to_le_bytes();
            blob[18..22].copy_from_slice(&size);
            blob[22..26].copy_from_slice(&size);
            let cd = blob.windows(4).rposition(|w| w == b"PK\x01\x02").unwrap();
            blob[cd + 20..cd + 24].copy_from_slice(&size);
            blob[cd + 24..cd + 28].copy_from_slice(&size);
            blob
        };
        let (opts, _) = small_limit(true);
        let v = scan_of(&db, &cut(&[0x41; 100_000]), &opts);
        assert!(matches!(v, Verdict::Clean), "{v:?}");
        let v = scan_of(&db, &cut(&ends_marked(100_000)), &opts);
        assert!(matches!(v, Verdict::Infected { .. }), "{v:?}");
    }

    /// A hold limit past the build's `usize` is no limit; it does not wrap to a
    /// small one.
    #[test]
    fn a_hold_limit_past_the_address_space_is_the_largest_length() {
        for max in [5, (1 << 32) + 5, 1 << 40, u64::MAX] {
            let opts = holding(max);
            assert_eq!(opts.hold_limit() as u64, max.min(usize::MAX as u64));
        }
    }

    #[test]
    #[cfg(feature = "all-formats")]
    fn scan_seekable_finds_eicar_in_zip() {
        let blob = zip_bytes(&[("a.txt", b"hello", false), ("evil", eicar(), false)]);
        let size = blob.len() as u64;
        let db = Scanner::builtin();
        let r = scan_seekable(&db, Cursor::new(blob), size, &ScanOptions::default()).unwrap();
        assert!(matches!(r.verdict, Verdict::Infected { .. }));
    }

    /// A range server that answers every request with a body SHORTER than the
    /// range it was asked for, while still advertising the object's full length.
    ///
    /// This is the shape that turns a network fault into a clean verdict: the
    /// reader knows more bytes exist (`pos < len`) but has none to hand. If it
    /// answers `Ok(0)` it is claiming end-of-file, and every layer above treats
    /// that as an ordinary truncated archive (content actually absent), which
    /// exav is entitled to call clean. It must be an error instead.
    #[cfg(feature = "http")]
    #[test]
    fn http_short_range_response_is_an_error_not_a_clean() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::thread;

        let blob = zip_bytes(&[("a.txt", b"padding to make this worth ranging", false)]);
        let total = blob.len();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut rdr = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if rdr.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                loop {
                    let mut h = String::new();
                    match rdr.read_line(&mut h) {
                        Ok(0) | Err(_) => break,
                        Ok(_) if h == "\r\n" || h == "\n" => break,
                        Ok(_) => {}
                    }
                }
                // Advertise the whole object, then hand back nothing.
                let hdr = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-0/{total}\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(hdr.as_bytes());
                let _ = stream.flush();
            }
        });

        let url = format!("http://{addr}/object.zip");
        let db = Scanner::builtin();
        let Ok(reader) = crate::source::HttpRangeReader::open(&url) else {
            return; // the server refused to come up; nothing to assert
        };
        let size = reader.len();
        match scan_seekable(&db, reader, size, &ScanOptions::default()) {
            // An error reaching the caller is the correct outcome.
            Err(_) => {}
            Ok(rep) => assert!(
                !matches!(rep.verdict, Verdict::Clean),
                "a range server that returned no data reported Clean: {:?}",
                rep.verdict
            ),
        }
    }

    /// Scan a ZIP over HTTP range requests: detection works, and the object is
    /// re-read a bounded number of times rather than without limit.
    #[cfg(feature = "http")]
    #[test]
    fn http_range_scan_fetches_only_what_it_needs() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::thread;

        let big: Vec<u8> = (0..1_000_000u32).map(|i| (i as u8) ^ 0x5a).collect();
        let blob = zip_bytes(&[("evil", eicar(), false), ("big.bin", &big, true)]);
        let total = blob.len();
        assert!(
            total > 900_000,
            "stored member should keep the zip large: {total}"
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let served = Arc::new(AtomicU64::new(0));
        let served_t = served.clone();
        let requests = Arc::new(AtomicU64::new(0));
        let requests_t = requests.clone();
        let blob_t = blob.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                requests_t.fetch_add(1, Ordering::SeqCst);
                let mut rdr = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if rdr.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut range: Option<String> = None;
                loop {
                    let mut h = String::new();
                    if rdr.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    let lower = h.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("range:") {
                        range = Some(v.trim().to_string());
                    }
                }
                let spec = range.unwrap_or_else(|| "bytes=0-".to_string());
                let spec = spec.trim_start_matches("bytes=");
                let mut it = spec.split('-');
                let a: usize = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
                let b = it.next().unwrap_or("").trim();
                let last = blob_t.len() - 1;
                let b: usize = if b.is_empty() {
                    last
                } else {
                    b.parse().unwrap_or(last)
                };
                let (a, b) = (a.min(last), b.min(last));
                let slice = &blob_t[a..=b];
                served_t.fetch_add(slice.len() as u64, Ordering::SeqCst);
                let hdr = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    a,
                    b,
                    blob_t.len(),
                    slice.len()
                );
                let _ = stream.write_all(hdr.as_bytes());
                let _ = stream.write_all(slice);
                let _ = stream.flush();
            }
        });

        let url = format!("http://{addr}/object.zip");
        let reader = crate::source::HttpRangeReader::open(&url).unwrap();
        let size = reader.len();
        assert_eq!(size as usize, total);
        let db = Scanner::builtin();
        let r = scan_seekable(&db, reader, size, &ScanOptions::default()).unwrap();
        assert!(
            matches!(r.verdict, Verdict::Infected { .. }),
            "should detect EICAR over HTTP range"
        );

        // What is bounded is MEMORY, not transfer. A range source may be read
        // more than once (the container is read again to run the checks that
        // need its whole bytes), so asserting a fraction of the object is
        // fetched would pin a property exav does not promise. What it does
        // promise is that a scan does not grow without limit: the object is
        // ~1 MB and is walked a small, constant number of times.
        let bytes = served.load(Ordering::SeqCst);
        assert!(
            bytes <= (total as u64) * 3,
            "fetched {bytes} of {total}; a scan should re-read the source a \
             small constant number of times, not unboundedly"
        );
        // Read straight through, each request continues the previous one and
        // fetches twice as much: 64 KiB, 128 KiB, ... rather than 16 of 64 KiB.
        let requests = requests.load(Ordering::SeqCst);
        assert!(
            requests <= 8,
            "{requests} range requests for a {total}-byte object"
        );
    }
}

/// The scan of an object read through a block cache answers as the scan of
/// the same bytes held in memory: same verdict, same detections.
#[cfg(test)]
mod parity {
    use super::*;
    use std::io::Cursor;

    /// Every fixture of this crate and of the extractors, de-obfuscated.
    fn fixtures() -> Vec<(String, Vec<u8>)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let path = e.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if let Ok(data) =
                    // `read_fixture` unmasks `<path>.xor` itself.
                    unpack::read_fixture(
                        path.to_string_lossy().trim_end_matches(".xor"),
                    )
                    && data.len() < 8 << 20
                {
                    out.push((path.display().to_string(), data));
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut out = Vec::new();
        walk(&root.join("tests/fixtures"), &mut out);
        walk(&root.join("../exav-unpack/tests/fixtures"), &mut out);
        out
    }

    fn database() -> Scanner {
        let mut b = loader::Builder::new();
        let eicar: String = unpack::eicar().iter().map(|b| format!("{b:02x}")).collect();
        b.add_named_bytes(
            "t.ndb",
            format!(
                "Test.Wild:0:*:4d5a90??03\nTest.Html:3:*:3c7363726970743e6576616c\n\
                 Test.Pe:1:EP+0:??\nTest.Eicar:0:*:{eicar}\n"
            )
            .as_bytes(),
            false,
        );
        b.add_named_bytes(
            "t.ldb",
            b"Test.Ldb;Engine:51-255,Target:0;0&1;504b0304;2e786d6c\n",
            false,
        );
        #[cfg(feature = "yara")]
        b.add_named_bytes(
            "t.yar",
            b"import \"pe\"\n\
              rule many_pk { strings: $a = \"PK\" condition: #a > 3 }\n\
              rule sections { condition: pe.number_of_sections > 2 }\n",
            false,
        );
        b.build().unwrap()
    }

    fn spilling(opts: &ScanOptions) -> ScanOptions {
        ScanOptions {
            spill: Some(std::sync::Arc::new(unpack::spill::MemSpill::new())),
            ..opts.clone()
        }
    }

    /// How the streamed scan of `data` differs from the in-memory one, if it
    /// does. Both have spill space, so a member too large to hold is scanned
    /// the same way on each.
    fn differs(db: &Scanner, data: &[u8], opts: &ScanOptions) -> Option<String> {
        let cache =
            byte_source::BlockCache::with_sizes(Cursor::new(data.to_vec()), 4093, 16 * 4093)
                .unwrap();
        let opts = &spilling(opts);
        let want = analyze(db, data, opts).verdict;
        let got = analyze_source(db, &cache, opts).verdict;
        if format!("{want:?}") != format!("{got:?}") {
            return Some(format!("verdict: memory {want:?}, streamed {got:?}"));
        }
        let size = data.len() as u64;
        let got = scan_seekable(db, Cursor::new(data), size, opts).map(|r| r.verdict);
        if format!("{:?}", Ok::<_, ()>(&want)) != format!("{:?}", got.as_ref().map_err(|_| ())) {
            return Some(format!("verdict: memory {want:?}, seekable {got:?}"));
        }
        let want = analyze_all_with_outcome(db, data, opts);
        let got = analyze_all_source(db, &cache, opts);
        if format!("{want:?}") != format!("{got:?}") {
            return Some(format!("all matches: memory {want:?}, streamed {got:?}"));
        }
        None
    }

    fn check(db: &Scanner, inputs: &[(String, Vec<u8>)], opts: &ScanOptions) {
        let mut wrong = Vec::new();
        for (name, data) in inputs {
            if let Some(d) = differs(db, data, opts) {
                wrong.push(format!("{name}: {d}"));
            }
        }
        assert!(
            wrong.is_empty(),
            "{} of {} differ:\n{}",
            wrong.len(),
            inputs.len(),
            wrong.join("\n")
        );
    }

    #[test]
    fn a_streamed_scan_answers_as_an_in_memory_one() {
        let inputs = fixtures();
        assert!(inputs.len() > 100, "the fixtures are where they were");
        let db = database();
        let opts = ScanOptions {
            heuristics: true,
            alert_broken: true,
            alert_broken_media: true,
            alert_partition_intersection: true,
            alert_phishing: true,
            structured_cc_count: Some(1),
            ..ScanOptions::default()
        };
        check(&db, &inputs, &opts);
    }

    /// What the scan answers for every fixture under a spread of settings, one
    /// line each: the verdict, the all-matches answer, and the verdict and the
    /// member path of the detection from `scan_seekable_located`. For
    /// comparing two trees (a refactor of the walk against the tree before it):
    /// `EXAV_DEBUG_PARITY_DUMP=<file> cargo test -p exav-core --lib parity::dump
    /// -- --ignored`, once on each, then `diff` the files.
    #[test]
    #[ignore = "writes a reference to compare trees with; needs EXAV_DEBUG_PARITY_DUMP"]
    fn dump() {
        use std::fmt::Write;
        let Ok(path) = std::env::var("EXAV_DEBUG_PARITY_DUMP") else {
            eprintln!("skip: EXAV_DEBUG_PARITY_DUMP unset");
            return;
        };
        let db = database();
        let base = ScanOptions {
            heuristics: true,
            alert_broken: true,
            alert_broken_media: true,
            alert_partition_intersection: true,
            alert_phishing: true,
            structured_cc_count: Some(1),
            ..ScanOptions::default()
        };
        let tiny = |mut o: ScanOptions| {
            o.limits.max_buffer_bytes = 4096;
            o
        };
        let settings = [
            ("default", base.clone()),
            ("hold-4k-spill", tiny(spilling(&base))),
            (
                "hold-4k-spill-small-cache",
                ScanOptions {
                    object_cache_block_bytes: 1024,
                    object_cache_bytes: 4096,
                    ..tiny(spilling(&base))
                },
            ),
            ("hold-4k-no-spill", tiny(base.clone())),
            ("depth-2", {
                let mut o = base.clone();
                o.limits.max_recursion = 2;
                o
            }),
        ];
        let mut inputs = fixtures();
        inputs.sort_by(|a, b| a.0.cmp(&b.0));
        let mut text = String::new();
        for (name, data) in &inputs {
            // The same name in any checkout: the crate, then the path in its fixtures.
            let (head, tail) = name.rsplit_once("/tests/fixtures/").unwrap_or(("", name));
            let krate = head.rsplit('/').next().unwrap_or("");
            for (label, opts) in &settings {
                let memory = analyze(&db, data, opts).verdict;
                let all = analyze_all_with_outcome(&db, data, opts);
                let size = data.len() as u64;
                let located = scan_seekable_located(&db, Cursor::new(data.clone()), size, opts)
                    .map(|(report, loc)| (report.verdict, loc));
                writeln!(
                    text,
                    "{krate}/{tail} | {label} | {memory:?} | {all:?} | {located:?}"
                )
                .unwrap();
            }
        }
        std::fs::write(&path, text).expect("write the dump");
        eprintln!("{} fixtures x {} settings", inputs.len(), settings.len());
    }

    /// The same, over a real database and a directory of samples:
    /// `EXAV_DEBUG_PARITY_DB=<.exavdb> EXAV_DEBUG_PARITY_CORPUS=<dir> cargo test
    /// -p exav-core --release --lib parity::corpus -- --ignored --nocapture`,
    /// and `EXAV_DEBUG_PARITY_LIMIT=<n>` for the first `n` samples.
    #[test]
    #[ignore = "needs a database and a corpus"]
    fn corpus() {
        let (Ok(db), Ok(dir)) = (
            std::env::var("EXAV_DEBUG_PARITY_DB"),
            std::env::var("EXAV_DEBUG_PARITY_CORPUS"),
        ) else {
            eprintln!("skip: EXAV_DEBUG_PARITY_DB / EXAV_DEBUG_PARITY_CORPUS unset");
            return;
        };
        let db = database::load(std::path::Path::new(&db)).expect("load the database");
        let limit: usize = std::env::var("EXAV_DEBUG_PARITY_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(usize::MAX);
        let opts = ScanOptions::default();
        let (mut seen, mut wrong) = (0, Vec::new());
        // One at a time: a corpus does not fit in memory.
        for e in walkdir_files(std::path::Path::new(&dir))
            .into_iter()
            .take(limit)
        {
            let Ok(data) = std::fs::read(&e) else {
                continue;
            };
            if data.len() >= 64 << 20 {
                continue;
            }
            seen += 1;
            if let Some(d) = differs(&db, &data, &opts) {
                eprintln!("DIFFERS {}: {d}", e.display());
                wrong.push(e.display().to_string());
            }
        }
        assert!(wrong.is_empty(), "{} of {seen} differ", wrong.len());
        eprintln!("{seen} samples, all the same");
    }

    fn walkdir_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        out.sort();
        out
    }
}
