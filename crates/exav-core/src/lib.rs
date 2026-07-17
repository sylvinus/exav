//! Streaming, size-unbounded file scanner.
//!
//! The pattern and whole-file-hash core ([`scan_stream`]) reads any input in
//! a single forward pass with constant memory, matching across internal
//! buffer boundaries, so file size is unbounded. Structural analysis
//! (archive extraction, PE parsing, ML/fuzzy) needs the whole object in
//! memory and so runs only for objects within [`ScanOptions::deep_analysis_max`].
//!
//! # Anti-evasion invariants
//!
//! A scanner's limits are an attack surface: anything that makes the scanner
//! *stop looking* is a bypass primitive an adversary will reach for (pad past a
//! size cap, nest past a depth cap, use an unsupported codec, …). These rules
//! are therefore load-bearing security properties, not mere ergonomics:
//!
//! 1. **A detection always beats a limit.** If a signature matches, the verdict
//!    is [`Verdict::Infected`] — never downgraded to `LimitsExceeded`/`Clean`
//!    because some *other* part of the input tripped a budget. Limits bound
//!    work; they never suppress a hit already found.
//! 2. **Never refuse by size without scanning.** A file over `--max-scan-size`
//!    is not skipped wholesale — the flat pattern/hash core is still run over
//!    the bytes within budget, so a detectable payload in the scanned prefix is
//!    reported. Only then, with nothing found, do we fall back to a limit
//!    verdict. (Otherwise `cat malware huge.pad > evil` is a one-line bypass.)
//! 3. **Not-fully-scanned is never `Clean`.** Anything we couldn't fully examine
//!    — a size/ratio/depth/scan-byte limit ([`Verdict::LimitsExceeded`]) or a
//!    recognised-but-undecodable container ([`Verdict::Unscannable`], e.g. an
//!    unsupported codec or encryption) — yields a distinct non-clean verdict.
//!    Callers must treat both as suspicious, never as a pass.
//!
//! Sizes and offsets are 64-bit throughout.

// The engine and every parser it drives are safe Rust. Enforce it: hostile
// input must never reach an `unsafe` block here (the only `unsafe` in the
// workspace is the CLI daemon's libc syscalls). `exav-unpack` forbids it too.
#![forbid(unsafe_code)]

// ---- Stable public API surface -------------------------------------------
// These modules are covered by semver. `filetype` is public because it is
// returned by `Database::identify`.
/// Authenticode (PE code-signing) triage without RSA — recompute the PE hash and
/// compare it to the signature's embedded digest, and extract signer-cert fields.
pub mod authenticode;
pub mod cache;
pub mod db;
/// Opt-in structured-data (DLP) heuristics: credit-card / SSN counting, a
/// data-exfiltration signal.
#[cfg(feature = "dlp")]
pub mod dlp;
pub mod filetype;
#[cfg(feature = "phishing")]
pub mod phishing;
pub mod profile;
pub mod source;
/// Archive/container extraction lives in its own crate; re-exported so
/// `exav_core::unpack` and the `ScanOptions::limits` type stay stable.
pub use exav_unpack as unpack;

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
            // so are unused within the lean build — don't warn on that (they are
            // exercised again once the feature re-exposes them). Scoped to the
            // engine internals only, so real dead code elsewhere still warns.
            #[cfg(not(feature = "unstable-internals"))]
            #[allow(dead_code, unused_imports, clippy::wrong_self_convention)]
            mod $m;
        )+
    };
}
engine_internals!(
    bytecode, container, cvd, engine, fuzzy, fuzzy_img, hashes, hexsig, icon, ml, normalize,
    patterns, pe, yara,
);

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use filetype::FileType;
use fuzzy::FuzzyDb;
use hashes::{digests_of, HashDb, SectionHashDb, TeeHasher};
use ml::Model;
use patterns::PatternSet;
use unpack::Budget;

/// Map a detected [`FileType`] to the extraction [`unpack::Format`], or `None`
/// if the type isn't an extractable container.
fn unpack_format(ft: FileType) -> Option<unpack::Format> {
    Some(match ft {
        FileType::Zip => unpack::Format::Zip,
        FileType::Gzip => unpack::Format::Gzip,
        FileType::Tar => unpack::Format::Tar,
        FileType::Bzip2 => unpack::Format::Bzip2,
        FileType::Xz => unpack::Format::Xz,
        FileType::Cab => unpack::Format::Cab,
        FileType::Chm => unpack::Format::Chm,
        FileType::Ole => unpack::Format::Ole,
        FileType::Pdf => unpack::Format::Pdf,
        FileType::Email => unpack::Format::Email,
        FileType::SevenZip => unpack::Format::SevenZip,
        FileType::Iso => unpack::Format::Iso,
        FileType::Lha => unpack::Format::Lha,
        FileType::Arj => unpack::Format::Arj,
        FileType::Rar => unpack::Format::Rar,
        FileType::Ar => unpack::Format::Ar,
        FileType::Cpio => unpack::Format::Cpio,
        FileType::Xar => unpack::Format::Xar,
        FileType::Zstd => unpack::Format::Zstd,
        FileType::Lzip => unpack::Format::Lzip,
        FileType::Uuencode => unpack::Format::Uuencode,
        FileType::Xdp => unpack::Format::Xdp,
        FileType::Szdd => unpack::Format::Szdd,
        FileType::Tnef => unpack::Format::Tnef,
        FileType::Swf => unpack::Format::Swf,
        FileType::Binhex => unpack::Format::Binhex,
        FileType::Lnk => unpack::Format::Lnk,
        FileType::Partition => unpack::Format::Partition,
        FileType::Pyc => unpack::Format::Pyc,
        FileType::Nsis => unpack::Format::Nsis,
        FileType::Machofat => unpack::Format::Machofat,
        FileType::Sfx => unpack::Format::Sfx,
        FileType::Autoit => unpack::Format::Autoit,
        FileType::OneNote => unpack::Format::OneNote,
        FileType::JavaClass => unpack::Format::JavaClass,
        FileType::AiModel => unpack::Format::AiModel,
        FileType::Screnc => unpack::Format::Screnc,
        FileType::Rtf => unpack::Format::Rtf,
        _ => return None,
    })
}

/// Like [`unpack_format`] but content-aware: also recognises a UPX-packed
/// executable (which is classified as a PE/ELF/Mach-O, not a container) so its
/// embedded original is decompressed and scanned.
fn unpack_target(ft: FileType, data: &[u8], restrict: bool) -> Option<unpack::Format> {
    if let Some(fmt) = unpack_format(ft) {
        // When restricted to ClamAV's extractor set, skip the formats stock
        // ClamAV lacks so a differential run doesn't count exav's extra reach as
        // a disagreement. Stock ClamAV has no `CL_TYPE_AR` (Unix archive /
        // `.deb` / `.a`) and no `CL_TYPE_LZIP`, so it extracts neither; it does
        // extract `cpio`, `xar` and UPX, so those must stay on even under compat
        // or exav would miss ClamAV detections.
        if restrict && matches!(fmt, unpack::Format::Ar | unpack::Format::Lzip) {
            return None;
        }
        return Some(fmt);
    }
    // UPX unpacking. ClamAV's UPX unpacker is invoked only from its PE scan path;
    // it never UPX-unpacks ELF or Mach-O. Under `restrict` (compat) we match that
    // scope so exav's broader reach — e.g. UPX-packed Mirai ELFs, which exav
    // decompresses and detects but ClamAV leaves packed and misses — isn't
    // counted as a disagreement. PE-UPX stays on either way (ClamAV does it too).
    if unpack::is_upx(data) {
        let upx_in_scope = if restrict {
            ft == FileType::Pe
        } else {
            ft.is_executable()
        };
        if upx_in_scope {
            return Some(unpack::Format::Upx);
        }
    }
    // Other PE runtime packers (Petite/FSG/NsPack/aPLib families are decompressed;
    // other packers are detected only). Checked after UPX since a file is packed
    // by at most one. Reproducing ClamAV's exact per-packer coverage isn't
    // practical, so under `restrict` (compat) these are gated off entirely: compat
    // deliberately trades reach for reproducibility (it is a differential-testing
    // mode, not for production — see the crate/CLI docs). Full capability stays in
    // normal mode. Only meaningful for PE (the detector requires a PE image), but
    // `is_executable` keeps it symmetric with UPX.
    if !restrict && ft.is_executable() && unpack::is_pepack(data) {
        return Some(unpack::Format::PePacked);
    }
    None
}

/// The container type that members extracted from a container of this `fmt`
/// (over `data`) belong to — used to enforce `Container:CL_TYPE_*` TDB
/// constraints on the members. `None` for formats exav doesn't map to a
/// container type (those constraints stay unenforced). A ZIP is further
/// classified into its OOXML sub-type (Word/Excel/PowerPoint) when it is an
/// Office Open XML document, since the signature format scopes many sigs to the
/// `CL_TYPE_OOXML_*` types rather than plain `CL_TYPE_ZIP`.
fn container_cltype(fmt: unpack::Format, data: &[u8]) -> Option<engine::ClType> {
    use engine::ClType;
    use unpack::Format;
    Some(match fmt {
        Format::Ole => ClType::Msole2,
        Format::Pdf => ClType::Pdf,
        Format::Email => ClType::Mail,
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
        _ => return None,
    })
}

/// Detect whether a ZIP is an Office Open XML document and which kind, by the
/// member names present in its central directory. A `.docx`/`.xlsx`/`.pptx` is
/// the `CL_TYPE_OOXML_*` container type (not plain `CL_TYPE_ZIP`) in the
/// signature format, and many sigs are scoped to those types; typing them this
/// way keeps such sigs firing on real Office documents while staying off plain
/// ZIPs. The marker is the conventional top-level part for each kind plus the
/// OOXML `[Content_Types].xml` package descriptor.
/// Bytes read from the front of a ZIP to detect its OOXML sub-type: the OOXML
/// part names (`[Content_Types].xml`, `word/document.xml`, …) sit in the leading
/// local file headers, so a bounded prefix reliably classifies real Office docs
/// without buffering a large archive.
const OOXML_DETECT_PREFIX: usize = 1 << 20;

fn ooxml_subtype(data: &[u8]) -> Option<engine::ClType> {
    use engine::ClType;
    // Cheap necessary condition: every OOXML package carries this part.
    if !contains_window(data, b"[Content_Types].xml") {
        return None;
    }
    if contains_window(data, b"word/document.xml") || contains_window(data, b"word/document2.xml") {
        Some(ClType::OoxmlWord)
    } else if contains_window(data, b"xl/workbook.xml") {
        Some(ClType::OoxmlXl)
    } else if contains_window(data, b"ppt/presentation.xml") {
        Some(ClType::OoxmlPpt)
    } else {
        None
    }
}

/// Substring search over raw bytes (the OOXML member names appear verbatim in
/// the ZIP central-directory file-name fields, which are stored uncompressed).
fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(haystack, needle).is_some()
}

/// Produce the final reported signature name from a matcher's CLEAN name plus
/// its per-signature `unofficial` provenance. In ClamAV-compat mode an
/// unofficial-database detection is suffixed `.UNOFFICIAL` (the `YARA.` prefix is
/// already part of the clean name the YARA matcher produces); otherwise, and for
/// official `.cvd` signatures, the clean name is reported verbatim. This is the
/// single point where the suffix is applied, so one loaded database/cache serves
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
pub enum Method {
    Pattern,
    Hash,
    Heuristic,
    Fuzzy,
    Ml,
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
            Method::Ml => "ml",
            Method::Bytecode => "bytecode",
            Method::Yara => "yara",
        }
    }
}

/// Outcome of scanning one input.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// NON-limit reason — an unsupported compression method (e.g. RAR PPMd).
    /// Distinct from `LimitsExceeded` (not a resource issue) and from `Clean`
    /// (we know there is content we couldn't examine). The `reason` names what
    /// was skipped.
    Unscannable {
        reason: String,
    },
    /// A member is encrypted: we recognised it but can't read its content
    /// without a password. Distinct from `Unscannable` because it is
    /// *actionable* — a caller can prompt for a password and re-scan with
    /// [`ScanOptions::password`] set. Takes precedence over `Unscannable` when
    /// both occur (it's the one the user can do something about).
    PasswordProtected {
        reason: String,
    },
}

/// Coarse classification of a [`Verdict`], the single source of truth for
/// summary counters and exit codes across every front-end (one-shot CLI, the
/// clamd daemon, and the daemon client). Keep counting/exit logic keyed on this
/// — never on the rendered string — so the three surfaces can't drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictCategory {
    /// Fully scanned, nothing found. Exit contribution: `0`.
    Clean,
    /// A signature matched. Exit contribution: `1`.
    Infected,
    /// Could not be fully examined (limit/undecodable/encrypted) — never a
    /// silent pass. Exit contribution: `2`.
    NotScanned,
}

impl Verdict {
    /// The coarse [`VerdictCategory`] for counters/exit codes.
    pub fn category(&self) -> VerdictCategory {
        match self {
            Verdict::Clean => VerdictCategory::Clean,
            Verdict::Infected { .. } => VerdictCategory::Infected,
            Verdict::LimitsExceeded { .. }
            | Verdict::Unscannable { .. }
            | Verdict::PasswordProtected { .. } => VerdictCategory::NotScanned,
        }
    }

    /// The clamscan/clamd status tag: `FOUND`, `OK`, `LIMITS-EXCEEDED`,
    /// `UNSCANNABLE`, or `PASSWORD-PROTECTED`. For `Infected` the signature name
    /// precedes this tag in output; for the others the [`Verdict::reason`] does.
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
    /// string for the not-scanned verdicts, `None` for `Clean`.
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

/// The serialised phishing-DB parts stored in the prebuilt cache: `(protected
/// domains, `M:` allow-list pairs, `X:` regex source pairs)`. Defined
/// unconditionally (the `phishing` feature only gates the *matcher*, not the
/// cache format) so a cache round-trips identically regardless of features.
pub(crate) type PhishingPartsOwned = (Vec<String>, Vec<(String, String)>, Vec<(String, String)>);

/// Full result of a scan.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanReport {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

impl ScanReport {
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

    /// Build an infected report from a core hit (clean name + provenance),
    /// applying the `.UNOFFICIAL` suffix at report time when `suffix` is set.
    fn infected_hit(hit: CoreHit, suffix: bool, findings: Vec<Finding>) -> Self {
        let (sig, offset, method, unofficial) = hit;
        Self::infected(
            report_name(&sig, unofficial, suffix),
            offset,
            method,
            findings,
        )
    }
    fn limits(reason: String, findings: Vec<Finding>) -> Self {
        Self {
            verdict: Verdict::LimitsExceeded { reason },
            findings,
        }
    }
    fn unscannable(reason: String, findings: Vec<Finding>) -> Self {
        Self {
            verdict: Verdict::Unscannable { reason },
            findings,
        }
    }
    fn password_protected(reason: String, findings: Vec<Finding>) -> Self {
        Self {
            verdict: Verdict::PasswordProtected { reason },
            findings,
        }
    }
}

/// Options controlling a scan and its limits.
#[derive(Clone)]
pub struct ScanOptions {
    /// Max bytes for a single top-level file. `None` = unlimited (default).
    /// Exceeding yields `LimitsExceeded`.
    pub max_scan_size: Option<u64>,
    /// Max object size eligible for in-memory structural/deep analysis
    /// (archive extraction, PE parse, ML/fuzzy). Larger objects are still
    /// stream-scanned (pattern+hash); the skipped structural step is
    /// reported as a finding. Default 256 MiB.
    pub deep_analysis_max: u64,
    /// Enable exav's *exclusive* structural heuristics: TLSH fuzzy matching, the
    /// static ML scorer (`Heuristics.ML.Suspect.*`), and the packed-with-injection
    /// heuristic. These have no stock-ClamAV analog, so they stay off under
    /// `--clamav-compat` (enabling them would count as false positives in a diff
    /// run). Archive extraction is always performed regardless of this flag.
    pub heuristics: bool,
    /// The heuristics stock ClamAV runs *by default* and that carry exact
    /// ClamAV-compatible names: `Heuristics.PDF.ObfuscatedNameObject` and imphash
    /// (`.imp`) matching. **On by default** — these are FP-safe (imphash is an
    /// exact DB signature; the PDF check counts only gratuitous escapes), so exav
    /// out of the box does every reasonable ClamAV-default match. Kept separate
    /// from [`heuristics`](Self::heuristics) so this parity subset stays on under
    /// `--clamav-compat` while the exav-exclusive TLSH/ML analysis (higher FP risk,
    /// no ClamAV analog) does not. `--heuristics` is the superset and implies this.
    pub clamav_heuristics: bool,
    /// Limits for recursive unpacking / bomb defenses.
    pub limits: unpack::Limits,
    /// Restrict exav's unpacking reach to stock ClamAV's, so a differential run
    /// against `clamscan` doesn't count exav's extra reach as a disagreement.
    /// Narrows three things to ClamAV's scope: (1) archive extractors — skip `ar`
    /// (Unix archive / `.deb` / `.a`) and `lzip`, which stock ClamAV lacks
    /// (verified against 1.4.x, which handles cpio/xar natively); (2) UPX — to PE
    /// only (ClamAV's UPX unpacker runs only from its PE path, never ELF/Mach-O);
    /// (3) other PE runtime packers (Petite/FSG/NsPack/aPLib) — off entirely, as
    /// their exact per-packer coverage can't be reproduced. Default off. This
    /// deliberately *reduces* exav's detection capability for reproducibility, so
    /// it is a diff-testing aid, **not for production** — it is one of the
    /// behaviours the CLI's `--clamav-compat` turns on.
    pub restrict_extractors: bool,
    /// Append `.UNOFFICIAL` (and the `YARA.` prefix) to signature names that come
    /// from unofficial databases, matching stock `clamscan`'s output. Purely
    /// cosmetic — it changes only how a detection is *named*, never whether it
    /// fires. Default off. (The other behaviour `--clamav-compat` turns on.)
    pub unofficial_suffix: bool,
    /// Password(s) to try when decrypting encrypted archive members. Empty by
    /// default. When a scan returns [`Verdict::PasswordProtected`], a caller can
    /// set this and re-scan. (The decryptors that consume it are a follow-up;
    /// the field is the stable API the verdict points callers to.)
    pub passwords: Vec<String>,
    /// Verify archive checksums (CRCs) during extraction. **Off by default** — a
    /// scanner scans decompressed content regardless of integrity metadata, so a
    /// corrupted checksum can't hide a payload from detection (this matches
    /// ClamAV, which ignores CRCs when scanning). Only has effect when exav-core
    /// is built with the `checksums` feature; otherwise checksums are never
    /// verified. Turn on only for extract-for-real use where a bad CRC is a
    /// genuine "corrupt file" signal.
    pub verify_checksums: bool,
    /// DLP structured-data heuristic (ClamAV `--structured-cc-count`): alert with
    /// `Heuristics.Structured.CreditCardNumber` when a textual buffer contains at
    /// least this many valid credit-card numbers. `None` (default) = off. Requires
    /// the `dlp` feature.
    pub structured_cc_count: Option<u32>,
    /// DLP structured-data heuristic (ClamAV `--structured-ssn-count`): alert with
    /// `Heuristics.Structured.SSN` when a textual buffer contains at least this
    /// many valid US SSNs. `None` (default) = off. Requires the `dlp` feature.
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
    /// Opt-in ClamAV heuristic (`--alert-broken-media`): report
    /// `Heuristics.Broken.Media.*` for a structurally invalid image/media file.
    /// Off by default; accepted/threaded as a no-op reservation for now.
    pub alert_broken_media: bool,
    /// Opt-in phishing heuristic (`--alert-phishing`, emitting ClamAV-compatible
    /// `Heuristics.Phishing.Email.*` names): report when an HTML/text buffer contains a
    /// link whose visible text spoofs a different domain than its `href`, hides
    /// the real host behind userinfo, or points at an IP literal under a brand
    /// name. Off by default.
    pub alert_phishing: bool,
    /// Opt-in Authenticode heuristic: report `Heuristics.Authenticode.HashMismatch`
    /// when a code-signed PE's embedded digest does NOT cover the current file
    /// bytes (i.e. the file was modified or had data appended after signing — a
    /// classic trojanized-signed-binary trick). Triage only: exav does not verify
    /// the RSA signature (see `authenticode`). Off by default.
    pub alert_broken_authenticode: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_scan_size: None,
            deep_analysis_max: 256 * 1024 * 1024,
            heuristics: false,
            // ClamAV-default matchings (PDF obfuscation, imphash) are on out of the
            // box — FP-safe and part of a faithful default scan. The exav-exclusive
            // TLSH/ML heuristics above stay opt-in.
            clamav_heuristics: true,
            limits: unpack::Limits::default(),
            restrict_extractors: false,
            unofficial_suffix: false,
            passwords: Vec::new(),
            verify_checksums: false,
            structured_cc_count: None,
            structured_ssn_count: None,
            alert_encrypted: false,
            alert_macros: false,
            alert_broken_media: false,
            alert_phishing: false,
            alert_broken_authenticode: false,
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
        Self {
            max_scan_size: Some(100 * 1024 * 1024),
            deep_analysis_max: 400 * 1024 * 1024,
            // exav-exclusive TLSH/ML stay off (they'd be diff-run false positives);
            // the ClamAV-default heuristics are on to match stock clamscan.
            heuristics: false,
            clamav_heuristics: true,
            limits: unpack::Limits {
                max_recursion: 17,
                max_files: 10_000,
                max_total_bytes: 400 * 1024 * 1024,
                ..unpack::Limits::default()
            },
            restrict_extractors: true,
            unofficial_suffix: true,
            passwords: Vec::new(),
            // ClamAV ignores CRCs when scanning — match it.
            verify_checksums: false,
            structured_cc_count: None,
            structured_ssn_count: None,
            alert_encrypted: false,
            alert_macros: false,
            alert_broken_media: false,
            alert_phishing: false,
            alert_broken_authenticode: false,
        }
    }
}

/// The loaded signature database and detection models.
///
/// Construct one with [`Database::builtin`], [`db::load`], or [`db::Loader`],
/// and query it through its methods. The fields hold internal engine types and
/// are crate-private (not part of the stable API); their layout may change
/// between releases.
pub struct Database {
    /// Literal patterns (EICAR + literal `.ndb`), also used on the streaming
    /// path where wildcard verification isn't possible.
    pub(crate) patterns: PatternSet,
    /// Full `.ndb`/`.ldb` matcher (wildcards, logical sigs); in-memory only.
    pub(crate) engine: engine::SigEngine,
    pub(crate) hashes: HashDb,
    /// `.mdb`/`.mdu`/`.msb` PE section-hash signatures.
    pub(crate) sections: SectionHashDb,
    pub(crate) fuzzy: FuzzyDb,
    /// `.cdb` container-metadata signatures.
    pub(crate) cdb: container::CdbDb,
    /// `.yar`/`.yara` YARA rules (via `yara-x`).
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
    /// [`filetype::identify`] is inconclusive (see [`Database::identify`]).
    pub(crate) ftm: filetype::FtmMagics,
    /// `.idb` PE-icon perceptual-hash database, used to satisfy `IconGroup1/2`
    /// constraints on logical signatures (see [`icon`]).
    pub(crate) icons: icon::IconDb,
    /// `.crb` Authenticode certificate block-list: a signed PE carrying a matching
    /// signer certificate is reported (identity match, no RSA verification).
    pub(crate) crb: authenticode::CrbDb,
    /// Passwords loaded from `.pwdb` files (ClamAV password database). Tried
    /// (unioned with [`ScanOptions::passwords`]) when decrypting encrypted
    /// archive members. The official CVDs ship none — this is user-supplied.
    pub(crate) passwords: Vec<String>,
    /// Version number and build-time of the newest loaded `.cvd`/`.cld` container
    /// (the one with the highest version — the daily set in a normal ClamAV DB
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
impl Database {
    pub fn engine(&self) -> &engine::SigEngine {
        &self.engine
    }

    /// Assemble a [`Database`] from individually-built subsystems over the
    /// [`Database::builtin`] baseline (which supplies `patterns`, `sections`,
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

impl Database {
    /// Passwords loaded from `.pwdb` files, tried (in addition to
    /// [`ScanOptions::passwords`]) when decrypting encrypted archive members.
    pub fn passwords(&self) -> &[String] {
        &self.passwords
    }

    /// Built-in baseline database (EICAR pattern, heuristic model).
    pub fn builtin() -> Self {
        // EICAR goes in the engine (used by in-memory scans) and in the
        // streaming PatternSet (used by stdin/pipe scans).
        let mut eb = engine::EngineBuilder::new();
        eb.add_literal("Exav.Test.EICAR", patterns::EICAR);
        Self {
            patterns: PatternSet::builtin(),
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
        let ft = filetype::identify(data);
        if ft == FileType::Unknown {
            if let Some(f) = self.ftm.identify(data) {
                return f;
            }
        }
        ft
    }

    pub fn signature_count(&self) -> usize {
        self.patterns.len()
            + self.engine.signature_count()
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
    /// for each program that detects with no unsupported op.
    pub fn run_bytecodes_forced(&self, data: &[u8]) -> Vec<(String, usize)> {
        self.bytecode.run_all_forced(data)
    }

    /// Source signatures that could not be loaded (e.g. unsupported `.ndb`
    /// wildcards, PCRE/bytecode subsignatures).
    pub fn unsupported_count(&self) -> usize {
        self.patterns.unsupported + self.engine.unsupported
    }
}

/// Scan a local file path (Seekable mode). The pattern+hash core handles
/// any size in constant memory; structural analysis runs for files within
/// `deep_analysis_max`.
pub fn scan_path(db: &Database, path: &Path, opts: &ScanOptions) -> io::Result<ScanReport> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    if let Some(max) = opts.max_scan_size {
        if size > max {
            // Invariant 2: don't refuse by size without looking. Run the flat
            // core over the budgeted prefix so a detection there is still
            // reported; only with nothing found do we return a (non-clean)
            // limit verdict for the unscanned remainder.
            if let Some(hit) = stream_core(db, (&file).take(max))? {
                return Ok(ScanReport::infected_hit(
                    hit,
                    opts.unofficial_suffix,
                    Vec::new(),
                ));
            }
            return Ok(ScanReport::limits(
                format!(
                    "file size {size} exceeds max-scan-size {max}; scanned first {max} bytes only"
                ),
                Vec::new(),
            ));
        }
    }

    let ft = peek_type(&file)?;

    // Natively-streaming containers (ZIP/tar/gzip) are walked member-by-member
    // off the file handle — the container is never buffered whole, so the
    // `deep_analysis_max` cap does not apply and an arbitrarily large on-disk
    // archive is scanned in bounded memory (one decoded member at a time). This
    // is what closes the ">deep-analysis-max archive hiding a payload" gap for
    // these formats: a 4 GiB `.tar.gz` is now unpacked, not skipped.
    if streams_natively(ft) {
        // Raw-container scan (whole-file hash + patterns over the compressed/
        // structural bytes), in constant memory — this preserves the whole-file
        // hash and raw-pattern detections that the buffered `analyze` path runs
        // via `scan_bytes_core` before unpacking. (A range-backed reader in
        // `scan_seekable` intentionally skips this so a range-GET fetches only the
        // members it scans; a local file always pays the cheap full read.)
        if let Some(hit) = stream_core(db, &file)? {
            return Ok(ScanReport::infected_hit(
                hit,
                opts.unofficial_suffix,
                Vec::new(),
            ));
        }
        return Ok(scan_container_stream(db, file, opts, ft));
    }

    if size <= opts.deep_analysis_max {
        // Read from the handle we already stat'd (no second open, no TOCTOU)
        // and bound the read so a special file whose metadata under-reports
        // its length (a FIFO/device reports 0) can't stream unbounded.
        let mut data = Vec::new();
        (&file)
            .take(opts.deep_analysis_max.saturating_add(1))
            .read_to_end(&mut data)?;
        if data.len() as u64 > opts.deep_analysis_max {
            return Ok(ScanReport::limits(
                format!("input exceeds deep-analysis-max {}", opts.deep_analysis_max),
                Vec::new(),
            ));
        }
        return Ok(analyze(db, &data, opts));
    }

    // Too large to buffer for structural analysis. Stream the pattern+hash
    // core; that alone is a complete scan for flat content.
    if let Some(hit) = stream_core(db, &file)? {
        return Ok(ScanReport::infected_hit(
            hit,
            opts.unofficial_suffix,
            Vec::new(),
        ));
    }
    // But an archive or executable can hide detections that only structural
    // parsing would find, and we skipped that. We cannot call it clean.
    if unpack_format(ft).is_some() || ft.is_executable() {
        return Ok(ScanReport::limits(
            format!(
                "{} is {size} bytes (> deep-analysis-max {}); contents not unpacked",
                ft.as_str(),
                opts.deep_analysis_max
            ),
            Vec::new(),
        ));
    }
    Ok(ScanReport::clean(vec![Finding::new(
        "type",
        format!("{} (flat content, fully scanned)", ft.as_str()),
    )]))
}

/// Read into `buf` until it is full or EOF, retrying short/interrupted reads.
/// Returns the number of bytes filled. Used so type identification never sees
/// a truncated prefix from a single short `read`.
fn fill_prefix<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Read a prefix to identify the type, then rewind so the caller can scan
/// from the start.
fn peek_type(file: &File) -> io::Result<FileType> {
    let mut prefix = [0u8; 4096];
    let mut r = file;
    let n = fill_prefix(&mut r, &mut prefix)?;
    let mut s = file;
    s.seek(SeekFrom::Start(0))?;
    Ok(filetype::identify(&prefix[..n]))
}

/// Scan a sequential stream (Stream mode): stdin, pipes, S3 streaming GET.
/// Runs the constant-memory pattern + hash core. (Structural analysis of
/// random-access formats needs a bounded buffer-upgrade or the seekable
/// backend — tracked for the S3 range-GET source.)
pub fn scan_stream<R: Read>(db: &Database, reader: R) -> io::Result<ScanReport> {
    // No `ScanOptions` here, so compat naming isn't applied: the streaming path
    // reports clean signature names (exav's default). Use [`scan_seekable`] /
    // [`scan_path`] (which take `ScanOptions`) when compat `.UNOFFICIAL` output is
    // required.
    if let Some(hit) = stream_core(db, reader)? {
        return Ok(suppress_name(
            db,
            ScanReport::infected_hit(hit, false, Vec::new()),
        ));
    }
    Ok(ScanReport::clean(Vec::new()))
}

thread_local! {
    /// Stack of container-member names for the scan in progress (deepest last).
    /// Pushed/popped by [`MatchPathGuard`] as the walk descends into members, so
    /// that at any detection point the joined stack is the member's location.
    static MATCH_PATH: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    /// The member path of the first detection recorded during the current scan,
    /// or `None` for a top-level (non-member) detection or a clean scan.
    static MATCH_LOC: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// RAII guard: pushes a (sanitized) container-member name onto [`MATCH_PATH`]
/// for the duration of that member's scan, popping it on drop. `let _mpg = …`
/// keeps it alive for the enclosing block.
struct MatchPathGuard;
impl MatchPathGuard {
    fn enter(name: &str) -> MatchPathGuard {
        MATCH_PATH.with(|p| p.borrow_mut().push(sanitize_member_name(name)));
        MatchPathGuard
    }
}
impl Drop for MatchPathGuard {
    fn drop(&mut self) {
        MATCH_PATH.with(|p| {
            p.borrow_mut().pop();
        });
    }
}

/// Record the current member path as the detection location, unless one is
/// already recorded (first detection wins, matching first-match scan
/// semantics). A no-op at top level (empty path) — a top-level detection has no
/// member location.
fn match_loc_record() {
    MATCH_PATH.with(|p| {
        let path = p.borrow();
        if path.is_empty() {
            return;
        }
        MATCH_LOC.with(|loc| {
            let mut loc = loc.borrow_mut();
            if loc.is_none() {
                *loc = Some(path.join("/"));
            }
        });
    });
}

/// Clear the per-scan location state at the start of a located scan.
fn match_loc_reset() {
    MATCH_PATH.with(|p| p.borrow_mut().clear());
    MATCH_LOC.with(|loc| *loc.borrow_mut() = None);
}

/// Take the recorded detection location, leaving `None` behind.
fn match_loc_take() -> Option<String> {
    MATCH_LOC.with(|loc| loc.borrow_mut().take())
}

/// Sanitize a container-member name for a reported location: strip control
/// characters and cap the length so a hostile archive can't inject terminal
/// escapes or unbounded strings into the location field.
fn sanitize_member_name(name: &str) -> String {
    const MAX: usize = 200;
    name.chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .take(MAX)
        .collect()
}

/// As [`scan_seekable`], additionally returning the container-member path of the
/// detection (e.g. `"inner.zip/evil.exe"`), or `None` for a top-level detection
/// or a clean scan. Used by the daemon's location-aware `EXINSTREAM` reply.
pub fn scan_seekable_located<R: Read + Seek>(
    db: &Database,
    reader: R,
    size: u64,
    opts: &ScanOptions,
) -> io::Result<(ScanReport, Option<String>)> {
    match_loc_reset();
    let report = scan_seekable(db, reader, size, opts)?;
    let loc = match_loc_take();
    Ok((report, loc))
}

/// Scan a seekable input (a local file, or [`source::HttpRangeReader`]). A ZIP
/// is read through the seekable reader, so only its central directory and the
/// members actually scanned are touched, and scanning stops at the first
/// detection — so a range-backed reader never fetches the rest. Non-ZIP
/// inputs within `deep_analysis_max` are buffered and analyzed; larger ones
/// fall back to the streaming pattern+hash core.
pub fn scan_seekable<R: Read + Seek>(
    db: &Database,
    mut reader: R,
    size: u64,
    opts: &ScanOptions,
) -> io::Result<ScanReport> {
    if let Some(max) = opts.max_scan_size {
        if size > max {
            // Invariant 2 (see crate docs): scan the budgeted prefix before
            // refusing by size, so a detection in it still wins.
            reader.seek(SeekFrom::Start(0))?;
            if let Some(hit) = stream_core(db, (&mut reader).take(max))? {
                return Ok(ScanReport::infected_hit(
                    hit,
                    opts.unofficial_suffix,
                    Vec::new(),
                ));
            }
            return Ok(ScanReport::limits(
                format!(
                    "file size {size} exceeds max-scan-size {max}; scanned first {max} bytes only"
                ),
                Vec::new(),
            ));
        }
    }
    let mut prefix = [0u8; 4096];
    let n = fill_prefix(&mut reader, &mut prefix)?;
    reader.seek(SeekFrom::Start(0))?;
    let ft = filetype::identify(&prefix[..n]);

    // Natively-streaming containers (ZIP/tar/gzip) are walked member-by-member
    // off the seekable source — the whole container is never buffered and no
    // `deep_analysis_max` cap applies, so an arbitrarily large on-disk archive is
    // scanned in bounded memory (one member at a time).
    if streams_natively(ft) {
        reader.seek(SeekFrom::Start(0))?;
        return Ok(scan_container_stream(db, reader, opts, ft));
    }

    if size <= opts.deep_analysis_max {
        let mut data = Vec::new();
        (&mut reader)
            .take(opts.deep_analysis_max.saturating_add(1))
            .read_to_end(&mut data)?;
        if data.len() as u64 > opts.deep_analysis_max {
            return Ok(ScanReport::limits(
                format!("input exceeds deep-analysis-max {}", opts.deep_analysis_max),
                Vec::new(),
            ));
        }
        return Ok(analyze(db, &data, opts));
    }

    // Large non-ZIP: stream the pattern+hash core from the start.
    if let Some(hit) = stream_core(db, &mut reader)? {
        return Ok(suppress_name(
            db,
            ScanReport::infected_hit(hit, opts.unofficial_suffix, Vec::new()),
        ));
    }
    if ft.is_executable() {
        return Ok(ScanReport::limits(
            format!(
                "{} is {size} bytes (> deep-analysis-max {}); not fully parsed",
                ft.as_str(),
                opts.deep_analysis_max
            ),
            Vec::new(),
        ));
    }
    Ok(ScanReport::clean(vec![Finding::new(
        "type",
        format!("{} (flat content, fully scanned)", ft.as_str()),
    )]))
}

/// Build an extraction [`Budget`] carrying the password pool for decrypting
/// encrypted archive members: the union of the database `.pwdb` pool and the
/// runtime [`ScanOptions::passwords`]. Runtime passwords are tried first (a
/// caller responding to a `PasswordProtected` verdict wins), then the `.pwdb`
/// pool; duplicates are dropped, preserving order.
fn scan_budget(db: &Database, opts: &ScanOptions) -> Budget {
    let mut pool: Vec<String> = Vec::with_capacity(opts.passwords.len() + db.passwords.len());
    for pw in opts.passwords.iter().chain(db.passwords.iter()) {
        if !pool.contains(pw) {
            pool.push(pw.clone());
        }
    }
    let mut b = Budget::with_passwords(opts.limits.clone(), pool);
    b.set_verify_checksums(opts.verify_checksums);
    b
}

/// Map an extraction [`unpack::LimitHit`] to the right top-level report: a
/// resource bound is `LimitsExceeded`; undecodable content is `Unscannable`.
fn report_for_hit(hit: unpack::LimitHit, findings: Vec<Finding>) -> ScanReport {
    if hit.corrupt {
        ScanReport::unscannable(hit.reason, findings)
    } else {
        ScanReport::limits(hit.reason, findings)
    }
}

/// As [`report_for_hit`] but for the recursive [`DeepOutcome`] path.
fn outcome_for_hit(hit: unpack::LimitHit) -> DeepOutcome {
    if hit.corrupt {
        DeepOutcome::Unscannable(hit.reason)
    } else {
        DeepOutcome::Limits(hit.reason)
    }
}

/// Container formats scanned member-by-member off the raw seekable source
/// **without holding the whole container in RAM**. Two mechanisms sit behind
/// this: gzip/tar use the low-level reader API ([`unpack::stream_members`]) so a
/// member is decoded on demand and a multi-gigabyte member is never materialized
/// (see [`scan_stream_member`]); ZIP uses the seekable [`unpack::Archive`] walk.
/// Either way the `deep_analysis_max` buffer no longer caps the container size —
/// a multi-gigabyte `.tar`/`.tar.gz`/`.zip`/`.gz` on disk is scanned in bounded
/// memory. Every other container still buffers (its decoder needs random access
/// over a slice), so it stays on the size-capped `analyze` path.
fn streams_natively(ft: FileType) -> bool {
    matches!(
        ft,
        FileType::Zip
            | FileType::Tar
            | FileType::Gzip
            | FileType::Zstd
            | FileType::Lzip
            | FileType::Lha
            | FileType::Ar
            | FileType::Cpio
            | FileType::Machofat
            | FileType::Pyc
            | FileType::Sfx
            | FileType::Tnef
            | FileType::Partition
            | FileType::Iso
            | FileType::OneNote
            | FileType::Swf
            | FileType::Szdd
            | FileType::SevenZip
            | FileType::Cab
    )
}

/// Outcome of scanning a single container member. Shared by the buffered
/// (`Archive`) and streamed (`stream_members`) walks so both apply identical
/// detection/suppression/precedence rules.
enum MemberScan {
    /// A detection that survived suppression (name-ignore + hash-allowlist).
    Infected(String, u64, Method),
    Limits(String),
    Unscannable(String),
    Password(String),
    Clean,
}

/// Scan a member whose bytes are fully in hand (`buf`): core pattern+hash, then
/// recursive structural analysis. The buffer is the caller's — for the streaming
/// path it is a bounded prefix owned high in `exav-core`, never allocated by the
/// low-level unpack layer.
fn scan_buffered_member(
    db: &Database,
    buf: &[u8],
    opts: &ScanOptions,
    budget: &mut Budget,
    depth: u32,
    container: Option<engine::ClType>,
    findings: &mut Vec<Finding>,
) -> MemberScan {
    // Pass the container context so `Container:CL_TYPE_*`-scoped signatures fire
    // on members of the intended container (e.g. an OOXML Word document's parts).
    if let Some((sig, off, method, unofficial)) = scan_bytes_member(db, buf, None, container) {
        let sig = report_name(&sig, unofficial, opts.unofficial_suffix);
        if !is_suppressed(db, buf, &sig) {
            return MemberScan::Infected(sig, off, method);
        }
    }
    match deep_analyze(db, buf, opts, budget, depth, container, true, findings) {
        DeepOutcome::Infected {
            signature,
            offset,
            method,
        } => {
            // The matched object isn't `buf` itself, so only the name-ignore
            // list applies (the hash allowlist is keyed on the whole member).
            if db.ignored.contains(&signature) {
                MemberScan::Clean
            } else {
                MemberScan::Infected(signature, offset, method)
            }
        }
        DeepOutcome::Limits(r) => MemberScan::Limits(r),
        DeepOutcome::Unscannable(r) => MemberScan::Unscannable(r),
        DeepOutcome::PasswordProtected(r) => MemberScan::Password(r),
        DeepOutcome::Clean => MemberScan::Clean,
    }
}

/// Scan a member presented as a **reader** (the low-level streaming API). A
/// bounded prefix — up to `deep_analysis_max` — is buffered here in `exav-core`
/// (the highest layer that can decide) so slice-based structural analysis runs
/// on members that fit. A member larger than the cap is *not* materialized: its
/// buffered prefix is chained with the still-streaming tail and pattern+hash
/// scanned end to end (so a signature anywhere in a 2 GiB member is found),
/// while structural/ML analysis is skipped — reported, never a silent Clean.
fn scan_stream_member(
    db: &Database,
    reader: &mut dyn Read,
    opts: &ScanOptions,
    budget: &mut Budget,
    depth: u32,
    container: Option<engine::ClType>,
    findings: &mut Vec<Finding>,
) -> MemberScan {
    let cap = opts.deep_analysis_max;
    let mut buf = Vec::new();
    let mut head = reader.take(cap.saturating_add(1));
    if let Err(e) = head.read_to_end(&mut buf) {
        if unpack::is_budget_overflow(&e) {
            return MemberScan::Limits(
                "member exceeds per-member decompression budget".to_string(),
            );
        }
        // A decode error still leaves the bytes decoded *before* the error in
        // `buf` — `Read::read_to_end` appends them. Scan that salvaged prefix so
        // malware in the recoverable part is caught (a truncated gzip/tar must
        // not hide its payload — observed on real samples).
        if !budget.should_verify_checksums() && !buf.is_empty() {
            buf.truncate(cap as usize);
            let scanned = scan_buffered_member(db, &buf, opts, budget, depth, container, findings);
            // We scanned every byte the stream yielded. If it simply ran out of
            // input (truncation — the missing tail is *absent*, not hidden), a
            // clean result is a real Clean: exav scans for malware, it is not a
            // file-integrity validator, so a damaged-but-payload-free file is not
            // flagged. A mid-stream *corruption* (undecodable bytes still present)
            // keeps the not-fully-scanned verdict on a clean salvage.
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return scanned;
            }
            return match scanned {
                MemberScan::Clean => MemberScan::Unscannable(format!(
                    "member decode error (salvaged {} B, no match): {e}",
                    buf.len()
                )),
                other => other,
            };
        }
        return MemberScan::Unscannable(format!("member decode error: {e}"));
    }
    if buf.len() as u64 <= cap {
        // Whole member in hand → full structural analysis on the bounded buffer.
        return scan_buffered_member(db, &buf, opts, budget, depth, container, findings);
    }
    // Member exceeds the structural-buffer cap: stream the whole thing through
    // the constant-memory pattern+hash core (prefix + tail chained so a match
    // straddling the boundary is still caught). No full-member buffer is held.
    let rest = head.into_inner();
    match stream_core(db, std::io::Cursor::new(&buf).chain(rest)) {
        Ok(Some((sig, off, method, unofficial))) => MemberScan::Infected(
            report_name(&sig, unofficial, opts.unofficial_suffix),
            off,
            method,
        ),
        Ok(None) => MemberScan::Unscannable(format!(
            "member exceeds deep-analysis-max {cap}; pattern-scanned, structural analysis skipped"
        )),
        Err(ref e) if unpack::is_budget_overflow(e) => {
            MemberScan::Limits("member exceeds per-member decompression budget".to_string())
        }
        Err(e) => MemberScan::Unscannable(format!("member stream error: {e}")),
    }
}

/// Scan a natively-streaming container ([`streams_natively`]) member-by-member
/// off a seekable source, stopping on the first detection. The container is
/// never fully buffered. gzip/tar go through the low-level reader API so a member
/// of any size is decoded on demand (see [`scan_stream_member`]); ZIP uses the
/// seekable [`unpack::Archive`] walk. Incomplete-scan signals (encrypted /
/// undecodable members) are accumulated and only surfaced after the whole
/// container is walked, so an early bad member can't mask a malicious sibling —
/// and "not fully scanned is never Clean" holds.
fn scan_container_stream<R: Read + Seek>(
    db: &Database,
    reader: R,
    opts: &ScanOptions,
    ft: FileType,
) -> ScanReport {
    let mut findings = vec![Finding::new("type", ft.as_str())];
    let mut budget = scan_budget(db, opts);
    let fmt = unpack_format(ft).unwrap_or(unpack::Format::Zip);
    let mut reader = reader;

    // Container `CL_TYPE_*` for `Container:`-scoped signatures, so each member
    // inherits it. A ZIP is sub-typed as OOXML Word/Excel/PowerPoint by its part
    // names; read a bounded prefix (the OOXML part names sit in the leading local
    // file headers) and rewind, so streamed OOXML members are scanned with the
    // right container context (e.g. `Container:CL_TYPE_OOXML_WORD` sigs fire).
    let container = if fmt == unpack::Format::Zip && db.engine.has_ooxml_container_sigs() {
        // Seek to the start FIRST: an earlier raw pass (`stream_core`) may have
        // consumed the reader to EOF, so reading without rewinding yields nothing.
        // Gated on the DB actually having `Container:CL_TYPE_OOXML_*` sigs: the
        // probe reads a leading prefix, which over a range-fetched source (HTTP)
        // would otherwise pull megabytes for a distinction nothing depends on.
        let _ = reader.seek(std::io::SeekFrom::Start(0));
        let mut prefix = vec![0u8; OOXML_DETECT_PREFIX];
        let n = fill_prefix(&mut reader, &mut prefix).unwrap_or(0);
        let _ = reader.seek(std::io::SeekFrom::Start(0));
        container_cltype(fmt, &prefix[..n])
    } else {
        container_cltype(fmt, &[])
    };

    if unpack::is_streamable(fmt) {
        return scan_streamed_container(
            db,
            reader,
            opts,
            fmt,
            ft,
            container,
            findings,
            &mut budget,
        );
    }

    // Non-streamable Archive-walkable containers: seekable member walk. Members
    // are still materialized one at a time by the Archive layer, but the container
    // is never buffered.
    let encrypted_name = encrypted_heuristic_name(fmt);
    // Container size for `.cdb` `ContainerSize` matching (seek to end, rewind).
    let container_size = reader
        .seek(std::io::SeekFrom::End(0))
        .and_then(|n| reader.seek(std::io::SeekFrom::Start(0)).map(|_| n))
        .unwrap_or(0);
    let mut archive = match unpack::Archive::open(reader) {
        Ok(a) => a,
        Err(h) => return report_for_hit(h, findings),
    };
    let mut unscannable: Option<String> = None;
    let mut password: Option<String> = None;
    // `.cdb` member position, 1-based (ClamAV `FilePos` counts from 1).
    let mut pos = 1u64;
    loop {
        let entry = match archive.extract_next(&mut budget) {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(h) => return report_for_hit(h, findings),
        };
        // Track this member on the location stack for the duration of its scan,
        // so a detection inside it (or a nested member) reports the full path.
        let _mpg = MatchPathGuard::enter(&entry.name);
        // `.cdb` container-metadata match on the member's name/size/pos/encryption
        // (matches even when the member body couldn't be decoded).
        if !db.cdb.is_empty() {
            let member = container::Member {
                name: &entry.name,
                size_in_container: entry.comp_size,
                size_real: entry.data.len() as u64,
                encrypted: entry.encrypted,
                pos,
            };
            if let Some((sig, unofficial)) = db.cdb.matches(ft, container_size, &member) {
                match_loc_record();
                return ScanReport::infected(
                    report_name(&sig, unofficial, opts.unofficial_suffix),
                    0,
                    Method::Hash,
                    findings,
                );
            }
        }
        pos += 1;
        if let Some(r) = entry.unsupported {
            if entry.encrypted {
                if opts.alert_encrypted {
                    match_loc_record();
                    return ScanReport::infected(
                        encrypted_name.to_string(),
                        0,
                        Method::Heuristic,
                        findings,
                    );
                }
                password.get_or_insert_with(|| r.to_string());
            } else {
                unscannable.get_or_insert_with(|| r.to_string());
            }
            continue;
        }
        match scan_buffered_member(
            db,
            &entry.data,
            opts,
            &mut budget,
            1,
            container,
            &mut findings,
        ) {
            MemberScan::Infected(sig, off, method) => {
                match_loc_record();
                return ScanReport::infected(sig, off, method, findings);
            }
            MemberScan::Limits(r) => return ScanReport::limits(r, findings),
            MemberScan::Unscannable(r) => {
                unscannable.get_or_insert(r);
            }
            MemberScan::Password(r) => {
                password.get_or_insert(r);
            }
            MemberScan::Clean => {}
        }
    }
    match (password, unscannable) {
        (Some(r), _) => ScanReport::password_protected(r, findings),
        (None, Some(r)) => ScanReport::unscannable(r, findings),
        (None, None) => ScanReport::clean(findings),
    }
}

/// Drive the low-level reader API ([`unpack::stream_members`]): each member is a
/// reader decoded on demand, scanned via [`scan_stream_member`] with no
/// full-member buffer. The visitor returns `Some(())` to halt the walk on a
/// terminal outcome (detection / limit), leaving the report in `terminal`.
#[allow(clippy::too_many_arguments)]
fn scan_streamed_container<R: Read + Seek>(
    db: &Database,
    reader: R,
    opts: &ScanOptions,
    fmt: unpack::Format,
    ft: FileType,
    container: Option<engine::ClType>,
    mut findings: Vec<Finding>,
    budget: &mut Budget,
) -> ScanReport {
    let encrypted_name = encrypted_heuristic_name(fmt);
    // Container size for `.cdb` `ContainerSize` matching (seek to end, rewind).
    let mut reader = reader;
    let container_size = reader
        .seek(std::io::SeekFrom::End(0))
        .and_then(|n| reader.seek(std::io::SeekFrom::Start(0)).map(|_| n))
        .unwrap_or(0);
    let mut unscannable: Option<String> = None;
    let mut password: Option<String> = None;
    let mut terminal: Option<ScanReport> = None;
    // `.cdb` member position, 1-based (ClamAV `FilePos` counts from 1).
    let mut pos = 1u64;
    let walk = {
        let findings = &mut findings;
        let unscannable = &mut unscannable;
        let password = &mut password;
        let terminal = &mut terminal;
        let pos = &mut pos;
        let mut visit = |meta: &unpack::MemberMeta,
                         rdr: Option<&mut dyn Read>,
                         budget: &mut Budget|
         -> Option<()> {
            // Track this member on the location stack for its scan (see
            // [`MatchPathGuard`]) so a detection reports the member path.
            let _mpg = MatchPathGuard::enter(&meta.name);
            // `.cdb` container-metadata match on the member's name/size/pos/
            // encryption (fires even when the body can't be decoded — the streamed
            // path is how ZIP/OOXML members reach this, so filename sigs like
            // `Archive.Filetype.*` are matched here).
            if !db.cdb.is_empty() {
                let member = container::Member {
                    name: &meta.name,
                    size_in_container: meta.comp_size,
                    size_real: meta.comp_size,
                    encrypted: meta.encrypted,
                    pos: *pos,
                };
                if let Some((sig, unofficial)) = db.cdb.matches(ft, container_size, &member) {
                    match_loc_record();
                    *terminal = Some(ScanReport::infected(
                        report_name(&sig, unofficial, opts.unofficial_suffix),
                        0,
                        Method::Hash,
                        std::mem::take(findings),
                    ));
                    return Some(());
                }
            }
            *pos += 1;
            if let Some(r) = meta.unsupported {
                if meta.encrypted {
                    // Opt-in ClamAV heuristic (`--alert-encrypted`): an encrypted
                    // member is a detection under the flag; otherwise it surfaces
                    // as the actionable PasswordProtected verdict.
                    if opts.alert_encrypted {
                        match_loc_record();
                        *terminal = Some(ScanReport::infected(
                            encrypted_name.to_string(),
                            0,
                            Method::Heuristic,
                            std::mem::take(findings),
                        ));
                        return Some(());
                    }
                    password.get_or_insert_with(|| r.to_string());
                } else {
                    unscannable.get_or_insert_with(|| r.to_string());
                }
                return None;
            }
            let rdr = rdr?;
            match scan_stream_member(db, rdr, opts, budget, 1, container, findings) {
                MemberScan::Infected(sig, off, method) => {
                    match_loc_record();
                    *terminal = Some(ScanReport::infected(
                        sig,
                        off,
                        method,
                        std::mem::take(findings),
                    ));
                    Some(())
                }
                MemberScan::Limits(r) => {
                    *terminal = Some(ScanReport::limits(r, std::mem::take(findings)));
                    Some(())
                }
                MemberScan::Unscannable(r) => {
                    unscannable.get_or_insert(r);
                    None
                }
                MemberScan::Password(r) => {
                    password.get_or_insert(r);
                    None
                }
                MemberScan::Clean => None,
            }
        };
        unpack::stream_members(fmt, reader, budget, &mut visit)
    };
    if let Err(h) = walk {
        return report_for_hit(h, findings);
    }
    if let Some(r) = terminal {
        return r;
    }
    match (password, unscannable) {
        (Some(r), _) => ScanReport::password_protected(r, findings),
        (None, Some(r)) => ScanReport::unscannable(r, findings),
        (None, None) => ScanReport::clean(findings),
    }
}

/// Full in-memory analysis of a bounded buffer: core detection, then
/// recursive unpacking and (optionally) structural/ML/fuzzy heuristics.
pub fn analyze(db: &Database, data: &[u8], opts: &ScanOptions) -> ScanReport {
    let report = analyze_inner(db, data, opts);
    suppress(db, data, report)
}

fn analyze_inner(db: &Database, data: &[u8], opts: &ScanOptions) -> ScanReport {
    if let Some((sig, off, method, unofficial)) = scan_bytes_core(db, data) {
        return ScanReport::infected(
            report_name(&sig, unofficial, opts.unofficial_suffix),
            off,
            method,
            Vec::new(),
        );
    }
    let mut findings = Vec::new();
    let mut budget = scan_budget(db, opts);
    match deep_analyze(db, data, opts, &mut budget, 0, None, true, &mut findings) {
        DeepOutcome::Infected {
            signature,
            offset,
            method,
        } => ScanReport::infected(signature, offset, method, findings),
        DeepOutcome::Limits(reason) => ScanReport::limits(reason, findings),
        // "Not-fully-scanned is never Clean" holds in EVERY mode — exav never
        // downgrades a real safety verdict to `Clean` to mimic clam's silent
        // `OK`. compat matches clam's capabilities and naming, not this. (A diff
        // harness should bucket exav-`UNSCANNABLE` vs clam-`OK` as an expected
        // capability difference, not have exav lie.)
        DeepOutcome::Unscannable(reason) => ScanReport::unscannable(reason, findings),
        DeepOutcome::PasswordProtected(reason) => ScanReport::password_protected(reason, findings),
        DeepOutcome::Clean => ScanReport::clean(findings),
    }
}

/// True if a detection of `signature` on `data` should be suppressed: the
/// name is on the ignore list (`.ign`/`.ign2`) or `data`'s whole-file hash is
/// allowlisted (`.fp`/`.sfp`).
fn is_suppressed(db: &Database, data: &[u8], signature: &str) -> bool {
    db.ignored.contains(signature)
        || (!db.allow.is_empty()
            && db
                .allow
                .lookup(&digests_of(data), data.len() as u64)
                .is_some())
}

/// Clear a detection if it is suppressed (see [`is_suppressed`]).
fn suppress(db: &Database, data: &[u8], report: ScanReport) -> ScanReport {
    if let Verdict::Infected { signature, .. } = &report.verdict {
        if is_suppressed(db, data, signature) {
            return ScanReport::clean(report.findings);
        }
    }
    report
}

/// Name-only suppression for the streaming paths, where the whole object is
/// not buffered so the `.fp`/`.sfp` hash allowlist cannot be evaluated (it
/// would require reading the entire stream, defeating the early-exit). The
/// `.ign`/`.ign2` name ignore-list needs no data and is always applied.
fn suppress_name(db: &Database, report: ScanReport) -> ScanReport {
    if let Verdict::Infected { signature, .. } = &report.verdict {
        if db.ignored.contains(signature) {
            return ScanReport::clean(report.findings);
        }
    }
    report
}

/// Every signature that matches `data` or its (recursively unpacked) members,
/// de-duplicated by name — the data behind `--allmatch`. Section and whole-file
/// hashes plus the wildcard/logical engine are collected; single-verdict
/// heuristics/ML are not. An allowlisted file yields nothing; ignored names are
/// dropped (the same suppression as a normal scan).
pub fn analyze_all(db: &Database, data: &[u8], opts: &ScanOptions) -> Vec<(String, Method)> {
    if !db.allow.is_empty()
        && db
            .allow
            .lookup(&digests_of(data), data.len() as u64)
            .is_some()
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut budget = scan_budget(db, opts);
    collect_all(
        db,
        data,
        &mut budget,
        0,
        &mut out,
        &mut seen,
        opts.restrict_extractors,
        opts.unofficial_suffix,
        None,
    );
    out
}

#[allow(clippy::too_many_arguments)]
fn collect_all(
    db: &Database,
    data: &[u8],
    budget: &mut Budget,
    depth: u32,
    out: &mut Vec<(String, Method)>,
    seen: &mut std::collections::HashSet<String>,
    restrict_extractors: bool,
    unofficial_suffix: bool,
    container: Option<engine::ClType>,
) {
    let ft = db.identify(data);
    let layout = if ft == FileType::Pe {
        pe::layout(data)
    } else {
        None
    };
    let icon_metrics = if ft == FileType::Pe && !db.icons.is_empty() {
        icon::pe_icon_metrics(data)
    } else {
        Vec::new()
    };
    let icon_ctx = engine::IconCtx::new(&db.icons, &icon_metrics);
    let mut eng = Vec::new();
    db.engine.scan_all_with_icons(
        data,
        ft,
        layout.as_ref(),
        container,
        Some(&icon_ctx),
        &mut eng,
    );
    if !db.engine.is_empty() && normalize::is_textual(data) {
        let mut norms = vec![normalize::html(data), normalize::text(data)];
        if looks_like_script(ft, data) {
            norms.push(normalize::javascript(data));
        }
        for norm in norms {
            db.engine
                .scan_all_with_layout(&norm, ft, None, container, &mut eng);
        }
    }
    for (name, _, unofficial) in eng {
        push_sig(
            db,
            out,
            seen,
            name,
            unofficial,
            unofficial_suffix,
            Method::Pattern,
        );
    }
    if !db.sections.is_empty() && ft == FileType::Pe {
        let want_sha = db.sections.wants_sha();
        for (size, slice) in pe::section_slices(data) {
            let d = hashes::section_digests(slice, want_sha);
            if let Some((name, unofficial)) = db.sections.lookup(size, &d) {
                push_sig(
                    db,
                    out,
                    seen,
                    name,
                    unofficial,
                    unofficial_suffix,
                    Method::Hash,
                );
            }
        }
    }
    if !db.hashes.is_empty() {
        if let Some((name, unofficial)) = db.hashes.lookup(&digests_of(data), data.len() as u64) {
            push_sig(
                db,
                out,
                seen,
                name,
                unofficial,
                unofficial_suffix,
                Method::Hash,
            );
        }
    }
    // Bytecode programs (the normal scan path runs these; all-match must too,
    // or it silently misses every bytecode detection). Surface the detection
    // and recurse into any buffers a bytecode unpacker extracted. Bytecode names
    // are reported verbatim (never `.UNOFFICIAL`-suffixed).
    if !db.bytecode.is_empty() {
        let (det, extracted) = db.bytecode.scan(data, ft, layout.as_ref());
        if let Some((name, _)) = det {
            push_sig(
                db,
                out,
                seen,
                name,
                false,
                unofficial_suffix,
                Method::Bytecode,
            );
        }
        if depth < budget.limits.max_recursion {
            for buf in extracted {
                collect_all(
                    db,
                    &buf,
                    budget,
                    depth + 1,
                    out,
                    seen,
                    restrict_extractors,
                    unofficial_suffix,
                    None,
                );
            }
        }
    }
    if let (Some(fmt), true) = (
        unpack_target(ft, data, restrict_extractors),
        depth < budget.limits.max_recursion,
    ) {
        // All-match: visit every member (never stop early), collecting detections
        // from each and recursing. Streams one member at a time to bound memory.
        let container_size = data.len() as u64;
        let member_container = container_cltype(fmt, data);
        let mut pos = 1u64;
        let _ = unpack::extract_each::<std::convert::Infallible>(
            fmt,
            data,
            budget,
            &mut |e: unpack::Entry, budget: &mut Budget| {
                // `.cdb` `FilePos` counts members from 1, matching ClamAV (`pos`
                // is seeded to 1). A sig with `FilePos:1` targets the first member.
                let member_pos = pos;
                pos += 1;
                if !db.cdb.is_empty() {
                    let member = container::Member {
                        name: &e.name,
                        size_in_container: e.comp_size,
                        size_real: e.data.len() as u64,
                        encrypted: e.encrypted,
                        pos: member_pos,
                    };
                    if let Some((sig, unofficial)) = db.cdb.matches(ft, container_size, &member) {
                        push_sig(
                            db,
                            out,
                            seen,
                            sig,
                            unofficial,
                            unofficial_suffix,
                            Method::Hash,
                        );
                    }
                }
                collect_all(
                    db,
                    &e.data,
                    budget,
                    depth + 1,
                    out,
                    seen,
                    restrict_extractors,
                    unofficial_suffix,
                    member_container,
                );
                None
            },
        );
    }

    // Embedded PE/ELF images (same as the first-match path in `deep_analyze`),
    // so `--allmatch` doesn't miss a detection on an appended/embedded executable.
    if depth < budget.limits.max_recursion {
        let embedded = pe::embedded_pe_offsets(data)
            .into_iter()
            .chain(pe::embedded_elf_offsets(data))
            .chain(pe::embedded_macho_offsets(data));
        for off in embedded {
            let sub = &data[off..];
            // Same cumulative scan-byte cap as the first-match path: stop carving
            // once the budget is spent (best effort — all-match has no verdict to
            // return, but the deterministic cap still bounds the work).
            if budget.charge_scan(sub.len() as u64).is_err() {
                break;
            }
            // Carved image inherits the container its host sits in.
            collect_all(
                db,
                sub,
                budget,
                depth + 1,
                out,
                seen,
                restrict_extractors,
                unofficial_suffix,
                container,
            );
        }

        // Embedded archives appended to / stapled inside a carrier — same as the
        // first-match path in `deep_analyze`, so `--allmatch` doesn't miss a
        // detection in an appended ZIP/CAB/7z/RAR overlay. Validated by the
        // unpacker's `detect` before recursing.
        for off in pe::embedded_archive_offsets(data) {
            let sub = &data[off..];
            if unpack::detect(sub).is_none() {
                continue;
            }
            if budget.charge_scan(sub.len() as u64).is_err() {
                break;
            }
            collect_all(
                db,
                sub,
                budget,
                depth + 1,
                out,
                seen,
                restrict_extractors,
                unofficial_suffix,
                container,
            );
        }
    }
}

fn push_sig(
    db: &Database,
    out: &mut Vec<(String, Method)>,
    seen: &mut std::collections::HashSet<String>,
    name: String,
    unofficial: bool,
    suffix: bool,
    method: Method,
) {
    // Apply the `.UNOFFICIAL` suffix before the ignore-list check (the
    // `.ign`/`.ign2` entry names the suffixed detection) and before de-dup.
    let name = report_name(&name, unofficial, suffix);
    if db.ignored.contains(&name) {
        return;
    }
    if seen.insert(name.clone()) {
        out.push((name, method));
    }
}

enum DeepOutcome {
    Clean,
    Infected {
        signature: String,
        offset: u64,
        method: Method,
    },
    Limits(String),
    /// A member was recognised but couldn't be decoded (unsupported method).
    /// Unlike `Limits` it does NOT stop scanning sibling members — it's
    /// remembered and surfaced only if nothing infected is found.
    Unscannable(String),
    /// An encrypted member: like `Unscannable` but actionable (re-scan with a
    /// password). Takes precedence over `Unscannable`.
    PasswordProtected(String),
}

/// Stream a nested single-stream compressor (gzip/zstd/lzip) at recursion
/// `depth`: its decompressed content is scanned via [`scan_stream_member`] as a
/// reader, so a nested stream decompressing to gigabytes is scanned in full with
/// RAM bounded by `deep_analysis_max` — rather than being decoded into a
/// `max_entry_bytes`-capped `Vec` by [`unpack::extract_each`]. `container` is the
/// compressor's `CL_TYPE_*` so the content is scanned in the right context.
#[allow(clippy::too_many_arguments)]
fn deep_analyze_streamed(
    db: &Database,
    data: &[u8],
    fmt: unpack::Format,
    opts: &ScanOptions,
    budget: &mut Budget,
    depth: u32,
    container: Option<engine::ClType>,
    findings: &mut Vec<Finding>,
) -> DeepOutcome {
    let mut unscannable: Option<String> = None;
    let mut password: Option<String> = None;
    let mut terminal: Option<DeepOutcome> = None;
    let walk = {
        let findings = &mut *findings;
        let unscannable = &mut unscannable;
        let password = &mut password;
        let terminal = &mut terminal;
        let mut visit = |meta: &unpack::MemberMeta,
                         rdr: Option<&mut dyn Read>,
                         budget: &mut Budget|
         -> Option<()> {
            // A single-stream compressor never yields an undecodable member.
            let _mpg = MatchPathGuard::enter(&meta.name);
            let rdr = rdr?;
            match scan_stream_member(db, rdr, opts, budget, depth + 1, container, findings) {
                MemberScan::Infected(signature, offset, method) => {
                    match_loc_record();
                    *terminal = Some(DeepOutcome::Infected {
                        signature,
                        offset,
                        method,
                    });
                    Some(())
                }
                MemberScan::Limits(r) => {
                    *terminal = Some(DeepOutcome::Limits(r));
                    Some(())
                }
                MemberScan::Unscannable(r) => {
                    unscannable.get_or_insert(r);
                    None
                }
                MemberScan::Password(r) => {
                    password.get_or_insert(r);
                    None
                }
                MemberScan::Clean => None,
            }
        };
        unpack::stream_members(fmt, std::io::Cursor::new(data), budget, &mut visit)
    };
    if let Err(h) = walk {
        return outcome_for_hit(h);
    }
    if let Some(o) = terminal {
        return o;
    }
    match (password, unscannable) {
        (Some(r), _) => DeepOutcome::PasswordProtected(r),
        (None, Some(r)) => DeepOutcome::Unscannable(r),
        (None, None) => DeepOutcome::Clean,
    }
}

/// Recursive structural analysis of an in-memory buffer.
#[allow(clippy::too_many_arguments)]
fn deep_analyze(
    db: &Database,
    data: &[u8],
    opts: &ScanOptions,
    budget: &mut Budget,
    depth: u32,
    // Container type this buffer sits inside (for `Container:CL_TYPE_*` scoping),
    // threaded so embedded/nested content inherits it rather than over-matching.
    container: Option<engine::ClType>,
    // Whether to enumerate embedded PE/ELF/Mach-O images in this buffer. False
    // when we were *reached by* embedded-carving: the parent already enumerated
    // every embedded offset in the larger buffer (a carved suffix is a subset),
    // so re-carving here would rescan the same overlapping regions — the source
    // of large scan-amplification. We still extract archives + run heuristics on
    // the carved image (so an appended archive in a dropper is not missed).
    carve: bool,
    findings: &mut Vec<Finding>,
) -> DeepOutcome {
    let ft = db.identify(data);
    if depth == 0 {
        findings.push(Finding::new("type", ft.as_str()));
    }

    // ClamAV `Heuristics.PDF.ObfuscatedNameObject`: a PDF whose name objects
    // hex-escape plain alphanumerics (`/J#61vaScript`, `/Ope#6eAction`) to hide
    // keywords from naive scanners. Structural and FP-safe (only gratuitous
    // escapes count). A ClamAV default heuristic, so on by default via
    // `clamav_heuristics` (`--heuristics` enables it too). Checked here (before the
    // PDF is unpacked) so it applies to the raw document structure.
    #[cfg(feature = "pdf")]
    if (opts.clamav_heuristics || opts.heuristics)
        && ft == FileType::Pdf
        && unpack::has_obfuscated_name_object(data)
    {
        return DeepOutcome::Infected {
            signature: "Heuristics.PDF.ObfuscatedNameObject".to_string(),
            offset: 0,
            method: Method::Heuristic,
        };
    }

    // Archives (and UPX-packed executables) are unpacked regardless of the
    // heuristics flag.
    if let Some(fmt) = unpack_target(ft, data, opts.restrict_extractors) {
        if depth >= budget.limits.max_recursion {
            return DeepOutcome::Limits(format!(
                "recursion depth exceeds {}",
                budget.limits.max_recursion
            ));
        }
        // Single-stream compressors (gzip/zstd/lzip) decompress to ONE member
        // with no per-member `.cdb`/OLE metadata. Stream that member's reader so a
        // nested stream that decompresses to gigabytes is scanned in full (in RAM
        // bounded by `deep_analysis_max`) instead of being truncated at
        // `max_entry_bytes` by the buffered `extract_each` path. The decompressed
        // content keeps this container's `CL_TYPE_*` context so `Container:`-scoped
        // signatures still fire; nothing is lost vs the buffered path here.
        if matches!(
            fmt,
            unpack::Format::Gzip | unpack::Format::Zstd | unpack::Format::Lzip
        ) {
            let member_container = container_cltype(fmt, data);
            return deep_analyze_streamed(
                db,
                data,
                fmt,
                opts,
                budget,
                depth,
                member_container,
                findings,
            );
        }
        // Stream members one at a time: scan + recurse into each, stopping (and
        // not decompressing the rest) on the first detection. `pos` is the
        // member's 1-based position in this container (for `.cdb` matching).
        let container_size = data.len() as u64;
        let container_is_ole = fmt == unpack::Format::Ole;
        // The container type each extracted member belongs to, so signatures
        // scoped with `Container:CL_TYPE_*` fire only inside their intended
        // container (computed once per container; a ZIP is sub-typed as OOXML
        // Word/Excel/PowerPoint when applicable).
        let member_container = container_cltype(fmt, data);
        let mut pos = 1u64;
        // A member we recognised but couldn't decode is remembered here — it
        // must not be reported clean, but it also must not stop us scanning the
        // remaining members. Encrypted members are tracked separately so the
        // (actionable) PasswordProtected verdict can take precedence.
        let mut unscannable: Option<String> = None;
        let mut password: Option<String> = None;
        let outcome =
            unpack::extract_each(fmt, data, budget, &mut |e: unpack::Entry,
                                                          budget: &mut Budget|
             -> Option<DeepOutcome> {
                // Track this member on the location stack for its scan (see
                // [`MatchPathGuard`]); a detection here or in a nested member
                // reports the full path.
                let _mpg = MatchPathGuard::enter(&e.name);
                // `.cdb` container-metadata signatures match on the member's
                // name/size/encryption/position within this container. `FilePos`
                // counts members from 1, matching ClamAV (`pos` seeded to 1).
                let member_pos = pos;
                pos += 1;
                // The member's metadata (name/size/pos) is still valid even when
                // its content couldn't be decompressed, so `.cdb` matching below
                // still runs; record that its bytes went unscanned.
                if let Some(r) = e.unsupported {
                    if e.encrypted {
                        // Opt-in ClamAV heuristic (`--alert-encrypted`): treat an
                        // encrypted member as a detection, upgrading the default
                        // actionable PasswordProtected verdict to
                        // `Heuristics.Encrypted.*`. A detection beats a limit, so
                        // return eagerly. Off by default → verdict untouched.
                        if opts.alert_encrypted {
                            match_loc_record();
                            return Some(DeepOutcome::Infected {
                                signature: encrypted_heuristic_name(fmt).to_string(),
                                offset: 0,
                                method: Method::Heuristic,
                            });
                        }
                        password.get_or_insert_with(|| r.to_string());
                    } else {
                        unscannable.get_or_insert_with(|| r.to_string());
                    }
                }
                // Opt-in ClamAV heuristic (`--alert-macros`): an OLE2 document
                // carrying a VBA project surfaces `vba_project*` artifacts from the
                // OLE extractor — their presence means the document has macros.
                if opts.alert_macros && container_is_ole && is_vba_member(&e.name) {
                    match_loc_record();
                    return Some(DeepOutcome::Infected {
                        signature: "Heuristics.OLE2.ContainsMacros".to_string(),
                        offset: 0,
                        method: Method::Heuristic,
                    });
                }
                if !db.cdb.is_empty() {
                    let member = container::Member {
                        name: &e.name,
                        size_in_container: e.comp_size,
                        size_real: e.data.len() as u64,
                        encrypted: e.encrypted,
                        pos: member_pos,
                    };
                    if let Some((sig, unofficial)) =
                        profile::timed("cdb", 0, || db.cdb.matches(ft, container_size, &member))
                    {
                        match_loc_record();
                        return Some(DeepOutcome::Infected {
                            signature: report_name(&sig, unofficial, opts.unofficial_suffix),
                            offset: 0,
                            method: Method::Hash,
                        });
                    }
                }
                // Textual content extracted from an OLE2 document is scanned in
                // OLE context: its type is forced to MSOLE2 so `Target:2` macro
                // sigs apply and `Target:7` (ascii-text) sigs do NOT — without
                // this a generic text macro sig (e.g. `Doc.Downloader.Macro-25`
                // on the standard `Name="Project"…` PROJECT stream)
                // false-positives on benign macro documents. Binary streams (an
                // embedded PE, etc.) keep their own type so embedded-executable
                // detection is preserved. Either way the member carries its
                // container type so `Container:`-scoped sigs are gated correctly.
                let hit = if container_is_ole && is_textual_type(filetype::identify(&e.data)) {
                    scan_bytes_member(db, &e.data, Some(FileType::Ole), member_container)
                } else {
                    scan_bytes_member(db, &e.data, None, member_container)
                };
                if let Some((sig, off, m, unofficial)) = hit {
                    match_loc_record();
                    return Some(DeepOutcome::Infected {
                        signature: report_name(&sig, unofficial, opts.unofficial_suffix),
                        offset: off,
                        method: m,
                    });
                }
                match deep_analyze(
                    db,
                    &e.data,
                    opts,
                    budget,
                    depth + 1,
                    member_container,
                    true,
                    findings,
                ) {
                    DeepOutcome::Clean => None,
                    // Nested unscannable/encrypted members are remembered, not
                    // propagated as a stop — keep scanning the rest of this
                    // container.
                    DeepOutcome::Unscannable(r) => {
                        unscannable.get_or_insert(r);
                        None
                    }
                    DeepOutcome::PasswordProtected(r) => {
                        password.get_or_insert(r);
                        None
                    }
                    other => Some(other),
                }
            });
        return match outcome {
            Ok(Some(o)) => o,
            // Precedence among incomplete outcomes: PasswordProtected (actionable)
            // over Unscannable over Clean.
            Ok(None) => match (password, unscannable) {
                (Some(r), _) => DeepOutcome::PasswordProtected(r),
                (None, Some(r)) => DeepOutcome::Unscannable(r),
                (None, None) => DeepOutcome::Clean,
            },
            Err(hit) => outcome_for_hit(hit),
        };
    }

    // Embedded executables: scan PE/ELF images appended/embedded at a non-zero
    // offset (file-infectors, droppers, self-extractors — on Windows via PE, on
    // Linux via ELF). Each carved image is run through the pattern/hash core (so
    // its section hashes match) and then recursed. Structural, not heuristic, so
    // it runs regardless of the flag — bounded by recursion depth and the
    // embedded-image cap.
    if carve && depth < budget.limits.max_recursion {
        let embedded = pe::embedded_pe_offsets(data)
            .into_iter()
            .chain(pe::embedded_elf_offsets(data))
            .chain(pe::embedded_macho_offsets(data));
        for off in embedded {
            let sub = &data[off..];
            // Each carved suffix is scanned in full (PE-relative offsets resolve
            // only when the image sits at position 0). Charge it against the
            // cumulative scan budget so a crafted disk image (e.g. a 58 MB VHD
            // full of PEs) trips `LimitsExceeded` instead of running for hours.
            if let Err(h) = budget.charge_scan(sub.len() as u64) {
                return DeepOutcome::Limits(h.reason);
            }
            // The carved image inherits the container its host sits in.
            if let Some((sig, o, m, unofficial)) = scan_bytes_member(db, sub, None, container) {
                return DeepOutcome::Infected {
                    signature: report_name(&sig, unofficial, opts.unofficial_suffix),
                    offset: off as u64 + o,
                    method: m,
                };
            }
            // Recurse with carve=false: the anchored scan above already matched
            // this image, and the embedded offsets within it are a subset of the
            // ones this level enumerated — so we recurse only to extract an
            // appended archive / unpack a packed stub, NOT to re-carve (which
            // would rescan the same overlapping regions, the amplification bug).
            match deep_analyze(db, sub, opts, budget, depth + 1, container, false, findings) {
                DeepOutcome::Clean => {}
                other => return other,
            }
        }

        // Embedded archives: a ZIP/CAB/7z/RAR/GZIP/XZ appended to or stapled
        // inside a carrier (droppers, SFX stubs, PE overlays). The offset-0 scan
        // never types these, so carve each candidate whose magic is confirmed by
        // the unpacker's own `detect` (skips coincidental byte-runs) and recurse
        // to extract it. carve=false on recursion: the archive's own members are
        // handled by extraction, not by re-carving overlapping regions.
        for off in pe::embedded_archive_offsets(data) {
            let sub = &data[off..];
            if unpack::detect(sub).is_none() {
                continue;
            }
            if let Err(h) = budget.charge_scan(sub.len() as u64) {
                return DeepOutcome::Limits(h.reason);
            }
            match deep_analyze(db, sub, opts, budget, depth + 1, container, false, findings) {
                DeepOutcome::Clean => {}
                other => return other,
            }
        }
    }

    // DLP structured-data heuristic (opt-in, ClamAV `--structured-*-count`): count
    // credit-card / SSN numbers in reasonably-sized textual buffers and alert when
    // a threshold is met. Driven solely by the ScanOptions thresholds, so it runs
    // independently of `--heuristics` (matching ClamAV, where
    // `CL_SCAN_HEURISTIC_STRUCTURED` is its own switch). Runs at every recursion
    // level, so structured data inside an extracted archive member is caught too.
    #[cfg(feature = "dlp")]
    if let Some(o) = structured_data_scan(data, opts) {
        return o;
    }

    // Phishing heuristic (opt-in, ClamAV `--alert-phishing`): flag link-spoofing
    // in HTML/text bodies. Like the DLP heuristic it is driven by its own flag,
    // independent of `--heuristics`, and runs at every recursion level (so a
    // phishing HTML part inside an email/archive is caught too).
    #[cfg(feature = "phishing")]
    if let Some(o) = phishing_scan(db, data, opts) {
        return o;
    }

    // Authenticode inspection (independent of `--heuristics`, like phishing/DLP).
    // One PE parse serves both checks:
    //   * `.crb` certificate block-list — a signed PE carrying a blocked signer
    //     cert is reported (always on when a `.crb` DB is loaded);
    //   * opt-in `alert_broken_authenticode` — the embedded digest does not cover
    //     the file (tampered with / appended-to after signing).
    if opts.alert_broken_authenticode || !db.crb.is_empty() {
        if let Some(sig) = authenticode::analyze_pe(data) {
            for cert in &sig.certs {
                if let Some(name) = db.crb.blocked(cert) {
                    return DeepOutcome::Infected {
                        signature: name.to_string(),
                        offset: 0,
                        method: Method::Hash,
                    };
                }
            }
            if opts.alert_broken_authenticode && !sig.digest_matches {
                return DeepOutcome::Infected {
                    signature: "Heuristics.Authenticode.HashMismatch".to_string(),
                    offset: 0,
                    method: Method::Heuristic,
                };
            }
        }
    }

    // Nothing below fires unless at least the ClamAV-default heuristics are on
    // (on by default; `--heuristics` is the superset and also enables them).
    if !opts.clamav_heuristics && !opts.heuristics {
        return DeepOutcome::Clean;
    }

    // TLSH fuzzy matching is exav-exclusive (ClamAV has no TLSH), so it stays
    // behind the full `--heuristics` flag and off under `--clamav-compat`.
    if opts.heuristics {
        if let Some(hit) = profile::timed("fuzzy", data.len() as u64, || db.fuzzy.match_tlsh(data))
        {
            return DeepOutcome::Infected {
                signature: hit,
                offset: 0,
                method: Method::Fuzzy,
            };
        }
    }

    if ft == FileType::Pe {
        if let Some(info) = pe::analyze(data) {
            // imphash (`.imp`) matching is a ClamAV default — matched whenever the
            // loaded DB carries `.imp` sigs — so it runs under `clamav_heuristics`
            // (i.e. under `--clamav-compat` too). The exav-exclusive ML scorer,
            // packed-injection heuristic, and the `-v` diagnostic findings below
            // stay behind the full `--heuristics` flag.
            if let Some(hit) = db
                .fuzzy
                .match_imphash(&info.imphash, info.import_count as u64)
            {
                return DeepOutcome::Infected {
                    signature: hit,
                    offset: 0,
                    method: Method::Fuzzy,
                };
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
                let score = profile::timed("ml", data.len() as u64, || {
                    db.model.score(&ml::extract(data, Some(&info)))
                });
                if depth == 0 {
                    findings.push(Finding::new(
                        "ml-score",
                        format!("{score:.2} ({})", db.model.name()),
                    ));
                }
                if score >= db.ml_threshold {
                    return DeepOutcome::Infected {
                        signature: format!("Heuristics.ML.Suspect.{:.0}", score * 100.0),
                        offset: 0,
                        method: Method::Ml,
                    };
                }
                if info.looks_packed() && info.suspicious_imports.len() >= 2 {
                    return DeepOutcome::Infected {
                        signature: "Heuristics.PE.PackedWithInjectionImports".to_string(),
                        offset: 0,
                        method: Method::Heuristic,
                    };
                }
            }
        }
    }
    DeepOutcome::Clean
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
        Format::Ole => "Heuristics.Encrypted.Doc",
        _ => "Heuristics.Encrypted.Archive",
    }
}

/// Whether an extracted member name is one of the macro artifacts exav's OLE
/// extractor emits for a macro-bearing document — the VBA-project text
/// (`vba_project`/`vba_project_raw`) or the Excel 4.0 macro-sheet surface
/// (`xlm_macro`). Presence is the signal for the `--alert-macros` heuristic.
fn is_vba_member(name: &str) -> bool {
    name == "vba_project" || name == "vba_project_raw" || name == "xlm_macro"
}

/// Run the opt-in DLP structured-data heuristic over `data`. Returns an
/// `Infected` outcome with a ClamAV-compatible name when a configured threshold
/// is met, else `None`. Only runs when a threshold is set, on textual buffers no
/// larger than `DLP_MAX_BYTES` (to bound cost on hostile input).
#[cfg(feature = "dlp")]
fn structured_data_scan(data: &[u8], opts: &ScanOptions) -> Option<DeepOutcome> {
    /// Cap on buffer size the structured-data scan runs over.
    const DLP_MAX_BYTES: usize = 16 * 1024 * 1024;

    if opts.structured_cc_count.is_none() && opts.structured_ssn_count.is_none() {
        return None;
    }
    if data.len() > DLP_MAX_BYTES || !normalize::is_textual(data) {
        return None;
    }
    if let Some(threshold) = opts.structured_cc_count {
        if dlp::count_credit_cards(data) >= threshold as usize {
            return Some(DeepOutcome::Infected {
                signature: "Heuristics.Structured.CreditCardNumber".to_string(),
                offset: 0,
                method: Method::Heuristic,
            });
        }
    }
    if let Some(threshold) = opts.structured_ssn_count {
        if dlp::count_ssns(data, dlp::SsnMode::Both) >= threshold as usize {
            return Some(DeepOutcome::Infected {
                signature: "Heuristics.Structured.SSN".to_string(),
                offset: 0,
                method: Method::Heuristic,
            });
        }
    }
    None
}

/// Run the opt-in phishing heuristic over `data`. Returns an `Infected` outcome
/// with a ClamAV-compatible name when a spoofed link is found, else `None`. Only
/// runs when the flag is set, on textual buffers no larger than `PHISH_MAX_BYTES`
/// (to bound cost on hostile input).
#[cfg(feature = "phishing")]
fn phishing_scan(db: &Database, data: &[u8], opts: &ScanOptions) -> Option<DeepOutcome> {
    /// Cap on buffer size the phishing scan runs over.
    const PHISH_MAX_BYTES: usize = 16 * 1024 * 1024;

    if !opts.alert_phishing {
        return None;
    }
    if data.len() > PHISH_MAX_BYTES || !normalize::is_textual(data) {
        return None;
    }
    phishing::scan(data, &db.phishing).map(|p| DeepOutcome::Infected {
        signature: p.signature().to_string(),
        offset: 0,
        method: Method::Heuristic,
    })
}

/// Core detection over an in-memory buffer: the full `.ndb`/`.ldb` engine
/// (literals, wildcards, logical sigs — including EICAR), section hashes, then
/// whole-file hashes. The streaming literal automaton isn't used here; the
/// engine already covers every literal, so it stays unbuilt for file scans.
/// A core detection: clean signature name, match offset, method, and whether the
/// matched signature is from an unofficial database (so the report layer can add
/// `.UNOFFICIAL` in compat mode). The name is ALWAYS clean here.
type CoreHit = (String, u64, Method, bool);

fn scan_bytes_core(db: &Database, data: &[u8]) -> Option<CoreHit> {
    // Total bytes of bytecode-extracted (unpacked) content this scan may
    // re-scan, across the whole recursion — bounds an extraction bomb where a
    // (trusted) unpacker, driven by a hostile input, emits many/large buffers.
    let mut extract_budget = MAX_BC_EXTRACT_TOTAL;
    scan_bytes_depth(db, data, 0, &mut extract_budget, None, None)
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

/// True if `data` looks like JavaScript / generic script and is worth running
/// the JS normaliser over (in addition to the HTML/text normalisers). Covers
/// shebang scripts and HTML (`FileType::Script` / `FileType::Html`), any text
/// embedding a `<script` tag, and `.js`-ish textual buffers exhibiting common
/// JS obfuscation primitives (`eval`/`unescape`/`fromCharCode`/`function`).
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
        || contains_ci(b"unescape(")
        || contains_ci(b"eval(")
        || contains_ci(b"function(")
        || contains_ci(b"function (")
}

/// Scan content extracted from a container, supplying the container context:
/// `ft_override` forces the member's top-level file type (e.g. the decompressed
/// VBA macro artifacts from an OLE2 document are scanned as `Ole` so `Target:2`
/// (MSOLE2) macro signatures apply), and `container` is the immediate
/// container's type so `Container:CL_TYPE_*`-scoped signatures fire only inside
/// their intended container.
fn scan_bytes_member(
    db: &Database,
    data: &[u8],
    ft_override: Option<FileType>,
    container: Option<engine::ClType>,
) -> Option<CoreHit> {
    let mut extract_budget = MAX_BC_EXTRACT_TOTAL;
    scan_bytes_depth(db, data, 0, &mut extract_budget, ft_override, container)
}

/// Max recursion into bytecode-extracted (unpacked) buffers, to bound
/// extraction bombs.
const MAX_BC_DEPTH: u32 = 4;
/// Cap on total bytes re-scanned from bytecode-extracted buffers per scan.
const MAX_BC_EXTRACT_TOTAL: u64 = 256 * 1024 * 1024;

fn scan_bytes_depth(
    db: &Database,
    data: &[u8],
    depth: u32,
    extract_budget: &mut u64,
    ft_override: Option<FileType>,
    container: Option<engine::ClType>,
) -> Option<CoreHit> {
    let ft = if ft_override.is_some() {
        ft_override
    } else if !db.engine.is_empty() || !db.sections.is_empty() || !db.bytecode.is_empty() {
        Some(db.identify(data))
    } else {
        None
    };
    if let Some(ft) = ft {
        // PE layout lets the engine resolve EP/section-relative offsets.
        let layout = if ft == FileType::Pe {
            pe::layout(data)
        } else {
            None
        };
        // PE-icon perceptual metrics for `IconGroup1/2`-constrained logical
        // signatures: computed once per scan, only for a PE when `.idb` entries
        // are loaded. They gate such sigs (the structural condition must also
        // hold) — see [`icon`] and the engine's `IconCtx`.
        let icon_metrics = if ft == FileType::Pe && !db.icons.is_empty() {
            profile::timed("icon", data.len() as u64, || icon::pe_icon_metrics(data))
        } else {
            Vec::new()
        };
        let icon_ctx = engine::IconCtx::new(&db.icons, &icon_metrics);
        if let Some((name, off, unofficial)) = profile::timed("engine", data.len() as u64, || {
            db.engine
                .scan_with_icons(data, ft, layout.as_ref(), container, Some(&icon_ctx))
        }) {
            return Some((name, off, Method::Pattern, unofficial));
        }
        // Normalised-content pass: HTML/text/mail (`Target:3/4/7`) signatures
        // are written against canonicalised content, not raw bytes. Run the
        // engine over normalised variants of textual input.
        if !db.engine.is_empty() && normalize::is_textual(data) {
            let norms = profile::timed("normalize", data.len() as u64, || {
                let mut v = vec![normalize::html(data), normalize::text(data)];
                if looks_like_script(ft, data) {
                    v.push(normalize::javascript(data));
                }
                v
            });
            for norm in norms {
                if let Some((name, off, unofficial)) =
                    profile::timed("engine", norm.len() as u64, || {
                        db.engine.scan_with_layout(&norm, ft, None, container)
                    })
                {
                    return Some((name, off, Method::Pattern, unofficial));
                }
            }
        }
        // Bytecode programs whose trigger/hook fires (gated execution). Bytecode
        // detection names are reported verbatim (not `.UNOFFICIAL`-suffixed).
        let (det, extracted) = profile::timed("bytecode", data.len() as u64, || {
            db.bytecode.scan(data, ft, layout.as_ref())
        });
        if let Some((name, _idx)) = det {
            return Some((name, 0, Method::Bytecode, false));
        }
        // Unpacker programs surface embedded files; re-scan them recursively
        // (bounded) so the payload inside a packed binary is caught.
        if depth < MAX_BC_DEPTH {
            for buf in extracted {
                let cost = buf.len() as u64;
                if *extract_budget < cost {
                    break; // extraction-bomb guard: stop re-scanning further
                }
                *extract_budget -= cost;
                if let Some(hit) =
                    scan_bytes_depth(db, &buf, depth + 1, extract_budget, None, container)
                {
                    return Some(hit);
                }
                // A packer may surface an embedded archive (e.g. an unpacked
                // payload that is itself a ZIP/gzip). Unpack it too, bounded by
                // the same extraction budget, so the real payload is reached.
                let bft = filetype::identify(&buf);
                // This deep bytecode-extracted-buffer rescan runs only behind a
                // ClamAV `.cbc` unpacker firing; it isn't part of the common
                // diff-tested path, so it always runs at full capability.
                if let Some(fmt) = unpack_target(bft, &buf, false) {
                    let inner_container = container_cltype(fmt, &buf);
                    let mut b = Budget::new(unpack::Limits::default());
                    // Stream members; `Some(Some(hit))` stops with a detection,
                    // `Some(None)` stops on the extraction-bomb guard, `None`
                    // continues. Extraction errors are ignored (best effort).
                    let res = unpack::extract_each(
                        fmt,
                        &buf,
                        &mut b,
                        &mut |e: unpack::Entry, _b: &mut Budget| {
                            let ec = e.data.len() as u64;
                            if *extract_budget < ec {
                                return Some(None);
                            }
                            *extract_budget -= ec;
                            scan_bytes_depth(
                                db,
                                &e.data,
                                depth + 1,
                                extract_budget,
                                None,
                                inner_container,
                            )
                            .map(Some)
                        },
                    );
                    if let Ok(Some(Some(hit))) = res {
                        return Some(hit);
                    }
                }
            }
        }
    }
    if !db.sections.is_empty() && ft == Some(FileType::Pe) {
        let want_sha = db.sections.wants_sha();
        if let Some((name, unofficial)) = profile::timed("sections", data.len() as u64, || {
            for (size, slice) in pe::section_slices(data) {
                let d = hashes::section_digests(slice, want_sha);
                if let Some(hit) = db.sections.lookup(size, &d) {
                    return Some(hit);
                }
            }
            None
        }) {
            return Some((name, 0, Method::Hash, unofficial));
        }
    }
    if !db.hashes.is_empty() {
        if let Some((name, unofficial)) = profile::timed("hashes", data.len() as u64, || {
            db.hashes.lookup(&digests_of(data), data.len() as u64)
        }) {
            return Some((name, 0, Method::Hash, unofficial));
        }
    }
    // YARA rules (yara-x): the matcher already formats the full ClamAV name
    // (`YARA.` prefix and any `.UNOFFICIAL` suffix), so it is reported verbatim.
    if !db.yara.is_empty() {
        if let Some(name) = profile::timed("yara", data.len() as u64, || db.yara.scan(data)) {
            return Some((name, 0, Method::Yara, false));
        }
    }
    None
}

/// Streaming detection core (constant memory, any size): Aho-Corasick +
/// triple hasher in one forward pass.
fn stream_core<R: Read>(db: &Database, reader: R) -> io::Result<Option<CoreHit>> {
    // When no hash signatures are loaded, skip the (expensive) triple hash on
    // every byte and just run the pattern matcher over the raw reader.
    if db.hashes.is_empty() {
        if let Some(mat) = db.patterns.ac().stream_find_iter(reader).next() {
            let mat = mat?;
            let (name, unofficial) = db.patterns.name_prov(mat.pattern().as_usize());
            return Ok(Some((
                name.to_string(),
                mat.start() as u64,
                Method::Pattern,
                unofficial,
            )));
        }
        return Ok(None);
    }
    let mut tee = TeeHasher::new(reader);
    // `next()` drives the reader until the first match or EOF; on `None`
    // the whole stream has been consumed, so the hashers saw every byte.
    if let Some(mat) = db.patterns.ac().stream_find_iter(&mut tee).next() {
        let mat = mat?;
        let (name, unofficial) = db.patterns.name_prov(mat.pattern().as_usize());
        return Ok(Some((
            name.to_string(),
            mat.start() as u64,
            Method::Pattern,
            unofficial,
        )));
    }
    let size = tee.bytes_read();
    let digests = tee.finalize();
    if let Some((name, unofficial)) = db.hashes.lookup(&digests, size) {
        return Ok(Some((name, 0, Method::Hash, unofficial)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use patterns::EICAR;
    use std::io::Cursor;

    #[test]
    fn restrict_extractors_gates_absent_formats() {
        // Of exav's extractors, `ar` and `lzip` are absent from stock ClamAV;
        // cpio/xar are supported by both, so the compat mask gates the absent
        // formats alone — gating cpio/xar would make exav miss detections
        // ClamAV makes.
        // `ar` — restricted only when `restrict` is set.
        assert_eq!(
            unpack_target(FileType::Ar, b"", false),
            Some(unpack::Format::Ar)
        );
        assert_eq!(unpack_target(FileType::Ar, b"", true), None);
        // cpio / xar — supported by ClamAV, so never gated.
        for (ft, fmt) in [
            (FileType::Cpio, unpack::Format::Cpio),
            (FileType::Xar, unpack::Format::Xar),
        ] {
            assert_eq!(unpack_target(ft, b"", false), Some(fmt));
            assert_eq!(
                unpack_target(ft, b"", true),
                Some(fmt),
                "{ft:?} must not be gated"
            );
        }
    }

    /// A minimal buffer whose UPX `PackHeader` passes `find_packheader` (so
    /// `is_upx` is true), without needing a real compressed payload.
    #[cfg(feature = "upx")]
    fn fake_upx() -> Vec<u8> {
        let mut b = vec![0u8; 40];
        b[4..8].copy_from_slice(b"UPX!"); // magic (l_info starts at 0)
        b[16..20].copy_from_slice(&100u32.to_le_bytes()); // filesize
        b[24..28].copy_from_slice(&8u32.to_le_bytes()); // first block sz_unc
        b[28..32].copy_from_slice(&4u32.to_le_bytes()); // first block sz_cpr (fits: 36+4=40)
        b
    }

    /// Compat restricts UPX unpacking to PE — ClamAV's UPX unpacker runs only
    /// from its PE path, so exav's ELF/Mach-O UPX reach (e.g. UPX-packed Mirai
    /// ELFs) must be gated off under `restrict` to stay apples-to-apples.
    #[cfg(feature = "upx")]
    #[test]
    fn restrict_scopes_upx_to_pe() {
        let buf = fake_upx();
        assert!(unpack::is_upx(&buf), "test buffer must look like UPX");
        // Normal mode: UPX unpacked for every executable type.
        for ft in [FileType::Pe, FileType::Elf, FileType::MachO] {
            assert_eq!(unpack_target(ft, &buf, false), Some(unpack::Format::Upx));
        }
        // Compat: PE stays on, ELF/Mach-O are gated off.
        assert_eq!(
            unpack_target(FileType::Pe, &buf, true),
            Some(unpack::Format::Upx),
            "PE-UPX must stay on under compat (ClamAV does it too)"
        );
        for ft in [FileType::Elf, FileType::MachO] {
            assert_eq!(
                unpack_target(ft, &buf, true),
                None,
                "{ft:?}-UPX must be gated off under compat"
            );
        }
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
                VerdictCategory::NotScanned,
                "LIMITS-EXCEEDED",
                Some("too big"),
            ),
            (
                Verdict::Unscannable {
                    reason: "rar ppmd".into(),
                },
                VerdictCategory::NotScanned,
                "UNSCANNABLE",
                Some("rar ppmd"),
            ),
            (
                Verdict::PasswordProtected {
                    reason: "encrypted".into(),
                },
                VerdictCategory::NotScanned,
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

    fn build_zip(members: &[(&str, &[u8])]) -> Vec<u8> {
        use zip::write::SimpleFileOptions;
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in members {
            w.start_file(*name, SimpleFileOptions::default()).unwrap();
            std::io::Write::write_all(&mut w, body).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn detects_eicar_pattern() {
        let db = Database::builtin();
        let r = scan_stream(&db, Cursor::new(EICAR.to_vec())).unwrap();
        assert!(matches!(
            r.verdict,
            Verdict::Infected {
                method: Method::Pattern,
                ..
            }
        ));
    }

    #[test]
    fn detects_cdb_container_metadata() {
        use std::io::Write;
        // A ZIP holding a member named like an executable dropper.
        let mut zbuf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut zbuf));
            zw.start_file(
                "payload_dropper.exe",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
            zw.write_all(b"harmless looking bytes").unwrap();
            zw.finish().unwrap();
        }
        let mut db = Database::builtin();
        // Match any ZIP containing a `*.exe` member, by container metadata alone.
        db.cdb
            .extend_from_text("Test.Cdb.Dropper:CL_TYPE_ZIP:*:.*\\.exe:*:*:*:*:*:\n");
        let r = analyze(&db, &zbuf, &ScanOptions::default());
        match r.verdict {
            Verdict::Infected { signature, .. } => assert_eq!(signature, "Test.Cdb.Dropper"),
            other => panic!("expected .cdb detection, got {other:?}"),
        }
    }

    #[test]
    fn detects_normalized_html_signature() {
        // Signature for lowercase "<script>evil", which only appears after
        // normalising mixed-case + entity-encoded HTML (`&#x69;` -> 'i').
        let mut db = Database::builtin();
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
        let mut db = Database::builtin();
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
        let mut db = Database::builtin();
        let d = digests_of(b"some clean-looking content");
        db.hashes
            .extend_from_text(&format!("{}:*:Test.ByHash\n", d.sha256));
        db.hashes.finalize();
        let r = scan_stream(&db, Cursor::new(b"some clean-looking content".to_vec())).unwrap();
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

    #[test]
    fn clean_is_clean() {
        let db = Database::builtin();
        let r = scan_stream(&db, Cursor::new(b"nothing to see".to_vec())).unwrap();
        assert_eq!(r.verdict, Verdict::Clean);
    }

    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn allowlist_and_ignore_suppress_detection() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.ndb"), "Demo.Hit:0:*:cafebabe\n").unwrap();
        let data = b"\x00\xca\xfe\xba\xbe\x00".to_vec(); // contains the bytes CA FE BA BE
        let opts = ScanOptions::default();

        // Detected with no allowlist.
        let db = db::load(dir.path()).unwrap();
        assert!(matches!(
            analyze(&db, &data, &opts).verdict,
            Verdict::Infected { .. }
        ));

        // `.fp` allowlisting this file's hash clears the detection.
        let d = digests_of(&data);
        std::fs::write(dir.path().join("b.fp"), format!("{}:*:Allowed\n", d.md5)).unwrap();
        assert_eq!(
            analyze(&db::load(dir.path()).unwrap(), &data, &opts).verdict,
            Verdict::Clean
        );
        std::fs::remove_file(dir.path().join("b.fp")).unwrap();

        // `.ign2` ignoring the signature name also clears it.
        std::fs::write(dir.path().join("c.ign2"), "Demo.Hit\n").unwrap();
        assert_eq!(
            analyze(&db::load(dir.path()).unwrap(), &data, &opts).verdict,
            Verdict::Clean
        );
    }

    #[test]
    fn detects_across_buffer_boundary() {
        let db = Database::builtin();
        let mut data = vec![b'A'; 3_000_000];
        data.extend_from_slice(EICAR);
        data.extend(std::iter::repeat_n(b'B', 3_000_000));
        let r = scan_stream(&db, Cursor::new(data)).unwrap();
        match r.verdict {
            Verdict::Infected { offset, .. } => assert_eq!(offset, 3_000_000),
            other => panic!("expected infection, got {other:?}"),
        }
    }

    #[test]
    fn finds_eicar_inside_gzip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(EICAR).unwrap();
        let blob = e.finish().unwrap();
        let db = Database::builtin();
        let r = analyze(&db, &blob, &ScanOptions::default());
        assert!(matches!(r.verdict, Verdict::Infected { .. }));
    }

    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), bytes).unwrap();
        f
    }

    // A container too large for structural analysis that does NOT stream (its
    // decoder needs random access over a buffered slice — here OLE2) must not be
    // cleared: its contents were never unpacked, so the verdict is
    // LimitsExceeded, never Clean. This is the invariant for the still-buffered
    // formats. (ZIP/tar/gzip now stream past the cap — see the tests below.)
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn oversize_nonstreaming_container_is_limits_not_clean() {
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
        let db = Database::builtin();
        let opts = ScanOptions {
            deep_analysis_max: 1,
            ..Default::default()
        };
        let r = scan_path(&db, f.path(), &opts).unwrap();
        assert!(
            matches!(r.verdict, Verdict::LimitsExceeded { .. }),
            "got {:?}",
            r.verdict
        );
    }

    // Streaming lift: a gzip/tar whose size exceeds `deep_analysis_max` is now
    // walked member-by-member off disk (never buffered whole) and fully scanned,
    // so a payload buried inside it is caught — the gap the old cap left open.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn streamed_gzip_over_cap_finds_eicar() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(EICAR).unwrap();
        let blob = e.finish().unwrap();
        let f = write_temp(&blob);
        let db = Database::builtin();
        // Cap of 1 byte: the old path would refuse this as "contents not
        // unpacked"; the streaming path unpacks and finds EICAR.
        let opts = ScanOptions {
            deep_analysis_max: 1,
            ..Default::default()
        };
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
        // A benign padding member first, then the payload — proves the walk
        // continues past clean members without buffering the whole archive.
        let pad = vec![b'Z'; 8192];
        let mut h = tar::Header::new_gnu();
        h.set_size(pad.len() as u64);
        h.set_cksum();
        ar.append_data(&mut h, "pad.bin", &pad[..]).unwrap();
        let mut h2 = tar::Header::new_gnu();
        h2.set_size(EICAR.len() as u64);
        h2.set_cksum();
        ar.append_data(&mut h2, "evil.com", EICAR).unwrap();
        let blob = ar.into_inner().unwrap();
        let f = write_temp(&blob);
        let db = Database::builtin();
        let opts = ScanOptions {
            deep_analysis_max: 1,
            ..Default::default()
        };
        let r = scan_path(&db, f.path(), &opts).unwrap();
        assert!(
            matches!(r.verdict, Verdict::Infected { .. }),
            "got {:?}",
            r.verdict
        );
    }

    // A streamed container's own whole-file hash must still be detected — the
    // streaming path runs a constant-memory raw scan (hash + patterns) before
    // walking members, matching the buffered `scan_bytes_core`. Regression guard
    // for the streaming routing.
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
        let mut db = Database::builtin();
        let d = digests_of(&blob);
        db.hashes
            .extend_from_text(&format!("{}:*:Test.TarWholeHash\n", d.sha256));
        db.hashes.finalize();
        let f = write_temp(&blob);
        let r = scan_path(&db, f.path(), &ScanOptions::default()).unwrap();
        match r.verdict {
            Verdict::Infected { signature, .. } => assert_eq!(signature, "Test.TarWholeHash"),
            other => panic!("expected whole-file-hash detection, got {other:?}"),
        }
    }

    // Recursion streaming (c): a gzip NESTED inside a tar, whose decompressed
    // content exceeds `max_entry_bytes` with EICAR buried past that cap. The old
    // buffered path decoded the nested gzip into a `max_entry_bytes`-capped Vec
    // and reported LIMITS before reaching EICAR; the streaming recursion scans the
    // whole decompressed member (RAM bounded by deep_analysis_max) and finds it.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn nested_gzip_over_entry_cap_is_streamed_and_found() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        // gzip whose decompressed content (padding + EICAR at the end) far exceeds
        // the tiny per-member buffer cap set below.
        let mut payload = vec![b'Z'; 4096];
        payload.extend_from_slice(EICAR);
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
        let db = Database::builtin();
        // Per-member buffer cap (256 bytes) is far below the 4 KiB+ decompressed
        // content: the old path would cap/truncate the nested gzip here.
        let mut opts = ScanOptions::default();
        opts.limits.max_entry_bytes = 256;
        opts.deep_analysis_max = 256;
        let r = scan_path(&db, f.path(), &opts).unwrap();
        assert!(
            matches!(r.verdict, Verdict::Infected { .. }),
            "nested gzip past the entry cap must be streamed and detected, got {:?}",
            r.verdict
        );
    }

    // Flat content larger than the deep-analysis cap is still fully scanned
    // by the streaming core, so signatures are found.
    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn oversize_flat_text_with_signature_is_found() {
        let mut data = vec![b'A'; 100];
        data.extend_from_slice(EICAR);
        let f = write_temp(&data);
        let db = Database::builtin();
        let opts = ScanOptions {
            deep_analysis_max: 1,
            ..Default::default()
        };
        let r = scan_path(&db, f.path(), &opts).unwrap();
        assert!(matches!(r.verdict, Verdict::Infected { .. }));
    }

    #[test]
    #[cfg_attr(
        target_family = "wasm",
        ignore = "host filesystem/tempdir unavailable under WASI"
    )]
    fn oversize_flat_text_clean_is_clean() {
        let f = write_temp(&vec![b'Z'; 5000]);
        let db = Database::builtin();
        let opts = ScanOptions {
            deep_analysis_max: 1,
            ..Default::default()
        };
        let r = scan_path(&db, f.path(), &opts).unwrap();
        assert_eq!(r.verdict, Verdict::Clean);
    }

    fn zip_bytes(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            for (name, data, stored) in members {
                let opts = if *stored {
                    SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored)
                } else {
                    SimpleFileOptions::default()
                };
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    #[test]
    fn scan_seekable_finds_eicar_in_zip() {
        let blob = zip_bytes(&[("a.txt", b"hello", false), ("evil", EICAR, false)]);
        let size = blob.len() as u64;
        let db = Database::builtin();
        let r = scan_seekable(&db, Cursor::new(blob), size, &ScanOptions::default()).unwrap();
        assert!(matches!(r.verdict, Verdict::Infected { .. }));
    }

    // Scan a ZIP over HTTP range requests: detection works AND only a fraction
    // of the object is fetched — the large second member is never requested
    // because the first member already matched.
    #[cfg(feature = "http")]
    #[test]
    fn http_range_scan_fetches_only_what_it_needs() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
        use std::thread;

        let big: Vec<u8> = (0..1_000_000u32).map(|i| (i as u8) ^ 0x5a).collect();
        let blob = zip_bytes(&[("evil", EICAR, false), ("big.bin", &big, true)]);
        let total = blob.len();
        assert!(
            total > 900_000,
            "stored member should keep the zip large: {total}"
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let served = Arc::new(AtomicU64::new(0));
        let served_t = served.clone();
        let blob_t = blob.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
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
                    a, b, blob_t.len(), slice.len()
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
        let db = Database::builtin();
        let r = scan_seekable(&db, reader, size, &ScanOptions::default()).unwrap();
        assert!(
            matches!(r.verdict, Verdict::Infected { .. }),
            "should detect EICAR over HTTP range"
        );

        let bytes = served.load(Ordering::SeqCst);
        assert!(
            bytes < (total as u64) / 2,
            "fetched {bytes} of {total}; expected a fraction"
        );
    }
}
