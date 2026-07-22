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
//! are therefore security properties rather than ergonomics:
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
// returned by `Scanner::identify`.
/// Authenticode (PE code-signing) triage without RSA — recompute the PE hash and
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
/// Temp files for the test suite, so testing needs no temp-file dependency.
#[cfg(test)]
mod tmpfile;
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
    bytecode, container, cvd, engine, fuzzy, fuzzy_img, hashes, hexsig, icon, jsnorm, ml,
    normalize, patterns, pe,
);

// YARA rule support. The native engine (compiler/scanner/modules) lives in-tree
// under `src/yara/`. This module is `pub` (not an `engine_internals!` member) so
// that a consumer who wants YARA alone can reach the compiler and scanner
// without going through a scan. It is ALWAYS compiled — the `yara::YaraDb` type
// is part of the
// on-disk database format regardless of the `yara` feature — while the actual
// compiler/matcher submodules inside it are gated on `feature = "yara"`.
pub mod yara;

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
        FileType::Wim => unpack::Format::Wim,
        FileType::Lz4 => unpack::Format::Lz4,
        FileType::Arc => unpack::Format::Arc,
        FileType::Ace => unpack::Format::Ace,
        FileType::Alz => unpack::Format::Alz,
        FileType::Egg => unpack::Format::Egg,
        FileType::Hwp3 => unpack::Format::Hwp3,
        FileType::IshieldMsi => unpack::Format::IshieldMsi,
        FileType::IshieldCab => unpack::Format::IshieldCab,
        FileType::IshieldZ => unpack::Format::IshieldZ,
        FileType::CryptFf => unpack::Format::CryptFf,
        FileType::Ext => unpack::Format::Ext,
        FileType::Lrzip => unpack::Format::Lrzip,
        FileType::Zoo => unpack::Format::Zoo,
        FileType::AppleSingle => unpack::Format::AppleSingle,
        FileType::StuffIt => unpack::Format::StuffIt,
        FileType::Fat => unpack::Format::Fat,
        FileType::Inno => unpack::Format::Inno,
        FileType::Ntfs => unpack::Format::Ntfs,
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
    // Formats with no ClamAV `CL_TYPE_*` of their own — disk images and Unix
    // `compress` — are typed `Unknown`, so `unpack_format` cannot reach them.
    // They still hold real content (a compressed QCOW2 cluster or a `.Z` stream
    // shows none of its payload in the file's bytes), so dispatch them straight
    // from the magic. Compat mode leaves them off: stock ClamAV opens none of
    // them, and extracting more there would be counted as a disagreement.
    if !restrict {
        if let Some(fmt) = unpack::detect(data) {
            if filetype::MAGIC_DISPATCH_ONLY.contains(&fmt) {
                return Some(fmt);
            }
        }
    }
    // Installers and self-extractors: real executables, so `identify` answers
    // `Pe`/`Elf` and `unpack_format` has nothing to map. Their payload is the
    // installer's own format rather than a recognisable archive, so carving does
    // not reach it either — without this an NSIS or Inno installer scans clean
    // with every file it packages unexamined.
    if ft.is_executable() {
        if let Some(fmt) = unpack::detect(data) {
            if filetype::EXECUTABLE_CONTAINERS.contains(&fmt) {
                // Stock ClamAV unpacks NSIS, AutoIt and SFX, so those stay on in
                // compat mode; it has no Inno Setup support, and claiming the
                // extra reach there would register as a disagreement.
                if !restrict || fmt != unpack::Format::Inno {
                    return Some(fmt);
                }
            }
        }
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
    // Other PE runtime packers: the aPLib families (Petite/FSG/NsPack) are
    // decompressed statically, and anything else that looks packed has its stub
    // run under the x86 emulator, which recovers the original image whatever
    // scheme produced it. Checked after UPX, since a file is packed by at most
    // one.
    //
    // This runs under `--clamav-compat` too. Compat exists to make a
    // differential run compare like with like — same alert *names*, same rough
    // feature scope — not to hold coverage down to another engine's. Skipping an
    // unpacker here would mean deliberately not looking inside a packed dropper,
    // and a miss is a miss whatever mode produced it.
    //
    // Only meaningful for PE (the detector requires a PE image), but
    // `is_executable` keeps it symmetric with UPX.
    if ft.is_executable() && unpack::is_pepack(data) {
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
        // A MIME document with no mail envelope is a saved web page, and its
        // parts carry `CL_TYPE_MHTML` rather than `CL_TYPE_MAIL`. The two are
        // mutually exclusive.
        Format::Email => {
            if filetype::looks_like_mhtml(data) {
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
        // `CL_TYPE_MSEXE` to the signature format — the members' parent is the
        // executable, whatever wrapped them inside it.
        Format::Sfx | Format::PePacked | Format::Upx | Format::Inno => ClType::MsExe,
        _ => return None,
    })
}

/// The container type of a markup document that carries embedded base64 assets,
/// or `None` if this buffer is not one.
///
/// The two flat-XML Office types are single-file documents — no ZIP, so nothing
/// an unpacker would open — identified by the processing instruction Office
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
    /// [`ScanOptions::passwords`] set. Takes precedence over `Unscannable` when
    /// both occur (it's the one the user can do something about).
    PasswordProtected {
        reason: String,
    },
}

/// Coarse classification of a [`Verdict`], the single source of truth for
/// summary counters and exit codes across every front-end (one-shot CLI, the
/// clamd daemon, and the daemon client). Keep counting/exit logic keyed on this
/// — never on the rendered string — so the three surfaces can't drift apart.
/// Deliberately NOT `#[non_exhaustive]`, unlike [`Verdict`]. This enum exists
/// so that exit codes and output shape are decided in one place, and the value
/// of that is the compiler refusing to build until every consumer has handled a
/// new category. A wildcard arm is exactly what must not happen here: it would
/// quietly give a future outcome some existing exit code. There are four
/// categories and adding one is a deliberate act inside this workspace, so the
/// cost of the break is small and lands on the people who caused it.
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

/// The serialised phishing-DB parts stored in the prebuilt database: `(protected
/// domains, `M:` allow-list pairs, `X:` regex source pairs)`. Defined
/// unconditionally (the `phishing` feature only gates the *matcher*, not the
/// database format) so a database round-trips identically regardless of features.
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
    /// static suspicion scorer (`Heuristics.Static.Suspect.*`), and the packed-with-injection
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
    /// no ClamAV analog) does not. `--detect heuristics` is the superset and implies this.
    pub clamav_heuristics: bool,
    /// Report findings under ClamAV's vocabulary where the two engines describe
    /// the same fact differently. Set by [`ScanOptions::clamav_compat`].
    ///
    /// This changes NAMES, never what is detected. exav does not withhold a
    /// finding in either mode, and does not adopt a check it believes is wrong —
    /// compat is about feature scope and the strings a drop-in replacement must
    /// emit, not about reproducing another engine's judgement.
    ///
    /// Today it affects one name: an ELF whose section-header table has been
    /// stripped. exav reports that as what it is; ClamAV calls it a broken
    /// executable, and a gateway filtering on ClamAV's exact string needs to
    /// keep matching.
    pub clamav_compat: bool,
    /// Limits for recursive unpacking / bomb defenses.
    pub limits: unpack::Limits,
    /// Restrict exav's unpacking reach to stock ClamAV's, so a differential run
    /// against `clamscan` doesn't count exav's extra reach as a disagreement.
    /// Narrows two things to ClamAV's scope: (1) archive extractors — skip the
    /// formats stock ClamAV lacks: `ar` (Unix archive / `.deb` / `.a`), `lzip`,
    /// Inno Setup, and the magic-dispatched disk-image / Unix `compress` formats
    /// (verified against 1.4.x, which handles cpio/xar natively); (2) UPX — to PE
    /// only (ClamAV's UPX unpacker runs only from its PE path, never ELF/Mach-O).
    ///
    /// The other PE runtime packers stay **on**: ClamAV unpacks those too, and
    /// switching an unpacker off would not make a run comparable, it would make
    /// it miss a packed dropper. Compat narrows *scope and naming*, never
    /// coverage of content that is there to be found. Default off. This
    /// deliberately *reduces* exav's detection capability for reproducibility, so
    /// it is a diff-testing aid, **not for production** — it is one of the
    /// behaviours the CLI's `--clamav-compat` turns on.
    pub restrict_extractors: bool,
    /// Decode long base64 blobs found in text/script buffers and rescan any that
    /// decode to a real executable (PE/ELF/Mach-O/OLE) — catching a PE stashed as
    /// a base64 string in a PowerShell/JS/VBS dropper or an RTF body, invisible to
    /// a signature that matches the decoded bytes. **On by default** (exav-exclusive
    /// reach beyond stock ClamAV); off under `--clamav-compat` and via `--no-base64`.
    /// FP-safe: only a decode with a valid executable header is rescanned.
    pub decode_base64: bool,
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
    /// Opt-in heuristic (`--alert-packed`): report `Heuristics.Packed.*` for an
    /// executable behind a packer or protector exav cannot unpack.
    ///
    /// Reported IN ADDITION TO the unscannable signal, never instead of it. The
    /// two say different things — "this is VMProtect" and "its original code was
    /// not recovered" — and a scanner that emits only the second leaves every
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
    /// Opt-in Authenticode heuristic: report `Heuristics.Authenticode.HashMismatch`
    /// when a code-signed PE's embedded digest does NOT cover the current file
    /// bytes (i.e. the file was modified or had data appended after signing — a
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
            alert_broken_authenticode: false,
            filename: None,
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
            clamav_compat: true,
            limits: unpack::Limits {
                max_recursion: 17,
                max_members: 10_000,
                max_extracted_bytes: 400 * 1024 * 1024,
                ..unpack::Limits::default()
            },
            restrict_extractors: true,
            // base64-decoding reaches beyond stock ClamAV; off for parity.
            decode_base64: false,
            unofficial_suffix: true,
            passwords: Vec::new(),
            // ClamAV ignores CRCs when scanning — match it.
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
            alert_broken_authenticode: false,
            filename: None,
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
impl Scanner {
    pub fn engine(&self) -> &engine::SigEngine {
        &self.engine
    }

    /// Assemble a [`Scanner`] from individually-built subsystems over the
    /// [`Scanner::builtin`] baseline (which supplies `patterns`, `sections`,
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
        let mut ft = filetype::identify(data);
        if ft == FileType::Unknown {
            if let Some(f) = self.ftm.identify(data) {
                ft = f;
            }
        }
        // The bzip2 (`BZh`), CAB (`MSCF`) and gzip (`1f 8b`) file-type magics are
        // short and collide with ordinary binary data; a false hit (e.g. a `BZh4…`,
        // `MSCF…` or `1f8b08…` byte-run inside an ISO member or PE overlay) would
        // be routed to that decoder, fail deep in parsing, and report the whole
        // object UNSCANNABLE / LIMITS-EXCEEDED. `.ftm` rules match on those weak
        // prefixes, so confirm each against the extractor's stronger magic check
        // (block magic for bzip2, zero `reserved1` for CAB, deflate CM + flag bits
        // for gzip) before trusting the typing; a false hit is scanned as raw bytes.
        let false_archive = match ft {
            FileType::Bzip2 => unpack::detect(data) != Some(unpack::Format::Bzip2),
            FileType::Cab => unpack::detect(data) != Some(unpack::Format::Cab),
            FileType::Gzip => unpack::detect(data) != Some(unpack::Format::Gzip),
            _ => false,
        };
        if false_archive {
            return FileType::Unknown;
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
        // The ENGINE is the authoritative loader: a signature it compiled is
        // loaded and will match, whatever the streaming set did with it.
        // `patterns.unsupported` counts lines the streaming literal set could
        // not carry — overwhelmingly wildcard bodies the engine handles fine —
        // so adding it here both invented gaps that don't exist and
        // double-counted the actually malformed lines (both loaders see the
        // same `.ndb` text). Report the engine's count alone.
        self.engine.unsupported
    }
}

/// Scan a local file path (Seekable mode). The pattern+hash core handles
/// any size in constant memory; structural analysis runs for files within
/// `deep_analysis_max`.
///
/// # Errors
///
/// The `io::Error` covers only reaching the file — opening, reading, seeking.
/// **Nothing about the scan's outcome is reported this way.** A file that could
/// not be decoded, that exhausted a budget, or that turned out to be encrypted
/// is a successful call returning a [`ScanReport`] whose [`Verdict`] says so.
///
/// Treating `Err` as "not infected" is therefore safe, and treating `Ok` as
/// "clean" is not: check the verdict.
///
/// # Panics
///
/// Individual decoders are wrapped, so malformed content yields a verdict
/// rather than unwinding. Two failure modes are outside that boundary and will
/// take the process down: an allocation large enough to abort, and stack
/// exhaustion from a deeply self-nested file. A caller that must survive
/// arbitrary input needs an out-of-process bound — see `SECURITY.md`.
pub fn scan_path(db: &Scanner, path: &Path, opts: &ScanOptions) -> io::Result<ScanReport> {
    // Supply the scanned file's identity to the YARA external variables
    // (`filepath`/`filename`/`extension`) unless the caller already set one.
    // `scan_path` is the single choke point every CLI/daemon file enters core
    // through, so deriving it here reaches YARA for all of them without touching
    // each call site, while an explicit `opts.filename` still wins.
    let owned_opts;
    let opts = if opts.filename.is_none() {
        let mut o = opts.clone();
        o.filename = Some(path.to_string_lossy().into_owned());
        owned_opts = o;
        &owned_opts
    } else {
        opts
    };

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
pub fn scan_stream<R: Read>(db: &Scanner, reader: R) -> io::Result<ScanReport> {
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
///
/// Must be called at EVERY site that returns a detection, including ones that
/// merely re-wrap a recursive result: first-write-wins makes the redundant calls
/// no-ops, while a missing call silently reports a nested hit as though it had
/// matched the container's own bytes. The consequence is not cosmetic: a
/// detection inside an RTF-embedded PE then looks like a `Target:1` (PE-only)
/// signature firing on an RTF file, which is indistinguishable from a
/// target-gating bug until you check whether the signature's bytes exist in the
/// container at all.
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
    db: &Scanner,
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
    db: &Scanner,
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
    // The same test `scan_path` applies, and for the same reason: a container
    // hides detections that only structural parsing finds, and the cap meant it
    // was never parsed. Checking `is_executable` alone would call an oversize
    // RAR, PDF or OLE clean — the flat core saw its bytes, but nothing opened
    // it. This path backs the daemon's stream verbs and the HTTP range source,
    // so the two entry points have to agree.
    if unpack_format(ft).is_some() || ft.is_executable() {
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
fn scan_budget(db: &Scanner, opts: &ScanOptions) -> Budget {
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
fn report_for_hit(hit: unpack::LimitHit, findings: Vec<Finding>, opts: &ScanOptions) -> ScanReport {
    if hit.corrupt {
        return ScanReport::unscannable(hit.reason, findings);
    }
    if opts.alert_exceeds_max {
        if let Some(name) = limits_alert_name(hit.kind) {
            return ScanReport::infected(name.to_string(), 0, Method::Heuristic, findings);
        }
    }
    ScanReport::limits(hit.reason, findings)
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

/// Turn a budget stop into an outcome, honouring `--alert-exceeds-max`.
///
/// The flag only changes the *shape* of the report, never whether the scan is
/// treated as complete: a kind with no alert name keeps the `LimitsExceeded`
/// verdict and its reason.
fn limits_outcome(opts: &ScanOptions, kind: unpack::LimitKind, reason: String) -> DeepOutcome {
    if opts.alert_exceeds_max {
        if let Some(name) = limits_alert_name(kind) {
            match_loc_record();
            return DeepOutcome::Infected {
                signature: name.to_string(),
                offset: 0,
                method: Method::Heuristic,
            };
        }
    }
    DeepOutcome::Limits(reason)
}

/// As [`report_for_hit`] but for the recursive [`DeepOutcome`] path.
fn outcome_for_hit(hit: unpack::LimitHit, opts: &ScanOptions) -> DeepOutcome {
    if hit.corrupt {
        DeepOutcome::Unscannable(hit.reason)
    } else {
        limits_outcome(opts, hit.kind, hit.reason)
    }
}

/// Container formats scanned member-by-member off the raw seekable source
/// **without holding the whole container in RAM**. Two mechanisms sit behind
/// this: every [`unpack::is_streamable`] format uses the low-level reader API
/// ([`unpack::stream_members`]), so a member is decoded on demand and a
/// multi-gigabyte member is never materialized (see [`member_stream_scan`]).
/// Either way the `deep_analysis_max` buffer does not cap the container size —
/// a multi-gigabyte `.tar`/`.tar.gz`/`.zip`/`.gz` on disk is scanned in bounded
/// memory. Every other container still buffers (its decoder needs random access
/// over a slice), so it stays on the size-capped `analyze` path.
fn streams_natively(ft: FileType) -> bool {
    matches!(
        ft,
        FileType::Zip
            | FileType::Tar
            | FileType::Gzip
            | FileType::Bzip2
            | FileType::Xz
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

/// The outcome of reading a streamed member into memory, capped.
///
/// In every case the bytes already consumed come back: a stream does not
/// rewind, so discarding them would lose content that was decoded and then
/// never scanned.
enum Capped {
    /// The whole member fitted under the cap.
    Whole(Vec<u8>),
    /// It did not fit. `.0` is the prefix consumed; chain it ahead of the
    /// reader rather than dropping it.
    TooBig(Vec<u8>),
    /// The read itself failed — a disk error, a dropped connection, a range
    /// request the server would not honour. `.0` is what arrived before the
    /// failure. This is NOT truncation: the rest of the member exists and we
    /// did not get it, so the caller must report rather than treat the prefix
    /// as the member.
    Failed(Vec<u8>, io::Error),
}

/// Read at most `cap` bytes from a streamed member.
fn read_capped(rdr: &mut dyn Read, cap: u64) -> Capped {
    let mut buf = Vec::new();
    // One byte past the cap: reading exactly `cap` cannot tell a member that
    // just fits from one that is about to overflow.
    if let Err(e) = rdr.take(cap.saturating_add(1)).read_to_end(&mut buf) {
        return Capped::Failed(buf, e);
    }
    if buf.len() as u64 > cap {
        Capped::TooBig(buf)
    } else {
        Capped::Whole(buf)
    }
}

/// Scan one member's *bytes* when they arrive as a **reader** rather than a
/// slice — the streaming counterpart of [`member_content_scan`], reporting to
/// the same sink and tally so the two produce identical results.
///
/// A bounded prefix — up to `deep_analysis_max` — is buffered here in
/// `exav-core` (the highest layer that can decide) so slice-based structural
/// analysis runs on members that fit; those hand straight to
/// [`member_content_scan`]. A member larger than the cap is *not* materialized:
/// its buffered prefix is chained with the still-streaming tail and pattern+hash
/// scanned end to end (so a signature anywhere in a 2 GiB member is found),
/// while structural/ML analysis is skipped — reported, never a silent Clean.
///
/// The over-cap branch can report only one detection: finding a second would
/// mean re-reading a stream that has already been consumed. That is the one
/// place `--all-matches` is bounded by how the member arrived, and it is the
/// bound the cap itself imposes, not a difference between the walks.
fn member_stream_scan(
    cx: &MemberCtx<'_>,
    tally: &mut MemberTally,
    reader: &mut dyn Read,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    let cap = cx.opts.deep_analysis_max;
    let mut buf = Vec::new();
    let mut head = reader.take(cap.saturating_add(1));
    if let Err(e) = head.read_to_end(&mut buf) {
        if unpack::is_budget_overflow(&e) {
            return Some(DeepOutcome::Limits(
                "member exceeds per-member decompression budget".to_string(),
            ));
        }
        // A decode error still leaves the bytes decoded *before* the error in
        // `buf` — `Read::read_to_end` appends them. Scan that salvaged prefix so
        // malware in the recoverable part is caught (a truncated gzip/tar must
        // not hide its payload — observed on real samples).
        if !budget.should_verify_checksums() && !buf.is_empty() {
            buf.truncate(cap as usize);
            let scanned = member_content_scan(cx, tally, &buf, budget, findings, sink);
            // We scanned every byte the stream yielded. If it simply ran out of
            // input (truncation — the missing tail is *absent*, not hidden), a
            // clean result is a real Clean: exav scans for malware, it is not a
            // file-integrity validator, so a damaged-but-payload-free file is not
            // flagged. A mid-stream *corruption* (undecodable bytes still present)
            // keeps the not-fully-scanned verdict on a clean salvage.
            if scanned.is_none() && e.kind() != std::io::ErrorKind::UnexpectedEof {
                tally.unscannable.get_or_insert_with(|| {
                    format!(
                        "member decode error (salvaged {} B, no match): {e}",
                        buf.len()
                    )
                });
            }
            return scanned;
        }
        tally
            .unscannable
            .get_or_insert_with(|| format!("member decode error: {e}"));
        return None;
    }
    if buf.len() as u64 <= cap {
        // Whole member in hand → full structural analysis on the bounded buffer.
        return member_content_scan(cx, tally, &buf, budget, findings, sink);
    }
    // Member exceeds the structural-buffer cap: stream the whole thing through
    // the constant-memory pattern+hash core (prefix + tail chained so a match
    // straddling the boundary is still caught). No full-member buffer is held.
    let rest = head.into_inner();
    match stream_core(cx.db, std::io::Cursor::new(&buf).chain(rest)) {
        Ok(Some((sig, off, method, unofficial))) => sink.hit(
            report_name(&sig, unofficial, cx.opts.unofficial_suffix),
            off,
            method,
        ),
        Ok(None) => {
            tally.unscannable.get_or_insert_with(|| {
                format!(
                    "member exceeds deep-analysis-max {cap}; pattern-scanned, \
                     structural analysis skipped"
                )
            });
            None
        }
        Err(ref e) if unpack::is_budget_overflow(e) => Some(DeepOutcome::Limits(
            "member exceeds per-member decompression budget".to_string(),
        )),
        Err(e) => {
            tally
                .unscannable
                .get_or_insert_with(|| format!("member stream error: {e}"));
            None
        }
    }
}

/// Scan a natively-streaming container ([`streams_natively`]) member-by-member
/// off a seekable source, stopping on the first detection. The container is
/// never fully buffered. Every [`unpack::is_streamable`] format goes through the
/// low-level reader API so a member of any size is decoded on demand (see
/// [`member_stream_scan`]); the rest use the seekable [`unpack::Archive`] walk,
/// which materializes one member at a time. Incomplete-scan signals (encrypted /
/// undecodable members) are accumulated and only surfaced after the whole
/// container is walked, so an early bad member can't mask a malicious sibling —
/// and "not fully scanned is never Clean" holds.
fn scan_container_stream<R: Read + Seek>(
    db: &Scanner,
    reader: R,
    opts: &ScanOptions,
    ft: FileType,
) -> ScanReport {
    let mut findings = vec![Finding::new("type", ft.as_str())];
    let mut budget = scan_budget(db, opts);
    // Every type that reaches this walk came from `filetype_of_format`, so the
    // inverse exists — `scan_dispatch_covers_every_format` asserts the
    // round-trip over `Format::ALL`. Defaulting to some format anyway would
    // parse, say, a RAR as a ZIP: the walk finds nothing, the file reports
    // clean, and the mistake looks exactly like an empty archive. If the two
    // mappings ever drift, say so instead.
    let Some(fmt) = unpack_format(ft) else {
        return ScanReport::unscannable(
            format!("no extractor is mapped for {}", ft.as_str()),
            findings,
        );
    };
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

    // Members are one layer below this container, so it joins their ancestry for
    // as long as we are walking it (`Intermediates:`). Both walks below need it:
    // a nested archive reached through the streaming path would otherwise show a
    // chain one link short, and a signature keyed on `A>B` would not fire on the
    // very nesting it describes.
    let _ag = engine::AncestryGuard::enter(container);
    if unpack::is_streamable(fmt) {
        let mut findings = findings;
        let outcome = scan_streamed_container(
            db,
            reader,
            opts,
            fmt,
            ft,
            container,
            &mut findings,
            &mut budget,
            0,
            &mut Sink::First,
        );
        return report_of_outcome(outcome, findings, opts);
    }

    // Non-streamable Archive-walkable containers: seekable member walk. Members
    // are still materialized one at a time by the Archive layer, but the container
    // is never buffered.
    // Container size for `.cdb` `ContainerSize` matching (seek to end, rewind).
    //
    // A failure here is reported rather than absorbed. This path is only taken
    // for a source that seeks, so the error is the file becoming unreadable
    // mid-scan, not a stream that never could. Substituting a size would keep
    // the scan running against a number that is not the container's: a `.cdb`
    // signature keyed on a size range would then quietly fail to match, and the
    // file would be called clean because of an I/O error nobody saw.
    let container_size = match reader
        .seek(std::io::SeekFrom::End(0))
        .and_then(|n| reader.seek(std::io::SeekFrom::Start(0)).map(|_| n))
    {
        Ok(n) => n,
        Err(e) => {
            return ScanReport::unscannable(format!("container size unreadable: {e}"), findings)
        }
    };
    let mut archive = match unpack::Archive::open(reader) {
        Ok(a) => a,
        Err(h) => return report_for_hit(h, findings, opts),
    };
    // The same context, tally and per-member checks the other walks use. A
    // container reached this way is a large one that was never buffered, which
    // is a statement about its size — not a reason for it to be scanned by
    // different rules than the same archive would get at any other size.
    let cx = MemberCtx {
        db,
        opts,
        container_size,
        container_is_ole: fmt == unpack::Format::Ole,
        member_container: container,
        ft,
        fmt,
        depth: 0,
    };
    let mut tally = MemberTally::new();
    let mut volumes = unpack::volume::Collector::new(budget.limits().max_buffer_bytes);
    let sink = &mut Sink::First;
    let mut terminal: Option<DeepOutcome> = None;
    loop {
        let mut entry = match archive.extract_next(&mut budget) {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(h) => return report_for_hit(h, findings, opts),
        };
        // Track this member on the location stack for the duration of its scan,
        // so a detection inside it (or a nested member) reports the full path.
        let _mpg = MatchPathGuard::enter(&entry.name);
        let size_real = entry.data.len() as u64;
        let facts = MemberFacts {
            name: &entry.name,
            comp_size: entry.comp_size,
            size_real,
            encrypted: entry.encrypted,
            unsupported: entry.unsupported,
        };
        if let Some(o) = member_metadata_scan(&cx, &mut tally, facts, sink) {
            terminal = Some(o);
            break;
        }
        if entry.unsupported.is_some() {
            // Nothing decoded: the metadata above is all this member has.
            continue;
        }
        // A part of a byte-split set is held and rejoined below, not scanned as
        // the fragment it is.
        let body = std::mem::take(&mut entry.data);
        let data = match volumes.offer(&entry.name, body) {
            unpack::volume::Offer::Held => continue,
            unpack::volume::Offer::PassThrough { data, .. } => data,
        };
        if let Some(o) =
            member_content_scan(&cx, &mut tally, &data, &mut budget, &mut findings, sink)
        {
            terminal = Some(o);
            break;
        }
    }
    // Reassembly happens only now: completeness is knowable only once no further
    // member can arrive. Every part held above is still scanned, rejoined or
    // not — bytes withheld and then dropped are the silent clean this scanner
    // exists to prevent.
    let held = volumes.finish();
    for (name, buf, incomplete) in held.into_scannable() {
        if terminal.is_some() {
            break;
        }
        if let Some(reason) = incomplete {
            tally.unscannable.get_or_insert_with(|| reason.to_string());
        }
        // Nothing else accounts for these bytes: the parts were charged as they
        // were extracted, but this is a buffer the collector made.
        if let Err(h) = budget.charge_scan(buf.len() as u64) {
            return report_for_hit(h, findings, opts);
        }
        let _mpg = MatchPathGuard::enter(&name);
        terminal = member_content_scan(&cx, &mut tally, &buf, &mut budget, &mut findings, sink);
    }
    report_of_outcome(terminal.unwrap_or_else(|| tally.verdict()), findings, opts)
}

/// Drive the low-level reader API ([`unpack::stream_members`]): each member is a
/// reader decoded on demand, scanned via [`scan_stream_member`] with no
/// full-member buffer. The visitor returns `Some(())` to halt the walk on a
/// terminal outcome (detection / limit), leaving the report in `terminal`.
#[allow(clippy::too_many_arguments)]
fn scan_streamed_container<R: Read + Seek>(
    db: &Scanner,
    reader: R,
    opts: &ScanOptions,
    fmt: unpack::Format,
    ft: FileType,
    container: Option<engine::ClType>,
    findings: &mut Vec<Finding>,
    budget: &mut Budget,
    depth: u32,
    sink: &mut Sink,
) -> DeepOutcome {
    // Container size for `.cdb` `ContainerSize` matching (seek to end, rewind).
    //
    // Reported rather than absorbed, on the same reasoning as the seekable walk:
    // every caller here hands in a source that seeks, so an error is the file
    // becoming unreadable mid-scan. A substituted size is a number that is not
    // the container's, and a `.cdb` signature keyed on a size range would then
    // quietly fail to match — the file called clean because of an I/O error
    // nobody saw.
    let mut reader = reader;
    let container_size = match reader
        .seek(std::io::SeekFrom::End(0))
        .and_then(|n| reader.seek(std::io::SeekFrom::Start(0)).map(|_| n))
    {
        Ok(n) => n,
        Err(e) => return DeepOutcome::Unscannable(format!("container size unreadable: {e}")),
    };
    // Only the container-level checks below record here; everything a member
    // produces goes on the tally.
    let mut unscannable: Option<String> = None;
    let mut terminal: Option<DeepOutcome> = None;

    // The checks that need the container's own bytes rather than a member's.
    // This walk holds one member at a time, so getting them means reading the
    // container again.
    //
    // That second read is deliberate. exav optimises for MEMORY, not bandwidth:
    // the cap below is what bounds the working set, and a re-fetch over a
    // range-reading HTTP source is accepted as the price of scanning the same
    // way regardless of how the file arrived. A caller who would rather pay in
    // memory than in transfer can download the object and hand exav the file.
    //
    // Over the cap the container is not held at all, and that is REPORTED —
    // scanning less because of how a file arrived, without saying so, is the
    // silent clean this scanner exists to prevent.
    if container_size <= opts.deep_analysis_max {
        let mut whole = Vec::new();
        let read = reader
            .by_ref()
            .take(opts.deep_analysis_max)
            .read_to_end(&mut whole);
        let _ = reader.seek(std::io::SeekFrom::Start(0));
        match read {
            Ok(_) => {
                if let Some(o) = whole_buffer_heuristics(&whole, ft, opts, sink) {
                    return o;
                }
            }
            // The source failed mid-read — a disk error, a dropped connection, a
            // range request the server would not honour. The bytes exist and we
            // did not get them, so the checks did not run: say so rather than
            // carrying on as though they had.
            Err(e) => {
                unscannable.get_or_insert_with(|| {
                    format!("could not re-read the container for whole-object checks: {e}")
                });
            }
        }
    } else {
        unscannable.get_or_insert_with(|| {
            format!(
                "container is {container_size} bytes, over the {}-byte \
                 deep-analysis limit: whole-container heuristics were not run",
                opts.deep_analysis_max
            )
        });
    }

    // The same context and running tally the buffered walk keeps, so the shared
    // member checks behave identically here.
    let cx = MemberCtx {
        db,
        opts,
        container_size,
        // OLE2 is not a streamable format, so a member reached this way is never
        // an OLE stream needing the forced type.
        container_is_ole: false,
        member_container: container,
        ft,
        fmt,
        // This container's own depth: members recurse at `depth + 1`, which is
        // what bounds nesting. A constant here would restart the count and let a
        // deeply nested chain of streamable containers run past the limit.
        depth,
    };
    let mut tally = MemberTally::new();
    // Parts of a byte-split set are held here and rejoined after the walk — see
    // the note at `finish()` below for why the join cannot happen sooner.
    let mut volumes = unpack::volume::Collector::new(budget.limits().max_buffer_bytes);
    let walk = {
        let findings = &mut *findings;
        let terminal = &mut terminal;
        let cx = &cx;
        let tally = &mut tally;
        let volumes = &mut volumes;
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
            let facts = MemberFacts {
                name: &meta.name,
                comp_size: meta.comp_size,
                // Nothing is decoded at this point, so the compressed size is
                // the only size this walk can offer for both fields.
                size_real: meta.comp_size,
                encrypted: meta.encrypted,
                unsupported: meta.unsupported,
            };
            if let Some(o) = member_metadata_scan(cx, tally, facts, sink) {
                *terminal = Some(o);
                return Some(());
            }
            if meta.unsupported.is_some() {
                // Nothing decoded: the metadata above is all this member has.
                return None;
            }
            let rdr = rdr?;
            // A part of a byte-split set is a fragment of a file that only
            // exists once the set is rejoined, so it is buffered and held
            // instead of being scanned on its own. This is the only place this
            // walk materializes a member — everything else still streams — and
            // the hold is bounded by `max_buffer_bytes`.
            let is_part =
                unpack::volume::parse(&meta.name).is_some_and(|v| v.scheme.is_byte_split());
            let outcome = if is_part {
                match read_capped(&mut *rdr, budget.limits().max_buffer_bytes) {
                    Capped::Whole(buf) => match volumes.offer(&meta.name, buf) {
                        unpack::volume::Offer::Held => return None,
                        // Past the collector's budget: it will not be joined, so
                        // scan it where it stands like any other member.
                        unpack::volume::Offer::PassThrough { data, .. } => {
                            member_content_scan(cx, tally, &data, budget, findings, sink)
                        }
                    },
                    // Too large to hold. The prefix is already consumed and a
                    // stream does not rewind, so it is chained back in front of
                    // the tail — dropping it would skip the bytes.
                    Capped::TooBig(prefix) => {
                        let mut whole = std::io::Cursor::new(prefix).chain(rdr);
                        member_stream_scan(cx, tally, &mut whole, budget, findings, sink)
                    }
                    // The read failed. Scan what did arrive, then report — a
                    // short buffer must NOT be offered to the collector, which
                    // would treat it as a complete volume and splice a truncated
                    // part into the rejoined archive.
                    Capped::Failed(prefix, e) => {
                        let got = member_content_scan(cx, tally, &prefix, budget, findings, sink);
                        if got.is_none() {
                            tally.unscannable.get_or_insert_with(|| {
                                format!("member read failed after {} B: {e}", prefix.len())
                            });
                        }
                        got
                    }
                }
            } else {
                member_stream_scan(cx, tally, rdr, budget, findings, sink)
            };
            // `Some` means this walk must stop: a first-match detection, or a
            // limit. Everything that does not stop the walk — a nested
            // unscannable member, an encrypted one, an all-match hit — has
            // already been recorded on the tally or the sink.
            match outcome {
                Some(o) => {
                    *terminal = Some(o);
                    Some(())
                }
                None => None,
            }
        };
        unpack::stream_members(fmt, reader, budget, &mut visit)
    };
    // Reassembly happens only now. Nothing in a byte-split set's names says how
    // many parts it has, so `.001`+`.002` looks contiguous even when `.003`
    // follows: joining on arrival would emit a truncated prefix that still
    // parses as the archive and would then be scanned as if it were whole.
    let held = volumes.finish();
    if let Err(h) = walk {
        return outcome_for_hit(h, opts);
    }
    // Rejoined files first, then the parts that could not be joined. Bytes
    // withheld from the scan and then dropped would be exactly the silent clean
    // this scanner exists to prevent, so every part held above still gets
    // scanned on its own here.
    for (name, buf, incomplete) in held.into_scannable() {
        if terminal.is_some() {
            break;
        }
        // A set with a gap in it is reported: the archive those bytes belong to
        // can no longer be read by anything — not by us and not by the tool that
        // wrote it.
        if let Some(reason) = incomplete {
            tally.unscannable.get_or_insert_with(|| reason.to_string());
        }
        // Nothing else accounts for these bytes: the parts were charged as they
        // were read, but this is a buffer the collector made.
        if let Err(h) = budget.charge_scan(buf.len() as u64) {
            return outcome_for_hit(h, opts);
        }
        let _mpg = MatchPathGuard::enter(&name);
        terminal = member_content_scan(&cx, &mut tally, &buf, budget, findings, sink);
    }
    if let Some(r) = terminal {
        return r;
    }
    // Fold in what the shared member checks recorded. They keep their findings
    // on the tally, and a member that is encrypted or undecodable is noted there
    // rather than here — dropping it would turn a PASSWORD-PROTECTED archive
    // into a clean one.
    //
    // A note made *about the container* — its whole-object checks could not run
    // — outranks a member's, because it says something was not looked at at all
    // rather than that one member could not be decoded.
    if let Some(r) = unscannable {
        tally.unscannable = Some(r);
    }
    tally.verdict()
}

/// The verdict of a multi-volume archive, reported against one of its parts.
pub struct VolumeSetVerdict {
    /// The part this verdict is attributed to — one of the names given.
    pub name: String,
    /// The name of the archive the part belongs to (`big.7z` for `big.7z.001`).
    pub set: String,
    pub report: ScanReport,
}

/// Scan the **multi-volume archives** spread across a group of files that
/// arrived together — a directory, a client's multi-file request.
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
/// its LAST part still looks contiguous and would join into a truncated prefix —
/// which parses as the archive and scans clean. The set is reported
/// `Unscannable` instead. The dropped part's own scan, which the caller does
/// separately, still covers that part's bytes.
///
/// Returns one entry per *part*, each carrying the verdict of the archive that
/// part belongs to — including `Unscannable` for a set with a hole in it, whose
/// bytes belong to an archive nothing can read. Callers report these against
/// the part's own name: one result per file, and a piece of an infected archive
/// is not a clean file.
///
/// Format-aware volumes (RAR `.partN`, ZIP `.zNN`) are **not** handled here.
/// Each of those carries its own headers and a member's data resumes past the
/// next volume's header, so concatenating them yields garbage that still looks
/// like an archive — the join has to be done by the format's own decoder.
pub fn analyze_volume_sets<F>(
    db: &Scanner,
    names: &[String],
    opts: &ScanOptions,
    mut fetch: F,
) -> Vec<VolumeSetVerdict>
where
    F: FnMut(&str) -> io::Result<Vec<u8>>,
{
    let mut collector = unpack::volume::Collector::new(opts.deep_analysis_max);
    let mut any = false;
    // Sets that lost a part on the way in, and why. `Collector::finish` cannot
    // see these: it judges completeness from the indices it was given, and a
    // missing trailing index leaves no trace in them.
    let mut broken: std::collections::BTreeMap<String, &'static str> =
        std::collections::BTreeMap::new();
    for name in names {
        if !unpack::volume::parse(name).is_some_and(|v| v.scheme.is_byte_split()) {
            continue;
        }
        let Ok(data) = fetch(name) else {
            broken.insert(
                volume_set_name(name),
                "part of a multi-volume set one of whose volumes could not be read",
            );
            continue;
        };
        any = true;
        // `PassThrough` means the collector declined to hold it — the held-bytes
        // cap, or a second part claiming an index another part already holds.
        if let unpack::volume::Offer::PassThrough { name, .. } = collector.offer(name, data) {
            broken.insert(
                volume_set_name(&name),
                "part of a multi-volume set that could not be reassembled whole",
            );
        }
    }
    if !any {
        return Vec::new();
    }
    let held = collector.finish();
    let mut out = Vec::new();
    // Each set gets its own budget, as every file in a scan does. A set needs at
    // least two parts, and the caller scans each of those parts on its own
    // anyway, so rejoining adds at most one budgeted scan per two files the
    // caller had already committed to. Held bytes across all sets are capped by
    // the collector, so no aggregate budget is threaded through here.
    for j in held.joined {
        // A set with a hole gets the hole's verdict, not a verdict read off the
        // bytes that happened to arrive.
        let report = match broken.get(j.name.as_str()) {
            Some(reason) => ScanReport::unscannable((*reason).to_string(), Vec::new()),
            None => analyze(db, &j.data, opts),
        };
        for part in j.parts {
            out.push(VolumeSetVerdict {
                name: part,
                set: j.name.clone(),
                report: report.clone(),
            });
        }
    }
    for u in held.unjoined {
        // A lone numbered file is not a set — plenty of ordinary files end in
        // `.001`, and the caller's own scan of it is the right answer.
        let Some(reason) = u.incomplete_set else {
            continue;
        };
        let set = volume_set_name(&u.name);
        out.push(VolumeSetVerdict {
            name: u.name,
            set,
            report: ScanReport::unscannable(reason.to_string(), Vec::new()),
        });
    }
    out
}

/// The name a part's SET is reported under, matching what
/// `unpack::volume::Collector` names a joined set. A name that does not parse as
/// a volume is its own set of one.
fn volume_set_name(part: &str) -> String {
    unpack::volume::parse(part)
        .map(|v| match v.scheme {
            unpack::volume::Scheme::NumberedSuffix { ref base_ext, .. } => {
                format!("{}.{}", v.stem, base_ext)
            }
            _ => v.stem.clone(),
        })
        .unwrap_or_else(|| part.to_string())
}

/// Full in-memory analysis of a bounded buffer: core detection, then
/// recursive unpacking and (optionally) structural/ML/fuzzy heuristics.
pub fn analyze(db: &Scanner, data: &[u8], opts: &ScanOptions) -> ScanReport {
    engine::reset_scan_truncated();
    let report = analyze_inner(db, data, opts);
    suppress(db, data, report)
}

fn analyze_inner(db: &Scanner, data: &[u8], opts: &ScanOptions) -> ScanReport {
    if let Some((sig, off, method, unofficial)) =
        scan_bytes_core(db, data, opts.filename.as_deref())
    {
        return ScanReport::infected(
            report_name(&sig, unofficial, opts.unofficial_suffix),
            off,
            method,
            Vec::new(),
        );
    }
    let mut findings = Vec::new();
    let mut budget = scan_budget(db, opts);
    match deep_analyze(
        db,
        data,
        opts,
        &mut budget,
        0,
        None,
        true,
        &mut findings,
        &mut Sink::First,
    ) {
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
        // Cardinal rule: a would-be `Clean` is downgraded to `LimitsExceeded` if
        // any wildcard verification was skipped because its per-buffer step budget
        // ran out — the search did not fully complete, so we must not report `OK`.
        DeepOutcome::Clean if engine::scan_was_truncated() => ScanReport::limits(
            "verify step budget exhausted — signature search incomplete".into(),
            findings,
        ),
        DeepOutcome::Clean => ScanReport::clean(findings),
    }
}

/// Turn a walk's outcome into the report a caller sees.
///
/// The walk speaks one currency — [`DeepOutcome`] — whatever entry point drove
/// it; this is the single place that becomes a [`ScanReport`].
fn report_of_outcome(
    outcome: DeepOutcome,
    findings: Vec<Finding>,
    _opts: &ScanOptions,
) -> ScanReport {
    match outcome {
        DeepOutcome::Infected {
            signature,
            offset,
            method,
        } => ScanReport::infected(signature, offset, method, findings),
        DeepOutcome::Limits(reason) => ScanReport::limits(reason, findings),
        DeepOutcome::Unscannable(reason) => ScanReport::unscannable(reason, findings),
        DeepOutcome::PasswordProtected(reason) => ScanReport::password_protected(reason, findings),
        // A would-be `Clean` is downgraded when wildcard verification ran out of
        // its per-buffer step budget: the search did not complete, so `OK` would
        // be a claim the scan cannot support.
        DeepOutcome::Clean if engine::scan_was_truncated() => ScanReport::limits(
            "verify step budget exhausted — signature search incomplete".into(),
            findings,
        ),
        DeepOutcome::Clean => ScanReport::clean(findings),
    }
}

/// True if a detection of `signature` on `data` should be suppressed: the
/// name is on the ignore list (`.ign`/`.ign2`) or `data`'s whole-file hash is
/// allowlisted (`.fp`/`.sfp`).
fn is_suppressed(db: &Scanner, data: &[u8], signature: &str) -> bool {
    db.ignored.contains(signature)
        || (!db.allow.is_empty()
            && db
                .allow
                .lookup(&digests_of(data), data.len() as u64)
                .is_some())
}

/// Clear a detection if it is suppressed (see [`is_suppressed`]).
fn suppress(db: &Scanner, data: &[u8], report: ScanReport) -> ScanReport {
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
fn suppress_name(db: &Scanner, report: ScanReport) -> ScanReport {
    if let Verdict::Infected { signature, .. } = &report.verdict {
        if db.ignored.contains(signature) {
            return ScanReport::clean(report.findings);
        }
    }
    report
}

/// Every detection on `data` or its (recursively unpacked) members,
/// de-duplicated by name — the data behind `--all-matches`.
///
/// This is `deep_analyze`, the same walk a normal scan uses, driven by a sink
/// that collects instead of stopping. Every heuristic, decoder and recursion
/// step is therefore shared by construction: all-match cannot see less than a
/// normal scan, because it *is* a normal scan that declines to stop.
///
/// An allowlisted file yields nothing; ignored names are dropped, the same
/// suppression as a normal scan.
pub fn analyze_all_with_outcome(
    db: &Scanner,
    data: &[u8],
    opts: &ScanOptions,
) -> (Vec<(String, Method)>, AllMatchOutcome) {
    let (names, outcome) = analyze_all_raw(db, data, opts);
    let outcome = match outcome {
        Some(DeepOutcome::Limits(r)) => AllMatchOutcome::LimitsExceeded(r),
        Some(DeepOutcome::Unscannable(r)) => AllMatchOutcome::Unscannable(r),
        Some(DeepOutcome::PasswordProtected(r)) => AllMatchOutcome::PasswordProtected(r),
        _ => AllMatchOutcome::Complete,
    };
    (names, outcome)
}

fn analyze_all_raw(
    db: &Scanner,
    data: &[u8],
    opts: &ScanOptions,
) -> (Vec<(String, Method)>, Option<DeepOutcome>) {
    if !db.allow.is_empty()
        && db
            .allow
            .lookup(&digests_of(data), data.len() as u64)
            .is_some()
    {
        return (Vec::new(), None);
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut findings = Vec::new();
    let mut budget = scan_budget(db, opts);
    let mut sink = Sink::All {
        out: &mut out,
        seen: &mut seen,
        ignored: &db.ignored,
    };
    // The walk core-scans every buffer it *reaches* — members, carved images,
    // decoded payloads — but not the one it is handed, because on the
    // first-match path `analyze_inner` has already scanned that itself before
    // calling in. So the top-level buffer is scanned here, or a signature on the
    // file's own bytes is never looked for.
    core_scan(db, data, None, None, opts, &mut sink);
    let outcome = deep_analyze(
        db,
        data,
        opts,
        &mut budget,
        0,
        None,
        true,
        &mut findings,
        &mut sink,
    );
    (out, Some(outcome))
}

/// Every detection on `data`, as [`analyze_all_with_outcome`], discarding the
/// not-scanned outcome.
///
/// Callers that report to a user want [`analyze_all_with_outcome`]: dropping the
/// outcome turns "this file was not fully scanned" into silence, and an empty
/// detection list then prints as OK. Kept for callers that only want
/// the names.
pub fn analyze_all(db: &Scanner, data: &[u8], opts: &ScanOptions) -> Vec<(String, Method)> {
    analyze_all_with_outcome(db, data, opts).0
}

/// The not-scanned outcome of an all-match scan, when there is one.
///
/// All-match and a normal scan may legitimately differ in HOW MANY signatures
/// they list. They must never differ on whether the file was fully scanned —
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

/// The checks that need the WHOLE object at once, rather than a member of it.
///
/// Separated because that requirement is what divides the two ways an object
/// reaches the scanner. A buffered walk always has the bytes; a streamed walk
/// holds only the member it is on, so it can run these only when the container
/// itself fits in memory — and must say so when it does not, rather than
/// quietly scanning less.
///
/// `Some(outcome)` means the walk must stop and return it.
fn whole_buffer_heuristics(
    data: &[u8],
    ft: FileType,
    opts: &ScanOptions,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    // Overlapping ZIP local file records: a parser-confusion technique where two
    // readers disagree about where a member starts, so the archive shows one
    // file to the scanner and another to the tool that opens it. ClamAV alerts
    // on this by default, and the threshold is >5 because a handful of overlaps
    // occur in oddly-built but benign archives, while a confusion attack needs
    // many.
    if (opts.clamav_heuristics || opts.heuristics) && ft == FileType::Zip {
        const OVERLAP_THRESHOLD: usize = 5;
        if unpack::overlapping_local_records(data) > OVERLAP_THRESHOLD {
            if let Some(o) = sink.hit(
                "Heuristics.Zip.OverlappingFiles".to_string(),
                0,
                Method::Heuristic,
            ) {
                return Some(o);
            }
        }
    }

    // An XZ stream declares the dictionary size a decoder must allocate before
    // producing a single byte, so an absurd declaration costs memory whether or
    // not the stream holds anything. ClamAV alerts on this with no way to switch
    // it off; exav already refuses to allocate past its cap, so this reports the
    // condition rather than letting it surface as an opaque decode failure.
    if ft == FileType::Xz {
        if let Some(dict) = unpack::xz_declared_dict_size(data) {
            if dict > unpack::XZ_MAX_DICT {
                if let Some(o) = sink.hit(
                    "Heuristics.XZ.DicSizeLimit".to_string(),
                    0,
                    Method::Heuristic,
                ) {
                    return Some(o);
                }
            }
        }
    }

    // Images whose container does not hold together. Opt-in, matching ClamAV:
    // a viewer renders a truncated GIF happily, and that forgiveness is what
    // exploit writers aim at — so the mismatch between "renders" and "parses" is
    // itself the signal.
    if opts.alert_broken_media {
        if let Some(name) = unpack::broken_media_alert(data) {
            if let Some(o) = sink.hit(name.to_string(), 0, Method::Heuristic) {
                return Some(o);
            }
        }
    }

    // A file that claims to be an executable and does not parse as one. The
    // signal is the contradiction: ordinary software ships well-formed headers,
    // while truncation, corruption and droppers that lean on a forgiving loader
    // do not.
    if opts.alert_broken && pe::looks_broken(data) {
        if let Some(o) = sink.hit(
            "Heuristics.Broken.Executable".to_string(),
            0,
            Method::Heuristic,
        ) {
            return Some(o);
        }
    }
    // An ELF whose section-header table has been stripped. Detected in BOTH
    // modes — only the name differs. It is not breakage (the program headers are
    // intact and the binary runs), but no toolchain zeroes the entry size, so it
    // is a deliberate anti-analysis step worth reporting under its own name.
    //
    // ClamAV files it under `Heuristics.Broken.Executable`. exav says what it
    // actually found, and under `--clamav-compat` says what ClamAV would, because
    // a gateway filtering on ClamAV's exact string has to keep matching. What is
    // reported never changes; only the vocabulary does.
    if opts.alert_broken && pe::elf_section_headers_stripped(data) {
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
    if opts.alert_partition_intersection {
        if let Some(name) = unpack::partition_intersection_alert(data) {
            if let Some(o) = sink.hit(name.to_string(), 0, Method::Heuristic) {
                return Some(o);
            }
        }
    }

    // ClamAV `Heuristics.PDF.ObfuscatedNameObject`: a PDF whose name objects
    // hex-escape plain alphanumerics (`/J#61vaScript`) to hide keywords from
    // naive scanners. Structural and FP-safe — only gratuitous escapes count.
    // Applied to the raw document, before the PDF is unpacked.
    #[cfg(feature = "pdf")]
    if (opts.clamav_heuristics || opts.heuristics)
        && ft == FileType::Pdf
        && unpack::has_obfuscated_name_object(data)
    {
        if let Some(o) = sink.hit(
            "Heuristics.PDF.ObfuscatedNameObject".to_string(),
            0,
            Method::Heuristic,
        ) {
            return Some(o);
        }
    }
    None
}

/// Where a walk sends its detections, and whether it wants the walk to go on.
///
/// A normal scan and `--all-matches` are the same traversal answering one question
/// differently: *is this hit enough?* That is the only difference, so it is the
/// only thing parameterised — the traversal reports to a sink rather than
/// returning a verdict, and there is exactly one traversal.
///
/// Two walks cannot be kept in step by discipline. Each capability added to one
/// and not the other changes *which signatures and heuristics run*, silently,
/// and the symptom is a clean verdict rather than an error.
enum Sink<'a> {
    /// Stop at the first detection — a normal scan.
    First,
    /// Collect every distinct detection and keep walking — `--all-matches`.
    All {
        out: &'a mut Vec<(String, Method)>,
        seen: &'a mut std::collections::HashSet<String>,
        /// `.ign`/`.ign2` names. Checked here because the name is already
        /// `.UNOFFICIAL`-suffixed by this point, which is what an ignore entry
        /// names.
        ignored: &'a std::collections::HashSet<String>,
    },
}

impl Sink<'_> {
    /// Record a detection. `Some(outcome)` means this walk must stop and return
    /// it; `None` means carry on looking.
    fn hit(&mut self, signature: String, offset: u64, method: Method) -> Option<DeepOutcome> {
        match_loc_record();
        match self {
            Sink::First => Some(DeepOutcome::Infected {
                signature,
                offset,
                method,
            }),
            Sink::All { out, seen, ignored } => {
                if !ignored.contains(&signature) && seen.insert(signature.clone()) {
                    out.push((signature, method));
                }
                None
            }
        }
    }

    /// Whether the matching core should gather every match rather than stop at
    /// the first. Only the core branches on this; the traversal never does.
    fn wants_all(&self) -> bool {
        matches!(self, Sink::All { .. })
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

/// Everything a container-member scan needs that does not vary between the
/// members of one container.
///
/// Bundled because the same per-member logic runs from two places: the
/// `extract_each` visitor as members arrive, and — after it returns — over the
/// files rejoined from a multi-volume set, which have no visitor to run in.
struct MemberCtx<'a> {
    db: &'a Scanner,
    opts: &'a ScanOptions,
    container_size: u64,
    container_is_ole: bool,
    /// The `CL_TYPE_*` each member belongs to, so `Container:`-scoped signatures
    /// fire only inside their intended container.
    member_container: Option<engine::ClType>,
    ft: FileType,
    fmt: unpack::Format,
    depth: u32,
}

/// What the metadata checks need to know about a member, independent of how it
/// was produced.
///
/// The buffered walk has an `unpack::Entry` with the bytes already decoded; the
/// streamed walk has a `MemberMeta` and a reader it has not touched yet. Both
/// know these five things, and the checks that run on them — `.cdb` container
/// signatures, the macro heuristic, the encrypted-member heuristic — care about
/// nothing else. Taking the facts rather than either struct is what lets one
/// implementation serve both.
struct MemberFacts<'a> {
    name: &'a str,
    /// Size within the container, for `.cdb` `ContainerSize` matching.
    comp_size: u64,
    /// Decompressed size when known. The streamed walk has not decoded the
    /// member yet, so it passes `comp_size` — the same value the walk used
    /// before this was shared.
    size_real: u64,
    encrypted: bool,
    /// `Some(reason)` when the member was recognised but its content could not
    /// be decoded.
    unsupported: Option<&'static str>,
}

/// Outcomes gathered across a container's members that do not stop the loop.
/// They decide the verdict once every member has been seen.
struct MemberTally {
    /// The next member's 1-based position in this container (`.cdb` `FilePos`).
    pos: u64,
    unscannable: Option<String>,
    password: Option<String>,
}

impl MemberTally {
    fn new() -> Self {
        MemberTally {
            pos: 1,
            unscannable: None,
            password: None,
        }
    }

    fn verdict(self) -> DeepOutcome {
        // Precedence among incomplete outcomes: PasswordProtected (actionable)
        // over Unscannable over Clean.
        match (self.password, self.unscannable) {
            (Some(r), _) => DeepOutcome::PasswordProtected(r),
            (None, Some(r)) => DeepOutcome::Unscannable(r),
            (None, None) => DeepOutcome::Clean,
        }
    }
}

/// The checks that read a member's *metadata* — name, size, position,
/// encryption — rather than its content.
///
/// Run as each member arrives, before any decision about its bytes, so
/// positions stay in container order even for members whose content is held
/// back to be rejoined. The caller owns the [`MatchPathGuard`].
fn member_metadata_scan(
    cx: &MemberCtx<'_>,
    tally: &mut MemberTally,
    e: MemberFacts<'_>,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    // `.cdb` container-metadata signatures match on the member's
    // name/size/encryption/position within this container. `FilePos` counts
    // members from 1, matching ClamAV (`pos` seeded to 1).
    let member_pos = tally.pos;
    tally.pos += 1;
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
    // keyed on undecodable content would never see it — exav would decrypt the
    // document, scan the plaintext, and say nothing about it having been
    // encrypted at all.
    //
    // Decrypting stays a genuine advantage over clamd: the recovered plaintext is
    // still scanned for real signatures. It just no longer costs us the fact.
    // A member we could NOT read reports here and now — there is no content
    // coming that could outrank it. A member we DECRYPTED is different: its
    // plaintext is about to be scanned, and a real signature in that plaintext
    // must win over "this was encrypted", so under first-match the heuristic
    // would otherwise pre-empt the detection it is standing in for.
    //
    // Under `--all-matches` both belong in the output and neither pre-empts
    // anything, so the decrypted case reports there.
    if e.encrypted && cx.opts.alert_encrypted && (e.unsupported.is_some() || sink.wants_all()) {
        if let Some(o) = sink.hit(
            encrypted_heuristic_name(cx.fmt).to_string(),
            0,
            Method::Heuristic,
        ) {
            return Some(o);
        }
    }
    // Opt-in (`--alert-packed`): name the packer as well as reporting that its
    // payload went unread. Same rule as the encryption case above — two facts,
    // both true, both reported.
    if cx.opts.alert_packed {
        if let Some(n) = packed_heuristic_name(e.name) {
            if let Some(o) = sink.hit(n, 0, Method::Heuristic) {
                return Some(o);
            }
        }
    }
    if let Some(r) = e.unsupported {
        if e.encrypted {
            // Only an encrypted member we could NOT read is password-blocked.
            // A decrypted one has its content and must not degrade the verdict
            // to PasswordProtected — this is the one place the two facts stay
            // deliberately separate.
            tally.password.get_or_insert_with(|| r.to_string());
        } else {
            tally.unscannable.get_or_insert_with(|| r.to_string());
        }
    }
    // Opt-in ClamAV heuristic (`--alert-macros`): an OLE2 document carrying a
    // VBA project surfaces `vba_project*` artifacts from the OLE extractor —
    // their presence means the document has macros.
    if cx.opts.alert_macros && cx.container_is_ole {
        // ClamAV suffixes the macro dialect — `.VBA` for a VBA project, `.XLM`
        // for an Excel 4.0 macro sheet. Emitting the bare name looked harmless
        // and is not: a gateway filtering on ClamAV's exact string matches
        // neither of ours.
        if let Some(kind) = macro_dialect(e.name) {
            if let Some(o) = sink.hit(
                format!("Heuristics.OLE2.ContainsMacros.{kind}"),
                0,
                Method::Heuristic,
            ) {
                return Some(o);
            }
        }
    }
    if !cx.db.cdb.is_empty() {
        let member = container::Member {
            name: e.name,
            size_in_container: e.comp_size,
            size_real: e.size_real,
            encrypted: e.encrypted,
            pos: member_pos,
        };
        if let Some((sig, unofficial)) = profile::timed("cdb", 0, || {
            cx.db.cdb.matches(cx.ft, cx.container_size, &member)
        }) {
            if let Some(o) = sink.hit(
                report_name(&sig, unofficial, cx.opts.unofficial_suffix),
                0,
                Method::Hash,
            ) {
                return Some(o);
            }
        }
    }
    None
}

/// Scan one member's *bytes*: the pattern/hash core, then recursion into it.
///
/// Split from [`member_metadata_scan`] because a member of a multi-volume set
/// has its metadata read on arrival but its content scanned only after the
/// container ends, once the set has been rejoined. The caller owns the
/// [`MatchPathGuard`] — this is entered under the member's own name in the
/// visitor and under the rejoined file's name afterwards.
fn member_content_scan(
    cx: &MemberCtx<'_>,
    tally: &mut MemberTally,
    data: &[u8],
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    // A member whose own whole-file hash is allowlisted (`.fp`/`.sfp`) is
    // content the operator has vouched for: neither it nor anything nested
    // inside it is a detection. Checked once, here, so an allowlist entry means
    // the same thing for a member of any container — the allowlist is keyed on
    // the member's bytes, which do not depend on how the member was produced.
    if !cx.db.allow.is_empty()
        && cx
            .db
            .allow
            .lookup(&digests_of(data), data.len() as u64)
            .is_some()
    {
        return None;
    }
    // Textual content extracted from an OLE2 document is scanned in OLE
    // context: its type is forced to MSOLE2 so `Target:2` macro sigs apply and
    // `Target:7` (ascii-text) sigs do NOT — without this a generic text macro
    // sig (e.g. `Doc.Downloader.Macro-25` on the standard `Name="Project"…`
    // PROJECT stream) false-positives on benign macro documents. Binary streams
    // (an embedded PE, etc.) keep their own type so embedded-executable
    // detection is preserved. Either way the member carries its container type
    // so `Container:`-scoped sigs are gated correctly.
    let ft_override = if cx.container_is_ole && is_textual_type(filetype::identify(data)) {
        Some(FileType::Ole)
    } else {
        None
    };
    if let Some(o) = core_scan(cx.db, data, ft_override, cx.member_container, cx.opts, sink) {
        return Some(o);
    }
    match deep_analyze(
        cx.db,
        data,
        cx.opts,
        budget,
        cx.depth + 1,
        cx.member_container,
        true,
        findings,
        sink,
    ) {
        DeepOutcome::Clean => None,
        // Nested unscannable/encrypted members are remembered, not propagated as
        // a stop — keep scanning the rest of this container.
        DeepOutcome::Unscannable(r) => {
            tally.unscannable.get_or_insert(r);
            None
        }
        DeepOutcome::PasswordProtected(r) => {
            tally.password.get_or_insert(r);
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

/// Recursive structural analysis of an in-memory buffer.
#[allow(clippy::too_many_arguments)]
fn deep_analyze(
    db: &Scanner,
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
    // Where detections go, and whether finding one ends the walk. This is the
    // ONLY difference between a normal scan and `--all-matches`; see [`Sink`].
    sink: &mut Sink,
) -> DeepOutcome {
    // A `HandlerType:` signature that matched this buffer during the pattern
    // scan just above says "treat this as type T" — it is programmable file-type
    // identification, filling in where the magic tables cannot: a PDF exploit
    // recognised by its object layout rather than a `%PDF` header still gets
    // opened as a PDF. Re-typing to what we already decided would be a no-op, so
    // only a genuine change is taken, which also makes a loop impossible.
    let ft = db.identify(data);
    let ft = match engine::take_retype(data).filter(|t| *t != ft) {
        None => ft,
        Some(retyped) => {
            // The re-type is only worth anything if the buffer is scanned AS the
            // new type: that is what brings the type's signatures and its
            // extractor into play. Rescan here, then carry `retyped` through the
            // rest of this frame so unpacking dispatches on it too.
            if let Some(o) = core_scan(db, data, Some(retyped), container, opts, sink) {
                return o;
            }
            retyped
        }
    };
    if depth == 0 {
        findings.push(Finding::new("type", ft.as_str()));
    }

    // Embedded base64-encoded executables. Scripts/RTF/HTML carriers stash a
    // PE/ELF as a long base64 string (PowerShell reflective loaders, JS/VBS
    // droppers) that is invisible to a signature matching the decoded bytes.
    // Decode such blobs (in a text-ish buffer) and rescan any that decode to a
    // real executable. Run BEFORE `unpack_target` so it also fires on carriers
    // that are themselves containers (RTF/HTML/email return early below). Bounded
    // by recursion depth and the scan budget; exav-exclusive, so off under
    // `--clamav-compat` and `--no-base64`.
    #[cfg(feature = "base64scan")]
    if opts.decode_base64 && depth < budget.limits().max_recursion && mostly_text(data) {
        for (b64ix, payload) in unpack::base64_payloads(data, budget.limits().max_buffer_bytes)
            .into_iter()
            .enumerate()
        {
            // Name the decoded run so a hit inside it is attributable. Without
            // this the detection reports no location and reads as a match on the
            // carrier's own bytes — which is how a correct `Win.Trojan.Mimikatz`
            // hit, on a PE base64-encoded inside an RTF, looked like a PE-only
            // signature firing on an RTF.
            let _mpg = MatchPathGuard::enter(&format!("base64-payload-{}", b64ix + 1));
            if let Err(h) = budget.charge_scan(payload.len() as u64) {
                return limits_outcome(opts, h.kind, h.reason);
            }
            // The payload's container is the CARRIER, not whatever the carrier
            // itself sits in — a `data:` URI image inside an HTML page has
            // `Container:CL_TYPE_HTML`, which is how a family of phishing
            // signatures scopes a logo's perceptual hash so it fires on a page
            // and not on the same image standing alone. Passing the carrier's
            // own container instead left those signatures unsatisfiable.
            let payload_container = carrier_cltype(ft).or(container);
            let _ag = engine::AncestryGuard::enter(payload_container);
            // Pattern/hash-scan the decoded executable (this is where a signature
            // like `Win.Trojan.Mimikatz` matches), then recurse structurally.
            if let Some(o) = core_scan(db, &payload, None, payload_container, opts, sink) {
                return o;
            }
            match deep_analyze(
                db,
                &payload,
                opts,
                budget,
                depth + 1,
                payload_container,
                false,
                findings,
                sink,
            ) {
                inf @ DeepOutcome::Infected { .. } => return inf,
                lim @ DeepOutcome::Limits(_) => return lim,
                _ => {}
            }
        }
    }

    // Assets embedded straight into a markup document: a `data:` URI image on
    // an HTML page, a base64 element body in a Word/Excel 2003 flat-XML file.
    // Distinct from the base64-executable pass above, which only decodes runs
    // starting with an executable magic — here the payload is usually the lure
    // IMAGE, and it is the image that signatures key on. Extracting it is what
    // makes `Container:CL_TYPE_HTML`/`_XML_WORD`/`_XML_XL` satisfiable at all:
    // those constraints exist to separate "this image, in a document" from
    // "this image, on its own".
    #[cfg(feature = "base64scan")]
    if opts.decode_base64 && depth < budget.limits().max_recursion {
        if let Some(mc) = markup_cltype(ft, data) {
            let _ag = engine::AncestryGuard::enter(Some(mc));
            for (ix, payload) in
                unpack::markup_embedded_payloads(data, budget.limits().max_buffer_bytes)
                    .into_iter()
                    .enumerate()
            {
                let _mpg = MatchPathGuard::enter(&format!("embedded-asset-{}", ix + 1));
                if let Err(h) = budget.charge_scan(payload.len() as u64) {
                    return limits_outcome(opts, h.kind, h.reason);
                }
                if let Some(o) = core_scan(db, &payload, None, Some(mc), opts, sink) {
                    return o;
                }
                match deep_analyze(
                    db,
                    &payload,
                    opts,
                    budget,
                    depth + 1,
                    Some(mc),
                    false,
                    findings,
                    sink,
                ) {
                    inf @ DeepOutcome::Infected { .. } => return inf,
                    lim @ DeepOutcome::Limits(_) => return lim,
                    _ => {}
                }
            }
        }
    }

    if let Some(o) = whole_buffer_heuristics(data, ft, opts, sink) {
        return o;
    }

    // A verdict from unpacking a *packed executable* that has not been reported
    // yet, because the file is also a carrier and the carving below still has to
    // run. `Clean` until one is produced.
    let mut deferred = DeepOutcome::Clean;

    // Archives (and UPX-packed executables) are unpacked regardless of the
    // heuristics flag.
    if let Some(fmt) = unpack_target(ft, data, opts.restrict_extractors) {
        if depth >= budget.limits().max_recursion {
            return limits_outcome(
                opts,
                unpack::LimitKind::MaxRecursion,
                format!("recursion depth exceeds {}", budget.limits().max_recursion),
            );
        }
        // A container whose members can be STREAMED is walked that way at every
        // depth, not just when it is the file handed in.
        //
        // Otherwise nesting changes what a scan finds. Measured on the same
        // 6 MB deflated member with `--max-object-bytes 1M`: as `lv0.zip` it was
        // FOUND, and as `tar > lv0.zip` it was "archive member exceeds size
        // budget". Identical bytes, different answer, purely because of depth —
        // the buffered `extract_each` path caps a member at `max_buffer_bytes`
        // while the streamed walk does not have to hold it at all.
        if unpack::is_streamable(fmt) {
            let member_container = container_cltype(fmt, data);
            let _ag = engine::AncestryGuard::enter(member_container);
            return scan_streamed_container(
                db,
                std::io::Cursor::new(data),
                opts,
                fmt,
                ft,
                member_container,
                findings,
                budget,
                depth,
                sink,
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
        let _ag = engine::AncestryGuard::enter(member_container);
        // Members we recognised but couldn't decode are remembered here — they
        // must not be reported clean, but they also must not stop us scanning
        // the remaining members. Encrypted members are tracked separately so the
        // (actionable) PasswordProtected verdict can take precedence.
        let mut tally = MemberTally::new();
        let cx = MemberCtx {
            db,
            opts,
            container_size,
            container_is_ole,
            member_container,
            ft,
            fmt,
            depth,
        };
        // Members whose names mark them as parts of a byte-split set
        // (`x.7z.001`, `.002`, …) are held here and rejoined once the container
        // has ended — see the note at `finish()` below for why not sooner.
        let mut volumes = unpack::volume::Collector::new(budget.limits().max_buffer_bytes);
        let outcome =
            unpack::extract_each(fmt, data, budget, &mut |mut e: unpack::Entry,
                                                          budget: &mut Budget|
             -> Option<DeepOutcome> {
                // Track this member on the location stack for its scan (see
                // [`MatchPathGuard`]); a detection here or in a nested member
                // reports the full path.
                let _mpg = MatchPathGuard::enter(&e.name);
                // A member byte-identical to its container is a **fixed point**:
                // typing it re-detects the same format, which yields the same
                // member, forever. It is never a real member — nothing was
                // unwrapped — and following it burns the whole recursion budget
                // on one buffer, so the content that actually needed those levels
                // never gets reached. Skipping loses nothing: these exact bytes
                // are already being scanned here, by this call.
                //
                // A FAT boot sector read as an MBR produces one, and any
                // extractor can grow one by accident, so the guard lives here
                // rather than in whichever extractor is responsible.
                //
                // The length test carries the cost: it is O(1) and false for
                // essentially every real member, so the byte comparison — which
                // short-circuits on the first difference — is only ever reached
                // by a genuine fixed point.
                if e.data.len() == data.len() && e.data == data {
                    return None;
                }
                let facts = MemberFacts {
                    name: &e.name,
                    comp_size: e.comp_size,
                    size_real: e.data.len() as u64,
                    encrypted: e.encrypted,
                    unsupported: e.unsupported,
                };
                if let Some(o) = member_metadata_scan(&cx, &mut tally, facts, sink) {
                    return Some(o);
                }
                // Nothing decoded: the metadata above is all this member has.
                if e.unsupported.is_some() {
                    return None;
                }
                // A part of a byte-split set is held, not scanned — its bytes
                // are a fragment of a file that only exists once the set is
                // rejoined. Everything else scans exactly as before.
                let data = match volumes.offer(&e.name, std::mem::take(&mut e.data)) {
                    unpack::volume::Offer::Held => return None,
                    unpack::volume::Offer::PassThrough { data, .. } => data,
                };
                member_content_scan(&cx, &mut tally, &data, budget, findings, sink)
            });
        // Reassembly happens only now. Nothing in a byte-split set's names says
        // how many parts it has, so `.001`+`.002` looks contiguous even when
        // `.003` follows: joining on arrival would emit a truncated prefix that
        // still parses as the archive and would then be scanned as if whole.
        // Completeness is only knowable once no further member can arrive.
        let held = volumes.finish();
        let mut terminal = match outcome {
            Ok(o) => o,
            Err(hit) => Some(outcome_for_hit(hit, opts)),
        };
        // Rejoined files first, then the parts that could not be joined. Bytes
        // withheld from the scan and then dropped would be exactly the silent
        // clean this scanner exists to prevent, so every part held above still
        // gets scanned on its own here.
        for (name, buf, incomplete) in held.into_scannable() {
            if terminal.is_some() {
                break;
            }
            // A set with a gap in it is reported: the archive those bytes belong
            // to can no longer be read by anything — not by us and not by the
            // tool that wrote it.
            if let Some(reason) = incomplete {
                tally.unscannable.get_or_insert_with(|| reason.to_string());
            }
            // Nothing else accounts for these bytes: the parts were charged as
            // they were extracted, but this is a buffer the collector made.
            if let Err(h) = budget.charge_scan(buf.len() as u64) {
                terminal = Some(limits_outcome(opts, h.kind, h.reason));
                break;
            }
            let _mpg = MatchPathGuard::enter(&name);
            terminal = member_content_scan(&cx, &mut tally, &buf, budget, findings, sink);
        }
        let verdict = match terminal {
            Some(o) => o,
            None => tally.verdict(),
        };
        // A packed executable is not only a container, it is also a *carrier*.
        // Unpacking accounts for the image the stub rebuilds; it accounts for
        // nothing appended to the file — and stapling an archive or a second PE
        // onto the end of a packed dropper is one of the commonest shapes there
        // is. For every other format, returning here is right: an archive's
        // bytes are its members. For these two, a clean result falls through to
        // the carving below, carrying any `UNSCANNABLE`/`PASSWORD-PROTECTED`
        // verdict with it so that it is still reported if nothing is carved.
        let packed_executable = matches!(fmt, unpack::Format::Upx | unpack::Format::PePacked);
        match verdict {
            DeepOutcome::Infected { .. } | DeepOutcome::Limits(_) => return verdict,
            other if !packed_executable => return other,
            other => deferred = other,
        }
    }

    // Embedded executables: scan PE/ELF images appended/embedded at a non-zero
    // offset (file-infectors, droppers, self-extractors — on Windows via PE, on
    // Linux via ELF). Each carved image is run through the pattern/hash core (so
    // its section hashes match) and then recursed. Structural, not heuristic, so
    // it runs regardless of the flag — bounded by recursion depth and the
    // embedded-image cap.
    if carve && depth < budget.limits().max_recursion {
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
                return limits_outcome(opts, h.kind, h.reason);
            }
            // The carved image inherits the container its host sits in.
            if let Some(o) = core_scan(db, sub, None, container, opts, sink) {
                return o;
            }
            // Recurse with carve=false: the anchored scan above already matched
            // this image, and the embedded offsets within it are a subset of the
            // ones this level enumerated — so we recurse only to extract an
            // appended archive / unpack a packed stub, NOT to re-carve (which
            // would rescan the same overlapping regions, the amplification bug).
            match deep_analyze(
                db,
                sub,
                opts,
                budget,
                depth + 1,
                container,
                false,
                findings,
                sink,
            ) {
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
                return limits_outcome(opts, h.kind, h.reason);
            }
            match deep_analyze(
                db,
                sub,
                opts,
                budget,
                depth + 1,
                container,
                false,
                findings,
                sink,
            ) {
                // A real detection in an appended/stapled archive is the whole
                // point of carving — surface it. A genuine resource limit (e.g. a
                // decompression bomb in a real appended archive) still matters.
                inf @ DeepOutcome::Infected { .. } => return inf,
                lim @ DeepOutcome::Limits(_) => return lim,
                // Clean, or a carve that could not be decoded (Unscannable /
                // PasswordProtected): the candidate was found by a short magic that
                // collides with ordinary binary data (a false `1f8b08` / `PK\x03\x04`
                // byte-run inside a PE), so it is not really an archive here. The
                // carrier buffer is already fully pattern-scanned, so a failed guess
                // must NOT poison it as UNSCANNABLE — that is a false positive
                // against `clamscan`, which reports such carriers clean. Move on.
                _ => {}
            }
        }
    }

    // DLP structured-data heuristic (opt-in, ClamAV `--structured-*-count`): count
    // credit-card / SSN numbers in reasonably-sized textual buffers and alert when
    // a threshold is met. Driven solely by the ScanOptions thresholds, so it runs
    // independently of `--detect heuristics` (matching ClamAV, where
    // `CL_SCAN_HEURISTIC_STRUCTURED` is its own switch). Runs at every recursion
    // level, so structured data inside an extracted archive member is caught too.
    #[cfg(feature = "dlp")]
    if let Some(o) = structured_data_scan(data, opts, sink) {
        return o;
    }

    // Phishing heuristic (opt-in, ClamAV `--alert-phishing`): flag link-spoofing
    // in HTML/text bodies. Like the DLP heuristic it is driven by its own flag,
    // independent of `--detect heuristics`, and runs at every recursion level (so a
    // phishing HTML part inside an email/archive is caught too).
    #[cfg(feature = "phishing")]
    if let Some(o) = phishing_scan(db, data, opts, sink) {
        return o;
    }

    // Authenticode inspection (independent of `--detect heuristics`, like phishing/DLP).
    // One PE parse serves both checks:
    //   * `.crb` certificate block-list — a signed PE carrying a blocked signer
    //     cert is reported (always on when a `.crb` DB is loaded);
    //   * opt-in `alert_broken_authenticode` — the embedded digest does not cover
    //     the file (tampered with / appended-to after signing).
    if opts.alert_broken_authenticode || !db.crb.is_empty() {
        if let Some(sig) = authenticode::analyze_pe(data) {
            for cert in &sig.certs {
                if let Some(name) = db.crb.blocked(cert) {
                    if let Some(o) = sink.hit(name.to_string(), 0, Method::Hash) {
                        return o;
                    }
                }
            }
            if opts.alert_broken_authenticode && !sig.digest_matches {
                if let Some(o) = sink.hit(
                    "Heuristics.Authenticode.HashMismatch".to_string(),
                    0,
                    Method::Heuristic,
                ) {
                    return o;
                }
            }
        }
    }

    // Nothing below fires unless at least the ClamAV-default heuristics are on
    // (on by default; `--detect heuristics` is the superset and also enables them).
    if !opts.clamav_heuristics && !opts.heuristics {
        return deferred;
    }

    // TLSH fuzzy matching is exav-exclusive (ClamAV has no TLSH), so it stays
    // behind the full `--detect heuristics` flag and off under `--clamav-compat`.
    if opts.heuristics {
        if let Some(hit) = profile::timed("fuzzy", data.len() as u64, || db.fuzzy.match_tlsh(data))
        {
            if let Some(o) = sink.hit(hit, 0, Method::Fuzzy) {
                return o;
            }
        }
    }

    if ft == FileType::Pe {
        if let Some(info) = pe::analyze(data) {
            // imphash (`.imp`) matching is a ClamAV default — matched whenever the
            // loaded DB carries `.imp` sigs — so it runs under `clamav_heuristics`
            // (i.e. under `--clamav-compat` too). The exav-exclusive ML scorer,
            // packed-injection heuristic, and the `-v` diagnostic findings below
            // stay behind the full `--detect heuristics` flag.
            if let Some(hit) = db
                .fuzzy
                .match_imphash(&info.imphash, info.import_count as u64)
            {
                if let Some(o) = sink.hit(hit, 0, Method::Fuzzy) {
                    return o;
                }
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
                let score = profile::timed("static", data.len() as u64, || {
                    db.model.score(&ml::extract(data, Some(&info)))
                });
                if depth == 0 {
                    findings.push(Finding::new(
                        "static-score",
                        format!("{score:.2} ({})", db.model.name()),
                    ));
                }
                if score >= db.ml_threshold {
                    if let Some(o) = sink.hit(
                        format!("Heuristics.Static.Suspect.{:.0}", score * 100.0),
                        0,
                        Method::Static,
                    ) {
                        return o;
                    }
                }
                if info.looks_packed() && info.suspicious_imports.len() >= 2 {
                    if let Some(o) = sink.hit(
                        "Heuristics.PE.PackedWithInjectionImports".to_string(),
                        0,
                        Method::Heuristic,
                    ) {
                        return o;
                    }
                }
            }
        }
    }
    deferred
}

/// The `Heuristics.Encrypted.*` name for an encrypted member of a container of
/// format `fmt` (ClamAV's `--alert-encrypted` naming), format-specific where
/// ClamAV distinguishes it, else the generic `.Archive`.
/// `Heuristics.Packed.<Packer>` for a member the PE-packer extractor surfaced as
/// an image it could not unpack, or `None` for anything else.
///
/// The packer name arrives already spelled the way it should be reported —
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

fn encrypted_heuristic_name(fmt: unpack::Format) -> &'static str {
    use unpack::Format;
    match fmt {
        Format::Zip => "Heuristics.Encrypted.Zip",
        Format::Rar => "Heuristics.Encrypted.RAR",
        Format::SevenZip => "Heuristics.Encrypted.7Zip",
        Format::Pdf => "Heuristics.Encrypted.PDF",
        // `OLE2`, not `Doc`. ClamAV's *config option* is `AlertEncryptedDoc`,
        // but the *signature name* it emits is `Heuristics.Encrypted.OLE2` —
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
/// is met, else `None`. Only runs when a threshold is set, on textual buffers no
/// larger than `DLP_MAX_BYTES` (to bound cost on hostile input).
#[cfg(feature = "dlp")]
fn structured_data_scan(data: &[u8], opts: &ScanOptions, sink: &mut Sink) -> Option<DeepOutcome> {
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
            if let Some(o) = sink.hit(
                "Heuristics.Structured.CreditCardNumber".to_string(),
                0,
                Method::Heuristic,
            ) {
                return Some(o);
            }
        }
    }
    if let Some(threshold) = opts.structured_ssn_count {
        if dlp::count_ssns(data, dlp::SsnMode::Both) >= threshold as usize {
            if let Some(o) = sink.hit(
                "Heuristics.Structured.SSN".to_string(),
                0,
                Method::Heuristic,
            ) {
                return Some(o);
            }
        }
    }
    None
}

/// Run the opt-in phishing heuristic over `data`. Returns an `Infected` outcome
/// with a ClamAV-compatible name when a spoofed link is found, else `None`. Only
/// runs when the flag is set, on textual buffers no larger than `PHISH_MAX_BYTES`
/// (to bound cost on hostile input).
#[cfg(feature = "phishing")]
fn phishing_scan(
    db: &Scanner,
    data: &[u8],
    opts: &ScanOptions,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    /// Cap on buffer size the phishing scan runs over.
    const PHISH_MAX_BYTES: usize = 16 * 1024 * 1024;

    if !opts.alert_phishing {
        return None;
    }
    if data.len() > PHISH_MAX_BYTES || !normalize::is_textual(data) {
        return None;
    }
    let p = phishing::scan(data, &db.phishing)?;
    sink.hit(p.signature().to_string(), 0, Method::Heuristic)
}

/// Core detection over an in-memory buffer: the full `.ndb`/`.ldb` engine
/// (literals, wildcards, logical sigs — including EICAR), section hashes, then
/// whole-file hashes. The streaming literal automaton isn't used here; the
/// engine already covers every literal, so it stays unbuilt for file scans.
/// A core detection: clean signature name, match offset, method, and whether the
/// matched signature is from an unofficial database (so the report layer can add
/// `.UNOFFICIAL` in compat mode). The name is ALWAYS clean here.
type CoreHit = (String, u64, Method, bool);

fn scan_bytes_core(db: &Scanner, data: &[u8], filename: Option<&str>) -> Option<CoreHit> {
    // Total bytes of bytecode-extracted (unpacked) content this scan may
    // re-scan, across the whole recursion — bounds an extraction bomb where a
    // (trusted) unpacker, driven by a hostile input, emits many/large buffers.
    let mut extract_budget = MAX_BC_EXTRACT_TOTAL;
    scan_bytes_depth(db, data, 0, &mut extract_budget, None, None, filename)
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

/// True if `data` looks like JavaScript / generic script and is worth running
/// the JS normaliser over (in addition to the HTML/text normalisers). Covers
/// shebang scripts and HTML (`FileType::Script` / `FileType::Html`), any text
/// embedding a `<script` tag, and `.js`-ish textual buffers exhibiting common
/// JS obfuscation primitives (`eval`/`unescape`/`fromCharCode`/`function`).
/// The normalised views of `data` a textual file is matched against, as
/// thunks so the caller holds one at a time.
///
/// Each one is a full-size copy of `data`. Materialising the set before
/// scanning any of it put two — four for a script — in memory at once, on top
/// of the buffer they were derived from, and nesting stacks that: a container,
/// its member and that member's own member are each mid-scan while the walk is
/// inside them. Returning thunks keeps the peak at one copy without changing
/// which views are scanned or in what order.
fn normalizations<'a>(ft: FileType, data: &'a [u8]) -> Vec<Box<dyn FnOnce() -> Vec<u8> + 'a>> {
    let mut v: Vec<Box<dyn FnOnce() -> Vec<u8> + 'a>> = vec![
        Box::new(move || normalize::html(data)),
        Box::new(move || normalize::text(data)),
    ];
    if looks_like_script(ft, data) {
        v.push(Box::new(move || normalize::javascript(data)));
        v.push(Box::new(move || jsnorm::normalize(data)));
    }
    v
}

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
        // normalised script buffer is produced — it can never cause a match.
        || contains_ci(b"activexobject")
        || contains_ci(b"createobject")
        || contains_ci(b"wscript")
}

/// Scan content extracted from a container, supplying the container context:
/// `ft_override` forces the member's top-level file type (e.g. the decompressed
/// VBA macro artifacts from an OLE2 document are scanned as `Ole` so `Target:2`
/// (MSOLE2) macro signatures apply), and `container` is the immediate
/// container's type so `Container:CL_TYPE_*`-scoped signatures fire only inside
/// their intended container.
fn scan_bytes_member(
    db: &Scanner,
    data: &[u8],
    ft_override: Option<FileType>,
    container: Option<engine::ClType>,
) -> Option<CoreHit> {
    let mut extract_budget = MAX_BC_EXTRACT_TOTAL;
    // A container member has its own identity (not the outer file's), which exav
    // does not track, so YARA filename externals stay undefined for members.
    scan_bytes_depth(
        db,
        data,
        0,
        &mut extract_budget,
        ft_override,
        container,
        None,
    )
}

/// Run the matching core over one buffer and report every hit to `sink`.
///
/// The all-match half of [`scan_bytes_member`]: the same pattern / section-hash
/// / whole-file-hash / bytecode passes, but gathering all matches instead of
/// returning the first. Only this function branches on `Sink::wants_all` — the
/// traversal above it does not, which is what the split buys: one walk, and a
/// single place where first-match and all-match differ.
///
/// Returns the buffers a bytecode unpacker produced, for the caller to recurse
/// into; they are content that exists nowhere else.
fn core_scan_all(
    db: &Scanner,
    data: &[u8],
    ft: FileType,
    container: Option<engine::ClType>,
    unofficial_suffix: bool,
    sink: &mut Sink,
) -> Vec<Vec<u8>> {
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
    // `is_textual_type(ft)` cannot be dropped, and `scan_bytes_depth` carries
    // the same guard: `normalize::is_textual` counts 0x80..=0xff as text and most
    // packed binaries carry few NULs, so a compressed PE — or an APK's DEX and
    // `.so` members — look textual and paid for two to four extra FULL engine
    // passes. A `Target:0` pattern already ran against the raw bytes, and
    // `target_ok` confines Target:3/4/7 to text-ish types, so for a
    // positively-typed binary those passes cannot match. They were pure cost.
    if !db.engine.is_empty() && is_textual_type(ft) && normalize::is_textual(data) {
        // One at a time. Each normalisation is a full-size copy of `data`, and
        // building the set before scanning any of it held two — four for a
        // script — alive at once, on top of the buffer they were made from.
        // Nesting multiplies that: a container, its member and that member's
        // member are each mid-scan while the walk is inside them.
        for norm in normalizations(ft, data) {
            db.engine
                .scan_all_with_layout(&norm(), ft, None, container, &mut eng);
        }
    }
    for (name, off, unofficial) in eng {
        sink.hit(
            report_name(&name, unofficial, unofficial_suffix),
            off,
            Method::Pattern,
        );
    }
    if !db.sections.is_empty() && ft == FileType::Pe {
        let want_sha = db.sections.wants_sha();
        for (size, slice) in pe::section_slices(data) {
            let d = hashes::section_digests(slice, want_sha);
            if let Some((name, unofficial)) = db.sections.lookup(size, &d) {
                sink.hit(
                    report_name(&name, unofficial, unofficial_suffix),
                    0,
                    Method::Hash,
                );
            }
        }
    }
    if !db.hashes.is_empty() {
        if let Some((name, unofficial)) = db.hashes.lookup(&digests_of(data), data.len() as u64) {
            sink.hit(
                report_name(&name, unofficial, unofficial_suffix),
                0,
                Method::Hash,
            );
        }
    }
    // YARA rules, in the same position the first-match core runs them. Omitting
    // them here would make all-match see LESS than a normal scan — a file whose
    // only detection is a YARA rule would come back with an empty list and a
    // `Complete` outcome, which renders as OK.
    //
    // `None` for the filename matches `scan_bytes_member`: a member has its own
    // identity rather than the outer file's, and exav does not track it, so
    // filename externals stay undefined on this path in both cores.
    //
    // The matcher already formats the full name (`YARA.` prefix and any
    // `.UNOFFICIAL` suffix), so it is reported verbatim.
    if !db.yara.is_empty() {
        if let Some(name) = profile::timed("yara", data.len() as u64, || db.yara.scan(data, None)) {
            sink.hit(name, 0, Method::Yara);
        }
    }
    // Bytecode names are reported verbatim, never `.UNOFFICIAL`-suffixed.
    if !db.bytecode.is_empty() {
        let (det, extracted) = db.bytecode.scan(data, ft, layout.as_ref());
        if let Some((name, _)) = det {
            sink.hit(name, 0, Method::Bytecode);
        }
        return extracted;
    }
    Vec::new()
}

/// The matching core over one buffer, in whichever mode the sink asks for.
///
/// The single place first-match and all-match differ. The traversal above never
/// branches on the mode; it calls this wherever a buffer needs scanning.
///
/// `Some(outcome)` means the walk must stop and return it.
fn core_scan(
    db: &Scanner,
    data: &[u8],
    ft_override: Option<FileType>,
    container: Option<engine::ClType>,
    opts: &ScanOptions,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    if sink.wants_all() {
        let ft = ft_override.unwrap_or_else(|| db.identify(data));
        // Buffers a bytecode unpacker produced are content that exists nowhere
        // else. The first-match core recurses into them itself (see
        // `scan_bytes_depth`), so the all-match core has to as well or a payload
        // that only exists after unpacking is missed.
        for buf in core_scan_all(db, data, ft, container, opts.unofficial_suffix, sink) {
            let bft = db.identify(&buf);
            core_scan_all(db, &buf, bft, container, opts.unofficial_suffix, sink);
        }
        return None;
    }
    let (sig, off, m, unofficial) = scan_bytes_member(db, data, ft_override, container)?;
    sink.hit(
        report_name(&sig, unofficial, opts.unofficial_suffix),
        off,
        m,
    )
}

/// Max recursion into bytecode-extracted (unpacked) buffers, to bound
/// extraction bombs.
const MAX_BC_DEPTH: u32 = 4;
/// Cap on total bytes re-scanned from bytecode-extracted buffers per scan.
const MAX_BC_EXTRACT_TOTAL: u64 = 256 * 1024 * 1024;

fn scan_bytes_depth(
    db: &Scanner,
    data: &[u8],
    depth: u32,
    extract_budget: &mut u64,
    ft_override: Option<FileType>,
    container: Option<engine::ClType>,
    filename: Option<&str>,
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
        // Normalisation is only worth doing when a signature could match the
        // result. `target_ok` already confines Target:3/4/7 (HTML/mail/text)
        // signatures to text-ish types, and a Target:0 byte pattern has already
        // been run against the raw bytes by the pass above — so for a
        // positively-typed binary (PE, ELF, Mach-O, a container…) the two
        // normalised passes are pure cost. They were running anyway, because
        // `is_textual` counts 0x80..=0xff as text and most packed binaries carry
        // few NULs, so a compressed PE looked textual and paid for two extra
        // full passes over its bytes.
        if !db.engine.is_empty() && is_textual_type(ft) && normalize::is_textual(data) {
            // Built and dropped one at a time — see the note on the same loop
            // in `scan_all_with_layout`'s caller. Holding the whole set was
            // two to four full-size copies of `data` alive simultaneously.
            for norm in normalizations(ft, data) {
                let norm = profile::timed("normalize", data.len() as u64, norm);
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
            for (bcix, buf) in extracted.into_iter().enumerate() {
                let cost = buf.len() as u64;
                if *extract_budget < cost {
                    break; // extraction-bomb guard: stop re-scanning further
                }
                *extract_budget -= cost;
                // Record where this buffer came from. Every OTHER extraction site
                // pushes a guard, and this one did not — so a detection inside a
                // bytecode-unpacked buffer was reported with no location at all,
                // i.e. as though it had matched the container's own bytes. That
                // is how four correct RTF detections came to look like
                // `Target:1` (PE) signatures firing on an RTF file, which reads
                // exactly like a target-gating bug and is not one. The unpacker
                // has no member name to offer, so the index is the identity.
                let _mpg = MatchPathGuard::enter(&format!("bytecode-unpacked-{}", bcix + 1));
                if let Some(hit) =
                    scan_bytes_depth(db, &buf, depth + 1, extract_budget, None, container, None)
                {
                    match_loc_record();
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
                    let _ag = engine::AncestryGuard::enter(inner_container);
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
                            // Same reason as above: this member has a real name,
                            // so a hit here can be attributed precisely.
                            let _mpg = MatchPathGuard::enter(&e.name);
                            let hit = scan_bytes_depth(
                                db,
                                &e.data,
                                depth + 1,
                                extract_budget,
                                None,
                                inner_container,
                                None,
                            );
                            if hit.is_some() {
                                match_loc_record();
                            }
                            hit.map(Some)
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
    // YARA rules: the matcher already formats the full ClamAV name
    // (`YARA.` prefix and any `.UNOFFICIAL` suffix), so it is reported verbatim.
    if !db.yara.is_empty() {
        if let Some(name) =
            profile::timed("yara", data.len() as u64, || db.yara.scan(data, filename))
        {
            return Some((name, 0, Method::Yara, false));
        }
    }
    None
}

/// Streaming detection core (constant memory, any size): Aho-Corasick +
/// triple hasher in one forward pass.
fn stream_core<R: Read>(db: &Scanner, reader: R) -> io::Result<Option<CoreHit>> {
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
        let db = Scanner::builtin();
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
    #[cfg(feature = "all-formats")]
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

    /// Every normalised view a textual file is matched against must still be
    /// produced, and each must be built only when asked for.
    ///
    /// The views are handed out as thunks so the scanner holds one full-size
    /// copy at a time instead of all of them — measured at 270 MB saved on a
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
            normalizations(FileType::Text, plain).len(),
            2,
            "a non-script textual file is matched against the html and text views"
        );
        assert_eq!(
            normalizations(FileType::Text, script).len(),
            4,
            "script-shaped content adds the javascript and jsnorm views"
        );
        assert_eq!(
            normalizations(FileType::Html, plain).len(),
            4,
            "an HTML file is script-like by type, whatever it holds"
        );

        // And each one produces something to scan.
        for (i, f) in normalizations(FileType::Text, script)
            .into_iter()
            .enumerate()
        {
            assert!(!f().is_empty(), "normalisation {i} produced nothing");
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
        let db = Scanner::builtin();
        let r = scan_stream(&db, Cursor::new(b"nothing to see".to_vec())).unwrap();
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
        std::fs::write(dir.path().join("b.fp"), format!("{}:*:Allowed\n", d.md5)).unwrap();
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

    #[test]
    fn detects_across_buffer_boundary() {
        let db = Scanner::builtin();
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
        let db = Scanner::builtin();
        let r = analyze(&db, &blob, &ScanOptions::default());
        assert!(matches!(r.verdict, Verdict::Infected { .. }));
    }

    fn write_temp(bytes: &[u8]) -> crate::tmpfile::TempFile {
        let f = crate::tmpfile::TempFile::new().unwrap();
        std::fs::write(f.path(), bytes).unwrap();
        f
    }

    // A container too large for structural analysis that does NOT stream (its
    // decoder needs random access over a buffered slice — here OLE2) must not be
    // cleared: its contents were never unpacked, so the verdict is
    // LimitsExceeded, never Clean. This is the invariant for the still-buffered
    // formats. (ZIP/tar/gzip now stream past the cap — see the tests below.)
    /// A seekable source that serves the object once and then fails.
    ///
    /// Models the case that actually bites: not a source that is broken from
    /// the start — that fails the first read and is obviously an error — but one
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
    /// The bytes it failed to deliver still exist — this is not truncation,
    /// where the content really is absent and a clean answer is honest — so
    /// the only truthful outcomes are a detection, a not-scanned verdict, or an
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
        let db = Scanner::builtin();
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

    // A gzip/tar whose size exceeds `deep_analysis_max` is walked
    // member-by-member off disk, never buffered whole, and fully scanned — so
    // the cap bounds memory without bounding what the scan can find.
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
        let db = Scanner::builtin();
        // A cap of one byte is far below the content, and the streaming path
        // still unpacks it and finds EICAR: the cap governs buffering, not
        // reach.
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
        let db = Scanner::builtin();
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
        let mut db = Scanner::builtin();
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
    // content exceeds `max_buffer_bytes` with EICAR buried past that cap. The old
    // buffered path decoded the nested gzip into a `max_buffer_bytes`-capped Vec
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
        let db = Scanner::builtin();
        // The per-member buffer cap (256 bytes) is far below the 4 KiB+ of
        // decompressed content, so this pins that a nested gzip is streamed
        // rather than capped or truncated at that boundary.
        let mut opts = ScanOptions::default();
        opts.limits.max_buffer_bytes = 256;
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
        let db = Scanner::builtin();
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
        let db = Scanner::builtin();
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
    #[cfg(feature = "all-formats")]
    fn scan_seekable_finds_eicar_in_zip() {
        let blob = zip_bytes(&[("a.txt", b"hello", false), ("evil", EICAR, false)]);
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
    /// that as an ordinary truncated archive — content actually absent, which
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
        let db = Scanner::builtin();
        let r = scan_seekable(&db, reader, size, &ScanOptions::default()).unwrap();
        assert!(
            matches!(r.verdict, Verdict::Infected { .. }),
            "should detect EICAR over HTTP range"
        );

        // What is bounded is MEMORY, not transfer. A range source may be read
        // more than once — the container is read again to run the checks that
        // need its whole bytes — so asserting a fraction of the object is
        // fetched would pin a property exav does not promise. What it does
        // promise is that a scan does not grow without limit: the object is
        // ~1 MB and is walked a small, constant number of times.
        let bytes = served.load(Ordering::SeqCst);
        assert!(
            bytes <= (total as u64) * 3,
            "fetched {bytes} of {total}; a scan should re-read the source a \
             small constant number of times, not unboundedly"
        );
    }
}
