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

pub mod bytecode;
pub mod cache;
pub mod container;
pub mod cvd;
pub mod db;
pub mod engine;
pub mod filetype;
pub mod fuzzy;
pub mod fuzzy_img;
pub mod hashes;
pub mod icon;
pub mod profile;
pub mod hexsig;
pub mod ml;
pub mod normalize;
pub mod patterns;
pub mod pe;
pub mod source;
/// Archive/container extraction lives in its own crate; re-exported so
/// `exav_core::unpack` and the `ScanOptions::limits` type stay stable.
pub use exav_unpack as unpack;
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
        _ => return None,
    })
}

/// Like [`unpack_format`] but content-aware: also recognises a UPX-packed
/// executable (which is classified as a PE/ELF/Mach-O, not a container) so its
/// embedded original is decompressed and scanned.
fn unpack_target(ft: FileType, data: &[u8], compat: bool) -> Option<unpack::Format> {
    if let Some(fmt) = unpack_format(ft) {
        // In ClamAV-compat mode, skip extractors stock ClamAV lacks so a
        // differential run doesn't count exav's extra reach as a disagreement.
        if compat
            && matches!(
                fmt,
                unpack::Format::Ar | unpack::Format::Cpio | unpack::Format::Xar
            )
        {
            return None;
        }
        return Some(fmt);
    }
    if !compat && ft.is_executable() && unpack::is_upx(data) {
        return Some(unpack::Format::Upx);
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
fn ooxml_subtype(data: &[u8]) -> Option<engine::ClType> {
    use engine::ClType;
    // Cheap necessary condition: every OOXML package carries this part.
    if !contains_window(data, b"[Content_Types].xml") {
        return None;
    }
    if contains_window(data, b"word/document.xml") || contains_window(data, b"word/document2.xml")
    {
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
pub(crate) fn report_name(name: &str, unofficial: bool, compat: bool) -> String {
    if compat && unofficial && !name.ends_with(".UNOFFICIAL") {
        format!("{name}.UNOFFICIAL")
    } else {
        name.to_string()
    }
}

/// How a detection was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// An informational finding (type, entropy, imphash, skipped sub-objects).
#[derive(Debug, Clone)]
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

/// Full result of a scan.
#[derive(Debug, Clone)]
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
    /// applying the `.UNOFFICIAL` suffix at report time when `compat` is set.
    fn infected_hit(hit: CoreHit, compat: bool, findings: Vec<Finding>) -> Self {
        let (sig, offset, method, unofficial) = hit;
        Self::infected(report_name(&sig, unofficial, compat), offset, method, findings)
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
    /// Enable structural heuristics / fuzzy / ML analysis (archive
    /// extraction is always performed regardless of this flag).
    pub heuristics: bool,
    /// Limits for recursive unpacking / bomb defenses.
    pub limits: unpack::Limits,
    /// ClamAV-compatibility mode: restrict to a stock ClamAV build's
    /// capabilities (skip exav-exclusive extractors like `ar`/`cpio`/`xar`/UPX)
    /// so differential testing against `clamscan` is apples-to-apples. Default
    /// off — exav runs at full capability.
    pub compat: bool,
    /// Password(s) to try when decrypting encrypted archive members. Empty by
    /// default. When a scan returns [`Verdict::PasswordProtected`], a caller can
    /// set this and re-scan. (The decryptors that consume it are a follow-up;
    /// the field is the stable API the verdict points callers to.)
    pub passwords: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_scan_size: None,
            deep_analysis_max: 256 * 1024 * 1024,
            heuristics: false,
            limits: unpack::Limits::default(),
            compat: false,
            passwords: Vec::new(),
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
            heuristics: false,
            limits: unpack::Limits {
                max_recursion: 17,
                max_files: 10_000,
                max_total_bytes: 400 * 1024 * 1024,
                ..unpack::Limits::default()
            },
            compat: true,
            passwords: Vec::new(),
        }
    }
}

/// The loaded signature database and detection models.
pub struct Database {
    /// Literal patterns (EICAR + literal `.ndb`), also used on the streaming
    /// path where wildcard verification isn't possible.
    pub patterns: PatternSet,
    /// Full `.ndb`/`.ldb` matcher (wildcards, logical sigs); in-memory only.
    pub engine: engine::SigEngine,
    pub hashes: HashDb,
    /// `.mdb`/`.mdu`/`.msb` PE section-hash signatures.
    pub sections: SectionHashDb,
    pub fuzzy: FuzzyDb,
    /// `.cdb` container-metadata signatures.
    pub cdb: container::CdbDb,
    /// `.yar`/`.yara` YARA rules (via `yara-x`).
    pub yara: yara::YaraDb,
    /// `.fp`/`.sfp` whole-file hash allowlist: a match here clears a detection.
    pub allow: HashDb,
    /// `.ign`/`.ign2` signature names to suppress.
    pub ignored: std::collections::HashSet<String>,
    /// Loaded `.cbc` bytecode programs, with their triggers/hooks, executed in
    /// a memory-safe sandbox when their gate fires (see [`bytecode::runtime`]).
    pub bytecode: bytecode::runtime::BytecodeRuntime,
    pub model: Box<dyn Model>,
    pub ml_threshold: f32,
    /// `.ftm` file-type magic rules; consulted only when content-based
    /// [`filetype::identify`] is inconclusive (see [`Database::identify`]).
    pub ftm: filetype::FtmMagics,
    /// `.idb` PE-icon perceptual-hash database, used to satisfy `IconGroup1/2`
    /// constraints on logical signatures (see [`icon`]).
    pub icons: icon::IconDb,
    /// Passwords loaded from `.pwdb` files (ClamAV password database). Tried
    /// (unioned with [`ScanOptions::passwords`]) when decrypting encrypted
    /// archive members. The official CVDs ship none — this is user-supplied.
    pub passwords: Vec<String>,
}

impl Database {
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
            passwords: Vec::new(),
        }
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
                return Ok(ScanReport::infected_hit(hit, opts.compat, Vec::new()));
            }
            return Ok(ScanReport::limits(
                format!("file size {size} exceeds max-scan-size {max}; scanned first {max} bytes only"),
                Vec::new(),
            ));
        }
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
    let ft = peek_type(&file)?;
    if let Some(hit) = stream_core(db, &file)? {
        return Ok(ScanReport::infected_hit(hit, opts.compat, Vec::new()));
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
                return Ok(ScanReport::infected_hit(hit, opts.compat, Vec::new()));
            }
            return Ok(ScanReport::limits(
                format!("file size {size} exceeds max-scan-size {max}; scanned first {max} bytes only"),
                Vec::new(),
            ));
        }
    }
    let mut prefix = [0u8; 4096];
    let n = fill_prefix(&mut reader, &mut prefix)?;
    reader.seek(SeekFrom::Start(0))?;
    let ft = filetype::identify(&prefix[..n]);

    if ft == FileType::Zip {
        return Ok(scan_zip_seekable(db, reader, opts));
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
            ScanReport::infected_hit(hit, opts.compat, Vec::new()),
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
    Budget::with_passwords(opts.limits.clone(), pool)
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

fn scan_zip_seekable<R: Read + Seek>(db: &Database, reader: R, opts: &ScanOptions) -> ScanReport {
    let mut findings = vec![Finding::new("type", "ZIP")];
    let mut budget = scan_budget(db, opts);
    // Lazy, seekable member reader: with a range-backed reader only the member
    // currently being read is fetched, and we stop on the first detection.
    let mut members = match unpack::ZipMembers::open(reader) {
        Ok(m) => m,
        Err(h) => return report_for_hit(h, findings),
    };
    // Incomplete-scan signals are accumulated across members and only surfaced
    // after the whole archive is walked: an encrypted or undecodable member that
    // happens to come first must NOT short-circuit and mask a malicious sibling
    // later in the archive. An actual detection still returns eagerly.
    let mut unscannable: Option<String> = None;
    let mut password: Option<String> = None;
    while let Some(res) = members.next_member(&mut budget) {
        let entry = match res {
            Ok(e) => e,
            Err(h) => return report_for_hit(h, findings),
        };
        // A member whose bytes couldn't be decoded (encrypted, or oversized) is
        // recorded as a password/unscannable signal; its content can't be
        // scanned, so keep walking the rest of the archive.
        if let Some(r) = entry.unsupported {
            if entry.encrypted {
                password.get_or_insert_with(|| r.to_string());
            } else {
                unscannable.get_or_insert_with(|| r.to_string());
            }
            continue;
        }
        let buf = entry.data;
        // First (non-suppressed) detection returns eagerly: with a range-backed
        // reader later members are never fetched. A suppressed member
        // (allowlisted/ignored) is skipped, not treated as clean.
        if let Some((sig, off, method, unofficial)) = scan_bytes_core(db, &buf) {
            // Apply the compat `.UNOFFICIAL` suffix before suppression so a
            // compat `.ign`/`.fp` entry (which names the suffixed detection) is
            // matched.
            let sig = report_name(&sig, unofficial, opts.compat);
            if !is_suppressed(db, &buf, &sig) {
                return ScanReport::infected(sig, off, method, findings);
            }
        }
        match deep_analyze(db, &buf, opts, &mut budget, 1, None, true, &mut findings) {
            DeepOutcome::Infected {
                signature,
                offset,
                method,
            } => {
                // Nested-object detection: apply the name ignore-list (the
                // matched object isn't `buf`, so the hash allowlist doesn't
                // directly apply).
                if !db.ignored.contains(&signature) {
                    return ScanReport::infected(signature, offset, method, findings);
                }
            }
            DeepOutcome::Limits(reason) => return ScanReport::limits(reason, findings),
            // Remember, don't stop: an incomplete member must not mask a later
            // sibling. Surfaced after the walk if nothing infected is found.
            DeepOutcome::Unscannable(reason) => {
                unscannable.get_or_insert(reason);
            }
            DeepOutcome::PasswordProtected(reason) => {
                password.get_or_insert(reason);
            }
            DeepOutcome::Clean => {}
        }
    }
    // No detection anywhere: surface the strongest incomplete-scan outcome
    // (PasswordProtected > Unscannable > Clean). The "not-fully-scanned is never
    // Clean" invariant holds in ALL modes — exav never lies `Clean` to mimic clam.
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
        return ScanReport::infected(report_name(&sig, unofficial, opts.compat), off, method, Vec::new());
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
        DeepOutcome::PasswordProtected(reason) => {
            ScanReport::password_protected(reason, findings)
        }
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
    if !db.allow.is_empty() && db.allow.lookup(&digests_of(data), data.len() as u64).is_some() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut budget = scan_budget(db, opts);
    collect_all(db, data, &mut budget, 0, &mut out, &mut seen, opts.compat, None);
    out
}

fn collect_all(
    db: &Database,
    data: &[u8],
    budget: &mut Budget,
    depth: u32,
    out: &mut Vec<(String, Method)>,
    seen: &mut std::collections::HashSet<String>,
    compat: bool,
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
    db.engine
        .scan_all_with_icons(data, ft, layout.as_ref(), container, Some(&icon_ctx), &mut eng);
    if !db.engine.is_empty() && normalize::is_textual(data) {
        for norm in [normalize::html(data), normalize::text(data)] {
            db.engine
                .scan_all_with_layout(&norm, ft, None, container, &mut eng);
        }
    }
    for (name, _, unofficial) in eng {
        push_sig(db, out, seen, name, unofficial, compat, Method::Pattern);
    }
    if !db.sections.is_empty() && ft == FileType::Pe {
        let want_sha = db.sections.wants_sha();
        for (size, slice) in pe::section_slices(data) {
            let d = hashes::section_digests(slice, want_sha);
            if let Some((name, unofficial)) = db.sections.lookup(size, &d) {
                push_sig(db, out, seen, name, unofficial, compat, Method::Hash);
            }
        }
    }
    if !db.hashes.is_empty() {
        if let Some((name, unofficial)) = db.hashes.lookup(&digests_of(data), data.len() as u64) {
            push_sig(db, out, seen, name, unofficial, compat, Method::Hash);
        }
    }
    // Bytecode programs (the normal scan path runs these; all-match must too,
    // or it silently misses every bytecode detection). Surface the detection
    // and recurse into any buffers a bytecode unpacker extracted. Bytecode names
    // are reported verbatim (never `.UNOFFICIAL`-suffixed).
    if !db.bytecode.is_empty() {
        let (det, extracted) = db.bytecode.scan(data, ft, layout.as_ref());
        if let Some((name, _)) = det {
            push_sig(db, out, seen, name, false, compat, Method::Bytecode);
        }
        if depth < budget.limits.max_recursion {
            for buf in extracted {
                collect_all(db, &buf, budget, depth + 1, out, seen, compat, None);
            }
        }
    }
    if let (Some(fmt), true) = (
        unpack_target(ft, data, compat),
        depth < budget.limits.max_recursion,
    ) {
        // All-match: visit every member (never stop early), collecting detections
        // from each and recursing. Streams one member at a time to bound memory.
        let container_size = data.len() as u64;
        let member_container = container_cltype(fmt, data);
        let mut pos = 0u64;
        let _ = unpack::extract_each::<std::convert::Infallible>(
            fmt,
            data,
            budget,
            &mut |e: unpack::Entry, budget: &mut Budget| {
                // `.cdb` `FilePos` is 0-based (first member = 0), matching ClamAV.
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
                        push_sig(db, out, seen, sig, unofficial, compat, Method::Hash);
                    }
                }
                collect_all(db, &e.data, budget, depth + 1, out, seen, compat, member_container);
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
            collect_all(db, sub, budget, depth + 1, out, seen, compat, container);
        }
    }
}

fn push_sig(
    db: &Database,
    out: &mut Vec<(String, Method)>,
    seen: &mut std::collections::HashSet<String>,
    name: String,
    unofficial: bool,
    compat: bool,
    method: Method,
) {
    // Apply the compat `.UNOFFICIAL` suffix before the ignore-list check (the
    // `.ign`/`.ign2` entry names the suffixed detection) and before de-dup.
    let name = report_name(&name, unofficial, compat);
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

/// Recursive structural analysis of an in-memory buffer.
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

    // Archives (and UPX-packed executables) are unpacked regardless of the
    // heuristics flag.
    if let Some(fmt) = unpack_target(ft, data, opts.compat) {
        if depth >= budget.limits.max_recursion {
            return DeepOutcome::Limits(format!(
                "recursion depth exceeds {}",
                budget.limits.max_recursion
            ));
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
        let mut pos = 0u64;
        // A member we recognised but couldn't decode is remembered here — it
        // must not be reported clean, but it also must not stop us scanning the
        // remaining members. Encrypted members are tracked separately so the
        // (actionable) PasswordProtected verdict can take precedence.
        let mut unscannable: Option<String> = None;
        let mut password: Option<String> = None;
        let outcome = unpack::extract_each(
            fmt,
            data,
            budget,
            &mut |e: unpack::Entry, budget: &mut Budget| -> Option<DeepOutcome> {
                // `.cdb` container-metadata signatures match on the member's
                // name/size/encryption/position within this container. `FilePos`
                // is 0-based (first member = 0), matching ClamAV.
                let member_pos = pos;
                pos += 1;
                // The member's metadata (name/size/pos) is still valid even when
                // its content couldn't be decompressed, so `.cdb` matching below
                // still runs; record that its bytes went unscanned.
                if let Some(r) = e.unsupported {
                    if e.encrypted {
                        password.get_or_insert_with(|| r.to_string());
                    } else {
                        unscannable.get_or_insert_with(|| r.to_string());
                    }
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
                        return Some(DeepOutcome::Infected {
                            signature: report_name(&sig, unofficial, opts.compat),
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
                    return Some(DeepOutcome::Infected {
                        signature: report_name(&sig, unofficial, opts.compat),
                        offset: off,
                        method: m,
                    });
                }
                match deep_analyze(db, &e.data, opts, budget, depth + 1, member_container, true, findings) {
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
            },
        );
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
                    signature: report_name(&sig, unofficial, opts.compat),
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
    }

    if !opts.heuristics {
        return DeepOutcome::Clean;
    }

    if let Some(hit) = profile::timed("fuzzy", data.len() as u64, || db.fuzzy.match_tlsh(data)) {
        return DeepOutcome::Infected {
            signature: hit,
            offset: 0,
            method: Method::Fuzzy,
        };
    }

    if ft == FileType::Pe {
        if let Some(info) = pe::analyze(data) {
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
    DeepOutcome::Clean
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
        // are loaded. The metrics gate such sigs (the structural condition must
        // also hold) — see [`icon`] and the engine's `IconCtx`.
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
                [normalize::html(data), normalize::text(data)]
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
        let (det, extracted) =
            profile::timed("bytecode", data.len() as u64, || db.bytecode.scan(data, ft, layout.as_ref()));
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
                            scan_bytes_depth(db, &e.data, depth + 1, extract_budget, None, inner_container)
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
            return Ok(Some((name.to_string(), mat.start() as u64, Method::Pattern, unofficial)));
        }
        return Ok(None);
    }
    let mut tee = TeeHasher::new(reader);
    // `next()` drives the reader until the first match or EOF; on `None`
    // the whole stream has been consumed, so the hashers saw every byte.
    if let Some(mat) = db.patterns.ac().stream_find_iter(&mut tee).next() {
        let mat = mat?;
        let (name, unofficial) = db.patterns.name_prov(mat.pattern().as_usize());
        return Ok(Some((name.to_string(), mat.start() as u64, Method::Pattern, unofficial)));
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
        assert_eq!(container_cltype(unpack::Format::Zip, &plain), Some(ClType::Zip));
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
            zw.start_file("payload_dropper.exe", zip::write::SimpleFileOptions::default())
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

    // An archive too large for structural analysis must not be cleared: its
    // contents were never unpacked, so the verdict is LimitsExceeded. The
    // payload here compresses away (so its bytes don't appear literally in
    // the gzip stream) and contains no signature, isolating the H1 path.
    #[test]
    fn oversize_archive_is_limits_not_clean() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(&vec![b'A'; 4096]).unwrap();
        let blob = e.finish().unwrap();
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

    // Flat content larger than the deep-analysis cap is still fully scanned
    // by the streaming core, so signatures are found.
    #[test]
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
