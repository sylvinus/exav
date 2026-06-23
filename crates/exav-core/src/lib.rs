//! Streaming, size-unbounded file scanner.
//!
//! The pattern and whole-file-hash core ([`scan_stream`]) reads any input in
//! a single forward pass with constant memory, matching across internal
//! buffer boundaries, so file size is unbounded. Structural analysis
//! (archive extraction, PE parsing, ML/fuzzy) needs the whole object in
//! memory and so runs only for objects within [`ScanOptions::deep_analysis_max`].
//!
//! A file that cannot be fully scanned is reported as [`Verdict::LimitsExceeded`],
//! not [`Verdict::Clean`]. Sizes and offsets are 64-bit throughout.

pub mod bytecode;
pub mod cache;
pub mod container;
pub mod cvd;
pub mod db;
pub mod engine;
pub mod filetype;
pub mod fuzzy;
pub mod hashes;
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
        _ => return None,
    })
}

/// Like [`unpack_format`] but content-aware: also recognises a UPX-packed
/// executable (which is classified as a PE/ELF/Mach-O, not a container) so its
/// embedded original is decompressed and scanned.
fn unpack_target(ft: FileType, data: &[u8]) -> Option<unpack::Format> {
    if let Some(fmt) = unpack_format(ft) {
        return Some(fmt);
    }
    if ft.is_executable() && unpack::is_upx(data) {
        return Some(unpack::Format::Upx);
    }
    None
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
    /// A limit prevented a full scan; the input is not known to be clean.
    LimitsExceeded {
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
    fn limits(reason: String, findings: Vec<Finding>) -> Self {
        Self {
            verdict: Verdict::LimitsExceeded { reason },
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
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_scan_size: None,
            deep_analysis_max: 256 * 1024 * 1024,
            heuristics: false,
            limits: unpack::Limits::default(),
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
        }
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
            return Ok(ScanReport::limits(
                format!("file size {size} exceeds max-scan-size {max}"),
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
    if let Some((sig, off, method)) = stream_core(db, &file)? {
        return Ok(ScanReport::infected(sig, off, method, Vec::new()));
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
    if let Some((sig, off, method)) = stream_core(db, reader)? {
        return Ok(suppress_name(
            db,
            ScanReport::infected(sig, off, method, Vec::new()),
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
            return Ok(ScanReport::limits(
                format!("file size {size} exceeds max-scan-size {max}"),
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
    if let Some((sig, off, method)) = stream_core(db, &mut reader)? {
        return Ok(suppress_name(
            db,
            ScanReport::infected(sig, off, method, Vec::new()),
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

fn scan_zip_seekable<R: Read + Seek>(db: &Database, reader: R, opts: &ScanOptions) -> ScanReport {
    let mut findings = vec![Finding::new("type", "ZIP")];
    let mut budget = Budget::new(opts.limits.clone());
    // Lazy, seekable member reader: with a range-backed reader only the member
    // currently being read is fetched, and we stop on the first detection.
    let mut members = match unpack::ZipMembers::open(reader) {
        Ok(m) => m,
        Err(h) => return ScanReport::limits(h.reason, findings),
    };
    while let Some(res) = members.next_member(&mut budget) {
        let buf = match res {
            Ok(e) => e.data,
            Err(h) => return ScanReport::limits(h.reason, findings),
        };
        // Early return on first (non-suppressed) detection: with a range-backed
        // reader this means later members are never fetched. A suppressed
        // member (allowlisted/ignored) is skipped, not treated as clean.
        if let Some((sig, off, method)) = scan_bytes_core(db, &buf) {
            if !is_suppressed(db, &buf, &sig) {
                return ScanReport::infected(sig, off, method, findings);
            }
        }
        match deep_analyze(db, &buf, opts, &mut budget, 1, &mut findings) {
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
            DeepOutcome::Clean => {}
        }
    }
    ScanReport::clean(findings)
}

/// Full in-memory analysis of a bounded buffer: core detection, then
/// recursive unpacking and (optionally) structural/ML/fuzzy heuristics.
pub fn analyze(db: &Database, data: &[u8], opts: &ScanOptions) -> ScanReport {
    let report = analyze_inner(db, data, opts);
    suppress(db, data, report)
}

fn analyze_inner(db: &Database, data: &[u8], opts: &ScanOptions) -> ScanReport {
    if let Some((sig, off, method)) = scan_bytes_core(db, data) {
        return ScanReport::infected(sig, off, method, Vec::new());
    }
    let mut findings = Vec::new();
    let mut budget = Budget::new(opts.limits.clone());
    match deep_analyze(db, data, opts, &mut budget, 0, &mut findings) {
        DeepOutcome::Infected {
            signature,
            offset,
            method,
        } => ScanReport::infected(signature, offset, method, findings),
        DeepOutcome::Limits(reason) => ScanReport::limits(reason, findings),
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
    let mut budget = Budget::new(opts.limits.clone());
    collect_all(db, data, &mut budget, 0, &mut out, &mut seen);
    out
}

fn collect_all(
    db: &Database,
    data: &[u8],
    budget: &mut Budget,
    depth: u32,
    out: &mut Vec<(String, Method)>,
    seen: &mut std::collections::HashSet<String>,
) {
    let ft = filetype::identify(data);
    let layout = if ft == FileType::Pe {
        pe::layout(data)
    } else {
        None
    };
    let mut eng = Vec::new();
    db.engine
        .scan_all_with_layout(data, ft, layout.as_ref(), &mut eng);
    if !db.engine.is_empty() && normalize::is_textual(data) {
        for norm in [normalize::html(data), normalize::text(data)] {
            db.engine.scan_all_with_layout(&norm, ft, None, &mut eng);
        }
    }
    for (name, _) in eng {
        push_sig(db, out, seen, name, Method::Pattern);
    }
    if !db.sections.is_empty() && ft == FileType::Pe {
        let want_sha = db.sections.wants_sha();
        for (size, slice) in pe::section_slices(data) {
            let d = hashes::section_digests(slice, want_sha);
            if let Some(name) = db.sections.lookup(size, &d) {
                push_sig(db, out, seen, name, Method::Hash);
            }
        }
    }
    if !db.hashes.is_empty() {
        if let Some(name) = db.hashes.lookup(&digests_of(data), data.len() as u64) {
            push_sig(db, out, seen, name, Method::Hash);
        }
    }
    // Bytecode programs (the normal scan path runs these; all-match must too,
    // or it silently misses every bytecode detection). Surface the detection
    // and recurse into any buffers a bytecode unpacker extracted.
    if !db.bytecode.is_empty() {
        let (det, extracted) = db.bytecode.scan(data, ft, layout.as_ref());
        if let Some((name, _)) = det {
            push_sig(db, out, seen, name, Method::Bytecode);
        }
        if depth < budget.limits.max_recursion {
            for buf in extracted {
                collect_all(db, &buf, budget, depth + 1, out, seen);
            }
        }
    }
    if let (Some(fmt), true) = (unpack_target(ft, data), depth < budget.limits.max_recursion) {
        if let Ok(entries) = unpack::extract(fmt, data, budget) {
            let container_size = data.len() as u64;
            for (i, e) in entries.iter().enumerate() {
                if !db.cdb.is_empty() {
                    let member = container::Member {
                        name: &e.name,
                        size_in_container: e.comp_size,
                        size_real: e.data.len() as u64,
                        encrypted: e.encrypted,
                        pos: (i + 1) as u64,
                    };
                    if let Some(sig) = db.cdb.matches(ft, container_size, &member) {
                        push_sig(db, out, seen, sig, Method::Hash);
                    }
                }
                collect_all(db, &e.data, budget, depth + 1, out, seen);
            }
        }
    }
}

fn push_sig(
    db: &Database,
    out: &mut Vec<(String, Method)>,
    seen: &mut std::collections::HashSet<String>,
    name: String,
    method: Method,
) {
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
}

/// Recursive structural analysis of an in-memory buffer.
fn deep_analyze(
    db: &Database,
    data: &[u8],
    opts: &ScanOptions,
    budget: &mut Budget,
    depth: u32,
    findings: &mut Vec<Finding>,
) -> DeepOutcome {
    let ft = filetype::identify(data);
    if depth == 0 {
        findings.push(Finding::new("type", ft.as_str()));
    }

    // Archives (and UPX-packed executables) are unpacked regardless of the
    // heuristics flag.
    if let Some(fmt) = unpack_target(ft, data) {
        if depth >= budget.limits.max_recursion {
            return DeepOutcome::Limits(format!(
                "recursion depth exceeds {}",
                budget.limits.max_recursion
            ));
        }
        let entries = match unpack::extract(fmt, data, budget) {
            Ok(e) => e,
            Err(hit) => return DeepOutcome::Limits(hit.reason),
        };
        let container_size = data.len() as u64;
        for (i, e) in entries.iter().enumerate() {
            // `.cdb` container-metadata signatures match on the member's
            // name/size/encryption/position within this container.
            if !db.cdb.is_empty() {
                let member = container::Member {
                    name: &e.name,
                    size_in_container: e.comp_size,
                    size_real: e.data.len() as u64,
                    encrypted: e.encrypted,
                    pos: (i + 1) as u64,
                };
                if let Some(sig) = db.cdb.matches(ft, container_size, &member) {
                    return DeepOutcome::Infected {
                        signature: sig,
                        offset: 0,
                        method: Method::Hash,
                    };
                }
            }
            if let Some((sig, off, m)) = scan_bytes_core(db, &e.data) {
                return DeepOutcome::Infected {
                    signature: sig,
                    offset: off,
                    method: m,
                };
            }
            match deep_analyze(db, &e.data, opts, budget, depth + 1, findings) {
                DeepOutcome::Clean => {}
                other => return other,
            }
        }
        return DeepOutcome::Clean;
    }

    // Embedded executables: scan PE images appended/embedded at a non-zero
    // offset (file-infectors, droppers, self-extractors). Each carved image is
    // run through the pattern/hash core (so its section hashes match) and then
    // recursed. Structural, not heuristic, so it runs regardless of the flag —
    // bounded by recursion depth and the embedded-image cap.
    if depth < budget.limits.max_recursion {
        for off in pe::embedded_pe_offsets(data) {
            let sub = &data[off..];
            if let Some((sig, o, m)) = scan_bytes_core(db, sub) {
                return DeepOutcome::Infected {
                    signature: sig,
                    offset: off as u64 + o,
                    method: m,
                };
            }
            match deep_analyze(db, sub, opts, budget, depth + 1, findings) {
                DeepOutcome::Clean => {}
                other => return other,
            }
        }
    }

    if !opts.heuristics {
        return DeepOutcome::Clean;
    }

    if let Some(hit) = db.fuzzy.match_tlsh(data) {
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
            let feats = ml::extract(data, Some(&info));
            let score = db.model.score(&feats);
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
fn scan_bytes_core(db: &Database, data: &[u8]) -> Option<(String, u64, Method)> {
    // Total bytes of bytecode-extracted (unpacked) content this scan may
    // re-scan, across the whole recursion — bounds an extraction bomb where a
    // (trusted) unpacker, driven by a hostile input, emits many/large buffers.
    let mut extract_budget = MAX_BC_EXTRACT_TOTAL;
    scan_bytes_depth(db, data, 0, &mut extract_budget)
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
) -> Option<(String, u64, Method)> {
    let ft = if !db.engine.is_empty() || !db.sections.is_empty() || !db.bytecode.is_empty() {
        Some(filetype::identify(data))
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
        if let Some((name, off)) = db.engine.scan_with_layout(data, ft, layout.as_ref()) {
            return Some((name, off, Method::Pattern));
        }
        // Normalised-content pass: HTML/text/mail (`Target:3/4/7`) signatures
        // are written against canonicalised content, not raw bytes. Run the
        // engine over normalised variants of textual input.
        if !db.engine.is_empty() && normalize::is_textual(data) {
            for norm in [normalize::html(data), normalize::text(data)] {
                if let Some((name, off)) = db.engine.scan_with_layout(&norm, ft, None) {
                    return Some((name, off, Method::Pattern));
                }
            }
        }
        // Bytecode programs whose trigger/hook fires (gated execution).
        let (det, extracted) = db.bytecode.scan(data, ft, layout.as_ref());
        if let Some((name, _idx)) = det {
            return Some((name, 0, Method::Bytecode));
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
                if let Some(hit) = scan_bytes_depth(db, &buf, depth + 1, extract_budget) {
                    return Some(hit);
                }
                // A packer may surface an embedded archive (e.g. an unpacked
                // payload that is itself a ZIP/gzip). Unpack it too, bounded by
                // the same extraction budget, so the real payload is reached.
                let bft = filetype::identify(&buf);
                if let Some(fmt) = unpack_target(bft, &buf) {
                    let mut b = Budget::new(unpack::Limits::default());
                    if let Ok(entries) = unpack::extract(fmt, &buf, &mut b) {
                        for e in entries {
                            let ec = e.data.len() as u64;
                            if *extract_budget < ec {
                                break;
                            }
                            *extract_budget -= ec;
                            if let Some(hit) =
                                scan_bytes_depth(db, &e.data, depth + 1, extract_budget)
                            {
                                return Some(hit);
                            }
                        }
                    }
                }
            }
        }
    }
    if !db.sections.is_empty() && ft == Some(FileType::Pe) {
        let want_sha = db.sections.wants_sha();
        for (size, slice) in pe::section_slices(data) {
            let d = hashes::section_digests(slice, want_sha);
            if let Some(name) = db.sections.lookup(size, &d) {
                return Some((name, 0, Method::Hash));
            }
        }
    }
    if !db.hashes.is_empty() {
        let d = digests_of(data);
        if let Some(name) = db.hashes.lookup(&d, data.len() as u64) {
            return Some((name, 0, Method::Hash));
        }
    }
    // YARA rules (yara-x): full-featured rule matching over the raw content.
    if !db.yara.is_empty() {
        if let Some(name) = db.yara.scan(data) {
            return Some((name, 0, Method::Yara));
        }
    }
    None
}

/// Streaming detection core (constant memory, any size): Aho-Corasick +
/// triple hasher in one forward pass.
fn stream_core<R: Read>(db: &Database, reader: R) -> io::Result<Option<(String, u64, Method)>> {
    // When no hash signatures are loaded, skip the (expensive) triple hash on
    // every byte and just run the pattern matcher over the raw reader.
    if db.hashes.is_empty() {
        if let Some(mat) = db.patterns.ac().stream_find_iter(reader).next() {
            let mat = mat?;
            let name = db.patterns.name(mat.pattern().as_usize()).to_string();
            return Ok(Some((name, mat.start() as u64, Method::Pattern)));
        }
        return Ok(None);
    }
    let mut tee = TeeHasher::new(reader);
    // `next()` drives the reader until the first match or EOF; on `None`
    // the whole stream has been consumed, so the hashers saw every byte.
    if let Some(mat) = db.patterns.ac().stream_find_iter(&mut tee).next() {
        let mat = mat?;
        let name = db.patterns.name(mat.pattern().as_usize()).to_string();
        return Ok(Some((name, mat.start() as u64, Method::Pattern)));
    }
    let size = tee.bytes_read();
    let digests = tee.finalize();
    if let Some(name) = db.hashes.lookup(&digests, size) {
        return Ok(Some((name, 0, Method::Hash)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use patterns::EICAR;
    use std::io::Cursor;

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
        eb.add_ndb("Test.Html:0:*:3c7363726970743e6576696c");
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
