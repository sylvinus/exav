//! Archive extraction with decompression-bomb limits.
//!
//! [`detect`] names a container's format and [`walk`] hands its members, one
//! at a time, to a visitor, which may stop the walk. The container is any
//! [`ByteSource`]: bytes in memory, or a seekable source read through a
//! [`source::BlockCache`]. A member comes as its bytes when its format decodes
//! it whole, or as a reader that decodes it as it is read, so a member of any
//! size is never held here. [`extract`] collects every member into memory, for
//! callers that want a list.
//!
//! Extraction is bounded by a [`Budget`] (members, output and scanned bytes,
//! recursion depth, the largest object held at once). Hitting a bound returns
//! [`LimitHit`], which the caller maps to `LimitsExceeded`, or to
//! `Unscannable` for content that could not be decoded.
//!
//! ```rust,no_run
//! use exav_unpack::{detect, walk, Budget, Limits, Member};
//!
//! # fn example(data: Vec<u8>) -> Result<(), exav_unpack::LimitHit> {
//! let Some(fmt) = detect(&data) else { return Ok(()) };
//! let mut budget = Budget::new(Limits::default());
//! walk::<()>(fmt, &data, &mut budget, &mut |meta, content, _| {
//!     let size = match content {
//!         Some(Member::Bytes(bytes)) => bytes.len() as u64,
//!         Some(Member::Stream(reader)) => std::io::copy(reader, &mut std::io::sink()).unwrap_or(0),
//!         None => 0,
//!     };
//!     println!("{}: {size} bytes", meta.name);
//!     None
//! })?;
//! # Ok(())
//! # }
//! ```
//!
//! # Safety
//!
//! This crate contains **no `unsafe` code**: the entire extraction layer,
//! including the vendored PPMd7 sub-allocator (`formats/ppmd7/`), is 100% safe
//! Rust over a bounds-checked byte arena. The forbid below is enforced
//! crate-wide.
#![forbid(unsafe_code)]

use std::io::Read;

pub use source::ByteSource;
#[cfg(feature = "base64scan")]
use source::{Bytes, Indexed, Stepper};

pub(crate) mod formats;
// Every name this pulls in is behind a format feature, so the glob imports
// nothing at all in a build with none of them compiled in.
#[allow(unused_imports)]
use formats::*;

#[cfg(any(feature = "gzip", feature = "zip", feature = "pdf", feature = "ole"))]
mod inflate;
pub mod profile;
pub mod source;
pub mod span;
mod stream;
pub mod volume;
#[cfg(feature = "pdf")]
pub use formats::has_obfuscated_name_object;
#[allow(unused_imports)]
pub(crate) use stream::Region;
pub use stream::{is_budget_overflow, walk, Member, MemberMeta, Mtime, Visit};

/// Count of overlapping ZIP local file records, the signal behind ClamAV's
/// `Heuristics.Zip.OverlappingFiles`. Zero for any well-formed archive.
#[cfg(feature = "zip")]
pub use formats::zip::overlapping_local_records;

/// Without the `zip` feature there is no ZIP parser, so no ZIP heuristic can
/// fire; answering zero keeps callers free of feature gates.
#[cfg(not(feature = "zip"))]
pub fn overlapping_local_records(_data: &dyn ByteSource) -> usize {
    0
}

#[cfg(feature = "zip")]
pub use formats::zip::directory_is_consistent as zip_directory_is_consistent;

/// Without the `zip` feature no ZIP is ever confirmed.
#[cfg(not(feature = "zip"))]
pub fn zip_directory_is_consistent(_data: &[u8]) -> bool {
    false
}

/// The dictionary size an XZ stream declares, and the largest exav will
/// allocate. A declaration above the cap is ClamAV's
/// `Heuristics.XZ.DicSizeLimit`: memory a decoder must commit before producing
/// a single byte.
#[cfg(feature = "xz")]
pub use formats::xz::{declared_dict_size as xz_declared_dict_size, XZ_MAX_DICT};

#[cfg(not(feature = "xz"))]
pub fn xz_declared_dict_size(_data: &[u8]) -> Option<u64> {
    None
}
#[cfg(not(feature = "xz"))]
pub const XZ_MAX_DICT: u64 = 64 * 1024 * 1024;

/// ClamAV's alert name when a partition table's entries overlap, or `None` when
/// the table is well formed. Overlapping partitions are parser confusion at the
/// disk-image layer.
///
/// Not gated on `partition`: that feature buys walking the volumes, which needs
/// a filesystem reader. Spotting overlap needs only the table.
pub use formats::partition::intersection_alert as partition_intersection_alert;

/// The first structural fault in an image, as a ClamAV
/// `Heuristics.Broken.Media.*` name, or `None` when the file is well formed or
/// is not an image. Pure parsing: no decoding, no allocation of pixel data.
pub use formats::mediacheck::broken_media_alert;

/// Without the `pdf` feature there is no PDF parser, so no PDF heuristic can
/// fire. Answering `false` keeps every caller free of feature gates; the
/// alternative left the documented `--no-default-features --features zip` build
/// (the one the WASM size figures come from) failing to compile at all.
#[cfg(not(feature = "pdf"))]
pub fn has_obfuscated_name_object(_data: &[u8]) -> bool {
    false
}
// RAR decompression primitives, exposed for the rar3/rar5 examples + tests.
// Diagnostic surface, not part of the stable API: may change in any release.
#[cfg(feature = "rar")]
#[doc(hidden)]
pub use formats::{unpack29, unpack50, window_size_from_comp_info};

/// Limits governing recursive extraction.
///
/// New fields may appear in any release. Build with `Limits::default()` and
/// assign the fields you care about, never with a struct literal, which a
/// new field would break.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Limits {
    pub max_recursion: u32,
    /// Cap on the number of members visited across the whole recursive walk.
    ///
    /// exav's default is deliberately HIGHER than ClamAV's 10,000, because the
    /// two count different populations for the same file. exav descends into
    /// nested archives that ClamAV does not, so it sees strictly more countable
    /// objects, and adopting ClamAV's number would buy less coverage under the
    /// same-looking setting.
    ///
    /// Measured on a live example: the `litellm` PyPI source tarball holds 2,794
    /// tar members, 27 of which are `.whl` files: ZIP archives with their own
    /// members. Counting those (correctly) puts the walk past 9,000, so at 10,000
    /// it stopped short of a member ClamAV matched. Nothing was miscounted; there
    /// was simply more to count. A source tarball vendoring wheels is ordinary,
    /// not adversarial.
    ///
    /// The limit is still a bomb defence and still trips loudly
    /// (`LIMITS-EXCEEDED`, never a silent clean). `--clamav-compat` sets 10,000
    /// so a differential run compares like with like.
    pub max_members: u64,
    /// Cap on the total decompressed bytes across the whole (recursive)
    /// extraction.
    ///
    /// Charged cumulatively by [`Budget::commit`] and never released, so it is
    /// also the ceiling on how much extracted data can be resident at one
    /// moment, which makes it, not [`Self::max_buffer_bytes`], the limit that
    /// bounds live extraction memory. It has to fit the address space the
    /// process is given, or the kernel's limit is reached before this one and a
    /// reportable verdict becomes a killed worker; the daemon clamps it to the
    /// per-job grant for exactly that reason.
    pub max_extracted_bytes: u64,
    /// Max output/input size ratio for a single compressed stream.
    pub max_compression_ratio: u64,
    /// The ceiling on the bytes any *one* forced-materialization site may hold
    /// at once: a decompressed member, a whole decompressed sub-container (7z
    /// solid block, CAB folder), an LZ sliding window, a decrypted blob, a
    /// parsed TOC. Every site that must buffer a whole object caps itself here,
    /// so an operator tunes peak allocation with one knob (see [MEMORY.md] for
    /// the exhaustive inventory).
    ///
    /// [MEMORY.md]: https://github.com/sylvinus/exav/blob/main/crates/exav-unpack/MEMORY.md
    ///
    /// It bounds one buffer, not the total: several are alive at once, because
    /// a container, its member and that member's own member are each mid-scan
    /// while the walk is inside them. [`Self::max_extracted_bytes`] is what
    /// bounds the sum. Default 256 MiB. (Also the per-member output cap fed to
    /// [`Budget::reserve`].)
    pub max_buffer_bytes: u64,
    /// Cap on the cumulative bytes fed to the *matching core* across the whole
    /// recursive analysis of one top-level file (distinct from
    /// [`Self::max_extracted_bytes`], which counts what decompression
    /// *produces*). Bounds re-scanning bombs (e.g. a disk image full of
    /// embedded PEs, where the same suffix is carved and matched at many
    /// offsets and depths) without limiting the legitimate one-pass scan of a
    /// large file. Deterministic, so it trips identically on every machine
    /// (unlike a wall-clock deadline).
    pub max_scanned_bytes: u64,
    /// Cap on the instructions the PE stub emulator may run across the whole
    /// recursive analysis of one top-level file.
    ///
    /// Each emulation already has its own instruction budget; this bounds their
    /// sum, which otherwise grows with the number of packed executables an
    /// archive carries. A run cut short by it is `LimitsExceeded`.
    pub max_pe_emulation_steps: u64,
    /// Formats this scan will open, or `None` for every format compiled in.
    ///
    /// A compile-time feature decides what a *binary* can do; this decides what
    /// a *call* may do, so one build can serve a caller that accepts archives
    /// and a caller that does not. A deployment that only ever expects ZIP can
    /// say so without maintaining its own build.
    ///
    /// A format excluded here is REPORTED, never skipped: the member comes
    /// back `Entry::unsupported`, so the scan says "there is a container here
    /// and I did not open it" rather than passing over it in silence. Refusing
    /// to look is a policy; pretending there was nothing to see is a bug.
    ///
    /// Applies at every nesting level, not only the top: a permitted ZIP
    /// containing a refused RAR reports the RAR.
    pub allowed_formats: Option<std::collections::BTreeSet<Format>>,
}

impl Limits {
    /// Whether `fmt` may be opened under these limits.
    pub fn allows(&self, fmt: Format) -> bool {
        self.allowed_formats
            .as_ref()
            .is_none_or(|set| set.contains(&fmt))
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_recursion: 16,
            max_members: 100_000,
            max_extracted_bytes: 1024 * 1024 * 1024, // 1 GiB extracted total
            max_compression_ratio: 1000,
            max_buffer_bytes: 256 * 1024 * 1024,
            // 10 GiB fed to the matcher total. This is a CPU/time bound, NOT a
            // memory bound: streamed members are scanned without being held in
            // RAM (capped separately by `max_buffer_bytes`/`deep_analysis_max`),
            // so this can be generous: it exists only to stop re-scanning bombs
            // and runaway scan time, and lets a multi-gigabyte member be fully
            // scanned.
            max_scanned_bytes: 10 * 1024 * 1024 * 1024,
            // A few seconds to tens of seconds of emulation per top-level file,
            // against the per-stub budget of `formats::pepack`.
            max_pe_emulation_steps: 1_000_000_000,
            // Every format the build was compiled with. Narrowing this is a
            // deployment decision, and a default that narrowed it would hide
            // content from callers who never asked for that.
            allowed_formats: None,
        }
    }
}

/// Mutable extraction budget, shared across the recursion.
pub struct Budget {
    /// The bounds this budget enforces. Readable through [`Budget::limits`] but
    /// not writable: the counters below are crate-private precisely so the
    /// bounds cannot be bypassed, and a caller free to raise the limits they are
    /// checked against would bypass them just as effectively. Set them once when
    /// constructing the budget.
    limits: Limits,
    // Running counters, mutated only through `charge_scan`/`count_entry`/
    // `reserve`/`commit` so the bomb-defense bounds can't be bypassed by a caller
    // writing them directly. Crate-private for that reason.
    pub(crate) files: u64,
    pub(crate) total_out: u64,
    /// Cumulative bytes fed to the matching core (see [`Limits::max_scanned_bytes`]).
    pub(crate) scanned: u64,
    /// Emulator instructions spent so far (see [`Limits::max_pe_emulation_steps`]).
    pub(crate) pe_emulation_steps: u64,
    /// Candidate passwords tried (in order) when decrypting an encrypted member
    /// (ZIP ZipCrypto/AES today). Empty by default: an encrypted member with no
    /// password yields an `Entry::unsupported(encrypted=true, …)` so the scanner
    /// reports `PasswordProtected`. The pool is the union of any `.pwdb` file and
    /// the runtime `ScanOptions::passwords`, threaded down by exav-core.
    pub passwords: Vec<String>,
    /// Verify container checksums (CRCs) during extraction. **Off by default**:
    /// a malware scanner scans decompressed content regardless of integrity
    /// metadata: a wrong CRC must never stop a member's bytes from being
    /// scanned (that would let an attacker downgrade a detection by flipping a
    /// checksum byte). This matches ClamAV, which ignores CRCs for scanning.
    /// Only has effect with the `checksums` Cargo feature compiled in; without
    /// it, checksums are never verified regardless of this flag.
    pub(crate) verify_checksums: bool,
    /// Hand the visitor the directory entries of a container that has them as
    /// members of their own (ZIP), with no content. Off by default: a scan
    /// has nothing to read in them. See [`Budget::set_visit_directories`].
    pub(crate) visit_directories: bool,
}

impl Budget {
    /// The bounds this budget enforces.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            files: 0,
            total_out: 0,
            scanned: 0,
            pe_emulation_steps: 0,
            passwords: Vec::new(),
            verify_checksums: false,
            visit_directories: false,
        }
    }

    /// Construct a budget with a password pool for decrypting encrypted members.
    pub fn with_passwords(limits: Limits, passwords: Vec<String>) -> Self {
        Self {
            passwords,
            ..Self::new(limits)
        }
    }

    /// Enable container-checksum verification (default off). Requires the
    /// `checksums` feature to have any effect. When off (default), extraction
    /// scans decompressed content even if a CRC fails (the scanner default).
    pub fn set_verify_checksums(&mut self, verify: bool) -> &mut Self {
        self.verify_checksums = verify;
        self
    }

    /// Also visit directory entries (default off), for a caller that recreates
    /// the tree, empty directories included.
    pub fn set_visit_directories(&mut self, visit: bool) -> &mut Self {
        self.visit_directories = visit;
        self
    }

    /// Whether checksum verification is active: the `checksums` feature is
    /// compiled in **and** [`Budget::set_verify_checksums`] was enabled.
    pub fn should_verify_checksums(&self) -> bool {
        cfg!(feature = "checksums") && self.verify_checksums
    }

    /// Charge `n` bytes against the cumulative scan-size budget. Returns `Err`
    /// once the total bytes matched across the recursive analysis exceeds
    /// [`Limits::max_scanned_bytes`], which the caller maps to `LimitsExceeded`.
    /// Used to bound re-scanning bombs (a buffer carved and matched at many
    /// offsets/depths) deterministically, before any wall-clock backstop.
    pub fn charge_scan(&mut self, n: u64) -> Result<(), LimitHit> {
        self.scanned = self.scanned.saturating_add(n);
        if self.scanned > self.limits.max_scanned_bytes {
            return Err(LimitHit::of_kind(
                LimitKind::MaxScanSize,
                format!("scanned bytes > {}", self.limits.max_scanned_bytes),
            ));
        }
        Ok(())
    }

    /// Bytes still available in the cumulative scan budget
    /// ([`Limits::max_scanned_bytes`] − already scanned). Used by the **streaming**
    /// member API as the per-member reader cap: a streamed member is never
    /// retained, so it is bounded by how much may still be fed to the matcher
    /// (a *processing* limit), not by the per-member *buffer* cap
    /// ([`Self::reserve`]). This is what decouples "how large a member we will
    /// scan" from "how much we hold in RAM at once".
    pub fn remaining_scan(&self) -> u64 {
        self.limits.max_scanned_bytes.saturating_sub(self.scanned)
    }

    /// Count one archive member toward the file-count budget. Called for
    /// every entry encountered, including directories and skipped entries,
    /// so a huge directory-only archive still trips the cap.
    pub fn count_entry(&mut self) -> Result<(), LimitHit> {
        self.files += 1;
        if self.files > self.limits.max_members {
            return Err(LimitHit::of_kind(
                LimitKind::MaxFiles,
                format!("file count > {}", self.limits.max_members),
            ));
        }
        Ok(())
    }

    /// Maximum bytes the next member may decompress to: the smaller of the
    /// per-member cap and the bytes still left in the total budget. Fails if
    /// the total budget is already exhausted.
    pub fn reserve(&mut self) -> Result<u64, LimitHit> {
        let remaining = self
            .limits
            .max_extracted_bytes
            .saturating_sub(self.total_out);
        if remaining == 0 {
            return Err(LimitHit::new(format!(
                "extracted bytes > {}, the total a scan may hold (exav's \
                 --max-process-bytes sets it)",
                self.limits.max_extracted_bytes
            )));
        }
        Ok(remaining.min(self.limits.max_buffer_bytes))
    }

    pub fn commit(&mut self, n: u64) {
        self.total_out = self.total_out.saturating_add(n);
    }

    /// Emulator instructions still available to this scan.
    #[cfg_attr(not(feature = "pe-emu"), allow(dead_code))]
    pub(crate) fn pe_emulation_room(&self) -> u64 {
        self.limits
            .max_pe_emulation_steps
            .saturating_sub(self.pe_emulation_steps)
    }

    #[cfg_attr(not(feature = "pe-emu"), allow(dead_code))]
    pub(crate) fn charge_pe_emulation(&mut self, steps: u64) {
        self.pe_emulation_steps = self.pe_emulation_steps.saturating_add(steps);
    }

    #[cfg_attr(not(feature = "pe-emu"), allow(dead_code))]
    pub(crate) fn pe_emulation_exhausted(&self) -> LimitHit {
        LimitHit::of_kind(
            LimitKind::MaxScanTime,
            format!(
                "PE emulation steps > {} (--max-pe-emulation-steps)",
                self.limits.max_pe_emulation_steps
            ),
        )
    }
}

/// An extraction stopped early. [`LimitHit::is_corrupt`] picks the verdict:
/// undecodable content (malformed/truncated structure, or a decoder that
/// panicked → `Unscannable`) versus a resource bound being hit
/// (size/recursion/ratio/scan budget → `LimitsExceeded`). Carries the
/// human-readable reason for the report.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{reason}")]
pub struct LimitHit {
    pub reason: String,
    /// Which budget stopped the scan. Carried as a *type*, not inferred from
    /// `reason`: a caller that needs to name the limit (the ClamAV-compatible
    /// `Heuristics.Limits.Exceeded.*` alerts) must not have to pattern-match
    /// prose, which drifts the moment a message is reworded.
    pub kind: LimitKind,
}

/// The budget that stopped a scan, named the way the signature format names it.
///
/// Deliberately no `Default`: there is no neutral kind. A bare default would
/// read as one verdict or the other, so every construction names its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LimitKind {
    /// Cumulative bytes fed to the matcher (`max_scanned_bytes`).
    MaxScanSize,
    /// A single member's decompressed size
    /// (`max_buffer_bytes`/`max_extracted_bytes`).
    MaxFileSize,
    /// Number of members visited (`max_members`).
    MaxFiles,
    /// Container nesting depth (`max_recursion`).
    MaxRecursion,
    /// CPU work: emulator instructions across the scan (`max_pe_emulation_steps`).
    MaxScanTime,
    /// Not a budget: the input was malformed. Kept in the same enum so every
    /// `LimitHit` has a kind and nothing has to guess.
    Corrupt,
}

impl LimitHit {
    /// Whether the stop was undecodable content rather than a resource bound:
    /// the verdict discriminator (`true` → `Unscannable`, `false` →
    /// `LimitsExceeded`).
    pub fn is_corrupt(&self) -> bool {
        matches!(self.kind, LimitKind::Corrupt)
    }

    /// A resource-budget stop → `LimitsExceeded`.
    fn new(reason: String) -> Self {
        Self {
            reason,
            kind: LimitKind::MaxFileSize,
        }
    }

    /// A resource-budget stop, naming which budget it was.
    fn of_kind(kind: LimitKind, reason: String) -> Self {
        Self { reason, kind }
    }
    /// An undecodable-content stop → `Unscannable`: malformed/truncated input, or
    /// a decoder panic contained at the extraction boundary.
    pub(crate) fn corrupt(reason: String) -> Self {
        Self {
            reason,
            kind: LimitKind::Corrupt,
        }
    }
}

/// Read until `buf` is full or the source ends, and return how much was read.
///
/// A read error is reported, never taken for the end: from a source that can
/// fail part way (a network range reader) it would pass for a short, complete
/// container, and every member past it would go unseen.
#[allow(dead_code)]
pub(crate) fn read_full<R: Read + ?Sized>(src: &mut R, buf: &mut [u8]) -> Result<usize, LimitHit> {
    let mut n = 0;
    while n < buf.len() {
        match src.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(LimitHit::corrupt(format!("read failed after {n} B: {e}"))),
        }
    }
    Ok(n)
}

/// Up to `len` bytes at `off`; fewer only where the source ends. See
/// [`read_full`] for why a failure is an error.
#[allow(dead_code)]
pub(crate) fn read_at<R: Read + std::io::Seek + ?Sized>(
    src: &mut R,
    off: u64,
    len: usize,
) -> Result<Vec<u8>, LimitHit> {
    src.seek(std::io::SeekFrom::Start(off))
        .map_err(|e| LimitHit::corrupt(format!("seek to {off} failed: {e}")))?;
    let mut buf = vec![0u8; len];
    let n = read_full(src, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// One extracted member.
///
/// New fields may appear in any release: build one with [`Entry::new`] or
/// [`Entry::unsupported`] and assign the others.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Entry {
    pub name: String,
    pub data: Vec<u8>,
    /// Compressed size within the container (for `.cdb` matching); defaults to
    /// the decompressed length when the extractor can't report it.
    pub comp_size: u64,
    /// Whether the member is stored encrypted (`.cdb` `IsEncrypted`).
    pub encrypted: bool,
    /// `Some(reason)` when the member was recognised but its *content* could not
    /// be decoded for a non-limit reason (unsupported compression, encryption).
    /// `data` is then empty, but the metadata is still valid (`.cdb` matches).
    /// The scanner surfaces this as a distinct `Unscannable` verdict rather than
    /// silently treating the member as clean.
    pub unsupported: Option<&'static str>,
    /// When the member was last modified (see [`MemberMeta::mtime`]).
    pub mtime: Option<Mtime>,
    /// Its Unix mode (see [`MemberMeta::mode`]).
    pub mode: Option<u32>,
}

impl Entry {
    /// An entry whose compressed size is unknown (use the decompressed length)
    /// and which is not encrypted: the common case.
    pub fn new(name: String, data: Vec<u8>) -> Self {
        Entry {
            comp_size: data.len() as u64,
            name,
            data,
            ..Entry::default()
        }
    }

    /// A member whose metadata is known but whose content could not be decoded
    /// (unsupported method / encryption). `reason` names the cause for the
    /// `Unscannable` verdict; `data` is empty.
    pub fn unsupported(
        name: String,
        comp_size: u64,
        encrypted: bool,
        reason: &'static str,
    ) -> Self {
        Entry {
            name,
            comp_size,
            encrypted,
            unsupported: Some(reason),
            ..Entry::default()
        }
    }
}

/// A container/archive format this crate can extract embedded files from
/// (archives plus structured documents: OLE2, PDF, MIME email).
// `Ord`/`Hash` so a caller can hold a set of formats; see
// [`Limits::allowed_formats`]. The ordering has no meaning beyond making that
// set cheap; nothing depends on which format sorts first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Format {
    Zip,
    Gzip,
    Tar,
    Bzip2,
    Xz,
    Cab,
    /// Microsoft Compiled HTML Help (`.chm`, ITSS container).
    Chm,
    Ole,
    Pdf,
    Email,
    SevenZip,
    Iso,
    Lha,
    Arj,
    /// RAR4/RAR5 archive. Stored, RAR3 (LZ + PPMd) and RAR5 members are
    /// decoded; RAR 1.5/2.x compression and encryption are reported.
    Rar,
    /// UPX-packed PE/ELF/Mach-O (decompress the embedded original).
    Upx,
    /// Unix `ar` archive (`.a` static libs, Debian `.deb` packages).
    Ar,
    /// cpio archive (RPM payloads, initramfs).
    Cpio,
    /// XAR archive (macOS `.pkg`/`.xip`).
    Xar,
    /// Apple DMG disk image (UDIF).
    Dmg,
    /// Microsoft Virtual Hard Disk (`conectix`), fixed or dynamic. The variant
    /// is always defined (like `Iso`/`Xar`) so it can be named in any build;
    /// only the detector and extractor are gated. Matches still need a
    /// wildcard arm: the enum is `#[non_exhaustive]`, so no downstream match
    /// is ever exhaustive.
    Vhd,
    /// Unix `compress` (`.Z`), LZW.
    Lzw,
    /// QEMU copy-on-write disk image.
    Qcow2,
    /// VMware virtual disk (sparse or streamOptimized).
    Vmdk,
    /// Microsoft VHDX, the modern Windows virtual disk.
    Vhdx,
    /// Windows Imaging Format (`.wim`/`.esd`): chunk-compressed file resources.
    Wim,
    /// LZ4 frame (`.lz4`).
    Lz4,
    /// ARC / PKARC / PAK archive, the pre-ZIP SEA format.
    Arc,
    /// ACE archive, recognised so it is reported, never decoded.
    Ace,
    StuffIt,
    /// ALZ archive (ESTsoft ALZip): stored, bzip2 and deflate members.
    Alz,
    /// EGG archive (ESTsoft): stored, deflate, bzip2, LZMA and AZO members.
    Egg,
    /// HWP v3 document (Hangul): the deflated body is decoded.
    Hwp3,
    /// InstallShield MSI installer, recognised so it is reported, not decoded.
    IshieldMsi,
    /// InstallShield InstallScript cabinet, recognised, not decoded.
    IshieldCab,
    /// InstallShield Z archive, the older `.z` installer format, decoded.
    IshieldZ,
    /// CryptFF-encrypted file, recognised so it is reported, not decrypted.
    CryptFf,
    /// ext2/3/4 filesystem image: walked, files reassembled from their extents.
    Ext,
    /// lrzip stream: recognised so it is reported, not decoded.
    Lrzip,
    /// ZOO archive: LZD and LZH members decoded, CRC-16 checked.
    Zoo,
    /// AppleSingle / AppleDouble container, recognised, not read.
    AppleSingle,
    /// FAT12/16/32 filesystem, walked, so fragmented files come back whole.
    Fat,
    /// Inno Setup installer, recognised so it is reported, never decoded.
    Inno,
    /// NTFS filesystem, walked through the master file table.
    Ntfs,
    /// Zstandard compressed stream.
    Zstd,
    /// Lzip compressed stream.
    Lzip,
    /// uuencode / Base64-uuencode (`begin`…`end`) wrapped file.
    Uuencode,
    /// Adobe XDP (XML-wrapped, base64-encoded PDF).
    Xdp,
    /// MS-Compress SZDD / KWAJ single-file compression.
    Szdd,
    /// TNEF (`winmail.dat`) MS email attachment container.
    Tnef,
    /// SWF (Adobe Flash) movie: decompress the inner FWS body (CWS/ZWS).
    Swf,
    /// BinHex 4.0 (`.hqx`), a classic-Mac 6-bit-encoded forked file.
    Binhex,
    /// Windows Shell Link (`.lnk`): extract command-line/target/icon strings.
    Lnk,
    /// Raw disk image partition map (GPT / Apple Partition Map / MBR).
    Partition,
    /// Python compiled bytecode (`.pyc`): surface the marshalled code body.
    Pyc,
    /// NSIS (Nullsoft) installer: decompress the embedded data blocks.
    Nsis,
    /// Mach-O universal ("fat") binary: split into per-architecture slices.
    Machofat,
    /// Self-extracting archive: an executable stub with an archive appended.
    Sfx,
    /// Compiled AutoIt3 script embedded in a PE (`AU3!EA05`/`AU3!EA06`).
    Autoit,
    /// Microsoft OneNote (`.one`) section: carve embedded FileDataStoreObjects.
    OneNote,
    /// RTF document: extract hex-encoded embedded objects (`\objdata`).
    Rtf,
    /// PE packed by a runtime packer (Petite/FSG/NsPack aPLib families are
    /// decompressed; other packers are detected only). See `formats/pepack.rs`.
    PePacked,
    /// Java `.class`: surface constant-pool strings and class/name references.
    JavaClass,
    /// AI model: Python pickle (dangerous-import surfacing) or safetensors.
    AiModel,
    /// Microsoft Script Encoder (`#@~^` VBScript/JScript.Encode): decode.
    Screnc,
}

impl Format {
    /// Every variant, so a caller can assert it handles the whole set. Adding a
    /// variant without adding it here fails `every_format_is_listed`.
    pub const ALL: &'static [Format] = &[
        Format::Zip,
        Format::Gzip,
        Format::Tar,
        Format::Bzip2,
        Format::Xz,
        Format::Cab,
        Format::Chm,
        Format::Ole,
        Format::Pdf,
        Format::Email,
        Format::SevenZip,
        Format::Iso,
        Format::Lha,
        Format::Arj,
        Format::Rar,
        Format::Upx,
        Format::Ar,
        Format::Cpio,
        Format::Xar,
        Format::Dmg,
        Format::Vhd,
        Format::Lzw,
        Format::Qcow2,
        Format::Vmdk,
        Format::Vhdx,
        Format::Wim,
        Format::Lz4,
        Format::Arc,
        Format::Ace,
        Format::StuffIt,
        Format::Alz,
        Format::Egg,
        Format::Hwp3,
        Format::IshieldMsi,
        Format::IshieldCab,
        Format::IshieldZ,
        Format::CryptFf,
        Format::Ext,
        Format::Lrzip,
        Format::Zoo,
        Format::AppleSingle,
        Format::Fat,
        Format::Inno,
        Format::Ntfs,
        Format::Zstd,
        Format::Lzip,
        Format::Uuencode,
        Format::Xdp,
        Format::Szdd,
        Format::Tnef,
        Format::Swf,
        Format::Binhex,
        Format::Lnk,
        Format::Partition,
        Format::Pyc,
        Format::Nsis,
        Format::Machofat,
        Format::Sfx,
        Format::Autoit,
        Format::OneNote,
        Format::Rtf,
        Format::PePacked,
        Format::JavaClass,
        Format::AiModel,
        Format::Screnc,
    ];
}

#[cfg(test)]
mod format_all_tests {
    use super::Format;

    /// `ALL` is written by hand, so it can fall behind the enum. Round-tripping
    /// each variant through a match the compiler checks for exhaustiveness makes
    /// a new variant a build error here rather than a silent omission, and an
    /// omission would let a container escape the scanner's dispatch coverage
    /// test in `exav-core`.
    #[test]
    fn every_format_is_listed() {
        fn tag(f: Format) -> u8 {
            match f {
                Format::Zip => 0,
                Format::Gzip => 1,
                Format::Tar => 2,
                Format::Bzip2 => 3,
                Format::Xz => 4,
                Format::Cab => 5,
                Format::Chm => 6,
                Format::Ole => 7,
                Format::Pdf => 8,
                Format::Email => 9,
                Format::SevenZip => 10,
                Format::Iso => 11,
                Format::Lha => 12,
                Format::Arj => 13,
                Format::Rar => 14,
                Format::Upx => 15,
                Format::Ar => 16,
                Format::Cpio => 17,
                Format::Xar => 18,
                Format::Dmg => 19,
                Format::Vhd => 20,
                Format::Lzw => 21,
                Format::Qcow2 => 22,
                Format::Vmdk => 23,
                Format::Vhdx => 45,
                Format::Wim => 46,
                Format::Lz4 => 47,
                Format::Arc => 48,
                Format::Ace => 49,
                Format::StuffIt => 54,
                Format::Alz => 55,
                Format::Egg => 56,
                Format::Hwp3 => 57,
                Format::IshieldMsi => 58,
                Format::CryptFf => 59,
                Format::IshieldCab => 60,
                Format::Ext => 61,
                Format::Lrzip => 62,
                Format::Zoo => 63,
                Format::AppleSingle => 64,
                Format::IshieldZ => 65,
                Format::Fat => 50,
                Format::Inno => 51,
                Format::Ntfs => 52,
                Format::Zstd => 24,
                Format::Lzip => 25,
                Format::Uuencode => 26,
                Format::Xdp => 27,
                Format::Szdd => 28,
                Format::Tnef => 29,
                Format::Swf => 30,
                Format::Binhex => 31,
                Format::Lnk => 32,
                Format::Partition => 33,
                Format::Pyc => 34,
                Format::Nsis => 35,
                Format::Machofat => 36,
                Format::Sfx => 37,
                Format::Autoit => 38,
                Format::OneNote => 39,
                Format::Rtf => 40,
                Format::PePacked => 41,
                Format::JavaClass => 42,
                Format::AiModel => 43,
                Format::Screnc => 44,
            }
        }
        let mut seen: Vec<u8> = Format::ALL.iter().map(|f| tag(*f)).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            65,
            "Format::ALL is missing a variant (or lists one twice)"
        );
    }
}

/// Whether `data` begins with a real bzip2 stream: `BZh` + a block-size digit
/// (`1`–`9`) + the 48-bit block magic `0x314159265359` (a compressed block) or
/// the empty-stream end magic `0x177245385090`. The bare 4-byte `BZh#` prefix is
/// too weak on its own: it occurs coincidentally in binary data (e.g. inside an
/// ISO or a PE overlay), and treating such a false hit as bzip2 makes the member
/// fail to decode and poisons the whole scan as `UNSCANNABLE`. Every genuine
/// bzip2 stream carries one of these two magics, so the check has no false
/// negatives.
fn is_bzip2_magic(data: &[u8]) -> bool {
    data.len() >= 10
        && data.starts_with(b"BZh")
        && matches!(data[3], b'1'..=b'9')
        && (data[4..10] == [0x31, 0x41, 0x59, 0x26, 0x53, 0x59]
            || data[4..10] == [0x17, 0x72, 0x45, 0x38, 0x50, 0x90])
}

/// Whether `data` begins with a real CAB (Microsoft Cabinet) header: `MSCF`
/// followed by the `reserved1` field, which the MS-CAB spec fixes at zero in
/// every genuine cabinet. The bare 4-byte `MSCF` magic collides with binary data
/// (e.g. inside an ISO), and a false hit routed to the cabinet parser fails deep
/// in string parsing and reports the object `LIMITS-EXCEEDED`; requiring the zero
/// `reserved1` rejects those without dropping any real cabinet.
fn is_cab_magic(data: &[u8]) -> bool {
    data.len() >= 8 && data.starts_with(b"MSCF") && data[4..8] == [0, 0, 0, 0]
}

/// Whether `data` begins with an ARJ main header: `60 EA`, a size of at most
/// 2600, and the header's CRC-32 after it. The magic alone is two bytes and
/// collides with binary data; a false hit fails in the extractor and reports
/// the object `UNSCANNABLE`.
#[cfg(feature = "arj")]
fn is_arj_magic(data: &[u8]) -> bool {
    let Some(&[0x60, 0xEA, lo, hi]) = data.get(..4) else {
        return false;
    };
    let size = u16::from_le_bytes([lo, hi]) as usize;
    let Some(crc) = data.get(4 + size..8 + size) else {
        return false;
    };
    (1..=2600).contains(&size)
        && crc32fast::hash(&data[4..4 + size]) == u32::from_le_bytes(crc.try_into().unwrap())
}

/// Whether `data` begins with a real gzip member (RFC 1952): `1f 8b`, then the
/// compression method `08` (deflate, the only method gzip defines), then a flag
/// byte whose three high bits are reserved and must be zero. The bare `1f 8b`
/// prefix is only two bytes and collides constantly with binary data (e.g. inside
/// a PE); a false hit is routed to the inflate path, fails with a "corrupt
/// deflate/gzip" member error, and reports the carrier `UNSCANNABLE`. Validating
/// CM + reserved flag bits rejects those with no loss on genuine gzip.
fn is_gzip_magic(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 0x08 && data[3] & 0xE0 == 0
}

/// Whether `d` starts with a stand-alone executable / OLE magic (PE `MZ`, ELF,
/// Mach-O, or OLE2/CFB). Cheap prefix test: 6 decoded bytes suffice, so it also
/// gates on just the first few decoded base64 chars. Deliberately excludes bare
/// ZIP (`PK`): a 4-byte match collides too often with base64 noise.
#[cfg(feature = "base64scan")]
fn starts_executable_magic(d: &[u8]) -> bool {
    d.starts_with(b"MZ")
        || d.starts_with(b"\x7fELF")
        || d.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || d.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || d.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || d.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || d.starts_with(&[0xd0, 0xcf, 0x11, 0xe0])
}

/// Whether a fully-decoded blob is a real, re-scannable executable: one of
/// [`starts_executable_magic`] and, for a PE, with a *valid* PE header at
/// `e_lfanew` (rejecting a bare `MZ`). See [`base64_payloads`].
#[cfg(feature = "base64scan")]
fn is_executable_payload(d: &[u8]) -> bool {
    if d.len() < 64 || !starts_executable_magic(d) {
        return false;
    }
    if d.starts_with(b"MZ") {
        let e = u32::from_le_bytes([d[0x3c], d[0x3d], d[0x3e], d[0x3f]]) as usize;
        return d.get(e..e + 4) == Some(b"PE\x00\x00");
    }
    true
}

/// Decode base64 assets embedded in a markup buffer (`data:` URIs in HTML and
/// base64 element bodies in flat-XML Office documents), returning each decoded
/// payload.
///
/// This is the inline-attachment channel of a document that has no archive to
/// unpack. A phishing page carries the brand logo it impersonates as a `data:`
/// URI, and a Word/Excel 2003 flat-XML dropper carries its "enable macros" lure
/// image as a base64 element body; in both cases the document is one
/// self-contained file with nothing to fetch and nothing to extract with an
/// ordinary unpacker. Signatures key on those images and scope them with
/// `Container:` precisely so they fire on the document and not on the same image
/// standing alone, which they can only do if the image is pulled out of it.
///
/// A run is decoded only when its first bytes are a real asset magic (image,
/// executable, OLE2), so ordinary base64-looking text costs a 6-byte decode and
/// nothing more. Bounded by `cap` per payload and by a cap on how many return.
#[cfg(feature = "base64scan")]
pub fn markup_embedded_payloads(src: &dyn ByteSource, cap: u64) -> Vec<Vec<u8>> {
    match src.as_slice() {
        Some(data) => markup_payloads_on(&mut Indexed(data), cap),
        None => markup_payloads_on(&mut Stepper::new(src), cap),
    }
}

#[cfg(feature = "base64scan")]
fn markup_payloads_on<B: Bytes>(data: &mut B, cap: u64) -> Vec<Vec<u8>> {
    use base64::Engine;
    /// Shortest base64 run worth decoding; below this it cannot be an asset.
    const MIN_RUN: usize = 64;
    const MAX_PAYLOADS: usize = 16;

    let engine = base64::engine::general_purpose::STANDARD;
    let plain = base64::engine::general_purpose::STANDARD_NO_PAD;
    let is_b64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
    let mut out = Vec::new();
    let mut i = 0usize;
    let n = data.len();
    while i < n && out.len() < MAX_PAYLOADS {
        if !is_b64(data.at(i)) {
            i += 1;
            continue;
        }
        // Only runs introduced by a `data:` URI or sitting directly inside an
        // element body are candidates. Anything else in markup is prose.
        let before = data.range(i.saturating_sub(96), i);
        let introduced = before.ends_with(b";base64,") || before.last() == Some(&b'>');
        let start = i;
        let mut j = i;
        while j < n && is_b64(data.at(j)) {
            j += 1;
        }
        i = j.max(start + 1);
        if !introduced || j - start < MIN_RUN {
            continue;
        }
        // Cheap gate first: 8 base64 chars decode to 6 bytes, enough for every
        // magic we care about, and costs no allocation on a miss.
        match plain.decode(data.range(start, start + 8)) {
            Ok(head) if starts_asset_magic(&head) => {}
            _ => continue,
        }
        // Absorb the padding the run scan stopped at, so a well-formed URI
        // decodes whole. Without it the tail falls off the last 4-char group and
        // the payload comes back one or two bytes short: invisible on an image,
        // fatal to a hash signature.
        let mut end = j;
        while end < n && end - j < 2 && data.at(end) == b'=' {
            end += 1;
        }
        i = i.max(end);
        if (end - start) as u64 > cap.saturating_mul(2) {
            continue;
        }
        let run = data.range(start, end);
        let decoded = engine
            .decode(&run)
            .or_else(|_| plain.decode(&run[..(j - start) / 4 * 4]));
        if let Ok(dec) = decoded {
            if !dec.is_empty() && dec.len() as u64 <= cap {
                out.push(dec);
            }
        }
    }
    out
}

/// Magics of things worth pulling out of a document: raster images (what
/// `Target:5` perceptual-hash signatures match), executables, and OLE2.
#[cfg(feature = "base64scan")]
fn starts_asset_magic(d: &[u8]) -> bool {
    starts_executable_magic(d)
        || d.starts_with(b"\x89PNG")
        || d.starts_with(&[0xff, 0xd8, 0xff])
        || d.starts_with(b"GIF8")
        || d.starts_with(b"BM")
        || d.starts_with(b"RIFF")
        || d.starts_with(b"II*\x00")
        || d.starts_with(b"MM\x00*")
        || d.starts_with(&[0x00, 0x00, 0x01, 0x00])
}

/// Find base64-encoded executables embedded in a text/script buffer and return
/// each decoded payload. Malware routinely stashes a PE/ELF as a long base64
/// string in a script, such as a PowerShell reflective loader (`$PEBytes =
/// "TVqQAA…"`), a JS/VBS dropper or an HTA, where the executable is invisible to a
/// signature that matches the *decoded* bytes. Each maximal run of base64
/// characters (internal whitespace tolerated, since scripts/RTF line-wrap the
/// blob) at least `MIN_RUN` long is decoded; a decode is returned only when it
/// passes `is_executable_payload`, so a coincidental base64-looking region in
/// binary data (which decodes to noise) is dropped: no false positives, and the
/// caller still validates + rescans through the normal type path. Bounded by
/// `cap` (per-payload size), `MAX_PAYLOADS`, and `MAX_ATTEMPTS` (decode tries).
#[cfg(feature = "base64scan")]
pub fn base64_payloads(src: &dyn ByteSource, cap: u64) -> Vec<Vec<u8>> {
    match src.as_slice() {
        Some(data) => base64_payloads_on(&mut Indexed(data), cap),
        None => base64_payloads_on(&mut Stepper::new(src), cap),
    }
}

#[cfg(feature = "base64scan")]
fn base64_payloads_on<B: Bytes>(data: &mut B, cap: u64) -> Vec<Vec<u8>> {
    use base64::Engine;
    // A base64-encoded PE is at minimum a few hundred bytes; require a run that
    // decodes to ≥ ~1 KB so we never trial-decode short incidental runs.
    const MIN_RUN: usize = 1400; // base64 chars → ≥ ~1 KB decoded
    const MAX_PAYLOADS: usize = 8;
    const MAX_ATTEMPTS: usize = 64;
    let is_b64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
    let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;

    let mut out = Vec::new();
    let mut attempts = 0;
    let n = data.len();
    let mut i = 0;
    while i < n && out.len() < MAX_PAYLOADS && attempts < MAX_ATTEMPTS {
        if !is_b64(data.at(i)) {
            i += 1;
            continue;
        }
        // Measure the run [start, j): count base64 chars (internal whitespace
        // from line-wrapping tolerated) and capture the first 8, WITHOUT
        // allocating. Stops at padding `=` or any other byte.
        let start = i;
        let mut nb64 = 0usize;
        let mut head = [0u8; 8];
        let mut j = i;
        while j < n {
            let b = data.at(j);
            if is_b64(b) {
                if nb64 < 8 {
                    head[nb64] = b;
                }
                nb64 += 1;
                j += 1;
            } else if is_ws(b) {
                j += 1;
            } else {
                break;
            }
        }
        i = j.max(start + 1);
        if nb64 < MIN_RUN {
            continue;
        }
        // Cheap gate: decode only the first 8 base64 chars (6 bytes) and bail
        // unless they start with an executable/OLE magic, so long runs that are
        // NOT executables (RTF `\objdata` hex, benign base64 text) cost nothing
        // beyond the byte count above: no full decode, no payload allocation.
        match engine.decode(head) {
            Ok(prefix) if starts_executable_magic(&prefix) => {}
            _ => continue,
        }
        attempts += 1;
        // Whole 4-char groups decode to exactly 3 bytes each, so a run too
        // large to keep is known before it is read.
        if (nb64 / 4 * 3) as u64 > cap {
            continue;
        }
        // Executable-looking: now materialize the run (whitespace stripped) and
        // decode the whole 4-char groups (dropping any partial tail / padding).
        let mut run: Vec<u8> = Vec::with_capacity(nb64);
        let mut at = start;
        while at < j {
            let piece_end = j.min(at + source::CHUNK);
            run.extend(
                data.range(at, piece_end)
                    .iter()
                    .copied()
                    .filter(|&b| is_b64(b)),
            );
            at = piece_end;
        }
        run.truncate(run.len() / 4 * 4);
        if let Ok(dec) = engine.decode(&run) {
            if dec.len() as u64 <= cap && is_executable_payload(&dec) {
                out.push(dec);
            }
        }
    }
    out
}

/// What [`detect`] reads of an object: its start (all of it when it is held in
/// memory), its length, and the rest of it for the checks that read its end or
/// search it through.
pub(crate) struct Probe<'a> {
    pub(crate) head: &'a [u8],
    pub(crate) len: usize,
    /// The object, when `head` is only its start.
    src: Option<&'a dyn ByteSource>,
    /// What the one read of `src` through [`search_through`] found.
    #[cfg_attr(
        not(any(
            feature = "screnc",
            feature = "autoit",
            feature = "nsis",
            feature = "sfx"
        )),
        allow(dead_code)
    )]
    found: std::cell::OnceCell<Searched>,
    /// The caller's read that makes the search, in place of one of its own.
    #[cfg_attr(
        not(any(
            feature = "screnc",
            feature = "autoit",
            feature = "nsis",
            feature = "sfx"
        )),
        allow(dead_code)
    )]
    prescan: Option<&'a dyn Fn() -> Prescan>,
}

/// What [`detect`] searches a whole object for, found in one read of it the
/// first time one is asked for, rather than in a read each: where each of
/// [`searched`] first occurs, and for an executable, where the archive a
/// self-extractor carries starts.
#[derive(Default)]
// Which field a build reads depends on its format features.
#[allow(dead_code)]
struct Searched {
    markers: Vec<Option<usize>>,
    sfx: Option<usize>,
}

/// The needles [`detect`] searches a whole object for.
// Which pushes a build makes depends on its format features.
#[allow(clippy::vec_init_then_push)]
fn searched() -> Vec<&'static [u8]> {
    #[allow(unused_mut)]
    let mut needles: Vec<&'static [u8]> = Vec::new();
    #[cfg(feature = "screnc")]
    needles.push(formats::SCRENC_MARKER);
    #[cfg(feature = "nsis")]
    needles.push(&formats::NSIS_SIG);
    #[cfg(feature = "autoit")]
    needles.extend([&formats::MARKER_EA05[..], &formats::MARKER_EA06[..]]);
    needles
}

/// What [`detect`] searches a whole object for, found as a caller reads the
/// object: fed every window of it in order, each running [`Self::OVERLAP`]
/// bytes into the next, and handed to [`detect_prescanned`] when it asks. One
/// read of an object then serves detection and whatever else the caller looks
/// for in it.
pub struct Prescan {
    finders: Vec<memchr::memmem::Finder<'static>>,
    markers: Vec<Option<usize>>,
    #[cfg(feature = "sfx")]
    payload: Option<formats::sfx::PayloadSearch>,
}

impl Prescan {
    /// Bytes each window must run into the next, so that what it looks for is
    /// seen whole across the seam: the longest marker, and a self-extractor's
    /// archive magic with the header check after it.
    pub const OVERLAP: usize = 32;

    /// Whether [`detect_prescanned`] can ask for the search on an object of
    /// `len` bytes: not when the start it reads anyway is all of it.
    pub fn needed(len: usize) -> bool {
        len > DETECT_HEAD
    }

    /// The search for an object that starts with `head`: a self-extractor's
    /// payload is looked for only in an executable.
    pub fn new(head: &[u8]) -> Self {
        let needles = searched();
        #[cfg(not(feature = "sfx"))]
        let _ = head;
        Prescan {
            finders: needles
                .iter()
                .map(|n| memchr::memmem::Finder::new(*n))
                .collect(),
            markers: vec![None; needles.len()],
            #[cfg(feature = "sfx")]
            payload: (head.starts_with(b"MZ") || head.starts_with(b"\x7fELF"))
                .then(formats::sfx::PayloadSearch::new),
        }
    }

    /// Search the window `w` at `base` in the object, its last or not.
    pub fn feed(&mut self, base: usize, w: &[u8], last: bool) {
        for (f, slot) in self.finders.iter().zip(&mut self.markers) {
            if slot.is_none() {
                *slot = f.find(w).map(|p| base + p);
            }
        }
        #[cfg(feature = "sfx")]
        if let Some(p) = &mut self.payload {
            p.feed(base, w, last);
        }
        #[cfg(not(feature = "sfx"))]
        let _ = last;
    }

    /// Whether every search has its answer, so the rest of the object has
    /// nothing more to tell it.
    pub fn done(&self) -> bool {
        #[cfg(feature = "sfx")]
        let payload = self.payload.as_ref().is_none_or(|p| p.done());
        #[cfg(not(feature = "sfx"))]
        let payload = true;
        payload && self.markers.iter().all(Option::is_some)
    }

    #[cfg_attr(
        not(any(
            feature = "screnc",
            feature = "autoit",
            feature = "nsis",
            feature = "sfx"
        )),
        allow(dead_code)
    )]
    fn searched(self) -> Searched {
        #[cfg(feature = "sfx")]
        const {
            assert!(formats::sfx::PayloadSearch::OVERLAP <= Prescan::OVERLAP)
        };
        Searched {
            markers: self.markers,
            #[cfg(feature = "sfx")]
            sfx: self.payload.and_then(|p| p.offset()),
            #[cfg(not(feature = "sfx"))]
            sfx: None,
        }
    }
}

/// [`Searched`] in the first `len` bytes of `src`, which starts with `head`,
/// a window at a time.
#[cfg(any(
    feature = "screnc",
    feature = "autoit",
    feature = "nsis",
    feature = "sfx"
))]
fn search_through(src: &dyn ByteSource, len: usize, head: &[u8]) -> Searched {
    let mut pre = Prescan::new(head);
    let overlap = Prescan::OVERLAP;
    let mut at = 0;
    while at < len && !pre.done() {
        let w = src.window(at, (len - at).min(source::CHUNK.max(overlap + 1)));
        let last = w.len() <= overlap || at + w.len() >= len;
        pre.feed(at, &w, last);
        if last {
            break;
        }
        at += w.len() - overlap;
    }
    pre.searched()
}

impl<'a> Probe<'a> {
    /// An object held in memory.
    pub(crate) fn whole(data: &'a [u8]) -> Self {
        Probe {
            head: data,
            len: data.len(),
            src: None,
            found: std::cell::OnceCell::new(),
            prescan: None,
        }
    }

    /// Up to `n` bytes of the object from `off`.
    pub(crate) fn window(&self, off: usize, n: usize) -> std::borrow::Cow<'a, [u8]> {
        match self.src {
            Some(src) => src.window(off, n),
            None => ByteSource::window(self.head, off, n),
        }
    }

    /// Where `needle` first occurs in the object.
    #[cfg(any(feature = "screnc", feature = "autoit", feature = "nsis"))]
    pub(crate) fn find(&self, needle: &[u8]) -> Option<usize> {
        let Some(src) = self.src else {
            return memchr::memmem::find(self.head, needle);
        };
        match searched().iter().position(|n| *n == needle) {
            Some(i) => self.searched(src).markers[i],
            None => src.find(needle, 0, self.len),
        }
    }

    /// For an object not held in memory, where the archive a self-extractor
    /// carries starts, as `sfx::payload_offset` finds it.
    #[cfg(feature = "sfx")]
    pub(crate) fn sfx_payload(&self) -> Option<usize> {
        self.searched(self.src?).sfx
    }

    #[cfg(any(
        feature = "screnc",
        feature = "autoit",
        feature = "nsis",
        feature = "sfx"
    ))]
    fn searched(&self, src: &dyn ByteSource) -> &Searched {
        self.found.get_or_init(|| match self.prescan {
            Some(read) => read().searched(),
            None => search_through(src, self.len, self.head),
        })
    }

    /// The object, when it is not held whole in `head`.
    #[cfg(any(feature = "uuencode", feature = "sfx"))]
    pub(crate) fn source(&self) -> Option<&'a dyn ByteSource> {
        self.src
    }
}

/// Bytes of an object's start the checks read, other than those that read its
/// end or search it. Inno's and InstallShield's markers are looked for in the
/// first 4 MiB, and InstallShield's fixed record lies past its marker.
const DETECT_HEAD: usize = 4 * 1024 * 1024 + 1024;

/// Best-effort recognition of a container by magic bytes. Detection is
/// recognition-only: it reports what the bytes look like under the Cargo
/// features compiled in, not what any build could extract. A format behind a
/// disabled feature (CHM, FAT, ARC, among others) returns `None` rather than
/// reaching extraction as `unsupported`.
///
/// Reads the object's start, and whatever else a check needs when the object
/// is not held in memory.
pub fn detect(src: &dyn ByteSource) -> Option<Format> {
    detect_with(src, None)
}

/// [`detect`], its search through `src` made by `read` when detection needs
/// it: a [`Prescan`] fed all of `src` by a read of it that serves the caller's
/// own searches too.
pub fn detect_prescanned(src: &dyn ByteSource, read: &dyn Fn() -> Prescan) -> Option<Format> {
    detect_with(src, Some(read))
}

fn detect_with(src: &dyn ByteSource, prescan: Option<&dyn Fn() -> Prescan>) -> Option<Format> {
    if let Some(data) = src.as_slice() {
        return detect_probe(&Probe::whole(data));
    }
    // The first checks need a few bytes, so an archive typed by them is not
    // read `DETECT_HEAD` deep: over a network or browser reader that is most
    // of a small archive. Only those `detect_probe` makes first: a later one,
    // such as RAR's, could be overruled by an earlier check that needs more.
    if let Some(fmt) = archive_magic(&src.window(0, 16)) {
        return Some(fmt);
    }
    let head = src.window(0, DETECT_HEAD);
    if head.len() == src.len() {
        return detect_probe(&Probe::whole(&head));
    }
    detect_probe(&Probe {
        head: &head,
        len: src.len(),
        src: Some(src),
        found: std::cell::OnceCell::new(),
        prescan,
    })
}

/// The archive `src` starts with, among those whose magic is at offset 0 and
/// is checked from its first bytes alone (ZIP, gzip, 7z, xz, bzip2, CAB,
/// RAR), as [`detect`] would type it: what an archive carved out of another
/// object at its magic needs confirmed, without a search through the rest.
pub fn detect_archive_start(src: &dyn ByteSource) -> Option<Format> {
    let head = src.window(0, 16);
    archive_magic(&head).or_else(|| is_rar_magic(&head).then_some(Format::Rar))
}

/// The first checks of [`detect_probe`], which read a few bytes of the start.
fn archive_magic(data: &[u8]) -> Option<Format> {
    if data.len() >= 4 && &data[..2] == b"PK" && matches!(data[2..4], [3, 4] | [5, 6] | [7, 8]) {
        return Some(Format::Zip);
    }
    if is_gzip_magic(data) {
        return Some(Format::Gzip);
    }
    if data.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return Some(Format::SevenZip);
    }
    if data.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some(Format::Xz);
    }
    if is_bzip2_magic(data) {
        return Some(Format::Bzip2);
    }
    if is_cab_magic(data) {
        return Some(Format::Cab);
    }
    None
}

fn is_rar_magic(data: &[u8]) -> bool {
    data.starts_with(b"Rar!\x1a\x07\x00") || data.starts_with(b"Rar!\x1a\x07\x01\x00")
}

fn detect_probe(p: &Probe) -> Option<Format> {
    // Checks that read only the start: every length they compare against is
    // well within `DETECT_HEAD`, so the start answers as the whole would.
    let data = p.head;
    if let Some(fmt) = archive_magic(data) {
        return Some(fmt);
    }
    // CHM (ITSS): "ITSF" header magic at offset 0.
    #[cfg(feature = "chm")]
    if data.starts_with(b"ITSF") {
        return Some(Format::Chm);
    }
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return Some(Format::Ole);
    }
    if data.starts_with(b"%PDF-") {
        return Some(Format::Pdf);
    }
    if data.len() >= 263 && &data[257..262] == b"ustar" {
        return Some(Format::Tar);
    }
    if data.len() >= 7 && data[2] == b'-' && data[6] == b'-' && matches!(data[3], b'l' | b'p') {
        return Some(Format::Lha);
    }
    #[cfg(feature = "arj")]
    if is_arj_magic(data) {
        return Some(Format::Arj);
    }
    if is_rar_magic(data) {
        return Some(Format::Rar);
    }
    if data.len() >= 32774 && &data[32769..32774] == b"CD001" {
        return Some(Format::Iso);
    }
    // A UDF-only image has no ISO 9660 descriptor at all. Windows and macOS
    // still mount it, so it must not fall through as an unknown blob. Handled by
    // the same extractor, which walks whichever filesystems are present.
    #[cfg(feature = "iso")]
    if formats::udf::has_udf(data) {
        return Some(Format::Iso);
    }
    if data.starts_with(b"xar!") {
        return Some(Format::Xar);
    }
    // Before DMG: a `.wim` carries its own 8-byte magic, while the DMG sniff is
    // structural and claims this file first if given the chance.
    if formats::sniff::is_in(p, Format::Wim) {
        return Some(Format::Wim);
    }
    if formats::sniff::is_in(p, Format::Lz4) {
        return Some(Format::Lz4);
    }
    // ARC last of the archive magics:  plus a method byte is only two bytes,
    // so the name-field validation in `is_arc` is what makes it safe, and a
    // stronger magic should still win the race.
    if formats::sniff::is_in(p, Format::Ace) {
        return Some(Format::Ace);
    }
    if formats::sniff::is_in(p, Format::Alz) {
        return Some(Format::Alz);
    }
    if formats::sniff::is_in(p, Format::Egg) {
        return Some(Format::Egg);
    }
    if formats::sniff::is_in(p, Format::Hwp3) {
        return Some(Format::Hwp3);
    }
    if formats::sniff::is_in(p, Format::StuffIt) {
        return Some(Format::StuffIt);
    }
    if formats::sniff::is_in(p, Format::CryptFf) {
        return Some(Format::CryptFf);
    }
    if formats::sniff::is_in(p, Format::IshieldZ) {
        return Some(Format::IshieldZ);
    }
    if formats::sniff::is_in(p, Format::IshieldCab) {
        return Some(Format::IshieldCab);
    }
    if formats::sniff::is_in(p, Format::Lrzip) {
        return Some(Format::Lrzip);
    }
    if formats::sniff::is_in(p, Format::Zoo) {
        return Some(Format::Zoo);
    }
    if formats::sniff::is_in(p, Format::AppleSingle) {
        return Some(Format::AppleSingle);
    }
    // ext last of the filesystem sniffs: its magic is 1080 bytes in, so a
    // partition table or boot sector at offset 0 is the more specific answer.
    if formats::sniff::is_in(p, Format::Ext) {
        return Some(Format::Ext);
    }
    // FAT before the partition check: a volume boot record and an MBR both end
    // in `55 AA`, and the filesystem is the more specific answer.
    #[cfg(feature = "fat")]
    if formats::fat::is_fat(data) {
        return Some(Format::Fat);
    }
    if formats::sniff::is_in(p, Format::Ntfs) {
        return Some(Format::Ntfs);
    }
    #[cfg(feature = "arc")]
    if formats::arc::is_arc_in(p) {
        return Some(Format::Arc);
    }
    #[cfg(feature = "dmg")]
    if is_dmg(p) {
        return Some(Format::Dmg);
    }
    if formats::sniff::is_in(p, Format::Vhd) {
        return Some(Format::Vhd);
    }
    if formats::sniff::is_in(p, Format::Lzw) {
        return Some(Format::Lzw);
    }
    if formats::sniff::is_in(p, Format::Qcow2) {
        return Some(Format::Qcow2);
    }
    if formats::sniff::is_in(p, Format::Vmdk) {
        return Some(Format::Vmdk);
    }
    if formats::sniff::is_in(p, Format::Vhdx) {
        return Some(Format::Vhdx);
    }
    if data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Some(Format::Zstd);
    }
    if data.starts_with(b"!<arch>\n") {
        return Some(Format::Ar);
    }
    if data.starts_with(b"LZIP") {
        return Some(Format::Lzip);
    }
    if data.starts_with(b"070701")
        || data.starts_with(b"070702")
        || data.starts_with(b"070707")
        || data.starts_with(&[0xc7, 0x71])
        || data.starts_with(&[0x71, 0xc7])
    {
        return Some(Format::Cpio);
    }
    // MS-Compress SZDD / KWAJ (fixed 8-byte magic).
    #[cfg(feature = "szdd")]
    if is_szdd(data) {
        return Some(Format::Szdd);
    }
    // uuencode has no byte-0 magic: require a `begin`/`begin-base64` opener with
    // a matching terminator (conservative; see `looks_like_uuencode`).
    #[cfg(feature = "uuencode")]
    if looks_like_uuencode(p) {
        return Some(Format::Uuencode);
    }
    // Adobe XDP: XML wrapping a base64-encoded PDF.
    #[cfg(feature = "xdp")]
    if looks_like_xdp(data) {
        return Some(Format::Xdp);
    }
    // TNEF (winmail.dat): signature 0x223E9F78, little-endian.
    #[cfg(feature = "tnef")]
    if data.starts_with(&[0x78, 0x9F, 0x3E, 0x22]) {
        return Some(Format::Tnef);
    }
    // SWF: CWS = zlib-compressed, ZWS = LZMA-compressed. FWS is already
    // uncompressed, so it is not registered as an extractable container.
    #[cfg(feature = "swf")]
    if data.starts_with(b"CWS") || data.starts_with(b"ZWS") {
        return Some(Format::Swf);
    }
    // Mach-O universal ("fat") binary: CAFEBABE/BF with a plausible arch table
    // (strict, to avoid the Java `.class` CAFEBABE collision).
    #[cfg(feature = "machofat")]
    if looks_like_machofat(p) {
        return Some(Format::Machofat);
    }
    // Java `.class`: CAFEBABE followed by a plausible major version (>= 45,
    // i.e. JDK 1.1+). Checked after Mach-O fat (which shares the magic) so a
    // universal binary is never misfiled; the version gate rejects fat headers,
    // whose bytes at [6..8] are an architecture count, not 45+.
    #[cfg(feature = "javaclass")]
    if data.len() >= 8
        && data[..4] == [0xCA, 0xFE, 0xBA, 0xBE]
        && u16::from_be_bytes([data[6], data[7]]) >= 45
    {
        return Some(Format::JavaClass);
    }
    // AI model: Python pickle (protocol 2–5 opener `80 0x`) or safetensors.
    #[cfg(feature = "aimodel")]
    if is_aimodel(p) {
        return Some(Format::AiModel);
    }
    // Microsoft Script Encoder: the `#@~^` marker (VBScript/JScript.Encode).
    #[cfg(feature = "screnc")]
    if looks_like_screnc(p) {
        return Some(Format::Screnc);
    }
    // OneNote (.one): the 16-byte OneStore section-header GUID at offset 0.
    #[cfg(feature = "onenote")]
    if is_onenote(data) {
        return Some(Format::OneNote);
    }
    #[cfg(feature = "rtf")]
    if data.starts_with(b"{\\rtf") {
        return Some(Format::Rtf);
    }
    // Windows Shell Link (.lnk): fixed 20-byte prefix (HeaderSize 0x4C + CLSID).
    #[cfg(feature = "lnk")]
    if data.starts_with(&[
        0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
    ]) {
        return Some(Format::Lnk);
    }
    // BinHex 4.0: a marker line (no byte-0 magic); scan the head for it.
    #[cfg(feature = "binhex")]
    if looks_like_binhex(data) {
        return Some(Format::Binhex);
    }
    // Python `.pyc`: weak magic (`\r\n` at offset 2), checked late, conservative.
    #[cfg(feature = "pyc")]
    if data.len() >= 16 && data[2] == 0x0D && data[3] == 0x0A {
        return Some(Format::Pyc);
    }
    // Partition maps last: GPT/APM carry strong magic, but the MBR `55 AA` boot
    // signature is weak, so `is_partition` only accepts an MBR with a plausible
    // entry, and being last means it never shadows a real format.
    // NSIS installer: PE stub + the NullsoftInst firstheader. Placed late (it
    // requires an MZ start, so it only claims a PE that is actually NSIS).
    #[cfg(feature = "nsis")]
    if is_nsis(p) {
        return Some(Format::Nsis);
    }
    // Compiled AutoIt3: the AU3!EA05/EA06 marker anywhere (embedded in a PE).
    #[cfg(feature = "autoit")]
    if is_autoit(p) {
        return Some(Format::Autoit);
    }
    // Inno Setup, before the generic SFX carve. The carve does produce the right
    // block, but that block is Inno's own chunked LZMA container. Emitted as an
    // ordinary member it read as clean, because compressed payload shows a
    // pattern scan nothing. Typing it here means it is reported instead.
    if formats::sniff::is_in(p, Format::Inno) {
        return Some(Format::Inno);
    }
    // After Inno and before the generic SFX carve, for the same reason: an
    // InstallShield installer is a PE whose payload the carve would mis-slice.
    if formats::sniff::is_in(p, Format::IshieldMsi) {
        return Some(Format::IshieldMsi);
    }
    // Self-extracting archive (PE/ELF stub + appended archive). After NSIS (more
    // specific) and only when a bare archive isn't at offset 0.
    #[cfg(feature = "sfx")]
    if looks_like_sfx(p) {
        return Some(Format::Sfx);
    }
    #[cfg(feature = "partition")]
    if is_partition(p) {
        return Some(Format::Partition);
    }
    None
}

#[cfg(test)]
mod detect_source_tests {
    use super::*;
    use crate::source::BlockCache;
    use std::io::Cursor;

    /// Longer than the start the probe reads.
    const BIG: usize = DETECT_HEAD + 4096;

    fn same(data: &[u8], what: &str) -> Option<Format> {
        let cache = BlockCache::with_sizes(Cursor::new(data.to_vec()), 4093, 64 * 4093).unwrap();
        let want = detect(&data);
        assert_eq!(detect(&cache), want, "{what}");
        want
    }

    fn fixtures(dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let path = e.path();
            if path.is_dir() {
                fixtures(&path, out);
            } else if let Ok(data) = std::fs::read(&path) {
                if data.len() < 8 << 20 {
                    out.push((path.display().to_string(), data));
                }
            }
        }
    }

    /// What one read of an object finds is where a search for each marker
    /// finds it, and where a self-extractor's own search finds its payload,
    /// whatever window seam they straddle, and nothing when absent.
    #[cfg(all(
        feature = "screnc",
        feature = "autoit",
        feature = "nsis",
        feature = "sfx"
    ))]
    #[test]
    fn markers_are_found_in_one_read() {
        let needles = searched();
        let payload = |data: &[u8]| {
            let mut r = source::Reader::new(&data);
            formats::sfx::payload_offset(&mut r, data.len() as u64)
                .unwrap()
                .map(|o| o as usize)
        };
        for shift in [0, 1, 7, 15, 16, 17] {
            let mut data = vec![b'.'; 7 * source::CHUNK];
            data[..2].copy_from_slice(b"MZ");
            for (k, n) in needles.iter().enumerate() {
                let at = (k + 1) * source::CHUNK - n.len() / 2 - shift;
                data[at..at + n.len()].copy_from_slice(n);
                // A second occurrence later, which must not be the one found.
                let later = at + 3 * source::CHUNK / 2;
                data[later..later + n.len()].copy_from_slice(n);
            }
            // An ARJ magic with no header behind it, then a ZIP, each across
            // a seam.
            let arj = 5 * source::CHUNK - 3 - shift;
            data[arj..arj + 2].copy_from_slice(&[0x60, 0xEA]);
            let zip = 6 * source::CHUNK - 2 - shift;
            data[zip..zip + 4].copy_from_slice(b"PK\x03\x04");
            let cache = BlockCache::with_sizes(Cursor::new(data.clone()), 4093, 64 * 4093).unwrap();
            let want: Vec<_> = needles
                .iter()
                .map(|n| memchr::memmem::find(&data, n))
                .collect();
            let got = search_through(&cache, data.len(), &data[..2]);
            assert_eq!(got.markers, want, "shift {shift}");
            assert_eq!(got.sfx, payload(&data), "shift {shift}");
            assert!(got.sfx.is_some());
            // Fed by a caller's own read, in windows of its own size.
            let got = prescanned(&data, 10007);
            assert_eq!(got.markers, want, "shift {shift}");
            assert_eq!(got.sfx, payload(&data), "shift {shift}");
            // Not an executable: no payload to look for.
            data[..2].copy_from_slice(b"..");
            assert_eq!(search_through(&cache, data.len(), &data[..2]).sfx, None);
        }
        let empty = vec![b'.'; 3 * source::CHUNK];
        let cache = BlockCache::with_sizes(Cursor::new(empty.clone()), 4093, 64 * 4093).unwrap();
        let got = search_through(&cache, empty.len(), b"MZ");
        assert!(got.markers.iter().all(Option::is_none) && got.sfx.is_none());
        for n in needles {
            assert!(n.len() <= Prescan::OVERLAP + 1);
        }
    }

    #[cfg(all(
        feature = "screnc",
        feature = "autoit",
        feature = "nsis",
        feature = "sfx"
    ))]
    fn prescanned(data: &[u8], window: usize) -> Searched {
        let mut pre = Prescan::new(data);
        let mut at = 0;
        loop {
            let end = (at + window).min(data.len());
            let last = end == data.len();
            pre.feed(at, &data[at..end], last);
            if last {
                return pre.searched();
            }
            at = end - Prescan::OVERLAP;
        }
    }

    #[test]
    fn a_large_object_is_typed_as_in_memory() {
        let mut all = Vec::new();
        fixtures(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"),
            &mut all,
        );
        assert!(all.len() > 100);
        let mut typed = std::collections::HashSet::new();
        for (name, x) in &all {
            // Longer than the probe's start, so the checks against the length
            // and the searches run over the source.
            let mut padded = x.clone();
            padded.resize(BIG.max(x.len() + 1), 0);
            typed.insert(same(&padded, name));
            // And the fixture's own end kept at the end, for the checks that
            // read there.
            padded.extend_from_slice(&x[x.len().saturating_sub(512)..]);
            typed.insert(same(&padded, &format!("{name}, end kept")));
        }
        // Fewer with fewer format features.
        assert!(typed.len() > 15, "{typed:?}");

        // Markers only a search through the object finds, past its start.
        let far = |head: &[u8], marker: &[u8], tail: &[u8]| {
            let mut v = head.to_vec();
            v.resize(BIG, b'.');
            v.extend_from_slice(marker);
            v.extend_from_slice(tail);
            v
        };
        let nsis_sig = [
            0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n',
            b's', b't',
        ];
        // Each case needs its format's detection compiled in.
        let cases: Vec<(Vec<u8>, Option<Format>, bool)> = vec![
            (
                far(b"", b"#@~^", b""),
                Some(Format::Screnc),
                cfg!(feature = "screnc"),
            ),
            (
                far(b"", b"AU3!EA06", b""),
                Some(Format::Autoit),
                cfg!(feature = "autoit"),
            ),
            (
                far(b"MZ", &nsis_sig, b""),
                Some(Format::Nsis),
                cfg!(feature = "nsis"),
            ),
            (
                far(b"MZ", b"PK\x03\x04", b""),
                Some(Format::Sfx),
                cfg!(feature = "sfx"),
            ),
            (
                far(b"begin 644 x\n", b"\n end \n", b""),
                Some(Format::Uuencode),
                cfg!(feature = "uuencode"),
            ),
            (far(b"begin 644 x\n", b"\n endx\n", b""), None, true),
            (far(b"", b"conectix", &[0; 504]), Some(Format::Vhd), true),
            (
                far(b"", b"koly", &[0; 508]),
                Some(Format::Dmg),
                cfg!(feature = "dmg"),
            ),
        ];
        for (i, (data, want, on)) in cases.iter().enumerate() {
            if *on {
                assert_eq!(same(data, &format!("case {i}")), *want, "case {i}");
            }
        }

        // A size read from the start, compared with the length.
        if cfg!(feature = "partition") {
            let mut mbr = vec![0u8; BIG + 1024];
            mbr[510..512].copy_from_slice(&[0x55, 0xAA]);
            mbr[446] = 0x80;
            mbr[450] = 0x0C;
            mbr[458..462].copy_from_slice(&2u32.to_le_bytes());
            for (lba, want) in [
                ((BIG / 512) as u32, Some(Format::Partition)),
                (u32::MAX / 2, None),
            ] {
                mbr[454..458].copy_from_slice(&lba.to_le_bytes());
                assert_eq!(same(&mbr, "mbr"), want, "lba {lba}");
            }
        }
        if cfg!(feature = "aimodel") {
            let mut st = vec![b' '; BIG + 100];
            for (n, want) in [
                (BIG as u64, Some(Format::AiModel)),
                (BIG as u64 + 100, None),
            ] {
                st[..8].copy_from_slice(&n.to_le_bytes());
                st[8..12].copy_from_slice(b"{\"a\"");
                assert_eq!(same(&st, "safetensors"), want, "n {n}");
            }
        }
    }
}

/// Per-member visitor of an extractor that decodes each member whole. Invoked
/// once per member with the shared [`Budget`]. Returns `Some(r)` to stop the
/// extraction, `None` to continue to the next member.
pub(crate) type Sink<'a, R> = &'a mut dyn FnMut(Entry, &mut Budget) -> Option<R>;

/// Fail the way a decoder can, for input carrying a marker that asks for it.
///
/// The marker is looked for ANYWHERE in the data, not just at the start, so the
/// trigger can be carried inside a genuinely well-formed container, which is
/// what lets the CLI be tested end to end: the file has to survive format
/// detection to reach a decoder at all.
///
/// Only the first is containable. `catch_unwind` catches unwinding and nothing
/// else, so the other two end the process, which is exactly why they are worth
/// firing: what a caller can observe then is the process's exit status, and a
/// crash that looks like a clean scan is the worst outcome exav has.
#[cfg(feature = "testing-faults")]
pub(crate) fn provoke(data: &[u8]) {
    let has = |m: &[u8]| data.windows(m.len()).any(|w| w == m);
    if has(b"__exav_panic__") {
        panic!("deliberate panic from the testing-faults feature");
    }
    if has(b"__exav_abort__") {
        // `abort` rather than a real allocation failure. The outcome is the one
        // being tested (`handle_alloc_error` aborts), and exhausting a
        // developer's machine to reach it would take the rest of the box with
        // it. On wasm32 the 4 GiB ceiling makes the genuine article safe; here
        // it is not.
        std::process::abort();
    }
    if has(b"__exav_stack__") {
        fn deeper(n: u64) -> u64 {
            if n == 0 {
                0
            } else {
                1 + std::hint::black_box(deeper(n + 1))
            }
        }
        std::hint::black_box(deeper(1));
    }
}

/// The extractors of the formats read whole, each decoding a member whole, for
/// [`walk`] (inside its panic boundary).
pub(crate) fn dispatch_extract<R>(
    fmt: Format,
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    match fmt {
        // A ZIP whose central directory will not parse: the directory it has,
        // then the local-header salvage.
        #[cfg(feature = "zip")]
        Format::Zip => extract_zip(data, budget, visit),
        #[cfg(feature = "chm")]
        Format::Chm => extract_chm(data, budget, visit),
        // OLE builds a combined VBA-macro dump from all streams, so it collects
        // then emits; the visitor still gets one member at a time.
        #[cfg(feature = "ole")]
        Format::Ole => emit_collected(extract_ole(data, budget)?, budget, visit),
        #[cfg(feature = "pdf")]
        Format::Pdf => extract_pdf(data, budget, visit),
        #[cfg(feature = "email")]
        Format::Email => extract_email(data, budget, visit),
        #[cfg(feature = "arj")]
        Format::Arj => extract_arj(data, budget, visit),
        // RAR decodes members eagerly (CRC checks, metadata-only entries for
        // encrypted/unsupported members), so it collects then emits; the visitor
        // still gets one member at a time and can stop early.
        #[cfg(feature = "rar")]
        Format::Rar => emit_collected(extract_rar(data, budget)?, budget, visit),
        #[cfg(feature = "upx")]
        Format::Upx => extract_upx(data, budget, visit),
        #[cfg(feature = "xar")]
        Format::Xar => extract_xar(data, budget, visit),
        #[cfg(feature = "vhd")]
        Format::Vhd => formats::vhd::extract_vhd(data, budget, visit),
        #[cfg(feature = "diskimage")]
        Format::Qcow2 => formats::qcow2::extract_qcow2(data, budget, visit),
        #[cfg(feature = "diskimage")]
        Format::Vmdk => formats::vmdk::extract_vmdk(data, budget, visit),
        #[cfg(feature = "diskimage")]
        Format::Vhdx => formats::vhdx::extract_vhdx(data, budget, visit),
        #[cfg(feature = "wim")]
        Format::Wim => formats::wim::extract_wim(data, budget, visit),
        #[cfg(feature = "arc")]
        Format::Arc => formats::arc::extract_arc(data, budget, visit),
        #[cfg(feature = "ace")]
        Format::Ace => formats::ace::extract_ace(data, budget, visit),
        #[cfg(feature = "alz")]
        Format::Alz => formats::alz::extract_alz(data, budget, visit),
        #[cfg(feature = "egg")]
        Format::Egg => formats::egg::extract_egg(data, budget, visit),
        #[cfg(feature = "hwp3")]
        Format::Hwp3 => formats::hwp3::extract_hwp3(data, budget, visit),
        // Recognised, not opened; all share one reporting path.
        Format::IshieldMsi
        | Format::IshieldCab
        | Format::CryptFf
        | Format::Lrzip
        | Format::AppleSingle => formats::reported::extract_reported(fmt, data, budget, visit),
        #[cfg(feature = "ext")]
        Format::Ext => formats::ext::extract_ext(data, budget, visit),
        #[cfg(feature = "zoo")]
        Format::Zoo => formats::zoo::extract_zoo(data, budget, visit),
        #[cfg(feature = "ishieldz")]
        Format::IshieldZ => formats::ishield_z::extract_ishield_z(data, budget, visit),
        #[cfg(feature = "stuffit")]
        Format::StuffIt => formats::stuffit::extract_stuffit(data, budget, visit),
        #[cfg(feature = "fat")]
        Format::Fat => formats::fat::extract_fat(data, budget, visit),
        #[cfg(feature = "inno")]
        Format::Inno => formats::inno::extract_inno(data, budget, visit),
        #[cfg(feature = "ntfs")]
        Format::Ntfs => formats::ntfs::extract_ntfs(data, budget, visit),
        #[cfg(feature = "uuencode")]
        Format::Uuencode => extract_uuencode(data, budget, visit),
        #[cfg(feature = "xdp")]
        Format::Xdp => extract_xdp(data, budget, visit),
        // KWAJ; SZDD itself is decoded as it is read.
        #[cfg(feature = "szdd")]
        Format::Szdd => extract_szdd(data, budget, visit),
        #[cfg(feature = "binhex")]
        Format::Binhex => extract_binhex(data, budget, visit),
        #[cfg(feature = "lnk")]
        Format::Lnk => extract_lnk(data, budget, visit),
        #[cfg(feature = "nsis")]
        Format::Nsis => extract_nsis(data, budget, visit),
        #[cfg(feature = "autoit")]
        Format::Autoit => extract_autoit(data, budget, visit),
        #[cfg(feature = "rtf")]
        Format::Rtf => extract_rtf(data, budget, visit),
        #[cfg(feature = "pepack")]
        Format::PePacked => extract_pepack(data, budget, visit),
        #[cfg(feature = "javaclass")]
        Format::JavaClass => extract_javaclass(data, budget, visit),
        #[cfg(feature = "aimodel")]
        Format::AiModel => extract_aimodel(data, budget, visit),
        #[cfg(feature = "screnc")]
        Format::Screnc => extract_screnc(data, budget, visit),
        // A format whose extractor this build left out. (A format decoded as it
        // is read never reaches here when its extractor is compiled in.)
        _ => not_compiled_in(fmt, data, budget, visit),
    }
}

/// The format was recognised but its extractor wasn't compiled into this build.
/// Emit one unsupported member so it reads as recognised-but-undecodable.
///
/// Every disabled-format arm must route here rather than return `Ok(None)`:
/// `Ok(None)` means "no members", which the caller cannot distinguish from an
/// empty archive, and the file then scans clean.
fn not_compiled_in<R>(
    fmt: Format,
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    emit_collected(
        vec![Entry::unsupported(
            format!("{fmt:?}"),
            data.len() as u64,
            false,
            "format support not compiled in",
        )],
        budget,
        visit,
    )
}

/// Feed an already-collected member list through a [`Sink`], stopping early if
/// the visitor does. Used by formats whose decoder can't (yet) stream.
pub(crate) fn emit_collected<R>(
    entries: Vec<Entry>,
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    for e in entries {
        if let Some(r) = visit(e, budget) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// Collect the immediate members of a container into a `Vec`, each read into
/// memory up to what [`Budget::reserve`] allows. [`walk`] is the call for
/// scanning: it hands members over one at a time and can stop early. This is
/// for callers that want the whole list.
///
/// A member whose decoding failed part way keeps the bytes decoded before the
/// failure and is marked `unsupported`, unless checksums are verified, when
/// the failure is an error.
///
/// # Errors
///
/// Returns [`LimitHit`], whose two shapes mean different things and should not
/// be collapsed into one "failed" branch:
///
/// * `corrupt == true`: the container could not be decoded: malformed,
///   truncated, an unsupported compression method, or a decoder panic caught at
///   the extraction boundary. The right verdict is `Unscannable`.
/// * `corrupt == false`: a budget stopped the walk, and `kind` names which
///   one. The right verdict is `LimitsExceeded`.
///
/// In both cases the members already decoded are discarded along with the
/// error; use [`walk`] if partial results matter.
///
/// **An error is never a reason to treat the input as clean.** A container this
/// call refused is content that was not scanned, which is the one outcome the
/// verdict model exists to keep distinguishable from an empty result.
pub fn extract(
    fmt: Format,
    src: &dyn ByteSource,
    budget: &mut Budget,
) -> Result<Vec<Entry>, LimitHit> {
    let mut out = Vec::new();
    let stopped = walk(fmt, src, budget, &mut |meta, content, budget| {
        let mut entry = Entry {
            name: meta.name.clone(),
            data: Vec::new(),
            comp_size: meta.comp_size,
            encrypted: meta.encrypted,
            unsupported: meta.unsupported,
            mtime: meta.mtime,
            mode: meta.mode,
        };
        if let Some(content) = content {
            match content.into_bytes(meta, budget) {
                Ok((data, partial)) => {
                    entry.data = data;
                    if partial && entry.unsupported.is_none() {
                        entry.unsupported = Some(
                            "member failed to decode part way; the bytes before the \
                             failure are kept",
                        );
                    }
                }
                Err(hit) => return Some(hit),
            }
        }
        out.push(entry);
        None
    })?;
    match stopped {
        Some(hit) => Err(hit),
        None => Ok(out),
    }
}

/// The volumes of a RAR set (`x.part1.rar`, `x.part2.rar`, ..., or `x.rar`,
/// `x.r00`, ...), in order, as one single-volume RAR archive: what [`walk`]
/// reads as [`Format::Rar`]. A member split across volumes is decoded whole
/// that way, where read one volume at a time it is reported unreadable.
/// `Err` names a part that does not fit the set.
#[cfg(feature = "rar")]
pub fn join_rar_volumes(volumes: &[&[u8]]) -> Result<Vec<u8>, String> {
    formats::join_rar_volumes(volumes)
}

/// True if `data` looks like a UPX-packed executable (a valid `PackHeader` is
/// present). Used by callers whose file-type classifier already recognises
/// PE/ELF/Mach-O and wants to additionally unpack UPX.
pub fn is_upx(data: &[u8]) -> bool {
    #[cfg(feature = "upx")]
    {
        // Both layouts the unpacker handles: the `l_info` chain, and a bare
        // PackHeader. Gating on `find_packheader` alone meant a PackHeader-only
        // image (a routine shape for packed malware) reached no unpacker at
        // all and scanned clean.
        find_packheader(data).is_some() || formats::has_packheader_layout(data)
    }
    #[cfg(not(feature = "upx"))]
    {
        let _ = data;
        false
    }
}

/// Run the PE-packer emulator over `data` and report what it did, for the
/// `pepack_emu` example. Returns a one-line summary plus the reconstructed
/// image when the stub produced one. Diagnostic surface only: the scan path
/// goes through [`extract`]; may change in any release.
#[cfg(feature = "pe-emu")]
#[doc(hidden)]
pub fn emulate_pe(data: &[u8], max_ticks: u64, trace: bool) -> (String, Vec<(String, Vec<u8>)>) {
    formats::emulate_pe(data, max_ticks, trace)
}

/// True if `data` is a PE packed by a runtime packer this crate recognises
/// (Petite/FSG/NsPack and the detect-only protectors). Used by callers whose
/// file-type classifier already recognises PE and wants to additionally unpack
/// runtime packers. Returns `false` when the `pepack` feature is disabled.
pub fn is_pepack(data: &[u8]) -> bool {
    #[cfg(feature = "pepack")]
    {
        formats::is_pepack(data)
    }
    #[cfg(not(feature = "pepack"))]
    {
        let _ = data;
        false
    }
}

/// Ceiling for a `Vec::with_capacity` pre-allocation driven by an
/// attacker-declared size (16 MiB). The buffer still grows on demand, bounded
/// by the budget-checked reads, so this only prevents a crafted header from
/// forcing a huge up-front allocation (the over-allocation DoS class; cf. the
/// ClamAV 7z/InstallShield advisories and the fuzz-found delharc OOM).
// Dead only in a build with none of the formats that pre-allocate (dmg, cab,
// 7z, ppmd7). Listing those features here instead would have to be corrected
// every time one of them starts or stops calling this, and getting that list
// wrong is a warning rather than an error, so it would rot quietly.
#[allow(dead_code)]
pub(crate) const PREALLOC_CAP: usize = 16 * 1024 * 1024;

/// Cap a pre-allocation request from an attacker-declared byte size.
#[allow(dead_code)] // see PREALLOC_CAP
pub(crate) fn cap_prealloc(requested: usize) -> usize {
    requested.min(PREALLOC_CAP)
}

/// Reject a stream whose decompressed size dwarfs its declared input size.
/// Absolute byte caps are the primary bomb defense; this is a fast reject
/// for the obvious cases. A declared input of 0 is ignored (we cannot trust
/// it) and left to the absolute caps.
///
/// Enforced only past [`RATIO_FLOOR_BYTES`] of output: below it the absolute
/// caps already bound the allocation and the content is cheap to scan, while a
/// bare ratio trips on ordinary content: a 1 KB-compressed blank scanned page
/// (1 MB of one byte) has a ratio over 1000:1 without being anyone's bomb. A
/// real bomb still trips as soon as its output crosses the floor, milliseconds
/// into the decompression.
// Dead only in a build with none of the compressing formats; see
// `cap_prealloc` for why the feature list is not spelled out.
#[allow(dead_code)]
pub(crate) fn ratio_guard(input: u64, output: u64, budget: &Budget) -> Result<(), LimitHit> {
    if output >= RATIO_FLOOR_BYTES
        && input > 0
        && output / input > budget.limits.max_compression_ratio
    {
        return Err(LimitHit::new(format!(
            "compression ratio {} > {}",
            output / input,
            budget.limits.max_compression_ratio
        )));
    }
    Ok(())
}

/// Output size from which the compression-ratio bomb check applies (4 MiB).
///
/// Below it, rejecting by ratio produces false `LIMITS-EXCEEDED` verdicts on
/// ordinary content: a blank scanned page is 1 MB of one repeated byte and
/// compresses past 1000:1 without being anyone's bomb. The absolute caps
/// (`max_buffer_bytes` per object, `max_extracted_bytes` in total) bound such
/// output anyway, and it is cheap to scan.
///
/// Sized to the evidence rather than generously: 4x the 1 MB page image that
/// makes the floor necessary. Every byte of headroom past that is ratio
/// checking given up for nothing: a bomb is still caught the moment its output
/// crosses the floor, milliseconds into decompression, and real bombs overshoot
/// by orders of magnitude.
pub(crate) const RATIO_FLOOR_BYTES: u64 = 4 * 1024 * 1024;

/// The EICAR anti-virus test string, assembled at runtime from its reverse.
///
/// The 68-byte sequence exists nowhere in this source tree, and nowhere in any
/// binary built from it. That is deliberate: a scanner is a file every other
/// scanner reads. Stored as a plain literal it would travel into the compiled
/// binary, the `.crate` tarballs on crates.io and the container image, and every
/// AV worth installing would quarantine all three on sight, which reads as a
/// broken release rather than as the test string it is. ClamAV keeps EICAR in a
/// signature database, not in its binary, for the same reason.
///
/// Reversed rather than encrypted so a reader can still verify it by eye: no
/// signature matches the reversed bytes, but `RACIE` is legible enough that
/// nobody has to trust a hex blob.
///
/// `exav`'s `scans_its_own_source_and_binary_clean` test holds this property for
/// the whole tree, so a literal reintroduced anywhere fails the build.
///
/// Test support, not part of the stable API: may change in any release.
#[doc(hidden)]
pub fn eicar() -> &'static [u8] {
    const REVERSED: &[u8] =
        br#"*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\4[PA@%P!O5X"#;
    static FORWARD: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    FORWARD.get_or_init(|| REVERSED.iter().rev().copied().collect())
}

/// The byte a masked test fixture is XORed with. Any non-zero value does the
/// job; this one is arbitrary.
///
/// Test support, not part of the stable API: may change in any release.
#[doc(hidden)]
pub const FIXTURE_MASK: u8 = 0x5A;

/// Undo the mask on a committed test fixture.
///
/// A committed fixture that a scanner detects is a fixture that gets quarantined
/// on `git clone`, deleted by an AV-scanned CI runner, and flagged by whatever
/// watches a contributor's laptop, for files whose entire job is to be detected.
/// Masking them removes the archive magic and the payload in one step, so no
/// scanner has anything to match, while the bytes stay one XOR away.
///
/// XOR rather than the password-protected ZIP that is standard for distributing
/// samples: these fixtures are the corpus for an archive extractor, so wrapping
/// them in archives would make the ZIP and 7z tests depend on working ZIP and
/// decryption support to load their own inputs, and the `--no-default-features`
/// build has neither compiled in.
///
/// Test support, not part of the stable API: may change in any release.
#[doc(hidden)]
pub fn unmask_fixture(masked: &[u8]) -> Vec<u8> {
    masked.iter().map(|b| b ^ FIXTURE_MASK).collect()
}

/// Read a test fixture, unmasking it when the masked form is what is committed.
///
/// Prefers `<path>.xor` and falls back to `<path>`, so only the fixtures a
/// scanner actually reacts to have to be masked and the rest stay readable with
/// ordinary tools. Missing-file errors name the plain path, which is the one a
/// reader is looking for.
///
/// Test support, not part of the stable API: may change in any release.
#[doc(hidden)]
pub fn read_fixture(path: &str) -> std::io::Result<Vec<u8>> {
    let masked = format!("{path}.xor");
    if std::fs::exists(&masked)? {
        return Ok(unmask_fixture(&std::fs::read(&masked)?));
    }
    std::fs::read(path)
}

/// Read up to `cap` bytes; the returned flag is true if the source had more
/// (so the caller can treat it as exceeding the budget rather than silently
/// truncating).
pub(crate) fn bounded_read<R: Read>(mut r: R, cap: u64) -> Result<(Vec<u8>, bool), std::io::Error> {
    let mut buf = Vec::new();
    (&mut r).take(cap.saturating_add(1)).read_to_end(&mut buf)?;
    let truncated = buf.len() as u64 > cap;
    if truncated {
        buf.truncate(cap as usize);
    }
    Ok((buf, truncated))
}

/// A decode error raised after the input was decoded in full, when only its
/// checksum disagreed. Carried inside the `io::Error` so a caller can tell it
/// from damage, which leaves content undecoded.
#[derive(Debug)]
struct ChecksumMismatch(&'static str);

impl std::fmt::Display for ChecksumMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} mismatch after a full decode", self.0)
    }
}

impl std::error::Error for ChecksumMismatch {}

#[allow(dead_code)] // see `bounded_read_salvage`
pub(crate) fn checksum_mismatch(what: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, ChecksumMismatch(what))
}

/// Whether a decode error left compressed content in the input that was never
/// decoded. A stream that ends early (the rest is absent) or that decoded in
/// full and failed its checksum hides nothing; damage part way does.
pub fn decode_error_hides_content(e: &std::io::Error) -> bool {
    e.kind() != std::io::ErrorKind::UnexpectedEof
        && !e
            .get_ref()
            .is_some_and(|inner| inner.is::<ChecksumMismatch>())
}

/// What [`bounded_read_salvage`] recovered.
#[allow(dead_code)] // see `bounded_read_salvage`
pub(crate) struct Salvaged {
    pub(crate) data: Vec<u8>,
    /// The source had more than `cap` bytes.
    pub(crate) over_cap: bool,
    /// A decode error stopped the read with content left undecoded
    /// ([`decode_error_hides_content`]).
    pub(crate) undecoded: bool,
}

/// Like [`bounded_read`], but when `salvage` is set, a read error does not
/// discard the bytes decoded so far: it returns them, and says whether the
/// error left content undecoded. This is the scan-everything default: the
/// prefix is scanned, and a clean prefix of a damaged stream is not reported
/// as a clean member. With `salvage` false errors propagate, as in
/// [`bounded_read`].
// Dead only in a build with none of the formats that salvage a partial member;
// see `cap_prealloc` for why the feature list is not spelled out.
#[allow(dead_code)]
pub(crate) fn bounded_read_salvage<R: Read>(
    mut r: R,
    cap: u64,
    salvage: bool,
) -> Result<Salvaged, std::io::Error> {
    if !salvage {
        let (data, over_cap) = bounded_read(r, cap)?;
        return Ok(Salvaged {
            data,
            over_cap,
            undecoded: false,
        });
    }
    let limit = cap.saturating_add(1);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut undecoded = false;
    while (buf.len() as u64) < limit {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                undecoded = decode_error_hides_content(&e);
                break;
            }
        }
    }
    let over_cap = buf.len() as u64 > cap;
    if over_cap {
        buf.truncate(cap as usize);
    }
    Ok(Salvaged {
        data: buf,
        over_cap,
        undecoded,
    })
}

#[cfg(all(test, feature = "base64scan"))]
mod markup_payload_tests {
    use super::*;
    use base64::Engine as _;

    /// A PNG big enough to clear `MIN_RUN`, carrying a marker so the decode can
    /// be checked byte-for-byte rather than by length alone.
    fn png(marker: &[u8]) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend_from_slice(marker);
        v.extend_from_slice(&[0x5au8; 200]);
        v
    }

    fn b64(d: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(d)
    }

    /// A PE big enough for the executable scan's shortest run.
    fn pe(marker: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 1200];
        v[..2].copy_from_slice(b"MZ");
        v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        v[0x80..0x84].copy_from_slice(b"PE\0\0");
        v[0x100..0x100 + marker.len()].copy_from_slice(marker);
        v
    }

    fn wrapped(s: &str, width: usize) -> String {
        s.as_bytes()
            .chunks(width)
            .map(|l| std::str::from_utf8(l).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n  ")
    }

    #[test]
    fn payloads_read_in_blocks_come_back_as_from_memory() {
        use crate::source::{BlockCache, CHUNK};
        let mut doc = String::new();
        // Each payload placed across a chunk seam, some line-wrapped, some a
        // near miss.
        let payloads: Vec<String> = vec![
            format!("<img src=\"data:image/png;base64,{}\">", b64(&png(b"one"))),
            format!("<w:binData>{}</w:binData>", b64(&png(b"two!"))),
            format!("$b = \"{}\";", wrapped(&b64(&pe(b"three")), 76)),
            format!("x={}=", b64(&pe(b"four"))),
            // Not introduced, not an asset, too short.
            format!("plain {} text", b64(&png(b"five"))),
            format!("<p>{}</p>", b64(b"just some words, not an image at all, long enough to pass the run length check")),
            format!("<i>{}</i>", b64(&png(b"")[..40])),
        ];
        for (k, p) in payloads.iter().enumerate() {
            let seam = (k + 1) * CHUNK;
            let pad = seam.saturating_sub(doc.len() + p.len() / 2);
            doc.push_str(&".".repeat(pad));
            doc.push_str(p);
        }
        let data = doc.as_bytes();
        let cache =
            BlockCache::with_sizes(std::io::Cursor::new(data.to_vec()), 509, 8 * 509).unwrap();
        for cap in [1 << 20, 1199, 1200, 1201, 260, 64] {
            let want = markup_embedded_payloads(&data, cap);
            assert_eq!(
                markup_embedded_payloads(&cache, cap),
                want,
                "markup, cap {cap}"
            );
            let want_b64 = base64_payloads(&data, cap);
            assert_eq!(base64_payloads(&cache, cap), want_b64, "base64, cap {cap}");
            if cap == 1 << 20 {
                assert_eq!(want.len(), 2, "both introduced images");
                assert_eq!(want_b64.len(), 2, "both executables");
            }
        }
        // The cap is applied to what a run decodes to, before it is read.
        assert_eq!(base64_payloads(&data, 1199).len(), 0);
        assert_eq!(base64_payloads(&data, 1200).len(), 2);
    }

    #[test]
    fn a_data_uri_image_comes_back_byte_for_byte() {
        let want = png(b"marker-A");
        let page = format!("<img src=\"data:image/png;base64,{}\">", b64(&want));
        let got = markup_embedded_payloads(&page.as_bytes(), 1 << 20);
        assert_eq!(got, vec![want], "padding must not be dropped from the tail");
    }

    #[test]
    fn a_base64_element_body_comes_back_too() {
        // The shape a Word/Excel 2003 flat-XML document stores an image in.
        let want = png(b"marker-B");
        let doc = format!(
            "<w:binData w:name=\"image1.png\">{}</w:binData>",
            b64(&want)
        );
        assert_eq!(
            markup_embedded_payloads(&doc.as_bytes(), 1 << 20),
            vec![want]
        );
    }

    #[test]
    fn prose_and_unintroduced_runs_are_not_decoded() {
        let asset = b64(&png(b"marker-C"));
        // Same bytes, but not introduced by a `data:` URI or an element body.
        let loose = format!("some text {asset} more text");
        assert!(markup_embedded_payloads(&loose.as_bytes(), 1 << 20).is_empty());
        // Introduced, but decodes to nothing that is an asset.
        let junk = "A".repeat(400);
        let page = format!("<img src=\"data:text/plain;base64,{junk}\">");
        assert!(markup_embedded_payloads(&page.as_bytes(), 1 << 20).is_empty());
    }

    #[test]
    fn a_payload_over_the_cap_is_dropped_not_truncated() {
        let want = png(b"marker-D");
        let page = format!("<img src=\"data:image/png;base64,{}\">", b64(&want));
        assert!(
            markup_embedded_payloads(&page.as_bytes(), 16).is_empty(),
            "a truncated asset is worse than no asset: it would be scanned as \
             if complete"
        );
    }
}

// Fixtures are built with real encoders (flate2/tar/ruzstd/zip/cab), linked
// only with their format feature.
#[cfg(all(test, feature = "all-formats"))]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::{Cursor, Write};

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// A gzip stream with a deliberately corrupted CRC-32 trailer (the 4 bytes
    /// before the final 4-byte ISIZE), simulating a smuggled/corrupted payload.
    fn gz_bad_crc(data: &[u8]) -> Vec<u8> {
        let mut g = gz(data);
        let n = g.len();
        g[n - 8] ^= 0xff; // flip the CRC-32 → flate2 errors on the trailer
        g
    }

    #[test]
    fn gzip_bad_crc_is_still_scanned_by_default() {
        let payload = b"malware payload hidden behind a wrong gzip CRC";
        let mut budget = Budget::new(Limits::default());
        assert!(!budget.should_verify_checksums(), "verify must default off");
        // Scan-everything default: the corrupted CRC must NOT hide the payload.
        let entries = extract(Format::Gzip, &gz_bad_crc(payload), &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, payload, "payload must survive a bad CRC");
    }

    #[test]
    fn verify_flag_is_inert_without_the_checksums_feature() {
        let mut b = Budget::new(Limits::default());
        b.set_verify_checksums(true);
        // The runtime flag only takes effect when the feature is compiled in.
        assert_eq!(b.should_verify_checksums(), cfg!(feature = "checksums"));
    }

    /// With the `checksums` feature AND verification enabled, a wrong CRC is a
    /// hard error (extract-for-real mode). Only runs under `--features checksums`.
    #[cfg(feature = "checksums")]
    #[test]
    fn gzip_bad_crc_rejected_when_verifying() {
        let payload = b"corrupt file, integrity mode";
        // Sanity: a *valid* gzip is fine with verification on.
        let mut b = Budget::new(Limits::default());
        b.set_verify_checksums(true);
        assert_eq!(
            extract(Format::Gzip, &gz(payload), &mut b).unwrap()[0].data,
            payload
        );
        // A bad CRC now surfaces as an error, not silently salvaged.
        let mut b = Budget::new(Limits::default());
        b.set_verify_checksums(true);
        assert!(extract(Format::Gzip, &gz_bad_crc(payload), &mut b).is_err());
    }

    #[test]
    fn ratio_guard_ignores_small_high_ratio_output() {
        // A 1 KB-compressed blank scanned page expanding to 1 MB (ratio
        // ~1000:1) is ordinary content, not a bomb: below the floor the
        // absolute caps already bound it, so the ratio must not trip.
        let b = Budget::new(Limits::default());
        assert!(ratio_guard(1021, 1_030_656, &b).is_ok());
        assert!(ratio_guard(100, 90_000, &b).is_ok());
    }

    #[test]
    fn ratio_guard_still_trips_past_the_floor() {
        // The same shape at bomb scale must still trip loudly: past the floor
        // the ratio means resource exhaustion, not a blank page.
        let b = Budget::new(Limits::default());
        assert!(ratio_guard(1021, 100 * 1024 * 1024, &b).is_err());
        assert!(ratio_guard(1021, RATIO_FLOOR_BYTES, &b).is_err());
    }

    /// Pins the floor at SHIPPED settings. Every other bomb test overrides
    /// `max_compression_ratio`, so before this one nothing exercised the guard
    /// as deployed: the floor could have been any value, or ineffective, and
    /// the suite would have stayed green.
    #[test]
    fn ratio_guard_boundary_at_default_limits() {
        let b = Budget::new(Limits::default());
        assert_eq!(
            b.limits().max_compression_ratio,
            1000,
            "the shipped ratio; this test is about the default configuration"
        );
        // One byte under the floor is exempt no matter how extreme the ratio...
        assert!(ratio_guard(1, RATIO_FLOOR_BYTES - 1, &b).is_ok());
        // ...and the guard resumes exactly at it.
        assert!(ratio_guard(1, RATIO_FLOOR_BYTES, &b).is_err());
        // The 1 MB blank page that the floor exists for keeps 4x of room.
        assert!(ratio_guard(1021, 1_030_656, &b).is_ok());
        assert_eq!(RATIO_FLOOR_BYTES, 4 * 1024 * 1024);
        // A ratio at or under the limit is fine even well past the floor, so
        // the floor only ever relaxes the check, never tightens it.
        assert!(ratio_guard(1024 * 1024, 64 * 1024 * 1024, &b).is_ok());
    }

    fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut b = ::tar::Builder::new(&mut buf);
            for (name, data) in members {
                let mut h = ::tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, *data).unwrap();
            }
            b.finish().unwrap();
        }
        buf
    }

    fn cab_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = ::cab::CabinetBuilder::new();
        {
            let folder = b.add_folder(::cab::CompressionType::None);
            for (name, _) in members {
                folder.add_file(*name);
            }
        }
        let mut w = b.build(Cursor::new(Vec::new())).unwrap();
        for (_, data) in members {
            let mut fw = w.next_file().unwrap().unwrap();
            fw.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn cab_with_corrupted_total_size_is_recovered() {
        // A well-formed cabinet whose CFHEADER `cbCabinet` (bytes 8..12) is
        // overwritten with 0xFFFFFFFF, an evasion that defeats strict parsers.
        // The field is not trusted, so the member is still extracted.
        let mut blob = cab_of(&[("payload.bin", b"INNER-CAB-PAYLOAD")]);
        blob[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Cab, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"INNER-CAB-PAYLOAD");
    }

    #[test]
    fn walk_stops_early_and_threads_budget() {
        // A tar with three members; the visitor stops at the second. The third
        // must never be decoded/visited (early-exit), and the visitor sees the
        // shared budget so it can recurse.
        let blob = tar_of(&[("a", b"first"), ("b", b"second"), ("c", b"third")]);
        let mut budget = Budget::new(Limits::default());
        let mut seen: Vec<String> = Vec::new();
        let stopped = walk(Format::Tar, &blob, &mut budget, &mut |_, content, b| {
            // The budget is real (the member was just counted against it).
            assert!(b.files > 0);
            let mut data = Vec::new();
            if let Some(Member::Stream(r)) = content {
                r.read_to_end(&mut data).unwrap();
            }
            seen.push(String::from_utf8_lossy(&data).into_owned());
            (data == b"second").then_some("hit-b")
        })
        .unwrap();
        assert_eq!(stopped, Some("hit-b"));
        assert_eq!(seen, vec!["first", "second"]); // "third" never visited
    }

    #[test]
    fn extract_collects_same_as_streaming() {
        let blob = tar_of(&[("a", b"one"), ("b", b"two")]);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Tar, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"one");
        assert_eq!(entries[1].data, b"two");
    }

    #[test]
    fn gzip_roundtrip() {
        let payload = b"hello exav inside gzip";
        let blob = gz(payload);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Gzip, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn gzip_multi_member_concatenated() {
        // A gzip file can be several concatenated members; the payload may live
        // in a later one. The extractor must decode ALL members (MultiGzDecoder),
        // not just the first: a real FN source for some packagers.
        let mut blob = gz(b"header-member-only");
        blob.extend_from_slice(&gz(b"PAYLOAD-with-eicar-marker-X5O!"));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Gzip, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        // Both members concatenated into one logical stream.
        assert_eq!(
            entries[0].data,
            b"header-member-onlyPAYLOAD-with-eicar-marker-X5O!"
        );
    }

    #[test]
    fn gzip_bomb_trips_ratio() {
        let blob = gz(&vec![0u8; 50 * 1024 * 1024]);
        let mut budget = Budget::new(Limits {
            max_compression_ratio: 100,
            ..Default::default()
        });
        let err = extract(Format::Gzip, &blob, &mut budget).unwrap_err();
        assert!(err.reason.contains("ratio"), "got: {}", err.reason);
    }

    #[test]
    fn total_bytes_budget_enforced() {
        let blob = gz(&vec![b'A'; 4096]);
        let mut budget = Budget::new(Limits {
            max_extracted_bytes: 1024,
            max_compression_ratio: u64::MAX,
            ..Default::default()
        });
        let err = extract(Format::Gzip, &blob, &mut budget).unwrap_err();
        assert!(err.reason.contains("exceeds budget") || err.reason.contains("extracted"));
    }

    // Regression for the "many members each allocating before accounting"
    // OOM (review finding C3): the total budget must bound the sum of all
    // members, not just trip after the fact.
    #[test]
    fn many_members_bounded_by_total() {
        let big = vec![b'X'; 200_000];
        let members: Vec<(&str, &[u8])> = (0..50).map(|_| ("m", big.as_slice())).collect();
        let blob = tar_of(&members);
        // total budget only allows ~3 members' worth.
        let mut budget = Budget::new(Limits {
            max_extracted_bytes: 600_000,
            max_buffer_bytes: 200_000,
            max_compression_ratio: u64::MAX,
            ..Default::default()
        });
        let err = extract(Format::Tar, &blob, &mut budget).unwrap_err();
        assert!(err.reason.contains("budget") || err.reason.contains("extracted"));
        // never accounted more than the cap (+ at most one in-flight member)
        assert!(budget.total_out <= 600_000);
    }

    #[test]
    fn bzip2_roundtrip() {
        // Fixed bzip2 stream of "hello exav inside bzip2" (bzip2-rs decodes only).
        let blob: &[u8] = &[
            66, 90, 104, 57, 49, 65, 89, 38, 83, 89, 213, 127, 182, 220, 0, 0, 5, 25, 128, 64, 0,
            16, 0, 54, 101, 201, 80, 32, 0, 49, 76, 0, 19, 66, 154, 105, 163, 77, 168, 242, 145,
            94, 233, 129, 65, 248, 112, 129, 150, 100, 114, 190, 46, 228, 138, 112, 161, 33, 170,
            255, 109, 184,
        ];
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Bzip2, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"hello exav inside bzip2");
    }

    #[test]
    fn bzip2_magic_rejects_false_positives() {
        // A genuine stream (BZh9 + pi block magic) is detected...
        let real: &[u8] = &[
            66, 90, 104, 57, 49, 65, 89, 38, 83, 89, 213, 127, 182, 220, 0, 0,
        ];
        assert_eq!(detect(&real), Some(Format::Bzip2));
        // ...but a coincidental `BZh#` run in binary data (as carved out of an ISO
        // at offset 343598: `BZh3` then `1h1H…`, not the block magic) is not. It
        // must not be treated as bzip2 and reported UNSCANNABLE.
        assert_eq!(detect(b"BZh31h1HDataHere....."), None);
        assert_eq!(detect(b"BZh4kUPHgo........."), None);
        // Truncated below the magic window → not enough to confirm → not bzip2.
        assert_eq!(detect(b"BZh9"), None);
    }

    #[test]
    fn cab_magic_rejects_false_positives() {
        // Real cabinet: MSCF + zero reserved1.
        let real = b"MSCF\x00\x00\x00\x00\x00\x10\x00\x00";
        assert_eq!(detect(real), Some(Format::Cab));
        // Coincidental `MSCF` run in binary data (as carved out of an ISO at
        // offset 4747707: `MSCF` then `LB1S…`, nonzero reserved1) → not a cabinet.
        assert_eq!(detect(b"MSCFLB1S6GBcextra"), None);
        assert_eq!(detect(b"MSCF"), None);
    }

    /// `60 EA` is two bytes, so about one object in 65,536 starts with it by
    /// chance, and reading such an object as a damaged ARJ reports it
    /// `UNSCANNABLE`. The main header carries a CRC-32 that settles it.
    #[cfg(feature = "arj")]
    #[test]
    fn arj_magic_rejects_false_positives() {
        let real: &[u8] = include_bytes!("../tests/fixtures/sample.arj");
        assert_eq!(detect(&real), Some(Format::Arj));
        let mut bad = real.to_vec();
        bad[10] ^= 0xff; // inside the main header
        assert_eq!(detect(&bad.as_slice()), None);
        assert_eq!(detect(b"\x60\xea\x10\x00random bytes after it"), None);
        assert_eq!(detect(b"\x60\xea"), None);
    }

    #[cfg(feature = "base64scan")]
    #[test]
    fn base64_payloads_extracts_embedded_executable() {
        use base64::Engine;
        // A minimal but valid PE (MZ + e_lfanew → "PE\0\0"), padded so its base64
        // run exceeds the minimum length.
        let mut pe = vec![0u8; 2048];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\x00\x00");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&pe);
        // Embedded as a PowerShell-style string assignment inside script text.
        let carrier = format!("$PEBytes = \"{b64}\"\nInvoke-Something $PEBytes\n");
        let got = base64_payloads(&carrier.as_bytes(), u64::MAX);
        assert_eq!(got.len(), 1, "should recover the one embedded PE");
        assert!(got[0].starts_with(b"MZ"));
        assert_eq!(&got[0][0x40..0x44], b"PE\x00\x00");

        // A long base64 run that decodes to plain text (no exec magic) is ignored.
        let txt = base64::engine::general_purpose::STANDARD.encode(vec![b'A'; 2048]);
        assert!(base64_payloads(&format!("x=\"{txt}\"").as_bytes(), u64::MAX).is_empty());
        // Too-short a run is never trial-decoded.
        assert!(base64_payloads(b"var x = \"aGVsbG8gd29ybGQ=\"", u64::MAX).is_empty());
    }

    #[cfg(feature = "base64scan")]
    #[test]
    fn executable_payload_rejects_bare_mz() {
        // `MZ` without a valid PE header at e_lfanew is not an executable payload.
        let mut d = vec![0u8; 128];
        d[0] = b'M';
        d[1] = b'Z';
        assert!(!is_executable_payload(&d));
        d[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        d[0x40..0x44].copy_from_slice(b"PE\x00\x00");
        assert!(is_executable_payload(&d));
    }

    #[test]
    fn gzip_magic_rejects_false_positives() {
        // Real gzip: 1f 8b + deflate CM (08) + a flag byte with zero reserved bits.
        assert_eq!(
            detect(&[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0]),
            Some(Format::Gzip)
        );
        assert_eq!(
            detect(&[0x1f, 0x8b, 0x08, 0x08, 0, 0, 0, 0]),
            Some(Format::Gzip)
        ); // FNAME set
           // Coincidental `1f 8b` in binary data with a non-deflate CM or reserved
           // flag bits set → not gzip (would otherwise fail inflate → UNSCANNABLE).
        assert_eq!(detect(&[0x1f, 0x8b, 0x99, 0xff]), None); // CM != 8
        assert_eq!(detect(&[0x1f, 0x8b, 0x08, 0xe0]), None); // reserved flag bits set
        assert_eq!(detect(&[0x1f, 0x8b]), None); // too short
    }

    #[test]
    fn bzip2_multi_stream_concatenated() {
        // pbzip2 concatenates bzip2 streams; the extractor must decode all of
        // them (the same FN class as multi-member gzip). Two copies of the fixed
        // stream → the content twice.
        let one: &[u8] = &[
            66, 90, 104, 57, 49, 65, 89, 38, 83, 89, 213, 127, 182, 220, 0, 0, 5, 25, 128, 64, 0,
            16, 0, 54, 101, 201, 80, 32, 0, 49, 76, 0, 19, 66, 154, 105, 163, 77, 168, 242, 145,
            94, 233, 129, 65, 248, 112, 129, 150, 100, 114, 190, 46, 228, 138, 112, 161, 33, 170,
            255, 109, 184,
        ];
        let mut blob = one.to_vec();
        blob.extend_from_slice(one);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Bzip2, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].data,
            b"hello exav inside bzip2hello exav inside bzip2"
        );
    }

    #[test]
    fn xz_multi_stream_concatenated() {
        // pixz/parallel-xz concatenate xz streams; our decoder handles them.
        // Fixture: cat a.xz b.xz  (generated by tests/fixtures/xz/fixture_gen.sh)
        let blob = include_bytes!("../tests/fixtures/xz/multi.xz");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Xz, blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"first-xz second-X5O!");
    }

    #[test]
    fn xz_roundtrip_and_bomb() {
        let payload = b"hello exav inside xz";
        let blob = include_bytes!("../tests/fixtures/xz/simple.xz");
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Xz, blob, &mut budget).unwrap();
        assert_eq!(entries[0].data, payload);

        // A compressible bomb must trip the total-bytes cap, not decode fully.
        let bomb = include_bytes!("../tests/fixtures/xz/bomb.xz");
        let mut budget = Budget::new(Limits {
            max_extracted_bytes: 1024,
            max_compression_ratio: u64::MAX,
            ..Default::default()
        });
        let err = extract(Format::Xz, bomb, &mut budget).unwrap_err();
        assert!(err.reason.contains("budget") || err.reason.contains("extracted"));
    }

    #[test]
    fn zstd_roundtrip() {
        let payload = b"hello exav inside zstd";
        let blob = zstd_of(payload);
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Zstd, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn zstd_bomb_trips_ratio() {
        let mut w =
            ruzstd::encoding::FrameCompressor::new(ruzstd::encoding::CompressionLevel::Fastest);
        let zeros = [0u8; 4096];
        let mut source = &zeros[..];
        let mut out = Vec::new();
        w.set_source(&mut source);
        w.set_drain(&mut out);
        w.compress();
        let mut budget = Budget::new(Limits {
            max_extracted_bytes: 1024,
            max_compression_ratio: u64::MAX,
            ..Default::default()
        });
        let err = extract(Format::Zstd, &out, &mut budget).unwrap_err();
        assert!(err.reason.contains("budget") || err.reason.contains("extracted"));
    }

    #[test]
    fn cab_roundtrip() {
        // Build a small uncompressed cabinet, then extract it.
        let mut builder = ::cab::CabinetBuilder::new();
        let folder = builder.add_folder(::cab::CompressionType::None);
        folder.add_file("payload.txt");
        let mut blob = Vec::new();
        let mut writer = builder.build(Cursor::new(&mut blob)).unwrap();
        while let Some(mut w) = writer.next_file().unwrap() {
            std::io::Write::write_all(&mut w, b"hello exav inside cab").unwrap();
        }
        writer.finish().unwrap();

        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Cab, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "payload.txt");
        assert_eq!(entries[0].data, b"hello exav inside cab");
    }

    fn eicar() -> &'static [u8] {
        crate::eicar()
    }

    fn has_eicar(entries: &[Entry]) -> bool {
        entries
            .iter()
            .any(|e| e.data.windows(4).any(|w| w == b"X5O!"))
    }

    #[test]
    fn ole_streams_extracted() {
        // Build an OLE2/CFB with a stream holding EICAR, then extract it.
        let mut buf = Cursor::new(Vec::new());
        {
            let mut comp = cfb::CompoundFile::create(&mut buf).unwrap();
            comp.create_storage("Macros").unwrap();
            let mut s = comp.create_stream("Macros/Module1").unwrap();
            std::io::Write::write_all(&mut s, eicar()).unwrap();
        }
        let data = buf.into_inner();
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Ole, &data, &mut budget).unwrap();
        assert!(has_eicar(&entries), "EICAR not found in OLE streams");
    }

    /// Build a minimal but well-formed PDF (catalog → pages → page → content
    /// stream) with a byte-accurate xref table, so the parser loads it and the
    /// stream object is extractable. No external PDF dependency.
    fn minimal_pdf_with_stream(content: &[u8]) -> Vec<u8> {
        let mut pdf = Vec::new();
        let mut off = [0usize; 5]; // 1-indexed object offsets
        pdf.extend_from_slice(b"%PDF-1.5\n");
        off[1] = pdf.len();
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        off[2] = pdf.len();
        pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        off[3] = pdf.len();
        pdf.extend_from_slice(
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n",
        );
        off[4] = pdf.len();
        pdf.extend_from_slice(
            format!("4 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes(),
        );
        pdf.extend_from_slice(content);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        let xref_off = pdf.len();
        pdf.extend_from_slice(b"xref\n0 5\n0000000000 65535 f \n");
        for o in &off[1..=4] {
            pdf.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n")
                .as_bytes(),
        );
        pdf
    }

    #[test]
    fn pdf_stream_extracted() {
        let pdf = minimal_pdf_with_stream(eicar());
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Pdf, &pdf, &mut budget).unwrap();
        assert!(has_eicar(&entries), "EICAR not found in PDF streams");
    }

    #[test]
    fn email_attachment_extracted() {
        // base64(EICAR) attachment in a multipart message.
        let b64 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=";
        let msg = format!(
            "From: a@b\r\nTo: c@d\r\nSubject: x\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=BB\r\n\r\n\
             --BB\r\nContent-Type: text/plain\r\n\r\nhello\r\n\
             --BB\r\nContent-Type: application/octet-stream\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--BB--\r\n"
        );
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Email, &msg.as_bytes(), &mut budget).unwrap();
        assert!(has_eicar(&entries), "EICAR not found in email parts");
    }

    #[test]
    fn file_count_capped() {
        let members: Vec<(&str, &[u8])> = (0..20).map(|_| ("e", b"x".as_slice())).collect();
        let blob = tar_of(&members);
        let mut budget = Budget::new(Limits {
            max_members: 5,
            ..Default::default()
        });
        let err = extract(Format::Tar, &blob, &mut budget).unwrap_err();
        assert!(err.reason.contains("file count"));
    }

    #[test]
    fn sevenz_roundtrip() {
        use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
        let payload = b"hello exav inside 7zip archive";
        let mut sink = Cursor::new(Vec::new());
        {
            let mut w = ArchiveWriter::new(&mut sink).unwrap();
            w.push_archive_entry(
                ArchiveEntry::new_file("payload.bin"),
                Some(Cursor::new(payload.to_vec())),
            )
            .unwrap();
            w.finish().unwrap();
        }
        let blob = sink.into_inner();
        assert_eq!(detect(&blob), Some(Format::SevenZip));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::SevenZip, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, payload);
    }

    /// Build a minimal single-file ISO 9660 image in memory: header sectors,
    /// a primary volume descriptor (sector 16) pointing at a root directory
    /// (sector 17) with one file record, and the file's data (sector 18).
    fn iso_with_file(name: &str, content: &[u8]) -> Vec<u8> {
        const S: usize = 2048;
        let mut img = vec![0u8; 19 * S + content.len().div_ceil(S) * S];
        // --- Primary Volume Descriptor at sector 16 ---
        let pvd = 16 * S;
        img[pvd] = 1; // type = primary
        img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        img[pvd + 6] = 1; // version
                          // Root directory record at PVD+156 (length 34).
        let rd = pvd + 156;
        img[rd] = 34; // record length
        img[rd + 2..rd + 6].copy_from_slice(&17u32.to_le_bytes()); // extent LBA (LE)
        img[rd + 10..rd + 14].copy_from_slice(&(S as u32).to_le_bytes()); // dir size
        img[rd + 25] = 0x02; // flags: directory
        img[rd + 32] = 1; // name len
        img[rd + 33] = 0; // name "\0" (self)
                          // --- Root directory at sector 17 ---
        let dir = 17 * S;
        let mut p = dir;
        // "." record
        img[p] = 34;
        img[p + 2..p + 6].copy_from_slice(&17u32.to_le_bytes());
        img[p + 10..p + 14].copy_from_slice(&(S as u32).to_le_bytes());
        img[p + 25] = 0x02;
        img[p + 32] = 1;
        img[p + 33] = 0;
        p += 34;
        // ".." record
        img[p] = 34;
        img[p + 2..p + 6].copy_from_slice(&17u32.to_le_bytes());
        img[p + 10..p + 14].copy_from_slice(&(S as u32).to_le_bytes());
        img[p + 25] = 0x02;
        img[p + 32] = 1;
        img[p + 33] = 1;
        p += 34;
        // file record
        let nm = name.as_bytes();
        let rec_len = 33 + nm.len() + (1 - nm.len() % 2); // padded to even
        img[p] = rec_len as u8;
        img[p + 2..p + 6].copy_from_slice(&18u32.to_le_bytes()); // file at sector 18
        img[p + 10..p + 14].copy_from_slice(&(content.len() as u32).to_le_bytes());
        img[p + 25] = 0; // flags: file
        img[p + 32] = nm.len() as u8;
        img[p + 33..p + 33 + nm.len()].copy_from_slice(nm);
        // --- file content at sector 18 ---
        img[18 * S..18 * S + content.len()].copy_from_slice(content);
        img
    }

    #[test]
    fn iso9660_single_file() {
        let payload = b"malware-marker inside an ISO image";
        let img = iso_with_file("EVIL.BIN;1", payload);
        assert_eq!(detect(&img), Some(Format::Iso));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Iso, &img, &mut budget).unwrap();
        assert_eq!(entries.len(), 1, "one file in the ISO");
        assert_eq!(entries[0].name, "EVIL.BIN"); // ";1" version suffix stripped
        assert_eq!(entries[0].data, payload);
    }

    /// A member with a local header and NO central-directory entry is the
    /// classic way to hide one: the directory is what most readers walk, and
    /// the target extracts it anyway.
    #[test]
    fn a_member_hidden_from_the_central_directory_is_extracted() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/zip/orphan_local.zip");
        let blob = std::fs::read(&path).expect("fixture reads");
        let mut budget = Budget::new(Limits::default());
        let names: Vec<String> = extract(Format::Zip, &blob, &mut budget)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["benign.txt", "hidden.txt"]);
    }

    fn zstd_of(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut source = data;
        let mut compressor =
            ruzstd::encoding::FrameCompressor::new(ruzstd::encoding::CompressionLevel::Fastest);
        compressor.set_source(&mut source);
        compressor.set_drain(&mut out);
        compressor.compress();
        out
    }

    #[test]
    fn lzip_roundtrip() {
        let payload = b"hello exav inside lzip";
        let blob = include_bytes!("../tests/fixtures/lzip_simple.lz");
        assert_eq!(detect(blob), Some(Format::Lzip));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Lzip, blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, payload);
    }
}

/// An LZMA dictionary size clamped to what the caller's budget allows.
///
/// The declared size comes straight out of the file and the decoder allocates it
/// UP FRONT, before decompressing a byte, so an attacker chooses how much
/// memory exav commits. Measured: a 766 KB NSIS installer declaring a 1.5 GB
/// dictionary, which aborted the process under the daemon's per-job address-space
/// limit. Under the daemon that abort closes the client connection with no reply,
/// which a client reads as a clean scan.
///
/// Clamping is free on real streams: LZMA only ever looks back into bytes it has
/// already produced, so a dictionary larger than the output cannot be consulted.
/// The floor keeps a nonsense-small declaration from breaking a legitimate one.
// Dead only in a build with none of the LZMA-bearing formats (swf, egg, nsis,
// zip, 7z); see `cap_prealloc` for why the feature list is not spelled out.
#[allow(dead_code)]
pub(crate) fn bounded_dict(declared: u32, cap: u64) -> u32 {
    const MIN_DICT: u32 = 1 << 12;
    declared.min(cap.min(u32::MAX as u64) as u32).max(MIN_DICT)
}
