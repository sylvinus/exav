//! Archive extraction with decompression-bomb limits.
//!
//! Extraction is bounded by a [`Budget`] (total output bytes, file count,
//! recursion depth, compression ratio). Hitting a bound returns [`LimitHit`],
//! which the caller maps to `LimitsExceeded`.
//!
//! The budget is reserved *before* each member is read, and each read is
//! capped to the bytes still remaining, so peak memory across an archive
//! (and across nested archives sharing the budget) never exceeds
//! `max_extracted_bytes`.
//!
//! # `Archive<R>` — lazy member-by-member access
//!
//! The primary API for most callers.  [`Archive::open`] detects the container
//! format and parses format-specific headers (e.g. the ZIP central directory).
//! Members are then extracted one at a time via [`Archive::extract_next`] under
//! a shared [`Budget`].  For seekable formats (ZIP) only the central directory
//! is read up front; individual members are fetched on demand.  For all other
//! formats the data is buffered on open and members are extracted lazily from
//! the buffer.
//!
//! ```rust,no_run
//! use std::io::Cursor;
//! use exav_unpack::{Archive, Budget, Limits};
//!
//! # fn example(data: &[u8]) -> Result<(), exav_unpack::LimitHit> {
//! let mut archive = Archive::open(Cursor::new(data))?;
//! println!("format: {:?}", archive.format());
//!
//! // Pre-parsed member metadata (free for ZIP).
//! for m in archive.list() {
//!     println!("  {} ({} bytes)", m.name, m.uncompressed_size);
//! }
//!
//! // Extract members one at a time.
//! let mut budget = Budget::new(Limits::default());
//! while let Some(entry) = archive.extract_next(&mut budget)? {
//!     println!("{}: {} bytes", entry.name, entry.data.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # `extract_each` — visitor-based streaming
//!
//! Lower-level API for callers that own the extraction loop.  [`extract_each`]
//! decodes one member at a time and hands it to a visitor closure, which scans
//! it, recurses into it, and drops it before the next member is decoded.  Peak
//! memory is ~one member, and a visitor that returns `Some(r)` halts extraction
//! immediately — remaining members are never decompressed.
//!
//! # Safety
//!
//! This crate contains **no `unsafe` code** — the entire extraction layer,
//! including the vendored PPMd7 sub-allocator (`formats/ppmd7/`), is 100% safe
//! Rust over a bounds-checked byte arena. The forbid below is enforced
//! crate-wide.
#![forbid(unsafe_code)]

use std::io::{Read, Seek};

#[doc(hidden)]
pub mod formats;
use formats::*;

mod stream;
pub mod volume;
pub use stream::{
    is_budget_overflow, is_streamable, stream_members, BudgetReader, MemberMeta, StreamVisit,
};
// RAR decompression primitives, exposed for the rar3/rar5 examples + tests.
#[cfg(feature = "zip")]
#[doc(hidden)]
#[cfg(feature = "pdf")]
pub use formats::has_obfuscated_name_object;

/// Count of overlapping ZIP local file records — the signal behind ClamAV's
/// `Heuristics.Zip.OverlappingFiles`. Zero for any well-formed archive.
#[cfg(feature = "zip")]
pub use formats::zip::overlapping_local_records;

/// Without the `zip` feature there is no ZIP parser, so no ZIP heuristic can
/// fire; answering zero keeps callers free of feature gates.
#[cfg(not(feature = "zip"))]
pub fn overlapping_local_records(_data: &[u8]) -> usize {
    0
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
/// is not an image. Pure parsing — no decoding, no allocation of pixel data.
pub use formats::mediacheck::broken_media_alert;

/// Without the `pdf` feature there is no PDF parser, so no PDF heuristic can
/// fire. Answering `false` keeps every caller free of feature gates — the
/// alternative left the documented `--no-default-features --features zip` build
/// (the one the WASM size figures come from) failing to compile at all.
#[cfg(not(feature = "pdf"))]
pub fn has_obfuscated_name_object(_data: &[u8]) -> bool {
    false
}
#[cfg(feature = "zip")]
pub use formats::ZipMembers;
#[cfg(feature = "rar")]
#[doc(hidden)]
pub use formats::{unpack29, unpack50, window_size_from_comp_info};

/// Limits governing recursive extraction.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_recursion: u32,
    /// Cap on the number of members visited across the whole recursive walk.
    ///
    /// exav's default is deliberately HIGHER than ClamAV's 10,000, because the
    /// two count different populations for the same file. exav descends into
    /// nested archives that ClamAV does not, so it sees strictly more countable
    /// objects — and adopting ClamAV's number would buy less coverage under the
    /// same-looking setting.
    ///
    /// Measured on a live example: the `litellm` PyPI source tarball holds 2,794
    /// tar members, 27 of which are `.whl` files — ZIP archives with their own
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
    /// moment — which makes it, not [`Self::max_buffer_bytes`], the limit that
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
    /// *produces*). Bounds re-scanning bombs — e.g. a disk image full of
    /// embedded PEs, where the same suffix is carved and matched at many
    /// offsets and depths — without limiting the legitimate one-pass scan of a
    /// large file. Deterministic, so it trips identically on every machine
    /// (unlike a wall-clock deadline).
    pub max_scanned_bytes: u64,
    /// Formats this scan will open, or `None` for every format compiled in.
    ///
    /// A compile-time feature decides what a *binary* can do; this decides what
    /// a *call* may do, so one build can serve a caller that accepts archives
    /// and a caller that does not. A deployment that only ever expects ZIP can
    /// say so without maintaining its own build.
    ///
    /// A format excluded here is REPORTED, never skipped — the member comes
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
            // memory bound — streamed members are scanned without being held in
            // RAM (capped separately by `max_buffer_bytes`/`deep_analysis_max`),
            // so this can be generous: it exists only to stop re-scanning bombs
            // and runaway scan time, and lets a multi-gigabyte member be fully
            // scanned.
            max_scanned_bytes: 10 * 1024 * 1024 * 1024,
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
    // Running counters — mutated only through `charge_scan`/`count_entry`/
    // `reserve`/`commit` so the bomb-defense bounds can't be bypassed by a caller
    // writing them directly. Crate-private for that reason.
    pub(crate) files: u64,
    pub(crate) total_out: u64,
    /// Cumulative bytes fed to the matching core (see [`Limits::max_scanned_bytes`]).
    pub(crate) scanned: u64,
    /// Candidate passwords tried (in order) when decrypting an encrypted member
    /// (ZIP ZipCrypto/AES today). Empty by default — an encrypted member with no
    /// password yields an `Entry::unsupported(encrypted=true, …)` so the scanner
    /// reports `PasswordProtected`. The pool is the union of any `.pwdb` file and
    /// the runtime `ScanOptions::passwords`, threaded down by exav-core.
    pub passwords: Vec<String>,
    /// Verify container checksums (CRCs) during extraction. **Off by default**:
    /// a malware scanner scans decompressed content regardless of integrity
    /// metadata — a wrong CRC must never stop a member's bytes from being
    /// scanned (that would let an attacker downgrade a detection by flipping a
    /// checksum byte). This matches ClamAV, which ignores CRCs for scanning.
    /// Only has effect with the `checksums` Cargo feature compiled in; without
    /// it, checksums are never verified regardless of this flag.
    pub(crate) verify_checksums: bool,
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
            passwords: Vec::new(),
            verify_checksums: false,
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
    /// scans decompressed content even if a CRC fails — the scanner default.
    pub fn set_verify_checksums(&mut self, verify: bool) -> &mut Self {
        self.verify_checksums = verify;
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
    /// retained, so it is bounded by how much may still be fed to the matcher —
    /// a *processing* limit — not by the per-member *buffer* cap
    /// ([`Self::reserve`]). This is what decouples "how large a member we will
    /// scan" from "how much we hold in RAM at once".
    pub fn remaining_scan(&self) -> u64 {
        self.limits.max_scanned_bytes.saturating_sub(self.scanned)
    }

    /// Count one archive member toward the file-count budget. Called for
    /// every entry encountered — including directories and skipped entries —
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
                "extracted bytes > {}",
                self.limits.max_extracted_bytes
            )));
        }
        Ok(remaining.min(self.limits.max_buffer_bytes))
    }

    pub fn commit(&mut self, n: u64) {
        self.total_out = self.total_out.saturating_add(n);
    }
}

/// An extraction stopped early. `corrupt` picks the verdict: `true` for
/// undecodable content (malformed/truncated structure, or a decoder that
/// panicked → `Unscannable`); `false` for a resource bound being hit
/// (size/recursion/ratio/scan budget → `LimitsExceeded`). Carries the
/// human-readable reason for the report.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{reason}")]
pub struct LimitHit {
    pub reason: String,
    pub corrupt: bool,
    /// Which budget stopped the scan. Carried as a *type*, not inferred from
    /// `reason`: a caller that needs to name the limit (the ClamAV-compatible
    /// `Heuristics.Limits.Exceeded.*` alerts) must not have to pattern-match
    /// prose, which drifts the moment a message is reworded.
    pub kind: LimitKind,
}

/// The budget that stopped a scan, named the way the signature format names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
    /// Not a budget — the input was malformed. Kept in the same enum so every
    /// `LimitHit` has a kind and nothing has to guess.
    #[default]
    Corrupt,
}

impl LimitHit {
    /// A resource-budget stop → `LimitsExceeded`.
    fn new(reason: String) -> Self {
        Self {
            reason,
            corrupt: false,
            kind: LimitKind::MaxFileSize,
        }
    }

    /// A resource-budget stop, naming which budget it was.
    fn of_kind(kind: LimitKind, reason: String) -> Self {
        Self {
            reason,
            corrupt: false,
            kind,
        }
    }
    /// An undecodable-content stop → `Unscannable`: malformed/truncated input, or
    /// a decoder panic contained at the extraction boundary.
    pub(crate) fn corrupt(reason: String) -> Self {
        Self {
            reason,
            corrupt: true,
            kind: LimitKind::Corrupt,
        }
    }
}

/// One extracted member.
#[derive(Debug, Clone)]
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
}

impl Entry {
    /// An entry whose compressed size is unknown (use the decompressed length)
    /// and which is not encrypted — the common case.
    pub fn new(name: String, data: Vec<u8>) -> Self {
        Entry {
            comp_size: data.len() as u64,
            encrypted: false,
            unsupported: None,
            name,
            data,
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
            data: Vec::new(),
            comp_size,
            encrypted,
            unsupported: Some(reason),
        }
    }
}

/// Metadata for one archive member (no data loaded).
#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub name: String,
    pub index: usize,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub encrypted: bool,
}

/// A container/archive format this crate can extract embedded files from
/// (archives plus structured documents: OLE2, PDF, MIME email).
// `Ord`/`Hash` so a caller can hold a set of formats — see
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
    /// RAR4/RAR5 archive (stored members; compressed methods are not decoded).
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
    /// is always defined (like `Iso`/`Xar`) so downstream matches stay
    /// exhaustive regardless of which crate enabled the feature; only the
    /// detector and extractor are gated.
    Vhd,
    /// Unix `compress` (`.Z`), LZW.
    Lzw,
    /// QEMU copy-on-write disk image.
    Qcow2,
    /// VMware virtual disk (sparse or streamOptimized).
    Vmdk,
    /// Microsoft VHDX — the modern Windows virtual disk.
    Vhdx,
    /// Windows Imaging Format (`.wim`/`.esd`) — chunk-compressed file resources.
    Wim,
    /// LZ4 frame (`.lz4`).
    Lz4,
    /// ARC / PKARC / PAK archive — the pre-ZIP SEA format.
    Arc,
    /// ACE archive — recognised so it is reported, never decoded.
    Ace,
    StuffIt,
    /// ALZ archive (ESTsoft ALZip) — recognised so it is reported, not decoded.
    Alz,
    /// EGG archive (ESTsoft) — recognised so it is reported, not decoded.
    Egg,
    /// HWP v3 document (Hangul) — recognised so it is reported, not decoded.
    Hwp3,
    /// InstallShield MSI installer — recognised so it is reported, not decoded.
    IshieldMsi,
    /// InstallShield InstallScript cabinet — recognised, not decoded.
    IshieldCab,
    /// InstallShield Z archive — the older `.z` installer format, decoded.
    IshieldZ,
    /// CryptFF-encrypted file — recognised so it is reported, not decrypted.
    CryptFf,
    /// ext2/3/4 filesystem image — recognised so it is reported, not walked.
    Ext,
    /// lrzip stream — recognised so it is reported, not decoded.
    Lrzip,
    /// ZOO archive — recognised so it is reported, not decoded.
    Zoo,
    /// AppleSingle / AppleDouble container — recognised, not read.
    AppleSingle,
    /// FAT12/16/32 filesystem — walked, so fragmented files come back whole.
    Fat,
    /// Inno Setup installer — recognised so it is reported, never decoded.
    Inno,
    /// NTFS filesystem — walked through the master file table.
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
    /// SWF (Adobe Flash) movie — decompress the inner FWS body (CWS/ZWS).
    Swf,
    /// BinHex 4.0 (`.hqx`) — classic-Mac 6-bit-encoded forked file.
    Binhex,
    /// Windows Shell Link (`.lnk`) — extract command-line/target/icon strings.
    Lnk,
    /// Raw disk image partition map (GPT / Apple Partition Map / MBR).
    Partition,
    /// Python compiled bytecode (`.pyc`) — surface the marshalled code body.
    Pyc,
    /// NSIS (Nullsoft) installer — decompress the embedded data blocks.
    Nsis,
    /// Mach-O universal ("fat") binary — split into per-architecture slices.
    Machofat,
    /// Self-extracting archive: an executable stub with an archive appended.
    Sfx,
    /// Compiled AutoIt3 script embedded in a PE (`AU3!EA05`/`AU3!EA06`).
    Autoit,
    /// Microsoft OneNote (`.one`) section — carve embedded FileDataStoreObjects.
    OneNote,
    /// RTF document — extract hex-encoded embedded objects (`\objdata`).
    Rtf,
    /// PE packed by a runtime packer (Petite/FSG/NsPack aPLib families are
    /// decompressed; other packers are detected only). See `formats/pepack.rs`.
    PePacked,
    /// Java `.class` — surface constant-pool strings and class/name references.
    JavaClass,
    /// AI model: Python pickle (dangerous-import surfacing) or safetensors.
    AiModel,
    /// Microsoft Script Encoder (`#@~^` VBScript/JScript.Encode) — decode.
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
    /// a new variant a build error here rather than a silent omission — and an
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
/// too weak on its own — it occurs coincidentally in binary data (e.g. inside an
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

/// Whether `data` begins with a real gzip member (RFC 1952): `1f 8b`, then the
/// compression method `08` (deflate — the only method gzip defines), then a flag
/// byte whose three high bits are reserved and must be zero. The bare `1f 8b`
/// prefix is only two bytes and collides constantly with binary data (e.g. inside
/// a PE); a false hit is routed to the inflate path, fails with a "corrupt
/// deflate/gzip" member error, and reports the carrier `UNSCANNABLE`. Validating
/// CM + reserved flag bits rejects those with no loss on genuine gzip.
fn is_gzip_magic(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 0x08 && data[3] & 0xE0 == 0
}

/// Whether `d` starts with a stand-alone executable / OLE magic (PE `MZ`, ELF,
/// Mach-O, or OLE2/CFB). Cheap prefix test — 6 decoded bytes suffice, so it also
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

/// Decode base64 assets embedded in a markup buffer — `data:` URIs in HTML and
/// base64 element bodies in flat-XML Office documents — returning each decoded
/// payload.
///
/// This is the inline-attachment channel of a document that has no archive to
/// unpack. A phishing page carries the brand logo it impersonates as a `data:`
/// URI, and a Word/Excel 2003 flat-XML dropper carries its "enable macros" lure
/// image as a base64 element body; in both cases the document is one
/// self-contained file with nothing to fetch and nothing to extract with an
/// ordinary unpacker. Signatures key on those images and scope them with
/// `Container:` precisely so they fire on the document and not on the same image
/// standing alone — which they can only do if the image is pulled out of it.
///
/// A run is decoded only when its first bytes are a real asset magic (image,
/// executable, OLE2), so ordinary base64-looking text costs a 6-byte decode and
/// nothing more. Bounded by `cap` per payload and by a cap on how many return.
#[cfg(feature = "base64scan")]
pub fn markup_embedded_payloads(data: &[u8], cap: u64) -> Vec<Vec<u8>> {
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
        if !is_b64(data[i]) {
            i += 1;
            continue;
        }
        // Only runs introduced by a `data:` URI or sitting directly inside an
        // element body are candidates. Anything else in markup is prose.
        let before = &data[i.saturating_sub(96)..i];
        let introduced = before.ends_with(b";base64,") || before.last() == Some(&b'>');
        let start = i;
        let mut j = i;
        while j < n && is_b64(data[j]) {
            j += 1;
        }
        i = j.max(start + 1);
        if !introduced || j - start < MIN_RUN {
            continue;
        }
        // Cheap gate first: 8 base64 chars decode to 6 bytes, enough for every
        // magic we care about, and costs no allocation on a miss.
        match plain.decode(&data[start..start + 8]) {
            Ok(head) if starts_asset_magic(&head) => {}
            _ => continue,
        }
        // Absorb the padding the run scan stopped at, so a well-formed URI
        // decodes whole. Without it the tail falls off the last 4-char group and
        // the payload comes back one or two bytes short — invisible on an image,
        // fatal to a hash signature.
        let mut end = j;
        while end < n && end - j < 2 && data[end] == b'=' {
            end += 1;
        }
        i = i.max(end);
        let run = &data[start..end];
        if run.len() as u64 > cap.saturating_mul(2) {
            continue;
        }
        let decoded = engine
            .decode(run)
            .or_else(|_| plain.decode(&data[start..start + (j - start) / 4 * 4]));
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
/// string in a script — e.g. PowerShell reflective loaders (`$PEBytes =
/// "TVqQAA…"`), JS/VBS droppers, HTA — where the executable is invisible to a
/// signature that matches the *decoded* bytes. Each maximal run of base64
/// characters (internal whitespace tolerated, since scripts/RTF line-wrap the
/// blob) at least `MIN_RUN` long is decoded; a decode is returned only when it
/// passes `is_executable_payload`, so a coincidental base64-looking region in
/// binary data (which decodes to noise) is dropped — no false positives, and the
/// caller still validates + rescans through the normal type path. Bounded by
/// `cap` (per-payload size), `MAX_PAYLOADS`, and `MAX_ATTEMPTS` (decode tries).
#[cfg(feature = "base64scan")]
pub fn base64_payloads(data: &[u8], cap: u64) -> Vec<Vec<u8>> {
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
        if !is_b64(data[i]) {
            i += 1;
            continue;
        }
        // Measure the run [start, j) — count base64 chars (internal whitespace
        // from line-wrapping tolerated) and capture the first 8 — WITHOUT
        // allocating. Stops at padding `=` or any other byte.
        let start = i;
        let mut nb64 = 0usize;
        let mut head = [0u8; 8];
        let mut j = i;
        while j < n {
            let b = data[j];
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
        // unless they start with an executable/OLE magic — so long runs that are
        // NOT executables (RTF `\objdata` hex, benign base64 text) cost nothing
        // beyond the byte count above: no full decode, no payload allocation.
        match engine.decode(head) {
            Ok(prefix) if starts_executable_magic(&prefix) => {}
            _ => continue,
        }
        attempts += 1;
        // Executable-looking: now materialize the run (whitespace stripped) and
        // decode the whole 4-char groups (dropping any partial tail / padding).
        let mut run: Vec<u8> = Vec::with_capacity(nb64);
        for &b in &data[start..j] {
            if is_b64(b) {
                run.push(b);
            }
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

/// Best-effort detection of an extractable container by magic bytes. Returns
/// `None` for content this crate can't unpack. Callers with a richer file-type
/// classifier may map to [`Format`] themselves instead of using this.
pub fn detect(data: &[u8]) -> Option<Format> {
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
    // ARJ: the 0x60 0xEA main-header magic.
    if data.starts_with(&[0x60, 0xEA]) {
        return Some(Format::Arj);
    }
    if data.starts_with(b"Rar!\x1a\x07\x00") || data.starts_with(b"Rar!\x1a\x07\x01\x00") {
        return Some(Format::Rar);
    }
    if data.len() >= 32774 && &data[32769..32774] == b"CD001" {
        return Some(Format::Iso);
    }
    // A UDF-only image has no ISO 9660 descriptor at all — Windows and macOS
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
    if formats::sniff::is(data, Format::Wim) {
        return Some(Format::Wim);
    }
    if formats::sniff::is(data, Format::Lz4) {
        return Some(Format::Lz4);
    }
    // ARC last of the archive magics:  plus a method byte is only two bytes,
    // so the name-field validation in `is_arc` is what makes it safe, and a
    // stronger magic should still win the race.
    if formats::sniff::is(data, Format::Ace) {
        return Some(Format::Ace);
    }
    if formats::sniff::is(data, Format::Alz) {
        return Some(Format::Alz);
    }
    if formats::sniff::is(data, Format::Egg) {
        return Some(Format::Egg);
    }
    if formats::sniff::is(data, Format::Hwp3) {
        return Some(Format::Hwp3);
    }
    if formats::sniff::is(data, Format::StuffIt) {
        return Some(Format::StuffIt);
    }
    if formats::sniff::is(data, Format::CryptFf) {
        return Some(Format::CryptFf);
    }
    if formats::sniff::is(data, Format::IshieldZ) {
        return Some(Format::IshieldZ);
    }
    if formats::sniff::is(data, Format::IshieldCab) {
        return Some(Format::IshieldCab);
    }
    if formats::sniff::is(data, Format::Lrzip) {
        return Some(Format::Lrzip);
    }
    if formats::sniff::is(data, Format::Zoo) {
        return Some(Format::Zoo);
    }
    if formats::sniff::is(data, Format::AppleSingle) {
        return Some(Format::AppleSingle);
    }
    // ext last of the filesystem sniffs: its magic is 1080 bytes in, so a
    // partition table or boot sector at offset 0 is the more specific answer.
    if formats::sniff::is(data, Format::Ext) {
        return Some(Format::Ext);
    }
    // FAT before the partition check: a volume boot record and an MBR both end
    // in `55 AA`, and the filesystem is the more specific answer.
    #[cfg(feature = "fat")]
    if formats::fat::is_fat(data) {
        return Some(Format::Fat);
    }
    if formats::sniff::is(data, Format::Ntfs) {
        return Some(Format::Ntfs);
    }
    #[cfg(feature = "arc")]
    if formats::arc::is_arc(data) {
        return Some(Format::Arc);
    }
    #[cfg(feature = "dmg")]
    if is_dmg(data) {
        return Some(Format::Dmg);
    }
    if formats::sniff::is(data, Format::Vhd) {
        return Some(Format::Vhd);
    }
    if formats::sniff::is(data, Format::Lzw) {
        return Some(Format::Lzw);
    }
    if formats::sniff::is(data, Format::Qcow2) {
        return Some(Format::Qcow2);
    }
    if formats::sniff::is(data, Format::Vmdk) {
        return Some(Format::Vmdk);
    }
    if formats::sniff::is(data, Format::Vhdx) {
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
    // a matching terminator (conservative — see `looks_like_uuencode`).
    #[cfg(feature = "uuencode")]
    if looks_like_uuencode(data) {
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
    if looks_like_machofat(data) {
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
    if is_aimodel(data) {
        return Some(Format::AiModel);
    }
    // Microsoft Script Encoder: the `#@~^` marker (VBScript/JScript.Encode).
    #[cfg(feature = "screnc")]
    if looks_like_screnc(data) {
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
    // BinHex 4.0: a marker line (no byte-0 magic) — scan the head for it.
    #[cfg(feature = "binhex")]
    if looks_like_binhex(data) {
        return Some(Format::Binhex);
    }
    // Python `.pyc`: weak magic (`\r\n` at offset 2) — checked late, conservative.
    #[cfg(feature = "pyc")]
    if data.len() >= 16 && data[2] == 0x0D && data[3] == 0x0A {
        return Some(Format::Pyc);
    }
    // Partition maps last: GPT/APM carry strong magic, but the MBR `55 AA` boot
    // signature is weak, so `is_partition` only accepts an MBR with a plausible
    // entry — and being last means it never shadows a real format.
    // NSIS installer: PE stub + the NullsoftInst firstheader. Placed late (it
    // requires an MZ start, so it only claims a PE that is actually NSIS).
    #[cfg(feature = "nsis")]
    if is_nsis(data) {
        return Some(Format::Nsis);
    }
    // Compiled AutoIt3: the AU3!EA05/EA06 marker anywhere (embedded in a PE).
    #[cfg(feature = "autoit")]
    if is_autoit(data) {
        return Some(Format::Autoit);
    }
    // Inno Setup, before the generic SFX carve. The carve does produce the right
    // block, but that block is Inno's own chunked LZMA container — emitted as an
    // ordinary member it read as clean, because compressed payload shows a
    // pattern scan nothing. Typing it here means it is reported instead.
    if formats::sniff::is(data, Format::Inno) {
        return Some(Format::Inno);
    }
    // After Inno and before the generic SFX carve, for the same reason: an
    // InstallShield installer is a PE whose payload the carve would mis-slice.
    if formats::sniff::is(data, Format::IshieldMsi) {
        return Some(Format::IshieldMsi);
    }
    // Self-extracting archive (PE/ELF stub + appended archive). After NSIS (more
    // specific) and only when a bare archive isn't at offset 0.
    #[cfg(feature = "sfx")]
    if looks_like_sfx(data) {
        return Some(Format::Sfx);
    }
    #[cfg(feature = "partition")]
    if is_partition(data) {
        return Some(Format::Partition);
    }
    None
}

/// Per-member visitor for [`extract_each`]. Invoked once per extracted member
/// with the member and the shared [`Budget`] (so the visitor can recurse into a
/// nested container under the same budget). Returns `Some(r)` to stop extraction
/// immediately — `r` is propagated out of [`extract_each`] — or `None` to
/// continue to the next member.
pub type Sink<'a, R> = &'a mut dyn FnMut(Entry, &mut Budget) -> Option<R>;

/// Stream the immediate members of a container (one level), invoking `visit` for
/// each under the shared `budget`. Members are decoded one at a time, so peak
/// memory is ~one member and a `visit` that returns `Some(r)` halts extraction
/// before the remaining members are decompressed.
///
/// Returns `Ok(Some(r))` if `visit` stopped early, `Ok(None)` if every member
/// was visited, or `Err` on a budget bound.
/// Fail the way a decoder can, for input carrying a marker that asks for it.
///
/// The marker is looked for ANYWHERE in the data, not just at the start, so the
/// trigger can be carried inside a genuinely well-formed container — which is
/// what lets the CLI be tested end to end: the file has to survive format
/// detection to reach a decoder at all.
///
/// Only the first is containable. `catch_unwind` catches unwinding and nothing
/// else, so the other two end the process, which is exactly why they are worth
/// firing: what a caller can observe then is the process's exit status, and a
/// crash that looks like a clean scan is the worst outcome exav has.
#[cfg(feature = "testing-faults")]
fn provoke(data: &[u8]) {
    let has = |m: &[u8]| data.windows(m.len()).any(|w| w == m);
    if has(b"__exav_panic__") {
        panic!("deliberate panic from the testing-faults feature");
    }
    if has(b"__exav_abort__") {
        // `abort` rather than a real allocation failure. The outcome is the one
        // being tested — `handle_alloc_error` aborts — and exhausting a
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

pub fn extract_each<R>(
    fmt: Format,
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Containment boundary. Some third-party decoders (e.g. `cab`, `sevenz`,
    // `pdf`) panic on crafted/truncated input instead of returning an error;
    // a scanner must never crash on the files it scans. Catch any unwinding
    // panic here and turn it into a clean bound, so hostile input is reported
    // (LimitsExceeded → never a silent Clean), not a process abort. This crate
    // is `#![forbid(unsafe_code)]` and pure-Rust, so there is no UB to leak
    // across the boundary.
    //
    // What this does NOT contain, because `catch_unwind` catches unwinding and
    // nothing else:
    //
    //   * an allocation large enough to abort — a decoder that sizes a buffer
    //     from a header field can ask for more than the machine has, and Rust
    //     aborts rather than unwinding, so the process is gone before this
    //     line runs;
    //   * stack exhaustion from a file nested into itself — `max_recursion`
    //     bounds CONTAINER nesting, not recursive descent inside one parser;
    //   * a loop that neither allocates nor returns.
    //
    // The daemon holds those with `RLIMIT_AS`, `RLIMIT_CPU` and worker
    // replacement. A one-shot run and a library embedding have no equivalent,
    // which is why `SECURITY.md` says so rather than implying this boundary is
    // total.
    // A format the caller excluded at runtime. Reported, not skipped: the
    // container is there, exav declined to open it, and the scan has to be able
    // to say so. Checked here rather than at each call site because every
    // extraction — including one nested inside another archive — passes through
    // this function.
    if !budget.limits().allows(fmt) {
        return Ok(visit(
            Entry::unsupported(
                format!("{fmt:?}"),
                data.len() as u64,
                false,
                "format excluded by the caller's allowed_formats",
            ),
            budget,
        ));
    }
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dispatch_extract(fmt, data, budget, visit)
    }));
    match caught {
        Ok(r) => r,
        Err(_) => Err(LimitHit::corrupt(format!(
            "{fmt:?} decoder panicked on malformed input"
        ))),
    }
}

/// Format dispatch for [`extract_each`]; kept separate so the panic-containment
/// boundary in `extract_each` wraps every decoder uniformly.
fn dispatch_extract<R>(
    fmt: Format,
    data: &[u8],
    budget: &mut Budget,
    visit: Sink<R>,
) -> Result<Option<R>, LimitHit> {
    // Panic on demand, to test the boundary rather than the decoders.
    //
    // The fixtures in `panic_containment` cover inputs that once panicked a
    // specific decoder — real regressions, worth keeping. But they do not test
    // the `catch_unwind` in `extract_each`: fix every one of those decoders and
    // they all still pass with the boundary deleted. This panics from inside the
    // dispatch for input nothing else produces, so the only thing that can turn
    // it into a `LimitHit` is the boundary itself.
    #[cfg(feature = "testing-faults")]
    provoke(data);
    match fmt {
        #[cfg(feature = "gzip")]
        Format::Gzip => extract_gzip(data, budget, visit),
        #[cfg(feature = "tar")]
        Format::Tar => extract_tar(data, budget, visit),
        #[cfg(feature = "zip")]
        Format::Zip => extract_zip(data, budget, visit),
        #[cfg(feature = "bzip2")]
        Format::Bzip2 => extract_bzip2(data, budget, visit),
        #[cfg(feature = "xz")]
        Format::Xz => extract_xz(data, budget, visit),
        #[cfg(feature = "cab")]
        Format::Cab => extract_cab(data, budget, visit),
        #[cfg(feature = "chm")]
        Format::Chm => extract_chm(data, budget, visit),
        // OLE builds a combined VBA-macro dump from all streams, so it collects
        // then emits — the visitor still gets one member at a time.
        #[cfg(feature = "ole")]
        Format::Ole => emit_collected(extract_ole(data, budget)?, budget, visit),
        #[cfg(feature = "pdf")]
        Format::Pdf => extract_pdf(data, budget, visit),
        #[cfg(feature = "email")]
        Format::Email => extract_email(data, budget, visit),
        #[cfg(feature = "sevenz")]
        Format::SevenZip => extract_sevenz(data, budget, visit),
        #[cfg(feature = "iso")]
        Format::Iso => extract_iso(data, budget, visit),
        #[cfg(feature = "lha")]
        Format::Lha => extract_lha(data, budget, visit),
        #[cfg(feature = "arj")]
        Format::Arj => extract_arj(data, budget, visit),
        // RAR decodes members eagerly (CRC checks, metadata-only entries for
        // encrypted/unsupported members), so it collects then emits — the visitor
        // still gets one member at a time and can stop early.
        #[cfg(feature = "rar")]
        Format::Rar => emit_collected(extract_rar(data, budget)?, budget, visit),
        #[cfg(feature = "upx")]
        Format::Upx => extract_upx(data, budget, visit),
        #[cfg(feature = "ar")]
        Format::Ar => extract_ar(data, budget, visit),
        #[cfg(feature = "cpio")]
        Format::Cpio => extract_cpio(data, budget, visit),
        #[cfg(feature = "xar")]
        Format::Xar => extract_xar(data, budget, visit),
        #[cfg(feature = "dmg")]
        Format::Dmg => extract_dmg(data, budget, visit),
        #[cfg(feature = "vhd")]
        Format::Vhd => formats::vhd::extract_vhd(data, budget, visit),
        #[cfg(not(feature = "vhd"))]
        Format::Vhd => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "lzw")]
        Format::Lzw => formats::lzw::extract_lzw(data, budget, visit),
        #[cfg(not(feature = "lzw"))]
        Format::Lzw => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "diskimage")]
        Format::Qcow2 => formats::qcow2::extract_qcow2(data, budget, visit),
        #[cfg(not(feature = "diskimage"))]
        Format::Qcow2 => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "diskimage")]
        Format::Vmdk => formats::vmdk::extract_vmdk(data, budget, visit),
        #[cfg(not(feature = "diskimage"))]
        Format::Vmdk => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "diskimage")]
        Format::Vhdx => formats::vhdx::extract_vhdx(data, budget, visit),
        #[cfg(not(feature = "diskimage"))]
        Format::Vhdx => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "wim")]
        Format::Wim => formats::wim::extract_wim(data, budget, visit),
        #[cfg(not(feature = "wim"))]
        Format::Wim => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "lz4")]
        Format::Lz4 => formats::lz4::extract_lz4(data, budget, visit),
        #[cfg(not(feature = "lz4"))]
        Format::Lz4 => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "arc")]
        Format::Arc => formats::arc::extract_arc(data, budget, visit),
        #[cfg(not(feature = "arc"))]
        Format::Arc => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "ace")]
        Format::Ace => formats::ace::extract_ace(data, budget, visit),
        #[cfg(not(feature = "ace"))]
        Format::Ace => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "alz")]
        Format::Alz => formats::alz::extract_alz(data, budget, visit),
        #[cfg(not(feature = "alz"))]
        Format::Alz => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "egg")]
        Format::Egg => formats::egg::extract_egg(data, budget, visit),
        #[cfg(not(feature = "egg"))]
        Format::Egg => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "hwp3")]
        Format::Hwp3 => formats::hwp3::extract_hwp3(data, budget, visit),
        #[cfg(not(feature = "hwp3"))]
        Format::Hwp3 => not_compiled_in(fmt, data, budget, visit),
        // Recognised, not opened — all share one reporting path.
        Format::IshieldMsi
        | Format::IshieldCab
        | Format::CryptFf
        | Format::Lrzip
        | Format::AppleSingle => formats::reported::extract_reported(fmt, data, budget, visit),
        #[cfg(feature = "ext")]
        Format::Ext => formats::ext::extract_ext(data, budget, visit),
        #[cfg(not(feature = "ext"))]
        Format::Ext => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "zoo")]
        Format::Zoo => formats::zoo::extract_zoo(data, budget, visit),
        #[cfg(not(feature = "zoo"))]
        Format::Zoo => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "ishieldz")]
        Format::IshieldZ => formats::ishield_z::extract_ishield_z(data, budget, visit),
        #[cfg(not(feature = "ishieldz"))]
        Format::IshieldZ => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "stuffit")]
        Format::StuffIt => formats::stuffit::extract_stuffit(data, budget, visit),
        #[cfg(not(feature = "stuffit"))]
        Format::StuffIt => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "fat")]
        Format::Fat => formats::fat::extract_fat(data, budget, visit),
        #[cfg(not(feature = "fat"))]
        Format::Fat => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "inno")]
        Format::Inno => formats::inno::extract_inno(data, budget, visit),
        #[cfg(not(feature = "inno"))]
        Format::Inno => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "ntfs")]
        Format::Ntfs => formats::ntfs::extract_ntfs(data, budget, visit),
        #[cfg(not(feature = "ntfs"))]
        Format::Ntfs => not_compiled_in(fmt, data, budget, visit),
        #[cfg(feature = "zstd")]
        Format::Zstd => extract_zstd(data, budget, visit),
        #[cfg(feature = "lzip")]
        Format::Lzip => extract_lzip(data, budget, visit),
        #[cfg(feature = "uuencode")]
        Format::Uuencode => extract_uuencode(data, budget, visit),
        #[cfg(feature = "xdp")]
        Format::Xdp => extract_xdp(data, budget, visit),
        #[cfg(feature = "szdd")]
        Format::Szdd => extract_szdd(data, budget, visit),
        #[cfg(feature = "tnef")]
        Format::Tnef => extract_tnef(data, budget, visit),
        #[cfg(feature = "swf")]
        Format::Swf => extract_swf(data, budget, visit),
        #[cfg(feature = "binhex")]
        Format::Binhex => extract_binhex(data, budget, visit),
        #[cfg(feature = "lnk")]
        Format::Lnk => extract_lnk(data, budget, visit),
        #[cfg(feature = "partition")]
        Format::Partition => extract_partition(data, budget, visit),
        #[cfg(feature = "pyc")]
        Format::Pyc => extract_pyc(data, budget, visit),
        #[cfg(feature = "nsis")]
        Format::Nsis => extract_nsis(data, budget, visit),
        #[cfg(feature = "machofat")]
        Format::Machofat => extract_machofat(data, budget, visit),
        #[cfg(feature = "sfx")]
        Format::Sfx => extract_sfx(data, budget, visit),
        #[cfg(feature = "autoit")]
        Format::Autoit => extract_autoit(data, budget, visit),
        #[cfg(feature = "onenote")]
        Format::OneNote => extract_onenote(data, budget, visit),
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
        // Unreachable when `all-formats` is on (every arm above exists then).
        #[cfg(not(feature = "all-formats"))]
        #[allow(unreachable_patterns)]
        _ => not_compiled_in(fmt, data, budget, visit),
    }
}

/// The format was recognised but its extractor wasn't compiled into this build.
/// Emit one unsupported member so it reads as recognised-but-undecodable.
///
/// Every disabled-format arm must route here rather than return `Ok(None)`:
/// `Ok(None)` means "no members", which the caller cannot distinguish from an
/// empty archive, and the file then scans clean.
#[cfg(not(feature = "all-formats"))]
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

/// Collect the immediate members of a container into a `Vec` (buffers them all
/// at once). Prefer [`extract_each`] for scanning — it streams member-by-member
/// and can stop early. Kept for callers/tests that want the full list.
///
/// # Errors
///
/// Returns [`LimitHit`], whose two shapes mean different things and should not
/// be collapsed into one "failed" branch:
///
/// * `corrupt == true` — the container could not be decoded: malformed,
///   truncated, an unsupported compression method, or a decoder panic caught at
///   the extraction boundary. The right verdict is `Unscannable`.
/// * `corrupt == false` — a budget stopped the walk, and `kind` names which
///   one. The right verdict is `LimitsExceeded`.
///
/// In both cases some members may already have been decoded and are discarded
/// along with the error; use [`extract_each`] if partial results matter.
///
/// **An error is never a reason to treat the input as clean.** A container this
/// call refused is content that was not scanned, which is the one outcome the
/// verdict model exists to keep distinguishable from an empty result.
pub fn extract(fmt: Format, data: &[u8], budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
    let mut out = Vec::new();
    extract_each::<std::convert::Infallible>(fmt, data, budget, &mut |e, _| {
        out.push(e);
        None
    })?;
    Ok(out)
}

/// True if `data` looks like a UPX-packed executable (a valid `PackHeader` is
/// present). Used by callers whose file-type classifier already recognises
/// PE/ELF/Mach-O and wants to additionally unpack UPX.
pub fn is_upx(data: &[u8]) -> bool {
    #[cfg(feature = "upx")]
    {
        // Both layouts the unpacker handles: the `l_info` chain, and a bare
        // PackHeader. Gating on `find_packheader` alone meant a PackHeader-only
        // image — a routine shape for packed malware — reached no unpacker at
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
/// image when the stub produced one. Diagnostic surface only — the scan path
/// goes through [`extract`].
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
/// attacker-declared size (16 MiB). The buffer still grows on demand — bounded
/// by the budget-checked reads — so this only prevents a crafted header from
/// forcing a huge up-front allocation (the over-allocation DoS class; cf. the
/// ClamAV 7z/InstallShield advisories and the fuzz-found delharc OOM).
pub(crate) const PREALLOC_CAP: usize = 16 * 1024 * 1024;

/// Cap a pre-allocation request from an attacker-declared byte size.
pub(crate) fn cap_prealloc(requested: usize) -> usize {
    requested.min(PREALLOC_CAP)
}

/// Reject a stream whose decompressed size dwarfs its declared input size.
/// Absolute byte caps are the primary bomb defense; this is a fast reject
/// for the obvious cases. A declared input of 0 is ignored (we cannot trust
/// it) and left to the absolute caps.
pub(crate) fn ratio_guard(input: u64, output: u64, budget: &Budget) -> Result<(), LimitHit> {
    if input > 0 && output / input > budget.limits.max_compression_ratio {
        return Err(LimitHit::new(format!(
            "compression ratio {} > {}",
            output / input,
            budget.limits.max_compression_ratio
        )));
    }
    Ok(())
}

/// Read up to `cap` bytes; the returned flag is true if the source had more
/// (so the caller can treat it as exceeding the budget rather than silently
/// truncating).
pub fn bounded_read<R: Read>(mut r: R, cap: u64) -> Result<(Vec<u8>, bool), std::io::Error> {
    let mut buf = Vec::new();
    (&mut r).take(cap.saturating_add(1)).read_to_end(&mut buf)?;
    let truncated = buf.len() as u64 > cap;
    if truncated {
        buf.truncate(cap as usize);
    }
    Ok((buf, truncated))
}

/// Like [`bounded_read`], but when `salvage` is set, a read error does not
/// discard the bytes decoded so far — it returns them. This is the
/// scan-everything default: a trailing checksum/integrity error from a
/// decompressor (e.g. a gzip CRC-32 or ISIZE mismatch, a ZIP CRC) must not throw
/// away already-decompressed content that a scanner still needs to inspect. With
/// `salvage` false it is exactly [`bounded_read`] (errors propagate).
pub(crate) fn bounded_read_salvage<R: Read>(
    mut r: R,
    cap: u64,
    salvage: bool,
) -> Result<(Vec<u8>, bool), std::io::Error> {
    if !salvage {
        return bounded_read(r, cap);
    }
    let limit = cap.saturating_add(1);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    while (buf.len() as u64) < limit {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // Salvage: keep the content decoded before the (likely checksum)
            // error rather than dropping the whole member.
            Err(_) => break,
        }
    }
    let truncated = buf.len() as u64 > cap;
    if truncated {
        buf.truncate(cap as usize);
    }
    Ok((buf, truncated))
}

// ---------------------------------------------------------------------------
// Archive<R> — format-agnostic streaming member access
// ---------------------------------------------------------------------------

/// State for buffered (non-seekable) format extraction.
struct BufState {
    next_index: usize,
    /// Lazily populated on first extraction. Once filled, members are yielded
    /// one at a time via `next_index`.
    cached: Option<Vec<Entry>>,
}

/// An opened archive with lazy, member-by-member extraction.
///
/// The public API is format-agnostic: [`open`](Archive::open) detects the
/// container, [`extract_next`](Archive::extract_next) pulls members one at a
/// time under a shared [`Budget`], and [`extract`](Archive::extract) /
/// [`extract_all`](Archive::extract_all) provide random-access and collect-all
/// convenience.
///
/// For seekable formats (ZIP today) the central directory is read once on
/// [`Archive::open`] and individual members are fetched on demand without loading
/// the whole file.  For non-seekable formats the data is read into memory on
/// [`Archive::open`] and members are extracted lazily from the buffer.
pub struct Archive<R: Read + Seek> {
    format: Format,
    inner: ArchiveInner<R>,
}

enum ArchiveInner<R: Read + Seek> {
    #[cfg(feature = "zip")]
    Zip {
        members: ZipMembers<R>,
        info: Vec<MemberInfo>,
    },
    #[cfg(feature = "gzip")]
    Gzip {
        reader: Option<R>,
        done: bool,
    },
    #[cfg(feature = "tar")]
    Tar {
        reader: Option<R>,
        members: Vec<TarMember>,
        /// The same members as [`MemberInfo`], so `list` can hand out a slice.
        info: Vec<MemberInfo>,
        next_index: usize,
    },
    Lazy {
        reader: Option<R>,
        format: Format,
        state: BufState,
    },
    Buffered {
        data: Vec<u8>,
        state: BufState,
    },
}

/// Pre-parsed tar member metadata.
#[cfg(feature = "tar")]
struct TarMember {
    name: String,
    size: u64,
    data_offset: u64,
}

#[cfg(feature = "tar")]
impl TarMember {
    fn parse(header: &[u8; 512]) -> Option<Self> {
        // End-of-archive: two consecutive all-zero blocks.
        if header.iter().all(|&b| b == 0) {
            return None;
        }
        let name_raw = &header[..100];
        let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(100);
        if name_end == 0 {
            return None;
        }
        let name = String::from_utf8_lossy(&name_raw[..name_end]).into_owned();

        // size: bytes 124..136, octal ASCII.
        //
        // POSIX leaves the terminator open: the field may end in NUL, in a space,
        // or in both, and writers disagree. GNU tar, python's tarfile and ustar
        // all write digits then NUL; node-tar — and therefore every npm package
        // tarball — writes digits, a space, then a NUL.
        //
        // Trimming whitespace before NULs cannot handle that second form. NUL is
        // not whitespace to `trim`, so it strips nothing, and stripping the NUL
        // afterwards leaves the space behind for `from_str_radix` to reject. The
        // failure is silent and total: an unparseable size ends the walk, so a
        // first-member failure yields ZERO members and the archive scans as an
        // empty tar. Strip both characters, from both ends, in one pass.
        let size_str = std::str::from_utf8(&header[124..136]).ok()?;
        let size = u64::from_str_radix(size_str.trim_matches(['\0', ' ']), 8).ok()?;

        // typeflag: byte 156 — skip directories and non-regular files.
        let typeflag = header[156];
        if typeflag == b'5' || typeflag == b'1' || typeflag == b'2' {
            // directory, hard link, symlink — skip but still advance
        }

        Some(TarMember {
            name,
            size,
            data_offset: 0,
        })
    }
}

/// Parse all tar headers from the reader, returning member metadata with
/// correct `data_offset` values.  The reader must be positioned at the start.
#[cfg(feature = "tar")]
fn parse_tar_headers<R: Read + Seek>(reader: &mut R) -> Result<Vec<TarMember>, std::io::Error> {
    let mut members = Vec::new();
    let mut offset = 0u64;
    loop {
        reader.seek(std::io::SeekFrom::Start(offset))?;
        let mut header = [0u8; 512];
        reader.read_exact(&mut header)?;
        match TarMember::parse(&header) {
            Some(mut m) => {
                m.data_offset = offset + 512;
                members.push(m);
                // Advance past header + padded data.
                let data_end = offset + 512 + ((members.last().unwrap().size + 511) & !511);
                offset = data_end;
            }
            // Two different things end the walk here, and they are not the same
            // fact. An all-zero block IS the archive's end marker; a header that
            // will not parse is a member the walk cannot get past, and stopping
            // on it silently truncates the archive at that point. When the very
            // first header is the one that fails, that means ZERO members and the
            // file scans as an empty tar — clean.
            //
            // That is not hypothetical: one mis-ordered trim in the size field
            // (fixed above) made every npm package tarball do exactly this.
            //
            // Members already recovered are kept — surfacing the damage must not
            // cost the coverage we DID get, which is the same rule the ZIP
            // walkers follow for an unreadable member. The consequence is that a
            // mid-archive header failure still stops quietly, since this
            // signature has nowhere to carry "these members, and also a problem";
            // only the total failure is reported. Narrowing that further needs
            // the return type to change and is tracked separately.
            None => {
                if header.iter().all(|&b| b == 0) || !members.is_empty() {
                    break;
                }
                // Nothing recovered at all: the FIRST header did not parse, so
                // this is not a short archive, it is one we could not read. Say
                // so. Reporting it Unscannable is the only honest answer: an
                // empty member list here makes a tarball whose size field uses a
                // terminator this reader mishandles scan as a clean empty
                // archive.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("tar: unparseable header at offset {offset}"),
                ));
            }
        }
    }
    Ok(members)
}

impl<R: Read + Seek> Archive<R> {
    /// Detect the container format, parse format-specific headers (e.g. the
    /// ZIP central directory), and return an [`Archive`] ready for member
    /// extraction.
    ///
    /// For ZIP the reader is kept alive and seeked on demand (only the central
    /// directory is read up front).  For all other formats the remaining bytes
    /// are read into memory so the existing buffer-based extractors are reused.
    pub fn open(mut reader: R) -> Result<Self, LimitHit> {
        // Read up to 64 KiB for format detection.
        let mut head = Vec::with_capacity(65536);
        reader
            .by_ref()
            .take(65536)
            .read_to_end(&mut head)
            .map_err(|e| LimitHit::corrupt(format!("read head: {e}")))?;

        let format =
            detect(&head).ok_or_else(|| LimitHit::corrupt("unrecognised archive format".into()))?;

        // Seekable per-format fast paths (only for the compiled formats). Each
        // returns early; anything not handled falls through to the buffered
        // path below, which re-reads the object and routes it through the same
        // `extract_each` dispatch (so a disabled format lands on the
        // "unsupported" fallback there rather than being silently skipped).
        #[cfg(feature = "zip")]
        if format == Format::Zip {
            // Seek back to the start so the ZIP central-directory parser sees
            // the full file.
            reader
                .seek(std::io::SeekFrom::Start(0))
                .map_err(|e| LimitHit::corrupt(format!("seek: {e}")))?;
            let mut members = ZipMembers::open(reader).map_err(|e| LimitHit::corrupt(e.reason))?;
            let info = members.list_entries();
            return Ok(Self {
                format,
                inner: ArchiveInner::Zip { members, info },
            });
        }
        #[cfg(feature = "gzip")]
        if format == Format::Gzip {
            reader
                .seek(std::io::SeekFrom::Start(0))
                .map_err(|e| LimitHit::corrupt(format!("seek: {e}")))?;
            return Ok(Self {
                format,
                inner: ArchiveInner::Gzip {
                    reader: Some(reader),
                    done: false,
                },
            });
        }
        #[cfg(feature = "tar")]
        if format == Format::Tar {
            reader
                .seek(std::io::SeekFrom::Start(0))
                .map_err(|e| LimitHit::corrupt(format!("seek: {e}")))?;
            let members = parse_tar_headers(&mut reader)
                .map_err(|e| LimitHit::corrupt(format!("tar: {e}")))?;
            // A tar's headers ARE its index: every member's name, size and
            // offset is known once they are parsed, which is what lets
            // `extract` seek straight to one. Reporting that through `list` is
            // what makes a caller able to see what an archive holds without
            // decompressing it — and an empty list would say it holds nothing.
            // Tar stores members uncompressed, so the two sizes are one size.
            let info = members
                .iter()
                .enumerate()
                .map(|(index, m)| MemberInfo {
                    name: m.name.clone(),
                    index,
                    compressed_size: m.size,
                    uncompressed_size: m.size,
                    encrypted: false,
                })
                .collect();
            return Ok(Self {
                format,
                inner: ArchiveInner::Tar {
                    reader: Some(reader),
                    members,
                    info,
                    next_index: 0,
                },
            });
        }
        if matches!(format, Format::Bzip2 | Format::Xz | Format::Zstd) {
            reader
                .seek(std::io::SeekFrom::Start(0))
                .map_err(|e| LimitHit::corrupt(format!("seek: {e}")))?;
            return Ok(Self {
                format,
                inner: ArchiveInner::Lazy {
                    reader: Some(reader),
                    format,
                    state: BufState {
                        next_index: 0,
                        cached: None,
                    },
                },
            });
        }
        // Buffered fallback: read the rest of the reader into memory, bounded by
        // the global peak-buffer limit. `Archive::open` predates the budget, so
        // it uses the default limit; callers wanting a different ceiling drive
        // extraction through the budgeted [`extract_each`]/[`stream_members`] APIs.
        // (In-tree, exav-core reaches `open` only for ZIP, which returns above
        // before this fallback — so this bounds the public API, not the scanner.)
        let max_buffer = Limits::default().max_buffer_bytes;
        let mut data = head;
        reader
            .take(
                max_buffer
                    .saturating_add(1)
                    .saturating_sub(data.len() as u64),
            )
            .read_to_end(&mut data)
            .map_err(|e| LimitHit::corrupt(format!("read: {e}")))?;
        if data.len() as u64 > max_buffer {
            return Err(LimitHit::new(format!(
                "container exceeds max-buffer {max_buffer}"
            )));
        }
        Ok(Self {
            format,
            inner: ArchiveInner::Buffered {
                data,
                state: BufState {
                    next_index: 0,
                    cached: None,
                },
            },
        })
    }

    /// Detected container format.
    pub fn format(&self) -> Format {
        self.format
    }

    /// Pre-parsed member metadata.  For ZIP this is free (central directory).
    /// For buffered formats the list is empty until the first extraction call
    /// populates the cache.
    pub fn list(&self) -> &[MemberInfo] {
        match &self.inner {
            #[cfg(feature = "zip")]
            ArchiveInner::Zip { info, .. } => info,
            #[cfg(feature = "gzip")]
            ArchiveInner::Gzip { .. } => &[],
            #[cfg(feature = "tar")]
            ArchiveInner::Tar { info, .. } => info,
            ArchiveInner::Lazy { .. } => &[],
            ArchiveInner::Buffered { .. } => &[],
        }
    }

    /// Extract the next member under budget.  Returns `Ok(None)` when the
    /// archive is exhausted.  Directories and other non-file entries are
    /// skipped (but still counted toward the file-count budget).
    pub fn extract_next(&mut self, budget: &mut Budget) -> Result<Option<Entry>, LimitHit> {
        match &mut self.inner {
            #[cfg(feature = "zip")]
            ArchiveInner::Zip { members, .. } => members.next_member(budget).transpose(),
            #[cfg(feature = "gzip")]
            ArchiveInner::Gzip { reader, done } => {
                if *done {
                    return Ok(None);
                }
                let r = reader
                    .take()
                    .ok_or_else(|| LimitHit::corrupt("gzip: already extracted".into()))?;
                budget.count_entry()?;
                let cap = budget.reserve()?;
                use flate2::read::MultiGzDecoder;
                let (out, truncated) = bounded_read_salvage(
                    MultiGzDecoder::new(r),
                    cap,
                    !budget.should_verify_checksums(),
                )
                .map_err(|e| LimitHit::corrupt(format!("gzip: {e}")))?;
                if truncated {
                    return Err(LimitHit::new("gzip member exceeds budget".to_string()));
                }
                budget.commit(out.len() as u64);
                *done = true;
                Ok(Some(Entry::new("gzip-content".to_string(), out)))
            }
            #[cfg(feature = "tar")]
            ArchiveInner::Tar {
                reader,
                members,
                next_index,
                ..
            } => {
                if *next_index >= members.len() {
                    return Ok(None);
                }
                let r = reader
                    .as_mut()
                    .ok_or_else(|| LimitHit::corrupt("tar: already consumed".into()))?;
                let m = &members[*next_index];
                budget.count_entry()?;
                let cap = budget.reserve()?;
                r.seek(std::io::SeekFrom::Start(m.data_offset))
                    .map_err(|e| LimitHit::corrupt(format!("tar seek: {e}")))?;
                let mut take = r.take(m.size);
                let (out, truncated) = bounded_read(&mut take, cap)
                    .map_err(|e| LimitHit::corrupt(format!("tar read: {e}")))?;
                if truncated {
                    return Err(LimitHit::new(format!(
                        "tar member '{}' exceeds budget",
                        m.name
                    )));
                }
                budget.commit(out.len() as u64);
                *next_index += 1;
                Ok(Some(Entry::new(m.name.clone(), out)))
            }
            ArchiveInner::Lazy {
                reader,
                format,
                state,
            } => {
                if state.cached.is_none() {
                    let r = reader
                        .take()
                        .ok_or_else(|| LimitHit::corrupt("lazy: already consumed".into()))?;
                    let mut data = Vec::new();
                    r.take(budget.limits.max_buffer_bytes.saturating_add(1))
                        .read_to_end(&mut data)
                        .map_err(|e| LimitHit::corrupt(format!("read: {e}")))?;
                    if data.len() as u64 > budget.limits.max_buffer_bytes {
                        return Err(LimitHit::new(format!(
                            "container exceeds max-buffer {}",
                            budget.limits.max_buffer_bytes
                        )));
                    }
                    let mut entries = Vec::new();
                    extract_each::<std::convert::Infallible>(
                        *format,
                        &data,
                        budget,
                        &mut |e, _| {
                            entries.push(e);
                            None
                        },
                    )?;
                    state.cached = Some(entries);
                }
                let entries = state.cached.as_ref().unwrap();
                if state.next_index < entries.len() {
                    let e = entries[state.next_index].clone();
                    state.next_index += 1;
                    Ok(Some(e))
                } else {
                    Ok(None)
                }
            }
            ArchiveInner::Buffered { data, state } => {
                // Lazy full extraction on first call.
                if state.cached.is_none() {
                    let fmt = self.format;
                    let mut entries = Vec::new();
                    extract_each::<std::convert::Infallible>(fmt, data, budget, &mut |e, _| {
                        entries.push(e);
                        None
                    })?;
                    state.cached = Some(entries);
                }
                let entries = state.cached.as_ref().unwrap();
                if state.next_index < entries.len() {
                    let e = entries[state.next_index].clone();
                    state.next_index += 1;
                    Ok(Some(e))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Extract a specific member by index under budget.  For ZIP this seeks
    /// directly to the member; for buffered formats the full extraction is
    /// triggered on first call and the result is returned from the cache.
    pub fn extract(&mut self, index: usize, budget: &mut Budget) -> Result<Entry, LimitHit> {
        match &mut self.inner {
            #[cfg(feature = "zip")]
            ArchiveInner::Zip { members, .. } => members
                .extract_entry(index, budget)?
                .ok_or_else(|| LimitHit::corrupt(format!("index {index} is a directory"))),
            #[cfg(feature = "gzip")]
            ArchiveInner::Gzip { reader, done } => {
                if index != 0 {
                    return Err(LimitHit::new(format!("index {index} out of bounds")));
                }
                if *done {
                    return Err(LimitHit::corrupt("gzip: already extracted".into()));
                }
                let r = reader
                    .take()
                    .ok_or_else(|| LimitHit::corrupt("gzip: already extracted".into()))?;
                budget.count_entry()?;
                let cap = budget.reserve()?;
                use flate2::read::MultiGzDecoder;
                let (out, truncated) = bounded_read_salvage(
                    MultiGzDecoder::new(r),
                    cap,
                    !budget.should_verify_checksums(),
                )
                .map_err(|e| LimitHit::corrupt(format!("gzip: {e}")))?;
                if truncated {
                    return Err(LimitHit::new("gzip member exceeds budget".to_string()));
                }
                budget.commit(out.len() as u64);
                *done = true;
                Ok(Entry::new("gzip-content".to_string(), out))
            }
            #[cfg(feature = "tar")]
            ArchiveInner::Tar {
                reader, members, ..
            } => {
                if index >= members.len() {
                    return Err(LimitHit::new(format!("index {index} out of bounds")));
                }
                let r = reader
                    .as_mut()
                    .ok_or_else(|| LimitHit::corrupt("tar: already consumed".into()))?;
                let m = &members[index];
                budget.count_entry()?;
                let cap = budget.reserve()?;
                r.seek(std::io::SeekFrom::Start(m.data_offset))
                    .map_err(|e| LimitHit::corrupt(format!("tar seek: {e}")))?;
                let mut take = r.take(m.size);
                let (out, truncated) = bounded_read(&mut take, cap)
                    .map_err(|e| LimitHit::corrupt(format!("tar read: {e}")))?;
                if truncated {
                    return Err(LimitHit::new(format!(
                        "tar member '{}' exceeds budget",
                        m.name
                    )));
                }
                budget.commit(out.len() as u64);
                Ok(Entry::new(m.name.clone(), out))
            }
            ArchiveInner::Lazy {
                reader,
                format,
                state,
            } => {
                if state.cached.is_none() {
                    let r = reader
                        .take()
                        .ok_or_else(|| LimitHit::corrupt("lazy: already consumed".into()))?;
                    let mut data = Vec::new();
                    r.take(budget.limits.max_buffer_bytes.saturating_add(1))
                        .read_to_end(&mut data)
                        .map_err(|e| LimitHit::corrupt(format!("read: {e}")))?;
                    if data.len() as u64 > budget.limits.max_buffer_bytes {
                        return Err(LimitHit::new(format!(
                            "container exceeds max-buffer {}",
                            budget.limits.max_buffer_bytes
                        )));
                    }
                    let mut entries = Vec::new();
                    extract_each::<std::convert::Infallible>(
                        *format,
                        &data,
                        budget,
                        &mut |e, _| {
                            entries.push(e);
                            None
                        },
                    )?;
                    state.cached = Some(entries);
                }
                let entries = state.cached.as_ref().unwrap();
                entries
                    .get(index)
                    .cloned()
                    .ok_or_else(|| LimitHit::new(format!("index {index} out of bounds")))
            }
            ArchiveInner::Buffered { data, state } => {
                if state.cached.is_none() {
                    let fmt = self.format;
                    let mut entries = Vec::new();
                    extract_each::<std::convert::Infallible>(fmt, data, budget, &mut |e, _| {
                        entries.push(e);
                        None
                    })?;
                    state.cached = Some(entries);
                }
                let entries = state.cached.as_ref().unwrap();
                entries
                    .get(index)
                    .cloned()
                    .ok_or_else(|| LimitHit::new(format!("index {index} out of bounds")))
            }
        }
    }

    /// Extract all members under budget and return them as a `Vec`.
    pub fn extract_all(&mut self, budget: &mut Budget) -> Result<Vec<Entry>, LimitHit> {
        let mut out = Vec::new();
        while let Some(e) = self.extract_next(budget)? {
            out.push(e);
        }
        Ok(out)
    }
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

    #[test]
    fn a_data_uri_image_comes_back_byte_for_byte() {
        let want = png(b"marker-A");
        let page = format!("<img src=\"data:image/png;base64,{}\">", b64(&want));
        let got = markup_embedded_payloads(page.as_bytes(), 1 << 20);
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
            markup_embedded_payloads(doc.as_bytes(), 1 << 20),
            vec![want]
        );
    }

    #[test]
    fn prose_and_unintroduced_runs_are_not_decoded() {
        let asset = b64(&png(b"marker-C"));
        // Same bytes, but not introduced by a `data:` URI or an element body.
        let loose = format!("some text {asset} more text");
        assert!(markup_embedded_payloads(loose.as_bytes(), 1 << 20).is_empty());
        // Introduced, but decodes to nothing that is an asset.
        let junk = "A".repeat(400);
        let page = format!("<img src=\"data:text/plain;base64,{junk}\">");
        assert!(markup_embedded_payloads(page.as_bytes(), 1 << 20).is_empty());
    }

    #[test]
    fn a_payload_over_the_cap_is_dropped_not_truncated() {
        let want = png(b"marker-D");
        let page = format!("<img src=\"data:image/png;base64,{}\">", b64(&want));
        assert!(
            markup_embedded_payloads(page.as_bytes(), 16).is_empty(),
            "a truncated asset is worse than no asset — it would be scanned as \
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
        let mut b = cab::CabinetBuilder::new();
        {
            let folder = b.add_folder(cab::CompressionType::None);
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
        // overwritten with 0xFFFFFFFF — an evasion that defeats strict parsers.
        // `repair_cab_size` clamps it so the member is still extracted.
        let mut blob = cab_of(&[("payload.bin", b"INNER-CAB-PAYLOAD")]);
        blob[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Cab, &blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"INNER-CAB-PAYLOAD");
    }

    #[test]
    fn extract_each_stops_early_and_threads_budget() {
        // A tar with three members; the visitor stops at the second. The third
        // must never be decoded/visited (early-exit), and the visitor sees the
        // shared budget so it can recurse.
        let blob = tar_of(&[("a", b"first"), ("b", b"second"), ("c", b"third")]);
        let mut budget = Budget::new(Limits::default());
        let mut seen: Vec<String> = Vec::new();
        let stopped = extract_each(Format::Tar, &blob, &mut budget, &mut |e, b| {
            // The budget is real (a member was just committed against it).
            assert!(b.total_out > 0);
            seen.push(String::from_utf8_lossy(&e.data).into_owned());
            if e.data == b"second" {
                Some("hit-b")
            } else {
                None
            }
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
        // not just the first — a real FN source for some packagers.
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
        let entries = extract(Format::Bzip2, blob, &mut budget).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"hello exav inside bzip2");
    }

    #[test]
    fn bzip2_magic_rejects_false_positives() {
        // A genuine stream (BZh9 + pi block magic) is detected...
        let real: &[u8] = &[
            66, 90, 104, 57, 49, 65, 89, 38, 83, 89, 213, 127, 182, 220, 0, 0,
        ];
        assert_eq!(detect(real), Some(Format::Bzip2));
        // ...but a coincidental `BZh#` run in binary data (as carved out of an ISO
        // at offset 343598: `BZh3` then `1h1H…`, not the block magic) is not — it
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
        let got = base64_payloads(carrier.as_bytes(), u64::MAX);
        assert_eq!(got.len(), 1, "should recover the one embedded PE");
        assert!(got[0].starts_with(b"MZ"));
        assert_eq!(&got[0][0x40..0x44], b"PE\x00\x00");

        // A long base64 run that decodes to plain text (no exec magic) is ignored.
        let txt = base64::engine::general_purpose::STANDARD.encode(vec![b'A'; 2048]);
        assert!(base64_payloads(format!("x=\"{txt}\"").as_bytes(), u64::MAX).is_empty());
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
        let mut builder = cab::CabinetBuilder::new();
        let folder = builder.add_folder(cab::CompressionType::None);
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

    const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

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
            std::io::Write::write_all(&mut s, EICAR).unwrap();
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
        let pdf = minimal_pdf_with_stream(EICAR);
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
        let entries = extract(Format::Email, msg.as_bytes(), &mut budget).unwrap();
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

    // -----------------------------------------------------------------------
    // Archive<R> tests
    // -----------------------------------------------------------------------

    #[test]
    fn archive_zip_extract_next() {
        let zip_blob = zip_of(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
        let mut archive = Archive::open(Cursor::new(zip_blob)).unwrap();
        assert_eq!(archive.format(), Format::Zip);

        let info = archive.list();
        assert_eq!(info.len(), 2);
        assert_eq!(info[0].name, "a.txt");
        assert_eq!(info[1].name, "b.txt");

        let mut budget = Budget::new(Limits::default());
        let e1 = archive.extract_next(&mut budget).unwrap().unwrap();
        assert_eq!(e1.name, "a.txt");
        assert_eq!(e1.data, b"alpha");

        let e2 = archive.extract_next(&mut budget).unwrap().unwrap();
        assert_eq!(e2.name, "b.txt");
        assert_eq!(e2.data, b"beta");

        assert!(archive.extract_next(&mut budget).unwrap().is_none());
    }

    #[test]
    fn archive_tar_extract_next() {
        let blob = tar_of(&[("x", b"one"), ("y", b"two"), ("z", b"three")]);
        let mut archive = Archive::open(Cursor::new(blob)).unwrap();
        assert_eq!(archive.format(), Format::Tar);

        let mut budget = Budget::new(Limits::default());
        let mut names = Vec::new();
        while let Some(e) = archive.extract_next(&mut budget).unwrap() {
            names.push(e.name);
        }
        assert_eq!(names, vec!["x", "y", "z"]);
    }

    /// A tar's headers ARE its index, so `list` must report them.
    ///
    /// Returning an empty slice here tells a caller the archive holds NOTHING,
    /// which is a different claim from "this format has no directory" and the
    /// wrong one — the names, sizes and offsets are all parsed at `open`, and
    /// `extract` already seeks straight to a member by them.
    #[test]
    fn archive_tar_lists_its_members_without_extracting_them() {
        let blob = tar_of(&[("x", b"one"), ("y", b"two"), ("z", b"three")]);
        let archive = Archive::open(Cursor::new(blob)).unwrap();

        let names: Vec<&str> = archive.list().iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["x", "y", "z"]);
        assert_eq!(archive.list()[2].uncompressed_size, 5);
        // Stored uncompressed, so the two sizes are the same size rather than
        // one of them being left at zero.
        assert_eq!(archive.list()[2].compressed_size, 5);
        assert_eq!(archive.list()[1].index, 1);
    }

    /// The two ways into a ZIP must find the same members.
    ///
    /// A member with a local header and NO central-directory entry is the
    /// classic way to hide one: the directory is what most readers walk, and
    /// the target extracts it anyway. `extract` scans for those; `Archive` walks
    /// the directory through the `zip` crate and does not. Whichever door a
    /// caller comes through, the archive holds what it holds.
    #[test]
    fn archive_finds_the_same_members_as_extract() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/zip/orphan_local.zip");
        let blob = std::fs::read(&path).expect("fixture reads");

        let mut budget = Budget::new(Limits::default());
        let buffered: Vec<String> = extract(Format::Zip, &blob, &mut budget)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();

        let mut archive = Archive::open(Cursor::new(blob)).unwrap();
        let mut budget = Budget::new(Limits::default());
        let mut streamed = Vec::new();
        while let Some(e) = archive.extract_next(&mut budget).unwrap() {
            streamed.push(e.name);
        }

        assert_eq!(buffered, streamed, "the two paths disagree about members");
    }

    /// Listing must account for a member hidden from the central directory, and
    /// must be able to do so without decompressing anything.
    ///
    /// A listing that reports only what the directory admits to is the polite
    /// version of the wrong answer: it is exactly what the archive was built to
    /// obtain. Finding the member and reading it are separate jobs, so the first
    /// costs a header parse — and the index it reports must be the index
    /// `extract` takes, or a caller acting on the listing reaches a different
    /// member than the one it was told about.
    #[test]
    fn archive_lists_a_member_hidden_from_the_central_directory() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/zip/orphan_local.zip");
        let blob = std::fs::read(&path).expect("fixture reads");

        let mut archive = Archive::open(Cursor::new(blob)).unwrap();
        let listed: Vec<(usize, String)> = archive
            .list()
            .iter()
            .map(|m| (m.index, m.name.clone()))
            .collect();
        assert_eq!(
            listed,
            vec![(0, "benign.txt".to_string()), (1, "hidden.txt".to_string())],
        );

        // The index from the listing addresses the member the listing named.
        let mut budget = Budget::new(Limits::default());
        let e = archive.extract(1, &mut budget).unwrap();
        assert_eq!(e.name, "hidden.txt");
    }

    #[test]
    fn archive_extract_by_index() {
        let zip_blob = zip_of(&[("first", b"111"), ("second", b"222"), ("third", b"333")]);
        let mut archive = Archive::open(Cursor::new(zip_blob)).unwrap();
        let mut budget = Budget::new(Limits::default());

        let e = archive.extract(1, &mut budget).unwrap();
        assert_eq!(e.name, "second");
        assert_eq!(e.data, b"222");
    }

    #[test]
    fn archive_extract_all_matches_next() {
        let zip_blob = zip_of(&[("a", b"aa"), ("b", b"bb")]);
        let mut budget1 = Budget::new(Limits::default());
        let mut budget2 = Budget::new(Limits::default());

        // extract_all via extract_next loop
        let mut a1 = Archive::open(Cursor::new(zip_blob.clone())).unwrap();
        let mut all_next = Vec::new();
        while let Some(e) = a1.extract_next(&mut budget1).unwrap() {
            all_next.push((e.name, e.data));
        }

        // extract_all
        let mut a2 = Archive::open(Cursor::new(zip_blob)).unwrap();
        let all = a2.extract_all(&mut budget2).unwrap();
        let all_collected: Vec<_> = all.into_iter().map(|e| (e.name, e.data)).collect();

        assert_eq!(all_next, all_collected);
    }

    #[test]
    fn archive_gzip_extract_next() {
        let blob = gz(b"hello from gzip");
        let mut archive = Archive::open(Cursor::new(blob)).unwrap();
        assert_eq!(archive.format(), Format::Gzip);

        let mut budget = Budget::new(Limits::default());
        let e = archive.extract_next(&mut budget).unwrap().unwrap();
        assert_eq!(e.data, b"hello from gzip");
        assert!(archive.extract_next(&mut budget).unwrap().is_none());
    }

    #[test]
    fn archive_bzip2_extract_next() {
        // Same hardcoded bzip2 stream as bzip2_roundtrip.
        let blob: &[u8] = &[
            66, 90, 104, 57, 49, 65, 89, 38, 83, 89, 213, 127, 182, 220, 0, 0, 5, 25, 128, 64, 0,
            16, 0, 54, 101, 201, 80, 32, 0, 49, 76, 0, 19, 66, 154, 105, 163, 77, 168, 242, 145,
            94, 233, 129, 65, 248, 112, 129, 150, 100, 114, 190, 46, 228, 138, 112, 161, 33, 170,
            255, 109, 184,
        ];
        let mut archive = Archive::open(Cursor::new(blob.to_vec())).unwrap();
        assert_eq!(archive.format(), Format::Bzip2);

        let mut budget = Budget::new(Limits::default());
        let e = archive.extract_next(&mut budget).unwrap().unwrap();
        assert_eq!(e.data, b"hello exav inside bzip2");
        assert!(archive.extract_next(&mut budget).unwrap().is_none());
    }

    #[test]
    fn archive_xz_extract_next() {
        let payload = b"hello exav inside xz";
        let blob = include_bytes!("../tests/fixtures/xz/simple.xz");

        let mut archive = Archive::open(Cursor::new(blob.as_slice())).unwrap();
        assert_eq!(archive.format(), Format::Xz);

        let mut budget = Budget::new(Limits::default());
        let e = archive.extract_next(&mut budget).unwrap().unwrap();
        assert_eq!(e.data, payload);
        assert!(archive.extract_next(&mut budget).unwrap().is_none());
    }

    // Helper: build a ZIP in memory (stored, no compression).
    fn zip_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = ::zip::ZipWriter::new(&mut buf);
            let opts = ::zip::write::SimpleFileOptions::default()
                .compression_method(::zip::CompressionMethod::Stored);
            for (name, data) in members {
                zip.start_file(*name, opts).unwrap();
                zip.write_all(data).unwrap();
            }
            zip.finish().unwrap();
        }
        buf.into_inner()
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
    fn archive_zstd_extract_next() {
        let blob = zstd_of(b"hello from zstd");
        let mut archive = Archive::open(Cursor::new(blob)).unwrap();
        assert_eq!(archive.format(), Format::Zstd);

        let mut budget = Budget::new(Limits::default());
        let e = archive.extract_next(&mut budget).unwrap().unwrap();
        assert_eq!(e.data, b"hello from zstd");
        assert!(archive.extract_next(&mut budget).unwrap().is_none());
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
/// UP FRONT, before decompressing a byte — so an attacker chooses how much
/// memory exav commits. Measured: a 766 KB NSIS installer declaring a 1.5 GB
/// dictionary, which aborted the process under the daemon's per-job address-space
/// limit. Under the daemon that abort closes the client connection with no reply,
/// which a client reads as a clean scan.
///
/// Clamping is free on real streams: LZMA only ever looks back into bytes it has
/// already produced, so a dictionary larger than the output cannot be consulted.
/// The floor keeps a nonsense-small declaration from breaking a legitimate one.
pub(crate) fn bounded_dict(declared: u32, cap: u64) -> u32 {
    const MIN_DICT: u32 = 1 << 12;
    declared.min(cap.min(u32::MAX as u64) as u32).max(MIN_DICT)
}
