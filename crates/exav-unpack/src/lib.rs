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
//! including the vendored PPMd sub-allocators (`formats/ppmd7/`,
//! `formats/ppmd8/`), is 100% safe
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

/// The bounds-checked little-endian cursor of the record readers.
pub mod bytes;
// What a build uses of it depends on the formats with a password it has.
#[cfg(any(
    feature = "gzip",
    feature = "zip",
    feature = "pdf",
    feature = "ole",
    feature = "sevenz",
    feature = "swf",
    feature = "nsis",
    feature = "alz",
    feature = "egg",
    feature = "hwp3",
    feature = "xar",
    feature = "diskimage",
    feature = "upx",
    feature = "dmg",
    feature = "squashfs",
    feature = "cramfs",
    feature = "erofs"
))]
mod inflate;
// Each item is read by a different mix of the `decrypt`, `sevenz`, `dmg` and
// `rar` features, so any build leaves some of them unused.
/// HTML as tokens, and the bytes of a page as text: the one HTML reader of
/// the scanner's text view and the converters. Feature `html`.
#[cfg(feature = "html")]
pub mod html;
#[allow(dead_code)]
mod kdf;
#[cfg(all(test, any(feature = "dmg", feature = "ishieldz")))]
mod oracle;
/// The headers of a PE executable and the file offset of an address in
/// memory, read from a window of the file.
pub mod pe;
mod pe_resource;
pub mod profile;
mod raster;
pub use raster::{Predictor, Raster, RasterCodec, RasterSpace};
pub mod source;
pub mod span;
pub mod spill;
mod stream;
mod text_kind;
mod zip_end;
pub use text_kind::{TextKind, field_name_len, is_message, looks_like_html, text_keeps, text_kind};
/// The text a reader sees in HTML, Office and OpenDocument XML parts, and
/// PDF. Feature `text`.
#[cfg(feature = "text")]
pub mod text;
pub mod tree;
pub mod volume;
/// What BIFF (Excel up to 2003) shares: the built-in function table that
/// formula tokens name by number. Feature `ole`.
#[cfg(feature = "ole")]
pub use formats::biff;
/// BinHex 4.0 text: the header of the file it holds and the start of its data
/// fork. Feature `binhex`.
#[cfg(feature = "binhex")]
pub use formats::binhex;
/// OLE2 compound files: the one reader of Word, Excel and PowerPoint 97 to
/// 2003 files and the like, lenient and bounded. Feature `ole`.
#[cfg(feature = "ole")]
pub use formats::cfb;
/// Text in a Windows code page number, as BIFF records and Office fonts name
/// them. Feature `ole`.
#[cfg(feature = "ole")]
pub use formats::charset;
/// AutoCAD DWG's bit codes, sections and object records, for drawing
/// readers. Feature `dwg`.
#[cfg(feature = "dwg")]
pub use formats::dwg;
/// AutoCAD DXF's pairs, records and strings, for drawing readers. Feature
/// `dxf`.
#[cfg(feature = "dxf")]
pub use formats::dxf;
#[cfg(feature = "pdf")]
pub use formats::has_obfuscated_name_object;
/// Excel workbooks saved with a password (RC4, CryptoAPI, XOR), opened with
/// the default password or those given. Feature `offcrypto`.
#[cfg(feature = "offcrypto")]
pub use formats::offcrypto;
/// Which Office or OpenDocument package a ZIP is, by its member names.
/// Feature `zip`.
#[cfg(feature = "zip")]
pub use formats::office_package::{
    CONTENT_TYPES, Part, has_parts, package_kinds, package_kinds_in, package_kinds_walked,
    package_parts,
};
/// PowerPoint 2 to 4, whose files have no compound structure. Feature `ole`.
#[cfg(feature = "ole")]
pub use formats::old_ppt;
/// RTF's tokenizer, which the scanner's extractor of embedded objects and
/// exav-render's converter both read with. Feature `rtf`.
#[cfg(feature = "rtf")]
pub use formats::rtf;
/// A ZIP's central directory from the last bytes of the file, for a reader
/// that fetches by ranges. Feature `zip`.
#[cfg(feature = "zip")]
pub use formats::zip::{
    Directory, DirectoryLimit, DirectoryMember, TailDirectory, directory_in_tail,
};
#[allow(unused_imports)]
pub(crate) use stream::Region;
pub use stream::{Member, MemberMeta, Mtime, Visit, is_budget_overflow, walk};

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

/// Where a ZIP appended to another file begins, by its end record at the end of
/// the file.
#[cfg(feature = "zip")]
pub use formats::zip::appended_start as appended_zip_start;

/// Without the `zip` feature no ZIP is found.
#[cfg(not(feature = "zip"))]
pub fn appended_zip_start(_src: &dyn ByteSource) -> Option<u64> {
    None
}

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
pub use formats::xz::{XZ_MAX_DICT, declared_dict_size as xz_declared_dict_size};

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

/// The report of a multipart message whose parts were not found, handed over
/// as one part whose bytes are scanned.
#[cfg(feature = "email")]
pub use formats::MULTIPART_NOT_FOUND;

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
// The LZO decoder of SquashFS, exposed for the fuzz target that drives it.
// Diagnostic surface, not part of the stable API: may change in any release.
#[cfg(feature = "squashfs")]
#[doc(hidden)]
pub use formats::lzo::decompress as lzo_decompress;

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
    /// Max output/input size ratio for a single compressed stream, checked
    /// only for a member whose output passes [`Self::max_buffer_bytes`]: below
    /// it a member is held in memory and the memory limits bound it. A member
    /// over the ratio is left out and the walk goes on with the next, ending
    /// with this limit. With `max_buffer_bytes` at `u64::MAX` the ratio never
    /// acts.
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
    /// Cap on the bytes of holes (the unwritten stretches of a sparse file in
    /// a filesystem) handed over as zeros across the scan of one top-level
    /// file. They are charged here instead of to [`Self::max_scanned_bytes`],
    /// so that a large sparse file does not use that up and end the walk
    /// before the rest of the volume. A CPU/time bound: the zeros are still
    /// matched. Default 64 GiB.
    pub max_hole_bytes: u64,
    /// What one run of a bytecode signature may hold in all: its `malloc`s
    /// (a program frees nothing), the frames of its calls in progress, and the
    /// globals it has read. A run that reaches it stops as incomplete. Default
    /// 256 MiB.
    pub max_bytecode_memory_bytes: u64,
    /// Cap on the instructions the PE stub emulator may run across the whole
    /// recursive analysis of one top-level file.
    ///
    /// Each emulation already has its own instruction budget; this bounds their
    /// sum, which otherwise grows with the number of packed executables an
    /// archive carries. A run cut short by it is `LimitsExceeded`.
    pub max_pe_emulation_steps: u64,
    /// Most PE, ELF or Mach-O images carving takes from one object, of each
    /// kind. A further one that validates is left out and the object is not
    /// fully scanned. Default 16. Read by exav-core, which carves.
    pub max_carved_executables: u64,
    /// Most archives carving takes from one object; a further one that
    /// validates is left out and the object is not fully scanned. Default 32.
    /// Read by exav-core, which carves.
    pub max_carved_archives: u64,
    /// Most executables or archives decoded from the base64 runs of one text;
    /// a further one is left out and the text is not fully scanned. Default 8.
    pub max_base64_payloads: u64,
    /// Most base64 runs of one text that start like an executable or an
    /// archive and are decoded to see; a further one is left out and the text
    /// is not fully scanned. Default 64.
    pub max_base64_runs: u64,
    /// Most base64 assets (`data:` URIs, inline images) decoded from one page
    /// of HTML or flat-XML Office; a further one is left out and the page is
    /// not fully scanned. Default 16.
    pub max_page_assets: u64,
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
            // RAM (capped separately by `max_buffer_bytes`),
            // so this can be generous: it exists only to stop re-scanning bombs
            // and runaway scan time, and lets a multi-gigabyte member be fully
            // scanned.
            max_scanned_bytes: 10 * 1024 * 1024 * 1024,
            max_hole_bytes: 64 * 1024 * 1024 * 1024,
            max_bytecode_memory_bytes: 256 * 1024 * 1024,
            // A few seconds to tens of seconds of emulation per top-level file,
            // against the per-stub budget of `formats::pepack`.
            max_pe_emulation_steps: 1_000_000_000,
            max_carved_executables: 16,
            max_carved_archives: 32,
            max_base64_payloads: 8,
            max_base64_runs: 64,
            max_page_assets: 16,
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
    /// Bytes of holes handed over so far (see [`Limits::max_hole_bytes`]).
    pub(crate) holes: u64,
    /// The first member a reader left out for a limit of its own while its
    /// walk went on ([`Budget::skip`]). The walk of the container ends with it
    /// once the other members are visited.
    pub(crate) skipped: Option<LimitHit>,
    /// Emulator instructions spent so far (see [`Limits::max_pe_emulation_steps`]).
    pub(crate) pe_emulation_steps: u64,
    /// PBKDF2 iterations spent so far on RAR5 and disk image passwords, across
    /// every archive of the scan. Atomic because the readers hold the budget by `&`.
    #[cfg_attr(not(feature = "decrypt"), allow(dead_code))]
    pub(crate) kdf_rounds: std::sync::atomic::AtomicU64,
    /// What the scan has spent on 7z key derivations, and the keys it made
    /// ([`kdf`]). A handle, so that a reader can hold it while the budget is
    /// borrowed for something else.
    #[cfg_attr(not(feature = "decrypt"), allow(dead_code))]
    pub(crate) kdf: std::sync::Arc<kdf::Kdf>,
    /// RAR3 key derivations made so far, across every archive of the scan.
    #[cfg_attr(not(feature = "decrypt"), allow(dead_code))]
    pub(crate) rar3_derivations: std::sync::atomic::AtomicUsize,
    /// Candidate passwords tried, in order, when decrypting an encrypted ZIP,
    /// 7z, RAR, ARJ, PDF, DMG or Office member, before the built-in ones a
    /// format has (a PDF's empty user password goes first). Empty by default:
    /// a member no password opens yields an
    /// `Entry::unsupported(encrypted=true, …)` so the scanner reports
    /// `PasswordProtected`. The pool is the union of any `.pwdb` file and
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
    /// Describe the images of a PDF as pixels ([`MemberMeta::raster`]). Off by
    /// default: only a consumer that builds pixels reads them, and describing
    /// one follows references and decodes JBIG2 globals, which count against
    /// the budget. See [`Budget::set_rasters`].
    #[cfg_attr(not(feature = "pdf"), allow(dead_code))]
    pub(crate) rasters: bool,
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
            holes: 0,
            skipped: None,
            pe_emulation_steps: 0,
            kdf_rounds: std::sync::atomic::AtomicU64::new(0),
            kdf: std::sync::Arc::default(),
            rar3_derivations: std::sync::atomic::AtomicUsize::new(0),
            passwords: Vec::new(),
            verify_checksums: false,
            visit_directories: false,
            rasters: false,
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

    /// Describe the images of a PDF as pixels, in [`Entry::raster`] and
    /// [`MemberMeta::raster`] (default off), for a consumer that reads them.
    /// With it off a PDF reader builds no raster, follows no reference for one
    /// and charges nothing for one.
    pub fn set_rasters(&mut self, rasters: bool) -> &mut Self {
        self.rasters = rasters;
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

    /// Charge `n` bytes of holes against [`Limits::max_hole_bytes`].
    pub fn charge_holes(&mut self, n: u64) -> Result<(), LimitHit> {
        self.holes = self.holes.saturating_add(n);
        if self.holes > self.limits.max_hole_bytes {
            return Err(LimitHit::of_kind(
                LimitKind::MaxScanSize,
                format!("hole bytes > {}", self.limits.max_hole_bytes),
            ));
        }
        Ok(())
    }

    /// Bytes of holes still available ([`Limits::max_hole_bytes`] − handed
    /// over).
    pub fn remaining_holes(&self) -> u64 {
        self.limits.max_hole_bytes.saturating_sub(self.holes)
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

    /// Note that a reader left a member out for a limit of that member (not of
    /// the whole walk), so that it goes on with the next one. Only the first is
    /// kept. The walk of the container ends with it once its members are
    /// visited, unless a limit of the whole walk or a stop ends it sooner.
    pub(crate) fn skip(&mut self, reason: std::fmt::Arguments<'_>) {
        if self.skipped.is_none() {
            self.skipped = Some(LimitHit::new(reason.to_string()));
        }
    }

    /// A member larger than `cap`, the room [`Self::reserve`] gave it, of
    /// which `spent` bytes were decoded. They are charged; the member is left
    /// out ([`Self::skip`]) when the per-member limit is what it is over, and
    /// the walk ends when the total is.
    #[allow(dead_code)]
    pub(crate) fn over_cap(
        &mut self,
        cap: u64,
        spent: u64,
        member: std::fmt::Arguments<'_>,
    ) -> Result<(), LimitHit> {
        self.commit(spent);
        let max = self.limits.max_buffer_bytes;
        if cap < max {
            return Err(LimitHit::new(format!(
                "{member}: extracted bytes > {}, the total a scan may hold (exav's \
                 --max-extracted-bytes sets it)",
                self.limits.max_extracted_bytes
            )));
        }
        self.skip(format_args!(
            "{member} is larger than --max-object-bytes {max}"
        ));
        Ok(())
    }

    /// [`Self::reserve`] for a member that its container says decodes to
    /// `size` bytes. When that is over the room, the member is left out before
    /// it is decoded ([`Self::skip`]): nothing is charged, and the walk goes on
    /// with members that fit. `None` then. A member that turns out larger than
    /// it said is still cut at the room ([`Self::over_cap`]).
    #[allow(dead_code)]
    pub(crate) fn reserve_for(
        &mut self,
        size: u64,
        member: std::fmt::Arguments<'_>,
    ) -> Result<Option<u64>, LimitHit> {
        let cap = self.reserve()?;
        if size <= cap {
            return Ok(Some(cap));
        }
        let (max, total) = (
            self.limits.max_buffer_bytes,
            self.limits.max_extracted_bytes,
        );
        match cap < max {
            true => self.skip(format_args!(
                "{member} is larger than what is left of the {total} bytes a scan may hold \
                 (exav's --max-extracted-bytes sets it)"
            )),
            false => self.skip(format_args!(
                "{member} is larger than --max-object-bytes {max}"
            )),
        }
        Ok(None)
    }

    /// Bytes still left in the total a scan may extract.
    pub(crate) fn left(&self) -> u64 {
        self.limits
            .max_extracted_bytes
            .saturating_sub(self.total_out)
    }

    /// Maximum bytes the next member may decompress to: the smaller of the
    /// per-member cap and the bytes still left in the total budget. Fails if
    /// the total budget is already exhausted.
    pub fn reserve(&mut self) -> Result<u64, LimitHit> {
        let remaining = self.left();
        if remaining == 0 {
            return Err(LimitHit::new(format!(
                "extracted bytes > {}, the total a scan may hold (exav's \
                 --max-extracted-bytes sets it)",
                self.limits.max_extracted_bytes
            )));
        }
        Ok(remaining.min(self.limits.max_buffer_bytes))
    }

    pub fn commit(&mut self, n: u64) {
        self.total_out = self.total_out.saturating_add(n);
    }

    /// Charge `n` bytes a reader parsed again against the total a scan may
    /// hold, as if they were extracted: `Err` once it is spent.
    #[cfg_attr(not(feature = "pdf"), allow(dead_code))]
    pub(crate) fn charge_reparsed(&mut self, n: u64) -> Result<(), LimitHit> {
        self.commit(n);
        self.reserve().map(|_| ())
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
pub(crate) fn read_full(src: &mut dyn Read, buf: &mut [u8]) -> Result<usize, LimitHit> {
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
pub(crate) fn read_at(
    src: &mut dyn stream::Disk,
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
    /// What kind of reason `unsupported` is (see [`MemberMeta::reason_kind`]).
    pub reason_kind: Option<tree::ReasonKind>,
    /// When the member was last modified (see [`MemberMeta::mtime`]).
    pub mtime: Option<Mtime>,
    /// Its Unix mode (see [`MemberMeta::mode`]).
    pub mode: Option<u32>,
    /// What describes its bytes as pixels (see [`MemberMeta::raster`]).
    pub raster: Option<Raster>,
    /// Whether the member is a PDF object stream, decoded: the text of the
    /// objects it holds (see [`MemberMeta::object_stream`]).
    pub object_stream: bool,
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

    /// The entry, with `kind` as the kind of its reason.
    #[must_use]
    pub fn of_kind(mut self, kind: tree::ReasonKind) -> Self {
        self.reason_kind = Some(kind);
        self
    }

    /// [`Entry::unsupported`] for a member not read for a size limit: its
    /// reason is that limit.
    #[allow(dead_code)]
    pub(crate) fn over_limit(name: String, comp_size: u64, reason: &'static str) -> Self {
        Self::unsupported(name, comp_size, false, reason).of_kind(tree::ReasonKind::OVER_SIZE)
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
    /// InstallShield setup executable: the installer MSI and the files that go
    /// with it, coded with a key made from their names and mostly inflated.
    /// A build without the `ishieldmsi` feature reports it instead.
    IshieldMsi,
    /// InstallShield InstallScript cabinet (`ISc(`): the files of a cabinet
    /// holding its header; those in other cabinets of the set are reported.
    IshieldCab,
    /// InstallShield Z archive, the older `.z` installer format, decoded.
    IshieldZ,
    /// CryptFF file: a 16-byte header, then the content with every byte
    /// XORed with 0xFF. One member, decoded as it is read.
    CryptFf,
    /// ext2/3/4 filesystem image: walked, files reassembled from their extents.
    Ext,
    /// lrzip stream: recognised so it is reported, not decoded.
    Lrzip,
    /// ZOO archive: LZD and LZH members decoded, CRC-16 checked.
    Zoo,
    /// AppleSingle / AppleDouble file: its data and resource forks.
    AppleSingle,
    /// FAT12/16/32 filesystem, walked, so fragmented files come back whole.
    Fat,
    /// Inno Setup installer (5.1.5 to 6.4.0): the files it holds, as they
    /// are read from its chunks.
    Inno,
    /// NTFS filesystem, walked through the master file table.
    Ntfs,
    /// Zstandard compressed stream.
    Zstd,
    /// Lzip compressed stream.
    Lzip,
    /// LZMA-alone (`.lzma`) compressed stream, as LZMA Utils wrote it.
    Lzma,
    /// RPM package: its install scripts and its payload (a compressed cpio).
    Rpm,
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
    /// AutoCAD DXF drawing, ASCII or binary: the files it embeds in binary
    /// chunks (an OLE2FRAME's object). See [`dxf`] (feature `dxf`).
    Dxf,
    /// AutoCAD DWG drawing, R13 to R2018: its preview images and
    /// the objects its OLE2FRAMEs embed. A drawing of an older release is
    /// one unsupported entry. See [`dwg`] (feature `dwg`).
    Dwg,
    /// exFAT filesystem, walked, so fragmented files come back whole.
    Exfat,
    /// SquashFS 4 image: walked, each block decompressed as it is read.
    Squashfs,
    /// cramfs image: walked, each block inflated as it is read.
    Cramfs,
    /// romfs image: walked, its files being stored as they are.
    Romfs,
    /// EROFS image: walked, files stored plain, in chunks, or compressed with
    /// LZ4, LZMA, DEFLATE or Zstandard.
    Erofs,
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
        Format::Lzma,
        Format::Rpm,
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
        Format::Dxf,
        Format::Dwg,
        Format::Exfat,
        Format::Squashfs,
        Format::Cramfs,
        Format::Romfs,
        Format::Erofs,
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
                Format::Dxf => 66,
                Format::Dwg => 67,
                Format::Lzma => 68,
                Format::Rpm => 69,
                Format::Exfat => 70,
                Format::Squashfs => 71,
                Format::Cramfs => 72,
                Format::Romfs => 73,
                Format::Erofs => 74,
            }
        }
        let mut seen: Vec<u8> = Format::ALL.iter().map(|f| tag(*f)).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            74,
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

/// A second format the object also is, when its first bytes were claimed by
/// `first`, for the formats that leave their own start free: an ISO 9660 image
/// keeps its first 32 KiB for the system area, and an ext volume its first
/// kilobyte for boot code, so either can start with an archive's magic and be
/// mounted all the same.
pub fn also_reads_as(src: &dyn ByteSource, first: Format) -> Option<Format> {
    #[cfg(feature = "iso")]
    if first != Format::Iso && src.window(32769, 5).starts_with(b"CD001") {
        return Some(Format::Iso);
    }
    #[cfg(feature = "ext")]
    if first != Format::Ext && formats::ext::is_volume(src) {
        return Some(Format::Ext);
    }
    let _ = (src, first);
    None
}

/// Whether `data` is a PDF: `%PDF-` and a version digit within its first
/// kilobyte, which is where Acrobat, qpdf, pdfium and pdf.js look. A file with a
/// newline, a byte-order mark or a mail's leftover headers before it is a PDF
/// to every one of them, and offsets in the file count from the header.
fn pdf_header_near_start(data: &[u8]) -> bool {
    // At the start the magic alone has always been enough.
    if data.starts_with(b"%PDF-") {
        return true;
    }
    let head = &data[..data.len().min(1024)];
    memchr::memmem::find_iter(head, b"%PDF-")
        .any(|at| head.get(at + 5).is_some_and(u8::is_ascii_digit))
}

/// Whether `data` begins with a real CAB (Microsoft Cabinet) header: `MSCF`
/// followed by the `reserved1` field, which the MS-CAB spec fixes at zero in
/// every genuine cabinet. The bare 4-byte `MSCF` magic collides with binary data
/// (e.g. inside an ISO), and a false hit routed to the cabinet parser fails deep
/// in string parsing and reports the object `LIMITS-EXCEEDED`; requiring the zero
/// `reserved1` rejects those without dropping any real cabinet.
///
/// Readers do not check `reserved1` (`cabextract` opens a cabinet whose field is
/// anything), so a cabinet is also recognised by what follows it: a size, the
/// offset of the first file entry inside it, and version 1.3, none of which a
/// chance `MSCF` has.
fn is_cab_magic(data: &[u8]) -> bool {
    if !data.starts_with(b"MSCF") || data.len() < 8 {
        return false;
    }
    if data[4..8] == [0, 0, 0, 0] {
        return true;
    }
    let u32_at = |o: usize| {
        data.get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let (Some(size), Some(files)) = (u32_at(8), u32_at(16)) else {
        return false;
    };
    // `versionMinor`, `versionMajor`.
    data.get(24..26) == Some(&[3, 1]) && size >= 36 && (36..=size).contains(&files)
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

/// Whether `data` begins with an ARJ header as ClamAV takes one at the start of
/// a file, by its shape alone, whatever its CRC-32 says: `60 EA`, a size of 1 to
/// 2600 with the header and the 4 bytes after it in `data`, a fixed part of at
/// least 30 bytes (the header's first byte) that leaves room for the two
/// strings, and those, a name and a comment, each ended by a NUL, filling the
/// rest. Measured with clamscan 1.4.3 on archives with each byte of the header
/// changed. It does not look at the security version or the file type; an
/// archive carved out of another file is confirmed by its CRC-32 and its file
/// type instead ([`arj_start`]).
#[cfg(feature = "arj")]
fn is_arj_start(data: &[u8]) -> bool {
    let Some(&[0x60, 0xEA, lo, hi]) = data.get(..4) else {
        return false;
    };
    let size = u16::from_le_bytes([lo, hi]) as usize;
    if !(1..=2600).contains(&size) || data.len() < 8 + size {
        return false;
    }
    let header = &data[4..4 + size];
    let fixed = usize::from(header[0]);
    if fixed < 30 || fixed + 2 > size {
        return false;
    }
    let strings = &header[fixed..];
    strings.iter().filter(|&&b| b == 0).count() == 2 && strings.last() == Some(&0)
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

/// The kind of executable a file starts as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Executable {
    /// `MZ`.
    Pe,
    /// `\x7fELF`.
    Elf,
    /// A thin Mach-O, in either byte order and either word size. The universal
    /// ("fat") magics are not one: that is a container of Mach-Os
    /// ([`Format::Machofat`]), and `CAFEBABE` is also a Java class.
    MachO,
}

/// What kind of executable `head` starts as, if it does: the one list of the
/// magics of an executable, for the typer that looks for a packer in one, the
/// scanner's file types, and the payloads of a page.
pub fn executable_kind(head: &[u8]) -> Option<Executable> {
    if head.starts_with(b"MZ") {
        Some(Executable::Pe)
    } else if head.starts_with(b"\x7fELF") {
        Some(Executable::Elf)
    } else if head.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || head.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || head.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || head.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
    {
        Some(Executable::MachO)
    } else {
        None
    }
}

/// Whether `d` starts with a stand-alone executable / OLE magic (PE `MZ`, ELF,
/// Mach-O, or OLE2/CFB). Cheap prefix test: 6 decoded bytes suffice, so it also
/// gates on just the first few decoded base64 chars. Deliberately excludes bare
/// ZIP (`PK`): a 4-byte match collides too often with base64 noise.
#[cfg(feature = "base64scan")]
fn starts_executable_magic(d: &[u8]) -> bool {
    executable_kind(d).is_some() || d.starts_with(&[0xd0, 0xcf, 0x11, 0xe0])
}

/// Whether `d` starts with the magic of an archive a script or page may carry
/// in base64 (HTML smuggling puts a ZIP in a `data:` URI or an `atob` string):
/// the magics long enough not to turn up by chance, and ZIP's and gzip's, which
/// [`is_archive_payload`] confirms from what follows.
#[cfg(feature = "base64scan")]
fn starts_archive_magic(d: &[u8]) -> bool {
    d.starts_with(b"PK\x03\x04")
        || is_gzip_magic(d)
        || d.starts_with(b"7z\xBC\xAF\x27\x1C")
        || d.starts_with(b"Rar!\x1a\x07")
        || d.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00])
}

/// Whether a fully-decoded blob is an archive worth scanning as one: a magic of
/// [`starts_archive_magic`], and for a ZIP a directory that holds together, so
/// four bytes of coincidence are not enough.
#[cfg(feature = "base64scan")]
fn is_archive_payload(d: &[u8]) -> bool {
    if d.len() < 22 || !starts_archive_magic(d) {
        return false;
    }
    !d.starts_with(b"PK\x03\x04") || zip_directory_is_consistent(d)
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
        return crate::bytes::at(d, e, 4) == Some(b"PE\x00\x00");
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
/// nothing more. Bounded by `cap` per payload and by
/// [`Limits::max_page_assets`] on how many return.
#[cfg(feature = "base64scan")]
pub fn markup_embedded_payloads(src: &dyn ByteSource, cap: u64) -> Vec<Vec<u8>> {
    markup_embedded_payloads_capped(src, cap, Limits::default().max_page_assets).0
}

/// [`markup_embedded_payloads`], at most `most` of them, and whether it stopped
/// at that number with another run behind them that it would have decoded.
#[cfg(feature = "base64scan")]
pub fn markup_embedded_payloads_capped(
    src: &dyn ByteSource,
    cap: u64,
    most: u64,
) -> (Vec<Vec<u8>>, bool) {
    let most = usize::try_from(most).unwrap_or(usize::MAX);
    match src.as_slice() {
        Some(data) => markup_payloads_on(&mut Indexed(data), cap, most),
        None => markup_payloads_on(&mut Stepper::new(src), cap, most),
    }
}

#[cfg(feature = "base64scan")]
fn markup_payloads_on<B: Bytes>(data: &mut B, cap: u64, most: usize) -> (Vec<Vec<u8>>, bool) {
    use base64::Engine;
    /// Shortest base64 run worth decoding; below this it cannot be an asset.
    const MIN_RUN: usize = 64;

    let engine = base64::engine::general_purpose::STANDARD;
    let plain = base64::engine::general_purpose::STANDARD_NO_PAD;
    let is_b64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
    let mut out = Vec::new();
    let mut capped = false;
    let mut i = 0usize;
    let n = data.len();
    while i < n {
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
            Ok(head) if starts_asset_magic(&head) || starts_archive_magic(&head) => {}
            _ => continue,
        }
        // Another run worth decoding, with the number returned already at its
        // limit: the rest of the document is not read.
        if out.len() >= most {
            capped = true;
            break;
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
        // Unpadded or damaged: the characters before any `=`, less a single
        // leftover one, which encodes no whole byte.
        let bare = j - start;
        let decoded = engine
            .decode(&run)
            .or_else(|_| plain.decode(&run[..bare - usize::from(bare % 4 == 1)]));
        if let Ok(dec) = decoded
            && !dec.is_empty()
            && dec.len() as u64 <= cap
            && (!starts_archive_magic(&dec) || is_archive_payload(&dec))
        {
            out.push(dec);
        }
    }
    (out, capped)
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
/// `cap` (per-payload size), [`Limits::max_base64_payloads`] and
/// [`Limits::max_base64_runs`] (decode tries).
#[cfg(feature = "base64scan")]
pub fn base64_payloads(src: &dyn ByteSource, cap: u64) -> Vec<Vec<u8>> {
    let l = Limits::default();
    base64_payloads_capped(src, cap, l.max_base64_payloads, l.max_base64_runs).0
}

/// [`base64_payloads`], at most `most` of them from at most `tries` decodes,
/// and whether it stopped at those limits with another run behind them that it
/// would have decoded.
#[cfg(feature = "base64scan")]
pub fn base64_payloads_capped(
    src: &dyn ByteSource,
    cap: u64,
    most: u64,
    tries: u64,
) -> (Vec<Vec<u8>>, bool) {
    let count = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
    let (most, tries) = (count(most), count(tries));
    match src.as_slice() {
        Some(data) => base64_payloads_on(&mut Indexed(data), cap, most, tries),
        None => base64_payloads_on(&mut Stepper::new(src), cap, most, tries),
    }
}

#[cfg(feature = "base64scan")]
fn base64_payloads_on<B: Bytes>(
    data: &mut B,
    cap: u64,
    most: usize,
    tries: usize,
) -> (Vec<Vec<u8>>, bool) {
    use base64::Engine;
    // A base64-encoded PE is at minimum a few hundred bytes; require a run that
    // decodes to ≥ ~1 KB so we never trial-decode short incidental runs.
    const MIN_RUN: usize = 1400; // base64 chars → ≥ ~1 KB decoded
    let is_b64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
    let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;

    let mut out = Vec::new();
    let mut capped = false;
    let mut attempts = 0;
    let n = data.len();
    let mut i = 0;
    while i < n {
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
            Ok(prefix) if starts_executable_magic(&prefix) || starts_archive_magic(&prefix) => {}
            _ => continue,
        }
        // Another run worth decoding, with the limits already reached: the
        // rest of the text is not read.
        if out.len() >= most || attempts >= tries {
            capped = true;
            break;
        }
        attempts += 1;
        // Whole 4-char groups decode to exactly 3 bytes each, so a run too
        // large to keep is known before it is read.
        if (nb64 / 4 * 3) as u64 > cap {
            continue;
        }
        // Executable-looking: now materialize the run (whitespace stripped) and
        // decode it. The run stops before any `=`, so a padded payload ends in
        // a partial group of 2 or 3 characters holding its last 1 or 2 bytes;
        // a single leftover character encodes no whole byte and is dropped.
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
        if run.len() % 4 == 1 {
            run.pop();
        }
        if let Ok(dec) = engine.decode(&run)
            && dec.len() as u64 <= cap
            && (is_executable_payload(&dec) || is_archive_payload(&dec))
        {
            out.push(dec);
        }
    }
    (out, capped)
}

/// What [`detect`] reads of an object: its start, its length, and windows at
/// the places past the start a check names: the end of the object, and
/// where its structure says ([`Probe::after_image`]).
///
/// No check searches through all of an object: a search is made in the start
/// alone, at most [`DETECT_HEAD`] bytes whether the object is held in memory
/// or not, or in a window at such a place.
pub(crate) struct Probe<'a> {
    /// The object's first [`DETECT_HEAD`] bytes, or all of it when shorter.
    pub(crate) head: &'a [u8],
    pub(crate) len: usize,
    /// The object, when `head` is only its start.
    rest: Option<Rest<'a>>,
    /// The object cannot be read past what `rest` holds (a stream): what a
    /// check asks of the rest is not there.
    partial: bool,
    /// Set when a check asked, of such an object, for what is past it.
    reached: std::cell::Cell<bool>,
}

/// The object whose start a [`Probe`] holds.
#[derive(Clone, Copy)]
enum Rest<'a> {
    Held(&'a [u8]),
    Source(&'a dyn ByteSource),
}

/// Bytes after an executable's image that a check reads, at most: where a
/// self-extractor, an NSIS installer or an AutoIt script of old keeps its
/// data, which the program reads from there.
#[cfg_attr(
    not(any(feature = "autoit", feature = "nsis", feature = "sfx")),
    allow(dead_code)
)]
pub(crate) const AFTER_IMAGE: usize = 1 << 20;

/// Where the image of the PE `window` shows ends (the end of its last
/// section's data), and up to [`AFTER_IMAGE`] bytes from there, when they run
/// past the first `searched` bytes, which a check has searched already.
#[cfg_attr(
    not(any(feature = "autoit", feature = "nsis", feature = "sfx")),
    allow(dead_code)
)]
pub(crate) fn after_image<'w>(
    window: &pe::Window<'w>,
    len: usize,
    searched: usize,
) -> Option<(usize, std::borrow::Cow<'w, [u8]>)> {
    let headers = pe::Headers::read(window)?;
    let end = headers
        .sections
        .iter()
        .map(|s| u64::from(s.raw_pointer) + u64::from(s.raw_size))
        .max()?;
    let end = usize::try_from(end).ok()?;
    if end >= len || end.saturating_add(AFTER_IMAGE) <= searched {
        return None;
    }
    Some((end, window(end, AFTER_IMAGE)))
}

/// What [`detect_head`] makes of the start of an object whose rest cannot be
/// read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// The start says it is this format.
    Is(Format),
    /// No check could have found it a container: none asked for the rest.
    Not,
    /// Not a format the start says, and a check that reads the rest of an
    /// object (a footer, an end record, a search through it) would have run:
    /// whether it is a container is not known.
    Unsettled,
}

impl<'a> Probe<'a> {
    /// An object held in memory.
    pub(crate) fn whole(data: &'a [u8]) -> Self {
        Probe {
            head: &data[..data.len().min(DETECT_HEAD)],
            len: data.len(),
            rest: (data.len() > DETECT_HEAD).then_some(Rest::Held(data)),
            partial: false,
            reached: std::cell::Cell::new(false),
        }
    }

    /// The start of an object that cannot be read any further.
    fn start(head: &'a [u8]) -> Self {
        Probe {
            // As long as an object can be: the checks that read its end ask
            // for what is past `head`, and are told so.
            len: usize::MAX,
            rest: Some(Rest::Held(head)),
            partial: true,
            ..Probe::whole(head)
        }
    }

    /// Up to `n` bytes of the object from `off`.
    pub(crate) fn window(&self, off: usize, n: usize) -> std::borrow::Cow<'a, [u8]> {
        let held = match self.rest {
            Some(Rest::Source(src)) => return src.window(off, n),
            Some(Rest::Held(data)) => data,
            None => self.head,
        };
        if self.partial && off.saturating_add(n) > held.len() {
            self.reached.set(true);
        }
        ByteSource::window(held, off, n)
    }

    /// [`Self::head`], for a check that searches it: of an object that cannot
    /// be read further, a start shorter than [`DETECT_HEAD`] is not all that
    /// such a search reads.
    #[cfg(any(
        feature = "screnc",
        feature = "autoit",
        feature = "nsis",
        feature = "sfx"
    ))]
    pub(crate) fn searched_start(&self) -> &'a [u8] {
        if self.partial && self.head.len() < DETECT_HEAD {
            self.reached.set(true);
        }
        self.head
    }

    /// [`after_image`] of the object: the bytes after an executable's image,
    /// and their offset, when they run past [`Self::head`].
    #[cfg(any(feature = "autoit", feature = "nsis", feature = "sfx"))]
    pub(crate) fn after_image(&self) -> Option<(usize, std::borrow::Cow<'_, [u8]>)> {
        after_image(&|off, n| self.window(off, n), self.len, self.head.len())
    }
}

/// Bytes of an object's start the checks read, and the most a check searches:
/// past them a check reads only the end of the object and the places its
/// structure names (Inno Setup's loader table through the executable's
/// resources, [`after_image`]). InstallShield's marker is looked for in the
/// first 4 MiB, and its fixed record lies past the marker.
pub(crate) const DETECT_HEAD: usize = 4 * 1024 * 1024 + 1024;

/// Best-effort recognition of a container by magic bytes. Detection is
/// recognition-only: it reports what the bytes look like under the Cargo
/// features compiled in, not what any build could extract. A format behind a
/// disabled feature (CHM, FAT, ARC, among others) returns `None` rather than
/// reaching extraction as `unsupported`.
///
/// Reads the object's start (its first 4 MiB), its end, and the places past
/// its start that its structure names: never all of it, held in memory or not.
pub fn detect(src: &dyn ByteSource) -> Option<Format> {
    if let Some(data) = src.as_slice() {
        return detect_probe(&Probe::whole(data));
    }
    // The first checks need a few bytes, so an archive typed by them is not
    // read `DETECT_HEAD` deep: over a network or browser reader that is most
    // of a small archive. Only those `detect_probe` makes first: a later one,
    // such as RAR's, could be overruled by an earlier check that needs more.
    if let Some(fmt) = archive_magic(&src.window(0, 32)) {
        return Some(udif_or(fmt, src.len(), |off| {
            src.window(off, 12).into_owned()
        }));
    }
    let head = src.window(0, DETECT_HEAD);
    if head.len() == src.len() {
        return detect_probe(&Probe::whole(&head));
    }
    detect_probe(&Probe {
        head: &head,
        len: src.len(),
        rest: Some(Rest::Source(src)),
        partial: false,
        reached: std::cell::Cell::new(false),
    })
}

/// [`detect`] for the start of an object that cannot be read any further, a
/// member decoded as it is read: `head` is what has been read, and the
/// checks that read the end of an object or search through it have nothing to
/// read. Where one of them would have run, the answer is
/// [`Settled::Unsettled`] rather than "not a container".
///
/// A format the start says it is wins, whatever such a check would have said.
pub fn detect_head(head: &[u8]) -> Settled {
    let probe = Probe::start(head);
    settled(detect_probe(&probe), probe.reached.get())
}

/// What a check that found `format` (or none), when it did or did not ask for
/// what is past the start, says of the object.
fn settled(format: Option<Format>, reached: bool) -> Settled {
    match format {
        Some(format) => Settled::Is(format),
        None if reached => Settled::Unsettled,
        None => Settled::Not,
    }
}

/// The formats [`detect`] gives for a string it finds in an object, not for a
/// header at its start: Script Encoder, XDP, BinHex, AutoIt, and a PDF header
/// in the first kilobyte.
pub fn is_found_by_string(format: Format) -> bool {
    matches!(
        format,
        Format::Screnc | Format::Xdp | Format::Binhex | Format::Autoit | Format::Pdf
    )
}

/// For a format [`detect`] finds by a string, whether `head`, the start of an
/// object, is what a file of that format looks like: Script Encoder's marker
/// and BinHex's marker line first, XDP's `<xdp:xdp` root, AutoIt's marker
/// after the script GUID. A text that only holds the string is not, and a PDF
/// header counts only at the first byte. `false` for any other format.
pub fn string_is_header(format: Format, head: &[u8]) -> bool {
    match format {
        #[cfg(feature = "screnc")]
        Format::Screnc => head.starts_with(formats::SCRENC_MARKER),
        #[cfg(feature = "binhex")]
        Format::Binhex => formats::binhex_marker_first(head),
        #[cfg(feature = "xdp")]
        Format::Xdp => formats::has_adobe_root(head),
        #[cfg(feature = "autoit")]
        Format::Autoit => !formats::autoit_marker_first(head),
        Format::Pdf => head.starts_with(b"%PDF-"),
        _ => {
            let _ = head;
            false
        }
    }
}

/// Whether the InstallShield installer in `src` (typed [`Format::IshieldMsi`])
/// has the header of InstallShield 2015 and later, `ISSetupStream\0`, which
/// clamscan 1.4.3 does not open, as it does the header of 2009 to 2011.
pub fn is_ishield_setup_stream(src: &dyn ByteSource) -> bool {
    let head = src.window(0, src.len().min(DETECT_HEAD));
    matches!(
        formats::sniff::ishield_msi_at(&head),
        Some((_, formats::sniff::IshieldHeader::Stream))
    )
}

/// The archive `src` starts with, among those whose magic is at offset 0 and
/// is checked from its first bytes alone (ZIP, gzip, 7z, xz, bzip2, CAB, RAR,
/// ARJ), as [`detect`] would type it: what an archive carved out of another
/// object at its magic needs confirmed, without a search through the rest.
pub fn detect_archive_start(src: &dyn ByteSource) -> Option<Format> {
    let head = src.window(0, 32);
    archive_magic(&head)
        .or_else(|| is_rar_magic(&head).then_some(Format::Rar))
        .or_else(|| arj_start(src, &head))
}

/// [`Format::Arj`] when `src` starts with a main header (file type 2) whose
/// CRC-32 holds. The header runs past `head`, so it is read in full only once
/// its two magic bytes are there. Each file of the archive has a header with
/// the same magic and a CRC too: only the main header starts an archive, or
/// every member would be one carved out of its own archive.
#[cfg(feature = "arj")]
fn arj_start(src: &dyn ByteSource, head: &[u8]) -> Option<Format> {
    // Magic, size, the header at most 2600 bytes long, its CRC-32.
    const MAX_MAIN_HEADER: usize = 4 + 2600 + 4;
    const FILE_TYPE: usize = 10;
    if !head.starts_with(&[0x60, 0xEA]) {
        return None;
    }
    let header = src.window(0, MAX_MAIN_HEADER);
    (is_arj_magic(&header) && header.get(FILE_TYPE) == Some(&2)).then_some(Format::Arj)
}

#[cfg(not(feature = "arj"))]
fn arj_start(_: &dyn ByteSource, _: &[u8]) -> Option<Format> {
    None
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

/// `fmt`, the magic an object `len` bytes long starts with, or a DMG when that
/// magic is bzip2's or xz's and the object ends in a UDIF `koly` trailer:
/// hdiutil writes UDBZ and ULMO images with the data fork, so the file,
/// opening on its first bzip2 or xz run. `read(off)` reads 12 bytes at `off`,
/// and only for those two magics.
fn udif_or(fmt: Format, len: usize, read: impl FnOnce(usize) -> Vec<u8>) -> Format {
    #[cfg(feature = "dmg")]
    if matches!(fmt, Format::Bzip2 | Format::Xz)
        && len >= 512
        && formats::dmg::is_koly(&read(len - 512))
    {
        return Format::Dmg;
    }
    #[cfg(not(feature = "dmg"))]
    let _ = (len, read);
    fmt
}

/// The first header of a tar from before `ustar` (V7), which has no magic:
/// a name, octal mode and size, and a checksum of the header that is right.
fn is_v7_tar(data: &[u8]) -> bool {
    let Some(h) = data.get(..512) else {
        return false;
    };
    let octal = |f: &[u8]| {
        let t = f
            .iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect::<Vec<u8>>();
        let t = t.trim_ascii();
        (!t.is_empty() && t.iter().all(|b| (b'0'..=b'7').contains(b))).then(|| {
            t.iter().fold(0u64, |a, b| {
                a.wrapping_mul(8).wrapping_add(u64::from(b - b'0'))
            })
        })
    };
    if h[0] == 0 || octal(&h[100..108]).is_none() || octal(&h[124..136]).is_none() {
        return false;
    }
    let Some(sum) = octal(&h[148..156]) else {
        return false;
    };
    let field = 148..156;
    let unsigned: u64 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| if field.contains(&i) { 32 } else { u64::from(b) })
        .sum();
    let signed: i64 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if field.contains(&i) {
                32
            } else {
                i64::from(b as i8)
            }
        })
        .sum();
    sum == unsigned || i64::try_from(sum).is_ok_and(|s| s == signed)
}

fn is_rar_magic(data: &[u8]) -> bool {
    data.starts_with(b"Rar!\x1a\x07\x00") || data.starts_with(b"Rar!\x1a\x07\x01\x00")
}

fn detect_probe(p: &Probe) -> Option<Format> {
    // The magic of an archive at the start of the object. A bzip2 or xz one is
    // a disk image when the object ends in a UDIF trailer, which is read from
    // the end.
    let data = p.head;
    if let Some(fmt) = archive_magic(data) {
        return Some(udif_or(fmt, p.len, |off| p.window(off, 12).into_owned()));
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
    if is_v7_tar(data) {
        return Some(Format::Tar);
    }
    #[cfg(feature = "arj")]
    if is_arj_start(data) || is_arj_magic(data) {
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
    if formats::sniff::is_in(p, Format::Squashfs) {
        return Some(Format::Squashfs);
    }
    if formats::sniff::is_in(p, Format::Cramfs) {
        return Some(Format::Cramfs);
    }
    if formats::sniff::is_in(p, Format::Romfs) {
        return Some(Format::Romfs);
    }
    if formats::sniff::is_in(p, Format::Erofs) {
        return Some(Format::Erofs);
    }
    // FAT before the partition check: a volume boot record and an MBR both end
    // in `55 AA`, and the filesystem is the more specific answer.
    #[cfg(feature = "fat")]
    if formats::fat::is_fat(data) {
        return Some(Format::Fat);
    }
    #[cfg(feature = "exfat")]
    if formats::exfat::is_exfat(data) {
        return Some(Format::Exfat);
    }
    if formats::sniff::is_in(p, Format::Ntfs) {
        return Some(Format::Ntfs);
    }
    // ARC starts with 0x1A and a method byte, only two bytes, so its name field
    // is checked as well (`is_arc`); it comes after the stronger magics above.
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
    if data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) || formats::sniff::zstd_after_skippable(data) {
        return Some(Format::Zstd);
    }
    if data.starts_with(b"!<arch>\n") {
        return Some(Format::Ar);
    }
    if data.starts_with(b"LZIP") {
        return Some(Format::Lzip);
    }
    if formats::sniff::is_in(p, Format::Lzma) {
        return Some(Format::Lzma);
    }
    if formats::sniff::is_in(p, Format::Rpm) {
        return Some(Format::Rpm);
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
    // An InstallShield installer: a PE whose payload the generic SFX carve
    // would mis-slice. Ahead of the checks that search the whole object for a
    // marker.
    if formats::sniff::is_in(p, Format::IshieldMsi) {
        return Some(Format::IshieldMsi);
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
    // DXF: the binary sentinel, or a `0`/`SECTION` pair after comments.
    #[cfg(feature = "dxf")]
    if dxf::looks_like_dxf(data) {
        return Some(Format::Dxf);
    }
    // DWG: a version ID, then section locators ending with their sentinel
    // (R13 to R2000), an encrypted file header that decrypts (R2004 on) or
    // a Reed-Solomon coded one that decodes (R2007). A release before R13
    // too, which extraction reports as unsupported.
    #[cfg(feature = "dwg")]
    if dwg::looks_like_dwg(data) || dwg::pre_r13_version(data).is_some() {
        return Some(Format::Dwg);
    }
    // Windows Shell Link (.lnk): fixed 20-byte prefix (HeaderSize 0x4C + CLSID).
    #[cfg(feature = "lnk")]
    if data.starts_with(&[
        0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
    ]) {
        return Some(Format::Lnk);
    }
    // Python `.pyc`: a number CPython has written, then `\r\n`.
    #[cfg(feature = "pyc")]
    if formats::pyc::is_pyc(data) {
        return Some(Format::Pyc);
    }
    // NSIS installer: PE stub + the NullsoftInst firstheader. It requires an MZ
    // start, so it only claims a PE that is actually NSIS.
    #[cfg(feature = "nsis")]
    if is_nsis(p) {
        return Some(Format::Nsis);
    }
    // What is told by a few bytes at a fixed place and the fields around
    // them, which another format can hold by chance in its data: the ext
    // superblock (at 1024), an LHA header (`-lh5-` and the like at bytes 2 to
    // 6, and the fields of its level) and the MBR `55 AA` signature (which
    // `is_partition` only accepts with a plausible entry). An executable is
    // neither of the first two. After every rule above, and before those that
    // search the object: a disk image holds the files it holds.
    let exe = data.starts_with(b"MZ") || data.starts_with(b"\x7fELF");
    if !exe && formats::sniff::is_in(p, Format::Ext) {
        return Some(Format::Ext);
    }
    if !exe && formats::sniff::is_in(p, Format::Lha) {
        return Some(Format::Lha);
    }
    #[cfg(feature = "partition")]
    if is_partition(p) {
        return Some(Format::Partition);
    }
    // Compiled AutoIt3: the AU3!EA05/EA06 marker after the script GUID, anywhere
    // in the object (embedded in a PE), or the marker at its start.
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
    // Self-extracting archive (PE/ELF stub + appended archive). After NSIS (more
    // specific) and only when a bare archive isn't at offset 0.
    #[cfg(feature = "sfx")]
    if looks_like_sfx(p) {
        return Some(Format::Sfx);
    }
    // After every header check above: a tar or a disk image holds a PDF in its
    // first kilobyte as a member, which is not the file's own header.
    if pdf_header_near_start(data) {
        return Some(Format::Pdf);
    }
    // A ZIP behind a script line or padding, found by its end record.
    // The walker reads such an archive (`open_archive`'s prepended case).
    #[cfg(feature = "zip")]
    if formats::sniff::prefixed_zip(p) {
        return Some(Format::Zip);
    }
    // The rest are texts told by a string they hold, the shortest last. Each
    // finds it in the object's first kilobytes or all through it, so whatever
    // has a header of its own or a structure is typed before them.
    //
    // BinHex 4.0: a marker line (no byte-0 magic) in the first kilobyte.
    #[cfg(feature = "binhex")]
    if looks_like_binhex(data) {
        return Some(Format::Binhex);
    }
    // Adobe XDP: XML wrapping a base64-encoded PDF.
    #[cfg(feature = "xdp")]
    if looks_like_xdp(data) {
        return Some(Format::Xdp);
    }
    // Microsoft Script Encoder: the `#@~^` marker (VBScript/JScript.Encode),
    // anywhere in the object.
    #[cfg(feature = "screnc")]
    if looks_like_screnc(p) {
        return Some(Format::Screnc);
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

    #[test]
    fn an_executable_is_a_pe_an_elf_or_a_thin_mach_o_and_nothing_else() {
        assert_eq!(executable_kind(b"MZ\x90\0"), Some(Executable::Pe));
        assert_eq!(executable_kind(b"\x7fELF"), Some(Executable::Elf));
        for magic in [
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xfe, 0xed, 0xfa, 0xce],
        ] {
            assert_eq!(
                executable_kind(&magic),
                Some(Executable::MachO),
                "{magic:x?}"
            );
        }
        // A universal binary is a container of them, and `CAFEBABE` is also
        // a Java class; a compound file, a ZIP and text are none.
        for head in [
            &[0xca, 0xfe, 0xba, 0xbe][..],
            &[0xca, 0xfe, 0xba, 0xbf],
            &[0xd0, 0xcf, 0x11, 0xe0],
            b"PK\x03\x04",
            b"M",
            b"",
        ] {
            assert_eq!(executable_kind(head), None, "{head:x?}");
        }
    }

    /// The marker of a compiled AutoIt script after the script GUID.
    fn autoit_marker(marker: &[u8]) -> Vec<u8> {
        let mut v = vec![
            0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6,
            0x48, 0x7D,
        ];
        v.extend_from_slice(marker);
        v
    }

    fn same(data: &[u8], what: &str) -> Option<Format> {
        let cache = BlockCache::with_sizes(Cursor::new(data.to_vec()), 4093, 64 * 4093).unwrap();
        let want = detect(&data);
        assert_eq!(detect(&cache), want, "{what}");
        want
    }

    /// An Inno Setup installer is told by its loader table in the resources
    /// of the executable, not by the bytes before it: a stub padded past the
    /// start that detection reads is still one, held in memory or read through
    /// a cache, and the same executable without the table is not.
    #[test]
    fn an_inno_stub_padded_past_the_probed_start_is_still_typed() {
        for raw in [0x400, BIG, 3 * BIG] {
            let stub = pe_resource::tests::inno_stub(raw);
            assert!(stub.len() > DETECT_HEAD || raw == 0x400);
            assert_eq!(
                same(&stub, "stub"),
                Some(Format::Inno),
                "resources at {raw}"
            );
        }
        // The marker is not the table: it is not looked for outside the
        // resource, wherever it is.
        let mut bare = vec![0u8; 3 * BIG];
        bare[..2].copy_from_slice(b"MZ");
        bare[100..106].copy_from_slice(b"rDlPtS");
        bare[1000..1021].copy_from_slice(b"Inno Setup Setup Data");
        assert_ne!(same(&bare, "bare"), Some(Format::Inno));
    }

    /// Four bytes that a search for the Script Encoder marker finds, in the
    /// stub or after it, do not make an installer anything else.
    #[test]
    fn an_inno_installer_holding_the_script_encoder_marker_is_still_one() {
        for raw in [0x400, BIG] {
            let stub = pe_resource::tests::inno_stub(raw);
            for at in [10, stub.len() - 8] {
                let mut marked = stub.clone();
                marked[at..at + 4].copy_from_slice(b"#@~^");
                assert_eq!(same(&marked, "marked"), Some(Format::Inno), "{raw} {at}");
            }
            let mut after = stub.clone();
            after.extend_from_slice(b"#@~^");
            assert_eq!(same(&after, "after"), Some(Format::Inno), "{raw}");
        }
    }

    fn fixtures(dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let path = e.path();
            if path.is_dir() {
                fixtures(&path, out);
            } else if let Ok(data) = std::fs::read(&path)
                && data.len() < 8 << 20
            {
                out.push((path.display().to_string(), data));
            }
        }
    }

    /// A source that notes the bytes read of it.
    struct Noted {
        data: Vec<u8>,
        read: std::cell::RefCell<Vec<(usize, usize)>>,
    }

    impl ByteSource for Noted {
        fn len(&self) -> usize {
            self.data.len()
        }

        fn window(&self, off: usize, len: usize) -> std::borrow::Cow<'_, [u8]> {
            let w = ByteSource::window(&self.data[..], off, len);
            self.read.borrow_mut().push((off, off + w.len()));
            w
        }

        fn identity(&self) -> (usize, usize) {
            ByteSource::identity(&self.data[..])
        }
    }

    impl Noted {
        /// How many bytes of it were read, each counted once.
        fn bytes_read(&self) -> usize {
            let mut ranges = self.read.borrow().clone();
            ranges.sort();
            let (mut total, mut end) = (0, 0);
            for (from, to) in ranges {
                let from = from.max(end);
                if to > from {
                    total += to - from;
                    end = to;
                }
            }
            total
        }
    }

    /// Detection reads an object's start, its end, and the bytes after an
    /// executable's image, never all of it: the bytes it reads do not grow
    /// with the object, whatever markers lie past the start (each check
    /// that searches looks for its own in the start alone).
    #[test]
    fn detection_reads_the_start_the_end_and_the_places_the_structure_names() {
        const LEN: usize = 32 << 20;
        // The start, the end the end checks read, the window after an image,
        // and the headers and directories a structure names.
        const MOST: usize = DETECT_HEAD + (64 << 10) + 64 + AFTER_IMAGE + (64 << 10);
        let markers: [&[u8]; 6] = [
            b"#@~^AAAAAA==",
            b"\xEF\xBE\xAD\xDENullsoftInst",
            b"PK\x03\x04local",
            b"Rar!\x1a\x07\x00",
            b"\0\0\0\0UPX!",
            b"\n end \n",
        ];
        let plant = |data: &mut Vec<u8>, from: usize| {
            for (k, m) in markers.iter().enumerate() {
                let at = from + k * 4096;
                data[at..at + m.len()].copy_from_slice(m);
            }
        };
        let mut objects = Vec::new();
        // A plain object, an executable of no image, and a text.
        for start in [&b"...."[..], b"MZ\0\0", b"begin 644 x\n"] {
            let mut data = vec![b'.'; LEN];
            data[..start.len()].copy_from_slice(start);
            plant(&mut data, DETECT_HEAD + 100);
            plant(&mut data, LEN / 2);
            objects.push(data);
        }
        // An executable whose image ends past the start, with markers past
        // the window after it.
        let mut pe = crate::pe_resource::tests::pe_with_resource(DETECT_HEAD + 512, 10, 1, b"x");
        let end = pe.len();
        pe.resize(LEN, b'.');
        plant(&mut pe, end + AFTER_IMAGE + 100);
        objects.push(pe);
        for (i, data) in objects.into_iter().enumerate() {
            let noted = Noted {
                data,
                read: Default::default(),
            };
            detect(&noted);
            is_upx_source(&noted);
            let read = noted.bytes_read();
            assert!(read <= MOST, "object {i}: {read} bytes read of {LEN}");
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

        // Markers past the start, which no check searches for there, and the
        // checks of its end and of the bytes after an executable's image.
        let far = |head: &[u8], marker: &[u8], tail: &[u8]| {
            let mut v = head.to_vec();
            v.resize(BIG, b'.');
            v.extend_from_slice(marker);
            v.extend_from_slice(tail);
            v
        };
        let after_image = |marker: &[u8]| {
            let mut v = crate::pe_resource::tests::pe_with_resource(BIG, 10, 1, b"x");
            v.resize(v.len() + 100, 0);
            v.extend_from_slice(marker);
            v.resize(v.len() + 200, 0);
            v
        };
        let nsis_sig = [
            0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n',
            b's', b't',
        ];
        // A UDIF trailer's signature, version and size.
        let koly = [b"koly".as_slice(), &[0, 0, 0, 4, 0, 0, 2, 0]].concat();
        // Each case needs its format's detection compiled in.
        let cases: Vec<(Vec<u8>, Option<Format>, bool)> = vec![
            (far(b"", b"#@~^AAAAAA==", b""), None, true),
            (far(b"", &autoit_marker(b"AU3!EA06"), b""), None, true),
            (far(b"MZ", &nsis_sig, b""), None, true),
            (far(b"MZ", b"PK\x03\x04", b""), None, true),
            (
                after_image(&autoit_marker(b"AU3!EA05")),
                Some(Format::Autoit),
                cfg!(feature = "autoit"),
            ),
            (
                after_image(&nsis_sig),
                Some(Format::Nsis),
                cfg!(feature = "nsis"),
            ),
            (
                after_image(b"PK\x03\x04"),
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
            // A UDIF image opening with its first bzip2 or xz run: the
            // trailer outranks the magic, which alone stays a bare stream.
            (
                far(b"BZh91AY&SY", &koly, &[0; 500]),
                Some(Format::Dmg),
                cfg!(feature = "dmg"),
            ),
            (
                far(b"\xFD7zXZ\0", &koly, &[0; 500]),
                Some(Format::Dmg),
                cfg!(feature = "dmg"),
            ),
            (
                far(b"BZh91AY&SY", b"koly", &[0; 508]),
                Some(Format::Bzip2),
                true,
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
pub(crate) type Sink<'a> = &'a mut dyn FnMut(Entry, &mut Budget) -> Option<Stop>;

/// Why an extraction stopped before its last member: the visitor said so (`Ok`)
/// or a limit was hit while it ran (`Err`). One type for every extractor, so
/// each is compiled once.
pub(crate) type Stop = Result<(), LimitHit>;

/// What an extractor returns.
pub(crate) type Extracted = Result<Option<Stop>, LimitHit>;

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
pub(crate) fn dispatch_extract(
    fmt: Format,
    data: &[u8],
    budget: &mut Budget,
    visit: Sink,
) -> Extracted {
    match fmt {
        // A ZIP whose central directory will not parse: the directory it has,
        // then the local-header salvage.
        #[cfg(feature = "zip")]
        Format::Zip => extract_zip(data, budget, visit),
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
        Format::IshieldMsi | Format::Lrzip => {
            formats::reported::extract_reported(fmt, data, budget, visit)
        }
        #[cfg(feature = "zoo")]
        Format::Zoo => formats::zoo::extract_zoo(data, budget, visit),
        #[cfg(feature = "ishieldz")]
        Format::IshieldZ => formats::ishield_z::extract_ishield_z(data, budget, visit),
        #[cfg(feature = "stuffit")]
        Format::StuffIt => formats::stuffit::extract_stuffit(data, budget, visit),
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
        #[cfg(feature = "dxf")]
        Format::Dxf => formats::dxf::extract_dxf(data, budget, visit),
        #[cfg(feature = "dwg")]
        Format::Dwg => formats::dwg::extract_dwg(data, budget, visit),
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
fn not_compiled_in(fmt: Format, data: &[u8], budget: &mut Budget, visit: Sink) -> Extracted {
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
pub(crate) fn emit_collected(entries: Vec<Entry>, budget: &mut Budget, visit: Sink) -> Extracted {
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
    let mut failed = None;
    walk::<()>(
        fmt,
        src,
        budget,
        &mut |meta, content, budget| match read_entry(meta, content, budget) {
            Ok(entry) => {
                out.push(entry);
                None
            }
            Err(hit) => {
                failed = Some(hit);
                Some(())
            }
        },
    )?;
    match failed {
        Some(hit) => Err(hit),
        None => Ok(out),
    }
}

/// A member [`walk`] handed over, as an [`Entry`]: a streamed one is read
/// whole under the bound a member decoded whole has ([`Budget::reserve`]), and
/// a limit it reaches is the error. A member that failed to decode part way
/// keeps the bytes before the failure and is marked `unsupported`.
pub fn read_entry(
    meta: &MemberMeta,
    content: Option<Member<'_>>,
    budget: &mut Budget,
) -> Result<Entry, LimitHit> {
    let mut entry = Entry {
        name: meta.name.clone(),
        data: Vec::new(),
        comp_size: meta.comp_size,
        encrypted: meta.encrypted,
        unsupported: meta.unsupported,
        reason_kind: meta.reason_kind,
        mtime: meta.mtime,
        mode: meta.mode,
        raster: meta.raster.clone(),
        object_stream: meta.object_stream,
    };
    if let Some(content) = content {
        let (data, partial) = content.into_bytes(meta, budget)?;
        entry.data = data;
        if partial && entry.unsupported.is_none() {
            entry.unsupported =
                Some("member failed to decode part way; the bytes before the failure are kept");
        }
    }
    Ok(entry)
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

/// What a cabinet's header says of its place in a set of them: the cabinet
/// before it and the one after it, by the names the header gives (labels, for
/// a caller to match against the names it was given: nothing here opens
/// one), its number in the set and the set's. `None` for a cabinet that is not
/// one of several.
#[cfg(feature = "cab")]
pub fn cab_links(cabinet: &[u8]) -> Option<CabLinks> {
    formats::cab_join::links(cabinet)
}

/// The cabinets of one set, in order, as the one cabinet they were cut from:
/// what [`walk`] reads as [`Format::Cab`]. A folder or a file that runs from
/// one cabinet into the next is read whole that way, where one cabinet at a
/// time it is cut short. `Err` says what does not fit the set.
#[cfg(feature = "cab")]
pub fn join_cab_volumes(cabinets: &[&[u8]]) -> Result<Vec<u8>, String> {
    formats::cab_join::join(cabinets)
}

#[cfg(feature = "cab")]
pub use formats::cab_join::Links as CabLinks;

/// True if `data` looks like a UPX-packed executable (a valid `PackHeader` is
/// present in its start, where UPX writes it). Used by callers whose file-type
/// classifier already recognises PE/ELF/Mach-O and wants to additionally
/// unpack UPX.
pub fn is_upx(data: &[u8]) -> bool {
    is_upx_start(&data[..data.len().min(DETECT_HEAD)], data.len())
}

/// [`is_upx`] of the object `src`, from its start alone.
pub fn is_upx_source(src: &dyn ByteSource) -> bool {
    let len = src.len();
    is_upx_start(&src.window(0, len.min(DETECT_HEAD)), len)
}

/// [`is_upx`] of an object of `len` bytes that starts with `start`.
fn is_upx_start(start: &[u8], len: usize) -> bool {
    #[cfg(feature = "upx")]
    {
        // Both layouts the unpacker handles: the `l_info` chain, and a bare
        // PackHeader. Gating on `find_packheader` alone meant a PackHeader-only
        // image (a routine shape for packed malware) reached no unpacker at
        // all and scanned clean.
        formats::find_packheader_in(start, len).is_some()
            || formats::has_packheader_layout_in(start, len)
    }
    #[cfg(not(feature = "upx"))]
    {
        let _ = (start, len);
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
/// Enforced only for an output past [`Limits::max_buffer_bytes`]: below it a
/// member is held in memory and the memory limits bound it, while a bare ratio
/// trips on ordinary content: a 1 KB-compressed blank scanned page (1 MB of one
/// byte) has a ratio over 1000:1 without being anyone's bomb. The streaming
/// reader applies the same bound as it reads (`stream::ratio_cap`).
// Dead only in a build with none of the formats that call it; see
// `cap_prealloc` for why the feature list is not spelled out.
#[allow(dead_code)]
pub(crate) fn ratio_guard(input: u64, output: u64, budget: &Budget) -> Result<(), LimitHit> {
    if output > budget.limits.max_buffer_bytes
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
/// build has neither compiled in. Real-malware samples, which are never
/// committed, are the exception (see [`read_fixture`]).
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
/// When neither exists, `<path>.zip` is read as a real-malware sample: never
/// committed, kept locally as a ZIP with its one member AES-encrypted under
/// the password `infected` (MalwareBazaar's convention), and decrypted here in
/// memory. A build without the `zip` and `decrypt` features cannot open it and
/// returns an `Unsupported` error.
///
/// Test support, not part of the stable API: may change in any release.
#[doc(hidden)]
pub fn read_fixture(path: &str) -> std::io::Result<Vec<u8>> {
    let masked = format!("{path}.xor");
    if std::fs::exists(&masked)? {
        return Ok(unmask_fixture(&std::fs::read(&masked)?));
    }
    let sealed = format!("{path}.zip");
    if !std::fs::exists(path)? && std::fs::exists(&sealed)? {
        return open_sample(&std::fs::read(&sealed)?);
    }
    std::fs::read(path)
}

/// The password real-malware samples are kept under (see [`read_fixture`]).
#[doc(hidden)]
pub const SAMPLE_PASSWORD: &str = "infected";

/// The one member of a sample ZIP, decrypted with [`SAMPLE_PASSWORD`].
fn open_sample(zip: &[u8]) -> std::io::Result<Vec<u8>> {
    #[cfg(all(feature = "zip", feature = "decrypt"))]
    {
        use std::io::{Error, ErrorKind};
        let mut budget = Budget::with_passwords(Limits::default(), vec![SAMPLE_PASSWORD.into()]);
        let mut entries = extract(Format::Zip, &zip, &mut budget)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e.reason))?;
        match entries.as_slice() {
            [e] if e.unsupported.is_none() => Ok(entries.remove(0).data),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "sample ZIP does not decrypt to one member",
            )),
        }
    }
    #[cfg(not(all(feature = "zip", feature = "decrypt")))]
    {
        let _ = zip;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "a sample ZIP needs the zip and decrypt features",
        ))
    }
}

/// Read up to `cap` bytes; the returned flag is true if the source had more
/// (so the caller can treat it as exceeding the budget rather than silently
/// truncating).
#[allow(dead_code)] // see `bounded_read_salvage`
#[inline]
pub(crate) fn bounded_read<R: Read>(mut r: R, cap: u64) -> Result<(Vec<u8>, bool), std::io::Error> {
    bounded_read_from(&mut r, cap)
}

/// [`bounded_read`], the one compiled copy.
fn bounded_read_from(r: &mut dyn Read, cap: u64) -> Result<(Vec<u8>, bool), std::io::Error> {
    let mut buf = Vec::new();
    source::read_capped(r, &mut buf, cap.saturating_add(1))?;
    let truncated = buf.len() as u64 > cap;
    if truncated {
        buf.truncate(cap as usize);
    }
    Ok((buf, truncated))
}

/// A decode error raised when only a checksum disagreed: after the input was
/// decoded in full, or as far as it goes when the archive ends inside the
/// member (`cut`). Carried inside the `io::Error` so a caller can tell it
/// from damage, which leaves content undecoded.
#[derive(Debug)]
struct ChecksumMismatch {
    what: &'static str,
    cut: bool,
}

impl std::fmt::Display for ChecksumMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.cut {
            true => write!(
                f,
                "{} not checked: the archive ends inside the member",
                self.what
            ),
            false => write!(f, "{} mismatch after a full decode", self.what),
        }
    }
}

impl std::error::Error for ChecksumMismatch {}

#[allow(dead_code)] // see `bounded_read_salvage`
pub(crate) fn checksum_mismatch(what: &'static str) -> std::io::Error {
    let e = ChecksumMismatch { what, cut: false };
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}

/// [`checksum_mismatch`] of a member the archive ends inside.
#[allow(dead_code)] // see `bounded_read_salvage`
pub(crate) fn checksum_cut(what: &'static str) -> std::io::Error {
    let e = ChecksumMismatch { what, cut: true };
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}

/// Whether a decode error left compressed content in the input that was never
/// decoded. A stream that ends early (the rest is absent) or that decoded in
/// full and failed its checksum hides nothing; damage part way does.
pub fn decode_error_hides_content(e: &std::io::Error) -> bool {
    e.kind() != std::io::ErrorKind::UnexpectedEof && !is_checksum_mismatch(e)
}

/// Whether `e` is a [`checksum_mismatch`] or a [`checksum_cut`].
#[allow(dead_code)] // see `bounded_read_salvage`
pub(crate) fn is_checksum_mismatch(e: &std::io::Error) -> bool {
    e.get_ref()
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
    /// The decoder ran out of input before its stream ended
    /// (`UnexpectedEof`).
    pub(crate) cut_short: bool,
}

#[allow(dead_code)] // see `bounded_read_salvage`
impl Salvaged {
    /// Whether bytes present in the input were left undecoded: damage, or
    /// a stream that ran out of input with more of the input after it.
    /// `rest_absent`: the member's data was cut by the end of the input, so
    /// running out of it hides nothing.
    pub(crate) fn part_way(&self, rest_absent: bool) -> bool {
        self.undecoded || (self.cut_short && !rest_absent)
    }
}

/// [`bounded_read_salvage`] of `r`, salvaging.
#[allow(dead_code)] // see `bounded_read_salvage`
#[inline]
pub(crate) fn salvage<R: Read>(mut r: R, cap: u64) -> Salvaged {
    match salvage_from(&mut r, cap, true) {
        Ok(s) => s,
        // Unreachable: with `salvage` set, errors end the read instead.
        Err(_) => Salvaged {
            data: Vec::new(),
            over_cap: false,
            undecoded: true,
            cut_short: false,
        },
    }
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
#[inline]
pub(crate) fn bounded_read_salvage<R: Read>(
    mut r: R,
    cap: u64,
    salvage: bool,
) -> Result<Salvaged, std::io::Error> {
    salvage_from(&mut r, cap, salvage)
}

/// [`bounded_read_salvage`], the one compiled copy.
#[allow(dead_code)]
fn salvage_from(r: &mut dyn Read, cap: u64, salvage: bool) -> Result<Salvaged, std::io::Error> {
    if !salvage {
        let (data, over_cap) = bounded_read_from(r, cap)?;
        return Ok(Salvaged {
            data,
            over_cap,
            undecoded: false,
            cut_short: false,
        });
    }
    let limit = cap.saturating_add(1);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut undecoded = false;
    let mut cut_short = false;
    while (buf.len() as u64) < limit {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                undecoded = decode_error_hides_content(&e);
                cut_short = e.kind() == std::io::ErrorKind::UnexpectedEof;
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
        cut_short,
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

    /// Some writers leave the `=` off. The partial last group still holds the
    /// asset's last one or two bytes.
    #[test]
    fn an_unpadded_data_uri_keeps_its_last_bytes() {
        for marker in [&b"m"[..], b"mmm"] {
            let want = png(marker);
            assert_ne!(want.len() % 3, 0);
            let bare = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&want);
            let page = format!("<img src=\"data:image/png;base64,{bare}\">");
            let got = markup_embedded_payloads(&page.as_bytes(), 1 << 20);
            let tail = want.len() % 3;
            assert_eq!(got, vec![want], "{tail} byte(s) past the last group");
        }
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
    use flate2::Compression;
    use flate2::write::GzEncoder;
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
    fn ratio_guard_ignores_output_within_the_object_limit() {
        // A 1 KB-compressed blank scanned page expanding to 1 MB (ratio
        // ~1000:1) is ordinary content, not a bomb: a member that size is held
        // in memory, so the memory limits bound it and the ratio must not trip.
        let b = Budget::new(Limits::default());
        assert!(ratio_guard(1021, 1_030_656, &b).is_ok());
        assert!(ratio_guard(100, 90_000, &b).is_ok());
        assert!(ratio_guard(1, 64 * 1024 * 1024, &b).is_ok());
    }

    /// Pins the bound at SHIPPED settings. Every other bomb test overrides
    /// `max_compression_ratio`, so before this one nothing exercised the guard
    /// as deployed.
    #[test]
    fn ratio_guard_boundary_at_default_limits() {
        let b = Budget::new(Limits::default());
        assert_eq!(
            b.limits().max_compression_ratio,
            1000,
            "the shipped ratio; this test is about the default configuration"
        );
        let held = b.limits().max_buffer_bytes;
        // An output at the object limit is held, however extreme the ratio...
        assert!(ratio_guard(1, held, &b).is_ok());
        // ...and the guard resumes one byte past it.
        assert!(ratio_guard(1, held + 1, &b).is_err());
        // A ratio at the limit is fine past the object limit; one over is not.
        let input = 1024 * 1024;
        assert!(held < input * 1000);
        assert!(ratio_guard(input, input * 1000, &b).is_ok());
        assert!(ratio_guard(input, input * 1001, &b).is_err());
    }

    /// With the object limit off nothing is past it, so the ratio never acts.
    #[test]
    fn ratio_guard_does_not_act_without_an_object_limit() {
        let b = Budget::new(Limits {
            max_buffer_bytes: u64::MAX,
            ..Default::default()
        });
        assert!(ratio_guard(1, u64::MAX, &b).is_ok());
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

    #[test]
    fn a_tar_from_before_ustar_has_no_magic_and_is_found_by_its_checksum() {
        let mut buf = Vec::new();
        {
            let mut b = ::tar::Builder::new(&mut buf);
            let mut h = ::tar::Header::new_old();
            h.set_size(5);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "input.txt", &b"hello"[..]).unwrap();
            b.finish().unwrap();
        }
        assert_eq!(&buf[257..262], &[0u8; 5], "no magic");
        assert_eq!(detect(&buf), Some(Format::Tar));
        let entries = extract(Format::Tar, &buf, &mut Budget::new(Limits::default())).unwrap();
        assert_eq!(entries[0].data, b"hello");
        // One byte of the header changed: the checksum no longer fits.
        buf[1] ^= 1;
        assert_eq!(detect(&buf), None);
        // Text that happens to be octal is not one.
        assert_eq!(detect(&[b'7'; 2048]), None);
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
            max_buffer_bytes: 1024 * 1024,
            ..Default::default()
        });
        // The member is read as it is decoded, past the object limit: `extract`
        // holds it under that limit and never gets to the ratio.
        let err = walk::<()>(Format::Gzip, &blob, &mut budget, &mut |_, content, _| {
            if let Some(Member::Stream(r)) = content {
                let _ = std::io::copy(r, &mut std::io::sink());
            }
            None
        })
        .unwrap_err();
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

    /// A member over the room `reserve` gave is left out when the object limit
    /// is that room, and ends the walk when the total is; what was decoded of
    /// it is charged either way.
    #[test]
    fn a_member_over_its_room_is_left_out_unless_the_total_is_the_room() {
        let mut b = Budget::new(Limits {
            max_buffer_bytes: 100,
            max_extracted_bytes: 250,
            ..Limits::default()
        });
        let cap = b.reserve().unwrap();
        assert_eq!(cap, 100);
        assert!(b.over_cap(cap, 100, format_args!("member 'a'")).is_ok());
        assert_eq!(b.total_out, 100);
        let skipped = b.skipped.as_ref().expect("the member is noted");
        assert_eq!(
            skipped.reason,
            "member 'a' is larger than --max-object-bytes 100"
        );
        assert!(!skipped.is_corrupt());

        b.commit(100);
        let cap = b.reserve().unwrap();
        assert_eq!(cap, 50);
        let hit = b.over_cap(cap, 50, format_args!("member 'b'")).unwrap_err();
        assert!(
            hit.reason.starts_with("member 'b': extracted bytes > 250"),
            "{}",
            hit.reason
        );
        assert_eq!(b.total_out, 250);
        // The first left out stays the one noted.
        assert!(b.skipped.unwrap().reason.contains("'a'"));
    }

    /// A member said to be over its room is left out before it is decoded,
    /// nothing charged, whether the room is the object limit or what is left
    /// of the total; one within it gets the room.
    #[test]
    fn a_member_said_to_be_over_its_room_is_left_out_and_charges_nothing() {
        let mut b = Budget::new(Limits {
            max_buffer_bytes: 100,
            max_extracted_bytes: 250,
            ..Limits::default()
        });
        assert_eq!(
            b.reserve_for(100, format_args!("member 'a'")).unwrap(),
            Some(100)
        );
        assert_eq!(
            b.reserve_for(101, format_args!("member 'b'")).unwrap(),
            None
        );
        let skipped = b.skipped.take().expect("the member is noted");
        assert_eq!(
            skipped.reason,
            "member 'b' is larger than --max-object-bytes 100"
        );
        b.commit(200);
        assert_eq!(b.reserve_for(51, format_args!("member 'c'")).unwrap(), None);
        assert_eq!(b.total_out, 200);
        let skipped = b.skipped.take().expect("the member is noted");
        assert!(
            skipped
                .reason
                .starts_with("member 'c' is larger than what is left of the 250"),
            "{}",
            skipped.reason
        );
        assert_eq!(
            b.reserve_for(50, format_args!("member 'd'")).unwrap(),
            Some(50)
        );
    }

    /// A member not read for its size is a limit, not damage.
    #[test]
    fn a_member_over_a_size_limit_is_a_limit() {
        let e = Entry::over_limit("m".into(), 9, "too big");
        let meta = MemberMeta {
            name: e.name.clone(),
            unsupported: e.unsupported,
            reason_kind: e.reason_kind,
            ..MemberMeta::default()
        };
        let why = tree::Reason::of_member(&meta).unwrap();
        assert_eq!(why.kind.class(), tree::ReasonClass::Limits);
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

    /// `reserved1` is reserved: `cabextract` opens a cabinet whatever it holds,
    /// so a cabinet with a nonzero field is a cabinet, not data.
    #[cfg(feature = "cab")]
    #[test]
    fn a_cabinet_with_a_nonzero_reserved_field_is_still_a_cabinet() {
        let real = include_bytes!("../tests/fixtures/cab/mszip_lzx_qtm.cab");
        let mut odd = real.to_vec();
        odd[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(detect(&odd), Some(Format::Cab));
        let names = |blob: &[u8]| {
            let mut budget = Budget::new(Limits::default());
            extract(Format::Cab, &blob, &mut budget)
                .unwrap()
                .into_iter()
                .map(|e| (e.name, e.data))
                .collect::<Vec<_>>()
        };
        assert!(!names(real).is_empty());
        assert_eq!(names(&odd), names(real));
        // And a header that only starts like one is still not.
        let mut chance = odd.clone();
        chance[24] = 9;
        assert_eq!(detect(&chance), None);
    }

    /// `60 EA` is two bytes, so about one object in 65,536 starts with it by
    /// chance, and reading such an object as a damaged ARJ reports it
    /// `UNSCANNABLE`. The shape of the main header settles it.
    #[cfg(feature = "arj")]
    #[test]
    fn arj_magic_rejects_false_positives() {
        let real: &[u8] = include_bytes!("../tests/fixtures/sample.arj");
        assert_eq!(detect(&real), Some(Format::Arj));
        assert_eq!(detect(b"\x60\xea\x10\x00random bytes after it"), None);
        assert_eq!(detect(b"\x60\xea"), None);
        // The shape: a size in range that fits, a fixed part of 30 bytes or
        // more with room for two strings after it, and exactly those two.
        let size = usize::from(u16::from_le_bytes([real[2], real[3]]));
        let set = |at: usize, to: u8| {
            let mut d = real.to_vec();
            d[at] = to;
            d
        };
        let strings = 4 + usize::from(real[4]);
        // A header of `fixed` bytes and two strings, with a CRC that is wrong.
        let with = |fixed: usize, strings: &[u8]| {
            let mut header = real[4..4 + fixed].to_vec();
            header[0] = fixed as u8;
            header.extend_from_slice(strings);
            let mut d = vec![0x60, 0xEA];
            d.extend_from_slice(&(header.len() as u16).to_le_bytes());
            d.extend_from_slice(&header);
            d.extend_from_slice(&[0; 4]);
            d
        };
        assert_eq!(detect(&with(30, b"a\0b\0").as_slice()), Some(Format::Arj));
        assert_eq!(detect(&with(34, b"\0\0").as_slice()), Some(Format::Arj));
        for (what, d) in [
            ("a fixed part of 29 bytes", with(29, b"a\0b\0")),
            ("a fixed part of 1 byte", with(1, b"a\0b\0")),
            ("one string", with(34, b"a\0")),
            ("three strings", with(34, b"a\0b\0c\0")),
            ("a string not ended", with(34, b"a\0b")),
            ("bytes after the strings", with(34, b"a\0b\0c")),
            ("size 0", set(2, 0)),
            ("size 2601", {
                let mut d = real.to_vec();
                d[2..4].copy_from_slice(&2601u16.to_le_bytes());
                d
            }),
            ("size past the data", real[..20].to_vec()),
            ("fixed part of 0", set(4, 0)),
            ("fixed part of 29", set(4, 29)),
            (
                "fixed part with no room for the strings",
                set(4, size as u8 - 1),
            ),
            ("fixed part of 255", set(4, 255)),
            ("the name not ended", set(strings + 8, b'x')),
            ("the comment not ended", set(strings + 9, b'x')),
            ("a NUL in the name", set(strings + 2, 0)),
            ("no CRC after the header", real[..4 + size + 3].to_vec()),
        ] {
            assert_eq!(detect(&d.as_slice()), None, "{what}");
        }
    }

    /// ClamAV takes the main header of a file by its shape, and ignores its
    /// CRC-32 and the bytes of the header that are not part of the shape. So
    /// does a file starting with one; an archive carved out of another file
    /// is confirmed by its CRC-32 and its file type, as before.
    #[cfg(feature = "arj")]
    #[test]
    fn an_arj_header_with_a_stale_crc_is_an_arj_at_the_start_of_a_file() {
        let real: &[u8] = include_bytes!("../tests/fixtures/sample.arj");
        let size = usize::from(u16::from_le_bytes([real[2], real[3]]));
        let fixed = usize::from(real[4]);
        // Each byte of the fixed part after its size, and of the CRC.
        for at in (5..4 + fixed).chain(4 + size..8 + size) {
            let mut stale = real.to_vec();
            stale[at] ^= 0xff;
            assert_eq!(detect(&stale.as_slice()), Some(Format::Arj), "byte {at}");
        }
        // Not as one carved out of another file.
        let mut stale = real.to_vec();
        stale[10] ^= 0xff;
        assert_eq!(detect_archive_start(&stale.as_slice()), None);
        // And what the shape does not need: the security version and the
        // file type, which a carved one must have right.
        for at in [9, 10] {
            let mut odd = real.to_vec();
            odd[at] = 0xff;
            assert_eq!(detect(&odd.as_slice()), Some(Format::Arj), "byte {at}");
        }
    }

    /// An archive carved out of another object is confirmed by the same checks:
    /// an ARJ by the CRC-32 of its main header, which runs past the first 32
    /// bytes read to confirm the others.
    #[cfg(feature = "arj")]
    #[test]
    fn an_arj_carved_at_its_magic_is_confirmed_by_its_header_crc() {
        let real: &[u8] = include_bytes!("../tests/fixtures/sample.arj");
        let size = usize::from(u16::from_le_bytes([real[2], real[3]]));
        assert!(size > 28, "the header must run past the bytes read first");
        assert_eq!(detect_archive_start(&real), Some(Format::Arj));
        // A byte of the header changed, then of the CRC itself.
        for at in [10, size - 1, 4 + size] {
            let mut bad = real.to_vec();
            bad[at] ^= 0x01;
            assert_eq!(detect_archive_start(&bad.as_slice()), None, "byte {at}");
        }
        // The header of the first file follows the main header's CRC and a
        // 2-byte length of extended headers (none). It has the magic and a CRC
        // that holds, which is enough to type an object, and not to carve one.
        let file_header = &real[10 + size..];
        assert!(file_header.starts_with(&[0x60, 0xEA]));
        assert_eq!(detect(&file_header), Some(Format::Arj));
        assert_eq!(detect_archive_start(&file_header), None);
        // The header, its CRC and nothing else, and a header cut short.
        assert_eq!(detect_archive_start(&&real[..8 + size]), Some(Format::Arj));
        assert_eq!(detect_archive_start(&&real[..7 + size]), None);
        assert_eq!(detect_archive_start(b"\x60\xea\x10\x00random bytes"), None);
        assert_eq!(detect_archive_start(b"\x60\xea"), None);
    }

    #[test]
    fn a_settled_answer_is_the_format_found_or_what_the_checks_asked_for() {
        assert_eq!(settled(Some(Format::Zip), true), Settled::Is(Format::Zip));
        assert_eq!(settled(Some(Format::Zip), false), Settled::Is(Format::Zip));
        assert_eq!(settled(None, true), Settled::Unsettled);
        assert_eq!(settled(None, false), Settled::Not);
    }

    #[cfg(all(feature = "gzip", feature = "tar"))]
    #[test]
    fn the_start_of_a_stream_says_a_format_when_a_check_of_the_start_finds_one() {
        let gzip = [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff];
        assert_eq!(detect_head(&gzip), Settled::Is(Format::Gzip));
        let mut tar = vec![0u8; 512];
        tar[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_head(&tar), Settled::Is(Format::Tar));
        // Found behind a check that reads the end of an object, which the
        // start cannot answer: the format found is still the answer.
        let mut tar_late = vec![b'x'; 300];
        tar_late[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_head(&tar_late), Settled::Is(Format::Tar));
    }

    #[test]
    fn a_probe_of_the_start_of_a_stream_notes_what_a_check_asks_for_past_it() {
        let head = [0u8; 100];
        let start = Probe::start(&head);
        assert_eq!(start.window(10, 20).len(), 20);
        assert!(!start.reached.get(), "within the start");
        assert!(start.window(90, 20).len() <= 10);
        assert!(start.reached.get(), "past the start");
        // An object held whole has nothing past its end to ask for.
        let whole = Probe::whole(&head);
        whole.window(90, 20);
        assert!(!whole.reached.get());
        #[cfg(any(
            feature = "screnc",
            feature = "autoit",
            feature = "nsis",
            feature = "sfx"
        ))]
        {
            // A search of the start reads all the start a check may search.
            let start = Probe::start(&head);
            assert_eq!(start.searched_start().len(), 100);
            assert!(start.reached.get(), "less than a search reads");
            let long = vec![0u8; DETECT_HEAD + 10];
            let start = Probe::start(&long);
            assert_eq!(start.searched_start().len(), DETECT_HEAD);
            assert!(!start.reached.get());
            let whole = Probe::whole(&head);
            whole.searched_start();
            assert!(!whole.reached.get());
        }
    }

    #[test]
    fn the_start_of_a_stream_that_no_check_finds_a_format_in_is_not_known_not_to_be_one() {
        // The end of a fixed VHD, a ZIP behind a stub: found only from the end
        // of the object, which a stream cannot be asked for.
        assert_eq!(
            detect_head(b"plain text, line after line\n".repeat(100).as_slice()),
            Settled::Unsettled
        );
        assert_eq!(detect_head(&[0u8; 4096]), Settled::Unsettled);
        // The whole of such an object is something else.
        assert_eq!(detect(&b"plain text".as_slice()), None);
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

    /// A payload whose length is not a multiple of three ends in a partial
    /// group (`xx==` or `xxx=`): its last one or two bytes must come back,
    /// wrapped or not, or a hash of the payload never matches.
    #[cfg(feature = "base64scan")]
    #[test]
    fn base64_payloads_keep_the_bytes_of_a_padded_tail() {
        use base64::Engine;
        for extra in [1usize, 2] {
            let mut pe = vec![0u8; 3 * 700 + extra];
            pe[..2].copy_from_slice(b"MZ");
            pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
            pe[0x40..0x44].copy_from_slice(b"PE\x00\x00");
            let n = pe.len();
            pe[n - extra..].fill(0xAB);
            let b64 = base64::engine::general_purpose::STANDARD.encode(&pe);
            assert!(b64.ends_with('='));
            let wrapped: Vec<&str> = b64
                .as_bytes()
                .chunks(76)
                .map(|l| std::str::from_utf8(l).unwrap())
                .collect();
            for carrier in [format!("x = \"{b64}\";"), wrapped.join("\r\n")] {
                let got = base64_payloads(&carrier.as_bytes(), u64::MAX);
                assert_eq!(got, vec![pe.clone()], "{extra} trailing byte(s)");
            }
        }
    }

    /// The payloads taken from a text, and the decodes tried for them, stop at
    /// the numbers given, and say so; a run that starts like an executable but
    /// is not one costs a try.
    #[cfg(feature = "base64scan")]
    #[test]
    fn base64_payloads_stop_at_the_limits_they_are_given() {
        use base64::Engine;
        let b64 = |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);
        let mut pe = vec![0u8; 2048];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\x00\x00");
        let mut bare_mz = vec![0u8; 2048];
        bare_mz[..2].copy_from_slice(b"MZ");
        let text = format!(
            "a = \"{}\";\nb = \"{}\";\nc = \"{}\";\n",
            b64(&bare_mz),
            b64(&pe),
            b64(&pe)
        );
        let src = text.as_bytes();
        let count = |most, tries| {
            let (got, capped) = base64_payloads_capped(&src, u64::MAX, most, tries);
            (got.len(), capped)
        };
        assert_eq!(count(u64::MAX, u64::MAX), (2, false));
        assert_eq!(count(2, 3), (2, false));
        assert_eq!(count(1, u64::MAX), (1, true));
        assert_eq!(count(u64::MAX, 2), (1, true));
        assert_eq!(count(u64::MAX, 1), (0, true));

        let png = [&b"\x89PNG\r\n\x1a\n"[..], &[7u8; 120]].concat();
        let page = format!(
            "<img src=\"data:image/png;base64,{0}\"><img src=\"data:image/png;base64,{0}\">",
            b64(&png)
        );
        let assets = |most| {
            let (got, capped) = markup_embedded_payloads_capped(&page.as_bytes(), u64::MAX, most);
            (got.len(), capped)
        };
        assert_eq!(assets(u64::MAX), (2, false));
        assert_eq!(assets(2), (2, false));
        assert_eq!(assets(1), (1, true));
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

    /// ClamAV's `skip_prefix.txt.zst`: a skippable frame (which LZ4 uses as
    /// well) ahead of the Zstandard one was taken for an LZ4 file.
    #[test]
    fn zstd_after_a_skippable_frame_is_zstd() {
        let payload = b"hello exav inside zstd";
        let mut blob = Vec::new();
        blob.extend_from_slice(&0x184D_2A50u32.to_le_bytes());
        blob.extend_from_slice(&5u32.to_le_bytes());
        blob.extend_from_slice(b"PADDY");
        blob.extend(zstd_of(payload));
        assert_eq!(detect(&blob), Some(Format::Zstd));
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
            let mut comp = ::cfb::CompoundFile::create(&mut buf).unwrap();
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

    /// A ZIP behind a script line (a zipapp), with a marker of a spanned archive
    /// in front, or with padding before and after is told by its end record, and
    /// opens as it does without them; text that merely ends like a ZIP is not.
    #[cfg(feature = "zip")]
    #[test]
    fn a_zip_behind_other_bytes_is_a_zip() {
        let zip = include_bytes!("../tests/fixtures/zip/legacy_implode.zip").to_vec();
        let plain = extract(
            Format::Zip,
            &zip.as_slice(),
            &mut Budget::new(Limits::default()),
        )
        .unwrap();
        assert!(!plain.is_empty());
        let names = |blob: &[u8]| -> Vec<(String, Vec<u8>)> {
            extract(Format::Zip, &blob, &mut Budget::new(Limits::default()))
                .unwrap()
                .into_iter()
                .map(|e| (e.name, e.data))
                .collect()
        };
        let want = names(&zip);
        for (what, blob) in [
            (
                "a zipapp",
                [&b"#!/usr/bin/env python3\n"[..], &zip].concat(),
            ),
            (
                "padding around",
                [&[7u8; 300][..], &zip, &[9u8; 100]].concat(),
            ),
        ] {
            assert_eq!(detect(&blob.as_slice()), Some(Format::Zip), "{what}");
            assert_eq!(names(&blob), want, "{what}");
        }
        // A directory that points at no local header, and an end record cut off.
        let mut broken = [&b"#!/bin/sh\n"[..], &zip].concat();
        let at = broken.len() - zip.len();
        broken[at..at + 4].copy_from_slice(b"XXXX");
        assert_eq!(detect(&broken.as_slice()), None);
        let cut = [&b"#!/bin/sh\n"[..], &zip[..zip.len() - 30]].concat();
        assert_eq!(detect(&cut.as_slice()), None);
    }

    /// Padding after the archive that holds an end record marker whose comment
    /// cannot fit does not hide it, as it does not for the reader.
    #[cfg(feature = "zip")]
    #[test]
    fn a_zip_followed_by_a_marker_that_is_no_end_record_is_a_zip() {
        let zip = include_bytes!("../tests/fixtures/zip/legacy_implode.zip");
        let mut blob = [&b"#!/usr/bin/env python3\n"[..], zip].concat();
        blob.extend_from_slice(b"PK\x05\x06");
        blob.extend_from_slice(&[0; 16]);
        blob.extend_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(detect(&blob.as_slice()), Some(Format::Zip));
    }

    /// `xz --format=lzma`: a stream that ends with a marker, and the same with
    /// its size in the header (what LZMA Utils wrote).
    #[cfg(feature = "lzma")]
    #[test]
    fn lzma_alone_roundtrip() {
        let payload = b"hello exav inside lzma";
        for blob in [
            &include_bytes!("../tests/fixtures/lzma_simple.lzma")[..],
            &include_bytes!("../tests/fixtures/lzma_sized.lzma")[..],
        ] {
            assert_eq!(detect(&blob), Some(Format::Lzma));
            let mut budget = Budget::new(Limits::default());
            let entries = extract(Format::Lzma, &blob, &mut budget).unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].name, "lzma-content");
            assert_eq!(entries[0].data, payload);
        }
    }

    /// The header chooses the dictionary the decoder allocates: one of 2 GiB is
    /// refused, not allocated.
    #[cfg(feature = "lzma")]
    #[test]
    fn lzma_alone_with_a_huge_dictionary_is_refused() {
        let mut blob = include_bytes!("../tests/fixtures/lzma_simple.lzma").to_vec();
        blob[1..5].copy_from_slice(&(1u32 << 31).to_le_bytes());
        assert_eq!(detect(&blob.as_slice()), Some(Format::Lzma));
        let mut budget = Budget::new(Limits::default());
        let entries = extract(Format::Lzma, &blob.as_slice(), &mut budget).unwrap();
        assert!(entries[0].data.is_empty() && entries[0].unsupported.is_some());
    }

    /// The streams the encoder writes are told whatever properties,
    /// dictionary and size they have, and so are those damaged or cut after
    /// their first bytes, which are then reported when read.
    #[cfg(feature = "lzma")]
    #[test]
    fn lzma_alone_streams_of_any_shape_are_told() {
        use std::io::Write;
        let text = b"the quick brown fox jumps over the lazy dog. ".repeat(200);
        let mut noise = Vec::new();
        let mut x = 0x9E37_79B9u32;
        for _ in 0..3000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            noise.push(x as u8);
        }
        let zeros = vec![0u8; 100_000];
        let encode = |payload: &[u8], lc, lp, pb, dict_size, known: bool| {
            let mut opts = lzma_rust2::LzmaOptions::with_preset(6);
            (opts.lc, opts.lp, opts.pb, opts.dict_size) = (lc, lp, pb, dict_size);
            let size = known.then_some(payload.len() as u64);
            let mut w = lzma_rust2::LzmaWriter::new_use_header(Vec::new(), &opts, size).unwrap();
            w.write_all(payload).unwrap();
            w.finish().unwrap()
        };
        for payload in [&text[..], &noise, &zeros, b"x", b""] {
            for (lc, lp, pb) in [(3, 0, 2), (0, 0, 0), (0, 2, 2), (4, 0, 0), (1, 3, 1)] {
                for dict in [1 << 12, 3 << 21] {
                    for known in [false, true] {
                        let blob = encode(payload, lc, lp, pb, dict, known);
                        let what =
                            format!("{} bytes, {lc}{lp}{pb}, {dict}, {known}", payload.len());
                        assert_eq!(detect(&blob.as_slice()), Some(Format::Lzma), "{what}");
                        let mut budget = Budget::new(Limits::default());
                        let entries = extract(Format::Lzma, &blob.as_slice(), &mut budget).unwrap();
                        assert_eq!(entries[0].data, payload, "{what}");
                    }
                }
            }
        }
        let big = encode(&text, 3, 0, 2, 1 << 26, true);
        assert_eq!(detect(&big.as_slice()), Some(Format::Lzma));
        // Damaged or cut after the first bytes the check decodes.
        let blob = encode(&noise, 3, 0, 2, 1 << 20, false);
        for at in [100, 1500] {
            let mut flipped = blob.clone();
            flipped[at] ^= 0x55;
            assert_eq!(detect(&flipped.as_slice()), Some(Format::Lzma), "{at}");
        }
        for len in [14, 30, 100, 1700] {
            assert_eq!(detect(&&blob[..len]), Some(Format::Lzma), "{len}");
        }
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
