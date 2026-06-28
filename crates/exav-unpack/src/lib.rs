//! Archive extraction with decompression-bomb limits.
//!
//! Extraction is bounded by a [`Budget`] (total output bytes, file count,
//! recursion depth, compression ratio). Hitting a bound returns [`LimitHit`],
//! which the caller maps to `LimitsExceeded`.
//!
//! The budget is reserved *before* each member is read, and each read is
//! capped to the bytes still remaining, so peak memory across an archive
//! (and across nested archives sharing the budget) never exceeds
//! `max_total_bytes`.
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
#[doc(hidden)]
pub use formats::{unpack29, unpack50, window_size_from_comp_info, ZipMembers};

/// Limits governing recursive extraction.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_recursion: u32,
    pub max_files: u64,
    /// Cap on the total decompressed bytes across the whole (recursive)
    /// extraction. Bounds peak memory.
    pub max_total_bytes: u64,
    /// Max output/input size ratio for a single compressed stream.
    pub max_ratio: u64,
    /// Per-member output cap.
    pub max_entry_bytes: u64,
    /// Cap on the cumulative bytes fed to the *matching core* across the whole
    /// recursive analysis of one top-level file (distinct from
    /// [`Self::max_total_bytes`], which counts *decompressed* bytes). Bounds
    /// re-scanning bombs — e.g. a disk image full of embedded PEs, where the
    /// same suffix is carved and matched at many offsets and depths — without
    /// limiting the legitimate one-pass scan of a large file. Deterministic, so
    /// it trips identically on every machine (unlike a wall-clock deadline).
    pub max_scan_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_recursion: 16,
            max_files: 10_000,
            max_total_bytes: 1024 * 1024 * 1024, // 1 GiB extracted total
            max_ratio: 1000,
            max_entry_bytes: 256 * 1024 * 1024,
            max_scan_bytes: 1024 * 1024 * 1024, // 1 GiB fed to the matcher total
        }
    }
}

/// Mutable extraction budget, shared across the recursion.
pub struct Budget {
    pub limits: Limits,
    pub files: u64,
    pub total_out: u64,
    /// Cumulative bytes fed to the matching core (see [`Limits::max_scan_bytes`]).
    pub scanned: u64,
    /// Candidate passwords tried (in order) when decrypting an encrypted member
    /// (ZIP ZipCrypto/AES today). Empty by default — an encrypted member with no
    /// password yields an `Entry::unsupported(encrypted=true, …)` so the scanner
    /// reports `PasswordProtected`. The pool is the union of any `.pwdb` file and
    /// the runtime `ScanOptions::passwords`, threaded down by exav-core.
    pub passwords: Vec<String>,
}

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            files: 0,
            total_out: 0,
            scanned: 0,
            passwords: Vec::new(),
        }
    }

    /// Construct a budget with a password pool for decrypting encrypted members.
    pub fn with_passwords(limits: Limits, passwords: Vec<String>) -> Self {
        Self {
            passwords,
            ..Self::new(limits)
        }
    }

    /// Charge `n` bytes against the cumulative scan-size budget. Returns `Err`
    /// once the total bytes matched across the recursive analysis exceeds
    /// [`Limits::max_scan_bytes`], which the caller maps to `LimitsExceeded`.
    /// Used to bound re-scanning bombs (a buffer carved and matched at many
    /// offsets/depths) deterministically, before any wall-clock backstop.
    pub fn charge_scan(&mut self, n: u64) -> Result<(), LimitHit> {
        self.scanned = self.scanned.saturating_add(n);
        if self.scanned > self.limits.max_scan_bytes {
            return Err(LimitHit::new(format!(
                "scanned bytes > {}",
                self.limits.max_scan_bytes
            )));
        }
        Ok(())
    }

    /// Count one archive member toward the file-count budget. Called for
    /// every entry encountered — including directories and skipped entries —
    /// so a huge directory-only archive still trips the cap.
    pub fn count_entry(&mut self) -> Result<(), LimitHit> {
        self.files += 1;
        if self.files > self.limits.max_files {
            return Err(LimitHit::new(format!(
                "file count > {}",
                self.limits.max_files
            )));
        }
        Ok(())
    }

    /// Maximum bytes the next member may decompress to: the smaller of the
    /// per-member cap and the bytes still left in the total budget. Fails if
    /// the total budget is already exhausted.
    pub fn reserve(&mut self) -> Result<u64, LimitHit> {
        let remaining = self.limits.max_total_bytes.saturating_sub(self.total_out);
        if remaining == 0 {
            return Err(LimitHit::new(format!(
                "extracted bytes > {}",
                self.limits.max_total_bytes
            )));
        }
        Ok(remaining.min(self.limits.max_entry_bytes))
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
}

impl LimitHit {
    /// A resource-budget stop → `LimitsExceeded`.
    fn new(reason: String) -> Self {
        Self {
            reason,
            corrupt: false,
        }
    }
    /// An undecodable-content stop → `Unscannable`: malformed/truncated input, or
    /// a decoder panic contained at the extraction boundary.
    pub(crate) fn corrupt(reason: String) -> Self {
        Self {
            reason,
            corrupt: true,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Zip,
    Gzip,
    Tar,
    Bzip2,
    Xz,
    Cab,
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
    /// Zstandard compressed stream.
    Zstd,
    /// Lzip compressed stream.
    Lzip,
}

/// Best-effort detection of an extractable container by magic bytes. Returns
/// `None` for content this crate can't unpack. Callers with a richer file-type
/// classifier may map to [`Format`] themselves instead of using this.
pub fn detect(data: &[u8]) -> Option<Format> {
    if data.len() >= 4 && &data[..2] == b"PK" && matches!(data[2..4], [3, 4] | [5, 6] | [7, 8]) {
        return Some(Format::Zip);
    }
    if data.starts_with(&[0x1f, 0x8b]) {
        return Some(Format::Gzip);
    }
    if data.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return Some(Format::SevenZip);
    }
    if data.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some(Format::Xz);
    }
    if data.starts_with(b"BZh") {
        return Some(Format::Bzip2);
    }
    if data.starts_with(b"MSCF") {
        return Some(Format::Cab);
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
    if data.starts_with(b"xar!") {
        return Some(Format::Xar);
    }
    if is_dmg(data) {
        return Some(Format::Dmg);
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
    // is `#![forbid(unsafe_code)]` and pure-Rust, so a panic is the only failure
    // mode to contain — there is no UB to leak across the boundary.
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
    match fmt {
        Format::Gzip => extract_gzip(data, budget, visit),
        Format::Tar => extract_tar(data, budget, visit),
        Format::Zip => extract_zip(data, budget, visit),
        Format::Bzip2 => extract_bzip2(data, budget, visit),
        Format::Xz => extract_xz(data, budget, visit),
        Format::Cab => extract_cab(data, budget, visit),
        // OLE builds a combined VBA-macro dump from all streams, so it collects
        // then emits — the visitor still gets one member at a time.
        Format::Ole => emit_collected(extract_ole(data, budget)?, budget, visit),
        Format::Pdf => extract_pdf(data, budget, visit),
        Format::Email => extract_email(data, budget, visit),
        Format::SevenZip => extract_sevenz(data, budget, visit),
        Format::Iso => extract_iso(data, budget, visit),
        Format::Lha => extract_lha(data, budget, visit),
        Format::Arj => extract_arj(data, budget, visit),
        // RAR decodes members eagerly (CRC checks, metadata-only entries for
        // encrypted/unsupported members), so it collects then emits — the visitor
        // still gets one member at a time and can stop early.
        Format::Rar => emit_collected(extract_rar(data, budget)?, budget, visit),
        Format::Upx => extract_upx(data, budget, visit),
        Format::Ar => extract_ar(data, budget, visit),
        Format::Cpio => extract_cpio(data, budget, visit),
        Format::Xar => extract_xar(data, budget, visit),
        Format::Dmg => extract_dmg(data, budget, visit),
        Format::Zstd => extract_zstd(data, budget, visit),
        Format::Lzip => extract_lzip(data, budget, visit),
    }
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
    find_packheader(data).is_some()
}

/// Reject a stream whose decompressed size dwarfs its declared input size.
/// Absolute byte caps are the primary bomb defense; this is a fast reject
/// for the obvious cases. A declared input of 0 is ignored (we cannot trust
/// it) and left to the absolute caps.
pub(crate) fn ratio_guard(input: u64, output: u64, budget: &Budget) -> Result<(), LimitHit> {
    if input > 0 && output / input > budget.limits.max_ratio {
        return Err(LimitHit::new(format!(
            "compression ratio {} > {}",
            output / input,
            budget.limits.max_ratio
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
    Zip {
        members: ZipMembers<R>,
        info: Vec<MemberInfo>,
    },
    Gzip {
        reader: Option<R>,
        done: bool,
    },
    Tar {
        reader: Option<R>,
        members: Vec<TarMember>,
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
struct TarMember {
    name: String,
    size: u64,
    data_offset: u64,
}

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

        // size: bytes 124..136, octal ASCII
        let size_str = std::str::from_utf8(&header[124..136]).ok()?;
        let size = u64::from_str_radix(size_str.trim().trim_end_matches('\0'), 8).ok()?;

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
            None => break, // all-zero block = end of archive
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

        if format == Format::Zip {
            // Seek back to the start so the ZIP central-directory parser sees
            // the full file.
            reader
                .seek(std::io::SeekFrom::Start(0))
                .map_err(|e| LimitHit::corrupt(format!("seek: {e}")))?;
            let mut members = ZipMembers::open(reader).map_err(|e| LimitHit::corrupt(e.reason))?;
            let info = members.list_entries();
            Ok(Self {
                format,
                inner: ArchiveInner::Zip { members, info },
            })
        } else if format == Format::Gzip {
            reader
                .seek(std::io::SeekFrom::Start(0))
                .map_err(|e| LimitHit::corrupt(format!("seek: {e}")))?;
            Ok(Self {
                format,
                inner: ArchiveInner::Gzip {
                    reader: Some(reader),
                    done: false,
                },
            })
        } else if format == Format::Tar {
            reader
                .seek(std::io::SeekFrom::Start(0))
                .map_err(|e| LimitHit::corrupt(format!("seek: {e}")))?;
            let members = parse_tar_headers(&mut reader)
                .map_err(|e| LimitHit::corrupt(format!("tar: {e}")))?;
            Ok(Self {
                format,
                inner: ArchiveInner::Tar {
                    reader: Some(reader),
                    members,
                    next_index: 0,
                },
            })
        } else if matches!(format, Format::Bzip2 | Format::Xz | Format::Zstd) {
            reader
                .seek(std::io::SeekFrom::Start(0))
                .map_err(|e| LimitHit::corrupt(format!("seek: {e}")))?;
            Ok(Self {
                format,
                inner: ArchiveInner::Lazy {
                    reader: Some(reader),
                    format,
                    state: BufState {
                        next_index: 0,
                        cached: None,
                    },
                },
            })
        } else {
            // Read the rest of the reader into memory.
            let mut data = head;
            reader
                .read_to_end(&mut data)
                .map_err(|e| LimitHit::corrupt(format!("read: {e}")))?;
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
            ArchiveInner::Zip { info, .. } => info,
            ArchiveInner::Gzip { .. } => &[],
            ArchiveInner::Tar { .. } => &[],
            ArchiveInner::Lazy { .. } => &[],
            ArchiveInner::Buffered { .. } => &[],
        }
    }

    /// Extract the next member under budget.  Returns `Ok(None)` when the
    /// archive is exhausted.  Directories and other non-file entries are
    /// skipped (but still counted toward the file-count budget).
    pub fn extract_next(&mut self, budget: &mut Budget) -> Result<Option<Entry>, LimitHit> {
        match &mut self.inner {
            ArchiveInner::Zip { members, .. } => members.next_member(budget).transpose(),
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
                let (out, truncated) = bounded_read(MultiGzDecoder::new(r), cap)
                    .map_err(|e| LimitHit::corrupt(format!("gzip: {e}")))?;
                if truncated {
                    return Err(LimitHit::new("gzip member exceeds budget".to_string()));
                }
                budget.commit(out.len() as u64);
                *done = true;
                Ok(Some(Entry::new("gzip-content".to_string(), out)))
            }
            ArchiveInner::Tar {
                reader,
                members,
                next_index,
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
                    r.take(256 * 1024 * 1024)
                        .read_to_end(&mut data)
                        .map_err(|e| LimitHit::corrupt(format!("read: {e}")))?;
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
            ArchiveInner::Zip { members, .. } => members
                .extract_entry(index, budget)?
                .ok_or_else(|| LimitHit::corrupt(format!("index {index} is a directory"))),
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
                let (out, truncated) = bounded_read(MultiGzDecoder::new(r), cap)
                    .map_err(|e| LimitHit::corrupt(format!("gzip: {e}")))?;
                if truncated {
                    return Err(LimitHit::new("gzip member exceeds budget".to_string()));
                }
                budget.commit(out.len() as u64);
                *done = true;
                Ok(Entry::new("gzip-content".to_string(), out))
            }
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
                    r.take(256 * 1024 * 1024)
                        .read_to_end(&mut data)
                        .map_err(|e| LimitHit::corrupt(format!("read: {e}")))?;
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

#[cfg(test)]
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

    fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            for (name, data) in members {
                let mut h = tar::Header::new_gnu();
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
            max_ratio: 100,
            ..Default::default()
        });
        let err = extract(Format::Gzip, &blob, &mut budget).unwrap_err();
        assert!(err.reason.contains("ratio"), "got: {}", err.reason);
    }

    #[test]
    fn total_bytes_budget_enforced() {
        let blob = gz(&vec![b'A'; 4096]);
        let mut budget = Budget::new(Limits {
            max_total_bytes: 1024,
            max_ratio: u64::MAX,
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
            max_total_bytes: 600_000,
            max_entry_bytes: 200_000,
            max_ratio: u64::MAX,
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
            max_total_bytes: 1024,
            max_ratio: u64::MAX,
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
            max_total_bytes: 1024,
            max_ratio: u64::MAX,
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
            max_files: 5,
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
