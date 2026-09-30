//! Streaming, size-unbounded file scanner.
//!
//! Every input goes through one scan, [`scan_seekable`] ([`scan_path`] opens a
//! file and hands it over), and every object in it, the input and whatever is
//! unpacked from it, goes through the same pipeline whatever its size: an
//! object within [`ScanOptions::deep_analysis_max`] is held in memory, a larger
//! one is read through a block cache of bounded size (or, for a decoded member,
//! a spill file), and a container's members are decoded as they are read. The
//! checks that parse an object whole (PE structure, a container format read
//! whole) do not run on one over that limit, and a scan that finds nothing is
//! then reported `LimitsExceeded`.
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
//! Sizes and offsets are 64-bit throughout.

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
    bytecode, container, cvd, engine, fuzzy, fuzzy_img, hashes, hexsig, icon, jsnorm, ml,
    normalize, patterns, pe,
);

mod byte_source;
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

/// Smallest object a whole-file hash signature (`.hdb`/`.hsb`) may be matched
/// against.
///
/// ClamAV refuses to scan any object of 5 bytes or fewer at all (`fmap->len <=
/// 5` in `cli_magic_scan` and its four sibling entry points (libclamav
/// `scanners.c`, checked against 1.4.3)), so every hash signature it ships with
/// a smaller declared size is unreachable in ClamAV, standalone file or nested
/// layer alike. Six such signatures exist in a current main+daily set.
///
/// exav extracts more aggressively and had no such floor, which turned those
/// six pieces of auto-generated junk into live detections. Measured against
/// ClamAV 1.4.3 on the same inputs, which reports OK for both:
///
///   * a 1-byte file holding `V` matched `Win.Trojan.Agent-1720205`;
///   * the 2 bytes `\x00\x00` that a benign PDF's 2x2 image XObject decodes to
///     matched `Win.Malware.Agent-7761897-0`.
///
/// Note where this does NOT apply: the allow-list (`.fp`/`.sfp`) is matched
/// with the same machinery but must stay unfloored, since a suppression that
/// silently stopped working would cause exactly the false positives this
/// prevents.
///
/// Deliberately a bound on hash *matching*, not on scanning: a short object is
/// still extracted, still pattern-matched, still counted. Only the claim "this
/// hash identifies a file" is refused for something too small to be one. No
/// detection is lost, because every signature below the floor is one ClamAV
/// itself can never fire, so nothing can depend on it.
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

/// What the scan of one object works out about all of it, once however many
/// steps ask. Each costs a read of the whole object, which for one not held in
/// memory is a read of its whole source: for such an object, the first step to
/// ask makes one read for all of them.
pub(crate) struct Facts<'a> {
    data: &'a dyn ByteSource,
    /// What [`unpack::detect`] makes of it: for an object with no magic at its
    /// start, detection searches all of it.
    fmt: std::cell::OnceCell<Option<unpack::Format>>,
    /// Its whole-object digests, for the allowlist and the hash signatures.
    digests: std::cell::OnceCell<hashes::Digests>,
    /// What carving finds in it.
    embedded: std::cell::RefCell<Option<pe::Embedded>>,
    /// For an object not held in memory, what the one read is for, until it
    /// is made.
    shared: std::cell::Cell<Option<Shared>>,
    /// What that read found for detection, until detection asks.
    prescan: std::cell::RefCell<Option<unpack::Prescan>>,
}

/// What the one read of an object not held in memory computes: the digests
/// `want` names, detection's search, and carving's when `carve`.
#[derive(Clone, Copy)]
struct Shared {
    want: hashes::Want,
    carve: bool,
}

impl<'a> Facts<'a> {
    /// The facts of `data`, each worked out by a read of its own when asked.
    pub(crate) fn new(data: &'a dyn ByteSource) -> Self {
        Facts {
            data,
            fmt: std::cell::OnceCell::new(),
            digests: std::cell::OnceCell::new(),
            embedded: std::cell::RefCell::new(None),
            shared: std::cell::Cell::new(None),
            prescan: std::cell::RefCell::new(None),
        }
    }

    /// The facts of `data` scanned by `db`, carved when `carve`: when `data`
    /// is not held in memory, all worked out in one read of it.
    fn for_scan(data: &'a dyn ByteSource, db: &Scanner, carve: bool) -> Self {
        let facts = Facts::new(data);
        if data.as_slice().is_none() {
            facts.shared.set(Some(Shared {
                want: digests_wanted_by(db, data.len() as u64),
                carve,
            }));
        }
        facts
    }

    pub(crate) fn format(&self) -> Option<unpack::Format> {
        *self.fmt.get_or_init(|| {
            if self.shared.get().is_none() && self.prescan.borrow().is_none() {
                return unpack::detect(self.data);
            }
            unpack::detect_prescanned(self.data, &|| {
                self.read_once();
                // None only when the source gave nothing to read.
                self.prescan
                    .take()
                    .unwrap_or_else(|| unpack::Prescan::new(b""))
            })
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
            self.read_once();
        }
        self.digests.get_or_init(|| {
            hashes::digests_wanted(self.data, digests_wanted_by(db, self.data.len() as u64))
        })
    }

    /// What carving finds in the object, taken: carving runs once.
    fn embedded(&self) -> pe::Embedded {
        self.read_once();
        self.embedded
            .take()
            .unwrap_or_else(|| pe::embedded_in(self.data))
    }

    /// The one read of an object not held in memory, the first time a step
    /// asks, if it was not made yet.
    fn read_once(&self) {
        let Some(Shared { want, carve }) = self.shared.take() else {
            return;
        };
        let search = self.fmt.get().is_none() && unpack::Prescan::needed(self.data.len());
        if want == hashes::Want::default() && !carve && !search {
            return;
        }
        let data = self.data;
        let len = data.len();
        let mut hashing = (want != hashes::Want::default()).then(|| hashes::Hashing::new(want));
        let mut carving = carve.then(pe::Carving::new);
        let mut prescan = None;
        let overlap = unpack::Prescan::OVERLAP.max(pe::Carving::OVERLAP);
        let mut at = 0;
        while at < len {
            let w = data.window(at, (len - at).min(byte_source::CHUNK));
            if w.is_empty() {
                break;
            }
            if at == 0 && search {
                prescan = Some(unpack::Prescan::new(&w));
            }
            let searching = prescan.as_ref().is_some_and(|p| !p.done())
                || carving.as_ref().is_some_and(|c| !c.full());
            if hashing.is_none() && !searching {
                break;
            }
            let last = at + w.len() >= len;
            let owned = if last {
                w.len()
            } else {
                w.len().saturating_sub(overlap).max(1)
            };
            if let Some(h) = &mut hashing {
                h.update(&w[..owned]);
            }
            if let Some(c) = &mut carving {
                c.feed(data, at, &w, owned);
            }
            if let Some(p) = &mut prescan {
                p.feed(at, &w, last);
            }
            at += owned;
        }
        if let Some(h) = hashing {
            let _ = self.digests.set(h.finish());
        }
        if let Some(c) = carving {
            *self.embedded.borrow_mut() = Some(c.found);
        }
        *self.prescan.borrow_mut() = prescan;
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

/// Like [`unpack_format`] but content-aware: also recognises a UPX-packed
/// executable (which is classified as a PE/ELF/Mach-O, not a container) so its
/// embedded original is decompressed and scanned.
fn unpack_target(
    ft: FileType,
    facts: &Facts,
    restrict: bool,
    opts: &ScanOptions,
) -> Option<unpack::Format> {
    let data = facts.data;
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
    // Formats with no ClamAV `CL_TYPE_*` of their own (disk images and Unix
    // `compress`) are typed `Unknown`, so `unpack_format` cannot reach them.
    // They still hold real content (a compressed QCOW2 cluster or a `.Z` stream
    // shows none of its payload in the file's bytes), so dispatch them straight
    // from the magic. Compat mode leaves them off: stock ClamAV opens none of
    // them, and extracting more there would be counted as a disagreement.
    let detected = || facts.format();
    if !restrict {
        if let Some(fmt) = detected() {
            if filetype::MAGIC_DISPATCH_ONLY.contains(&fmt) {
                return Some(fmt);
            }
        }
    }
    // Installers and self-extractors: real executables, so `identify` answers
    // `Pe`/`Elf` and `unpack_format` has nothing to map. Their payload is the
    // installer's own format rather than a recognisable archive, so carving does
    // not reach it either. Without this an NSIS or Inno installer scans clean
    // with every file it packages unexamined.
    if ft.is_executable() {
        if let Some(fmt) = detected() {
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
    // scope so exav's broader reach (e.g. UPX-packed Mirai ELFs, which exav
    // decompresses and detects but ClamAV leaves packed and misses) isn't
    // counted as a disagreement. PE-UPX stays on either way (ClamAV does it too).
    //
    // This and the packer check below apply to executables only, and read one
    // whole.
    if !ft.is_executable() {
        return None;
    }
    let image = whole(data, opts, "the UPX and packer checks")?;
    if unpack::is_upx(&image) {
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
    // differential run compare like with like (same alert *names*, same rough
    // feature scope), not to hold coverage down to another engine's. Skipping an
    // unpacker here would mean deliberately not looking inside a packed dropper,
    // and a miss is a miss whatever mode produced it.
    //
    // Only meaningful for PE (the detector requires a PE image), but
    // `is_executable` keeps it symmetric with UPX.
    if unpack::is_pepack(&image) {
        return Some(unpack::Format::PePacked);
    }
    None
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
/// member names present in its central directory. A `.docx`/`.xlsx`/`.pptx` is
/// the `CL_TYPE_OOXML_*` container type (not plain `CL_TYPE_ZIP`) in the
/// signature format, and many sigs are scoped to those types; typing them this
/// way keeps such sigs firing on real Office documents while staying off plain
/// ZIPs. The marker is the conventional top-level part for each kind plus the
/// OOXML `[Content_Types].xml` package descriptor.
fn ooxml_subtype(data: &dyn ByteSource) -> Option<engine::ClType> {
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
fn contains_window(haystack: &dyn ByteSource, needle: &[u8]) -> bool {
    haystack.find(needle, 0, haystack.len()).is_some()
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

/// A verdict reason with its control characters replaced.
///
/// Reasons quote container member names, which come from the file being
/// scanned. Every front-end prints the reason inside a line-framed reply (the
/// clamd protocol, the clamscan-style CLI line, the `--log` file), so a newline
/// in a member name would let the file write a line of its own, such as a
/// second `stream: OK` for a client that reads the last line it gets.
fn one_line(reason: String) -> String {
    if !reason.chars().any(char::is_control) {
        return reason;
    }
    reason
        .chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
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
    /// Exceeding yields `LimitsExceeded`.
    pub max_scan_size: Option<u64>,
    /// Largest object held in memory (`--max-object-bytes`). A larger one gets
    /// the same scan, read through a block cache or, for a decoded member, a
    /// spill file; the checks that parse an object whole do not run on it, and
    /// if nothing is found it is reported `LimitsExceeded`. A decoded member
    /// over this limit with no spill to go to is not scanned, and reported.
    /// A scan also holds `limits.max_buffer_bytes` to it. Default 256 MiB.
    pub deep_analysis_max: u64,
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
    pub clamav_heuristics: bool,
    /// Report findings under ClamAV's vocabulary where the two engines describe
    /// the same fact differently. Set by [`ScanOptions::clamav_compat`].
    ///
    /// This changes NAMES, never what is detected. exav does not withhold a
    /// finding in either mode, and does not adopt a check it believes is wrong:
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
    /// Narrows two things to ClamAV's scope: (1) archive extractors, skipping the
    /// formats stock ClamAV lacks: `ar` (Unix archive / `.deb` / `.a`), `lzip`,
    /// Inno Setup, and the magic-dispatched disk-image / Unix `compress` formats
    /// (verified against 1.4.x, which handles cpio/xar natively); (2) UPX: to PE
    /// only (ClamAV's UPX unpacker runs only from its PE path, never ELF/Mach-O).
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

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_scan_size: None,
            deep_analysis_max: 256 * 1024 * 1024,
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
            deep_analysis_max: 400 * 1024 * 1024,
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
        let data = facts.data;
        let mut ft = filetype::identify_source_with(data, || facts.format());
        if ft == FileType::Unknown {
            if let Some(f) = self.ftm.identify_source(data) {
                ft = f;
            }
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
        let false_archive = match ft {
            FileType::Bzip2 => facts.format() != Some(unpack::Format::Bzip2),
            FileType::Cab => facts.format() != Some(unpack::Format::Cab),
            FileType::Gzip => facts.format() != Some(unpack::Format::Gzip),
            FileType::Arj => facts.format() != Some(unpack::Format::Arj),
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
    /// wildcards, PCRE/bytecode subsignatures).
    pub fn unsupported_count(&self) -> usize {
        self.engine.unsupported
    }
}

/// Scan a local file: [`scan_seekable`] over the opened file, with its path
/// as the YARA `filepath`/`filename`/`extension` unless `opts.filename` is
/// set. The file must be able to seek; a FIFO or other stream is buffered by
/// the caller first.
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
    scan_seekable(db, file, size, opts)
}

/// Whether the object's whole-file hash is on the `.fp`/`.sfp` allowlist.
fn allowlisted(db: &Scanner, facts: &Facts) -> bool {
    !db.allow.is_empty()
        && db
            .allow
            .lookup(facts.digests(db), facts.data.len() as u64)
            .is_some()
}

/// Build every structure a scan initialises lazily (engine automata, compiled
/// YARA rules), so a process that forks workers after loading shares them
/// copy-on-write instead of each worker building its own.
pub fn warm_up(db: &Scanner) {
    const PROBE: &[u8] = b"MZ\x90\x00\x00\x00\x00\x00";
    let _ = analyze(db, PROBE, &ScanOptions::default());
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
/// semantics). A no-op at top level (empty path): a top-level detection has no
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

/// Scan an input: the one scan every entry point runs, whether the bytes come
/// from a file, a buffered stream (stdin, `INSTREAM`, ICAP) or an HTTP range
/// source.
///
/// `size` is the input's full size. Past `--max-input-bytes` the reader need
/// only hold the first `max_scan_size` bytes: those get the whole scan, and
/// with no detection in them the input is reported over the limit.
///
/// An input within `deep_analysis_max` is read into memory; a larger one is
/// read through a block cache of bounded size, by offset, as the scan needs it.
/// Either way it gets the same scan.
pub fn scan_seekable<R: Read + Seek>(
    db: &Scanner,
    mut reader: R,
    size: u64,
    opts: &ScanOptions,
) -> io::Result<ScanReport> {
    // Thread-local, so it carries over from whatever this thread scanned last
    // unless every entry point clears it.
    engine::reset_scan_truncated();
    if let Some(max) = opts.max_scan_size {
        if size > max {
            // Invariant 2 (see crate docs): scan what is within the limit
            // before refusing by size, so a detection in it still wins.
            let head = scan_within(db, Window::new(&mut reader, max)?, max, opts)?;
            if head.verdict.category() == VerdictCategory::Infected {
                return Ok(head);
            }
            return Ok(max_file_size_report(size, max, opts));
        }
    }
    scan_within(db, reader, size, opts)
}

/// [`scan_seekable`] for an input within `--max-input-bytes`.
fn scan_within<R: Read + Seek>(
    db: &Scanner,
    mut reader: R,
    size: u64,
    opts: &ScanOptions,
) -> io::Result<ScanReport> {
    if size <= opts.deep_analysis_max {
        // Bounded, so a source whose size under-reports its length cannot
        // stream unbounded.
        let mut data = Vec::new();
        (&mut reader)
            .take(opts.deep_analysis_max.saturating_add(1))
            .read_to_end(&mut data)?;
        if data.len() as u64 <= opts.deep_analysis_max {
            return Ok(analyze(db, &data, opts));
        }
        // It grew while it was read: scanned as the larger object it now is.
        reader.seek(SeekFrom::Start(0))?;
    }
    let cache = byte_source::BlockCache::new(reader)?;
    let report = analyze_source(db, &cache, opts);
    // A read that failed part way leaves bytes the scan never saw.
    if let Some(e) = cache.read_error() {
        return Err(io::Error::other(e));
    }
    Ok(report)
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
    // Nothing is held in memory past the deep-analysis limit, a container its
    // format reads whole included.
    let mut limits = opts.limits.clone();
    limits.max_buffer_bytes = limits.max_buffer_bytes.min(opts.deep_analysis_max);
    let mut b = Budget::with_passwords(limits, pool);
    b.set_verify_checksums(opts.verify_checksums);
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
    if opts.alert_exceeds_max {
        if let Some(name) = limits_alert_name(unpack::LimitKind::MaxFileSize) {
            match_loc_record();
            return ScanReport::infected(name.to_string(), 0, Method::Heuristic, Vec::new());
        }
    }
    ScanReport::limits(
        format!("file size {size} exceeds max-input-bytes {max}; scanned first {max} bytes only"),
        Vec::new(),
    )
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

/// Map an extraction [`unpack::LimitHit`] to an outcome: a resource bound is
/// `Limits` (or its alert under `--alert-exceeds-max`); undecodable content is
/// `Unscannable`.
fn outcome_for_hit(hit: unpack::LimitHit, opts: &ScanOptions) -> DeepOutcome {
    if hit.is_corrupt() {
        DeepOutcome::Unscannable(hit.reason)
    } else {
        limits_outcome(opts, hit.kind, hit.reason)
    }
}

/// A member's bytes, once read.
enum Body {
    /// Nothing to scan: the member was not decoded, or could not be read.
    None,
    Mem(Vec<u8>),
    /// Too large to hold, and written to the host's spill.
    Spilled(spill::Spilled),
}

/// Read a member decoded as it is read: into memory up to the deep-analysis
/// limit, else to the host's spill, the prefix already read first. What could
/// not be read is noted on the tally; `Err` means the walk must stop.
///
/// A decode error keeps what was decoded before it (a truncated gzip or tar
/// must not hide the payload in its readable part), and `failed` says why the
/// rest is missing.
fn read_member(
    cx: &MemberCtx<'_>,
    tally: &mut MemberTally,
    rdr: &mut dyn Read,
    verify_checksums: bool,
    failed: &mut Option<io::Error>,
) -> Result<Body, DeepOutcome> {
    let cap = cx.opts.deep_analysis_max;
    // The walk reports the budget that ran out once the member is left.
    let over_budget = || DeepOutcome::Limits("member exceeds the scan budget".to_string());
    let mut buf = Vec::new();
    // One byte past the cap: reading exactly `cap` cannot tell a member that
    // just fits from one that does not.
    let mut head = rdr.take(cap.saturating_add(1));
    match head.read_to_end(&mut buf) {
        Err(e) if unpack::is_budget_overflow(&e) => return Err(over_budget()),
        Err(e) if verify_checksums || buf.is_empty() => {
            tally
                .unscannable
                .get_or_insert_with(|| format!("member decode error: {e}"));
            return Ok(Body::None);
        }
        Err(e) => {
            buf.truncate(cap as usize);
            *failed = Some(e);
            return Ok(Body::Mem(buf));
        }
        Ok(_) if buf.len() as u64 <= cap => return Ok(Body::Mem(buf)),
        Ok(_) => {}
    }
    let rest = head.into_inner();
    let not_scanned = |tally: &mut MemberTally, why: &str| {
        let reason = format!(
            "a member is over the {cap}-byte deep-analysis limit \
             (--max-object-bytes) and could not be spilled to disk ({why}): \
             it was not scanned"
        );
        match limits_outcome(cx.opts, unpack::LimitKind::MaxFileSize, reason) {
            DeepOutcome::Limits(r) => {
                tally.limits.get_or_insert(r);
                Ok(Body::None)
            }
            alert => Err(alert),
        }
    };
    let Some(spill) = &cx.opts.spill else {
        return not_scanned(tally, "spilling to disk is off");
    };
    match spill::spill_stream(spill.as_ref(), &mut io::Cursor::new(buf).chain(rest)) {
        Ok(spilled) => Ok(Body::Spilled(spilled)),
        Err(spill::SpillStreamError::Read(e)) if unpack::is_budget_overflow(&e) => {
            Err(over_budget())
        }
        Err(spill::SpillStreamError::Read(e)) => {
            tally
                .unscannable
                .get_or_insert_with(|| format!("member stream error: {e}"));
            Ok(Body::None)
        }
        Err(spill::SpillStreamError::Spill(e)) => not_scanned(tally, &e),
    }
}

/// One member of a container walk: its metadata, then its bytes, scanned as an
/// object one level down. `Some` means the walk must stop.
#[allow(clippy::too_many_arguments)]
fn visit_member(
    cx: &MemberCtx<'_>,
    tally: &mut MemberTally,
    volumes: &mut unpack::volume::Collector,
    container: &dyn ByteSource,
    meta: &unpack::MemberMeta,
    content: Option<unpack::Member<'_>>,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
    let mut failed = None;
    let body = match content {
        None => Body::None,
        Some(unpack::Member::Bytes(data)) => Body::Mem(data),
        Some(unpack::Member::Stream(rdr)) => {
            let verify = budget.should_verify_checksums();
            match read_member(cx, tally, rdr, verify, &mut failed) {
                Ok(body) => body,
                Err(stop) => return Some(stop),
            }
        }
    };
    // A member byte-identical to its container is a **fixed point**: typing it
    // re-detects the same format, which yields the same member, forever. It is
    // never a real member (nothing was unwrapped), and following it burns the
    // whole recursion budget on one buffer, so the content that actually needed
    // those levels never gets reached. Skipping loses nothing: these exact
    // bytes are already being scanned, as the container.
    //
    // A FAT boot sector read as an MBR produces one, and a gzip can be built
    // to decompress to itself, so the guard lives here rather than in any
    // extractor. The length test is false for essentially every real member,
    // so the comparison is only reached by a genuine fixed point.
    if let Body::Mem(data) = &body {
        if data.len() == container.len() && *container.window(0, data.len()) == data[..] {
            return None;
        }
    }
    let size_real = match &body {
        Body::Mem(data) => data.len() as u64,
        Body::Spilled(spilled) => spilled.len() as u64,
        Body::None => meta.comp_size,
    };
    if let Some(o) = member_metadata_scan(cx, tally, meta, size_real, sink) {
        return Some(o);
    }
    match body {
        Body::None => None,
        // Nothing decoded: the metadata above is all this member has.
        Body::Mem(data) if data.is_empty() && meta.unsupported.is_some() => None,
        Body::Mem(data) => {
            if let Some(e) = failed {
                // Every byte that decoded was scanned. A member that ran out
                // of input has its tail absent, not hidden, and a clean scan
                // of it is a real Clean: exav scans for malware, it is not a
                // file-integrity validator. Undecodable bytes still present
                // keep the not-fully-scanned verdict.
                let o = member_content_scan(cx, tally, &data, budget, findings, sink);
                if o.is_none() && unpack::decode_error_hides_content(&e) {
                    tally.unscannable.get_or_insert_with(|| {
                        format!(
                            "member decode error (salvaged {} B, no match): {e}",
                            data.len()
                        )
                    });
                }
                return o;
            }
            // A part of a byte-split set is a fragment of a file that only
            // exists once the set is rejoined, so it is held rather than
            // scanned on its own. A part cut short above is not offered: it
            // would splice a hole into the rejoined archive.
            let data = match volumes.offer(&meta.name, data) {
                unpack::volume::Offer::Held => return None,
                unpack::volume::Offer::PassThrough { data, .. } => data,
            };
            member_content_scan(cx, tally, &data, budget, findings, sink)
        }
        Body::Spilled(spilled) => {
            let o = member_content_scan(cx, tally, &spilled, budget, findings, sink);
            if let Some(e) = spilled.read_error() {
                tally
                    .unscannable
                    .get_or_insert_with(|| format!("spilled member unreadable: {e}"));
            }
            o
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
    if obj.depth >= budget.limits().max_recursion {
        return limits_outcome(
            opts,
            unpack::LimitKind::MaxRecursion,
            format!("recursion depth exceeds {}", budget.limits().max_recursion),
        );
    }
    // The type the members belong to, so signatures scoped with
    // `Container:CL_TYPE_*` fire only inside their intended container. A ZIP
    // is sub-typed as OOXML Word/Excel/PowerPoint by its part names.
    let member_container = container_cltype(fmt, data);
    // The members are one layer below this container, so it is on their
    // ancestry (`Intermediates:`) for as long as they are scanned.
    let _ag = engine::AncestryGuard::enter(member_container);
    let cx = MemberCtx {
        db,
        opts,
        container_size: data.len() as u64,
        container_is_ole: fmt == unpack::Format::Ole,
        member_container,
        ft,
        fmt,
        depth: obj.depth,
    };
    let mut tally = MemberTally::new();
    // Parts of a byte-split set (`x.7z.001`, `.002`, …) are held here and
    // rejoined once the walk has ended.
    let mut volumes = unpack::volume::Collector::new(budget.limits().max_buffer_bytes);
    // Inclusive wall time: this drives the member scans, so `unpack_us`
    // contains the member matchers' time too, and `emu_us` splits the
    // emulator's share of it out.
    let walk = profile::timed("unpack", data.len() as u64, || {
        unpack::walk(fmt, data, budget, &mut |meta, content, budget| {
            // Track this member on the location stack for its scan, so a
            // detection in it, or deeper, reports the full path.
            let _mpg = MatchPathGuard::enter(&meta.name);
            visit_member(
                &cx,
                &mut tally,
                &mut volumes,
                data,
                meta,
                content,
                budget,
                findings,
                sink,
            )
        })
    });
    // Reassembly happens only now. Nothing in a byte-split set's names says
    // how many parts it has, so `.001`+`.002` looks contiguous even when
    // `.003` follows: joining on arrival would emit a truncated prefix that
    // still parses as the archive and would then be scanned as if whole.
    let held = volumes.finish();
    let mut terminal = match walk {
        Ok(o) => o,
        Err(hit) => Some(outcome_for_hit(hit, opts)),
    };
    // Rejoined files first, then the parts that could not be joined. Bytes
    // withheld from the scan and then dropped would be exactly the silent
    // clean this scanner exists to prevent.
    for (name, buf, incomplete) in held.into_scannable() {
        if terminal.is_some() {
            break;
        }
        // A set with a gap in it can no longer be read by anything, not by us
        // and not by the tool that wrote it.
        if let Some(reason) = incomplete {
            tally.unscannable.get_or_insert_with(|| reason.to_string());
        }
        // The parts were charged as they were read; this is a buffer the
        // collector made.
        if let Err(h) = budget.charge_scan(buf.len() as u64) {
            terminal = Some(limits_outcome(opts, h.kind, h.reason));
            break;
        }
        let _mpg = MatchPathGuard::enter(&name);
        terminal = member_content_scan(&cx, &mut tally, &buf, budget, findings, sink);
    }
    terminal.unwrap_or_else(|| tally.verdict())
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
/// `Unscannable` instead. The dropped part's own scan, which the caller does
/// separately, still covers that part's bytes.
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
        // `PassThrough` means the collector declined to hold it: the held-bytes
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
        // A lone numbered file is not a set: plenty of ordinary files end in
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

/// Scan an object held in memory: [`scan_seekable`] without the reader.
pub fn analyze(db: &Scanner, data: &[u8], opts: &ScanOptions) -> ScanReport {
    analyze_source(db, &data, opts)
}

/// As [`analyze`], over an object that need not be held in memory.
fn analyze_source(db: &Scanner, data: &dyn ByteSource, opts: &ScanOptions) -> ScanReport {
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
        &mut Sink::First(&db.ignored),
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
        DeepOutcome::Unscannable(reason) => ScanReport::unscannable(reason, findings),
        DeepOutcome::PasswordProtected(reason) => ScanReport::password_protected(reason, findings),
        DeepOutcome::Clean => match unfinished(opts) {
            Some(outcome) => report_of_outcome(outcome, findings, opts),
            None => ScanReport::clean(findings),
        },
    }
}

/// What a walk that found nothing amounts to when a check did not finish:
/// the size limit, when an object too large to hold kept one from running,
/// else an incomplete search (a per-buffer bound ran out). `None` when the
/// walk was complete and `Clean` is the true answer.
fn unfinished(opts: &ScanOptions) -> Option<DeepOutcome> {
    if let Some(reason) = engine::scan_over_size() {
        return Some(limits_outcome(opts, unpack::LimitKind::MaxFileSize, reason));
    }
    engine::scan_was_truncated().then(|| DeepOutcome::Limits(SEARCH_INCOMPLETE.into()))
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
pub fn analyze_all_seekable<R: Read + Seek>(
    db: &Scanner,
    mut reader: R,
    size: u64,
    opts: &ScanOptions,
) -> io::Result<(Vec<(String, Method)>, AllMatchOutcome)> {
    if size <= opts.deep_analysis_max {
        let mut data = Vec::new();
        (&mut reader)
            .take(opts.deep_analysis_max.saturating_add(1))
            .read_to_end(&mut data)?;
        if data.len() as u64 <= opts.deep_analysis_max {
            return Ok(analyze_all_with_outcome(db, &data, opts));
        }
        reader.seek(SeekFrom::Start(0))?;
    }
    let cache = byte_source::BlockCache::new(reader)?;
    let found = analyze_all_source(db, &cache, opts);
    // A read that failed part way leaves bytes the scan never saw.
    if let Some(e) = cache.read_error() {
        return Err(io::Error::other(e));
    }
    Ok(found)
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
        Some(DeepOutcome::Unscannable(r)) => AllMatchOutcome::Unscannable(one_line(r)),
        Some(DeepOutcome::PasswordProtected(r)) => AllMatchOutcome::PasswordProtected(one_line(r)),
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
    let mut sink = Sink::All {
        out: &mut out,
        seen: &mut seen,
        ignored: &db.ignored,
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
/// deep-analysis limit, and the scan says so (see [`whole`]).
///
/// `Some(outcome)` means the walk must stop and return it.
fn whole_buffer_heuristics(
    src: &dyn ByteSource,
    ft: FileType,
    embedded: bool,
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
        if unpack::overlapping_local_records(src) > OVERLAP_THRESHOLD {
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
        // The stream header and the first block header, which is at most
        // 1024 bytes.
        if let Some(dict) = unpack::xz_declared_dict_size(&src.window(0, 12 + 1024 + 64)) {
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
    if opts.alert_broken_media && media {
        if let Some(name) = whole().and_then(unpack::broken_media_alert) {
            if let Some(o) = sink.hit(name.to_string(), 0, Method::Heuristic) {
                return Some(o);
            }
        }
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
    if opts.alert_broken && executable && !embedded && pe::looks_broken_in(src) {
        if let Some(o) = sink.hit(
            "Heuristics.Broken.Executable".to_string(),
            0,
            Method::Heuristic,
        ) {
            return Some(o);
        }
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
    if opts.alert_partition_intersection {
        if let Some(name) = unpack::partition_intersection_alert(src) {
            if let Some(o) = sink.hit(name.to_string(), 0, Method::Heuristic) {
                return Some(o);
            }
        }
    }

    // ClamAV `Heuristics.PDF.ObfuscatedNameObject`: a PDF whose name objects
    // hex-escape plain alphanumerics (`/J#61vaScript`) to hide keywords from
    // naive scanners. Structural and FP-safe: only gratuitous escapes count.
    // Applied to the raw document, before the PDF is unpacked.
    #[cfg(feature = "pdf")]
    if (opts.clamav_heuristics || opts.heuristics)
        && ft == FileType::Pdf
        && whole().is_some_and(unpack::has_obfuscated_name_object)
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
/// only thing parameterised: the traversal reports to a sink rather than
/// returning a verdict, and there is exactly one traversal.
///
/// Two walks cannot be kept in step by discipline. Each capability added to one
/// and not the other changes *which signatures and heuristics run*, silently,
/// and the symptom is a clean verdict rather than an error.
enum Sink<'a> {
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

impl Sink<'_> {
    /// Record a detection. `Some(outcome)` means this walk must stop and return
    /// it; `None` means carry on looking.
    fn hit(&mut self, signature: String, offset: u64, method: Method) -> Option<DeepOutcome> {
        match self {
            Sink::First(ignored) => {
                if ignored.contains(&signature) {
                    return None;
                }
                match_loc_record();
                Some(DeepOutcome::Infected {
                    signature,
                    offset,
                    method,
                })
            }
            Sink::All { out, seen, ignored } => {
                match_loc_record();
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
    /// Unlike `Limits` it does NOT stop scanning sibling members; it's
    /// remembered and surfaced only if nothing infected is found.
    Unscannable(String),
    /// An encrypted member: like `Unscannable` but actionable (re-scan with a
    /// password). Takes precedence over `Unscannable`.
    PasswordProtected(String),
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
    ft: FileType,
    fmt: unpack::Format,
    depth: u32,
}

/// Outcomes gathered across a container's members that do not stop the loop.
/// They decide the verdict once every member has been seen.
struct MemberTally {
    /// The next member's 1-based position in this container (`.cdb` `FilePos`).
    pos: u64,
    unscannable: Option<String>,
    password: Option<String>,
    /// A size limit cut the analysis of something short without stopping the
    /// walk: the rest of the members were still scanned.
    limits: Option<String>,
}

impl MemberTally {
    fn new() -> Self {
        MemberTally {
            pos: 1,
            unscannable: None,
            password: None,
            limits: None,
        }
    }

    fn verdict(self) -> DeepOutcome {
        // Precedence among incomplete outcomes: PasswordProtected (actionable)
        // over Limits over Unscannable over Clean.
        match (self.password, self.limits, self.unscannable) {
            (Some(r), _, _) => DeepOutcome::PasswordProtected(r),
            (None, Some(r), _) => DeepOutcome::Limits(r),
            (None, None, Some(r)) => DeepOutcome::Unscannable(r),
            (None, None, None) => DeepOutcome::Clean,
        }
    }
}

/// The checks that read a member's *metadata* (name, size, position,
/// encryption) rather than its content.
///
/// Run as each member arrives, before any decision about its bytes, so
/// positions stay in container order even for members whose content is held
/// back to be rejoined. `size_real` is its decoded size, or its size in the
/// container when it was not decoded. The caller owns the [`MatchPathGuard`].
fn member_metadata_scan(
    cx: &MemberCtx<'_>,
    tally: &mut MemberTally,
    e: &unpack::MemberMeta,
    size_real: u64,
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
    // Opt-in (`--detect packed`): name the packer as well as reporting that its
    // payload went unread. Same rule as the encryption case above: two facts,
    // both true, both reported.
    if cx.opts.alert_packed {
        if let Some(n) = packed_heuristic_name(&e.name) {
            if let Some(o) = sink.hit(n, 0, Method::Heuristic) {
                return Some(o);
            }
        }
    }
    if let Some(r) = e.unsupported {
        if e.encrypted {
            // Only an encrypted member we could NOT read is password-blocked.
            // A decrypted one has its content and must not degrade the verdict
            // to PasswordProtected; this is the one place the two facts stay
            // deliberately separate.
            tally.password.get_or_insert_with(|| r.to_string());
        } else {
            tally.unscannable.get_or_insert_with(|| r.to_string());
        }
    }
    // Opt-in ClamAV heuristic (`--alert-macros`): an OLE2 document carrying a
    // VBA project surfaces `vba_project*` artifacts from the OLE extractor;
    // their presence means the document has macros.
    if cx.opts.alert_macros && cx.container_is_ole {
        // ClamAV suffixes the macro dialect: `.VBA` for a VBA project, `.XLM`
        // for an Excel 4.0 macro sheet. Emitting the bare name looked harmless
        // and is not: a gateway filtering on ClamAV's exact string matches
        // neither of ours.
        if let Some(kind) = macro_dialect(&e.name) {
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
            name: &e.name,
            size_in_container: e.comp_size,
            size_real,
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

/// Scan one member's bytes, as an object one level below its container.
///
/// Split from [`member_metadata_scan`] because a member of a multi-volume set
/// has its metadata read on arrival but its content scanned only after the
/// container ends, once the set has been rejoined. The caller owns the
/// [`MatchPathGuard`]: this is entered under the member's own name in the
/// visitor and under the rejoined file's name afterwards.
fn member_content_scan(
    cx: &MemberCtx<'_>,
    tally: &mut MemberTally,
    data: &dyn ByteSource,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> Option<DeepOutcome> {
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
        core_type,
        filename: None,
        core: true,
        carve: true,
        embedded: false,
    };
    match scan_object(cx.db, data, obj, cx.opts, budget, findings, sink) {
        DeepOutcome::Clean => None,
        // Nested unscannable/encrypted members are remembered, not propagated as
        // a stop: keep scanning the rest of this container.
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

/// Where an object sits in the scan, and what its container decided about it.
#[derive(Clone, Copy)]
struct Obj<'a> {
    /// Nesting depth; the input is at 0.
    depth: u32,
    /// The type of the container the object sits in, for `Container:`-scoped
    /// signatures. Inherited by what is carved or decoded out of the object,
    /// rather than over-matching.
    container: Option<engine::ClType>,
    /// The type the matching core takes the object for, when its container
    /// decides that (a textual OLE stream is matched as OLE); else its own.
    core_type: Option<FileType>,
    /// The input's name, for YARA's filename externals. Nothing inside the
    /// input has one.
    filename: Option<&'a str>,
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
}

impl<'a> Obj<'a> {
    /// The input.
    fn top(opts: &'a ScanOptions) -> Self {
        Obj {
            depth: 0,
            container: None,
            core_type: None,
            filename: opts.filename.as_deref(),
            core: true,
            carve: true,
            embedded: false,
        }
    }

    /// Something found inside this object, one level down, in `container`.
    fn inner(self, container: Option<engine::ClType>) -> Self {
        Obj {
            depth: self.depth + 1,
            container,
            core_type: None,
            filename: None,
            core: true,
            carve: true,
            embedded: false,
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
    // Content the operator has vouched for (`.fp`/`.sfp`): neither it nor
    // anything inside it is a detection. Keyed on the object's bytes, so an
    // entry means the same thing wherever the object is found.
    let carve = obj.carve && obj.depth < budget.limits().max_recursion;
    let facts = Facts::for_scan(data, db, carve);
    if allowlisted(db, &facts) {
        return DeepOutcome::Clean;
    }
    let ft = db.identify_facts(&facts);
    match unpack_target(ft, &facts, opts.restrict_extractors, opts) {
        Some(fmt) if !ft.is_executable() => {
            scan_archive(db, &facts, obj, ft, fmt, opts, budget, findings, sink)
        }
        fmt => scan_file(db, &facts, obj, ft, fmt, opts, budget, findings, sink),
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
    if obj.depth == 0 {
        findings.push(Finding::new("type", ft.as_str()));
    }
    if let Some(o) = scan_carried(db, data, obj, ft, opts, budget, findings, sink) {
        return o;
    }
    let members = walk_members(db, data, obj, ft, fmt, opts, budget, findings, sink);
    // Matched whatever stopped the walk short of a detection: a detection beats
    // a limit.
    if matches!(members, DeepOutcome::Infected { .. }) || !obj.core {
        return members;
    }
    let mut outcome = members;
    let rest = match core(db, facts, obj.core_type.unwrap_or(ft), obj, opts, sink) {
        Ok(rest) => rest,
        Err(stop) => return stop,
    };
    scan_unpacked(
        db,
        rest.unpacked,
        obj,
        opts,
        budget,
        findings,
        sink,
        &mut outcome,
    )
    .unwrap_or(outcome)
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
) -> Option<DeepOutcome> {
    // Embedded base64-encoded executables. Scripts/RTF/HTML carriers stash a
    // PE/ELF as a long base64 string (PowerShell reflective loaders, JS/VBS
    // droppers) that is invisible to a signature matching the decoded bytes.
    // Decode such blobs (in a text-ish buffer) and rescan any that decode to a
    // real executable. Bounded by recursion depth and the scan budget;
    // exav-exclusive, so off under `--clamav-compat` and `--no-base64`.
    #[cfg(feature = "base64scan")]
    if opts.decode_base64
        && obj.depth < budget.limits().max_recursion
        && mostly_text(&data.window(0, 8192))
    {
        for (b64ix, payload) in unpack::base64_payloads(data, budget.limits().max_buffer_bytes)
            .into_iter()
            .enumerate()
        {
            // Name the decoded run so a hit inside it is attributable. Without
            // this the detection reports no location and reads as a match on the
            // carrier's own bytes, which is how a correct `Win.Trojan.Mimikatz`
            // hit, on a PE base64-encoded inside an RTF, looked like a PE-only
            // signature firing on an RTF.
            let _mpg = MatchPathGuard::enter(&format!("base64-payload-{}", b64ix + 1));
            // The payload's container is the CARRIER, not whatever the carrier
            // itself sits in: a `data:` URI image inside an HTML page has
            // `Container:CL_TYPE_HTML`, which is how a family of phishing
            // signatures scopes a logo's perceptual hash so it fires on a page
            // and not on the same image standing alone.
            let payload_container = carrier_cltype(ft).or(obj.container);
            let _ag = engine::AncestryGuard::enter(payload_container);
            let inner = Obj {
                carve: false,
                ..obj.inner(payload_container)
            };
            let o = scan_found(db, &payload, inner, opts, budget, findings, sink);
            if matches!(o, DeepOutcome::Infected { .. } | DeepOutcome::Limits(_)) {
                return Some(o);
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
    if opts.decode_base64 && obj.depth < budget.limits().max_recursion {
        if let Some(mc) = markup_cltype(ft, &data.window(0, 4096)) {
            let _ag = engine::AncestryGuard::enter(Some(mc));
            for (ix, payload) in
                unpack::markup_embedded_payloads(data, budget.limits().max_buffer_bytes)
                    .into_iter()
                    .enumerate()
            {
                let _mpg = MatchPathGuard::enter(&format!("embedded-asset-{}", ix + 1));
                let inner = Obj {
                    carve: false,
                    ..obj.inner(Some(mc))
                };
                let o = scan_found(db, &payload, inner, opts, budget, findings, sink);
                if matches!(o, DeepOutcome::Infected { .. } | DeepOutcome::Limits(_)) {
                    return Some(o);
                }
            }
        }
    }

    whole_buffer_heuristics(data, ft, obj.embedded, opts, sink)
}

/// [`scan_object`] for content found inside another object rather than
/// decoded from a container, charged to the scan budget (a container's
/// members are charged as they are decoded).
fn scan_found(
    db: &Scanner,
    data: &dyn ByteSource,
    obj: Obj<'_>,
    opts: &ScanOptions,
    budget: &mut Budget,
    findings: &mut Vec<Finding>,
    sink: &mut Sink,
) -> DeepOutcome {
    if let Err(h) = budget.charge_scan(data.len() as u64) {
        return limits_outcome(opts, h.kind, h.reason);
    }
    scan_object(db, data, obj, opts, budget, findings, sink)
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
        let _mpg = MatchPathGuard::enter(&format!("bytecode-unpacked-{}", i + 1));
        // An unpacker that fires again on its own output would never stop.
        if obj.depth >= budget.limits().max_recursion {
            return Some(limits_outcome(
                opts,
                unpack::LimitKind::MaxRecursion,
                format!("recursion depth exceeds {}", budget.limits().max_recursion),
            ));
        }
        match scan_found(
            db,
            &buf,
            obj.inner(obj.container),
            opts,
            budget,
            findings,
            sink,
        ) {
            DeepOutcome::Clean => {}
            o @ (DeepOutcome::Infected { .. } | DeepOutcome::Limits(_)) => return Some(o),
            o => defer(deferred, o),
        }
    }
    None
}

/// Keep the first outcome that does not stop the walk.
fn defer(slot: &mut DeepOutcome, outcome: DeepOutcome) {
    if matches!(slot, DeepOutcome::Clean) {
        *slot = outcome;
    }
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
        let rest = match core(db, facts, obj.core_type.unwrap_or(ft), obj, opts, sink) {
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
                match core(db, facts, retyped, obj, opts, sink) {
                    Ok(rest) => unpacked.extend(rest.unpacked),
                    Err(stop) => return stop,
                }
                let fmt = unpack_target(retyped, facts, opts.restrict_extractors, opts);
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
    if let Some(o) = scan_carried(db, data, obj, ft, opts, budget, findings, sink) {
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
        // clean result falls through to the carving below, carrying any
        // `UNSCANNABLE`/`PASSWORD-PROTECTED` verdict with it so that it is
        // still reported if nothing is carved.
        let packed_executable = matches!(fmt, unpack::Format::Upx | unpack::Format::PePacked);
        match verdict {
            DeepOutcome::Infected { .. } | DeepOutcome::Limits(_) => return verdict,
            other => defer(&mut deferred, other),
        }
        if !packed_executable {
            return deferred;
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
        let images = embedded
            .pe
            .into_iter()
            .chain(embedded.elf)
            .chain(embedded.macho);
        for off in images {
            let sub = &byte_source::Sub::new(data, off, data.len() - off);
            match scan_found(db, sub, carved, opts, budget, findings, sink) {
                DeepOutcome::Clean => {}
                other => return other,
            }
        }

        // Embedded archives: a ZIP/CAB/7z/RAR/GZIP/XZ appended to or stapled
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
            let archive = Obj {
                core: false,
                ..carved
            };
            match scan_found(db, sub, archive, opts, budget, findings, sink) {
                // A real detection in an appended/stapled archive is the whole
                // point of carving: surface it. A genuine resource limit (e.g. a
                // decompression bomb in a real appended archive) still matters.
                inf @ DeepOutcome::Infected { .. } => return inf,
                lim @ DeepOutcome::Limits(_) => return lim,
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
                    deferred = pw;
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
    // One PE parse serves both checks:
    //   * `.crb` certificate block-list: a signed PE carrying a blocked signer
    //     cert is reported (always on when a `.crb` DB is loaded);
    //   * opt-in `alert_broken_authenticode`: the embedded digest does not cover
    //     the file (tampered with / appended-to after signing).
    // Only a PE carries one, and it is parsed from all of the file.
    let signed =
        (opts.alert_broken_authenticode || !db.crb.is_empty()) && data.window(0, 2)[..] == *b"MZ";
    if signed {
        if let Some(sig) =
            whole(data, opts, "the Authenticode checks").and_then(|w| authenticode::analyze_pe(&w))
        {
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
    // (on by default; `--detect exav-heuristics` is the superset and also enables them).
    if !opts.clamav_heuristics && !opts.heuristics {
        return deferred;
    }

    // TLSH fuzzy matching is exav-exclusive (ClamAV has no TLSH), so it stays
    // behind the full `--detect exav-heuristics` flag and off under `--clamav-compat`.
    if opts.heuristics {
        if let Some(hit) = profile::timed("fuzzy", data.len() as u64, || {
            db.fuzzy.match_tlsh_source(data)
        }) {
            if let Some(o) = sink.hit(hit, 0, Method::Fuzzy) {
                return o;
            }
        }
    }

    // Parsed from all of the PE, so read only when something below uses it.
    let image = if ft == FileType::Pe && (db.fuzzy.has_imphash() || opts.heuristics) {
        whole(data, opts, "the PE import and static-model checks")
    } else {
        None
    };
    if let Some(image) = image {
        let data: &[u8] = &image;
        if let Some(info) = pe::analyze(data) {
            // imphash (`.imp`) matching is a ClamAV default (matched whenever the
            // loaded DB carries `.imp` sigs), so it runs under `clamav_heuristics`
            // (i.e. under `--clamav-compat` too). The exav-exclusive ML scorer,
            // packed-injection heuristic, and the `-v` diagnostic findings below
            // stay behind the full `--detect exav-heuristics` flag.
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
    if let Some(threshold) = opts.structured_cc_count {
        if count_cards() >= threshold as usize {
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
        if count_ssns() >= threshold as usize {
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

/// All of a PE, for the checks that parse its structure (see [`whole`]).
fn pe_image<'a>(
    ft: FileType,
    data: &'a dyn ByteSource,
    opts: &ScanOptions,
) -> Option<std::borrow::Cow<'a, [u8]>> {
    if ft == FileType::Pe {
        whole(data, opts, "the PE layout, icon and section checks")
    } else {
        None
    }
}

/// All of `data`, for a check that parses an object whole: the object itself
/// when it is held in memory, or read into memory when it is at most
/// `deep_analysis_max`. `None` otherwise, and the scan is then reported as
/// over the size limit: `what` applied and did not run.
fn whole<'a>(
    data: &'a dyn ByteSource,
    opts: &ScanOptions,
    what: &str,
) -> Option<std::borrow::Cow<'a, [u8]>> {
    let whole = data.materialize(opts.deep_analysis_max as usize);
    if whole.is_none() {
        engine::mark_over_size(|| over_size(data.len(), opts, &format!("{what} did not run")));
    }
    whole
}

/// Why something was skipped on an object of `len` bytes: it is over the
/// deep-analysis limit, and `consequence`.
fn over_size(len: usize, opts: &ScanOptions, consequence: &str) -> String {
    format!(
        "object is {len} bytes, over the {}-byte deep-analysis limit \
         (--max-object-bytes): {consequence}",
        opts.deep_analysis_max
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

/// The normalised views of `data` a textual file is matched against, in order.
/// The caller makes each with [`make_view`] and drops it before the next.
///
/// Each one is a full-size copy of `data`. Materialising the set before
/// scanning any of it put two (four for a script) in memory at once, on top
/// of the buffer they were derived from, and nesting stacks that: a container,
/// its member and that member's own member are each mid-scan while the walk is
/// inside them. Making one at a time keeps the peak at one copy without
/// changing which views are scanned or in what order.
fn normalizations(ft: FileType, data: &dyn ByteSource) -> Vec<ViewKind> {
    let mut v = vec![ViewKind::Html, ViewKind::Text];
    if looks_like_script(ft, &data.window(0, 8192)) {
        v.push(ViewKind::Javascript);
        v.push(ViewKind::Deobfuscated);
    }
    v
}

/// A normalised view of an object: [`normalize`]'s three, and [`jsnorm`]'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewKind {
    Html,
    Text,
    Javascript,
    Deobfuscated,
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
        let (view, cut) = jsnorm::normalize_source(data);
        // The raw bytes are still scanned in full; only this view is short.
        if cut {
            engine::mark_scan_truncated();
        }
        return Some(View::Mem(view));
    }
    if let Some(d) = data.as_slice() {
        return Some(View::Mem(match kind {
            ViewKind::Html => normalize::html(d),
            ViewKind::Text => normalize::text(d),
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
        _ => normalize::javascript_into(&mut src, &mut out),
    }
    match out.finish() {
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

/// The matching core over an object's own bytes, `ft` being the type it is
/// matched as. Every detection goes to `sink`; `Err` means the walk must stop.
fn core(
    db: &Scanner,
    facts: &Facts,
    ft: FileType,
    obj: Obj<'_>,
    opts: &ScanOptions,
    sink: &mut Sink,
) -> Result<CoreRest, DeepOutcome> {
    let data = facts.data;
    let unpacked = core_matches(db, facts, ft, obj, opts, sink);
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
fn core_matches(
    db: &Scanner,
    facts: &Facts,
    ft: FileType,
    obj: Obj<'_>,
    opts: &ScanOptions,
    sink: &mut Sink,
) -> Result<Vec<Vec<u8>>, DeepOutcome> {
    let data = facts.data;
    let suffix = opts.unofficial_suffix;
    let materialize = opts.deep_analysis_max as usize;
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
    // A PE's structure (layout, icons, section table) is parsed from all of it.
    let image = pe_image(ft, data, opts);
    // PE layout lets the engine resolve EP/section-relative offsets.
    let layout = image.as_deref().and_then(pe::layout);
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
    let mut engine_pass = |src: &dyn ByteSource,
                           layout: Option<&pe::PeLayout>,
                           icons: Option<&engine::IconCtx>,
                           fired: Option<&mut Vec<engine::Fired>>|
     -> Result<(), DeepOutcome> {
        let mut found = Vec::new();
        profile::timed("engine", src.len() as u64, || {
            let c = obj.container;
            if all {
                db.engine.scan_all_source(
                    src,
                    ft,
                    layout,
                    c,
                    icons,
                    &mut found,
                    materialize,
                    fired,
                );
            } else {
                found.extend(db.engine.scan_first_source(
                    src,
                    ft,
                    layout,
                    c,
                    icons,
                    &skip,
                    materialize,
                    fired,
                ));
            }
        });
        for (name, off, unofficial) in found {
            hit(&name, unofficial, off, Method::Pattern)?;
        }
        Ok(())
    };
    engine_pass(data, layout.as_ref(), Some(&icon_ctx), Some(&mut fired))?;
    // Normalised-content passes: HTML/text/mail (`Target:3/4/7`) signatures
    // are written against canonicalised content, not raw bytes. Only worth
    // making when a signature could match the result: `target_ok` confines
    // Target:3/4/7 to text-ish types, and a Target:0 pattern has already run
    // against the raw bytes, so for a positively-typed binary they are pure
    // cost. `is_textual` alone does not say so: it counts 0x80..=0xff as text,
    // and most packed binaries carry few NULs.
    if !db.engine.is_empty()
        && is_textual_type(ft)
        && normalize::is_textual(&data.window(0, normalize::SAMPLE))
    {
        // One at a time: each is a full-size copy of `data`, and nesting
        // stacks them (a container, its member and that member's member are
        // each mid-scan while the walk is inside them).
        for kind in normalizations(ft, data) {
            let Some(view) = profile::timed("normalize", data.len() as u64, || {
                make_view(kind, data, opts)
            }) else {
                continue;
            };
            engine_pass(view.source(), None, None, None)?;
        }
    }
    // Bytecode programs whose trigger/hook fires (gated execution). Their
    // names are reported verbatim, never `.UNOFFICIAL`-suffixed.
    let mut unpacked = Vec::new();
    if !db.bytecode.is_empty() {
        let (det, extracted) = profile::timed("bytecode", data.len() as u64, || {
            db.bytecode.scan_source(data, ft, materialize, &fired)
        });
        if let Some((name, _)) = det {
            hit(&name, false, 0, Method::Bytecode)?;
        }
        unpacked = extracted;
    }
    if !db.sections.is_empty() {
        if let Some(image) = &image {
            let want_sha = db.sections.wants_sha();
            let found: Vec<_> = profile::timed("sections", data.len() as u64, || {
                pe::section_slices(image)
                    .into_iter()
                    .filter_map(|(size, slice)| {
                        db.sections
                            .lookup(size, &hashes::section_digests(slice, want_sha))
                    })
                    .collect()
            });
            for (name, unofficial) in found {
                hit(&name, unofficial, 0, Method::Hash)?;
            }
        }
    }
    if !db.hashes.is_empty() && hash_matchable(data.len() as u64) {
        if let Some((name, unofficial)) = profile::timed("hashes", data.len() as u64, || {
            db.hashes.lookup(facts.digests(db), data.len() as u64)
        }) {
            hit(&name, unofficial, 0, Method::Hash)?;
        }
    }
    if !db.yara.is_empty() {
        let unofficial = db.yara.unofficial();
        for name in profile::timed("yara", data.len() as u64, || {
            db.yara.scan_source(data, obj.filename, materialize)
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

    /// How many times over a scan by `db` reads `data` from a source it does
    /// not hold in memory.
    fn passes_over(db: &Scanner, data: &[u8]) -> f64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
        let read = Arc::new(AtomicU64::new(0));
        let reader = Counting(Cursor::new(data.to_vec()), read.clone());
        let opts = ScanOptions {
            deep_analysis_max: 1 << 20,
            ..ScanOptions::default()
        };
        scan_seekable(db, reader, data.len() as u64, &opts).unwrap();
        read.load(Ordering::Relaxed) as f64 / data.len() as f64
    }

    /// Every full read of an object not held in memory is counted, per kind of
    /// object and of signature set. Each is a read of the source, for an HTTP
    /// one a download, so a change that adds one fails here: raising a bound
    /// needs the maintainer's approval, not a new expectation.
    ///
    /// What each read is: one for detection's search for its markers (and
    /// for an executable, a self-extractor's payload), carving, and the
    /// digests when a hash signature has the object's size; one for the
    /// signature sweep; and one at most for a signature with an unbounded
    /// gap, whose literal after it is searched through the rest of the object
    /// once. Each bound allows half a read more, for window seams and headers
    /// read again.
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
            l.build().unwrap()
        };
        let (other_size, this_size) = (db(12345), db(size));
        let mut pe = noise.clone();
        pe[..2].copy_from_slice(b"MZ");
        let mut gap = noise.clone();
        gap[1000..1004].copy_from_slice(&[0x0b, 0xad, 0xc0, 0xde]);
        let cases: [(&str, &Scanner, &[u8], f64); 5] = [
            ("unknown", &other_size, &noise, 2.0),
            ("PE", &other_size, &pe, 2.0),
            ("unknown, hashed", &this_size, &noise, 2.0),
            ("PE, hashed", &this_size, &pe, 2.0),
            ("unknown, a gap to the end", &other_size, &gap, 3.0),
        ];
        for (what, db, data, bound) in cases {
            let passes = passes_over(db, data);
            assert!(
                passes <= bound + 0.5,
                "{what}: read {passes:.2} times over, the bound is {bound}"
            );
        }
    }

    /// The one read of a streamed object finds what each step's own read of
    /// it would, whichever step asks first.
    #[test]
    fn one_read_serves_every_step() {
        use byte_source::CHUNK;
        // Longer than the start detection reads, so it searches the rest.
        let mut data = vec![b'.'; (5 << 20) + 77];
        let end = data.len();
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
        put(end - 3 * CHUNK - 3, b"AU3!EA06");
        let size = data.len();
        let mut l = loader::Builder::new();
        let hdb = format!("0123456789abcdef0123456789abcdef:{size}:Sig.Hash\n");
        l.add_named_bytes("a.hdb", hdb.as_bytes(), true);
        let hsb = format!("{}:{size}:Sig.Sha\n", "ab".repeat(32));
        l.add_named_bytes("b.hsb", hsb.as_bytes(), true);
        let db = l.build().unwrap();

        let slice: &[u8] = &data;
        let want_fmt = unpack::detect(&slice);
        let want_embedded = pe::embedded_in(&slice);
        let want_digests = hashes::digests_wanted(&slice, digests_wanted_by(&db, size as u64));
        // Found by the search past detection's start, in a build that has it.
        #[cfg(feature = "all-formats")]
        assert_eq!(want_fmt, Some(unpack::Format::Autoit));
        assert!(!want_embedded.pe.is_empty() && !want_embedded.archives.is_empty());
        assert!(!want_digests.md5.is_empty() && !want_digests.sha256.is_empty());
        for first in 0..3 {
            let cache =
                byte_source::BlockCache::with_sizes(Cursor::new(data.clone()), 4093, 16 * 4093)
                    .unwrap();
            let facts = Facts::for_scan(&cache, &db, true);
            let mut embedded = None;
            for step in (0..3).map(|k| (first + k) % 3) {
                match step {
                    0 => assert_eq!(facts.format(), want_fmt, "first {first}"),
                    1 => embedded = Some(facts.embedded()),
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
            let facts = Facts::for_scan(&cache, &db, false);
            let before = read.load(Ordering::Relaxed);
            assert!(!allowlisted(&db, &facts));
            assert_eq!(
                read.load(Ordering::Relaxed),
                before,
                "{len}: the allowlist read it"
            );
            facts.format();
            let passes = (read.load(Ordering::Relaxed) - before) as f64 / len as f64;
            // Its start, and past that start a search through all of it.
            let bound = if unpack::Prescan::needed(len) {
                2.0
            } else {
                1.0
            };
            assert!(
                passes <= bound + 0.1,
                "{len}: detection read it {passes:.2} times over"
            );
        }
    }

    /// [`super::unpack_target`] of an object held in memory.
    fn unpack_target(
        ft: FileType,
        data: &[u8],
        restrict: bool,
        opts: &ScanOptions,
    ) -> Option<unpack::Format> {
        super::unpack_target(ft, &Facts::new(&data), restrict, opts)
    }

    #[test]
    fn restrict_extractors_gates_absent_formats() {
        // Of exav's extractors, `ar` and `lzip` are absent from stock ClamAV;
        // cpio/xar are supported by both, so the compat mask gates the absent
        // formats alone: gating cpio/xar would make exav miss detections
        // ClamAV makes.
        // `ar`: restricted only when `restrict` is set.
        let opts = ScanOptions::default();
        assert_eq!(
            unpack_target(FileType::Ar, b"", false, &opts),
            Some(unpack::Format::Ar)
        );
        assert_eq!(unpack_target(FileType::Ar, b"", true, &opts), None);
        // cpio / xar: supported by ClamAV, so never gated.
        for (ft, fmt) in [
            (FileType::Cpio, unpack::Format::Cpio),
            (FileType::Xar, unpack::Format::Xar),
        ] {
            assert_eq!(unpack_target(ft, b"", false, &opts), Some(fmt));
            assert_eq!(
                unpack_target(ft, b"", true, &opts),
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

    /// Compat restricts UPX unpacking to PE: ClamAV's UPX unpacker runs only
    /// from its PE path, so exav's ELF/Mach-O UPX reach (e.g. UPX-packed Mirai
    /// ELFs) must be gated off under `restrict` to stay apples-to-apples.
    #[cfg(feature = "upx")]
    #[test]
    fn restrict_scopes_upx_to_pe() {
        let buf = fake_upx();
        let opts = ScanOptions::default();
        assert!(unpack::is_upx(&buf), "test buffer must look like UPX");
        // Normal mode: UPX unpacked for every executable type.
        for ft in [FileType::Pe, FileType::Elf, FileType::MachO] {
            assert_eq!(
                unpack_target(ft, &buf, false, &opts),
                Some(unpack::Format::Upx)
            );
        }
        // Compat: PE stays on, ELF/Mach-O are gated off.
        assert_eq!(
            unpack_target(FileType::Pe, &buf, true, &opts),
            Some(unpack::Format::Upx),
            "PE-UPX must stay on under compat (ClamAV does it too)"
        );
        for ft in [FileType::Elf, FileType::MachO] {
            assert_eq!(
                unpack_target(ft, &buf, true, &opts),
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

    /// As [`build_zip`], with every member deflated.
    #[cfg(any(feature = "zip", feature = "all-formats"))]
    fn build_zip_deflated(members: &[(&str, &[u8])]) -> Vec<u8> {
        use zip::write::SimpleFileOptions;
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, body) in members {
            w.start_file(*name, opts).unwrap();
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
    fn a_top_level_container_gets_the_full_engine_over_its_own_bytes() {
        let zip = build_zip(&[("payload_marker.txt", b"nothing to see here")]);
        let wild = db_from(&[("w.ndb", "Test.ZipName:0:*:7061796c6f6164??6d61726b6572\n")]);
        let d = digests_of(&zip);
        let hash = db_from(&[("h.hdb", &format!("{}:{}:Test.ZipHash\n", d.md5, zip.len()))]);
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
    }

    /// A file too large to hold gets the full engine, read through a block
    /// cache: a wildcard signature is found as well as a literal one. A clean
    /// text file is clean only when its normalised views could be made, which
    /// takes a spill.
    #[test]
    fn a_file_over_the_deep_analysis_limit_gets_the_full_engine() {
        let db = db_from(&[
            ("w.ndb", "Test.Wild:0:*:6576696c??7061796c6f6164\n"),
            ("l.ndb", "Test.Literal:0:*:6d61726b65726d61726b6572\n"),
        ]);
        let opts = ScanOptions {
            deep_analysis_max: 64,
            ..ScanOptions::default()
        };
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
        assert!(
            matches!(seekable(&db, &clean, &opts), Verdict::LimitsExceeded { .. }),
            "without a spill the text views were not scanned"
        );
        let spilling = ScanOptions {
            spill: Some(std::sync::Arc::new(spill::tests::MemSpill {
                budget: usize::MAX,
                made: Default::default(),
            })),
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

    /// The `.fp` allowlist covers a top-level archive, not only its members.
    #[test]
    fn an_allowlisted_top_level_archive_is_clean() {
        let zip = build_zip(&[("b.txt", eicar())]);
        let d = digests_of(&zip);
        let db = db_from(&[("x.fp", &format!("{}:{}:Allowed\n", d.md5, zip.len()))]);
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
        for (i, kind) in normalizations(FileType::Text, script)
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
            .extend_from_text(&format!("{}:*:Test.ByHash\n", d.sha256));
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
    /// and the boundary is exactly where ClamAV puts it: 5 bytes is refused, 6
    /// matches. Verified against ClamAV 1.4.3 with an equivalent `.hdb`, which
    /// reports OK up to 5 bytes and FOUND from 6.
    #[test]
    fn hash_signatures_do_not_match_tiny_objects() {
        for n in 1..=8usize {
            let data: Vec<u8> = (0..n).map(|i| b'A' + (i % 26) as u8).collect();
            let mut db = Scanner::builtin();
            let d = digests_of(&data);
            db.hashes
                .extend_from_text(&format!("{}:{}:Test.Tiny{}\n", d.md5, n, n));
            db.hashes.finalize();
            let hit = matches!(
                analyze(&db, &data, &ScanOptions::default()).verdict,
                Verdict::Infected { .. }
            );
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
        let mut db = Scanner::builtin();
        let mut eb = engine::EngineBuilder::new();
        eb.add_ndb("Test.Tiny.Pattern:0:*:61626364", false); // "abcd"
        db.engine = eb.build();
        let r = analyze(&db, b"abcd", &ScanOptions::default());
        assert!(
            matches!(r.verdict, Verdict::Infected { .. }),
            "pattern must still match a 4-byte object: {:?}",
            r.verdict
        );
        let d = digests_of(b"abcd");
        db.allow
            .extend_from_text(&format!("{}:4:Test.Allow\n", d.md5));
        db.allow.finalize();
        let r = analyze(&db, b"abcd", &ScanOptions::default());
        assert!(
            !matches!(r.verdict, Verdict::Infected { .. }),
            "allow-list must suppress below the hash floor: {:?}",
            r.verdict
        );
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

    /// A match across the block cache's block boundaries is found, at its
    /// offset in the object.
    #[test]
    fn detects_across_buffer_boundary() {
        let db = Scanner::builtin();
        let mut data = vec![b'A'; 3_000_000];
        data.extend_from_slice(eicar());
        data.extend(std::iter::repeat_n(b'B', 3_000_000));
        let opts = ScanOptions {
            deep_analysis_max: 1 << 20,
            ..ScanOptions::default()
        };
        let size = data.len() as u64;
        let r = scan_seekable(&db, Cursor::new(data), size, &opts).unwrap();
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
            spill: Some(std::sync::Arc::new(spill::tests::MemSpill {
                budget: usize::MAX,
                made: Default::default(),
            })),
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

    /// A container over the deep-analysis limit whose format is read whole
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
    // member-by-member off disk, never held whole, and its members, too large
    // to hold as well, go through the spill: the cap bounds memory without
    // bounding what the scan can find.
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
        e.write_all(eicar()).unwrap();
        let blob = e.finish().unwrap();
        let f = write_temp(&blob);
        let db = Scanner::builtin();
        let opts = spilling(ScanOptions {
            deep_analysis_max: 1,
            ..Default::default()
        });
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
        let opts = spilling(ScanOptions {
            deep_analysis_max: 1,
            ..Default::default()
        });
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
            .extend_from_text(&format!("{}:*:Test.TarWholeHash\n", d.sha256));
        db.hashes.finalize();
        let f = write_temp(&blob);
        let r = scan_path(&db, f.path(), &ScanOptions::default()).unwrap();
        match r.verdict {
            Verdict::Infected { signature, .. } => assert_eq!(signature, "Test.TarWholeHash"),
            other => panic!("expected whole-file-hash detection, got {other:?}"),
        }
    }

    // A gzip NESTED inside a tar, whose decompressed content exceeds both
    // `max_buffer_bytes` and `deep_analysis_max`, with EICAR buried past them:
    // the member is decoded as it is read and spilled, not capped or truncated
    // at either limit. With nowhere to spill it, it is reported, not cleared.
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
        opts.deep_analysis_max = 256;
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

    // Flat content larger than the deep-analysis cap gets the full engine
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
    fn oversize_flat_text_is_a_limit_not_clean() {
        let f = write_temp(&vec![b'Z'; 5000]);
        let db = Scanner::builtin();
        let opts = ScanOptions {
            deep_analysis_max: 1,
            ..Default::default()
        };
        let r = scan_path(&db, f.path(), &opts).unwrap();
        assert!(matches!(r.verdict, Verdict::LimitsExceeded { .. }));
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
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
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
                {
                    if data.len() < 8 << 20 {
                        out.push((path.display().to_string(), data));
                    }
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
        b.add_named_bytes(
            "t.ndb",
            b"Test.Wild:0:*:4d5a90??03\nTest.Html:3:*:3c7363726970743e6576616c\n\
              Test.Pe:1:EP+0:??\n",
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
            spill: Some(std::sync::Arc::new(spill::tests::MemSpill {
                budget: usize::MAX,
                made: Default::default(),
            })),
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

    /// The same, over a real database and a directory of samples:
    /// `EXAV_PARITY_DB=<.exavdb> EXAV_PARITY_CORPUS=<dir> cargo test -p exav-core
    /// --release --lib parity::corpus -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs a database and a corpus"]
    fn corpus() {
        let (Ok(db), Ok(dir)) = (
            std::env::var("EXAV_PARITY_DB"),
            std::env::var("EXAV_PARITY_CORPUS"),
        ) else {
            eprintln!("skip: EXAV_PARITY_DB / EXAV_PARITY_CORPUS unset");
            return;
        };
        let db = database::load(std::path::Path::new(&db)).expect("load the database");
        let limit: usize = std::env::var("EXAV_PARITY_LIMIT")
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
