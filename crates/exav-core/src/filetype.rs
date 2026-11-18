//! Content-based file-type identification (magic bytes), never trusting
//! the file extension. Reads the first few KB, and whatever container
//! detection (`unpack::detect`) needs: the end of an object, or a search of it.
//! Drives routing to unpackers and structural analyzers.

use crate::byte_source::ByteSource;
use crate::unpack;

/// File-type magic rules loaded from ClamAV `.ftm` databases. Each is a literal
/// byte prefix at a fixed offset that assigns a [`FileType`]. Applied ONLY as a
/// fallback when content-based [`identify`] is inconclusive (`Unknown`), so it
/// never overrides (and so never regresses) a confidently-typed file.
#[derive(Default, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FtmMagics {
    rules: Vec<FtmRule>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct FtmRule {
    offset: usize,
    magic: Vec<u8>,
    ft: FileType,
}

impl FtmMagics {
    pub fn len(&self) -> usize {
        self.rules.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Parse one `.ftm` file. Lines are
    /// `magictype:offset:hexmagic:name:rtype:CL_TYPE[:minfl[:maxfl]]`. We keep
    /// only absolute-offset (`magictype 0`) rules whose magic is purely literal
    /// hex and whose `CL_TYPE` maps to a [`FileType`] exav models; wildcarded
    /// magics and unmodelled types are skipped (the engine still type-detects
    /// natively; these only fill gaps). Returns how many lines did not parse
    /// (not those skipped on purpose).
    pub fn extend_from_text(&mut self, text: &str) -> usize {
        let mut skipped = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 6 {
                skipped += 1;
                continue;
            }
            if f[0] != "0" {
                continue;
            }
            let Ok(offset) = f[1].parse::<usize>() else {
                skipped += 1;
                continue;
            };
            let Some(magic) = parse_literal_hex(f[2]) else {
                skipped += 1;
                continue;
            };
            if magic.is_empty() || magic.len() > 64 {
                continue;
            }
            let Some(ft) = cl_type_to_filetype(f[5]) else {
                continue;
            };
            self.rules.push(FtmRule { offset, magic, ft });
        }
        skipped
    }

    /// First magic that matches `data`, if any. Intended as the `Unknown`
    /// fallback for [`identify`].
    pub fn identify(&self, data: &[u8]) -> Option<FileType> {
        self.identify_source(&data)
    }

    /// As [`Self::identify`], over an object that need not be held in memory.
    pub(crate) fn identify_source(&self, data: &dyn ByteSource) -> Option<FileType> {
        for r in &self.rules {
            // One rule with an offset past the address space says nothing
            // about the ones after it.
            let Some(end) = r.offset.checked_add(r.magic.len()) else {
                continue;
            };
            if end <= data.len() && data.window(r.offset, r.magic.len())[..] == r.magic[..] {
                return Some(r.ft);
            }
        }
        None
    }
}

/// Decode a fully-literal hex string to bytes; `None` if it carries any ndb
/// wildcard / non-hex byte (those rules are skipped).
fn parse_literal_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Map a ClamAV `CL_TYPE_*` to the exav [`FileType`] it corresponds to, or
/// `None` for types exav doesn't model (compiled python, …). Assigning those
/// would gain nothing since no `Target` keys on them.
pub(crate) fn cl_type_to_filetype(t: &str) -> Option<FileType> {
    Some(match t {
        "CL_TYPE_MSEXE" => FileType::Pe,
        "CL_TYPE_ELF" => FileType::Elf,
        "CL_TYPE_MACHO" | "CL_TYPE_MACHO_UNIBIN" => FileType::MachO,
        "CL_TYPE_ZIP" => FileType::Zip,
        "CL_TYPE_GZ" => FileType::Gzip,
        "CL_TYPE_BZ" => FileType::Bzip2,
        "CL_TYPE_XZ" => FileType::Xz,
        "CL_TYPE_7Z" => FileType::SevenZip,
        "CL_TYPE_RAR" => FileType::Rar,
        "CL_TYPE_MSCAB" => FileType::Cab,
        "CL_TYPE_MSCHM" => FileType::Chm,
        "CL_TYPE_POSIX_TAR" | "CL_TYPE_OLD_TAR" | "CL_TYPE_GNU_TAR" => FileType::Tar,
        "CL_TYPE_PDF" => FileType::Pdf,
        "CL_TYPE_MSOLE2" => FileType::Ole,
        "CL_TYPE_MAIL" => FileType::Email,
        "CL_TYPE_HTML" => FileType::Html,
        "CL_TYPE_RTF" => FileType::Rtf,
        "CL_TYPE_ISO9660" => FileType::Iso,
        "CL_TYPE_LHA_LZH" => FileType::Lha,
        "CL_TYPE_ARJ" | "CL_TYPE_ARJSFX" => FileType::Arj,
        "CL_TYPE_CPIO_OLD" | "CL_TYPE_CPIO_ODC" | "CL_TYPE_CPIO_NEWC" | "CL_TYPE_CPIO_CRC" => {
            FileType::Cpio
        }
        "CL_TYPE_XAR" => FileType::Xar,
        "CL_TYPE_GPT" | "CL_TYPE_MBR" | "CL_TYPE_APM" => FileType::Partition,
        "CL_TYPE_SWF" => FileType::Swf,
        "CL_TYPE_GRAPHICS" => FileType::Graphics,
        "CL_TYPE_SCRIPT" => FileType::Script,
        "CL_TYPE_TEXT_ASCII"
        | "CL_TYPE_TEXT_UTF8"
        | "CL_TYPE_TEXT_UTF16LE"
        | "CL_TYPE_TEXT_UTF16BE" => FileType::Text,
        _ => return None,
    })
}

/// Recognised file types relevant to scanning/unpacking decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum FileType {
    Pe,
    Elf,
    MachO,
    Zip,
    Gzip,
    Bzip2,
    Xz,
    Tar,
    Pdf,
    Ole,   // legacy MS Office (doc/xls/ppt), MSI
    Email, // RFC822 / MIME message (heuristic)
    Rtf,
    SevenZip,
    Rar,
    Cab,
    Chm,         // MS Compiled HTML Help (ITSS container)
    Iso,         // ISO 9660 CD/DVD image
    Lha,         // LHA/LZH archive
    Arj,         // ARJ archive
    Ar,          // Unix ar archive (.a, .deb)
    Cpio,        // cpio archive (RPM payload, initramfs)
    Xar,         // XAR archive (macOS .pkg/.xip)
    Wim,         // Windows Imaging Format (.wim/.esd)
    Lz4,         // LZ4 frame
    Arc,         // ARC / PKARC / PAK archive
    Ace,         // ACE archive (recognised, not decoded)
    Alz,         // ALZ archive
    Egg,         // EGG archive
    Hwp3,        // Hangul HWP v3 document
    IshieldMsi,  // InstallShield setup executable (its files decoded)
    IshieldCab,  // InstallShield InstallScript cabinet (decoded)
    IshieldZ,    // InstallShield `.z` archive (decoded)
    CryptFf,     // CryptFF file (its content decoded)
    Ext,         // ext2/3/4 filesystem image (walked)
    Lrzip,       // lrzip stream (recognised, not decoded)
    Zoo,         // ZOO archive (decoded)
    AppleSingle, // AppleSingle/AppleDouble file (its forks read)
    StuffIt,     // StuffIt / StuffIt X archive (recognised, not decoded)
    Fat,         // FAT12/16/32 filesystem
    Inno,        // Inno Setup installer (its files read)
    Ntfs,        // NTFS filesystem
    Zstd,        // Zstandard compressed stream
    Lzip,        // Lzip compressed stream
    Uuencode,    // uuencode / base64-uuencode wrapped file
    Xdp,         // Adobe XDP (XML-wrapped base64 PDF)
    Szdd,        // MS-Compress SZDD / KWAJ
    Tnef,        // TNEF (winmail.dat) MS email attachment container
    Swf,         // SWF (Adobe Flash) movie (CWS/ZWS compressed)
    // Raster image. Never produced by content detection: `Target:5` signatures
    // reach images through the engine's `looks_like_image` instead. This exists
    // only so a `HandlerType:CL_TYPE_GRAPHICS` signature has a type to re-type
    // *to*; giving it one costs nothing precisely because nothing else can
    // produce it.
    Graphics,
    Binhex,    // BinHex 4.0 (.hqx) classic-Mac 6-bit-encoded file
    Lnk,       // Windows Shell Link (.lnk) shortcut
    Partition, // raw disk image partition map (GPT / APM / MBR)
    Pyc,       // Python compiled bytecode (.pyc)
    Nsis,      // NSIS (Nullsoft) installer
    Machofat,  // Mach-O universal ("fat") binary
    Sfx,       // Self-extracting archive (executable stub + appended archive)
    Autoit,    // Compiled AutoIt3 script (AU3!EA05/EA06)
    OneNote,   // Microsoft OneNote (.one) section file with embedded files
    JavaClass, // Java `.class` bytecode
    AiModel,   // AI model (Python pickle / safetensors)
    Screnc,    // Microsoft Script Encoder (#@~^)
    Script,    // shell/script with a shebang
    Html,      // HTML document (content-detected)
    Text,      // ASCII/UTF-8 text (content-detected)
    Unknown,
    // The normalised views of an object, which never type an object itself:
    // the one HTML (`Target:3`) signatures match, and the one text
    // (`Target:7`) signatures match.
    HtmlView,
    TextView,
    // Stored by index in the `.exavdb`: add new variants below, never above.
    Exfat,    // exFAT filesystem
    Squashfs, // SquashFS image
    Cramfs,   // cramfs image
    Romfs,    // romfs image
    Erofs,    // EROFS image
    // The scripts of an HTML object, normalised: a view that both HTML
    // (`Target:3`) and text (`Target:7`) signatures match.
    ScriptView,
}

impl FileType {
    pub fn is_executable(self) -> bool {
        matches!(self, FileType::Pe | FileType::Elf | FileType::MachO)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FileType::Pe => "PE",
            FileType::Elf => "ELF",
            FileType::MachO => "Mach-O",
            FileType::Zip => "ZIP",
            FileType::Gzip => "GZIP",
            FileType::Bzip2 => "BZIP2",
            FileType::Xz => "XZ",
            FileType::Tar => "TAR",
            FileType::Pdf => "PDF",
            FileType::Ole => "OLE",
            FileType::Email => "email",
            FileType::Rtf => "RTF",
            FileType::SevenZip => "7Z",
            FileType::Rar => "RAR",
            FileType::Cab => "CAB",
            FileType::Chm => "CHM",
            FileType::Iso => "ISO",
            FileType::Lha => "LHA",
            FileType::Arj => "ARJ",
            FileType::Ar => "AR",
            FileType::Cpio => "CPIO",
            FileType::Xar => "XAR",
            FileType::Wim => "WIM",
            FileType::Lz4 => "LZ4",
            FileType::Arc => "ARC",
            FileType::Ace => "ACE",
            FileType::Alz => "ALZ",
            FileType::Egg => "EGG",
            FileType::Hwp3 => "HWP3",
            FileType::IshieldMsi => "InstallShieldMSI",
            FileType::IshieldCab => "InstallShieldCAB",
            FileType::IshieldZ => "InstallShieldZ",
            FileType::CryptFf => "CryptFF",
            FileType::Ext => "ext",
            FileType::Lrzip => "lrzip",
            FileType::Zoo => "ZOO",
            FileType::AppleSingle => "AppleSingle",
            FileType::StuffIt => "StuffIt",
            FileType::Fat => "FAT",
            FileType::Inno => "InnoSetup",
            FileType::Ntfs => "NTFS",
            FileType::Exfat => "exFAT",
            FileType::Squashfs => "SquashFS",
            FileType::Cramfs => "cramfs",
            FileType::Romfs => "romfs",
            FileType::Erofs => "EROFS",
            FileType::Zstd => "ZSTD",
            FileType::Lzip => "LZIP",
            FileType::Uuencode => "uuencode",
            FileType::Xdp => "XDP",
            FileType::Szdd => "SZDD",
            FileType::Tnef => "TNEF",
            FileType::Swf => "SWF",
            FileType::Graphics => "graphics",
            FileType::Binhex => "BinHex",
            FileType::Lnk => "LNK",
            FileType::Partition => "partition",
            FileType::Pyc => "PYC",
            FileType::Nsis => "NSIS",
            FileType::Machofat => "Mach-O universal",
            FileType::Sfx => "SFX",
            FileType::Autoit => "AutoIt",
            FileType::OneNote => "OneNote",
            FileType::JavaClass => "Java class",
            FileType::AiModel => "AI model",
            FileType::Screnc => "Script Encoder",
            FileType::Script => "script",
            FileType::Html => "HTML",
            FileType::Text => "ASCII text",
            FileType::Unknown => "data",
            FileType::HtmlView => "normalised HTML",
            FileType::TextView => "normalised text",
            FileType::ScriptView => "normalised script",
        }
    }
}

/// Identify a file type from a header prefix (and, for tar, a 512-byte
/// record if available).
pub fn identify(buf: &[u8]) -> FileType {
    identify_with(buf, || crate::unpack::detect(&buf))
}

/// Bytes of an object's start the content sniffers below read.
const SNIFF_HEAD: usize = 64 * 1024;

/// As [`identify`], over an object that need not be held in memory: its start
/// is read, and the container detection reads what it needs.
pub(crate) fn identify_source(src: &dyn ByteSource) -> FileType {
    identify_source_with(src, || crate::unpack::detect(src))
}

/// As [`identify_source`], asking `detect` for what [`crate::unpack::detect`]
/// makes of `src`, if the checks before it fail.
pub(crate) fn identify_source_with(
    src: &dyn ByteSource,
    detect: impl FnOnce() -> Option<crate::unpack::Format>,
) -> FileType {
    let head = match src.as_slice() {
        Some(buf) => std::borrow::Cow::Borrowed(buf),
        None => src.window(0, SNIFF_HEAD),
    };
    identify_with(&head, detect)
}

/// [`identify`] given the object's start, which holds at least what every
/// check but `detect` reads, and `detect`, asked only if those checks fail.
fn identify_with(buf: &[u8], detect: impl FnOnce() -> Option<crate::unpack::Format>) -> FileType {
    // Executables and RTF: types core recognises itself (not extractable
    // containers, so `exav-unpack` doesn't know them).
    // Thin Mach-O magics only. The universal/"fat" magics (CA FE BA BE /
    // CA FE BA BF) are deliberately NOT matched, so a fat binary falls
    // through to `unpack::detect` → `Format::Machofat` and gets split into its
    // per-arch slices (each a thin Mach-O, re-scanned). CA FE BA BE is also the
    // Java `.class` magic; `machofat` detection rejects those.
    match crate::unpack::executable_kind(buf) {
        Some(crate::unpack::Executable::Pe) => return FileType::Pe,
        Some(crate::unpack::Executable::Elf) => return FileType::Elf,
        Some(crate::unpack::Executable::MachO) => return FileType::MachO,
        None => {}
    }
    if buf.starts_with(b"{\\rtf") {
        return FileType::Rtf;
    }
    // Uncompressed Flash. `CWS`/`ZWS` (the compressed variants) are containers
    // and belong to `unpack::detect`; `FWS` has nothing to decompress, so core
    // types it directly. Without this, `Target:11` signatures would never see
    // an uncompressed movie, nor the `FWS` body exav rebuilds from a `CWS`/`ZWS`
    // one. The magic is the bare three bytes, matching ClamAV: probing clamscan
    // with a `Target:11` signature shows `FWS` + garbage version + a nonsense
    // length field still types as SWF, so validating the header here would drop
    // detections ClamAV keeps.
    if buf.starts_with(b"FWS") {
        return FileType::Swf;
    }
    // Archive/container formats: the magic detection is owned solely by
    // `exav-unpack::detect` (single source of truth); map its `Format` to the
    // broader `FileType`.
    // A DXF drawing has no ClamAV type: an ASCII one is text to ClamAV and
    // stays so here, for `Target:7`; what it embeds is extracted from the
    // magic (`unpack::tree::MAGIC_DISPATCH_ONLY`).
    match detect() {
        Some(crate::unpack::Format::Dxf) | None => {}
        Some(fmt) => {
            if crate::unpack::is_found_by_string(fmt)
                && let Some(own) = text_kept(fmt, buf)
            {
                return own;
            }
            return filetype_of_format(fmt);
        }
    }
    text_type(buf).unwrap_or(FileType::Unknown)
}

/// The type core gives a kind of text: what [`unpack::text_kind`] says it is.
fn text_type_of(kind: unpack::TextKind) -> FileType {
    match kind {
        unpack::TextKind::Script => FileType::Script,
        unpack::TextKind::Message => FileType::Email,
        unpack::TextKind::Page => FileType::Html,
        unpack::TextKind::Plain => FileType::Text,
    }
}

/// The type core's own checks give a text. `None` for what is not text.
fn text_type(buf: &[u8]) -> Option<FileType> {
    unpack::text_kind(buf).map(text_type_of)
}

/// The type a text keeps, when `detect` gives `fmt` for a string it finds in
/// the object; `None` when `fmt` is the type (see [`unpack::text_keeps`]).
fn text_kept(fmt: unpack::Format, buf: &[u8]) -> Option<FileType> {
    unpack::text_keeps(fmt, buf).map(text_type_of)
}

pub(crate) use crate::unpack::{field_name_len, looks_like_html};

/// Whether a MIME document is an **MHTML web archive** rather than a mail
/// message: a saved web page (`.mht`), not something that travelled through a
/// mail server.
///
/// The discriminator is the mail envelope, not the multipart subtype: probed
/// with `Container:CL_TYPE_MHTML` and `Container:CL_TYPE_MAIL` signatures,
/// clamscan types a `multipart/related` document *with* `From:`/`To:` as mail
/// and a `multipart/mixed` document *without* them as MHTML. The two are
/// mutually exclusive, so a document is one or the other, never both.
pub(crate) fn looks_like_mhtml(buf: &[u8]) -> bool {
    let head = &buf[..buf.len().min(8192)];
    let text = String::from_utf8_lossy(head);
    if text.starts_with("From ") {
        return false; // mbox is mail by definition
    }
    // Only the header block counts: a quoted `From:` inside the body is not an
    // envelope.
    let headers = text.split("\r\n\r\n").next().unwrap_or(&text);
    let has_envelope = headers.lines().any(|l| {
        let key = l.split_once(':').map(|(k, _)| k).unwrap_or("");
        matches!(
            key,
            "Received" | "Return-Path" | "From" | "To" | "Delivered-To" | "Message-ID"
        )
    });
    !has_envelope && headers.contains("Content-Type:")
}

/// The [`FileType`] a magic-detected [`Format`] corresponds to.
///
/// (`Format::Email` is never returned by magic, since email is content-sniffed,
/// but is mapped for completeness.)
///
/// Several formats have no ClamAV `CL_TYPE_*` of their own and land on
/// `FileType::Unknown`; they are listed in [`unpack::tree::MAGIC_DISPATCH_ONLY`]
/// and read from their magic, as the walk's typer does for every format.
/// `a_type_a_signature_gives_names_the_format_it_is` holds the list and the
/// mapping together.
pub(crate) fn filetype_of_format(fmt: crate::unpack::Format) -> FileType {
    use crate::unpack::Format;
    match fmt {
        Format::Zip => FileType::Zip,
        Format::Gzip => FileType::Gzip,
        Format::Tar => FileType::Tar,
        Format::Bzip2 => FileType::Bzip2,
        Format::Xz => FileType::Xz,
        Format::Cab => FileType::Cab,
        Format::Chm => FileType::Chm,
        Format::Ole => FileType::Ole,
        Format::Pdf => FileType::Pdf,
        Format::Email => FileType::Email,
        Format::SevenZip => FileType::SevenZip,
        Format::Iso => FileType::Iso,
        Format::Lha => FileType::Lha,
        Format::Rar => FileType::Rar,
        Format::Arj => FileType::Arj,
        Format::Ar => FileType::Ar,
        Format::Cpio => FileType::Cpio,
        Format::Xar => FileType::Xar,
        // UPX and other PE runtime packers are content-detected on
        // executables, never by `detect`.
        Format::Upx => FileType::Unknown,
        Format::PePacked => FileType::Unknown,
        Format::JavaClass => FileType::JavaClass,
        Format::AiModel => FileType::AiModel,
        Format::Screnc => FileType::Screnc,
        Format::Dmg => FileType::Unknown,
        // A disk image has no ClamAV `CL_TYPE_*` of its own; what matters is
        // the filesystem inside, which is typed when the member is scanned.
        Format::Vhd => FileType::Unknown,
        Format::Lzw => FileType::Unknown,
        // LZMA Utils' `.lzma` has no ClamAV type either.
        Format::Lzma => FileType::Unknown,
        // So has an RPM package.
        Format::Rpm => FileType::Unknown,
        Format::Qcow2 | Format::Vmdk | Format::Vhdx => FileType::Unknown,
        Format::Wim => FileType::Wim,
        Format::Lz4 => FileType::Lz4,
        Format::Arc => FileType::Arc,
        Format::Ace => FileType::Ace,
        Format::Alz => FileType::Alz,
        Format::Egg => FileType::Egg,
        Format::Hwp3 => FileType::Hwp3,
        Format::IshieldMsi => FileType::IshieldMsi,
        Format::IshieldCab => FileType::IshieldCab,
        Format::IshieldZ => FileType::IshieldZ,
        Format::CryptFf => FileType::CryptFf,
        Format::Ext => FileType::Ext,
        Format::Lrzip => FileType::Lrzip,
        Format::Zoo => FileType::Zoo,
        Format::AppleSingle => FileType::AppleSingle,
        Format::StuffIt => FileType::StuffIt,
        Format::Fat => FileType::Fat,
        Format::Inno => FileType::Inno,
        Format::Ntfs => FileType::Ntfs,
        Format::Exfat => FileType::Exfat,
        Format::Squashfs => FileType::Squashfs,
        Format::Cramfs => FileType::Cramfs,
        Format::Romfs => FileType::Romfs,
        Format::Erofs => FileType::Erofs,
        Format::Zstd => FileType::Zstd,
        Format::Lzip => FileType::Lzip,
        Format::Uuencode => FileType::Uuencode,
        Format::Xdp => FileType::Xdp,
        Format::Szdd => FileType::Szdd,
        Format::Tnef => FileType::Tnef,
        Format::Swf => FileType::Swf,
        Format::Binhex => FileType::Binhex,
        Format::Lnk => FileType::Lnk,
        Format::Partition => FileType::Partition,
        Format::Pyc => FileType::Pyc,
        Format::Nsis => FileType::Nsis,
        Format::Machofat => FileType::Machofat,
        Format::Sfx => FileType::Sfx,
        Format::Autoit => FileType::Autoit,
        Format::OneNote => FileType::OneNote,
        Format::Rtf => FileType::Rtf,
        // `Format` is `#[non_exhaustive]`, so the compiler can no longer prove
        // this mapping is total. `a_type_a_signature_gives_names_the_format_it_is`
        // proves it instead, walking `Format::ALL` and failing on any variant
        // that does not round-trip. That catches a missing arm here for the
        // same reason the compiler used to, and with a better message.
        _ => FileType::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use crate::unpack::{Format, tree};

    /// The type a signature gives an object (`HandlerType:`) names the format
    /// that reads it: every format that has a type of its own is found from its
    /// type. A format that lands on `FileType::Unknown` has none, and is read
    /// from its magic ([`tree::MAGIC_DISPATCH_ONLY`]); the runtime packers are
    /// found on an executable and not by `detect`.
    #[test]
    fn a_type_a_signature_gives_names_the_format_it_is() {
        for &fmt in Format::ALL {
            if matches!(fmt, Format::Upx | Format::PePacked)
                || tree::MAGIC_DISPATCH_ONLY.contains(&fmt)
            {
                continue;
            }
            let ft = super::filetype_of_format(fmt);
            assert_eq!(
                crate::declared_by(ft),
                tree::Declared::Format(fmt),
                "{fmt:?} maps to {ft:?}, which does not name {fmt:?}: its contents \
                 would go unscanned when a signature types an object so. Give it a \
                 FileType, or add it to MAGIC_DISPATCH_ONLY."
            );
        }
    }

    use super::*;

    #[test]
    fn ftm_fallback_typing() {
        let mut ftm = FtmMagics::default();
        // Real daily.ftm-style lines: literal magic, wildcarded magic (skipped),
        // unmodelled CL_TYPE (skipped), and a non-zero magictype (skipped).
        ftm.extend_from_text(
            "0:0:550d0d0a:Python:CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED\n\
             0:0:46726f6d20:MBox:CL_TYPE_ANY:CL_TYPE_MAIL\n\
             0:0:255044462d:PDF:CL_TYPE_ANY:CL_TYPE_PDF\n\
             0:0:6125{4}62:wild:CL_TYPE_ANY:CL_TYPE_MAIL\n\
             1:0:cafe:pe:CL_TYPE_ANY:CL_TYPE_MSEXE",
        );
        // Compiled Python has no exav FileType here -> not stored;
        // MAIL + PDF map and are stored.
        assert_eq!(ftm.identify(b"\x55\x0d\x0d\x0a rest"), None);
        assert_eq!(ftm.identify(b"From the start"), Some(FileType::Email));
        assert_eq!(ftm.identify(b"%PDF-1.7 ..."), Some(FileType::Pdf));
        assert_eq!(ftm.identify(b"no magic here"), None);
    }

    /// A rule whose offset is the largest `usize` has no end to compare with;
    /// the rules after it still apply.
    #[test]
    fn a_rule_at_the_top_of_the_address_space_does_not_end_the_search() {
        let mut ftm = FtmMagics::default();
        ftm.extend_from_text(&format!(
            "0:{}:cafe:far:CL_TYPE_ANY:CL_TYPE_MSEXE\n\
             0:0:255044462d:PDF:CL_TYPE_ANY:CL_TYPE_PDF",
            usize::MAX
        ));
        assert_eq!(ftm.len(), 2);
        assert_eq!(ftm.identify(b"%PDF-1.7 ..."), Some(FileType::Pdf));
    }

    /// ClamAV has no DXF type: an ASCII drawing is text to it, so `Target:7`
    /// signatures apply, and a binary one is data.
    #[test]
    fn a_dxf_keeps_the_type_its_bytes_give() {
        assert_eq!(
            identify(b"  0\r\nSECTION\r\n  2\r\nHEADER\r\n"),
            FileType::Text
        );
        assert_eq!(
            identify(b"AutoCAD Binary DXF\r\n\x1a\0\0\0SECTION\0"),
            FileType::Unknown
        );
    }

    #[test]
    fn detects_common_types() {
        assert_eq!(identify(b"MZ\x90\x00"), FileType::Pe);
        assert_eq!(identify(b"\x7fELF"), FileType::Elf);
        assert_eq!(identify(b"PK\x03\x04...."), FileType::Zip);
        assert_eq!(identify(&[0x1f, 0x8b, 0x08, 0x00]), FileType::Gzip);
        // A bare `1f 8b` prefix without a valid deflate CM + flag byte is not gzip
        // (it collides with binary data); must not be typed as an archive.
        assert_ne!(identify(&[0x1f, 0x8b, 0x99, 0xff]), FileType::Gzip);
        assert_eq!(identify(b"%PDF-1.7"), FileType::Pdf);
        assert_eq!(identify(b"#!/bin/sh\n"), FileType::Script);
        // Printable prose → text; non-printable bytes → binary Unknown.
        assert_eq!(identify(b"random bytes"), FileType::Text);
        assert_eq!(
            identify(&[0x00, 0xff, 0x01, 0xfe, 0x80, 0x90]),
            FileType::Unknown
        );
    }

    #[test]
    fn html_typed_but_js_is_not() {
        assert_eq!(
            identify(b"<!DOCTYPE html><html><body>hi</body></html>"),
            FileType::Html
        );
        assert_eq!(identify(b"<script>alert(1)</script>"), FileType::Html);
        // Obfuscated JS with no HTML tags must NOT be Html (so Target:3 HTML
        // exploit sigs don't fire on it, as in the npm-package FP). It is text, so it
        // types as Text (covered by Target:7), never Html.
        assert_eq!(
            identify(b"const _0x12=_0x37;var a=new Uint32Array(0x10000);for(;;){}"),
            FileType::Text
        );
        // Binary containing an angle-bracket sequence must not be mis-typed HTML.
        assert_eq!(
            identify(b"\x00\x01\x02<script>\xff\xfe\x00\x00"),
            FileType::Unknown
        );
    }

    #[test]
    fn email_heuristic() {
        let eml = b"From: a@b\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhi";
        assert_eq!(identify(eml), FileType::Email);
        // Plain prose with a colon must not be misread as email (it is text).
        assert_eq!(identify(b"Notes: buy milk\nand eggs\n"), FileType::Text);
    }

    /// A message is a message by what its headers are, not by which one comes
    /// first or how it is spelt: a mail client writes its own header ahead of the
    /// rest, and a header name is not case sensitive.
    #[test]
    fn a_message_is_known_by_its_headers_not_by_the_first_of_them() {
        let rest = "Subject: x\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhi";
        for first in [
            "X-Mozilla-Status: 0001",
            "X-Account-Key: account1",
            "Cc: a@b",
            "Message-Id: <1@b>",
            "Authentication-Results: mx; spf=pass",
            "FROM: a@b",
            "received: from x",
        ] {
            let eml = format!("{first}\r\n{rest}");
            assert_eq!(identify(eml.as_bytes()), FileType::Email, "{first}");
        }
        let lower = "from: a@b\nmime-version: 1.0\ncontent-type: text/plain\n\nhi";
        assert_eq!(identify(lower.as_bytes()), FileType::Email);
    }

    /// Header blocks of mail that went through gateways run past 8 KiB.
    #[test]
    fn a_long_header_block_does_not_hide_the_mime_headers() {
        let mut eml = String::new();
        for i in 0..200 {
            eml.push_str(&format!("Received: from relay{i}.example.org by mx{i}.example.net; Tue, 1 Jan 2030 00:00:00 +0000\r\n"));
        }
        let at = eml.len();
        eml.push_str("MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhi");
        assert!(at > 8192, "{at}");
        assert_eq!(identify(eml.as_bytes()), FileType::Email);
    }

    #[test]
    fn headers_alone_do_not_make_a_message() {
        // No MIME header.
        assert_ne!(
            identify(b"X-Thing: a\r\nFrom: a@b\r\n\r\nhi"),
            FileType::Email
        );
        // MIME headers in the body, not the headers.
        assert_ne!(
            identify(b"X-Thing: a\r\nFrom: a@b\r\n\r\nContent-Type: text/plain\r\nhi"),
            FileType::Email
        );
        // A header-looking first line and nothing mail about it.
        assert_ne!(
            identify(b"Server: x\r\nContent-Length: 3\r\nContent-Type: text/plain\r\n\r\nhi"),
            FileType::Email
        );
    }

    /// What clamscan 1.4.3 types as mail from a file's first bytes alone: no
    /// MIME header, no second header, any body, markup in it included.
    #[test]
    fn a_file_that_starts_with_a_mail_header_is_a_message() {
        for first in [
            "From a@b Mon Jan  1 00:00:00 2024",
            "From: a@b",
            "Received: from x by y",
            "Received-SPF: pass",
            "Return-Path: <a@b>",
            "Return-path: <a@b>",
            "To: a@b",
            "Subject: x",
            "Message-ID: <1@b>",
            "Message-Id: <1@b>",
            "Date: Mon, 1 Jan 2024 00:00:00 +0000",
            "Delivered-To: a@b",
            "Envelope-to: a@b",
            "X-Original-To: a@b",
            "X-Envelope-From: a@b",
            "X-Apparently-To: a@b",
            "X-Real-To: a@b",
            "X-Sieve: CMU Sieve 2.2",
            "X-UIDL: 1",
        ] {
            for body in [
                "",
                "\n\nhi",
                "\r\n\r\nhi",
                "\n\n<html><body>hi</body></html>",
                "\n\n<script>x</script>",
                "\n\n\x00\x01binary",
            ] {
                let m = format!("{first}{body}");
                assert_eq!(identify(m.as_bytes()), FileType::Email, "{m:?}");
            }
        }
    }

    /// What a text starts with, and the type its own checks give it.
    const TEXTS: [(&[u8], FileType); 6] = [
        (b"From: a@b\n\nhi ", FileType::Email),
        (b"Received: from x by y\n\nhi ", FileType::Email),
        (
            b"MIME-Version: 1.0\nContent-Type: text/plain\n\nhi ",
            FileType::Email,
        ),
        (b"#!/bin/sh\necho ", FileType::Script),
        (
            b"<html><body>lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do \
              eiusmod tempor incididunt ut labore et dolore magna aliqua, ut enim ad minim ",
            FileType::Html,
        ),
        (b"just some notes, ", FileType::Text),
    ];

    #[cfg(all(
        feature = "screnc",
        feature = "binhex",
        feature = "xdp",
        feature = "autoit"
    ))]
    const SCRIPT_GUID: [u8; 16] = [
        0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 0x48,
        0x7D,
    ];

    /// A string `detect` searches for in an object (the Script Encoder
    /// marker, an XDP tag, the BinHex line, an AutoIt marker) does not retype
    /// a message, a script, a page or a text that holds it: it keeps its type,
    /// so the signatures of that type and its views apply.
    #[test]
    fn a_string_found_in_a_text_does_not_retype_it() {
        let strings: [&[u8]; 5] = [
            b"#@~^AAAAAA==",
            b"<xdp><pdf><chunk>",
            b"(This file must be converted with BinHex 4.0)",
            b"AU3!EA06",
            b"AU3!EA05",
        ];
        for s in strings {
            for (start, want) in TEXTS {
                let file = [start, s, b"\n"].concat();
                assert_eq!(identify(&file), want, "{file:?}");
            }
        }
        // The marker of a script by itself, first in a text.
        assert_eq!(identify(b"AU3!EA06 and notes\n"), FileType::Text);
    }

    /// Where the string is the header of the format, the format is the type:
    /// a Script Encoder file and a BinHex file start with theirs, an XDP has
    /// its root element, a compiled script its marker after the script GUID.
    /// A page, and a message with a mail header first, keep their type.
    #[cfg(all(
        feature = "screnc",
        feature = "binhex",
        feature = "xdp",
        feature = "autoit"
    ))]
    #[test]
    fn the_header_of_a_format_found_by_a_string_types_a_text() {
        let blob: &[u8] = b"#@~^AAAAAA==xxxxxxxx^#~@";
        let binhex: &[u8] = b"(This file must be converted with BinHex 4.0)\r:#@9TB:";
        let root: &[u8] =
            b"<?xml version=\"1.0\"?>\n<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\">";
        let au3 = [&SCRIPT_GUID[..], b"AU3!EA06"].concat();
        assert_eq!(identify(blob), FileType::Screnc);
        assert_eq!(identify(binhex), FileType::Binhex);
        assert_eq!(identify(root), FileType::Xdp);
        assert_eq!(
            identify(&[b"just notes\n", &au3[..], b"\n"].concat()),
            FileType::Autoit
        );
        // Not first: the start says what it is.
        for s in [blob, binhex] {
            for (start, want) in TEXTS {
                let file = [start, s].concat();
                assert_eq!(identify(&file), want, "{file:?}");
            }
        }
        // The XDP root and the AutoIt marker type a text and a script, and not
        // a page or a message that starts with a mail header.
        for s in [root, &au3[..]] {
            for (start, want) in TEXTS {
                let file = [start, s, b"\n"].concat();
                let page_or_mail = want == FileType::Html
                    || start.starts_with(b"From: ")
                    || start.starts_with(b"Received: ");
                if page_or_mail {
                    assert_eq!(identify(&file), want, "{file:?}");
                } else {
                    let typed = if s == root {
                        FileType::Xdp
                    } else {
                        FileType::Autoit
                    };
                    assert_eq!(identify(&file), typed, "{file:?}");
                }
            }
        }
    }

    /// A PDF header in the first kilobyte types a text, a script and a message
    /// told by its MIME headers as a PDF, and not a page or a message that
    /// starts with a mail header. Clamscan 1.4.3 does the same. Past the
    /// first kilobyte, or with no digit after the dash, it is a string.
    #[test]
    fn a_pdf_header_near_the_start_types_a_text_but_not_a_page_or_a_message() {
        for (start, want) in TEXTS {
            let file = [start, b"\n%PDF-1.4\n"].concat();
            let typed = match want {
                FileType::Html | FileType::Email if start.starts_with(b"From") => want,
                FileType::Html => want,
                FileType::Email if start.starts_with(b"Received") => want,
                _ => FileType::Pdf,
            };
            assert_eq!(identify(&file), typed, "{file:?}");
            let late = [start, &[b'.'; 1100][..], b"\n%PDF-1.4\n"].concat();
            assert_eq!(identify(&late), want, "past the first kilobyte");
            let nodigit = [start, b"\n%PDF-x\n"].concat();
            assert_eq!(identify(&nodigit), want, "no digit");
        }
        // At the first byte it is the header, whatever the PDF holds.
        assert_eq!(identify(b"%PDF-1.4\n<html><body>"), FileType::Pdf);
    }

    /// A message whose headers carry a MIME header is a message before it is a
    /// page, whichever header comes first and whatever its first part is: clamscan
    /// opens a message with an HTML part, and typing it as HTML would not.
    #[test]
    fn a_message_with_an_html_part_is_a_message_not_a_page() {
        for head in [
            "Cc: a@b\nMIME-Version: 1.0",
            "X-Mozilla-Status: 0001\nSubject: x\nMIME-Version: 1.0",
            "from: a@b\nmime-version: 1.0",
            "MIME-Version: 1.0",
            "Content-Type: multipart/related; boundary=\"BB\"\nMIME-Version: 1.0",
        ] {
            let m = format!(
                "{head}\nContent-Type: multipart/related; boundary=\"BB\"\n\n\
                 --BB\nContent-Type: text/html\n\n<html><body>hi</body></html>\n--BB--\n"
            );
            assert_eq!(identify(m.as_bytes()), FileType::Email, "{head:?}");
        }
        // A page is still a page, whatever its first line holds.
        for page in [
            "<title>Note: x</title>\n<html><body>hi</body></html>\n",
            "<html>\n<body>Content-Type: text/html\nMIME-Version: 1.0</body></html>\n",
        ] {
            assert_eq!(identify(page.as_bytes()), FileType::Html, "{page:?}");
        }
    }

    /// Case counts, the colon is followed by a space, and nothing comes first.
    #[test]
    fn what_clamscan_does_not_type_as_mail_is_not_typed_as_mail() {
        for text in [
            "Cc: a@b\n\nhi",
            "Reply-To: a@b\n\nhi",
            "X-Mailer: x\n\nhi",
            "X-Mozilla-Status: 0001\n\nhi",
            "from: a@b\nto: c@d\nsubject: x\n\nhi",
            "FROM: a@b\nTO: c@d\nSUBJECT: x\n\nhi",
            "return-path: <a@b>\n\nhi",
            "Message-id: <1@b>\n\nhi",
            "From:a@b\n\nhi",
            "Date:Mon\n\nhi",
            "To:",
            " From: a@b\nTo: c@d\n\nhi",
            "\nFrom: a@b\nTo: c@d\n\nhi",
            "\r\nFrom: a@b\r\nTo: c@d\r\n\r\nhi",
            "\u{feff}From: a@b\n\nhi",
            "This is a note.\nFrom: me\nRegards\n",
            "<html>\nFrom: a@b\nTo: c@d\n\nhi",
            "Server: x\r\nDate: Mon\r\n\r\nhi",
        ] {
            assert_ne!(identify(text.as_bytes()), FileType::Email, "{text:?}");
        }
    }
}
