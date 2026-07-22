//! Content-based file-type identification (magic bytes), never trusting
//! the file extension. Only needs the first few KB, so it works in stream
//! mode. Drives routing to unpackers and structural analyzers.

/// File-type magic rules loaded from ClamAV `.ftm` databases. Each is a literal
/// byte prefix at a fixed offset that assigns a [`FileType`]. Applied ONLY as a
/// fallback when content-based [`identify`] is inconclusive (`Unknown`), so it
/// never overrides — and so never regresses — a confidently-typed file.
#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct FtmMagics {
    rules: Vec<FtmRule>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
    /// natively — these only fill gaps).
    pub fn extend_from_text(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 6 || f[0] != "0" {
                continue;
            }
            let Ok(offset) = f[1].parse::<usize>() else {
                continue;
            };
            let Some(magic) = parse_literal_hex(f[2]) else {
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
    }

    /// First magic that matches `data`, if any. Intended as the `Unknown`
    /// fallback for [`identify`].
    pub fn identify(&self, data: &[u8]) -> Option<FileType> {
        for r in &self.rules {
            let end = r.offset.checked_add(r.magic.len())?;
            if end <= data.len() && &data[r.offset..end] == r.magic.as_slice() {
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
/// `None` for types exav doesn't model (compiled python, …) — assigning those
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
    Alz,         // ALZ archive (recognised, not decoded)
    Egg,         // EGG archive (recognised, not decoded)
    Hwp3,        // Hangul HWP v3 document (recognised, not decoded)
    IshieldMsi,  // InstallShield MSI installer (recognised, not unpacked)
    IshieldCab,  // InstallShield InstallScript cabinet (recognised, not unpacked)
    IshieldZ,    // InstallShield `.z` archive (decoded)
    CryptFf,     // CryptFF-encrypted file (recognised, not decrypted)
    Ext,         // ext2/3/4 filesystem image (walked)
    Lrzip,       // lrzip stream (recognised, not decoded)
    Zoo,         // ZOO archive (decoded)
    AppleSingle, // AppleSingle/AppleDouble container (recognised, not read)
    StuffIt,     // StuffIt / StuffIt X archive (recognised, not decoded)
    Fat,         // FAT12/16/32 filesystem
    Inno,        // Inno Setup installer (recognised, not decoded)
    Ntfs,        // NTFS filesystem
    Zstd,        // Zstandard compressed stream
    Lzip,        // Lzip compressed stream
    Uuencode,    // uuencode / base64-uuencode wrapped file
    Xdp,         // Adobe XDP (XML-wrapped base64 PDF)
    Szdd,        // MS-Compress SZDD / KWAJ
    Tnef,        // TNEF (winmail.dat) MS email attachment container
    Swf,         // SWF (Adobe Flash) movie (CWS/ZWS compressed)
    // Raster image. Never produced by content detection — `Target:5` signatures
    // reach images through `fuzzy_img::looks_like_image` instead. This exists
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
    Html,      // HTML document (content-detected; for `Target:3` HTML signatures)
    Text,      // ASCII/UTF-8 text (content-detected; for `Target:7` text signatures)
    Unknown,
}

impl FileType {
    pub fn is_archive(self) -> bool {
        matches!(
            self,
            FileType::Zip
                | FileType::Gzip
                | FileType::Bzip2
                | FileType::Xz
                | FileType::Tar
                | FileType::SevenZip
                | FileType::Rar
                | FileType::Cab
                | FileType::Chm
                | FileType::Iso
                | FileType::Lha
                | FileType::Arj
                | FileType::Ar
                | FileType::Cpio
                | FileType::Xar
                | FileType::Wim
                | FileType::Lz4
                | FileType::Arc
                | FileType::Ace
                | FileType::Alz
                | FileType::Egg
                | FileType::Hwp3
                | FileType::IshieldMsi
                | FileType::IshieldCab
                | FileType::IshieldZ
                | FileType::CryptFf
                | FileType::Ext
                | FileType::Lrzip
                | FileType::Zoo
                | FileType::AppleSingle
                | FileType::Fat
                | FileType::Inno
                | FileType::Ntfs
                | FileType::Zstd
                | FileType::Lzip
                | FileType::Partition
        )
    }

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
        }
    }
}

/// Identify a file type from a header prefix (and, for tar, a 512-byte
/// record if available).
pub fn identify(buf: &[u8]) -> FileType {
    // Executables and RTF: types core recognises itself (not extractable
    // containers, so `exav-unpack` doesn't know them).
    if buf.starts_with(b"MZ") {
        return FileType::Pe;
    }
    if buf.starts_with(b"\x7fELF") {
        return FileType::Elf;
    }
    // Thin Mach-O magics only. The universal/"fat" magics (CA FE BA BE /
    // CA FE BA BF) are deliberately NOT matched here, so a fat binary falls
    // through to `unpack::detect` → `Format::Machofat` and gets split into its
    // per-arch slices (each a thin Mach-O, re-scanned). CA FE BA BE is also the
    // Java `.class` magic; `machofat` detection rejects those.
    if buf.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
        || buf.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
        || buf.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
        || buf.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
    {
        return FileType::MachO;
    }
    if buf.starts_with(b"{\\rtf") {
        return FileType::Rtf;
    }
    // Uncompressed Flash. `CWS`/`ZWS` (the compressed variants) are containers
    // and belong to `unpack::detect`; `FWS` has nothing to decompress, so core
    // types it directly — without this, `Target:11` signatures would never see
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
    if let Some(fmt) = crate::unpack::detect(buf) {
        return filetype_of_format(fmt);
    }
    // Content-sniffed text-ish types (core-specific).
    if buf.starts_with(b"#!") {
        return FileType::Script;
    }
    if looks_like_html(buf) {
        return FileType::Html;
    }
    if looks_like_email(buf) {
        return FileType::Email;
    }
    // Mostly-printable content with no more specific type is ASCII/UTF-8 text.
    // ClamAV distinguishes text from binary so `Target:7` (text) signatures apply
    // only to text; mirroring that keeps text sigs off binary blobs.
    if looks_textual(buf) {
        return FileType::Text;
    }
    FileType::Unknown
}

/// True if the head looks like text (ASCII *or* UTF-8) rather than binary.
/// Generous on purpose: a NUL byte or a high density of non-whitespace control
/// bytes marks binary, but high bytes (0x80..=0xff) are accepted so non-ASCII
/// UTF-8 text still types as text — otherwise non-English text malware would
/// type as binary and lose its `Target:7` (ASCII-text) coverage.
fn looks_textual(buf: &[u8]) -> bool {
    let head = &buf[..buf.len().min(8192)];
    if head.is_empty() {
        return false;
    }
    let mut ctrl = 0usize;
    for &b in head {
        if b == 0 {
            return false; // NUL ⇒ binary
        }
        if b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c) {
            ctrl += 1;
        }
    }
    ctrl * 20 < head.len() // < 5% non-whitespace control bytes
}

/// Heuristic HTML detection (HTML has no magic bytes). ClamAV types content as
/// HTML and applies `Target:3` signatures only to it; exav mirrors that so an
/// HTML-exploit sig does not fire on, say, obfuscated JavaScript that merely
/// contains `Uint32Array(0x..)`. Conservative: requires a real structural tag in
/// the (text-ish) head — plain JS/text is left `Unknown` and is still covered by
/// `Target:7` text signatures.
fn looks_like_html(buf: &[u8]) -> bool {
    let head = &buf[..buf.len().min(8192)];
    // Must be text-ish (mostly printable); skip binary that happens to contain
    // an angle-bracket sequence.
    let printable = head
        .iter()
        .filter(|&&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b))
        .count();
    if head.is_empty() || printable * 10 < head.len() * 9 {
        return false;
    }
    let lower = head.to_ascii_lowercase();
    const MARKERS: &[&[u8]] = &[
        b"<!doctype html",
        b"<html",
        b"<head",
        b"<body",
        b"<script",
        b"<iframe",
        b"<title",
        b"<table",
        b"<style",
        b"<meta ",
        b"<div",
        b"<span",
        b"<a href",
        b"<img ",
    ];
    MARKERS
        .iter()
        .any(|m| memchr::memmem::find(&lower, m).is_some())
}

/// Heuristic RFC822/MIME detection (email has no magic bytes). Conservative:
/// the message must start with a recognized header line *and* carry a
/// MIME-Version/Content-Type header, or be an mbox (`From ` separator).
fn looks_like_email(buf: &[u8]) -> bool {
    let head = &buf[..buf.len().min(8192)];
    let text = String::from_utf8_lossy(head);
    if text.starts_with("From ") {
        return true; // mbox
    }
    let first_is_header = text.lines().next().is_some_and(|l| {
        let key = l.split_once(':').map(|(k, _)| k).unwrap_or("");
        matches!(
            key,
            "Received"
                | "Return-Path"
                | "From"
                | "To"
                | "Subject"
                | "Date"
                | "Message-ID"
                | "Delivered-To"
                | "MIME-Version"
                | "Content-Type"
        )
    });
    first_is_header && (text.contains("MIME-Version:") || text.contains("Content-Type:"))
}

/// Whether a MIME document is an **MHTML web archive** rather than a mail
/// message — a saved web page (`.mht`), not something that travelled through a
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
/// (`Format::Email` is never returned by magic — email is content-sniffed — but
/// is mapped for completeness.)
///
/// Several formats have no ClamAV `CL_TYPE_*` of their own and land on
/// `FileType::Unknown`. Since the scanner reaches an extractor through
/// `FileType`, such a format would never be extracted at all; they are listed in
/// [`MAGIC_DISPATCH_ONLY`] and dispatched straight from the magic instead.
/// `scan_dispatch_covers_every_format` holds the two lists together.
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
        // this mapping is total. `scan_dispatch_covers_every_format` proves it
        // instead, walking `Format::ALL` and failing on any variant that does
        // not round-trip — which catches a missing arm here for the same reason
        // the compiler used to, and with a better message.
        _ => FileType::Unknown,
    }
}

/// Formats that [`filetype_of_format`] maps to `FileType::Unknown` yet still
/// have real content to extract, so the scanner dispatches them from the magic
/// rather than from the file type.
///
/// `Upx`/`PePacked` are deliberately absent: they are content-detected on an
/// already-typed executable, not returned by `detect`.
/// Containers that live *inside* an executable: an installer or self-extractor
/// whose payload is appended to a PE/ELF stub.
///
/// `identify` answers `Pe`/`Elf` for these — correctly, since they are real
/// executables and the PE signature scan has to run on them — and
/// `unpack_format` has no mapping from an executable to a container, so the
/// extractor is never reached. Embedded-archive carving covers the case where
/// the appended data is a *recognisable* archive (a ZIP glued to a stub), but
/// not where it is the installer's own format: NSIS's compressed blocks and
/// Inno Setup's chunked LZMA look like nothing in particular, so a carve finds
/// no candidate and the file scans clean with every packaged file unexamined.
///
/// So these are dispatched from the magic instead, exactly as
/// [`MAGIC_DISPATCH_ONLY`] is. `scan_dispatch_covers_every_format` holds the
/// lists and the mapping together.
pub(crate) const EXECUTABLE_CONTAINERS: &[crate::unpack::Format] = &[
    crate::unpack::Format::Nsis,
    crate::unpack::Format::Sfx,
    crate::unpack::Format::Autoit,
    crate::unpack::Format::Inno,
];

pub(crate) const MAGIC_DISPATCH_ONLY: &[crate::unpack::Format] = &[
    crate::unpack::Format::Dmg,
    crate::unpack::Format::Vhd,
    crate::unpack::Format::Lzw,
    crate::unpack::Format::Qcow2,
    crate::unpack::Format::Vmdk,
    crate::unpack::Format::Vhdx,
];

#[cfg(test)]
mod tests {
    use crate::unpack::Format;

    /// Every format the magic detector recognises must be reachable by the
    /// scanner. A format that lands on `FileType::Unknown` and is not listed in
    /// [`MAGIC_DISPATCH_ONLY`] is never handed to an extractor at all: its
    /// members are simply not scanned, and the file is reported clean on the
    /// strength of a raw pattern scan that cannot see compressed content.
    ///
    /// This is a real regression that shipped — `.Z`, DMG, VHD, QCOW2 and VMDK
    /// each had a working extractor that nothing ever called.
    #[test]
    fn scan_dispatch_covers_every_format() {
        for &fmt in Format::ALL {
            // Runtime packers are detected on an already-typed executable
            // rather than by `detect`, so they have no file type to map.
            if matches!(fmt, Format::Upx | Format::PePacked) {
                continue;
            }
            if super::MAGIC_DISPATCH_ONLY.contains(&fmt) {
                continue;
            }
            let ft = super::filetype_of_format(fmt);
            assert_eq!(
                crate::unpack_format(ft),
                Some(fmt),
                "{fmt:?} maps to {ft:?}, which the scanner does not dispatch                  back to {fmt:?} — its contents would go unscanned. Give it a                  FileType, or add it to MAGIC_DISPATCH_ONLY."
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
            "0:0:49545346:MS CHM:CL_TYPE_ANY:CL_TYPE_MSCHM\n\
             0:0:46726f6d20:MBox:CL_TYPE_ANY:CL_TYPE_MAIL\n\
             0:0:255044462d:PDF:CL_TYPE_ANY:CL_TYPE_PDF\n\
             0:0:6125{4}62:wild:CL_TYPE_ANY:CL_TYPE_MAIL\n\
             1:0:cafe:pe:CL_TYPE_ANY:CL_TYPE_MSEXE",
        );
        // CHM has no exav FileType (CL_TYPE_MSCHM unmodelled) -> not stored;
        // MAIL + PDF map and are stored.
        assert_eq!(ftm.identify(b"From the start"), Some(FileType::Email));
        assert_eq!(ftm.identify(b"%PDF-1.7 ..."), Some(FileType::Pdf));
        assert_eq!(ftm.identify(b"no magic here"), None);
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
        // exploit sigs don't fire on it — the npm-package FP). It is text, so it
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
}
