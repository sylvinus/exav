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
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
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
/// `None` for types exav doesn't model (graphics, compiled python, swf, …) —
/// assigning those would gain nothing since no `Target` keys on them.
fn cl_type_to_filetype(t: &str) -> Option<FileType> {
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
        _ => return None,
    })
}

/// Recognised file types relevant to scanning/unpacking decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    Iso,    // ISO 9660 CD/DVD image
    Lha,    // LHA/LZH archive
    Arj,    // ARJ archive
    Ar,     // Unix ar archive (.a, .deb)
    Cpio,   // cpio archive (RPM payload, initramfs)
    Xar,    // XAR archive (macOS .pkg/.xip)
    Zstd,   // Zstandard compressed stream
    Lzip,   // Lzip compressed stream
    Script, // shell/script with a shebang
    Html,   // HTML document (content-detected; for `Target:3` HTML signatures)
    Text,   // ASCII/UTF-8 text (content-detected; for `Target:7` text signatures)
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
                | FileType::Iso
                | FileType::Lha
                | FileType::Arj
                | FileType::Ar
                | FileType::Cpio
                | FileType::Xar
                | FileType::Zstd
                | FileType::Lzip
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
            FileType::Iso => "ISO",
            FileType::Lha => "LHA",
            FileType::Arj => "ARJ",
            FileType::Ar => "AR",
            FileType::Cpio => "CPIO",
            FileType::Xar => "XAR",
            FileType::Zstd => "ZSTD",
            FileType::Lzip => "LZIP",
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
    if buf.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
        || buf.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
        || buf.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
        || buf.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
        || buf.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
    {
        return FileType::MachO;
    }
    if buf.starts_with(b"{\\rtf") {
        return FileType::Rtf;
    }
    // Archive/container formats: the magic detection is owned solely by
    // `exav-unpack::detect` (single source of truth); map its `Format` to the
    // broader `FileType`. (`Format::Email` is never returned by magic — email is
    // content-sniffed below — but is handled for completeness.)
    if let Some(fmt) = crate::unpack::detect(buf) {
        use crate::unpack::Format;
        return match fmt {
            Format::Zip => FileType::Zip,
            Format::Gzip => FileType::Gzip,
            Format::Tar => FileType::Tar,
            Format::Bzip2 => FileType::Bzip2,
            Format::Xz => FileType::Xz,
            Format::Cab => FileType::Cab,
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
            // UPX is content-detected on executables, never by `detect`.
            Format::Upx => FileType::Unknown,
            Format::Dmg => FileType::Unknown,
            Format::Zstd => FileType::Zstd,
            Format::Lzip => FileType::Lzip,
        };
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
/// lose its `Target:7` coverage (which previously matched via `Unknown`).
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

#[cfg(test)]
mod tests {
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
        assert_eq!(identify(&[0x1f, 0x8b, 0x08]), FileType::Gzip);
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
