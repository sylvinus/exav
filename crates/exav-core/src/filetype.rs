//! Content-based file-type identification (magic bytes), never trusting
//! the file extension. Only needs the first few KB, so it works in stream
//! mode. Drives routing to unpackers and structural analyzers.

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
    Script, // shell/script with a shebang
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
            FileType::Script => "script",
            FileType::Unknown => "data",
        }
    }
}

/// Identify a file type from a header prefix (and, for tar, a 512-byte
/// record if available).
pub fn identify(buf: &[u8]) -> FileType {
    if buf.len() >= 2 {
        match &buf[..2] {
            b"MZ" => return FileType::Pe,
            b"PK"
                if buf.len() >= 4
                    && (buf[2..4] == [3, 4] || buf[2..4] == [5, 6] || buf[2..4] == [7, 8]) =>
            {
                return FileType::Zip
            }
            [0x1f, 0x8b] => return FileType::Gzip,
            _ => {}
        }
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
    if buf.starts_with(b"%PDF-") {
        return FileType::Pdf;
    }
    if buf.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return FileType::Ole;
    }
    if buf.starts_with(b"{\\rtf") {
        return FileType::Rtf;
    }
    if buf.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return FileType::SevenZip;
    }
    if buf.starts_with(b"Rar!\x1A\x07") {
        return FileType::Rar;
    }
    if buf.starts_with(b"MSCF") {
        return FileType::Cab;
    }
    if buf.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return FileType::Xz;
    }
    if buf.starts_with(b"BZh") {
        return FileType::Bzip2;
    }
    // LHA/LZH: a method id "-lhN-"/"-lzN-"/"-pmN-" at offset 2 (offsets 0/1 are
    // header size/checksum, which vary).
    if buf.len() >= 7
        && buf[2] == b'-'
        && buf[6] == b'-'
        && matches!(buf[3], b'l' | b'p')
    {
        return FileType::Lha;
    }
    // ISO 9660: "CD001" at the start of the first volume descriptor (sector 16,
    // offset 0x8000). Needs the image to be buffered this far.
    if buf.len() >= 32774 && &buf[32769..32774] == b"CD001" {
        return FileType::Iso;
    }
    if buf.starts_with(b"#!") {
        return FileType::Script;
    }
    // tar: "ustar" magic at offset 257 in the first 512-byte record.
    if buf.len() >= 263 && &buf[257..262] == b"ustar" {
        return FileType::Tar;
    }
    if looks_like_email(buf) {
        return FileType::Email;
    }
    FileType::Unknown
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
    fn detects_common_types() {
        assert_eq!(identify(b"MZ\x90\x00"), FileType::Pe);
        assert_eq!(identify(b"\x7fELF"), FileType::Elf);
        assert_eq!(identify(b"PK\x03\x04...."), FileType::Zip);
        assert_eq!(identify(&[0x1f, 0x8b, 0x08]), FileType::Gzip);
        assert_eq!(identify(b"%PDF-1.7"), FileType::Pdf);
        assert_eq!(identify(b"#!/bin/sh\n"), FileType::Script);
        assert_eq!(identify(b"random bytes"), FileType::Unknown);
    }

    #[test]
    fn email_heuristic() {
        let eml = b"From: a@b\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhi";
        assert_eq!(identify(eml), FileType::Email);
        // Plain prose with a colon must not be misread as email.
        assert_eq!(identify(b"Notes: buy milk\nand eggs\n"), FileType::Unknown);
    }
}
