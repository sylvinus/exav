//! What reads an object: the one typer, for every consumer of the walk.
//!
//! [`Typing`] decides from the bytes of an object which reader opens it, if
//! any. The consumers differ in few things, given as its fields: whether it
//! types as the scanner does ([`Typing::scanner`]), whether it keeps to what
//! ClamAV opens ([`Typing::clamav`]), whether an executable's appended archive
//! is read ([`Typing::sfx`]). What a consumer has already read of the object
//! (a scan reads each object once for everything it asks of it) is handed over
//! through [`Observed`]; [`Typing`] used as a [`Typer`] reads for itself.

use std::borrow::Cow;

use super::engine::{Node, Typed, Typer, packer_not_checked};
use crate::source::ByteSource;
use crate::{Executable, Format};

/// How much of an object's start the typer looks at to tell a message.
const HEAD: usize = 64 * 1024;

/// The formats that have no type of their own for the scanner and are read
/// from their magic: disk images, `compress`, LZMA-alone, RPM, DXF and DWG
/// drawings. In `--clamav-compat` only DMG is, as ClamAV opens it.
pub const MAGIC_DISPATCH_ONLY: &[Format] = &[
    Format::Dmg,
    Format::Vhd,
    Format::Lzw,
    Format::Lzma,
    Format::Rpm,
    Format::Qcow2,
    Format::Vmdk,
    Format::Vhdx,
    Format::Dxf,
    Format::Dwg,
];

/// Containers that live inside an executable: an installer or self-extractor
/// whose payload is appended to a PE/ELF stub, and is not a recognisable
/// archive (NSIS's compressed blocks, Inno Setup's chunked LZMA), so carving
/// does not reach it either.
pub const EXECUTABLE_CONTAINERS: &[Format] = &[
    Format::Nsis,
    Format::Sfx,
    Format::Autoit,
    Format::Inno,
    Format::IshieldMsi,
];

/// The formats stock ClamAV does not open. clamscan 1.4.3 with `--debug`, on a
/// container whose member only an extraction shows (EICAR in a compressed
/// member, or a signature anchored at the member's first byte), types each of
/// them as binary data, or by a type of its own with nothing extracted, and
/// never finds the member; a tar or plain file holding the same bytes is
/// found. With [`Typing::clamav`] they are not opened.
///
/// Not here, because ClamAV opens them: cpio, xar, UPX, ALZ, EGG, SZDD (see
/// [`clamav_opens_szdd`]), HWP3, partition tables, universal Mach-O, DMG.
pub const NOT_OPENED_BY_CLAMAV: &[Format] = &[
    Format::Ace,
    Format::AiModel,
    Format::AppleSingle,
    Format::Ar,
    Format::Arc,
    Format::Cramfs,
    Format::Erofs,
    Format::Exfat,
    Format::Ext,
    Format::Fat,
    Format::IshieldCab,
    Format::IshieldZ,
    Format::JavaClass,
    Format::Lnk,
    Format::Lrzip,
    Format::Lz4,
    Format::Lzip,
    Format::Ntfs,
    Format::Pyc,
    Format::Romfs,
    Format::Squashfs,
    Format::StuffIt,
    Format::Wim,
    Format::Zoo,
    Format::Zstd,
];

/// Whether ClamAV opens the SZDD or KWAJ file starting with `head`: only an
/// SZDD in compression mode `A` whose byte 9 (the missing character) is zero.
/// A KWAJ file is typed as binary data, and an SZDD in another mode or with a
/// nonzero byte 9 is logged as `Not supported file format`: nothing is
/// extracted from either.
pub fn clamav_opens_szdd(head: &[u8]) -> bool {
    head.starts_with(b"SZDD\x88\xF0\x27\x33A\0")
}

/// What a consumer has read of an object already, so that the typer asks and
/// does not read again. A consumer that has read nothing is [`Typing`] itself
/// as a [`Typer`].
pub trait Observed {
    /// What [`crate::detect`] makes of the object.
    fn format(&self) -> Option<Format>;
    /// An executable of `kind` held in memory for the checks of the packers:
    /// all of it, or the part of a PE a check that parses it is given when it is
    /// too large to hold (its image). `None` when neither can be held: whether
    /// it is packed was not checked.
    fn executable(&self, kind: Executable) -> Option<Cow<'_, [u8]>>;
    /// Whether a UPX pack header is in the object past the part
    /// [`Self::executable`] gave.
    fn upx_header(&self) -> bool;
}

/// What a consumer has decided an object is, whatever its bytes say: a
/// signature that tells the scanner to treat it as a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Declared {
    /// An object a format reads, as the format's own type.
    Format(Format),
    /// An executable.
    Executable(Executable),
    /// A type that has no reader of its own (a page, a text, a script): only a
    /// format that a string in it names, or that is read from its magic, is
    /// read.
    Other,
}

/// What the typer reads of an object that a consumer has not read.
struct Direct<'a> {
    src: &'a dyn ByteSource,
    hold: u64,
}

impl Observed for Direct<'_> {
    fn format(&self) -> Option<Format> {
        crate::detect(self.src)
    }

    fn executable(&self, _: Executable) -> Option<Cow<'_, [u8]>> {
        self.src
            .materialize(usize::try_from(self.hold).unwrap_or(usize::MAX))
    }

    fn upx_header(&self) -> bool {
        false
    }
}

/// Which reader opens an object. As a [`Typer`] it is the walk's: what
/// [`crate::detect`] says, then the packers of an executable, read from the
/// object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Typing {
    /// Types as the scanner does, which sniffs what has no magic: a message is
    /// read as one, and uncompressed Flash as Flash (a reader that gives no
    /// member).
    pub scanner: bool,
    /// Keeps to what ClamAV opens (`--clamav-compat`): the formats it does not
    /// open ([`NOT_OPENED_BY_CLAMAV`]), the disk images and drawings it does not
    /// ([`MAGIC_DISPATCH_ONLY`]), Inno Setup and the installers of InstallShield
    /// 2015 and later, and UPX out of an ELF or a Mach-O. A reach that is
    /// narrower, never wider.
    pub clamav: bool,
    /// Reads the archive appended to an executable (a self-extractor). Off for
    /// an executable carved out of the sectors of a compound file, whose bytes
    /// are not in the order of the stream that holds them.
    pub sfx: bool,
}

impl Default for Typing {
    fn default() -> Self {
        Typing::WALK
    }
}

impl Typing {
    /// The walk of a search or a listing: no sniffing, no restriction.
    pub const WALK: Typing = Typing {
        scanner: false,
        clamav: false,
        sfx: true,
    };

    /// What reads the object `src`, which a consumer may hold up to `hold`
    /// bytes of: as `seen` has it, and as `declared` says it is, if it does.
    pub fn type_source(
        &self,
        src: &dyn ByteSource,
        hold: u64,
        seen: &dyn Observed,
        declared: Option<Declared>,
    ) -> Typed {
        let start = src.window(0, 16);
        if let Some(declared) = declared {
            return match declared {
                Declared::Format(f) => self.reader(f, &start),
                Declared::Executable(kind) => self.executable(kind, seen.format(), src, hold, seen),
                Declared::Other => match seen.format() {
                    Some(f) if crate::is_found_by_string(f) || MAGIC_DISPATCH_ONLY.contains(&f) => {
                        self.reader(f, &start)
                    }
                    _ => Typed::Plain,
                },
            };
        }
        let exe = crate::executable_kind(&start);
        // Before `detect`, as the scanner's file types are: an RTF document,
        // and for the scanner uncompressed Flash, which `detect` does not type
        // (there is nothing to decode in it).
        if exe.is_none() {
            if crate::is_rtf(&start) {
                return Typed::Container(Format::Rtf);
            }
            if self.scanner && start.starts_with(b"FWS") {
                return Typed::Container(Format::Swf);
            }
        }
        let format = seen.format();
        if let Some(exe) = exe {
            return self.executable(exe, format, src, hold, seen);
        }
        if self.scanner {
            let head = src.window(0, HEAD);
            // A message has a reader of its own, unless the object is a format
            // that a string in the message names and that wins over it.
            let message = crate::is_message(&head)
                && match format {
                    None | Some(Format::Dxf) => true,
                    Some(f) => {
                        crate::is_found_by_string(f) && crate::text_keeps(f, &head).is_some()
                    }
                };
            if message {
                return Typed::Container(Format::Email);
            }
        }
        match format {
            Some(f) => self.reader(f, &src.window(0, 16)),
            None => Typed::Plain,
        }
    }

    /// The reader of an object `detect` gives `format` for.
    fn reader(&self, format: Format, head: &[u8]) -> Typed {
        let opened = if MAGIC_DISPATCH_ONLY.contains(&format) {
            !self.clamav || format == Format::Dmg
        } else {
            !(self.clamav
                && (NOT_OPENED_BY_CLAMAV.contains(&format)
                    || (format == Format::Szdd && !clamav_opens_szdd(head))))
        };
        if opened {
            Typed::Container(format)
        } else {
            Typed::Plain
        }
    }

    /// The reader of an executable: its installer, or the packer it is packed
    /// by.
    fn executable(
        &self,
        kind: Executable,
        format: Option<Format>,
        src: &dyn ByteSource,
        hold: u64,
        seen: &dyn Observed,
    ) -> Typed {
        if let Some(f) = format {
            if MAGIC_DISPATCH_ONLY.contains(&f) && (!self.clamav || f == Format::Dmg) {
                return Typed::Container(f);
            }
            if EXECUTABLE_CONTAINERS.contains(&f) {
                // Stock ClamAV unpacks NSIS, AutoIt, SFX and InstallShield
                // setups; it has no Inno Setup support, and opens the
                // installers of InstallShield 2009 to 2011 and not those of
                // 2015 and later.
                let beyond = f == Format::Inno
                    || (f == Format::IshieldMsi && crate::is_ishield_setup_stream(src));
                if f == Format::Sfx && !self.sfx {
                    return Typed::Plain;
                }
                if !self.clamav || !beyond {
                    return Typed::Container(f);
                }
            }
        }
        // Packed, which no magic says: the packer check reads all of the
        // executable (a PE too large to hold: its image), the UPX check its
        // start.
        let Some(image) = seen.executable(kind) else {
            return Typed::Unchecked(packer_not_checked(hold));
        };
        // ClamAV's UPX unpacker runs only from its PE path, so with `clamav`
        // it is not tried on an ELF or a Mach-O.
        let upx = crate::is_upx(&image) || (image.len() < src.len() && seen.upx_header());
        if upx && (!self.clamav || kind == Executable::Pe) {
            return Typed::Container(Format::Upx);
        }
        // The other runtime packers of a PE: decompressed statically, or run
        // under the emulator. Under `clamav` as well: skipping an unpacker
        // there would be a miss, not a closer match.
        if crate::is_pepack(&image) {
            return Typed::Container(Format::PePacked);
        }
        Typed::Plain
    }
}

impl Typer for Typing {
    fn type_of(&self, node: &Node<'_>) -> Typed {
        let Some(src) = node.source() else {
            return Typed::Plain;
        };
        let hold = node.hold();
        self.type_source(src, hold, &Direct { src, hold }, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(typing: Typing, data: &[u8]) -> Option<Format> {
        match typing.type_source(
            &data,
            u64::MAX,
            &Direct {
                src: &data,
                hold: u64::MAX,
            },
            None,
        ) {
            Typed::Container(f) => Some(f),
            Typed::Plain | Typed::Unchecked(_) => None,
        }
    }

    fn clamav() -> Typing {
        Typing {
            clamav: true,
            ..Typing::default()
        }
    }

    fn scanner() -> Typing {
        Typing {
            scanner: true,
            ..Typing::default()
        }
    }

    fn declared(typing: Typing, data: &[u8], declared: Declared) -> Option<Format> {
        match typing.type_source(
            &data,
            u64::MAX,
            &Direct {
                src: &data,
                hold: u64::MAX,
            },
            Some(declared),
        ) {
            Typed::Container(f) => Some(f),
            Typed::Plain | Typed::Unchecked(_) => None,
        }
    }

    /// The scanner types what has no magic: a message is read as one, and
    /// uncompressed Flash as Flash. A search or a listing does not.
    #[test]
    fn the_scanner_reads_a_message_and_uncompressed_flash() {
        let message = b"From: a@b\nTo: c@d\nSubject: x\n\nhello\n";
        assert_eq!(read(scanner(), message), Some(Format::Email));
        assert_eq!(read(Typing::WALK, message), None);
        // A message told by its MIME headers, and one that holds a string a
        // format is found by: still a message. With the header of the format
        // (an XDP root) in a message that does not start with a mail header,
        // the format.
        let mime = b"MIME-Version: 1.0\nContent-Type: text/plain\n\nhi #@~^AAAAAA== ";
        assert_eq!(read(scanner(), mime), Some(Format::Email));
        #[cfg(feature = "xdp")]
        {
            let root = b"MIME-Version: 1.0\nContent-Type: text/plain\n\n<xdp:xdp xmlns:xdp=\"x\">";
            assert_eq!(read(scanner(), root), Some(Format::Xdp));
        }
        let from = b"From: a@b\nSubject: x\n\n<xdp:xdp xmlns:xdp=\"x\">";
        assert_eq!(read(scanner(), from), Some(Format::Email));
        // A script is not a message.
        assert_eq!(read(scanner(), b"#!/bin/sh\nFrom: a@b\n"), None);
        assert_eq!(
            read(scanner(), b"FWS\x09\x10\0\0\0 body"),
            Some(Format::Swf)
        );
        assert_eq!(read(Typing::WALK, b"FWS\x09\x10\0\0\0 body"), None);
        #[cfg(feature = "swf")]
        assert_eq!(
            read(scanner(), b"CWS\x09\x10\0\0\0 body"),
            Some(Format::Swf)
        );
    }

    /// An RTF document is one whatever a later rule says of its bytes; an
    /// executable is read as an installer or a packed program, not as a
    /// format a string near its start names.
    #[test]
    fn an_rtf_and_an_executable_are_typed_before_the_strings() {
        let mut rtf = b"{\\rtf1 ".to_vec();
        rtf.resize(257, b' ');
        rtf.extend_from_slice(b"ustar  ");
        assert_eq!(crate::detect(&&rtf[..]), Some(Format::Tar));
        assert_eq!(read(Typing::WALK, &rtf), Some(Format::Rtf));
        let mut pe = b"MZ".to_vec();
        pe.resize(100, 0);
        pe.extend_from_slice(b"%PDF-1.4\n");
        pe.resize(600, 0);
        assert_eq!(read(Typing::WALK, &pe), None);
        assert_eq!(read(scanner(), &pe), None);
    }

    /// The RTF header is `{\rt`: `{\rt0` is typed as `{\rtf1` is, `{\r` is not.
    #[test]
    fn an_rtf_with_a_short_header_is_typed_before_the_strings() {
        let mut rtf = b"{\\rt0 ".to_vec();
        rtf.resize(257, b' ');
        rtf.extend_from_slice(b"ustar  ");
        assert_eq!(crate::detect(&&rtf[..]), Some(Format::Tar));
        assert_eq!(read(Typing::WALK, &rtf), Some(Format::Rtf));
        rtf[2] = b' ';
        assert_eq!(read(Typing::WALK, &rtf), Some(Format::Tar));
    }

    /// A type a signature gave an object decides which reader opens it, as
    /// far as that type has one.
    #[test]
    fn a_declared_type_names_the_reader() {
        let zip = b"PK\x03\x04 and the rest";
        assert_eq!(read(Typing::WALK, zip), Some(Format::Zip));
        // Declared a page, a text or a script: a ZIP's bytes are not read.
        assert_eq!(declared(scanner(), zip, Declared::Other), None);
        // Declared a ZIP, whatever the bytes are.
        assert_eq!(
            declared(scanner(), b"plain text", Declared::Format(Format::Zip)),
            Some(Format::Zip)
        );
        assert_eq!(
            declared(clamav(), b"plain text", Declared::Format(Format::Ar)),
            None
        );
        // A string a format is found by, or a format read from its magic, is
        // still read from a page.
        #[cfg(feature = "screnc")]
        assert_eq!(
            declared(
                scanner(),
                b"<html> #@~^AAAAAA==xxxxxxxx^#~@",
                Declared::Other
            ),
            Some(Format::Screnc)
        );
        // Declared an executable: the checks of a packed one apply.
        #[cfg(feature = "upx")]
        assert_eq!(
            declared(
                scanner(),
                &fake_upx(b"xx"),
                Declared::Executable(Executable::Pe)
            ),
            Some(Format::Upx)
        );
    }

    #[test]
    fn clamav_gates_absent_formats() {
        // The compat mask gates the formats stock ClamAV does not open and
        // nothing it opens: gating cpio or xar would make exav miss detections
        // ClamAV makes.
        let open = |t: Typing, f: Format, head: &[u8]| match t.reader(f, head) {
            Typed::Container(g) => Some(g),
            _ => None,
        };
        assert_eq!(open(Typing::default(), Format::Ar, b""), Some(Format::Ar));
        assert_eq!(open(clamav(), Format::Ar, b""), None);
        // Opened by ClamAV, so never gated.
        for f in [
            Format::Cpio,
            Format::Xar,
            Format::Alz,
            Format::Egg,
            Format::Hwp3,
            Format::Iso,
            Format::Lha,
            Format::Arj,
            Format::Tnef,
            Format::Dmg,
        ] {
            assert_eq!(open(Typing::default(), f, b""), Some(f));
            assert_eq!(open(clamav(), f, b""), Some(f), "{f:?} must not be gated");
        }
        // Typed by ClamAV as binary data (or by a type of its own) with nothing
        // extracted, so gated like `ar`.
        for f in NOT_OPENED_BY_CLAMAV
            .iter()
            .chain(MAGIC_DISPATCH_ONLY.iter().filter(|&&f| f != Format::Dmg))
        {
            assert_eq!(open(Typing::default(), *f, b""), Some(*f));
            assert_eq!(open(clamav(), *f, b""), None, "{f:?}");
        }
        // SZDD: ClamAV opens mode `A` with a zero byte 9, and no KWAJ file.
        let szdd = |tail: &[u8]| [&b"SZDD\x88\xF0\x27\x33"[..], tail].concat();
        for (what, data, opened) in [
            ("SZDD, mode A, byte 9 zero", szdd(b"A\0\x10\0\0\0"), true),
            ("SZDD, byte 9 not zero", szdd(b"AX\x10\0\0\0"), false),
            ("SZDD, mode B", szdd(b"B\0\x10\0\0\0"), false),
            (
                "KWAJ",
                b"KWAJ\x88\xF0\x27\xD1\0\0\x0e\0\0\0".to_vec(),
                false,
            ),
        ] {
            assert_eq!(
                open(Typing::default(), Format::Szdd, &data),
                Some(Format::Szdd),
                "{what}"
            );
            assert_eq!(
                open(clamav(), Format::Szdd, &data).is_some(),
                opened,
                "{what}"
            );
        }
    }

    /// A minimal buffer whose UPX `PackHeader` passes `find_packheader` (so
    /// `is_upx` is true), without needing a real compressed payload.
    #[cfg(feature = "upx")]
    fn fake_upx(magic: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 40];
        b[..magic.len()].copy_from_slice(magic);
        b[4..8].copy_from_slice(b"UPX!"); // magic (l_info starts at 0)
        b[16..20].copy_from_slice(&100u32.to_le_bytes()); // filesize
        b[24..28].copy_from_slice(&8u32.to_le_bytes()); // first block sz_unc
        b[28..32].copy_from_slice(&4u32.to_le_bytes()); // first block sz_cpr (fits: 36+4=40)
        b
    }

    /// Compat restricts UPX unpacking to PE: ClamAV's UPX unpacker runs only
    /// from its PE path, so the UPX reach of an ELF or Mach-O (e.g. UPX-packed
    /// Mirai ELFs) is gated off with `clamav` to stay apples-to-apples.
    #[cfg(feature = "upx")]
    #[test]
    fn clamav_scopes_upx_to_pe() {
        let kinds: [&[u8]; 3] = [b"MZ", b"\x7fELF", &[0xcf, 0xfa, 0xed, 0xfe]];
        for (i, magic) in kinds.into_iter().enumerate() {
            let buf = fake_upx(magic);
            assert!(crate::is_upx(&buf), "test buffer must look like UPX");
            // Every executable type, normally.
            assert_eq!(read(Typing::default(), &buf), Some(Format::Upx));
            // With `clamav`: a PE stays on, an ELF and a Mach-O are gated off.
            let got = read(clamav(), &buf);
            if i == 0 {
                assert_eq!(got, Some(Format::Upx), "PE-UPX must stay on");
            } else {
                assert_eq!(got, None, "UPX out of {magic:?} must be gated off");
            }
        }
    }
}
