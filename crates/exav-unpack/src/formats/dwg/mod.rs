//! AutoCAD DWG, R13 to R2018 (AC1012, AC1014, AC1015, AC1018, AC1021,
//! AC1024, AC1027, AC1032): the file's structure, for a reader of drawings
//! to build on (exav-render's), and the files a drawing embeds, for the
//! scanner. Follows the Open Design Specification for .dwg files 5.4.1
//! ("spec" below), and says where files differ from it.
//!
//! [`Bits`] reads the bit codes every part of the file is made of (spec 2).
//! [`Dwg`] finds the sections: R13 to R2000 where the file header locates
//! them (spec 3), R2004 on by name in a paged container whose maps and
//! pages it decrypts, checks and decompresses (spec 4; R2007's own, Reed-
//! Solomon coded, with its own compression, spec 5). They are the header
//! variables (spec 9), which it leaves to the reader, the classes (spec 10)
//! and the object map (spec 23); it reads any object the map holds as an
//! [`Object`]: its type and handle, extended data, the common entity data
//! (spec 20.4.1 and 20.4.2), and the streams its own data, strings (R2007
//! on) and handles are read from. Nothing here says what an object means.
//!
//! Every offset, size and count a file gives is checked against the data it
//! claims to describe before it is used; what compressed sections expand to
//! is bounded by their declared sizes and by [`Dwg::open_with`]'s limit.
//!
//! As a container ([`crate::Format::Dwg`]), a drawing's members are its
//! preview images: `thumbnail.bmp` (the bitmap with a BMP file header put
//! before it; `thumbnail.dib` as stored when its own header is not one),
//! `thumbnail.wmf`, `thumbnail.png`, and `thumbnail-<code>.bin` for an entry
//! of another code; and the object each OLE2FRAME entity embeds,
//! `ole2frame-<HANDLE>.ole` from the compound file's signature on (`.bin`
//! when there is none). A drawing whose objects cannot be read gives an
//! unsupported `dwg-objects` entry, since what they embed was not examined;
//! a drawing of a release before R13 ([`pre_r13_version`]) an unsupported
//! `dwg-<version ID>` entry.

mod bits;
mod extract;
mod file;
mod object;
mod r2004;
mod r2007;

pub use bits::{BitError, BitResult, Bits, HandleRef};
pub use extract::bmp_file;
pub(crate) use extract::extract_dwg;
pub use file::{
    preview, trim_zeros, Class, Dwg, Locator, PreviewImage, PreviewKind, DEFAULT_MAX_BYTES,
};
pub use object::{Eed, EedValue, EntityColor, EntityCommon, HeaderStreams, Object, Text};

pub use super::codepage::Decoder;

/// The release a DWG file was saved as, from its first six bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Version {
    R13,
    R14,
    R2000,
    R2004,
    R2007,
    R2010,
    R2013,
    R2018,
}

impl Version {
    /// From the version ID at the start of the file (spec 3.2.1).
    pub fn from_magic(head: &[u8]) -> Option<Version> {
        Some(match head.get(..6)? {
            b"AC1012" => Version::R13,
            b"AC1014" => Version::R14,
            b"AC1015" => Version::R2000,
            b"AC1018" => Version::R2004,
            b"AC1021" => Version::R2007,
            b"AC1024" => Version::R2010,
            b"AC1027" => Version::R2013,
            b"AC1032" => Version::R2018,
            _ => return None,
        })
    }

    /// The version ID, as `$ACADVER` gives it.
    pub fn acadver(self) -> &'static str {
        match self {
            Version::R13 => "AC1012",
            Version::R14 => "AC1014",
            Version::R2000 => "AC1015",
            Version::R2004 => "AC1018",
            Version::R2007 => "AC1021",
            Version::R2010 => "AC1024",
            Version::R2013 => "AC1027",
            Version::R2018 => "AC1032",
        }
    }
}

/// Why a file could not be opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// No DWG file header.
    NotDwg,
    /// A release this reader does not read, by its version ID: one before
    /// R13 ([`pre_r13_version`]).
    UnsupportedVersion(String),
    /// The file header is there, the sections it locates are not.
    Damaged(String),
    /// The compressed sections expand past the limit [`Dwg::open_with`]
    /// was given.
    LimitExceeded(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotDwg => f.write_str("not a DWG file"),
            Error::UnsupportedVersion(v) => write!(f, "DWG version {v} is not supported"),
            Error::Damaged(why) => write!(f, "damaged DWG file: {why}"),
            Error::LimitExceeded(why) => write!(f, "DWG file past the size limit: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// Whether `head` is the start of a DWG file this module reads: a version
/// ID of R13 to R2000 and a file header whose section locators end with
/// their sentinel, of R2004, R2010, R2013 or R2018 and a file header whose
/// ID string decrypts (spec 4.1), or of R2007 and a file header that
/// decodes (spec 5.2), at 0x80 or as its copy at the end of `head`.
pub fn looks_like_dwg(head: &[u8]) -> bool {
    file::has_file_header(head)
}

/// The version ID of a DWG file of a release before R13 (`AC1009` for R11
/// and R12, `AC1004`, `AC2.10`...), which this module does not read.
///
/// The specification covers R13 on. What is checked is what every such
/// file seen has (227 of AC2.10, AC1002, AC1003, AC1004 and AC1009, and the
/// ODA File Converter's AC1009): the version ID, zeros to 0x0C,
/// `03 00 05 00` at 0x0D, and two offsets at 0x14 and 0x18 in order (the
/// first the same in every file of a release: 1743 for AC1009).
pub fn pre_r13_version(head: &[u8]) -> Option<&str> {
    let id = head.get(..6)?;
    let known = match id {
        [b'A', b'C', b'1', b'0', b'0', d] => (b'1'..=b'9').contains(d),
        [b'A', b'C', b'1', b'0', b'1', d] => (b'0'..=b'1').contains(d),
        [b'A', b'C', a, b'.', b, c] => {
            a.is_ascii_digit() && b.is_ascii_digit() && (c.is_ascii_digit() || *c == 0)
        }
        _ => false,
    };
    let le32 = |at: usize| -> Option<u32> {
        let b = crate::bytes::at(head, at, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let shaped = head.get(6..12)? == [0; 6]
        && head.get(0x0D..0x11)? == [3, 0, 5, 0]
        && le32(0x14)? <= le32(0x18)?;
    if !(known && shaped) {
        return None;
    }
    std::str::from_utf8(trim_zeros(id)).ok()
}

/// `$DWGCODEPAGE`'s name for the code page number at 0x13 of the file.
///
/// The specification does not list the numbers. These are what the ODA
/// File Converter 27.9 writes as `$DWGCODEPAGE` when converting an R2000
/// file whose number (and file header CRC) was patched to each value: 46
/// and above made it write no name.
pub fn code_page_name(number: u16) -> Option<&'static str> {
    const NAMES: [&str; 46] = [
        "UNDEFINED",
        "ASCII",
        "ISO8859-1",
        "ISO8859-2",
        "ISO8859-3",
        "ISO8859-4",
        "ISO8859-5",
        "ISO8859-6",
        "ISO8859-7",
        "ISO8859-8",
        "ISO8859-9",
        "DOS437",
        "DOS850",
        "DOS852",
        "DOS855",
        "DOS857",
        "DOS860",
        "DOS861",
        "DOS863",
        "DOS864",
        "DOS865",
        "DOS869",
        "DOS932",
        "MAC-ROMAN",
        "BIG5",
        "KSC5601",
        "JOHAB",
        "DOS866",
        "ANSI_1250",
        "ANSI_1251",
        "ANSI_1252",
        "GB2312",
        "ANSI_1253",
        "ANSI_1254",
        "ANSI_1255",
        "ANSI_1256",
        "ANSI_1257",
        "ANSI_874",
        "ANSI_932",
        "ANSI_936",
        "ANSI_949",
        "ANSI_950",
        "ANSI_1361",
        "ANSI_1200",
        "ANSI_1258",
        "CNT",
    ];
    NAMES.get(usize::from(number)).copied()
}

/// The DXF record name of a fixed object type (spec 20.3); `None` for the
/// types numbered by class (500 on) and the unused numbers.
pub fn fixed_type_name(type_code: u16) -> Option<&'static str> {
    Some(match type_code {
        0x01 => "TEXT",
        0x02 => "ATTRIB",
        0x03 => "ATTDEF",
        0x04 => "BLOCK",
        0x05 => "ENDBLK",
        0x06 => "SEQEND",
        0x07 | 0x08 => "INSERT",
        0x0A..=0x0E => "VERTEX",
        0x0F | 0x10 | 0x1D | 0x1E => "POLYLINE",
        0x11 => "ARC",
        0x12 => "CIRCLE",
        0x13 => "LINE",
        0x14..=0x1A => "DIMENSION",
        0x1B => "POINT",
        0x1C => "3DFACE",
        0x1F => "SOLID",
        0x20 => "TRACE",
        0x21 => "SHAPE",
        0x22 => "VIEWPORT",
        0x23 => "ELLIPSE",
        0x24 => "SPLINE",
        0x25 => "REGION",
        0x26 => "3DSOLID",
        0x27 => "BODY",
        0x28 => "RAY",
        0x29 => "XLINE",
        0x2A => "DICTIONARY",
        0x2B => "OLEFRAME",
        0x2C => "MTEXT",
        0x2D => "LEADER",
        0x2E => "TOLERANCE",
        0x2F => "MLINE",
        0x30 => "BLOCK_CONTROL",
        0x31 => "BLOCK_RECORD",
        0x32 => "LAYER_CONTROL",
        0x33 => "LAYER",
        0x34 => "STYLE_CONTROL",
        0x35 => "STYLE",
        0x38 => "LTYPE_CONTROL",
        0x39 => "LTYPE",
        0x3C => "VIEW_CONTROL",
        0x3D => "VIEW",
        0x3E => "UCS_CONTROL",
        0x3F => "UCS",
        0x40 => "VPORT_CONTROL",
        0x41 => "VPORT",
        0x42 => "APPID_CONTROL",
        0x43 => "APPID",
        0x44 => "DIMSTYLE_CONTROL",
        0x45 => "DIMSTYLE",
        0x46 => "VP_ENT_HDR_CONTROL",
        0x47 => "VP_ENT_HDR",
        0x48 => "GROUP",
        0x49 => "MLINESTYLE",
        0x4A => "OLE2FRAME",
        0x4B => "DUMMY",
        0x4C => "LONG_TRANSACTION",
        0x4D => "LWPOLYLINE",
        0x4E => "HATCH",
        0x4F => "XRECORD",
        0x50 => "ACDBPLACEHOLDER",
        0x51 => "VBA_PROJECT",
        0x52 => "LAYOUT",
        0x1F2 => "ACAD_PROXY_ENTITY",
        0x1F3 => "ACAD_PROXY_OBJECT",
        _ => return None,
    })
}

/// Whether a fixed object type is an entity; `None` for the types numbered
/// by class, whose class says.
pub fn fixed_type_is_entity(type_code: u16) -> Option<bool> {
    match type_code {
        0x01..=0x29 | 0x2B..=0x2F | 0x4A | 0x4D | 0x4E | 0x1F2 => Some(true),
        0x2A | 0x30..=0x49 | 0x4B | 0x4C | 0x4F..=0x52 | 0x1F3 => Some(false),
        _ if type_code >= 500 => None,
        _ => Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_come_from_the_first_six_bytes() {
        assert_eq!(Version::from_magic(b"AC1015\0\0"), Some(Version::R2000));
        assert_eq!(Version::from_magic(b"AC1009"), None);
        assert_eq!(Version::from_magic(b"AC10"), None);
        assert!(Version::R13 < Version::R2018);
    }

    #[test]
    fn a_version_id_alone_is_not_a_dwg() {
        assert!(!looks_like_dwg(b"AC1015 is the version of a DWG file"));
        assert!(!looks_like_dwg(b""));
    }
}
