//! AutoCAD DXF, ASCII and binary, R12 to 2018: the file's pairs, records and
//! strings, for a reader of drawings to build on (exav-render's), and the
//! payloads a drawing embeds, for the scanner.
//!
//! A DXF file is a list of pairs, a group code and a value whose type the
//! code decides (DXF reference, "Group Code Value Types"). [`Tags`] reads
//! them from either form; [`Records`] groups them from one group code 0 to
//! the next (an entity, an object, a table entry, a section marker); [`Parts`]
//! splits one record into its application groups (102), extended data (from
//! 1001) and subclasses (100). [`Decoder`] turns a string value into UTF-8 in
//! the drawing's code page. Nothing here interprets a drawing: what each code
//! means in each record is the reader's business.
//!
//! Every read is bounded by the data: a count a file declares is never used
//! to allocate, and a value that would run past the end stops the reading
//! with [`Stop::Truncated`].
//!
//! As a container ([`crate::Format::Dxf`]), a drawing's members are the
//! files it carries in binary chunks (group 310): the object an OLE2FRAME
//! embeds (`ole2frame-<handle>.ole`, the OLE2 compound file, or `.bin` when
//! the data holds none), and any other record's or the preview image's chunk
//! data that is a whole file of a known kind (`<type>-<handle>.<ext>`,
//! `thumbnail.<ext>`).

mod extract;
mod pairs;
mod parts;
mod records;

pub(crate) use extract::extract_dxf;
pub use pairs::{Stop, Tag, Tags, Value, BINARY_SENTINEL};
pub use parts::Parts;
pub use records::{Record, Records};

pub use super::codepage::Decoder;

/// Whether `head` starts like a DXF file: the binary sentinel, or a group
/// code 0 `SECTION` pair, after comments (999), blank lines or a UTF-8 byte
/// order mark.
pub fn looks_like_dxf(head: &[u8]) -> bool {
    if head.starts_with(BINARY_SENTINEL) {
        return true;
    }
    for tag in Tags::new(head) {
        match tag.code {
            999 => continue,
            0 => return tag.is("SECTION"),
            _ => return false,
        }
    }
    false
}

/// Bounds for a reader of drawings built on this module: what it should
/// refuse to hold, whatever the file says.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Entities in the whole drawing, block contents included.
    pub max_entities: usize,
    /// Vertices, knots, boundary edges or other repeated items in one entity
    /// or object.
    pub max_items: usize,
    /// Bytes in one string, after joining the chunks of an MTEXT.
    pub max_string_bytes: usize,
    /// Warnings kept.
    pub max_warnings: usize,
    /// Bytes the compressed sections of a DWG file (R2004 on) may
    /// decompress to, all together.
    pub max_decompressed_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_entities: 8_000_000,
            max_items: 4_000_000,
            max_string_bytes: 1 << 20,
            max_warnings: 1000,
            max_decompressed_bytes: 1 << 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dxf_is_told_apart_by_its_first_pairs() {
        assert!(looks_like_dxf(b"  0\r\nSECTION\r\n  2\r\nHEADER\r\n"));
        assert!(looks_like_dxf(b"999\nmade by hand\n0\nSECTION\n"));
        assert!(looks_like_dxf(b"\xEF\xBB\xBF0\nSECTION\n"));
        assert!(looks_like_dxf(b"AutoCAD Binary DXF\r\n\x1a\0rest"));
        assert!(!looks_like_dxf(b"0\nSECTIONS\n"));
        assert!(!looks_like_dxf(b"1\nSECTION\n"));
        assert!(!looks_like_dxf(b"%PDF-1.7"));
        assert!(!looks_like_dxf(b""));
    }
}
