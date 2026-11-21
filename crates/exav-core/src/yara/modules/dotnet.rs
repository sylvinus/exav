//! The `dotnet` module: .NET assembly metadata.
//!
//! Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X. Field
//! semantics follow yara-x's `lib/src/modules/dotnet/`, and every value here was
//! diffed against `yr dump --module dotnet` on real assemblies.
//!
//! A .NET assembly is a PE whose COM descriptor directory points at a CLI
//! header, which points at a metadata root. That root holds a handful of named
//! streams:
//!
//! ```text
//! #~        the metadata tables (Module, TypeDef, AssemblyRef, ...)
//! #Strings  NUL-terminated UTF-8, referenced by index from the tables
//! #US       user strings, length-prefixed UTF-16
//! #GUID     a flat array of 16-byte GUIDs
//! #Blob     length-prefixed binary, e.g. constant values and public keys
//! ```
//!
//! Only the fields listed in [`validate_access`] are implemented; any other
//! `dotnet.*` field is an explicit compile error, so a rule that needs something
//! missing is rejected and **counted** rather than silently evaluating against
//! an undefined value. `dotnet.classes` is the notable gap: it needs the
//! TypeDef/MethodDef/Param tables plus signature decoding, which is a piece of
//! work in its own right.

use std::rc::Rc;

use super::{Copies, FieldName};
use crate::yara::error::{Error, Result};
use crate::yara::ir::{Fields, Value};

/// `BSJB`, the metadata root signature.
const METADATA_MAGIC: u32 = 0x424A_5342;
/// Data directory index 14 is the CLI header ("COM descriptor").
const COM_DESCRIPTOR_DIR: usize = 14;

/// Table identifiers used here.
const T_MODULE: usize = 0x00;
const T_TYPEDEF: usize = 0x02;
const T_FIELD: usize = 0x04;
const T_METHODDEF: usize = 0x06;
const T_PARAM: usize = 0x08;
const T_INTERFACEIMPL: usize = 0x09;
const T_MEMBERREF: usize = 0x0A;
const T_CONSTANT: usize = 0x0B;
const T_CUSTOMATTRIBUTE: usize = 0x0C;
const T_FIELDMARSHAL: usize = 0x0D;
const T_DECLSECURITY: usize = 0x0E;
const T_CLASSLAYOUT: usize = 0x0F;
const T_FIELDLAYOUT: usize = 0x10;
const T_STANDALONESIG: usize = 0x11;
const T_EVENTMAP: usize = 0x12;
const T_EVENT: usize = 0x14;
const T_PROPERTYMAP: usize = 0x15;
const T_PROPERTY: usize = 0x17;
const T_METHODSEMANTICS: usize = 0x18;
const T_METHODIMPL: usize = 0x19;
const T_MODULEREF: usize = 0x1A;
const T_TYPESPEC: usize = 0x1B;
const T_IMPLMAP: usize = 0x1C;
const T_FIELDRVA: usize = 0x1D;
const T_ASSEMBLY: usize = 0x20;
const T_ASSEMBLYREF: usize = 0x23;
const T_FILE: usize = 0x26;
const T_EXPORTEDTYPE: usize = 0x27;
const T_MANIFESTRESOURCE: usize = 0x28;
const T_NESTEDCLASS: usize = 0x29;
const T_GENERICPARAM: usize = 0x2A;
const T_METHODSPEC: usize = 0x2B;
const T_GENERICPARAMCONSTRAINT: usize = 0x2C;
const T_TYPEREF: usize = 0x01;

/// `ELEMENT_TYPE_STRING`, the Constant table's type byte for a string literal.
const ELEMENT_TYPE_STRING: u8 = 0x0E;

/// Whether `b` is an `ELEMENT_TYPE_*` value of ECMA-335, as the type byte of a
/// Constant row has to be.
fn is_element_type(b: u8) -> bool {
    matches!(b, 0x00..=0x16 | 0x18 | 0x19 | 0x1B..=0x21 | 0x40 | 0x41 | 0x45)
}

const MAX_TABLES: usize = 64;

/// The size of the CLI header, its first field.
const CLI_HEADER_SIZE: u32 = 0x48;

/// The longest version string of the metadata root that yara-x accepts.
const MAX_VERSION_LEN: usize = 255;

/// yara-x reads no more rows than this from a table, and lays the tables
/// out, and sizes the indexes, as if the table had no more.
const MAX_ROWS: u32 = 15_000;

fn le_u16(d: &[u8], off: usize) -> u16 {
    off.checked_add(2)
        .and_then(|end| d.get(off..end))
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

fn le_u32(d: &[u8], off: usize) -> u32 {
    off.checked_add(4)
        .and_then(|end| d.get(off..end))
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Building the module value tree
// ---------------------------------------------------------------------------

/// Parses `data` and returns the `dotnet` root value. Anything that is not a
/// .NET assembly yields `is_dotnet: false` with no other field set, so each
/// reads as undefined — YARA's behaviour — rather than as a wrong value.
///
/// The strings and blobs of the heaps are charged to `copies` as they are
/// copied for a row, and from the first that does not fit they read as empty:
/// many rows can index one long string.
pub(crate) fn build(data: &[u8], copies: &Copies) -> Value {
    match Meta::parse(data, copies) {
        Some(m) => m.build(),
        None => {
            let mut f = Fields::new();
            f.insert("is_dotnet".into(), Value::Bool(false));
            Value::Struct(Rc::new(f))
        }
    }
}

/// The most section headers yara-x reads.
const MAX_SECTIONS: usize = 96;

/// What the module reads of the PE headers.
struct PeHeaders {
    sections: Vec<goblin::pe::section_table::SectionTable>,
    file_alignment: u32,
    section_alignment: u32,
    /// The RVA of the CLI header, the data directory 14.
    cli_rva: u32,
}

/// The PE headers as yara-x reads them: the optional header is PE32+ only
/// for the magic 0x20B and has as many data directories as the file has
/// room for, whatever it says; at most [`MAX_SECTIONS`] section headers,
/// those that are whole in the file.
fn read_headers(data: &[u8]) -> Option<PeHeaders> {
    use goblin::pe::section_table::SectionTable;
    let pe = goblin::pe::header::DosHeader::parse(data).ok()?.pe_pointer as usize;
    if data.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let coff = pe + 4;
    let sections_count = usize::from(le_u16(data, coff + 2));
    let optional = coff + 20;
    let size_of_optional = usize::from(le_u16(data, coff + 16));
    let directories = optional
        + if le_u16(data, optional) == 0x20B {
            112
        } else {
            96
        };
    let cli = directories + COM_DESCRIPTOR_DIR * 8;
    let mut headers = PeHeaders {
        sections: Vec::new(),
        file_alignment: le_u32(data, optional + 36),
        section_alignment: le_u32(data, optional + 32),
        cli_rva: u32::from_le_bytes(*data.get(cli..)?.first_chunk::<4>()?),
    };
    let first = optional.checked_add(size_of_optional)?;
    for i in 0..sections_count.min(MAX_SECTIONS) {
        let Some(h) = first
            .checked_add(i * 40)
            .and_then(|at| data.get(at..)?.first_chunk::<40>())
        else {
            break;
        };
        let word = |i: usize| u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
        headers.sections.push(SectionTable {
            virtual_size: word(8),
            virtual_address: word(12),
            size_of_raw_data: word(16),
            pointer_to_raw_data: word(20),
            ..Default::default()
        });
    }
    Some(headers)
}

/// One named stream in the metadata root.
struct Stream {
    /// `None` for a name that is not UTF-8.
    name: Option<String>,
    offset: u32,
    size: u32,
}

/// The parsed metadata: the streams, the table row counts, and the widths that
/// index sizes depend on.
struct Meta<'a> {
    data: &'a [u8],
    copies: &'a Copies,
    /// Offset of the metadata root within the file.
    root: usize,
    version: String,
    streams: Vec<Stream>,
    strings: &'a [u8],
    blobs: &'a [u8],
    guids: &'a [u8],
    us: &'a [u8],
    /// Row count per table, indexed by table number.
    rows: [u32; MAX_TABLES],
    /// Byte offset of each table's first row within `tables`.
    table_at: [usize; MAX_TABLES],
    tables: &'a [u8],
    /// yara-x reads the tables in order and gives up at the first that does
    /// not parse: the tables from this number on read as absent.
    stop: usize,
    wide_str: bool,
    wide_guid: bool,
    wide_blob: bool,
    /// What converts an RVA to a file offset, as yara-x does.
    sections: Vec<goblin::pe::section_table::SectionTable>,
    file_alignment: u32,
    section_alignment: u32,
    /// The RVA and the size of the managed resources, from the CLI header.
    resources_rva: u32,
    resources_size: u32,
}

impl<'a> Meta<'a> {
    fn parse(data: &'a [u8], copies: &'a Copies) -> Option<Meta<'a>> {
        let PeHeaders {
            sections,
            file_alignment,
            section_alignment,
            cli_rva,
        } = read_headers(data)?;
        // yara-x converts RVAs here as in its `pe` module.
        let rva_to_offset = |rva: u32| {
            crate::pe::yarax_offset(rva, &sections, file_alignment, section_alignment)
                .map(|offset| offset as usize)
        };
        let cli = rva_to_offset(cli_rva)?;
        // The CLI header starts with its size, which is 0x48.
        if le_u32(data, cli) != CLI_HEADER_SIZE {
            return None;
        }
        // Its `MetaData` directory: the RVA at offset 8, the size at 12.
        // yara-x reads the root and the list of streams only inside it.
        let md_rva = le_u32(data, cli + 8);
        let md_size = le_u32(data, cli + 12) as usize;
        let root = rva_to_offset(md_rva)?;
        let window = data.get(root..)?;
        let window = &window[..window.len().min(md_size)];
        if le_u32(window, 0) != METADATA_MAGIC {
            return None;
        }

        // Root: signature, major, minor, reserved, then a length-prefixed
        // version string. The streams start right after its stated length,
        // which is not rounded up.
        let vlen = le_u32(window, 12) as usize;
        if vlen > MAX_VERSION_LEN {
            return None;
        }
        let vbytes = window.get(16..)?.get(..vlen)?;
        let version = std::str::from_utf8(
            &vbytes[..vbytes.iter().position(|&b| b == 0).unwrap_or(vbytes.len())],
        )
        .ok()?
        .to_owned();
        // Flags and the number of streams, then one entry per stream.
        let list = window.get(16 + vlen..)?;
        let n_streams = usize::from(le_u16(list.get(..4)?, 2));

        let mut streams = Vec::with_capacity(n_streams.min(64));
        let mut p = 4;
        for _ in 0..n_streams {
            let entry = list.get(p..)?;
            let offset = le_u32(entry.get(..8)?, 0);
            let size = le_u32(entry, 4);
            let name = entry.get(8..)?;
            let len = name.iter().position(|&b| b == 0)?;
            // Names are NUL-terminated and padded to four bytes.
            let padded = (len + 1).next_multiple_of(4);
            name.get(..padded)?;
            let name = std::str::from_utf8(&name[..len]).ok().map(String::from);
            streams.push(Stream { name, offset, size });
            p += 8 + padded;
        }

        let heap = |n: &str| -> &'a [u8] {
            // With two streams of one name, the last is the one yara-x reads.
            streams
                .iter()
                .rev()
                .find(|s| s.name.as_deref() == Some(n))
                .and_then(|s| {
                    let a = root.checked_add(s.offset as usize)?;
                    data.get(a..a.checked_add(s.size as usize)?)
                })
                .unwrap_or(&[])
        };
        let strings = heap("#Strings");
        let blobs = heap("#Blob");
        let guids = heap("#GUID");
        let us = heap("#US");
        // The table stream is `#~` normally and `#-` in unoptimised metadata.
        let tilde = if streams.iter().any(|s| s.name.as_deref() == Some("#~")) {
            heap("#~")
        } else {
            heap("#-")
        };

        // `#~` header: reserved, major, minor, heap-size flags, reserved, then
        // the valid/sorted bitmaps and one row count per valid table. Without
        // the whole header the assembly is still one, with no tables.
        let mut heap_sizes = 0;
        let mut rows = [0u32; MAX_TABLES];
        let mut tables: &[u8] = &[];
        if tilde.len() >= 24 {
            heap_sizes = tilde[6];
            let valid = u64::from_le_bytes(tilde.get(8..16)?.try_into().ok()?);
            let mut p = 24;
            for (i, r) in rows.iter_mut().enumerate() {
                if valid & (1u64 << i) != 0 {
                    *r = le_u32(tilde, p).min(MAX_ROWS);
                    p += 4;
                }
            }
            tables = tilde.get(p..).unwrap_or(&[]);
        }

        let mut m = Meta {
            data,
            copies,
            root,
            version,
            streams,
            strings,
            blobs,
            guids,
            us,
            rows,
            table_at: [0; MAX_TABLES],
            tables,
            stop: MAX_TABLES,
            wide_str: heap_sizes & 0x01 != 0,
            wide_guid: heap_sizes & 0x02 != 0,
            wide_blob: heap_sizes & 0x04 != 0,
            sections,
            file_alignment,
            section_alignment,
            // The `Resources` directory of the CLI header is at offset 24.
            resources_rva: le_u32(data, cli + 24),
            resources_size: le_u32(data, cli + 28),
        };
        m.locate_tables();
        Some(m)
    }

    /// The file offset of `rva`, as yara-x converts it.
    fn file_offset(&self, rva: u32) -> Option<i64> {
        crate::pe::yarax_offset(
            rva,
            &self.sections,
            self.file_alignment,
            self.section_alignment,
        )
        .map(i64::from)
    }

    /// Row sizes depend on how many rows every *other* table has, so the layout
    /// has to be computed before any row can be read.
    fn locate_tables(&mut self) {
        let mut at = 0usize;
        for t in 0..MAX_TABLES {
            self.table_at[t] = at;
            at = at.saturating_add((self.rows[t] as usize).saturating_mul(self.row_size(t)));
        }
        // Past ManifestResource no table gives a value.
        self.stop = (0..=T_MANIFESTRESOURCE)
            .find(|&t| !self.table_parses(t))
            .unwrap_or(MAX_TABLES);
    }

    /// Whether yara-x reads table `t`: all its rows are in the stream, and
    /// each coded index has a tag that names one of the tables it can point at.
    fn table_parses(&self, t: usize) -> bool {
        let rows = self.rows[t] as usize;
        let size = self.row_size(t);
        if rows == 0 || size == 0 {
            return true;
        }
        let at = self.table_at[t];
        let Some(body) = rows
            .checked_mul(size)
            .and_then(|n| self.tables.get(at..at.checked_add(n)?))
        else {
            return false;
        };
        let s = self.str_w();
        // (offset, width, tag bits, number of tags that name a table)
        let (def_or_ref, implementation) = (self.type_def_or_ref(), self.implementation());
        let columns: &[(usize, usize, u32, u32)] = match t {
            T_TYPEDEF => &[(4 + 2 * s, def_or_ref, 2, 3)],
            T_INTERFACEIMPL => &[(self.idx_w(T_TYPEDEF), def_or_ref, 2, 3)],
            T_MEMBERREF => &[(0, self.member_ref_parent(), 3, 5)],
            T_CONSTANT => &[(2, self.has_constant(), 2, 3)],
            T_CUSTOMATTRIBUTE => &[
                (0, self.has_custom_attribute(), 5, 22),
                (
                    self.has_custom_attribute(),
                    self.custom_attribute_type(),
                    3,
                    5,
                ),
            ],
            T_DECLSECURITY => &[(2, self.has_decl_security(), 2, 3)],
            T_EVENT => &[(2 + s, def_or_ref, 2, 3)],
            T_EXPORTEDTYPE => &[(8 + 2 * s, implementation, 2, 3)],
            T_MANIFESTRESOURCE => &[(8 + s, implementation, 2, 3)],
            _ => &[],
        };
        body.chunks_exact(size).all(|row| {
            (t != T_CONSTANT || is_element_type(row[0]))
                && columns
                    .iter()
                    .all(|&(off, w, bits, n)| self.idx(row, off, w) & ((1 << bits) - 1) < n)
        })
    }

    fn str_w(&self) -> usize {
        if self.wide_str { 4 } else { 2 }
    }
    fn guid_w(&self) -> usize {
        if self.wide_guid { 4 } else { 2 }
    }
    fn blob_w(&self) -> usize {
        if self.wide_blob { 4 } else { 2 }
    }

    /// A simple index into one table: two bytes unless that table is large.
    fn idx_w(&self, table: usize) -> usize {
        if self.rows[table] >= 1 << 16 { 4 } else { 2 }
    }

    /// A coded index packs a table tag into the low bits, so it widens once any
    /// of the tables it can point at is large enough. yara-x widens it above
    /// `2^(16 - tag_bits)` rows, one more than the format says.
    fn coded_w(&self, tables: &[usize], tag_bits: u32) -> usize {
        let max = tables.iter().map(|&t| self.rows[t]).max().unwrap_or(0);
        if (max as u64) > (1u64 << (16 - tag_bits)) {
            4
        } else {
            2
        }
    }

    fn type_def_or_ref(&self) -> usize {
        self.coded_w(&[T_TYPEDEF, T_TYPEREF, T_TYPESPEC], 2)
    }
    fn has_constant(&self) -> usize {
        self.coded_w(&[T_FIELD, T_PARAM, T_PROPERTY], 2)
    }
    fn has_custom_attribute(&self) -> usize {
        self.coded_w(
            &[
                T_METHODDEF,
                T_FIELD,
                T_TYPEREF,
                T_TYPEDEF,
                T_PARAM,
                T_INTERFACEIMPL,
                T_MEMBERREF,
                T_MODULE,
                T_DECLSECURITY,
                T_PROPERTY,
                T_EVENT,
                T_STANDALONESIG,
                T_MODULEREF,
                T_TYPESPEC,
                T_ASSEMBLY,
                T_ASSEMBLYREF,
                T_FILE,
                T_EXPORTEDTYPE,
                T_MANIFESTRESOURCE,
                T_GENERICPARAM,
                T_GENERICPARAMCONSTRAINT,
                T_METHODSPEC,
            ],
            5,
        )
    }
    fn has_field_marshal(&self) -> usize {
        self.coded_w(&[T_FIELD, T_PARAM], 1)
    }
    fn has_decl_security(&self) -> usize {
        self.coded_w(&[T_TYPEDEF, T_METHODDEF, T_ASSEMBLY], 2)
    }
    fn member_ref_parent(&self) -> usize {
        self.coded_w(
            &[T_TYPEDEF, T_TYPEREF, T_MODULEREF, T_METHODDEF, T_TYPESPEC],
            3,
        )
    }
    fn has_semantics(&self) -> usize {
        self.coded_w(&[T_EVENT, T_PROPERTY], 1)
    }
    fn method_def_or_ref(&self) -> usize {
        self.coded_w(&[T_METHODDEF, T_MEMBERREF], 1)
    }
    fn member_forwarded(&self) -> usize {
        self.coded_w(&[T_FIELD, T_METHODDEF], 1)
    }
    fn implementation(&self) -> usize {
        self.coded_w(&[T_FILE, T_ASSEMBLYREF, T_EXPORTEDTYPE], 2)
    }
    fn custom_attribute_type(&self) -> usize {
        self.coded_w(&[T_METHODDEF, T_MEMBERREF], 3)
    }
    fn resolution_scope(&self) -> usize {
        self.coded_w(&[T_MODULE, T_MODULEREF, T_ASSEMBLYREF, T_TYPEREF], 2)
    }
    fn type_or_method_def(&self) -> usize {
        self.coded_w(&[T_TYPEDEF, T_METHODDEF], 1)
    }

    /// Bytes per row for one table. Every table has to be sized, even the ones
    /// this module never reads, because the ones it does read sit after them.
    fn row_size(&self, t: usize) -> usize {
        let (s, g, b) = (self.str_w(), self.guid_w(), self.blob_w());
        match t {
            T_MODULE => 2 + s + g * 3,
            T_TYPEREF => self.resolution_scope() + s * 2,
            T_TYPEDEF => {
                4 + s * 2 + self.type_def_or_ref() + self.idx_w(T_FIELD) + self.idx_w(T_METHODDEF)
            }
            0x03 => 2 + self.idx_w(T_FIELD), // FieldPtr
            T_FIELD => 2 + s + b,
            0x05 => 2 + self.idx_w(T_METHODDEF), // MethodPtr
            T_METHODDEF => 8 + s + b + self.idx_w(T_PARAM),
            0x07 => 2 + self.idx_w(T_PARAM), // ParamPtr
            T_PARAM => 4 + s,
            T_INTERFACEIMPL => self.idx_w(T_TYPEDEF) + self.type_def_or_ref(),
            T_MEMBERREF => self.member_ref_parent() + s + b,
            T_CONSTANT => 2 + self.has_constant() + b,
            T_CUSTOMATTRIBUTE => self.has_custom_attribute() + self.custom_attribute_type() + b,
            T_FIELDMARSHAL => self.has_field_marshal() + b,
            T_DECLSECURITY => 2 + self.has_decl_security() + b,
            T_CLASSLAYOUT => 6 + self.idx_w(T_TYPEDEF),
            T_FIELDLAYOUT => 4 + self.idx_w(T_FIELD),
            T_STANDALONESIG => b,
            T_EVENTMAP => self.idx_w(T_TYPEDEF) + self.idx_w(T_EVENT),
            0x13 => 2 + self.idx_w(T_EVENT), // EventPtr
            T_EVENT => 2 + s + self.type_def_or_ref(),
            T_PROPERTYMAP => self.idx_w(T_TYPEDEF) + self.idx_w(T_PROPERTY),
            0x16 => 2 + self.idx_w(T_PROPERTY), // PropertyPtr
            T_PROPERTY => 2 + s + b,
            T_METHODSEMANTICS => 2 + self.idx_w(T_METHODDEF) + self.has_semantics(),
            T_METHODIMPL => self.idx_w(T_TYPEDEF) + self.method_def_or_ref() * 2,
            T_MODULEREF => s,
            T_TYPESPEC => b,
            T_IMPLMAP => 2 + self.member_forwarded() + s + self.idx_w(T_MODULEREF),
            T_FIELDRVA => 4 + self.idx_w(T_FIELD),
            0x1E => 8, // ENCLog
            0x1F => 4, // ENCMap
            T_ASSEMBLY => 16 + b + s * 2,
            0x21 => 4,  // AssemblyProcessor
            0x22 => 12, // AssemblyOS
            T_ASSEMBLYREF => 12 + b * 2 + s * 2,
            0x24 => 4 + self.idx_w(T_ASSEMBLYREF),
            0x25 => 12 + self.idx_w(T_ASSEMBLYREF),
            T_FILE => 4 + s + b,
            T_EXPORTEDTYPE => 8 + s * 2 + self.implementation(),
            T_MANIFESTRESOURCE => 8 + s + self.implementation(),
            T_NESTEDCLASS => self.idx_w(T_TYPEDEF) * 2,
            T_GENERICPARAM => 4 + self.type_or_method_def() + s,
            T_METHODSPEC => self.method_def_or_ref() + b,
            T_GENERICPARAMCONSTRAINT => self.idx_w(T_GENERICPARAM) + self.type_def_or_ref(),
            _ => 0,
        }
    }

    /// The bytes of row `i` (zero-based) of table `t`.
    fn row(&self, t: usize, i: u32) -> Option<&'a [u8]> {
        if t >= self.stop || i >= self.rows[t] {
            return None;
        }
        let sz = self.row_size(t);
        let at = self.table_at[t].saturating_add((i as usize).saturating_mul(sz));
        self.tables.get(at..at.checked_add(sz)?)
    }

    /// Read an index of `w` bytes at `off`.
    fn idx(&self, row: &[u8], off: usize, w: usize) -> u32 {
        if w == 4 {
            le_u32(row, off)
        } else {
            le_u16(row, off) as u32
        }
    }

    /// A NUL-terminated string from `#Strings`, `None` if the index is not in
    /// the heap, no NUL ends the string before the heap does, or it is not
    /// UTF-8. Empty once the copies have used up their room.
    fn string(&self, i: u32) -> Option<Vec<u8>> {
        let s = self.strings.get(i as usize..)?;
        let end = s.iter().position(|&b| b == 0)?;
        if !self.copies.take(end) {
            return Some(Vec::new());
        }
        std::str::from_utf8(&s[..end]).ok()?;
        Some(s[..end].to_vec())
    }

    /// A length-prefixed blob from `#Blob`, minus its prefix; `None` if the
    /// index, the length or the blob is not in the heap. Empty once the
    /// copies have used up their room.
    fn blob(&self, i: u32) -> Option<Vec<u8>> {
        let s = self.blobs.get(i as usize..)?;
        let (len, hdr) = compressed_uint(s)?;
        let blob = s.get(hdr..hdr.checked_add(len as usize)?)?;
        Some(if self.copies.take(blob.len()) {
            blob.to_vec()
        } else {
            Vec::new()
        })
    }

    fn build(&self) -> Value {
        let mut f = Fields::new();
        f.insert("is_dotnet".into(), Value::Bool(true));
        f.insert(
            "version".into(),
            Value::Str(self.version.as_bytes().to_vec()),
        );

        // Module: generation, name, mvid, encid, encbaseid.
        if let Some(r) = self.row(T_MODULE, 0) {
            let name = self.idx(r, 2, self.str_w());
            if let Some(name) = self.string(name) {
                f.insert("module_name".into(), Value::Str(name));
            }
        }

        let mut streams = Vec::with_capacity(self.streams.len());
        for s in &self.streams {
            let mut v = Fields::new();
            if let Some(name) = &s.name {
                v.insert("name".into(), Value::Str(name.as_bytes().to_vec()));
            }
            // Stream offsets are relative to the metadata root; yara-x reports
            // them as file offsets.
            v.insert(
                "offset".into(),
                Value::Int((self.root as i64) + s.offset as i64),
            );
            v.insert("size".into(), Value::Int(s.size as i64));
            streams.push(Value::Struct(Rc::new(v)));
        }
        f.insert("number_of_streams".into(), Value::Int(streams.len() as i64));
        f.insert("streams".into(), Value::Array(Rc::new(streams)));

        let guids: Vec<Value> = self
            .guids
            .as_chunks::<16>()
            .0
            .iter()
            .map(|g| Value::Str(format_guid(g).into_bytes()))
            .collect();
        f.insert("number_of_guids".into(), Value::Int(guids.len() as i64));
        f.insert("guids".into(), Value::Array(Rc::new(guids)));

        // User strings: the `#US` heap is a run of length-prefixed UTF-16
        // values, normally after a leading empty one.
        let mut user_strings = Vec::new();
        let mut p = 0usize;
        while p < self.us.len() {
            // A length that is not valid ends the list, keeping what was read.
            let Some((len, hdr)) = compressed_uint(&self.us[p..]) else {
                break;
            };
            let start = p + hdr;
            // An entry that does not fit in the stream voids the whole list.
            let Some(next) = start
                .checked_add(len as usize)
                .filter(|&next| next <= self.us.len())
            else {
                user_strings.clear();
                break;
            };
            // The last byte of an entry is a flag rather than character data.
            // YARA keeps the entries with at least two bytes of characters
            // and none of the shorter ones.
            if len >= 3 {
                user_strings.push(Value::Str(self.us[start..next - 1].to_vec()));
            }
            p = next;
        }
        f.insert(
            "number_of_user_strings".into(),
            Value::Int(user_strings.len() as i64),
        );
        f.insert("user_strings".into(), Value::Array(Rc::new(user_strings)));

        // Constants: the *string* rows of the Constant table. The table also
        // holds numeric literals — 568 rows here against 95 strings — and YARA
        // exposes only the strings, since that is what a rule looks for.
        let mut constants = Vec::new();
        for i in 0..self.rows[T_CONSTANT] {
            let Some(r) = self.row(T_CONSTANT, i) else {
                break;
            };
            if r.first() != Some(&ELEMENT_TYPE_STRING) {
                continue;
            }
            let b = self.idx(r, 2 + self.has_constant(), self.blob_w());
            // A row whose value is not in the heap has no entry.
            if let Some(value) = self.blob(b) {
                constants.push(Value::Str(value));
            }
        }
        f.insert(
            "number_of_constants".into(),
            Value::Int(constants.len() as i64),
        );
        f.insert("constants".into(), Value::Array(Rc::new(constants)));

        // ModuleRef: a single name index.
        let mut modulerefs = Vec::new();
        for i in 0..self.rows[T_MODULEREF] {
            let Some(r) = self.row(T_MODULEREF, i) else {
                break;
            };
            if let Some(name) = self.string(self.idx(r, 0, self.str_w())) {
                modulerefs.push(Value::Str(name));
            }
        }
        f.insert(
            "number_of_modulerefs".into(),
            Value::Int(modulerefs.len() as i64),
        );
        f.insert("modulerefs".into(), Value::Array(Rc::new(modulerefs)));

        // Assembly: version, flags, public key, name, culture.
        if let Some(r) = self.row(T_ASSEMBLY, 0) {
            let mut a = Fields::new();
            if let Some(name) = self.string(self.idx(r, 16 + self.blob_w(), self.str_w())) {
                a.insert("name".into(), Value::Str(name));
            }
            a.insert("version".into(), version_struct(r, 4));
            f.insert("assembly".into(), Value::Struct(Rc::new(a)));
        }

        let mut refs = Vec::new();
        for i in 0..self.rows[T_ASSEMBLYREF] {
            let Some(r) = self.row(T_ASSEMBLYREF, i) else {
                break;
            };
            let mut a = Fields::new();
            let key = self.idx(r, 12, self.blob_w());
            if let Some(name) = self.string(self.idx(r, 12 + self.blob_w(), self.str_w())) {
                a.insert("name".into(), Value::Str(name));
            }
            // An empty key is no key.
            if let Some(key) = self.blob(key).filter(|key| !key.is_empty()) {
                a.insert("public_key_or_token".into(), Value::Str(key));
            }
            a.insert("version".into(), version_struct(r, 0));
            refs.push(Value::Struct(Rc::new(a)));
        }
        f.insert(
            "number_of_assembly_refs".into(),
            Value::Int(refs.len() as i64),
        );
        f.insert("assembly_refs".into(), Value::Array(Rc::new(refs)));

        // `field_offsets` is the FieldRVA table's RVA column converted to a
        // file offset: where a field with an initial value is stored. It is
        // not the FieldLayout table, which gives a field's offset *within its
        // class* and is usually absent. A row whose RVA is in no section has no
        // entry.
        let mut offsets = Vec::new();
        for i in 0..self.rows[T_FIELDRVA] {
            let Some(r) = self.row(T_FIELDRVA, i) else {
                break;
            };
            if let Some(offset) = self.file_offset(le_u32(r, 0)) {
                offsets.push(Value::Int(offset));
            }
        }
        f.insert(
            "number_of_field_offsets".into(),
            Value::Int(offsets.len() as i64),
        );
        f.insert("field_offsets".into(), Value::Array(Rc::new(offsets)));

        // Every row is a resource. The `offset` is the file offset of its data,
        // after the four bytes of its length, and only a resource held in this
        // file (`Implementation` 0) and inside the resources directory of the CLI
        // header has one.
        let resources_at = self.file_offset(self.resources_rva);
        let mut resources = Vec::new();
        for i in 0..self.rows[T_MANIFESTRESOURCE] {
            let Some(r) = self.row(T_MANIFESTRESOURCE, i) else {
                break;
            };
            let mut m = Fields::new();
            let in_this_file = self.idx(r, 8 + self.str_w(), self.implementation()) == 0;
            let start = u64::from(le_u32(r, 0)) + 4;
            if let (Some(base), true) = (resources_at, in_this_file)
                && start <= u64::from(self.resources_size)
            {
                m.insert("offset".into(), Value::Int(base + start as i64));
            }
            if let Some(name) = self.string(self.idx(r, 8, self.str_w())) {
                m.insert("name".into(), Value::Str(name));
            }
            resources.push(Value::Struct(Rc::new(m)));
        }
        f.insert(
            "number_of_resources".into(),
            Value::Int(resources.len() as i64),
        );
        f.insert("resources".into(), Value::Array(Rc::new(resources)));

        // A TypeDef row is a class when its name can be read and is neither
        // empty nor `<Module>`, the pseudo-type of the global functions and
        // fields that is row 0 of every assembly.
        let mut classes = 0;
        for i in 0..self.rows[T_TYPEDEF] {
            let Some(r) = self.row(T_TYPEDEF, i) else {
                break;
            };
            if let Some(name) = self.string(self.idx(r, 4, self.str_w()))
                && !name.is_empty()
                && name != b"<Module>"
            {
                classes += 1;
            }
        }
        f.insert("number_of_classes".into(), Value::Int(classes));

        let _ = self.data;
        Value::Struct(Rc::new(f))
    }
}

/// A four-part version read from `row` at `off`.
fn version_struct(row: &[u8], off: usize) -> Value {
    let mut v = Fields::new();
    v.insert("major".into(), Value::Int(le_u16(row, off) as i64));
    v.insert("minor".into(), Value::Int(le_u16(row, off + 2) as i64));
    v.insert(
        "build_number".into(),
        Value::Int(le_u16(row, off + 4) as i64),
    );
    v.insert(
        "revision_number".into(),
        Value::Int(le_u16(row, off + 6) as i64),
    );
    Value::Struct(Rc::new(v))
}

/// The compressed unsigned integer the metadata format uses for blob and string
/// lengths: one, two or four bytes, selected by the top bits of the first. A
/// first byte of 0xE0 or more starts none of them.
fn compressed_uint(s: &[u8]) -> Option<(u32, usize)> {
    let b0 = *s.first()? as u32;
    if b0 & 0xE0 == 0xE0 {
        None
    } else if b0 & 0x80 == 0 {
        Some((b0, 1))
    } else if b0 & 0x40 == 0 {
        Some((((b0 & 0x3F) << 8) | *s.get(1)? as u32, 2))
    } else {
        Some((
            ((b0 & 0x1F) << 24)
                | ((*s.get(1)? as u32) << 16)
                | ((*s.get(2)? as u32) << 8)
                | *s.get(3)? as u32,
            4,
        ))
    }
}

/// The registry format: first three components little-endian, the rest as-is.
fn format_guid(g: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

// ---------------------------------------------------------------------------
// Compile-time field validation
// ---------------------------------------------------------------------------

/// Rejects `dotnet.*` accesses this module does not implement, so a gap is a
/// per-rule compile error that gets counted rather than an undefined value that
/// quietly changes what a rule matches.
pub(crate) fn validate_access(path: &[FieldName]) -> Result<()> {
    let head = match path.first() {
        Some(FieldName::Field(n)) => n.as_str(),
        _ => return Err(Error::new("bad dotnet field access")),
    };
    let ok = matches!(
        head,
        "is_dotnet"
            | "module_name"
            | "version"
            | "number_of_streams"
            | "number_of_guids"
            | "number_of_resources"
            | "number_of_classes"
            | "number_of_assembly_refs"
            | "number_of_modulerefs"
            | "number_of_user_strings"
            | "number_of_constants"
            | "number_of_field_offsets"
            | "streams"
            | "guids"
            | "constants"
            | "user_strings"
            | "modulerefs"
            | "assembly"
            | "assembly_refs"
            | "field_offsets"
            | "resources"
    );
    if !ok {
        return Err(unsupported(head));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Compile-time schema
// ---------------------------------------------------------------------------

const STREAM_FIELDS: &[&str] = &["name", "offset", "size"];
const ASSEMBLY_FIELDS: &[&str] = &["name", "version"];
const ASSEMBLY_REF_FIELDS: &[&str] = &["name", "version", "public_key_or_token"];
const VERSION_FIELDS: &[&str] = &["major", "minor", "build_number", "revision_number"];
const RESOURCE_FIELDS: &[&str] = &["offset", "name"];

/// Where a `dotnet.*` field-access chain currently sits, so the compiler can
/// type each step without knowing the module's shape.
#[derive(Clone, Copy)]
pub(crate) enum Node {
    Root,
    StreamsArray,
    Stream,
    AssemblyStruct,
    AssemblyRefsArray,
    AssemblyRef,
    Version,
    ResourcesArray,
    Resource,
    /// An array whose elements are plain scalars (guids, constants, ...).
    ScalarArray,
    Scalar,
}

impl Node {
    pub(crate) fn root() -> Node {
        Node::Root
    }

    pub(crate) fn is_scalar(self) -> bool {
        matches!(self, Node::Scalar)
    }

    pub(crate) fn field(self, name: &str) -> Result<Node> {
        Ok(match self {
            Node::Root => root_field(name)?,
            Node::Stream if STREAM_FIELDS.contains(&name) => Node::Scalar,
            Node::AssemblyStruct if name == "version" => Node::Version,
            Node::AssemblyStruct if ASSEMBLY_FIELDS.contains(&name) => Node::Scalar,
            Node::AssemblyRef if name == "version" => Node::Version,
            Node::AssemblyRef if ASSEMBLY_REF_FIELDS.contains(&name) => Node::Scalar,
            Node::Version if VERSION_FIELDS.contains(&name) => Node::Scalar,
            Node::Resource if RESOURCE_FIELDS.contains(&name) => Node::Scalar,
            _ => return Err(unsupported(name)),
        })
    }

    pub(crate) fn index(self) -> Result<Node> {
        Ok(match self {
            Node::StreamsArray => Node::Stream,
            Node::AssemblyRefsArray => Node::AssemblyRef,
            Node::ResourcesArray => Node::Resource,
            Node::ScalarArray => Node::Scalar,
            _ => return Err(Error::new("dotnet: value is not indexable")),
        })
    }

    pub(crate) fn iterable(self) -> Option<(Node, usize)> {
        Some(match self {
            Node::StreamsArray => (Node::Stream, 1),
            Node::AssemblyRefsArray => (Node::AssemblyRef, 1),
            Node::ResourcesArray => (Node::Resource, 1),
            Node::ScalarArray => (Node::Scalar, 1),
            _ => return None,
        })
    }
}

fn root_field(name: &str) -> Result<Node> {
    Ok(match name {
        "streams" => Node::StreamsArray,
        "assembly" => Node::AssemblyStruct,
        "assembly_refs" => Node::AssemblyRefsArray,
        "resources" => Node::ResourcesArray,
        "guids" | "constants" | "user_strings" | "modulerefs" | "field_offsets" => {
            Node::ScalarArray
        }
        "is_dotnet"
        | "module_name"
        | "version"
        | "number_of_streams"
        | "number_of_guids"
        | "number_of_resources"
        | "number_of_classes"
        | "number_of_assembly_refs"
        | "number_of_modulerefs"
        | "number_of_user_strings"
        | "number_of_constants"
        | "number_of_field_offsets" => Node::Scalar,
        other => return Err(unsupported(other)),
    })
}

fn unsupported(name: &str) -> Error {
    Error::new(format!("unsupported dotnet field: {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str) -> Vec<FieldName> {
        vec![FieldName::Field(name.to_string())]
    }

    #[test]
    fn implemented_fields_are_accepted() {
        for n in [
            "is_dotnet",
            "module_name",
            "version",
            "streams",
            "guids",
            "constants",
            "user_strings",
            "assembly",
            "assembly_refs",
            "field_offsets",
            "resources",
            "number_of_classes",
        ] {
            assert!(validate_access(&field(n)).is_ok(), "{n} should be accepted");
        }
    }

    #[test]
    fn an_unimplemented_field_is_rejected_rather_than_left_undefined() {
        // `dotnet.classes` needs the TypeDef/MethodDef/Param tables and
        // signature decoding, and is not implemented. A rule that uses it has to
        // be rejected — and counted, which is what the caller does with this
        // error — because evaluating it against an undefined value silently
        // changes what the rule matches instead of admitting the gap.
        for n in ["classes", "typelib", "not_a_field"] {
            assert!(
                validate_access(&field(n)).is_err(),
                "{n} is not implemented and must be rejected"
            );
        }
    }

    /// A PE32 of one section, a CLI header and metadata with a `ModuleRef`
    /// table of `rows` rows that all name one string of `name_len` bytes.
    fn assembly_with_module_refs(rows: usize, name_len: usize) -> Vec<u8> {
        fn put(v: &mut [u8], at: usize, bytes: &[u8]) {
            v[at..at + bytes.len()].copy_from_slice(bytes);
        }
        let mut strings = vec![0u8];
        strings.extend(vec![b'A'; name_len]);
        strings.push(0);
        let mut tilde = vec![0u8; 24];
        tilde[4] = 2; // major
        tilde[7] = 1;
        tilde[8..16].copy_from_slice(&(1u64 << T_MODULEREF).to_le_bytes());
        tilde.extend((rows as u32).to_le_bytes());
        for _ in 0..rows {
            tilde.extend(1u16.to_le_bytes());
        }
        // A blob of the same length, at index 1: its length in two bytes.
        let mut blob = vec![0u8, 0x80 | (name_len >> 8) as u8, name_len as u8];
        blob.extend(vec![b'B'; name_len]);
        // The streams follow their headers: 12, 20 and 16 bytes.
        let root = 0x100;
        let first = 32 + 12 + 20 + 16;
        let mut meta = vec![0u8; first];
        put(&mut meta, 0, &METADATA_MAGIC.to_le_bytes());
        put(&mut meta, 4, &[1, 0, 1, 0]);
        put(&mut meta, 12, &12u32.to_le_bytes());
        put(&mut meta, 16, b"v4.0.30319\0\0");
        put(&mut meta, 30, &3u16.to_le_bytes());
        let mut at = first;
        let mut p = 32;
        for (name, data) in [
            (&b"#~\0\0"[..], &tilde),
            (b"#Strings\0\0\0\0", &strings),
            (b"#Blob\0\0\0", &blob),
        ] {
            put(&mut meta, p, &(at as u32).to_le_bytes());
            put(&mut meta, p + 4, &(data.len() as u32).to_le_bytes());
            put(&mut meta, p + 8, name);
            p += 8 + name.len();
            at += data.len().next_multiple_of(4);
        }
        for data in [&tilde, &strings, &blob] {
            meta.extend(data.iter());
            meta.resize(meta.len().next_multiple_of(4), 0);
        }
        let size = root + meta.len();
        let mut f = vec![0u8; 0x400 + size];
        put(&mut f, 0, b"MZ");
        put(&mut f, 0x3c, &0x40u32.to_le_bytes());
        put(&mut f, 0x40, b"PE\0\0");
        put(&mut f, 0x44, &0x14cu16.to_le_bytes());
        put(&mut f, 0x46, &1u16.to_le_bytes());
        put(&mut f, 0x54, &0xe0u16.to_le_bytes());
        let opt = 0x58;
        put(&mut f, opt, &0x10bu16.to_le_bytes());
        put(&mut f, opt + 32, &0x1000u32.to_le_bytes());
        put(&mut f, opt + 36, &0x200u32.to_le_bytes());
        put(
            &mut f,
            opt + 56,
            &(0x1000 + size.next_multiple_of(0x1000) as u32).to_le_bytes(),
        );
        put(&mut f, opt + 60, &0x200u32.to_le_bytes());
        put(&mut f, opt + 92, &16u32.to_le_bytes());
        // The CLI header is the 14th data directory.
        put(
            &mut f,
            opt + 96 + 8 * COM_DESCRIPTOR_DIR,
            &0x1000u32.to_le_bytes(),
        );
        put(
            &mut f,
            opt + 96 + 8 * COM_DESCRIPTOR_DIR + 4,
            &72u32.to_le_bytes(),
        );
        let section = opt + 0xe0;
        put(&mut f, section, b".text");
        put(&mut f, section + 8, &(size as u32).to_le_bytes());
        put(&mut f, section + 12, &0x1000u32.to_le_bytes());
        put(&mut f, section + 16, &(size as u32).to_le_bytes());
        put(&mut f, section + 20, &0x400u32.to_le_bytes());
        put(&mut f, 0x400, &72u32.to_le_bytes());
        put(&mut f, 0x400 + 8, &(0x1000 + root as u32).to_le_bytes());
        put(&mut f, 0x400 + 12, &(meta.len() as u32).to_le_bytes());
        put(&mut f, 0x400 + root, &meta);
        f
    }

    /// Where `assembly_with_module_refs` puts its section header, and the
    /// fields of it that the tests below change.
    const SECTION_HEADER: usize = 0x58 + 0xe0;
    const RAW_SIZE: usize = SECTION_HEADER + 16;
    const RAW_POINTER: usize = SECTION_HEADER + 20;

    fn parses(pe: &[u8]) -> bool {
        Meta::parse(pe, &Copies::new(usize::MAX)).is_some()
    }

    /// An address past the raw size of its section is zeros in memory and
    /// has no place in the file, as yara-x's `rva_to_offset` has it.
    #[test]
    fn metadata_past_the_raw_size_of_its_section_is_not_read() {
        let mut pe = assembly_with_module_refs(1, 4);
        assert!(parses(&pe));
        // The CLI header is in the raw data, the metadata root is not.
        pe[RAW_SIZE..RAW_SIZE + 4].copy_from_slice(&0x100u32.to_le_bytes());
        assert!(!parses(&pe));
    }

    /// The pointer to the raw data is rounded down to the file alignment
    /// (to 0x200 when the section alignment is 0x1000 or more), as in
    /// yara-x.
    #[test]
    fn the_pointer_to_raw_data_is_rounded_down() {
        let mut pe = assembly_with_module_refs(1, 4);
        pe[RAW_POINTER..RAW_POINTER + 4].copy_from_slice(&0x5ffu32.to_le_bytes());
        assert!(parses(&pe));
    }

    /// An address below the first section is the same offset in the file.
    #[test]
    fn a_cli_header_below_the_first_section_is_read() {
        let mut pe = assembly_with_module_refs(1, 4);
        let header = pe[0x400..0x400 + 72].to_vec();
        pe[0x200..0x200 + 72].copy_from_slice(&header);
        let dir = 0x58 + 96 + 8 * COM_DESCRIPTOR_DIR;
        pe[dir..dir + 4].copy_from_slice(&0x200u32.to_le_bytes());
        assert!(parses(&pe));
    }

    /// yara-x reads 15,000 rows of a table and no more.
    #[test]
    fn a_table_is_read_up_to_15000_rows() {
        for (rows, read) in [(14_999, 14_999), (15_000, 15_000), (15_001, 15_000)] {
            let pe = assembly_with_module_refs(rows, 4);
            let refs = module_refs(&build(&pe, &Copies::new(usize::MAX)));
            assert_eq!(refs.len(), read, "{rows} rows");
        }
    }

    /// A coded index is 4 bytes above `2^(16 - tag bits)` rows of a table it
    /// can name, one more than ECMA-335 says: yara-x reads 2,048 rows of a
    /// table that a 5-bit index names as 2 bytes, and 8,192 of a 3-bit one.
    #[test]
    fn a_coded_index_widens_one_row_later_than_the_format_says() {
        let pe = assembly_with_module_refs(1, 4);
        let copies = Copies::new(usize::MAX);
        let mut meta = Meta::parse(&pe, &copies).unwrap();
        for (rows, custom_attribute, member_ref_parent) in
            [(2_048, 2, 2), (2_049, 4, 2), (8_192, 4, 2), (8_193, 4, 4)]
        {
            meta.rows[T_METHODDEF] = rows;
            assert_eq!(meta.has_custom_attribute(), custom_attribute, "{rows}");
            assert_eq!(meta.member_ref_parent(), member_ref_parent, "{rows}");
        }
    }

    /// The tables that compilers do not write have the size the format gives
    /// them, and the ones after them are where yara-x finds them.
    #[test]
    fn the_rarely_used_tables_have_their_size() {
        let pe = assembly_with_module_refs(1, 4);
        let copies = Copies::new(usize::MAX);
        let meta = Meta::parse(&pe, &copies).unwrap();
        // ENCLog, ENCMap, AssemblyProcessor, AssemblyOS.
        for (table, size) in [(0x1E, 8), (0x1F, 4), (0x21, 4), (0x22, 12)] {
            assert_eq!(meta.row_size(table), size, "table {table:#x}");
        }
    }

    fn module_refs(root: &Value) -> Vec<Vec<u8>> {
        let Value::Struct(f) = root else {
            panic!("not a struct")
        };
        let Some(Value::Array(refs)) = f.get("modulerefs") else {
            panic!("no module references: {:?}", f.keys().collect::<Vec<_>>())
        };
        refs.iter()
            .map(|r| match r {
                Value::Str(name) => name.clone(),
                _ => panic!("not a string"),
            })
            .collect()
    }

    /// Each row copies the string it indexes, and a table of rows that all
    /// index one long string asks for the string many times over: the copies
    /// are charged, and stop where the room ends.
    #[test]
    fn a_string_many_rows_index_is_charged_for_each_copy() {
        let pe = assembly_with_module_refs(2000, 1000);
        let copies = Copies::new(usize::MAX);
        let refs = module_refs(&build(&pe, &copies));
        assert!(!copies.cut());
        assert_eq!(refs.len(), 2000);
        assert!(refs.iter().all(|name| name.len() == 1000));

        // Room for 500 of the 2,000 copies of 1,000 bytes.
        let copies = Copies::new(500_000);
        let refs = module_refs(&build(&pe, &copies));
        assert!(copies.cut());
        let named = refs.iter().filter(|name| !name.is_empty()).count();
        assert_eq!(named, 500);
    }

    /// A blob is charged as a string is.
    #[test]
    fn a_blob_many_rows_index_is_charged_for_each_copy() {
        let pe = assembly_with_module_refs(1, 1000);
        let copies = Copies::new(2500);
        let meta = Meta::parse(&pe, &copies).unwrap();
        assert_eq!(meta.blob(1), Some(vec![b'B'; 1000]));
        assert_eq!(meta.blob(1), Some(vec![b'B'; 1000]));
        assert!(!copies.cut());
        assert_eq!(meta.blob(1), Some(Vec::new()));
        assert!(copies.cut());
        // From then on nothing is copied, whatever its size.
        assert_eq!(meta.blob(0), Some(Vec::new()));
        assert_eq!(meta.string(1), Some(Vec::new()));
    }

    #[test]
    fn the_schema_walks_nested_structures() {
        // `dotnet.assembly_refs[0].version.major`: an array, then a struct,
        // then a scalar.
        let n = Node::root().field("assembly_refs").unwrap();
        let n = n.index().unwrap();
        let n = n.field("version").unwrap();
        assert!(n.field("major").unwrap().is_scalar());
        assert!(n.field("no_such_field").is_err());
    }
}
