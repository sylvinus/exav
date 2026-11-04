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

const MAX_TABLES: usize = 64;

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

/// One named stream in the metadata root.
struct Stream {
    name: String,
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
    wide_str: bool,
    wide_guid: bool,
    wide_blob: bool,
}

impl<'a> Meta<'a> {
    fn parse(data: &'a [u8], copies: &'a Copies) -> Option<Meta<'a>> {
        let pe = crate::pe::headers(data)?;
        let opt = pe.header.optional_header?;
        let (_, dd) = opt.data_directories.data_directories[COM_DESCRIPTOR_DIR]?;
        // yara-x converts RVAs here as in its `pe` module.
        let rva_to_offset = |rva: u32| {
            crate::pe::yarax_offset(
                rva,
                &pe.sections,
                opt.windows_fields.file_alignment,
                opt.windows_fields.section_alignment,
            )
            .map(|offset| offset as usize)
        };
        let cli = rva_to_offset(dd.virtual_address)?;
        // The CLI header's `MetaData` directory sits at offset 8.
        let md_rva = le_u32(data, cli + 8);
        let root = rva_to_offset(md_rva)?;
        if le_u32(data, root) != METADATA_MAGIC {
            return None;
        }

        // Root: signature, major, minor, reserved, then a length-prefixed
        // version string padded to a four-byte boundary.
        let vlen = le_u32(data, root.saturating_add(12)) as usize;
        let vbytes = data.get(root.checked_add(16)?..)?.get(..vlen)?;
        let version = String::from_utf8_lossy(
            &vbytes[..vbytes.iter().position(|&b| b == 0).unwrap_or(vbytes.len())],
        )
        .into_owned();
        let after_version = root + 16 + vlen.next_multiple_of(4);
        let n_streams = le_u16(data, after_version + 2) as usize;

        let mut streams = Vec::with_capacity(n_streams.min(64));
        let mut p = after_version + 4;
        for _ in 0..n_streams.min(64) {
            let offset = le_u32(data, p);
            let size = le_u32(data, p + 4);
            let name_start = p + 8;
            let end = data.get(name_start..)?.iter().position(|&b| b == 0)? + name_start;
            let name = String::from_utf8_lossy(data.get(name_start..end)?).into_owned();
            streams.push(Stream { name, offset, size });
            // Names are NUL-terminated and padded to four bytes.
            p = name_start + (end - name_start + 1).next_multiple_of(4);
        }

        let heap = |n: &str| -> &'a [u8] {
            streams
                .iter()
                .find(|s| s.name == n)
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
        let tilde = if streams.iter().any(|s| s.name == "#~") {
            heap("#~")
        } else {
            heap("#-")
        };
        if tilde.len() < 24 {
            return None;
        }

        // `#~` header: reserved, major, minor, heap-size flags, reserved, then
        // the valid/sorted bitmaps and one row count per valid table.
        let heap_sizes = tilde[6];
        let valid = u64::from_le_bytes(tilde.get(8..16)?.try_into().ok()?);
        let mut rows = [0u32; MAX_TABLES];
        let mut p = 24;
        for (i, r) in rows.iter_mut().enumerate() {
            if valid & (1u64 << i) != 0 {
                *r = le_u32(tilde, p);
                p += 4;
            }
        }
        let tables = tilde.get(p..)?;

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
            wide_str: heap_sizes & 0x01 != 0,
            wide_guid: heap_sizes & 0x02 != 0,
            wide_blob: heap_sizes & 0x04 != 0,
        };
        m.locate_tables();
        Some(m)
    }

    /// Row sizes depend on how many rows every *other* table has, so the layout
    /// has to be computed before any row can be read.
    fn locate_tables(&mut self) {
        let mut at = 0usize;
        for t in 0..MAX_TABLES {
            self.table_at[t] = at;
            at = at.saturating_add((self.rows[t] as usize).saturating_mul(self.row_size(t)));
        }
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
    /// of the tables it can point at is large enough.
    fn coded_w(&self, tables: &[usize], tag_bits: u32) -> usize {
        let max = tables.iter().map(|&t| self.rows[t]).max().unwrap_or(0);
        if (max as u64) >= (1u64 << (16 - tag_bits)) {
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
            0x1E | 0x1F => 4, // ENCLog / ENCMap
            T_ASSEMBLY => 16 + b + s * 2,
            0x21 => 4 + b + s * 2, // AssemblyProcessor / OS variants
            0x22 => 4,
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
        if i >= self.rows[t] {
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

    /// A NUL-terminated string from `#Strings`; empty once the copies have
    /// used up their room.
    fn string(&self, i: u32) -> Vec<u8> {
        let i = i as usize;
        match self.strings.get(i..) {
            Some(s) => {
                let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                if self.copies.take(end) {
                    s[..end].to_vec()
                } else {
                    Vec::new()
                }
            }
            None => Vec::new(),
        }
    }

    /// A length-prefixed blob from `#Blob`, minus its prefix; empty once the
    /// copies have used up their room.
    fn blob(&self, i: u32) -> Vec<u8> {
        let i = i as usize;
        let Some(s) = self.blobs.get(i..) else {
            return Vec::new();
        };
        let (len, hdr) = match compressed_uint(s) {
            Some(v) => v,
            None => return Vec::new(),
        };
        hdr.checked_add(len as usize)
            .and_then(|end| s.get(hdr..end))
            .filter(|blob| self.copies.take(blob.len()))
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
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
            f.insert("module_name".into(), Value::Str(self.string(name)));
        }

        let mut streams = Vec::with_capacity(self.streams.len());
        for s in &self.streams {
            let mut v = Fields::new();
            v.insert("name".into(), Value::Str(s.name.as_bytes().to_vec()));
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
        // values starting after a single leading zero byte.
        let mut user_strings = Vec::new();
        let mut p = 1usize;
        while p < self.us.len() {
            let Some((len, hdr)) = compressed_uint(&self.us[p..]) else {
                break;
            };
            let len = len as usize;
            // The last byte of an entry is a flag rather than character data, so
            // a one-byte entry carries no characters at all. YARA counts neither
            // those nor zero-length ones.
            let start = p.saturating_add(hdr);
            let next = start.saturating_add(len);
            if len <= 1 {
                p = next;
                continue;
            }
            let end = next.min(self.us.len());
            let body = &self.us[start..end.saturating_sub(1).max(start)];
            user_strings.push(Value::Str(body.to_vec()));
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
            constants.push(Value::Str(self.blob(b)));
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
            modulerefs.push(Value::Str(self.string(self.idx(r, 0, self.str_w()))));
        }
        f.insert(
            "number_of_modulerefs".into(),
            Value::Int(modulerefs.len() as i64),
        );
        f.insert("modulerefs".into(), Value::Array(Rc::new(modulerefs)));

        // Assembly: version, flags, public key, name, culture.
        if let Some(r) = self.row(T_ASSEMBLY, 0) {
            let mut a = Fields::new();
            a.insert(
                "name".into(),
                Value::Str(self.string(self.idx(r, 16 + self.blob_w(), self.str_w()))),
            );
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
            a.insert(
                "name".into(),
                Value::Str(self.string(self.idx(r, 12 + self.blob_w(), self.str_w()))),
            );
            a.insert("public_key_or_token".into(), Value::Str(self.blob(key)));
            a.insert("version".into(), version_struct(r, 0));
            refs.push(Value::Struct(Rc::new(a)));
        }
        f.insert(
            "number_of_assembly_refs".into(),
            Value::Int(refs.len() as i64),
        );
        f.insert("assembly_refs".into(), Value::Array(Rc::new(refs)));

        // `field_offsets` is the FieldRVA table's RVA column — where a field
        // with an initial value is stored — not the FieldLayout table, which
        // gives a field's offset *within its class* and is usually absent. This
        // assembly has zero FieldLayout rows and twenty-two FieldRVA ones.
        let mut offsets = Vec::new();
        for i in 0..self.rows[T_FIELDRVA] {
            let Some(r) = self.row(T_FIELDRVA, i) else {
                break;
            };
            offsets.push(Value::Int(le_u32(r, 0) as i64));
        }
        f.insert(
            "number_of_field_offsets".into(),
            Value::Int(offsets.len() as i64),
        );
        f.insert("field_offsets".into(), Value::Array(Rc::new(offsets)));

        // Only resources held in this file count; the ones with a non-zero
        // `Implementation` live in another file entirely.
        let mut resources = Vec::new();
        for i in 0..self.rows[T_MANIFESTRESOURCE] {
            let Some(r) = self.row(T_MANIFESTRESOURCE, i) else {
                break;
            };
            let mut m = Fields::new();
            m.insert("offset".into(), Value::Int(le_u32(r, 0) as i64));
            m.insert(
                "name".into(),
                Value::Str(self.string(self.idx(r, 8, self.str_w()))),
            );
            resources.push(Value::Struct(Rc::new(m)));
        }
        f.insert(
            "number_of_resources".into(),
            Value::Int(resources.len() as i64),
        );
        f.insert("resources".into(), Value::Array(Rc::new(resources)));

        // Every assembly's TypeDef row 0 is the `<Module>` pseudo-type, which
        // holds global functions and fields rather than being a class. YARA does
        // not count it.
        f.insert(
            "number_of_classes".into(),
            Value::Int(self.rows[T_TYPEDEF].saturating_sub(1) as i64),
        );

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
/// lengths: one, two or four bytes, selected by the top bits of the first.
fn compressed_uint(s: &[u8]) -> Option<(u32, usize)> {
    let b0 = *s.first()? as u32;
    if b0 & 0x80 == 0 {
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
        assert_eq!(meta.blob(1), vec![b'B'; 1000]);
        assert_eq!(meta.blob(1), vec![b'B'; 1000]);
        assert!(!copies.cut());
        assert!(meta.blob(1).is_empty());
        assert!(copies.cut());
        // From then on nothing is copied, whatever its size.
        assert!(meta.blob(0).is_empty());
        assert!(meta.string(1).is_empty());
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
