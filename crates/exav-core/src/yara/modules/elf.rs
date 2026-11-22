//! The `elf` module, over the `elf` crate's readers of ELF records.
//!
//! Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X. Field
//! semantics (including `entry_point` being a *file offset* rather than the raw
//! `e_entry` virtual address) follow yara-x's `lib/src/modules/elf/`, and where
//! the two differ exav follows yara-x: tables are located by the header and the
//! section types, and a table that is not all in the file is undefined without
//! emptying the rest.
//!
//! Only the fields listed in [`validate_access`] are implemented; any other
//! `elf.*` field is an explicit compile error so that coverage gaps are visible
//! rather than silently undefined. The functions `import_md5` and `telfhash`
//! are in [`super::elf_hashes`].

use std::rc::Rc;

use elf::abi::{DT_NULL, EI_NIDENT, EI_VERSION, ET_DYN, ET_EXEC, EV_CURRENT};
use elf::abi::{PT_DYNAMIC, SHN_LORESERVE, SHT_DYNSYM, SHT_NOBITS, SHT_SYMTAB};
use elf::dynamic::DynamicTable;
use elf::endian::AnyEndian;
use elf::file::{Class, ELF32_EHDR_TAILSIZE, ELF64_EHDR_TAILSIZE, FileHeader, parse_ident};
use elf::parse::ParseAt;
use elf::section::{SectionHeader, SectionHeaderTable};
use elf::segment::{ProgramHeader, SegmentTable};
use elf::symbol::{Symbol, SymbolTable};

use super::{Copies, FieldName};
use crate::yara::error::{Error, Result};
use crate::yara::ir::{Fields, Value};

// ---------------------------------------------------------------------------
// Building the module value tree
// ---------------------------------------------------------------------------

/// Parses `data` and returns the `elf` root value. A non-ELF input yields an
/// empty struct, so every field reads as undefined (YARA's behaviour) rather
/// than as a wrong value.
///
/// The names of sections and symbols, and the entries of the dynamic section,
/// are charged to `copies` as they are copied, and the tables are cut where it
/// runs out: many entries can name one long string, and many segments can
/// cover one table.
pub(crate) fn build(data: &[u8], copies: &Copies) -> Value {
    match Elf::parse(data) {
        Some(elf) => build_elf(&elf, copies),
        None => Value::Struct(Rc::new(Fields::new())),
    }
}

/// What the module exposes of an ELF file. A table that is not all in the file
/// is `None`, and the others are as if it were not there.
struct Elf<'a> {
    data: &'a [u8],
    header: FileHeader<AnyEndian>,
    segments: Option<SegmentTable<'a, AnyEndian>>,
    sections: Option<SectionHeaderTable<'a, AnyEndian>>,
    /// Where the names of the sections are, as a file offset.
    shstrtab: Option<u64>,
    /// The first `SHT_SYMTAB` section.
    symtab: Option<Symbols<'a>>,
    /// The first `SHT_DYNSYM` section.
    dynsym: Option<Symbols<'a>>,
}

struct Symbols<'a> {
    table: SymbolTable<'a, AnyEndian>,
    /// Where the names are, as a file offset.
    names: Option<u64>,
}

/// `count` records of `size` bytes at `offset`; `None` if they are not all in
/// `data`. No records are in `data` when `offset` is past its end.
fn records(data: &[u8], offset: u64, count: usize, size: usize) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    data.get(start..start.checked_add(count.checked_mul(size)?)?)
}

/// The string `offset` bytes after `base` in the file, up to the next NUL or
/// the end of the file. A string table is not bounded by its size here.
/// `None` when there is no table, or the string starts past the end of the file.
fn name_at(data: &[u8], base: Option<u64>, offset: u32) -> Option<&[u8]> {
    let start = usize::try_from(base?).ok()?.checked_add(offset as usize)?;
    let rest = data.get(start..)?;
    Some(&rest[..rest.iter().position(|&b| b == 0).unwrap_or(rest.len())])
}

/// The file offset of section `index`, where its strings are.
fn strings_of(sections: &SectionHeaderTable<'_, AnyEndian>, index: usize) -> Option<u64> {
    sections.get(index).ok().map(|sh| sh.sh_offset)
}

/// The symbols of the first section of type `kind`. Their number is the
/// section's size over the size of a symbol, whatever its entry size says.
fn symbols<'a>(
    data: &'a [u8],
    header: &FileHeader<AnyEndian>,
    sections: &SectionHeaderTable<'_, AnyEndian>,
    kind: u32,
) -> Option<Symbols<'a>> {
    let sh = sections.iter().find(|sh| sh.sh_type == kind)?;
    let size = Symbol::size_for(header.class);
    let count = usize::try_from(sh.sh_size / size as u64).ok()?;
    if count == 0 {
        return None;
    }
    Some(Symbols {
        table: SymbolTable::new(
            header.endianness,
            header.class,
            records(data, sh.sh_offset, count, size)?,
        ),
        names: strings_of(sections, sh.sh_link as usize),
    })
}

impl<'a> Elf<'a> {
    /// `None` when the header is cut or not an ELF header.
    fn parse(data: &'a [u8]) -> Option<Self> {
        let mut ident: [u8; EI_NIDENT] = data.get(..EI_NIDENT)?.try_into().ok()?;
        // The version byte is not looked at: a file with another value is read
        // all the same.
        ident[EI_VERSION] = EV_CURRENT;
        let (endian, class, osabi, abi_version) = parse_ident::<AnyEndian>(&ident).ok()?;
        let tail = match class {
            Class::ELF32 => ELF32_EHDR_TAILSIZE,
            Class::ELF64 => ELF64_EHDR_TAILSIZE,
        };
        let tail = data.get(EI_NIDENT..EI_NIDENT + tail)?;
        let header = FileHeader::parse_tail((endian, class, osabi, abi_version), tail).ok()?;

        // The offsets are read as they are, 0 included: the entry sizes of the
        // header are not used, a record is the size of its class.
        let segments = records(
            data,
            header.e_phoff,
            usize::from(header.e_phnum),
            ProgramHeader::size_for(class),
        )
        .map(|bytes| SegmentTable::new(endian, class, bytes));
        // `e_shnum` 0 is no section, whatever the null section says.
        let sections = records(
            data,
            header.e_shoff,
            usize::from(header.e_shnum),
            SectionHeader::size_for(class),
        )
        .map(|bytes| SectionHeaderTable::new(endian, class, bytes));

        let (mut shstrtab, mut symtab, mut dynsym) = (None, None, None);
        if let Some(sections) = &sections {
            shstrtab = strings_of(sections, usize::from(header.e_shstrndx));
            symtab = symbols(data, &header, sections, SHT_SYMTAB);
            dynsym = symbols(data, &header, sections, SHT_DYNSYM);
        }

        Some(Elf {
            data,
            header,
            segments,
            sections,
            shstrtab,
            symtab,
            dynsym,
        })
    }
}

fn build_elf(elf: &Elf, copies: &Copies) -> Value {
    let mut f = Fields::new();
    let ins = |f: &mut Fields, k: &str, v: i64| {
        f.insert(k.into(), Value::Int(v));
    };

    let h = &elf.header;
    ins(&mut f, "type", h.e_type as i64);
    ins(&mut f, "machine", h.e_machine as i64);
    ins(&mut f, "osabi", h.osabi as i64);
    ins(&mut f, "sh_offset", h.e_shoff as i64);
    ins(&mut f, "sh_entry_size", h.e_shentsize as i64);
    ins(&mut f, "ph_offset", h.e_phoff as i64);
    ins(&mut f, "ph_entry_size", h.e_phentsize as i64);
    ins(&mut f, "number_of_sections", h.e_shnum as i64);
    ins(&mut f, "number_of_segments", h.e_phnum as i64);

    // `elf.entry_point` is the entry point's FILE OFFSET, not `e_entry`.
    if let Some(off) = entry_point_offset_from(elf) {
        ins(&mut f, "entry_point", off);
    }

    // The sections, and what is read through them, are undefined when the
    // section table is not all in the file.
    if let Some(table) = &elf.sections {
        let mut sections = Vec::with_capacity(table.len());
        for sh in table.iter() {
            let mut s = Fields::new();
            let name = name_at(elf.data, elf.shstrtab, sh.sh_name);
            if !copies.take(name.map_or(0, <[u8]>::len)) {
                break;
            }
            if let Some(name) = name {
                s.insert("name".into(), Value::Str(name.to_vec()));
            }
            // The types are signed 32-bit numbers.
            s.insert("type".into(), Value::Int(i64::from(sh.sh_type as i32)));
            s.insert("flags".into(), Value::Int(sh.sh_flags as i64));
            s.insert("address".into(), Value::Int(sh.sh_addr as i64));
            s.insert("size".into(), Value::Int(sh.sh_size as i64));
            s.insert("offset".into(), Value::Int(sh.sh_offset as i64));
            sections.push(Value::Struct(Rc::new(s)));
        }
        if !sections.is_empty() {
            f.insert("sections".into(), Value::Array(Rc::new(sections)));
        }

        // Undefined when the sections are, 0 for a file with no such table.
        for (count, key, table) in [
            ("symtab_entries", "symtab", &elf.symtab),
            ("dynsym_entries", "dynsym", &elf.dynsym),
        ] {
            let built = table
                .as_ref()
                .map(|t| build_symbols(elf.data, t, copies))
                .unwrap_or_default();
            ins(&mut f, count, built.len() as i64);
            if !built.is_empty() {
                f.insert(key.into(), Value::Array(Rc::new(built)));
            }
        }
    }

    if let Some(table) = &elf.segments {
        let mut segments = Vec::with_capacity(table.len());
        for ph in table.iter() {
            let mut s = Fields::new();
            s.insert("type".into(), Value::Int(i64::from(ph.p_type as i32)));
            s.insert("flags".into(), Value::Int(ph.p_flags as i64));
            s.insert("offset".into(), Value::Int(ph.p_offset as i64));
            s.insert("virtual_address".into(), Value::Int(ph.p_vaddr as i64));
            s.insert("physical_address".into(), Value::Int(ph.p_paddr as i64));
            s.insert("file_size".into(), Value::Int(ph.p_filesz as i64));
            s.insert("memory_size".into(), Value::Int(ph.p_memsz as i64));
            s.insert("alignment".into(), Value::Int(ph.p_align as i64));
            segments.push(Value::Struct(Rc::new(s)));
        }
        if !segments.is_empty() {
            f.insert("segments".into(), Value::Array(Rc::new(segments)));
        }
    }

    let dynamic = dynamic_entries(elf, copies);
    ins(&mut f, "dynamic_section_entries", dynamic.len() as i64);
    if !dynamic.is_empty() {
        f.insert("dynamic".into(), Value::Array(Rc::new(dynamic)));
    }

    Value::Struct(Rc::new(f))
}

/// What an entry of the dynamic section costs, against the copy limit: many
/// segments can cover one table.
const DYNAMIC_ENTRY_COST: usize = 16;

/// The entries of every `PT_DYNAMIC` segment, each up to its first `DT_NULL`
/// (not included). A segment that is not all in the file has none.
fn dynamic_entries(elf: &Elf, copies: &Copies) -> Vec<Value> {
    let mut out = Vec::new();
    let Some(segments) = &elf.segments else {
        return out;
    };
    let (endian, class) = (elf.header.endianness, elf.header.class);
    for ph in segments.iter().filter(|ph| ph.p_type == PT_DYNAMIC) {
        let Some(bytes) = usize::try_from(ph.p_filesz)
            .ok()
            .and_then(|size| records(elf.data, ph.p_offset, size, 1))
        else {
            continue;
        };
        for d in DynamicTable::new(endian, class, bytes).iter() {
            if d.d_tag == DT_NULL {
                break;
            }
            if !copies.take(DYNAMIC_ENTRY_COST) {
                return out;
            }
            let mut s = Fields::new();
            // The tag is a signed 32-bit number.
            s.insert("type".into(), Value::Int(i64::from(d.d_tag as i32)));
            s.insert("val".into(), Value::Int(d.d_val() as i64));
            out.push(Value::Struct(Rc::new(s)));
        }
    }
    out
}

fn build_symbols(data: &[u8], syms: &Symbols, copies: &Copies) -> Vec<Value> {
    let mut out = Vec::with_capacity(syms.table.len());
    for sym in syms.table.iter() {
        let mut s = Fields::new();
        let name = name_at(data, syms.names, sym.st_name);
        if !copies.take(name.map_or(0, <[u8]>::len)) {
            break;
        }
        if let Some(name) = name {
            s.insert("name".into(), Value::Str(name.to_vec()));
        }
        s.insert("value".into(), Value::Int(sym.st_value as i64));
        s.insert("size".into(), Value::Int(sym.st_size as i64));
        // `st_info` packs bind in the high nibble and type in the low nibble.
        s.insert("type".into(), Value::Int((sym.st_info & 0x0f) as i64));
        s.insert("bind".into(), Value::Int((sym.st_info >> 4) as i64));
        s.insert("shndx".into(), Value::Int(sym.st_shndx as i64));
        // The visibility is the low two bits of `st_other`.
        s.insert(
            "visibility".into(),
            Value::Int((sym.st_other & 0x03) as i64),
        );
        out.push(Value::Struct(Rc::new(s)));
    }
    out
}

/// Maps `e_entry` (a virtual address) back to a file offset, the way YARA
/// reports `elf.entry_point`: through the first segment that holds it in an
/// executable or a shared object, through the first section that does (but
/// for `SHT_NOBITS`) in any other file, and undefined for no entry (`e_entry`
/// 0) and for an `e_shnum` in the reserved indexes (yara-x gives none then). A
/// segment or a section whose end overflows ends the search.
fn entry_point_offset_from(elf: &Elf) -> Option<i64> {
    let entry = elf.header.e_entry;
    if entry == 0 || elf.header.e_shnum >= SHN_LORESERVE {
        return None;
    }
    // `None` when the end of the range overflows.
    let holds = |addr: u64, size: u64| {
        addr.checked_add(size)
            .map(|end| entry >= addr && entry < end)
    };
    match elf.header.e_type {
        ET_EXEC | ET_DYN => {
            for ph in elf.segments.iter().flat_map(|table| table.iter()) {
                if holds(ph.p_vaddr, ph.p_memsz)? {
                    return ph
                        .p_offset
                        .checked_add(entry - ph.p_vaddr)
                        .map(|o| o as i64);
                }
            }
        }
        _ => {
            let sections = elf.sections.iter().flat_map(|table| table.iter());
            for sh in sections.filter(|sh| sh.sh_type != SHT_NOBITS) {
                if holds(sh.sh_addr, sh.sh_size)? {
                    return sh
                        .sh_offset
                        .checked_add(entry - sh.sh_addr)
                        .map(|o| o as i64);
                }
            }
        }
    }
    None
}

/// `elf.entry_point` for a standalone caller (mirrors `pe::entry_point_offset`).
#[cfg(test)]
pub(crate) fn entry_point_offset(data: &[u8]) -> Option<i64> {
    Elf::parse(data).and_then(|e| entry_point_offset_from(&e))
}

// ---------------------------------------------------------------------------
// Compile-time schema validation
// ---------------------------------------------------------------------------

/// Node types encountered while walking an `elf.*` field-access chain. Exposed
/// to the compiler so it can type loop/`with` variables bound to `elf`
/// sub-values (e.g. `for any s in elf.sections : (s.name == ".text")`).
#[derive(Clone, Copy)]
pub(crate) enum Node {
    Root,
    SectionsArray,
    Section,
    SegmentsArray,
    Segment,
    DynamicArray,
    Dynamic,
    SymbolsArray,
    Symbol,
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
            Node::Section if SECTION_FIELDS.contains(&name) => Node::Scalar,
            Node::Segment if SEGMENT_FIELDS.contains(&name) => Node::Scalar,
            Node::Dynamic if DYNAMIC_FIELDS.contains(&name) => Node::Scalar,
            Node::Symbol if SYMBOL_FIELDS.contains(&name) => Node::Scalar,
            _ => return Err(unsupported(name)),
        })
    }

    pub(crate) fn index(self) -> Result<Node> {
        match self {
            Node::SectionsArray => Ok(Node::Section),
            Node::SegmentsArray => Ok(Node::Segment),
            Node::DynamicArray => Ok(Node::Dynamic),
            Node::SymbolsArray => Ok(Node::Symbol),
            _ => Err(Error::new("cannot index this elf field (not an array/map)")),
        }
    }

    /// If this node is an array, returns `(element node, number of loop
    /// variables)`, which is 1 for an array.
    pub(crate) fn iterable(self) -> Option<(Node, usize)> {
        match self {
            Node::SectionsArray => Some((Node::Section, 1)),
            Node::SegmentsArray => Some((Node::Segment, 1)),
            Node::DynamicArray => Some((Node::Dynamic, 1)),
            Node::SymbolsArray => Some((Node::Symbol, 1)),
            _ => None,
        }
    }
}

/// Validates an `elf` field-access chain, rejecting unknown/unsupported fields.
pub(crate) fn validate_access(path: &[FieldName]) -> Result<()> {
    let mut node = Node::Root;
    for seg in path {
        node = match seg {
            FieldName::Field(name) => node.field(name)?,
            FieldName::Index => node.index()?,
        };
    }
    Ok(())
}

fn root_field(name: &str) -> Result<Node> {
    Ok(match name {
        n if ROOT_SCALARS.contains(&n) => Node::Scalar,
        "sections" => Node::SectionsArray,
        "segments" => Node::SegmentsArray,
        "dynamic" => Node::DynamicArray,
        "symtab" | "dynsym" => Node::SymbolsArray,
        _ => return Err(unsupported(name)),
    })
}

fn unsupported(field: &str) -> Error {
    Error::new(format!("unsupported elf field: {field}"))
}

const ROOT_SCALARS: &[&str] = &[
    "type",
    "machine",
    "osabi",
    "entry_point",
    "sh_offset",
    "sh_entry_size",
    "ph_offset",
    "ph_entry_size",
    "number_of_sections",
    "number_of_segments",
    "dynamic_section_entries",
    "symtab_entries",
    "dynsym_entries",
];

const SECTION_FIELDS: &[&str] = &["name", "type", "flags", "address", "size", "offset"];
const SEGMENT_FIELDS: &[&str] = &[
    "type",
    "flags",
    "offset",
    "virtual_address",
    "physical_address",
    "file_size",
    "memory_size",
    "alignment",
];
const DYNAMIC_FIELDS: &[&str] = &["type", "val"];
const SYMBOL_FIELDS: &[&str] = &[
    "name",
    "value",
    "size",
    "type",
    "bind",
    "shndx",
    "visibility",
];

// ---------------------------------------------------------------------------
// Enum constants (accessed as `elf.<NAME>`; yara-x inlines these into the
// module namespace). The names and values are yara-x's, which has no `SHF_*`:
// exav must not be a superset, a rule that compiles here has to compile there.
// ---------------------------------------------------------------------------

pub(crate) fn constant(name: &str) -> Option<i64> {
    Some(match name {
        // e_type
        "ET_NONE" => 0,
        "ET_REL" => 1,
        "ET_EXEC" => 2,
        "ET_DYN" => 3,
        "ET_CORE" => 4,
        "ET_LOPROC" => 0xff00,
        "ET_HIPROC" => 255,

        // e_machine
        "EM_NONE" => 0,
        "EM_M32" => 1,
        "EM_SPARC" => 2,
        "EM_386" => 3,
        "EM_68K" => 4,
        "EM_88K" => 5,
        "EM_IAMCU" => 6,
        "EM_860" => 7,
        "EM_MIPS" => 8,
        "EM_S370" => 9,
        "EM_MIPS_RS3_LE" => 10,
        "EM_PARISC" => 15,
        "EM_SPARC32PLUS" => 18,
        "EM_PPC" => 20,
        "EM_PPC64" => 21,
        "EM_S390" => 22,
        "EM_MCORE" => 39,
        "EM_RCE" => 39,
        "EM_ARM" => 40,
        "EM_SH" => 42,
        "EM_SPARCV9" => 43,
        "EM_X86_64" => 62,
        "EM_ARC_COMPACT" => 93,
        "EM_AARCH64" => 183,
        "EM_BPF" => 247,
        "EM_LOONGARCH" => 0x102,

        // e_ident[EI_OSABI]
        "OSABI_NONE" => 0,
        "OSABI_HPUX" => 1,
        "OSABI_NETBSD" => 2,
        "OSABI_LINUX" => 3,
        "OSABI_GNU_HURD" => 4,
        "OSABI_SOLARIS" => 6,
        "OSABI_AIX" => 7,
        "OSABI_IRIX" => 8,
        "OSABI_FREE_BSD" => 9,
        "OSABI_TRU64" => 10,
        "OSABI_MODESTO" => 11,
        "OSABI_OPENBSD" => 12,
        "OSABI_OPENVMS" => 13,
        "OSABI_NSK" => 14,
        "OSABI_AROS" => 15,
        "OSABI_FENIXOS" => 16,
        "OSABI_CLOUDABI" => 17,
        "OSABI_OPENVOS" => 18,
        "OSABI_ARM_AEABI" => 64,
        "OSABI_ARM" => 97,
        "OSABI_STANDALONE" => 255,

        // sh_type
        "SHT_NULL" => 0,
        "SHT_PROGBITS" => 1,
        "SHT_SYMTAB" => 2,
        "SHT_STRTAB" => 3,
        "SHT_RELA" => 4,
        "SHT_HASH" => 5,
        "SHT_DYNAMIC" => 6,
        "SHT_NOTE" => 7,
        "SHT_NOBITS" => 8,
        "SHT_REL" => 9,
        "SHT_SHLIB" => 10,
        "SHT_DYNSYM" => 11,
        "SHT_INIT_ARRAY" => 14,
        "SHT_FINI_ARRAY" => 15,

        // p_type
        "PT_NULL" => 0,
        "PT_LOAD" => 1,
        "PT_DYNAMIC" => 2,
        "PT_INTERP" => 3,
        "PT_NOTE" => 4,
        "PT_SHLIB" => 5,
        "PT_PHDR" => 6,
        "PT_TLS" => 7,
        "PT_GNU_EH_FRAME" => 0x6474e550,
        "PT_GNU_STACK" => 0x6474e551,
        "PT_GNU_RELRO" => 0x6474e552,
        "PT_GNU_PROPERTY" => 0x6474e553,

        // p_flags
        "PF_X" => 1,
        "PF_W" => 2,
        "PF_R" => 4,

        // Symbol type (st_info low nibble)
        "STT_NOTYPE" => 0,
        "STT_OBJECT" => 1,
        "STT_FUNC" => 2,
        "STT_SECTION" => 3,
        "STT_FILE" => 4,
        "STT_COMMON" => 5,
        "STT_TLS" => 6,

        // Symbol binding (st_info high nibble)
        "STB_LOCAL" => 0,
        "STB_GLOBAL" => 1,
        "STB_WEAK" => 2,

        // Symbol visibility (st_other low bits)
        "STV_DEFAULT" => 0,
        "STV_INTERNAL" => 1,
        "STV_HIDDEN" => 2,
        "STV_PROTECTED" => 3,

        // d_tag
        "DT_NULL" => 0,
        "DT_NEEDED" => 1,
        "DT_PLTRELSZ" => 2,
        "DT_PLTGOT" => 3,
        "DT_HASH" => 4,
        "DT_STRTAB" => 5,
        "DT_SYMTAB" => 6,
        "DT_RELA" => 7,
        "DT_RELASZ" => 8,
        "DT_RELAENT" => 9,
        "DT_STRSZ" => 10,
        "DT_SYMENT" => 11,
        "DT_INIT" => 12,
        "DT_FINI" => 13,
        "DT_SONAME" => 14,
        "DT_RPATH" => 15,
        "DT_SYMBOLIC" => 16,
        "DT_REL" => 17,
        "DT_RELSZ" => 18,
        "DT_RELENT" => 19,
        "DT_PLTREL" => 20,
        "DT_DEBUG" => 21,
        "DT_TEXTREL" => 22,
        "DT_JMPREL" => 23,
        "DT_BIND_NOW" => 24,
        "DT_INIT_ARRAY" => 25,
        "DT_FINI_ARRAY" => 26,
        "DT_INIT_ARRAYSZ" => 27,
        "DT_FINI_ARRAYSZ" => 28,
        "DT_RUNPATH" => 29,
        "DT_FLAGS" => 30,
        "DT_ENCODING" => 32,
        "DT_LOOS" => 0x6000000d,
        "DT_HIOS" => 0x6ffff000,
        "DT_VALRNGLO" => 0x6ffffd00,
        "DT_VALRNGHI" => 0x6ffffdff,
        "DT_ADDRRNGLO" => 0x6ffffe00,
        "DT_ADDRRNGHI" => 0x6ffffeff,
        "DT_VERSYM" => 0x6ffffff0,
        "DT_RELACOUNT" => 0x6ffffff9,
        "DT_RELCOUNT" => 0x6ffffffa,
        "DT_FLAGS_1" => 0x6ffffffb,
        "DT_VERDEF" => 0x6ffffffc,
        "DT_VERDEFNUM" => 0x6ffffffd,
        "DT_VERNEED" => 0x6ffffffe,
        "DT_VERNEEDNUM" => 0x6fffffff,
        "DT_LOPROC" => 0x70000000,
        "DT_HIPROC" => 0x7fffffff,

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ELF64 file of `segments` `PT_DYNAMIC` segments over one table of
    /// `entries` entries, none of them the end.
    fn many_dynamic(segments: usize, entries: usize) -> Vec<u8> {
        let table = 64 + segments * 56;
        let mut data = vec![0u8; table + entries * 16];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4..7].copy_from_slice(&[2, 1, 1]);
        data[16..18].copy_from_slice(&3u16.to_le_bytes());
        data[32..40].copy_from_slice(&64u64.to_le_bytes());
        data[52..58].copy_from_slice(&[64, 0, 56, 0, segments as u8, 0]);
        for i in 0..segments {
            let at = 64 + i * 56;
            data[at..at + 4].copy_from_slice(&2u32.to_le_bytes());
            data[at + 8..at + 16].copy_from_slice(&(table as u64).to_le_bytes());
            data[at + 32..at + 40].copy_from_slice(&(entries as u64 * 16).to_le_bytes());
        }
        for i in 0..entries {
            data[table + i * 16] = 1;
        }
        data
    }

    /// Many segments can cover one table, so the entries are charged to the
    /// copy limit.
    #[test]
    fn dynamic_entries_of_many_segments_are_charged_to_the_copy_limit() {
        let data = many_dynamic(100, 1000);
        let elf = Elf::parse(&data).unwrap();
        let copies = Copies::new(usize::MAX);
        assert_eq!(dynamic_entries(&elf, &copies).len(), 100_000);
        assert!(!copies.cut());

        let copies = Copies::new(DYNAMIC_ENTRY_COST * 1500);
        assert_eq!(dynamic_entries(&elf, &copies).len(), 1500);
        assert!(copies.cut());
    }
}
