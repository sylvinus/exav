//! The `elf` module, backed by the pure-Rust `goblin` ELF parser.
//!
//! Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X. Field
//! semantics (including `entry_point` being a *file offset* rather than the raw
//! `e_entry` virtual address) follow yara-x's `lib/src/modules/elf/`.
//!
//! Only the fields listed in [`validate_access`] are implemented; any other
//! `elf.*` field is an explicit compile error so that coverage gaps are visible
//! rather than silently undefined. The module exposes no functions, matching
//! YARA.

use std::rc::Rc;

use super::FieldName;
use crate::yara::error::{Error, Result};
use crate::yara::ir::{Fields, Value};

// ---------------------------------------------------------------------------
// Building the module value tree
// ---------------------------------------------------------------------------

/// Parses `data` and returns the `elf` root value. A non-ELF input yields an
/// empty struct, so every field reads as undefined (YARA's behaviour) rather
/// than as a wrong value.
pub(crate) fn build(data: &[u8]) -> Value {
    match goblin::elf::Elf::parse(data) {
        Ok(elf) => build_elf(data, &elf),
        Err(_) => Value::Struct(Rc::new(Fields::new())),
    }
}

fn build_elf(data: &[u8], elf: &goblin::elf::Elf) -> Value {
    let mut f = Fields::new();
    let ins = |f: &mut Fields, k: &str, v: i64| {
        f.insert(k.into(), Value::Int(v));
    };

    let h = &elf.header;
    ins(&mut f, "type", h.e_type as i64);
    ins(&mut f, "machine", h.e_machine as i64);
    ins(&mut f, "sh_offset", h.e_shoff as i64);
    ins(&mut f, "sh_entry_size", h.e_shentsize as i64);
    ins(&mut f, "ph_offset", h.e_phoff as i64);
    ins(&mut f, "ph_entry_size", h.e_phentsize as i64);
    ins(&mut f, "number_of_sections", h.e_shnum as i64);
    ins(&mut f, "number_of_segments", h.e_phnum as i64);

    // `elf.entry_point` is the entry point's FILE OFFSET, not `e_entry`. For an
    // executable the virtual address is mapped back through the segment that
    // contains it; a relocatable object has no segments, so the section table is
    // used instead. Left undefined when nothing maps it, rather than reported as
    // the unmapped virtual address.
    if let Some(off) = entry_point_offset_from(elf) {
        ins(&mut f, "entry_point", off);
    }

    let mut sections = Vec::with_capacity(elf.section_headers.len());
    for sh in elf.section_headers.iter() {
        let mut s = Fields::new();
        let name = elf
            .shdr_strtab
            .get_at(sh.sh_name)
            .unwrap_or_default()
            .as_bytes()
            .to_vec();
        s.insert("name".into(), Value::Str(name));
        s.insert("type".into(), Value::Int(sh.sh_type as i64));
        s.insert("flags".into(), Value::Int(sh.sh_flags as i64));
        s.insert("address".into(), Value::Int(sh.sh_addr as i64));
        s.insert("size".into(), Value::Int(sh.sh_size as i64));
        s.insert("offset".into(), Value::Int(sh.sh_offset as i64));
        sections.push(Value::Struct(Rc::new(s)));
    }
    f.insert("sections".into(), Value::Array(Rc::new(sections)));

    let mut segments = Vec::with_capacity(elf.program_headers.len());
    for ph in elf.program_headers.iter() {
        let mut s = Fields::new();
        s.insert("type".into(), Value::Int(ph.p_type as i64));
        s.insert("flags".into(), Value::Int(ph.p_flags as i64));
        s.insert("offset".into(), Value::Int(ph.p_offset as i64));
        s.insert("virtual_address".into(), Value::Int(ph.p_vaddr as i64));
        s.insert("physical_address".into(), Value::Int(ph.p_paddr as i64));
        s.insert("file_size".into(), Value::Int(ph.p_filesz as i64));
        s.insert("memory_size".into(), Value::Int(ph.p_memsz as i64));
        s.insert("alignment".into(), Value::Int(ph.p_align as i64));
        segments.push(Value::Struct(Rc::new(s)));
    }
    f.insert("segments".into(), Value::Array(Rc::new(segments)));

    // `.dynamic` entries. YARA exposes the count only when the section exists,
    // so an object without one leaves both undefined rather than reporting 0.
    if let Some(dynamic) = &elf.dynamic {
        let mut dyns = Vec::with_capacity(dynamic.dyns.len());
        for d in &dynamic.dyns {
            let mut s = Fields::new();
            s.insert("type".into(), Value::Int(d.d_tag as i64));
            s.insert("val".into(), Value::Int(d.d_val as i64));
            dyns.push(Value::Struct(Rc::new(s)));
        }
        ins(&mut f, "dynamic_section_entries", dyns.len() as i64);
        f.insert("dynamic".into(), Value::Array(Rc::new(dyns)));
    }

    let symtab = build_symbols(&elf.syms, &elf.strtab);
    if !symtab.is_empty() {
        ins(&mut f, "symtab_entries", symtab.len() as i64);
        f.insert("symtab".into(), Value::Array(Rc::new(symtab)));
    }
    let dynsym = build_symbols(&elf.dynsyms, &elf.dynstrtab);
    if !dynsym.is_empty() {
        ins(&mut f, "dynsym_entries", dynsym.len() as i64);
        f.insert("dynsym".into(), Value::Array(Rc::new(dynsym)));
    }

    let _ = data;
    Value::Struct(Rc::new(f))
}

fn build_symbols(syms: &goblin::elf::Symtab, strtab: &goblin::strtab::Strtab) -> Vec<Value> {
    let mut out = Vec::with_capacity(syms.len());
    for sym in syms.iter() {
        let mut s = Fields::new();
        let name = strtab
            .get_at(sym.st_name)
            .unwrap_or_default()
            .as_bytes()
            .to_vec();
        s.insert("name".into(), Value::Str(name));
        s.insert("value".into(), Value::Int(sym.st_value as i64));
        s.insert("size".into(), Value::Int(sym.st_size as i64));
        // `st_info` packs bind in the high nibble and type in the low nibble.
        s.insert("type".into(), Value::Int((sym.st_info & 0x0f) as i64));
        s.insert("bind".into(), Value::Int((sym.st_info >> 4) as i64));
        s.insert("shndx".into(), Value::Int(sym.st_shndx as i64));
        out.push(Value::Struct(Rc::new(s)));
    }
    out
}

/// Maps `e_entry` (a virtual address) back to a file offset, the way YARA
/// reports `elf.entry_point`.
fn entry_point_offset_from(elf: &goblin::elf::Elf) -> Option<i64> {
    let entry = elf.header.e_entry;
    // ET_EXEC / ET_DYN: find the PT_LOAD segment covering the entry VA.
    for ph in elf.program_headers.iter() {
        if ph.p_type == goblin::elf::program_header::PT_LOAD
            && entry >= ph.p_vaddr
            && entry < ph.p_vaddr.saturating_add(ph.p_memsz)
        {
            return Some((ph.p_offset + (entry - ph.p_vaddr)) as i64);
        }
    }
    // ET_REL has no segments: fall back to the section that covers the entry.
    for sh in elf.section_headers.iter() {
        if sh.sh_flags & u64::from(goblin::elf::section_header::SHF_ALLOC) != 0
            && entry >= sh.sh_addr
            && entry < sh.sh_addr.saturating_add(sh.sh_size)
        {
            return Some((sh.sh_offset + (entry - sh.sh_addr)) as i64);
        }
    }
    None
}

/// `elf.entry_point` for a standalone caller (mirrors `pe::entry_point_offset`).
#[cfg(test)]
pub(crate) fn entry_point_offset(data: &[u8]) -> Option<i64> {
    goblin::elf::Elf::parse(data)
        .ok()
        .and_then(|e| entry_point_offset_from(&e))
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
    /// variables)` — 1 for an array.
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
const SYMBOL_FIELDS: &[&str] = &["name", "value", "size", "type", "bind", "shndx"];

// ---------------------------------------------------------------------------
// Enum constants (accessed as `elf.<NAME>`; yara-x inlines these into the
// module namespace). Values are from the System V gABI / Linux `elf.h`.
// ---------------------------------------------------------------------------

pub(crate) fn constant(name: &str) -> Option<i64> {
    Some(match name {
        // e_type
        "ET_NONE" => 0,
        "ET_REL" => 1,
        "ET_EXEC" => 2,
        "ET_DYN" => 3,
        "ET_CORE" => 4,

        // e_machine (the subset YARA exposes)
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
        "EM_PPC" => 20,
        "EM_PPC64" => 21,
        "EM_ARM" => 40,
        "EM_X86_64" => 62,
        "EM_AARCH64" => 183,

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

        // NOTE: no `SHF_*` here, and no `EM_*` beyond the list above. The real
        // yara-x `elf` module does not define them, and exav must not be a
        // *superset*: a rule written against a constant only exav accepts would
        // compile here and fail on real YARA, which is the wrong direction for a
        // drop-in. Verified by the differential test against yara-x.

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
        "PF_X" => 0x1,
        "PF_W" => 0x2,
        "PF_R" => 0x4,

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

        _ => return None,
    })
}
