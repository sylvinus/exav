//! The `pe` module, backed by the pure-Rust `goblin` PE parser.
//!
//! Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X. Field
//! semantics (e.g. `entry_point` being a *file offset*, `number_of_imports`
//! counting DLLs, the `rva_to_offset` algorithm, and the imphash construction)
//! are ported from yara-x's `lib/src/modules/pe/`.
//!
//! Only the fields and functions listed in [`validate_access`] / [`resolve_func`]
//! are implemented; any other `pe.*` field or function is an explicit compile
//! error so that coverage gaps are visible rather than silently undefined.

use std::cmp::{max, min};
use std::rc::Rc;

use md5::{Digest, Md5};

use super::{FieldName, FuncId};
use crate::yara::error::{Error, Result};
use crate::yara::ir::{Fields, Value};

/// Extra parsed PE state needed by functions (imphash / imports / exports /
/// section_index). Grouped by DLL, preserving parse order.
pub(crate) struct PeExtra {
    is_pe: bool,
    /// One entry per imported DLL, in first-seen order: (dll_name, functions).
    imports: Vec<(String, Vec<ImpFunc>)>,
    exports: Vec<ExpFunc>,
    section_names: Vec<Vec<u8>>,
}

struct ImpFunc {
    name: Option<String>,
    ordinal: u16,
}

struct ExpFunc {
    name: Option<String>,
    ordinal: u32,
}

// ---------------------------------------------------------------------------
// Building the module value tree
// ---------------------------------------------------------------------------

/// Parses `data` and returns the `pe` root value plus the extra state used by
/// PE functions. For non-PE inputs the root is `{ is_pe: false }`.
pub(crate) fn build(data: &[u8]) -> (Value, PeExtra) {
    match goblin::pe::PE::parse(data) {
        Ok(pe) => build_pe(data, &pe),
        Err(_) => {
            let mut f = Fields::new();
            f.insert("is_pe".into(), Value::Bool(false));
            (
                Value::Struct(Rc::new(f)),
                PeExtra {
                    is_pe: false,
                    imports: Vec::new(),
                    exports: Vec::new(),
                    section_names: Vec::new(),
                },
            )
        }
    }
}

fn build_pe(_data: &[u8], pe: &goblin::pe::PE) -> (Value, PeExtra) {
    let coff = &pe.header.coff_header;
    let mut f = Fields::new();
    let ins = |f: &mut Fields, k: &str, v: i64| {
        f.insert(k.into(), Value::Int(v));
    };

    f.insert("is_pe".into(), Value::Bool(true));
    ins(&mut f, "machine", coff.machine as i64);
    ins(&mut f, "characteristics", coff.characteristics as i64);
    ins(&mut f, "timestamp", coff.time_date_stamp as i64);
    ins(
        &mut f,
        "pointer_to_symbol_table",
        coff.pointer_to_symbol_table as i64,
    );
    ins(
        &mut f,
        "number_of_symbols",
        coff.number_of_symbol_table as i64,
    );
    ins(
        &mut f,
        "size_of_optional_header",
        coff.size_of_optional_header as i64,
    );
    // yara-x reports the *actual* number of parsed sections.
    ins(&mut f, "number_of_sections", pe.sections.len() as i64);

    // Section array + collect raw names for section_index().
    let mut sections = Vec::with_capacity(pe.sections.len());
    let mut section_names = Vec::with_capacity(pe.sections.len());
    for s in &pe.sections {
        let name = trim_name(&s.name);
        section_names.push(name.clone());
        let mut sf = Fields::new();
        sf.insert("name".into(), Value::Str(name.clone()));
        sf.insert("full_name".into(), Value::Str(name));
        ins(&mut sf, "virtual_address", s.virtual_address as i64);
        ins(&mut sf, "virtual_size", s.virtual_size as i64);
        ins(&mut sf, "raw_data_size", s.size_of_raw_data as i64);
        ins(&mut sf, "raw_data_offset", s.pointer_to_raw_data as i64);
        ins(&mut sf, "characteristics", s.characteristics as i64);
        ins(
            &mut sf,
            "pointer_to_relocations",
            s.pointer_to_relocations as i64,
        );
        ins(
            &mut sf,
            "pointer_to_line_numbers",
            s.pointer_to_linenumbers as i64,
        );
        ins(
            &mut sf,
            "number_of_relocations",
            s.number_of_relocations as i64,
        );
        ins(
            &mut sf,
            "number_of_line_numbers",
            s.number_of_linenumbers as i64,
        );
        sections.push(Value::Struct(Rc::new(sf)));
    }
    f.insert("sections".into(), Value::Array(Rc::new(sections)));

    if let Some(opt) = &pe.header.optional_header {
        let std = &opt.standard_fields;
        let win = &opt.windows_fields;
        ins(&mut f, "opthdr_magic", std.magic as i64);
        ins(&mut f, "entry_point_raw", std.address_of_entry_point as i64);
        if let Some(off) = rva_to_offset(
            std.address_of_entry_point,
            &pe.sections,
            win.file_alignment,
            win.section_alignment,
        ) {
            ins(&mut f, "entry_point", off as i64);
        }
        ins(&mut f, "base_of_code", std.base_of_code as i64);
        ins(&mut f, "size_of_code", std.size_of_code as i64);
        ins(&mut f, "image_base", win.image_base as i64);
        ins(&mut f, "subsystem", win.subsystem as i64);
        ins(
            &mut f,
            "dll_characteristics",
            win.dll_characteristics as i64,
        );
        ins(&mut f, "checksum", win.check_sum as i64);
        ins(&mut f, "size_of_image", win.size_of_image as i64);
        ins(&mut f, "size_of_headers", win.size_of_headers as i64);
        ins(&mut f, "section_alignment", win.section_alignment as i64);
        ins(&mut f, "file_alignment", win.file_alignment as i64);

        f.insert(
            "linker_version".into(),
            version(
                std.major_linker_version as i64,
                std.minor_linker_version as i64,
            ),
        );
        f.insert(
            "os_version".into(),
            version(
                win.major_operating_system_version as i64,
                win.minor_operating_system_version as i64,
            ),
        );
        f.insert(
            "image_version".into(),
            version(
                win.major_image_version as i64,
                win.minor_image_version as i64,
            ),
        );
        f.insert(
            "subsystem_version".into(),
            version(
                win.major_subsystem_version as i64,
                win.minor_subsystem_version as i64,
            ),
        );
    }

    // Group imports by DLL, preserving first-seen order.
    let mut imports: Vec<(String, Vec<ImpFunc>)> = Vec::new();
    for imp in &pe.imports {
        let dll = imp.dll.to_string();
        let entry = match imports.iter_mut().find(|(d, _)| *d == dll) {
            Some(e) => e,
            None => {
                imports.push((dll, Vec::new()));
                imports.last_mut().unwrap()
            }
        };
        entry.1.push(ImpFunc {
            name: Some(imp.name.to_string()),
            ordinal: imp.ordinal,
        });
    }
    let num_imported_functions: usize = imports.iter().map(|(_, fns)| fns.len()).sum();
    ins(&mut f, "number_of_imports", imports.len() as i64);
    ins(
        &mut f,
        "number_of_imported_functions",
        num_imported_functions as i64,
    );

    let mut exports = Vec::new();
    for exp in &pe.exports {
        exports.push(ExpFunc {
            name: exp.name.map(|n| n.to_string()),
            // goblin doesn't surface the ordinal on Export directly; use rva as
            // a placeholder isn't meaningful, so default to 0 (exports-by-name
            // is what real rules use).
            ordinal: 0,
        });
    }
    ins(&mut f, "number_of_exports", pe.exports.len() as i64);

    let extra = PeExtra {
        is_pe: true,
        imports,
        exports,
        section_names,
    };
    (Value::Struct(Rc::new(f)), extra)
}

fn version(major: i64, minor: i64) -> Value {
    let mut v = Fields::new();
    v.insert("major".into(), Value::Int(major));
    v.insert("minor".into(), Value::Int(minor));
    Value::Struct(Rc::new(v))
}

/// Trims trailing NUL padding from an 8-byte section name (yara-x semantics).
fn trim_name(raw: &[u8; 8]) -> Vec<u8> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    raw[..end].to_vec()
}

/// Computes the PE entry-point *file offset* (used by the `entrypoint` keyword
/// and the `pe.entry_point` field). Undefined for non-PE inputs.
///
/// NOTE (Phase 2.3, kept-local decision): this deliberately does NOT delegate to
/// `crate::pe::layout(...).entry`. That function uses a simpler RVA→offset map
/// that is NOT byte-for-byte compatible with yara-x's `pe/rva2off.rs` (which
/// `rva_to_offset` below ports faithfully). The differences are exactly the
/// packed/malformed-PE cases the yara-x A/B differential must stay identical on.
///
/// - A header-resident EP (`rva < lowest section RVA`) is defined here as `rva`
///   itself, but `layout()` returns `None`.
/// - yara-x rounds the section raw pointer down to `min(file_alignment, 0x200)`
///   and (when `section_alignment >= 0x1000`) to `0x200`; `layout()` uses the raw
///   `PointerToRawData` verbatim.
/// - The undefined boundary here is `size_of_raw_data`, vs `layout()`'s
///   `max(virtual_size, size_of_raw_data)`.
///
/// Delegating to `layout()` would keep the single-fixture difftest green while
/// silently regressing yara-x parity on real inputs, so we keep this version.
pub(crate) fn entry_point_offset(data: &[u8]) -> Option<i64> {
    let pe = goblin::pe::PE::parse(data).ok()?;
    let opt = pe.header.optional_header.as_ref()?;
    let off = rva_to_offset(
        opt.standard_fields.address_of_entry_point,
        &pe.sections,
        opt.windows_fields.file_alignment,
        opt.windows_fields.section_alignment,
    )?;
    Some(off as i64)
}

/// Convert an RVA to a file offset. Ported from yara-x's `pe/rva2off.rs`.
fn rva_to_offset(
    rva: u32,
    sections: &[goblin::pe::section_table::SectionTable],
    file_alignment: u32,
    section_alignment: u32,
) -> Option<u32> {
    let lowest_section_rva = sections.iter().map(|s| s.virtual_address).min();
    if matches!(lowest_section_rva, Some(x) if rva < x) {
        return Some(rva);
    }

    let mut section_rva = 0;
    let mut section_offset = 0;
    let mut section_raw_size = 0;

    for s in sections {
        let size = max(s.virtual_size, s.size_of_raw_data);
        let start = s.virtual_address;
        let end = start.saturating_add(size);

        if section_rva <= s.virtual_address && (start..end).contains(&rva) {
            section_rva = s.virtual_address;
            section_offset = s.pointer_to_raw_data;
            section_raw_size = s.size_of_raw_data;

            let file_alignment = min(file_alignment, 0x200);
            if let Some(rem) = section_offset.checked_rem(file_alignment) {
                section_offset -= rem;
            }
            if section_alignment >= 0x1000 {
                section_offset = section_offset.saturating_sub(section_offset % 0x200);
            }
        }
    }

    if rva.saturating_sub(section_rva) >= section_raw_size {
        return None;
    }
    Some(section_offset.saturating_add(rva - section_rva))
}

// ---------------------------------------------------------------------------
// Function dispatch
// ---------------------------------------------------------------------------

pub(crate) fn call(func: FuncId, extra: Option<&PeExtra>, args: &[Value]) -> Option<Value> {
    let extra = extra?;
    match func {
        FuncId::PeImphash => imphash(extra),
        FuncId::PeImportsDll => {
            let dll = args[0].as_bytes()?;
            let count: i64 = extra
                .imports
                .iter()
                .filter(|(d, _)| d.as_bytes().eq_ignore_ascii_case(dll))
                .map(|(_, fns)| fns.len() as i64)
                .sum();
            Some(Value::Int(count))
        }
        FuncId::PeImportsFunc => {
            let dll = args[0].as_bytes()?;
            let fname = args[1].as_bytes()?;
            let found = extra
                .imports
                .iter()
                .filter(|(d, _)| d.as_bytes().eq_ignore_ascii_case(dll))
                .flat_map(|(_, fns)| fns.iter())
                .any(|fun| {
                    fun.name
                        .as_ref()
                        .is_some_and(|n| n.as_bytes().eq_ignore_ascii_case(fname))
                });
            Some(Value::Bool(found))
        }
        FuncId::PeImportsOrdinal => {
            let dll = args[0].as_bytes()?;
            let ordinal = args[1].to_i64()?;
            let count: i64 = extra
                .imports
                .iter()
                .filter(|(d, _)| d.as_bytes().eq_ignore_ascii_case(dll))
                .flat_map(|(_, fns)| fns.iter())
                .filter(|fun| fun.ordinal as i64 == ordinal)
                .count() as i64;
            Some(Value::Int(count))
        }
        FuncId::PeExportsFunc => {
            let fname = args[0].as_bytes()?;
            let found = extra.exports.iter().any(|e| {
                e.name
                    .as_ref()
                    .is_some_and(|n| n.as_bytes().eq_ignore_ascii_case(fname))
            });
            Some(Value::Bool(found))
        }
        FuncId::PeExportsOrdinal => {
            let ordinal = args[0].to_i64()?;
            let found = extra.exports.iter().any(|e| e.ordinal as i64 == ordinal);
            Some(Value::Bool(found))
        }
        FuncId::PeSectionIndexName => {
            let name = args[0].as_bytes()?;
            extra
                .section_names
                .iter()
                .position(|n| n == name)
                .map(|i| Value::Int(i as i64))
        }
        _ => unreachable!("non-pe FuncId dispatched to pe::call"),
    }
}

/// The import hash. Ported from yara-x: DLL names lowercased and stripped of
/// `.dll`/`.sys`/`.ocx`, function names lowercased, entries joined `dll.func`
/// with commas, then MD5-hashed.
fn imphash(extra: &PeExtra) -> Option<Value> {
    if !extra.is_pe {
        return None;
    }
    let mut hasher = Md5::new();
    let mut first = true;
    for (dll, fns) in &extra.imports {
        let dll = trim_library_extension(dll);
        for fun in fns {
            let Some(name) = &fun.name else { continue };
            if !first {
                Digest::update(&mut hasher, b",");
            }
            Digest::update(&mut hasher, dll.to_ascii_lowercase().as_bytes());
            Digest::update(&mut hasher, b".");
            Digest::update(&mut hasher, name.to_ascii_lowercase().as_bytes());
            first = false;
        }
    }
    let digest = hasher.finalize();
    let mut out = Vec::with_capacity(32);
    for b in digest.iter() {
        out.push(hex_nibble(b >> 4));
        out.push(hex_nibble(b & 0xf));
    }
    Some(Value::Str(out))
}

fn hex_nibble(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

fn trim_library_extension(name: &str) -> &str {
    for ext in [".dll", ".sys", ".ocx"] {
        let nb = name.as_bytes();
        let eb = ext.as_bytes();
        if nb.len() >= eb.len() && nb[nb.len() - eb.len()..].eq_ignore_ascii_case(eb) {
            return &name[..nb.len() - eb.len()];
        }
    }
    name
}

// ---------------------------------------------------------------------------
// Compile-time schema validation
// ---------------------------------------------------------------------------

/// Node types encountered while walking a `pe.*` field-access chain. Exposed to
/// the compiler so it can type loop/`with` variables bound to `pe` sub-values
/// (e.g. `for any s in pe.sections : (s.name == ".text")`).
#[derive(Clone, Copy)]
pub(crate) enum Node {
    Root,
    Version,
    SectionsArray,
    Section,
    Scalar,
}

impl Node {
    /// The starting node for a `pe.*` chain.
    pub(crate) fn root() -> Node {
        Node::Root
    }

    /// A scalar node cannot be navigated further; it can be used as a value.
    pub(crate) fn is_scalar(self) -> bool {
        matches!(self, Node::Scalar)
    }

    /// Navigates `.field`, returning the resulting node or a compile error for
    /// an unknown/unsupported field.
    pub(crate) fn field(self, name: &str) -> Result<Node> {
        Ok(match self {
            Node::Root => root_field(name)?,
            Node::Version => {
                if name == "major" || name == "minor" {
                    Node::Scalar
                } else {
                    return Err(unsupported(name));
                }
            }
            Node::Section => {
                if SECTION_FIELDS.contains(&name) {
                    Node::Scalar
                } else {
                    return Err(unsupported(name));
                }
            }
            Node::SectionsArray | Node::Scalar => return Err(unsupported(name)),
        })
    }

    /// Navigates `[…]` (array index / map key), returning the element node.
    pub(crate) fn index(self) -> Result<Node> {
        match self {
            Node::SectionsArray => Ok(Node::Section),
            _ => Err(Error::new("cannot index this pe field (not an array/map)")),
        }
    }

    /// If this node is an array/map, returns `(element node, number of loop
    /// variables)` — 1 for an array, 2 for a map. `pe.sections` is the only
    /// iterable exposed today.
    pub(crate) fn iterable(self) -> Option<(Node, usize)> {
        match self {
            Node::SectionsArray => Some((Node::Section, 1)),
            _ => None,
        }
    }
}

/// Validates a `pe` field-access chain, rejecting unknown/unsupported fields.
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
    if ROOT_SCALARS.contains(&name) {
        Ok(Node::Scalar)
    } else if matches!(
        name,
        "os_version" | "subsystem_version" | "image_version" | "linker_version"
    ) {
        Ok(Node::Version)
    } else if name == "sections" {
        Ok(Node::SectionsArray)
    } else {
        Err(unsupported(name))
    }
}

fn unsupported(field: &str) -> Error {
    Error::new(format!("unsupported pe field: {field}"))
}

const ROOT_SCALARS: &[&str] = &[
    "is_pe",
    "machine",
    "number_of_sections",
    "characteristics",
    "dll_characteristics",
    "subsystem",
    "entry_point",
    "entry_point_raw",
    "image_base",
    "timestamp",
    "checksum",
    "opthdr_magic",
    "base_of_code",
    "size_of_code",
    "size_of_image",
    "size_of_headers",
    "size_of_optional_header",
    "section_alignment",
    "file_alignment",
    "pointer_to_symbol_table",
    "number_of_symbols",
    "number_of_imports",
    "number_of_imported_functions",
    "number_of_exports",
];

const SECTION_FIELDS: &[&str] = &[
    "name",
    "full_name",
    "virtual_address",
    "virtual_size",
    "raw_data_size",
    "raw_data_offset",
    "characteristics",
    "pointer_to_relocations",
    "pointer_to_line_numbers",
    "number_of_relocations",
    "number_of_line_numbers",
];

// ---------------------------------------------------------------------------
// Enum constants (accessed as `pe.<NAME>`; yara-x inlines these into the
// module namespace).
// ---------------------------------------------------------------------------

pub(crate) fn constant(name: &str) -> Option<i64> {
    Some(match name {
        // Machine
        "MACHINE_UNKNOWN" => 0x0000,
        "MACHINE_AM33" => 0x01d3,
        "MACHINE_AMD64" => 0x8664,
        "MACHINE_ARM" => 0x01c0,
        "MACHINE_ARM64" => 0xaa64,
        "MACHINE_ARMNT" => 0x01c4,
        "MACHINE_EBC" => 0x0ebc,
        "MACHINE_I386" => 0x014c,
        "MACHINE_IA64" => 0x0200,
        "MACHINE_M32R" => 0x9041,
        "MACHINE_MIPS16" => 0x0266,
        "MACHINE_MIPSFPU" => 0x0366,
        "MACHINE_MIPSFPU16" => 0x0466,
        "MACHINE_POWERPC" => 0x01f0,
        "MACHINE_POWERPCFP" => 0x01f1,
        "MACHINE_R4000" => 0x0166,
        "MACHINE_SH3" => 0x01a2,
        "MACHINE_SH3DSP" => 0x01a3,
        "MACHINE_SH4" => 0x01a6,
        "MACHINE_SH5" => 0x01a8,
        "MACHINE_THUMB" => 0x01c2,
        "MACHINE_WCEMIPSV2" => 0x0169,
        // Subsystem
        "SUBSYSTEM_UNKNOWN" => 0,
        "SUBSYSTEM_NATIVE" => 1,
        "SUBSYSTEM_WINDOWS_GUI" => 2,
        "SUBSYSTEM_WINDOWS_CUI" => 3,
        "SUBSYSTEM_OS2_CUI" => 5,
        "SUBSYSTEM_POSIX_CUI" => 7,
        "SUBSYSTEM_NATIVE_WINDOWS" => 8,
        "SUBSYSTEM_WINDOWS_CE_GUI" => 9,
        "SUBSYSTEM_EFI_APPLICATION" => 10,
        "SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER" => 11,
        "SUBSYSTEM_EFI_RUNTIME_DRIVER" => 12,
        "SUBSYSTEM_EFI_ROM_IMAGE" => 13,
        "SUBSYSTEM_XBOX" => 14,
        "SUBSYSTEM_WINDOWS_BOOT_APPLICATION" => 16,
        // Characteristics
        "RELOCS_STRIPPED" => 0x0001,
        "EXECUTABLE_IMAGE" => 0x0002,
        "LINE_NUMS_STRIPPED" => 0x0004,
        "LOCAL_SYMS_STRIPPED" => 0x0008,
        "AGGRESIVE_WS_TRIM" => 0x0010,
        "LARGE_ADDRESS_AWARE" => 0x0020,
        "BYTES_REVERSED_LO" => 0x0080,
        "MACHINE_32BIT" => 0x0100,
        "DEBUG_STRIPPED" => 0x0200,
        "REMOVABLE_RUN_FROM_SWAP" => 0x0400,
        "NET_RUN_FROM_SWAP" => 0x0800,
        "SYSTEM" => 0x1000,
        "DLL" => 0x2000,
        "UP_SYSTEM_ONLY" => 0x4000,
        "BYTES_REVERSED_HI" => 0x8000,
        // DllCharacteristics
        "HIGH_ENTROPY_VA" => 0x0020,
        "DYNAMIC_BASE" => 0x0040,
        "FORCE_INTEGRITY" => 0x0080,
        "NX_COMPAT" => 0x0100,
        "NO_ISOLATION" => 0x0200,
        "NO_SEH" => 0x0400,
        "NO_BIND" => 0x0800,
        "APPCONTAINER" => 0x1000,
        "WDM_DRIVER" => 0x2000,
        "GUARD_CF" => 0x4000,
        "TERMINAL_SERVER_AWARE" => 0x8000,
        // OptionalMagic
        "IMAGE_NT_OPTIONAL_HDR32_MAGIC" => 0x10b,
        "IMAGE_NT_OPTIONAL_HDR64_MAGIC" => 0x20b,
        "IMAGE_ROM_OPTIONAL_HDR_MAGIC" => 0x107,
        // ImportFlags
        "IMPORT_STANDARD" => 0x01,
        "IMPORT_DELAYED" => 0x02,
        "IMPORT_ANY" => 0x03,
        // A handful of common SectionCharacteristics flags.
        "SECTION_CNT_CODE" => 0x00000020,
        "SECTION_CNT_INITIALIZED_DATA" => 0x00000040,
        "SECTION_CNT_UNINITIALIZED_DATA" => 0x00000080,
        "SECTION_MEM_DISCARDABLE" => 0x02000000,
        "SECTION_MEM_EXECUTE" => 0x20000000,
        "SECTION_MEM_READ" => 0x40000000,
        "SECTION_MEM_WRITE" => 0x80000000u32 as i64,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    /// A hand-crafted minimal but valid PE32 with one `.text` section importing
    /// `ExitProcess` from `kernel32.dll` (see tests/testdata/gen_pe.py notes in
    /// the difftest). Entry point RVA 0x1000 -> file offset 0x200.
    const PE: &[u8] = include_bytes!("../testdata/tiny_pe32.exe");

    fn t(cond: &str, data: &[u8]) -> bool {
        let src = format!("import \"pe\" rule r {{ condition: {cond} }}");
        let rules = crate::yara::compile(&src).expect("compile");
        rules.scan(data).matching_rules().len() == 1
    }

    #[test]
    fn header_fields() {
        assert!(t("pe.is_pe", PE));
        assert!(t("pe.machine == pe.MACHINE_I386", PE));
        assert!(t("pe.machine == 0x14c", PE));
        assert!(t("pe.number_of_sections == 1", PE));
        assert!(t("pe.characteristics == 0x102", PE));
        assert!(t("pe.characteristics & pe.EXECUTABLE_IMAGE != 0", PE));
        assert!(t("pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI", PE));
        assert!(t("pe.dll_characteristics == 0x8140", PE));
        assert!(t("pe.image_base == 0x400000", PE));
        assert!(t("pe.timestamp == 0x5A6B7C8D", PE));
        assert!(t("pe.opthdr_magic == pe.IMAGE_NT_OPTIONAL_HDR32_MAGIC", PE));
        assert!(t("pe.entry_point_raw == 0x1000", PE));
        assert!(t("pe.entry_point == 0x200", PE));
        assert!(t("pe.linker_version.major == 0", PE));
    }

    #[test]
    fn sections() {
        assert!(t("pe.sections[0].name == \".text\"", PE));
        assert!(t("pe.sections[0].virtual_address == 0x1000", PE));
        assert!(t("pe.sections[0].raw_data_offset == 0x200", PE));
        assert!(t("pe.sections[0].raw_data_size == 0x200", PE));
        assert!(t(
            "pe.sections[0].characteristics & pe.SECTION_MEM_EXECUTE != 0",
            PE
        ));
        // Out-of-bounds section index is undefined.
        assert!(t("not defined pe.sections[5].name", PE));
    }

    #[test]
    fn imports_and_exports() {
        assert!(t("pe.number_of_imports == 1", PE));
        assert!(t("pe.number_of_imported_functions == 1", PE));
        assert!(t("pe.number_of_exports == 0", PE));
        assert!(t("pe.imports(\"kernel32.dll\") == 1", PE));
        assert!(t("pe.imports(\"KERNEL32.DLL\") == 1", PE));
        assert!(t("pe.imports(\"kernel32.dll\", \"ExitProcess\")", PE));
        assert!(t("pe.imports(\"kernel32.dll\", \"exitprocess\")", PE));
        assert!(!t("pe.imports(\"kernel32.dll\", \"NoSuchFunc\")", PE));
        assert!(!t("pe.exports(\"ExitProcess\")", PE));
    }

    #[test]
    fn imphash() {
        assert!(t(
            "pe.imphash() == \"f9ade0aa18f660a34a4fa23392e21838\"",
            PE
        ));
    }

    #[test]
    fn entrypoint_keyword() {
        assert!(t("entrypoint == 0x200", PE));
    }

    #[test]
    fn non_pe_is_undefined() {
        assert!(t("not pe.is_pe", b"not a pe file at all"));
        assert!(t("not defined pe.machine", b"not a pe file at all"));
        assert!(t("not defined pe.imphash()", b"not a pe file at all"));
        assert!(t("not defined entrypoint", b"not a pe file at all"));
    }
}
