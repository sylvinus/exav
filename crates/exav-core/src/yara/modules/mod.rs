//! YARA modules: per-scan structured values, integer/field access, and
//! function dispatch.
//!
//! The engine is self-contained: modules are implemented natively in-crate
//! rather than via the wasm module ABI that yara-x uses. Each imported module
//! parses the scanned bytes once per scan and produces a [`Value`] tree (see
//! [`crate::yara::ir::Value`]); rule conditions resolve field accesses against that
//! tree and dispatch function calls to native Rust implementations here.
//!
//! Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X.

use std::borrow::Cow;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::byte_source::ByteSource;
use crate::yara::error::{Error, Result};
use crate::yara::ir::{Cond, EvalCtx, Value};

pub(crate) mod dotnet;
pub(crate) mod elf;
pub(crate) mod hash;
pub(crate) mod math;
pub(crate) mod pe;
pub(crate) mod stringmod;
pub(crate) mod timemod;

/// The modules the engine understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum ModuleKind {
    Math,
    Hash,
    StringMod,
    Time,
    Pe,
    Elf,
    DotNet,
}

impl ModuleKind {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "math" => ModuleKind::Math,
            "hash" => ModuleKind::Hash,
            "string" => ModuleKind::StringMod,
            "time" => ModuleKind::Time,
            "pe" => ModuleKind::Pe,
            "elf" => ModuleKind::Elf,
            "dotnet" => ModuleKind::DotNet,
            _ => return None,
        })
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            ModuleKind::Math => "math",
            ModuleKind::Hash => "hash",
            ModuleKind::StringMod => "string",
            ModuleKind::Time => "time",
            ModuleKind::Pe => "pe",
            ModuleKind::Elf => "elf",
            ModuleKind::DotNet => "dotnet",
        }
    }
}

/// The bytes that the module values copy out of the object. A name that many
/// entries refer to (an import name that thousands of thunks point at, a
/// string of a table that thousands of rows index) is copied for each of
/// them, so a crafted object makes the copies many times its own size. They
/// are charged to a limit (`--max-object-bytes`), and from the first that
/// does not fit nothing more is copied.
pub(crate) struct Copies {
    left: std::cell::Cell<usize>,
    cut: std::cell::Cell<bool>,
}

impl Copies {
    pub(crate) fn new(limit: usize) -> Self {
        Copies {
            left: std::cell::Cell::new(limit),
            cut: std::cell::Cell::new(false),
        }
    }

    /// Whether `n` more bytes may be copied; if not, none may be, then or later.
    pub(crate) fn take(&self, n: usize) -> bool {
        if self.cut.get() {
            return false;
        }
        match self.left.get().checked_sub(n) {
            Some(left) => {
                self.left.set(left);
                true
            }
            None => {
                self.cut.set(true);
                false
            }
        }
    }

    /// Some copy was refused, so the values are not all of the object's.
    pub(crate) fn cut(&self) -> bool {
        self.cut.get()
    }

    /// The bytes that may still be copied.
    pub(crate) fn room(&self) -> usize {
        self.left.get()
    }
}

// ---------------------------------------------------------------------------
// Per-scan module state
// ---------------------------------------------------------------------------

/// Holds each imported module's value tree plus a small amount of extra parsed
/// state (the PE import/export tables, needed by `pe.imphash()`/`pe.imports()`,
/// and the `entrypoint` file offset). Built once per scan.
pub(crate) struct ModuleCtx {
    roots: HashMap<ModuleKind, Value>,
    pub entry_point: Option<i64>,
    pe: Option<pe::PeExtra>,
}

impl ModuleCtx {
    /// Builds the module state for one scan. `imported` lists the modules the
    /// rule set imported; `need_entrypoint` is set when any rule uses the
    /// `entrypoint` keyword (which needs a PE parse even without `import "pe"`).
    ///
    /// The format parsers read the object in memory. One not held there is
    /// read whole when it is at most `materialize` bytes. A larger one gives
    /// each parser the part of it that holds its format's structure (a PE's
    /// image, [`crate::pe::image_in`]; an ELF's, [`crate::pe::elf_image_in`]),
    /// when that is at most `materialize` bytes. For a format whose part is
    /// longer, or cannot be found, it gets the value the parser gives when the
    /// object is not of its format, which is exact when the object does not
    /// start with that format's magic, and the build is otherwise incomplete
    /// (the `bool`).
    ///
    /// The values copy names out of the object, at most `materialize` bytes
    /// of them in all; the build is incomplete when it had to stop copying.
    /// It is incomplete too when the `pe` module could not read a table of the
    /// PE. If the parser had the whole object, that table is malformed, and the
    /// scan is marked unreadable rather than only incomplete: no limit makes it
    /// readable. `carved` says the object was cut out of a host at an offset.
    pub(crate) fn build(
        src: &dyn ByteSource,
        imported: &[ModuleKind],
        need_entrypoint: bool,
        materialize: usize,
        carved: bool,
    ) -> (Self, bool) {
        let wants_pe = need_entrypoint
            || imported.contains(&ModuleKind::Pe)
            || imported.contains(&ModuleKind::DotNet);
        let wants_elf = imported.contains(&ModuleKind::Elf);
        let whole = if wants_pe || wants_elf {
            src.materialize(materialize)
        } else {
            None
        };
        let mut complete = true;
        let (pe_data, elf_data) = match &whole {
            Some(data) => (Cow::Borrowed(&data[..]), Cow::Borrowed(&data[..])),
            None => {
                let head = src.window(0, 4);
                let none = || Some(Cow::Borrowed(&[][..]));
                let pe = if wants_pe && head.starts_with(b"MZ") {
                    crate::pe::image_in(src, materialize)
                } else {
                    none()
                };
                let elf = if wants_elf && head.starts_with(b"\x7fELF") {
                    crate::pe::elf_image_in(src, materialize)
                } else {
                    none()
                };
                complete = pe.is_some() && elf.is_some();
                (pe.unwrap_or_default(), elf.unwrap_or_default())
            }
        };
        let copies = Copies::new(materialize);
        let ctx = Self::build_from(&pe_data, &elf_data, imported, need_entrypoint, &copies);
        // A table that does not parse from an image may be fine in the object
        // it is cut from, and one too large to parse is a limit. Only a table
        // of the whole object that is malformed is unreadable.
        // An import table that starts past the end of a PE carved out of a
        // host is not in the PE's bytes: nothing was left unread.
        let absent = carved && ctx.pe.as_ref().is_some_and(pe::PeExtra::absent);
        match ctx.pe.as_ref().and_then(pe::PeExtra::unread) {
            _ if absent => {}
            Some((table, crate::pe::Unread::Malformed)) if whole.is_some() => {
                crate::engine::mark_unreadable(|| {
                    format!(
                        "the YARA pe module could not read the {table} table of the PE: it does not parse"
                    )
                });
                complete = false;
            }
            Some(_) => complete = false,
            None => {}
        }
        (ctx, complete && !copies.cut())
    }

    fn build_from(
        pe_data: &[u8],
        elf_data: &[u8],
        imported: &[ModuleKind],
        need_entrypoint: bool,
        copies: &Copies,
    ) -> Self {
        let mut roots = HashMap::new();
        let mut pe_extra = None;

        for &kind in imported {
            match kind {
                ModuleKind::Math => {
                    roots.insert(kind, math::root());
                }
                ModuleKind::Hash => {
                    roots.insert(kind, hash::root());
                }
                ModuleKind::StringMod => {
                    roots.insert(kind, stringmod::root());
                }
                ModuleKind::Time => {
                    roots.insert(kind, timemod::root());
                }
                ModuleKind::Pe => {
                    let (root, extra) = pe::build(pe_data, copies);
                    roots.insert(kind, root);
                    pe_extra = Some(extra);
                }
                ModuleKind::Elf => {
                    roots.insert(kind, elf::build(elf_data, copies));
                }
                ModuleKind::DotNet => {
                    roots.insert(kind, dotnet::build(pe_data, copies));
                }
            }
        }

        let entry_point = if need_entrypoint {
            pe::entry_point_offset(pe_data)
        } else {
            None
        };

        ModuleCtx {
            roots,
            entry_point,
            pe: pe_extra,
        }
    }

    /// An empty state (no modules), used when a rule set imports nothing.
    pub(crate) fn empty() -> Self {
        ModuleCtx {
            roots: HashMap::new(),
            entry_point: None,
            pe: None,
        }
    }

    pub(crate) fn root(&self, kind: ModuleKind) -> Option<&Value> {
        self.roots.get(&kind)
    }

    pub(crate) fn pe_extra(&self) -> Option<&pe::PeExtra> {
        self.pe.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Compile-time field-access resolution
// ---------------------------------------------------------------------------

/// The static type of an argument expression, used for overload resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArgKind {
    Int,
    Float,
    Str,
    Other,
}

pub(crate) fn arg_kind(c: &Cond) -> ArgKind {
    match c {
        Cond::Int(_) => ArgKind::Int,
        Cond::Float(_) => ArgKind::Float,
        Cond::Str(_) => ArgKind::Str,
        _ => ArgKind::Other,
    }
}

/// If `name` (a single field of `module`) names a compile-time constant,
/// returns its folded value.
pub(crate) fn module_constant(module: ModuleKind, name: &str) -> Option<Value> {
    match module {
        ModuleKind::Math => match name {
            "MEAN_BYTES" => Some(Value::Float(127.5)),
            _ => None,
        },
        ModuleKind::Pe => pe::constant(name).map(Value::Int),
        ModuleKind::Elf => elf::constant(name).map(Value::Int),
        _ => None,
    }
}

/// Validates a module data field-access chain at compile time, rejecting
/// unknown/unsupported fields with a descriptive error so coverage gaps are
/// visible rather than silently evaluating to undefined.
pub(crate) fn validate_access(module: ModuleKind, path: &[FieldName]) -> Result<()> {
    match module {
        ModuleKind::Pe => pe::validate_access(path),
        ModuleKind::Elf => elf::validate_access(path),
        ModuleKind::DotNet => dotnet::validate_access(path),
        // These modules expose no data fields (only functions + constants).
        other => {
            if let Some(FieldName::Field(name)) = path.first() {
                Err(Error::new(format!(
                    "unsupported {} field: {name}",
                    other.label()
                )))
            } else {
                Err(Error::new(format!(
                    "unsupported {} field access",
                    other.label()
                )))
            }
        }
    }
}

/// A schema node in whichever module's tree is being navigated. The compiler
/// tracks one of these while lowering a field-access chain (and while typing a
/// loop/`with` variable bound to a module sub-value), so each module can define
/// its own shape without the compiler knowing about any of them.
#[derive(Clone, Copy)]
pub(crate) enum SchemaNode {
    Pe(pe::Node),
    Elf(elf::Node),
    DotNet(dotnet::Node),
}

impl SchemaNode {
    /// The root node for a module's tree, or `None` for the modules that expose
    /// only functions and constants (no navigable data).
    pub(crate) fn root(kind: ModuleKind) -> Option<Self> {
        match kind {
            ModuleKind::Pe => Some(SchemaNode::Pe(pe::Node::root())),
            ModuleKind::Elf => Some(SchemaNode::Elf(elf::Node::root())),
            ModuleKind::DotNet => Some(SchemaNode::DotNet(dotnet::Node::root())),
            _ => None,
        }
    }

    pub(crate) fn is_scalar(self) -> bool {
        match self {
            SchemaNode::Pe(n) => n.is_scalar(),
            SchemaNode::Elf(n) => n.is_scalar(),
            SchemaNode::DotNet(n) => n.is_scalar(),
        }
    }

    pub(crate) fn field(self, name: &str) -> Result<Self> {
        Ok(match self {
            SchemaNode::Pe(n) => SchemaNode::Pe(n.field(name)?),
            SchemaNode::Elf(n) => SchemaNode::Elf(n.field(name)?),
            SchemaNode::DotNet(n) => SchemaNode::DotNet(n.field(name)?),
        })
    }

    pub(crate) fn index(self) -> Result<Self> {
        Ok(match self {
            SchemaNode::Pe(n) => SchemaNode::Pe(n.index()?),
            SchemaNode::Elf(n) => SchemaNode::Elf(n.index()?),
            SchemaNode::DotNet(n) => SchemaNode::DotNet(n.index()?),
        })
    }

    /// `(element node, number of loop variables)` when this node is iterable.
    pub(crate) fn iterable(self) -> Option<(Self, usize)> {
        match self {
            SchemaNode::Pe(n) => n.iterable().map(|(e, k)| (SchemaNode::Pe(e), k)),
            SchemaNode::Elf(n) => n.iterable().map(|(e, k)| (SchemaNode::Elf(e), k)),
            SchemaNode::DotNet(n) => n.iterable().map(|(e, k)| (SchemaNode::DotNet(e), k)),
        }
    }
}

/// A field-access step described by name only (indices are opaque here); used
/// for compile-time schema validation.
pub(crate) enum FieldName {
    Field(String),
    Index,
}

// ---------------------------------------------------------------------------
// Function resolution + dispatch
// ---------------------------------------------------------------------------

/// A resolved module function, identified concretely (overload already chosen).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum FuncId {
    // math
    MathMin,
    MathMax,
    MathAbs,
    MathToNumber,
    MathInRange,
    MathToStringDec,
    MathToStringBase,
    MathEntropyData,
    MathEntropyStr,
    MathMeanData,
    MathMeanStr,
    MathDeviationData,
    MathDeviationStr,
    MathSerialCorrelationData,
    MathSerialCorrelationStr,
    MathMonteCarloPiData,
    MathMonteCarloPiStr,
    MathCountRange,
    MathCountGlobal,
    MathPercentageRange,
    MathPercentageGlobal,
    MathModeGlobal,
    MathModeRange,
    // hash
    HashMd5Data,
    HashMd5Str,
    HashSha1Data,
    HashSha1Str,
    HashSha256Data,
    HashSha256Str,
    HashCrc32Data,
    HashCrc32Str,
    HashChecksum32Data,
    HashChecksum32Str,
    // string
    StringToInt,
    StringToIntBase,
    StringLength,
    // time
    TimeNow,
    // pe
    PeImphash,
    PeImportsDll,
    PeImportsFunc,
    PeImportsOrdinal,
    PeExportsFunc,
    PeExportsOrdinal,
    PeSectionIndexName,
}

/// Resolves a module function call to a concrete [`FuncId`], choosing the
/// correct overload from the argument count and (where needed) static types.
/// Unknown functions or unsupported overloads are compile errors.
pub(crate) fn resolve_func(module: ModuleKind, name: &str, args: &[Cond]) -> Result<FuncId> {
    let kinds: Vec<ArgKind> = args.iter().map(arg_kind).collect();
    let n = args.len();
    let unsupported = || {
        Error::new(format!(
            "unsupported {}.{name}() overload ({n} args)",
            module.label()
        ))
    };
    let unknown = || Error::new(format!("unknown function {}.{name}()", module.label()));

    let id = match module {
        ModuleKind::Math => match (name, n) {
            ("min", 2) => FuncId::MathMin,
            ("max", 2) => FuncId::MathMax,
            ("abs", 1) => FuncId::MathAbs,
            ("to_number", 1) => FuncId::MathToNumber,
            ("in_range", 3) => FuncId::MathInRange,
            ("to_string", 1) => FuncId::MathToStringDec,
            ("to_string", 2) => FuncId::MathToStringBase,
            ("entropy", 2) => FuncId::MathEntropyData,
            ("entropy", 1) => FuncId::MathEntropyStr,
            ("mean", 2) => FuncId::MathMeanData,
            ("mean", 1) => FuncId::MathMeanStr,
            ("deviation", 3) => FuncId::MathDeviationData,
            ("deviation", 2) => FuncId::MathDeviationStr,
            ("serial_correlation", 2) => FuncId::MathSerialCorrelationData,
            ("serial_correlation", 1) => FuncId::MathSerialCorrelationStr,
            ("monte_carlo_pi", 2) => FuncId::MathMonteCarloPiData,
            ("monte_carlo_pi", 1) => FuncId::MathMonteCarloPiStr,
            ("count", 3) => FuncId::MathCountRange,
            ("count", 1) => FuncId::MathCountGlobal,
            ("percentage", 3) => FuncId::MathPercentageRange,
            ("percentage", 1) => FuncId::MathPercentageGlobal,
            ("mode", 0) => FuncId::MathModeGlobal,
            ("mode", 2) => FuncId::MathModeRange,
            (
                "min" | "max" | "abs" | "to_number" | "in_range" | "to_string" | "entropy" | "mean"
                | "deviation" | "serial_correlation" | "monte_carlo_pi" | "count" | "percentage"
                | "mode",
                _,
            ) => return Err(unsupported()),
            _ => return Err(unknown()),
        },
        ModuleKind::Hash => match (name, n) {
            ("md5", 2) => FuncId::HashMd5Data,
            ("md5", 1) => FuncId::HashMd5Str,
            ("sha1", 2) => FuncId::HashSha1Data,
            ("sha1", 1) => FuncId::HashSha1Str,
            ("sha256", 2) => FuncId::HashSha256Data,
            ("sha256", 1) => FuncId::HashSha256Str,
            ("crc32", 2) => FuncId::HashCrc32Data,
            ("crc32", 1) => FuncId::HashCrc32Str,
            ("checksum32", 2) => FuncId::HashChecksum32Data,
            ("checksum32", 1) => FuncId::HashChecksum32Str,
            ("md5" | "sha1" | "sha256" | "crc32" | "checksum32", _) => return Err(unsupported()),
            _ => return Err(unknown()),
        },
        ModuleKind::StringMod => match (name, n) {
            ("to_int", 1) => FuncId::StringToInt,
            ("to_int", 2) => FuncId::StringToIntBase,
            ("length", 1) => FuncId::StringLength,
            ("to_int" | "length", _) => return Err(unsupported()),
            _ => return Err(unknown()),
        },
        ModuleKind::Time => match (name, n) {
            ("now", 0) => FuncId::TimeNow,
            ("now", _) => return Err(unsupported()),
            _ => return Err(unknown()),
        },
        ModuleKind::Pe => match name {
            "imphash" if n == 0 => FuncId::PeImphash,
            "imports" => match kinds.as_slice() {
                [ArgKind::Str] => FuncId::PeImportsDll,
                [ArgKind::Str, ArgKind::Str] => FuncId::PeImportsFunc,
                [ArgKind::Str, ArgKind::Int] => FuncId::PeImportsOrdinal,
                _ => {
                    return Err(Error::new(
                        "unsupported pe.imports() overload (only string dll, \
                         (dll, func) and (dll, ordinal) forms are implemented; \
                         regexp and import_flags forms are not)",
                    ));
                }
            },
            "exports" => match kinds.as_slice() {
                [ArgKind::Str] => FuncId::PeExportsFunc,
                [ArgKind::Int] => FuncId::PeExportsOrdinal,
                _ => {
                    return Err(Error::new(
                        "unsupported pe.exports() overload (only string name and \
                         integer ordinal forms are implemented; the regexp form \
                         is not)",
                    ));
                }
            },
            "section_index" if kinds.as_slice() == [ArgKind::Str] => FuncId::PeSectionIndexName,
            _ => return Err(Error::new(format!("unsupported pe function: {name}()"))),
        },
        // YARA's `elf` module exposes data fields and constants only — it has no
        // functions — so any call is a genuine error, not a coverage gap.
        ModuleKind::Elf => return Err(unknown()),
        ModuleKind::DotNet => return Err(unknown()),
    };
    Ok(id)
}

/// Dispatches a resolved module function at scan time. Returns undefined
/// (`None`) exactly where yara-x would.
pub(crate) fn call(func: FuncId, ctx: &EvalCtx, args: &[Value]) -> Option<Value> {
    use FuncId::*;
    match func {
        MathMin
        | MathMax
        | MathAbs
        | MathToNumber
        | MathInRange
        | MathToStringDec
        | MathToStringBase
        | MathEntropyData
        | MathEntropyStr
        | MathMeanData
        | MathMeanStr
        | MathDeviationData
        | MathDeviationStr
        | MathSerialCorrelationData
        | MathSerialCorrelationStr
        | MathMonteCarloPiData
        | MathMonteCarloPiStr
        | MathCountRange
        | MathCountGlobal
        | MathPercentageRange
        | MathPercentageGlobal
        | MathModeGlobal
        | MathModeRange => math::call(func, ctx.data, args),

        HashMd5Data | HashMd5Str | HashSha1Data | HashSha1Str | HashSha256Data | HashSha256Str
        | HashCrc32Data | HashCrc32Str | HashChecksum32Data | HashChecksum32Str => {
            hash::call(func, ctx.data, args)
        }

        StringToInt | StringToIntBase | StringLength => stringmod::call(func, args),

        TimeNow => timemod::call(func),

        PeImphash | PeImportsDll | PeImportsFunc | PeImportsOrdinal | PeExportsFunc
        | PeExportsOrdinal | PeSectionIndexName => pe::call(func, ctx.modules.pe_extra(), args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_source::BlockCache;

    const PE: &[u8] = include_bytes!("../testdata/tiny_pe32.exe");
    const ELF: &[u8] = include_bytes!("../../../tests/testdata/tiny_elf64");

    fn cached(data: &[u8]) -> BlockCache<std::io::Cursor<Vec<u8>>> {
        BlockCache::with_sizes(std::io::Cursor::new(data.to_vec()), 509, 8 * 509).unwrap()
    }

    /// Whether the `is_pe` of the `pe` module is true, and how many sections
    /// it counts (`None` when the module did not parse a PE).
    fn pe_sections(ctx: &ModuleCtx) -> Option<i64> {
        let Some(Value::Struct(f)) = ctx.root(ModuleKind::Pe) else {
            return None;
        };
        match (f.get("is_pe"), f.get("number_of_sections")) {
            (Some(Value::Bool(true)), Some(Value::Int(n))) => Some(*n),
            _ => None,
        }
    }

    /// The `elf` module's number of sections, `None` for an empty value.
    fn elf_sections(ctx: &ModuleCtx) -> Option<i64> {
        let Some(Value::Struct(f)) = ctx.root(ModuleKind::Elf) else {
            return None;
        };
        match f.get("number_of_sections") {
            Some(Value::Int(n)) => Some(*n),
            _ => None,
        }
    }

    /// An object too large to hold gives each module the image of its format,
    /// and is a complete build when that fits; else the value for an object
    /// that is not of the format, and a build that says it is not complete.
    #[test]
    fn a_module_parses_the_image_of_an_object_too_large_to_hold() {
        let all = [ModuleKind::Pe, ModuleKind::Elf, ModuleKind::DotNet];
        let overlay = vec![b'z'; 100_000];
        let pe = [PE, &overlay].concat();
        let elf = [ELF, &overlay].concat();
        // A PE's image reaches a page past its last section's data.
        let pe_image = crate::pe::extent(&cached(&pe), 1 << 20).unwrap().image;
        assert!(pe_image > PE.len() && pe_image < pe.len());
        for (file, held, image, wants) in [
            (&pe, PE, pe_image, ModuleKind::Pe),
            (&elf, ELF, ELF.len(), ModuleKind::Elf),
        ] {
            let (whole, complete) = ModuleCtx::build(&held, &all, true, 1 << 20, false);
            assert!(complete);
            let (ctx, complete) = ModuleCtx::build(&cached(file), &all, true, image, false);
            assert!(complete, "{wants:?}");
            assert_eq!(pe_sections(&ctx), pe_sections(&whole), "{wants:?}");
            assert_eq!(elf_sections(&ctx), elf_sections(&whole), "{wants:?}");
            assert_eq!(ctx.entry_point, whole.entry_point, "{wants:?}");
            // One byte under the image's length.
            let (ctx, complete) = ModuleCtx::build(&cached(file), &all, true, image - 1, false);
            assert!(!complete, "{wants:?}");
            assert_eq!(
                (pe_sections(&ctx), elf_sections(&ctx)),
                (None, None),
                "{wants:?}"
            );
        }
        assert_eq!(
            pe_sections(&ModuleCtx::build(&cached(&pe), &all, true, pe_image, false).0),
            Some(1)
        );
        assert_eq!(
            elf_sections(&ModuleCtx::build(&cached(&elf), &all, true, ELF.len(), false).0),
            Some(3)
        );
        // Another format's object is complete either way, and has no value
        // for a module that is not of its format.
        let (ctx, complete) = ModuleCtx::build(&cached(&overlay), &all, true, 10, false);
        assert!(complete);
        assert_eq!((pe_sections(&ctx), elf_sections(&ctx)), (None, None));
    }
}
