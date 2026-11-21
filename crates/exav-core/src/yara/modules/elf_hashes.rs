//! `elf.import_md5()` and `elf.telfhash()`, over the symbols of the `elf` value.
//!
//! Both read the dynamic symbol table, or the symbol table when the file has no
//! dynamic one, as the module built them: names the file does not hold are
//! missing, and a table cut by the copy limit is short (the scan then says so).
//! The values are yara-x's, found by comparing with `yr` 1.23. The selection of
//! symbols for `telfhash()` follows the published telfhash of Trend Micro
//! (Apache-2.0, https://github.com/trendmicro/telfhash): global default-visibility
//! functions, minus a list of names, lowercased, sorted, joined with commas and
//! hashed with TLSH. Its disassembly fallback for files without symbols is not
//! in yara-x and not here.

use md5::{Digest, Md5};

use super::tlsh;
use crate::yara::ir::Value;

const STT_FUNC: i64 = 2;
const STB_GLOBAL: i64 = 1;
const SHN_UNDEF: i64 = 0;

/// Names telfhash leaves out: compiler and libc artifacts that differ between
/// builds of the same program.
const EXCLUDED: &[&str] = &[
    "__libc_start_main",
    "main",
    "abort",
    "cachectl",
    "cacheflush",
    "puts",
    "atol",
    "malloc_trim",
];

fn excluded(name: &str) -> bool {
    EXCLUDED.contains(&name)
        || name.starts_with(['_', '.'])
        || name.starts_with("str")
        || name.starts_with("mem")
        || name.ends_with("64")
}

/// The two values of a file.
pub(crate) struct ElfHashes {
    pub import_md5: String,
    pub telfhash: Option<String>,
}

fn int(fields: &crate::yara::ir::Fields, key: &str) -> Option<i64> {
    match fields.get(key)? {
        Value::Int(i) => Some(*i),
        _ => None,
    }
}

/// Computes both values from the root of the `elf` module.
pub(crate) fn compute(root: Option<&Value>) -> ElfHashes {
    let table = |key: &str| match root {
        Some(Value::Struct(f)) => match f.get(key) {
            Some(Value::Array(items)) if !items.is_empty() => Some(items.clone()),
            _ => None,
        },
        _ => None,
    };
    let symbols = table("dynsym").or_else(|| table("symtab"));

    let mut imports = Vec::new();
    let mut functions = Vec::new();
    for sym in symbols.iter().flat_map(|s| s.iter()) {
        let Value::Struct(f) = sym else { continue };
        let Some(Value::Str(raw)) = f.get("name") else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        let name = String::from_utf8_lossy(raw);
        if int(f, "shndx") == Some(SHN_UNDEF) {
            imports.push(name.to_lowercase());
        }
        if int(f, "type") == Some(STT_FUNC)
            && int(f, "bind") == Some(STB_GLOBAL)
            && int(f, "visibility") == Some(0)
            && !excluded(&name)
        {
            functions.push(name.to_lowercase());
        }
    }
    imports.sort_unstable();
    functions.sort_unstable();

    ElfHashes {
        import_md5: crate::hexsig::encode_hex(&Md5::digest(imports.join(",").as_bytes())),
        telfhash: tlsh::digest(functions.join(",").as_bytes()),
    }
}
