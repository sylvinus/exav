//! Differential harness: give the SAME rules and the SAME inputs to exav's
//! engine and to yara-x, and assert the set of matching rule identifiers is
//! identical.
//!
//! yara-x is invoked as a PROGRAM (the `yr` binary) rather than linked as a
//! library. As a dependency it brings a ~200-crate WebAssembly subtree in for
//! the benefit of two test files, and a crate in the graph can end up in a
//! shipped artifact by accident in a way a binary on `PATH` cannot. This is the
//! same relationship exav already has with `clamscan`: run the reference tool,
//! compare its output.
//!
//! Skipped when `yr` is not installed. Point `EXAV_DEBUG_YR_BIN` at a specific build
//! to override the lookup.
//!
//!   cargo install yara-x-cli     # provides `yr`
//!
//! Seeded with representative Phase-A rules; extend `RULES`/`INPUTS` to widen
//! coverage.
//!
//! Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X.

use std::collections::BTreeSet;

/// Phase-A rules understood by both engines.
const RULES: &str = r#"
rule literal_and_filesize {
    strings:
        $a = "malware"
        $b = "evil" nocase
    condition:
        $a and $b and filesize < 100
}

rule hex_pattern {
    strings:
        $h = { 4D 5A ?? ?? [0-4] 50 45 }
    condition:
        $h
}

rule regexp_rule {
    strings:
        $r = /https?:\/\/[a-z]+\.(com|net)/
    condition:
        $r
}

rule counting {
    strings:
        $x = "ab"
    condition:
        #x >= 3 and @x[1] == 0
}

rule any_of {
    strings:
        $a = "foo"
        $b = "bar"
        $c = "baz"
    condition:
        2 of them
}

rule anchored {
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}

rule xored {
    strings:
        $k = "secret" xor
    condition:
        $k
}

rule base64_rule {
    strings:
        $b = "password" base64
    condition:
        $b
}

rule arithmetic {
    condition:
        (2 + 3) * 4 == 20 and filesize % 2 == 0
}

rule ref_rule {
    condition:
        anchored and not xored
}
"#;

const INPUTS: &[&[u8]] = &[
    b"",
    b"nothing to see here",
    b"malware and EVIL things",
    b"malware and EVIL things but this input is definitely longer than one hundred bytes so the filesize check should now fail for sure yes",
    b"MZ\x00\x00PE and http://example.com",
    b"ababab",
    b"abab",
    b"foo bar",
    b"foo bar baz",
    b"\x71\x60\x62\x71\x60\x77", // "secret" xor 0x13ish
    b"cGFzc3dvcmQ=",             // base64("password")
    b"MZthis starts with MZ",
    &[0x4D, 0x5A, 0x01, 0x02, 0x50, 0x45],
];

fn exav_matches(rules: &exav_core::yara::Rules, data: &[u8]) -> BTreeSet<String> {
    rules
        .scan(data)
        .matching_rules()
        .map(|r| r.identifier().to_string())
        .collect()
}

/// Where the oracle lives. Overridable so a checkout can point at a specific
/// build rather than whatever is on `PATH`.
fn yr_bin() -> String {
    std::env::var("EXAV_DEBUG_YR_BIN").unwrap_or_else(|_| "yr".to_string())
}

/// Whether the oracle is available at all. Absent is not a failure: the same
/// rule the clamd differential follows: a harness that needs a tool nobody
/// installed should skip, not fail, or it becomes noise everyone learns to
/// ignore.
fn have_yr() -> bool {
    std::process::Command::new(yr_bin())
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Run the oracle over `data` with `rules`, returning the matching rule names.
///
/// Shelling out rather than linking `yara-x`: as a library it drags a
/// ~200-crate WebAssembly subtree into the dependency graph for the benefit of
/// two test files. As a binary it is exactly what it should be: an external
/// oracle, the same relationship exav already has with `clamscan`, and one that
/// cannot end up in a shipped artifact by accident.
fn yr_matches(rules: &str, data: &[u8], defines: &[(&str, &str)]) -> BTreeSet<String> {
    // A directory of its own: tests run in parallel, and one that shared it
    // would read another's rules (and fail on identifiers the other defines).
    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "exav-yr-{}-{}",
        std::process::id(),
        CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::create_dir_all(&dir);
    let rule_path = dir.join("rules.yar");
    let data_path = dir.join("target.bin");
    std::fs::write(&rule_path, rules).expect("write rules");
    std::fs::write(&data_path, data).expect("write target");

    let mut cmd = std::process::Command::new(yr_bin());
    cmd.arg("scan");
    // Every define here is a string, which `yr` takes only quoted.
    for (k, v) in defines {
        let v = v.replace('\\', "\\\\").replace('"', "\\\"");
        cmd.arg("--define").arg(format!("{k}=\"{v}\""));
    }
    let out = cmd
        .arg(&rule_path)
        .arg(&data_path)
        .output()
        .expect("run yr scan");
    let _ = std::fs::remove_dir_all(&dir);

    if !out.status.success() {
        panic!(
            "yr scan failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    // `yr scan` prints one line per match: the rule identifier, then the path.
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[test]
fn differential_matches_agree() {
    agree("phase-a", RULES, INPUTS);
}

/// The `elf` module, cross-checked against the real engine. Linux-focused
/// rulesets lean on this module heavily, so every field exav exposes has to
/// agree with yara-x, including the undefined-propagation behaviour on inputs
/// that are not ELF at all.
const ELF_RULES: &str = r#"
import "elf"

rule elf_is_exec {
    condition: elf.type == elf.ET_EXEC
}

rule elf_is_x86_64 {
    condition: elf.machine == elf.EM_X86_64
}

rule elf_counts {
    condition: elf.number_of_sections == 3 and elf.number_of_segments == 1
}

rule elf_entry_point_offset {
    condition: elf.entry_point == 0x80
}

rule elf_header_offsets {
    condition: elf.ph_offset == 64 and elf.ph_entry_size == 56 and elf.sh_entry_size == 64
}

rule elf_has_text_section {
    condition: for any s in elf.sections : (s.name == ".text")
}

rule elf_text_is_executable {
    condition:
        for any s in elf.sections :
            (s.name == ".text" and s.type == elf.SHT_PROGBITS
             and s.flags & 0x4 != 0)
}

rule elf_indexed_section {
    condition: elf.sections[1].name == ".text"
}

rule elf_load_segment {
    condition:
        for any s in elf.segments :
            (s.type == elf.PT_LOAD and s.flags == elf.PF_R | elf.PF_X)
}

rule elf_segment_extent {
    condition: elf.segments[0].virtual_address == 0x400000 and elf.segments[0].alignment == 0x1000
}
"#;

const ELF_INPUTS: &[&[u8]] = &[
    TINY_ELF,
    b"",
    b"not an elf at all",
    b"\x7fELF truncated right after the magic",
    TINY_PE,
];

#[test]
fn differential_elf_module_agrees() {
    agree("elf", ELF_RULES, ELF_INPUTS);
}

/// A hand-crafted minimal ELF64 executable (see tests/testdata/tiny_elf64).
const TINY_ELF: &[u8] = include_bytes!("testdata/tiny_elf64");

/// Compiles `rules` with both engines and asserts the matching-rule set is
/// identical for every input. Bucketed by feature so a failure is attributable.
fn agree(bucket: &str, rules: &str, inputs: &[&[u8]]) {
    if !have_yr() {
        eprintln!("[{bucket}] skipped: `yr` (yara-x CLI) not on PATH");
        return;
    }
    let exav = exav_core::yara::compile(rules).expect("exav compile failed");

    for (i, input) in inputs.iter().enumerate() {
        let a = exav_matches(&exav, input);
        let b = yr_matches(rules, input, &[]);
        assert_eq!(
            a,
            b,
            "\n\n[{bucket}] mismatch on input #{i} ({:?}):\n  exav: {a:?}\n  yara-x:    {b:?}",
            String::from_utf8_lossy(&input[..input.len().min(32)])
        );
    }
}

/// A hand-crafted minimal PE32 (see tests/testdata/tiny_pe32.exe) used by the
/// `pe`/integer-read buckets; a couple of non-PE inputs exercise the
/// undefined-propagation paths.
const TINY_PE: &[u8] = include_bytes!("testdata/tiny_pe32.exe");

const BYTE_INPUTS: &[&[u8]] = &[
    b"",
    b"MZ\x00\x00PE",
    b"\x7fELF\x01\x01\x01\x00",
    b"foobarbaz",
    b"AABAAB",
    b"the quick brown fox jumps over the lazy dog",
];

fn pe_inputs() -> Vec<&'static [u8]> {
    let mut v: Vec<&'static [u8]> = BYTE_INPUTS.to_vec();
    v.push(TINY_PE);
    v
}

// --- integer file reads (uintN/intN/_be) -----------------------------------

const INT_RULES: &str = r#"
rule mz_magic { condition: uint16(0) == 0x5A4D }
rule mz_be    { condition: uint16be(0) == 0x4D5A }
rule elf_be   { condition: uint32be(0) == 0x7F454C46 }
rule u8_a     { condition: uint8(0) == 0x41 }
rule i8_neg   { condition: int8(0) == -1 }
rule oob      { condition: not defined uint32(1000000) }
rule combo    { condition: uint8(0) == 0x4D and uint8(1) == 0x5A }
"#;

#[test]
fn differential_integer_reads() {
    agree("int-reads", INT_RULES, &pe_inputs());
}

// --- math module -----------------------------------------------------------

const MATH_RULES: &str = r#"
import "math"
rule ent_low   { condition: math.entropy(0, filesize) < 1.0 }
rule ent_high  { condition: math.entropy(0, filesize) > 3.0 }
rule mean_rule { condition: math.mean(0, filesize) > 60.0 }
rule count_a   { condition: math.count(0x41) >= 2 }
rule mode_a    { condition: math.mode() == 0x41 }
rule pct       { condition: math.percentage(0x41) > 0.3 }
rule inrange   { condition: math.in_range(math.mean(0, filesize), 60.0, 130.0) }
rule oob_undef { condition: not defined math.entropy(1000000, 4) }
"#;

#[test]
fn differential_math() {
    agree("math", MATH_RULES, &pe_inputs());
}

// --- hash module -----------------------------------------------------------

const HASH_RULES: &str = r#"
import "hash"
rule md5_foobarbaz {
    condition: hash.md5(0, filesize) == "6df23dc03f9b54cc38a0fc1483df6e21"
}
rule sha256_foobarbaz {
    condition: hash.sha256(0, filesize) == "97df3588b5a3f24babc3851b372f0ba71a9dcdded43b14b9d06961bfc1707d9d"
}
rule crc_defined { condition: defined hash.crc32(0, filesize) }
rule checksum_match { condition: hash.checksum32(0, filesize) == hash.checksum32(0, filesize) }
rule md5_selfeq { condition: hash.md5(0, filesize) == hash.md5(0, filesize) }
rule oob_undef { condition: not defined hash.md5(0, 1000000) }
"#;

#[test]
fn differential_hash() {
    agree("hash", HASH_RULES, &pe_inputs());
}

// --- string module ---------------------------------------------------------

const STRING_RULES: &str = r#"
import "string"
rule len9  { condition: string.length("AXsx00ERS") == 9 }
rule toint { condition: string.to_int("1234") == 1234 }
rule hexint { condition: string.to_int("ff", 16) == 255 }
"#;

#[test]
fn differential_string() {
    agree("string", STRING_RULES, &pe_inputs());
}

// --- pe module -------------------------------------------------------------

const PE_RULES: &str = r#"
import "pe"
rule is_pe          { condition: pe.is_pe }
rule i386           { condition: pe.machine == pe.MACHINE_I386 }
rule one_section    { condition: pe.number_of_sections == 1 }
rule exec_image     { condition: pe.characteristics & pe.EXECUTABLE_IMAGE != 0 }
rule cui            { condition: pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI }
rule image_base     { condition: pe.image_base == 0x400000 }
rule dll_chars      { condition: pe.dll_characteristics == 0x8140 }
rule text_section   { condition: pe.sections[0].name == ".text" }
rule sec_va         { condition: pe.sections[0].virtual_address == 0x1000 }
rule entry_off      { condition: pe.entry_point == 0x200 }
rule entry_raw      { condition: pe.entry_point_raw == 0x1000 }
rule num_imports    { condition: pe.number_of_imports == 1 }
rule imports_k32    { condition: pe.imports("kernel32.dll") == 1 }
rule imports_fn     { condition: pe.imports("KERNEL32.dll", "ExitProcess") }
rule imphash        { condition: pe.imphash() == "f9ade0aa18f660a34a4fa23392e21838" }
"#;

#[test]
fn differential_pe() {
    agree("pe", PE_RULES, &pe_inputs());
}

/// What a thunk of [`pe_importing`] holds.
enum Thunk<'a> {
    /// A hint/name entry with this name.
    Name(&'a [u8]),
    Ordinal(u16),
}
use Thunk::{Name, Ordinal};

/// A PE32 that imports `ExitProcess` by name from `KERNEL32.DLL`, and by
/// ordinal from `WS2_32.dll` (115 and 2), `OLEAUT32.dll` (2) and `USER32.dll`
/// (100): descriptors, names, thunk tables and hint/name entries in one
/// section.
fn pe_with_ordinal_imports() -> Vec<u8> {
    pe_importing(&[
        (b"KERNEL32.DLL", &[Name(b"ExitProcess")]),
        (b"WS2_32.dll", &[Ordinal(115), Ordinal(2)]),
        (b"OLEAUT32.dll", &[Ordinal(2)]),
        (b"USER32.dll", &[Ordinal(100)]),
    ])
}

/// A PE32 whose one section holds the import table of `libs`: the descriptors
/// and the null one at file offset 0x200, then the names of the libraries, a
/// thunk table each (the lookup table is the address table) and the hint/name
/// entries.
fn pe_importing(libs: &[(&[u8], &[Thunk])]) -> Vec<u8> {
    let rva = |at: usize| (0x1000 + at) as u32;
    let mut body = vec![0u8; 20 * (libs.len() + 1)];
    let mut names = Vec::new();
    for (name, _) in libs {
        names.push(body.len());
        body.extend_from_slice(name);
        body.push(0);
    }
    body.resize(body.len().next_multiple_of(4), 0);
    let mut tables = Vec::new();
    for (_, entries) in libs {
        tables.push(body.len());
        body.resize(body.len() + 4 * (entries.len() + 1), 0);
    }
    for (i, (_, entries)) in libs.iter().enumerate() {
        for (j, entry) in entries.iter().enumerate() {
            let thunk = match entry {
                Name(name) => {
                    body.resize(body.len().next_multiple_of(2), 0);
                    let at = body.len();
                    body.extend_from_slice(&[0, 0]);
                    body.extend_from_slice(name);
                    body.push(0);
                    rva(at)
                }
                Ordinal(ordinal) => 0x8000_0000 | u32::from(*ordinal),
            };
            let at = tables[i] + 4 * j;
            body[at..at + 4].copy_from_slice(&thunk.to_le_bytes());
        }
        for (field, value) in [
            (0, rva(tables[i])),
            (12, rva(names[i])),
            (16, rva(tables[i])),
        ] {
            body[20 * i + field..20 * i + field + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    let raw = body.len().next_multiple_of(0x200);
    let mut f = vec![0u8; 0x200 + raw];
    let mut put = |at: usize, bytes: &[u8]| f[at..at + bytes.len()].copy_from_slice(bytes);
    put(0, b"MZ");
    put(0x3c, &0x40u32.to_le_bytes());
    put(0x40, b"PE\0\0");
    put(0x44, &0x14cu16.to_le_bytes());
    put(0x46, &1u16.to_le_bytes()); // sections
    put(0x54, &0xe0u16.to_le_bytes()); // size of the optional header
    put(0x56, &0x0102u16.to_le_bytes());
    let opt = 0x58;
    put(opt, &0x10bu16.to_le_bytes());
    put(opt + 16, &0x1000u32.to_le_bytes()); // entry point
    put(opt + 28, &0x40_0000u32.to_le_bytes()); // image base
    put(opt + 32, &0x1000u32.to_le_bytes()); // section alignment
    put(opt + 36, &0x200u32.to_le_bytes()); // file alignment
    put(opt + 56, &(0x1000 + raw as u32).to_le_bytes()); // size of image
    put(opt + 60, &0x200u32.to_le_bytes()); // size of headers
    put(opt + 68, &3u16.to_le_bytes()); // subsystem
    put(opt + 92, &16u32.to_le_bytes()); // data directories
    put(opt + 96 + 8, &rva(0).to_le_bytes()); // the import table
    put(opt + 96 + 12, &(20 * (libs.len() as u32 + 1)).to_le_bytes());
    let section = opt + 0xe0;
    put(section, b".idata");
    put(section + 8, &(raw as u32).to_le_bytes()); // virtual size
    put(section + 12, &0x1000u32.to_le_bytes());
    put(section + 16, &(raw as u32).to_le_bytes()); // raw size
    put(section + 20, &0x200u32.to_le_bytes());
    put(section + 36, &0xc000_0040u32.to_le_bytes());
    f[0x200..0x200 + body.len()].copy_from_slice(&body);
    f
}

/// Imports by ordinal, which libyara and yara-x name from the same tables:
/// both list `WSAStartup` for ordinal 115 of `ws2_32` and `ord100` for ordinal
/// 100 of `user32`, and `imports(dll, ordinal)` holds only for an import by
/// ordinal.
const PE_ORDINAL_RULES: &str = r#"
import "pe"
rule ws2_name { condition: pe.imports("ws2_32.dll", "WSAStartup") }
rule ws2_bind { condition: pe.imports("ws2_32.dll", "bind") }
rule ws2_ord { condition: pe.imports("ws2_32.dll", 115) }
rule ws2_numbered { condition: pe.imports("ws2_32.dll", "ord115") }
rule ole { condition: pe.imports("oleaut32.dll", "SysAllocString") }
rule user_name { condition: pe.imports("user32.dll", "ord100") }
rule user_ord { condition: pe.imports("user32.dll", 100) }
rule user_other_ord { condition: pe.imports("user32.dll", 101) }
rule named_has_no_ordinal { condition: pe.imports("kernel32.dll", 1) }
rule counts {
    condition: pe.number_of_imports == 4 and pe.number_of_imported_functions == 5
}
rule imphash {
    condition: pe.imphash() == "fc0dc1e0f56f5ff581a24a0da3ef55ff"
}
"#;

#[test]
fn differential_pe_imports_by_ordinal() {
    let pe = pe_with_ordinal_imports();
    let want: BTreeSet<String> = [
        "ws2_name",
        "ws2_bind",
        "ws2_ord",
        "ole",
        "user_name",
        "user_ord",
        "counts",
        "imphash",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    // What libyara 4.5.2 and yara-x 1.22.1 give for the same imports.
    let exav = exav_core::yara::compile(PE_ORDINAL_RULES).expect("exav compile failed");
    assert_eq!(exav_matches(&exav, &pe), want);
    agree("pe-ordinals", PE_ORDINAL_RULES, &[&pe]);
}

/// The md5 of `s`, in hex.
fn md5_hex(s: &[u8]) -> String {
    use md5::{Digest, Md5};
    Md5::digest(s).iter().map(|b| format!("{b:02x}")).collect()
}

/// `pe` with its section's data at `at` in the file, its header's pointer at
/// `pointer`, and these alignments.
fn placed(
    pe: &[u8],
    file_alignment: u32,
    section_alignment: u32,
    pointer: u32,
    at: usize,
) -> Vec<u8> {
    let mut f = pe[..0x200].to_vec();
    f.resize(at, 0);
    f.extend_from_slice(&pe[0x200..]);
    let mut put = |off: usize, v: u32| f[off..off + 4].copy_from_slice(&v.to_le_bytes());
    put(0x58 + 32, section_alignment);
    put(0x58 + 36, file_alignment);
    put(0x58 + 0xe0 + 20, pointer);
    f
}

/// Imports on which yara-x 1.21.0 and libyara 4.5.2 give different answers,
/// and the module follows yara-x: the extension of a library is cut only if
/// it ends the name; an ordinal is named for the whole name of its library; a
/// function name is any printable ASCII but the space, up to 1024 bytes; a
/// library may be empty, long or UTF-8, and not have a space; a descriptor
/// with no table ends the table; a table is cut at 16384 functions; a section
/// is placed at its pointer rounded to the file alignment. Not in the fixtures
/// of the other tests, which is why they stayed green when the module followed
/// libyara.
#[test]
fn differential_pe_imports_where_yarax_and_libyara_differ() {
    let long_name = vec![b'a'; 600];
    let long_lib = [vec![b'd'; 252], b".dll".to_vec()].concat();
    let many = |n: usize| -> Vec<Thunk> { (0..n).map(|_| Name(b"f")).collect() };
    let (ten_a, ten_b) = (many(10_000), many(10_000));
    let tableless = {
        let mut pe = pe_importing(&[
            (b"K.DLL", &[Name(b"a")]),
            (b"U.DLL", &[Name(b"b")]),
            (b"G.DLL", &[Name(b"c")]),
        ]);
        // The second descriptor: no lookup table, no address table.
        pe[0x200 + 20..0x200 + 24].fill(0);
        pe[0x200 + 20 + 16..0x200 + 20 + 20].fill(0);
        pe
    };
    let standard = pe_importing(&[(b"K.DLL", &[Name(b"a"), Name(b"b")])]);
    // (a name for the rules, the PE, the string yara-x hashes for pe.imphash())
    let cases: Vec<(&str, Vec<u8>, String)> = vec![
        (
            "suffix",
            pe_importing(&[(b"x.dllx", &[Name(b"f")])]),
            "x.dllx.f".into(),
        ),
        (
            "ordinal_suffix",
            pe_importing(&[
                (b"ws2_32.dllx", &[Ordinal(115)]),
                (b"ws2_32.dll.mui", &[Ordinal(2)]),
            ]),
            "ws2_32.dllx.ord115,ws2_32.dll.mui.ord2".into(),
        ),
        (
            "dash",
            pe_importing(&[(
                b"K.DLL",
                &[Name(b"a"), Name(b"a-b"), Name(b"~"), Name(b"b")],
            )]),
            "k.a,k.a-b,k.~,k.b".into(),
        ),
        (
            "long_function",
            pe_importing(&[(b"K.DLL", &[Name(&long_name)])]),
            format!("k.{}", "a".repeat(600)),
        ),
        (
            "empty_library",
            pe_importing(&[(b"", &[Name(b"f")])]),
            ".f".into(),
        ),
        (
            "long_library",
            pe_importing(&[(&long_lib, &[Name(b"f")])]),
            format!("{}.f", "d".repeat(252)),
        ),
        (
            "space_in_library",
            pe_importing(&[(b"my lib.dll", &[Name(b"f")])]),
            String::new(),
        ),
        (
            "utf8_library",
            pe_importing(&[("k\u{e9}rnel.dll".as_bytes(), &[Name(b"f")])]),
            "k\u{e9}rnel.f".into(),
        ),
        ("no_table_ends_the_list", tableless, "k.a".into()),
        (
            "capped",
            pe_importing(&[(b"K.DLL", &many(16_385))]),
            format!("k.f{}", ",k.f".repeat(16_383)),
        ),
        (
            "two_libraries_over_the_cap",
            pe_importing(&[(b"K.DLL", &ten_a), (b"U.DLL", &ten_b)]),
            format!("k.f{},u.f{}", ",k.f".repeat(9_999), ",u.f".repeat(9_999)),
        ),
        // The data of the section is where yara-x rounds its pointer to (a
        // file alignment of 0x100), or where a section alignment of 0x1000
        // rounds it further (0x200).
        (
            "rounded_to_alignment",
            placed(&standard, 0x100, 0x200, 0x7f0, 0x700),
            "k.a,k.b".into(),
        ),
        (
            "rounded_further",
            placed(&standard, 0x100, 0x1000, 0x7f0, 0x600),
            "k.a,k.b".into(),
        ),
        (
            "not_rounded_far_enough",
            placed(&standard, 0x100, 0x1000, 0x7f0, 0x700),
            String::new(),
        ),
    ];
    let mut rules = String::from("import \"pe\"\n");
    for n in [0, 1, 2, 3] {
        rules += &format!("rule imports_{n} {{ condition: pe.number_of_imports == {n} }}\n");
    }
    for n in [0, 1, 2, 3, 4, 16_384, 20_000] {
        rules += &format!(
            "rule functions_{n} {{ condition: pe.number_of_imported_functions == {n} }}\n"
        );
    }
    rules += "rule dash { condition: pe.imports(\"k.dll\", \"a-b\") and pe.imports(\"k.dll\", \"~\") }\n";
    rules += &format!(
        "rule long_function {{ condition: pe.imports(\"k.dll\", \"{}\") }}\n",
        "a".repeat(600)
    );
    rules += "rule ws2_numbered { condition: pe.imports(\"ws2_32.dllx\", \"ord115\") }\n";
    rules += "rule ws2_named { condition: pe.imports(\"ws2_32.dllx\", \"WSAStartup\") }\n";
    rules += "rule ordinal_115 { condition: pe.imports(\"ws2_32.dllx\", 115) }\n";
    rules += "rule empty_library { condition: pe.imports(\"\", \"f\") }\n";
    for (name, _, hashed) in &cases {
        let hash = md5_hex(hashed.as_bytes());
        rules += &format!("rule hash_{name} {{ condition: pe.imphash() == \"{hash}\" }}\n");
    }
    let inputs: Vec<&[u8]> = cases.iter().map(|(_, pe, _)| pe.as_slice()).collect();
    // What yara-x says of each: the rules that hold, besides the hashes.
    let exav = exav_core::yara::compile(&rules).expect("exav compile failed");
    for (name, pe, hashed) in &cases {
        let want: &[&str] = match *name {
            "suffix" => &["imports_1", "functions_1"],
            "ordinal_suffix" => &["imports_2", "functions_2", "ws2_numbered", "ordinal_115"],
            "dash" => &["imports_1", "functions_4", "dash"],
            "long_function" => &["imports_1", "functions_1", "long_function"],
            "empty_library" => &["imports_1", "functions_1", "empty_library"],
            "long_library" => &["imports_1", "functions_1"],
            "space_in_library" | "not_rounded_far_enough" => &["imports_0", "functions_0"],
            "utf8_library" => &["imports_1", "functions_1"],
            "no_table_ends_the_list" => &["imports_1", "functions_1"],
            "capped" => &["imports_1", "functions_16384"],
            "two_libraries_over_the_cap" => &["imports_2", "functions_20000"],
            _ => &["imports_1", "functions_2"],
        };
        let mut want: Vec<String> = want.iter().map(|s| s.to_string()).collect();
        // The hash rules that hold are those of the cases hashing the same
        // string, which for a PE with no imports is the empty one.
        want.extend(
            cases
                .iter()
                .filter(|(_, _, h)| h == hashed)
                .map(|(n, _, _)| format!("hash_{n}")),
        );
        want.sort();
        let held: Vec<String> = exav_matches(&exav, pe).into_iter().collect();
        assert_eq!(held, want, "{name}");
    }
    agree("pe-imports-yarax", &rules, &inputs);
}

// --- for … in / for … of / with (Phase C) ----------------------------------

const FOR_RULES: &str = r#"
rule for_all_range   { condition: for all i in (0..3) : (i < 10) }
rule for_none_range  { condition: for none i in (0..10) : (i > 100) }
rule for_count_range { condition: for 2 i in (0..10) : (i < 2) }
rule for_pct_range   { condition: for 50% i in (0..10) : (i < 6) }
rule for_tuple_any   { condition: for any e in (1, 2, 3) : (e == 3) }
rule for_str_tuple   { condition: for 2 s in ("foo", "bar", "baz") : (s contains "ba") }
rule for_bytes_A     { condition: for any i in (0..filesize - 1) : (uint8(i) == 0x41) }
rule with_filesize   { condition: with s = filesize : (s > 3 and s < 100) }
rule with_two        { condition: with a = 2, b = a + 3 : (a + b == 7) }
rule nested_loops    { condition: for all i in (0..2) : ( for any j in (i..3) : (j >= i) ) }

rule for_of_all {
    strings: $a = "foo" $b = "bar"
    condition: for all of them : ( # >= 1 )
}
rule for_of_any_anon {
    strings: $x = "MZ" $y = "PE"
    condition: for any of them : ( $ )
}
rule for_of_offsets {
    strings: $a = "ab"
    condition: #a > 0 and for all i in (0..#a - 1) : ( @a[i] < 100 )
}
rule for_1_of {
    strings: $a = "foo" $b = "bar"
    condition: for 1 of them : ( # == 2 )
}
"#;

#[test]
fn differential_for_with() {
    // Reuse the general byte inputs plus a couple that exercise `foo`/`bar`
    // counts, `ab` offsets, and the `A`-byte scan.
    let inputs: &[&[u8]] = &[
        b"",
        b"nothing",
        b"foo bar",
        b"foobarbar",
        b"foobarfoobar",
        b"AABAAB",
        b"ababab",
        b"MZ and PE headers",
        b"the quick brown fox",
        &[0x41, 0x42, 0x41],
    ];
    agree("for-with", FOR_RULES, inputs);
}

const FOR_PE_RULES: &str = r#"
import "pe"
rule sec_text_any {
    condition: for any s in pe.sections : (s.name == ".text")
}
rule sec_all_va {
    condition: pe.is_pe and for all s in pe.sections : (s.virtual_address >= 0x1000)
}
rule sec_any_exec {
    condition: for any s in pe.sections : (s.characteristics & pe.SECTION_MEM_EXECUTE != 0)
}
rule with_first_section {
    condition: pe.number_of_sections > 0 and
               with s = pe.sections[0] : (s.raw_data_offset == 0x200)
}
rule with_pe_struct {
    condition: with p = pe : (p.is_pe and p.machine == pe.MACHINE_I386)
}
"#;

#[test]
fn differential_for_pe() {
    agree("for-pe", FOR_PE_RULES, &pe_inputs());
}

// --- external variables (filename / filepath / extension) -------------------

/// Rules that reference the standard scanner externals. The SAME externals are
/// declared + set to the SAME values in both engines below, so the matching-rule
/// sets must be identical.
const EXTERNAL_RULES: &str = r#"
rule ext_js       { condition: extension == ".js" }
rule ext_not_exe  { condition: extension != ".exe" }
rule fn_matches   { condition: filename matches /invoice.*\.js/i }
rule fn_contains  { condition: filename contains "voice" }
rule fp_contains  { condition: filepath contains "Downloads" }
rule fp_starts    { condition: filepath startswith "/home" }
rule combo        { condition: filesize < 1000 and extension == ".js" and filename icontains "INVOICE" }
rule fn_and_bytes {
    strings: $a = "payload"
    condition: $a and filename endswith ".js"
}
"#;

/// External values the difftest applies to both engines (path, basename, ext).
const EXTERNAL_VALUES: &[(&str, &str)] = &[
    ("filepath", "/home/user/Downloads/invoice_2026.js"),
    ("filename", "invoice_2026.js"),
    ("extension", ".js"),
];

fn exav_matches_ext(rules: &exav_core::yara::Rules, data: &[u8]) -> BTreeSet<String> {
    let mut scanner = exav_core::yara::Scanner::new(rules);
    for (k, v) in EXTERNAL_VALUES {
        scanner.set_global(k, *v);
    }
    scanner
        .scan(data)
        .expect("exav scan failed")
        .matching_rules()
        .map(|r| r.identifier().to_string())
        .collect()
}

#[test]
fn differential_external_variables() {
    if !have_yr() {
        eprintln!("[externals] skipped: `yr` (yara-x CLI) not on PATH");
        return;
    }
    // exav pre-declares the standard externals in `Compiler::new`, but
    // declaring them explicitly keeps the comparison independent of that
    // default. The oracle is given the same values on its command line.
    let mut ec = exav_core::yara::Compiler::new();
    ec.define_external("filename", "");
    ec.define_external("filepath", "");
    ec.define_external("extension", "");
    ec.add_source(EXTERNAL_RULES).expect("exav compile failed");
    let exav = ec.build();

    let inputs: &[&[u8]] = &[
        b"",
        b"nothing here",
        b"....payload....",
        b"a longer buffer with the word payload embedded somewhere inside it",
    ];
    for (i, input) in inputs.iter().enumerate() {
        let a = exav_matches_ext(&exav, input);
        let b = yr_matches(EXTERNAL_RULES, input, EXTERNAL_VALUES);
        assert_eq!(
            a, b,
            "\n\n[externals] mismatch on input #{i}:\n  exav: {a:?}\n  yara-x:    {b:?}",
        );
    }
}
