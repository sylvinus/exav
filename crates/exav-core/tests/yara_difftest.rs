//! Differential harness: give the SAME rules and the SAME inputs to exav's
//! engine and to yara-x, and assert the set of matching rule identifiers is
//! identical.
//!
//! yara-x is invoked as a PROGRAM — the `yr` binary — rather than linked as a
//! library. As a dependency it brings a ~200-crate WebAssembly subtree in for
//! the benefit of two test files, and a crate in the graph can end up in a
//! shipped artifact by accident in a way a binary on `PATH` cannot. This is the
//! same relationship exav already has with `clamscan`: run the reference tool,
//! compare its output.
//!
//! Skipped when `yr` is not installed. Point `EXAV_YR_BIN` at a specific build
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
    std::env::var("EXAV_YR_BIN").unwrap_or_else(|_| "yr".to_string())
}

/// Whether the oracle is available at all. Absent is not a failure: the same
/// rule the clamd differential follows — a harness that needs a tool nobody
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
/// two test files. As a binary it is exactly what it should be — an external
/// oracle, the same relationship exav already has with `clamscan`, and one that
/// cannot end up in a shipped artifact by accident.
fn yr_matches(rules: &str, data: &[u8], defines: &[(&str, &str)]) -> BTreeSet<String> {
    let dir = std::env::temp_dir().join(format!("exav-yr-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let rule_path = dir.join("rules.yar");
    let data_path = dir.join("target.bin");
    std::fs::write(&rule_path, rules).expect("write rules");
    std::fs::write(&data_path, data).expect("write target");

    let mut cmd = std::process::Command::new(yr_bin());
    cmd.arg("scan");
    for (k, v) in defines {
        cmd.arg("--define").arg(format!("{k}={v}"));
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
/// agree with yara-x — including the undefined-propagation behaviour on inputs
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
    // default — the oracle is given the same values on its command line.
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
