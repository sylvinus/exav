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

mod dotnet_damaged;
mod elf_image;

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

/// As [`yr_matches`] for many inputs in one run of the oracle: the matching
/// rules of each, in the order of `inputs`.
fn yr_matches_each(rules: &str, inputs: &[&[u8]]) -> Vec<BTreeSet<String>> {
    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "exav-yr-many-{}-{}",
        std::process::id(),
        CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let targets = dir.join("targets");
    std::fs::create_dir_all(&targets).expect("create dir");
    let rule_path = dir.join("rules.yar");
    std::fs::write(&rule_path, rules).expect("write rules");
    for (i, data) in inputs.iter().enumerate() {
        std::fs::write(targets.join(format!("{i}.bin")), data).expect("write target");
    }
    let out = std::process::Command::new(yr_bin())
        .args(["scan", "--recursive"])
        .arg(&rule_path)
        .arg(&targets)
        .output()
        .expect("run yr scan");
    let _ = std::fs::remove_dir_all(&dir);
    if !out.status.success() {
        panic!(
            "yr scan failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let mut matched = vec![BTreeSet::new(); inputs.len()];
    // One line per match: the rule identifier, then the path of the input.
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut words = line.split_whitespace();
        let (Some(rule), Some(path)) = (words.next(), words.next()) else {
            continue;
        };
        let index: usize = std::path::Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("unexpected yr output: {line}"));
        matched[index].insert(rule.to_string());
    }
    matched
}

#[test]
fn differential_matches_agree() {
    agree("phase-a", RULES, INPUTS);
}

/// Patterns used only at one offset, which both engines look for there
/// alone, and patterns used at two offsets, which they do not.
const ANCHORED_RULES: &str = r#"
rule not_at_zero {
    strings:
        $v = { 00 00 }
        $m = "hello"
    condition:
        $m and not $v at 0
}

rule of_at {
    strings:
        $a = "AB"
        $b = "CD"
    condition:
        any of ($a, $b) at 2
}

rule two_offsets {
    strings:
        $a = "AB"
    condition:
        $a at 0 or $a at 2
}

rule regexp_at {
    strings:
        $r = /\bword[0-9]*/
    condition:
        $r at 1
}

rule wide_fullword_at {
    strings:
        $w = "word" wide ascii fullword
    condition:
        $w at 1
}

rule base64_at {
    strings:
        $b = "password" base64
    condition:
        $b at 1
}
"#;

#[test]
fn differential_anchored_patterns() {
    // Past the most matches a pattern keeps.
    let mut zeros = vec![0u8; 1_000_010];
    zeros.extend_from_slice(b"hello");
    let mut mz = zeros.clone();
    mz[..2].copy_from_slice(b"MZ");
    let inputs: [&[u8]; 11] = [
        b"",
        b"ABCDAB",
        b"xxCDxx",
        b"\x00\x00hello",
        b"MZ\x00\x00hello",
        b" word42 and more",
        b"xword42",
        b" w\0o\0r\0d\0 ",
        b"xcGFzc3dvcmQ=",
        &zeros,
        &mz,
    ];
    agree("anchored", ANCHORED_RULES, &inputs);
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

/// Rules over the fields of the images written by `elf_image`, one family of
/// fields each. A field one image does not have makes its rules undefined, as
/// in yara-x; the rule set as a whole must match on both sides alike.
const ELF_IMAGE_RULES: &str = r#"
import "elf"

rule osabi_linux { condition: elf.osabi == elf.OSABI_LINUX }
rule osabi_unknown { condition: elf.osabi == 66 }
rule header {
    condition: elf.type == elf.ET_DYN and elf.machine == elf.EM_X86_64
        and elf.number_of_sections == 6 and elf.number_of_segments == 2
}
rule header_without_sections { condition: elf.type == elf.ET_DYN and elf.number_of_sections == 0 }
rule symbol_counts { condition: elf.dynsym_entries == 4 and elf.symtab_entries == 2 }
rule symbol_counts_zero { condition: elf.dynsym_entries == 0 and elf.symtab_entries == 0 }
rule symbol_counts_undefined {
    condition: not defined elf.dynsym_entries and not defined elf.symtab_entries
}
rule dynsym_alpha {
    condition: elf.dynsym[1].name == "alpha" and elf.dynsym[1].value == 0x1234
        and elf.dynsym[1].size == 8 and elf.dynsym[1].type == elf.STT_FUNC
        and elf.dynsym[1].bind == elf.STB_GLOBAL and elf.dynsym[1].shndx == 5
        and elf.dynsym[1].visibility == elf.STV_INTERNAL
}
rule dynsym_beta {
    condition: elf.dynsym[2].name == "beta" and elf.dynsym[2].type == elf.STT_OBJECT
        and elf.dynsym[2].bind == elf.STB_WEAK and elf.dynsym[2].shndx == 0xfff1
        and elf.dynsym[2].visibility == elf.STV_PROTECTED
}
rule dynsym_gamma {
    condition: elf.dynsym[3].name == "gamma" and elf.dynsym[3].visibility == elf.STV_HIDDEN
}
rule symtab_main {
    condition: elf.symtab[1].name == "main" and elf.symtab[1].value == 0x1000
        and elf.symtab[1].size == 16 and elf.symtab[1].visibility == elf.STV_DEFAULT
}
rule dynamic_entries {
    condition: elf.dynamic_section_entries == 4 and elf.dynamic[0].type == elf.DT_HASH
        and elf.dynamic[2].val == 18 and elf.dynamic[3].type == elf.DT_SYMTAB
}
rule dynamic_end_not_listed {
    condition: not defined elf.dynamic[4].type
        and not (for any d in elf.dynamic : (d.type == elf.DT_NULL))
}
rule dynamic_two_segments { condition: elf.dynamic_section_entries == 6 }
rule dynamic_zero { condition: elf.dynamic_section_entries == 0 }
rule dynamic_high_tag { condition: elf.dynamic[4].type == -2147483648 }
rule high_types {
    condition: elf.sections[6].type == -2147483648 and elf.segments[2].type == -2147483647
}
rule section_names {
    condition: elf.sections[1].name == ".dynsym" and elf.sections[5].name == ".shstrtab"
}
rule section_name_from_the_header { condition: elf.sections[0].name contains "ELF" }
rule section_name_undefined {
    condition: not defined elf.sections[1].name and elf.sections[1].type == elf.SHT_DYNSYM
}
rule segment_from_the_header { condition: elf.segments[0].type == 0x464c457f }
rule segment_from_the_header_be { condition: elf.segments[0].type == 0x7f454c46 }
rule segments_not_in_the_file {
    condition: elf.number_of_segments == 200 and not defined elf.segments[0].type
}
rule entry_in_dynstr { condition: elf.entry_point == elf.sections[2].offset + 3 }
rule len_sections { condition: elf.sections.len() == 6 }
rule len_sections_is_the_number { condition: elf.sections.len() == elf.number_of_sections }
rule len_sections_zero { condition: elf.sections.len() == 0 }
rule len_segments { condition: elf.segments.len() == 2 }
rule len_segments_zero { condition: elf.segments.len() == 0 }
rule len_dynsym { condition: elf.dynsym.len() == elf.dynsym_entries and elf.dynsym.len() == 4 }
rule len_dynsym_zero { condition: elf.dynsym.len() == 0 }
rule len_symtab { condition: elf.symtab.len() == 2 }
rule len_symtab_zero { condition: elf.symtab.len() == 0 }
rule len_dynamic { condition: elf.dynamic.len() == elf.dynamic_section_entries and elf.dynamic.len() == 4 }
rule len_dynamic_zero { condition: elf.dynamic.len() == 0 }
rule len_in_a_range {
    condition: for any i in (0..elf.sections.len() - 1) : (elf.sections[i].type == elf.SHT_DYNSYM)
}
rule len_of_a_bound_array { condition: with s = elf.symtab : (s.len() == 2) }
rule entry_undefined { condition: not defined elf.entry_point }
rule entry_at_zero { condition: elf.entry_point == 0 }
rule second_symtab { condition: elf.number_of_sections == 7 and elf.symtab_entries == 2 }
"#;

/// Images that differ in what one point of the module reads: the tables the
/// header and the section types locate, the identification and the entry point.
fn elf_images() -> Vec<(String, Vec<u8>)> {
    use elf_image::{Image, SectionHeaders};

    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut add = |what: &str, image: &Image| {
        out.push((
            format!("{what} (wide {}, big {})", image.wide, image.big),
            image.bytes(),
        ));
    };
    for (wide, big) in [(true, false), (true, true), (false, false), (false, true)] {
        add("base", &Image::new(wide, big));

        let mut image = Image::new(wide, big);
        image.osabi = 3;
        add("osabi linux", &image);
        image.osabi = 0x42;
        add("osabi 66", &image);

        let mut image = Image::new(wide, big);
        image.dt_symtab = false;
        add("no DT_SYMTAB", &image);
        let mut image = Image::new(wide, big);
        image.machine = 22;
        image.hash_bucket = 1;
        add("s390x, hash table of 32-bit words", &image);

        let mut image = Image::new(wide, big);
        image.section_headers = SectionHeaders::Absent;
        add("no section headers", &image);
        image.e_phnum = Some(0);
        add("no section headers, no segments", &image);
        image.section_headers = SectionHeaders::PastEnd;
        add("section headers past the end, no segments", &image);
        image.section_headers = SectionHeaders::PastEndNoCount;
        add("no section header, past the end", &image);
        let mut image = Image::new(wide, big);
        image.section_headers = SectionHeaders::PastEnd;
        add("section headers past the end", &image);

        let mut image = Image::new(wide, big);
        image.e_phoff_zero = true;
        add("e_phoff 0", &image);
        image.e_phnum = Some(200);
        add("e_phoff 0, 200 segments", &image);

        let mut image = Image::new(wide, big);
        image.second_dynamic = true;
        add("two PT_DYNAMIC", &image);
        let mut image = Image::new(wide, big);
        image.high_types = true;
        add("types of 2^31 and more", &image);
        let mut image = Image::new(wide, big);
        image.second_symtab = true;
        image.symtab_entsize_zero = true;
        add("two SHT_SYMTAB, entsize 0", &image);

        let mut image = Image::new(wide, big);
        image.e_shstrndx = 0;
        add("e_shstrndx 0", &image);
        image.e_shstrndx = 99;
        add("e_shstrndx 99", &image);

        for e_shnum in [0xfeff, 0xff00, 0xffff] {
            let mut image = Image::new(wide, big);
            image.entry = image.va(0);
            image.e_shnum = Some(e_shnum);
            add(&format!("entry, e_shnum {e_shnum:#x}"), &image);
        }
        let mut image = Image::new(wide, big);
        image.nobits = true;
        image.e_type = 1;
        image.entry = image.va(0x40) + 4;
        add("entry in a SHT_NOBITS section", &image);

        // The sections are 0x100000 above the segment that holds the file.
        let dynstr = Image::new(wide, big).build().1.dynstr;
        for base in [0x1000, 0] {
            let mut image = Image::new(wide, big);
            image.base = base;
            image.section_shift = 0x10_0000;
            for e_type in [0, 1, 2, 3, 4, 127] {
                let in_dynstr = image.va(dynstr) + 3;
                for entry in [0, image.va(0), in_dynstr, in_dynstr + 0x10_0000] {
                    image.e_type = e_type;
                    image.entry = entry;
                    add(
                        &format!("type {e_type}, entry {entry:#x}, base {base:#x}"),
                        &image,
                    );
                }
            }
        }
    }
    out
}

#[test]
fn differential_elf_module_on_written_images() {
    if !have_yr() {
        eprintln!("[elf images] skipped: `yr` (yara-x CLI) not on PATH");
        return;
    }
    let exav = exav_core::yara::compile(ELF_IMAGE_RULES).expect("exav compile failed");
    let images = elf_images();
    let inputs: Vec<&[u8]> = images.iter().map(|(_, bytes)| bytes.as_slice()).collect();
    let mut seen = BTreeSet::new();
    for ((what, bytes), b) in images.iter().zip(yr_matches_each(ELF_IMAGE_RULES, &inputs)) {
        let a = exav_matches(&exav, bytes);
        assert_eq!(
            a, b,
            "\n\n[elf images] {what}:\n  exav: {a:?}\n  yara-x: {b:?}"
        );
        seen.extend(b);
    }
    // A rule that no image matches would agree without checking anything.
    let never: Vec<_> = ELF_IMAGE_RULES
        .lines()
        .filter_map(|l| l.strip_prefix("rule ")?.split_whitespace().next())
        .filter(|id| !seen.contains(*id))
        .collect();
    assert!(never.is_empty(), "no image matches: {never:?}");
}

/// Every constant, with its value, compiles in yara-x and means the same.
#[test]
fn differential_elf_constants() {
    let mut rules = String::from("import \"elf\"\n");
    for (name, value) in elf_image::CONSTANTS {
        rules.push_str(&format!(
            "rule {name} {{ condition: elf.{name} == {value} }}\n"
        ));
    }
    let exav = exav_core::yara::compile(&rules).expect("exav compile failed");
    let ours = exav_matches(&exav, b"");
    assert_eq!(ours.len(), elf_image::CONSTANTS.len());
    if !have_yr() {
        eprintln!("[elf constants] skipped: `yr` (yara-x CLI) not on PATH");
        return;
    }
    assert_eq!(ours, yr_matches(&rules, b"", &[]));
}

/// What `yr` gives for `elf.import_md5()` and `elf.telfhash()` on each input
/// (`None` for a value that is undefined), from its console.
fn yr_elf_hashes(inputs: &[&[u8]]) -> Vec<(Option<String>, Option<String>)> {
    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "exav-yr-hashes-{}-{}",
        std::process::id(),
        CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let targets = dir.join("targets");
    std::fs::create_dir_all(&targets).expect("create dir");
    let rule_path = dir.join("rules.yar");
    std::fs::write(
        &rule_path,
        "import \"elf\"\nimport \"console\"\n\
         rule i { condition: console.log(\"I=\", elf.import_md5()) }\n\
         rule t { condition: console.log(\"T=\", elf.telfhash()) }\n",
    )
    .expect("write rules");
    for (i, data) in inputs.iter().enumerate() {
        std::fs::write(targets.join(format!("{i}.bin")), data).expect("write target");
    }
    let out = std::process::Command::new(yr_bin())
        .args(["scan", "--recursive"])
        .arg(&rule_path)
        .arg(&targets)
        .output()
        .expect("run yr scan");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "yr scan failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let mut values = vec![(None, None); inputs.len()];
    for line in String::from_utf8_lossy(&out.stderr).lines() {
        let Some((path, rest)) = line.split_once(": ") else {
            continue;
        };
        let index: usize = std::path::Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("unexpected yr output: {line}"));
        if let Some(md5) = rest.strip_prefix("I=") {
            values[index].0 = Some(md5.to_string());
        } else if let Some(hash) = rest.strip_prefix("T=") {
            values[index].1 = Some(hash.to_string());
        }
    }
    values
}

/// A pseudo-random sequence, the same on every run.
struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// ELF files whose symbols vary in name, kind, binding, visibility, whether the
/// file defines them and which table holds them.
fn symbol_images() -> Vec<Vec<u8>> {
    use elf_image::{Sym, symbol_elf};
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    const PREFIXES: &[&str] = &["", "", "", "_", ".", "str", "mem", "Str"];
    const SUFFIXES: &[&str] = &["", "", "", "", "64", "_ex"];
    const FIXED: &[&str] = &["main", "puts", "abort", "atol", "__libc_start_main"];
    let mut rng = Xorshift(0x2545_f491_4f6c_dd1d);
    let mut images = Vec::new();
    for _ in 0..400 {
        let count = 1 + rng.below(45) as usize;
        let symbols: Vec<Sym> = (0..count)
            .map(|_| {
                let mut name = String::from(PREFIXES[rng.below(PREFIXES.len() as u64) as usize]);
                for _ in 0..3 + rng.below(18) {
                    name.push(LETTERS[rng.below(LETTERS.len() as u64) as usize] as char);
                }
                name.push_str(SUFFIXES[rng.below(SUFFIXES.len() as u64) as usize]);
                if rng.below(40) == 0 {
                    name = FIXED[rng.below(FIXED.len() as u64) as usize].to_string();
                }
                // Mostly global functions; the rest vary one attribute.
                let (kind, bind, other, shndx) = match rng.below(12) {
                    0 => (1, 1, 0, 0),
                    1 => (0, 1, 0, 0),
                    2 => (2, 2, 0, 0),
                    3 => (2, 0, 0, 0),
                    4 => (2, 1, 2, 0),
                    5 => (2, 1, 0, 1),
                    _ => (2, 1, 0, 0),
                };
                Sym::new(name.as_bytes(), bind << 4 | kind, other, shndx)
            })
            .collect();
        images.push(match rng.below(4) {
            0 => symbol_elf(None, Some(&symbols)),
            1 => symbol_elf(Some(&symbols), None),
            2 => symbol_elf(Some(&symbols[count / 2..]), Some(&symbols[..count / 2])),
            _ => symbol_elf(Some(&[]), Some(&symbols)),
        });
    }
    images
}

#[test]
fn differential_elf_import_md5_and_telfhash() {
    if !have_yr() {
        eprintln!("[elf hashes] skipped: `yr` (yara-x CLI) not on PATH");
        return;
    }
    let images = symbol_images();
    let inputs: Vec<&[u8]> = images.iter().map(Vec::as_slice).collect();
    let theirs = yr_elf_hashes(&inputs);
    let mut telfhashes = 0;
    for (i, (image, (md5, telfhash))) in images.iter().zip(&theirs).enumerate() {
        let md5 = md5.as_deref().expect("yr has an import_md5");
        let telfhash = match telfhash {
            Some(h) => {
                telfhashes += 1;
                format!("elf.telfhash() == \"{h}\"")
            }
            None => "not defined elf.telfhash()".to_string(),
        };
        let rules = exav_core::yara::compile(&format!(
            "import \"elf\" rule r {{ condition: elf.import_md5() == \"{md5}\" and {telfhash} }}"
        ))
        .expect("exav compile failed");
        assert_eq!(
            exav_matches(&rules, image).len(),
            1,
            "[elf hashes] image {i}: yara-x gives import_md5 {md5}, {telfhash}"
        );
    }
    // The comparison has to see both a hash and no hash.
    assert!(
        telfhashes > 100 && telfhashes < images.len(),
        "{telfhashes} of {} images have a telfhash",
        images.len()
    );
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

// --- dotnet module ---------------------------------------------------------

const DOTNET_RULES: &str = r#"
import "dotnet"
rule field_offset { condition: dotnet.field_offsets[0] == 9312 }
rule field_offsets_none { condition: dotnet.is_dotnet and dotnet.number_of_field_offsets == 0 }
rule field_offsets_len { condition: dotnet.field_offsets.len() == 1 }
rule resource_offset { condition: dotnet.resources[0].offset == 8852 }
rule resource_offset_edge { condition: dotnet.resources[0].offset == 8848 + 340 + 4 }
rule resource_offset_undefined {
    condition: dotnet.number_of_resources == 1 and not defined dotnet.resources[0].offset
}
rule resources_len { condition: dotnet.resources.len() == 1 and dotnet.streams.len() == 5 }
rule not_dotnet { condition: not dotnet.is_dotnet and dotnet.streams.len() == 0 }
"#;

/// The assemblies of `tests/fixtures/dotnet`, and copies with the fields that
/// the offsets of the module depend on changed (see `suites/yara_dotnet.rs`).
#[test]
fn differential_dotnet_offsets() {
    let sha3: &[u8] = include_bytes!("fixtures/dotnet/sha3_field_rva.dll");
    let buffers: &[u8] = include_bytes!("fixtures/dotnet/system_buffers_resource.dll");
    let reference: &[u8] = include_bytes!("fixtures/dotnet/system_buffers.dll");
    let mut inputs = vec![
        sha3.to_vec(),
        buffers.to_vec(),
        reference.to_vec(),
        b"MZ".to_vec(),
    ];
    let mut cut = sha3.to_vec();
    for at in [376 + 8, 376 + 16] {
        cut[at..at + 4].copy_from_slice(&0x2000u32.to_le_bytes());
    }
    inputs.push(cut);
    for (at, value) in [(4756, 340u32), (4756, 341), (520 + 24, 0x9000_0000)] {
        let mut data = buffers.to_vec();
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
        inputs.push(data);
    }
    let mut other_file = buffers.to_vec();
    other_file[4756 + 10] = 1;
    inputs.push(other_file);
    let inputs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    agree("dotnet", DOTNET_RULES, &inputs);
}

/// Assemblies with a header, a table or a heap damaged (`dotnet_damaged`):
/// every condition that was recorded from `yr` holds in `yr` and in exav.
#[test]
fn differential_dotnet_damaged() {
    if !have_yr() {
        eprintln!("[dotnet damaged] skipped: `yr` (yara-x CLI) not on PATH");
        return;
    }
    for case in dotnet_damaged::cases() {
        let rules: String = std::iter::once("import \"dotnet\"\n".to_string())
            .chain(
                case.holds
                    .iter()
                    .enumerate()
                    .map(|(i, cond)| format!("rule c{i} {{ condition: {cond} }}\n")),
            )
            .collect();
        let all: BTreeSet<String> = (0..case.holds.len()).map(|i| format!("c{i}")).collect();
        let exav = exav_core::yara::compile(&rules).expect("exav compile failed");
        assert_eq!(
            exav_matches(&exav, &case.data),
            all,
            "[{}] exav: some of {:?} does not hold",
            case.name,
            case.holds
        );
        assert_eq!(
            yr_matches(&rules, &case.data, &[]),
            all,
            "[{}] yara-x: some of {:?} does not hold",
            case.name,
            case.holds
        );
    }
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
rule len_sections   { condition: pe.sections.len() == 1 and pe.sections.len() == pe.number_of_sections }
rule len_no_sections { condition: pe.sections.len() == 0 }
rule len_of_a_bound_array { condition: with s = pe.sections : (s.len() > 0) }
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
