//! The `elf` module: header fields, section/segment/symbol arrays, constants,
//! and the compile-time schema.
//!
//! `elf` is the standard module for Linux-focused rulesets, so a rule that uses
//! it must either evaluate correctly or fail to compile — never silently
//! evaluate to undefined.

const TINY_ELF: &[u8] = include_bytes!("testdata/tiny_elf64");

fn matches(rule: &str, data: &[u8]) -> bool {
    let rules =
        exav_core::yara::compile(rule).unwrap_or_else(|e| panic!("compile failed: {e}\n{rule}"));
    rules.scan(data).matching_rules().len() == 1
}

fn compile_err(rule: &str) -> String {
    match exav_core::yara::compile(rule) {
        Ok(_) => panic!("expected a compile error for:\n{rule}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn header_fields() {
    // ET_EXEC / EM_X86_64, from the fixture's ELF header.
    assert!(matches(
        r#"import "elf" rule t { condition: elf.type == elf.ET_EXEC }"#,
        TINY_ELF
    ));
    assert!(matches(
        r#"import "elf" rule t { condition: elf.machine == elf.EM_X86_64 }"#,
        TINY_ELF
    ));
    assert!(matches(
        r#"import "elf" rule t { condition: elf.number_of_sections == 3 and elf.number_of_segments == 1 }"#,
        TINY_ELF
    ));
}

#[test]
fn entry_point_is_a_file_offset_not_a_virtual_address() {
    // The fixture's entry VA is 0x400080, mapped by the PT_LOAD segment at
    // vaddr 0x400000 / offset 0 — so the file offset is 0x80. Reporting the raw
    // e_entry here is the classic mistake; YARA reports the offset.
    assert!(matches(
        r#"import "elf" rule t { condition: elf.entry_point == 0x80 }"#,
        TINY_ELF
    ));
    assert!(!matches(
        r#"import "elf" rule t { condition: elf.entry_point == 0x400080 }"#,
        TINY_ELF
    ));
}

#[test]
fn sections_are_iterable() {
    assert!(matches(
        r#"import "elf"
           rule t { condition: for any s in elf.sections : (s.name == ".text") }"#,
        TINY_ELF
    ));
    assert!(matches(
        r#"import "elf"
           rule t { condition:
             for any s in elf.sections :
               (s.name == ".text" and s.type == elf.SHT_PROGBITS
                and s.flags & 0x4 != 0) }"#,
        TINY_ELF
    ));
    assert!(!matches(
        r#"import "elf"
           rule t { condition: for any s in elf.sections : (s.name == ".nope") }"#,
        TINY_ELF
    ));
}

#[test]
fn segments_are_iterable() {
    assert!(matches(
        r#"import "elf"
           rule t { condition:
             for any s in elf.segments :
               (s.type == elf.PT_LOAD and s.flags == elf.PF_R | elf.PF_X) }"#,
        TINY_ELF
    ));
}

#[test]
fn indexed_access_works() {
    assert!(matches(
        r#"import "elf" rule t { condition: elf.sections[1].name == ".text" }"#,
        TINY_ELF
    ));
    assert!(matches(
        r#"import "elf" rule t { condition: elf.segments[0].type == elf.PT_LOAD }"#,
        TINY_ELF
    ));
}

#[test]
fn non_elf_input_leaves_fields_undefined_rather_than_wrong() {
    // Every field must read undefined (so conditions are false) instead of
    // evaluating against garbage.
    let not_elf = b"MZ\x90\x00 this is not an ELF at all";
    assert!(!matches(
        r#"import "elf" rule t { condition: elf.type == elf.ET_EXEC }"#,
        not_elf
    ));
    assert!(!matches(
        r#"import "elf" rule t { condition: elf.number_of_sections == 0 }"#,
        not_elf
    ));
}

#[test]
fn unknown_fields_are_compile_errors_not_silent_undefined() {
    // The schema is explicit so that a gap in it is visible rather than silent.
    let e = compile_err(r#"import "elf" rule t { condition: elf.no_such_field == 1 }"#);
    assert!(
        e.contains("elf") && e.contains("no_such_field"),
        "error should name the module and field, got: {e}"
    );
    let e = compile_err(
        r#"import "elf" rule t { condition: for any s in elf.sections : (s.bogus == 1) }"#,
    );
    assert!(e.contains("bogus"), "got: {e}");
    // `elf` has no functions in YARA, so a call is a genuine error.
    let e = compile_err(r#"import "elf" rule t { condition: elf.imphash() == "x" }"#);
    assert!(e.contains("elf"), "got: {e}");
}

#[test]
fn elf_import_compiles() {
    // A rejected `import "elf"` drops every rule in a Linux-focused feed, so the
    // import has to compile even for a rule that touches no `elf.` field.
    assert!(exav_core::yara::compile(r#"import "elf" rule t { condition: true }"#).is_ok());
}
