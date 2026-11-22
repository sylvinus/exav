//! The `elf` module: header fields, section/segment/symbol arrays, constants,
//! and the compile-time schema.
//!
//! `elf` is the standard module for Linux-focused rulesets, so a rule that uses
//! it must either evaluate correctly or fail to compile, never silently
//! evaluate to undefined.

mod elf_image;

use elf_image::{CONSTANTS, Image, SectionHeaders};

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

/// A rule over the `elf` module with `condition`.
fn elf_rule(condition: &str) -> String {
    format!(r#"import "elf" rule t {{ condition: {condition} }}"#)
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
    // vaddr 0x400000 / offset 0, so the file offset is 0x80. Reporting the raw
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
    // `elf.imphash` is not a function of the module.
    let e = compile_err(r#"import "elf" rule t { condition: elf.imphash() == "x" }"#);
    assert!(e.contains("elf"), "got: {e}");
}

/// The ELF's own numbers (entry, segment and section offsets and addresses)
/// are the file's; none of them may panic the module.
#[test]
fn fields_at_their_extremes_do_not_panic_the_module() {
    let rules = exav_core::yara::compile(
        r#"import "elf" rule t { condition: elf.entry_point == 1 or elf.number_of_sections == 99
           or for any s in elf.sections : (s.offset == 1 or s.name == "x")
           or for any g in elf.segments : (g.offset == 1) }"#,
    )
    .expect("compile");
    let mut bad = Vec::new();
    let mut data = TINY_ELF.to_vec();
    for at in (0..TINY_ELF.len() - 8).step_by(4) {
        for v in [
            u64::MAX,
            u64::MAX - 15,
            1 << 63,
            i64::MAX as u64,
            0xFFFF_FFFF_FFFF_F000,
        ] {
            data[at..at + 8].copy_from_slice(&v.to_le_bytes());
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rules.scan(&data).matching_rules().len()
            }));
            if r.is_err() {
                bad.push(format!("{at:#x} {v:#x}"));
            }
        }
        data[at..at + 8].copy_from_slice(&TINY_ELF[at..at + 8]);
    }
    assert!(
        bad.is_empty(),
        "{} panics, first: {:?}",
        bad.len(),
        &bad[..bad.len().min(12)]
    );
}

#[test]
fn elf_import_compiles() {
    // A rejected `import "elf"` drops every rule in a Linux-focused feed, so the
    // import has to compile even for a rule that touches no `elf.` field.
    assert!(exav_core::yara::compile(r#"import "elf" rule t { condition: true }"#).is_ok());
}

// The expected values of the tests below are those of yara-x's `elf` module on
// the same images (`yara_difftest` checks them against it).

/// Every field of the symbol tables, the dynamic section, the dynamic symbols
/// and their visibility, for both classes and byte orders.
#[test]
fn symbols_and_the_dynamic_section_in_every_class_and_byte_order() {
    for (wide, big) in [(false, false), (false, true), (true, false), (true, true)] {
        let rule = elf_rule(
            r#"elf.type == elf.ET_DYN and elf.machine == elf.EM_X86_64
                and elf.osabi == elf.OSABI_NONE
                and elf.number_of_sections == 6 and elf.number_of_segments == 2
                and elf.sections[1].name == ".dynsym" and elf.sections[1].type == elf.SHT_DYNSYM
                and elf.sections[3].name == ".symtab" and elf.sections[3].type == elf.SHT_SYMTAB
                and elf.sections[5].name == ".shstrtab"
                and elf.segments[1].type == elf.PT_DYNAMIC and elf.segments[1].flags == 6
                and elf.symtab_entries == 2
                and elf.symtab[1].name == "main" and elf.symtab[1].value == 0x1000
                and elf.symtab[1].size == 16 and elf.symtab[1].type == elf.STT_FUNC
                and elf.symtab[1].bind == elf.STB_GLOBAL and elf.symtab[1].shndx == 1
                and elf.symtab[1].visibility == elf.STV_DEFAULT
                and elf.dynamic_section_entries == 4
                and elf.dynamic[0].type == elf.DT_HASH and elf.dynamic[2].type == elf.DT_STRSZ
                and elf.dynamic[2].val == 18 and elf.dynamic[3].type == elf.DT_SYMTAB
                and elf.dynsym_entries == 4
                and elf.dynsym[1].name == "alpha" and elf.dynsym[1].value == 0x1234
                and elf.dynsym[1].size == 8 and elf.dynsym[1].shndx == 5
                and elf.dynsym[1].visibility == elf.STV_INTERNAL
                and elf.dynsym[2].name == "beta" and elf.dynsym[2].type == elf.STT_OBJECT
                and elf.dynsym[2].bind == elf.STB_WEAK and elf.dynsym[2].shndx == 0xfff1
                and elf.dynsym[2].visibility == elf.STV_PROTECTED
                and elf.dynsym[3].name == "gamma" and elf.dynsym[3].visibility == elf.STV_HIDDEN"#,
        );
        assert!(
            matches(&rule, &Image::new(wide, big).bytes()),
            "wide {wide}, big {big}"
        );
    }
}

/// The dynamic symbols are the `SHT_DYNSYM` section: the dynamic section does
/// not locate them, and no table in it (a hash table whose words are not those
/// of the architecture, as on s390x) can make them undefined.
#[test]
fn dynsym_is_the_section_whatever_the_dynamic_section_says() {
    let rule = elf_rule(
        r#"elf.dynsym_entries == 4 and elf.dynsym[1].name == "alpha"
           and elf.dynsym[3].name == "gamma""#,
    );
    let mut image = Image::new(true, false);
    image.dt_symtab = false;
    assert!(matches(&rule, &image.bytes()), "no DT_SYMTAB");

    let mut image = Image::new(true, true);
    image.machine = 22;
    image.hash_bucket = 1;
    assert!(
        matches(&rule, &image.bytes()),
        "s390x with a table of 32-bit words"
    );
}

/// Without section headers there is no symbol table, and the counts are 0; if
/// the table is not in the file they are undefined. The segments are read all
/// the same.
#[test]
fn without_section_headers_there_are_no_symbols() {
    let mut image = Image::new(true, false);
    image.section_headers = SectionHeaders::Absent;
    let bytes = image.bytes();
    assert!(matches(
        &elf_rule(
            r#"elf.dynsym_entries == 0 and elf.symtab_entries == 0 and elf.number_of_sections == 0
               and not defined elf.dynsym[0].name and not defined elf.symtab[0].name
               and not defined elf.sections[0].type and elf.dynamic_section_entries == 4"#
        ),
        &bytes
    ));

    // Even with no section to read, the offset has to be in the file.
    for (headers, count) in [
        (SectionHeaders::PastEnd, 6),
        (SectionHeaders::PastEndNoCount, 0),
    ] {
        image.section_headers = headers;
        assert!(matches(
            &elf_rule(&format!(
                r#"not defined elf.dynsym_entries and not defined elf.symtab_entries
                   and elf.number_of_sections == {count} and not defined elf.sections[0].type
                   and elf.dynamic_section_entries == 4"#
            )),
            &image.bytes()
        ));
    }
}

/// The counts of the tables a file does not have are defined, and 0.
#[test]
fn the_counts_of_the_tables_a_file_does_not_have_are_zero() {
    let mut image = Image::new(true, false);
    image.section_headers = SectionHeaders::Absent;
    image.e_phnum = Some(0);
    let bytes = image.bytes();
    assert!(matches(
        &elf_rule(
            r#"elf.number_of_segments == 0 and elf.dynamic_section_entries == 0
               and elf.symtab_entries == 0 and elf.dynsym_entries == 0"#
        ),
        &bytes
    ));
}

/// `e_phoff` 0 is an offset like another: the records are read from the start
/// of the file (the ELF header itself) when they all fit, and there are none
/// when they do not.
#[test]
fn e_phoff_zero_reads_the_segments_at_the_start_of_the_file() {
    for (big, magic) in [(false, 0x464c_457f_i64), (true, 0x7f45_4c46)] {
        let mut image = Image::new(true, big);
        image.e_phoff_zero = true;
        assert!(
            matches(
                &elf_rule(&format!(
                    "elf.number_of_segments == 2 and elf.segments[0].type == {magic}
                     and elf.dynamic_section_entries == 0"
                )),
                &image.bytes()
            ),
            "big {big}"
        );
    }
    let mut image = Image::new(true, false);
    image.e_phoff_zero = true;
    image.e_phnum = Some(200);
    assert!(matches(
        &elf_rule(
            r#"elf.number_of_segments == 200 and not defined elf.segments[0].type
               and elf.type == elf.ET_DYN"#
        ),
        &image.bytes()
    ));
}

#[test]
fn osabi_is_the_identification_byte() {
    let mut image = Image::new(false, true);
    image.osabi = 3;
    assert!(matches(
        &elf_rule("elf.osabi == elf.OSABI_LINUX"),
        &image.bytes()
    ));
    image.osabi = 0x42;
    assert!(matches(&elf_rule("elf.osabi == 66"), &image.bytes()));
}

/// The end of the dynamic section is not an entry and nothing after it is
/// read; every `PT_DYNAMIC` segment adds its entries; a tag is a signed 32-bit
/// number, like the types of sections and segments.
#[test]
fn dynamic_entries_stop_before_the_end_marker_and_types_are_signed() {
    for wide in [false, true] {
        let image = Image::new(wide, false);
        assert!(matches(
            &elf_rule(
                r#"elf.dynamic_section_entries == 4 and not defined elf.dynamic[4].type
                   and not (for any d in elf.dynamic : (d.type == elf.DT_NULL))"#
            ),
            &image.bytes()
        ));

        let mut image = Image::new(wide, true);
        image.second_dynamic = true;
        assert!(matches(
            &elf_rule(
                r#"elf.dynamic_section_entries == 6 and elf.dynamic[3].type == elf.DT_SYMTAB
                   and elf.dynamic[4].type == elf.DT_HASH and elf.dynamic[5].type == elf.DT_STRTAB"#
            ),
            &image.bytes()
        ));

        let mut image = Image::new(wide, false);
        image.high_types = true;
        assert!(matches(
            &elf_rule(
                r#"elf.dynamic_section_entries == 5 and elf.dynamic[4].type == -2147483648
                   and elf.dynamic[4].val == 9
                   and elf.sections[6].type == -2147483648
                   and elf.segments[2].type == -2147483647"#
            ),
            &image.bytes()
        ));
    }
}

/// `elf.entry_point` is undefined for `e_entry` 0, even where an address 0 is
/// mapped. A segment (of any type) maps it in an executable or a shared
/// object, a section in any other file.
#[test]
fn entry_point_by_the_type_of_the_file() {
    let mut image = Image::new(true, false);
    image.base = 0;
    assert!(matches(
        &elf_rule("not defined elf.entry_point"),
        &image.bytes()
    ));

    // The sections are 0x100000 above the segment.
    let layout = Image::new(true, false).build().1;
    let mut image = Image::new(true, false);
    image.section_shift = 0x10_0000;
    let in_segment = image.va(layout.dynstr) + 3;
    let in_section = in_segment + 0x10_0000;
    let offset = layout.dynstr + 3;
    let defined = elf_rule(&format!("elf.entry_point == {offset}"));
    let undefined = elf_rule("not defined elf.entry_point");
    for (e_type, entry, mapped) in [
        (3, in_segment, true),
        (2, in_segment, true),
        (3, in_section, false),
        (0, in_segment, false),
        (1, in_section, true),
        (0, in_section, true),
        (4, in_section, true),
    ] {
        image.e_type = e_type;
        image.entry = entry;
        assert!(
            matches(if mapped { &defined } else { &undefined }, &image.bytes()),
            "type {e_type}, entry {entry:#x}"
        );
    }

    // No entry point, as in yara-x, when the number of sections is an index of
    // the reserved range.
    let mut image = Image::new(true, false);
    image.entry = image.va(layout.dynstr);
    assert!(matches(
        &elf_rule(&format!("elf.entry_point == {}", layout.dynstr)),
        &image.bytes()
    ));
    for e_shnum in [0xfeff, 0xff00, 0xffff] {
        image.e_shnum = Some(e_shnum);
        assert_eq!(
            matches(&undefined, &image.bytes()),
            e_shnum >= 0xff00,
            "e_shnum {e_shnum:#x}"
        );
    }

    // A section with no bytes in the file maps nothing.
    let mut image = Image::new(true, false);
    image.nobits = true;
    image.e_type = 1;
    image.entry = image.va(0x40) + 4;
    assert!(matches(&undefined, &image.bytes()));
}

/// The symbols of a table are the first section of the type: a second
/// `SHT_SYMTAB` is not read, and `sh_entsize` does not count them.
#[test]
fn symbol_tables_are_the_first_of_their_type_sized_by_the_symbol_size() {
    let mut image = Image::new(true, false);
    image.second_symtab = true;
    image.symtab_entsize_zero = true;
    assert!(matches(
        &elf_rule(
            r#"elf.number_of_sections == 7 and elf.symtab_entries == 2
               and elf.symtab[1].name == "main" and elf.dynsym_entries == 4"#
        ),
        &image.bytes()
    ));
}

/// Names are read from the file at the offset of the string section, up to the
/// end of the file; undefined without such a section.
#[test]
fn names_are_read_from_the_file_where_the_string_section_starts() {
    // Section 0 has no offset: the names are those of the first bytes.
    let mut image = Image::new(true, false);
    image.e_shstrndx = 0;
    assert!(matches(
        &elf_rule(
            r#"elf.sections[0].name contains "ELF" and elf.sections[1].type == elf.SHT_DYNSYM"#
        ),
        &image.bytes()
    ));
    image.e_shstrndx = 99;
    assert!(matches(
        &elf_rule(
            r#"elf.number_of_sections == 6 and not defined elf.sections[1].name
               and elf.sections[1].type == elf.SHT_DYNSYM"#
        ),
        &image.bytes()
    ));
}

/// Every constant of yara-x, and none it does not have.
#[test]
fn constants_are_those_of_yara_x() {
    for (name, value) in CONSTANTS {
        assert!(
            matches(&elf_rule(&format!("elf.{name} == {value}")), b""),
            "{name}"
        );
    }
    let e = compile_err(&elf_rule("elf.SHF_ALLOC == 2"));
    assert!(e.contains("SHF_ALLOC"), "got: {e}");
}

/// `.len()` of an array, as yara-x gives it: the number of elements, 0 for an
/// array the file does not have, and defined for a file that is not an ELF.
#[test]
fn len_of_an_array_is_its_number_of_elements() {
    let image = Image::new(true, false).bytes();
    for (condition, expected) in [
        ("elf.sections.len() == 6", true),
        ("elf.segments.len() == 2", true),
        ("elf.dynsym.len() == 4", true),
        ("elf.symtab.len() == 2", true),
        ("elf.dynamic.len() == 4", true),
        ("elf.sections.len() == elf.number_of_sections", true),
        ("elf.dynsym.len() == elf.dynsym_entries", true),
        ("elf.sections.len() + elf.segments.len() == 8", true),
        ("elf.sections.len() == 5", false),
        // In a range, and on an array bound by `with`.
        (
            "for any i in (0..elf.sections.len() - 1) : (elf.sections[i].type == elf.SHT_DYNSYM)",
            true,
        ),
        ("with s = elf.sections : (s.len() == 6)", true),
    ] {
        assert_eq!(
            matches(&elf_rule(condition), &image),
            expected,
            "{condition}"
        );
    }
    let mut image = Image::new(true, false);
    image.section_headers = SectionHeaders::Absent;
    let image = image.bytes();
    assert!(matches(&elf_rule("elf.sections.len() == 0"), &image));
    assert!(matches(&elf_rule("elf.dynsym.len() == 0"), &image));
    assert!(matches(&elf_rule("defined elf.symtab.len()"), &image));
    // Not an ELF: the module has no values, and a count is still 0.
    assert!(matches(&elf_rule("elf.segments.len() == 0"), b"MZ"));
    assert!(matches(
        &elf_rule("not defined elf.number_of_segments"),
        b"MZ"
    ));
}

/// `.len()` exists only for an array or a map, and takes no argument.
#[test]
fn len_of_anything_else_is_a_compile_error() {
    for condition in [
        "elf.type.len() == 1",
        "elf.sections[0].len() == 1",
        "elf.sections.len(1) == 1",
        "elf.sections.size() == 1",
        "elf.number_of_sections.len() == 1",
    ] {
        compile_err(&elf_rule(condition));
    }
}

// Values of `yr` 1.23.0 on the same symbols. The functions read the dynamic
// symbols, and the symbols when the file has no dynamic ones.

fn call_is(call: &str, expected: &str, data: &[u8]) -> bool {
    matches(&elf_rule(&format!("elf.{call}() == \"{expected}\"")), data)
}

fn call_is_undefined(call: &str, data: &[u8]) -> bool {
    matches(&elf_rule(&format!("not defined elf.{call}()")), data)
}

const EMPTY_MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";

#[test]
fn import_md5_is_the_md5_of_the_sorted_lowercase_names_of_the_undefined_symbols() {
    use elf_image::{Sym, symbol_elf};
    let symbols = [
        Sym::import("Zeta_Import"),
        Sym::import("alpha_import"),
        Sym::import("beta_import"),
        Sym::func("own_function"),
        // An undefined weak symbol and an undefined object count.
        Sym::new(b"weak_import", 0x20, 0, 0),
        Sym::new(b"data_import", 0x11, 0, 0),
    ];
    let md5 = "d9147e48a6daf6eac6904a21078f1a40";
    assert!(call_is(
        "import_md5",
        md5,
        &symbol_elf(Some(&symbols), None)
    ));
    // The symbol table when there is no dynamic one.
    assert!(call_is(
        "import_md5",
        md5,
        &symbol_elf(None, Some(&symbols))
    ));
    // The dynamic one when there are both.
    let tab = [Sym::import("tab_import_one"), Sym::import("tab_import_two")];
    assert!(call_is(
        "import_md5",
        "fb75df12d34580406cd9b39997469e2c",
        &symbol_elf(Some(&[Sym::import("dyn_import_one")]), Some(&tab)),
    ));
    // A file without symbols, one with only defined ones, and a file that is
    // not an ELF.
    assert!(call_is(
        "import_md5",
        EMPTY_MD5,
        &symbol_elf(None, Some(&[]))
    ));
    assert!(call_is(
        "import_md5",
        EMPTY_MD5,
        &symbol_elf(Some(&[Sym::func("a_defined_function")]), None),
    ));
    assert!(call_is("import_md5", EMPTY_MD5, b"MZ"));
    // Names are lowercased as text and a byte that is not UTF-8 is replaced.
    let names = [
        Sym::import("Caf\u{c9}_imp"),
        Sym::new(b"bad\xff_import", 0x12, 0, 0),
        Sym::import("plain_import"),
    ];
    assert!(call_is(
        "import_md5",
        "472f27f5a6394a4e4dee77de66aec6d3",
        &symbol_elf(Some(&names), None),
    ));
    compile_err(&elf_rule("elf.import_md5(1) == \"\""));
}

#[test]
fn telfhash_hashes_the_global_functions_without_the_excluded_names() {
    use elf_image::{Sym, symbol_elf};
    let kept = [
        "isl_options_set_schedule_separate_components",
        "isl_poly_neginfty",
        "menu_driver",
        "sd_varlink_server_listen_fd",
    ];
    let mut symbols: Vec<Sym> = kept.iter().map(|n| Sym::import(n)).collect();
    // Names that are left out, by the list and by the first and last letters.
    for n in [
        "main",
        "__libc_start_main",
        "_init",
        "strcpy",
        "memcpy",
        "sym64",
        ".hidden",
    ] {
        symbols.push(Sym::import(n));
    }
    // A weak function, an object, a hidden function and a local one.
    symbols.push(Sym::new(b"weakfn_not_counted", 0x22, 0, 0));
    symbols.push(Sym::new(b"object_not_counted", 0x11, 0, 0));
    symbols.push(Sym::new(b"hiddenfn_not_counted", 0x12, 2, 0));
    symbols.push(Sym::new(b"localfn_not_counted", 0x02, 0, 0));
    let hash = "T1C9B012D72504440F8EC2A1EFC9336996B39542C09546914ED171A4C78000C468648841";
    assert!(call_is("telfhash", hash, &symbol_elf(Some(&symbols), None)));
    assert!(call_is("telfhash", hash, &symbol_elf(None, Some(&symbols))));

    // The dynamic symbols are the ones read even when they have no function.
    let objects = [Sym::new(b"only_object", 0x11, 0, 0)];
    let image = symbol_elf(Some(&objects), Some(&symbols));
    assert!(call_is_undefined("telfhash", &image));
    // Under 50 bytes of names, no symbols, and not an ELF.
    let short = [Sym::import("Zeta_Import"), Sym::import("alpha_import")];
    assert!(call_is_undefined(
        "telfhash",
        &symbol_elf(Some(&short), None)
    ));
    assert!(call_is_undefined("telfhash", &symbol_elf(None, Some(&[]))));
    assert!(call_is_undefined("telfhash", b"MZ"));
    compile_err(&elf_rule("elf.telfhash(1) == \"\""));
}
