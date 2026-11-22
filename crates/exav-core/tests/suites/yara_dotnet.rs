//! The `dotnet` YARA module, checked against yara-x.
//!
//! Every expected value here is `yr dump --module dotnet` output from the
//! yara-x CLI 1.23.0, the reference implementation's, not this crate's. A
//! module validated against its own parser can agree with itself on a
//! misreading of the metadata format, and several of these fields are exactly
//! the kind that invites one:
//!
//! * `number_of_classes` excludes the `<Module>` pseudo-type that occupies
//!   TypeDef row 0, so it is the row count minus one;
//! * `constants` is only the *string* rows of the Constant table: on
//!   Newtonsoft.Json that is 95 of 568;
//! * `field_offsets` comes from **FieldRVA**, not the similarly-named
//!   FieldLayout table, which is usually empty, and holds file offsets, not the
//!   RVAs of the table;
//! * `resources[].offset` is the file offset of the data of a resource, after
//!   its four bytes of length;
//! * a one-byte `#US` entry is a lone flag byte with no characters, and is not
//!   counted.
//!
//! Each of those was wrong on the first pass and found by the diff.
//!
//! The fixture is `System.Buffers.dll` from the NuGet package (MIT). It is small
//! and exercises the container, the streams, the GUID heap and the assembly
//! tables. The count-heavy paths were additionally diffed against
//! Newtonsoft.Json 13.0.3 (493 classes, 783 user strings, 95 constants, 22
//! field offsets, 22 assembly refs), which is too large to commit;
//! `scripts/yara-dotnet-difftest.sh` reproduces that run.
//!
//! Two more assemblies from NuGet hold what that one does not: the netstandard2.0
//! build of System.Buffers 4.5.1 (MIT) has an embedded resource, and SHA3 1.0.0
//! (Apache-2.0) has a field with an initial value.

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};

#[path = "../dotnet_damaged/mod.rs"]
mod dotnet_damaged;

fn fixture() -> Vec<u8> {
    fixture_named("system_buffers.dll")
}

fn fixture_named(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/dotnet/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

/// Compile one rule into a scanner, via a temporary `.yar` file: the same path
/// the CLI takes for a rule set.
fn scanner_for(condition: &str) -> Result<Scanner, String> {
    let src = format!("import \"dotnet\"\nrule t {{ condition: {condition} }}\n");
    // Unique per call: the tests run in parallel within one process, and a
    // shared path means two of them writing the same file at once.
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("exav-dotnet-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(format!("t{}.yar", SEQ.fetch_add(1, Ordering::Relaxed)));
    std::fs::write(&path, src).expect("write rule");
    let r = loader::load_with_options(&path, false, false).map_err(|e| e.to_string());
    let _ = std::fs::remove_file(&path);
    r
}

/// Whether the rule both compiled and matched the fixture.
fn matches(condition: &str) -> bool {
    matches_in(&fixture(), condition)
}

/// As [`matches`], over the bytes `data`.
fn matches_in(data: &[u8], condition: &str) -> bool {
    let db = scanner_for(condition).unwrap_or_else(|e| panic!("compile `{condition}`: {e}"));
    matches!(
        analyze(&db, data, &ScanOptions::default()).verdict,
        Verdict::Infected { .. }
    )
}

#[test]
fn scalar_fields_match_yara_x() {
    for cond in [
        "dotnet.is_dotnet",
        r#"dotnet.module_name == "System.Buffers.dll""#,
        r#"dotnet.version == "v4.0.30319""#,
        "dotnet.number_of_streams == 5",
        "dotnet.number_of_guids == 1",
        "dotnet.number_of_classes == 2",
        "dotnet.number_of_assembly_refs == 1",
        "dotnet.number_of_modulerefs == 0",
        "dotnet.number_of_user_strings == 0",
        "dotnet.number_of_constants == 0",
        "dotnet.number_of_field_offsets == 0",
        "dotnet.number_of_resources == 0",
    ] {
        assert!(matches(cond), "expected `{cond}` to hold");
    }
}

#[test]
fn arrays_and_nested_structs_match_yara_x() {
    for cond in [
        r##"dotnet.streams[0].name == "#~""##,
        "dotnet.streams[1].size == 0x30c",
        r#"dotnet.guids[0] == "07b57855-b20d-4199-b234-1de66d29ec1e""#,
        r#"dotnet.assembly.name == "System.Buffers""#,
        "dotnet.assembly.version.major == 4",
        "dotnet.assembly.version.build_number == 2",
        r#"dotnet.assembly_refs[0].name == "System.Runtime""#,
        // A subscript followed by two more field steps. The parser groups the
        // tail into a nested field access, which the compiler used to reject
        // outright, so every `pe` and `dotnet` rule shaped like this was
        // dropped, not just this one.
        "dotnet.assembly_refs[0].version.major > 0",
    ] {
        assert!(matches(cond), "expected `{cond}` to hold");
    }
}

/// Header fields are the file's; none of them may panic the module, whatever the
/// value (a sum of a section's address and size, a raw pointer plus an offset,
/// a stream name running to the end of the file).
#[test]
fn fields_at_their_extremes_do_not_panic_the_module() {
    let db = scanner_for(
        r#"dotnet.number_of_streams == 99 or dotnet.number_of_resources == 99 or dotnet.number_of_classes == 99 or dotnet.version == "x""#,
    )
    .expect("compile");
    let base = fixture();
    let mut bad = Vec::new();
    let mut data = base.clone();
    for at in (0..base.len() - 4).step_by(4) {
        for v in [u32::MAX, 1 << 31, 0xFFFF_F000u32, 0xFFFF_FF00u32] {
            data[at..at + 4].copy_from_slice(&v.to_le_bytes());
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                analyze(&db, &data, &ScanOptions::default())
            }));
            if r.is_err() {
                bad.push(format!("{at:#x} {v:#x}"));
            }
        }
        data[at..at + 4].copy_from_slice(&base[at..at + 4]);
    }
    // The stream table at the end of the metadata root, cut short.
    for cut in (base.len() - 64..base.len()).step_by(1) {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            analyze(&db, &base[..cut], &ScanOptions::default())
        }));
        if r.is_err() {
            bad.push(format!("cut at {cut:#x}"));
        }
    }
    assert!(
        bad.is_empty(),
        "{} panics, first: {:?}",
        bad.len(),
        &bad[..bad.len().min(12)]
    );
}

#[test]
fn a_file_that_is_not_dotnet_reads_as_such() {
    // Every other field is left undefined rather than given a wrong value, which
    // is YARA's behaviour for a module that found nothing.
    let db = scanner_for("dotnet.is_dotnet").expect("compile");
    let not_dotnet = b"MZ\x90\x00this is not a managed assembly".to_vec();
    assert!(!matches!(
        analyze(&db, &not_dotnet, &ScanOptions::default()).verdict,
        Verdict::Infected { .. }
    ));
}

#[test]
fn len_of_an_array_matches_yara_x() {
    for cond in [
        "dotnet.streams.len() == 5",
        "dotnet.streams.len() == dotnet.number_of_streams",
        "dotnet.guids.len() == 1",
        "dotnet.assembly_refs.len() == 1",
        "dotnet.field_offsets.len() == 0",
        "dotnet.resources.len() == 0",
    ] {
        assert!(matches(cond), "expected `{cond}` to hold");
    }
    let not_dotnet = b"MZ\x90\x00this is not a managed assembly";
    assert!(matches_in(not_dotnet, "dotnet.streams.len() == 0"));
}

/// The RVA a FieldRVA row holds is converted to a file offset, and a row whose
/// RVA is in no section has no entry.
#[test]
fn field_offsets_are_file_offsets() {
    let assembly = fixture_named("sha3_field_rva.dll");
    // The RVA of the data is 0x2000 + 9312 - 0x200.
    assert!(matches_in(
        &assembly,
        "dotnet.number_of_field_offsets == 1 and dotnet.field_offsets[0] == 9312"
    ));
    // The size of the `.text` section (its header is at 376, the virtual size
    // 8 bytes into it and the size in the file 16) ends before the data.
    let mut cut = assembly.clone();
    for at in [376 + 8, 376 + 16] {
        cut[at..at + 4].copy_from_slice(&0x2000u32.to_le_bytes());
    }
    assert!(matches_in(
        &cut,
        "dotnet.is_dotnet and dotnet.number_of_field_offsets == 0 \
         and not defined dotnet.field_offsets[0]"
    ));
}

/// The offset of a resource is that of its data, four bytes after the offset
/// the table gives from the start of the resources of the CLI header; a
/// resource that is in another file, or that does not start inside those
/// resources, has none and still counts.
#[test]
fn a_resource_offset_is_the_file_offset_of_its_data() {
    let assembly = fixture_named("system_buffers_resource.dll");
    let name = r#"dotnet.resources[0].name == "FxResources.System.Buffers.SR.resources""#;
    assert!(matches_in(
        &assembly,
        &format!(
            "dotnet.number_of_resources == 1 and {name} and dotnet.resources[0].offset == 8852"
        )
    ));
    // The ManifestResource row is at 4756 (offset, flags, name, implementation),
    // and the resources of the CLI header, at 520 + 24, are 344 bytes.
    let patched = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut data = assembly.clone();
        edit(&mut data);
        data
    };
    let undefined = format!(
        "dotnet.number_of_resources == 1 and {name} and not defined dotnet.resources[0].offset"
    );
    let at = |data: &mut Vec<u8>, offset: usize, value: u32| {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    };
    // 340 and the 4 bytes of length end where the resources end.
    assert!(matches_in(
        &patched(&|d| at(d, 4756, 340)),
        "dotnet.resources[0].offset == 8848 + 340 + 4"
    ));
    assert!(matches_in(&patched(&|d| at(d, 4756, 341)), &undefined));
    // Held in another file.
    assert!(matches_in(&patched(&|d| d[4756 + 10] = 1), &undefined));
    // The resources of the CLI header in no section.
    assert!(matches_in(
        &patched(&|d| at(d, 520 + 24, 0x9000_0000)),
        &undefined
    ));
}

/// An assembly with a header, a table or a heap damaged reads as yara-x reads
/// it: what it cannot read is undefined, and what comes after a table it
/// cannot read is not read. The conditions are what `yr` holds true for each
/// case (`differential_dotnet_damaged` checks that it still does).
#[test]
fn a_damaged_assembly_reads_as_yara_x_reads_it() {
    let mut failed = Vec::new();
    for case in dotnet_damaged::cases() {
        for cond in &case.holds {
            if !matches_in(&case.data, cond) {
                failed.push(format!("{}: {cond}", case.name));
            }
        }
    }
    assert!(failed.is_empty(), "{} fail: {failed:#?}", failed.len());
}
