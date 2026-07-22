//! The `dotnet` YARA module, checked against yara-x.
//!
//! Every expected value here is `yr dump --module dotnet` output from the
//! yara-x CLI 1.19.0 — the reference implementation's, not this crate's. A
//! module validated against its own parser can agree with itself on a
//! misreading of the metadata format, and several of these fields are exactly
//! the kind that invites one:
//!
//! * `number_of_classes` excludes the `<Module>` pseudo-type that occupies
//!   TypeDef row 0, so it is the row count minus one;
//! * `constants` is only the *string* rows of the Constant table — on
//!   Newtonsoft.Json that is 95 of 568;
//! * `field_offsets` comes from **FieldRVA**, not the similarly-named
//!   FieldLayout table, which is usually empty;
//! * a one-byte `#US` entry is a lone flag byte with no characters, and is not
//!   counted.
//!
//! Each of those was wrong on the first pass and found by the diff.
//!
//! The fixture is `System.Buffers.dll` from the NuGet package (MIT). It is small
//! and exercises the container, the streams, the GUID heap and the assembly
//! tables. The count-heavy paths were additionally diffed against
//! Newtonsoft.Json 13.0.3 — 493 classes, 783 user strings, 95 constants, 22
//! field offsets, 22 assembly refs — which is too large to commit;
//! `scripts/yara-dotnet-difftest.sh` reproduces that run.

use exav_core::{analyze, loader, ScanOptions, Scanner, Verdict};

fn fixture() -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/dotnet/system_buffers.dll",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

/// Compile one rule into a scanner, via a temporary `.yar` file — the same path
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
    let db = scanner_for(condition).unwrap_or_else(|e| panic!("compile `{condition}`: {e}"));
    matches!(
        analyze(&db, &fixture(), &ScanOptions::default()).verdict,
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
        // outright — so every `pe` and `dotnet` rule shaped like this was
        // dropped, not just this one.
        "dotnet.assembly_refs[0].version.major > 0",
    ] {
        assert!(matches(cond), "expected `{cond}` to hold");
    }
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
