//! Copies of the `system_buffers.dll` fixture with one header, table or heap
//! damaged, and the conditions that `yr` 1.23.0 (yara-x) holds true for each:
//! what it reads out of an assembly that is not well formed. `suites/yara_dotnet.rs`
//! checks that exav holds the same conditions, `yara_difftest.rs` that `yr`
//! still does and that both engines agree.
#![allow(dead_code)]

const FIXTURE: &[u8] = include_bytes!("../fixtures/dotnet/system_buffers.dll");

// Where the fields that the cases change are in the fixture.
const PE_SIGNATURE: usize = 0x80;
const NUMBER_OF_SECTIONS: usize = 0x86;
const OPTIONAL_HEADER: usize = 0x98;
const NUMBER_OF_RVA_AND_SIZES: usize = 0xf4;
const SECTIONS: usize = 0x178;
const CLI_HEADER: usize = 0x208;
const METADATA_SIZE: usize = CLI_HEADER + 12;
const ROOT: usize = 0x264;
const VERSION: usize = ROOT + 16;
const STREAMS: usize = ROOT + 0x20;
/// The `#~` stream is the first of the five, the `#US` the third, `#GUID` the fourth.
const TILDE_SIZE: usize = STREAMS + 4;
const TILDE_NAME: usize = STREAMS + 8;
const US_SIZE: usize = STREAMS + 0x24;
const GUID_NAME: usize = STREAMS + 0x34;
const US: usize = 0x87c;
const STRINGS: usize = 0x570;
/// Row counts, in table order: Module, TypeRef, TypeDef, MethodDef, Param,
/// MemberRef, Constant, CustomAttribute, PropertyMap, Property,
/// MethodSemantics, Assembly, AssemblyRef, GenericParam.
const ROWS: usize = 0x2e8;
const TYPEDEF_ROWS: usize = ROWS + 8;
const METHODDEF_ROWS: usize = ROWS + 12;
const ASSEMBLYREF_ROWS: usize = ROWS + 48;
const TYPEDEF: usize = 0x3a2;
const MEMBERREF: usize = 0x44c;
const CONSTANT: usize = 0x4b8;
const CUSTOM_ATTRIBUTE: usize = 0x4be;
const ASSEMBLY: usize = 0x53a;
const ASSEMBLYREF: usize = 0x550;

pub struct Case {
    pub name: &'static str,
    pub data: Vec<u8>,
    /// Conditions on the `dotnet` module that yara-x holds true for `data`.
    pub holds: Vec<&'static str>,
}

fn patched(edits: &[(usize, &[u8])]) -> Vec<u8> {
    let mut data = FIXTURE.to_vec();
    for &(at, bytes) in edits {
        data[at..at + bytes.len()].copy_from_slice(bytes);
    }
    data
}

fn word(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}

fn dword(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// A section header whose address range holds the CLI header and the metadata,
/// and that maps all of it to the start of the file.
fn remapping_section() -> Vec<u8> {
    let mut h = b".fake\0\0\0".to_vec();
    for v in [0x10_0000u32, 0x2000, 0x1_0000, 0, 0, 0, 0, 0x6000_0020] {
        h.extend(dword(v));
    }
    h
}

/// The fixture with its metadata root written again: `version_len` bytes of
/// version string, then the list of streams (`first` before the five of the
/// fixture) right after them, and the heaps moved to the end of the file.
fn rebuilt_root(version_len: usize, first: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut streams: Vec<(Vec<u8>, Vec<u8>)> = first
        .iter()
        .map(|&(name, data)| (name.to_vec(), data.to_vec()))
        .collect();
    let mut at = STREAMS;
    for _ in 0..5 {
        let word = |at: usize| u32::from_le_bytes(FIXTURE[at..at + 4].try_into().unwrap()) as usize;
        let (offset, size) = (word(at), word(at + 4));
        let name_end = at + 8 + FIXTURE[at + 8..].iter().position(|&b| b == 0).unwrap();
        streams.push((
            FIXTURE[at + 8..name_end].to_vec(),
            FIXTURE[ROOT + offset..ROOT + offset + size].to_vec(),
        ));
        at += 8 + (name_end - (at + 8) + 1).next_multiple_of(4);
    }
    let mut data = FIXTURE.to_vec();
    let mut root = b"BSJB\x01\0\x01\0\0\0\0\0".to_vec();
    root.extend(dword(version_len as u32));
    let mut version = b"v4.0.30319".to_vec();
    version.resize(version_len, 0);
    root.extend(version);
    root.extend(word(0));
    root.extend(word(streams.len() as u16));
    let mut heaps = Vec::new();
    for (name, bytes) in &streams {
        let mut entry = dword((data.len() - ROOT + heaps.len()) as u32).to_vec();
        entry.extend(dword(bytes.len() as u32));
        entry.extend(name);
        entry.push(0);
        entry.resize(entry.len().next_multiple_of(4), 0);
        root.extend(entry);
        heaps.extend(bytes);
        heaps.resize(heaps.len().next_multiple_of(4), 0);
    }
    // The first section ends at 0xe00: the root has to stay inside it.
    assert!(ROOT + root.len() < 0xe00);
    data[ROOT..ROOT + root.len()].copy_from_slice(&root);
    data.extend(heaps);
    data
}

/// The cases.
pub fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    let mut add = |name, data, holds| cases.push(Case { name, data, holds });

    // The section headers: at most 96 are read, and those whole in the file.
    let section = |index: usize| SECTIONS + 40 * index;
    let fake = remapping_section();
    add(
        "the 97th section header is not read",
        patched(&[(NUMBER_OF_SECTIONS, &word(97)), (section(96), &fake)]),
        vec!["dotnet.is_dotnet", "dotnet.number_of_streams == 5"],
    );
    add(
        "the 96th section header is read",
        patched(&[(NUMBER_OF_SECTIONS, &word(96)), (section(95), &fake)]),
        vec!["not dotnet.is_dotnet"],
    );
    let mut data = patched(&[(NUMBER_OF_SECTIONS, &word(200))]);
    data.truncate(0x1000);
    add(
        "section headers run past the end of the file",
        data,
        vec!["dotnet.is_dotnet", "dotnet.number_of_classes == 2"],
    );
    for (name, cut, holds) in [
        (
            "a section header cut by the end of the file is not read",
            section(64) + 39,
            "dotnet.is_dotnet",
        ),
        (
            "a section header whole at the end of the file is read",
            section(64) + 40,
            "not dotnet.is_dotnet",
        ),
    ] {
        let mut data = patched(&[(NUMBER_OF_SECTIONS, &word(65)), (section(64), &fake)]);
        data.truncate(cut);
        add(name, data, vec![holds]);
    }

    // No table stream, or one that does not hold its tables: the assembly is
    // one, with no tables.
    let no_tables = vec![
        "dotnet.is_dotnet",
        "dotnet.number_of_streams == 5",
        "dotnet.number_of_classes == 0",
        "dotnet.number_of_assembly_refs == 0",
        "not defined dotnet.module_name",
    ];
    add(
        "a table stream too short for its header",
        patched(&[(TILDE_SIZE, &dword(0x17))]),
        no_tables.clone(),
    );
    add(
        "a table stream shorter than its row counts",
        patched(&[(TILDE_SIZE, &dword(0x30))]),
        no_tables.clone(),
    );
    add(
        "a table stream past the end of the file",
        patched(&[(TILDE_SIZE, &dword(0x10_0000))]),
        no_tables.clone(),
    );
    add(
        "no table stream",
        patched(&[(TILDE_NAME, b"#X")]),
        no_tables.clone(),
    );
    let mut data = FIXTURE.to_vec();
    data.truncate(0x500);
    add("a table stream cut by the end of the file", data, no_tables);

    // User strings.
    let user_strings =
        |content: &[u8], size: u32| patched(&[(US_SIZE, &dword(size)), (US, content)]);
    add(
        "a user string where the stream starts",
        user_strings(b"\x03A\0\x01", 4),
        vec![
            "dotnet.number_of_user_strings == 1",
            r#"dotnet.user_strings[0] == "A\x00""#,
        ],
    );
    add(
        "a user string cut by the end of the stream voids all",
        user_strings(b"\0\x03A\0\x01\x03B\0", 8),
        vec!["dotnet.number_of_user_strings == 0"],
    );
    add(
        "a user string of one character byte is skipped",
        user_strings(b"\0\x02A\x01\x03B\0\x01", 8),
        vec![
            "dotnet.number_of_user_strings == 1",
            r#"dotnet.user_strings[0] == "B\x00""#,
        ],
    );
    add(
        "an invalid length ends the user strings",
        user_strings(b"\0\x03A\0\x01\xe0\x03B\0\x01", 10),
        vec![
            "dotnet.number_of_user_strings == 1",
            r#"dotnet.user_strings[0] == "A\x00""#,
        ],
    );

    // Names and blobs that cannot be read are undefined.
    let name_at = |field: usize, index: u16| patched(&[(field, &word(index))]);
    for (name, data) in [
        (
            "an assembly name past the string heap",
            name_at(ASSEMBLY + 18, 0xfff0),
        ),
        (
            "an assembly name at the end of the string heap",
            name_at(ASSEMBLY + 18, 780),
        ),
    ] {
        add(
            name,
            data,
            vec![
                "not defined dotnet.assembly.name",
                "dotnet.assembly.version.major == 4",
            ],
        );
    }
    add(
        "an assembly reference name past the string heap",
        name_at(ASSEMBLYREF + 14, 0xfff0),
        vec![
            "not defined dotnet.assembly_refs[0].name",
            "dotnet.number_of_assembly_refs == 1",
        ],
    );
    for (name, index) in [
        ("a public key past the blob heap", 0xfff0),
        ("an empty public key", 0),
    ] {
        add(
            name,
            name_at(ASSEMBLYREF + 12, index),
            vec![
                "not defined dotnet.assembly_refs[0].public_key_or_token",
                r#"dotnet.assembly_refs[0].name == "System.Runtime""#,
            ],
        );
    }
    add(
        "a module name that is not UTF-8",
        patched(&[(STRINGS + 0x22e + 3, b"\xff")]),
        vec![
            "not defined dotnet.module_name",
            r#"dotnet.assembly.name == "System.Buffers""#,
        ],
    );
    add(
        "a stream name that is not UTF-8",
        patched(&[(GUID_NAME + 3, b"\xff")]),
        vec![
            "not defined dotnet.streams[3].name",
            "dotnet.streams[3].size == 16",
            "dotnet.number_of_streams == 5",
        ],
    );
    add(
        "a version that is not UTF-8",
        patched(&[(VERSION + 3, b"\xff")]),
        vec!["not dotnet.is_dotnet"],
    );

    // The classes: the TypeDef rows with a name, other than `<Module>`.
    let name_of = |row: usize| FIXTURE[TYPEDEF + 14 * row + 4..][..2].to_vec();
    for (name, data, holds) in [
        (
            "a class name past the string heap",
            patched(&[(TYPEDEF + 14 + 4, &word(0xfff0))]),
            "dotnet.number_of_classes == 1",
        ),
        (
            "an empty class name",
            patched(&[(TYPEDEF + 14 + 4, &word(0))]),
            "dotnet.number_of_classes == 1",
        ),
        (
            "a class namespace past the string heap",
            patched(&[(TYPEDEF + 14 + 6, &word(0xfff0))]),
            "dotnet.number_of_classes == 2",
        ),
        (
            "the first row is a class when it has another name",
            patched(&[(TYPEDEF + 4, &name_of(1))]),
            "dotnet.number_of_classes == 3",
        ),
        (
            "a second row named <Module> is not a class",
            patched(&[(TYPEDEF + 14 + 4, &name_of(0))]),
            "dotnet.number_of_classes == 1",
        ),
    ] {
        add(name, data, vec![holds]);
    }

    // A table that does not parse ends the tables read: the assembly and its
    // references come after the first that is damaged. The classes and the
    // module name come before.
    let lost_after = vec![
        "defined dotnet.module_name",
        "dotnet.number_of_classes == 2",
        "dotnet.number_of_assembly_refs == 0",
        "not defined dotnet.assembly.version.major",
    ];
    for (name, data) in [
        (
            "a custom attribute parent that names no table",
            patched(&[(CUSTOM_ATTRIBUTE, &word(0x011f))]),
        ),
        (
            "a custom attribute type that names no table",
            patched(&[(CUSTOM_ATTRIBUTE + 2, &word(0x0105))]),
        ),
        (
            "a member reference class that names no table",
            patched(&[(MEMBERREF, &word(0x0105))]),
        ),
        (
            "a constant parent that names no table",
            patched(&[(CONSTANT + 2, &word(0x0103))]),
        ),
        (
            "a constant type that is no element type",
            patched(&[(CONSTANT, &[0x90])]),
        ),
        (
            "a table that ends past the table stream",
            patched(&[(TILDE_SIZE, &dword(0x100))]),
        ),
        (
            "a table of a huge number of rows",
            patched(&[(METHODDEF_ROWS, &dword(0x7fff_ffff))]),
        ),
    ] {
        add(name, data, lost_after.clone());
    }
    add(
        "a type extends that names no table",
        patched(&[(TYPEDEF + 14 + 8, &word(0x0103))]),
        vec![
            "dotnet.number_of_classes == 0",
            "dotnet.number_of_assembly_refs == 0",
            "not defined dotnet.assembly.version.major",
        ],
    );
    for (name, data) in [
        (
            "an assembly reference row cut by the end of the table stream",
            patched(&[(TILDE_SIZE, &dword(0x293))]),
        ),
        (
            "a second assembly reference row past the table stream",
            patched(&[(ASSEMBLYREF_ROWS, &dword(2))]),
        ),
    ] {
        add(
            name,
            data,
            vec![
                "dotnet.number_of_assembly_refs == 0",
                r#"dotnet.assembly.name == "System.Buffers""#,
                "dotnet.number_of_classes == 2",
            ],
        );
    }
    add(
        "the module row cut by the end of the table stream",
        patched(&[(TILDE_SIZE, &dword(0x40))]),
        vec![
            "dotnet.number_of_classes == 0",
            "not defined dotnet.module_name",
        ],
    );

    // At most 15,000 rows of a table are read, and the indexes are sized for
    // no more.
    add(
        "an assembly reference table of 2^24 rows",
        patched(&[(ASSEMBLYREF_ROWS, &dword(1 << 24))]),
        lost_after.clone(),
    );
    // 2,049 rows of a table that a custom attribute parent can name widen it
    // to 4 bytes, and the rows after it are not where they were.
    add(
        "2,048 assembly reference rows keep the custom attribute parent 2 bytes",
        patched(&[(ASSEMBLYREF_ROWS, &dword(2048))]),
        vec![
            r#"dotnet.assembly.name == "System.Buffers""#,
            "dotnet.number_of_assembly_refs == 0",
        ],
    );
    add(
        "2,049 assembly reference rows widen the custom attribute parent",
        patched(&[(ASSEMBLYREF_ROWS, &dword(2049))]),
        lost_after.clone(),
    );
    add(
        "a type table of 15,001 rows",
        patched(&[(TYPEDEF_ROWS, &dword(15_001))]),
        vec![
            "dotnet.number_of_classes == 0",
            "defined dotnet.module_name",
        ],
    );

    // The metadata root.
    let streams_ok = vec![
        "dotnet.number_of_streams == 5",
        "dotnet.number_of_classes == 2",
    ];
    add(
        "a version length that is not a multiple of 4",
        rebuilt_root(10, &[]),
        streams_ok.clone(),
    );
    add("a version of 255 bytes", rebuilt_root(255, &[]), streams_ok);
    add(
        "a version of 256 bytes",
        rebuilt_root(256, &[]),
        vec!["not dotnet.is_dotnet"],
    );
    let extra: Vec<(Vec<u8>, &[u8])> = (0..70)
        .map(|i| (format!("#{i:02}").into_bytes(), &b"abcd"[..]))
        .collect();
    let extra: Vec<(&[u8], &[u8])> = extra.iter().map(|(n, d)| (n.as_slice(), *d)).collect();
    add(
        "75 streams",
        rebuilt_root(12, &extra),
        vec![
            "dotnet.number_of_streams == 75",
            "dotnet.number_of_classes == 2",
        ],
    );
    add(
        "two table streams",
        rebuilt_root(12, &[(b"#~", &[0; 30])]),
        vec![
            "dotnet.number_of_streams == 6",
            "dotnet.number_of_classes == 2",
            "defined dotnet.module_name",
        ],
    );
    add(
        "two string heaps",
        rebuilt_root(12, &[(b"#Strings", b"x\0")]),
        vec![
            "dotnet.number_of_streams == 6",
            r#"dotnet.module_name == "System.Buffers.dll""#,
        ],
    );
    add(
        "a metadata size that ends with the list of streams",
        patched(&[(METADATA_SIZE, &dword(0x6c))]),
        vec!["dotnet.is_dotnet", "dotnet.number_of_streams == 5"],
    );
    add(
        "a metadata size that ends in the list of streams",
        patched(&[(METADATA_SIZE, &dword(0x6b))]),
        vec!["not dotnet.is_dotnet"],
    );

    // The PE header and the CLI header.
    for (name, value) in [("no data directories", 0), ("14 data directories", 14)] {
        add(
            name,
            patched(&[(NUMBER_OF_RVA_AND_SIZES, &dword(value))]),
            vec!["dotnet.is_dotnet", "dotnet.number_of_classes == 2"],
        );
    }
    add(
        "a CLI header size other than 0x48",
        patched(&[(CLI_HEADER, &dword(0x49))]),
        vec!["not dotnet.is_dotnet"],
    );
    add(
        "an optional header that is neither PE32 nor PE32+",
        patched(&[(OPTIONAL_HEADER, &word(0x107))]),
        vec!["dotnet.is_dotnet", "dotnet.number_of_classes == 2"],
    );
    add(
        "a PE32+ magic over a PE32 layout",
        patched(&[(OPTIONAL_HEADER, &word(0x20b))]),
        vec!["not dotnet.is_dotnet"],
    );
    add(
        "a PE signature that is not",
        patched(&[(PE_SIGNATURE, b"PX")]),
        vec!["not dotnet.is_dotnet"],
    );
    cases
}
