//! The import hash of a PE (`.imp` signatures) and the imports the YARA `pe`
//! module lists, as clamscan 1.4.3 and libyara 4.5.2 make them: the hashes and
//! sizes below are the ones `clamscan --debug` prints for these files, and the
//! YARA values those of `yara -D`.

use std::io::Cursor;

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader, scan_seekable};
use exav_unpack::zip_write::{FileOptions, Method, ZipWriter};
use md5::{Digest, Md5};

/// What a thunk of [`pe`] holds.
enum Imp<'a> {
    /// A hint/name entry with this hint and name.
    Name(&'a str, u16),
    Ordinal(u16),
}
use Imp::{Name, Ordinal};

fn put(v: &mut [u8], at: usize, bytes: &[u8]) {
    v[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put16(v: &mut [u8], at: usize, n: u16) {
    put(v, at, &n.to_le_bytes());
}

fn put32(v: &mut [u8], at: usize, n: u32) {
    put(v, at, &n.to_le_bytes());
}

/// A PE32 (PE32+ if `wide`) of `.text` and `.idata`, whose import table lists
/// `libs`: descriptors and the null one, the libraries' names, a thunk table
/// each (the lookup table is the address table), and the hint/name entries.
/// 300 zero bytes follow, so that every entry is more than 258 bytes from the
/// end of the file, as the import hash needs.
fn pe(wide: bool, libs: &[(&str, &[Imp])]) -> Vec<u8> {
    pe_filled(wide, libs, 0)
}

/// [`pe`] with `fill` zero bytes between the libraries' names and the thunk
/// tables, which moves the tables and the entries toward the end of `.idata`.
fn pe_filled(wide: bool, libs: &[(&str, &[Imp])], fill: usize) -> Vec<u8> {
    let (thunk, opt_size, dirs) = if wide { (8, 0xf0, 112) } else { (4, 0xe0, 96) };
    let rva = |at: usize| (0x2000 + at) as u32;
    let mut idata = vec![0u8; 20 * (libs.len() + 1)];
    let mut names = Vec::new();
    for (name, _) in libs {
        names.push(idata.len());
        idata.extend_from_slice(name.as_bytes());
        idata.push(0);
    }
    idata.resize((idata.len() + fill).next_multiple_of(8), 0);
    let mut tables = Vec::new();
    for (_, imps) in libs {
        tables.push(idata.len());
        idata.resize(idata.len() + thunk * (imps.len() + 1), 0);
    }
    for (i, (_, imps)) in libs.iter().enumerate() {
        for (j, imp) in imps.iter().enumerate() {
            let value = match imp {
                Name(name, hint) => {
                    idata.resize(idata.len().next_multiple_of(2), 0);
                    let at = idata.len();
                    idata.extend_from_slice(&hint.to_le_bytes());
                    idata.extend_from_slice(name.as_bytes());
                    idata.push(0);
                    u64::from(rva(at))
                }
                Ordinal(n) => (1u64 << (8 * thunk - 1)) | u64::from(*n),
            };
            let at = tables[i] + thunk * j;
            put(&mut idata, at, &value.to_le_bytes()[..thunk]);
        }
        put32(&mut idata, 20 * i, rva(tables[i]));
        put32(&mut idata, 20 * i + 12, rva(names[i]));
        put32(&mut idata, 20 * i + 16, rva(tables[i]));
    }
    let dir_size = 20 * (libs.len() + 1);
    let raw = idata.len().next_multiple_of(0x200);
    let mut f = vec![0u8; 0x400 + raw];
    put(&mut f, 0, b"MZ");
    put32(&mut f, 0x3c, 0x40);
    put(&mut f, 0x40, b"PE\0\0");
    put16(&mut f, 0x44, if wide { 0x8664 } else { 0x14c });
    put16(&mut f, 0x46, 2); // sections
    put16(&mut f, 0x54, opt_size);
    put16(&mut f, 0x56, if wide { 0x0022 } else { 0x0102 });
    let opt = 0x58;
    put16(&mut f, opt, if wide { 0x20b } else { 0x10b });
    put32(&mut f, opt + 16, 0x1000); // entry point
    put32(&mut f, opt + 20, 0x1000); // base of code
    put32(&mut f, opt + 32, 0x1000); // section alignment
    put32(&mut f, opt + 36, 0x200); // file alignment
    put32(&mut f, opt + 56, 0x2000 + raw as u32); // size of image
    put32(&mut f, opt + 60, 0x200); // size of headers
    put16(&mut f, opt + 68, 3); // subsystem
    put32(&mut f, opt + dirs - 4, 16); // data directories
    put32(&mut f, opt + dirs + 8, rva(0)); // the import table
    put32(&mut f, opt + dirs + 12, dir_size as u32);
    let table = opt + opt_size as usize;
    for (at, name, size, va, ptr, flags) in [
        (table, &b".text"[..], 0x200, 0x1000, 0x200, 0x6000_0020u32),
        (table + 40, b".idata", raw, 0x2000, 0x400, 0xc000_0040),
    ] {
        put(&mut f, at, name);
        put32(&mut f, at + 8, size as u32); // virtual size
        put32(&mut f, at + 12, va);
        put32(&mut f, at + 16, size as u32); // raw size
        put32(&mut f, at + 20, ptr);
        put32(&mut f, at + 36, flags);
    }
    put(&mut f, 0x400, &idata);
    f.resize(f.len() + 300, 0);
    f
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn md5_of(s: &str) -> String {
    hex(&Md5::digest(s.as_bytes()))
}

fn db(files: &[(&str, &str)]) -> Scanner {
    let mut b = loader::Builder::new();
    for (name, text) in files {
        b.add_named_bytes(name, text.as_bytes(), true);
    }
    b.build().expect("build db")
}

fn found(db: &Scanner, file: &[u8], opts: &ScanOptions) -> Option<String> {
    match analyze(db, file, opts).verdict {
        Verdict::Infected { signature, .. } => Some(signature),
        _ => None,
    }
}

/// Four functions of two libraries, one by ordinal. `clamscan --debug` prints
/// `IMP: 74d5ac01e60a489ceee1bff98faf59c3:78` for this file: the size is the
/// length of `kernel32.loadlibrarya,kernel32.getprocaddress,user32.messageboxa,
/// user32.ord100`, not the number of imports, which is 4.
fn four_functions(wide: bool) -> Vec<u8> {
    pe(
        wide,
        &[
            (
                "KERNEL32.DLL",
                &[Name("LoadLibraryA", 0), Name("GetProcAddress", 0)],
            ),
            ("USER32.DLL", &[Name("MessageBoxA", 0), Ordinal(100)]),
        ],
    )
}

const FOUR: &str = "74d5ac01e60a489ceee1bff98faf59c3";

#[test]
fn an_imp_signature_carries_the_length_of_the_hashed_string_as_its_size() {
    let f = four_functions(false);
    for opts in [ScanOptions::default(), ScanOptions::clamav_compat()] {
        let sig = |size: &str| db(&[("a.imp", &format!("{FOUR}:{size}:Sig.Imp\n"))]);
        assert_eq!(
            found(&sig("78"), &f, &opts).as_deref(),
            Some("Sig.Imp"),
            "clamscan's size"
        );
        assert_eq!(
            found(&sig("*"), &f, &opts).as_deref(),
            Some("Sig.Imp"),
            "any size"
        );
        assert_eq!(found(&sig("4"), &f, &opts), None, "the number of imports");
        assert_eq!(found(&sig("79"), &f, &opts), None);
        assert_eq!(found(&sig("77"), &f, &opts), None);
    }
}

/// Three libraries of one function each.
fn three_libraries() -> Vec<u8> {
    pe(
        false,
        &[
            ("KERNEL32.DLL", &[Name("LoadLibraryA", 0)]),
            ("USER32.DLL", &[Name("MessageBoxA", 0)]),
            ("GDI32.DLL", &[Name("BitBlt", 0)]),
        ],
    )
}

const THREE: [&str; 3] = [
    "kernel32.loadlibrarya",
    "user32.messageboxa",
    "gdi32.bitblt",
];

/// `f` with the size of its import data directory set to `size`.
fn with_directory_size(mut f: Vec<u8>, size: u32) -> Vec<u8> {
    // The PE32 optional header is at 0x58, its data directories 96 bytes in.
    put32(&mut f, 0x58 + 96 + 8 + 4, size);
    f
}

/// clamscan reads the descriptors that leave more than 20 bytes of the
/// directory unread, and makes no hash for an empty directory or one that ends
/// past the file.
#[test]
fn an_imp_signature_covers_the_descriptors_the_size_of_the_directory_leaves_room_for() {
    let opts = ScanOptions::default();
    for (size, read) in [
        (0x28, 1),
        (0x29, 2),
        (0x3c, 2),
        (0x3d, 3),
        (0x50, 3),
        (0x100, 3),
    ] {
        let f = with_directory_size(three_libraries(), size);
        let hashed = THREE[..read].join(",");
        let sig = db(&[(
            "a.imp",
            &format!("{}:{}:Sig.Imp\n", md5_of(&hashed), hashed.len()),
        )]);
        assert_eq!(
            found(&sig, &f, &opts).as_deref(),
            Some("Sig.Imp"),
            "size {size:#x}"
        );
        if read < 3 {
            let all = THREE.join(",");
            let sig = db(&[("a.imp", &format!("{}:*:Sig.Imp\n", md5_of(&all)))]);
            assert_eq!(found(&sig, &f, &opts), None, "size {size:#x}: the three");
        }
    }
    let all = THREE.join(",");
    let sig = db(&[("a.imp", &format!("{}:*:Sig.Imp\n", md5_of(&all)))]);
    for size in [0, 0x100000] {
        let f = with_directory_size(three_libraries(), size);
        assert_eq!(found(&sig, &f, &opts), None, "size {size:#x}");
    }
}

/// `three_libraries` with the name of the second library at an address no
/// section holds.
fn second_library_unreadable() -> Vec<u8> {
    let mut f = three_libraries();
    put32(&mut f, 0x400 + 20 + 12, 0x9000);
    f
}

/// A descriptor that the directory leaves room for and that cannot be read is
/// left out. clamscan makes no import hash then; the scan says it did not see
/// all, unless a check finds something in the descriptors that were read.
#[test]
fn a_descriptor_that_cannot_be_read_marks_the_scan_and_hides_nothing_else() {
    let f = second_library_unreadable();
    let opts = ScanOptions::default();
    // The hash of the others is not made, so no signature for it matches.
    let others = [THREE[0], THREE[2]].join(",");
    let sig = db(&[("a.imp", &format!("{}:*:Sig.Imp\n", md5_of(&others)))]);
    match analyze(&sig, &f, &opts).verdict {
        Verdict::Unscannable { reason } => {
            assert!(reason.contains("part of the import table"), "{reason}")
        }
        other => panic!("expected UNSCANNABLE, got {other:?}"),
    }
    // The whole table of the same file with the name readable is hashed.
    let all = THREE.join(",");
    let sig = db(&[("a.imp", &format!("{}:*:Sig.Imp\n", md5_of(&all)))]);
    assert_eq!(
        found(&sig, &three_libraries(), &opts).as_deref(),
        Some("Sig.Imp")
    );
}

/// A section's data is taken from its pointer rounded down to 0x200, as
/// clamscan and libyara take it: the pointer of `.idata` here is 0x10 past
/// where its data is.
#[test]
fn a_section_pointer_that_is_not_aligned_is_rounded_down() {
    let mut f = four_functions(false);
    // The second section header is at 0x138 + 40; its pointer is 20 bytes in.
    put32(&mut f, 0x138 + 40 + 20, 0x410);
    let sig = db(&[("a.imp", &format!("{FOUR}:78:Sig.Imp\n"))]);
    assert_eq!(
        found(&sig, &f, &ScanOptions::default()).as_deref(),
        Some("Sig.Imp")
    );
}

const LIMIT: u64 = 16 * 1024;

/// The distance of an entry from the end of the file that the import hash
/// looks at is that of the object, and not that of the image a scan holds of a
/// PE over `--max-object-bytes`.
#[test]
fn the_distance_of_an_entry_from_the_end_is_that_of_the_object_and_not_of_its_image() {
    let libs: [(&str, &[Imp]); 1] = [("K.DLL", &[Name("A", 0), Name("B", 0)])];
    // The entries are at the end of the last page of the image, which ends at
    // 0x1400; the file goes on for more than 258 bytes after them.
    let mut f = pe_filled(false, &libs, 0xf90);
    let at_b = f.windows(4).position(|w| w == b"\0\0B\0").unwrap() + 1;
    assert!(
        0x1400 - at_b < 258 && f.len() - at_b >= 258,
        "{at_b:#x} {:#x}",
        f.len()
    );
    f.extend((0..3 * LIMIT).map(|i| 0x80 + (i % 64) as u8));
    let hashed = "k.a,k.b";
    let sig = db(&[(
        "a.imp",
        &format!("{}:{}:Sig.Imp\n", md5_of(hashed), hashed.len()),
    )]);
    let opts = ScanOptions::default();
    assert_eq!(
        found(&sig, &f, &opts).as_deref(),
        Some("Sig.Imp"),
        "held in memory"
    );
    let mut small = ScanOptions::default();
    small.limits.max_buffer_bytes = LIMIT;
    small.object_cache_block_bytes = 4096;
    small.object_cache_bytes = 4 * 4096;
    let seen = scan_seekable(&sig, Cursor::new(f.clone()), f.len() as u64, &small).expect("scan");
    assert!(
        matches!(&seen.verdict, Verdict::Infected { signature, .. } if signature == "Sig.Imp"),
        "{:?}",
        seen.verdict
    );
}

/// `ws2_32`, `wsock32` and `oleaut32` name their ordinals in clamscan and
/// libyara, and other libraries do not (`user32.ord100`).
fn by_ordinal(wide: bool) -> Vec<u8> {
    pe(
        wide,
        &[
            ("WS2_32.dll", &[Ordinal(115), Name("connect", 0)]),
            ("OLEAUT32.dll", &[Ordinal(2)]),
            ("USER32.dll", &[Ordinal(100)]),
        ],
    )
}

const ORDINALS: &str = "ws2_32.wsastartup,ws2_32.connect,oleaut32.sysallocstring,user32.ord100";

#[test]
fn an_import_by_ordinal_matches_an_imp_signature_by_the_name_of_the_function() {
    let f = by_ordinal(false);
    let (hash, len) = (md5_of(ORDINALS), ORDINALS.len());
    assert_eq!(len, 70);
    let sigs = db(&[("a.imp", &format!("{hash}:{len}:Sig.Ordinals\n"))]);
    assert_eq!(
        found(&sigs, &f, &ScanOptions::default()).as_deref(),
        Some("Sig.Ordinals")
    );
    // The hash with the ordinals as `ord<n>` is not the one.
    let numbered = "ws2_32.ord115,ws2_32.connect,oleaut32.ord2,user32.ord100";
    let sigs = db_with(&format!(
        "{}:{}:Sig.Numbered\n",
        md5_of(numbered),
        numbered.len()
    ));
    assert_eq!(found(&sigs, &f, &ScanOptions::default()), None);
}

fn db_with(imp: &str) -> Scanner {
    db(&[("a.imp", imp)])
}

/// clamscan makes no import hash of a PE32+: a signature does not match one
/// under `--clamav-compat`, and does otherwise.
#[test]
fn a_pe32_plus_matches_no_imp_signature_under_clamav_compat() {
    let f = four_functions(true);
    let db = db(&[("a.imp", &format!("{FOUR}:78:Sig.Imp\n"))]);
    assert_eq!(
        found(&db, &f, &ScanOptions::default()).as_deref(),
        Some("Sig.Imp")
    );
    assert_eq!(found(&db, &f, &ScanOptions::clamav_compat()), None);
    // The same imports in a PE32 match in both.
    let f32 = four_functions(false);
    assert_eq!(
        found(&db, &f32, &ScanOptions::clamav_compat()).as_deref(),
        Some("Sig.Imp")
    );
}

/// What it is, the PE32, its usual import hash, and clamscan's hash with the
/// length of what it is of.
type TwoHashes = (
    &'static str,
    Vec<u8>,
    &'static str,
    Option<(&'static str, usize)>,
);

/// PE32 files whose usual import hash and clamscan's differ, with both: the
/// usual one is what pefile 2024.8.26 `get_imphash()` gives (and `pe.imphash()`
/// of yara-x 1.21.0), the other what `clamscan --debug` prints as `IMP: hash:size`
/// (none for C++ names).
fn two_hashes() -> Vec<TwoHashes> {
    vec![
        (
            "lua5.1.dll",
            pe(
                false,
                &[
                    (
                        "KERNEL32.DLL",
                        &[Name("LoadLibraryA", 0), Name("GetProcAddress", 0)],
                    ),
                    ("lua5.1.dll", &[Name("lua_close", 0)]),
                ],
            ),
            "a45c60f2fafbe13e8ce8e3d498a61620",
            Some(("1920ebec25090a48291d58a4f4ed8e84", 66)),
        ),
        (
            "ordinals and x.dll.dll",
            pe(
                false,
                &[
                    ("WS2_32.dll", &[Ordinal(115), Name("connect", 0)]),
                    ("OLEAUT32.dll", &[Ordinal(2)]),
                    ("USER32.dll", &[Ordinal(100)]),
                    ("x.dll.dll", &[Name("f", 0)]),
                ],
            ),
            "c6fe27f236b98c0471ddee10ed2c1836",
            Some(("3194c6bb5232733e3548bdeb870689df", 74)),
        ),
        (
            "a C++ name",
            pe(
                false,
                &[("MSVCP140.dll", &[Name("??0exception@std@@QEAA@XZ", 0)])],
            ),
            "11acd039b7870cde38ca3e9813c97b91",
            None,
        ),
        (
            "ws2_32.dllx and .sys, .Ocx",
            pe(
                false,
                &[
                    ("ws2_32.dllx", &[Ordinal(115)]),
                    ("A.SYS", &[Name("Fn", 0)]),
                    ("b.Ocx", &[Name("g", 0)]),
                ],
            ),
            "2a6e29e5197005a7d07b43c0bffb2442",
            Some(("2efe4d837823bd986278ec24a1213ac2", 26)),
        ),
    ]
}

/// The `imphash:` lines of a `.fdb` file carry the usual import hash, the
/// value of `pe.imphash()`, and the `.imp` signatures the one clamscan prints.
/// Each matches its own, and not the other's.
#[test]
fn an_imphash_line_is_matched_with_the_usual_import_hash_and_an_imp_signature_with_clamscans() {
    for (what, f, usual, clamscan) in two_hashes() {
        let line = |hash: &str| db(&[("a.fdb", &format!("imphash:{hash}:Sig.Fdb\n"))]);
        let sig = |hash: &str, size: &str| db(&[("a.imp", &format!("{hash}:{size}:Sig.Imp\n"))]);
        for opts in [ScanOptions::default(), ScanOptions::clamav_compat()] {
            assert_eq!(
                found(&line(usual), &f, &opts).as_deref(),
                Some("Sig.Fdb"),
                "{what}"
            );
            assert_eq!(found(&sig(usual, "*"), &f, &opts), None, "{what}");
            let Some((hash, size)) = clamscan else {
                continue;
            };
            assert_eq!(found(&line(hash), &f, &opts), None, "{what}");
            assert_eq!(
                found(&sig(hash, &size.to_string()), &f, &opts).as_deref(),
                Some("Sig.Imp"),
                "{what}"
            );
            assert_eq!(
                found(&sig(hash, "*"), &f, &opts).as_deref(),
                Some("Sig.Imp"),
                "{what}"
            );
        }
    }
}

/// clamscan makes no import hash of a PE32+, so `--clamav-compat` matches it
/// no `.imp` signature; an `imphash:` line is exav's own, and matches.
#[test]
fn an_imphash_line_matches_a_pe32_plus_under_clamav_compat() {
    let libs: [(&str, &[Imp]); 2] = [
        ("KERNEL32.DLL", &[Name("LoadLibraryA", 0)]),
        ("lua5.1.dll", &[Name("lua_close", 0)]),
    ];
    let (wide, narrow) = (pe(true, &libs), pe(false, &libs));
    let usual = md5_of("kernel32.loadlibrarya,lua5.1.lua_close");
    let hashed = "kernel32.loadlibrarya,lua5.1.dll.lua_close";
    let line = db(&[("a.fdb", &format!("imphash:{usual}:Sig.Fdb\n"))]);
    let sig = db(&[(
        "a.imp",
        &format!("{}:{}:Sig.Imp\n", md5_of(hashed), hashed.len()),
    )]);
    for opts in [ScanOptions::default(), ScanOptions::clamav_compat()] {
        assert_eq!(found(&line, &wide, &opts).as_deref(), Some("Sig.Fdb"));
        assert_eq!(found(&line, &narrow, &opts).as_deref(), Some("Sig.Fdb"));
    }
    assert_eq!(
        found(&sig, &wide, &ScanOptions::default()).as_deref(),
        Some("Sig.Imp")
    );
    assert_eq!(found(&sig, &wide, &ScanOptions::clamav_compat()), None);
}

/// pefile has no import hash for a PE with no imports, and a line with the
/// hash of the empty string matches none. clamscan makes that hash (of length
/// 0) for one, and an `.imp` signature for it matches.
#[test]
fn a_pe_with_no_imports_matches_no_imphash_line() {
    let f = pe(false, &[]);
    let empty = md5_of("");
    let line = db(&[("a.fdb", &format!("imphash:{empty}:Sig.Fdb\n"))]);
    let sig = db(&[("a.imp", &format!("{empty}:*:Sig.Imp\n"))]);
    let opts = ScanOptions::default();
    assert_eq!(found(&line, &f, &opts), None);
    assert_eq!(found(&sig, &f, &opts).as_deref(), Some("Sig.Imp"));
}

/// A PE whose imports no signature of either kind is for, with a `.fdb` file
/// of other lines, is clean: the `imphash:` lookup does not match by default.
#[test]
fn an_imphash_line_for_other_imports_matches_nothing() {
    let line = db(&[(
        "a.fdb",
        "imphash:00000000000000000000000000000000:Sig.Other\ntlsh:T1:Sig.Tlsh\n",
    )]);
    for (_, f, _, _) in two_hashes() {
        assert_eq!(found(&line, &f, &ScanOptions::default()), None);
    }
}

/// Under `--detect exav-heuristics` the findings carry both import hashes:
/// `imphash` is the one clamscan makes (what a `.imp` signature is made from),
/// `pe-imphash` the usual one, which an `imphash:` line made from it matches.
#[test]
fn the_usual_import_hash_is_a_finding_that_makes_an_imphash_line() {
    for (what, f, usual, clamscan) in two_hashes() {
        let report = analyze(&db(&[]), &f, &heuristics());
        let get = |label: &str| {
            report
                .findings
                .iter()
                .find(|finding| finding.label == label)
                .map(|finding| finding.detail.clone())
        };
        assert_eq!(get("pe-imphash").as_deref(), Some(usual), "{what}");
        let clamscan = clamscan.map_or("-", |(hash, _)| hash);
        assert_eq!(get("imphash").as_deref(), Some(clamscan), "{what}");
        let line = db(&[(
            "a.fdb",
            &format!("imphash:{}:Sig.Line\n", get("pe-imphash").unwrap()),
        )]);
        assert_eq!(
            found(&line, &f, &ScanOptions::default()).as_deref(),
            Some("Sig.Line"),
            "{what}"
        );
    }
    // Without the flag there are none.
    let (_, f, _, _) = two_hashes().remove(0);
    let report = analyze(&db(&[]), &f, &ScanOptions::default());
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.label != "pe-imphash")
    );
}

/// An installer or self-extractor: a compiled AutoIt script behind a PE.
fn installer(f: Vec<u8>) -> Vec<u8> {
    let mut f = f;
    // The script GUID, then the marker, as in a compiled script.
    f.extend_from_slice(&[
        0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C, 0x53, 0x0A, 0x86, 0xD6, 0x48,
        0x7D,
    ]);
    f.extend_from_slice(b"AU3!EA06");
    f.extend((0..1000).map(|i| (i % 251) as u8));
    f
}

/// scanning an installer ends with its members, and never reached the import
/// hash of the executable: clamscan matches `.imp` signatures against it.
#[test]
fn the_executable_of_an_installer_matches_imp_signatures_and_imphash_lines() {
    for (what, f, usual, clamscan) in two_hashes() {
        let f = installer(f);
        let line = db(&[("a.fdb", &format!("imphash:{usual}:Sig.Fdb\n"))]);
        for opts in [ScanOptions::default(), ScanOptions::clamav_compat()] {
            assert_eq!(
                found(&line, &f, &opts).as_deref(),
                Some("Sig.Fdb"),
                "{what}"
            );
            if let Some((hash, size)) = clamscan {
                let sig = db(&[("a.imp", &format!("{hash}:{size}:Sig.Imp\n"))]);
                assert_eq!(found(&sig, &f, &opts).as_deref(), Some("Sig.Imp"), "{what}");
            }
        }
    }
}

/// The TLSH digest of `f`, as a `.fdb` file holds it.
fn tlsh_of(f: &[u8]) -> String {
    let mut b = tlsh2::TlshDefaultBuilder::new();
    b.update(f);
    String::from_utf8_lossy(&b.build().expect("a digest").hash()).into_owned()
}

fn heuristics() -> ScanOptions {
    let mut opts = ScanOptions::default();
    opts.heuristics = true;
    opts
}

/// A `tlsh:` line made from an installer matches the installer's executable,
/// as it does any other file, under `--detect exav-heuristics` only. It could
/// not match before: the scan of an installer ended with its members.
#[test]
fn a_tlsh_line_matches_the_executable_of_an_installer() {
    let f = installer(two_hashes().remove(0).1);
    let line = db(&[("a.fdb", &format!("tlsh:{}:Sig.Tlsh:0\n", tlsh_of(&f)))]);
    assert_eq!(found(&line, &f, &heuristics()).as_deref(), Some("Sig.Tlsh"));
    assert_eq!(found(&line, &f, &ScanOptions::default()), None);
    assert_eq!(found(&line, &f, &ScanOptions::clamav_compat()), None);
}

/// An installer over the size an object is held at has its executable read
/// through the cache and matched: one whose format is read whole after its
/// members end over the limit, which is kept aside and reported when nothing
/// matches, and a self-extractor whose archive is read from the cache.
#[cfg(feature = "all-formats")]
#[test]
fn a_tlsh_line_for_an_installer_executable_over_the_size_an_object_is_held_at() {
    use std::io::Write;
    let verdict = |line: &Scanner, f: &[u8]| {
        let mut small = heuristics();
        small.limits.max_buffer_bytes = 1024;
        small.object_cache_block_bytes = 4096;
        small.object_cache_bytes = 4 * 4096;
        assert!(f.len() as u64 > small.limits.max_buffer_bytes);
        scan_seekable(line, Cursor::new(f.to_vec()), f.len() as u64, &small)
            .expect("scan")
            .verdict
    };
    let autoit = installer(two_hashes().remove(0).1);
    let line = db(&[("a.fdb", &format!("tlsh:{}:Sig.Tlsh:0\n", tlsh_of(&autoit)))]);
    let seen = verdict(&line, &autoit);
    assert!(
        matches!(&seen, Verdict::Infected { signature, .. } if signature == "Sig.Tlsh"),
        "{seen:?}"
    );
    let none = db(&[("a.ndb", "Sig.None:0:*:6e6f7468696e67206d617463686573\n")]);
    let seen = verdict(&none, &autoit);
    assert!(matches!(seen, Verdict::LimitsExceeded { .. }), "{seen:?}");

    let mut z = ZipWriter::new(Cursor::new(Vec::new()));
    let deflated = FileOptions::default().method(Method::Deflated);
    z.start_file("a.txt", deflated).unwrap();
    z.write_all(b"a member of the self-extractor, nothing more")
        .unwrap();
    let mut sfx = two_hashes().remove(0).1;
    sfx.extend((0..1000).map(|i| (i % 251) as u8));
    sfx.extend_from_slice(&z.finish().unwrap().into_inner());
    let line = db(&[("a.fdb", &format!("tlsh:{}:Sig.Tlsh:0\n", tlsh_of(&sfx)))]);
    let seen = verdict(&line, &sfx);
    assert!(
        matches!(&seen, Verdict::Infected { signature, .. } if signature == "Sig.Tlsh"),
        "{seen:?}"
    );
}

/// A detection in a member of the installer is reported before its
/// executable's `tlsh:` line.
#[cfg(feature = "all-formats")]
#[test]
fn a_member_of_an_installer_is_found_before_its_tlsh_line() {
    use std::io::Write;
    let member = b"a member of the self-extractor, nothing more";
    let mut z = ZipWriter::new(Cursor::new(Vec::new()));
    let deflated = FileOptions::default().method(Method::Deflated);
    z.start_file("a.txt", deflated).unwrap();
    z.write_all(member).unwrap();
    let mut sfx = two_hashes().remove(0).1;
    sfx.extend((0..1000).map(|i| (i % 251) as u8));
    sfx.extend_from_slice(&z.finish().unwrap().into_inner());
    let sigs = db(&[
        ("a.fdb", &format!("tlsh:{}:Sig.Tlsh:0\n", tlsh_of(&sfx))),
        (
            "a.hdb",
            &format!(
                "{}:{}:Sig.Member\n",
                md5_of(&String::from_utf8_lossy(member)),
                member.len()
            ),
        ),
    ]);
    assert_eq!(
        found(&sigs, &sfx, &heuristics()).as_deref(),
        Some("Sig.Member")
    );
}

/// The static checks do not run on the executable of an installer, whose stub
/// and payload they would score; only the signatures on its imports do.
#[cfg(feature = "autoit")]
#[test]
fn the_static_checks_do_not_run_on_the_executable_of_an_installer() {
    let (_, f, _, _) = two_hashes().remove(0);
    let sigs = db(&[("a.imp", "00000000000000000000000000000000:*:Sig.Imp\n")]);
    let mut opts = ScanOptions::default();
    opts.heuristics = true;
    let names = |f: &[u8]| -> Vec<String> {
        analyze(&sigs, f, &opts)
            .findings
            .iter()
            .map(|finding| finding.label.clone())
            .collect()
    };
    assert!(names(&f).iter().any(|n| n == "static-score"));
    assert!(!names(&installer(f)).iter().any(|n| n == "static-score"));
}

/// A detection in a member of the installer comes first, as it did: the
/// signatures on the imports of the executable are matched after its members
/// are scanned. The member here is found by its hash, in the walk of the
/// self-extractor's archive.
#[cfg(feature = "all-formats")]
#[test]
fn a_member_of_an_installer_is_found_before_its_executable() {
    use std::io::Write;
    let member = b"a member of the self-extractor, nothing more";
    let archive = |content: &[u8]| {
        let mut z = ZipWriter::new(Cursor::new(Vec::new()));
        let deflated = FileOptions::default().method(Method::Deflated);
        z.start_file("a.txt", deflated).unwrap();
        z.write_all(content).unwrap();
        z.finish().unwrap().into_inner()
    };
    let selfextractor = |content: &[u8]| {
        let (_, mut f, _, _) = two_hashes().remove(0);
        f.extend((0..1000).map(|i| (i % 251) as u8));
        f.extend_from_slice(&archive(content));
        f
    };
    let usual = two_hashes().remove(0).2;
    let sigs = db(&[
        ("a.fdb", &format!("imphash:{usual}:Sig.Fdb\n")),
        (
            "a.hdb",
            &format!(
                "{}:{}:Sig.Member\n",
                md5_of(&String::from_utf8_lossy(member)),
                member.len()
            ),
        ),
    ]);
    let opts = ScanOptions::default();
    assert_eq!(
        found(&sigs, &selfextractor(member), &opts).as_deref(),
        Some("Sig.Member")
    );
    // A member nothing is for: the executable's imports are found.
    assert_eq!(
        found(&sigs, &selfextractor(b"another member"), &opts).as_deref(),
        Some("Sig.Fdb")
    );
}

#[cfg(feature = "yara")]
mod yara {
    use super::*;

    fn rule(condition: &str) -> Scanner {
        db(&[(
            "a.yar",
            &format!("import \"pe\"\nrule R {{ condition: {condition} }}\n"),
        )])
    }

    fn holds(f: &[u8], condition: &str) -> bool {
        found(&rule(condition), f, &ScanOptions::default()).is_some()
    }

    /// libyara lists `WSAStartup` for ordinal 115 of `ws2_32`, `SysAllocString`
    /// for ordinal 2 of `oleaut32`, and `ord100` for ordinal 100 of `user32`;
    /// its import hash is made of those names.
    #[test]
    fn the_pe_module_lists_an_import_by_ordinal_by_name() {
        for wide in [false, true] {
            let f = by_ordinal(wide);
            for condition in [
                "pe.imports(\"ws2_32.dll\", \"WSAStartup\")",
                "pe.imports(\"WS2_32.DLL\", \"wsastartup\")",
                "pe.imports(\"oleaut32.dll\", \"SysAllocString\")",
                "pe.imports(\"user32.dll\", \"ord100\")",
                "pe.imports(\"ws2_32.dll\", 115)",
                "pe.imports(\"user32.dll\", 100)",
                "pe.imports(\"ws2_32.dll\") == 2",
                "pe.number_of_imports == 3 and pe.number_of_imported_functions == 4",
            ] {
                assert!(holds(&f, condition), "wide {wide}: {condition}");
            }
            for condition in [
                "pe.imports(\"ws2_32.dll\", \"ord115\")",
                "pe.imports(\"ws2_32.dll\", \"ORDINAL 115\")",
                "pe.imports(\"oleaut32.dll\", \"ord2\")",
                "pe.imports(\"user32.dll\", 101)",
                "pe.imports(\"kernel32.dll\", 100)",
                // `connect` is imported by name, so it has no ordinal.
                "pe.imports(\"ws2_32.dll\", 4)",
            ] {
                assert!(!holds(&f, condition), "wide {wide}: {condition}");
            }
            let imphash = format!("pe.imphash() == \"{}\"", md5_of(ORDINALS));
            assert!(holds(&f, &imphash), "wide {wide}: {imphash}");
        }
    }

    /// yara-x cuts the extension of a library only when it ends the name and is
    /// exactly `.dll`, `.sys` or `.ocx`, whatever the case (libyara cuts from
    /// the last `.` when `dll`, `sys` or `ocx` follows; clamscan from the
    /// first).
    #[test]
    fn the_imphash_cuts_the_extension_of_a_library_as_yarax_cuts_it() {
        for (library, hashed) in [
            ("KERNEL32.DLL", "kernel32.f"),
            ("lua5.1.dll", "lua5.1.f"),
            ("x.dllx", "x.dllx.f"),
            ("x.dll.mui", "x.dll.mui.f"),
            ("x.dll.dll", "x.dll.f"),
            ("a.b.sys", "a.b.f"),
            ("x.OCX", "x.f"),
            ("ntoskrnl.exe", "ntoskrnl.exe.f"),
            ("x.drv", "x.drv.f"),
        ] {
            let f = pe(false, &[(library, &[Name("f", 0)])]);
            let imphash = format!("pe.imphash() == \"{}\"", md5_of(hashed));
            assert!(holds(&f, &imphash), "{library}: {hashed}");
        }
    }

    /// Only an import by ordinal has an ordinal to libyara, whatever the hint
    /// of an import by name says.
    #[test]
    fn the_hint_of_an_import_by_name_is_not_an_ordinal() {
        let f = pe(false, &[("KERNEL32.DLL", &[Name("ExitProcess", 100)])]);
        assert!(holds(&f, "pe.imports(\"kernel32.dll\", \"ExitProcess\")"));
        assert!(!holds(&f, "pe.imports(\"kernel32.dll\", 100)"));
    }

    /// The descriptors that can be read are listed, as libyara lists them,
    /// and one of them finds the file; one that does not is UNSCANNABLE.
    #[test]
    fn the_pe_module_lists_the_descriptors_that_can_be_read() {
        let f = second_library_unreadable();
        let opts = ScanOptions::default();
        let rule = |condition: &str| {
            db(&[(
                "a.yar",
                &format!("import \"pe\"\nrule R {{ condition: {condition} }}\n"),
            )])
        };
        let hit = rule("pe.number_of_imports == 2 and pe.imports(\"gdi32.dll\", \"BitBlt\")");
        assert_eq!(found(&hit, &f, &opts).as_deref(), Some("YARA.R"));
        let miss = rule("pe.imports(\"user32.dll\") == 1");
        match analyze(&miss, &f, &opts).verdict {
            Verdict::Unscannable { reason } => {
                assert!(reason.contains("import table"), "{reason}")
            }
            other => panic!("expected UNSCANNABLE, got {other:?}"),
        }
    }

    /// Two descriptors for one library are two imports, as libyara counts them.
    #[test]
    fn two_descriptors_for_one_library_are_two_imports() {
        let f = pe(
            false,
            &[
                ("KERNEL32.DLL", &[Name("A", 0)]),
                ("KERNEL32.DLL", &[Name("B", 0)]),
            ],
        );
        assert!(holds(
            &f,
            "pe.number_of_imports == 2 and pe.number_of_imported_functions == 2"
        ));
        assert!(holds(&f, "pe.imports(\"kernel32.dll\") == 2"));
    }
}
