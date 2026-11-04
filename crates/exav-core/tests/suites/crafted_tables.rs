//! Tables a crafted executable makes the scan read many times over.
//!
//! Entries of a PE's imports or an ELF's sections can all point at one long
//! name, and the sections of a PE can all be as long as the file. The work and
//! the memory to copy those names, or to hash those sections, is the entries
//! times the length: a file of a few kilobytes asks for hundreds of megabytes.
//! The copies are charged to `--max-object-bytes`, the bytes hashed to
//! `--max-matcher-bytes`, and a scan that stopped for either is not clean.

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};

fn put(v: &mut [u8], at: usize, bytes: &[u8]) {
    v[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put16(v: &mut [u8], at: usize, n: u16) {
    put(v, at, &n.to_le_bytes());
}

fn put32(v: &mut [u8], at: usize, n: u32) {
    put(v, at, &n.to_le_bytes());
}

#[cfg(feature = "yara")]
fn put64(v: &mut [u8], at: usize, n: u64) {
    put(v, at, &n.to_le_bytes());
}

/// The headers of a PE32 with `sections` sections and the optional header's
/// fields every one of these files shares; the file is `headers` long.
fn pe_headers(f: &mut [u8], sections: usize, image: usize) {
    put(f, 0, b"MZ");
    put32(f, 0x3c, 0x40);
    put(f, 0x40, b"PE\0\0");
    put16(f, 0x44, 0x14c);
    put16(f, 0x46, sections as u16);
    put16(f, 0x54, 0xe0);
    put16(f, 0x56, 0x0102);
    let opt = 0x58;
    put16(f, opt, 0x10b);
    put32(f, opt + 28, 0x40_0000);
    put32(f, opt + 32, 0x1000);
    put32(f, opt + 36, 0x200);
    put32(f, opt + 56, 0x1000 + image.next_multiple_of(0x1000) as u32);
    put32(f, opt + 60, 0x200);
    put16(f, opt + 68, 3);
    put32(f, opt + 92, 16);
}

/// A PE32 with one import descriptor whose `thunks` entries all point at one
/// hint/name entry, a name of `name_len` bytes. The file is a little over
/// `name_len` + 4 `thunks` bytes.
fn pe_importing_one_long_name(thunks: usize, name_len: usize) -> Vec<u8> {
    let ilt = 0x28;
    let iat = ilt + 4 * (thunks + 1);
    let dll = iat + 4 * (thunks + 1);
    let hint = dll + 8;
    let idata = hint + 2 + name_len + 1;
    let mut f = vec![0u8; 0x400 + idata];
    pe_headers(&mut f, 1, idata);
    let opt = 0x58;
    put32(&mut f, opt + 96 + 8, 0x1000); // the import table
    put32(&mut f, opt + 96 + 12, 40);
    let section = opt + 0xe0;
    put(&mut f, section, b".idata");
    put32(&mut f, section + 8, idata as u32);
    put32(&mut f, section + 12, 0x1000);
    put32(&mut f, section + 16, idata as u32);
    put32(&mut f, section + 20, 0x400);
    put32(&mut f, section + 36, 0xc000_0040);
    let rva = |off: usize| (0x1000 + off) as u32;
    let base = 0x400;
    put32(&mut f, base, rva(ilt));
    put32(&mut f, base + 12, rva(dll));
    put32(&mut f, base + 16, rva(iat));
    for i in 0..thunks {
        put32(&mut f, base + ilt + 4 * i, rva(hint));
        put32(&mut f, base + iat + 4 * i, rva(hint));
    }
    put(&mut f, base + dll, b"a.dll\0");
    f[base + hint + 2..base + hint + 2 + name_len].fill(b'A');
    f
}

/// A PE32 of `count` sections that all start at the same place and are all
/// `body` bytes long.
fn pe_with_overlapping_sections(count: usize, body: usize) -> Vec<u8> {
    let headers = (0x138 + 40 * count).next_multiple_of(0x200);
    let mut f = vec![0u8; headers + body];
    pe_headers(&mut f, count, body);
    for i in 0..count {
        let at = 0x58 + 0xe0 + 40 * i;
        put(&mut f, at, b".text");
        put32(&mut f, at + 8, body as u32);
        put32(&mut f, at + 12, 0x1000);
        put32(&mut f, at + 16, body as u32);
        put32(&mut f, at + 20, headers as u32);
        put32(&mut f, at + 36, 0x6000_0020);
    }
    for (i, b) in f[headers..].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    f
}

/// An ELF64 of `sections` sections that are all named by one string of
/// `name_len` bytes; the second is the table of names.
#[cfg(feature = "yara")]
fn elf_naming_sections_by_one_string(sections: usize, name_len: usize) -> Vec<u8> {
    let table = 64;
    let names = table + 64 * sections;
    let mut f = vec![0u8; names + 1 + name_len + 1];
    put(&mut f, 0, b"\x7fELF");
    f[4] = 2; // 64 bits
    f[5] = 1; // little-endian
    f[6] = 1;
    put16(&mut f, 16, 2); // executable
    put16(&mut f, 18, 0x3e);
    put32(&mut f, 20, 1);
    put64(&mut f, 40, table as u64);
    put16(&mut f, 52, 64);
    put16(&mut f, 54, 56);
    put16(&mut f, 58, 64);
    put16(&mut f, 60, sections as u16);
    put16(&mut f, 62, 1);
    for i in 0..sections {
        let at = table + 64 * i;
        put32(&mut f, at, 1); // the name
        put32(&mut f, at + 4, if i == 1 { 3 } else { 1 }); // string table, or program data
        if i == 1 {
            put64(&mut f, at + 24, names as u64);
            put64(&mut f, at + 32, (name_len + 2) as u64);
        }
    }
    f[names + 1..names + 1 + name_len].fill(b'A');
    f
}

#[cfg(feature = "yara")]
fn yara(rule: &str) -> Scanner {
    let mut l = loader::Builder::new();
    l.add_named_bytes("t.yar", rule.as_bytes(), false);
    l.build().expect("build database")
}

fn incomplete(v: &Verdict) -> bool {
    matches!(v, Verdict::LimitsExceeded { .. })
}

fn infected_by(v: &Verdict, name: &str) -> bool {
    matches!(v, Verdict::Infected { signature, .. } if signature == name)
}

/// The names in the import table are 4,096 references to a name of 64 KiB,
/// from a file of 98,000 bytes. Copied whole they take 268 MiB for the `pe`
/// module, which copies 512 bytes of a name at most: 2 MiB.
const THUNKS: usize = 4096;
const LONG_NAME: usize = 64 * 1024;

#[cfg(feature = "yara")]
#[test]
fn the_import_names_the_pe_module_copies_are_charged_to_the_object_limit() {
    let pe = pe_importing_one_long_name(THUNKS, LONG_NAME);
    assert!(pe.len() < 100_000);
    let db = yara(&format!(
        "import \"pe\" rule r {{ condition: pe.number_of_imported_functions == {THUNKS} }}"
    ));
    // The rule is true when every import is there.
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = u64::MAX;
    let v = analyze(&db, &pe, &opts).verdict;
    assert!(infected_by(&v, "YARA.r"), "{v:?}");
    // The copies come to more than 1 MiB: the table is cut where they do,
    // the rule does not hold, and the scan says it did not see all.
    opts.limits.max_buffer_bytes = 1 << 20;
    let v = analyze(&db, &pe, &opts).verdict;
    assert!(incomplete(&v), "{v:?}");
    // Within the limit they are made, whole.
    opts.limits.max_buffer_bytes = (THUNKS * LONG_NAME * 2) as u64;
    let v = analyze(&db, &pe, &opts).verdict;
    assert!(infected_by(&v, "YARA.r"), "{v:?}");
}

/// The import hash copies 256 bytes of a name at most, so it takes more
/// entries than the `pe` module, which copies 512, to come to the same size.
const HASH_THUNKS: usize = 8192;

#[test]
fn the_import_names_the_import_hash_copies_are_charged_to_the_object_limit() {
    let pe = pe_importing_one_long_name(HASH_THUNKS, LONG_NAME);
    let db = Scanner::builtin();
    let mut opts = ScanOptions::default();
    opts.heuristics = true;
    opts.limits.max_buffer_bytes = u64::MAX;
    let v = analyze(&db, &pe, &opts).verdict;
    assert!(matches!(v, Verdict::Clean), "{v:?}");
    opts.limits.max_buffer_bytes = 1 << 20;
    match analyze(&db, &pe, &opts).verdict {
        Verdict::LimitsExceeded { reason } => {
            assert!(reason.contains("--max-object-bytes"), "{reason}")
        }
        other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
    }
}

#[cfg(feature = "yara")]
#[test]
fn the_names_the_elf_module_copies_are_charged_to_the_object_limit() {
    let sections = 2000;
    let elf = elf_naming_sections_by_one_string(sections, LONG_NAME);
    assert!(elf.len() < 200_000);
    // True only if the last section's value is there to be read.
    let db = yara(&format!(
        "import \"elf\" rule r {{ condition: elf.sections[{}].type == 1 }}",
        sections - 1
    ));
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = u64::MAX;
    let v = analyze(&db, &elf, &opts).verdict;
    assert!(infected_by(&v, "YARA.r"), "{v:?}");
    opts.limits.max_buffer_bytes = 1 << 20;
    let v = analyze(&db, &elf, &opts).verdict;
    assert!(incomplete(&v), "{v:?}");
}

// ---------------------------------------------------------------------------
// Section hashes
// ---------------------------------------------------------------------------

/// A `*`-sized signature makes every section a candidate, so each is hashed.
fn section_hashes(md5: &str) -> Scanner {
    let mut l = loader::Builder::new();
    l.add_named_bytes(
        "t.mdb",
        format!("*:{md5}:Exav.Test.Section\n").as_bytes(),
        false,
    );
    l.build().expect("build database")
}

const NO_SUCH_SECTION: &str = "00112233445566778899aabbccddeeff";

/// 100 sections of 100,000 bytes: 10 MB hashed from a file of 105,000.
#[test]
fn the_bytes_of_overlapping_sections_hashed_are_charged_to_the_scan() {
    let pe = pe_with_overlapping_sections(100, 100_000);
    let db = section_hashes(NO_SUCH_SECTION);
    let mut opts = ScanOptions::default();
    let v = analyze(&db, &pe, &opts).verdict;
    assert!(matches!(v, Verdict::Clean), "{v:?}");
    opts.limits.max_scanned_bytes = 1 << 20;
    let v = analyze(&db, &pe, &opts).verdict;
    assert!(incomplete(&v), "{v:?}");
    // The bytes of the sections are the ones that fit: ten of them, and the file.
    opts.limits.max_scanned_bytes = 11 * 100_000 + pe.len() as u64;
    let v = analyze(&db, &pe, &opts).verdict;
    assert!(incomplete(&v), "{v:?}");
    opts.limits.max_scanned_bytes = 101 * 100_000 + pe.len() as u64;
    let v = analyze(&db, &pe, &opts).verdict;
    assert!(matches!(v, Verdict::Clean), "{v:?}");
}

/// The entropy of each section is read for the static model and the import
/// hash, which are the heuristics: the same bytes, the same charge.
#[test]
fn the_bytes_of_overlapping_sections_whose_entropy_is_read_are_charged_to_the_scan() {
    let pe = pe_with_overlapping_sections(100, 100_000);
    let db = Scanner::builtin();
    let mut opts = ScanOptions::default();
    opts.heuristics = true;
    let v = analyze(&db, &pe, &opts).verdict;
    assert!(matches!(v, Verdict::Clean), "{v:?}");
    opts.limits.max_scanned_bytes = 1 << 20;
    let v = analyze(&db, &pe, &opts).verdict;
    assert!(incomplete(&v), "{v:?}");
}

/// A section that matches is a detection, and a detection beats a limit.
#[test]
fn a_section_found_before_the_limit_is_reported() {
    use md5::{Digest, Md5};
    let pe = pe_with_overlapping_sections(100, 100_000);
    let headers = pe.len() - 100_000;
    let md5: String = Md5::digest(&pe[headers..])
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let db = section_hashes(&md5);
    let mut opts = ScanOptions::default();
    opts.limits.max_scanned_bytes = 1 << 20;
    let v = analyze(&db, &pe, &opts).verdict;
    assert!(infected_by(&v, "Exav.Test.Section"), "{v:?}");
}

/// Not only the overlap: a section hashed that no signature could match is
/// not read, and is not charged.
#[test]
fn a_section_no_signature_can_match_is_not_charged() {
    let pe = pe_with_overlapping_sections(100, 100_000);
    let mut l = loader::Builder::new();
    // A size no section has.
    l.add_named_bytes(
        "t.mdb",
        format!("12345:{NO_SUCH_SECTION}:Exav.Test.Section\n").as_bytes(),
        false,
    );
    let db = l.build().expect("build database");
    let mut opts = ScanOptions::default();
    opts.limits.max_scanned_bytes = 1 << 20;
    let v = analyze(&db, &pe, &opts).verdict;
    assert!(matches!(v, Verdict::Clean), "{v:?}");
}
