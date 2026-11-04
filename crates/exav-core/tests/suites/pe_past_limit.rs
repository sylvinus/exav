//! A PE over `--max-object-bytes` is nearly always a small image with a large
//! overlay (an installer, a self-extractor). Its structure is read from the
//! image, through the block cache, so the checks that need it run on such a
//! file as they do on a small one, and the object ends `OK` only when none of
//! them was skipped.
//!
//! Every file here is over the limit the scans use. Unless the test is about an
//! image past the limit, the image is far under it. A check that finds
//! something is shown to find it on the file read through the cache as on the
//! same bytes held in memory.

use std::io::Cursor;

use exav_core::{
    AllMatchOutcome, ScanOptions, Scanner, Verdict, analyze, analyze_all_seekable,
    analyze_all_with_outcome, loader, scan_seekable,
};
use md5::{Digest, Md5};
use sha2::Sha256;

/// What a scan may hold of an object: every file here is over it.
const LIMIT: u64 = 16 * 1024;

fn fixture(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/tests/fixtures/authenticode/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

/// `n` bytes from 0x80 to 0xbf: not text, and none of the ASCII bytes the
/// magics of the format checks are made of.
fn overlay(n: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            0x80 + ((state >> 33) % 64) as u8
        })
        .collect()
}

fn put(v: &mut [u8], at: usize, bytes: &[u8]) {
    v[at..at + bytes.len()].copy_from_slice(bytes);
}

fn put16(v: &mut [u8], at: usize, n: u16) {
    put(v, at, &n.to_le_bytes());
}

fn put32(v: &mut [u8], at: usize, n: u32) {
    put(v, at, &n.to_le_bytes());
}

/// The bytes of `.text`: a run of 29 values, so that a wrong offset reads other
/// bytes, and not so random that the file looks packed.
fn text() -> Vec<u8> {
    (0..0x200u32).map(|i| ((i % 29) * 7 + 3) as u8).collect()
}

/// A PE32 of `0x400 + idata_size` bytes: `.text` (0x200 bytes at 0x200, the
/// entry point at its start) and `.idata`, which imports `ExitProcess` from
/// `KERNEL32.dll`. `idata_size` is the raw size of `.idata`, zero-filled past
/// its tables.
fn small_pe(idata_size: usize) -> Vec<u8> {
    let mut f = vec![0u8; 0x400 + idata_size];
    put(&mut f, 0, b"MZ");
    put32(&mut f, 0x3c, 0x40);
    put(&mut f, 0x40, b"PE\0\0");
    put16(&mut f, 0x44, 0x14c); // machine
    put16(&mut f, 0x46, 2); // sections
    put16(&mut f, 0x54, 0xe0); // size of the optional header
    put16(&mut f, 0x56, 0x0102); // characteristics
    let opt = 0x58;
    put16(&mut f, opt, 0x10b);
    put32(&mut f, opt + 16, 0x1000); // entry point
    put32(&mut f, opt + 20, 0x1000); // base of code
    put32(&mut f, opt + 28, 0x40_0000); // image base
    put32(&mut f, opt + 32, 0x1000); // section alignment
    put32(&mut f, opt + 36, 0x200); // file alignment
    put32(&mut f, opt + 56, 0x3000); // size of image
    put32(&mut f, opt + 60, 0x200); // size of headers
    put16(&mut f, opt + 68, 3); // subsystem
    put32(&mut f, opt + 92, 16); // data directories
    put32(&mut f, opt + 96 + 8, 0x2000); // the import table
    put32(&mut f, opt + 96 + 12, 40);
    let table = opt + 0xe0;
    for (at, name, size, va, raw, flags) in [
        (table, &b".text"[..], 0x200, 0x1000, 0x200, 0x6000_0020u32),
        (
            table + 40,
            b".idata",
            idata_size,
            0x2000,
            0x400,
            0xc000_0040,
        ),
    ] {
        put(&mut f, at, name);
        put32(&mut f, at + 8, size as u32); // virtual size
        put32(&mut f, at + 12, va);
        put32(&mut f, at + 16, size as u32); // raw size
        put32(&mut f, at + 20, raw);
        put32(&mut f, at + 36, flags);
    }
    put(&mut f, 0x200, &text());
    // The import table at RVA 0x2000: one descriptor and the null one, then
    // the name table, the address table, the library's name and the hint/name.
    put32(&mut f, 0x400, 0x2040); // names
    put32(&mut f, 0x400 + 12, 0x2080); // library
    put32(&mut f, 0x400 + 16, 0x2060); // addresses
    put32(&mut f, 0x440, 0x20a0);
    put32(&mut f, 0x460, 0x20a0);
    put(&mut f, 0x480, b"KERNEL32.dll\0");
    put(&mut f, 0x4a2, b"ExitProcess\0");
    f
}

/// [`small_pe`] with an overlay 3 times the limit after it, which starts with
/// what its certificate table points to: an entry with the header of a
/// signature, followed by bytes that are not one. A strict parse of the PE
/// refuses a table it cannot read, and the image does not hold this one.
fn pe_with_overlay() -> Vec<u8> {
    let mut f = small_pe(0x200);
    f.extend(overlay(3 * LIMIT as usize));
    put32(&mut f, 0x58 + 96 + 4 * 8, 0x600);
    put32(&mut f, 0x58 + 96 + 4 * 8 + 4, 0x100);
    put32(&mut f, 0x600, 0x100); // length
    put16(&mut f, 0x604, 0x0200); // revision
    put16(&mut f, 0x606, 0x0002); // PKCS#7 signed data
    f
}

/// [`pe_with_overlay`] whose debug directory has a CodeView record (a PDB
/// path) that lies in the overlay, as some linkers put it after the sections.
fn pe_with_debug_record_in_overlay() -> Vec<u8> {
    let mut f = pe_with_overlay();
    let record = 0x800;
    // The directory is the last 28 bytes of `.idata`'s raw data, at RVA 0x2180.
    let table = 0x580;
    put32(&mut f, 0x58 + 96 + 6 * 8, 0x2180);
    put32(&mut f, 0x58 + 96 + 6 * 8 + 4, 28);
    put32(&mut f, table + 12, 2); // CodeView
    put32(&mut f, table + 16, 40); // size of the record
    put32(&mut f, table + 24, record as u32); // its file offset
    put(&mut f, record, b"RSDS");
    put(&mut f, record + 24, b"a.pdb\0");
    f
}

/// A PE whose `.idata` raw data is 0x180 bytes, which its file alignment pads
/// to 0x200, with an export directory in the padding: the bytes of the
/// overlay that an address of the section maps to.
fn pe_with_exports_in_the_padding() -> Vec<u8> {
    let mut f = small_pe(0x180);
    f.extend(overlay(3 * LIMIT as usize));
    // File offsets 0x580..0x600 are RVAs 0x2180..0x2200.
    let dir = 0x580;
    put32(&mut f, 0x58 + 96, 0x2180);
    put32(&mut f, 0x58 + 96 + 4, 40);
    put32(&mut f, dir + 12, 0x21c0); // the name
    put32(&mut f, dir + 16, 1); // the ordinal base
    put32(&mut f, dir + 20, 1); // functions
    put32(&mut f, dir + 24, 1); // names
    put32(&mut f, dir + 28, 0x21b0); // their addresses
    put32(&mut f, dir + 32, 0x21b4); // the addresses of the names
    put32(&mut f, dir + 36, 0x21b8); // and their ordinals
    put32(&mut f, 0x5b0, 0x1000);
    put32(&mut f, 0x5b4, 0x21d0);
    put16(&mut f, 0x5b8, 0);
    put(&mut f, 0x5c0, b"x.dll\0");
    put(&mut f, 0x5d0, b"Func\0");
    f
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The imphash of [`small_pe`]: its one import, as the import hash builds it.
fn imphash() -> String {
    hex(&Md5::digest(b"kernel32.exitprocess"))
}

/// The size of its `.imp` signature: the length of what the hash is of.
const IMPHASH_LEN: usize = "kernel32.exitprocess".len();

fn db(files: &[(&str, &str)]) -> Scanner {
    let mut b = loader::Builder::new();
    for (name, text) in files {
        b.add_named_bytes(name, text.as_bytes(), true);
    }
    b.build().expect("build db")
}

/// Options for scans of the files here: a scan holds at most `LIMIT` bytes of
/// an object, and the cache is small, so what is read through it is read again.
fn small(mut o: ScanOptions) -> ScanOptions {
    o.limits.max_buffer_bytes = LIMIT;
    o.object_cache_block_bytes = 4096;
    o.object_cache_bytes = 4 * 4096;
    o
}

/// The verdict on `file` read through a cache, over `LIMIT`.
fn streamed(db: &Scanner, file: &[u8], opts: ScanOptions) -> Verdict {
    assert!(file.len() as u64 > LIMIT, "the file is over the limit");
    scan_seekable(
        db,
        Cursor::new(file.to_vec()),
        file.len() as u64,
        &small(opts),
    )
    .expect("scan")
    .verdict
}

/// The verdict on `file` held in memory.
fn held(db: &Scanner, file: &[u8], opts: &ScanOptions) -> Verdict {
    analyze(db, file, opts).verdict
}

fn infected(v: &Verdict) -> Option<&str> {
    match v {
        Verdict::Infected { signature, .. } => Some(signature),
        _ => None,
    }
}

/// `file` is named `name` both held in memory and read through the cache.
fn found(db: &Scanner, file: &[u8], opts: ScanOptions, name: &str) {
    let mem = held(db, file, &opts);
    assert_eq!(infected(&mem), Some(name), "held in memory: {mem:?}");
    let v = streamed(db, file, opts);
    assert_eq!(infected(&v), Some(name), "over the limit: {v:?}");
}

/// A database of signatures that each need the PE's structure, none of which
/// matches [`pe_with_overlay`] (each is off by one from one that would).
fn near_misses() -> Scanner {
    let text_md5 = hex(&Md5::digest(text()));
    let mut wrong_ep = text()[..16].to_vec();
    wrong_ep[0] ^= 1;
    db(&[
        ("a.mdb", &format!("513:{text_md5}:Sig.Section.WrongSize\n")),
        (
            "a.imp",
            &format!("{}:{}:Sig.Imp.WrongSize\n", imphash(), IMPHASH_LEN + 1),
        ),
        (
            "a.ldb",
            &format!(
                "Sig.Ep.Wrong;Engine:51-255,Target:1;0;EP+0:{}\n",
                hex(&wrong_ep)
            ),
        ),
    ])
}

#[test]
fn a_section_hash_matches_in_a_pe_with_an_overlay_past_the_limit() {
    let f = pe_with_overlay();
    let md5 = hex(&Md5::digest(text()));
    let db = db(&[("a.mdb", &format!("512:{md5}:Sig.Section\n"))]);
    found(&db, &f, ScanOptions::default(), "Sig.Section");
}

#[test]
fn an_import_hash_matches_in_a_pe_with_an_overlay_past_the_limit() {
    let f = pe_with_overlay();
    let db = db(&[("a.imp", &format!("{}:{}:Sig.Imp\n", imphash(), IMPHASH_LEN))]);
    found(&db, &f, ScanOptions::default(), "Sig.Imp");
}

#[test]
fn an_entry_point_signature_matches_in_a_pe_with_an_overlay_past_the_limit() {
    let f = pe_with_overlay();
    let sig = format!(
        "Sig.Ep;Engine:51-255,Target:1;0;EP+0:{}\n",
        hex(&text()[..16])
    );
    let db = db(&[("a.ldb", &sig)]);
    found(&db, &f, ScanOptions::default(), "Sig.Ep");
}

#[cfg(feature = "yara")]
#[test]
fn a_yara_pe_rule_matches_in_a_pe_with_an_overlay_past_the_limit() {
    let f = pe_with_overlay();
    let rule = format!(
        r#"import "pe"
rule Pe_Module {{
  condition:
    pe.is_pe and pe.number_of_sections == 2 and pe.entry_point == 0x200
    and pe.imports("kernel32.dll") == 1 and pe.imphash() == "{}"
}}
"#,
        imphash()
    );
    let db = db(&[("a.yar", &rule)]);
    found(&db, &f, ScanOptions::default(), "YARA.Pe_Module");
}

/// A PE whose tables do not parse from its image is not a clean scan of the
/// object it is cut from: the checks that read them did not run. Here the
/// import directory points outside every section.
#[test]
fn tables_that_do_not_parse_from_the_image_are_not_a_clean_scan() {
    let mut f = pe_with_overlay();
    put32(&mut f, 0x58 + 96 + 8, 0x9000);
    put32(&mut f, 0x58 + 96 + 12, 40);
    let imp = db(&[("a.imp", &format!("{}:{}:Sig.Imp\n", imphash(), IMPHASH_LEN))]);
    match streamed(&imp, &f, ScanOptions::default()) {
        Verdict::LimitsExceeded { reason } => {
            assert!(reason.contains("does not parse from its image"), "{reason}");
        }
        other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
    }
    #[cfg(feature = "yara")]
    {
        let rule = "import \"pe\"\nrule R { condition: pe.number_of_sections == 9999 }\n";
        match streamed(&db(&[("a.yar", rule)]), &f, ScanOptions::default()) {
            Verdict::LimitsExceeded { .. } => {}
            other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
        }
    }
}

/// No check reads a debug record, so one past the limit does not put the
/// image past it.
#[test]
fn a_debug_record_past_the_limit_does_not_stop_the_checks() {
    let mut f = pe_with_debug_record_in_overlay();
    let last = f.len() - 100;
    put32(&mut f, 0x580 + 24, last as u32);
    assert_eq!(
        streamed(&near_misses(), &f, ScanOptions::default()),
        Verdict::Clean
    );
}

/// The checks that read the structure of a PE run when the record its debug
/// directory points to is in the overlay.
#[test]
fn the_structure_checks_run_on_a_pe_whose_debug_record_is_in_the_overlay() {
    let f = pe_with_debug_record_in_overlay();
    let md5 = hex(&Md5::digest(text()));
    let ep = format!(
        "Sig.Ep;Engine:51-255,Target:1;0;EP+0:{}\n",
        hex(&text()[..16])
    );
    found(
        &db(&[("a.mdb", &format!("512:{md5}:Sig.Section\n"))]),
        &f,
        ScanOptions::default(),
        "Sig.Section",
    );
    found(&db(&[("a.ldb", &ep)]), &f, ScanOptions::default(), "Sig.Ep");
    found(
        &db(&[("a.imp", &format!("{}:{}:Sig.Imp\n", imphash(), IMPHASH_LEN))]),
        &f,
        ScanOptions::default(),
        "Sig.Imp",
    );
}

/// What an address of a section maps to in the file is in the image: the
/// padding that the file alignment adds after the section's data too.
#[cfg(feature = "yara")]
#[test]
fn the_yara_pe_module_reads_the_padding_after_a_section() {
    let f = pe_with_exports_in_the_padding();
    let rule = "import \"pe\"\nrule Exports { condition: pe.number_of_exports == 1 }\n";
    found(
        &db(&[("a.yar", rule)]),
        &f,
        ScanOptions::default(),
        "YARA.Exports",
    );
}

#[cfg(feature = "yara")]
#[test]
fn the_yara_pe_module_runs_on_a_pe_whose_debug_record_is_in_the_overlay() {
    let f = pe_with_debug_record_in_overlay();
    let rule = format!(
        r#"import "pe"
rule Pe_Module {{
  condition:
    pe.is_pe and pe.number_of_sections == 2 and pe.imports("kernel32.dll") == 1
    and pe.imphash() == "{}"
}}
"#,
        imphash()
    );
    found(
        &db(&[("a.yar", &rule)]),
        &f,
        ScanOptions::default(),
        "YARA.Pe_Module",
    );
}

#[cfg(feature = "yara")]
#[test]
fn a_yara_elf_rule_matches_in_an_elf_with_an_overlay_past_the_limit() {
    let mut f = include_bytes!("../testdata/tiny_elf64").to_vec();
    f.extend(overlay(3 * LIMIT as usize));
    let rule = r#"import "elf"
rule Elf_Module {
  condition:
    elf.number_of_sections == 3 and elf.entry_point == 0x80
    and for any s in elf.sections : (s.name == ".text")
}
"#;
    let db = db(&[("a.yar", rule)]);
    found(&db, &f, ScanOptions::default(), "YARA.Elf_Module");
}

#[cfg(feature = "yara")]
#[test]
fn a_yara_dotnet_rule_matches_in_an_assembly_with_an_overlay_past_the_limit() {
    let p = format!(
        "{}/tests/fixtures/dotnet/system_buffers.dll",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut f = exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    assert!((f.len() as u64) < LIMIT, "the assembly is under the limit");
    f.extend(overlay(3 * LIMIT as usize));
    let rule = r#"import "dotnet"
rule Dotnet_Module { condition: dotnet.is_dotnet and dotnet.number_of_streams > 0 }
"#;
    let db = db(&[("a.yar", rule)]);
    found(&db, &f, ScanOptions::default(), "YARA.Dotnet_Module");
}

/// The signed fixture with `n` bytes of overlay between its last section and
/// its certificate table (which stays at the end of the file, as the signing
/// tools put it), and the table's address in the headers moved to match. With
/// `covering`, the digest the signature carries is the one of the new file,
/// as goblin lists its ranges: it ends with the zeros that pad a file whose
/// length is not a multiple of 8.
fn signed_with_overlay(n: usize, covering: bool) -> Vec<u8> {
    let base = fixture("signed_mismatch.exe");
    // The certificate table's entry: `e_lfanew` + 24 + 96 (PE32) + 4 * 8.
    let entry = 0x40 + 24 + 96 + 4 * 8;
    let at = u32::from_le_bytes(base[entry..entry + 4].try_into().unwrap()) as usize;
    let mut f = base[..at].to_vec();
    f.extend(overlay(n));
    let moved = f.len();
    f.extend_from_slice(&base[at..]);
    put32(&mut f, entry, moved as u32);
    if covering {
        let parsed = goblin::pe::PE::parse(&f).expect("goblin parses it");
        let mut h = Sha256::new();
        parsed.authenticode_ranges().for_each(|r| h.update(r));
        let digest = h.finalize();
        // The signature's digest is of other bytes: the one it was built with.
        let was = Sha256::digest(b"hello authenticode");
        let pos = f[moved..]
            .windows(32)
            .position(|w| w == was.as_slice())
            .expect("the fixture's digest");
        put(&mut f, moved + pos, &digest);
    }
    f
}

fn crb() -> Scanner {
    // SHA-1 of the fixture certificate's subject name.
    db(&[(
        "a.crb",
        "Malware.StolenCert;0;2c190fb742c4be7399e7706dd24610807dc9860c;\n",
    )])
}

#[test]
fn a_blocked_signer_is_found_in_a_pe_with_an_overlay_past_the_limit() {
    for covering in [false, true] {
        let f = signed_with_overlay(3 * LIMIT as usize, covering);
        found(&crb(), &f, ScanOptions::default(), "Malware.StolenCert");
    }
}

#[test]
fn the_authenticode_digest_covers_the_overlay_of_a_pe_past_the_limit() {
    let mut opts = ScanOptions::default();
    opts.alert_broken_authenticode = true;
    let db = Scanner::builtin();
    let f = signed_with_overlay(3 * LIMIT as usize, true);
    assert_eq!(held(&db, &f, &opts), Verdict::Clean);
    assert_eq!(streamed(&db, &f, opts.clone()), Verdict::Clean);
    // One byte of the overlay, far from the headers and from the first
    // blocks: the signature no longer covers the file.
    let mut changed = f.clone();
    let at = 0x600 + 2 * LIMIT as usize;
    changed[at] ^= 1;
    found(
        &db,
        &changed,
        opts.clone(),
        "Heuristics.Authenticode.HashMismatch",
    );
    // And a digest of other bytes, as the fixture has.
    let other = signed_with_overlay(3 * LIMIT as usize, false);
    found(
        &db,
        &other,
        opts.clone(),
        "Heuristics.Authenticode.HashMismatch",
    );
    // A file whose length is not a multiple of 8 is hashed with the zeros
    // that pad it to one.
    let odd = signed_with_overlay(3 * LIMIT as usize + 3, true);
    assert_ne!(odd.len() % 8, 0);
    assert_eq!(held(&db, &odd, &opts), Verdict::Clean);
    assert_eq!(streamed(&db, &odd, opts), Verdict::Clean);
}

#[test]
fn a_clean_pe_with_an_overlay_is_ok_when_nothing_was_skipped() {
    let f = pe_with_overlay();
    let db = near_misses();
    assert_eq!(held(&db, &f, &ScanOptions::default()), Verdict::Clean);
    assert_eq!(streamed(&db, &f, ScanOptions::default()), Verdict::Clean);
    // With the exav-exclusive heuristics too: the static model reads the whole
    // object a chunk at a time, for its byte counts.
    let mut o = ScanOptions::default();
    o.heuristics = true;
    let (mem, v) = (held(&db, &f, &o), streamed(&db, &f, o));
    assert_eq!((mem, v), (Verdict::Clean, Verdict::Clean));
}

#[test]
fn a_clean_signed_pe_with_an_overlay_is_ok() {
    let mut o = ScanOptions::default();
    o.alert_broken_authenticode = true;
    let db = db(&[(
        "a.crb",
        "Malware.Other;0;00112233445566778899aabbccddeeff00112233;\n",
    )]);
    let f = signed_with_overlay(3 * LIMIT as usize, true);
    assert_eq!(held(&db, &f, &o), Verdict::Clean);
    assert_eq!(streamed(&db, &f, o), Verdict::Clean);
}

#[cfg(feature = "yara")]
#[test]
fn a_clean_pe_is_ok_under_yara_modules() {
    let f = pe_with_overlay();
    let rule = r#"import "pe"
import "elf"
import "dotnet"
rule Never {
  condition: pe.number_of_sections == 3 or elf.number_of_sections > 0 or dotnet.is_dotnet
}
"#;
    let db = db(&[("a.yar", rule)]);
    assert_eq!(held(&db, &f, &ScanOptions::default()), Verdict::Clean);
    assert_eq!(streamed(&db, &f, ScanOptions::default()), Verdict::Clean);
}

#[test]
fn a_pe_whose_image_is_past_the_limit_stays_limits_exceeded() {
    // `.idata` runs to 0x8400, which is over the limit: its structure is not
    // read, so the signatures that need it did not run.
    let mut f = small_pe(0x8000);
    f.extend(overlay(LIMIT as usize));
    let md5 = hex(&Md5::digest(text()));
    let db = db(&[("a.mdb", &format!("512:{md5}:Sig.Section\n"))]);
    // Held in memory, the same bytes are named.
    let mem = held(&db, &f, &ScanOptions::default());
    assert_eq!(infected(&mem), Some("Sig.Section"), "{mem:?}");
    match streamed(&db, &f, ScanOptions::default()) {
        Verdict::LimitsExceeded { reason } => {
            assert!(reason.contains("did not run"), "{reason}");
            assert!(reason.contains("the PE's image"), "{reason}");
        }
        other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
    }
}

#[test]
fn a_pe_past_the_limit_stays_limits_exceeded_while_a_check_needs_all_of_it() {
    // A regular expression with a back-reference runs on the object held
    // whole, which a PE past the limit is not, whatever its image.
    let mut f = small_pe(0x200);
    f.extend(b"TRIGGERabab");
    f.extend(overlay(3 * LIMIT as usize));
    // The same file, and signatures that need only its structure: OK.
    assert_eq!(
        streamed(&near_misses(), &f, ScanOptions::default()),
        Verdict::Clean
    );
    let sig = format!(
        "Sig.Backref;Engine:81-255,Target:1;0&1;{};0/(ab)\\1/\n",
        hex(b"TRIGGER")
    );
    let db = db(&[("a.ldb", &sig)]);
    let mem = held(&db, &f, &ScanOptions::default());
    assert_eq!(infected(&mem), Some("Sig.Backref"), "{mem:?}");
    match streamed(&db, &f, ScanOptions::default()) {
        Verdict::LimitsExceeded { .. } => {}
        other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
    }
}

/// How many times over a scan reads `file` from its source: bytes read,
/// counted at the source, in units of its length.
fn passes_over(db: &Scanner, file: &[u8], opts: ScanOptions) -> f64 {
    use std::io::{Read, Seek};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Counting(Cursor<Vec<u8>>, Arc<AtomicU64>);
    impl Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.0.read(buf)?;
            self.1.fetch_add(n as u64, Ordering::Relaxed);
            Ok(n)
        }
    }
    impl Seek for Counting {
        fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
            self.0.seek(p)
        }
    }
    let read = Arc::new(AtomicU64::new(0));
    let reader = Counting(Cursor::new(file.to_vec()), read.clone());
    let report = scan_seekable(db, reader, file.len() as u64, &small(opts)).expect("scan");
    assert_eq!(report.verdict, Verdict::Clean);
    read.load(Ordering::Relaxed) as f64 / file.len() as f64
}

/// What a PE past the limit costs to read, the cache holding a few blocks of
/// a file of 1 MiB: detection reads the start of the object, which is all of
/// it up to 4 MiB; and the one read serves the signature sweep, carving, the
/// prefilter, the search of the rest of the object for a UPX header, which
/// the image alone cannot answer, and with `--detect exav-heuristics` the
/// static model's byte counts. Each bound allows a fifth of a read more, for
/// the headers and the image, read again by each check that needs them.
#[test]
fn a_pe_with_an_overlay_is_read_a_few_times() {
    let mut f = small_pe(0x200);
    f.extend(overlay(1 << 20));
    let mut heuristics = ScanOptions::default();
    heuristics.heuristics = true;
    for (what, opts, bound) in [
        ("default", ScanOptions::default(), 2.0),
        ("heuristics", heuristics, 2.0),
    ] {
        let passes = passes_over(&near_misses(), &f, opts);
        assert!(
            passes <= bound + 0.2,
            "{what}: read {passes:.2} times over, the bound is {bound}"
        );
    }
}

/// UPX's pack header can lie anywhere in an executable, and the check is made
/// on the image of a PE too large to hold: so the rest of it is searched for
/// one, and what the image cannot unpack is not OK.
#[cfg(feature = "all-formats")]
#[test]
fn a_upx_header_past_the_image_of_a_pe_is_not_ok() {
    let mut f = pe_with_overlay();
    let at = 0x600 + 5000;
    f[at + 4..at + 8].copy_from_slice(b"UPX!");
    f[at + 10] = 2; // the method NRV2B
    put32(&mut f, at + 20, 100); // the size unpacked
    put32(&mut f, at + 24, 100); // and packed
    let db = near_misses();
    let mem = held(&db, &f, &ScanOptions::default());
    assert_ne!(
        mem,
        Verdict::Clean,
        "held in memory, UPX is looked for in all of it"
    );
    match streamed(&db, &f, ScanOptions::default()) {
        Verdict::LimitsExceeded { .. } => {}
        other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
    }
    // A magic that no header goes with is not one.
    let mut f = pe_with_overlay();
    f[at + 4..at + 8].copy_from_slice(b"UPX!");
    assert_eq!(streamed(&db, &f, ScanOptions::default()), Verdict::Clean);
}

// A PE whose directories are not all readable: held in memory, as past the
// limit, and as a first match or all matches. A check reads the tables it
// needs, and only those.

/// `f` with data directory `i` (0 exports, 1 imports, 6 debug) at `rva`, for
/// `size` bytes, whatever the width of its optional header.
fn with_dir(mut f: Vec<u8>, i: usize, rva: u32, size: u32) -> Vec<u8> {
    let opt = u32::from_le_bytes(f[0x3c..0x40].try_into().unwrap()) as usize + 24;
    let wide = f[opt..opt + 2] == [0x0b, 0x02];
    let dirs = opt + if wide { 112 } else { 96 };
    put32(&mut f, dirs + 8 * i, rva);
    put32(&mut f, dirs + 8 * i + 4, size);
    f
}

/// The debug directory points at an address no section holds: Windows ignores
/// it, and a parse of the PE as a whole refuses the file for it.
fn with_stray_debug_directory(f: Vec<u8>) -> Vec<u8> {
    with_dir(f, 6, 0x9000, 28)
}

/// The names `analyze_all_with_outcome` lists for `file` held in memory, and
/// how it ended.
fn all_held(db: &Scanner, file: &[u8], opts: ScanOptions) -> (Vec<String>, AllMatchOutcome) {
    let (names, outcome) = analyze_all_with_outcome(db, file, &opts);
    (names.into_iter().map(|(n, _)| n).collect(), outcome)
}

/// The same read through a cache, `file` being over `LIMIT`.
fn all_streamed(db: &Scanner, file: &[u8], opts: ScanOptions) -> (Vec<String>, AllMatchOutcome) {
    assert!(file.len() as u64 > LIMIT, "the file is over the limit");
    let (names, outcome) = analyze_all_seekable(
        db,
        Cursor::new(file.to_vec()),
        file.len() as u64,
        &small(opts),
    )
    .expect("scan");
    (names.into_iter().map(|(n, _)| n).collect(), outcome)
}

/// `name` is the one detection of `file`, held in memory and (when it is over
/// the limit) read through the cache, as a first match and among all.
fn found_everywhere(db: &Scanner, file: &[u8], name: &str) {
    let opts = ScanOptions::default;
    let mem = held(db, file, &opts());
    assert_eq!(infected(&mem), Some(name), "held in memory: {mem:?}");
    let want = (vec![name.to_string()], AllMatchOutcome::Complete);
    assert_eq!(all_held(db, file, opts()), want);
    if file.len() as u64 > LIMIT {
        let v = streamed(db, file, opts());
        assert_eq!(infected(&v), Some(name), "over the limit: {v:?}");
        assert_eq!(all_streamed(db, file, opts()), want);
    }
}

/// `file` is not clean, held in memory and read through the cache, first match
/// and all matches, for a reason that contains `why`: `expect` of the verdict
/// held in memory.
fn unscannable_everywhere(db: &Scanner, file: &[u8], opts: ScanOptions, why: &str) {
    match held(db, file, &opts) {
        Verdict::Unscannable { reason } => assert!(reason.contains(why), "{reason}"),
        other => panic!("held in memory: expected UNSCANNABLE, got {other:?}"),
    }
    match all_held(db, file, opts) {
        (names, AllMatchOutcome::Unscannable(reason)) => {
            assert!(names.is_empty(), "{names:?}");
            assert!(reason.contains(why), "{reason}");
        }
        other => panic!("held in memory: expected UNSCANNABLE, got {other:?}"),
    }
}

/// An import hash is found in a PE whose debug directory is outside every
/// section, which it was not: the file was OK, held in memory as it is.
#[test]
fn a_stray_debug_directory_does_not_hide_the_import_hash() {
    let db = db(&[("a.imp", &format!("{}:{}:Sig.Imp\n", imphash(), IMPHASH_LEN))]);
    let held_pe = with_stray_debug_directory(small_pe(0x200));
    let cut_pe = with_stray_debug_directory(pe_with_overlay());
    found_everywhere(&db, &held_pe, "Sig.Imp");
    found_everywhere(&db, &cut_pe, "Sig.Imp");
}

/// Nor does it hide the checks that read the structure of the PE in YARA.
#[cfg(feature = "yara")]
#[test]
fn a_stray_debug_directory_does_not_hide_the_yara_modules() {
    let pe = format!(
        r#"import "pe"
rule Pe_Module {{
  condition:
    pe.is_pe and pe.imports("kernel32.dll") == 1 and pe.imphash() == "{}"
}}
"#,
        imphash()
    );
    // The bytes `text()` starts with, at the entry point.
    let ep = "rule Ep { condition: uint8(entrypoint) == 3 and uint8(entrypoint + 1) == 10 }\n";
    for f in [
        with_stray_debug_directory(small_pe(0x200)),
        with_stray_debug_directory(pe_with_overlay()),
    ] {
        found_everywhere(&db(&[("a.yar", &pe)]), &f, "YARA.Pe_Module");
        found_everywhere(&db(&[("a.yar", ep)]), &f, "YARA.Ep");
    }
    let p = format!(
        "{}/tests/fixtures/dotnet/system_buffers.dll",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut f = exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
    f = with_stray_debug_directory(f);
    let rule = r#"import "dotnet"
rule Dotnet_Module { condition: dotnet.is_dotnet and dotnet.number_of_streams > 0 }
"#;
    found_everywhere(&db(&[("a.yar", rule)]), &f, "YARA.Dotnet_Module");
    f.extend(overlay(3 * LIMIT as usize));
    found_everywhere(&db(&[("a.yar", rule)]), &f, "YARA.Dotnet_Module");
}

/// An import table that does not parse (here, at an address no section
/// holds) leaves the import hash and the static model unmade: such a PE is
/// not clean when the loaded signatures or the options need them, and is when
/// they do not.
#[test]
fn a_pe_whose_import_table_does_not_parse_is_not_a_clean_scan() {
    let f = with_dir(small_pe(0x200), 1, 0x9000, 40);
    let imp = db(&[("a.imp", &format!("{}:{}:Sig.Imp\n", imphash(), IMPHASH_LEN))]);
    unscannable_everywhere(&imp, &f, ScanOptions::default(), "import table");
    // The static model needs the imports too.
    let mut heuristics = ScanOptions::default();
    heuristics.heuristics = true;
    unscannable_everywhere(&db(&[]), &f, heuristics, "import table");
    // Without either, nothing reads the imports: a section hash that is off
    // by one in its size finds nothing, and the scan is complete.
    let md5 = hex(&Md5::digest(text()));
    let near = db(&[("a.mdb", &format!("513:{md5}:Sig.Section\n"))]);
    let mut clamav = ScanOptions::default();
    clamav.clamav_heuristics = true;
    assert_eq!(held(&near, &f, &clamav), Verdict::Clean);
    assert_eq!(all_held(&near, &f, clamav).1, AllMatchOutcome::Complete);
    // A detection stands, whatever was not read.
    let section = format!("512:{md5}:Sig.Section\n");
    let both = db(&[
        ("a.imp", &format!("{}:{}:Sig.Imp\n", imphash(), IMPHASH_LEN)),
        ("a.mdb", &section),
    ]);
    let v = held(&both, &f, &ScanOptions::default());
    assert_eq!(infected(&v), Some("Sig.Section"), "{v:?}");
    let (names, outcome) = all_held(&both, &f, ScanOptions::default());
    assert_eq!(names, ["Sig.Section"]);
    let unscannable = matches!(outcome, AllMatchOutcome::Unscannable(_));
    assert!(unscannable, "{outcome:?}");
}

/// The same for the `pe` module, which reads the export table as well; the
/// modules that read the headers only (`dotnet`, `entrypoint`) are not
/// affected.
#[cfg(feature = "yara")]
#[test]
fn a_pe_whose_tables_do_not_parse_is_not_a_clean_scan_under_the_pe_module() {
    let pe = "import \"pe\"\nrule R { condition: pe.number_of_sections == 9999 }\n";
    let no_imports = with_dir(small_pe(0x200), 1, 0x9000, 40);
    let no_exports = with_dir(small_pe(0x200), 0, 0x9000, 40);
    unscannable_everywhere(
        &db(&[("a.yar", pe)]),
        &no_imports,
        ScanOptions::default(),
        "import table",
    );
    unscannable_everywhere(
        &db(&[("a.yar", pe)]),
        &no_exports,
        ScanOptions::default(),
        "export table",
    );
    // The import hash does not read the exports.
    let imp = db(&[("a.imp", &format!("{}:{}:Sig.Imp\n", imphash(), IMPHASH_LEN))]);
    found_everywhere(&imp, &no_exports, "Sig.Imp");
    // A rule that reads the headers only is not held up by either.
    let headers = r#"import "dotnet"
rule R { condition: dotnet.is_dotnet or uint8(entrypoint) == 77 }
"#;
    let headers = db(&[("a.yar", headers)]);
    for f in [&no_imports, &no_exports] {
        assert_eq!(held(&headers, f, &ScanOptions::default()), Verdict::Clean);
    }
}

/// Some bytes of a host, then `pe`: a PE carved out of the host runs to the
/// host's end.
fn in_a_host(pe: &[u8]) -> Vec<u8> {
    [&overlay(0x100)[..], pe].concat()
}

/// A PE whose import directory lies past its own bytes has no import table in
/// them. Whole, such a file is cut and not clean. Carved out of a host, the
/// copy of a header that a packer keeps (its sections are those of the file it
/// came from) has nothing unread. Any other table that does not read is still
/// not clean, carved or not.
#[test]
fn an_import_directory_past_the_bytes_of_a_carved_pe_is_absent_not_unread() {
    let mut heuristics = ScanOptions::default();
    heuristics.heuristics = true;
    let imp = db(&[("a.imp", &format!("{}:{}:Sig.Imp\n", imphash(), IMPHASH_LEN))]);
    #[allow(unused_mut)]
    let mut checks: Vec<(Scanner, ScanOptions)> =
        vec![(imp, ScanOptions::default()), (db(&[]), heuristics)];
    #[cfg(feature = "yara")]
    checks.push((
        db(&[(
            "a.yar",
            "import \"pe\"\nrule R { condition: pe.number_of_sections == 9999 }\n",
        )]),
        ScanOptions::default(),
    ));

    // The data of `.idata` is not in the bytes: the directory points at their end.
    let cut = small_pe(0x200)[..0x400].to_vec();
    // The directory is in the bytes and a descriptor is cut by their end.
    let inside = small_pe(0x200)[..0x410].to_vec();
    // The first descriptor is read; its library name is at an address no section holds.
    let mut nameless = small_pe(0x200);
    put32(&mut nameless, 0x400 + 12, 0x9000);
    // The directory is at an address no section holds.
    let nowhere = with_dir(small_pe(0x200), 1, 0x9000, 40);
    for (db, opts) in &checks {
        unscannable_everywhere(db, &cut, opts.clone(), "import table");
        assert_eq!(held(db, &in_a_host(&cut), opts), Verdict::Clean);
        for kept in [&inside, &nameless, &nowhere] {
            unscannable_everywhere(db, kept, opts.clone(), "import table");
            unscannable_everywhere(db, &in_a_host(kept), opts.clone(), "import table");
        }
    }
}

/// The tables of a PE are parsed within what `--max-object-bytes` allows: a
/// table that would take more is not parsed, and the scan is over the limit.
/// Here the file is 3 KB, and many descriptors list one table.
#[test]
fn an_import_table_that_would_take_too_much_to_parse_is_over_the_limit() {
    let (libs, thunks) = (40usize, 100usize);
    let mut f = small_pe(20 * (libs + 1) + 4 * (thunks + 1) + 32);
    f[0x400..].fill(0);
    // The import hash leaves out an entry less than 258 bytes from the end.
    f.resize(f.len() + 300, 0);
    let rva = |at: usize| (0x2000 + at) as u32;
    let table = 20 * (libs + 1);
    let (hint, name) = (table + 4 * (thunks + 1), table + 4 * (thunks + 1) + 16);
    for i in 0..libs {
        put32(&mut f, 0x400 + 20 * i, rva(table)); // names
        put32(&mut f, 0x400 + 20 * i + 12, rva(name)); // library
        put32(&mut f, 0x400 + 20 * i + 16, rva(table)); // addresses
    }
    for j in 0..thunks {
        put32(&mut f, 0x400 + table + 4 * j, rva(hint));
    }
    put(&mut f, 0x400 + name, b"A.dll\0");
    put(&mut f, 0x400 + hint + 2, b"F\0");
    let f = with_dir(f, 1, rva(0), (20 * (libs + 1)) as u32);
    let all = vec!["a.f"; libs * thunks].join(",");
    let hash = hex(&Md5::digest(&all));
    let sig = format!("{hash}:{}:Sig.Imp.Many\n", all.len());
    let imp = db(&[("a.imp", &sig)]);
    // At the default limit it is read, and found.
    found_everywhere(&imp, &f, "Sig.Imp.Many");
    // At one that the parse of its tables would pass, it is not.
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 64 * 1024;
    assert!((f.len() as u64) < opts.limits.max_buffer_bytes);
    match held(&imp, &f, &opts) {
        Verdict::LimitsExceeded { reason } => {
            assert!(reason.contains("would take more than"), "{reason}");
        }
        other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
    }
    match all_held(&imp, &f, opts.clone()) {
        (names, AllMatchOutcome::LimitsExceeded(_)) => assert!(names.is_empty()),
        other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
    }
    // As is the `pe` module's.
    #[cfg(feature = "yara")]
    {
        let rule = "import \"pe\"\nrule R { condition: pe.number_of_imports == 9999 }\n";
        let yara = db(&[("a.yar", rule)]);
        match held(&yara, &f, &opts) {
            Verdict::LimitsExceeded { .. } => {}
            other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
        }
        assert_eq!(held(&yara, &f, &ScanOptions::default()), Verdict::Clean);
    }
}

/// `f` with its PE header moved to offset 0x0c, inside the DOS header, as some
/// packers lay it out (Windows loads it, and so does ClamAV). `e_lfanew` at
/// 0x3c is then the `BaseOfData` of a PE32's optional header, and goblin's
/// strict parse refuses the file.
fn with_header_in_the_dos_header(f: &[u8]) -> Vec<u8> {
    let mut g = f.to_vec();
    g[0x0c..0x1cc].copy_from_slice(&f[0x40..0x200]);
    g[0x1cc..0x200].fill(0);
    put32(&mut g, 0x3c, 0x0c);
    g
}

/// Every check that reads the structure of a PE runs on one whose header is in
/// the DOS header: section hashes, entry point offsets, the import hash and,
/// in YARA, the `pe` module.
#[test]
fn the_structure_checks_run_on_a_pe_whose_header_is_in_the_dos_header() {
    let md5 = hex(&Md5::digest(text()));
    let ep = format!(
        "Sig.Ep;Engine:51-255,Target:1;0;EP+0:{}\n",
        hex(&text()[..16])
    );
    for f in [
        with_header_in_the_dos_header(&small_pe(0x200)),
        with_header_in_the_dos_header(&pe_with_overlay()),
    ] {
        let sec = format!("512:{md5}:Sig.Section\n");
        found_everywhere(&db(&[("a.mdb", &sec)]), &f, "Sig.Section");
        found_everywhere(&db(&[("a.ldb", &ep)]), &f, "Sig.Ep");
        let imp = format!("{}:{}:Sig.Imp\n", imphash(), IMPHASH_LEN);
        found_everywhere(&db(&[("a.imp", &imp)]), &f, "Sig.Imp");
        #[cfg(feature = "yara")]
        {
            let rule =
                "import \"pe\"\nrule R { condition: pe.is_pe and pe.number_of_sections == 2 }\n";
            found_everywhere(&db(&[("a.yar", rule)]), &f, "YARA.R");
        }
    }
}

/// [`small_pe`] with the name of its library and its hint/name entry in the
/// DOS header, and no lookup table: where WinUpack keeps them. Windows maps
/// the headers, and clamscan and libyara read them there.
fn pe_with_names_in_the_dos_header(mut f: Vec<u8>) -> Vec<u8> {
    put(&mut f, 2, b"KERNEL32.dll\0");
    put(&mut f, 0x12, b"ExitProcess\0"); // after its hint, at 0x10
    put32(&mut f, 0x400, 0); // no lookup table
    put32(&mut f, 0x400 + 12, 2); // the library
    put32(&mut f, 0x460, 0x10); // the entry, in the address table
    f
}

/// The import hash and the `pe` module read the names of a PE that are in its
/// headers, held in memory and over the limit: the file was UNSCANNABLE.
#[test]
fn names_in_the_headers_of_a_pe_are_read() {
    let held = pe_with_names_in_the_dos_header(small_pe(0x200));
    let mut over = held.clone();
    over.extend(overlay(3 * LIMIT as usize));
    for f in [held, over] {
        let imp = format!("{}:{}:Sig.Imp\n", imphash(), IMPHASH_LEN);
        found_everywhere(&db(&[("a.imp", &imp)]), &f, "Sig.Imp");
        #[cfg(feature = "yara")]
        {
            let rule = "import \"pe\"\nrule R { condition: pe.imports(\"KERNEL32.dll\", \"ExitProcess\") }\n";
            found_everywhere(&db(&[("a.yar", rule)]), &f, "YARA.R");
        }
    }
}

/// An entry point in the headers is at the file offset of its RVA: an `EP+n`
/// signature is anchored there, as clamscan does.
#[test]
fn an_entry_point_in_the_headers_anchors_a_signature() {
    let mut f = small_pe(0x200);
    put32(&mut f, 0x58 + 16, 0x200); // where `.text` starts in the file
    let ep = format!(
        "Sig.Ep;Engine:51-255,Target:1;0;EP+0:{}\n",
        hex(&text()[..16])
    );
    found_everywhere(&db(&[("a.ldb", &ep)]), &f, "Sig.Ep");
}
