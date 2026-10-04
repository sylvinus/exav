//! A member whose recorded checksum disagrees with what it decodes to is
//! scanned: the bytes are there, and a checksum is no reason not to read them.
//! EICAR in such a member is FOUND, and a clean one scans OK. With checksum
//! verification on (the `checksums` feature and `verify_checksums`), the
//! mismatch is reported instead, as ZIP, gzip and EGG members always were.
//!
//! Each archive was written by the format's own tool, and only its recorded
//! checksum is changed here: exav-unpack's `tests/fixtures/checksum/`
//! (`make.py` there: bzip2, lzip, wimlib, arc) and the RAR and ZOO fixtures
//! written by RAR and zoo. EICAR is compressed in every one, so it is found
//! only in the decoded member, never in the archive's own bytes.

use exav_core::{analyze, ScanOptions, Scanner, Verdict};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Want {
    Found,
    Clean,
    Unscannable,
}
use Want::*;

fn fixture(rel: &str) -> Vec<u8> {
    let p = format!(
        "{}/../exav-unpack/tests/fixtures/{rel}",
        env!("CARGO_MANIFEST_DIR")
    );
    exav_core::unpack::read_fixture(&p).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

fn u16_le(d: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes([d[at], d[at + 1]]))
}

fn u32_le(d: &[u8], at: usize) -> usize {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap()) as usize
}

fn u64_le(d: &[u8], at: usize) -> usize {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap()) as usize
}

/// bzip2: the first block's CRC, right after the stream header and the
/// block magic. EICAR is in the second block, or in the stream after.
fn bzip2(rel: &str) -> Vec<u8> {
    let mut d = fixture(rel);
    assert_eq!(&d[4..10], b"\x31\x41\x59\x26\x53\x59", "{rel}: block magic");
    d[10] ^= 1;
    d
}

/// lzip: the first member's CRC-32, the start of its 20-byte trailer. The
/// last member's trailer ends the file and records that member's size.
fn lzip_first(rel: &str) -> Vec<u8> {
    let mut d = fixture(rel);
    let last = u64_le(&d, d.len() - 8);
    let first_end = d.len() - last;
    assert!(
        first_end == 0 || d[first_end..].starts_with(b"LZIP"),
        "{rel}"
    );
    let first_end = if first_end == 0 { d.len() } else { first_end };
    d[first_end - 20] ^= 1;
    d
}

/// WIM: the SHA-1 of each file resource in the offset table (an
/// uncompressed resource whose header is at 48: 7-byte size, flags, offset).
fn wim(rel: &str) -> Vec<u8> {
    let mut d = fixture(rel);
    let size = u64_le(&d, 48) & 0x00FF_FFFF_FFFF_FFFF;
    let at = u64_le(&d, 56);
    let mut patched = 0;
    for e in (at..at + size).step_by(50) {
        let metadata = d[e + 7] & 0x02 != 0;
        if !metadata && u64_le(&d, e + 16) > 0 {
            d[e + 30] ^= 1;
            patched += 1;
        }
    }
    assert_eq!(patched, 1, "{rel}");
    d
}

/// ARC: the first member's CRC-16, at 23 in its header.
fn arc(rel: &str) -> Vec<u8> {
    let mut d = fixture(rel);
    assert!(d[0] == 0x1A && d[1] == 8, "{rel}: a crunched member first");
    d[23] ^= 1;
    d
}

/// ZOO: the first member's CRC-16, at 18 in its directory entry.
fn zoo(rel: &str) -> Vec<u8> {
    let mut d = fixture(rel);
    let first = u32_le(&d, 24);
    d[first + 18] ^= 1;
    d
}

/// RAR4: `name`'s FILE_CRC, with the header's own CRC (the low 16 bits of
/// the CRC-32 of the rest of the header) brought back in line.
fn rar4(rel: &str, name: &[u8]) -> Vec<u8> {
    let mut d = fixture(rel);
    let mut p = 0;
    while p + 7 <= d.len() {
        let (kind, flags, size) = (d[p + 2], u16_le(&d, p + 3), u16_le(&d, p + 5));
        let add = if flags & 0x8000 != 0 {
            u32_le(&d, p + 7)
        } else {
            0
        };
        if kind == 0x74 {
            let name_at = p + 32 + if flags & 0x100 != 0 { 8 } else { 0 };
            if &d[name_at..name_at + u16_le(&d, p + 26)] == name {
                d[p + 16] ^= 1;
                let head = (crc32(&d[p + 2..p + size]) & 0xFFFF) as u16;
                d[p..p + 2].copy_from_slice(&head.to_le_bytes());
                return d;
            }
        }
        p += size + add;
    }
    panic!("{rel}: no member {}", String::from_utf8_lossy(name));
}

/// A RAR5 variable-length integer at `at`: its value and where it ends.
fn vint(d: &[u8], mut at: usize) -> (usize, usize) {
    let mut v = 0;
    for shift in (0..).step_by(7) {
        let b = d[at];
        at += 1;
        v |= usize::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            break;
        }
    }
    (v, at)
}

/// RAR5: `name`'s data CRC-32, with the header's CRC-32 (of everything
/// after it in the header) brought back in line.
fn rar5(rel: &str, name: &[u8]) -> Vec<u8> {
    let mut d = fixture(rel);
    let mut p = 8;
    while p + 4 < d.len() {
        let (hsize, body) = vint(&d, p + 4);
        let end = body + hsize;
        let (kind, q) = vint(&d, body);
        let (hflags, mut q) = vint(&d, q);
        if hflags & 0x01 != 0 {
            q = vint(&d, q).1;
        }
        let mut data_size = 0;
        if hflags & 0x02 != 0 {
            (data_size, q) = vint(&d, q);
        }
        if kind == 2 {
            let (fflags, q) = vint(&d, q);
            let q = vint(&d, q).1; // unpacked size
            let mut q = vint(&d, q).1; // attributes
            if fflags & 0x02 != 0 {
                q += 4; // mtime
            }
            let crc_at = (fflags & 0x04 != 0).then_some(q);
            q += if crc_at.is_some() { 4 } else { 0 };
            let q = vint(&d, q).1; // compression
            let q = vint(&d, q).1; // host OS
            let (len, q) = vint(&d, q);
            if &d[q..q + len] == name {
                d[crc_at.expect("a data CRC")] ^= 1;
                let head = crc32(&d[p + 4..end]);
                d[p..p + 4].copy_from_slice(&head.to_le_bytes());
                return d;
            }
        }
        p = end + data_size;
    }
    panic!("{rel}: no member {}", String::from_utf8_lossy(name));
}

/// Every case: the archive with a wrong checksum, and what a default scan
/// gives.
fn cases() -> Vec<(&'static str, Vec<u8>, Want)> {
    vec![
        ("bzip2 EICAR", bzip2("checksum/two_blocks.bz2"), Found),
        ("bzip2 clean", bzip2("checksum/clean.bz2"), Clean),
        (
            "bzip2 EICAR in the next stream",
            [
                bzip2("checksum/clean.bz2"),
                fixture("checksum/two_blocks.bz2"),
            ]
            .concat(),
            Found,
        ),
        ("lzip EICAR", lzip_first("checksum/two_members.lz"), Found),
        ("lzip clean", lzip_first("checksum/clean.lz"), Clean),
        ("wim EICAR", wim("checksum/eicar.wim"), Found),
        ("wim clean", wim("checksum/clean.wim"), Clean),
        ("arc EICAR", arc("checksum/eicar.arc"), Found),
        ("arc clean", arc("checksum/clean.arc"), Clean),
        ("zoo clean", zoo("zoo/default.zoo"), Clean),
        (
            "rar4 EICAR",
            rar4("rar_solid/solid_rar4.rar", b"eicar.com"),
            Found,
        ),
        (
            "rar4 clean",
            rar4("rar4/two_windows.rar", b"e_text.txt"),
            Clean,
        ),
        (
            "rar5 EICAR",
            rar5("rar_solid/solid_rar5.rar", b"eicar.com"),
            Found,
        ),
        (
            "rar5 clean",
            rar5("rar_solid/two_windows.rar", b"a.txt"),
            Clean,
        ),
    ]
}

fn run(opts: &ScanOptions, cases: Vec<(&'static str, Vec<u8>, Want)>) {
    let db = Scanner::builtin();
    let mut wrong = Vec::new();
    for (label, data, want) in cases {
        let v = analyze(&db, &data, opts).verdict;
        let got = match &v {
            Verdict::Infected { signature, .. }
                if signature.to_ascii_uppercase().contains("EICAR") =>
            {
                Found
            }
            Verdict::Clean => Clean,
            Verdict::Unscannable { .. } => Unscannable,
            _ => {
                wrong.push(format!("{label}: {v:?}"));
                continue;
            }
        };
        if got != want {
            wrong.push(format!("{label}: want {want:?}, got {v:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_member_failing_its_checksum_is_scanned() {
    run(&ScanOptions::default(), cases());
}

/// The fixtures as written, for the oracle: every one scans as its name
/// says, so the failures above are the checksum's doing.
#[test]
fn the_fixtures_scan_as_named_with_their_checksums_intact() {
    let intact = [
        ("bzip2 EICAR", "checksum/two_blocks.bz2", Found),
        ("bzip2 clean", "checksum/clean.bz2", Clean),
        ("lzip EICAR", "checksum/two_members.lz", Found),
        ("lzip clean", "checksum/clean.lz", Clean),
        ("wim EICAR", "checksum/eicar.wim", Found),
        ("wim clean", "checksum/clean.wim", Clean),
        ("arc EICAR", "checksum/eicar.arc", Found),
        ("arc clean", "checksum/clean.arc", Clean),
        ("zoo clean", "zoo/default.zoo", Clean),
        ("rar4 EICAR", "rar_solid/solid_rar4.rar", Found),
        ("rar4 clean", "rar4/two_windows.rar", Clean),
        ("rar5 EICAR", "rar_solid/solid_rar5.rar", Found),
        ("rar5 clean", "rar_solid/two_windows.rar", Clean),
    ];
    run(
        &ScanOptions::default(),
        intact
            .into_iter()
            .map(|(label, rel, want)| (label, fixture(rel), want))
            .collect(),
    );
}

/// With verification on, a clean member failing its checksum is reported.
#[cfg(feature = "checksums")]
#[test]
fn a_member_failing_its_checksum_is_reported_when_checksums_are_verified() {
    let mut opts = ScanOptions::default();
    opts.verify_checksums = true;
    run(
        &opts,
        cases()
            .into_iter()
            .filter(|c| c.2 == Clean)
            .map(|(label, data, _)| (label, data, Unscannable))
            .collect(),
    );
}
