//! Sets of volumes whose headers say how they join (RAR, ZIP, CAB), scanned as
//! the archives they are.
//!
//! Each volume holds part of a member's bytes, so no volume read alone shows
//! what the member is. The signatures here are the ones only the whole member
//! satisfies: its MD5 (`.hdb`) for the RAR and ZIP sets, and for the CAB a
//! marker that straddles the place the folder was cut. A control in each test
//! scans the parts one at a time and finds nothing.
//!
//! Fixtures: the RAR sets are official RAR's (`rar a -ma5 -m3 -v8k` and
//! `-ma4 -m3 -vn -v8k`, `text.txt` and `noise.bin`; the MD5s are of the inputs,
//! made by `random.Random(20261001)`, see exav-unpack's `rar_solid` suite); the
//! ZIP is `zip -0 -s 64k split.zip payload.bin` of 100,000 bytes of
//! `random.Random(77)`, whose rejoined archive (`zip -s 0`) holds the payload.

use exav_core::{analyze, analyze_split_sets, loader, ScanOptions, Scanner, Verdict};
use std::cell::RefCell;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/volumes/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn db(files: &[(&str, &str)]) -> Scanner {
    let mut b = loader::Builder::new();
    for (name, text) in files {
        b.add_named_bytes(name, text.as_bytes(), true);
    }
    b.build().expect("database")
}

fn infected(v: &Verdict) -> Option<&str> {
    match v {
        Verdict::Infected { signature, .. } => Some(signature.as_str()),
        _ => None,
    }
}

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

const NOISE_MD5: &str = "147b5c8ca1767bca1ef297b3024fb0dd";
const PAYLOAD_MD5: &str = "2e94a8cfc2ebdd36f886a897aeb0cf96";

#[test]
fn rar_sets_are_scanned_as_the_archive_they_are() {
    let scanner = db(&[("t.hdb", &format!("{NOISE_MD5}:20000:Test.Noise\n"))]);
    let opts = ScanOptions::default();
    for (set, parts) in [
        (
            "set5.rar",
            ["set5.part1.rar", "set5.part2.rar", "set5.part3.rar"],
        ),
        ("set4.rar", ["set4.rar", "set4.r00", "set4.r01"]),
    ] {
        // Alone, no volume shows the member.
        for p in parts {
            assert!(
                infected(&analyze(&scanner, &fixture(p), &opts).verdict).is_none(),
                "{p} alone"
            );
        }
        let mut given = names(&parts);
        given.push("notes.txt".into());
        let fetched = RefCell::new(Vec::new());
        let got = analyze_split_sets(&scanner, &given, &opts, |n, head| {
            fetched.borrow_mut().push(n.to_string());
            assert!(head.is_none(), "a RAR volume is read whole or not at all");
            Ok(fixture(n))
        });
        assert_eq!(got.len(), 3, "{set}");
        for v in &got {
            assert_eq!(
                infected(&v.report.verdict),
                Some("Test.Noise"),
                "{set}: {}",
                v.name
            );
            assert_eq!(v.set, set);
        }
        assert!(
            !fetched.borrow().iter().any(|n| n == "notes.txt"),
            "a file of no set is not read"
        );
    }
}

#[test]
fn a_rar_set_with_a_volume_missing_is_unscannable_not_clean() {
    let scanner = db(&[("t.hdb", &format!("{NOISE_MD5}:20000:Test.Noise\n"))]);
    let given = names(&["set5.part1.rar", "set5.part3.rar"]);
    let got = analyze_split_sets(&scanner, &given, &ScanOptions::default(), |n, _| {
        Ok(fixture(n))
    });
    assert_eq!(got.len(), 2);
    for v in &got {
        assert!(
            matches!(v.report.verdict, Verdict::Unscannable { .. }),
            "{}: {:?}",
            v.name,
            v.report.verdict
        );
    }
    // One volume of a set is a file, not a set.
    let alone = analyze_split_sets(
        &scanner,
        &names(&["set5.part1.rar"]),
        &ScanOptions::default(),
        |n, _| Ok(fixture(n)),
    );
    assert!(alone.is_empty());
}

#[test]
fn a_split_zip_is_scanned_as_the_archive_it_is() {
    let scanner = db(&[("t.hdb", &format!("{PAYLOAD_MD5}:100000:Test.Payload\n"))]);
    let opts = ScanOptions::default();
    for p in ["split.z01", "split.zip"] {
        assert!(
            infected(&analyze(&scanner, &fixture(p), &opts).verdict).is_none(),
            "{p} alone"
        );
    }
    let got = analyze_split_sets(
        &scanner,
        &names(&["split.zip", "other.bin", "split.z01"]),
        &opts,
        |n, _| Ok(fixture(n)),
    );
    assert_eq!(got.len(), 2);
    for v in &got {
        assert_eq!(
            infected(&v.report.verdict),
            Some("Test.Payload"),
            "{}",
            v.name
        );
        assert_eq!(v.set, "split.zip");
    }
    // Without its last part, the `.zip`, the others are a set with a hole.
    let hole = analyze_split_sets(
        &scanner,
        &names(&["split.z01", "other.bin"]),
        &opts,
        |n, _| Ok(fixture(n)),
    );
    assert_eq!(hole.len(), 1);
    assert!(
        matches!(hole[0].report.verdict, Verdict::Unscannable { .. }),
        "{:?}",
        hole[0].report.verdict
    );
}

/// A cabinet of one folder, uncompressed, as exav-unpack's tests build them.
fn cab(
    prev: Option<&str>,
    next: Option<&str>,
    index: u16,
    files: &[(u32, u32, u16, &str)],
    blocks: &[(u16, &[u8])],
) -> Vec<u8> {
    let flags = u16::from(prev.is_some()) | (u16::from(next.is_some()) << 1);
    let mut links = Vec::new();
    for n in [prev, next].into_iter().flatten() {
        links.extend_from_slice(n.as_bytes());
        links.extend_from_slice(b"\0disk\0");
    }
    let mut records = Vec::new();
    for (size, offset, place, name) in files {
        records.extend_from_slice(&size.to_le_bytes());
        records.extend_from_slice(&offset.to_le_bytes());
        records.extend_from_slice(&place.to_le_bytes());
        records.extend_from_slice(&[0x21, 0x5a, 0x00, 0x60, 0x20, 0x00]);
        records.extend_from_slice(name.as_bytes());
        records.push(0);
    }
    let coff_files = 36 + links.len() + 8;
    let data_at = coff_files + records.len();
    let mut data = Vec::new();
    for (uncompressed, payload) in blocks {
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        data.extend_from_slice(&uncompressed.to_le_bytes());
        data.extend_from_slice(payload);
    }
    let mut out = b"MSCF".to_vec();
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&((data_at + data.len()) as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(coff_files as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[3, 1]);
    for v in [1u16, files.len() as u16, flags, 5, index] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend(links);
    out.extend_from_slice(&(data_at as u32).to_le_bytes());
    out.extend_from_slice(&(blocks.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend(records);
    out.extend(data);
    out
}

const MARKER: &[u8] = b"exav-cab-set-marker-0123456789-end";

fn cab_set() -> (Vec<u8>, Vec<u8>) {
    let mut stream = vec![b'.'; 600];
    stream.extend_from_slice(MARKER);
    stream.extend_from_slice(&[b'.'; 600]);
    // One block cut inside the marker.
    let cut = 600 + MARKER.len() / 2;
    let one = cab(
        None,
        Some("part2.cab"),
        0,
        &[(stream.len() as u32, 0, 0xFFFE, "marker.txt")],
        &[(0, &stream[..cut])],
    );
    let two = cab(
        Some("part1.cab"),
        None,
        1,
        &[(stream.len() as u32, 0, 0xFFFD, "marker.txt")],
        &[(stream.len() as u16, &stream[cut..])],
    );
    (one, two)
}

fn cab_db() -> Scanner {
    let hex: String = MARKER.iter().map(|b| format!("{b:02x}")).collect();
    db(&[("t.ndb", &format!("Test.Cab:0:*:{hex}\n"))])
}

#[test]
fn a_cab_set_is_found_by_the_names_its_headers_give() {
    let (one, two) = cab_set();
    let scanner = cab_db();
    let opts = ScanOptions::default();
    for (p, name) in [(&one, "part1.cab"), (&two, "part2.cab")] {
        assert!(
            infected(&analyze(&scanner, p, &opts).verdict).is_none(),
            "{name} alone"
        );
    }
    let files = [
        ("part1.cab", one.clone()),
        ("part2.cab", two.clone()),
        ("Readme.txt", b"hello".to_vec()),
    ];
    let given = names(&["part2.cab", "readme.txt", "part1.cab", "solo.cab"]);
    let reads = RefCell::new(Vec::new());
    let got = analyze_split_sets(&scanner, &given, &opts, |n, head| {
        reads.borrow_mut().push((n.to_string(), head));
        files
            .iter()
            .find(|(f, _)| *f == n)
            .map(|(_, d)| d.clone())
            .ok_or_else(|| std::io::Error::other("no such file"))
    });
    assert_eq!(got.len(), 2, "{got:?}");
    for v in &got {
        assert_eq!(infected(&v.report.verdict), Some("Test.Cab"), "{}", v.name);
        assert_eq!(v.set, "part1.cab");
    }
    // A text file is not read at all; a cabinet is read by its head to see whether it names a neighbour.
    assert!(!reads.borrow().iter().any(|(n, _)| n == "readme.txt"));
    assert!(reads
        .borrow()
        .iter()
        .any(|(n, h)| n == "part1.cab" && h.is_some()));
}

#[test]
fn cabinets_that_do_not_follow_one_another_as_their_headers_say_are_not_joined() {
    let (one, two) = cab_set();
    let scanner = cab_db();
    let files = [("part1.cab", one), ("renamed.cab", two)];
    let got = analyze_split_sets(
        &scanner,
        &names(&["part1.cab", "renamed.cab"]),
        &ScanOptions::default(),
        |n, _| {
            files
                .iter()
                .find(|(f, _)| *f == n)
                .map(|(_, d)| d.clone())
                .ok_or_else(|| std::io::Error::other("no such file"))
        },
    );
    assert_eq!(got.len(), 2);
    for v in &got {
        assert!(
            matches!(v.report.verdict, Verdict::Unscannable { .. }),
            "{}: {:?}",
            v.name,
            v.report.verdict
        );
    }
}
