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

use exav_core::{
    AllMatchOutcome, ScanOptions, Scanner, Verdict, analyze, analyze_split_sets,
    analyze_split_sets_seekable, analyze_split_sets_seekable_all, loader,
};
use std::cell::RefCell;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

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

/// `x.part1.rar` and `x.part01.rar` name one volume twice. The set is not
/// joined, and every name in it is reported with the reason: none is left out
/// of the result to be scanned as a file of its own.
#[test]
fn a_rar_set_with_two_names_for_one_volume_is_reported_not_dropped() {
    let scanner = db(&[("t.hdb", &format!("{NOISE_MD5}:20000:Test.Noise\n"))]);
    let given = names(&[
        "set5.part2.rar",
        "set5.part01.rar",
        "notes.txt",
        "set5.part1.rar",
    ]);
    let got = analyze_split_sets(&scanner, &given, &ScanOptions::default(), |n, _| {
        panic!("{n} was fetched: a set that is not joined is not read")
    });
    let mut reported: Vec<&str> = got.iter().map(|v| v.name.as_str()).collect();
    reported.sort_unstable();
    assert_eq!(
        reported,
        ["set5.part01.rar", "set5.part1.rar", "set5.part2.rar"]
    );
    for v in &got {
        let Verdict::Unscannable { reason } = &v.report.verdict else {
            panic!("{}: {:?}", v.name, v.report.verdict);
        };
        assert!(reason.contains("two names claim one volume"), "{reason}");
        assert_eq!(v.set, "set5.rar");
    }
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
    assert!(
        reads
            .borrow()
            .iter()
            .any(|(n, h)| n == "part1.cab" && h.is_some())
    );
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

#[test]
fn a_set_turned_away_for_its_size_does_not_use_up_the_budget_of_the_next() {
    // The first set trips the cap. The part that did it was counted and never
    // given back, so the second set, which fits, was "too large to hold" too.
    let scanner = db(&[]);
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 4096;
    let given = names(&["a.part1.rar", "a.part2.rar", "b.part1.rar", "b.part2.rar"]);
    let got = analyze_split_sets(&scanner, &given, &opts, |n, _| {
        Ok(vec![0u8; if n == "a.part1.rar" { 4097 } else { 1000 }])
    });
    let reason = |name: &str| match &got.iter().find(|v| v.name == name).unwrap().report.verdict {
        Verdict::Unscannable { reason } => reason.clone(),
        other => format!("{other:?}"),
    };
    assert!(
        reason("a.part1.rar").contains("too large to hold"),
        "{}",
        reason("a.part1.rar")
    );
    assert!(
        !reason("b.part1.rar").contains("too large to hold"),
        "b fits the budget: {}",
        reason("b.part1.rar")
    );
}

#[test]
fn rar_sets_are_scanned_where_their_volumes_lie() {
    let scanner = db(&[("t.hdb", &format!("{NOISE_MD5}:20000:Test.Noise\n"))]);
    let opts = ScanOptions::default();
    for (set, parts) in [
        (
            "set5.rar",
            ["set5.part1.rar", "set5.part2.rar", "set5.part3.rar"],
        ),
        ("set4.rar", ["set4.rar", "set4.r00", "set4.r01"]),
    ] {
        let mut given = names(&parts);
        given.push("notes.txt".into());
        let opened = RefCell::new(Vec::new());
        let got = analyze_split_sets_seekable(&scanner, &given, &opts, |n| {
            opened.borrow_mut().push(n.to_string());
            Ok(Cursor::new(fixture(n)))
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
            !opened.borrow().iter().any(|n| n == "notes.txt"),
            "a file of no set is not opened"
        );
    }
}

/// A set read where it lies lists every signature its member matches with the
/// `_all` entry point, and the first one only with the other.
#[test]
fn a_set_listed_with_every_detection_reports_all_of_them() {
    // The MD5 of the other member of the set, `text.txt`.
    let text_md5 = "f704b62a1885c3912e30df545aca774a";
    let scanner = db(&[(
        "t.hdb",
        &format!("{NOISE_MD5}:20000:Test.Noise\n{text_md5}:14661:Test.Text\n"),
    )]);
    let opts = ScanOptions::default();
    let parts = ["set5.part1.rar", "set5.part2.rar", "set5.part3.rar"];
    let open = |n: &str| Ok(Cursor::new(fixture(n)));
    let first = analyze_split_sets_seekable(&scanner, &names(&parts), &opts, open);
    assert_eq!(first.len(), 3);
    assert!(first.iter().all(|v| infected(&v.report.verdict).is_some()));
    let all = analyze_split_sets_seekable_all(&scanner, &names(&parts), &opts, open);
    assert_eq!(all.len(), 3);
    for m in &all {
        let mut found: Vec<&str> = m.found.iter().map(|(n, _)| n.as_str()).collect();
        found.sort();
        assert_eq!(found, ["Test.Noise", "Test.Text"], "{}", m.name);
        assert_eq!(m.outcome, AllMatchOutcome::Complete);
        assert_eq!(m.set, "set5.rar");
    }
}

#[test]
fn a_rar_set_the_seekable_form_cannot_join_is_reported_not_dropped() {
    let scanner = db(&[("t.hdb", &format!("{NOISE_MD5}:20000:Test.Noise\n"))]);
    let opts = ScanOptions::default();
    let unscannable = |got: &[exav_core::VolumeSetVerdict]| {
        got.iter()
            .map(|v| match &v.report.verdict {
                Verdict::Unscannable { reason } => reason.clone(),
                other => panic!("{}: {other:?}", v.name),
            })
            .collect::<Vec<_>>()
    };
    // A volume missing, and one not read: each part of the set is reported.
    let got = analyze_split_sets_seekable(
        &scanner,
        &names(&["set5.part1.rar", "set5.part3.rar"]),
        &opts,
        |n| Ok(Cursor::new(fixture(n))),
    );
    assert_eq!(unscannable(&got).len(), 2);
    let got = analyze_split_sets_seekable(
        &scanner,
        &names(&["set5.part1.rar", "set5.part2.rar", "set5.part3.rar"]),
        &opts,
        |n| {
            if n.contains("part2") {
                return Err(io::Error::other("no such file"));
            }
            Ok(Cursor::new(fixture(n)))
        },
    );
    let reasons = unscannable(&got);
    assert_eq!(reasons.len(), 3);
    assert!(
        reasons.iter().all(|r| r.contains("could not be read")),
        "{reasons:?}"
    );
    // Two names for one volume: not joined, so nothing is opened.
    let got = analyze_split_sets_seekable(
        &scanner,
        &names(&["set5.part2.rar", "set5.part01.rar", "set5.part1.rar"]),
        &opts,
        |n| -> io::Result<Cursor<Vec<u8>>> { panic!("{n} was opened: the set is not joined") },
    );
    assert!(unscannable(&got).iter().all(|r| r.contains("two names")));
}

/// A RAR5 block: the checksum the walk does not read, the size of the header,
/// and the header.
fn block5(content: Vec<u8>) -> Vec<u8> {
    [vec![0; 4], vint(content.len() as u64), content].concat()
}

fn vint(mut x: u64) -> Vec<u8> {
    let mut o = Vec::new();
    loop {
        let b = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            o.push(b);
            return o;
        }
        o.push(b | 0x80);
    }
}

/// A stored member of `data`, a part of `size` bytes in all.
fn member5(name: &str, split: u64, size: usize, data: &[u8]) -> Vec<u8> {
    let mut c = [2, 0x02 | split, data.len() as u64].map(vint).concat();
    // File flags, unpacked size, attributes, stored, host OS, name.
    c.extend(
        [0, size as u64, 0, 0, 0, name.len() as u64]
            .map(vint)
            .concat(),
    );
    c.extend_from_slice(name.as_bytes());
    [block5(c), data.to_vec()].concat()
}

/// A RAR5 set of three volumes: `payload` stored in a member across all of
/// them, and `filler` in one of its own in the last.
fn rar5_set(payload: &[u8], filler: &[u8]) -> Vec<Vec<u8>> {
    let share = payload.len().div_ceil(3);
    (0..3)
        .map(|k| {
            let mut v = b"Rar!\x1a\x07\x01\x00".to_vec();
            let mut main = [1, 0, if k > 0 { 3 } else { 1 }].map(vint).concat();
            if k > 0 {
                main.extend(vint(k as u64));
            }
            v.extend(block5(main));
            let part = &payload[k * share..((k + 1) * share).min(payload.len())];
            let split = if k > 0 { 0x08 } else { 0 } | if k < 2 { 0x10 } else { 0 };
            v.extend(member5("big.bin", split, payload.len(), part));
            if k == 2 {
                v.extend(member5("filler.bin", 0, filler.len(), filler));
            }
            v.extend(block5([5, 0, if k < 2 { 1 } else { 0 }].map(vint).concat()));
            v
        })
        .collect()
}

/// `(i * 7) % 251` for `i` below 100,000.
const BIG_MD5: &str = "c260642229888763c0fa2a4843f50a36";

/// A set too large to hold is scanned all the same where it lies: what a
/// member holds is found across the volumes, in the memory of a window.
#[test]
fn a_rar_set_past_the_memory_limit_is_scanned_where_it_lies() {
    let payload: Vec<u8> = (0..100_000).map(|i| (i * 7 % 251) as u8).collect();
    let vols = rar5_set(&payload, &[b' '; 70_000]);
    // The member fits the limit, the set does not.
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 128 * 1024;
    assert!(vols.iter().map(Vec::len).sum::<usize>() as u64 > opts.limits.max_buffer_bytes);
    let scanner = db(&[("t.hdb", &format!("{BIG_MD5}:100000:Test.Big\n"))]);
    let given = names(&["big.part1.rar", "big.part2.rar", "big.part3.rar"]);
    let file = |n: &str, vols: &[Vec<u8>]| vols[usize::from(n.as_bytes()[8] - b'1')].clone();
    // Held in memory, a set of this size is turned away.
    let held = analyze_split_sets(&scanner, &given, &opts, |n, _| Ok(file(n, &vols)));
    assert_eq!(held.len(), 3);
    for v in &held {
        let Verdict::Unscannable { reason } = &v.report.verdict else {
            panic!("{}: {:?}", v.name, v.report.verdict);
        };
        assert!(reason.contains("too large to hold"), "{reason}");
    }
    let got =
        analyze_split_sets_seekable(&scanner, &given, &opts, |n| Ok(Cursor::new(file(n, &vols))));
    assert_eq!(got.len(), 3);
    for v in &got {
        assert_eq!(infected(&v.report.verdict), Some("Test.Big"), "{}", v.name);
        assert_eq!(v.set, "big.rar");
    }
    // One byte of the member different, the signature does not match.
    let mut other = vols.clone();
    let at = other[1].len() / 2;
    other[1][at] ^= 1;
    let got = analyze_split_sets_seekable(&scanner, &given, &opts, |n| {
        Ok(Cursor::new(file(n, &other)))
    });
    assert!(got.iter().all(|v| infected(&v.report.verdict).is_none()));
}

/// A volume read from memory that fails over a stretch of its bytes.
struct Flaky {
    inner: Cursor<Vec<u8>>,
    bad: std::ops::Range<u64>,
}

impl Read for Flaky {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.bad.contains(&self.inner.position()) {
            return Err(io::Error::other("the disk is gone"));
        }
        self.inner.read(buf)
    }
}

impl Seek for Flaky {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.inner.seek(to)
    }
}

/// A volume that fails to read is not a clean one, whether it fails where the
/// set is joined or where the scan reads a member.
#[test]
fn a_set_with_a_volume_that_fails_to_read_is_not_clean() {
    let payload: Vec<u8> = (0..100_000).map(|i| (i * 7 % 251) as u8).collect();
    let vols = rar5_set(&payload, &[b' '; 70_000]);
    let mut opts = ScanOptions::default();
    opts.object_cache_block_bytes = 4096;
    let scanner = db(&[("t.hdb", &format!("{BIG_MD5}:100000:Test.Big\n"))]);
    let given = names(&["big.part1.rar", "big.part2.rar", "big.part3.rar"]);
    // (volume, the bytes that fail): the first block of the second, then the
    // second's data.
    for (volume, bad, join) in [(1, 0..4096, true), (1, 8192..12288, false)] {
        let got = analyze_split_sets_seekable(&scanner, &given, &opts, |n| {
            let k = usize::from(n.as_bytes()[8] - b'1');
            Ok(Flaky {
                inner: Cursor::new(vols[k].clone()),
                bad: if k == volume { bad.clone() } else { 0..0 },
            })
        });
        assert_eq!(got.len(), 3);
        for v in &got {
            let Verdict::Unscannable { reason } = &v.report.verdict else {
                panic!("{bad:?}: {}: {:?}", v.name, v.report.verdict);
            };
            if join {
                assert!(reason.contains("a part could not be read"), "{reason}");
            }
        }
    }
}

/// A volume that fails where no member is read (the data of a service block,
/// which the walk of the archive skips) is not clean either: the scan of the
/// bytes of the joined archive reads it, and the walk that ends on a source
/// that failed says so, with the failure's own words.
#[test]
fn a_set_with_a_volume_that_fails_where_no_member_is_read_is_not_clean() {
    let payload: Vec<u8> = (0..100_000).map(|i| (i * 7 % 251) as u8).collect();
    let mut vols = rar5_set(&payload, &[b' '; 70_000]);
    // A comment of 40,000 bytes in the second volume, before its end block.
    let data = [b'c'; 40_000];
    let mut service = [3, 0x02, data.len() as u64].map(vint).concat();
    service.extend([0, data.len() as u64, 0, 0, 0, 3].map(vint).concat());
    service.extend_from_slice(b"CMT");
    let service = [block5(service), data.to_vec()].concat();
    let end = block5([5, 0, 1].map(vint).concat());
    let at = vols[1].len() - end.len();
    vols[1].splice(at..at, service.iter().copied());
    // What fails is the inside of the comment: the blocks of the cache that
    // start 8 KiB or more from either end, so that the headers around it
    // read.
    let (from, to) = (at + service.len() - data.len(), at + service.len());
    let bad = (from + 8192) as u64..(to - 8192) as u64;

    let mut opts = ScanOptions::default();
    opts.object_cache_block_bytes = 4096;
    let given = names(&["big.part1.rar", "big.part2.rar", "big.part3.rar"]);
    let scan = |scanner: &Scanner, bad: std::ops::Range<u64>| {
        analyze_split_sets_seekable(scanner, &given, &opts, |n| {
            let k = usize::from(n.as_bytes()[8] - b'1');
            Ok(Flaky {
                inner: Cursor::new(vols[k].clone()),
                bad: if k == 1 { bad.clone() } else { 0..0 },
            })
        })
    };
    // Control: the comment where it is and nothing failing. The member is
    // found with its signature, and with another the set is clean.
    let found = db(&[("t.hdb", &format!("{BIG_MD5}:100000:Test.Big\n"))]);
    for v in scan(&found, 0..0) {
        assert_eq!(infected(&v.report.verdict), Some("Test.Big"), "{}", v.name);
    }
    let none = db(&[(
        "t.hdb",
        "00000000000000000000000000000000:100000:Test.None\n",
    )]);
    for v in scan(&none, 0..0) {
        assert!(matches!(v.report.verdict, Verdict::Clean), "{}", v.name);
    }
    let got = scan(&none, bad);
    assert_eq!(got.len(), 3);
    for v in &got {
        let Verdict::Unscannable { reason } = &v.report.verdict else {
            panic!("{}: {:?}", v.name, v.report.verdict);
        };
        assert!(reason.contains("the disk is gone"), "{reason}");
    }
}

/// A set whose last volume is cut inside the member is scanned as far as the
/// volumes go, and gives what an archive cut at the same place gives: a
/// signature in what is there is found, one in the part cut off is not (it is
/// absent, as in the single file). A set that ends where the member goes on, in
/// a volume not given, finds the same and is not clean.
#[test]
fn a_rar_set_whose_last_volume_is_cut_is_scanned_as_far_as_it_goes() {
    const HEAD: &[u8] = b"EXAV-SET-HEAD-MARKER";
    const TAIL: &[u8] = b"EXAV-SET-TAIL-MARKER";
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let mut payload: Vec<u8> = (0..99_999).map(|i| (i * 7 % 251) as u8).collect();
    payload[100..100 + HEAD.len()].copy_from_slice(HEAD);
    payload[95_000..95_000 + TAIL.len()].copy_from_slice(TAIL);
    let vols = rar5_set(&payload, &[b' '; 70_000]);
    // The third volume ends inside the third share of the member.
    let mut cut = vols.clone();
    cut[2].truncate(20_000);
    // The same member in one archive, cut after 60,000 bytes of it.
    let header = member5("big.bin", 0, payload.len(), &[]).len();
    let mut single = b"Rar!\x1a\x07\x01\x00".to_vec();
    single.extend(block5([1, 0, 0].map(vint).concat()));
    single.extend(member5("big.bin", 0, payload.len(), &payload));
    single.truncate(single.len() - payload.len() + 60_000);
    assert!(single.len() > header + 60_000);

    let given = names(&["big.part1.rar", "big.part2.rar", "big.part3.rar"]);
    let opts = ScanOptions::default();
    for (what, set, which) in [
        ("cut", &cut, &given[..]),
        ("last not given", &vols, &given[..2]),
    ] {
        for (marker, found) in [(HEAD, true), (TAIL, false)] {
            let sig = format!("Test.Marker:0:*:{}\n", hex(marker));
            let scanner = db(&[("t.ndb", &sig)]);
            let file = |n: &str| set[usize::from(n.as_bytes()[8] - b'1')].clone();
            let got = [
                analyze_split_sets(&scanner, which, &opts, |n, _| Ok(file(n))),
                analyze_split_sets_seekable(&scanner, which, &opts, |n| Ok(Cursor::new(file(n)))),
            ];
            for got in got {
                assert_eq!(got.len(), which.len(), "{what}");
                for v in &got {
                    let name =
                        format!("{what}: {} for {}", v.name, String::from_utf8_lossy(marker));
                    match (found, what) {
                        (true, _) => {
                            assert_eq!(infected(&v.report.verdict), Some("Test.Marker"), "{name}")
                        }
                        // The cut file's own answer, which the set gives too.
                        (false, "cut") => {
                            let alone = analyze(&scanner, &single, &opts);
                            assert!(matches!(alone.verdict, Verdict::Clean), "{name}");
                            assert!(matches!(v.report.verdict, Verdict::Clean), "{name}");
                        }
                        (false, _) => assert!(
                            matches!(v.report.verdict, Verdict::Unscannable { .. }),
                            "{name}: {:?}",
                            v.report.verdict
                        ),
                    }
                }
            }
        }
    }
}
