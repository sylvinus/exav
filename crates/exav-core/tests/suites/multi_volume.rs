//! A multi-volume archive must be rejoined before it is scanned.
//!
//! An archive split across `x.7z.001`, `.002`, … is one file cut into pieces at
//! arbitrary byte offsets. Scanned a piece at a time, nothing decodes and every
//! piece reports clean — the payload is never reassembled, so the whole set
//! passes as harmless. Each test below therefore splits its payload *through the
//! middle of the signature bytes*, so no individual part can match and only the
//! rejoin can find it. Anything less would pass with the collector removed.
//!
//! The other half of the contract is what happens when a set cannot be
//! rejoined: those bytes were withheld from the scan, and dropping them there
//! would be a silent clean — the exact failure this scanner exists to prevent.

use exav_core::{analyze, ScanOptions, Scanner, Verdict};

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// A stored-only ZIP holding the given members, in order.
fn zip_with(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut count = 0u16;
    for (name, data) in members {
        let crc = crc32(data);
        let offset = out.len() as u32;
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
        count += 1;
    }
    let cd_offset = out.len() as u32;
    let cd_len = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Cut `blob` into `n` roughly equal pieces.
fn split(blob: &[u8], n: usize) -> Vec<Vec<u8>> {
    let each = blob.len().div_ceil(n);
    blob.chunks(each).map(|c| c.to_vec()).collect()
}

/// The set that every test below is built from: a ZIP carrying EICAR, cut into
/// `n` parts. Returns `(part_name, bytes)` pairs.
fn split_zip(stem: &str, n: usize) -> Vec<(String, Vec<u8>)> {
    let inner = zip_with(&[("payload.txt", EICAR)]);
    split(&inner, n)
        .into_iter()
        .enumerate()
        .map(|(i, part)| (format!("{stem}.zip.{:03}", i + 1), part))
        .collect()
}

fn scan(blob: &[u8]) -> exav_core::ScanReport {
    analyze(&Scanner::builtin(), blob, &ScanOptions::default())
}

/// The other entry point, and a wholly different code path: a seekable
/// reader walks the top-level container member-by-member as *readers*, so its
/// collector has to buffer a part before it can hold it. A fix applied to only
/// one of the two walks is the mistake these pairs exist to catch.
fn scan_streamed(blob: &[u8]) -> exav_core::ScanReport {
    exav_core::scan_seekable(
        &Scanner::builtin(),
        std::io::Cursor::new(blob.to_vec()),
        blob.len() as u64,
        &ScanOptions::default(),
    )
    .expect("scan")
}

/// Sanity check on the fixture itself: if any single part still carried the
/// whole signature, every test here would pass with the collector deleted.
#[test]
fn no_single_part_of_the_fixture_carries_the_payload() {
    for (name, part) in split_zip("x", 3) {
        assert!(
            !part.windows(EICAR.len()).any(|w| w == EICAR),
            "{name} contains the whole payload — the fixture proves nothing"
        );
        assert!(
            !matches!(scan(&part).verdict, Verdict::Infected { .. }),
            "{name} is detectable on its own — the fixture proves nothing"
        );
    }
}

#[test]
fn a_byte_split_archive_inside_a_zip_is_rejoined_and_scanned() {
    let parts = split_zip("payload", 3);
    let outer = zip_with(
        &parts
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect::<Vec<_>>(),
    );
    for report in [scan(&outer), scan_streamed(&outer)] {
        assert!(
            matches!(report.verdict, Verdict::Infected { .. }),
            "a split archive whose parts are all present must be rejoined and \
             scanned; got {:?}",
            report.verdict
        );
    }
}

#[test]
fn parts_out_of_order_in_the_container_still_rejoin() {
    // A container yields members in whatever order it was written, which need
    // not be volume order. Reassembly is by index, not by arrival.
    let parts = split_zip("payload", 3);
    let outer = zip_with(&[
        (parts[2].0.as_str(), parts[2].1.as_slice()),
        (parts[0].0.as_str(), parts[0].1.as_slice()),
        (parts[1].0.as_str(), parts[1].1.as_slice()),
    ]);
    assert!(
        matches!(scan(&outer).verdict, Verdict::Infected { .. }),
        "arrival order must not decide the join order"
    );
}

#[test]
fn a_prefix_that_looks_complete_is_not_joined_early() {
    // `.001`+`.002` are contiguous, so a collector that joins as soon as the
    // positions line up would emit a truncated prefix — which still parses as a
    // ZIP and would then be scanned as if it were the whole archive, with the
    // payload in `.003` never reached. Splitting into four parts and putting the
    // signature in the last one makes that failure visible.
    let inner = zip_with(&[("filler.bin", &vec![b'.'; 4096]), ("payload.txt", EICAR)]);
    let parts: Vec<(String, Vec<u8>)> = split(&inner, 4)
        .into_iter()
        .enumerate()
        .map(|(i, p)| (format!("late.zip.{:03}", i + 1), p))
        .collect();
    let outer = zip_with(
        &parts
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect::<Vec<_>>(),
    );
    assert!(
        matches!(scan(&outer).verdict, Verdict::Infected { .. }),
        "an early join would have stopped before the last part"
    );
}

#[test]
fn an_incomplete_set_is_reported_not_passed_as_clean() {
    // Parts were withheld from the scan to be joined and then could not be.
    // Reporting clean here would hide an archive nothing can read.
    let parts = split_zip("gap", 3);
    let outer = zip_with(&[
        (parts[0].0.as_str(), parts[0].1.as_slice()),
        (parts[2].0.as_str(), parts[2].1.as_slice()),
    ]);
    for report in [scan(&outer), scan_streamed(&outer)] {
        assert!(
            matches!(report.verdict, Verdict::Unscannable { .. }),
            "a set with a hole in it must not scan clean; got {:?}",
            report.verdict
        );
    }
}

#[test]
fn a_set_missing_its_first_volume_is_reported() {
    let parts = split_zip("headless", 3);
    let outer = zip_with(&[
        (parts[1].0.as_str(), parts[1].1.as_slice()),
        (parts[2].0.as_str(), parts[2].1.as_slice()),
    ]);
    assert!(
        matches!(scan(&outer).verdict, Verdict::Unscannable { .. }),
        "without the first volume the archive has no head and cannot be read"
    );
}

#[test]
fn a_lone_numbered_file_is_still_scanned_and_not_flagged() {
    // Plenty of ordinary files end in `.001`. One part is not a set: it must be
    // scanned normally, and it must not be reported as a broken archive.
    let infected = zip_with(&[("notes.dat.001", EICAR)]);
    assert!(
        matches!(scan(&infected).verdict, Verdict::Infected { .. }),
        "a held member must still reach the scanner"
    );
    let clean = zip_with(&[("notes.dat.001", b"nothing to see here")]);
    for report in [scan(&clean), scan_streamed(&clean)] {
        assert!(
            matches!(report.verdict, Verdict::Clean),
            "a single `.001` is a file, not evidence of a missing archive; \
             got {:?}",
            report.verdict
        );
    }
}

#[test]
fn format_aware_volumes_are_not_concatenated() {
    // RAR volumes carry their own headers and a member's data resumes *past*
    // the next volume's header, so concatenating them yields garbage that still
    // looks like an archive. They pass through and are scanned individually —
    // which is what finds this payload.
    let outer = zip_with(&[("a.part1.rar", b"Rar!\x1a\x07\x00"), ("a.part2.rar", EICAR)]);
    assert!(
        matches!(scan(&outer).verdict, Verdict::Infected { .. }),
        "a `.partN.rar` member must still be scanned on its own"
    );
}

#[test]
fn two_sets_in_one_container_do_not_mix() {
    let a = split_zip("alpha", 2);
    let b = split_zip("beta", 2);
    // Interleaved, so a collector keying on anything less than the stem would
    // splice the two together and decode neither.
    let outer = zip_with(&[
        (a[0].0.as_str(), a[0].1.as_slice()),
        (b[0].0.as_str(), b[0].1.as_slice()),
        (a[1].0.as_str(), a[1].1.as_slice()),
        (b[1].0.as_str(), b[1].1.as_slice()),
    ]);
    assert!(
        matches!(scan(&outer).verdict, Verdict::Infected { .. }),
        "interleaved sets must each rejoin"
    );
}

#[test]
fn an_ordinary_container_is_unaffected() {
    let outer = zip_with(&[("a.txt", b"hello"), ("b.bin", &[0u8; 64])]);
    assert!(
        matches!(scan(&outer).verdict, Verdict::Clean),
        "a container with no volume members must behave exactly as before"
    );
}

// ---- The directory entry point ---------------------------------------------
//
// `analyze_volume_sets` takes a group of names that arrived together and the
// means to fetch each. Its hard case is a part it cannot get hold of: byte-split
// naming records no part count, so a set missing its LAST part is
// indistinguishable, by index alone, from a set that is all there.

/// The names and bytes of a split set, as a directory would hold them.
fn split_set(stem: &str, n: usize) -> Vec<(String, Vec<u8>)> {
    split_zip(stem, n)
}

/// A set whose payload lives entirely in the LAST part, the rest being ordinary
/// text that scans clean on its own.
///
/// A truncated archive usually gives itself away — a ZIP with no central
/// directory does not parse, and exav says so. This set has no such tell: drop
/// its last part and what remains is a plain text file, complete and harmless
/// looking, with nothing in it to suggest more was meant to follow.
fn set_with_payload_in_the_tail(stem: &str) -> Vec<(String, Vec<u8>)> {
    let filler = vec![b'A'; 4096];
    vec![
        (format!("{stem}.bin.001"), filler.clone()),
        (format!("{stem}.bin.002"), filler),
        (format!("{stem}.bin.003"), EICAR.to_vec()),
    ]
}

fn sets(parts: &[(String, Vec<u8>)], unreadable: &[&str]) -> Vec<exav_core::VolumeSetVerdict> {
    let names: Vec<String> = parts.iter().map(|(n, _)| n.clone()).collect();
    exav_core::analyze_volume_sets(
        &Scanner::builtin(),
        &names,
        &ScanOptions::default(),
        |want| {
            if unreadable.contains(&want) {
                return Err(std::io::Error::other("permission denied"));
            }
            parts
                .iter()
                .find(|(n, _)| n == want)
                .map(|(_, d)| d.clone())
                .ok_or_else(|| std::io::Error::other("no such file"))
        },
    )
}

#[test]
fn a_complete_set_is_rejoined_and_scanned() {
    let parts = split_set("whole", 3);
    let v = sets(&parts, &[]);
    assert_eq!(v.len(), 3, "one verdict per part");
    for e in &v {
        assert!(
            matches!(e.report.verdict, Verdict::Infected { .. }),
            "{}: a rejoined set holding EICAR is infected, got {:?}",
            e.name,
            e.report.verdict
        );
    }
}

#[test]
fn a_set_whose_last_part_cannot_be_read_is_never_called_clean() {
    // The dangerous shape. Parts 1 and 2 arrive and their indices run
    // contiguously from the start, so nothing in the index list says a part 3
    // was ever meant to follow. Joining them yields bytes that scan clean.
    let parts = set_with_payload_in_the_tail("truncated");
    let last = parts[2].0.clone();

    // The premise: the join of the readable parts really is clean on its own,
    // so only knowing that a part went missing can save this verdict.
    let mut prefix = parts[0].1.clone();
    prefix.extend_from_slice(&parts[1].1);
    assert!(
        matches!(scan(&prefix).verdict, Verdict::Clean),
        "the fixture must be clean without its last part, or this test proves nothing"
    );

    let v = sets(&parts, &[last.as_str()]);
    assert!(!v.is_empty(), "the readable parts still get verdicts");
    for e in &v {
        assert!(
            !matches!(e.report.verdict, Verdict::Clean),
            "{}: part of a set that lost a volume was reported CLEAN. Those bytes \
             were withheld from the scan, so this is a false assurance rather \
             than a finding. Verdict: {:?}",
            e.name,
            e.report.verdict
        );
    }
}

#[test]
fn a_set_missing_its_first_part_is_unscannable() {
    // The already-visible case, kept beside the invisible one: a hole at the
    // start shows up in the index list, so the collector refuses the join.
    let mut parts = split_set("headless", 3);
    parts.remove(0);
    let v = sets(&parts, &[]);
    assert!(!v.is_empty());
    for e in &v {
        assert!(
            matches!(e.report.verdict, Verdict::Unscannable { .. }),
            "{}: expected UNSCANNABLE for a set with no first volume, got {:?}",
            e.name,
            e.report.verdict
        );
    }
}

#[test]
fn ordinary_names_cost_nothing_and_return_nothing() {
    let names = vec!["notes.txt".to_string(), "image.png".to_string()];
    let v = exav_core::analyze_volume_sets(
        &Scanner::builtin(),
        &names,
        &ScanOptions::default(),
        |_| panic!("fetch must not run for a name that is not a volume part"),
    );
    assert!(v.is_empty(), "no sets, no verdicts");
}
