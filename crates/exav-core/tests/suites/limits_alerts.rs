//! `--alert-exceeds-max`: report a budget stop as a ClamAV-named detection.
//!
//! exav and ClamAV model the same condition in two vocabularies. exav says
//! "this scan did not finish" with a `LIMITS-EXCEEDED` verdict — honest, but it
//! needs the clamd `ERROR` reply shape, which most clients read as *the scanner
//! broke* rather than *this file is interesting*. ClamAV says
//! `Heuristics.Limits.Exceeded.MaxFiles FOUND`, an ordinary detection that fits
//! the protocol's three reply shapes and that gateways already have policy for.
//!
//! This flag is the bridge: same facts, ClamAV's names, opt-in.
//!
//! The alert name comes from a **typed** `LimitKind` carried on the
//! `LimitHit`, never from parsing the human-readable reason. Deriving a
//! detection name from prose is how a reworded message silently becomes a
//! different alert.

use exav_core::{analyze, loader, ScanOptions, Scanner, Verdict};
use std::io::Write;

fn scanner() -> Scanner {
    let mut l = loader::Builder::new();
    l.add_named_bytes("t.ndb", b"Zzz.Never:0:*:deadbeefdeadbeefdead\n", true);
    l.build().expect("build database")
}

/// A ZIP holding more members than the file-count budget allows.
fn zip_with_members(n: usize) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for i in 0..n {
        z.start_file(
            format!("m{i}.txt"),
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        z.write_all(b"padding padding padding\n").unwrap();
    }
    z.finish().unwrap().into_inner()
}

/// Budget tightened so the fixture is guaranteed to trip it.
fn tight(alert: bool) -> ScanOptions {
    let mut o = ScanOptions::default();
    o.alert_exceeds_max = alert;
    o.limits.max_members = 4;
    o
}

#[test]
fn a_budget_stop_is_a_limits_verdict_by_default() {
    let db = scanner();
    let blob = zip_with_members(40);
    match analyze(&db, &blob, &tight(false)).verdict {
        Verdict::LimitsExceeded { .. } => {}
        other => panic!("expected the default LIMITS-EXCEEDED verdict, got {other:?}"),
    }
}

#[test]
fn alert_exceeds_max_turns_it_into_a_clamav_named_detection() {
    let db = scanner();
    let blob = zip_with_members(40);
    match analyze(&db, &blob, &tight(true)).verdict {
        Verdict::Infected { signature, .. } => {
            assert!(
                signature.starts_with("Heuristics.Limits.Exceeded."),
                "must use ClamAV's alert family; got {signature}"
            );
            // The kind must be the one that actually stopped the scan. A generic
            // name would be worse than useless: an operator tuning limits needs
            // to know *which* budget to raise.
            assert_eq!(
                signature, "Heuristics.Limits.Exceeded.MaxFiles",
                "the file-count budget stopped this scan, so the alert must say so"
            );
        }
        other => panic!("expected a Heuristics.Limits.Exceeded.* detection, got {other:?}"),
    }
}

#[test]
fn the_recursion_budget_reports_its_own_name() {
    let db = scanner();
    // Nested ZIPs deeper than the recursion budget.
    let mut blob = b"payload payload payload\n".to_vec();
    for i in 0..8 {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        z.start_file(
            format!("n{i}.zip"),
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        z.write_all(&blob).unwrap();
        blob = z.finish().unwrap().into_inner();
    }
    let mut opts = ScanOptions::default();
    opts.alert_exceeds_max = true;
    opts.limits.max_recursion = 2;

    match analyze(&db, &blob, &opts).verdict {
        Verdict::Infected { signature, .. } => assert_eq!(
            signature, "Heuristics.Limits.Exceeded.MaxRecursion",
            "depth stopped this scan, not size or count"
        ),
        other => panic!("expected MaxRecursion, got {other:?}"),
    }
}

/// A PE shaped like a packed file (entry point in a writable section, a
/// destination section with no raw data) whose stub is `jmp $`.
#[cfg(any(feature = "pe-emu", feature = "all-formats"))]
fn spinning_packed_pe() -> Vec<u8> {
    let (pe, opt_size, raw) = (0x80usize, 0xe0usize, 0x400usize);
    let mut d = vec![0u8; raw + 0x1000];
    d[..2].copy_from_slice(b"MZ");
    d[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
    d[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    d[coff..coff + 2].copy_from_slice(&0x14cu16.to_le_bytes());
    d[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
    d[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
    let opt = coff + 20;
    d[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
    d[opt + 16..opt + 20].copy_from_slice(&0xe000u32.to_le_bytes());
    d[opt + 28..opt + 32].copy_from_slice(&0x40_0000u32.to_le_bytes());
    d[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    d[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    d[opt + 56..opt + 60].copy_from_slice(&0x2_0000u32.to_le_bytes());
    d[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
    let s0 = opt + opt_size;
    d[s0..s0 + 5].copy_from_slice(b".text");
    d[s0 + 8..s0 + 12].copy_from_slice(&0xd000u32.to_le_bytes());
    d[s0 + 12..s0 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    d[s0 + 36..s0 + 40].copy_from_slice(&0xe000_0020u32.to_le_bytes());
    let s1 = s0 + 40;
    d[s1..s1 + 5].copy_from_slice(b".data");
    d[s1 + 8..s1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    d[s1 + 12..s1 + 16].copy_from_slice(&0xe000u32.to_le_bytes());
    d[s1 + 16..s1 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    d[s1 + 20..s1 + 24].copy_from_slice(&(raw as u32).to_le_bytes());
    d[s1 + 36..s1 + 40].copy_from_slice(&0xe000_0060u32.to_le_bytes());
    d[raw..raw + 2].copy_from_slice(&[0xeb, 0xfe]);
    d
}

#[cfg(any(feature = "pe-emu", feature = "all-formats"))]
#[test]
fn the_emulation_budget_reports_its_own_name() {
    let db = scanner();
    let blob = spinning_packed_pe();
    let mut opts = ScanOptions::default();
    opts.limits.max_pe_emulation_steps = 10_000;
    match analyze(&db, &blob, &opts).verdict {
        Verdict::LimitsExceeded { reason } => assert!(
            reason.contains("--max-pe-emulation-steps"),
            "the reason names the flag to raise: {reason}"
        ),
        other => panic!("expected LIMITS-EXCEEDED, got {other:?}"),
    }
    opts.alert_exceeds_max = true;
    match analyze(&db, &blob, &opts).verdict {
        Verdict::Infected { signature, .. } => {
            assert_eq!(signature, "Heuristics.Limits.Exceeded.MaxScanTime")
        }
        other => panic!("expected MaxScanTime, got {other:?}"),
    }
}

#[test]
fn a_real_detection_still_beats_the_limit_alert() {
    // Precedence matters: a file that both trips a budget and carries malware
    // must report the malware. Reporting "limits exceeded" instead would turn a
    // detection into a shrug.
    let hex: String = b"exav-limit-precedence-marker"
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut l = loader::Builder::new();
    l.add_named_bytes("t.ndb", format!("Test.Real:0:*:{hex}\n").as_bytes(), true);
    let db = l.build().expect("db");

    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    z.start_file("hit.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    z.write_all(b"exav-limit-precedence-marker").unwrap();
    for i in 0..40 {
        z.start_file(
            format!("f{i}.txt"),
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        z.write_all(b"padding\n").unwrap();
    }
    let blob = z.finish().unwrap().into_inner();

    match analyze(&db, &blob, &tight(true)).verdict {
        Verdict::Infected { signature, .. } => assert_eq!(
            signature, "Test.Real",
            "the real signature must win over the limit alert"
        ),
        other => panic!("expected the real detection, got {other:?}"),
    }
}
