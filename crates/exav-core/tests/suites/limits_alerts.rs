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
    let mut o = ScanOptions {
        alert_exceeds_max: alert,
        ..ScanOptions::default()
    };
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
    let mut opts = ScanOptions {
        alert_exceeds_max: true,
        ..ScanOptions::default()
    };
    opts.limits.max_recursion = 2;

    match analyze(&db, &blob, &opts).verdict {
        Verdict::Infected { signature, .. } => assert_eq!(
            signature, "Heuristics.Limits.Exceeded.MaxRecursion",
            "depth stopped this scan, not size or count"
        ),
        other => panic!("expected MaxRecursion, got {other:?}"),
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
