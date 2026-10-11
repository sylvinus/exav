#![no_main]
//! The scanner end to end, built the way a deployment builds it, and held to
//! what the entry points promise each other.
//!
//! The input is `fuzz_support::frame`: a header of option bits (the
//! `options::scan_options` switches) and up to eight database files, each a
//! kind byte (an extension of the loader's, bit 7 for an official database)
//! and its text, then the bytes to scan. The files go through
//! `loader::Builder::add_named_bytes`, the path the CLI and the daemon take, so
//! every database kind the loader reads is reached: signatures (`ndb`, `ldb`),
//! hashes, container and file-type rules, YARA, bytecode, phishing and
//! allow-lists, Authenticode block-lists, passwords. With no file in the
//! header the signatures are those of `fuzz/db/`, which is what a raw fixture
//! behind a three-byte zero header scans against.
//!
//! What is checked, and where the claim is made:
//!
//! * the same bytes scanned twice give the same report;
//! * `analyze_all` is a superset of `analyze`: a detection in one is in the
//!   other, a clean scan lists nothing, and neither is fully scanned when the
//!   other is not (`tests/suites/allmatch_parity.rs`, the doc on
//!   `AllMatchOutcome`);
//! * a stream and a buffer are one scan: `scan_seekable` over a reader that
//!   returns what it is asked in pieces answers what `analyze` did, while the
//!   object is within `deep_analysis_max` (`tests/suites/one_scan.rs`);
//! * a database written out and read back scans as the one it came from.
use std::io::{Cursor, Read, Seek, SeekFrom};

use exav_core::{
    analyze, analyze_all_with_outcome, database, loader, scan_seekable, AllMatchOutcome, ScanReport,
    Scanner, Verdict, VerdictCategory,
};
use exav_fuzz_support::{extreme, frame};
use libfuzzer_sys::fuzz_target;

#[path = "../db.rs"]
mod db;
#[path = "../options.rs"]
mod options;

libfuzzer_sys::fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    if extreme::set_extreme_field(data, size, seed) {
        size
    } else {
        libfuzzer_sys::fuzzer_mutate(data, size, max_size)
    }
});

/// A reader that gives at most a few bytes a call, as a socket does.
struct Pieces<R>(R, usize);

impl<R: Read> Read for Pieces<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.1);
        self.0.read(&mut buf[..n])
    }
}

impl<R: Seek> Seek for Pieces<R> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(to)
    }
}

fn same(what: &str, a: &ScanReport, b: &ScanReport) {
    assert_eq!(a.verdict, b.verdict, "{what}: the verdicts differ");
    let findings = |r: &ScanReport| {
        r.findings
            .iter()
            .map(|f| (f.label.clone(), f.detail.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(findings(a), findings(b), "{what}: the findings differ");
}

/// The static database as a prebuilt file reads it back, once.
fn static_roundtrip() -> &'static Scanner {
    static LOADED: std::sync::OnceLock<Scanner> = std::sync::OnceLock::new();
    LOADED.get_or_init(|| roundtrip(db::scanner()).expect("the fuzz database round-trips"))
}

fn roundtrip(db: &Scanner) -> Option<Scanner> {
    let mut buf = Vec::new();
    database::write(db, &mut buf).ok()?;
    database::read(buf.as_slice()).ok()
}

fuzz_target!(|data: &[u8]| {
    let Some(f) = frame::parse(data) else {
        return;
    };
    let opts = options::scan_options(f.bits);
    let scan = f.rest;

    let built;
    let (db, loaded): (&Scanner, Option<Scanner>) = if f.files.is_empty() {
        (db::scanner(), None)
    } else {
        let mut b = loader::Builder::new();
        for (i, (kind, text)) in f.files.iter().enumerate() {
            let name = format!("f{i}.{}", db::kind(kind & 0x7f));
            b.add_named_bytes(&name, text, kind & 0x80 != 0);
        }
        let Ok(s) = b.build() else {
            return;
        };
        built = s;
        let loaded = roundtrip(&built);
        (&built, loaded)
    };

    let first = analyze(db, scan, &opts);
    let again = analyze(db, scan, &opts);
    same("the same bytes twice", &first, &again);

    let (names, outcome) = analyze_all_with_outcome(db, scan, &opts);
    match first.verdict.category() {
        VerdictCategory::Infected => {
            if let Verdict::Infected { signature, .. } = &first.verdict {
                // Including the alert a budget stop becomes under
                // `--alert-exceeds-max`, which is a name in both.
                assert!(
                    names.iter().any(|(n, _)| n == signature),
                    "analyze found {signature}, analyze_all listed {:?}",
                    names.iter().map(|(n, _)| n).collect::<Vec<_>>()
                );
            }
        }
        VerdictCategory::Clean => {
            assert!(names.is_empty(), "analyze says clean, analyze_all lists {names:?}");
            assert_eq!(outcome, AllMatchOutcome::Complete, "analyze says clean, analyze_all did not finish");
        }
        VerdictCategory::Partial => {
            assert!(
                outcome != AllMatchOutcome::Complete || !names.is_empty(),
                "analyze did not finish ({:?}), analyze_all says it did",
                first.verdict
            );
        }
    }

    // One scan from any source, within the limit that decides how it is read.
    let len = scan.len() as u64;
    if len <= opts.deep_analysis_max && opts.max_scan_size.map_or(true, |m| len <= m) {
        let reader = Pieces(Cursor::new(scan), 1 + scan.len() % 7);
        let streamed = scan_seekable(db, reader, len, &opts).expect("a memory reader does not fail");
        same("a stream and a buffer", &first, &streamed);
    }

    let loaded = match &loaded {
        Some(l) => Some(l),
        None if f.files.is_empty() => Some(static_roundtrip()),
        None => None,
    };
    if let Some(loaded) = loaded {
        let back = analyze(loaded, scan, &opts);
        same("a database read back", &first, &back);
    }
});
