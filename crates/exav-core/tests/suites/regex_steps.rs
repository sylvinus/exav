//! The work budget of the regex engines (`--max-regex-steps`).
//!
//! A pattern with lookaround or a back reference runs on a backtracking
//! engine, a YARA regexp reports a match at every offset it can start at, and
//! a crafted object makes either take as long as it likes. A search that
//! reaches the budget stops, and a scan that stopped must not end `OK`.

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};

fn database(name: &str, text: &str) -> Scanner {
    let mut l = loader::Builder::new();
    l.add_named_bytes(name, text.as_bytes(), false);
    l.build().expect("build database")
}

fn incomplete(v: &Verdict) -> bool {
    matches!(v, Verdict::LimitsExceeded { .. })
}

/// The verdict with `steps` as the budget, the object held in memory.
fn held(db: &Scanner, data: &[u8], steps: Option<u64>) -> Verdict {
    let mut opts = ScanOptions::default();
    opts.max_regex_steps = steps;
    analyze(db, data, &opts).verdict
}

/// The verdict with `steps` as the budget, the object read through a block
/// cache, as one past `--max-object-bytes` is.
#[cfg(feature = "yara")]
fn read_in_place(db: &Scanner, data: &[u8], steps: Option<u64>) -> Verdict {
    let mut opts = ScanOptions::default();
    opts.max_regex_steps = steps;
    opts.limits.max_buffer_bytes = 512;
    opts.spill = Some(std::sync::Arc::new(
        exav_core::unpack::spill::MemSpill::new(),
    ));
    exav_core::scan_seekable(
        db,
        std::io::Cursor::new(data.to_vec()),
        data.len() as u64,
        &opts,
    )
    .expect("scan")
    .verdict
}

// ---------------------------------------------------------------------------
// PCRE: backtracks
// ---------------------------------------------------------------------------

/// `aa` anchors the pattern, which needs a back reference and so runs on the
/// backtracking engine. On `a`s with no `c` after them it finds nothing, after
/// a number of backtracks that grows steeply with the `a`s.
fn backtracking() -> Scanner {
    database(
        "t.ldb",
        "Exav.Test.Redos;Target:0;0&1;6161;0/(?:(a+)\\1)+c/\n",
    )
}

fn backtracking_input(a: usize) -> Vec<u8> {
    let mut d = vec![b'a'; a];
    d.extend(b"bc");
    d
}

/// 14 `a`s take more than 1,000 steps and fewer than 2,048, 36 take more than
/// 1,000,000, and every one of them is a search that finds nothing.
#[test]
fn a_search_that_reaches_the_budget_is_incomplete_not_clean() {
    let db = backtracking();
    let v = held(&db, &backtracking_input(14), Some(1000));
    assert!(incomplete(&v), "{v:?}");
    let v = held(&db, &backtracking_input(36), Some(1_000_000));
    assert!(incomplete(&v), "{v:?}");
}

#[test]
fn a_search_within_the_budget_finishes_clean() {
    let db = backtracking();
    assert!(matches!(
        held(&db, &backtracking_input(14), Some(100_000)),
        Verdict::Clean
    ));
    assert!(matches!(
        held(&db, &backtracking_input(14), Some(1_000_000)),
        Verdict::Clean
    ));
}

#[test]
fn the_default_budget_is_a_hundred_million_steps() {
    assert_eq!(ScanOptions::default().max_regex_steps, Some(100_000_000));
    assert_eq!(
        ScanOptions::clamav_compat().max_regex_steps,
        Some(100_000_000)
    );
}

#[test]
fn off_lifts_the_budget() {
    // The same input a budget of a million stops, searched to its end.
    let db = backtracking();
    assert!(matches!(
        held(&db, &backtracking_input(36), None),
        Verdict::Clean
    ));
}

/// The matches of one subsignature under `g` are searches that share one
/// budget: each costs a backtrack, past the `x` that the lookbehind wants, and
/// 3,000 of them cost more than 1,000.
#[test]
fn the_matches_of_one_subsignature_share_the_budget() {
    let db = database(
        "t.ldb",
        "Exav.Test.Many;Target:0;0&1>2999;7861;0/(?<=x)a/g\n",
    );
    let data = b"xa".repeat(3001);
    // Enough for the count to get there.
    let v = held(&db, &data, Some(1_000_000));
    assert!(matches!(v, Verdict::Infected { .. }), "{v:?}");
    // Not enough: the count stopped short of 2,999, and the scan says so.
    let v = held(&db, &data, Some(1000));
    assert!(incomplete(&v), "{v:?}");
}

// ---------------------------------------------------------------------------
// PCRE: what a sub-pattern handed to the linear engine reads
// ---------------------------------------------------------------------------

/// A lookbehind, then a greedy run the VM hands to the linear engine. Every
/// offset of the run passes the lookbehind, reads to the end of the run and
/// fails: the backtracks are as many as the offsets, the bytes read are the
/// square of them.
fn delegating() -> Scanner {
    database(
        "t.ldb",
        "Exav.Test.Delegated;Target:0;0&1;4d41524b;0/(?<=[xa])a+d/\n",
    )
}

fn delegating_input(a: usize) -> Vec<u8> {
    let mut d = b"MARKx".to_vec();
    d.extend(vec![b'a'; a]);
    d.extend(b"eXad");
    d
}

/// 2,000 offsets are 2,000 steps of backtracks and some 62,500 of the 2,000,000
/// bytes read.
#[test]
fn the_bytes_a_delegated_search_reads_count_as_steps() {
    let db = delegating();
    let data = delegating_input(2000);
    let v = held(&db, &data, Some(10_000));
    assert!(incomplete(&v), "{v:?}");
    assert!(matches!(held(&db, &data, Some(1_000_000)), Verdict::Clean));
    assert!(matches!(held(&db, &data, None), Verdict::Clean));
}

/// The run is 128 KiB: unbounded, 8 GiB are read, and the search takes the
/// better part of a minute.
#[test]
fn a_long_run_for_a_delegated_search_is_cut_short() {
    let db = delegating();
    let v = held(&db, &delegating_input(128 * 1024), Some(1_000_000));
    assert!(incomplete(&v), "{v:?}");
}

// ---------------------------------------------------------------------------
// YARA regexps
// ---------------------------------------------------------------------------

/// Every offset of a run of base64 characters starts a match that ends where
/// the run does. The condition cannot hold, so only the search says whether
/// the rule matched.
#[cfg(feature = "yara")]
fn base64_run(condition: &str) -> Scanner {
    database(
        "t.yar",
        &format!("rule r {{ strings: $a = /[A-Za-z0-9+\\/=]{{40,}}/ condition: {condition} }}"),
    )
}

/// A NUL first, so that the object has no text view to be read in place.
#[cfg(feature = "yara")]
fn run_of_base64(n: usize) -> Vec<u8> {
    let mut d = vec![0u8];
    d.extend(vec![b'A'; n]);
    d
}

/// 4,096 offsets, each reading to the end of the run and back over the match:
/// a little over 500,000 steps.
#[cfg(feature = "yara")]
#[test]
fn a_yara_regexp_that_reads_the_run_from_each_offset_reaches_the_budget() {
    let db = base64_run("#a > 100000000");
    let data = run_of_base64(4096);
    let v = held(&db, &data, Some(100_000));
    assert!(incomplete(&v), "{v:?}");
    assert!(matches!(held(&db, &data, Some(10_000_000)), Verdict::Clean));
    assert!(matches!(held(&db, &data, None), Verdict::Clean));
}

#[cfg(feature = "yara")]
#[test]
fn the_budget_of_a_yara_regexp_holds_over_a_block_cache_too() {
    let db = base64_run("#a > 100000000");
    let data = run_of_base64(4096);
    let v = read_in_place(&db, &data, Some(100_000));
    assert!(incomplete(&v), "{v:?}");
    assert!(matches!(
        read_in_place(&db, &data, Some(10_000_000)),
        Verdict::Clean
    ));
    assert!(matches!(read_in_place(&db, &data, None), Verdict::Clean));
}

/// The matches found before the search stopped are matches: a rule that
/// they satisfy matches, and one that needs more than they are does not.
#[cfg(feature = "yara")]
#[test]
fn a_yara_rule_the_matches_found_before_the_budget_satisfy_still_matches() {
    let data = run_of_base64(4096);
    for read in [held, read_in_place] {
        let v = read(&base64_run("#a > 2"), &data, Some(2000));
        assert!(
            matches!(&v, Verdict::Infected { signature, .. } if signature == "YARA.r"),
            "{v:?}"
        );
        let v = read(&base64_run("#a > 100000000"), &data, Some(2000));
        assert!(incomplete(&v), "{v:?}");
    }
}

/// 128 KiB of one run: unbounded, a minute of reading; a budget of a million
/// steps stops it in a fraction of a second.
#[cfg(feature = "yara")]
#[test]
fn a_long_run_for_a_yara_regexp_is_cut_short() {
    let db = base64_run("#a > 100000000");
    let v = held(&db, &run_of_base64(128 * 1024), Some(1_000_000));
    assert!(incomplete(&v), "{v:?}");
}
