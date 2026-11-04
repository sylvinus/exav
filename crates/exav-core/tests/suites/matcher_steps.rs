//! The step bounds of the body-signature verifier (`--max-matcher-steps`).
//!
//! A body with a wildcard or a gap is verified at each hit of its anchor, and
//! the work of a scan grows with the number of hits. The verifier has a pool
//! of steps for the object and a share of it for each group of bodies that
//! share an anchor; a scan that spends either did not finish its search and
//! must not end `OK`.

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};

fn database(text: &str) -> Scanner {
    let mut l = loader::Builder::new();
    l.add_named_bytes("t.ndb", text.as_bytes(), false);
    l.build().expect("build database")
}

fn verdict(db: &Scanner, data: &[u8], steps: Option<u64>) -> Verdict {
    let mut opts = ScanOptions::default();
    opts.max_matcher_steps = steps;
    analyze(db, data, &opts).verdict
}

fn incomplete(v: &Verdict) -> bool {
    matches!(v, Verdict::LimitsExceeded { .. })
}

/// One body, `aaaa` then `ffff` later, and an object with the anchor many
/// times and the rest never: every hit searches the rest of the object.
fn one_group() -> (Scanner, Vec<u8>) {
    let db = database("Exav.Test.Group:0:*:61616161*66666666\n");
    let data = b"aaaa-".repeat(2000);
    (db, data)
}

/// Many bodies with an anchor of their own, each hit once, so that no group
/// draws much and the pool is what runs out.
fn many_groups() -> (Scanner, Vec<u8>) {
    let (mut sigs, mut data) = (String::new(), Vec::new());
    for i in 0..400u32 {
        let (a, b) = (format!("A{i:04}"), format!("B{i:04}"));
        sigs.push_str(&format!("Exav.Test.Pool{i}:0:*:{}*{}\n", hex(&a), hex(&b)));
        // The second token comes before the first: no match.
        data.extend(format!("{b}-{a}-").bytes());
    }
    (database(&sigs), data)
}

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_default_rate_is_two_million_steps_per_mib() {
    assert_eq!(ScanOptions::default().max_matcher_steps, Some(2_000_000));
    assert_eq!(
        ScanOptions::clamav_compat().max_matcher_steps,
        Some(2_000_000)
    );
}

#[test]
fn a_group_past_its_share_of_the_pool_is_incomplete_not_clean() {
    let (db, data) = one_group();
    assert!(matches!(
        verdict(&db, &data, Some(2_000_000)),
        Verdict::Clean
    ));
    // A pool of 256 steps, 8 for the group.
    let v = verdict(&db, &data, Some(1));
    assert!(incomplete(&v), "{v:?}");
}

/// The group that spends its share is the only one set aside: the pool is not
/// spent, and a body behind another anchor is still verified.
#[test]
fn a_group_past_its_share_leaves_the_pool_to_the_others() {
    let db =
        database("Exav.Test.Group:0:*:61616161*66666666\nExav.Test.Other:0:*:7a7a7a7a*79797979\n");
    let mut data = b"aaaa-".repeat(2000);
    data.extend(b"zzzz-yyyy");
    for steps in [Some(1), Some(2_000_000), None] {
        match verdict(&db, &data, steps) {
            Verdict::Infected { .. } => {}
            v => panic!("{steps:?}: {v:?}"),
        }
    }
}

#[test]
fn a_pool_that_runs_out_is_incomplete_not_clean() {
    let (db, data) = many_groups();
    assert!(matches!(
        verdict(&db, &data, Some(2_000_000)),
        Verdict::Clean
    ));
    let v = verdict(&db, &data, Some(1));
    assert!(incomplete(&v), "{v:?}");
}

#[test]
fn off_lifts_both_bounds() {
    for (db, data) in [one_group(), many_groups()] {
        assert!(incomplete(&verdict(&db, &data, Some(1))));
        assert!(matches!(verdict(&db, &data, None), Verdict::Clean));
    }
}
