//! Integration test for the `--json` machine-readable output mode.

use std::process::Command;

// The binary's own temp-directory type, so the test suite needs no temp-file
// dependency either.
#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

fn exav() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_exav"));
    // These tests deliberately run against the built-in EICAR-only baseline (empty
    // `-d`); exav otherwise refuses to run with no real database.
    c.env("EXAV_ALLOW_NO_DB", "1");
    c
}

// `eicar_bytes`, not `eicar`: the tests below bind `eicar` to the path they
// write these bytes to, and a same-named function would be shadowed by it.
fn eicar_bytes() -> &'static [u8] {
    exav_core::unpack::eicar()
}

#[test]
fn json_output_is_valid_jsonl_with_expected_fields() {
    // Empty datadir -> only the builtin EICAR pattern loads (fast, no DB needed).
    let db = TempDir::new().unwrap();
    let files = TempDir::new().unwrap();
    let eicar = files.path().join("eicar.txt");
    std::fs::write(&eicar, eicar_bytes()).unwrap();
    let clean = files.path().join("clean.txt");
    std::fs::write(&clean, b"nothing bad in here\n").unwrap();

    let out = exav()
        .arg("-d")
        .arg(db.path())
        .arg("--json")
        .arg(&eicar)
        .arg(&clean)
        .output()
        .expect("run exav");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    // Two result objects + one summary object.
    assert_eq!(lines.len(), 3, "stdout was:\n{stdout}");

    let objs: Vec<serde_json::Value> = lines
        .iter()
        .map(|l| serde_json::from_str(l).expect("each line is valid JSON"))
        .collect();

    // First: the EICAR detection. `status` is the same word the human line ends
    // with, and `category` is absent — it sub-classifies a PARTIAL and there is
    // nothing to sub-classify here.
    assert_eq!(objs[0]["status"], "FOUND");
    assert!(objs[0]["category"].is_null());
    assert!(objs[0]["signature"].is_string());
    assert_eq!(objs[0]["method"], "pattern");

    // Second: the clean file.
    assert_eq!(objs[1]["status"], "OK");
    assert!(objs[1]["category"].is_null());

    // Third: the summary.
    assert_eq!(objs[2]["summary"]["scanned"], 2);
    assert_eq!(objs[2]["summary"]["infected"], 1);

    // Exit code 1 = at least one detection (clamscan-compatible).
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn json_infected_only_suppresses_clean() {
    let db = TempDir::new().unwrap();
    let files = TempDir::new().unwrap();
    let eicar = files.path().join("eicar.txt");
    std::fs::write(&eicar, eicar_bytes()).unwrap();
    let clean = files.path().join("clean.txt");
    std::fs::write(&clean, b"benign\n").unwrap();

    let out = exav()
        .arg("-d")
        .arg(db.path())
        .arg("--json")
        // `--quiet` is the whole output dial: it suppresses the clean records
        // and the summary together.
        .arg("--quiet")
        .arg(&eicar)
        .arg(&clean)
        .output()
        .expect("run exav");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "only the infected file should print: {stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(v["status"], "FOUND");
}

/// `--all-matches` must not answer `OK` for a file `--max-input-bytes` says was
/// never fully examined.
///
/// The all-match engine entry takes bytes rather than a file, so it cannot see
/// the ceiling; the CLI has to route an over-limit file to the single-match path,
/// which enforces it. Without that, adding a flag about *how many signatures to
/// report* silently turns a `PARTIAL` into a clean pass — the exact failure the
/// never-a-silent-clean invariant exists to prevent, and one no signature change
/// would ever reveal.
#[test]
fn all_matches_still_reports_a_file_past_the_size_ceiling() {
    let db = TempDir::new().unwrap();
    let files = TempDir::new().unwrap();
    let big = files.path().join("big.bin");
    std::fs::write(&big, vec![b'a'; 3 * 1024 * 1024]).unwrap();

    let mut seen = Vec::new();
    for extra in [&[][..], &["--all-matches"][..]] {
        let out = exav()
            .arg("-d")
            .arg(db.path())
            .arg("--json")
            .arg("--max-input-bytes")
            .arg("1M")
            .args(extra)
            .arg(&big)
            .output()
            .expect("run exav");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let first = stdout.lines().next().unwrap_or_default().to_string();
        let v: serde_json::Value = serde_json::from_str(&first).expect(&first);
        seen.push((
            out.status.code(),
            v["status"].clone(),
            v["category"].clone(),
        ));
    }
    assert_eq!(
        seen[0], seen[1],
        "--all-matches must give the same answer as a single-match scan"
    );
    assert_eq!(seen[0].1, "PARTIAL");
    assert_eq!(seen[0].2, "LIMITS-EXCEEDED");
    assert_eq!(seen[0].0, Some(3));
}

/// `--profile` must not change the answer, only add timings beside it.
///
/// It prints a CSV row and returns before the reporting path where every other
/// mode applies `--partial-as`, so the policy has to be applied there too.
/// Without that, asking for over-limit files to pass still exits 3 under
/// `--profile` — a flag about *where the time went* silently overriding a flag
/// about *what the verdict is*, in the direction a CI gate would notice only by
/// failing.
#[test]
fn profile_reports_the_same_verdict_as_a_plain_scan() {
    let db = TempDir::new().unwrap();
    let files = TempDir::new().unwrap();
    let big = files.path().join("big.bin");
    std::fs::write(&big, vec![b'a'; 3 * 1024 * 1024]).unwrap();

    // The CSV `verdict` column against the exit code the same policy produces
    // without `--profile`: partial keeps it, `ok` passes it, `error` fails it.
    for (policy, exit, column) in [
        ("partial", 3, "limits"),
        ("ok", 0, "clean"),
        ("error", 2, "limits"),
        ("found", 1, "infected"),
    ] {
        let run = |extra: &[&str]| {
            exav()
                .arg("-d")
                .arg(db.path())
                .arg("--max-input-bytes")
                .arg("1M")
                .arg("--partial-as")
                .arg(policy)
                .args(extra)
                .arg(&big)
                .output()
                .expect("run exav")
        };
        let plain = run(&[]);
        let profiled = run(&["--profile"]);
        assert_eq!(
            profiled.status.code(),
            plain.status.code(),
            "--partial-as {policy}: --profile changed the exit code"
        );
        assert_eq!(
            plain.status.code(),
            Some(exit),
            "--partial-as {policy}: unexpected exit code"
        );

        // Row after the header; `verdict` is the third column.
        let stdout = String::from_utf8_lossy(&profiled.stdout);
        let row = stdout.lines().nth(1).unwrap_or_default().to_string();
        assert_eq!(
            row.split(',').nth(2),
            Some(column),
            "--partial-as {policy}: CSV verdict column disagrees with the policy"
        );
    }
}

/// A detection does not mean the search finished. In `--all-matches` the status
/// word is `FOUND`, which cannot also say `PARTIAL`, so an incomplete search has
/// to be reported alongside the detections instead of replacing them — on its
/// own line in the normal grammar, and as `partial`/`partial_reasons` in JSON.
///
/// Before this, the all-match path discarded the outcome whenever it had
/// detections, so a truncated scan was indistinguishable from a complete one.
#[test]
fn all_matches_reports_an_incomplete_search_alongside_detections() {
    let db = TempDir::new().unwrap();
    // `Test.Hit` is the detection. `Test.Wild` exists to burn the per-group
    // step budget: its anchor repeats tens of thousands of times and the tail it
    // searches for is never present, so every hit scans to the end of the file.
    std::fs::write(
        db.path().join("t.ndb"),
        "Test.Hit:0:*:4558415654455354\nTest.Wild:0:*:51574552*5a584356\n",
    )
    .unwrap();
    let files = TempDir::new().unwrap();
    let sample = files.path().join("sample.bin");
    let mut data = b"EXAVTEST".to_vec();
    data.extend(std::iter::repeat_n(*b"QWER", 50_000).flatten());
    std::fs::write(&sample, &data).unwrap();

    let run = |cap: Option<&str>, json: bool| {
        let mut c = exav();
        c.arg("-d").arg(db.path()).arg("--all-matches");
        if json {
            c.arg("--json");
        }
        if let Some(cap) = cap {
            // Forces the repeated-anchor cap to refuse the group after its first
            // charged verify, which is what flags the search truncated.
            c.env("EXAV_MAX_GROUP_STEPS", cap);
        }
        c.arg(&sample).output().expect("run exav")
    };

    // Search completes: the detection stands alone, with nothing added.
    let out = run(None, false);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Test.Hit FOUND"), "{text}");
    assert!(
        !text.contains("PARTIAL"),
        "a complete search must not be reported partial: {text}"
    );
    assert_eq!(out.status.code(), Some(1));

    // Search truncated: the detection still stands, and the incompleteness is
    // reported next to it in the `[reason ][CATEGORY ]STATUS` grammar.
    let out = run(Some("1"), false);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Test.Hit FOUND"), "{text}");
    let partial = text
        .lines()
        .find(|l| l.ends_with("PARTIAL"))
        .unwrap_or_else(|| panic!("no PARTIAL line: {text}"));
    assert!(
        partial.ends_with("LIMITS-EXCEEDED PARTIAL"),
        "category must precede the status word: {partial}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "a confirmed detection still decides the exit code"
    );

    // Same thing in JSON, as fields rather than a second record.
    let out = run(Some("1"), true);
    let text = String::from_utf8_lossy(&out.stdout);
    let row: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(row["status"], "FOUND");
    assert_eq!(row["partial"], true);
    assert!(
        row["partial_reasons"]
            .as_array()
            .is_some_and(|r| !r.is_empty()),
        "partial_reasons must name the cause: {row}"
    );
    // And absent, not false, when the search finished.
    let out = run(None, true);
    let text = String::from_utf8_lossy(&out.stdout);
    let row: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert!(row.get("partial").is_none(), "{row}");
    assert!(row.get("partial_reasons").is_none(), "{row}");
}
