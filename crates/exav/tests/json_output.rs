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

const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

#[test]
fn json_output_is_valid_jsonl_with_expected_fields() {
    // Empty datadir -> only the builtin EICAR pattern loads (fast, no DB needed).
    let db = TempDir::new().unwrap();
    let files = TempDir::new().unwrap();
    let eicar = files.path().join("eicar.txt");
    std::fs::write(&eicar, EICAR).unwrap();
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
    std::fs::write(&eicar, EICAR).unwrap();
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
