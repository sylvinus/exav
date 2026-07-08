//! Integration test for the `--json` machine-readable output mode.

use std::process::Command;

fn exav() -> Command {
    Command::new(env!("CARGO_BIN_EXE_exav"))
}

const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

#[test]
fn json_output_is_valid_jsonl_with_expected_fields() {
    // Empty datadir -> only the builtin EICAR pattern loads (fast, no DB needed).
    let db = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
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

    // First: the EICAR detection.
    assert_eq!(objs[0]["category"], "infected");
    assert_eq!(objs[0]["status"], "FOUND");
    assert!(objs[0]["signature"].is_string());
    assert_eq!(objs[0]["method"], "pattern");

    // Second: the clean file.
    assert_eq!(objs[1]["category"], "clean");
    assert_eq!(objs[1]["status"], "OK");

    // Third: the summary.
    assert_eq!(objs[2]["summary"]["scanned"], 2);
    assert_eq!(objs[2]["summary"]["infected"], 1);

    // Exit code 1 = at least one detection (clamscan-compatible).
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn json_infected_only_suppresses_clean() {
    let db = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let eicar = files.path().join("eicar.txt");
    std::fs::write(&eicar, EICAR).unwrap();
    let clean = files.path().join("clean.txt");
    std::fs::write(&clean, b"benign\n").unwrap();

    let out = exav()
        .arg("-d")
        .arg(db.path())
        .arg("--json")
        .arg("--infected")
        .arg("--no-summary")
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
