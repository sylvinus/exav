//! A one-shot run that `--max-scan-secs` ends keeps the exit code of what it had
//! already found.
//!
//! The alarm ends the process from a signal handler, which can read nothing but
//! atomics. A fixed exit code there turned a run that had reported a detection
//! into a `3`, and `--partial-as` could not change it: the order the exit codes
//! are documented in (a detection, then an error, then a partial file) stopped
//! applying the moment the clock did.

#![cfg(unix)]

use std::process::{Command, Output};

#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

fn exav() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_exav"));
    c.env("EXAV_ALLOW_NO_DB", "1");
    c
}

/// A sparse file that takes seconds to scan and no disk.
fn slow(dir: &TempDir) -> std::path::PathBuf {
    let f = dir.path().join("zeros.bin");
    std::fs::File::create(&f).unwrap().set_len(4 << 30).unwrap();
    f
}

fn run(args: &[&str], paths: &[&std::path::Path]) -> Output {
    exav()
        .args(["--max-scan-secs", "1"])
        .args(args)
        .args(paths)
        .output()
        .unwrap()
}

#[test]
fn a_detection_already_reported_stays_a_one() {
    let dir = TempDir::new().unwrap();
    let hit = dir.path().join("a-eicar.txt");
    std::fs::write(&hit, exav_core::unpack::eicar()).unwrap();
    let zeros = slow(&dir);
    let o = run(&[], &[&hit, &zeros]);
    let out = String::from_utf8_lossy(&o.stdout);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(out.contains("FOUND"), "{out}{err}");
    assert!(
        err.contains("exceeded --max-scan-secs"),
        "the alarm did not end the run: {err}"
    );
    assert_eq!(o.status.code(), Some(1), "{out}{err}");
    // Whatever `--partial-as` says about the file that ran out of time.
    let o = run(&["--partial-as", "ok"], &[&hit, &zeros]);
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn an_error_already_reported_stays_a_two() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("not-there.txt");
    let zeros = slow(&dir);
    let o = run(&[], &[&missing, &zeros]);
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn the_file_that_ran_out_of_time_is_what_partial_as_says() {
    let dir = TempDir::new().unwrap();
    let zeros = slow(&dir);
    let by = |policy: &[&str]| run(policy, &[&zeros]).status.code();
    assert_eq!(by(&[]), Some(3));
    assert_eq!(by(&["--partial-as", "ok"]), Some(0));
    assert_eq!(by(&["--partial-as", "found"]), Some(1));
    assert_eq!(by(&["--partial-as", "error"]), Some(2));
    assert_eq!(by(&["--partial-as", "limits-exceeded=ok"]), Some(0));
}
