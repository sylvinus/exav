//! `exav DIR` scans the directory's immediate files; `exav -r DIR` descends.
//!
//! `clamscan DIR` is a working command line: it scans the files in DIR and
//! leaves the subdirectories alone. Every expectation below was checked against
//! ClamAV 1.4.3 on the same trees — a clean directory exits 0 having scanned one
//! directory and its files, an infected one exits 1, and neither reads a
//! subdirectory without `-r`.

use std::process::Command;

// The binary's own temp-directory type, so the test suite needs no temp-file
// dependency either.
#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

fn exav() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_exav"));
    // Deliberately the built-in EICAR-only baseline (empty `-d`); exav otherwise
    // refuses to run with no real database.
    c.env("EXAV_ALLOW_NO_DB", "1");
    c
}

/// A tree with one clean file beside one infected file in a subdirectory:
/// without `-r` only the first is reachable, with `-r` both are.
fn tree() -> (TempDir, TempDir) {
    let db = TempDir::new().unwrap();
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("clean.txt"), b"nothing bad here\n").unwrap();
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("deep.txt"), EICAR).unwrap();
    (db, dir)
}

/// Scan `dir` with the given extra flags; returns (exit code, stdout).
fn scan(db: &TempDir, dir: &TempDir, args: &[&str]) -> (i32, String) {
    let out = exav()
        .arg("-d")
        .arg(db.path())
        .args(args)
        .arg(dir.path())
        .output()
        .expect("run exav");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn a_named_directory_is_scanned_all_the_way_down() {
    // Naming a directory means the directory. Scanning only its top level —
    // which is what `clamscan` does, and what exav used to — reports a subset as
    // though it were the whole thing: the files never opened are, in the output,
    // indistinguishable from the ones that were fine.
    let (db, dir) = tree();
    let (code, stdout) = scan(&db, &dir, &[]);
    assert!(
        stdout.contains("clean.txt: OK"),
        "the directory's own files are scanned: {stdout}"
    );
    assert!(
        stdout.contains("deep.txt"),
        "and so are the ones below it: {stdout}"
    );
    assert!(
        stdout.contains("Scanned directories: 2"),
        "both directories were descended into: {stdout}"
    );
    assert!(
        stdout.contains("Scanned files: 2"),
        "both files were there to scan: {stdout}"
    );
    // The fixture's only infected file is the one in the subdirectory, so the
    // exit code is itself the evidence that the descent happened.
    assert!(
        stdout.contains("deep.txt: Eicar-Test-Signature FOUND"),
        "{stdout}"
    );
    assert_eq!(
        code, 1,
        "the detection below the top level counts: {stdout}"
    );
}

#[test]
fn an_infected_file_in_the_directory_itself_exits_1() {
    let (db, dir) = tree();
    std::fs::write(dir.path().join("bad.txt"), EICAR).unwrap();
    let (code, stdout) = scan(&db, &dir, &[]);
    assert!(
        stdout.contains("bad.txt: Eicar-Test-Signature FOUND"),
        "{stdout}"
    );
    assert_eq!(code, 1, "a detection exits 1, as clamscan does: {stdout}");
}

#[test]
fn no_recursive_stops_at_the_top_level() {
    let (db, dir) = tree();
    let (code, stdout) = scan(&db, &dir, &["--no-recursive"]);
    assert!(
        stdout.contains("clean.txt: OK"),
        "the directory's own files are still scanned: {stdout}"
    );
    assert!(
        !stdout.contains("deep.txt"),
        "the subdirectory is left alone: {stdout}"
    );
    assert!(
        stdout.contains("Scanned directories: 1"),
        "the named directory counts, the one below it does not: {stdout}"
    );
    assert_eq!(
        code, 0,
        "the infected file below was never opened, so nothing was found: {stdout}"
    );
}

/// The filters apply to the immediate files too — the walk is the same walk,
/// and a directory scanned under `--exclude` that ignored it would scan more
/// than was asked for.
#[test]
fn exclude_applies_at_the_top_level_too() {
    let (db, dir) = tree();
    std::fs::write(dir.path().join("bad.txt"), EICAR).unwrap();
    // `--no-recursive` so the fixture's own infected file below is out of the
    // way and this test is about the filter and nothing else.
    let (code, stdout) = scan(&db, &dir, &["--no-recursive", "--exclude", "bad"]);
    assert!(!stdout.contains("bad.txt"), "{stdout}");
    assert!(stdout.contains("clean.txt: OK"), "{stdout}");
    assert_eq!(code, 0, "{stdout}");
}

/// An empty directory is a scan of nothing, not an error: clamscan reports zero
/// files and exits 0.
#[test]
fn an_empty_directory_is_clean() {
    let db = TempDir::new().unwrap();
    let dir = TempDir::new().unwrap();
    let (code, stdout) = scan(&db, &dir, &[]);
    assert!(stdout.contains("Scanned files: 0"), "{stdout}");
    assert_eq!(code, 0, "{stdout}");
}
