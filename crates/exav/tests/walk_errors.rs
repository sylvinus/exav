//! A tree the scanner could not fully read is never reported as clean.
//!
//! An unreadable directory is the quietest way to lose files: the walk yields an
//! error instead of entries, and an error that is dropped leaves a run that
//! reports on what it reached and exits 0. To an operator, and to a pipeline
//! reading the exit code, that is indistinguishable from a tree with nothing
//! wrong in it, even when the part nobody could open holds the malware.
//!
//! Every surface that walks a tree goes through one walker, so this pins the
//! contract at the surface an operator actually runs.

use std::process::Command;

#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

fn exav() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_exav"));
    // The built-in EICAR-only baseline is enough here: this is about which files
    // are reached, not about what the signatures say.
    c.env("EXAV_ALLOW_NO_DB", "1");
    c
}

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

/// Returns `None` when the platform or the test environment cannot make a
/// directory unreadable: running as root defeats mode 0, and non-Unix has no
/// equivalent. Skipping beats asserting something the environment cannot show.
#[cfg(unix)]
fn unreadable_tree() -> Option<TempDir> {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().ok()?;
    let readable = dir.path().join("readable");
    let secret = dir.path().join("secret");
    std::fs::create_dir_all(&readable).ok()?;
    std::fs::create_dir_all(&secret).ok()?;
    std::fs::write(readable.join("ordinary.txt"), b"nothing here").ok()?;
    std::fs::write(secret.join("payload.com"), eicar()).ok()?;
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).ok()?;
    // Confirm the environment actually enforces it.
    if std::fs::read_dir(&secret).is_ok() {
        let _ = std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o755));
        return None;
    }
    Some(dir)
}

#[cfg(unix)]
#[test]
fn an_unreadable_subdirectory_is_reported_and_fails_the_run() {
    use std::os::unix::fs::PermissionsExt;
    let Some(dir) = unreadable_tree() else {
        eprintln!("skipped: this environment cannot make a directory unreadable");
        return;
    };

    let out = exav().arg(dir.path()).output().expect("run exav");

    // Restore before any assertion can unwind, so the temp dir can be removed.
    let _ = std::fs::set_permissions(
        dir.path().join("secret"),
        std::fs::Permissions::from_mode(0o755),
    );

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert_ne!(
        out.status.code(),
        Some(0),
        "a tree with an unreadable subdirectory exited 0. Files in it were never \
         opened, so this reports clean over bytes nobody looked at.\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("secret") && stderr.contains("ERROR"),
        "the unreadable path must be named. Without it an operator cannot tell \
         which part of the tree went unscanned.\n--- stderr ---\n{stderr}"
    );
    // The counterweight: the reachable part is still scanned and reported.
    assert!(
        stdout.contains("ordinary.txt"),
        "the readable file must still be scanned\n--- stdout ---\n{stdout}"
    );
}

/// `--quiet` drops the `OK` lines and the summary, never an error, and an error
/// reaches `--log` as a detection does.
#[test]
fn an_error_is_printed_under_quiet_and_logged() {
    let dir = TempDir::new().expect("temp dir");
    let log = dir.path().join("scan.log");
    let missing = dir.path().join("missing.bin");
    let out = exav()
        .arg("--quiet")
        .arg("--log")
        .arg(&log)
        .arg(&missing)
        .output()
        .expect("run exav");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("missing.bin") && stderr.contains("ERROR"),
        "{stderr}"
    );
    let logged = std::fs::read_to_string(&log).expect("read the log");
    assert!(
        logged.contains("missing.bin") && logged.contains("ERROR"),
        "{logged}"
    );
}

/// A URL this run will not scan (no `--allow-http-scan`, or a build without
/// `http-scan`) is an error like any other: logged, and a JSON record.
#[test]
fn a_refused_url_is_logged_and_reported_in_json() {
    let dir = TempDir::new().expect("temp dir");
    let log = dir.path().join("scan.log");
    let url = "https://example.invalid/sample.bin";
    let out = exav()
        .args(["--json", "--log"])
        .arg(&log)
        .arg(url)
        .output()
        .expect("run exav");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(2), "{stdout}");
    assert!(
        stdout.contains(url) && stdout.contains(r#""status":"ERROR""#),
        "{stdout}"
    );
    let out = exav()
        .arg("--log")
        .arg(&log)
        .arg(url)
        .output()
        .expect("run exav");
    assert_eq!(out.status.code(), Some(2));
    let logged = std::fs::read_to_string(&log).expect("read the log");
    assert!(logged.contains(url) && logged.contains("ERROR"), "{logged}");
}

/// The summary counts a file not fully examined as partial, not as an error:
/// the two exit differently, and the summary has to agree with the exit code.
#[test]
fn the_summary_counts_a_partial_file_apart_from_errors() {
    let dir = TempDir::new().expect("temp dir");
    let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    gz.extend_from_slice(&[0xff; 64]);
    std::fs::write(dir.path().join("damaged.gz"), gz).expect("write");
    let out = exav().arg(dir.path()).output().expect("run exav");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(3), "{stdout}");
    assert!(stdout.contains("Partial files: 1"), "{stdout}");
    assert!(!stdout.contains("Total errors"), "{stdout}");
}

/// The counterweight to the above: a tree with nothing wrong still exits 0.
/// A test that only checks the failure direction is satisfied by a scanner that
/// always fails.
#[test]
fn a_fully_readable_tree_still_exits_zero() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
    std::fs::write(dir.path().join("sub/a.txt"), b"nothing here").expect("write");

    let out = exav().arg(dir.path()).output().expect("run exav");

    assert_eq!(
        out.status.code(),
        Some(0),
        "a clean, fully readable tree must exit 0\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
