//! `--detect`: the heuristic detectors a default build carries run when asked.
//!
//! A detector compiled out of the binary accepts its flag and finds nothing, so
//! the only check that it is really there is a scan from outside.

use std::process::Command;

#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

/// A link whose text names one site and whose target is another.
#[test]
fn detect_phishing_runs_in_a_default_build() {
    let dir = TempDir::new().unwrap();
    let page = dir.path().join("mail.html");
    std::fs::write(
        &page,
        br#"<html><body><a href="http://evil.example/login">https://www.paypal.com/signin</a></body></html>"#,
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_exav"))
        .env("EXAV_ALLOW_NO_DB", "1")
        .args(["--detect", "phishing"])
        .arg(&page)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Heuristics.Phishing.Email.SpoofedDomain FOUND"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
