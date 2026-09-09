//! `exav … | head` ends quietly, the way every other Unix filter does.
//!
//! Rust's runtime ignores `SIGPIPE` before `main`, so a write to a closed pipe
//! comes back as `EPIPE` and `println!` panics on it. Left alone, that prints a
//! Rust backtrace at anyone who piped exav into `head`, `grep -q`, or a shell
//! that stopped reading — all completely ordinary things to do, and one of them
//! is on the front page of the README.
//!
//! The listeners need the opposite disposition, so [`daemon_client`] and the
//! ICAP suite cover the other half: a client hanging up costs one connection,
//! not the daemon.

#![cfg(unix)]

use std::io::Read;
use std::process::{Command, Stdio};

// The binary's own temp-directory type, so the test suite needs no temp-file
// dependency either.
#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

/// Enough files that exav is still writing when the reader goes away. One file
/// would be written, flushed and finished before the pipe ever closed, and the
/// test would pass against the broken behaviour too.
const FILES: usize = 500;

/// Scan a directory, close the pipe after the first line, and return exav's
/// stderr.
fn scan_into_a_closed_pipe() -> String {
    let dir = TempDir::new().unwrap();
    for i in 0..FILES {
        std::fs::write(dir.path().join(format!("f{i}.txt")), b"nothing here\n").unwrap();
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_exav"))
        .arg("--allow-no-db")
        .arg(dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start exav");

    // Read one line, then drop the pipe — which is what `head -1` does.
    let mut out = child.stdout.take().expect("stdout");
    let mut byte = [0u8; 1];
    while out.read(&mut byte).unwrap_or(0) == 1 && byte[0] != b'\n' {}
    drop(out);

    let mut err = String::new();
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut err)
        .unwrap();
    let _ = child.wait();
    err
}

#[test]
fn a_closed_pipe_is_not_a_panic() {
    let err = scan_into_a_closed_pipe();
    assert!(
        !err.contains("panicked"),
        "exav panicked when its reader went away:\n{err}"
    );
    assert!(
        !err.contains("Broken pipe"),
        "a closed pipe is how `head` says it has enough, not an error to report:\n{err}"
    );
}
