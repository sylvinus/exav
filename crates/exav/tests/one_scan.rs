//! One object, one answer, whichever way it reaches exav: a file path, stdin,
//! a FIFO, `INSTREAM` or `EXINSTREAM`.
//!
//! The signatures are wildcard ones, which only the full engine matches; the
//! constant-memory literal pass cannot carry them. A verdict that depends on
//! the entry point shows up as one of these inputs missing the match.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

const SIGS: &str = "Exav.Test.Wild:0:*:57494c44??4f4e45\nExav.Test.Wild2:0:*:5345434f??44\n";

/// Matches `Exav.Test.Wild`.
const PAYLOAD: &[u8] = b"WILD-ONE";
/// Matches `Exav.Test.Wild2`.
const PAYLOAD2: &[u8] = b"SECO-D";

fn sig_dir() -> TempDir {
    let d = TempDir::new().unwrap();
    std::fs::write(d.path().join("t.ndb"), SIGS).unwrap();
    d
}

fn exav(sigs: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_exav"));
    c.arg("-d").arg(sigs);
    c
}

/// Exit code and stdout of one run.
fn run(mut c: Command, stdin: Option<&[u8]>) -> (i32, String) {
    c.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    let mut child = c.spawn().unwrap();
    if let Some(bytes) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        let bytes = bytes.to_vec();
        std::thread::spawn(move || {
            let _ = pipe.write_all(&bytes);
        });
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// The verdict word of every way the CLI can be handed `blob`.
fn cli_verdicts(sigs: &Path, blob: &[u8], args: &[&str]) -> Vec<(&'static str, i32, String)> {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("input");
    std::fs::write(&file, blob).unwrap();

    let mut by_path = exav(sigs);
    by_path.args(args).arg(&file);
    let mut by_stdin = exav(sigs);
    by_stdin.args(args).arg("-");

    let fifo = dir.path().join("fifo");
    let made = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(made.success());
    let writer = {
        let fifo = fifo.clone();
        let blob = blob.to_vec();
        std::thread::spawn(move || {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&fifo) {
                let _ = f.write_all(&blob);
            }
        })
    };
    let mut by_fifo = exav(sigs);
    by_fifo.args(args).arg(&fifo);

    let mut out = Vec::new();
    for (how, cmd, input) in [
        ("path", by_path, None),
        ("stdin", by_stdin, Some(blob)),
        ("fifo", by_fifo, None),
    ] {
        let (code, stdout) = run(cmd, input);
        out.push((how, code, stdout));
    }
    let _ = writer.join();
    out
}

/// A daemon on a socket of its own.
struct Daemon {
    child: Child,
    sock: PathBuf,
    _dir: TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn start(sigs: &Path, args: &[&str]) -> Self {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("d.sock");
        let child = exav(sigs)
            .arg("--listen")
            .arg(format!("clamd://{}", sock.display()))
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while std::os::unix::net::UnixStream::connect(&sock).is_err() {
            assert!(Instant::now() < deadline, "the daemon never answered");
            std::thread::sleep(Duration::from_millis(50));
        }
        Self {
            child,
            sock,
            _dir: dir,
        }
    }

    fn stream(&self, verb: &str, blob: &[u8]) -> String {
        let mut s = std::os::unix::net::UnixStream::connect(&self.sock).unwrap();
        s.write_all(format!("z{verb}\0").as_bytes()).unwrap();
        for c in blob.chunks(64 * 1024) {
            s.write_all(&(c.len() as u32).to_be_bytes()).unwrap();
            s.write_all(c).unwrap();
        }
        s.write_all(&0u32.to_be_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out)
            .trim_end_matches('\0')
            .to_string()
    }
}

/// Over `--max-input-bytes` with the payload inside the limit: found, by the
/// full engine, on every entry point. With it past the limit: the limit, on
/// every entry point.
#[test]
fn every_entry_point_scans_the_start_of_an_oversize_input_the_same_way() {
    let sigs = sig_dir();
    let limit = ["--max-input-bytes", "1K"];

    let mut inside = PAYLOAD.to_vec();
    inside.extend(vec![b'.'; 64 * 1024]);
    for (how, code, out) in cli_verdicts(sigs.path(), &inside, &limit) {
        assert!(out.contains("Exav.Test.Wild FOUND"), "{how}: {out}");
        assert_eq!(code, 1, "{how}: {out}");
    }

    let mut past = vec![b'.'; 64 * 1024];
    past.extend_from_slice(PAYLOAD);
    for (how, code, out) in cli_verdicts(sigs.path(), &past, &limit) {
        assert!(out.contains("LIMITS-EXCEEDED"), "{how}: {out}");
        assert_eq!(code, 3, "{how}: {out}");
    }

    let d = Daemon::start(sigs.path(), &limit);
    let line = d.stream("INSTREAM", &inside);
    assert_eq!(line, "stream: Exav.Test.Wild FOUND");
    let json = d.stream("EXINSTREAM", &inside);
    assert!(json.contains("Exav.Test.Wild"), "{json}");
    let line = d.stream("INSTREAM", &past);
    assert!(line.contains("max-input-bytes"), "{line}");
    assert!(line.ends_with("LIMITS-EXCEEDED ERROR"), "{line}");
}

/// Options that only the file path used to honour reach stdin too.
#[test]
fn stdin_gets_the_options_a_file_gets() {
    let sigs = sig_dir();
    let mut both = PAYLOAD.to_vec();
    both.extend_from_slice(b" and ");
    both.extend_from_slice(PAYLOAD2);
    for (how, code, out) in cli_verdicts(sigs.path(), &both, &["--all-matches"]) {
        assert!(
            out.contains("Exav.Test.Wild") && out.contains("Exav.Test.Wild2"),
            "{how}: {out}"
        );
        assert_eq!(code, 1, "{how}: {out}");
    }
}
