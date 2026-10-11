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

/// Stdin and a FIFO are counted, profiled and bounded by `--max-process-bytes`
/// as the same bytes in a file are.
#[test]
fn stdin_is_counted_profiled_and_bounded_as_a_file_is() {
    let sigs = sig_dir();
    let mut blob = PAYLOAD.to_vec();
    blob.extend(vec![b'.'; 1 << 20]);

    // The summary, less the time it took.
    let summary = |out: &str| -> Vec<String> {
        out.lines()
            .skip_while(|l| !l.contains("SCAN SUMMARY"))
            .filter(|l| !l.starts_with("Time:"))
            .map(str::to_string)
            .collect()
    };
    let runs = cli_verdicts(sigs.path(), &blob, &[]);
    let file = summary(&runs[0].2);
    assert!(
        file.iter().any(|l| l == "Data scanned: 1.00 MB"),
        "{file:?}"
    );
    for (how, _, out) in &runs[1..] {
        assert_eq!(summary(out), file, "{how}");
    }

    // The CSV row, less its name and its timings.
    let row = |out: &str| -> Vec<String> {
        let mut lines = out.lines();
        let (head, row) = (lines.next().unwrap_or(""), lines.next().unwrap_or(""));
        head.split(',')
            .zip(row.split(','))
            .filter(|(h, _)| *h != "file" && !h.ends_with("_us"))
            .map(|(h, v)| format!("{h}={v}"))
            .collect()
    };
    let runs = cli_verdicts(sigs.path(), &blob, &["--profile"]);
    let file = row(&runs[0].2);
    assert!(file.iter().any(|c| c == "verdict=infected"), "{file:?}");
    for (how, _, out) in &runs[1..] {
        assert_eq!(row(out), file, "{how}: {out}");
    }

    // A PE larger than the quarter of 128M a scan may hold in one object.
    let mut pe = vec![0u8; 40 << 20];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    pe[0x44..0x46].copy_from_slice(&0x14cu16.to_le_bytes());
    for (how, code, out) in cli_verdicts(sigs.path(), &pe, &["--max-process-bytes", "128M"]) {
        assert!(out.contains("deep-analysis limit"), "{how}: {out}");
        assert_eq!(code, 3, "{how}: {out}");
    }
    // The cap is what made it a limit.
    for (how, code, out) in cli_verdicts(sigs.path(), &pe, &[]) {
        assert_eq!(code, 0, "{how}: {out}");
    }
}

/// All-match over an object past `--max-object-bytes` still lists every
/// detection, from the CLI on every entry point and from `ALLMATCHSCAN`.
#[test]
fn all_matches_lists_every_detection_past_the_object_limit() {
    let sigs = sig_dir();
    let mut blob = PAYLOAD.to_vec();
    blob.extend(vec![b'.'; 512 * 1024]);
    blob.extend_from_slice(PAYLOAD2);
    let limit = ["--max-object-bytes", "64K"];
    let found = |out: &str| -> Vec<String> {
        let mut v: Vec<String> = out
            .lines()
            .filter_map(|l| {
                l.strip_suffix(" FOUND")?
                    .rsplit_once(": ")
                    .map(|(_, s)| s.to_string())
            })
            .collect();
        v.sort();
        v
    };
    for (how, code, out) in cli_verdicts(
        sigs.path(),
        &blob,
        &[&limit[..], &["--all-matches"]].concat(),
    ) {
        assert_eq!(
            found(&out),
            ["Exav.Test.Wild", "Exav.Test.Wild2"],
            "{how}: {out}"
        );
        assert_eq!(code, 1, "{how}: {out}");
    }

    let d = Daemon::start(sigs.path(), &limit);
    let f = d._dir.path().join("two.bin");
    std::fs::write(&f, &blob).unwrap();
    let mut s = std::os::unix::net::UnixStream::connect(&d.sock).unwrap();
    s.write_all(format!("zALLMATCHSCAN {}\0", f.display()).as_bytes())
        .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let out = String::from_utf8_lossy(&out).replace('\0', "\n");
    assert_eq!(found(&out), ["Exav.Test.Wild", "Exav.Test.Wild2"], "{out}");
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
