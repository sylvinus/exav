//! The daemon's socket permissions, and what a client can send it.
//!
//! Everything here runs a real daemon over a real Unix socket, because that is
//! where these answers live: the mode a socket ends up with, which verb the
//! daemon was asked, and what it wrote to its log are all observable only from
//! outside the process.
//!
//! The client expectations were checked against ClamAV 1.4.3's `clamdscan`
//! against this same daemon (`clamdscan -c <conf> --stream|--fdpass|-`, whose
//! two transports exav spells `--send-as contents|fd`), which
//! speaks the protocol the tests exercise. `clamd` itself is not installed, so
//! the daemon side of `LocalSocketMode` is read from `clamd.conf.sample`
//! (`Default: disabled (socket is world accessible)`) rather than run.

#![cfg(unix)]

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// The binary's own temp-directory type, so the test suite needs no temp-file
// dependency either.
#[path = "../src/tmpfile.rs"]
mod tmpfile;
use tmpfile::TempDir;

fn eicar() -> &'static [u8] {
    exav_core::unpack::eicar()
}

fn exav_bin() -> &'static str {
    env!("CARGO_BIN_EXE_exav")
}

fn exav() -> Command {
    let mut c = Command::new(exav_bin());
    // Deliberately the built-in EICAR-only baseline (empty `-d`); exav otherwise
    // refuses to run with no real database.
    c.env("EXAV_ALLOW_NO_DB", "1");
    c
}

/// A running daemon, stopped when the test drops it.
struct Daemon {
    child: Child,
    sock: PathBuf,
    _db: TempDir,
    dir: TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    /// Start a daemon on a socket of its own, under process umask `umask`.
    ///
    /// The umask is set by the shell that execs the binary: it is what an
    /// operator's environment supplies, and the socket's permissions must come
    /// from the address's `?mode=` rather than from it.
    fn start(umask: &str, extra: &[&str]) -> Daemon {
        Self::start_mode(umask, None, extra)
    }

    /// [`Daemon::start`] with an explicit `?mode=` on the listen address.
    fn start_mode(umask: &str, mode: Option<&str>, extra: &[&str]) -> Daemon {
        let db = TempDir::new().unwrap();
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("d.sock");
        let listen = match mode {
            Some(m) => format!("clamd://{}?mode={m}", sock.display()),
            None => format!("clamd://{}", sock.display()),
        };
        // `"$@"` hands the arguments through unchanged, so no path here is
        // parsed by the shell.
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(format!("umask {umask}; exec \"$@\""))
            .arg("sh")
            .arg(exav_bin())
            .arg("-d")
            .arg(db.path())
            .arg("--listen")
            .arg(&listen)
            .args(extra)
            .env("EXAV_ALLOW_NO_DB", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = cmd.spawn().expect("start the daemon");
        let d = Daemon {
            child,
            sock,
            _db: db,
            dir,
        };
        d.wait_until_answering();
        d
    }

    /// Block until the daemon answers on its socket. A connection refused (or
    /// denied, in the moment between `bind` and the mode being set) means it is
    /// not up yet.
    fn wait_until_answering(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if std::os::unix::net::UnixStream::connect(&self.sock).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the daemon never answered on {}", self.sock.display());
    }

    fn mode(&self) -> u32 {
        std::fs::metadata(&self.sock)
            .expect("the socket exists")
            .permissions()
            .mode()
            & 0o777
    }

    /// Run a client against this daemon; returns (exit code, stdout).
    fn client(&self, args: &[&str], paths: &[&Path]) -> (i32, String) {
        let out = exav()
            .arg("--connect")
            .arg(&self.sock)
            .args(args)
            .args(paths)
            .output()
            .expect("run the client");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    /// A file inside this daemon's own temp directory.
    fn file(&self, name: &str, body: &[u8]) -> PathBuf {
        let p = self.dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p
    }
}

/// A tree of three files, one of them EICAR, one of them a level down: enough
/// for "the answer covers every file" and "the walk descends" to be separate
/// observations.
fn infected_tree() -> TempDir {
    let t = TempDir::new().unwrap();
    std::fs::write(t.path().join("clean.txt"), b"nothing here\n").unwrap();
    std::fs::write(t.path().join("eicar.com"), eicar()).unwrap();
    std::fs::create_dir(t.path().join("sub")).unwrap();
    std::fs::write(t.path().join("sub/deep.txt"), b"nothing here\n").unwrap();
    t
}

/// The verdict lines of a client run, sorted. Two runs that scanned the same
/// files agree here whatever order the walk produced them in.
fn verdicts(stdout: &str) -> Vec<String> {
    let mut v: Vec<String> = stdout
        .lines()
        .filter(|l| l.ends_with(": OK") || l.contains(" FOUND") || l.ends_with("ERROR"))
        .map(str::to_string)
        .collect();
    v.sort();
    v
}

/// One counter out of the client's summary block, e.g. `Scanned files:`.
fn summary_count(stdout: &str, field: &str) -> u64 {
    stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix(field))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("no `{field}` in the summary: {stdout}"))
}

/// The socket is the daemon's front door. Left readable and writable by every
/// local user, it lets any of them submit scan jobs and read the verdicts, so
/// owner-only is the default and widening it is an explicit act.
#[test]
fn the_socket_is_owner_only_by_default() {
    // Under a umask that grants everything, so the mode can only come from the
    // daemon's own decision.
    let d = Daemon::start("000", &[]);
    assert_eq!(
        d.mode(),
        0o600,
        "with no ?mode= on the address the socket must be owner-only whatever the umask"
    );
}

/// `?mode=` is what a clamd deployment expresses as `LocalSocketMode`: the
/// milter or web server under another UID has to be able to connect.
#[test]
fn socket_mode_sets_the_mode_whatever_the_umask() {
    // A permissive umask must not widen it, and a restrictive one must not
    // narrow it: the flag is the answer in both directions. Creating the socket
    // under a umask of 0777 is what keeps it from ever existing at 0666 in the
    // window before its mode is set.
    for umask in ["000", "077"] {
        let d = Daemon::start_mode(umask, Some("660"), &[]);
        assert_eq!(
            d.mode(),
            0o660,
            "umask {umask}: the socket mode is the one asked for"
        );
    }
}

/// The thread model (`--workers 0`) binds its socket in a different place from
/// the prefork supervisor. Both are front doors.
#[test]
fn the_thread_model_socket_is_permissioned_too() {
    let d = Daemon::start_mode("000", Some("660"), &["--workers", "threads"]);
    assert_eq!(d.mode(), 0o660);
    let d = Daemon::start("000", &["--workers", "threads"]);
    assert_eq!(d.mode(), 0o600);
}

/// A mode is octal, and a mode that is not one is refused rather than applied.
/// `666` read as decimal is 0o1232 — a setgid socket nobody asked for.
#[test]
fn a_mode_that_is_not_a_mode_is_refused() {
    // Under the test's own directory rather than a fixed `/tmp` name: the
    // assertion below is that the socket was NOT created, and a shared path
    // makes that a claim about every process on the machine.
    let dir = TempDir::new().expect("tempdir");
    let sock = dir.path().join("refused.sock");
    for bad in ["999", "abc", "1660", "", "444"] {
        let out = exav()
            .arg("--listen")
            .arg(format!("clamd://{}?mode={bad}", sock.display()))
            .output()
            .expect("run exav");
        assert_eq!(
            out.status.code(),
            Some(2),
            "?mode={bad:?} must be refused, not applied"
        );
        assert!(
            !sock.exists(),
            "nothing may be bound for a mode that was refused"
        );
    }
}

/// A mode names a file's permissions, and only a Unix socket is one.
///
/// A flag of its own would need a cross-check against two others to establish
/// what it is being applied to. Carried by the address, the only wrong thing
/// left to attach it to is a `host:port`, which the address parser answers on
/// its own.
#[test]
fn a_mode_needs_a_socket() {
    let out = exav()
        .args(["--listen", "clamd://127.0.0.1:0?mode=660"])
        .output()
        .expect("run exav");
    assert_eq!(
        out.status.code(),
        Some(2),
        "a mode on a host:port listener should be refused rather than ignored"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("host:port"), "{err}");
}

/// `--log` in daemon mode: the daemon's results go to whoever asked for them,
/// so the log is the operator's only record of what it answered. An empty file
/// beside a served detection is the defect this pins.
#[test]
fn the_daemon_logs_what_it_answered() {
    let logdir = TempDir::new().unwrap();
    let log = logdir.path().join("scan.log");
    let d = Daemon::start("077", &["--log", log.to_str().unwrap()]);
    let bad = d.file("bad.txt", eicar());
    let clean = d.file("clean.txt", b"nothing here\n");
    let (code, _) = d.client(&[], &[&bad, &clean]);
    assert_eq!(code, 1);

    let mut text = String::new();
    std::fs::File::open(&log)
        .expect("the daemon created its log")
        .read_to_string(&mut text)
        .unwrap();
    assert!(
        text.contains("bad.txt: Eicar-Test-Signature FOUND"),
        "the detection the daemon served must be in its log: {text:?}"
    );
    assert!(
        text.contains("clean.txt: OK"),
        "and the clean result beside it: {text:?}"
    );
    assert!(
        !text.contains("PONG") && !text.contains("COMMANDS:"),
        "a scan log carries scan results, not protocol chatter: {text:?}"
    );
}

/// `--send-as contents` sends the file's bytes (`INSTREAM`), so the daemon needs
/// no access to the path — the case a milter or a container deployment is in.
///
/// The daemon's own log is the proof of which verb ran: it records a streamed
/// scan as `stream:` and a path scan under the path it was given.
#[test]
fn send_as_contents_sends_the_file_by_content() {
    let logdir = TempDir::new().unwrap();
    let log = logdir.path().join("scan.log");
    let d = Daemon::start("077", &["--log", log.to_str().unwrap()]);
    let bad = d.file("bad.txt", eicar());
    let clean = d.file("clean.txt", b"nothing here\n");

    let (code, stdout) = d.client(&["--send-as", "contents"], &[&bad, &clean]);
    assert!(
        stdout.contains(&format!("{}: Eicar-Test-Signature FOUND", bad.display())),
        "the reply is reported under the local name, not the daemon's \
         `stream`: {stdout}"
    );
    assert!(
        stdout.contains(&format!("{}: OK", clean.display())),
        "{stdout}"
    );
    assert_eq!(code, 1, "{stdout}");

    let mut text = String::new();
    std::fs::File::open(&log)
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    assert!(
        text.contains("stream: Eicar-Test-Signature FOUND"),
        "the daemon must have been given the contents, not the path: {text:?}"
    );
}

/// `--send-as fd` hands over an open descriptor (`FILDES`): the daemon reads the
/// file this client opened, without permission to open the path itself.
#[test]
fn send_as_fd_sends_the_file_by_descriptor() {
    let logdir = TempDir::new().unwrap();
    let log = logdir.path().join("scan.log");
    let d = Daemon::start("077", &["--log", log.to_str().unwrap()]);
    let bad = d.file("bad.txt", eicar());

    let (code, stdout) = d.client(&["--send-as", "fd"], &[&bad]);
    assert!(
        stdout.contains(&format!("{}: Eicar-Test-Signature FOUND", bad.display())),
        "{stdout}"
    );
    assert_eq!(code, 1, "{stdout}");

    let mut text = String::new();
    std::fs::File::open(&log)
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    assert!(
        text.contains("fd: Eicar-Test-Signature FOUND"),
        "the daemon must have scanned a passed descriptor: {text:?}"
    );
}

/// `-` in client mode. There is no path to name, so this only works by
/// streaming, which is what makes a pipeline work against a daemon that shares
/// no filesystem with it.
#[test]
fn stdin_streams_to_the_daemon() {
    let d = Daemon::start("077", &[]);
    let out = exav()
        .arg("--connect")
        .arg(&d.sock)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.take().unwrap().write_all(eicar())?;
            c.wait_with_output()
        })
        .expect("run the client");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("stdin: Eicar-Test-Signature FOUND"),
        "reported under the name a local `exav -` uses: {stdout}"
    );
    assert_eq!(out.status.code(), Some(1), "{stdout}");
}

/// A byte-split set is one archive cut into pieces: no piece decodes alone, so
/// streaming them one at a time collects a clean answer per fragment and never
/// opens the archive. Sent together, the daemon rejoins them.
#[test]
fn a_split_set_is_rejoined_when_streamed() {
    let d = Daemon::start("077", &[]);
    let dir = TempDir::new().unwrap();
    // Cut through the middle of the signature, so no part can match by itself.
    std::fs::write(dir.path().join("e.zip.001"), &eicar()[..34]).unwrap();
    std::fs::write(dir.path().join("e.zip.002"), &eicar()[34..]).unwrap();

    let (code, stdout) = d.client(&["--send-as", "contents"], &[dir.path()]);
    assert_eq!(
        stdout.matches("FOUND (in e.zip)").count(),
        2,
        "each part carries the archive's verdict: {stdout}"
    );
    assert_eq!(code, 1, "{stdout}");
}

/// `--verbose` in client mode. The daemon's reply is a verdict and nothing
/// else, so what `-v` has to add here is which daemon answered and what it was
/// asked — accepting the flag and printing nothing is the defect.
#[test]
fn verbose_names_the_daemon_and_the_command() {
    let d = Daemon::start("077", &[]);
    let clean = d.file("clean.txt", b"nothing here\n");

    let (_, stdout) = d.client(&["-v"], &[&clean]);
    // Named in the same grammar `--connect` takes, so what `-v` prints can be
    // pasted straight back onto a command line.
    assert!(
        stdout.contains(&format!("[daemon] clamd://{}", d.sock.display())),
        "-v names the daemon that answered: {stdout}"
    );
    assert!(
        stdout.contains("[SCAN] "),
        "-v names the command sent: {stdout}"
    );

    let (_, stdout) = d.client(&["-v", "--send-as", "contents"], &[&clean]);
    assert!(
        stdout.contains("[INSTREAM] "),
        "and names the streaming verb when the contents are sent: {stdout}"
    );
}

/// A stream the daemon could not examine comes back as `PARTIAL`, exit 3 — the
/// same answer a local scan of the same object gives.
///
/// The wire grammar is `<path>: <reason> <CATEGORY> ERROR`, because clamd has no
/// word for `PARTIAL` and the category is what carries it across. Emit the two
/// the other way round and the reply still *reads* right to a person, while the
/// client sees a category it cannot find, files it under hard errors, and exits
/// `2`. That difference is the whole point of having a fourth code: `2` says the
/// scanner broke, `3` says this object needs a decision.
#[test]
fn an_unexaminable_stream_is_partial_over_the_wire_not_a_hard_error() {
    // Nowhere to spill and almost no room in RAM, so any real object is one the
    // daemon cannot examine — the condition, reached the quickest way.
    let d = Daemon::start(
        "077",
        &["--spill-dir", "off", "--spill-threshold-bytes", "1M"],
    );
    let big = d.file("big.bin", &vec![b'A'; 4 << 20]);

    let (code, out) = d.client(&["--send-as", "contents"], &[&big]);
    assert!(
        out.contains("UNSCANNABLE"),
        "the category has to survive the trip: {out}"
    );
    assert!(
        out.contains("PARTIAL"),
        "and the client must read it back as PARTIAL, not a hard error: {out}"
    );
    assert_eq!(code, 3, "which is exit 3, not 2: {out}");
}

/// `--json` is a machine stream: the informational lines `-v` prints would be
/// parse errors in it.
#[test]
fn verbose_stays_out_of_the_json_stream() {
    let d = Daemon::start("077", &[]);
    let clean = d.file("clean.txt", b"nothing here\n");
    let (_, stdout) = d.client(&["-v", "--json"], &[&clean]);
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|e| panic!("every line must be JSON ({e}): {line:?}"));
    }
}

/// A directory names a tree in client mode, with or without `-r`, and
/// `--no-recursive` bounds it there exactly as it does locally.
///
/// `clamdscan` has no `-r`, so a command line migrated from it hands the client
/// a bare directory. Answering for one file in it and exiting 0 is a clean
/// verdict over a tree that holds a detection, which is the one thing a scanner
/// may never report — so the default has to be the whole tree.
///
/// Asking for the top level is a different matter: `--no-recursive` is exav's
/// own flag and the caller typed it. The client does its own walking, so it is
/// the one part of a client run that *can* honour it, and a flag accepted and
/// dropped is how a scan of two files comes back looking like a scan of the
/// tree. Same flag, same meaning, whichever end holds the database.
#[test]
fn a_directory_recurses_by_default_and_no_recursive_bounds_it() {
    let d = Daemon::start("077", &[]);
    let t = infected_tree();

    let (bare_code, bare) = d.client(&[], &[t.path()]);
    assert!(
        bare.contains("eicar.com: Eicar-Test-Signature FOUND"),
        "a detection anywhere in the tree must be reported: {bare}"
    );
    assert_eq!(bare_code, 1, "and the exit code must say so: {bare}");
    assert!(
        bare.contains("sub/deep.txt"),
        "a bare directory is the whole tree: {bare}"
    );

    let (r_code, shallow) = d.client(&["--no-recursive"], &[t.path()]);
    assert!(
        !shallow.contains("sub/deep.txt"),
        "`--no-recursive` stops at the directory's own files: {shallow}"
    );
    assert!(
        shallow.contains("eicar.com: Eicar-Test-Signature FOUND"),
        "and still answers for the files it did reach: {shallow}"
    );
    assert_eq!(r_code, bare_code, "a detection is still a detection");
    assert!(
        verdicts(&bare).len() > verdicts(&shallow).len(),
        "the bounded walk must be the smaller one"
    );
}

/// The summary counts what the daemon answered about, not how many commands the
/// client sent. A tree of three answered as `Scanned files: 1` is the same lost
/// reply the exit code would be computed from.
#[test]
fn the_summary_counts_every_file_the_daemon_answered_for() {
    let d = Daemon::start("077", &[]);
    let t = infected_tree();

    let (_, stdout) = d.client(&[], &[t.path()]);
    assert_eq!(
        summary_count(&stdout, "Scanned files:"),
        3,
        "three files in the tree, three verdicts: {stdout}"
    );
    assert_eq!(summary_count(&stdout, "Infected files:"), 1, "{stdout}");
    assert_eq!(
        verdicts(&stdout).len(),
        3,
        "every file gets its own line: {stdout}"
    );
}

/// A directory and a file in one run. Both are answered on the same session, so
/// a reply left unread by the first command is read as the second's answer —
/// which loses the file's verdict and misattributes the tree's.
#[test]
fn a_directory_beside_a_file_keeps_every_answer() {
    let d = Daemon::start("077", &[]);
    let t = infected_tree();
    let lone = d.file("lone.txt", b"nothing here\n");

    let (code, stdout) = d.client(&[], &[t.path(), &lone]);
    assert!(
        stdout.contains(&format!("{}: OK", lone.display())),
        "the file named after the tree must get its own verdict: {stdout}"
    );
    assert!(
        stdout.contains("eicar.com: Eicar-Test-Signature FOUND"),
        "{stdout}"
    );
    assert_eq!(summary_count(&stdout, "Scanned files:"), 4, "{stdout}");
    assert_eq!(code, 1, "{stdout}");
}

/// `--all-matches` over a tree. The flag changes how many signatures a file can
/// report, not how many files are looked at: the tree is still answered file by
/// file and counted the same way.
#[test]
fn allmatch_answers_for_every_file_in_a_tree() {
    let d = Daemon::start("077", &[]);
    let t = infected_tree();

    let (code, stdout) = d.client(&["--all-matches"], &[t.path()]);
    assert!(
        stdout.contains("eicar.com: Eicar-Test-Signature FOUND"),
        "{stdout}"
    );
    assert_eq!(
        summary_count(&stdout, "Scanned files:"),
        3,
        "one count per file, whatever the number of matches: {stdout}"
    );
    assert_eq!(code, 1, "{stdout}");
}

/// `--all-matches` over a byte-split set. No part decodes on its own, so scanning
/// the parts as the files they are finds nothing; the set has to be rejoined
/// whichever flag was passed, or the answer is clean over an archive nobody
/// opened.
#[test]
fn allmatch_rejoins_a_split_set() {
    let d = Daemon::start("077", &[]);
    let dir = TempDir::new().unwrap();
    // Cut through the middle of the signature, so no part can match by itself.
    std::fs::write(dir.path().join("e.zip.001"), &eicar()[..34]).unwrap();
    std::fs::write(dir.path().join("e.zip.002"), &eicar()[34..]).unwrap();

    let (code, stdout) = d.client(&["--all-matches"], &[dir.path()]);
    assert_eq!(
        stdout.matches("FOUND (in e.zip)").count(),
        2,
        "each part carries the archive's verdict: {stdout}"
    );
    assert_eq!(summary_count(&stdout, "Scanned files:"), 2, "{stdout}");
    assert_eq!(code, 1, "{stdout}");
}

/// The client's contract with the protocol is per COMMAND, not per file: every
/// reply message a command produced has to reach the user.
///
/// A daemon of the test's own answers one `SCAN` with two messages, which is
/// what a real one does whenever the path it was handed names more than one
/// file. A client that reads a fixed single line reports the first and drops
/// the second — and the second is the detection here.
#[test]
fn every_reply_message_of_a_scan_is_reported() {
    use std::io::Write;
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("fake.sock");
    let target = dir.path().join("a.txt");
    std::fs::write(&target, b"nothing here\n").unwrap();

    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("the client connected");
        // Commands arrive NUL-terminated and can share a write, so they are
        // taken from a buffer rather than one per read.
        let mut pending: Vec<u8> = Vec::new();
        let mut id = 0u64;
        loop {
            let mut chunk = [0u8; 1024];
            let n = match s.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            pending.extend_from_slice(&chunk[..n]);
            while let Some(i) = pending.iter().position(|&b| b == 0) {
                let cmd = String::from_utf8_lossy(&pending[..i])
                    .trim_start_matches(['z', 'n'])
                    .to_string();
                pending.drain(..=i);
                let word = cmd.split_whitespace().next().unwrap_or("");
                let replies = match word {
                    "IDSESSION" => continue,
                    "END" => return,
                    "PING" => {
                        id += 1;
                        vec![format!("{id}: PONG")]
                    }
                    _ => {
                        id += 1;
                        vec![
                            format!("{id}: /t/one: OK"),
                            format!("{id}: /t/two: Eicar-Test-Signature FOUND"),
                        ]
                    }
                };
                for r in replies {
                    if s.write_all(r.as_bytes())
                        .and_then(|()| s.write_all(b"\0"))
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    });

    let out = exav()
        .arg("--connect")
        .arg(&sock)
        .arg(&target)
        .output()
        .expect("run the client");
    let stdout = String::from_utf8_lossy(&out.stdout);
    server.join().expect("the test daemon finished");

    assert!(
        stdout.contains("/t/one: OK"),
        "the first reply message: {stdout}"
    );
    assert!(
        stdout.contains("/t/two: Eicar-Test-Signature FOUND"),
        "and the second one, which is the whole verdict: {stdout}"
    );
    assert_eq!(summary_count(&stdout, "Scanned files:"), 2, "{stdout}");
    assert_eq!(out.status.code(), Some(1), "{stdout}");
}

/// The premise the client's session framing rests on: one command, any number
/// of replies. `SCAN` over a directory answers once per file, every message
/// tagged with the same command id and nothing marking the last — so a client
/// that reads a fixed line count drops verdicts, and the one it sends behind
/// the scan (`PING`) is what tells it the scan has finished talking.
#[test]
fn a_session_command_can_answer_more_than_once() {
    use std::io::Write;
    let d = Daemon::start("077", &[]);
    let t = infected_tree();

    let mut s = std::os::unix::net::UnixStream::connect(&d.sock).unwrap();
    let req = format!("zIDSESSION\0zSCAN {}\0zPING\0zEND\0", t.path().display());
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw);
    let msgs: Vec<&str> = text.split('\0').filter(|m| !m.is_empty()).collect();

    assert_eq!(
        msgs.len(),
        4,
        "three files answered, then the marker: {msgs:?}"
    );
    assert!(
        msgs[..3].iter().all(|m| m.starts_with("1: ")),
        "every verdict answers the first command: {msgs:?}"
    );
    assert!(
        msgs.iter()
            .any(|m| m.contains("Eicar-Test-Signature FOUND")),
        "{msgs:?}"
    );
    assert_eq!(
        msgs[3], "2: PONG",
        "the marker arrives after the scan it follows, under its own id: {msgs:?}"
    );
}
