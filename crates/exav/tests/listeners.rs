//! What a serving exav binds, and what it refuses to serve.
//!
//! Both questions are only answerable from outside the process. Whether one
//! command line ends up with two listeners over one database is a fact about
//! sockets and process trees; whether a daemon comes up at all against an empty
//! signature directory is a fact about its exit code. Neither is observable from
//! a unit test of the argument parser, and both are exactly what an operator
//! finds out the hard way if they regress.

#![cfg(unix)]

use std::io::{self, Read, Write};
use std::net::TcpStream;
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

/// A signature set with enough in it to count as a real database: exav refuses
/// to serve anything that adds nothing to the built-in EICAR-only baseline, and
/// that guard is one of the things under test here.
const SIGNATURES: &str = "Exav.Test.Alpha:0:*:6d616c7761726541\n\
                          Exav.Test.Beta:0:*:6d616c7761726542\n\
                          Exav.Test.Gamma:0:*:6d616c7761726543\n";

/// A byte string matching `Exav.Test.Alpha` above (`malwareA`).
const ALPHA: &[u8] = b"malwareA";

fn exav_bin() -> &'static str {
    env!("CARGO_BIN_EXE_exav")
}

/// A free localhost port, taken by binding and releasing one. The window between
/// releasing and the daemon binding is a race in principle; in practice the
/// kernel does not hand the same ephemeral port straight back, and the
/// alternative — a fixed port — collides with whatever else is on the machine.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a localhost port")
        .local_addr()
        .expect("its address")
        .port()
}

/// A running exav, stopped when the test drops it.
struct Server {
    child: Child,
    log: PathBuf,
    _dir: TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    /// Start exav with `args`, its stderr captured to a file the test can read.
    fn start(dir: TempDir, args: &[&str]) -> Server {
        let log = dir.path().join("stderr.log");
        let child = Command::new(exav_bin())
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(&log).expect("create the log"),
            ))
            .spawn()
            .expect("start exav");
        Server {
            child,
            log,
            _dir: dir,
        }
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Ask the process to stop the way an orchestrator does, and wait for it.
    ///
    /// `SIGTERM` rather than a kill, because the supervisor's teardown is what
    /// is under test: a `SIGKILL` leaves its children orphaned and still holding
    /// their listeners, which says nothing about whether it took them down.
    fn terminate(&mut self) {
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the server never stopped on SIGTERM:\n{}", self.stderr());
    }
}

/// Block until nothing answers on `port`, so a teardown check does not race the
/// last child closing its listener.
fn wait_until_closed(port: u16, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the {what} listener on {port} outlived the process that owned it");
}

/// Connect to `port`, retrying until it answers or the deadline passes.
fn dial(port: u16, what: &str) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            return s;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("nothing ever answered on the {what} port {port}");
}

/// Retry `f` until it answers or the deadline passes.
///
/// `dial` succeeds as soon as the listener is bound, which the daemon does
/// *before* it warms the database and forks its pool — so a connection made in
/// that window can be reset. Under a loaded test host, every suite running at
/// once and each daemon forking one worker per core, that window is wide enough
/// to hit. A real client retries a reset against a daemon that has just started;
/// a test standing in for one does the same.
///
/// This excuses a dropped connection, never a wrong answer: whatever finally
/// comes back is still asserted on.
fn until_answered<T>(what: &str, mut f: impl FnMut() -> io::Result<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match f() {
            Ok(v) => return v,
            Err(e) if Instant::now() >= deadline => {
                panic!("the daemon never answered a {what}: {e}")
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// Send one clamd `INSTREAM` and return the verdict line.
fn clamd_instream(port: u16, body: &[u8]) -> String {
    until_answered("scan", || try_clamd_instream(port, body))
}

/// The same, reporting a dropped connection instead of panicking on it.
fn try_clamd_instream(port: u16, body: &[u8]) -> io::Result<String> {
    let mut s = dial(port, "clamd");
    s.write_all(b"zINSTREAM\0")?;
    s.write_all(&(body.len() as u32).to_be_bytes())?;
    s.write_all(body)?;
    s.write_all(&0u32.to_be_bytes())?;
    let mut out = Vec::new();
    s.read_to_end(&mut out)?;
    Ok(String::from_utf8_lossy(&out).trim_end_matches('\0').into())
}

/// Send one clamd `PING` and return the reply. Retries a dropped connection for
/// the same reason [`clamd_instream`] does.
fn clamd_ping(port: u16) -> String {
    until_answered("ping", || {
        let mut s = dial(port, "clamd");
        s.write_all(b"zPING\0")?;
        let mut out = Vec::new();
        s.read_to_end(&mut out)?;
        Ok(String::from_utf8_lossy(&out).trim_end_matches('\0').into())
    })
}

/// Send one ICAP `RESPMOD` carrying `body` and return the whole answer.
fn icap_respmod(port: u16, body: &[u8]) -> String {
    let mut s = dial(port, "icap");
    let http = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
    // Asking for the connection to close is what lets the answer be read to
    // end-of-stream; keep-alive would leave the reader waiting on a second
    // request this test is never going to send.
    let head = format!(
        "RESPMOD icap://127.0.0.1:{port}/avscan ICAP/1.0\r\n\
         Host: 127.0.0.1\r\n\
         Connection: close\r\n\
         Encapsulated: res-hdr=0, res-body={}\r\n\r\n",
        http.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(http.as_bytes()).unwrap();
    s.write_all(format!("{:x}\r\n", body.len()).as_bytes())
        .unwrap();
    s.write_all(body).unwrap();
    s.write_all(b"\r\n0\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// A signature directory holding a real (if small) database.
fn sig_dir() -> TempDir {
    let d = TempDir::new().unwrap();
    std::fs::write(d.path().join("test.ndb"), SIGNATURES).unwrap();
    d
}

/// Wait for `haystack` to contain `needle`, so a test can key on a line the
/// server writes when it reaches a particular state rather than on a sleep.
fn wait_for_log(server: &Server, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if server.stderr().contains(needle) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "never saw {needle:?} in the server's output:\n{}",
        server.stderr()
    );
}

/// One process, two protocols, one loaded database.
///
/// The two listeners are separate protocols on separate ports, and the reason to
/// serve them together is the database: loading a full signature set costs
/// seconds and gigabytes, and paying that twice to answer the same questions on
/// two sockets is the cost a second container exists to avoid. So the check is
/// not only that both answer — it is that both answer *the same detection*,
/// which is what says they are reading one database.
#[test]
fn one_process_serves_both_protocols() {
    for workers in ["4", "threads"] {
        let dir = TempDir::new().unwrap();
        let sigs = sig_dir();
        let (clamd, icap) = (free_port(), free_port());
        let mut server = Server::start(
            dir,
            &[
                "--workers",
                workers,
                "--listen",
                &format!("clamd://127.0.0.1:{clamd}"),
                "--listen",
                &format!("icap://127.0.0.1:{icap}"),
                "-d",
                sigs.path().to_str().unwrap(),
            ],
        );

        assert_eq!(
            clamd_ping(clamd),
            "PONG",
            "workers={workers}: the clamd listener must answer"
        );
        let verdict = clamd_instream(clamd, ALPHA);
        assert!(
            verdict.contains("Exav.Test.Alpha") && verdict.contains("FOUND"),
            "workers={workers}: the clamd listener scanned with the loaded database, got {verdict:?}"
        );

        let answer = icap_respmod(icap, ALPHA);
        assert!(
            answer.contains("Exav.Test.Alpha"),
            "workers={workers}: the ICAP listener answered from the SAME database, got {answer:?}"
        );

        // Both listeners belong to the one process the test started, so asking
        // that process to stop takes both down — including, under the pool, the
        // separate child the ICAP listener runs in.
        server.terminate();
        wait_until_closed(clamd, "clamd");
        wait_until_closed(icap, "icap");
    }
}

/// One `icap://` address is a whole deployment on its own, and it serves ICAP
/// and nothing else.
///
/// The protocol travels in the address, so the failure this guards against is
/// the two getting crossed: a port asked for as ICAP that also answers the clamd
/// wire protocol is one an unrelated client can drive.
#[test]
fn icap_alone_serves_only_icap() {
    let sigs = sig_dir();
    let icap = free_port();
    let _server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--listen",
            &format!("icap://127.0.0.1:{icap}"),
            "-d",
            sigs.path().to_str().unwrap(),
        ],
    );
    // The announcement comes after the database is loaded, so waiting for it is
    // what keeps this about the listener rather than about a race: a scan sent
    // to a bound-but-still-loading server comes back clean and looks like a
    // detection failure.
    wait_for_log(&_server, "serving ICAP on tcp:");
    let answer = icap_respmod(icap, ALPHA);
    assert!(answer.contains("Exav.Test.Alpha"), "got {answer:?}");

    // A clamd `PING` here gets no `PONG`. Read with a short timeout rather than
    // to end-of-stream: a server that does not understand the command is under
    // no obligation to answer at all, and waiting for one it will never send is
    // the same evidence arriving thirty seconds later.
    let mut s = dial(icap, "icap");
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"zPING\0").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    assert!(
        !String::from_utf8_lossy(&out).contains("PONG"),
        "an ICAP port must not also answer the clamd protocol"
    );
}

/// `--auto-update` with no source of its own waits for a sidecar to write the
/// signature directory, and serves what turns up.
///
/// The wait is the whole reason a container can be started before the volume it
/// reads is populated. Without it the daemon reaches an empty directory, refuses
/// to serve, and the orchestrator restarts it in a loop that outlives whatever
/// was going to fill the volume.
#[test]
fn auto_update_waits_for_a_sidecar_to_write_the_signatures() {
    let dir = TempDir::new().unwrap();
    let sigs = TempDir::new().unwrap();
    let clamd = free_port();
    let server = Server::start(
        dir,
        &[
            "--auto-update",
            "--startup-wait-secs",
            "60",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );

    wait_for_log(&server, "waiting up to 60s for signatures");
    assert!(
        TcpStream::connect(("127.0.0.1", clamd)).is_err(),
        "nothing may be served while there are no signatures to serve it from"
    );

    // The sidecar writes the volume.
    std::fs::write(sigs.path().join("test.ndb"), SIGNATURES).unwrap();

    let verdict = clamd_instream(clamd, ALPHA);
    assert!(
        verdict.contains("Exav.Test.Alpha") && verdict.contains("FOUND"),
        "the daemon came up on the signatures that arrived, got {verdict:?}"
    );
}

/// When they never arrive, it refuses to serve rather than answering everything
/// `OK` from the near-empty baseline. A scanner that reports clean is worse than
/// one that is not running: the caller cannot tell the difference from a verdict,
/// only from an exit code.
#[test]
fn serving_no_signatures_is_refused() {
    let sigs = TempDir::new().unwrap();
    let clamd = free_port();
    let out = Command::new(exav_bin())
        .args([
            "--auto-update",
            "--startup-wait-secs",
            "1",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ])
        .output()
        .expect("run exav");
    assert_eq!(out.status.code(), Some(2), "an empty database is an error");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("refusing to run"),
        "and it says why, rather than serving nothing quietly: {err}"
    );

    // `--allow-no-db` is how a test rig opts into the baseline, and it says so.
    let baseline = Server::start(
        TempDir::new().unwrap(),
        &[
            "--allow-no-db",
            "--listen",
            &format!("clamd://127.0.0.1:{}", free_port()),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    let _ = &baseline;
}

/// A signature change on disk reaches the running daemon: the supervisor's
/// mtime watch is what a sidecar deployment relies on, and it has to keep
/// working now that the signature lifecycle is a flag rather than a mode, and
/// whatever serves: the pool, the thread model, or ICAP alone.
#[test]
fn a_rewritten_signature_directory_is_reloaded() {
    for model in ["pool", "threads", "icap"] {
        let sigs = sig_dir();
        let port = free_port();
        let listen = match model {
            "icap" => format!("icap://127.0.0.1:{port}"),
            _ => format!("clamd://127.0.0.1:{port}"),
        };
        let mut args = vec![
            "--listen",
            &listen,
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ];
        if model == "threads" {
            args.extend(["--workers", "threads"]);
        }
        let server = Server::start(TempDir::new().unwrap(), &args);
        // A worker of the old generation may still take a connection, so an
        // answer without the new signature means "not yet".
        let scan = || match model {
            "icap" => icap_respmod(port, b"malwareD"),
            _ => try_clamd_instream(port, b"malwareD").unwrap_or_default(),
        };
        if model == "icap" {
            wait_for_log(&server, "serving ICAP on tcp:");
        }
        let before = match model {
            "icap" => icap_respmod(port, b"malwareD"),
            _ => clamd_instream(port, b"malwareD"),
        };
        assert!(
            !before.contains("Exav.Test.Delta"),
            "{model}: nothing detects this yet, got {before:?}"
        );

        std::fs::write(
            sigs.path().join("more.ndb"),
            "Exav.Test.Delta:0:*:6d616c7761726544\n",
        )
        .unwrap();
        wait_for_log(&server, "reloading signatures");
        until_delta(scan, &server);
    }
}

/// Bytes `pid` has read so far, from `/proc/<pid>/io`.
#[cfg(target_os = "linux")]
fn bytes_read(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/io"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("rchar:"))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0)
}

/// A file a sidecar writes while the first load is still running is a change:
/// the watch's baseline is what the load started from, not what the directory
/// held once it finished.
#[cfg(target_os = "linux")]
#[test]
fn a_file_written_during_the_first_load_is_reloaded() {
    use std::fmt::Write as _;
    let sigs = sig_dir();
    // Enough that building the database takes seconds after the files are read.
    let mut big = String::new();
    for i in 0..1_000_000u64 {
        writeln!(
            big,
            "Exav.Big.{i}:0:*:{:016x}",
            i.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        )
        .unwrap();
    }
    std::fs::write(sigs.path().join("big.ndb"), &big).unwrap();
    let clamd = free_port();
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "threads",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    while bytes_read(server.child.id()) < big.len() as u64 {
        assert!(Instant::now() < deadline, "the signatures were never read");
        std::thread::sleep(Duration::from_millis(1));
    }
    std::fs::write(
        sigs.path().join("more.ndb"),
        "Exav.Test.Delta:0:*:6d616c7761726544\n",
    )
    .unwrap();
    // Otherwise the write missed the window this is about.
    assert!(
        !server.stderr().contains("listening on"),
        "the load had already finished:\n{}",
        server.stderr()
    );
    let first = clamd_instream(clamd, b"malwareD");
    assert!(first.contains(": OK"), "loaded before the write: {first}");
    until_delta(|| clamd_instream(clamd, b"malwareD"), &server);
}

/// A reload or a shutdown signal that lands while the supervisor is busy is
/// acted on as soon as it is free, not at the end of its next idle poll.
///
/// Busy means reloading a database big enough to take seconds, started by a
/// `SIGUSR2`; the poll is ten seconds, well past what either answer may take.
/// The worker a reload retires is kept in a job, so its exit is not what wakes
/// the supervisor.
#[cfg(target_os = "linux")]
#[test]
fn a_request_while_the_supervisor_is_busy_is_not_left_for_the_next_poll() {
    use std::fmt::Write as _;
    let sigs = sig_dir();
    let mut big = String::new();
    for i in 0..1_000_000u64 {
        writeln!(
            big,
            "Exav.Big.{i}:0:*:{:016x}",
            i.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        )
        .unwrap();
    }
    std::fs::write(sigs.path().join("big.ndb"), &big).unwrap();
    let clamd = free_port();
    let mut server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "1",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    assert_eq!(clamd_ping(clamd), "PONG");
    let pid = server.child.id();
    let reloads = |s: &Server| s.stderr().matches("reloading signatures").count();
    // A reload under way: it has read the signatures and is building from them.
    let start_a_reload = |s: &Server| {
        let before = bytes_read(pid);
        signal(s, libc::SIGUSR2);
        let deadline = Instant::now() + Duration::from_secs(60);
        while bytes_read(pid) < before + big.len() as u64 {
            assert!(
                Instant::now() < deadline,
                "no reload started:\n{}",
                s.stderr()
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    // When `done` first holds.
    let when = |what: &str, done: &mut dyn FnMut() -> bool| {
        let since = Instant::now();
        while !done() {
            assert!(
                since.elapsed() < Duration::from_secs(60),
                "{what} never happened"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Instant::now()
    };

    // A job the worker is in until the test ends.
    let hold = || {
        let mut s = dial(clamd, "clamd");
        s.write_all(b"zINSTREAM\0").unwrap();
        s.write_all(&4u32.to_be_bytes()).unwrap();
        s.write_all(b"ab").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        s
    };

    let _job = hold();
    start_a_reload(&server);
    signal(&server, libc::SIGUSR2);
    assert_eq!(
        reloads(&server),
        0,
        "the first reload ended before the second request"
    );
    let first = when("the first reload", &mut || reloads(&server) >= 1);
    let second = when("the second reload", &mut || reloads(&server) >= 2);
    assert!(
        second - first < Duration::from_secs(8),
        "the second reload waited {:?} after the first:\n{}",
        second - first,
        server.stderr()
    );

    // The idle worker of the first reload, retired by the second, is gone.
    when("the idle worker's exit", &mut || {
        server.stderr().contains("retired after a reload")
    });
    let _job = hold();
    start_a_reload(&server);
    signal(&server, libc::SIGTERM);
    assert_eq!(reloads(&server), 2, "the third reload ended before SIGTERM");
    let third = when("the third reload", &mut || reloads(&server) >= 3);
    let exit = when("the exit", &mut || {
        matches!(server.child.try_wait(), Ok(Some(_)))
    });
    assert!(
        exit - third < Duration::from_secs(5),
        "SIGTERM waited {:?} after the reload:\n{}",
        exit - third,
        server.stderr()
    );
}

/// Rewrite a signature file in place and put its mtime back, so the directory
/// watch sees no change and only an explicit reload can pick it up.
fn rewrite_unseen(dir: &Path, name: &str, body: &str) {
    let p = dir.join(name);
    let before = std::fs::metadata(&p).unwrap().modified().unwrap();
    std::fs::write(&p, body).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(before)
        .unwrap();
}

fn signal(server: &Server, sig: libc::c_int) {
    // SAFETY: signals the child this test started and has not reaped.
    assert_eq!(
        unsafe { libc::kill(server.child.id() as libc::pid_t, sig) },
        0
    );
}

/// Scan `malwareD` until `Exav.Test.Delta` detects it: the reload that brought
/// it in has taken effect.
fn until_delta(scan: impl Fn() -> String, server: &Server) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let got = scan();
        if got.contains("Exav.Test.Delta") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the reload never took effect: {got:?}\n{}",
            server.stderr()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

const WITH_DELTA: &str = "Exav.Test.Alpha:0:*:6d616c7761726541\n\
                          Exav.Test.Beta:0:*:6d616c7761726542\n\
                          Exav.Test.Delta:0:*:6d616c7761726544\n";

/// As in clamd: `SIGUSR2` reloads the signatures and `SIGHUP` reopens the
/// `--log` file, whatever serves. Neither stops the daemon.
#[test]
fn signals_reload_and_reopen_the_log_like_clamd() {
    for workers in ["2", "threads"] {
        let sigs = sig_dir();
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("scans.log");
        let clamd = free_port();
        let server = Server::start(
            dir,
            &[
                "--workers",
                workers,
                "--log",
                log.to_str().unwrap(),
                "--listen",
                &format!("clamd://127.0.0.1:{clamd}"),
                "--sig-dir",
                sigs.path().to_str().unwrap(),
            ],
        );
        let scan = || until_answered("scan", || try_clamd_instream(clamd, b"malwareD"));
        assert!(scan().contains(": OK"), "workers={workers}");

        // Rotation: the log moves away, SIGHUP, and the next line lands in a
        // new file at the configured path.
        std::fs::rename(&log, log.with_extension("1")).unwrap();
        signal(&server, libc::SIGHUP);
        let deadline = Instant::now() + Duration::from_secs(60);
        while !std::fs::read_to_string(&log).is_ok_and(|s| s.contains(": OK")) {
            assert!(
                Instant::now() < deadline,
                "workers={workers}: the log was never reopened:\n{}",
                server.stderr()
            );
            scan();
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            clamd_ping(clamd),
            "PONG",
            "workers={workers}: SIGHUP stopped it"
        );

        rewrite_unseen(sigs.path(), "test.ndb", WITH_DELTA);
        signal(&server, libc::SIGUSR2);
        wait_for_log(&server, "reloading signatures");
        until_delta(scan, &server);
    }
}

/// `RELOAD` reloads in the thread model too; it used to answer `RELOADING`
/// and do nothing.
#[test]
fn reload_works_in_the_thread_model() {
    let sigs = sig_dir();
    let clamd = free_port();
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "threads",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    let scan = || until_answered("scan", || try_clamd_instream(clamd, b"malwareD"));
    assert!(scan().contains(": OK"));
    rewrite_unseen(sigs.path(), "test.ndb", WITH_DELTA);
    let mut s = dial(clamd, "clamd");
    s.write_all(b"zRELOAD\0").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    assert_eq!(
        String::from_utf8_lossy(&out).trim_end_matches('\0'),
        "RELOADING"
    );
    wait_for_log(&server, "reloading signatures");
    until_delta(scan, &server);
}

/// ICAP served alone reloads on `SIGUSR2`, and `SIGHUP` does not stop it.
#[test]
fn icap_alone_reloads_on_sigusr2() {
    let sigs = sig_dir();
    let icap = free_port();
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--listen",
            &format!("icap://127.0.0.1:{icap}"),
            "-d",
            sigs.path().to_str().unwrap(),
        ],
    );
    wait_for_log(&server, "serving ICAP on tcp:");
    assert!(!icap_respmod(icap, b"malwareD").contains("Exav.Test.Delta"));
    signal(&server, libc::SIGHUP);
    rewrite_unseen(sigs.path(), "test.ndb", WITH_DELTA);
    signal(&server, libc::SIGUSR2);
    wait_for_log(&server, "reloading signatures");
    until_delta(|| icap_respmod(icap, b"malwareD"), &server);
}

/// A reload does not cut short a scan already in progress: the worker holding
/// it finishes the job on the database it started with, then retires.
#[test]
fn a_reload_lets_a_scan_in_progress_finish() {
    let sigs = sig_dir();
    let clamd = free_port();
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "2",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    assert_eq!(clamd_ping(clamd), "PONG");

    let mut s = dial(clamd, "clamd");
    s.write_all(b"zINSTREAM\0").unwrap();
    s.write_all(&(ALPHA.len() as u32).to_be_bytes()).unwrap();
    s.write_all(ALPHA).unwrap();

    std::fs::write(
        sigs.path().join("more.ndb"),
        "Exav.Test.Delta:0:*:6d616c7761726544\n",
    )
    .unwrap();
    wait_for_log(&server, "reloading signatures");
    // Past the moment the old generation is told to go.
    std::thread::sleep(Duration::from_secs(2));

    s.write_all(&0u32.to_be_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let reply = String::from_utf8_lossy(&out);
    assert!(
        reply.contains("Exav.Test.Alpha FOUND"),
        "the scan in progress was dropped by the reload: {reply:?}\n{}",
        server.stderr()
    );
}

/// The same for an ICAP request, served by a child of its own.
#[test]
fn a_reload_lets_an_icap_request_in_progress_finish() {
    let sigs = sig_dir();
    let (clamd, icap) = (free_port(), free_port());
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "2",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--listen",
            &format!("icap://127.0.0.1:{icap}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    wait_for_log(&server, "serving ICAP on tcp:");

    let mut s = dial(icap, "icap");
    let http = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", ALPHA.len());
    let head = format!(
        "RESPMOD icap://127.0.0.1:{icap}/avscan ICAP/1.0\r\n\
         Host: 127.0.0.1\r\n\
         Connection: close\r\n\
         Encapsulated: res-hdr=0, res-body={}\r\n\r\n",
        http.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(http.as_bytes()).unwrap();
    s.write_all(format!("{:x}\r\n", ALPHA.len()).as_bytes())
        .unwrap();
    s.write_all(ALPHA).unwrap();

    std::fs::write(
        sigs.path().join("more.ndb"),
        "Exav.Test.Delta:0:*:6d616c7761726544\n",
    )
    .unwrap();
    wait_for_log(&server, "reloading signatures");
    std::thread::sleep(Duration::from_secs(2));

    s.write_all(b"\r\n0\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let answer = String::from_utf8_lossy(&out);
    assert!(
        answer.contains("Exav.Test.Alpha"),
        "the ICAP request in progress was dropped by the reload: {answer:?}\n{}",
        server.stderr()
    );
}

/// Processes whose parent is `pid`.
#[cfg(target_os = "linux")]
fn children_of(pid: u32) -> usize {
    child_pids(pid).len()
}

#[cfg(target_os = "linux")]
fn child_pids(pid: u32) -> Vec<u32> {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| {
            let e = e.ok()?;
            let stat = std::fs::read_to_string(e.path().join("stat")).ok()?;
            // `pid (comm) state ppid ...`; comm may hold spaces, so split after it.
            let ppid: u32 = stat
                .rsplit_once(')')?
                .1
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()?;
            (ppid == pid).then(|| e.file_name().to_str()?.parse().ok())?
        })
        .collect()
}

/// A reload replaces the pool, it does not add to it: the retired generation's
/// workers are not replaced as they exit.
#[cfg(target_os = "linux")]
#[test]
fn a_reload_keeps_the_pool_its_size() {
    let sigs = sig_dir();
    let (clamd, icap) = (free_port(), free_port());
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "2",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--listen",
            &format!("icap://127.0.0.1:{icap}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    assert_eq!(clamd_ping(clamd), "PONG");
    wait_for_log(&server, "serving ICAP on tcp:");
    let pid = server.child.id();
    assert_eq!(children_of(pid), 3, "two workers and the ICAP child");
    // An idle keep-alive connection does not keep a retired ICAP child alive.
    let _idle = dial(icap, "icap");
    for (i, name) in ["d.ndb", "e.ndb"].iter().enumerate() {
        std::fs::write(
            sigs.path().join(name),
            format!("Exav.Test.X{i}:0:*:6d616c776172655{i}\n"),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while server.stderr().matches("reloading signatures").count() <= i {
            assert!(Instant::now() < deadline, "no reload:\n{}", server.stderr());
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(
            children_of(pid),
            3,
            "after reload {}:\n{}",
            i + 1,
            server.stderr()
        );
    }
}

/// A retired worker does not outlive its grace period: one held by an idle
/// session would otherwise keep serving it the old signatures until the client
/// hangs up.
#[cfg(target_os = "linux")]
#[test]
fn a_retired_worker_is_stopped_after_its_grace() {
    let sigs = sig_dir();
    let clamd = free_port();
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "2",
            "--max-scan-secs",
            "1",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    assert_eq!(clamd_ping(clamd), "PONG");
    let pid = server.child.id();

    let mut session = dial(clamd, "clamd");
    session.write_all(b"zIDSESSION\0zPING\0").unwrap();
    let mut reply = [0u8; 8];
    session.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"1: PONG\0");

    std::fs::write(
        sigs.path().join("more.ndb"),
        "Exav.Test.Delta:0:*:6d616c7761726544\n",
    )
    .unwrap();
    wait_for_log(&server, "reloading signatures");
    let reloaded = Instant::now();
    // The grace is one job's time limit and a margin: well under the minute an
    // idle session is otherwise allowed.
    while children_of(pid) > 2 {
        assert!(
            reloaded.elapsed() < Duration::from_secs(30),
            "the retired worker is still up:\n{}",
            server.stderr()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let mut rest = Vec::new();
    let _ = session.read_to_end(&mut rest);
    assert!(rest.is_empty(), "{rest:?}");
}

/// A worker stopped in the middle of a job answers it, as one stopped by its
/// time limit does: a connection closed with no reply reads as clean to some
/// clients.
#[test]
fn a_worker_stopped_mid_job_answers() {
    let sigs = sig_dir();
    let clamd = free_port();
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "1",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    assert_eq!(clamd_ping(clamd), "PONG");
    let mut s = dial(clamd, "clamd");
    s.write_all(b"zINSTREAM\0").unwrap();
    s.write_all(&4u32.to_be_bytes()).unwrap();
    s.write_all(b"ab").unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let status = Command::new("kill")
        .args(["-TERM", &server.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let reply = String::from_utf8_lossy(&out);
    assert!(reply.contains("ERROR"), "no answer: {reply:?}");
}

/// So does one whose supervisor is killed outright, and it does not outlive it.
#[cfg(target_os = "linux")]
#[test]
fn a_worker_whose_supervisor_dies_mid_job_answers() {
    let sigs = sig_dir();
    let clamd = free_port();
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "1",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    assert_eq!(clamd_ping(clamd), "PONG");
    let workers = child_pids(server.child.id());
    assert_eq!(workers.len(), 1, "{workers:?}");
    let mut s = dial(clamd, "clamd");
    s.write_all(b"zINSTREAM\0").unwrap();
    s.write_all(&4u32.to_be_bytes()).unwrap();
    s.write_all(b"ab").unwrap();
    std::thread::sleep(Duration::from_millis(500));
    signal(&server, libc::SIGKILL);
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let reply = String::from_utf8_lossy(&out).into_owned();
    let proc = format!("/proc/{}", workers[0]);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Path::new(&proc).exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let gone = !Path::new(&proc).exists();
    // SAFETY: the worker this test started, if it is still there.
    unsafe {
        libc::kill(workers[0] as libc::pid_t, libc::SIGKILL);
    }
    assert!(
        reply.contains("stopped before it finished ERROR"),
        "{reply:?}"
    );
    assert!(gone, "the worker outlived its supervisor");
}

/// An updater-only run with nothing to fetch from is refused. A container told
/// to keep signatures current, with no source configured, would otherwise sit in
/// a loop doing nothing while every health check it has says it is fine.
///
/// "Updater-only" is inferred rather than declared: `--auto-update` with no
/// `--listen` and no paths says it, and so cannot contradict itself the way a
/// flag alongside a listener would.
#[test]
fn an_updater_without_a_source_is_refused() {
    let out = Command::new(exav_bin())
        .args(["--auto-update"])
        .env_remove("EXAV_SIG_SOURCES")
        .env_remove("EXAV_DB_URL")
        .output()
        .expect("run exav");
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("no signature source"),
        "the message names what is missing: {err}"
    );
}

/// Configuring a source without asking for it to be fetched is reported, so a
/// setting can never be silently inert.
#[test]
fn configured_sources_without_auto_update_are_reported() {
    let sigs = sig_dir();
    let out = Command::new(exav_bin())
        .args(["--sig-dir", sigs.path().to_str().unwrap(), "--build-db"])
        .arg(sigs.path().join("out.exavdb"))
        .env("EXAV_SIG_SOURCES", "https://mirror.invalid/")
        .output()
        .expect("run exav");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--auto-update"),
        "a configured source that nothing fetches must say so: {err}"
    );
}

/// The environment configures a container, and a flag on the command line
/// overrides it — never the other way round, and never by refusing the flag.
///
/// This is the same rule the parser tests pin, checked where it actually lands:
/// against a running process whose listener is the one the flag named.
#[test]
fn a_flag_overrides_the_environments_listener() {
    let sigs = sig_dir();
    let (from_env, from_flag) = (free_port(), free_port());
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("stderr.log");
    let child = Command::new(exav_bin())
        .args([
            "--listen",
            &format!("clamd://127.0.0.1:{from_flag}"),
            "-d",
            sigs.path().to_str().unwrap(),
        ])
        .env("EXAV_LISTEN", format!("clamd://127.0.0.1:{from_env}"))
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&log).unwrap()))
        .spawn()
        .expect("start exav");
    let server = Server {
        child,
        log,
        _dir: dir,
    };

    assert_eq!(
        clamd_ping(from_flag),
        "PONG",
        "the flag's port is the one served"
    );
    assert!(
        TcpStream::connect(("127.0.0.1", from_env)).is_err(),
        "and the environment's port is not"
    );
    let _ = &server;
}

/// The signature directory is where `--auto-update` writes, and it comes from
/// the environment in a container. Naming it on the command line has to win.
#[test]
fn a_flag_overrides_the_environments_signature_dir() {
    let real = sig_dir();
    let empty = TempDir::new().unwrap();
    let clamd = free_port();
    let dir = TempDir::new().unwrap();
    let log = dir.path().join("stderr.log");
    let child = Command::new(exav_bin())
        .args([
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--sig-dir",
            real.path().to_str().unwrap(),
        ])
        .env("EXAV_SIG_DIR", empty.path())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&log).unwrap()))
        .spawn()
        .expect("start exav");
    let server = Server {
        child,
        log,
        _dir: dir,
    };

    let verdict = clamd_instream(clamd, ALPHA);
    assert!(
        verdict.contains("Exav.Test.Alpha"),
        "the flag's directory is the one loaded, got {verdict:?}"
    );
    let _ = &server;
}

/// EICAR still detects through both listeners with the built-in baseline, which
/// is what an image smoke test does before any signatures exist.
#[test]
fn the_baseline_still_answers_on_an_opted_in_run() {
    let (clamd, icap) = (free_port(), free_port());
    let sigs = TempDir::new().unwrap();
    let _server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--allow-no-db",
            "--startup-wait-secs",
            "0",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--listen",
            &format!("icap://127.0.0.1:{icap}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    assert!(clamd_instream(clamd, eicar()).contains("FOUND"));
    assert!(icap_respmod(icap, eicar()).contains("Exav.Test.EICAR"));
}

/// Paths outside a temp dir are never touched by this suite; the helper exists
/// so a stray absolute path in a future test fails to compile rather than
/// scanning the developer's disk.
#[allow(dead_code)]
fn under_temp(p: &Path) -> bool {
    p.starts_with(std::env::temp_dir())
}
