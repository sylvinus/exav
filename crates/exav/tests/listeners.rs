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
/// alternative (a fixed port) collides with whatever else is on the machine.
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

    /// The same, run under a limit of `nofile` open descriptors, which is how a
    /// test makes the process run out of them.
    fn start_with_descriptor_limit(dir: TempDir, nofile: u32, args: &[&str]) -> Server {
        let log = dir.path().join("stderr.log");
        let child = Command::new("sh")
            .args(["-c", "ulimit -n \"$0\" && exec \"$@\"", &nofile.to_string()])
            .arg(exav_bin())
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
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        // SAFETY: `kill` has no memory precondition. The child is not reaped
        // (`try_wait` just found it running or a zombie), so its pid is not
        // another process's.
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
/// *before* it warms the database and forks its pool, so a connection made in
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
/// not only that both answer: it is that both answer *the same detection*,
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
        // that process to stop takes both down, including, under the pool, the
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

/// In the pool, `--auto-update`'s re-check is a process of its own: the
/// supervisor forks its workers with no other thread running, which POSIX asks
/// of a process that forks, and what the re-check installs reaches them at
/// once, not at the supervisor's next look at the directory (every 10 s).
#[cfg(all(target_os = "linux", feature = "http-update"))]
#[test]
fn a_pool_rechecks_its_signatures_in_a_child_and_reloads_on_an_update() {
    use std::sync::{Arc, Mutex};
    let served = Arc::new(Mutex::new(SIGNATURES.to_string()));
    let delta_served: Arc<Mutex<Option<Instant>>> = Arc::default();
    let source = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/test.ndb", source.local_addr().unwrap());
    let body = Arc::clone(&served);
    let served_at = Arc::clone(&delta_served);
    std::thread::spawn(move || {
        for conn in source.incoming() {
            let Ok(mut conn) = conn else { continue };
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") && conn.read(&mut byte).unwrap_or(0) == 1 {
                request.push(byte[0]);
            }
            let text = body.lock().unwrap().clone();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                text.len()
            );
            let _ = conn.write_all(head.as_bytes());
            if !request.starts_with(b"HEAD") {
                let _ = conn.write_all(text.as_bytes());
                if text.contains("Delta") {
                    served_at.lock().unwrap().get_or_insert_with(Instant::now);
                }
            }
        }
    });
    let sigs = TempDir::new().unwrap();
    let clamd = free_port();
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--auto-update",
            "--sig-sources",
            &url,
            // Off the supervisor's 10 s look at the directory, so a reload
            // there would come about 5 s after the fetch.
            "--update-interval-secs",
            "65",
            "--workers",
            "2",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    wait_for_log(&server, "prefork daemon");
    assert!(clamd_instream(clamd, ALPHA).contains("Exav.Test.Alpha"));
    let status = std::fs::read_to_string(format!("/proc/{}/status", server.child.id())).unwrap();
    let threads = status.lines().find(|l| l.starts_with("Threads:")).unwrap();
    assert_eq!(threads.split_whitespace().nth(1), Some("1"), "{threads}");

    // A signature added at the source reaches the workers at the next check.
    served
        .lock()
        .unwrap()
        .push_str("Exav.Test.Delta:0:*:6d616c7761726544\n");
    let deadline = Instant::now() + Duration::from_secs(150);
    loop {
        let verdict = clamd_instream(clamd, b"malwareD");
        if verdict.contains("Exav.Test.Delta") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the update never reached the pool: {verdict:?}\n{}",
            server.stderr()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let served = delta_served
        .lock()
        .unwrap()
        .expect("the new source was fetched");
    let after = served.elapsed();
    assert!(
        after < Duration::from_secs(3),
        "the reload came {after:?} after the update was fetched, not at once\n{}",
        server.stderr()
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
/// `SIGUSR2`. What is timed is the wait from the end of that reload to the
/// start of the next (the supervisor reading the signatures again), or to the
/// exit, against the ten-second poll: one left for the poll waits all of it,
/// and a slow machine only slows the reloads, which are not timed. The worker
/// a reload retires is kept in a job, so its exit is not what wakes the
/// supervisor.
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
    // The supervisor's idle poll.
    const POLL: Duration = Duration::from_secs(10);
    let first = when("the first reload", &mut || reloads(&server) >= 1);
    // Half the file: the second reload may have begun reading by the time the
    // first one's line is seen.
    let read = bytes_read(pid) + big.len() as u64 / 2;
    let second = when("the second reload", &mut || bytes_read(pid) >= read);
    assert!(
        second - first < POLL,
        "the second reload started {:?} after the first ended:\n{}",
        second - first,
        server.stderr()
    );
    when("the second reload's end", &mut || reloads(&server) >= 2);

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
        exit - third < POLL,
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
    // Not a worker that is gone: init has reaped it, and its pid may already be
    // another process's.
    if !gone {
        // SAFETY: `kill` has no memory precondition.
        unsafe {
            libc::kill(workers[0] as libc::pid_t, libc::SIGKILL);
        }
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

/// `?idle-secs=` on the clamd address is how long a client that sends nothing
/// keeps its connection, in the pool and in the thread model.
#[test]
fn a_clamd_client_that_sends_nothing_is_let_go_after_the_address_idle_wait() {
    for workers in ["1", "threads"] {
        let sigs = sig_dir();
        let port = free_port();
        let _server = Server::start(
            TempDir::new().unwrap(),
            &[
                "--workers",
                workers,
                "--listen",
                &format!("clamd://127.0.0.1:{port}?idle-secs=1"),
                "-d",
                sigs.path().to_str().unwrap(),
            ],
        );
        assert_eq!(clamd_ping(port), "PONG", "workers={workers}");
        let mut quiet = dial(port, "clamd");
        let start = Instant::now();
        let mut buf = [0u8; 16];
        let got = quiet.read(&mut buf);
        let waited = start.elapsed();
        assert!(matches!(got, Ok(0) | Err(_)), "workers={workers}: {got:?}");
        assert!(
            waited >= Duration::from_millis(800) && waited < Duration::from_secs(20),
            "workers={workers}: {waited:?}"
        );
    }
}

/// `?idle-secs=` on a `--listen-health` address is how long its client has, in
/// the pool and in the thread model.
#[test]
fn a_health_client_that_sends_nothing_is_let_go_after_the_address_idle_wait() {
    for workers in ["1", "threads"] {
        let sigs = sig_dir();
        let (port, health) = (free_port(), free_port());
        let _server = Server::start(
            TempDir::new().unwrap(),
            &[
                "--workers",
                workers,
                "--listen",
                &format!("clamd://127.0.0.1:{port}"),
                "--listen-health",
                &format!("clamd://127.0.0.1:{health}?idle-secs=1"),
                "-d",
                sigs.path().to_str().unwrap(),
            ],
        );
        assert_eq!(clamd_ping(health), "PONG", "workers={workers}");
        let mut quiet = dial(health, "health");
        let start = Instant::now();
        let mut buf = [0u8; 16];
        let got = quiet.read(&mut buf);
        let waited = start.elapsed();
        assert!(matches!(got, Ok(0) | Err(_)), "workers={workers}: {got:?}");
        // Under the 5 s the listener gives without it.
        assert!(
            waited >= Duration::from_millis(800) && waited < Duration::from_millis(4000),
            "workers={workers}: {waited:?}"
        );
    }
}

/// `--build-db` makes the directories its output goes in, as a volume mounted
/// empty in a container has none.
#[test]
fn a_database_is_built_into_a_directory_that_does_not_exist_yet() {
    let sigs = sig_dir();
    let out = sigs.path().join("new").join("dir").join("out.exavdb");
    let run = Command::new(exav_bin())
        .args(["--sig-dir", sigs.path().to_str().unwrap(), "--build-db"])
        .arg(&out)
        .env_remove("EXAV_SIG_SOURCES")
        .output()
        .expect("run exav");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(exav_core::database::is_database_file(&out));
}

/// The environment configures a container, and a flag on the command line
/// overrides it, never the other way round, and never by refusing the flag.
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

/// One clamd command answered in `limit`, or `None` when nothing came back.
fn clamd_command_within(port: u16, command: &[u8], limit: Duration) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(limit)).ok()?;
    s.write_all(command).ok()?;
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    // A reply ends at its terminator; the connection may stay open after it.
    while !out.ends_with(&[0]) && !out.ends_with(b"\n") {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    (!out.is_empty()).then(|| {
        String::from_utf8_lossy(&out)
            .trim_end_matches('\0')
            .trim()
            .into()
    })
}

/// A `PING` to the scan listener waits for a worker, and a health listener
/// does not: with the only worker held in a job, the first gets no answer and
/// the second, and `exav --ping` pointed at the same configuration, do.
#[test]
fn a_health_listener_answers_while_every_worker_is_busy() {
    let sigs = sig_dir();
    let (clamd, health) = (free_port(), free_port());
    let listen = format!("clamd://127.0.0.1:{clamd}");
    let listen_health = format!("clamd://127.0.0.1:{health}");
    let args = [
        "--workers",
        "1",
        "--listen",
        &listen,
        "--listen-health",
        &listen_health,
        "--sig-dir",
        sigs.path().to_str().unwrap(),
    ];
    let _server = Server::start(TempDir::new().unwrap(), &args);
    assert_eq!(clamd_ping(clamd), "PONG");
    // The worker, held in an INSTREAM that never ends.
    let mut busy = dial(clamd, "clamd");
    busy.write_all(b"zINSTREAM\0").unwrap();
    busy.write_all(&4u32.to_be_bytes()).unwrap();
    busy.write_all(b"ab").unwrap();
    std::thread::sleep(Duration::from_millis(500));

    assert_eq!(
        clamd_command_within(clamd, b"zPING\0", Duration::from_secs(2)),
        None,
        "the scan listener has no worker to answer with"
    );
    let started = Instant::now();
    let reply = until_answered("health ping", || {
        clamd_command_within(health, b"zPING\0", Duration::from_secs(5))
            .ok_or_else(|| io::Error::other("no reply"))
    });
    assert_eq!(reply, "PONG");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    let version = clamd_command_within(health, b"zVERSION\0", Duration::from_secs(5)).unwrap();
    assert!(version.starts_with("ClamAV "), "{version}");
    let refused =
        clamd_command_within(health, b"zSCAN /etc/passwd\0", Duration::from_secs(5)).unwrap();
    assert!(
        refused.contains("only PING, VERSION and STATS"),
        "{refused}"
    );

    let ping = Command::new(exav_bin())
        .args([
            "--ping",
            "--listen",
            &listen,
            "--listen-health",
            &listen_health,
        ])
        .output()
        .expect("run exav --ping");
    assert!(
        ping.status.success(),
        "exav --ping: {}",
        String::from_utf8_lossy(&ping.stderr)
    );
    assert!(String::from_utf8_lossy(&ping.stdout).contains(&health.to_string()));
    drop(busy);
}

/// What a process that scanned nothing reports of the pool: the scans the
/// workers made. Each worker counted into its own
/// memory before, so the health child (and any worker asked) said "0".
#[test]
fn stats_are_the_pools_from_any_process() {
    let sigs = sig_dir();
    let (clamd, health) = (free_port(), free_port());
    let _server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "3",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--listen-health",
            &format!("clamd://127.0.0.1:{health}"),
            "--sig-dir",
            sigs.path().to_str().unwrap(),
        ],
    );
    for _ in 0..6 {
        assert!(clamd_instream(clamd, eicar()).contains("FOUND"));
    }
    let field = |stats: &str, name: &str| -> u64 {
        let rest = stats.split(&format!("{name} ")).nth(1).unwrap_or_default();
        rest.split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("no {name} in {stats}"))
    };
    let stats = |port: u16| {
        until_answered("stats", || {
            clamd_command_within(port, b"zSTATS\0", Duration::from_secs(5))
                .map(|s| s.replace('\0', ""))
                .ok_or_else(|| io::Error::other("no reply"))
        })
    };
    let from_health = stats(health);
    assert!(from_health.contains("SCANSTATS"), "{from_health}");
    assert!(field(&from_health, "scans") >= 6, "{from_health}");
    assert!(field(&from_health, "infected") >= 6, "{from_health}");
    // The same from a worker, which has handled only some of the six.
    assert!(field(&stats(clamd), "scans") >= 6);
}

#[test]
fn an_icap_health_listener_answers_options_and_refuses_the_rest() {
    for workers in ["1", "threads"] {
        let sigs = sig_dir();
        let (clamd, health) = (free_port(), free_port());
        let _server = Server::start(
            TempDir::new().unwrap(),
            &[
                "--workers",
                workers,
                "--listen",
                &format!("clamd://127.0.0.1:{clamd}"),
                "--listen-health",
                &format!("icap://127.0.0.1:{health}"),
                "--sig-dir",
                sigs.path().to_str().unwrap(),
            ],
        );
        let ask = |method: &str| {
            until_answered("health request", || {
                let mut s = dial(health, "icap health");
                s.write_all(
                    format!(
                        "{method} icap://127.0.0.1:{health}/avscan ICAP/1.0\r\nHost: h\r\n\r\n"
                    )
                    .as_bytes(),
                )?;
                let mut out = Vec::new();
                s.read_to_end(&mut out)?;
                Ok(String::from_utf8_lossy(&out).into_owned())
            })
        };
        assert!(ask("OPTIONS").starts_with("ICAP/1.0 200 OK"), "{workers}");
        assert!(ask("REQMOD").starts_with("ICAP/1.0 405 "), "{workers}");
    }
}

#[test]
fn a_health_listener_without_a_scan_listener_is_refused() {
    let out = Command::new(exav_bin())
        .args(["--allow-no-db", "--listen-health", "clamd://127.0.0.1:1"])
        .output()
        .expect("run exav");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--listen-health"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// What a client that sends a command a byte at a time is answered, per
/// protocol: `INSTREAM` on clamd, a `RESPMOD` body on ICAP. Each byte arrives
/// well inside the per-read timeouts, so only a limit on the whole command can
/// stop it. After the last byte each client ends its command properly. Returns
/// the two answers.
fn slow_clients(clamd: u16, icap: u16, bytes: usize, gap: Duration) -> (String, String) {
    fn drip(
        s: &TcpStream,
        bytes: usize,
        gap: Duration,
        end: &'static [u8],
    ) -> std::thread::JoinHandle<()> {
        let mut w = s.try_clone().unwrap();
        std::thread::spawn(move || {
            for _ in 0..bytes {
                if w.write_all(b"a").is_err() {
                    return;
                }
                std::thread::sleep(gap);
            }
            let _ = w.write_all(end);
        })
    }
    fn read_all(mut s: TcpStream) -> String {
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).trim_end_matches('\0').into()
    }

    let mut s = dial(clamd, "clamd");
    s.write_all(b"zINSTREAM\0").unwrap();
    s.write_all(&(bytes as u32).to_be_bytes()).unwrap();
    // The terminating zero-length chunk.
    let sender = drip(&s, bytes, gap, &[0, 0, 0, 0]);
    let on_clamd = read_all(s);
    sender.join().unwrap();

    let mut s = dial(icap, "icap");
    let http = "HTTP/1.1 200 OK\r\n\r\n";
    s.write_all(
        format!(
            "RESPMOD icap://127.0.0.1:{icap}/avscan ICAP/1.0\r\nHost: h\r\nConnection: close\r\n\
             Encapsulated: res-hdr=0, res-body={}\r\n\r\n{http}{bytes:x}\r\n",
            http.len()
        )
        .as_bytes(),
    )
    .unwrap();
    let sender = drip(&s, bytes, gap, b"\r\n0\r\n\r\n");
    let on_icap = read_all(s);
    sender.join().unwrap();
    (on_clamd, on_icap)
}

/// A client that sends a command a byte at a time, each inside the per-read
/// timeout, is cut off at `?request-secs=`: on both protocols, in both worker
/// models. The answer says why, the log says it too, and the daemon serves the
/// next client.
#[test]
fn a_client_that_sends_a_byte_at_a_time_is_cut_off_at_the_command_read_limit() {
    for workers in ["2", "threads"] {
        let sigs = sig_dir();
        let (clamd, icap) = (free_port(), free_port());
        let server = Server::start(
            TempDir::new().unwrap(),
            &[
                "--workers",
                workers,
                "--listen",
                &format!("clamd://127.0.0.1:{clamd}?request-secs=1"),
                "--listen",
                &format!("icap://127.0.0.1:{icap}?request-secs=1"),
                "-d",
                sigs.path().to_str().unwrap(),
            ],
        );
        assert_eq!(clamd_ping(clamd), "PONG", "workers={workers}");
        wait_for_log(&server, "serving ICAP on tcp:");

        // 100 bytes at 100 ms would take ten seconds.
        let (on_clamd, on_icap) = slow_clients(clamd, icap, 100, Duration::from_millis(100));
        assert_eq!(on_clamd, "COMMAND READ TIMED OUT\n", "workers={workers}");
        assert!(
            on_icap.starts_with("ICAP/1.0 408 Request Timeout"),
            "workers={workers}: {on_icap}"
        );
        wait_for_log(&server, "took longer than ?request-secs=");

        let verdict = clamd_instream(clamd, ALPHA);
        assert!(
            verdict.contains("Exav.Test.Alpha"),
            "workers={workers}: the daemon serves the next client, got {verdict:?}"
        );
    }
}

/// The same slow clients are served when the limit is off.
#[test]
fn a_slow_client_is_served_when_the_command_read_limit_is_off() {
    let sigs = sig_dir();
    let (clamd, icap) = (free_port(), free_port());
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "threads",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}?request-secs=off"),
            "--listen",
            &format!("icap://127.0.0.1:{icap}?request-secs=off"),
            "-d",
            sigs.path().to_str().unwrap(),
        ],
    );
    assert_eq!(clamd_ping(clamd), "PONG");
    wait_for_log(&server, "serving ICAP on tcp:");
    // 10 bytes at 150 ms is more than the 1 second the other test allows.
    let (on_clamd, on_icap) = slow_clients(clamd, icap, 10, Duration::from_millis(150));
    assert_eq!(on_clamd, "stream: OK");
    assert!(on_icap.starts_with("ICAP/1.0 200 OK"), "{on_icap}");
}

/// A one-shot scan of an EICAR file, with `env` set and `args` added: the
/// output, and the file's name for the verdict to be found in.
fn scan_eicar_with(env: &[(&str, &str)], args: &[&str]) -> (std::process::Output, String) {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("eicar.txt");
    std::fs::write(&file, eicar()).unwrap();
    let file = file.to_str().unwrap().to_string();
    let out = Command::new(exav_bin())
        .args(["--allow-no-db"])
        .args(args)
        .arg(&file)
        .envs(env.iter().copied())
        .output()
        .expect("run exav");
    (out, file)
}

/// An image that sets a listener's settings for its daemon also runs one-shot
/// scans. A setting that only the environment gave is dropped with a warning,
/// and the scan runs and finds what is there; `EXAV_LISTEN` set too, as the
/// published image does, changes nothing.
#[test]
fn a_listener_setting_in_the_environment_does_not_stop_a_one_shot_scan() {
    for with_listen in [false, true] {
        let mut env = vec![
            ("EXAV_MAX_JOBS_PER_WORKER", "5"),
            ("EXAV_LISTEN_HEALTH", "clamd://127.0.0.1:2"),
            ("EXAV_WORKERS", "2"),
        ];
        if with_listen {
            env.push(("EXAV_LISTEN", "clamd://127.0.0.1:1"));
        }
        let (out, file) = scan_eicar_with(&env, &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "listen {with_listen}: {stderr}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&format!("{file}: ")),
            "the scan ran"
        );
        for var in [
            "EXAV_MAX_JOBS_PER_WORKER",
            "EXAV_LISTEN_HEALTH",
            "EXAV_WORKERS",
        ] {
            assert!(
                stderr.contains(&format!("ignoring {var}:")),
                "listen {with_listen}, {var}: {stderr}"
            );
        }
    }
}

/// The same settings typed on the command line are a contradiction and stay
/// refused, also when the variable is set to something else.
#[test]
fn a_listener_setting_on_the_command_line_stops_a_one_shot_scan() {
    for (flag, var) in [
        ("--workers", "EXAV_WORKERS"),
        ("--max-jobs-per-worker", "EXAV_MAX_JOBS_PER_WORKER"),
    ] {
        for env in [&[][..], &[(var, "9")][..]] {
            let (out, _) = scan_eicar_with(env, &[flag, "5"]);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(2), "{flag}: {stderr}");
            assert!(stderr.contains(flag), "{flag}: {stderr}");
            assert!(!stderr.contains("ignoring"), "{flag}: {stderr}");
        }
    }
}

/// A clamd session that sends commands and never reads the replies. The
/// replies fill the sockets and the server's write blocks. The stream is
/// returned to keep the connection open; the sender stops when it closes.
fn client_that_never_reads(port: u16) -> TcpStream {
    let s = dial(port, "clamd");
    flood_without_reading(s.try_clone().unwrap());
    s
}

/// The same over a Unix socket.
fn unix_client_that_never_reads(path: &Path) -> std::os::unix::net::UnixStream {
    let s = until_answered("connection", || {
        std::os::unix::net::UnixStream::connect(path)
    });
    flood_without_reading(s.try_clone().unwrap());
    s
}

/// Sends a session's worth of commands from a thread of its own, stopping when
/// the connection closes.
fn flood_without_reading(mut w: impl Write + Send + 'static) {
    std::thread::spawn(move || {
        if w.write_all(b"zIDSESSION\0").is_err() {
            return;
        }
        let burst = b"zVERSIONCOMMANDS\0".repeat(1000);
        for _ in 0..100 {
            if w.write_all(&burst).is_err() {
                return;
            }
        }
    });
}

/// A clamd `PING` over a Unix socket.
fn unix_ping(path: &Path) -> String {
    until_answered("ping", || {
        let mut s = std::os::unix::net::UnixStream::connect(path)?;
        s.set_read_timeout(Some(Duration::from_secs(30)))?;
        s.write_all(b"zPING\0")?;
        let mut out = Vec::new();
        s.read_to_end(&mut out)?;
        Ok(String::from_utf8_lossy(&out).trim_end_matches('\0').into())
    })
}

const NOT_READING: &str = "did not read its reply within ?idle-secs=";

/// A client that stops reading is cut off once a write has waited
/// `?idle-secs=`, in both worker models and on both kinds of socket; the log
/// says why and the daemon serves the next client.
#[test]
fn a_client_that_never_reads_is_cut_by_the_idle_wait() {
    for workers in ["2", "threads"] {
        for unix in [false, true] {
            let sigs = sig_dir();
            let dir = TempDir::new().unwrap();
            let sock = dir.path().join("clamd.sock");
            let clamd = free_port();
            let address = if unix {
                format!("{}?idle-secs=1", sock.display())
            } else {
                format!("clamd://127.0.0.1:{clamd}?idle-secs=1")
            };
            let server = Server::start(
                TempDir::new().unwrap(),
                &[
                    "--workers",
                    workers,
                    "--listen",
                    &address,
                    "-d",
                    sigs.path().to_str().unwrap(),
                ],
            );
            let what = format!("workers={workers}, unix={unix}");
            let ping = || {
                if unix {
                    unix_ping(&sock)
                } else {
                    clamd_ping(clamd)
                }
            };
            assert_eq!(ping(), "PONG", "{what}");
            let _tcp;
            let _unix;
            if unix {
                _unix = Some(unix_client_that_never_reads(&sock));
            } else {
                _tcp = Some(client_that_never_reads(clamd));
            }
            wait_for_log(&server, NOT_READING);
            assert_eq!(ping(), "PONG", "{what}");
        }
    }
}

/// Within the default idle wait (120 s) the same client holds its connection,
/// and a daemon in the thread model still serves others meanwhile.
#[test]
fn a_client_that_never_reads_keeps_its_connection_within_the_idle_wait() {
    let sigs = sig_dir();
    let clamd = free_port();
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "threads",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "-d",
            sigs.path().to_str().unwrap(),
        ],
    );
    assert_eq!(clamd_ping(clamd), "PONG");
    let _stuck = client_that_never_reads(clamd);
    // Longer than the 1 second the other test allows.
    std::thread::sleep(Duration::from_secs(4));
    assert!(
        !server.stderr().contains(NOT_READING),
        "{}",
        server.stderr()
    );
    assert_eq!(clamd_ping(clamd), "PONG");
}

/// `?reply-secs=` on the clamd address cuts a client that stops reading in
/// the time it names, though each write has the 120 s of the idle wait; in
/// both worker models and on both kinds of socket.
#[test]
fn a_client_that_never_reads_is_cut_by_the_address_reply_budget() {
    for workers in ["2", "threads"] {
        for unix in [false, true] {
            let sigs = sig_dir();
            let dir = TempDir::new().unwrap();
            let sock = dir.path().join("clamd.sock");
            let clamd = free_port();
            let address = if unix {
                format!("{}?reply-secs=1", sock.display())
            } else {
                format!("clamd://127.0.0.1:{clamd}?reply-secs=1")
            };
            let server = Server::start(
                TempDir::new().unwrap(),
                &[
                    "--workers",
                    workers,
                    "--listen",
                    &address,
                    "-d",
                    sigs.path().to_str().unwrap(),
                ],
            );
            let what = format!("workers={workers}, unix={unix}");
            let ping = || {
                if unix {
                    unix_ping(&sock)
                } else {
                    clamd_ping(clamd)
                }
            };
            assert_eq!(ping(), "PONG", "{what}");
            let _tcp;
            let _unix;
            if unix {
                _unix = Some(unix_client_that_never_reads(&sock));
            } else {
                _tcp = Some(client_that_never_reads(clamd));
            }
            wait_for_log(&server, NOT_READING);
            assert_eq!(ping(), "PONG", "{what}");
        }
    }
}

/// `?session-secs=` on the clamd address ends a connection after that long,
/// whatever the idle wait, in both worker models.
#[test]
fn a_clamd_connection_is_closed_at_the_address_lifetime() {
    for workers in ["1", "threads"] {
        let sigs = sig_dir();
        let port = free_port();
        let _server = Server::start(
            TempDir::new().unwrap(),
            &[
                "--workers",
                workers,
                "--listen",
                &format!("clamd://127.0.0.1:{port}?session-secs=1"),
                "-d",
                sigs.path().to_str().unwrap(),
            ],
        );
        assert_eq!(clamd_ping(port), "PONG", "workers={workers}");
        let mut session = dial(port, "clamd");
        let start = Instant::now();
        session.write_all(b"zIDSESSION\0").unwrap();
        // A client that keeps talking: the idle wait never runs out.
        let mut answered = 0;
        let ended = loop {
            if start.elapsed() > Duration::from_secs(20) {
                break false;
            }
            let mut reply = [0u8; 32];
            if session.write_all(b"zPING\0").is_err() {
                break true;
            }
            match session.read(&mut reply) {
                Ok(n) if n > 0 => answered += 1,
                _ => break true,
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        let lived = start.elapsed();
        assert!(ended, "workers={workers}: still answering after {lived:?}");
        assert!(answered >= 1, "workers={workers}");
        assert!(
            lived >= Duration::from_millis(800) && lived < Duration::from_secs(15),
            "workers={workers}: {lived:?}"
        );
    }
}

/// A process out of descriptors cannot accept, and the connection it fails
/// for stays queued. The listener waits and tries again rather than ending the
/// daemon, and serves the queued client once descriptors are free.
#[test]
fn a_clamd_listener_out_of_descriptors_keeps_accepting() {
    let sigs = sig_dir();
    let clamd = free_port();
    let mut server = Server::start_with_descriptor_limit(
        TempDir::new().unwrap(),
        24,
        &[
            "--workers",
            "threads",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "-d",
            sigs.path().to_str().unwrap(),
        ],
    );
    assert_eq!(clamd_ping(clamd), "PONG");
    // More idle connections than the server has descriptors for.
    let mut idle: Vec<TcpStream> = (0..40).map(|_| dial(clamd, "clamd")).collect();
    wait_for_log(&server, "accept failed, trying again");
    let mut last = idle.pop().unwrap();
    last.write_all(b"zPING\0").unwrap();
    // The others hang up, which frees the descriptors of the accepted ones.
    drop(idle);
    let mut out = Vec::new();
    last.read_to_end(&mut out).unwrap();
    assert_eq!(out, b"PONG\0", "{}", server.stderr());
    assert!(
        matches!(server.child.try_wait(), Ok(None)),
        "the daemon ended:\n{}",
        server.stderr()
    );
}

/// A process's limit of kind `resource` (a `libc::RLIMIT_*` as an `i32`), after
/// setting its soft limit to `soft` when given. The hard limit stays.
#[cfg(target_os = "linux")]
fn soft_limit(pid: u32, resource: i32, soft: Option<u64>) -> u64 {
    let pid = pid as libc::pid_t;
    let mut old = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: both pointers are valid for the call; the new limit is null.
    let rc = unsafe { libc::prlimit(pid, resource as _, std::ptr::null(), &mut old) };
    assert_eq!(rc, 0, "prlimit: {}", io::Error::last_os_error());
    if let Some(rlim_cur) = soft {
        let new = libc::rlimit {
            rlim_cur,
            rlim_max: old.rlim_max,
        };
        // SAFETY: as above, with the old limit pointer null.
        let rc = unsafe { libc::prlimit(pid, resource as _, &new, std::ptr::null_mut()) };
        assert_eq!(rc, 0, "prlimit: {}", io::Error::last_os_error());
    }
    old.rlim_cur
}

/// The lowest descriptor number a process has not got open, which is the next
/// it gets: a limit of this many leaves it unable to open anything more.
#[cfg(target_os = "linux")]
fn next_descriptor(pid: u32) -> u64 {
    let open: std::collections::BTreeSet<u64> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("the process's descriptors")
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    (0..).find(|n| !open.contains(n)).unwrap()
}

/// Ten idle connections to `port`. They stay open until the vector is dropped.
#[cfg(target_os = "linux")]
fn hold_connections(port: u16, what: &str) -> Vec<TcpStream> {
    (0..10).map(|_| dial(port, what)).collect()
}

/// An ICAP `OPTIONS` request and its whole answer.
#[cfg(target_os = "linux")]
fn icap_options(port: u16) -> String {
    let mut s = dial(port, "icap");
    s.write_all(
        format!(
            "OPTIONS icap://127.0.0.1:{port}/avscan ICAP/1.0\r\nHost: 127.0.0.1\r\n\
             Connection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// The ICAP listener and the health listener also fail an accept when the
/// process is out of descriptors. They wait between attempts instead of
/// spinning, which would fill the log and use a core, and serve again once
/// descriptors are free.
///
/// The limit is set to the next descriptor number, so that no accept can
/// succeed and each keeps failing until it is lifted.
#[cfg(target_os = "linux")]
#[test]
fn the_icap_and_health_listeners_wait_between_accepts_that_fail() {
    let sigs = sig_dir();
    let (clamd, icap, health) = (free_port(), free_port(), free_port());
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "threads",
            "--listen",
            &format!("clamd://127.0.0.1:{clamd}"),
            "--listen",
            &format!("icap://127.0.0.1:{icap}"),
            "--listen-health",
            &format!("clamd://127.0.0.1:{health}"),
            "-d",
            sigs.path().to_str().unwrap(),
        ],
    );
    assert_eq!(clamd_ping(health), "PONG");
    wait_for_log(&server, "serving ICAP on tcp:");
    let pid = server.child.id();
    let nofile = libc::RLIMIT_NOFILE as i32;
    let usual = soft_limit(pid, nofile, None);

    for (name, port, needle) in [
        ("icap", icap, "icap: accept failed"),
        ("health", health, "health: accept on"),
    ] {
        // Whatever the last round left open has closed.
        std::thread::sleep(Duration::from_millis(500));
        soft_limit(pid, nofile, Some(next_descriptor(pid)));
        let held = hold_connections(port, name);
        wait_for_log(&server, needle);
        std::thread::sleep(Duration::from_millis(1500));
        // A pause that doubles from 5 ms to 1 s allows about ten lines in the
        // time; a loop with no pause writes thousands.
        let n = server.stderr().matches(needle).count();
        assert!(n <= 40, "{n} lines of {needle:?}");

        // Back to the usual limit, and the held connections closed: the
        // listener serves again.
        soft_limit(pid, nofile, Some(usual));
        drop(held);
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let answered = if name == "icap" {
                icap_options(port).starts_with("ICAP/1.0 200 OK")
            } else {
                clamd_ping(port) == "PONG"
            };
            if answered {
                break;
            }
            assert!(Instant::now() < deadline, "{name} never answered again");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// A process that cannot start a thread for a connection drops that connection
/// and keeps listening: the thread model gives each connection a thread, and a
/// failed spawn would otherwise end the accepting thread and leave a daemon with
/// no listener that still looks alive. The limit on processes is lowered once
/// the daemon is up, so that only the new connection's thread fails.
#[cfg(target_os = "linux")]
#[test]
fn a_clamd_listener_that_cannot_start_a_thread_keeps_accepting() {
    let sigs = sig_dir();
    let clamd = free_port();
    let server = Server::start(
        TempDir::new().unwrap(),
        &[
            "--workers",
            "threads",
            "--listen",
            // Two connections at most: a connection that failed to start must
            // give its place back, or the third would find none.
            &format!("clamd://127.0.0.1:{clamd}?max-connections=2"),
            "-d",
            sigs.path().to_str().unwrap(),
        ],
    );
    assert_eq!(clamd_ping(clamd), "PONG");
    let pid = server.child.id();
    let nproc = libc::RLIMIT_NPROC as i32;
    let usual = soft_limit(pid, nproc, None);
    soft_limit(pid, nproc, Some(1));
    let answers: Vec<Vec<u8>> = (0..3)
        .map(|_| {
            let mut refused = dial(clamd, "clamd");
            let _ = refused.write_all(b"zPING\0");
            let mut out = Vec::new();
            let _ = refused.read_to_end(&mut out);
            out
        })
        .collect();
    // Restored before anything is asserted, so a failure does not leave the
    // daemon unable to start threads.
    soft_limit(pid, nproc, Some(usual));
    assert!(
        answers.iter().all(Vec::is_empty),
        "answered without a thread: {answers:?}"
    );
    wait_for_log(&server, "no thread for a new connection");
    assert_eq!(clamd_ping(clamd), "PONG", "{}", server.stderr());
}

/// Paths outside a temp dir are never touched by this suite; the helper exists
/// so a stray absolute path in a future test fails to compile rather than
/// scanning the developer's disk.
#[allow(dead_code)]
fn under_temp(p: &Path) -> bool {
    p.starts_with(std::env::temp_dir())
}
