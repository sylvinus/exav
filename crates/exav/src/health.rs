//! Health listeners (`--listen-health`): an address that answers "are you
//! there?" and nothing else, in the protocol of its scheme.
//!
//! Why a listener of its own. The clamd pool's workers take one job at a time
//! and accept from the kernel's backlog, so a `PING` sent while every worker is
//! in a long scan waits for one to finish, and a container health check that
//! times out restarts a daemon that is only busy. Nothing here scans, loads a
//! database or waits for a worker, so it answers however the rest is doing:
//!
//! * `clamd://…` answers `PING` with `PONG`, `VERSION` with the version line
//!   and `STATS` with the pool's totals (the counters are shared by the
//!   processes of the pool), and any other command with an error that names the
//!   listener.
//! * `icap://…` answers `OPTIONS`, and `405` to a method that would adapt
//!   anything.
//!
//! Under the pool the listeners are served by one child of their own, forked,
//! reaped and re-forked with the workers; in the thread model by threads. Each
//! connection gets a thread, up to `?max-connections=` (64 by default), and a
//! client has `?idle-secs=` ([`DEFAULT_CLIENT_TIMEOUT`] by default) to say its
//! piece and take the reply, so a listener nobody authenticates cannot be used
//! to hold threads.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::daemon;
use crate::endpoint::{Addr, Endpoint, Proto};

/// Connections served at once unless the address says (`?max-connections=`).
pub(crate) const DEFAULT_MAX_CONNECTIONS: usize = 64;

/// How long a client has to send its request and take the reply, unless the
/// address says (`?idle-secs=`).
const DEFAULT_CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest an ICAP request head is read.
const ICAP_HEAD_MAX: u64 = 8192;

/// What `OPTIONS` is answered with: the one method, and no body.
const ICAP_OPTIONS: &str = "ICAP/1.0 200 OK\r\nMethods: OPTIONS\r\nService: exav health\r\n\
                            ISTag: \"exav-health\"\r\nEncapsulated: null-body=0\r\n\
                            Connection: close\r\n\r\n";

/// What any other method is answered with.
const ICAP_NOT_ALLOWED: &str = "ICAP/1.0 405 Method Not Allowed\r\nService: exav health\r\n\
                                ISTag: \"exav-health\"\r\nEncapsulated: null-body=0\r\n\
                                Connection: close\r\n\r\n";

enum Sock {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixListener),
}

/// A bound health listener.
pub(crate) struct Listener {
    sock: Sock,
    proto: Proto,
    max: usize,
    /// How long a connection is served.
    within: Duration,
    /// For the log.
    name: String,
}

type Halves = (Box<dyn Read + Send>, Box<dyn Write + Send>);

impl Listener {
    /// Binds `e`, before anything is forked, so a busy port is reported by the
    /// process that was asked to listen.
    pub(crate) fn bind(e: &Endpoint) -> io::Result<Self> {
        let sock = match &e.addr {
            Addr::Tcp(a) => Sock::Tcp(TcpListener::bind(a)?),
            #[cfg(unix)]
            Addr::Unix { path, mode } => Sock::Unix(daemon::bind_unix_socket(
                path,
                mode.unwrap_or(daemon::DEFAULT_SOCKET_MODE),
            )?),
            #[cfg(not(unix))]
            Addr::Unix { .. } => {
                return Err(io::Error::other(
                    "a Unix-socket address needs a Unix platform",
                ));
            }
        };
        Ok(Listener {
            sock,
            proto: e.proto,
            max: e.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            within: e
                .idle_secs
                .map_or(DEFAULT_CLIENT_TIMEOUT, Duration::from_secs),
            name: e.to_string(),
        })
    }

    #[cfg(unix)]
    fn raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        match &self.sock {
            Sock::Tcp(l) => l.as_raw_fd(),
            Sock::Unix(l) => l.as_raw_fd(),
        }
    }

    #[cfg(unix)]
    fn set_nonblocking(&self) -> io::Result<()> {
        match &self.sock {
            Sock::Tcp(l) => l.set_nonblocking(true),
            Sock::Unix(l) => l.set_nonblocking(true),
        }
    }

    fn accept(&self) -> io::Result<Halves> {
        match &self.sock {
            Sock::Tcp(l) => {
                let (s, _) = l.accept()?;
                // An accepted socket can inherit the listener's non-blocking mode.
                s.set_nonblocking(false)?;
                s.set_read_timeout(Some(self.within))?;
                s.set_write_timeout(Some(self.within))?;
                let w = s.try_clone()?;
                Ok((Box::new(s), Box::new(w)))
            }
            #[cfg(unix)]
            Sock::Unix(l) => {
                let (s, _) = l.accept()?;
                s.set_nonblocking(false)?;
                s.set_read_timeout(Some(self.within))?;
                s.set_write_timeout(Some(self.within))?;
                let w = s.try_clone()?;
                Ok((Box::new(s), Box::new(w)))
            }
        }
    }
}

/// The version line `VERSION` answers.
pub(crate) type Version = Arc<dyn Fn() -> String + Send + Sync>;

/// Serves `l` until the generation `retire` belongs to is retired (never, when
/// there is none). A connection is a thread, counted against the listener's
/// limit; one past it is closed unanswered.
fn serve(l: &Listener, version: &Version, retire: Option<i32>) {
    let live = Arc::new(AtomicUsize::new(0));
    let mut backoff = daemon::AcceptBackoff::default();
    loop {
        #[cfg(unix)]
        if let Some(fd) = retire
            && !daemon::await_connection(l.raw_fd(), fd)
        {
            return;
        }
        #[cfg(not(unix))]
        let _ = retire;
        match l.accept() {
            Ok((r, w)) => {
                backoff.reset();
                if live.fetch_add(1, Ordering::Relaxed) >= l.max {
                    live.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }
                let (live, version, proto) = (Arc::clone(&live), Arc::clone(version), l.proto);
                let within = l.within;
                std::thread::spawn(move || {
                    handle(proto, r, w, version.as_ref(), within);
                    live.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => {
                let pause = backoff.pause();
                eprintln!(
                    "exav: health: accept on {} failed, trying again in {} ms: {e}",
                    l.name,
                    pause.as_millis()
                );
                std::thread::sleep(pause);
            }
        }
    }
}

/// A connection's reads, which fail once its time is up: the socket's timeout
/// bounds each read, this all of them, so a client that sends a byte at a
/// time cannot hold the connection.
struct Deadline<R> {
    inner: R,
    end: Instant,
}

impl<R: Read> Read for Deadline<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.end {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the client took too long",
            ));
        }
        self.inner.read(buf)
    }
}

/// One connection, in the protocol of its listener, read for `within`.
fn handle(
    proto: Proto,
    r: Box<dyn Read + Send>,
    mut w: Box<dyn Write + Send>,
    version: &dyn Fn() -> String,
    within: Duration,
) {
    let r = Box::new(Deadline {
        inner: r,
        end: Instant::now() + within,
    });
    match proto {
        Proto::Clamd => clamd(r, &mut w, version),
        Proto::Icap => icap(r, &mut w),
    }
}

/// `PING` and `VERSION`, a few to a connection as clamd's sessions allow.
fn clamd(r: Box<dyn Read + Send>, mut w: &mut dyn Write, version: &dyn Fn() -> String) {
    let mut r = BufReader::new(r);
    for _ in 0..8 {
        let (cmd, delim) = match daemon::read_command(&mut r) {
            Ok(Some(c)) => c,
            Ok(None) => return,
            Err(e) => {
                daemon::write_refusal(&mut w, None, &e);
                return;
            }
        };
        let word = daemon::Command::parse(&cmd).word;
        let reply = if word.eq_ignore_ascii_case("PING") {
            "PONG".to_string()
        } else if word.eq_ignore_ascii_case("VERSION") {
            version()
        } else if word.eq_ignore_ascii_case("STATS") {
            daemon::stats_reply()
        } else {
            "health listener: only PING, VERSION and STATS are answered ERROR".to_string()
        };
        if daemon::write_reply(&mut w, None, reply.as_bytes(), delim).is_err() {
            return;
        }
    }
}

/// `OPTIONS`, and a refusal of everything else. The request head is read, so a
/// client that sent it whole is not reset on the reply.
fn icap(r: Box<dyn Read + Send>, w: &mut dyn Write) {
    let mut r = BufReader::new(r.take(ICAP_HEAD_MAX));
    let mut line = String::new();
    if r.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    loop {
        let mut header = String::new();
        match r.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) if header.trim().is_empty() => break,
            Ok(_) => {}
        }
    }
    let reply = if line
        .split_whitespace()
        .next()
        .is_some_and(|m| m.eq_ignore_ascii_case("OPTIONS"))
    {
        ICAP_OPTIONS
    } else {
        ICAP_NOT_ALLOWED
    };
    let _ = w.write_all(reply.as_bytes());
    let _ = w.flush();
}

/// The thread model: each listener on a thread of its own.
pub(crate) fn spawn(listeners: Vec<Listener>, version: Version) {
    for l in listeners {
        eprintln!("exav: health listener on {}", l.name);
        let version = Arc::clone(&version);
        std::thread::spawn(move || serve(&l, &version, None));
    }
}

/// The pool: one child serves every health listener. It never touches a worker
/// or the scan path, and a reload re-forks it with the rest, which is all it
/// needs (the version line is read from the new database).
#[cfg(unix)]
pub(crate) fn side_listener(listeners: Vec<Listener>) -> daemon::SideListener {
    let listeners: Vec<Arc<Listener>> = listeners.into_iter().map(Arc::new).collect();
    daemon::SideListener {
        name: "health".to_string(),
        serve: Box::new(move |db, _opts, retire| {
            let line = daemon::clamav_version(&db);
            let version: Version = Arc::new(move || line.clone());
            let mut threads = Vec::new();
            for l in &listeners {
                if let Err(e) = l.set_nonblocking() {
                    eprintln!("exav: health: listener stopped: {e}");
                    std::process::exit(2);
                }
                eprintln!("exav: health listener on {}", l.name);
                let (l, version) = (Arc::clone(l), Arc::clone(&version));
                threads.push(std::thread::spawn(move || {
                    serve(&l, &version, Some(retire))
                }));
            }
            let ok = threads.into_iter().all(|t| t.join().is_ok());
            std::process::exit(if ok { 0 } else { 2 });
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn answer(proto: Proto, request: &[u8]) -> String {
        let r: Box<dyn Read + Send> = Box::new(Cursor::new(request.to_vec()));
        let out = Arc::new(std::sync::Mutex::new(Vec::new()));
        struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        handle(
            proto,
            r,
            Box::new(Sink(Arc::clone(&out))),
            &|| "ClamAV test".to_string(),
            DEFAULT_CLIENT_TIMEOUT,
        );
        String::from_utf8_lossy(&out.lock().unwrap()).into_owned()
    }

    #[test]
    fn a_client_that_sends_a_byte_at_a_time_is_cut_off() {
        /// A byte every 2 ms, never a line's end, for `LEFT` reads.
        struct Slow(Arc<AtomicUsize>);
        const LEFT: usize = 500;
        impl Read for Slow {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                std::thread::sleep(Duration::from_millis(2));
                if self.0.fetch_add(1, Ordering::Relaxed) >= LEFT {
                    return Ok(0);
                }
                match b.first_mut() {
                    Some(x) => {
                        *x = b'x';
                        Ok(1)
                    }
                    None => Ok(0),
                }
            }
        }
        for proto in [Proto::Clamd, Proto::Icap] {
            let reads = Arc::new(AtomicUsize::new(0));
            handle(
                proto,
                Box::new(Slow(Arc::clone(&reads))),
                Box::new(io::sink()),
                &String::new,
                Duration::from_millis(40),
            );
            // A read takes at least 2 ms, so 40 ms allow 20 of them, whatever
            // the load; the client's 500 would take a second.
            let reads = reads.load(Ordering::Relaxed);
            assert!(reads <= 20, "{proto:?}: {reads} reads");
        }
    }

    #[test]
    fn clamd_answers_ping_and_version_in_either_framing() {
        assert_eq!(answer(Proto::Clamd, b"zPING\0"), "PONG\0");
        assert_eq!(answer(Proto::Clamd, b"nPING\n"), "PONG\n");
        assert_eq!(answer(Proto::Clamd, b"PING\n"), "PONG\n");
        assert_eq!(answer(Proto::Clamd, b"nVERSION\n"), "ClamAV test\n");
        assert_eq!(
            answer(Proto::Clamd, b"nping\nnVERSION\n"),
            "PONG\nClamAV test\n"
        );
    }

    #[test]
    fn clamd_answers_nothing_that_scans() {
        for cmd in [&b"nSCAN /etc/passwd\n"[..], b"nINSTREAM\n", b"nRELOAD\n"] {
            let reply = answer(Proto::Clamd, cmd);
            assert!(
                reply.contains("only PING, VERSION and STATS") && reply.ends_with("ERROR\n"),
                "{reply}"
            );
        }
    }

    #[test]
    fn clamd_answers_stats_with_the_counters() {
        let reply = answer(Proto::Clamd, b"nSTATS\n");
        assert!(reply.starts_with("POOLS: 1"), "{reply}");
        assert!(reply.contains("SCANSTATS: scans "), "{reply}");
        assert!(reply.trim_end().ends_with("END"), "{reply}");
    }

    /// A command the listener cannot read is answered, in its framing, before
    /// the connection closes: the scan listener's reply for the same command.
    #[test]
    fn clamd_answers_a_command_it_refuses_to_read() {
        let mut long = b"nPING ".to_vec();
        long.resize(200_000, b'x');
        let reply = answer(Proto::Clamd, &long);
        assert_eq!(reply, "command line exceeds limit ERROR\n");
    }

    #[test]
    fn icap_answers_options_and_refuses_the_methods_that_adapt() {
        let options = answer(
            Proto::Icap,
            b"OPTIONS icap://h/avscan ICAP/1.0\r\nHost: h\r\n\r\n",
        );
        assert!(options.starts_with("ICAP/1.0 200 OK\r\n"), "{options}");
        assert!(options.contains("Methods: OPTIONS"));
        for method in ["REQMOD", "RESPMOD"] {
            let reply = answer(
                Proto::Icap,
                format!("{method} icap://h/avscan ICAP/1.0\r\nHost: h\r\n\r\n").as_bytes(),
            );
            assert!(reply.starts_with("ICAP/1.0 405 "), "{reply}");
        }
        assert_eq!(answer(Proto::Icap, b""), "");
    }
}
