//! Persistent daemon mode: load the database once, then serve scan requests
//! over a socket so callers pay no per-scan cold-start cost.
//!
//! The wire protocol is a subset of the `clamd` protocol, so existing
//! tooling (`clamdscan`, milters, `clamd` client libraries) can talk to exav
//! unchanged. Commands may be framed with a `z` prefix (NUL-terminated) or `n`
//! prefix (newline-terminated); replies use the same terminator.
//!
//! Supported commands:
//!   `PING`                 -> `PONG`
//!   `VERSION`              -> `exav <version>`
//!   `STATS`                -> a short status block ending with `END`
//!   `RELOAD`               -> `RELOADING`; in the prefork pool this signals the
//!                             supervisor to re-read the data dir and re-fork the
//!                             workers with the new signatures (the mechanism a
//!                             stock `freshclam`'s `NotifyClamd` drives)
//!   `SCAN <path>`          -> `<path>: OK` / `<path>: <sig> FOUND` / `… ERROR`
//!   `CONTSCAN <path>`      -> recurse a directory, one reply line per file
//!   `MULTISCAN <path>`     -> alias of CONTSCAN
//!   `INSTREAM`             -> scan a `<u32 len><data>…<u32 0>` chunked stream.
//!                             The payload is materialized to a seekable source
//!                             (kept in RAM when small, spilled to an auto-deleted
//!                             temp file when large) and given the FULL
//!                             container-aware scan — so malware inside an archive
//!                             is detected, matching clamd. Bounded by
//!                             `--max-input-bytes` (disk is the ceiling). Reply
//!                             `stream: …`
//!   `EXINSTREAM`           -> exav extension: same chunk framing as INSTREAM, but
//!                             the payload is buffered (≤ `--max-input-bytes`) and
//!                             run through full container-aware analysis, and the
//!                             reply is ONE line of compact JSON with the nested
//!                             match location. Schema (compact, no raw newlines):
//!                               {"status":"OK","v":1}
//!                               {"v":1,"status":"FOUND","signature":S
//!                                 [,"location":"outer.zip/…/inside.txt"]}
//!                                 (location present only for a NESTED hit; it is
//!                                 the `/`-joined container member-name path from
//!                                 the stream to the matched leaf — control bytes
//!                                 sanitised, capped ~512 chars)
//!                               {"v":1,"status":"PARTIAL","category":C[,"reason":R]}
//!                                 (C ∈ LIMITS-EXCEEDED / UNSCANNABLE /
//!                                 PASSWORD-PROTECTED / TRUNCATED — a stream that
//!                                 was not fully scanned is PARTIAL, NEVER OK)
//!                               {"v":1,"status":"ERROR","reason":R}
//!                                 (transient/infra failure the client may retry,
//!                                 or a PARTIAL under `--partial-as error`)
//!                             `status` is the same four-word vocabulary the CLI
//!                             prints and `--json` emits, and each word names the
//!                             exit code a one-shot scan would give: OK 0,
//!                             FOUND 1, ERROR 2, PARTIAL 3.
//!                             Verdict classification matches INSTREAM (a
//!                             detection beats a limit; one detection per scan).
//!                             Unknown to old clients → `UNKNOWN COMMAND` (below).
//!   `EXINSTREAM MULTI`     -> exav extension: several files in ONE request, so a
//!                             multi-volume archive split across them (`x.7z.001`,
//!                             `.002`, …) is rejoined and scanned as the one
//!                             archive it is — sent one at a time, no part decodes
//!                             and every one of them replies `clean`. Framing,
//!                             repeated per file:
//!                               `<u32 name_len><name>` then the INSTREAM chunk
//!                               sequence `<u32 len><data>…<u32 0>`
//!                             ended by a zero `name_len`. A name is a LABEL, not
//!                             a path: nothing here opens or resolves it. Reply:
//!                               {"v":1,"files":[{"name":N,…verdict fields…},…]}
//!                             each entry carrying the same fields as a single
//!                             EXINSTREAM reply, plus "set" when the verdict came
//!                             from a rejoined archive rather than the file itself.
//!   `SCANURL <url>`        -> exav extension: scan an http(s)// object via
//!                             range requests (no download); reply `<url>: …`
//!   `IDSESSION` / `END`    -> session mode; each reply is prefixed `<n>: `
//!
//! A limit that prevents a full scan is reported as `ERROR` carrying
//! `LIMITS-EXCEEDED`, never a silent `OK` (exav's core invariant).

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use exav_core::{
    analyze_all_with_outcome, scan_path, scan_seekable_located, scan_stream, AllMatchOutcome,
    ScanOptions, ScanReport, Scanner, VerdictCategory,
};
use walkdir::WalkDir;

/// Worker/thread count advertised as `max` in the clamd-compatible `STATS`
/// reply. Set once at daemon startup (prefork: the configured worker count) and
/// inherited by every forked worker via copy-on-write. `0` = unset (unit tests
/// and direct `dispatch` calls), where [`daemon_max_workers`] falls back to the
/// host's CPU parallelism.
static DAEMON_MAX_WORKERS: AtomicUsize = AtomicUsize::new(0);

/// The `max` thread count to report in `STATS`, falling back to CPU parallelism
/// when the daemon startup hook hasn't run (tests / direct dispatch).
fn daemon_max_workers() -> usize {
    match DAEMON_MAX_WORKERS.load(Ordering::Relaxed) {
        0 => std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        n => n,
    }
}

/// The clamd-compatible `VERSION` string: `ClamAV <flevel-release>/<db-version>/
/// <db-build-time>` when a signed container is loaded (what `clamdtop` parses
/// into its ENGINE / DBVER / DBTIME columns), degrading to just `ClamAV
/// <release>` for the loose-signature / built-in-baseline case (no container to
/// report a version for).
fn clamav_version(db: &Scanner) -> String {
    match db.db_version() {
        Some((ver, btime)) => format!(
            "ClamAV {}/{}/{}",
            crate::CLAMAV_COMPAT_VERSION,
            ver,
            ctime_from_btime(btime)
        ),
        None => format!("ClamAV {}", crate::CLAMAV_COMPAT_VERSION),
    }
}

/// Reformat a CVD build-time (`"17 Jul 2026 06-24 +0000"`) into the ctime-style
/// stamp clamd puts in its `VERSION` reply (`"Fri Jul 17 06:24:00 2026"`), the
/// shape `clamdtop` parses for its DBTIME column. The input's own timezone is
/// preserved (UTC in practice); on any parse failure the original string is
/// returned unchanged so a client still sees *something*.
fn ctime_from_btime(btime: &str) -> String {
    fn parse(btime: &str) -> Option<String> {
        const MON: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        const WDAY: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
        let mut it = btime.split_whitespace();
        let day: u32 = it.next()?.parse().ok()?;
        let mon_name = it.next()?;
        let year: i64 = it.next()?.parse().ok()?;
        let (hh, mm) = it.next()?.split_once(['-', ':'])?;
        let mon = MON.iter().position(|m| m.eq_ignore_ascii_case(mon_name))? + 1;
        // Sakamoto's algorithm: day-of-week (0 = Sunday) for a Gregorian date.
        let t = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
        let y = if mon < 3 { year - 1 } else { year };
        let w = ((y + y / 4 - y / 100 + y / 400 + t[mon - 1] + day as i64) % 7 + 7) % 7;
        Some(format!(
            "{} {} {:>2} {}:{}:00 {}",
            WDAY[w as usize],
            MON[mon - 1],
            day,
            hh,
            mm,
            year
        ))
    }
    parse(btime).unwrap_or_else(|| btime.to_string())
}

/// A reader that can also surface file descriptors passed over the socket as
/// `SCM_RIGHTS` ancillary data (the `FILDES` command). Non-fd transports
/// (TCP) just return `None`.
trait FdSource {
    fn take_fd(&mut self) -> Option<File>;
}

impl<R: Read + FdSource> FdSource for BufReader<R> {
    fn take_fd(&mut self) -> Option<File> {
        self.get_mut().take_fd()
    }
}

impl FdSource for &TcpListenerStream {
    fn take_fd(&mut self) -> Option<File> {
        None
    }
}

/// Newtype so we can give `&TcpStream` an `FdSource` impl (TCP can't pass fds).
struct TcpListenerStream(std::net::TcpStream);

impl Read for &TcpListenerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.0).read(buf)
    }
}
impl Write for &TcpListenerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.0).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&self.0).flush()
    }
}

/// A `UnixStream` reader that captures any `SCM_RIGHTS` file descriptors
/// arriving alongside the data (used by the `FILDES` command). Every read is a
/// `recvmsg` so an fd is captured whether it accompanies the command bytes or a
/// follow-up packet.
#[cfg(unix)]
struct AncillaryReader<'a> {
    stream: &'a std::os::unix::net::UnixStream,
    fds: Vec<std::os::fd::RawFd>,
}

#[cfg(unix)]
impl<'a> AncillaryReader<'a> {
    fn new(stream: &'a std::os::unix::net::UnixStream) -> Self {
        Self {
            stream,
            fds: Vec::new(),
        }
    }

    /// One `recvmsg` into `buf`, draining any passed fds into `self.fds`.
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::fd::{AsRawFd, RawFd};
        // Control buffer sized for a handful of fds.
        let mut cmsg = [0u8; 256];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY: msghdr is zeroed then populated with valid pointers/lengths
        // into `iov`/`cmsg`, which outlive the call.
        let n = unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg.len() as _;
            let n = libc::recvmsg(self.stream.as_raw_fd(), &mut msg, 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            // Walk the control messages for SCM_RIGHTS fd arrays.
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(c);
                    let payload = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    let count = payload / std::mem::size_of::<RawFd>();
                    for i in 0..count {
                        let mut fd: RawFd = -1;
                        std::ptr::copy_nonoverlapping(
                            data.add(i * std::mem::size_of::<RawFd>()),
                            &mut fd as *mut RawFd as *mut u8,
                            std::mem::size_of::<RawFd>(),
                        );
                        if fd >= 0 {
                            self.fds.push(fd);
                        }
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
            n
        };
        Ok(n as usize)
    }
}

#[cfg(unix)]
impl Read for AncillaryReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf)
    }
}

#[cfg(unix)]
impl FdSource for AncillaryReader<'_> {
    fn take_fd(&mut self) -> Option<File> {
        use std::os::fd::FromRawFd;
        if self.fds.is_empty() {
            // The fd may be in a follow-up packet (≥1 data byte + ancillary).
            let mut scratch = [0u8; 64];
            let _ = self.recv(&mut scratch);
        }
        // SAFETY: the fd was just received over the socket; we take ownership
        // so the returned File closes it on drop.
        self.fds.pop().map(|fd| unsafe { File::from_raw_fd(fd) })
    }
}

/// Send `cmd` on `stream` with `fd` attached as `SCM_RIGHTS` ancillary data —
/// the client half of `FILDES`, and the one thing a plain `write` cannot do.
///
/// The descriptor the daemon receives is its own, pointing at the same open
/// file: it reads the bytes this client already has access to, without needing
/// permission on the path or a view of this filesystem.
#[cfg(unix)]
pub(crate) fn send_fd_command(
    stream: &std::os::unix::net::UnixStream,
    cmd: &[u8],
    fd: std::os::fd::RawFd,
) -> io::Result<()> {
    use std::os::fd::{AsRawFd, RawFd};
    const FD_SIZE: usize = std::mem::size_of::<RawFd>();
    let mut iov = libc::iovec {
        iov_base: cmd.as_ptr() as *mut libc::c_void,
        iov_len: cmd.len(),
    };
    // `usize` rather than `u8`: a control buffer has to be aligned for
    // `cmsghdr`, and a byte array carries no such guarantee.
    let mut control = [0usize; 8];
    // SAFETY: msghdr is zeroed and then populated with pointers into `iov` and
    // `control`, both of which outlive the call. The control buffer is large
    // enough for one `SCM_RIGHTS` header plus one descriptor, and `msg_controllen`
    // says so; `fd` stays open for the whole call, since the caller holds the
    // `File` it came from.
    let sent = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(FD_SIZE as u32) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(FD_SIZE as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(c),
            FD_SIZE,
        );
        libc::sendmsg(stream.as_raw_fd(), &msg, 0)
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    // A short send would leave the daemon reading a truncated command with the
    // descriptor already attached, which it would answer as an unknown command.
    if (sent as usize) < cmd.len() {
        return Err(io::Error::other("short send passing the file descriptor"));
    }
    Ok(())
}

#[cfg(unix)]
impl Drop for AncillaryReader<'_> {
    fn drop(&mut self) {
        // Close any descriptors that arrived over the socket but were never
        // consumed by `take_fd`, so a client passing extra or unsolicited
        // `SCM_RIGHTS` fds cannot leak them across connections and exhaust
        // `RLIMIT_NOFILE`.
        for fd in self.fds.drain(..) {
            // SAFETY: each fd was received on this socket and is owned by us;
            // nothing else holds it.
            unsafe {
                libc::close(fd);
            }
        }
    }
}

/// Where the daemon listens.
pub enum ListenAddr {
    /// Unix domain socket at this path, created with these permission bits.
    #[cfg(unix)]
    Unix { path: std::path::PathBuf, mode: u32 },
    /// TCP `host:port`.
    Tcp(String),
}

/// Permissions a Unix socket gets when its address carries no `?mode=`: owner
/// only. Widening it is an explicit act, because every user the mode admits can
/// submit scan jobs to the daemon and read the verdicts.
#[cfg(unix)]
pub const DEFAULT_SOCKET_MODE: u32 = 0o600;

/// Longest command line (selectors + path) the daemon will buffer. INSTREAM
/// payload is read separately by length-prefixed chunks, not via this path.
const MAX_COMMAND: usize = 64 * 1024;

/// Concurrent client connections accepted when the address does not say.
///
/// Each connection gets its own thread, so without a cap a flood of them would
/// exhaust threads and memory. `?max-connections=` on the address overrides it,
/// which is how a deployment that fans out more clients than this raises it
/// without a flag that would have to name a protocol to apply to.
pub const DEFAULT_MAX_CONNECTIONS: usize = 128;

/// Per-read socket timeout. Bounds how long a connection may block the daemon
/// waiting for the client to send data (a command, or the next INSTREAM chunk),
/// so a slow/idle client — the classic slow-loris — can't pin a connection slot
/// (or, in the thread model where there is no per-job kill, a worker) forever.
/// Applied to every accepted stream; a stall past this closes the connection.
const SOCKET_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// True for I/O errors that are a normal client disconnect (or the read-timeout
/// above), which should close the connection quietly rather than log as an error.
fn is_benign_disconnect(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
    )
}

/// RAII counter: decrements the live-connection count when the handler thread
/// exits (normally or via panic).
struct ConnGuard(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Run the daemon until the listener errors (e.g. the process is killed).
/// `allow_shutdown` controls whether the `SHUTDOWN` command stops the daemon
/// (here it exits the process; the thread model has no supervisor to unwind).
///
/// The database arrives already shared so one load can answer on more than one
/// listener in the same process.
pub fn run(
    db: Arc<Scanner>,
    addr: ListenAddr,
    opts: Arc<ScanOptions>,
    allow_shutdown: bool,
    max_connections: usize,
) -> io::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let conns = Arc::new(AtomicUsize::new(0));
    // A client that disconnects right after reading a reply delivers SIGPIPE on
    // the next write. `main` set the default disposition — which kills the
    // process — so that a one-shot scan piped into `head` ends quietly; a
    // listener wants the opposite. Ignoring it makes the write fail with EPIPE
    // and cost one connection instead of the daemon.
    #[cfg(unix)]
    // SAFETY: sets this process's own disposition for one signal, before any
    // connection is accepted or any worker forked.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    match addr {
        #[cfg(unix)]
        ListenAddr::Unix { path, mode } => {
            let listener = bind_unix_socket(&path, mode)?;
            eprintln!("exav: daemon listening on unix:{}", path.display());
            for stream in listener.incoming() {
                let stream = stream?;
                let _ = stream.set_read_timeout(Some(SOCKET_READ_TIMEOUT));
                if conns.fetch_add(1, Ordering::Relaxed) >= max_connections {
                    conns.fetch_sub(1, Ordering::Relaxed);
                    continue; // at capacity — drop the connection
                }
                let (db, opts, c) = (Arc::clone(&db), Arc::clone(&opts), Arc::clone(&conns));
                std::thread::spawn(move || {
                    let _guard = ConnGuard(c);
                    // The fd-capturing reader handles FILDES; the writer is a
                    // second borrow of the same stream (full-duplex socket).
                    let reader = AncillaryReader::new(&stream);
                    // Thread model: no per-job kill, so the per-command timer is a
                    // no-op; the read timeout above is what bounds a stalled client.
                    let shutdown = || {
                        if allow_shutdown {
                            std::process::exit(0)
                        } else {
                            false
                        }
                    };
                    if let Err(e) = handle_conn(
                        reader,
                        &stream,
                        &db,
                        &opts,
                        &|| {},
                        &|| {},
                        &|| {},
                        &shutdown,
                    ) {
                        if !is_benign_disconnect(&e) {
                            eprintln!("exav: connection error: {e}");
                        }
                    }
                });
            }
            Ok(())
        }
        ListenAddr::Tcp(addr) => {
            let listener = TcpListener::bind(&addr)?;
            eprintln!("exav: daemon listening on tcp:{addr}");
            for stream in listener.incoming() {
                let tcp = stream?;
                let _ = tcp.set_read_timeout(Some(SOCKET_READ_TIMEOUT));
                let stream = TcpListenerStream(tcp);
                if conns.fetch_add(1, Ordering::Relaxed) >= max_connections {
                    conns.fetch_sub(1, Ordering::Relaxed);
                    continue; // at capacity — drop the connection
                }
                let (db, opts, c) = (Arc::clone(&db), Arc::clone(&opts), Arc::clone(&conns));
                std::thread::spawn(move || {
                    let _guard = ConnGuard(c);
                    let shutdown = || {
                        if allow_shutdown {
                            std::process::exit(0)
                        } else {
                            false
                        }
                    };
                    if let Err(e) = handle_conn(
                        &stream,
                        &stream,
                        &db,
                        &opts,
                        &|| {},
                        &|| {},
                        &|| {},
                        &shutdown,
                    ) {
                        if !is_benign_disconnect(&e) {
                            eprintln!("exav: connection error: {e}");
                        }
                    }
                });
            }
            Ok(())
        }
    }
}

// ───────────────────────── prefork worker pool (Unix) ─────────────────────
//
// `--workers N` switches the daemon from the in-process thread model above to a
// pool of N persistent worker *processes*. Each worker handles one scan at a
// time (sequentially), so a single job can be bounded and, if it goes rogue,
// killed without touching any other in-flight work — the one thing the thread
// model cannot do safely at all (no safe thread-kill in Rust/C).
//
// Why processes / why Unix-only here:
//   * Workers `fork()` from the parent *after* the DB is loaded and warmed, so
//     the (large, read-only) signature DB is shared via copy-on-write — no
//     re-load, low memory.
//   * They inherit the listening socket and `accept()` on it directly, so the
//     full clamd protocol (incl. `FILDES` fd-passing via `SCM_RIGHTS`) is
//     handled in the worker with zero parent relay.
//   * Limits are enforced by the kernel, the only layer that can stop a stuck
//     call inside a dependency: `RLIMIT_AS` (memory) / `RLIMIT_CPU` (CPU time)
//     trigger a kernel kill, and a per-job `setitimer(SIGALRM)` whose handler
//     `_exit()`s gives a hard wall-clock bound even on a non-yielding CPU loop.
//   * Workers recycle after `max_jobs` to bound slow leaks/fragmentation; the
//     supervisor respawns them by forking from the clean parent (pristine COW).
//
// This is the deterministic-caps backstop (Layer 3): the in-core
// `max_scanned_bytes`/ratio/recursion caps still fire first and identically in
// both models — the pool only adds the hard kill for the residual tail.

/// Exit code a worker uses when its per-job wall-clock alarm fires.
#[cfg(unix)]
const EXIT_TIMEOUT: i32 = 17;

/// Configuration for prefork worker-pool mode. A `0` limit means "unbounded".
#[cfg(unix)]
pub struct PoolConfig {
    /// Number of worker processes (== max concurrent scans).
    pub workers: usize,
    /// Hard wall-clock budget per scan job (`SIGALRM` → `_exit`).
    pub max_scan_time: std::time::Duration,
    /// Per-worker address-space cap in bytes (`RLIMIT_AS`).
    pub max_memory_bytes: u64,
    /// Per-worker CPU-seconds cap (`RLIMIT_CPU`; kernel `SIGXCPU`/`SIGKILL`).
    pub max_cpu_secs: u64,
    /// Recycle a worker after this many jobs (bounds slow leaks).
    pub max_jobs: u64,
    /// Whether the `SHUTDOWN` command is honoured (clamd default: yes). When
    /// false, `SHUTDOWN` replies with an error instead of stopping the daemon —
    /// useful when the socket/port is reachable by untrusted clients.
    pub allow_shutdown: bool,
}

/// A bound listening socket the workers share across `fork()`.
#[cfg(unix)]
enum BoundListener {
    Unix(std::os::unix::net::UnixListener),
    Tcp(TcpListener),
}

#[cfg(unix)]
fn bind_listener(addr: &ListenAddr) -> io::Result<BoundListener> {
    match addr {
        ListenAddr::Unix { path, mode } => Ok(BoundListener::Unix(bind_unix_socket(path, *mode)?)),
        ListenAddr::Tcp(a) => Ok(BoundListener::Tcp(TcpListener::bind(a)?)),
    }
}

/// Bind the daemon's Unix socket at `path` with permission bits `mode`.
///
/// `bind` takes the socket's mode from the process umask, so the socket is
/// listening before any `chmod` runs and, under a permissive umask, listening
/// at 0777 while it does. Binding under a umask of 0777 instead creates it with
/// no permissions at all: the only mode a client can ever find on the path is
/// the one asked for. A failed `chmod` is fatal for the same reason — the
/// socket would otherwise stay at mode 000 and refuse everyone silently.
///
/// The path itself is still a name another process can replace between the two
/// calls if it can write the directory, so a socket belongs somewhere only its
/// owner can write — `$XDG_RUNTIME_DIR` or `/var/run`, not world-writable
/// `/tmp`, where another local user can pre-create the path.
#[cfg(unix)]
fn bind_unix_socket(
    path: &std::path::Path,
    mode: u32,
) -> io::Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    // Remove a stale socket from a previous run before binding.
    let _ = std::fs::remove_file(path);
    // SAFETY: `umask` reads and writes only the calling process's own mask.
    // The daemon binds before it forks its workers or spawns any thread, so no
    // other file is being created while the mask is restrictive.
    let saved = unsafe { libc::umask(0o777) };
    let listener = std::os::unix::net::UnixListener::bind(path);
    // SAFETY: as above; restores the mask the process was started with.
    unsafe { libc::umask(saved) };
    let listener = listener?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    if mode & 0o007 != 0 {
        eprintln!(
            "exav: socket {} is mode {mode:03o}: any local user can submit scans \
             to this daemon and read the verdicts",
            path.display()
        );
    }
    Ok(listener)
}

/// Set to true by the parent's SIGTERM/SIGINT handler so the supervisor loop
/// tears the pool down instead of respawning.
#[cfg(unix)]
static SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set to true when a DB reload is requested: by SIGHUP (which a worker raises on
/// a `RELOAD` command, and which the CLI's background updater raises after a
/// successful download) or by the supervisor noticing the data dir changed on
/// disk. The supervisor drains it each tick and re-forks the pool.
#[cfg(unix)]
static RELOAD_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn on_shutdown(_sig: libc::c_int) {
    SHUTDOWN.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(unix)]
extern "C" fn on_sighup(_sig: libc::c_int) {
    RELOAD_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Empty handler whose only job is to interrupt the supervisor's `nanosleep`
/// (handlers are installed without `SA_RESTART`) so a worker exit is reaped
/// promptly rather than after the full poll interval.
#[cfg(unix)]
extern "C" fn on_sigchld(_sig: libc::c_int) {}

/// Public so the CLI's updater thread can raise a reload after writing new
/// signatures to the data dir (equivalent to sending `RELOAD` over the socket).
/// Only called from the `http-update`-gated updater, so it's dead otherwise.
#[cfg(unix)]
#[cfg_attr(not(feature = "http-update"), allow(dead_code))]
pub fn request_reload() {
    RELOAD_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
    // Also poke the process so a sleeping supervisor wakes immediately.
    unsafe {
        libc::kill(libc::getpid(), libc::SIGHUP);
    }
}

/// The supervisor's **idle** poll cadence — the upper bound on how long a
/// *signal-less* database change (a sidecar that writes the volume without
/// `RELOAD`) can go unnoticed. Everything urgent is signal-driven and interrupts
/// the sleep immediately, so this timer's only job is the mtime poll: a worker
/// exit (SIGCHLD) triggers instant reap+respawn, `RELOAD`/the updater/`SIGHUP`
/// trigger an instant reload, and SIGTERM/SIGINT an instant shutdown. It is
/// therefore a few seconds, not sub-second — polling the filesystem twice a
/// second for a database that changes a few times a day would wake the process
/// (and, on an NFS-mounted DB directory, generate GETATTR/READDIR traffic) for
/// nothing. Still ~60× more responsive than clamd's 600 s `SelfCheck`; use
/// `RELOAD`/`NotifyClamd`/`SIGHUP` when you want a change picked up instantly.
#[cfg(unix)]
const SUPERVISOR_TICK: std::time::Duration = std::time::Duration::from_secs(10);

/// Newest mtime of the watched source — the reload trigger for a sidecar that
/// writes the volume without sending `RELOAD` (clamd's `SelfCheck`). For a
/// **directory** this is the newest mtime **across the whole tree**: the loader
/// reads the directory recursively (including the updater's `env/<host>/…`
/// subtree), so the watch must too — an in-place overwrite deep in the tree bumps
/// only its own directory's mtime, which a top-level-only scan would miss. For a
/// single **file** (a prebuilt database) it is just that file's mtime — an atomic
/// swap replaces it with a newer-mtime inode, so the poll fires. `None` if the
/// path can't be stat'd. Symlinks are not followed (no cycles).
///
/// Also the ICAP server's reload trigger, which is why it is not Unix-gated:
/// that server runs on every platform.
#[cfg(any(unix, feature = "icap"))]
pub(crate) fn datadir_mtime(dir: &std::path::Path) -> Option<std::time::SystemTime> {
    let mut newest = std::fs::metadata(dir).and_then(|m| m.modified()).ok()?;
    // WalkDir over a file yields just that file, so this also covers the
    // single-`.exavdb` case (leaving `newest` at the file's own mtime).
    for entry in WalkDir::new(dir).follow_links(false).into_iter().flatten() {
        if let Some(t) = entry.metadata().ok().and_then(|m| m.modified().ok()) {
            if t > newest {
                newest = t;
            }
        }
    }
    Some(newest)
}

/// Sleep, but return early if a signal arrives (no `SA_RESTART`).
#[cfg(unix)]
fn nap(d: std::time::Duration) {
    let ts = libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as _,
    };
    unsafe {
        libc::nanosleep(&ts, std::ptr::null_mut());
    }
}

/// The worker's per-job wall-clock alarm. Terminating immediately is the whole
/// point: the scan blew its time budget (possibly stuck inside a dependency
/// that never returns to a cooperative checkpoint), and there is no safe way to
/// unwind in-process — so we `_exit` (async-signal-safe) and let the supervisor
/// respawn a replacement.
#[cfg(unix)]
extern "C" fn on_sigalrm(_sig: libc::c_int) {
    unsafe { libc::_exit(EXIT_TIMEOUT) }
}

/// The fd of the connection this worker is currently serving, for the abort
/// handler below. `-1` when idle. A raw atomic because a signal handler may read
/// nothing that could lock.
#[cfg(unix)]
static CURRENT_CONN_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Reply terminator the abort handler emits. Both framings end a reply the
/// client will accept; NUL is what `z`-prefixed commands use and a trailing NUL
/// after a newline is harmless to a line-framed client.
#[cfg(unix)]
const ABORT_REPLY: &[u8] = b": scan aborted (out of memory) ERROR\n\0";

/// Say something before dying.
///
/// A worker killed mid-scan closes its connection with no reply at all, and a
/// clean close is indistinguishable from "scanned, found nothing" — so a crash
/// reads as a clean verdict, which is the one answer a scanner must never give
/// by accident. Measured: 55 worker deaths in an 8,978-file run, every one
/// recorded as clean by the client.
///
/// `SIGABRT` (Rust's allocation-failure path) is catchable, so those can be
/// reported. A `SIGKILL` from the OOM killer cannot be, which is why the client
/// must ALSO treat a silent close as an error — the two fixes are complementary,
/// not alternatives.
///
/// Async-signal-safe: only `write` and `_exit`, no allocation, no locks.
#[cfg(unix)]
extern "C" fn on_sigabrt(_sig: libc::c_int) {
    let fd = CURRENT_CONN_FD.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        unsafe {
            libc::write(
                fd,
                ABORT_REPLY.as_ptr() as *const libc::c_void,
                ABORT_REPLY.len(),
            );
        }
    }
    unsafe { libc::_exit(EXIT_ABORTED) }
}

/// Exit code for a worker that aborted mid-scan and managed to say so.
#[cfg(unix)]
const EXIT_ABORTED: libc::c_int = 91;

#[cfg(unix)]
fn install_handler(sig: libc::c_int, handler: extern "C" fn(libc::c_int)) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        // No SA_RESTART: a signal interrupts blocking syscalls (accept/waitpid)
        // with EINTR so the loops can observe shutdown / fire the alarm.
        sa.sa_flags = 0;
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

#[cfg(unix)]
fn set_rlimit(resource: libc::c_int, limit: u64) {
    if limit == 0 {
        return;
    }
    let rl = libc::rlimit {
        rlim_cur: limit as _,
        rlim_max: limit as _,
    };
    unsafe {
        libc::setrlimit(resource as _, &rl);
    }
}

/// Bytes of address space this process already occupies, from `/proc/self/statm`
/// (page count in field 0). `None` when it cannot be read — the caller then
/// applies the configured cap alone.
///
/// Needed because `RLIMIT_AS` is a whole-process ceiling while the per-job
/// setting is meant to bound a SCAN. The resident signature database sits inside
/// that ceiling and is not part of any job.
#[cfg(unix)]
fn current_address_space() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().next()?.parse().ok()?;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    (page > 0).then(|| pages.saturating_mul(page as u64))
}

/// How much address space one job may use so the whole pool fits in RAM.
///
/// `None` when the host's memory cannot be read, in which case the configured
/// value stands unmodified.
///
/// The signature database is shared copy-on-write by every worker, so it is
/// subtracted ONCE rather than per worker. A slice of RAM is held back for the
/// kernel and everything else on the box — running the machine to exactly zero
/// free just moves the kill from one process to another.
#[cfg(unix)]
/// Bring the in-core extraction budget inside the memory a job is actually
/// granted, so the deterministic cap fires before the kernel one.
///
/// The pool's design puts three layers in a fixed order: the in-core
/// size/ratio/recursion caps decide first and produce a *verdict*
/// (`LIMITS-EXCEEDED`), and `RLIMIT_AS` is only a backstop for the residual
/// tail. That order is not automatic — it holds only while the in-core budget
/// is smaller than the address space the worker gets, and nothing enforced it.
///
/// It did not hold, and the inversion is easy to reach: on a modest host the
/// per-job grant lands below `max_extracted_bytes`, which defaults to 1 GiB.
/// Extraction buffers are charged cumulatively and never released, so a scan
/// can hold most of that budget live at once and meet the kernel limit first.
/// A campaign run turned up dozens of aborts from exactly that. Every one was
/// reported as an error rather than a clean, so nothing was missed — but a scan
/// that should have said "I hit a limit" instead said "I died", which is a
/// worse answer and a noisier one.
///
/// Clamping here restores the intended order. It only ever *lowers* a budget,
/// so it cannot make a scan look at more than the operator asked for.
pub(crate) fn fit_limits_to_job_memory(opts: &mut ScanOptions, job_memory: u64) {
    /// Of the memory a job is granted, the share extraction buffers may claim.
    /// The rest covers the matcher's own working set — chiefly the lowercase
    /// copy it makes of each buffer it scans — plus allocator slack.
    const EXTRACTION_SHARE_NUM: u64 = 1;
    const EXTRACTION_SHARE_DEN: u64 = 2;

    let budget = (job_memory / EXTRACTION_SHARE_DEN) * EXTRACTION_SHARE_NUM;
    if budget == 0 || opts.limits.max_extracted_bytes <= budget {
        return;
    }
    let was = opts.limits.max_extracted_bytes;
    opts.limits.max_extracted_bytes = budget;
    // A single member may not exceed the whole extraction budget either.
    opts.limits.max_buffer_bytes = opts.limits.max_buffer_bytes.min(budget);
    eprintln!(
        "exav: extraction budget {} MiB exceeds the {} MiB of address space available; using {} \
         MiB so a size limit is reported rather than the scan being killed for hitting one",
        was >> 20,
        job_memory >> 20,
        budget >> 20,
    );
}

fn affordable_job_memory(workers: usize, shared_db_bytes: u64) -> Option<u64> {
    /// Leave this fraction of total RAM to the rest of the system.
    ///
    /// A third, not a token slice. A single scan's peak is NOT one buffer: the
    /// matcher allocates a full-size lowercase copy of every buffer it scans for
    /// case-insensitive partitions, and nesting stacks those — a container, its
    /// member and that member's own member each hold a buffer AND a copy while
    /// the walk is inside them. So the per-job figure below is a floor on what a
    /// scan can want, not a ceiling, and the pool has to be sized with room for
    /// several workers to be deep at once.
    ///
    /// A campaign at one eighth was still losing workers to the OOM killer:
    /// the per-worker grants plus the shared database left too little for the
    /// kernel and page cache, and dozens of workers were killed over a single
    /// run. An OOM kill cannot be caught, so it costs a scan its answer
    /// entirely — strictly worse than the scan reporting that it hit a limit,
    /// which is why the headroom is this generous.
    const HEADROOM_NUM: u64 = 1;
    const HEADROOM_DEN: u64 = 3;
    /// Never clamp below this: a job that cannot allocate anything is useless,
    /// and on a tiny host the right answer is to fail loudly elsewhere.
    const FLOOR: u64 = 256 << 20;

    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let total_kb: u64 = meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let total = total_kb.saturating_mul(1024);
    let usable = total
        .saturating_sub(total / HEADROOM_DEN * HEADROOM_NUM)
        .saturating_sub(shared_db_bytes);
    Some((usable / workers.max(1) as u64).max(FLOOR))
}

/// Handler for the one-shot CLI's wall-clock alarm.
///
/// Separate from [`on_sigalrm`], which serves a pool worker that a parent will
/// reap and report on. Here nobody is watching, so the handler has to say what
/// happened itself — through `write(2)`, the only output an async-signal-safe
/// handler may use.
#[cfg(unix)]
extern "C" fn on_oneshot_alarm(_sig: libc::c_int) {
    const MSG: &[u8] = b"exav: scan exceeded --max-scan-time\n";
    unsafe {
        libc::write(2, MSG.as_ptr().cast(), MSG.len());
        // Exit 3, the `PARTIAL` code, rather than the pool's dedicated timeout
        // code: a scan that ran out of time is one more object exav declined to
        // call clean, and it should sort with the others. The handler cannot
        // consult `--partial-as` — reading it here would not be
        // async-signal-safe — so a run that folds partials elsewhere still gets
        // 3 from this path alone.
        libc::_exit(3)
    }
}

/// Apply the wall-clock and address-space caps to a one-shot run.
///
/// The pool gets these from a parent that arms them per job and reports what it
/// reaped. A one-shot run has no parent, so it arms them for itself and lives
/// with the coarser outcome: the process ends rather than the file being
/// reported. That is still better than the alternative, which is a scan that
/// never returns.
///
/// Both are kernel-enforced backstops, not the primary bound. The in-core
/// budgets decide first and produce a verdict; these catch what escapes them —
/// an allocation the budget cannot see, or a decoder that loops without
/// producing output.
#[cfg(unix)]
pub(crate) fn apply_oneshot_limits(max_scan_time: Option<u64>, max_scan_memory: Option<u64>) {
    if let Some(bytes) = max_scan_memory {
        set_rlimit(libc::RLIMIT_AS as libc::c_int, bytes);
    }
    if let Some(secs) = max_scan_time {
        install_handler(libc::SIGALRM, on_oneshot_alarm);
        set_timer(std::time::Duration::from_secs(secs));
    }
}

/// Arm (or, with a zero duration, disarm) the one-shot wall-clock timer.
#[cfg(unix)]
fn set_timer(d: std::time::Duration) {
    let it = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: d.as_secs() as libc::time_t,
            tv_usec: d.subsec_micros() as libc::suseconds_t,
        },
    };
    unsafe {
        libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut());
    }
}

/// A second protocol served from the same pool, in a child process of its own.
///
/// The pool's own workers take one job at a time under kernel-enforced limits,
/// which suits the clamd protocol's short request/response connections. A
/// protocol whose connections are long-lived instead needs its own process, or a
/// few idle clients would occupy every worker; giving it one keeps it sharing
/// the supervisor's warmed database copy-on-write, and being re-forked from the
/// new one on every reload is all the signature swap it needs.
#[cfg(unix)]
pub struct SideListener {
    /// Named in the supervisor's log when the child exits.
    pub name: &'static str,
    /// Serves the listener it captured, in the forked child. Runs until the
    /// process is stopped; returning at all means the listener is gone.
    #[allow(clippy::type_complexity)]
    pub serve: Box<dyn Fn(Arc<Scanner>, Arc<ScanOptions>) + Send + Sync>,
}

/// Run the daemon as a prefork pool of `cfg.workers` worker processes.
///
/// `datadir` (when `Some`) is polled for on-disk changes so a sidecar that writes
/// the volume triggers a reload without sending `RELOAD`. `reload_db` re-reads the
/// signatures; on a `RELOAD`/SIGHUP/data-dir change the supervisor calls it,
/// warms the result, and re-forks the pool with the new DB — a failed reload is
/// logged and the running DB is kept. `side` is an additional listener served by
/// one more child, forked, reaped and reloaded exactly as the workers are.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub fn run_prefork(
    db: Arc<Scanner>,
    addr: ListenAddr,
    opts: Arc<ScanOptions>,
    mut cfg: PoolConfig,
    datadir: Option<std::path::PathBuf>,
    reload_db: &dyn Fn() -> Result<Scanner, String>,
    side: Option<&SideListener>,
) -> io::Result<()> {
    use std::sync::atomic::Ordering;
    // Same SIGPIPE rationale as `run`.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let listener = bind_listener(&addr)?;

    // Warm every lazily-initialised structure (engine automaton, compiled YARA
    // rules) BEFORE forking, so all workers share them read-only via COW rather
    // than each compiling its own private copy on first scan.
    let _ = scan_stream(&db, &b"MZ\x90\x00\x00\x00\x00\x00"[..]);

    // Sized here, before the options are shared: the address space is measured
    // once the database is loaded and warmed, and both the per-job ceiling and
    // the in-core budget that must sit under it are decided from that figure.
    let db_bytes = current_address_space().unwrap_or(0);
    if let Some(afford) = affordable_job_memory(cfg.workers, db_bytes) {
        if cfg.max_memory_bytes > afford {
            eprintln!(
                "exav: per-job memory {} MiB x {} workers exceeds what this host can back; \
                 using {} MiB per job (RAM minus the {} MiB shared database). Raise RAM, \
                 lower --workers, or set a smaller --max-memory to silence this.",
                cfg.max_memory_bytes >> 20,
                cfg.workers,
                afford >> 20,
                db_bytes >> 20,
            );
            cfg.max_memory_bytes = afford;
        }
    }
    let opts = {
        let mut opts = opts;
        fit_limits_to_job_memory(Arc::make_mut(&mut opts), cfg.max_memory_bytes);
        opts
    };

    let mut db = db;

    // Bound the POOL, not just each worker.
    //
    // `RLIMIT_AS` is per process, so N workers at a B-byte budget permit N*B in
    // total — and nothing checked that against the machine. On a 5.9 GB host, 4
    // workers at 2 GiB each permits 8 GiB, so the per-process backstop never
    // fires and the SYSTEM OOM killer picks workers off instead. That is strictly
    // worse: a `SIGKILL` cannot be caught, so the worker dies without answering
    // its client, whereas an `RLIMIT_AS` abort is catchable and reportable.
    //
    // Measured going the wrong way: widening the per-worker ceiling turned 32
    // clean aborts into OOM kills. A crash is worse than a missed detection, and
    // an uncatchable crash is worse than a catchable one.
    //
    // So take the smaller of what was asked for and what the pool can actually
    // afford: (usable RAM - the shared database) / workers. The database is
    // shared copy-on-write across workers, so it is subtracted once, not N times.
    eprintln!(
        "exav: prefork daemon: {} workers; per-job limits: wall {}s, mem {} MiB, cpu {}s; recycle every {} jobs",
        cfg.workers,
        cfg.max_scan_time.as_secs(),
        cfg.max_memory_bytes >> 20,
        cfg.max_cpu_secs,
        cfg.max_jobs,
    );

    // Record the pool size for the STATS `max` field before forking, so every
    // worker inherits it via copy-on-write.
    DAEMON_MAX_WORKERS.store(cfg.workers.max(1), Ordering::Relaxed);

    install_handler(libc::SIGTERM, on_shutdown);
    install_handler(libc::SIGINT, on_shutdown);
    install_handler(libc::SIGHUP, on_sighup);
    install_handler(libc::SIGCHLD, on_sigchld);

    let mut children = std::collections::HashSet::new();
    for _ in 0..cfg.workers {
        children.insert(spawn_worker(&listener, &db, &opts, &cfg)?);
    }
    let mut side_pid = match side {
        Some(s) => Some(spawn_side(s, &db, &opts)?),
        None => None,
    };

    let mut last_mtime = datadir.as_deref().and_then(datadir_mtime);

    // Supervisor: reap exited workers and respawn to keep the count constant,
    // reload signatures on request, until a shutdown signal arrives.
    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }

        // Reap any exited children without blocking, so we can also service
        // reloads and the data-dir poll in this loop.
        loop {
            let mut status: libc::c_int = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                break; // 0 = none exited yet; <0 = no children / error
            }
            let is_side = side_pid == Some(pid);
            if is_side {
                side_pid = None;
            } else {
                children.remove(&pid);
            }
            log_child_exit(pid, status, side.map_or("worker", |s| s.name), is_side);
            if !SHUTDOWN.load(Ordering::Relaxed) {
                if is_side {
                    // Unwrapping is sound: `is_side` is only ever true when a
                    // side listener was configured in the first place.
                    side_pid = Some(spawn_side(
                        side.expect("a side listener exited, so there is one"),
                        &db,
                        &opts,
                    )?);
                } else {
                    children.insert(spawn_worker(&listener, &db, &opts, &cfg)?);
                }
            }
        }

        // Reload trigger: an explicit RELOAD/SIGHUP, or the data dir changed on
        // disk (a sidecar wrote it). Coalesce both into one reload per tick.
        let disk_changed = match datadir.as_deref().and_then(datadir_mtime) {
            Some(t) => {
                let changed = last_mtime.map(|prev| t > prev).unwrap_or(true);
                if changed {
                    last_mtime = Some(t);
                }
                changed
            }
            None => false,
        };
        if RELOAD_REQUESTED.swap(false, Ordering::Relaxed) || disk_changed {
            match reload_db() {
                Ok(new_db) => {
                    eprintln!(
                        "exav: reloading signatures ({} known)",
                        new_db.signature_count()
                    );
                    // Warm before forking so new workers share it COW.
                    let _ = scan_stream(&new_db, &b"MZ\x90\x00\x00\x00\x00\x00"[..]);
                    db = Arc::new(new_db);
                    // Graceful re-fork: bring up a fresh generation from the new
                    // DB, then retire the old children (reaped on the next tick).
                    // The side listener goes with them, which is the whole of its
                    // signature swap — it comes back forked from the new database.
                    let mut old: Vec<libc::pid_t> = children.drain().collect();
                    old.extend(side_pid.take());
                    for _ in 0..cfg.workers {
                        children.insert(spawn_worker(&listener, &db, &opts, &cfg)?);
                    }
                    if let Some(s) = side {
                        side_pid = Some(spawn_side(s, &db, &opts)?);
                    }
                    for pid in old {
                        unsafe {
                            libc::kill(pid, libc::SIGTERM);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("exav: signature reload failed, keeping current DB: {e}");
                }
            }
        }

        nap(SUPERVISOR_TICK);
    }

    // Graceful teardown: signal every child, then reap them.
    let all: Vec<libc::pid_t> = children.iter().copied().chain(side_pid).collect();
    for &pid in &all {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    for &pid in &all {
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
    }
    Ok(())
}

/// Fork the side listener's child. It resets the signal dispositions the
/// supervisor installed, so the supervisor's `SIGTERM` terminates it and no
/// inherited handler fires there, and then never returns.
#[cfg(unix)]
fn spawn_side(
    side: &SideListener,
    db: &Arc<Scanner>,
    opts: &Arc<ScanOptions>,
) -> io::Result<libc::pid_t> {
    use std::io::Write as _;
    let _ = io::stderr().flush();
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                libc::signal(libc::SIGHUP, libc::SIG_DFL);
                libc::signal(libc::SIGCHLD, libc::SIG_DFL);
            }
            (side.serve)(Arc::clone(db), Arc::clone(opts));
            // The listener was the child's whole job, so there is nothing left
            // for it to do but let the supervisor respawn it.
            unsafe { libc::_exit(2) }
        }
        n => Ok(n),
    }
}

#[cfg(unix)]
fn spawn_worker(
    listener: &BoundListener,
    db: &Arc<Scanner>,
    opts: &Arc<ScanOptions>,
    cfg: &PoolConfig,
) -> io::Result<libc::pid_t> {
    // Flush so buffered parent output isn't duplicated into the child.
    use std::io::Write as _;
    let _ = io::stderr().flush();
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => worker_main(listener, db, opts, cfg), // never returns
        n => Ok(n),
    }
}

/// A worker process: bound by the kernel limits, it accepts and serves
/// connections one at a time until it hits its job limit (then exits cleanly so
/// the supervisor recycles it). Never returns.
#[cfg(unix)]
fn worker_main(listener: &BoundListener, db: &Scanner, opts: &ScanOptions, cfg: &PoolConfig) -> ! {
    // Apply the kernel-enforced resource caps to *this* process.
    //
    // `RLIMIT_AS` bounds the WHOLE address space, and this process already holds
    // the signature database, which is most of a gigabyte. Setting the raw
    // configured value would give a scan only what is left over rather than the
    // budget the setting names, and jobs would be killed for exceeding a ceiling
    // nobody asked for. Adding what the process already uses makes the number
    // mean what it says — memory available TO A SCAN.
    //
    // Zero means "no limit", so it must not be added to: `already` is non-zero,
    // and the sum would pin the address space at the worker's current footprint,
    // failing every allocation a scan makes.
    if cfg.max_memory_bytes != 0 {
        let already = current_address_space().unwrap_or(0);
        set_rlimit(
            libc::RLIMIT_AS as libc::c_int,
            cfg.max_memory_bytes.saturating_add(already),
        );
    }
    set_rlimit(libc::RLIMIT_CPU as libc::c_int, cfg.max_cpu_secs);
    install_handler(libc::SIGALRM, on_sigalrm);
    // Report an allocation failure to the client instead of dying silently.
    install_handler(libc::SIGABRT, on_sigabrt);
    // Restore default disposition for the signals the parent handles, so the
    // supervisor's kill terminates us and inherited handlers don't fire here.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGHUP, libc::SIG_DFL);
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
    }
    let arm = || set_timer(cfg.max_scan_time);
    let disarm = || set_timer(std::time::Duration::ZERO);
    // A `RELOAD` command reaches a worker, not the supervisor; forward it by
    // signalling the parent, which owns the pool and does the re-fork.
    let reload = || unsafe {
        libc::kill(libc::getppid(), libc::SIGHUP);
    };
    // `SHUTDOWN` likewise forwards to the supervisor (SIGTERM → graceful
    // teardown of the whole pool). Disabled → report it wasn't honoured.
    let allow_shutdown = cfg.allow_shutdown;
    let shutdown = move || -> bool {
        if allow_shutdown {
            unsafe {
                libc::kill(libc::getppid(), libc::SIGTERM);
            }
            true
        } else {
            false
        }
    };

    let mut jobs = 0u64;
    loop {
        let outcome: io::Result<()> = match listener {
            BoundListener::Unix(l) => match l.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_read_timeout(Some(SOCKET_READ_TIMEOUT));
                    // Record the fd so `on_sigabrt` can answer on this connection
                    // if the scan aborts, instead of closing without a word.
                    CURRENT_CONN_FD.store(
                        std::os::fd::AsRawFd::as_raw_fd(&stream),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    let reader = AncillaryReader::new(&stream);
                    let r =
                        handle_conn(reader, &stream, db, opts, &arm, &disarm, &reload, &shutdown);
                    CURRENT_CONN_FD.store(-1, std::sync::atomic::Ordering::Relaxed);
                    disarm(); // ensure the timer is off between connections
                    r
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => unsafe {
                    eprintln!("exav: worker accept error: {e}");
                    libc::_exit(1);
                },
            },
            BoundListener::Tcp(l) => match l.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_read_timeout(Some(SOCKET_READ_TIMEOUT));
                    // As on the Unix path: without the fd, `on_sigabrt` has
                    // nowhere to send its last word and an aborted scan closes
                    // the connection in silence. TCP is the transport a
                    // containerised daemon serves on, which is where an
                    // unexplained silence costs the most.
                    CURRENT_CONN_FD.store(
                        std::os::fd::AsRawFd::as_raw_fd(&stream),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    let s = TcpListenerStream(stream);
                    let r = handle_conn(&s, &s, db, opts, &arm, &disarm, &reload, &shutdown);
                    CURRENT_CONN_FD.store(-1, std::sync::atomic::Ordering::Relaxed);
                    disarm();
                    r
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => unsafe {
                    eprintln!("exav: worker accept error: {e}");
                    libc::_exit(1);
                },
            },
        };
        if let Err(e) = outcome {
            if !is_benign_disconnect(&e) {
                eprintln!("exav: connection error: {e}");
            }
        }
        jobs += 1;
        if cfg.max_jobs != 0 && jobs >= cfg.max_jobs {
            unsafe { libc::_exit(0) } // recycle: supervisor respawns from clean parent
        }
    }
}

/// Decode a reaped child's wait-status into a human-readable cause, so the
/// operator can see *why* it died (timeout / OOM / CPU / recycle). `side_name`
/// names the extra listener's child when `is_side`; everything else is a worker.
#[cfg(unix)]
fn log_child_exit(pid: libc::pid_t, status: libc::c_int, side_name: &str, is_side: bool) {
    let cause = if libc::WIFEXITED(status) {
        match libc::WEXITSTATUS(status) {
            EXIT_TIMEOUT => "scan wall-clock timeout".to_string(),
            EXIT_ABORTED => "aborted mid-scan (reported to the client)".to_string(),
            0 => "recycled (job limit / clean exit)".to_string(),
            code => format!("exit code {code}"),
        }
    } else if libc::WIFSIGNALED(status) {
        match libc::WTERMSIG(status) {
            libc::SIGKILL => "killed (OOM / RLIMIT_AS)".to_string(),
            libc::SIGXCPU => "CPU-time limit (RLIMIT_CPU)".to_string(),
            libc::SIGABRT => "aborted (allocation failure under RLIMIT_AS)".to_string(),
            sig => format!("signal {sig}"),
        }
    } else {
        "unknown".to_string()
    };
    let what = if is_side { side_name } else { "worker" };
    eprintln!("exav: {what} {pid} exited: {cause}");
}

/// Command terminator, mirrored from the request onto the reply.
#[derive(Clone, Copy, PartialEq)]
enum Delim {
    Newline,
    Null,
}

impl Delim {
    fn byte(self) -> u8 {
        match self {
            Delim::Newline => b'\n',
            Delim::Null => b'\0',
        }
    }
}

/// Read one command. Returns `None` at clean end-of-connection. The leading
/// `z`/`n` prefix (if any) selects the terminator; a bare command is treated as
/// legacy newline-terminated.
fn read_command<R: Read>(r: &mut BufReader<R>) -> io::Result<Option<(String, Delim)>> {
    let mut first = [0u8; 1];
    if read_full(r, &mut first)? == 0 {
        return Ok(None);
    }
    let (delim, mut buf) = match first[0] {
        b'z' => (Delim::Null, Vec::new()),
        b'n' => (Delim::Newline, Vec::new()),
        // Legacy: the byte is part of the command itself.
        other => (Delim::Newline, vec![other]),
    };
    read_until(r, delim.byte(), &mut buf)?;
    // Strip the terminator and any trailing CR.
    if buf.last() == Some(&delim.byte()) {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    // A path on Unix is bytes, not text, and a filename that is not valid UTF-8
    // is perfectly legal — so `from_utf8_lossy` can replace bytes and produce a
    // path that names a different file, or none. The command pipeline is `str`
    // throughout, so the lossy conversion stands for now; what must not stand is
    // the misleading answer. Without this the client is told "No such file or
    // directory" about a file that exists, which sends an operator looking in
    // the wrong place. Naming the real cause keeps the failure honest.
    let cmd = match std::str::from_utf8(&buf) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "command is not valid UTF-8 (a path with non-UTF-8 bytes cannot \
                 be sent over this protocol; scan it by descriptor with FILDES)",
            ))
        }
    };
    Ok(Some((cmd, delim)))
}

/// Read exactly `buf.len()` bytes, or fewer only at EOF. Returns bytes read.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// Append bytes up to and including `delim` (or EOF) to `buf`, bounded to
/// [`MAX_COMMAND`] bytes so a client that never sends a terminator can't make
/// the daemon buffer unbounded memory (the standard `read_until` is unbounded).
fn read_until<R: Read>(r: &mut BufReader<R>, delim: u8, buf: &mut Vec<u8>) -> io::Result<()> {
    use std::io::BufRead;
    loop {
        let available = r.fill_buf()?;
        if available.is_empty() {
            return Ok(()); // EOF
        }
        if let Some(pos) = available.iter().position(|&b| b == delim) {
            buf.extend_from_slice(&available[..=pos]);
            r.consume(pos + 1);
            return Ok(());
        }
        buf.extend_from_slice(available);
        let n = available.len();
        r.consume(n);
        if buf.len() > MAX_COMMAND {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "command line exceeds limit",
            ));
        }
    }
}

/// Serve one connection. `arm`/`disarm` bracket the execution of each command
/// with the prefork per-job wall-clock timer (a no-op in the thread model): the
/// timer is re-armed *per command* rather than once per connection, so a long
/// `IDSESSION` batch of quick scans isn't killed by a single budget spanning the
/// whole session, and idle time between commands isn't charged to a scan.
#[allow(clippy::too_many_arguments)]
fn handle_conn<R, W>(
    rd: R,
    mut writer: W,
    db: &Scanner,
    opts: &ScanOptions,
    arm: &dyn Fn(),
    disarm: &dyn Fn(),
    reload: &dyn Fn(),
    shutdown: &dyn Fn() -> bool,
) -> io::Result<()>
where
    R: Read + FdSource,
    W: Write,
{
    let mut reader = BufReader::new(rd);

    let (cmd, delim) = match read_command(&mut reader)? {
        Some(c) => c,
        None => return Ok(()),
    };
    let cmd = cmd.trim().to_string();
    let word = cmd.split_whitespace().next().unwrap_or("").to_string();

    // IDSESSION/SESSION keep the connection open for many commands until END.
    // IDSESSION tags each reply with a sequence id (the modern, client-preferred
    // form); the legacy SESSION does not. Every other command is handled once and
    // the connection is then closed — clamd's single-command-per-connection
    // semantics, which clients rely on to know the reply is complete.
    let idsession = word.eq_ignore_ascii_case("IDSESSION");
    if idsession || word.eq_ignore_ascii_case("SESSION") {
        let mut id = 0u64;
        loop {
            let (cmd, delim) = match read_command(&mut reader)? {
                Some(c) => c,
                None => return Ok(()),
            };
            let cmd = cmd.trim();
            let word = cmd.split_whitespace().next().unwrap_or("");
            if word.eq_ignore_ascii_case("END") {
                return Ok(());
            }
            if cmd.is_empty() {
                continue;
            }
            id += 1;
            arm();
            let r = run_command(
                cmd,
                word,
                &mut reader,
                &mut writer,
                delim,
                idsession.then_some(id),
                db,
                opts,
                reload,
                shutdown,
            );
            disarm();
            r?;
        }
    }

    if cmd.is_empty() || word.eq_ignore_ascii_case("END") {
        return Ok(());
    }
    arm();
    let r = run_command(
        &cmd,
        &word,
        &mut reader,
        &mut writer,
        delim,
        None,
        db,
        opts,
        reload,
        shutdown,
    );
    disarm();
    r
}

/// Execute one command and write its reply line(s). FILDES is handled here
/// (it needs the fd-capturing reader); everything else goes to `dispatch`.
#[allow(clippy::too_many_arguments)]
fn run_command<R, W>(
    cmd: &str,
    word: &str,
    reader: &mut BufReader<R>,
    writer: &mut W,
    delim: Delim,
    id: Option<u64>,
    db: &Scanner,
    opts: &ScanOptions,
    reload: &dyn Fn(),
    shutdown: &dyn Fn() -> bool,
) -> io::Result<()>
where
    R: Read + FdSource,
    W: Write,
{
    let replies = if word.eq_ignore_ascii_case("FILDES") {
        vec![fildes(reader, db, opts)]
    } else if word.eq_ignore_ascii_case("RELOAD") {
        // Ask the supervisor to re-read the data dir and re-fork the pool. The
        // reply is clamd's `RELOADING` either way; the reload happens out of band
        // (a no-op in the thread model, which has no supervisor to re-fork).
        reload();
        vec!["RELOADING".to_string()]
    } else if word.eq_ignore_ascii_case("SHUTDOWN") || word.eq_ignore_ascii_case("QUIT") {
        // clamd accepts QUIT as an alias for SHUTDOWN. Answering
        // `UNKNOWN COMMAND` leaves a client that speaks clamd unable to stop a
        // daemon that claims to speak it back.
        // clamd's SHUTDOWN stops the daemon. `shutdown()` initiates a graceful
        // teardown and returns true; if the command is disabled it returns false
        // and we surface an error instead of a silent no-op. clamd sends no reply
        // on success, so neither do we (the process tears down).
        if shutdown() {
            Vec::new()
        } else {
            vec!["SHUTDOWN: command disabled ERROR".to_string()]
        }
    } else {
        dispatch(cmd, word, reader, delim, db, opts)?
    };
    // Mirror scan results into `--log`. A daemon's results go to whoever asked
    // for them and nowhere else, so this file is the operator's only record of
    // what was scanned and what came back; logging before the write means a
    // client that hangs up mid-reply still leaves the verdict on disk.
    if is_scan_verb(word) {
        for reply in &replies {
            crate::log_line(reply);
        }
    }
    for reply in replies {
        write_reply(writer, id, &reply, delim)?;
    }
    Ok(())
}

/// Whether a command's replies are scan results, and so belong in `--log`.
/// `PING`, `VERSION` and `STATS` answer questions about the daemon rather than
/// about a file, and a scan log they appear in is a scan log nobody can count.
fn is_scan_verb(word: &str) -> bool {
    const SCAN_VERBS: [&str; 8] = [
        "SCAN",
        "CONTSCAN",
        "MULTISCAN",
        "ALLMATCHSCAN",
        "INSTREAM",
        "EXINSTREAM",
        "FILDES",
        "SCANURL",
    ];
    SCAN_VERBS.iter().any(|v| word.eq_ignore_ascii_case(v))
}

/// FILDES: scan a file descriptor passed over the socket via SCM_RIGHTS.
fn fildes<R: Read + FdSource>(
    reader: &mut BufReader<R>,
    db: &Scanner,
    opts: &ScanOptions,
) -> String {
    match reader.take_fd() {
        Some(file) => {
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            // Isolate a panic on a malicious fd so it becomes an ERROR reply for
            // this target instead of tearing down the connection (matches the
            // per-file containment of SCAN/scan_one_path).
            let scanned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                exav_core::scan_seekable(db, file, size, opts)
            }));
            match scanned {
                Ok(Ok(report)) => verdict_line("fd", &report),
                Ok(Err(e)) => format!("fd: {e} ERROR"),
                Err(_) => "fd: internal error while scanning ERROR".to_string(),
            }
        }
        None => "FILDES: no file descriptor received ERROR".to_string(),
    }
}

/// Run a single command, returning the reply line(s). For INSTREAM the chunk
/// stream is consumed from `reader`.
fn dispatch<R: Read>(
    cmd: &str,
    word: &str,
    reader: &mut BufReader<R>,
    _delim: Delim,
    db: &Scanner,
    opts: &ScanOptions,
) -> io::Result<Vec<String>> {
    let arg = cmd[word.len()..].trim();
    let reply = match word.to_ascii_uppercase().as_str() {
        "PING" => vec!["PONG".to_string()],
        // clamd-compatible `ClamAV <release>/<db-version>/<db-time>` so version-
        // parsing clients (clamdtop, health checks) recognise a clamd and can
        // read the signature freshness. The exav build version is available via
        // the CLI `--version`.
        "VERSION" => vec![clamav_version(db)],
        // Feature-detection: clients (incl. clamdscan) query this to learn which
        // commands the daemon speaks. Format matches clamd: `<version>| COMMANDS:
        // <space-separated list>`.
        // The list is what a client uses to decide what it may send, so a verb
        // that works and is missing here is a capability nobody discovers.
        "VERSIONCOMMANDS" => vec![format!(
            "{}| COMMANDS: SCAN CONTSCAN MULTISCAN ALLMATCHSCAN INSTREAM EXINSTREAM FILDES \
             STATS VERSION VERSIONCOMMANDS RELOAD SHUTDOWN QUIT PING IDSESSION SESSION END{}",
            clamav_version(db),
            if cfg!(feature = "http-scan") {
                " SCANURL"
            } else {
                ""
            }
        )],
        // RELOAD is intercepted in `run_command` (it needs the supervisor hook).
        // clamd-compatible status block: POOLS/STATE/THREADS/QUEUE/MEMSTATS/END,
        // the shape `clamdtop` parses for its live columns. exav has no custom
        // allocator instrumentation, so the heap/mmap memory figures are `N/A`
        // (clamd reports the same when built without its pools allocator).
        //
        // The clamd fields keep their positions and their names, because
        // `clamdtop` finds its columns by both. What exav knows and clamd does
        // not — where this process spent its scan time — follows them as
        // `SCANSTATS`/`MATCHERSTATS` lines, which a clamd client ignores and a
        // human or a scraper can read. `QUEUE` reports the scans actually in
        // flight rather than the constant `0 items` a stub would give, since a
        // saturated listener is exactly what someone runs this command to see.
        "STATS" => {
            let max = daemon_max_workers();
            let live = crate::metrics::in_flight();
            vec![format!(
                "POOLS: 1\n\nSTATE: VALID PRIMARY\n\
                 THREADS: live {live}  idle 0 max {max} idle-timeout 30\n\
                 QUEUE: {live} items\n\tSTATS 0.000000 \n\n\
                 MEMSTATS: heap N/A mmap N/A used N/A free N/A releasable N/A \
                 pools 1 pools_used N/A pools_total N/A\n{}\nEND",
                crate::metrics::stats_block()
            )]
        }
        // clamd's SCAN takes a file OR a directory, and recurses into one. A
        // client that sends a directory and gets `Is a directory ERROR` back is
        // a client that works against clamd and not against exav, which is the
        // whole claim of speaking this protocol. `scan_tree` also rejoins split
        // sets, so a directory answered here matches what CONTSCAN would say.
        "SCAN" if Path::new(arg).is_dir() => scan_tree(db, opts, arg),
        "SCAN" => vec![scan_one_path(db, opts, arg)],
        "CONTSCAN" | "MULTISCAN" => scan_tree(db, opts, arg),
        // All-match: report every matching signature per file (not just the
        // first), one reply line each — clamd's ALLMATCHSCAN semantics.
        "ALLMATCHSCAN" => scan_tree_allmatch(db, opts, arg),
        "INSTREAM" => vec![instream(db, opts, reader)?],
        // Extended INSTREAM: same chunk framing, structured JSON reply with the
        // nested match location. Older/newer clients that don't know it fall to
        // the `UNKNOWN COMMAND` arm below and degrade cleanly.
        // `EXINSTREAM MULTI` sends several files in one request so a
        // multi-volume archive split across them can be rejoined; bare
        // `EXINSTREAM` is the single-file form and is unchanged.
        "EXINSTREAM" if arg.eq_ignore_ascii_case("MULTI") => {
            vec![exinstream_multi(db, opts, reader)?]
        }
        "EXINSTREAM" => vec![exinstream(db, opts, reader)?],
        #[cfg(feature = "http-scan")]
        "SCANURL" => vec![scan_url(db, opts, arg)],
        #[cfg(not(feature = "http-scan"))]
        "SCANURL" => vec![format!(
            "{arg}: SCANURL needs a build with `--features http-scan` ERROR"
        )],
        _ => vec![format!("UNKNOWN COMMAND {word} ERROR")],
    };
    Ok(reply)
}

fn write_reply<W: Write>(w: &mut W, id: Option<u64>, reply: &str, delim: Delim) -> io::Result<()> {
    // In session (IDSESSION) mode each reply MESSAGE is tagged with its command
    // id on its FIRST line only; the remaining lines of a multi-line reply (the
    // STATS block) travel raw, exactly as clamd frames them. Prefixing every line
    // breaks clamd-session clients like clamdtop, which then see
    // `2: STATE:`/`2: THREADS:` instead of the bare field lines and can't parse
    // the body. Each CONTSCAN file result is a separate reply message (its own
    // call here), so it still gets its own id — only intra-message lines change.
    if let Some(n) = id {
        write!(w, "{n}: ")?;
    }
    w.write_all(reply.as_bytes())?;
    w.write_all(&[delim.byte()])?;
    w.flush()
}

/// Format a scan verdict into a clamd-style reply line, from the shared
/// [`exav_core::Verdict`] classification. A partial verdict is surfaced as
/// `<TAG> (<reason>) ERROR` (never `OK`) so the never-silent-skip invariant
/// holds on the wire, and the tag/detail come from the same source the one-shot
/// CLI uses — the two surfaces cannot drift apart.
fn verdict_line(target: &str, report: &ScanReport) -> String {
    let mut owned;
    let report = if report.verdict.category() == VerdictCategory::Partial {
        owned = report.clone();
        crate::policy::apply(&mut owned, crate::policy::current());
        &owned
    } else {
        report
    };
    let v = &report.verdict;
    match v.category() {
        VerdictCategory::Infected => format!("{target}: {} FOUND", v.detail().unwrap_or_default()),
        VerdictCategory::Clean => format!("{target}: OK"),
        // The same grammar the one-shot CLI prints — `reason CATEGORY STATUS` —
        // so the two surfaces do not describe one verdict two ways. Only the
        // status word differs, and it has to: clamd's vocabulary is `OK`,
        // `FOUND` and `ERROR`, and a real client reads a word outside it as
        // `OK`. Measured against clamdscan 1.4.3, which rewrites an unknown
        // status to `OK` and exits 0 — so `PARTIAL` on this wire would turn
        // exav's fail-closed answer into a fail-open one at every existing
        // client. `ERROR` is the only word here that fails closed.
        //
        // The category is what tells the two apart, so `--partial-as error`
        // drops it: it asks for this object to be an operational failure, and a
        // categorised reply is exactly what an exav client reads back as a
        // partial and exits 3 for. The reason still says what happened.
        VerdictCategory::Partial => {
            let reason = v.detail().unwrap_or_default();
            if crate::policy::current().for_tag(v.status_tag())
                == crate::policy::PartialStatus::Error
            {
                format!("{target}: {reason} ERROR")
            } else {
                format!("{target}: {reason} {} ERROR", v.status_tag())
            }
        }
    }
}

fn scan_one_path(db: &Scanner, opts: &ScanOptions, path: &str) -> String {
    if path.is_empty() {
        return "SCAN: missing path ERROR".to_string();
    }
    // Isolate a panic on a malicious file: report ERROR for this target rather
    // than letting it tear down the connection (or, with the per-file recursion
    // in scan_tree, the rest of the walk).
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let timer = crate::metrics::ScanTimer::start();
    let scanned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scan_path(db, Path::new(path), opts)
    }));
    let category = match &scanned {
        Ok(Ok(report)) => report.verdict.category().into(),
        _ => crate::metrics::Category::Partial,
    };
    timer.finish(path, size, category);
    match scanned {
        Ok(Ok(report)) => verdict_line(path, &report),
        Ok(Err(e)) => format!("{path}: {e} ERROR"),
        Err(_) => format!("{path}: scan failed (internal error) ERROR"),
    }
}

/// CONTSCAN/MULTISCAN: a single file scans like SCAN; a directory yields one
/// reply line per regular file (recursively).
///
/// Scanning a directory one file at a time misses one whole class of archive: a
/// set split across `big.7z.001`, `.002`, `.003` has no piece that decodes on
/// its own, so every part reports `OK` and the archive is never opened. Sets are
/// therefore rejoined per directory and scanned as the archives they are — see
/// [`volume_set_lines`] for how the result is attributed back to files.
fn scan_tree(db: &Scanner, opts: &ScanOptions, path: &str) -> Vec<String> {
    if path.is_empty() {
        return vec!["CONTSCAN: missing path ERROR".to_string()];
    }
    let p = Path::new(path);
    if p.is_file() {
        return vec![scan_one_path(db, opts, path)];
    }
    if !p.exists() {
        return vec![format!("{path}: No such file or directory ERROR")];
    }
    // A path the walk could not reach gets its own ERROR reply rather than being
    // dropped: a reply list that omits it tells the client the tree was scanned
    // when part of it was never opened.
    let walk = crate::walk_tree(p, None, crate::Descent::Recursive);
    let files = walk.files;
    let sets = volume_set_lines(db, opts, &files);
    let mut out = walk.errors;
    for f in &files {
        let name = f.to_string_lossy();
        let line = scan_one_path(db, opts, &name);
        // The archive's verdict replaces a part's own `OK`: on its own the part
        // decoded to nothing, so that `OK` says only "this fragment is not
        // itself malware". A verdict the part earned by itself stands.
        match sets.get(f) {
            Some(status) if line.ends_with(": OK") => out.push(format!("{name}: {status}")),
            _ => out.push(line),
        }
    }
    if out.is_empty() {
        out.push(format!("{path}: OK"));
    }
    out
}

/// Rejoin the multi-volume sets among `files` and scan each as one archive.
///
/// Returns the status text to report for each part of a set that resolved to
/// something other than clean — keyed by the part's own path, so the caller
/// still emits exactly one reply line per file. A piece of an infected archive
/// is not a clean file, and it is the piece the operator has to act on.
///
/// Grouped per directory: `a/big.7z.001` and `b/big.7z.002` are two unrelated
/// files that happen to share a name, and splicing them would concatenate bytes
/// nothing ever wrote.
fn volume_set_lines(
    db: &Scanner,
    opts: &ScanOptions,
    files: &[std::path::PathBuf],
) -> std::collections::HashMap<std::path::PathBuf, String> {
    use std::collections::HashMap;
    let mut by_dir: HashMap<&Path, Vec<&std::path::PathBuf>> = HashMap::new();
    for f in files {
        by_dir
            .entry(f.parent().unwrap_or(Path::new("")))
            .or_default()
            .push(f);
    }
    let mut out = HashMap::new();
    for (dir, group) in by_dir {
        let names: Vec<String> = group
            .iter()
            .filter_map(|f| f.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        // `fetch` only ever runs for a name that parses as a part, so a
        // directory of large ordinary files is not read here at all.
        let verdicts = exav_core::analyze_volume_sets(db, &names, opts, |name| {
            let mut data = Vec::new();
            File::open(dir.join(name))?
                .take(opts.deep_analysis_max.saturating_add(1))
                .read_to_end(&mut data)?;
            Ok(data)
        });
        for v in verdicts {
            // Named for the archive, not the fragment: `big.7z FOUND …` tells an
            // operator what was actually found, which `big.7z.002` does not.
            //
            // Built by `verdict_line` so a part's reply and a whole file's reply
            // share one grammar — including `--partial-as`, which `verdict_line`
            // applies. The empty target leaves a bare `": "` in front for the
            // caller to fill in with the part's path.
            let line = verdict_line("", &v.report);
            let status = line.trim_start_matches(": ");
            // Checked on the rendered line, not on the raw verdict: under
            // `--partial-as ok` a part exav could not fully examine has become
            // clean by this point, and a clean part earns no reply at all.
            if status == "OK" {
                continue;
            }
            out.insert(dir.join(&v.name), format!("{status} (in {})", v.set));
        }
    }
    out
}

/// ALLMATCHSCAN: like [`scan_tree`] but every matching signature is reported per
/// file (one reply line each), not just the first.
fn scan_tree_allmatch(db: &Scanner, opts: &ScanOptions, path: &str) -> Vec<String> {
    if path.is_empty() {
        return vec!["ALLMATCHSCAN: missing path ERROR".to_string()];
    }
    let p = Path::new(path);
    if p.is_file() {
        return scan_one_allmatch(db, opts, path);
    }
    if !p.exists() {
        return vec![format!("{path}: No such file or directory ERROR")];
    }
    // As in `scan_tree`: an unreachable path is reported, never omitted.
    let walk = crate::walk_tree(p, None, crate::Descent::Recursive);
    let mut out = walk.errors;
    for f in &walk.files {
        out.extend(scan_one_allmatch(db, opts, &f.to_string_lossy()));
    }
    if out.is_empty() {
        out.push(format!("{path}: OK"));
    }
    out
}

/// All-match scan of a single file: report every matching signature. Works on a
/// buffered copy (bounded by `deep_analysis_max`); a larger file falls back to a
/// normal single-match scan so it is never silently skipped — mirroring the CLI's
/// `--all-matches` so the two surfaces agree.
fn scan_one_allmatch(db: &Scanner, opts: &ScanOptions, path: &str) -> Vec<String> {
    if path.is_empty() {
        return vec!["ALLMATCHSCAN: missing path ERROR".to_string()];
    }
    let cap = opts.deep_analysis_max;
    let mut data = Vec::new();
    let read = File::open(Path::new(path)).and_then(|f| {
        f.take(cap.saturating_add(1))
            .read_to_end(&mut data)
            .map(|_| ())
    });
    if let Err(e) = read {
        return vec![format!("{path}: {e} ERROR")];
    }
    if data.len() as u64 > cap {
        // Too big to buffer for all-match; single-match scan (never skip).
        return vec![scan_one_path(db, opts, path)];
    }
    // Isolate a panic on a crafted file into an ERROR for this target.
    let found = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        analyze_all_with_outcome(db, &data, opts)
    }));
    match found {
        Ok((dets, _)) if !dets.is_empty() => dets
            .into_iter()
            .map(|(sig, _method)| format!("{path}: {sig} FOUND"))
            .collect(),
        // No detections, but the walk may not have covered the file. Reporting OK
        // here regardless is a silent clean, and it lands in the mode a
        // differential harness drives every file through — so the measurements
        // steering development inherited it too.
        Ok((_, outcome)) => vec![match outcome {
            AllMatchOutcome::Complete => format!("{path}: OK"),
            AllMatchOutcome::LimitsExceeded(r) => format!("{path}: {r} LIMITS-EXCEEDED"),
            AllMatchOutcome::Unscannable(r) => format!("{path}: {r} UNSCANNABLE"),
            AllMatchOutcome::PasswordProtected(r) => {
                format!("{path}: {r} PASSWORD-PROTECTED")
            }
        }],
        Err(_) => vec![format!("{path}: scan failed (internal error) ERROR")],
    }
}

#[cfg(feature = "http-scan")]
fn scan_url(db: &Scanner, opts: &ScanOptions, url: &str) -> String {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return format!("{url}: SCANURL requires an http(s) URL ERROR");
    }
    let reader = match exav_core::source::HttpRangeReader::open(url) {
        Ok(r) => r,
        Err(e) => return format!("{url}: {e} ERROR"),
    };
    let size = reader.len();
    let scanned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exav_core::scan_seekable(db, reader, size, opts)
    }));
    match scanned {
        Ok(Ok(report)) => verdict_line(url, &report),
        Ok(Err(e)) => format!("{url}: {e} ERROR"),
        Err(_) => format!("{url}: scan failed (internal error) ERROR"),
    }
}

/// How much of an abandoned stream is read and discarded before the connection
/// is given up on.
///
/// Reading the tail of a stream whose verdict is already decided is what lets
/// the connection be reused for the next command. It is worth a bounded amount
/// of work and no more: an unbounded drain is an invitation to keep a worker
/// busy indefinitely, since every individual read arrives inside the socket
/// timeout and so never trips it.
pub(crate) const MAX_DRAIN_BYTES: u64 = 64 * 1024 * 1024;

/// A stream payload materialized into a **seekable** source — in RAM when small,
/// else spilled to an auto-deleting temp file. A seekable view is what lets a
/// streamed input (INSTREAM/EXINSTREAM, and the CLI's stdin) get full
/// container-aware scanning (a ZIP's central directory is at the end) at ANY size
/// with bounded memory, matching clamd. `.len()` reports its size.
pub(crate) enum StreamPayload {
    Mem(Vec<u8>),
    Disk(crate::spill::SpillFile, u64),
}

impl StreamPayload {
    pub(crate) fn len(&self) -> u64 {
        match self {
            StreamPayload::Mem(v) => v.len() as u64,
            StreamPayload::Disk(_, n) => *n,
        }
    }

    /// The payload's bytes, or `None` when it is larger than `cap`. Used to feed
    /// a payload back for multi-volume rejoining, which is the one thing that
    /// needs a second look at the same bytes.
    fn bytes_capped(&self, cap: u64) -> io::Result<Option<Vec<u8>>> {
        if self.len() > cap {
            return Ok(None);
        }
        match self {
            StreamPayload::Mem(v) => Ok(Some(v.clone())),
            StreamPayload::Disk(tmp, _) => {
                let mut buf = Vec::new();
                tmp.reopen()?.read_to_end(&mut buf)?;
                Ok(Some(buf))
            }
        }
    }
}

/// Buffer an (already de-chunked / pre-capped) reader into a [`StreamPayload`]:
/// up to the configured threshold in RAM, then spill the rest to a temp file.
/// Shared by the daemon stream verbs and the CLI stdin path so both get the same
/// seekable, container-aware scan under the same budgets.
pub(crate) fn buffer_to_seekable<R: Read>(
    reader: &mut R,
) -> Result<StreamPayload, crate::spill::SpillError> {
    let threshold = crate::spill::config().threshold;
    let mut buf = Vec::new();
    reader.by_ref().take(threshold).read_to_end(&mut buf)?;
    if (buf.len() as u64) < threshold {
        return Ok(StreamPayload::Mem(buf));
    }
    // More data remains — spill the RAM head, then stream the rest to disk. The
    // budgets live in `SpillFile`: `RLIMIT_AS` caps address space and does not
    // cap a file, so without them a client that never stops sending fills the
    // temp filesystem — a denial of service against the host rather than the
    // scan, and one that outlives the connection.
    let mut tmp = crate::spill::SpillFile::create()?;
    tmp.write_all(&buf)?;
    let mut block = vec![0u8; 64 * 1024];
    loop {
        let got = reader.read(&mut block)?;
        if got == 0 {
            break;
        }
        tmp.write_all(&block[..got])?;
    }
    let len = tmp.len()?;
    Ok(StreamPayload::Disk(tmp, len))
}

/// Scan a materialized payload via the seekable (container-aware) path, returning
/// the report and the nested match location (`None` for a top-level hit).
pub(crate) fn scan_payload(
    db: &Scanner,
    opts: &ScanOptions,
    payload: &StreamPayload,
) -> io::Result<(ScanReport, Option<String>)> {
    match payload {
        StreamPayload::Mem(v) => {
            scan_seekable_located(db, std::io::Cursor::new(&v[..]), v.len() as u64, opts)
        }
        StreamPayload::Disk(tmp, len) => {
            // A fresh handle positioned at 0; the `TempFile` stays alive (and
            // thus the file) for as long as the payload does.
            let file = tmp.reopen()?;
            scan_seekable_located(db, file, *len, opts)
        }
    }
}

/// [`scan_payload`], timed into the process counters.
///
/// The ICAP listener times its own scans (it names the object from the request
/// target, which this cannot see), so this is the daemon's stream verbs only —
/// double-counting a scan would make the throughput figure a fiction.
fn scan_payload_timed(
    db: &Scanner,
    opts: &ScanOptions,
    payload: &StreamPayload,
    target: &str,
) -> io::Result<(ScanReport, Option<String>)> {
    let timer = crate::metrics::ScanTimer::start();
    let result = scan_payload(db, opts, payload);
    let category = match &result {
        Ok((report, _)) => report.verdict.category().into(),
        // A scan that failed is a scan that did not finish, which is the
        // partial column wherever else exav counts it.
        Err(_) => crate::metrics::Category::Partial,
    };
    timer.finish(target, payload.len(), category);
    result
}

/// Scan an INSTREAM chunk stream. The payload is materialized to a seekable
/// source (RAM or a temp file) and given the full container-aware scan — so
/// malware inside an archive sent over INSTREAM is detected, matching clamd (the
/// old flat-only path missed it). Any unread chunks are drained so the connection
/// stays in sync for the next command.
fn instream<R: Read>(
    db: &Scanner,
    opts: &ScanOptions,
    reader: &mut BufReader<R>,
) -> io::Result<String> {
    let max = opts.max_scan_size;
    let mut stream = Instream::new(reader, max);
    let payload = match buffer_to_seekable(&mut stream) {
        Ok(p) => p,
        // A budget with no room is a stream nobody could examine, which is a
        // verdict the client is owed. Letting it out as an I/O error would drop
        // the connection instead, and a client with no answer decides for
        // itself — the one outcome an over-full temp filesystem must not buy.
        Err(crate::spill::SpillError::Budget(reason)) => {
            let _ = stream.drain();
            return Ok(format!("stream: UNSCANNABLE ({reason}) ERROR"));
        }
        Err(crate::spill::SpillError::Io(e)) => return Err(e),
    };
    let over = stream.over_limit;
    let truncated = stream.truncated();
    // The reply is already decided; a drain that stops at its cap only means the
    // connection will not be reusable.
    let _reached_terminator = stream.drain()?;
    if over {
        let max = max.unwrap_or(0);
        return Ok(format!(
            "stream: LIMITS-EXCEEDED (size exceeds {max}) ERROR"
        ));
    }
    // Answering a prefix would answer a question the client never finished
    // asking, and `OK` on the benign head of a file is a bypass anyone can drive.
    if truncated {
        return Ok("stream: UNSCANNABLE (stream ended before its terminator) ERROR".to_string());
    }
    let (report, _loc) = scan_payload_timed(db, opts, &payload, "stream")?;
    Ok(verdict_line("stream", &report))
}

/// `EXINSTREAM`: scan a file sent over the exact INSTREAM chunk framing and reply
/// with one line of compact JSON — `{"v":1,"verdict":...}`. Unlike INSTREAM's
/// flat scan, the payload is buffered (bounded by `--max-input-bytes`) and run
/// through the full container-aware analysis, so a detection carries its nested
/// `location` (the `/`-joined member path). The verdict *classification* matches
/// INSTREAM: a detection beats a limit; a not-fully-scanned stream is
/// `unscannable`, never `clean`. An over-limit stream is `unscannable` (never
/// clean). One detection per scan (first / most relevant).
fn exinstream<R: Read>(
    db: &Scanner,
    opts: &ScanOptions,
    reader: &mut BufReader<R>,
) -> io::Result<String> {
    // Materialize to a seekable source (RAM small / temp file large) — same path
    // as INSTREAM — bounded by `--max-input-bytes` (disk is the ceiling). That is
    // the flag this cap actually reads: `opts.max_scan_size` is exav-core's
    // per-top-level-file bound, which `--max-input-bytes` sets. Naming the other
    // flag here would send an operator to raise a setting that changes nothing.
    let mut stream = Instream::new(reader, opts.max_scan_size);
    let payload = match buffer_to_seekable(&mut stream) {
        Ok(p) => p,
        Err(e) => {
            let _ = stream.drain();
            return Ok(json_error(&format!("stream read error: {e}")));
        }
    };
    let over = stream.over_limit;
    let truncated = stream.truncated();
    // The reply is already decided; a drain that stops at its cap only means the
    // connection will not be reusable.
    let _reached_terminator = stream.drain()?;
    if over {
        return Ok(json_partial(
            "LIMITS-EXCEEDED",
            Some("stream exceeds max-filesize; not fully scanned"),
        ));
    }
    // As in INSTREAM: a prefix is not the file, so it gets no verdict.
    if truncated {
        return Ok(json_partial(
            "TRUNCATED",
            Some("stream ended before its terminator; not fully received"),
        ));
    }
    match scan_payload_timed(db, opts, &payload, "stream") {
        Ok((report, loc)) => Ok(verdict_json(&report, loc)),
        Err(e) => Ok(json_error(&format!("scan error: {e}"))),
    }
}

/// Longest filename accepted in an `EXINSTREAM MULTI` request.
const MAX_STREAM_NAME: u32 = 4096;
/// Most files one `EXINSTREAM MULTI` request may carry.
///
/// A count alone is not a bound on anything that matters: every payload is held
/// until the whole request has been read, so the resource a client actually
/// spends is bytes, and this many files each just under the spill threshold is
/// a great deal more memory than any host wants to find. See
/// [`MAX_STREAM_REQUEST_RAM`] and [`MAX_STREAM_REQUEST_SPILL`], which bound the
/// thing being consumed.
const MAX_STREAM_FILES: usize = 1024;

/// Resident bytes one `EXINSTREAM MULTI` request may hold across all its files.
///
/// Payloads under [`STREAM_SPILL_THRESHOLD`] stay in RAM, and they accumulate:
/// the per-file threshold says nothing about a request carrying a thousand of
/// them. In the thread model there is no `RLIMIT_AS` behind this at all.
const MAX_STREAM_REQUEST_RAM: u64 = 256 * 1024 * 1024;

/// Temp-file bytes one `EXINSTREAM MULTI` request may hold across all its files.
///
/// Spilled payloads are bounded per file by [`MAX_STREAM_SPILL_BYTES`], which
/// leaves a request free to fill the temp filesystem a file at a time. Disk is
/// also the one resource `RLIMIT_AS` cannot see.
const MAX_STREAM_REQUEST_SPILL: u64 = 8 * 1024 * 1024 * 1024;

/// `EXINSTREAM MULTI`: scan several files sent in one request.
///
/// The reason this exists is the multi-volume archive. A set split across
/// `big.7z.001`, `.002`, `.003` has no part that decodes on its own, so a client
/// sending them as three separate `EXINSTREAM` requests gets three `clean`
/// replies and the archive is never opened. Sent together, they are rejoined and
/// scanned as the one archive they are.
///
/// Framing, repeated once per file:
///
/// ```text
///   <u32 be name_len><name bytes>          (name_len 0 ends the request)
///   <u32 be len><data> … <u32 be 0>        the ordinary INSTREAM chunk sequence
/// ```
///
/// A name is a **label, never a path**: it is used only to recognise volume
/// naming, and nothing here opens, creates or resolves it against a filesystem.
///
/// Reply: one line of compact JSON,
/// `{"v":1,"files":[{"name":N,…verdict fields…},…]}`, each entry carrying the
/// same verdict fields as a single-file `EXINSTREAM` reply, plus `"set"` when
/// the verdict came from a rejoined multi-volume archive rather than from the
/// file itself.
fn exinstream_multi<R: Read>(
    db: &Scanner,
    opts: &ScanOptions,
    reader: &mut BufReader<R>,
) -> io::Result<String> {
    use serde_json::json;
    let mut names: Vec<String> = Vec::new();
    let mut payloads: Vec<StreamPayload> = Vec::new();
    let mut entries: Vec<serde_json::Value> = Vec::new();
    // Set when the request stops before its terminator. Every file already read
    // still gets its verdict — those streams were complete — but the request as
    // a whole is answered as incomplete, because the files that never arrived
    // are indistinguishable from files the client chose not to send.
    let mut request_truncated = false;
    // What this request is holding so far, counted separately because the two
    // are limited by different things: RAM by the host, disk by the filesystem,
    // and only the first is something `RLIMIT_AS` can see.
    let mut held_ram: u64 = 0;
    let mut held_spill: u64 = 0;
    loop {
        let mut len = [0u8; 4];
        if read_full(reader, &mut len)? < 4 {
            request_truncated = true;
            break;
        }
        let n = u32::from_be_bytes(len);
        if n == 0 {
            break;
        }
        if n > MAX_STREAM_NAME {
            return Ok(json_error("filename too long"));
        }
        if names.len() >= MAX_STREAM_FILES {
            return Ok(json_error("too many files in one request"));
        }
        let mut raw = vec![0u8; n as usize];
        if read_full(reader, &mut raw)? < raw.len() {
            request_truncated = true;
            break;
        }
        let name = String::from_utf8_lossy(&raw).into_owned();

        let mut stream = Instream::new(reader, opts.max_scan_size);
        let payload = match buffer_to_seekable(&mut stream) {
            Ok(p) => p,
            Err(e) => {
                let _ = stream.drain();
                return Ok(json_error(&format!("stream read error: {e}")));
            }
        };
        let over = stream.over_limit;
        let truncated = stream.truncated();
        stream.drain()?;
        if truncated {
            request_truncated = true;
        }
        let fields = if over {
            json!({
                "status": "PARTIAL",
                "category": "LIMITS-EXCEEDED",
                "reason": "stream exceeds max-filesize; not fully scanned",
            })
        } else if truncated {
            json!({
                "status": "PARTIAL",
                "category": "TRUNCATED",
                "reason": "stream ended before its terminator; not fully received",
            })
        } else {
            match scan_payload_timed(db, opts, &payload, &name) {
                Ok((report, loc)) => verdict_fields(&report, loc),
                Err(e) => json!({"status": "ERROR", "reason": format!("scan error: {e}")}),
            }
        };
        match &payload {
            StreamPayload::Mem(v) => held_ram += v.len() as u64,
            StreamPayload::Disk(_, n) => held_spill += *n,
        }
        entries.push(named_entry(&name, fields, None));
        names.push(name);
        payloads.push(payload);

        // Stop before accepting the file that would cross the line, so the
        // reply describes a request the daemon actually held rather than one it
        // died part-way through.
        if held_ram > MAX_STREAM_REQUEST_RAM || held_spill > MAX_STREAM_REQUEST_SPILL {
            return Ok(json_error(
                "request too large: the files sent together exceed what one \
                 request may hold",
            ));
        }
    }

    // Now the multi-volume pass, which is why these are sent together at all.
    // It reads back only the payloads whose names parse as parts.
    let verdicts = exav_core::analyze_volume_sets(db, &names, opts, |name| {
        // First occurrence wins on a repeated name. Two files claiming one
        // volume position make the set ambiguous, and the collector refuses to
        // splice such a set rather than pick between them.
        let i = names
            .iter()
            .position(|n| n == name)
            .ok_or_else(|| io::Error::other("no such stream"))?;
        payloads[i]
            .bytes_capped(opts.deep_analysis_max)?
            .ok_or_else(|| io::Error::other("stream too large to rejoin"))
    });
    for v in verdicts {
        let Some(i) = names.iter().position(|n| *n == v.name) else {
            continue;
        };
        // The archive's verdict replaces the part's own `clean`: on its own the
        // part decoded to nothing, so that `clean` says only "this fragment is
        // not itself malware". A verdict the part earned by itself stands.
        if entries[i]["status"] != "OK" {
            continue;
        }
        entries[i] = named_entry(&v.name, verdict_fields(&v.report, None), Some(&v.set));
    }
    let mut out = json!({"v": 1, "files": entries});
    if request_truncated {
        // The per-file verdicts above stand — those streams arrived whole. This
        // says the LIST is short: files the client meant to send never got here,
        // and a caller treating "every file came back clean" as "the batch is
        // clean" would be wrong about a batch it never fully sent.
        out["truncated"] = json!(true);
    }
    Ok(out.to_string())
}

/// One `files[]` entry: `"name"` first, then the verdict fields, then `"set"`
/// when the verdict came from a rejoined archive rather than the file itself.
fn named_entry(name: &str, fields: serde_json::Value, set: Option<&str>) -> serde_json::Value {
    let mut o = serde_json::json!({ "name": name });
    if let Some(map) = fields.as_object() {
        for (k, val) in map {
            o[k.as_str()] = val.clone();
        }
    }
    if let Some(s) = set {
        o["set"] = serde_json::json!(s);
    }
    o
}

/// The verdict fields shared by the single-file and multi-file EXINSTREAM
/// replies. No envelope: the caller adds `"v"`/`"name"` as its shape needs.
fn verdict_fields(report: &ScanReport, location: Option<String>) -> serde_json::Value {
    use serde_json::json;
    let mut owned;
    let report = if report.verdict.category() == VerdictCategory::Partial {
        owned = report.clone();
        crate::policy::apply(&mut owned, crate::policy::current());
        &owned
    } else {
        report
    };
    let v = &report.verdict;
    // `status` / `category` / `reason` — the same three names the one-shot
    // `--json` uses, so one schema describes both. The old `verdict`/`tag`/
    // `message` trio named the same things differently here, and its
    // `"unscannable"` collided with the *category* of that name: a
    // `{"verdict":"unscannable","tag":"PASSWORD-PROTECTED"}` read as a
    // contradiction.
    match v.category() {
        VerdictCategory::Clean => json!({"status": "OK"}),
        VerdictCategory::Infected => {
            let mut o = json!({
                "status": "FOUND",
                "signature": v.detail().unwrap_or_default(),
            });
            // `location` only for a nested hit; omitted for a top-level match.
            if let Some(l) = location {
                o["location"] = json!(l);
            }
            o
        }
        VerdictCategory::Partial => {
            let status = if crate::policy::current().for_tag(v.status_tag())
                == crate::policy::PartialStatus::Error
            {
                "ERROR"
            } else {
                "PARTIAL"
            };
            let mut o = json!({"status": status, "category": v.status_tag()});
            if let Some(m) = v.detail() {
                o["reason"] = json!(m);
            }
            o
        }
    }
}

/// Render a scan verdict as one line of compact JSON for `EXINSTREAM`.
fn verdict_json(report: &ScanReport, location: Option<String>) -> String {
    // `"v"` is the schema version every reply carries. Key *order* is not part
    // of the contract — the object is serialised with sorted keys, and a JSON
    // consumer reads by name — so nothing here depends on where it lands.
    let mut o = serde_json::json!({"v": 1});
    if let Some(fields) = verdict_fields(report, location).as_object() {
        for (k, val) in fields {
            o[k.as_str()] = val.clone();
        }
    }
    o.to_string()
}

fn json_error(message: &str) -> String {
    serde_json::json!({"v": 1, "status": "ERROR", "reason": message}).to_string()
}

fn json_partial(tag: &str, message: Option<&str>) -> String {
    let mut o = serde_json::json!({"v": 1, "status": "PARTIAL", "category": tag});
    if let Some(m) = message {
        o["reason"] = serde_json::json!(m);
    }
    o.to_string()
}

/// A `Read` over a clamd INSTREAM chunk sequence: `<u32 be len><data>` repeated,
/// ended by a zero length. Presents the de-chunked payload as one stream.
struct Instream<'a, R: Read> {
    inner: &'a mut BufReader<R>,
    /// Bytes left in the current chunk.
    remaining: u32,
    /// True once the stream has ended, whether properly or not.
    done: bool,
    /// The stream ended WITHOUT its zero-length terminator: the client closed or
    /// was cut off part-way through. The bytes received are a prefix of the file
    /// the client meant to send, so a verdict on them is a verdict on something
    /// nobody chose to scan — and `OK` on a prefix is the shape of a bypass:
    /// send the benign head of a file, hang up, collect a clean answer. The
    /// caller must reply with an error instead.
    truncated: bool,
    total: u64,
    max: Option<u64>,
    over_limit: bool,
}

impl<'a, R: Read> Instream<'a, R> {
    fn new(inner: &'a mut BufReader<R>, max: Option<u64>) -> Self {
        Self {
            inner,
            remaining: 0,
            done: false,
            truncated: false,
            total: 0,
            max,
            over_limit: false,
        }
    }

    /// Whether the client's stream ended without its terminator.
    fn truncated(&self) -> bool {
        self.truncated
    }

    /// Read the next chunk length, setting `done` on the zero terminator.
    fn next_chunk(&mut self) -> io::Result<()> {
        let mut len = [0u8; 4];
        if read_full(self.inner, &mut len)? < 4 {
            // The client stopped before the terminator — either at a chunk
            // boundary or part-way through a length. A well-formed INSTREAM ends
            // with a zero-length chunk, so either way this is not the file the
            // client set out to send.
            self.done = true;
            self.truncated = true;
            return Ok(());
        }
        self.remaining = u32::from_be_bytes(len);
        if self.remaining == 0 {
            self.done = true;
        }
        Ok(())
    }

    /// Consume any remaining chunks up to the terminator (used when the scan
    /// stopped early on a detection), up to [`MAX_DRAIN_BYTES`].
    ///
    /// Draining is a courtesy — it lets the connection carry another command
    /// instead of being reset — and a courtesy with no bound is a way to hold a
    /// worker. Every read completes inside the socket timeout, so the timeout
    /// never fires while a client keeps sending; without a cap one connection
    /// can occupy a slot for as long as it likes, and in the thread model there
    /// is no per-command timer behind it.
    ///
    /// Past the cap the reply still goes out and the rest of the client's bytes
    /// are left in the socket. The session is then desynchronised — the leftover
    /// payload parses as garbage commands — which is the client's own doing and
    /// costs it a byte for every byte the daemon reads. What it no longer buys
    /// is a worker held for free.
    ///
    /// Returns whether the terminator was reached.
    fn drain(&mut self) -> io::Result<bool> {
        let mut sink = [0u8; 8192];
        let mut drained = 0u64;
        while !self.done {
            if drained >= MAX_DRAIN_BYTES {
                return Ok(false);
            }
            if self.remaining == 0 {
                self.next_chunk()?;
                continue;
            }
            let want = self.remaining.min(sink.len() as u32) as usize;
            let n = read_full(self.inner, &mut sink[..want])?;
            if n == 0 {
                self.done = true;
                self.truncated = true;
                break;
            }
            self.remaining -= n as u32;
            drained += n as u64;
        }
        Ok(true)
    }
}

impl<R: Read> Read for Instream<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.done || self.over_limit {
                return Ok(0);
            }
            if self.remaining == 0 {
                self.next_chunk()?;
                continue;
            }
            let want = self.remaining.min(buf.len() as u32) as usize;
            let n = self.inner.read(&mut buf[..want])?;
            if n == 0 {
                // EOF with `remaining` bytes still owed: the chunk header
                // promised data that never arrived.
                self.done = true;
                self.truncated = true;
                return Ok(0);
            }
            self.remaining -= n as u32;
            self.total += n as u64;
            if let Some(max) = self.max {
                if self.total > max {
                    // Stop feeding the scanner; the caller reports the limit.
                    self.over_limit = true;
                    return Ok(0);
                }
            }
            return Ok(n);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    fn eicar() -> &'static [u8] {
        exav_core::unpack::eicar()
    }

    /// The in-core extraction budget must fit inside the memory a job is
    /// granted, so a size limit is *reported* rather than the worker being
    /// killed for reaching it.
    ///
    /// This is the ordering the whole three-layer design rests on, and it held
    /// only by coincidence: with the default 1 GiB budget and the ~750 MiB a
    /// four-worker pool grants on a 6 GiB host, the kernel won. 48 aborts in an
    /// 8,978-file run came from exactly that inversion.
    #[test]
    fn the_extraction_budget_is_clamped_to_what_a_job_is_granted() {
        let mut opts = ScanOptions::default();
        opts.limits.max_extracted_bytes = 1024 << 20;
        opts.limits.max_buffer_bytes = 256 << 20;

        fit_limits_to_job_memory(&mut opts, 750 << 20);
        assert!(
            opts.limits.max_extracted_bytes < 750 << 20,
            "budget {} MiB is not inside the {} MiB grant",
            opts.limits.max_extracted_bytes >> 20,
            750,
        );
        assert!(
            opts.limits.max_buffer_bytes <= opts.limits.max_extracted_bytes,
            "one member may not exceed the whole extraction budget"
        );
    }

    /// Clamping only ever lowers: a generous grant must leave the operator's
    /// configuration exactly as they set it.
    #[test]
    fn a_job_with_room_to_spare_keeps_the_configured_budget() {
        let mut opts = ScanOptions::default();
        opts.limits.max_extracted_bytes = 512 << 20;
        opts.limits.max_buffer_bytes = 256 << 20;
        let (before_total, before_buffer) = (
            opts.limits.max_extracted_bytes,
            opts.limits.max_buffer_bytes,
        );

        fit_limits_to_job_memory(&mut opts, 8192 << 20);
        assert_eq!(opts.limits.max_extracted_bytes, before_total);
        assert_eq!(opts.limits.max_buffer_bytes, before_buffer);
    }

    /// Spawn a handler on one end of a socket pair; return the client end.
    fn serve() -> UnixStream {
        let (client, server) = UnixStream::pair().unwrap();
        let db = Scanner::builtin();
        let opts = ScanOptions::default();
        std::thread::spawn(move || {
            let reader = AncillaryReader::new(&server);
            let _ = handle_conn(reader, &server, &db, &opts, &|| {}, &|| {}, &|| {}, &|| {
                false
            });
        });
        client
    }

    fn frame(data: &[u8]) -> Vec<u8> {
        let mut v = (data.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(data);
        v.extend_from_slice(&0u32.to_be_bytes());
        v
    }

    /// One command on a fresh connection; read the reply terminated by `delim`
    /// (the daemon closes after a single non-session command).
    fn one(send: &[u8], delim: u8) -> String {
        let mut w = serve();
        let mut r = BufReader::new(w.try_clone().unwrap());
        w.write_all(send).unwrap();
        w.flush().unwrap();
        let mut buf = Vec::new();
        r.read_until(delim, &mut buf).unwrap();
        if buf.last() == Some(&delim) {
            buf.pop();
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn instream_msg(data: &[u8]) -> Vec<u8> {
        let mut m = b"zINSTREAM\0".to_vec();
        m.extend(frame(data));
        m
    }

    fn exinstream_msg(data: &[u8]) -> Vec<u8> {
        let mut m = b"zEXINSTREAM\0".to_vec();
        m.extend(frame(data));
        m
    }

    /// One command on a fresh connection using a custom `ScanOptions`.
    /// Send `send`, then half-close, the way a client that stops part-way
    /// through actually behaves: the server sees EOF rather than waiting for
    /// bytes that will never come. Without the shutdown the server blocks in
    /// `read_full` and the test hangs instead of failing.
    fn one_half_closed(send: &[u8], delim: u8) -> String {
        let (mut client, server) = UnixStream::pair().unwrap();
        let db = Scanner::builtin();
        let opts = ScanOptions::default();
        std::thread::spawn(move || {
            let reader = AncillaryReader::new(&server);
            let _ = handle_conn(reader, &server, &db, &opts, &|| {}, &|| {}, &|| {}, &|| {
                false
            });
        });
        let mut r = BufReader::new(client.try_clone().unwrap());
        client.write_all(send).unwrap();
        client.flush().unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut buf = Vec::new();
        r.read_until(delim, &mut buf).unwrap();
        if buf.last() == Some(&delim) {
            buf.pop();
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn one_with(send: &[u8], delim: u8, opts: ScanOptions) -> String {
        let (mut client, server) = UnixStream::pair().unwrap();
        let db = Scanner::builtin();
        std::thread::spawn(move || {
            let reader = AncillaryReader::new(&server);
            let _ = handle_conn(reader, &server, &db, &opts, &|| {}, &|| {}, &|| {}, &|| {
                false
            });
        });
        let mut r = BufReader::new(client.try_clone().unwrap());
        client.write_all(send).unwrap();
        client.flush().unwrap();
        let mut buf = Vec::new();
        r.read_until(delim, &mut buf).unwrap();
        if buf.last() == Some(&delim) {
            buf.pop();
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    // A WinZip-AES-encrypted `.zip` (member `secret.txt`) whose password is NOT in
    // exav's built-in crack list, so it stays password-protected (Python pyzipper).
    const ZIP_ENCRYPTED: &[u8] = &[
        80, 75, 3, 4, 20, 0, 1, 0, 99, 0, 110, 191, 244, 92, 0, 0, 0, 0, 98, 0, 0, 0, 68, 0, 0, 0,
        10, 0, 11, 0, 115, 101, 99, 114, 101, 116, 46, 116, 120, 116, 1, 153, 7, 0, 2, 0, 65, 69,
        3, 8, 0, 120, 66, 88, 172, 93, 251, 129, 161, 38, 115, 22, 250, 22, 191, 47, 17, 190, 137,
        204, 88, 222, 212, 135, 250, 93, 233, 195, 111, 201, 62, 52, 85, 104, 162, 35, 193, 74,
        126, 203, 204, 215, 217, 57, 104, 3, 45, 230, 104, 142, 131, 151, 224, 83, 15, 227, 187,
        255, 32, 117, 59, 209, 121, 227, 46, 15, 41, 174, 124, 135, 85, 69, 132, 135, 45, 50, 163,
        38, 6, 248, 241, 54, 111, 216, 138, 215, 134, 100, 248, 99, 248, 49, 84, 220, 171, 177,
        119, 57, 208, 80, 75, 1, 2, 20, 3, 20, 0, 1, 0, 99, 0, 110, 191, 244, 92, 0, 0, 0, 0, 98,
        0, 0, 0, 68, 0, 0, 0, 10, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1, 0, 0, 0, 0, 115, 101,
        99, 114, 101, 116, 46, 116, 120, 116, 1, 153, 7, 0, 2, 0, 65, 69, 3, 8, 0, 80, 75, 5, 6, 0,
        0, 0, 0, 1, 0, 1, 0, 67, 0, 0, 0, 149, 0, 0, 0, 0, 0,
    ];

    // Real DEFLATE ZIPs (generated by Python's zipfile). Compressed so the EICAR
    // is NOT visible to a flat scan of the container, forcing real extraction of
    // each level — which is what exercises the nested-location chain.
    // `ZIP_EICAR_INSIDE`: a `.zip` with member `inside.txt` = EICAR.
    const ZIP_EICAR_INSIDE: &[u8] = &[
        80, 75, 3, 4, 20, 0, 0, 0, 8, 0, 230, 190, 244, 92, 60, 207, 81, 104, 70, 0, 0, 0, 68, 0,
        0, 0, 10, 0, 0, 0, 105, 110, 115, 105, 100, 101, 46, 116, 120, 116, 139, 48, 245, 87, 12,
        80, 117, 112, 12, 136, 54, 137, 9, 136, 138, 48, 53, 209, 8, 136, 211, 52, 119, 118, 214,
        52, 175, 85, 113, 245, 116, 118, 12, 210, 13, 14, 113, 244, 115, 113, 12, 114, 209, 117,
        244, 11, 241, 12, 243, 12, 10, 13, 214, 13, 113, 13, 14, 209, 117, 243, 244, 113, 85, 84,
        241, 208, 246, 208, 2, 0, 80, 75, 1, 2, 20, 3, 20, 0, 0, 0, 8, 0, 230, 190, 244, 92, 60,
        207, 81, 104, 70, 0, 0, 0, 68, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1, 0, 0,
        0, 0, 105, 110, 115, 105, 100, 101, 46, 116, 120, 116, 80, 75, 5, 6, 0, 0, 0, 0, 1, 0, 1,
        0, 56, 0, 0, 0, 110, 0, 0, 0, 0, 0,
    ];
    // `ZIP_IN_ZIP_EICAR`: a `.zip` whose member `inner.zip` is itself a DEFLATE
    // zip with member `inside.txt` = EICAR (two compressed levels).
    const ZIP_IN_ZIP_EICAR: &[u8] = &[
        80, 75, 3, 4, 20, 0, 0, 0, 8, 0, 230, 190, 244, 92, 166, 221, 172, 86, 140, 0, 0, 0, 188,
        0, 0, 0, 9, 0, 0, 0, 105, 110, 110, 101, 114, 46, 122, 105, 112, 11, 240, 102, 102, 17, 97,
        96, 96, 224, 96, 120, 182, 239, 75, 140, 205, 249, 192, 12, 55, 32, 207, 5, 136, 185, 128,
        56, 51, 175, 56, 51, 37, 85, 175, 164, 162, 164, 219, 224, 107, 56, 79, 64, 105, 1, 79,
        135, 89, 39, 103, 71, 151, 129, 233, 69, 142, 142, 203, 38, 229, 101, 215, 76, 214, 135,
        22, 126, 45, 41, 227, 185, 196, 203, 87, 248, 165, 184, 144, 167, 232, 98, 233, 23, 238,
        143, 60, 159, 121, 184, 120, 175, 241, 22, 242, 242, 93, 44, 253, 252, 165, 48, 52, 228,
        227, 133, 111, 23, 152, 24, 2, 188, 25, 153, 68, 152, 113, 219, 7, 3, 13, 140, 12, 40, 182,
        7, 120, 179, 178, 129, 68, 24, 129, 208, 2, 72, 231, 129, 85, 1, 0, 80, 75, 1, 2, 20, 3,
        20, 0, 0, 0, 8, 0, 230, 190, 244, 92, 166, 221, 172, 86, 140, 0, 0, 0, 188, 0, 0, 0, 9, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1, 0, 0, 0, 0, 105, 110, 110, 101, 114, 46, 122, 105,
        112, 80, 75, 5, 6, 0, 0, 0, 0, 1, 0, 1, 0, 55, 0, 0, 0, 179, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn instream_extracts_archives() {
        // INSTREAM must detect malware INSIDE an archive, as clamd does — a
        // flat-only scan of the stream is not enough. EICAR is DEFLATE-compressed inside
        // the zip, so a flat scan of the raw stream can't see it — extraction is
        // required.
        let r = one(&instream_msg(ZIP_EICAR_INSIDE), 0);
        assert!(
            r.contains("FOUND"),
            "INSTREAM must extract the zip; got {r}"
        );
    }

    #[test]
    fn exinstream_clean() {
        assert_eq!(
            one(&exinstream_msg(b"totally benign content"), 0),
            r#"{"status":"OK","v":1}"#
        );
    }

    #[test]
    fn exinstream_eicar_top_level_no_location() {
        let r = one(&exinstream_msg(eicar()), 0);
        assert!(r.contains(r#""status":"FOUND""#), "got {r}");
        assert!(r.contains(r#""signature":"#), "got {r}");
        assert!(
            !r.contains("location"),
            "top-level hit must have no location: {r}"
        );
    }

    #[test]
    fn exinstream_eicar_in_zip_has_location() {
        let r = one(&exinstream_msg(ZIP_EICAR_INSIDE), 0);
        assert!(r.contains(r#""status":"FOUND""#), "got {r}");
        assert!(r.contains(r#""location":"inside.txt""#), "got {r}");
    }

    #[test]
    fn exinstream_zip_in_zip_full_path() {
        let r = one(&exinstream_msg(ZIP_IN_ZIP_EICAR), 0);
        assert!(r.contains(r#""status":"FOUND""#), "got {r}");
        assert!(
            r.contains(r#""location":"inner.zip/inside.txt""#),
            "nested path chain expected, got {r}"
        );
    }

    /// Build an `EXINSTREAM MULTI` request from `(name, bytes)` pairs.
    fn exinstream_multi_msg(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut m = b"zEXINSTREAM MULTI\0".to_vec();
        for (name, data) in files {
            m.extend((name.len() as u32).to_be_bytes());
            m.extend_from_slice(name.as_bytes());
            m.extend(frame(data));
        }
        m.extend(0u32.to_be_bytes());
        m
    }

    /// Cut a blob into `n` roughly equal pieces named as a byte-split set.
    fn split_set(stem: &str, blob: &[u8], n: usize) -> Vec<(String, Vec<u8>)> {
        let each = blob.len().div_ceil(n);
        blob.chunks(each)
            .enumerate()
            .map(|(i, c)| (format!("{stem}.zip.{:03}", i + 1), c.to_vec()))
            .collect()
    }

    #[test]
    fn exinstream_multi_reports_one_entry_per_file() {
        let r = one(
            &exinstream_multi_msg(&[("a.txt", b"hello"), ("b.txt", eicar())]),
            0,
        );
        let v: serde_json::Value = serde_json::from_str(&r).unwrap_or_else(|e| panic!("{e}: {r}"));
        let files = v["files"].as_array().expect("files array");
        assert_eq!(files.len(), 2, "got {r}");
        assert_eq!(files[0]["name"], "a.txt");
        assert_eq!(files[0]["status"], "OK");
        assert_eq!(files[1]["name"], "b.txt");
        assert_eq!(files[1]["status"], "FOUND", "got {r}");
    }

    #[test]
    fn exinstream_multi_rejoins_a_split_archive() {
        // The reason the verb exists. Each part on its own decodes to nothing —
        // asserted below — so three separate EXINSTREAM calls would all reply
        // `clean` and the archive would never be opened.
        let parts = split_set("payload", ZIP_EICAR_INSIDE, 3);
        for (name, part) in &parts {
            let solo = one(&exinstream_msg(part), 0);
            assert!(
                solo.contains(r#""status":"OK""#),
                "{name} is detectable alone — the fixture proves nothing: {solo}"
            );
        }
        let msg = exinstream_multi_msg(
            &parts
                .iter()
                .map(|(n, d)| (n.as_str(), d.as_slice()))
                .collect::<Vec<_>>(),
        );
        let r = one(&msg, 0);
        let v: serde_json::Value = serde_json::from_str(&r).unwrap_or_else(|e| panic!("{e}: {r}"));
        let files = v["files"].as_array().expect("files array");
        assert_eq!(files.len(), 3, "got {r}");
        for f in files {
            assert_eq!(f["status"], "FOUND", "every part is a piece of it: {r}");
            assert_eq!(f["set"], "payload.zip", "named for the archive: {r}");
        }
    }

    #[test]
    fn exinstream_multi_reports_a_set_with_a_hole() {
        // The parts were withheld from the scan to be rejoined and then could
        // not be. Replying `clean` would hide an archive nothing can read.
        let parts = split_set("gap", ZIP_EICAR_INSIDE, 3);
        let r = one(
            &exinstream_multi_msg(&[
                (parts[0].0.as_str(), parts[0].1.as_slice()),
                (parts[2].0.as_str(), parts[2].1.as_slice()),
            ]),
            0,
        );
        let v: serde_json::Value = serde_json::from_str(&r).unwrap_or_else(|e| panic!("{e}: {r}"));
        for f in v["files"].as_array().expect("files array") {
            assert_eq!(f["status"], "PARTIAL", "got {r}");
        }
    }

    #[test]
    fn exinstream_multi_leaves_a_lone_numbered_file_alone() {
        // Plenty of ordinary files end in `.001`. One part is not a set.
        let r = one(&exinstream_multi_msg(&[("notes.dat.001", b"hello")]), 0);
        let v: serde_json::Value = serde_json::from_str(&r).unwrap_or_else(|e| panic!("{e}: {r}"));
        let files = v["files"].as_array().expect("files array");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["status"], "OK", "got {r}");
    }

    #[test]
    fn bare_exinstream_is_unchanged_by_the_multi_verb() {
        // The single-file form must keep its exact reply shape: a client that
        // never sends MULTI must not be able to tell this landed.
        assert_eq!(
            one(&exinstream_msg(b"hello"), 0),
            r#"{"status":"OK","v":1}"#
        );
    }

    #[test]
    fn exinstream_password_protected() {
        let r = one(&exinstream_msg(ZIP_ENCRYPTED), 0);
        assert!(r.contains(r#""status":"PARTIAL""#), "got {r}");
        assert!(r.contains(r#""category":"PASSWORD-PROTECTED""#), "got {r}");
    }

    #[test]
    fn exinstream_oversized_is_unscannable_never_clean() {
        // A stream past `--max-input-bytes` can't be fully scanned → it must be
        // `unscannable`, never `clean`.
        let opts = ScanOptions {
            max_scan_size: Some(8),
            ..ScanOptions::default()
        };
        let r = one_with(
            &exinstream_msg(b"way more than eight bytes of benign content"),
            0,
            opts,
        );
        assert!(r.contains(r#""status":"PARTIAL""#), "got {r}");
        assert!(!r.contains(r#""status":"OK""#), "must never be clean: {r}");
    }

    #[test]
    fn exinstream_unknown_verb_degrades() {
        // A made-up verb must get the normal clamd UNKNOWN COMMAND reply.
        assert!(one(b"zBOGUSVERB\0", 0).starts_with("UNKNOWN COMMAND"));
    }

    #[test]
    fn ping_and_version() {
        assert_eq!(one(b"zPING\0", 0), "PONG");
        // clamd-compatible VERSION: `ClamAV <release>[/<dbver>/<dbtime>]`.
        assert!(one(b"zVERSION\0", 0).starts_with("ClamAV "));
    }

    #[test]
    fn newline_framing() {
        assert_eq!(one(b"nPING\n", b'\n'), "PONG");
    }

    #[test]
    fn instream_detects_eicar_and_passes_clean() {
        assert!(one(&instream_msg(eicar()), 0).contains("FOUND"));
        assert_eq!(
            one(&instream_msg(b"totally benign content"), 0),
            "stream: OK"
        );
    }

    /// A stream that stops before its terminator gets no verdict.
    ///
    /// The bytes that arrived are a prefix of the file the client meant to send.
    /// Scanning a prefix and answering `OK` is a bypass anyone can drive: put
    /// the payload past the cut, send the benign head, hang up, read "clean".
    /// clamd treats an interrupted INSTREAM as an error and so does exav.
    #[test]
    fn a_truncated_instream_gets_no_verdict() {
        // The payload sits entirely in the part that never arrives, so a scan of
        // what did arrive would come back clean.
        let mut payload = vec![b'.'; 64];
        payload.extend_from_slice(eicar());

        // Announce the full length, then send only the benign head and close.
        let mut msg = b"zINSTREAM\0".to_vec();
        msg.extend((payload.len() as u32).to_be_bytes());
        msg.extend_from_slice(&payload[..64]);
        let reply = one_half_closed(&msg, 0);
        assert!(
            !reply.ends_with(": OK"),
            "a stream cut off mid-chunk was answered {reply:?}. The scanner saw \
             a prefix and called it clean; the payload was in the part that \
             never arrived."
        );
        assert!(
            reply.contains("ERROR"),
            "an interrupted stream must be an error, got {reply:?}"
        );

        // The other shape: whole chunks arrive, but the zero-length terminator
        // never does. Nothing is mid-chunk, so only the missing terminator
        // distinguishes this from a complete stream.
        let mut msg = b"zINSTREAM\0".to_vec();
        msg.extend((64u32).to_be_bytes());
        msg.extend_from_slice(&payload[..64]);
        let reply = one_half_closed(&msg, 0);
        assert!(
            !reply.ends_with(": OK"),
            "a stream with no terminator was answered {reply:?}"
        );

        // The counterweight: the same bytes, properly terminated, still scan.
        // Without this the test passes for a daemon that errors on everything.
        assert_eq!(
            one(&instream_msg(&payload[..64]), 0),
            "stream: OK",
            "a complete stream of the same benign bytes must still be OK"
        );
    }

    #[test]
    fn instream_chunked_across_frames() {
        // EICAR split across several INSTREAM chunks must still match.
        let mut msg = b"zINSTREAM\0".to_vec();
        for chunk in eicar().chunks(7) {
            msg.extend((chunk.len() as u32).to_be_bytes());
            msg.extend_from_slice(chunk);
        }
        msg.extend(0u32.to_be_bytes());
        assert!(one(&msg, 0).contains("FOUND"));
    }

    #[test]
    fn an_oversized_stream_spills_to_disk_and_reads_back() {
        // Everything under the threshold stays in RAM, so only a stream that
        // crosses it reaches the temp file at all. Cross it by one byte, with
        // the signature at the very end so a truncated or mis-sized spill
        // cannot pass.
        let threshold = crate::spill::config().threshold as usize;
        let mut payload = vec![b'.'; threshold + 1 - eicar().len()];
        payload.extend_from_slice(eicar());
        let expected = payload.len() as u64;

        let materialized = buffer_to_seekable(&mut &payload[..]).unwrap();
        assert!(
            matches!(materialized, StreamPayload::Disk(_, _)),
            "past the threshold the payload belongs on disk, not in RAM"
        );
        assert_eq!(materialized.len(), expected);
        assert_eq!(
            materialized.bytes_capped(expected).unwrap().as_deref(),
            Some(&payload[..]),
            "a second read gives back every byte that was written"
        );
        assert_eq!(
            materialized.bytes_capped(expected - 1).unwrap(),
            None,
            "the cap is honoured against the on-disk size"
        );

        let db = Scanner::builtin();
        let (report, _) = scan_payload(&db, &ScanOptions::default(), &materialized).unwrap();
        assert!(
            matches!(report.verdict.category(), VerdictCategory::Infected),
            "the spilled bytes are what gets scanned"
        );
    }

    #[test]
    fn scan_path_eicar_and_clean() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        let bad = dir.path().join("bad");
        std::fs::write(&bad, eicar()).unwrap();
        let good = dir.path().join("good");
        std::fs::write(&good, b"hello there").unwrap();
        let rb = one(format!("zSCAN {}\0", bad.display()).as_bytes(), 0);
        assert!(rb.contains("FOUND"), "got {rb}");
        let rg = one(format!("zSCAN {}\0", good.display()).as_bytes(), 0);
        assert!(rg.ends_with("OK"), "got {rg}");
    }

    #[test]
    fn contscan_rejoins_a_split_archive_in_a_directory() {
        // A directory holding `payload.zip.001..003` is one archive, not three
        // files. Scanned one at a time — which is all CONTSCAN did — no part
        // decodes and every line reads `OK`.
        let dir = crate::tmpfile::TempDir::new().unwrap();
        for (name, part) in split_set("payload", ZIP_EICAR_INSIDE, 3) {
            std::fs::write(dir.path().join(&name), &part).unwrap();
        }
        let lines = scan_tree(
            &Scanner::builtin(),
            &ScanOptions::default(),
            &dir.path().to_string_lossy(),
        );
        assert_eq!(lines.len(), 3, "one line per file: {lines:?}");
        for l in &lines {
            assert!(
                l.contains("FOUND"),
                "every part is a piece of it: {lines:?}"
            );
            assert!(
                l.contains("(in payload.zip)"),
                "the line must name the archive, not just the fragment: {l}"
            );
        }
    }

    #[test]
    fn contscan_does_not_splice_across_directories() {
        // `a/x.zip.001` and `b/x.zip.002` are two unrelated files that happen to
        // share a name. Concatenating them would splice bytes nothing wrote.
        let dir = crate::tmpfile::TempDir::new().unwrap();
        let parts = split_set("x", ZIP_EICAR_INSIDE, 2);
        for (i, (name, part)) in parts.iter().enumerate() {
            let sub = dir.path().join(if i == 0 { "a" } else { "b" });
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join(name), part).unwrap();
        }
        let lines = scan_tree(
            &Scanner::builtin(),
            &ScanOptions::default(),
            &dir.path().to_string_lossy(),
        );
        assert!(
            lines.iter().all(|l| !l.contains("FOUND")),
            "parts in different directories are not one set: {lines:?}"
        );
    }

    #[test]
    fn contscan_reports_a_directory_holding_half_a_set() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        let parts = split_set("gap", ZIP_EICAR_INSIDE, 3);
        for i in [0, 2] {
            std::fs::write(dir.path().join(&parts[i].0), &parts[i].1).unwrap();
        }
        let lines = scan_tree(
            &Scanner::builtin(),
            &ScanOptions::default(),
            &dir.path().to_string_lossy(),
        );
        assert_eq!(lines.len(), 2, "{lines:?}");
        for l in &lines {
            assert!(
                l.contains("ERROR"),
                "an archive with a hole in it must not read OK: {lines:?}"
            );
        }
    }

    #[test]
    fn contscan_is_unchanged_for_ordinary_files() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        std::fs::write(dir.path().join("bad"), eicar()).unwrap();
        let lines = scan_tree(
            &Scanner::builtin(),
            &ScanOptions::default(),
            &dir.path().to_string_lossy(),
        );
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines.iter().filter(|l| l.ends_with(": OK")).count(), 1);
        assert_eq!(lines.iter().filter(|l| l.contains("FOUND")).count(), 1);
    }

    #[test]
    fn idsession_prefixes_replies_and_closes_on_end() {
        let mut w = serve();
        let mut r = BufReader::new(w.try_clone().unwrap());
        w.write_all(b"zIDSESSION\0").unwrap();
        w.write_all(&instream_msg(eicar())).unwrap();
        w.flush().unwrap();
        let mut b1 = Vec::new();
        r.read_until(0, &mut b1).unwrap();
        let r1 = String::from_utf8_lossy(&b1);
        assert!(r1.starts_with("1: ") && r1.contains("FOUND"), "got {r1}");
        w.write_all(&instream_msg(b"clean")).unwrap();
        w.flush().unwrap();
        let mut b2 = Vec::new();
        r.read_until(0, &mut b2).unwrap();
        let r2 = String::from_utf8_lossy(&b2);
        assert!(
            r2.starts_with("2: ") && r2.trim_end_matches('\0').ends_with("OK"),
            "got {r2}"
        );
        // END closes the connection.
        w.write_all(b"zEND\0").unwrap();
        w.flush().unwrap();
        let mut b3 = Vec::new();
        assert_eq!(
            r.read_until(0, &mut b3).unwrap(),
            0,
            "connection should close on END"
        );
    }

    #[test]
    fn unknown_command_errors() {
        assert!(one(b"zBOGUS\0", 0).ends_with("ERROR"));
    }

    #[test]
    fn stats_reports_clamd_fields() {
        // clamdtop parses these lines out of the STATS block; all must be present.
        let r = one(b"zSTATS\0", 0);
        for field in [
            "POOLS:",
            "STATE: VALID",
            "THREADS: live",
            "QUEUE:",
            "MEMSTATS:",
            "END",
        ] {
            assert!(r.contains(field), "STATS missing {field:?}: {r:?}");
        }
        // exav's own lines come after clamd's and before END, so a clamd client
        // keeps its columns and a human gets the answer clamd cannot give.
        for field in ["SCANSTATS: scans", "MATCHERSTATS:"] {
            assert!(r.contains(field), "STATS missing {field:?}: {r:?}");
        }
        let (before_end, _) = r.split_once("END").expect("an END marker");
        assert!(
            before_end.contains("SCANSTATS:"),
            "the added lines must sit inside the block: {r:?}"
        );
    }

    #[test]
    fn stats_counts_the_scans_this_process_did() {
        // The gap this closes: a listener that cannot say how much it scanned or
        // how long that took leaves "the box is at 100% CPU" as the only
        // available observation.
        // The counters are process-global and this binary's tests run in
        // parallel, so this asserts movement rather than an absolute count.
        let before = crate::metrics::scans();
        let reply = one(&instream_msg(eicar()), 0);
        assert!(reply.contains("FOUND"), "{reply}");
        assert!(
            crate::metrics::scans() > before,
            "an INSTREAM scan was not counted"
        );

        let stats = one(b"zSTATS\0", 0);
        assert!(stats.contains("SCANSTATS: scans "), "{stats}");
        // Not `scans 0`: a count that never moves is the gap this closed.
        assert!(!stats.contains("SCANSTATS: scans 0 "), "{stats}");
        // Bytes and time are what turn a scan count into a throughput figure.
        assert!(stats.contains("scan-seconds"), "{stats}");
        assert!(stats.contains("throughput-MBps"), "{stats}");
    }

    #[test]
    fn idsession_stats_prefixes_first_line_only() {
        // Regression: in a session, clamd tags a multi-line reply's command id on
        // its FIRST line only and sends the body raw. Prefixing every line (as we
        // once did) makes clamdtop see `1: STATE:`/`1: THREADS:` and fail to parse
        // the block, leaving its table empty.
        let mut w = serve();
        let mut r = BufReader::new(w.try_clone().unwrap());
        w.write_all(b"zIDSESSION\0").unwrap();
        w.write_all(b"zSTATS\0").unwrap();
        w.flush().unwrap();
        let mut b = Vec::new();
        r.read_until(0, &mut b).unwrap();
        let reply = String::from_utf8_lossy(&b);
        let reply = reply.trim_end_matches('\0');
        let mut lines = reply.lines();
        assert_eq!(
            lines.next().unwrap(),
            "1: POOLS: 1",
            "first line carries the command id"
        );
        for l in lines {
            assert!(!l.starts_with("1: "), "body line must be raw, got {l:?}");
        }
        assert!(
            reply.contains("\nSTATE: VALID PRIMARY") && reply.contains("\nEND"),
            "raw body lines present: {reply:?}"
        );
    }

    /// Send `data` plus one file descriptor as SCM_RIGHTS over the socket.
    fn send_with_fd(stream: &UnixStream, data: &[u8], fd: std::os::fd::RawFd) {
        use std::os::fd::AsRawFd;
        let fdsz = std::mem::size_of::<std::os::fd::RawFd>();
        unsafe {
            let mut iov = libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            };
            let mut cmsg = [0u8; 64];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = libc::CMSG_SPACE(fdsz as u32) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(fdsz as u32) as _;
            std::ptr::copy_nonoverlapping(&fd as *const _ as *const u8, libc::CMSG_DATA(c), fdsz);
            assert!(libc::sendmsg(stream.as_raw_fd(), &msg, 0) >= 0);
        }
    }

    #[test]
    fn fildes_scans_passed_descriptor() {
        use std::os::fd::AsRawFd;
        let dir = crate::tmpfile::TempDir::new().unwrap();
        let bad = dir.path().join("bad");
        std::fs::write(&bad, eicar()).unwrap();
        let f = std::fs::File::open(&bad).unwrap();

        let mut w = serve();
        let mut r = BufReader::new(w.try_clone().unwrap());
        send_with_fd(&w, b"zFILDES\0", f.as_raw_fd());
        let mut buf = Vec::new();
        r.read_until(0, &mut buf).unwrap();
        let reply = String::from_utf8_lossy(&buf);
        assert!(reply.contains("FOUND"), "got {reply}");
        let _ = w.write(b""); // keep w alive until reply read
    }

    #[test]
    fn versioncommands_lists_supported_commands() {
        let r = one(b"zVERSIONCOMMANDS\0", 0);
        assert!(
            r.contains("COMMANDS:") && r.contains("INSTREAM") && r.contains("IDSESSION"),
            "got {r}"
        );
    }

    #[test]
    fn session_replies_are_untagged_until_end() {
        // Legacy SESSION keeps the connection open like IDSESSION but does NOT
        // prefix replies with a sequence id.
        let mut w = serve();
        let mut r = BufReader::new(w.try_clone().unwrap());
        w.write_all(b"zSESSION\0").unwrap();
        w.write_all(b"zPING\0").unwrap();
        w.flush().unwrap();
        let mut b1 = Vec::new();
        r.read_until(0, &mut b1).unwrap();
        let r1 = String::from_utf8_lossy(&b1);
        assert_eq!(r1.trim_end_matches('\0'), "PONG", "got {r1}");
        w.write_all(b"zEND\0").unwrap();
        w.flush().unwrap();
        let mut b2 = Vec::new();
        assert_eq!(
            r.read_until(0, &mut b2).unwrap(),
            0,
            "END should close the SESSION"
        );
    }

    #[test]
    fn allmatchscan_reports_detection() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        let bad = dir.path().join("bad");
        std::fs::write(&bad, eicar()).unwrap();
        let r = one(format!("zALLMATCHSCAN {}\0", bad.display()).as_bytes(), 0);
        assert!(r.contains("FOUND"), "got {r}");
        let good = dir.path().join("good");
        std::fs::write(&good, b"benign").unwrap();
        let rg = one(format!("zALLMATCHSCAN {}\0", good.display()).as_bytes(), 0);
        assert!(rg.trim_end_matches('\0').ends_with("OK"), "got {rg}");
    }

    #[test]
    fn shutdown_disabled_reports_error_and_does_not_exit() {
        // With the hook returning false (disabled), SHUTDOWN must reply an ERROR
        // rather than silently succeeding — and obviously not kill the test.
        let (mut client, server) = UnixStream::pair().unwrap();
        let db = Scanner::builtin();
        let opts = ScanOptions::default();
        std::thread::spawn(move || {
            let reader = AncillaryReader::new(&server);
            let _ = handle_conn(reader, &server, &db, &opts, &|| {}, &|| {}, &|| {}, &|| {
                false
            });
        });
        client.write_all(b"zSHUTDOWN\0").unwrap();
        client.flush().unwrap();
        let mut r = BufReader::new(client.try_clone().unwrap());
        let mut buf = Vec::new();
        r.read_until(0, &mut buf).unwrap();
        let reply = String::from_utf8_lossy(&buf);
        assert!(
            reply.contains("disabled") && reply.contains("ERROR"),
            "got {reply}"
        );
        let _ = client.write(b"");
    }

    #[test]
    fn shutdown_enabled_fires_hook() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (mut client, server) = UnixStream::pair().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = Arc::clone(&hits);
        let db = Scanner::builtin();
        let opts = ScanOptions::default();
        std::thread::spawn(move || {
            let reader = AncillaryReader::new(&server);
            let shutdown = || {
                h.fetch_add(1, Ordering::Relaxed);
                true
            };
            let _ = handle_conn(
                reader,
                &server,
                &db,
                &opts,
                &|| {},
                &|| {},
                &|| {},
                &shutdown,
            );
        });
        client.write_all(b"zSHUTDOWN\0").unwrap();
        client.flush().unwrap();
        // Give the handler a moment to run the hook (no reply is sent on success).
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(
            hits.load(Ordering::Relaxed),
            1,
            "shutdown hook must fire once"
        );
        let _ = client.write(b"");
    }

    #[test]
    fn reload_command_fires_hook_and_replies_reloading() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (mut client, server) = UnixStream::pair().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = Arc::clone(&hits);
        let db = Scanner::builtin();
        let opts = ScanOptions::default();
        std::thread::spawn(move || {
            let reader = AncillaryReader::new(&server);
            let reload = || {
                h.fetch_add(1, Ordering::Relaxed);
            };
            let _ = handle_conn(
                reader,
                &server,
                &db,
                &opts,
                &|| {},
                &|| {},
                &reload,
                &|| false,
            );
        });
        client.write_all(b"zRELOAD\0").unwrap();
        client.flush().unwrap();
        let mut r = BufReader::new(client.try_clone().unwrap());
        let mut buf = Vec::new();
        r.read_until(0, &mut buf).unwrap();
        let reply = String::from_utf8_lossy(&buf);
        assert_eq!(reply.trim_end_matches('\0'), "RELOADING", "got {reply}");
        assert_eq!(
            hits.load(Ordering::Relaxed),
            1,
            "reload hook must fire once"
        );
        let _ = client.write(b"");
    }
}
