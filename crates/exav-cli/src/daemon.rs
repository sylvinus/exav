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
//!                             `--max-scansize` (disk is the ceiling). Reply
//!                             `stream: …`
//!   `EXINSTREAM`           -> exav extension: same chunk framing as INSTREAM, but
//!                             the payload is buffered (≤ `--max-scansize`) and
//!                             run through full container-aware analysis, and the
//!                             reply is ONE line of compact JSON with the nested
//!                             match location. Schema (compact, no raw newlines):
//!                               {"v":1,"verdict":"clean"}
//!                               {"v":1,"verdict":"malware","signature":S
//!                                 [,"location":"outer.zip/…/inside.txt"]}
//!                                 (location present only for a NESTED hit; it is
//!                                 the `/`-joined container member-name path from
//!                                 the stream to the matched leaf — control bytes
//!                                 sanitised, capped ~512 chars)
//!                               {"v":1,"verdict":"unscannable","tag":T[,"message":M]}
//!                                 (T ∈ LIMITS-EXCEEDED / UNSCANNABLE /
//!                                 PASSWORD-PROTECTED — a not-fully-scanned stream
//!                                 is unscannable, NEVER clean)
//!                               {"v":1,"verdict":"error","message":M}
//!                                 (transient/infra failure the client may retry)
//!                             Verdict classification matches INSTREAM (a
//!                             detection beats a limit; one detection per scan).
//!                             Unknown to old clients → `UNKNOWN COMMAND` (below).
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
    analyze_all, scan_path, scan_seekable_located, scan_stream, Database, ScanOptions, ScanReport,
    VerdictCategory,
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
fn clamav_version(db: &Database) -> String {
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
    /// Unix domain socket at this path.
    #[cfg(unix)]
    Unix(std::path::PathBuf),
    /// TCP `host:port`.
    Tcp(String),
}

/// Longest command line (selectors + path) the daemon will buffer. INSTREAM
/// payload is read separately by length-prefixed chunks, not via this path.
const MAX_COMMAND: usize = 64 * 1024;

/// Cap on concurrent client connections. Each connection gets its own thread;
/// without a cap a flood of connections would exhaust threads/memory.
const MAX_CONNECTIONS: usize = 128;

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
pub fn run(
    db: Database,
    addr: ListenAddr,
    opts: ScanOptions,
    allow_shutdown: bool,
) -> io::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let conns = Arc::new(AtomicUsize::new(0));
    // A client that disconnects right after reading a reply would otherwise
    // deliver SIGPIPE on the next write and (Rust resets SIGPIPE to default)
    // kill the whole daemon. Ignore it so writes fail per-connection with EPIPE.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let db = Arc::new(db);
    let opts = Arc::new(opts);
    match addr {
        #[cfg(unix)]
        ListenAddr::Unix(path) => {
            use std::os::unix::net::UnixListener;
            // Remove a stale socket from a previous run before binding.
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path)?;
            restrict_socket_perms(&path);
            eprintln!("exav: daemon listening on unix:{}", path.display());
            for stream in listener.incoming() {
                let stream = stream?;
                let _ = stream.set_read_timeout(Some(SOCKET_READ_TIMEOUT));
                if conns.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
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
                if conns.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
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
// model fundamentally can't do safely (no safe thread-kill in Rust/C).
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
// `max_scan_bytes`/ratio/recursion caps still fire first and identically in
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
        ListenAddr::Unix(path) => {
            let _ = std::fs::remove_file(path);
            let l = std::os::unix::net::UnixListener::bind(path)?;
            restrict_socket_perms(path);
            Ok(BoundListener::Unix(l))
        }
        ListenAddr::Tcp(a) => Ok(BoundListener::Tcp(TcpListener::bind(a)?)),
    }
}

/// Restrict a freshly-bound Unix socket to the owner (mode 0600) so only the
/// user running the daemon can connect. Best-effort: on the `/tmp` fallback
/// there is a brief window between bind and chmod, so prefer `$XDG_RUNTIME_DIR`
/// (the default when set), whose directory is already owner-only.
#[cfg(unix)]
fn restrict_socket_perms(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
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
/// Only called from the `http`-gated updater, so it's dead in a no-updater build.
#[cfg(unix)]
#[cfg_attr(not(feature = "http"), allow(dead_code))]
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
/// **directory** this is the newest mtime across it and its entries (a rename or
/// a new file bumps the dir mtime; scanning entries too catches an in-place
/// overwrite). For a single **file** (a prebuilt cache) it is just that file's
/// mtime — an atomic swap replaces it with a newer-mtime inode, so the poll fires.
/// `None` if the path can't be stat'd.
#[cfg(unix)]
fn datadir_mtime(dir: &std::path::Path) -> Option<std::time::SystemTime> {
    let mut newest = std::fs::metadata(dir).and_then(|m| m.modified()).ok()?;
    // `read_dir` fails on a file, leaving `newest` as the file's own mtime.
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if let Ok(t) = e.metadata().and_then(|m| m.modified()) {
                if t > newest {
                    newest = t;
                }
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

/// Run the daemon as a prefork pool of `cfg.workers` worker processes.
///
/// `datadir` (when `Some`) is polled for on-disk changes so a sidecar that writes
/// the volume triggers a reload without sending `RELOAD`. `reload_db` re-reads the
/// signatures; on a `RELOAD`/SIGHUP/data-dir change the supervisor calls it,
/// warms the result, and re-forks the pool with the new DB — a failed reload is
/// logged and the running DB is kept.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub fn run_prefork(
    db: Database,
    addr: ListenAddr,
    opts: ScanOptions,
    cfg: PoolConfig,
    datadir: Option<std::path::PathBuf>,
    reload_db: &dyn Fn() -> Result<Database, String>,
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

    let mut db = Arc::new(db);
    let opts = Arc::new(opts);

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

    let mut last_mtime = datadir.as_deref().and_then(datadir_mtime);

    // Supervisor: reap exited workers and respawn to keep the count constant,
    // reload signatures on request, until a shutdown signal arrives.
    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }

        // Reap any exited workers without blocking, so we can also service
        // reloads and the data-dir poll in this loop.
        loop {
            let mut status: libc::c_int = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                break; // 0 = none exited yet; <0 = no children / error
            }
            children.remove(&pid);
            log_worker_exit(pid, status);
            if !SHUTDOWN.load(Ordering::Relaxed) {
                children.insert(spawn_worker(&listener, &db, &opts, &cfg)?);
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
                    // DB, then retire the old workers (reaped on the next tick).
                    let old: Vec<libc::pid_t> = children.drain().collect();
                    for _ in 0..cfg.workers {
                        children.insert(spawn_worker(&listener, &db, &opts, &cfg)?);
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

    // Graceful teardown: signal every worker, then reap them.
    for &pid in &children {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    for &pid in &children {
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn spawn_worker(
    listener: &BoundListener,
    db: &Arc<Database>,
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
fn worker_main(listener: &BoundListener, db: &Database, opts: &ScanOptions, cfg: &PoolConfig) -> ! {
    // Apply the kernel-enforced resource caps to *this* process.
    set_rlimit(libc::RLIMIT_AS as libc::c_int, cfg.max_memory_bytes);
    set_rlimit(libc::RLIMIT_CPU as libc::c_int, cfg.max_cpu_secs);
    install_handler(libc::SIGALRM, on_sigalrm);
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
                    let reader = AncillaryReader::new(&stream);
                    let r =
                        handle_conn(reader, &stream, db, opts, &arm, &disarm, &reload, &shutdown);
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
                    let s = TcpListenerStream(stream);
                    let r = handle_conn(&s, &s, db, opts, &arm, &disarm, &reload, &shutdown);
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

/// Decode a reaped worker's wait-status into a human-readable cause, so the
/// operator can see *why* a worker died (timeout / OOM / CPU / recycle).
#[cfg(unix)]
fn log_worker_exit(pid: libc::pid_t, status: libc::c_int) {
    let cause = if libc::WIFEXITED(status) {
        match libc::WEXITSTATUS(status) {
            EXIT_TIMEOUT => "scan wall-clock timeout".to_string(),
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
    eprintln!("exav: worker {pid} exited: {cause}");
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
    Ok(Some((String::from_utf8_lossy(&buf).into_owned(), delim)))
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
    db: &Database,
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
    db: &Database,
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
    } else if word.eq_ignore_ascii_case("SHUTDOWN") {
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
    for reply in replies {
        write_reply(writer, id, &reply, delim)?;
    }
    Ok(())
}

/// FILDES: scan a file descriptor passed over the socket via SCM_RIGHTS.
fn fildes<R: Read + FdSource>(
    reader: &mut BufReader<R>,
    db: &Database,
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
    db: &Database,
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
        "VERSIONCOMMANDS" => vec![format!(
            "{}| COMMANDS: SCAN CONTSCAN MULTISCAN ALLMATCHSCAN INSTREAM EXINSTREAM FILDES \
             STATS VERSION VERSIONCOMMANDS RELOAD SHUTDOWN PING IDSESSION SESSION END",
            clamav_version(db)
        )],
        // RELOAD is intercepted in `run_command` (it needs the supervisor hook).
        // clamd-compatible status block: POOLS/STATE/THREADS/QUEUE/MEMSTATS/END,
        // the shape `clamdtop` parses for its live columns. exav has no custom
        // allocator instrumentation, so the heap/mmap memory figures are `N/A`
        // (clamd reports the same when built without its pools allocator).
        "STATS" => {
            let max = daemon_max_workers();
            vec![format!(
                "POOLS: 1\n\nSTATE: VALID PRIMARY\n\
                 THREADS: live 1  idle 0 max {max} idle-timeout 30\n\
                 QUEUE: 0 items\n\tSTATS 0.000000 \n\n\
                 MEMSTATS: heap N/A mmap N/A used N/A free N/A releasable N/A \
                 pools 1 pools_used N/A pools_total N/A\nEND"
            )]
        }
        "SCAN" => vec![scan_one_path(db, opts, arg)],
        "CONTSCAN" | "MULTISCAN" => scan_tree(db, opts, arg),
        // All-match: report every matching signature per file (not just the
        // first), one reply line each — clamd's ALLMATCHSCAN semantics.
        "ALLMATCHSCAN" => scan_tree_allmatch(db, opts, arg),
        "INSTREAM" => vec![instream(db, opts, reader)?],
        // Extended INSTREAM: same chunk framing, structured JSON reply with the
        // nested match location. Older/newer clients that don't know it fall to
        // the `UNKNOWN COMMAND` arm below and degrade cleanly.
        "EXINSTREAM" => vec![exinstream(db, opts, reader)?],
        #[cfg(feature = "http")]
        "SCANURL" => vec![scan_url(db, opts, arg)],
        #[cfg(not(feature = "http"))]
        "SCANURL" => vec![format!(
            "{arg}: SCANURL needs a build with `--features http` ERROR"
        )],
        _ => vec![format!("UNKNOWN COMMAND {word} ERROR")],
    };
    Ok(reply)
}

fn write_reply<W: Write>(w: &mut W, id: Option<u64>, reply: &str, delim: Delim) -> io::Result<()> {
    // In session (IDSESSION) mode each reply MESSAGE is tagged with its command
    // id on its FIRST line only; the remaining lines of a multi-line reply (the
    // STATS block) travel raw, exactly as clamd frames them. Prefixing every line
    // (as we once did) breaks clamd-session clients like clamdtop, which then see
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
/// [`Verdict`] classification in exav-core. A not-scanned verdict is surfaced as
/// `<TAG> (<reason>) ERROR` (never `OK`) so the never-silent-skip invariant
/// holds on the wire, and the tag/detail come from the same source the one-shot
/// CLI uses — the two surfaces cannot drift apart.
fn verdict_line(target: &str, report: &ScanReport) -> String {
    let v = &report.verdict;
    match v.category() {
        VerdictCategory::Infected => format!("{target}: {} FOUND", v.detail().unwrap_or_default()),
        VerdictCategory::Clean => format!("{target}: OK"),
        VerdictCategory::NotScanned => format!(
            "{target}: {} ({}) ERROR",
            v.status_tag(),
            v.detail().unwrap_or_default()
        ),
    }
}

fn scan_one_path(db: &Database, opts: &ScanOptions, path: &str) -> String {
    if path.is_empty() {
        return "SCAN: missing path ERROR".to_string();
    }
    // Isolate a panic on a malicious file: report ERROR for this target rather
    // than letting it tear down the connection (or, with the per-file recursion
    // in scan_tree, the rest of the walk).
    let scanned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scan_path(db, Path::new(path), opts)
    }));
    match scanned {
        Ok(Ok(report)) => verdict_line(path, &report),
        Ok(Err(e)) => format!("{path}: {e} ERROR"),
        Err(_) => format!("{path}: scan failed (internal error) ERROR"),
    }
}

/// CONTSCAN/MULTISCAN: a single file scans like SCAN; a directory yields one
/// reply line per regular file (recursively).
fn scan_tree(db: &Database, opts: &ScanOptions, path: &str) -> Vec<String> {
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
    let mut out = Vec::new();
    for entry in WalkDir::new(p).follow_links(false).into_iter().flatten() {
        if entry.file_type().is_file() {
            out.push(scan_one_path(db, opts, &entry.path().to_string_lossy()));
        }
    }
    if out.is_empty() {
        out.push(format!("{path}: OK"));
    }
    out
}

/// ALLMATCHSCAN: like [`scan_tree`] but every matching signature is reported per
/// file (one reply line each), not just the first.
fn scan_tree_allmatch(db: &Database, opts: &ScanOptions, path: &str) -> Vec<String> {
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
    let mut out = Vec::new();
    for entry in WalkDir::new(p).follow_links(false).into_iter().flatten() {
        if entry.file_type().is_file() {
            out.extend(scan_one_allmatch(db, opts, &entry.path().to_string_lossy()));
        }
    }
    if out.is_empty() {
        out.push(format!("{path}: OK"));
    }
    out
}

/// All-match scan of a single file: report every matching signature. Works on a
/// buffered copy (bounded by `deep_analysis_max`); a larger file falls back to a
/// normal single-match scan so it is never silently skipped — mirroring the CLI's
/// `--allmatch` so the two surfaces agree.
fn scan_one_allmatch(db: &Database, opts: &ScanOptions, path: &str) -> Vec<String> {
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
        analyze_all(db, &data, opts)
    }));
    match found {
        Ok(dets) if !dets.is_empty() => dets
            .into_iter()
            .map(|(sig, _method)| format!("{path}: {sig} FOUND"))
            .collect(),
        Ok(_) => vec![format!("{path}: OK")],
        Err(_) => vec![format!("{path}: scan failed (internal error) ERROR")],
    }
}

#[cfg(feature = "http")]
fn scan_url(db: &Database, opts: &ScanOptions, url: &str) -> String {
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

/// Small streams below this stay in RAM; larger ones spill to a temp file.
const STREAM_SPILL_THRESHOLD: usize = 16 * 1024 * 1024;

/// A stream payload materialized into a **seekable** source — in RAM when small,
/// else spilled to an auto-deleting temp file. A seekable view is what lets a
/// streamed input (INSTREAM/EXINSTREAM, and the CLI's stdin) get full
/// container-aware scanning (a ZIP's central directory is at the end) at ANY size
/// with bounded memory, matching clamd. `.len()` reports its size.
pub(crate) enum StreamPayload {
    Mem(Vec<u8>),
    Disk(tempfile::NamedTempFile, u64),
}

impl StreamPayload {
    pub(crate) fn len(&self) -> u64 {
        match self {
            StreamPayload::Mem(v) => v.len() as u64,
            StreamPayload::Disk(_, n) => *n,
        }
    }
}

/// Buffer an (already de-chunked / pre-capped) reader into a [`StreamPayload`]:
/// up to `STREAM_SPILL_THRESHOLD` in RAM, then spill the rest to a temp file.
/// Shared by the daemon stream verbs and the CLI stdin path so both get the same
/// seekable, container-aware scan.
pub(crate) fn buffer_to_seekable<R: Read>(reader: &mut R) -> io::Result<StreamPayload> {
    let mut buf = Vec::new();
    reader
        .by_ref()
        .take(STREAM_SPILL_THRESHOLD as u64)
        .read_to_end(&mut buf)?;
    if buf.len() < STREAM_SPILL_THRESHOLD {
        return Ok(StreamPayload::Mem(buf));
    }
    // More data remains — spill the RAM head, then stream the rest to disk.
    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(&buf)?;
    io::copy(reader, tmp.as_file_mut())?;
    let len = tmp.as_file().metadata()?.len();
    Ok(StreamPayload::Disk(tmp, len))
}

/// Scan a materialized payload via the seekable (container-aware) path, returning
/// the report and the nested match location (`None` for a top-level hit).
pub(crate) fn scan_payload(
    db: &Database,
    opts: &ScanOptions,
    payload: StreamPayload,
) -> io::Result<(ScanReport, Option<String>)> {
    match payload {
        StreamPayload::Mem(v) => {
            let n = v.len() as u64;
            scan_seekable_located(db, std::io::Cursor::new(v), n, opts)
        }
        StreamPayload::Disk(tmp, len) => {
            // A fresh handle positioned at 0; the `NamedTempFile` stays alive
            // (and thus the file) until it drops at the end of this scope.
            let file = tmp.reopen()?;
            scan_seekable_located(db, file, len, opts)
        }
    }
}

/// Scan an INSTREAM chunk stream. The payload is materialized to a seekable
/// source (RAM or a temp file) and given the full container-aware scan — so
/// malware inside an archive sent over INSTREAM is detected, matching clamd (the
/// old flat-only path missed it). Any unread chunks are drained so the connection
/// stays in sync for the next command.
fn instream<R: Read>(
    db: &Database,
    opts: &ScanOptions,
    reader: &mut BufReader<R>,
) -> io::Result<String> {
    let max = opts.max_scan_size;
    let mut stream = Instream::new(reader, max);
    let payload = buffer_to_seekable(&mut stream)?;
    let over = stream.over_limit;
    stream.drain()?;
    if over {
        let max = max.unwrap_or(0);
        return Ok(format!(
            "stream: LIMITS-EXCEEDED (size exceeds {max}) ERROR"
        ));
    }
    let (report, _loc) = scan_payload(db, opts, payload)?;
    Ok(verdict_line("stream", &report))
}

/// `EXINSTREAM`: scan a file sent over the exact INSTREAM chunk framing and reply
/// with one line of compact JSON — `{"v":1,"verdict":...}`. Unlike INSTREAM's
/// flat scan, the payload is buffered (bounded by `--max-scansize`) and run
/// through the full container-aware analysis, so a detection carries its nested
/// `location` (the `/`-joined member path). The verdict *classification* matches
/// INSTREAM: a detection beats a limit; a not-fully-scanned stream is
/// `unscannable`, never `clean`. An over-limit stream is `unscannable` (never
/// clean). One detection per scan (first / most relevant).
fn exinstream<R: Read>(
    db: &Database,
    opts: &ScanOptions,
    reader: &mut BufReader<R>,
) -> io::Result<String> {
    // Materialize to a seekable source (RAM small / temp file large) — same path
    // as INSTREAM — bounded by `--max-scansize` (disk is the ceiling).
    let mut stream = Instream::new(reader, opts.max_scan_size);
    let payload = match buffer_to_seekable(&mut stream) {
        Ok(p) => p,
        Err(e) => {
            let _ = stream.drain();
            return Ok(json_error(&format!("stream read error: {e}")));
        }
    };
    let over = stream.over_limit;
    stream.drain()?;
    if over {
        return Ok(json_unscannable(
            "LIMITS-EXCEEDED",
            Some("stream exceeds max-scansize; not fully scanned"),
        ));
    }
    match scan_payload(db, opts, payload) {
        Ok((report, loc)) => Ok(verdict_json(&report, loc)),
        Err(e) => Ok(json_error(&format!("scan error: {e}"))),
    }
}

/// Render a scan verdict as one line of compact JSON for `EXINSTREAM`.
fn verdict_json(report: &ScanReport, location: Option<String>) -> String {
    use serde_json::json;
    let v = &report.verdict;
    let val = match v.category() {
        VerdictCategory::Clean => json!({"v": 1, "verdict": "clean"}),
        VerdictCategory::Infected => {
            let mut o = json!({
                "v": 1,
                "verdict": "malware",
                "signature": v.detail().unwrap_or_default(),
            });
            // `location` only for a nested hit; omitted for a top-level match.
            if let Some(l) = location {
                o["location"] = json!(l);
            }
            o
        }
        VerdictCategory::NotScanned => {
            let mut o = json!({
                "v": 1,
                "verdict": "unscannable",
                "tag": v.status_tag(),
            });
            if let Some(m) = v.detail() {
                o["message"] = json!(m);
            }
            o
        }
    };
    val.to_string()
}

fn json_error(message: &str) -> String {
    serde_json::json!({"v": 1, "verdict": "error", "message": message}).to_string()
}

fn json_unscannable(tag: &str, message: Option<&str>) -> String {
    let mut o = serde_json::json!({"v": 1, "verdict": "unscannable", "tag": tag});
    if let Some(m) = message {
        o["message"] = serde_json::json!(m);
    }
    o.to_string()
}

/// A `Read` over a clamd INSTREAM chunk sequence: `<u32 be len><data>` repeated,
/// ended by a zero length. Presents the de-chunked payload as one stream.
struct Instream<'a, R: Read> {
    inner: &'a mut BufReader<R>,
    /// Bytes left in the current chunk.
    remaining: u32,
    /// True once the terminating zero-length chunk is seen.
    done: bool,
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
            total: 0,
            max,
            over_limit: false,
        }
    }

    /// Read the next chunk length, setting `done` on the zero terminator.
    fn next_chunk(&mut self) -> io::Result<()> {
        let mut len = [0u8; 4];
        if read_full(self.inner, &mut len)? < 4 {
            // Client closed mid-frame; treat as end of stream.
            self.done = true;
            return Ok(());
        }
        self.remaining = u32::from_be_bytes(len);
        if self.remaining == 0 {
            self.done = true;
        }
        Ok(())
    }

    /// Consume any remaining chunks up to the terminator (used when the scan
    /// stopped early on a detection).
    fn drain(&mut self) -> io::Result<()> {
        let mut sink = [0u8; 8192];
        while !self.done {
            if self.remaining == 0 {
                self.next_chunk()?;
                continue;
            }
            let want = self.remaining.min(sink.len() as u32) as usize;
            let n = read_full(self.inner, &mut sink[..want])?;
            if n == 0 {
                self.done = true;
                break;
            }
            self.remaining -= n as u32;
        }
        Ok(())
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
                self.done = true;
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

    const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

    /// Spawn a handler on one end of a socket pair; return the client end.
    fn serve() -> UnixStream {
        let (client, server) = UnixStream::pair().unwrap();
        let db = Database::builtin();
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
    fn one_with(send: &[u8], delim: u8, opts: ScanOptions) -> String {
        let (mut client, server) = UnixStream::pair().unwrap();
        let db = Database::builtin();
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
        // Regression: INSTREAM must detect malware INSIDE an archive (clamd does;
        // the old flat-only path missed it). EICAR is DEFLATE-compressed inside
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
            r#"{"v":1,"verdict":"clean"}"#
        );
    }

    #[test]
    fn exinstream_eicar_top_level_no_location() {
        let r = one(&exinstream_msg(EICAR), 0);
        assert!(r.contains(r#""verdict":"malware""#), "got {r}");
        assert!(r.contains(r#""signature":"#), "got {r}");
        assert!(
            !r.contains("location"),
            "top-level hit must have no location: {r}"
        );
    }

    #[test]
    fn exinstream_eicar_in_zip_has_location() {
        let r = one(&exinstream_msg(ZIP_EICAR_INSIDE), 0);
        assert!(r.contains(r#""verdict":"malware""#), "got {r}");
        assert!(r.contains(r#""location":"inside.txt""#), "got {r}");
    }

    #[test]
    fn exinstream_zip_in_zip_full_path() {
        let r = one(&exinstream_msg(ZIP_IN_ZIP_EICAR), 0);
        assert!(r.contains(r#""verdict":"malware""#), "got {r}");
        assert!(
            r.contains(r#""location":"inner.zip/inside.txt""#),
            "nested path chain expected, got {r}"
        );
    }

    #[test]
    fn exinstream_password_protected() {
        let r = one(&exinstream_msg(ZIP_ENCRYPTED), 0);
        assert!(r.contains(r#""verdict":"unscannable""#), "got {r}");
        assert!(r.contains(r#""tag":"PASSWORD-PROTECTED""#), "got {r}");
    }

    #[test]
    fn exinstream_oversized_is_unscannable_never_clean() {
        // A stream past `--max-scansize` can't be fully scanned → it must be
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
        assert!(r.contains(r#""verdict":"unscannable""#), "got {r}");
        assert!(
            !r.contains(r#""verdict":"clean""#),
            "must never be clean: {r}"
        );
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
        assert!(one(&instream_msg(EICAR), 0).contains("FOUND"));
        assert_eq!(
            one(&instream_msg(b"totally benign content"), 0),
            "stream: OK"
        );
    }

    #[test]
    fn instream_chunked_across_frames() {
        // EICAR split across several INSTREAM chunks must still match.
        let mut msg = b"zINSTREAM\0".to_vec();
        for chunk in EICAR.chunks(7) {
            msg.extend((chunk.len() as u32).to_be_bytes());
            msg.extend_from_slice(chunk);
        }
        msg.extend(0u32.to_be_bytes());
        assert!(one(&msg, 0).contains("FOUND"));
    }

    #[test]
    fn scan_path_eicar_and_clean() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad");
        std::fs::write(&bad, EICAR).unwrap();
        let good = dir.path().join("good");
        std::fs::write(&good, b"hello there").unwrap();
        let rb = one(format!("zSCAN {}\0", bad.display()).as_bytes(), 0);
        assert!(rb.contains("FOUND"), "got {rb}");
        let rg = one(format!("zSCAN {}\0", good.display()).as_bytes(), 0);
        assert!(rg.ends_with("OK"), "got {rg}");
    }

    #[test]
    fn idsession_prefixes_replies_and_closes_on_end() {
        let mut w = serve();
        let mut r = BufReader::new(w.try_clone().unwrap());
        w.write_all(b"zIDSESSION\0").unwrap();
        w.write_all(&instream_msg(EICAR)).unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad");
        std::fs::write(&bad, EICAR).unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad");
        std::fs::write(&bad, EICAR).unwrap();
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
        let db = Database::builtin();
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
        let db = Database::builtin();
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
        let db = Database::builtin();
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
