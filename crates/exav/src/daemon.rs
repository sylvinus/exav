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
//!   `RELOAD`               -> `RELOADING`; the supervisor re-reads the
//!                             signatures (in the prefork pool, re-forking the
//!                             workers with them), as `SIGUSR2` does. The
//!                             mechanism a stock `freshclam`'s `NotifyClamd`
//!                             drives
//!   `SCAN <path>`          -> `<path>: OK` / `<path>: <sig> FOUND` / `… ERROR`
//!   `CONTSCAN <path>`      -> recurse a directory, one reply line per file
//!   `MULTISCAN <path>`     -> alias of CONTSCAN
//!   `INSTREAM`             -> scan a `<u32 len><data>…<u32 0>` chunked stream.
//!                             The payload is materialized to a seekable source
//!                             (kept in RAM when small, spilled to an auto-deleted
//!                             temp file when large) and given the FULL
//!                             container-aware scan, so malware inside an archive
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
//!                                 the stream to the matched leaf; control bytes
//!                                 sanitised, capped ~512 chars)
//!                               {"v":1,"status":"PARTIAL","category":C[,"reason":R]}
//!                                 (C ∈ LIMITS-EXCEEDED / UNSCANNABLE /
//!                                 PASSWORD-PROTECTED; a stream that was not
//!                                 fully scanned is PARTIAL unless `--partial-as`
//!                                 says otherwise)
//!                               {"v":1,"status":"ERROR","reason":R}
//!                                 (transient/infra failure the client may retry,
//!                                 a stream that ended before its terminator,
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
//!                             archive it is. Sent one at a time, no part decodes
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
//!                             range requests (no download); reply `<url>: …`.
//!                             Honoured only when the daemon was started with
//!                             `--allow-http-scan`, and listed in VERSIONCOMMANDS
//!                             only then.
//!   `IDSESSION` / `END`    -> session mode; each reply is prefixed `<n>: `
//!
//! A limit that prevents a full scan is reported as `ERROR` carrying
//! `LIMITS-EXCEEDED`, never a silent `OK` (exav's core invariant).

use std::cell::Cell;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use exav_core::{
    AllMatchOutcome, ScanOptions, ScanReport, Scanner, Verdict, VerdictCategory, analyze_all_path,
    scan_path, scan_seekable_located,
};
use walkdir::WalkDir;

/// Whether this daemon honours `SHUTDOWN` and `QUIT`, set once at startup and
/// inherited by every forked worker, so that `VERSIONCOMMANDS` lists them only
/// when they work.
static SHUTDOWN_ALLOWED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The `VERSIONCOMMANDS` reply: the version, then the verbs this daemon honours.
fn versioncommands(version: &str, shutdown: bool, scanurl: bool) -> String {
    format!(
        "{version}| COMMANDS: SCAN CONTSCAN MULTISCAN ALLMATCHSCAN INSTREAM EXINSTREAM FILDES \
         STATS VERSION VERSIONCOMMANDS RELOAD{} PING IDSESSION SESSION END{}",
        if shutdown { " SHUTDOWN QUIT" } else { "" },
        if cfg!(feature = "http-scan") && scanurl {
            " SCANURL"
        } else {
            ""
        }
    )
}

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

/// The `STATS` reply: clamd's block, then exav's counters. Under the pool the
/// counters are shared by every process (`metrics::share_across_fork`), so any
/// process, the health child included, reports the pool's totals.
pub(crate) fn stats_reply() -> String {
    let max = daemon_max_workers();
    let live = crate::metrics::in_flight();
    format!(
        "POOLS: 1\n\nSTATE: VALID PRIMARY\n\
         THREADS: live {live}  idle 0 max {max} idle-timeout 30\n\
         QUEUE: {live} items\n\tSTATS 0.000000 \n\n\
         MEMSTATS: heap N/A mmap N/A used N/A free N/A releasable N/A \
         pools 1 pools_used N/A pools_total N/A\n{}\nEND",
        crate::metrics::stats_block()
    )
}

/// The clamd-compatible `VERSION` string: `ClamAV <flevel-release>/<db-version>/
/// <db-build-time>` when a signed container is loaded (what `clamdtop` parses
/// into its ENGINE / DBVER / DBTIME columns), degrading to just `ClamAV
/// <release>` for the loose-signature / built-in-baseline case (no container to
/// report a version for).
pub(crate) fn clamav_version(db: &Scanner) -> String {
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
        // The weekday sum below is for real calendar years; a build time is
        // text from a database file.
        if !(1..=9999).contains(&year) {
            return None;
        }
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
pub(crate) trait FdSource {
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
    // Safety invariant: each is an open descriptor this reader alone owns,
    // listed once.
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
        // Control buffer sized for a handful of fds. `u64` rather than `u8` for
        // the alignment `cmsghdr` needs, as in `send_fd_command`.
        let mut cmsg = [0u64; 32];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY:
        // - `mem::zeroed::<msghdr>`: its fields are integers and raw pointers,
        //   for which all-zero bytes are valid values.
        // - `recvmsg` (POSIX): `msg_iov` is one `iovec` naming `buf`, writable
        //   for `buf.len()` bytes; `msg_control` is `cmsg`, writable for
        //   `msg_controllen` bytes and aligned for `cmsghdr` (`u64`). Both
        //   outlive the call, which sets `msg_controllen` to what it wrote.
        // - `CMSG_FIRSTHDR` and `CMSG_NXTHDR` give null or a header within
        //   those bytes, so `*c` reads a `cmsghdr` the kernel wrote.
        // - For `SCM_RIGHTS` the kernel sets `cmsg_len` to `CMSG_LEN` of the
        //   descriptors it installed, within the buffer: `data.add(i * 4)` for
        //   `i < count` stays in it, and `copy_nonoverlapping` copies 4 bytes
        //   into the local `fd`, with no alignment needed.
        // - The descriptors are new to this process and owned by nothing
        //   else: pushed once each, they keep the invariant of `fds`.
        let n = unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = std::mem::size_of_val(&cmsg) as _;
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
        // SAFETY: `File::from_raw_fd` needs an open descriptor the caller owns.
        // By the invariant of `fds`, `fd` is one this reader alone owns, and
        // `pop` removes it, so the `File` is its only owner.
        self.fds.pop().map(|fd| unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
impl SetReadTimeout for AncillaryReader<'_> {
    fn set_read_timeout(&self, wait: Duration) -> io::Result<()> {
        self.stream.set_read_timeout(Some(wait))
    }
}

/// Send `cmd` on `stream` with `fd` attached as `SCM_RIGHTS` ancillary data:
/// the client half of `FILDES`, and the one thing a plain `write` cannot do.
///
/// The descriptor the daemon receives is its own, pointing at the same open
/// file: it reads the bytes this client already has access to, without needing
/// permission on the path or a view of this filesystem.
#[cfg(unix)]
pub(crate) fn send_fd_command(
    stream: &std::os::unix::net::UnixStream,
    cmd: &[u8],
    fd: std::os::fd::BorrowedFd<'_>,
) -> io::Result<()> {
    use std::os::fd::{AsRawFd, RawFd};
    const FD_SIZE: usize = std::mem::size_of::<RawFd>();
    let fd = fd.as_raw_fd();
    let mut iov = libc::iovec {
        iov_base: cmd.as_ptr() as *mut libc::c_void,
        iov_len: cmd.len(),
    };
    // `usize` rather than `u8`: a control buffer has to be aligned for
    // `cmsghdr`, and a byte array carries no such guarantee.
    let mut control = [0usize; 8];
    // SAFETY:
    // - `mem::zeroed::<msghdr>`: its fields are integers and raw pointers,
    //   for which all-zero bytes are valid values.
    // - `CMSG_FIRSTHDR` returns `control`'s start, non-null since
    //   `msg_controllen` (`CMSG_SPACE` of one descriptor, 24 bytes at most)
    //   holds a `cmsghdr`; `control` is 64 bytes, aligned for `cmsghdr`
    //   (`usize`), so the three field writes through `c` are in bounds and
    //   aligned, and `CMSG_DATA(c)` has room for `FD_SIZE` bytes after them.
    // - `copy_nonoverlapping` copies `FD_SIZE` bytes from the local `fd`.
    // - `sendmsg` (POSIX) only reads: `iov` names `cmd`, readable for
    //   `cmd.len()` bytes, and `msg_control` the header just written; all
    //   outlive the call. `fd` is open for it: it comes from a `BorrowedFd`.
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
            // SAFETY: `close` ends a descriptor this process owns. By the
            // invariant of `fds`, this reader alone owns `fd`, and `drain`
            // takes each out once.
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

/// Default of `?idle-secs=` on a clamd address, the most one read from a
/// client waits (for a command, the next INSTREAM chunk, or the next command
/// of an `IDSESSION`) and the most one write of a reply waits for a client
/// that is not reading it. clamd's `ReadTimeout` default. It is what keeps a
/// client that sends or takes nothing from holding a connection slot, or a
/// pool worker; a stall past it closes the connection. It bounds each read and
/// write, not a whole command: that is [`DEFAULT_COMMAND_READ`]'s job.
pub(crate) const DEFAULT_IDLE: Duration = Duration::from_secs(120);

/// The time a clamd client has, from its address: to send, to stay
/// connected, and to take the replies.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reads {
    /// The most one read or one write waits (`?idle-secs=`).
    pub idle: Duration,
    /// The most one command takes in full (`?request-secs=`, `None` for no
    /// limit).
    pub command: Option<Duration>,
    /// How long a connection stays open, from accept (`?session-secs=`, `None`
    /// for no limit): after it no new command is read.
    pub session: Option<Duration>,
    /// The most the writes of one reply wait for the client, in all
    /// (`?reply-secs=`, `None` for no limit).
    pub reply: Option<Duration>,
}

impl Reads {
    /// Each read bounded by [`DEFAULT_IDLE`], a command by `command`, and
    /// nothing else.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn with_command(command: Option<Duration>) -> Self {
        Reads {
            idle: DEFAULT_IDLE,
            command,
            session: None,
            reply: None,
        }
    }
}

/// Default of `?request-secs=`, the most time one clamd command or ICAP
/// request may take to arrive in full.
pub(crate) const DEFAULT_COMMAND_READ: Duration = Duration::from_secs(600);

/// `?request-secs=` as a limit: unset is the default, `0` (which `off` parses
/// to) is no limit.
pub(crate) fn command_read_limit(secs: Option<u64>) -> Option<Duration> {
    match secs {
        None => Some(DEFAULT_COMMAND_READ),
        Some(0) => None,
        Some(s) => Some(Duration::from_secs(s)),
    }
}

/// An accept error that leaves the listener usable: the connection it was for
/// is gone, or the process is short of a resource that closing connections give
/// back. Anything else (a closed or invalid listener) is not mended by waiting.
fn transient_accept_error(e: &io::Error) -> bool {
    if matches!(
        e.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
    ) {
        return true;
    }
    #[cfg(unix)]
    if let Some(code) = e.raw_os_error() {
        // Out of descriptors or memory, which closing connections give back,
        // and the errors accept(2) says a caller is to treat like EAGAIN,
        // which belong to the new connection and not to the listener.
        #[cfg(target_os = "linux")]
        if code == libc::ENONET {
            return true;
        }
        return matches!(
            code,
            libc::EMFILE
                | libc::ENFILE
                | libc::ENOBUFS
                | libc::ENOMEM
                | libc::EPERM
                | libc::EPROTO
                | libc::ENETDOWN
                | libc::ENOPROTOOPT
                | libc::EHOSTDOWN
                | libc::EHOSTUNREACH
                | libc::EOPNOTSUPP
                | libc::ENETUNREACH
        );
    }
    false
}

/// The pauses between accepts that keep failing: 5 ms, doubling to 1 s, and
/// starting over once an accept works. Without a pause an accept that fails for
/// want of a descriptor fails again at once, because the connection it was
/// for stays queued, and the listener spins and floods the log.
#[derive(Default)]
pub(crate) struct AcceptBackoff(Option<Duration>);

impl AcceptBackoff {
    const FIRST: Duration = Duration::from_millis(5);
    const LAST: Duration = Duration::from_secs(1);

    /// How long to wait before the next accept, after one that failed.
    pub(crate) fn pause(&mut self) -> Duration {
        let now = self.0.unwrap_or(Self::FIRST);
        self.0 = Some((now * 2).min(Self::LAST));
        now
    }

    /// An accept worked.
    pub(crate) fn reset(&mut self) {
        self.0 = None;
    }
}

/// Hands each connection `accept` returns to `serve`, until an accept fails in a
/// way waiting does not mend, which is returned. A transient failure is logged
/// and retried after a pause ([`AcceptBackoff`]).
fn accept_loop<S>(
    mut accept: impl FnMut() -> io::Result<S>,
    mut serve: impl FnMut(S),
) -> io::Result<()> {
    let mut backoff = AcceptBackoff::default();
    loop {
        match accept() {
            Ok(conn) => {
                backoff.reset();
                serve(conn);
            }
            Err(e) if transient_accept_error(&e) => {
                let pause = backoff.pause();
                eprintln!(
                    "exav: accept failed, trying again in {} ms: {e}",
                    pause.as_millis()
                );
                std::thread::sleep(pause);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Runs `job`, which owns one accepted connection and was counted in `conns`,
/// on a thread of its own. When no thread can be had the connection is dropped,
/// as at capacity, and its count given back: `std::thread::spawn` would panic
/// the listener's thread instead.
fn spawn_conn(conns: &Arc<std::sync::atomic::AtomicUsize>, job: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new().spawn(job) {
        conns.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        eprintln!("exav: no thread for a new connection, dropping it: {e}");
    }
}

/// What a read fails with once its command has run out of time.
#[derive(Debug)]
pub(crate) struct CommandTooSlow;

impl std::fmt::Display for CommandTooSlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the client took longer than ?request-secs= to send its command")
    }
}

impl std::error::Error for CommandTooSlow {}

/// Whether `e` is [`CommandTooSlow`].
pub(crate) fn is_too_slow(e: &io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.is::<CommandTooSlow>())
}

/// What a write fails with once the client has not read for the whole of the
/// socket's write timeout (`?idle-secs=`), or for the whole of the reply's
/// time (`?reply-secs=`).
#[derive(Debug)]
pub(crate) struct ClientNotReading;

impl std::fmt::Display for ClientNotReading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the client did not read its reply within ?idle-secs= or ?reply-secs=")
    }
}

impl std::error::Error for ClientNotReading {}

/// Whether `e` is [`ClientNotReading`].
pub(crate) fn is_not_reading(e: &io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.is::<ClientNotReading>())
}

/// What a read fails with when the connection reached its lifetime
/// (`?session-secs=`) while waiting for the first byte of a command or request.
/// An ordinary end of connection: not logged.
#[derive(Debug)]
pub(crate) struct SessionOver;

impl std::fmt::Display for SessionOver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the connection reached its ?session-secs= lifetime")
    }
}

impl std::error::Error for SessionOver {}

/// Whether `e` is [`SessionOver`].
pub(crate) fn is_session_over(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<SessionOver>())
}

/// A transport whose wait for a write can be read and changed between writes.
pub(crate) trait SetWriteTimeout {
    /// The wait of one write now, `None` for none.
    fn write_wait(&self) -> io::Result<Option<Duration>>;
    fn set_write_wait(&self, wait: Option<Duration>) -> io::Result<()>;
}

impl SetWriteTimeout for &std::net::TcpStream {
    fn write_wait(&self) -> io::Result<Option<Duration>> {
        std::net::TcpStream::write_timeout(self)
    }
    fn set_write_wait(&self, wait: Option<Duration>) -> io::Result<()> {
        std::net::TcpStream::set_write_timeout(self, wait)
    }
}

impl SetWriteTimeout for &TcpListenerStream {
    fn write_wait(&self) -> io::Result<Option<Duration>> {
        self.0.write_timeout()
    }
    fn set_write_wait(&self, wait: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(wait)
    }
}

#[cfg(unix)]
impl SetWriteTimeout for &std::os::unix::net::UnixStream {
    fn write_wait(&self) -> io::Result<Option<Duration>> {
        std::os::unix::net::UnixStream::write_timeout(self)
    }
    fn set_write_wait(&self, wait: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_write_timeout(self, wait)
    }
}

/// Memory has no socket to wait on.
#[cfg(any(test, feature = "fuzzing"))]
impl SetWriteTimeout for &mut Vec<u8> {
    fn write_wait(&self) -> io::Result<Option<Duration>> {
        Ok(None)
    }
    fn set_write_wait(&self, _wait: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

/// A reply writer that tells a write timeout from the other failures. The
/// socket reports it as `WouldBlock`, which on the read side is the quiet end
/// of an idle client.
///
/// With a `budget` (`?reply-secs=`) it also bounds the time the writes of one
/// reply spend waiting for the client: each write is given the smaller of the
/// socket's own write timeout and what is left of the budget, and the time it
/// blocked is charged to it. The server's time between two writes is not.
pub(crate) struct Replies<W> {
    inner: W,
    /// The most the writes of one reply may wait, in all. `None`: the socket's
    /// own timeout alone, which this leaves untouched.
    budget: Option<Duration>,
    /// The socket's write timeout when this was made, with a `budget` only.
    per_write: Option<Duration>,
    /// What the writes of the running reply have waited so far.
    spent: Duration,
}

impl<W: SetWriteTimeout> Replies<W> {
    pub(crate) fn new(inner: W, budget: Option<Duration>) -> io::Result<Self> {
        let per_write = match budget {
            Some(_) => inner.write_wait()?,
            None => None,
        };
        Ok(Self {
            inner,
            budget,
            per_write,
            spent: Duration::ZERO,
        })
    }
}

impl<W> Replies<W> {
    /// A reply begins: its writes have the whole budget.
    pub(crate) fn start_reply(&mut self) {
        self.spent = Duration::ZERO;
    }

    fn not_reading() -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, ClientNotReading)
    }

    fn named(e: io::Error) -> io::Error {
        if matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ) {
            Self::not_reading()
        } else {
            e
        }
    }
}

impl<W: Write + SetWriteTimeout> Write for Replies<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(budget) = self.budget else {
            return self.inner.write(buf).map_err(Self::named);
        };
        let left = budget.saturating_sub(self.spent);
        if left.is_zero() {
            return Err(Self::not_reading());
        }
        let wait = self.per_write.map_or(left, |each| each.min(left));
        self.inner.set_write_wait(Some(wait))?;
        let from = Instant::now();
        let written = self.inner.write(buf);
        self.spent = self.spent.saturating_add(from.elapsed());
        written.map_err(Self::named)
    }

    /// Not charged to the budget: the writers here are sockets, which hold
    /// nothing back for a flush to send.
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().map_err(Self::named)
    }
}

/// A transport whose wait for the next bytes can be changed between reads.
pub(crate) trait SetReadTimeout {
    fn set_read_timeout(&self, wait: Duration) -> io::Result<()>;
}

impl SetReadTimeout for std::net::TcpStream {
    fn set_read_timeout(&self, wait: Duration) -> io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, Some(wait))
    }
}

impl SetReadTimeout for &TcpListenerStream {
    fn set_read_timeout(&self, wait: Duration) -> io::Result<()> {
        self.0.set_read_timeout(Some(wait))
    }
}

/// The time one command may take to arrive, from its first byte to the end of
/// its data (`?request-secs=`). The socket's own timeout bounds each
/// read; this bounds all of them, so a client that sends a byte inside every
/// timeout cannot hold its connection.
///
/// One per connection, shared by the reads ([`Clocked`]) and whoever starts
/// each command. The idle wait for a command's first byte is not part of it.
///
/// It also holds the connection's lifetime (`?session-secs=`), which cuts only
/// the wait for a command's first byte: a command that has begun is read to its
/// end.
pub(crate) struct ReadClock {
    /// `None`: no limit.
    limit: Option<Duration>,
    /// The wait of one read when the command has time to spare.
    per_read: Duration,
    /// When the connection's lifetime is up. `None`: no lifetime.
    session_end: Option<Instant>,
    /// The running command's first byte has arrived.
    begun: Cell<bool>,
    /// When the running command's time is up. `None` before its first byte, or
    /// with no limit.
    end: Cell<Option<Instant>>,
    /// A read failed for want of time since the last [`restart`](Self::restart).
    fired: Cell<bool>,
}

impl ReadClock {
    pub(crate) fn new(limit: Option<Duration>, per_read: Duration) -> Self {
        Self {
            limit,
            per_read,
            session_end: None,
            begun: Cell::new(false),
            end: Cell::new(None),
            fired: Cell::new(false),
        }
    }

    /// The connection ends `session` from now. A lifetime past the range of a
    /// clock is no lifetime.
    pub(crate) fn lasting(mut self, session: Option<Duration>) -> Self {
        self.session_end = session.and_then(|s| Instant::now().checked_add(s));
        self
    }

    /// A new command begins. `started` says its first bytes are already in
    /// hand (buffered ahead of the last command), so its time runs from now;
    /// otherwise it runs from the first byte that arrives.
    pub(crate) fn restart(&self, started: bool) {
        self.begun.set(started);
        self.end.set(if started { self.deadline() } else { None });
        self.fired.set(false);
    }

    /// The end of a command that starts now. `None` past the range of a clock,
    /// which is a limit no command reaches.
    fn deadline(&self) -> Option<Instant> {
        Instant::now().checked_add(self.limit?)
    }

    /// Whether a read failed for want of time during this command.
    pub(crate) fn fired(&self) -> bool {
        self.fired.get()
    }

    /// Runs `work`, the server's own time between two reads of one command,
    /// without charging it to the client.
    #[cfg(any(test, feature = "icap"))]
    pub(crate) fn excluding<T>(&self, work: impl FnOnce() -> T) -> T {
        let from = Instant::now();
        let out = work();
        if let Some(end) = self.end.get() {
            self.end
                .set(Some(end.checked_add(from.elapsed()).unwrap_or(end)));
        }
        out
    }

    fn expired(&self) -> io::Error {
        self.fired.set(true);
        io::Error::new(io::ErrorKind::TimedOut, CommandTooSlow)
    }

    /// Whether the connection has reached its lifetime. Asked between
    /// commands, before reading another, whatever is already buffered.
    pub(crate) fn lifetime_over(&self) -> bool {
        self.session_end.is_some_and(|end| Instant::now() >= end)
    }

    fn lifetime_error() -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, SessionOver)
    }
}

/// A transport read under a [`ReadClock`].
pub(crate) struct Clocked<'a, R> {
    inner: R,
    clock: &'a ReadClock,
}

impl<'a, R> Clocked<'a, R> {
    pub(crate) fn new(inner: R, clock: &'a ReadClock) -> Self {
        Self { inner, clock }
    }

    #[cfg(any(test, feature = "icap"))]
    pub(crate) fn get_ref(&self) -> &R {
        &self.inner
    }
}

impl<R: Read + SetReadTimeout> Read for Clocked<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let clock = self.clock;
        if clock.limit.is_none() && clock.session_end.is_none() {
            return self.inner.read(buf);
        }
        // The wait of this read: what is left of the command's time, or before
        // its first byte what is left of the connection's lifetime, when that
        // is less than the socket's own. A timeout on the shorter wait is the
        // command's or the lifetime's, not the socket's.
        let mut wait = clock.per_read;
        let mut cut_by_clock = false;
        let mut cut_by_session = false;
        if let Some(end) = clock.end.get() {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(clock.expired());
            }
            if left <= wait {
                wait = left;
                cut_by_clock = true;
            }
        } else if !clock.begun.get()
            && let Some(end) = clock.session_end
        {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(ReadClock::lifetime_error());
            }
            if left <= wait {
                wait = left;
                cut_by_session = true;
            }
        }
        self.inner.set_read_timeout(wait)?;
        match self.inner.read(buf) {
            Ok(n) => {
                if n > 0 && !clock.begun.get() {
                    clock.begun.set(true);
                    if clock.end.get().is_none() {
                        clock.end.set(clock.deadline());
                    }
                }
                Ok(n)
            }
            Err(e)
                if (cut_by_clock || cut_by_session)
                    && matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
            {
                Err(if cut_by_clock {
                    clock.expired()
                } else {
                    ReadClock::lifetime_error()
                })
            }
            Err(e) => Err(e),
        }
    }
}

impl<R: FdSource> FdSource for Clocked<'_, R> {
    fn take_fd(&mut self) -> Option<File> {
        self.inner.take_fd()
    }
}

/// True for I/O errors that are a normal client disconnect (or the read-timeout
/// above), which should close the connection quietly rather than log as an
/// error. A command that ran out of time, or a client that stopped reading its
/// replies, is not one: it is a limit, and the operator should see it.
fn is_benign_disconnect(e: &io::Error) -> bool {
    !is_too_slow(e)
        && !is_not_reading(e)
        && matches!(
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

/// The database the thread-model listeners share, swapped whole on a reload.
/// A connection or request already in progress keeps the one it started with.
pub struct SharedDb(std::sync::RwLock<Arc<Scanner>>);

impl SharedDb {
    pub fn new(db: Arc<Scanner>) -> Self {
        Self(std::sync::RwLock::new(db))
    }

    /// The database to serve the next connection or request with.
    pub fn current(&self) -> Arc<Scanner> {
        // A poisoned lock means a panic happened while swapping, not that the
        // database is unusable.
        Arc::clone(&self.0.read().unwrap_or_else(|e| e.into_inner()))
    }

    pub(crate) fn replace(&self, db: Scanner) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(db);
    }
}

/// The thread model's supervisor: reload `db` on `RELOAD`, `SIGUSR2`, or a
/// change to the watched signature source, and reopen the `--log` file on
/// `SIGHUP`, as clamd does. A failed reload keeps the database in use. Never
/// returns.
pub fn supervise(
    db: &SharedDb,
    mut watch: Option<Watch>,
    reload_db: &dyn Fn() -> Result<Scanner, String>,
) -> ! {
    #[cfg(unix)]
    {
        if let Err(e) = arm_wakeup() {
            eprintln!(
                "exav: reload signals will wait for the next {}s poll: {e}",
                SUPERVISOR_TICK.as_secs()
            );
        }
        // Restarting: the listeners' threads must not see their reads and
        // accepts interrupted by a signal meant for this one.
        // SAFETY: both handlers are async-signal-safe, as their docs say.
        unsafe {
            install_restarting_handler(libc::SIGHUP, on_sighup);
            install_restarting_handler(libc::SIGUSR2, on_sigusr2);
        }
    }
    loop {
        #[cfg(unix)]
        nap(SUPERVISOR_TICK);
        #[cfg(not(unix))]
        std::thread::sleep(SUPERVISOR_TICK);
        let disk_changed = watch.as_mut().is_some_and(Watch::changed);
        if RELOAD_REQUESTED.swap(false, Ordering::Relaxed) || disk_changed {
            match reload_db() {
                Ok(new_db) => {
                    eprintln!(
                        "exav: reloading signatures ({} known)",
                        new_db.signature_count()
                    );
                    exav_core::warm_up(&new_db);
                    db.replace(new_db);
                }
                Err(e) => eprintln!("exav: signature reload failed, keeping current DB: {e}"),
            }
        }
    }
}

/// Run the daemon until the listener errors (e.g. the process is killed).
/// `allow_shutdown` controls whether the `SHUTDOWN` command stops the daemon
/// (here it exits the process; the thread model has no supervisor to unwind).
/// `allow_http_scan` controls whether the exav-only `SCANURL` command fetches,
/// off by default, since it lets any client that can reach the socket make the
/// daemon fetch a URL. `reads` bound how long a client takes to send and to
/// take its replies ([`Reads`]).
///
/// Each connection is served with the database current when it opened; a
/// reload ([`supervise`]) swaps it for the connections after. An accept that
/// fails for a transient reason (out of descriptors, a connection lost before
/// it was accepted) is logged and retried after a pause; any other accept error
/// ends the listener and is returned.
#[allow(clippy::too_many_arguments)]
pub fn run(
    db: Arc<SharedDb>,
    addr: ListenAddr,
    opts: Arc<ScanOptions>,
    allow_shutdown: bool,
    allow_http_scan: bool,
    max_connections: usize,
    reads: Reads,
) -> io::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    SHUTDOWN_ALLOWED.store(allow_shutdown, Ordering::Relaxed);
    let conns = Arc::new(AtomicUsize::new(0));
    // A client that disconnects right after reading a reply delivers SIGPIPE on
    // the next write. `main` set the default disposition, which kills the
    // process, so that a one-shot scan piped into `head` ends quietly; a
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
            accept_loop(
                || listener.accept().map(|(stream, _)| stream),
                |stream| {
                    let _ = stream.set_read_timeout(Some(reads.idle));
                    let _ = stream.set_write_timeout(Some(reads.idle));
                    if conns.fetch_add(1, Ordering::Relaxed) >= max_connections {
                        conns.fetch_sub(1, Ordering::Relaxed);
                        return; // at capacity: drop the connection
                    }
                    let (db, opts, c) = (db.current(), Arc::clone(&opts), Arc::clone(&conns));
                    spawn_conn(&conns, move || {
                        let _guard = ConnGuard(c);
                        // The fd-capturing reader handles FILDES; the writer is a
                        // second borrow of the same stream (full-duplex socket).
                        let reader = AncillaryReader::new(&stream);
                        // Thread model: no per-job kill, so the per-command timer is a
                        // no-op; `reads` is what bounds a stalled client.
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
                            &request_reload,
                            &shutdown,
                            allow_http_scan,
                            reads,
                        ) && !is_benign_disconnect(&e)
                        {
                            eprintln!("exav: connection error: {e}");
                        }
                    });
                },
            )
        }
        ListenAddr::Tcp(addr) => {
            let listener = TcpListener::bind(&addr)?;
            eprintln!("exav: daemon listening on tcp:{addr}");
            accept_loop(
                || listener.accept().map(|(tcp, _)| tcp),
                |tcp| {
                    let _ = tcp.set_read_timeout(Some(reads.idle));
                    let _ = tcp.set_write_timeout(Some(reads.idle));
                    let stream = TcpListenerStream(tcp);
                    if conns.fetch_add(1, Ordering::Relaxed) >= max_connections {
                        conns.fetch_sub(1, Ordering::Relaxed);
                        return; // at capacity: drop the connection
                    }
                    let (db, opts, c) = (db.current(), Arc::clone(&opts), Arc::clone(&conns));
                    spawn_conn(&conns, move || {
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
                            &request_reload,
                            &shutdown,
                            allow_http_scan,
                            reads,
                        ) && !is_benign_disconnect(&e)
                        {
                            eprintln!("exav: connection error: {e}");
                        }
                    });
                },
            )
        }
    }
}

// ───────────────────────── prefork worker pool (Unix) ─────────────────────
//
// `--workers N` switches the daemon from the in-process thread model above to a
// pool of N persistent worker *processes*. Each worker handles one scan at a
// time (sequentially), so a single job can be bounded and, if it goes rogue,
// killed without touching any other in-flight work, the one thing the thread
// model cannot do safely at all (no safe thread-kill in Rust/C).
//
// Why processes / why Unix-only here:
//   * Workers `fork()` from the parent *after* the DB is loaded and warmed, so
//     the (large, read-only) signature DB is shared via copy-on-write: no
//     re-load, low memory.
//   * They inherit the listening socket and `accept()` on it directly, so the
//     full clamd protocol (incl. `FILDES` fd-passing via `SCM_RIGHTS`) is
//     handled in the worker with zero parent relay.
//   * Limits are enforced by the kernel, the only layer that can stop a stuck
//     call inside a dependency: `RLIMIT_AS` fails the allocation past the
//     memory cap, a per-job soft `RLIMIT_CPU` raises `SIGXCPU`, and a per-job
//     `setitimer(SIGALRM)` gives a wall-clock bound even on a non-yielding CPU
//     loop. Both signal handlers answer the client and `_exit()`.
//   * Workers recycle after `max_jobs` to bound slow leaks/fragmentation; the
//     supervisor respawns them by forking from the clean parent (pristine COW).
//
// This is the deterministic-caps backstop (Layer 3): the in-core
// `max_scanned_bytes`/ratio/recursion caps still fire first and identically in
// both models; the pool only adds the hard kill for the residual tail.

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
    /// Per-job CPU-seconds cap (soft `RLIMIT_CPU`, re-armed per job; `SIGXCPU`).
    pub max_cpu_secs: u64,
    /// Recycle a worker after this many jobs (bounds slow leaks).
    pub max_jobs: u64,
    /// Whether the `SHUTDOWN` command is honoured (clamd default: yes). When
    /// false, `SHUTDOWN` replies with an error instead of stopping the daemon,
    /// useful when the socket/port is reachable by untrusted clients.
    pub allow_shutdown: bool,
    /// Whether the exav-only `SCANURL` command fetches (default: no). When
    /// false, `SCANURL` replies with an error instead of fetching, useful for
    /// the same reason: it lets any client that can reach the socket make the
    /// daemon fetch a URL.
    pub allow_http_scan: bool,
    /// How long a client may take to send and to take its replies ([`Reads`]).
    /// The job's own timer starts after the command line has been read, so
    /// these also cover the line; it also covers the writes, unless
    /// `max_scan_time` is off.
    pub reads: Reads,
}

/// A bound listening socket the workers share across `fork()`.
#[cfg(unix)]
enum BoundListener {
    Unix(std::os::unix::net::UnixListener),
    Tcp(TcpListener),
}

#[cfg(unix)]
impl BoundListener {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        match self {
            BoundListener::Unix(l) => l.as_raw_fd(),
            BoundListener::Tcp(l) => l.as_raw_fd(),
        }
    }

    fn set_nonblocking(&self) -> io::Result<()> {
        match self {
            BoundListener::Unix(l) => l.set_nonblocking(true),
            BoundListener::Tcp(l) => l.set_nonblocking(true),
        }
    }
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
/// `bind` takes the socket's mode from the process umask, so a socket bound at
/// `path` would be listening before its `chmod` runs. It is bound instead in a
/// new directory beside `path` that only this user can enter, given its mode
/// there, and renamed to `path`: the only mode a client can ever find on the
/// path is the one asked for, and the umask, which every thread of the process
/// shares, is left alone. The rename replaces a stale socket from a previous
/// run.
///
/// The path itself is still a name another process can replace if it can write
/// the directory, so a socket belongs somewhere only its owner can write
/// (`$XDG_RUNTIME_DIR` or `/var/run`), not world-writable `/tmp`, where another
/// local user can pre-create the path.
#[cfg(unix)]
pub(crate) fn bind_unix_socket(
    path: &std::path::Path,
    mode: u32,
) -> io::Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let private = private_dir_beside(path)?;
    // `.N/s`: no longer than a name of four bytes or more, so a path within
    // the length limit of a socket's is within it here too.
    let staged = private.join("s");
    let bound = std::os::unix::net::UnixListener::bind(&staged).and_then(|listener| {
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode))?;
        std::fs::rename(&staged, path)?;
        Ok(listener)
    });
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_dir(&private);
    let listener = bound?;
    if mode & 0o007 != 0 {
        eprintln!(
            "exav: socket {} is mode {mode:03o}: any local user can submit scans \
             to this daemon and read the verdicts",
            path.display()
        );
    }
    Ok(listener)
}

/// A new directory in the directory of `path`, mode 0700: `mkdir` fails on a
/// name that exists, so one made here is this process's own.
#[cfg(unix)]
fn private_dir_beside(path: &std::path::Path) -> io::Result<std::path::PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    };
    let mut builder = std::fs::DirBuilder::new();
    // The umask can only take bits away from it; the `chmod` gives back the
    // owner's, which a umask such as 0177 takes.
    builder.mode(0o700);
    for n in 0..64 {
        let dir = parent.join(format!(".{n}"));
        match builder.create(&dir) {
            Ok(()) => {
                if let Err(e) =
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                {
                    let _ = std::fs::remove_dir(&dir);
                    return Err(e);
                }
                return Ok(dir);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "no free name for a private directory in {}",
            parent.display()
        ),
    ))
}

/// Set to true by the parent's SIGTERM/SIGINT handler so the supervisor loop
/// tears the pool down instead of respawning.
#[cfg(unix)]
static SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set to true when a DB reload is requested: by SIGUSR2 (which a worker raises
/// on a `RELOAD` command, and which the CLI's background updater raises after a
/// successful download), as clamd does. The supervisor drains it each tick.
static RELOAD_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set by SIGHUP in the supervisor, for it to pass the signal on to its
/// children: each reopens its own `--log` handle.
#[cfg(unix)]
static HUP_RECEIVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// SIGTERM and SIGINT in the supervisor: stop. Async-signal-safe: an atomic
/// and [`wake`].
#[cfg(unix)]
extern "C" fn on_shutdown(_sig: libc::c_int) {
    SHUTDOWN.store(true, std::sync::atomic::Ordering::Relaxed);
    wake();
}

/// SIGUSR2: reload the signatures. Async-signal-safe: an atomic and [`wake`].
#[cfg(unix)]
extern "C" fn on_sigusr2(_sig: libc::c_int) {
    RELOAD_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
    wake();
}

/// SIGHUP: reopen the `--log` file. Async-signal-safe: atomics and [`wake`].
#[cfg(unix)]
extern "C" fn on_sighup(_sig: libc::c_int) {
    crate::LOG_REOPEN.store(true, std::sync::atomic::Ordering::Relaxed);
    HUP_RECEIVED.store(true, std::sync::atomic::Ordering::Relaxed);
    wake();
}

/// SIGHUP in a worker or the side listener's child: reopen its own handle.
/// Async-signal-safe: an atomic.
#[cfg(unix)]
extern "C" fn on_sighup_child(_sig: libc::c_int) {
    crate::LOG_REOPEN.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// The dispositions every child of the pool starts from: the supervisor's
/// flag-setting handlers must not fire in it, its SIGTERM is the default until
/// the child installs its own, and a SIGUSR2 sent to the whole process group is
/// the supervisor's to act on.
#[cfg(unix)]
fn child_signals() {
    // SAFETY: sets this process's own dispositions, right after `fork`.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        libc::signal(libc::SIGUSR2, libc::SIG_IGN);
    }
    // SAFETY: `on_sighup_child` is async-signal-safe, as its doc says.
    unsafe { install_restarting_handler(libc::SIGHUP, on_sighup_child) };
}

/// Wakes the supervisor so a worker exit is reaped at once. Async-signal-safe:
/// [`wake`].
#[cfg(unix)]
extern "C" fn on_sigchld(_sig: libc::c_int) {
    wake();
}

/// The supervisor's self-pipe: the signal handlers write to it and [`nap`]
/// polls it. Interrupting a sleep is not enough, because a signal that lands
/// while the supervisor is awake would then wait out the next full nap.
// Safety invariant (both): -1, or an end of the self-pipe, open and
// non-blocking for the rest of the process's life.
#[cfg(unix)]
static WAKE_READ: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
#[cfg(unix)]
static WAKE_WRITE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
/// A byte is in the pipe. Keeps it to one, so the handler's `write` never
/// fails and never changes `errno` under the code it interrupted.
#[cfg(unix)]
static WAKE_PENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Create the self-pipe. Idempotent; call before installing the handlers.
#[cfg(unix)]
fn arm_wakeup() -> io::Result<()> {
    use std::sync::atomic::Ordering;
    if WAKE_WRITE.load(Ordering::Relaxed) >= 0 {
        return Ok(());
    }
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe` writes two descriptors into `fds`.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for fd in fds {
        // SAFETY: sets flags on descriptors this process just created.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        }
    }
    WAKE_READ.store(fds[0], Ordering::Relaxed);
    WAKE_WRITE.store(fds[1], Ordering::Relaxed);
    Ok(())
}

/// Make the next [`nap`] return at once. Async-signal-safe: atomics and one
/// `write`.
#[cfg(unix)]
fn wake() {
    use std::sync::atomic::Ordering;
    if WAKE_PENDING.swap(true, Ordering::SeqCst) {
        return;
    }
    let fd = WAKE_WRITE.load(Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: writes one byte from a static to a descriptor this process
        // owns. The pipe is empty here, so this neither blocks nor fails.
        unsafe {
            libc::write(fd, b"!".as_ptr() as *const libc::c_void, 1);
        }
    }
}

/// Ask the supervisor for a reload: what `RELOAD` does in the thread model, and
/// what the CLI's updater thread does after writing new signatures.
pub fn request_reload() {
    RELOAD_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
    #[cfg(unix)]
    wake();
}

/// The supervisor's **idle** poll cadence: the upper bound on how long a
/// *signal-less* database change (a sidecar that writes the volume without
/// `RELOAD`) can go unnoticed. Everything urgent is signal-driven and interrupts
/// the sleep immediately, so this timer's only job is the source poll: a worker
/// exit (SIGCHLD) triggers instant reap+respawn, `RELOAD`/the updater/`SIGUSR2`
/// trigger an instant reload, and SIGTERM/SIGINT an instant shutdown. It is
/// therefore a few seconds, not sub-second: polling the filesystem twice a
/// second for a database that changes a few times a day would wake the process
/// (and, on an NFS-mounted DB directory, generate GETATTR/READDIR traffic) for
/// nothing. Still ~60× more responsive than clamd's 600 s `SelfCheck`; use
/// `RELOAD`/`NotifyClamd`/`SIGUSR2` when you want a change picked up instantly.
pub(crate) const SUPERVISOR_TICK: std::time::Duration = std::time::Duration::from_secs(10);

/// A child of a retired generation, finishing the job it had when a reload
/// replaced it.
#[cfg(unix)]
struct Retiring {
    /// The name of the side listener this child served, `None` for a worker.
    name: Option<&'static str>,
    since: std::time::Instant,
    /// Sent SIGTERM for outliving its grace.
    stopped: bool,
}

#[cfg(unix)]
impl Retiring {
    fn new(name: Option<&'static str>, since: std::time::Instant) -> Self {
        Self {
            name,
            since,
            stopped: false,
        }
    }
}

/// How long a retired child may take to finish: one job's time limit, plus a
/// margin to write its answer. With no time limit, a fixed ceiling.
#[cfg(unix)]
fn retire_grace(max_scan_time: std::time::Duration) -> std::time::Duration {
    const MARGIN: std::time::Duration = std::time::Duration::from_secs(5);
    const NO_LIMIT: std::time::Duration = std::time::Duration::from_secs(600);
    if max_scan_time.is_zero() {
        NO_LIMIT
    } else {
        max_scan_time.saturating_add(MARGIN)
    }
}

/// A signature source the supervisor polls for changes, with its
/// [`source_state`] from before the serving database was read from it.
///
/// Taken before the load rather than when the supervisor starts polling: a
/// sidecar writing the source between the two (the load can take minutes)
/// would otherwise be in the baseline, and its signatures never loaded.
pub struct Watch {
    pub path: std::path::PathBuf,
    seen: Option<u64>,
}

impl Watch {
    /// Call before loading the database from `path`.
    pub fn new(path: std::path::PathBuf) -> Self {
        let seen = source_state(&path);
        Watch { path, seen }
    }

    /// Whether the source changed since it was last seen, noting it as seen.
    /// Any difference counts: a database swapped for one with an older mtime
    /// (copied with `cp -p`, unpacked from an archive) is still a new one.
    fn changed(&mut self) -> bool {
        match source_state(&self.path) {
            Some(s) if self.seen != Some(s) => {
                self.seen = Some(s);
                true
            }
            _ => false,
        }
    }
}

/// A digest of the watched source, the reload trigger for a sidecar that writes
/// the volume without sending `RELOAD` (clamd's `SelfCheck`): the path, size,
/// mtime and inode of every entry. For a **directory** that is the whole tree,
/// since the loader reads it recursively (including the updater's
/// `env/<host>/…` subtree). For a single **file** (a prebuilt database) it is
/// that file; an atomic swap replaces its inode. `None` if the path can't be
/// stat'd. Symlinks are not followed (no cycles).
///
/// Not the newest mtime alone: some filesystems stamp from a coarse clock, and
/// a file written within one tick of the baseline (a sidecar finishing just
/// after a load started) carries the same mtime as everything before it.
pub(crate) fn source_state(dir: &std::path::Path) -> Option<u64> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::fs::metadata(dir).ok()?.modified().ok().hash(&mut h);
    let entries = WalkDir::new(dir).follow_links(false).sort_by_file_name();
    for entry in entries.into_iter().flatten() {
        entry.path().hash(&mut h);
        if let Ok(m) = entry.metadata() {
            m.len().hash(&mut h);
            m.modified().ok().hash(&mut h);
            #[cfg(unix)]
            std::os::unix::fs::MetadataExt::ino(&m).hash(&mut h);
        }
    }
    Some(h.finish())
}

/// Sleep for `d`, or less if a supervisor signal arrived since the last nap.
#[cfg(unix)]
fn nap(d: std::time::Duration) {
    use std::sync::atomic::Ordering;
    let mut fds = [libc::pollfd {
        // A negative fd (not armed) is ignored by `poll`: a plain sleep.
        fd: WAKE_READ.load(Ordering::Relaxed),
        events: libc::POLLIN,
        revents: 0,
    }];
    let ms = d.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
    // SAFETY: `fds` is one valid `pollfd` for the duration of the call.
    unsafe {
        libc::poll(fds.as_mut_ptr(), 1, ms);
    }
    if fds[0].fd < 0 {
        return;
    }
    let mut buf = [0u8; 16];
    // SAFETY: `read` writes at most `buf.len()` bytes into the local `buf`.
    // The descriptor is `WAKE_READ`'s, open and non-blocking by its
    // invariant, so the loop ends at EAGAIN.
    while unsafe { libc::read(fds[0].fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) } > 0 {}
    // Cleared after draining: a signal before this point is handled by the
    // loop the caller is about to run, one after it writes a fresh byte.
    WAKE_PENDING.store(false, Ordering::SeqCst);
}

/// The worker's per-job wall-clock alarm. Terminating immediately is the whole
/// point: the scan blew its time budget (possibly stuck inside a dependency
/// that never returns to a cooperative checkpoint), and there is no safe way to
/// unwind in-process, so we `_exit` (async-signal-safe) and let the supervisor
/// respawn a replacement. The client gets a verdict first, as in
/// [`on_sigabrt`]: a connection closed with no reply reads as clean to some
/// clients. Async-signal-safe: an atomic, `write` and `_exit`.
#[cfg(unix)]
extern "C" fn on_sigalrm(_sig: libc::c_int) {
    let fd = CURRENT_CONN_FD.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: `write` (async-signal-safe) reads `TIMEOUT_REPLY.len()`
        // bytes of a static. By the invariant of `CURRENT_CONN_FD`, `fd` is
        // the open connection.
        unsafe {
            libc::write(
                fd,
                TIMEOUT_REPLY.as_ptr() as *const libc::c_void,
                TIMEOUT_REPLY.len(),
            );
        }
    }
    // SAFETY: `_exit` (async-signal-safe) has no memory precondition; it ends
    // the process without running destructors, which a handler may not run.
    unsafe { libc::_exit(EXIT_TIMEOUT) }
}

/// The job used its CPU budget (see [`arm_cpu_limit`]): answered as
/// [`on_sigalrm`] answers, since the budget is `--max-scan-secs` too.
/// Async-signal-safe: an atomic, `write` and `_exit`.
#[cfg(unix)]
extern "C" fn on_sigxcpu(_sig: libc::c_int) {
    let fd = CURRENT_CONN_FD.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: as in `on_sigalrm`.
        unsafe {
            libc::write(
                fd,
                TIMEOUT_REPLY.as_ptr() as *const libc::c_void,
                TIMEOUT_REPLY.len(),
            );
        }
    }
    // SAFETY: as in `on_sigalrm`.
    unsafe { libc::_exit(EXIT_CPU) }
}

/// Exit code a worker uses when a job runs out of CPU time.
#[cfg(unix)]
const EXIT_CPU: i32 = 18;

/// Reply [`on_sigalrm`] emits, framed like [`ABORT_REPLY`].
#[cfg(unix)]
const TIMEOUT_REPLY: &[u8] = b": scan exceeded --max-scan-secs LIMITS-EXCEEDED ERROR\n\0";

/// The fd of the connection this worker is currently serving, for the abort
/// handler below. `-1` when idle. A raw atomic because a signal handler may read
/// nothing that could lock.
// Safety invariant: -1, or the descriptor of the connection being served,
// which stays open until this is set back to -1.
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
/// clean close is indistinguishable from "scanned, found nothing", so a crash
/// reads as a clean verdict, which is the one answer a scanner must never give
/// by accident. Measured: 55 worker deaths in an 8,978-file run, every one
/// recorded as clean by the client.
///
/// `SIGABRT` (Rust's allocation-failure path) is catchable, so those can be
/// reported. A `SIGKILL` from the OOM killer cannot be, which is why the client
/// must ALSO treat a silent close as an error. The two fixes are complementary,
/// not alternatives.
///
/// Async-signal-safe: only `write` and `_exit`, no allocation, no locks.
#[cfg(unix)]
extern "C" fn on_sigabrt(_sig: libc::c_int) {
    let fd = CURRENT_CONN_FD.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: as in `on_sigalrm`, for `ABORT_REPLY`.
        unsafe {
            libc::write(
                fd,
                ABORT_REPLY.as_ptr() as *const libc::c_void,
                ABORT_REPLY.len(),
            );
        }
    }
    // SAFETY: as in `on_sigalrm`.
    unsafe { libc::_exit(EXIT_ABORTED) }
}

/// Whether the worker is inside a job: between `arm` and `disarm`.
#[cfg(unix)]
static IN_JOB: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Reply [`on_sigterm`] emits, framed like [`ABORT_REPLY`].
#[cfg(unix)]
const STOPPED_REPLY: &[u8] = b": scan stopped before it finished ERROR\n\0";

/// A worker told to stop (a shutdown, its supervisor gone, or a retired
/// generation past its grace) answers the job it is in, as [`on_sigalrm`]
/// does. Between jobs it just exits: a line written then would be read as the
/// answer to the client's next command. Async-signal-safe: atomics, `write`
/// and `_exit`.
#[cfg(unix)]
extern "C" fn on_sigterm(_sig: libc::c_int) {
    let fd = CURRENT_CONN_FD.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 && IN_JOB.load(std::sync::atomic::Ordering::Relaxed) {
        // SAFETY: as in `on_sigalrm`, for `STOPPED_REPLY`.
        unsafe {
            libc::write(
                fd,
                STOPPED_REPLY.as_ptr() as *const libc::c_void,
                STOPPED_REPLY.len(),
            );
        }
    }
    // SAFETY: as in `on_sigalrm`.
    unsafe { libc::_exit(EXIT_STOPPED) }
}

/// Exit code for a worker stopped by [`on_sigterm`].
#[cfg(unix)]
const EXIT_STOPPED: libc::c_int = 92;

/// Exit code for a worker that aborted mid-scan and managed to say so.
#[cfg(unix)]
const EXIT_ABORTED: libc::c_int = 91;

/// Install `handler` for `sig`.
///
/// # Safety
///
/// The caller must ensure that `handler`, which may run on any thread and at
/// any point of it, makes only async-signal-safe calls (POSIX) and touches no
/// state but lock-free atomics.
#[cfg(unix)]
unsafe fn install_handler(sig: libc::c_int, handler: extern "C" fn(libc::c_int)) {
    // SAFETY:
    // - `mem::zeroed::<sigaction>`: integers, the handler's address as an
    //   integer and a `sigset_t`, for which all-zero bytes are valid values.
    // - `sigemptyset` writes the `sigset_t` of this local.
    // - `sigaction` reads the local and takes a null old action (POSIX).
    //   Without `SA_SIGINFO` the kernel calls the handler with one `c_int`,
    //   as its type says; what it may do then is this function's
    //   precondition.
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

/// [`install_handler`] with `SA_RESTART`, for a signal that only sets a flag in
/// a process whose blocking calls (a client read, `accept`) must carry on.
///
/// # Safety
///
/// The caller must ensure what [`install_handler`] requires of `handler`.
#[cfg(unix)]
unsafe fn install_restarting_handler(sig: libc::c_int, handler: extern "C" fn(libc::c_int)) {
    // SAFETY: as in `install_handler`.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = libc::SA_RESTART;
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
    // SAFETY: `setrlimit` reads the local `rl`; a bad resource fails.
    unsafe {
        libc::setrlimit(resource as _, &rl);
    }
}

/// Give the next job `secs` of CPU on top of what this worker has already used.
///
/// `RLIMIT_CPU` counts the whole life of the process, so it is re-armed per job.
/// Only the soft limit moves: an unprivileged process cannot raise a hard limit
/// it has lowered. Its `SIGXCPU` is caught by [`on_sigxcpu`].
#[cfg(unix)]
fn arm_cpu_limit(secs: u64) {
    if secs == 0 {
        return;
    }
    // SAFETY: `mem::zeroed` of `rusage` and `rlimit`, whose fields are
    // integers and `timeval`s of integers, for which all-zero bytes are
    // valid; `getrusage` and `getrlimit` write those locals, `setrlimit`
    // reads one.
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        let mut rl: libc::rlimit = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut ru) != 0
            || libc::getrlimit(libc::RLIMIT_CPU, &mut rl) != 0
        {
            return;
        }
        let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
        let used = (us(ru.ru_utime) + us(ru.ru_stime)).div_ceil(1_000_000);
        rl.rlim_cur = (used.saturating_add(secs) as libc::rlim_t).min(rl.rlim_max);
        libc::setrlimit(libc::RLIMIT_CPU, &rl);
    }
}

/// Bytes of address space this process already occupies, from `/proc/self/statm`
/// (page count in field 0). `None` when it cannot be read; the caller then
/// applies the configured cap alone.
///
/// Needed because `RLIMIT_AS` is a whole-process ceiling while the per-job
/// setting is meant to bound a SCAN. The resident signature database sits inside
/// that ceiling and is not part of any job.
#[cfg(unix)]
fn current_address_space() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().next()?.parse().ok()?;
    // SAFETY: `sysconf` has no memory precondition.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    (page > 0).then(|| pages.saturating_mul(page as u64))
}

/// Bring the in-core extraction budget inside the memory a job is actually
/// granted, so the deterministic cap fires before the kernel one.
///
/// The pool's design puts three layers in a fixed order: the in-core
/// size/ratio/recursion caps decide first and produce a *verdict*
/// (`LIMITS-EXCEEDED`), and `RLIMIT_AS` is only a backstop for the residual
/// tail. That order is not automatic: it holds only while the in-core budget
/// is smaller than the address space the worker gets, and nothing enforced it.
///
/// It did not hold, and the inversion is easy to reach: on a modest host the
/// per-job grant lands below `max_extracted_bytes`, which defaults to 1 GiB.
/// Extraction buffers are charged cumulatively and never released, so a scan
/// can hold most of that budget live at once and meet the kernel limit first.
/// A campaign run turned up dozens of aborts from exactly that. Every one was
/// reported as an error rather than a clean, so nothing was missed, but a scan
/// that should have said "I hit a limit" instead said "I died", which is a
/// worse answer and a noisier one.
///
/// Clamping here restores the intended order. It only ever *lowers* a budget,
/// so it cannot make a scan look at more than the operator asked for.
#[cfg(unix)]
pub(crate) fn fit_limits_to_job_memory(opts: &mut ScanOptions, job_memory: u64) {
    // Beside an object held whole, matching it may take an image decoded from
    // it and that image's grey copy, each up to an object's size, and a
    // lowercase copy of at most `LOWERCASE_COPY_MAX`. So one object may take a
    // quarter of the job's memory, and the total held, which includes that
    // object, leaves room for those plus a tenth for everything else.
    let mut lowered = false;
    let mut cap = |v: &mut u64, max: u64| {
        lowered |= *v > max;
        *v = (*v).min(max);
    };
    cap(&mut opts.limits.max_buffer_bytes, job_memory / 4);
    cap(&mut opts.limits.max_bytecode_memory_bytes, job_memory / 4);
    // The cache of an object read in place, and one HTTP request held while it
    // is read, each an eighth of the job's memory at most.
    cap(&mut opts.object_cache_bytes, job_memory / 8);
    cap(&mut opts.http_request_bytes, job_memory / 8);
    let object = opts.limits.max_buffer_bytes;
    cap(
        &mut opts.limits.max_extracted_bytes,
        job_memory.saturating_sub(2 * object + exav_core::LOWERCASE_COPY_MAX + job_memory / 10),
    );
    let total = opts.limits.max_extracted_bytes;
    if lowered {
        eprintln!(
            "exav: of the {} MiB of memory a scan gets, it may hold {} MiB at once and \
             {} MiB in one object, so a size limit is reported rather than the scan being \
             killed for hitting one",
            job_memory >> 20,
            total >> 20,
            object >> 20,
        );
    }
}

/// This process's cgroup memory ceiling, if it has one.
#[cfg(unix)]
fn cgroup_memory_limit() -> Option<u64> {
    let own = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    cgroup_limit_from(&own, |p| std::fs::read_to_string(p).ok())
}

/// The smallest memory limit on the cgroup `proc_self_cgroup` names and its
/// ancestors, reading files through `read`.
///
/// v2 first (`memory.max`, the unified hierarchy every current runtime uses),
/// then v1 (`memory.limit_in_bytes`). Both spell "no limit" as a sentinel
/// (literal `max` on v2, a number near `u64::MAX` on v1), which reads as
/// *unlimited*, not as a cap of that size. A path the mount does not show (a
/// v1 container sees its own cgroup at the mount root) ends up at the root,
/// which is then the process's own.
#[cfg(unix)]
fn cgroup_limit_from(proc_self_cgroup: &str, read: impl Fn(&str) -> Option<String>) -> Option<u64> {
    let mut v2 = None;
    let mut v1 = None;
    for line in proc_self_cgroup.lines() {
        let mut f = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if controllers.is_empty() {
            v2 = Some(path);
        } else if controllers.split(',').any(|c| c == "memory") {
            v1 = Some(path);
        }
    }
    let lowest = |mount: &str, file: &str, own: &str| -> Option<Option<u64>> {
        let mut dir = own.trim_end_matches('/').to_string();
        let mut found = None;
        let mut limit: Option<u64> = None;
        loop {
            if let Some(raw) = read(&format!("{mount}{dir}/{file}")) {
                found = Some(());
                let raw = raw.trim();
                // v1 reports "unlimited" as a huge page-aligned number rather
                // than a word; anything past the host's own RAM is no ceiling.
                if let Ok(v) = raw.parse::<u64>()
                    && v > 0
                    && v < (u64::MAX >> 10)
                {
                    limit = Some(limit.map_or(v, |l| l.min(v)));
                }
            }
            match dir.rfind('/') {
                Some(i) => dir.truncate(i),
                None => break,
            }
        }
        found.map(|()| limit)
    };
    [
        v2.and_then(|p| lowest("/sys/fs/cgroup", "memory.max", p)),
        v1.and_then(|p| lowest("/sys/fs/cgroup/memory", "memory.limit_in_bytes", p)),
        // No `/proc/self/cgroup` to go by: the mount roots, as seen from here.
        lowest("/sys/fs/cgroup", "memory.max", "/"),
        lowest("/sys/fs/cgroup/memory", "memory.limit_in_bytes", "/"),
    ]
    .into_iter()
    .flatten()
    .next()
    .flatten()
}

/// How much address space one job may use so the whole pool fits in RAM.
///
/// `None` when the host's memory cannot be read, in which case the configured
/// value stands unmodified.
///
/// The signature database is shared copy-on-write by every worker, so it is
/// subtracted ONCE rather than per worker. A slice of RAM is held back for the
/// kernel and everything else on the box: running the machine to exactly zero
/// free just moves the kill from one process to another.
#[cfg(unix)]
fn affordable_job_memory(workers: usize, shared_db_bytes: u64) -> Option<u64> {
    /// Leave this fraction of total RAM to the rest of the system.
    ///
    /// A third, not a token slice. A single scan's peak is NOT one buffer: the
    /// matcher allocates a full-size lowercase copy of every buffer it scans for
    /// case-insensitive partitions, and nesting stacks those: a container, its
    /// member and that member's own member each hold a buffer AND a copy while
    /// the walk is inside them. So the per-job figure below is a floor on what a
    /// scan can want, not a ceiling, and the pool has to be sized with room for
    /// several workers to be deep at once.
    ///
    /// A campaign at one eighth was still losing workers to the OOM killer:
    /// the per-worker grants plus the shared database left too little for the
    /// kernel and page cache, and dozens of workers were killed over a single
    /// run. An OOM kill cannot be caught, so it costs a scan its answer
    /// entirely, strictly worse than the scan reporting that it hit a limit,
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
    // `/proc/meminfo` is the HOST's memory even inside a container, so on its
    // own it hands a memory-capped container per-job grants its cgroup will
    // never honour, and the cgroup's OOM killer then arrives before this
    // process's own `RLIMIT_AS` ever would, costing the scan its answer for
    // exactly the reason the headroom above exists to avoid. Containers are how
    // this daemon is mostly run, and every Kubernetes pod carries a limit.
    let total = cgroup_memory_limit()
        .unwrap_or(u64::MAX)
        .min(total_kb.saturating_mul(1024));
    let usable = total
        .saturating_sub(total / HEADROOM_DEN * HEADROOM_NUM)
        .saturating_sub(shared_db_bytes);
    Some((usable / workers.max(1) as u64).max(FLOOR))
}

/// What the one-shot run has found so far, kept where the alarm's handler can
/// read it: an atomic is the only state an async-signal-safe handler may read.
#[cfg(unix)]
static ONESHOT_INFECTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(unix)]
static ONESHOT_ERRORS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// The exit code of a run that ran out of time and had found nothing else:
/// what `--partial-as` gives a `LIMITS-EXCEEDED`.
#[cfg(unix)]
static ONESHOT_TIMEOUT_EXIT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(3);

/// The run's detections and errors so far, for the exit code of a run the alarm
/// ends. Cheap enough to call after every file.
pub(crate) fn note_run(infected: u64, errors: u64) {
    #[cfg(unix)]
    {
        use std::sync::atomic::Ordering::Relaxed;
        ONESHOT_INFECTED.store(infected > 0, Relaxed);
        ONESHOT_ERRORS.store(errors > 0, Relaxed);
    }
    #[cfg(not(unix))]
    let _ = (infected, errors);
}

/// The exit code a one-shot run ends with when the alarm cuts it short, by the
/// same precedence as a run that finished: a detection, then an error, then the
/// file that ran out of time as `--partial-as` says.
#[cfg(unix)]
fn oneshot_exit_code() -> i32 {
    use std::sync::atomic::Ordering::Relaxed;
    if ONESHOT_INFECTED.load(Relaxed) {
        1
    } else if ONESHOT_ERRORS.load(Relaxed) {
        2
    } else {
        ONESHOT_TIMEOUT_EXIT.load(Relaxed)
    }
}

/// Handler for the one-shot CLI's wall-clock alarm.
///
/// Separate from [`on_sigalrm`], which serves a pool worker that a parent will
/// reap and report on. Here nobody is watching, so the handler has to say what
/// happened itself, through `write(2)`, the only output an async-signal-safe
/// handler may use. Async-signal-safe: atomics, `write` and `_exit`.
#[cfg(unix)]
extern "C" fn on_oneshot_alarm(_sig: libc::c_int) {
    const MSG: &[u8] =
        b"exav: scan exceeded --max-scan-secs; the files after it were not scanned\n";
    // SAFETY: `write` (async-signal-safe) reads `MSG.len()` bytes of a static
    // into descriptor 2, which needs no precondition: a closed one fails.
    // `_exit` (async-signal-safe) ends the process without running
    // destructors; `oneshot_exit_code` reads atomics.
    unsafe {
        libc::write(2, MSG.as_ptr().cast(), MSG.len());
        // The code the run would have had: a detection already reported stays
        // a 1, however the run ended. The file that ran out of time counts as a
        // `LIMITS-EXCEEDED` under `--partial-as`, read at startup because the
        // policy cannot be consulted here.
        libc::_exit(oneshot_exit_code())
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
/// budgets decide first and produce a verdict; these catch what escapes them:
/// an allocation the budget cannot see, or a decoder that loops without
/// producing output.
#[cfg(unix)]
pub(crate) fn apply_oneshot_limits(max_scan_time: Option<u64>, max_scan_memory: Option<u64>) {
    if let Some(bytes) = max_scan_memory {
        set_rlimit(libc::RLIMIT_AS as libc::c_int, bytes);
    }
    if let Some(secs) = max_scan_time {
        use crate::policy::PartialStatus;
        let code = match crate::policy::current().for_tag("LIMITS-EXCEEDED") {
            PartialStatus::Partial => 3,
            PartialStatus::Ok => 0,
            PartialStatus::Found => 1,
            PartialStatus::Error => 2,
        };
        ONESHOT_TIMEOUT_EXIT.store(code, std::sync::atomic::Ordering::Relaxed);
        // SAFETY: `on_oneshot_alarm` is async-signal-safe, as its doc says.
        unsafe { install_handler(libc::SIGALRM, on_oneshot_alarm) };
        set_timer(std::time::Duration::from_secs(secs));
    }
}

/// The longest the one-shot timer is armed for: what `setitimer` accepts on
/// macOS, where a larger value is `EINVAL` and would leave no limit at all.
#[cfg(unix)]
const MAX_TIMER_SECS: u64 = 100_000_000;

/// Arm (or, with a zero duration, disarm) the one-shot wall-clock timer.
#[cfg(unix)]
fn set_timer(d: std::time::Duration) {
    let it = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            // A limit past what the clock holds is the longest one: cast, it
            // would wrap negative, and the kernel refuses a negative time.
            // macOS refuses more than 100,000,000 seconds (EINVAL, three
            // years), so that is the longest, on every platform.
            tv_sec: libc::time_t::try_from(d.as_secs().min(MAX_TIMER_SECS))
                .unwrap_or(libc::time_t::MAX),
            tv_usec: d.subsec_micros() as _,
        },
    };
    // SAFETY: `setitimer` reads the local `it` and takes a null old value
    // (POSIX).
    let armed = unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) };
    if armed != 0 {
        eprintln!(
            "exav: the scan time limit could not be set: {}",
            std::io::Error::last_os_error()
        );
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
    /// Serves the listener it captured, in the forked child. The descriptor is
    /// the child's generation (see [`await_connection`]): once it is retired,
    /// the child finishes what it is serving and exits 0.
    #[allow(clippy::type_complexity)]
    pub serve: Box<dyn Fn(Arc<Scanner>, Arc<ScanOptions>, std::os::fd::RawFd) + Send + Sync>,
}

/// One generation of the pool: a pipe whose write end only the supervisor
/// holds. Its children wait on the read end alongside the listener, and
/// dropping the generation closes the write end, which they see as end of
/// file: an idle child leaves at once, a busy one after its current job. A
/// reload retires the old children this way rather than by signal, so no scan
/// in progress is cut short.
#[cfg(unix)]
struct Generation {
    retire: std::os::fd::OwnedFd,
    /// The write end; none in a child once it has entered the generation.
    notice: std::cell::RefCell<Option<std::os::fd::OwnedFd>>,
}

#[cfg(unix)]
impl Generation {
    fn new() -> io::Result<Self> {
        use std::os::fd::FromRawFd;
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe` writes two descriptors into `fds`.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors were just created and nothing else owns them.
        let (retire, notice) = unsafe {
            (
                std::os::fd::OwnedFd::from_raw_fd(fds[0]),
                std::os::fd::OwnedFd::from_raw_fd(fds[1]),
            )
        };
        for fd in fds {
            // SAFETY: sets a flag on a descriptor this process owns.
            unsafe {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
        Ok(Self {
            retire,
            notice: std::cell::RefCell::new(Some(notice)),
        })
    }

    /// In a child just forked: close its copy of the write end, so only the
    /// supervisor's keeps the generation alive. Returns the end to wait on.
    fn enter(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        drop(self.notice.borrow_mut().take());
        self.retire.as_raw_fd()
    }
}

/// An accept error that only means there is nothing to accept right now.
#[cfg(unix)]
pub(crate) fn lost_accept_race(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// Block until `listener` has a connection to accept (`true`) or the
/// generation `retire` belongs to has been retired (`false`).
#[cfg(unix)]
pub(crate) fn await_connection(listener: std::os::fd::RawFd, retire: std::os::fd::RawFd) -> bool {
    let mut fds = [
        libc::pollfd {
            fd: retire,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `fds` is two valid `pollfd` for the duration of the call.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // Let the accept that follows report the failure.
            return true;
        }
        if fds[0].revents != 0 {
            return false;
        }
        if fds[1].revents != 0 {
            return true;
        }
    }
}

/// Run the daemon as a prefork pool of `cfg.workers` worker processes.
///
/// `datadir` (when `Some`) is polled for on-disk changes so a sidecar that writes
/// the volume triggers a reload without sending `RELOAD`. `reload_db` re-reads the
/// signatures; on a `RELOAD`/SIGUSR2/data-dir change the supervisor calls it,
/// warms the result, and re-forks the pool with the new DB. A failed reload is
/// logged and the running DB is kept. Each of `side` is an additional listener
/// served by a child of its own, forked, reaped and reloaded exactly as the
/// workers are. `updater`, the `--auto-update` child, is reaped and forked
/// again when it dies, and kept through the reloads.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub fn run_prefork(
    db: Arc<Scanner>,
    addr: ListenAddr,
    opts: Arc<ScanOptions>,
    mut cfg: PoolConfig,
    mut datadir: Option<Watch>,
    reload_db: &dyn Fn() -> Result<Scanner, String>,
    side: &[SideListener],
    mut updater: Option<Updater>,
) -> io::Result<()> {
    use std::sync::atomic::Ordering;
    // Same SIGPIPE rationale as `run`.
    // SAFETY: `signal` with `SIG_IGN` installs no handler and has no memory
    // precondition.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let listener = bind_listener(&addr)?;
    // Workers wait in `await_connection`, not in `accept`: several may wake for
    // one connection, and the ones that lose the race must not block in accept.
    listener.set_nonblocking()?;

    // Warm every lazily-initialised structure BEFORE forking, so all workers
    // share them read-only via COW rather than each building its own copy on
    // first scan.
    exav_core::warm_up(&db);

    // Sized here, before the options are shared: the address space is measured
    // once the database is loaded and warmed, and both the per-job ceiling and
    // the in-core budget that must sit under it are decided from that figure.
    let db_bytes = current_address_space().unwrap_or(0);
    if let Some(afford) = affordable_job_memory(cfg.workers, db_bytes)
        && cfg.max_memory_bytes > afford
    {
        eprintln!(
            "exav: per-job memory {} MiB x {} workers exceeds what this host can back; \
                 using {} MiB per job (two thirds of RAM, less the {} MiB shared database, \
                 over the workers). Raise RAM, lower --workers, or set a smaller \
                 --max-process-bytes to silence this.",
            cfg.max_memory_bytes >> 20,
            cfg.workers,
            afford >> 20,
            db_bytes >> 20,
        );
        cfg.max_memory_bytes = afford;
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
    // total, and nothing checked that against the machine. On a 5.9 GB host, 4
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

    arm_wakeup()?;
    // SAFETY: these handlers are async-signal-safe, as their docs say.
    unsafe {
        install_handler(libc::SIGTERM, on_shutdown);
        install_handler(libc::SIGINT, on_shutdown);
        install_handler(libc::SIGHUP, on_sighup);
        install_handler(libc::SIGUSR2, on_sigusr2);
        install_handler(libc::SIGCHLD, on_sigchld);
    }

    // Before the first fork, so every child counts into the same block and a
    // `STATS` answered by any of them is the pool's. Without it each process
    // counts its own jobs, which `STATS` then reports as the pool's.
    if let Err(e) = crate::metrics::share_across_fork() {
        eprintln!("exav: the counters stay per process, so STATS shows one process's: {e}");
    }
    let mut r#gen = Generation::new()?;
    let mut children = std::collections::HashSet::new();
    for _ in 0..cfg.workers {
        children.insert(spawn_worker(&listener, &db, &opts, &cfg, &r#gen)?);
    }
    let mut side_pids: Vec<Option<libc::pid_t>> = Vec::with_capacity(side.len());
    for s in side {
        side_pids.push(Some(spawn_side(s, &db, &opts, &r#gen)?));
    }
    // Children of retired generations, still finishing their last job. They
    // are reaped but not replaced, and stopped once their grace has passed.
    let mut retiring: std::collections::HashMap<libc::pid_t, Retiring> =
        std::collections::HashMap::new();
    let grace = retire_grace(cfg.max_scan_time);

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
            // SAFETY: `waitpid` writes the local `status`.
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                break; // 0 = none exited yet; <0 = no children / error
            }
            if updater.as_mut().is_some_and(|u| u.reaped(pid)) {
                log_child_exit(pid, status, "signature updater", false);
                continue;
            }
            // A child that died mid-scan (its time ran out) takes its scans in
            // flight with it.
            crate::metrics::release(pid);
            if let Some(r) = retiring.remove(&pid) {
                log_child_exit(pid, status, r.name.unwrap_or("worker"), true);
                continue;
            }
            let which = side_pids.iter().position(|p| *p == Some(pid));
            match which {
                Some(i) => side_pids[i] = None,
                None => {
                    children.remove(&pid);
                }
            }
            log_child_exit(pid, status, which.map_or("worker", |i| side[i].name), false);
            if !SHUTDOWN.load(Ordering::Relaxed) {
                match which {
                    Some(i) => side_pids[i] = Some(spawn_side(&side[i], &db, &opts, &r#gen)?),
                    None => {
                        children.insert(spawn_worker(&listener, &db, &opts, &cfg, &r#gen)?);
                    }
                }
            }
        }

        // Log rotation: every child holds its own handle.
        if HUP_RECEIVED.swap(false, Ordering::Relaxed) {
            for &pid in children
                .iter()
                .chain(side_pids.iter().flatten())
                .chain(retiring.keys())
            {
                // SAFETY: signals a child of this process that has not been
                // reaped, so the pid cannot have been reused.
                unsafe {
                    libc::kill(pid, libc::SIGHUP);
                }
            }
        }

        // Reload trigger: an explicit RELOAD/SIGUSR2, or the data dir changed on
        // disk (a sidecar wrote it). Coalesce both into one reload per tick.
        let disk_changed = datadir.as_mut().is_some_and(Watch::changed);
        if RELOAD_REQUESTED.swap(false, Ordering::Relaxed) || disk_changed {
            match reload_db() {
                Ok(new_db) => {
                    eprintln!(
                        "exav: reloading signatures ({} known)",
                        new_db.signature_count()
                    );
                    // Warm before forking so new workers share it COW.
                    exav_core::warm_up(&new_db);
                    db = Arc::new(new_db);
                    // Replacing the generation drops the old one, which is the
                    // old children's notice to leave once idle. It happens
                    // before the fork so the new children never hold the old
                    // write end. The side listener goes with them, which is the
                    // whole of its signature swap: it comes back forked from
                    // the new database.
                    r#gen = Generation::new()?;
                    let since = std::time::Instant::now();
                    retiring.extend(
                        children
                            .drain()
                            .map(|pid| (pid, Retiring::new(None, since))),
                    );
                    for (slot, s) in side_pids.iter_mut().zip(side) {
                        retiring.extend(
                            slot.take()
                                .map(|pid| (pid, Retiring::new(Some(s.name), since))),
                        );
                    }
                    for _ in 0..cfg.workers {
                        children.insert(spawn_worker(&listener, &db, &opts, &cfg, &r#gen)?);
                    }
                    for (slot, s) in side_pids.iter_mut().zip(side) {
                        *slot = Some(spawn_side(s, &db, &opts, &r#gen)?);
                    }
                }
                Err(e) => {
                    eprintln!("exav: signature reload failed, keeping current DB: {e}");
                }
            }
        }

        // A retired child past its grace is stopped: an idle session or a
        // client that never finishes its request would otherwise keep it, and
        // the old signatures it serves, alive indefinitely.
        let now = std::time::Instant::now();
        let mut tick = SUPERVISOR_TICK;
        if let Some(wait) = updater.as_mut().and_then(|u| u.due(&r#gen)) {
            tick = tick.min(wait);
        }
        for (&pid, r) in retiring.iter_mut().filter(|(_, r)| !r.stopped) {
            // A grace too long to add to the clock is one that never ends.
            let Some(due) = r.since.checked_add(grace) else {
                continue;
            };
            if now >= due {
                let what = r.name.unwrap_or("worker");
                eprintln!(
                    "exav: {what} {pid} of a retired generation is still busy after {}s; stopping it",
                    grace.as_secs()
                );
                // SAFETY: signals a child of this process that has not been
                // reaped, so the pid cannot have been reused.
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
                r.stopped = true;
            } else {
                tick = tick.min(due - now);
            }
        }
        nap(tick);
    }

    // Graceful teardown: signal every child, then reap them.
    let all: Vec<libc::pid_t> = children
        .iter()
        .copied()
        .chain(side_pids.iter().flatten().copied())
        .chain(retiring.keys().copied())
        .chain(updater.as_mut().and_then(Updater::take))
        .collect();
    for &pid in &all {
        // SAFETY: `kill` has no memory precondition. `pid` is a child of this
        // process that has not been reaped, so the number cannot have been
        // reused.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    for &pid in &all {
        let mut status: libc::c_int = 0;
        // SAFETY: `waitpid` writes the local `status`.
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
    }
    Ok(())
}

/// Ask the kernel to kill this process when its parent goes.
///
/// A worker spends its life blocked in `accept()`, so it cannot notice that the
/// supervisor has died, and when the supervisor is killed outright rather than
/// asked to stop (the OOM killer, `kill -9`, a container stop, a test harness
/// dropping the child) it never gets to take its pool down with it. The workers
/// are reparented to init and block forever on a socket nobody will connect to
/// again, holding their descriptors and process slots. Measured at 64 orphans
/// per run of this crate's daemon tests, accumulating across runs until the
/// process table or the descriptor ceiling gives out.
///
/// `PR_SET_PDEATHSIG` is Linux-only and there is no portable equivalent: the
/// alternatives all need the worker to be watching a descriptor it is not
/// watching. On other Unixes a supervisor killed outright still leaves its
/// workers behind; one asked to stop takes them with it as it always did.
///
/// `supervisor` is the pid the parent read of *itself* before forking. Nothing
/// else identifies it: in a container the daemon is pid 1, so every worker is
/// legitimately a child of pid 1 and "my parent is init" says nothing at all.
/// Reading that as orphanhood exits every worker the moment it starts, and the
/// supervisor refills the pool forever.
#[cfg(unix)]
fn die_with_parent(supervisor: libc::pid_t) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `prctl(PR_SET_PDEATHSIG)` takes a signal number, no pointer,
        // and sets this process's own parent-death signal.
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
        }
        // The parent can die between `fork` and the `prctl`, in which case the
        // signal it would have raised was already missed and this worker would
        // block forever: the same leak through a narrower window. Comparing
        // against the pid the supervisor recorded of itself is what makes that
        // check sound: a parent that is no longer *that* process is gone,
        // whatever pid took its place.
        if std::os::unix::process::parent_id() as libc::pid_t != supervisor {
            // SAFETY: `_exit` has no memory precondition; it ends this child
            // without running the destructors of the frames it inherited.
            unsafe { libc::_exit(0) }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = supervisor;
}

/// Fork the side listener's child. It resets the signal dispositions the
/// supervisor installed, so the supervisor's `SIGTERM` terminates it and no
/// inherited handler fires there, and then never returns.
#[cfg(unix)]
fn spawn_side(
    side: &SideListener,
    db: &Arc<Scanner>,
    opts: &Arc<ScanOptions>,
    r#gen: &Generation,
) -> io::Result<libc::pid_t> {
    use std::io::Write as _;
    let _ = io::stderr().flush();
    // Read before forking: afterwards the child can only ask who its parent is,
    // which does not say whether that is still the process that forked it.
    let supervisor = std::process::id() as libc::pid_t;
    // SAFETY: as in `spawn_worker`.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            let retire = r#gen.enter();
            child_signals();
            // After the resets above, so the SIGTERM it arranges is the default
            // disposition; a handler inherited from the supervisor would
            // otherwise decide what parent death means here.
            die_with_parent(supervisor);
            (side.serve)(Arc::clone(db), Arc::clone(opts), retire);
            // The listener was the child's whole job, so there is nothing left
            // for it to do but let the supervisor respawn it.
            // SAFETY: `_exit` has no memory precondition; it ends this child
            // without running the destructors of the frames it inherited.
            unsafe { libc::_exit(2) }
        }
        n => Ok(n),
    }
}

/// The `--auto-update` re-check of a pool, in a child of the supervisor.
///
/// On a thread of the supervisor it would be running whenever a worker is
/// forked, and a child of a process with several threads can find a lock held
/// by a thread it does not have. Forked before the database is loaded, the
/// child holds none of it, and it stays through the reloads with the
/// validators it has learned. It asks the supervisor for a reload with
/// `SIGUSR2`, and one that dies is forked again. Dropping this stops it.
#[cfg(unix)]
pub struct Updater {
    check: crate::signatures::AutoUpdate,
    pid: Option<libc::pid_t>,
    /// When the child was last forked.
    since: Instant,
}

/// Off Unix there is no pool, and no updater child.
#[cfg(not(unix))]
pub enum Updater {}

/// The least time between two forks of the updater's child, so that one that
/// dies at once is not forked in a loop.
#[cfg(unix)]
const UPDATER_REFORK: Duration = Duration::from_secs(60);

#[cfg(unix)]
impl Updater {
    /// Fork the child that runs `check`'s poll. Called while this process has
    /// one thread, before the database is loaded.
    pub fn start(check: crate::signatures::AutoUpdate) -> io::Result<Self> {
        // The child's first request can come before the pool installs its
        // handlers, and the default action of SIGUSR2 ends this process.
        // SAFETY: `on_sigusr2` is async-signal-safe, as its doc says.
        unsafe { install_handler(libc::SIGUSR2, on_sigusr2) };
        let mut updater = Updater {
            check,
            pid: None,
            since: Instant::now(),
        };
        updater.fork(None)?;
        Ok(updater)
    }

    /// Fork the child. `r#gen`: the pool's current generation, whose write
    /// end the child is not to hold.
    fn fork(&mut self, r#gen: Option<&Generation>) -> io::Result<()> {
        use std::io::Write as _;
        let _ = io::stderr().flush();
        // Read before forking; see `die_with_parent`.
        let supervisor = std::process::id() as libc::pid_t;
        // A fork that fails is tried again no sooner than one that dies.
        self.since = Instant::now();
        // SAFETY: as in `spawn_worker`.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => Err(io::Error::last_os_error()),
            0 => {
                if let Some(g) = r#gen {
                    g.enter();
                }
                child_signals();
                die_with_parent(supervisor);
                self.check.clone().poll(&|| {
                    // SAFETY: `kill` has no memory precondition.
                    unsafe { libc::kill(supervisor, libc::SIGUSR2) };
                });
                // SAFETY: `_exit` has no memory precondition; it ends this
                // child without running the destructors of the frames it
                // inherited.
                unsafe { libc::_exit(0) }
            }
            n => {
                self.pid = Some(n);
                Ok(())
            }
        }
    }

    /// Whether `pid` is the child; it is then reaped, and forked again by
    /// [`Updater::due`].
    fn reaped(&mut self, pid: libc::pid_t) -> bool {
        let ours = self.pid == Some(pid);
        if ours {
            self.pid = None;
        }
        ours
    }

    /// Fork the child again if it is gone and it was last forked long enough
    /// ago; how long until it may be otherwise. A fork that fails is logged
    /// and tried again then: the pool serves on without it.
    fn due(&mut self, r#gen: &Generation) -> Option<Duration> {
        if self.pid.is_some() {
            return None;
        }
        let wait = UPDATER_REFORK.saturating_sub(self.since.elapsed());
        if !wait.is_zero() {
            return Some(wait);
        }
        match self.fork(Some(r#gen)) {
            Ok(()) => None,
            Err(e) => {
                eprintln!("exav: the signature updater could not be forked again: {e}");
                Some(UPDATER_REFORK)
            }
        }
    }

    /// The child, for the supervisor's teardown, which reaps it.
    fn take(&mut self) -> Option<libc::pid_t> {
        self.pid.take()
    }
}

#[cfg(unix)]
impl Drop for Updater {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            let mut status: libc::c_int = 0;
            // SAFETY: signals and reaps a child of this process that has not
            // been reaped, so the pid cannot have been reused; `waitpid` writes
            // the local `status`.
            unsafe {
                libc::kill(pid, libc::SIGTERM);
                libc::waitpid(pid, &mut status, 0);
            }
        }
    }
}

#[cfg(unix)]
fn spawn_worker(
    listener: &BoundListener,
    db: &Arc<Scanner>,
    opts: &Arc<ScanOptions>,
    cfg: &PoolConfig,
    r#gen: &Generation,
) -> io::Result<libc::pid_t> {
    // Flush so buffered parent output isn't duplicated into the child.
    use std::io::Write as _;
    let _ = io::stderr().flush();
    // Read before forking; see `die_with_parent`.
    let supervisor = std::process::id() as libc::pid_t;
    // SAFETY: `fork` has no memory precondition. Its child runs this
    // program's code, which allocates and takes locks: POSIX allows that only
    // in the child of a process that has one thread. The supervisor starts
    // none: `--auto-update`'s periodic check is a child of its own
    // ([`Updater`]).
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => worker_main(listener, db, opts, cfg, supervisor, r#gen.enter()), // never returns
        n => Ok(n),
    }
}

/// A worker process: bound by the kernel limits, it accepts and serves
/// connections one at a time until it hits its job limit or its generation
/// `retire` is retired (then exits cleanly, and the supervisor replaces it in
/// the first case only). Never returns.
#[cfg(unix)]
fn worker_main(
    listener: &BoundListener,
    db: &Scanner,
    opts: &ScanOptions,
    cfg: &PoolConfig,
    supervisor: libc::pid_t,
    retire: std::os::fd::RawFd,
) -> ! {
    // Apply the kernel-enforced resource caps to *this* process.
    //
    // `RLIMIT_AS` bounds the WHOLE address space, and this process already holds
    // the signature database, which is most of a gigabyte. Setting the raw
    // configured value would give a scan only what is left over rather than the
    // budget the setting names, and jobs would be killed for exceeding a ceiling
    // nobody asked for. Adding what the process already uses makes the number
    // mean what it says: memory available TO A SCAN.
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
    // SAFETY: these handlers are async-signal-safe, as their docs say.
    unsafe {
        install_handler(libc::SIGALRM, on_sigalrm);
        install_handler(libc::SIGXCPU, on_sigxcpu);
        // Report an allocation failure to the client instead of dying silently.
        install_handler(libc::SIGABRT, on_sigabrt);
    }
    // Replace the handlers inherited from the supervisor, so its flag-setting
    // handlers don't fire here.
    child_signals();
    // SAFETY: `on_sigterm` is async-signal-safe, as its doc says.
    unsafe { install_handler(libc::SIGTERM, on_sigterm) };
    // Only now, with SIGTERM handled here: arranged before, parent death would
    // run the handler this worker inherited from the supervisor, which only
    // sets a flag, and the worker would go on to block in `accept()` exactly
    // as if nothing had been arranged at all.
    die_with_parent(supervisor);
    let arm = || {
        IN_JOB.store(true, std::sync::atomic::Ordering::Relaxed);
        arm_cpu_limit(cfg.max_cpu_secs);
        set_timer(cfg.max_scan_time)
    };
    let disarm = || {
        set_timer(std::time::Duration::ZERO);
        IN_JOB.store(false, std::sync::atomic::Ordering::Relaxed);
    };
    // A `RELOAD` command reaches a worker, not the supervisor; forward it by
    // signalling the parent, which owns the pool and does the re-fork.
    let reload = || {
        let parent = std::os::unix::process::parent_id() as libc::pid_t;
        // SAFETY: `kill` has no memory precondition.
        unsafe { libc::kill(parent, libc::SIGUSR2) };
    };
    // `SHUTDOWN` likewise forwards to the supervisor (SIGTERM → graceful
    // teardown of the whole pool). Disabled → report it wasn't honoured.
    let allow_shutdown = cfg.allow_shutdown;
    SHUTDOWN_ALLOWED.store(allow_shutdown, Ordering::Relaxed);
    let allow_http_scan = cfg.allow_http_scan;
    let reads = cfg.reads;
    let shutdown = move || -> bool {
        if allow_shutdown {
            let parent = std::os::unix::process::parent_id() as libc::pid_t;
            // SAFETY: `kill` has no memory precondition.
            unsafe { libc::kill(parent, libc::SIGTERM) };
            true
        } else {
            false
        }
    };

    let mut jobs = 0u64;
    loop {
        if !await_connection(listener.as_raw_fd(), retire) {
            // SAFETY: `_exit` has no memory precondition; it ends this child
            // without running the destructors of the frames it inherited.
            unsafe { libc::_exit(0) }
        }
        // The listener is non-blocking, and on some systems an accepted socket
        // inherits that; a job's reads are written for a blocking one.
        let outcome: io::Result<()> = match listener {
            BoundListener::Unix(l) => match l.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(reads.idle));
                    let _ = stream.set_write_timeout(Some(reads.idle));
                    // Record the fd so `on_sigabrt` can answer on this connection
                    // if the scan aborts, instead of closing without a word.
                    CURRENT_CONN_FD.store(
                        std::os::fd::AsRawFd::as_raw_fd(&stream),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    let reader = AncillaryReader::new(&stream);
                    let r = handle_conn(
                        reader,
                        &stream,
                        db,
                        opts,
                        &arm,
                        &disarm,
                        &reload,
                        &shutdown,
                        allow_http_scan,
                        reads,
                    );
                    CURRENT_CONN_FD.store(-1, std::sync::atomic::Ordering::Relaxed);
                    disarm(); // ensure the timer is off between connections
                    r
                }
                // Another worker took the connection this one woke for.
                Err(e) if lost_accept_race(&e) => continue,
                Err(e) => {
                    eprintln!("exav: worker accept error: {e}");
                    // SAFETY: as at the top of the loop.
                    unsafe { libc::_exit(1) }
                }
            },
            BoundListener::Tcp(l) => match l.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(reads.idle));
                    let _ = stream.set_write_timeout(Some(reads.idle));
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
                    let r = handle_conn(
                        &s,
                        &s,
                        db,
                        opts,
                        &arm,
                        &disarm,
                        &reload,
                        &shutdown,
                        allow_http_scan,
                        reads,
                    );
                    CURRENT_CONN_FD.store(-1, std::sync::atomic::Ordering::Relaxed);
                    disarm();
                    r
                }
                Err(e) if lost_accept_race(&e) => continue,
                Err(e) => {
                    eprintln!("exav: worker accept error: {e}");
                    // SAFETY: as at the top of the loop.
                    unsafe { libc::_exit(1) }
                }
            },
        };
        if let Err(e) = outcome
            && !is_benign_disconnect(&e)
        {
            eprintln!("exav: connection error: {e}");
        }
        jobs += 1;
        if cfg.max_jobs != 0 && jobs >= cfg.max_jobs {
            // Recycle: the supervisor respawns from a clean parent.
            // SAFETY: as at the top of the loop.
            unsafe { libc::_exit(0) }
        }
    }
}

/// Decode a reaped child's wait-status into a human-readable cause, so the
/// operator can see *why* it died (timeout / OOM / CPU / recycle). `what` names
/// the child; `retired` says it belonged to a generation a reload replaced.
#[cfg(unix)]
fn log_child_exit(pid: libc::pid_t, status: libc::c_int, what: &str, retired: bool) {
    let cause = if libc::WIFEXITED(status) {
        match libc::WEXITSTATUS(status) {
            EXIT_TIMEOUT => "scan wall-clock timeout".to_string(),
            EXIT_CPU => "scan CPU-time limit".to_string(),
            EXIT_ABORTED => "aborted mid-scan (reported to the client)".to_string(),
            EXIT_STOPPED => "stopped".to_string(),
            0 if retired => "retired after a reload".to_string(),
            0 => "recycled (job limit / clean exit)".to_string(),
            code => format!("exit code {code}"),
        }
    } else if libc::WIFSIGNALED(status) {
        match libc::WTERMSIG(status) {
            // RLIMIT_AS fails an allocation (SIGABRT below); SIGKILL comes from
            // the system OOM killer, a hard RLIMIT_CPU or an operator.
            libc::SIGKILL => "killed by SIGKILL (system OOM killer or operator)".to_string(),
            libc::SIGXCPU => "CPU-time limit (RLIMIT_CPU)".to_string(),
            libc::SIGABRT => "aborted (allocation failure under RLIMIT_AS)".to_string(),
            sig => format!("signal {sig}"),
        }
    } else {
        "unknown".to_string()
    };
    eprintln!("exav: {what} {pid} exited: {cause}");
}

/// Command terminator, mirrored from the request onto the reply.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Delim {
    Newline,
    Null,
}

impl Delim {
    pub(crate) fn byte(self) -> u8 {
        match self {
            Delim::Newline => b'\n',
            Delim::Null => b'\0',
        }
    }
}

/// Read one command. Returns `None` at clean end-of-connection. The leading
/// `z`/`n` prefix (if any) selects the terminator; a bare command is treated as
/// legacy newline-terminated.
pub(crate) fn read_command<R: Read>(r: &mut BufReader<R>) -> io::Result<Option<(String, Delim)>> {
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
    // is perfectly legal, so `from_utf8_lossy` can replace bytes and produce a
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
            ));
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
///
/// `reads` bound each read and each command, from its first byte to the end of
/// its data ([`Reads`]). A client past the second is told so and disconnected.
///
/// A reply write that fails with the socket's write timeout (set by the
/// caller, `?idle-secs=`), or that finds the reply's time
/// (`reads.reply`) spent, ends the connection with a [`ClientNotReading`] error,
/// which the caller logs.
///
/// A connection past `reads.session` reads no new command and ends with `Ok`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_conn<R, W>(
    rd: R,
    writer: W,
    db: &Scanner,
    opts: &ScanOptions,
    arm: &dyn Fn(),
    disarm: &dyn Fn(),
    reload: &dyn Fn(),
    shutdown: &dyn Fn() -> bool,
    allow_http_scan: bool,
    reads: Reads,
) -> io::Result<()>
where
    R: Read + FdSource + SetReadTimeout,
    W: Write + SetWriteTimeout,
{
    // The wait of a read with no command limit to cut it.
    rd.set_read_timeout(reads.idle)?;
    let clock = ReadClock::new(reads.command, reads.idle).lasting(reads.session);
    let mut reader = BufReader::new(Clocked::new(rd, &clock));
    let mut writer = Replies::new(writer, reads.reply)?;
    let r = converse(
        &mut reader,
        &clock,
        &mut writer,
        db,
        opts,
        arm,
        disarm,
        reload,
        shutdown,
        allow_http_scan,
    );
    if let Err(e) = &r
        && is_too_slow(e)
    {
        // clamd's words and framing for the same event, so a client that reads
        // its replies reads this one the same way.
        writer.start_reply();
        let _ = writer.write_all(b"COMMAND READ TIMED OUT\n");
        let _ = writer.flush();
    }
    match r {
        // The lifetime ended the wait for a command: a connection that ends as
        // any other does.
        Err(e) if is_session_over(&e) => Ok(()),
        r => r,
    }
}

/// The commands of one connection, under `clock`.
#[allow(clippy::too_many_arguments)]
fn converse<R, W>(
    reader: &mut BufReader<Clocked<'_, R>>,
    clock: &ReadClock,
    writer: &mut Replies<W>,
    db: &Scanner,
    opts: &ScanOptions,
    arm: &dyn Fn(),
    disarm: &dyn Fn(),
    reload: &dyn Fn(),
    shutdown: &dyn Fn() -> bool,
    allow_http_scan: bool,
) -> io::Result<()>
where
    R: Read + FdSource + SetReadTimeout,
    W: Write + SetWriteTimeout,
{
    let (cmd, delim) = match read_command(reader)? {
        Some(c) => c,
        None => return Ok(()),
    };
    let cmd = cmd.trim().to_string();
    let word = cmd.split_whitespace().next().unwrap_or("").to_string();

    // IDSESSION/SESSION keep the connection open for many commands until END.
    // IDSESSION tags each reply with a sequence id (the modern, client-preferred
    // form); the legacy SESSION does not. Every other command is handled once and
    // the connection is then closed: clamd's single-command-per-connection
    // semantics, which clients rely on to know the reply is complete.
    let idsession = word.eq_ignore_ascii_case("IDSESSION");
    if idsession || word.eq_ignore_ascii_case("SESSION") {
        let mut id = 0u64;
        loop {
            // Past the connection's lifetime no command is read, buffered or not.
            if clock.lifetime_over() {
                return Ok(());
            }
            // Each command of a session has its own time, which runs from its
            // first byte: the wait for that byte is the socket's timeout, or
            // what is left of the connection's lifetime.
            clock.restart(!reader.buffer().is_empty());
            let (cmd, delim) = match read_command(reader)? {
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
            writer.start_reply();
            arm();
            let r = run_command(
                cmd,
                word,
                reader,
                writer,
                delim,
                idsession.then_some(id),
                db,
                opts,
                reload,
                shutdown,
                allow_http_scan,
            );
            disarm();
            // A stream that ran out of time, or was left unread, was answered,
            // and what is left of it on the wire is not a command.
            if r? == Rest::Unread || clock.fired() {
                return Ok(());
            }
        }
    }

    if cmd.is_empty() || word.eq_ignore_ascii_case("END") {
        return Ok(());
    }
    writer.start_reply();
    arm();
    let r = run_command(
        &cmd,
        &word,
        reader,
        writer,
        delim,
        None,
        db,
        opts,
        reload,
        shutdown,
        allow_http_scan,
    );
    disarm();
    r.map(|_| ())
}

/// Execute one command and write its reply line(s), and say what it left of
/// its request. FILDES is handled here (it needs the fd-capturing reader);
/// everything else goes to `dispatch`.
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
    allow_http_scan: bool,
) -> io::Result<Rest>
where
    R: Read + FdSource,
    W: Write,
{
    let (replies, rest) = if word.eq_ignore_ascii_case("FILDES") {
        (vec![fildes(reader, db, opts)], Rest::Read)
    } else if word.eq_ignore_ascii_case("RELOAD") {
        // Ask the supervisor to re-read the data dir and re-fork the pool. The
        // reply is clamd's `RELOADING` either way; the reload happens out of band
        // (a no-op in the thread model, which has no supervisor to re-fork).
        reload();
        (vec!["RELOADING".to_string()], Rest::Read)
    } else if word.eq_ignore_ascii_case("SHUTDOWN") || word.eq_ignore_ascii_case("QUIT") {
        // clamd accepts QUIT as an alias for SHUTDOWN. Answering
        // `UNKNOWN COMMAND` leaves a client that speaks clamd unable to stop a
        // daemon that claims to speak it back.
        // clamd's SHUTDOWN stops the daemon. `shutdown()` initiates a graceful
        // teardown and returns true; if the command is disabled it returns false
        // and we surface an error instead of a silent no-op. clamd sends no reply
        // on success, so neither do we (the process tears down).
        let replies = if shutdown() {
            Vec::new()
        } else {
            vec!["SHUTDOWN: command disabled ERROR".to_string()]
        };
        (replies, Rest::Read)
    } else {
        dispatch(cmd, word, reader, delim, db, opts, allow_http_scan)?
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
    Ok(rest)
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

/// Run a single command, returning the reply line(s) and what it left of its
/// request. For INSTREAM the chunk stream is consumed from `reader`.
fn dispatch<R: Read>(
    cmd: &str,
    word: &str,
    reader: &mut BufReader<R>,
    _delim: Delim,
    db: &Scanner,
    opts: &ScanOptions,
    allow_http_scan: bool,
) -> io::Result<(Vec<String>, Rest)> {
    let arg = cmd[word.len()..].trim();
    // The fuzz target feeds this arbitrary bytes, and a path in them would be
    // opened on the machine fuzzing.
    #[cfg(feature = "fuzzing")]
    if matches!(
        word.to_ascii_uppercase().as_str(),
        "SCAN" | "CONTSCAN" | "MULTISCAN" | "ALLMATCHSCAN"
    ) {
        return Ok((
            vec![format!("{word}: paths are not read when fuzzing ERROR")],
            Rest::Read,
        ));
    }
    let streamed = |(reply, rest)| Ok((vec![reply], rest));
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
        // that works and is missing here is a capability nobody discovers, and
        // a verb that is listed but refused is a capability nobody can use.
        // `SCANURL` is therefore listed only when this daemon would honour it:
        // built with `http-scan` and started with `--allow-http-scan`.
        "VERSIONCOMMANDS" => vec![versioncommands(
            &clamav_version(db),
            SHUTDOWN_ALLOWED.load(Ordering::Relaxed),
            allow_http_scan,
        )],
        // RELOAD is intercepted in `run_command` (it needs the supervisor hook).
        // clamd-compatible status block: POOLS/STATE/THREADS/QUEUE/MEMSTATS/END,
        // the shape `clamdtop` parses for its live columns. exav has no custom
        // allocator instrumentation, so the heap/mmap memory figures are `N/A`
        // (clamd reports the same when built without its pools allocator).
        //
        // The clamd fields keep their positions and their names, because
        // `clamdtop` finds its columns by both. What exav knows and clamd does
        // not (where this process spent its scan time) follows them as
        // `SCANSTATS`/`MATCHERSTATS` lines, which a clamd client ignores and a
        // human or a scraper can read. `QUEUE` reports the scans actually in
        // flight rather than the constant `0 items` a stub would give, since a
        // saturated listener is exactly what someone runs this command to see.
        "STATS" => vec![stats_reply()],
        // clamd's SCAN takes a file OR a directory, and recurses into one. A
        // client that sends a directory and gets `Is a directory ERROR` back is
        // a client that works against clamd and not against exav, which is the
        // whole claim of speaking this protocol. `scan_tree` also rejoins split
        // sets, so a directory answered here matches what CONTSCAN would say.
        "SCAN" if Path::new(arg).is_dir() => scan_tree(db, opts, arg),
        "SCAN" => vec![scan_one_path(db, opts, arg)],
        "CONTSCAN" | "MULTISCAN" => scan_tree(db, opts, arg),
        // All-match: report every matching signature per file (not just the
        // first), one reply line each: clamd's ALLMATCHSCAN semantics.
        "ALLMATCHSCAN" => scan_tree_allmatch(db, opts, arg),
        "INSTREAM" => return streamed(instream(db, opts, reader)?),
        // Extended INSTREAM: same chunk framing, structured JSON reply with the
        // nested match location. Older/newer clients that don't know it fall to
        // the `UNKNOWN COMMAND` arm below and degrade cleanly.
        // `EXINSTREAM MULTI` sends several files in one request so a
        // multi-volume archive split across them can be rejoined; bare
        // `EXINSTREAM` is the single-file form and is unchanged.
        "EXINSTREAM" if arg.eq_ignore_ascii_case("MULTI") => {
            return streamed(exinstream_multi(db, opts, reader)?);
        }
        "EXINSTREAM" => return streamed(exinstream(db, opts, reader)?),
        #[cfg(feature = "http-scan")]
        "SCANURL" => {
            vec![if allow_http_scan {
                scan_url(db, opts, arg)
            } else {
                format!(
                    "{arg}: SCANURL disabled (the daemon was not started with --allow-http-scan) ERROR"
                )
            }]
        }
        #[cfg(not(feature = "http-scan"))]
        "SCANURL" => vec![format!(
            "{arg}: SCANURL needs a build with `--features http-scan` ERROR"
        )],
        _ => vec![format!("UNKNOWN COMMAND {word} ERROR")],
    };
    Ok((reply, Rest::Read))
}

pub(crate) fn write_reply<W: Write>(
    w: &mut W,
    id: Option<u64>,
    reply: &str,
    delim: Delim,
) -> io::Result<()> {
    // In session (IDSESSION) mode each reply MESSAGE is tagged with its command
    // id on its FIRST line only; the remaining lines of a multi-line reply (the
    // STATS block) travel raw, exactly as clamd frames them. Prefixing every line
    // breaks clamd-session clients like clamdtop, which then see
    // `2: STATE:`/`2: THREADS:` instead of the bare field lines and can't parse
    // the body. Each CONTSCAN file result is a separate reply message (its own
    // call here), so it still gets its own id; only intra-message lines change.
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
/// CLI uses, so the two surfaces cannot drift apart.
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
        // The same grammar the one-shot CLI prints (`reason CATEGORY STATUS`),
        // so the two surfaces do not describe one verdict two ways. Only the
        // status word differs, and it has to: clamd's vocabulary is `OK`,
        // `FOUND` and `ERROR`, and a real client reads a word outside it as
        // `OK`. Measured against clamdscan 1.4.3, which rewrites an unknown
        // status to `OK` and exits 0, so `PARTIAL` on this wire would turn
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
/// therefore rejoined per directory and scanned as the archives they are. See
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
        // is a fragment, so that `OK` says only "this fragment is not itself
        // malware". A detection in the archive also replaces a part's own
        // `PARTIAL`, which says only that the fragment could not be read
        // whole. Any other verdict the part earned by itself stands.
        match sets.get(f) {
            Some((found, status))
                if line.ends_with(": OK") || (*found && !line.ends_with(" FOUND")) =>
            {
                out.push(format!("{name}: {status}"))
            }
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
/// Returns whether the set was found infected and the status text to report,
/// for each part of a set that resolved to something other than clean, keyed
/// by the part's own path, so the caller still emits exactly one reply line
/// per file. A piece of an infected archive is not a clean file, and it is the
/// piece the operator has to act on.
///
/// Grouped per directory: `a/big.7z.001` and `b/big.7z.002` are two unrelated
/// files that happen to share a name, and splicing them would concatenate bytes
/// nothing ever wrote.
fn volume_set_lines(
    db: &Scanner,
    opts: &ScanOptions,
    files: &[std::path::PathBuf],
) -> std::collections::HashMap<std::path::PathBuf, (bool, String)> {
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
        let mut verdicts = exav_core::analyze_volume_sets(db, &names, opts, |name| {
            let mut data = Vec::new();
            exav_core::unpack::source::read_capped(
                &mut File::open(dir.join(name))?,
                &mut data,
                opts.limits.max_buffer_bytes.saturating_add(1),
            )?;
            Ok(data)
        });
        // The sets whose volumes carry their own headers (RAR, ZIP, CAB), read
        // where they lie. A `.cab` is read by its head to see whether it names
        // a neighbour, and no name is turned into a path: only names in this
        // directory's list.
        verdicts.extend(exav_core::analyze_split_sets_seekable(
            db,
            &names,
            opts,
            |name| File::open(dir.join(name)),
        ));
        for v in verdicts {
            // Named for the archive, not the fragment: `big.7z FOUND …` tells an
            // operator what was actually found, which `big.7z.002` does not.
            //
            // Built by `verdict_line` so a part's reply and a whole file's reply
            // share one grammar, including `--partial-as`, which `verdict_line`
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
            let found = v.report.verdict.category() == VerdictCategory::Infected;
            out.insert(
                dir.join(&v.name),
                (found, format!("{status} (in {})", v.set)),
            );
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

/// All-match scan of a single file: report every matching signature, at any
/// size; past `--max-input-bytes`, what its first bytes hold. With no
/// detection, an incomplete scan is reported as such. Unlike the CLI's
/// `--all-matches`, a reply with detections carries no line for the limit.
fn scan_one_allmatch(db: &Scanner, opts: &ScanOptions, path: &str) -> Vec<String> {
    if path.is_empty() {
        return vec!["ALLMATCHSCAN: missing path ERROR".to_string()];
    }
    // Isolate a panic on a crafted file into an ERROR for this target.
    let found = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        analyze_all_path(db, Path::new(path), opts)
    }));
    let found = match found {
        Ok(Ok(found)) => Ok(found),
        Ok(Err(e)) => return vec![format!("{path}: {e} ERROR")],
        Err(panic) => Err(panic),
    };
    match found {
        Ok((dets, _)) if !dets.is_empty() => dets
            .into_iter()
            .map(|(sig, _method)| format!("{path}: {sig} FOUND"))
            .collect(),
        // No detections, but the walk may not have covered the file. Reporting OK
        // here regardless is a silent clean, and it lands in the mode a
        // differential harness drives every file through, so the measurements
        // steering development inherited it too.
        // The same line a single-match scan gives, `--partial-as` included.
        Ok((_, outcome)) => {
            let verdict = match outcome {
                AllMatchOutcome::Complete => Verdict::Clean,
                AllMatchOutcome::LimitsExceeded(reason) => Verdict::LimitsExceeded { reason },
                AllMatchOutcome::Unscannable(reason) => Verdict::Unscannable { reason },
                AllMatchOutcome::PasswordProtected(reason) => Verdict::PasswordProtected { reason },
            };
            vec![verdict_line(path, &ScanReport::new(verdict, Vec::new()))]
        }
        Err(_) => vec![format!("{path}: scan failed (internal error) ERROR")],
    }
}

#[cfg(feature = "http-scan")]
fn scan_url(db: &Scanner, opts: &ScanOptions, url: &str) -> String {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return format!("{url}: SCANURL requires an http(s) URL ERROR");
    }
    let (reader, size) = match exav_core::source::open_http(url, opts) {
        Ok(r) => r,
        Err(e) => return format!("{url}: {e} ERROR"),
    };
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

/// What a command leaves of its request on the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rest {
    /// Nothing: the next byte is the next command's.
    Read,
    /// Bytes that were not read and are not a command: the connection is
    /// closed after the reply.
    Unread,
}

/// A stream payload materialized into a **seekable** source: in RAM when small,
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

    /// The payload's bytes, or `None` when it is larger than `cap`. For the
    /// second looks at the same bytes: multi-volume rejoining, and
    /// `--all-matches`.
    pub(crate) fn bytes_capped(&self, cap: u64) -> io::Result<Option<Vec<u8>>> {
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

    /// Every detection in the payload, at any size (see
    /// [`exav_core::analyze_all_seekable`]), for a stream of `size` bytes:
    /// past `--max-input-bytes`, more than the payload holds.
    pub(crate) fn all_matches(
        &self,
        db: &Scanner,
        opts: &ScanOptions,
        size: u64,
    ) -> io::Result<(Vec<(String, exav_core::Method)>, AllMatchOutcome)> {
        match self {
            StreamPayload::Mem(v) => {
                exav_core::analyze_all_seekable(db, std::io::Cursor::new(&v[..]), size, opts)
            }
            StreamPayload::Disk(tmp, _) => {
                exav_core::analyze_all_seekable(db, tmp.reopen()?, size, opts)
            }
        }
    }
}

/// A stream read into a seekable payload, as far as it could be held.
pub(crate) struct Held {
    pub(crate) payload: StreamPayload,
    /// Why the payload stops before the stream's end, when it does: there was
    /// nowhere left to put the rest. The reader is left at that point.
    pub(crate) short: Option<String>,
}

/// Buffer an (already de-chunked / pre-capped) reader into a [`StreamPayload`]:
/// up to the configured threshold in RAM, then spill the rest to a temp file.
/// Shared by the daemon stream verbs and the CLI's stdin so all get the same
/// seekable, container-aware scan under the same budgets. A stream larger than
/// the budgets allow is held as far as they allow.
pub(crate) fn buffer_to_seekable<R: Read>(reader: &mut R) -> io::Result<Held> {
    use crate::spill::SpillError;
    let threshold = crate::spill::config().threshold;
    let mut buf = Vec::new();
    exav_core::unpack::source::read_capped(&mut *reader, &mut buf, threshold)?;
    let mut block = vec![0u8; 64 * 1024];
    let got = match (buf.len() as u64) < threshold {
        true => 0,
        false => read_full(reader, &mut block)?,
    };
    if got == 0 {
        return Ok(Held {
            payload: StreamPayload::Mem(buf),
            short: None,
        });
    }
    // More data remains: spill the RAM head, then stream the rest to disk. The
    // budgets live in `SpillFile`: `RLIMIT_AS` caps address space and does not
    // cap a file, so without them a client that never stops sending fills the
    // temp filesystem, a denial of service against the host rather than the
    // scan, and one that outlives the connection.
    let mut tmp = match crate::spill::SpillFile::create() {
        Ok(t) => t,
        Err(SpillError::Budget(why)) => {
            return Ok(Held {
                payload: StreamPayload::Mem(buf),
                short: Some(why),
            });
        }
        Err(SpillError::Io(e)) => return Err(e),
    };
    let mut short = None;
    for chunk in [&buf[..], &block[..got]] {
        match tmp.write_all(chunk) {
            Ok(()) => {}
            Err(SpillError::Budget(why)) => {
                short = Some(why);
                break;
            }
            Err(SpillError::Io(e)) => return Err(e),
        }
    }
    while short.is_none() {
        let n = reader.read(&mut block)?;
        if n == 0 {
            break;
        }
        match tmp.write_all(&block[..n]) {
            Ok(()) => {}
            Err(SpillError::Budget(why)) => short = Some(why),
            Err(SpillError::Io(e)) => return Err(e),
        }
    }
    let len = tmp.len()?;
    Ok(Held {
        payload: StreamPayload::Disk(tmp, len),
        short,
    })
}

/// Scan what was held of a stream of `size` bytes. A payload that stops short
/// for want of room is treated as `--max-input-bytes` treats an input past it:
/// the held bytes get the whole scan, and with no detection in them the limit
/// is reported.
pub(crate) fn scan_held(
    db: &Scanner,
    opts: &ScanOptions,
    held: &Held,
    size: u64,
) -> io::Result<(ScanReport, Option<String>)> {
    let Some(why) = &held.short else {
        return scan_payload(db, opts, &held.payload, size);
    };
    let kept = held.payload.len();
    let (report, loc) = scan_payload(db, opts, &held.payload, kept)?;
    if report.verdict.category() == VerdictCategory::Infected {
        return Ok((report, loc));
    }
    let reason = format!("{why}; scanned the first {kept} bytes only");
    Ok((
        ScanReport::new(Verdict::LimitsExceeded { reason }, Vec::new()),
        None,
    ))
}

/// Scan a materialized payload via the seekable (container-aware) path, returning
/// the report and the nested match location (`None` for a top-level hit).
///
/// `size` is the input's full size. It is larger than the payload when the
/// input went past `--max-input-bytes` and only its start was kept.
pub(crate) fn scan_payload(
    db: &Scanner,
    opts: &ScanOptions,
    payload: &StreamPayload,
    size: u64,
) -> io::Result<(ScanReport, Option<String>)> {
    match payload {
        StreamPayload::Mem(v) => {
            scan_seekable_located(db, std::io::Cursor::new(&v[..]), size, opts)
        }
        StreamPayload::Disk(tmp, _) => {
            // A fresh handle positioned at 0; the `TempFile` stays alive (and
            // thus the file) for as long as the payload does.
            let file = tmp.reopen()?;
            scan_seekable_located(db, file, size, opts)
        }
    }
}

/// [`scan_held`], timed into the process counters.
///
/// The ICAP listener times its own scans (it names the object from the request
/// target, which this cannot see), so this is the daemon's stream verbs only:
/// double-counting a scan would make the throughput figure a fiction.
fn scan_payload_timed(
    db: &Scanner,
    opts: &ScanOptions,
    held: &Held,
    size: u64,
    target: &str,
) -> io::Result<(ScanReport, Option<String>)> {
    let timer = crate::metrics::ScanTimer::start();
    let result = scan_held(db, opts, held, size);
    let category = match &result {
        Ok((report, _)) => report.verdict.category().into(),
        // A scan that failed is a scan that did not finish, which is the
        // partial column wherever else exav counts it.
        Err(_) => crate::metrics::Category::Partial,
    };
    timer.finish(target, held.payload.len(), category);
    result
}

/// Scan an INSTREAM chunk stream. The payload is materialized to a seekable
/// source (RAM or a temp file) and given the full container-aware scan, so
/// malware inside an archive sent over INSTREAM is detected, matching clamd (the
/// old flat-only path missed it). Any unread chunks are drained so the connection
/// stays in sync for the next command.
fn instream<R: Read>(
    db: &Scanner,
    opts: &ScanOptions,
    reader: &mut BufReader<R>,
) -> io::Result<(String, Rest)> {
    let mut stream = Instream::new(reader, opts.max_scan_size);
    let held = buffer_to_seekable(&mut stream)?;
    // Counts what was not held, so the size is the stream's.
    let rest = stream.drain()?;
    // Answering a prefix would answer a question the client never finished
    // asking, and `OK` on the benign head of a file is a bypass anyone can drive.
    // Not a partial either: `--partial-as ok` would turn it back into that `OK`.
    if stream.truncated() {
        return Ok((format!("stream: {STREAM_CUT} ERROR"), rest));
    }
    let (report, _loc) = scan_payload_timed(db, opts, &held, stream.total(), "stream")?;
    Ok((verdict_line("stream", &report), rest))
}

/// `EXINSTREAM`: scan a file sent over the exact INSTREAM chunk framing and reply
/// with one line of compact JSON, `{"v":1,"status":...}` (module docs). The
/// payload is buffered and scanned as INSTREAM's is, and a detection also
/// carries its nested `location` (the `/`-joined member path). A detection beats
/// a limit, a stream not fully examined is `PARTIAL` with its category, never
/// `OK`, and one cut before its terminator is `ERROR`. One detection per scan.
fn exinstream<R: Read>(
    db: &Scanner,
    opts: &ScanOptions,
    reader: &mut BufReader<R>,
) -> io::Result<(String, Rest)> {
    // Materialize to a seekable source (RAM small / temp file large), the same
    // path as INSTREAM, bounded by `--max-input-bytes` (disk is the ceiling). That is
    // the flag this cap actually reads: `opts.max_scan_size` is exav-core's
    // per-top-level-file bound, which `--max-input-bytes` sets. Naming the other
    // flag here would send an operator to raise a setting that changes nothing.
    let mut stream = Instream::new(reader, opts.max_scan_size);
    let held = match buffer_to_seekable(&mut stream) {
        Ok(h) => h,
        Err(e) => {
            let rest = stream.drain().unwrap_or(Rest::Unread);
            return Ok((json_error(&format!("stream read error: {e}")), rest));
        }
    };
    // As in INSTREAM: counts what was not held.
    let rest = stream.drain()?;
    // As in INSTREAM: a prefix is not the file, so it gets no verdict.
    if stream.truncated() {
        return Ok((json_error(STREAM_CUT), rest));
    }
    let reply = match scan_payload_timed(db, opts, &held, stream.total(), "stream") {
        Ok((report, loc)) => verdict_json(&report, loc),
        Err(e) => json_error(&format!("scan error: {e}")),
    };
    Ok((reply, rest))
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
) -> io::Result<(String, Rest)> {
    use serde_json::json;
    // An answer before the request's end leaves the rest of it unread.
    let refused = |reason: &str| Ok((json_error(reason), Rest::Unread));
    let mut names: Vec<String> = Vec::new();
    // `None` for a file the daemon could not hold.
    let mut payloads: Vec<Option<StreamPayload>> = Vec::new();
    let mut entries: Vec<serde_json::Value> = Vec::new();
    // Set when the request stops before its terminator. Every file already read
    // still gets its verdict (those streams were complete), but the request as
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
            return refused("filename too long");
        }
        if names.len() >= MAX_STREAM_FILES {
            return refused("too many files in one request");
        }
        let mut raw = vec![0u8; n as usize];
        if read_full(reader, &mut raw)? < raw.len() {
            request_truncated = true;
            break;
        }
        let name = String::from_utf8_lossy(&raw).into_owned();

        let mut stream = Instream::new(reader, opts.max_scan_size);
        let held = match buffer_to_seekable(&mut stream) {
            Ok(h) => h,
            Err(e) => return refused(&format!("stream read error: {e}")),
        };
        // Past a drain that stopped at its cap, or at end of input, the next
        // file's framing is not where the loop would look for it.
        let cut = stream.drain()? == Rest::Unread || stream.truncated();
        let fields = if stream.truncated() {
            json!({"status": "ERROR", "reason": STREAM_CUT})
        } else {
            match scan_payload_timed(db, opts, &held, stream.total(), &name) {
                Ok((report, loc)) => verdict_fields(&report, loc),
                Err(e) => json!({"status": "ERROR", "reason": format!("scan error: {e}")}),
            }
        };
        match &held.payload {
            StreamPayload::Mem(v) => held_ram += v.len() as u64,
            StreamPayload::Disk(_, n) => held_spill += *n,
        }
        entries.push(named_entry(&name, fields, None));
        names.push(name);
        // Only a whole file can be a part of a rejoined set.
        let whole = held.short.is_none() && held.payload.len() == stream.total();
        payloads.push(whole.then_some(held.payload));
        if cut {
            request_truncated = true;
            break;
        }

        // Stop before accepting the file that would cross the line, so the
        // reply describes a request the daemon actually held rather than one it
        // died part-way through.
        if held_ram > MAX_STREAM_REQUEST_RAM || held_spill > MAX_STREAM_REQUEST_SPILL {
            return refused(
                "request too large: the files sent together exceed what one \
                 request may hold",
            );
        }
    }

    // Now the multi-volume pass, which is why these are sent together at all.
    // It reads back only the payloads whose names parse as parts.
    let held_bytes = |name: &str| {
        // First occurrence wins on a repeated name. Two files claiming one
        // volume position make the set ambiguous, and the collector refuses to
        // splice such a set rather than pick between them.
        let i = names
            .iter()
            .position(|n| n == name)
            .ok_or_else(|| io::Error::other("no such stream"))?;
        payloads[i]
            .as_ref()
            .ok_or_else(|| io::Error::other("stream was not held"))?
            .bytes_capped(opts.limits.max_buffer_bytes)?
            .ok_or_else(|| io::Error::other("stream too large to rejoin"))
    };
    let mut verdicts = exav_core::analyze_volume_sets(db, &names, opts, held_bytes);
    // And the sets whose volumes carry their own headers (RAR, ZIP, CAB), the
    // heads of `.cab` streams being read to see whether they name a neighbour.
    verdicts.extend(exav_core::analyze_split_sets(
        db,
        &names,
        opts,
        |name, head| {
            let mut data = held_bytes(name)?;
            if let Some(n) = head {
                data.truncate(n);
            }
            Ok(data)
        },
    ));
    for v in verdicts {
        let Some(i) = names.iter().position(|n| *n == v.name) else {
            continue;
        };
        // The archive's verdict replaces the part's own `clean`: on its own the
        // part is a fragment, so that `clean` says only "this fragment is not
        // itself malware". A detection in the archive also replaces the part's
        // own `PARTIAL`, which says only that the fragment could not be read
        // whole. Any other verdict the part earned by itself stands.
        let found = v.report.verdict.category() == VerdictCategory::Infected;
        let own = &entries[i]["status"];
        if own != "OK" && !(found && own != "FOUND") {
            continue;
        }
        entries[i] = named_entry(&v.name, verdict_fields(&v.report, None), Some(&v.set));
    }
    let mut out = json!({"v": 1, "files": entries});
    if request_truncated {
        // The per-file verdicts above stand: those streams arrived whole. This
        // says the LIST is short: files the client meant to send never got here,
        // and a caller treating "every file came back clean" as "the batch is
        // clean" would be wrong about a batch it never fully sent.
        out["truncated"] = json!(true);
    }
    let rest = if request_truncated {
        Rest::Unread
    } else {
        Rest::Read
    };
    Ok((out.to_string(), rest))
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
    // `status` / `category` / `reason`: the same three names the one-shot
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
    // of the contract: the object is serialised with sorted keys, and a JSON
    // consumer reads by name, so nothing here depends on where it lands.
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

/// The reason for a stream that ended before its terminator.
const STREAM_CUT: &str = "stream ended before its terminator";

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
    /// nobody chose to scan, and `OK` on a prefix is the shape of a bypass:
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
            // The client stopped before the terminator, either at a chunk
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
    /// Draining is a courtesy (it lets the connection carry another command
    /// instead of being reset), and a courtesy with no bound is a way to hold a
    /// worker. Every read completes inside the socket timeout, so the timeout
    /// never fires while a client keeps sending. The command's read time
    /// (`?request-secs=`) bounds it unless that is off; without either,
    /// one connection can occupy a slot for as long as it likes.
    ///
    /// Past the cap the reply still goes out, and the rest of the client's
    /// bytes are left unread: [`Rest::Unread`], after which the connection is
    /// closed.
    fn drain(&mut self) -> io::Result<Rest> {
        let mut sink = [0u8; 8192];
        let mut drained = 0u64;
        while !self.done {
            if drained >= MAX_DRAIN_BYTES {
                return Ok(Rest::Unread);
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
            self.total += n as u64;
        }
        Ok(Rest::Read)
    }

    /// The stream's size: every byte received, including those past the
    /// limit that were only counted. A lower bound when `drain` stopped at
    /// its cap.
    fn total(&self) -> u64 {
        self.total
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
            let before = self.total;
            self.total += n as u64;
            if let Some(max) = self.max
                && self.total > max
            {
                // Hand over up to one byte past the limit, so the payload
                // holds everything the scan looks at and shows it is over;
                // the rest is only counted, by `drain`.
                self.over_limit = true;
                return Ok((max + 1 - before) as usize);
            }
            return Ok(n);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    /// `--max-scan-secs` is an operator's number, and a database's build time is
    /// text from a file: neither may panic the supervisor or a connection.
    #[test]
    fn a_scan_time_limit_as_wide_as_a_duration_gets_a_grace_not_a_panic() {
        let g = super::retire_grace(std::time::Duration::MAX);
        assert!(g >= std::time::Duration::from_secs(5));
    }

    /// A limit of `u64::MAX` seconds wrapped to -1 as a `time_t`, which the
    /// kernel refuses, and the run went on with no limit at all.
    #[test]
    fn a_scan_time_limit_past_time_t_still_arms_the_timer() {
        let armed = |it: &libc::itimerval| it.it_value.tv_sec > 0;
        let read = || {
            // SAFETY: `itimerval` is two `timeval`s of integers, for which
            // all-zero bytes are valid.
            let mut it: libc::itimerval = unsafe { std::mem::zeroed() };
            // SAFETY: `getitimer` writes the local `it`.
            unsafe { libc::getitimer(libc::ITIMER_REAL, &mut it) };
            it
        };
        super::set_timer(std::time::Duration::from_secs(u64::MAX));
        let set = armed(&read());
        super::set_timer(std::time::Duration::ZERO);
        assert!(set, "the timer was armed");
        assert!(!armed(&read()), "and disarmed again");
    }

    #[test]
    fn a_build_time_with_a_huge_year_is_returned_unchanged() {
        let t = "17 Jul 9223372036854775807 06-24 +0000";
        assert_eq!(super::ctime_from_btime(t), t);
    }

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

    /// Every cap on what a scan holds fits the grant, not only the total: the
    /// engine reads an object whole up to `max_buffer_bytes`, and a total
    /// already under the grant says nothing about one object's cap.
    #[test]
    fn every_holding_cap_fits_the_grant() {
        let mut opts = ScanOptions::default();
        opts.limits.max_extracted_bytes = 1024 << 20;
        opts.limits.max_buffer_bytes = 256 << 20;
        fit_limits_to_job_memory(&mut opts, 300 << 20);
        assert_eq!(opts.limits.max_buffer_bytes, 75 << 20);
        assert_eq!(opts.limits.max_extracted_bytes, 104 << 20);

        let mut opts = ScanOptions::default();
        opts.limits.max_extracted_bytes = 100 << 20;
        opts.limits.max_buffer_bytes = u64::MAX;
        fit_limits_to_job_memory(&mut opts, 1000 << 20);
        assert_eq!(opts.limits.max_extracted_bytes, 100 << 20);
        assert_eq!(opts.limits.max_buffer_bytes, 250 << 20);
    }

    /// The cache of an object read in place and an HTTP request are held
    /// memory too: an eighth of the grant each at most.
    #[test]
    fn the_cache_and_the_request_fit_the_grant() {
        let mut opts = ScanOptions::default();
        opts.object_cache_bytes = 1 << 30;
        opts.http_request_bytes = 1 << 30;
        fit_limits_to_job_memory(&mut opts, 400 << 20);
        assert_eq!(opts.object_cache_bytes, 50 << 20);
        assert_eq!(opts.http_request_bytes, 50 << 20);
        let mut opts = ScanOptions::default();
        fit_limits_to_job_memory(&mut opts, 818 << 20);
        assert_eq!(opts.object_cache_bytes, 32 << 20);
    }

    /// From live archives scanned with objects allowed up to 2000M in 2 GiB
    /// workers: a ~420 MB member read whole was matched through copies of it
    /// (since removed) and the worker died on the allocation. What matching
    /// still takes beside an object, an image decoded from it and its grey
    /// copy plus a bounded lowercase copy, must fit what the job gets.
    #[test]
    fn an_object_and_what_matching_it_takes_fit_the_grant() {
        let job = 2048u64 << 20;
        let mut opts = ScanOptions::default();
        opts.limits.max_extracted_bytes = 2000 << 20;
        opts.limits.max_buffer_bytes = 2000 << 20;
        fit_limits_to_job_memory(&mut opts, job);
        let object = opts.limits.max_buffer_bytes;
        assert!(opts.limits.max_extracted_bytes + 2 * object + exav_core::LOWERCASE_COPY_MAX < job);
    }

    /// The default 2 GiB job leaves the default and `--clamav-compat` limits
    /// as they are.
    #[test]
    fn the_default_grant_keeps_the_default_limits() {
        for opts in [ScanOptions::default(), ScanOptions::clamav_compat()] {
            let mut fitted = opts.clone();
            fit_limits_to_job_memory(&mut fitted, 2048 << 20);
            assert_eq!(
                fitted.limits.max_extracted_bytes,
                opts.limits.max_extracted_bytes
            );
            assert_eq!(fitted.limits.max_buffer_bytes, opts.limits.max_buffer_bytes);
        }
    }

    /// A child that entered its generation and then drops it, as a panic
    /// unwinding out of a worker does, closes the write end once: a descriptor
    /// that took its number meanwhile stays open.
    #[test]
    fn a_generation_entered_then_dropped_closes_its_write_end_once() {
        use std::os::fd::AsRawFd;
        let g = Generation::new().unwrap();
        let n = g.notice.borrow().as_ref().unwrap().as_raw_fd();
        // SAFETY: `fork` has no memory precondition. The child is alone in its
        // process, so no other thread takes `n` once it is closed, and it makes
        // only async-signal-safe calls (`close`, `open`, `dup2`, `fcntl`,
        // `_exit`), as POSIX requires of the child of a threaded process.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            g.enter();
            // SAFETY: `open` takes a NUL-terminated path; `dup2` and `fcntl`
            // take descriptor numbers and fail on a bad one; `_exit` ends the
            // child without running the parent's destructors again.
            unsafe {
                let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
                libc::dup2(null, n);
                drop(g);
                libc::_exit(i32::from(libc::fcntl(n, libc::F_GETFD) == -1));
            }
        }
        assert!(pid > 0, "fork: {}", io::Error::last_os_error());
        drop(g);
        let mut status = 0;
        // SAFETY: waits for the child forked above, into a local.
        let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(reaped, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "dropping the generation closed descriptor {n} a second time"
        );
    }

    /// A signal that lands while the supervisor is awake (reaping, reloading)
    /// still cuts its next nap short, so a crashed worker is replaced and a
    /// `RELOAD` served at once rather than a tick later. SIGUSR2 stands in for
    /// SIGCHLD so the children other tests spawn do not reach the handler.
    #[test]
    fn a_signal_before_the_nap_ends_it() {
        arm_wakeup().unwrap();
        // SAFETY: `on_sigchld` is async-signal-safe, as its doc says.
        unsafe { install_handler(libc::SIGUSR2, on_sigchld) };
        // SAFETY: raises a signal on this thread; its handler only wakes.
        unsafe {
            libc::raise(libc::SIGUSR2);
        }
        let start = std::time::Instant::now();
        nap(SUPERVISOR_TICK);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "slept {:?} after the signal",
            start.elapsed()
        );
    }

    /// The ceiling is the one on this process's own cgroup and its ancestors,
    /// not whatever sits at the mount root.
    #[test]
    fn the_cgroup_limit_is_read_where_the_process_lives() {
        let files: std::collections::HashMap<&str, &str> = [
            ("/sys/fs/cgroup/memory.max", "max\n"),
            ("/sys/fs/cgroup/system.slice/memory.max", "8589934592\n"),
            (
                "/sys/fs/cgroup/system.slice/exav.service/memory.max",
                "max\n",
            ),
            (
                "/sys/fs/cgroup/memory/memory.limit_in_bytes",
                "9223372036854771712\n",
            ),
            (
                "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes",
                "1073741824\n",
            ),
        ]
        .into_iter()
        .collect();
        let read = |p: &str| files.get(p).map(|s| s.to_string());

        // A service under a slice with a limit: the slice's limit applies.
        let v2 = "0::/system.slice/exav.service\n";
        assert_eq!(cgroup_limit_from(v2, read), Some(8 << 30));
        // A container with its own namespace sees itself at the root.
        assert_eq!(cgroup_limit_from("0::/\n", read), None);
        // v1, memory controller listed with others.
        let v1 = "5:cpu,cpuacct:/docker/abc\n4:memory:/docker/abc\n";
        assert_eq!(cgroup_limit_from(v1, read), Some(1 << 30));
        // A v1 path this mount does not show falls back to the mount root.
        let v1 = "4:memory:/elsewhere\n";
        assert_eq!(cgroup_limit_from(v1, read), None);
    }

    /// A file added with the very timestamps already there, as a coarse clock
    /// stamps one written within a tick of the baseline, is a change; so is a
    /// file put back with an older mtime. Nothing changed is no change.
    #[test]
    fn a_source_is_watched_by_more_than_its_newest_mtime() {
        use std::time::{Duration, SystemTime};
        let dir = crate::tmpfile::TempDir::new().unwrap();
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let file = |name: &str, body: &str, mtime: SystemTime| {
            std::fs::write(dir.path().join(name), body).unwrap();
            let f = std::fs::File::options()
                .write(true)
                .open(dir.path().join(name))
                .unwrap();
            f.set_modified(mtime).unwrap();
        };
        let pin_dir = || {
            let d = std::fs::File::open(dir.path()).unwrap();
            d.set_modified(t).unwrap();
        };
        file("test.ndb", "a", t);
        pin_dir();
        let mut watch = Watch::new(dir.path().to_path_buf());
        assert!(!watch.changed());

        file("more.ndb", "b", t);
        pin_dir();
        assert!(watch.changed(), "a file added with the same timestamps");
        assert!(!watch.changed());

        file("more.ndb", "b", t - Duration::from_secs(60));
        assert!(watch.changed(), "an older mtime");
        assert!(!watch.changed());

        // Swapped in by a rename: the same name, size and timestamps, another
        // file. In a directory, and as a single database file.
        file("swap.tmp", "c", t - Duration::from_secs(60));
        std::fs::rename(dir.path().join("swap.tmp"), dir.path().join("more.ndb")).unwrap();
        pin_dir();
        assert!(watch.changed(), "a file swapped in by a rename");
        let db = dir.path().join("more.ndb");
        let mut watch = Watch::new(db.clone());
        file("swap.tmp", "d", t - Duration::from_secs(60));
        std::fs::rename(dir.path().join("swap.tmp"), &db).unwrap();
        assert!(watch.changed(), "a database file swapped in by a rename");
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
        serve_allow_http_scan(false)
    }

    /// Spawn a handler as [`serve`], with `SCANURL` fetching honoured or not.
    fn serve_allow_http_scan(allow_http_scan: bool) -> UnixStream {
        let (client, server) = UnixStream::pair().unwrap();
        let db = Scanner::builtin();
        let opts = ScanOptions::default();
        std::thread::spawn(move || {
            let reader = AncillaryReader::new(&server);
            let _ = handle_conn(
                reader,
                &server,
                &db,
                &opts,
                &|| {},
                &|| {},
                &|| {},
                &|| false,
                allow_http_scan,
                Reads::with_command(None),
            );
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
        one_allow_http_scan(send, delim, false)
    }

    /// One command on a fresh connection as [`one`], with `SCANURL` honoured
    /// or refused.
    fn one_allow_http_scan(send: &[u8], delim: u8, allow_http_scan: bool) -> String {
        let mut w = serve_allow_http_scan(allow_http_scan);
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
            let _ = handle_conn(
                reader,
                &server,
                &db,
                &opts,
                &|| {},
                &|| {},
                &|| {},
                &|| false,
                false,
                Reads::with_command(None),
            );
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
            let _ = handle_conn(
                reader,
                &server,
                &db,
                &opts,
                &|| {},
                &|| {},
                &|| {},
                &|| false,
                false,
                Reads::with_command(None),
            );
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
    // each level, which is what exercises the nested-location chain.
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
        // INSTREAM must detect malware INSIDE an archive, as clamd does; a
        // flat-only scan of the stream is not enough. EICAR is DEFLATE-compressed inside
        // the zip, so a flat scan of the raw stream can't see it: extraction is
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

    /// A ZIP of `(name, method, bytes)` members, each holding its bytes as
    /// given, central directory included.
    fn zip_members(members: &[(&str, u16, &[u8])]) -> Vec<u8> {
        let crc = |data: &[u8]| {
            let mut c = !0u32;
            for &b in data {
                c ^= u32::from(b);
                for _ in 0..8 {
                    c = if c & 1 != 0 {
                        (c >> 1) ^ 0xEDB8_8320
                    } else {
                        c >> 1
                    };
                }
            }
            !c
        };
        let (mut out, mut cd) = (Vec::new(), Vec::new());
        for (name, method, data) in members {
            let fields = |v: &mut Vec<u8>| {
                v.extend_from_slice(&[20, 0, 0, 0]); // version needed, flags
                v.extend_from_slice(&method.to_le_bytes());
                v.extend_from_slice(&[0; 4]); // time, date
                v.extend_from_slice(&crc(data).to_le_bytes());
                v.extend_from_slice(&(data.len() as u32).to_le_bytes());
                v.extend_from_slice(&(data.len() as u32).to_le_bytes());
                v.extend_from_slice(&(name.len() as u16).to_le_bytes());
                v.extend_from_slice(&[0, 0]); // extra length
            };
            cd.extend_from_slice(b"PK\x01\x02\x14\x00");
            fields(&mut cd);
            cd.extend_from_slice(&[0; 10]); // comment length, disk, attributes
            cd.extend_from_slice(&(out.len() as u32).to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b"PK\x03\x04");
            fields(&mut out);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
        }
        let n = (members.len() as u16).to_le_bytes();
        let cd_at = (out.len() as u32).to_le_bytes();
        let cd_len = (cd.len() as u32).to_le_bytes();
        out.extend_from_slice(&cd);
        out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        out.extend_from_slice(&[n[0], n[1], n[0], n[1]]);
        out.extend_from_slice(&cd_len);
        out.extend_from_slice(&cd_at);
        out.extend_from_slice(&[0, 0]);
        out
    }

    /// A split ZIP whose first part alone is `PARTIAL`: it holds a member in
    /// WavPack (method 97), which exav does not decode. The second member is
    /// EICAR, stored, cut through by the split, so no part alone is found.
    fn split_set_partial_alone() -> Vec<(String, Vec<u8>)> {
        let blob = zip_members(&[("a.bin", 97, &[0x5a; 64]), ("e.txt", 0, eicar())]);
        let parts = split_set("mixed", &blob, 2);
        let at = blob
            .windows(eicar().len())
            .position(|w| w == eicar())
            .unwrap();
        assert!(at < parts[0].1.len() && at + eicar().len() > parts[0].1.len());
        parts
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
        // The reason the verb exists. Each part on its own is clean (asserted
        // below), so three separate EXINSTREAM calls would all reply `OK` and
        // the archive's content would never be reported.
        let parts = split_set("payload", ZIP_EICAR_INSIDE, 3);
        for (name, part) in &parts {
            let solo = one(&exinstream_msg(part), 0);
            assert!(
                solo.contains(r#""status":"OK""#),
                "{name} is not clean alone, so the fixture proves nothing: {solo}"
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
    fn exinstream_multi_reports_a_found_set_on_a_part_partial_alone() {
        // A part's own `PARTIAL` is about the part; the archive it belongs to
        // is infected, and that is what the part has to report.
        let parts = split_set_partial_alone();
        let solo: Vec<_> = parts
            .iter()
            .map(|(_, p)| one(&exinstream_msg(p), 0))
            .collect();
        assert!(
            solo[0].contains(r#""status":"PARTIAL""#),
            "the first part alone: {}",
            solo[0]
        );
        assert!(
            solo.iter().all(|s| !s.contains(r#""status":"FOUND""#)),
            "{solo:?}"
        );
        let msg = exinstream_multi_msg(
            &parts
                .iter()
                .map(|(n, d)| (n.as_str(), d.as_slice()))
                .collect::<Vec<_>>(),
        );
        let r = one(&msg, 0);
        let v: serde_json::Value = serde_json::from_str(&r).unwrap_or_else(|e| panic!("{e}: {r}"));
        let files = v["files"].as_array().expect("files array");
        assert_eq!(files.len(), 2, "got {r}");
        for f in files {
            assert_eq!(f["status"], "FOUND", "every part is a piece of it: {r}");
            assert_eq!(f["set"], "mixed.zip", "named for the archive: {r}");
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
        let mut opts = ScanOptions::default();
        opts.max_scan_size = Some(8);
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
        //
        // Held for the lifetime of the payload: the spill budget is a process
        // -wide counter, and the 16 MiB charged here is what the budget test
        // would otherwise see appear inside its own measurement.
        let _budget = crate::spill::budget_guard();
        let threshold = crate::spill::config().threshold as usize;
        let mut payload = vec![b'.'; threshold + 1 - eicar().len()];
        payload.extend_from_slice(eicar());
        let expected = payload.len() as u64;

        let held = buffer_to_seekable(&mut &payload[..]).unwrap();
        assert!(held.short.is_none());
        let materialized = held.payload;
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
        let (report, _) =
            scan_payload(&db, &ScanOptions::default(), &materialized, expected).unwrap();
        assert!(
            matches!(report.verdict.category(), VerdictCategory::Infected),
            "the spilled bytes are what gets scanned"
        );
    }

    /// The socket is bound out of reach and moved to its path with its mode: it
    /// answers there with the mode asked for, in place of a stale one, and
    /// nothing is left beside it.
    #[cfg(unix)]
    #[test]
    fn a_unix_socket_is_bound_beside_its_path_and_moved_there() {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let dir = crate::tmpfile::TempDir::new().unwrap();
        let path = dir.path().join("exav.sock");
        // The socket of an earlier run, which nothing listens on any more.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let listener = bind_unix_socket(&path, 0o640).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o640);
        let _client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        listener.accept().unwrap();
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["exav.sock"]);
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
        // files. Scanned one at a time (which is all CONTSCAN did), every line
        // reads `OK`.
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
    fn contscan_reports_a_found_set_on_a_part_partial_alone() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        for (name, part) in split_set_partial_alone() {
            std::fs::write(dir.path().join(&name), &part).unwrap();
        }
        let first = dir.path().join("mixed.zip.001");
        let solo = scan_one_path(
            &Scanner::builtin(),
            &ScanOptions::default(),
            &first.to_string_lossy(),
        );
        assert!(solo.ends_with(" ERROR"), "the first part alone: {solo}");
        let lines = scan_tree(
            &Scanner::builtin(),
            &ScanOptions::default(),
            &dir.path().to_string_lossy(),
        );
        assert_eq!(lines.len(), 2, "one line per file: {lines:?}");
        for l in &lines {
            assert!(
                l.contains("FOUND") && l.contains("(in mixed.zip)"),
                "every part carries the archive's verdict: {lines:?}"
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
    fn send_with_fd(stream: &UnixStream, data: &[u8], fd: std::os::fd::BorrowedFd<'_>) {
        super::send_fd_command(stream, data, fd).unwrap();
    }

    #[test]
    fn fildes_scans_passed_descriptor() {
        use std::os::fd::AsFd;
        let dir = crate::tmpfile::TempDir::new().unwrap();
        let bad = dir.path().join("bad");
        std::fs::write(&bad, eicar()).unwrap();
        let f = std::fs::File::open(&bad).unwrap();

        let mut w = serve();
        let mut r = BufReader::new(w.try_clone().unwrap());
        send_with_fd(&w, b"zFILDES\0", f.as_fd());
        let mut buf = Vec::new();
        r.read_until(0, &mut buf).unwrap();
        let reply = String::from_utf8_lossy(&buf);
        assert!(reply.contains("FOUND"), "got {reply}");
        let _ = w.write(b""); // keep w alive until reply read
    }

    /// A verb is listed when it works and not when it is refused, so a client
    /// that reads the list does not send a command that cannot do anything.
    #[test]
    fn versioncommands_lists_shutdown_only_when_it_is_honoured() {
        assert!(!versioncommands("v", false, false).contains("SHUTDOWN"));
        assert!(!versioncommands("v", false, false).contains("QUIT"));
        assert!(versioncommands("v", true, false).contains(" SHUTDOWN QUIT "));
        assert!(!versioncommands("v", false, false).contains("SCANURL"));
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
    fn scanurl_refused_by_default() {
        // The default handler refuses SCANURL without fetching: without the
        // feature it needs a build with it, with the feature it needs
        // --allow-http-scan on the daemon. Either way nothing is fetched.
        let r = one(b"zSCANURL http://127.0.0.1:9/x\0", 0);
        assert!(r.contains("ERROR"), "got {r}");
        #[cfg(feature = "http-scan")]
        assert!(r.contains("disabled"), "got {r}");
        #[cfg(not(feature = "http-scan"))]
        assert!(r.contains("needs a build"), "got {r}");
    }

    #[test]
    fn versioncommands_advertises_scanurl_only_when_allowed() {
        let r = one(b"zVERSIONCOMMANDS\0", 0);
        assert!(!r.contains("SCANURL"), "got {r}");
        #[cfg(feature = "http-scan")]
        {
            let r = one_allow_http_scan(b"zVERSIONCOMMANDS\0", 0, true);
            assert!(r.contains("SCANURL"), "got {r}");
        }
    }

    #[cfg(feature = "http-scan")]
    #[test]
    fn scanurl_allowed_attempts_fetch() {
        // Allowed: the daemon tries to fetch rather than refusing. A closed
        // loopback port fails fast with a fetch ERROR; the point is the
        // request got past the gate, not that it downloaded anything.
        let r = one_allow_http_scan(b"zSCANURL http://127.0.0.1:9/x\0", 0, true);
        assert!(r.contains("ERROR") && !r.contains("disabled"), "got {r}");
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

    /// A file ALLMATCHSCAN could not fully examine is answered in the same
    /// words as SCAN, ending in `ERROR`: a bare category is a word clamd
    /// clients read as `OK`.
    #[test]
    fn allmatchscan_ends_a_partial_in_error() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        let damaged = dir.path().join("damaged.gz");
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        gz.extend_from_slice(&[0xff; 64]);
        std::fs::write(&damaged, gz).unwrap();
        let path = damaged.to_string_lossy();
        let db = Scanner::builtin();
        let lines = scan_one_allmatch(&db, &ScanOptions::default(), &path);
        assert_eq!(
            lines,
            [scan_one_path(&db, &ScanOptions::default(), &path)],
            "ALLMATCHSCAN and SCAN disagree"
        );
        assert!(lines[0].ends_with(" UNSCANNABLE ERROR"), "{lines:?}");
    }

    #[test]
    fn shutdown_disabled_reports_error_and_does_not_exit() {
        // With the hook returning false (disabled), SHUTDOWN must reply an ERROR
        // rather than silently succeeding, and obviously not kill the test.
        let (mut client, server) = UnixStream::pair().unwrap();
        let db = Scanner::builtin();
        let opts = ScanOptions::default();
        std::thread::spawn(move || {
            let reader = AncillaryReader::new(&server);
            let _ = handle_conn(
                reader,
                &server,
                &db,
                &opts,
                &|| {},
                &|| {},
                &|| {},
                &|| false,
                false,
                Reads::with_command(None),
            );
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
                false,
                Reads::with_command(None),
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
                false,
                Reads::with_command(None),
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

    /// [`serve`], with `command_read` as the most time one command may take.
    fn serve_within(command_read: Option<Duration>) -> UnixStream {
        let (client, server) = UnixStream::pair().unwrap();
        let db = Scanner::builtin();
        let opts = ScanOptions::default();
        std::thread::spawn(move || {
            let reader = AncillaryReader::new(&server);
            let _ = handle_conn(
                reader,
                &server,
                &db,
                &opts,
                &|| {},
                &|| {},
                &|| {},
                &|| false,
                false,
                Reads::with_command(command_read),
            );
        });
        client
    }

    /// A client that sends nothing is let go once one read has waited the
    /// address's `idle-secs`.
    #[test]
    fn a_client_that_sends_nothing_is_let_go_after_the_idle_wait() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (db, opts) = (Scanner::builtin(), ScanOptions::default());
        let reads = Reads {
            idle: Duration::from_millis(300),
            ..Reads::with_command(None)
        };
        let start = std::time::Instant::now();
        std::thread::spawn(move || {
            let reader = AncillaryReader::new(&server);
            let _ = handle_conn(
                reader,
                &server,
                &db,
                &opts,
                &|| {},
                &|| {},
                &|| {},
                &|| false,
                false,
                reads,
            );
        });
        assert_eq!(read_to_close(&mut client), "");
        let waited = start.elapsed();
        assert!(
            waited >= Duration::from_millis(250) && waited < Duration::from_secs(10),
            "{waited:?}"
        );
    }

    /// What the daemon sends until it closes the connection or resets it. A
    /// daemon that never does leaves the test with what it got in 20 seconds,
    /// not hanging.
    fn read_to_close(client: &mut UnixStream) -> String {
        client
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        while let Ok(n) = client.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Sends `bytes` one at a time, `gap` apart, from a thread of its own so
    /// that the caller can read the reply meanwhile. The thread ends when the
    /// daemon closes the connection.
    fn drip(client: &UnixStream, bytes: Vec<u8>, gap: Duration) -> std::thread::JoinHandle<()> {
        let mut w = client.try_clone().unwrap();
        std::thread::spawn(move || {
            for b in bytes {
                if w.write_all(&[b]).is_err() {
                    return;
                }
                std::thread::sleep(gap);
            }
        })
    }

    /// The chunk header of an `INSTREAM` that promises 1000 bytes.
    fn chunk_header() -> Vec<u8> {
        1000u32.to_be_bytes().to_vec()
    }

    const TIMED_OUT: &str = "COMMAND READ TIMED OUT\n";

    #[test]
    fn a_command_line_sent_a_byte_at_a_time_is_cut_off() {
        let mut client = serve_within(Some(Duration::from_millis(300)));
        let sender = drip(&client, b"zINSTREAM\0".to_vec(), Duration::from_millis(50));
        assert_eq!(read_to_close(&mut client), TIMED_OUT);
        sender.join().unwrap();
    }

    #[test]
    fn a_stream_sent_a_byte_at_a_time_is_cut_off() {
        let mut client = serve_within(Some(Duration::from_millis(300)));
        client.write_all(b"zINSTREAM\0").unwrap();
        let mut data = chunk_header();
        data.extend_from_slice(&[b'a'; 100]);
        let sender = drip(&client, data, Duration::from_millis(50));
        assert_eq!(read_to_close(&mut client), TIMED_OUT);
        sender.join().unwrap();
    }

    #[test]
    fn an_exinstream_sent_a_byte_at_a_time_is_answered_with_an_error() {
        let mut client = serve_within(Some(Duration::from_millis(300)));
        client.write_all(b"zEXINSTREAM\0").unwrap();
        let mut data = chunk_header();
        data.extend_from_slice(&[b'a'; 100]);
        let sender = drip(&client, data, Duration::from_millis(50));
        let reply = read_to_close(&mut client);
        assert!(
            reply.contains("\"status\":\"ERROR\"") && reply.contains("took longer"),
            "{reply}"
        );
        sender.join().unwrap();
    }

    /// The same slow client, with no limit and with a long one, is served: the
    /// cut-off above is the limit's doing, not the transport's.
    #[test]
    fn the_same_slow_stream_is_scanned_without_a_limit_or_within_one() {
        for limit in [None, Some(Duration::from_secs(60))] {
            let mut client = serve_within(limit);
            client.write_all(b"zINSTREAM\0").unwrap();
            let mut data = 10u32.to_be_bytes().to_vec();
            data.extend_from_slice(&[b'a'; 10]);
            data.extend_from_slice(&0u32.to_be_bytes());
            let sender = drip(&client, data, Duration::from_millis(20));
            assert_eq!(read_to_close(&mut client), "stream: OK\0", "{limit:?}");
            sender.join().unwrap();
        }
    }

    /// A session's commands each have their own time, from their first byte:
    /// the wait between them is the socket's timeout, not the command's.
    #[test]
    fn each_command_of_a_session_has_its_own_time() {
        let mut client = serve_within(Some(Duration::from_millis(300)));
        client
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut r = BufReader::new(client.try_clone().unwrap());
        let mut reply = || {
            let mut buf = Vec::new();
            r.read_until(0, &mut buf).unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        };
        // The first command is in hand with the one that opens the session.
        client.write_all(b"zIDSESSION\0zPING\0").unwrap();
        assert_eq!(reply(), "1: PONG\0");
        std::thread::sleep(Duration::from_millis(600));
        client.write_all(b"zPING\0").unwrap();
        assert_eq!(reply(), "2: PONG\0");
        client.write_all(b"zEND\0").unwrap();
    }

    #[test]
    fn the_wait_for_a_commands_first_byte_is_not_charged_to_it() {
        let mut client = serve_within(Some(Duration::from_millis(300)));
        std::thread::sleep(Duration::from_millis(600));
        // In two pieces, so that a second read is made after the wait.
        client.write_all(b"z").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        client.write_all(b"PING\0").unwrap();
        assert_eq!(read_to_close(&mut client), "PONG\0");
    }

    /// A transport that gives its script's reads in turn and records the wait
    /// it was set to before each.
    struct Scripted {
        reads: std::collections::VecDeque<io::Result<Vec<u8>>>,
        waits: std::cell::RefCell<Vec<Duration>>,
    }

    impl Scripted {
        fn new(reads: Vec<io::Result<Vec<u8>>>) -> Self {
            Self {
                reads: reads.into(),
                waits: Default::default(),
            }
        }
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.reads.pop_front() {
                Some(Ok(v)) => {
                    buf[..v.len()].copy_from_slice(&v);
                    Ok(v.len())
                }
                Some(Err(e)) => Err(e),
                None => Ok(0),
            }
        }
    }

    impl SetReadTimeout for Scripted {
        fn set_read_timeout(&self, wait: Duration) -> io::Result<()> {
            self.waits.borrow_mut().push(wait);
            Ok(())
        }
    }

    impl FdSource for Scripted {
        fn take_fd(&mut self) -> Option<std::fs::File> {
            None
        }
    }

    /// A client's bytes, made as they are read, and how many were read.
    struct Sent<R> {
        inner: R,
        read: std::rc::Rc<std::cell::Cell<u64>>,
    }

    impl<R: Read> Read for Sent<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.read.set(self.read.get() + n as u64);
            Ok(n)
        }
    }

    impl<R> SetReadTimeout for Sent<R> {
        fn set_read_timeout(&self, _wait: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    impl<R> FdSource for Sent<R> {
        fn take_fd(&mut self) -> Option<std::fs::File> {
            None
        }
    }

    /// A stream longer than the drain reads past the limit, or a request
    /// answered before its end, is answered, and the session ends there: the
    /// rest of it is not read as commands.
    #[test]
    fn a_session_ends_after_a_stream_left_unread() {
        let hold = 1024u64;
        let mut opts = ScanOptions::default();
        opts.max_scan_size = Some(hold);
        let stream = hold + MAX_DRAIN_BYTES;
        let name = u64::from(MAX_STREAM_NAME) + 1;
        for (verb, before, len, first) in [
            (&b"INSTREAM"[..], &b""[..], stream, "1: stream: "),
            (b"EXINSTREAM", b"", stream, "1: {"),
            // A name too long, or a file's stream.
            (b"EXINSTREAM MULTI", b"", name, "1: {"),
            (b"EXINSTREAM MULTI", b"\0\0\0\x01a", stream, "1: {"),
        ] {
            let len = len + 1024 * 1024;
            let mut head = [b"zIDSESSION\0z", verb, b"\0", before].concat();
            head.extend_from_slice(&u32::try_from(len).unwrap().to_be_bytes());
            let all = head.len() as u64 + len + 4;
            let read = std::rc::Rc::new(std::cell::Cell::new(0));
            let sent = Sent {
                inner: io::Cursor::new(head)
                    .chain(io::repeat(0).take(len))
                    .chain(io::Cursor::new(vec![0; 4])),
                read: read.clone(),
            };
            let mut out = Vec::new();
            let r = handle_conn(
                sent,
                &mut out,
                &Scanner::builtin(),
                &opts,
                &|| {},
                &|| {},
                &|| {},
                &|| false,
                false,
                Reads::with_command(None),
            );
            let out = String::from_utf8_lossy(&out);
            let shown: String = out.chars().take(200).collect();
            let verb = String::from_utf8_lossy(verb);
            assert!(r.is_ok(), "{verb}: {r:?}: {shown:?}");
            assert!(
                out.starts_with(first) && out.matches('\0').count() == 1,
                "{verb}: {shown:?}"
            );
            assert!(read.get() < all, "{verb}: the request was read to its end");
        }
    }

    const SOCKET_WAIT: Duration = Duration::from_secs(60);

    fn would_block() -> io::Error {
        io::ErrorKind::WouldBlock.into()
    }

    /// Once a command has begun, a read waits no longer than what is left of
    /// its time: a read already blocked is what would overshoot it.
    #[test]
    fn a_read_waits_no_longer_than_the_command_has_left() {
        let clock = ReadClock::new(Some(Duration::from_secs(10)), SOCKET_WAIT);
        let mut r = Clocked::new(
            Scripted::new(vec![Ok(b"x".to_vec()), Ok(b"y".to_vec())]),
            &clock,
        );
        let mut b = [0u8; 8];
        assert_eq!(r.read(&mut b).unwrap(), 1);
        assert_eq!(r.read(&mut b).unwrap(), 1);
        let waits = r.get_ref().waits.borrow().clone();
        assert_eq!(waits[0], SOCKET_WAIT, "before the first byte: the socket's");
        assert!(waits[1] <= Duration::from_secs(10), "{waits:?}");
    }

    /// A timeout on the shortened wait is the command's; one on the socket's
    /// own is not, and keeps its kind.
    #[test]
    fn only_a_timeout_on_the_commands_wait_is_the_commands() {
        let mut b = [0u8; 8];
        let clock = ReadClock::new(Some(Duration::from_secs(10)), SOCKET_WAIT);
        let mut r = Clocked::new(
            Scripted::new(vec![Ok(b"x".to_vec()), Err(would_block())]),
            &clock,
        );
        assert_eq!(r.read(&mut b).unwrap(), 1);
        let e = r.read(&mut b).unwrap_err();
        assert!(is_too_slow(&e) && clock.fired(), "{e}");

        let clock = ReadClock::new(Some(Duration::from_secs(1000)), SOCKET_WAIT);
        let mut r = Clocked::new(
            Scripted::new(vec![Ok(b"x".to_vec()), Err(would_block())]),
            &clock,
        );
        assert_eq!(r.read(&mut b).unwrap(), 1);
        let e = r.read(&mut b).unwrap_err();
        assert!(!is_too_slow(&e) && !clock.fired(), "{e}");
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn a_read_past_the_commands_time_does_not_reach_the_transport() {
        let clock = ReadClock::new(Some(Duration::from_millis(1)), SOCKET_WAIT);
        clock.restart(true);
        std::thread::sleep(Duration::from_millis(5));
        let mut r = Clocked::new(Scripted::new(vec![Ok(b"x".to_vec())]), &clock);
        let e = r.read(&mut [0u8; 8]).unwrap_err();
        assert!(is_too_slow(&e) && clock.fired(), "{e}");
        assert_eq!(r.get_ref().reads.len(), 1, "the transport was read");
        // The next command starts afresh.
        clock.restart(false);
        assert_eq!(r.read(&mut [0u8; 8]).unwrap(), 1);
    }

    #[test]
    fn without_a_limit_the_sockets_timeout_is_left_alone() {
        let clock = ReadClock::new(None, SOCKET_WAIT);
        let mut r = Clocked::new(Scripted::new(vec![Ok(b"x".to_vec())]), &clock);
        assert_eq!(r.read(&mut [0u8; 8]).unwrap(), 1);
        assert!(r.get_ref().waits.borrow().is_empty());
    }

    /// A limit no clock can add to an instant is no limit, not a panic.
    #[test]
    fn a_limit_past_the_range_of_a_clock_is_no_limit() {
        let clock = ReadClock::new(Some(Duration::MAX), SOCKET_WAIT);
        clock.restart(true);
        let mut r = Clocked::new(
            Scripted::new(vec![Ok(b"x".to_vec()), Ok(b"y".to_vec())]),
            &clock,
        );
        assert_eq!(r.read(&mut [0u8; 8]).unwrap(), 1);
        assert_eq!(r.read(&mut [0u8; 8]).unwrap(), 1);
        assert!(!clock.fired());
    }

    /// The server's own time inside a command, a preview scan say, is not the
    /// client's: the command's end moves by as much as the work took.
    #[test]
    fn work_the_server_does_inside_a_command_is_not_charged_to_it() {
        let clock = ReadClock::new(Some(Duration::from_secs(10)), SOCKET_WAIT);
        clock.restart(true);
        let before = clock.end.get().unwrap();
        clock.excluding(|| std::thread::sleep(Duration::from_millis(50)));
        let after = clock.end.get().unwrap();
        assert!(after - before >= Duration::from_millis(50));
    }

    /// A command that ran out of time is a limit the operator should see in
    /// the log; the socket's own timeout is an idle client going away.
    #[test]
    fn a_command_out_of_time_is_not_a_quiet_disconnect() {
        let slow = io::Error::new(io::ErrorKind::TimedOut, CommandTooSlow);
        assert!(!is_benign_disconnect(&slow));
        assert!(is_benign_disconnect(&io::ErrorKind::TimedOut.into()));
    }

    #[test]
    fn the_limit_is_the_default_unless_given_and_off_is_none() {
        assert_eq!(command_read_limit(None), Some(DEFAULT_COMMAND_READ));
        assert_eq!(command_read_limit(Some(0)), None);
        assert_eq!(command_read_limit(Some(7)), Some(Duration::from_secs(7)));
    }

    /// The error a socket gives a write that waited out its timeout is the one
    /// an idle client's read gives. Only the writer knows which it is.
    #[test]
    fn a_write_that_times_out_names_the_client_that_is_not_reading() {
        struct Fails(io::ErrorKind);
        impl Write for Fails {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(self.0.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(self.0.into())
            }
        }
        impl SetWriteTimeout for Fails {
            fn write_wait(&self) -> io::Result<Option<Duration>> {
                Ok(None)
            }
            fn set_write_wait(&self, _: Option<Duration>) -> io::Result<()> {
                Ok(())
            }
        }
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut] {
            let mut w = Replies::new(Fails(kind), None).unwrap();
            let e = w.write_all(b"PONG").unwrap_err();
            assert!(is_not_reading(&e), "{kind:?}: {e}");
            let e = w.flush().unwrap_err();
            assert!(is_not_reading(&e), "flush, {kind:?}: {e}");
            assert!(!is_benign_disconnect(&e), "it is logged");
        }
        // A client that went away is the quiet case it always was.
        let e = Replies::new(Fails(io::ErrorKind::BrokenPipe), None)
            .unwrap()
            .write_all(b"PONG")
            .unwrap_err();
        assert!(!is_not_reading(&e) && is_benign_disconnect(&e), "{e}");
    }

    /// A client that sends commands and never reads the replies fills the
    /// socket, and the connection is ended by the write timeout instead of
    /// holding its thread for as long as the client keeps the socket open.
    #[test]
    fn a_client_that_never_reads_is_cut_by_the_write_timeout() {
        let (client, server) = UnixStream::pair().unwrap();
        server
            .set_write_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let db = Scanner::builtin();
            let opts = ScanOptions::default();
            let r = handle_conn(
                AncillaryReader::new(&server),
                &server,
                &db,
                &opts,
                &|| {},
                &|| {},
                &|| {},
                &|| false,
                false,
                Reads::with_command(None),
            );
            let _ = done.send(r);
        });
        let mut w = client.try_clone().unwrap();
        let sender = std::thread::spawn(move || {
            if w.write_all(b"zIDSESSION\0").is_err() {
                return;
            }
            // Far more replies than a socket holds, none of them read.
            let burst = b"zVERSIONCOMMANDS\0".repeat(1000);
            for _ in 0..200 {
                if w.write_all(&burst).is_err() {
                    return;
                }
            }
        });
        let r = result
            .recv_timeout(Duration::from_secs(30))
            .expect("the connection was never ended");
        let e = r.expect_err("a client that does not read is an error");
        assert!(is_not_reading(&e) && !is_benign_disconnect(&e), "{e}");
        drop(client);
        sender.join().unwrap();
    }

    /// [`serve`], under `reads`.
    fn serve_with(reads: Reads) -> UnixStream {
        let (client, server) = UnixStream::pair().unwrap();
        let (db, opts) = (Scanner::builtin(), ScanOptions::default());
        std::thread::spawn(move || {
            let _ = handle_conn(
                AncillaryReader::new(&server),
                &server,
                &db,
                &opts,
                &|| {},
                &|| {},
                &|| {},
                &|| false,
                false,
                reads,
            );
        });
        client
    }

    fn lasting(session: Duration) -> Reads {
        Reads {
            session: Some(session),
            ..Reads::with_command(None)
        }
    }

    /// A client that talks all the time is answered while the connection has
    /// lifetime left, and not after: the wait for its next command is what the
    /// lifetime cuts.
    #[test]
    fn a_session_client_is_answered_until_the_connection_reaches_its_lifetime() {
        let mut client = serve_with(lasting(Duration::from_secs(1)));
        client
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let start = Instant::now();
        client.write_all(b"zIDSESSION\0").unwrap();
        let mut replies = BufReader::new(client.try_clone().unwrap());
        let mut answered = 0;
        let ended = loop {
            if start.elapsed() > Duration::from_secs(8) {
                break false;
            }
            if client.write_all(b"zPING\0").is_err() {
                break true;
            }
            let mut reply = Vec::new();
            match replies.read_until(0, &mut reply) {
                Ok(n) if n > 0 => {
                    assert!(reply.ends_with(b": PONG\0"), "{reply:?}");
                    answered += 1;
                }
                _ => break true,
            }
            std::thread::sleep(Duration::from_millis(300));
        };
        let lived = start.elapsed();
        assert!(ended, "still answering after {lived:?}");
        assert!(answered >= 1, "never answered");
        assert!(lived >= Duration::from_millis(900), "{lived:?}");
        assert!(lived < Duration::from_secs(6), "{lived:?}");
    }

    /// A client that sends nothing is let go at the lifetime, not at the idle
    /// wait.
    #[test]
    fn a_silent_client_is_let_go_at_the_lifetime() {
        let mut client = serve_with(lasting(Duration::from_secs(1)));
        let start = Instant::now();
        assert_eq!(read_to_close(&mut client), "");
        let waited = start.elapsed();
        assert!(
            waited >= Duration::from_millis(900) && waited < Duration::from_secs(10),
            "{waited:?}"
        );
    }

    /// A command whose first byte arrived before the lifetime ended is read
    /// to its end, however long that takes, and answered; the next one is not
    /// read.
    #[test]
    fn a_command_begun_before_the_lifetime_ended_is_answered() {
        let mut client = serve_with(lasting(Duration::from_secs(1)));
        let start = Instant::now();
        client.write_all(b"zIDSESSION\0").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        client.write_all(b"z").unwrap();
        std::thread::sleep(Duration::from_millis(1200));
        client.write_all(b"PING\0zPING\0").unwrap();
        assert_eq!(read_to_close(&mut client), "1: PONG\0");
        assert!(start.elapsed() < Duration::from_secs(10), "never closed");
    }

    /// A reply is bounded in all, not per write: a client that does not read a
    /// large reply is cut by `reply`, though the socket has no write timeout.
    #[test]
    fn a_reply_the_client_does_not_read_is_cut_by_the_reply_budget() {
        let dir = crate::tmpfile::TempDir::new().unwrap();
        for i in 0..8000 {
            let name = format!("{i:04}-{}", "x".repeat(120));
            std::fs::write(dir.path().join(name), b"clean").unwrap();
        }
        let (client, server) = UnixStream::pair().unwrap();
        let reads = Reads {
            reply: Some(Duration::from_millis(500)),
            ..Reads::with_command(None)
        };
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (db, opts) = (Scanner::builtin(), ScanOptions::default());
            let r = handle_conn(
                AncillaryReader::new(&server),
                &server,
                &db,
                &opts,
                &|| {},
                &|| {},
                &|| {},
                &|| false,
                false,
                reads,
            );
            let _ = done.send(r);
        });
        let mut w = client.try_clone().unwrap();
        w.write_all(format!("zCONTSCAN {}\0", dir.path().display()).as_bytes())
            .unwrap();
        let r = result
            .recv_timeout(Duration::from_secs(30))
            .expect("the connection was never ended");
        let e = r.expect_err("a client that does not read is an error");
        assert!(is_not_reading(&e) && !is_benign_disconnect(&e), "{e}");
        drop(client);
    }

    /// A writer whose writes block for scripted times. A write whose time
    /// reaches the timeout in force waits that long and fails the way a socket
    /// does.
    struct Blocking {
        /// How long each write blocks, in order; none left means no time.
        blocks: std::cell::RefCell<std::collections::VecDeque<Duration>>,
        /// The write timeout in force.
        wait: Cell<Option<Duration>>,
        /// The write timeout in force at each write.
        given: std::cell::RefCell<Vec<Option<Duration>>>,
        /// Times the timeout was changed.
        sets: Cell<usize>,
    }

    impl Blocking {
        fn new(wait: Option<Duration>, blocks: &[u64]) -> Self {
            Self {
                blocks: std::cell::RefCell::new(
                    blocks.iter().map(|ms| Duration::from_millis(*ms)).collect(),
                ),
                wait: Cell::new(wait),
                given: Default::default(),
                sets: Cell::new(0),
            }
        }
    }

    impl Write for &Blocking {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.given.borrow_mut().push(self.wait.get());
            let block = self.blocks.borrow_mut().pop_front().unwrap_or_default();
            match self.wait.get() {
                Some(wait) if block >= wait => {
                    std::thread::sleep(wait);
                    Err(io::ErrorKind::WouldBlock.into())
                }
                _ => {
                    std::thread::sleep(block);
                    Ok(buf.len())
                }
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SetWriteTimeout for &Blocking {
        fn write_wait(&self) -> io::Result<Option<Duration>> {
            Ok(self.wait.get())
        }
        fn set_write_wait(&self, wait: Option<Duration>) -> io::Result<()> {
            self.sets.set(self.sets.get() + 1);
            self.wait.set(wait);
            Ok(())
        }
    }

    /// Each write is given what is left of the budget, or the socket's own
    /// timeout when that is shorter, so the waits of one reply add up to at
    /// most the budget.
    #[test]
    fn each_write_of_a_reply_gets_what_is_left_of_its_budget() {
        let budget = Duration::from_millis(600);
        let sock = Blocking::new(Some(Duration::from_secs(5)), &[150, 150, 150]);
        let mut w = Replies::new(&sock, Some(budget)).unwrap();
        for _ in 0..3 {
            w.write_all(b"x").unwrap();
        }
        let given = sock.given.borrow().clone();
        assert_eq!(given[0], Some(budget), "the whole budget at first");
        // Each earlier write blocked for at least its 150 ms.
        assert!(
            given[1] <= Some(budget - Duration::from_millis(150)),
            "{given:?}"
        );
        assert!(
            given[2] <= Some(budget - Duration::from_millis(300)),
            "{given:?}"
        );

        // The socket's own timeout, when it is the shorter.
        let sock = Blocking::new(Some(Duration::from_millis(200)), &[]);
        let mut w = Replies::new(&sock, Some(Duration::from_secs(10))).unwrap();
        w.write_all(b"x").unwrap();
        assert_eq!(sock.given.borrow()[0], Some(Duration::from_millis(200)));

        // And with none, the budget alone.
        let sock = Blocking::new(None, &[]);
        let mut w = Replies::new(&sock, Some(budget)).unwrap();
        w.write_all(b"x").unwrap();
        assert_eq!(sock.given.borrow()[0], Some(budget));
    }

    /// Past the budget a write fails as a client that is not reading, whether
    /// it ran out of time inside the write or finds none left, and the
    /// transport is not written to again.
    #[test]
    fn a_write_past_the_reply_budget_fails_as_a_client_not_reading() {
        let sock = Blocking::new(Some(Duration::from_secs(5)), &[200, 200]);
        let mut w = Replies::new(&sock, Some(Duration::from_millis(300))).unwrap();
        w.write_all(b"x").unwrap();
        // 100 ms are left and the write would block for 200.
        let e = w.write_all(b"x").unwrap_err();
        assert!(is_not_reading(&e) && !is_benign_disconnect(&e), "{e}");
        let e = w.write_all(b"x").unwrap_err();
        assert!(is_not_reading(&e), "{e}");
        assert_eq!(sock.given.borrow().len(), 2, "written to with no time left");
    }

    /// Only the time a write is blocked counts: the server's time between two
    /// writes does not, and the next reply has the whole budget again.
    #[test]
    fn only_time_blocked_in_a_write_is_charged_to_the_reply() {
        let budget = Duration::from_secs(1);
        let sock = Blocking::new(Some(Duration::from_secs(5)), &[20, 20, 20, 20]);
        let mut w = Replies::new(&sock, Some(budget)).unwrap();
        for _ in 0..4 {
            w.write_all(b"x").unwrap();
            // Four times what the reply may wait, in all.
            std::thread::sleep(Duration::from_millis(300));
        }
        let given = sock.given.borrow().clone();
        assert!(given[3] > Some(Duration::from_millis(500)), "{given:?}");

        let sock = Blocking::new(Some(Duration::from_secs(5)), &[400, 400]);
        let mut w = Replies::new(&sock, Some(Duration::from_millis(600))).unwrap();
        w.write_all(b"x").unwrap();
        w.start_reply();
        w.write_all(b"x").unwrap();
        assert_eq!(sock.given.borrow()[1], Some(Duration::from_millis(600)));
    }

    /// Each command of a session has its reply's whole budget: two replies
    /// whose writes each wait about two thirds of it are both written.
    #[test]
    fn each_command_of_a_session_starts_a_reply() {
        let reader = Scripted::new(vec![Ok(b"zIDSESSION\0zPING\0zPING\0".to_vec())]);
        // `1: PONG\0` goes out in a few writes, of 100 ms each.
        let sock = Blocking::new(Some(Duration::from_secs(5)), &[100; 16]);
        let reads = Reads {
            reply: Some(Duration::from_millis(600)),
            ..Reads::with_command(None)
        };
        let (db, opts) = (Scanner::builtin(), ScanOptions::default());
        let r = handle_conn(
            reader,
            &sock,
            &db,
            &opts,
            &|| {},
            &|| {},
            &|| {},
            &|| false,
            false,
            reads,
        );
        let writes = sock.given.borrow().len();
        assert!(r.is_ok(), "after {writes} writes: {r:?}");
        // Two replies, more than the budget's worth of writes in all.
        assert!(writes >= 7, "{writes} writes");
    }

    /// Without a budget the socket's write timeout is not touched.
    #[test]
    fn without_a_reply_budget_the_sockets_write_timeout_is_left_alone() {
        let wait = Some(Duration::from_secs(5));
        let sock = Blocking::new(wait, &[10, 10]);
        let mut w = Replies::new(&sock, None).unwrap();
        w.write_all(b"x").unwrap();
        w.start_reply();
        w.write_all(b"x").unwrap();
        assert_eq!(sock.sets.get(), 0);
        assert_eq!(sock.wait.get(), wait);
    }

    fn timed_out() -> io::Error {
        io::ErrorKind::TimedOut.into()
    }

    #[test]
    fn an_accept_error_is_transient_unless_the_listener_is_broken() {
        for transient in [
            io::Error::from_raw_os_error(libc::EMFILE),
            io::Error::from_raw_os_error(libc::ENFILE),
            io::Error::from_raw_os_error(libc::ENOBUFS),
            io::Error::from_raw_os_error(libc::ENOMEM),
            io::Error::from_raw_os_error(libc::ECONNABORTED),
            io::Error::from_raw_os_error(libc::EINTR),
            io::Error::from_raw_os_error(libc::EPROTO),
            io::Error::from_raw_os_error(libc::EPERM),
            io::Error::from_raw_os_error(libc::ENETDOWN),
            io::Error::from_raw_os_error(libc::EHOSTUNREACH),
            io::Error::from_raw_os_error(libc::EAGAIN),
            timed_out(),
        ] {
            assert!(transient_accept_error(&transient), "{transient}");
        }
        for broken in [
            io::Error::from_raw_os_error(libc::EBADF),
            io::Error::from_raw_os_error(libc::EINVAL),
            io::Error::from_raw_os_error(libc::ENOTSOCK),
            io::Error::from_raw_os_error(libc::EFAULT),
            io::Error::other("anything else"),
        ] {
            assert!(!transient_accept_error(&broken), "{broken}");
        }
    }

    #[test]
    fn a_failing_accept_waits_longer_each_time_and_starts_over_after_one_that_works() {
        let mut b = AcceptBackoff::default();
        let ms: Vec<u128> = (0..12).map(|_| b.pause().as_millis()).collect();
        assert_eq!(
            ms,
            [5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000, 1000, 1000]
        );
        b.reset();
        assert_eq!(b.pause(), Duration::from_millis(5));
    }

    /// Transient failures are retried, connections after them are served, and
    /// the first error that waiting does not mend ends the loop and is returned.
    #[test]
    fn the_accept_loop_retries_what_is_transient_and_ends_on_the_rest() {
        let mut script: Vec<io::Result<u32>> = (0..6)
            .map(|_| Err(io::Error::from_raw_os_error(libc::EMFILE)))
            .collect();
        script.extend([
            Ok(1),
            Err(io::Error::from_raw_os_error(libc::ECONNABORTED)),
            Ok(2),
            Err(io::Error::from_raw_os_error(libc::EBADF)),
            Ok(3),
        ]);
        let mut script = script.into_iter();
        // When each accept was called.
        let mut calls = Vec::new();
        let mut served = Vec::new();
        let end = accept_loop(
            || {
                calls.push(Instant::now());
                script.next().unwrap()
            },
            |n| served.push(n),
        );
        assert_eq!(served, [1, 2], "the connection after the broken listener");
        assert_eq!(end.unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert_eq!(script.len(), 1, "nothing is accepted after the end");
        let gap = |from: usize| calls[from + 1] - calls[from];
        // The sixth failure in a row waited 160 ms, so the pauses grew.
        assert!(gap(5) >= Duration::from_millis(150), "{:?}", gap(5));
        // The failure after a good accept waited 5 ms, not the 320 ms next in line.
        assert!(gap(7) < Duration::from_millis(200), "{:?}", gap(7));
    }
}
