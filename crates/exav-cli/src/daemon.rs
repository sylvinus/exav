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
//!   `RELOAD`               -> `RELOADING` (no-op; the DB is immutable)
//!   `SCAN <path>`          -> `<path>: OK` / `<path>: <sig> FOUND` / `… ERROR`
//!   `CONTSCAN <path>`      -> recurse a directory, one reply line per file
//!   `MULTISCAN <path>`     -> alias of CONTSCAN
//!   `INSTREAM`             -> scan a `<u32 len><data>…<u32 0>` chunked stream,
//!                             fed straight into the constant-memory scanner so
//!                             total size is unbounded; reply `stream: …`
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
use std::sync::Arc;

use exav_core::{scan_path, scan_stream, Database, ScanOptions, ScanReport, Verdict};
use walkdir::WalkDir;

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

/// RAII counter: decrements the live-connection count when the handler thread
/// exits (normally or via panic).
struct ConnGuard(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Run the daemon until the listener errors (e.g. the process is killed).
pub fn run(db: Database, addr: ListenAddr, opts: ScanOptions) -> io::Result<()> {
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
            eprintln!("exav: daemon listening on unix:{}", path.display());
            for stream in listener.incoming() {
                let stream = stream?;
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
                    if let Err(e) = handle_conn(reader, &stream, &db, &opts) {
                        if e.kind() != io::ErrorKind::UnexpectedEof {
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
                let stream = TcpListenerStream(stream?);
                if conns.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
                    conns.fetch_sub(1, Ordering::Relaxed);
                    continue; // at capacity — drop the connection
                }
                let (db, opts, c) = (Arc::clone(&db), Arc::clone(&opts), Arc::clone(&conns));
                std::thread::spawn(move || {
                    let _guard = ConnGuard(c);
                    if let Err(e) = handle_conn(&stream, &stream, &db, &opts) {
                        if e.kind() != io::ErrorKind::UnexpectedEof {
                            eprintln!("exav: connection error: {e}");
                        }
                    }
                });
            }
            Ok(())
        }
    }
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

fn handle_conn<R, W>(rd: R, mut writer: W, db: &Database, opts: &ScanOptions) -> io::Result<()>
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

    // IDSESSION keeps the connection open for many commands (each reply tagged
    // with its sequence id) until END. Every other command is handled once and
    // the connection is then closed — clamd's single-command-per-connection
    // semantics, which clients rely on to know the reply is complete.
    if word.eq_ignore_ascii_case("IDSESSION") {
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
            run_command(
                cmd,
                word,
                &mut reader,
                &mut writer,
                delim,
                Some(id),
                db,
                opts,
            )?;
        }
    }

    if cmd.is_empty() || word.eq_ignore_ascii_case("END") {
        return Ok(());
    }
    run_command(&cmd, &word, &mut reader, &mut writer, delim, None, db, opts)
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
) -> io::Result<()>
where
    R: Read + FdSource,
    W: Write,
{
    let replies = if word.eq_ignore_ascii_case("FILDES") {
        vec![fildes(reader, db, opts)]
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
            match exav_core::scan_seekable(db, file, size, opts) {
                Ok(report) => verdict_line("fd", &report),
                Err(e) => format!("fd: {e} ERROR"),
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
        "VERSION" => vec![format!("exav {}", env!("CARGO_PKG_VERSION"))],
        "RELOAD" => vec!["RELOADING".to_string()],
        "STATS" => vec![format!(
            "POOLS: 1\nSTATE: VALID\nKNOWN SIGNATURES: {}\nEND",
            db.signature_count()
        )],
        "SCAN" => vec![scan_one_path(db, opts, arg)],
        "CONTSCAN" | "MULTISCAN" | "ALLMATCHSCAN" => scan_tree(db, opts, arg),
        "INSTREAM" => vec![instream(db, opts, reader)?],
        "SCANURL" => vec![scan_url(db, opts, arg)],
        _ => vec![format!("UNKNOWN COMMAND {word} ERROR")],
    };
    Ok(reply)
}

fn write_reply<W: Write>(w: &mut W, id: Option<u64>, reply: &str, delim: Delim) -> io::Result<()> {
    // A multi-line reply (e.g. STATS) keeps its internal newlines; in session
    // mode every line is prefixed with the command id.
    let prefix = id.map(|n| format!("{n}: ")).unwrap_or_default();
    let body = if prefix.is_empty() {
        reply.to_string()
    } else {
        reply
            .lines()
            .map(|l| format!("{prefix}{l}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    w.write_all(body.as_bytes())?;
    w.write_all(&[delim.byte()])?;
    w.flush()
}

/// Format a scan verdict into a clamd-style reply line. A limit is surfaced as
/// `ERROR` (never `OK`) so the never-silent-skip invariant holds on the wire.
fn verdict_line(target: &str, report: &ScanReport) -> String {
    match &report.verdict {
        Verdict::Infected { signature, .. } => format!("{target}: {signature} FOUND"),
        Verdict::Clean => format!("{target}: OK"),
        Verdict::LimitsExceeded { reason } => {
            format!("{target}: LIMITS-EXCEEDED ({reason}) ERROR")
        }
    }
}

fn scan_one_path(db: &Database, opts: &ScanOptions, path: &str) -> String {
    if path.is_empty() {
        return "SCAN: missing path ERROR".to_string();
    }
    // Isolate a panic on a malicious file: report ERROR for this target rather
    // than letting it tear down the connection (or, with the per-file recursion
    // in scan_tree, the rest of the walk).
    let scanned =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan_path(db, Path::new(path), opts)));
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

/// Scan an INSTREAM chunk stream. The chunks are fed into the constant-memory
/// streaming scanner via [`Instream`], so the total size is unbounded and RAM
/// stays flat. After scanning, any unread chunks are drained so the connection
/// stays in sync for the next command.
fn instream<R: Read>(
    db: &Database,
    opts: &ScanOptions,
    reader: &mut BufReader<R>,
) -> io::Result<String> {
    let max = opts.max_scan_size;
    let mut stream = Instream::new(reader, max);
    let report = scan_stream(db, &mut stream)?;
    let over = stream.over_limit;
    stream.drain()?;
    if over {
        let max = max.unwrap_or(0);
        return Ok(format!(
            "stream: LIMITS-EXCEEDED (size exceeds {max}) ERROR"
        ));
    }
    Ok(verdict_line("stream", &report))
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
            let _ = handle_conn(reader, &server, &db, &opts);
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

    #[test]
    fn ping_and_version() {
        assert_eq!(one(b"zPING\0", 0), "PONG");
        assert!(one(b"zVERSION\0", 0).starts_with("exav"));
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
}
