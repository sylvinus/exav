//! The listener and the per-connection request loop.
//!
//! Concurrency follows the clamd daemon's thread model: one thread per
//! connection, with a hard cap on how many may be live at once. The prefork
//! worker pool the daemon can also run is not reused here — it is built on
//! `fork`, signals and `setrlimit`, none of which this module is allowed to
//! reach for, and its purpose (killing a job that will not stop) is answered on
//! this path by the in-engine budgets.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use exav_core::{scan_seekable_located, ScanOptions, Scanner};

use super::chunked::{read_chunked_body, Body, BodyEnd, BodyError, BodyOutcome};
use super::config::IcapConfig;
use super::response::{self, Decision};
use super::wire::{read_head, Entity, IcapMethod, RequestHead};
use crate::daemon::Held;

/// Supplies the signature database to scan the next request with.
///
/// Indirected rather than handed over once, so that a signature reload is
/// visible to in-flight connections — and, through the `ISTag` derived from it,
/// to every client cache downstream.
pub(super) trait Signatures: Send + Sync {
    /// The database for the request about to be scanned.
    fn scanner(&self) -> Arc<Scanner>;
}

/// A database that never changes: the forked ICAP child's (Unix only).
#[cfg(unix)]
pub(super) struct FixedDb(Arc<Scanner>);

#[cfg(unix)]
impl FixedDb {
    /// Wrap a database already shared with another server, so one load answers
    /// on every listener a process binds.
    pub(super) fn from_arc(db: Arc<Scanner>) -> Self {
        Self(db)
    }
}

#[cfg(unix)]
impl Signatures for FixedDb {
    fn scanner(&self) -> Arc<Scanner> {
        Arc::clone(&self.0)
    }
}

/// The thread model's database, which the supervisor swaps on a reload.
impl Signatures for crate::daemon::SharedDb {
    fn scanner(&self) -> Arc<Scanner> {
        self.current()
    }
}

/// A bound ICAP listener.
pub(crate) struct Server {
    listener: TcpListener,
    cfg: Arc<IcapConfig>,
}

impl Server {
    /// Bind the configured address.
    pub(super) fn bind(cfg: IcapConfig) -> std::io::Result<Self> {
        let listener = TcpListener::bind(&cfg.listen)?;
        Ok(Self {
            listener,
            cfg: Arc::new(cfg),
        })
    }

    /// The address actually bound, which is how a caller learns the port after
    /// asking for `:0`.
    pub(super) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The configuration this listener was bound with, for a caller that reports
    /// what it is serving.
    pub(super) fn config(&self) -> &IcapConfig {
        &self.cfg
    }

    /// Make accepting non-blocking, for a listener more than one process waits on.
    #[cfg(unix)]
    pub(super) fn set_nonblocking(&self) -> std::io::Result<()> {
        self.listener.set_nonblocking(true)
    }

    /// Serve until `wait` says to stop, then finish the requests in progress
    /// and return. `wait` blocks until there is a connection to accept (`true`)
    /// or the server should stop (`false`). An error means the listener failed.
    pub(super) fn run(
        &self,
        db: Arc<dyn Signatures>,
        opts: Arc<ScanOptions>,
        wait: &dyn Fn(&TcpListener) -> bool,
    ) -> std::io::Result<()> {
        let live = Arc::new(AtomicUsize::new(0));
        let idle = Arc::new(Idle::default());
        while wait(&self.listener) {
            let stream = match self.listener.accept() {
                Ok((s, _)) => s,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                // One failed accept (a client that vanished between the SYN and
                // the accept, say) is not a reason to stop serving.
                Err(e) => {
                    eprintln!("exav: icap: accept failed: {e}");
                    continue;
                }
            };
            // An accepted socket can inherit the listener's non-blocking mode.
            let _ = stream.set_nonblocking(false);
            if live.fetch_add(1, Ordering::Relaxed) >= self.cfg.max_connections {
                live.fetch_sub(1, Ordering::Relaxed);
                // Nothing is written back: at capacity, the cheapest safe act
                // is to drop the connection rather than spend a thread telling
                // the client about it.
                continue;
            }
            let _ = stream.set_read_timeout(Some(self.cfg.idle_timeout));
            let _ = stream.set_write_timeout(Some(self.cfg.idle_timeout));
            let _ = stream.set_nodelay(true);
            let (cfg, db, opts, live, idle) = (
                Arc::clone(&self.cfg),
                Arc::clone(&db),
                Arc::clone(&opts),
                Arc::clone(&live),
                Arc::clone(&idle),
            );
            std::thread::spawn(move || {
                let _guard = LiveGuard(live);
                serve_connection(stream, &cfg, db.as_ref(), &opts, &idle);
            });
        }
        idle.close_all();
        while live.load(Ordering::SeqCst) > 0 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Ok(())
    }
}

/// Connections waiting for their next request, so a server that is stopping
/// can close them rather than wait out the idle timeout. A connection in the
/// middle of a request is not in here and is left to finish it.
#[derive(Default)]
struct Idle {
    closing: AtomicBool,
    next_id: AtomicUsize,
    waiting: Mutex<HashMap<usize, TcpStream>>,
}

impl Idle {
    /// Block until the next request starts arriving on `reader`. `Ok(false)`
    /// at end of stream, or when the server is stopping.
    fn next_request(&self, id: usize, reader: &mut BufReader<TcpStream>) -> std::io::Result<bool> {
        if let Ok(s) = reader.get_ref().try_clone() {
            self.lock().insert(id, s);
        }
        // After registering: either `close_all` sees this connection, or this
        // sees the flag it set first.
        let arrived = if self.closing.load(Ordering::SeqCst) {
            Ok(false)
        } else {
            reader.fill_buf().map(|b| !b.is_empty())
        };
        self.lock().remove(&id);
        arrived
    }

    fn close_all(&self) {
        self.closing.store(true, Ordering::SeqCst);
        for s in self.lock().values() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<usize, TcpStream>> {
        self.waiting.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Decrements the live-connection count however the handler thread ends.
struct LiveGuard(Arc<AtomicUsize>);

impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Whether the connection continues after a request.
enum Next {
    KeepAlive,
    Close,
}

fn serve_connection(
    stream: TcpStream,
    cfg: &IcapConfig,
    db: &dyn Signatures,
    opts: &ScanOptions,
    idle: &Idle,
) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("exav: icap: cannot split connection: {e}");
            return;
        }
    });
    let mut writer = stream;
    let id = idle.next_id.fetch_add(1, Ordering::Relaxed);
    for _ in 0..cfg.keepalive_requests {
        let next = idle
            .next_request(id, &mut reader)
            .and_then(|more| match more {
                true => handle_request(&mut reader, &mut writer, cfg, db, opts),
                false => Ok(Next::Close),
            });
        match next {
            Ok(Next::KeepAlive) => {}
            Ok(Next::Close) => break,
            Err(e) => {
                if !is_benign_disconnect(&e) {
                    eprintln!("exav: icap: connection error: {e}");
                }
                break;
            }
        }
    }
    lingering_close(&writer, &mut reader);
}

/// Close a connection without destroying the response just written to it.
///
/// Closing a socket that still has unread bytes in its receive queue makes the
/// kernel send an RST, and an RST discards whatever the peer has not read yet —
/// including the block response that is the entire point of the exchange. So
/// the write side is shut down first (the peer sees a clean end of response),
/// then whatever the peer is still sending is read and dropped, bounded, before
/// the socket goes away.
fn lingering_close(stream: &TcpStream, reader: &mut BufReader<TcpStream>) {
    /// Enough to cover a client finishing the request it was in the middle of;
    /// past this the RST is the lesser evil.
    const MAX_LINGER_BYTES: u64 = 4 * 1024 * 1024;
    use std::io::Read as _;
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut sink = std::io::sink();
    let mut bounded = reader.take(MAX_LINGER_BYTES);
    let _ = std::io::copy(&mut bounded, &mut sink);
}

/// I/O errors that mean the client went away (or stopped talking long enough to
/// hit the idle timeout), which is how connections normally end.
fn is_benign_disconnect(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        UnexpectedEof | BrokenPipe | ConnectionReset | ConnectionAborted | TimedOut | WouldBlock
    )
}

fn handle_request<W: Write>(
    reader: &mut BufReader<TcpStream>,
    writer: &mut W,
    cfg: &IcapConfig,
    db: &dyn Signatures,
    opts: &ScanOptions,
) -> std::io::Result<Next> {
    let head = match read_head(reader, cfg.max_header_bytes)? {
        Some(h) => h,
        None => return Ok(Next::Close),
    };
    let scanner = db.scanner();
    let istag = response::istag(&scanner);

    let req = match RequestHead::parse(&head) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("exav: icap: bad request: {e}");
            // The framing is not understood, so where the next request starts
            // is not known either. Answering and closing is the only honest
            // move; keeping the connection would be guessing.
            response::error(400, "Bad Request")
                .closing()
                .write_to(writer, &istag)?;
            return Ok(Next::Close);
        }
    };

    if !cfg.serves(&req.service) {
        // A REQMOD/RESPMOD to an unknown service still has a body queued behind
        // it that will never be read, so the connection cannot be reused.
        response::error(404, "ICAP Service not found")
            .closing()
            .write_to(writer, &istag)?;
        return Ok(Next::Close);
    }

    let close_after = req.wants_close();
    // `None` means the answer already went out on this writer, which is how a
    // rejected body and an early answer to a preview report back.
    let answer = match req.method {
        IcapMethod::Options => Some(response::options(cfg)),
        IcapMethod::ReqMod | IcapMethod::RespMod => {
            modify(reader, writer, cfg, &req, &scanner, opts, &istag)?
        }
        IcapMethod::Other(ref m) => {
            eprintln!("exav: icap: unsupported method {m}");
            Some(response::error(405, "Method Not Allowed").closing())
        }
    };

    match answer {
        None => Ok(Next::Close),
        Some(mut r) => {
            if close_after {
                r = r.closing();
            }
            let closing = r.close;
            r.write_to(writer, &istag)?;
            Ok(if closing {
                Next::Close
            } else {
                Next::KeepAlive
            })
        }
    }
}

/// Handle a REQMOD or RESPMOD: read the encapsulated message, scan it, and
/// build the answer.
///
/// `Ok(None)` means the answer has already gone out and the connection must
/// close.
fn modify<W: Write>(
    reader: &mut BufReader<TcpStream>,
    writer: &mut W,
    cfg: &IcapConfig,
    req: &RequestHead,
    scanner: &Scanner,
    opts: &ScanOptions,
    istag: &str,
) -> std::io::Result<Option<response::Response>> {
    let enc = match req.encapsulated(cfg.max_header_bytes) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("exav: icap: bad Encapsulated header: {e}");
            response::error(400, "Bad Request")
                .closing()
                .write_to(writer, istag)?;
            return Ok(None);
        }
    };
    let preview = match req.preview() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("exav: icap: {e}");
            response::error(400, "Bad Request")
                .closing()
                .write_to(writer, istag)?;
            return Ok(None);
        }
    };

    // The encapsulated HTTP headers: a fixed-size block whose length the
    // (already validated and capped) offset list gives.
    let mut headers = vec![0u8; enc.header_bytes()];
    std::io::Read::read_exact(reader, &mut headers)?;

    let (body_entity, _) = enc.terminal();
    let mut body: Option<Held> = None;
    let mut over_limit = false;
    let mut abandoned = false;
    // Set when a spill budget refused the rest of the object: what was held
    // is scanned, and the verdict is at best the limit.
    let mut rejected: Option<String> = None;
    let mut total = 0u64;

    if body_entity.has_body() {
        let mut buf = Body::new();
        let outcome = match read_body(reader, cfg, opts, &mut buf) {
            Ok(o) => o,
            Err(BodyError::Io(e)) => return Err(e),
            Err(e @ BodyError::Malformed(_)) => {
                eprintln!("exav: icap: {e}");
                response::error(400, "Bad Request")
                    .closing()
                    .write_to(writer, istag)?;
                return Ok(None);
            }
        };
        over_limit = outcome.over_limit;
        abandoned = outcome.abandoned;
        total = outcome.total;
        take_rejection(&mut rejected, &outcome);

        // Preview handling. A `0; ieof` terminator says the preview was the
        // whole object, so there is nothing to ask for and the verdict is final
        // straight away.
        if preview.is_some() && outcome.end == BodyEnd::Eof && !over_limit && rejected.is_none() {
            // A detection in the preview is already decisive, so the rest of
            // the object is never requested. A *clean* preview is not: it is
            // the head of a file, and the head of a file being clean is exactly
            // the bypass that answering early would create. Nor is a
            // partial verdict acted on here — a truncated archive is
            // undecodable because it is truncated, which says nothing about the
            // whole one.
            // Scanned from the RAM head, which for any preview a client actually
            // sends is the whole of it.
            let early = scan_bytes(
                scanner,
                opts,
                buf.head(),
                &headers,
                enc.span(Entity::ReqHdr),
            );
            if matches!(early, Decision::Infected(_)) {
                log_block(req, &early);
                return Ok(Some(response::block(&early, cfg.infection_header)));
            }
            response::write_continue(writer)?;
            let o = match read_body(reader, cfg, opts, &mut buf) {
                Ok(o) => o,
                Err(BodyError::Io(e)) => return Err(e),
                Err(e @ BodyError::Malformed(_)) => {
                    eprintln!("exav: icap: {e}");
                    response::error(400, "Bad Request")
                        .closing()
                        .write_to(writer, istag)?;
                    return Ok(None);
                }
            };
            over_limit = o.over_limit;
            abandoned = o.abandoned;
            total = total.saturating_add(o.total);
            take_rejection(&mut rejected, &o);
        }
        body = Some(Held {
            payload: buf.finish()?,
            short: rejected.clone(),
        });
    }

    // The scan every other entry point runs: the part of an object over
    // `--max-input-bytes`, or past what the spill budgets could hold, is
    // scanned, and the limit is reported only with no detection in it.
    let decision = scan(
        scanner,
        opts,
        body.as_ref(),
        total,
        &headers,
        enc.span(Entity::ReqHdr),
    );

    // A deployment can choose to take delivery of an object exav could not
    // fully examine. Whether that choice can be honoured for *this* object is a
    // second question, and the answer is no when the body is over the limit and
    // the client wants the message handed back: the tail was discarded to reach
    // the next request boundary, so the bytes are gone, and echoing the head
    // alone would deliver a truncated object as if it were the real one.
    let pass_wanted = matches!(&decision, Decision::Partial(tag, _)
        if cfg.partial_as.for_tag(tag) == crate::policy::PartialStatus::Ok);
    let passing = pass_wanted && (!over_limit || req.allow_204());

    if decision.blocks() && !passing {
        if pass_wanted {
            // Not a policy that failed to apply but an object it cannot apply
            // to, and the difference matters to whoever set the policy and is
            // now looking at a block they did not expect.
            eprintln!(
                "exav: icap: cannot pass an object past --max-input-bytes to a client that sent no \
                 `Allow: 204`: the discarded tail is not available to hand back; blocking instead"
            );
        }
        log_block(req, &decision);
        let mut r = response::block(&decision, cfg.infection_header);
        if abandoned {
            // The discard gave up before the body ended, so the client still
            // has bytes to send that nothing will read. Reusing this connection
            // would read them as the next request.
            r = r.closing();
        }
        return Ok(Some(r));
    }
    if passing {
        log_pass(req, &decision);
    }

    if req.allow_204() {
        let mut r = response::no_content().noting(&decision);
        if abandoned {
            r = r.closing();
        }
        return Ok(Some(r));
    }

    // No `Allow: 204`, so the client wants a whole message back: hand its own
    // message straight back to it.
    let hdr_entity = if enc.span(Entity::ResHdr).is_some() {
        Entity::ResHdr
    } else {
        Entity::ReqHdr
    };
    let hdr = enc
        .span(hdr_entity)
        .map(|(s, e)| &headers[s..e])
        .unwrap_or(&[]);
    Ok(Some(
        response::echo(hdr_entity, hdr, body.map(|h| h.payload)).noting(&decision),
    ))
}

/// Carry a spill budget's refusal out of a body read, once.
///
/// The preview and the continuation are two reads of one object; whichever hit
/// the budget first is the reason, and the later read must not overwrite it with
/// `None`.
fn take_rejection(slot: &mut Option<String>, outcome: &BodyOutcome) {
    if let Some(reason) = &outcome.rejected {
        if slot.is_none() {
            eprintln!("exav: icap: cannot buffer this object: {reason}");
            *slot = Some(reason.clone());
        }
    }
}

/// Read an encapsulated body, keeping at most `--max-input-bytes` of it.
fn read_body(
    reader: &mut BufReader<TcpStream>,
    cfg: &IcapConfig,
    opts: &ScanOptions,
    out: &mut Body,
) -> Result<BodyOutcome, BodyError> {
    read_chunked_body(reader, opts.max_scan_size, cfg.max_drain_bytes, out)
}

/// The options an encapsulated object is scanned under, when the request names
/// it something.
///
/// Naming the object after the URL it came from is what lets filename-sensitive
/// rules (YARA's `filename` / `extension` externals) see what a scan of the
/// downloaded file would have seen. `None` means the caller's options serve.
fn named_opts(
    opts: &ScanOptions,
    headers: &[u8],
    req_hdr: Option<(usize, usize)>,
) -> Option<ScanOptions> {
    match req_hdr.and_then(|(s, e)| request_target(&headers[s..e])) {
        Some(name) if opts.filename.is_none() => {
            let mut o = opts.clone();
            o.filename = Some(name);
            Some(o)
        }
        _ => None,
    }
}

/// Turn a scan result into a decision.
///
/// A malicious object that panics a decoder must fail this one request, not the
/// connection and not the process — the same containment the CLI and the daemon
/// put around every file.
fn decide(
    scanned: std::thread::Result<std::io::Result<(exav_core::ScanReport, Option<String>)>>,
) -> Decision {
    let decision = match scanned {
        Ok(Ok((report, _loc))) => Decision::from_report(&report),
        // Not a partial: nothing was examined, and `--partial-as ok` must not
        // deliver it.
        Ok(Err(e)) => Decision::Error(format!("scan failed: {e}")),
        Err(_) => Decision::Error("scan failed (internal error)".to_string()),
    };
    apply_found_policy(decision)
}

/// Turn a partial decision into a detection where `--partial-as` says `found`.
///
/// `found` is settled here; `ok` is not, because whether this listener can
/// honour a pass depends on whether it still holds the object's bytes — a
/// question only the request loop can answer. `partial` and `error` change
/// nothing: ICAP has no exit code, which is all those two differ in.
///
/// Applied to every partial, not only the ones the engine produced, so a
/// deployment's answer to "what becomes of an object I could not examine" does
/// not depend on which layer noticed.
fn apply_found_policy(decision: Decision) -> Decision {
    match &decision {
        Decision::Partial(tag, _)
            if crate::policy::current().for_tag(tag) == crate::policy::PartialStatus::Found =>
        {
            Decision::Infected(crate::policy::heuristic_name(tag))
        }
        _ => decision,
    }
}

/// Scan one encapsulated body.
///
/// Handed to the daemon's own payload scanner, so an object arriving here is
/// examined exactly as the same object arriving over `INSTREAM` would be:
/// through the seekable path, which is what gives archives their
/// container-aware treatment (a ZIP's directory lives at its end), from RAM or
/// from the spill file, under the same [`ScanOptions`] every other exav
/// front-end uses.
fn scan(
    scanner: &Scanner,
    opts: &ScanOptions,
    body: Option<&Held>,
    size: u64,
    headers: &[u8],
    req_hdr: Option<(usize, usize)>,
) -> Decision {
    let Some(held) = body else {
        return Decision::Clean;
    };
    if size == 0 {
        return Decision::Clean;
    }
    let owned = named_opts(opts, headers, req_hdr);
    let named = owned.as_ref().unwrap_or(opts);

    // Timed so a listener can answer "where did the CPU go" about itself. The
    // object is named after the request target where there is one, because a
    // slow-scan line nobody can trace back to an object says only that
    // something was slow.
    let timer = crate::metrics::ScanTimer::start();
    let decision = decide(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || crate::daemon::scan_held(scanner, named, held, size),
    )));
    timer.finish(
        named.filename.as_deref().unwrap_or("<icap object>"),
        held.payload.len(),
        decision.category(),
    );
    decision
}

/// Scan bytes already in hand — the preview head, which is small by
/// construction and never worth a round trip through a file.
fn scan_bytes(
    scanner: &Scanner,
    opts: &ScanOptions,
    body: &[u8],
    headers: &[u8],
    req_hdr: Option<(usize, usize)>,
) -> Decision {
    if body.is_empty() {
        return Decision::Clean;
    }
    let owned = named_opts(opts, headers, req_hdr);
    let opts = owned.as_ref().unwrap_or(opts);
    decide(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || scan_seekable_located(scanner, std::io::Cursor::new(body), body.len() as u64, opts),
    )))
}

/// The request target from an encapsulated HTTP request line, for naming the
/// scanned object. Untrusted, so it is length-capped and stripped of anything
/// that is not printable ASCII before it goes anywhere.
fn request_target(req_hdr: &[u8]) -> Option<String> {
    let line = req_hdr.split(|&b| b == b'\n').next()?;
    let mut fields = line.split(|&b| b == b' ').filter(|f| !f.is_empty());
    let _method = fields.next()?;
    let target = fields.next()?;
    let target: String = target
        .iter()
        .take(512)
        .map(|&b| if b.is_ascii_graphic() { b as char } else { '_' })
        .collect();
    if target.is_empty() {
        None
    } else {
        Some(target)
    }
}

/// Record a block. Clean objects are not logged: at proxy volumes that is every
/// request, and a log nobody can read is a log nobody reads.
fn log_block(req: &RequestHead, decision: &Decision) {
    eprintln!(
        "exav: icap: {} {} blocked ({})",
        method_name(req),
        req.service,
        decision.summary()
    );
}

/// Record an object policy let through without exav having fully examined it.
///
/// Logged for the same reason the clean case is not: this is the rare event, and
/// it is the one an operator needs to be able to count. A configured pass is a
/// risk the deployment accepted, and accepting it must not also mean losing
/// sight of how often it fires.
fn log_pass(req: &RequestHead, decision: &Decision) {
    eprintln!(
        "exav: icap: {} {} passed unscanned by policy ({})",
        method_name(req),
        req.service,
        decision.summary()
    );
}

fn method_name(req: &RequestHead) -> &'static str {
    match req.method {
        IcapMethod::ReqMod => "REQMOD",
        IcapMethod::RespMod => "RESPMOD",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scan that failed is an error, not a partial: `--partial-as ok` passes
    /// a partial, and must never pass an object nothing examined.
    #[test]
    fn a_failed_scan_is_an_error_that_blocks() {
        let failed = decide(Ok(Err(std::io::Error::other("read failed"))));
        assert!(matches!(failed, Decision::Error(_)), "{}", failed.summary());
        assert!(failed.blocks());
        let panicked = decide(Err(Box::new("boom")));
        assert!(matches!(panicked, Decision::Error(_)));
    }

    #[test]
    fn extracts_the_request_target() {
        assert_eq!(
            request_target(b"GET /downloads/setup.exe HTTP/1.1\r\nHost: a\r\n\r\n"),
            Some("/downloads/setup.exe".to_string())
        );
        assert_eq!(
            request_target(b"GET http://h/a.zip HTTP/1.1\r\n"),
            Some("http://h/a.zip".to_string())
        );
        assert_eq!(request_target(b""), None);
        assert_eq!(request_target(b"GET\r\n"), None);
    }

    #[test]
    fn a_hostile_request_target_is_flattened() {
        let got = request_target(b"GET /a\x00b\x1bc HTTP/1.1\r\n").unwrap();
        assert_eq!(got, "/a_b_c");
        let long = format!("GET /{} HTTP/1.1\r\n", "a".repeat(5000));
        assert!(request_target(long.as_bytes()).unwrap().len() <= 512);
    }

    #[test]
    fn a_reloadable_database_changes_its_istag() {
        let db = crate::daemon::SharedDb::new(Arc::new(Scanner::builtin()));
        let before = response::istag(&db.scanner());

        let mut b = exav_core::loader::Builder::new();
        b.add_named_bytes("extra.ndb", b"Test.Marker:0:*:4d5a4d5a\n", false);
        db.replace(b.build().unwrap());

        let after = response::istag(&db.scanner());
        assert_ne!(
            before, after,
            "a signature reload must invalidate downstream ICAP caches"
        );
    }
}
