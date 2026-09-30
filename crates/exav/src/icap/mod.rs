//! ICAP (RFC 3507) server — a drop-in replacement for a `c-icap` container
//! running the `virus_scan` service against ClamAV.
//!
//! An ICAP client (Squid, a WAF, a mail gateway) hands over an HTTP request or
//! response for inspection and acts on the answer. The protocol surface a
//! virus-scanning service needs is small: `OPTIONS` for capability discovery,
//! `REQMOD`/`RESPMOD` to submit a message, `Preview` to send only a head of the
//! body first, and `204 No Content` to say "unchanged, pass it on".
//!
//! The listener is **opt-in**: nothing here runs without an `icap://` address on
//! `--listen`, so starting the scanner or the clamd daemon binds no ICAP port on
//! its own. It is a listener rather than a mode — named alongside a `clamd://`
//! address, both protocols are served from one process over one loaded database.
//!
//! Every setting reads a flag, then an `EXAV_ICAP_*` environment variable, then
//! its default, so a container and a shell invocation configure it the same way
//! as the rest of the CLI. That precedence is the argument parser's, applied
//! uniformly; nothing here decides it.
//!
//! ## Verdict mapping
//!
//! | [`Verdict`](exav_core::Verdict) | ICAP response | headers |
//! |---|---|---|
//! | `Clean` | `204 No Content` when the client sent `Allow: 204`, else `200` echoing the message unmodified | — |
//! | `Infected` | `200 OK` + a block page | `X-Infection-Found: Type=0; Resolution=2; Threat=<name>;` |
//! | `LimitsExceeded` / `Unscannable` / `PasswordProtected` | `200 OK` + a block page, or the clean answer above when [`PartialAs`](crate::policy::PartialAs) says `ok` | `X-Infection-Found` naming `Heuristics.Exav.<Condition>` on a block only, plus `X-Exav-Status: PARTIAL` + `X-Exav-Category` + `X-Exav-Reason` either way |
//!
//! Every non-clean verdict blocks, and every block says so in the c-icap
//! vocabulary. Both halves are needed, because ICAP clients split into two
//! kinds. A proxy acts on the message: it sees a `200` carrying a replacement
//! body instead of the object and stops it, whatever the headers say. A scan
//! wrapper acts on the headers alone — it hands a file over and greps the
//! response for `X-Infection-Found`, and a `200` without that header is what it
//! calls clean. Withholding the header from a partial block therefore turns
//! exav's fail-closed answer into a fail-open one on the second kind of client,
//! which is the one answer exav must never give for an object nobody examined.
//!
//! What keeps the two distinguishable is the threat name, not the header's
//! presence. A database hit is reported under its signature name; a partial
//! block under `Heuristics.Exav.<Condition>`, the prefix ClamAV uses for a
//! policy block rather than a database entry, qualified by the scanner that
//! synthesised it. An analyst reading an incident log can tell them apart, and
//! [`X-Exav-Category`](IcapConfig) still carries the exact condition for a client
//! that reads it. [`InfectionHeader::Detections`] restores the strict split for
//! a deployment that wants the header to mean a database hit and nothing else.
//!
//! The header's format is byte-for-byte what c-icap's `virus_scan` emits,
//! because deployed clients parse it by hand.
//!
//! ## Passing what could not be examined
//!
//! Blocking is the default, not the only option. [`PartialAs`](crate::policy::PartialAs) lets a
//! deployment take delivery of the objects exav could not fully examine, named
//! by verdict tag or all at once, which is the trade an upload service makes
//! when rejecting a user's encrypted archive costs it more than delivering one.
//! c-icap + ClamAV makes that same trade by default and without saying so.
//!
//! A pass here is never silent. It is logged per object, the listener says at
//! startup that it is running that way, and the response still carries
//! `X-Exav-Category` / `X-Exav-Reason` naming what was skipped — never
//! `X-Infection-Found`, which on a delivered object would be false and would
//! make the header-only client the setting exists for block it anyway.
//!
//! One object cannot be passed whatever the policy says: one past
//! `--max-input-bytes` whose client sent no `Allow: 204`. Its tail was
//! discarded to reach the next request boundary, so handing the message back
//! would mean handing back the head as though it were the whole thing.
//!
//! ## What is exav-specific
//!
//! c-icap's `virus_scan.MaxObjectSize` lets an object **through unscanned** once
//! it is larger than the ceiling. `--max-input-bytes` is the same knob
//! with the opposite default: past the ceiling the object is blocked with
//! `X-Exav-Category: LIMITS-EXCEEDED`. [`PartialAs`](crate::policy::PartialAs) can ask for c-icap's
//! answer back, and the difference that remains is the one that matters — exav
//! says which objects it delivered without examining, where c-icap says nothing
//! at all.
//
// The crate as a whole cannot forbid `unsafe`, because the prefork daemon is
// built on libc calls that have no safe binding. This module needs none of
// them — ICAP is a line protocol over `std::net` and a scan — so it carries the
// guarantee itself, and it is the part of the binary that most needs it: every
// byte the parsers below look at arrived from the network.
//
// `forbid`, not `deny`: `deny` is one `#[allow(unsafe_code)]` away from being
// switched off inside the module it guards, which is precisely where such an
// exemption would be written and least likely to be questioned. `forbid` cannot
// be overridden from within, so the only way to add `unsafe` here is to delete
// this line — a visible change to the module's contract rather than a local
// annotation. The lint level applies to every submodule below.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use exav_core::ScanOptions;

use crate::Cli;

mod chunked;
mod config;
mod response;
mod server;
mod wire;

pub(crate) use self::config::{IcapConfig, InfectionHeader};
pub(crate) use self::server::Server;

use self::server::{FixedDb, Signatures};
use crate::daemon::SharedDb;

/// Version string reported in the `Service` and `Server` headers.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build the server configuration from the parsed arguments.
pub fn config_from_cli(cli: &Cli) -> Result<IcapConfig, String> {
    let d = IcapConfig::default();
    let endpoint = crate::icap_endpoint(cli);

    // Naming services replaces the default set rather than adding to it: an
    // operator who names them means that set exactly, and silently adding the
    // defaults back would answer on names they did not configure. They come off
    // the address — the path of the ICAP URL, or `?service=` — because that is
    // where a proxy's configuration already carries them.
    let services = match endpoint.as_ref().map(|e| e.services.as_slice()) {
        Some([]) | None => d.services,
        Some(named) => named.to_vec(),
    };

    Ok(IcapConfig {
        // The address came in on `--listen icap://…`, already parsed. ICAP is
        // TCP-only, which `Endpoint::parse` enforces, so this cannot be a path.
        listen: match endpoint.as_ref().map(|e| &e.addr) {
            Some(crate::endpoint::Addr::Tcp(a)) => a.clone(),
            _ => d.listen,
        },
        services,
        preview_size: cli.icap_preview_size.map_or(d.preview_size, |p| p.value()),
        // `off` omits the header. An empty string used to be the way to say
        // that, which is a sentinel nobody guesses and a shell quoting accident
        // away from being set by mistake.
        transfer_preview: match cli.icap_transfer_preview.as_deref() {
            Some(v) if v.eq_ignore_ascii_case("off") => String::new(),
            Some(v) => v.to_string(),
            None => d.transfer_preview,
        },
        // `?max-connections=` on the address, the same option the clamd listener
        // reads — a cap belongs to the listener it bounds, not to a flag that
        // would have to name a protocol to apply to. Also advertised to clients
        // as `Max-Connections`.
        max_connections: endpoint
            .as_ref()
            .and_then(|e| e.max_connections)
            .unwrap_or(d.max_connections),
        options_ttl: cli.icap_options_ttl.map_or(d.options_ttl, |t| t.value()),
        keepalive_requests: match cli.icap_keepalive_requests {
            Some(0) => u64::MAX,
            Some(n) => n,
            None => d.keepalive_requests,
        },
        idle_timeout: cli
            .icap_idle_timeout
            .map_or(d.idle_timeout, Duration::from_secs),
        max_drain_bytes: d.max_drain_bytes,
        max_header_bytes: cli.icap_max_header_size.unwrap_or(d.max_header_bytes),
        service_label: d.service_label,
        infection_header: cli.icap_infection_header.unwrap_or(d.infection_header),
        partial_as: cli.partial_as.unwrap_or(d.partial_as),
    })
}

/// Bind the configured address.
///
/// Separate from serving so the port is claimed by the process that was asked to
/// listen: a busy port or a bad address is then reported there, rather than by a
/// thread or a forked child nobody is watching.
pub fn bind(cfg: IcapConfig) -> std::io::Result<Server> {
    Server::bind(cfg)
}

/// Announce the bound listener, once, from whichever process ends up serving it.
fn announce(server: &Server) {
    let cfg = server.config();
    eprintln!(
        "exav: serving ICAP on tcp:{} (services: {}; preview {})",
        server
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| cfg.listen.clone()),
        cfg.services.join(", "),
        cfg.preview_size
            .map_or_else(|| "off".to_string(), |n| format!("{n} B")),
    );
    // Said at startup as well as per object, because a deployment that passes
    // what it could not examine should be legible from its logs alone — nobody
    // reconstructs a running container's command line to answer "are we
    // delivering unscanned files?".
    if cfg.partial_as.reports_any_as_ok() {
        eprintln!(
            "exav: icap: objects that could not be fully examined are PASSED to the client, \
             not blocked (--partial-as {})",
            cfg.partial_as
        );
    }
}

/// Serve ICAP on a listener thread of its own, over the database the thread
/// model's supervisor ([`crate::daemon::supervise`]) swaps on a reload. A swap
/// moves the `ISTag` and so invalidates every downstream ICAP cache.
pub fn spawn(server: Server, db: Arc<SharedDb>, opts: Arc<ScanOptions>) {
    announce(&server);
    let handle: Arc<dyn Signatures> = db;
    std::thread::spawn(move || {
        if let Err(e) = server.run(handle, opts, &|_| true) {
            eprintln!("exav: icap: listener stopped: {e}");
        }
        // The listener is the whole job. Without it the process is a supervisor
        // watching for signature changes nobody will ever scan with, and an
        // orchestrator can only restart what it can see has stopped.
        std::process::exit(2);
    });
}

/// Hand the bound listener to the prefork supervisor as a child process of its
/// own.
///
/// The pool serves one job per worker under kernel-enforced limits, which is the
/// wrong shape for ICAP: its connections are keep-alive and long-lived, so a
/// handful of idle proxy connections would occupy every worker and starve the
/// clamd listener as well. A dedicated child keeps ICAP's threaded model while
/// still sharing the supervisor's warmed database copy-on-write, and the
/// supervisor re-forks it from the new database on every reload — so the
/// signature swap needs no in-process machinery at all. The retired child
/// finishes the requests it is serving before it exits.
#[cfg(unix)]
pub fn forked_child(server: Server, metrics_interval: Duration) -> crate::daemon::SideListener {
    crate::daemon::SideListener {
        name: "icap",
        serve: Box::new(move |db, opts, retire| {
            announce(&server);
            // A child of its own, so its counters are its own: the clamd
            // workers' `STATS` cannot see them and this log line is where they
            // surface. Started here rather than before the fork, because a
            // thread does not survive one.
            crate::metrics::spawn_reporter(metrics_interval, "icap");
            let handle: Arc<dyn Signatures> = Arc::new(FixedDb::from_arc(db));
            // Shared with the other generation's child during a reload, so
            // both wait for readiness instead of blocking in accept.
            let wait = |l: &std::net::TcpListener| {
                use std::os::fd::AsRawFd;
                crate::daemon::await_connection(l.as_raw_fd(), retire)
            };
            if let Err(e) = server.set_nonblocking() {
                eprintln!("exav: icap: listener stopped: {e}");
                std::process::exit(2);
            }
            match server.run(handle, opts, &wait) {
                Ok(()) => std::process::exit(0),
                Err(e) => eprintln!("exav: icap: listener stopped: {e}"),
            }
            std::process::exit(2);
        }),
    }
}
