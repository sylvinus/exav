//! exav CLI: the scanner, the client, and the listeners.
//!
//! Exit codes and output match clamscan (0 = clean, 1 = found, 2 = error;
//! `PATH: Signature FOUND` / `PATH: OK`), so a script reading either keeps
//! working. The *flags* are exav's own — one clamscan has and exav does not
//! stops the run rather than being swallowed, so a migrated command line never
//! scans under settings nobody asked for.
//!
//! `-` reads stdin, so input can be streamed, e.g. `aws s3 cp s3://… - | exav -`.
//! Unlike clamscan, the size bounds accept values above 2 GB, and a file that
//! can't be fully scanned is reported `LIMITS-EXCEEDED`, not `OK`.
//!
//! # `unsafe`
//!
//! This is the one crate in the workspace without `#![forbid(unsafe_code)]`,
//! and [`daemon`] is the only module that accounts for it: the prefork pool is
//! `fork`, `waitpid`, `setrlimit`, `sigaction`, the `umask` that fixes the
//! socket's permissions at creation, and `SCM_RIGHTS` descriptor passing in
//! both directions (the daemon's `FILDES`, the client's `--send-as fd`), none of
//! which has a safe binding that does not itself pull in a raw-syscall crate
//! larger than the code it replaces. Nothing on the scanning path is unsafe —
//! no scanned byte reaches any of it, and the engine, extractor, emulator and
//! decoder all forbid it outright. The `icap` module, whose parsers read
//! straight off the network, carries `#![deny(unsafe_code)]` of its own.

mod daemon;
mod endpoint;
#[cfg(feature = "icap")]
mod icap;
mod metrics;
mod perf;
mod policy;
#[cfg(unix)]
mod signatures;
mod spill;
mod tmpfile;

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use exav_core::{loader, scan_path, ScanOptions, ScanReport, Scanner, Verdict, VerdictCategory};

/// Categories the daemon names before the closing ` ERROR` when a verdict is
/// `PARTIAL` — as opposed to a hard scan error, which has no category. The
/// client reads them back so its summary and exit code match a local one-shot
/// scan of the same file.
const PARTIAL_TAGS: [&str; 3] = ["LIMITS-EXCEEDED", "UNSCANNABLE", "PASSWORD-PROTECTED"];

/// The category of a `PARTIAL` daemon reply, or `None` for a hard error.
///
/// The wire grammar is `<path>: <reason> <CATEGORY> ERROR`, the same
/// `reason CATEGORY STATUS` order the one-shot CLI prints. So the category is
/// the second-to-last word — not a prefix of anything, and not a substring
/// search: a reason is free text and a path like `/data/UNSCANNABLE/x` would
/// otherwise turn a real error into a partial, moving it out of the error
/// counter and off stderr.
fn partial_category(line: &str) -> Option<&'static str> {
    let head = line.strip_suffix(" ERROR")?;
    PARTIAL_TAGS
        .iter()
        .copied()
        .find(|t| head.strip_suffix(t).is_some_and(|h| h.ends_with(' ')))
}

use walkdir::WalkDir;

/// Print one result line to stdout and mirror it into `--log`.
///
/// Every verdict goes through here so the log can never disagree with the
/// terminal — a log that is missing a detection is worse than no log.
macro_rules! outln {
    ($($arg:tt)*) => {{
        let line = format!($($arg)*);
        println!("{line}");
        log_line(&line);
    }};
}

/// Read a newline-separated list of paths, skipping blanks and `#` comments.
/// `-` reads the list itself from stdin.
fn read_path_list(list: &std::path::Path) -> std::io::Result<Vec<PathBuf>> {
    use std::io::Read;
    let mut s = String::new();
    if list == std::path::Path::new("-") {
        std::io::stdin().read_to_string(&mut s)?;
    } else {
        s = std::fs::read_to_string(list)?;
    }
    Ok(s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(PathBuf::from)
        .collect())
}

/// The `--log` sink. A process scans once, so one lazily-opened handle is the
/// whole mechanism; `None` means no `--log` was given.
static LOG_FILE: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

fn log_open(path: &std::path::Path) -> std::io::Result<()> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    *LOG_FILE.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    Ok(())
}

/// Mirror one result line into the `--log` file. Writing to stdout stays the
/// caller's job — the log is an addition, never a redirection, so piping still
/// behaves and a broken log cannot swallow a detection.
///
/// Line and newline go out in one `write_all`. The prefork daemon's workers are
/// separate processes sharing this one appending descriptor, and a line written
/// in two calls can have another worker's line land between them, so the log
/// would carry results no reader can attribute.
pub(crate) fn log_line(line: &str) {
    use std::io::Write;
    let mut g = LOG_FILE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(f) = g.as_mut() {
        let mut buf = String::with_capacity(line.len() + 1);
        buf.push_str(line);
        buf.push('\n');
        let _ = f.write_all(buf.as_bytes());
        let _ = f.flush();
    }
}

/// Printed at the foot of `--help`.
///
/// exav reads ClamAV's databases and speaks its protocol; it does not take its
/// command line. Accepting `clamscan`'s spellings as aliases meant two names for
/// every bound — twice the documentation, and a second way for a command line to
/// be subtly wrong — in exchange for letting an invocation be pasted across,
/// which nobody does twice. What replaces them is a pointer to the table that
/// says what maps to what.
const AFTER_HELP: &str = "\
Coming from ClamAV:
  exav loads the same signature databases and answers the same clamd protocol,
  but the flags are its own. The per-flag mapping is at
  https://exav.org/reference/clamav-flag-matrix/

  A clamscan flag exav does not have is REFUSED, never ignored: the run stops
  rather than scanning under settings you did not ask for.";

/// Every flag falls back to an environment variable, and the environment
/// belongs to the process while a test does not. So any test that sets a
/// variable — or that parses a command line a variable could change the meaning
/// of — holds this for its duration, and the whole crate shares the one lock:
/// two test modules with a lock each would not exclude one another.
#[cfg(test)]
pub(crate) fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // A poisoned lock means some earlier test panicked, not that the
    // environment is unusable; taking it anyway keeps one failure from
    // cascading into every test that parses.
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// How a switch set in the environment is read: `1`/`yes`/`on`/`true` (and
/// `y`/`t`) turn it on, `0`/`no`/`off`/`false` (and `n`/`f`) leave it off, and
/// anything else stops the run.
///
/// Guessing at the rest is what makes a typo dangerous. `EXAV_AUTO_UPDATE=ture`
/// read as false fetches nothing and says nothing about why, and an operator
/// reading their own configuration has no way to tell it is not the one running.
fn env_switch() -> clap::builder::BoolishValueParser {
    clap::builder::BoolishValueParser::new()
}

/// What a `--connect` client hands the daemon for each file.
///
/// One dial rather than a switch per transport: the three are alternatives, so
/// as switches every pair was a combination that had to be refused, and none of
/// them could say "the default" out loud.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SendAs {
    /// `SCAN <abspath>` — the daemon opens the file itself.
    #[default]
    Path,
    /// `INSTREAM` — the bytes go over the connection.
    Contents,
    /// `FILDES` — an open descriptor over a Unix socket (SCM_RIGHTS).
    Fd,
}

impl SendAs {
    fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "path" => Ok(Self::Path),
            "contents" => Ok(Self::Contents),
            "fd" => Ok(Self::Fd),
            other => Err(format!(
                "unknown --send-as {other:?} (known: path, contents, fd)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Contents => "contents",
            Self::Fd => "fd",
        }
    }

    /// Whether this sends the file itself rather than its name. The client walks
    /// directories itself in that case: the daemon gets bytes, not a tree it
    /// could descend.
    fn sends_contents(self) -> bool {
        !matches!(self, Self::Path)
    }
}

/// exav: scan files of effectively unlimited size for malware.
#[derive(Parser, Debug)]
#[command(name = "exav", version, about, long_about = None, after_help = AFTER_HELP)]
struct Cli {
    /// Files or directories to scan. Use `-` for stdin.
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Scan only the files directly inside a directory, not its subdirectories.
    ///
    /// A named directory is scanned recursively by default. Naming a directory
    /// and getting some of it is the kind of surprise that reads as a clean
    /// result: the files that were never opened are indistinguishable, in the
    /// output, from files that were and were fine.
    #[arg(long = "no-recursive", env = "EXAV_NO_RECURSIVE", value_parser = env_switch())]
    no_recursive: bool,

    /// Sound a bell on virus detection.
    #[arg(long = "bell", env = "EXAV_BELL", value_parser = env_switch())]
    bell: bool,

    /// Read the list of files to scan from FILE, one path per line (`-` reads
    /// the list from stdin). Blank lines and lines starting with `#` are
    /// skipped. Merged with any PATHs given on the command line.
    ///
    /// A path list is expanded here, before the scan mode is chosen, so it
    /// behaves identically for a local scan and for a `--connect` client scan.
    /// Note the daemon protocol distinction: paths are sent as paths, so the
    /// *daemon's* filesystem must be able to see them. `--send-as contents`, and
    /// `-` / stdin, send the bytes instead, which works from anywhere.
    #[arg(long = "files-from", value_name = "FILE", env = "EXAV_FILES_FROM")]
    file_list: Option<PathBuf>,

    /// Append scan results to FILE as well as writing them to stdout. The file
    /// is opened once and appended to, so it survives log rotation the same way
    /// clamd's `LogFile` does.
    #[arg(long = "log", value_name = "FILE", env = "EXAV_LOG")]
    log: Option<PathBuf>,

    /// Load this exact FILE or DIR instead of --sigs-dir. Recognizes `.ndb`,
    /// `.hdb`/`.hsb`, `.fdb` (fuzzy), exav `.db`, and `.cvd`/`.cld` containers;
    /// a DIR is scanned recursively (hidden `.`-prefixed sub-dirs skipped).
    ///
    /// Distinct from --sigs-dir, which names the *directory signatures live in* —
    /// the one --auto-update writes into and the one a sidecar populates. This
    /// names what to load, and is how a deployment loads a prebuilt `.exavdb`
    /// that lives somewhere other than that directory. With neither, and no real
    /// database, exav refuses to run unless --allow-no-db (built-in EICAR-only
    /// baseline, testing only).
    #[arg(
        short = 'd',
        long = "database",
        value_name = "PATH",
        env = "EXAV_DATABASE"
    )]
    database: Option<PathBuf>,

    /// Directory signatures live in (.ndb/.hdb/.hsb/.cvd/...), loaded
    /// recursively. Populate it with `cvd`/`freshclam` (+
    /// `clamav-unofficial-sigs` for third-party feeds), or let --auto-update
    /// keep it current — it is the directory written to, so it stays a
    /// directory even when -d points the load somewhere else.
    #[arg(
        long = "sigs-dir",
        value_name = "DIR",
        env = "EXAV_SIGS_DIR",
        default_value = "/var/lib/exav"
    )]
    sigs: PathBuf,

    /// Where --auto-update fetches signatures from. Repeatable (comma- or
    /// whitespace-separated in the environment); the sources merge.
    ///
    ///   https://host/main.cvd   an exact source, fetched verbatim
    ///   https://host/db/        a mirror base — the trailing slash makes it one,
    ///                           expanding to <base>/{main,daily,bytecode}.cvd
    ///   /etc/exav/sources       a file of the above, one per line (`#` comments
    ///                           OK), or a `freshclam.conf`
    ///
    /// One flag rather than one per shape: which of the three a value is, is
    /// legible from the value. A `freshclam.conf` works as-is — exav reads its
    /// *source* directives (`DatabaseMirror`/`PrivateMirror`,
    /// `DatabaseCustomURL`) and warns about the lines it ignores, including
    /// `DatabaseDirectory` (that is --sigs-dir; it is not a source).
    ///
    /// No source is privileged: every URL here is fetched the same way, over
    /// plain HTTPS with no signature verification. Point it at a mirror you
    /// trust, or use `freshclam`/`cvd` and let exav hot-reload the directory.
    #[arg(
        long = "sig-sources",
        value_name = "URL|FILE",
        env = "EXAV_SIG_SOURCES",
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    sig_sources: Vec<String>,

    /// URL of a prebuilt `.exavdb` to pull and serve, instead of fetching
    /// signature files. Re-checked and hot-reloaded on change by --auto-update,
    /// with a cheap conditional `HEAD` — which is why its default re-check is
    /// far more frequent than a full source fetch's. Basic auth via `user:pass@`.
    /// Needs a build with `--features http-update`.
    ///
    /// Where it lands, and is therefore loaded from, is `-d` when given, else
    /// `<--sigs-dir>/remote.exavdb`.
    #[arg(long = "db-url", value_name = "URL", env = "EXAV_DB_URL")]
    db_url: Option<String>,

    /// Keep the signature source current for as long as this process runs:
    /// create the signature dir, fetch every --sig-sources (or the prebuilt
    /// `.exavdb` at --db-url) before the first load, then re-check every
    /// --update-interval-secs and hot-reload the served database whenever
    /// anything changed. With no source configured it instead waits
    /// --startup-wait-secs for a sidecar to populate the dir. Serving with no
    /// signatures is refused either way. Fetching needs a build with
    /// `--features http-update`. Unix only.
    #[arg(long = "auto-update", env = "EXAV_AUTO_UPDATE", value_parser = env_switch())]
    auto_update: bool,

    /// Seconds to wait at startup for signatures to appear in the signature dir
    /// before giving up, for a deployment where a sidecar populates it. `0` does
    /// not wait. [default: 1800 with --auto-update, 0 otherwise]
    #[arg(
        long = "startup-wait-secs",
        value_name = "SECS",
        env = "EXAV_STARTUP_WAIT_SECS"
    )]
    startup_timeout: Option<u64>,

    /// Seconds between signature update checks (--auto-update). Floored at 60
    /// however low this goes: a zero-second sleep is not a fast poll, it is a
    /// loop with no delay aimed at someone else's servers. [default: 86400]
    #[arg(
        long = "update-interval-secs",
        value_name = "SECS",
        env = "EXAV_UPDATE_INTERVAL_SECS"
    )]
    update_interval_secs: Option<u64>,

    /// Run with only the built-in EICAR-only baseline when no real signature
    /// database is present. **Testing and CI only**: a scanner with near-zero
    /// coverage reports real malware as clean, so exav otherwise refuses to
    /// scan or serve without signatures.
    #[arg(long = "allow-no-db", env = "EXAV_ALLOW_NO_DB", value_parser = env_switch())]
    allow_no_db: bool,

    /// Compile the loaded signatures into a prebuilt `.exavdb` database, write it
    /// to FILE, and exit. The file loads directly with `-d` for a near-instant
    /// cold start and can be distributed as-is. Run this on a host with enough
    /// RAM (compiling the full signature set needs several GB); the resulting
    /// database loads cheaply everywhere.
    #[arg(long = "build-db", value_name = "FILE", env = "EXAV_BUILD_DB")]
    build_db: Option<PathBuf>,

    /// Serve on this address. Repeatable (comma-separated in the environment);
    /// nothing listens without it.
    ///
    ///   clamd://0.0.0.0:3310        the clamd protocol over TCP
    ///   clamd:///var/run/exav.sock  the clamd protocol over a Unix socket
    ///   icap://0.0.0.0:1344         ICAP (RFC 3507), for a proxy's hook
    ///   icap://0.0.0.0:1344/avscan  ICAP answering on that service only
    ///   0.0.0.0:3310                no scheme — clamd
    ///   /var/run/exav.sock          no scheme, a path — clamd over a socket
    ///
    /// An ICAP service name is the path of the URL a proxy is configured with,
    /// so it goes where it already lives: paste `icap://scanner:1344/avscan`
    /// out of a squid.conf unchanged. With no path exav answers on all three
    /// names a c-icap `virus_scan` deployment does — avscan, srv_clamav,
    /// virus_scan — so it stands in for one without knowing which the proxy
    /// asks for. Naming one replaces that set rather than adding to it.
    ///
    /// A `?key=value` tail sets what belongs to this listener alone:
    ///
    ///   mode=660             permission bits for a Unix socket. Default 0600,
    ///                        owner only — every user the mode admits can submit
    ///                        scans and read the verdicts.
    ///   max-connections=200  concurrent connections accepted here. Default 128
    ///                        for clamd, 100 for ICAP (which also advertises it
    ///                        as `Max-Connections`). Bounds the clamd listener
    ///                        only under `--workers threads`; the prefork pool
    ///                        bounds concurrency by its worker count.
    ///   service=a&service=b  several ICAP service names, for two proxies whose
    ///                        configurations disagree about the path. One name
    ///                        belongs in the path instead.
    ///
    /// Naming both protocols serves both from one process over one loaded
    /// database, which is what replaces a `c-icap` + `clamav` container pair.
    /// The database is loaded once, so callers pay no per-scan startup cost.
    #[arg(
        long = "listen",
        value_name = "ADDR",
        env = "EXAV_LISTEN",
        value_delimiter = ',',
        verbatim_doc_comment
    )]
    listen: Vec<String>,

    /// Scan by handing each file to a daemon already running at this address,
    /// instead of loading a database here. Same address grammar as --listen.
    ///
    /// The direction is the flag, not a mode: --listen accepts connections,
    /// --connect makes one.
    #[arg(long = "connect", value_name = "ADDR", env = "EXAV_CONNECT")]
    connect: Option<String>,

    /// Bytes of a body an ICAP client should send before pausing for a verdict
    /// (the `Preview` header). [default: 4096]
    #[cfg(feature = "icap")]
    #[arg(
        long = "icap-preview-bytes",
        value_name = "N",
        env = "EXAV_ICAP_PREVIEW_BYTES"
    )]
    icap_preview_size: Option<usize>,

    /// Which objects a client should preview (the `Transfer-Preview` header);
    /// `*` means all, `off` omits the header. [default: *]
    #[cfg(feature = "icap")]
    #[arg(
        long = "icap-transfer-preview",
        value_name = "PATTERN|off",
        env = "EXAV_ICAP_TRANSFER_PREVIEW"
    )]
    icap_transfer_preview: Option<String>,

    /// Seconds a client may cache the ICAP `OPTIONS` answer (`Options-TTL`).
    /// [default: 3600]
    #[cfg(feature = "icap")]
    #[arg(
        long = "icap-options-ttl-secs",
        value_name = "SECS",
        env = "EXAV_ICAP_OPTIONS_TTL_SECS"
    )]
    icap_options_ttl: Option<u32>,

    /// Requests served on one ICAP connection before it is closed.
    /// [default: 100] [c-icap.conf: MaxKeepAliveRequests]
    #[cfg(feature = "icap")]
    #[arg(
        long = "icap-max-requests",
        value_name = "N",
        env = "EXAV_ICAP_MAX_REQUESTS"
    )]
    icap_keepalive_requests: Option<u64>,

    /// Seconds an idle ICAP connection is held open. [default: 600]
    /// [c-icap.conf: KeepAliveTimeout]
    #[cfg(feature = "icap")]
    #[arg(
        long = "icap-idle-secs",
        value_name = "SECS",
        env = "EXAV_ICAP_IDLE_SECS"
    )]
    icap_idle_timeout: Option<u64>,

    /// Largest ICAP head plus encapsulated HTTP headers accepted in one
    /// request. [default: 65536]
    #[cfg(feature = "icap")]
    #[arg(
        long = "icap-max-header-bytes",
        value_name = "N",
        env = "EXAV_ICAP_MAX_HEADER_BYTES"
    )]
    icap_max_header_size: Option<usize>,

    /// Which ICAP blocks carry the c-icap `X-Infection-Found` header: `blocks`
    /// (every one, a partial verdict under `Heuristics.Exav.*`) or
    /// `detections` (a signature match only). [default: blocks]
    ///
    /// The default is what makes a block visible to a client that decides
    /// clean-or-not from that header alone, such as a script that shells out to
    /// `c-icap-client` and greps the response. `detections` keeps the header
    /// meaning a database hit and nothing else, at the cost of those clients
    /// reading an unscannable object as clean.
    #[cfg(feature = "icap")]
    #[arg(
        long = "icap-infection-header",
        value_name = "WHEN",
        env = "EXAV_ICAP_INFECTION_HEADER",
        value_parser = icap::InfectionHeader::parse
    )]
    icap_infection_header: Option<icap::InfectionHeader>,

    /// What `--connect` hands the daemon for each file: `path` (default),
    /// `contents`, or `fd`.
    ///
    ///   path      the name only (`SCAN`). The daemon opens it, so it must see
    ///             the same filesystem and have permission on the path.
    ///   contents  the bytes (`INSTREAM`). The daemon needs no view of this
    ///             filesystem at all, which is what lets it run on another host.
    ///   fd        an open descriptor over the Unix socket (`FILDES`). A daemon
    ///             running as another user reads the file without permission to
    ///             open the path. Cheaper than `contents` (no copy), and Unix
    ///             sockets only — it rides on SCM_RIGHTS.
    ///
    /// `-` (stdin) has no path to name, so it always goes as contents.
    #[arg(
        long = "send-as",
        value_name = "WHAT",
        env = "EXAV_SEND_AS",
        value_parser = SendAs::parse,
        verbatim_doc_comment
    )]
    send_as: Option<SendAs>,

    /// Honour the clamd `SHUTDOWN` command, letting any client that can reach
    /// the daemon stop it. Off by default.
    ///
    /// A scanner that is not running does not report infected — it reports
    /// nothing, and a pipeline that reads "no answer" as "fine" passes
    /// everything. clamd honours `SHUTDOWN`; exav does not unless asked.
    #[arg(long = "allow-shutdown", env = "EXAV_ALLOW_SHUTDOWN", value_parser = env_switch())]
    allow_shutdown: bool,

    /// Daemon worker model (Unix): a worker count, or `threads`.
    /// [default: CPU cores]
    ///
    /// A count runs a prefork pool — one worker process per core, each scanning
    /// one job at a time under kernel-enforced per-job limits (see
    /// --max-scan-secs/-memory) and recycled per --max-jobs-per-worker, so a
    /// runaway scan is isolated and hard-killed. `threads` runs the listeners
    /// in one process instead, which cannot kill a single job but is the only
    /// model where both listeners share one set of counters.
    #[arg(
        long = "workers",
        value_name = "N|threads",
        env = "EXAV_WORKERS",
        value_parser = parse_workers
    )]
    workers: Option<usize>,

    /// Hard wall-clock budget, in seconds (0 = none). Unix only. In the prefork
    /// pool it is per scan job, and on expiry the worker is killed and the
    /// connection dropped; it also caps CPU time (RLIMIT_CPU). In a one-shot
    /// run it bounds the whole run, which then exits 3 saying so — running out
    /// of time is a scan that stopped short, not a scanner that failed. The
    /// deterministic in-core caps still apply first in every mode.
    /// [default in the pool: 120; unset otherwise]
    #[arg(
        long = "max-scan-secs",
        value_name = "SECS",
        env = "EXAV_MAX_SCAN_SECS"
    )]
    max_scan_time: Option<u64>,

    /// Address-space cap (RLIMIT_AS), bounding memory bombs. Unix only. Per
    /// worker in the prefork pool, whole-process in a one-shot run. Setting it
    /// also lowers the in-core extraction budget to fit inside it, so a scan
    /// reports a limit instead of being killed for hitting one. K/M/G/T
    /// suffixes; 0 = none. [default in the pool: 2G; unset otherwise]
    #[arg(
        long = "max-process-bytes",
        value_name = "SIZE",
        env = "EXAV_MAX_PROCESS_BYTES",
        value_parser = parse_size
    )]
    max_scan_memory: Option<u64>,

    /// Cap the per-shard automaton-BUILD transient (`--build-db` only): shard
    /// each large partition so no single Aho-Corasick construction exceeds ~this
    /// many bytes. NOTE this bounds the per-shard *transient*, not the total peak
    /// — the resident parsed-signature set (~2 GB for main+daily) sits under it,
    /// so peak ≈ this + that floor. K/M/G/T suffixes.
    ///
    /// This trades BUILD memory for SCAN structure: every shard is another walk
    /// of every buffer for as long as that database is in use. On a daily-only
    /// set, `256M` gave the PE partition 11 shards (15 walks per PE) against 3
    /// shards at `1G` (7 walks) — but the measured scan-time difference was
    /// **within run-to-run noise**, so do not expect a speed-up from raising it.
    ///
    /// The reason is worth knowing: partitions and shards hold *disjoint*
    /// pattern sets, so N walks are not N times the work — they match N
    /// different pattern sets over the same bytes. More walks means more state
    /// transitions but smaller, more cache-friendly automata, and the two effects
    /// largely cancel. Merging partitions to remove a walk was measured to be
    /// 10% SLOWER (see the target-0 note in `engine`).
    ///
    /// Use the largest value the build host can afford, on the general principle
    /// that fewer, larger automata are the simpler shape — but treat it as a
    /// build-memory knob, not a performance one.
    #[arg(
        long = "build-shard-bytes",
        value_name = "SIZE",
        env = "EXAV_BUILD_SHARD_BYTES",
        value_parser = parse_size
    )]
    max_build_memory: Option<u64>,

    /// Prefork only (requires --workers N): recycle a worker process after this
    /// many jobs to bound slow leaks/fragmentation (0 = never). Mirrors Apache
    /// MaxRequestsPerChild. [default: 1000]
    #[arg(
        long = "max-jobs-per-worker",
        value_name = "N",
        env = "EXAV_MAX_JOBS_PER_WORKER"
    )]
    max_jobs_per_worker: Option<u64>,

    /// Largest top-level input exav will scan. A larger file is reported
    /// LIMITS-EXCEEDED (never a silent OK, unlike ClamAV). K/M/G/T suffixes;
    /// `0` means no limit. exav default: no limit. `--clamav-compat` sets 100M.
    #[arg(
        long = "max-input-bytes",
        env = "EXAV_MAX_INPUT_BYTES",
        value_name = "SIZE",
        value_parser = parse_size
    )]
    max_input_bytes: Option<u64>,

    /// Where a streamed object goes once it is too large to hold in RAM
    /// (`INSTREAM`, stdin, an ICAP body): a directory, or `off` to never write
    /// one at all. [default: the platform temp directory, i.e. $TMPDIR]
    ///
    /// Point it at a filesystem with room, and one you are willing to see fill
    /// up: the alternative is that a large upload competes for space with
    /// everything else on the host.
    ///
    /// `off` makes --spill-threshold-bytes a hard per-object memory ceiling —
    /// anything larger is reported UNSCANNABLE, because there is nowhere left to
    /// put it. For a read-only root filesystem, a container with no writable
    /// temp directory, or a deployment that would rather refuse a large object
    /// than let a scanned payload touch a disk. Worst-case memory is then
    /// --spill-threshold-bytes times the number of concurrent scans.
    #[arg(long = "spill-dir", value_name = "DIR|off", env = "EXAV_SPILL_DIR")]
    spill_dir: Option<String>,

    /// How much of a streamed object is held in RAM before it spills to a temp
    /// file. K/M/G/T suffixes. [default: 16M]
    ///
    /// This is what bounds a listener's memory: a connection costs this much
    /// whatever the object on it weighs. Raising it trades RAM for fewer temp
    /// files; lowering it does the reverse.
    #[arg(
        long = "spill-threshold-bytes",
        value_name = "SIZE",
        env = "EXAV_SPILL_THRESHOLD_BYTES",
        value_parser = parse_size
    )]
    spill_threshold: Option<u64>,

    /// The most temp space one object may occupy. K/M/G/T suffixes; `0` means
    /// no limit. [default: 2G] [clamd.conf: StreamMaxLength]
    ///
    /// An object past it is reported UNSCANNABLE — never clean, and never a
    /// dropped connection. To stop spilling altogether use `--spill-dir off`;
    /// `0` here is the opposite, and reads as "no ceiling" like every other
    /// --max- flag — which leaves --max-total-spill-bytes as the only bound on
    /// one object.
    #[arg(
        long = "max-spill-bytes",
        value_name = "SIZE",
        env = "EXAV_MAX_SPILL_BYTES",
        value_parser = parse_size
    )]
    max_spill_bytes: Option<u64>,

    /// The most temp space every in-flight object may occupy **together**,
    /// across the whole process. K/M/G/T suffixes; `0` means no limit.
    /// [default: 8G]
    ///
    /// The one a per-object cap cannot stand in for: a hundred connections at
    /// 2G each is a 200G worst case, and filling the temp filesystem is a denial
    /// of service against the host that outlives the connection causing it.
    /// Size it against the free space on --spill-dir, not against the object
    /// size you expect.
    #[arg(
        long = "max-total-spill-bytes",
        value_name = "SIZE",
        env = "EXAV_MAX_TOTAL_SPILL_BYTES",
        value_parser = parse_size
    )]
    max_total_spill_bytes: Option<u64>,

    /// Cap on what decompression may *produce* across one top-level file:
    /// caps deep/structural analysis size and the summed extracted bytes with
    /// one value. K/M/G/T suffixes; `0` means no limit. exav defaults when
    /// unset: 256M deep-analysis, 1G extracted total. `--clamav-compat` sets
    /// 400M for both.
    #[arg(
        long = "max-extracted-bytes",
        env = "EXAV_MAX_EXTRACTED_BYTES",
        value_name = "SIZE",
        value_parser = parse_size
    )]
    max_extracted_bytes: Option<u64>,

    /// The most memory any **single** materialized object (a decompressed
    /// member/sub-container, an LZ window, a decrypted blob) may use. Every
    /// forced-materialization site obeys it. Not a cap on total
    /// memory: several buffers are live at once across nesting levels, and
    /// `--max-extracted-bytes` is what bounds their sum. K/M/G/T suffixes. exav
    /// default: 256M.
    #[arg(
        long = "max-object-bytes",
        env = "EXAV_MAX_OBJECT_BYTES",
        value_name = "SIZE",
        value_parser = parse_size
    )]
    max_buffer_bytes: Option<u64>,

    /// Cumulative scan-reach limit: the most bytes fed to the matcher across one
    /// top-level file (streamed members + re-scanned/carved regions). This is a
    /// **CPU/time** bound, NOT a memory bound — streamed members are scanned
    /// without being held in RAM (that is capped by --max-object-bytes), so this
    /// can be set far higher to fully scan multi-gigabyte members, paying only in
    /// scan time. Guards re-scanning/decompression-time bombs. K/M/G/T suffixes.
    /// exav default: 10G.
    #[arg(
        long = "max-matcher-bytes",
        env = "EXAV_MAX_MATCHER_BYTES",
        value_name = "SIZE",
        value_parser = parse_size
    )]
    max_scanned_bytes: Option<u64>,

    /// Maximum nesting depth for recursive unpacking. exav default: 16.
    /// `--clamav-compat` sets 17.
    #[arg(long = "max-depth", env = "EXAV_MAX_DEPTH", value_name = "N")]
    max_recursion: Option<u32>,

    /// Maximum number of members visited across the whole recursive walk.
    /// exav default: 100000 — higher than ClamAV's 10000 because exav descends
    /// into nested archives ClamAV does not, so the same file yields more
    /// countable members (see `Limits::max_members`). `--clamav-compat` sets
    /// 10000.
    #[arg(long = "max-members", env = "EXAV_MAX_MEMBERS", value_name = "N")]
    max_members: Option<u64>,

    /// Decode base64-encoded executables embedded in text/script files.
    /// On by default; off under --clamav-compat, which has no such reach.
    ///
    /// Spelled as a value rather than as `--no-base64` so an explicit choice can
    /// win over the compat preset, the way every other preset flag's does: a
    /// negative switch has no way to say "on", so under compat there would be no
    /// way to ask for it back.
    #[arg(
        long = "base64",
        value_name = "on|off",
        env = "EXAV_BASE64",
        value_parser = env_switch(),
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    base64: Option<bool>,

    /// Alert `Heuristics.Structured.CreditCardNumber` on a textual file holding
    /// N or more valid credit-card numbers. Off unless set.
    ///
    /// A leak detector rather than a malware one: what it finds is the
    /// organisation's own data on its way somewhere, so it says `--alert-` and
    /// not `--detect`. Needs the `dlp` feature. [clamscan: --structured-cc-count]
    #[arg(
        long = "alert-credit-cards",
        value_name = "N",
        env = "EXAV_ALERT_CREDIT_CARDS"
    )]
    structured_cc_count: Option<u32>,

    /// Alert `Heuristics.Structured.SSN` on a textual file holding N or more
    /// valid US Social Security numbers. Off unless set. See
    /// --alert-credit-cards. Needs the `dlp` feature.
    /// [clamscan: --structured-ssn-count]
    #[arg(long = "alert-ssns", value_name = "N", env = "EXAV_ALERT_SSNS")]
    structured_ssn_count: Option<u32>,

    /// Heuristic detectors to switch on, over and above the signature database:
    /// `none` (default), `all`, or a comma-separated list.
    ///
    ///   macros                  `Heuristics.OLE2.ContainsMacros` — an OLE2/OOXML
    ///                           document carrying VBA macros.
    ///   broken                  `Heuristics.Broken.Executable` — a PE/ELF/Mach-O
    ///                           magic whose headers do not parse.
    ///   broken-media            `Heuristics.Broken.Media.*` — a structurally
    ///                           invalid GIF, PNG, TIFF or JPEG.
    ///   partition-intersection  overlapping partition entries in a disk image.
    ///   phishing                `Heuristics.Phishing.Email.*` — a link whose
    ///                           visible text spoofs its href, hides the host
    ///                           behind userinfo, or is an IP under a brand name.
    ///   packed                  `Heuristics.Packed.*` — names the packer or
    ///                           protector wrapping an executable exav cannot
    ///                           unpack. Reported alongside the unscannable
    ///                           signal, not instead of it.
    ///   pua                     Potentially Unwanted Applications: load the
    ///                           `.??u` databases and keep `PUA.*` signatures.
    ///                           Applied at database load, not per scan.
    ///
    /// What an *unscannable* object becomes is not here — that is a verdict
    /// question, and --partial-as answers it.
    #[arg(
        long = "detect",
        value_name = "LIST",
        env = "EXAV_DETECT",
        value_parser = policy::Detectors::parse,
        verbatim_doc_comment
    )]
    detect: Option<policy::Detectors>,

    /// Which status an object exav could not fully examine is reported as.
    /// One value for all of them, or per category, e.g.
    /// `password-protected=ok,limits-exceeded=found`.
    ///
    ///   partial  What it is. Exit 3, under one of the three categories below.
    ///            [default]
    ///   ok       Deliver it as clean. Exit 0, OK, an ICAP 204. This is what
    ///            ClamAV does for an encrypted archive and what c-icap does past
    ///            MaxObjectSize; a real trade, not a mistake, and exav will not
    ///            make it quietly — every such object is logged.
    ///   found    Report it as a detection named `Heuristics.*`. Exit 1, FOUND,
    ///            X-Infection-Found — an ordinary hit to any client, and what
    ///            ClamAV's --alert-exceeds-max / --alert-encrypted produce.
    ///   error    Report it as an operational failure. Exit 2, for a caller that
    ///            would rather not learn a fourth exit code.
    ///
    /// The value names the status, and status and exit code are the same thing
    /// said twice: OK 0, FOUND 1, ERROR 2, PARTIAL 3.
    ///
    /// Categories: limits-exceeded, unscannable, password-protected.
    ///
    /// On the clamd wire `partial` and `error` are both an `ERROR` reply: that
    /// protocol's vocabulary is closed, and a real client reads a word it does
    /// not know as OK — a fail-open exav will not risk. They differ only where
    /// there is an exit code to differ in.
    #[arg(
        long = "partial-as",
        value_name = "STATUS",
        env = "EXAV_PARTIAL_AS",
        value_parser = policy::PartialAs::parse,
        verbatim_doc_comment
    )]
    partial_as: Option<policy::PartialAs>,

    /// Password to try when decrypting encrypted archive members (ZIP
    /// ZipCrypto/AES). Repeatable (comma-separated in the environment):
    /// `--password a --password b` builds a pool, tried in order. Unioned with
    /// any passwords loaded from `.pwdb` databases. When a scan reports
    /// `password-protected`, re-run with the right password.
    #[arg(
        long = "passwords",
        value_name = "PW",
        env = "EXAV_PASSWORDS",
        value_delimiter = ','
    )]
    password: Vec<String>,

    /// Shortcut that sets exav to a stock ClamAV build's documented defaults for
    /// apples-to-apples differential testing. Equivalent to `--max-input-bytes
    /// 100M --max-extracted-bytes 400M --max-depth 17 --max-members 10000
    /// --base64 off`, plus narrowing the unpacking reach to the formats stock
    /// ClamAV handles and reporting under ClamAV's vocabulary where the two
    /// engines name the same fact differently. This DELIBERATELY REDUCES exav's
    /// detection capability so results reproduce clamscan's — it is a
    /// diff-testing mode, NOT recommended for production. Off by default (full
    /// capability). Each preset flag can still be set or overridden on its own;
    /// an explicit flag wins over the preset.
    #[arg(long = "clamav-compat", env = "EXAV_CLAMAV_COMPAT", value_parser = env_switch())]
    clamav_compat: bool,

    /// Measure where scan time goes, per matcher.
    ///
    /// Scanning files, this replaces the normal output with a CSV row per file
    /// (`_us`, `_calls`, `_bytes` per matcher) — a performance matrix over a
    /// dataset. On a listener there is no per-file output to put it in, so the
    /// same numbers accumulate and are reported through the clamd `STATS`
    /// command as a `MATCHERSTATS` line.
    ///
    /// One flag rather than two, because which of those happens is a property of
    /// what exav was asked to do, not a second decision. Off by default: it
    /// times every matcher invocation, and there are many per scan. Scan counts,
    /// bytes and wall time are always collected.
    #[arg(long = "profile", env = "EXAV_PROFILE", value_parser = env_switch())]
    profile: bool,

    /// Log any scan taking longer than this many seconds, naming the object and
    /// (with --profile) which matchers the time went to. `off` disables it.
    /// [default: 10]
    ///
    /// A listener holds nothing to go back to, so an object that pins a core is
    /// gone by the time anyone notices the load. This is what leaves a trace.
    /// Unlike --max-scan-secs it stops nothing; see that flag for why bounding a
    /// scan needs the worker pool.
    #[arg(
        long = "slow-scan-secs",
        value_name = "SECS|off",
        env = "EXAV_SLOW_SCAN_SECS",
        value_parser = parse_secs_or_off
    )]
    slow_scan_secs: Option<u64>,

    /// Seconds between the scan-totals lines a listener writes to its log —
    /// scans, bytes, mean and slowest scan, throughput. `off` disables them.
    /// [default: 300]
    ///
    /// The clamd `STATS` command reports the same figures on demand, but only
    /// where a clamd listener exists and only for the process that answers: an
    /// ICAP-only deployment binds no clamd port, and under the worker pool ICAP
    /// is a forked child of its own. The log is the channel every arrangement
    /// has. Silent while nothing is being scanned.
    #[arg(
        long = "metrics-secs",
        value_name = "SECS|off",
        env = "EXAV_METRICS_SECS",
        value_parser = parse_secs_or_off
    )]
    metrics_secs: Option<u64>,

    /// Emit one JSON object per scanned input (newline-delimited JSON) instead
    /// of the human `PATH: … FOUND/OK` lines, plus a final JSON summary object
    /// (unless `--quiet`). Machine-readable output for tooling/pipelines.
    #[arg(long = "json", env = "EXAV_JSON", value_parser = env_switch())]
    json: bool,

    /// Print informational findings (type, entropy, imphash, ml score). Those
    /// come from the local scanner, and a daemon reply carries a verdict and
    /// nothing else, so in client mode this prints what the client itself knows:
    /// which daemon answered, and the command sent for each target.
    #[arg(short = 'v', long = "verbose", env = "EXAV_VERBOSE", value_parser = env_switch())]
    verbose: bool,

    /// Print only errors and detections: no per-file `OK` lines, no summary.
    ///
    /// The single output dial, with -v at the other end. One flag rather than
    /// one per suppressed line, because how much output a run makes is one
    /// setting: separate switches for the `OK` lines and for the summary end up
    /// meaning the same thing without anyone noticing.
    #[arg(long = "quiet", env = "EXAV_QUIET", value_parser = env_switch())]
    quiet: bool,

    /// Report every matching signature, not just the first.
    #[arg(long = "all-matches", env = "EXAV_ALL_MATCHES", value_parser = env_switch())]
    allmatch: bool,

    /// Skip files whose path matches this regex. Repeatable on the command
    /// line; the environment variable sets one pattern, since a comma is a legal
    /// character in a regex and splitting on it would silently cut one in half.
    #[arg(long = "exclude", value_name = "REGEX", env = "EXAV_EXCLUDE")]
    exclude: Vec<String>,

    /// Skip directories whose path matches this regex. Repeatable; see --exclude
    /// for the environment form.
    #[arg(long = "exclude-dir", value_name = "REGEX", env = "EXAV_EXCLUDE_DIR")]
    exclude_dir: Vec<String>,

    /// Only scan files whose path matches this regex. Repeatable; see --exclude
    /// for the environment form.
    #[arg(long = "include", value_name = "REGEX", env = "EXAV_INCLUDE")]
    include: Vec<String>,
}

/// Compiled path filters from --exclude/--exclude-dir/--include.
struct Filters {
    exclude: Vec<regex::Regex>,
    exclude_dir: Vec<regex::Regex>,
    include: Vec<regex::Regex>,
}

impl Filters {
    fn compile(cli: &Cli) -> Result<Self, regex::Error> {
        let c = |pats: &[String]| -> Result<Vec<regex::Regex>, regex::Error> {
            pats.iter().map(|p| regex::Regex::new(p)).collect()
        };
        Ok(Self {
            exclude: c(&cli.exclude)?,
            exclude_dir: c(&cli.exclude_dir)?,
            include: c(&cli.include)?,
        })
    }

    fn dir_excluded(&self, path: &Path) -> bool {
        let s = path.to_string_lossy();
        self.exclude_dir.iter().any(|r| r.is_match(&s))
    }

    /// True if this file path should be skipped per the filters.
    fn file_skipped(&self, path: &Path) -> bool {
        let s = path.to_string_lossy();
        if self.exclude.iter().any(|r| r.is_match(&s)) {
            return true;
        }
        if !self.include.is_empty() && !self.include.iter().any(|r| r.is_match(&s)) {
            return true;
        }
        false
    }
}

/// What walking a tree found: the regular files to scan, and the paths nobody
/// could reach.
pub(crate) struct Walk {
    pub files: Vec<PathBuf>,
    /// One ready-to-print `"<path>: <reason> ERROR"` line per unreachable path.
    pub errors: Vec<String>,
    /// Directories descended into, including `root` when it is one.
    pub dirs: u64,
}

/// How far into a directory target a walk goes.
///
/// `clamscan DIR` scans the directory's immediate files and `clamscan -r DIR`
/// descends into the tree; both are working command lines, so both are here.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Descent {
    /// The named directory's own files. A subdirectory is listed and left alone.
    Immediate,
    /// The whole tree below the named directory.
    Recursive,
}

/// Walk `root` for regular files, keeping the paths the walk could not reach.
///
/// Every scan surface — one-shot `-r`, the client, CONTSCAN, the daemon's
/// all-match tree — needs the same two facts, and the second is the one easy to
/// drop. An unreadable directory or a file removed mid-walk is a part of the
/// tree nothing looked at; a surface that silently omits it reports on what it
/// managed to reach and calls that the answer. That is a clean verdict over
/// unscanned bytes, so the errors come back alongside the files and every
/// caller has to do something with them.
///
/// One walker rather than one per surface: four copies is four chances for the
/// next one to forget the error arm, which is how this went wrong to begin with.
/// `filters` prunes excluded directories before descending and skips excluded
/// files; `None` walks everything.
pub(crate) fn walk_tree(root: &Path, filters: Option<&Filters>, descent: Descent) -> Walk {
    let mut out = Walk {
        files: Vec::new(),
        errors: Vec::new(),
        dirs: 0,
    };
    let mut wd = WalkDir::new(root).follow_links(false);
    if descent == Descent::Immediate {
        // Depth 1 is the named directory's own entries: its files are yielded
        // and its subdirectories are listed without being opened.
        wd = wd.max_depth(1);
    }
    let it = wd.into_iter();
    // `filter_entry` prunes a directory before its contents are read, so an
    // excluded tree costs one match rather than a full descent.
    let it: Box<dyn Iterator<Item = walkdir::Result<walkdir::DirEntry>>> = match filters {
        Some(f) => {
            Box::new(it.filter_entry(|e| !(e.file_type().is_dir() && f.dir_excluded(e.path()))))
        }
        None => Box::new(it),
    };
    for entry in it {
        match entry {
            Ok(e) if e.file_type().is_file() => {
                if filters.is_none_or(|f| !f.file_skipped(e.path())) {
                    out.files.push(e.into_path());
                }
            }
            // Only the named directory counts without recursion: a subdirectory
            // that was listed and never opened is not a directory the scan
            // looked at, and clamscan's summary counts the same one.
            Ok(e) if e.file_type().is_dir() => {
                if descent == Descent::Recursive || e.depth() == 0 {
                    out.dirs += 1;
                }
            }
            Ok(_) => {}
            Err(e) => {
                let at = e
                    .path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| root.display().to_string());
                out.errors.push(format!("{at}: {e} ERROR"));
            }
        }
    }
    out
}

#[derive(Default)]
struct Totals {
    scanned: u64,
    infected: u64,
    errors: u64,
    limits: u64,
    /// Directories descended into, for the clamscan-style summary line.
    dirs: u64,
    /// Total bytes of the scanned files (for the clamscan-style "Data scanned").
    data_scanned: u64,
}

/// Every endpoint this run listens on, or the reason it cannot.
///
/// One function so every caller reads the same answer, and so a malformed
/// address stops the run at startup rather than at the moment a listener would
/// have been bound.
fn listeners(cli: &Cli) -> Result<Vec<endpoint::Endpoint>, String> {
    endpoint::listeners(&cli.listen)
}

/// The clamd endpoint, if one was asked for.
fn clamd_endpoint(cli: &Cli) -> Option<endpoint::Endpoint> {
    listeners(cli)
        .ok()?
        .into_iter()
        .find(|e| e.proto == endpoint::Proto::Clamd)
}

/// The ICAP endpoint, if one was asked for.
///
/// Without the `icap` feature there is no such listener and the whole ICAP path
/// compiles out — an `icap://` address is then refused at startup rather than
/// silently ignored, because a listener that was asked for and never bound is a
/// deployment that thinks it is scanning.
#[cfg(feature = "icap")]
fn icap_endpoint(cli: &Cli) -> Option<endpoint::Endpoint> {
    listeners(cli)
        .ok()?
        .into_iter()
        .find(|e| e.proto == endpoint::Proto::Icap)
}

/// Whether this run serves anything at all.
///
/// Asked of the parsed addresses rather than the raw values, because an empty
/// one names no listener: `EXAV_LISTEN=` is how a container switches off the
/// address its image's `ENV` set, and reading that as "serves" would give it a
/// server that binds nothing.
fn serves(cli: &Cli) -> bool {
    !listeners(cli).unwrap_or_default().is_empty()
}

/// Whether this run is the updater half of a two-container deployment: keep the
/// signature volume current and serve nothing.
///
/// Inferred rather than declared, so the command line cannot contradict itself.
/// A flag saying "update only" alongside a listener is a run whose two halves
/// disagree, and it takes a conflict check to catch; asking to update and not
/// asking to listen says the same thing and has no second half to disagree with.
fn updater_only(cli: &Cli) -> bool {
    cli.auto_update && !serves(cli) && cli.paths.is_empty() && cli.build_db.is_none()
}

/// Default daemon worker count: one per CPU core on Unix (the prefork pool),
/// 0 elsewhere (the thread model — Unix-only `fork` isn't available).
fn default_workers() -> usize {
    #[cfg(unix)]
    {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Seconds a scan may take before it is logged, unless `--slow-scan-secs` says
/// otherwise.
///
/// On by default, and high enough that a healthy deployment never sees a line:
/// the point is that the *first* time an object pins a core, the log already
/// names it. A default of "off" would mean the answer is only ever available to
/// someone who anticipated needing it.
const DEFAULT_SLOW_SCAN_SECS: u64 = 10;

/// Seconds between a listener's scan-totals lines, unless `--metrics-secs` says
/// otherwise. Rare enough to be free, frequent enough that a load spike leaves
/// a trace someone can find afterwards.
const DEFAULT_METRICS_SECS: u64 = 300;

/// The reporting interval a serving process should use.
fn metrics_interval(cli: &Cli) -> std::time::Duration {
    std::time::Duration::from_secs(cli.metrics_secs.unwrap_or(DEFAULT_METRICS_SECS))
}

/// Die quietly when the reader of our output goes away, the way every other
/// Unix filter does.
///
/// Rust's runtime sets `SIGPIPE` to `SIG_IGN` before `main`, so a write to a
/// closed pipe returns `EPIPE` instead of killing the process — and `println!`
/// turns that error into a panic. `exav /data | head -3` would then print a Rust
/// backtrace at a user who did something completely ordinary.
///
/// Restoring the default disposition makes the process die on the signal
/// instead, silently, which is what `head` closing its end is supposed to mean.
/// The listeners want the opposite — a client hanging up must not stop a daemon
/// — so each of them sets `SIG_IGN` back when it starts serving.
#[cfg(unix)]
fn restore_default_sigpipe() {
    // SAFETY: `signal` here only sets this process's own disposition for one
    // signal, before any thread is spawned or any output is written.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restore_default_sigpipe() {}

/// The listener's disposition: a peer that hangs up costs one connection, not
/// the process. The inverse of [`restore_default_sigpipe`], which `main` runs
/// first for the sake of the one-shot scan.
#[cfg(all(unix, feature = "icap"))]
fn ignore_sigpipe() {
    // SAFETY: as above — this process's own disposition for one signal, before
    // any connection is accepted.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// Nothing to do off Unix: there is no `SIGPIPE`, and a peer that hangs up
/// mid-response surfaces as an ordinary write error on the socket. Provided so
/// the ICAP listener's call sites stay unconditional — gating each of them
/// instead is how this came to not compile for Windows at all.
#[cfg(all(not(unix), feature = "icap"))]
fn ignore_sigpipe() {}

fn main() -> ExitCode {
    restore_default_sigpipe();
    let mut cli = Cli::parse();

    // Before any role is chosen, so it covers every one of them.
    if let Err(msg) = check_flag_conflicts(&cli) {
        eprintln!("exav: {msg}");
        return ExitCode::from(2);
    }

    // Installed before anything can buffer an object, and once: every surface
    // that materializes a stream reads these, so a one-shot scan of stdin and an
    // ICAP listener spill under the same rules.
    if let Err(msg) = configure_spill(&cli) {
        eprintln!("exav: {msg}");
        return ExitCode::from(2);
    }

    // Same reason, same place: every scan on every surface asks these before it
    // reports anything, so they have to be installed before the first one runs.
    //
    // `--clamav-compat` reports a partial as `ok`, because that is what a stock
    // ClamAV build answers for this whole class — over `--max-filesize`, an
    // encrypted archive, a container it cannot decode: `OK`, exit 0. A
    // differential run that answered `PARTIAL` where clamscan answers `OK` would
    // report a difference on every such file that is nothing to do with
    // detection. An explicit `--partial-as` still wins, as every value in the
    // preset does, and the objects are logged either way.
    policy::configure(cli.partial_as.unwrap_or(if cli.clamav_compat {
        policy::PartialAs::uniform(policy::PartialStatus::Ok)
    } else {
        policy::PartialAs::default()
    }));
    metrics::configure(
        cli.profile,
        match cli.slow_scan_secs.unwrap_or(DEFAULT_SLOW_SCAN_SECS) {
            0 => None,
            n => Some(std::time::Duration::from_secs(n)),
        },
    );

    // Open the log file before anything scans so a failure is reported up front
    // rather than after a long scan whose results then have nowhere to go, and
    // before the role is chosen so a long-running listener gets the same file a
    // one-shot scan does.
    if let Some(path) = cli.log.clone() {
        if let Err(e) = log_open(&path) {
            eprintln!("exav: --log {}: {e}", path.display());
            return ExitCode::from(2);
        }
    }

    // Expand --files-from into `paths` FIRST, so every downstream mode (local,
    // client, stdin) sees one uniform target list and none of them needs to know
    // the flag exists.
    if let Some(list) = cli.file_list.clone() {
        match read_path_list(&list) {
            Ok(mut extra) => cli.paths.append(&mut extra),
            Err(e) => {
                eprintln!("exav: --files-from {}: {e}", list.display());
                return ExitCode::from(2);
            }
        }
        if cli.paths.is_empty() {
            eprintln!("exav: --files-from {} contained no paths", list.display());
            return ExitCode::from(2);
        }
    }

    // Every listener address is parsed once, here, so a malformed one stops the
    // run before anything is loaded rather than when a bind is attempted.
    if let Err(e) = listeners(&cli) {
        eprintln!("exav: --listen: {e}");
        return ExitCode::from(2);
    }

    // Client mode: `--connect` with paths delegates the scan to a running
    // daemon (no DB load here). The direction is the flag, so there is nothing
    // to infer from what else is on the line.
    if cli.connect.is_some() && !cli.paths.is_empty() {
        return run_client(&cli);
    }

    let serves = serves(&cli);
    let updater_only = updater_only(&cli);

    if !serves && !updater_only && cli.build_db.is_none() && cli.paths.is_empty() {
        eprintln!("exav: no input; provide PATH(s), `-` (stdin), or --listen");
        return ExitCode::from(2);
    }

    // The per-job limits are enforced by the kernel inside worker processes, so
    // they only exist with a prefork pool. Reject them with workers=0 rather
    // than silently ignoring them.
    // The prefork pool (and its per-job limits) only exists for the daemon, with
    // workers > 0. Default to the CPU-core count on Unix; --workers 0 forces the
    // in-process thread model. One-shot scans never use the pool.
    let pool_workers = if clamd_endpoint(&cli).is_some() {
        cli.workers.unwrap_or_else(default_workers)
    } else {
        0
    };

    // Signatures first: `--auto-update` creates the directory, fetches every
    // configured source (or waits for a sidecar to write one) and settles where
    // the database is loaded from, all before the load below reads it. The
    // periodic half starts once that load has succeeded.
    #[cfg(unix)]
    let auto_update = {
        // Only the prefork supervisor acts on a reload request; anywhere else
        // the mtime watch on the same path is what notices.
        let reload = if pool_workers > 0 {
            signatures::Reload::Signal
        } else {
            signatures::Reload::Watch
        };
        if cli.auto_update {
            if updater_only {
                if let Some(msg) = signatures::updater_only_error(&cli) {
                    eprintln!("exav: {msg}");
                    return ExitCode::from(2);
                }
            }
            match signatures::start(&mut cli, reload) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("exav: {e}");
                    return ExitCode::from(2);
                }
            }
        } else {
            if let Some(msg) = signatures::unused_sources_notice(&cli) {
                eprintln!("exav: {msg}");
            }
            None
        }
    };
    #[cfg(not(unix))]
    if cli.auto_update {
        eprintln!("exav: --auto-update is only supported on Unix");
        return ExitCode::from(2);
    }

    // Updater-only: the sources are fetched and kept current for whoever serves
    // the directory, and this process never loads a database of its own.
    #[cfg(unix)]
    if updater_only {
        match auto_update {
            Some(a) => a.refresh_forever(),
            // `updater_only_error` already refused a run with no source, so the
            // only way here is a build with no updater to run.
            None => {
                eprintln!(
                    "exav: fetching signatures needs the updater — build with \
                     `--features http-update`"
                );
                return ExitCode::from(2);
            }
        }
    }

    if pool_workers == 0 {
        // `--max-jobs-per-worker` counts jobs before a worker is recycled, so it
        // means nothing without workers. The other two bound a scan, and a scan
        // outside the pool needs bounding just as much — arguably more, since
        // there is no parent to reap a run that never ends.
        if cli.max_jobs_per_worker.is_some() {
            eprintln!(
                "exav: --max-jobs-per-worker only applies to the daemon worker pool \
                 (needs --listen clamd://… and --workers > 0)"
            );
            return ExitCode::from(2);
        }
        // A clamd listener under `--workers threads` also lands here, and it is
        // a long-running server rather than one scan. `apply_oneshot_limits` arms a
        // process-wide `ITIMER_REAL`, which for a server means the whole daemon
        // exits that many seconds after startup — mid-scan, or while idle. The
        // thread model has no per-job timer to enforce the flag with, so it is
        // refused rather than turned into a countdown to shutdown.
        //
        // The ICAP server is the same shape — threads, no per-job kill — so the
        // flag is refused there for the same reason.
        if serves && cli.max_scan_time.is_some() {
            // Refused rather than quietly downgraded: the flag means "kill the
            // job", and a mode where it meant something weaker would be worse
            // than not having it. But an operator reaching for it has a real
            // problem, so the refusal names what does bound a scan here.
            eprintln!(
                "exav: --max-scan-secs needs the worker pool (--listen clamd://… \
                 with --workers N); the in-process thread model has no way to \
                 stop one job without stopping the daemon"
            );
            eprintln!(
                "exav: on this listener a scan is bounded by work, not time: \
                 --max-matcher-bytes (default 10G) is the per-object CPU bound, \
                 with --max-depth and --max-members. --slow-scan-secs logs \
                 the objects that run long so you can see which they are."
            );
            return ExitCode::from(2);
        }
        // A memory cap is still meaningful for the thread-model daemon: it
        // bounds the process, which is all there is to bound.
        #[cfg(unix)]
        daemon::apply_oneshot_limits(
            if serves { None } else { cli.max_scan_time },
            cli.max_scan_memory,
        );
        #[cfg(not(unix))]
        if cli.max_scan_time.is_some() || cli.max_scan_memory.is_some() {
            eprintln!(
                "exav: --max-scan-secs and --max-process-bytes need the kernel limits \
                 exav only sets on Unix; the in-core budgets still apply"
            );
        }
    }

    let db = match load_db(&cli) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("exav: {e}");
            return ExitCode::from(2);
        }
    };

    // Refuse to operate with no real signature database (absent, empty, or a
    // valid-but-signature-less DB) — a scan or daemon would report real malware as
    // clean against the near-zero-coverage EICAR-only baseline, a silent miss.
    // Applies to one-shot scans, the listeners, and --build-db alike. Opt into the
    // baseline explicitly with --allow-no-db (testing/CI only).
    if is_effectively_empty(&db) && !cli.allow_no_db {
        eprintln!(
            "exav: no signature database loaded — refusing to run (it would report real \
             malware as clean). Load signatures with -d/--sigs-dir, or pass --allow-no-db \
             to use the built-in EICAR-only baseline (testing only)."
        );
        return ExitCode::from(2);
    }

    // The database is loaded, so the periodic re-check can start behind it: the
    // first tick is then a cheap conditional check rather than a re-download of
    // what was just fetched.
    #[cfg(unix)]
    if let Some(a) = auto_update {
        a.poll_in_background();
    }

    if serves {
        return run_listeners(&cli, db, pool_workers);
    }

    if let Some(out) = &cli.build_db {
        return match exav_core::database::save(&db, out) {
            Ok(()) => {
                if !cli.quiet {
                    println!(
                        "exav: compiled {} signatures into {}",
                        db.signature_count(),
                        out.display()
                    );
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("exav: writing database to {}: {e}", out.display());
                ExitCode::from(2)
            }
        };
    }

    let mut opts = build_scan_options(&cli);
    // Keep the three layers in their intended order outside the pool too: the
    // in-core budget decides first and produces a verdict, and the kernel cap
    // is only the backstop. Without this the 1 GiB default budget can exceed
    // an address space the operator just asked for, and the kernel wins — so a
    // scan that should report a limit gets killed for hitting one.
    #[cfg(unix)]
    if pool_workers == 0 {
        if let Some(bytes) = cli.max_scan_memory {
            daemon::fit_limits_to_job_memory(&mut opts, bytes);
        }
    }
    let opts = opts;

    let filters = match Filters::compile(&cli) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("exav: invalid filter regex: {e}");
            return ExitCode::from(2);
        }
    };

    let mut totals = Totals::default();
    let scan_start = std::time::Instant::now();
    if cli.profile {
        println!("{}", perf::header());
    }
    for path in &cli.paths {
        match path.to_str() {
            Some("-") => scan_stdin(&db, &cli, &mut totals),
            #[cfg(feature = "http-scan")]
            Some(s) if s.starts_with("http://") || s.starts_with("https://") => {
                scan_url(s, &db, &opts, &cli, &mut totals)
            }
            #[cfg(not(feature = "http-scan"))]
            Some(s) if s.starts_with("http://") || s.starts_with("https://") => {
                totals.errors += 1;
                eprintln!("{s}: URL scanning needs a build with `--features http-scan` ERROR");
            }
            _ => scan_target(path, &db, &opts, &cli, &filters, &mut totals),
        }
    }

    if !cli.quiet && !cli.profile {
        if cli.json {
            emit_json_summary(&totals, scan_start.elapsed());
        } else {
            print_summary(&db, &totals, scan_start.elapsed(), cli.verbose);
        }
    }

    exit_code(&totals)
}

/// What a finished run exits with.
///
///   0  clean — everything was scanned, nothing matched
///   1  a detection
///   2  an error: exav could not do its job (an unreadable path, a database that
///      would not load). This is `clamscan`'s meaning of 2, and only that.
///   3  not scanned: exav worked, but something could not be fully examined —
///      `LIMITS-EXCEEDED`, `UNSCANNABLE`, `PASSWORD-PROTECTED`.
///
/// The last two are separated because they ask different things of a caller. A
/// `2` says the scanner is broken or misconfigured and the run's result cannot
/// be trusted; a `3` says the scanner worked and this particular object needs a
/// policy decision. Collapsing them into one code — which is what `clamscan`
/// does, by calling the whole third class `OK` and exiting 0 — is what leaves an
/// operator unable to tell "my scanner is down" from "someone uploaded an
/// encrypted zip".
///
/// A detection outranks both. Finding malware is conclusive: that a limit was
/// also hit, or another file failed to open, does not make the match less true.
/// An error outranks a partial file for the opposite reason — it casts doubt
/// on the whole run, where a partial file is a fact *about that file*.
fn exit_code(totals: &Totals) -> ExitCode {
    if totals.infected > 0 {
        ExitCode::from(1)
    } else if totals.errors > 0 {
        ExitCode::from(2)
    } else if totals.limits > 0 {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    }
}

/// The path the daemon should watch for on-disk signature changes, mirroring how
/// `load_db` picks its source. For `--database` this is the given path whether it
/// is a **directory** (a sidecar/freshclam rewriting the volume) or a single
/// **file** (a prebuilt `.exavdb` database atomically swapped in place) — the mtime poll
/// handles both, so a database-file deployment hot-reloads on swap without needing
/// an explicit `RELOAD`. `None` only for the built-in baseline (no source path).
fn reload_watch_dir(cli: &Cli) -> Option<PathBuf> {
    if let Some(p) = &cli.database {
        return p.exists().then(|| p.clone());
    }
    cli.sigs.is_dir().then(|| cli.sigs.clone())
}

/// Serve until the process is stopped.
///
/// Each `--listen` address is a listener rather than a mode, so either protocol
/// or both can be asked for and one loaded database answers on all of them. The clamd
/// listener runs a prefork worker pool where it can (`--workers` > 0 on Unix)
/// and in-process threads otherwise; ICAP is a threaded server either way,
/// because its connections are long-lived and keep-alive, and one job per
/// process would let a handful of idle proxy connections occupy the whole pool.
///
/// Under the pool the two therefore live in separate processes: the supervisor
/// binds both listeners, forks the scan workers, and forks one more child for
/// ICAP. Every child shares the warmed database copy-on-write, and a reload
/// re-forks all of them from the new one.
fn run_listeners(cli: &Cli, db: Scanner, pool_workers: usize) -> ExitCode {
    let mut opts = build_scan_options(cli);
    // The pool does this per worker (`run_prefork`). Everywhere else it happens
    // here: the in-core extraction budget has to fit inside the address space
    // the operator asked for, or the kernel wins and a scan that should report
    // a limit is killed instead.
    #[cfg(unix)]
    if pool_workers == 0 {
        if let Some(bytes) = cli.max_scan_memory {
            daemon::fit_limits_to_job_memory(&mut opts, bytes);
        }
    }
    let opts = opts;

    // Watch the path the database came from so a sidecar rewriting it triggers a
    // reload without an explicit `RELOAD`. Guard the reload itself: if the
    // source was emptied or clobbered out from under us, refuse the swap and
    // keep serving the current database rather than silently downgrading to the
    // near-zero-coverage baseline.
    let watch = reload_watch_dir(cli);
    let reload_source = watch
        .as_ref()
        .map(|p| format!("reloaded signature source {}", p.display()))
        .unwrap_or_else(|| "reloaded signature source".to_string());
    let allow_no_db = cli.allow_no_db;
    let reload = || load_db(cli).and_then(|db| guard_not_empty(db, &reload_source, allow_no_db));

    #[cfg(feature = "icap")]
    let icap_server = if icap_endpoint(cli).is_some() {
        let cfg = match icap::config_from_cli(cli) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("exav: {e}");
                return ExitCode::from(2);
            }
        };
        // Bound before anything is spawned or forked, so a busy port or a bad
        // address is reported by the process that was asked to listen rather
        // than by a child nobody is watching.
        match icap::bind(cfg) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("exav: icap: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };

    let db = std::sync::Arc::new(db);
    let opts = std::sync::Arc::new(opts);

    // ICAP alone: its own listener thread, and this thread becomes the
    // supervisor that watches the signature source and swaps the database in.
    #[cfg(feature = "icap")]
    let clamd = clamd_endpoint(cli);
    #[cfg(not(feature = "icap"))]
    let clamd = clamd_endpoint(cli);

    #[cfg(feature = "icap")]
    if clamd.is_none() {
        let server = icap_server.expect("an icap:// address is the only listener asked for");
        // A proxy that hangs up mid-response must cost one connection, not the
        // listener — the same reason the clamd daemon does this. Set here rather
        // than inside the ICAP module, which is `forbid(unsafe_code)` and stays
        // that way.
        ignore_sigpipe();
        return icap::serve_alone(server, db, opts, watch, &reload, metrics_interval(cli));
    }

    // `?max-connections=` on the clamd address, the same option the ICAP one
    // reads. Only the thread model consults it: the prefork pool bounds
    // concurrency by its worker count instead, so a second cap there would be a
    // setting with nothing to do.
    let clamd_max_connections = clamd
        .as_ref()
        .and_then(|e| e.max_connections)
        .unwrap_or(daemon::DEFAULT_MAX_CONNECTIONS);
    let addr = match clamd.map(|e| e.addr) {
        Some(endpoint::Addr::Tcp(a)) => daemon::ListenAddr::Tcp(a),
        #[cfg(unix)]
        Some(endpoint::Addr::Unix { path, mode }) => daemon::ListenAddr::Unix {
            path,
            mode: mode.unwrap_or(daemon::DEFAULT_SOCKET_MODE),
        },
        #[cfg(not(unix))]
        Some(endpoint::Addr::Unix { .. }) => {
            eprintln!("exav: a Unix-socket address needs a Unix platform; use host:port");
            return ExitCode::from(2);
        }
        None => {
            eprintln!("exav: no listener to serve");
            return ExitCode::from(2);
        }
    };

    // A prefork worker pool (--workers N > 0) is the isolated/killable model;
    // it's Unix-only (relies on fork for COW DB-sharing + kernel limits).
    #[cfg(unix)]
    if pool_workers > 0 {
        // Defaults live here (not in clap) so an unset flag is distinguishable
        // from an explicit one for the workers=0 validation in `main`.
        let scan_time = cli.max_scan_time.unwrap_or(120);
        let cfg = daemon::PoolConfig {
            workers: pool_workers,
            max_scan_time: std::time::Duration::from_secs(scan_time),
            max_memory_bytes: cli.max_scan_memory.unwrap_or(2 * 1024 * 1024 * 1024),
            // Bound CPU time too (catches a busy loop that an I/O-wait-free
            // wall clock would also catch, but as a kernel-level backstop).
            max_cpu_secs: scan_time,
            max_jobs: cli.max_jobs_per_worker.unwrap_or(1000),
            allow_shutdown: shutdown_allowed(cli.allow_shutdown),
        };
        #[cfg(feature = "icap")]
        let icap_child = icap_server.map(|s| icap::forked_child(s, metrics_interval(cli)));
        #[cfg(not(feature = "icap"))]
        let icap_child: Option<daemon::SideListener> = None;
        return match daemon::run_prefork(db, addr, opts, cfg, watch, &reload, icap_child.as_ref()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("exav: daemon error: {e}");
                ExitCode::from(2)
            }
        };
    }
    #[cfg(not(unix))]
    if pool_workers > 0 {
        eprintln!("exav: --workers is only supported on Unix; using in-process threads");
    }

    // Thread model: one process, so one reporter covers every listener it runs.
    metrics::spawn_reporter(metrics_interval(cli), "daemon");

    // With ICAP alongside, the clamd listener moves to a thread of its own so
    // this one can stay the supervisor that watches the signature source — the
    // arrangement ICAP already has when it serves alone.
    #[cfg(feature = "icap")]
    if let Some(server) = icap_server {
        let (clamd_db, clamd_opts) = (std::sync::Arc::clone(&db), std::sync::Arc::clone(&opts));
        let allow_shutdown = shutdown_allowed(cli.allow_shutdown);
        // Before the thread starts, for the same reason the ICAP-only path sets
        // it before serving. The disposition is process-wide, so leaving it to
        // `daemon::run` on the new thread would leave this one serving ICAP
        // under `SIG_DFL` until that thread got there — a window in which a
        // proxy hanging up mid-response kills the whole process.
        ignore_sigpipe();
        std::thread::spawn(move || {
            if let Err(e) = daemon::run(
                clamd_db,
                addr,
                clamd_opts,
                allow_shutdown,
                clamd_max_connections,
            ) {
                eprintln!("exav: daemon error: {e}");
            }
            // The listener is the whole job, and an orchestrator can only
            // restart what it can see has stopped.
            std::process::exit(2);
        });
        // The reporter is already running for this process (started above), so
        // one line covers both listeners rather than each announcing its own
        // share of a total they contribute to together.
        return icap::serve_alone(server, db, opts, watch, &reload, std::time::Duration::ZERO);
    }
    match daemon::run(
        db,
        addr,
        opts,
        shutdown_allowed(cli.allow_shutdown),
        clamd_max_connections,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("exav: daemon error: {e}");
            ExitCode::from(2)
        }
    }
}

/// Build the scan options from the CLI. `--clamav-compat` is a *preset*: it
/// supplies ClamAV's documented defaults for the individual limit/capability
/// flags, but any explicit flag overrides the preset (an unset flag falls back
/// to the preset value under `--clamav-compat`, else to exav's own default).
///
/// Each exav flag is spelled like the field it feeds, so the mapping reads off
/// the name. The flag↔field table lives in
/// `www/src/content/docs/reference/limits.md`, and the
/// `limit_flags_land_on_their_fields` test pins every pair; keep both in step
/// with any change here.
#[allow(clippy::field_reassign_with_default)] // conditional per-field overrides read cleaner than a struct literal
fn build_scan_options(cli: &Cli) -> ScanOptions {
    const MIB: u64 = 1024 * 1024;
    let compat = cli.clamav_compat;
    if compat {
        // The name reads like the mode you want when migrating. It is the
        // opposite: it narrows exav to a stock build's reach so a differential
        // run has a fair baseline, which means switching off detection exav
        // would otherwise deliver. Nobody should discover that from the exit
        // code of a production scan.
        eprintln!(
            "exav: --clamav-compat reduces detection capability on purpose \
             (narrower unpacking reach, ClamAV's smaller limits). It exists for \
             differential testing against clamscan. Do not use it in production."
        );
    }
    let mut opts = ScanOptions::default();
    // Report under ClamAV's vocabulary where the two engines name the same fact
    // differently. Affects names only — nothing is detected in one mode and not
    // the other.
    opts.clamav_compat = compat;

    // --max-input-bytes: per top-level file cap. exav default unlimited;
    // compat 100M.
    //
    // `0` is ClamAV's spelling of "no limit" for both size flags, and exav's own
    // `--max-scan-secs`/`--max-process-bytes` already read it that way. Taking it
    // literally instead turns a request for no limit into a limit of zero, which
    // refuses every file with a byte in it — the opposite of what was asked, and
    // an operator reading ClamAV's documentation has no reason to expect it. An
    // explicit `0` wins over the compat default: the flag was given.
    opts.max_scan_size = match cli.max_input_bytes {
        Some(0) => None,
        Some(v) => Some(v),
        None => compat.then_some(100 * MIB),
    };

    // --max-extracted-bytes: what decompression may produce (deep-analysis size
    // + summed extracted bytes, set together). Unset, the two keep their own
    // defaults: 256M deep-analysis (`ScanOptions::default`), 1G extracted total
    // (`Limits::default`); compat 400M for both.
    match cli.max_extracted_bytes {
        Some(0) => {
            opts.deep_analysis_max = u64::MAX;
            opts.limits.max_extracted_bytes = u64::MAX;
        }
        Some(s) => {
            opts.deep_analysis_max = s;
            opts.limits.max_extracted_bytes = s;
        }
        None => {
            if let Some(s) = compat.then_some(400 * MIB) {
                opts.deep_analysis_max = s;
                opts.limits.max_extracted_bytes = s;
            }
        }
    }
    // --max-object-bytes: the global peak-buffer limit. Sets the unpack
    // per-object cap and the core-side structural buffer (deep_analysis_max)
    // together, so one knob governs the largest single allocation on every
    // materialization path.
    if let Some(b) = cli.max_buffer_bytes {
        opts.limits.max_buffer_bytes = b;
        opts.deep_analysis_max = b;
    }
    // --max-matcher-bytes: the cumulative scan-reach (CPU/time) limit. Decoupled
    // from memory — a streamed member is bounded by this, not by the buffer cap,
    // so raising it scans larger members (in RAM bounded by
    // --max-object-bytes) at the cost of scan time only.
    if let Some(s) = cli.max_scanned_bytes {
        opts.limits.max_scanned_bytes = s;
    }
    // --max-depth: nesting depth. exav default 16; compat 17.
    if let Some(r) = cli.max_recursion.or_else(|| compat.then_some(17)) {
        opts.limits.max_recursion = r;
    }
    // --max-members: members per recursive walk. exav default 100000 (see
    // `Limits::max_members` for why it is higher than ClamAV's); compat 10000.
    if let Some(f) = cli.max_members.or_else(|| compat.then_some(10_000)) {
        opts.limits.max_members = f;
    }

    // Narrowing the unpacking reach to stock ClamAV's, and naming signatures the
    // way clamscan does, are both only ever wanted for a differential run, so
    // the preset is the whole interface — flags of their own would be two more
    // ways to ask for one mode.
    opts.restrict_extractors = compat;
    opts.unofficial_suffix = compat;
    // Base64 executable decoding: exav-exclusive reach, on by default and off
    // under --clamav-compat for parity — but an explicit `--base64 on/off` wins
    // over the preset, as every other flag here does.
    opts.decode_base64 = cli.base64.unwrap_or(!compat);

    // `clamav_heuristics` (PDF ObfuscatedNameObject, imphash `.imp` matching) is on
    // by default from `ScanOptions::default()` — a faithful out-of-the-box scan —
    // and `--clamav-compat` / `--detect heuristics` keep it on. Nothing turns it
    // off from the CLI, so no assignment here.
    opts.passwords = cli.password.clone();
    opts.structured_cc_count = cli.structured_cc_count;
    opts.structured_ssn_count = cli.structured_ssn_count;
    // The detectors say what to look for; the partial policy says what a
    // verdict becomes. Two of the engine's `alert_*` fields belong to the
    // second question, not the first: they turn a condition into a detection
    // under ClamAV's own `Heuristics.Encrypted.*` / `Heuristics.Limits.*`
    // names, which is exactly what `--partial-as … =alert` asks for.
    let detect = cli.detect.unwrap_or_default();
    let partial_as = cli.partial_as.unwrap_or_default();
    opts.heuristics = detect.heuristics();
    opts.alert_macros = detect.macros();
    opts.alert_broken_media = detect.broken_media();
    opts.alert_packed = detect.packed();
    opts.alert_partition_intersection = detect.partition_intersection();
    opts.alert_broken = detect.broken();
    opts.alert_phishing = detect.phishing();
    opts.alert_encrypted = partial_as.reports_encrypted_as_found();
    opts.alert_exceeds_max = partial_as.reports_limits_as_found();
    opts
}

/// Reject flag combinations where one would silently override the other.
///
/// The cost of accepting them is not cosmetic: `--profile --all-matches` would
/// emit a CSV header followed by non-CSV lines, and a client transport with
/// nothing to send to would scan nothing while looking like it had.
/// Build the spill settings from the flags and install them.
///
/// The budgets nest — RAM, then one object, then the process — so a
/// configuration that inverts the nesting is refused here rather than at the
/// first object large enough to expose it. An operator who sets a 4 GiB
/// per-object cap under a 1 GiB total has said two things that cannot both hold,
/// and finding out from a `UNSCANNABLE` verdict in production is finding out
/// late.
fn configure_spill(cli: &Cli) -> Result<(), String> {
    let d = spill::SpillConfig::default();
    // `0` reads as "no ceiling" here as it does on every other `--max-` size
    // flag. Turning spilling *off* is `--spill-dir off`, said out loud, because a
    // number that silently meant "none allowed" on one flag and "unlimited" on
    // its neighbours is how an operator ends up with the opposite of what they
    // configured.
    let no_ceiling = |v: Option<u64>, default: u64| match v {
        Some(0) => u64::MAX,
        Some(n) => n,
        None => default,
    };
    // `off` is a place a spilled object could go, spelled as the answer "it
    // doesn't", which is why it lives on this flag rather than a switch of its
    // own. `0` would not do: the neighbouring `--max-` flags read `0` as "no
    // ceiling", the opposite of turning something off.
    let off = cli
        .spill_dir
        .as_deref()
        .is_some_and(|d| d.eq_ignore_ascii_case("off"));
    let cfg = spill::SpillConfig {
        enabled: !off,
        dir: if off {
            None
        } else {
            cli.spill_dir.as_deref().map(PathBuf::from)
        },
        threshold: cli.spill_threshold.unwrap_or(d.threshold),
        max_object: no_ceiling(cli.max_spill_bytes, d.max_object),
        max_total: no_ceiling(cli.max_total_spill_bytes, d.max_total),
    };
    if !cfg.enabled {
        // The disk budgets describe a disk nothing will be written to, so they
        // are not checked against each other — but saying both is a
        // contradiction worth naming rather than silently resolving.
        if cli.max_spill_bytes.is_some() || cli.max_total_spill_bytes.is_some() {
            return Err("--spill-dir off leaves nothing for --max-spill-bytes / \
                 --max-total-spill-bytes to describe; drop one of them"
                .to_string());
        }
        spill::configure(cfg);
        return Ok(());
    }
    if let Some(dir) = &cfg.dir {
        if !dir.is_dir() {
            return Err(format!(
                "--spill-dir {}: not a directory (use `off` to disable spilling)",
                dir.display()
            ));
        }
    }
    // An *unlimited* per-object cap under a finite total is not the same
    // mistake: it says "the total is the only bound", which is coherent and is
    // what the total already enforces. The contradiction is a finite per-object
    // allowance no object could ever reach.
    if cfg.max_object != u64::MAX && cfg.max_object > cfg.max_total {
        return Err(format!(
            "--max-spill-bytes ({}) exceeds --max-total-spill-bytes ({}): no single object could \
             ever use its allowance",
            spill::human_bytes(cfg.max_object),
            spill::human_bytes(cfg.max_total)
        ));
    }
    if cfg.threshold > cfg.max_object {
        return Err(format!(
            "--spill-threshold ({}) exceeds --max-spill-bytes ({}): an object would be refused the \
             disk it only needs because it outgrew RAM",
            spill::human_bytes(cfg.threshold),
            spill::human_bytes(cfg.max_object)
        ));
    }
    spill::configure(cfg);
    Ok(())
}

fn check_flag_conflicts(cli: &Cli) -> Result<(), String> {
    // The policy belongs to whoever scans. A client only ever sees the reply the
    // daemon already decided, so this flag would parse, look like it was in
    // force, and change nothing — and it cannot be made to work: once the daemon
    // has reported `OK` for something it passed, the fact is gone from the wire.
    if cli.partial_as.is_some() && cli.connect.is_some() {
        return Err(
            "--partial-as decides how a scan reports what it could not examine, so it \
             belongs to whatever does the scanning; set it on the daemon you are \
             --connect-ing to"
                .to_string(),
        );
    }
    if cli.connect.is_some() && serves(cli) {
        return Err(
            "--listen accepts connections and --connect makes one; a run does one or the \
             other"
                .to_string(),
        );
    }
    if cli.json && cli.profile {
        return Err(
            "--json and --profile are two different output formats for a file scan".to_string(),
        );
    }
    if cli.allmatch && cli.profile {
        return Err(
            "--profile cannot report an all-match scan: one file yields many \
             detections and the row format has one verdict per file"
                .to_string(),
        );
    }
    let clamd = clamd_endpoint(cli);
    if cli.workers.is_some() && clamd.is_none() {
        return Err(
            "--workers is the clamd listener's worker model; it needs --listen clamd://…"
                .to_string(),
        );
    }
    if let Some(send_as) = cli.send_as {
        let what = send_as.as_str();
        if cli.connect.is_none() {
            return Err(format!(
                "--send-as {what} says how to hand a file to a running daemon; it needs \
                 --connect ADDR"
            ));
        }
        // SCM_RIGHTS is a Unix-socket mechanism: there is no way to hand a
        // descriptor to the other end of a TCP connection, and a client that
        // quietly fell back to sending the path would scan a file on the
        // daemon's host that need not be the one named here.
        if send_as == SendAs::Fd
            && matches!(
                cli.connect.as_deref().map(endpoint::Endpoint::parse),
                Some(Ok(endpoint::Endpoint {
                    addr: endpoint::Addr::Tcp(_),
                    ..
                }))
            )
        {
            return Err(
                "--send-as fd passes a file descriptor over a Unix socket (SCM_RIGHTS), \
                 which a TCP connection cannot carry; --connect a socket path, or \
                 --send-as contents"
                    .to_string(),
            );
        }
        // One INSTREAM/FILDES request answers with one verdict, so an all-match
        // scan cannot be expressed by either. Reporting the first match under a
        // flag that asks for every match would hide the rest.
        if cli.allmatch && send_as.sends_contents() {
            return Err(format!(
                "--all-matches reports every matching signature, and --send-as {what} gets \
                 one verdict per file back; --send-as path for an all-match client scan"
            ));
        }
    }
    if serves(cli) && !cli.paths.is_empty() {
        return Err("--listen starts a server; it takes no paths to scan".to_string());
    }
    // An `icap://` address in a build with no ICAP listener is a listener that
    // was asked for and will never be bound — the shape of deployment that
    // believes it is scanning. Refused rather than ignored.
    #[cfg(not(feature = "icap"))]
    if listeners(cli)
        .unwrap_or_default()
        .iter()
        .any(|e| e.proto == endpoint::Proto::Icap)
    {
        return Err("this build has no ICAP listener (build with `--features icap`)".to_string());
    }
    Ok(())
}

/// Whether this run honours the clamd `SHUTDOWN` command.
///
/// **Refused by default.** A client that can reach the daemon must not be able
/// to stop it: a scanner that is not running does not report infected, it
/// reports nothing, and a pipeline that treats "no answer" as "fine" passes
/// everything. `--allow-shutdown` opts back into clamd's behaviour.
///
/// Every listening mode calls this one function. Three modes each deciding the
/// policy for themselves is how one of them ends up defaulting the other way.
fn shutdown_allowed(allow_shutdown: bool) -> bool {
    allow_shutdown
}

/// Signature count of the built-in EICAR-only baseline, computed once.
fn baseline_sig_count() -> usize {
    use std::sync::OnceLock;
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| Scanner::builtin().signature_count())
}

/// Whether `db` carries no real detection capability beyond the built-in
/// baseline — an absent DB, an empty/junk `--sigs-dir`, OR a *valid-but-empty*
/// loaded database (e.g. a build server that shipped a signature-less `.exavdb`).
/// Checking the loaded count, not just whether a source path exists, is what
/// makes this hard to fool: a reachable daemon in this state would report real
/// malware as clean, so a listening exav refuses it unless `--allow-no-db`.
fn is_effectively_empty(db: &Scanner) -> bool {
    db.signature_count() <= baseline_sig_count()
}

/// Gate a freshly-loaded database for a listener: refuse an effectively-empty
/// one (see [`is_effectively_empty`]) unless `--allow-no-db` opts into the
/// baseline (with a loud warning). Used as (and by) the reload closure, so an
/// emptied/corrupt volume never silently downgrades a running daemon to zero
/// coverage. `source` names the DB origin for the message.
fn guard_not_empty(db: Scanner, source: &str, allow_no_db: bool) -> Result<Scanner, String> {
    if is_effectively_empty(&db) {
        if !allow_no_db {
            return Err(format!(
                "{source} has no signature database — refusing to serve (near-zero coverage; \
                 real malware would be reported clean). Provide signatures, or pass \
                 --allow-no-db to serve the EICAR-only baseline (testing only)."
            ));
        }
        eprintln!(
            "exav: WARNING: {source} has no signatures — serving the built-in EICAR-only \
             baseline (--allow-no-db); near-zero coverage."
        );
    }
    Ok(db)
}

fn load_db(cli: &Cli) -> Result<Scanner, String> {
    // `--unofficial-names` (or the `--clamav-compat` preset) selects exact ClamAV
    // naming (the `.UNOFFICIAL` suffix / `YARA.` prefix on unofficial-database
    // signatures). The suffix is actually applied at report time from
    // `ScanOptions::unofficial_suffix`; this load-time flag is retained for
    // provenance/API compatibility.
    let suffix = cli.clamav_compat;
    let bmem = cli.max_build_memory;
    let pua = cli.detect.unwrap_or_default().pua();
    if let Some(path) = &cli.database {
        return loader::load_with_options_mem(path, pua, suffix, bmem).map_err(|e| e.to_string());
    }
    if cli.sigs.is_dir() {
        // Use the data dir if it actually contains something loadable.
        if std::fs::read_dir(&cli.sigs)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
        {
            return loader::load_with_options_mem(&cli.sigs, pua, suffix, bmem)
                .map_err(|e| e.to_string());
        }
    }
    Ok(Scanner::builtin())
}

fn scan_target(
    path: &Path,
    db: &Scanner,
    opts: &ScanOptions,
    cli: &Cli,
    filters: &Filters,
    totals: &mut Totals,
) {
    if path.is_dir() {
        // Naming a directory means the directory. Scanning only its top level by
        // default — as `clamscan` does, and as exav used to — answers a question
        // nobody asked, and answers it in the shape of a clean result: the files
        // that were never opened look exactly like the ones that were fine.
        let descent = if cli.no_recursive {
            Descent::Immediate
        } else {
            Descent::Recursive
        };
        // Parts of a byte-split archive, remembered as they go past. Only a
        // name that parses as one is kept, so a tree of ordinary files costs
        // one parse each and nothing is accumulated.
        let mut parts: Vec<PathBuf> = Vec::new();
        let walk = walk_tree(path, Some(filters), descent);
        totals.dirs += walk.dirs;
        for line in &walk.errors {
            totals.errors += 1;
            if !cli.quiet {
                eprintln!("{line}");
            }
        }
        for file in &walk.files {
            if is_volume_part(file) {
                parts.push(file.clone());
            }
            scan_one(file, db, opts, cli, totals);
        }
        // A set like `big.7z.001`, `.002`, `.003` is one archive cut into
        // pieces: no piece decodes on its own, so the `OK` lines above say
        // only that each fragment is not itself malware. Rejoin and scan the
        // archives they make.
        scan_volume_sets(&parts, db, opts, cli, totals);
    } else if !filters.file_skipped(path) {
        scan_one(path, db, opts, cli, totals);
    }
}

/// Whether a path's *filename* marks it as one part of a byte-split archive.
/// Names only — nothing is opened to decide this.
fn is_volume_part(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(exav_core::unpack::volume::parse)
        .is_some_and(|v| v.scheme.is_byte_split())
}

/// Rejoin the multi-volume archives among `parts` and scan each as one file.
///
/// Reported under the archive's own name (`dir/big.7z`), not a fragment's: that
/// is the object that was scanned, and it is what an operator needs to see. The
/// per-part lines already printed stand — each said only that the fragment is
/// not itself malware, which remains true.
///
/// Grouped per directory: `a/big.7z.001` and `b/big.7z.002` are unrelated files
/// that happen to share a name, and splicing them would concatenate bytes
/// nothing ever wrote.
fn scan_volume_sets(
    parts: &[PathBuf],
    db: &Scanner,
    opts: &ScanOptions,
    cli: &Cli,
    totals: &mut Totals,
) {
    use std::collections::BTreeMap;
    if parts.is_empty() {
        return;
    }
    let mut by_dir: BTreeMap<&Path, Vec<String>> = BTreeMap::new();
    for p in parts {
        let (Some(dir), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str())) else {
            continue;
        };
        by_dir.entry(dir).or_default().push(name.to_string());
    }
    for (dir, names) in by_dir {
        let verdicts = exav_core::analyze_volume_sets(db, &names, opts, |name| {
            use std::io::Read;
            let mut data = Vec::new();
            std::fs::File::open(dir.join(name))?
                .take(opts.deep_analysis_max.saturating_add(1))
                .read_to_end(&mut data)?;
            Ok(data)
        });
        // One line per *archive*, not per part: every part of a set carries the
        // same verdict, and repeating it once per fragment would be noise.
        let mut seen = std::collections::HashSet::new();
        for v in verdicts {
            if !seen.insert(v.set.clone()) {
                continue;
            }
            if matches!(v.report.verdict.category(), VerdictCategory::Clean) {
                continue;
            }
            totals.scanned += 1;
            report_result(
                &dir.join(&v.set).display().to_string(),
                v.report,
                cli,
                totals,
            );
        }
    }
}

fn scan_one(path: &Path, db: &Scanner, opts: &ScanOptions, cli: &Cli, totals: &mut Totals) {
    if cli.allmatch {
        return scan_one_allmatch(path, db, opts, cli, totals);
    }
    totals.scanned += 1;
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    totals.data_scanned += size;
    // Isolate each file: a parser panic on a crafted input must not abort
    // the whole run, and must count as an error — never a clean result.
    let t0 = std::time::Instant::now();
    if cli.profile {
        exav_core::profile::enable();
    }
    let mut scanned =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan_path(db, path, opts)));
    if cli.profile {
        let prof = exav_core::profile::take();
        // `--profile` returns before `report_result`, so the partial policy has
        // to be applied here too. Without it `--partial-as` reaches every mode
        // except this one: the same files would exit 3 under `--profile` and 0
        // without it, and the CSV would name a verdict the operator asked to be
        // reported as something else.
        if let Ok(Ok(r)) = &mut scanned {
            policy::apply(r, policy::current());
        }
        let (verdict, sig) = match &scanned {
            Ok(Ok(r)) => {
                let v = &r.verdict;
                // Counted, not just labelled, and counted the way `report_result`
                // counts — through the exhaustive `VerdictCategory`. The CSV row
                // records what happened, but the exit code is the machine-readable
                // answer, and a run whose files all hit limits exiting 0 tells a
                // script every one of them was scanned and clean.
                match v.category() {
                    VerdictCategory::Infected => totals.infected += 1,
                    // As in `report_result`: `--partial-as error` changes no
                    // verdict, only which counter — and so which exit code —
                    // this object contributes to.
                    VerdictCategory::Partial => {
                        if policy::current().for_tag(v.status_tag()) == policy::PartialStatus::Error
                        {
                            totals.errors += 1;
                        } else {
                            totals.limits += 1;
                        }
                    }
                    VerdictCategory::Clean => {}
                }
                match v {
                    Verdict::Clean => ("clean", String::new()),
                    Verdict::Infected { signature, .. } => ("infected", signature.clone()),
                    Verdict::LimitsExceeded { reason } => ("limits", reason.clone()),
                    Verdict::Unscannable { reason } => ("unscannable", reason.clone()),
                    Verdict::PasswordProtected { reason } => ("password-protected", reason.clone()),
                    // `Verdict` is `#[non_exhaustive]`. This is a profiling
                    // column, not a verdict decision — the counters above already
                    // classified it — so an unrecognised outcome is labelled
                    // rather than guessed at, and never labelled clean.
                    _ => ("other", String::new()),
                }
            }
            Ok(Err(e)) => {
                totals.errors += 1;
                ("error", e.to_string())
            }
            Err(_) => {
                totals.errors += 1;
                ("panic", String::new())
            }
        };
        println!(
            "{}",
            perf::row(path, verdict, &sig, prof.as_ref(), t0.elapsed(), size)
        );
        return;
    }
    match scanned {
        Ok(Ok(report)) => report_result(&path.display().to_string(), report, cli, totals),
        Ok(Err(e)) => report_error(&path.display().to_string(), &e.to_string(), cli, totals),
        Err(_) => report_error(
            &path.display().to_string(),
            "internal error while scanning",
            cli,
            totals,
        ),
    }
}

/// Report a file that could not be scanned, and count it.
///
/// In `--json` mode this emits an object like every other result. Printing only
/// to stderr leaves a JSONL consumer with fewer objects than it sent paths, and
/// nothing in the stream saying which path is missing or why — under
/// `--quiet` there is no trace at all. A record that says "error" is the
/// difference between a consumer that can react and one that cannot tell.
fn report_error(name: &str, message: &str, cli: &Cli, totals: &mut Totals) {
    totals.errors += 1;
    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "file": name, "category": "error",
                "status": "ERROR", "detail": message
            })
        );
    } else if !cli.quiet {
        eprintln!("{name}: {message} ERROR");
    }
}

fn scan_stdin(db: &Scanner, cli: &Cli, totals: &mut Totals) {
    use std::io::Read;
    totals.scanned += 1;
    let opts = build_scan_options(cli);
    let scanned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> io::Result<exav_core::ScanReport> {
            // Buffer stdin to a SEEKABLE source (RAM small / temp file large) and
            // run the full container-aware scan — so `cat archive.zip | exav -`
            // detects malware INSIDE the archive, like clamscan. The old
            // `scan_stream` was flat and missed it (and ignored `opts`).
            let max = opts.max_scan_size;
            let limit = max.map(|m| m.saturating_add(1)).unwrap_or(u64::MAX);
            let stdin = io::stdin();
            let mut capped = stdin.lock().take(limit);
            let payload = match daemon::buffer_to_seekable(&mut capped) {
                Ok(p) => p,
                // Nowhere to put it is not "nothing found in it".
                Err(spill::SpillError::Budget(reason)) => {
                    return Ok(exav_core::ScanReport {
                        verdict: exav_core::Verdict::Unscannable { reason },
                        findings: Vec::new(),
                    })
                }
                Err(spill::SpillError::Io(e)) => return Err(e),
            };
            if let Some(m) = max {
                if payload.len() > m {
                    return Ok(exav_core::ScanReport {
                        verdict: exav_core::Verdict::LimitsExceeded {
                            reason: format!("stdin exceeds max-input-bytes {m}"),
                        },
                        findings: Vec::new(),
                    });
                }
            }
            let (report, _loc) = daemon::scan_payload(db, &opts, &payload)?;
            Ok(report)
        },
    ));
    match scanned {
        Ok(Ok(report)) => report_result("stdin", report, cli, totals),
        Ok(Err(e)) => report_error("stdin", &e.to_string(), cli, totals),
        Err(_) => report_error("stdin", "internal error while scanning", cli, totals),
    }
}

/// Scan an http(s):// URL via range requests, fetching only the bytes the
/// scan touches (e.g. a ZIP's directory + the members it reads).
#[cfg(feature = "http-scan")]
fn scan_url(url: &str, db: &Scanner, opts: &ScanOptions, cli: &Cli, totals: &mut Totals) {
    totals.scanned += 1;
    let reader = match exav_core::source::HttpRangeReader::open(url) {
        Ok(r) => r,
        Err(e) => {
            report_error(url, &e.to_string(), cli, totals);
            return;
        }
    };
    let size = reader.len();
    let scanned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exav_core::scan_seekable(db, reader, size, opts)
    }));
    match scanned {
        Ok(Ok(report)) => report_result(url, report, cli, totals),
        Ok(Err(e)) => report_error(url, &e.to_string(), cli, totals),
        Err(_) => report_error(url, "internal error while scanning", cli, totals),
    }
}

/// Where `--connect` points, parsed. `None` when it was not given.
fn connect_endpoint(cli: &Cli) -> Option<endpoint::Endpoint> {
    endpoint::Endpoint::parse(cli.connect.as_deref()?).ok()
}

/// The daemon endpoint this client talks to, as it appears in messages.
fn client_endpoint(cli: &Cli) -> String {
    connect_endpoint(cli)
        .map(|e| e.to_string())
        .unwrap_or_else(|| "no endpoint".to_string())
}

/// Open one connection to the daemon, over a unix socket or TCP.
fn client_dial(cli: &Cli) -> io::Result<Box<dyn ReadWrite>> {
    match connect_endpoint(cli).map(|e| e.addr) {
        Some(endpoint::Addr::Tcp(addr)) => Ok(Box::new(std::net::TcpStream::connect(addr)?)),
        #[cfg(unix)]
        Some(endpoint::Addr::Unix { path, .. }) => {
            Ok(Box::new(std::os::unix::net::UnixStream::connect(path)?))
        }
        #[cfg(not(unix))]
        Some(endpoint::Addr::Unix { .. }) => Err(io::Error::other(
            "a Unix-socket address needs a Unix platform",
        )),
        None => Err(io::Error::other("--connect ADDR required for client mode")),
    }
}

/// [`client_dial`] for the callers whose failure ends the run: reports the
/// endpoint that could not be reached and hands back the exit code.
fn client_connect(cli: &Cli) -> Result<Box<dyn ReadWrite>, ExitCode> {
    client_dial(cli).map_err(|e| {
        eprintln!("exav: connect {}: {e}", client_endpoint(cli));
        ExitCode::from(2)
    })
}

/// Read one NUL-terminated reply, without the terminator or trailing blanks.
/// `None` means the daemon closed the connection instead of answering.
fn read_reply(r: &mut impl std::io::BufRead) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    if r.read_until(0, &mut buf)? == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(Some(String::from_utf8_lossy(&buf).trim_end().to_string()))
}

/// Read every reply a command produced, up to the daemon closing the
/// connection. That close is the end marker for anything sent outside a
/// session, and the only one a command whose reply count is not announced —
/// `CONTSCAN`, `ALLMATCHSCAN` — has.
///
/// The second half of the pair is the reason the stream ended, when it ended
/// badly. The lines that did arrive are still returned, because they name files
/// with verdicts; what must not happen is treating them as the complete answer,
/// which would call a tree clean on the strength of the part of it that was
/// scanned before the connection broke.
fn read_replies_until_close(r: &mut impl std::io::BufRead) -> (Vec<String>, Option<String>) {
    let mut out = Vec::new();
    loop {
        match read_reply(r) {
            Ok(Some(line)) => {
                if !line.is_empty() {
                    out.push(line);
                }
            }
            Ok(None) => return (out, None),
            Err(e) => return (out, Some(e.to_string())),
        }
    }
}

/// Split an IDSESSION reply message into the command id it answers and the
/// reply itself. Only a leading run of digits counts as an id: a verdict line
/// carries colons of its own, starting with the one after the path.
fn split_session_id(msg: &str) -> (Option<u64>, &str) {
    match msg.split_once(": ") {
        Some((head, rest)) => match head.parse::<u64>() {
            Ok(id) => (Some(id), rest),
            Err(_) => (None, msg),
        },
        None => (None, msg),
    }
}

/// Read one session command's replies, up to the `PONG` that ends them.
///
/// A session announces no reply count and sends no terminator between commands,
/// and a scan can answer with any number of messages — `SCAN` on a directory
/// answers one per file in it. A client that reads a fixed single line reports
/// the first verdict, drops every other one, and then reads the leftovers as
/// the next command's answer. `PING` is therefore sent behind each scan: the
/// daemon numbers replies in command order, so the `PONG` carrying the ping's
/// id is the first message that is not the scan's, and everything before it is.
///
/// `Err` is a daemon that closed, failed, or answered out of order before the
/// marker arrived: the command is then unanswered, which is not the same as
/// answered clean.
fn read_session_replies(r: &mut impl std::io::BufRead, marker_id: u64) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    loop {
        let Some(msg) = read_reply(r)? else {
            return Err(io::Error::other("the daemon closed the connection"));
        };
        let (id, body) = split_session_id(&msg);
        match id {
            // The marker, whatever it says: the scan has finished answering.
            Some(n) if n == marker_id => return Ok(out),
            // A later command's answer means the replies have lost step with the
            // commands, and a verdict read under the wrong file's name is worse
            // than none at all.
            Some(n) if n > marker_id => {
                return Err(io::Error::other(format!(
                    "the daemon answered command {n} while {} was outstanding",
                    marker_id - 1
                )))
            }
            Some(_) => {
                if !body.is_empty() {
                    out.push(body.to_string());
                }
            }
            // A daemon that tags no ids leaves nothing to find the marker by, so
            // its message is taken as the whole answer rather than blocking on
            // one that may never come. `PONG` is the marker answering untagged.
            None => {
                if !body.is_empty() && body != "PONG" {
                    out.push(body.to_string());
                }
                return Ok(out);
            }
        }
    }
}

/// With `--verbose`, name the command the client is about to send and what it
/// names. A daemon reply carries a verdict and nothing else, so which daemon
/// answered and what it was asked is the informational detail client mode has;
/// `--json` is a machine stream and gets none of it.
fn client_verbose_cmd(cli: &Cli, verb: &str, target: &str) {
    if cli.verbose && !cli.json {
        println!("  [{verb}] {target}");
    }
}

/// With `--verbose`, name the daemon that is about to answer: the endpoint the
/// client reached and the engine/signature version it reports. Best-effort — a
/// daemon that cannot be reached is reported by the scan itself.
fn client_banner(cli: &Cli) {
    use std::io::{BufReader, Write};
    if !cli.verbose || cli.json {
        return;
    }
    let endpoint = client_endpoint(cli);
    let Ok(mut c) = client_dial(cli) else {
        return;
    };
    if c.write_all(b"zVERSION\0").and_then(|()| c.flush()).is_err() {
        return;
    }
    let mut r = BufReader::new(c.try_clone_box());
    if let Ok(Some(v)) = read_reply(&mut r) {
        println!("  [daemon] {endpoint} {v}");
    }
}

/// Send one `INSTREAM` request: the command, then the payload in
/// length-prefixed chunks, then the zero-length terminator that tells the
/// daemon the file is complete.
///
/// A read failure part-way through returns *without* that terminator, so the
/// daemon answers a prefix with an error rather than a clean verdict on a file
/// nobody finished sending.
fn send_instream<W: std::io::Write, R: io::Read>(w: &mut W, mut src: R) -> io::Result<()> {
    // Big enough that a large file is not a syscall per kilobyte, small enough
    // that the client holds one of these and not the file.
    const CHUNK: usize = 64 * 1024;
    w.write_all(b"zINSTREAM\0")?;
    write_chunks(w, &mut src, &mut vec![0u8; CHUNK])?;
    w.write_all(&0u32.to_be_bytes())?;
    w.flush()
}

/// The chunk sequence itself (no command, no terminator), shared by `INSTREAM`
/// and the per-file payloads of an `EXINSTREAM MULTI` request.
fn write_chunks<W: std::io::Write, R: io::Read>(
    w: &mut W,
    src: &mut R,
    buf: &mut [u8],
) -> io::Result<()> {
    loop {
        let n = match src.read(buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        w.write_all(&(n as u32).to_be_bytes())?;
        w.write_all(&buf[..n])?;
    }
}

/// Replace the daemon's own name for a streamed target with the local one.
///
/// `INSTREAM` answers about `stream` and `FILDES` about `fd`; neither means
/// anything to whoever named a file on the command line, and clamdscan rewrites
/// the same way. A protocol-level error (`FILDES: …`) is left alone: it is
/// about the request, not about a file.
fn retarget(line: &str, target: &str) -> String {
    for prefix in ["stream: ", "fd: "] {
        if let Some(rest) = line.strip_prefix(prefix) {
            return format!("{target}: {rest}");
        }
    }
    line.to_string()
}

/// Stream one source's bytes to the daemon over a connection of its own, and
/// return the reply line under the local name.
///
/// A connection per target rather than one `IDSESSION` batch: a local read that
/// fails mid-stream leaves the connection carrying half a request, and dropping
/// it is the only way back to a known state. It is also what clamdscan does.
fn client_stream(cli: &Cli, target: &str, src: impl io::Read) -> io::Result<String> {
    use std::io::BufReader;
    let mut conn = client_dial(cli)?;
    send_instream(&mut conn, src)?;
    let mut r = BufReader::new(conn.try_clone_box());
    match read_reply(&mut r)? {
        Some(line) => Ok(retarget(&line, target)),
        None => Err(io::Error::other("daemon closed without replying")),
    }
}

/// Pass one open file to the daemon by descriptor (`FILDES`), over a connection
/// of its own, and return the reply line under the local name. The daemon reads
/// the file through the descriptor, so it needs no permission on the path and
/// no view of this filesystem at all.
#[cfg(unix)]
fn client_fdpass(cli: &Cli, path: &Path) -> io::Result<String> {
    use std::io::BufReader;
    use std::os::fd::AsRawFd;
    let Some(endpoint::Addr::Unix { path: sock, .. }) = connect_endpoint(cli).map(|e| e.addr)
    else {
        return Err(io::Error::other(
            "--send-as fd needs --connect on a Unix socket path",
        ));
    };
    let file = std::fs::File::open(path)?;
    let stream = std::os::unix::net::UnixStream::connect(sock)?;
    daemon::send_fd_command(&stream, b"zFILDES\0", file.as_raw_fd())?;
    let mut r = BufReader::new(stream.try_clone()?);
    match read_reply(&mut r)? {
        Some(line) => Ok(retarget(&line, &path.display().to_string())),
        None => Err(io::Error::other("daemon closed without replying")),
    }
}

/// Hand one local file to the daemon by contents or by descriptor, as
/// `--send-as` asked.
fn client_send_file(cli: &Cli, path: &Path) -> io::Result<String> {
    let name = path.display().to_string();
    #[cfg(unix)]
    if cli.send_as == Some(SendAs::Fd) {
        client_verbose_cmd(cli, "FILDES", &name);
        return client_fdpass(cli, path);
    }
    client_verbose_cmd(cli, "INSTREAM", &name);
    client_stream(cli, &name, std::fs::File::open(path)?)
}

/// Send the parts of one directory's byte-split archives together
/// (`EXINSTREAM MULTI`) so the daemon rejoins them and scans the archive they
/// form, reporting the verdict on each part.
///
/// Streaming each part on its own would collect a clean answer per fragment —
/// true of every fragment, and no answer at all about the archive, which is the
/// object the malware is in. In path mode the daemon does this job from
/// `CONTSCAN`; here the bytes have to be sent together for it to be possible.
///
/// `--send-as fd` sends its parts this way too: `FILDES` carries one descriptor
/// per request, so there is no fd-passing form of "these files are one archive".
fn client_stream_set(cli: &Cli, dir: &Path, parts: &[PathBuf], totals: &mut Totals) {
    let dirname = dir.display().to_string();
    client_verbose_cmd(cli, "EXINSTREAM MULTI", &dirname);
    let reply = match client_send_set(cli, parts) {
        Ok(r) => r,
        Err(e) => {
            report_error(&dirname, &e.to_string(), cli, totals);
            return;
        }
    };
    let doc: serde_json::Value = match serde_json::from_str(&reply) {
        Ok(v) => v,
        Err(e) => {
            report_error(
                &dirname,
                &format!("unreadable EXINSTREAM reply: {e}"),
                cli,
                totals,
            );
            return;
        }
    };
    let Some(entries) = doc.get("files").and_then(|f| f.as_array()) else {
        let msg = doc
            .get("reason")
            .and_then(|m| m.as_str())
            .unwrap_or("the daemon refused the request");
        report_error(&dirname, msg, cli, totals);
        return;
    };
    for (part, entry) in parts.iter().zip(entries) {
        totals.scanned += 1;
        print_daemon_reply(
            &set_entry_line(&part.display().to_string(), entry),
            cli,
            totals,
        );
    }
    // Short of a verdict per part, the batch answered about files it never
    // received; "all clean" over a list that stopped early is not an answer
    // about this directory.
    if entries.len() < parts.len() || doc.get("truncated") == Some(&serde_json::Value::Bool(true)) {
        report_error(
            &dirname,
            "the daemon answered for fewer files than were sent",
            cli,
            totals,
        );
    }
}

/// The `EXINSTREAM MULTI` request itself: `<u32 name_len><name>` plus the
/// ordinary chunk sequence per file, ended by a zero-length name. Returns the
/// single JSON reply line.
fn client_send_set(cli: &Cli, parts: &[PathBuf]) -> io::Result<String> {
    use std::io::{BufReader, Write};
    let mut conn = client_dial(cli)?;
    conn.write_all(b"zEXINSTREAM MULTI\0")?;
    let mut buf = vec![0u8; 64 * 1024];
    for p in parts {
        // A name is a label the daemon uses to recognise volume numbering, never
        // a path it opens, so the file name alone is what it needs.
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        conn.write_all(&(name.len() as u32).to_be_bytes())?;
        conn.write_all(name.as_bytes())?;
        let mut f = std::fs::File::open(p)?;
        write_chunks(&mut conn, &mut f, &mut buf)?;
        conn.write_all(&0u32.to_be_bytes())?;
    }
    conn.write_all(&0u32.to_be_bytes())?;
    conn.flush()?;
    let mut r = BufReader::new(conn.try_clone_box());
    match read_reply(&mut r)? {
        Some(line) => Ok(line),
        None => Err(io::Error::other("daemon closed without replying")),
    }
}

/// Render one `EXINSTREAM MULTI` verdict entry as the clamd-style line the rest
/// of the client already knows how to count, print and log.
fn set_entry_line(target: &str, entry: &serde_json::Value) -> String {
    let field = |k: &str| entry.get(k).and_then(|v| v.as_str()).unwrap_or_default();
    // The daemon marks an entry whose verdict came from the rejoined archive
    // rather than from the part itself; the reader needs to know which archive.
    let from_set = match entry.get("set").and_then(|v| v.as_str()) {
        Some(s) => format!(" (in {s})"),
        None => String::new(),
    };
    // The same grammar every other line uses — `reason CATEGORY STATUS` — built
    // from the reply's own `status` / `category` / `reason`. The wire word for a
    // partial is `ERROR`, as it is everywhere on the clamd protocol.
    match field("status") {
        "OK" => format!("{target}: OK"),
        "FOUND" => format!("{target}: {} FOUND{from_set}", field("signature")),
        "PARTIAL" => format!(
            "{target}: {} {} ERROR{from_set}",
            field("reason"),
            field("category")
        ),
        _ => format!("{target}: {} ERROR", field("reason")),
    }
}

/// Client mode: connect to a running daemon and scan the given paths via the
/// clamd-compatible protocol (one `SCAN <abspath>` per file, reusing the
/// connection). The daemon already holds the DB, so this pays no load cost.
///
/// A directory names a tree here whatever `--no-recursive` says: the daemon
/// descends into any path it is handed, and the client walks the tree itself so
/// the filter flags apply to it.
///
/// `--send-as contents`/`fd`, and `-`, send the file itself instead of its path,
/// so a daemon that shares no filesystem with this host can still answer.
fn run_client(cli: &Cli) -> ExitCode {
    use std::collections::BTreeMap;
    use std::io::{BufReader, Write};

    let started = std::time::Instant::now();
    // Expand the requested paths into individual files (the client walks dirs so
    // replies stay one-per-command and order is predictable).
    // The same walker the local scan uses, so `--exclude`/`--include` apply here
    // too and an unreachable path is reported rather than dropped.
    let filters = match Filters::compile(cli) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("exav: bad filter pattern: {e}");
            return ExitCode::from(2);
        }
    };
    client_banner(cli);

    // Sending contents means the client does its own walking: the daemon gets
    // bytes, not a tree it could descend.
    let sending_contents = cli.send_as.unwrap_or_default().sends_contents();
    // `-` is stdin. There is no path to name, so it goes as content whatever the
    // mode — which is exactly why it works against a daemon on another host.
    let mut scan_stdin = false;
    let mut files = Vec::new();
    let mut walk_errors = Vec::new();
    // Parts of a byte-split set, so the rejoined archive is scanned rather than
    // only its fragments. The daemon holds the database, so the rejoin has to
    // happen there: by path the client asks for it with CONTSCAN over the
    // directory, and by content with one `EXINSTREAM MULTI` per directory.
    let mut rejoin_dirs: Vec<PathBuf> = Vec::new();
    let mut stream_sets: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    for p in &cli.paths {
        if p.as_os_str() == "-" {
            scan_stdin = true;
        // A directory always recurses in client mode, with or without `-r`:
        // clamdscan has no such flag, so a command line migrated from it names a
        // tree and expects the tree scanned, and the daemon descends into any
        // path it is handed anyway. The client does the walking itself so
        // `--exclude`/`--include` apply and each command has one reply.
        } else if p.is_dir() {
            let walk = walk_tree(p, Some(&filters), Descent::Recursive);
            walk_errors.extend(walk.errors);
            if sending_contents {
                // Grouped by the directory the parts sit in: `a/big.7z.001` and
                // `b/big.7z.002` are unrelated files that share a name, and
                // splicing them would join bytes nothing ever wrote.
                for f in walk.files {
                    match (is_volume_part(&f), f.parent()) {
                        (true, Some(dir)) => stream_sets.entry(dir.into()).or_default().push(f),
                        _ => files.push(f),
                    }
                }
                continue;
            }
            if walk.files.iter().any(|f| is_volume_part(f)) {
                // Handed to `CONTSCAN` whole rather than scanned file by file.
                // The daemon reports a set's verdict on each PART's line — the
                // part is the file an operator has to act on — so asking for the
                // files individually and the set separately would report each
                // part twice and disagree with itself.
                rejoin_dirs.push(p.clone());
                continue;
            }
            files.extend(walk.files);
        } else if !filters.file_skipped(p) {
            files.push(p.clone());
        }
    }

    let mut totals = Totals::default();
    for line in &walk_errors {
        totals.errors += 1;
        if !cli.quiet {
            eprintln!("{line}");
        }
    }

    if scan_stdin {
        totals.scanned += 1;
        client_verbose_cmd(cli, "INSTREAM", "stdin");
        // Reported under `stdin`, the name a local `exav -` uses for the same
        // input: one input carries one name across every surface, so a `--json`
        // consumer or a log reader does not have to know whether the scan went
        // over a socket.
        match client_stream(cli, "stdin", io::stdin().lock()) {
            Ok(line) => print_daemon_reply(&line, cli, &mut totals),
            // Counted as scanned even so, as every other surface counts a file
            // it could not read: the target was named, and the summary says
            // what became of each one.
            Err(e) => report_error("stdin", &e.to_string(), cli, &mut totals),
        }
    }

    // Content-sending modes answer everything themselves: there is no path for
    // the daemon to open, so nothing below this point applies.
    if sending_contents {
        for f in &files {
            totals.scanned += 1;
            match client_send_file(cli, f) {
                Ok(line) => print_daemon_reply(&line, cli, &mut totals),
                Err(e) => report_error(&f.display().to_string(), &e.to_string(), cli, &mut totals),
            }
        }
        for (dir, parts) in &stream_sets {
            client_stream_set(cli, dir, parts, &mut totals);
        }
        return client_summary(cli, &totals, started.elapsed());
    }

    // `--all-matches` reports EVERY matching signature, so one file yields an
    // unknown number of reply messages, and a connection of its own is what
    // bounds them.
    if cli.allmatch {
        for f in &files {
            let abs = std::fs::canonicalize(f).unwrap_or_else(|_| f.clone());
            let lines = match client_oneshot(cli, "ALLMATCHSCAN", &abs, &mut totals) {
                Ok(lines) => lines,
                Err(code) => return code,
            };
            // One command per file, so the extra lines are further signatures
            // for the same file and the summary counts it once. A file the
            // daemon never answered about is counted too — it was named, and the
            // summary says what became of each name.
            totals.scanned += 1;
            for line in lines {
                print_daemon_reply(&line, cli, &mut totals);
            }
        }
        if let Err(code) = client_rejoin_sets(cli, &rejoin_dirs, &mut totals) {
            return code;
        }
        return client_summary(cli, &totals, started.elapsed());
    }

    // Everything left goes by path: the files on one session, and each split set
    // on a connection of its own. With nothing left there is no daemon to ask.
    if files.is_empty() && rejoin_dirs.is_empty() {
        return client_summary(cli, &totals, started.elapsed());
    }

    let mut conn: Box<dyn ReadWrite> = match client_connect(cli) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let mut reader = BufReader::new(conn.try_clone_box());
    // Batch all scans on one connection via IDSESSION (the daemon otherwise
    // closes after a single command).
    if conn.write_all(b"zIDSESSION\0").is_err() {
        eprintln!("exav: daemon connection lost");
        return ExitCode::from(2);
    }
    // The daemon numbers session replies in the order it reads the commands, so
    // counting the commands here says which id answers which scan.
    let mut last_id = 0u64;
    for f in &files {
        let abs = std::fs::canonicalize(f).unwrap_or_else(|_| f.clone());
        client_verbose_cmd(cli, "SCAN", &abs.display().to_string());
        // `PING` rides behind the scan as its end marker — see
        // [`read_session_replies`] for why a session needs one.
        let cmd = format!("zSCAN {}\0zPING\0", abs.display());
        if conn
            .write_all(cmd.as_bytes())
            .and_then(|_| conn.flush())
            .is_err()
        {
            eprintln!("exav: daemon connection lost");
            return ExitCode::from(2);
        }
        last_id += 2;
        let lines = match read_session_replies(&mut reader, last_id) {
            Ok(lines) => lines,
            Err(e) => {
                eprintln!("exav: {e}");
                return ExitCode::from(2);
            }
        };
        // A scan the daemon answered nothing about is not a scan that came back
        // clean, and the summary has to be able to say so.
        if lines.is_empty() {
            report_error(
                &abs.display().to_string(),
                "the daemon answered nothing",
                cli,
                &mut totals,
            );
        }
        // One verdict per file, whether the daemon answered about the one file
        // asked for or about a tree, so the count follows the replies.
        for line in lines {
            totals.scanned += 1;
            print_daemon_reply(&line, cli, &mut totals);
        }
    }
    let _ = conn.write_all(b"zEND\0");

    if let Err(code) = client_rejoin_sets(cli, &rejoin_dirs, &mut totals) {
        return code;
    }

    client_summary(cli, &totals, started.elapsed())
}

/// Send one command the daemon answers with an unannounced number of replies,
/// on a connection of its own, and hand back everything it wrote.
///
/// The connection is the framing: the daemon closes it after a single command
/// outside a session, and that close is the end marker `CONTSCAN` and
/// `ALLMATCHSCAN` have — neither says how many files it is about to answer for.
///
/// A target the daemon owed an answer about and did not give one is reported
/// here, so no caller can mistake an empty reply list for nothing to find.
/// `Err` is a daemon that could not be reached, which ends the run.
fn client_oneshot(
    cli: &Cli,
    verb: &str,
    target: &Path,
    totals: &mut Totals,
) -> Result<Vec<String>, ExitCode> {
    use std::io::{BufReader, Write};
    let name = target.display().to_string();
    client_verbose_cmd(cli, verb, &name);
    let mut c = client_connect(cli)?;
    let cmd = format!("z{verb} {name}\0");
    if c.write_all(cmd.as_bytes()).and_then(|_| c.flush()).is_err() {
        eprintln!("exav: daemon connection lost");
        return Err(ExitCode::from(2));
    }
    let mut r = BufReader::new(c.try_clone_box());
    let (lines, broke) = read_replies_until_close(&mut r);
    if let Some(e) = broke {
        report_error(&name, &e, cli, totals);
    } else if lines.is_empty() {
        report_error(&name, "the daemon closed without replying", cli, totals);
    }
    Ok(lines)
}

/// Ask the daemon to rejoin the byte-split sets in each directory and scan the
/// archives they form (`CONTSCAN`).
///
/// A set is one archive cut into pieces and no piece decodes on its own, so
/// scanning the directory file by file collects a clean answer per fragment and
/// never opens the archive the malware is in. The daemon holds the database, so
/// the rejoin happens there; the verdict comes back on each PART's line,
/// because the part is the file an operator has to act on.
fn client_rejoin_sets(cli: &Cli, dirs: &[PathBuf], totals: &mut Totals) -> Result<(), ExitCode> {
    for dir in dirs {
        let abs = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.clone());
        // `CONTSCAN` answers with one message per file in the tree, so the count
        // follows the replies.
        for line in client_oneshot(cli, "CONTSCAN", &abs, totals)? {
            totals.scanned += 1;
            print_daemon_reply(&line, cli, totals);
        }
    }
    Ok(())
}

/// The run summary and exit code, shared by every client path so they cannot
/// drift apart.
///
/// `--json` gets the same summary object a local scan emits: the flag promises
/// a stream of JSON, and a human banner at the end of it is a parse error for
/// whoever is reading.
fn client_summary(cli: &Cli, totals: &Totals, elapsed: std::time::Duration) -> ExitCode {
    if !cli.quiet {
        if cli.json {
            emit_json_summary(totals, elapsed);
        } else {
            print_client_summary(totals);
        }
    }
    // The same rule as a local scan, from the same place: a client and a local
    // run answering differently about the same verdicts would be a difference
    // nobody could see until it mattered.
    exit_code(totals)
}

/// The human client summary: the counters the daemon's replies produced. A
/// client scans no directories and reads no bytes itself, so the fields a local
/// scan reports for those are absent rather than zero.
fn print_client_summary(totals: &Totals) {
    println!("\n----------- SCAN SUMMARY -----------");
    println!("Scanned files: {}", totals.scanned);
    println!("Infected files: {}", totals.infected);
    if totals.limits > 0 {
        println!("Limits exceeded (unscanned, not clean): {}", totals.limits);
    }
    if totals.errors > 0 {
        println!("Errors: {}", totals.errors);
    }
}

/// Print a `<path>: <status>` daemon reply line in clamscan style.
///
/// Goes through `outln!` so `--log` receives it: a log that is missing a
/// detection is worse than no log, and client mode writing nothing to a log the
/// operator asked for would be exactly that. In `--json` mode the line is turned
/// into an object, so the flag means the same thing whichever surface answered.
fn print_daemon_reply(line: &str, cli: &Cli, totals: &mut Totals) {
    let line = line.trim_end();
    if cli.json {
        return json_daemon_reply(line, cli, totals);
    }
    // A verdict earned by a rejoined multi-volume set is reported on each part
    // as `<part>: <sig> FOUND (in <set>)`. The status word is therefore not last,
    // and a check anchored to the end of the line reads a detection as an
    // unrecognised line — which prints and counts as clean. Strip the annotation
    // before classifying; the printed line keeps it, because it is what tells an
    // operator which archive the part belongs to.
    let verdict = strip_set_annotation(line);
    if verdict.ends_with("FOUND") {
        totals.infected += 1;
        outln!("{line}");
        if cli.bell {
            print!("\x07");
        }
    } else if verdict.ends_with("ERROR") {
        // A `PARTIAL` verdict travels as `ERROR` because clamd's vocabulary has
        // no fourth word, so the category is what separates it from a scan that
        // actually failed. Count a categorised reply as a partial and print it
        // like a one-shot scan does, so the two paths agree; only an
        // uncategorised `ERROR` is a genuine failure, and it goes to the error
        // counter and stderr.
        if partial_category(verdict).is_some() {
            totals.limits += 1;
            outln!("{line}");
        } else {
            totals.errors += 1;
            eprintln!("{line}");
        }
    } else if !cli.quiet {
        outln!("{line}");
    }
}

/// A daemon reply with any trailing `" (in <set>)"` removed.
///
/// The daemon appends that to a part's line when the verdict came from the
/// rejoined archive rather than the part itself. It carries real information for
/// a reader and nothing but noise for a classifier, which needs the status word
/// to be last.
fn strip_set_annotation(line: &str) -> &str {
    match line.rfind(" (in ") {
        Some(i) if line.ends_with(')') => line[..i].trim_end(),
        _ => line,
    }
}

/// The `--json` rendering of a daemon reply.
///
/// Split from the human path so the two cannot drift on what a line MEANS while
/// agreeing on how it prints. The shape matches [`emit_json_result`], so a
/// consumer reads the same objects whether the scan ran locally or over the
/// socket.
fn json_daemon_reply(line: &str, cli: &Cli, totals: &mut Totals) {
    // As in the human path: the set annotation moves the status word off the end
    // of the line, so classify on the line without it.
    let line = strip_set_annotation(line);
    let (file, status) = match line.rsplit_once(": ") {
        Some((f, s)) => (f, s),
        None => (line, line),
    };
    let obj = if line.ends_with("FOUND") {
        totals.infected += 1;
        let sig = status.strip_suffix(" FOUND").unwrap_or(status);
        serde_json::json!({"file": file, "status": "FOUND", "signature": sig})
    } else if line.ends_with("ERROR") {
        if let Some(tag) = partial_category(line) {
            totals.limits += 1;
            // The reason is what is left once the category and the status word
            // are taken off — the same string `emit_json_result` puts under
            // `reason` for a local scan. Split from the FRONT here, unlike the
            // other two branches: a reason is a sentence and can carry `": "`,
            // where a signature name cannot.
            let head = line
                .strip_suffix(" ERROR")
                .and_then(|h| h.strip_suffix(tag))
                .map_or(line, str::trim_end);
            let (file, reason) = head.split_once(": ").unwrap_or((head, ""));
            serde_json::json!({
                "file": file, "status": "PARTIAL", "category": tag, "reason": reason
            })
        } else {
            totals.errors += 1;
            let reason = status.strip_suffix(" ERROR").unwrap_or(status);
            serde_json::json!({"file": file, "status": "ERROR", "reason": reason})
        }
    } else {
        if cli.quiet {
            return;
        }
        serde_json::json!({"file": file, "category": "clean", "status": "OK"})
    };
    println!("{obj}");
}

/// A stream that can be both read and written and cloned (for split buffering).
trait ReadWrite: io::Read + io::Write {
    fn try_clone_box(&self) -> Box<dyn io::Read + Send>;
}

#[cfg(unix)]
impl ReadWrite for std::os::unix::net::UnixStream {
    fn try_clone_box(&self) -> Box<dyn io::Read + Send> {
        Box::new(self.try_clone().expect("clone unix stream"))
    }
}

impl ReadWrite for std::net::TcpStream {
    fn try_clone_box(&self) -> Box<dyn io::Read + Send> {
        Box::new(self.try_clone().expect("clone tcp stream"))
    }
}

/// `--all-matches` scan of one file: report every matching signature. Works on a
/// buffered copy (bounded by deep-analysis-max); a larger file falls back to a
/// normal single-match scan so it is never silently skipped.
fn scan_one_allmatch(
    path: &Path,
    db: &Scanner,
    opts: &ScanOptions,
    cli: &Cli,
    totals: &mut Totals,
) {
    use std::io::Read;
    totals.scanned += 1;
    // Counted here as well as on the single-match path: a summary reporting
    // "Data scanned: 0.00 MB" for a multi-megabyte archive reads exactly like a
    // scan that skipped its contents, and is expensive to tell apart from one.
    totals.data_scanned += std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let name = path.display().to_string();
    // Two ceilings, one fallback. `deep_analysis_max` is how much this path can
    // buffer; `max_scan_size` is how much the operator said may be scanned at
    // all, and `analyze_all` — which takes bytes, not a file — cannot see it.
    // Whichever is lower decides, because a file over the second must reach the
    // single-match path: that is where the ceiling is enforced, and without this
    // `--all-matches` would answer `OK` for a file `--max-input-bytes` says was
    // never fully examined. A silent clean, produced by adding a flag about how
    // many signatures to report.
    let cap = opts.max_scan_size.map_or(opts.deep_analysis_max, |max| {
        opts.deep_analysis_max.min(max)
    });
    let mut data = Vec::new();
    let read = std::fs::File::open(path).and_then(|f| {
        f.take(cap.saturating_add(1))
            .read_to_end(&mut data)
            .map(|_| ())
    });
    if let Err(e) = read {
        report_error(&name, &e.to_string(), cli, totals);
        return;
    }
    if data.len() as u64 > cap {
        // Too big for all-match; fall back to a single-match scan, which scans
        // the budgeted prefix before reporting the limit, so a detection in the
        // part that did fit still wins.
        let scanned =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan_path(db, path, opts)));
        match scanned {
            Ok(Ok(report)) => report_result(&name, report, cli, totals),
            // An I/O failure has a cause worth printing; only a panic is truly
            // opaque, and folding the two loses the one that says what went
            // wrong.
            Ok(Err(e)) => report_error(&name, &e.to_string(), cli, totals),
            Err(_) => report_error(&name, "internal error while scanning", cli, totals),
        }
        return;
    }
    let found = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exav_core::analyze_all_with_outcome(db, &data, opts)
    }));
    match found {
        Ok((dets, _)) if !dets.is_empty() => {
            totals.infected += 1;
            if cli.json {
                let sigs: Vec<serde_json::Value> = dets
                    .iter()
                    .map(|(sig, method)| {
                        serde_json::json!({"signature": sig, "method": method.as_str()})
                    })
                    .collect();
                // `status` and no `category`, the shape `emit_json_result` uses:
                // `signatures` is the plural of its `signature`, which is the
                // one thing all-match genuinely adds.
                println!(
                    "{}",
                    serde_json::json!({
                        "file": name, "status": "FOUND", "signatures": sigs
                    })
                );
            } else {
                for (sig, method) in dets {
                    outln!("{name}: {sig} FOUND");
                    if cli.verbose {
                        println!("  [method] {}", method.as_str());
                    }
                }
                if cli.bell {
                    print!("\x07");
                }
            }
        }
        // No detections — but "found nothing" and "did not look at all of it" are
        // different answers, and printing OK for both is a silent clean.
        //
        // Turned back into a `ScanReport` and handed to `report_result` rather
        // than rendered here. That is the single-match path, so `--partial-as`,
        // the counters, the exit code, the line grammar and the JSON schema all
        // come from one place: the same file must not answer differently for
        // having been passed `--all-matches`.
        Ok((_, outcome)) => {
            let verdict = match outcome {
                exav_core::AllMatchOutcome::Complete => Verdict::Clean,
                exav_core::AllMatchOutcome::LimitsExceeded(reason) => {
                    Verdict::LimitsExceeded { reason }
                }
                exav_core::AllMatchOutcome::Unscannable(reason) => Verdict::Unscannable { reason },
                exav_core::AllMatchOutcome::PasswordProtected(reason) => {
                    Verdict::PasswordProtected { reason }
                }
            };
            report_result(
                &name,
                ScanReport {
                    verdict,
                    findings: Vec::new(),
                },
                cli,
                totals,
            );
        }
        Err(_) => report_error(&name, "internal error while scanning", cli, totals),
    }
}

/// Emit the final `--json` summary object (counts + timing), mirroring the
/// human `SCAN SUMMARY` fields.
fn emit_json_summary(totals: &Totals, elapsed: std::time::Duration) {
    println!(
        "{}",
        serde_json::json!({
            "summary": {
                "scanned": totals.scanned,
                "infected": totals.infected,
                "partial": totals.limits,
                "errors": totals.errors,
                "data_scanned_bytes": totals.data_scanned,
                "elapsed_secs": elapsed.as_secs_f64(),
            }
        })
    );
}

fn report_result(name: &str, mut report: ScanReport, cli: &Cli, totals: &mut Totals) {
    // Every scan the CLI reports comes through here — human output, JSON,
    // counters and therefore the exit code — so the partial policy is
    // applied once, in front of all of them. Applied per output mode instead, a
    // `pass` would have had to be remembered four times, and forgetting the
    // counters would mean an object the operator asked to pass still exiting 2.
    // (`--profile` is the one path that does not reach here: it prints a CSV row
    // and returns, so it applies the policy itself and counts the same way.)
    policy::apply(&mut report, policy::current());
    // Classification, status tag and detail all come from exav-core so this
    // human output and the daemon's wire output can't disagree (see
    // `Verdict::category`/`status_tag`/`detail`).
    let v = &report.verdict;
    // Update counters first (identical in every output mode), then render.
    match v.category() {
        VerdictCategory::Infected => totals.infected += 1,
        // `--partial-as error` is the one status `apply` cannot express in the
        // report: it changes no verdict, only which counter — and therefore
        // which exit code — this object contributes to. The line still names
        // the category, so the report has to keep it.
        VerdictCategory::Partial => {
            if policy::current().for_tag(v.status_tag()) == policy::PartialStatus::Error {
                totals.errors += 1;
            } else {
                totals.limits += 1;
            }
        }
        VerdictCategory::Clean => {}
    }
    if cli.json {
        emit_json_result(name, &report, cli);
        return;
    }
    match v.category() {
        VerdictCategory::Infected => {
            // A detection with no name renders `<path>: FOUND`, not a stray
            // double space that a clamscan-output parser splitting on
            // whitespace would read as an empty field.
            match v.detail() {
                Some(d) if !d.is_empty() => outln!("{name}: {d} FOUND"),
                _ => outln!("{name}: FOUND"),
            }
            if cli.verbose {
                if let Verdict::Infected { method, .. } = v {
                    println!("  [method] {}", method.as_str());
                }
            }
            if cli.bell {
                print!("\x07");
            }
        }
        // Limit hit / undecodable / encrypted — all "work happened and stopped
        // short". One grammar with every other line: `path: [reason ][CATEGORY ]
        // STATUS`, the status word last, which is where `clamscan` puts `OK` and
        // `FOUND` and therefore where anything reading these lines looks.
        //
        // `--partial-as error` prints the same line: the object is still partial
        // and the category still has to be named. Only the exit code differs,
        // which is the one thing a line cannot carry.
        VerdictCategory::Partial => {
            let status =
                if policy::current().for_tag(v.status_tag()) == policy::PartialStatus::Error {
                    "ERROR"
                } else {
                    "PARTIAL"
                };
            outln!(
                "{name}: {} {} {status}",
                v.detail().unwrap_or_default(),
                v.status_tag()
            );
        }
        VerdictCategory::Clean => {
            if !cli.quiet {
                outln!("{name}: OK");
            }
        }
    }
    if cli.verbose {
        for f in &report.findings {
            println!("  [{}] {}", f.label, f.detail);
        }
    }
}

/// The status word for a report, in JSON as on a line.
///
/// The same four values everywhere — `OK`, `FOUND`, `ERROR`, `PARTIAL` — each
/// naming the exit code it contributes, so a machine consumer and a human read
/// the same vocabulary and neither needs a translation table.
fn status_str(c: VerdictCategory, tag: &str) -> &'static str {
    match c {
        VerdictCategory::Clean => "OK",
        VerdictCategory::Infected => "FOUND",
        VerdictCategory::Partial => {
            if policy::current().for_tag(tag) == policy::PartialStatus::Error {
                "ERROR"
            } else {
                "PARTIAL"
            }
        }
    }
}

/// Emit one newline-delimited JSON object for a scan result. `--quiet`
/// suppresses clean results (matching the human output). Findings are always
/// included so the machine consumer never needs `-v`.
fn emit_json_result(name: &str, report: &ScanReport, cli: &Cli) {
    let v = &report.verdict;
    let cat = v.category();
    if cat == VerdictCategory::Clean && cli.quiet {
        return;
    }
    let mut obj = serde_json::Map::new();
    obj.insert("file".into(), name.into());
    // `status` is the same word the line ends with; `category` says which of the
    // three conditions produced a PARTIAL, and is absent for the other statuses
    // because they have no sub-classification to give.
    obj.insert("status".into(), status_str(cat, v.status_tag()).into());
    if cat == VerdictCategory::Partial {
        obj.insert("category".into(), v.status_tag().into());
    }
    if let Some(d) = v.detail() {
        // For Infected this is the signature name; otherwise the reason string.
        let key = if cat == VerdictCategory::Infected {
            "signature"
        } else {
            "reason"
        };
        obj.insert(key.into(), d.into());
    }
    if let Verdict::Infected { method, offset, .. } = v {
        obj.insert("method".into(), method.as_str().into());
        obj.insert("offset".into(), (*offset).into());
    }
    if !report.findings.is_empty() {
        obj.insert(
            "findings".into(),
            serde_json::Value::Array(
                report
                    .findings
                    .iter()
                    .map(|f| serde_json::json!({"label": f.label, "detail": f.detail}))
                    .collect(),
            ),
        );
    }
    println!("{}", serde_json::Value::Object(obj));
}

/// ClamAV functionality level exav emulates (see `engine::EXAV_FLEVEL`), and the
/// ClamAV release that flevel corresponds to — reported as the engine version so
/// clamscan-parsing tooling sees a recognised, recent engine.
pub(crate) const CLAMAV_COMPAT_VERSION: &str = "1.4.3";

/// Print a clamscan-compatible `SCAN SUMMARY` (same field names and order, so
/// existing clamscan-output parsers work). exav-specific counters are shown only
/// with `-v`/`--verbose`.
fn print_summary(db: &Scanner, totals: &Totals, elapsed: std::time::Duration, verbose: bool) {
    let mb = totals.data_scanned as f64 / (1024.0 * 1024.0);
    let secs = elapsed.as_secs_f64();
    let (m, s) = (elapsed.as_secs() / 60, elapsed.as_secs() % 60);
    println!("\n----------- SCAN SUMMARY -----------");
    println!("Known viruses: {}", db.signature_count());
    println!("Engine version: {CLAMAV_COMPAT_VERSION}");
    println!("Scanned directories: {}", totals.dirs);
    println!("Scanned files: {}", totals.scanned);
    println!("Infected files: {}", totals.infected);
    if totals.limits > 0 {
        println!("Total errors: {}", totals.limits + totals.errors);
    } else if totals.errors > 0 {
        println!("Total errors: {}", totals.errors);
    }
    println!("Data scanned: {mb:.2} MB");
    println!("Data read: {mb:.2} MB (ratio 0.00:1)");
    println!("Time: {secs:.3} sec ({m} m {s} s)");
    if verbose {
        // exav-specific detail (not part of clamscan's summary).
        println!("Engine signatures: {}", db.signature_count());
        println!("Unsupported sigs skipped: {}", db.unsupported_count());
        println!("Bytecode programs loaded: {}", db.bytecode_count());
        if totals.limits > 0 {
            println!("Limits exceeded (unscanned, not clean): {}", totals.limits);
        }
    }
}

/// Parse `--workers`: a worker count, or `threads` for the in-process model.
///
/// `0` is refused rather than accepted as the thread model, which is what it
/// used to mean. A count of zero reads as "no workers", not "a different process
/// architecture" — and the two models differ in isolation, in whether a single
/// job can be killed, and in whether the listeners share one set of counters.
/// None of that is something a reader infers from a digit.
fn parse_workers(s: &str) -> Result<usize, String> {
    if s.eq_ignore_ascii_case("threads") {
        return Ok(0);
    }
    match s.parse::<usize>() {
        Ok(0) => Err(
            "a worker count of 0 is not a worker model; say `--workers threads` for the \
             in-process model"
                .to_string(),
        ),
        Ok(n) => Ok(n),
        Err(_) => Err(format!("expected a worker count or `threads`, got `{s}`")),
    }
}

/// Parse a number of seconds, or `off`.
///
/// `off` rather than `0`, because for a duration `0` has an honest second
/// reading — "immediately", "every time" — and a flag whose disable value is
/// also a plausible setting is one an operator can get backwards without ever
/// seeing an error. `0` is refused and says which word to use.
fn parse_secs_or_off(s: &str) -> Result<u64, String> {
    if s.eq_ignore_ascii_case("off") {
        return Ok(0);
    }
    match s.parse::<u64>() {
        Ok(0) => Err("say `off` to disable this; `0` seconds would read as \"always\"".to_string()),
        Ok(n) => Ok(n),
        Err(_) => Err(format!("expected a number of seconds or `off`, got `{s}`")),
    }
}

/// Parse a size with optional K/M/G/T suffix (base-1024), like clamscan.
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty size".to_string());
    }
    // Match on the last byte (not char) so a multibyte trailing character
    // can't cause a non-char-boundary slice panic.
    let (num, mult) = match s.as_bytes()[s.len() - 1] {
        b'K' | b'k' => (&s[..s.len() - 1], 1024u64),
        b'M' | b'm' => (&s[..s.len() - 1], 1024 * 1024),
        b'G' | b'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        b'T' | b't' => (&s[..s.len() - 1], 1024u64 * 1024 * 1024 * 1024),
        _ => (s, 1u64),
    };
    let base: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid size: {s}"))?;
    base.checked_mul(mult)
        .ok_or_else(|| format!("size overflow: {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Environment variables set for the length of a test and put back
    /// afterwards, whatever they were, so no test leaves configuration behind
    /// for the next one to read as its own.
    struct EnvVars(Vec<(String, Option<String>)>);

    impl EnvVars {
        fn set(vars: &[(&str, &str)]) -> Self {
            let saved = vars
                .iter()
                .map(|(k, v)| {
                    let prev = std::env::var(k).ok();
                    std::env::set_var(k, v);
                    ((*k).to_string(), prev)
                })
                .collect();
            Self(saved)
        }
    }

    impl Drop for EnvVars {
        fn drop(&mut self) {
            for (k, prev) in &self.0 {
                match prev {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    /// A session command answers with as many messages as it has files to
    /// answer about, and only the marker says it has stopped.
    ///
    /// Reading a fixed single line takes the first verdict, drops the rest, and
    /// leaves them in the socket for the next command to read as its own answer
    /// — a detection lost and a verdict misattributed from one read.
    #[test]
    fn a_session_reply_runs_to_its_marker() {
        let wire: &[u8] = b"1: /t/a: OK\x001: /t/b: Eicar-Test-Signature FOUND\x00\
                            2: PONG\x003: /t/c: OK\x00";
        let mut r = std::io::BufReader::new(wire);

        let replies = read_session_replies(&mut r, 2).expect("the marker arrived");
        assert_eq!(
            replies,
            vec![
                "/t/a: OK".to_string(),
                "/t/b: Eicar-Test-Signature FOUND".to_string(),
            ],
            "every message before the marker belongs to the scan"
        );
        assert_eq!(
            read_reply(&mut r).unwrap().as_deref(),
            Some("3: /t/c: OK"),
            "and the next command's answer is still waiting, unconsumed"
        );
    }

    /// A daemon that stops talking before the marker has not answered the
    /// command. Handing back the lines that did arrive as the whole answer
    /// would report a tree as scanned on the strength of its first files.
    #[test]
    fn a_session_reply_cut_short_is_an_error() {
        let wire: &[u8] = b"1: /t/a: OK\x00";
        let mut r = std::io::BufReader::new(wire);
        assert!(
            read_session_replies(&mut r, 2).is_err(),
            "an answer that never ended is not an answer"
        );
    }

    /// Two ways a daemon can fail to mark the end, neither of which may leave
    /// the client waiting on a message that is not coming: replies that have
    /// lost step with the commands, and a daemon that tags no ids at all.
    #[test]
    fn a_session_reply_out_of_step_does_not_block() {
        let ahead: &[u8] = b"5: /t/a: OK\x00";
        assert!(
            read_session_replies(&mut std::io::BufReader::new(ahead), 2).is_err(),
            "an answer to a command that has not been sent yet is not this \
             command's answer"
        );

        let untagged: &[u8] = b"/t/a: OK\x00";
        assert_eq!(
            read_session_replies(&mut std::io::BufReader::new(untagged), 2).unwrap(),
            vec!["/t/a: OK".to_string()],
            "an untagged reply is taken as the whole answer, not waited on"
        );
    }

    /// Only a leading number is a command id. A verdict line carries colons of
    /// its own — the one after the path, and any inside the path — and reading
    /// one of those as the id would strip part of the file name off the reply.
    #[test]
    fn only_a_leading_number_is_a_session_id() {
        assert_eq!(split_session_id("7: /t/x: OK"), (Some(7), "/t/x: OK"));
        assert_eq!(
            split_session_id("/t/od: d: OK"),
            (None, "/t/od: d: OK"),
            "a path with a colon in it is not an id"
        );
        assert_eq!(split_session_id("PONG"), (None, "PONG"));
    }

    /// A reachable daemon must not be stoppable by whoever reaches it.
    ///
    /// The failure this guards is quiet: a scanner that has been shut down does
    /// not report infected, it reports nothing, and a pipeline that reads "no
    /// answer" as "nothing wrong" then passes everything. The flag's own help
    /// text promises refusal is the default, so the default is the contract.
    ///
    /// This asserts the policy function rather than any one listening mode
    /// because the defect it replaces was not in the policy — it was three
    /// modes each deciding it separately, one of them the other way round.
    /// `shutdown_allowed` exists so there is only one answer to assert.
    ///
    /// The setting used to have two spellings in opposite polarities: an
    /// `EXAV_ALLOW_SHUTDOWN` env var that turned it on and a
    /// `--no-shutdown-command` flag that could only turn it off. `--allow-shutdown`
    /// is one setting with the env var as its own, which is what makes the
    /// question below answerable by parsing rather than by two sources.
    #[test]
    fn shutdown_is_refused_unless_the_operator_opts_in() {
        let _env = env_guard();
        let restore = std::env::var("EXAV_ALLOW_SHUTDOWN").ok();
        std::env::remove_var("EXAV_ALLOW_SHUTDOWN");

        let off = Cli::parse_from(["exav", "--listen", "clamd://h:1"]);
        assert!(
            !shutdown_allowed(off.allow_shutdown),
            "with no opt-in, SHUTDOWN must be refused"
        );

        let on = Cli::parse_from(["exav", "--listen", "clamd://h:1", "--allow-shutdown"]);
        assert!(
            shutdown_allowed(on.allow_shutdown),
            "--allow-shutdown restores clamd's behaviour"
        );

        std::env::set_var("EXAV_ALLOW_SHUTDOWN", "1");
        let from_env = Cli::parse_from(["exav", "--listen", "clamd://h:1"]);
        assert!(
            shutdown_allowed(from_env.allow_shutdown),
            "EXAV_ALLOW_SHUTDOWN=1 is the same setting under its own name"
        );

        match restore {
            Some(v) => std::env::set_var("EXAV_ALLOW_SHUTDOWN", v),
            None => std::env::remove_var("EXAV_ALLOW_SHUTDOWN"),
        }
    }

    /// Assert every limit flag in `argv` lands on its own field, using the
    /// distinct sentinels 101..106 so any swapped pair fails loudly. `argv`
    /// carries the six spellings under test; `label` names the spelling family
    /// in the assertion messages.
    ///
    /// `--max-object-bytes` is parsed on its own because it also sets the
    /// deep-analysis cap (one knob for the largest single allocation), which
    /// would mask the extracted-bytes assertion.
    fn assert_limit_flags(label: &str, argv: [&str; 11], buffer_argv: [&str; 3]) {
        let opts = build_scan_options(&Cli::parse_from(argv));
        assert_eq!(opts.max_scan_size, Some(101), "{label}: input bytes");
        assert_eq!(opts.deep_analysis_max, 102, "{label}: extracted (deep)");
        assert_eq!(
            opts.limits.max_extracted_bytes, 102,
            "{label}: extracted (total)"
        );
        assert_eq!(opts.limits.max_scanned_bytes, 103, "{label}: scanned bytes");
        assert_eq!(opts.limits.max_recursion, 104, "{label}: recursion");
        assert_eq!(opts.limits.max_members, 105, "{label}: members");

        let opts = build_scan_options(&Cli::parse_from(buffer_argv));
        assert_eq!(opts.limits.max_buffer_bytes, 106, "{label}: buffer bytes");
        assert_eq!(opts.deep_analysis_max, 106, "{label}: buffer (deep)");
    }

    /// Pins the flag→field mapping in [`build_scan_options`], for exav's own
    /// flag names and for every clamscan alias that has to keep working. Both
    /// tables are asserted against the same sentinels, so an alias silently
    /// detaching from its field — or landing on a neighbouring one — fails
    /// here rather than in someone's migrated command line.
    #[test]
    fn limit_flags_land_on_their_fields() {
        let _env = env_guard();
        assert_limit_flags(
            "exav",
            [
                "exav",
                "--max-input-bytes",
                "101",
                "--max-extracted-bytes",
                "102",
                "--max-matcher-bytes",
                "103",
                "--max-depth",
                "104",
                "--max-members",
                "105",
            ],
            ["exav", "--max-object-bytes", "106"],
        );
        // Each bound has exactly one spelling. clamscan's names are not hidden
        // aliases for it: two names for one bound is two things to document and
        // one more way for a command line to be subtly wrong.
        for gone in [
            "--max-filesize",
            "--max-scansize",
            "--max-files",
            "--max-buffer",
            "--max-scan-total",
        ] {
            assert!(
                Cli::try_parse_from(["exav", gone, "1M"]).is_err(),
                "{gone} is a clamscan spelling and must not be accepted"
            );
        }

        // With no flags, the defaults the --help text quotes.
        let opts = build_scan_options(&Cli::parse_from(["exav"]));
        assert_eq!(opts.max_scan_size, None);
        assert_eq!(opts.deep_analysis_max, 256 * 1024 * 1024);
        assert_eq!(opts.limits.max_extracted_bytes, 1024 * 1024 * 1024);
        assert_eq!(opts.limits.max_buffer_bytes, 256 * 1024 * 1024);
        assert_eq!(opts.limits.max_scanned_bytes, 10 * 1024 * 1024 * 1024);
        assert_eq!(opts.limits.max_recursion, 16);
        assert_eq!(opts.limits.max_members, 100_000);

        // The --clamav-compat preset supplies ClamAV's documented defaults.
        let opts = build_scan_options(&Cli::parse_from(["exav", "--clamav-compat"]));
        assert_eq!(opts.max_scan_size, Some(100 * 1024 * 1024));
        assert_eq!(opts.limits.max_extracted_bytes, 400 * 1024 * 1024);
        assert_eq!(opts.limits.max_recursion, 17);
        assert_eq!(opts.limits.max_members, 10_000);
    }

    /// Pins the ClamAV-compatibility surface documented by the flag matrix
    /// (`www/src/content/docs/reference/clamav-flag-matrix.md`).
    ///
    /// Both halves matter, and the second one more. A spelling that stops
    /// parsing breaks a migrated command line, which the operator finds out
    /// about at once. A spelling that *starts* parsing is a flag the matrix
    /// calls absent while exav quietly takes it — a reader then believes the
    /// setting is in effect, and nothing on the command line says otherwise.
    /// Adding a flag here is part of adding it to the page.
    #[test]
    fn clamav_spellings_are_accepted_or_refused_as_documented() {
        let _env = env_guard();
        // exav does not take clamscan's command line. What it does share is the
        // handful of short flags any scanner has, spelled the obvious way — and
        // the promise that anything else stops the run instead of being
        // swallowed, which is what the flag matrix documents.
        for argv in [
            &["-v"][..],
            &["-d", "db.ndb"],
            &["--no-recursive"],
            &["--verbose"],
            &["--bell"],
            &["--quiet"],
            &["--all-matches"],
            &["--database", "db.ndb"],
            &["--files-from", "list.txt"],
            &["--log", "scan.log"],
            &["--exclude", "re"],
            &["--exclude-dir", "re"],
            &["--include", "re"],
            &["--max-depth", "5"],
            &["--alert-ssns", "3"],
            &["--alert-credit-cards", "3"],
            // The ways of handing the daemon a file it cannot open itself.
            // Refused outside client mode, which is a conflict check rather
            // than a parse error.
            &["--send-as", "contents"],
            &["--send-as", "fd"],
        ] {
            let full: Vec<&str> = std::iter::once("exav")
                .chain(argv.iter().copied())
                .collect();
            assert!(
                Cli::try_parse_from(&full).is_ok(),
                "{argv:?} is documented as accepted, but does not parse"
            );
        }

        // Refused: the matrix calls each of these absent, and a reader relies
        // on the run stopping rather than the flag being swallowed. The
        // `=yes` value form clamscan spells its switches with is refused too.
        for argv in [
            &["-a"][..],
            &["-o"],
            &["-z"],
            &["-l", "scan.log"],
            &["-m"],
            &["--archive-verbose"],
            &["--debug"],
            &["--stdout"],
            &["--suppress-ok-results"],
            &["--tempdir", "/tmp"],
            &["--leave-temps"],
            &["--force-to-disk"],
            &["--gen-json"],
            &["--official-db-only"],
            &["--fail-if-cvd-older-than", "7"],
            &["--cross-fs"],
            &["--follow-dir-symlinks", "1"],
            &["--follow-file-symlinks", "1"],
            &["--remove"],
            &["--move", "/q"],
            &["--copy", "/q"],
            &["--include-dir", "re"],
            &["--bytecode"],
            &["--bytecode-unsigned"],
            &["--bytecode-timeout", "5"],
            &["--statistics", "none"],
            &["--exclude-pua", "cat"],
            &["--include-pua", "cat"],
            &["--detect-structured"],
            &["--structured-ssn-format", "1"],
            &["--structured-cc-mode", "1"],
            &["--scan-mail"],
            &["--scan-pe"],
            &["--scan-elf"],
            &["--scan-ole2"],
            &["--scan-pdf"],
            &["--scan-swf"],
            &["--scan-html"],
            &["--scan-xmldocs"],
            &["--scan-hwp3"],
            &["--scan-onenote"],
            &["--scan-archive"],
            &["--scan-image"],
            &["--scan-image-fuzzy-hash"],
            &["--phishing-sigs"],
            &["--phishing-scan-urls"],
            &["--heuristic-alerts"],
            &["--heuristic-scan-precedence"],
            &["--normalize"],
            &["--alert-encrypted-archive"],
            &["--alert-encrypted-doc"],
            &["--alert-phishing-ssl"],
            &["--alert-phishing-cloak"],
            &["--nocerts"],
            &["--dumpcerts"],
            &["--max-scantime", "1000"],
            &["--max-dir-recursion", "5"],
            &["--max-embeddedpe", "1M"],
            &["--max-htmlnormalize", "1M"],
            &["--max-htmlnotags", "1M"],
            &["--max-scriptnormalize", "1M"],
            &["--max-ziptypercg", "1M"],
            &["--max-partitions", "5"],
            &["--max-iconspe", "5"],
            &["--max-rechwp3", "5"],
            &["--pcre-match-limit", "5"],
            &["--pcre-recmatch-limit", "5"],
            &["--pcre-max-filesize", "1M"],
            &["--disable-cache"],
            // clamdscan's client-side flags.
            &["--config-file", "clamd.conf"],
            &["--multiscan"],
            &["--reload"],
            &["--ping", "1"],
            &["--wait"],
            // clamscan's `--flag=yes/no` value form.
            &["--allmatch=yes"],
            &["--recursive=no"],
        ] {
            let full: Vec<&str> = std::iter::once("exav")
                .chain(argv.iter().copied())
                .collect();
            assert!(
                Cli::try_parse_from(&full).is_err(),
                "{argv:?} is documented as absent, but parses — either implement \
                 it properly or correct the flag matrix; silently accepting it \
                 tells an operator the setting is in effect when it is not"
            );
        }
    }

    /// An address with no `?mode=` gets the documented default, and it is the
    /// one the daemon actually binds with — owner-only, so a socket left
    /// unqualified is never reachable by another local user.
    #[test]
    fn an_unqualified_socket_is_owner_only() {
        assert_eq!(daemon::DEFAULT_SOCKET_MODE, 0o600);
        let Some(endpoint::Endpoint {
            addr: endpoint::Addr::Unix { mode, .. },
            ..
        }) = clamd_endpoint(&Cli::parse_from(["exav", "--listen", "/run/x.sock"]))
        else {
            panic!("a path is a Unix clamd listener");
        };
        assert_eq!(mode, None, "no mode asked for, so the default applies");
    }

    /// `--send-as` is refused where it would do nothing, so a command line that
    /// asks for a transport either gets it or stops.
    ///
    /// One dial rather than a switch per transport: `path`, `contents` and `fd`
    /// are alternatives, so there is no combination of two to refuse.
    #[test]
    fn send_as_needs_a_daemon_to_send_to() {
        let _env = env_guard();
        let refused = |argv: &[&str]| {
            let cli = Cli::parse_from(std::iter::once("exav").chain(argv.iter().copied()));
            check_flag_conflicts(&cli).is_err()
        };
        assert!(refused(&["--send-as", "contents", "f"]), "no endpoint");
        assert!(refused(&["--send-as", "fd", "f"]), "no endpoint");
        assert!(
            refused(&["--listen", "/s", "--connect", "/s", "f"]),
            "a run accepts connections or makes one, not both"
        );
        assert!(
            refused(&["--connect", "h:1", "--send-as", "fd", "f"]),
            "a descriptor cannot cross a TCP connection"
        );
        assert!(
            refused(&[
                "--connect",
                "/s",
                "--send-as",
                "contents",
                "--all-matches",
                "f"
            ]),
            "one verdict comes back, and --all-matches asks for every match"
        );
        assert!(
            refused(&["--listen", "/s", "f"]),
            "a listener takes no paths to scan"
        );
        assert!(
            Cli::try_parse_from(["exav", "--send-as", "socket", "f"]).is_err(),
            "an unknown transport is refused rather than read as the default"
        );

        for ok in [
            &["--connect", "/s", "--send-as", "contents", "f"][..],
            &["--connect", "/s", "--send-as", "fd", "f"],
            &["--connect", "h:1", "--send-as", "contents", "f"],
            &[
                "--connect",
                "h:1",
                "--send-as",
                "path",
                "--all-matches",
                "f",
            ],
            &["--listen", "clamd:///s?mode=660"],
        ] {
            let cli = Cli::parse_from(std::iter::once("exav").chain(ok.iter().copied()));
            assert!(
                check_flag_conflicts(&cli).is_ok(),
                "{ok:?} is a working combination"
            );
        }
    }

    /// The ICAP listener is opt-in and composes: no flag, no port, and asking
    /// for it alongside the clamd daemon is a working command line rather than a
    /// refused one.
    #[cfg(feature = "icap")]
    #[test]
    fn icap_is_opt_in_and_composes() {
        let _env = env_guard();
        let cli =
            |argv: &[&str]| Cli::parse_from(std::iter::once("exav").chain(argv.iter().copied()));

        // Nothing about a plain scan or the clamd listener turns ICAP on.
        let clamd = ["--listen", "clamd://h:1"];
        for quiet in [
            &["file"][..],
            &clamd,
            &["--listen", "clamd://h:1", "--auto-update"],
        ] {
            assert!(
                icap_endpoint(&cli(quiet)).is_none(),
                "{quiet:?} must not start an ICAP listener"
            );
        }
        assert!(icap_endpoint(&cli(&["--listen", "icap://h:1"])).is_some());

        assert!(
            check_flag_conflicts(&cli(&["--listen", "icap://h:1", "file"])).is_err(),
            "a listener is a server, not a scan"
        );
        for ok in [
            &["--listen", "icap://h:1"][..],
            &["--listen", "icap://h:1", "--listen", "clamd://h:2"],
            &[
                "--listen",
                "icap://h:1",
                "--listen",
                "clamd://h:2",
                "--auto-update",
            ],
        ] {
            assert!(
                check_flag_conflicts(&cli(ok)).is_ok(),
                "{ok:?} is a working combination: two listeners, one process"
            );
        }
    }

    /// The ICAP defaults are the service names and bounds a c-icap deployment
    /// already answers on, and a flag replaces the one it names and no other.
    #[cfg(feature = "icap")]
    #[test]
    fn icap_settings_come_from_flags_then_defaults() {
        let _env = env_guard();
        // No `--listen icap://…` at all: the defaults still resolve, which is
        // what the settings below are measured against.
        let cfg = icap::config_from_cli(&Cli::parse_from(["exav"])).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:1344");
        assert_eq!(cfg.services, ["avscan", "srv_clamav", "virus_scan"]);
        // Out of the box every block is legible to a client that reads only
        // `X-Infection-Found`, which is what makes exav a safe swap for a
        // c-icap container behind such a client.
        assert_eq!(cfg.infection_header, icap::InfectionHeader::Blocks);
        // exav does not take the c-icap trade on a deployment's behalf.
        assert_eq!(cfg.partial_as, policy::PartialAs::default());

        let cfg = icap::config_from_cli(&Cli::parse_from([
            "exav",
            "--listen",
            "icap://127.0.0.1:2000?service=one&service=two",
            "--icap-preview-bytes",
            "512",
            "--icap-infection-header",
            "detections",
            "--partial-as",
            "password-protected=ok",
        ]))
        .unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:2000");
        // Naming services replaces the defaults rather than adding to them, so
        // exav never answers on a name nobody configured.
        assert_eq!(cfg.services, ["one", "two"]);
        assert_eq!(cfg.preview_size, 512);
        // The ICAP listener has no size ceiling of its own to configure: an
        // object's size is `--max-input-bytes`, the same on every surface.
        assert!(
            Cli::try_parse_from(["exav", "--icap-max-object-size", "5M"]).is_err(),
            "a per-listener size ceiling would answer differently from the daemon"
        );
        assert_eq!(cfg.infection_header, icap::InfectionHeader::Detections);
        // The ICAP listener does not have its own pass policy: `--partial-as`
        // answers the same question for the CLI's exit code and the daemon's
        // reply, and one question with two answers is how two surfaces come to
        // disagree about the same object.
        assert_eq!(
            cfg.partial_as,
            policy::PartialAs::parse("password-protected=ok").unwrap()
        );

        // A value neither flag recognises is refused at parse time rather than
        // falling back to a policy nobody asked for. Both of these decide what
        // reaches a client for an object exav could not examine, so a typo that
        // parsed would be a hole nobody knows they are running.
        for bad in [
            &["--icap-infection-header", "sometimes"][..],
            &["--partial-as", "unscannble"],
        ] {
            assert!(
                Cli::try_parse_from(["exav"].iter().chain(bad.iter()).copied()).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn spill_budgets_have_to_nest() {
        let _env = env_guard();
        let cli =
            |argv: &[&str]| Cli::parse_from(std::iter::once("exav").chain(argv.iter().copied()));

        // RAM inside one object inside the process. A configuration that
        // inverts the nesting is two statements that cannot both hold, and
        // finding out from an UNSCANNABLE verdict in production is finding out
        // late.
        let err = |argv: &[&str]| configure_spill(&cli(argv)).unwrap_err();
        assert!(
            err(&["--max-spill-bytes", "4G", "--max-total-spill-bytes", "1G"])
                .contains("exceeds --max-total-spill-bytes")
        );
        assert!(
            err(&["--spill-threshold-bytes", "1G", "--max-spill-bytes", "16M"])
                .contains("exceeds --max-spill-bytes")
        );
        assert!(err(&["--spill-dir", "/definitely/not/here"]).contains("not a directory"));

        // A nesting that holds is accepted, and the defaults are one.
        assert!(configure_spill(&cli(&[])).is_ok());
        assert!(configure_spill(&cli(&[
            "--spill-threshold-bytes",
            "1M",
            "--max-spill-bytes",
            "64M",
            "--max-total-spill-bytes",
            "256M"
        ]))
        .is_ok());

        // `0` is "no ceiling" here as on every other --max- size flag, so it
        // cannot make the nesting fail — and cannot be mistaken for the way to
        // turn spilling off.
        assert!(configure_spill(&cli(&["--max-spill-bytes", "0"])).is_ok());
        assert!(configure_spill(&cli(&["--max-total-spill-bytes", "0"])).is_ok());

        // `--spill-dir off` needs no disk budgets, and saying both is a
        // contradiction rather than a preference.
        assert!(configure_spill(&cli(&["--spill-dir", "off"])).is_ok());
        assert!(configure_spill(&cli(&[
            "--spill-dir",
            "off",
            "--spill-threshold-bytes",
            "512M"
        ]))
        .is_ok());
        assert!(err(&["--spill-dir", "off", "--max-spill-bytes", "1G"]).contains("--spill-dir off"));
    }

    /// The updater-only deployment — keep the signature volume current, serve
    /// nothing — is inferred rather than declared.
    ///
    /// A flag saying it could contradict itself: the flag plus a listener is a
    /// run whose two halves disagree, and it takes a conflict check to catch.
    /// Asking to update while asking for nothing else says the same thing and has
    /// no second half, so the state the check protected against is
    /// unrepresentable.
    #[test]
    fn an_updater_serves_nothing() {
        let _env = env_guard();
        let cli =
            |argv: &[&str]| Cli::parse_from(std::iter::once("exav").chain(argv.iter().copied()));

        assert!(updater_only(&cli(&["--auto-update"])));
        // An empty address names no listener, which is how a container removes
        // the one its image's ENV set — so it is an updater too, not a server
        // that binds nothing.
        assert!(updater_only(&cli(&["--auto-update", "--listen", ""])));
        for serving in [
            &["--auto-update", "--listen", "clamd://h:1"][..],
            &["--auto-update", "file"],
            &["--auto-update", "--build-db", "out.exavdb"],
        ] {
            assert!(
                !updater_only(&cli(serving)),
                "{serving:?} asks this process to do something besides update"
            );
        }
    }

    /// Every setting reads the flag first, the environment next, and its own
    /// default last — one rule, applied to every kind of setting there is: a
    /// switch, a path, a number, a size, a listen address and a repeatable list.
    ///
    /// The rule is what makes a container configurable by environment without
    /// any command line becoming a special case. Getting it backwards for one
    /// setting is not a small bug: an operator who passes a flag to override the
    /// image's environment gets the environment's value and no indication of it.
    #[test]
    fn a_flag_beats_the_environment_and_the_environment_beats_the_default() {
        let _env = env_guard();
        let cli =
            |argv: &[&str]| Cli::parse_from(std::iter::once("exav").chain(argv.iter().copied()));

        // Defaults, with nothing set anywhere.
        let d = cli(&[]);
        assert_eq!(d.sigs, PathBuf::from("/var/lib/exav"));
        assert!(d.listen.is_empty());
        assert_eq!(d.workers, None);
        assert!(!d.auto_update);
        assert!(!d.allow_no_db);

        let _vars = EnvVars::set(&[
            ("EXAV_SIGS_DIR", "/env/sigs"),
            ("EXAV_LISTEN", "clamd://10.0.0.1:3310,icap://10.0.0.1:1344"),
            ("EXAV_WORKERS", "3"),
            ("EXAV_MAX_PROCESS_BYTES", "512M"),
            ("EXAV_STARTUP_WAIT_SECS", "90"),
            ("EXAV_AUTO_UPDATE", "yes"),
            ("EXAV_ALLOW_NO_DB", "true"),
            ("EXAV_LOG", "/env/scan.log"),
        ]);

        // The environment beats the defaults.
        let e = cli(&[]);
        assert_eq!(e.sigs, PathBuf::from("/env/sigs"));
        // One variable now carries both listeners, which is the point of putting
        // the protocol in the value rather than in the flag name.
        assert_eq!(
            e.listen,
            vec![
                "clamd://10.0.0.1:3310".to_string(),
                "icap://10.0.0.1:1344".to_string()
            ]
        );
        assert_eq!(e.workers, Some(3));
        assert_eq!(e.max_scan_memory, Some(512 * 1024 * 1024));
        assert_eq!(e.startup_timeout, Some(90));
        assert_eq!(e.log, Some(PathBuf::from("/env/scan.log")));
        assert!(e.auto_update, "EXAV_AUTO_UPDATE=yes is a set flag");
        assert!(e.allow_no_db, "EXAV_ALLOW_NO_DB=true is a set flag");

        // And a flag beats the environment, for every one of them.
        let f = cli(&[
            "--sigs-dir",
            "/flag/sigs",
            "--listen",
            "127.0.0.1:9999",
            "--workers",
            "7",
            "--max-process-bytes",
            "64M",
            "--startup-wait-secs",
            "5",
            "--log",
            "/flag/scan.log",
        ]);
        assert_eq!(f.sigs, PathBuf::from("/flag/sigs"));
        // The flag replaces the environment's whole list rather than adding to
        // it, so a run listens on exactly what it was given.
        assert_eq!(f.listen, vec!["127.0.0.1:9999".to_string()]);
        assert_eq!(f.workers, Some(7));
        assert_eq!(f.max_scan_memory, Some(64 * 1024 * 1024));
        assert_eq!(f.startup_timeout, Some(5));
        assert_eq!(f.log, Some(PathBuf::from("/flag/scan.log")));

        // The ICAP services ride on the address, so they inherit the one
        // precedence rule rather than having their own: a `--listen` replaces
        // the environment's address entire, services included. Nothing can
        // half-override, because there is only ever one address in play.
        #[cfg(feature = "icap")]
        {
            let _listen =
                EnvVars::set(&[("EXAV_LISTEN", "icap://0.0.0.0:1344?service=a&service=b")]);
            let e = icap::config_from_cli(&cli(&[])).unwrap();
            assert_eq!(e.services, ["a", "b"]);
            let f = icap::config_from_cli(&cli(&["--listen", "icap://0.0.0.0:1344/from_flag"]))
                .unwrap();
            assert_eq!(f.services, ["from_flag"]);
        }
    }

    /// A switch set in the environment is read the way a container writes one,
    /// and a value that is neither true nor false stops the run instead of being
    /// guessed at — a typo would otherwise be indistinguishable from not setting
    /// it, and `EXAV_AUTO_UPDATE=ture` would silently update nothing.
    #[test]
    fn an_environment_switch_is_true_false_or_an_error() {
        let _env = env_guard();
        for on in ["1", "true", "yes", "on"] {
            let _v = EnvVars::set(&[("EXAV_AUTO_UPDATE", on)]);
            assert!(
                Cli::try_parse_from(["exav"])
                    .expect("a known spelling")
                    .auto_update,
                "EXAV_AUTO_UPDATE={on} must set the flag"
            );
        }
        for off in ["0", "false", "no", "off"] {
            let _v = EnvVars::set(&[("EXAV_AUTO_UPDATE", off)]);
            assert!(
                !Cli::try_parse_from(["exav"])
                    .expect("a known spelling")
                    .auto_update,
                "EXAV_AUTO_UPDATE={off} must leave the flag unset"
            );
        }
        for bad in ["ture", "maybe", ""] {
            let _v = EnvVars::set(&[("EXAV_AUTO_UPDATE", bad)]);
            assert!(
                Cli::try_parse_from(["exav"]).is_err(),
                "EXAV_AUTO_UPDATE={bad:?} says neither yes nor no and must be refused"
            );
        }
    }

    /// A detection is a detection wherever the status word sits in the line.
    ///
    /// When a verdict comes from a rejoined multi-volume set the daemon reports
    /// it on each part as `<part>: <sig> FOUND (in <set>)`. A classifier anchored
    /// to the end of the line does not see `FOUND` there, falls through to the
    /// "unrecognised" arm, and prints it as an ordinary line — so the client
    /// shows a detection, counts nothing, and exits 0. A caller reading the exit
    /// code is told the tree is clean while the detection is on its screen.
    #[test]
    fn a_set_annotated_detection_still_counts() {
        let _env = env_guard();
        let cli = Cli::parse_from(["exav"]);
        let mut totals = Totals::default();
        print_daemon_reply(
            "/x/set.zip.001: Exav.Test.EICAR FOUND (in set.zip)",
            &cli,
            &mut totals,
        );
        assert_eq!(
            totals.infected, 1,
            "a FOUND carrying a set annotation must count as infected; \
             otherwise the run exits 0 with the detection printed"
        );

        // The plain form still works, and a clean line is still clean.
        let mut totals = Totals::default();
        print_daemon_reply("/x/a.exe: Sig.Name FOUND", &cli, &mut totals);
        assert_eq!(totals.infected, 1);
        let mut totals = Totals::default();
        print_daemon_reply("/x/a.txt: OK", &cli, &mut totals);
        assert_eq!(
            (totals.infected, totals.errors, totals.limits),
            (0, 0, 0),
            "a clean line stays clean"
        );

        // A partial verdict from a set is a limit, not a hard error. The
        // annotation moves the status off the end of the line, so the category
        // is only where `partial_category` looks for it once it is stripped.
        let mut totals = Totals::default();
        print_daemon_reply(
            "/x/set.7z.001: part 2 is missing LIMITS-EXCEEDED ERROR (in set.7z)",
            &cli,
            &mut totals,
        );
        assert_eq!(
            (totals.limits, totals.errors),
            (1, 0),
            "a set-annotated limit must land in the limits bucket"
        );

        // And an uncategorised ERROR from a set is a real failure, so the two
        // cannot be told apart by the annotation alone.
        let mut totals = Totals::default();
        print_daemon_reply(
            "/x/set.7z.001: cannot open file ERROR (in set.7z)",
            &cli,
            &mut totals,
        );
        assert_eq!((totals.limits, totals.errors), (0, 1));
    }

    /// Regression guard for the no-DB footgun: the built-in baseline must count as
    /// "effectively empty", so daemon/serve modes refuse to serve it by default
    /// (they'd otherwise report real malware as clean). A real DB, having many
    /// more signatures than the baseline, must NOT be flagged.
    #[test]
    fn baseline_is_flagged_effectively_empty() {
        assert!(
            baseline_sig_count() >= 1,
            "baseline should have >=1 sig (EICAR)"
        );
        assert!(
            is_effectively_empty(&Scanner::builtin()),
            "the built-in baseline must be treated as no-real-DB"
        );
    }
}
