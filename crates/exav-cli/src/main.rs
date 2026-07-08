//! exav CLI: a clamscan-compatible front-end.
//!
//! Exit codes and output match clamscan (0 = clean, 1 = found, 2 = error;
//! `PATH: Signature FOUND` / `PATH: OK`). `-` reads stdin, so input can be
//! streamed, e.g. `aws s3 cp s3://… - | exav -`. Unlike clamscan,
//! `--max-filesize`/`--max-scansize` accept values above 2 GB, and a file
//! that can't be fully scanned is reported `LIMITS-EXCEEDED`, not `OK`.

mod daemon;
mod perf;

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use exav_core::{
    db, scan_path, scan_stream, Database, ScanOptions, ScanReport, Verdict, VerdictCategory,
};

/// Status tags the daemon appends (before ` ERROR`) for a verdict that was not
/// fully scanned — as opposed to a hard scan error. The client classifies these
/// as "limits" (not errors) so its summary/exit match a local one-shot scan.
const NOT_SCANNED_TAGS: [&str; 3] = ["LIMITS-EXCEEDED", "UNSCANNABLE", "PASSWORD-PROTECTED"];

/// Default daemon Unix-socket path. Prefer the per-user runtime directory
/// (`$XDG_RUNTIME_DIR`, typically mode-0700 and user-owned) over world-writable
/// `/tmp`, so another local user can't pre-create the path or connect to the
/// daemon and `SCAN` files it can read. Falls back to `/tmp` when unset.
#[cfg(unix)]
fn default_socket_path() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("exav.sock"),
        _ => PathBuf::from("/tmp/exav.sock"),
    }
}
use walkdir::WalkDir;

/// exav: scan files of effectively unlimited size for malware.
#[derive(Parser, Debug)]
#[command(name = "exav", version, about, long_about = None)]
struct Cli {
    /// Files or directories to scan. Use `-` for stdin.
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Scan directories recursively.
    #[arg(short = 'r', long = "recursive")]
    recursive: bool,

    /// Only print infected files.
    #[arg(short = 'i', long = "infected")]
    infected_only: bool,

    /// Sound a bell on virus detection.
    #[arg(long = "bell")]
    bell: bool,

    /// Load signatures from FILE or DIR. Recognizes `.ndb`, `.hdb`/`.hsb`,
    /// `.fdb` (fuzzy), exav `.db`, and `.cvd`/`.cld` containers. If
    /// omitted, --datadir is used if populated, else the built-in baseline.
    #[arg(short = 'd', long = "database", value_name = "PATH")]
    database: Option<PathBuf>,

    /// Directory of signature databases (.ndb/.hdb/.hsb/.cvd/...). Populate
    /// it with `cvdupdate` or `freshclam`; exav only reads it.
    #[arg(long = "datadir", value_name = "DIR", default_value = "exav-db")]
    datadir: PathBuf,

    /// Build a prebuilt cache from the loaded database, write it to FILE, and
    /// exit. The file can then be distributed and loaded directly with `-d`
    /// for a near-instant cold start. Run this on a host with enough RAM
    /// (building the full signature DB needs several GB); the resulting cache
    /// loads cheaply everywhere.
    #[arg(long = "build-cache", value_name = "FILE")]
    build_cache: Option<PathBuf>,

    /// Run as a persistent daemon: load the database once and serve scan
    /// requests over a socket (clamd-compatible protocol), so callers pay no
    /// per-scan startup cost. Defaults to a Unix socket unless --tcp is given.
    #[arg(long = "daemon")]
    daemon: bool,

    /// Container/supervisor entrypoint (the image's default): run the
    /// clamd-compatible daemon on TCP 3310 with a data dir of /var/lib/clamav,
    /// hot-reloading signatures when the volume changes. Drop-in compatible with
    /// the ClamAV Docker image — honours CLAMAV_NO_CLAMD, CLAMAV_NO_FRESHCLAMD,
    /// CLAMD_STARTUP_TIMEOUT and FRESHCLAM_CHECKS, and (built with `--features
    /// http`) fetches from EXAV_DB_MIRROR when that env var is set. Unix only.
    #[arg(long = "serve")]
    serve: bool,

    /// Unix-socket path for the daemon to listen on, or for a client to connect
    /// to. With paths and no --daemon, exav acts as a client of a running
    /// daemon at this socket.
    #[arg(long = "socket", value_name = "PATH")]
    socket: Option<PathBuf>,

    /// TCP `host:port` for the daemon to listen on, or for a client to connect
    /// to (alternative to --socket).
    #[arg(long = "tcp", value_name = "ADDR")]
    tcp: Option<String>,

    /// Refuse the clamd `SHUTDOWN` command (which otherwise stops the daemon).
    /// Use when the socket/port is reachable by untrusted clients. In --serve
    /// mode the env var EXAV_NO_SHUTDOWN_COMMAND=true does the same.
    #[arg(long = "no-shutdown-command")]
    no_shutdown_command: bool,

    /// Daemon worker model (Unix). Default: one prefork worker process per CPU
    /// core, each scanning one job at a time under kernel-enforced per-job limits
    /// (see --max-scan-time/-memory) and recycled per --max-jobs-per-worker, so a
    /// runaway scan is isolated and hard-killed (the thread model can't).
    /// --workers 0 forces the in-process thread model. [default: CPU cores]
    #[arg(long = "workers", value_name = "N")]
    workers: Option<usize>,

    /// Prefork only (requires --workers N): hard wall-clock budget per scan, in
    /// seconds (0 = none). On expiry the worker is killed and the connection
    /// dropped; also caps CPU time (RLIMIT_CPU). The deterministic in-core caps
    /// still apply first in every mode. [default: 120]
    #[arg(long = "max-scan-time", value_name = "SECS")]
    max_scan_time: Option<u64>,

    /// Prefork only (requires --workers N): per-worker address-space cap
    /// (RLIMIT_AS), bounding memory bombs. K/M/G/T suffixes; 0 = none.
    /// [default: 2G]
    #[arg(long = "max-scan-memory", value_name = "SIZE", value_parser = parse_size)]
    max_scan_memory: Option<u64>,

    /// Prefork only (requires --workers N): recycle a worker process after this
    /// many jobs to bound slow leaks/fragmentation (0 = never). Mirrors Apache
    /// MaxRequestsPerChild. [default: 1000]
    #[arg(long = "max-jobs-per-worker", value_name = "N")]
    max_jobs_per_worker: Option<u64>,

    /// Per top-level file cap (ClamAV `--max-filesize`). A larger file is
    /// reported LIMITS-EXCEEDED (never a silent OK, unlike ClamAV). K/M/G/T
    /// suffixes. exav default: no limit. `--clamav-compat` sets 100M.
    #[arg(long = "max-filesize", value_name = "SIZE", value_parser = parse_size)]
    max_filesize: Option<u64>,

    /// Total data-scanned budget within a container (ClamAV `--max-scansize`):
    /// caps deep/structural analysis size and the summed extracted bytes.
    /// K/M/G/T suffixes. exav default: 256M. `--clamav-compat` sets 400M.
    #[arg(long = "max-scansize", value_name = "SIZE", value_parser = parse_size)]
    max_scansize: Option<u64>,

    /// Global peak-buffer limit: the most memory any single materialized object
    /// (a decompressed member/sub-container, an LZ window, a decrypted blob) may
    /// use. This is the knob for tuning the scanner's peak **memory** — every
    /// forced-materialization site obeys it (see MEMORY.md). K/M/G/T suffixes.
    /// exav default: 256M.
    #[arg(long = "max-buffer", value_name = "SIZE", value_parser = parse_size)]
    max_buffer: Option<u64>,

    /// Cumulative scan-reach limit: the most bytes fed to the matcher across one
    /// top-level file (streamed members + re-scanned/carved regions). This is a
    /// **CPU/time** bound, NOT a memory bound — streamed members are scanned
    /// without being held in RAM (that is capped by --max-buffer), so this can be
    /// set far higher to fully scan multi-gigabyte members, paying only in scan
    /// time. Guards re-scanning/decompression-time bombs. K/M/G/T suffixes.
    /// exav default: 10G.
    #[arg(long = "max-scan-total", value_name = "SIZE", value_parser = parse_size)]
    max_scan_total: Option<u64>,

    /// Maximum nesting depth for recursive unpacking (ClamAV `--max-recursion`).
    /// exav default: 16. `--clamav-compat` sets 17.
    #[arg(long = "max-recursion", value_name = "N")]
    max_recursion: Option<u32>,

    /// Maximum number of files extracted from an archive (ClamAV `--max-files`).
    /// exav default: 10000 (same as ClamAV).
    #[arg(long = "max-files", value_name = "N")]
    max_files: Option<u64>,

    /// Restrict archive extraction to stock ClamAV's set: skip `ar`
    /// (Unix archive / `.deb` / `.a`), the only extractor exav has that ClamAV
    /// lacks (cpio/xar/UPX are supported by both). For apples-to-apples
    /// differential testing. Off by default. Also enabled by `--clamav-compat`.
    #[arg(long = "clamav-formats")]
    clamav_formats: bool,

    /// Append `.UNOFFICIAL` (and the `YARA.` prefix) to signatures from
    /// unofficial databases, matching stock clamscan's output. Cosmetic: changes
    /// only the name, never whether a detection fires. Off by default. Also
    /// enabled by `--clamav-compat`.
    #[arg(long = "unofficial-names")]
    unofficial_names: bool,

    /// Enable structural heuristics / fuzzy / ML analysis.
    #[arg(long = "heuristics")]
    heuristics: bool,

    /// DLP heuristic (ClamAV --structured-cc-count): alert
    /// `Heuristics.Structured.CreditCardNumber` when a textual file contains at
    /// least N valid credit-card numbers. Off unless set. (Needs the `dlp` feature.)
    #[arg(long = "structured-cc-count", value_name = "N")]
    structured_cc_count: Option<u32>,

    /// DLP heuristic (ClamAV --structured-ssn-count): alert
    /// `Heuristics.Structured.SSN` when a textual file contains at least N valid
    /// US Social Security numbers. Off unless set. (Needs the `dlp` feature.)
    #[arg(long = "structured-ssn-count", value_name = "N")]
    structured_ssn_count: Option<u32>,

    /// Heuristic alert (ClamAV --alert-encrypted): report an encrypted /
    /// password-protected member as `Heuristics.Encrypted.*` (a detection)
    /// instead of the default `password-protected` status. Off unless set.
    #[arg(long = "alert-encrypted")]
    alert_encrypted: bool,

    /// Heuristic alert (ClamAV --alert-macros): report
    /// `Heuristics.OLE2.ContainsMacros` when an OLE2/OOXML document has VBA
    /// macros. Off unless set.
    #[arg(long = "alert-macros")]
    alert_macros: bool,

    /// Heuristic alert (ClamAV --alert-broken-media): report
    /// `Heuristics.Broken.Media.*` for a structurally invalid image/media file.
    /// Off unless set. (Reserved; no-op until per-format media validation lands.)
    #[arg(long = "alert-broken-media")]
    alert_broken_media: bool,

    /// Heuristic alert (ClamAV --alert-phishing): report
    /// `Heuristics.Phishing.Email.*` when an HTML/text body contains a link whose
    /// visible text spoofs a different domain than its href, hides the real host
    /// behind userinfo, or points at an IP literal under a brand name. Off unless
    /// set.
    #[arg(long = "alert-phishing")]
    alert_phishing: bool,

    /// Password to try when decrypting encrypted archive members (ZIP
    /// ZipCrypto/AES). Repeatable: `--password a --password b` builds a pool,
    /// tried in order. Unioned with any passwords loaded from `.pwdb` databases.
    /// When a scan reports `password-protected`, re-run with the right password.
    #[arg(long = "password", value_name = "PW")]
    password: Vec<String>,

    /// Shortcut that sets exav to a stock ClamAV build's documented defaults for
    /// apples-to-apples differential testing. Equivalent to: `--max-filesize 100M
    /// --max-scansize 400M --max-recursion 17 --max-files 10000 --clamav-formats
    /// --unofficial-names`. Each of those can be set (or overridden) on its own;
    /// an explicit flag wins over the preset. Off by default (full capability).
    #[arg(long = "clamav-compat")]
    clamav_compat: bool,

    /// Detect Potentially Unwanted Applications (ClamAV `--detect-pua`): load the
    /// `.??u` PUA databases and keep `PUA.*` signatures. Off by default, matching
    /// ClamAV. Applied at DB load / cache build time.
    #[arg(long = "detect-pua")]
    detect_pua: bool,

    /// Emit a CSV row per file with a per-matcher timing breakdown (one column
    /// group per matcher: `_us`, `_calls`, `_bytes`) instead of the normal
    /// output — for building a performance matrix across a dataset. A header row
    /// is printed first. Adds light timing overhead.
    #[arg(long = "perf-csv")]
    perf_csv: bool,

    /// Emit one JSON object per scanned input (newline-delimited JSON) instead
    /// of the human `PATH: … FOUND/OK` lines, plus a final JSON summary object
    /// (unless `--no-summary`). Machine-readable output for tooling/pipelines.
    #[arg(long = "json")]
    json: bool,

    /// Print informational findings (type, entropy, imphash, ml score).
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Be quiet (only print errors and detections).
    #[arg(long = "quiet")]
    quiet: bool,

    /// Do not print the summary at the end.
    #[arg(long = "no-summary")]
    no_summary: bool,

    /// Report every matching signature, not just the first (clamscan --allmatch).
    #[arg(long = "allmatch")]
    allmatch: bool,

    /// Skip files whose path matches this regex (repeatable; clamscan --exclude).
    #[arg(long = "exclude", value_name = "REGEX")]
    exclude: Vec<String>,

    /// Skip directories whose path matches this regex (repeatable).
    #[arg(long = "exclude-dir", value_name = "REGEX")]
    exclude_dir: Vec<String>,

    /// Only scan files whose path matches this regex (repeatable; clamscan --include).
    #[arg(long = "include", value_name = "REGEX")]
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

#[derive(Default)]
struct Totals {
    scanned: u64,
    infected: u64,
    errors: u64,
    limits: u64,
    /// Total bytes of the scanned files (for the clamscan-style "Data scanned").
    data_scanned: u64,
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

/// Read a boolean env var the way the ClamAV image does (`true`/`false`), also
/// accepting `1`/`yes`/`on`. Anything else (or unset) is `default`.
#[cfg(unix)]
fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

#[cfg(unix)]
fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

#[cfg(unix)]
fn env_str(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// True if the data dir exists and holds at least one file (matching how
/// `load_db` decides whether to use the dir or the built-in baseline).
#[cfg(unix)]
fn datadir_has_db(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false)
}

/// Block (up to `timeout`) for a sidecar to populate an empty data dir, so the
/// container matches ClamAV's "wait for a database before serving" behaviour.
/// On timeout we start anyway with the built-in baseline and hot-reload later.
#[cfg(unix)]
fn wait_for_db(dir: &Path, timeout: std::time::Duration) {
    if timeout.is_zero() || datadir_has_db(dir) {
        return;
    }
    eprintln!(
        "exav: waiting up to {}s for signatures in {} ...",
        timeout.as_secs(),
        dir.display()
    );
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if datadir_has_db(dir) {
            eprintln!("exav: signatures found");
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    eprintln!(
        "exav: no signatures after {}s; starting with the built-in baseline \
         (hot-reloads when the volume is populated)",
        timeout.as_secs()
    );
}

/// Container/supervisor entrypoint (`--serve`). Env-driven and drop-in
/// compatible with the ClamAV Docker image; Unix only (needs the prefork pool).
#[cfg(unix)]
fn run_serve(cli: &Cli) -> ExitCode {
    use std::time::Duration;

    // Data dir: env override, else ClamAV's conventional /var/lib/clamav.
    let datadir =
        env_str("EXAV_DATADIR").map_or_else(|| PathBuf::from("/var/lib/clamav"), PathBuf::from);
    let no_clamd = env_bool("CLAMAV_NO_CLAMD", false);
    let no_freshclamd = env_bool("CLAMAV_NO_FRESHCLAMD", false);
    let startup_timeout = Duration::from_secs(env_u64("CLAMD_STARTUP_TIMEOUT", 1800));
    let checks_per_day = env_u64("FRESHCLAM_CHECKS", 1).max(1);
    let interval = Duration::from_secs(24 * 3600 / checks_per_day);
    let mirror = env_str("EXAV_DB_MIRROR");
    let tcp_addr = env_str("EXAV_LISTEN").unwrap_or_else(|| "0.0.0.0:3310".to_string());

    if let Err(e) = std::fs::create_dir_all(&datadir) {
        eprintln!(
            "exav: warning: cannot create data dir {}: {e}",
            datadir.display()
        );
    }

    let want_updates = !no_freshclamd && mirror.is_some();
    if want_updates {
        eprintln!(
            "exav: signature auto-update every {}s from the configured mirror",
            interval.as_secs()
        );
    }
    #[cfg(not(feature = "http"))]
    if mirror.is_some() {
        eprintln!(
            "exav: EXAV_DB_MIRROR is set but this build has no updater — rebuild \
             with `--features http`, or update {} from a sidecar. Continuing.",
            datadir.display()
        );
    }

    // Initial fetch so the container comes up with fresh signatures (freshclam's
    // fetch-on-first-start). Best-effort — a failure just leaves the volume as-is.
    #[cfg(feature = "http")]
    if want_updates {
        if let Some(m) = &mirror {
            eprintln!("exav: fetching signatures from {m} ...");
            match exav_update::update_from_mirror(m, &datadir) {
                Ok(true) => eprintln!("exav: signatures updated"),
                Ok(false) => eprintln!("exav: signatures already current"),
                Err(e) => eprintln!("exav: initial signature fetch failed: {e}"),
            }
        }
    }

    // Updater-only container: the "second container that writes the file mount".
    // Refresh on the schedule and let the scanner container hot-reload the volume.
    if no_clamd {
        #[cfg(feature = "http")]
        {
            let Some(m) = mirror else {
                eprintln!("exav: CLAMAV_NO_CLAMD is set but EXAV_DB_MIRROR is not — nothing to do");
                return ExitCode::from(2);
            };
            eprintln!(
                "exav: updater-only mode: refreshing {} every {}s",
                datadir.display(),
                interval.as_secs()
            );
            loop {
                std::thread::sleep(interval);
                match exav_update::update_from_mirror(&m, &datadir) {
                    Ok(true) => eprintln!("exav: signatures updated"),
                    Ok(false) => {}
                    Err(e) => eprintln!("exav: update failed: {e}"),
                }
            }
        }
        #[cfg(not(feature = "http"))]
        {
            eprintln!("exav: CLAMAV_NO_CLAMD needs the updater — build with `--features http`");
            return ExitCode::from(2);
        }
    }

    // Scanner: give a sidecar a chance to populate an empty volume first.
    if !want_updates {
        wait_for_db(&datadir, startup_timeout);
    }

    // Reload signatures from the volume, or fall back to the built-in baseline
    // until real databases appear (the supervisor re-forks on every reload).
    let load = || -> Result<Database, String> {
        if datadir_has_db(&datadir) {
            db::load_with_options(
                &datadir,
                cli.detect_pua,
                cli.unofficial_names || cli.clamav_compat,
            )
            .map_err(|e| e.to_string())
        } else {
            eprintln!(
                "exav: no databases in {} yet — serving with the built-in baseline",
                datadir.display()
            );
            Ok(Database::builtin())
        }
    };
    let db = match load() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("exav: {e}");
            return ExitCode::from(2);
        }
    };

    // Background updater thread: fetch on the schedule, then trigger a reload.
    #[cfg(feature = "http")]
    if want_updates {
        if let Some(m) = mirror.clone() {
            let dir = datadir.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(interval);
                match exav_update::update_from_mirror(&m, &dir) {
                    Ok(true) => {
                        eprintln!("exav: signatures updated");
                        daemon::request_reload();
                    }
                    Ok(false) => {}
                    Err(e) => eprintln!("exav: update failed: {e}"),
                }
            });
        }
    }

    let opts = build_scan_options(cli);

    // Serve requires the prefork supervisor (workers >= 1); it owns the reload.
    let workers = cli.workers.unwrap_or_else(default_workers).max(1);
    let scan_time = cli.max_scan_time.unwrap_or(120);
    // SHUTDOWN is honoured unless disabled by flag or the serve-mode env var.
    let allow_shutdown = !cli.no_shutdown_command && !env_bool("EXAV_NO_SHUTDOWN_COMMAND", false);
    let poolcfg = daemon::PoolConfig {
        workers,
        max_scan_time: Duration::from_secs(scan_time),
        max_memory_bytes: cli.max_scan_memory.unwrap_or(2 * 1024 * 1024 * 1024),
        max_cpu_secs: scan_time,
        max_jobs: cli.max_jobs_per_worker.unwrap_or(1000),
        allow_shutdown,
    };
    eprintln!(
        "exav: serving clamd protocol on tcp:{tcp_addr} (data dir {})",
        datadir.display()
    );
    match daemon::run_prefork(
        db,
        daemon::ListenAddr::Tcp(tcp_addr),
        opts,
        poolcfg,
        Some(datadir.clone()),
        &load,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("exav: daemon error: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(not(unix))]
fn run_serve(_cli: &Cli) -> ExitCode {
    eprintln!("exav: --serve (container mode) is only supported on Unix");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Container/supervisor entrypoint. Env-driven, ClamAV-Docker-compatible.
    if cli.serve {
        return run_serve(&cli);
    }

    // Client mode: a socket/tcp target with paths and no --daemon delegates the
    // scan to a running daemon (no DB load here).
    if !cli.daemon && (cli.socket.is_some() || cli.tcp.is_some()) && !cli.paths.is_empty() {
        return run_client(&cli);
    }

    if !cli.daemon && cli.build_cache.is_none() && cli.paths.is_empty() {
        eprintln!("exav: no input; provide PATH(s) or `-` (stdin)");
        return ExitCode::from(2);
    }

    // The per-job limits are enforced by the kernel inside worker processes, so
    // they only exist with a prefork pool. Reject them with workers=0 rather
    // than silently ignoring them.
    // The prefork pool (and its per-job limits) only exists for the daemon, with
    // workers > 0. Default to the CPU-core count on Unix; --workers 0 forces the
    // in-process thread model. One-shot scans never use the pool.
    let pool_workers = if cli.daemon {
        cli.workers.unwrap_or_else(default_workers)
    } else {
        0
    };
    if pool_workers == 0 {
        let offender = [
            cli.max_scan_time.map(|_| "--max-scan-time"),
            cli.max_scan_memory.map(|_| "--max-scan-memory"),
            cli.max_jobs_per_worker.map(|_| "--max-jobs-per-worker"),
        ]
        .into_iter()
        .flatten()
        .next();
        if let Some(flag) = offender {
            eprintln!(
                "exav: {flag} only applies to the daemon worker pool (needs --daemon and --workers > 0)"
            );
            return ExitCode::from(2);
        }
    }

    let db = match load_db(&cli) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("exav: {e}");
            return ExitCode::from(2);
        }
    };

    if cli.daemon {
        let opts = build_scan_options(&cli);
        let addr = match &cli.tcp {
            Some(a) => daemon::ListenAddr::Tcp(a.clone()),
            #[cfg(unix)]
            None => {
                daemon::ListenAddr::Unix(cli.socket.clone().unwrap_or_else(default_socket_path))
            }
            #[cfg(not(unix))]
            None => {
                eprintln!("exav: --tcp is required for the daemon on this platform");
                return ExitCode::from(2);
            }
        };
        // A prefork worker pool (--workers N > 0) is the isolated/killable model;
        // it's Unix-only (relies on fork for COW DB-sharing + kernel limits).
        #[cfg(unix)]
        if pool_workers > 0 {
            // Defaults live here (not in clap) so an unset flag is distinguishable
            // from an explicit one for the workers=0 validation above.
            let scan_time = cli.max_scan_time.unwrap_or(120);
            let cfg = daemon::PoolConfig {
                workers: pool_workers,
                max_scan_time: std::time::Duration::from_secs(scan_time),
                max_memory_bytes: cli.max_scan_memory.unwrap_or(2 * 1024 * 1024 * 1024),
                // Bound CPU time too (catches a busy loop that an I/O-wait-free
                // wall clock would also catch, but as a kernel-level backstop).
                max_cpu_secs: scan_time,
                max_jobs: cli.max_jobs_per_worker.unwrap_or(1000),
                allow_shutdown: !cli.no_shutdown_command,
            };
            // On RELOAD / a data-dir change, re-read signatures the same way the
            // initial load did. Watch the directory the DB came from so a sidecar
            // rewriting it triggers a reload without an explicit RELOAD.
            let reload = || load_db(&cli);
            let watch = reload_watch_dir(&cli);
            return match daemon::run_prefork(db, addr, opts, cfg, watch, &reload) {
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
        return match daemon::run(db, addr, opts, !cli.no_shutdown_command) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("exav: daemon error: {e}");
                ExitCode::from(2)
            }
        };
    }

    if let Some(out) = &cli.build_cache {
        return match exav_core::cache::save(&db, out) {
            Ok(()) => {
                if !cli.quiet {
                    println!(
                        "exav: wrote cache for {} signatures to {}",
                        db.signature_count(),
                        out.display()
                    );
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("exav: writing cache to {}: {e}", out.display());
                ExitCode::from(2)
            }
        };
    }

    let opts = build_scan_options(&cli);

    let filters = match Filters::compile(&cli) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("exav: invalid filter regex: {e}");
            return ExitCode::from(2);
        }
    };

    let mut totals = Totals::default();
    let scan_start = std::time::Instant::now();
    if cli.perf_csv {
        println!("{}", perf::header());
    }
    for path in &cli.paths {
        match path.to_str() {
            Some("-") => scan_stdin(&db, &cli, &mut totals),
            #[cfg(feature = "http")]
            Some(s) if s.starts_with("http://") || s.starts_with("https://") => {
                scan_url(s, &db, &opts, &cli, &mut totals)
            }
            #[cfg(not(feature = "http"))]
            Some(s) if s.starts_with("http://") || s.starts_with("https://") => {
                totals.errors += 1;
                eprintln!("{s}: URL scanning needs a build with `--features http` ERROR");
            }
            _ => scan_target(path, &db, &opts, &cli, &filters, &mut totals),
        }
    }

    if !cli.no_summary && !cli.quiet && !cli.perf_csv {
        if cli.json {
            emit_json_summary(&totals, scan_start.elapsed());
        } else {
            print_summary(&db, &totals, scan_start.elapsed(), cli.verbose);
        }
    }

    if totals.infected > 0 {
        ExitCode::from(1)
    } else if totals.errors > 0 || totals.limits > 0 {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// The directory the daemon should watch for on-disk signature changes (a
/// sidecar/freshclam rewriting the volume), mirroring how `load_db` picks its
/// source. `None` for a single-file `--database` or the built-in baseline, where
/// there's no directory to poll (an explicit `RELOAD` still reloads).
fn reload_watch_dir(cli: &Cli) -> Option<PathBuf> {
    if let Some(p) = &cli.database {
        return p.is_dir().then(|| p.clone());
    }
    cli.datadir.is_dir().then(|| cli.datadir.clone())
}

/// Build the scan options from the CLI. `--clamav-compat` is a *preset*: it
/// supplies ClamAV's documented defaults for the individual limit/capability
/// flags, but any explicit flag overrides the preset (an unset flag falls back
/// to the preset value under `--clamav-compat`, else to exav's own default). See
/// the README "ClamAV compatibility" table for the full mapping.
#[allow(clippy::field_reassign_with_default)] // conditional per-field overrides read cleaner than a struct literal
fn build_scan_options(cli: &Cli) -> ScanOptions {
    const MIB: u64 = 1024 * 1024;
    let compat = cli.clamav_compat;
    let mut opts = ScanOptions::default();

    // --max-filesize: per top-level file cap. exav default unlimited; compat 100M.
    opts.max_scan_size = cli.max_filesize.or_else(|| compat.then_some(100 * MIB));

    // --max-scansize: total data-scanned budget (deep-analysis size + summed
    // extracted bytes). exav default 256M; compat 400M.
    if let Some(s) = cli.max_scansize.or_else(|| compat.then_some(400 * MIB)) {
        opts.deep_analysis_max = s;
        opts.limits.max_total_bytes = s;
    }
    // --max-buffer: the global peak-buffer limit. Sets the unpack per-object cap
    // (max_entry_bytes, which backs Limits::max_buffer_bytes) and the core-side
    // structural buffer (deep_analysis_max) together, so one knob governs the
    // largest single allocation on every materialization path.
    if let Some(b) = cli.max_buffer {
        opts.limits.max_entry_bytes = b;
        opts.deep_analysis_max = b;
    }
    // --max-scan-total: the cumulative scan-reach (CPU/time) limit. Decoupled
    // from memory — a streamed member is bounded by this, not by --max-buffer, so
    // raising it scans larger members (in RAM bounded by --max-buffer) at the
    // cost of scan time only.
    if let Some(s) = cli.max_scan_total {
        opts.limits.max_scan_bytes = s;
    }
    // --max-recursion: nesting depth. exav default 16; compat 17.
    if let Some(r) = cli.max_recursion.or_else(|| compat.then_some(17)) {
        opts.limits.max_recursion = r;
    }
    // --max-files: files per archive. exav default 10000 (== ClamAV); exposed for
    // parity and overriding.
    if let Some(f) = cli.max_files.or_else(|| compat.then_some(10_000)) {
        opts.limits.max_files = f;
    }

    // Capability + naming: on when set individually or via the compat preset.
    opts.restrict_extractors = cli.clamav_formats || compat;
    opts.unofficial_suffix = cli.unofficial_names || compat;

    opts.heuristics = cli.heuristics;
    opts.passwords = cli.password.clone();
    opts.structured_cc_count = cli.structured_cc_count;
    opts.structured_ssn_count = cli.structured_ssn_count;
    opts.alert_encrypted = cli.alert_encrypted;
    opts.alert_macros = cli.alert_macros;
    opts.alert_broken_media = cli.alert_broken_media;
    opts.alert_phishing = cli.alert_phishing;
    opts
}

fn load_db(cli: &Cli) -> Result<Database, String> {
    // `--unofficial-names` (or the `--clamav-compat` preset) selects exact ClamAV
    // naming (the `.UNOFFICIAL` suffix / `YARA.` prefix on unofficial-database
    // signatures). The suffix is actually applied at report time from
    // `ScanOptions::unofficial_suffix`; this load-time flag is retained for
    // provenance/API compatibility.
    let suffix = cli.unofficial_names || cli.clamav_compat;
    if let Some(path) = &cli.database {
        return db::load_with_options(path, cli.detect_pua, suffix).map_err(|e| e.to_string());
    }
    if cli.datadir.is_dir() {
        // Use the data dir if it actually contains something loadable.
        if std::fs::read_dir(&cli.datadir)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
        {
            return db::load_with_options(&cli.datadir, cli.detect_pua, suffix)
                .map_err(|e| e.to_string());
        }
    }
    Ok(Database::builtin())
}

fn scan_target(
    path: &Path,
    db: &Database,
    opts: &ScanOptions,
    cli: &Cli,
    filters: &Filters,
    totals: &mut Totals,
) {
    if path.is_dir() {
        if cli.recursive {
            for entry in WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                // Prune excluded directories before descending into them.
                .filter_entry(|e| !(e.file_type().is_dir() && filters.dir_excluded(e.path())))
                .filter_map(Result::ok)
            {
                if entry.file_type().is_file() && !filters.file_skipped(entry.path()) {
                    scan_one(entry.path(), db, opts, cli, totals);
                }
            }
        } else if !cli.quiet {
            eprintln!(
                "{}: Can't scan directory (use -r to recurse)",
                path.display()
            );
        }
    } else if !filters.file_skipped(path) {
        scan_one(path, db, opts, cli, totals);
    }
}

fn scan_one(path: &Path, db: &Database, opts: &ScanOptions, cli: &Cli, totals: &mut Totals) {
    if cli.allmatch {
        return scan_one_allmatch(path, db, opts, cli, totals);
    }
    totals.scanned += 1;
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    totals.data_scanned += size;
    // Isolate each file: a parser panic on a crafted input must not abort
    // the whole run, and must count as an error — never a clean result.
    let t0 = std::time::Instant::now();
    if cli.perf_csv {
        exav_core::profile::enable();
    }
    let scanned =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan_path(db, path, opts)));
    if cli.perf_csv {
        let prof = exav_core::profile::take();
        let (verdict, sig) = match &scanned {
            Ok(Ok(r)) => match &r.verdict {
                Verdict::Clean => ("clean", String::new()),
                Verdict::Infected { signature, .. } => {
                    totals.infected += 1;
                    ("infected", signature.clone())
                }
                Verdict::LimitsExceeded { reason } => ("limits", reason.clone()),
                Verdict::Unscannable { reason } => ("unscannable", reason.clone()),
                Verdict::PasswordProtected { reason } => ("password-protected", reason.clone()),
            },
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
        Ok(Err(e)) => {
            totals.errors += 1;
            if !cli.quiet {
                eprintln!("{}: {e} ERROR", path.display());
            }
        }
        Err(_) => {
            totals.errors += 1;
            eprintln!("{}: internal error while scanning ERROR", path.display());
        }
    }
}

fn scan_stdin(db: &Database, cli: &Cli, totals: &mut Totals) {
    totals.scanned += 1;
    let stdin = io::stdin();
    let scanned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scan_stream(db, stdin.lock())
    }));
    match scanned {
        Ok(Ok(report)) => report_result("stdin", report, cli, totals),
        Ok(Err(e)) => {
            totals.errors += 1;
            if !cli.quiet {
                eprintln!("stdin: {e} ERROR");
            }
        }
        Err(_) => {
            totals.errors += 1;
            eprintln!("stdin: internal error while scanning ERROR");
        }
    }
}

/// Scan an http(s):// URL via range requests, fetching only the bytes the
/// scan touches (e.g. a ZIP's directory + the members it reads).
#[cfg(feature = "http")]
fn scan_url(url: &str, db: &Database, opts: &ScanOptions, cli: &Cli, totals: &mut Totals) {
    totals.scanned += 1;
    let reader = match exav_core::source::HttpRangeReader::open(url) {
        Ok(r) => r,
        Err(e) => {
            totals.errors += 1;
            eprintln!("{url}: {e} ERROR");
            return;
        }
    };
    let size = reader.len();
    let scanned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exav_core::scan_seekable(db, reader, size, opts)
    }));
    match scanned {
        Ok(Ok(report)) => report_result(url, report, cli, totals),
        Ok(Err(e)) => {
            totals.errors += 1;
            eprintln!("{url}: {e} ERROR");
        }
        Err(_) => {
            totals.errors += 1;
            eprintln!("{url}: internal error while scanning ERROR");
        }
    }
}

/// Client mode: connect to a running daemon and scan the given paths via the
/// clamd-compatible protocol (one `SCAN <abspath>` per file, reusing the
/// connection). The daemon already holds the DB, so this pays no load cost.
fn run_client(cli: &Cli) -> ExitCode {
    use std::io::{BufRead, BufReader, Write};

    let mut conn: Box<dyn ReadWrite> = match (&cli.socket, &cli.tcp) {
        (_, Some(addr)) => match std::net::TcpStream::connect(addr) {
            Ok(s) => Box::new(s),
            Err(e) => {
                eprintln!("exav: connect tcp:{addr}: {e}");
                return ExitCode::from(2);
            }
        },
        #[cfg(unix)]
        (Some(path), None) => match std::os::unix::net::UnixStream::connect(path) {
            Ok(s) => Box::new(s),
            Err(e) => {
                eprintln!("exav: connect unix:{}: {e}", path.display());
                return ExitCode::from(2);
            }
        },
        _ => {
            eprintln!("exav: --socket or --tcp required for client mode");
            return ExitCode::from(2);
        }
    };

    // Expand the requested paths into individual files (the client walks dirs so
    // replies stay one-per-command and order is predictable).
    let mut files = Vec::new();
    for p in &cli.paths {
        if p.is_dir() && cli.recursive {
            for e in WalkDir::new(p).follow_links(false).into_iter().flatten() {
                if e.file_type().is_file() {
                    files.push(e.path().to_path_buf());
                }
            }
        } else {
            files.push(p.clone());
        }
    }

    let mut totals = Totals::default();
    let mut reader = BufReader::new(conn.try_clone_box());
    // Batch all scans on one connection via IDSESSION (the daemon otherwise
    // closes after a single command).
    if conn.write_all(b"zIDSESSION\0").is_err() {
        eprintln!("exav: daemon connection lost");
        return ExitCode::from(2);
    }
    for f in &files {
        let abs = std::fs::canonicalize(f).unwrap_or_else(|_| f.clone());
        let cmd = format!("zSCAN {}\0", abs.display());
        if conn
            .write_all(cmd.as_bytes())
            .and_then(|_| conn.flush())
            .is_err()
        {
            eprintln!("exav: daemon connection lost");
            return ExitCode::from(2);
        }
        let mut buf = Vec::new();
        if reader.read_until(0, &mut buf).unwrap_or(0) == 0 {
            eprintln!("exav: daemon closed the connection");
            return ExitCode::from(2);
        }
        if buf.last() == Some(&0) {
            buf.pop();
        }
        // Strip the IDSESSION "<id>: " reply prefix.
        let raw = String::from_utf8_lossy(&buf);
        let line = raw.split_once(": ").map(|x| x.1).unwrap_or(&raw);
        totals.scanned += 1;
        print_daemon_reply(line, cli, &mut totals);
    }
    let _ = conn.write_all(b"zEND\0");

    if !cli.no_summary && !cli.quiet {
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
    // Same precedence as a local scan: a detection is exit 1; anything not fully
    // scanned (limits) or a hard error is exit 2.
    if totals.infected > 0 {
        ExitCode::from(1)
    } else if totals.errors > 0 || totals.limits > 0 {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// Print a `<path>: <status>` daemon reply line in clamscan style.
fn print_daemon_reply(line: &str, cli: &Cli, totals: &mut Totals) {
    let line = line.trim_end();
    if line.ends_with("FOUND") {
        totals.infected += 1;
        println!("{line}");
        if cli.bell {
            print!("\x07");
        }
    } else if line.ends_with("ERROR") {
        // The daemon renders a not-scanned verdict as `<TAG> (<reason>) ERROR`.
        // Count those as "limits" (never clean, but not a hard error) and print
        // them like a one-shot scan does, so the two paths agree; only a genuine
        // scan error falls through to the error counter and stderr.
        if NOT_SCANNED_TAGS.iter().any(|t| line.contains(t)) {
            totals.limits += 1;
            println!("{line}");
        } else {
            totals.errors += 1;
            eprintln!("{line}");
        }
    } else if !cli.infected_only && !cli.quiet {
        println!("{line}");
    }
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

/// `--allmatch` scan of one file: report every matching signature. Works on a
/// buffered copy (bounded by deep-analysis-max); a larger file falls back to a
/// normal single-match scan so it is never silently skipped.
fn scan_one_allmatch(
    path: &Path,
    db: &Database,
    opts: &ScanOptions,
    cli: &Cli,
    totals: &mut Totals,
) {
    use std::io::Read;
    totals.scanned += 1;
    let name = path.display().to_string();
    let cap = opts.deep_analysis_max;
    let mut data = Vec::new();
    let read = std::fs::File::open(path).and_then(|f| {
        f.take(cap.saturating_add(1))
            .read_to_end(&mut data)
            .map(|_| ())
    });
    if let Err(e) = read {
        totals.errors += 1;
        if !cli.quiet {
            eprintln!("{name}: {e} ERROR");
        }
        return;
    }
    if data.len() as u64 > cap {
        // Too big to buffer for all-match; fall back to a single-match scan.
        let scanned =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan_path(db, path, opts)));
        match scanned {
            Ok(Ok(report)) => report_result(&name, report, cli, totals),
            _ => {
                totals.errors += 1;
                eprintln!("{name}: internal error while scanning ERROR");
            }
        }
        return;
    }
    let found = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exav_core::analyze_all(db, &data, opts)
    }));
    match found {
        Ok(dets) if !dets.is_empty() => {
            totals.infected += 1;
            if cli.json {
                let sigs: Vec<serde_json::Value> = dets
                    .iter()
                    .map(|(sig, method)| {
                        serde_json::json!({"signature": sig, "method": method.as_str()})
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::json!({
                        "file": name, "category": "infected", "status": "FOUND",
                        "signatures": sigs
                    })
                );
            } else {
                for (sig, method) in dets {
                    println!("{name}: {sig} FOUND");
                    if cli.verbose {
                        println!("  [method] {}", method.as_str());
                    }
                }
                if cli.bell {
                    print!("\x07");
                }
            }
        }
        Ok(_) => {
            if cli.infected_only {
            } else if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"file": name, "category": "clean", "status": "OK"})
                );
            } else if !cli.quiet {
                println!("{name}: OK");
            }
        }
        Err(_) => {
            totals.errors += 1;
            eprintln!("{name}: internal error while scanning ERROR");
        }
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
                "not_scanned": totals.limits,
                "errors": totals.errors,
                "data_scanned_bytes": totals.data_scanned,
                "elapsed_secs": elapsed.as_secs_f64(),
            }
        })
    );
}

fn report_result(name: &str, report: ScanReport, cli: &Cli, totals: &mut Totals) {
    // Classification, status tag and detail all come from exav-core so this
    // human output and the daemon's wire output can't disagree (see
    // `Verdict::category`/`status_tag`/`detail`).
    let v = &report.verdict;
    // Update counters first (identical in every output mode), then render.
    match v.category() {
        VerdictCategory::Infected => totals.infected += 1,
        VerdictCategory::NotScanned => totals.limits += 1,
        VerdictCategory::Clean => {}
    }
    if cli.json {
        emit_json_result(name, &report, cli);
        return;
    }
    match v.category() {
        VerdictCategory::Infected => {
            println!("{name}: {} FOUND", v.detail().unwrap_or_default());
            if cli.verbose {
                if let Verdict::Infected { method, .. } = v {
                    println!("  [method] {}", method.as_str());
                }
            }
            if cli.bell {
                print!("\x07");
            }
        }
        // Limit hit / undecodable / encrypted — all "not clean, not fully
        // scanned". Counted together (never a silent pass); the tag distinguishes
        // them. Encrypted is actionable: re-scan with --password.
        VerdictCategory::NotScanned => {
            println!(
                "{name}: {} {}",
                v.detail().unwrap_or_default(),
                v.status_tag()
            );
        }
        VerdictCategory::Clean => {
            if !cli.infected_only && !cli.quiet {
                println!("{name}: OK");
            }
        }
    }
    if cli.verbose {
        for f in &report.findings {
            println!("  [{}] {}", f.label, f.detail);
        }
    }
}

/// Coarse `category()` as a stable machine string for `--json`.
fn category_str(c: VerdictCategory) -> &'static str {
    match c {
        VerdictCategory::Clean => "clean",
        VerdictCategory::Infected => "infected",
        VerdictCategory::NotScanned => "not-scanned",
    }
}

/// Emit one newline-delimited JSON object for a scan result. `--infected-only`
/// suppresses clean results (matching the human output). Findings are always
/// included so the machine consumer never needs `-v`.
fn emit_json_result(name: &str, report: &ScanReport, cli: &Cli) {
    let v = &report.verdict;
    let cat = v.category();
    if cat == VerdictCategory::Clean && cli.infected_only {
        return;
    }
    let mut obj = serde_json::Map::new();
    obj.insert("file".into(), name.into());
    obj.insert("category".into(), category_str(cat).into());
    obj.insert("status".into(), v.status_tag().into());
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
const CLAMAV_COMPAT_VERSION: &str = "1.4.3";

/// Print a clamscan-compatible `SCAN SUMMARY` (same field names and order, so
/// existing clamscan-output parsers work). exav-specific counters are shown only
/// with `-v`/`--verbose`.
fn print_summary(db: &Database, totals: &Totals, elapsed: std::time::Duration, verbose: bool) {
    let mb = totals.data_scanned as f64 / (1024.0 * 1024.0);
    let secs = elapsed.as_secs_f64();
    let (m, s) = (elapsed.as_secs() / 60, elapsed.as_secs() % 60);
    println!("\n----------- SCAN SUMMARY -----------");
    println!("Known viruses: {}", db.signature_count());
    println!("Engine version: {CLAMAV_COMPAT_VERSION}");
    println!("Scanned directories: 0");
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
