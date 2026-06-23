//! exav CLI: a clamscan-compatible front-end.
//!
//! Exit codes and output match clamscan (0 = clean, 1 = found, 2 = error;
//! `PATH: Signature FOUND` / `PATH: OK`). `-` reads stdin, so input can be
//! streamed, e.g. `aws s3 cp s3://… - | exav -`. Unlike clamscan,
//! `--max-filesize`/`--max-scansize` accept values above 2 GB, and a file
//! that can't be fully scanned is reported `LIMITS-EXCEEDED`, not `OK`.

mod daemon;

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use exav_core::{db, scan_path, scan_stream, Database, ScanOptions, ScanReport, Verdict};
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

    /// Unix-socket path for the daemon to listen on, or for a client to connect
    /// to. With paths and no --daemon, exav acts as a client of a running
    /// daemon at this socket.
    #[arg(long = "socket", value_name = "PATH")]
    socket: Option<PathBuf>,

    /// TCP `host:port` for the daemon to listen on, or for a client to connect
    /// to (alternative to --socket).
    #[arg(long = "tcp", value_name = "ADDR")]
    tcp: Option<String>,

    /// Files larger than this are reported LIMITS-EXCEEDED (never OK).
    /// Accepts K/M/G/T suffixes. Default: no limit.
    #[arg(long = "max-filesize", value_name = "SIZE", value_parser = parse_size)]
    max_filesize: Option<u64>,

    /// Alias of --max-filesize for clamscan compatibility.
    #[arg(long = "max-scansize", value_name = "SIZE", value_parser = parse_size)]
    max_scansize: Option<u64>,

    /// Enable structural heuristics / fuzzy / ML analysis.
    #[arg(long = "heuristics")]
    heuristics: bool,

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
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Client mode: a socket/tcp target with paths and no --daemon delegates the
    // scan to a running daemon (no DB load here).
    if !cli.daemon && (cli.socket.is_some() || cli.tcp.is_some()) && !cli.paths.is_empty() {
        return run_client(&cli);
    }

    if !cli.daemon && cli.build_cache.is_none() && cli.paths.is_empty() {
        eprintln!("exav: no input; provide PATH(s) or `-` (stdin)");
        return ExitCode::from(2);
    }

    let db = match load_db(&cli) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("exav: {e}");
            return ExitCode::from(2);
        }
    };

    if cli.daemon {
        let max = match (cli.max_filesize, cli.max_scansize) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let opts = ScanOptions {
            max_scan_size: max,
            heuristics: cli.heuristics,
            ..Default::default()
        };
        let addr = match &cli.tcp {
            Some(a) => daemon::ListenAddr::Tcp(a.clone()),
            #[cfg(unix)]
            None => daemon::ListenAddr::Unix(
                cli.socket
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("/tmp/exav.sock")),
            ),
            #[cfg(not(unix))]
            None => {
                eprintln!("exav: --tcp is required for the daemon on this platform");
                return ExitCode::from(2);
            }
        };
        return match daemon::run(db, addr, opts) {
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

    let max = match (cli.max_filesize, cli.max_scansize) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    let opts = ScanOptions {
        max_scan_size: max,
        heuristics: cli.heuristics,
        ..Default::default()
    };

    let filters = match Filters::compile(&cli) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("exav: invalid filter regex: {e}");
            return ExitCode::from(2);
        }
    };

    let mut totals = Totals::default();
    for path in &cli.paths {
        match path.to_str() {
            Some("-") => scan_stdin(&db, &cli, &mut totals),
            Some(s) if s.starts_with("http://") || s.starts_with("https://") => {
                scan_url(s, &db, &opts, &cli, &mut totals)
            }
            _ => scan_target(path, &db, &opts, &cli, &filters, &mut totals),
        }
    }

    if !cli.no_summary && !cli.quiet {
        print_summary(&db, &totals);
    }

    if totals.infected > 0 {
        ExitCode::from(1)
    } else if totals.errors > 0 || totals.limits > 0 {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn load_db(cli: &Cli) -> Result<Database, String> {
    if let Some(path) = &cli.database {
        return db::load(path);
    }
    if cli.datadir.is_dir() {
        // Use the data dir if it actually contains something loadable.
        if std::fs::read_dir(&cli.datadir)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
        {
            return db::load(&cli.datadir);
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
    // Isolate each file: a parser panic on a crafted input must not abort
    // the whole run, and must count as an error — never a clean result.
    let scanned =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan_path(db, path, opts)));
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
        if totals.errors > 0 {
            println!("Errors: {}", totals.errors);
        }
    }
    if totals.infected > 0 {
        ExitCode::from(1)
    } else if totals.errors > 0 {
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
        totals.errors += 1;
        eprintln!("{line}");
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
        Ok(_) => {
            if !cli.infected_only && !cli.quiet {
                println!("{name}: OK");
            }
        }
        Err(_) => {
            totals.errors += 1;
            eprintln!("{name}: internal error while scanning ERROR");
        }
    }
}

fn report_result(name: &str, report: ScanReport, cli: &Cli, totals: &mut Totals) {
    match report.verdict {
        Verdict::Infected {
            signature, method, ..
        } => {
            totals.infected += 1;
            println!("{name}: {signature} FOUND");
            if cli.verbose {
                println!("  [method] {}", method.as_str());
            }
            if cli.bell {
                print!("\x07");
            }
        }
        Verdict::LimitsExceeded { reason } => {
            totals.limits += 1;
            println!("{name}: {reason} LIMITS-EXCEEDED");
        }
        Verdict::Clean => {
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

fn print_summary(db: &Database, totals: &Totals) {
    println!("\n----------- SCAN SUMMARY -----------");
    println!("Known signatures: {}", db.signature_count());
    if db.unsupported_count() > 0 {
        println!("Unsupported sigs skipped: {}", db.unsupported_count());
    }
    if db.bytecode_count() > 0 {
        println!("Bytecode programs loaded: {}", db.bytecode_count());
    }
    println!("Scanned files: {}", totals.scanned);
    println!("Infected files: {}", totals.infected);
    if totals.limits > 0 {
        println!("Limits exceeded (unscanned, not clean): {}", totals.limits);
    }
    if totals.errors > 0 {
        println!("Errors: {}", totals.errors);
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
