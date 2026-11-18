//! `exav-unpack`: extract, list and test archives, with `unzip`'s command line.
//!
//! The command line is a subset of Info-ZIP `unzip` 6.00's: every option it
//! takes means what it means to `unzip`, and an `unzip` option it does not take
//! is refused (exit 10) rather than ignored. It adds `-r` (`unzip` has no
//! option of that name), which also opens the archives found inside the
//! archive, and long options (`--volume`, the `--max-*` limits, the
//! `--object-cache-*` sizes, `--help`, `--version`). It reads every archive
//! format the `exav-unpack` library reads, not only ZIP.
//!
//! Where it differs from `unzip` on purpose:
//! - no password prompt (not implemented yet): an encrypted member with no
//!   `-P` is skipped, as `unzip` does with no terminal, after the library's
//!   built-in passwords;
//! - a symbolic link whose target leaves the extraction directory is not made;
//! - every member is `extracting:`, whatever its compression;
//! - a split archive is read from any of its parts.
//!
//! An archive longer than the object cache or `--max-object-bytes` is read from
//! disk as it is needed (a shorter one is read whole), and each member is
//! written as it is decoded: neither is held in memory whole, except where a
//! format's decoder needs it, or, with `-r`, a member that is an archive and is
//! opened.

#![forbid(unsafe_code)]

/// `println!`, except that a closed standard output ends the run quietly.
///
/// Rust's runtime ignores `SIGPIPE`, so `exav-unpack -l archive | head` made
/// `println!` panic on the `EPIPE` and print a backtrace at the user. Every
/// other Unix filter just stops.
macro_rules! println {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        if let Err(e) = writeln!(std::io::stdout(), $($arg)*) {
            stdout_closed(&e);
        }
    }};
}

/// The end of a run whose standard output cannot be written to: 141, what a
/// shell reports for a process killed by `SIGPIPE`, when the reader went away,
/// and 2 for any other write error.
fn stdout_closed(e: &std::io::Error) -> ! {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        std::process::exit(141);
    }
    eprintln!("exav-unpack:  cannot write to standard output: {e}");
    std::process::exit(2);
}

use chrono::{Local, LocalResult, TimeZone};
use exav_unpack::source::{BlockCache, open_source};
#[cfg(not(target_family = "wasm"))]
use exav_unpack::spill::DirSpill;
use exav_unpack::spill::Spill;
use exav_unpack::tree::{
    Content, Cx, End, Ended, Flow, Hold, Large, Name, Node, Origin, Path as Located, Reason,
    ReasonKind, Reasons, Root, Typed, Typing, Visitor, Walk, Walker, shown_text, type_object,
};
use exav_unpack::volume::{ByteSpan, Parts, SetKind, SetPlan, join, plan};
use exav_unpack::{Budget, ByteSource, Limits, Member, MemberMeta, Mtime, walk};
use std::borrow::Cow;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

const USAGE: &str = "\
usage: exav-unpack [-opts[modifiers]] archive [list] [-x xlist] [-d exdir]

Extracts the members in list (all by default), except those in xlist, into
exdir (the current directory by default). The options are a subset of
unzip's and mean what they mean to unzip; archive may be a wildcard, and of
any format exav-unpack reads.

  -l  list members                           -t  test members
  -p  extract members to stdout, no messages -c  as -p, with messages
  -Z1 list member names only                 -x  exclude the members that follow
  -d  extract into exdir
modifiers:
  -o  overwrite files without prompting      -n  never overwrite files
  -q  quiet (-qq quieter)                    -P  password to decrypt members
  -j  junk paths (no directories)            -C  match names case-insensitively
  -D  do not restore directory times (-DD: no times at all)

exav-unpack only:
  -r, --recursive    also open the archives found inside the archive: a member
                     that is one is replaced by its own members, named
                     archive!member in listings and nested as directories
  --volume FILE      another part of a split archive (repeat for each part)
  --max-extracted-bytes SIZE|off
                     stop past SIZE decoded bytes in all (default 64G);
                     --max-size is the older name
  --max-object-bytes SIZE|off
                     largest member or container held in memory whole (1G);
                     --max-memory is the older name. With -r, a member that is
                     decoded as it is read is held whole, whatever this is,
                     when it ends or fails within 4 MiB + 1 KiB: the start
                     that is read to tell what it is
  --max-members N|off
                     stop past N members (default 1000000)
  --max-compression-ratio N|off
                     leave out a member that decodes to more than N times its
                     size, once it is past --max-object-bytes (default 1000);
                     the other members are still read, and the run ends with
                     the limit
  --max-unpack-depth N
                     deepest nesting -r opens (default 16); 0 opens no
                     archive, and -r takes the one named as one file
  --spill-dir DIR|off
                     with -r, the directory of the anonymous temporary file a
                     container inside a member over --max-object-bytes is
                     written to so that it can be opened (default: the system
                     temporary directory); off writes nothing, and such a
                     container is reported unreadable
  --max-total-spill-bytes SIZE|off
                     most the spill files open at once may hold (default 2G);
                     a container that would pass it is reported unreadable
  --object-cache-bytes SIZE
                     memory of the cache over the archive on disk, shared by
                     the parts of a split archive; an archive that fits in it
                     and in --max-object-bytes is read whole (default 32M)
  --object-cache-block-bytes SIZE
                     what that cache reads at a time (default 1M)
  --help, --version
SIZE takes a K, M, G or T suffix (powers of 1024). A limit that takes off takes
0 as off too. The two cache sizes also take off, which is 0: a cache never
holds less than two blocks. Each limit above is also read from the environment,
as EXAV_ and its name in capitals with underscores (EXAV_MAX_OBJECT_BYTES,
EXAV_SPILL_DIR); the option wins over the variable.";

/// unzip's exit statuses, as far as they apply.
mod status {
    pub const OK: u8 = 0;
    pub const WARNING: u8 = 1;
    pub const ERROR: u8 = 2;
    pub const NO_PASSWORD: u8 = 5;
    pub const NO_ARCHIVE: u8 = 9;
    pub const BAD_OPTIONS: u8 = 10;
    pub const NO_MATCH: u8 = 11;
    pub const DISK_FULL: u8 = 50;
    pub const UNSUPPORTED: u8 = 81;
    pub const BAD_PASSWORD: u8 = 82;
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Extract,
    List,
    Test,
    /// `-p`: the members' bytes to stdout.
    Pipe,
    /// `-c`: as `-p`, with messages.
    Show,
    /// `-Z1`: names only.
    Names,
}

struct Opts {
    mode: Mode,
    archive: String,
    members: Vec<String>,
    excludes: Vec<String>,
    dir: Option<PathBuf>,
    /// `Some(true)` for `-o`, `Some(false)` for `-n`, `None` to ask.
    overwrite: Option<bool>,
    quiet: u8,
    passwords: Vec<String>,
    junk: bool,
    nocase: bool,
    /// `-D` count: 1 keeps directory times off, 2 all times.
    no_times: u8,
    volumes: Vec<PathBuf>,
    /// `-r`: the archives inside the archive are opened too.
    recursive: bool,
    limits: Limits,
    /// The block cache of the archive: what it holds, and what it reads at a
    /// time.
    cache_bytes: u64,
    cache_block: u64,
    /// With `-r`, where a container inside a member over `--max-object-bytes`
    /// is written to be opened; `None` writes nothing.
    spill_dir: Option<PathBuf>,
    /// The most the spill files open at once may hold; `None` is no ceiling.
    max_spill: Option<u64>,
}

/// The defaults of the scanner's `--object-cache-bytes` and
/// `--object-cache-block-bytes`.
const CACHE_BYTES: u64 = exav_unpack::source::CACHE_BYTES as u64;
const CACHE_BLOCK: u64 = 1 << 20;

/// The default of `--max-total-spill-bytes`, as exav-grep has it.
const MAX_SPILL: u64 = 2 << 30;

/// The environment variables the options fall back to, with the option each
/// stands for. They are named as the scanner names them.
const ENV: &[(&str, &str)] = &[
    ("EXAV_MAX_EXTRACTED_BYTES", "max-extracted-bytes"),
    ("EXAV_MAX_OBJECT_BYTES", "max-object-bytes"),
    ("EXAV_MAX_MEMBERS", "max-members"),
    ("EXAV_MAX_COMPRESSION_RATIO", "max-compression-ratio"),
    ("EXAV_MAX_UNPACK_DEPTH", "max-unpack-depth"),
    ("EXAV_OBJECT_CACHE_BYTES", "object-cache-bytes"),
    ("EXAV_OBJECT_CACHE_BLOCK_BYTES", "object-cache-block-bytes"),
    ("EXAV_SPILL_DIR", "spill-dir"),
    ("EXAV_MAX_TOTAL_SPILL_BYTES", "max-total-spill-bytes"),
];

enum Parsed {
    Usage(u8),
    Version,
    Run(Box<Opts>),
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Ok(Parsed::Usage(code)) => {
            match code {
                status::OK => println!("{USAGE}"),
                _ => eprintln!("{USAGE}"),
            }
            ExitCode::from(code)
        }
        Ok(Parsed::Version) => {
            println!("exav-unpack {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Parsed::Run(o)) => ExitCode::from(run(&o)),
        Err(e) => {
            eprintln!("exav-unpack:  {e}\n\n{USAGE}");
            ExitCode::from(status::BAD_OPTIONS)
        }
    }
}

/// unzip's options that this subset refuses, with what they do.
const UNSUPPORTED: &[(char, &str)] = &[
    ('f', "freshen"),
    ('u', "update"),
    ('z', "archive comment"),
    ('T', "archive timestamp"),
    ('a', "text conversion"),
    ('b', "binary/text mode"),
    ('B', "backups"),
    ('E', "MacOS extra field"),
    ('F', "Acorn filetypes"),
    ('i', "MacOS names"),
    ('J', "file attributes"),
    ('K', "setuid/setgid bits"),
    ('L', "lowercase names"),
    ('M', "pager"),
    ('N', "Amiga filenotes"),
    ('s', "spaces to underscores"),
    ('S', "VMS Stream_LF"),
    ('U', "Unicode escapes"),
    ('V', "VMS version numbers"),
    ('W', "wildcard stop at directories"),
    ('X', "owners and ACLs"),
    ('Y', "VMS versions"),
    ('$', "volume labels"),
    ('/', "Acorn extension list"),
    (':', "paths outside the extraction directory"),
    ('^', "control characters in names"),
    ('2', "ODS names"),
    ('A', "DLL help"),
];

fn parse(args: &[String]) -> Result<Parsed, String> {
    parse_with(args, &|name| std::env::var(name).ok())
}

/// [`parse`], reading the environment through `env`. A variable that is set
/// is read as the option is, an empty one included, as the scanner reads
/// its own. The command line wins over the environment.
fn parse_with(args: &[String], env: &dyn Fn(&str) -> Option<String>) -> Result<Parsed, String> {
    if args.is_empty() {
        return Ok(Parsed::Usage(status::OK));
    }
    // An extractor writes to disk rather than holding what it decodes, so its
    // totals can be far above the scanner's. The compression-ratio limit
    // still leaves out a member that passes `max_buffer_bytes` at the ratio,
    // long before them.
    let mut limits = Limits::default();
    limits.max_extracted_bytes = 64 << 30;
    limits.max_scanned_bytes = 64 << 30;
    limits.max_buffer_bytes = 1 << 30;
    limits.max_members = 1_000_000;
    let mut o = Opts {
        mode: Mode::Extract,
        archive: String::new(),
        members: Vec::new(),
        excludes: Vec::new(),
        dir: None,
        overwrite: None,
        quiet: 0,
        passwords: Vec::new(),
        junk: false,
        nocase: false,
        no_times: 0,
        volumes: Vec::new(),
        recursive: false,
        limits,
        cache_bytes: CACHE_BYTES,
        cache_block: CACHE_BLOCK,
        spill_dir: Some(std::env::temp_dir()),
        max_spill: Some(MAX_SPILL),
    };
    for (var, option) in ENV {
        if let Some(value) = env(var) {
            set_limit(&mut o, option, &value, var)?;
        }
    }
    let (mut modes, mut verbose, mut archive, mut excluding) = (Vec::new(), false, None, false);
    let mut i = 0;
    let next = |i: &mut usize, what: &str| -> Result<String, String> {
        *i += 1;
        args.get(*i)
            .cloned()
            .ok_or_else(|| format!("{what} needs a value"))
    };
    while i < args.len() {
        let a = &args[i];
        // The long options are exav-unpack's own; unzip has none, so they
        // are read anywhere.
        if let Some(long) = a.strip_prefix("--").filter(|l| !l.is_empty()) {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            let value = |i: &mut usize| inline.clone().map_or_else(|| next(i, a), Ok);
            match name {
                "help" => return Ok(Parsed::Usage(status::OK)),
                "version" => return Ok(Parsed::Version),
                "volume" => o.volumes.push(PathBuf::from(value(&mut i)?)),
                "recursive" => o.recursive = true,
                // The older names are kept.
                "max-size" => set_limit(&mut o, "max-extracted-bytes", &value(&mut i)?, a)?,
                "max-memory" => set_limit(&mut o, "max-object-bytes", &value(&mut i)?, a)?,
                "max-extracted-bytes"
                | "max-object-bytes"
                | "max-unpack-depth"
                | "object-cache-bytes"
                | "object-cache-block-bytes"
                | "max-members"
                | "max-compression-ratio"
                | "spill-dir"
                | "max-total-spill-bytes" => set_limit(&mut o, name, &value(&mut i)?, a)?,
                _ => return Err(format!("unknown option `{a}`")),
            }
            i += 1;
            continue;
        }
        let option = a.len() > 1 && a.starts_with('-');
        // Past the archive, only `-x` and `-d` are options: anything else is
        // a member name, as unzip has it.
        if !option || (archive.is_some() && a != "-x" && !a.starts_with("-d")) {
            match (&archive, excluding) {
                (None, false) => archive = Some(a.clone()),
                (_, true) => o.excludes.push(a.clone()),
                (Some(_), false) => o.members.push(a.clone()),
            }
            i += 1;
            continue;
        }
        excluding = false;
        let cluster: Vec<char> = a[1..].chars().collect();
        if cluster[0] == 'Z' {
            match (i, &cluster[1..]) {
                (0, ['1']) => modes.push(Mode::Names),
                (0, _) => return Err("-Z is supported as -Z1 only".to_string()),
                _ => return Err("-Z must be the first option".to_string()),
            }
            i += 1;
            continue;
        }
        let mut k = 0;
        while k < cluster.len() {
            let c = cluster[k];
            // The rest of the cluster, or the next argument.
            let mut operand = |i: &mut usize| -> Result<String, String> {
                let rest: String = cluster[k + 1..].iter().collect();
                k = cluster.len();
                match rest.is_empty() {
                    true => next(i, &format!("-{c}")),
                    false => Ok(rest),
                }
            };
            match c {
                'r' => o.recursive = true,
                'l' => modes.push(Mode::List),
                't' => modes.push(Mode::Test),
                'p' => modes.push(Mode::Pipe),
                'c' => modes.push(Mode::Show),
                'v' => verbose = true,
                'o' => o.overwrite = Some(true),
                'n' => o.overwrite = Some(false),
                'q' => o.quiet = o.quiet.saturating_add(1),
                'j' => o.junk = true,
                'C' => o.nocase = true,
                'D' => o.no_times = o.no_times.saturating_add(1),
                'h' => return Ok(Parsed::Usage(status::OK)),
                'd' => o.dir = Some(PathBuf::from(operand(&mut i)?)),
                'P' => o.passwords.push(operand(&mut i)?),
                'x' => excluding = true,
                _ => {
                    return Err(match UNSUPPORTED.iter().find(|u| u.0 == c) {
                        Some((_, what)) => {
                            format!("-{c} ({what}) is an unzip option exav-unpack does not take")
                        }
                        None => format!("unknown option -{c}"),
                    });
                }
            }
            k += 1;
        }
        i += 1;
    }
    if verbose {
        // unzip's `-v` alone shows its version; with an archive it is the
        // verbose listing, which this subset does not have.
        return match (&archive, modes.is_empty()) {
            (None, true) => Ok(Parsed::Version),
            _ => {
                Err("-v (verbose listing) is an unzip option exav-unpack does not take".to_string())
            }
        };
    }
    if modes.len() > 1 {
        return Err("any combination of -c, -l, -p, -t and -Z1 is invalid".to_string());
    }
    o.mode = modes.pop().unwrap_or(Mode::Extract);
    let Some(archive) = archive else {
        return Ok(Parsed::Usage(status::BAD_OPTIONS));
    };
    o.archive = archive;
    Ok(Parsed::Run(Box::new(o)))
}

/// `n`, `nK`, `nM`, `nG` or `nT`, in bytes.
fn size(s: &str) -> Result<u64, String> {
    let bad = || format!("`{s}` is not a size");
    let (digits, shift) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => {
            let shift = match c.to_ascii_uppercase() {
                'K' => 10,
                'M' => 20,
                'G' => 30,
                'T' => 40,
                _ => return Err(bad()),
            };
            (&s[..i], shift)
        }
        _ => (s, 0),
    };
    let n: u64 = digits.parse().map_err(|_| bad())?;
    n.checked_mul(1 << shift).ok_or_else(bad)
}

/// [`size`], or `off`, which is 0, as the scanner's size options take it.
fn cache_size(s: &str) -> Result<u64, String> {
    match s.trim().eq_ignore_ascii_case("off") {
        true => Ok(0),
        false => size(s.trim()),
    }
}

/// [`size`], or `off`, which is no limit (the largest number).
fn size_or_off(s: &str) -> Result<u64, String> {
    match s.trim().eq_ignore_ascii_case("off") {
        true => Ok(u64::MAX),
        // As in exav: a limit every object is over is none.
        false => size(s.trim()).map(|n| if n == 0 { u64::MAX } else { n }),
    }
}

/// Set the option `name` (without its dashes) to `value`, which came from the
/// flag or the variable `shown`. The one place a limit is read, so that a flag
/// and its variable take the same values.
fn set_limit(o: &mut Opts, name: &str, value: &str, shown: &str) -> Result<(), String> {
    let at = |e: String| format!("{shown}: {e}");
    let number = |what: &str| -> Result<u64, String> {
        match value.trim().eq_ignore_ascii_case("off") {
            true => Ok(u64::MAX),
            false => match value.trim().parse() {
                Ok(0) => Ok(u64::MAX),
                Ok(n) => Ok(n),
                Err(_) => Err(format!("{shown} takes a number{what}")),
            },
        }
    };
    match name {
        "max-extracted-bytes" => {
            let n = size_or_off(value).map_err(at)?;
            o.limits.max_extracted_bytes = n;
            o.limits.max_scanned_bytes = n;
        }
        "max-object-bytes" => o.limits.max_buffer_bytes = size_or_off(value).map_err(at)?,
        // No `off`: every level of nesting costs stack.
        "max-unpack-depth" => {
            o.limits.max_recursion = value
                .trim()
                .parse()
                .map_err(|_| format!("{shown} takes a number"))?
        }
        "max-members" => o.limits.max_members = number(" or `off`")?,
        "max-compression-ratio" => o.limits.max_compression_ratio = number(" or `off`")?,
        "object-cache-bytes" => o.cache_bytes = cache_size(value).map_err(at)?,
        "object-cache-block-bytes" => o.cache_block = cache_size(value).map_err(at)?,
        "spill-dir" => {
            o.spill_dir = match value {
                "off" => None,
                dir => Some(PathBuf::from(dir)),
            }
        }
        // `off` and 0 are no ceiling, as exav-grep has it.
        "max-total-spill-bytes" => {
            o.max_spill = match size_or_off(value).map_err(at)? {
                0 | u64::MAX => None,
                n => Some(n),
            }
        }
        _ => unreachable!("{name} is not a limit"),
    }
    Ok(())
}

/// How the archives went, for unzip's closing tally.
#[derive(Default)]
struct Tally {
    ok: u32,
    warned: u32,
    failed: u32,
    worst: u8,
}

fn run(o: &Opts) -> u8 {
    let archives = match archives(&o.archive) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("exav-unpack:  {e}");
            return status::NO_ARCHIVE;
        }
    };
    if archives.len() > 1 && !o.volumes.is_empty() {
        eprintln!(
            "exav-unpack:  --volume names the parts of one archive, not of {}",
            o.archive
        );
        return status::BAD_OPTIONS;
    }
    if o.dir.is_some() && matches!(o.mode, Mode::List | Mode::Test | Mode::Names) {
        eprintln!("caution:  not extracting; -d ignored");
    }
    let mut prompt = Prompt::default();
    let mut t = Tally::default();
    for (n, path) in archives.iter().enumerate() {
        if n > 0 && o.quiet == 0 && !matches!(o.mode, Mode::Pipe | Mode::Names) {
            println!();
        }
        let s = Archive::new(o, path, &mut prompt).run();
        match s {
            status::OK => t.ok += 1,
            status::WARNING => t.warned += 1,
            _ => t.failed += 1,
        }
        t.worst = t.worst.max(s);
    }
    if archives.len() > 1 && o.quiet == 0 && !matches!(o.mode, Mode::Pipe | Mode::Names) {
        eprintln!();
        let line = |n: u32, one: &str, many: &str| match n {
            1 => eprintln!("1 archive {one}"),
            n => eprintln!("{n} archives {many}"),
        };
        line(
            t.ok,
            "was successfully processed.",
            "were successfully processed.",
        );
        if t.warned > 0 {
            line(
                t.warned,
                "had warnings but no fatal errors.",
                "had warnings but no fatal errors.",
            );
        }
        if t.failed > 0 {
            line(t.failed, "had fatal errors.", "had fatal errors.");
        }
    }
    t.worst
}

/// The archives `spec` names: itself, or failing that with `.zip` or `.ZIP`
/// added, as unzip tries them; or every file a wildcard matches.
fn archives(spec: &str) -> Result<Vec<PathBuf>, String> {
    let missing = || format!("cannot find or open {spec}, {spec}.zip or {spec}.ZIP.");
    let path = Path::new(spec);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or(spec);
    if name.contains(['*', '?', '[']) {
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut found: Vec<PathBuf> = fs::read_dir(dir)
            .map_err(|_| missing())?
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| matches(name, n, false))
            })
            .map(
                |e| match path.parent().filter(|d| !d.as_os_str().is_empty()) {
                    Some(_) => dir.join(e.file_name()),
                    None => PathBuf::from(e.file_name()),
                },
            )
            .collect();
        found.sort();
        return match found.is_empty() {
            true => Err(missing()),
            false => Ok(found),
        };
    }
    [
        spec.to_string(),
        format!("{spec}.zip"),
        format!("{spec}.ZIP"),
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
    .map(|p| vec![p])
    .ok_or_else(missing)
}

/// Whether `name` matches unzip's wildcard `pattern`: `*` any run of
/// characters, `/` included; `?` any one; `[...]` one of a set, `[!...]` one
/// outside it, with ranges.
fn matches(pattern: &str, name: &str, nocase: bool) -> bool {
    let fold = |c: char| if nocase { c.to_ascii_lowercase() } else { c };
    let p: Vec<char> = pattern.chars().map(fold).collect();
    let n: Vec<char> = name.chars().map(fold).collect();
    // Classic backtracking on the last `*`: linear in practice.
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        let step = match p.get(pi) {
            Some('*') => {
                star = Some(pi);
                mark = ni;
                pi += 1;
                continue;
            }
            Some('?') => Some(pi + 1),
            Some('[') => class(&p, pi, n[ni]),
            Some(&c) if c == n[ni] => Some(pi + 1),
            _ => None,
        };
        match (step, star) {
            (Some(next), _) => {
                pi = next;
                ni += 1;
            }
            (None, Some(s)) => {
                pi = s + 1;
                mark += 1;
                ni = mark;
            }
            (None, None) => return false,
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// Where the pattern goes on when the set at `p[at] == '['` takes `c`.
fn class(p: &[char], at: usize, c: char) -> Option<usize> {
    let mut i = at + 1;
    let negate = matches!(p.get(i), Some('!') | Some('^'));
    if negate {
        i += 1;
    }
    let mut hit = false;
    let mut first = true;
    while let Some(&x) = p.get(i) {
        if x == ']' && !first {
            return (hit != negate).then_some(i + 1);
        }
        first = false;
        if p.get(i + 1) == Some(&'-') && p.get(i + 2).is_some_and(|&y| y != ']') {
            hit |= (x..=p[i + 2]).contains(&c);
            i += 3;
        } else {
            hit |= x == c;
            i += 1;
        }
    }
    // No closing `]`: a literal `[`.
    (c == '[').then_some(at + 1)
}

/// The answers to "replace?" that hold for the rest of the run.
#[derive(Default)]
struct Prompt {
    all: Option<bool>,
}

/// A link made once every member is out, so no member is written through it.
struct Deferred {
    path: PathBuf,
    shown: String,
    target: String,
}

/// One archive's run.
struct Archive<'a> {
    o: &'a Opts,
    path: &'a Path,
    prompt: &'a mut Prompt,
    status: u8,
    /// Which of the include and exclude patterns matched something.
    matched: Vec<bool>,
    excluded: Vec<bool>,
    files: u64,
    bytes: u64,
    links: Vec<Deferred>,
    /// Directories whose times and modes are set last, once their contents
    /// are written.
    dirs: Vec<(PathBuf, Option<Mtime>, Option<u32>)>,
    buf: Vec<u8>,
    tested_bad: bool,
    /// Members out (or tested) whole, and those skipped for a wrong password.
    ok: u64,
    bad_password: u64,
}

impl<'a> Archive<'a> {
    fn new(o: &'a Opts, path: &'a Path, prompt: &'a mut Prompt) -> Self {
        Archive {
            o,
            path,
            prompt,
            status: status::OK,
            matched: vec![false; o.members.len()],
            excluded: vec![false; o.excludes.len()],
            files: 0,
            bytes: 0,
            links: Vec::new(),
            dirs: Vec::new(),
            buf: vec![0; 1 << 20],
            tested_bad: false,
            ok: 0,
            bad_password: 0,
        }
    }

    fn raise(&mut self, s: u8) {
        self.status = self.status.max(s);
    }

    fn run(mut self) -> u8 {
        let o = self.o;
        let messages = o.quiet == 0 && !matches!(o.mode, Mode::Pipe | Mode::Names);
        if messages && !(o.mode == Mode::Test && o.quiet > 0) {
            println!("Archive:  {}", self.path.display());
        }
        let src = match o.open(self.path, &open_file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("exav-unpack:  cannot read {}: {e}", self.path.display());
                return status::NO_ARCHIVE;
            }
        };
        let fmt = match type_object(&Typing::WALK, &*src, o.limits.max_buffer_bytes) {
            Typed::Container(fmt) => fmt,
            Typed::Plain => {
                eprintln!(
                    "exav-unpack:  {} is not an archive exav-unpack reads.",
                    self.path.display()
                );
                return status::NO_ARCHIVE;
            }
            Typed::Unchecked(why) => {
                let why = shown_text(&why.text);
                eprintln!("exav-unpack:  {}: {why}.", self.path.display());
                return status::NO_ARCHIVE;
            }
        };
        if o.mode == Mode::List && o.quiet < 2 {
            println!("  Length      Date    Time    Name");
            println!("---------  ---------- -----   ----");
        }
        let root = o.dir.clone().unwrap_or_else(|| PathBuf::from("."));
        if o.mode == Mode::Extract
            && let Err(e) = fs::create_dir_all(&root)
        {
            eprintln!("exav-unpack:  cannot create {}: {e}", root.display());
            return status::ERROR;
        }
        let mut budget = Budget::with_passwords(o.limits.clone(), o.passwords.clone());
        budget.set_visit_directories(true);
        let fatal = match o.recursive {
            true => self.run_nested(&root, &*src, &mut budget),
            false => {
                let mut fatal = None;
                let stopped = walk::<()>(fmt, &*src, &mut budget, &mut |meta, content, _| {
                    let label = Label::stored(&meta.name);
                    // A member the end of the archive cuts is reported, as
                    // unzip and tar report one.
                    let failed = content
                        .is_some()
                        .then(|| exav_unpack::tree::range_cut(meta, src.len()))
                        .flatten();
                    let item = Item {
                        label,
                        meta,
                        failed,
                    };
                    match self.member(&root, &item, content) {
                        Ok(()) => None,
                        Err(why) => {
                            fatal = Some(why);
                            Some(())
                        }
                    }
                });
                if let Err(hit) = stopped {
                    self.fail("", &hit.to_string());
                }
                fatal
            }
        };
        if let Some(fatal) = fatal {
            eprintln!("exav-unpack:  {fatal}");
            self.raise(status::DISK_FULL);
        }
        self.finish(&root, messages);
        self.status
    }

    /// `-r`: the walk goes down into the archives the members are, and what
    /// comes out of them is handled as a member of a single archive is.
    /// `Some` is what stopped it.
    fn run_nested(
        &mut self,
        root: &Path,
        src: &dyn ByteSource,
        budget: &mut Budget,
    ) -> Option<String> {
        let o = self.o;
        // A spill directory is a file system's: none on WASI, where a member
        // over the limit is reported as without one.
        #[cfg(not(target_family = "wasm"))]
        let spill = o
            .spill_dir
            .clone()
            .map(|dir| Box::new(DirSpill::new(dir).total(o.max_spill)) as Box<dyn Spill>);
        #[cfg(target_family = "wasm")]
        let spill: Option<Box<dyn Spill>> = None;
        let walker = Walker::new(
            Walk {
                hold: Hold {
                    limit: o.limits.max_buffer_bytes,
                    spill: spill.as_deref(),
                    cache: cache_sizes(1, o.cache_bytes, o.cache_block),
                    // A member over the limit that is not an archive is
                    // written as it is decoded; one that is a container is
                    // written to the spill to be opened, and with no spill it
                    // is reported.
                    large: Large::StreamLeaves,
                },
                sets: true,
                second_readings: false,
            },
            &Typing::WALK,
        );
        let name = self.path.display().to_string();
        let mut nested = Nested {
            archive: self,
            root,
        };
        let done = walker.run(
            Root {
                name: &name,
                source: src,
            },
            budget,
            &mut nested,
        );
        match done.ended {
            Ended::Stopped(fatal) => Some(fatal),
            Ended::Complete | Ended::Limit(_) => None,
        }
    }

    /// The links, directory times, the listing's totals, the test's verdict
    /// and the patterns nothing matched.
    fn finish(&mut self, root: &Path, messages: bool) {
        let o = self.o;
        if !self.links.is_empty() {
            if messages {
                println!("finishing deferred symbolic links:");
            }
            for l in std::mem::take(&mut self.links) {
                if messages {
                    println!("  {:<22} -> {}", l.shown, l.target);
                }
                if let Err(e) = make_link(root, &l.path, &l.target) {
                    eprintln!("   skipping: {:<22}  {e}", l.shown);
                    self.raise(status::WARNING);
                }
            }
        }
        // Deepest first, so setting a directory's time is not undone by a
        // write into it.
        let mut dirs = std::mem::take(&mut self.dirs);
        dirs.sort_by_key(|d| std::cmp::Reverse(d.0.components().count()));
        for (path, mtime, mode) in dirs {
            set_mode(&path, mode);
            if o.no_times == 0 {
                set_time(&path, mtime);
            }
        }
        match o.mode {
            Mode::List if o.quiet < 2 => {
                println!("---------                     -------");
                let s = if self.files == 1 { "" } else { "s" };
                println!(
                    "{:>9}                     {} file{s}",
                    self.bytes, self.files
                );
            }
            Mode::Test if o.quiet < 2 => {
                let plural = |n: u64| if n == 1 { "file" } else { "files" };
                match (self.tested_bad, self.bad_password, self.ok) {
                    (true, ..) => println!(
                        "At least one error was detected in {}.",
                        self.path.display()
                    ),
                    (false, 0, _) => println!(
                        "No errors detected in compressed data of {}.",
                        self.path.display()
                    ),
                    (false, _, 0) => {
                        println!("Caution:  zero files tested in {}.", self.path.display())
                    }
                    (false, _, n) => println!(
                        "No errors detected in {} for the {n} {} tested.",
                        self.path.display(),
                        plural(n)
                    ),
                }
                if self.bad_password > 0 {
                    let n = self.bad_password;
                    println!("{n} {} skipped because of incorrect password.", plural(n));
                }
            }
            _ => {}
        }
        // As unzip has it: a wrong password is an error only when it left
        // nothing to extract or test.
        if self.bad_password > 0 {
            self.raise(if self.ok == 0 {
                status::BAD_PASSWORD
            } else {
                status::WARNING
            });
        }
        for (p, hit) in o.members.iter().zip(&self.matched) {
            if !hit {
                eprintln!("caution: filename not matched:  {p}");
                self.status = self.status.max(status::NO_MATCH);
            }
        }
        for (p, hit) in o.excludes.iter().zip(&self.excluded) {
            if !hit {
                eprintln!("caution: excluded filename not matched:  {p}");
            }
        }
    }

    /// Whether member `name` is one the command line asks for.
    fn wanted(&mut self, name: &str) -> bool {
        let o = self.o;
        let mut take = o.members.is_empty();
        for (p, hit) in o.members.iter().zip(&mut self.matched) {
            if matches(p, name, o.nocase) {
                *hit = true;
                take = true;
            }
        }
        for (p, hit) in o.excludes.iter().zip(&mut self.excluded) {
            if matches(p, name, o.nocase) {
                *hit = true;
                take = false;
            }
        }
        take
    }

    /// List, test, print or write one member. `Err` ends the walk.
    fn member(
        &mut self,
        root: &Path,
        item: &Item<'_>,
        content: Option<Member<'_>>,
    ) -> Result<(), String> {
        let o = self.o;
        let meta = item.meta;
        let name = item.label.shown.as_ref();
        if !self.wanted(&item.label.raw) {
            return Ok(());
        }
        let kind = meta.mode.map(|m| m & 0o170000);
        let raw = item.label.raw.as_ref();
        let dir = kind == Some(0o040000)
            || ((raw.ends_with('/') || raw.ends_with('\\')) && meta.size.unwrap_or(0) == 0);
        let link = kind == Some(0o120000);
        let messages = o.quiet == 0;
        match o.mode {
            Mode::Names => {
                println!("{name}");
                return Ok(());
            }
            Mode::List => {
                let size = match content {
                    Some(Member::Bytes(b)) => b.len() as u64,
                    // A size the archive declares is listed as declared,
                    // without decoding the member to measure it.
                    Some(Member::Stream(r)) => meta
                        .size
                        .unwrap_or_else(|| copy(r, &mut io::sink(), &mut self.buf).unwrap_or(0)),
                    None => meta.size.unwrap_or(0),
                };
                self.files += 1;
                self.bytes = self.bytes.saturating_add(size);
                println!("{size:>9}  {}   {name}", when(meta.mtime));
                return Ok(());
            }
            _ => {}
        }
        if dir {
            match o.mode {
                Mode::Test if messages => println!("    testing: {name:<22}   OK"),
                Mode::Extract if !o.junk => {
                    let Some(path) = target(root, &item.label.rel) else {
                        return self.unsafe_name(name);
                    };
                    let shown = format!("{}/", shown(o, &path));
                    let made = !path.is_dir();
                    if let Err(e) = directories(root, &path, true) {
                        eprintln!("exav-unpack:  {e}");
                        self.raise(status::ERROR);
                        return Ok(());
                    }
                    if messages && made {
                        println!("   creating: {shown}");
                    }
                    self.dirs.push((path, meta.mtime, meta.mode));
                }
                _ => {}
            }
            self.ok += 1;
            return Ok(());
        }
        // Not decodable: say why, as unzip's `skipping:` does, or as its test
        // reports damage.
        let Some(content) = content else {
            // By the kind of the reason the reader gave, never by its words.
            let (kind, text) = match Reason::of_member(meta) {
                Some(r) => (r.kind, r.text),
                None if meta.encrypted => (ReasonKind::Password, String::new()),
                // A stream that failed to decode gives its error to the walk,
                // not to its member.
                None => (
                    ReasonKind::Damaged,
                    item.failed
                        .clone()
                        .unwrap_or_else(|| "no content".to_string()),
                ),
            };
            let (why, s) = match (kind, o.passwords.is_empty()) {
                (ReasonKind::Password, true) => {
                    ("unable to get password".to_string(), status::NO_PASSWORD)
                }
                (ReasonKind::Password, false) => {
                    ("incorrect password".to_string(), status::BAD_PASSWORD)
                }
                (ReasonKind::Unsupported, _) => (text, status::UNSUPPORTED),
                _ => (text, status::ERROR),
            };
            match s {
                // Settled in `finish`, once it is known what else came out.
                status::BAD_PASSWORD => self.bad_password += 1,
                _ => {
                    self.tested_bad = true;
                    self.raise(s);
                }
            }
            let why = shown_text(&why);
            match (o.mode, s) {
                (Mode::Test, status::ERROR) => {
                    println!("    testing: {name:<22}  ");
                    println!("  error:  {why}");
                }
                (Mode::Test, _) => println!("   skipping: {name:<22}  {why}"),
                _ => eprintln!("   skipping: {name:<22}  {why}"),
            }
            return Ok(());
        };
        match o.mode {
            Mode::Test => {
                let got = self.decode(content, &mut io::sink());
                let damage = got
                    .err()
                    .or_else(|| item.failed.clone())
                    .or_else(|| meta.unsupported.map(str::to_string));
                match damage {
                    None => {
                        if messages {
                            println!("    testing: {name:<22}   OK");
                        }
                        self.ok += 1;
                    }
                    Some(e) => {
                        println!("    testing: {name:<22}  ");
                        println!("  error:  {}", shown_text(&e));
                        self.tested_bad = true;
                        self.raise(status::ERROR);
                    }
                }
                Ok(())
            }
            Mode::Pipe | Mode::Show => {
                if o.mode == Mode::Show && messages {
                    println!(" extracting: {name:<22}  ");
                }
                let mut out = io::stdout().lock();
                let got = self.decode(content, &mut out);
                if o.mode == Mode::Show {
                    let _ = writeln!(out);
                }
                drop(out);
                let late = item.failed.clone();
                let unsupported = meta.unsupported.map(str::to_string);
                match got.and_then(|_| late.or(unsupported).map_or(Ok(()), Err)) {
                    Ok(()) => self.ok += 1,
                    Err(e) => {
                        eprintln!("  error:  {}", shown_text(&e));
                        self.raise(status::ERROR);
                    }
                }
                Ok(())
            }
            _ => self.extract(root, item, content, link),
        }
    }

    /// Report what went wrong at `at`, a member of an archive inside the
    /// archive, or the archive itself when it is empty. A test then does not
    /// end with "No errors detected".
    fn fail(&mut self, at: &str, why: &str) {
        let why = shown_text(why);
        match at.is_empty() {
            true => eprintln!("  error:  {why}"),
            false => eprintln!("  error:  {at}: {why}"),
        }
        self.tested_bad = true;
        self.raise(status::ERROR);
    }

    fn unsafe_name(&mut self, name: &str) -> Result<(), String> {
        eprintln!("   skipping: {name:<22}  unsafe member name");
        self.raise(status::WARNING);
        Ok(())
    }

    /// Decode `content` into `w`; `Err` names what went wrong part way.
    fn decode(&mut self, content: Member<'_>, w: &mut dyn Write) -> Result<u64, String> {
        match content {
            Member::Bytes(b) => w
                .write_all(&b)
                .map(|_| b.len() as u64)
                .map_err(|e| e.to_string()),
            Member::Stream(r) => copy(r, w, &mut self.buf).map_err(|e| match e {
                Copy::Write(e) => e.to_string(),
                Copy::Read(e) => e.to_string(),
            }),
        }
    }

    /// Write one member to disk.
    fn extract(
        &mut self,
        root: &Path,
        item: &Item<'_>,
        content: Member<'_>,
        link: bool,
    ) -> Result<(), String> {
        let o = self.o;
        let meta = item.meta;
        let name = item.label.shown.as_ref();
        let whole = item.label.rel.as_ref();
        let rel = match o.junk {
            true => whole.rsplit(['/', '\\']).next().unwrap_or(whole),
            false => whole,
        };
        let Some(mut path) = target(root, rel) else {
            return self.unsafe_name(name);
        };
        if link {
            let target = match (&meta.link, content) {
                (Some(t), _) => t.clone(),
                (None, c) => {
                    let mut t = Vec::new();
                    let _ = self.decode(c, &mut t);
                    String::from_utf8_lossy(&t).into_owned()
                }
            };
            if let Ok(m) = fs::symlink_metadata(&path) {
                match (o.overwrite, m.file_type().is_symlink()) {
                    (Some(true), _) => {}
                    (_, true) => {
                        println!("{} exists and is a symbolic link.", shown(o, &path));
                        return Ok(());
                    }
                    (_, false) => match self.replace(&path) {
                        Replace::Yes => {}
                        Replace::No => return Ok(()),
                        Replace::Rename(p) => path = p,
                    },
                }
            }
            let shown = shown(o, &path);
            if o.quiet == 0 {
                println!("    linking: {shown:<22}  -> {target} ");
            }
            self.links.push(Deferred {
                path,
                shown,
                target,
            });
            self.ok += 1;
            return Ok(());
        }
        if let Err(e) = directories(root, &path, false) {
            eprintln!("exav-unpack:  {e}");
            self.raise(status::ERROR);
            return Ok(());
        }
        if fs::symlink_metadata(&path).is_ok() {
            match self.replace(&path) {
                Replace::Yes => {}
                Replace::No => return Ok(()),
                Replace::Rename(p) => path = p,
            }
        }
        let shown = shown(o, &path);
        // A link or a file in the way is removed, never written through.
        if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_dir()) {
            let _ = fs::remove_file(&path);
        }
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("exav-unpack:  cannot create {shown}: {e}");
                self.raise(status::ERROR);
                return Ok(());
            }
        };
        // As unzip has it, the line is ended once the member is out, and left
        // open when the error that stopped it goes to stderr.
        if o.quiet == 0 {
            print!("{:>11}: {shown:<22}  ", verb(meta));
            let _ = io::stdout().flush();
        }
        let got = match content {
            Member::Bytes(b) => file.write_all(&b).map_err(Copy::Write),
            Member::Stream(r) => copy(r, &mut file, &mut self.buf).map(|_| ()),
        };
        let error = match got {
            Ok(()) => item
                .failed
                .clone()
                .or_else(|| meta.unsupported.map(str::to_string)),
            Err(Copy::Write(e)) => return Err(format!("cannot write {shown}: {e}")),
            Err(Copy::Read(e)) => Some(e.to_string()),
        };
        match error {
            None => {
                if o.quiet == 0 {
                    println!();
                }
                self.ok += 1;
            }
            Some(e) => {
                eprintln!("\n  error:  {}", shown_text(&e));
                self.raise(status::ERROR);
            }
        }
        drop(file);
        set_mode(&path, meta.mode);
        if o.no_times < 2 {
            set_time(&path, meta.mtime);
        }
        Ok(())
    }

    /// What to do about a file already at `path`: `-o`, `-n`, or ask, as unzip
    /// does, on stdin.
    fn replace(&mut self, path: &Path) -> Replace {
        if let Some(yes) = self.o.overwrite.or(self.prompt.all) {
            return if yes { Replace::Yes } else { Replace::No };
        }
        let shown = shown(self.o, path);
        loop {
            eprint!("replace {shown}? [y]es, [n]o, [A]ll, [N]one, [r]ename: ");
            let Some(answer) = read_line() else {
                eprintln!(" NULL\n(EOF or read error, treating as \"[N]one\" ...)");
                self.prompt.all = Some(false);
                self.raise(status::WARNING);
                return Replace::No;
            };
            match answer.trim() {
                "y" | "Y" => return Replace::Yes,
                "n" => return Replace::No,
                "A" => {
                    self.prompt.all = Some(true);
                    return Replace::Yes;
                }
                "N" => {
                    self.prompt.all = Some(false);
                    return Replace::No;
                }
                "r" | "R" => {
                    eprint!("new name: ");
                    match read_line()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                    {
                        Some(new) => return Replace::Rename(PathBuf::from(new)),
                        None => return Replace::No,
                    }
                }
                _ => eprintln!("error:  invalid response [{}]", answer.trim()),
            }
        }
    }
}

enum Replace {
    Yes,
    No,
    Rename(PathBuf),
}

/// unzip's word for writing out a member, by its ZIP method; `extracting`
/// for any other.
fn verb(meta: &MemberMeta) -> &'static str {
    match meta.zip_method {
        Some(8 | 9) => "inflating",
        Some(12) => "bunzipping",
        Some(6) => "exploding",
        Some(1) => "unshrinking",
        Some(2..=5) => "unreducing",
        _ => "extracting",
    }
}

fn read_line() -> Option<String> {
    let mut s = String::new();
    match io::stdin().lock().read_line(&mut s) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(s),
    }
}

/// `path` as unzip prints it: under `-d DIR`, `DIR/name`; else the name.
fn shown(o: &Opts, path: &Path) -> String {
    match &o.dir {
        Some(_) => path.display().to_string(),
        None => path.strip_prefix(".").unwrap_or(path).display().to_string(),
    }
}

/// A member's time as `-l` lists it, in local time.
fn when(m: Option<Mtime>) -> String {
    match m {
        Some(Mtime::Local {
            year,
            month,
            day,
            hour,
            minute,
            ..
        }) => {
            format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}")
        }
        Some(Mtime::Unix(s)) => match Local.timestamp_opt(s, 0) {
            LocalResult::Single(t) | LocalResult::Ambiguous(t, _) => {
                t.format("%Y-%m-%d %H:%M").to_string()
            }
            LocalResult::None => " ".repeat(16),
        },
        None => " ".repeat(16),
    }
}

/// A member's time as an instant: a DOS time is read in the local zone, as
/// unzip reads it.
fn instant(m: Mtime) -> Option<SystemTime> {
    let secs = match m {
        Mtime::Unix(s) => s,
        Mtime::Local {
            year,
            month,
            day,
            hour,
            minute,
            second,
        } => Local
            .with_ymd_and_hms(
                year.into(),
                month.into(),
                day.into(),
                hour.into(),
                minute.into(),
                second.into(),
            )
            .earliest()?
            .timestamp(),
    };
    match secs >= 0 {
        true => SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64)),
        false => SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs())),
    }
}

fn set_time(path: &Path, m: Option<Mtime>) {
    let Some(t) = m.and_then(instant) else { return };
    // Opening a directory to set its time works on Unix only.
    if let Ok(f) = File::open(path) {
        let _ = f.set_modified(t);
    }
}

/// The permission bits of a Unix `mode`, without setuid, setgid or sticky:
/// unzip keeps those only with `-K`.
fn set_mode(path: &Path, mode: Option<u32>) {
    #[cfg(unix)]
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(m & 0o777));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

/// Whether a link at `path` to `target` leads out of `root`, by the words of
/// the target alone: a `..` past the root, or a root of its own.
fn escapes(root: &Path, path: &Path, target: &str) -> bool {
    let parent = path.parent().unwrap_or(root);
    let mut depth = parent
        .strip_prefix(root)
        .map_or(0, |r| r.components().count()) as isize;
    for c in Path::new(target).components() {
        match c {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => depth -= 1,
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return true,
        }
        if depth < 0 {
            return true;
        }
    }
    false
}

/// Whether a link at `path` to `target` leads out of `root` once the links
/// already made are followed. [`escapes`] reads the words of the target alone,
/// and counts a `..` against the link's own depth: `a -> .` and `b -> a/..` each
/// pass it, and `b` is the directory above the root.
fn resolves_outside(root: &Path, path: &Path, target: &str) -> bool {
    let Ok(root) = fs::canonicalize(root) else {
        return true;
    };
    let Some(mut at) = path.parent().and_then(|p| fs::canonicalize(p).ok()) else {
        return true;
    };
    if !at.starts_with(&root) {
        return true;
    }
    // The words still to be read, the next one last.
    let words = |t: &str| -> Option<Vec<std::ffi::OsString>> {
        let mut out = Vec::new();
        for c in Path::new(t).components().rev() {
            match c {
                Component::RootDir | Component::Prefix(_) => return None,
                Component::CurDir => {}
                Component::ParentDir => out.push("..".into()),
                Component::Normal(n) => out.push(n.to_os_string()),
            }
        }
        Some(out)
    };
    let Some(mut todo) = words(target) else {
        return true;
    };
    let mut hops = 0;
    while let Some(w) = todo.pop() {
        if w == ".." {
            if !at.pop() || !at.starts_with(&root) {
                return true;
            }
            continue;
        }
        at.push(&w);
        if fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_symlink()) {
            hops += 1;
            let Some(next) = (hops <= 40)
                .then(|| fs::read_link(&at).ok())
                .flatten()
                .and_then(|l| words(&l.to_string_lossy()))
            else {
                return true;
            };
            at.pop();
            todo.extend(next);
        }
    }
    !at.starts_with(&root)
}

/// Make the link at `path` to `target`, if the target stays under `root`.
fn make_link(root: &Path, path: &Path, target: &str) -> Result<(), String> {
    if escapes(root, path, target) {
        return Err("symbolic link points outside the extraction directory".to_string());
    }
    directories(root, path, false)?;
    if resolves_outside(root, path, target) {
        return Err("symbolic link points outside the extraction directory".to_string());
    }
    if fs::symlink_metadata(path).is_ok() {
        fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    return std::os::unix::fs::symlink(target, path).map_err(|e| e.to_string());
    // Where links take privileges to make, unzip writes the target as text.
    #[cfg(not(unix))]
    fs::write(path, target).map_err(|e| e.to_string())
}

/// Why a copy stopped: a failed write, or a failed read.
enum Copy {
    Write(io::Error),
    Read(io::Error),
}

/// Copy `r` into `w` through `buf`, returning the bytes copied.
fn copy(r: &mut dyn Read, w: &mut dyn Write, buf: &mut [u8]) -> Result<u64, Copy> {
    let mut n = 0u64;
    loop {
        match r.read(buf) {
            Ok(0) => return Ok(n),
            Ok(k) => {
                w.write_all(&buf[..k]).map_err(Copy::Write)?;
                n += k as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Copy::Read(e)),
        }
    }
}

/// Where member `name` goes under `root`: its plain components only, so no
/// name can climb out (`..`), restart at a root (`/`, `C:`) or be empty.
fn target(root: &Path, name: &str) -> Option<PathBuf> {
    let mut rel = PathBuf::new();
    for c in name.split(['/', '\\']) {
        let drive = c.len() == 2 && c.ends_with(':');
        if c.is_empty() || c == "." || c == ".." || drive {
            continue;
        }
        rel.push(file_name(c));
    }
    (!rel.as_os_str().is_empty()).then(|| root.join(rel))
}

/// `c` as a file name the platform takes: no NUL or control character, and
/// on Windows none of the characters it reserves.
fn file_name(c: &str) -> String {
    c.chars()
        .map(|ch| match ch {
            c if c.is_control() => '_',
            '<' | '>' | ':' | '"' | '|' | '?' | '*' if cfg!(windows) => '_',
            c => c,
        })
        .collect()
}

/// Make the directories from `root` down to `path` (`path` itself too when
/// `last`), refusing to go through a link: one already in the output
/// directory must not take a member somewhere else.
fn directories(root: &Path, path: &Path, last: bool) -> Result<(), String> {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let parts: Vec<_> = rel.components().collect();
    let upto = if last {
        parts.len()
    } else {
        parts.len().saturating_sub(1)
    };
    let mut at = root.to_path_buf();
    for c in &parts[..upto] {
        at.push(c);
        match fs::symlink_metadata(&at) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(format!("{} is a link, not followed", at.display()));
            }
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(format!("{} is a file, not a directory", at.display())),
            Err(_) => {
                fs::create_dir(&at).map_err(|e| format!("cannot create {}: {e}", at.display()))?
            }
        }
    }
    Ok(())
}

/// The files an archive is made of, found from its name or given.
#[derive(Debug, PartialEq)]
enum Layout {
    /// One file.
    One(PathBuf),
    /// A finished file cut into parts (`x.7z.001`, ...): end to end.
    Bytes(Vec<PathBuf>),
    /// Volumes of a format that reads them together (`x.z01`, ..., `x.zip`;
    /// `x.part1.rar`, ...; cabinets), in the order found or given: which of
    /// them make a set is for [`plan`].
    Volumes(Vec<PathBuf>),
}

fn volume_of(p: &Path) -> Option<exav_unpack::volume::VolumeName> {
    p.file_name()
        .and_then(|n| n.to_str())
        .and_then(exav_unpack::volume::parse)
}

/// The files of the archive at `path`: `volumes` with it when given, else the
/// parts its name says are next to it. Siblings are named from the pattern,
/// never from anything a file holds, and looked for in order until one is
/// missing: nothing in the naming records how many parts a set has.
fn parts(path: &Path, volumes: &[PathBuf]) -> io::Result<Layout> {
    use exav_unpack::volume::Scheme;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let is_zip = |p: &Path| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip"));
    let siblings = |v: &exav_unpack::volume::VolumeName, from: usize| -> Vec<PathBuf> {
        (from..)
            .map_while(|i| v.name_at(i))
            .map(|n| dir.join(n))
            .take_while(|p| p.is_file())
            .collect()
    };
    if !volumes.is_empty() {
        let mut all: Vec<PathBuf> = std::iter::once(path.to_path_buf())
            .chain(volumes.iter().cloned())
            .collect();
        // In the order of their volume numbers when their names all have
        // them (a ZIP's `.zip` last), else as given.
        let key = |p: &PathBuf| match volume_of(p) {
            Some(v) => Some(v.index),
            None if is_zip(p) => Some(usize::MAX),
            None => None,
        };
        if all.iter().all(|p| key(p).is_some()) {
            all.sort_by_key(key);
        }
        return Ok(Layout::Volumes(all));
    }
    let missing = |what: String| {
        io::Error::other(format!(
            "one part of a split archive, whose {what} is not next to it"
        ))
    };
    match volume_of(path) {
        Some(v) if v.scheme.is_byte_split() => {
            let all = siblings(&v, 0);
            match all.is_empty() {
                true => Err(missing(format!(
                    "first part ({})",
                    v.name_at(0).unwrap_or_default()
                ))),
                false => Ok(Layout::Bytes(all)),
            }
        }
        Some(v) if v.scheme == Scheme::ZipSplit => {
            let last = dir.join(format!("{}.zip", v.stem));
            let mut all = siblings(&v, 0);
            match last.is_file() && !all.is_empty() {
                true => {
                    all.push(last);
                    Ok(Layout::Volumes(all))
                }
                false => Err(missing(format!("last part ({})", last.display()))),
            }
        }
        Some(v) if matches!(v.scheme, Scheme::RarPart { .. } | Scheme::RarOld) => {
            let all = siblings(&v, 0);
            match all.len() {
                0 => Err(missing(format!(
                    "first part ({})",
                    v.name_at(0).unwrap_or_default()
                ))),
                1 => Ok(Layout::One(all[0].clone())),
                _ => Ok(Layout::Volumes(all)),
            }
        }
        _ if is_zip(path) => {
            // `x.zip` is the last part of a set when `x.z01` is next to it.
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            match volume_of(&dir.join(format!("{stem}.z01"))) {
                Some(v) if dir.join(format!("{stem}.z01")).is_file() => {
                    let mut all = siblings(&v, 0);
                    all.push(path.to_path_buf());
                    Ok(Layout::Volumes(all))
                }
                _ => Ok(Layout::One(path.to_path_buf())),
            }
        }
        _ => Ok(Layout::One(path.to_path_buf())),
    }
}

/// A file the archive is read from. The trait of the spill files, so that the
/// block cache over either is compiled once.
use exav_unpack::spill::SpillReader as ReadSeek;

/// How a file of an archive is opened.
type Opener<'a> = &'a dyn Fn(&Path) -> io::Result<Box<dyn ReadSeek>>;

/// How one of several files that are open together is read: behind its cache.
type Cached<'a> = &'a dyn Fn(&Path, usize) -> io::Result<Box<dyn ByteSource>>;

fn open_file(path: &Path) -> io::Result<Box<dyn ReadSeek>> {
    Ok(Box::new(File::open(path)?))
}

/// The block and the capacity, in bytes, of the cache of each of `parts` files
/// that share `bytes`, read `block` at a time. The parts of a set take a share
/// each, with room for two blocks at least, so smaller blocks when there are
/// many; a cache is never below a byte a block.
fn cache_sizes(parts: usize, bytes: u64, block: u64) -> (usize, usize) {
    let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
    let block = usize::try_from(block).unwrap_or(usize::MAX).max(1);
    if parts <= 1 {
        return (block, bytes);
    }
    let share = bytes / parts;
    (block.min((share / 2).max(4096)), share)
}

impl Opts {
    /// The archive at `path`, with the other parts of its set. A single file
    /// that fits in the object cache and in `--max-object-bytes` is read whole;
    /// any other is read from disk as it is needed, through block caches sized
    /// by `--object-cache-*`, the parts of a set sharing the cache. The table
    /// that joins a RAR set may take up to `--max-object-bytes` bytes.
    fn open(&self, path: &Path, opener: Opener) -> io::Result<Box<dyn ByteSource>> {
        let layout = parts(path, &self.volumes)?;
        // Each of `of` files that are open together, behind its cache.
        let cached = |p: &Path, of: usize| -> io::Result<Box<dyn ByteSource>> {
            let (block, share) = cache_sizes(of, self.cache_bytes, self.cache_block);
            Ok(Box::new(BlockCache::with_sizes(opener(p)?, block, share)?))
        };
        match layout {
            Layout::One(p) => {
                let mut file = opener(&p)?;
                let len = file.seek(SeekFrom::End(0))?;
                file.seek(SeekFrom::Start(0))?;
                let cache = cache_sizes(1, self.cache_bytes, self.cache_block);
                // Held only if the cache could hold it and `--max-object-bytes`
                // allows it: a format read whole checks its size against that
                // limit only for a source that is not in memory.
                let hold = self.cache_bytes.min(self.limits.max_buffer_bytes);
                open_source(file, len, hold, cache)
            }
            Layout::Bytes(files) => self.bytes_of(&files, &cached),
            Layout::Volumes(files) => {
                // A name is a label; the planner never opens one.
                let mut labelled: Vec<(String, &Path)> = Vec::new();
                for p in &files {
                    let label = p.file_name().map_or_else(
                        || p.display().to_string(),
                        |n| n.to_string_lossy().into_owned(),
                    );
                    if labelled.iter().any(|(l, _)| *l == label) {
                        return Err(io::Error::other(format!(
                            "two parts of the archive are both called {label}"
                        )));
                    }
                    labelled.push((label, p));
                }
                let names: Vec<String> = labelled.iter().map(|(l, _)| l.clone()).collect();
                let mut open = |label: &str, of: usize| -> io::Result<Box<dyn ByteSource>> {
                    let (_, p) = labelled
                        .iter()
                        .find(|(l, _)| l == label)
                        .ok_or_else(|| io::Error::other(format!("no part called {label}")))?;
                    cached(p, of)
                };
                let mut found = Parts::Files(&mut open);
                let mut sets = plan(&names, &mut found);
                // Parts named as no set of volumes: a RAR volume by its first
                // bytes, else a file cut into pieces.
                if sets.is_empty() {
                    let mut head = [0u8; 4];
                    let rar = File::open(path)
                        .and_then(|mut f| f.read_exact(&mut head))
                        .is_ok()
                        && &head == b"Rar!";
                    if !rar {
                        return self.bytes_of(&files, &cached);
                    }
                    sets.push(SetPlan {
                        name: names[0].clone(),
                        kind: SetKind::Rar,
                        parts: names.clone(),
                        broken: None,
                    });
                }
                let first = &names[0];
                let set = sets
                    .iter()
                    .find(|s| s.parts.contains(first))
                    .unwrap_or(&sets[0]);
                let table = usize::try_from(self.limits.max_buffer_bytes).unwrap_or(usize::MAX);
                join(set, &mut found, table, &mut 0).map_err(io::Error::other)
            }
        }
    }

    /// The parts of a file that was cut into pieces, end to end.
    fn bytes_of(&self, files: &[PathBuf], cached: Cached) -> io::Result<Box<dyn ByteSource>> {
        let parts = files
            .iter()
            .map(|p| cached(p, files.len()))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Box::new(ByteSpan::new(parts).map_err(io::Error::other)?))
    }
}

/// How a member is called.
struct Label<'a> {
    /// What the patterns of the command line are matched against: the name the
    /// archive wrote, and for a member of an archive in the archive (`-r`) the
    /// names down to it, joined by `!`.
    raw: Cow<'a, str>,
    /// What is printed: `raw` with the characters that end a line, move the
    /// cursor or reorder text replaced, and each name cut at a length.
    shown: Cow<'a, str>,
    /// Where it goes under the extraction directory: the names joined by `/`.
    rel: Cow<'a, str>,
}

impl<'a> Label<'a> {
    /// A member of the archive itself.
    fn stored(name: &'a str) -> Self {
        Label {
            raw: Cow::Borrowed(name),
            shown: Name::stored(name).shown(),
            rel: Cow::Borrowed(name),
        }
    }

    /// The node at `path`, below the archive: the names after the first.
    fn nested(path: &Located<'_>) -> Label<'static> {
        let segments = path.segments();
        let names = segments.get(1..).unwrap_or_default();
        let join = |of: &dyn Fn(&Name<'_>) -> String, with: &str| {
            names.iter().map(of).collect::<Vec<_>>().join(with)
        };
        Label {
            raw: Cow::Owned(join(&|n| n.raw.to_string(), "!")),
            shown: Cow::Owned(join(&|n| n.shown().into_owned(), "!")),
            rel: Cow::Owned(join(&|n| n.raw.to_string(), "/")),
        }
    }
}

/// A member, and what is known of it besides its bytes.
struct Item<'a> {
    label: Label<'a>,
    meta: &'a MemberMeta,
    /// Why the bytes are not all there, when the walk knew before it handed
    /// them over.
    failed: Option<String>,
}

/// A source read as a stream.
struct Windows<'a> {
    src: &'a dyn ByteSource,
    at: usize,
}

impl Read for Windows<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = buf.len().min(self.src.len().saturating_sub(self.at));
        if want == 0 {
            return Ok(0);
        }
        let got = self.src.window(self.at, want);
        if got.is_empty() {
            return Err(io::Error::other(
                self.src
                    .read_error()
                    .unwrap_or_else(|| "the source gave nothing".to_string()),
            ));
        }
        buf[..got.len()].copy_from_slice(&got);
        self.at += got.len();
        Ok(got.len())
    }
}

/// The walk of `-r`: each node below the archive that is not an archive, or is
/// one that gave no member, is handled as a member of a single archive is.
struct Nested<'a, 'o> {
    archive: &'a mut Archive<'o>,
    root: &'a Path,
}

impl Nested<'_, '_> {
    /// Handle `node` as a member. The walk stops with what ends the run.
    fn emit(&mut self, node: &Node<'_>) -> Flow<String> {
        self.emit_as(node, Label::nested(&node.path))
    }

    /// [`Self::emit`] under `label`.
    fn emit_as(&mut self, node: &Node<'_>, label: Label<'_>) -> Flow<String> {
        if let Some(why) = node.capped {
            self.archive.fail(&label.shown, why);
            return Flow::Leaf;
        }
        let made;
        let meta = match node.meta {
            Some(meta) => meta,
            None => {
                made = MemberMeta {
                    name: node.path.name().raw.to_string(),
                    comp_size: node.size,
                    size: Some(node.size),
                    ..MemberMeta::default()
                };
                &made
            }
        };
        let failed = match &node.end {
            End::Complete => None,
            End::Cut(e) | End::Damaged(e) => Some(e.clone()),
        };
        let item = Item {
            label,
            meta,
            failed,
        };
        let mut windows;
        let mut chain;
        let content = match &node.content {
            Content::None => None,
            Content::Source(src) => {
                windows = Windows { src: *src, at: 0 };
                Some(Member::Stream(&mut windows))
            }
            Content::Stream(cell) => match cell.take() {
                Some(taken) => {
                    chain = taken;
                    Some(Member::Stream(&mut chain))
                }
                None => None,
            },
        };
        match self.archive.member(self.root, &item, content) {
            Ok(()) => Flow::Leaf,
            Err(fatal) => Flow::Stop(fatal),
        }
    }
}

impl Visitor<String> for Nested<'_, '_> {
    fn visit(&mut self, node: &Node<'_>, cx: &mut Cx<'_>, _: &mut Reasons) -> Flow<String> {
        if node.origin == Origin::Root {
            // A depth of 0 opens no archive, this one included: it is the
            // one file, under its own name.
            if cx.budget().limits().max_recursion > 0 {
                return Flow::Descend;
            }
            let path = self.archive.path;
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            return self.emit_as(node, Label::stored(&name));
        }
        match node.format() {
            Typed::Container(_) if node.source().is_some() && node.capped.is_none() => {
                match cx.depth_hit(node.depth) {
                    None => return Flow::Descend,
                    // Not opened: it is one more file, and a limit was reached.
                    Some(hit) => {
                        let label = Label::nested(&node.path);
                        self.archive.fail(&label.shown, &hit.reason);
                    }
                }
            }
            Typed::Unchecked(why) => {
                let label = Label::nested(&node.path);
                eprintln!("caution: {}: {}", label.shown, shown_text(&why.text));
                self.archive.raise(status::WARNING);
            }
            _ => {}
        }
        self.emit(node)
    }

    /// An archive nothing came out of is one more file.
    fn leave(
        &mut self,
        node: &Node<'_>,
        members: u64,
        _: &mut Cx<'_>,
        _: &mut Reasons,
    ) -> Flow<String> {
        match (node.origin == Origin::Root, members) {
            (false, 0) => self.emit(node),
            _ => Flow::Leaf,
        }
    }

    fn reason(&mut self, at: &Located<'_>, reason: &Reason) {
        match reason.kind {
            // The copy that met it says so.
            ReasonKind::ReadFailed => {}
            ReasonKind::NotChecked => {
                let label = Label::nested(at);
                eprintln!("caution: {}: {}", label.shown, shown_text(&reason.text));
                self.archive.raise(status::WARNING);
            }
            _ => {
                let label = Label::nested(at);
                self.archive.fail(&label.shown, &reason.text);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_match_as_unzip_does() {
        for (p, n, want) in [
            ("*", "a/b/c.txt", true),
            ("*.txt", "dir/x.txt", true),
            ("dir/*", "dir/x/y", true),
            ("?.txt", "a.txt", true),
            ("?.txt", "ab.txt", false),
            ("[ab]*", "bcd", true),
            ("[!ab]*", "bcd", false),
            ("[a-c]x", "bx", true),
            ("[a-c]x", "dx", false),
            ("one.txt", "one.txt", true),
            ("one.txt", "one.txtx", false),
            ("*a*b", "xaxxb", true),
            ("[", "[", true),
        ] {
            assert_eq!(matches(p, n, false), want, "{p} {n}");
        }
        assert!(matches("ONE.TXT", "one.txt", true));
        assert!(!matches("ONE.TXT", "one.txt", false));
    }

    #[test]
    fn a_link_out_of_the_root_escapes() {
        let root = Path::new("/r");
        assert!(!escapes(root, Path::new("/r/a/l"), "../b"));
        assert!(!escapes(root, Path::new("/r/a/l"), "x/../../b"));
        assert!(escapes(root, Path::new("/r/a/l"), "../../b"));
        assert!(escapes(root, Path::new("/r/l"), "../l"));
        assert!(escapes(root, Path::new("/r/l"), "/etc/passwd"));
    }

    /// The options of a run with an environment of no variables.
    fn parsed(args: &[&str]) -> Result<Box<Opts>, String> {
        parsed_in(&[], args)
    }

    /// The options of a run with `vars` in its environment.
    fn parsed_in(vars: &[(&str, &str)], args: &[&str]) -> Result<Box<Opts>, String> {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let env = |name: &str| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        };
        match parse_with(&args, &env)? {
            Parsed::Run(o) => Ok(o),
            _ => Err("not a run".to_string()),
        }
    }

    /// Every limit has its variable, with the values its option takes and the
    /// `off` the scanner's flag of that name takes.
    #[test]
    fn the_limits_are_read_from_the_environment() {
        let get = |vars: &[(&str, &str)]| parsed_in(vars, &["a.zip"]).unwrap();
        let o = get(&[]);
        let (extracted, object, members) = (
            o.limits.max_extracted_bytes,
            o.limits.max_buffer_bytes,
            o.limits.max_members,
        );
        assert_eq!((extracted, object, members), (64 << 30, 1 << 30, 1_000_000));
        assert_eq!(o.limits.max_recursion, Limits::default().max_recursion);
        assert_eq!(
            o.limits.max_compression_ratio,
            Limits::default().max_compression_ratio
        );

        let o = get(&[("EXAV_MAX_EXTRACTED_BYTES", "2M")]);
        assert_eq!(
            (o.limits.max_extracted_bytes, o.limits.max_scanned_bytes),
            (2 << 20, 2 << 20)
        );
        assert_eq!(
            get(&[("EXAV_MAX_OBJECT_BYTES", "3K")])
                .limits
                .max_buffer_bytes,
            3 << 10
        );
        assert_eq!(get(&[("EXAV_MAX_MEMBERS", "7")]).limits.max_members, 7);
        assert_eq!(
            get(&[("EXAV_MAX_COMPRESSION_RATIO", "7")])
                .limits
                .max_compression_ratio,
            7
        );
        assert_eq!(
            get(&[("EXAV_MAX_UNPACK_DEPTH", "3")]).limits.max_recursion,
            3
        );
        let o = get(&[
            ("EXAV_OBJECT_CACHE_BYTES", "4M"),
            ("EXAV_OBJECT_CACHE_BLOCK_BYTES", "64K"),
        ]);
        assert_eq!((o.cache_bytes, o.cache_block), (4 << 20, 64 << 10));
        let o = get(&[
            ("EXAV_SPILL_DIR", "/spill"),
            ("EXAV_MAX_TOTAL_SPILL_BYTES", "5M"),
        ]);
        assert_eq!(o.spill_dir, Some(PathBuf::from("/spill")));
        assert_eq!(o.max_spill, Some(5 << 20));

        // `off`: no limit, where the scanner's flag takes it.
        let o = get(&[
            ("EXAV_MAX_EXTRACTED_BYTES", "off"),
            ("EXAV_MAX_OBJECT_BYTES", "OFF"),
            ("EXAV_MAX_MEMBERS", "off"),
            ("EXAV_MAX_COMPRESSION_RATIO", "off"),
            ("EXAV_OBJECT_CACHE_BYTES", "off"),
            ("EXAV_OBJECT_CACHE_BLOCK_BYTES", "off"),
            ("EXAV_SPILL_DIR", "off"),
            ("EXAV_MAX_TOTAL_SPILL_BYTES", "off"),
        ]);
        assert_eq!(
            (
                o.limits.max_extracted_bytes,
                o.limits.max_scanned_bytes,
                o.limits.max_buffer_bytes,
                o.limits.max_members,
                o.limits.max_compression_ratio
            ),
            (u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX)
        );
        assert_eq!((o.cache_bytes, o.cache_block), (0, 0));
        assert_eq!((o.spill_dir, o.max_spill), (None, None));
        // The depth has none.
        let e = parsed_in(&[("EXAV_MAX_UNPACK_DEPTH", "off")], &["a.zip"]).err();
        assert!(e.is_some_and(|e| e.contains("EXAV_MAX_UNPACK_DEPTH")));

        // A bad value names the variable.
        for (var, bad) in [
            ("EXAV_MAX_EXTRACTED_BYTES", "x"),
            ("EXAV_MAX_OBJECT_BYTES", "1MB"),
            ("EXAV_MAX_MEMBERS", "-1"),
            ("EXAV_MAX_COMPRESSION_RATIO", "-1"),
            ("EXAV_OBJECT_CACHE_BYTES", "big"),
            ("EXAV_OBJECT_CACHE_BLOCK_BYTES", "1.5M"),
            ("EXAV_MAX_TOTAL_SPILL_BYTES", "lots"),
        ] {
            let e = parsed_in(&[(var, bad)], &["a.zip"])
                .err()
                .unwrap_or_default();
            assert!(e.contains(var), "{var}={bad}: {e}");
        }
        // An empty one is a value that is none, as it is for the scanner.
        for var in ["EXAV_MAX_OBJECT_BYTES", "EXAV_MAX_UNPACK_DEPTH"] {
            let e = parsed_in(&[(var, "")], &["a.zip"])
                .err()
                .unwrap_or_default();
            assert!(e.contains(var), "{var}: {e}");
        }
    }

    /// The command line wins over the environment, whichever name it uses.
    #[test]
    fn the_command_line_wins_over_the_environment() {
        let vars = [
            ("EXAV_MAX_EXTRACTED_BYTES", "1K"),
            ("EXAV_MAX_OBJECT_BYTES", "1K"),
            ("EXAV_MAX_MEMBERS", "1"),
            ("EXAV_MAX_COMPRESSION_RATIO", "1"),
            ("EXAV_MAX_UNPACK_DEPTH", "1"),
            ("EXAV_OBJECT_CACHE_BYTES", "1K"),
            ("EXAV_OBJECT_CACHE_BLOCK_BYTES", "1K"),
            ("EXAV_SPILL_DIR", "/env"),
            ("EXAV_MAX_TOTAL_SPILL_BYTES", "1K"),
        ];
        let o = parsed_in(
            &vars,
            &[
                "--max-extracted-bytes=9M",
                "--max-object-bytes",
                "8M",
                "--max-members",
                "70",
                "--max-compression-ratio",
                "300",
                "--max-unpack-depth",
                "5",
                "--object-cache-bytes",
                "6M",
                "--object-cache-block-bytes",
                "64K",
                "--spill-dir",
                "/flag",
                "--max-total-spill-bytes",
                "off",
                "a.zip",
            ],
        )
        .unwrap();
        assert_eq!(o.limits.max_extracted_bytes, 9 << 20);
        assert_eq!(o.limits.max_buffer_bytes, 8 << 20);
        assert_eq!(o.limits.max_members, 70);
        assert_eq!(o.limits.max_compression_ratio, 300);
        assert_eq!(o.limits.max_recursion, 5);
        assert_eq!((o.cache_bytes, o.cache_block), (6 << 20, 64 << 10));
        assert_eq!(o.spill_dir, Some(PathBuf::from("/flag")));
        assert_eq!(o.max_spill, None);
        // The older names are options too: they win as the new ones do.
        let o = parsed_in(&vars, &["--max-size", "9M", "--max-memory", "8M", "a.zip"]).unwrap();
        assert_eq!(o.limits.max_extracted_bytes, 9 << 20);
        assert_eq!(o.limits.max_buffer_bytes, 8 << 20);
        // An option that is bad is refused whatever the variable says.
        assert!(parsed_in(&vars, &["--max-object-bytes", "x", "a.zip"]).is_err());
        // The spill defaults are exav-grep's.
        let o = parsed(&["a.zip"]).unwrap();
        assert_eq!(o.spill_dir, Some(std::env::temp_dir()));
        assert_eq!(o.max_spill, Some(2 << 30));
        let o = parsed(&[
            "--spill-dir",
            "off",
            "--max-total-spill-bytes",
            "0",
            "a.zip",
        ])
        .unwrap();
        assert_eq!((o.spill_dir, o.max_spill), (None, None));
    }

    /// `0` is no limit, as `off` is, for every limit that takes `off`.
    #[test]
    fn zero_is_no_limit() {
        let o = parsed(&[
            "--max-extracted-bytes",
            "0",
            "--max-object-bytes",
            "0K",
            "--max-members",
            "0",
            "--max-compression-ratio",
            "0",
            "a.zip",
        ])
        .unwrap();
        let l = &o.limits;
        assert_eq!(
            [
                l.max_extracted_bytes,
                l.max_scanned_bytes,
                l.max_buffer_bytes
            ],
            [u64::MAX; 3]
        );
        assert_eq!([l.max_members, l.max_compression_ratio], [u64::MAX; 2]);
    }

    /// The scanner's names and defaults, and its `off`, which is 0.
    #[test]
    fn the_cache_options_are_read_and_default_to_the_scanners() {
        let o = parsed(&["a.zip"]).unwrap();
        assert_eq!((o.cache_bytes, o.cache_block), (32 << 20, 1 << 20));
        let o = parsed(&[
            "--object-cache-bytes",
            "4M",
            "--object-cache-block-bytes=64K",
            "a.zip",
        ])
        .unwrap();
        assert_eq!((o.cache_bytes, o.cache_block), (4 << 20, 64 << 10));
        for off in ["off", "OFF", "0"] {
            let o = parsed(&[
                "--object-cache-bytes",
                off,
                "--object-cache-block-bytes",
                off,
                "a.zip",
            ])
            .unwrap();
            assert_eq!((o.cache_bytes, o.cache_block), (0, 0), "{off}");
        }
        for flag in ["--object-cache-bytes", "--object-cache-block-bytes"] {
            for bad in ["1MB", "big", "", "-1", "1.5M"] {
                assert!(parsed(&[flag, bad, "a.zip"]).is_err(), "{flag} {bad}");
            }
            let e = parsed(&["a.zip", flag]).err().unwrap_or_default();
            assert!(e.contains("needs a value"), "{flag}: {e}");
        }
        // The limits take it too, as no limit.
        let o = parsed(&["--max-memory", "off", "a.zip"]).unwrap();
        assert_eq!(o.limits.max_buffer_bytes, u64::MAX);
    }

    #[test]
    fn the_parts_of_a_set_share_the_cache() {
        let (block, cap) = (1 << 20, 32 << 20);
        // One file or one source: as it is given.
        assert_eq!(cache_sizes(1, cap, block), (1 << 20, 32 << 20));
        assert_eq!(cache_sizes(0, cap, block), (1 << 20, 32 << 20));
        // A set: a share each, the block the same while two fit a share.
        assert_eq!(cache_sizes(4, cap, block), (1 << 20, 8 << 20));
        // Many parts: two blocks at least in a share, so the block shrinks.
        let (b, share) = cache_sizes(100, cap, block);
        assert_eq!(share, (32 << 20) / 100);
        assert_eq!(b, share / 2);
        // And not below 4 KiB.
        assert_eq!(cache_sizes(100_000, cap, block).0, 4096);
        // `off`: a byte a block, and a cache of nothing for the cache to round
        // up to two blocks.
        assert_eq!(cache_sizes(1, 0, 0), (1, 0));
        assert_eq!(cache_sizes(3, 0, 0), (1, 0));
        // Nothing overflows.
        assert_eq!(cache_sizes(2, u64::MAX, u64::MAX).1, usize::MAX / 2);
    }

    /// A file that keeps the sizes of the reads made of it.
    struct Counting {
        inner: io::Cursor<Vec<u8>>,
        reads: std::rc::Rc<std::cell::RefCell<Vec<usize>>>,
    }

    impl Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.reads.borrow_mut().push(n);
            Ok(n)
        }
    }

    impl Seek for Counting {
        fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
            self.inner.seek(to)
        }
    }

    /// The options reach the cache the archive is read through: what it reads
    /// at a time, and how much of it it keeps.
    #[test]
    fn the_cache_options_size_the_reads_of_the_archive() {
        let dir = std::env::temp_dir().join(format!("exav-unpack-main-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plain.bin");
        let data: Vec<u8> = (0..(1u32 << 20)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let p = path.to_str().unwrap();

        // The sizes of the reads of the file, and the bytes read, when
        // `rounds` passes are made over the blocks of 64 KiB.
        let run = |flags: &[&str], rounds: usize| -> (Vec<usize>, bool, usize) {
            let reads = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let opener = |_: &Path| -> io::Result<Box<dyn ReadSeek>> {
                Ok(Box::new(Counting {
                    inner: io::Cursor::new(data.clone()),
                    reads: std::rc::Rc::clone(&reads),
                }))
            };
            let args: Vec<&str> = flags.iter().copied().chain([p]).collect();
            let src = parsed(&args).unwrap().open(&path, &opener).unwrap();
            // What the open itself read.
            let opened = reads.borrow().iter().sum::<usize>();
            let mut same = true;
            for _ in 0..rounds {
                for k in 0..16 {
                    let w = src.window(k * 65536, 4);
                    same &= w[..] == data[k * 65536..k * 65536 + 4];
                }
            }
            let reads = reads.borrow().clone();
            (reads, same, opened)
        };

        // A file the cache can hold is read whole, when it is opened, and not
        // again whatever is asked of it after.
        let (reads, same, opened) = run(&["--object-cache-block-bytes", "64K"], 3);
        assert!(same);
        assert_eq!(
            (reads.iter().sum::<usize>(), opened),
            (data.len(), data.len())
        );
        // The size of the cache is the most a file read whole may be.
        let (reads, same, opened) = run(&["--object-cache-bytes", "1M"], 3);
        assert!(same);
        assert_eq!(
            (reads.iter().sum::<usize>(), opened),
            (data.len(), data.len())
        );
        // Nor is a file held past `--max-object-bytes`, whatever the cache.
        let (_, same, opened) = run(&["--max-object-bytes", "512K"], 1);
        assert!(same);
        assert!(opened < data.len(), "{opened}");
        // A file longer than the cache is read where it lies, a block at a
        // time, as it is asked for, and the cache of 4 blocks cannot keep the
        // 16 of the passes.
        let one_short = (1 << 20) - 1;
        let long = ["--object-cache-block-bytes", "64K", "--object-cache-bytes"];
        let (reads, same, opened) = run(&[long[0], long[1], long[2], &one_short.to_string()], 1);
        assert!(same);
        assert_eq!(reads, vec![65536; 16]);
        assert!(opened < data.len(), "{opened}");
        let (reads, same, _) = run(&[long[0], long[1], long[2], "256K"], 3);
        assert!(same);
        assert!(reads.len() > 16, "{} reads", reads.len());
        assert!(reads.iter().all(|&n| n <= 65536), "{reads:?}");
        // `off`: a cache of two blocks, so that the passes read again.
        let (reads, same, _) = run(&[long[0], long[1], long[2], "off"], 3);
        assert!(same);
        assert!(reads.len() > 2 * 16, "{} reads", reads.len());
        assert!(reads.iter().all(|&n| n <= 65536 || n == 0), "{reads:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The parts of a set read through one cache between them: three parts of
    /// a RAR set under 12 KiB are read 4 KiB at a time, where one under the
    /// same would read 6 KiB.
    #[test]
    fn the_parts_of_a_set_are_read_through_their_share() {
        let dir = std::env::temp_dir().join(format!("exav-unpack-main-set-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Parts that are RAR volumes by name and by their first bytes, and
        // nothing else: the set is refused, after its parts were read.
        let mut data = b"Rar!\x1a\x07\x00".to_vec();
        data.resize(100_000, 0xAA);
        let names: Vec<PathBuf> = (1..=3)
            .map(|k| dir.join(format!("set.part{k}.rar")))
            .collect();
        for p in &names {
            std::fs::write(p, &data).unwrap();
        }
        let reads = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let opener = |_: &Path| -> io::Result<Box<dyn ReadSeek>> {
            Ok(Box::new(Counting {
                inner: io::Cursor::new(data.clone()),
                reads: std::rc::Rc::clone(&reads),
            }))
        };
        let first = names[0].to_str().unwrap();
        let o = parsed(&["--object-cache-bytes", "12K", first]).unwrap();
        let _ = o.open(&names[0], &opener);
        let reads = reads.borrow().clone();
        assert!(!reads.is_empty());
        assert!(reads.iter().all(|&n| n <= 4096), "{reads:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
