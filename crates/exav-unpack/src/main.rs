//! `exav-unpack`: extract, list and test archives, with `unzip`'s command line.
//!
//! The command line is a subset of Info-ZIP `unzip` 6.00's: every option it
//! takes means what it means to `unzip`, and an `unzip` option it does not take
//! is refused (exit 10) rather than ignored. It adds long options only
//! (`--volume`, the `--max-*` limits, `--help`, `--version`), and reads every
//! archive format the `exav-unpack` library reads, not only ZIP.
//!
//! Where it differs from `unzip` on purpose:
//! - no password prompt (not implemented yet): an encrypted member with no
//!   `-P` is skipped, as `unzip` does with no terminal, after the library's
//!   built-in passwords;
//! - a symbolic link whose target leaves the extraction directory is not made;
//! - every member is `extracting:`, whatever its compression;
//! - a split archive is read from any of its parts.
//!
//! The archive is read from disk as it is needed and each member written as
//! it is decoded: neither is held in memory whole, except where a format's
//! decoder needs it.

#![forbid(unsafe_code)]

use chrono::{Local, LocalResult, TimeZone};
use exav_unpack::source::BlockCache;
use exav_unpack::{detect, walk, Budget, ByteSource, Format, Limits, Member, MemberMeta, Mtime};
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
  --volume FILE      another part of a split archive (repeat for each part)
  --max-size SIZE    stop past SIZE decoded bytes in all (default 64G)
  --max-memory SIZE  largest member or container held in memory whole (1G)
  --max-members N    stop past N members (default 1000000)
  --help, --version
SIZE takes a K, M, G or T suffix (powers of 1024).";

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
    limits: Limits,
}

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
    if args.is_empty() {
        return Ok(Parsed::Usage(status::OK));
    }
    // An extractor writes to disk rather than holding what it decodes, so its
    // totals can be far above the scanner's. The compression-ratio cap still
    // stops a bomb long before them.
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
        limits,
    };
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
                "max-size" => {
                    let n = size(&value(&mut i)?)?;
                    o.limits.max_extracted_bytes = n;
                    o.limits.max_scanned_bytes = n;
                }
                "max-memory" => o.limits.max_buffer_bytes = size(&value(&mut i)?)?,
                "max-members" => {
                    o.limits.max_members = value(&mut i)?
                        .parse()
                        .map_err(|_| format!("{a} takes a number"))?
                }
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
                'l' => modes.push(Mode::List),
                't' => modes.push(Mode::Test),
                'p' => modes.push(Mode::Pipe),
                'c' => modes.push(Mode::Show),
                'v' => verbose = true,
                'o' => o.overwrite = Some(true),
                'n' => o.overwrite = Some(false),
                'q' => o.quiet += 1,
                'j' => o.junk = true,
                'C' => o.nocase = true,
                'D' => o.no_times += 1,
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
                    })
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
        let src = match open(self.path, &o.volumes, o.limits.max_buffer_bytes) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("exav-unpack:  cannot read {}: {e}", self.path.display());
                return status::NO_ARCHIVE;
            }
        };
        let Some(fmt) = detect(&*src).or_else(|| packed(&*src, o.limits.max_buffer_bytes)) else {
            eprintln!(
                "exav-unpack:  {} is not an archive exav-unpack reads.",
                self.path.display()
            );
            return status::NO_ARCHIVE;
        };
        if o.mode == Mode::List && o.quiet < 2 {
            println!("  Length      Date    Time    Name");
            println!("---------  ---------- -----   ----");
        }
        let root = o.dir.clone().unwrap_or_else(|| PathBuf::from("."));
        if o.mode == Mode::Extract {
            if let Err(e) = fs::create_dir_all(&root) {
                eprintln!("exav-unpack:  cannot create {}: {e}", root.display());
                return status::ERROR;
            }
        }
        let mut budget = Budget::with_passwords(o.limits.clone(), o.passwords.clone());
        budget.set_visit_directories(true);
        let stopped = walk(fmt, &*src, &mut budget, &mut |meta, content, _| {
            self.member(&root, meta, content).err()
        });
        match stopped {
            Ok(None) => {}
            Ok(Some(fatal)) => {
                eprintln!("exav-unpack:  {fatal}");
                self.raise(status::DISK_FULL);
            }
            Err(hit) => {
                eprintln!("  error:  {hit}");
                self.raise(status::ERROR);
            }
        }
        self.finish(&root, messages);
        self.status
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
        meta: &MemberMeta,
        content: Option<Member<'_>>,
    ) -> Result<(), String> {
        let o = self.o;
        let name = meta.name.as_str();
        if !self.wanted(name) {
            return Ok(());
        }
        let kind = meta.mode.map(|m| m & 0o170000);
        let dir = kind == Some(0o040000)
            || ((name.ends_with('/') || name.ends_with('\\')) && meta.size.unwrap_or(0) == 0);
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
                self.bytes += size;
                println!("{size:>9}  {}   {name}", when(meta.mtime));
                return Ok(());
            }
            _ => {}
        }
        if dir {
            match o.mode {
                Mode::Test if messages => println!("    testing: {name:<22}   OK"),
                Mode::Extract if !o.junk => {
                    let Some(path) = target(root, name) else {
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
            let why = meta.unsupported.unwrap_or("no content");
            let unsupported = ["unsupported", "method", "codec"]
                .iter()
                .any(|w| why.contains(w));
            let (why, s) = match (meta.encrypted, o.passwords.is_empty()) {
                (true, true) => ("unable to get password", status::NO_PASSWORD),
                (true, false) => ("incorrect password", status::BAD_PASSWORD),
                _ if unsupported => (why, status::UNSUPPORTED),
                _ => (why, status::ERROR),
            };
            match s {
                // Settled in `finish`, once it is known what else came out.
                status::BAD_PASSWORD => self.bad_password += 1,
                _ => {
                    self.tested_bad = true;
                    self.raise(s);
                }
            }
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
                let damage = got.err().or_else(|| meta.unsupported.map(str::to_string));
                match damage {
                    None => {
                        if messages {
                            println!("    testing: {name:<22}   OK");
                        }
                        self.ok += 1;
                    }
                    Some(e) => {
                        println!("    testing: {name:<22}  ");
                        println!("  error:  {e}");
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
                match got.and_then(|_| meta.unsupported.map_or(Ok(()), |u| Err(u.to_string()))) {
                    Ok(()) => self.ok += 1,
                    Err(e) => {
                        eprintln!("  error:  {e}");
                        self.raise(status::ERROR);
                    }
                }
                Ok(())
            }
            _ => self.extract(root, meta, content, link),
        }
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
        meta: &MemberMeta,
        content: Member<'_>,
        link: bool,
    ) -> Result<(), String> {
        let o = self.o;
        let name = meta.name.as_str();
        let rel = match o.junk {
            true => name.rsplit(['/', '\\']).next().unwrap_or(name),
            false => name,
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
            Ok(()) => meta.unsupported.map(str::to_string),
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
                eprintln!("\n  error:  {e}");
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

/// Make the link at `path` to `target`, if the target stays under `root`.
fn make_link(root: &Path, path: &Path, target: &str) -> Result<(), String> {
    if escapes(root, path, target) {
        return Err("symbolic link points outside the extraction directory".to_string());
    }
    directories(root, path, false)?;
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
                return Err(format!("{} is a link, not followed", at.display()))
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

/// How the parts of a split archive make one.
#[derive(Clone, Copy, PartialEq)]
enum Set {
    /// One file.
    One,
    /// A finished file cut into parts (`x.7z.001`, ...): end to end.
    Bytes,
    /// `x.z01`, ..., `x.zip`: end to end, the directory rebased.
    Zip,
    /// `x.part1.rar`, ... or `x.rar`, `x.r00`, ...: each member's parts joined.
    Rar,
}

fn volume_of(p: &Path) -> Option<exav_unpack::volume::VolumeName> {
    p.file_name()
        .and_then(|n| n.to_str())
        .and_then(exav_unpack::volume::parse)
}

/// The files of the archive at `path`, in order, and how they make one:
/// `volumes` with it when given, else the parts its name says are next to it.
/// Siblings are named from the pattern, never from anything a file holds, and
/// read in order until one is missing: nothing in the naming records how many
/// parts a set has.
fn parts(path: &Path, volumes: &[PathBuf]) -> io::Result<(Vec<PathBuf>, Set)> {
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
        let schemes: Vec<_> = all.iter().map(|p| volume_of(p).map(|v| v.scheme)).collect();
        let kind = if schemes.iter().any(|s| matches!(s, Some(Scheme::ZipSplit))) {
            Set::Zip
        } else if schemes
            .iter()
            .all(|s| matches!(s, Some(Scheme::RarPart { .. } | Scheme::RarOld)))
        {
            Set::Rar
        } else {
            match File::open(path).and_then(|mut f| {
                let mut head = [0u8; 4];
                f.read_exact(&mut head).map(|_| head)
            }) {
                Ok(h) if &h == b"Rar!" => Set::Rar,
                _ => Set::Bytes,
            }
        };
        // In the order of their volume numbers when their names all have
        // them (a ZIP's `.zip` last), else as given.
        let key = |p: &PathBuf| match volume_of(p) {
            Some(v) => Some(v.index),
            None if kind == Set::Zip && is_zip(p) => Some(usize::MAX),
            None => None,
        };
        if all.iter().all(|p| key(p).is_some()) {
            all.sort_by_key(key);
        }
        return Ok((all, kind));
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
                false => Ok((all, Set::Bytes)),
            }
        }
        Some(v) if v.scheme == Scheme::ZipSplit => {
            let last = dir.join(format!("{}.zip", v.stem));
            let mut all = siblings(&v, 0);
            match last.is_file() && !all.is_empty() {
                true => {
                    all.push(last);
                    Ok((all, Set::Zip))
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
                1 => Ok((all, Set::One)),
                _ => Ok((all, Set::Rar)),
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
                    Ok((all, Set::Zip))
                }
                _ => Ok((vec![path.to_path_buf()], Set::One)),
            }
        }
        _ => Ok((vec![path.to_path_buf()], Set::One)),
    }
}

/// The archive at `path`, with the other parts of its set, read from disk as
/// it is needed; a RAR set is joined in memory, up to `max` bytes.
fn open(path: &Path, volumes: &[PathBuf], max: u64) -> io::Result<Box<dyn ByteSource>> {
    let (files, kind) = parts(path, volumes)?;
    let cached = |p: &PathBuf| -> io::Result<Box<dyn ByteSource>> {
        Ok(Box::new(BlockCache::new(File::open(p)?)?))
    };
    match kind {
        Set::One => cached(&files[0]),
        Set::Bytes => {
            let mut parts = Vec::new();
            for p in &files {
                let f = File::open(p)?;
                let len = f.metadata()?.len();
                parts.push((f, len));
            }
            Ok(Box::new(BlockCache::new(Joined::new(parts))?))
        }
        Set::Zip => {
            let parts = files.iter().map(cached).collect::<io::Result<Vec<_>>>()?;
            Ok(Box::new(
                exav_unpack::span::ZipSpan::new(parts).map_err(io::Error::other)?,
            ))
        }
        Set::Rar => {
            let total: u64 = files
                .iter()
                .map(|p| fs::metadata(p).map_or(0, |m| m.len()))
                .sum();
            if total > max {
                return Err(io::Error::other(format!(
                    "a RAR set of {total} bytes is joined in memory, past --max-memory {max}"
                )));
            }
            let data = files.iter().map(fs::read).collect::<io::Result<Vec<_>>>()?;
            let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
            let joined = exav_unpack::join_rar_volumes(&refs).map_err(io::Error::other)?;
            Ok(Box::new(joined))
        }
    }
}

/// The format of a packed executable, which `detect` does not report: read
/// whole, so only up to `max` bytes.
fn packed(src: &dyn ByteSource, max: u64) -> Option<Format> {
    if src.len() as u64 > max {
        return None;
    }
    let data = src.window(0, src.len());
    if exav_unpack::is_upx(&data) {
        Some(Format::Upx)
    } else if exav_unpack::is_pepack(&data) {
        Some(Format::PePacked)
    } else {
        None
    }
}

/// The parts of a byte-split set, read as one file.
struct Joined {
    parts: Vec<(File, u64)>,
    len: u64,
    pos: u64,
}

impl Joined {
    fn new(parts: Vec<(File, u64)>) -> Self {
        let len = parts.iter().map(|p| p.1).sum();
        Joined { parts, len, pos: 0 }
    }
}

impl Read for Joined {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut base = 0;
        for (f, len) in &mut self.parts {
            if self.pos < base + *len {
                let off = self.pos - base;
                f.seek(SeekFrom::Start(off))?;
                let want = buf
                    .len()
                    .min(usize::try_from(*len - off).unwrap_or(usize::MAX));
                let n = f.read(&mut buf[..want])?;
                self.pos += n as u64;
                return Ok(n);
            }
            base += *len;
        }
        Ok(0)
    }
}

impl Seek for Joined {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let new = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = new
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        Ok(self.pos)
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
}
