//! `exav-grep` — grep that can see inside archives.
//!
//! Familiar flags, but every ZIP/RAR/7z/tar/ISO/OLE/PDF/email it meets is
//! descended into, recursively, in memory. Matches are reported with the nesting
//! path (`backup.zip!logs.tar!app.log:42:…`) so the output stays greppable.
//!
//! Exit codes follow `grep`, with one addition:
//!   0  matches found
//!   1  no matches
//!   2  a usage/IO error
//!   3  **no matches, but some members could not be read** — the search was
//!      incomplete, so "no matches" does not mean "not present"

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use exav_grep::{Event, Matcher, Options, Searcher};
use exav_unpack::Limits;

#[derive(Parser)]
#[command(
    name = "exav-grep",
    about = "grep that searches inside archives (zip, rar, 7z, tar, iso, OLE, PDF, email — recursively)",
    long_about = None,
    version
)]
struct Cli {
    /// Pattern to search for.
    pattern: String,

    /// Files or directories to search.
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Treat the pattern as a fixed string rather than a regular expression.
    #[arg(short = 'F', long)]
    fixed_strings: bool,

    /// Case-insensitive matching.
    #[arg(short = 'i', long)]
    ignore_case: bool,

    /// Select non-matching lines.
    #[arg(short = 'v', long)]
    invert_match: bool,

    /// Print only a count of matching members.
    #[arg(short = 'c', long)]
    count: bool,

    /// Print only the paths of members with matches.
    #[arg(short = 'l', long)]
    files_with_matches: bool,

    /// Recurse into directories.
    #[arg(short = 'r', long)]
    recursive: bool,

    /// Lines of context after each match.
    #[arg(short = 'A', long, value_name = "N", default_value_t = 0)]
    after_context: usize,

    /// Lines of context before each match.
    #[arg(short = 'B', long, value_name = "N", default_value_t = 0)]
    before_context: usize,

    /// Lines of context around each match.
    #[arg(short = 'C', long, value_name = "N")]
    context: Option<usize>,

    /// Stop after N matches per member.
    #[arg(short = 'm', long, value_name = "N", default_value_t = 0)]
    max_count: usize,

    /// Password to try on encrypted members (repeatable).
    #[arg(long = "passwords", value_name = "PASSWORD")]
    passwords: Vec<String>,

    /// Max bytes any single member may decompress to.
    #[arg(long = "max-object-bytes", value_name = "BYTES")]
    max_object_bytes: Option<u64>,

    /// Max members to visit inside each input file. The budget is per file, not
    /// a total across the tree — a directory of N archives may yield N times
    /// this many members.
    #[arg(long = "max-members", value_name = "N")]
    max_members: Option<u64>,

    /// Max nesting depth of archives within archives.
    #[arg(long = "max-depth", value_name = "N")]
    max_depth: Option<u32>,

    /// Don't report members that could not be read. Off by default, because
    /// hiding them turns "I couldn't look" into an indistinguishable "no match".
    #[arg(long)]
    quiet_unreadable: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let matcher = match if cli.fixed_strings {
        Matcher::fixed(&cli.pattern, cli.ignore_case)
    } else {
        Matcher::regex(&cli.pattern, cli.ignore_case)
    } {
        Ok(m) => m.inverted(cli.invert_match),
        Err(e) => {
            eprintln!("exav-grep: bad pattern: {e}");
            return ExitCode::from(2);
        }
    };

    let mut limits = Limits::default();
    if let Some(b) = cli.max_object_bytes {
        limits.max_buffer_bytes = b;
    }
    if let Some(n) = cli.max_members {
        limits.max_members = n;
    }
    if let Some(d) = cli.max_depth {
        limits.max_recursion = d;
    }

    let ctx = cli.context.unwrap_or(0);
    let opts = Options {
        limits,
        passwords: cli.passwords.clone(),
        before_context: cli.before_context.max(ctx),
        after_context: cli.after_context.max(ctx),
        max_count: cli.max_count,
        binary_as_matches: true,
    };

    let mut searcher = Searcher::new(matcher, opts);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut seen_paths: Vec<String> = Vec::new();
    let mut io_error = false;
    // Set when a result could not be written. Kept apart from a scan error so
    // the summary below is still attempted, but it reaches the exit code the
    // same way: output that did not arrive is not a clean run.
    let mut write_failed = false;
    // Paths the filesystem walk could not reach. Counted like an unreadable
    // member, because it is the same fact one level up: a subtree nobody could
    // open is not a subtree with nothing in it, and exit 1 would say it was.
    let mut walk_unreadable = 0u64;

    for p in &cli.paths {
        let files: Vec<PathBuf> = if p.is_dir() {
            if !cli.recursive {
                eprintln!("exav-grep: {}: is a directory (use -r)", p.display());
                io_error = true;
                continue;
            }
            let mut files = Vec::new();
            for entry in walkdir::WalkDir::new(p) {
                match entry {
                    Ok(e) if e.file_type().is_file() => files.push(e.into_path()),
                    Ok(_) => {}
                    Err(e) => {
                        walk_unreadable += 1;
                        if !cli.quiet_unreadable {
                            let at = e
                                .path()
                                .map(|q| q.display().to_string())
                                .unwrap_or_else(|| p.display().to_string());
                            eprintln!("exav-grep: {at}: unreadable: {e}");
                        }
                    }
                }
            }
            files
        } else {
            vec![p.clone()]
        };

        for f in files {
            let r = searcher.search_path(&f, &mut |ev| {
                let line = match &ev {
                    Event::Unreadable { .. } => {
                        if !cli.quiet_unreadable {
                            eprintln!("{ev}");
                        }
                        return true;
                    }
                    Event::Match { path, .. } | Event::BinaryMatch { path } => {
                        if cli.files_with_matches || cli.count {
                            if !seen_paths.iter().any(|s| s == path) {
                                seen_paths.push(path.clone());
                            }
                            return true;
                        }
                        ev.to_string()
                    }
                    Event::Context { .. } => {
                        if cli.files_with_matches || cli.count {
                            return true;
                        }
                        ev.to_string()
                    }
                };
                // A failed write is not "stop quietly": a closed pipe or a full
                // disk means results the caller asked for did not arrive, and
                // exiting 0 with truncated output says they did.
                match writeln!(out, "{line}") {
                    Ok(()) => true,
                    Err(_) => {
                        write_failed = true;
                        false
                    }
                }
            });
            match r {
                // The sink asked to stop — a closed pipe, or `--max-count`
                // satisfied. Carrying on writes into a pipe nobody is reading
                // for the rest of the tree.
                Ok(false) => break,
                Ok(true) => {}
                Err(e) => {
                    eprintln!("exav-grep: {}: {e}", f.display());
                    io_error = true;
                }
            }
        }
    }

    // These are the whole answer under `-l`/`-c`, so a write that fails here
    // loses everything the run found. Silently discarding the error left the
    // process exiting 0 having printed nothing.
    if cli.files_with_matches {
        for p in &seen_paths {
            if writeln!(out, "{p}").is_err() {
                write_failed = true;
                break;
            }
        }
    } else if cli.count && writeln!(out, "{}", seen_paths.len()).is_err() {
        write_failed = true;
    }

    if write_failed {
        eprintln!("exav-grep: could not write results");
        return ExitCode::from(2);
    }
    if io_error {
        return ExitCode::from(2);
    }
    if searcher.matched_count() > 0 {
        ExitCode::SUCCESS
    } else if searcher.unreadable_count() > 0 || walk_unreadable > 0 {
        // Distinct from "no matches": part of the input was never examined, so
        // the caller must not read this as "not present".
        ExitCode::from(3)
    } else {
        ExitCode::from(1)
    }
}
