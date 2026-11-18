//! `exav-grep`: grep that can see inside archives.
//!
//! Familiar flags, but every ZIP/RAR/7z/tar/ISO/OLE/PDF/email it meets is
//! descended into, recursively, in bounded memory. Matches are reported with the nesting
//! path (`backup.zip!logs.tar!app.log:42:…`) so the output stays greppable.
//!
//! Exit codes follow `grep`, with one addition:
//!   0  matches found
//!   1  no matches
//!   2  a usage/IO error
//!   3  **no matches, but some members could not be read**: the search was
//!      incomplete, so "no matches" does not mean "not present"

#![forbid(unsafe_code)]

mod cli;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use exav_grep::{Event, Matcher, Searcher};

#[derive(Parser)]
#[command(
    name = "exav-grep",
    about = "grep that searches inside archives, recursively (zip, rar, 7z, tar, iso, OLE, PDF, email)",
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

    #[command(flatten)]
    read: cli::ReadArgs,

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

    /// Max members to visit inside each input file; `off` or `0` sets no limit. The
    /// budget is per file, not a total across the tree: a directory of N
    /// archives may yield N times this many members.
    #[arg(
        long = "max-members",
        env = "EXAV_MAX_MEMBERS",
        value_name = "N|off",
        value_parser = count_or_off
    )]
    max_members: Option<u64>,

    /// Leave out a member that decodes to more than N times its size, once it
    /// is past --max-object-bytes; the other members are still searched and the
    /// file is reported as not fully read. `off` or `0` sets no limit.
    #[arg(
        long = "max-compression-ratio",
        env = "EXAV_MAX_COMPRESSION_RATIO",
        value_name = "N|off",
        value_parser = count_or_off
    )]
    max_compression_ratio: Option<u64>,

    /// Don't report members that could not be read. Off by default, because
    /// hiding them turns "I couldn't look" into an indistinguishable "no match".
    #[arg(long)]
    quiet_unreadable: bool,

    /// Search the text a reader sees rather than the bytes, for the files that
    /// have one: Markdown, HTML, Office and OpenDocument XML parts, PDF and
    /// drawings (DXF, DWG). Entities are decoded and each link is followed by
    /// where it goes; matches are reported under `file.md!text`, with the
    /// text's line numbers.
    #[cfg(feature = "text")]
    #[arg(long)]
    text: bool,

    /// Search the payloads of the QR codes in images as well as their bytes,
    /// one to a line, under `image.png!qr`.
    #[cfg(feature = "qr")]
    #[arg(long)]
    qr: bool,

    #[command(flatten)]
    qr_limits: cli::QrArgs,
}

/// A count given as a number or `off`; `off` and `0` are no limit, as in exav.
fn count_or_off(v: &str) -> Result<u64, String> {
    match v.trim() {
        n if n.eq_ignore_ascii_case("off") => Ok(u64::MAX),
        n => match n.parse() {
            Ok(0) => Ok(u64::MAX),
            Ok(n) => Ok(n),
            Err(_) => Err(format!("expected a number or `off`, got `{n}`")),
        },
    }
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

    let mut opts = match cli.read.options() {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("exav-grep: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = cli.qr_limits.apply(&mut opts) {
        eprintln!("exav-grep: {e}");
        return ExitCode::from(2);
    }
    if let Some(n) = cli.max_members {
        opts.limits.max_members = n;
    }
    if let Some(n) = cli.max_compression_ratio {
        opts.limits.max_compression_ratio = n;
    }
    let ctx = cli.context.unwrap_or(0);
    opts.passwords = cli.passwords.clone();
    opts.before_context = cli.before_context.max(ctx);
    opts.after_context = cli.after_context.max(ctx);
    opts.max_count = cli.max_count;
    opts.binary_as_matches = true;
    #[cfg(feature = "text")]
    {
        opts.text = cli.text;
    }
    #[cfg(feature = "qr")]
    {
        opts.qr = cli.qr;
    }

    let mut searcher = Searcher::new(matcher, opts);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut seen_paths: Vec<String> = Vec::new();
    // Set when a result could not be written. Kept apart from a scan error so
    // the summary below is still attempted, but it reaches the exit code the
    // same way: output that did not arrive is not a clean run.
    let mut write_failed = false;

    let walked = cli::each_file(
        "exav-grep",
        &cli.paths,
        cli.read.recursive,
        cli.quiet_unreadable,
        |f| {
            searcher.search_path(f, &mut |ev| {
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
                    // `Event` is non-exhaustive: a result kind added later
                    // renders through its `Display`, like the line kinds do.
                    _ => ev.to_string(),
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
            })
        },
    );

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

    cli::exit_code(
        "exav-grep",
        &walked,
        write_failed,
        searcher.matched_count(),
        searcher.unreadable_count(),
    )
}
