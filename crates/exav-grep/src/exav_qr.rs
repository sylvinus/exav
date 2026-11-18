//! `exav-qr`: the payloads of the QR codes in images, and in what holds them.
//!
//! Every archive, document and disk image it meets is opened, as `exav-grep`
//! does, and the codes of the images in it (and of the raw images of a PDF)
//! are printed one to a line, `path!to!image.png:1:payload`, the number being
//! that of the code among those read in the image. Control characters in a
//! payload are written as escapes, so a payload never adds a line or a
//! terminal escape sequence to the output.
//!
//! Exit codes are `exav-grep`'s:
//!   0  a code was found
//!   1  none was found
//!   2  a usage/IO error
//!   3  **none was found, but something could not be read**: an image that
//!      does not decode, a limit that was reached, a member that could not be
//!      opened. Said on stderr; "none" is then only about what was read.

#![forbid(unsafe_code)]

mod cli;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use exav_grep::{Event, Searcher};

#[derive(Parser)]
#[command(
    name = "exav-qr",
    about = "print the payloads of the QR codes in images, and inside archives, documents and PDFs",
    long_about = None,
    version
)]
struct Cli {
    /// Files or directories to read.
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    #[command(flatten)]
    read: cli::ReadArgs,

    #[command(flatten)]
    qr_limits: cli::QrArgs,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let mut opts = match cli.read.options() {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("exav-qr: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = cli.qr_limits.apply(&mut opts) {
        eprintln!("exav-qr: {e}");
        return ExitCode::from(2);
    }

    let mut searcher = Searcher::qr_codes(opts);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut write_failed = false;

    let walked = cli::each_file("exav-qr", &cli.paths, cli.read.recursive, false, |f| {
        searcher.search_path(f, &mut |ev| match ev {
            // What was not read is said, never skipped: "no code" would
            // otherwise also mean "not looked at".
            Event::Unreadable { path, reason } => {
                eprintln!("exav-qr: {path}: could not read ({reason})");
                true
            }
            ev => match writeln!(out, "{ev}") {
                Ok(()) => true,
                Err(_) => {
                    write_failed = true;
                    false
                }
            },
        })
    });

    cli::exit_code(
        "exav-qr",
        &walked,
        write_failed,
        searcher.matched_count(),
        searcher.unreadable_count(),
    )
}
