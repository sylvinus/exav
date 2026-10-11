#![no_main]
//! The clamd protocol the daemon speaks to anyone who can reach its socket:
//! command lines (newline or NUL terminated, or the legacy form that is not),
//! `IDSESSION`, and the `INSTREAM`, `EXINSTREAM` and `EXINSTREAM MULTI` chunk
//! framings, over memory in place of a socket (`exav::fuzzing::clamd`).
//!
//! The input is a list of commands (`arbitrary`), written out as the protocol
//! writes them, with the mistakes a client makes: a chunk that declares more or
//! fewer bytes than it carries, a stream with no terminator, a line that is not
//! a command at all. The paths a command could name are refused in this build
//! (`daemon::dispatch`), so what is left is the framing, the session loop and
//! the scan of what a stream carries.
//!
//! One check beyond "does not panic": a single, well-formed `INSTREAM` or
//! `EXINSTREAM` of some bytes answers what `analyze` says of the same bytes, in
//! the protocol's words (`OK`, `FOUND`, `ERROR` for a verdict that is partial):
//! the daemon and the library are one scanner (`tests/suites/one_scan.rs`).
use arbitrary::Arbitrary;
use exav_core::{analyze, ScanOptions, VerdictCategory};
use libfuzzer_sys::fuzz_target;

#[path = "../db.rs"]
mod db;

#[derive(Arbitrary, Debug)]
enum Lie {
    /// Declares what it carries.
    Honest,
    /// Declares this many bytes fewer.
    Under(u16),
    /// Declares this many bytes more.
    Over(u32),
}

#[derive(Arbitrary, Debug)]
struct Chunk {
    lie: Lie,
    data: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Stream {
    chunks: Vec<Chunk>,
    /// Ends without the zero chunk.
    unterminated: bool,
}

impl Stream {
    fn write(&self, out: &mut Vec<u8>) {
        for c in &self.chunks {
            let len = c.data.len() as u32;
            let declared = match c.lie {
                Lie::Honest => len,
                Lie::Under(n) => len.saturating_sub(n as u32),
                Lie::Over(n) => len.saturating_add(n),
            };
            // A zero chunk is the end of the stream, so an empty honest one is
            // written as the terminator it is.
            out.extend_from_slice(&declared.to_be_bytes());
            out.extend_from_slice(&c.data);
        }
        if !self.unterminated {
            out.extend_from_slice(&0u32.to_be_bytes());
        }
    }

    /// The bytes a well-formed stream carries, or `None` if any chunk lies, is
    /// empty (an empty chunk ends it) or the end is missing.
    fn honest(&self) -> Option<Vec<u8>> {
        if self.unterminated
            || self
                .chunks
                .iter()
                .any(|c| !matches!(c.lie, Lie::Honest) || c.data.is_empty())
        {
            return None;
        }
        Some(self.chunks.iter().flat_map(|c| c.data.iter().copied()).collect())
    }
}

#[derive(Arbitrary, Debug)]
enum Command {
    Ping,
    Version,
    Stats,
    Commands,
    Instream(Stream),
    ExInstream(Stream),
    /// `(label, stream)` per file, and the zero-length name that ends them.
    ExMulti(Vec<(Vec<u8>, Stream)>, bool),
    /// A line of anything.
    Line(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum Session {
    None,
    Legacy,
    Ids,
}

#[derive(Arbitrary, Debug)]
struct Connection {
    session: Session,
    commands: Vec<Command>,
    /// Closes a session with `END`.
    end: bool,
    /// NUL-terminated lines in place of newline-terminated.
    nul: bool,
}

fn line(out: &mut Vec<u8>, nul: bool, text: &[u8]) {
    out.push(if nul { b'z' } else { b'n' });
    out.extend_from_slice(text);
    out.push(if nul { 0 } else { b'\n' });
}

fn render(c: &Connection) -> Vec<u8> {
    let mut out = Vec::new();
    match c.session {
        Session::None => {}
        Session::Legacy => line(&mut out, c.nul, b"SESSION"),
        Session::Ids => line(&mut out, c.nul, b"IDSESSION"),
    }
    for command in &c.commands {
        match command {
            Command::Ping => line(&mut out, c.nul, b"PING"),
            Command::Version => line(&mut out, c.nul, b"VERSION"),
            Command::Stats => line(&mut out, c.nul, b"STATS"),
            Command::Commands => line(&mut out, c.nul, b"VERSIONCOMMANDS"),
            Command::Instream(s) => {
                line(&mut out, c.nul, b"INSTREAM");
                s.write(&mut out);
            }
            Command::ExInstream(s) => {
                line(&mut out, c.nul, b"EXINSTREAM");
                s.write(&mut out);
            }
            Command::ExMulti(files, terminated) => {
                line(&mut out, c.nul, b"EXINSTREAM MULTI");
                for (name, stream) in files {
                    out.extend_from_slice(&(name.len() as u32).to_be_bytes());
                    out.extend_from_slice(name);
                    stream.write(&mut out);
                }
                if *terminated {
                    out.extend_from_slice(&0u32.to_be_bytes());
                }
            }
            Command::Line(text) => line(&mut out, c.nul, text),
        }
    }
    if c.end && !matches!(c.session, Session::None) {
        line(&mut out, c.nul, b"END");
    }
    out
}

fn options() -> ScanOptions {
    let mut o = ScanOptions::default();
    let l = &mut o.limits;
    l.max_recursion = 8;
    l.max_members = 1_000;
    l.max_extracted_bytes = 8 << 20;
    l.max_compression_ratio = 200;
    l.max_buffer_bytes = 4 << 20;
    l.max_scanned_bytes = 16 << 20;
    l.max_pe_emulation_steps = 2_000_000;
    o
}

/// The protocol's word for a verdict's category.
fn status(category: VerdictCategory) -> &'static str {
    match category {
        VerdictCategory::Clean => "OK",
        VerdictCategory::Infected => "FOUND",
        VerdictCategory::Partial => "ERROR",
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(connection) = Connection::arbitrary(&mut arbitrary::Unstructured::new(data)) else {
        return;
    };
    let opts = options();
    let input = render(&connection);
    let out = exav_cli::fuzzing::clamd(&input, db::scanner(), &opts);

    // A single stream, sent plainly: the daemon's answer is the library's.
    if let ([Command::Instream(s) | Command::ExInstream(s)], Session::None) =
        (connection.commands.as_slice(), &connection.session)
    {
        if let Some(bytes) = s.honest() {
            let want = status(analyze(db::scanner(), &bytes, &opts).verdict.category());
            let reply = String::from_utf8_lossy(&out);
            let reply = reply.trim_end_matches(['\n', '\0']);
            let got = if matches!(connection.commands[0], Command::Instream(_)) {
                reply.rsplit(' ').next().unwrap_or("")
            } else {
                // `{"v":1,"status":"OK"}`: the field's value.
                reply
                    .split("\"status\":\"")
                    .nth(1)
                    .and_then(|s| s.split('"').next())
                    .unwrap_or("")
            };
            // The JSON says PARTIAL where the line says ERROR.
            let got = if got == "PARTIAL" { "ERROR" } else { got };
            assert_eq!(got, want, "the daemon said {reply:?} of bytes analyze calls {want}");
        }
    }
});
