//! `grep`, but it can see inside archives.
//!
//! Ordinary `grep -r` stops at the container: a ZIP, ISO, 7z or Word document is
//! one opaque binary blob to it. This crate walks *into* containers with
//! [`exav_unpack`], recursively, and searches every member as if it were a file
//! on disk — reporting matches with a path that shows the nesting:
//!
//! ```text
//! backup.zip!logs.tar.gz!logs/app.log:42:  connection from 10.0.0.7
//! ```
//!
//! Everything happens **in memory** — no member is ever written to disk, so the
//! zip-slip / path-traversal / symlink class does not arise. Extraction runs
//! under [`exav_unpack::Budget`], the same decompression-bomb budgets the
//! scanner uses, so a malicious archive cannot turn a search into an unbounded
//! allocation.
//!
//! ## Members that cannot be read are reported
//!
//! A member exav cannot decode — unsupported codec, encryption without a working
//! password, a budget stop — is **not silently omitted from the results**. It is
//! surfaced as a [`Event::Unreadable`], because "no matches" and "I could not
//! look" are different answers and quietly conflating them is how a search tool
//! lies to you. The CLI prints them to stderr and sets a distinct exit code.
//!
//! ```no_run
//! use exav_grep::{Matcher, Searcher, Options};
//! let matcher = Matcher::fixed("password", false)?;
//! let mut searcher = Searcher::new(matcher, Options::default());
//! searcher.search_path(std::path::Path::new("backup.zip"), &mut |ev| {
//!     println!("{ev}");
//!     true
//! })?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![forbid(unsafe_code)]
// This crate's public surface is fully documented. The lint keeps it that way:
// an undocumented public item is a build warning rather than something noticed
// on docs.rs after publishing.
#![warn(missing_docs)]

use std::fmt;
use std::path::Path;

use exav_unpack::{Budget, Entry, Limits};

/// Separator between a container and a member in a reported path, mirroring the
/// convention `7z`/`unzip` tooling uses so the output is greppable in turn.
pub const NESTING_SEP: char = '!';

/// What to search for. Fixed strings are searched literally (no escaping
/// surprises); regex patterns compile on the linear-time `regex` engine, so a
/// pathological pattern cannot hang the search.
pub struct Matcher {
    re: regex::bytes::Regex,
    invert: bool,
}

impl Matcher {
    /// A literal string.
    pub fn fixed(pattern: &str, ignore_case: bool) -> Result<Self, regex::Error> {
        Self::build(&regex::escape(pattern), ignore_case)
    }

    /// A regular expression.
    pub fn regex(pattern: &str, ignore_case: bool) -> Result<Self, regex::Error> {
        Self::build(pattern, ignore_case)
    }

    fn build(pattern: &str, ignore_case: bool) -> Result<Self, regex::Error> {
        Ok(Matcher {
            re: regex::bytes::RegexBuilder::new(pattern)
                .case_insensitive(ignore_case)
                .build()?,
            invert: false,
        })
    }

    /// Select non-matching lines instead (`grep -v`).
    pub fn inverted(mut self, invert: bool) -> Self {
        self.invert = invert;
        self
    }

    fn hits(&self, line: &[u8]) -> bool {
        self.re.is_match(line) != self.invert
    }
}

/// Search behaviour.
#[derive(Clone, Default)]
pub struct Options {
    /// Extraction budgets (bomb guards, recursion depth, file count).
    pub limits: Limits,
    /// Passwords to try on encrypted members, before the built-in defaults.
    pub passwords: Vec<String>,
    /// Lines of context to print before a match.
    pub before_context: usize,
    /// Lines of context to print after a match.
    pub after_context: usize,
    /// Stop after this many matches per member (0 = unlimited).
    pub max_count: usize,
    /// Treat a member as binary and report only that it matched, not the line.
    pub binary_as_matches: bool,
}

/// One result of the search.
#[derive(Debug, Clone)]
pub enum Event {
    /// A matching line.
    Match {
        /// Nesting path, e.g. `a.zip!b.tar!c.txt`.
        path: String,
        /// 1-based line number within the member.
        line_no: usize,
        /// The line itself, without its terminator. Raw bytes: a member is not
        /// required to be UTF-8, and re-encoding it would change what matched.
        line: Vec<u8>,
    },
    /// A context line around a match (`-A`/`-B`), never itself a match.
    Context {
        /// Nesting path of the member the line came from.
        path: String,
        /// 1-based line number within the member.
        line_no: usize,
        /// The line itself, without its terminator.
        line: Vec<u8>,
    },
    /// A member matched but its content is binary, so no line is shown.
    BinaryMatch {
        /// Nesting path of the member that matched.
        path: String,
    },
    /// A member exists but could not be read. **Not** the same as "no matches":
    /// this is content the search did not see.
    Unreadable {
        /// Nesting path of the member that could not be read.
        path: String,
        /// Why it could not be read, in the words of the layer that failed.
        reason: String,
    },
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Match {
                path,
                line_no,
                line,
            } => {
                write!(f, "{path}:{line_no}:{}", String::from_utf8_lossy(line))
            }
            Event::Context {
                path,
                line_no,
                line,
            } => {
                write!(f, "{path}-{line_no}-{}", String::from_utf8_lossy(line))
            }
            Event::BinaryMatch { path } => write!(f, "Binary file {path} matches"),
            Event::Unreadable { path, reason } => {
                write!(f, "exav-grep: {path}: could not read ({reason})")
            }
        }
    }
}

/// Drives the search. `true` from the sink continues, `false` stops early.
pub type Sink<'a> = &'a mut dyn FnMut(Event) -> bool;

/// Searches every member of a container, recursively, feeding an [`Event`] per
/// hit to a [`Sink`].
///
/// Holds the running tallies across a whole search, so one searcher is meant to
/// be reused across the inputs of a single run rather than constructed per file
/// — that is what makes `unreadable` a total the caller can act on rather than
/// a per-file curiosity. A member that could not be read is reported as
/// [`Event::Unreadable`], never skipped silently: content the search did not
/// see is not the same as content with no matches.
pub struct Searcher {
    matcher: Matcher,
    opts: Options,
    /// Members that existed but could not be read, across the whole run.
    unreadable: usize,
    matched: usize,
}

impl Searcher {
    /// Build a searcher from a compiled matcher and the search options.
    pub fn new(matcher: Matcher, opts: Options) -> Self {
        Searcher {
            matcher,
            opts,
            unreadable: 0,
            matched: 0,
        }
    }

    /// How many members existed but could not be read. Non-zero means the search
    /// was incomplete, and "no matches" cannot be trusted as "not present".
    pub fn unreadable_count(&self) -> usize {
        self.unreadable
    }

    /// How many members produced at least one match.
    pub fn matched_count(&self) -> usize {
        self.matched
    }

    /// Search a file on disk, descending into it if it is a container.
    ///
    /// Returns whether the caller wants more results, mirroring
    /// [`Self::search_bytes`]. Dropping that answer means a caller whose output
    /// has gone away — a closed pipe, a full disk — keeps being handed results
    /// for the rest of the walk.
    ///
    /// A file larger than the per-object budget is reported rather than read:
    /// the extraction limits bound what comes OUT of a container, and nothing
    /// bounded what went in, so a sparse file, a disk image or a `/proc`-style
    /// pseudo-file was read whole into memory first. Under a memory cgroup that
    /// is a kill rather than an error, and a killed process reports nothing at
    /// all.
    pub fn search_path(&mut self, path: &Path, sink: Sink) -> std::io::Result<bool> {
        let label = path.display().to_string();
        let meta = std::fs::metadata(path)?;
        if !meta.is_file() {
            self.unreadable += 1;
            return Ok(sink(Event::Unreadable {
                path: label,
                reason: "not a regular file".to_string(),
            }));
        }
        let cap = self.opts.limits.max_buffer_bytes;
        if meta.len() > cap {
            self.unreadable += 1;
            return Ok(sink(Event::Unreadable {
                path: label,
                reason: format!("{} bytes, over the {cap}-byte input cap", meta.len()),
            }));
        }
        let data = std::fs::read(path)?;
        Ok(self.search_bytes(&label, &data, sink))
    }

    /// Search an in-memory buffer under `label`.
    ///
    pub fn search_bytes(&mut self, label: &str, data: &[u8], sink: Sink) -> bool {
        let mut budget = Budget::new(self.opts.limits.clone());
        budget.passwords = self.opts.passwords.clone();
        self.walk(label, data, &mut budget, 0, sink)
    }

    /// Search `data`, then recurse into it if it is a container. Returns `false`
    /// when the sink asked to stop.
    fn walk(
        &mut self,
        label: &str,
        data: &[u8],
        budget: &mut Budget,
        depth: u32,
        sink: Sink,
    ) -> bool {
        // Depth is bounded here, not only by the extraction budget: a member can
        // be a container of the same kind as its parent — a packed executable
        // whose recovered image is itself packed-looking — and each level is a
        // *stack* frame. Without a limit the recursion ends in a stack overflow,
        // which aborts the process rather than reporting anything.
        if depth >= budget.limits().max_recursion {
            self.unreadable += 1;
            return sink(Event::Unreadable {
                path: label.to_string(),
                reason: format!(
                    "nesting deeper than {} levels",
                    budget.limits().max_recursion
                ),
            });
        }
        let Some(fmt) = exav_unpack::detect(data).or_else(|| packed_executable(data)) else {
            // A leaf: search its bytes.
            return self.search_one(label, data, sink);
        };
        // A container is searched through its MEMBERS, not its raw bytes — for a
        // stored member those are the same bytes, and reporting both would
        // duplicate every hit. If extraction yields nothing (a broken or empty
        // container) the raw bytes are searched instead, so a damaged archive
        // still gets looked at rather than silently producing no output.
        let mut members = 0usize;
        let mut keep_going = true;
        let r =
            exav_unpack::extract_each(fmt, data, budget, &mut |entry: Entry, b: &mut Budget| {
                let child = format!("{label}{NESTING_SEP}{}", entry.name);
                // A member exav could not decode is content this search did not see.
                // Saying nothing here would report "no matches" for bytes nobody
                // looked at.
                if let Some(reason) = entry.unsupported {
                    // Counted as a member even though it yielded nothing. The
                    // fallback below exists for a buffer the walker found no
                    // members in at all; a container whose members all failed to
                    // decode HAS members, and line-searching its own compressed
                    // bytes would emit a stream of garbage matches contradicting
                    // the `Unreadable` events just reported for the same file.
                    members += 1;
                    self.unreadable += 1;
                    if !sink(Event::Unreadable {
                        path: child,
                        reason: reason.to_string(),
                    }) {
                        keep_going = false;
                        return Some(());
                    }
                    return None;
                }
                members += 1;
                if !self.walk(&child, &entry.data, b, depth + 1, sink) {
                    keep_going = false;
                    return Some(());
                }
                None
            });
        // A budget stop or a decoder failure means members went unexamined.
        if let Err(e) = r {
            self.unreadable += 1;
            if !sink(Event::Unreadable {
                path: label.to_string(),
                reason: e.to_string(),
            }) {
                return false;
            }
        }
        // Nothing came back at all: the format was recognised but the walker
        // yielded no entries, so the bytes themselves are the only content there
        // is to look at.
        if keep_going && members == 0 {
            return self.search_one(label, data, sink);
        }
        keep_going
    }

    /// Line-match a single object's bytes.
    fn search_one(&mut self, path: &str, data: &[u8], sink: Sink) -> bool {
        if looks_binary(data) {
            let any = data
                .split(|&b| b == b'\n')
                .any(|l| self.matcher.hits(strip_cr(l)));
            if any {
                if self.opts.binary_as_matches {
                    // Counted here because this returns without reaching the
                    // line loop. When the loop DOES run it does its own
                    // counting, and doing both made every matching binary
                    // member count twice in `matched_count()`.
                    self.matched += 1;
                    return sink(Event::BinaryMatch {
                        path: path.to_string(),
                    });
                }
            } else {
                return true;
            }
        }

        let mut lines: Vec<&[u8]> = data.split(|&b| b == b'\n').map(strip_cr).collect();
        // `split` on a trailing newline yields a final empty element that is not
        // a line of the file. It rarely matches a pattern, but `-v` matches
        // everything it is not given, so leaving it in reports a phantom match
        // at line N+1 for every file that ends the way text files end.
        if lines.len() > 1 && lines.last().is_some_and(|l| l.is_empty()) {
            lines.pop();
        }
        let mut hits = 0usize;
        let mut last_printed: Option<usize> = None;
        let mut counted = false;
        for (i, line) in lines.iter().enumerate() {
            if !self.matcher.hits(line) {
                continue;
            }
            if !counted {
                self.matched += 1;
                counted = true;
            }
            let from = i.saturating_sub(self.opts.before_context);
            let to = (i + self.opts.after_context).min(lines.len().saturating_sub(1));
            for (j, l) in lines.iter().enumerate().take(to + 1).skip(from) {
                // Don't reprint a line already emitted as context for an earlier
                // match, and never downgrade a match line to a context line.
                if last_printed.is_some_and(|p| j <= p) {
                    continue;
                }
                let ev = if j == i {
                    Event::Match {
                        path: path.to_string(),
                        line_no: j + 1,
                        line: l.to_vec(),
                    }
                } else {
                    Event::Context {
                        path: path.to_string(),
                        line_no: j + 1,
                        line: l.to_vec(),
                    }
                };
                if !sink(ev) {
                    return false;
                }
                last_printed = Some(j);
            }
            hits += 1;
            if self.opts.max_count != 0 && hits >= self.opts.max_count {
                break;
            }
        }
        true
    }
}

fn strip_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((b'\r', rest)) => rest,
        _ => line,
    }
}

/// A NUL byte in the first 8 KiB — the conventional binary-file heuristic.
fn looks_binary(data: &[u8]) -> bool {
    data.iter().take(8192).any(|&b| b == 0)
}

/// The format for a *packed executable*, which `detect` cannot report.
///
/// A packed PE is not a container by magic — "this is a PE" says nothing about
/// whether the program on disk is the program that runs. The scanner routes
/// these by content; a search tool has to do the same, or it reads the packed
/// bytes, matches nothing, and reports a clean "no matches" for a file whose
/// contents it never saw.
fn packed_executable(data: &[u8]) -> Option<exav_unpack::Format> {
    if exav_unpack::is_upx(data) {
        Some(exav_unpack::Format::Upx)
    } else if exav_unpack::is_pepack(data) {
        Some(exav_unpack::Format::PePacked)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(matcher: Matcher, opts: Options, label: &str, data: &[u8]) -> Vec<Event> {
        let mut out = Vec::new();
        let mut s = Searcher::new(matcher, opts);
        s.search_bytes(label, data, &mut |e| {
            out.push(e);
            true
        });
        out
    }

    fn zip_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        // Minimal stored-member ZIP, local headers only (exav reads those).
        let mut v = Vec::new();
        for (name, body) in members {
            v.extend_from_slice(b"PK\x03\x04");
            v.extend_from_slice(&20u16.to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes()); // stored
            v.extend_from_slice(&0u16.to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&(body.len() as u32).to_le_bytes());
            v.extend_from_slice(&(body.len() as u32).to_le_bytes());
            v.extend_from_slice(&(name.len() as u16).to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes());
            v.extend_from_slice(name.as_bytes());
            v.extend_from_slice(body);
        }
        v
    }

    #[test]
    fn finds_a_match_inside_a_zip_member() {
        let z = zip_of(&[("notes.txt", b"hello\nsecret sauce\nbye\n")]);
        let ev = collect(
            Matcher::fixed("secret", false).unwrap(),
            Options::default(),
            "a.zip",
            &z,
        );
        let m: Vec<_> = ev
            .iter()
            .filter_map(|e| match e {
                Event::Match { path, line_no, .. } => Some((path.clone(), *line_no)),
                _ => None,
            })
            .collect();
        assert_eq!(m, vec![("a.zip!notes.txt".to_string(), 2)]);
    }

    #[test]
    fn nesting_is_visible_in_the_path() {
        let inner = zip_of(&[("deep.txt", b"needle here\n")]);
        let outer = zip_of(&[("inner.zip", &inner)]);
        let ev = collect(
            Matcher::fixed("needle", false).unwrap(),
            Options::default(),
            "outer.zip",
            &outer,
        );
        assert!(
            ev.iter().any(|e| matches!(e, Event::Match { path, .. }
                if path == "outer.zip!inner.zip!deep.txt")),
            "got {ev:?}"
        );
    }

    #[test]
    fn an_unreadable_member_is_reported_not_silently_skipped() {
        // Method 9 with a bogus stream: a real member exav cannot decode. A
        // search tool that omits it is claiming "not present" about bytes it
        // never read.
        let mut v = Vec::new();
        v.extend_from_slice(b"PK\x03\x04");
        v.extend_from_slice(&20u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&99u16.to_le_bytes()); // not a real method
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&8u32.to_le_bytes());
        v.extend_from_slice(&8u32.to_le_bytes());
        v.extend_from_slice(&(b"x.bin".len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(b"x.bin");
        v.extend_from_slice(b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8");

        let mut s = Searcher::new(
            Matcher::fixed("anything", false).unwrap(),
            Options::default(),
        );
        let mut evs = Vec::new();
        s.search_bytes("a.zip", &v, &mut |e| {
            evs.push(e);
            true
        });
        assert!(
            evs.iter().any(|e| matches!(e, Event::Unreadable { .. })),
            "an undecodable member must be reported: {evs:?}"
        );
        assert_eq!(s.unreadable_count(), 1);
    }

    #[test]
    fn invert_and_ignore_case() {
        let z = zip_of(&[("f.txt", b"Alpha\nbeta\n")]);
        let ev = collect(
            Matcher::fixed("ALPHA", true).unwrap(),
            Options::default(),
            "a.zip",
            &z,
        );
        assert_eq!(
            ev.iter()
                .filter(|e| matches!(e, Event::Match { .. }))
                .count(),
            1
        );

        let ev = collect(
            Matcher::fixed("Alpha", false).unwrap().inverted(true),
            Options::default(),
            "a.zip",
            &z,
        );
        // "beta" and the trailing empty line both fail to match "Alpha".
        assert!(ev
            .iter()
            .any(|e| matches!(e, Event::Match { line, .. } if line == b"beta")));
    }

    #[test]
    fn context_lines_surround_the_match() {
        let z = zip_of(&[("f.txt", b"one\ntwo\nTARGET\nfour\nfive\n")]);
        let opts = Options {
            before_context: 1,
            after_context: 1,
            ..Options::default()
        };
        let ev = collect(Matcher::fixed("TARGET", false).unwrap(), opts, "a.zip", &z);
        let nums: Vec<usize> = ev
            .iter()
            .filter_map(|e| match e {
                Event::Match { line_no, .. } | Event::Context { line_no, .. } => Some(*line_no),
                _ => None,
            })
            .collect();
        assert_eq!(nums, vec![2, 3, 4], "one line either side of the match");
    }

    #[test]
    fn a_container_yielding_no_members_falls_back_to_its_raw_bytes() {
        // A ZIP magic with nothing extractable behind it must still be searched,
        // rather than producing silence because "it's a container".
        let mut z = b"PK\x03\x04".to_vec();
        z.extend_from_slice(b"\x00".repeat(8).as_slice());
        z.extend_from_slice(b"\nTRAILING-MARKER\n");
        let ev = collect(
            Matcher::fixed("TRAILING-MARKER", false).unwrap(),
            Options::default(),
            "a.zip",
            &z,
        );
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Match { path, .. } if path == "a.zip")),
            "got {ev:?}"
        );
    }

    #[test]
    fn a_hit_inside_a_stored_member_is_reported_once() {
        // The member's bytes are literally present in the container too;
        // reporting both would double every result.
        let z = zip_of(&[("f.txt", b"unique-token\n")]);
        let ev = collect(
            Matcher::fixed("unique-token", false).unwrap(),
            Options::default(),
            "a.zip",
            &z,
        );
        assert_eq!(
            ev.iter()
                .filter(|e| matches!(e, Event::Match { .. }))
                .count(),
            1,
            "got {ev:?}"
        );
    }
}
