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
//! No member is ever written to disk, so the zip-slip / path-traversal /
//! symlink class does not arise. Extraction runs under
//! [`exav_unpack::Budget`], the same decompression-bomb budgets the scanner
//! uses, so a malicious archive cannot turn a search into an unbounded
//! allocation.
//!
//! ## Memory
//!
//! A file is read as the search needs it, never whole past a small size: a
//! container is walked through a block cache, and a file or a member that is
//! not a container is searched a megabyte at a time. What is held is bounded
//! by [`exav_unpack::Limits::max_buffer_bytes`]: a member up to it is held (so
//! that a container inside it can be opened), a longer one is searched as it
//! is read, and a container in it, which cannot be opened without holding it,
//! is reported unreadable. A line longer than the bound is reported
//! unreadable too.
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

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read};
use std::path::Path;

use exav_unpack::source::{BlockCache, Reader};
use exav_unpack::{Budget, ByteSource, Format, Limits, Member, MemberMeta};

/// Files up to this size are read into memory; a larger one is read through a
/// block cache.
const HOLD_WHOLE: u64 = 16 << 20;

/// Bytes read at a time when a file or a member is searched as a stream.
const READ: usize = 1 << 20;

/// How much of a member is looked at to tell text from binary.
const BINARY_PROBE: usize = 8192;

/// Separator between a container and a member in a reported path, mirroring the
/// convention `7z`/`unzip` tooling uses so the output is greppable in turn.
pub const NESTING_SEP: char = '!';

/// What to search for. Fixed strings are searched literally (no escaping
/// surprises); regex patterns compile on the linear-time `regex` engine, so a
/// pathological pattern cannot hang the search.
#[derive(Debug, Clone)]
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
#[derive(Clone, Default, Debug)]
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
    /// Search the text a reader sees rather than the bytes, for a member that
    /// has one: Markdown, HTML, the XML parts of Office and OpenDocument files,
    /// PDF and drawings are searched as their words, with entities decoded and
    /// each link followed by where it goes, under the path `file.md!text`, its
    /// line numbers being the text's. A document that is also a container (a
    /// PDF, a drawing) is walked for its members as before. Does nothing
    /// without the `text` feature.
    pub text: bool,
}

/// One result of the search.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
#[derive(Debug)]
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
    /// A file of any size is searched in bounded memory: one over 16 MiB is
    /// read through a block cache, so a disk image or a multi-gigabyte log costs
    /// what its walk holds and not its size. A pseudo-file that is not a regular
    /// file is reported rather than read.
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
        let file = std::fs::File::open(path)?;
        if meta.len() <= HOLD_WHOLE {
            let mut data = Vec::with_capacity(meta.len() as usize);
            (&file).take(HOLD_WHOLE + 1).read_to_end(&mut data)?;
            return Ok(self.search_source(&label, &data, sink));
        }
        let cache = BlockCache::new(file)?;
        Ok(self.search_source(&label, &cache, sink))
    }

    /// Search an in-memory buffer under `label`.
    pub fn search_bytes(&mut self, label: &str, data: &[u8], sink: Sink) -> bool {
        self.search_source(label, &data, sink)
    }

    /// Search any readable-at-an-offset source under `label`. A read that
    /// failed is reported unreadable, never taken for the end of the data.
    fn search_source(&mut self, label: &str, src: &dyn ByteSource, sink: Sink) -> bool {
        let mut budget = Budget::new(self.opts.limits.clone());
        budget.passwords = self.opts.passwords.clone();
        let go = self.walk(label, src, &mut budget, 0, sink);
        if go && let Some(e) = src.read_error() {
            self.unreadable += 1;
            return sink(Event::Unreadable {
                path: label.to_string(),
                reason: format!("read failed: {e}"),
            });
        }
        go
    }

    /// The most a buffer may hold, as `usize`.
    fn cap(&self) -> usize {
        usize::try_from(self.opts.limits.max_buffer_bytes).unwrap_or(usize::MAX)
    }

    /// Search `data`, then recurse into it if it is a container. Returns `false`
    /// when the sink asked to stop.
    fn walk(
        &mut self,
        label: &str,
        src: &dyn ByteSource,
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
        let mut unchecked = false;
        let fmt = exav_unpack::detect(src).or_else(|| match self.packed_executable(src) {
            Packed::Is(fmt) => Some(fmt),
            Packed::Not => None,
            Packed::Unchecked => {
                unchecked = true;
                None
            }
        });
        let Some(fmt) = fmt else {
            // A leaf: search its bytes, or its text.
            if !self.search_leaf(label, src, sink) {
                return false;
            }
            if unchecked {
                self.unreadable += 1;
                return sink(Event::Unreadable {
                    path: label.to_string(),
                    reason: format!(
                        "an executable over the {}-byte limit: whether it is packed was not checked",
                        self.opts.limits.max_buffer_bytes
                    ),
                });
            }
            return true;
        };
        // A container is searched through its MEMBERS, not its raw bytes — for a
        // stored member those are the same bytes, and reporting both would
        // duplicate every hit. If extraction yields nothing (a broken or empty
        // container) the raw bytes are searched instead, so a damaged archive
        // still gets looked at rather than silently producing no output.
        let mut members = 0usize;
        let mut keep_going = true;
        let r = exav_unpack::walk(fmt, src, budget, &mut |meta, content, b| {
            let child = format!("{label}{NESTING_SEP}{}", meta.name);
            // Counted as a member whether or not it yields anything. The
            // fallback below exists for a buffer the walker found no members in
            // at all; a container whose members all failed to decode HAS
            // members, and line-searching its own compressed bytes would emit a
            // stream of garbage matches contradicting the `Unreadable` events
            // reported for the same file.
            members += 1;
            // A member exav could not decode is content this search did not
            // see. Saying nothing here would report "no matches" for bytes
            // nobody looked at.
            let mut go = true;
            let mut unread: Option<String> = None;
            match (meta.unsupported, content) {
                (Some(reason), _) => unread = Some(reason.to_string()),
                (None, None) => go = self.walk(&child, &Vec::<u8>::new(), b, depth + 1, sink),
                (None, Some(Member::Bytes(data))) => {
                    go = self.walk(&child, &data, b, depth + 1, sink);
                }
                (None, Some(Member::Stream(stream))) => {
                    match self.walk_stream(&child, meta, stream, b, depth, sink) {
                        Err(hit) => return Some(Err(hit)),
                        Ok((more, partial)) => {
                            go = more;
                            if partial {
                                unread = Some("member failed to decode part way".to_string());
                            }
                        }
                    }
                }
            }
            if let Some(reason) = unread.filter(|_| go) {
                self.unreadable += 1;
                go = sink(Event::Unreadable {
                    path: child,
                    reason,
                });
            }
            if go {
                None
            } else {
                keep_going = false;
                Some(Ok(()))
            }
        });
        let r = match r {
            Ok(Some(Err(why))) => Err(why),
            Err(hit) => Err(hit.to_string()),
            Ok(_) => Ok(()),
        };
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
            return self.search_lines(label, src, sink);
        }
        // A container with text of its own (a PDF, a drawing) is searched as
        // that too, besides its members.
        #[cfg(feature = "text")]
        if keep_going && let Some(go) = self.text_of(label, src, sink) {
            return go;
        }
        keep_going
    }

    /// A member that is read as it is produced. Up to the buffer limit it is
    /// held, and searched like any other member, so a container in it can be
    /// opened. A longer one is searched as it is read: held memory does not
    /// grow with it. `Err` is a budget that ran out, which ends the walk. The
    /// flag says the decoder failed part way.
    fn walk_stream(
        &mut self,
        child: &str,
        meta: &MemberMeta,
        stream: &mut dyn Read,
        budget: &mut Budget,
        depth: u32,
        sink: Sink,
    ) -> Result<(bool, bool), String> {
        let name = &meta.name;
        let cap = budget.reserve().map_err(|hit| hit.to_string())?;
        let mut data = Vec::new();
        let mut partial = false;
        match stream.take(cap.saturating_add(1)).read_to_end(&mut data) {
            Ok(_) => {}
            Err(e) if exav_unpack::is_budget_overflow(&e) => {
                return Err(format!("member '{name}': {e}"));
            }
            Err(e) if budget.should_verify_checksums() => {
                return Err(format!("member '{name}': {e}"));
            }
            Err(e) => partial = exav_unpack::decode_error_hides_content(&e),
        }
        if data.len() as u64 <= cap {
            budget.commit(data.len() as u64);
            if partial && data.is_empty() {
                return Ok((true, true));
            }
            return Ok((self.walk(child, &data, budget, depth + 1, sink), partial));
        }
        // Past the limit. A container cannot be opened without holding it, so
        // it is reported; anything else is searched as it is read.
        let probe = &data[..data.len().min(64 << 10)];
        if let Some(fmt) = exav_unpack::detect(&probe) {
            self.unreadable += 1;
            let reason = format!(
                "a {fmt:?} container over the {cap}-byte limit: its members were not searched"
            );
            let go = sink(Event::Unreadable {
                path: child.to_string(),
                reason,
            });
            return Ok((go, false));
        }
        #[cfg(feature = "text")]
        if self.opts.text && exav_render::text::wants(name, probe) {
            self.unreadable += 1;
            let path = format!("{child}{NESTING_SEP}text");
            let reason = format!("visible text: over the {cap}-byte limit");
            if !sink(Event::Unreadable { path, reason }) {
                return Ok((false, false));
            }
        }
        let mut whole = io::Cursor::new(data).chain(stream);
        match self.search_reader(child, &mut whole, sink) {
            Ok(go) => Ok((go, false)),
            Err(e) if exav_unpack::is_budget_overflow(&e) => Err(format!("member '{name}': {e}")),
            Err(e) if budget.should_verify_checksums() => Err(format!("member '{name}': {e}")),
            // What decoded was searched. Only damage that hides content, not a
            // checksum that failed after a full decode, makes it a partial one.
            Err(e) => Ok((true, exav_unpack::decode_error_hides_content(&e))),
        }
    }

    /// Whether a leaf is a packed executable, which `detect` cannot say: a
    /// packed PE is not a container by magic, and "this is a PE" says nothing
    /// about whether the program on disk is the program that runs. Searched as
    /// it lies, it would report "no matches" for contents never seen. Only an
    /// executable is looked at, and only one that can be held: the check reads
    /// all of it.
    fn packed_executable(&self, src: &dyn ByteSource) -> Packed {
        if !is_executable(&src.window(0, 4)) {
            return Packed::Not;
        }
        let Some(data) = src.materialize(self.cap()) else {
            return Packed::Unchecked;
        };
        if exav_unpack::is_upx(&data) {
            Packed::Is(Format::Upx)
        } else if exav_unpack::is_pepack(&data) {
            Packed::Is(Format::PePacked)
        } else {
            Packed::Not
        }
    }

    /// Search a leaf: its text under `--text` when it has one, else its bytes.
    fn search_leaf(&mut self, label: &str, src: &dyn ByteSource, sink: Sink) -> bool {
        #[cfg(feature = "text")]
        if let Some(go) = self.text_of(label, src, sink) {
            return go;
        }
        self.search_lines(label, src, sink)
    }

    /// The text of `src` under `--text`, when it is a kind of document that has
    /// some (see [`Self::search_text`]). A document too large to hold has its
    /// text unread: reported, and `None` so its bytes are searched instead.
    #[cfg(feature = "text")]
    fn text_of(&mut self, label: &str, src: &dyn ByteSource, sink: Sink) -> Option<bool> {
        if !self.opts.text {
            return None;
        }
        let name = label.rsplit(NESTING_SEP).next().unwrap_or(label);
        if !exav_render::text::wants(name, &src.window(0, 1024)) {
            return None;
        }
        let cap = self.cap();
        match src.materialize(cap) {
            Some(data) => self.search_text(label, &data, sink),
            None => {
                self.unreadable += 1;
                let path = format!("{label}{NESTING_SEP}text");
                let reason = format!(
                    "visible text: {} bytes, over the {cap}-byte limit",
                    src.len()
                );
                (!sink(Event::Unreadable { path, reason })).then_some(false)
            }
        }
    }

    /// Line-match the bytes of `src`: in place when it is in memory, else as
    /// they are read.
    fn search_lines(&mut self, label: &str, src: &dyn ByteSource, sink: Sink) -> bool {
        if let Some(data) = src.as_slice() {
            return self.search_one(label, data, sink);
        }
        match self.search_reader(label, &mut Reader::new(src), sink) {
            Ok(go) => go,
            // The source says it failed: `search_source` reports that, once.
            Err(_) if src.read_error().is_some() => true,
            Err(e) => {
                self.unreadable += 1;
                let reason = format!("read failed: {e}");
                sink(Event::Unreadable {
                    path: label.to_string(),
                    reason,
                })
            }
        }
    }

    /// Search the text a reader sees in `data`, as `label!text` (and
    /// `label!text/<section>` for a sheet or a slide), when it is a kind of
    /// document that has some (`None` when it is not, and also when its text
    /// could not be taken out: that is reported unreadable and its bytes are
    /// searched instead). A text cut short is reported unreadable, as a
    /// member that failed part way is.
    #[cfg(feature = "text")]
    fn search_text(&mut self, label: &str, data: &[u8], sink: Sink) -> Option<bool> {
        let name = label.rsplit(NESTING_SEP).next().unwrap_or(label);
        let cap = usize::try_from(self.opts.limits.max_buffer_bytes).unwrap_or(usize::MAX);
        let cap = data
            .len()
            .saturating_mul(4)
            .saturating_add(64 << 10)
            .min(cap);
        let visible = exav_render::text::visible_text(name, data, cap, &self.opts.limits)?;
        let path = format!("{label}{NESTING_SEP}text");
        if let Some(why) = &visible.unreadable {
            // A document of a kind that has text whose text could not be
            // taken out: said, and its bytes are searched instead.
            self.unreadable += 1;
            if !sink(Event::Unreadable {
                path,
                reason: format!("visible text: {why}"),
            }) {
                return Some(false);
            }
            return None;
        }
        // One search to a section (a sheet, a slide), so that a match says
        // where it is: `book.xls!text/sheet "Budget"`; what comes before the
        // first section, and a document of one block, is `!text`.
        let mut at = 0;
        let mut parts: Vec<(String, std::ops::Range<usize>)> = Vec::new();
        for (section, range) in &visible.sections {
            if range.start > at {
                parts.push((path.clone(), at..range.start));
            }
            parts.push((format!("{path}/{section}"), range.clone()));
            at = range.end;
        }
        if at < visible.text.len() || parts.is_empty() {
            parts.push((path.clone(), at..visible.text.len()));
        }
        for (part, range) in parts {
            let bytes = visible.text.as_bytes().get(range).unwrap_or_default();
            if !self.search_one(&part, bytes, sink) {
                return Some(false);
            }
        }
        if visible.truncated {
            self.unreadable += 1;
            return Some(sink(Event::Unreadable {
                path,
                reason: format!("visible text cut at {cap} bytes"),
            }));
        }
        Some(true)
    }

    /// Line-match a single object's bytes.
    fn search_one(&mut self, path: &str, data: &[u8], sink: Sink) -> bool {
        // A cursor over memory cannot fail.
        self.search_reader(path, &mut io::Cursor::new(data), sink)
            .unwrap_or(true)
    }

    /// Line-match a stream, holding a line at a time (and the lines of
    /// `-B` context). `Err` is a read error: every line read before it has
    /// been matched. `Ok(false)` is the sink asking to stop.
    fn search_reader(&mut self, path: &str, r: &mut dyn Read, sink: Sink) -> io::Result<bool> {
        let mut lines = Lines::new(path, self.cap());
        let mut buf = vec![0u8; READ];
        let mut probe = Vec::new();
        let mut failed = None;
        while !lines.done {
            let n = match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            };
            if lines.binary.is_none() {
                probe.extend_from_slice(&buf[..n]);
                if probe.len() < BINARY_PROBE {
                    continue;
                }
                lines.binary = Some(looks_binary(&probe));
                let held = std::mem::take(&mut probe);
                self.feed(&mut lines, &held, sink);
            } else {
                self.feed(&mut lines, &buf[..n], sink);
            }
        }
        if lines.binary.is_none() {
            lines.binary = Some(looks_binary(&probe));
            let held = std::mem::take(&mut probe);
            self.feed(&mut lines, &held, sink);
        }
        if !lines.done {
            self.finish(&mut lines, sink);
        }
        if lines.stopped {
            return Ok(false);
        }
        failed.map_or(Ok(true), Err)
    }

    /// Match every complete line of `chunk`, and keep the rest for the next.
    fn feed(&mut self, lines: &mut Lines, chunk: &[u8], sink: Sink) {
        let mut rest = chunk;
        while !lines.done {
            let Some(end) = memchr::memchr(b'\n', rest) else {
                break;
            };
            if lines.partial.is_empty() {
                self.line(lines, &rest[..end], sink);
            } else {
                lines.partial.extend_from_slice(&rest[..end]);
                let whole = std::mem::take(&mut lines.partial);
                self.line(lines, &whole, sink);
            }
            rest = &rest[end + 1..];
        }
        if lines.done {
            return;
        }
        lines.partial.extend_from_slice(rest);
        if lines.partial.len() > lines.max_line {
            self.unreadable += 1;
            lines.done = true;
            lines.stopped = !sink(Event::Unreadable {
                path: lines.path.clone(),
                reason: format!(
                    "line {} is longer than {} bytes: the rest of it was not searched",
                    lines.n + 1,
                    lines.max_line
                ),
            });
        }
    }

    /// The end of the data: a last line with no terminator, or the one empty
    /// line of an empty object. A terminator at the very end does not start
    /// another line, which `-v` would otherwise match.
    fn finish(&mut self, lines: &mut Lines, sink: Sink) {
        if !lines.partial.is_empty() {
            let whole = std::mem::take(&mut lines.partial);
            self.line(lines, &whole, sink);
        } else if lines.n == 0 {
            self.line(lines, b"", sink);
        }
    }

    /// One line, without its `\n`.
    fn line(&mut self, lines: &mut Lines, raw: &[u8], sink: Sink) {
        let text = strip_cr(raw);
        let at = lines.n;
        lines.n += 1;
        let hit = self.matcher.hits(text);
        let emit = |lines: &mut Lines, ev: Event, sink: Sink| {
            if !sink(ev) {
                lines.stopped = true;
                lines.done = true;
            }
        };
        if hit && lines.binary == Some(true) && self.opts.binary_as_matches {
            // One result for the member, not a line.
            self.matched += 1;
            lines.done = true;
            let ev = Event::BinaryMatch {
                path: lines.path.clone(),
            };
            emit(lines, ev, sink);
            return;
        }
        let context = |lines: &Lines, line_no: usize, line: &[u8]| Event::Context {
            path: lines.path.clone(),
            line_no,
            line: line.to_vec(),
        };
        // After the last wanted match, only its trailing context remains.
        if lines.finished_matching {
            if lines.after_left == 0 {
                lines.done = true;
                return;
            }
            lines.after_left -= 1;
            let ev = context(lines, at + 1, text);
            emit(lines, ev, sink);
            if lines.after_left == 0 {
                lines.done = true;
            }
            return;
        }
        if hit {
            if !lines.counted {
                self.matched += 1;
                lines.counted = true;
            }
            // The context before a match is only what has not been printed.
            while let Some((line_no, held)) = lines.before.pop_front() {
                lines.before_bytes -= held.len();
                let ev = context(lines, line_no, &held);
                emit(lines, ev, sink);
                if lines.done {
                    return;
                }
            }
            let ev = Event::Match {
                path: lines.path.clone(),
                line_no: at + 1,
                line: text.to_vec(),
            };
            emit(lines, ev, sink);
            lines.after_left = self.opts.after_context;
            lines.hits += 1;
            if self.opts.max_count != 0 && lines.hits >= self.opts.max_count {
                lines.finished_matching = true;
                if lines.after_left == 0 {
                    lines.done = true;
                }
            }
        } else if lines.after_left > 0 {
            lines.after_left -= 1;
            let ev = context(lines, at + 1, text);
            emit(lines, ev, sink);
        } else if self.opts.before_context > 0 {
            lines.before_bytes += text.len();
            lines.before.push_back((at + 1, text.to_vec()));
            while lines.before.len() > self.opts.before_context
                || lines.before_bytes > lines.max_line
            {
                if let Some((_, held)) = lines.before.pop_front() {
                    lines.before_bytes -= held.len();
                }
            }
        }
    }
}

/// Where a line search is, between chunks.
struct Lines {
    path: String,
    /// Lines completed so far.
    n: usize,
    /// The line being read, when it is not whole in the chunk.
    partial: Vec<u8>,
    /// The longest line held.
    max_line: usize,
    /// Whether the start looked binary, once enough has been read to say.
    binary: Option<bool>,
    /// Unprinted lines kept for `-B`, with their numbers.
    before: VecDeque<(usize, Vec<u8>)>,
    before_bytes: usize,
    /// Lines of trailing context still to print.
    after_left: usize,
    hits: usize,
    counted: bool,
    /// `-m` was met: only the trailing context is left.
    finished_matching: bool,
    /// Nothing more to read.
    done: bool,
    /// The sink asked to stop.
    stopped: bool,
}

impl Lines {
    fn new(path: &str, max_line: usize) -> Self {
        Lines {
            path: path.to_string(),
            n: 0,
            partial: Vec::new(),
            max_line,
            binary: None,
            before: VecDeque::new(),
            before_bytes: 0,
            after_left: 0,
            hits: 0,
            counted: false,
            finished_matching: false,
            done: false,
            stopped: false,
        }
    }
}

/// What looking at a leaf for a packer found.
enum Packed {
    /// A packed executable, to be opened as this.
    Is(Format),
    Not,
    /// An executable too large to hold, which the check needs whole.
    Unchecked,
}

/// Whether `head` starts like a PE, an ELF or a Mach-O: what a packed
/// executable is.
fn is_executable(head: &[u8]) -> bool {
    head.starts_with(b"MZ")
        || head.starts_with(b"\x7fELF")
        || matches!(
            head,
            [0xfe, 0xed, 0xfa, 0xce | 0xcf, ..] | [0xce | 0xcf, 0xfa, 0xed, 0xfe, ..]
        )
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

    /// `-A` is a number off the command line: as wide as `usize` it means "to
    /// the end of the file", and the match line is still printed.
    #[test]
    fn an_after_context_as_wide_as_usize_reaches_the_end() {
        let opts = Options {
            after_context: usize::MAX,
            ..Options::default()
        };
        let ev = collect(
            Matcher::fixed("two", false).unwrap(),
            opts,
            "f",
            b"one\ntwo\nthree\nfour\n",
        );
        let lines: Vec<_> = ev
            .iter()
            .filter_map(|e| match e {
                Event::Match { line_no, .. } => Some(*line_no),
                _ => None,
            })
            .collect();
        assert_eq!(lines, vec![2]);
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
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Match { line, .. } if line == b"beta"))
        );
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

    /// `(kind, line number)` of the line events.
    fn shown(ev: &[Event]) -> Vec<(char, usize)> {
        ev.iter()
            .filter_map(|e| match e {
                Event::Match { line_no, .. } => Some(('M', *line_no)),
                Event::Context { line_no, .. } => Some(('C', *line_no)),
                _ => None,
            })
            .collect()
    }

    fn capped(bytes: u64) -> Options {
        let mut opts = Options::default();
        opts.limits.max_buffer_bytes = bytes;
        opts
    }

    #[test]
    fn a_match_in_the_trailing_context_of_another_is_still_a_match() {
        let opts = Options {
            after_context: 1,
            ..Options::default()
        };
        let ev = collect(
            Matcher::fixed("b", false).unwrap(),
            opts,
            "f",
            b"a\nb\nb\nc\nd\n",
        );
        assert_eq!(shown(&ev), vec![('M', 2), ('M', 3), ('C', 4)]);
    }

    #[test]
    fn the_last_wanted_match_still_gets_its_trailing_context() {
        let opts = Options {
            after_context: 1,
            max_count: 1,
            ..Options::default()
        };
        let ev = collect(Matcher::fixed("x", false).unwrap(), opts, "f", b"x\nx\nx\n");
        assert_eq!(shown(&ev), vec![('M', 1), ('C', 2)]);
    }

    #[test]
    fn before_context_is_not_printed_twice() {
        let opts = Options {
            before_context: 2,
            after_context: 1,
            ..Options::default()
        };
        let ev = collect(
            Matcher::fixed("T", false).unwrap(),
            opts,
            "f",
            b"1\n2\nT\n4\n5\n6\nT\n8\n",
        );
        assert_eq!(
            shown(&ev),
            vec![
                ('C', 1),
                ('C', 2),
                ('M', 3),
                ('C', 4),
                ('C', 5),
                ('C', 6),
                ('M', 7),
                ('C', 8)
            ]
        );
    }

    #[test]
    fn an_empty_object_is_one_empty_line_and_a_final_newline_starts_no_other() {
        let inverted = || Matcher::fixed("zzz", false).unwrap().inverted(true);
        let ev = collect(inverted(), Options::default(), "f", b"");
        assert_eq!(shown(&ev), vec![('M', 1)]);
        let ev = collect(inverted(), Options::default(), "f", b"a\n");
        assert_eq!(shown(&ev), vec![('M', 1)]);
        let ev = collect(inverted(), Options::default(), "f", b"a\n\n");
        assert_eq!(shown(&ev), vec![('M', 1), ('M', 2)]);
    }

    #[test]
    fn a_carriage_return_is_not_part_of_the_line_and_the_last_line_needs_no_newline() {
        let ev = collect(
            Matcher::regex("^needle$", false).unwrap(),
            Options::default(),
            "f",
            b"a\r\nneedle",
        );
        assert_eq!(shown(&ev), vec![('M', 2)]);
    }

    #[test]
    fn a_binary_member_that_matches_counts_once() {
        let mut s = Searcher::new(Matcher::fixed("needle", false).unwrap(), {
            Options {
                binary_as_matches: true,
                ..Options::default()
            }
        });
        let mut ev = Vec::new();
        s.search_bytes("f", b"\0\0\0 needle \n needle again\0", &mut |e| {
            ev.push(e);
            true
        });
        assert_eq!(ev.len(), 1, "got {ev:?}");
        assert!(matches!(ev[0], Event::BinaryMatch { .. }));
        assert_eq!(s.matched_count(), 1);
    }

    /// A stored-member ZIP with its central directory, so that its members are
    /// read as they are produced rather than found by their local headers.
    fn zip_indexed(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut v = zip_of(members);
        let mut directory = Vec::new();
        let mut offset = 0u32;
        for (name, body) in members {
            directory.extend_from_slice(b"PK\x01\x02");
            directory.extend_from_slice(&20u16.to_le_bytes()); // made by
            directory.extend_from_slice(&20u16.to_le_bytes()); // needed
            directory.extend_from_slice(&[0; 2]); // flags
            directory.extend_from_slice(&[0; 2]); // stored
            directory.extend_from_slice(&[0; 4]); // time, date
            directory.extend_from_slice(&[0; 4]); // crc
            directory.extend_from_slice(&(body.len() as u32).to_le_bytes());
            directory.extend_from_slice(&(body.len() as u32).to_le_bytes());
            directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
            directory.extend_from_slice(&[0; 8]); // extra, comment, disk, internal attributes
            directory.extend_from_slice(&[0; 4]); // external attributes
            directory.extend_from_slice(&offset.to_le_bytes());
            directory.extend_from_slice(name.as_bytes());
            offset += 30 + name.len() as u32 + body.len() as u32;
        }
        let at = v.len() as u32;
        v.extend_from_slice(&directory);
        v.extend_from_slice(b"PK\x05\x06");
        v.extend_from_slice(&[0; 4]); // disk numbers
        v.extend_from_slice(&(members.len() as u16).to_le_bytes());
        v.extend_from_slice(&(members.len() as u16).to_le_bytes());
        v.extend_from_slice(&(directory.len() as u32).to_le_bytes());
        v.extend_from_slice(&at.to_le_bytes());
        v.extend_from_slice(&[0; 2]); // comment
        v
    }

    #[test]
    fn a_line_longer_than_the_limit_is_reported_not_searched_in_part() {
        // Longer than one read, so it cannot be matched where it lies.
        let mut data = vec![b'a'; 3 << 20];
        data.extend_from_slice(b"needle\n");
        let mut s = Searcher::new(Matcher::fixed("needle", false).unwrap(), capped(1024));
        let mut ev = Vec::new();
        s.search_bytes("f", &data, &mut |e| {
            ev.push(e);
            true
        });
        assert!(shown(&ev).is_empty(), "got {ev:?}");
        assert!(
            matches!(ev.as_slice(), [Event::Unreadable { reason, .. }] if reason.contains("longer than 1024")),
            "got {ev:?}"
        );
        assert_eq!(s.unreadable_count(), 1);
    }

    /// A text of `n` lines whose last one holds the needle.
    fn log_of(n: usize) -> Vec<u8> {
        let mut data = Vec::new();
        for i in 0..n {
            data.extend_from_slice(format!("line {i} of the log, nothing to see\n").as_bytes());
        }
        data.extend_from_slice(b"the needle is here\n");
        data
    }

    #[test]
    fn a_source_read_in_blocks_is_searched_as_it_is_read() {
        let data = log_of(100_000);
        let cache = BlockCache::with_sizes(std::io::Cursor::new(data.clone()), 512, 8192).unwrap();
        let mut s = Searcher::new(Matcher::fixed("needle", false).unwrap(), capped(64 << 10));
        let mut ev = Vec::new();
        s.search_source("log", &cache, &mut |e| {
            ev.push(e);
            true
        });
        assert_eq!(shown(&ev), vec![('M', 100_001)], "got {:?}", ev.len());
        assert_eq!(s.unreadable_count(), 0);
    }

    #[test]
    fn a_file_over_the_limit_is_searched_not_refused() {
        let path = std::env::temp_dir().join(format!("exav-grep-big-{}.log", std::process::id()));
        // Past HOLD_WHOLE, so it goes through the block cache.
        let data = log_of(600_000);
        assert!(data.len() as u64 > HOLD_WHOLE);
        std::fs::write(&path, &data).unwrap();
        let mut s = Searcher::new(Matcher::fixed("needle", false).unwrap(), capped(1 << 20));
        let mut ev = Vec::new();
        let r = s.search_path(&path, &mut |e| {
            ev.push(e);
            true
        });
        std::fs::remove_file(&path).unwrap();
        assert!(r.unwrap());
        assert_eq!(shown(&ev), vec![('M', 600_001)]);
        assert_eq!(s.unreadable_count(), 0, "got {} events", ev.len());
    }

    #[test]
    fn a_member_over_the_limit_is_searched_as_it_is_read() {
        let z = zip_indexed(&[("big.txt", &log_of(10_000))]);
        let mut s = Searcher::new(Matcher::fixed("needle", false).unwrap(), capped(64 << 10));
        let mut ev = Vec::new();
        s.search_bytes("a.zip", &z, &mut |e| {
            ev.push(e);
            true
        });
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Match { path, line_no, .. }
                if path == "a.zip!big.txt" && *line_no == 10_001)),
            "got {ev:?}"
        );
        assert_eq!(s.unreadable_count(), 0, "got {ev:?}");
    }

    #[test]
    fn a_container_over_the_limit_inside_a_member_is_reported_not_opened() {
        let inner = zip_indexed(&[("deep.txt", &log_of(10_000))]);
        let outer = zip_indexed(&[("inner.zip", &inner)]);
        let mut s = Searcher::new(Matcher::fixed("needle", false).unwrap(), capped(64 << 10));
        let mut ev = Vec::new();
        s.search_bytes("o.zip", &outer, &mut |e| {
            ev.push(e);
            true
        });
        assert!(shown(&ev).is_empty(), "got {ev:?}");
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Unreadable { path, reason }
                if path == "o.zip!inner.zip" && reason.contains("container"))),
            "got {ev:?}"
        );
    }
}
