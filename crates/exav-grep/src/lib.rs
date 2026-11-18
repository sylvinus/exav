//! `grep`, but it can see inside archives.
//!
//! Ordinary `grep -r` stops at the container: a ZIP, ISO, 7z or Word document is
//! one opaque binary blob to it. This crate walks *into* containers with
//! [`exav_unpack`], recursively, and searches every member as if it were a file
//! on disk, reporting matches with a path that shows the nesting:
//!
//! ```text
//! backup.zip!logs.tar.gz!logs/app.log:42:  connection from 10.0.0.7
//! ```
//!
//! No member is ever written to disk, so the zip-slip / path-traversal /
//! symlink class does not arise. Extraction runs under
//! [`exav_unpack::Budget`], the same decompression-bomb budgets the scanner
//! uses, so a malicious archive cannot turn a search into an unbounded
//! allocation. The walk is the scanner's own ([`exav_unpack::tree`]): the same
//! depth rule, the same members, the same sets of split files and the same
//! second readings (a ZIP appended to a PDF), and the names of members are
//! cleaned of what could change how the output reads.
//!
//! ## Memory
//!
//! A file is read as the search needs it, never whole past
//! [`Limits::max_buffer_bytes`]: a larger one is read where it lies through a
//! block cache ([`Options::object_cache_bytes`]). What is held is bounded by
//! the same limit: a member up to it is held (so that a container inside it
//! can be opened), a longer one is searched as it is read, and a container in
//! it, which cannot be opened without seeking in it, is written to an
//! anonymous temporary file in [`Options::spill_dir`] and opened from there,
//! or reported unreadable when there is none. A line longer than the bound is
//! reported unreadable.
//!
//! ## Members that cannot be read are reported
//!
//! A member exav cannot decode (unsupported codec, encryption without a working
//! password, a budget stop) is **not silently omitted from the results**. It is
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
use std::fmt::{self, Write as _};
use std::io::{self, Read};
use std::path::Path;

use exav_unpack::source::{Reader, open_source};
use exav_unpack::spill::{DirSpill, Spill};
use exav_unpack::tree::{
    Content, Cx, End, Flow, Hold, Large, Node, PathStyle, Reason, Reasons, Root, Typed, Typing,
    Visitor, Walk, Walker,
};
use exav_unpack::{Budget, ByteSource, Limits, Raster};

/// Bytes read at a time when a file or a member is searched as a stream.
const READ: usize = 1 << 20;

/// How much of a member is looked at to tell text from binary.
const BINARY_PROBE: usize = 8192;

/// How much of the start of a member too long to hold is looked at to tell
/// whether it is a document or an image that has text or QR codes.
const KIND_PROBE: usize = 64 << 10;

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
#[derive(Clone, Debug)]
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
    /// Search the payloads of the QR codes in an image as well as its bytes,
    /// one to a line under the path `image.png!qr`. Does nothing without the
    /// `qr` feature.
    pub qr: bool,
    /// Report the QR codes of the images and nothing else: no line is
    /// matched and no text read, and each payload is an [`Event::Qr`] under
    /// the path of its image. Set by [`Searcher::qr_codes`]. Without the `qr`
    /// feature nothing is read.
    pub qr_only: bool,
    /// Pixels an image may have for its QR codes to be read, `None` for any;
    /// a larger one is reported unreadable.
    pub max_qr_pixels: Option<u64>,
    /// Milliseconds the reading of one image's QR codes may take, `None` for
    /// any; one cut short is reported unreadable.
    pub max_qr_millis: Option<u64>,
    /// QR codes read in one image, `None` for all; an image with more is
    /// reported unreadable.
    pub max_qr_codes: Option<u64>,
    /// Finder patterns (the square a QR code has in three corners) found in
    /// one image, `None` for all; an image with more is reported unreadable.
    pub max_qr_finders: Option<u64>,
    /// Groups of three finder patterns tried as a QR code in one image,
    /// `None` for all; an image with more is reported unreadable.
    pub max_qr_grids: Option<u64>,
    /// Where a container inside a member over
    /// [`Limits::max_buffer_bytes`] is written so that it can be opened: an
    /// anonymous temporary file in this directory, deleted when its search
    /// ends. `None` (the default) writes nothing, and such a container is
    /// reported unreadable.
    pub spill_dir: Option<std::path::PathBuf>,
    /// The most the spill files open at once may hold, `None` for no
    /// ceiling. A container that would pass it is reported unreadable.
    pub max_spill_bytes: Option<u64>,
    /// Memory, in bytes, of the block cache of an object that is read where it
    /// lies instead of being held: a file past [`Limits::max_buffer_bytes`], a
    /// container spilled to disk. One cache per such object being searched.
    /// Never below two blocks. Default 32 MiB.
    pub object_cache_bytes: u64,
    /// The size of one block of that cache, in bytes. Default 1 MiB.
    pub object_cache_block_bytes: u64,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            limits: Limits::default(),
            passwords: Vec::new(),
            before_context: 0,
            after_context: 0,
            max_count: 0,
            binary_as_matches: false,
            text: false,
            qr: false,
            qr_only: false,
            max_qr_pixels: None,
            max_qr_millis: None,
            max_qr_codes: None,
            max_qr_finders: None,
            max_qr_grids: None,
            spill_dir: None,
            max_spill_bytes: None,
            object_cache_bytes: exav_unpack::source::CACHE_BYTES as u64,
            object_cache_block_bytes: 1 << 20,
        }
    }
}

impl Options {
    /// The block size and the capacity, in bytes, of the cache of an object
    /// read where it lies.
    fn cache_sizes(&self) -> (usize, usize) {
        let block = usize::try_from(self.object_cache_block_bytes)
            .unwrap_or(usize::MAX)
            .max(1);
        let bytes = usize::try_from(self.object_cache_bytes).unwrap_or(usize::MAX);
        (block, bytes)
    }
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
        /// Why it could not be read, in the words of the layer that failed,
        /// with the characters that could change how an output reads written
        /// `_`, as in a name: a reason can quote a member's name.
        reason: String,
    },
    /// The payload of a QR code ([`Options::qr_only`]).
    Qr {
        /// Nesting path of the image the code is in.
        path: String,
        /// 1-based number of the code among those read in the image.
        index: usize,
        /// The payload, as text (invalid UTF-8 replaced). Shown with the
        /// characters that could change how an output reads written as
        /// escapes, and the backslash doubled so that an escape is never
        /// mistaken for the text.
        payload: String,
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
            Event::Qr {
                path,
                index,
                payload,
            } => {
                write!(f, "{path}:{index}:")?;
                for c in payload.chars() {
                    match c {
                        '\\' => f.write_str("\\\\")?,
                        '\n' => f.write_str("\\n")?,
                        '\r' => f.write_str("\\r")?,
                        '\t' => f.write_str("\\t")?,
                        c if exav_unpack::tree::unsafe_to_show(c) => {
                            write!(f, "\\u{{{:x}}}", u32::from(c))?
                        }
                        c => f.write_char(c)?,
                    }
                }
                Ok(())
            }
        }
    }
}

/// `ev` with the reason of an [`Event::Unreadable`] as it is shown.
fn shown_reason(ev: Event) -> Event {
    match ev {
        Event::Unreadable { path, reason } => {
            let reason = match exav_unpack::tree::shown_text(&reason) {
                std::borrow::Cow::Borrowed(_) => reason,
                std::borrow::Cow::Owned(shown) => shown,
            };
            Event::Unreadable { path, reason }
        }
        ev => ev,
    }
}

/// Drives the search. `true` from the sink continues, `false` stops early.
pub type Sink<'a> = &'a mut dyn FnMut(Event) -> bool;

/// Searches every member of a container, recursively, feeding an [`Event`] per
/// hit to a [`Sink`].
///
/// Holds the running tallies across a whole search, so one searcher is meant to
/// be reused across the inputs of a single run rather than constructed per file
/// (that is what makes `unreadable` a total the caller can act on rather than
/// a per-file curiosity). A member that could not be read is reported as
/// [`Event::Unreadable`], never skipped silently: content the search did not
/// see is not the same as content with no matches.
#[derive(Debug)]
pub struct Searcher {
    matcher: Matcher,
    opts: Options,
    /// Members that existed but could not be read, across the whole run.
    unreadable: usize,
    matched: usize,
    /// Where a container too large to hold is written, if anywhere. Its
    /// ceiling is shared by the files open at once.
    spill: Option<DirSpill>,
}

impl Searcher {
    /// Build a searcher from a compiled matcher and the search options.
    pub fn new(matcher: Matcher, opts: Options) -> Self {
        let spill = opts
            .spill_dir
            .clone()
            .map(|dir| DirSpill::new(dir).total(opts.max_spill_bytes));
        Searcher {
            matcher,
            opts,
            unreadable: 0,
            matched: 0,
            spill,
        }
    }

    /// A searcher of the QR codes in images and nothing else, over the same
    /// walk: each payload is an [`Event::Qr`], and `opts` is used as given
    /// except for [`Options::qr`], [`Options::qr_only`] and [`Options::text`].
    /// An image that does not decode, or that a limit stopped, is an
    /// [`Event::Unreadable`] and counts in [`Self::unreadable_count`];
    /// [`Self::matched_count`] counts the images with a code.
    pub fn qr_codes(mut opts: Options) -> Self {
        opts.qr = true;
        opts.qr_only = true;
        opts.text = false;
        let any = Matcher::fixed("", false).expect("the empty pattern compiles");
        Searcher::new(any, opts)
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
    /// has gone away (a closed pipe, a full disk) keeps being handed results
    /// for the rest of the walk.
    ///
    /// A file of any size is searched in bounded memory: one over
    /// [`Limits::max_buffer_bytes`] is read through a block cache, so a disk
    /// image or a multi-gigabyte log costs what its walk holds and not its
    /// size. A pseudo-file that is not a regular file is reported rather than
    /// read.
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
        let src = open_source(
            file,
            meta.len(),
            self.opts.limits.max_buffer_bytes,
            self.opts.cache_sizes(),
        )?;
        Ok(self.search_source(&label, &*src, sink))
    }

    /// Search an in-memory buffer under `label`.
    pub fn search_bytes(&mut self, label: &str, data: &[u8], sink: Sink) -> bool {
        self.search_source(label, &data, sink)
    }

    /// Search any readable-at-an-offset source under `label`. A read that
    /// failed is reported unreadable, never taken for the end of the data.
    fn search_source(&mut self, label: &str, src: &dyn ByteSource, sink: Sink) -> bool {
        let mut shown = |ev| sink(shown_reason(ev));
        let sink: Sink = &mut shown;
        let mut budget = Budget::new(self.opts.limits.clone());
        budget.passwords = self.opts.passwords.clone();
        // Only the QR search reads the pixels of a PDF image.
        budget.set_rasters(cfg!(feature = "qr") && self.opts.qr);
        let spill = self.spill.clone();
        let walk = Walk {
            hold: Hold {
                limit: self.opts.limits.max_buffer_bytes,
                spill: spill.as_ref().map(|s| s as &dyn Spill),
                cache: self.opts.cache_sizes(),
                // A member too long to hold is searched as it is read, unless
                // it is a container, which cannot be opened without seeking.
                large: Large::StreamLeaves,
            },
            // A set of split files inside a container is one file.
            sets: true,
            // A ZIP appended to a PDF is searched, as is a disk image that
            // starts as an archive.
            second_readings: true,
        };
        let walker = Walker::new(walk, &Typing::WALK);
        let mut grep = Grep {
            s: self,
            sink,
            stopped: false,
        };
        walker.run(
            Root {
                name: label,
                source: src,
            },
            &mut budget,
            &mut grep,
        );
        let go = !grep.stopped;
        let sink = grep.sink;
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

    /// Search a leaf: its QR codes under `--qr` when it is an image, its text
    /// under `--text` when it has one, else its bytes. `name` is its own name,
    /// which says what kind of document it is; `raster` says how to read its
    /// bytes as pixels when they are raw samples.
    fn search_leaf(
        &mut self,
        label: &str,
        name: &str,
        raster: Option<&Raster>,
        src: &dyn ByteSource,
        sink: Sink,
    ) -> bool {
        #[cfg(feature = "qr")]
        if !self.search_qr(label, raster, src, sink) {
            return false;
        }
        if self.opts.qr_only {
            return true;
        }
        #[cfg(feature = "text")]
        if let Some(go) = self.text_of(label, name, src, sink) {
            return go;
        }
        let _ = (name, raster);
        self.search_lines(label, src, sink)
    }

    /// Say that `path` could not be read, and why.
    #[cfg(feature = "qr")]
    fn unreadable_at(&mut self, path: String, reason: String, sink: Sink) -> bool {
        self.unreadable += 1;
        sink(Event::Unreadable { path, reason })
    }

    /// Under `--qr`, the payloads of the QR codes in `src` when it is an
    /// image (a file, or raw samples that `raster` describes), searched as
    /// `label!qr`. An image too large to read, whose reading a limit cut
    /// short, that does not decode, or that is a PDF image in a color space or
    /// with a predictor that is not read, is reported unreadable.
    ///
    /// With [`Options::qr_only`] each payload is an [`Event::Qr`] at `label`.
    #[cfg(feature = "qr")]
    fn search_qr(
        &mut self,
        label: &str,
        raster: Option<&Raster>,
        src: &dyn ByteSource,
        sink: Sink,
    ) -> bool {
        if !self.opts.qr {
            return true;
        }
        let only = self.opts.qr_only;
        let path = match only {
            true => label.to_string(),
            false => format!("{label}{NESTING_SEP}qr"),
        };
        if !exav_render::qr::wants(&src.window(0, 64), raster) {
            return true;
        }
        let cap = self.cap();
        let Some(data) = src.materialize(cap) else {
            let reason = format!("QR codes: an image over the {cap}-byte limit");
            return self.unreadable_at(path, reason, sink);
        };
        let Some(found) = exav_render::qr::search(
            &data,
            raster,
            &exav_render::qr::Settings {
                max_pixels: self.opts.max_qr_pixels,
                max_millis: self.opts.max_qr_millis,
                max_codes: self.opts.max_qr_codes,
                max_finders: self.opts.max_qr_finders,
                max_grids: self.opts.max_qr_grids,
                max_buffer_bytes: self.opts.limits.max_buffer_bytes,
            },
        ) else {
            return true;
        };
        if only {
            self.matched += usize::from(!found.payloads.is_empty());
            for (i, payload) in found.payloads.into_iter().enumerate() {
                let path = path.clone();
                if !sink(Event::Qr {
                    path,
                    index: i + 1,
                    payload,
                }) {
                    return false;
                }
            }
        } else {
            let text: String = found.payloads.iter().map(|p| format!("{p}\n")).collect();
            if !text.is_empty() && !self.search_one(&path, text.as_bytes(), sink) {
                return false;
            }
        }
        for reason in found.cut.into_iter().chain(found.unread) {
            if !self.unreadable_at(path.clone(), reason, sink) {
                return false;
            }
        }
        true
    }

    /// The text of `src` under `--text`, when it is a kind of document that has
    /// some (see [`Self::search_text`]). A document too large to hold has its
    /// text unread: reported, and `None` so its bytes are searched instead.
    #[cfg(feature = "text")]
    fn text_of(
        &mut self,
        label: &str,
        name: &str,
        src: &dyn ByteSource,
        sink: Sink,
    ) -> Option<bool> {
        if !self.opts.text {
            return None;
        }
        if !exav_render::text::wants(name, src) {
            return None;
        }
        let cap = self.cap();
        match src.materialize(cap) {
            Some(data) => self.search_text(label, name, &data, sink),
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
    fn search_text(&mut self, label: &str, name: &str, data: &[u8], sink: Sink) -> Option<bool> {
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

/// The search as the walk's visitor: told of each node, it searches the node's
/// bytes if it is a leaf, and what is left to say of a container once its
/// members have been visited.
struct Grep<'a, 'b> {
    s: &'a mut Searcher,
    sink: Sink<'b>,
    /// The sink asked to stop.
    stopped: bool,
}

impl Grep<'_, '_> {
    /// Run a search with the sink, noting when it asks to stop: nothing more
    /// is given to it after that.
    fn with<R>(&mut self, search: impl FnOnce(&mut Searcher, Sink<'_>) -> R) -> R {
        let (s, sink, stopped) = (&mut *self.s, &mut *self.sink, &mut self.stopped);
        let mut guarded = |ev: Event| {
            if *stopped {
                return false;
            }
            let go = sink(ev);
            *stopped = !go;
            go
        };
        search(s, &mut guarded)
    }

    /// Say that `path` could not be read, and why.
    fn unreadable(&mut self, path: String, reason: String) {
        self.with(|s, sink| {
            s.unreadable += 1;
            sink(Event::Unreadable { path, reason })
        });
    }

    /// Go on with the next node, or stop if the sink asked to.
    fn flow(&self) -> Flow<()> {
        match self.stopped {
            true => Flow::Stop(()),
            false => Flow::Leaf,
        }
    }

    /// `--max-unpack-depth 0`: no container is opened.
    fn opens_nothing(&self) -> bool {
        self.s.opts.limits.max_recursion == 0
    }

    /// Go on with what is under the node, or stop if the sink asked to.
    fn flow_down(&self) -> Flow<()> {
        match self.stopped {
            true => Flow::Stop(()),
            false => Flow::Descend,
        }
    }

    /// What is said of a member once its bytes have been searched: what its
    /// container says of it, and that its decoding failed part way.
    fn after(&mut self, node: &Node<'_>, label: &str, failed_reading: bool) {
        if let Some(reason) = node.meta.and_then(Reason::of_member) {
            self.unreadable(label.to_string(), reason.text);
        }
        if failed_reading || matches!(node.end, End::Damaged(_)) {
            self.unreadable(
                label.to_string(),
                "member failed to decode part way".to_string(),
            );
        }
    }

    /// Search a member too long to hold as it is read.
    fn search_stream(&mut self, node: &Node<'_>, label: &str, name: &str) -> bool {
        let Content::Stream(cell) = &node.content else {
            return false;
        };
        let head = cell.head();
        let kind = &head[..head.len().min(KIND_PROBE)];
        let cap = node.hold();
        #[cfg(feature = "text")]
        if self.s.opts.text && exav_render::text::wants(name, &kind) {
            self.unreadable(
                format!("{label}{NESTING_SEP}text"),
                format!("visible text: over the {cap}-byte limit"),
            );
        }
        #[cfg(feature = "qr")]
        if self.s.opts.qr && exav_render::image::Format::detect(kind).is_some() {
            let path = match self.s.opts.qr_only {
                true => label.to_string(),
                false => format!("{label}{NESTING_SEP}qr"),
            };
            self.unreadable(
                path,
                format!("QR codes: an image over the {cap}-byte limit"),
            );
        }
        // Nothing but the QR codes is read, and this one is not held.
        if self.s.opts.qr_only {
            return false;
        }
        let _ = (name, kind, cap);
        let Some(mut stream) = cell.take() else {
            return false;
        };
        match self.with(|s, sink| s.search_reader(label, &mut stream, sink)) {
            // What decoded was searched. Only damage that hides content, not
            // a checksum that failed after a full decode, makes it a partial
            // one. A bound that ran out ends the walk, which says so.
            Err(e) => {
                !exav_unpack::is_budget_overflow(&e) && exav_unpack::decode_error_hides_content(&e)
            }
            Ok(_) => false,
        }
    }
}

impl Visitor<()> for Grep<'_, '_> {
    fn visit(&mut self, node: &Node<'_>, cx: &mut Cx<'_>, _: &mut Reasons) -> Flow<()> {
        if self.stopped {
            return Flow::Stop(());
        }
        let label = node.path.render(PathStyle::Nested);
        let name = node.path.name().raw;
        // A container too large to hold and with nowhere to be written is
        // reported, not searched as the bytes of a file.
        if let Some(why) = node.capped {
            self.unreadable(label.clone(), why.to_string());
            self.after(node, &label, false);
            return self.flow();
        }
        let src = match &node.content {
            Content::None => {
                self.after(node, &label, false);
                return self.flow();
            }
            Content::Stream(_) => {
                let failed = self.search_stream(node, &label, name);
                self.after(node, &label, failed);
                // The walk says why it was not looked at for a container.
                return match (self.stopped, self.opens_nothing()) {
                    (true, _) => Flow::Stop(()),
                    (false, true) => Flow::Leaf,
                    (false, false) => Flow::Descend,
                };
            }
            Content::Source(src) => *src,
        };
        match node.format() {
            // With a depth of 0 no container is opened: each file is searched
            // as it stands, and nothing is said of the members not looked at.
            Typed::Container(_) if self.opens_nothing() => {
                let raster = node.meta.and_then(|m| m.raster.as_ref());
                self.with(|s, sink| s.search_leaf(&label, name, raster, src, sink));
                self.after(node, &label, false);
                match self.stopped {
                    true => Flow::Stop(()),
                    false => Flow::Leaf,
                }
            }
            // Its members are searched, not its raw bytes: for a stored member
            // those are the same bytes, and reporting both would duplicate
            // every hit. What is left to say of it is said once they are.
            Typed::Container(_) => {
                // One at the depth limit is not opened (the walk says so), and
                // is not left either: what is left to say of it is said now.
                if cx.depth_hit(node.depth).is_some() {
                    self.after(node, &label, false);
                }
                self.flow_down()
            }
            Typed::Plain | Typed::Unchecked(_) => {
                let raster = node.meta.and_then(|m| m.raster.as_ref());
                self.with(|s, sink| s.search_leaf(&label, name, raster, src, sink));
                self.after(node, &label, false);
                match (self.stopped, node.format()) {
                    (true, _) => Flow::Stop(()),
                    // The walk says why it could not be told what it is.
                    (false, Typed::Unchecked(_)) => Flow::Descend,
                    (false, _) => Flow::Leaf,
                }
            }
        }
    }

    fn reason(&mut self, at: &exav_unpack::tree::Path<'_>, reason: &Reason) {
        self.unreadable(at.render(PathStyle::Nested), reason.text.clone());
    }

    fn leave(
        &mut self,
        node: &Node<'_>,
        members: u64,
        _: &mut Cx<'_>,
        _: &mut Reasons,
    ) -> Flow<()> {
        if self.stopped {
            return Flow::Stop(());
        }
        let label = node.path.render(PathStyle::Nested);
        if let Some(src) = node.source()
            && !self.s.opts.qr_only
        {
            if members == 0 {
                // Nothing came back at all: the format was recognised but the
                // walker yielded no entries, so the bytes themselves are the
                // only content there is to look at.
                self.with(|s, sink| s.search_lines(&label, src, sink));
            } else {
                // A container with text of its own (a PDF, a drawing) is
                // searched as that too, besides its members.
                #[cfg(feature = "text")]
                {
                    let name = node.path.name().raw;
                    self.with(|s, sink| s.text_of(&label, name, src, sink));
                }
            }
        }
        self.after(node, &label, false);
        self.flow()
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

fn strip_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((b'\r', rest)) => rest,
        _ => line,
    }
}

/// A NUL byte in the first 8 KiB: the conventional binary-file heuristic.
fn looks_binary(data: &[u8]) -> bool {
    data.iter().take(8192).any(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use exav_unpack::source::BlockCache;

    fn collect(matcher: Matcher, opts: Options, label: &str, data: &[u8]) -> Vec<Event> {
        let mut out = Vec::new();
        let mut s = Searcher::new(matcher, opts);
        s.search_bytes(label, data, &mut |e| {
            out.push(e);
            true
        });
        out
    }

    /// The CRC-32 of `data`.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
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
            v.extend_from_slice(&crc32(body).to_le_bytes());
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
            directory.extend_from_slice(&crc32(body).to_le_bytes());
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

    /// A reason quotes a member's name as a path shows it.
    #[test]
    fn a_reason_quotes_a_hostile_name_as_it_is_shown() {
        let name = format!("e\u{1b}[31m\u{202e}{}", "n".repeat(300));
        let mut z = zip_indexed(&[(&name, &[b'x'; 4096])]);
        // A method no ZIP specification defines: read as stored, held whole.
        z[8] = 77;
        let at = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        z[at + 10] = 77;
        let (ev, _) = run(capped(1024), "m.zip", &z, "needle");
        let gone = unreadable(&ev);
        assert!(
            !gone
                .iter()
                .any(|(_, why)| why.contains(['\u{1b}', '\u{202e}'])),
            "{gone:?}"
        );
        let shown = format!("'e_[31m_{}'", "n".repeat(193));
        assert!(gone.iter().any(|(_, why)| why.contains(&shown)), "{gone:?}");
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
        let data = log_of(600_000);
        std::fs::write(&path, &data).unwrap();
        // Past the limit, so it goes through the block cache.
        let mut opts = capped(1 << 20);
        assert!(data.len() as u64 > opts.limits.max_buffer_bytes);
        opts.object_cache_bytes = 64 << 10;
        opts.object_cache_block_bytes = 4 << 10;
        let mut s = Searcher::new(Matcher::fixed("needle", false).unwrap(), opts);
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

    /// A gzip of `data`, in stored blocks: the one member of it is a stream
    /// decoded as it is read, with no range in its container.
    fn gzip_of(data: &[u8]) -> Vec<u8> {
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
        let mut blocks = data.chunks(65_535).peekable();
        while let Some(block) = blocks.next() {
            gz.push(u8::from(blocks.peek().is_none()));
            gz.extend_from_slice(&(block.len() as u16).to_le_bytes());
            gz.extend_from_slice(&(!(block.len() as u16)).to_le_bytes());
            gz.extend_from_slice(block);
        }
        gz.extend_from_slice(&crc32(data).to_le_bytes());
        gz.extend_from_slice(&(data.len() as u32).to_le_bytes());
        gz
    }

    /// A ZIP, in a gzip, in a ZIP: the inner one is a stream too long to hold,
    /// and a container.
    fn zip_in_gzip_in_zip() -> Vec<u8> {
        let inner = zip_indexed(&[("a.txt", &log_of(5_000)), ("deep.txt", &log_of(10_000))]);
        zip_indexed(&[("inner.gz", &gzip_of(&inner))])
    }

    #[test]
    fn a_container_over_the_limit_inside_a_member_is_reported_not_opened() {
        let outer = zip_in_gzip_in_zip();
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
                if path == "o.zip!inner.gz!gzip-content" && reason.contains("container"))),
            "got {ev:?}"
        );
    }

    /// A directory of its own under the system's temporary one.
    fn spill_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("exav-grep-test-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// With a spill directory, the container is written to a file there,
    /// opened, and its members searched; the file is gone afterwards.
    #[test]
    fn a_container_over_the_limit_inside_a_member_is_opened_through_a_spill_file() {
        let outer = zip_in_gzip_in_zip();
        let dir = spill_dir("open");
        let mut opts = capped(64 << 10);
        opts.spill_dir = Some(dir.clone());
        let mut s = Searcher::new(Matcher::fixed("needle", false).unwrap(), opts);
        let mut ev = Vec::new();
        s.search_bytes("o.zip", &outer, &mut |e| {
            ev.push(e);
            true
        });
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Match { path, line_no, .. }
                if path == "o.zip!inner.gz!gzip-content!deep.txt" && *line_no == 10_001)),
            "got {ev:?}"
        );
        assert_eq!(s.unreadable_count(), 0, "got {ev:?}");
        assert_eq!(s.spill.as_ref().unwrap().in_use(), 0);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        std::fs::remove_dir(&dir).unwrap();
    }

    /// A container that would pass the spill budget is reported, and says so.
    #[test]
    fn a_container_past_the_spill_budget_is_reported() {
        let outer = zip_in_gzip_in_zip();
        let dir = spill_dir("budget");
        let mut opts = capped(64 << 10);
        opts.spill_dir = Some(dir.clone());
        opts.max_spill_bytes = Some(100 << 10);
        let mut s = Searcher::new(Matcher::fixed("needle", false).unwrap(), opts);
        let mut ev = Vec::new();
        s.search_bytes("o.zip", &outer, &mut |e| {
            ev.push(e);
            true
        });
        assert!(shown(&ev).is_empty(), "got {ev:?}");
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Unreadable { path, reason }
                if path == "o.zip!inner.gz!gzip-content" && reason.contains("spill budget"))),
            "got {ev:?}"
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        std::fs::remove_dir(&dir).unwrap();
    }

    /// The events of a search of `data`, and the unreadable ones as
    /// `(path, reason)`.
    fn run(opts: Options, label: &str, data: &[u8], pattern: &str) -> (Vec<Event>, Searcher) {
        let mut s = Searcher::new(Matcher::fixed(pattern, false).unwrap(), opts);
        let mut ev = Vec::new();
        s.search_bytes(label, data, &mut |e| {
            ev.push(e);
            true
        });
        (ev, s)
    }

    fn unreadable(ev: &[Event]) -> Vec<(&str, &str)> {
        ev.iter()
            .filter_map(|e| match e {
                Event::Unreadable { path, reason } => Some((path.as_str(), reason.as_str())),
                _ => None,
            })
            .collect()
    }

    fn matches(ev: &[Event]) -> Vec<(&str, usize)> {
        ev.iter()
            .filter_map(|e| match e {
                Event::Match { path, line_no, .. } => Some((path.as_str(), *line_no)),
                _ => None,
            })
            .collect()
    }

    // Row 5: the depth rule is the scanner's. A container at the limit is not
    // opened and says so; a plain file at the limit is searched. A limit of 0
    // opens no container, and each file is searched as it stands.

    #[test]
    fn a_leaf_at_the_depth_limit_is_searched_and_a_container_at_it_is_reported() {
        let leaf = zip_indexed(&[("leaf.txt", b"the needle is here\n")]);
        let outer = zip_indexed(&[("inner.zip", &leaf)]);
        let at = |depth| {
            let mut opts = Options::default();
            opts.limits.max_recursion = depth;
            run(opts, "o.zip", &outer, "needle").0
        };
        // o.zip is at depth 0, inner.zip at 1, leaf.txt at 2.
        let ev = at(2);
        assert_eq!(matches(&ev), [("o.zip!inner.zip!leaf.txt", 1)]);
        assert!(unreadable(&ev).is_empty(), "{ev:?}");
        let ev = at(1);
        assert!(matches(&ev).is_empty());
        assert_eq!(
            unreadable(&ev),
            [("o.zip!inner.zip", "recursion depth exceeds 1")]
        );
        // At 0 no container is opened: o.zip is searched as the bytes it is,
        // its stored member's line among them, and nothing is said missing.
        let ev = at(0);
        let paths: Vec<_> = matches(&ev).into_iter().map(|m| m.0).collect();
        assert_eq!(paths, ["o.zip"]);
        assert!(unreadable(&ev).is_empty(), "{ev:?}");
        // A plain file at depth 0 is the leaf at the limit.
        let mut opts = Options::default();
        opts.limits.max_recursion = 0;
        let (ev, _) = run(opts, "f.txt", b"the needle is here\n", "needle");
        assert_eq!(matches(&ev), [("f.txt", 1)]);
        assert!(unreadable(&ev).is_empty());
    }

    // Row 6: a member that is its container is not walked again.

    /// An MBR whose first partition is the whole disk, and the second a gzip
    /// of a text with the needle in it.
    fn disk_that_is_its_first_partition() -> Vec<u8> {
        let mut disk = vec![0u8; 1024];
        let mut entry = |at: usize, lba: u32, sectors: u32| {
            disk[at + 4] = 0x83;
            disk[at + 8..at + 12].copy_from_slice(&lba.to_le_bytes());
            disk[at + 12..at + 16].copy_from_slice(&sectors.to_le_bytes());
        };
        entry(446, 0, 2);
        entry(462, 1, 1);
        disk[510..512].copy_from_slice(&[0x55, 0xAA]);
        let gz = gzip_of(b"the needle is here\n");
        disk[512..512 + gz.len()].copy_from_slice(&gz);
        disk
    }

    #[test]
    fn a_member_that_is_the_whole_of_its_container_is_not_walked_again() {
        let disk = disk_that_is_its_first_partition();
        let (ev, s) = run(Options::default(), "disk.img", &disk, "needle");
        assert_eq!(matches(&ev), [("disk.img!mbr-part-2!gzip-content", 1)]);
        assert_eq!(s.unreadable_count(), 0, "{ev:?}");
    }

    // Row 11: a stored member over the limit is read where it lies: no spill
    // is needed for a container in it.

    #[test]
    fn a_stored_member_over_the_limit_is_read_in_place_without_a_spill() {
        let inner = zip_indexed(&[("deep.txt", &log_of(10_000))]);
        let outer = zip_indexed(&[("inner.zip", &inner)]);
        assert!(inner.len() > 64 << 10);
        // The ZIP is not held, as one over the limit is not: a member of it is
        // a range of it.
        let cache = BlockCache::with_sizes(std::io::Cursor::new(outer), 4096, 64 << 10).unwrap();
        let mut s = Searcher::new(Matcher::fixed("needle", false).unwrap(), capped(64 << 10));
        let mut ev = Vec::new();
        s.search_source("o.zip", &cache, &mut |e| {
            ev.push(e);
            true
        });
        assert_eq!(matches(&ev), [("o.zip!inner.zip!deep.txt", 10_001)]);
        assert_eq!(s.unreadable_count(), 0, "{ev:?}");
    }

    // Row 12: a member too long to hold is told to be a container from as far
    // into it as detection looks, and what could not be told is said.

    #[test]
    fn a_member_over_the_limit_is_told_a_container_from_further_than_a_short_probe() {
        // An InstallShield installer is told by a marker 100 KB into it, and a
        // record 292 bytes on.
        let tag = b"InstallShield\0";
        let mut installer = vec![b' '; 200_000];
        installer[100_000..100_000 + tag.len()].copy_from_slice(tag);
        let record = 100_000 + tag.len() + 292;
        installer[record..record + 8].copy_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        installer[record + 16..record + 21].copy_from_slice(&[0, 0, 0, 0, 1]);
        let z = zip_indexed(&[("disk.gz", &gzip_of(&installer))]);
        let (ev, _) = run(capped(64 << 10), "a.zip", &z, "needle");
        assert!(
            unreadable(&ev).iter().any(|(path, reason)| {
                *path == "a.zip!disk.gz!gzip-content"
                    && reason.ends_with("it is a container, and its members were not examined")
            }),
            "{ev:?}"
        );
        assert!(matches(&ev).is_empty());
    }

    #[test]
    fn a_member_longer_than_detection_reaches_is_searched_and_said_not_checked() {
        let mut text = log_of(200_000);
        assert!(text.len() > 4 << 20);
        text.extend_from_slice(b"the needle again\n");
        let z = zip_indexed(&[("big.gz", &gzip_of(&text))]);
        let (ev, s) = run(capped(64 << 10), "a.zip", &z, "needle");
        assert_eq!(
            matches(&ev),
            [
                ("a.zip!big.gz!gzip-content", 200_001),
                ("a.zip!big.gz!gzip-content", 200_002)
            ]
        );
        let said = unreadable(&ev);
        assert_eq!(said.len(), 1, "{ev:?}");
        assert_eq!(said[0].0, "a.zip!big.gz!gzip-content");
        assert!(said[0].1.ends_with("was not checked"), "{}", said[0].1);
        assert_eq!(s.unreadable_count(), 1);
    }

    // Row 15: bytes of a member a reader could only partly decode are
    // searched, and the reason is still reported.

    /// The `a` of a zlib stream in stored blocks.
    fn zlib_stored(data: &[u8]) -> Vec<u8> {
        let (mut a, mut b) = (1u32, 0u32);
        for &x in data {
            a = (a + u32::from(x)) % 65_521;
            b = (b + a) % 65_521;
        }
        let mut z = vec![0x78, 0x01, 1];
        z.extend_from_slice(&(data.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(data.len() as u16)).to_le_bytes());
        z.extend_from_slice(data);
        z.extend_from_slice(&((b << 16) | a).to_be_bytes());
        z
    }

    /// A PDF with one stream, filtered by `filter`.
    fn pdf_of(filter: &str, text: &[u8]) -> Vec<u8> {
        let body = zlib_stored(text);
        let mut pdf = format!(
            "%PDF-1.4\n1 0 obj\n<< /Length {} /Filter {filter} >>\nstream\n",
            body.len()
        )
        .into_bytes();
        pdf.extend_from_slice(&body);
        pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
        pdf
    }

    #[test]
    fn the_bytes_of_a_member_that_was_partly_decoded_are_searched_and_the_reason_reported() {
        let good = pdf_of("/FlateDecode", b"hello needle in a good stream\n");
        let (ev, s) = run(Options::default(), "g.pdf", &good, "needle");
        assert_eq!(matches(&ev), [("g.pdf!pdf-obj-1-0", 1)]);
        assert_eq!(s.unreadable_count(), 0, "{ev:?}");
        let bad = pdf_of("[/FlateDecode /Foo]", b"hello needle in salvaged bytes\n");
        let (ev, s) = run(Options::default(), "u.pdf", &bad, "needle");
        assert_eq!(matches(&ev), [("u.pdf!pdf-obj-1-0", 1)]);
        let said = unreadable(&ev);
        assert_eq!(said.len(), 1, "{ev:?}");
        assert_eq!(said[0].0, "u.pdf!pdf-obj-1-0");
        assert!(said[0].1.contains("not decoded"), "{}", said[0].1);
        assert_eq!(s.unreadable_count(), 1);
    }

    // Row 23: the parts of a split file inside a container are one file.

    /// A tar of `(name, data)`, in ustar blocks.
    fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, data) in members {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..107].copy_from_slice(b"0000644");
            h[108..115].copy_from_slice(b"0000000");
            h[116..123].copy_from_slice(b"0000000");
            h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
            h[136..147].copy_from_slice(b"00000000000");
            h[156] = b'0';
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
            h[148..156].copy_from_slice(b"        ");
            let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
            h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
            tar.extend_from_slice(&h);
            tar.extend_from_slice(data);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }
        tar.extend_from_slice(&[0; 1024]);
        tar
    }

    #[test]
    fn the_parts_of_a_split_file_in_a_container_are_searched_as_the_file_they_make() {
        let gz = gzip_of(b"the needle is here\n");
        let (a, b) = gz.split_at(gz.len() / 2);
        let tar = tar_of(&[("p.txt.gz.001", a), ("p.txt.gz.002", b)]);
        let (ev, s) = run(Options::default(), "set.tar", &tar, "needle");
        assert_eq!(matches(&ev), [("set.tar!p.txt.gz!gzip-content", 1)]);
        assert_eq!(s.unreadable_count(), 0, "{ev:?}");
        // A part missing is said of each part there is, and each is still
        // searched on its own.
        let tar = tar_of(&[
            ("r.txt.001", b"the needle alone\n"),
            ("r.txt.003", b"and apart\n"),
        ]);
        let (ev, s) = run(Options::default(), "set.tar", &tar, "needle");
        assert_eq!(matches(&ev), [("set.tar!r.txt.001", 1)], "{ev:?}");
        assert_eq!(s.unreadable_count(), 2, "{ev:?}");
        assert!(
            unreadable(&ev)
                .iter()
                .all(|(_, reason)| reason.contains("incomplete multi-volume set")),
            "{ev:?}"
        );
    }

    // Row 25: a ZIP appended to a file is read as the archive it is.

    #[test]
    fn a_zip_appended_to_a_pdf_is_searched() {
        let mut pdf = pdf_of("/FlateDecode", b"nothing here\n");
        pdf.extend_from_slice(&zip_indexed(&[("s.txt", b"the secret needle\n")]));
        let (ev, s) = run(Options::default(), "pz.pdf", &pdf, "needle");
        assert_eq!(matches(&ev), [("pz.pdf!s.txt", 1)]);
        assert_eq!(s.unreadable_count(), 0, "{ev:?}");
    }

    // Row 33: a member's name cannot change how the output reads.

    #[test]
    fn a_member_name_cannot_add_a_line_or_an_escape_to_the_output() {
        let name = "evil\u{1b}[31mred\nfake: OK.txt\u{202e}gpj";
        let z = zip_of(&[(name, b"the needle is here\n")]);
        let (ev, _) = run(Options::default(), "names.zip", &z, "needle");
        assert_eq!(
            matches(&ev),
            [("names.zip!evil_[31mred_fake: OK.txt_gpj", 1)]
        );
        for e in &ev {
            assert_eq!(e.to_string().lines().count(), 1, "{e}");
        }
        // And in the path of a member that could not be read.
        let mut opts = Options::default();
        opts.limits.max_recursion = 1;
        let inner = zip_of(&[(name, b"x")]);
        let outer = zip_of(&[(name, &inner)]);
        let (ev, _) = run(opts, "names.zip", &outer, "needle");
        assert_eq!(unreadable(&ev).len(), 1, "{ev:?}");
        assert_eq!(
            unreadable(&ev)[0].0,
            "names.zip!evil_[31mred_fake: OK.txt_gpj"
        );
    }

    // Row 34: what kind of document a member is comes from its name, not from
    // the end of its rendered path.

    #[cfg(feature = "text")]
    #[test]
    fn a_member_is_a_kind_of_document_by_its_own_name_not_by_the_end_of_its_path() {
        let doc = br#"<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>visible needle words</w:t></w:r></w:p></w:body></w:document>"#;
        let opts = || Options {
            text: true,
            ..Options::default()
        };
        // A document part: searched as the words it shows.
        let z = zip_of(&[("word/document.xml", doc)]);
        let (ev, _) = run(opts(), "a.zip", &z, "visible needle");
        assert_eq!(matches(&ev), [("a.zip!word/document.xml!text", 1)]);
        // A file whose name only ends in the name of one is not.
        let z = zip_of(&[("weird!word/document.xml", doc)]);
        let (ev, _) = run(opts(), "a.zip", &z, "visible needle");
        assert!(
            matches(&ev)
                .iter()
                .all(|(path, _)| !path.ends_with("!text")),
            "{ev:?}"
        );
        assert_eq!(matches(&ev).len(), 1);
    }

    // Row 3: a packer is looked for in an executable that can be held, and
    // said not to have been for one that cannot.

    #[test]
    fn an_executable_that_cannot_be_held_is_said_not_checked_for_a_packer() {
        // Over the limit, in lines shorter than it: a longer line is cut where
        // a read ends, which depends on the size of the reads.
        let mut exe = b"MZ".to_vec();
        while exe.len() < 200 << 10 {
            exe.extend_from_slice(&[b'a'; 1023]);
            exe.push(b'\n');
        }
        exe.extend_from_slice(b"the needle is here\n");
        let path = std::env::temp_dir().join(format!("exav-grep-exe-{}.exe", std::process::id()));
        std::fs::write(&path, &exe).unwrap();
        let mut s = Searcher::new(Matcher::fixed("needle", false).unwrap(), capped(64 << 10));
        let mut ev = Vec::new();
        let r = s.search_path(&path, &mut |e| {
            ev.push(e);
            true
        });
        std::fs::remove_file(&path).unwrap();
        assert!(r.unwrap());
        let said = unreadable(&ev);
        assert_eq!(said.len(), 1, "{ev:?}");
        assert!(
            said[0].1.ends_with("whether it is packed was not checked"),
            "{}",
            said[0].1
        );
        // It is searched all the same, before it is said.
        assert!(
            matches!(ev[0], Event::Match { .. } | Event::BinaryMatch { .. }),
            "{ev:?}"
        );
    }
}
