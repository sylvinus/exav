//! The one pass over an object read through a block cache.
//!
//! The searches that need every byte of such an object, in order, are fed
//! from a single read of it: carving, the digests, the search for a message
//! in a text file, the signature sweep and YARA's patterns. Detection is not
//! among them: it reads the object's start and the places its structure
//! names. This module holds what they share:
//! the [`Tap`] a search implements and the [`Fed`] that hands it each byte
//! once, whichever reader drives the read.

use crate::byte_source::{ByteSource, CHUNK};
use crate::engine;
use crate::filetype::FileType;
use crate::{Facts, ScanOptions, Scanner, Shared, hashes, mail_inside, pe, profile};

/// A search fed the bytes of an object, in order, once.
pub(crate) trait Tap {
    /// The bytes `at..at + w.len()` of the object, where the last call left off.
    fn feed(&mut self, at: usize, w: &[u8]);

    /// Whether bytes not yet fed could still change what the tap finds.
    fn wants_more(&self) -> bool;
}

/// A [`Tap`] and how far it has been fed. The reader that drives the read
/// hands it every window it reads. A window may overlap what was already fed
/// or start past it: only the new bytes reach the tap, in order, and a gap is
/// read from the object first.
pub(crate) struct Fed<'a> {
    tap: &'a mut dyn Tap,
    data: &'a dyn ByteSource,
    at: usize,
}

impl<'a> Fed<'a> {
    pub(crate) fn new(tap: &'a mut dyn Tap, data: &'a dyn ByteSource) -> Self {
        Fed { tap, data, at: 0 }
    }

    /// Hand the tap the bytes of `w`, which starts at `at`, that it was not
    /// given yet. A window that starts past what was fed leaves a gap, which
    /// is read from the object first, so no byte is skipped.
    pub(crate) fn feed(&mut self, at: usize, w: &[u8]) {
        let end = at + w.len();
        if end <= self.at {
            return;
        }
        if at > self.at {
            self.fill(at);
            if self.at < at {
                // The gap could not be read in full: the source records the
                // failure (`read_error`), and nothing more is fed.
                return;
            }
        }
        self.tap.feed(self.at, &w[self.at - at..]);
        self.at = end;
    }

    /// Read what lies between what was fed and `to`, and feed it.
    fn fill(&mut self, to: usize) {
        while self.at < to {
            let w = self.data.window(self.at, (to - self.at).min(CHUNK));
            if w.is_empty() {
                return;
            }
            self.tap.feed(self.at, &w);
            self.at += w.len();
        }
    }

    /// Read the rest of the object, as far as the tap wants it, and feed it.
    pub(crate) fn drain(&mut self) {
        let len = self.data.len();
        while self.at < len && self.tap.wants_more() {
            let w = self.data.window(self.at, (len - self.at).min(CHUNK));
            if w.is_empty() {
                return;
            }
            self.tap.feed(self.at, &w);
            self.at += w.len();
        }
    }
}

/// When the read of an object is asked for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Why {
    /// A step wants what the read finds out about the object (its format, its
    /// digests, the images carved from it), whatever the core finds.
    Search,
    /// The matching core wants the signature engine's answer. A detection
    /// ends the scan of the object, so what the read would go on to feed the
    /// other searches is not needed.
    Match,
}

/// What the matching core will run over an object: what the read of it needs
/// to know to run the signature engine and YARA's patterns over the bytes it
/// reads, the way the core will.
#[derive(Clone, Copy)]
pub(crate) struct Matching<'a> {
    pub(crate) db: &'a Scanner,
    pub(crate) opts: &'a ScanOptions,
    /// The type of the container the object sits in.
    pub(crate) container: Option<engine::ClType>,
    /// The types of the containers above it.
    pub(crate) ancestry: engine::Ancestors<'a>,
    /// The type the core takes the object for, when its container decides it.
    pub(crate) core_type: Option<FileType>,
    /// Whether the scan collects every detection rather than the first.
    pub(crate) all: bool,
}

/// What the signature engine found in the read of an object, kept until the
/// core asks, with the effects the scan would have had.
pub(crate) struct EngineRun {
    /// The type the engine ran as.
    ft: FileType,
    /// The detections: name, offset, and whether the signature is unofficial.
    pub(crate) found: Vec<(String, u64, bool)>,
    /// The bytecode triggers that fired.
    pub(crate) fired: Vec<engine::Fired>,
    /// A type a `HandlerType:` signature decided.
    retype: Option<FileType>,
    /// Whether a check stopped short, which the scan reports if it is not clean.
    truncated: bool,
    /// Whether the detection ended the sweep.
    stopped: bool,
}

impl EngineRun {
    /// Take on the effects the run had in the engine's own state, now that
    /// the core uses its answer.
    pub(crate) fn apply(&self, data: &dyn ByteSource) {
        if self.truncated {
            engine::mark_scan_truncated();
        }
        if let Some(ft) = self.retype {
            engine::set_retype(data, ft);
        }
    }
}

/// Whether a type has a layout read from its headers, which a signature's
/// offsets are measured against.
fn has_layout(ft: FileType) -> bool {
    matches!(ft, FileType::Pe | FileType::Elf | FileType::MachO)
}

/// The searches fed from the one read of an object: those the object's steps
/// asked for, and YARA's patterns.
struct Taps<'a> {
    data: &'a dyn ByteSource,
    len: usize,
    /// Where the last bytes fed end.
    end: usize,
    hashing: Option<hashes::Hashing>,
    carving: Option<pe::Carving>,
    /// How many times each byte occurs, for the static model.
    counts: Option<Box<[u64; 256]>>,
    /// The search for a message inside a text file.
    mail: Option<mail_inside::Search>,
    #[cfg(feature = "yara")]
    yara: Option<crate::yara::YaraFeed<'a>>,
    /// The window and what follows it, which carving sees across the seam.
    ahead: Vec<u8>,
}

impl Taps<'_> {
    /// Bytes each window runs into the next.
    const OVERLAP: usize = pe::Carving::OVERLAP;

    fn searching(&self) -> bool {
        self.carving.as_ref().is_some_and(|c| !c.full())
            || self.mail.as_ref().is_some_and(|m| !m.done())
    }

    fn fully_fed(&self) -> bool {
        self.end >= self.len
    }
}

impl Tap for Taps<'_> {
    fn feed(&mut self, at: usize, w: &[u8]) {
        let end = at + w.len();
        self.end = end;
        if let Some(h) = &mut self.hashing {
            h.update(w);
        }
        if let Some(c) = &mut self.counts {
            for &b in w {
                c[usize::from(b)] += 1;
            }
        }
        if let Some(m) = self.mail.as_mut().filter(|m| !m.done()) {
            m.feed(at, w, end >= self.len);
        }
        if let Some(c) = self.carving.as_mut().filter(|c| !c.full()) {
            self.ahead.clear();
            self.ahead.extend_from_slice(w);
            if end < self.len {
                self.ahead
                    .extend_from_slice(&self.data.window(end, Self::OVERLAP));
            }
            c.feed(self.data, at, &self.ahead, w.len());
        }
        #[cfg(feature = "yara")]
        if let Some(y) = &mut self.yara {
            y.feed(at, w);
        }
    }

    fn wants_more(&self) -> bool {
        #[cfg(feature = "yara")]
        let yara = self.yara.as_ref().is_some_and(|y| y.wants_more());
        #[cfg(not(feature = "yara"))]
        let yara = false;
        self.hashing.is_some() || self.counts.is_some() || self.searching() || yara
    }
}

impl<'a> Facts<'a> {
    /// Say what the matching core will run over the object, so that the one
    /// read of it feeds the signature engine and YARA's patterns too.
    pub(crate) fn will_match(&self, m: Matching<'a>) {
        if self.shared.get().is_some() {
            self.matching.set(Some(m));
        }
    }

    /// Say that nothing will use the images carved from the object, unless
    /// it is `keep`.
    pub(crate) fn carve_only(&self, keep: bool) {
        if !keep && let Some(mut s) = self.shared.take() {
            s.carve = false;
            self.shared.set(Some(s));
        }
    }

    /// What the signature engine finds in the object as `ft`: the answer of
    /// the one read, if it ran the engine as a type the scan cannot tell from
    /// `ft`.
    pub(crate) fn engine_answer(&self, ft: FileType) -> Option<EngineRun> {
        if self.matching.get().is_some() {
            self.read_once(Why::Match);
        }
        let run = self.engine_run.take()?;
        let same = run.ft == ft
            || (!has_layout(ft) && !has_layout(run.ft) && engine::same_view(run.ft, ft));
        same.then_some(run)
    }

    /// What the read found of YARA's patterns, if it found it.
    pub(crate) fn yara_pass(&self) -> Option<crate::yara::YaraPass> {
        self.yara_pass.take()
    }

    /// Whether the object holds a UPX pack header, as
    /// [`pe::upx_header_in`] says: in its start.
    pub(crate) fn upx_header(&self) -> bool {
        *self.upx.get_or_init(|| pe::upx_header_in(self.data))
    }

    /// The offset of the first line of the first pair of header lines that
    /// makes a message of the object, as clamscan reads one from a text file:
    /// found in the one read, or by a search of its own.
    #[cfg(feature = "email")]
    fn mail_pair(&self) -> Option<usize> {
        if self.shared.get().is_some_and(|s| s.mail) {
            self.read_once(Why::Search);
        }
        match self.mail.take() {
            Some(search) => search.found(),
            None => mail_inside::first_pair(self.data, true),
        }
    }

    /// Where the message inside the object starts, if there is one: the first
    /// of the header lines above the first pair, read back no further than
    /// `back` bytes. A page of HTML (`whole` false) is looked into only at its
    /// start.
    #[cfg(feature = "email")]
    pub(crate) fn mail_start(&self, whole: bool, back: usize) -> Option<usize> {
        let pair = if whole {
            self.mail_pair()
        } else {
            mail_inside::first_pair(self.data, false)
        }?;
        Some(mail_inside::block_start(self.data, pair, back))
    }

    /// How many times each byte occurs in the object, if the one read counted
    /// them for the static model.
    pub(crate) fn byte_counts(&self) -> Option<&[u64; 256]> {
        if self.shared.get().is_some_and(|s| s.counts) {
            self.read_once(Why::Search);
        }
        self.counts.get().map(|c| &**c)
    }

    /// The one read of an object not held in memory, the first time a step
    /// asks, if it was not made yet.
    pub(crate) fn read_once(&self, why: Why) {
        let Some(Shared {
            want,
            carve,
            far,
            counts,
            mail,
            caps,
        }) = self.shared.take()
        else {
            return;
        };
        let matching = self.matching.take();
        let (data, len) = (self.data, self.data.len());
        let engine = matching.filter(|m| !m.db.engine.is_empty());
        #[cfg(feature = "yara")]
        let yara = matching.and_then(|m| m.db.yara.feed(data, &crate::whole_limits(m.opts)));
        #[cfg(not(feature = "yara"))]
        let yara = None::<()>;
        if want == hashes::Want::default()
            && !carve
            && !counts
            && !mail
            && engine.is_none()
            && yara.is_none()
        {
            return;
        }
        let mut taps = Taps {
            data,
            len,
            end: 0,
            hashing: (want != hashes::Want::default()).then(|| hashes::Hashing::new(want)),
            carving: carve.then(|| pe::Carving::new(far, caps)),
            counts: counts.then(|| Box::new([0; 256])),
            mail: mail.then(mail_inside::Search::new),
            #[cfg(feature = "yara")]
            yara,
            ahead: Vec::new(),
        };
        let mut run = None;
        {
            let mut fed = Fed::new(&mut taps, data);
            if let Some(m) = engine {
                run = self.run_engine(m, &mut fed);
            }
            // The core stops at a detection. When the matching core asked for
            // the read and the engine detected, the rest of the object is not
            // read for the other searches: a step that needs one reads the
            // object for it.
            if !(why == Why::Match && run.as_ref().is_some_and(|r| r.stopped)) {
                fed.drain();
            }
        }
        // What a search saw all it needed of is kept; the others are made when
        // a step asks, by a read of their own.
        let complete = taps.fully_fed();
        if let Some(h) = taps.hashing.filter(|_| complete) {
            let _ = self.digests.set(h.finish());
        }
        if let Some(mut c) = taps.carving.filter(|c| complete || c.full()) {
            c.settle(data);
            *self.embedded.borrow_mut() = Some(c.found);
        }
        if let Some(c) = taps.counts.filter(|_| complete) {
            let _ = self.counts.set(c);
        }
        *self.mail.borrow_mut() = taps.mail.filter(|m| complete || m.done());
        #[cfg(feature = "yara")]
        {
            *self.yara_pass.borrow_mut() = taps.yara.and_then(|y| y.finish());
        }
        *self.engine_run.borrow_mut() = run;
    }

    /// Run the signature engine over the object as the core will, feeding the
    /// read to `fed`. `None` when the engine has to run on its own: the type
    /// the core will take the object for is a PE and a signature database
    /// of icons is loaded, which the core matches against its image.
    fn run_engine(&self, m: Matching<'a>, fed: &mut Fed) -> Option<EngineRun> {
        let (db, opts, data) = (m.db, m.opts, self.data);
        let ft = m.core_type.unwrap_or_else(|| db.identify_inner(self));
        if ft == FileType::Pe && !db.icons.is_empty() {
            return None;
        }
        // The layout as the core finds it. The core marks the scan if a PE's
        // image does not fit, when it asks: not made here, where the scan may
        // end without it.
        let layout = engine::unmarked(|| {
            crate::layout_of(ft, crate::pe_image(ft, data, opts).as_deref(), data)
        });
        let limits = crate::whole_limits(opts);
        let suffix = opts.unofficial_suffix;
        let skip = |name: &str, unofficial: bool| crate::is_ignored(db, name, unofficial, suffix);
        let icons = engine::IconCtx::new(&db.icons, &[]);
        let mut fired = Vec::new();
        let mut found = Vec::new();
        let ((), truncated) = engine::deferred_flags(|| {
            profile::timed("engine", data.len() as u64, || {
                if m.all {
                    db.engine.scan_all_fed(
                        data,
                        ft,
                        layout.as_ref(),
                        m.container,
                        m.ancestry,
                        Some(&icons),
                        &mut found,
                        limits,
                        Some(&mut fired),
                        Some(&mut *fed),
                    );
                } else {
                    found.extend(db.engine.scan_first_fed(
                        data,
                        ft,
                        layout.as_ref(),
                        m.container,
                        m.ancestry,
                        Some(&icons),
                        &skip,
                        limits,
                        Some(&mut fired),
                        Some(&mut *fed),
                    ));
                }
            });
        });
        // Taken here, so it cannot outlive the object and retype a later one
        // at the same address; given back when the core takes the answer.
        let retype = engine::take_retype_source(data);
        Some(EngineRun {
            ft,
            stopped: !m.all && !found.is_empty(),
            found,
            fired,
            retype,
            truncated,
        })
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::Tap;

    /// A tap that keeps the bytes it is fed, and fails if a call does not
    /// start where the last one ended.
    #[derive(Default)]
    pub(crate) struct Recorder {
        pub(crate) bytes: Vec<u8>,
        /// It wants no more once it holds this many bytes.
        pub(crate) enough: Option<usize>,
    }

    impl Tap for Recorder {
        fn feed(&mut self, at: usize, w: &[u8]) {
            assert_eq!(at, self.bytes.len(), "a call starts where the last ended");
            self.bytes.extend_from_slice(w);
        }

        fn wants_more(&self) -> bool {
            self.enough.is_none_or(|n| self.bytes.len() < n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Recorder;
    use super::*;
    use crate::byte_source::BlockCache;

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 251) as u8).collect()
    }

    /// The bytes of `d` a tap is fed through `Fed`, given `windows` as
    /// `(start, end)` of `d`, then drained.
    fn fed_through(d: &[u8], src: &dyn ByteSource, windows: &[(usize, usize)]) -> Vec<u8> {
        let mut rec = Recorder::default();
        let mut fed = Fed::new(&mut rec, src);
        for &(a, b) in windows {
            fed.feed(a, &d[a..b]);
        }
        fed.drain();
        rec.bytes
    }

    /// A window the tap was given already, one that overlaps what it has, one
    /// inside it and one past a gap reach it as the bytes it lacks, once, in
    /// order, whether the gap is read from memory or through a cache.
    #[test]
    fn a_tap_is_given_each_byte_once_in_order() {
        let d = data(3 * CHUNK + 100);
        let windows = [
            (0, 100),
            (0, 100),
            (50, 150),
            (300, 400),
            (350, 370),
            (390, 440),
            (440, 440),
            (2 * CHUNK, 2 * CHUNK + 5),
        ];
        let held: &[u8] = &d;
        assert_eq!(fed_through(&d, &held, &windows), d);
        let cache = BlockCache::with_sizes(std::io::Cursor::new(d.clone()), 61, 4 * 61).unwrap();
        assert_eq!(fed_through(&d, &cache, &windows), d);
        // Without a window it is the drain that reads everything.
        assert_eq!(fed_through(&d, &held, &[]), d);
    }

    /// A window past the end of the object feeds the object up to its end
    /// and nothing else; so do the windows after it.
    #[test]
    fn a_window_past_the_end_of_the_object_feeds_what_there_is() {
        let d = data(1000);
        let held: &[u8] = &d;
        let mut rec = Recorder::default();
        let mut fed = Fed::new(&mut rec, &held);
        fed.feed(0, &d[..100]);
        fed.feed(2000, &[1, 2, 3]);
        fed.feed(2003, &[4, 5]);
        fed.drain();
        assert_eq!(rec.bytes, d);
    }

    /// A drain reads only while the tap wants more, a chunk at a time.
    #[test]
    fn a_drain_stops_when_the_tap_wants_no_more() {
        let d = data(4 * CHUNK + 3);
        let held: &[u8] = &d;
        let mut rec = Recorder {
            enough: Some(CHUNK + 1),
            ..Recorder::default()
        };
        Fed::new(&mut rec, &held).drain();
        assert_eq!(rec.bytes, d[..2 * CHUNK]);
    }
}
