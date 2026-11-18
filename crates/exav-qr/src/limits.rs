// Written for exav, not part of rqrr. Same license as the crate:
// (MIT OR Apache-2.0) AND ISC, see LICENSE-*.

//! What a search may spend, and the count of what it has spent.
//!
//! The search never unwinds and never aborts for a limit: its loops count
//! their steps in a [`Meter`], and past a limit they stop and return what they
//! have, with the reason in [`Stop`].

use std::cell::Cell;
use std::fmt;
use std::time::Instant;

/// What a search for QR codes may spend. `None` is no limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SearchLimits {
    /// When the search must be over. The clock is read once every
    /// [`CHECK_EVERY`] steps, so a search may run a little past it.
    pub deadline: Option<Instant>,
    /// Finder patterns found in the image. When one more is found the search
    /// for patterns ends; the ones found are still grouped and read.
    pub max_finder_patterns: Option<usize>,
    /// Groups of three finder patterns tried as a grid, each on a copy of the
    /// image. When one more would be tried the trials end; the groups already
    /// found are still read.
    pub max_candidate_grids: Option<usize>,
    /// Bytes of memory: the grey image and the working buffers of the search,
    /// counted by the size of what is allocated (one byte for a pixel), not by
    /// the allocator.
    pub max_bytes: Option<u64>,
}

/// Why a search ended before its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// [`SearchLimits::deadline`] came.
    Deadline,
    /// [`SearchLimits::max_bytes`] would be passed, or an allocation failed.
    Memory,
    /// [`SearchLimits::max_finder_patterns`] was passed.
    FinderPatterns,
    /// [`SearchLimits::max_candidate_grids`] was passed.
    CandidateGrids,
}

impl fmt::Display for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Stop::Deadline => "the search ran past its deadline",
            Stop::Memory => "the search needs more memory than it may use",
            Stop::FinderPatterns => "the image has more finder patterns than the limit",
            Stop::CandidateGrids => "the image has more candidate grids than the limit",
        })
    }
}

impl std::error::Error for Stop {}

/// Steps of work between two reads of the clock.
pub const CHECK_EVERY: u64 = 1 << 15;

/// The limits of one search and what it has spent so far. It is shared by
/// reference down the search, so its counters are cells.
#[derive(Clone, Debug, Default)]
pub(crate) struct Meter {
    limits: SearchLimits,
    work: Cell<u64>,
    next_check: Cell<u64>,
    bytes: Cell<u64>,
    finder_patterns: Cell<usize>,
    candidate_grids: Cell<usize>,
    /// A limit the search cannot go on past; the first one reached.
    stop: Cell<Option<Stop>>,
    /// A cap that ended one phase of the search: the next phases still run on
    /// what the phase found.
    cut: Cell<Option<Stop>>,
}

impl Meter {
    pub fn new(limits: SearchLimits) -> Self {
        Meter {
            limits,
            next_check: Cell::new(CHECK_EVERY),
            ..Meter::default()
        }
    }

    /// No limit at all.
    pub fn unlimited() -> Self {
        Meter::new(SearchLimits::default())
    }

    /// The reason the search cannot go on, if it cannot: its deadline came or
    /// its memory is spent. The loops of the search end when it does, and what
    /// they hold then is not to be relied on.
    pub fn stopped(&self) -> Option<Stop> {
        self.stop.get()
    }

    pub fn is_stopped(&self) -> bool {
        self.stop.get().is_some()
    }

    fn stop(&self, why: Stop) {
        if self.stop.get().is_none() {
            self.stop.set(Some(why));
        }
    }

    fn cut(&self, why: Stop) {
        if self.cut.get().is_none() {
            self.cut.set(Some(why));
        }
    }

    /// Why the search ended early, if it did.
    pub fn outcome(&self) -> Option<Stop> {
        self.stop.get().or(self.cut.get())
    }

    /// Counts `units` of work. Returns `false` when the search cannot go on;
    /// the clock is read only when `CHECK_EVERY` steps have passed since it
    /// was last read.
    pub fn charge(&self, units: u64) -> bool {
        if self.is_stopped() {
            return false;
        }
        let work = self.work.get().saturating_add(units);
        self.work.set(work);
        if work >= self.next_check.get() {
            self.next_check.set(work.saturating_add(CHECK_EVERY));
            if self.limits.deadline.is_some_and(|d| Instant::now() >= d) {
                self.stop(Stop::Deadline);
                return false;
            }
        }
        true
    }

    /// Counts `bytes` as held. Returns `false`, and holds nothing, when that
    /// passes the budget.
    pub fn reserve(&self, bytes: u64) -> bool {
        let total = self.bytes.get().saturating_add(bytes);
        if self.limits.max_bytes.is_some_and(|max| total > max) {
            self.stop(Stop::Memory);
            return false;
        }
        self.bytes.set(total);
        true
    }

    /// An allocation the budget allowed failed.
    pub fn out_of_memory(&self) {
        self.stop(Stop::Memory);
    }

    /// Counts `bytes` as no longer held.
    pub fn release(&self, bytes: u64) {
        self.bytes.set(self.bytes.get().saturating_sub(bytes));
    }

    /// Counts a finder pattern. Returns `false` when it is past the cap, and
    /// is not counted.
    pub fn count_finder_pattern(&self) -> bool {
        let n = self.finder_patterns.get();
        if self.limits.max_finder_patterns.is_some_and(|max| n >= max) {
            self.cut(Stop::FinderPatterns);
            return false;
        }
        self.finder_patterns.set(n + 1);
        true
    }

    /// Counts a group of finder patterns tried as a grid. Returns `false`
    /// when it is past the cap, and is not counted.
    pub fn count_candidate_grid(&self) -> bool {
        let n = self.candidate_grids.get();
        if self.limits.max_candidate_grids.is_some_and(|max| n >= max) {
            self.cut(Stop::CandidateGrids);
            return false;
        }
        self.candidate_grids.set(n + 1);
        true
    }

    pub fn finder_patterns(&self) -> usize {
        self.finder_patterns.get()
    }

    pub fn candidate_grids(&self) -> usize {
        self.candidate_grids.get()
    }
}
