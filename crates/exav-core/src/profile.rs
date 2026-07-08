//! Optional per-matcher profiling.
//!
//! When enabled on the current thread (via [`enable`]), each instrumented
//! matcher records its wall time, invocation count, and bytes of input through
//! [`timed`]. After a scan, [`take`] returns the accumulated [`Profile`] so a
//! caller can emit a per-file breakdown (the CLI's `--perf-json` mode). When
//! profiling is *not* enabled, [`timed`] is just the wrapped call plus one cheap
//! thread-local check, so it's safe to leave on the hot scan path.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::Instant;

thread_local! {
    static CURRENT: RefCell<Option<Profile>> = const { RefCell::new(None) };
}

/// Per-matcher accumulated statistics for one scan.
#[derive(Default, Clone)]
pub struct Profile {
    matchers: BTreeMap<&'static str, Stat>,
}

/// Time, call count, and input bytes attributed to one matcher.
#[derive(Default, Clone, Copy)]
pub struct Stat {
    /// Total nanoseconds spent in this matcher.
    pub ns: u64,
    /// Number of times the matcher was invoked.
    pub calls: u64,
    /// Total bytes of input handed to the matcher.
    pub bytes: u64,
}

impl Profile {
    /// Iterate `(matcher_name, stat)` in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, Stat)> + '_ {
        self.matchers.iter().map(|(k, v)| (*k, *v))
    }
}

/// Begin profiling on this thread, discarding any in-progress profile.
pub fn enable() {
    CURRENT.with(|c| *c.borrow_mut() = Some(Profile::default()));
}

/// Stop profiling on this thread and return the accumulated profile, or `None`
/// if profiling was never enabled.
pub fn take() -> Option<Profile> {
    CURRENT.with(|c| c.borrow_mut().take())
}

#[inline]
fn active() -> bool {
    CURRENT.with(|c| c.borrow().is_some())
}

/// Run `f`, attributing its wall time and `bytes` of input to matcher `name`
/// when profiling is active; otherwise just runs `f`. Re-entrant: no borrow is
/// held across `f`, so nested instrumented calls accumulate independently.
#[inline]
pub fn timed<T>(name: &'static str, bytes: u64, f: impl FnOnce() -> T) -> T {
    if !active() {
        return f();
    }
    let t = Instant::now();
    let r = f();
    let ns = t.elapsed().as_nanos() as u64;
    CURRENT.with(|c| {
        if let Some(p) = c.borrow_mut().as_mut() {
            let e = p.matchers.entry(name).or_default();
            e.ns += ns;
            e.calls += 1;
            e.bytes += bytes;
        }
    });
    r
}
