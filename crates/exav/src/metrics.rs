//! What a running listener can say about where its time went.
//!
//! A one-shot scan can be timed from outside — `time exav file`, or
//! `--perf-csv` for a per-matcher breakdown. A listener cannot: it is a
//! long-lived process serving objects nobody kept, and "the box is at 100% CPU"
//! is all an operator gets from the outside. Answering *which* objects, and
//! which matcher inside them, needs the process to keep count itself.
//!
//! So every scan on the clamd and ICAP listeners is timed, and the totals are
//! reported through the clamd `STATS` command — the one channel a clamd client
//! already knows how to ask on, and which `clamdtop` already polls.
//!
//! Two costs, kept apart because they are not the same size:
//!
//! * **Timing and counting** is one [`Instant::now`] pair per scan against work
//!   measured in milliseconds. Always on; a listener that cannot say how busy it
//!   is cannot be tuned.
//! * **The per-matcher breakdown** is a timer around every matcher invocation,
//!   and there are many per scan. Opt-in, behind `--profile-scans`, because the
//!   overhead is proportional to how much work is being measured.
//!
//! ## Under the worker pool
//!
//! The prefork daemon answers each connection from a forked child, so these
//! counters live in whichever process handled the request and cover that
//! process's own jobs. `STATS` says so rather than presenting one worker's
//! numbers as the pool's. The thread-model daemon (`--workers 0`) and the ICAP
//! listener are single processes, where the totals are the whole story.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use exav_core::profile::Profile;

/// Matchers reported in the breakdown, in a fixed order so successive `STATS`
/// replies line up. The same set `--perf-csv` uses; a matcher the engine names
/// but this list does not is folded into `other`.
pub(crate) const MATCHERS: &[&str] = &[
    "engine",
    "yara",
    "hashes",
    "sections",
    "cdb",
    "fuzzy",
    "bytecode",
    "static",
    "normalize",
];

/// Counters for one matcher.
struct MatcherCell {
    ns: AtomicU64,
    calls: AtomicU64,
    bytes: AtomicU64,
}

impl MatcherCell {
    const fn new() -> Self {
        Self {
            ns: AtomicU64::new(0),
            calls: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }
}

/// One cell per name in [`MATCHERS`], plus a trailing cell for anything else.
/// Sized from the list so the two cannot drift.
const CELLS: usize = MATCHERS.len() + 1;

/// Index of the catch-all cell.
const OTHER: usize = MATCHERS.len();

// `AtomicU64` is not `Copy`, so the array cannot be built with `[expr; N]` and
// the cells have to be listed. The declared length is `CELLS`, derived from
// `MATCHERS`, so adding a matcher name without adding a cell fails to compile
// rather than silently dropping that matcher's numbers.
static MATCHER_CELLS: [MatcherCell; CELLS] = [
    MatcherCell::new(),
    MatcherCell::new(),
    MatcherCell::new(),
    MatcherCell::new(),
    MatcherCell::new(),
    MatcherCell::new(),
    MatcherCell::new(),
    MatcherCell::new(),
    MatcherCell::new(),
    MatcherCell::new(),
];

static SCANS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static NANOS: AtomicU64 = AtomicU64::new(0);
static SLOWEST_NS: AtomicU64 = AtomicU64::new(0);
static SLOW: AtomicU64 = AtomicU64::new(0);
static INFECTED: AtomicU64 = AtomicU64::new(0);
static PARTIAL: AtomicU64 = AtomicU64::new(0);
static IN_FLIGHT: AtomicU64 = AtomicU64::new(0);

/// Whether the per-matcher breakdown is being collected.
static PROFILING: AtomicBool = AtomicBool::new(false);

/// How long a scan may take before it is logged, in nanoseconds. `0` disables
/// the report.
static SLOW_AFTER_NS: AtomicU64 = AtomicU64::new(0);

/// Install the reporting settings, once, at startup.
pub(crate) fn configure(profile: bool, slow_after: Option<Duration>) {
    PROFILING.store(profile, Ordering::Relaxed);
    SLOW_AFTER_NS.store(
        slow_after.map(|d| d.as_nanos() as u64).unwrap_or(0),
        Ordering::Relaxed,
    );
}

/// Whether a scan should collect a per-matcher profile.
pub(crate) fn profiling() -> bool {
    PROFILING.load(Ordering::Relaxed)
}

/// Scans running right now, for the `QUEUE`/`THREADS` fields a clamd client
/// polls to see whether the server is saturated.
pub(crate) fn in_flight() -> u64 {
    IN_FLIGHT.load(Ordering::Relaxed)
}

/// Log the totals every `interval`, from whichever process is serving.
///
/// `STATS` answers only where a clamd listener exists and only for the process
/// that answers it, and neither is a given: an ICAP-only deployment binds no
/// clamd port at all, and under the worker pool ICAP is a forked child of its
/// own. A line in the log is the one channel every arrangement has — which for a
/// container means `docker logs` answers "how busy, how fast" without anything
/// being wired up first.
///
/// Started per serving process, after any fork, because threads do not survive
/// one. Silent while nothing is being scanned, so an idle deployment stays quiet.
pub(crate) fn spawn_reporter(interval: Duration, what: &'static str) {
    if interval.is_zero() {
        return;
    }
    std::thread::spawn(move || {
        let mut last = SCANS.load(Ordering::Relaxed);
        loop {
            std::thread::sleep(interval);
            let now = SCANS.load(Ordering::Relaxed);
            if now == last {
                continue;
            }
            last = now;
            for line in stats_block().lines() {
                eprintln!("exav: {what}: {line}");
            }
        }
    });
}

/// Scans finished by this process, for the tests that check a surface counts
/// what it scanned.
#[cfg(test)]
pub(crate) fn scans() -> u64 {
    SCANS.load(Ordering::Relaxed)
}

/// A scan in progress, and the counters it will land in when it finishes.
///
/// A guard rather than a pair of calls, so a scan that leaves early — a panic
/// caught by the surrounding handler, a client that vanished — is still counted
/// and still leaves the in-flight gauge where it found it. A gauge that only
/// decrements on the happy path reads as a permanently busy server.
pub(crate) struct ScanTimer {
    start: std::time::Instant,
}

impl ScanTimer {
    /// Start timing, and enable per-matcher profiling on this thread when it is
    /// switched on.
    pub(crate) fn start() -> Self {
        IN_FLIGHT.fetch_add(1, Ordering::Relaxed);
        if profiling() {
            exav_core::profile::enable();
        }
        Self {
            start: std::time::Instant::now(),
        }
    }

    /// Record the finished scan. `target` names the object for the slow-scan
    /// line; `bytes` is its size.
    pub(crate) fn finish(self, target: &str, bytes: u64, category: Category) {
        let elapsed = self.start.elapsed();
        let ns = elapsed.as_nanos() as u64;
        IN_FLIGHT.fetch_sub(1, Ordering::Relaxed);
        SCANS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(bytes, Ordering::Relaxed);
        NANOS.fetch_add(ns, Ordering::Relaxed);
        SLOWEST_NS.fetch_max(ns, Ordering::Relaxed);
        match category {
            Category::Infected => {
                INFECTED.fetch_add(1, Ordering::Relaxed);
            }
            Category::Partial => {
                PARTIAL.fetch_add(1, Ordering::Relaxed);
            }
            Category::Clean => {}
        }

        let profile = exav_core::profile::take();
        if let Some(p) = &profile {
            for (name, stat) in p.iter() {
                let cell = &MATCHER_CELLS[index_of(name)];
                cell.ns.fetch_add(stat.ns, Ordering::Relaxed);
                cell.calls.fetch_add(stat.calls, Ordering::Relaxed);
                cell.bytes.fetch_add(stat.bytes, Ordering::Relaxed);
            }
        }

        let threshold = SLOW_AFTER_NS.load(Ordering::Relaxed);
        if threshold > 0 && ns >= threshold {
            SLOW.fetch_add(1, Ordering::Relaxed);
            // The point of the line is to name the object, because the next
            // question is always "which one?" and a listener holds nothing to
            // go back to. The breakdown follows when there is one.
            eprintln!(
                "exav: slow scan: {:.3}s for {} bytes of {target}{}",
                elapsed.as_secs_f64(),
                bytes,
                profile
                    .map(|p| format!(" [{}]", breakdown(&p)))
                    .unwrap_or_default()
            );
        }
    }
}

/// Which column of the verdict counters a scan lands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Category {
    Clean,
    Infected,
    Partial,
}

impl From<exav_core::VerdictCategory> for Category {
    fn from(c: exav_core::VerdictCategory) -> Self {
        match c {
            exav_core::VerdictCategory::Clean => Self::Clean,
            exav_core::VerdictCategory::Infected => Self::Infected,
            exav_core::VerdictCategory::Partial => Self::Partial,
        }
    }
}

/// The cell a matcher name accumulates into.
fn index_of(name: &str) -> usize {
    MATCHERS.iter().position(|m| *m == name).unwrap_or(OTHER)
}

/// One scan's matcher times, longest first, for the slow-scan line.
fn breakdown(p: &Profile) -> String {
    let mut rows: Vec<(&str, u64)> = p
        .iter()
        .filter(|(_, s)| s.ns > 0)
        .map(|(n, s)| (n, s.ns))
        .collect();
    rows.sort_by_key(|(_, ns)| std::cmp::Reverse(*ns));
    rows.iter()
        .map(|(n, ns)| format!("{n} {:.1}ms", *ns as f64 / 1e6))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The counters at one moment.
///
/// Read out before rendering rather than read field by field while formatting,
/// so one `STATS` reply describes one instant instead of a smear across however
/// long the formatting took — and so the rendering can be tested without a
/// process's worth of accumulated history behind it.
#[derive(Debug, Default, Clone)]
pub(crate) struct Snapshot {
    scans: u64,
    bytes: u64,
    ns: u64,
    slowest_ns: u64,
    slow: u64,
    infected: u64,
    partial: u64,
    in_flight: u64,
    profiling: bool,
    /// `(name, ns, calls, bytes)` per matcher that ran.
    matchers: Vec<(&'static str, u64, u64, u64)>,
}

fn snapshot() -> Snapshot {
    Snapshot {
        scans: SCANS.load(Ordering::Relaxed),
        bytes: BYTES.load(Ordering::Relaxed),
        ns: NANOS.load(Ordering::Relaxed),
        slowest_ns: SLOWEST_NS.load(Ordering::Relaxed),
        slow: SLOW.load(Ordering::Relaxed),
        infected: INFECTED.load(Ordering::Relaxed),
        partial: PARTIAL.load(Ordering::Relaxed),
        in_flight: IN_FLIGHT.load(Ordering::Relaxed),
        profiling: profiling(),
        matchers: MATCHERS
            .iter()
            .chain(std::iter::once(&"other"))
            .enumerate()
            .filter_map(|(i, name)| {
                let cell = &MATCHER_CELLS[i];
                let calls = cell.calls.load(Ordering::Relaxed);
                (calls > 0).then(|| {
                    (
                        *name,
                        cell.ns.load(Ordering::Relaxed),
                        calls,
                        cell.bytes.load(Ordering::Relaxed),
                    )
                })
            })
            .collect(),
    }
}

/// The `STATS` body describing what this process has scanned.
///
/// Appended to the clamd-compatible block rather than replacing it: `clamdtop`
/// parses the fields above by name and would lose its columns if they moved.
pub(crate) fn stats_block() -> String {
    render(&snapshot())
}

fn render(s: &Snapshot) -> String {
    let Snapshot {
        scans, bytes, ns, ..
    } = *s;
    let secs = ns as f64 / 1e9;
    let mut out = format!(
        "SCANSTATS: scans {scans} bytes {bytes} scan-seconds {secs:.3} \
         mean-ms {mean:.3} slowest-ms {slowest:.3} throughput-MBps {tput:.1} \
         in-flight {inflight} slow {slow} infected {infected} partial {partial}",
        mean = if scans == 0 {
            0.0
        } else {
            ns as f64 / scans as f64 / 1e6
        },
        slowest = s.slowest_ns as f64 / 1e6,
        // Bytes per second of *scanning*, not of wall time: it answers "how fast
        // is this engine on this corpus", which is the number that transfers to
        // another machine. Divide by cores for a capacity estimate.
        tput = if ns == 0 {
            0.0
        } else {
            bytes as f64 / (ns as f64 / 1e9) / 1e6
        },
        inflight = s.in_flight,
        slow = s.slow,
        infected = s.infected,
        partial = s.partial,
    );

    if !s.profiling {
        out.push_str("\nMATCHERSTATS: off (start with --profile-scans)");
        return out;
    }
    out.push_str("\nMATCHERSTATS:");
    for (name, ns, calls, bytes) in &s.matchers {
        out.push_str(&format!(
            " {name}={:.3}ms/{calls}calls/{bytes}b",
            *ns as f64 / 1e6
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_matcher_has_a_cell_and_a_home() {
        assert_eq!(MATCHER_CELLS.len(), CELLS);
        for (i, name) in MATCHERS.iter().enumerate() {
            assert_eq!(index_of(name), i, "{name}");
        }
        // A matcher the engine grows before this list does still lands
        // somewhere, rather than being dropped or panicking a live listener.
        assert_eq!(index_of("a-matcher-added-later"), OTHER);
    }

    #[test]
    fn stats_are_reported_before_anything_has_been_scanned() {
        // `STATS` on a freshly started listener is the normal case — a health
        // check, or clamdtop connecting — and a divide-by-zero there would take
        // the daemon down on its most harmless command. Rendered from an empty
        // snapshot rather than from the process, because these counters are
        // global and every other test in this binary has already scanned.
        let block = render(&Snapshot::default());
        assert!(block.contains("scans 0"), "{block}");
        assert!(block.contains("mean-ms 0.000"), "{block}");
        assert!(block.contains("throughput-MBps 0.0"), "{block}");
        assert!(block.contains("MATCHERSTATS: off"), "{block}");
    }

    #[test]
    fn the_breakdown_reports_what_ran_and_nothing_else() {
        let s = Snapshot {
            scans: 2,
            bytes: 2048,
            ns: 4_000_000,
            profiling: true,
            matchers: vec![("engine", 3_000_000, 7, 2048), ("yara", 1_000_000, 2, 2048)],
            ..Snapshot::default()
        };
        let block = render(&s);
        assert!(block.contains("scans 2 bytes 2048"), "{block}");
        assert!(block.contains("mean-ms 2.000"), "{block}");
        assert!(block.contains("engine=3.000ms/7calls/2048b"), "{block}");
        assert!(block.contains("yara=1.000ms/2calls/2048b"), "{block}");
        // Matchers that never ran are absent rather than listed as zeroes: the
        // line is read by a human looking for where the time went.
        assert!(!block.contains("fuzzy"), "{block}");
    }

    #[test]
    fn a_timed_scan_lands_in_the_totals() {
        // Counters are process-global and this binary's tests run in parallel,
        // so the assertions are about movement, not absolute values.
        let before = SCANS.load(Ordering::Relaxed);
        let infected_before = INFECTED.load(Ordering::Relaxed);
        let t = ScanTimer::start();
        assert!(
            IN_FLIGHT.load(Ordering::Relaxed) >= 1,
            "a running scan must show as in flight"
        );
        t.finish("some-object", 4096, Category::Infected);
        assert!(SCANS.load(Ordering::Relaxed) > before);
        assert!(INFECTED.load(Ordering::Relaxed) > infected_before);
    }

    #[test]
    fn the_in_flight_gauge_is_released_even_when_a_scan_leaves_early() {
        // A gauge that only decrements on the happy path reads as a permanently
        // busy server, which is the opposite of what someone polling it wants.
        let before = IN_FLIGHT.load(Ordering::Relaxed);
        let t = ScanTimer::start();
        assert!(IN_FLIGHT.load(Ordering::Relaxed) > before);
        t.finish("gone", 0, Category::Partial);
        assert_eq!(IN_FLIGHT.load(Ordering::Relaxed), before);
    }
}
