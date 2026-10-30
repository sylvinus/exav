//! What a running listener can say about where its time went.
//!
//! A one-shot scan can be timed from outside — `time exav file`, or
//! `--profile` for a per-matcher breakdown. A listener cannot: it is a
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
//!   and there are many per scan. Opt-in, behind `--profile`, because the
//!   overhead is proportional to how much work is being measured.
//!
//! ## Under the worker pool
//!
//! The prefork daemon answers each connection from a forked child. The counters
//! are in memory the supervisor maps shared before it forks, each process
//! writing its own slot of the in-flight gauge, so `STATS` from any process of
//! the pool reports the pool's totals. A slot is cleared when its process is
//! reaped. The thread-model daemon (`--workers 0`) and the ICAP listener are
//! single processes.

use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::time::Duration;

use exav_core::profile::Profile;

/// Matchers reported in the breakdown, in a fixed order so successive `STATS`
/// replies line up. The same set `--profile` uses; a matcher the engine names
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
    "unpack",
    "emu",
    "filetype",
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

/// Processes whose scans in flight are counted apart: the slot of a process is
/// its pid modulo this.
const SLOTS: usize = 4096;

/// Everything counted, in one block so that it can sit in memory the forked
/// processes of the pool share.
struct Counters {
    scans: AtomicU64,
    bytes: AtomicU64,
    nanos: AtomicU64,
    slowest_ns: AtomicU64,
    slow: AtomicU64,
    infected: AtomicU64,
    partial: AtomicU64,
    /// Scans running, by process. Apart because a worker killed mid-scan (its
    /// time ran out) would otherwise leave the gauge one too high for good;
    /// the supervisor clears the slot of a child it reaps ([`release`]).
    in_flight: [AtomicU64; SLOTS],
    cells: [MatcherCell; CELLS],
}

impl Counters {
    const fn new() -> Self {
        Self {
            scans: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            nanos: AtomicU64::new(0),
            slowest_ns: AtomicU64::new(0),
            slow: AtomicU64::new(0),
            infected: AtomicU64::new(0),
            partial: AtomicU64::new(0),
            in_flight: [const { AtomicU64::new(0) }; SLOTS],
            cells: [const { MatcherCell::new() }; CELLS],
        }
    }
}

/// This process's own counters: where they are until the supervisor of a pool
/// puts them somewhere its children share.
static LOCAL: Counters = Counters::new();

/// The shared block, once there is one.
static SHARED: AtomicPtr<Counters> = AtomicPtr::new(std::ptr::null_mut());

/// The counters in use.
fn c() -> &'static Counters {
    let shared = SHARED.load(Ordering::Acquire);
    if shared.is_null() {
        &LOCAL
    } else {
        // SAFETY: set only by `share_across_fork`, to a mapping that is never
        // unmapped, is the size of `Counters`, and holds only atomics, which
        // are valid at any bit pattern and meant to be used from many processes.
        unsafe { &*shared }
    }
}

/// Put the counters in memory shared with every process forked from here on,
/// so that `STATS` in any of them (and in the health child) reports the whole
/// pool and not one worker. Called once, by the supervisor, before it forks.
/// On failure the counters stay each process's own and the reason is returned.
#[cfg(unix)]
pub(crate) fn share_across_fork() -> std::io::Result<()> {
    // SAFETY: an anonymous shared mapping of the size of `Counters`, which the
    // kernel zero-fills (every field is an atomic whose zero is its initial
    // value). Nothing else refers to it, and it is never unmapped.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            std::mem::size_of::<Counters>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    SHARED.store(ptr.cast(), Ordering::Release);
    Ok(())
}

/// Clear the scans in flight of child `pid`, which has exited: whatever it was
/// doing, it is not doing it now.
#[cfg(unix)]
pub(crate) fn release(pid: i32) {
    c().in_flight[slot_of(pid)].store(0, Ordering::Relaxed);
}

fn slot_of(pid: i32) -> usize {
    pid as usize % SLOTS
}

#[cfg(unix)]
fn my_slot() -> usize {
    slot_of(std::process::id() as i32)
}

#[cfg(not(unix))]
fn my_slot() -> usize {
    0
}

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
    c().in_flight
        .iter()
        .map(|n| n.load(Ordering::Relaxed))
        .sum()
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
        let mut last = c().scans.load(Ordering::Relaxed);
        loop {
            std::thread::sleep(interval);
            let now = c().scans.load(Ordering::Relaxed);
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
/// what it scanned (the daemon's, Unix only).
#[cfg(all(test, unix))]
pub(crate) fn scans() -> u64 {
    c().scans.load(Ordering::Relaxed)
}

/// A scan in progress, and the counters it will land in when it finishes.
///
/// A guard rather than a pair of calls, so a scan that leaves early — a panic
/// caught by the surrounding handler, a client that vanished — is still counted
/// and still leaves the in-flight gauge where it found it. A gauge that only
/// decrements on the happy path reads as a permanently busy server.
pub(crate) struct ScanTimer {
    start: std::time::Instant,
    /// The gauge was given back, by `finish` or by dropping the timer.
    released: bool,
}

impl ScanTimer {
    /// Start timing, and enable per-matcher profiling on this thread when it is
    /// switched on.
    pub(crate) fn start() -> Self {
        c().in_flight[my_slot()].fetch_add(1, Ordering::Relaxed);
        if profiling() {
            exav_core::profile::enable();
        }
        Self {
            start: std::time::Instant::now(),
            released: false,
        }
    }

    /// Give the in-flight gauge back, once.
    fn release(&mut self) {
        if std::mem::replace(&mut self.released, true) {
            return;
        }
        // Not below zero: a supervisor that cleared this slot after this
        // process was thought dead must not wrap it.
        let slot = &c().in_flight[my_slot()];
        if slot.fetch_sub(1, Ordering::Relaxed) == 0 {
            slot.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record the finished scan. `target` names the object for the slow-scan
    /// line; `bytes` is its size.
    pub(crate) fn finish(mut self, target: &str, bytes: u64, category: Category) {
        let elapsed = self.start.elapsed();
        let ns = elapsed.as_nanos() as u64;
        let k = c();
        self.release();
        k.scans.fetch_add(1, Ordering::Relaxed);
        k.bytes.fetch_add(bytes, Ordering::Relaxed);
        k.nanos.fetch_add(ns, Ordering::Relaxed);
        k.slowest_ns.fetch_max(ns, Ordering::Relaxed);
        match category {
            Category::Infected => {
                k.infected.fetch_add(1, Ordering::Relaxed);
            }
            Category::Partial => {
                k.partial.fetch_add(1, Ordering::Relaxed);
            }
            Category::Clean => {}
        }

        let profile = exav_core::profile::take();
        if let Some(p) = &profile {
            for (name, stat) in p.iter() {
                let cell = &k.cells[index_of(name)];
                cell.ns.fetch_add(stat.ns, Ordering::Relaxed);
                cell.calls.fetch_add(stat.calls, Ordering::Relaxed);
                cell.bytes.fetch_add(stat.bytes, Ordering::Relaxed);
            }
        }

        let threshold = SLOW_AFTER_NS.load(Ordering::Relaxed);
        if threshold > 0 && ns >= threshold {
            k.slow.fetch_add(1, Ordering::Relaxed);
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

/// A scan that ends without `finish` (a panic unwinding, an early return)
/// still gives the gauge back. It is not counted as a scan.
impl Drop for ScanTimer {
    fn drop(&mut self) {
        if !self.released {
            self.release();
            // Profiling was enabled on this thread for a scan that did not
            // report.
            let _ = exav_core::profile::take();
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
    let k = c();
    Snapshot {
        scans: k.scans.load(Ordering::Relaxed),
        bytes: k.bytes.load(Ordering::Relaxed),
        ns: k.nanos.load(Ordering::Relaxed),
        slowest_ns: k.slowest_ns.load(Ordering::Relaxed),
        slow: k.slow.load(Ordering::Relaxed),
        infected: k.infected.load(Ordering::Relaxed),
        partial: k.partial.load(Ordering::Relaxed),
        in_flight: in_flight(),
        profiling: profiling(),
        matchers: MATCHERS
            .iter()
            .chain(std::iter::once(&"other"))
            .enumerate()
            .filter_map(|(i, name)| {
                let cell = &k.cells[i];
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
        out.push_str("\nMATCHERSTATS: off (start with --profile)");
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
        assert_eq!(c().cells.len(), CELLS);
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
        let before = c().scans.load(Ordering::Relaxed);
        let infected_before = c().infected.load(Ordering::Relaxed);
        let t = ScanTimer::start();
        assert!(in_flight() >= 1, "a running scan must show as in flight");
        t.finish("some-object", 4096, Category::Infected);
        assert!(c().scans.load(Ordering::Relaxed) > before);
        assert!(c().infected.load(Ordering::Relaxed) > infected_before);
    }

    /// A worker killed mid-scan never finishes it. Its scans in flight are in a
    /// slot of its own, which the supervisor clears when it reaps the child, so
    /// the gauge of the pool does not stay one too high for good.
    #[test]
    #[cfg(unix)]
    fn a_child_that_died_mid_scan_leaves_no_scan_in_flight() {
        // A pid no test process has: its slot is nobody's but this test's.
        let pid = 4096 * 100 + 17;
        let slot = &c().in_flight[slot_of(pid)];
        let before = in_flight();
        slot.store(2, Ordering::Relaxed);
        assert!(in_flight() >= before + 2);
        release(pid);
        assert_eq!(slot.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn the_in_flight_gauge_is_released_even_when_a_scan_leaves_early() {
        // A gauge that only decrements on the happy path reads as a permanently
        // busy server, which is the opposite of what someone polling it wants.
        let before = c().in_flight[my_slot()].load(Ordering::Relaxed);
        let t = ScanTimer::start();
        assert!(c().in_flight[my_slot()].load(Ordering::Relaxed) > before);
        t.finish("gone", 0, Category::Partial);
        assert_eq!(c().in_flight[my_slot()].load(Ordering::Relaxed), before);

        // A scan that panics, or returns, without reaching `finish`.
        let slot = &c().in_flight[my_slot()];
        let before = slot.load(Ordering::Relaxed);
        let scans = c().scans.load(Ordering::Relaxed);
        let panicked = std::panic::catch_unwind(|| {
            let _t = ScanTimer::start();
            panic!("the scan died");
        });
        assert!(panicked.is_err());
        assert_eq!(
            slot.load(Ordering::Relaxed),
            before,
            "the panic leaked the gauge"
        );
        assert_eq!(
            c().scans.load(Ordering::Relaxed),
            scans,
            "a dropped timer is not a finished scan"
        );
        drop(ScanTimer::start());
        assert_eq!(
            slot.load(Ordering::Relaxed),
            before,
            "an early return leaked the gauge"
        );
    }
}
