//! Every container fixture, with each length or count in turn set to an
//! extreme.
//!
//! A container's header says how big its parts are and how many there are, and
//! the file that lies about it is the oldest trick against a reader: the size
//! becomes an allocation before a byte of the data has been seen, a count
//! becomes a loop, an offset a seek. Fuzzing finds these by chance, and an
//! over-allocation is the kind it finds worst, because asking for the memory
//! costs nothing until it is used. This sweep is the deterministic version:
//! for each fixture, at each position of its start, a field of 4 bytes is
//! overwritten with `0xFFFFFFFF`, with `0x7FFFFFFF`, and the walk is made. None
//! may allocate more than a few times the file (the allocator counts what was
//! asked for, whether or not it was used), take seconds, or panic where it
//! should have said the file is damaged.
//!
//! The quick sweep runs with the suite; `EXAV_DEBUG_SATURATE=full` takes every
//! position of the first kilobytes, with more values; `deep` takes every
//! fourth position of the first 64 KB of the fixtures up to 256 KB, where the
//! tables of the file systems and the directories of the archives are.
//!
//! A case that fails prints the fixture, the position and the value, which is
//! the whole reproduction.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use exav_unpack::{Budget, Limits, Member, detect, walk};

struct Counting;

static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// The largest single request this run has made.
static BIGGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            note(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            note(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        NOW.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, layout, new) };
        if !q.is_null() {
            if new >= layout.size() {
                note(new - layout.size());
                BIGGEST.fetch_max(new, Ordering::Relaxed);
            } else {
                NOW.fetch_sub(layout.size() - new, Ordering::Relaxed);
            }
        }
        q
    }
}

/// Set to print where the request over [`ALLOC_BASE`] comes from.
static TRACING: AtomicBool = AtomicBool::new(false);
static IN_TRACE: AtomicBool = AtomicBool::new(false);

fn note(size: usize) {
    let now = NOW.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(now, Ordering::Relaxed);
    BIGGEST.fetch_max(size, Ordering::Relaxed);
    if size > REQUEST_MAX
        && TRACING.load(Ordering::Relaxed)
        && !IN_TRACE.swap(true, Ordering::Relaxed)
    {
        eprintln!(
            "{} bytes asked for at:\n{}",
            size,
            std::backtrace::Backtrace::force_capture()
        );
        IN_TRACE.store(false, Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// What a walk may hold, over the size of the file: a decoder's window and a
/// member that really expands both need room, a header that only says so does
/// not. Measured as what the process has resident at its peak, where the
/// kernel counts memory a decoder asked for and never touched as nothing.
const RESIDENT_BASE: usize = 96 << 20;
const RESIDENT_PER_BYTE: usize = 256;
/// What a walk may ask for in one request, touched or not: past what any limit
/// of the extractor's allows, a request is a header's size taken at its word.
const REQUEST_MAX: usize = 1 << 30;
const SLOW: Duration = Duration::from_secs(4);

fn fixtures(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            fixtures(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// The fixtures as `(name, bytes)`, masked ones unmasked, those too large to
/// sweep and those no container reader takes left out.
fn corpus() -> Vec<(String, Vec<u8>)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut paths = vec![];
    fixtures(&root, &mut paths);
    let mut out = vec![];
    for p in paths {
        let name = p.strip_prefix(&root).unwrap().display().to_string();
        let plain = name.strip_suffix(".xor").unwrap_or(&name).to_string();
        if matches!(
            plain.rsplit('.').next(),
            Some("md" | "json" | "txt" | "py" | "sh" | "zip" | "gz")
        ) {
            continue;
        }
        let Ok(data) = exav_unpack::read_fixture(root.join(&plain).to_str().unwrap()) else {
            continue;
        };
        let largest = if mode() == "deep" {
            256 << 10
        } else {
            64 << 10
        };
        if data.len() <= largest && detect(&data).is_some() {
            out.push((plain, data));
        }
    }
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

/// `EXAV_DEBUG_SATURATE`: `full`, `deep`, or the quick sweep.
fn mode() -> String {
    std::env::var("EXAV_DEBUG_SATURATE").unwrap_or_default()
}

/// The positions to put a value at, and the values.
fn sweep() -> (Vec<usize>, Vec<Vec<u8>>) {
    if mode() == "deep" {
        return (
            (0..64 << 10).step_by(4).collect(),
            vec![vec![0xFF; 4], vec![0xFF, 0xFF, 0xFF, 0x7F]],
        );
    }
    if mode() == "full" {
        let mut at: Vec<usize> = (0..256).collect();
        at.extend((256..2048).step_by(2));
        at.extend((2048..8192).step_by(8));
        let values = vec![
            vec![0xFF; 4],
            vec![0xFF, 0xFF, 0xFF, 0x7F],
            vec![0x00, 0x00, 0x00, 0x80],
            vec![0x00, 0x00, 0x00, 0x10],
            vec![0xFF; 2],
            vec![0xFF; 8],
        ];
        (at, values)
    } else {
        let mut at: Vec<usize> = (0..64).collect();
        at.extend((64..512).step_by(8));
        (at, vec![vec![0xFF; 4], vec![0xFF, 0xFF, 0xFF, 0x7F]])
    }
}

/// What came of one walk.
struct Outcome {
    resident: usize,
    biggest: usize,
    took: Duration,
    panicked: Option<String>,
}

/// The resident-set high-water mark in bytes, from `/proc` (Linux only).
fn high_water() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmHWM:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<usize>().ok())
        })
        .map_or(0, |kb| kb << 10)
}

/// Starts the high-water mark again from what is resident now.
fn reset_high_water() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

fn run(fmt: exav_unpack::Format, data: &[u8]) -> Outcome {
    let before = NOW.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    BIGGEST.store(0, Ordering::Relaxed);
    reset_high_water();
    let resident_before = high_water();
    let started = Instant::now();
    let mut budget = Budget::new(Limits::default());
    let mut panicked = None;
    let r = walk::<()>(fmt, &data, &mut budget, &mut |_, content, _| {
        match content {
            Some(Member::Bytes(b)) => drop(b),
            Some(Member::Stream(r)) => {
                let mut sink = [0u8; 8192];
                while matches!(r.read(&mut sink), Ok(n) if n > 0) {}
            }
            None => {}
        }
        None
    });
    if let Err(hit) = r
        && hit.reason.contains("panicked")
    {
        panicked = Some(hit.reason);
    }
    Outcome {
        resident: high_water().saturating_sub(resident_before),
        biggest: BIGGEST.load(Ordering::Relaxed),
        took: started.elapsed(),
        panicked,
    }
}

/// `EXAV_DEBUG_SATURATE_CASE=<fixture>:<position>:<hex>` walks one case and
/// prints where its large requests come from: the reproduction of a finding.
#[test]
fn one_case_traced() {
    let Ok(case) = std::env::var("EXAV_DEBUG_SATURATE_CASE") else {
        return;
    };
    let mut parts = case.rsplitn(3, ':');
    let hex = parts.next().unwrap();
    let at: usize = parts.next().unwrap().parse().unwrap();
    let name = parts.next().unwrap();
    let value: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    let (_, data) = corpus().into_iter().find(|(n, _)| n == name).unwrap();
    let mut mutated = data.clone();
    mutated[at..at + value.len()].copy_from_slice(&value);
    TRACING.store(true, Ordering::Relaxed);
    let o = run(detect(&mutated).unwrap(), &mutated);
    TRACING.store(false, Ordering::Relaxed);
    eprintln!("held {} MiB in {:?}", o.resident >> 20, o.took);
}

#[test]
fn a_field_at_its_extreme_costs_nothing_like_what_it_says() {
    let corpus = corpus();
    assert!(corpus.len() > 50, "only {} fixtures", corpus.len());
    let (positions, values) = sweep();
    let mut findings: Vec<String> = vec![];
    let mut runs = 0u64;
    for (name, data) in &corpus {
        let fmt = detect(data).unwrap();
        let allowed = RESIDENT_BASE + RESIDENT_PER_BYTE * data.len();
        // One finding per fixture and field: the same field set to the other
        // value is the same bug.
        let mut seen: Vec<usize> = vec![];
        for &at in &positions {
            if seen.contains(&at) {
                continue;
            }
            for value in &values {
                if at + value.len() > data.len() {
                    continue;
                }
                let mut mutated = data.clone();
                mutated[at..at + value.len()].copy_from_slice(value);
                // A mutation that turns the container into another kind is
                // another test: this one is about the format's own fields.
                if detect(&mutated) != Some(fmt) {
                    continue;
                }
                runs += 1;
                let o = run(fmt, &mutated);
                let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
                if o.resident > allowed || o.biggest > REQUEST_MAX {
                    findings.push(format!(
                        "{name} ({fmt:?}): bytes {at}..{} set to {hex} held {} MiB at its peak, and asked for {} MiB at once (allowed {} MiB held, {} MiB asked)",
                        at + value.len(),
                        o.resident >> 20,
                        o.biggest >> 20,
                        allowed >> 20,
                        REQUEST_MAX >> 20
                    ));
                    seen.push(at);
                } else if o.took > SLOW {
                    findings.push(format!(
                        "{name} ({fmt:?}): bytes {at}..{} set to {hex} took {:.1} s",
                        at + value.len(),
                        o.took.as_secs_f64()
                    ));
                    seen.push(at);
                } else if let Some(why) = o.panicked {
                    findings.push(format!(
                        "{name} ({fmt:?}): bytes {at}..{} set to {hex} panicked: {why}",
                        at + value.len()
                    ));
                    seen.push(at);
                }
            }
        }
    }
    eprintln!(
        "{} fixtures, {runs} walks, {} findings",
        corpus.len(),
        findings.len()
    );
    assert!(findings.is_empty(), "\n{}", findings.join("\n"));
}
