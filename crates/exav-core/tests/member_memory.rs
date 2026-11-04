//! A decoded member held in memory costs about the object limit, not twice it.
//!
//! Alone in its test binary because it replaces the global allocator, to count
//! what a scan holds at most. A buffer that grows in place counts only what it
//! gains, as glibc's `mremap` does.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every call is the system allocator's, with the sizes counted around it.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is `System.alloc`'s.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller passes a block of this allocator, that is of
        // `System`, with its layout: `System.dealloc`'s contract.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        // SAFETY: as in `dealloc`, and the caller's `new` is `System.realloc`'s.
        let q = unsafe { System.realloc(ptr, layout, new) };
        if !q.is_null() {
            if new >= layout.size() {
                grow(new - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new, Ordering::Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Bytes that do not compress.
fn noise(n: usize) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[test]
fn a_member_over_the_object_limit_holds_about_the_limit() {
    let limit: usize = 8 << 20;
    let file = gzip(&noise(3 * limit));
    let db: Scanner = loader::Builder::new().build().expect("build db");
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = limit as u64;
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let v = analyze(&db, &file, &opts).verdict;
    let peak = PEAK.load(Ordering::Relaxed) - before;
    // The member is held up to the limit, with no spill to go on in.
    assert!(matches!(v, Verdict::LimitsExceeded { .. }), "{v:?}");
    assert!(
        peak <= limit + limit / 4,
        "peak {} KiB for a limit of {} KiB",
        peak >> 10,
        limit >> 10
    );
}
