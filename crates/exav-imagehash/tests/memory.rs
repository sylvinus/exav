//! A very wide, one-pixel-high image hashes in memory of the order of its own
//! size. The resampling weights are `ksize` per output pixel, and `ksize` grows
//! with the image, so all of them held at once were many times the image.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use exav_imagehash::{Hasher, Preset};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is the system allocator's, with the sizes counted around it.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

#[test]
fn a_four_megapixel_line_hashes_in_a_few_times_its_size() {
    const WIDTH: u32 = 4_000_000;
    let gray: Vec<u8> = (0..WIDTH).map(|x| (x % 251) as u8).collect();
    let before = PEAK.load(Ordering::Relaxed);
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    let hash = Hasher::new(Preset::ImagehashPhash)
        .hash_gray(WIDTH, 1, &gray)
        .unwrap();
    let peak = PEAK.load(Ordering::Relaxed);
    assert!(!hash.to_string().is_empty());
    // The weights of every output pixel at once were 288 MB for this line.
    assert!(
        peak < 100 * 1024 * 1024,
        "peak {} MB (before: {})",
        peak >> 20,
        before >> 20
    );
}
