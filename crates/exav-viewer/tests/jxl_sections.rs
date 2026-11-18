//! A JPEG XL file whose table of contents declares a section of about 1 GiB
//! is refused without that much being allocated. zenjxl-decoder 0.3.10 sized
//! each section's buffer by the declared length before reading it; the copy
//! in vendor/ sizes it by the bytes the file has (vendor/zenjxl-decoder/EXAV.md).
//! `huge-toc-34b.jxl` is upstream's test file for the same fix (BSD-3-Clause),
//! `huge-toc-116b.jxl` and `huge-toc-14k.jxl` inputs of exav's nightly fuzz
//! campaign; the last is longer than the decoder's first read, so its section
//! is filled by the read loop rather than from the bytes read with the headers.
#![cfg(feature = "image")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// The largest block asked for, granted or not: a host that refuses a
/// gigabyte must not let the test pass.
static ASKED: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is the system allocator's, with the sizes counted around it.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ASKED.fetch_max(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller's contract for `alloc` is `System.alloc`'s.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller passes a block of this allocator, that is of
        // `System`, with its layout: `System.dealloc`'s contract.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

#[test]
fn a_section_the_file_declares_huge_is_not_allocated() {
    for name in ["huge-toc-34b.jxl", "huge-toc-116b.jxl", "huge-toc-14k.jxl"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let data = std::fs::read(&path).unwrap();
        let before = LIVE.load(Ordering::Relaxed);
        PEAK.store(before, Ordering::Relaxed);
        ASKED.store(0, Ordering::Relaxed);
        // As much as the viewer lets an image decode take.
        let decoded = exav_render::image::decode_any(&data, 256 << 20);
        let grew = PEAK.load(Ordering::Relaxed) - before;
        let asked = ASKED.load(Ordering::Relaxed);
        assert!(decoded.is_err(), "{name} decoded");
        // The decoder's own tables, its 4 MiB LZ77 window the largest; the
        // declared section was about 1 GiB.
        assert!(grew < 16 << 20, "{name}: {} MB allocated", grew >> 20);
        assert!(asked < 16 << 20, "{name}: {} MB asked for", asked >> 20);
    }
}
