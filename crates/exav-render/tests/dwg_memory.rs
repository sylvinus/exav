//! How much memory tessellating a drawing takes at its peak, per stroke, on
//! a drawing of 100,000 lines made here: the scene's lists, the buffers it
//! hands over, and what building those takes, but not a copy of the lists.

#![cfg(feature = "dwg")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use exav_render::dwg::{Document, STROKE_BYTES};

struct Counting;

static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = NOW.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        NOW.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The counters are the process's: one test measures at a time.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn an_entity_takes_what_the_limits_count() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let mut dxf = String::from("  0\nSECTION\n  2\nENTITIES\n");
    for _ in 0..100_000 {
        dxf.push_str("  0\nLINE\n 10\n0\n 20\n0\n 11\n1\n 21\n1\n");
    }
    dxf.push_str("  0\nENDSEC\n  0\nEOF\n");
    let before = NOW.load(Ordering::Relaxed);
    let drawing = exav_render::cad::read_dxf(dxf.as_bytes()).unwrap();
    let held = NOW.load(Ordering::Relaxed) - before;
    // The allocator rounds each of an entity's strings up to a grain of its
    // own, which the counter does not see.
    let per_entity = held as u64 / 100_000 + 3 * 24;
    assert!(
        per_entity <= exav_render::cad::ENTITY_BYTES,
        "{per_entity} bytes per entity held"
    );
    drop(drawing);
}

#[test]
fn tessellating_takes_no_copy_of_the_scene() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let mut dxf = String::from("  0\nSECTION\n  2\nENTITIES\n");
    for i in 0..100_000 {
        let (x, y) = ((i % 1000) as f64, (i / 1000) as f64);
        dxf.push_str(&format!(
            "  0\nLINE\n  8\n0\n 10\n{x}\n 20\n{y}\n 11\n{}\n 21\n{}\n",
            x + 0.5,
            y + 0.5
        ));
    }
    dxf.push_str("  0\nENDSEC\n  0\nEOF\n");
    let doc = Document::parse(dxf.as_bytes()).unwrap();
    drop(dxf);

    let before = NOW.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let d = doc.tessellate(None, None);
    let strokes = d.strokes.len() / STROKE_BYTES;
    assert_eq!(strokes, 100_000);
    let per_stroke = (PEAK.load(Ordering::Relaxed) - before) / strokes;
    // The scene's stroke (48 bytes, and a list's spare room), its encoding
    // (28) and an index or two; a copy of the strokes would add 48.
    assert!(
        per_stroke < 125,
        "{per_stroke} bytes per stroke at the peak"
    );
}
