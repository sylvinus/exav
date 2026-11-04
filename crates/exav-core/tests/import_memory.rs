//! Descriptors that share one long table of thunks make a small PE take a
//! great deal of memory to read: 2000 descriptors that list the same 5000
//! thunks are 61 KB. The table is counted before it is built, and one that
//! would take more than `--max-object-bytes` allocates nothing for its
//! functions (measured before: 280 MB for the default limit of 256 MiB).
//!
//! Alone in its test binary because it replaces the global allocator, to count
//! what a scan holds at most.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use exav_core::{ScanOptions, Scanner, Verdict, analyze, loader};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is the system allocator's, with the sizes counted around it.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
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

fn put(v: &mut [u8], at: usize, bytes: &[u8]) {
    v[at..at + bytes.len()].copy_from_slice(bytes);
}

/// A PE32 whose `.idata` holds `descriptors` descriptors, all of the library
/// `A.dll` and its one table of `thunks` thunks, which all name the function
/// `Fn`.
fn amplifier(descriptors: usize, thunks: usize) -> Vec<u8> {
    let va = 0x1000u32;
    let dir_size = 20 * (descriptors + 1);
    let table = dir_size;
    let hint = table + 4 * (thunks + 1);
    let name = hint + 16;
    let mut idata = vec![0u8; name + 16];
    for i in 0..descriptors {
        for (field, value) in [(0, table), (12, name), (16, table)] {
            put(
                &mut idata,
                20 * i + field,
                &(va + value as u32).to_le_bytes(),
            );
        }
    }
    for j in 0..thunks {
        put(&mut idata, table + 4 * j, &(va + hint as u32).to_le_bytes());
    }
    put(&mut idata, hint + 2, b"Fn\0");
    put(&mut idata, name, b"A.dll\0");
    let raw = idata.len().next_multiple_of(0x200);
    idata.resize(raw, 0);
    let mut f = vec![0u8; 0x200];
    put(&mut f, 0, b"MZ");
    put(&mut f, 0x3c, &0x40u32.to_le_bytes());
    put(&mut f, 0x40, b"PE\0\0");
    put(&mut f, 0x44, &0x14cu16.to_le_bytes());
    put(&mut f, 0x46, &1u16.to_le_bytes()); // sections
    put(&mut f, 0x54, &0xe0u16.to_le_bytes());
    put(&mut f, 0x56, &0x0102u16.to_le_bytes());
    let opt = 0x58;
    put(&mut f, opt, &0x10bu16.to_le_bytes());
    put(&mut f, opt + 28, &0x40_0000u32.to_le_bytes());
    put(&mut f, opt + 32, &0x1000u32.to_le_bytes());
    put(&mut f, opt + 36, &0x200u32.to_le_bytes());
    put(&mut f, opt + 56, &(0x1000 + raw as u32).to_le_bytes());
    put(&mut f, opt + 60, &0x200u32.to_le_bytes());
    put(&mut f, opt + 68, &3u16.to_le_bytes());
    put(&mut f, opt + 92, &16u32.to_le_bytes());
    put(&mut f, opt + 96 + 8, &va.to_le_bytes()); // the import table
    put(&mut f, opt + 96 + 12, &(dir_size as u32).to_le_bytes());
    let section = opt + 0xe0;
    put(&mut f, section, b".idata");
    put(&mut f, section + 8, &(raw as u32).to_le_bytes());
    put(&mut f, section + 12, &va.to_le_bytes());
    put(&mut f, section + 16, &(raw as u32).to_le_bytes());
    put(&mut f, section + 20, &0x200u32.to_le_bytes());
    put(&mut f, section + 36, &0xc000_0040u32.to_le_bytes());
    f.extend_from_slice(&idata);
    f
}

fn db(files: &[(&str, &str)]) -> Scanner {
    let mut b = loader::Builder::new();
    for (name, text) in files {
        b.add_named_bytes(name, text.as_bytes(), true);
    }
    b.build().expect("build db")
}

/// One test at a time: the counts are of the whole process.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The most memory a scan holds at once, above what is held before it.
fn peak_of(scan: impl FnOnce() -> Verdict) -> (usize, Verdict) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let verdict = scan();
    (PEAK.load(Ordering::Relaxed).saturating_sub(before), verdict)
}

#[test]
fn a_table_over_the_limit_is_refused_without_building_it() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    // 10 million functions, 320 MB to hold, for 61 KB.
    let f = amplifier(2000, 5000);
    assert!(f.len() < 100_000);
    let imp = db(&[("a.imp", "00000000000000000000000000000000:*:Sig.Imp\n")]);
    let mut heuristics = ScanOptions::default();
    heuristics.heuristics = true;
    #[cfg_attr(not(feature = "yara"), allow(unused_mut))]
    let mut configurations: Vec<(&str, Scanner, ScanOptions)> = vec![
        ("an .imp signature", imp, ScanOptions::default()),
        ("--detect exav-heuristics", db(&[]), heuristics),
    ];
    #[cfg(feature = "yara")]
    configurations.push((
        "a YARA rule on pe",
        db(&[(
            "a.yar",
            "import \"pe\"\nrule R { condition: pe.number_of_imports == 9999 }\n",
        )]),
        ScanOptions::default(),
    ));
    for (what, scanner, opts) in configurations {
        let (peak, verdict) = peak_of(|| analyze(&scanner, &f, &opts).verdict);
        assert!(
            matches!(verdict, Verdict::LimitsExceeded { .. }),
            "{what}: {verdict:?}"
        );
        assert!(peak < 32 << 20, "{what}: {} MB", peak >> 20);
    }
}

#[test]
fn a_table_within_the_limit_takes_what_it_holds() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    // 500 descriptors of 1000 thunks: 500 000 functions, a little over 16 MB
    // to hold; a limit that fits them.
    let f = amplifier(500, 1000);
    let sig = db(&[("a.imp", "00000000000000000000000000000000:*:Sig.Imp\n")]);
    let mut opts = ScanOptions::default();
    opts.limits.max_buffer_bytes = 40 << 20;
    let (peak, verdict) = peak_of(|| analyze(&sig, &f, &opts).verdict);
    assert!(matches!(verdict, Verdict::Clean), "{verdict:?}");
    assert!((8 << 20..24 << 20).contains(&peak), "{} MB", peak >> 20);
}
