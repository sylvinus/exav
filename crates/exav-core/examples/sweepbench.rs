// Times the signature engine on its own: the anchor sweep alone, then the full
// all-match scan, each the fastest of a few runs per file, over the files listed
// in a manifest. Prints a digest of every detection so two builds can be checked
// for identical answers as well as compared for speed.
use exav_core::engine::{reset_scan_truncated, scan_was_truncated};
use exav_core::{filetype, loader, pe};
use std::hash::{Hash, Hasher};
use std::time::Instant;

fn main() {
    let mut a = std::env::args().skip(1);
    let usage = "usage: sweepbench <db> <manifest> [reps] [max files]";
    let db = a.next().expect(usage);
    let manifest = a.next().expect(usage);
    let reps: usize = a.next().map_or(3, |s| s.parse().expect(usage));
    let max: usize = a.next().map_or(usize::MAX, |s| s.parse().expect(usage));
    let t = Instant::now();
    let scanner = loader::load(std::path::Path::new(&db)).expect("load database");
    eprintln!("load {:.2}s", t.elapsed().as_secs_f64());
    let eng = scanner.engine();
    let list = std::fs::read_to_string(&manifest).expect("read manifest");
    let (mut bytes, mut sweep, mut full, mut hits, mut dets, mut trunc) =
        (0u64, 0f64, 0f64, 0u64, 0usize, 0usize);
    let mut digest = std::collections::hash_map::DefaultHasher::new();
    let mut files = 0;
    for path in list.lines().take(max) {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        files += 1;
        bytes += data.len() as u64;
        let ft = filetype::identify(&data);
        let layout = pe::layout(&data);
        let (mut best_sweep, mut best_full) = (f64::MAX, f64::MAX);
        let mut out = Vec::new();
        for _ in 0..reps {
            let t = Instant::now();
            hits = hits.wrapping_add(eng.scan_diag_hits(&data, ft));
            best_sweep = best_sweep.min(t.elapsed().as_secs_f64());
            out.clear();
            reset_scan_truncated();
            let t = Instant::now();
            eng.scan_all_with_layout(&data, ft, layout.as_ref(), None, &mut out);
            best_full = best_full.min(t.elapsed().as_secs_f64());
        }
        sweep += best_sweep;
        full += best_full;
        out.sort();
        dets += out.len();
        let truncated = scan_was_truncated();
        trunc += truncated as usize;
        (path, &out, truncated).hash(&mut digest);
    }
    let mb = bytes as f64 / (1 << 20) as f64;
    println!(
        "files={files} MiB={mb:.0} sweep={:.3}s ({:.0} MiB/s) full={:.3}s ({:.0} MiB/s) hits={} dets={dets} truncated={trunc} digest={:016x}",
        sweep,
        mb / sweep,
        full,
        mb / full,
        hits / reps as u64,
        digest.finish()
    );
}
