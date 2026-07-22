// Temporary measurement + equivalence harness for the gap-split matcher work.
// Loads a database (file or dir), scans every file in a corpus dir with
// `scan_all_with_layout`, and prints for each file: the sorted (name, offset)
// detections and whether the scan was truncated (LIMITS-EXCEEDED). Deterministic
// output so two runs (old vs new path) can be `diff`ed.
use exav_core::engine::{reset_scan_truncated, scan_was_truncated};
use exav_core::{filetype, loader};
use std::time::Instant;

fn main() {
    let mut a = std::env::args().skip(1);
    let db_path = a.next().expect("usage: splitmeas <db> <corpusdir>");
    let corpus = a.next().expect("usage: splitmeas <db> <corpusdir>");
    let scanner = loader::load(std::path::Path::new(&db_path)).expect("load database");
    let eng = scanner.engine();

    let mut entries: Vec<_> = std::fs::read_dir(&corpus)
        .expect("read corpus dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    entries.sort();

    let mut truncated_files = 0usize;
    let mut total_dets = 0usize;
    let mut slowest: (f64, String) = (0.0, String::new());
    let t_all = Instant::now();
    for p in &entries {
        let data = match std::fs::read(p) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let ft = filetype::identify(&data);
        reset_scan_truncated();
        let t = Instant::now();
        let mut out = Vec::new();
        eng.scan_all_with_layout(&data, ft, None, None, &mut out);
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        if ms > slowest.0 {
            slowest = (ms, p.file_name().unwrap().to_string_lossy().into_owned());
        }
        let trunc = scan_was_truncated();
        if trunc {
            truncated_files += 1;
        }
        out.sort();
        let name = p.file_name().unwrap().to_string_lossy();
        for (n, off, _unof) in &out {
            total_dets += 1;
            println!("{name}\t{n}\t{off}");
        }
        if trunc {
            println!("{name}\t__TRUNCATED__\t0");
        }
    }
    let secs = t_all.elapsed().as_secs_f64();
    eprintln!(
        "files={} dets={} truncated_files={} total={:.2}s slowest={:.0}ms ({})",
        entries.len(),
        total_dets,
        truncated_files,
        secs,
        slowest.0,
        slowest.1,
    );
}
