// Diagnostic: load a cache, scan a file's raw bytes through the engine, and
// print the match-work breakdown + timing. Temporary perf-analysis tool.
use exav_core::{cache, filetype, pe};
use std::time::Instant;

fn main() {
    let mut a = std::env::args().skip(1);
    let cache_path = a.next().unwrap();
    let file = a.next().unwrap();
    let db = cache::load(std::path::Path::new(&cache_path)).expect("load cache");
    let data = std::fs::read(&file).unwrap();
    let ft = filetype::identify(&data);
    let layout = if ft == filetype::FileType::Pe { pe::layout(&data) } else { None };
    eprintln!("{} bytes, ft={:?}, sigs={}", data.len(), ft, db.signature_count());

    // Real scan path (early-return + budget), averaged over a few runs.
    let mut real_ms = f64::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        let hit = db.engine.scan_with_layout(&data, ft, layout.as_ref(), None);
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        real_ms = real_ms.min(ms);
        if let Some((n, ..)) = hit {
            eprintln!("  REAL scan hit: {n}");
            break;
        }
    }
    eprintln!("  REAL scan (min of 5): {real_ms:.1} ms");

    let t = Instant::now();
    let d = db.engine.scan_diag(&data, ft, layout.as_ref());
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "scan_diag {ms:.0} ms | cs_hits={} ci_hits={} fanout={} | target_reject={} literal={} token={} ok={}",
        d[0], d[1], d[2], d[3], d[4], d[5], d[6]
    );
    eprintln!(
        "  cs_hits/byte={:.1} ci_hits/byte={:.1} fanout/hit={:.1}",
        d[0] as f64 / data.len() as f64,
        d[1] as f64 / data.len() as f64,
        d[2] as f64 / (d[0] + d[1]).max(1) as f64,
    );
    let (us, bid) = db.engine.diag_slowest();
    eprintln!("  slowest verify: {us} us  body[{bid}] = {}", db.engine.describe_body(bid));
    eprintln!("  anchor-length histogram (len: hits fanout):");
    for (len, (hits, fan)) in db.engine.scan_diag_hist(&data, ft).into_iter().enumerate() {
        if hits > 0 {
            eprintln!("    {len:>2}: {hits:>9} {fan:>11}");
        }
    }
    eprintln!("  top fan-out groups (alen gsize hits fanout | best_off coverage%):");
    for (alen, gsize, hits, fan, off, cov) in db.engine.scan_diag_groups(&data, ft) {
        eprintln!("    alen={alen} gsize={gsize:>5} hits={hits:>7} fanout={fan:>10} | off={off:>4} cov={cov}%");
    }
}
