// Probe: feed a raw ldb trigger line into the engine and report a gated match.
use exav_core::engine::EngineBuilder;
use exav_core::{filetype, pe};

fn main() {
    let mut a = std::env::args().skip(1);
    let ldb = a.next().unwrap();          // full ldb line
    let path = a.next().unwrap();
    let data = std::fs::read(&path).unwrap();
    let ft = filetype::identify(&data);
    let layout = if ft == filetype::FileType::Pe { pe::layout(&data) } else { None };
    eprintln!("ft={:?} layout.entry={:?}", ft, layout.as_ref().and_then(|l| l.entry));
    let mut eb = EngineBuilder::new();
    eb.add_ldb(&format!("{ldb}\n"), false);
    eprintln!("sig_count={} unsupported={}", eb.signature_count(), eb.unsupported());
    let eng = eb.build();
    let hit = eng.scan_with_layout(&data, ft, layout.as_ref(), None);
    println!("scan_with_layout => {:?}", hit);
    let mut all = Vec::new();
    eng.scan_all_with_layout(&data, ft, layout.as_ref(), None, &mut all);
    println!("scan_all_with_layout => {:?}", all);
    let mut lo = Vec::new();
    eng.scan_logical_offsets(&data, ft, layout.as_ref(), None, &mut lo);
    println!("scan_logical_offsets => {:?}", lo);
}
