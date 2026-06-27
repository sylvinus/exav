// Diagnostic: load a cache and report how many `fuzzy_img#` logical sigs loaded.
use exav_core::cache;

fn main() {
    let path = std::env::args().nth(1).expect("usage: fzcount <cache>");
    let db = cache::load(std::path::Path::new(&path)).expect("load cache");
    eprintln!(
        "total sigs={}  unsupported={}  fuzzy_img sigs loaded={}",
        db.signature_count(),
        db.engine.unsupported,
        db.engine.fuzzy_sig_count(),
    );
}
