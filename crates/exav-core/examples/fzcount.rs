// Diagnostic: load a database and report how many `fuzzy_img#` logical sigs loaded.
use exav_core::database;

fn main() {
    let path = std::env::args().nth(1).expect("usage: fzcount <database>");
    let db = database::load(std::path::Path::new(&path)).expect("load database");
    eprintln!(
        "total sigs={}  unsupported={}  fuzzy_img sigs loaded={}",
        db.signature_count(),
        db.engine().unsupported,
        db.engine().fuzzy_sig_count(),
    );
}
