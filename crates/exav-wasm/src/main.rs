//! WASI command: scan files for malware using a ClamAV-compatible signature DB.
//!
//! # Usage
//!
//! ```sh
//! # Build
//! cargo build --release --target wasm32-wasip1 -p exav-wasm
//! wasm-tools strip -a target/wasm32-wasip1/release/exav_wasm.wasm -o exav.wasm
//!
//! # Run
//! wasmtime --dir ./sigs::/db --dir .::. exav.wasm /db malware.exe
//! ```
//!
//! - First arg: path to the signature directory (as mounted inside the WASM)
//! - Remaining args: files to scan (relative to mounted dirs)
//! - JSON results to stdout; progress/errors to stderr.

use exav_core::{analyze, ScanOptions, ScanReport};
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <db-dir> <file1> [file2] ...", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!(
            "  wasmtime --dir ./sigs::/db --dir .::. {0} /db malware.exe",
            args[0]
        );
        std::process::exit(1);
    }

    let db_path = PathBuf::from(&args[1]);
    let file_paths: Vec<PathBuf> = args[2..].iter().map(PathBuf::from).collect();

    let db = match load_db(&db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("error: failed to load database: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("loaded {} signatures", db.signature_count());

    let opts = ScanOptions::default();
    for path in &file_paths {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("error: {}: {e}", path.display());
                continue;
            }
        };

        eprintln!("scanning {} ({} bytes)", path.display(), data.len());
        let report: ScanReport = analyze(&db, &data, &opts);
        match serde_json::to_string(&report) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("error: serializing result: {e}"),
        }
    }
}

fn load_db(path: &Path) -> Result<exav_core::Database, String> {
    let mut loader = exav_core::db::Loader::new();
    loader.add_path(path).map_err(|e| format!("{e}"))?;
    loader.build().map_err(|e| format!("{e}"))
}
