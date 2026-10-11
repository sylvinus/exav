//! WASI command: scan files for malware using a ClamAV-compatible signature DB.
//!
//! # Usage
//!
//! ```sh
//! # Build
//! cargo build --release --target wasm32-wasip1 -p exav-core --features wasi-bin
//! wasm-tools strip -a target/wasm32-wasip1/release/exav-wasm.wasm -o exav.wasm
//!
//! # Run
//! wasmtime --dir ./sigs::/db --dir ./files::/files exav.wasm /db /files/malware.exe
//! ```
//!
//! - First arg: the signature database, a directory or a prebuilt `.exavdb`
//!   file (as mounted inside the WASM). One that loads no real signatures is
//!   refused.
//! - Remaining args: files to scan (paths inside the mounted dirs).
//! - One JSON object per file on stdout: the `ScanReport` plus `"file"`. A file
//!   that cannot be read gets `{"file", "error"}`. Progress goes to stderr.
//! - Exit code as the `exav` CLI: 0 clean, 1 a detection, 2 an error, 3 a file
//!   not fully examined.

#![forbid(unsafe_code)]

use exav_core::{analyze, ScanOptions, Scanner, VerdictCategory};
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <db-dir-or-exavdb> <file1> [file2] ...", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!(
            "  wasmtime --dir ./sigs::/db --dir ./files::/files {0} /db /files/malware.exe",
            args[0]
        );
        std::process::exit(2);
    }

    let db_path = PathBuf::from(&args[1]);
    let file_paths: Vec<PathBuf> = args[2..].iter().map(PathBuf::from).collect();

    let db = match load_db(&db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    eprintln!("loaded {} signatures", db.signature_count());

    let opts = ScanOptions::default();
    let (mut found, mut errors, mut partial) = (false, false, false);
    for path in &file_paths {
        let name = path.display().to_string();
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                errors = true;
                println!(
                    "{}",
                    serde_json::json!({"file": name, "error": e.to_string()})
                );
                continue;
            }
        };
        eprintln!("scanning {name} ({} bytes)", data.len());
        let report = analyze(&db, &data, &opts);
        match report.verdict.category() {
            VerdictCategory::Infected => found = true,
            VerdictCategory::Partial => partial = true,
            VerdictCategory::Clean => {}
        }
        match serde_json::to_value(&report) {
            Ok(serde_json::Value::Object(mut obj)) => {
                obj.insert("file".into(), name.into());
                println!("{}", serde_json::Value::Object(obj));
            }
            Ok(other) => println!("{other}"),
            Err(e) => {
                errors = true;
                println!(
                    "{}",
                    serde_json::json!({"file": name, "error": e.to_string()})
                );
            }
        }
    }
    std::process::exit(if found {
        1
    } else if errors {
        2
    } else if partial {
        3
    } else {
        0
    });
}

/// The database at `path`, refusing one that holds nothing past the built-in
/// test signature: scanning against it would report every file clean.
fn load_db(path: &Path) -> Result<Scanner, String> {
    let db = exav_core::loader::load(path).map_err(|e| format!("failed to load database: {e}"))?;
    if db.signature_count() <= Scanner::builtin().signature_count() {
        return Err(format!(
            "no signatures in {}: refusing to scan, every file would be reported clean",
            path.display()
        ));
    }
    Ok(db)
}
