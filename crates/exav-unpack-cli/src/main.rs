//! `exav-unpack`: a memory-safe universal archive extractor.
//!
//! Auto-detects the container format by magic and lists or extracts its members
//! using the pure-Rust `exav-unpack` library (the same extractors the exav
//! scanner uses — including a pure-Rust RAR and UPX). No native/C dependencies.
//!
//! Usage:
//!   exav-unpack list <archive>
//!   exav-unpack extract <archive> [output-dir]   (default: current directory)

use exav_unpack::{detect, extract, Budget, Limits};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (extract_mode, archive, outdir) = match args.get(1).map(String::as_str) {
        Some("list") if args.len() == 3 => (false, &args[2], None),
        Some("extract") if args.len() == 3 || args.len() == 4 => (true, &args[2], args.get(3)),
        _ => {
            eprintln!(
                "usage:\n  exav-unpack list <archive>\n  exav-unpack extract <archive> [output-dir]"
            );
            return ExitCode::from(2);
        }
    };

    let data = match std::fs::read(archive) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("exav-unpack: cannot read {archive}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let Some(fmt) = detect(&data) else {
        eprintln!("exav-unpack: {archive}: unrecognised archive format");
        return ExitCode::FAILURE;
    };
    eprintln!("format: {fmt:?}");

    // Generous limits for an interactive extractor (the scanner uses tighter
    // ones); still bounded to contain decompression bombs.
    let mut budget = Budget::new(Limits::default());
    let entries = match extract(fmt, &data, &mut budget) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("exav-unpack: extraction stopped: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !extract_mode {
        println!("{} member(s):", entries.len());
        for e in &entries {
            println!("{:>12}  {}", e.data.len(), e.name);
        }
        return ExitCode::SUCCESS;
    }

    let root = PathBuf::from(outdir.map(String::as_str).unwrap_or("."));
    let mut failures = 0u32;
    for e in &entries {
        // Reject path traversal / absolute paths from hostile member names: keep
        // only normal path components, dropping `..`, root, and prefixes.
        let Some(rel) = safe_relative_path(&e.name) else {
            eprintln!("skipping unsafe member name: {:?}", e.name);
            failures += 1;
            continue;
        };
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                eprintln!("exav-unpack: mkdir {}: {err}", parent.display());
                failures += 1;
                continue;
            }
        }
        match std::fs::write(&path, &e.data) {
            Ok(()) => println!("{} ({} bytes)", path.display(), e.data.len()),
            Err(err) => {
                eprintln!("exav-unpack: write {}: {err}", path.display());
                failures += 1;
            }
        }
    }
    if failures > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Reduce a member name to a safe relative path under the output directory:
/// only `Normal` components are kept (no absolute root, `..`, or drive prefix).
/// Returns `None` if nothing usable remains.
fn safe_relative_path(name: &str) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for comp in Path::new(name).components() {
        if let Component::Normal(c) = comp {
            out.push(c);
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}
