//! `exav-unpack`: a memory-safe universal archive extractor.
//!
//! Auto-detects the container format by magic and lists or extracts its members
//! using the pure-Rust `exav-unpack` library (the same extractors the exav
//! scanner uses — including a pure-Rust RAR and UPX). No native/C dependencies.
//!
//! Usage:
//!   exav-unpack list <archive>
//!   exav-unpack extract <archive> [output-dir]   (default: current directory)
//!
//! `<archive>` may be any part of a byte-split set (`big.7z.001`, `.002`, …):
//! the volumes are rejoined from the same directory first, since no single part
//! is a readable archive on its own.

#![forbid(unsafe_code)]

use exav_unpack::{detect, extract, Budget, Format, Limits};
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

    let data = match read_archive(archive) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("exav-unpack: {archive}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // A packed executable is not a container by magic: "this is a PE" says
    // nothing about whether the program on disk is the program that runs. The
    // scanner routes those by content, and so does this, or `extract` on a
    // packed dropper reports "unrecognised" for a file that unpacks fine.
    let packed = || {
        if exav_unpack::is_upx(&data) {
            Some(Format::Upx)
        } else if exav_unpack::is_pepack(&data) {
            Some(Format::PePacked)
        } else {
            None
        }
    };
    let Some(fmt) = detect(&data).or_else(packed) else {
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

/// Read an archive, rejoining it with its siblings when the path names one part
/// of a **byte-split set** (`big.7z.001`, `.002`, …).
///
/// A single part is not an archive at all: the split was made at an arbitrary
/// byte offset, so `.002` has no header, no directory and nothing to detect.
/// Pointing this tool at any one part is the natural thing for a user to do, and
/// answering "unrecognised archive format" would be technically true and
/// useless.
///
/// Sibling names are **generated from the parsed pattern** and looked up in the
/// same directory — never taken from anything a file contains — so no input can
/// steer which paths are opened. Volumes are read in order from the first until
/// one is missing; that is where the archive ends, since nothing in the naming
/// records how many parts a set has.
fn read_archive(path: &str) -> std::io::Result<Vec<u8>> {
    let p = Path::new(path);
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let Some(vol) = exav_unpack::volume::parse(name).filter(|v| v.scheme.is_byte_split()) else {
        return std::fs::read(p)
            .map_err(|e| std::io::Error::other(format!("cannot read {path}: {e}")));
    };
    let dir = p.parent().unwrap_or(Path::new("."));
    let mut data = Vec::new();
    let mut parts = 0usize;
    for i in 0.. {
        let Some(part) = vol.name_at(i) else { break };
        let Ok(bytes) = std::fs::read(dir.join(&part)) else {
            break;
        };
        data.extend_from_slice(&bytes);
        parts += 1;
    }
    if parts == 0 {
        // The set does not start where it must: everything before the given part
        // is missing, so the head of the archive is simply not here.
        return Err(std::io::Error::other(format!(
            "{name} is one part of a split archive, and its first volume \
             ({}) is not in the same directory",
            vol.name_at(0).unwrap_or_default()
        )));
    }
    if parts > 1 {
        eprintln!("joined {parts} volumes of a split archive");
    }
    Ok(data)
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
