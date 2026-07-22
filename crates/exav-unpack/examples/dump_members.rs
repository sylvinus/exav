//! Dump every member exav extracts from a container, recursively, to a
//! directory — so an external engine can be asked about exactly the bytes exav
//! scanned.
//!
//! This exists for differential triage. When exav reports a detection that the
//! other engine does not, the question is always the same: did exav match
//! wrongly, or did it simply *reach* content the other engine never unpacked?
//! Re-scanning exav's own members with the other engine settles it — if that
//! engine flags the extracted member with the same signature while calling the
//! container clean, exav was right and the difference is extraction depth.
//!
//! Usage: `cargo run --example dump_members --all-features -- <file> <outdir>`

use exav_unpack::{detect, extract_each, Budget, Entry, Limits};
use std::path::PathBuf;

fn main() {
    let mut args = std::env::args_os().skip(1);
    let (Some(input), Some(outdir)) = (args.next(), args.next()) else {
        eprintln!("usage: dump_members <file> <outdir>");
        std::process::exit(2);
    };
    let outdir = PathBuf::from(outdir);
    let data = std::fs::read(&input).expect("read input");
    std::fs::create_dir_all(&outdir).expect("create outdir");
    let mut n = 0usize;
    walk(&data, &outdir, 0, &mut n, "");
    println!("{n}");
}

/// Recurse to the same depth a scan would, writing each member out. Depth is
/// capped well below the scanner's own limit — this is a triage aid, and a
/// runaway nest here would fill the disk rather than merely waste a budget.
fn walk(data: &[u8], outdir: &PathBuf, depth: u32, n: &mut usize, prefix: &str) {
    if depth > 8 {
        return;
    }
    let Some(fmt) = detect(data) else { return };
    let mut budget = Budget::new(Limits::default());
    let _ = extract_each::<()>(fmt, data, &mut budget, &mut |e: Entry, _b: &mut Budget| {
        if e.data.is_empty() {
            return None;
        }
        // A member byte-identical to its container is the fixed point the
        // scanner also refuses to follow; recursing here would never terminate.
        if e.data.len() == data.len() && e.data == data {
            return None;
        }
        *n += 1;
        let safe: String = e
            .name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let safe = &safe[safe.len().saturating_sub(60)..];
        let path = outdir.join(format!("{prefix}{:05}_{safe}", *n));
        if std::fs::write(&path, &e.data).is_ok() {
            let child = format!("{prefix}{:05}_", *n);
            walk(&e.data, outdir, depth + 1, n, &child);
        }
        None
    });
}
