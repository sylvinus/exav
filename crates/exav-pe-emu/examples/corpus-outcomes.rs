//! Record what the emulator does to every packed sample, as one line each.
//!
//! WHY THIS EXISTS: the emulator's output is not a verdict but an image, and
//! the ways it can go subtly wrong — an operand read from the wrong register,
//! a memory access one width too narrow — do not announce themselves. They
//! change which bytes come out, or turn a successful unpack into a stall,
//! quietly. A per-sample record of what happened is what makes a change to the
//! decoder or the semantics reviewable: run it before, run it after, diff.
//!
//!   cargo run --release -p exav-pe-emu --example corpus-outcomes > before.txt
//!
//! The digest is of the recovered image, so a run that still succeeds but
//! rebuilds different bytes shows up as a changed line rather than as nothing.

use std::path::{Path, PathBuf};

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// FNV-1a. Not a security hash — this only has to change when the bytes do,
/// and it keeps the example free of a hashing dependency.
fn digest(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for x in b {
        h ^= u64::from(*x);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn main() {
    let root = std::env::args().nth(1).unwrap_or_else(|| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../corpus/packers").to_string()
    });
    let mut files = Vec::new();
    collect(Path::new(&root), &mut files);
    files.sort();
    if files.is_empty() {
        eprintln!("no samples under {root}");
        std::process::exit(2);
    }

    let limits = exav_pe_emu::EmuLimits::default();
    let (mut ok, mut failed) = (0u32, 0u32);
    for f in &files {
        let Ok(data) = std::fs::read(f) else { continue };
        let r = exav_pe_emu::unpack(&data, &limits);
        let name = f.strip_prefix(&root).unwrap_or(f).display();
        match &r.unpacked {
            Some(u) => {
                ok += 1;
                println!(
                    "{name}\tOK\toep={:#x}\treached={}\tticks={}\tdirty={}\textra={}\timage={:016x}\tlen={}",
                    u.oep_rva,
                    u.reached_oep,
                    r.ticks,
                    r.dirty_bytes,
                    r.extra.len(),
                    digest(&u.data),
                    u.data.len()
                );
            }
            None => {
                failed += 1;
                println!(
                    "{name}\tNONE\tticks={}\tdirty={}\textra={}\tstop={}",
                    r.ticks,
                    r.dirty_bytes,
                    r.extra.len(),
                    r.stop
                );
            }
        }
    }
    eprintln!("{} samples: {ok} unpacked, {failed} not", files.len());
}
