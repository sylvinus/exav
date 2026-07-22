//! Run the PE runtime-packer emulator over files and report what each stub did.
//!
//! This is the triage tool for the emulator: for every file it prints how far
//! the stub got, why it stopped, and whether an image came out. A stub that
//! does not unpack names the instruction, export or fault responsible, which is
//! what turns "this packer does not work" into a specific thing to implement.
//!
//! ```text
//! cargo run --release --example pepack_emu -- [--dump DIR] [--ticks N] [--trace] [--all] FILE...
//! ```

use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut files: Vec<PathBuf> = Vec::new();
    let mut dump_dir: Option<PathBuf> = None;
    let mut ticks: u64 = 200_000_000;
    let mut trace = false;
    let mut force_all = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--trace" => trace = true,
            "--all" => force_all = true,
            "--dump" => dump_dir = args.next().map(PathBuf::from),
            "--ticks" => {
                ticks = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(200_000_000)
            }
            _ => files.push(PathBuf::from(a)),
        }
    }
    if files.is_empty() {
        eprintln!("usage: pepack_emu [--dump DIR] [--ticks N] [--trace] [--all] FILE...");
        std::process::exit(2);
    }
    if let Some(d) = &dump_dir {
        let _ = std::fs::create_dir_all(d);
    }

    let mut unpacked = 0usize;
    for f in &files {
        let Ok(data) = std::fs::read(f) else {
            println!("{}: unreadable", f.display());
            continue;
        };
        // The scan path only emulates files the packed-look gate routes here;
        // the tool reports the same decision so a survey measures what the
        // scanner would actually spend.
        let gated = exav_unpack::is_pepack(&data);
        if !gated && !force_all {
            println!("{}: not routed to the unpacker", f.display());
            continue;
        }
        let started = std::time::Instant::now();
        let (summary, images) = exav_unpack::emulate_pe(&data, ticks, trace);
        let ms = started.elapsed().as_millis();
        println!(
            "{}: in={}KiB {summary} [{ms}ms]",
            f.display(),
            data.len() / 1024
        );
        if let Some(dir) = dump_dir.as_ref() {
            if !images.is_empty() {
                unpacked += 1;
            }
            let name = f.file_name().unwrap_or_default().to_string_lossy();
            for (kind, img) in images {
                let out = dir.join(format!("{name}.{kind}"));
                if let Err(e) = std::fs::write(&out, &img) {
                    eprintln!("  could not write {}: {e}", out.display());
                }
            }
        }
    }
    if dump_dir.is_some() {
        println!("{unpacked}/{} files produced an image", files.len());
    }
}
