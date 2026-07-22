//! `exav-pe-emu` — unpack a packed Windows executable by running its own stub.
//!
//! Point it at a packed PE and it prints what the stub did and writes the image
//! the stub rebuilt. When the stub wins, it says so and why, and writes nothing:
//! there is no mode in which this invents an answer.
//!
//! ```text
//! exav-pe-emu packed.exe                 # report, and write packed.exe.unpacked
//! exav-pe-emu -o out.exe packed.exe      # choose the output path
//! exav-pe-emu --report-only packed.exe   # just say what happened
//! exav-pe-emu --trace packed.exe         # every Windows call, then the last
//!                                        # instructions before it stopped
//! ```
//!
//! Nothing about the emulated program reaches the host: no syscalls, no
//! filesystem, no network. The only file it can read is the one you named, and
//! it is read into memory before emulation starts.

#![forbid(unsafe_code)]

use exav_pe_emu::{unpack, EmuLimits};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
usage: exav-pe-emu [options] FILE...

  -o, --output PATH   write the recovered image here (single input only)
  -d, --dir DIR       write recovered images into DIR, named after each input
      --report-only   do not write anything
      --trace         print the Windows calls and the last instructions
      --ticks N       instruction budget per file (default 120000000)
  -h, --help          this

Exit status: 0 if every input gave back an image, 1 if any did not, 2 on a
usage or I/O error.";

struct Opts {
    files: Vec<PathBuf>,
    output: Option<PathBuf>,
    dir: Option<PathBuf>,
    report_only: bool,
    trace: bool,
    ticks: u64,
}

fn parse_args() -> Result<Opts, String> {
    let mut o = Opts {
        files: Vec::new(),
        output: None,
        dir: None,
        report_only: false,
        trace: false,
        ticks: 120_000_000,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => return Err(String::new()),
            "-o" | "--output" => o.output = Some(args.next().ok_or("-o needs a path")?.into()),
            "-d" | "--dir" => o.dir = Some(args.next().ok_or("-d needs a path")?.into()),
            "--report-only" => o.report_only = true,
            "--trace" => o.trace = true,
            "--ticks" => {
                o.ticks = args
                    .next()
                    .ok_or("--ticks needs a number")?
                    .parse()
                    .map_err(|_| "--ticks needs a number")?
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unknown option {other}"))
            }
            other => o.files.push(other.into()),
        }
    }
    if o.files.is_empty() {
        return Err("no input files".to_string());
    }
    if o.output.is_some() && o.files.len() > 1 {
        return Err("-o takes a single input; use -d for several".to_string());
    }
    Ok(o)
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("exav-pe-emu: {msg}\n");
            }
            eprintln!("{USAGE}");
            return if msg.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            };
        }
    };
    if let Some(dir) = &opts.dir {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("exav-pe-emu: {}: {e}", dir.display());
            return ExitCode::from(2);
        }
    }

    let limits = EmuLimits {
        max_ticks: opts.ticks,
        trace: opts.trace,
        ..Default::default()
    };
    let mut all_recovered = true;
    for path in &opts.files {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("exav-pe-emu: {}: {e}", path.display());
                return ExitCode::from(2);
            }
        };
        let started = std::time::Instant::now();
        let report = unpack(&data, &limits);
        let ms = started.elapsed().as_millis();

        let name = path.display();
        match &report.unpacked {
            Some(u) => println!(
                "{name}: recovered {} KiB (entry point {:#x}{}) in {} instructions, {ms} ms",
                u.data.len() / 1024,
                u.oep_rva,
                if u.reached_oep {
                    ""
                } else {
                    ", stub stopped before reaching it"
                },
                report.ticks
            ),
            None => println!(
                "{name}: nothing recovered — {} (after {} instructions, {ms} ms)",
                report.stop, report.ticks
            ),
        }
        if !report.extra.is_empty() {
            println!(
                "{name}: {} image(s) also found in memory the stub allocated",
                report.extra.len()
            );
        }
        if !report.missing_apis.is_empty() {
            println!(
                "{name}: unimplemented calls: {}",
                report.missing_apis.join(", ")
            );
        }
        if opts.trace {
            for c in &report.api_calls {
                println!("  api  {c}");
            }
            for t in &report.tail {
                println!("  {t}");
            }
        }

        let mut wrote_any = false;
        if !opts.report_only {
            let mut images: Vec<(String, &Vec<u8>)> = Vec::new();
            if let Some(u) = &report.unpacked {
                images.push(("unpacked".to_string(), &u.data));
            }
            for (i, e) in report.extra.iter().enumerate() {
                images.push((format!("allocation-{i}"), e));
            }
            for (kind, bytes) in images {
                let out = match (&opts.output, &opts.dir) {
                    (Some(p), _) if kind == "unpacked" => p.clone(),
                    (Some(p), _) => p.with_extension(&kind),
                    (None, Some(d)) => d.join(format!(
                        "{}.{kind}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    )),
                    (None, None) => {
                        let mut p = path.clone().into_os_string();
                        p.push(format!(".{kind}"));
                        PathBuf::from(p)
                    }
                };
                if let Err(e) = std::fs::write(&out, bytes) {
                    eprintln!("exav-pe-emu: {}: {e}", out.display());
                    return ExitCode::from(2);
                }
                println!("{name}: wrote {}", out.display());
                wrote_any = true;
            }
        } else {
            wrote_any = report.unpacked.is_some() || !report.extra.is_empty();
        }
        all_recovered &= wrote_any;
    }
    if all_recovered {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
