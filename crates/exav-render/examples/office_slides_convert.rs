//! Converts presentations and drawings from the command line:
//! `cargo run -p exav-render --features office-slides --example office_slides_convert -- <command>`.
//!
//! `one <format> <in> <out.pptx>` converts one file.
//! `batch <format> <in dir> <out dir>` converts every file of a directory,
//! writing `<out dir>/<name>.pptx` and printing one JSON line per file: its
//! name, the outcome, the time in microseconds, the size of the PPTX, the
//! slides, and the warnings.

use exav_render::slides::{convert, Format, Limits};
use std::time::Instant;

fn format(name: &str) -> Format {
    Format::from_extension(name).unwrap_or_else(|| {
        eprintln!("unknown format {name}");
        std::process::exit(2);
    })
}

fn json(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push(' '),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let limits = Limits::default();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["one", fmt, input, output] => {
            let bytes = std::fs::read(input).expect("read the input");
            match convert(&bytes, format(fmt), &limits) {
                Ok(c) => {
                    std::fs::write(output, &c.pptx).expect("write the output");
                    for w in &c.warnings {
                        eprintln!("warning: {w}");
                    }
                }
                Err(e) => {
                    eprintln!("{}: {e}", e.kind());
                    std::process::exit(1);
                }
            }
        }
        ["batch", fmt, dir, out] => {
            let fmt = format(fmt);
            std::fs::create_dir_all(out).expect("create the output directory");
            let mut names: Vec<_> = std::fs::read_dir(dir)
                .expect("read the directory")
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect();
            names.sort();
            for p in names {
                let name = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let Ok(bytes) = std::fs::read(&p) else {
                    continue;
                };
                let t = Instant::now();
                let r = std::panic::catch_unwind(|| convert(&bytes, fmt, &Limits::default()));
                let us = t.elapsed().as_micros();
                match r {
                    Ok(Ok(c)) => {
                        let stem = name.rsplit_once('.').map(|s| s.0).unwrap_or(&name);
                        std::fs::write(format!("{out}/{stem}.pptx"), &c.pptx).expect("write");
                        let w: Vec<String> = c.warnings.iter().map(|w| json(w)).collect();
                        println!(
                            "{{\"name\":{},\"ok\":true,\"us\":{us},\"size\":{},\"slides\":{},\"warnings\":[{}]}}",
                            json(&name),
                            c.pptx.len(),
                            c.slides,
                            w.join(",")
                        );
                    }
                    Ok(Err(e)) => println!(
                        "{{\"name\":{},\"ok\":false,\"kind\":\"{}\",\"error\":{},\"us\":{us}}}",
                        json(&name),
                        e.kind(),
                        json(&e.to_string())
                    ),
                    Err(_) => println!(
                        "{{\"name\":{},\"ok\":false,\"kind\":\"panic\",\"error\":\"panic\",\"us\":{us}}}",
                        json(&name)
                    ),
                }
            }
        }
        _ => {
            eprintln!("usage: one <format> <in> <out> | batch <format> <dir> <out dir>");
            std::process::exit(2);
        }
    }
}
