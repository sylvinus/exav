//! The text of office documents, as the scanner and `exav-grep --text` read it:
//! `cargo run --release -p exav-render --features text-office --example office_text -- <command>`.
//!
//! `one <file>` prints the file's sections and its text, and the links.
//! `bench <dir>` reads every file of a directory (not recursively) and prints
//! one JSON line each, the name, the outcome, the microseconds and the text's
//! bytes, then the totals.

use exav_render::text::visible_text;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let limits = exav_unpack::Limits::default();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["one", file] => {
            let data = std::fs::read(file).expect("read the file");
            let name = file.rsplit('/').next().unwrap_or(file);
            match visible_text(name, &data, 1 << 24, &limits) {
                None => println!("no text view"),
                Some(v) => {
                    if let Some(why) = &v.unreadable {
                        println!("unreadable: {why}");
                    }
                    for (label, range) in &v.sections {
                        println!("--- {label} ({} bytes)", range.len());
                    }
                    print!("{}", v.text);
                    for (label, target) in &v.links {
                        println!("link: {label} -> {target}");
                    }
                }
            }
        }
        ["bench", dir] => {
            let mut names: Vec<_> = std::fs::read_dir(dir)
                .expect("read the directory")
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();
            names.sort();
            let (mut bytes, mut micros, mut read) = (0u64, 0u128, 0u32);
            for p in names {
                let Ok(data) = std::fs::read(&p) else {
                    continue;
                };
                let name = p
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let t = Instant::now();
                let r = std::panic::catch_unwind(|| {
                    visible_text(&name, &data, 1 << 24, &exav_unpack::Limits::default())
                });
                let us = t.elapsed().as_micros();
                let outcome = match &r {
                    Ok(Some(v)) if v.unreadable.is_some() => "unreadable",
                    Ok(Some(_)) => "text",
                    Ok(None) => "none",
                    Err(_) => "panic",
                };
                let text = match &r {
                    Ok(Some(v)) => v.text.len(),
                    _ => 0,
                };
                if outcome == "text" {
                    bytes += data.len() as u64;
                    micros += us;
                    read += 1;
                }
                println!(
                    "{{\"name\":{name:?},\"outcome\":\"{outcome}\",\"us\":{us},\"text\":{text}}}"
                );
            }
            println!(
                "{{\"documents\":{read},\"input_bytes\":{bytes},\"us\":{micros},\"mb_per_s\":{:.1}}}",
                bytes as f64 / micros.max(1) as f64
            );
        }
        _ => {
            eprintln!("usage: one <file> | bench <dir>");
            std::process::exit(2);
        }
    }
}
