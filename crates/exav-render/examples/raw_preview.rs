//! Print what the RAW reader makes of each file given: its family, the
//! preview chosen, and how long it took, one tab-separated line a file. With
//! `--png DIR`, the preview is also saved there as `<file name>.png`.
//!
//!     cargo run --release -p exav-render --example raw_preview -- \
//!         [--png DIR] [--budget BYTES] <file>...

use std::time::Instant;

use exav_render::image::DECODE_MAX;
use exav_render::image::raw;

fn main() {
    let mut args = std::env::args().skip(1).peekable();
    let (mut png_dir, mut budget) = (None, DECODE_MAX);
    let mut files = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--png" => png_dir = args.next(),
            "--budget" => budget = args.next().and_then(|v| v.parse().ok()).unwrap_or(budget),
            _ => files.push(a),
        }
    }
    for f in files {
        let data = match std::fs::read(&f) {
            Ok(d) => d,
            Err(e) => {
                println!("{f}\tERR\tread: {e}");
                continue;
            }
        };
        let name = std::path::Path::new(&f)
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let started = Instant::now();
        let result = raw::preview(&data, budget);
        let ms = started.elapsed().as_millis();
        match result {
            Ok((pixels, info)) => {
                println!(
                    "{name}\t{}\t{}x{}\to{}\t{}\tfound {}\tout {}x{}\t{ms} ms",
                    info.kind.name(),
                    info.width,
                    info.height,
                    info.orientation,
                    if info.jpeg { "jpeg" } else { "samples" },
                    info.found,
                    pixels.width,
                    pixels.height,
                );
                if let Some(dir) = &png_dir {
                    let rgba = pixels.to_rgba8();
                    if let Some(img) = image::RgbaImage::from_raw(pixels.width, pixels.height, rgba)
                    {
                        let _ = img.save(format!("{dir}/{name}.png"));
                    }
                }
            }
            // Not a RAW file for the reader: `decode_any` reads it as the
            // image it may be (a plain TIFF).
            Err(exav_render::image::Error::Unsupported) => {
                match exav_render::image::decode_any(&data, budget) {
                    Ok(p) => println!("{name}\tOTHER\t{}x{}\t{ms} ms", p.width, p.height),
                    Err(e) => println!("{name}\t-\tERR\t{e}\t{ms} ms"),
                }
            }
            Err(e) => match raw::detect(&data) {
                Some(kind) => println!("{name}\t{}\tERR\t{e}\t{ms} ms", kind.name()),
                None => println!("{name}\t-\tERR\t{e}\t{ms} ms"),
            },
        }
    }
}
