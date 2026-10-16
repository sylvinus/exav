// hayro-eval PDF OUTDIR MAXPAGES: renders the first MAXPAGES pages of PDF at scale 1 (one point to
// one pixel, as pdf.js's viewport at scale 1) on white, writes OUTDIR/<stem>-<page>.png and prints
// one JSON line per page: ms to render, size, or the failure.
use hayro::{render, RenderCache, RenderSettings, PixmapSettings};
use hayro_interpret::InterpreterSettings;
use hayro_syntax::Pdf;
use std::time::Instant;

fn json(s: &str) -> String {
    s.chars().flat_map(|c| match c {
        '"' => vec!['\\', '"'],
        '\\' => vec!['\\', '\\'],
        c if (c as u32) < 0x20 => vec![' '],
        c => vec![c],
    }).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (path, out, max) = (&a[1], &a[2], a[3].parse::<usize>().unwrap());
    let stem = std::path::Path::new(path).file_stem().unwrap().to_string_lossy().to_string();
    let data = std::fs::read(path).unwrap();
    let t0 = Instant::now();
    let pdf = match Pdf::new(data) {
        Ok(p) => p,
        Err(e) => {
            println!("{{\"pdf\":\"{}\",\"page\":0,\"status\":\"load: {}\"}}", json(&stem), json(&format!("{e:?}")));
            return;
        }
    };
    let load_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let pages = pdf.pages();
    let cache = RenderCache::new();
    let settings = InterpreterSettings::default();
    let render_settings = RenderSettings::default();
    for (i, page) in pages.iter().enumerate().take(max) {
        let t = Instant::now();
        let pix = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ps = PixmapSettings { bg_color: hayro::vello_cpu::color::palette::css::WHITE, ..PixmapSettings::default() };
            render(page, &cache, &settings, &render_settings, &ps)
        }));
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        match pix {
            Ok(p) => {
                let (w, h) = (p.width(), p.height());
                let png = p.into_png().unwrap_or_default();
                let file = format!("{out}/{stem}-{}.png", i + 1);
                std::fs::write(&file, &png).unwrap();
                println!("{{\"pdf\":\"{}\",\"page\":{},\"pages\":{},\"w\":{w},\"h\":{h},\"ms\":{ms:.1},\"load_ms\":{load_ms:.1},\"status\":\"ok\"}}", json(&stem), i + 1, pages.len());
            }
            Err(_) => println!("{{\"pdf\":\"{}\",\"page\":{},\"status\":\"panic\"}}", json(&stem), i + 1),
        }
    }
}
