//! Every fixture, with each length or count in turn set to an extreme.
//!
//! A file's header says how big its parts are and how many there are, and a
//! file that lies about it is the oldest trick against a reader: the size
//! becomes an allocation before a byte of the data has been seen, a count a
//! loop. Fuzzing finds these by chance. This sweep is the deterministic
//! version: for each fixture, at each position of its start, 4 bytes are
//! overwritten with `0xFFFFFFFF` and with `0x7FFFFFFF`, and the file is read.
//! None may hold more than a few times the file (measured as what the process
//! has resident, where a request the reader never touches costs nothing),
//! take seconds, or panic. `EXAV_DEBUG_SATURATE=full` takes more positions and
//! values. A finding prints the fixture, the position and the value.

#![cfg(all(
    feature = "office-docs",
    feature = "office-slides",
    feature = "office-sheets"
))]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// What reading may hold over the size of the file.
const RESIDENT_BASE: usize = 96 << 20;
const RESIDENT_PER_BYTE: usize = 256;
const SLOW: Duration = Duration::from_secs(4);
/// What the converters are given to hold, so that holding more is theirs.
const OFFICE_MEMORY: u64 = 32 << 20;

fn walk_dir(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            walk_dir(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// A fixture's name without a `.gz`, and its bytes.
fn load(p: &Path) -> Option<(String, Vec<u8>)> {
    let raw = std::fs::read(p).ok()?;
    let name = p.display().to_string();
    match name.strip_suffix(".gz") {
        Some(plain) => {
            let mut out = vec![];
            flate2::read::GzDecoder::new(&raw[..])
                .take(8 << 20)
                .read_to_end(&mut out)
                .ok()?;
            Some((plain.to_string(), out))
        }
        None => Some((name, raw)),
    }
}

/// What reads a file, by its extension. `None` when nothing here does.
type Reader = fn(&[u8]);

fn reader_for(name: &str) -> Option<Reader> {
    let ext = name.rsplit('.').next()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        // Not JPEG XL: zenjxl-decoder sizes the buffer of each section of a frame
        // from the length its table of contents declares, and zero-fills it
        // before the data is looked at, so one header can take a gigabyte. The
        // pixel and channel limits set in `image::jxl` do not reach it.
        #[cfg(feature = "image")]
        "png" | "jpg" | "jpeg" | "gif" | "tif" | "tiff" | "bmp" | "webp" | "ico" | "ppm"
        | "pgm" | "pbm" | "pam" | "qoi" | "dds" | "ff" | "hdr" | "j2k" | "jp2" | "jb2" | "raf"
        | "dng" | "cr2" | "cr3" | "nef" | "arw" | "orf" | "rw2" | "pef" | "dcr" => |d| {
            let _ = exav_render::image::decode_any(d, 64 << 20);
        },
        #[cfg(feature = "stl")]
        "stl" => |d| {
            let _ = exav_render::stl::read(d, 1 << 20);
        },
        #[cfg(feature = "obj")]
        "obj" => |d| {
            let _ = exav_render::obj::read(d, 1 << 20);
        },
        #[cfg(feature = "ply")]
        "ply" => |d| {
            let _ = exav_render::ply::read(d, 1 << 20);
        },
        #[cfg(feature = "gltf")]
        "gltf" | "glb" => |d| {
            let _ = exav_render::gltf::read(d, 1 << 20);
        },
        #[cfg(feature = "ifc")]
        "ifc" => |d| {
            let _ = exav_render::ifc::read(d, &exav_render::ifc::Limits::default());
        },
        #[cfg(feature = "dwg")]
        "dwg" => |d| {
            let _ = exav_render::dwg::Document::parse(d).map(|doc| {
                for l in doc.layouts() {
                    let _ = doc.tessellate(Some(&l.name), None);
                }
            });
        },
        #[cfg(feature = "dwg")]
        "dxf" => |d| {
            let _ = exav_render::cad::read_dxf(d);
        },
        "ppt" => slides(exav_render::slides::Format::Ppt),
        "odp" => slides(exav_render::slides::Format::Odp),
        "fodp" => slides(exav_render::slides::Format::Fodp),
        "key" => slides(exav_render::slides::Format::Keynote),
        "odg" => slides(exav_render::slides::Format::Odg),
        "fodg" => slides(exav_render::slides::Format::Fodg),
        "vsdx" => slides(exav_render::slides::Format::Vsdx),
        "xls" => sheets(exav_render::sheets::Format::Xls),
        "ods" => sheets(exav_render::sheets::Format::Ods),
        "fods" => sheets(exav_render::sheets::Format::Fods),
        "numbers" => sheets(exav_render::sheets::Format::Numbers),
        "doc" => docs(exav_render::docs::Format::Doc),
        "odt" => docs(exav_render::docs::Format::Odt),
        "fodt" => docs(exav_render::docs::Format::Fodt),
        "rtf" => docs(exav_render::docs::Format::Rtf),
        "pages" => docs(exav_render::docs::Format::Pages),
        _ => return None,
    })
}

fn slides(f: exav_render::slides::Format) -> Reader {
    // A function pointer cannot capture, so one per format.
    match f {
        exav_render::slides::Format::Ppt => |d| conv_slides(d, exav_render::slides::Format::Ppt),
        exav_render::slides::Format::Odp => |d| conv_slides(d, exav_render::slides::Format::Odp),
        exav_render::slides::Format::Fodp => |d| conv_slides(d, exav_render::slides::Format::Fodp),
        exav_render::slides::Format::Keynote => {
            |d| conv_slides(d, exav_render::slides::Format::Keynote)
        }
        exav_render::slides::Format::Odg => |d| conv_slides(d, exav_render::slides::Format::Odg),
        exav_render::slides::Format::Fodg => |d| conv_slides(d, exav_render::slides::Format::Fodg),
        _ => |d| conv_slides(d, exav_render::slides::Format::Vsdx),
    }
}

fn conv_slides(d: &[u8], f: exav_render::slides::Format) {
    let l = exav_render::slides::Limits::default().with_max_memory(OFFICE_MEMORY);
    let _ = exav_render::slides::convert(d, f, &l);
}

fn sheets(f: exav_render::sheets::Format) -> Reader {
    match f {
        exav_render::sheets::Format::Xls => |d| conv_sheets(d, exav_render::sheets::Format::Xls),
        exav_render::sheets::Format::Ods => |d| conv_sheets(d, exav_render::sheets::Format::Ods),
        exav_render::sheets::Format::Fods => |d| conv_sheets(d, exav_render::sheets::Format::Fods),
        _ => |d| conv_sheets(d, exav_render::sheets::Format::Numbers),
    }
}

fn conv_sheets(d: &[u8], f: exav_render::sheets::Format) {
    let l = exav_render::sheets::Limits::default().with_max_memory(OFFICE_MEMORY);
    let _ = exav_render::sheets::convert(d, f, &l);
}

fn docs(f: exav_render::docs::Format) -> Reader {
    match f {
        exav_render::docs::Format::Doc => |d| conv_docs(d, exav_render::docs::Format::Doc),
        exav_render::docs::Format::Odt => |d| conv_docs(d, exav_render::docs::Format::Odt),
        exav_render::docs::Format::Fodt => |d| conv_docs(d, exav_render::docs::Format::Fodt),
        exav_render::docs::Format::Rtf => |d| conv_docs(d, exav_render::docs::Format::Rtf),
        _ => |d| conv_docs(d, exav_render::docs::Format::Pages),
    }
}

fn conv_docs(d: &[u8], f: exav_render::docs::Format) {
    let l = exav_render::docs::Limits::default().with_max_memory(OFFICE_MEMORY);
    let _ = exav_render::docs::convert(d, f, &l);
}

fn sweep() -> (Vec<usize>, Vec<Vec<u8>>) {
    if std::env::var("EXAV_DEBUG_SATURATE").is_ok_and(|v| v == "full") {
        let mut at: Vec<usize> = (0..256).collect();
        at.extend((256..2048).step_by(2));
        at.extend((2048..8192).step_by(8));
        (
            at,
            vec![
                vec![0xFF; 4],
                vec![0xFF, 0xFF, 0xFF, 0x7F],
                vec![0x00, 0x00, 0x00, 0x80],
                vec![0x00, 0x00, 0x00, 0x10],
                vec![0xFF; 2],
                vec![0xFF; 8],
            ],
        )
    } else {
        let mut at: Vec<usize> = (0..64).collect();
        at.extend((64..512).step_by(8));
        (at, vec![vec![0xFF; 4], vec![0xFF, 0xFF, 0xFF, 0x7F]])
    }
}

/// The resident-set high-water mark in bytes, from `/proc` (Linux only).
fn high_water() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmHWM:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<usize>().ok())
        })
        .map_or(0, |kb| kb << 10)
}

fn reset_high_water() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

#[test]
fn a_field_at_its_extreme_costs_nothing_like_what_it_says() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut paths = vec![];
    walk_dir(&root, &mut paths);
    let mut corpus: Vec<(String, Reader, Vec<u8>)> = vec![];
    for p in paths {
        if let Some((name, data)) = load(&p)
            && data.len() <= 256 << 10
            && let Some(r) = reader_for(&name)
        {
            corpus.push((
                name.strip_prefix(&format!("{}/", root.display()))
                    .unwrap_or(&name)
                    .to_string(),
                r,
                data,
            ));
        }
    }
    // The office fixtures alone, when the readers of the other formats are
    // not built, are fewer.
    let least = if cfg!(feature = "image") { 30 } else { 10 };
    assert!(corpus.len() > least, "only {} fixtures", corpus.len());
    let (positions, values) = sweep();
    let mut findings: Vec<String> = vec![];
    let mut runs = 0u64;
    for (name, read, data) in &corpus {
        let allowed = RESIDENT_BASE + RESIDENT_PER_BYTE * data.len();
        let mut seen: Vec<usize> = vec![];
        for &at in &positions {
            if seen.contains(&at) {
                continue;
            }
            for value in &values {
                if at + value.len() > data.len() {
                    continue;
                }
                let mut mutated = data.clone();
                mutated[at..at + value.len()].copy_from_slice(value);
                runs += 1;
                reset_high_water();
                let before = high_water();
                let started = Instant::now();
                let r = std::panic::catch_unwind(|| read(&mutated));
                let took = started.elapsed();
                let held = high_water().saturating_sub(before);
                let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
                let end = at + value.len();
                if r.is_err() {
                    findings.push(format!("{name}: bytes {at}..{end} set to {hex} panicked"));
                    seen.push(at);
                } else if held > allowed {
                    findings.push(format!(
                        "{name}: bytes {at}..{end} set to {hex} held {} MiB (allowed {} MiB)",
                        held >> 20,
                        allowed >> 20
                    ));
                    seen.push(at);
                } else if took > SLOW {
                    findings.push(format!(
                        "{name}: bytes {at}..{end} set to {hex} took {:.1} s",
                        took.as_secs_f64()
                    ));
                    seen.push(at);
                }
            }
        }
    }
    eprintln!(
        "{} fixtures, {runs} reads, {} findings",
        corpus.len(),
        findings.len()
    );
    assert!(findings.is_empty(), "\n{}", findings.join("\n"));
}
