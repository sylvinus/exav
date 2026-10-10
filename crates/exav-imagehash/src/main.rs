//! `exav-imagehash`: perceptual hashes of image files.

use std::process::ExitCode;

use exav_imagehash::{
    Error, Format, Formats, Grey, Hasher, Params, PillowFilter, Precision, Preset, Resize,
    Threshold,
};

const USAGE: &str = "\
usage: exav-imagehash [OPTIONS] FILE...
       exav-imagehash [OPTIONS] --distance FILE FILE

Prints `FILE: HASH` for each file, the hash in hex. The ClamAV preset gives
`sigtool --fuzzy-img`'s hash, the imagehash one Python `imagehash.phash`'s.

  --preset clamav|imagehash  the starting values (default: clamav)
  --hash-size N              bits per side (default: 8)
  --highfreq-factor N        the DCT side is the hash size times N (default: 4)
  --grey bt601-float|pillow
  --resize lanczos3|catmull-rom|gaussian|triangle|nearest|
           pillow-lanczos|pillow-bicubic|pillow-bilinear|pillow-hamming|pillow-box
  --precision f32|f64
  --threshold median|mean
  --drop-dc                  leave out the DC term
  --formats all|clamav-graphics|LIST
                             the formats hashed (default: all); clamav-graphics
                             is what clamscan hashes while scanning (png, gif,
                             jpeg, tiff, bmp), LIST is like png,webp
  --max-decode-bytes N       the most a decoded image may take
  --distance                 print the number of bits that differ between
                             the two files' hashes
  --print-params             print the parameters in effect and exit
  -h, --help                 this help
  -V, --version";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("exav-imagehash: {msg}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    // The preset first, wherever it is, so the other options apply on top.
    let mut params = Params::CLAMAV;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(v) = value(a, "--preset", &mut it)? {
            params = match v.as_str() {
                "clamav" => Preset::ClamAv,
                "imagehash" => Preset::ImagehashPhash,
                _ => return Err(format!("unknown preset `{v}`")),
            }
            .params();
        }
    }
    let (mut files, mut distance, mut print_params) = (Vec::new(), false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            "-V" | "--version" => {
                println!("exav-imagehash {}", env!("CARGO_PKG_VERSION"));
                return Ok(ExitCode::SUCCESS);
            }
            "--drop-dc" => params.keep_dc = false,
            "--distance" => distance = true,
            "--print-params" => print_params = true,
            "--" => files.extend(it.by_ref().cloned()),
            _ => {
                if value(a, "--preset", &mut it)?.is_some() {
                } else if let Some(v) = value(a, "--hash-size", &mut it)? {
                    params.hash_size = number32(&v)?;
                } else if let Some(v) = value(a, "--highfreq-factor", &mut it)? {
                    params.highfreq_factor = number32(&v)?;
                } else if let Some(v) = value(a, "--grey", &mut it)? {
                    params.grey = match v.as_str() {
                        "bt601-float" => Grey::Bt601Float,
                        "pillow" => Grey::Pillow,
                        _ => return Err(format!("unknown grey conversion `{v}`")),
                    };
                } else if let Some(v) = value(a, "--resize", &mut it)? {
                    params.resize = resize(&v)?;
                } else if let Some(v) = value(a, "--precision", &mut it)? {
                    params.precision = match v.as_str() {
                        "f32" => Precision::F32,
                        "f64" => Precision::F64,
                        _ => return Err(format!("unknown precision `{v}`")),
                    };
                } else if let Some(v) = value(a, "--threshold", &mut it)? {
                    params.threshold = match v.as_str() {
                        "median" => Threshold::Median,
                        "mean" => Threshold::Mean,
                        _ => return Err(format!("unknown threshold `{v}`")),
                    };
                } else if let Some(v) = value(a, "--formats", &mut it)? {
                    params.formats = formats(&v)?;
                } else if let Some(v) = value(a, "--max-decode-bytes", &mut it)? {
                    params.max_decode_bytes = number(&v)?;
                } else if a.starts_with('-') && a.len() > 1 {
                    return Err(format!("unknown option `{a}`"));
                } else {
                    files.push(a.clone());
                }
            }
        }
    }
    let hasher = Hasher::with_params(params).map_err(|e| e.to_string())?;
    if print_params {
        let p = hasher.params();
        let names: Vec<&str> = p.formats.iter().map(Format::name).collect();
        println!(
            "hash-size {} highfreq-factor {} grey {:?} resize {:?} precision {:?} \
             threshold {:?} keep-dc {} formats {} max-decode-bytes {}",
            p.hash_size,
            p.highfreq_factor,
            p.grey,
            p.resize,
            p.precision,
            p.threshold,
            p.keep_dc,
            names.join(","),
            p.max_decode_bytes
        );
        return Ok(ExitCode::SUCCESS);
    }
    if files.is_empty() {
        return Err("no file given".into());
    }
    if distance {
        let [a, b] = files.as_slice() else {
            return Err("--distance takes two files".into());
        };
        let (ha, hb) = (hash(&hasher, a), hash(&hasher, b));
        return match (ha, hb) {
            (Ok(ha), Ok(hb)) => {
                println!("{}", ha.distance(&hb).expect("same parameters, same size"));
                Ok(ExitCode::SUCCESS)
            }
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("exav-imagehash: {e}");
                Ok(ExitCode::FAILURE)
            }
        };
    }
    let mut ok = true;
    for f in &files {
        match hash(&hasher, f) {
            Ok(h) => println!("{f}: {h}"),
            Err(e) => {
                eprintln!("exav-imagehash: {e}");
                ok = false;
            }
        }
    }
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn hash(hasher: &Hasher, path: &str) -> Result<exav_imagehash::ImageHash, String> {
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    hasher.hash(&data).map_err(|e| match e {
        Error::Unsupported => format!("{path}: not an image of the formats asked for"),
        e => format!("{path}: {e}"),
    })
}

/// The value of `--name VALUE` or `--name=VALUE`, when `arg` is that option.
fn value(
    arg: &str,
    name: &str,
    rest: &mut std::slice::Iter<'_, String>,
) -> Result<Option<String>, String> {
    if arg == name {
        return rest
            .next()
            .cloned()
            .map(Some)
            .ok_or(format!("{name} takes a value"));
    }
    Ok(arg
        .strip_prefix(name)
        .and_then(|r| r.strip_prefix('='))
        .map(str::to_string))
}

fn number(v: &str) -> Result<u64, String> {
    v.parse().map_err(|_| format!("`{v}` is not a number"))
}

/// A number that fits `u32`: one past it would otherwise be cut to its low
/// bits, a different hash size with no word about it.
fn number32(v: &str) -> Result<u32, String> {
    u32::try_from(number(v)?).map_err(|_| format!("`{v}` is too large"))
}

fn resize(v: &str) -> Result<Resize, String> {
    Ok(match v {
        "lanczos3" => Resize::Lanczos3,
        "catmull-rom" => Resize::CatmullRom,
        "gaussian" => Resize::Gaussian,
        "triangle" => Resize::Triangle,
        "nearest" => Resize::Nearest,
        "pillow-lanczos" => Resize::Pillow(PillowFilter::Lanczos),
        "pillow-bicubic" => Resize::Pillow(PillowFilter::Bicubic),
        "pillow-bilinear" => Resize::Pillow(PillowFilter::Bilinear),
        "pillow-hamming" => Resize::Pillow(PillowFilter::Hamming),
        "pillow-box" => Resize::Pillow(PillowFilter::Box),
        _ => return Err(format!("unknown resize `{v}`")),
    })
}

fn formats(v: &str) -> Result<Formats, String> {
    match v {
        "clamav-graphics" => return Ok(Formats::CLAMAV_GRAPHICS),
        "all" => return Ok(Formats::all()),
        _ => {}
    }
    let mut set = Formats::NONE;
    for name in v.split(',') {
        let f = Formats::ALL
            .iter()
            .find(|f| f.name() == name)
            .ok_or(format!("unknown or not built format `{name}`"))?;
        set = set.with(f);
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_size_past_u32_is_refused_not_cut() {
        // 2^32 + 8 would be a hash size of 8.
        for opt in ["--hash-size", "--highfreq-factor"] {
            let err = run(vec![opt.into(), "4294967304".into()]).unwrap_err();
            assert!(err.contains("too large"), "{opt}: {err}");
        }
    }

    #[test]
    #[cfg(all(feature = "jp2", feature = "jbig2"))]
    fn formats_takes_jpeg_2000_and_jbig2() {
        let set = formats("jpeg2000,jbig2").unwrap();
        let names: Vec<&str> = set.iter().map(Format::name).collect();
        assert_eq!(names, ["jpeg2000", "jbig2"]);
        assert!(formats("all").unwrap().contains(Format::Jpeg2000));
        assert!(!formats("clamav-graphics").unwrap().contains(Format::Jbig2));
        assert!(formats("png,nope").is_err());
    }
}
