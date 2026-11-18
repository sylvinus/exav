//! What the `exav-grep` and `exav-qr` commands share: the flags that say how a
//! file is read and what is opened in it, the limits of the QR reading, the
//! walk over the paths named on the command line, and the exit code. Compiled
//! into each binary; it is not part of the library.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use exav_grep::Options;
use exav_unpack::Limits;

/// How files are read and what is opened in them.
#[derive(Args)]
pub struct ReadArgs {
    /// Recurse into directories.
    #[arg(short = 'r', long)]
    pub recursive: bool,

    /// Most bytes held in memory at once for one file or member, with
    /// K/M/G/T suffixes (default 256M). A member up to it is held, so a
    /// container in it can be opened; a longer one is read as a stream (a
    /// file, or a stored member, where it lies, through a block cache: see
    /// --object-cache-bytes), and a container in it is opened through a spill
    /// file (--spill-dir). `off` or `0` sets no limit.
    ///
    /// A member that is decoded as it is read is held whole, whatever this
    /// is, when it ends or fails within 4 MiB + 1 KiB: the start that is read
    /// to tell what it is.
    #[arg(
        long = "max-object-bytes",
        env = "EXAV_MAX_OBJECT_BYTES",
        value_name = "SIZE|off"
    )]
    max_object_bytes: Option<String>,

    /// Most bytes of members that a format decodes into memory itself before
    /// handing them over (OLE streams, PDF streams, RTF objects, installers,
    /// decrypted members and the like), summed over one file and never
    /// released, with K/M/G/T suffixes (default 1G). The bytes a PDF is read
    /// again to follow its objects count too. A member handed over as a
    /// stream (ZIP, 7z, TAR, CAB and the stream codecs) is not counted. A file
    /// that reaches it is reported unreadable. `off` or `0` sets no limit.
    #[arg(
        long = "max-extracted-bytes",
        env = "EXAV_MAX_EXTRACTED_BYTES",
        value_name = "SIZE|off"
    )]
    max_extracted_bytes: Option<String>,

    /// Max nesting depth of archives within archives. `0` opens no archive:
    /// each file is searched as it stands. There is no `off`: every level
    /// costs stack.
    ///
    /// Not directory depth, which `find`/`du`/`tree` spell `--max-depth`; named
    /// for what it bounds, and matching `exav --max-unpack-depth`.
    #[arg(
        long = "max-unpack-depth",
        env = "EXAV_MAX_UNPACK_DEPTH",
        value_name = "N"
    )]
    max_depth: Option<u32>,

    /// Directory for the anonymous temporary file a container inside a
    /// member over --max-object-bytes is written to so it can be opened
    /// (default: the system temporary directory). `off` writes nothing, and
    /// such a container is reported unreadable.
    #[arg(long = "spill-dir", env = "EXAV_SPILL_DIR", value_name = "DIR|off")]
    spill_dir: Option<String>,

    /// Most the spill files open at once may hold, with K/M/G/T suffixes
    /// (default 2G). A container that would pass it is reported unreadable.
    /// `off` or `0` sets no ceiling.
    #[arg(
        long = "max-total-spill-bytes",
        env = "EXAV_MAX_TOTAL_SPILL_BYTES",
        value_name = "SIZE|off"
    )]
    max_spill_bytes: Option<String>,

    /// Memory of the block cache of an object that is read where it lies
    /// instead of being held: a file past --max-object-bytes, a container
    /// spilled to disk. One cache per such object being read, the nested ones
    /// included. K/M/G/T suffixes (default 32M). Never below two blocks; `off`
    /// or `0` is that least.
    #[arg(
        long = "object-cache-bytes",
        env = "EXAV_OBJECT_CACHE_BYTES",
        value_name = "SIZE|off"
    )]
    object_cache_bytes: Option<String>,

    /// One block of that cache: the unit read from the object at a time, with
    /// K/M/G/T suffixes (default 1M). `off` or `0` is a byte.
    #[arg(
        long = "object-cache-block-bytes",
        env = "EXAV_OBJECT_CACHE_BLOCK_BYTES",
        value_name = "SIZE|off"
    )]
    object_cache_block_bytes: Option<String>,
}

impl ReadArgs {
    /// The options these flags set, the others being `Options::default()`'s,
    /// or the first flag whose value is refused.
    pub fn options(&self) -> Result<Options, String> {
        let defaults = Options::default();
        let mut limits = Limits::default();
        if let Some(v) = self.max_object_bytes.as_deref() {
            limits.max_buffer_bytes = size_limit("--max-object-bytes", v)?.unwrap_or(u64::MAX);
        }
        if let Some(v) = self.max_extracted_bytes.as_deref() {
            limits.max_extracted_bytes =
                size_limit("--max-extracted-bytes", v)?.unwrap_or(u64::MAX);
        }
        if let Some(d) = self.max_depth {
            limits.max_recursion = d;
        }
        // `off` and `0` are the least a cache can be: the library never goes
        // below two blocks of a byte.
        let size_or = |flag: &str, value: &Option<String>, default: u64| match value.as_deref() {
            None => Ok(default),
            Some(v) => size_limit(flag, v).map(|n| n.unwrap_or(0)),
        };
        let object_cache_bytes = size_or(
            "--object-cache-bytes",
            &self.object_cache_bytes,
            defaults.object_cache_bytes,
        )?;
        let object_cache_block_bytes = size_or(
            "--object-cache-block-bytes",
            &self.object_cache_block_bytes,
            defaults.object_cache_block_bytes,
        )?;
        let spill_dir = match self.spill_dir.as_deref() {
            Some("off") => None,
            Some(dir) => Some(dir.into()),
            None => Some(std::env::temp_dir()),
        };
        let max_spill_bytes = match self.max_spill_bytes.as_deref() {
            None => Some(2 << 30),
            Some(v) => size_limit("--max-total-spill-bytes", v)?,
        };
        Ok(Options {
            limits,
            object_cache_bytes,
            object_cache_block_bytes,
            spill_dir,
            max_spill_bytes,
            ..defaults
        })
    }
}

/// The limits of the reading of the QR codes of an image. Without the `qr`
/// feature there are none, and the struct has no flags.
#[derive(Args)]
pub struct QrArgs {
    /// Pixels an image may have for its QR codes to be read (default
    /// 50000000). A larger one is reported unreadable. `off` or `0` sets no
    /// limit.
    #[cfg(feature = "qr")]
    #[arg(
        long = "max-qr-pixels",
        env = "EXAV_MAX_QR_PIXELS",
        value_name = "N|off"
    )]
    max_qr_pixels: Option<String>,

    /// Milliseconds the reading of the QR codes of one image may take (default
    /// 5000). One cut short is reported unreadable. `off` or `0` sets no
    /// limit.
    #[cfg(feature = "qr")]
    #[arg(
        long = "max-qr-millis",
        env = "EXAV_MAX_QR_MILLIS",
        value_name = "MS|off"
    )]
    max_qr_millis: Option<String>,

    /// QR codes that may be read in one image (default 64). An image with
    /// more is reported unreadable. `off` or `0` reads them all.
    #[cfg(feature = "qr")]
    #[arg(long = "max-qr-codes", env = "EXAV_MAX_QR_CODES", value_name = "N|off")]
    max_qr_codes: Option<String>,

    /// Finder patterns (the square a QR code has in three corners) that may be
    /// found in one image (default 1000). An image with more is reported
    /// unreadable. `off` or `0` sets no limit.
    #[cfg(feature = "qr")]
    #[arg(
        long = "max-qr-finders",
        env = "EXAV_MAX_QR_FINDERS",
        value_name = "N|off"
    )]
    max_qr_finders: Option<String>,

    /// Groups of three finder patterns that may be tried as a QR code in one
    /// image (default 256). An image with more is reported unreadable. `off`
    /// or `0` sets no limit.
    #[cfg(feature = "qr")]
    #[arg(long = "max-qr-grids", env = "EXAV_MAX_QR_GRIDS", value_name = "N|off")]
    max_qr_grids: Option<String>,
}

impl QrArgs {
    /// Set the QR limits of `opts` from these flags, or name the first flag
    /// whose value is refused.
    #[cfg(feature = "qr")]
    pub fn apply(&self, opts: &mut Options) -> Result<(), String> {
        use exav_render::qr::{
            DEFAULT_MAX_CODES, DEFAULT_MAX_FINDERS, DEFAULT_MAX_GRIDS, DEFAULT_MAX_PIXELS,
            DEFAULT_MAX_TIME,
        };
        opts.max_qr_pixels = limit_or_off(
            self.max_qr_pixels.as_deref(),
            DEFAULT_MAX_PIXELS,
            "--max-qr-pixels",
        )?;
        opts.max_qr_millis = limit_or_off(
            self.max_qr_millis.as_deref(),
            DEFAULT_MAX_TIME.as_millis() as u64,
            "--max-qr-millis",
        )?;
        opts.max_qr_codes = limit_or_off(
            self.max_qr_codes.as_deref(),
            DEFAULT_MAX_CODES as u64,
            "--max-qr-codes",
        )?;
        opts.max_qr_finders = limit_or_off(
            self.max_qr_finders.as_deref(),
            DEFAULT_MAX_FINDERS as u64,
            "--max-qr-finders",
        )?;
        opts.max_qr_grids = limit_or_off(
            self.max_qr_grids.as_deref(),
            DEFAULT_MAX_GRIDS as u64,
            "--max-qr-grids",
        )?;
        Ok(())
    }

    /// Without the `qr` feature there is nothing to set.
    #[cfg(not(feature = "qr"))]
    pub fn apply(&self, _: &mut Options) -> Result<(), String> {
        Ok(())
    }
}

/// A limit given as a number or `off`: `None` for `off` or `0`, as `exav`
/// reads them, `default` when not given. `Err` names the flag.
#[cfg(feature = "qr")]
fn limit_or_off(v: Option<&str>, default: u64, flag: &str) -> Result<Option<u64>, String> {
    match v.map(str::trim) {
        None => Ok(Some(default)),
        Some(n) if n.eq_ignore_ascii_case("off") => Ok(None),
        Some(n) => match n.parse::<u64>() {
            Ok(0) => Ok(None),
            Ok(n) => Ok(Some(n)),
            Err(_) => Err(format!("{flag}: expected a number or `off`, got `{n}`")),
        },
    }
}

/// A size given as the scanner's flags take one: bytes with an optional
/// K/M/G/T suffix (base 1024), where `off` and `0` mean no limit (`None`).
/// `Err` names the flag.
fn size_limit(flag: &str, value: &str) -> Result<Option<u64>, String> {
    let s = value.trim();
    if s.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    let (digits, shift) = match s.char_indices().last() {
        Some((i, 'k' | 'K')) => (&s[..i], 10),
        Some((i, 'm' | 'M')) => (&s[..i], 20),
        Some((i, 'g' | 'G')) => (&s[..i], 30),
        Some((i, 't' | 'T')) => (&s[..i], 40),
        _ => (s, 0),
    };
    match digits
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(1 << shift))
    {
        Some(0) => Ok(None),
        Some(n) => Ok(Some(n)),
        None => Err(format!(
            "{flag}: expected a size (bytes, or K/M/G/T suffixes) or `off`, got `{value}`"
        )),
    }
}

/// What the walk over the paths of a command line left unsaid.
#[derive(Default)]
pub struct Walked {
    /// A path could not be searched, or is a directory without `-r`.
    pub io_error: bool,
    /// Paths of a directory the filesystem walk could not reach. Counted like
    /// an unreadable member, because it is the same fact one level up: a
    /// subtree nobody could open is not a subtree with nothing in it.
    pub unreachable: u64,
}

/// Call `search` on each file of `paths`, those of a directory too under
/// `recursive`, until it answers `Ok(false)`. An error from `search` is said
/// on stderr under the name of the command, `prog`, and ends in
/// [`Walked::io_error`]; so does a directory without `recursive`. A path the
/// walk of a directory could not reach is said too, unless `quiet`.
pub fn each_file(
    prog: &str,
    paths: &[PathBuf],
    recursive: bool,
    quiet: bool,
    mut search: impl FnMut(&Path) -> io::Result<bool>,
) -> Walked {
    let mut walked = Walked::default();
    for p in paths {
        let files: Vec<PathBuf> = if p.is_dir() {
            if !recursive {
                eprintln!("{prog}: {}: is a directory (use -r)", p.display());
                walked.io_error = true;
                continue;
            }
            let mut files = Vec::new();
            for entry in walkdir::WalkDir::new(p) {
                match entry {
                    Ok(e) if e.file_type().is_file() => files.push(e.into_path()),
                    Ok(_) => {}
                    Err(e) => {
                        walked.unreachable += 1;
                        if !quiet {
                            let at = e
                                .path()
                                .map(|q| q.display().to_string())
                                .unwrap_or_else(|| p.display().to_string());
                            eprintln!("{prog}: {at}: unreadable: {e}");
                        }
                    }
                }
            }
            files
        } else {
            vec![p.clone()]
        };
        for f in files {
            match search(&f) {
                // The sink asked to stop, a closed pipe say. Carrying on
                // writes into a pipe nobody is reading for the rest of the
                // tree.
                Ok(false) => return walked,
                Ok(true) => {}
                Err(e) => {
                    eprintln!("{prog}: {}: {e}", f.display());
                    walked.io_error = true;
                }
            }
        }
    }
    walked
}

/// The exit code of a run: 2 when a result could not be written or a path
/// could not be searched, 0 when something was `found`, 3 when nothing was
/// but some of the input was not examined (`unreadable` members, or paths the
/// walk could not reach), else 1. The 3 is the one a script has to handle:
/// "nothing found" is only an answer about what was read.
pub fn exit_code(
    prog: &str,
    walked: &Walked,
    write_failed: bool,
    found: usize,
    unreadable: usize,
) -> ExitCode {
    if write_failed {
        eprintln!("{prog}: could not write results");
        ExitCode::from(2)
    } else if walked.io_error {
        ExitCode::from(2)
    } else if found > 0 {
        ExitCode::SUCCESS
    } else if unreadable > 0 || walked.unreachable > 0 {
        ExitCode::from(3)
    } else {
        ExitCode::from(1)
    }
}
