//! Presentations to PPTX: PowerPoint 95 and 97 to 2003 (PPT, PPS, POT; 2 to
//! 4 are recognised and reported as unsupported), OpenDocument (ODP, OTP,
//! FODP) and Apple Keynote (every version), converted for a PPTX renderer to
//! draw. OpenDocument drawings (ODG, OTG, FODG) and Visio drawings (VSDX,
//! VSDM, VSTX, VSTM) too: each page is a slide, named as the page is.

mod error;
mod keynote;
mod limits;
mod model;
mod odp;
mod package;
mod ppt;
mod pptx;
mod text;
mod vsdx;

pub use error::Error;
pub use limits::Limits;
pub use package::Source;

/// The formats this module converts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    /// PowerPoint presentations, shows and templates (.ppt, .pps, .pot):
    /// 95 and 97 to 2003 are read, 2 to 4 refused as unsupported.
    Ppt,
    /// OpenDocument presentations and templates (.odp, .otp).
    Odp,
    /// Flat OpenDocument presentations (.fodp).
    Fodp,
    /// Apple Keynote documents (.key), as one file, a package directory
    /// given file by file, or the XML of Keynote 1 to 5 alone.
    Keynote,
    /// OpenDocument drawings and templates (.odg, .otg): each page a slide,
    /// the pages' largest size the PPTX's.
    Odg,
    /// Flat OpenDocument drawings (.fodg).
    Fodg,
    /// Visio 2013 and later drawings and templates (.vsdx, .vsdm, .vstx,
    /// .vstm): each page a slide, the pages' largest size the PPTX's.
    Vsdx,
}

impl Format {
    /// The format of a file extension (without its dot, any case).
    pub fn from_extension(ext: &str) -> Option<Format> {
        Some(match ext.to_ascii_lowercase().as_str() {
            "ppt" | "pps" | "pot" => Format::Ppt,
            "odp" | "otp" => Format::Odp,
            "fodp" => Format::Fodp,
            "key" | "keynote" => Format::Keynote,
            "odg" | "otg" => Format::Odg,
            "fodg" => Format::Fodg,
            "vsdx" | "vsdm" | "vstx" | "vstm" => Format::Vsdx,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Format::Ppt => "ppt",
            Format::Odp => "odp",
            Format::Fodp => "fodp",
            Format::Keynote => "key",
            Format::Odg => "odg",
            Format::Fodg => "fodg",
            Format::Vsdx => "vsdx",
        }
    }
}

/// A converted document.
#[derive(Debug)]
pub struct Converted {
    /// The PPTX package.
    pub pptx: Vec<u8>,
    /// Slides in the PPTX.
    pub slides: usize,
    /// Slides in the document: more than `slides` from [`convert_first`].
    pub total_slides: usize,
    /// What was left out or could not be read, for diagnostics.
    pub warnings: Vec<String>,
}

/// Converts `input`, a document of `format`, to PPTX.
pub fn convert(input: &[u8], format: Format, limits: &Limits) -> Result<Converted, Error> {
    convert_first(input, format, limits, usize::MAX)
}

/// Converts the masters and the first `n` slides of `input` only, to show
/// them while the whole document converts. The pictures and parts of the
/// other slides are not read. Links to slides past `n` are dropped.
pub fn convert_first(
    input: &[u8],
    format: Format,
    limits: &Limits,
    n: usize,
) -> Result<Converted, Error> {
    if input.len() as u64 > limits.max_input {
        return Err(Error::TooLarge("input"));
    }
    let mut budget = limits::Budget::new(*limits).only(0..n);
    let p = read(input, format, &mut budget)?;
    finish(p, &budget)
}

/// `input` read into the model, whatever its format.
fn read(
    input: &[u8],
    format: Format,
    budget: &mut limits::Budget,
) -> Result<model::Presentation, Error> {
    Ok(match format {
        Format::Ppt => ppt::read(input, budget)?,
        Format::Odp => odp::read_odp(package::Zip::open(input)?, budget)?,
        Format::Fodp => odp::read_fodp(input, budget)?,
        Format::Odg => odp::read_odg(package::Zip::open(input)?, budget)?,
        Format::Fodg => odp::read_fodg(input, budget)?,
        Format::Vsdx => vsdx::read_bytes(input, budget)?,
        Format::Keynote if keynote::is_bare_xml(input) => keynote::read_bare(input, budget)?,
        Format::Keynote => keynote::read(package::Zip::open(input), budget)?,
    })
}

/// The text of `input`, a document of `format`, cut at `cap` bytes: a section
/// to a slide, from the model the reader fills and not from a PPTX written
/// and read back. Refuses what [`convert`] refuses.
pub fn text(
    input: &[u8],
    format: Format,
    limits: &Limits,
    cap: usize,
) -> Result<crate::formats::office::text::Text, Error> {
    if input.len() as u64 > limits.max_input {
        return Err(Error::TooLarge("input"));
    }
    let mut budget = limits::Budget::new(*limits);
    let p = read(input, format, &mut budget)?;
    let mut out = crate::formats::office::text::Out::new(cap);
    text::lines(&p, &mut out);
    Ok(out.finish())
}

/// As [`convert_first`], reading the document from `source`. An ODP or
/// Keynote package is read part by part, as the conversion asks for them:
/// its directory, its content and styles, and the pictures of the slides
/// converted, so that a source that fetches byte ranges fetches only those.
/// A PPT or FODP is read whole.
pub fn convert_first_from<S: Source>(
    mut source: S,
    format: Format,
    limits: &Limits,
    n: usize,
) -> Result<Converted, Error> {
    let size = source
        .seek(std::io::SeekFrom::End(0))
        .map_err(|e| Error::Malformed(format!("the source: {e}")))?;
    if size > limits.max_input {
        return Err(Error::TooLarge("input"));
    }
    let mut budget = limits::Budget::new(*limits).only(0..n);
    let p = match format {
        Format::Odp => odp::read_odp(package::Zip::from_source(Box::new(source))?, &mut budget)?,
        Format::Odg => odp::read_odg(package::Zip::from_source(Box::new(source))?, &mut budget)?,
        Format::Vsdx => vsdx::read_source(Box::new(source), &mut budget)?,
        Format::Keynote => keynote::read(package::Zip::from_source(Box::new(source)), &mut budget)?,
        Format::Ppt | Format::Fodp | Format::Fodg => {
            let mut bytes = vec![];
            source
                .seek(std::io::SeekFrom::Start(0))
                .and_then(|_| source.read_to_end(&mut bytes))
                .map_err(|e| Error::Malformed(format!("the source: {e}")))?;
            return convert_first(&bytes, format, limits, n);
        }
    };
    finish(p, &budget)
}

/// Converts an Apple Keynote document saved as a package directory, given
/// as its files: paths relative to the package and contents.
pub fn convert_keynote_package(
    files: &[(&str, &[u8])],
    limits: &Limits,
) -> Result<Converted, Error> {
    let total: u64 = files.iter().map(|f| f.1.len() as u64).sum();
    if total > limits.max_input {
        return Err(Error::TooLarge("input"));
    }
    let mut budget = limits::Budget::new(*limits);
    let p = keynote::read_package(files, &mut budget)?;
    finish(p, &budget)
}

fn finish(mut p: model::Presentation, budget: &limits::Budget) -> Result<Converted, Error> {
    let left = budget.limits.max_memory.saturating_sub(budget.used());
    let pptx = pptx::write(&mut p, left)?;
    Ok(Converted {
        pptx,
        slides: p.slides.len(),
        total_slides: p.total_slides.max(p.slides.len()),
        warnings: p.warnings,
    })
}
