//! Word-processing documents to DOCX: Word 6 to 2003 (DOC), OpenDocument
//! text (ODT, OTT, FODT), RTF, Word 2003 XML and Apple Pages, converted for a
//! DOCX renderer to draw ([`convert`]), or read for their text ([`text`]).

mod doc;
mod docx;
mod error;
mod fields;
mod grid;
mod limits;
mod model;
mod odt;
mod pages;
mod rtf;
mod text;
mod wml;

pub use error::Error;
pub use limits::Limits;

/// The formats this module converts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    /// Word 6 to 2003 documents and templates (.doc, .dot).
    Doc,
    /// OpenDocument text and templates (.odt, .ott).
    Odt,
    /// Flat OpenDocument text (.fodt).
    Fodt,
    /// Rich Text Format (.rtf).
    Rtf,
    /// Word 2003 XML (WordprocessingML 2003, .xml).
    Wml2003,
    /// Apple Pages documents (.pages).
    Pages,
}

impl Format {
    /// The format of a file extension (without its dot, any case).
    pub fn from_extension(ext: &str) -> Option<Format> {
        Some(match ext.to_ascii_lowercase().as_str() {
            "doc" | "dot" => Format::Doc,
            "odt" | "ott" => Format::Odt,
            "fodt" => Format::Fodt,
            "rtf" => Format::Rtf,
            "xml" | "wml" | "wml2003" => Format::Wml2003,
            "pages" => Format::Pages,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Format::Doc => "doc",
            Format::Odt => "odt",
            Format::Fodt => "fodt",
            Format::Rtf => "rtf",
            Format::Wml2003 => "wml2003",
            Format::Pages => "pages",
        }
    }
}

/// A converted document.
#[derive(Debug)]
pub struct Converted {
    /// The DOCX package.
    pub docx: Vec<u8>,
    /// Paragraphs in the body.
    pub paragraphs: usize,
    /// What was left out or could not be read, for diagnostics.
    pub warnings: Vec<String>,
}

/// Converts `input`, a document of `format`, to DOCX.
pub fn convert(input: &[u8], format: Format, limits: &Limits) -> Result<Converted, Error> {
    let (doc, budget) = read(input, format, limits)?;
    finish(doc, &budget)
}

/// The text of `input`, a document of `format`, cut at `cap` bytes: what a
/// reader sees, taken from the model the converter reads, with the same
/// limits and refusals as [`convert`]. See [`crate::formats::office::text`].
pub fn text(
    input: &[u8],
    format: Format,
    limits: &Limits,
    cap: usize,
) -> Result<crate::formats::office::text::Text, Error> {
    let (doc, _) = read(input, format, limits)?;
    let mut out = crate::formats::office::text::Out::new(cap);
    text::lines(&doc, &mut out);
    Ok(out.finish())
}

/// Reads `input` into the model, within `limits`.
fn read(
    input: &[u8],
    format: Format,
    limits: &Limits,
) -> Result<(model::Document, limits::Budget), Error> {
    if input.len() as u64 > limits.max_input {
        return Err(Error::TooLarge("input"));
    }
    let mut budget = limits::Budget::new(*limits);
    let doc = match format {
        Format::Doc => doc::read(input, &mut budget)?,
        Format::Odt => odt::read_odt(
            crate::formats::office::common::package::Zip::open(input)?,
            &mut budget,
        )?,
        Format::Fodt => odt::read_fodt(input, &mut budget)?,
        Format::Rtf => rtf::read(input, &mut budget)?,
        Format::Wml2003 => wml::read(input, &mut budget)?,
        Format::Pages => pages::read(
            crate::formats::office::common::package::Zip::open(input)?,
            &mut budget,
        )?,
    };
    Ok((doc, budget))
}

fn finish(doc: model::Document, budget: &limits::Budget) -> Result<Converted, Error> {
    let left = budget.limits.max_memory.saturating_sub(budget.used());
    let docx = docx::write(&doc, left)?;
    Ok(Converted {
        docx,
        paragraphs: doc.body.len(),
        warnings: doc.warnings,
    })
}
