//! Spreadsheets to XLSX: XLS (BIFF2 to BIFF8), ODS, FODS, OTS, Apple
//! Numbers, and the text formats Excel opens from a .xls file (XML
//! Spreadsheet, HTML tables, SYLK), converted for an XLSX renderer to draw, or
//! read as text ([`text()`]). CSV and TSV ([`convert_csv`], feature
//! `office-csv`) are read into the same model and written by the same XLSX
//! writer; with that feature alone, none of the workbook readers is compiled.
// Without `office-sheets` the readers are compiled for the presentations'
// charts only (`office-slides`), and most of them is unused.
#![cfg_attr(not(feature = "office-sheets"), allow(dead_code))]

mod charts;
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
pub(crate) mod css;
#[cfg(feature = "office-csv")]
mod csv;
mod error;
mod fonts;
mod geom;
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
pub(crate) mod html;
mod limits;
mod model;
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
mod numbers;
mod numtext;
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
mod ods;
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
mod r1c1;
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
mod sylk;
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
mod text;
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
pub(crate) mod textenc;
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
mod xls;
mod xlsx;
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
mod xmlss;

pub use error::Error;
pub use limits::Limits;

/// The formats this module converts.
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    /// Excel 2.x to 2003 workbooks and templates (.xls, .xlt, .xlw).
    Xls,
    /// OpenDocument spreadsheets and templates (.ods, .ots).
    Ods,
    /// Flat OpenDocument spreadsheets (.fods).
    Fods,
    /// Apple Numbers documents saved as one file (.numbers), Numbers '08
    /// and later.
    Numbers,
    /// Excel 2002 and 2003 XML Spreadsheet (SpreadsheetML, .xml).
    SpreadsheetMl,
    /// HTML tables, Excel's "Web Page" among them (.htm, .html).
    Html,
    /// Symbolic Link (.slk).
    Sylk,
}

#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
impl Format {
    /// The format of a file extension (without its dot, any case).
    pub fn from_extension(ext: &str) -> Option<Format> {
        Some(match ext.to_ascii_lowercase().as_str() {
            "xls" | "xlt" | "xlw" => Format::Xls,
            "ods" | "ots" => Format::Ods,
            "fods" => Format::Fods,
            "numbers" => Format::Numbers,
            "xml" => Format::SpreadsheetMl,
            "html" | "htm" => Format::Html,
            "slk" | "sylk" => Format::Sylk,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Format::Xls => "xls",
            Format::Ods => "ods",
            Format::Fods => "fods",
            Format::Numbers => "numbers",
            Format::SpreadsheetMl => "xml",
            Format::Html => "html",
            Format::Sylk => "slk",
        }
    }
}

/// A converted document.
#[derive(Debug)]
pub struct Converted {
    /// The XLSX package.
    pub xlsx: Vec<u8>,
    /// What was left out or could not be read, for diagnostics.
    pub warnings: Vec<String>,
}

/// Converts `input`, a document of `format`, to XLSX.
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
pub fn convert(input: &[u8], format: Format, limits: &Limits) -> Result<Converted, Error> {
    let (wb, used) = read(input, format, limits)?;
    finish(wb, limits, used)
}

/// The text of `input`, a workbook of `format`, cut at `cap` bytes: each
/// sheet's name and cells, its comments and its drawings' text, taken from
/// what the reader parsed, within the same [`Limits`] and with the same
/// refusals as [`convert`]. No XLSX is written.
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
pub fn text(
    input: &[u8],
    format: Format,
    limits: &Limits,
    cap: usize,
) -> Result<crate::formats::office::text::Text, Error> {
    Ok(text::of(&read(input, format, limits)?.0, cap))
}

/// Reads `input` into the model, within `limits`, and says how much of the
/// memory limit the model took.
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
fn read(input: &[u8], format: Format, limits: &Limits) -> Result<(model::Workbook, u64), Error> {
    if input.len() as u64 > limits.max_input {
        return Err(Error::TooLarge("input"));
    }
    let mut budget = limits::Budget::new(*limits);
    let wb = match format {
        Format::Xls => xls::read(input, &mut budget),
        Format::Ods => ods::read_ods(input, &mut budget),
        Format::Fods => ods::read_fods(input, &mut budget),
        Format::Numbers => numbers::read(input, &mut budget),
        Format::SpreadsheetMl => xmlss::read(input, &mut budget),
        Format::Html => html::read(input, &mut budget),
        Format::Sylk => sylk::read(input, &mut budget),
    }?;
    Ok((wb, budget.used()))
}

/// Converts an Apple Numbers document saved as a package directory, given
/// as its files: paths relative to the package and contents.
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
pub fn convert_numbers_package(
    files: &[(&str, &[u8])],
    limits: &Limits,
) -> Result<Converted, Error> {
    let total: u64 = files.iter().map(|f| f.1.len() as u64).sum();
    if total > limits.max_input {
        return Err(Error::TooLarge("input"));
    }
    let mut budget = limits::Budget::new(*limits);
    let wb = numbers::read_package(files, &mut budget)?;
    finish(wb, limits, budget.used())
}

/// An ODF chart object's content (an office:chart holding its own data
/// table, as presentations and drawings embed them) as a DrawingML chart
/// part, its values written as literals. `None` when it is not a chart.
#[cfg(any(feature = "office-sheets", feature = "office-slides"))]
pub fn odf_chart_part(content: &[u8]) -> Option<String> {
    let anchor = model::Anchor {
        from: (0, 0, 0, 0),
        to: (0, 0, 0, 0),
    };
    let mut chart = ods::chart::read(content, anchor, &[], &mut |_| true).ok()??;
    for s in &mut chart.series {
        s.name_ref = None;
        s.cat_ref = None;
        s.val_ref = None;
        s.size_ref = None;
    }
    Some(xlsx::chart::chart_xml(&chart))
}

/// Converts `input`, a CSV or TSV, to an XLSX of one sheet, "Sheet1", whose
/// cells are all text. The encoding is read as exav-unpack reads a text file
/// (a UTF-16 byte-order mark, else UTF-8 when valid, else windows-1252) and
/// the separator is the comma, semicolon or tab that cuts the first rows into
/// the same number of fields. `limits.max_cells` counts every field, empty
/// ones included.
#[cfg(feature = "office-csv")]
pub fn convert_csv(input: &[u8], limits: &Limits) -> Result<Converted, Error> {
    if input.len() as u64 > limits.max_input {
        return Err(Error::TooLarge("input"));
    }
    let mut budget = limits::Budget::new(*limits);
    let wb = csv::read(input, &mut budget)?;
    finish(wb, limits, budget.used())
}

/// Writes the workbook, in what the model left of the memory limit: the
/// limit is for the model and the output together.
fn finish(mut wb: model::Workbook, limits: &Limits, used: u64) -> Result<Converted, Error> {
    let mut left = limits.max_memory.saturating_sub(used);
    // The caches charts keep of the cells they draw are copies, one per series.
    let fits = charts::fill(&mut wb, &mut |bytes| {
        if bytes > left {
            return false;
        }
        left -= bytes;
        true
    });
    if !fits {
        return Err(Error::TooLarge("memory"));
    }
    // An XLSX has a sheet at least: an empty workbook is one empty sheet.
    if wb.sheets.is_empty() {
        wb.sheets.push(model::Sheet::new("Sheet1".into()));
    }
    let xlsx = xlsx::write(&wb, left)?;
    Ok(Converted {
        xlsx,
        warnings: wb.warnings,
    })
}
