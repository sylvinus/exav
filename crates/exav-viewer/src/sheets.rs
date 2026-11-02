//! exav-render's `sheets`: XLS, ODS, FODS and Numbers converted to XLSX, which
//! the spreadsheet engine shows.

use exav_render::sheets::{Error, Format, Limits, convert};
use wasm_bindgen::prelude::*;

/// A converted spreadsheet.
#[wasm_bindgen]
pub struct Converted {
    xlsx: Vec<u8>,
    warnings: Vec<String>,
}

#[wasm_bindgen]
impl Converted {
    /// The XLSX package. Moves it out: a second call returns nothing.
    #[wasm_bindgen(js_name = takeXlsx)]
    pub fn take_xlsx(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.xlsx)
    }

    /// What was left out or could not be read, one line each.
    #[wasm_bindgen(getter)]
    pub fn warnings(&self) -> String {
        self.warnings.join("\n")
    }
}

/// Converts `bytes`, a document of `format` ("xls", "ods", "fods",
/// "numbers", "xml" for Excel's XML Spreadsheet, "html" or "slk"), within `max_cells` cells and `max_memory` bytes. Fails with
/// the error's kind as message: "not-format", "encrypted", "unsupported",
/// "too-large" or "malformed".
#[wasm_bindgen(js_name = convertSheets)]
pub fn convert_sheets(
    bytes: &[u8],
    format: &str,
    max_cells: f64,
    max_memory: f64,
) -> Result<Converted, JsError> {
    let format = Format::from_extension(format).ok_or_else(|| JsError::new("unsupported"))?;
    // Saturating: Infinity is no limit but the module's memory, NaN and
    // anything not positive refuse every document.
    let limits = Limits::default()
        .with_max_cells(max_cells as u64)
        .with_max_memory(max_memory as u64);
    let c = convert(bytes, format, &limits).map_err(|e: Error| JsError::new(e.kind()))?;
    Ok(Converted {
        xlsx: c.xlsx,
        warnings: c.warnings,
    })
}
