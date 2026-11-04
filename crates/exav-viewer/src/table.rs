//! exav-render's `sheets::convert_csv`: a CSV or TSV converted to XLSX, which
//! the spreadsheet engine shows.

use wasm_bindgen::prelude::*;

/// A CSV or TSV as an XLSX of one sheet, "Sheet1", of text cells
/// (exav-render's `convert_csv`): the encoding and the separator are read off
/// the bytes. Fails with the error's kind as message: "not-format" (not
/// text), "too-large" (more than `max_cells` fields, empty ones included, a
/// sheet's size, or `max_memory` bytes of input, text, cells and output),
/// "encrypted", "unsupported" or "malformed".
#[wasm_bindgen(js_name = convertTable)]
pub fn convert_table(bytes: &[u8], max_cells: f64, max_memory: f64) -> Result<Vec<u8>, JsError> {
    // Saturating: Infinity is no limit but the module's memory, NaN and
    // anything not positive refuse every table.
    let memory = max_memory as u64;
    let mut limits = exav_render::sheets::Limits::default()
        .with_max_cells(max_cells as u64)
        .with_max_memory(memory);
    limits.max_input = memory;
    exav_render::sheets::convert_csv(bytes, &limits)
        .map(|c| c.xlsx)
        .map_err(|e| JsError::new(e.kind()))
}
