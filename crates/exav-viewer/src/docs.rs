//! exav-render's `docs`: DOC, ODT, FODT, RTF and the other word-processing
//! formats converted to DOCX, which the document engine shows.

use exav_render::docs::{convert, Error, Format, Limits};
use wasm_bindgen::prelude::*;

/// A converted document.
#[wasm_bindgen]
pub struct ConvertedDocs {
    docx: Vec<u8>,
    paragraphs: usize,
    warnings: Vec<String>,
}

#[wasm_bindgen]
impl ConvertedDocs {
    /// The DOCX package. Moves it out: a second call returns nothing.
    #[wasm_bindgen(js_name = takeDocx)]
    pub fn take_docx(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.docx)
    }

    /// Paragraphs in the body.
    #[wasm_bindgen(getter)]
    pub fn paragraphs(&self) -> u32 {
        self.paragraphs.min(u32::MAX as usize) as u32
    }

    /// What was left out or could not be read, one line each.
    #[wasm_bindgen(getter)]
    pub fn warnings(&self) -> String {
        self.warnings.join("\n")
    }
}

/// Converts `bytes`, a document of `format` ("doc", "odt", "fodt", "rtf",
/// "wml2003" or "pages"), within `max_paragraphs` paragraphs and `max_memory`
/// bytes. Fails with the error's kind as message: "not-format", "encrypted",
/// "unsupported", "too-large" or "malformed".
#[wasm_bindgen(js_name = convertDocs)]
pub fn convert_docs(
    bytes: &[u8],
    format: &str,
    max_paragraphs: f64,
    max_memory: f64,
) -> Result<ConvertedDocs, JsError> {
    let format = Format::from_extension(format).ok_or_else(|| JsError::new("unsupported"))?;
    // Saturating: Infinity is no limit but the module's memory, NaN and
    // anything not positive refuse every document.
    let limits = Limits::default()
        .with_max_paragraphs(max_paragraphs as u64)
        .with_max_memory(max_memory as u64);
    let c = convert(bytes, format, &limits).map_err(|e: Error| JsError::new(e.kind()))?;
    Ok(ConvertedDocs {
        docx: c.docx,
        paragraphs: c.paragraphs,
        warnings: c.warnings,
    })
}
