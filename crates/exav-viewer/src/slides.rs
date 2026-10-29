//! exav-render's `slides`: PPT, ODP, FODP and Keynote converted to PPTX, which
//! the presentation engine shows.

use exav_render::slides::{Error, Format, Limits, convert_first};
use wasm_bindgen::prelude::*;

/// A converted presentation.
#[wasm_bindgen]
pub struct ConvertedSlides {
    pptx: Vec<u8>,
    slides: usize,
    total_slides: usize,
    warnings: Vec<String>,
}

#[wasm_bindgen]
impl ConvertedSlides {
    /// The PPTX package. Moves it out: a second call returns nothing.
    #[wasm_bindgen(js_name = takePptx)]
    pub fn take_pptx(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pptx)
    }

    /// Slides in the PPTX.
    #[wasm_bindgen(getter)]
    pub fn slides(&self) -> u32 {
        self.slides.min(u32::MAX as usize) as u32
    }

    /// Slides in the document: more than `slides` when `first` left some
    /// out.
    #[wasm_bindgen(getter, js_name = totalSlides)]
    pub fn total_slides(&self) -> u32 {
        self.total_slides.min(u32::MAX as usize) as u32
    }

    /// What was left out or could not be read, one line each.
    #[wasm_bindgen(getter)]
    pub fn warnings(&self) -> String {
        self.warnings.join("\n")
    }
}

/// Converts `bytes`, a document of `format` ("ppt", "odp", "fodp" or
/// "key"), within `max_shapes` shapes and `max_memory` bytes: its masters
/// and its `first` slides (Infinity for all). Fails with the error's kind as
/// message: "not-format", "encrypted", "unsupported", "too-large" or
/// "malformed".
#[wasm_bindgen(js_name = convertSlides)]
pub fn convert_slides(
    bytes: &[u8],
    format: &str,
    max_shapes: f64,
    max_memory: f64,
    first: f64,
) -> Result<ConvertedSlides, JsError> {
    let format = Format::from_extension(format).ok_or_else(|| JsError::new("unsupported"))?;
    // Saturating: Infinity is no limit but the module's memory, NaN and
    // anything not positive refuse every document.
    let limits = Limits::default()
        .with_max_shapes(max_shapes as u64)
        .with_max_memory(max_memory as u64);
    // Saturating too: NaN converts no slide.
    let c = convert_first(bytes, format, &limits, first as usize)
        .map_err(|e: Error| JsError::new(e.kind()))?;
    Ok(ConvertedSlides {
        pptx: c.pptx,
        slides: c.slides,
        total_slides: c.total_slides,
        warnings: c.warnings,
    })
}
