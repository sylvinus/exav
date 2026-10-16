use hayro::{render, PixmapSettings, RenderCache, RenderSettings};
use hayro_interpret::InterpreterSettings;
use hayro_syntax::Pdf;
use wasm_bindgen::prelude::*;

/// Page `index` (0-based) of `data` at scale 1 on white: width and height as two u32 (LE), then RGBA.
#[wasm_bindgen(js_name = renderPage)]
pub fn render_page(data: &[u8], index: u32) -> Result<Vec<u8>, JsError> {
    let pdf = Pdf::new(data.to_vec()).map_err(|e| JsError::new(&format!("{e:?}")))?;
    let pages = pdf.pages();
    let page = pages.get(index as usize).ok_or_else(|| JsError::new("no such page"))?;
    let cache = RenderCache::new();
    let ps = PixmapSettings { bg_color: hayro::vello_cpu::color::palette::css::WHITE, ..PixmapSettings::default() };
    let pix = render(page, &cache, &InterpreterSettings::default(), &RenderSettings::default(), &ps);
    let (w, h) = (pix.width() as u32, pix.height() as u32);
    let mut out = Vec::with_capacity(8 + (w * h * 4) as usize);
    out.extend_from_slice(&w.to_le_bytes());
    out.extend_from_slice(&h.to_le_bytes());
    out.extend_from_slice(pix.data_as_u8_slice());
    Ok(out)
}

#[wasm_bindgen(js_name = pageCount)]
pub fn page_count(data: &[u8]) -> Result<u32, JsError> {
    let pdf = Pdf::new(data.to_vec()).map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(pdf.pages().len() as u32)
}
