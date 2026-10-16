#![no_main]
//! Visio drawings on hostile bytes: exav-render's `slides` VSDX reader (the
//! package and its relationships, document, pages and masters, shape sheets
//! with their inheritance from masters and styles, formulas, geometry rows
//! and splines, text, pictures, themes) and the PPTX writer. Every panic is
//! a finding, and so is an output that is not a PPTX.
use exav_render::slides::Format;
use libfuzzer_sys::fuzz_target;

#[path = "slides_check.rs"]
mod slides_check;

fuzz_target!(|data: &[u8]| {
    slides_check::run(data, Format::Vsdx);
});
