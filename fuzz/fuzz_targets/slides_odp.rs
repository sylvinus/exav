#![no_main]
//! OpenDocument presentations on hostile bytes: exav-render's `slides` ODP
//! reader for a ZIP, its FODP reader for anything else (styles and their
//! parents, list styles, masters, enhanced geometry and its formulas, SVG
//! paths, text and fields, tables, pictures, charts through
//! the `sheets` chart writer), and the PPTX writer. Every panic is a finding,
//! and so is an output that is not a PPTX.
use exav_render::slides::Format;
use libfuzzer_sys::fuzz_target;

#[path = "slides_check.rs"]
mod slides_check;

fuzz_target!(|data: &[u8]| {
    let format = if data.starts_with(b"PK") {
        Format::Odp
    } else {
        Format::Fodp
    };
    slides_check::run(data, format);
});
