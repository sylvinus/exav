#![no_main]
//! OpenDocument drawings on hostile bytes: exav-render's `slides` ODG reader
//! for a ZIP, its FODG reader for anything else (what the ODP reader does,
//! and the page sizes of the master pages, the layers that are not
//! displayed, the pages' names), and the PPTX writer. Every panic is a
//! finding, and so is an output that is not a PPTX.
use exav_render::slides::Format;
use libfuzzer_sys::fuzz_target;

#[path = "slides_check.rs"]
mod slides_check;

fuzz_target!(|data: &[u8]| {
    let format = if data.starts_with(b"PK") {
        Format::Odg
    } else {
        Format::Fodg
    };
    slides_check::run(data, format);
});
