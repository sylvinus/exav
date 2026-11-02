#![no_main]
//! OpenDocument text on hostile bytes: exav-render's `docs` ODT and
//! FODT readers (the XML tree's bounds, automatic and named styles and their
//! parents, master pages, lists, tables, frames, pictures, notes, fields)
//! and the DOCX writer. A ZIP is read as ODT, anything else as FODT. Every
//! panic is a finding, and so is an output that is not a DOCX.
use exav_render::docs::Format;
use libfuzzer_sys::fuzz_target;

#[path = "docs_check.rs"]
mod docs_check;

fuzz_target!(|data: &[u8]| {
    let format = if data.starts_with(b"PK") {
        Format::Odt
    } else {
        Format::Fodt
    };
    docs_check::run(data, format);
});
