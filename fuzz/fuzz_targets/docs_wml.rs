#![no_main]
//! Word 2003 XML on hostile bytes: exav-render's `docs` WordprocessingML
//! 2003 reader (UTF-8 and UTF-16 input, styles, lists, sections, tables, fields,
//! `binData` pictures, comments) and the DOCX writer. Every panic is a
//! finding, and so is an output that is not a DOCX.
use exav_render::docs::Format;
use libfuzzer_sys::fuzz_target;

#[path = "docs_check.rs"]
mod docs_check;

fuzz_target!(|data: &[u8]| {
    docs_check::run(data, Format::Wml2003);
});
