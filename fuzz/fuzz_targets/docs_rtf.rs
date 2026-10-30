#![no_main]
//! Rich Text Format on hostile bytes: exav-render's `docs` RTF reader
//! (the tokenizer, the group stack and its destinations, font and color tables,
//! code pages, `\u` and its skip count, list tables, tables, fields,
//! pictures in hex and `\bin`, notes, headers) and the DOCX writer. Every
//! panic is a finding, and so is an output that is not a DOCX.
use exav_render::docs::Format;
use libfuzzer_sys::fuzz_target;

#[path = "docs_check.rs"]
mod docs_check;

fuzz_target!(|data: &[u8]| {
    docs_check::run(data, Format::Rtf);
});
