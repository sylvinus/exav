#![no_main]
//! Web pages as documents on hostile bytes: exav-render's `docs` HTML reader
//! (Word's "Save as Web Page", its MIME form, and other pages: the tokenizer,
//! style sheets, tables with spans, lists, links, pictures in `data:` addresses
//! and MIME parts) and the DOCX writer. Every panic is a finding, and so is an
//! output that is not a DOCX.
use exav_render::docs::Format;
use libfuzzer_sys::fuzz_target;

#[path = "docs_check.rs"]
mod docs_check;

fuzz_target!(|data: &[u8]| {
    docs_check::run(data, Format::Html);
});
