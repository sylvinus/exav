#![no_main]
//! The text formats exav-render's `sheets` reads, on hostile bytes: Excel's
//! XML Spreadsheet 2003 (XML tree, styles and their parents, R1C1 formulas,
//! declared encodings), HTML tables (the tokenizer, CSS, spans, conditional
//! markup, character sets) and SYLK (records, escapes, shared formulas),
//! then the XLSX writer. The first byte picks the reader. Every panic is a
//! finding, and so is an output that is not an XLSX.
use exav_render::sheets::{Format, convert};
use libfuzzer_sys::fuzz_target;

#[path = "sheets_check.rs"]
mod sheets_check;

fuzz_target!(|data: &[u8]| {
    let Some((&pick, doc)) = data.split_first() else {
        return;
    };
    let format = match pick % 3 {
        0 => Format::SpreadsheetMl,
        1 => Format::Html,
        _ => Format::Sylk,
    };
    let limits = sheets_check::limits();
    if let Ok(c) = convert(doc, format, &limits) {
        sheets_check::xlsx(&c.xlsx, &limits);
    }
});
