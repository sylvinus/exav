#![no_main]
//! OpenDocument spreadsheets on hostile bytes: exav-render's `sheets` ODS
//! reader for a ZIP, its FODS reader for anything else (styles, data styles,
//! formulas, conditional formats, validations, frames, charts), and the XLSX
//! writer. Every panic is a finding, and so is an output that is not an
//! XLSX.
use exav_render::sheets::{Format, convert};
use libfuzzer_sys::fuzz_target;

#[path = "sheets_check.rs"]
mod sheets_check;

fuzz_target!(|data: &[u8]| {
    let limits = sheets_check::limits();
    let format = if data.starts_with(b"PK") {
        Format::Ods
    } else {
        Format::Fods
    };
    if let Ok(c) = convert(data, format, &limits) {
        sheets_check::xlsx(&c.xlsx, &limits);
    }
});
