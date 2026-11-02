#![no_main]
//! Apple Pages documents on hostile bytes: exav-render's `docs` IWA reader
//! (ZIP, Snappy, protobuf, the text storages, styles, page geometry) and
//! the DOCX writer. The input is an IWA stream, stored as
//! `Index/Document.iwa` in a ZIP here so that the fuzzer mutates the
//! archives and not the ZIP around them, or a whole document when it is a
//! ZIP. Every panic is a finding, and so is an output that is not a DOCX.
use std::io::Write;

use exav_render::docs::Format;
use libfuzzer_sys::fuzz_target;

#[path = "docs_check.rs"]
mod docs_check;

fuzz_target!(|data: &[u8]| {
    let doc = if data.starts_with(b"PK") {
        data.to_vec()
    } else {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        if z.start_file("Index/Document.iwa", opts).is_err() || z.write_all(data).is_err() {
            return;
        }
        match z.finish() {
            Ok(c) => c.into_inner(),
            Err(_) => return,
        }
    };
    docs_check::run(&doc, Format::Pages);
});
