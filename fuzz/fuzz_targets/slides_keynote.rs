#![no_main]
//! Apple Keynote documents on hostile bytes: exav-render's `slides` IWA reader
//! (ZIP, Snappy, protobuf, slides, masters, placeholders, styles, shapes,
//! paths, text storages), its XML readers for Keynote 1 to 5 (styles and
//! their parents, layers, placeholders, headlines, shapes, text, pictures)
//! and the PPTX writer. The input is an IWA stream, stored as
//! `Index/Document.iwa` in a ZIP here so that the fuzzer mutates the
//! archives and not the ZIP around them; a whole document when it is a ZIP;
//! an `.apxl` file on its own when it starts with `<` or is gzipped. Every
//! panic is a finding, and so is an output that is not a PPTX.
use std::io::Write;

use exav_render::slides::Format;
use libfuzzer_sys::fuzz_target;

#[path = "slides_check.rs"]
mod slides_check;

fuzz_target!(|data: &[u8]| {
    let doc = if data.starts_with(b"PK")
        || data.first() == Some(&b'<')
        || data.starts_with(&[0x1F, 0x8B])
    {
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
    slides_check::run(&doc, Format::Keynote);
});
