#![no_main]
//! Apple Numbers documents on hostile bytes: exav-render's `sheets` IWA reader
//! (ZIP, Snappy, protobuf, tiles, cell records, styles, formulas), its
//! Numbers '08 and '09 reader (XML, styles, formulas) and the XLSX writer.
//! The input is the document's one IWA stream, or its `index.xml` when it
//! starts with `<` (`index.xml.gz` when gzipped), stored in a ZIP here, so
//! that the fuzzer mutates the archives and the XML and not the ZIP around
//! them. Every panic is a finding, and so is an output that is not an XLSX.
use std::io::Write;

use exav_render::sheets::{Format, convert};
use libfuzzer_sys::fuzz_target;

#[path = "sheets_check.rs"]
mod sheets_check;

fuzz_target!(|data: &[u8]| {
    let limits = sheets_check::limits();
    // A whole document as it is, else the bytes as one of its members.
    let doc = if data.starts_with(b"PK") {
        data.to_vec()
    } else {
        let name = if data.starts_with(b"<") {
            "index.xml"
        } else if data.starts_with(&[0x1F, 0x8B]) {
            "index.xml.gz"
        } else {
            "Index/Document.iwa"
        };
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        if z.start_file(name, opts).is_err() || z.write_all(data).is_err() {
            return;
        }
        match z.finish() {
            Ok(c) => c.into_inner(),
            Err(_) => return,
        }
    };
    if let Ok(c) = convert(&doc, Format::Numbers, &limits) {
        sheets_check::xlsx(&c.xlsx, &limits);
    }
});
