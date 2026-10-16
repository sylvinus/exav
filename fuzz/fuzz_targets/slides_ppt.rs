#![no_main]
//! PowerPoint presentations on hostile bytes: exav-render's `slides` PPT
//! reader (the lenient compound file reader, the record tree, the persist
//! directory, text and style atoms, the OfficeArt drawing layer, the blip
//! store, the PowerPoint 95 records, the OLE charts, the headers of
//! versions 2 to 4 and BinHex text) and the PPTX writer. A compound file is
//! read as it is, as is a file of PowerPoint 2 to 4 or BinHex text; any
//! other input is stored as its `PowerPoint Document` stream in a compound
//! file built here, so that the fuzzer mutates the records and not the
//! compound file around them (a PowerPoint 95 stream is one of them). Every
//! panic is a finding, and so is an output that is not a PPTX.
use exav_render::formats::office::test_util::build_cfb as build;
use exav_render::slides::Format;
use libfuzzer_sys::fuzz_target;

#[path = "slides_check.rs"]
mod slides_check;

const CFB: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

fuzz_target!(|data: &[u8]| {
    let doc = if data.starts_with(CFB)
        || data.starts_with(&[0xED, 0xDE, 0xAD, 0x0B])
        || data.starts_with(&[0x0B, 0xAD, 0xDE, 0xED])
        || data.starts_with(b"(This file must be converted")
    {
        data.to_vec()
    } else {
        build(&[("PowerPoint Document", data)])
    };
    slides_check::run(&doc, Format::Ppt);
});
