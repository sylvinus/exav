#![no_main]
//! Word 97 to 2003 documents on hostile bytes: exav-render's `docs` DOC
//! reader (the lenient compound file reader, the FIB, the piece table, the
//! character and paragraph FKPs, the sprms, the stylesheet, lists, sections,
//! tables, notes, comments, fields, the OfficeArt layer) and the DOCX
//! writer. A compound file is read as it is; any other input is stored as
//! its `WordDocument` stream in one built here, next to the table streams
//! made of the input's second half, so that the fuzzer mutates the
//! structures and not the compound file around them. Every panic is a
//! finding, and so is an output that is not a DOCX.
use exav_render::docs::Format;
use exav_render::formats::office::test_util::build_cfb as build;
use libfuzzer_sys::fuzz_target;

#[path = "docs_check.rs"]
mod docs_check;

const CFB: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

fuzz_target!(|data: &[u8]| {
    let doc = if data.starts_with(CFB) {
        data.to_vec()
    } else {
        let (word, table) = data.split_at(data.len() / 2);
        build(&[("WordDocument", word), ("0Table", table), ("1Table", table)])
    };
    docs_check::run(&doc, Format::Doc);
});
