//! The text of an XML part of an Office or OpenDocument file.
//!
//! Where the text is depends on the part: Word and PowerPoint keep it in `t`
//! elements, a sheet in `t` (inline strings) and `f` (formulas), the shared
//! strings in `t`, OpenDocument anywhere in its content. A field code
//! (`instrText`) and deleted text (`delText`) are not read: a reader does not
//! see them. Paragraphs, rows and breaks end the line, cells are apart by
//! tabs. Entities are the XML ones and character references; a DTD, and so a
//! custom entity, is never read.

use quick_xml::events::Event;
use quick_xml::Reader;

use super::{Out, XmlPart};

pub(super) fn read(src: &str, part: XmlPart, out: &mut Out) {
    let mut reader = Reader::from_str(src);
    {
        let c = reader.config_mut();
        c.check_end_names = false;
        c.allow_unmatched_ends = true;
        c.allow_dangling_amp = true;
    }
    // How many open elements hold text, how many hold what is not read, and
    // for each open element what it added to those.
    let mut text = usize::from(part == XmlPart::Odf);
    let mut skip = 0usize;
    // OpenDocument table cells open, whose paragraphs do not end the line.
    let mut cells = 0usize;
    let mut open: Vec<(bool, bool)> = Vec::new();
    while !out.full() {
        let event = match reader.read_event() {
            Ok(Event::Eof) | Err(_) => break,
            Ok(e) => e,
        };
        match event {
            Event::Start(e) => {
                let name = e.local_name();
                let name = name.as_ref().as_bytes();
                let holds = holds_text(part, name);
                let hides = matches!(name, b"instrText" | b"delText");
                text += usize::from(holds);
                skip += usize::from(hides);
                open.push((holds, hides));
                cells += usize::from(part == XmlPart::Odf && name == b"table-cell");
                starts(part, name, out);
            }
            Event::Empty(e) => starts(part, e.local_name().as_ref().as_bytes(), out),
            Event::End(e) => {
                let (holds, hides) = open.pop().unwrap_or((false, false));
                text -= usize::from(holds);
                skip -= usize::from(hides);
                let name = e.local_name();
                let name = name.as_ref().as_bytes();
                if part == XmlPart::Odf && name == b"table-cell" {
                    cells = cells.saturating_sub(1);
                }
                ends(part, name, cells > 0, out);
            }
            Event::Text(t) if text > 0 && skip == 0 => {
                out.text(&t.xml10_content());
            }
            Event::CData(t) if text > 0 && skip == 0 => {
                out.text(&t);
            }
            Event::GeneralRef(r) if text > 0 && skip == 0 => {
                if let Ok(Some(c)) = r.resolve_char_ref() {
                    out.text(c.encode_utf8(&mut [0; 4]));
                } else if let Some(s) = quick_xml::escape::resolve_predefined_entity(&r) {
                    out.text(s);
                }
            }
            _ => {}
        }
    }
}

fn holds_text(part: XmlPart, name: &[u8]) -> bool {
    match part {
        XmlPart::Word | XmlPart::Slide | XmlPart::SharedStrings => name == b"t",
        XmlPart::Sheet => matches!(name, b"t" | b"f"),
        XmlPart::Odf => false,
    }
}

/// An element that is itself a break or a gap.
fn starts(part: XmlPart, name: &[u8], out: &mut Out) {
    match (part, name) {
        (XmlPart::Word, b"tab") | (XmlPart::Odf, b"tab" | b"s") => out.space(),
        (XmlPart::Word, b"br" | b"cr")
        | (XmlPart::Slide, b"br")
        | (XmlPart::Odf, b"line-break") => out.newline(),
        _ => {}
    }
}

/// An element whose end ends a line or a cell. `in_cell`: inside an
/// OpenDocument table cell, where a paragraph is a gap.
fn ends(part: XmlPart, name: &[u8], in_cell: bool, out: &mut Out) {
    match (part, name) {
        (XmlPart::Odf, b"p" | b"h") if in_cell => out.space(),
        (XmlPart::Word | XmlPart::Slide, b"p")
        | (XmlPart::SharedStrings, b"si")
        | (XmlPart::Sheet, b"row")
        | (XmlPart::Odf, b"p" | b"h" | b"table-row") => out.newline(),
        (XmlPart::Sheet, b"c") | (XmlPart::Odf, b"table-cell") => out.tab(),
        _ => {}
    }
}
