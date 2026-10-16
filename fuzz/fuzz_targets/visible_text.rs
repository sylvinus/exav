#![no_main]
//! The text a reader sees, on hostile bytes: exav-render's `text::visible_text`
//! as the scanner and `exav-grep --text` call it, under every name that picks
//! a reader (Markdown, HTML, each Office and OpenDocument XML part, PDF, DXF,
//! DWG, DOC, XLS, PPT, RTF, Word 2003 XML, SYLK, the flat OpenDocument files,
//! Numbers, Pages, Keynote). The first byte picks the name, so every reader is
//! reached whatever the rest is. A panic is a finding; so is a text past its
//! cap, more links than the bound, sections that are not in order inside the
//! text, or a document read that `wants` did not announce.
use exav_render::text::{visible_text, wants};
use exav_unpack::Limits;
use libfuzzer_sys::fuzz_target;

const NAMES: &[&str] = &[
    "a.md",
    "a.html",
    "word/document.xml",
    "xl/worksheets/sheet1.xml",
    "xl/sharedStrings.xml",
    "ppt/slides/slide1.xml",
    "content.xml",
    "a.pdf",
    "a.dxf",
    "a.dwg",
    "member",
    // The office formats the XML parts do not reach (`text-office`).
    "a.doc",
    "a.xls",
    "a.ppt",
    "a.rtf",
    "a.xml",
    "a.slk",
    "a.fodt",
    "a.fods",
    "a.fodp",
    "a.fodg",
    "a.numbers",
    "a.pages",
    "a.key",
];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, body)) = data.split_first() else {
        return;
    };
    let name = NAMES[usize::from(pick) % NAMES.len()];
    // Small limits keep a decompression bomb cheap to refuse.
    let mut limits = Limits::default();
    limits.max_buffer_bytes = 16 << 20;
    let cap = 1 << 20;
    if let Some(v) = visible_text(name, body, cap, &limits) {
        assert!(v.text.len() <= cap, "{} bytes", v.text.len());
        assert!(v.links.len() <= 4096);
        assert!(wants(name, &body[..body.len().min(1024)]));
        // Sections are in order, inside the text, on character boundaries.
        let mut at = 0;
        for (_, r) in &v.sections {
            assert!(at <= r.start && r.start <= r.end && r.end <= v.text.len());
            assert!(v.text.is_char_boundary(r.start) && v.text.is_char_boundary(r.end));
            at = r.end;
        }
        // A document whose text could not be read has none.
        assert!(v.unreadable.is_none() || v.text.is_empty());
    }
});
