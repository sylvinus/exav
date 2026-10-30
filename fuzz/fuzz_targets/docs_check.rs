//! What the docs targets check of a conversion that succeeds.
use std::io::Read;

use exav_render::docs::{Format, Limits, convert};

/// Converts `doc` and checks the DOCX.
pub fn run(doc: &[u8], format: Format) {
    let limits = limits();
    let Ok(c) = convert(doc, format, &limits) else {
        return;
    };
    docx(&c.docx, &limits);
}

/// Smaller than the converter's defaults, to keep runs short; the bounds
/// are what is tested, not their size.
pub fn limits() -> Limits {
    Limits::default()
        .with_max_paragraphs(20_000)
        .with_max_cells(20_000)
        .with_max_memory(64 << 20)
}

/// A DOCX package within the memory limit, whose parts the viewer reads
/// first are there, and whose XML parts are XML without a C0 control
/// character.
pub fn docx(bytes: &[u8], limits: &Limits) {
    assert!(bytes.len() as u64 <= limits.max_memory);
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("a ZIP");
    for part in [
        "[Content_Types].xml",
        "_rels/.rels",
        "word/document.xml",
        "word/styles.xml",
    ] {
        assert!(z.index_for_name(part).is_some(), "{part}");
    }
    for i in 0..z.len() {
        let mut f = z.by_index(i).expect("a part");
        let name = f.name().map(|n| n.to_string()).unwrap_or_default();
        if !(name.ends_with(".xml") || name.ends_with(".rels")) {
            continue;
        }
        let mut s = String::new();
        f.read_to_string(&mut s)
            .unwrap_or_else(|_| panic!("{name}: UTF-8"));
        assert!(s.starts_with("<?xml"), "{name}");
        // No C0 control character but white space: XML 1.0 refuses them.
        assert!(
            !s.chars()
                .any(|c| (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r')),
            "{name}"
        );
    }
}
