//! What the docs targets check of a conversion that succeeds.
use exav_render::docs::{Format, Limits, convert};

#[path = "zip_parts.rs"]
mod zip_parts;

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
    let parts = zip_parts::parts(bytes);
    for part in [
        "[Content_Types].xml",
        "_rels/.rels",
        "word/document.xml",
        "word/styles.xml",
    ] {
        assert!(parts.iter().any(|(name, _)| name == part), "{part}");
    }
    for (name, data) in &parts {
        if !(name.ends_with(".xml") || name.ends_with(".rels")) {
            continue;
        }
        let s = std::str::from_utf8(data).unwrap_or_else(|_| panic!("{name}: UTF-8"));
        assert!(s.starts_with("<?xml"), "{name}");
        // No C0 control character but white space: XML 1.0 refuses them.
        assert!(
            !s.chars()
                .any(|c| (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r')),
            "{name}"
        );
    }
}
