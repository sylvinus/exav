//! What the slides targets check of a conversion that succeeds.
use exav_render::slides::{Format, Limits, convert, convert_first};

#[path = "zip_parts.rs"]
mod zip_parts;

/// Converts `doc` whole, then, when it has more than one slide, its first
/// slide alone; checks both.
pub fn run(doc: &[u8], format: Format) {
    let limits = limits();
    let Ok(c) = convert(doc, format, &limits) else {
        return;
    };
    pptx(&c.pptx, c.slides, &limits);
    if c.slides > 1 {
        let f = convert_first(doc, format, &limits, 1)
            .expect("the first slide of a document that converts whole");
        assert_eq!((f.slides, f.total_slides), (1, c.total_slides));
        pptx(&f.pptx, 1, &limits);
    }
}

/// Smaller than the converter's defaults, to keep runs short; the bounds
/// are what is tested, not their size.
pub fn limits() -> Limits {
    Limits::default()
        .with_max_shapes(20_000)
        .with_max_memory(64 << 20)
}

/// A PPTX package within the memory limit, whose parts the viewer reads
/// first are there, and whose XML parts are XML without a C0 control
/// character.
pub fn pptx(bytes: &[u8], slides: usize, limits: &Limits) {
    assert!(bytes.len() as u64 <= limits.max_memory);
    let parts = zip_parts::parts(bytes);
    for part in [
        "[Content_Types].xml",
        "ppt/presentation.xml",
        "ppt/slideMasters/slideMaster1.xml",
        "ppt/slideLayouts/slideLayout1.xml",
    ] {
        assert!(parts.iter().any(|(name, _)| name == part), "{part}");
    }
    if slides > 0 {
        assert!(
            parts
                .iter()
                .any(|(name, _)| name == "ppt/slides/slide1.xml")
        );
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
