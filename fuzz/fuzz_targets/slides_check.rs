//! What the slides targets check of a conversion that succeeds.
use std::io::Read;

use exav_render::slides::{convert, convert_first, Format, Limits};

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
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("a ZIP");
    for part in [
        "[Content_Types].xml",
        "ppt/presentation.xml",
        "ppt/slideMasters/slideMaster1.xml",
        "ppt/slideLayouts/slideLayout1.xml",
    ] {
        assert!(z.index_for_name(part).is_some(), "{part}");
    }
    if slides > 0 {
        assert!(z.index_for_name("ppt/slides/slide1.xml").is_some());
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
