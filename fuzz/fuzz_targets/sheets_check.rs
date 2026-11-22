//! What the sheets targets check of a conversion that succeeds.
use exav_render::sheets::Limits;

#[path = "zip_parts.rs"]
mod zip_parts;

/// Smaller than the converter's defaults, to keep runs short; the bounds
/// are what is tested, not their size.
pub fn limits() -> Limits {
    Limits::default()
        .with_max_cells(200_000)
        .with_max_memory(64 << 20)
}

/// An XLSX package within the memory limit, whose parts the viewer reads
/// first are there and are XML: the first sheet is a worksheet or a chart
/// sheet.
pub fn xlsx(bytes: &[u8], limits: &Limits) {
    assert!(bytes.len() as u64 <= limits.max_memory);
    let parts = zip_parts::parts(bytes);
    let member = |part: &str| parts.iter().find(|(name, _)| name == part);
    let first = if member("xl/worksheets/sheet1.xml").is_some() {
        "xl/worksheets/sheet1.xml"
    } else {
        "xl/chartsheets/sheet1.xml"
    };
    for part in [
        "[Content_Types].xml",
        "xl/workbook.xml",
        "xl/styles.xml",
        first,
    ] {
        let (_, data) = member(part).unwrap_or_else(|| panic!("{part}"));
        let s = std::str::from_utf8(data).unwrap_or_else(|_| panic!("{part}: UTF-8"));
        assert!(s.starts_with("<?xml"), "{part}");
        // No C0 control character but white space: XML 1.0 refuses them.
        assert!(
            !s.chars()
                .any(|c| (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r')),
            "{part}"
        );
    }
}
