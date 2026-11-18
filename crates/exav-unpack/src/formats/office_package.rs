//! Which Office or OpenDocument package a ZIP is, told by the member names of
//! its central directory.

use crate::source::ByteSource;

/// A part a package must have: any one of these member names.
pub type Part = &'static [&'static str];

/// The descriptor every Open Packaging Conventions package has.
pub const CONTENT_TYPES: Part = &["[Content_Types].xml"];

/// The Open XML formats and the parts each must have, by id.
const OPEN_XML: &[(&str, &[Part])] = &[
    (
        "docx",
        &[CONTENT_TYPES, &["word/document.xml", "word/document2.xml"]],
    ),
    (
        "xlsx",
        &[CONTENT_TYPES, &["xl/workbook.xml", "xl/workbook.bin"]],
    ),
    ("pptx", &[CONTENT_TYPES, &["ppt/presentation.xml"]]),
];

/// The OpenDocument formats, which ask for the same parts: the members do not
/// say which of them a package is.
const OPEN_DOCUMENT: &[&str] = &["odt", "ods", "odp"];
const OPEN_DOCUMENT_PARTS: &[Part] = &[&["content.xml"]];

/// The parts a package of format `id` (`docx`, `xlsx`, `pptx`, `odt`, `ods`
/// or `odp`) must have.
pub fn package_parts(id: &str) -> Option<&'static [Part]> {
    if OPEN_DOCUMENT.contains(&id) {
        return Some(OPEN_DOCUMENT_PARTS);
    }
    OPEN_XML.iter().find(|(i, _)| *i == id).map(|(_, p)| *p)
}

/// Whether `names` has a member for each of `parts`.
pub fn has_parts(names: &[&str], parts: &[Part]) -> bool {
    parts
        .iter()
        .all(|part| names.iter().any(|name| part.contains(name)))
}

/// The packages the members `names` make it: the Open XML formats whose parts
/// it has (`docx`, `xlsx`, `pptx`), then, unless a name has `ppt/` or `xl/` in
/// it, every OpenDocument format (`odt`, `ods`, `odp`).
pub fn package_kinds(names: &[&str]) -> Vec<&'static str> {
    let mut kinds: Vec<&'static str> = OPEN_XML
        .iter()
        .filter(|(_, parts)| has_parts(names, parts))
        .map(|(id, _)| *id)
        .collect();
    let has = |part: &str| names.iter().any(|name| name.contains(part));
    if !has("ppt/") && !has("xl/") && has_parts(names, OPEN_DOCUMENT_PARTS) {
        kinds.extend(OPEN_DOCUMENT);
    }
    kinds
}

/// [`package_kinds`] of the ZIP `src`, by its central directory read as the
/// extraction reads it; none when that will not open. This is the package a
/// `Container:` type names: a package cut before its directory is a plain ZIP
/// to clamscan 1.4.3 too.
pub fn package_kinds_in(src: &dyn ByteSource) -> Vec<&'static str> {
    let names = super::zip::member_names(src).unwrap_or_default();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    package_kinds(&names)
}

/// [`package_kinds_in`], or, when the directory will not open (a package cut
/// short or damaged), by its local headers, as the walk then reads its
/// members: the package to read the text of.
pub fn package_kinds_walked(src: &dyn ByteSource) -> Vec<&'static str> {
    let names = super::zip::member_names(src).unwrap_or_else(|| {
        // Only the names the rules look at: the parts, and one under `ppt/`
        // or `xl/`.
        let other = std::cell::Cell::new(false);
        let part = |n: &str| {
            OPEN_XML
                .iter()
                .flat_map(|(_, p)| p.iter())
                .chain(OPEN_DOCUMENT_PARTS)
                .any(|p| p.contains(&n))
        };
        let keep = |n: &str| {
            part(n) || ((n.contains("ppt/") || n.contains("xl/")) && !other.replace(true))
        };
        super::zip::local_names(src, &keep)
    });
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    package_kinds(&names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(names: &[&str]) -> Vec<&'static str> {
        package_kinds(names)
    }

    #[test]
    fn open_xml_needs_the_descriptor_and_the_main_part() {
        assert_eq!(
            kinds(&["[Content_Types].xml", "word/document.xml"]),
            ["docx"]
        );
        assert_eq!(kinds(&["[Content_Types].xml", "xl/workbook.bin"]), ["xlsx"]);
        assert_eq!(
            kinds(&["[Content_Types].xml", "ppt/presentation.xml"]),
            ["pptx"]
        );
        assert!(kinds(&["word/document.xml"]).is_empty());
        assert!(kinds(&["[Content_Types].xml", "word/styles.xml"]).is_empty());
        // A part inside another path is not the main part.
        assert!(kinds(&["[Content_Types].xml", "backup/word/document.xml"]).is_empty());
    }

    #[test]
    fn open_document_is_content_without_a_deck_or_a_workbook() {
        assert_eq!(kinds(&["content.xml"]), ["odt", "ods", "odp"]);
        assert!(kinds(&["content.xml", "ppt/slides/slide1.xml"]).is_empty());
        assert!(kinds(&["content.xml", "xl/workbook.xml"]).is_empty());
    }

    /// Cut before its central directory, a package is a plain ZIP as a
    /// container type, as clamscan types it, and is told by its local headers
    /// for its text, as its members are then read; a name its data only quotes
    /// is not a header.
    #[test]
    fn a_package_whose_directory_is_lost_is_read_by_its_local_headers() {
        use std::io::Write;
        let mut z = ::zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, data) in [
            ("docProps/app.xml", &b"word/document.xml"[..]),
            ("[Content_Types].xml", b"<Types/>"),
            ("word/document.xml", b"<w:document/>"),
        ] {
            z.start_file(name, ::zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(data).unwrap();
        }
        let whole = z.finish().unwrap().into_inner();
        assert_eq!(package_kinds_in(&whole), ["docx"]);
        assert_eq!(package_kinds_walked(&whole), ["docx"]);
        let directory = whole.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        let cut = &whole[..directory];
        assert!(super::super::zip::member_names(&cut).is_none());
        assert!(package_kinds_in(&cut).is_empty());
        assert_eq!(package_kinds_walked(&cut), ["docx"]);
        // Without the main part's header, the name in the data does not count.
        let main = whole
            .windows(4)
            .enumerate()
            .filter(|(_, w)| *w == b"PK\x03\x04")
            .nth(2)
            .unwrap()
            .0;
        let before_main = &whole[..main];
        assert!(package_kinds_walked(&before_main).is_empty());
    }

    #[test]
    fn the_parts_of_a_format_are_the_ones_the_kinds_ask_for() {
        for id in ["docx", "xlsx", "pptx", "odt", "ods", "odp"] {
            assert!(package_parts(id).is_some(), "{id}");
        }
        assert!(package_parts("odg").is_none());
    }
}
