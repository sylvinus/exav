//! Which Office source formats a file is, told by its container and not by
//! its name: a compound file by its directory, a ZIP by the parts its
//! directory lists, PowerPoint 2 to 4 by its magic number or its BinHex
//! header. The text and XML forms (flat ODF, SYLK, Word 2003 XML) are not
//! here.

use exav_unpack::binhex;
use exav_unpack::cfb::{self, Kind};
use exav_unpack::old_ppt;

use exav_unpack::{CONTENT_TYPES, TailDirectory, directory_in_tail, has_parts, package_kinds};

/// The formats `bytes` may be, by the id of the converter that reads each
/// (`doc`, `xls`, `ppt`, `docx`, `ods`, `key`, `vsdx`). A file can be several:
/// a compound file with a Word and a workbook stream, an iWork package whose
/// members do not tell the three apart. `bytes` is the whole file when it is a
/// compound file, whose directory can be anywhere; else its first kilobyte
/// is enough. `names` are the members of its ZIP directory.
pub fn office_kinds(bytes: &[u8], names: &[String]) -> Vec<&'static str> {
    if bytes.starts_with(&cfb::SIGNATURE) {
        return cfb::compound_kinds(bytes)
            .into_iter()
            .map(|kind| match kind {
                Kind::Word => "doc",
                Kind::Workbook => "xls",
                Kind::Presentation => "ppt",
            })
            .collect();
    }
    if bytes.starts_with(b"PK") {
        return zip_kinds(bytes, names);
    }
    if old_ppt::parse(bytes).is_some() || binhex_powerpoint(bytes) {
        return vec!["ppt"];
    }
    Vec::new()
}

/// What [`zip_kinds_in_tail`] makes of the last bytes of a ZIP.
#[derive(Debug, PartialEq, Eq)]
pub enum TailKinds {
    /// The formats the directory's members say it may be: none for a file
    /// the reader does not open as a ZIP.
    Kinds(Vec<&'static str>),
    /// The reader needs the bytes from this offset.
    Needs(u64),
}

/// [`office_kinds`] of a `size`-byte ZIP whose first bytes are `head` and
/// whose last bytes are `tail`, the directory being read from them.
pub fn zip_kinds_in_tail(head: &[u8], tail: &[u8], size: u64) -> TailKinds {
    match directory_in_tail(tail, size) {
        TailDirectory::Found(d) => {
            let names: Vec<String> = d.members.into_iter().map(|m| m.name).collect();
            TailKinds::Kinds(office_kinds(head, &names))
        }
        TailDirectory::Needs(at) => TailKinds::Needs(at),
        TailDirectory::NotZip => TailKinds::Kinds(Vec::new()),
    }
}

/// A BinHex 4.0 file of PowerPoint's creator code, or of a file type that
/// starts with SLD or PPT.
fn binhex_powerpoint(text: &[u8]) -> bool {
    binhex::header(text, 0).is_some_and(|h| {
        &h.creator == b"PPNT" || h.file_type.starts_with(b"SLD") || h.file_type.starts_with(b"PPT")
    })
}

/// The ODF format named by the stored `mimetype` member that opens the ZIP:
/// its content, right after the local header's name.
fn odf_mimetype(head: &[u8]) -> Option<&'static str> {
    let text = head.get(38..head.len().min(120))?;
    let has = |word: &str| text.windows(word.len()).any(|w| w == word.as_bytes());
    [
        ("opendocument.text", "odt"),
        ("spreadsheet", "ods"),
        ("presentation", "odp"),
        // "drawing" in OpenOffice 1.x files.
        ("graphics", "odg"),
        ("opendocument.drawing", "odg"),
    ]
    .into_iter()
    .find_map(|(word, id)| has(word).then_some(id))
}

fn zip_kinds(head: &[u8], names: &[String]) -> Vec<&'static str> {
    // OpenDocument: a stored "mimetype" member first. A deflated one is told
    // by the members below.
    let stored = matches!(head.get(8..10), Some([0, 0]));
    if stored && head.get(30..38) == Some(&b"mimetype"[..]) {
        return odf_mimetype(head).into_iter().collect();
    }
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let has = |part: &str| names.iter().any(|name| name.contains(part));
    // Open XML, then, without a usable mimetype, any ODF format.
    let mut kinds = package_kinds(&names);
    // Visio 2013 and later: an Open Packaging package with a visio/ directory.
    if has_parts(&names, &[CONTENT_TYPES, &["visio/document.xml"]]) {
        kinds.push("vsdx");
    }
    // iWork: IWA archives or an Index.zip, which the member names tell
    // apart by Slide and Tables (an Index.zip not at all), and the XML
    // packages of Numbers '08 and '09 and Keynote 1 to 5.
    let iwa = has(".iwa") || has("Index.zip");
    if (has("Index/Document.iwa") || has("Index.zip")) && !(has("Index/Tables/") || has("Slide")) {
        kinds.push("pages");
    }
    if iwa || has("index.xml") {
        kinds.push("numbers");
    }
    if (iwa && (has("Slide") || has("Index.zip"))) || has("index.apxl") || has("presentation.apxl")
    {
        kinds.push("key");
    }
    kinds
}

#[cfg(test)]
mod tests {
    use super::super::tests::zip;
    use super::*;

    /// The kinds of a stored ZIP with these members, empty but for the first
    /// word `mimetype=...`, which is the content of that member.
    fn of_zip(words: &str) -> Vec<&'static str> {
        let members: Vec<(&str, &[u8])> = words
            .split_whitespace()
            .map(|w| match w.strip_prefix("mimetype=") {
                Some(content) => ("mimetype", content.as_bytes()),
                None => (w, &b""[..]),
            })
            .collect();
        let z = zip(&members, b"", 0, false);
        let names: Vec<String> = members.iter().map(|(n, _)| n.to_string()).collect();
        office_kinds(&z, &names)
    }

    fn compound(streams: &[&str]) -> Vec<u8> {
        let streams: Vec<(&str, &[u8])> = streams.iter().map(|n| (*n, &[0u8; 64][..])).collect();
        cfb::build(&streams)
    }

    #[test]
    fn a_compound_file_is_what_its_directory_says() {
        assert_eq!(
            office_kinds(&compound(&["WordDocument", "1Table"]), &[]),
            ["doc"]
        );
        assert_eq!(office_kinds(&compound(&["Workbook"]), &[]), ["xls"]);
        assert_eq!(office_kinds(&compound(&["wordDOCUMENT"]), &[]), ["doc"]);
        assert_eq!(office_kinds(&compound(&["PP40"]), &[]), ["ppt"]);
        assert!(office_kinds(&compound(&["Contents"]), &[]).is_empty());
    }

    /// A Word document is not a workbook because it is a compound file.
    #[test]
    fn a_word_document_is_not_a_workbook() {
        let word = compound(&["WordDocument"]);
        assert!(!office_kinds(&word, &[]).contains(&"xls"));
    }

    /// The order is the one of `compound_kinds`, not the directory's.
    #[test]
    fn a_workbook_and_a_word_stream_are_both_named_in_one_order() {
        let both = compound(&["Workbook", "WordDocument", "PowerPoint Document"]);
        assert_eq!(office_kinds(&both, &[]), ["doc", "xls", "ppt"]);
        let kinds: Vec<_> = cfb::compound_kinds(&both)
            .into_iter()
            .map(|k| format!("{k:?}"))
            .collect();
        assert_eq!(kinds, ["Word", "Workbook", "Presentation"]);
    }

    /// The name of a stream written in the content of another is not one.
    #[test]
    fn a_name_quoted_in_a_stream_does_not_name_a_document() {
        let mut quote = Vec::new();
        for unit in "WordDocument".encode_utf16() {
            quote.extend_from_slice(&unit.to_le_bytes());
        }
        // Padded to 64 bytes, then the length with the terminator, the type.
        quote.resize(64, 0);
        quote.extend_from_slice(&[26, 0, 2]);
        assert!(office_kinds(&cfb::build(&[("Notes", &quote[..])]), &[]).is_empty());
    }

    #[test]
    fn open_xml_packages_are_told_by_the_parts_of_the_table() {
        assert_eq!(of_zip("[Content_Types].xml word/document.xml"), ["docx"]);
        assert_eq!(of_zip("[Content_Types].xml xl/workbook.bin"), ["xlsx"]);
        assert_eq!(of_zip("[Content_Types].xml ppt/presentation.xml"), ["pptx"]);
        assert!(of_zip("word/document.xml").is_empty());
        assert!(of_zip("[Content_Types].xml word/styles.xml").is_empty());
        assert_eq!(
            of_zip("[Content_Types].xml visio/document.xml visio/pages/page1.xml"),
            ["vsdx"]
        );
    }

    #[test]
    fn opendocument_is_told_by_its_mimetype_then_by_its_members() {
        let odf = "mimetype=application/vnd.oasis.opendocument";
        assert_eq!(of_zip(&format!("{odf}.text")), ["odt"]);
        assert_eq!(of_zip(&format!("{odf}.text-template")), ["odt"]);
        assert_eq!(of_zip(&format!("{odf}.spreadsheet")), ["ods"]);
        assert_eq!(of_zip(&format!("{odf}.presentation")), ["odp"]);
        assert_eq!(of_zip(&format!("{odf}.graphics")), ["odg"]);
        assert_eq!(of_zip(&format!("{odf}.drawing")), ["odg"]);
        // A type that is none of them says none, whatever the members.
        assert!(of_zip(&format!("{odf}.formula content.xml")).is_empty());
        // No usable mimetype: any of the three.
        assert_eq!(of_zip("content.xml styles.xml"), ["odt", "ods", "odp"]);
        // Unless the members are those of a deck or a workbook.
        assert!(of_zip("content.xml ppt/slides/slide1.xml").is_empty());
        assert!(of_zip("content.xml xl/workbook.xml").is_empty());
    }

    #[test]
    fn a_deflated_mimetype_is_told_by_the_members() {
        let mut z = zip(
            &[("mimetype", b"\x05\xc1\x81"), ("content.xml", b"")],
            b"",
            0,
            false,
        );
        z[8] = 8;
        let names = vec!["mimetype".to_string(), "content.xml".to_string()];
        assert_eq!(office_kinds(&z, &names), ["odt", "ods", "odp"]);
    }

    #[test]
    fn a_zip_is_told_from_its_first_and_last_bytes() {
        let docx = zip(
            &[
                ("docProps/app.xml", b""),
                ("[Content_Types].xml", b""),
                ("word/document.xml", b""),
            ],
            b"",
            0,
            false,
        );
        let size = docx.len() as u64;
        // The directory is not in the first bytes: the reader asks for it.
        let end = &docx[docx.len() - 40..];
        let TailKinds::Needs(at) = zip_kinds_in_tail(&docx[..40], end, size) else {
            panic!("a directory cut short was read");
        };
        assert!(at < size - 40);
        assert_eq!(
            zip_kinds_in_tail(&docx[..40], &docx, size),
            TailKinds::Kinds(vec!["docx"])
        );
        assert_eq!(
            zip_kinds_in_tail(b"not a zip", b"not a zip", 9),
            TailKinds::Kinds(Vec::new())
        );
    }

    #[test]
    fn iwork_packages_are_told_by_their_members() {
        assert_eq!(
            of_zip("Index/Document.iwa Index/Tables/Tile.iwa"),
            ["numbers"]
        );
        assert_eq!(
            of_zip("Index/Document.iwa Index/DocumentStylesheet.iwa"),
            ["pages", "numbers"]
        );
        assert_eq!(
            of_zip("Index/Document.iwa Index/Slide-1.iwa"),
            ["numbers", "key"]
        );
        assert_eq!(of_zip("Doc.key/Index.zip"), ["pages", "numbers", "key"]);
        assert_eq!(of_zip("index.xml"), ["numbers"]);
        assert_eq!(of_zip("Contents/PkgInfo index.apxl"), ["key"]);
        assert!(of_zip("backup.zip").is_empty());
    }

    /// A BinHex 4.0 text of a Macintosh file of this type and creator.
    fn binhex(file_type: &[u8; 4], creator: &[u8; 4]) -> Vec<u8> {
        let mut raw = vec![1, b'a', 0];
        raw.extend_from_slice(file_type);
        raw.extend_from_slice(creator);
        raw.extend_from_slice(&[0; 12]);
        let alphabet = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";
        let mut text = b"(This file must be converted with BinHex 4.0)\r\r:".to_vec();
        let (mut bits, mut n) = (0u32, 0u32);
        for b in raw {
            bits = bits << 8 | u32::from(b);
            n += 8;
            while n >= 6 {
                n -= 6;
                text.push(alphabet[(bits >> n & 63) as usize]);
            }
        }
        if n > 0 {
            text.push(alphabet[(bits << (6 - n) & 63) as usize]);
        }
        text
    }

    #[test]
    fn powerpoint_2_to_4_is_told_by_its_magic_number_or_its_binhex_header() {
        assert_eq!(
            office_kinds(&[0xed, 0xde, 0xad, 0x0b, 2, 0, 0, 0], &[]),
            ["ppt"]
        );
        assert_eq!(
            office_kinds(&[0x0b, 0xad, 0xde, 0xed, 0, 0, 0, 3], &[]),
            ["ppt"]
        );
        assert!(office_kinds(&[0xed, 0xde, 0xad, 0x0b, 9, 0, 0, 0], &[]).is_empty());
        assert_eq!(office_kinds(&binhex(b"SLDS", b"PPNT"), &[]), ["ppt"]);
        assert_eq!(office_kinds(&binhex(b"TEXT", b"PPNT"), &[]), ["ppt"]);
        assert_eq!(office_kinds(&binhex(b"PPT3", b"????"), &[]), ["ppt"]);
        assert!(office_kinds(&binhex(b"TEXT", b"ttxt"), &[]).is_empty());
        assert!(office_kinds(b"(not binhex)", &[]).is_empty());
        assert!(office_kinds(b"", &[]).is_empty());
    }
}
