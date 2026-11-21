//! Which office document a file is, by its bytes and its name, and its text:
//! the legacy and flat formats the XML parts of `exav_unpack::text` do not
//! reach (DOC, XLS, PPT, RTF, Word 2003 XML, SpreadsheetML 2003, SYLK, the
//! flat OpenDocument files, Numbers, Pages, Keynote). For [`crate::text`].

use super::text::Text;
use super::{docs, sheets, slides};
use exav_unpack::cfb::Kind;

/// What a file is, among what is read here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Doc {
    Docs(docs::Format),
    Sheets(sheets::Format),
    Slides(slides::Format),
}

/// Extensions of the compound files read here: another compound file (an
/// installer, a message) is not, and is not read whole to find out.
const COMPOUND_EXTENSIONS: &[&str] = &[
    ".doc", ".dot", ".xls", ".xlt", ".xlw", ".ppt", ".pps", ".pot",
];
/// Extensions of a bare BIFF worksheet, whose first bytes are a weak sign.
const BIFF_EXTENSIONS: &[&str] = &[".xls", ".xlt", ".xlw"];
/// Extensions of the flat and iWork files read here.
const NAMED_EXTENSIONS: &[&str] = &[
    ".fodt", ".fods", ".fodp", ".fodg", ".slk", ".sylk", ".pages", ".key", ".keynote", ".numbers",
];

const OLE2: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// The start of a text document as ASCII, lower case: UTF-16 by its byte
/// order mark read a byte in two, a UTF-8 mark and leading white space
/// skipped. At most `n` characters.
fn ascii_head(data: &[u8], n: usize) -> String {
    let (step, from) = match data {
        [0xFF, 0xFE, ..] => (2, 2),
        [0xFE, 0xFF, ..] => (2, 3),
        [0xEF, 0xBB, 0xBF, ..] => (1, 3),
        _ => (1, 0),
    };
    data.iter()
        .skip(from)
        .step_by(step)
        .take(n)
        .map(|&b| {
            if b < 0x80 {
                b.to_ascii_lowercase() as char
            } else {
                '?'
            }
        })
        .collect::<String>()
        .trim_start()
        .to_string()
}

fn has_extension(name: &str, list: &[&str]) -> bool {
    let lower = name.to_ascii_lowercase();
    list.iter().any(|e| lower.ends_with(e))
}

/// The XML a flat file's first bytes say it is.
fn xml_kind(head: &str) -> Option<Doc> {
    if head.contains("urn:schemas-microsoft-com:office:spreadsheet")
        && head.contains("workbook")
        && !head.contains("<html")
    {
        return Some(Doc::Sheets(sheets::Format::SpreadsheetMl));
    }
    if head.contains("w:worddocument") || head.contains("schemas-microsoft-com:office:word") {
        return Some(Doc::Docs(docs::Format::Wml2003));
    }
    if head.contains("office:document") {
        for (marker, doc) in [
            ("opendocument.text", Doc::Docs(docs::Format::Fodt)),
            (
                "opendocument.spreadsheet",
                Doc::Sheets(sheets::Format::Fods),
            ),
            (
                "opendocument.presentation",
                Doc::Slides(slides::Format::Fodp),
            ),
            ("opendocument.graphics", Doc::Slides(slides::Format::Fodg)),
            ("opendocument.drawing", Doc::Slides(slides::Format::Fodg)),
        ] {
            if head.contains(marker) {
                return Some(doc);
            }
        }
    }
    None
}

/// Whether `head`, a file's first kilobyte, says it is one of the flat XML
/// documents read here (SpreadsheetML or Word 2003 XML, a flat
/// OpenDocument file): a document that HTML's tags in it (a SpreadsheetML
/// `<Table>`) do not make a page.
pub(crate) fn flat_xml(head: &[u8]) -> bool {
    let first = &head[..head.len().min(1024)];
    let utf16 = first.starts_with(&[0xFF, 0xFE]) || first.starts_with(&[0xFE, 0xFF]);
    (utf16 || exav_unpack::text::looks_text(first)) && xml_kind(&ascii_head(first, 1024)).is_some()
}

/// Whether a file or member called `name`, starting with `head` (a kilobyte
/// is enough), may be an office document read here. Cheap: nothing is
/// parsed, and a compound file or an archive is told by its name.
pub fn wants(name: &str, head: &[u8]) -> bool {
    if exav_unpack::is_rtf_after_space(head) {
        return true;
    }
    if head.starts_with(&OLE2) {
        return has_extension(name, COMPOUND_EXTENSIONS);
    }
    if is_biff(head) && has_extension(name, BIFF_EXTENSIONS) {
        return true;
    }
    if has_extension(name, NAMED_EXTENSIONS) {
        return true;
    }
    let utf16 = head.starts_with(&[0xFF, 0xFE]) || head.starts_with(&[0xFE, 0xFF]);
    if !(utf16 || exav_unpack::text::looks_text(head)) {
        return false;
    }
    let text = ascii_head(&head[..head.len().min(1024)], 1024);
    text.starts_with("id;") || xml_kind(&text).is_some()
}

/// The documents of a compound file ([`exav_unpack::cfb::compound_kinds`]): a
/// compound file may hold several, and each is read.
fn compound_kinds(data: &[u8]) -> Vec<Doc> {
    exav_unpack::cfb::compound_kinds(data)
        .into_iter()
        .map(|k| match k {
            Kind::Word => Doc::Docs(docs::Format::Doc),
            Kind::Workbook => Doc::Sheets(sheets::Format::Xls),
            Kind::Presentation => Doc::Slides(slides::Format::Ppt),
        })
        .collect()
}

/// What kind of document `data` is, when it is one read here.
fn kind(name: &str, data: &[u8]) -> Option<Doc> {
    let head = &data[..data.len().min(4096)];
    if exav_unpack::is_rtf_after_space(head) {
        return Some(Doc::Docs(docs::Format::Rtf));
    }
    if head.starts_with(&OLE2) {
        if !has_extension(name, COMPOUND_EXTENSIONS) {
            return None;
        }
        return compound_kinds(data).first().copied();
    }
    if head.starts_with(b"PK") {
        return iwork(name);
    }
    // A bare BIFF2 to BIFF4 worksheet: a weak signature, so the name asks too.
    if is_biff(head) && has_extension(name, BIFF_EXTENSIONS) {
        return Some(Doc::Sheets(sheets::Format::Xls));
    }
    // The first kilobyte, as `wants` reads it; a flat OpenDocument file's
    // root element, which declares many namespaces before it says what it is,
    // may need more, and its name has asked for it.
    let first = &head[..head.len().min(1024)];
    // Text, as `wants` asks first: a binary file with a marker among its bytes
    // is not a document of that kind.
    let utf16 = first.starts_with(&[0xFF, 0xFE]) || first.starts_with(&[0xFE, 0xFF]);
    let sniffable = utf16 || exav_unpack::text::looks_text(first);
    let text = ascii_head(first, 1024);
    if sniffable && text.starts_with("id;") {
        return Some(Doc::Sheets(sheets::Format::Sylk));
    }
    sniffable.then(|| xml_kind(&text)).flatten().or_else(|| {
        has_extension(name, &[".fodt", ".fods", ".fodp", ".fodg"])
            .then(|| xml_kind(&ascii_head(head, 4096)))
            .flatten()
    })
}

/// Numbers, Pages or Keynote, by the name of the package (a ZIP of members
/// whose names tell the three apart only with the iWork versions in mind): the
/// converters refuse what is not theirs.
fn iwork(name: &str) -> Option<Doc> {
    if has_extension(name, &[".key", ".keynote"]) {
        Some(Doc::Slides(slides::Format::Keynote))
    } else if has_extension(name, &[".numbers"]) {
        Some(Doc::Sheets(sheets::Format::Numbers))
    } else if has_extension(name, &[".pages"]) {
        Some(Doc::Docs(docs::Format::Pages))
    } else {
        None
    }
}

/// A BIFF2 to BIFF4 worksheet's first record (BOF).
fn is_biff(head: &[u8]) -> bool {
    matches!(head, [0x09, 0 | 2 | 4, b, 0, ..] if *b < 0x20)
}

/// What reading an office document's text gave.
#[derive(Debug)]
pub enum Read {
    /// The text.
    Text(Text),
    /// The document is one read here, and its text could not be read: why
    /// (encrypted, past a limit, damaged).
    Unreadable(String),
}

/// The text of `data`, a file called `name`, when it is an office document
/// read here (`None` when it is not). `cap` bounds the text, `limits` the
/// work.
pub fn read(name: &str, data: &[u8], cap: usize, limits: &exav_unpack::Limits) -> Option<Read> {
    let doc = kind(name, data)?;
    if data.starts_with(&OLE2) {
        let kinds = compound_kinds(data);
        if kinds.len() > 1 {
            return read_all(&kinds, data, cap, limits);
        }
    }
    read_one(doc, data, cap, limits)
}

/// The text of each document of a compound file that holds several, one
/// after the other within `cap`. One that cannot be read cuts the text; when
/// none can, the file is unreadable.
fn read_all(kinds: &[Doc], data: &[u8], cap: usize, limits: &exav_unpack::Limits) -> Option<Read> {
    let mut all = Text::default();
    let mut read = 0;
    let mut why = None;
    for &doc in kinds {
        let left = cap.saturating_sub(all.text.len());
        match read_one(doc, data, left, limits) {
            Some(Read::Text(t)) => {
                read += 1;
                let at = all.text.len();
                all.text.push_str(&t.text);
                all.truncated |= t.truncated;
                let room = super::text::MAX_LINKS.saturating_sub(all.links.len());
                all.links.extend(t.links.into_iter().take(room));
                all.sections.extend(t.sections.into_iter().map(|mut s| {
                    s.range = s.range.start + at..s.range.end + at;
                    s
                }));
            }
            Some(Read::Unreadable(w)) => {
                all.truncated = true;
                why.get_or_insert(w);
            }
            None => {}
        }
    }
    match why {
        Some(w) if read == 0 => Some(Read::Unreadable(w)),
        _ if read == 0 => None,
        _ => Some(Read::Text(all)),
    }
}

/// The three converters' limits, derived from the scanner's.
#[derive(Debug, PartialEq, Eq)]
struct Converters {
    docs: docs::Limits,
    sheets: sheets::Limits,
    slides: slides::Limits,
}

/// The size the converters' limits follow: the object limit, or when that is
/// off the extraction budget, or when both are off the object limit's default.
/// Never unbounded, so a converter's memory always has a ceiling.
fn bound(limits: &exav_unpack::Limits) -> u64 {
    [limits.max_buffer_bytes, limits.max_extracted_bytes]
        .into_iter()
        .find(|&b| b != u64::MAX)
        .unwrap_or(exav_unpack::Limits::default().max_buffer_bytes)
}

/// The converters' limits for a scan under `limits`. Sizes (one part, memory)
/// are the bound itself; counts grow in proportion to it from their defaults,
/// which are what the bound's default gives; an input is at least its default.
fn converters(limits: &exav_unpack::Limits) -> Converters {
    let bound = bound(limits);
    let base = exav_unpack::Limits::default().max_buffer_bytes;
    let count = |n: u64| {
        let scaled = u128::from(n) * u128::from(bound) / u128::from(base);
        u64::try_from(scaled).unwrap_or(u64::MAX).max(n)
    };
    let count32 = |n: u32| u32::try_from(count(n.into())).unwrap_or(u32::MAX);
    let (d, s, p) = (
        docs::Limits::default(),
        sheets::Limits::default(),
        slides::Limits::default(),
    );
    Converters {
        docs: docs::Limits {
            max_input: bound.max(d.max_input),
            max_memory: bound,
            max_part: bound,
            max_paragraphs: count(d.max_paragraphs),
            max_cells: count(d.max_cells),
        },
        sheets: sheets::Limits {
            max_input: bound.max(s.max_input),
            max_cells: count(s.max_cells),
            max_memory: bound,
            max_part: bound,
            max_sheets: count32(s.max_sheets),
        },
        slides: slides::Limits {
            max_input: bound.max(p.max_input),
            max_memory: bound,
            max_part: bound,
            max_slides: count32(p.max_slides),
            max_shapes: count(p.max_shapes),
        },
    }
}

fn read_one(doc: Doc, data: &[u8], cap: usize, limits: &exav_unpack::Limits) -> Option<Read> {
    let c = converters(limits);
    let made = match doc {
        Doc::Docs(f) => docs::text(data, f, &c.docs, cap).map_err(|e| (e.kind(), e.to_string())),
        Doc::Sheets(f) => {
            sheets::text(data, f, &c.sheets, cap).map_err(|e| (e.kind(), e.to_string()))
        }
        Doc::Slides(f) => {
            slides::text(data, f, &c.slides, cap).map_err(|e| (e.kind(), e.to_string()))
        }
    };
    match made {
        Ok(t) => Some(Read::Text(t)),
        // Not that kind of file after all: nothing to say.
        Err(("not-format", _)) => None,
        Err((kind, why)) => Some(Read::Unreadable(format!("{kind}: {why}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    fn with_object(bytes: u64) -> exav_unpack::Limits {
        let mut l = exav_unpack::Limits::default();
        l.max_buffer_bytes = bytes;
        l
    }

    #[test]
    fn the_default_object_limit_gives_the_numbers_the_converters_always_had() {
        assert_eq!(
            converters(&exav_unpack::Limits::default()),
            Converters {
                docs: docs::Limits::default().with_max_memory(256 * MIB),
                sheets: sheets::Limits::default().with_max_memory(256 * MIB),
                slides: slides::Limits::default().with_max_memory(256 * MIB),
            }
        );
    }

    #[test]
    fn a_raised_object_limit_raises_sizes_to_it_and_counts_in_proportion() {
        let c = converters(&with_object(2048 * MIB));
        assert_eq!(c.docs.max_memory, 2048 * MIB);
        assert_eq!(c.docs.max_part, 2048 * MIB);
        assert_eq!(c.docs.max_input, 2048 * MIB);
        assert_eq!(c.docs.max_paragraphs, 40_000_000);
        assert_eq!(c.docs.max_cells, 16_000_000);
        assert_eq!(c.sheets.max_input, 2048 * MIB);
        assert_eq!(c.sheets.max_cells, 32_000_000);
        assert_eq!(c.sheets.max_sheets, 32_768);
        assert_eq!(c.slides.max_slides, 80_000);
        assert_eq!(c.slides.max_shapes, 8_000_000);
    }

    #[test]
    fn a_lowered_object_limit_lowers_sizes_but_not_counts() {
        let c = converters(&with_object(8 * MIB));
        assert_eq!(c.sheets.max_memory, 8 * MIB);
        assert_eq!(c.sheets.max_part, 8 * MIB);
        assert_eq!(c.sheets.max_input, 256 * MIB);
        assert_eq!(c.sheets.max_cells, sheets::Limits::default().max_cells);
        assert_eq!(
            c.docs.max_paragraphs,
            docs::Limits::default().max_paragraphs
        );
    }

    #[test]
    fn with_the_object_limit_off_the_converters_follow_the_extraction_budget() {
        let mut l = with_object(u64::MAX);
        let c = converters(&l);
        assert_eq!(c.docs.max_memory, l.max_extracted_bytes);
        assert_eq!(c.sheets.max_cells, 4 * sheets::Limits::default().max_cells);
        // Both off: the object limit's default, never unbounded.
        l.max_extracted_bytes = u64::MAX;
        let c = converters(&l);
        assert_eq!(c.slides.max_memory, 256 * MIB);
        assert_eq!(c.slides.max_part, 256 * MIB);
    }
}
