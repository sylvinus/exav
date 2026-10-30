//! Which office document a file is, by its bytes and its name, and its text:
//! the legacy and flat formats the XML parts of `exav_unpack::text` do not
//! reach (DOC, XLS, PPT, RTF, Word 2003 XML, SpreadsheetML 2003, SYLK, the
//! flat OpenDocument files, Numbers, Pages, Keynote). For [`crate::text`].

use super::text::Text;
use super::{docs, sheets, slides};
use exav_unpack::cfb::Compound;

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

fn is_rtf(head: &[u8]) -> bool {
    let h = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head);
    let at = h
        .iter()
        .take(16)
        .take_while(|b| b.is_ascii_whitespace())
        .count();
    h[at..].starts_with(b"{\\rtf")
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

/// Whether a file or member called `name`, starting with `head` (a kilobyte
/// is enough), may be an office document read here. Cheap: nothing is
/// parsed, and a compound file or an archive is told by its name.
pub fn wants(name: &str, head: &[u8]) -> bool {
    if is_rtf(head) {
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

/// What kind of document `data` is, when it is one read here.
fn kind(name: &str, data: &[u8]) -> Option<Doc> {
    let head = &data[..data.len().min(4096)];
    if is_rtf(head) {
        return Some(Doc::Docs(docs::Format::Rtf));
    }
    if head.starts_with(&OLE2) {
        if !has_extension(name, COMPOUND_EXTENSIONS) {
            return None;
        }
        let c = Compound::open(data)?;
        let has = |n: &str| c.names().any(|s| s.eq_ignore_ascii_case(n));
        return if has("WordDocument") {
            Some(Doc::Docs(docs::Format::Doc))
        } else if has("Workbook") || has("Book") {
            Some(Doc::Sheets(sheets::Format::Xls))
        } else if has("PowerPoint Document") || has("PP40") {
            Some(Doc::Slides(slides::Format::Ppt))
        } else {
            None
        };
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
    let memory = limits.max_buffer_bytes;
    let made = match doc {
        Doc::Docs(f) => docs::text(
            data,
            f,
            &docs::Limits::default()
                .with_max_memory(memory.min(docs::Limits::default().max_memory)),
            cap,
        )
        .map_err(|e| (e.kind(), e.to_string())),
        Doc::Sheets(f) => sheets::text(
            data,
            f,
            &sheets::Limits::default()
                .with_max_memory(memory.min(sheets::Limits::default().max_memory)),
            cap,
        )
        .map_err(|e| (e.kind(), e.to_string())),
        Doc::Slides(f) => slides::text(
            data,
            f,
            &slides::Limits::default()
                .with_max_memory(memory.min(slides::Limits::default().max_memory)),
            cap,
        )
        .map_err(|e| (e.kind(), e.to_string())),
    };
    match made {
        Ok(t) => Some(Read::Text(t)),
        // Not that kind of file after all: nothing to say.
        Err(("not-format", _)) => None,
        Err((kind, why)) => Some(Read::Unreadable(format!("{kind}: {why}"))),
    }
}
