//! The text a reader sees in a document, for a scanner or a search: HTML, the
//! XML parts of Office and OpenDocument files, the hyperlinks of an Office
//! Open XML package (feature `zip`), an email's headers (feature `email`) and
//! (feature `text-pdf`) PDF.
//!
//! A signature written against what a document says (a phrase, a link's
//! address) cannot match it in the bytes when markup, escapes, encodings or
//! compression sit between the words. These readers take the words out, one
//! block to a line, and nothing else: what a reader never sees (a script, a
//! style, a comment, a field code) is left out, and where a link leads is
//! written after its label, `label (target)`, whatever the target is.
//!
//! The parsing is other people's: html5gum's tokenizer for HTML, quick-xml
//! for XML, hayro for PDF. Each is read in a single pass that builds no tree,
//! except hayro's page interpretation, and the text made is cut at the `cap`
//! given, which [`Extracted`] says. Nothing here fetches, runs or follows
//! anything.

#[cfg(feature = "email")]
mod email;
mod html;
#[cfg(feature = "zip")]
mod package;
#[cfg(feature = "text-pdf")]
mod pdf;
#[cfg(feature = "text-pdf")]
mod pdf_screen;
mod xml;

use std::borrow::Cow;

/// What a document is, for reading its text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An HTML document or fragment.
    Html,
    /// A PDF document. Feature `text-pdf`: without it, [`kind`] never says so.
    Pdf,
    /// One XML part of an Office or OpenDocument file.
    Xml(XmlPart),
    /// An Office Open XML package, whose hyperlinks are read: each label with
    /// the target its part's relationships give. Feature `zip`.
    Package,
    /// An email, whose headers are read: From, To, Subject and the others a
    /// mail reader shows. Feature `email`.
    Email,
    /// The targets of a PDF's link annotations and actions, one to a line, as
    /// the PDF reader gives them (its `pdf-uris` member): each is a link
    /// whose label is not known.
    Targets,
}

/// Which part of an Office or OpenDocument file an XML member is, which says
/// where its text is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmlPart {
    /// WordprocessingML: the document, its headers, footers, notes and comments.
    Word,
    /// DrawingML slides and their notes.
    Slide,
    /// SpreadsheetML's shared strings.
    SharedStrings,
    /// A SpreadsheetML sheet: inline strings and formulas.
    Sheet,
    /// OpenDocument's content and styles.
    Odf,
}

/// What [`extract`] made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extracted {
    /// The text, in UTF-8, one block to a line.
    pub text: String,
    /// The text reached the cap, or a PDF stream decompressed past it: the
    /// rest of the document is not here.
    pub truncated: bool,
    /// Each link whose label is not its target, as `(label, target)`, for a
    /// check of what a link says against where it goes. At most [`MAX_LINKS`].
    pub links: Vec<(String, String)>,
}

/// Links kept in [`Extracted::links`].
pub const MAX_LINKS: usize = 4096;

/// What the file or member `src` is, going by its `name` and its first
/// kilobyte, when its text can be read. A ZIP is read to its end for its
/// members.
///
/// A PDF is known by its signature (with the `text-pdf` feature), HTML by its extension or an `<html>`,
/// `<body>` or doctype near the start, an XML part by its path in the package,
/// an Office Open XML package by its name or the members of its ZIP
/// directory, an email by its headers.
pub fn kind(name: &str, src: &dyn crate::ByteSource) -> Option<Kind> {
    let head = src.window(0, 1024);
    let head = &head[..];
    #[cfg(feature = "text-pdf")]
    if find(head, b"%PDF-").is_some() {
        return Some(Kind::Pdf);
    }
    #[cfg(feature = "zip")]
    if package::is_package(name, head, src) {
        return Some(Kind::Package);
    }
    // The rest is markup: a binary file called `x.html` is not.
    if !looks_text(head) {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if let Some(part) = xml_part(&lower) {
        return Some(Kind::Xml(part));
    }
    if lower == "pdf-uris" {
        return Some(Kind::Targets);
    }
    // Before HTML: a message's body can be HTML from its first kilobyte.
    #[cfg(feature = "email")]
    if email::is_email(head) {
        return Some(Kind::Email);
    }
    let by_name = [".html", ".htm", ".xhtml", ".shtml"]
        .iter()
        .any(|e| lower.ends_with(e));
    let by_head = {
        let h = head.to_ascii_lowercase();
        HTML_MARKERS.iter().any(|n| find(&h, n).is_some())
    };
    (by_name || by_head).then_some(Kind::Html)
}

/// What near the start of a text says it is HTML: a document's tags, or the
/// ones a fragment (an email's body, say) is made of.
const HTML_MARKERS: &[&[u8]] = &[
    b"<!doctype html",
    b"<html",
    b"<body",
    b"<head>",
    b"<a href",
    b"<p>",
    b"<p ",
    b"<div",
    b"<table",
    b"<span",
    b"<br",
    b"<img ",
    b"<font",
    b"<center",
    b"<ul>",
    b"<li>",
];

/// Whether `head` reads as text: no NUL, and few other control bytes.
pub fn looks_text(head: &[u8]) -> bool {
    let controls = head
        .iter()
        .filter(|&&b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c))
        .count();
    !head.is_empty() && !head.contains(&0) && controls * 20 <= head.len()
}

/// The text of `data`, a document of `kind`, cut at `cap` bytes. `limits` bound
/// what a PDF's streams decompress to.
pub fn extract(kind: Kind, data: &[u8], cap: usize, limits: &crate::Limits) -> Extracted {
    let mut out = Out::new(cap);
    match kind {
        Kind::Html => html::read(&crate::html::decode(data), &mut out),
        #[cfg(feature = "text-pdf")]
        Kind::Pdf => pdf::read(data, limits, &mut out),
        #[cfg(not(feature = "text-pdf"))]
        Kind::Pdf => {
            let _ = limits;
        }
        Kind::Xml(part) => xml::read(&decode(data), part, &mut out),
        #[cfg(feature = "zip")]
        Kind::Package => package::read(data, limits, &mut out),
        #[cfg(feature = "email")]
        Kind::Email => email::read(data, &mut out),
        Kind::Targets => {
            for line in decode(data).lines() {
                if out.full() {
                    break;
                }
                out.newline();
                let from = out.len();
                out.target(from, line);
            }
        }
        #[cfg(not(all(feature = "zip", feature = "email")))]
        _ => {}
    }
    out.finish()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(hay, needle)
}

/// Whether the package path `lower` (lowercased) is a part that holds text.
fn xml_part(lower: &str) -> Option<XmlPart> {
    let path = lower.trim_start_matches('/');
    let numbered = |dir: &str, stem: &str| {
        path.strip_prefix(dir)
            .and_then(|r| r.strip_prefix(stem))
            .and_then(|r| r.strip_suffix(".xml"))
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
    };
    if matches!(
        path,
        "word/document.xml" | "word/comments.xml" | "word/footnotes.xml" | "word/endnotes.xml"
    ) || numbered("word/", "header")
        || numbered("word/", "footer")
    {
        Some(XmlPart::Word)
    } else if numbered("ppt/slides/", "slide") || numbered("ppt/notesslides/", "notesslide") {
        Some(XmlPart::Slide)
    } else if path == "xl/sharedstrings.xml" {
        Some(XmlPart::SharedStrings)
    } else if numbered("xl/worksheets/", "sheet") {
        Some(XmlPart::Sheet)
    } else if path == "content.xml" || path == "styles.xml" {
        Some(XmlPart::Odf)
    } else {
        None
    }
}

/// The encoding [`decode_file`] read a text in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Windows1252,
}

impl Encoding {
    /// The WHATWG label of the encoding.
    pub fn label(self) -> &'static str {
        match self {
            Encoding::Utf8 => "utf-8",
            Encoding::Utf16Le => "utf-16le",
            Encoding::Utf16Be => "utf-16be",
            Encoding::Windows1252 => "windows-1252",
        }
    }
}

/// A file read as text by [`decode_file`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub text: String,
    pub encoding: Encoding,
}

/// Bytes of a file [`decode_file`] checks for being text.
const SAMPLE: usize = 64 * 1024;

/// A file as text to show: `None` when it is not text.
///
/// The encoding is the one the readers of this module use ([`decode`]): a
/// UTF-16 byte-order mark, else UTF-8 when the bytes are valid in it, else
/// windows-1252. UTF-32 is refused. The check is [`looks_text`] over the first
/// 64 KiB, over the decoded text for UTF-16, whose bytes hold NULs. An empty
/// file is an empty text.
///
/// With `partial`, `data` is the start of a longer file: a character cut by
/// its end is left out instead of being an error.
pub fn decode_file(data: &[u8], partial: bool) -> Option<Decoded> {
    let reading = file_reading(data, partial)?;
    Some(Decoded {
        text: apply(data, &reading).into_owned(),
        encoding: reading.encoding,
    })
}

/// How [`decode_file`] reads a file: `data[start..end]`, in `encoding`.
///
/// A decoder of the WHATWG Encoding Standard, a browser's `TextDecoder` for
/// one, gives the text of [`decode_file`] from this, given the label of the
/// encoding and the bytes in range, with `ignoreBOM` so that it strips no
/// second mark. A reader that only makes the choice needs none of the tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    pub encoding: Encoding,
    /// After the byte-order mark.
    pub start: usize,
    /// Before the character a partial read cut.
    pub end: usize,
}

/// The [`Reading`] of a file, or `None` when it is not text: the rule of
/// [`decode_file`], without decoding anything but the sample a UTF-16 file is
/// checked on.
pub fn file_reading(data: &[u8], partial: bool) -> Option<Reading> {
    if data.starts_with(&[0xff, 0xfe, 0, 0]) || data.starts_with(&[0, 0, 0xfe, 0xff]) {
        return None;
    }
    let reading = reading(data, partial);
    let refused = match reading.encoding {
        Encoding::Utf16Le | Encoding::Utf16Be => {
            let big = reading.encoding == Encoding::Utf16Be;
            let head = utf16_head(&data[reading.start..reading.end], big);
            !head.is_empty() && !looks_text(&head.as_bytes()[..head.len().min(SAMPLE)])
        }
        _ => !data.is_empty() && !looks_text(&data[..data.len().min(SAMPLE)]),
    };
    (!refused).then_some(reading)
}

/// The start of UTF-16 `body` as text, about [`SAMPLE`] bytes of it.
fn utf16_head(body: &[u8], big: bool) -> String {
    let (pairs, _) = body.as_chunks::<2>();
    let units = pairs.iter().map(|&p| {
        if big {
            u16::from_be_bytes(p)
        } else {
            u16::from_le_bytes(p)
        }
    });
    let mut out = String::new();
    for c in char::decode_utf16(units) {
        out.push(c.unwrap_or('\u{fffd}'));
        if out.len() >= SAMPLE {
            return out;
        }
    }
    // An odd byte at the end reads as one replacement character.
    if body.len() % 2 == 1 {
        out.push('\u{fffd}');
    }
    out
}

/// The encoding a byte-order mark names, UTF-16 only.
fn utf16_bom(data: &[u8]) -> Option<Encoding> {
    match data {
        [0xff, 0xfe, ..] => Some(Encoding::Utf16Le),
        [0xfe, 0xff, ..] => Some(Encoding::Utf16Be),
        _ => None,
    }
}

/// `data` as text by [`decode_file`]'s rule, whatever the bytes are: a UTF-16
/// byte-order mark, else UTF-8 when they are valid in it (after a UTF-8 mark,
/// which is left out), else windows-1252, which no byte sequence is invalid
/// in.
pub fn decode(data: &[u8]) -> Cow<'_, str> {
    apply(data, &reading(data, false))
}

/// The choice of [`decode`]. With `partial`, a character `data` ends in the
/// middle of is left out.
fn reading(data: &[u8], partial: bool) -> Reading {
    if let Some(encoding) = utf16_bom(data) {
        let mut end = data.len();
        if partial {
            // An odd byte, and a high surrogate whose pair is not here.
            end &= !1;
            if let [.., a, b] = data[..end] {
                let unit = match encoding {
                    Encoding::Utf16Le => u16::from_le_bytes([a, b]),
                    _ => u16::from_be_bytes([a, b]),
                };
                if (0xd800..0xdc00).contains(&unit) {
                    end -= 2;
                }
            }
        }
        return Reading {
            encoding,
            start: 2,
            end,
        };
    }
    let start = 3 * usize::from(data.starts_with(b"\xef\xbb\xbf"));
    match std::str::from_utf8(&data[start..]) {
        Ok(_) => Reading {
            encoding: Encoding::Utf8,
            start,
            end: data.len(),
        },
        Err(e) if partial && e.error_len().is_none() => Reading {
            encoding: Encoding::Utf8,
            start,
            end: start + e.valid_up_to(),
        },
        Err(_) => Reading {
            encoding: Encoding::Windows1252,
            start,
            end: data.len(),
        },
    }
}

/// `data` as text, as `reading` says.
fn apply<'a>(data: &'a [u8], reading: &Reading) -> Cow<'a, str> {
    let body = &data[reading.start..reading.end];
    let decoder = match reading.encoding {
        Encoding::Utf8 => return String::from_utf8_lossy(body),
        Encoding::Utf16Le => encoding_rs::UTF_16LE,
        Encoding::Utf16Be => encoding_rs::UTF_16BE,
        Encoding::Windows1252 => encoding_rs::WINDOWS_1252,
    };
    decoder.decode_without_bom_handling(body).0
}

/// The text being made: whitespace collapsed to one space, blocks on their
/// own lines, and a cap.
pub(crate) struct Out {
    s: String,
    cap: usize,
    pub(crate) truncated: bool,
    space: bool,
    links: Vec<(String, String)>,
}

impl Out {
    pub(crate) fn new(cap: usize) -> Self {
        Out {
            s: String::new(),
            cap,
            truncated: false,
            space: false,
            links: Vec::new(),
        }
    }

    /// The cap was reached: nothing more is wanted.
    pub(crate) fn full(&self) -> bool {
        self.truncated
    }

    pub(crate) fn len(&self) -> usize {
        self.s.len()
    }

    /// The text made from byte offset `from`.
    pub(crate) fn since(&self, from: usize) -> &str {
        self.s.get(from..).unwrap_or("")
    }

    fn at_line_start(&self) -> bool {
        self.s.is_empty() || self.s.ends_with('\n')
    }

    fn put(&mut self, c: char) {
        if self.s.len() + c.len_utf8() > self.cap {
            self.truncated = true;
        } else {
            self.s.push(c);
        }
    }

    /// Words: any white space is one space, none at the start of a line.
    pub(crate) fn text(&mut self, t: &str) {
        for c in t.chars() {
            if self.truncated {
                return;
            }
            if c.is_whitespace() || c == '\u{200b}' {
                self.space = true;
            } else {
                if self.space && !self.at_line_start() {
                    self.put(' ');
                }
                self.space = false;
                self.put(c);
            }
        }
    }

    /// A separator inside a line.
    pub(crate) fn space(&mut self) {
        self.space = true;
    }

    /// The end of a block: the next text starts a line.
    pub(crate) fn newline(&mut self) {
        // A row ends its last cell's tab.
        if self.s.ends_with('\t') {
            self.s.pop();
        }
        if !self.at_line_start() {
            self.put('\n');
        }
        self.space = false;
    }

    /// A tab between cells.
    pub(crate) fn tab(&mut self) {
        if !self.at_line_start() && !self.s.ends_with('\t') {
            self.put('\t');
        }
        self.space = false;
    }

    /// Mark the text cut short, for a reader that stopped for another reason.
    #[cfg(any(feature = "text-pdf", feature = "zip"))]
    pub(crate) fn cut(&mut self) {
        self.truncated = true;
    }

    /// ` (target)` after a link's label, unless the label is the target (or
    /// there is no label to follow).
    pub(crate) fn target(&mut self, label_from: usize, target: &str) {
        let target = target.trim();
        if target.is_empty() || target.starts_with('#') {
            return;
        }
        let label = self.since(label_from).trim();
        let bare = target.strip_prefix("mailto:").unwrap_or(target);
        if label == target
            || label == bare
            || label.trim_end_matches('/') == target.trim_end_matches('/')
        {
            return;
        }
        if self.links.len() < MAX_LINKS {
            self.links.push((
                label.chars().take(2048).collect(),
                target.chars().take(2048).collect(),
            ));
        }
        self.space();
        self.text(&format!("({target})"));
    }

    fn finish(mut self) -> Extracted {
        while self.s.ends_with(['\n', ' ', '\t']) {
            self.s.pop();
        }
        if !self.s.is_empty() {
            self.s.push('\n');
        }
        Extracted {
            text: self.s,
            truncated: self.truncated,
            links: self.links,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_a_part_of_a_package_is() {
        assert_eq!(xml_part("word/document.xml"), Some(XmlPart::Word));
        assert_eq!(xml_part("word/header2.xml"), Some(XmlPart::Word));
        assert_eq!(xml_part("word/headers.xml"), None);
        assert_eq!(xml_part("ppt/slides/slide12.xml"), Some(XmlPart::Slide));
        assert_eq!(xml_part("ppt/slides/_rels/slide1.xml.rels"), None);
        assert_eq!(xml_part("xl/worksheets/sheet1.xml"), Some(XmlPart::Sheet));
        assert_eq!(
            xml_part("xl/sharedstrings.xml"),
            Some(XmlPart::SharedStrings)
        );
        assert_eq!(xml_part("content.xml"), Some(XmlPart::Odf));
        assert_eq!(xml_part("docprops/core.xml"), None);
    }

    fn file(data: &[u8]) -> Option<(String, Encoding)> {
        decode_file(data, false).map(|d| (d.text, d.encoding))
    }

    fn utf16(s: &str, big: bool) -> Vec<u8> {
        let mut out = if big {
            vec![0xfe, 0xff]
        } else {
            vec![0xff, 0xfe]
        };
        for u in s.encode_utf16() {
            out.extend(if big {
                u.to_be_bytes()
            } else {
                u.to_le_bytes()
            });
        }
        out
    }

    #[test]
    fn a_file_is_utf8_utf16_or_windows_1252() {
        assert_eq!(
            file("naïve café ✓".as_bytes()),
            Some(("naïve café ✓".into(), Encoding::Utf8))
        );
        assert_eq!(file(b"\xef\xbb\xbfhello").unwrap().0, "hello");
        let s = "Zażółć 😀 ok";
        assert_eq!(file(&utf16(s, false)), Some((s.into(), Encoding::Utf16Le)));
        assert_eq!(file(&utf16(s, true)), Some((s.into(), Encoding::Utf16Be)));
        // 0xE9 alone is not UTF-8; 0x80 is the euro sign in windows-1252.
        assert_eq!(
            file(b"caf\xe9 \x80"),
            Some(("café €".into(), Encoding::Windows1252))
        );
        assert_eq!(file(b""), Some((String::new(), Encoding::Utf8)));
    }

    #[test]
    fn a_character_cut_by_the_end_of_a_partial_read_is_left_out() {
        let read = |d: &[u8], partial| decode_file(d, partial).map(|d| (d.text, d.encoding));
        assert_eq!(read(b"ab\xc3", true), Some(("ab".into(), Encoding::Utf8)));
        assert_eq!(
            read(b"ab\xc3", false),
            Some(("abÃ".into(), Encoding::Windows1252))
        );
        // A high surrogate without its pair, and then an odd byte too.
        let mut cut = utf16("ab😀", false);
        cut.pop();
        cut.pop();
        assert_eq!(read(&cut, true).unwrap().0, "ab");
        cut.push(0);
        assert_eq!(read(&cut, true).unwrap().0, "ab");
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The viewer decodes with a browser's `TextDecoder` from the label and
    /// the range of `file_reading`; its test reads the same cases.
    #[test]
    fn a_reading_names_the_encoding_and_range_of_the_decoded_text() {
        let cases = include_str!("../../tests/fixtures/text/decode_file.txt");
        let mut seen = 0;
        for line in cases.lines().filter(|l| !l.starts_with('#')) {
            let [name, partial, label, input, text] = line.split(';').collect::<Vec<_>>()[..]
            else {
                panic!("bad case {line}");
            };
            let (data, partial) = (unhex(input), partial == "1");
            let want = String::from_utf8(unhex(text)).unwrap();
            let read = decode_file(&data, partial).unwrap();
            assert_eq!(read.text, want, "{name}");
            let reading = file_reading(&data, partial).unwrap();
            assert_eq!(reading.encoding.label(), label, "{name}");
            assert_eq!(reading.encoding, read.encoding, "{name}");
            if reading.encoding == Encoding::Utf8 {
                let body = &data[reading.start..reading.end];
                assert_eq!(std::str::from_utf8(body).unwrap(), want, "{name}");
            }
            seen += 1;
        }
        assert_eq!(seen, 21);
    }

    #[test]
    fn a_file_with_a_nul_or_a_utf32_mark_is_not_text() {
        assert_eq!(file(b"text\0more"), None);
        assert_eq!(file(&[0xff, 0xfe, 0, 0, 0x41, 0, 0, 0]), None);
        assert_eq!(file(&[0, 0, 0xfe, 0xff, 0, 0, 0, 0x41]), None);
        // UTF-16 without a mark is NULs for ASCII: not guessed.
        assert_eq!(file(&[0x68, 0, 0x69, 0]), None);
    }

    #[test]
    fn one_control_byte_in_twenty_is_the_most_a_text_has() {
        // 6 % of the bytes are ESC: not text, as `looks_text` says of a head.
        let mut six = b"a log line\n".repeat(9);
        six.truncate(94);
        six.extend_from_slice(&[0x1b; 6]);
        assert_eq!(six.len(), 100);
        assert_eq!(file(&six), None);
        assert!(!looks_text(&six));
        // 5 %: text.
        six[94] = b'x';
        assert!(file(&six).is_some());
        // Form feeds are not controls here.
        assert!(file(&[0x0c; 50]).is_some());
        // The same count in UTF-16 is judged on the decoded text.
        let noise: String = (0..100)
            .map(|i| if i < 6 { '\u{1b}' } else { 'a' })
            .collect();
        assert_eq!(file(&utf16(&noise, false)), None);
    }
}
