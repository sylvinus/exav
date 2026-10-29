//! The text a reader sees in a document, for a scanner or a search: HTML, the
//! XML parts of Office and OpenDocument files, and (feature `text-pdf`) PDF.
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

mod html;
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

/// What `data` is, going by its member `name` and its first bytes `head`
/// (a kilobyte is enough), when its text can be read.
///
/// A PDF is known by its signature (with the `text-pdf` feature), HTML by its extension or an `<html>`,
/// `<body>` or doctype near the start, an XML part by its path in the package.
pub fn kind(name: &str, head: &[u8]) -> Option<Kind> {
    let head = &head[..head.len().min(1024)];
    #[cfg(feature = "text-pdf")]
    if find(head, b"%PDF-").is_some() {
        return Some(Kind::Pdf);
    }
    // The rest is markup: a binary file called `x.html` is not.
    if !looks_text(head) {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if let Some(part) = xml_part(&lower) {
        return Some(Kind::Xml(part));
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

/// `data` as text: UTF-8, UTF-16 by its byte-order mark, else windows-1252,
/// which no byte sequence is invalid in.
fn decode(data: &[u8]) -> Cow<'_, str> {
    if data.starts_with(&[0xff, 0xfe]) || data.starts_with(&[0xfe, 0xff]) {
        let (text, _, _) = encoding_rs::UTF_16LE.decode(data);
        let (text, _, _) = if data[0] == 0xfe {
            encoding_rs::UTF_16BE.decode(data)
        } else {
            (text, encoding_rs::UTF_16LE, false)
        };
        return Cow::Owned(text.into_owned());
    }
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    match std::str::from_utf8(data) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => Cow::Owned(encoding_rs::WINDOWS_1252.decode(data).0.into_owned()),
    }
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
    #[cfg(feature = "text-pdf")]
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
}
