//! Text as the lines a page shows: JSON and XML indented, a diff's lines
//! marked.
//!
//! The result is data: lines made of pieces, a piece being a slice of the
//! input and the class that colours it. No document is built. JSON and XML are
//! read as tokens and copied as written (a number keeps its text, an entity is
//! never expanded, nothing is fetched), and every producer stops keeping
//! lines at a cap given by the caller.

mod diff;
mod json;
mod xml;

pub use diff::format_diff;
pub use json::format_json;
pub use xml::format_xml;

/// The classes that colour a piece.
pub mod class {
    pub const KEY: &str = "exav-viewer-text-key";
    pub const STR: &str = "exav-viewer-text-str";
    pub const NUM: &str = "exav-viewer-text-num";
    pub const LIT: &str = "exav-viewer-text-lit";
    pub const TAG: &str = "exav-viewer-text-tag";
    pub const ATTR: &str = "exav-viewer-text-attr";
    pub const COMMENT: &str = "exav-viewer-text-comment";
    pub const META: &str = "exav-viewer-text-meta";
    pub const HUNK: &str = "exav-viewer-text-hunk";
    pub const ADD: &str = "exav-viewer-text-add";
    pub const DEL: &str = "exav-viewer-text-del";
}

/// A piece of a line, with the class that colours it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seg<'a> {
    pub text: &'a str,
    pub class: Option<&'static str>,
}

/// A line: plain text, or pieces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line<'a> {
    Plain(&'a str),
    Segs(Vec<Seg<'a>>),
}

impl Line<'_> {
    /// The text of the line without its classes.
    pub fn text(&self) -> String {
        match self {
            Line::Plain(s) => (*s).to_owned(),
            Line::Segs(segs) => segs.iter().map(|s| s.text).collect(),
        }
    }
}

/// Lines made from a text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Formatted<'a> {
    pub lines: Vec<Line<'a>>,
    /// There were more lines than the cap.
    pub more: bool,
    /// XML: every construct ended and every tag was closed by its own.
    pub well_formed: bool,
}

impl Formatted<'_> {
    /// `{"lines": [...], "more": bool, "wellFormed": bool}`. A line is a
    /// string, or an array of `[text]` and `[text, class]`: the page's `Line`
    /// type (`ts/text/lines.ts`).
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\"lines\":[");
        for (i, line) in self.lines.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            match line {
                Line::Plain(s) => string(&mut out, s),
                Line::Segs(segs) => {
                    out.push('[');
                    for (k, seg) in segs.iter().enumerate() {
                        if k > 0 {
                            out.push(',');
                        }
                        out.push('[');
                        string(&mut out, seg.text);
                        if let Some(class) = seg.class {
                            out.push(',');
                            string(&mut out, class);
                        }
                        out.push(']');
                    }
                    out.push(']');
                }
            }
        }
        out.push_str(&format!(
            "],\"more\":{},\"wellFormed\":{}}}",
            self.more, self.well_formed
        ));
        out
    }
}

/// `s` as a JSON string.
fn string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Indentation stops growing at this many levels.
const MAX_INDENT: usize = 100;

/// Two spaces for each of `levels` (up to [`MAX_INDENT`]), without allocating.
fn indent(levels: usize) -> &'static str {
    const SPACES: &str = "                                                                                                                                                                                                        ";
    &SPACES[..levels.min(MAX_INDENT) * 2]
}

/// Collects lines up to a cap. Past it, `full` is true and nothing more is
/// kept, so that a producer can stop early.
struct LineBuilder<'a> {
    lines: Vec<Line<'a>>,
    current: Vec<Seg<'a>>,
    max: usize,
    full: bool,
}

impl<'a> LineBuilder<'a> {
    fn new(max: usize) -> Self {
        LineBuilder {
            lines: Vec::new(),
            current: Vec::new(),
            max,
            full: false,
        }
    }

    fn add(&mut self, text: &'a str, class: Option<&'static str>) {
        if !text.is_empty() {
            self.current.push(Seg { text, class });
        }
    }

    /// Ends the line.
    fn end(&mut self) {
        if self.lines.len() >= self.max {
            self.full = true;
            self.current.clear();
        } else {
            self.lines
                .push(Line::Segs(std::mem::take(&mut self.current)));
        }
    }

    /// Ends the line being written if it has anything.
    fn finish(&mut self) {
        if !self.current.is_empty() {
            self.end();
        }
    }
}

/// Splits on LF, CRLF and CR, stopping after `max` lines. The flag says there
/// was more.
fn split_lines(text: &str, max: usize) -> (Vec<&str>, bool) {
    let b = text.as_bytes();
    let n = b.len();
    let mut lines = Vec::new();
    let mut at = 0;
    while at <= n {
        if lines.len() == max {
            return (lines, at < n);
        }
        let end = b[at..]
            .iter()
            .position(|&c| c == b'\n' || c == b'\r')
            .map_or(n, |p| at + p);
        lines.push(&text[at..end]);
        if end >= n {
            break;
        }
        at = end
            + if b[end] == b'\r' && b.get(end + 1) == Some(&b'\n') {
                2
            } else {
                1
            };
    }
    (lines, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indentation_is_two_spaces_a_level_up_to_a_hundred() {
        assert_eq!(indent(0), "");
        assert_eq!(indent(3), "      ");
        assert_eq!(indent(100).len(), 200);
        assert_eq!(indent(5000).len(), 200);
    }

    #[test]
    fn lines_split_on_lf_crlf_and_cr_up_to_a_cap() {
        assert_eq!(
            split_lines("a\nb\r\nc\rd", 10),
            (vec!["a", "b", "c", "d"], false)
        );
        assert_eq!(split_lines("a\n", 10), (vec!["a", ""], false));
        assert_eq!(split_lines("", 10), (vec![""], false));
        assert_eq!(split_lines("a\nb\nc", 2), (vec!["a", "b"], true));
        assert_eq!(split_lines("a\nb", 2), (vec!["a", "b"], false));
        assert_eq!(split_lines("a\nb\n", 2), (vec!["a", "b"], false));
    }

    #[test]
    fn lines_go_to_the_page_as_json() {
        let f = Formatted {
            lines: vec![
                Line::Plain("a \"q\"\t\u{1}"),
                Line::Segs(vec![
                    Seg {
                        text: "x",
                        class: Some(class::KEY),
                    },
                    Seg {
                        text: "y\\",
                        class: None,
                    },
                ]),
                Line::Segs(vec![]),
            ],
            more: true,
            well_formed: false,
        };
        assert_eq!(
            f.to_json(),
            r#"{"lines":["a \"q\"\t\u0001",[["x","exav-viewer-text-key"],["y\\"]],[]],"more":true,"wellFormed":false}"#
        );
    }
}
