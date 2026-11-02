//! The text of an office document as a reader sees it, taken from what the
//! converters read (`sheets`, `slides`, `docs`), for a scanner or a search:
//! the words, one block to a line, and where a link leads written after its
//! label as `label (target)`. What a reader never sees (a macro, a formula's
//! source, a style) is left out. Nothing is written back out as OOXML first.
//!
//! The text is cut at the cap given, which [`Text::truncated`] says, and is in
//! sections (a sheet, a slide, a page's header), so that a match can say where
//! it is.

/// Links kept in [`Text::links`].
pub const MAX_LINKS: usize = 4096;
/// Characters of a link's label or target kept in [`Text::links`].
const LINK_CHARS: usize = 2048;

/// What a text extraction made.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Text {
    /// The text, in UTF-8, one block to a line.
    pub text: String,
    /// The cap was reached: the rest of the document is not here.
    pub truncated: bool,
    /// Each link whose label is not its target, as `(label, target)`. At most
    /// [`MAX_LINKS`].
    pub links: Vec<(String, String)>,
    /// The parts of the text, in order: a sheet, a slide, a header. Empty
    /// when the document is one block.
    pub sections: Vec<Section>,
}

/// A part of a [`Text`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// What the part is: `sheet "Budget"`, `slide 3`, `footnotes`.
    pub label: String,
    /// Its bytes in [`Text::text`].
    pub range: std::ops::Range<usize>,
}

/// Builds a [`Text`] within a cap.
pub(crate) struct Out {
    text: String,
    cap: usize,
    truncated: bool,
    links: Vec<(String, String)>,
    /// Where each open link's label starts, and its target.
    open: Vec<(usize, String)>,
    sections: Vec<(String, usize)>,
}

impl Out {
    pub(crate) fn new(cap: usize) -> Out {
        Out {
            text: String::new(),
            cap,
            truncated: false,
            links: Vec::new(),
            open: Vec::new(),
            sections: Vec::new(),
        }
    }

    /// Whether the cap is reached: a reader may stop.
    pub(crate) fn full(&self) -> bool {
        self.truncated
    }

    /// Starts a section. An empty one is dropped when the next starts.
    pub(crate) fn section(&mut self, label: impl Into<String>) {
        self.newline();
        self.sections.push((label.into(), self.text.len()));
    }

    /// Appends text to the current line, its control characters turned into
    /// spaces; a line break in it ends the line.
    pub(crate) fn push(&mut self, s: &str) {
        for c in s.chars() {
            if self.truncated {
                return;
            }
            if self.text.len() + c.len_utf8() > self.cap {
                self.truncated = true;
                return;
            }
            match c {
                '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{2028}' | '\u{2029}' => self.newline(),
                c if c.is_control() && c != '\t' => self.text.push(' '),
                c => self.text.push(c),
            }
        }
    }

    /// Ends the line, unless it is empty.
    pub(crate) fn newline(&mut self) {
        let start = self.text.rfind('\n').map_or(0, |i| i + 1);
        let line = &self.text[start..];
        if line.trim().is_empty() {
            self.text.truncate(start);
        } else if self.text.len() < self.cap {
            self.text.push('\n');
        } else {
            self.truncated = true;
        }
    }

    /// One line: `s` and a line break. Some readers write whole lines, some
    /// push runs: a build with only the others leaves this one unused.
    #[allow(dead_code)]
    pub(crate) fn line(&mut self, s: &str) {
        self.push(s);
        self.newline();
    }

    /// Opens a link to `target`: the text pushed until [`Out::end_link`] is
    /// its label.
    pub(crate) fn begin_link(&mut self, target: &str) {
        if self.open.len() < 16 {
            self.open.push((self.text.len(), target.to_string()));
        }
    }

    /// Closes the last open link: its target follows its label in the text,
    /// `label (target)`, and the pair is kept when they differ.
    pub(crate) fn end_link(&mut self) {
        let Some((start, target)) = self.open.pop() else {
            return;
        };
        let label = self.text.get(start..).unwrap_or("");
        let bare = target.strip_prefix("mailto:").unwrap_or(&target);
        if label == target || label == bare || target.is_empty() {
            return;
        }
        let pair = (
            label.trim().chars().take(LINK_CHARS).collect::<String>(),
            target.chars().take(LINK_CHARS).collect::<String>(),
        );
        if self.links.len() < MAX_LINKS {
            self.links.push(pair);
        }
        self.push(" (");
        self.push(&target);
        self.push(")");
    }

    pub(crate) fn finish(mut self) -> Text {
        while !self.open.is_empty() {
            self.end_link();
        }
        self.newline();
        let end = self.text.len();
        let mut sections = Vec::new();
        for (i, (label, start)) in self.sections.iter().enumerate() {
            let to = self.sections.get(i + 1).map_or(end, |s| s.1);
            if *start < to {
                sections.push(Section {
                    label: label.clone(),
                    range: *start..to,
                });
            }
        }
        Text {
            text: self.text,
            truncated: self.truncated,
            links: self.links,
            sections,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_sections_and_links() {
        let mut o = Out::new(1000);
        o.section("sheet \"A\"");
        o.push("one ");
        o.push("two\nthree\r\n");
        o.begin_link("https://example.com/x");
        o.push("here");
        o.end_link();
        o.newline();
        o.begin_link("https://example.com/");
        o.push("https://example.com/");
        o.end_link();
        o.line("");
        o.section("empty");
        o.section("slide 2");
        o.line("end");
        let t = o.finish();
        assert_eq!(
            t.text,
            "one two\nthree\nhere (https://example.com/x)\nhttps://example.com/\nend\n"
        );
        assert_eq!(
            t.links,
            [("here".to_string(), "https://example.com/x".to_string())]
        );
        let labels: Vec<_> = t.sections.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(labels, ["sheet \"A\"", "slide 2"]);
        assert_eq!(&t.text[t.sections[1].range.clone()], "end\n");
        assert!(!t.truncated);
    }

    #[test]
    fn the_cap_cuts_the_text_and_says_so() {
        let mut o = Out::new(10);
        o.line("abcdef");
        o.line("ghijkl");
        o.line("more");
        assert!(o.full());
        let t = o.finish();
        assert!(t.text.len() <= 10);
        assert!(t.truncated);
    }

    #[test]
    fn control_characters_are_spaces_and_a_mailto_label_is_its_address() {
        let mut o = Out::new(100);
        o.push("a\u{1}b");
        o.newline();
        o.begin_link("mailto:x@y.test");
        o.push("x@y.test");
        o.end_link();
        let t = o.finish();
        assert_eq!(t.text, "a b\nx@y.test\n");
        assert!(t.links.is_empty());
    }
}
