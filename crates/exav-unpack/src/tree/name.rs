//! Names of the nodes of a walk, and the path from the root to one.

use std::borrow::Cow;

/// The most characters of a name that [`Name::shown`] keeps.
const SHOWN_CHARS: usize = 200;

/// How a name came to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKind {
    /// As the container wrote it.
    Stored,
    /// The one member of a compressor: `gzip-content`, `bzip2-content`.
    Stream,
    /// A report, not a file: `<ntfs-volume>`, or the name of an excluded format.
    Report,
    /// Made by a reader: `pdf-obj-3-0`, `thumbnail.bmp`.
    Generated,
    /// Made by the walk for a payload found in an object:
    /// `base64-payload-1`, `embedded-asset-1`.
    Derived,
}

/// The name of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name<'a> {
    /// What the container or the reader called it, unchanged.
    pub raw: &'a str,
    pub kind: NameKind,
}

impl<'a> Name<'a> {
    pub fn new(raw: &'a str, kind: NameKind) -> Self {
        Name { raw, kind }
    }

    /// The name as a container wrote it.
    pub fn stored(raw: &'a str) -> Self {
        Name::new(raw, NameKind::Stored)
    }

    /// The name for a report or a location: the control characters (the C0
    /// and C1 ranges and DEL), the bidirectional controls (U+061C, U+200E,
    /// U+200F, U+202A to U+202E, U+2066 to U+2069) and the line and paragraph
    /// separators (U+2028, U+2029) become `_`, and at most 200 characters are
    /// kept, so a hostile archive cannot add a line or an escape sequence to
    /// an output, make a name read in another order than it is stored, or fill
    /// the output. Borrowed when nothing changes.
    ///
    /// The characters a file system refuses (`<>:"|?*`) are for a file name,
    /// not for display, and pass.
    pub fn shown(&self) -> Cow<'a, str> {
        let clean =
            self.raw.chars().nth(SHOWN_CHARS).is_none() && !self.raw.contains(unsafe_to_show);
        if clean {
            return Cow::Borrowed(self.raw);
        }
        Cow::Owned(
            self.raw
                .chars()
                .map(|c| if unsafe_to_show(c) { '_' } else { c })
                .take(SHOWN_CHARS)
                .collect(),
        )
    }
}

/// A text for an output, such as a reason: the characters [`unsafe_to_show`]
/// finds become `_`. Borrowed when nothing changes.
pub fn shown_text(text: &str) -> Cow<'_, str> {
    if !text.contains(unsafe_to_show) {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.chars()
            .map(|c| if unsafe_to_show(c) { '_' } else { c })
            .collect(),
    )
}

/// A stored name as a reason quotes it: [`Name::shown`].
pub(crate) fn quoted(raw: &str) -> Cow<'_, str> {
    Name::stored(raw).shown()
}

/// Whether a character changes what an output reads as when it is part of a
/// name: it ends a line, moves the cursor, or reorders the text around it.
pub fn unsafe_to_show(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

/// How [`Path::render`] writes a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStyle {
    /// Where a detection is: the shown names below the root joined by `/`,
    /// and nothing for the root itself.
    Located,
    /// The root's label as given, then the shown names below it, joined by `!`.
    Nested,
    /// The shown name of the last node.
    Last,
}

/// The path from the root of a walk to a node: names linked on the stack, so a
/// node costs no allocation until a path is written out.
#[derive(Debug, Clone, Copy)]
pub struct Path<'a> {
    parent: Option<&'a Path<'a>>,
    name: Name<'a>,
}

impl<'a> Path<'a> {
    /// The root of a walk. Its name is a label for the whole object (a file
    /// path, say), not a member of anything.
    pub fn root(name: Name<'a>) -> Self {
        Path { parent: None, name }
    }

    /// A node one level below this one.
    pub fn child<'b>(&'b self, name: Name<'b>) -> Path<'b> {
        Path {
            parent: Some(self),
            name,
        }
    }

    /// The last name of the path.
    pub fn name(&self) -> &Name<'a> {
        &self.name
    }

    /// Levels below the root: 0 for the root.
    pub fn depth(&self) -> usize {
        let mut depth = 0;
        let mut at = self;
        while let Some(parent) = at.parent {
            depth += 1;
            at = parent;
        }
        depth
    }

    /// The names from the root to this node.
    pub fn segments(&self) -> Vec<Name<'a>> {
        let mut out = vec![self.name];
        let mut at = self;
        while let Some(parent) = at.parent {
            out.push(parent.name);
            at = parent;
        }
        out.reverse();
        out
    }

    pub fn render(&self, style: PathStyle) -> String {
        match style {
            PathStyle::Last => self.name.shown().into_owned(),
            PathStyle::Located => {
                let names = self.segments();
                let shown: Vec<_> = names[1..].iter().map(Name::shown).collect();
                shown.join("/")
            }
            PathStyle::Nested => {
                let names = self.segments();
                let mut out = names[0].raw.to_string();
                for name in &names[1..] {
                    out.push('!');
                    out.push_str(&name.shown());
                }
                out
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(raw: &str) -> String {
        Name::stored(raw).shown().into_owned()
    }

    #[test]
    fn shown_replaces_control_characters_and_caps_the_length() {
        let long = "é".repeat(SHOWN_CHARS + 1);
        let at_the_cap = "b".repeat(SHOWN_CHARS);
        let long_with_escape = format!("{at_the_cap}\u{1b}");
        let escape_first = format!("\u{1b}{at_the_cap}");
        let escape_first_shown = format!("_{}", &at_the_cap[1..]);
        // (what the container wrote, what is shown)
        let table: [(&str, &str); 14] = [
            ("dir/file.txt", "dir/file.txt"),
            ("", ""),
            ("naïve \u{4e2d}\u{6587}.txt", "naïve \u{4e2d}\u{6587}.txt"),
            ("a\nb", "a_b"),
            ("a\r\nb\tc", "a__b_c"),
            ("evil\u{1b}[31mred", "evil_[31mred"),
            ("nul\0here", "nul_here"),
            ("del\u{7f}", "del_"),
            ("c1\u{85}\u{9f}", "c1__"),
            // Not control characters to Unicode, but they reorder or end lines.
            ("rtl\u{202e}gpj.exe\u{2028}\u{2066}", "rtl_gpj.exe__"),
            (&at_the_cap, &at_the_cap),
            // Cut by characters, not bytes.
            (&long, &long[..2 * SHOWN_CHARS]),
            (&long_with_escape, &at_the_cap),
            (&escape_first, &escape_first_shown),
        ];
        for (raw, want) in table {
            assert_eq!(shown(raw), want, "{raw:?}");
        }
    }

    /// The set is the one the viewer cleans a name of for display
    /// (`safeFileName`), without what only a file system refuses.
    #[test]
    fn shown_replaces_each_bidirectional_control_and_separator_and_nothing_near_them() {
        let replaced: Vec<char> = ['\u{61c}', '\u{200e}', '\u{200f}', '\u{2028}', '\u{2029}']
            .into_iter()
            .chain('\u{202a}'..='\u{202e}')
            .chain('\u{2066}'..='\u{2069}')
            .collect();
        for c in &replaced {
            assert_eq!(shown(&format!("a{c}b")), "a_b", "U+{:04X}", *c as u32);
        }
        // Their neighbours are ordinary characters: a zero width joiner, the
        // hyphenation point, a no-break space, the isolates' neighbours.
        for c in [
            '\u{61b}', '\u{61d}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{2010}', '\u{2027}',
            '\u{202f}', '\u{2030}', '\u{2065}', '\u{206a}',
        ] {
            let name = format!("a{c}b");
            assert_eq!(shown(&name), name, "U+{:04X}", c as u32);
        }
        // What a file system refuses is for a file name: it shows.
        assert_eq!(shown("a<b>:\"|?*c"), "a<b>:\"|?*c");
    }

    #[test]
    fn a_name_that_needs_no_change_is_not_copied() {
        let raw = "plain.txt";
        assert!(
            matches!(Name::stored(raw).shown(), Cow::Borrowed(s) if s.as_ptr() == raw.as_ptr())
        );
        assert!(matches!(Name::stored("a\nb").shown(), Cow::Owned(_)));
    }

    #[test]
    fn a_path_renders_in_each_style() {
        let root = Path::root(Name::stored("in/outer.zip"));
        let inner = root.child(Name::stored("inner.tar"));
        let leaf = inner.child(Name::new("gzip-content", NameKind::Stream));
        assert_eq!(leaf.render(PathStyle::Located), "inner.tar/gzip-content");
        assert_eq!(
            leaf.render(PathStyle::Nested),
            "in/outer.zip!inner.tar!gzip-content"
        );
        assert_eq!(leaf.render(PathStyle::Last), "gzip-content");
        assert_eq!(inner.render(PathStyle::Located), "inner.tar");
        assert_eq!(inner.render(PathStyle::Nested), "in/outer.zip!inner.tar");
        // The root is not a member: nothing to locate, and its label is its own.
        assert_eq!(root.render(PathStyle::Located), "");
        assert_eq!(root.render(PathStyle::Nested), "in/outer.zip");
        assert_eq!(root.render(PathStyle::Last), "in/outer.zip");
        assert_eq!((root.depth(), inner.depth(), leaf.depth()), (0, 1, 2));
        let names: Vec<_> = leaf.segments().iter().map(|n| n.raw).collect();
        assert_eq!(names, ["in/outer.zip", "inner.tar", "gzip-content"]);
        assert_eq!(leaf.name().kind, NameKind::Stream);
    }

    #[test]
    fn a_member_name_cannot_break_a_rendered_path() {
        let root = Path::root(Name::stored("a.zip"));
        let evil = root.child(Name::stored("x\nfake: OK\u{1b}[0m"));
        for style in [PathStyle::Located, PathStyle::Nested, PathStyle::Last] {
            let out = evil.render(style);
            assert!(!out.contains(['\n', '\u{1b}']), "{style:?}: {out:?}");
        }
        assert_eq!(evil.render(PathStyle::Nested), "a.zip!x_fake: OK_[0m");
    }

    #[test]
    fn each_segment_is_capped_on_its_own() {
        let long = "n".repeat(SHOWN_CHARS + 50);
        let root = Path::root(Name::stored("r"));
        let a = root.child(Name::stored(&long));
        let b = a.child(Name::stored(&long));
        let want = "n".repeat(SHOWN_CHARS);
        assert_eq!(b.render(PathStyle::Located), format!("{want}/{want}"));
    }
}
