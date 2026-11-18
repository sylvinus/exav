//! An XML pretty printer that only reads tokens: no DOM, no entity is
//! expanded (a document's `&xxe;` or nested entities are shown as written),
//! no DTD or stylesheet is fetched or even followed. Used for display, so
//! markup is re-indented where that adds no text, and text is trimmed.
//!
//! This is not the reader that extracts the text of Office parts
//! (`exav_unpack::text`): that one drops markup and whitespace, this one
//! shows them, and a construct that never ends is shown as it is.

use super::{Formatted, LineBuilder, class, indent, split_lines};

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Text,
    Comment,
    Cdata,
    Pi,
    Decl,
    Open,
    Empty,
    Close,
    Bad,
}

#[derive(Clone, Copy)]
struct Token {
    kind: Kind,
    end: usize,
}

/// A text longer than this (in UTF-16 units, as the page counts) is not put
/// on its element's line.
const INLINE_TEXT: usize = 200;

const fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

/// A character a name may start with.
fn is_name_start(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == ':' || c as u32 >= 0xc0)
}

/// `s` as JavaScript's `String.prototype.trim` cuts it: U+FEFF is white space
/// there and U+0085 is not.
fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}')
}

/// Whether `s` is at most `max` UTF-16 units long.
fn fits_utf16(s: &str, max: usize) -> bool {
    let mut n = 0;
    for c in s.chars() {
        n += c.len_utf16();
        if n > max {
            return false;
        }
    }
    true
}

/// The token at `at`. A construct with no end becomes a `Bad` token that takes
/// the rest of the text, so that no construct is searched for twice.
fn token(s: &str, at: usize) -> Token {
    let b = s.as_bytes();
    let n = b.len();
    if b.get(at) != Some(&b'<') {
        let end = s[at..].find('<').map_or(n, |p| at + p);
        return tok(Kind::Text, end);
    }
    let until = |kind: Kind, mark: &str, from: usize| match s[from..].find(mark) {
        Some(p) => tok(kind, from + p + mark.len()),
        None => tok(Kind::Bad, n),
    };
    if s[at..].starts_with("<!--") {
        return until(Kind::Comment, "-->", at + 4);
    }
    if s[at..].starts_with("<![CDATA[") {
        return until(Kind::Cdata, "]]>", at + 9);
    }
    if b.get(at + 1) == Some(&b'?') {
        return until(Kind::Pi, "?>", at + 2);
    }
    if b.get(at + 1) == Some(&b'!') {
        // A declaration; its internal subset sits in brackets and may hold `>`.
        let mut quote = 0u8;
        let mut brackets = 0usize;
        for (j, &ch) in b.iter().enumerate().skip(at + 2) {
            if quote != 0 {
                if ch == quote {
                    quote = 0;
                }
            } else if ch == b'"' || ch == b'\'' {
                quote = ch;
            } else if ch == b'[' {
                brackets += 1;
            } else if ch == b']' {
                brackets = brackets.saturating_sub(1);
            } else if ch == b'>' && brackets == 0 {
                return tok(Kind::Decl, j + 1);
            }
        }
        return tok(Kind::Bad, n);
    }
    let closing = b.get(at + 1) == Some(&b'/');
    let first = at + if closing { 2 } else { 1 };
    if !is_name_start(s[first..].chars().next()) {
        return tok(Kind::Text, at + 1);
    }
    let mut quote = 0u8;
    for (j, &ch) in b.iter().enumerate().skip(at + 2) {
        if quote != 0 {
            if ch == quote {
                quote = 0;
            }
        } else if ch == b'"' || ch == b'\'' {
            quote = ch;
        } else if ch == b'>' {
            let kind = if closing {
                Kind::Close
            } else if b[j - 1] == b'/' {
                Kind::Empty
            } else {
                Kind::Open
            };
            return tok(kind, j + 1);
        }
    }
    tok(Kind::Bad, n)
}

const fn tok(kind: Kind, end: usize) -> Token {
    Token { kind, end }
}

/// The name in the tag at `at`.
fn name_of(s: &str, at: usize) -> &str {
    let b = s.as_bytes();
    let start = at + if b.get(at + 1) == Some(&b'/') { 2 } else { 1 };
    let mut j = start;
    while j < b.len() && !is_space(b[j]) && b[j] != b'/' && b[j] != b'>' {
        j += 1;
    }
    &s[start..j]
}

/// Writes the tag in `s[at..end]` with its parts coloured.
fn write_tag<'a>(out: &mut LineBuilder<'a>, s: &'a str, at: usize, end: usize) {
    let b = s.as_bytes();
    let closing = b.get(at + 1) == Some(&b'/');
    let name = name_of(s, at);
    out.add(if closing { "</" } else { "<" }, None);
    out.add(name, Some(class::TAG));
    let mut j = at + if closing { 2 } else { 1 } + name.len();
    let stop = end - 1;
    while j < stop {
        if is_space(b[j]) {
            j += 1;
            continue;
        }
        if b[j] == b'/' {
            break;
        }
        let mut k = j;
        while k < stop && !is_space(b[k]) && b[k] != b'=' && b[k] != b'/' {
            k += 1;
        }
        if k == j {
            k = j + 1;
        }
        out.add(" ", None);
        out.add(&s[j..k], Some(class::ATTR));
        j = k;
        while j < stop && is_space(b[j]) {
            j += 1;
        }
        if b[j] != b'=' {
            continue;
        }
        out.add("=", None);
        j += 1;
        while j < stop && is_space(b[j]) {
            j += 1;
        }
        let q = b[j];
        let mut v = j;
        if q == b'"' || q == b'\'' {
            v = match s[j + 1..].find(q as char) {
                Some(p) if j + 1 + p <= stop => j + 1 + p + 1,
                _ => stop,
            };
        } else {
            while v < stop && !is_space(b[v]) {
                v += 1;
            }
        }
        out.add(&s[j..v], Some(class::STR));
        j = v.max(j + 1);
    }
    out.add(
        if b[end - 2] == b'/' && !closing {
            "/>"
        } else {
            ">"
        },
        None,
    );
}

/// The lines of `text` indented, at most `max_lines` of them, or `None` when
/// it does not start with markup. `well_formed` says when every construct
/// ended and every tag was closed by its own.
pub fn format_xml(text: &str, max_lines: usize) -> Option<Formatted<'_>> {
    let b = text.as_bytes();
    let n = b.len();
    let mut pos = 0;
    while pos < n && is_space(b[pos]) {
        pos += 1;
    }
    if b.get(pos) != Some(&b'<') {
        return None;
    }

    let mut out = LineBuilder::new(max_lines);
    let mut open: Vec<&str> = Vec::new();
    let mut well_formed = true;
    let mut depth = 0usize;

    /// Raw text that may span lines, the first at the indent.
    fn raw<'a>(out: &mut LineBuilder<'a>, s: &'a str, cls: Option<&'static str>, depth: usize) {
        let (lines, _) = split_lines(s, out.max);
        for (k, l) in lines.into_iter().enumerate() {
            if k == 0 {
                out.add(indent(depth), None);
            }
            out.add(l, cls);
            out.end();
        }
    }

    while pos < n && !out.full {
        let t = token(text, pos);
        let src = &text[pos..t.end];
        match t.kind {
            Kind::Text => {
                let body = js_trim(src);
                if !body.is_empty() {
                    for l in split_lines(body, out.max).0 {
                        let line = js_trim(l);
                        if line.is_empty() {
                            continue;
                        }
                        out.add(indent(depth), None);
                        out.add(line, None);
                        out.end();
                    }
                }
            }
            Kind::Comment => raw(&mut out, src, Some(class::COMMENT), depth),
            Kind::Cdata => raw(&mut out, src, Some(class::STR), depth),
            Kind::Pi | Kind::Decl => raw(&mut out, src, Some(class::META), depth),
            Kind::Bad => {
                well_formed = false;
                raw(&mut out, src, None, depth);
            }
            Kind::Empty => {
                out.add(indent(depth), None);
                write_tag(&mut out, text, pos, t.end);
                out.end();
            }
            Kind::Close => {
                let name = name_of(text, pos);
                if open.pop() != Some(name) {
                    well_formed = false;
                }
                depth = depth.saturating_sub(1);
                out.add(indent(depth), None);
                write_tag(&mut out, text, pos, t.end);
                out.end();
            }
            Kind::Open => {
                let name = name_of(text, pos);
                // `<a>text</a>` and `<a></a>` stay on one line.
                let a = token(text, t.end);
                let body = if a.kind == Kind::Text {
                    &text[t.end..a.end]
                } else {
                    ""
                };
                let close_at = if a.kind == Kind::Text { a.end } else { t.end };
                let c = token(text, close_at);
                if matches!(a.kind, Kind::Text | Kind::Close)
                    && c.kind == Kind::Close
                    && name_of(text, close_at) == name
                    && fits_utf16(body, INLINE_TEXT)
                    && !js_trim(body).contains(['\r', '\n'])
                {
                    out.add(indent(depth), None);
                    write_tag(&mut out, text, pos, t.end);
                    out.add(js_trim(body), None);
                    write_tag(&mut out, text, close_at, c.end);
                    out.end();
                    pos = c.end;
                    continue;
                }
                out.add(indent(depth), None);
                write_tag(&mut out, text, pos, t.end);
                out.end();
                open.push(name);
                depth += 1;
            }
        }
        pos = t.end;
    }
    if !open.is_empty() {
        well_formed = false;
    }
    out.finish();
    Some(Formatted {
        lines: out.lines,
        more: out.full,
        well_formed,
    })
}

#[cfg(test)]
mod tests {
    use super::super::Line;
    use super::*;
    use std::time::Instant;

    fn show(text: &str, max: usize) -> Option<String> {
        format_xml(text, max).map(|f| {
            f.lines
                .iter()
                .map(|l| l.text())
                .collect::<Vec<_>>()
                .join("\n")
        })
    }

    fn show_all(text: &str) -> String {
        show(text, 50_000).unwrap()
    }

    #[test]
    fn indents_elements_and_keeps_text_on_its_elements_line() {
        let out = show_all(
            r#"<?xml version="1.0"?><feed><entry id="1" lang='fr'><title>Hello</title><empty/><e></e></entry><!-- note --></feed>"#,
        );
        assert_eq!(
            out,
            [
                r#"<?xml version="1.0"?>"#,
                "<feed>",
                r#"  <entry id="1" lang='fr'>"#,
                "    <title>Hello</title>",
                "    <empty/>",
                "    <e></e>",
                "  </entry>",
                "  <!-- note -->",
                "</feed>",
            ]
            .join("\n")
        );
    }

    #[test]
    fn puts_long_or_multi_line_text_on_lines_of_its_own() {
        assert_eq!(
            show_all("<a>one\n   two</a>"),
            ["<a>", "  one", "  two", "</a>"].join("\n")
        );
        let long = "x".repeat(300);
        assert_eq!(
            show_all(&format!("<a>{long}</a>")),
            ["<a>".to_owned(), format!("  {long}"), "</a>".to_owned()].join("\n")
        );
    }

    #[test]
    fn shows_cdata_comments_processing_instructions_and_a_doctype_as_written() {
        assert_eq!(
            show_all(
                r#"<!DOCTYPE note [<!ENTITY a "x>y">]><note><![CDATA[<b>&a;</b>]]><?pi do it?></note>"#
            ),
            [
                r#"<!DOCTYPE note [<!ENTITY a "x>y">]>"#,
                "<note>",
                "  <![CDATA[<b>&a;</b>]]>",
                "  <?pi do it?>",
                "</note>",
            ]
            .join("\n")
        );
    }

    #[test]
    fn never_expands_an_entity_or_follows_an_external_one() {
        let out = show_all(
            r#"<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd"><!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><r>&xxe; &lol2; &#60;script&#62;</r>"#,
        );
        assert!(out.contains(r#"<!ENTITY xxe SYSTEM "file:///etc/passwd">"#));
        assert!(out.contains("&xxe; &lol2; &#60;script&#62;"));
        assert!(!out.contains("<script>"));
        assert!(!out.contains("lollol"));
    }

    #[test]
    fn keeps_attribute_values_with_a_greater_than_in_them_inside_their_tag() {
        assert_eq!(
            show_all(r#"<a href="x>y" b='1>2'>t</a>"#),
            r#"<a href="x>y" b='1>2'>t</a>"#
        );
    }

    #[test]
    fn is_not_xml_when_it_does_not_start_with_markup() {
        for s in ["hello <b>world</b>", "", "   \n", "{}"] {
            assert!(format_xml(s, 50_000).is_none(), "{s:?}");
        }
    }

    #[test]
    fn says_when_the_markup_is_not_well_formed_and_still_shows_it_all() {
        let cases = [
            ("<a><b></b></a>", true),
            ("<a><b></a></b>", false),
            ("<a><b>", false),
            ("<a></a></a>", false),
            ("<a><!-- never closed", false),
            ("<a x='1", false),
            ("<a>1 < 2</a>", true),
        ];
        for (src, ok) in cases {
            let f = format_xml(src, 50_000).unwrap();
            assert_eq!(f.well_formed, ok, "{src}");
            // Everything typed is somewhere in the output, in order.
            let flat: String = f.lines.iter().map(Line::text).collect::<String>();
            let squeeze = |s: &str| s.split_whitespace().collect::<String>();
            assert_eq!(squeeze(&flat), squeeze(src), "{src}");
        }
    }

    #[test]
    fn marks_tags_attributes_and_values_for_colour() {
        let f = format_xml(r#"<a k="v">t</a>"#, 100).unwrap();
        let of = |cls: &str| -> Vec<&str> {
            f.lines
                .iter()
                .flat_map(|l| match l {
                    Line::Segs(s) => s.clone(),
                    _ => vec![],
                })
                .filter(|s| s.class == Some(cls))
                .map(|s| s.text)
                .collect()
        };
        assert_eq!(of(class::TAG), ["a", "a"]);
        assert_eq!(of(class::ATTR), ["k"]);
        assert_eq!(of(class::STR), [r#""v""#]);
    }

    #[test]
    fn stops_at_the_line_cap() {
        let text = format!("<r>{}</r>", "<i>1</i>".repeat(1000));
        let f = format_xml(&text, 10).unwrap();
        assert_eq!(f.lines.len(), 10);
        assert!(f.more);
    }

    #[test]
    fn limits_indentation_however_deep_the_document_nests() {
        let text = format!("{}x{}", "<a>".repeat(5000), "</a>".repeat(5000));
        let out = show(&text, 6000).unwrap();
        let widest = out
            .lines()
            .map(|l| l.len() - l.trim_start().len())
            .max()
            .unwrap();
        assert!(widest <= 200, "{widest}");
    }

    #[test]
    fn trims_text_as_a_browser_does() {
        // U+FEFF is white space for JavaScript and U+0085 is not; the page's
        // output had them so.
        assert_eq!(show_all("<a>\u{feff} x \u{feff}</a>"), "<a>x</a>");
        assert_eq!(show_all("<a>\u{85}x</a>"), "<a>\u{85}x</a>");
    }

    #[test]
    fn counts_the_length_of_a_text_in_utf16_units() {
        // 101 astral characters are 202 units: over the limit of 200, on lines of their own.
        let wide = "\u{1f600}".repeat(101);
        assert_eq!(
            show_all(&format!("<a>{wide}</a>")),
            ["<a>".to_owned(), format!("  {wide}"), "</a>".to_owned()].join("\n")
        );
        let ok = "\u{1f600}".repeat(100);
        assert_eq!(show_all(&format!("<a>{ok}</a>")), format!("<a>{ok}</a>"));
    }

    #[test]
    fn is_quick_on_hostile_input() {
        let t = Instant::now();
        for s in [
            "<".repeat(1_000_000),
            "<a ".repeat(500_000),
            "<a>".repeat(600_000),
            "<!--".repeat(500_000),
            "<![CDATA[".repeat(200_000),
            "<a b=\"".repeat(300_000),
            "<?".repeat(1_000_000),
            "<!DOCTYPE [".repeat(200_000),
            "<a>x</b>".repeat(250_000),
            "<a></a>".repeat(250_000),
            "<</>".repeat(500_000),
        ] {
            format_xml(&s, 50_000);
        }
        // The page's test allowed 6 s in a JavaScript engine; this one runs unoptimised.
        assert!(t.elapsed().as_secs() < 30, "{:?}", t.elapsed());
    }
}
