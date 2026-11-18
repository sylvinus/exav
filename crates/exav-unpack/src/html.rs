//! HTML as a stream of tokens, through html5gum's tokenizer alone: its states,
//! entities and quirks are the specification's, and no tree is built. The one
//! HTML reader of the scanner's text view and of the converters that read
//! Word's and Excel's web pages.
//!
//! What this adds is the reading of the tokenizer's output: element and
//! attribute names in lower case, the content of `script`, `style`, `title`,
//! `textarea`, `iframe`, `noembed`, `noframes` and `xmp` read as the
//! specification reads it (text up to the end tag), and the text of a run of
//! characters in one token. What a reader does with an element is its own
//! policy.
//!
//! [`decode`] is the other half: the bytes of a page as text, in the encoding
//! its byte order mark or `<meta>` names.

use html5gum::{HtmlString, State, StringReader, Token as Gum, Tokenizer};
use std::borrow::Cow;

/// Attributes kept of one tag.
pub const MAX_ATTRS: usize = 256;

#[derive(Debug, PartialEq)]
pub enum Token {
    Start {
        name: String,
        attrs: Vec<(String, String)>,
        /// Written `<name ... />`.
        closed: bool,
    },
    End(String),
    Text(String),
    Comment(String),
}

impl Token {
    /// What the token takes in memory: its own size and its strings'.
    pub fn size(&self) -> u64 {
        const ALLOC: u64 = 16;
        let heap = match self {
            Token::Start { name, attrs, .. } => {
                name.len() as u64
                    + ALLOC
                    + attrs.capacity() as u64 * std::mem::size_of::<(String, String)>() as u64
                    + attrs
                        .iter()
                        .map(|(k, v)| (k.len() + v.len()) as u64 + 2 * ALLOC)
                        .sum::<u64>()
            }
            Token::End(s) | Token::Text(s) | Token::Comment(s) => s.len() as u64 + ALLOC,
        };
        std::mem::size_of::<Token>() as u64 + heap
    }
}

/// The tokens of `src`, one at a time.
pub fn tokens(src: &str) -> Tokens<'_> {
    Tokens {
        gum: Tokenizer::new(src),
        ahead: None,
    }
}

pub struct Tokens<'a> {
    gum: Tokenizer<StringReader<'a>>,
    /// A token read past the end of a text.
    ahead: Option<Token>,
}

fn lower(b: &HtmlString) -> String {
    String::from_utf8_lossy(b).to_ascii_lowercase()
}

fn text(b: &HtmlString) -> String {
    String::from_utf8_lossy(b).into_owned()
}

impl Tokens<'_> {
    /// The next token as html5gum has it, converted.
    fn one(&mut self) -> Option<Token> {
        loop {
            match self.gum.next()?.ok()? {
                Gum::String(s) => return Some(Token::Text(text(&s.value))),
                Gum::Comment(c) => return Some(Token::Comment(text(&c.value))),
                Gum::EndTag(t) => return Some(Token::End(lower(&t.name))),
                Gum::StartTag(t) => {
                    let name = lower(&t.name);
                    // The tokenizer reads what is inside as the specification has it.
                    match name.as_str() {
                        "script" => self.gum.set_state(State::ScriptData),
                        "style" | "iframe" | "noembed" | "noframes" | "xmp" => {
                            self.gum.set_state(State::RawText)
                        }
                        "textarea" | "title" => self.gum.set_state(State::RcData),
                        "plaintext" => self.gum.set_state(State::PlainText),
                        _ => {}
                    }
                    let attrs = t
                        .attributes
                        .iter()
                        .take(MAX_ATTRS)
                        .map(|(k, v)| (lower(k), text(&v.value)))
                        .collect();
                    return Some(Token::Start {
                        name,
                        attrs,
                        closed: t.self_closing,
                    });
                }
                Gum::Doctype(_) | Gum::Error(_) => {}
            }
        }
    }
}

impl Iterator for Tokens<'_> {
    type Item = Token;

    fn next(&mut self) -> Option<Token> {
        let first = match self.ahead.take() {
            Some(t) => t,
            None => self.one()?,
        };
        let Token::Text(mut joined) = first else {
            return Some(first);
        };
        loop {
            match self.one() {
                Some(Token::Text(more)) => joined.push_str(&more),
                other => {
                    self.ahead = other;
                    return Some(Token::Text(joined));
                }
            }
        }
    }
}

/// The tokens of `src` did not fit what the caller allows.
#[derive(Debug, PartialEq, Eq)]
pub struct TooLarge;

/// All the tokens of `src`. `charge` is told what each takes in memory as it
/// is made, and answers whether the caller allows it: a page of `<a>` takes
/// many times its size.
pub fn read(src: &str, charge: &mut dyn FnMut(u64) -> bool) -> Result<Vec<Token>, TooLarge> {
    let mut out = Vec::new();
    for t in tokens(src) {
        if !charge(t.size()) {
            return Err(TooLarge);
        }
        out.push(t);
    }
    Ok(out)
}

/// The text of `s` with its character references resolved, as the tokenizer
/// resolves them; markup in `s` is dropped.
pub fn unescape(s: &str) -> String {
    tokens(s)
        .filter_map(|t| match t {
            Token::Text(t) => Some(t),
            _ => None,
        })
        .collect()
}

/// The tokens of a page Office wrote, without what it writes for browsers:
/// the content of a downlevel-revealed conditional (`<![if !vml]> ... <![endif]>`,
/// and the ones that name `support`) is not what Office reads, and the markers
/// go. They are comments to the tokenizer.
pub fn without_downlevel(tokens: Vec<Token>) -> Vec<Token> {
    // `Some(Some(hide))` opens a conditional, `Some(None)` ends one.
    let marker = |t: &Token| match t {
        Token::Comment(c) => {
            let c = c.trim().to_ascii_lowercase();
            if c == "[endif]" {
                Some(None)
            } else if c.starts_with("[if") && c.ends_with(']') && !c.contains('>') {
                Some(Some(c.contains('!') || c.contains("support")))
            } else {
                None
            }
        }
        _ => None,
    };
    let mut out = Vec::with_capacity(tokens.len());
    // For each conditional open, whether it hides its content.
    let mut open: Vec<bool> = vec![];
    for t in tokens {
        match marker(&t) {
            Some(Some(hide)) => open.push(hide),
            Some(None) => {
                open.pop();
            }
            None if open.iter().any(|&h| h) => {}
            None => out.push(t),
        }
    }
    out
}

/// The value of the attribute `key` of a start tag.
pub fn attr<'a>(attrs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attrs.iter().find(|a| a.0 == key).map(|a| a.1.as_str())
}

/// How far into a page its encoding is looked for.
const HEAD: usize = 4096;

/// UTF-16 by its byte order mark, or by the `<` of a page without one.
fn utf16(b: &[u8]) -> Option<&'static encoding_rs::Encoding> {
    match b {
        [0xFF, 0xFE, ..] | [b'<', 0, b'?' | b'!' | b'h' | b'H', 0, ..] => {
            Some(encoding_rs::UTF_16LE)
        }
        [0xFE, 0xFF, ..] | [0, b'<', 0, b'?' | b'!' | b'h' | b'H', ..] => {
            Some(encoding_rs::UTF_16BE)
        }
        _ => None,
    }
}

/// The value of `name="..."` (or `'...'`, or bare) in `head`, any case.
fn attr_value(head: &str, name: &str) -> Option<String> {
    let lower = head.to_ascii_lowercase();
    let mut from = 0;
    while let Some(p) = lower[from..].find(name) {
        let mut i = from + p + name.len();
        from = i;
        let b = lower.as_bytes();
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        if b.get(i) != Some(&b'=') {
            continue;
        }
        i += 1;
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        let quote = b.get(i).copied().filter(|q| matches!(q, b'"' | b'\''));
        if quote.is_some() {
            i += 1;
        }
        let start = i;
        while i < b.len() && !matches!(b[i], b'"' | b'\'' | b' ' | b'>' | b';' | b'/') {
            i += 1;
        }
        if i > start {
            return Some(lower[start..i].to_string());
        }
    }
    None
}

/// How [`decode`] reads a page: `b[start..end]` in `encoding`, with no
/// byte-order mark handling (a WHATWG decoder with `ignoreBOM`, such as a
/// browser's `TextDecoder`, given its name).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    pub encoding: &'static encoding_rs::Encoding,
    /// After the byte-order mark.
    pub start: usize,
    pub end: usize,
}

/// The [`Reading`] of a page: its byte order mark's encoding, else the
/// charset a `<meta>` in its first kilobytes names, else UTF-8 when it is
/// valid UTF-8, else Windows-1252, in which no byte is invalid.
pub fn reading(b: &[u8]) -> Reading {
    if let Some(encoding) = utf16(b) {
        let marked = b.starts_with(&[0xFF, 0xFE]) || b.starts_with(&[0xFE, 0xFF]);
        return Reading {
            encoding,
            start: 2 * usize::from(marked),
            // UTF-16 cut after an odd byte: the half unit dropped.
            end: b.len() - b.len() % 2,
        };
    }
    if b.starts_with(b"\xEF\xBB\xBF") {
        return Reading {
            encoding: encoding_rs::UTF_8,
            start: 3,
            end: b.len(),
        };
    }
    let head = String::from_utf8_lossy(&b[..b.len().min(HEAD)]);
    let named =
        attr_value(&head, "charset").and_then(|l| encoding_rs::Encoding::for_label(l.as_bytes()));
    let encoding = match named {
        // A page declaring UTF-16 that is not is read as ASCII-compatible.
        Some(e) if e == encoding_rs::UTF_16LE || e == encoding_rs::UTF_16BE => encoding_rs::UTF_8,
        Some(e) => e,
        None if std::str::from_utf8(b).is_ok() => encoding_rs::UTF_8,
        None => encoding_rs::WINDOWS_1252,
    };
    Reading {
        encoding,
        start: 0,
        end: b.len(),
    }
}

/// A page as text, as [`reading`] says.
pub fn decode(b: &[u8]) -> Cow<'_, str> {
    let r = reading(b);
    let body = &b[r.start..r.end];
    // The same text as encoding_rs's UTF-8 decoder, borrowed when valid.
    if r.encoding == encoding_rs::UTF_8 {
        return String::from_utf8_lossy(body);
    }
    r.encoding.decode_without_bom_handling(body).0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(src: &str) -> Vec<Token> {
        tokens(src).collect()
    }

    fn start(name: &str, attrs: &[(&str, &str)], closed: bool) -> Token {
        Token::Start {
            name: name.into(),
            attrs: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            closed,
        }
    }

    #[test]
    fn names_are_lower_case_and_text_is_one_token() {
        assert_eq!(
            all("<TD Class=xl65 X:Num='3'>a &amp; b &lt;c</TD><br/>"),
            [
                start("td", &[("class", "xl65"), ("x:num", "3")], false),
                Token::Text("a & b <c".into()),
                Token::End("td".into()),
                start("br", &[], true),
            ]
        );
    }

    #[test]
    fn the_content_of_a_raw_element_is_text_up_to_its_end_tag() {
        assert_eq!(
            all(
                "<style>td { x: 1 } <b></style><script>if (a<b) {}</script><title>A &amp; B</title>"
            ),
            [
                start("style", &[], false),
                Token::Text("td { x: 1 } <b>".into()),
                Token::End("style".into()),
                start("script", &[], false),
                Token::Text("if (a<b) {}".into()),
                Token::End("script".into()),
                start("title", &[], false),
                Token::Text("A & B".into()),
                Token::End("title".into()),
            ]
        );
    }

    #[test]
    fn comments_and_downlevel_conditionals_are_comments() {
        let t = all("<!--[if gte mso 9]><xml/><![endif]--><![if !vml]>x<![endif]>");
        assert_eq!(
            t[0],
            Token::Comment("[if gte mso 9]><xml/><![endif]".into())
        );
        assert_eq!(t[1], Token::Comment("[if !vml]".into()));
        assert_eq!(t[2], Token::Text("x".into()));
        assert_eq!(t[3], Token::Comment("[endif]".into()));
    }

    #[test]
    fn what_office_writes_for_browsers_is_left_out() {
        let t = without_downlevel(all(
            "a<![if !vml]>b<![if x]>c<![endif]>d<![endif]>e<![if gte x]>f<![endif]>\
             <!--[if gte mso 9]><xml/><![endif]-->",
        ));
        assert_eq!(
            t,
            [
                Token::Text("a".into()),
                Token::Text("e".into()),
                Token::Text("f".into()),
                Token::Comment("[if gte mso 9]><xml/><![endif]".into()),
            ]
        );
    }

    #[test]
    fn a_page_of_empty_elements_is_charged_for_what_it_builds() {
        let page = "<a>".repeat(1000);
        let mut told = 0u64;
        let r = read(&page, &mut |n| {
            told += n;
            true
        });
        assert_eq!(r.unwrap().len(), 1000);
        assert!(told > 1000 * 3 * 20, "told {told} for 3000 bytes");
        assert_eq!(read(&page, &mut |_| false), Err(TooLarge));
    }

    /// What the viewer reads a page's source in, without decoding it here.
    #[test]
    fn the_reading_of_a_page_names_the_charset_of_its_meta() {
        let page = b"<meta charset=\"Shift_JIS\"><p>\x93\xfa\x96\x7b</p>";
        let r = reading(page);
        assert_eq!(
            (r.encoding.name(), r.start, r.end),
            ("Shift_JIS", 0, page.len())
        );
        assert_eq!(
            decode(page),
            "<meta charset=\"Shift_JIS\"><p>\u{65e5}\u{672c}</p>"
        );
    }

    #[test]
    fn the_encoding_a_page_names_is_the_one_it_is_read_in() {
        assert_eq!(
            decode(b"<meta charset=windows-1251><td>\xC0"),
            "<meta charset=windows-1251><td>\u{410}"
        );
        assert_eq!(
            decode(b"<meta http-equiv=Content-Type content=\"text/html; charset=iso-8859-1\">\xE9"),
            "<meta http-equiv=Content-Type content=\"text/html; charset=iso-8859-1\">\u{E9}"
        );
        assert_eq!(decode("<td>é".as_bytes()), "<td>é");
        assert_eq!(decode(b"<td>\xE9"), "<td>\u{E9}");
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("<td>é".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(decode(&utf16), "<td>é");
    }
}
