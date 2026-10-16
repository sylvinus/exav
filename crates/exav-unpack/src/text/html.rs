//! HTML into its text, through html5gum's tokenizer alone: its states, entities
//! and quirks are the specification's, no tree is built, and tokens are pulled
//! one at a time.
//!
//! What this adds is the policy: left out are comments, `script`, `style`,
//! `template` and `iframe` (code, markup and content nobody reads as text);
//! kept is every text node, including a `noscript` and what a CSS rule would
//! hide (a reader of the source cannot tell), an image's `alt`, and each
//! link's target after its label. Blocks, rows and breaks end the line.

use html5gum::{HtmlString, StartTag, State as Lex, Token, Tokenizer};

use super::Out;

/// Elements whose start and end end the line.
const BLOCKS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "body",
    "br",
    "caption",
    "center",
    "dd",
    "details",
    "dialog",
    "dir",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "html",
    "legend",
    "li",
    "main",
    "menu",
    "nav",
    "noscript",
    "ol",
    "optgroup",
    "option",
    "p",
    "pre",
    "section",
    "select",
    "summary",
    "table",
    "tbody",
    "textarea",
    "tfoot",
    "thead",
    "title",
    "tr",
    "ul",
];

/// Elements whose content is skipped to their end tag.
const SKIPPED: &[&str] = &[
    "script", "style", "template", "iframe", "noembed", "noframes", "xmp",
];

struct State<'a> {
    out: &'a mut Out,
    /// The element being skipped.
    skipping: Option<String>,
    /// The link being read: where its label starts in the text, and its target.
    anchor: Option<(usize, String)>,
}

pub(super) fn read(src: &str, out: &mut Out) {
    let mut st = State {
        out,
        skipping: None,
        anchor: None,
    };
    let mut tok = Tokenizer::new(src);
    while let Some(Ok(token)) = tok.next() {
        match token {
            Token::String(text) => {
                if st.skipping.is_none() {
                    st.out.text(&String::from_utf8_lossy(&text.value));
                }
            }
            Token::StartTag(tag) => {
                if let Some(state) = st.start(&tag) {
                    tok.set_state(state);
                }
            }
            Token::EndTag(tag) => st.end(&lower(&tag.name)),
            _ => {}
        }
        if st.out.full() {
            return;
        }
    }
    st.close_anchor();
}

fn lower(name: &HtmlString) -> String {
    String::from_utf8_lossy(name).into_owned()
}

impl State<'_> {
    fn close_anchor(&mut self) {
        if let Some((from, href)) = self.anchor.take() {
            self.out.target(from, &href);
        }
    }

    fn end(&mut self, name: &str) {
        if self.skipping.as_deref() == Some(name) {
            self.skipping = None;
        } else if self.skipping.is_none() {
            match name {
                "a" => self.close_anchor(),
                "td" | "th" => self.out.tab(),
                _ if BLOCKS.contains(&name) => self.out.newline(),
                _ => {}
            }
        }
    }

    /// The tokenizer state the element's content is read in, if not the data state.
    fn start(&mut self, tag: &StartTag<()>) -> Option<Lex> {
        let name = &*lower(&tag.name);
        if self.skipping.is_some() {
            return None;
        }
        let attr = |n: &str| {
            tag.attributes
                .iter()
                .find(|(k, _)| k.as_slice() == n.as_bytes())
                .map(|(_, v)| String::from_utf8_lossy(&v.value).into_owned())
        };
        match name {
            "a" => {
                self.close_anchor();
                if let Some(href) = attr("href") {
                    self.anchor = Some((self.out.len(), href));
                }
            }
            "img" | "area" => {
                if let Some(alt) = attr("alt") {
                    self.out.space();
                    self.out.text(&alt);
                    self.out.space();
                }
            }
            "td" | "th" => self.out.tab(),
            _ if BLOCKS.contains(&name) => self.out.newline(),
            _ => {}
        }
        if SKIPPED.contains(&name) {
            self.skipping = Some(name.to_string());
        }
        // The tokenizer reads what is inside as the specification has it.
        match name {
            "script" => Some(Lex::ScriptData),
            "style" | "iframe" | "noembed" | "noframes" | "xmp" => Some(Lex::RawText),
            "textarea" | "title" => Some(Lex::RcData),
            "plaintext" => Some(Lex::PlainText),
            _ => None,
        }
    }
}
