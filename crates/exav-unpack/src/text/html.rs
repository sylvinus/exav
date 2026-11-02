//! HTML into its text, from the tokens of `crate::html`, pulled one at a time.
//!
//! What this adds is the policy: left out are comments, `script`, `style`,
//! `template` and `iframe` (code, markup and content nobody reads as text);
//! kept is every text node, including a `noscript` and what a CSS rule would
//! hide (a reader of the source cannot tell), an image's `alt`, and each
//! link's target after its label. Blocks, rows and breaks end the line.

use crate::html::{Token, attr, tokens};

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
    for token in tokens(src) {
        match token {
            Token::Text(text) => {
                if st.skipping.is_none() {
                    st.out.text(&text);
                }
            }
            Token::Start { name, attrs, .. } => st.start(&name, &attrs),
            Token::End(name) => st.end(&name),
            Token::Comment(_) => {}
        }
        if st.out.full() {
            return;
        }
    }
    st.close_anchor();
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

    fn start(&mut self, name: &str, attrs: &[(String, String)]) {
        if self.skipping.is_some() {
            return;
        }
        match name {
            "a" => {
                self.close_anchor();
                if let Some(href) = attr(attrs, "href") {
                    self.anchor = Some((self.out.len(), href.to_string()));
                }
            }
            "img" | "area" => {
                if let Some(alt) = attr(attrs, "alt") {
                    self.out.space();
                    self.out.text(alt);
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
    }
}
