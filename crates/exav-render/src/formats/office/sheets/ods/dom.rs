//! A small element tree over quick-xml, with element and attribute names
//! given the usual ODF prefixes whatever prefixes a file declares. Bounded:
//! nesting depth, element count and text are limited.

use crate::formats::office::sheets::error::{Error, Result};
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::NsReader;

#[derive(Debug, Default)]
pub struct Node {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Child>,
}

#[derive(Debug)]
pub enum Child {
    Node(Node),
    Text(String),
}

const NS: &[(&str, &str)] = &[
    ("urn:oasis:names:tc:opendocument:xmlns:office:1.0", "office"),
    ("urn:oasis:names:tc:opendocument:xmlns:style:1.0", "style"),
    ("urn:oasis:names:tc:opendocument:xmlns:text:1.0", "text"),
    ("urn:oasis:names:tc:opendocument:xmlns:table:1.0", "table"),
    ("urn:oasis:names:tc:opendocument:xmlns:drawing:1.0", "draw"),
    (
        "urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0",
        "fo",
    ),
    ("http://www.w3.org/1999/xlink", "xlink"),
    ("http://purl.org/dc/elements/1.1/", "dc"),
    ("urn:oasis:names:tc:opendocument:xmlns:meta:1.0", "meta"),
    (
        "urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0",
        "number",
    ),
    (
        "urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0",
        "svg",
    ),
    ("urn:oasis:names:tc:opendocument:xmlns:chart:1.0", "chart"),
    ("urn:oasis:names:tc:opendocument:xmlns:of:1.2", "of"),
    (
        "urn:org:documentfoundation:names:experimental:calc:xmlns:calcext:1.0",
        "calcext",
    ),
    (
        "urn:org:documentfoundation:names:experimental:office:xmlns:loext:1.0",
        "loext",
    ),
    ("http://openoffice.org/2009/table", "tableooo"),
    ("http://openoffice.org/2004/office", "ooo"),
    ("http://openoffice.org/2004/calc", "oooc"),
    ("urn:oasis:names:tc:opendocument:xmlns:config:1.0", "config"),
    ("urn:oasis:names:tc:opendocument:xmlns:form:1.0", "form"),
    ("http://www.w3.org/1998/Math/MathML", "math"),
    ("urn:oasis:names:tc:opendocument:xmlns:dr3d:1.0", "dr3d"),
    // Numbers '08 and '09.
    ("http://developer.apple.com/namespaces/sf", "sf"),
    ("http://developer.apple.com/namespaces/sfa", "sfa"),
    ("http://developer.apple.com/namespaces/ls", "ls"),
    // Excel 2003 XML Spreadsheet.
    ("urn:schemas-microsoft-com:office:spreadsheet", "ss"),
    ("urn:schemas-microsoft-com:office:excel", "x"),
    ("urn:schemas-microsoft-com:office:office", "o"),
    ("http://www.w3.org/TR/REC-html40", "html"),
];

fn prefix_of(r: &ResolveResult) -> String {
    match r {
        ResolveResult::Bound(ns) => {
            let u = ns.as_ref();
            NS.iter()
                .find(|e| e.0 == u)
                .map(|e| e.1.to_string())
                .unwrap_or_else(|| format!("{{{u}}}"))
        }
        _ => String::new(),
    }
}

fn qualify(p: String, l: &str) -> String {
    if p.is_empty() {
        l.to_owned()
    } else {
        format!("{p}:{l}")
    }
}

/// Bounds of one document.
pub const MAX_DEPTH: usize = 256;
pub const MAX_ELEMENTS: usize = 20_000_000;

/// Parses a document. `max_elements` bounds the elements read.
pub fn parse(xml: &[u8], max_elements: usize) -> Result<Node> {
    let mut r = NsReader::from_reader(xml);
    r.config_mut().check_end_names = false;
    let mut stack: Vec<Node> = vec![Node {
        name: "#root".into(),
        ..Default::default()
    }];
    let mut count = 0usize;
    let mut buf = Vec::new();
    loop {
        let (res, ev) = r
            .read_resolved_event_into(&mut buf)
            .map_err(|e| Error::Malformed(format!("XML: {e}")))?;
        match ev {
            Event::Start(ref e) | Event::Empty(ref e) => {
                count += 1;
                if count > max_elements {
                    return Err(Error::TooLarge("XML elements"));
                }
                let name = qualify(prefix_of(&res), e.local_name().as_ref());
                let mut attrs = Vec::new();
                for a in e.attributes().with_checks(false).flatten() {
                    let (ar, local) = r.resolver().resolve_attribute(a.key);
                    let key = qualify(prefix_of(&ar), local.as_ref());
                    let v = a
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map(|v| v.into_owned())
                        .unwrap_or_else(|_| a.value.to_string());
                    attrs.push((key, v));
                }
                let node = Node {
                    name,
                    attrs,
                    children: vec![],
                };
                let empty = matches!(ev, Event::Empty(_));
                if empty {
                    if let Some(top) = stack.last_mut() {
                        top.children.push(Child::Node(node));
                    }
                } else if stack.len() < MAX_DEPTH {
                    stack.push(node);
                } else {
                    return Err(Error::Malformed("XML nested too deep".into()));
                }
            }
            Event::End(_) => {
                if stack.len() > 1 {
                    if let Some(n) = stack.pop() {
                        if let Some(top) = stack.last_mut() {
                            top.children.push(Child::Node(n));
                        }
                    }
                }
            }
            Event::Text(t) => {
                let s = t.xml10_content().into_owned();
                push_text(&mut stack, &s);
            }
            Event::CData(t) => {
                push_text(&mut stack, &t);
            }
            Event::GeneralRef(g) => {
                let s = match g.resolve_char_ref() {
                    Ok(Some(c)) => c.to_string(),
                    _ => match &*g {
                        "amp" => "&".into(),
                        "lt" => "<".into(),
                        "gt" => ">".into(),
                        "quot" => "\"".into(),
                        "apos" => "'".into(),
                        _ => String::new(),
                    },
                };
                push_text(&mut stack, &s);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    while stack.len() > 1 {
        if let Some(n) = stack.pop() {
            if let Some(top) = stack.last_mut() {
                top.children.push(Child::Node(n));
            }
        }
    }
    let mut root = stack.pop().unwrap_or_default();
    root.children.retain(|c| matches!(c, Child::Node(_)));
    match root.children.pop() {
        Some(Child::Node(n)) => Ok(n),
        _ => Err(Error::NotFormat("an empty XML document".into())),
    }
}

fn push_text(stack: &mut [Node], s: &str) {
    let Some(n) = stack.last_mut() else { return };
    if let Some(Child::Text(t)) = n.children.last_mut() {
        t.push_str(s);
    } else {
        n.children.push(Child::Text(s.to_string()));
    }
}

impl Node {
    pub fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|a| a.0 == k).map(|a| a.1.as_str())
    }

    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.children.iter().filter_map(|c| {
            if let Child::Node(n) = c {
                Some(n)
            } else {
                None
            }
        })
    }

    pub fn child(&self, name: &str) -> Option<&Node> {
        self.nodes().find(|n| n.name == name)
    }

    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.nodes().filter(move |n| n.name == name)
    }

    /// The first descendant named `name`, depth first.
    pub fn find(&self, name: &str) -> Option<&Node> {
        let mut stack: Vec<&Node> = self.nodes().collect();
        stack.reverse();
        while let Some(n) = stack.pop() {
            if n.name == name {
                return Some(n);
            }
            let mut kids: Vec<&Node> = n.nodes().collect();
            kids.reverse();
            stack.extend(kids);
        }
        None
    }

    /// The text directly in this node.
    pub fn own_text(&self) -> String {
        self.children
            .iter()
            .filter_map(|c| {
                if let Child::Text(t) = c {
                    Some(t.as_str())
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_are_normalized() {
        let x = br#"<a:document xmlns:a="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:t="urn:oasis:names:tc:opendocument:xmlns:table:1.0"><t:table t:name="S&amp;1">x&#65;<![CDATA[<y>]]></t:table></a:document>"#;
        let d = parse(x, 100).unwrap();
        assert_eq!(d.name, "office:document");
        let t = d.child("table:table").unwrap();
        assert_eq!(t.attr("table:name"), Some("S&1"));
        assert_eq!(t.own_text(), "xA<y>");
    }

    #[test]
    fn bounded() {
        let mut x = String::new();
        for _ in 0..300 {
            x.push_str("<a>");
        }
        assert!(parse(x.as_bytes(), 1000).is_err());
        assert_eq!(
            parse(b"<a><b/><b/><b/></a>", 2).err(),
            Some(Error::TooLarge("XML elements"))
        );
        // Unclosed elements are closed at the end.
        assert_eq!(parse(b"<a><b>", 10).unwrap().nodes().count(), 1);
    }
}
