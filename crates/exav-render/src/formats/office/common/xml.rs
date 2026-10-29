//! A small element tree over quick-xml, with element and attribute names
//! given the usual ODF prefixes whatever prefixes a file declares. Bounded:
//! nesting depth is limited, and the memory of the tree is told to the caller
//! as it grows.

use quick_xml::events::Event;
use std::fmt;

/// Why a document did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not well-formed, or nested past [`MAX_DEPTH`].
    Malformed(String),
    /// More elements than allowed: what was counted.
    TooLarge(&'static str),
    /// No element at all.
    NotFormat(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(why) | Error::NotFormat(why) => f.write_str(why),
            Error::TooLarge(what) => write!(f, "too large: {what}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
use quick_xml::NsReader;
use quick_xml::name::ResolveResult;

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
    (
        "urn:oasis:names:tc:opendocument:xmlns:presentation:1.0",
        "presentation",
    ),
    (
        "urn:oasis:names:tc:opendocument:xmlns:smil-compatible:1.0",
        "smil",
    ),
    (
        "urn:oasis:names:tc:opendocument:xmlns:animation:1.0",
        "anim",
    ),
    ("http://openoffice.org/2010/draw", "drawooo"),
    ("http://openoffice.org/2009/office", "officeooo"),
    // Apple's iWork '04 to '09 documents (Keynote 2 to 5).
    ("http://developer.apple.com/namespaces/sf", "sf"),
    ("http://developer.apple.com/namespaces/sfa", "sfa"),
    ("http://developer.apple.com/namespaces/ls", "ls"),
    ("http://developer.apple.com/namespaces/keynote2", "key"),
    ("http://www.w3.org/2001/XMLSchema-instance", "xsi"),
    // Early OpenDocument drafts used the W3C namespaces.
    ("http://www.w3.org/2000/svg", "svg"),
    ("http://www.w3.org/1999/XSL/Format", "fo"),
    ("http://www.w3.org/2001/SMIL20", "smil"),
    // Word 2003 XML (WordprocessingML 2003).
    ("http://schemas.microsoft.com/office/word/2003/wordml", "w"),
    (
        "http://schemas.microsoft.com/office/word/2003/auxHint",
        "wx",
    ),
    ("urn:schemas-microsoft-com:office:office", "o"),
    ("urn:schemas-microsoft-com:vml", "v"),
    ("urn:schemas-microsoft-com:office:word", "w10"),
    ("http://schemas.microsoft.com/aml/2001/core", "aml"),
    // Excel 2003 XML Spreadsheet.
    ("urn:schemas-microsoft-com:office:spreadsheet", "ss"),
    ("urn:schemas-microsoft-com:office:excel", "x"),
    ("http://www.w3.org/TR/REC-html40", "html"),
    // Visio drawings (VSDX) and the Open Packaging Conventions.
    (
        "http://schemas.microsoft.com/office/visio/2012/main",
        "visio",
    ),
    (
        "http://schemas.microsoft.com/office/visio/2011/1/core",
        "visio",
    ),
    (
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        "r",
    ),
    (
        "http://schemas.openxmlformats.org/package/2006/relationships",
        "rels",
    ),
    ("http://schemas.openxmlformats.org/drawingml/2006/main", "a"),
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

/// What the tree takes for an element or a text in its parent's list: the
/// room of the list doubles as it grows.
const SLOT: u64 = 2 * size_of::<Child>() as u64;

/// What the allocator takes for `len` bytes: a header, a 16-byte grain, and 32
/// at least.
fn heap(len: usize) -> u64 {
    if len == 0 {
        0
    } else {
        ((len as u64 + 8 + 15) & !15).max(32)
    }
}

/// A `charge` for [`parse`] that refuses past `max` bytes in all.
pub fn within(max: u64) -> impl FnMut(u64) -> bool {
    let mut left = max;
    move |bytes| match left.checked_sub(bytes) {
        Some(l) => {
            left = l;
            true
        }
        None => false,
    }
}

/// Parses a document. The memory of the tree is told to `charge` as it grows,
/// in bytes, and the parse fails once `charge` returns false.
pub fn parse(xml: &[u8], charge: &mut dyn FnMut(u64) -> bool) -> Result<Node> {
    let mut spend = |bytes: u64| {
        if charge(bytes) {
            Ok(())
        } else {
            Err(Error::TooLarge("memory"))
        }
    };
    let mut r = NsReader::from_reader(xml);
    r.config_mut().check_end_names = false;
    let mut stack: Vec<Node> = vec![Node {
        name: "#root".into(),
        ..Default::default()
    }];
    let mut buf = Vec::new();
    loop {
        let (res, ev) = r
            .read_resolved_event_into(&mut buf)
            .map_err(|e| Error::Malformed(format!("XML: {e}")))?;
        match ev {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let name = qualify(prefix_of(&res), e.local_name().as_ref());
                let mut cost = SLOT + heap(name.len());
                let mut attrs = Vec::new();
                for a in e.attributes().with_checks(false).flatten() {
                    let (ar, local) = r.resolver().resolve_attribute(a.key);
                    let key = qualify(prefix_of(&ar), local.as_ref());
                    let v = a
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map(|v| v.into_owned())
                        .unwrap_or_else(|_| a.value.to_string());
                    cost += heap(key.len()) + heap(v.len());
                    attrs.push((key, v));
                }
                cost += heap(attrs.capacity() * size_of::<(String, String)>());
                spend(cost)?;
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
                if stack.len() > 1
                    && let Some(n) = stack.pop()
                    && let Some(top) = stack.last_mut()
                {
                    top.children.push(Child::Node(n));
                }
            }
            Event::Text(t) => {
                let s = t.xml10_content().into_owned();
                spend(push_text(&mut stack, &s))?;
            }
            Event::CData(t) => {
                spend(push_text(&mut stack, &t))?;
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
                spend(push_text(&mut stack, &s))?;
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    while stack.len() > 1 {
        if let Some(n) = stack.pop()
            && let Some(top) = stack.last_mut()
        {
            top.children.push(Child::Node(n));
        }
    }
    let mut root = stack.pop().unwrap_or_default();
    root.children.retain(|c| matches!(c, Child::Node(_)));
    match root.children.pop() {
        Some(Child::Node(n)) => Ok(n),
        _ => Err(Error::NotFormat("an empty XML document".into())),
    }
}

/// Adds `s` to the text of the open element; the bytes it takes in the tree.
fn push_text(stack: &mut [Node], s: &str) -> u64 {
    let Some(n) = stack.last_mut() else { return 0 };
    if let Some(Child::Text(t)) = n.children.last_mut() {
        t.push_str(s);
        s.len() as u64
    } else {
        n.children.push(Child::Text(s.to_string()));
        SLOT + heap(s.len())
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

    /// The node as a document that `parse` reads back to the same names: the
    /// known namespaces are declared on it. Elements and attributes of
    /// other namespaces are left out.
    pub fn to_xml(&self) -> String {
        fn escape(s: &str, out: &mut String) {
            for c in s.chars() {
                match c {
                    '&' => out.push_str("&amp;"),
                    '<' => out.push_str("&lt;"),
                    '>' => out.push_str("&gt;"),
                    '"' => out.push_str("&quot;"),
                    c => out.push(c),
                }
            }
        }
        fn write(n: &Node, root: bool, out: &mut String) {
            out.push('<');
            out.push_str(&n.name);
            if root {
                let mut seen: Vec<&str> = vec![];
                for (uri, prefix) in NS {
                    if !seen.contains(prefix) {
                        seen.push(prefix);
                        out.push_str(&format!(" xmlns:{prefix}=\"{uri}\""));
                    }
                }
            }
            for (k, v) in n.attrs.iter().filter(|a| !a.0.starts_with('{')) {
                out.push_str(&format!(" {k}=\""));
                escape(v, out);
                out.push('"');
            }
            out.push('>');
            for c in &n.children {
                match c {
                    Child::Node(k) if !k.name.starts_with('{') => write(k, false, out),
                    Child::Node(_) => {}
                    Child::Text(t) => escape(t, out),
                }
            }
            out.push_str("</");
            out.push_str(&n.name);
            out.push('>');
        }
        let mut out = String::new();
        write(self, true, &mut out);
        out
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
        let d = parse(x, &mut within(1 << 20)).unwrap();
        assert_eq!(d.name, "office:document");
        let t = d.child("table:table").unwrap();
        assert_eq!(t.attr("table:name"), Some("S&1"));
        assert_eq!(t.own_text(), "xA<y>");
        // An early draft's W3C SVG namespace reads as svg.
        let x = br#"<d xmlns:s="http://www.w3.org/2000/svg" s:width="2cm"/>"#;
        let d = parse(x, &mut within(1 << 20)).unwrap();
        assert_eq!(d.attr("svg:width"), Some("2cm"));
    }

    #[test]
    fn written_back_reads_the_same() {
        let x = br#"<o:document xmlns:o="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:t="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:z="urn:other" z:skip="1"><t:table t:name="S&amp;&quot;1&quot;">a &lt; b<z:skipped/><t:row/></t:table></o:document>"#;
        let d = parse(x, &mut within(1 << 20)).unwrap();
        let back = d.to_xml();
        assert!(!back.contains("skip"), "{back}");
        let e = parse(back.as_bytes(), &mut within(1 << 20)).unwrap();
        assert_eq!(e.name, "office:document");
        let t = e.child("table:table").unwrap();
        assert_eq!(t.attr("table:name"), Some("S&\"1\""));
        assert_eq!(t.own_text(), "a < b");
        assert!(t.child("table:row").is_some());
    }

    #[test]
    fn bounded() {
        let mut x = String::new();
        for _ in 0..300 {
            x.push_str("<a>");
        }
        assert!(parse(x.as_bytes(), &mut within(1 << 20)).is_err());
        // Unclosed elements are closed at the end.
        let d = parse(b"<a><b>", &mut within(1 << 20)).unwrap();
        assert_eq!(d.nodes().count(), 1);
    }

    #[test]
    fn the_memory_of_the_tree_is_told_as_it_grows() {
        // An element of four bytes of input takes a node, whatever its size.
        let x = format!("<r>{}</r>", "<a/>".repeat(10_000));
        let mut told = 0;
        parse(x.as_bytes(), &mut |n| {
            told += n;
            true
        })
        .unwrap();
        assert!(told >= 10_000 * size_of::<Node>() as u64, "{told}");
        let refused = parse(x.as_bytes(), &mut within(told / 2));
        assert_eq!(refused.err(), Some(Error::TooLarge("memory")));
        // A text takes its slot and its bytes.
        let x = format!("<r>{}</r>", "x".repeat(100_000));
        assert_eq!(
            parse(x.as_bytes(), &mut within(99_999)).err(),
            Some(Error::TooLarge("memory"))
        );
    }
}
