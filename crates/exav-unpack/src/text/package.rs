//! The hyperlinks of an Office Open XML package (DOCX, PPTX, XLSX and their
//! macro and template variants), each label joined to its target.
//!
//! A part says where a link starts and ends (`w:hyperlink`, `a:hlinkClick`,
//! a sheet's `hyperlink`) and names the target by a relationship id; the
//! target is in the part's `_rels/<part>.rels`. The text of the parts is read
//! member by member ([`super::xml`]); this reads only the links, as
//! `label (target)` lines, so that a label naming one site over a target on
//! another can be judged. Word's `HYPERLINK` field codes, whose target is in
//! the code itself, are read the same way.

use std::collections::{HashMap, HashSet};

use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use super::{Out, XmlPart, decode, xml_part};
use crate::{Budget, ByteSource, Format, Limits, package_kinds_walked};

/// Whether `src`, a file called `name` that starts with `head`, is an Office
/// Open XML package: a ZIP named as one, or whose directory (its local
/// headers when the directory is lost) has the parts of one.
pub(super) fn is_package(name: &str, head: &[u8], src: &dyn ByteSource) -> bool {
    if !head.starts_with(b"PK\x03\x04") {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    if EXTENSIONS.iter().any(|e| lower.ends_with(e)) {
        return true;
    }
    package_kinds_walked(src)
        .iter()
        .any(|kind| matches!(*kind, "docx" | "xlsx" | "pptx"))
}

const EXTENSIONS: &[&str] = &[
    ".docx", ".docm", ".dotx", ".dotm", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm",
    ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlam",
];

/// Each member of `data` this asks for, whole: `want` says which from its
/// lowercased path, `got` takes it. A member that could not be read whole
/// cuts the text.
fn members(
    data: &[u8],
    limits: &Limits,
    out: &mut Out,
    want: &dyn Fn(&str) -> bool,
    got: &mut dyn FnMut(&str, Vec<u8>, &mut Out),
) {
    let mut budget = Budget::new(limits.clone());
    let mut cut = false;
    let walked = crate::walk(Format::Zip, &data, &mut budget, &mut |meta, content, b| {
        let lower = meta.name.to_ascii_lowercase();
        let lower = lower.trim_start_matches('/');
        if !want(lower) {
            return None;
        }
        let Some(content) = content else {
            cut |= meta.unsupported.is_some();
            return None;
        };
        let Ok((bytes, partial)) = content.into_bytes(meta, b) else {
            cut = true;
            return Some(());
        };
        cut |= partial;
        got(lower, bytes, out);
        None
    });
    if walked.is_err() || cut {
        out.cut();
    }
}

pub(super) fn read(data: &[u8], limits: &Limits, out: &mut Out) {
    // The relationships first, then each part as it comes; a sheet with links
    // waits for the shared strings, which may come after it.
    let mut rels: HashMap<String, HashMap<String, String>> = HashMap::new();
    members(
        data,
        limits,
        out,
        &|p| p.ends_with(".rels"),
        &mut |p, bytes, _| {
            let links = hyperlinks(&decode(&bytes));
            if !links.is_empty() {
                rels.insert(p.to_string(), links);
            }
        },
    );
    let part = |p: &str| xml_part(p).filter(|k| *k != XmlPart::Odf);
    let targets = |p: &str| rels.get(&rels_of(p));
    let want = |p: &str| match part(p) {
        Some(XmlPart::Word) => true,
        Some(XmlPart::Slide | XmlPart::Sheet) => targets(p).is_some(),
        Some(XmlPart::SharedStrings) => rels.keys().any(|r| r.starts_with("xl/")),
        _ => false,
    };
    let mut sheets: Vec<(String, Vec<u8>)> = Vec::new();
    let mut shared_part = None;
    let none = HashMap::new();
    members(
        data,
        limits,
        out,
        &want,
        &mut |p, bytes, out| match part(p) {
            Some(XmlPart::Sheet) => sheets.push((p.to_string(), bytes)),
            Some(XmlPart::SharedStrings) => shared_part = Some(bytes),
            _ if !out.full() => text_links(&decode(&bytes), targets(p).unwrap_or(&none), out),
            _ => {}
        },
    );
    let mut shared = None;
    for (p, bytes) in &sheets {
        if out.full() {
            return;
        }
        let t = targets(p).unwrap_or(&none);
        sheet_links(&decode(bytes), t, &shared_part, &mut shared, out);
    }
}

/// The relationships part of `path`: `word/document.xml` has
/// `word/_rels/document.xml.rels`.
fn rels_of(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((dir, file)) => format!("{dir}/_rels/{file}.rels"),
        None => format!("_rels/{path}.rels"),
    }
}

fn reader(src: &str) -> Reader<&[u8]> {
    let mut reader = Reader::from_str(src);
    let c = reader.config_mut();
    c.check_end_names = false;
    c.allow_unmatched_ends = true;
    c.allow_dangling_amp = true;
    reader
}

/// An attribute's value by its local name, entities resolved; with
/// `prefixed`, only one with a namespace prefix (`r:id`, not `id`).
fn attr_of(e: &BytesStart<'_>, local: &str, prefixed: bool) -> Option<String> {
    e.attributes().with_checks(false).flatten().find_map(|a| {
        (a.key.local_name().as_ref() == local && (!prefixed || a.key.prefix().is_some()))
            .then(|| {
                a.normalized_value(XmlVersion::Implicit1_0)
                    .ok()
                    .map(|v| v.into_owned())
            })
            .flatten()
    })
}

fn attr(e: &BytesStart<'_>, local: &str) -> Option<String> {
    attr_of(e, local, false)
}

/// The target a link element names by its relationship id (`r:id`).
fn target_of(e: &BytesStart<'_>, targets: &HashMap<String, String>) -> Option<String> {
    attr_of(e, "id", true).and_then(|id| targets.get(&id).cloned())
}

/// The hyperlink relationships of a `.rels` part: id to target.
fn hyperlinks(src: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut reader = reader(src);
    loop {
        match reader.read_event() {
            Ok(Event::Eof) | Err(_) => break,
            Ok(Event::Start(e) | Event::Empty(e)) if e.local_name().as_ref() == "Relationship" => {
                let hyperlink = attr(&e, "Type").is_some_and(|t| t.ends_with("/hyperlink"));
                if let (true, Some(id), Some(target)) =
                    (hyperlink, attr(&e, "Id"), attr(&e, "Target"))
                {
                    map.insert(id, target);
                }
            }
            _ => {}
        }
    }
    map
}

/// Writes `label (target)` on a line.
fn emit(out: &mut Out, label: &str, target: &str) {
    out.newline();
    let from = out.len();
    out.text(label);
    out.target(from, target);
    out.newline();
}

/// The target of a `HYPERLINK` field code: its first quoted argument, or
/// the first word after it. A `\l` bookmark only is not a link out.
fn field_target(code: &str) -> Option<String> {
    let rest = code.trim_start();
    let rest = rest
        .get(..9)
        .filter(|h| h.eq_ignore_ascii_case("HYPERLINK"))
        .and_then(|_| rest.get(9..))?
        .trim_start();
    if rest.starts_with('\\') {
        return None;
    }
    let target = match rest.strip_prefix('"') {
        Some(q) => q.split('"').next()?,
        None => rest.split_whitespace().next()?,
    };
    (!target.is_empty()).then(|| target.to_string())
}

/// A link being read: where it goes, its label so far, and the depth of the
/// element that ends it (`None`: a field's `end` mark does).
struct Open {
    target: String,
    label: String,
    depth: Option<usize>,
}

/// What [`text_links`] is in the middle of.
#[derive(Default)]
struct State {
    depth: usize,
    in_t: bool,
    in_instr: bool,
    /// A `w:hyperlink`, a `w:fldSimple` or a complex field's result.
    open: Option<Open>,
    /// A run with an `a:hlinkClick`.
    run: Option<Open>,
    /// The depths of the runs open.
    runs: Vec<usize>,
    /// A complex field: its code so far, and whether its result has started.
    field: Option<(String, bool)>,
}

impl State {
    fn start(&mut self, e: &BytesStart<'_>, targets: &HashMap<String, String>, out: &mut Out) {
        match e.local_name().as_ref() {
            "hyperlink" if self.open.is_none() => {
                if let Some(target) = target_of(e, targets) {
                    self.open(target, Some(self.depth));
                }
            }
            "fldSimple" if self.open.is_none() => {
                if let Some(target) = attr(e, "instr").and_then(|c| field_target(&c)) {
                    self.open(target, Some(self.depth));
                }
            }
            "t" => self.in_t = true,
            "instrText" => self.in_instr = true,
            "r" => self.runs.push(self.depth),
            _ => self.mark(e, targets, out),
        }
    }

    fn open(&mut self, target: String, depth: Option<usize>) {
        self.open = Some(Open {
            target,
            label: String::new(),
            depth,
        });
    }

    /// An element that marks without holding text: a click target, a field
    /// character.
    fn mark(&mut self, e: &BytesStart<'_>, targets: &HashMap<String, String>, out: &mut Out) {
        match e.local_name().as_ref() {
            "hlinkClick" | "hlinkMouseOver" => {
                let Some(target) = target_of(e, targets) else {
                    return;
                };
                // On a run, its text is the label; on a shape (a picture, a
                // button) there is none.
                match self.runs.last() {
                    Some(&d) if self.run.is_none() => {
                        self.run = Some(Open {
                            target,
                            label: String::new(),
                            depth: Some(d),
                        });
                    }
                    Some(_) => {}
                    None => emit(out, "", &target),
                }
            }
            "fldChar" => match attr(e, "fldCharType").as_deref() {
                Some("begin") => self.field = Some((String::new(), false)),
                Some("separate") => {
                    let code = match &mut self.field {
                        Some((code, result)) => {
                            *result = true;
                            field_target(code)
                        }
                        None => None,
                    };
                    if let (None, Some(target)) = (&self.open, code) {
                        self.open(target, None);
                    }
                }
                Some("end") => {
                    if self.field.take().is_some()
                        && let Some(o) = self.open.take_if(|o| o.depth.is_none())
                    {
                        emit(out, &o.label, &o.target);
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn end(&mut self, name: &str, out: &mut Out) {
        match name {
            "t" => self.in_t = false,
            "instrText" => self.in_instr = false,
            "r" => {
                self.runs.pop();
            }
            _ => {}
        }
        if let Some(r) = self.run.take_if(|r| r.depth == Some(self.depth)) {
            emit(out, &r.label, &r.target);
        }
        if let Some(o) = self.open.take_if(|o| o.depth == Some(self.depth)) {
            emit(out, &o.label, &o.target);
        }
    }

    fn text(&mut self, s: &str) {
        if self.in_instr {
            if let Some((code, false)) = &mut self.field {
                code.push_str(s);
            }
            return;
        }
        if !self.in_t {
            return;
        }
        for o in [&mut self.open, &mut self.run].into_iter().flatten() {
            if o.label.len() < LABEL_BYTES {
                o.label.push_str(s);
            }
        }
    }
}

/// Bytes of a label kept: `Out` keeps less of it in a link.
const LABEL_BYTES: usize = 16 << 10;

/// Text of an entity or a character reference.
fn entity(r: &BytesRef<'_>) -> String {
    if let Ok(Some(c)) = r.resolve_char_ref() {
        c.to_string()
    } else {
        quick_xml::escape::resolve_predefined_entity(r)
            .unwrap_or_default()
            .to_string()
    }
}

/// The links of a Word or DrawingML part.
fn text_links(src: &str, targets: &HashMap<String, String>, out: &mut Out) {
    let mut reader = reader(src);
    let mut s = State::default();
    while !out.full() {
        match reader.read_event() {
            Ok(Event::Eof) | Err(_) => break,
            Ok(Event::Start(e)) => {
                s.depth += 1;
                s.start(&e, targets, out);
            }
            Ok(Event::Empty(e)) => s.mark(&e, targets, out),
            Ok(Event::End(e)) => {
                s.end(e.local_name().as_ref(), out);
                s.depth = s.depth.saturating_sub(1);
            }
            Ok(Event::Text(t)) => s.text(&t.xml10_content()),
            Ok(Event::CData(t)) => s.text(&t.xml10_content()),
            Ok(Event::GeneralRef(r)) => s.text(&entity(&r)),
            _ => {}
        }
    }
}

/// The strings of a workbook's shared strings part, in order.
fn shared_strings(src: &str) -> Vec<String> {
    let mut list = Vec::new();
    let mut reader = reader(src);
    let mut cur: Option<String> = None;
    let mut in_t = false;
    loop {
        match reader.read_event() {
            Ok(Event::Eof) | Err(_) => break,
            Ok(Event::Start(e)) => match e.local_name().as_ref() {
                "si" => cur = Some(String::new()),
                "t" => in_t = true,
                _ => {}
            },
            Ok(Event::Empty(e)) if e.local_name().as_ref() == "si" => list.push(String::new()),
            Ok(Event::End(e)) => match e.local_name().as_ref() {
                "si" => list.extend(cur.take()),
                "t" => in_t = false,
                _ => {}
            },
            Ok(Event::Text(t)) if in_t => {
                if let Some(c) = &mut cur {
                    c.push_str(&t.xml10_content());
                }
            }
            Ok(Event::GeneralRef(r)) if in_t => {
                if let Some(c) = &mut cur {
                    c.push_str(&entity(&r));
                }
            }
            _ => {}
        }
    }
    list
}

/// The links of a sheet: each `hyperlink` with a target, labelled by its
/// `display` or, without one, by its cell's text. The shared strings are
/// read the first time a sheet with a link needs them.
fn sheet_links(
    src: &str,
    targets: &HashMap<String, String>,
    shared_part: &Option<Vec<u8>>,
    shared: &mut Option<Vec<String>>,
    out: &mut Out,
) {
    // The links first (they follow the cells), then only the cells they name.
    let mut links: Vec<(String, Option<String>, String)> = Vec::new();
    let mut reader = reader(src);
    loop {
        match reader.read_event() {
            Ok(Event::Eof) | Err(_) => break,
            Ok(Event::Start(e) | Event::Empty(e)) if e.local_name().as_ref() == "hyperlink" => {
                if links.len() < super::MAX_LINKS
                    && let Some(target) = target_of(&e, targets)
                {
                    let first = attr(&e, "ref")
                        .unwrap_or_default()
                        .split(':')
                        .next()
                        .unwrap_or("")
                        .to_ascii_uppercase();
                    links.push((first, attr(&e, "display"), target));
                }
            }
            _ => {}
        }
    }
    if links.is_empty() {
        return;
    }
    let wanted: HashSet<&str> = links.iter().map(|l| l.0.as_str()).collect();
    let mut cells: HashMap<String, (String, String)> = HashMap::new();
    let mut reader = self::reader(src);
    // The cell being read: its reference, type and value.
    let mut cell: Option<(String, String, String)> = None;
    let mut in_value = false;
    loop {
        match reader.read_event() {
            Ok(Event::Eof) | Err(_) => break,
            Ok(Event::Start(e)) => match e.local_name().as_ref() {
                "c" => {
                    let r = attr(&e, "r").unwrap_or_default().to_ascii_uppercase();
                    cell = wanted
                        .contains(r.as_str())
                        .then(|| (r, attr(&e, "t").unwrap_or_default(), String::new()));
                }
                "v" | "t" => in_value = true,
                _ => {}
            },
            Ok(Event::End(e)) => match e.local_name().as_ref() {
                "c" => {
                    if let Some((r, kind, value)) = cell.take() {
                        cells.insert(r, (kind, value));
                    }
                }
                "v" | "t" => in_value = false,
                _ => {}
            },
            Ok(Event::Text(t)) if in_value => {
                if let Some((_, _, v)) = &mut cell {
                    v.push_str(&t.xml10_content());
                }
            }
            Ok(Event::GeneralRef(r)) if in_value => {
                if let Some((_, _, v)) = &mut cell {
                    v.push_str(&entity(&r));
                }
            }
            _ => {}
        }
    }
    for (r, display, target) in links {
        if out.full() {
            return;
        }
        let label = match display.filter(|d| !d.trim().is_empty()) {
            Some(d) => d,
            None => match cells.get(&r) {
                Some((kind, v)) if kind == "s" => {
                    let strings = shared.get_or_insert_with(|| {
                        shared_part
                            .as_deref()
                            .map(|s| shared_strings(&decode(s)))
                            .unwrap_or_default()
                    });
                    v.trim()
                        .parse::<usize>()
                        .ok()
                        .and_then(|i| strings.get(i).cloned())
                        .unwrap_or_default()
                }
                Some((_, v)) => v.clone(),
                None => String::new(),
            },
        };
        emit(out, &label, &target);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_code_names_its_target() {
        assert_eq!(
            field_target(r#" HYPERLINK "http://a.example/x" \o "tip" "#).as_deref(),
            Some("http://a.example/x")
        );
        assert_eq!(
            field_target("HYPERLINK http://b.example").as_deref(),
            Some("http://b.example")
        );
        assert_eq!(field_target(r#"HYPERLINK \l "_Toc1""#), None);
        assert_eq!(field_target("PAGEREF _Toc1"), None);
    }

    #[test]
    fn the_rels_of_a_part() {
        assert_eq!(rels_of("word/document.xml"), "word/_rels/document.xml.rels");
        assert_eq!(
            rels_of("ppt/slides/slide2.xml"),
            "ppt/slides/_rels/slide2.xml.rels"
        );
    }
}
