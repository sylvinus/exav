//! The text a reader sees in a document, for a scanner or a search: one entry
//! for every kind of document that has some.
//!
//! - Markdown (`.md`, `.markdown`): [`markdown::visible_text`].
//! - HTML, the XML parts of Office and OpenDocument files, PDF:
//!   `exav_unpack::text`, over html5gum's tokenizer, quick-xml and hayro.
//! - The hyperlinks of an Office Open XML package, each label with its
//!   target from the `.rels` parts, and an email's headers:
//!   `exav_unpack::text` too.
//! - AutoCAD drawings (DXF and DWG): what the drawing model holds as text:
//!   TEXT and MTEXT, attributes with their tags and prompts, dimension
//!   overrides, multileaders' text, block and layer names. A DWG's
//!   hyperlinks too: each target and description a line, and each
//!   description that is not its target as a link.
//! - IFC models and other STEP files: the strings of each instance (names,
//!   descriptions, property values), one instance to a line.
//! - Office documents the XML parts do not reach (feature `text-office`):
//!   DOC, XLS, PPT, RTF, Word 2003 XML, SpreadsheetML 2003, SYLK, the flat
//!   OpenDocument files, Numbers, Pages and Keynote, from what the
//!   converters of `exav_render::sheets`, `slides` and `docs` read, without
//!   writing an Open XML package. The text has sections (a sheet, a slide).
//!   One of those formats whose text could not be read (encrypted, past a
//!   limit, damaged) says so in [`Visible::unreadable`]: it is never an
//!   empty text.
//!
//! A document is known by its bytes where they say what it is (PDF, HTML,
//! drawings, the office formats) and by its name where they do not (Markdown,
//! the parts of a package, a compound file). The text is one block to a line
//! and cut at `cap`, which [`Visible::truncated`] says.

use super::cad::{self, Drawing, Entity, EntityKind};
use super::dwg::mtext_lines;
use super::ifc::step::is_step;
use super::markdown;
pub use super::markdown::Visible;

/// A Markdown file is known by its name, and by being text.
fn is_markdown(name: &str, head: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.ends_with(".md") || lower.ends_with(".markdown")) && exav_unpack::text::looks_text(head)
}

/// Whether the file or member `src` called `name` is a kind of document
/// [`visible_text`] reads. Cheap: nothing is parsed, but a ZIP's directory is
/// read when its name does not say what it is.
pub fn wants(name: &str, src: &dyn exav_unpack::ByteSource) -> bool {
    let window = src.window(0, 1024);
    let head = &window[..];
    is_markdown(name, head)
        || exav_unpack::text::kind(name, src).is_some()
        || cad::looks_like_dwg(head)
        || is_r2007_dwg(head)
        || cad::looks_like_dxf(head)
        || is_step(head)
        || office_wants(name, head)
}

/// An R2007 DWG (`AC1021` and five zero bytes), whose file header ends at
/// 0x480: more than the kilobyte `wants` is given, so [`cad::looks_like_dwg`]
/// cannot tell. The whole file is checked when it is read.
fn is_r2007_dwg(head: &[u8]) -> bool {
    head.starts_with(b"AC1021") && head.get(6..11) == Some(&[0u8; 5][..])
}

#[cfg(feature = "text-office")]
fn office_wants(name: &str, head: &[u8]) -> bool {
    super::office::visible::wants(name, head)
}

#[cfg(not(feature = "text-office"))]
fn office_wants(_: &str, _: &[u8]) -> bool {
    false
}

/// The text of `data`, a file or archive member called `name`, when it is a
/// kind of document that has some. `limits` bound what a PDF's streams
/// decompress to.
pub fn visible_text(
    name: &str,
    data: &[u8],
    cap: usize,
    limits: &exav_unpack::Limits,
) -> Option<Visible> {
    let head = &data[..data.len().min(1024)];
    if is_markdown(name, head) {
        // Read as exav-unpack reads text, binary bytes included, as its XML
        // parts are.
        return Some(markdown::visible_text(
            &exav_unpack::text::decode(data),
            cap,
        ));
    }
    if let Some(kind) = exav_unpack::text::kind(name, &data) {
        let e = exav_unpack::text::extract(kind, data, cap, limits);
        return Some(Visible {
            text: e.text,
            truncated: e.truncated,
            links: e.links,
            sections: Vec::new(),
            unreadable: None,
        });
    }
    if let Some(v) = drawing(data, head, cap, limits) {
        return Some(v);
    }
    if is_step(head) {
        return step(data, cap);
    }
    #[cfg(feature = "text-office")]
    return office(name, data, cap, limits);
    #[cfg(not(feature = "text-office"))]
    None
}

/// An office document the XML parts above do not reach: the legacy and flat
/// formats and iWork's, read by exav-render's `sheets`, `slides` and `docs`.
#[cfg(feature = "text-office")]
fn office(name: &str, data: &[u8], cap: usize, limits: &exav_unpack::Limits) -> Option<Visible> {
    use super::office::visible::{Read, read};
    Some(match read(name, data, cap, limits)? {
        Read::Text(t) => Visible {
            text: t.text,
            truncated: t.truncated,
            links: t.links,
            sections: t.sections.into_iter().map(|s| (s.label, s.range)).collect(),
            unreadable: None,
        },
        Read::Unreadable(why) => Visible {
            text: String::new(),
            truncated: false,
            links: Vec::new(),
            sections: Vec::new(),
            unreadable: Some(why),
        },
    })
}

/// A drawing's text; the drawing may take what the caller's `limits` allow
/// of memory, and the text is `truncated` when it did not fit.
fn drawing(data: &[u8], head: &[u8], cap: usize, limits: &exav_unpack::Limits) -> Option<Visible> {
    let within = cad::limits_within(limits.max_buffer_bytes);
    let read = if cad::looks_like_dwg(data) {
        cad::read_dwg_with(data, &within)
    } else if cad::looks_like_dxf(head) {
        cad::read_dxf_with(data, &within)
    } else {
        return None;
    };
    let drawing = match read {
        Ok(d) => d,
        Err(cad::Error::LimitExceeded(why)) => {
            return Some(Visible {
                text: String::new(),
                truncated: false,
                links: Vec::new(),
                sections: Vec::new(),
                unreadable: Some(format!("too-large: {why}")),
            });
        }
        Err(_) => return None,
    };
    let cut = drawing
        .warnings
        .iter()
        .any(|w| w.kind == cad::WarningKind::LimitReached);
    let mut lines = Lines {
        text: String::new(),
        cap,
        truncated: false,
    };
    // The hyperlinks first, so that a text cut at the cap keeps them.
    let links = hyperlink_lines(&drawing, &mut lines);
    drawing_lines(&drawing, &mut lines);
    Some(Visible {
        text: lines.text,
        truncated: lines.truncated || cut,
        links,
        sections: Vec::new(),
        unreadable: None,
    })
}

/// A drawing's hyperlinks: each target and each text a line, and as a link
/// (description, target) each whose description is not its target. Stops at
/// the cap, which `out.truncated` then says.
fn hyperlink_lines(d: &Drawing, out: &mut Lines) -> Vec<(String, String)> {
    let mut links = Vec::new();
    for h in &d.hyperlinks {
        out.line(&h.url);
        for t in &h.texts {
            out.line(t);
        }
        if out.truncated {
            break;
        }
        let url = h.url.trim();
        let label = h.texts.first().map_or("", |t| t.trim());
        if !url.is_empty() && label != url {
            links.push((label.to_string(), url.to_string()));
        }
    }
    links
}

/// The text of an IFC model or another STEP file: the strings of each
/// instance (names, descriptions, property values, labels), one instance to a
/// line. An IfcRoot's GlobalId, its first attribute, is left out, and so is
/// an instance that cannot be read.
fn step(data: &[u8], cap: usize) -> Option<Visible> {
    use super::ifc::step::{StepFile, Value, decode_string};
    fn strings(v: &Value<'_>, first: bool, out: &mut Vec<String>) {
        match v {
            Value::Str(s) if !(first && is_global_id(s)) => {
                let s = decode_string(s);
                if !s.trim().is_empty() {
                    out.push(s);
                }
            }
            Value::Typed(_, v) => strings(v, false, out),
            Value::List(l) => l.iter().for_each(|v| strings(v, false, out)),
            _ => {}
        }
    }
    let file = StepFile::parse(data).ok()?;
    let mut lines = Lines {
        text: String::new(),
        cap,
        truncated: false,
    };
    let mut found = Vec::new();
    for id in file.ids() {
        if lines.truncated {
            break;
        }
        if !file.raw(id).is_some_and(|r| r.contains(&b'\'')) {
            continue;
        }
        let Some(params) = file.params(id) else {
            continue;
        };
        found.clear();
        for (i, v) in params.iter().enumerate() {
            strings(v, i == 0, &mut found);
        }
        lines.line(&found.join(" "));
    }
    Some(Visible {
        text: lines.text,
        truncated: lines.truncated,
        links: Vec::new(),
        sections: Vec::new(),
        unreadable: None,
    })
}

/// An IFC GlobalId: 22 characters of its base 64 alphabet.
fn is_global_id(s: &[u8]) -> bool {
    s.len() == 22
        && s.iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'$')
}

struct Lines {
    text: String,
    cap: usize,
    truncated: bool,
}

impl Lines {
    /// One line: its white space collapsed, empty ones left out.
    fn line(&mut self, s: &str) {
        let line = s.split_whitespace().collect::<Vec<_>>().join(" ");
        if line.is_empty() || self.truncated {
            return;
        }
        if self.text.len() + line.len() + 1 > self.cap {
            self.truncated = true;
            return;
        }
        self.text.push_str(&line);
        self.text.push('\n');
    }

    fn mtext(&mut self, raw: &str) {
        for l in mtext_lines(raw) {
            self.line(&l);
        }
    }
}

fn drawing_lines(d: &Drawing, out: &mut Lines) {
    for layer in &d.layers {
        out.line(&layer.name);
    }
    for block in &d.blocks {
        if !block.name.starts_with('*') {
            out.line(&block.name);
        }
        out.line(&block.description);
        for e in &block.entities {
            entity_lines(e, out);
        }
    }
}

fn entity_lines(e: &Entity, out: &mut Lines) {
    match &e.kind {
        EntityKind::Text(t) => out.line(&t.value),
        EntityKind::MText(m) => out.mtext(&m.text),
        EntityKind::Attribute(a) | EntityKind::AttributeDefinition(a) => {
            out.line(&a.tag);
            out.line(&a.prompt);
            match &a.mtext {
                Some(m) => out.mtext(&m.text),
                None => out.line(&a.text.value),
            }
        }
        EntityKind::Dimension(d) if d.text != "<>" => out.mtext(&d.text),
        EntityKind::MultiLeader(m) => out.mtext(&m.context.text),
        EntityKind::Insert(i) => {
            out.line(&i.block_name);
            for a in &i.attributes {
                entity_lines(a, out);
            }
        }
        _ => {}
    }
}
