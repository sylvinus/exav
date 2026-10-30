//! The text of a presentation as a reader sees it, from the model the
//! readers fill: each slide's shapes in order (groups, tables, charts' text),
//! then the masters' own text where it is not a placeholder.

use crate::formats::office::slides::model::*;
use crate::formats::office::text::Out;

/// Writes the text of `p`: a section to a slide, named by its page where it
/// has one, `slide 3`, `hidden slide 4`.
pub(crate) fn lines(p: &Presentation, out: &mut Out) {
    for (i, slide) in p.slides.iter().enumerate() {
        if out.full() {
            return;
        }
        let n = i + 1;
        let kind = if slide.hidden {
            "hidden slide"
        } else {
            "slide"
        };
        match &slide.name {
            Some(name) if !name.is_empty() => out.section(format!("{kind} {n} \"{name}\"")),
            _ => out.section(format!("{kind} {n}")),
        }
        shapes(&slide.shapes, out);
    }
    // Text a master draws on every slide that is not a placeholder: a
    // footer or a notice repeated on each of them.
    for (i, master) in p.masters.iter().enumerate() {
        if out.full() {
            return;
        }
        let shown: Vec<&Shape> = master
            .shapes
            .iter()
            .filter(|s| s.placeholder.is_none())
            .collect();
        if shown.iter().any(|s| has_text(s)) {
            let name = if master.name.is_empty() {
                format!("master {}", i + 1)
            } else {
                format!("master \"{}\"", master.name)
            };
            out.section(name);
            for s in shown {
                shape(s, out);
            }
        }
    }
}

fn has_text(s: &Shape) -> bool {
    match &s.kind {
        ShapeKind::Sp(sp) => sp
            .text
            .as_ref()
            .is_some_and(|t| t.paras.iter().any(|p| !p.runs.is_empty())),
        ShapeKind::Group(g) => g.shapes.iter().any(has_text),
        ShapeKind::Table(_) => true,
        _ => false,
    }
}

fn shapes(list: &[Shape], out: &mut Out) {
    for s in list {
        if out.full() {
            return;
        }
        shape(s, out);
    }
}

fn shape(s: &Shape, out: &mut Out) {
    // A hidden shape is read as a hidden slide is: a person can show it, and
    // hiding is where content goes that is meant not to be noticed.
    // A shape's link is where its text goes when its runs have none.
    let link = match &s.link {
        Some(Link::Url(u)) => Some(u.as_str()),
        _ => None,
    };
    match &s.kind {
        ShapeKind::Sp(sp) => {
            if let Some(t) = &sp.text {
                body(t, link, out);
            }
        }
        ShapeKind::Group(g) => shapes(&g.shapes, out),
        ShapeKind::Table(t) => {
            for row in &t.rows {
                for (i, cell) in row.cells.iter().enumerate() {
                    if cell.h_merge || cell.v_merge {
                        continue;
                    }
                    if i > 0 {
                        out.push("\t");
                    }
                    for (j, para) in cell.text.paras.iter().enumerate() {
                        if j > 0 {
                            out.push(" ");
                        }
                        paragraph(para, link, out);
                    }
                }
                out.newline();
            }
        }
        ShapeKind::Chart(xml) => chart(xml, out),
        ShapeKind::Pic(_) => {}
    }
    // What a picture or shape says when it cannot be seen.
    if !s.descr.trim().is_empty() {
        out.line(&s.descr);
    }
}

fn body(t: &TextBody, link: Option<&str>, out: &mut Out) {
    for para in &t.paras {
        paragraph(para, link, out);
        out.newline();
    }
}

fn paragraph(p: &Paragraph, shape_link: Option<&str>, out: &mut Out) {
    for run in &p.runs {
        // A run's link, else the shape's.
        let target = match &run.props.link {
            Some(Link::Url(u)) => Some(u.as_str()),
            _ => shape_link,
        };
        match &run.kind {
            RunKind::Text(s) => {
                if let Some(t) = target {
                    out.begin_link(t);
                    out.push(s);
                    out.end_link();
                } else {
                    out.push(s);
                }
            }
            RunKind::Break => out.newline(),
            // The slide number and the date are noise.
            RunKind::Field(kind, text) => {
                if !kind.starts_with("slidenum") && !kind.starts_with("datetime") {
                    out.push(text);
                }
            }
        }
    }
}

/// The text a chart part's XML holds: titles, series names, categories
/// (`a:t`, `c:v`), in order.
fn chart(xml: &str, out: &mut Out) {
    for tag in ["a:t", "c:v"] {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let mut rest = xml;
        while let Some(i) = rest.find(&open) {
            let from = i + open.len();
            let Some(j) = rest[from..].find(&close) else {
                break;
            };
            out.line(&unescape(&rest[from..from + j]));
            rest = &rest[from + j + close.len()..];
            if out.full() {
                return;
            }
        }
    }
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}
