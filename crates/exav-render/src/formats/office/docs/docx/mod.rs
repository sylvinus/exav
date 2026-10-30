//! The document model to a DOCX package (ECMA-376 WordprocessingML).

mod body;
mod parts;
mod props;

use crate::formats::office::common::package::PackageWriter;
use crate::formats::office::common::xmlout::XML_HEAD;
use crate::formats::office::docs::error::{Error, Result};
use crate::formats::office::docs::model::*;
use body::{Rels, W, root};
use std::fmt::Write;

const CT_MAIN: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml";
const REL_BASE: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

fn mime(ext: &str) -> &'static str {
    match ext {
        "png" => "image/png",
        "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "tiff" => "image/tiff",
        "emf" => "image/x-emf",
        "wmf" => "image/x-wmf",
        "svg" => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

fn rels_xml(r: &Rels) -> String {
    let mut o = String::from(XML_HEAD);
    o.push_str(
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">",
    );
    for (id, typ, target, external) in &r.items {
        let _ = write!(o, "<Relationship Id=\"{id}\" Type=\"{typ}\"");
        props::attr(&mut o, "Target", target);
        if *external {
            o.push_str(" TargetMode=\"External\"");
        }
        o.push_str("/>");
    }
    o.push_str("</Relationships>");
    o
}

/// Writes `doc` as a DOCX, refusing to grow past `limit` bytes.
pub fn write(doc: &Document, limit: u64) -> Result<Vec<u8>> {
    let mut z = PackageWriter::new(limit);
    let mut w = W::new(doc, limit);
    let mut rels = Rels::default();

    // Parts that other parts refer to are numbered first, so that their
    // ids do not depend on the body.
    let styles = parts::styles(doc);
    let numbering = parts::numbering(&doc.numbering);
    let settings = parts::settings(doc);
    rels.add(&format!("{REL_BASE}/styles"), "styles.xml", false);
    if numbering.is_some() {
        rels.add(&format!("{REL_BASE}/numbering"), "numbering.xml", false);
    }
    rels.add(&format!("{REL_BASE}/settings"), "settings.xml", false);

    // The body, in a string; the last section's properties close it.
    let mut body = root("document");
    body.push_str("<w:body>");
    w.blocks(&mut body, &doc.body, &mut rels);
    let last = w.sect_pr(&doc.section, &mut rels, true);
    body.push_str(&last);
    body.push_str("</w:body></w:document>");
    if w.over {
        return Err(Error::TooLarge("memory"));
    }

    let mut notes_rels = Rels::default();
    let footnotes = (!doc.footnotes.is_empty())
        .then(|| parts::notes(&mut w, &doc.footnotes, false, &mut notes_rels));
    let mut endnotes_rels = Rels::default();
    let endnotes = (!doc.endnotes.is_empty())
        .then(|| parts::notes(&mut w, &doc.endnotes, true, &mut endnotes_rels));
    let mut comments_rels = Rels::default();
    let comments = (!doc.comments.is_empty())
        .then(|| parts::comments(&mut w, &doc.comments, &mut comments_rels));
    if footnotes.is_some() {
        rels.add(&format!("{REL_BASE}/footnotes"), "footnotes.xml", false);
    }
    if endnotes.is_some() {
        rels.add(&format!("{REL_BASE}/endnotes"), "endnotes.xml", false);
    }
    if comments.is_some() {
        rels.add(&format!("{REL_BASE}/comments"), "comments.xml", false);
    }

    let mut ct = String::from(XML_HEAD);
    ct.push_str("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/>");
    let mut exts: Vec<&str> = doc.media.iter().map(|m| m.ext).collect();
    exts.sort_unstable();
    exts.dedup();
    for e in exts {
        let _ = write!(
            ct,
            "<Default Extension=\"{e}\" ContentType=\"{}\"/>",
            mime(e)
        );
    }
    let over = |ct: &mut String, name: &str, kind: &str| {
        let _ = write!(
            ct,
            "<Override PartName=\"/word/{name}\" ContentType=\"{CT_MAIN}.{kind}+xml\"/>"
        );
    };
    over(&mut ct, "document.xml", "document.main");
    over(&mut ct, "styles.xml", "styles");
    over(&mut ct, "settings.xml", "settings");
    if numbering.is_some() {
        over(&mut ct, "numbering.xml", "numbering");
    }
    if footnotes.is_some() {
        over(&mut ct, "footnotes.xml", "footnotes");
    }
    if endnotes.is_some() {
        over(&mut ct, "endnotes.xml", "endnotes");
    }
    if comments.is_some() {
        over(&mut ct, "comments.xml", "comments");
    }
    for p in &w.parts {
        over(&mut ct, &p.name, if p.header { "header" } else { "footer" });
    }
    ct.push_str("</Types>");

    let pk = |e: crate::formats::office::common::package::Error| -> Error { e.into() };
    z.put("[Content_Types].xml", ct.as_bytes(), true)
        .map_err(pk)?;
    let mut top = String::from(XML_HEAD);
    let _ = write!(
        top,
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"{REL_BASE}/officeDocument\" Target=\"word/document.xml\"/></Relationships>"
    );
    z.put("_rels/.rels", top.as_bytes(), true).map_err(pk)?;
    z.put("word/document.xml", body.as_bytes(), true)
        .map_err(pk)?;
    z.put(
        "word/_rels/document.xml.rels",
        rels_xml(&rels).as_bytes(),
        true,
    )
    .map_err(pk)?;
    z.put("word/styles.xml", styles.as_bytes(), true)
        .map_err(pk)?;
    z.put("word/settings.xml", settings.as_bytes(), true)
        .map_err(pk)?;
    if let Some(n) = &numbering {
        z.put("word/numbering.xml", n.as_bytes(), true)
            .map_err(pk)?;
    }
    for (name, xml, r) in [
        ("footnotes.xml", &footnotes, &notes_rels),
        ("endnotes.xml", &endnotes, &endnotes_rels),
        ("comments.xml", &comments, &comments_rels),
    ] {
        if let Some(x) = xml {
            z.put(&format!("word/{name}"), x.as_bytes(), true)
                .map_err(pk)?;
            if !r.items.is_empty() {
                z.put(
                    &format!("word/_rels/{name}.rels"),
                    rels_xml(r).as_bytes(),
                    true,
                )
                .map_err(pk)?;
            }
        }
    }
    for p in &w.parts {
        z.put(&format!("word/{}", p.name), p.xml.as_bytes(), true)
            .map_err(pk)?;
        if !p.rels.items.is_empty() {
            z.put(
                &format!("word/_rels/{}.rels", p.name),
                rels_xml(&p.rels).as_bytes(),
                true,
            )
            .map_err(pk)?;
        }
    }
    for (i, m) in doc.media.iter().enumerate() {
        let compress = !matches!(m.ext, "png" | "jpeg" | "gif");
        z.put(
            &format!("word/media/image{}.{}", i + 1, m.ext),
            &m.data,
            compress,
        )
        .map_err(pk)?;
    }
    z.finish().map_err(pk)
}
