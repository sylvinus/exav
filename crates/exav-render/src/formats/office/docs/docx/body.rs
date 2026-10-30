//! Blocks, paragraphs, runs and drawings as WordprocessingML.

use super::props::*;
use crate::formats::office::common::xmlout::{esc_into, hex};
use crate::formats::office::docs::model::*;
use std::fmt::Write;

pub const REL_IMAGE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image";
pub const REL_HYPERLINK: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink";
pub const REL_HEADER: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/header";
pub const REL_FOOTER: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer";

#[derive(Default)]
pub struct Rels {
    pub items: Vec<(String, String, String, bool)>,
}

impl Rels {
    pub fn add(&mut self, typ: &str, target: &str, external: bool) -> String {
        if let Some(r) = self
            .items
            .iter()
            .find(|r| r.1 == typ && r.2 == target && r.3 == external)
        {
            return r.0.clone();
        }
        let id = format!("rId{}", self.items.len() + 1);
        self.items
            .push((id.clone(), typ.to_string(), target.to_string(), external));
        id
    }
}

/// A header or footer part written while a section is.
pub struct HfPart {
    pub name: String,
    pub header: bool,
    pub xml: String,
    pub rels: Rels,
}

pub struct W<'a> {
    pub doc: &'a Document,
    pub next_id: u32,
    pub parts: Vec<HfPart>,
    /// The part being written is a note or a comment: no section breaks.
    pub depth: u32,
    /// What one part's XML may take in memory before it is deflated.
    pub limit: u64,
    /// A part's XML grew past `limit`: what is left is not written.
    pub over: bool,
}

const NS_DECL: &str = "xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\" xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" xmlns:pic=\"http://schemas.openxmlformats.org/drawingml/2006/picture\" xmlns:wps=\"http://schemas.microsoft.com/office/word/2010/wordprocessingShape\" xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\" xmlns:wpg=\"http://schemas.microsoft.com/office/word/2010/wordprocessingGroup\"";

pub fn root(name: &str) -> String {
    format!(
        "{}<w:{name} {NS_DECL}>",
        crate::formats::office::common::xmlout::XML_HEAD
    )
}

impl<'a> W<'a> {
    pub fn new(doc: &'a Document, limit: u64) -> W<'a> {
        W {
            doc,
            next_id: 1,
            parts: vec![],
            depth: 0,
            limit,
            over: false,
        }
    }

    pub fn blocks(&mut self, o: &mut String, blocks: &[Block], rels: &mut Rels) {
        for b in blocks {
            match b {
                Block::Para(p) => self.para(o, p, rels),
                Block::Table(t) => self.table(o, t, rels),
            }
            // The XML of a part is held whole before it is deflated, and it
            // is what the model's text and runs become with their markup.
            if o.len() as u64 > self.limit {
                self.over = true;
                return;
            }
        }
    }

    /// The content of a cell, note or text box: it must end with a
    /// paragraph.
    pub fn story(&mut self, o: &mut String, blocks: &[Block], rels: &mut Rels) {
        self.blocks(o, blocks, rels);
        if !matches!(blocks.last(), Some(Block::Para(_))) {
            o.push_str("<w:p/>");
        }
    }

    fn table(&mut self, o: &mut String, t: &Table, rels: &mut Rels) {
        // A DOCX table has a row; one without has nothing to show.
        if t.rows.is_empty() {
            return;
        }
        o.push_str("<w:tbl>");
        table_props(o, &t.props, true);
        o.push_str("<w:tblGrid>");
        for g in &t.grid {
            let _ = write!(o, "<w:gridCol w:w=\"{}\"/>", (*g).max(0));
        }
        o.push_str("</w:tblGrid>");
        for r in &t.rows {
            o.push_str("<w:tr>");
            row_props(o, &r.props);
            for c in &r.cells {
                o.push_str("<w:tc>");
                cell_props(o, &c.props);
                self.story(o, &c.content, rels);
                o.push_str("</w:tc>");
            }
            o.push_str("</w:tr>");
        }
        o.push_str("</w:tbl>");
    }

    fn para(&mut self, o: &mut String, p: &Para, rels: &mut Rels) {
        o.push_str("<w:p>");
        let sect = p
            .section
            .as_ref()
            .filter(|_| self.depth == 0)
            .map(|s| self.sect_pr(s, rels, false));
        para_props(o, &p.props, &p.mark, sect.as_deref());
        self.inlines(o, &p.content, rels);
        o.push_str("</w:p>");
    }

    fn inlines(&mut self, o: &mut String, content: &[Inline], rels: &mut Rels) {
        for i in content {
            match i {
                Inline::Run(r) => self.run(o, r, rels),
                Inline::FieldChar(k) => {
                    let t = match k {
                        FieldCharKind::Begin => "begin",
                        FieldCharKind::Separate => "separate",
                        FieldCharKind::End => "end",
                    };
                    let _ = write!(o, "<w:r><w:fldChar w:fldCharType=\"{t}\"/></w:r>");
                }
                Inline::InstrText(s) => {
                    o.push_str("<w:r><w:instrText xml:space=\"preserve\">");
                    esc_into(o, s);
                    o.push_str("</w:instrText></w:r>");
                }
                Inline::Field {
                    instr,
                    props,
                    result,
                } => {
                    o.push_str("<w:r>");
                    run_props(o, props);
                    o.push_str("<w:fldChar w:fldCharType=\"begin\"/></w:r><w:r>");
                    run_props(o, props);
                    o.push_str("<w:instrText xml:space=\"preserve\">");
                    esc_into(o, instr);
                    o.push_str("</w:instrText></w:r><w:r>");
                    run_props(o, props);
                    o.push_str("<w:fldChar w:fldCharType=\"separate\"/></w:r>");
                    self.inlines(o, result, rels);
                    o.push_str("<w:r>");
                    run_props(o, props);
                    o.push_str("<w:fldChar w:fldCharType=\"end\"/></w:r>");
                }
                Inline::Hyperlink {
                    target,
                    anchor,
                    tooltip,
                    content,
                } => {
                    o.push_str("<w:hyperlink");
                    if let Some(t) = target {
                        let id = rels.add(REL_HYPERLINK, t, true);
                        attr(o, "r:id", &id);
                    }
                    if let Some(a) = anchor {
                        attr(o, "w:anchor", a);
                    }
                    if let Some(t) = tooltip {
                        attr(o, "w:tooltip", t);
                    }
                    o.push('>');
                    self.inlines(o, content, rels);
                    o.push_str("</w:hyperlink>");
                }
                Inline::BookmarkStart { id, name } => {
                    let _ = write!(o, "<w:bookmarkStart w:id=\"{id}\"");
                    attr(o, "w:name", name);
                    o.push_str("/>");
                }
                Inline::BookmarkEnd(id) => {
                    let _ = write!(o, "<w:bookmarkEnd w:id=\"{id}\"/>");
                }
                Inline::CommentStart(id) => {
                    let _ = write!(o, "<w:commentRangeStart w:id=\"{id}\"/>");
                }
                Inline::CommentEnd(id) => {
                    let _ = write!(o, "<w:commentRangeEnd w:id=\"{id}\"/>");
                }
            }
        }
    }

    fn run(&mut self, o: &mut String, r: &Run, rels: &mut Rels) {
        if r.items.is_empty() {
            return;
        }
        o.push_str("<w:r>");
        run_props(o, &r.props);
        for it in &r.items {
            match it {
                RunItem::Text(t) => {
                    o.push_str("<w:t xml:space=\"preserve\">");
                    esc_into(o, t);
                    o.push_str("</w:t>");
                }
                RunItem::Tab => o.push_str("<w:tab/>"),
                RunItem::Break(k) => match k {
                    BreakKind::Line => o.push_str("<w:br/>"),
                    BreakKind::Page => o.push_str("<w:br w:type=\"page\"/>"),
                    BreakKind::Column => o.push_str("<w:br w:type=\"column\"/>"),
                },
                RunItem::NoBreakHyphen => o.push_str("<w:noBreakHyphen/>"),
                RunItem::SoftHyphen => o.push_str("<w:softHyphen/>"),
                RunItem::Symbol { font, ch } => {
                    o.push_str("<w:sym");
                    attr(o, "w:font", font);
                    let _ = write!(o, " w:char=\"{ch:04X}\"/>");
                }
                RunItem::FootnoteRef(id) => {
                    let _ = write!(o, "<w:footnoteReference w:id=\"{id}\"/>");
                }
                RunItem::EndnoteRef(id) => {
                    let _ = write!(o, "<w:endnoteReference w:id=\"{id}\"/>");
                }
                RunItem::NoteMark(endnote) => {
                    o.push_str(if *endnote {
                        "<w:endnoteRef/>"
                    } else {
                        "<w:footnoteRef/>"
                    });
                }
                RunItem::CommentRef(id) => {
                    let _ = write!(o, "<w:commentReference w:id=\"{id}\"/>");
                }
                RunItem::PageNumber => {
                    o.push_str("<w:fldChar w:fldCharType=\"begin\"/><w:instrText xml:space=\"preserve\"> PAGE </w:instrText><w:fldChar w:fldCharType=\"separate\"/><w:t>1</w:t><w:fldChar w:fldCharType=\"end\"/>");
                }
                RunItem::Drawing(d) => self.drawing(o, d, rels),
            }
        }
        o.push_str("</w:r>");
    }

    fn drawing(&mut self, o: &mut String, d: &Drawing, rels: &mut Rels) {
        let id = self.next_id;
        self.next_id += 1;
        let (cx, cy) = (d.cx.clamp(0, 1 << 40), d.cy.clamp(0, 1 << 40));
        o.push_str("<w:drawing>");
        match &d.anchor {
            None => {
                o.push_str("<wp:inline distT=\"0\" distB=\"0\" distL=\"0\" distR=\"0\">");
            }
            Some(a) => {
                let _ = write!(
                    o,
                    "<wp:anchor distT=\"{}\" distB=\"{}\" distL=\"{}\" distR=\"{}\" simplePos=\"0\" relativeHeight=\"{}\" behindDoc=\"{}\" locked=\"0\" layoutInCell=\"1\" allowOverlap=\"1\"><wp:simplePos x=\"0\" y=\"0\"/>",
                    a.dist[0].clamp(0, 1 << 32),
                    a.dist[1].clamp(0, 1 << 32),
                    a.dist[2].clamp(0, 1 << 32),
                    a.dist[3].clamp(0, 1 << 32),
                    251_658_240u64 + u64::from(a.z.min(1 << 24)),
                    u8::from(a.behind)
                );
                for (tag, rel, off, align) in [
                    ("positionH", a.h_rel, a.h_off, a.h_align),
                    ("positionV", a.v_rel, a.v_off, a.v_align),
                ] {
                    let _ = write!(o, "<wp:{tag} relativeFrom=\"{rel}\">");
                    match align {
                        Some(al) => {
                            let _ = write!(o, "<wp:align>{al}</wp:align>");
                        }
                        None => {
                            let _ = write!(
                                o,
                                "<wp:posOffset>{}</wp:posOffset>",
                                off.clamp(-(1 << 36), 1 << 36)
                            );
                        }
                    }
                    let _ = write!(o, "</wp:{tag}>");
                }
            }
        }
        let _ = write!(o, "<wp:extent cx=\"{cx}\" cy=\"{cy}\"/>");
        if let Some(a) = &d.anchor {
            o.push_str("<wp:effectExtent l=\"0\" t=\"0\" r=\"0\" b=\"0\"/>");
            match a.wrap {
                Wrap::None => o.push_str("<wp:wrapNone/>"),
                Wrap::Square => o.push_str("<wp:wrapSquare wrapText=\"bothSides\"/>"),
                Wrap::TopBottom => o.push_str("<wp:wrapTopAndBottom/>"),
                Wrap::Tight | Wrap::Through => {
                    o.push_str("<wp:wrapTight wrapText=\"bothSides\"><wp:wrapPolygon edited=\"0\"><wp:start x=\"0\" y=\"0\"/><wp:lineTo x=\"0\" y=\"21600\"/><wp:lineTo x=\"21600\" y=\"21600\"/><wp:lineTo x=\"21600\" y=\"0\"/><wp:lineTo x=\"0\" y=\"0\"/></wp:wrapPolygon></wp:wrapTight>");
                }
            }
        }
        let _ = write!(o, "<wp:docPr id=\"{id}\"");
        attr(o, "name", &d.name);
        if let Some(t) = &d.descr {
            attr(o, "descr", t);
        }
        o.push_str("/>");
        o.push_str("<wp:cNvGraphicFramePr/>");
        o.push_str("<a:graphic>");
        match &d.kind {
            DrawingKind::Picture { media, crop } => {
                let m = self.doc.media.get(*media);
                let target = m.map(|m| format!("media/image{}.{}", media + 1, m.ext));
                o.push_str("<a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/picture\"><pic:pic><pic:nvPicPr><pic:cNvPr");
                let _ = write!(o, " id=\"{id}\"");
                attr(o, "name", &d.name);
                o.push_str("/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill>");
                match target {
                    Some(t) => {
                        let rid = rels.add(REL_IMAGE, &t, false);
                        o.push_str("<a:blip");
                        attr(o, "r:embed", &rid);
                        o.push_str("/>");
                    }
                    None => o.push_str("<a:blip/>"),
                }
                if *crop != Crop::default() {
                    let _ = write!(
                        o,
                        "<a:srcRect l=\"{}\" t=\"{}\" r=\"{}\" b=\"{}\"/>",
                        crop.l, crop.t, crop.r, crop.b
                    );
                }
                let _ = write!(
                    o,
                    "<a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"{cx}\" cy=\"{cy}\"/></a:xfrm><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData>"
                );
            }
            DrawingKind::Shape(s) => {
                o.push_str("<a:graphicData uri=\"http://schemas.microsoft.com/office/word/2010/wordprocessingShape\"><wps:wsp>");
                o.push_str(if s.text.is_empty() {
                    "<wps:cNvSpPr/>"
                } else {
                    "<wps:cNvSpPr txBox=\"1\"/>"
                });
                o.push_str("<wps:spPr><a:xfrm");
                if s.rot != 0 {
                    let _ = write!(o, " rot=\"{}\"", s.rot);
                }
                if s.flip_h {
                    o.push_str(" flipH=\"1\"");
                }
                if s.flip_v {
                    o.push_str(" flipV=\"1\"");
                }
                let _ = write!(
                    o,
                    "><a:off x=\"0\" y=\"0\"/><a:ext cx=\"{cx}\" cy=\"{cy}\"/></a:xfrm><a:prstGeom prst=\"{}\"><a:avLst/></a:prstGeom>",
                    s.preset
                );
                match &s.fill {
                    Fill::None => o.push_str("<a:noFill/>"),
                    Fill::Solid(c) => {
                        let _ = write!(
                            o,
                            "<a:solidFill><a:srgbClr val=\"{}\"/></a:solidFill>",
                            hex(*c)
                        );
                    }
                }
                match &s.line {
                    None => o.push_str("<a:ln><a:noFill/></a:ln>"),
                    Some(l) => {
                        let c = match l.color {
                            Color::Rgb(v) => v,
                            Color::Auto => 0,
                        };
                        let _ = write!(
                            o,
                            "<a:ln w=\"{}\"><a:solidFill><a:srgbClr val=\"{}\"/></a:solidFill><a:prstDash val=\"{}\"/></a:ln>",
                            l.width.clamp(0, 1 << 24),
                            hex(c),
                            l.dash
                        );
                    }
                }
                o.push_str("</wps:spPr>");
                if !s.text.is_empty() {
                    o.push_str("<wps:txbx><w:txbxContent>");
                    let save = self.depth;
                    self.depth += 1;
                    self.story(o, &s.text, rels);
                    self.depth = save;
                    o.push_str("</w:txbxContent></wps:txbx>");
                }
                let _ = write!(
                    o,
                    "<wps:bodyPr rot=\"0\" lIns=\"{}\" tIns=\"{}\" rIns=\"{}\" bIns=\"{}\" anchor=\"{}\"><a:noAutofit/></wps:bodyPr></wps:wsp></a:graphicData>",
                    s.insets[0], s.insets[1], s.insets[2], s.insets[3], s.v_anchor
                );
            }
        }
        o.push_str("</a:graphic>");
        o.push_str(if d.anchor.is_some() {
            "</wp:anchor>"
        } else {
            "</wp:inline>"
        });
        o.push_str("</w:drawing>");
    }

    /// A w:sectPr for `s`, writing its headers and footers as parts.
    pub fn sect_pr(&mut self, s: &Section, rels: &mut Rels, last: bool) -> String {
        let mut o = String::from("<w:sectPr>");
        let _ = last;
        for (header, hf) in [(true, &s.headers), (false, &s.footers)] {
            for (kind, content) in [
                ("default", &hf.default),
                ("first", &hf.first),
                ("even", &hf.even),
            ] {
                let Some(blocks) = content else { continue };
                let n = self.parts.iter().filter(|p| p.header == header).count() + 1;
                let name = format!("{}{}.xml", if header { "header" } else { "footer" }, n);
                let mut xml = root(if header { "hdr" } else { "ftr" });
                let mut prels = Rels::default();
                let save = self.depth;
                self.depth += 1;
                self.story(&mut xml, blocks, &mut prels);
                self.depth = save;
                xml.push_str(if header { "</w:hdr>" } else { "</w:ftr>" });
                self.parts.push(HfPart {
                    name: name.clone(),
                    header,
                    xml,
                    rels: prels,
                });
                let rid = rels.add(if header { REL_HEADER } else { REL_FOOTER }, &name, false);
                let _ = write!(
                    o,
                    "<w:{}Reference w:type=\"{kind}\" r:id=\"{rid}\"/>",
                    if header { "header" } else { "footer" }
                );
            }
        }
        if s.kind != SectionType::NextPage {
            let k = match s.kind {
                SectionType::Continuous => "continuous",
                SectionType::EvenPage => "evenPage",
                SectionType::OddPage => "oddPage",
                SectionType::NextColumn => "nextColumn",
                SectionType::NextPage => "nextPage",
            };
            let _ = write!(o, "<w:type w:val=\"{k}\"/>");
        }
        let _ = write!(
            o,
            "<w:pgSz w:w=\"{}\" w:h=\"{}\"",
            s.width.max(0),
            s.height.max(0)
        );
        if s.landscape {
            o.push_str(" w:orient=\"landscape\"");
        }
        let _ = write!(
            o,
            "/><w:pgMar w:top=\"{}\" w:right=\"{}\" w:bottom=\"{}\" w:left=\"{}\" w:header=\"{}\" w:footer=\"{}\" w:gutter=\"{}\"/>",
            s.top,
            s.right,
            s.bottom,
            s.left,
            s.header.max(0),
            s.footer.max(0),
            s.gutter.max(0)
        );
        if !s.page_borders.is_empty() {
            o.push_str("<w:pgBorders>");
            let b = &s.page_borders;
            for (n, v) in [
                ("top", &b.top),
                ("left", &b.left),
                ("bottom", &b.bottom),
                ("right", &b.right),
            ] {
                if let Some(v) = v {
                    border(&mut o, n, v);
                }
            }
            o.push_str("</w:pgBorders>");
        }
        if let Some((start, count_by, distance)) = s.line_numbers {
            let _ = write!(
                o,
                "<w:lnNumType w:countBy=\"{}\" w:start=\"{}\" w:distance=\"{}\"/>",
                count_by.max(1),
                start,
                distance.max(0)
            );
        }
        if s.page_start.is_some() || s.page_fmt.is_some() {
            o.push_str("<w:pgNumType");
            if let Some(f) = s.page_fmt {
                attr(&mut o, "w:fmt", f);
            }
            if let Some(v) = s.page_start {
                let _ = write!(o, " w:start=\"{v}\"");
            }
            o.push_str("/>");
        }
        let c = &s.columns;
        if c.num > 1 || !c.widths.is_empty() {
            let _ = write!(o, "<w:cols w:num=\"{}\"", c.num.max(1));
            if c.separator {
                o.push_str(" w:sep=\"1\"");
            }
            if c.widths.is_empty() {
                let _ = write!(o, " w:space=\"{}\" w:equalWidth=\"1\"/>", c.space.max(0));
            } else {
                o.push_str(" w:equalWidth=\"0\">");
                for (w, sp) in &c.widths {
                    let _ = write!(
                        o,
                        "<w:col w:w=\"{}\" w:space=\"{}\"/>",
                        (*w).max(0),
                        (*sp).max(0)
                    );
                }
                o.push_str("</w:cols>");
            }
        }
        if let Some(v) = s.v_align {
            let _ = write!(o, "<w:vAlign w:val=\"{v}\"/>");
        }
        if s.title_page {
            o.push_str("<w:titlePg/>");
        }
        if let Some(d) = s.text_direction {
            let _ = write!(o, "<w:textDirection w:val=\"{d}\"/>");
        }
        if s.bidi {
            o.push_str("<w:bidi/>");
        }
        if s.rtl_gutter {
            o.push_str("<w:rtlGutter/>");
        }
        o.push_str("</w:sectPr>");
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::common::package::Zip;

    #[test]
    fn a_table_without_a_row_is_not_written() {
        let doc = Document {
            body: vec![
                Block::Table(Table {
                    props: TableProps::default(),
                    grid: vec![1],
                    rows: vec![],
                }),
                Block::Para(Para::default()),
            ],
            ..Document::default()
        };
        let bytes = crate::formats::office::docs::docx::write(&doc, 1 << 20).unwrap();
        let mut z = Zip::open(&bytes).unwrap();
        let body =
            String::from_utf8(z.read("word/document.xml", 1 << 20).unwrap().unwrap()).unwrap();
        assert!(
            !body.contains("<w:tbl>") && body.contains("<w:p>"),
            "{body}"
        );
    }

    /// The XML of the body is held whole before it is deflated, so a body that
    /// deflates to nothing still counts at its own size.
    #[test]
    fn a_body_that_deflates_small_is_still_refused_at_its_size() {
        let para = |text: &str| {
            Block::Para(Para {
                content: vec![Inline::Run(Run::text(RunProps::default(), text))],
                ..Para::default()
            })
        };
        let long = "a".repeat(1000);
        let doc = Document {
            body: (0..1000).map(|_| para(&long)).collect(),
            ..Document::default()
        };
        // About a megabyte of XML, a few kilobytes deflated.
        assert!(crate::formats::office::docs::docx::write(&doc, 2 << 20).is_ok());
        assert_eq!(
            crate::formats::office::docs::docx::write(&doc, 100 << 10),
            Err(crate::formats::office::docs::error::Error::TooLarge(
                "memory"
            ))
        );
    }
}
