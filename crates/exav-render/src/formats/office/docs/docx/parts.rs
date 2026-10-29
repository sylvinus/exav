//! styles.xml, numbering.xml, settings.xml, notes and comments.

use super::body::{Rels, W, root};
use super::props::*;
use crate::formats::office::common::xmlout::XML_HEAD;
use crate::formats::office::docs::model::*;
use std::fmt::Write;

const NS_W: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";

pub fn styles(doc: &Document) -> String {
    let mut o = String::from(XML_HEAD);
    let _ = write!(o, "<w:styles xmlns:w=\"{NS_W}\"><w:docDefaults>");
    o.push_str("<w:rPrDefault>");
    let mut rp = doc.defaults_run.clone();
    if rp.size.is_none() {
        rp.size = Some(20);
    }
    run_props(&mut o, &rp);
    o.push_str("</w:rPrDefault><w:pPrDefault>");
    let mut pp = String::new();
    para_props_body(&mut pp, &doc.defaults_para);
    if !pp.is_empty() {
        o.push_str("<w:pPr>");
        o.push_str(&pp);
        o.push_str("</w:pPr>");
    }
    o.push_str("</w:pPrDefault></w:docDefaults>");
    let has = |kind: StyleKind, default: bool| {
        doc.styles
            .iter()
            .any(|s| s.kind == kind && s.default == default)
    };
    if !has(StyleKind::Paragraph, true) {
        let n = Style {
            default: true,
            ..Style::new("Normal", "Normal", StyleKind::Paragraph)
        };
        style(&mut o, &n);
    }
    if !has(StyleKind::Character, true) {
        let n = Style {
            default: true,
            ..Style::new(
                "DefaultParagraphFont",
                "Default Paragraph Font",
                StyleKind::Character,
            )
        };
        style(&mut o, &n);
    }
    if !has(StyleKind::Table, true) {
        let mut n = Style {
            default: true,
            ..Style::new("TableNormal", "Normal Table", StyleKind::Table)
        };
        n.tbl = Some(TableProps {
            cell_margins: Margins {
                top: Some(0),
                left: Some(108),
                bottom: Some(0),
                right: Some(108),
            },
            ..TableProps::default()
        });
        style(&mut o, &n);
    }
    for s in &doc.styles {
        style(&mut o, s);
    }
    o.push_str("</w:styles>");
    o
}

fn style(o: &mut String, s: &Style) {
    let kind = match s.kind {
        StyleKind::Paragraph => "paragraph",
        StyleKind::Character => "character",
        StyleKind::Table => "table",
        StyleKind::Numbering => "numbering",
    };
    let _ = write!(o, "<w:style w:type=\"{kind}\"");
    if s.default {
        o.push_str(" w:default=\"1\"");
    }
    attr(o, "w:styleId", &s.id);
    o.push_str("><w:name");
    attr(o, "w:val", &s.name);
    o.push_str("/>");
    if let Some(b) = &s.based_on {
        o.push_str("<w:basedOn");
        attr(o, "w:val", b);
        o.push_str("/>");
    }
    if let Some(b) = &s.next {
        o.push_str("<w:next");
        attr(o, "w:val", b);
        o.push_str("/>");
    }
    if let Some(b) = &s.link {
        o.push_str("<w:link");
        attr(o, "w:val", b);
        o.push_str("/>");
    }
    if let Some(p) = s.ui_priority {
        let _ = write!(o, "<w:uiPriority w:val=\"{p}\"/>");
    }
    if s.hidden {
        o.push_str("<w:semiHidden/>");
    }
    if s.q_format {
        o.push_str("<w:qFormat/>");
    }
    if s.kind != StyleKind::Table || s.tbl.is_none() {
        let mut pp = String::new();
        para_props_body(&mut pp, &s.ppr);
        if !pp.is_empty() {
            o.push_str("<w:pPr>");
            o.push_str(&pp);
            o.push_str("</w:pPr>");
        }
    }
    run_props(o, &s.rpr);
    if let Some(t) = &s.tbl {
        table_props(o, t, false);
    }
    o.push_str("</w:style>");
}

fn level(o: &mut String, ilvl: usize, l: &Level, in_override: bool) {
    let _ = write!(o, "<w:lvl w:ilvl=\"{ilvl}\">");
    let _ = write!(o, "<w:start w:val=\"{}\"/>", l.start);
    let _ = write!(o, "<w:numFmt w:val=\"{}\"/>", l.fmt);
    if let Some(r) = l.restart {
        let _ = write!(o, "<w:lvlRestart w:val=\"{r}\"/>");
    }
    if let Some(s) = &l.style {
        o.push_str("<w:pStyle");
        attr(o, "w:val", s);
        o.push_str("/>");
    }
    if l.legal {
        o.push_str("<w:isLgl/>");
    }
    if l.suff != "tab" {
        let _ = write!(o, "<w:suff w:val=\"{}\"/>", l.suff);
    }
    o.push_str("<w:lvlText");
    attr(o, "w:val", &l.text);
    o.push_str("/>");
    let jc = match l.jc {
        Jc::Right => "right",
        Jc::Center => "center",
        _ => "left",
    };
    let _ = write!(o, "<w:lvlJc w:val=\"{jc}\"/>");
    let mut pp = String::new();
    para_props_body(&mut pp, &l.ppr);
    if !pp.is_empty() {
        o.push_str("<w:pPr>");
        o.push_str(&pp);
        o.push_str("</w:pPr>");
    }
    run_props(o, &l.rpr);
    let _ = in_override;
    o.push_str("</w:lvl>");
}

pub fn numbering(n: &Numbering) -> Option<String> {
    if n.abstracts.is_empty() && n.nums.is_empty() {
        return None;
    }
    let mut o = String::from(XML_HEAD);
    let _ = write!(o, "<w:numbering xmlns:w=\"{NS_W}\">");
    for a in &n.abstracts {
        let _ = write!(o, "<w:abstractNum w:abstractNumId=\"{}\">", a.id);
        let _ = write!(
            o,
            "<w:multiLevelType w:val=\"{}\"/>",
            if a.multi_level {
                "multilevel"
            } else {
                "singleLevel"
            }
        );
        for (i, l) in a.levels.iter().enumerate().take(9) {
            level(&mut o, i, l, false);
        }
        o.push_str("</w:abstractNum>");
    }
    for m in &n.nums {
        let _ = write!(
            o,
            "<w:num w:numId=\"{}\"><w:abstractNumId w:val=\"{}\"/>",
            m.id, m.abstract_id
        );
        for (lvl, start, def) in &m.overrides {
            let _ = write!(o, "<w:lvlOverride w:ilvl=\"{lvl}\">");
            if let Some(s) = start {
                let _ = write!(o, "<w:startOverride w:val=\"{s}\"/>");
            }
            if let Some(d) = def {
                level(&mut o, *lvl as usize, d, true);
            }
            o.push_str("</w:lvlOverride>");
        }
        o.push_str("</w:num>");
    }
    o.push_str("</w:numbering>");
    Some(o)
}

pub fn settings(doc: &Document) -> String {
    let s = &doc.settings;
    let mut o = String::from(XML_HEAD);
    let _ = write!(o, "<w:settings xmlns:w=\"{NS_W}\">");
    if s.mirror_margins {
        o.push_str("<w:mirrorMargins/>");
    }
    if s.gutter_at_top {
        o.push_str("<w:gutterAtTop/>");
    }
    let _ = write!(
        o,
        "<w:defaultTabStop w:val=\"{}\"/>",
        s.default_tab_stop.unwrap_or(720).max(1)
    );
    if s.even_and_odd_headers {
        o.push_str("<w:evenAndOddHeaders/>");
    }
    for (tag, pos, fmt, start, restart, has_sep) in [
        (
            "footnotePr",
            s.footnote_pos,
            s.footnote_fmt,
            s.footnote_start,
            s.footnote_restart,
            !doc.footnotes.is_empty(),
        ),
        (
            "endnotePr",
            None,
            s.endnote_fmt,
            s.endnote_start,
            s.endnote_restart,
            !doc.endnotes.is_empty(),
        ),
    ] {
        if pos.is_none() && fmt.is_none() && start.is_none() && restart.is_none() && !has_sep {
            continue;
        }
        let _ = write!(o, "<w:{tag}>");
        if let Some(p) = pos {
            let _ = write!(o, "<w:pos w:val=\"{p}\"/>");
        }
        if let Some(f) = fmt {
            let _ = write!(o, "<w:numFmt w:val=\"{f}\"/>");
        }
        if let Some(v) = start {
            let _ = write!(o, "<w:numStart w:val=\"{v}\"/>");
        }
        if let Some(r) = restart {
            let _ = write!(o, "<w:numRestart w:val=\"{r}\"/>");
        }
        let n = if tag == "footnotePr" {
            "footnote"
        } else {
            "endnote"
        };
        if has_sep {
            let _ = write!(o, "<w:{n} w:id=\"-1\"/><w:{n} w:id=\"0\"/>");
        }
        let _ = write!(o, "</w:{tag}>");
    }
    o.push_str("<w:compat><w:compatSetting w:name=\"compatibilityMode\" w:uri=\"http://schemas.microsoft.com/office/word\" w:val=\"15\"/></w:compat></w:settings>");
    o
}

pub fn notes(w: &mut W, notes: &[Note], endnotes: bool, rels: &mut Rels) -> String {
    let tag = if endnotes { "endnote" } else { "footnote" };
    let mut o = root(if endnotes { "endnotes" } else { "footnotes" });
    let _ = write!(
        o,
        "<w:{tag} w:type=\"separator\" w:id=\"-1\"><w:p><w:r><w:separator/></w:r></w:p></w:{tag}><w:{tag} w:type=\"continuationSeparator\" w:id=\"0\"><w:p><w:r><w:continuationSeparator/></w:r></w:p></w:{tag}>"
    );
    w.depth += 1;
    for n in notes {
        let _ = write!(o, "<w:{tag} w:id=\"{}\">", n.id);
        w.story(&mut o, &n.content, rels);
        let _ = write!(o, "</w:{tag}>");
    }
    w.depth -= 1;
    let _ = write!(
        o,
        "</w:{}>",
        if endnotes { "endnotes" } else { "footnotes" }
    );
    o
}

pub fn comments(w: &mut W, comments: &[Comment], rels: &mut Rels) -> String {
    let mut o = root("comments");
    w.depth += 1;
    for c in comments {
        let _ = write!(o, "<w:comment w:id=\"{}\"", c.id);
        attr(&mut o, "w:author", &c.author);
        if let Some(d) = &c.date {
            attr(&mut o, "w:date", d);
        }
        attr(&mut o, "w:initials", &c.initials);
        o.push('>');
        w.story(&mut o, &c.content, rels);
        o.push_str("</w:comment>");
    }
    w.depth -= 1;
    o.push_str("</w:comments>");
    o
}
