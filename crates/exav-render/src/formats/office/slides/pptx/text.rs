//! Text bodies, paragraphs and runs as DrawingML.

use super::draw::{Ctx, angle, color, line, solid};
use super::xml::{esc, esc_into};
use crate::formats::office::slides::model::*;
use std::fmt::Write as _;

pub fn write_text_body(o: &mut String, tag: &str, t: &TextBody, ctx: &mut Ctx) {
    let _ = write!(o, "<{tag}>");
    body_pr(o, &t.body);
    list_style(o, "a:lstStyle", &t.levels, ctx);
    if t.paras.is_empty() {
        o.push_str("<a:p><a:endParaRPr lang=\"en-US\"/></a:p>");
    }
    for p in &t.paras {
        paragraph(o, p, ctx);
    }
    let _ = write!(o, "</{tag}>");
}

fn body_pr(o: &mut String, b: &BodyProps) {
    o.push_str("<a:bodyPr");
    let rot = angle(b.rot);
    if rot != 0 {
        let _ = write!(o, " rot=\"{rot}\"");
    }
    if let Some(v) = b.vert {
        let _ = write!(o, " vert=\"{v}\"");
    }
    let _ = write!(
        o,
        " wrap=\"{}\" lIns=\"{}\" tIns=\"{}\" rIns=\"{}\" bIns=\"{}\"",
        if b.wrap { "square" } else { "none" },
        b.insets[0].max(0),
        b.insets[1].max(0),
        b.insets[2].max(0),
        b.insets[3].max(0)
    );
    if b.columns > 1 {
        let _ = write!(o, " numCol=\"{}\"", b.columns.min(16));
    }
    let _ = write!(o, " anchor=\"{}\"", b.anchor);
    if b.anchor_ctr {
        o.push_str(" anchorCtr=\"1\"");
    }
    o.push_str(" rtlCol=\"0\">");
    match b.autofit {
        Autofit::None => o.push_str("<a:noAutofit/>"),
        Autofit::Shape => o.push_str("<a:spAutoFit/>"),
        Autofit::Normal(scale, reduce) => {
            o.push_str("<a:normAutofit");
            if scale < 100_000 {
                let _ = write!(o, " fontScale=\"{}\"", scale.max(1000));
            }
            if reduce > 0 {
                let _ = write!(o, " lnSpcReduction=\"{}\"", reduce.min(100_000));
            }
            o.push_str("/>");
        }
    }
    o.push_str("</a:bodyPr>");
}

/// A list style: `a:lstStyle`, or a master's `p:titleStyle`...
pub fn list_style(o: &mut String, tag: &str, l: &ListStyle, ctx: &mut Ctx) {
    if l.is_empty() {
        if tag == "a:lstStyle" {
            o.push_str("<a:lstStyle/>");
        } else {
            let _ = write!(o, "<{tag}/>");
        }
        return;
    }
    let _ = write!(o, "<{tag}>");
    for (i, lvl) in l.levels.iter().enumerate() {
        if let Some((p, r)) = lvl {
            para_pr(o, &format!("a:lvl{}pPr", i + 1), p, Some(r), false, ctx);
        }
    }
    let _ = write!(o, "</{tag}>");
}

fn spacing(o: &mut String, tag: &str, s: &Option<Spacing>) {
    match s {
        Some(Spacing::Pct(v)) => {
            let _ = write!(
                o,
                "<a:{tag}><a:spcPct val=\"{}\"/></a:{tag}>",
                v.clamp(&0, &13_200_000)
            );
        }
        Some(Spacing::Pts(v)) => {
            let _ = write!(
                o,
                "<a:{tag}><a:spcPts val=\"{}\"/></a:{tag}>",
                v.clamp(&0, &158_400)
            );
        }
        None => {}
    }
}

/// `a:pPr` or a level's `a:lvlNpPr`; `with_level` writes `lvl`.
fn para_pr(
    o: &mut String,
    tag: &str,
    p: &ParaProps,
    def: Option<&RunProps>,
    with_level: bool,
    ctx: &mut Ctx,
) {
    let _ = write!(o, "<{tag}");
    if let Some(m) = p.margin {
        let _ = write!(o, " marL=\"{}\"", m.clamp(0, 51_206_400));
    }
    if let Some(i) = p.indent {
        let _ = write!(o, " indent=\"{}\"", i.clamp(-51_206_400, 51_206_400));
    }
    if with_level && p.level > 0 {
        let _ = write!(o, " lvl=\"{}\"", p.level.min(8));
    }
    if let Some(a) = p.align {
        let _ = write!(o, " algn=\"{a}\"");
    }
    if let Some(t) = p.default_tab {
        let _ = write!(o, " defTabSz=\"{}\"", t.clamp(0, 51_206_400));
    }
    if p.rtl {
        o.push_str(" rtl=\"1\"");
    }
    o.push('>');
    spacing(o, "lnSpc", &p.line_spacing);
    spacing(o, "spcBef", &p.space_before);
    spacing(o, "spcAft", &p.space_after);
    match &p.bullet {
        Some(Bullet::None) => o.push_str("<a:buNone/>"),
        Some(Bullet::Char {
            ch,
            font,
            color: c,
            size,
        }) => {
            bullet_style(o, c, size, font);
            let _ = write!(o, "<a:buChar char=\"{}\"/>", esc(&ch.to_string()));
        }
        Some(Bullet::AutoNum {
            scheme,
            start,
            font,
            color: c,
            size,
        }) => {
            bullet_style(o, c, size, font);
            let _ = write!(o, "<a:buAutoNum type=\"{scheme}\"");
            if *start > 1 {
                let _ = write!(o, " startAt=\"{}\"", start.min(&32767));
            }
            o.push_str("/>");
        }
        Some(Bullet::Picture { media, size }) => match ctx.image(*media) {
            Some(rid) => {
                bullet_style(o, &None, size, &None);
                let _ = write!(o, "<a:buBlip><a:blip r:embed=\"{rid}\"/></a:buBlip>");
            }
            None => o.push_str("<a:buChar char=\"&#8226;\"/>"),
        },
        None => {}
    }
    if !p.tabs.is_empty() {
        o.push_str("<a:tabLst>");
        for (pos, algn) in p.tabs.iter().take(32) {
            let _ = write!(
                o,
                "<a:tab pos=\"{}\" algn=\"{algn}\"/>",
                pos.clamp(&0, &51_206_400)
            );
        }
        o.push_str("</a:tabLst>");
    }
    if let Some(r) = def {
        run_pr(o, "a:defRPr", r, ctx);
    }
    let _ = write!(o, "</{tag}>");
}

fn bullet_style(o: &mut String, c: &Option<Color>, size: &Option<u32>, font: &Option<String>) {
    if let Some(c) = c {
        o.push_str("<a:buClr>");
        color(o, c);
        o.push_str("</a:buClr>");
    }
    if let Some(s) = size {
        let _ = write!(o, "<a:buSzPct val=\"{}\"/>", (*s).clamp(25_000, 400_000));
    }
    if let Some(f) = font {
        let _ = write!(o, "<a:buFont typeface=\"{}\"/>", esc(f));
    }
}

pub fn run_pr(o: &mut String, tag: &str, r: &RunProps, ctx: &mut Ctx) {
    let _ = write!(o, "<{tag}");
    match &r.lang {
        Some(l) => {
            let _ = write!(o, " lang=\"{}\"", esc(l));
        }
        None if tag != "a:defRPr" => o.push_str(" lang=\"en-US\""),
        None => {}
    }
    if let Some(s) = r.size {
        let _ = write!(o, " sz=\"{}\"", s.clamp(100, 400_000));
    }
    if let Some(b) = r.bold {
        let _ = write!(o, " b=\"{}\"", u8::from(b));
    }
    if let Some(i) = r.italic {
        let _ = write!(o, " i=\"{}\"", u8::from(i));
    }
    if let Some(u) = r.underline {
        let _ = write!(o, " u=\"{u}\"");
    }
    if let Some(s) = r.strike {
        let _ = write!(o, " strike=\"{s}\"");
    }
    if let Some(c) = r.caps {
        let _ = write!(o, " cap=\"{c}\"");
    }
    if let Some(s) = r.spacing {
        let _ = write!(o, " spc=\"{}\"", s.clamp(-400_000, 400_000));
    }
    if let Some(b) = r.baseline
        && b != 0
    {
        let _ = write!(o, " baseline=\"{}\"", b.clamp(-1_000_000, 1_000_000));
    }
    o.push('>');
    if let Some(l) = &r.outline {
        line(o, l, ctx);
    }
    if let Some(c) = &r.color {
        solid(o, c);
    }
    if let Some(s) = &r.shadow {
        let _ = write!(
            o,
            "<a:effectLst><a:outerShdw blurRad=\"{}\" dist=\"{}\" dir=\"{}\" algn=\"ctr\" rotWithShape=\"0\">",
            s.blur.max(0),
            s.dist.max(0),
            angle(s.dir)
        );
        color(o, &s.color);
        o.push_str("</a:outerShdw></a:effectLst>");
    }
    if let Some(h) = &r.highlight {
        o.push_str("<a:highlight>");
        color(o, h);
        o.push_str("</a:highlight>");
    }
    for (t, f) in [
        ("latin", &r.font),
        ("ea", &r.ea_font),
        ("cs", &r.cs_font),
        ("sym", &r.sym_font),
    ] {
        if let Some(f) = f {
            let _ = write!(o, "<a:{t} typeface=\"{}\"/>", esc(f));
        }
    }
    if let Some(l) = &r.link
        && let Some(attrs) = ctx.link_attrs(l)
    {
        let _ = write!(o, "<a:hlinkClick{attrs}/>");
    }
    let _ = write!(o, "</{tag}>");
}

fn paragraph(o: &mut String, p: &Paragraph, ctx: &mut Ctx) {
    o.push_str("<a:p>");
    if p.props != ParaProps::default() {
        para_pr(o, "a:pPr", &p.props, None, true, ctx);
    }
    let mut field = 0u32;
    for r in &p.runs {
        match &r.kind {
            RunKind::Text(t) => {
                if t.is_empty() {
                    continue;
                }
                o.push_str("<a:r>");
                run_pr(o, "a:rPr", &r.props, ctx);
                o.push_str("<a:t>");
                esc_into(o, t);
                o.push_str("</a:t></a:r>");
            }
            RunKind::Break => {
                o.push_str("<a:br>");
                run_pr(o, "a:rPr", &r.props, ctx);
                o.push_str("</a:br>");
            }
            RunKind::Field(kind, text) => {
                field += 1;
                let _ = write!(
                    o,
                    "<a:fld id=\"{{B6F15528-21DE-4FAA-801E-634DDDAF4B{:02X}}}\" type=\"{kind}\">",
                    field.min(255)
                );
                run_pr(o, "a:rPr", &r.props, ctx);
                o.push_str("<a:t>");
                esc_into(o, text);
                o.push_str("</a:t></a:fld>");
            }
        }
    }
    run_pr(o, "a:endParaRPr", &p.end, ctx);
    o.push_str("</a:p>");
}
