//! Property elements (WordprocessingML w:rPr, w:pPr, w:tblPr, ...) written in
//! schema order.

use crate::formats::office::common::xmlout::{esc_into, hex};
use crate::formats::office::docs::model::*;
use std::fmt::Write;

pub fn attr(o: &mut String, k: &str, v: &str) {
    o.push(' ');
    o.push_str(k);
    o.push_str("=\"");
    esc_into(o, v);
    o.push('"');
}

fn num_attr(o: &mut String, k: &str, v: impl std::fmt::Display) {
    let _ = write!(o, " {k}=\"{v}\"");
}

fn color_val(c: Color) -> String {
    match c {
        Color::Auto => "auto".to_string(),
        Color::Rgb(v) => hex(v),
    }
}

/// `<w:name w:val="..."/>` for a boolean toggle.
fn toggle(o: &mut String, name: &str, v: Option<bool>) {
    match v {
        Some(true) => {
            let _ = write!(o, "<w:{name}/>");
        }
        Some(false) => {
            let _ = write!(o, "<w:{name} w:val=\"0\"/>");
        }
        None => {}
    }
}

pub fn border(o: &mut String, name: &str, b: &Border) {
    let _ = write!(o, "<w:{name}");
    attr(o, "w:val", b.style);
    num_attr(
        o,
        "w:sz",
        b.size
            .clamp(2, 96)
            .max(if b.style == "nil" || b.style == "none" {
                0
            } else {
                2
            }),
    );
    num_attr(o, "w:space", b.space.min(31));
    attr(o, "w:color", &color_val(b.color));
    if b.shadow {
        o.push_str(" w:shadow=\"1\"");
    }
    o.push_str("/>");
}

pub fn shading(o: &mut String, s: &Shading) {
    o.push_str("<w:shd");
    attr(o, "w:val", s.pattern);
    attr(
        o,
        "w:color",
        &s.color.map(color_val).unwrap_or_else(|| "auto".into()),
    );
    attr(
        o,
        "w:fill",
        &s.fill.map(color_val).unwrap_or_else(|| "auto".into()),
    );
    o.push_str("/>");
}

pub fn run_props_body(o: &mut String, p: &RunProps) {
    if let Some(s) = &p.style {
        o.push_str("<w:rStyle");
        attr(o, "w:val", s);
        o.push_str("/>");
    }
    let f = &p.fonts;
    if f.ascii.is_some() || f.hansi.is_some() || f.east_asia.is_some() || f.cs.is_some() {
        o.push_str("<w:rFonts");
        if let Some(v) = &f.ascii {
            attr(o, "w:ascii", v);
        }
        if let Some(v) = &f.hansi {
            attr(o, "w:hAnsi", v);
        }
        if let Some(v) = &f.east_asia {
            attr(o, "w:eastAsia", v);
        }
        if let Some(v) = &f.cs {
            attr(o, "w:cs", v);
        }
        o.push_str("/>");
    }
    toggle(o, "b", p.bold);
    toggle(o, "bCs", p.bold_cs);
    toggle(o, "i", p.italic);
    toggle(o, "iCs", p.italic_cs);
    toggle(o, "caps", p.caps);
    toggle(o, "smallCaps", p.small_caps);
    toggle(o, "strike", p.strike);
    toggle(o, "dstrike", p.dstrike);
    toggle(o, "outline", p.outline);
    toggle(o, "shadow", p.shadow);
    toggle(o, "emboss", p.emboss);
    toggle(o, "imprint", p.imprint);
    toggle(o, "vanish", p.vanish);
    if let Some(c) = p.color {
        o.push_str("<w:color");
        attr(o, "w:val", &color_val(c));
        o.push_str("/>");
    }
    if let Some(v) = p.spacing {
        let _ = write!(o, "<w:spacing w:val=\"{v}\"/>");
    }
    if let Some(v) = p.scale {
        let _ = write!(o, "<w:w w:val=\"{}\"/>", v.clamp(1, 600));
    }
    if let Some(v) = p.kerning {
        let _ = write!(o, "<w:kern w:val=\"{v}\"/>");
    }
    if let Some(v) = p.position {
        let _ = write!(o, "<w:position w:val=\"{v}\"/>");
    }
    if let Some(v) = p.size {
        let _ = write!(o, "<w:sz w:val=\"{}\"/>", v.clamp(1, 3277));
    }
    if let Some(v) = p.size_cs {
        let _ = write!(o, "<w:szCs w:val=\"{}\"/>", v.clamp(1, 3277));
    }
    if let Some(h) = p.highlight {
        o.push_str("<w:highlight");
        attr(o, "w:val", h);
        o.push_str("/>");
    }
    if let Some(u) = p.underline {
        o.push_str("<w:u");
        attr(o, "w:val", u);
        if let Some(c) = p.underline_color {
            attr(o, "w:color", &color_val(c));
        }
        o.push_str("/>");
    }
    if let Some(b) = &p.border {
        border(o, "bdr", b);
    }
    if let Some(s) = &p.shading {
        shading(o, s);
    }
    if let Some(v) = p.vert_align {
        let v = match v {
            VertAlign::Baseline => "baseline",
            VertAlign::Superscript => "superscript",
            VertAlign::Subscript => "subscript",
        };
        let _ = write!(o, "<w:vertAlign w:val=\"{v}\"/>");
    }
    toggle(o, "rtl", p.rtl);
    toggle(o, "cs", p.cs);
    if p.lang.is_some() || p.lang_east_asia.is_some() || p.lang_bidi.is_some() {
        o.push_str("<w:lang");
        if let Some(v) = &p.lang {
            attr(o, "w:val", v);
        }
        if let Some(v) = &p.lang_east_asia {
            attr(o, "w:eastAsia", v);
        }
        if let Some(v) = &p.lang_bidi {
            attr(o, "w:bidi", v);
        }
        o.push_str("/>");
    }
}

pub fn run_props(o: &mut String, p: &RunProps) {
    let mut b = String::new();
    run_props_body(&mut b, p);
    if !b.is_empty() {
        o.push_str("<w:rPr>");
        o.push_str(&b);
        o.push_str("</w:rPr>");
    }
}

fn jc_val(j: Jc) -> &'static str {
    match j {
        Jc::Left => "left",
        Jc::Center => "center",
        Jc::Right => "right",
        Jc::Both => "both",
        Jc::Distribute => "distribute",
    }
}

fn frame_pr(o: &mut String, f: &Frame) {
    o.push_str("<w:framePr");
    if let Some(v) = f.drop_cap {
        attr(o, "w:dropCap", v);
    }
    if let Some(v) = f.lines {
        num_attr(o, "w:lines", v);
    }
    if let Some(v) = f.width {
        num_attr(o, "w:w", v);
    }
    if let Some(v) = f.height {
        num_attr(o, "w:h", v);
        attr(
            o,
            "w:hRule",
            if f.height_exact { "exact" } else { "atLeast" },
        );
    }
    if let Some(v) = f.h_space {
        num_attr(o, "w:hSpace", v);
    }
    if let Some(v) = f.v_space {
        num_attr(o, "w:vSpace", v);
    }
    if let Some(v) = f.wrap {
        attr(o, "w:wrap", v);
    }
    if let Some(v) = f.h_anchor {
        attr(o, "w:hAnchor", v);
    }
    if let Some(v) = f.v_anchor {
        attr(o, "w:vAnchor", v);
    }
    if let Some(v) = f.x {
        num_attr(o, "w:x", v);
    }
    if let Some(v) = f.x_align {
        attr(o, "w:xAlign", v);
    }
    if let Some(v) = f.y {
        num_attr(o, "w:y", v);
    }
    if let Some(v) = f.y_align {
        attr(o, "w:yAlign", v);
    }
    o.push_str("/>");
}

/// The children of a w:pPr, in schema order, without the paragraph mark's
/// run properties.
pub fn para_props_body(o: &mut String, p: &ParaProps) {
    if let Some(s) = &p.style {
        o.push_str("<w:pStyle");
        attr(o, "w:val", s);
        o.push_str("/>");
    }
    toggle(o, "keepNext", p.keep_next);
    toggle(o, "keepLines", p.keep_lines);
    toggle(o, "pageBreakBefore", p.page_break_before);
    if let Some(f) = &p.frame {
        frame_pr(o, f);
    }
    toggle(o, "widowControl", p.widow_control);
    if p.num_id.is_some() || p.num_level.is_some() {
        o.push_str("<w:numPr>");
        if let Some(l) = p.num_level {
            let _ = write!(o, "<w:ilvl w:val=\"{}\"/>", l.min(8));
        }
        if let Some(n) = p.num_id {
            let _ = write!(o, "<w:numId w:val=\"{n}\"/>");
        }
        o.push_str("</w:numPr>");
    }
    toggle(o, "suppressLineNumbers", p.suppress_line_numbers);
    if !p.borders.is_empty() {
        o.push_str("<w:pBdr>");
        let b = &p.borders;
        for (name, v) in [
            ("top", &b.top),
            ("left", &b.left),
            ("bottom", &b.bottom),
            ("right", &b.right),
            ("between", &b.between),
        ] {
            if let Some(v) = v {
                border(o, name, v);
            }
        }
        o.push_str("</w:pBdr>");
    }
    if let Some(s) = &p.shading {
        shading(o, s);
    }
    if !p.tabs.is_empty() {
        o.push_str("<w:tabs>");
        for t in p.tabs.iter().take(64) {
            let kind = match t.kind {
                TabKind::Left => "left",
                TabKind::Center => "center",
                TabKind::Right => "right",
                TabKind::Decimal => "decimal",
                TabKind::Bar => "bar",
                TabKind::Clear => "clear",
            };
            let leader = match t.leader {
                TabLeader::None => "none",
                TabLeader::Dot => "dot",
                TabLeader::Hyphen => "hyphen",
                TabLeader::Underscore => "underscore",
                TabLeader::MiddleDot => "middleDot",
                TabLeader::Heavy => "heavy",
            };
            let _ = write!(
                o,
                "<w:tab w:val=\"{kind}\" w:leader=\"{leader}\" w:pos=\"{}\"/>",
                t.pos
            );
        }
        o.push_str("</w:tabs>");
    }
    toggle(o, "bidi", p.bidi);
    toggle(o, "snapToGrid", p.snap_to_grid);
    if p.space_before.is_some()
        || p.space_after.is_some()
        || p.line.is_some()
        || p.before_auto.is_some()
        || p.after_auto.is_some()
    {
        o.push_str("<w:spacing");
        if let Some(v) = p.space_before {
            num_attr(o, "w:before", v.max(0));
        }
        if let Some(v) = p.before_auto {
            num_attr(o, "w:beforeAutospacing", u8::from(v));
        }
        if let Some(v) = p.space_after {
            num_attr(o, "w:after", v.max(0));
        }
        if let Some(v) = p.after_auto {
            num_attr(o, "w:afterAutospacing", u8::from(v));
        }
        if let Some(v) = p.line {
            num_attr(o, "w:line", v.max(0));
            attr(
                o,
                "w:lineRule",
                match p.line_rule.unwrap_or(LineRule::Auto) {
                    LineRule::Auto => "auto",
                    LineRule::Exact => "exact",
                    LineRule::AtLeast => "atLeast",
                },
            );
        }
        o.push_str("/>");
    }
    if p.ind_left.is_some()
        || p.ind_right.is_some()
        || p.ind_first_line.is_some()
        || p.ind_hanging.is_some()
    {
        o.push_str("<w:ind");
        if let Some(v) = p.ind_left {
            num_attr(o, "w:left", v);
        }
        if let Some(v) = p.ind_right {
            num_attr(o, "w:right", v);
        }
        if let Some(v) = p.ind_hanging {
            num_attr(o, "w:hanging", v.max(0));
        } else if let Some(v) = p.ind_first_line {
            num_attr(o, "w:firstLine", v.max(0));
        }
        o.push_str("/>");
    }
    toggle(o, "contextualSpacing", p.contextual_spacing);
    if let Some(j) = p.jc {
        let _ = write!(o, "<w:jc w:val=\"{}\"/>", jc_val(j));
    }
    if let Some(l) = p.outline_level {
        let _ = write!(o, "<w:outlineLvl w:val=\"{}\"/>", l.min(9));
    }
}

pub fn para_props(o: &mut String, p: &ParaProps, mark: &RunProps, section: Option<&str>) {
    let mut b = String::new();
    para_props_body(&mut b, p);
    run_props(&mut b, mark);
    if let Some(s) = section {
        b.push_str(s);
    }
    if !b.is_empty() {
        o.push_str("<w:pPr>");
        o.push_str(&b);
        o.push_str("</w:pPr>");
    }
}

pub fn width(o: &mut String, name: &str, w: Width) {
    match w {
        Width::Auto => {
            let _ = write!(o, "<w:{name} w:w=\"0\" w:type=\"auto\"/>");
        }
        Width::Twips(v) => {
            let _ = write!(o, "<w:{name} w:w=\"{v}\" w:type=\"dxa\"/>");
        }
        Width::Pct(v) => {
            let _ = write!(o, "<w:{name} w:w=\"{v}\" w:type=\"pct\"/>");
        }
    }
}

fn margins(o: &mut String, name: &str, m: &Margins) {
    if m.top.is_none() && m.left.is_none() && m.bottom.is_none() && m.right.is_none() {
        return;
    }
    let _ = write!(o, "<w:{name}>");
    for (n, v) in [
        ("top", m.top),
        ("left", m.left),
        ("bottom", m.bottom),
        ("right", m.right),
    ] {
        if let Some(v) = v {
            let _ = write!(o, "<w:{n} w:w=\"{}\" w:type=\"dxa\"/>", v.max(0));
        }
    }
    let _ = write!(o, "</w:{name}>");
}

fn table_borders(o: &mut String, name: &str, b: &TableBorders, cell: bool) {
    let any = b.top.is_some()
        || b.left.is_some()
        || b.bottom.is_some()
        || b.right.is_some()
        || b.inside_h.is_some()
        || b.inside_v.is_some();
    if !any {
        return;
    }
    let _ = write!(o, "<w:{name}>");
    let all = [
        ("top", &b.top),
        ("left", &b.left),
        ("bottom", &b.bottom),
        ("right", &b.right),
        ("insideH", &b.inside_h),
        ("insideV", &b.inside_v),
    ];
    for (n, v) in all {
        if let Some(v) = v {
            border(o, n, v);
        }
    }
    let _ = cell;
    let _ = write!(o, "</w:{name}>");
}

pub fn table_props(o: &mut String, t: &TableProps, with_style: bool) {
    let mut b = String::new();
    if with_style && let Some(s) = &t.style {
        b.push_str("<w:tblStyle");
        attr(&mut b, "w:val", s);
        b.push_str("/>");
    }
    if let Some(f) = &t.float {
        b.push_str("<w:tblpPr");
        if let Some(v) = f.h_anchor {
            attr(&mut b, "w:horzAnchor", v);
        }
        if let Some(v) = f.v_anchor {
            attr(&mut b, "w:vertAnchor", v);
        }
        if let Some(v) = f.x {
            num_attr(&mut b, "w:tblpX", v);
        }
        if let Some(v) = f.y {
            num_attr(&mut b, "w:tblpY", v);
        }
        if let Some(v) = f.x_align {
            attr(&mut b, "w:tblpXSpec", v);
        }
        if let Some(v) = f.y_align {
            attr(&mut b, "w:tblpYSpec", v);
        }
        b.push_str("/>");
    }
    if t.bidi {
        b.push_str("<w:bidiVisual/>");
    }
    if let Some(w) = t.width {
        width(&mut b, "tblW", w);
    }
    if let Some(j) = t.jc {
        let _ = write!(b, "<w:jc w:val=\"{}\"/>", jc_val(j));
    }
    if let Some(v) = t.cell_spacing {
        let _ = write!(b, "<w:tblCellSpacing w:w=\"{v}\" w:type=\"dxa\"/>");
    }
    if let Some(v) = t.indent {
        let _ = write!(b, "<w:tblInd w:w=\"{v}\" w:type=\"dxa\"/>");
    }
    table_borders(&mut b, "tblBorders", &t.borders, false);
    if let Some(s) = &t.shading {
        shading(&mut b, s);
    }
    if t.fixed_layout {
        b.push_str("<w:tblLayout w:type=\"fixed\"/>");
    }
    margins(&mut b, "tblCellMar", &t.cell_margins);
    if !b.is_empty() || with_style {
        o.push_str("<w:tblPr>");
        o.push_str(&b);
        o.push_str("</w:tblPr>");
    }
}

pub fn row_props(o: &mut String, r: &RowProps) {
    let mut b = String::new();
    if r.grid_before > 0 {
        let _ = write!(b, "<w:gridBefore w:val=\"{}\"/>", r.grid_before);
    }
    if r.grid_after > 0 {
        let _ = write!(b, "<w:gridAfter w:val=\"{}\"/>", r.grid_after);
    }
    if let Some(w) = r.width_before {
        width(&mut b, "wBefore", w);
    }
    if let Some(w) = r.width_after {
        width(&mut b, "wAfter", w);
    }
    if r.cant_split {
        b.push_str("<w:cantSplit/>");
    }
    if let Some(h) = r.height {
        let _ = write!(
            b,
            "<w:trHeight w:val=\"{}\" w:hRule=\"{}\"/>",
            h.max(0),
            if r.height_exact { "exact" } else { "atLeast" }
        );
    }
    if r.header {
        b.push_str("<w:tblHeader/>");
    }
    if let Some(j) = r.jc {
        let _ = write!(b, "<w:jc w:val=\"{}\"/>", jc_val(j));
    }
    if !b.is_empty() {
        o.push_str("<w:trPr>");
        o.push_str(&b);
        o.push_str("</w:trPr>");
    }
}

pub fn cell_props(o: &mut String, c: &CellProps) {
    let mut b = String::new();
    if let Some(w) = c.width {
        width(&mut b, "tcW", w);
    }
    if c.grid_span > 1 {
        let _ = write!(b, "<w:gridSpan w:val=\"{}\"/>", c.grid_span);
    }
    match c.v_merge {
        VMerge::None => {}
        VMerge::Restart => b.push_str("<w:vMerge w:val=\"restart\"/>"),
        VMerge::Continue => b.push_str("<w:vMerge/>"),
    }
    table_borders(&mut b, "tcBorders", &c.borders, true);
    if let Some(s) = &c.shading {
        shading(&mut b, s);
    }
    if c.no_wrap {
        b.push_str("<w:noWrap/>");
    }
    margins(&mut b, "tcMar", &c.margins);
    if let Some(d) = c.text_direction {
        let _ = write!(b, "<w:textDirection w:val=\"{d}\"/>");
    }
    if c.fit_text {
        b.push_str("<w:tcFitText/>");
    }
    if let Some(v) = c.v_align {
        let v = match v {
            VAlign::Top => "top",
            VAlign::Center => "center",
            VAlign::Bottom => "bottom",
        };
        let _ = write!(b, "<w:vAlign w:val=\"{v}\"/>");
    }
    if !b.is_empty() {
        o.push_str("<w:tcPr>");
        o.push_str(&b);
        o.push_str("</w:tcPr>");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_properties_come_in_schema_order() {
        let p = RunProps {
            bold: Some(true),
            size: Some(24),
            color: Some(Color::Rgb(0xFF0000)),
            underline: Some("single"),
            italic: Some(false),
            ..RunProps::default()
        };
        let mut o = String::new();
        run_props(&mut o, &p);
        assert_eq!(
            o,
            "<w:rPr><w:b/><w:i w:val=\"0\"/><w:color w:val=\"FF0000\"/><w:sz w:val=\"24\"/><w:u w:val=\"single\"/></w:rPr>"
        );
        // Sizes the format cannot hold are cut to its range.
        let big = RunProps {
            size: Some(100_000),
            ..RunProps::default()
        };
        let mut o = String::new();
        run_props(&mut o, &big);
        assert_eq!(o, "<w:rPr><w:sz w:val=\"3277\"/></w:rPr>");
    }

    #[test]
    fn paragraph_properties() {
        let p = ParaProps {
            style: Some("Heading1".into()),
            jc: Some(Jc::Center),
            ind_left: Some(720),
            ind_first_line: Some(360),
            space_after: Some(120),
            num_id: Some(3),
            num_level: Some(1),
            ..ParaProps::default()
        };
        let mut o = String::new();
        para_props(&mut o, &p, &RunProps::default(), None);
        assert_eq!(
            o,
            "<w:pPr><w:pStyle w:val=\"Heading1\"/><w:numPr><w:ilvl w:val=\"1\"/><w:numId w:val=\"3\"/></w:numPr><w:spacing w:after=\"120\"/><w:ind w:left=\"720\" w:firstLine=\"360\"/><w:jc w:val=\"center\"/></w:pPr>"
        );
    }
}
