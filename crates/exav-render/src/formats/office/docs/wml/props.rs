//! Property elements of Word 2003 XML: character, paragraph, table, row and
//! cell properties.

use crate::formats::office::common::xml::Node;
use crate::formats::office::docs::model::*;

/// An on/off value: absent or on, true, 1 is on.
pub fn is_on(v: Option<&str>) -> bool {
    !matches!(v, Some("off" | "false" | "0" | "none"))
}

fn val(n: &Node) -> Option<&str> {
    n.attr("w:val")
}

fn int(n: &Node, k: &str) -> Option<i32> {
    n.attr(k).and_then(|v| v.trim().parse::<i32>().ok())
}

fn color(v: &str) -> Color {
    let h = v.trim().trim_start_matches('#');
    if h.len() == 6
        && let Ok(c) = u32::from_str_radix(h, 16)
    {
        return Color::Rgb(c);
    }
    Color::Auto
}

fn border(n: &Node) -> Option<Border> {
    let style = match val(n)? {
        "nil" | "none" => return None,
        "double" => "double",
        "dotted" => "dotted",
        "dashed" => "dashed",
        "dot-dash" => "dotDash",
        "dot-dot-dash" => "dotDotDash",
        "triple" => "triple",
        "thick" => "thick",
        "wave" => "wave",
        "thin-thick-small-gap" => "thinThickSmallGap",
        "thick-thin-small-gap" => "thickThinSmallGap",
        "inset" => "inset",
        "outset" => "outset",
        _ => "single",
    };
    Some(Border {
        style,
        size: int(n, "w:sz").unwrap_or(4).clamp(2, 96) as u32,
        space: int(n, "w:space").unwrap_or(0).clamp(0, 31) as u32,
        color: n.attr("w:color").map(color).unwrap_or(Color::Auto),
        shadow: n.attr("w:shadow").is_some_and(|s| is_on(Some(s))),
    })
}

fn shading(n: &Node) -> Option<Shading> {
    let fill = n.attr("w:fill").map(color);
    let fore = n.attr("w:color").map(color);
    let pat = n.attr("w:val").unwrap_or("clear");
    match (pat, fill, fore) {
        ("clear" | "nil", Some(f), _) if f != Color::Auto => Some(Shading::fill(f)),
        ("solid", _, Some(c)) if c != Color::Auto => Some(Shading::fill(c)),
        (p, f, c) if p.starts_with("percent-") || p.starts_with("pct") => {
            let pct: f64 = p
                .trim_start_matches("percent-")
                .trim_start_matches("pct")
                .parse()
                .unwrap_or(50.0);
            let rgb = |c: Option<Color>, auto: u32| match c {
                Some(Color::Rgb(v)) => v,
                _ => auto,
            };
            let (fv, bv) = (rgb(c, 0), rgb(f, 0xFFFFFF));
            let mix = |s: u32| {
                let (x, y) = (f64::from((fv >> s) & 0xFF), f64::from((bv >> s) & 0xFF));
                (x * pct / 100.0 + y * (1.0 - pct / 100.0)).round() as u32
            };
            Some(Shading::fill(Color::Rgb(
                mix(16) << 16 | mix(8) << 8 | mix(0),
            )))
        }
        _ => None,
    }
}

fn underline(v: &str) -> &'static str {
    match v {
        "none" => "none",
        "double" => "double",
        "words" => "words",
        "dotted" => "dotted",
        "thick" => "thick",
        "dash" => "dash",
        "dot-dash" => "dotDash",
        "dot-dot-dash" => "dotDotDash",
        "wave" => "wave",
        _ => "single",
    }
}

fn highlight(v: &str) -> Option<&'static str> {
    Some(match v {
        "black" => "black",
        "blue" => "blue",
        "cyan" => "cyan",
        "green" => "green",
        "magenta" => "magenta",
        "red" => "red",
        "yellow" => "yellow",
        "white" => "white",
        "dark-blue" => "darkBlue",
        "dark-cyan" => "darkCyan",
        "dark-green" => "darkGreen",
        "dark-magenta" => "darkMagenta",
        "dark-red" => "darkRed",
        "dark-yellow" => "darkYellow",
        "dark-gray" => "darkGray",
        "light-gray" => "lightGray",
        "none" => "none",
        _ => return None,
    })
}

pub fn run_props(n: &Node) -> RunProps {
    let mut r = RunProps::default();
    for c in n.nodes() {
        let on = || Some(is_on(val(c)));
        match c.name.as_str() {
            "w:rStyle" => r.style = val(c).map(str::to_string),
            "w:rFonts" => {
                r.fonts.ascii = c.attr("w:ascii").map(str::to_string);
                r.fonts.hansi = c.attr("w:h-ansi").or(c.attr("w:ascii")).map(str::to_string);
                r.fonts.east_asia = c.attr("w:fareast").map(str::to_string);
                r.fonts.cs = c.attr("w:cs").map(str::to_string);
            }
            "w:b" => r.bold = on(),
            "w:b-cs" => r.bold_cs = on(),
            "w:i" => r.italic = on(),
            "w:i-cs" => r.italic_cs = on(),
            "w:caps" => r.caps = on(),
            "w:smallCaps" => r.small_caps = on(),
            "w:strike" => r.strike = on(),
            "w:dstrike" => r.dstrike = on(),
            "w:outline" => r.outline = on(),
            "w:shadow" => r.shadow = on(),
            "w:emboss" => r.emboss = on(),
            "w:imprint" => r.imprint = on(),
            "w:vanish" => r.vanish = on(),
            "w:color" => r.color = val(c).map(color),
            "w:spacing" => r.spacing = int(c, "w:val"),
            "w:w" => r.scale = int(c, "w:val").map(|v| v.clamp(1, 600) as u32),
            "w:kern" => r.kerning = int(c, "w:val").map(|v| v.max(0) as u32),
            "w:position" => r.position = int(c, "w:val"),
            "w:sz" => r.size = int(c, "w:val").map(|v| v.clamp(1, 3277) as u32),
            "w:sz-cs" => r.size_cs = int(c, "w:val").map(|v| v.clamp(1, 3277) as u32),
            "w:highlight" => r.highlight = val(c).and_then(highlight),
            "w:u" => {
                r.underline = Some(underline(val(c).unwrap_or("single")));
                r.underline_color = c.attr("w:color").map(color);
            }
            "w:bdr" => r.border = border(c),
            "w:shd" => r.shading = shading(c),
            "w:vertAlign" => {
                r.vert_align = match val(c) {
                    Some("superscript") => Some(VertAlign::Superscript),
                    Some("subscript") => Some(VertAlign::Subscript),
                    _ => Some(VertAlign::Baseline),
                }
            }
            "w:rtl" => r.rtl = on(),
            "w:lang" => {
                r.lang = val(c).map(str::to_string);
                r.lang_east_asia = c.attr("w:fareast").map(str::to_string);
                r.lang_bidi = c.attr("w:bidi").map(str::to_string);
            }
            _ => {}
        }
    }
    r
}

pub fn para_props(n: &Node) -> ParaProps {
    let mut p = ParaProps::default();
    for c in n.nodes() {
        let on = || Some(is_on(val(c)));
        match c.name.as_str() {
            "w:pStyle" => p.style = val(c).map(str::to_string),
            "w:keepNext" => p.keep_next = on(),
            "w:keepLines" => p.keep_lines = on(),
            "w:pageBreakBefore" => p.page_break_before = on(),
            "w:widowControl" => p.widow_control = on(),
            "w:suppressLineNumbers" => p.suppress_line_numbers = on(),
            "w:bidi" => p.bidi = on(),
            "w:contextualSpacing" => p.contextual_spacing = on(),
            "w:listPr" => {
                if let Some(l) = c.child("w:ilvl").and_then(|n| int(n, "w:val")) {
                    p.num_level = Some(l.clamp(0, 8) as u32);
                }
                if let Some(l) = c.child("w:ilfo").and_then(|n| int(n, "w:val")) {
                    p.num_id = Some(l.max(0) as u32);
                }
            }
            "w:pBdr" => {
                for b in c.nodes() {
                    let v = border(b);
                    match b.name.as_str() {
                        "w:top" => p.borders.top = v,
                        "w:left" => p.borders.left = v,
                        "w:bottom" => p.borders.bottom = v,
                        "w:right" => p.borders.right = v,
                        "w:between" => p.borders.between = v,
                        _ => {}
                    }
                }
            }
            "w:shd" => p.shading = shading(c),
            "w:tabs" => {
                for t in c.all("w:tab") {
                    let Some(pos) = int(t, "w:pos") else { continue };
                    p.tabs.push(Tab {
                        pos,
                        kind: match t.attr("w:val") {
                            Some("center") => TabKind::Center,
                            Some("right") => TabKind::Right,
                            Some("decimal") => TabKind::Decimal,
                            Some("bar") => TabKind::Bar,
                            Some("clear") => TabKind::Clear,
                            _ => TabKind::Left,
                        },
                        leader: match t.attr("w:leader") {
                            Some("dot") => TabLeader::Dot,
                            Some("hyphen") => TabLeader::Hyphen,
                            Some("underscore") => TabLeader::Underscore,
                            Some("heavy") => TabLeader::Heavy,
                            Some("middle-dot") => TabLeader::MiddleDot,
                            _ => TabLeader::None,
                        },
                    });
                }
            }
            "w:spacing" => {
                p.space_before = int(c, "w:before");
                p.space_after = int(c, "w:after");
                if let Some(l) = int(c, "w:line") {
                    p.line = Some(l);
                    p.line_rule = Some(match c.attr("w:line-rule") {
                        Some("exact") => LineRule::Exact,
                        Some("at-least") => LineRule::AtLeast,
                        _ => LineRule::Auto,
                    });
                }
            }
            "w:ind" => {
                p.ind_left = int(c, "w:left");
                p.ind_right = int(c, "w:right");
                if let Some(h) = int(c, "w:hanging") {
                    p.ind_hanging = Some(h);
                } else {
                    p.ind_first_line = int(c, "w:first-line");
                }
            }
            "w:jc" => {
                p.jc = match val(c) {
                    Some("center") => Some(Jc::Center),
                    Some("right") => Some(Jc::Right),
                    Some("both") => Some(Jc::Both),
                    Some("distribute") => Some(Jc::Distribute),
                    _ => Some(Jc::Left),
                }
            }
            "w:outlineLvl" => p.outline_level = int(c, "w:val").map(|v| v.clamp(0, 9) as u32),
            _ => {}
        }
    }
    p
}

fn width(n: &Node) -> Option<Width> {
    let w = int(n, "w:w")?;
    Some(match n.attr("w:type") {
        Some("pct") => Width::Pct(w),
        Some("auto") => Width::Auto,
        _ => Width::Twips(w),
    })
}

fn margins(n: &Node) -> Margins {
    let mut m = Margins::default();
    for c in n.nodes() {
        let v = int(c, "w:w");
        match c.name.as_str() {
            "w:top" => m.top = v,
            "w:left" => m.left = v,
            "w:bottom" => m.bottom = v,
            "w:right" => m.right = v,
            _ => {}
        }
    }
    m
}

fn borders(n: &Node) -> TableBorders {
    let mut b = TableBorders::default();
    for c in n.nodes() {
        let v = border(c);
        match c.name.as_str() {
            "w:top" => b.top = v,
            "w:left" => b.left = v,
            "w:bottom" => b.bottom = v,
            "w:right" => b.right = v,
            "w:insideH" => b.inside_h = v,
            "w:insideV" => b.inside_v = v,
            _ => {}
        }
    }
    b
}

pub fn table_props(n: &Node) -> TableProps {
    let mut t = TableProps::default();
    for c in n.nodes() {
        match c.name.as_str() {
            "w:tblStyle" => t.style = val(c).map(str::to_string),
            "w:tblW" => t.width = width(c),
            "w:jc" => {
                t.jc = match val(c) {
                    Some("center") => Some(Jc::Center),
                    Some("right") => Some(Jc::Right),
                    _ => None,
                }
            }
            "w:tblInd" => t.indent = int(c, "w:w"),
            "w:tblBorders" => t.borders = borders(c),
            "w:shd" => t.shading = shading(c),
            "w:tblCellMar" => t.cell_margins = margins(c),
            "w:tblLayout" => t.fixed_layout = c.attr("w:type") == Some("fixed"),
            "w:bidiVisual" => t.bidi = is_on(val(c)),
            _ => {}
        }
    }
    t
}

pub fn row_props(n: &Node, r: &mut RowProps) {
    for c in n.nodes() {
        match c.name.as_str() {
            "w:trHeight" => {
                r.height = int(c, "w:val");
                r.height_exact = c.attr("w:h-rule") == Some("exact");
            }
            "w:cantSplit" => r.cant_split = is_on(val(c)),
            "w:tblHeader" => r.header = is_on(val(c)),
            "w:jc" => {
                r.jc = match val(c) {
                    Some("center") => Some(Jc::Center),
                    Some("right") => Some(Jc::Right),
                    _ => None,
                }
            }
            _ => {}
        }
    }
}

pub fn cell_props(n: &Node) -> CellProps {
    let mut p = CellProps::default();
    for c in n.nodes() {
        match c.name.as_str() {
            "w:tcW" => p.width = width(c),
            "w:gridSpan" => p.grid_span = int(c, "w:val").unwrap_or(1).clamp(1, 63) as u32,
            "w:vmerge" => {
                p.v_merge = if val(c) == Some("restart") {
                    VMerge::Restart
                } else {
                    VMerge::Continue
                }
            }
            "w:tcBorders" => p.borders = borders(c),
            "w:shd" => p.shading = shading(c),
            "w:noWrap" => p.no_wrap = is_on(val(c)),
            "w:tcMar" => p.margins = margins(c),
            "w:vAlign" => {
                p.v_align = match val(c) {
                    Some("center") => Some(VAlign::Center),
                    Some("bottom") => Some(VAlign::Bottom),
                    _ => Some(VAlign::Top),
                }
            }
            _ => {}
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::common::xml::{parse, within};

    const NS: &str = "xmlns:w=\"http://schemas.microsoft.com/office/word/2003/wordml\"";

    #[test]
    fn run_and_paragraph_properties() {
        let x = format!(
            "<w:rPr {NS}><w:b/><w:i w:val=\"off\"/><w:rFonts w:ascii=\"Arial\" w:h-ansi=\"Arial\"/><w:color w:val=\"FF0000\"/><w:sz w:val=\"28\"/><w:u w:val=\"double\"/></w:rPr>"
        );
        let r = run_props(&parse(x.as_bytes(), &mut within(1 << 20)).unwrap());
        assert_eq!((r.bold, r.italic), (Some(true), Some(false)));
        assert_eq!(r.fonts.ascii.as_deref(), Some("Arial"));
        assert_eq!(r.color, Some(Color::Rgb(0xFF0000)));
        assert_eq!((r.size, r.underline), (Some(28), Some("double")));
        let x = format!(
            "<w:pPr {NS}><w:jc w:val=\"center\"/><w:ind w:left=\"720\" w:hanging=\"360\"/><w:spacing w:before=\"120\" w:line=\"240\" w:line-rule=\"exact\"/><w:listPr><w:ilvl w:val=\"1\"/><w:ilfo w:val=\"3\"/></w:listPr></w:pPr>"
        );
        let p = para_props(&parse(x.as_bytes(), &mut within(1 << 20)).unwrap());
        assert_eq!(p.jc, Some(Jc::Center));
        assert_eq!((p.ind_left, p.ind_hanging), (Some(720), Some(360)));
        assert_eq!(
            (p.space_before, p.line_rule),
            (Some(120), Some(LineRule::Exact))
        );
        assert_eq!((p.num_id, p.num_level), (Some(3), Some(1)));
    }
}
