//! ODF style properties ([ODF 1.2] 20) as model properties.

use crate::formats::office::common::odf::{self, Props, Styles};
use crate::formats::office::docs::model::*;

/// "0.06pt solid #000000" and the like. `None` for no border.
pub fn border(v: &str, pad: Option<f64>) -> Option<Border> {
    let mut width = None;
    let mut style = None;
    let mut color = None;
    for tok in v.split_whitespace() {
        if tok == "none" || tok == "hidden" {
            return None;
        }
        if let Some(c) = odf::color(tok) {
            color = Some(c);
        } else if let Some(w) = odf::pt(tok) {
            width = Some(w);
        } else {
            style = Some(tok);
        }
    }
    let w = width.unwrap_or(0.75);
    let style = match style.unwrap_or("solid") {
        "double" => "double",
        "dotted" => "dotted",
        "dashed" => "dashed",
        "dot-dash" => "dotDash",
        "dot-dot-dash" => "dotDotDash",
        "groove" => "threeDEngrave",
        "ridge" => "threeDEmboss",
        "inset" => "inset",
        "outset" => "outset",
        "fine-dashed" => "dashSmallGap",
        _ => "single",
    };
    Some(Border {
        style,
        size: ((w * 8.0).round() as u32).clamp(2, 96),
        space: pad.map(|p| p.round() as u32).unwrap_or(0).min(31),
        color: color.map(Color::Rgb).unwrap_or(Color::Auto),
        shadow: false,
    })
}

/// The border of one side: `fo:border-top`, else `fo:border`.
pub fn side(p: &Props, kind: &str, side: &str) -> Option<Option<Border>> {
    let v = p
        .get(&format!("{kind}/fo:border-{side}"))
        .or_else(|| p.get(&format!("{kind}/fo:border")))?;
    let pad = p
        .pt(&format!("{kind}/fo:padding-{side}"))
        .or_else(|| p.pt(&format!("{kind}/fo:padding")));
    Some(border(v, pad))
}

fn size_half_points(v: &str, base_half: u32) -> Option<u32> {
    if let Some(p) = odf::percent(v) {
        return Some(((f64::from(base_half) * p).round() as u32).clamp(2, 3276));
    }
    odf::pt(v).map(|p| ((p * 2.0).round() as u32).clamp(2, 3276))
}

fn bold_of(v: &str) -> Option<bool> {
    match v {
        "bold" | "bolder" => Some(true),
        "normal" | "lighter" => Some(false),
        n => n.parse::<u32>().ok().map(|w| w >= 600),
    }
}

fn italic_of(v: &str) -> Option<bool> {
    match v {
        "italic" | "oblique" => Some(true),
        "normal" => Some(false),
        _ => None,
    }
}

fn lang_tag(lang: Option<&str>, country: Option<&str>) -> Option<String> {
    let l = lang?;
    if l == "none" || l.is_empty() {
        return None;
    }
    Some(match country {
        Some(c) if c != "none" && !c.is_empty() => format!("{l}-{c}"),
        _ => l.to_string(),
    })
}

/// Character properties; `base_half` is the size percentages refer to.
pub fn run_props(p: &Props, st: &Styles, base_half: u32) -> RunProps {
    let mut r = RunProps::default();
    let t = |k: &str| p.get(&format!("text/{k}"));
    if let Some(v) = t("fo:font-weight").and_then(bold_of) {
        r.bold = Some(v);
    }
    if let Some(v) = t("style:font-weight-complex").and_then(bold_of) {
        r.bold_cs = Some(v);
    } else if let Some(b) = r.bold {
        r.bold_cs = Some(b);
    }
    if let Some(v) = t("fo:font-style").and_then(italic_of) {
        r.italic = Some(v);
    }
    if let Some(v) = t("style:font-style-complex").and_then(italic_of) {
        r.italic_cs = Some(v);
    } else if let Some(b) = r.italic {
        r.italic_cs = Some(b);
    }
    if let Some(sz) = t("fo:font-size").and_then(|v| size_half_points(v, base_half)) {
        r.size = Some(sz);
        r.size_cs = Some(sz);
    }
    if let Some(sz) = t("style:font-size-complex").and_then(|v| size_half_points(v, base_half)) {
        r.size_cs = Some(sz);
    }
    let family = |name: &str, fam: &str| -> Option<String> {
        t(name)
            .map(|n| st.font(n))
            .or_else(|| t(fam).map(|f| f.trim().trim_matches(['\'', '"']).to_string()))
            .filter(|s| !s.is_empty())
    };
    if let Some(f) = family("style:font-name", "fo:font-family") {
        r.fonts.ascii = Some(f.clone());
        r.fonts.hansi = Some(f);
    }
    r.fonts.east_asia = family("style:font-name-asian", "style:font-family-asian");
    r.fonts.cs = family("style:font-name-complex", "style:font-family-complex");
    if let Some(c) = t("fo:color").and_then(odf::color) {
        r.color = Some(Color::Rgb(c));
    }
    if t("style:use-window-font-color") == Some("true") {
        r.color = Some(Color::Auto);
    }
    if let Some(v) = t("fo:background-color") {
        r.shading = odf::color(v).map(|c| Shading::fill(Color::Rgb(c)));
        if v == "transparent" {
            r.shading = Some(Shading::fill(Color::Auto));
        }
    }
    if let Some(s) = t("style:text-underline-style") {
        r.underline = Some(match s {
            "none" => "none",
            _ => {
                let double = t("style:text-underline-type") == Some("double");
                let bold = matches!(t("style:text-underline-width"), Some("bold" | "thick"));
                match (s, double, bold) {
                    ("dotted", _, true) => "dottedHeavy",
                    ("dotted", _, _) => "dotted",
                    ("dash" | "long-dash", _, true) => "dashedHeavy",
                    ("dash", _, _) => "dash",
                    ("long-dash", _, _) => "dashLong",
                    ("dot-dash", _, true) => "dashDotHeavy",
                    ("dot-dash", _, _) => "dotDash",
                    ("dot-dot-dash", _, true) => "dashDotDotHeavy",
                    ("dot-dot-dash", _, _) => "dotDotDash",
                    ("wave", true, _) => "wavyDouble",
                    ("wave", _, true) => "wavyHeavy",
                    ("wave", _, _) => "wave",
                    (_, true, _) => "double",
                    (_, _, true) => "thick",
                    _ => "single",
                }
            }
        });
        r.underline_color = t("style:text-underline-color").map(|c| match odf::color(c) {
            Some(v) => Color::Rgb(v),
            None => Color::Auto,
        });
    }
    if let Some(s) = t("style:text-line-through-style") {
        if s == "none" {
            r.strike = Some(false);
            r.dstrike = Some(false);
        } else if t("style:text-line-through-type") == Some("double") {
            r.dstrike = Some(true);
        } else {
            r.strike = Some(true);
        }
    }
    match t("fo:text-transform") {
        Some("uppercase") => r.caps = Some(true),
        Some("none" | "lowercase" | "capitalize") => r.caps = Some(false),
        _ => {}
    }
    match t("fo:font-variant") {
        Some("small-caps") => r.small_caps = Some(true),
        Some("normal") => r.small_caps = Some(false),
        _ => {}
    }
    if let Some(v) = t("style:text-position") {
        let mut it = v.split_whitespace();
        let first = it.next().unwrap_or("0%");
        let pct = match first {
            "super" => Some(33.0),
            "sub" => Some(-33.0),
            s => s.strip_suffix('%').and_then(|x| x.parse::<f64>().ok()),
        };
        if let Some(pct) = pct {
            if pct.abs() < 0.5 {
                r.vert_align = Some(VertAlign::Baseline);
            } else if first == "super" || first == "sub" || pct.abs() >= 20.0 {
                r.vert_align = Some(if pct > 0.0 {
                    VertAlign::Superscript
                } else {
                    VertAlign::Subscript
                });
            } else {
                let half = f64::from(r.size.unwrap_or(base_half));
                r.position = Some((pct / 100.0 * half).round() as i32);
            }
        }
    }
    if let Some(v) = t("fo:letter-spacing") {
        if v != "normal" {
            if let Some(tw) = odf::twips(v) {
                r.spacing = Some(tw);
            }
        }
    }
    if let Some(v) = t("style:text-scale").and_then(odf::percent) {
        r.scale = Some(((v * 100.0).round() as u32).clamp(1, 600));
    }
    if t("text:display") == Some("none") {
        r.vanish = Some(true);
    } else if t("text:display") == Some("true") {
        r.vanish = Some(false);
    }
    match t("style:font-relief") {
        Some("embossed") => r.emboss = Some(true),
        Some("engraved") => r.imprint = Some(true),
        _ => {}
    }
    if t("style:text-outline") == Some("true") {
        r.outline = Some(true);
    }
    if t("fo:text-shadow").is_some_and(|s| s != "none") {
        r.shadow = Some(true);
    }
    r.lang = lang_tag(t("fo:language"), t("fo:country"));
    r.lang_east_asia = lang_tag(t("style:language-asian"), t("style:country-asian"));
    r.lang_bidi = lang_tag(t("style:language-complex"), t("style:country-complex"));
    r
}

fn jc_of(v: &str) -> Option<Jc> {
    Some(match v {
        "start" | "left" => Jc::Left,
        "end" | "right" => Jc::Right,
        "center" => Jc::Center,
        "justify" => Jc::Both,
        _ => return None,
    })
}

/// Paragraph properties. `kind` is "paragraph".
pub fn para_props(p: &Props, in_list: bool) -> ParaProps {
    let mut r = ParaProps::default();
    let g = |k: &str| p.get(&format!("paragraph/{k}"));
    if let Some(j) = g("fo:text-align").and_then(jc_of) {
        r.jc = Some(j);
    }
    if g("style:writing-mode").is_some_and(|w| w.starts_with("rl")) {
        r.bidi = Some(true);
    }
    if !in_list {
        if let Some(v) = g("fo:margin-left").and_then(odf::twips) {
            r.ind_left = Some(v);
        }
        if let Some(v) = g("fo:text-indent").and_then(odf::twips) {
            if v >= 0 {
                r.ind_first_line = Some(v);
            } else {
                r.ind_hanging = Some(-v);
            }
        }
    }
    if let Some(v) = g("fo:margin-right").and_then(odf::twips) {
        r.ind_right = Some(v);
    }
    if let Some(v) = g("fo:margin-top").and_then(odf::twips) {
        r.space_before = Some(v.max(0));
    }
    if let Some(v) = g("fo:margin-bottom").and_then(odf::twips) {
        r.space_after = Some(v.max(0));
    }
    if let Some(v) = g("fo:line-height") {
        if let Some(pc) = odf::percent(v) {
            r.line = Some((pc * 240.0).round() as i32);
            r.line_rule = Some(LineRule::Auto);
        } else if let Some(t) = odf::twips(v) {
            if t > 0 {
                r.line = Some(t);
                r.line_rule = Some(LineRule::Exact);
            }
        }
    }
    if let Some(t) = g("style:line-height-at-least").and_then(odf::twips) {
        r.line = Some(t);
        r.line_rule = Some(LineRule::AtLeast);
    }
    match g("fo:keep-together") {
        Some("always") => r.keep_lines = Some(true),
        Some("auto") => r.keep_lines = Some(false),
        _ => {}
    }
    match g("fo:keep-with-next") {
        Some("always") => r.keep_next = Some(true),
        Some("auto") => r.keep_next = Some(false),
        _ => {}
    }
    if g("fo:break-before") == Some("page") {
        r.page_break_before = Some(true);
    }
    let widows = g("fo:widows").and_then(|v| v.parse::<u32>().ok());
    let orphans = g("fo:orphans").and_then(|v| v.parse::<u32>().ok());
    if widows.is_some() || orphans.is_some() {
        r.widow_control = Some(widows.unwrap_or(0) > 1 || orphans.unwrap_or(0) > 1);
    }
    if let Some(v) = g("fo:background-color") {
        r.shading = odf::color(v).map(|c| Shading::fill(Color::Rgb(c)));
    }
    for (name, slot) in [
        ("top", &mut r.borders.top),
        ("left", &mut r.borders.left),
        ("bottom", &mut r.borders.bottom),
        ("right", &mut r.borders.right),
    ] {
        if let Some(b) = side(p, "paragraph", name) {
            *slot = b;
        }
    }
    if g("style:contextual-spacing") == Some("true") {
        r.contextual_spacing = Some(true);
    }
    r
}

/// The tab stops of a style, relative to its left margin `left`.
pub fn tabs(children: &[(String, String, odf::Attrs)], left: i32) -> Vec<Tab> {
    let mut out = vec![];
    for (_, name, attrs) in children {
        if name != "style:tab-stop" {
            continue;
        }
        let get = |k: &str| attrs.iter().find(|a| a.0 == k).map(|a| a.1.as_str());
        let Some(pos) = get("style:position").and_then(odf::twips) else {
            continue;
        };
        let kind = match get("style:type") {
            Some("center") => TabKind::Center,
            Some("right") => TabKind::Right,
            Some("char") => TabKind::Decimal,
            _ => TabKind::Left,
        };
        let leader = match (get("style:leader-style"), get("style:leader-text")) {
            (Some("none") | None, None) => TabLeader::None,
            (_, Some("-")) => TabLeader::Hyphen,
            (_, Some("_")) => TabLeader::Underscore,
            (Some("dotted"), _) | (_, Some(".")) => TabLeader::Dot,
            (Some("solid"), _) => TabLeader::Underscore,
            (Some("dash" | "long-dash"), _) => TabLeader::Hyphen,
            _ => TabLeader::Dot,
        };
        out.push(Tab {
            pos: pos + left,
            kind,
            leader,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borders() {
        let b = border("0.5pt solid #ff0000", Some(2.0)).unwrap();
        assert_eq!(
            (b.style, b.size, b.space, b.color),
            ("single", 4, 2, Color::Rgb(0xFF0000))
        );
        assert!(border("none", None).is_none());
        assert_eq!(border("1pt double #000000", None).unwrap().style, "double");
    }

    #[test]
    fn run_and_paragraph_properties() {
        let p = Props(vec![
            ("text/fo:font-weight".into(), "bold".into()),
            ("text/fo:font-size".into(), "12pt".into()),
            ("text/fo:color".into(), "#0000ff".into()),
            ("text/style:text-position".into(), "super 58%".into()),
            ("text/style:text-underline-style".into(), "solid".into()),
            ("paragraph/fo:text-align".into(), "justify".into()),
            ("paragraph/fo:margin-left".into(), "1cm".into()),
            ("paragraph/fo:text-indent".into(), "-0.5cm".into()),
            ("paragraph/fo:line-height".into(), "150%".into()),
        ]);
        let st = Styles::default();
        let r = run_props(&p, &st, 24);
        assert_eq!(r.bold, Some(true));
        assert_eq!(r.size, Some(24));
        assert_eq!(r.color, Some(Color::Rgb(0xFF)));
        assert_eq!(r.vert_align, Some(VertAlign::Superscript));
        assert_eq!(r.underline, Some("single"));
        let q = para_props(&p, false);
        assert_eq!(q.jc, Some(Jc::Both));
        assert_eq!(q.ind_left, Some(567));
        assert_eq!(q.ind_hanging, Some(283));
        assert_eq!((q.line, q.line_rule), (Some(360), Some(LineRule::Auto)));
        // In a list the indents come from the list level.
        assert_eq!(para_props(&p, true).ind_left, None);
    }
}
