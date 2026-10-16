//! The bits of CSS that Excel's HTML and SpreadsheetML carry: colours
//! (hexadecimal, `rgb()`, the CSS named colours and the Windows system
//! colours Internet Explorer knew), lengths, declaration lists and border
//! shorthands.

use crate::formats::office::sheets::model::{Edge, Rgb};

/// CSS Color Module Level 4's named colours, sorted.
const NAMED: &[(&str, Rgb)] = &[
    ("aliceblue", 0xF0F8FF),
    ("antiquewhite", 0xFAEBD7),
    ("aqua", 0x00FFFF),
    ("aquamarine", 0x7FFFD4),
    ("azure", 0xF0FFFF),
    ("beige", 0xF5F5DC),
    ("bisque", 0xFFE4C4),
    ("black", 0x000000),
    ("blanchedalmond", 0xFFEBCD),
    ("blue", 0x0000FF),
    ("blueviolet", 0x8A2BE2),
    ("brown", 0xA52A2A),
    ("burlywood", 0xDEB887),
    ("cadetblue", 0x5F9EA0),
    ("chartreuse", 0x7FFF00),
    ("chocolate", 0xD2691E),
    ("coral", 0xFF7F50),
    ("cornflowerblue", 0x6495ED),
    ("cornsilk", 0xFFF8DC),
    ("crimson", 0xDC143C),
    ("cyan", 0x00FFFF),
    ("darkblue", 0x00008B),
    ("darkcyan", 0x008B8B),
    ("darkgoldenrod", 0xB8860B),
    ("darkgray", 0xA9A9A9),
    ("darkgreen", 0x006400),
    ("darkgrey", 0xA9A9A9),
    ("darkkhaki", 0xBDB76B),
    ("darkmagenta", 0x8B008B),
    ("darkolivegreen", 0x556B2F),
    ("darkorange", 0xFF8C00),
    ("darkorchid", 0x9932CC),
    ("darkred", 0x8B0000),
    ("darksalmon", 0xE9967A),
    ("darkseagreen", 0x8FBC8F),
    ("darkslateblue", 0x483D8B),
    ("darkslategray", 0x2F4F4F),
    ("darkslategrey", 0x2F4F4F),
    ("darkturquoise", 0x00CED1),
    ("darkviolet", 0x9400D3),
    ("deeppink", 0xFF1493),
    ("deepskyblue", 0x00BFFF),
    ("dimgray", 0x696969),
    ("dimgrey", 0x696969),
    ("dodgerblue", 0x1E90FF),
    ("firebrick", 0xB22222),
    ("floralwhite", 0xFFFAF0),
    ("forestgreen", 0x228B22),
    ("fuchsia", 0xFF00FF),
    ("gainsboro", 0xDCDCDC),
    ("ghostwhite", 0xF8F8FF),
    ("gold", 0xFFD700),
    ("goldenrod", 0xDAA520),
    ("gray", 0x808080),
    ("green", 0x008000),
    ("greenyellow", 0xADFF2F),
    ("grey", 0x808080),
    ("honeydew", 0xF0FFF0),
    ("hotpink", 0xFF69B4),
    ("indianred", 0xCD5C5C),
    ("indigo", 0x4B0082),
    ("ivory", 0xFFFFF0),
    ("khaki", 0xF0E68C),
    ("lavender", 0xE6E6FA),
    ("lavenderblush", 0xFFF0F5),
    ("lawngreen", 0x7CFC00),
    ("lemonchiffon", 0xFFFACD),
    ("lightblue", 0xADD8E6),
    ("lightcoral", 0xF08080),
    ("lightcyan", 0xE0FFFF),
    ("lightgoldenrodyellow", 0xFAFAD2),
    ("lightgray", 0xD3D3D3),
    ("lightgreen", 0x90EE90),
    ("lightgrey", 0xD3D3D3),
    ("lightpink", 0xFFB6C1),
    ("lightsalmon", 0xFFA07A),
    ("lightseagreen", 0x20B2AA),
    ("lightskyblue", 0x87CEFA),
    ("lightslategray", 0x778899),
    ("lightslategrey", 0x778899),
    ("lightsteelblue", 0xB0C4DE),
    ("lightyellow", 0xFFFFE0),
    ("lime", 0x00FF00),
    ("limegreen", 0x32CD32),
    ("linen", 0xFAF0E6),
    ("magenta", 0xFF00FF),
    ("maroon", 0x800000),
    ("mediumaquamarine", 0x66CDAA),
    ("mediumblue", 0x0000CD),
    ("mediumorchid", 0xBA55D3),
    ("mediumpurple", 0x9370DB),
    ("mediumseagreen", 0x3CB371),
    ("mediumslateblue", 0x7B68EE),
    ("mediumspringgreen", 0x00FA9A),
    ("mediumturquoise", 0x48D1CC),
    ("mediumvioletred", 0xC71585),
    ("midnightblue", 0x191970),
    ("mintcream", 0xF5FFFA),
    ("mistyrose", 0xFFE4E1),
    ("moccasin", 0xFFE4B5),
    ("navajowhite", 0xFFDEAD),
    ("navy", 0x000080),
    ("oldlace", 0xFDF5E6),
    ("olive", 0x808000),
    ("olivedrab", 0x6B8E23),
    ("orange", 0xFFA500),
    ("orangered", 0xFF4500),
    ("orchid", 0xDA70D6),
    ("palegoldenrod", 0xEEE8AA),
    ("palegreen", 0x98FB98),
    ("paleturquoise", 0xAFEEEE),
    ("palevioletred", 0xDB7093),
    ("papayawhip", 0xFFEFD5),
    ("peachpuff", 0xFFDAB9),
    ("peru", 0xCD853F),
    ("pink", 0xFFC0CB),
    ("plum", 0xDDA0DD),
    ("powderblue", 0xB0E0E6),
    ("purple", 0x800080),
    ("rebeccapurple", 0x663399),
    ("red", 0xFF0000),
    ("rosybrown", 0xBC8F8F),
    ("royalblue", 0x4169E1),
    ("saddlebrown", 0x8B4513),
    ("salmon", 0xFA8072),
    ("sandybrown", 0xF4A460),
    ("seagreen", 0x2E8B57),
    ("seashell", 0xFFF5EE),
    ("sienna", 0xA0522D),
    ("silver", 0xC0C0C0),
    ("skyblue", 0x87CEEB),
    ("slateblue", 0x6A5ACD),
    ("slategray", 0x708090),
    ("slategrey", 0x708090),
    ("snow", 0xFFFAFA),
    ("springgreen", 0x00FF7F),
    ("steelblue", 0x4682B4),
    ("tan", 0xD2B48C),
    ("teal", 0x008080),
    ("thistle", 0xD8BFD8),
    ("tomato", 0xFF6347),
    ("turquoise", 0x40E0D0),
    ("violet", 0xEE82EE),
    ("wheat", 0xF5DEB3),
    ("white", 0xFFFFFF),
    ("whitesmoke", 0xF5F5F5),
    ("yellow", 0xFFFF00),
    ("yellowgreen", 0x9ACD32),
];

/// The Windows system colours of a default Windows theme, for the CSS2
/// system colour names Excel writes (`windowtext` above all), sorted.
const SYSTEM: &[(&str, Rgb)] = &[
    ("activeborder", 0xB4B4B4),
    ("activecaption", 0x99B4D1),
    ("appworkspace", 0xABABAB),
    ("background", 0x000000),
    ("buttonface", 0xF0F0F0),
    ("buttonhighlight", 0xFFFFFF),
    ("buttonshadow", 0xA0A0A0),
    ("buttontext", 0x000000),
    ("captiontext", 0x000000),
    ("graytext", 0x6D6D6D),
    ("highlight", 0x0078D7),
    ("highlighttext", 0xFFFFFF),
    ("inactiveborder", 0xF4F7FC),
    ("inactivecaption", 0xBFCDDB),
    ("inactivecaptiontext", 0x000000),
    ("infobackground", 0xFFFFE1),
    ("infotext", 0x000000),
    ("menu", 0xF0F0F0),
    ("menutext", 0x000000),
    ("scrollbar", 0xC8C8C8),
    ("threeddarkshadow", 0x696969),
    ("threedface", 0xF0F0F0),
    ("threedhighlight", 0xFFFFFF),
    ("threedlightshadow", 0xE3E3E3),
    ("threedshadow", 0xA0A0A0),
    ("window", 0xFFFFFF),
    ("windowframe", 0x646464),
    ("windowtext", 0x000000),
];

/// A colour: `Some(Some(rgb))`, `Some(None)` for the automatic colour or
/// transparent, `None` when it is not one.
pub fn color(s: &str) -> Option<Option<Rgb>> {
    let s = s
        .trim()
        .trim_end_matches("!important")
        .trim()
        .to_ascii_lowercase();
    if matches!(
        s.as_str(),
        "automatic" | "auto" | "transparent" | "none" | "inherit" | "initial"
    ) {
        return Some(None);
    }
    if let Some(h) = s.strip_prefix('#') {
        let v = u32::from_str_radix(h, 16).ok()?;
        return match h.len() {
            6 => Some(Some(v)),
            3 => Some(Some(
                ((v >> 8) & 0xF) * 0x110000 + ((v >> 4) & 0xF) * 0x1100 + (v & 0xF) * 0x11,
            )),
            _ => None,
        };
    }
    if let Some(args) = s.strip_prefix("rgb(").or_else(|| s.strip_prefix("rgba(")) {
        let parts: Vec<&str> = args
            .trim_end_matches(')')
            .split([',', ' ', '/'])
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() < 3 {
            return None;
        }
        let mut rgb = 0u32;
        for p in &parts[..3] {
            let v = match p.strip_suffix('%') {
                Some(pc) => pc.parse::<f64>().ok()? * 255.0 / 100.0,
                None => p.parse::<f64>().ok()?,
            };
            if !v.is_finite() {
                return None;
            }
            rgb = rgb << 8 | v.round().clamp(0.0, 255.0) as u32;
        }
        return Some(Some(rgb));
    }
    let find = |t: &[(&str, Rgb)]| {
        t.binary_search_by_key(&s.as_str(), |e| e.0)
            .ok()
            .map(|i| t[i].1)
    };
    find(NAMED).or_else(|| find(SYSTEM)).map(Some)
}

/// A length in points: pt, px (at 96 dpi), in, cm, mm, pc; a bare number
/// is taken as `bare_unit`.
pub fn length_pt(s: &str, bare_unit: &str) -> Option<f64> {
    let s = s
        .trim()
        .trim_end_matches("!important")
        .trim()
        .to_ascii_lowercase();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || matches!(c, '.' | '-' | '+')))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let v: f64 = num.parse().ok().filter(|v: &f64| v.is_finite())?;
    let unit = if unit.is_empty() {
        bare_unit
    } else {
        unit.trim()
    };
    Some(match unit {
        "pt" => v,
        "px" => v * 0.75,
        "in" => v * 72.0,
        "cm" => v * 72.0 / 2.54,
        "mm" => v * 72.0 / 25.4,
        "pc" => v * 12.0,
        _ => return None,
    })
}

/// A declaration list (`a: b; c: d`), property names in lower case, values
/// trimmed. Quotes and parentheses keep their semicolons.
pub fn declarations(s: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    let mut start = 0;
    let mut quote = None;
    let mut depth = 0u32;
    let b = s.as_bytes();
    for i in 0..=b.len() {
        let c = b.get(i).copied();
        match (c, quote) {
            (Some(q), Some(open)) if q == open => quote = None,
            (Some(_), Some(_)) => {}
            (Some(q @ (b'"' | b'\'')), None) => quote = Some(q),
            (Some(b'('), None) => depth += 1,
            (Some(b')'), None) => depth = depth.saturating_sub(1),
            (Some(b';'), None) | (None, _) if depth == 0 || c.is_none() => {
                let decl = &s[start..i];
                if let Some((k, v)) = decl.split_once(':') {
                    let k = k.trim().to_ascii_lowercase();
                    if !k.is_empty() {
                        out.push((k, v.trim().to_string()));
                    }
                }
                start = i + 1;
                if out.len() >= 256 {
                    break;
                }
            }
            _ => {}
        }
    }
    out
}

/// A border shorthand (`.5pt solid windowtext`, `1px dashed #000`) as an
/// XLSX edge.
pub fn border(s: &str) -> Edge {
    let mut width = None;
    let mut style = None;
    let mut rgb = None;
    for t in s.split_whitespace() {
        let l = t.to_ascii_lowercase();
        match l.as_str() {
            "none" | "hidden" => return Edge::default(),
            "solid" | "dashed" | "dotted" | "double" | "groove" | "ridge" | "inset" | "outset"
            | "hairline" | "dot-dash" | "dot-dot-dash" | "dot-dash-slanted" => style = Some(l),
            "thin" => width = Some(0.75),
            "medium" => width = Some(1.5),
            "thick" => width = Some(2.25),
            _ => {
                if let Some(w) = length_pt(&l, "px") {
                    width = Some(w);
                } else if let Some(c) = color(&l) {
                    rgb = c;
                }
            }
        }
    }
    let Some(style) = style else {
        return Edge::default();
    };
    let w = width.unwrap_or(0.75);
    if w <= 0.0 {
        return Edge::default();
    }
    // Excel writes its thin lines .5pt wide, medium 1pt and thick 1.5pt; a
    // browser's 1px is .75pt.
    let wide = w >= 1.0;
    let name = match style.as_str() {
        "double" => "double",
        "hairline" => "hair",
        "dashed" if wide => "mediumDashed",
        "dashed" => "dashed",
        "dotted" => "dotted",
        "dot-dash" if wide => "mediumDashDot",
        "dot-dash" => "dashDot",
        "dot-dot-dash" if wide => "mediumDashDotDot",
        "dot-dot-dash" => "dashDotDot",
        "dot-dash-slanted" => "slantDashDot",
        _ if w < 1.0 => "thin",
        _ if w < 1.5 => "medium",
        _ => "thick",
    };
    Edge {
        style: Some(name),
        color: rgb.filter(|&c| c != 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_sorted() {
        for t in [NAMED, SYSTEM] {
            assert!(t.windows(2).all(|w| w[0].0 < w[1].0));
        }
    }

    #[test]
    fn colors() {
        assert_eq!(color("#FF8000"), Some(Some(0xFF8000)));
        assert_eq!(color("#f80"), Some(Some(0xFF8800)));
        assert_eq!(color("WindowText"), Some(Some(0)));
        assert_eq!(color("Silver"), Some(Some(0xC0C0C0)));
        assert_eq!(color("rgb(255, 0, 50%)"), Some(Some(0xFF0080)));
        assert_eq!(color("Automatic"), Some(None));
        assert_eq!(color("nonsense"), None);
    }

    #[test]
    fn lists_lengths_borders() {
        assert_eq!(
            declarations("mso-number-format:\"0\\.00;\\(0\\)\"; color:red ;;bad"),
            [
                (
                    "mso-number-format".to_string(),
                    "\"0\\.00;\\(0\\)\"".to_string()
                ),
                ("color".to_string(), "red".to_string())
            ]
        );
        assert_eq!(length_pt("20px", "pt"), Some(15.0));
        assert_eq!(length_pt("12", "pt"), Some(12.0));
        assert_eq!(
            border(".5pt solid windowtext"),
            Edge {
                style: Some("thin"),
                color: None
            }
        );
        assert_eq!(
            border("1.0pt solid windowtext"),
            Edge {
                style: Some("medium"),
                color: None
            }
        );
        assert_eq!(
            border(".5pt hairline windowtext"),
            Edge {
                style: Some("hair"),
                color: None
            }
        );
        assert_eq!(
            border(".5pt dashed #FF0000"),
            Edge {
                style: Some("dashed"),
                color: Some(0xFF0000)
            }
        );
        assert_eq!(
            border("2pt double black"),
            Edge {
                style: Some("double"),
                color: None
            }
        );
        assert_eq!(border("none"), Edge::default());
    }
}
