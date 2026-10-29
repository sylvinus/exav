//! CSS as a spreadsheet reads it: the colours, lengths and declarations of
//! `common::css`, and a border shorthand as an XLSX edge.

pub use crate::formats::office::common::css::{color, declarations, length_pt};
use crate::formats::office::sheets::model::Edge;

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
    fn borders() {
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
