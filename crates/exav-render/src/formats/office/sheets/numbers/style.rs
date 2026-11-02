//! Cell and text styles. A style holds the properties it sets and names its
//! parent (TSS.StyleArchive: name 1, parent 3, in field 1 of each style);
//! a property comes from the first style up the chain that sets it.
//!
//! TST.CellStyleArchive: cell_properties 11, with cell_fill 1 (TSD.FillArchive:
//! color 1, gradient 2 with stops 2 holding color 1), text_wrap 3 and
//! vertical_alignment 8 (0 top, 1 middle, 2 bottom).
//! TSWP.ParagraphStyleArchive and CharacterStyleArchive: char_properties 11
//! (bold 1, italic 2, font_size 3, font_name 5, font_color 7, underline 11,
//! strikethru 12) and, for paragraphs, para_properties 12 (alignment 1: 0
//! left, 1 right, 2 center, 3 justified, 4 natural).
//! TSP.Color: model 1 (1 RGB, 2 CMYK, 3 white), r 3, g 4, b 5, alpha 6,
//! c 7, m 8, y 9, k 10, w 11, all in 0 to 1.

use super::iwa::Store;
use super::proto::Msg;
use crate::formats::office::sheets::model::{Edge, Font, Rgb};

const MAX_CHAIN: usize = 32;

/// A colour, `None` when transparent.
pub fn color(c: Msg) -> Option<Rgb> {
    if c.float(6).unwrap_or(1.0) < 0.01 {
        return None;
    }
    let f = |n| f64::from(c.float(n).unwrap_or(0.0)).clamp(0.0, 1.0);
    let (r, g, b) = match c.uint(1).unwrap_or(1) {
        2 => {
            let k = 1.0 - f(10);
            ((1.0 - f(7)) * k, (1.0 - f(8)) * k, (1.0 - f(9)) * k)
        }
        3 => (f(11), f(11), f(11)),
        _ => (f(3), f(4), f(5)),
    };
    let q = |v: f64| (v * 255.0).round() as u32;
    Some(q(r) << 16 | q(g) << 8 | q(b))
}

/// A fill's colour: its colour, or its gradient's first stop.
pub fn fill_color(f: Msg) -> Option<Rgb> {
    if let Some(c) = f.msg(1) {
        return color(c);
    }
    let stop = f.msg(2)?.msgs(2).next()?;
    color(stop.msg(1)?)
}

/// The properties of cell styles that the XLSX style takes.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CellProps {
    pub fill: Option<Option<Rgb>>,
    pub wrap: Option<bool>,
    pub valign: Option<u64>,
}

impl CellProps {
    /// Fills what is unset from `o`.
    pub fn under(&mut self, o: &CellProps) {
        self.fill = self.fill.or(o.fill);
        self.wrap = self.wrap.or(o.wrap);
        self.valign = self.valign.or(o.valign);
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TextProps {
    pub bold: Option<bool>,
    pub italic: Option<bool>,
    pub size: Option<f32>,
    pub font: Option<String>,
    pub color: Option<Option<Rgb>>,
    pub underline: Option<u64>,
    pub strike: Option<u64>,
    pub align: Option<u64>,
}

impl TextProps {
    pub fn under(&mut self, o: &TextProps) {
        self.bold = self.bold.or(o.bold);
        self.italic = self.italic.or(o.italic);
        self.size = self.size.or(o.size);
        if self.font.is_none() {
            self.font.clone_from(&o.font);
        }
        self.color = self.color.or(o.color);
        self.underline = self.underline.or(o.underline);
        self.strike = self.strike.or(o.strike);
        self.align = self.align.or(o.align);
    }

    /// The character properties of a style's field `n`.
    fn chars(&mut self, cp: Msg) {
        let t = TextProps {
            bold: cp.boolean(1),
            italic: cp.boolean(2),
            size: cp.float(3).filter(|s| s.is_finite() && *s > 0.0),
            font: cp.string(5).filter(|s| !s.is_empty()),
            color: if cp.boolean(6).unwrap_or(false) {
                None
            } else {
                cp.msg(7).map(color)
            },
            underline: cp.uint(11),
            strike: cp.uint(12),
            align: None,
        };
        self.under(&t);
    }

    pub fn font(&self) -> Font {
        let (name, bold, italic) = family(self.font.as_deref().unwrap_or("HelveticaNeue"));
        Font {
            name,
            size_centipt: (f64::from(self.size.unwrap_or(10.0)) * 100.0)
                .round()
                .clamp(100.0, 40_000.0) as u32,
            bold: self.bold.unwrap_or(bold),
            italic: self.italic.unwrap_or(italic),
            underline: match self.underline {
                Some(1 | 3) => Some("single"),
                Some(2) => Some("double"),
                _ => None,
            },
            strike: self.strike.is_some_and(|s| s > 0),
            color: self.color.flatten().filter(|&c| c != 0),
            ..Font::default()
        }
    }
}

/// The parent of a style.
fn parent(m: Msg) -> Option<u64> {
    m.msg(1)?.reference(3)
}

pub fn cell_props(store: &Store, id: u64) -> CellProps {
    let mut out = CellProps::default();
    let mut cur = Some(id);
    for _ in 0..MAX_CHAIN {
        let Some((_, m)) = cur.and_then(|i| store.get(i)) else {
            break;
        };
        if let Some(cp) = m.msg(11) {
            let p = CellProps {
                fill: cp.msg(1).map(fill_color),
                wrap: cp.boolean(3),
                valign: cp.uint(8),
            };
            out.under(&p);
        }
        cur = parent(m);
    }
    out
}

pub fn text_props(store: &Store, id: u64) -> TextProps {
    let mut out = TextProps::default();
    let mut cur = Some(id);
    for _ in 0..MAX_CHAIN {
        let Some((_, m)) = cur.and_then(|i| store.get(i)) else {
            break;
        };
        if let Some(cp) = m.msg(11) {
            out.chars(cp);
        }
        if out.align.is_none() {
            out.align = m.msg(12).and_then(|pp| pp.uint(1));
        }
        cur = parent(m);
    }
    out
}

/// A PostScript font name ("HelveticaNeue-Bold", "ArialMT") to its family
/// and the weight and slant its name says: from the names of macOS fonts
/// the rule below misses, else by the rule.
pub fn family(ps: &str) -> (String, bool, bool) {
    let (base, face) = ps.split_once('-').unwrap_or((ps, ""));
    let f = face.to_ascii_lowercase();
    let bold = f.contains("bold");
    let italic = f.contains("italic") || f.contains("oblique");
    if let Ok(i) = super::fonts::FAMILIES.binary_search_by_key(&ps, |f| f.0) {
        return (super::fonts::FAMILIES[i].1.to_string(), bold, italic);
    }
    if base.starts_with(".SF") {
        // The system font.
        return ("SF Pro".into(), bold, italic);
    }
    let base = base
        .strip_suffix("PSMT")
        .or_else(|| base.strip_suffix("MT"))
        .unwrap_or(base);
    // "HelveticaNeue" to "Helvetica Neue": a space before a capital that
    // follows a lower-case letter.
    let mut name = String::new();
    let mut prev_lower = false;
    for c in base.chars() {
        if c.is_uppercase() && prev_lower {
            name.push(' ');
        }
        prev_lower = c.is_lowercase();
        name.push(c);
    }
    if name.is_empty() {
        name = "Helvetica Neue".into();
    }
    (name, bold, italic)
}

/// A TSD.StrokeArchive (color 1, width 2, pattern 6: type 1 with 0 dashes,
/// 1 solid, 2 none, and the dash lengths 4) as an XLSX edge; an edge
/// without style when the stroke draws nothing.
pub fn stroke_edge(s: Msg) -> Edge {
    let pattern = s.msg(6);
    let kind = pattern.and_then(|p| p.uint(1)).unwrap_or(1);
    let width = f64::from(s.float(2).unwrap_or(1.0));
    let color = s.msg(1).and_then(color);
    if kind == 2 || width <= 0.0 || color.is_none() {
        return Edge::default();
    }
    let dash = pattern.and_then(|p| match p.get(4) {
        Some(super::proto::Val::Fixed32(v)) => Some(f32::from_bits(v)),
        Some(super::proto::Val::Bytes(b)) if b.len() >= 4 => {
            Some(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }
        _ => None,
    });
    let style = match (kind, width) {
        (0, w) if dash.is_some_and(|d| d < 1.0) => {
            if w >= 1.5 {
                "mediumDashDotDot"
            } else {
                "dotted"
            }
        }
        (0, w) if w >= 1.5 => "mediumDashed",
        (0, _) => "dashed",
        (_, w) if w >= 2.5 => "thick",
        (_, w) if w >= 1.5 => "medium",
        _ => "thin",
    };
    Edge {
        style: Some(style),
        color: color.filter(|&c| c != 0),
    }
}

#[cfg(test)]
mod tests {
    use super::super::proto::write::W;
    use super::*;

    #[test]
    fn families() {
        assert_eq!(
            family("HelveticaNeue-Bold"),
            ("Helvetica Neue".into(), true, false)
        );
        assert_eq!(family("ArialMT"), ("Arial".into(), false, false));
        assert_eq!(family("Georgia-BoldItalic"), ("Georgia".into(), true, true));
        assert_eq!(
            family("TimesNewRomanPSMT"),
            ("Times New Roman".into(), false, false)
        );
        assert_eq!(family("Arial-Black"), ("Arial Black".into(), false, false));
        assert_eq!(
            family("BodoniSvtyTwoITCTT-Book"),
            ("Bodoni 72".into(), false, false)
        );
    }

    #[test]
    fn colors() {
        let c = W::default()
            .uint(1, 1)
            .float(3, 1.0)
            .float(4, 0.5)
            .float(5, 0.0);
        assert_eq!(color(Msg(&c.0)), Some(0xFF8000));
        let c = W::default().uint(1, 3).float(11, 1.0);
        assert_eq!(color(Msg(&c.0)), Some(0xFFFFFF));
        let c = W::default().uint(1, 1).float(3, 1.0).float(6, 0.0);
        assert_eq!(color(Msg(&c.0)), None);
    }

    #[test]
    fn strokes() {
        let black = W::default().uint(1, 1).float(3, 0.0);
        let solid = W::default()
            .msg(1, black.clone())
            .float(2, 0.35)
            .msg(6, W::default().uint(1, 1));
        assert_eq!(stroke_edge(Msg(&solid.0)).style, Some("thin"));
        let none = W::default()
            .msg(1, black.clone())
            .float(2, 1.0)
            .msg(6, W::default().uint(1, 2));
        assert_eq!(stroke_edge(Msg(&none.0)).style, None);
        let dots = W::default()
            .msg(1, black)
            .float(2, 1.0)
            .msg(6, W::default().uint(1, 0).float(4, 0.1).float(4, 2.0));
        assert_eq!(stroke_edge(Msg(&dots.0)).style, Some("dotted"));
    }
}
