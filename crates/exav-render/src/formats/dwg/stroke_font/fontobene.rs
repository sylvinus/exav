//! Parser for the FontoBene stroke font format, version 1.0.
//!
//! <https://github.com/fontobene/fontobene/blob/master/SPECIFICATION.md>
//!
//! A FontoBene file is UTF-8 text: an INI-style header, a `---` separator, then
//! one block per glyph holding backward references, polylines and an optional
//! trailing-space override. Coordinates are in ninths of the cap height, with
//! the origin on the baseline at the glyph's left edge.
//!
//! This module is also compiled into `build.rs`, which is why it depends on
//! nothing else in the crate.

use std::collections::HashMap;
use std::f32::consts::PI;

/// Font units per cap height. Fixed by the format.
pub const UNITS_PER_CAP: f32 = 9.0;

/// Largest sagitta, in font units, left when flattening a bulge arc.
///
/// One font unit is a ninth of the cap height, so this is 0.5% of a glyph's
/// height: below what a stroke of any visible width would reveal.
const ARC_TOLERANCE: f32 = 0.045;

#[derive(Debug, Default, Clone)]
pub struct Glyph {
    /// Stroke paths, already flattened to line segments.
    pub polylines: Vec<Vec<[f32; 2]>>,
    /// Trailing space from a `~` definition, in font units.
    pub trailing: f32,
}

#[derive(Debug, Clone)]
pub struct Font {
    pub name: String,
    pub license: String,
    /// Space inserted after every glyph, in font units.
    pub letter_spacing: f32,
    /// Baseline-to-baseline distance, in font units.
    pub line_spacing: f32,
    /// Set only by a monospace font; every glyph then occupies this width.
    pub monospace_width: Option<f32>,
    pub glyphs: HashMap<u32, Glyph>,
}

#[derive(Debug)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parse a whole font file.
pub fn parse(text: &str) -> Result<Font, ParseError> {
    let mut font = Font {
        name: String::new(),
        license: String::new(),
        // The spec's defaults when a key is absent.
        letter_spacing: 0.0,
        line_spacing: UNITS_PER_CAP,
        monospace_width: None,
        glyphs: HashMap::new(),
    };

    // Glyph declaration order, so that a reference can only reach backwards.
    let mut order: Vec<u32> = Vec::new();
    let mut current: Option<u32> = None;

    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Header keys, until the separator. After it, `key = value` is not
        // valid syntax, so this only needs to distinguish the two sections.
        if current.is_none() && !line.starts_with('[') && !line.starts_with("---") {
            if let Some((k, v)) = line.split_once('=') {
                let (k, v) = (k.trim(), v.trim());
                let num = |what: &str| -> Result<f32, ParseError> {
                    v.parse::<f32>().map_err(|_| ParseError {
                        line: line_no,
                        message: format!("{what} is not a number: {v:?}"),
                    })
                };
                match k {
                    "name" => font.name = v.to_string(),
                    // The spec allows several `license` keys for a font under
                    // more than one; keep them all, so the provenance survives.
                    "license" if font.license.is_empty() => font.license = v.to_string(),
                    "license" => {
                        font.license.push_str(" AND ");
                        font.license.push_str(v);
                    }
                    "letter_spacing" => font.letter_spacing = num("letter_spacing")?,
                    "line_spacing" => font.line_spacing = num("line_spacing")?,
                    "monospace_width" => font.monospace_width = Some(num("monospace_width")?),
                    _ => {}
                }
            }
            continue;
        }

        // A section header in the body would be a glyph, so only skip these
        // before the first glyph block is open.
        if current.is_none() && line.starts_with('[') && line.ends_with(']') && !is_glyph_decl(line)
        {
            continue;
        }
        if line == "---" {
            continue;
        }

        if let Some(cp) = glyph_declaration(line, line_no)? {
            font.glyphs.entry(cp).or_default();
            order.push(cp);
            current = Some(cp);
            continue;
        }

        let Some(cp) = current else {
            continue;
        };

        if let Some(rest) = line.strip_prefix('@') {
            let target = u32::from_str_radix(rest.trim(), 16).map_err(|_| ParseError {
                line: line_no,
                message: format!("reference is not a codepoint: {rest:?}"),
            })?;
            // Backward references only, so one pass suffices and loops cannot
            // form. A reference to the block being defined is also rejected.
            if !order[..order.len() - 1].contains(&target) {
                return Err(ParseError {
                    line: line_no,
                    message: format!("reference to U+{target:04X} which is not yet defined"),
                });
            }
            let src = font.glyphs[&target].clone();
            let g = font.glyphs.get_mut(&cp).expect("declared above");
            g.polylines.extend(src.polylines);
            // Trailing space is inherited, and the last one named wins.
            g.trailing = src.trailing;
        } else if let Some(rest) = line.strip_prefix('~') {
            let w = rest.trim().parse::<f32>().map_err(|_| ParseError {
                line: line_no,
                message: format!("whitespace width is not a number: {rest:?}"),
            })?;
            font.glyphs.get_mut(&cp).expect("declared above").trailing = w;
        } else {
            let poly = parse_polyline(line, line_no)?;
            if poly.len() >= 2 {
                font.glyphs
                    .get_mut(&cp)
                    .expect("declared above")
                    .polylines
                    .push(poly);
            }
        }
    }

    Ok(font)
}

/// Does `[...]` hold a codepoint rather than an INI section name?
fn is_glyph_decl(line: &str) -> bool {
    let inner = &line[1..line.len() - 1];
    !inner.is_empty() && inner.chars().all(|c| c.is_ascii_hexdigit())
}

/// `[0041] A`: the trailing preview character is ignored, as the spec says.
fn glyph_declaration(line: &str, line_no: usize) -> Result<Option<u32>, ParseError> {
    if !line.starts_with('[') {
        return Ok(None);
    }
    let Some(end) = line.find(']') else {
        return Ok(None);
    };
    let inner = &line[1..end];
    if inner.is_empty() || !inner.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(None);
    }
    u32::from_str_radix(inner, 16)
        .map(Some)
        .map_err(|_| ParseError {
            line: line_no,
            message: format!("codepoint out of range: {inner:?}"),
        })
}

/// `x,y;x,y,bulge;x,y`: a polyline, with arcs flattened into it.
fn parse_polyline(line: &str, line_no: usize) -> Result<Vec<[f32; 2]>, ParseError> {
    let num = |s: &str| -> Result<f32, ParseError> {
        s.trim().parse::<f32>().map_err(|_| ParseError {
            line: line_no,
            message: format!("coordinate is not a number: {s:?}"),
        })
    };

    // Parse to points plus the bulge that leads away from each.
    let mut pts: Vec<([f32; 2], f32)> = Vec::new();
    for part in line.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut f = part.split(',');
        let (Some(x), Some(y)) = (f.next(), f.next()) else {
            return Err(ParseError {
                line: line_no,
                message: format!("coordinate pair expected: {part:?}"),
            });
        };
        let bulge = match f.next() {
            Some(b) => num(b)?,
            None => 0.0,
        };
        if f.next().is_some() {
            return Err(ParseError {
                line: line_no,
                message: format!("too many values in coordinate: {part:?}"),
            });
        }
        pts.push(([num(x)?, num(y)?], bulge));
    }

    let mut out: Vec<[f32; 2]> = Vec::with_capacity(pts.len());
    for (i, (p, bulge)) in pts.iter().enumerate() {
        out.push(*p);
        if let Some((next, _)) = pts.get(i + 1) {
            if *bulge != 0.0 {
                flatten_arc(*p, *next, *bulge, &mut out);
            }
        }
    }
    Ok(out)
}

/// Append the interior points of an arc from `a` to `b`, exclusive of both.
///
/// The bulge runs -9..+9 for -180°..+180° of included angle, positive meaning
/// counter-clockwise. Note that the specification's own worked example for "B"
/// annotates two arcs as forming the bowls "on the right side", which under
/// this sign convention they do not; the normative sentence is followed here.
/// NewStroke contains no arcs at all, so nothing shipped depends on it.
fn flatten_arc(a: [f32; 2], b: [f32; 2], bulge: f32, out: &mut Vec<[f32; 2]>) {
    let angle = (bulge / 9.0).clamp(-1.0, 1.0) * PI;
    if angle == 0.0 {
        return;
    }
    let chord = ((b[0] - a[0]).powi(2) + (b[1] - a[1]).powi(2)).sqrt();
    if chord <= f32::EPSILON {
        return;
    }
    let radius = chord / (2.0 * (angle / 2.0).sin()).abs();

    // Centre lies on the chord's perpendicular bisector. `n` is the chord
    // direction turned a quarter turn anticlockwise, which puts the centre to
    // the left of the chord for an anticlockwise arc. The spec caps the angle
    // at half a turn, so the centre is never on the far side.
    let mid = [(a[0] + b[0]) / 2.0, (a[1] + b[1]) / 2.0];
    let h = (radius * radius - chord * chord / 4.0).max(0.0).sqrt();
    let (nx, ny) = (-(b[1] - a[1]) / chord, (b[0] - a[0]) / chord);
    let s = angle.signum();
    let centre = [mid[0] + nx * h * s, mid[1] + ny * h * s];

    // Enough segments that the sagitta stays under tolerance.
    let step = 2.0 * (1.0 - (ARC_TOLERANCE / radius).min(1.0)).acos();
    let n = if step > 0.0 {
        (angle.abs() / step).ceil().max(1.0) as usize
    } else {
        1
    };

    let start = (a[1] - centre[1]).atan2(a[0] - centre[0]);
    for k in 1..n {
        let t = start + angle * (k as f32 / n as f32);
        out.push([centre[0] + radius * t.cos(), centre[1] + radius * t.sin()]);
    }
}

impl Font {
    /// Pen advance for a glyph, in font units: its own extent, its trailing
    /// space, and the font's global letter spacing.
    ///
    /// The spec builds the gap between two glyphs from three parts: the first
    /// glyph's trailing space, the global letter spacing, and the second
    /// glyph's leading space. The third falls out of placing the next glyph at
    /// the pen, since a glyph's leading space *is* its leftmost coordinate.
    pub fn advance(&self, g: &Glyph) -> f32 {
        if let Some(w) = self.monospace_width {
            return w + self.letter_spacing;
        }
        let right = g
            .polylines
            .iter()
            .flatten()
            .map(|p| p[0])
            .fold(0.0f32, f32::max);
        right + g.trailing + self.letter_spacing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The font from section 7 of the specification, which exercises
    /// references, inherited whitespace, `~0` cancellation and bulge arcs.
    const SPEC_EXAMPLE: &str = "\
[format]
format = FontoBene
format_version = 1.0.0

[font]
id = spec-example
name = FontoBene Specification Example
version = 1.0.0
license = CC0-1.0

---

[0020] Space
~3.6

[0041] A
0,0;3,9;6,0
1.2,3.6;4.8,3.6

[0049] I
0,0;0,9
~0.5

[0042] B
@0049
0,4.5,7.75;0,0
0,4.5,-7.75;0,9
~0

[005F] _
0,0;3,0
~0.25

[004C] L
@0049
@005F
";

    #[test]
    fn parses_header() {
        let f = parse(SPEC_EXAMPLE).unwrap();
        assert_eq!(f.name, "FontoBene Specification Example");
        assert_eq!(f.license, "CC0-1.0");
        // Absent from this file, so the spec's defaults apply.
        assert_eq!(f.letter_spacing, 0.0);
        assert_eq!(f.line_spacing, 9.0);
        assert!(f.monospace_width.is_none());
    }

    #[test]
    fn parses_polylines() {
        let f = parse(SPEC_EXAMPLE).unwrap();
        let a = &f.glyphs[&0x41];
        assert_eq!(a.polylines.len(), 2);
        assert_eq!(a.polylines[0], vec![[0.0, 0.0], [3.0, 9.0], [6.0, 0.0]]);
        assert_eq!(a.trailing, 0.0);
    }

    #[test]
    fn space_has_width_but_no_strokes() {
        let f = parse(SPEC_EXAMPLE).unwrap();
        let sp = &f.glyphs[&0x20];
        assert!(sp.polylines.is_empty());
        assert_eq!(sp.trailing, 3.6);
        assert_eq!(f.advance(sp), 3.6);
    }

    #[test]
    fn reference_copies_strokes_and_inherits_trailing() {
        let f = parse(SPEC_EXAMPLE).unwrap();
        // "L" inherits I's stroke then _'s stroke, and _'s trailing space,
        // because the last whitespace definition seen wins.
        let l = &f.glyphs[&0x4c];
        assert_eq!(l.polylines.len(), 2);
        assert_eq!(l.polylines[0], vec![[0.0, 0.0], [0.0, 9.0]]);
        assert_eq!(l.polylines[1], vec![[0.0, 0.0], [3.0, 0.0]]);
        assert_eq!(l.trailing, 0.25, "should take _'s trailing, not I's");
    }

    #[test]
    fn trailing_can_be_cancelled() {
        let f = parse(SPEC_EXAMPLE).unwrap();
        // "B" references "I", whose ~0.5 it then overrides with ~0.
        assert_eq!(f.glyphs[&0x42].trailing, 0.0);
    }

    #[test]
    fn bulge_becomes_an_arc() {
        let f = parse(SPEC_EXAMPLE).unwrap();
        let b = &f.glyphs[&0x42];
        // The straight stroke from "I", then the two arcs.
        assert_eq!(b.polylines.len(), 3);
        let arc = &b.polylines[1];
        assert!(arc.len() > 2, "arc should be subdivided, got {}", arc.len());
        assert_eq!(arc[0], [0.0, 4.5]);
        assert_eq!(*arc.last().unwrap(), [0.0, 0.0]);
    }

    /// A quarter turn whose answer can be written down: bulge 4.5 is +90°, so
    /// (1,0) to (0,1) anticlockwise is the unit circle about the origin.
    #[test]
    fn quarter_arc_lands_on_the_unit_circle() {
        let src = "[font]\n\n---\n\n[0041] A\n1,0,4.5;0,1\n";
        let g = &parse(src).unwrap().glyphs[&0x41];
        let arc = &g.polylines[0];
        assert!(arc.len() > 2, "should be subdivided, got {}", arc.len());
        for p in arc {
            let r = (p[0] * p[0] + p[1] * p[1]).sqrt();
            assert!((r - 1.0).abs() < 1e-3, "point {p:?} is {r} from the origin");
            // The short way round stays in the first quadrant.
            assert!(
                p[0] >= -1e-3 && p[1] >= -1e-3,
                "point {p:?} took the long way"
            );
        }
    }

    /// The same chord with the sign flipped must bow the other way, around
    /// (1,1) rather than the origin.
    #[test]
    fn negative_bulge_turns_the_other_way() {
        let src = "[font]\n\n---\n\n[0041] A\n1,0,-4.5;0,1\n";
        let g = &parse(src).unwrap().glyphs[&0x41];
        for p in &g.polylines[0] {
            let r = ((p[0] - 1.0).powi(2) + (p[1] - 1.0).powi(2)).sqrt();
            assert!((r - 1.0).abs() < 1e-3, "point {p:?} is {r} from (1,1)");
        }
    }

    /// Flattening has to be fine enough that the deviation stays under the
    /// stated tolerance, which is what lets the arcs be baked at build time.
    #[test]
    fn arc_flattening_respects_the_tolerance() {
        // A half turn of radius 9, the largest an arc can be in a normal glyph.
        let src = "[font]\n\n---\n\n[0041] A\n0,0,9;18,0\n";
        let g = &parse(src).unwrap().glyphs[&0x41];
        let arc = &g.polylines[0];
        for w in arc.windows(2) {
            let mid = [(w[0][0] + w[1][0]) / 2.0, (w[0][1] + w[1][1]) / 2.0];
            // Sagitta is how far the chord midpoint falls inside the circle.
            let r = ((mid[0] - 9.0).powi(2) + mid[1].powi(2)).sqrt();
            assert!(
                9.0 - r <= ARC_TOLERANCE + 1e-4,
                "sagitta {} exceeds tolerance {ARC_TOLERANCE}",
                9.0 - r
            );
        }
    }

    #[test]
    fn advance_adds_extent_trailing_and_letter_spacing() {
        let mut f = parse(SPEC_EXAMPLE).unwrap();
        f.letter_spacing = 1.8;
        // "A" spans x 0..6 and has no trailing space.
        assert_eq!(f.advance(&f.glyphs[&0x41]), 6.0 + 1.8);
        // "I" is a zero-width vertical stroke with 0.5 of trailing space.
        assert_eq!(f.advance(&f.glyphs[&0x49]), 0.0 + 0.5 + 1.8);
    }

    #[test]
    fn monospace_overrides_every_advance() {
        let mut f = parse(SPEC_EXAMPLE).unwrap();
        f.monospace_width = Some(6.0);
        f.letter_spacing = 1.8;
        assert_eq!(f.advance(&f.glyphs[&0x41]), 7.8);
        assert_eq!(f.advance(&f.glyphs[&0x49]), 7.8);
        assert_eq!(f.advance(&f.glyphs[&0x20]), 7.8);
    }

    #[test]
    fn forward_reference_is_rejected() {
        let src = "[font]\nname = x\n\n---\n\n[0041] A\n@0042\n\n[0042] B\n0,0;1,1\n";
        let err = parse(src).unwrap_err();
        assert!(err.message.contains("U+0042"), "got {err}");
    }

    #[test]
    fn self_reference_is_rejected() {
        let src = "[font]\nname = x\n\n---\n\n[0041] A\n@0041\n";
        assert!(parse(src).is_err());
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let src = "[font]\nname = x\n\n---\n\n# a comment\n[0041] A\n# another\n0,0;1,1\n";
        let f = parse(src).unwrap();
        assert_eq!(f.glyphs[&0x41].polylines.len(), 1);
    }

    #[test]
    fn malformed_coordinates_are_errors() {
        for bad in [
            "[font]\n\n---\n\n[0041] A\n0,0;1\n",
            "[font]\n\n---\n\n[0041] A\n0,x;1,1\n",
        ] {
            assert!(parse(bad).is_err(), "should reject {bad:?}");
        }
    }
}
