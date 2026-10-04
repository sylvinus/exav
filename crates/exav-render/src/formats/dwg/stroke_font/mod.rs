//! Stroke fonts for CAD text.
//!
//! A stroke font draws each glyph as bare centre lines rather than filled
//! outlines, which is what AutoCAD's `.shx` fonts are and what a plotter
//! expects. It is the right shape for CAD text for a reason that outlives
//! appearance: a stroke has no thickness of its own, so the drawing's lineweight
//! decides it, exactly as AutoCAD renders SHX text.
//!
//! This module reads the [FontoBene] format and ships [NewStroke], a CC0
//! stroke font with 2,573 glyphs, as [`newstroke`]. Neither needs wasm to run.
//!
//! [FontoBene]: https://github.com/fontobene/fontobene
//! [NewStroke]: http://vovanium.ru/sledy/newstroke/en
//!
//! ```
//! let font = exav_render::dwg::stroke_font::newstroke();
//! let a = font.glyph('A').unwrap();
//! assert!(a.polylines().count() > 0);
//! // Advances are in cap heights, which is the unit a DWG text height is in.
//! assert!((0.5..1.5).contains(&font.advance('A')));
//! ```
//!
//! # Units
//!
//! FontoBene measures in ninths of the cap height. This crate divides that out
//! and reports **cap heights**, because a DWG text height is a cap height: a
//! run at height `h` scales glyph coordinates by `h` directly, with no
//! ratio to estimate. That is a real advantage over the TrueType path, where
//! cap height has to be measured out of the face and varies between them.

mod binary;
pub mod fontobene;

use binary::Layout;

/// NewStroke, compiled from `fonts/newstroke.bene` by the build script.
static NEWSTROKE_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/newstroke.bin"));

/// Font units per cap height, from the FontoBene specification.
const UNITS_PER_CAP: f32 = fontobene::UNITS_PER_CAP;

/// The bundled NewStroke font.
///
/// CC0-1.0, by Vladimir Uryvaev, via the FontoBene distribution. Covers
/// U+0020 to U+FFFD: Latin, Greek, Cyrillic and the symbols technical drawings
/// use, including `⌀` U+2300, which none of the bundled TrueType faces carry.
pub fn newstroke() -> &'static StrokeFont {
    static FONT: std::sync::OnceLock<StrokeFont> = std::sync::OnceLock::new();
    FONT.get_or_init(|| {
        StrokeFont::from_bytes(NEWSTROKE_BYTES).expect("the build script wrote this table")
    })
}

/// A stroke font in its compact form.
pub struct StrokeFont {
    bytes: &'static [u8],
    layout: Layout,
}

impl StrokeFont {
    /// Read a table produced by `binary::encode` (the build script runs it).
    ///
    /// Returns `None` if the bytes are not a table of this version, or if its
    /// internal offsets do not agree with its length. Everything read
    /// afterwards is in range because this checked it.
    pub fn from_bytes(bytes: &'static [u8]) -> Option<StrokeFont> {
        let layout = binary::layout(bytes)?;
        Some(StrokeFont { bytes, layout })
    }

    /// Number of glyphs.
    pub fn len(&self) -> usize {
        self.layout.glyph_count
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Baseline-to-baseline distance for multi-line text, in cap heights.
    ///
    /// Advisory: a DWG carries its own line spacing, which takes precedence.
    pub fn line_spacing(&self) -> f32 {
        binary::line_spacing(self.bytes) / UNITS_PER_CAP
    }

    /// Space added after every glyph, in cap heights. Already included in
    /// [`advance`](Self::advance).
    pub fn letter_spacing(&self) -> f32 {
        binary::letter_spacing(self.bytes) / UNITS_PER_CAP
    }

    /// Set for a monospaced font, in cap heights.
    pub fn monospace_width(&self) -> Option<f32> {
        binary::monospace_width(self.bytes).map(|w| w / UNITS_PER_CAP)
    }

    /// Index of a codepoint, by binary search over the sorted table.
    fn index(&self, c: char) -> Option<usize> {
        let target = c as u32;
        let base = self.layout.codepoints;
        let (mut lo, mut hi) = (0usize, self.layout.glyph_count);
        while lo < hi {
            let mid = (lo + hi) / 2;
            match binary::u32_at(self.bytes, base + mid * 4).cmp(&target) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }

    /// Look up a glyph.
    pub fn glyph(&self, c: char) -> Option<Glyph<'_>> {
        let i = self.index(c)?;
        Some(Glyph {
            font: self,
            index: i,
        })
    }

    /// Whether the font can draw a character.
    pub fn has(&self, c: char) -> bool {
        self.index(c).is_some()
    }

    /// Pen advance for a character, in cap heights.
    ///
    /// A character the font does not have advances by the width of `?`, which
    /// is what will be drawn in its place.
    pub fn advance(&self, c: char) -> f32 {
        let i = self.index(c).or_else(|| self.index(NOTDEF));
        match i {
            Some(i) => {
                binary::i16_at(self.bytes, self.layout.advances + i * 2) as f32
                    / binary::SCALE
                    / UNITS_PER_CAP
            }
            None => 0.0,
        }
    }

    /// Width of a string, in cap heights.
    pub fn measure(&self, s: &str) -> f32 {
        s.chars().map(|c| self.advance(c)).sum()
    }

    /// Every codepoint the font covers, ascending.
    pub fn codepoints(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.layout.glyph_count)
            .map(move |i| binary::u32_at(self.bytes, self.layout.codepoints + i * 4))
    }
}

/// Drawn in place of a character the font does not have.
const NOTDEF: char = '?';

/// One glyph's strokes.
pub struct Glyph<'a> {
    font: &'a StrokeFont,
    index: usize,
}

impl<'a> Glyph<'a> {
    /// Pen advance, in cap heights.
    pub fn advance(&self) -> f32 {
        binary::i16_at(self.font.bytes, self.font.layout.advances + self.index * 2) as f32
            / binary::SCALE
            / UNITS_PER_CAP
    }

    fn poly_range(&self) -> (usize, usize) {
        let o = self.font.layout.glyph_poly + self.index * 4;
        (
            binary::u32_at(self.font.bytes, o) as usize,
            binary::u32_at(self.font.bytes, o + 4) as usize,
        )
    }

    /// Number of separate strokes.
    pub fn polyline_count(&self) -> usize {
        let (a, z) = self.poly_range();
        z - a
    }

    /// The strokes, each a run of points in cap-height units with the origin on
    /// the baseline at the glyph's left edge.
    pub fn polylines(&self) -> impl Iterator<Item = Polyline<'a>> + 'a {
        let (a, z) = self.poly_range();
        let font = self.font;
        (a..z).map(move |i| Polyline { font, index: i })
    }
}

/// One stroke of a glyph.
pub struct Polyline<'a> {
    font: &'a StrokeFont,
    index: usize,
}

impl<'a> Polyline<'a> {
    fn range(&self) -> (usize, usize) {
        let o = self.font.layout.poly_vert + self.index * 4;
        (
            binary::u32_at(self.font.bytes, o) as usize,
            binary::u32_at(self.font.bytes, o + 4) as usize,
        )
    }

    pub fn len(&self) -> usize {
        let (a, z) = self.range();
        z - a
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The points, in cap heights.
    pub fn points(&self) -> impl Iterator<Item = [f32; 2]> + 'a {
        let (a, z) = self.range();
        let font = self.font;
        (a..z).map(move |i| {
            let p = binary::vertex(font.bytes, &font.layout, i);
            [p[0] / UNITS_PER_CAP, p[1] / UNITS_PER_CAP]
        })
    }
}

/// Compile a parsed font into the byte table [`StrokeFont::from_bytes`] reads.
pub fn encode(font: &fontobene::Font) -> Vec<u8> {
    binary::encode(font)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newstroke_loads() {
        let f = newstroke();
        assert_eq!(f.len(), 2573, "every glyph in the vendored file");
        assert!(f.has('A') && f.has('é') && f.has('Ω') && f.has('Ж'));
    }

    /// The characters these drawings need that a substituted TrueType face
    /// tends to miss. U+2300 is the one none of Arimo, Tinos or Cousine has.
    #[test]
    fn covers_the_characters_drawings_use() {
        let f = newstroke();
        for c in "°±²³µØ⌀€ÇàâçèéêëîïôöùûüÿœŒæÆ«»".chars() {
            assert!(f.has(c), "missing {c:?} (U+{:04X})", c as u32);
        }
    }

    /// Cap height is 9 font units, so a capital reaches 1.0 and no further.
    #[test]
    fn capitals_reach_the_cap_height() {
        let f = newstroke();
        for c in ['A', 'E', 'H', 'I', 'T'] {
            let top = f
                .glyph(c)
                .unwrap()
                .polylines()
                .flat_map(|p| p.points())
                .map(|p| p[1])
                .fold(f32::MIN, f32::max);
            assert!(
                (top - 1.0).abs() < 0.01,
                "{c:?} reaches {top}, expected 1.0"
            );
        }
    }

    /// Letters sit on the baseline, so nothing but a descender goes below zero.
    #[test]
    fn capitals_sit_on_the_baseline() {
        let f = newstroke();
        for c in ['A', 'E', 'H', 'I', 'T', 'M'] {
            let bottom = f
                .glyph(c)
                .unwrap()
                .polylines()
                .flat_map(|p| p.points())
                .map(|p| p[1])
                .fold(f32::MAX, f32::min);
            assert!(bottom.abs() < 0.01, "{c:?} bottoms at {bottom}, expected 0");
        }
    }

    /// The decoded "A" must match the vendored file exactly: two strokes, the
    /// crossbar and the two legs, at the coordinates the file gives.
    #[test]
    fn glyph_a_matches_the_source_file() {
        let g = newstroke().glyph('A').unwrap();
        let polys: Vec<Vec<[f32; 2]>> = g
            .polylines()
            .map(|p| p.points().map(|q| [q[0] * 9.0, q[1] * 9.0]).collect())
            .collect();
        assert_eq!(polys.len(), 2);
        let close = |a: [f32; 2], b: [f32; 2]| {
            assert!(
                (a[0] - b[0]).abs() < 0.01 && (a[1] - b[1]).abs() < 0.01,
                "{a:?} != {b:?}"
            );
        };
        // .86,2.57;5.14,2.57
        close(polys[0][0], [0.86, 2.57]);
        close(polys[0][1], [5.14, 2.57]);
        // 0,0;3,9;6,0
        close(polys[1][0], [0.0, 0.0]);
        close(polys[1][1], [3.0, 9.0]);
        close(polys[1][2], [6.0, 0.0]);
    }

    /// Advance is the glyph's extent plus its trailing space plus the font's
    /// letter spacing. "A" spans 0..6 with no trailing space, and NewStroke
    /// declares letter_spacing = 1.8, so 7.8 font units.
    #[test]
    fn advance_matches_the_specified_formula() {
        let f = newstroke();
        assert!(
            (f.advance('A') * 9.0 - 7.8).abs() < 0.02,
            "got {}",
            f.advance('A') * 9.0
        );
        // Space has no strokes and declares ~3.6, so 3.6 + 1.8.
        assert!(
            (f.advance(' ') * 9.0 - 5.4).abs() < 0.02,
            "got {}",
            f.advance(' ') * 9.0
        );
    }

    /// The font is proportional: a narrow letter must advance less than a wide
    /// one, which is the whole reason for using its widths rather than a
    /// substitute's.
    #[test]
    fn widths_are_proportional() {
        let f = newstroke();
        assert!(
            f.advance('I') < f.advance('A'),
            "I should be narrower than A"
        );
        assert!(
            f.advance('A') < f.advance('W'),
            "A should be narrower than W"
        );
        assert!(
            f.advance('i') < f.advance('m'),
            "i should be narrower than m"
        );
        assert!(f.monospace_width().is_none());
    }

    #[test]
    fn measure_sums_advances() {
        let f = newstroke();
        let expect = f.advance('A') + f.advance('B') + f.advance('C');
        assert!((f.measure("ABC") - expect).abs() < 1e-6);
    }

    /// An unknown character falls back to "?" rather than collapsing the run.
    #[test]
    fn unknown_character_takes_the_notdef_width() {
        let f = newstroke();
        let missing = '\u{10FFFF}';
        assert!(!f.has(missing));
        assert_eq!(f.advance(missing), f.advance('?'));
        assert!(f.advance(missing) > 0.0);
    }

    #[test]
    fn spacing_is_reported_in_cap_heights() {
        let f = newstroke();
        // letter_spacing = 1.8, line_spacing = 16, both over 9. Stored as
        // floats rather than fixed point, so these survive exactly.
        assert_eq!(f.letter_spacing(), 1.8 / 9.0);
        assert_eq!(f.line_spacing(), 16.0 / 9.0);
    }

    /// Round-tripping any parsed font has to preserve geometry and advances.
    #[test]
    fn encode_decode_round_trip() {
        let src = "\
[font]
name = round trip
letter_spacing = 1.8
line_spacing = 16

---

[0020] Space
~3.6

[0041] A
0,0;3,9;6,0
1.2,3.6;4.8,3.6

[0042] B
0,0;0,9
~0.5
";
        let parsed = fontobene::parse(src).unwrap();
        let bytes: &'static [u8] = Box::leak(encode(&parsed).into_boxed_slice());
        let f = StrokeFont::from_bytes(bytes).unwrap();

        assert_eq!(f.len(), 3);
        assert_eq!(f.letter_spacing(), 1.8 / 9.0);
        assert_eq!(f.line_spacing(), 16.0 / 9.0);

        let a = f.glyph('A').unwrap();
        assert_eq!(a.polyline_count(), 2);
        let first: Vec<[f32; 2]> = a.polylines().next().unwrap().points().collect();
        assert_eq!(first.len(), 3);
        assert!((first[1][0] * 9.0 - 3.0).abs() < 0.01);
        assert!((first[1][1] * 9.0 - 9.0).abs() < 0.01);

        // A spans 0..6, no trailing: 6 + 1.8. B is a bare stroke at x=0 with
        // ~0.5: 0 + 0.5 + 1.8. Space: 3.6 + 1.8.
        assert!((f.advance('A') * 9.0 - 7.8).abs() < 0.02);
        assert!((f.advance('B') * 9.0 - 2.3).abs() < 0.02);
        assert!((f.advance(' ') * 9.0 - 5.4).abs() < 0.02);
    }

    /// A table that is not one, or one whose counts disagree with its length,
    /// must be refused rather than read out of bounds.
    #[test]
    fn corrupt_tables_are_rejected() {
        assert!(StrokeFont::from_bytes(b"").is_none());
        assert!(StrokeFont::from_bytes(b"not a font at all, really").is_none());

        let good = NEWSTROKE_BYTES;
        // Truncated at every scale.
        for cut in [1, 8, 27, 28, 100, 5000, good.len() - 1] {
            let bytes: &'static [u8] = Box::leak(good[..cut].to_vec().into_boxed_slice());
            assert!(
                StrokeFont::from_bytes(bytes).is_none(),
                "accepted a table truncated to {cut} bytes"
            );
        }
        // Every field the section offsets are computed from: magic, version,
        // palette length and the three counts. Changing any of them must make
        // the declared sections stop adding up to the file's length.
        for (offset, what) in [
            (0, "magic"),
            (4, "version"),
            (20, "palette_len"),
            (24, "glyph_count"),
            (28, "poly_count"),
            (32, "vert_count"),
        ] {
            let mut bad = good.to_vec();
            bad[offset] = bad[offset].wrapping_add(1);
            let bytes: &'static [u8] = Box::leak(bad.into_boxed_slice());
            assert!(
                StrokeFont::from_bytes(bytes).is_none(),
                "accepted a table with a corrupted {what}"
            );
        }
    }

    /// Every glyph must decode without panicking and stay in a sane box. This
    /// walks all 2,573, which is the only way to know the offset tables are
    /// consistent all the way to the end.
    #[test]
    fn every_glyph_decodes() {
        let f = newstroke();
        let mut points = 0usize;
        for cp in f.codepoints() {
            let c = char::from_u32(cp).expect("a valid codepoint");
            let g = f.glyph(c).unwrap();
            assert!(f.advance(c).is_finite());
            for p in g.polylines() {
                for q in p.points() {
                    assert!(q[0].is_finite() && q[1].is_finite());
                    // Ascenders, descenders and a few wide symbols go past the
                    // cap box; nothing should be far outside it.
                    assert!(q[0] > -1.0 && q[0] < 4.0, "U+{cp:04X} x={}", q[0]);
                    assert!(q[1] > -1.5 && q[1] < 3.0, "U+{cp:04X} y={}", q[1]);
                    points += 1;
                }
            }
        }
        // The file holds 34,484 points, of which 8 are single-point polylines
        // left behind by the converter: a stray point in U+04BA and one in each
        // of the half-filled circles U+25D0..U+25D7. A one-point stroke draws
        // nothing, so the parser drops them.
        assert_eq!(points, 34_476, "every drawable vertex in the vendored file");
    }
}
